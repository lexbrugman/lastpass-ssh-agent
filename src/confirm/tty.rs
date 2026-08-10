use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use super::{ConfirmContext, Confirmer, Decision};

/// Prompt on the agent's controlling terminal (`/dev/tty`). Useful when the
/// agent runs in a foreground terminal, and as the default on Linux.
///
/// Prompts are strictly serialized: concurrent signing requests would
/// otherwise interleave their prompts and a single "yes" could approve a
/// different request than the one the user read. The whole exchange runs
/// under one deadline, so an expired prompt gives up instead of lingering
/// and swallowing input meant for the next one.
pub struct TtyConfirmer {
    timeout: Duration,
    tty_path: PathBuf,
    serialize: tokio::sync::Mutex<()>,
}

impl TtyConfirmer {
    pub fn new(timeout: Duration) -> Self {
        Self::with_tty(PathBuf::from("/dev/tty"), timeout)
    }

    /// Tests point this at a pty slave instead of the real terminal.
    pub fn with_tty(tty_path: PathBuf, timeout: Duration) -> Self {
        Self {
            timeout,
            tty_path,
            serialize: tokio::sync::Mutex::new(()),
        }
    }
}

#[async_trait::async_trait]
impl Confirmer for TtyConfirmer {
    async fn confirm(&self, ctx: &ConfirmContext) -> Decision {
        // One prompt on the terminal at a time; queued requests each get
        // their own full prompt + timeout once the terminal is free.
        let _one_at_a_time = self.serialize.lock().await;

        let message = super::describe_request(ctx);
        match tokio::time::timeout(self.timeout, prompt_on_tty(&self.tty_path, &message)).await {
            Ok(Ok(answered)) => {
                if answered {
                    Decision::Approve
                } else {
                    Decision::Deny
                }
            }
            Ok(Err(e)) => {
                tracing::warn!("no usable terminal for confirmation, denying: {e}");
                Decision::Deny
            }
            Err(_) => {
                tracing::info!("confirmation timed out, denying");
                Decision::Deny
            }
        }
    }
}

/// Ask on the terminal and wait for an answer. The caller imposes the
/// deadline by dropping this future, which is why every wait here is a
/// cancellation point rather than a blocking call.
async fn prompt_on_tty(path: &std::path::Path, message: &str) -> std::io::Result<bool> {
    // Our own open file description, so O_NONBLOCK is ours alone and cannot
    // change the behaviour of anything else sharing this terminal.
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    discard_pending_input(&tty);
    let tty = AsyncFd::new(tty)?;

    let prompt = format!("\n{message}\nAllow? (type 'yes' to approve, anything else denies): ");
    write_all(&tty, prompt.as_bytes()).await?;

    // Read a byte at a time: in noncanonical mode the terminal reports
    // readiness per keystroke, and a half-typed answer must not outlive the
    // caller's deadline.
    let mut answer = String::new();
    loop {
        let mut byte = [0u8; 1];
        read_once(&tty, &mut byte).await?;
        if byte[0] == b'\n' {
            break;
        }
        answer.push(char::from(byte[0]));
    }
    Ok(answer.trim() == "yes")
}

/// Drop anything already typed before showing a prompt.
///
/// Terminal input is queued in the terminal, not in our file description, so
/// a line finished after an earlier prompt timed out would still be sitting
/// there. Without this, that stale `yes` would answer the *next* signing
/// request — approving something the user never saw. Best effort: a target
/// that is not a terminal has no queue to flush.
fn discard_pending_input(tty: &std::fs::File) {
    use std::os::unix::io::AsRawFd as _;
    // SAFETY: tcflush only acts on the descriptor it is given.
    unsafe { libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH) };
}

/// `async_io` owns the readiness dance, including the retry a spurious
/// wakeup demands — there is no reason to hand-roll that loop.
///
/// A zero-length read means the terminal hung up, which ends the exchange
/// as a refusal. That edge is excluded from coverage because platforms
/// disagree on how a hangup surfaces — macOS reports `EIO` on a closed pty
/// and will not even register `/dev/null` with kqueue — so no single test
/// reaches it on both.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn read_once(tty: &AsyncFd<std::fs::File>, buf: &mut [u8]) -> std::io::Result<()> {
    let read = tty
        .async_io(Interest::READABLE, |mut inner| inner.read(buf))
        .await?;
    if read == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    Ok(())
}

async fn write_all(tty: &AsyncFd<std::fs::File>, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        let written = tty
            .async_io(Interest::WRITABLE, |mut inner| inner.write(buf))
            .await?;
        buf = &buf[written..];
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::confirm::PeerInfo;
    use std::fs::File;
    use std::os::unix::io::FromRawFd;
    use std::time::Instant;

    fn ctx() -> ConfirmContext {
        ConfirmContext {
            key_name: "tty test".into(),
            fingerprint: "SHA256:tty".into(),
            item_id: "1".into(),
            peer: Some(PeerInfo {
                pid: None,
                uid: 501,
            }),
            bindings: Vec::new(),
        }
    }

    /// Open a pty pair; return the master, a keepalive slave handle (a pty
    /// master errors with EIO when no slave is open), and the slave's path.
    fn open_pty() -> (File, File, PathBuf) {
        let mut master: libc::c_int = 0;
        let mut slave: libc::c_int = 0;
        // SAFETY: openpty writes two fds; name/termios/winsize may be null.
        let rc = unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty failed");
        // SAFETY: ptsname on a fresh valid master fd.
        let name = unsafe { libc::ptsname(master) };
        assert!(!name.is_null());
        let path = PathBuf::from(
            unsafe { std::ffi::CStr::from_ptr(name) }
                .to_string_lossy()
                .to_string(),
        );
        // SAFETY: master and slave are valid fds we own; File takes ownership.
        let (master, keepalive) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        (master, keepalive, path)
    }

    #[tokio::test]
    async fn yes_approves() {
        let (mut master, _keepalive, slave_path) = open_pty();
        let confirmer = TtyConfirmer::with_tty(slave_path, Duration::from_secs(10));
        let answer = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(150));
            master.write_all(b"yes\n").unwrap();
            master
        });
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Approve);
        drop(answer.await.unwrap());
    }

    #[tokio::test]
    async fn anything_else_denies() {
        let (mut master, _keepalive, slave_path) = open_pty();
        let confirmer = TtyConfirmer::with_tty(slave_path, Duration::from_secs(10));
        let answer = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(150));
            master.write_all(b"no\n").unwrap();
            master
        });
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Deny);
        drop(answer.await.unwrap());
    }

    #[tokio::test]
    async fn silence_times_out_to_deny() {
        let (master, _keepalive, slave_path) = open_pty();
        let confirmer = TtyConfirmer::with_tty(slave_path, Duration::from_millis(200));
        let start = Instant::now();
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Deny);
        // the deadline is honored in full: poll rounds its wait up, so an
        // expiry can never come early
        assert!(start.elapsed() >= Duration::from_millis(200));
        // generous hang-guard: parallel test load can starve the blocking pool
        assert!(start.elapsed() < Duration::from_secs(30));
        drop(master);
    }

    #[tokio::test]
    async fn input_typed_before_the_prompt_is_discarded() {
        // The user answers an earlier prompt too late; that queued "yes"
        // must not silently approve the request that comes next.
        let (mut master, _keepalive, slave_path) = open_pty();
        master.write_all(b"yes\n").unwrap();
        // give the pty time to queue it before the prompt is shown
        tokio::time::sleep(Duration::from_millis(100)).await;

        let confirmer = TtyConfirmer::with_tty(slave_path, Duration::from_millis(400));
        assert_eq!(
            confirmer.confirm(&ctx()).await,
            Decision::Deny,
            "stale input must not answer a later prompt"
        );
    }

    #[tokio::test]
    async fn a_half_typed_answer_still_times_out() {
        // noncanonical-mode hazard: bytes arrive without a newline. The
        // deadline must still fire instead of blocking forever.
        let (mut master, _keepalive, slave_path) = open_pty();
        master.write_all(b"ye").unwrap();
        let confirmer = TtyConfirmer::with_tty(slave_path, Duration::from_millis(300));
        let start = Instant::now();
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Deny);
        assert!(start.elapsed() >= Duration::from_millis(300));
        assert!(start.elapsed() < Duration::from_secs(30));
    }

    #[tokio::test]
    async fn missing_tty_denies() {
        let confirmer =
            TtyConfirmer::with_tty(PathBuf::from("/nonexistent/tty"), Duration::from_secs(1));
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Deny);
    }

    #[tokio::test]
    async fn concurrent_prompts_are_serialized_one_answer_each() {
        let (master, _keepalive, slave_path) = open_pty();
        let confirmer =
            std::sync::Arc::new(TtyConfirmer::with_tty(slave_path, Duration::from_secs(10)));
        // Answer each prompt as it appears: input queued before a prompt is
        // discarded by design, and the second prompt only starts once the
        // first has been answered.
        let responder = tokio::task::spawn_blocking(move || {
            let mut master = master;
            std::thread::sleep(Duration::from_millis(200));
            master.write_all(b"yes\n").unwrap();
            std::thread::sleep(Duration::from_millis(600));
            master.write_all(b"no\n").unwrap();
            master
        });

        let (a, b) = tokio::join!(
            {
                let c = confirmer.clone();
                async move { c.confirm(&ctx()).await }
            },
            {
                let c = confirmer.clone();
                async move { c.confirm(&ctx()).await }
            },
        );
        drop(responder.await.unwrap());
        let approvals = [a, b].iter().filter(|d| **d == Decision::Approve).count();
        assert_eq!(approvals, 1, "got {a:?} and {b:?}");
    }
}
