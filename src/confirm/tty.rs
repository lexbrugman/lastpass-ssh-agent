use std::path::PathBuf;
use std::time::Duration;

use super::{ConfirmContext, Confirmer, Decision};
use crate::tty;

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
        // One prompt at a time; see the type's documentation.
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
    let terminal = tty::open(path)?;
    // A stale `yes` left over from a prompt that timed out must not approve
    // this request, which the user has not read yet.
    tty::discard_pending_input(&terminal);

    let prompt = format!("\n{message}\nAllow? (type 'yes' to approve, anything else denies): ");
    tty::write_all(&terminal, prompt.as_bytes()).await?;

    // A byte at a time, stopping at the newline: a larger read could swallow
    // input typed after the answer, which belongs to whatever prompts next.
    let mut answer = String::new();
    loop {
        let mut byte = [0u8; 1];
        tty::read_once(&terminal, &mut byte).await?;
        if byte[0] == b'\n' {
            break;
        }
        answer.push(char::from(byte[0]));
    }
    Ok(answer.trim() == "yes")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::confirm::PeerInfo;
    use crate::testutil::open_pty;
    use std::io::Write as _;
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
