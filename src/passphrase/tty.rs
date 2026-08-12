use std::os::unix::io::AsRawFd as _;
use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

use super::{PassphrasePrompt, PassphraseRequest, PromptError};
use crate::tty;

/// Read a passphrase from the controlling terminal with echo disabled.
///
/// Entry is serialized: two prompts sharing a terminal would interleave, and
/// the answer to one would be read as the answer to the other — here that
/// would mean unlocking a key with the passphrase typed for a different one.
pub struct TtyPrompt {
    timeout: Duration,
    tty_path: PathBuf,
    max_bytes: usize,
    serialize: tokio::sync::Mutex<()>,
}

impl TtyPrompt {
    pub fn new(timeout: Duration) -> Self {
        Self::with_tty(PathBuf::from("/dev/tty"), timeout)
    }

    /// Tests point this at a pty slave instead of the real terminal.
    pub fn with_tty(tty_path: PathBuf, timeout: Duration) -> Self {
        Self::with_limit(tty_path, timeout, super::MAX_PASSPHRASE_BYTES)
    }

    /// Tests also shrink the cap: a terminal in canonical mode will not hand
    /// over a line long enough to trip the real one.
    pub fn with_limit(tty_path: PathBuf, timeout: Duration, max_bytes: usize) -> Self {
        Self {
            timeout,
            tty_path,
            max_bytes,
            serialize: tokio::sync::Mutex::new(()),
        }
    }
}

#[async_trait::async_trait]
impl PassphrasePrompt for TtyPrompt {
    async fn prompt(&self, request: &PassphraseRequest) -> Result<Zeroizing<Vec<u8>>, PromptError> {
        let _one_at_a_time = self.serialize.lock().await;

        let message = request.describe();
        let read = read_passphrase(&self.tty_path, &message, self.max_bytes);
        match tokio::time::timeout(self.timeout, read).await {
            Ok(Ok(Some(secret))) => Ok(secret),
            // More than a typed line: refused rather than buffered, so the
            // capped allocation is never outgrown.
            Ok(Ok(None)) => Err(PromptError::TooLong(self.max_bytes)),
            Ok(Err(e)) => Err(PromptError::Unavailable(format!(
                "{}: {e}",
                self.tty_path.display()
            ))),
            // Nobody typed anything. Indistinguishable from a refusal, and
            // treated as one.
            Err(_) => {
                tracing::info!("passphrase entry timed out");
                Err(PromptError::Cancelled)
            }
        }
    }
}

/// Restores the terminal's original mode when dropped.
///
/// A guard, not a call at the end: the deadline drops this future mid-read, so
/// only unwinding can guarantee echo comes back. A terminal left with `ECHO`
/// off is invisible until the user types and sees nothing.
struct TerminalMode {
    fd: std::os::unix::io::RawFd,
    original: libc::termios,
    /// Whether anything still queued belongs to a passphrase.
    discard_input: bool,
}

impl TerminalMode {
    /// Turn echo off, refusing anything that is not a terminal.
    ///
    /// A non-terminal has no echo to disable, so typing into it would be
    /// visible — better to report no usable prompt than to read a passphrase
    /// in the clear.
    fn hide_input(file: &std::fs::File) -> std::io::Result<Self> {
        let fd = file.as_raw_fd();
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr fills the struct it is given, or fails.
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: tcgetattr returned success, so the struct is initialized.
        let original = unsafe { original.assume_init() };

        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        // Canonical mode still applies, so the terminal assembles the line and
        // hands it over on Enter; only the echoing of it is suppressed.
        apply(fd, &hidden)?;
        Ok(Self {
            fd,
            original,
            discard_input: true,
        })
    }

    /// Entry finished: the line was consumed through its newline, so anything
    /// still queued is type-ahead meant for whatever runs next, not part of a
    /// passphrase. Keep it.
    const fn keep_queued_input(&mut self) {
        self.discard_input = false;
    }
}

/// Split out so its failure edge can be excluded from coverage: `tcgetattr`
/// has just accepted this descriptor, so it is a terminal, and applying a
/// termios that came from it cannot be made to fail from a test. Silently
/// ignoring the result is not an option — that would echo the passphrase.
#[cfg_attr(coverage_nightly, coverage(off))]
fn apply(fd: std::os::unix::io::RawFd, mode: &libc::termios) -> std::io::Result<()> {
    // SAFETY: fd is a terminal, and `mode` is a valid termios for it.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, mode) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        // Bytes typed before giving up stay in the terminal's canonical queue,
        // where the next reader gets them — usually the shell, which would echo
        // the passphrase and run it as a command. This is the last point that
        // controls them.
        //
        // Only when entry did not finish: after a completed line the queue
        // holds type-ahead meant for whatever runs next.
        //
        // Best effort: nothing useful follows a failure, and Drop must not
        // panic while a signature is being abandoned.
        if self.discard_input {
            // SAFETY: tcflush only acts on the descriptor it is given.
            unsafe { libc::tcflush(self.fd, libc::TCIFLUSH) };
        }
        // SAFETY: fd was a terminal when the guard was built, and `original`
        // came from tcgetattr on it.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &raw const self.original) };
    }
}

/// Show the prompt and read one line, echo suppressed throughout.
///
/// `Ok(None)` means the line ran past `max_bytes` and was refused.
async fn read_passphrase(
    path: &std::path::Path,
    message: &str,
    max_bytes: usize,
) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    let terminal = tty::open(path)?;

    // Anything typed before the prompt appeared was meant for something else.
    // Left queued it would be read as the passphrase — and with echo off the
    // user would never see that it had been.
    tty::discard_pending_input(&terminal);

    // Declared *after* `terminal` on purpose: locals drop in reverse order, so
    // the guard restores the terminal while the descriptor is still open. Built
    // first, it would restore through a closed fd and silently do nothing.
    let hidden = TerminalMode::hide_input(terminal.get_ref())?;

    let prompt = format!("\n{message}\nPassphrase (not echoed): ");
    tty::write_all(&terminal, prompt.as_bytes()).await?;

    // Allocated once, up front: growing this buffer would copy the bytes
    // typed so far into a new allocation and free the old one unwiped,
    // leaving fragments of the passphrase behind that zeroizing the final
    // buffer cannot reach.
    let mut secret: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(max_bytes));
    let mut too_long = false;
    loop {
        let mut byte = Zeroizing::new([0u8; 1]);
        tty::read_once(&terminal, &mut byte[..]).await?;
        if byte[0] == b'\n' {
            break;
        }
        if secret.len() == max_bytes {
            // Keep draining to the newline rather than returning here: the
            // rest of the line would otherwise be left queued and read as the
            // answer to the next prompt.
            too_long = true;
            continue;
        }
        secret.push(byte[0]);
    }
    // Echo is off, so the user's Enter never moved the cursor.
    tty::write_all(&terminal, b"\n").await?;
    let mut hidden = hidden;
    hidden.keep_queued_input();
    drop(hidden);

    // No trailing-CR trim: the terminal is left in canonical mode, where
    // ICRNL has already turned a typed carriage return into the newline that
    // ends the line, so one can never reach the end of `secret`.
    Ok((!too_long).then_some(secret))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testutil::open_pty;
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::path::Path;
    use std::time::Instant;

    fn request() -> PassphraseRequest {
        PassphraseRequest {
            key_name: "tty key".into(),
            fingerprint: "SHA256:tty".into(),
            item_id: "1".into(),
            master_password: false,
        }
    }

    /// Block until the prompt has been written to the terminal, then answer it.
    ///
    /// Sleeping a fixed time instead would make every test here flaky by
    /// construction: anything typed before the prompt appears is deliberately
    /// discarded, so on a slow run the answer is flushed and the prompt waits
    /// out its whole timeout. Reading the banner is the only reliable signal
    /// that the reader is listening.
    fn answer_prompt(master: &mut File, answer: &[u8]) {
        const BANNER: &[u8] = b"Passphrase (not echoed): ";
        let mut seen: Vec<u8> = Vec::new();
        let mut buf = [0u8; 512];
        while !seen.windows(BANNER.len()).any(|window| window == BANNER) {
            let read = master.read(&mut buf).expect("the pty stays open");
            seen.extend_from_slice(&buf[..read]);
        }
        master.write_all(answer).unwrap();
    }

    fn echo_is_on(file: &File) -> bool {
        let mut mode = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr fills the struct or fails.
        assert_eq!(
            unsafe { libc::tcgetattr(file.as_raw_fd(), mode.as_mut_ptr()) },
            0
        );
        // SAFETY: initialized by the successful call above.
        (unsafe { mode.assume_init() }.c_lflag & libc::ECHO) != 0
    }

    #[tokio::test]
    async fn a_typed_line_is_returned_and_never_echoed() {
        let (mut master, keepalive, slave_path) = open_pty();
        let prompt = TtyPrompt::with_tty(slave_path, Duration::from_secs(10));
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, b"correct horse\n");
            master
        });
        let secret = prompt.prompt(&request()).await.unwrap();
        assert_eq!(&*secret, b"correct horse");
        // Checked while the master is still open: closing it hangs the pty up,
        // after which tcgetattr on the slave fails and proves nothing.
        assert!(echo_is_on(&keepalive), "echo must be restored");
        drop(typist.await.unwrap());
    }

    #[tokio::test]
    async fn a_half_typed_passphrase_does_not_survive_a_timeout() {
        // The hazard this guards: entry gives up while a passphrase is
        // half-typed, those bytes stay in the terminal's queue, and the next
        // reader — normally the user's shell — receives them when the line is
        // finished. It would echo the passphrase and run it as a command.
        let (mut master, _keepalive, slave_path) = open_pty();
        let prompt = TtyPrompt::with_tty(slave_path.clone(), Duration::from_millis(300));
        let typist = tokio::task::spawn_blocking(move || {
            // no newline: entry times out mid-passphrase
            answer_prompt(&mut master, b"half-typed-secret");
            master
        });
        assert_eq!(
            prompt.prompt(&request()).await.unwrap_err(),
            PromptError::Cancelled
        );
        let mut master = typist.await.unwrap();

        // The user finishes the line after the prompt has gone away.
        master.write_all(b"\n").unwrap();
        // Read as any ordinary consumer of the terminal would, without the
        // flush our own prompts do on the way in.
        let leftover = read_available(&slave_path);
        assert_eq!(
            leftover,
            b"\n",
            "typed bytes escaped to the next reader: {}",
            String::from_utf8_lossy(&leftover)
        );
    }

    /// Read whatever the terminal will hand over right now, as a plain reader.
    fn read_available(slave_path: &Path) -> Vec<u8> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut reader = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(slave_path)
            .unwrap();
        // give the line discipline a moment to deliver the completed line
        std::thread::sleep(Duration::from_millis(100));
        let mut buf = [0u8; 256];
        // nothing queued at all is also a pass
        reader
            .read(&mut buf)
            .map_or_else(|_| Vec::new(), |read| buf[..read].to_vec())
    }

    #[tokio::test]
    async fn a_passphrase_may_contain_spaces_and_survives_verbatim() {
        let (mut master, _keepalive, slave_path) = open_pty();
        let prompt = TtyPrompt::with_tty(slave_path, Duration::from_secs(10));
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, b"  leading and trailing  \n");
            master
        });
        let secret = prompt.prompt(&request()).await.unwrap();
        assert_eq!(&*secret, b"  leading and trailing  ");
        drop(typist.await.unwrap());
    }

    #[tokio::test]
    async fn the_terminal_turns_a_typed_return_into_the_line_ending() {
        // Why no trailing-CR trim is needed: ICRNL is still in effect, so the
        // carriage return arrives as the newline that ends the line.
        let (mut master, _keepalive, slave_path) = open_pty();
        let prompt = TtyPrompt::with_tty(slave_path, Duration::from_secs(10));
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, b"secret\r\n");
            master
        });
        let secret = prompt.prompt(&request()).await.unwrap();
        assert_eq!(&*secret, b"secret");
        drop(typist.await.unwrap());
    }

    #[tokio::test]
    async fn silence_times_out_as_a_refusal_and_restores_the_terminal() {
        let (master, keepalive, slave_path) = open_pty();
        let prompt = TtyPrompt::with_tty(slave_path, Duration::from_millis(200));
        let start = Instant::now();
        assert_eq!(
            prompt.prompt(&request()).await.unwrap_err(),
            PromptError::Cancelled
        );
        assert!(start.elapsed() >= Duration::from_millis(200));
        assert!(start.elapsed() < Duration::from_secs(30));
        // the deadline drops the read mid-line; echo must still come back
        assert!(echo_is_on(&keepalive), "echo must be restored on timeout");
        drop(master);
    }

    #[tokio::test]
    async fn input_typed_before_the_prompt_is_discarded() {
        // With echo off the user cannot see that a stale line was consumed as
        // their passphrase, so it must be flushed rather than read.
        let (mut master, _keepalive, slave_path) = open_pty();
        master.write_all(b"stale\n").unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let prompt = TtyPrompt::with_tty(slave_path, Duration::from_millis(400));
        assert_eq!(
            prompt.prompt(&request()).await.unwrap_err(),
            PromptError::Cancelled,
            "stale input must not be taken as the passphrase"
        );
    }

    #[tokio::test]
    async fn a_missing_terminal_reports_no_prompt_available() {
        let prompt = TtyPrompt::with_tty(PathBuf::from("/nonexistent/tty"), Duration::from_secs(1));
        let error = prompt.prompt(&request()).await.unwrap_err();
        assert!(matches!(error, PromptError::Unavailable(_)), "{error:?}");
    }

    #[tokio::test]
    async fn an_overlong_line_is_refused_and_not_left_queued() {
        // The cap exists so the buffer is never grown; input past it is
        // refused rather than truncated into a passphrase the user did not
        // type. The rest of the line must be consumed too, or it would answer
        // the next prompt.
        let (mut master, _keepalive, slave_path) = open_pty();
        let prompt = std::sync::Arc::new(TtyPrompt::with_limit(
            slave_path,
            Duration::from_secs(10),
            8,
        ));
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, b"far too long to be accepted\n");
            answer_prompt(&mut master, b"short\n");
            master
        });
        assert_eq!(
            prompt.prompt(&request()).await.unwrap_err(),
            PromptError::TooLong(8)
        );
        // the next entry gets its own line, not the tail of the last one
        let next = prompt.prompt(&request()).await.unwrap();
        assert_eq!(&*next, b"short");
        drop(typist.await.unwrap());
    }

    #[tokio::test]
    async fn a_line_exactly_at_the_cap_is_accepted() {
        let (mut master, _keepalive, slave_path) = open_pty();
        let prompt = TtyPrompt::with_limit(slave_path, Duration::from_secs(10), 8);
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, b"12345678\n");
            master
        });
        assert_eq!(&*prompt.prompt(&request()).await.unwrap(), b"12345678");
        drop(typist.await.unwrap());
    }

    #[tokio::test]
    async fn a_target_the_event_loop_rejects_is_refused() {
        // A regular file cannot be registered for readiness at all.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-tty");
        std::fs::write(&path, b"").unwrap();
        let prompt = TtyPrompt::with_tty(path, Duration::from_secs(1));
        let error = prompt.prompt(&request()).await.unwrap_err();
        assert!(matches!(error, PromptError::Unavailable(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_pollable_target_that_is_not_a_terminal_is_refused() {
        // A pipe registers with the event loop happily, but has no echo to
        // switch off — a passphrase typed at it would be visible. Refuse
        // rather than read one in the clear.
        use std::os::unix::ffi::OsStrExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo");
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: mkfifo only reads the path it is given.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let prompt = TtyPrompt::with_tty(path, Duration::from_secs(1));
        let error = prompt.prompt(&request()).await.unwrap_err();
        assert!(matches!(error, PromptError::Unavailable(_)), "{error:?}");
    }

    #[tokio::test]
    async fn concurrent_entries_are_serialized_one_answer_each() {
        let (master, _keepalive, slave_path) = open_pty();
        let prompt = std::sync::Arc::new(TtyPrompt::with_tty(slave_path, Duration::from_secs(10)));
        let typist = tokio::task::spawn_blocking(move || {
            let mut master = master;
            answer_prompt(&mut master, b"first\n");
            answer_prompt(&mut master, b"second\n");
            master
        });

        let (a, b) = tokio::join!(
            {
                let p = prompt.clone();
                async move { p.prompt(&request()).await }
            },
            {
                let p = prompt.clone();
                async move { p.prompt(&request()).await }
            },
        );
        drop(typist.await.unwrap());
        // each answer went to exactly one waiter, neither got both lines
        let mut answers = [a.unwrap().to_vec(), b.unwrap().to_vec()];
        answers.sort_unstable();
        assert_eq!(answers, [b"first".to_vec(), b"second".to_vec()]);
    }
}
