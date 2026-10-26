//! The terminal transport, and the terminal mechanics under it.
//!
//! Both questions are one line typed at a prompt; they differ only in whether
//! the line is echoed and how long it may be. Opening the terminal, flushing
//! what is queued on it, setting its mode and reading the line live here once,
//! so the `unsafe` has one home and a terminal bug has one place to be fixed.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use zeroize::Zeroizing;

use super::{Failure, Transport};

/// Prompt on the agent's controlling terminal (`/dev/tty`). Useful when the
/// agent runs in a foreground terminal, and the default on Linux.
///
/// Prompts are strictly serialized: concurrent requests would otherwise
/// interleave their prompts and a single answer could go to a different
/// question than the one the user read. The whole exchange runs under one
/// deadline, so an expired prompt gives up instead of lingering and swallowing
/// input meant for the next one.
pub struct TtyTransport {
    timeout: Duration,
    tty_path: PathBuf,
    max_secret_bytes: usize,
    serialize: tokio::sync::Mutex<()>,
}

impl TtyTransport {
    pub fn new(timeout: Duration) -> Self {
        Self::with_tty(PathBuf::from("/dev/tty"), timeout)
    }

    /// Tests point this at a pty slave instead of the real terminal.
    pub fn with_tty(tty_path: PathBuf, timeout: Duration) -> Self {
        Self::with_limit(tty_path, timeout, crate::passphrase::MAX_PASSPHRASE_BYTES)
    }

    /// Tests also shrink the secret's cap: a terminal in canonical mode will
    /// not hand over a line long enough to trip the real one.
    pub fn with_limit(tty_path: PathBuf, timeout: Duration, max_secret_bytes: usize) -> Self {
        Self {
            timeout,
            tty_path,
            max_secret_bytes,
            serialize: tokio::sync::Mutex::new(()),
        }
    }

    /// One line typed at `prompt`, under the deadline.
    async fn read_line(
        &self,
        prompt: &str,
        echo: Echo,
        max_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let read = read_line(&self.tty_path, prompt, echo, max_bytes);
        match tokio::time::timeout(self.timeout, read).await {
            Ok(Ok(Some(line))) => Ok(line),
            // More than a typed line: refused rather than buffered, so the
            // capped allocation is never outgrown.
            Ok(Ok(None)) => Err(Failure::TooLong(max_bytes)),
            Ok(Err(e)) => Err(Failure::Unavailable(format!(
                "{}: {e}",
                self.tty_path.display()
            ))),
            Err(_) => Err(Failure::TimedOut),
        }
    }
}

/// The answer to a yes/no question is one short word, so this is already far
/// past anything real. It exists for the same reason every other reader here is
/// capped: nothing that arrives from outside gets to decide how much this
/// process allocates. The deadline alone is not a bound — at an hour, the most
/// a confirmation timeout can be, a terminal writing steadily would grow this
/// without limit.
const MAX_ANSWER_BYTES: usize = 64;

#[async_trait::async_trait]
impl Transport for TtyTransport {
    async fn ask_to_confirm(&self, message: &str) -> Result<bool, Failure> {
        // One prompt at a time; see the type's documentation.
        let _one_at_a_time = self.serialize.lock().await;
        let prompt = format!("\n{message}\nAllow? (type 'yes' to approve, anything else denies): ");
        let answer = self
            .read_line(&prompt, Echo::Shown, MAX_ANSWER_BYTES)
            .await?;
        Ok(answer.trim_ascii() == b"yes")
    }

    async fn ask_for_secret(&self, message: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Failure> {
        let _one_at_a_time = self.serialize.lock().await;
        let prompt = format!("\n{message}\nPassphrase (not echoed): ");
        // A terminal has no cancel button: the one way not to answer is not
        // to, and the deadline is what reports that.
        self.read_line(&prompt, Echo::Hidden, self.max_secret_bytes)
            .await
            .map(Some)
    }
}

/// Whether the line is shown as it is typed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Echo {
    Shown,
    Hidden,
}

/// A terminal opened for prompting, registered with the event loop.
type Terminal = AsyncFd<std::fs::File>;

/// Open a terminal and register it for readiness.
///
/// Our own open file description, so `O_NONBLOCK` is ours alone and cannot
/// change the behaviour of anything else sharing this terminal. Every wait on
/// the result is a cancellation point, which is what lets a caller impose a
/// deadline by dropping the future rather than by blocking with one.
fn open(path: &Path) -> std::io::Result<Terminal> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    // SAFETY: the descriptor stays open and unchanged for as long as it is
    // registered — the `File` is owned by the `AsyncFd`, which is what closes
    // it.
    unsafe { AsyncFd::register(tty) }.map_err(std::io::Error::from)
}

/// Drop anything typed before the prompt was shown.
///
/// Terminal input is queued in the terminal, not in our file description, so a
/// line finished after an earlier prompt gave up would still be sitting there.
/// Without this it would answer the *next* prompt — approving, or unlocking,
/// something the user never read. Best effort: a target that is not a terminal
/// has no queue to flush.
fn discard_pending_input(tty: &Terminal) {
    // SAFETY: tcflush only acts on the descriptor it is given.
    unsafe { libc::tcflush(tty.get_ref().as_raw_fd(), libc::TCIFLUSH) };
}

/// Wait for the terminal to have input, then read what fits in `buf`.
///
/// `async_io` owns the readiness dance, including the retry a spurious wakeup
/// demands — there is no reason to hand-roll that loop.
///
/// A zero-length read means the terminal hung up, which ends the exchange. That
/// edge is excluded from coverage because platforms disagree on how a hangup
/// surfaces — macOS reports `EIO` on a closed pty and will not even register
/// `/dev/null` with kqueue — so no single test reaches it on both.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn read_once(tty: &Terminal, buf: &mut [u8]) -> std::io::Result<()> {
    let read = tty
        .async_io(Interest::READABLE, |mut inner| inner.read(buf))
        .await?;
    if read == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    Ok(())
}

async fn write_all(tty: &Terminal, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        let written = tty
            .async_io(Interest::WRITABLE, |mut inner| inner.write(buf))
            .await?;
        buf = &buf[written..];
    }
    Ok(())
}

/// Restores the terminal's original mode when dropped.
///
/// A guard, not a call at the end: the deadline drops this future mid-read, so
/// only unwinding can guarantee the mode comes back. A terminal left with
/// `ECHO` off is invisible until the user types and sees nothing.
struct TerminalMode {
    fd: std::os::unix::io::RawFd,
    original: libc::termios,
    /// Whether anything still queued belongs to an answer.
    discard_input: bool,
}

impl TerminalMode {
    /// Put the terminal in line mode, with echo off when the line is a secret,
    /// refusing anything that is not a terminal.
    ///
    /// A non-terminal has no echo to disable, so typing a secret into it would
    /// be visible — better to report no usable prompt than to read a passphrase
    /// in the clear. A yes/no answer is refused the same way, so that what the
    /// two questions can be asked on does not differ.
    fn set(file: &std::fs::File, echo: Echo) -> std::io::Result<Self> {
        let fd = file.as_raw_fd();
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr fills the struct it is given, or fails.
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: tcgetattr returned success, so the struct is initialized.
        let original = unsafe { original.assume_init() };

        let mut mode = original;
        if echo == Echo::Hidden {
            mode.c_lflag &= !libc::ECHO;
        }
        // The terminal assembles the line and hands it over on Enter, a typed
        // carriage return arriving as the newline that ends it. Set rather
        // than inherited: a terminal some program left in raw mode would
        // otherwise hand over keystrokes one at a time, backspaces included,
        // and never the newline this waits for.
        mode.c_lflag |= libc::ICANON;
        mode.c_iflag |= libc::ICRNL;
        // IGNCR would discard the return before ICRNL could translate it,
        // and Enter would then never end the line.
        mode.c_iflag &= !libc::IGNCR;
        apply(fd, &mode)?;
        Ok(Self {
            fd,
            original,
            discard_input: true,
        })
    }

    /// The line was consumed through its newline, so anything still queued is
    /// type-ahead meant for whatever runs next, not part of an answer. Keep it.
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
        // a half-typed passphrase and run it as a command. This is the last
        // point that controls them.
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

/// Show the prompt and read one line.
///
/// `Ok(None)` means the line ran past `max_bytes` and was refused.
async fn read_line(
    path: &Path,
    prompt: &str,
    echo: Echo,
    max_bytes: usize,
) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    let terminal = open(path)?;

    // Anything typed before the prompt appeared was meant for something else.
    // Left queued it would be read as the answer — and with echo off the user
    // would never see that it had been.
    discard_pending_input(&terminal);

    // Declared *after* `terminal` on purpose: locals drop in reverse order, so
    // the guard restores the terminal while the descriptor is still open. Built
    // first, it would restore through a closed fd and silently do nothing.
    let mut mode = TerminalMode::set(terminal.get_ref(), echo)?;

    write_all(&terminal, prompt.as_bytes()).await?;

    // Allocated once, up front: growing this buffer would copy the bytes
    // typed so far into a new allocation and free the old one unwiped,
    // leaving fragments of a passphrase behind that zeroizing the final
    // buffer cannot reach. The same buffer for a yes/no answer, which costs
    // nothing and keeps one reader.
    let mut line: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(max_bytes));
    let mut too_long = false;
    loop {
        // A byte at a time, stopping at the newline: a larger read could
        // swallow input typed after the answer, which belongs to whatever
        // prompts next. Bytes rather than a `String`, because the terminal
        // delivers bytes and the cap counts them: decoded as `char`s, a byte
        // from 0x80 up would take two bytes of the buffer, and the length
        // could step over the limit without ever meeting it.
        let mut byte = Zeroizing::new([0u8; 1]);
        read_once(&terminal, &mut byte[..]).await?;
        if byte[0] == b'\n' {
            break;
        }
        if line.len() == max_bytes {
            // Keep draining to the newline rather than returning here: the
            // rest of the line would otherwise be left queued and read as the
            // answer to the next prompt.
            too_long = true;
            continue;
        }
        line.push(byte[0]);
    }
    if echo == Echo::Hidden {
        // Echo is off, so the user's Enter never moved the cursor.
        write_all(&terminal, b"\n").await?;
    }
    mode.keep_queued_input();
    drop(mode);

    // No trailing-CR trim: the terminal is left in canonical mode, where
    // ICRNL has already turned a typed carriage return into the newline that
    // ends the line, so one can never reach the end of `line`.
    Ok((!too_long).then_some(line))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testutil::open_pty;
    use std::fs::File;
    use std::time::Instant;

    const CONFIRM_BANNER: &[u8] = b"anything else denies): ";
    const SECRET_BANNER: &[u8] = b"Passphrase (not echoed): ";

    /// Block until `banner` has reached the terminal, then answer the prompt.
    ///
    /// Sleeping a fixed time instead would make these tests flaky by
    /// construction: input typed before the prompt appears is deliberately
    /// discarded, so on a slow run the answer is flushed and the prompt waits
    /// out its whole timeout. Reading the banner is the only reliable signal
    /// that the prompt is listening.
    fn answer_prompt(master: &mut File, banner: &[u8], answer: &[u8]) {
        let mut seen: Vec<u8> = Vec::new();
        let mut buf = [0u8; 512];
        while !seen.windows(banner.len()).any(|window| window == banner) {
            let read = master.read(&mut buf).expect("the pty stays open");
            seen.extend_from_slice(&buf[..read]);
        }
        master.write_all(answer).unwrap();
    }

    /// Long enough that it can only expire if something is badly wrong.
    ///
    /// These cases are about what an answer *means*, never how quickly it
    /// arrives — but an expired prompt fails, so a deadline tight enough to be
    /// reached under load turns into a wrong-looking result rather than a
    /// timeout. The answer is read one byte per readiness wakeup, so the
    /// longest of them needs sixty-odd round trips and is the first to feel a
    /// loaded machine. Tighten this and it flakes — around one run in ten with
    /// a second instrumented build alongside.
    const UNHURRIED: Duration = Duration::from_secs(120);

    /// Shared body for the yes/no cases, so each stays one line and still gets
    /// its own name and `cargo test` filter.
    async fn expect_verdict(typed: Vec<u8>, expected: Result<bool, Failure>) {
        let (mut master, _keepalive, slave_path) = open_pty();
        let transport = TtyTransport::with_tty(slave_path, UNHURRIED);
        let answer = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, CONFIRM_BANNER, &typed);
            master
        });
        assert_eq!(transport.ask_to_confirm("question").await, expected);
        drop(answer.await.unwrap());
    }

    #[tokio::test]
    async fn yes_is_a_yes() {
        expect_verdict(b"yes\n".to_vec(), Ok(true)).await;
    }

    #[tokio::test]
    async fn anything_else_is_a_no() {
        expect_verdict(b"no\n".to_vec(), Ok(false)).await;
    }

    #[tokio::test]
    async fn an_answer_may_be_padded_with_spaces() {
        expect_verdict(b"  yes  \n".to_vec(), Ok(true)).await;
    }

    #[tokio::test]
    async fn an_answer_exactly_at_the_cap_still_counts() {
        // The boundary belongs to the answer: the cap refuses what is past it,
        // not what reaches it.
        let mut typed = b"yes".to_vec();
        typed.resize(MAX_ANSWER_BYTES, b' ');
        typed.push(b'\n');
        expect_verdict(typed, Ok(true)).await;
    }

    #[tokio::test]
    async fn an_overlong_answer_is_refused_rather_than_buffered() {
        // The cap keeps an untrusted writer from growing this without bound.
        // A line past it is refused whatever its first bytes spell: taking a
        // prefix would read "yes" with something else after it as consent to
        // the something else.
        //
        // Padded with a byte above 0x7f on purpose. Counted as anything but raw
        // bytes — decoded to a `char` and pushed to a `String`, say — each of
        // these would take two bytes of the buffer, so the length would step
        // over the limit rather than land on it and the cap would never fire.
        let mut typed = b"yes".to_vec();
        typed.resize(MAX_ANSWER_BYTES * 2, 0xff);
        typed.push(b'\n');
        expect_verdict(typed, Err(Failure::TooLong(MAX_ANSWER_BYTES))).await;
    }

    #[tokio::test]
    async fn silence_times_out() {
        let (master, _keepalive, slave_path) = open_pty();
        let transport = TtyTransport::with_tty(slave_path, Duration::from_millis(200));
        let start = Instant::now();
        assert_eq!(
            transport.ask_to_confirm("question").await,
            Err(Failure::TimedOut)
        );
        // the deadline is honored in full: poll rounds its wait up, so an
        // expiry can never come early
        assert!(start.elapsed() >= Duration::from_millis(200));
        // generous hang-guard: parallel test load can starve the blocking pool
        assert!(start.elapsed() < Duration::from_secs(30));
        drop(master);
    }

    #[tokio::test]
    async fn an_answer_typed_before_the_question_is_discarded() {
        // The user answers an earlier prompt too late; that queued "yes"
        // must not silently approve the request that comes next.
        let (mut master, _keepalive, slave_path) = open_pty();
        master.write_all(b"yes\n").unwrap();
        // give the pty time to queue it before the prompt is shown
        tokio::time::sleep(Duration::from_millis(100)).await;

        let transport = TtyTransport::with_tty(slave_path, Duration::from_millis(400));
        assert_eq!(
            transport.ask_to_confirm("question").await,
            Err(Failure::TimedOut),
            "stale input must not answer a later prompt"
        );
    }

    #[tokio::test]
    async fn a_missing_terminal_is_unavailable_for_either_question() {
        let transport =
            TtyTransport::with_tty(PathBuf::from("/nonexistent/tty"), Duration::from_secs(1));
        assert!(matches!(
            transport.ask_to_confirm("question").await,
            Err(Failure::Unavailable(_))
        ));
        assert!(matches!(
            transport.ask_for_secret("question").await,
            Err(Failure::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_questions_are_serialized_one_answer_each() {
        let (master, _keepalive, slave_path) = open_pty();
        let transport = std::sync::Arc::new(TtyTransport::with_tty(slave_path, UNHURRIED));
        // Answer each prompt as it appears: input queued before a prompt is
        // discarded by design, and the second prompt only starts once the
        // first has been answered.
        let responder = tokio::task::spawn_blocking(move || {
            let mut master = master;
            answer_prompt(&mut master, CONFIRM_BANNER, b"yes\n");
            answer_prompt(&mut master, CONFIRM_BANNER, b"no\n");
            master
        });

        let (a, b) = tokio::join!(
            {
                let t = transport.clone();
                async move { t.ask_to_confirm("question").await }
            },
            {
                let t = transport.clone();
                async move { t.ask_to_confirm("question").await }
            },
        );
        drop(responder.await.unwrap());
        let yeses = [&a, &b].iter().filter(|v| ***v == Ok(true)).count();
        assert_eq!(yeses, 1, "got {a:?} and {b:?}");
    }

    fn echo_is_on(file: &File) -> bool {
        (termios_of(file).c_lflag & libc::ECHO) != 0
    }

    fn termios_of(file: &File) -> libc::termios {
        let mut mode = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr fills the struct or fails.
        assert_eq!(
            unsafe { libc::tcgetattr(file.as_raw_fd(), mode.as_mut_ptr()) },
            0
        );
        // SAFETY: initialized by the successful call above.
        unsafe { mode.assume_init() }
    }

    #[tokio::test]
    async fn a_typed_secret_is_returned_and_never_echoed() {
        let (mut master, keepalive, slave_path) = open_pty();
        let transport = TtyTransport::with_tty(slave_path, UNHURRIED);
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, SECRET_BANNER, b"correct horse\n");
            master
        });
        let secret = transport.ask_for_secret("key").await.unwrap().unwrap();
        assert_eq!(&*secret, b"correct horse");
        // Checked while the master is still open: closing it hangs the pty up,
        // after which tcgetattr on the slave fails and proves nothing.
        assert!(echo_is_on(&keepalive), "echo must be restored");
        drop(typist.await.unwrap());
    }

    #[tokio::test]
    async fn a_half_typed_secret_does_not_survive_a_timeout() {
        // The hazard this guards: entry gives up while a passphrase is
        // half-typed, those bytes stay in the terminal's queue, and the next
        // reader — normally the user's shell — receives them when the line is
        // finished. It would echo the passphrase and run it as a command.
        let (mut master, _keepalive, slave_path) = open_pty();
        let transport = TtyTransport::with_tty(slave_path.clone(), Duration::from_millis(300));
        let typist = tokio::task::spawn_blocking(move || {
            // no newline: entry times out mid-passphrase
            answer_prompt(&mut master, SECRET_BANNER, b"half-typed-secret");
            master
        });
        assert_eq!(
            transport.ask_for_secret("key").await,
            Err(Failure::TimedOut)
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
        let mut reader = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(slave_path)
            .unwrap();
        // give the line discipline a moment to deliver the completed line
        std::thread::sleep(Duration::from_millis(100));
        let mut buf = [0u8; 256];
        // Nothing delivered reads as nothing, which the caller's assertion then
        // fails on: the newline the user typed has to be there.
        reader
            .read(&mut buf)
            .map_or_else(|_| Vec::new(), |read| buf[..read].to_vec())
    }

    #[tokio::test]
    async fn a_secret_may_contain_spaces_and_survives_verbatim() {
        let (mut master, _keepalive, slave_path) = open_pty();
        let transport = TtyTransport::with_tty(slave_path, UNHURRIED);
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, SECRET_BANNER, b"  leading and trailing  \n");
            master
        });
        let secret = transport.ask_for_secret("key").await.unwrap().unwrap();
        assert_eq!(&*secret, b"  leading and trailing  ");
        drop(typist.await.unwrap());
    }

    /// Leave the terminal the way a program that quit in raw mode would.
    fn make_raw(slave_path: &Path) -> File {
        let slave = File::open(slave_path).unwrap();
        let mut mode = termios_of(&slave);
        mode.c_lflag &= !libc::ICANON;
        mode.c_iflag &= !libc::ICRNL;
        mode.c_iflag |= libc::IGNCR;
        // SAFETY: slave is a terminal and `mode` came from it.
        assert_eq!(
            unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &raw const mode) },
            0
        );
        slave
    }

    #[tokio::test]
    async fn a_terminal_left_in_raw_mode_is_read_a_line_at_a_time_anyway() {
        // Canonical mode and the CR-to-NL translation are set, not assumed,
        // so a terminal a previous program left raw still yields the line —
        // and is handed back raw, as it was found.
        let (mut master, _keepalive, slave_path) = open_pty();
        let slave = make_raw(&slave_path);
        let transport = TtyTransport::with_tty(slave_path, UNHURRIED);
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, SECRET_BANNER, b"secret\r");
            master
        });
        let secret = transport.ask_for_secret("key").await.unwrap().unwrap();
        assert_eq!(&*secret, b"secret");
        let after = termios_of(&slave);
        assert_eq!(after.c_lflag & libc::ICANON, 0);
        assert_eq!(after.c_iflag & libc::ICRNL, 0);
        assert_ne!(after.c_iflag & libc::IGNCR, 0);
        drop(typist.await.unwrap());
    }

    #[tokio::test]
    async fn a_yes_typed_at_a_raw_terminal_still_arrives() {
        // The same line mode for a yes/no answer: a raw terminal delivering
        // Enter as a bare return would otherwise leave the question waiting
        // for a newline that never comes, and every confirmation would time
        // out.
        let (mut master, _keepalive, slave_path) = open_pty();
        let _slave = make_raw(&slave_path);
        let transport = TtyTransport::with_tty(slave_path, UNHURRIED);
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, CONFIRM_BANNER, b"yes\r");
            master
        });
        assert_eq!(transport.ask_to_confirm("question").await, Ok(true));
        drop(typist.await.unwrap());
    }

    #[tokio::test]
    async fn the_terminal_turns_a_typed_return_into_the_line_ending() {
        // Why no trailing-CR trim is needed: ICRNL is still in effect, so the
        // carriage return arrives as the newline that ends the line.
        let (mut master, _keepalive, slave_path) = open_pty();
        let transport = TtyTransport::with_tty(slave_path, UNHURRIED);
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, SECRET_BANNER, b"secret\r\n");
            master
        });
        let secret = transport.ask_for_secret("key").await.unwrap().unwrap();
        assert_eq!(&*secret, b"secret");
        drop(typist.await.unwrap());
    }

    #[tokio::test]
    async fn a_secret_nobody_types_times_out_and_restores_the_terminal() {
        let (master, keepalive, slave_path) = open_pty();
        let transport = TtyTransport::with_tty(slave_path, Duration::from_millis(200));
        let start = Instant::now();
        assert_eq!(
            transport.ask_for_secret("key").await,
            Err(Failure::TimedOut)
        );
        assert!(start.elapsed() >= Duration::from_millis(200));
        assert!(start.elapsed() < Duration::from_secs(30));
        // the deadline drops the read mid-line; echo must still come back
        assert!(echo_is_on(&keepalive), "echo must be restored on timeout");
        drop(master);
    }

    #[tokio::test]
    async fn a_line_typed_before_the_secret_was_asked_for_is_discarded() {
        // With echo off the user cannot see that a stale line was consumed as
        // their passphrase, so it must be flushed rather than read.
        let (mut master, _keepalive, slave_path) = open_pty();
        master.write_all(b"stale\n").unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let transport = TtyTransport::with_tty(slave_path, Duration::from_millis(400));
        assert_eq!(
            transport.ask_for_secret("key").await,
            Err(Failure::TimedOut),
            "stale input must not be taken as the passphrase"
        );
    }

    #[tokio::test]
    async fn an_overlong_secret_is_refused_and_not_left_queued() {
        // The cap exists so the buffer is never grown; input past it is
        // refused rather than truncated into a passphrase the user did not
        // type. The rest of the line must be consumed too, or it would answer
        // the next prompt.
        let (mut master, _keepalive, slave_path) = open_pty();
        let transport = std::sync::Arc::new(TtyTransport::with_limit(slave_path, UNHURRIED, 8));
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, SECRET_BANNER, b"far too long to be accepted\n");
            answer_prompt(&mut master, SECRET_BANNER, b"short\n");
            master
        });
        assert_eq!(
            transport.ask_for_secret("key").await,
            Err(Failure::TooLong(8))
        );
        // the next entry gets its own line, not the tail of the last one
        let next = transport.ask_for_secret("key").await.unwrap().unwrap();
        assert_eq!(&*next, b"short");
        drop(typist.await.unwrap());
    }

    #[tokio::test]
    async fn a_secret_exactly_at_the_cap_is_accepted() {
        let (mut master, _keepalive, slave_path) = open_pty();
        let transport = TtyTransport::with_limit(slave_path, UNHURRIED, 8);
        let typist = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, SECRET_BANNER, b"12345678\n");
            master
        });
        assert_eq!(
            &*transport.ask_for_secret("key").await.unwrap().unwrap(),
            b"12345678"
        );
        drop(typist.await.unwrap());
    }

    #[tokio::test]
    async fn a_target_the_event_loop_rejects_is_refused() {
        // A regular file cannot be registered for readiness at all.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-tty");
        std::fs::write(&path, b"").unwrap();
        let transport = TtyTransport::with_tty(path, Duration::from_secs(1));
        assert!(matches!(
            transport.ask_for_secret("key").await,
            Err(Failure::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn a_pollable_target_that_is_not_a_terminal_is_refused() {
        // A pipe registers with the event loop happily, but has no line mode
        // to set and no echo to switch off — a passphrase typed at it would be
        // visible. Refuse rather than read one in the clear, for either
        // question.
        use std::os::unix::ffi::OsStrExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo");
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: mkfifo only reads the path it is given.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let transport = TtyTransport::with_tty(path, Duration::from_secs(1));
        assert!(matches!(
            transport.ask_for_secret("key").await,
            Err(Failure::Unavailable(_))
        ));
        assert!(matches!(
            transport.ask_to_confirm("question").await,
            Err(Failure::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_secrets_are_serialized_one_answer_each() {
        let (master, _keepalive, slave_path) = open_pty();
        let transport = std::sync::Arc::new(TtyTransport::with_tty(slave_path, UNHURRIED));
        let typist = tokio::task::spawn_blocking(move || {
            let mut master = master;
            answer_prompt(&mut master, SECRET_BANNER, b"first\n");
            answer_prompt(&mut master, SECRET_BANNER, b"second\n");
            master
        });

        let (a, b) = tokio::join!(
            {
                let t = transport.clone();
                async move { t.ask_for_secret("key").await }
            },
            {
                let t = transport.clone();
                async move { t.ask_for_secret("key").await }
            },
        );
        drop(typist.await.unwrap());
        // each answer went to exactly one waiter, neither got both lines
        let mut answers = [a.unwrap().unwrap().to_vec(), b.unwrap().unwrap().to_vec()];
        answers.sort_unstable();
        assert_eq!(answers, [b"first".to_vec(), b"second".to_vec()]);
    }
}
