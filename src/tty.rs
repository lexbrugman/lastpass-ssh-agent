//! The terminal mechanics shared by confirmation and passphrase entry.
//!
//! The two prompts answer to different rules — a confirmation fails closed, and
//! secret entry has to say why it failed — but the terminal underneath them is
//! the same one. Opening it, flushing what is queued on it, and moving bytes
//! over it live here rather than once in each, so the `unsafe` has one home and
//! a terminal bug has one place to be fixed.
//!
//! Echo suppression is deliberately not here: only passphrase entry turns it
//! off, and the guard that restores it belongs with the code that owns that
//! decision.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::io::AsRawFd as _;
use std::path::Path;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

/// A terminal opened for prompting, registered with the event loop.
pub type Terminal = AsyncFd<std::fs::File>;

/// Open a terminal and register it for readiness.
///
/// Our own open file description, so `O_NONBLOCK` is ours alone and cannot
/// change the behaviour of anything else sharing this terminal. Every wait on
/// the result is a cancellation point, which is what lets a caller impose a
/// deadline by dropping the future rather than by blocking with one.
pub fn open(path: &Path) -> std::io::Result<Terminal> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    AsyncFd::new(tty)
}

/// Drop anything typed before the prompt was shown.
///
/// Terminal input is queued in the terminal, not in our file description, so a
/// line finished after an earlier prompt gave up would still be sitting there.
/// Without this it would answer the *next* prompt — approving, or unlocking,
/// something the user never read. Best effort: a target that is not a terminal
/// has no queue to flush.
pub fn discard_pending_input(tty: &Terminal) {
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
pub async fn read_once(tty: &Terminal, buf: &mut [u8]) -> std::io::Result<()> {
    let read = tty
        .async_io(Interest::READABLE, |mut inner| inner.read(buf))
        .await?;
    if read == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    Ok(())
}

pub async fn write_all(tty: &Terminal, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        let written = tty
            .async_io(Interest::WRITABLE, |mut inner| inner.write(buf))
            .await?;
        buf = &buf[written..];
    }
    Ok(())
}
