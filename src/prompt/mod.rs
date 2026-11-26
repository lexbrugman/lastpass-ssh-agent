//! How the agent reaches the user.
//!
//! Three transports — a terminal, a helper program following the `SSH_ASKPASS`
//! convention, and a macOS dialog — and two questions each of them can put: a
//! yes/no one, and one answered with a secret. A transport owns the mechanics
//! of reaching the user — opening the terminal, spawning the helper, drawing
//! the dialog, the deadline, one prompt at a time — and nothing about what an
//! answer means. That is the callers' business: `confirm` fails closed, and
//! `passphrase` has to say why a secret did not arrive.

mod askpass;
mod osascript;
mod tty;

pub use askpass::AskpassTransport;
pub use osascript::OsascriptTransport;
pub use tty::TtyTransport;

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::passphrase::MAX_PASSPHRASE_BYTES;

/// Why a question got no answer. Deliberately coarse: a reason is logged and
/// shown, so it must never carry anything the user typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Nobody answered before the deadline.
    TimedOut,
    /// There is nowhere to ask — no terminal, no GUI session, no helper — or
    /// the one there is failed, with its own account of why.
    Unavailable(String),
    /// More arrived than an answer can be, so it was refused rather than
    /// buffered.
    TooLong(usize),
}

/// One way of reaching the user.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Put a yes/no question. `Ok(true)` is a yes; `Ok(false)` is anything
    /// the user did short of one, a refusal and a dismissal alike. `caution`
    /// marks a question to stop and read, for a transport that can make one
    /// look different from the rest.
    async fn ask_to_confirm(&self, message: &str, caution: bool) -> Result<bool, Failure>;

    /// Ask for a secret, hidden as it is typed. `Ok(None)` is a dismissal: the
    /// user chose not to answer, which is not an empty answer.
    async fn ask_for_secret(&self, message: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Failure>;
}

/// The transport the config selects, or `None` for `confirm = "off"`, which
/// names none: that means "stop asking me to approve signatures", not "I am
/// unreachable", and a caller that still needs one takes `default_transport`.
pub fn from_config(
    config: &crate::config::Config,
) -> crate::error::Result<Option<Arc<dyn Transport>>> {
    use crate::config::ConfirmMode;
    use std::time::Duration;
    let timeout = Duration::from_secs(config.confirm_timeout_secs);
    Ok(match config.confirm {
        ConfirmMode::Off => None,
        ConfirmMode::Osascript => Some(Arc::new(OsascriptTransport::new(timeout))),
        ConfirmMode::Tty => Some(Arc::new(TtyTransport::new(timeout))),
        ConfirmMode::Askpass => {
            // validated at config load
            let program = config.askpass.clone().ok_or_else(|| {
                crate::error::Error::ConfigInvalid("askpass mode without helper".into())
            })?;
            Some(Arc::new(AskpassTransport::new(program, timeout)))
        }
    })
}

/// The platform's native transport, for when `confirm` names none.
#[cfg(target_os = "macos")]
pub fn default_transport(timeout: std::time::Duration) -> Arc<dyn Transport> {
    Arc::new(OsascriptTransport::new(timeout))
}

#[cfg(not(target_os = "macos"))]
pub fn default_transport(timeout: std::time::Duration) -> Arc<dyn Transport> {
    Arc::new(TtyTransport::new(timeout))
}

/// A helper's pipe or exit could not be read.
///
/// A named function rather than an inline closure so its body is not a line of
/// its own in the coverage report: no test can make a helper's pipe error or
/// its `wait` fail once it has closed stdout, and excluding one shared mapping
/// beats excluding the readers that enforce the cap.
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::needless_pass_by_value,
    reason = "by value is what map_err hands a function; taking a reference \
              would require wrapping it in a closure, and that closure body \
              would be the uncovered line this exists to avoid"
)]
fn helper_failed(e: std::io::Error) -> Failure {
    Failure::Unavailable(format!("prompt helper failed: {e}"))
}

/// Read a helper's answer into a buffer that is allocated once and wiped on
/// drop, refusing anything past the cap instead of growing to fit it.
async fn read_secret(
    pipe: &mut tokio::process::ChildStdout,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    use tokio::io::AsyncReadExt as _;
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE_BYTES));
    let mut chunk = Zeroizing::new([0u8; 256]);
    loop {
        let read = pipe.read(&mut chunk[..]).await.map_err(helper_failed)?;
        if read == 0 {
            return Ok(out);
        }
        if out.len() + read > MAX_PASSPHRASE_BYTES {
            return Err(Failure::TooLong(MAX_PASSPHRASE_BYTES));
        }
        out.extend_from_slice(&chunk[..read]);
    }
}

/// Read a helper's diagnostics, which say why it failed rather than what was
/// typed. Capped so a spewing helper cannot exhaust memory here either.
async fn read_diagnostics(pipe: &mut tokio::process::ChildStderr) -> Result<Vec<u8>, Failure> {
    use tokio::io::AsyncReadExt as _;
    let mut out = Vec::new();
    pipe.take(4096)
        .read_to_end(&mut out)
        .await
        .map_err(helper_failed)?;
    Ok(out)
}

/// Wait for a helper that has already closed its pipes.
async fn reap(child: &mut tokio::process::Child) -> Result<std::process::ExitStatus, Failure> {
    child.wait().await.map_err(helper_failed)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn from_config_selects_a_transport_for_every_mode_but_off() {
        let build = |s: &str| {
            let config: Config = toml::from_str(s).unwrap();
            from_config(&config)
        };
        assert!(build("confirm = \"off\"").unwrap().is_none());
        assert!(build("confirm = \"osascript\"").unwrap().is_some());
        assert!(build("confirm = \"tty\"").unwrap().is_some());
        assert!(
            build("confirm = \"askpass\"\naskpass = \"/bin/true\"")
                .unwrap()
                .is_some()
        );
        // config load-time validation normally rejects this; the defensive
        // branch must fail rather than default to anything
        assert!(build("confirm = \"askpass\"").is_err());
    }
}
