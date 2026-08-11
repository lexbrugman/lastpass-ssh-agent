//! Where the passphrase of an encrypted private key comes from.
//!
//! `LastPass` is always asked first. Only an *empty* `Passphrase` field hands
//! over to the configured fallback: a populated one is authoritative, and a
//! populated-but-wrong one fails the signature rather than opening a prompt.
//! That distinction is the whole point — if a wrong vault value fell through
//! to a local prompt, anything able to draw a dialog could unlock a key whose
//! passphrase the vault pins.
//!
//! Nothing here logs, formats or stores a passphrase. Secrets travel in
//! `Zeroizing` buffers and are wiped when the signature is done.

mod askpass;
mod osascript;
mod tty;

pub use askpass::AskpassPrompt;
pub use osascript::OsascriptPrompt;
pub use tty::TtyPrompt;

use zeroize::Zeroizing;

use crate::config::PassphraseFallback;
use crate::keystore::KeyEntry;
use crate::lpass::LpassClient;
use crate::text::escape_for_display;

/// What the user is being asked to unlock. Display context only — no secret
/// belongs in here. `key_name` comes from the vault and is escaped before any
/// implementation renders it.
#[derive(Debug, Clone)]
pub struct PassphraseRequest {
    pub key_name: String,
    pub fingerprint: String,
    pub item_id: String,
}

impl PassphraseRequest {
    pub fn new(entry: &KeyEntry) -> Self {
        Self {
            key_name: entry.name.clone(),
            fingerprint: entry.fingerprint(),
            item_id: entry.item_id.clone(),
        }
    }

    /// The text a prompt shows. Enough to tell two keys apart, and escaped:
    /// a vault-controlled name must not be able to redraw a terminal or
    /// reverse the line that says which key is being unlocked.
    pub fn describe(&self) -> String {
        format!(
            "Enter passphrase for SSH key\n\nKey: {}\nFingerprint: {}\nLastPass item: {}",
            escape_for_display(&self.key_name),
            escape_for_display(&self.fingerprint),
            escape_for_display(&self.item_id),
        )
    }
}

/// Why no passphrase was typed. Deliberately coarse: the reason is logged and
/// shown, so it must never carry anything the user entered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptError {
    /// The user dismissed the prompt, or it timed out.
    Cancelled,
    /// There is nowhere to ask: no terminal, no GUI session, no helper.
    Unavailable(String),
    /// More input arrived than a typed passphrase can be, so it was refused
    /// rather than buffered.
    TooLong(usize),
}

impl std::fmt::Display for PromptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("passphrase entry cancelled"),
            Self::Unavailable(why) => {
                write!(f, "no interactive passphrase prompt is available: {why}")
            }
            Self::TooLong(max) => write!(f, "passphrase longer than {max} bytes, refused"),
        }
    }
}

/// A passphrase is a line somebody types, and 1 KiB is far past what anyone
/// does. The cap is what lets every buffer holding one be allocated exactly
/// once: a `Vec` that never grows can never leave a copy of a secret behind in
/// freed memory, which zeroizing the final allocation would not undo. It also
/// bounds what a misbehaving helper can make the agent allocate. The
/// `LastPass` field reader is capped for the same two reasons.
///
/// It counts the answer as delivered, so a helper's trailing newline comes out
/// of the same allowance — at least 1022 bytes of passphrase always fit. The
/// exact boundary is not worth a second length check after stripping the
/// framing: the number is arbitrary, and no typed passphrase is near it.
const MAX_PASSPHRASE_BYTES: usize = 1024;

/// A prompt helper's pipe or exit could not be read.
///
/// A named function rather than an inline closure so its body is not a line of
/// its own in the coverage report: no test can make a helper's pipe error or
/// its `wait` fail once it has closed stdout, and excluding one shared mapping
/// beats excluding the readers that enforce the cap.
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "by value is what map_err hands a function; taking a reference \
              would require wrapping it in a closure, and that closure body \
              would be the uncovered line this exists to avoid"
)]
fn helper_failed(e: std::io::Error) -> PromptError {
    PromptError::Unavailable(format!("passphrase helper failed: {e}"))
}

/// Read a helper's answer into a buffer that is allocated once and wiped on
/// drop, refusing anything past the cap instead of growing to fit it.
async fn read_secret(
    pipe: &mut tokio::process::ChildStdout,
) -> Result<Zeroizing<Vec<u8>>, PromptError> {
    use tokio::io::AsyncReadExt as _;
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE_BYTES));
    let mut chunk = Zeroizing::new([0u8; 256]);
    loop {
        let read = pipe.read(&mut chunk[..]).await.map_err(helper_failed)?;
        if read == 0 {
            return Ok(out);
        }
        if out.len() + read > MAX_PASSPHRASE_BYTES {
            return Err(PromptError::TooLong(MAX_PASSPHRASE_BYTES));
        }
        out.extend_from_slice(&chunk[..read]);
    }
}

/// Read a helper's diagnostics, which say why it failed rather than what was
/// typed. Capped so a spewing helper cannot exhaust memory here either.
async fn read_diagnostics(pipe: &mut tokio::process::ChildStderr) -> Result<Vec<u8>, PromptError> {
    use tokio::io::AsyncReadExt as _;
    let mut out = Vec::new();
    pipe.take(4096)
        .read_to_end(&mut out)
        .await
        .map_err(helper_failed)?;
    Ok(out)
}

/// Wait for a prompt helper that has already closed its pipes.
async fn reap(child: &mut tokio::process::Child) -> Result<std::process::ExitStatus, PromptError> {
    child.wait().await.map_err(helper_failed)
}

/// Strip the single line ending a helper adds when printing the answer. Never
/// more than one: a passphrase may legitimately end in whitespace.
fn strip_line_ending(secret: &mut Zeroizing<Vec<u8>>) {
    if secret.last() == Some(&b'\n') {
        secret.pop();
        if secret.last() == Some(&b'\r') {
            secret.pop();
        }
    }
}

/// Asks the user for a passphrase, with the text hidden as it is typed.
///
/// Distinct from `Confirmer` on purpose. That one answers a yes/no question
/// and treats every failure as "deny"; this one returns secret input, so
/// "something went wrong" must never look like a successful empty answer.
#[async_trait::async_trait]
pub trait PassphrasePrompt: Send + Sync {
    async fn prompt(&self, request: &PassphraseRequest) -> Result<Zeroizing<Vec<u8>>, PromptError>;
}

/// The `Passphrase` field first, the configured fallback only if it is empty.
///
/// Returns the error text the signing path reports; it never contains key
/// material.
pub async fn resolve(
    lpass: &dyn LpassClient,
    prompt: &dyn PassphrasePrompt,
    entry: &KeyEntry,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let stored: Zeroizing<Vec<u8>> = lpass
        .show_field(&entry.item_id, "Passphrase")
        .await
        .map_err(|e| format!("fetching passphrase: {e}"))?;

    // Not trimmed: a passphrase may legitimately begin or end with a space,
    // and trimming one to nothing would silently divert to the fallback.
    if !stored.is_empty() {
        tracing::debug!(item = %entry.item_id, source = "lastpass", "passphrase resolved");
        return Ok(stored);
    }

    match entry.passphrase_fallback {
        // Word-for-word what the agent said before a fallback existed, so
        // configuring this mode reproduces the old behaviour exactly.
        PassphraseFallback::Error => Err(
            "private key is passphrase-protected but the item's Passphrase field is empty".into(),
        ),
        PassphraseFallback::Prompt => {
            let request = PassphraseRequest::new(entry);
            let typed = prompt.prompt(&request).await.map_err(|e| format!("{e}"))?;
            if typed.is_empty() {
                // An encrypted key cannot have an empty passphrase, so this
                // is a stray return keypress rather than an answer. Saying so
                // beats a bare "decrypting private key failed".
                return Err("no passphrase entered".into());
            }
            tracing::debug!(item = %entry.item_id, source = "prompt", "passphrase resolved");
            Ok(typed)
        }
    }
}

/// Build the prompt selected by the config.
///
/// It follows the confirmation transport: whoever set `confirm` has already
/// said how they can be reached. `confirm = "off"` is not such a statement —
/// it means "stop asking me to approve signatures", not "I am unreachable" —
/// so that case takes the platform default instead.
pub fn from_config(
    config: &crate::config::Config,
) -> crate::error::Result<std::sync::Arc<dyn PassphrasePrompt>> {
    use crate::config::ConfirmMode;
    use std::time::Duration;
    let timeout = Duration::from_secs(config.confirm_timeout_secs);
    Ok(match config.confirm {
        ConfirmMode::Osascript => std::sync::Arc::new(OsascriptPrompt::new(timeout)),
        ConfirmMode::Tty => std::sync::Arc::new(TtyPrompt::new(timeout)),
        ConfirmMode::Askpass => {
            // validated at config load
            let program = config.askpass.clone().ok_or_else(|| {
                crate::error::Error::ConfigInvalid("askpass mode without helper".into())
            })?;
            std::sync::Arc::new(AskpassPrompt::new(program, timeout))
        }
        ConfirmMode::Off => default_prompt(timeout),
    })
}

/// The platform's native prompt, for when `confirm` names no transport.
#[cfg(target_os = "macos")]
fn default_prompt(timeout: std::time::Duration) -> std::sync::Arc<dyn PassphrasePrompt> {
    std::sync::Arc::new(OsascriptPrompt::new(timeout))
}

#[cfg(not(target_os = "macos"))]
fn default_prompt(timeout: std::time::Duration) -> std::sync::Arc<dyn PassphrasePrompt> {
    std::sync::Arc::new(TtyPrompt::new(timeout))
}

/// Refuses every request, so a test can prove the prompt was never reached —
/// and that a case which does reach it fails rather than quietly succeeding.
///
/// Test-only: every configuration resolves to a real transport, because
/// `passphrase_fallback` is per-key and no single key's setting can rule
/// prompting out for the agent as a whole.
#[cfg(test)]
pub struct NoPrompt;

#[cfg(test)]
#[async_trait::async_trait]
impl PassphrasePrompt for NoPrompt {
    async fn prompt(
        &self,
        _request: &PassphraseRequest,
    ) -> Result<Zeroizing<Vec<u8>>, PromptError> {
        Err(PromptError::Unavailable(
            "passphrase prompting is disabled".into(),
        ))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::lpass::mock::MockLpass;
    use std::sync::Mutex;

    const ED25519_PUB: &str = include_str!("../tests/fixtures/ed25519.pub");

    fn entry(fallback: PassphraseFallback) -> KeyEntry {
        KeyEntry {
            item_id: "1".into(),
            name: "pw key".into(),
            public: ssh_key::PublicKey::from_openssh(ED25519_PUB.trim()).unwrap(),
            confirm: false,
            passphrase_fallback: fallback,
        }
    }

    /// An item whose `Passphrase` field exists but holds nothing — the one
    /// state that hands over to the fallback.
    fn empty_field() -> MockLpass {
        MockLpass::logged_in().with_field("1", "Passphrase", b"")
    }

    /// Answers with a fixed secret and records every call, so a test can
    /// prove the prompt was or was not consulted.
    #[derive(Default)]
    struct FakePrompt {
        answer: Option<Vec<u8>>,
        error: Option<PromptError>,
        calls: Mutex<Vec<String>>,
    }

    impl FakePrompt {
        fn answering(secret: &[u8]) -> Self {
            Self {
                answer: Some(secret.to_vec()),
                ..Self::default()
            }
        }
        fn failing(error: PromptError) -> Self {
            Self {
                error: Some(error),
                ..Self::default()
            }
        }
        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl PassphrasePrompt for FakePrompt {
        async fn prompt(
            &self,
            request: &PassphraseRequest,
        ) -> Result<Zeroizing<Vec<u8>>, PromptError> {
            self.calls.lock().unwrap().push(request.describe());
            match (&self.answer, &self.error) {
                (Some(secret), _) => Ok(Zeroizing::new(secret.clone())),
                (None, Some(error)) => Err(error.clone()),
                // nothing configured: an empty answer, as a stray Enter gives
                (None, None) => Ok(Zeroizing::new(Vec::new())),
            }
        }
    }

    #[tokio::test]
    async fn a_populated_field_wins_and_never_prompts() {
        // The precedence rule: LastPass is authoritative, so no fallback runs.
        for fallback in [PassphraseFallback::Prompt, PassphraseFallback::Error] {
            let lpass = MockLpass::logged_in().with_field("1", "Passphrase", b"from-vault");
            let prompt = FakePrompt::answering(b"from-prompt");
            let resolved = resolve(&lpass, &prompt, &entry(fallback)).await.unwrap();
            assert_eq!(&*resolved, b"from-vault");
            assert_eq!(prompt.call_count(), 0, "{fallback:?} must not prompt");
        }
    }

    #[tokio::test]
    async fn a_field_of_only_spaces_is_a_passphrase_not_an_absence() {
        // Trimming would divert a legitimate passphrase to the fallback.
        let lpass = MockLpass::logged_in().with_field("1", "Passphrase", b"  ");
        let prompt = FakePrompt::answering(b"from-prompt");
        let resolved = resolve(&lpass, &prompt, &entry(PassphraseFallback::Prompt))
            .await
            .unwrap();
        assert_eq!(&*resolved, b"  ");
        assert_eq!(prompt.call_count(), 0);
    }

    #[tokio::test]
    async fn an_empty_field_with_error_mode_keeps_the_original_message() {
        let lpass = empty_field();
        let prompt = FakePrompt::answering(b"from-prompt");
        let error = resolve(&lpass, &prompt, &entry(PassphraseFallback::Error))
            .await
            .unwrap_err();
        assert_eq!(
            error,
            "private key is passphrase-protected but the item's Passphrase field is empty"
        );
        assert_eq!(prompt.call_count(), 0);
    }

    #[tokio::test]
    async fn an_empty_field_with_prompt_mode_asks_and_shows_which_key() {
        let lpass = empty_field();
        let prompt = FakePrompt::answering(b"typed");
        let resolved = resolve(&lpass, &prompt, &entry(PassphraseFallback::Prompt))
            .await
            .unwrap();
        assert_eq!(&*resolved, b"typed");
        let shown = &prompt.calls.lock().unwrap()[0];
        assert!(shown.contains("pw key"), "{shown}");
        assert!(shown.contains("SHA256:"), "{shown}");
    }

    #[tokio::test]
    async fn a_cancelled_prompt_and_an_unavailable_one_report_differently() {
        let lpass = empty_field();
        let cancelled = resolve(
            &lpass,
            &FakePrompt::failing(PromptError::Cancelled),
            &entry(PassphraseFallback::Prompt),
        )
        .await
        .unwrap_err();
        assert_eq!(cancelled, "passphrase entry cancelled");

        let unavailable = resolve(
            &lpass,
            &FakePrompt::failing(PromptError::Unavailable("no tty".into())),
            &entry(PassphraseFallback::Prompt),
        )
        .await
        .unwrap_err();
        assert!(unavailable.contains("no interactive passphrase prompt"));
        assert!(unavailable.contains("no tty"));

        let too_long = resolve(
            &lpass,
            &FakePrompt::failing(PromptError::TooLong(1024)),
            &entry(PassphraseFallback::Prompt),
        )
        .await
        .unwrap_err();
        assert_eq!(too_long, "passphrase longer than 1024 bytes, refused");
    }

    #[tokio::test]
    async fn an_empty_answer_is_rejected_rather_than_attempted() {
        let lpass = empty_field();
        let prompt = FakePrompt::default(); // answers with nothing
        let error = resolve(&lpass, &prompt, &entry(PassphraseFallback::Prompt))
            .await
            .unwrap_err();
        assert_eq!(error, "no passphrase entered");
    }

    #[tokio::test]
    async fn a_broken_field_fetch_fails_without_falling_back() {
        // A vault that cannot answer is not the same as a vault that answers
        // "empty" — only the latter hands over to the fallback.
        let lpass = MockLpass::logged_in().with_broken_field("1", "Passphrase");
        let prompt = FakePrompt::answering(b"typed");
        let error = resolve(&lpass, &prompt, &entry(PassphraseFallback::Prompt))
            .await
            .unwrap_err();
        assert!(error.starts_with("fetching passphrase:"), "{error}");
        assert_eq!(prompt.call_count(), 0);
    }

    #[tokio::test]
    async fn no_prompt_refuses_every_request() {
        let error = NoPrompt
            .prompt(&PassphraseRequest::new(&entry(PassphraseFallback::Prompt)))
            .await
            .unwrap_err();
        assert!(matches!(error, PromptError::Unavailable(_)));
    }

    #[test]
    fn from_config_selects_a_prompt_for_every_confirm_mode() {
        let build = |s: &str| {
            let config: Config = toml::from_str(s).unwrap();
            from_config(&config)
        };
        // including "off": that setting silences approval, it does not claim
        // the user cannot be reached
        assert!(build("confirm = \"off\"").is_ok());
        assert!(build("confirm = \"osascript\"").is_ok());
        assert!(build("confirm = \"tty\"").is_ok());
        assert!(build("confirm = \"askpass\"\naskpass = \"/bin/true\"").is_ok());
        // defensive branch: config validation normally rejects this
        assert!(build("confirm = \"askpass\"").is_err());
    }

    #[test]
    fn untrusted_key_names_cannot_redraw_the_prompt() {
        let mut spoofed = entry(PassphraseFallback::Prompt);
        spoofed.name = "innocent\r\n\x1b[2JKey: safe".into();
        let text = PassphraseRequest::new(&spoofed).describe();
        assert!(!text.contains('\x1b'), "{text}");
        assert!(!text.contains('\r'), "{text}");
        assert_eq!(text.lines().filter(|l| l.starts_with("Key: ")).count(), 1);
    }
}
