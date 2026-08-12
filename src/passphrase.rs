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
// Excluded from coverage as a whole, which is the point of it being this
// small: every line in it talks to the real Keychain of whoever runs the
// tests, and the suite must never do that. The rules around these calls are
// covered through `PassphraseStore` fakes on every platform.
#[cfg(target_os = "macos")]
#[cfg_attr(coverage_nightly, coverage(off))]
mod keychain;
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
    /// Set when the secret wanted is the vault's own master password rather
    /// than one key's passphrase. The two are asked for in different words —
    /// a prompt naming a key when it wants the master password would train
    /// someone to type the master password at a per-key prompt.
    master_password: bool,
}

impl PassphraseRequest {
    pub fn new(entry: &KeyEntry) -> Self {
        Self {
            key_name: entry.name.clone(),
            fingerprint: entry.fingerprint(),
            item_id: entry.item_id.clone(),
            master_password: false,
        }
    }

    /// What `lpass` asks for once its agent no longer holds the derived key.
    ///
    /// Nothing identifies a key here, because nothing about this is per-key:
    /// answering it unlocks the vault, and the signature that prompted it is
    /// incidental.
    pub const fn master_password() -> Self {
        Self {
            key_name: String::new(),
            fingerprint: String::new(),
            item_id: String::new(),
            master_password: true,
        }
    }

    /// The text a prompt shows. Enough to tell two keys apart, and escaped:
    /// a vault-controlled name must not be able to redraw a terminal or
    /// reverse the line that says which key is being unlocked.
    pub fn describe(&self) -> String {
        if self.master_password {
            // No cause claimed: lpass asks for this whenever its cached key is
            // gone, which is a screen lock only sometimes — the hourly expiry
            // reaches here too, and naming the wrong reason at a password
            // prompt is worse than naming none.
            return "Enter your LastPass master password\n\nThe vault is locked, and a \
                    signature needs it."
                .to_string();
        }
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

/// A typed line, so 1 KiB is far past anything real. The cap is what lets every
/// buffer holding a passphrase be allocated once: a `Vec` that never grows
/// cannot leave a copy in freed memory, which zeroizing the final allocation
/// would not reach. It also bounds what a misbehaving helper can make the agent
/// allocate. `MAX_FIELD_BYTES` exists for both reasons too.
///
/// Counted against the answer as delivered, framing included, so at least 1022
/// bytes of passphrase always fit.
pub const MAX_PASSPHRASE_BYTES: usize = 1024;

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

/// Somewhere a verified passphrase can be kept between signatures, keyed by the
/// key's own fingerprint.
///
/// Holds *only* passphrases, so the second signature need not ask again. The
/// private key never goes near it and stays fetched per signature.
///
/// Portable on purpose, though the Keychain is the only implementation: it is
/// what keeps the rules around it — prefer the vault, verify before saving,
/// re-ask when a saved passphrase stops working — testable on any platform,
/// leaving only the calls into Apple's API behind a `cfg`.
#[async_trait::async_trait]
pub trait PassphraseStore: Send + Sync {
    /// How a log line names this store — "the macOS Keychain". A line saying a
    /// passphrase was kept must say where, or the reader is left guessing
    /// whether it means a file on disk.
    fn name(&self) -> &'static str;
    /// The passphrase remembered for this fingerprint, if there is one.
    async fn get(&self, fingerprint: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String>;
    /// Remember (or replace) the passphrase for this fingerprint.
    async fn set(&self, fingerprint: &str, secret: &[u8]) -> Result<(), String>;
}

/// Turns the encrypted key the vault handed over into one that can sign.
///
/// Owning the decryption is the point: "is this passphrase right?" is the same
/// question as "did the key decrypt?", and a saved passphrase must never be
/// written before that question is answered.
pub struct Unlocker {
    lpass: std::sync::Arc<dyn LpassClient>,
    prompt: std::sync::Arc<dyn PassphrasePrompt>,
    store: std::sync::Arc<dyn PassphraseStore>,
}

impl Unlocker {
    pub fn new(
        lpass: std::sync::Arc<dyn LpassClient>,
        prompt: std::sync::Arc<dyn PassphrasePrompt>,
    ) -> Self {
        Self::with_store(lpass, prompt, default_store())
    }

    /// Tests substitute an in-memory store for the platform's real one.
    pub fn with_store(
        lpass: std::sync::Arc<dyn LpassClient>,
        prompt: std::sync::Arc<dyn PassphrasePrompt>,
        store: std::sync::Arc<dyn PassphraseStore>,
    ) -> Self {
        Self {
            lpass,
            prompt,
            store,
        }
    }

    /// Decrypt `encrypted`, taking the passphrase from the vault if it is
    /// there and from the configured fallback if it is not.
    ///
    /// The error text is what the signing path reports; it never contains key
    /// material.
    pub async fn unlock(
        &self,
        entry: &KeyEntry,
        encrypted: &ssh_key::PrivateKey,
        gate: &mut crate::interaction::InteractionGate,
    ) -> Result<ssh_key::PrivateKey, String> {
        let stored: Zeroizing<Vec<u8>> = self
            .lpass
            .show_field(&entry.item_id, "Passphrase")
            .await
            .map_err(|e| format!("fetching passphrase: {e}"))?;

        // Not trimmed: a passphrase may legitimately begin or end with a
        // space, and trimming one to nothing would silently divert to the
        // fallback.
        if !stored.is_empty() {
            tracing::debug!(item = %entry.item_id, source = "lastpass", "passphrase resolved");
            // Authoritative. A wrong value fails the signature here rather
            // than falling through, or anything able to draw a prompt could
            // override a passphrase the vault pins.
            return decrypt(encrypted, &stored);
        }

        match entry.passphrase_fallback {
            // Names the field to populate: the only fix is in the vault item.
            PassphraseFallback::Error => Err(
                "private key is passphrase-protected but the item's Passphrase field is empty"
                    .into(),
            ),
            PassphraseFallback::Prompt => {
                let typed = self.ask(entry, gate).await?;
                decrypt(encrypted, &typed)
            }
            PassphraseFallback::Keychain => self.unlock_from_store(entry, encrypted, gate).await,
        }
    }

    /// Ask the user, rejecting an answer that cannot be a passphrase.
    async fn ask(
        &self,
        entry: &KeyEntry,
        gate: &mut crate::interaction::InteractionGate,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        // Nothing before this point reaches the user, so this is where a request
        // that only ever needed a passphrase claims the gate.
        gate.enter().await;
        let typed = self
            .prompt
            .prompt(&PassphraseRequest::new(entry))
            .await
            .map_err(|e| format!("{e}"))?;
        if typed.is_empty() {
            // An encrypted key cannot have an empty passphrase, so this is a
            // stray return keypress rather than an answer. Saying so beats a
            // bare "decrypting private key failed".
            return Err("no passphrase entered".into());
        }
        tracing::debug!(item = %entry.item_id, source = "prompt", "passphrase resolved");
        Ok(typed)
    }

    /// Try what was saved for this key; ask, verify and save if that fails.
    async fn unlock_from_store(
        &self,
        entry: &KeyEntry,
        encrypted: &ssh_key::PrivateKey,
        gate: &mut crate::interaction::InteractionGate,
    ) -> Result<ssh_key::PrivateKey, String> {
        // Before the read, not just before the prompt: a locked Keychain puts a
        // system dialog on screen and waits (see `crate::apple::blocking`), so the
        // read is itself an interaction. Outside the gate it could share the
        // screen with another request's confirmation, and two requests missing
        // at once would queue duplicate passphrase prompts behind it.
        gate.enter().await;
        let fingerprint = entry.fingerprint();
        match self.store.get(&fingerprint).await {
            // Nothing this agent saved can be over the cap, so one that is
            // did not come from here. Refused rather than used — and the cap is
            // enforced on this side because a store is an outside system whose
            // contents are not ours to trust.
            Ok(Some(saved)) if saved.len() > MAX_PASSPHRASE_BYTES => {
                tracing::warn!(fingerprint = %fingerprint,
                    "ignoring a value in {} too long to be a passphrase",
                    self.store.name());
            }
            Ok(Some(saved)) => {
                if let Ok(key) = encrypted.decrypt(&*saved) {
                    tracing::debug!(item = %entry.item_id, source = self.store.name(),
                        "passphrase resolved");
                    return Ok(key);
                }
                // The key was replaced, or this entry belongs to an older one.
                // Asking again is the only way out: retrying a value that
                // cannot work would lock the key permanently.
                tracing::info!(fingerprint = %fingerprint,
                    "the passphrase in {} no longer decrypts this key — asking again",
                    self.store.name());
            }
            Ok(None) => {
                tracing::debug!(fingerprint = %fingerprint,
                    "no passphrase stored in {} for this key yet", self.store.name());
            }
            // A store that cannot be read is not a reason to refuse the
            // signature: asking is always available as a way through.
            Err(e) => tracing::warn!(fingerprint = %fingerprint,
                "cannot read the passphrase from {}, asking instead: {e}",
                self.store.name()),
        }

        let typed = self.ask(entry, gate).await?;
        // Verified first. A typo must never become a stored credential, which
        // is why decryption happens here and not after this function returns.
        let key = decrypt(encrypted, &typed)?;
        if let Err(e) = self.store.set(&fingerprint, &typed).await {
            // Not fatal: the signature can go ahead, and the next one asks.
            tracing::warn!(fingerprint = %fingerprint,
                "could not store the passphrase in {}, so the next signature will ask \
                 again: {e}",
                self.store.name());
        } else {
            // Says what was stored, where, and what was not: a log line about
            // persisting a secret must not leave the private key in doubt.
            tracing::info!(fingerprint = %fingerprint,
                "stored this key's passphrase in {} — the private key itself is never \
                 stored, and is still fetched from LastPass for every signature",
                self.store.name());
        }
        Ok(key)
    }
}

fn decrypt(encrypted: &ssh_key::PrivateKey, secret: &[u8]) -> Result<ssh_key::PrivateKey, String> {
    encrypted
        .decrypt(secret)
        .map_err(|e| format!("decrypting private key: {e}"))
}

/// The platform's passphrase store.
#[cfg(target_os = "macos")]
fn default_store() -> std::sync::Arc<dyn PassphraseStore> {
    std::sync::Arc::new(keychain::Keychain)
}

#[cfg(not(target_os = "macos"))]
fn default_store() -> std::sync::Arc<dyn PassphraseStore> {
    std::sync::Arc::new(NoStore)
}

/// There is nowhere to save a passphrase off macOS.
///
/// A running agent never reaches this: `passphrase_fallback = "keychain"` is
/// refused at config load on these platforms. It exists because an unreadable
/// store already means "ask instead", so the portable rules stay honest here
/// rather than depending on a store that cannot fail.
#[cfg(not(target_os = "macos"))]
struct NoStore;

#[cfg(not(target_os = "macos"))]
#[async_trait::async_trait]
impl PassphraseStore for NoStore {
    fn name(&self) -> &'static str {
        "no passphrase store"
    }

    async fn get(&self, _fingerprint: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        Err("this platform has no passphrase store".into())
    }
    async fn set(&self, _fingerprint: &str, _secret: &[u8]) -> Result<(), String> {
        Err("this platform has no passphrase store".into())
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
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const ED25519_PW: &str = include_str!("../tests/fixtures/ed25519_pw");
    const ED25519_PW_PUB: &str = include_str!("../tests/fixtures/ed25519_pw.pub");
    const RIGHT: &[u8] = b"fixture-passphrase";
    const WRONG: &[u8] = b"not the passphrase";

    fn entry(fallback: PassphraseFallback) -> KeyEntry {
        KeyEntry {
            item_id: "1".into(),
            name: "pw key".into(),
            public: ssh_key::PublicKey::from_openssh(ED25519_PW_PUB.trim()).unwrap(),
            confirm: false,
            passphrase_fallback: fallback,
        }
    }

    /// The encrypted key as the vault hands it over.
    fn encrypted() -> ssh_key::PrivateKey {
        let key = ssh_key::PrivateKey::from_openssh(ED25519_PW).unwrap();
        assert!(key.is_encrypted(), "the fixture must be encrypted");
        key
    }

    /// An item whose `Passphrase` field exists but holds nothing — the one
    /// state that hands over to the fallback.
    fn empty_field() -> MockLpass {
        MockLpass::logged_in().with_field("1", "Passphrase", b"")
    }

    fn vault_holding(secret: &[u8]) -> MockLpass {
        MockLpass::logged_in().with_field("1", "Passphrase", secret)
    }

    /// Answers with a fixed secret and counts how often it was asked.
    #[derive(Default)]
    struct FakePrompt {
        answer: Option<Vec<u8>>,
        error: Option<PromptError>,
        calls: Mutex<Vec<String>>,
    }

    impl FakePrompt {
        fn answering(secret: &[u8]) -> Arc<Self> {
            Arc::new(Self {
                answer: Some(secret.to_vec()),
                ..Self::default()
            })
        }
        fn failing(error: PromptError) -> Arc<Self> {
            Arc::new(Self {
                error: Some(error),
                ..Self::default()
            })
        }
        fn silent() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn calls(&self) -> usize {
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

    /// An in-memory stand-in for the Keychain, so no test touches the real one.
    #[derive(Default)]
    struct FakeStore {
        saved: Mutex<HashMap<String, Vec<u8>>>,
        fail_get: bool,
        fail_set: bool,
        reads: Mutex<usize>,
        writes: Mutex<usize>,
    }

    impl FakeStore {
        fn empty() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn holding(secret: &[u8]) -> Arc<Self> {
            let store = Self::default();
            store.saved.lock().unwrap().insert(
                entry(PassphraseFallback::Keychain).fingerprint(),
                secret.to_vec(),
            );
            Arc::new(store)
        }
        fn unreadable() -> Arc<Self> {
            Arc::new(Self {
                fail_get: true,
                ..Self::default()
            })
        }
        fn unwritable() -> Arc<Self> {
            Arc::new(Self {
                fail_set: true,
                ..Self::default()
            })
        }
        fn contents(&self) -> Option<Vec<u8>> {
            self.saved_for(&entry(PassphraseFallback::Keychain).fingerprint())
        }
        fn saved_for(&self, fingerprint: &str) -> Option<Vec<u8>> {
            self.saved.lock().unwrap().get(fingerprint).cloned()
        }
        fn entries(&self) -> usize {
            self.saved.lock().unwrap().len()
        }
        fn writes(&self) -> usize {
            *self.writes.lock().unwrap()
        }
        fn reads(&self) -> usize {
            *self.reads.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl PassphraseStore for FakeStore {
        fn name(&self) -> &'static str {
            "a test store"
        }

        async fn get(&self, fingerprint: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            *self.reads.lock().unwrap() += 1;
            if self.fail_get {
                return Err("keychain unavailable".into());
            }
            Ok(self
                .saved
                .lock()
                .unwrap()
                .get(fingerprint)
                .map(|secret| Zeroizing::new(secret.clone())))
        }
        async fn set(&self, fingerprint: &str, secret: &[u8]) -> Result<(), String> {
            *self.writes.lock().unwrap() += 1;
            if self.fail_set {
                return Err("keychain is locked".into());
            }
            self.saved
                .lock()
                .unwrap()
                .insert(fingerprint.to_string(), secret.to_vec());
            Ok(())
        }
    }

    fn unlocker(lpass: MockLpass, prompt: Arc<FakePrompt>, store: Arc<FakeStore>) -> Unlocker {
        Unlocker::with_store(Arc::new(lpass), prompt, store)
    }

    /// A gate nothing is contending for, standing in for the one the agent
    /// builds per signing request. These tests are about where a passphrase
    /// comes from; that it is asked for under the gate is `interaction`'s own
    /// business, and `agent` proves the two prompts never share a channel.
    fn gate() -> crate::interaction::InteractionGate {
        crate::interaction::InteractionGate::new(Arc::new(tokio::sync::Mutex::new(())))
    }

    /// The decrypted key must be the one the fixture's public half names.
    fn assert_unlocked(key: &ssh_key::PrivateKey) {
        assert!(!key.is_encrypted());
        assert_eq!(
            key.public_key().key_data(),
            ssh_key::PublicKey::from_openssh(ED25519_PW_PUB.trim())
                .unwrap()
                .key_data()
        );
    }

    #[tokio::test]
    async fn a_populated_field_wins_and_no_fallback_runs() {
        // The precedence rule, for every mode: LastPass is authoritative, so
        // neither the prompt nor the store is consulted at all.
        for fallback in [
            PassphraseFallback::Prompt,
            PassphraseFallback::Error,
            PassphraseFallback::Keychain,
        ] {
            let prompt = FakePrompt::answering(WRONG);
            let store = FakeStore::holding(WRONG);
            let unlocker = unlocker(vault_holding(RIGHT), prompt.clone(), store.clone());
            let key = unlocker
                .unlock(&entry(fallback), &encrypted(), &mut gate())
                .await
                .unwrap();
            assert_unlocked(&key);
            assert_eq!(prompt.calls(), 0, "{fallback:?} must not prompt");
            assert_eq!(store.reads(), 0, "{fallback:?} must not read the store");
        }
    }

    #[tokio::test]
    async fn a_wrong_field_fails_without_reaching_any_fallback() {
        // Fallback happens on absence, never on failure. Otherwise a local
        // prompt or a planted store entry could override what the vault pins.
        for fallback in [PassphraseFallback::Prompt, PassphraseFallback::Keychain] {
            let prompt = FakePrompt::answering(RIGHT);
            let store = FakeStore::holding(RIGHT);
            let unlocker = unlocker(vault_holding(WRONG), prompt.clone(), store.clone());
            let error = unlocker
                .unlock(&entry(fallback), &encrypted(), &mut gate())
                .await
                .unwrap_err();
            assert!(error.starts_with("decrypting private key:"), "{error}");
            assert_eq!(prompt.calls(), 0, "{fallback:?}");
            assert_eq!(store.reads(), 0, "{fallback:?}");
        }
    }

    #[tokio::test]
    async fn a_field_of_only_spaces_is_a_passphrase_not_an_absence() {
        // Trimming would divert a legitimate passphrase to the fallback.
        let prompt = FakePrompt::answering(RIGHT);
        let unlocker = unlocker(vault_holding(b"  "), prompt.clone(), FakeStore::empty());
        // wrong passphrase, so it fails — but as a decryption failure, which
        // proves the field was used rather than skipped
        let error = unlocker
            .unlock(
                &entry(PassphraseFallback::Prompt),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap_err();
        assert!(error.starts_with("decrypting private key:"), "{error}");
        assert_eq!(prompt.calls(), 0);
    }

    #[tokio::test]
    async fn error_mode_keeps_the_original_message() {
        let prompt = FakePrompt::answering(RIGHT);
        let unlocker = unlocker(empty_field(), prompt.clone(), FakeStore::empty());
        let error = unlocker
            .unlock(&entry(PassphraseFallback::Error), &encrypted(), &mut gate())
            .await
            .unwrap_err();
        assert_eq!(
            error,
            "private key is passphrase-protected but the item's Passphrase field is empty"
        );
        assert_eq!(prompt.calls(), 0);
    }

    #[tokio::test]
    async fn prompt_mode_asks_shows_the_key_and_unlocks() {
        let prompt = FakePrompt::answering(RIGHT);
        let unlocker = unlocker(empty_field(), prompt.clone(), FakeStore::empty());
        let key = unlocker
            .unlock(
                &entry(PassphraseFallback::Prompt),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap();
        assert_unlocked(&key);
        let shown = &prompt.calls.lock().unwrap()[0];
        assert!(shown.contains("pw key"), "{shown}");
        assert!(shown.contains("SHA256:"), "{shown}");
    }

    #[tokio::test]
    async fn prompt_mode_never_saves_what_was_typed() {
        let store = FakeStore::empty();
        let unlocker = unlocker(empty_field(), FakePrompt::answering(RIGHT), store.clone());
        unlocker
            .unlock(
                &entry(PassphraseFallback::Prompt),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap();
        assert_eq!(store.writes(), 0, "prompt mode persists nothing");
    }

    #[tokio::test]
    async fn a_wrongly_typed_passphrase_fails() {
        let unlocker = unlocker(
            empty_field(),
            FakePrompt::answering(WRONG),
            FakeStore::empty(),
        );
        let error = unlocker
            .unlock(
                &entry(PassphraseFallback::Prompt),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap_err();
        assert!(error.starts_with("decrypting private key:"), "{error}");
    }

    #[tokio::test]
    async fn each_way_a_prompt_can_fail_reports_differently() {
        for (error, expected) in [
            (PromptError::Cancelled, "passphrase entry cancelled"),
            (
                PromptError::TooLong(1024),
                "passphrase longer than 1024 bytes, refused",
            ),
        ] {
            let unlocker = unlocker(
                empty_field(),
                FakePrompt::failing(error),
                FakeStore::empty(),
            );
            let reported = unlocker
                .unlock(
                    &entry(PassphraseFallback::Prompt),
                    &encrypted(),
                    &mut gate(),
                )
                .await
                .unwrap_err();
            assert_eq!(reported, expected);
        }

        let unlocker = unlocker(
            empty_field(),
            FakePrompt::failing(PromptError::Unavailable("no tty".into())),
            FakeStore::empty(),
        );
        let reported = unlocker
            .unlock(
                &entry(PassphraseFallback::Prompt),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap_err();
        assert!(
            reported.contains("no interactive passphrase prompt"),
            "{reported}"
        );
        assert!(reported.contains("no tty"), "{reported}");
    }

    #[tokio::test]
    async fn an_empty_answer_is_rejected_rather_than_attempted() {
        let unlocker = unlocker(empty_field(), FakePrompt::silent(), FakeStore::empty());
        let error = unlocker
            .unlock(
                &entry(PassphraseFallback::Prompt),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, "no passphrase entered");
    }

    #[tokio::test]
    async fn a_broken_field_fetch_fails_without_falling_back() {
        // A vault that cannot answer is not a vault that answered "empty".
        let prompt = FakePrompt::answering(RIGHT);
        let lpass = MockLpass::logged_in().with_broken_field("1", "Passphrase");
        let unlocker = unlocker(lpass, prompt.clone(), FakeStore::empty());
        let error = unlocker
            .unlock(
                &entry(PassphraseFallback::Prompt),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap_err();
        assert!(error.starts_with("fetching passphrase:"), "{error}");
        assert_eq!(prompt.calls(), 0);
    }

    #[tokio::test]
    async fn a_saved_passphrase_unlocks_without_asking() {
        // The whole point of the store: the second signature is silent.
        let prompt = FakePrompt::answering(RIGHT);
        let store = FakeStore::holding(RIGHT);
        let unlocker = unlocker(empty_field(), prompt.clone(), store.clone());
        let key = unlocker
            .unlock(
                &entry(PassphraseFallback::Keychain),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap();
        assert_unlocked(&key);
        assert_eq!(prompt.calls(), 0, "a saved passphrase must not prompt");
        assert_eq!(store.writes(), 0, "nothing changed, nothing to write");
    }

    #[tokio::test]
    async fn nothing_saved_yet_asks_verifies_and_saves() {
        let prompt = FakePrompt::answering(RIGHT);
        let store = FakeStore::empty();
        let unlocker = unlocker(empty_field(), prompt.clone(), store.clone());
        let key = unlocker
            .unlock(
                &entry(PassphraseFallback::Keychain),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap();
        assert_unlocked(&key);
        assert_eq!(prompt.calls(), 1);
        assert_eq!(store.contents().as_deref(), Some(RIGHT));
    }

    #[tokio::test]
    async fn a_typo_never_becomes_a_saved_passphrase() {
        // Verify before persisting: the wrong answer must not be remembered,
        // or the key would be locked behind it until someone cleared it.
        let store = FakeStore::empty();
        let unlocker = unlocker(empty_field(), FakePrompt::answering(WRONG), store.clone());
        assert!(unlocker
            .unlock(
                &entry(PassphraseFallback::Keychain),
                &encrypted(),
                &mut gate()
            )
            .await
            .is_err());
        assert_eq!(store.writes(), 0, "an unverified passphrase was saved");
        assert_eq!(store.contents(), None);
    }

    #[tokio::test]
    async fn a_saved_passphrase_that_stops_working_is_replaced() {
        // A stale entry must not lock the key permanently: it is retried once,
        // the user corrects it, and the correction overwrites it.
        let prompt = FakePrompt::answering(RIGHT);
        let store = FakeStore::holding(WRONG);
        let unlocker = unlocker(empty_field(), prompt.clone(), store.clone());
        let key = unlocker
            .unlock(
                &entry(PassphraseFallback::Keychain),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap();
        assert_unlocked(&key);
        assert_eq!(prompt.calls(), 1, "a stale entry must ask, once");
        assert_eq!(store.contents().as_deref(), Some(RIGHT), "not replaced");
    }

    #[tokio::test]
    async fn a_stale_entry_with_no_correction_leaves_it_alone() {
        let store = FakeStore::holding(WRONG);
        let unlocker = unlocker(
            empty_field(),
            FakePrompt::failing(PromptError::Cancelled),
            store.clone(),
        );
        assert_eq!(
            unlocker
                .unlock(
                    &entry(PassphraseFallback::Keychain),
                    &encrypted(),
                    &mut gate()
                )
                .await
                .unwrap_err(),
            "passphrase entry cancelled"
        );
        assert_eq!(store.contents().as_deref(), Some(WRONG), "left as it was");
        assert_eq!(store.writes(), 0);
    }

    /// Two keys keep two passphrases, each under its own fingerprint.
    ///
    /// The account a store is keyed by is the fingerprint, so nothing about one
    /// key can reach another's entry. Worth pinning down: keying by item id or
    /// by name instead would still pass every other test here while quietly
    /// letting the second key overwrite the first's passphrase.
    #[tokio::test]
    async fn every_key_keeps_its_own_passphrase() {
        let store = FakeStore::empty();
        let mut keys = Vec::new();
        for (item, secret) in [("1", &b"first-passphrase"[..]), ("2", b"second-passphrase")] {
            let plain =
                ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                    .unwrap();
            let locked = plain.encrypt(&mut rand_core::OsRng, secret).unwrap();
            let entry = KeyEntry {
                item_id: item.into(),
                name: format!("key {item}"),
                public: plain.public_key().clone(),
                confirm: false,
                passphrase_fallback: PassphraseFallback::Keychain,
            };
            keys.push((entry, locked, secret.to_vec()));
        }
        assert_ne!(
            keys[0].0.fingerprint(),
            keys[1].0.fingerprint(),
            "the fixtures must be different keys"
        );

        // Each is asked for once and unlocks with its own answer.
        for (entry, locked, secret) in &keys {
            let lpass = MockLpass::logged_in().with_field(&entry.item_id, "Passphrase", b"");
            let prompt = FakePrompt::answering(secret);
            let unlocker = Unlocker::with_store(Arc::new(lpass), prompt.clone(), store.clone());
            assert!(unlocker.unlock(entry, locked, &mut gate()).await.is_ok());
            assert_eq!(prompt.calls(), 1, "item {}", entry.item_id);
        }

        // Both are kept, separately, with the right value under each.
        assert_eq!(store.entries(), 2, "one key's entry replaced the other's");
        for (entry, _, secret) in &keys {
            assert_eq!(
                store.saved_for(&entry.fingerprint()).as_deref(),
                Some(&secret[..]),
                "wrong passphrase stored for item {}",
                entry.item_id
            );
        }

        // And each is found again without asking — proving the lookup matched
        // that key rather than merely finding *something*.
        for (entry, locked, _) in &keys {
            let lpass = MockLpass::logged_in().with_field(&entry.item_id, "Passphrase", b"");
            // any prompt at all would fail this unlock
            let prompt = FakePrompt::failing(PromptError::Cancelled);
            let unlocker = Unlocker::with_store(Arc::new(lpass), prompt.clone(), store.clone());
            assert!(
                unlocker.unlock(entry, locked, &mut gate()).await.is_ok(),
                "item {} was not found again",
                entry.item_id
            );
            assert_eq!(prompt.calls(), 0, "item {}", entry.item_id);
        }
    }

    #[tokio::test]
    async fn a_saved_value_too_long_to_be_a_passphrase_is_ignored() {
        // Nothing this agent saves can exceed the cap, so a longer value was
        // put there by something else and is not used.
        let prompt = FakePrompt::answering(RIGHT);
        let store = FakeStore::holding(&vec![b'x'; MAX_PASSPHRASE_BYTES + 1]);
        let unlocker = unlocker(empty_field(), prompt.clone(), store.clone());
        let key = unlocker
            .unlock(
                &entry(PassphraseFallback::Keychain),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap();
        assert_unlocked(&key);
        assert_eq!(prompt.calls(), 1, "it must ask instead");
        assert_eq!(store.contents().as_deref(), Some(RIGHT), "and replace it");
    }

    #[tokio::test]
    async fn an_unreadable_store_asks_instead_of_refusing() {
        // Losing the saved passphrase is an inconvenience, not a reason to
        // refuse a signature the user can still authorise by typing it.
        let prompt = FakePrompt::answering(RIGHT);
        let store = FakeStore::unreadable();
        let unlocker = unlocker(empty_field(), prompt.clone(), store.clone());
        let key = unlocker
            .unlock(
                &entry(PassphraseFallback::Keychain),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap();
        assert_unlocked(&key);
        assert_eq!(prompt.calls(), 1);
    }

    #[tokio::test]
    async fn a_store_that_cannot_be_written_still_signs() {
        let prompt = FakePrompt::answering(RIGHT);
        let store = FakeStore::unwritable();
        let unlocker = unlocker(empty_field(), prompt.clone(), store.clone());
        let key = unlocker
            .unlock(
                &entry(PassphraseFallback::Keychain),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap();
        assert_unlocked(&key);
        assert_eq!(store.writes(), 1, "it tried");
        assert_eq!(store.contents(), None, "and failed");
    }

    #[tokio::test]
    async fn the_stored_key_is_the_fingerprint_not_the_item() {
        // So renaming the vault item, moving it, or recreating it still finds
        // the same passphrase.
        let store = FakeStore::empty();
        // the same key, now living in a different item under a different name
        let moved = MockLpass::logged_in().with_field("9999", "Passphrase", b"");
        let unlocker = unlocker(moved, FakePrompt::answering(RIGHT), store.clone());
        let mut renamed = entry(PassphraseFallback::Keychain);
        renamed.name = "renamed since".into();
        renamed.item_id = "9999".into();
        unlocker
            .unlock(&renamed, &encrypted(), &mut gate())
            .await
            .unwrap();
        assert_eq!(
            store.contents().as_deref(),
            Some(RIGHT),
            "the entry is keyed by fingerprint, so a rename finds it"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn without_a_platform_store_keychain_mode_falls_back_to_asking() {
        // Config validation refuses this mode off macOS, so a running agent
        // never gets here — but the default store must still behave, and an
        // unreadable one means "ask".
        let prompt = FakePrompt::answering(RIGHT);
        let unlocker = Unlocker::new(Arc::new(empty_field()), prompt.clone());
        let key = unlocker
            .unlock(
                &entry(PassphraseFallback::Keychain),
                &encrypted(),
                &mut gate(),
            )
            .await
            .unwrap();
        assert_unlocked(&key);
        assert_eq!(prompt.calls(), 1);
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
    fn the_master_password_is_asked_for_in_its_own_words() {
        // Never as a key's passphrase: a prompt naming a key while wanting the
        // vault's master password would teach someone to type the master
        // password at a per-key prompt, which is the habit to avoid.
        let text = PassphraseRequest::master_password().describe();
        assert!(text.contains("master password"), "{text}");
        assert!(!text.contains("SSH key"), "{text}");
        assert!(!text.contains("Fingerprint:"), "{text}");
        // and a key's own prompt is unchanged by its existence
        let key = PassphraseRequest::new(&entry(PassphraseFallback::Prompt)).describe();
        assert!(key.contains("passphrase for SSH key"), "{key}");
        assert!(!key.contains("master password"), "{key}");
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
