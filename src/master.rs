//! Where the master password comes from, and where it may be kept.
//!
//! Obtaining it is `resolve`: the Secure Enclave when that is configured and
//! seeded, the prompt otherwise. Keeping it is `seed`, which stores nothing it
//! has not first watched open the vault. Holding it while the vault is unlocked
//! is `crate::unlock`'s business.

// Excluded from coverage as a whole, which is the point of it being this
// small: every line crosses into the Secure Enclave of whoever runs the tests,
// and asks for a fingerprint. What the answers mean is in `crate::enclave`,
// tested on every platform; the rules around the store are covered through
// `MasterPasswordStore` fakes, likewise everywhere.
#[cfg(target_os = "macos")]
#[cfg_attr(coverage_nightly, coverage(off))]
mod enclave;

use std::path::Path;

use zeroize::Zeroizing;

use crate::config::MasterPassword;
use crate::error::{Error, Result};
use crate::passphrase::{PassphrasePrompt, PassphraseRequest};

/// Somewhere the master password can be kept between vault unlocks.
///
/// One secret rather than one per key, so nothing is keyed by anything — and
/// released only on user presence, which is the whole reason it is worth
/// keeping at all. A stored secret that anything able to trigger a signature
/// could read silently would hand over the entire vault; one that needs a
/// fingerprint cannot.
///
/// Portable on purpose, though the macOS Secure Enclave is the only
/// implementation: it keeps the rules around it — prefer what is stored, fall
/// back to asking, never treat a failure as an empty answer — testable
/// everywhere, leaving only the calls into Apple's API behind a `cfg`.
#[async_trait::async_trait]
pub trait MasterPasswordStore: Send + Sync {
    /// How a log line names this store.
    fn name(&self) -> &'static str;
    /// The master password, if one is kept and presence was proved. `None`
    /// means nothing is stored; an error means the store could not be asked.
    async fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String>;
    /// Keep it, replacing whatever was there.
    async fn set(&self, secret: &[u8]) -> Result<(), String>;
    /// Remove it. Already absent is success.
    async fn forget(&self) -> Result<(), String>;
}

/// Whether the vault opens with a candidate master password.
///
/// A trait because the answer comes from running `lpass` with the candidate on
/// its stdin, and the rule around it — keep nothing that did not open the vault
/// — is worth testing without one.
#[async_trait::async_trait]
pub trait VaultUnlock: Send + Sync {
    /// Use the vault for something harmless. The error says why it would not
    /// open, and is shown to whoever is setting this up.
    async fn attempt(&self) -> Result<(), String>;
}

/// Keep a master password, but only once it has been shown to open the vault.
///
/// Checked first and stored second, so a typo is never on disk for a moment,
/// and whatever was there before survives a failed replacement untouched.
pub async fn seed(
    store: &dyn MasterPasswordStore,
    secret: &[u8],
    vault: &dyn VaultUnlock,
) -> Result<()> {
    vault.attempt().await.map_err(|why| {
        Error::ConfigInvalid(format!(
            "that master password did not open the vault, so nothing was kept: {why}"
        ))
    })?;
    store
        .set(secret)
        .await
        .map_err(|e| Error::ConfigInvalid(format!("could not store the master password: {e}")))?;
    tracing::info!(
        "the master password opens the vault and is stored in {} — released only on Touch \
         ID, never silently and never for your login password",
        store.name()
    );
    Ok(())
}

/// Nowhere to keep it: every read falls through to asking.
///
/// Off macOS this is the only implementation there will be, and config
/// validation refuses `touchid` there anyway. Compiled on macOS only for the
/// tests, which use it to prove the portable rules around an absent store —
/// there it is a stand-in rather than something the agent would reach.
#[cfg(any(test, not(target_os = "macos")))]
pub struct NoStore;

#[cfg(any(test, not(target_os = "macos")))]
const NOWHERE: &str = "this platform has no master password store";

#[cfg(any(test, not(target_os = "macos")))]
#[async_trait::async_trait]
impl MasterPasswordStore for NoStore {
    fn name(&self) -> &'static str {
        "no master password store"
    }
    async fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        Err(NOWHERE.into())
    }
    async fn set(&self, _secret: &[u8]) -> Result<(), String> {
        Err(NOWHERE.into())
    }
    /// Nothing can be kept here, so nothing is: the trait's "already absent
    /// is success".
    async fn forget(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Where a resolved master password actually came from.
///
/// The agent's log names it, and `crate::unlock` acts on it: a password the
/// store supplied and `lpass` rejected means the store is not asked again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Store,
    Prompt,
}

impl Source {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Prompt => "prompt",
        }
    }
}

/// The master password, from wherever the config says.
///
/// A store that has nothing yet, or cannot be asked, falls through to the
/// prompt rather than failing: the secret is the same one either way, and
/// refusing would strand a vault that a typed password could open. A prompt
/// that fails is a different matter and is reported — treating it as an empty
/// answer would hand `lpass` a password nobody typed. `skip_store` is for a
/// store whose answer `lpass` has already rejected once.
pub async fn resolve(
    source: MasterPassword,
    store: &dyn MasterPasswordStore,
    prompt: &dyn PassphrasePrompt,
    skip_store: bool,
) -> Result<(Zeroizing<Vec<u8>>, Source)> {
    if source == MasterPassword::TouchId && !skip_store {
        match store.get().await {
            // Nothing this agent stored can be over the cap, so one that is
            // did not come from here. Refused rather than used, and checked on
            // this side because a store's contents are not ours to trust.
            Ok(Some(secret)) if secret.len() > crate::passphrase::MAX_PASSPHRASE_BYTES => {
                tracing::warn!(
                    "ignoring a value in {} too long to be a master password",
                    store.name()
                );
            }
            Ok(Some(secret)) => return Ok((secret, Source::Store)),
            Ok(None) => tracing::info!(
                "nothing stored in {} yet — asking, and `store-master-password` will \
                 keep it",
                store.name()
            ),
            // Biometry unavailable, the item gone, presence refused: asking is
            // always still a way through, so none of them refuse the signature.
            Err(e) => tracing::info!("cannot read the master password from {}: {e}", store.name()),
        }
    }
    let typed = prompt
        .prompt(&PassphraseRequest::master_password())
        .await
        .map_err(|e| Error::ConfigInvalid(e.to_string()))?;
    Ok((typed, Source::Prompt))
}

/// Whether this platform's store could work at all, so `doctor` can say so
/// rather than letting the first signature discover it.
#[cfg(target_os = "macos")]
pub fn store_available() -> bool {
    enclave::available()
}

/// Nowhere to keep it, so nothing to check.
#[cfg(not(target_os = "macos"))]
pub const fn store_available() -> bool {
    false
}

/// The store this platform has, keeping its state beside the socket.
#[cfg(target_os = "macos")]
pub fn default_store(socket: &Path) -> std::sync::Arc<dyn MasterPasswordStore> {
    std::sync::Arc::new(enclave::SecureEnclave::new(crate::enclave::path_for(
        socket,
    )))
}

/// Nowhere to keep it, so `touchid` behaves as `prompt` — which config
/// validation refuses to configure here anyway.
#[cfg(not(target_os = "macos"))]
pub fn default_store(_socket: &Path) -> std::sync::Arc<dyn MasterPasswordStore> {
    std::sync::Arc::new(NoStore)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A store with whatever answer the case needs, recording what it is asked
    /// to keep.
    #[derive(Default)]
    struct FakeStore {
        held: Option<std::result::Result<Option<&'static [u8]>, &'static str>>,
        kept: std::sync::Mutex<Option<Vec<u8>>>,
        writes: std::sync::Mutex<usize>,
        set_fails: bool,
    }

    impl FakeStore {
        fn holding(answer: std::result::Result<Option<&'static [u8]>, &'static str>) -> Self {
            Self {
                held: Some(answer),
                ..Self::default()
            }
        }
        fn kept(&self) -> Option<Vec<u8>> {
            self.kept.lock().unwrap().clone()
        }
        fn writes(&self) -> usize {
            *self.writes.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl MasterPasswordStore for FakeStore {
        fn name(&self) -> &'static str {
            "a test store"
        }
        async fn get(&self) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, String> {
            self.held
                .unwrap_or(Ok(None))
                .map(|held| held.map(|secret| Zeroizing::new(secret.to_vec())))
                .map_err(str::to_string)
        }
        async fn set(&self, secret: &[u8]) -> std::result::Result<(), String> {
            *self.writes.lock().unwrap() += 1;
            if self.set_fails {
                return Err("the store would not take it".into());
            }
            *self.kept.lock().unwrap() = Some(secret.to_vec());
            Ok(())
        }
        async fn forget(&self) -> std::result::Result<(), String> {
            *self.kept.lock().unwrap() = None;
            Ok(())
        }
    }

    /// A vault that opens, or says why it did not.
    struct FakeVault(std::result::Result<(), &'static str>);

    #[async_trait::async_trait]
    impl VaultUnlock for FakeVault {
        async fn attempt(&self) -> std::result::Result<(), String> {
            self.0.map_err(str::to_string)
        }
    }

    #[tokio::test]
    async fn a_master_password_that_opens_the_vault_is_kept() {
        let store = FakeStore::default();
        seed(&store, b"correct", &FakeVault(Ok(()))).await.unwrap();
        assert_eq!(store.kept().as_deref(), Some(&b"correct"[..]));
    }

    #[tokio::test]
    async fn one_that_does_not_open_the_vault_is_never_written() {
        // Checked before it is stored, so a typo is never on disk — and what
        // was there before is untouched.
        let store = FakeStore::default();
        *store.kept.lock().unwrap() = Some(b"the one that works".to_vec());
        let error = seed(&store, b"wrong", &FakeVault(Err("could not decrypt")))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("did not open the vault"), "{error}");
        assert!(error.contains("could not decrypt"), "{error}");
        assert_eq!(store.writes(), 0, "nothing was written");
        assert_eq!(
            store.kept().as_deref(),
            Some(&b"the one that works"[..]),
            "the previous password survives"
        );
    }

    #[tokio::test]
    async fn a_store_that_will_not_take_it_is_reported() {
        let store = FakeStore {
            set_fails: true,
            ..FakeStore::default()
        };
        let error = seed(&store, b"secret", &FakeVault(Ok(())))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("could not store the master password"),
            "{error}"
        );
    }

    /// Answers with a fixed secret, or refuses, and counts the asking.
    struct FakePrompt {
        answer: Option<&'static [u8]>,
        asked: std::sync::Mutex<usize>,
    }

    impl FakePrompt {
        fn answering(secret: &'static [u8]) -> Self {
            Self {
                answer: Some(secret),
                asked: std::sync::Mutex::new(0),
            }
        }
        fn refusing() -> Self {
            Self {
                answer: None,
                asked: std::sync::Mutex::new(0),
            }
        }
        fn asked(&self) -> usize {
            *self.asked.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl PassphrasePrompt for FakePrompt {
        async fn prompt(
            &self,
            _request: &PassphraseRequest,
        ) -> std::result::Result<Zeroizing<Vec<u8>>, crate::passphrase::PromptError> {
            *self.asked.lock().unwrap() += 1;
            self.answer.map_or_else(
                || Err(crate::passphrase::PromptError::Cancelled),
                |secret| Ok(Zeroizing::new(secret.to_vec())),
            )
        }
    }

    #[tokio::test]
    async fn a_stored_master_password_is_used_without_asking() {
        let store = FakeStore::holding(Ok(Some(b"from the keychain")));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, from) = resolve(MasterPassword::TouchId, &store, &prompt, false)
            .await
            .unwrap();
        assert_eq!(&*secret, b"from the keychain");
        assert_eq!(from, Source::Store);
        assert_eq!(prompt.asked(), 0, "nothing to ask");
    }

    #[tokio::test]
    async fn a_rejected_store_is_skipped_in_favour_of_the_prompt() {
        let store = FakeStore::holding(Ok(Some(b"stale")));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, from) = resolve(MasterPassword::TouchId, &store, &prompt, true)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
        assert_eq!(from, Source::Prompt);
    }

    #[tokio::test]
    async fn nothing_stored_yet_falls_through_to_asking() {
        // What `touchid` does before `store-master-password` has been run.
        let store = FakeStore::holding(Ok(None));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, from) = resolve(MasterPassword::TouchId, &store, &prompt, false)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
        assert_eq!(from, Source::Prompt);
        assert_eq!(prompt.asked(), 1);
    }

    #[tokio::test]
    async fn a_store_that_cannot_be_read_falls_through_too() {
        // Biometry unavailable, presence refused, the item gone: the same
        // secret is still reachable by typing it, so none of these refuse.
        let store = FakeStore::holding(Err("no biometry here"));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::TouchId, &store, &prompt, false)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
        assert_eq!(prompt.asked(), 1);
    }

    #[tokio::test]
    async fn the_prompt_source_never_looks_at_the_store() {
        let store = FakeStore::holding(Ok(Some(b"should not be read")));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::Prompt, &store, &prompt, false)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
    }

    #[tokio::test]
    async fn a_refused_prompt_is_an_error_not_an_empty_answer() {
        // Handing lpass an empty password would be a wrong one, tried silently.
        let store = FakeStore::holding(Ok(None));
        let prompt = FakePrompt::refusing();
        assert!(resolve(MasterPassword::TouchId, &store, &prompt, false)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_stored_value_too_long_to_be_a_password_is_ignored() {
        // Nothing this agent stores can exceed the cap, so a longer value was
        // put there by something else.
        static HUGE: &[u8] = &[b'x'; crate::passphrase::MAX_PASSPHRASE_BYTES + 1];
        let store = FakeStore::holding(Ok(Some(HUGE)));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::TouchId, &store, &prompt, false)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed", "it asks instead");
    }

    #[test]
    fn each_source_names_itself() {
        assert_eq!(Source::Store.name(), "store");
        assert_eq!(Source::Prompt.name(), "prompt");
    }

    #[tokio::test]
    async fn a_platform_with_nowhere_to_keep_it_says_so() {
        assert!(NoStore.name().contains("no master password store"));
        assert!(!default_store(Path::new("/tmp/agent.sock"))
            .name()
            .is_empty());
        let _: bool = store_available();
        assert!(NoStore.set(b"secret").await.is_err());
        assert!(
            NoStore.forget().await.is_ok(),
            "nothing kept, so nothing to do"
        );
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::TouchId, &NoStore, &prompt, false)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
    }
}
