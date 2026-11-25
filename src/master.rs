//! Where the master password comes from, and where it may be kept.
//!
//! Obtaining it is `resolve`: the Secure Enclave when that is configured and
//! holds a sealed copy, the prompt otherwise — and a typed answer is then
//! sealed for the next time. Nothing here is kept at rest; `crate::enclave`
//! says why. Holding it while the vault is unlocked is `crate::unlock`'s
//! business.

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

/// Somewhere the master password can be kept between vault unlocks, for as
/// long as the agent runs.
///
/// One secret rather than one per key, so nothing is keyed by anything — and
/// released only on user presence, which is the whole reason it is worth
/// keeping at all. A kept secret that anything able to trigger a signature
/// could read silently would hand over the entire vault; one that needs a
/// fingerprint cannot.
///
/// Portable on purpose, though the macOS Secure Enclave is the only
/// implementation: it keeps the rules around it — prefer what is kept, fall
/// back to asking, never treat a failure as an empty answer — testable
/// everywhere, leaving only the calls into Apple's API behind a `cfg`.
#[async_trait::async_trait]
pub trait MasterPasswordStore: Send + Sync {
    /// How a log line names this store.
    fn name(&self) -> &'static str;
    /// The master password, if one is kept and presence was proved. `None`
    /// means nothing is kept; an error means the store could not be asked.
    async fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String>;
    /// Keep it, replacing whatever was there.
    async fn set(&self, secret: &[u8]) -> Result<(), String>;
    /// Drop it. Nothing kept is nothing to do.
    async fn forget(&self);
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
    async fn forget(&self) {}
}

/// Where a resolved master password actually came from.
///
/// The agent's log names it, in `crate::unlock`, when it is held and when
/// `lpass` rejects it.
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
/// answer would hand `lpass` a password nobody typed.
///
/// Under `touchid` a typed answer is handed to the store before `lpass` has
/// seen it. A wrong one is therefore kept too, for as long as it takes `lpass`
/// to say so: `Unlock::rejected` drops it from the store with the held copy.
pub async fn resolve(
    source: MasterPassword,
    store: &dyn MasterPasswordStore,
    prompt: &dyn PassphrasePrompt,
) -> Result<(Zeroizing<Vec<u8>>, Source)> {
    if source == MasterPassword::TouchId {
        match store.get().await {
            // Nothing this agent kept can be over the cap, so one that is
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
                "nothing kept in {} yet — asking, and keeping the answer there",
                store.name()
            ),
            // Biometry unavailable, presence refused: asking is always still a
            // way through, so none of them refuse the signature.
            Err(e) => tracing::info!("cannot read the master password from {}: {e}", store.name()),
        }
    }
    let typed = prompt
        .prompt(&PassphraseRequest::master_password())
        .await
        .map_err(|e| Error::ConfigInvalid(e.to_string()))?;
    if typed.is_empty() {
        // A stray Return at the dialog, not an answer. `lpass` would only
        // reject it, and "rejected" sends someone off to check a password
        // they never typed.
        return Err(Error::ConfigInvalid("no master password entered".into()));
    }
    if source == MasterPassword::TouchId {
        keep(store, &typed).await;
    }
    Ok((typed, Source::Prompt))
}

/// Hand a typed master password to the store. One that will not take it is
/// not a reason to refuse the vault: the next unlock is typed as well.
async fn keep(store: &dyn MasterPasswordStore, secret: &[u8]) {
    match store.set(secret).await {
        Ok(()) => tracing::info!(
            "the master password is kept in {}, in this agent's memory and nowhere else — \
             the next unlock takes a fingerprint",
            store.name()
        ),
        Err(e) => tracing::info!(
            "cannot keep the master password in {}, so the next unlock asks for it again: {e}",
            store.name()
        ),
    }
}

/// The line a master password sealed on disk begins with. One layout was ever
/// released, so one header is all there is to recognise.
const SEALED_ON_DISK: &[u8] = b"lastpass-ssh-agent secure enclave v2\n";

/// Remove a master password sealed on disk beside the socket.
///
/// Nothing here writes one: releases that kept the sealed password at rest
/// left it in this file, and what `crate::enclave` says about a sealed copy on
/// disk holds for as long as the file exists, whether or not anything reads
/// it. So a start removes it rather than ignoring it — once it has bound, so
/// that a start refused because an agent of such a release is still serving
/// takes nothing from it.
///
/// Recognised by its contents, not its name: the socket path is the user's to
/// choose, and a file of theirs that happens to sit at this one is not ours to
/// delete.
pub fn discard_at_rest(socket: &Path) {
    let path = socket.with_added_extension("master");
    if !is_sealed_password(&path) {
        return;
    }
    match std::fs::remove_file(&path) {
        Ok(()) => tracing::warn!(path = %path.display(),
            "removed a master password sealed on disk — it is kept in memory only, so the \
             first unlock after each start is typed"),
        Err(e) => tracing::warn!(path = %path.display(),
            "could not remove a master password sealed on disk, remove it by hand: {e}"),
    }
}

/// Whether `path` is a regular file that begins as a sealed password does.
/// Anything that cannot be opened or read is not one.
fn is_sealed_password(path: &Path) -> bool {
    use std::io::Read as _;

    let Ok(Some(file)) = crate::files::open_regular(path) else {
        return false;
    };
    let mut head = Vec::with_capacity(SEALED_ON_DISK.len());
    // A read that fails leaves less than the whole beginning, which is no match.
    file.take(SEALED_ON_DISK.len() as u64)
        .read_to_end(&mut head)
        .unwrap_or_default();
    head == SEALED_ON_DISK
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

/// The store this platform has.
#[cfg(target_os = "macos")]
pub fn default_store() -> std::sync::Arc<dyn MasterPasswordStore> {
    std::sync::Arc::new(crate::enclave::Kept::new(std::sync::Arc::new(
        enclave::SecureEnclave,
    )))
}

/// Nowhere to keep it, so `touchid` behaves as `prompt` — which config
/// validation refuses to configure here anyway.
#[cfg(not(target_os = "macos"))]
pub fn default_store() -> std::sync::Arc<dyn MasterPasswordStore> {
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
            if self.set_fails {
                return Err("the store would not take it".into());
            }
            *self.kept.lock().unwrap() = Some(secret.to_vec());
            Ok(())
        }
        async fn forget(&self) {
            *self.kept.lock().unwrap() = None;
        }
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
    async fn a_kept_master_password_is_used_without_asking() {
        let store = FakeStore::holding(Ok(Some(b"from the enclave")));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, from) = resolve(MasterPassword::TouchId, &store, &prompt)
            .await
            .unwrap();
        assert_eq!(&*secret, b"from the enclave");
        assert_eq!(from, Source::Store);
        assert_eq!(prompt.asked(), 0, "nothing to ask");
        assert_eq!(store.kept(), None, "and nothing to keep again");
    }

    #[tokio::test]
    async fn nothing_kept_yet_falls_through_to_asking_and_keeps_the_answer() {
        // The first unlock after every start.
        let store = FakeStore::holding(Ok(None));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, from) = resolve(MasterPassword::TouchId, &store, &prompt)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
        assert_eq!(from, Source::Prompt);
        assert_eq!(prompt.asked(), 1);
        assert_eq!(store.kept().as_deref(), Some(&b"typed"[..]));
    }

    #[tokio::test]
    async fn a_store_that_cannot_be_read_falls_through_too() {
        // Biometry unavailable, presence refused: the same secret is still
        // reachable by typing it, so none of these refuse.
        let store = FakeStore::holding(Err("no biometry here"));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::TouchId, &store, &prompt)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
        assert_eq!(prompt.asked(), 1);
    }

    #[tokio::test]
    async fn a_store_that_will_not_keep_it_does_not_refuse_the_vault() {
        let store = FakeStore {
            set_fails: true,
            ..FakeStore::default()
        };
        let prompt = FakePrompt::answering(b"typed");
        let (secret, from) = resolve(MasterPassword::TouchId, &store, &prompt)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
        assert_eq!(from, Source::Prompt);
        assert_eq!(store.kept(), None);
    }

    #[tokio::test]
    async fn the_prompt_source_never_touches_the_store() {
        let store = FakeStore::holding(Ok(Some(b"should not be read")));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::Prompt, &store, &prompt)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
        assert_eq!(store.kept(), None, "typed, and kept nowhere");
    }

    #[tokio::test]
    async fn a_refused_prompt_is_an_error_not_an_empty_answer() {
        // Handing lpass an empty password would be a wrong one, tried silently.
        let store = FakeStore::holding(Ok(None));
        let prompt = FakePrompt::refusing();
        assert!(
            resolve(MasterPassword::TouchId, &store, &prompt)
                .await
                .is_err()
        );
        assert_eq!(store.kept(), None);
    }

    #[tokio::test]
    async fn an_empty_answer_is_an_error_not_a_password() {
        let store = FakeStore::default();
        let prompt = FakePrompt::answering(b"");
        let err = resolve(MasterPassword::TouchId, &store, &prompt)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no master password entered"),
            "{err}"
        );
        assert_eq!(store.kept(), None, "a stray Return is not kept");
    }

    #[tokio::test]
    async fn a_kept_value_too_long_to_be_a_password_is_ignored() {
        // Nothing this agent keeps can exceed the cap, so a longer value was
        // put there by something else.
        static HUGE: &[u8] = &[b'x'; crate::passphrase::MAX_PASSPHRASE_BYTES + 1];
        let store = FakeStore::holding(Ok(Some(HUGE)));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::TouchId, &store, &prompt)
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
        assert_ne!(default_store().name(), "");
        let _: bool = store_available();
        assert!(NoStore.set(b"secret").await.is_err());
        NoStore.forget().await; // nothing kept, so nothing to do
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::TouchId, &NoStore, &prompt)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
    }

    /// A file as a release that sealed the password on disk left it.
    fn sealed_beside(socket: &Path) -> std::path::PathBuf {
        let sealed = socket.with_added_extension("master");
        std::fs::write(
            &sealed,
            b"lastpass-ssh-agent secure enclave v2\n\0\0\0\x01x",
        )
        .unwrap();
        sealed
    }

    #[test]
    fn a_password_sealed_on_disk_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let sealed = sealed_beside(&socket);
        discard_at_rest(&socket);
        assert!(!sealed.exists());
        discard_at_rest(&socket); // nothing there is the usual case
    }

    #[test]
    fn a_file_of_that_name_holding_something_else_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let theirs = dir.path().join("agent.sock.master");
        for contents in [
            &b"somebody's notes"[..],
            b"lastpass-ssh-agent secure enclave notes",
            b"lastpass-ssh",
            b"",
        ] {
            std::fs::write(&theirs, contents).unwrap();
            discard_at_rest(&socket);
            assert_eq!(std::fs::read(&theirs).unwrap(), contents);
        }
    }

    #[test]
    fn something_of_that_name_that_is_no_file_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let theirs = dir.path().join("agent.sock.master");
        std::fs::create_dir(&theirs).unwrap();
        discard_at_rest(&dir.path().join("agent.sock"));
        assert!(theirs.is_dir());
    }

    #[test]
    fn one_that_cannot_be_removed_is_left_and_said() {
        // A directory that cannot be written to keeps what is in it.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let sealed = sealed_beside(&socket);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        discard_at_rest(&socket);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(sealed.exists());
    }
}
