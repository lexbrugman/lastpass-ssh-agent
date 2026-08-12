//! The `LPASS_ASKPASS` helper: asking for the master password on lpass's behalf.
//!
//! `lpass` runs a helper as `execlp(program, "lpass-askpass", prompt, NULL)` —
//! a bare executable path, one argument, no shell. There is no room in that to
//! name a subcommand, so pointing `LPASS_ASKPASS` straight at this binary would
//! mean deciding what to be from the environment alone, before the command line
//! is even read. That works, and it is invisible: `--help` cannot mention a mode
//! that has no command, and nothing in a process listing explains it either.
//!
//! So the agent writes a two-line wrapper instead and points lpass at that. What
//! runs is `lastpass-ssh-agent askpass`, which is an ordinary subcommand: listed
//! in `--help`, visible in `ps`, and refusing to run outside the arrangement it
//! belongs to rather than silently behaving like a password prompt.

// Excluded from coverage as a whole, which is the point of it being this
// small: every line crosses into the Secure Enclave of whoever runs the tests,
// and asks for a fingerprint. What the answers mean is in `crate::enclave`,
// tested on every platform; the rules around the store are covered through
// `MasterPasswordStore` fakes, likewise everywhere.
#[cfg(target_os = "macos")]
#[cfg_attr(coverage_nightly, coverage(off))]
mod enclave;

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::config::MasterPassword;
use crate::error::{Error, Result};
use crate::passphrase::{PassphrasePrompt, PassphraseRequest};

/// Write the wrapper beside the socket and return its path.
///
/// Named after the socket rather than fixed, so it cannot collide with the
/// socket itself however that is configured — a path ending in `/askpass`
/// would otherwise be claimed twice, and `bind` would refuse the file this had
/// just put there.
///
/// Rewritten on every start rather than kept: it names the binary that is
/// running now, so an upgrade or a move corrects itself without anyone noticing
/// there was a file to correct.
pub fn install(socket_path: &Path, binary: &Path) -> Result<PathBuf> {
    let mut name = socket_path.as_os_str().to_os_string();
    name.push(".askpass");
    let path = PathBuf::from(name);

    // The name is derived from a path the user chooses, so it can land on
    // something that was already there. Replacing our own wrapper is the point;
    // replacing anything else would be quietly destroying a file nobody asked
    // us to touch. `socket::bind` refuses an unexpected file in the same way.
    //
    // Judged from `symlink_metadata`, so a symlink is refused as itself rather
    // than followed, and anything that is not a regular file — a FIFO, where a
    // read waits for a writer that never comes — never reaches `read_marker`.
    // Deliberately not `files::open_regular`: this wants to say *whose* file is
    // in the way, and that answer is worth more here than closing the moment
    // between the check and the open, which only another process running as
    // this user could exploit and only to hang a startup.
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        Ok(meta) if meta.file_type().is_file() => {
            if !is_our_wrapper(&read_marker(&path)?) {
                return Err(occupied(&path));
            }
        }
        Ok(_) => return Err(occupied(&path)),
    }

    // 0700 because lpass execs this one. The staged write matters more here
    // than anywhere else — a second agent starting while the first is being
    // asked for a password would otherwise truncate the file mid-exec — and
    // `files::write_private` says why it is done that way.
    crate::files::write_private(&path, &script_for(binary), 0o700)?;
    Ok(path)
}

/// Read just enough of a file to recognise the marker.
///
/// Bounded because the path is derived from one the user chose: a collision
/// with something enormous should produce `occupied`, not an allocation the
/// size of whatever happened to be sitting there.
fn read_marker(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let mut head = Vec::with_capacity(MARKER.len());
    std::fs::File::open(path)?
        .take(MARKER.len() as u64)
        .read_to_end(&mut head)?;
    Ok(head)
}

/// Something that is not ours is in the way.
fn occupied(path: &Path) -> Error {
    Error::Socket(format!(
        "{} exists and is not this agent's askpass wrapper — refusing to replace it \
         (choose a different `socket` path)",
        path.display()
    ))
}

/// The line that says a file at the wrapper's path is ours to replace.
///
/// A marker rather than the shape of the script: the binary named inside
/// changes with every upgrade, and another wrapper written by something else
/// could plausibly be a one-line `exec` too. This says whose it is.
const MARKER: &[u8] = b"#!/bin/sh\n# lastpass-ssh-agent askpass wrapper\n";

fn is_our_wrapper(contents: &[u8]) -> bool {
    contents.starts_with(MARKER)
}

/// The wrapper's contents, built from the path's bytes rather than its display
/// form.
///
/// A Unix path is bytes, not text, and `display()` turns anything that is not
/// UTF-8 into replacement characters — which would name a binary that does not
/// exist and fail every prompt, for a reason nothing would explain.
///
/// `"$@"` forwards the prompt lpass passes; `exec` so no shell lingers between
/// lpass and the prompt, waiting on a process it also has to reap.
fn script_for(binary: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut script = MARKER.to_vec();
    script.extend_from_slice(b"exec '");
    for &byte in binary.as_os_str().as_bytes() {
        // Single quotes hold everything else literally; a quote of its own has
        // to close them, escape itself, and open them again.
        if byte == b'\'' {
            script.extend_from_slice(br"'\''");
        } else {
            script.push(byte);
        }
    }
    script.extend_from_slice(b"' askpass \"$@\"\n");
    script
}

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

/// Whether the vault can actually be opened with what is stored.
///
/// A trait because the answer comes from running `lpass`, and the rules around
/// it — store, check, put back what was there — are worth testing without one.
#[async_trait::async_trait]
pub trait VaultUnlock: Send + Sync {
    /// Use the vault for something harmless. The error says why it would not
    /// open, and is shown to whoever is setting this up.
    async fn attempt(&self) -> Result<(), String>;
}

/// Keep a master password, but only once it has been shown to work.
///
/// Stored before it is checked, because the only way to check is to let `lpass`
/// use it, and the only channel `lpass` reads from is the helper — which reads
/// the store. So the secret is in the store for as long as one vault call
/// takes, and is taken back out again if it turns out to be wrong. The
/// alternative is passing a candidate through argv, the environment or a
/// temporary file, and none of those are places a master password may go.
pub async fn seed(
    store: &dyn MasterPasswordStore,
    secret: &[u8],
    vault: &dyn VaultUnlock,
) -> Result<()> {
    // What is there now, so a failed replacement is not a destroyed one.
    //
    // The distinction the store draws is the one this turns on. Holding
    // something that can never be opened again counts as empty — there is
    // nothing to put back, and seeding over it is the documented repair. Being
    // unable to *say* what is there — a declined fingerprint, no Enclave —
    // stops this before anything is overwritten, because guessing "nothing was
    // there" and rolling back to nothing would delete a password that worked.
    let previous = store.get().await.map_err(|e| {
        Error::ConfigInvalid(format!(
            "cannot read what is already stored in {}, so nothing was changed: {e}",
            store.name()
        ))
    })?;
    store
        .set(secret)
        .await
        .map_err(|e| Error::ConfigInvalid(format!("could not store the master password: {e}")))?;

    match vault.attempt().await {
        Ok(()) => {
            tracing::info!(
                "the master password opens the vault and is stored in {} — released only \
                 on Touch ID, never silently and never for your login password",
                store.name()
            );
            Ok(())
        }
        Err(why) => {
            // Put the store back as it was. A password that does not work is
            // worse than none — every later unlock would prove presence and
            // then fail anyway — and one that used to work is worse still to
            // lose over a typo in its replacement.
            let restored = match &previous {
                Some(old) => store.set(old).await,
                None => store.forget().await,
            };
            if let Err(e) = restored {
                // Say so rather than claim a clean failure: the store may still
                // hold what was just rejected, and every later unlock would
                // prove presence and then fail with it.
                return Err(Error::ConfigInvalid(format!(
                    "that master password did not open the vault ({why}), and the store \
                     could not be put back as it was ({e}) — {} now holds a password that \
                     does not work, so run `lastpass-ssh-agent store-master-password` \
                     again to replace it",
                    store.name()
                )));
            }
            Err(Error::ConfigInvalid(format!(
                "that master password did not open the vault, so nothing was kept: {why}"
            )))
        }
    }
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
    async fn forget(&self) -> Result<(), String> {
        Err(NOWHERE.into())
    }
}

/// Where a resolved master password actually came from.
///
/// The difference matters to setup and nowhere else: a password typed at the
/// fallback prompt proves nothing about what is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Store,
    Prompt,
}

impl Source {
    /// What the helper adds to its signal so the agent can tell the two apart.
    ///
    /// Here rather than at the one call site: which platform can produce which
    /// answer depends on whether a store exists, so a `match` beside the
    /// `eprintln!` could only ever go one way on some of them.
    pub const fn signal_suffix(self) -> &'static str {
        match self {
            Self::Store => crate::lpass::ASKPASS_FROM_STORE,
            Self::Prompt => "",
        }
    }
}

/// Whether the store has already answered this `lpass`.
///
/// `None` when no marker was named — nothing to remember, so nothing is
/// refused. That is the honest reading of an agent that did not ask for the
/// guard, and it leaves the older behaviour intact.
fn store_already_answered(once: Option<&Path>) -> bool {
    once.is_some_and(Path::exists)
}

/// Record that it has, so a second ask can be told apart from the first.
///
/// A failure here only costs the guard, never the answer that is already in
/// hand, so it is reported and not propagated.
fn remember_store_answered(once: Option<&Path>) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let Some(path) = once else { return };
    if let Err(e) = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
    {
        tracing::warn!("cannot record that the store answered, so it may answer again: {e}");
    }
}

/// The master password to hand `lpass`, from wherever the config says.
///
/// A store that has nothing yet, or cannot be asked, falls through to the
/// prompt rather than failing: the secret is the same one either way, and
/// refusing would strand a vault that a typed password could open. A prompt
/// that fails is a different matter and is reported — treating it as an empty
/// answer would hand `lpass` a password nobody typed.
pub async fn resolve(
    source: MasterPassword,
    store: &dyn MasterPasswordStore,
    prompt: &dyn PassphrasePrompt,
    once: Option<&Path>,
) -> Result<(Zeroizing<Vec<u8>>, Source)> {
    // Nothing to resolve: the agent was told not to handle this secret at all.
    // Reachable when a running agent's config is changed under it — the helper
    // reloads it, and must honour what it says now rather than what it said at
    // startup.
    if source == MasterPassword::Off {
        return Err(Error::ConfigInvalid(
            "master_password is \"off\", so this agent does not handle the master \
             password — reopen the vault with `lpass` yourself"
                .into(),
        ));
    }
    if source == MasterPassword::TouchId {
        // Asked twice by one `lpass` means the first answer was refused, and
        // the store holds only that one answer — so giving it again cannot
        // help, and would cost another fingerprint for each turn of a loop
        // that ends only at our timeout. Refused outright rather than falling
        // through to the prompt: during `store-master-password` a password
        // typed here would open the vault and be taken as proof that the
        // *stored* one works, quietly keeping one that does not.
        if store_already_answered(once) {
            return Err(Error::ConfigInvalid(format!(
                "{} has already given this `lpass` the stored master password once and it \
                 was not accepted — run `lastpass-ssh-agent store-master-password` to \
                 replace it",
                store.name()
            )));
        }
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
            Ok(Some(secret)) => {
                tracing::debug!(source = store.name(), "master password resolved");
                remember_store_answered(once);
                return Ok((secret, Source::Store));
            }
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

/// Which config the helper should prompt from, as the agent left it.
///
/// An error rather than a default: reaching this without the variable means
/// somebody ran `askpass` by hand, and the honest answer is that this is not a
/// command to run that way — not to silently prompt for a master password
/// because a default config happened to parse.
pub fn config_from_env() -> Result<PathBuf> {
    std::env::var_os(crate::lpass::ASKPASS_MARKER).map_or_else(
        || {
            Err(Error::ConfigInvalid(format!(
                "{} is not set — `askpass` is the password helper a running agent \
                 points lpass at, not a command to run by hand",
                crate::lpass::ASKPASS_MARKER
            )))
        },
        |value| Ok(PathBuf::from(value)),
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// The socket the agent would bind, in a directory of its own.
    fn socket(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("agent.sock")
    }

    #[test]
    fn the_wrapper_runs_this_binary_as_an_ordinary_subcommand() {
        let dir = tempfile::tempdir().unwrap();
        let path = install(&socket(&dir), Path::new("/opt/bin/lastpass-ssh-agent")).unwrap();
        assert_eq!(path, dir.path().join("agent.sock.askpass"));
        let script = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            script,
            "#!/bin/sh\n# lastpass-ssh-agent askpass wrapper\n\
             exec '/opt/bin/lastpass-ssh-agent' askpass \"$@\"\n"
        );
        assert_eq!(mode_of(&path), 0o700, "only this user may run it");
    }

    #[test]
    fn a_path_with_a_quote_in_it_survives_the_shell() {
        let dir = tempfile::tempdir().unwrap();
        let path = install(&socket(&dir), Path::new("/home/o'brien/bin/agent")).unwrap();
        let script = std::fs::read_to_string(path).unwrap();
        assert!(script.contains(r"'/home/o'\''brien/bin/agent'"), "{script}");
    }

    #[test]
    fn an_unrelated_file_in_the_way_is_left_alone() {
        // The name comes from a socket path the user chose, so it can collide
        // with something real. Destroying it silently would be the worst
        // possible answer.
        let dir = tempfile::tempdir().unwrap();
        let socket = socket(&dir);
        let occupied = dir.path().join("agent.sock.askpass");
        std::fs::write(&occupied, "notes I care about").unwrap();

        let error = install(&socket, Path::new("/bin/agent"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing to"), "{error}");
        assert_eq!(
            std::fs::read_to_string(&occupied).unwrap(),
            "notes I care about",
            "the file must survive untouched"
        );
    }

    #[test]
    fn a_wrapper_path_that_is_not_a_file_is_refused_rather_than_read() {
        // A FIFO here would hang a plain read waiting for a writer, and startup
        // with it. Nothing is read until the path is known to be a file.
        use std::os::unix::ffi::OsStrExt as _;
        let dir = tempfile::tempdir().unwrap();
        let socket = socket(&dir);
        let fifo = dir.path().join("agent.sock.askpass");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: mkfifo only reads the path it is given.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let error = install(&socket, Path::new("/bin/agent"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing to replace it"), "{error}");
    }

    #[test]
    fn a_path_that_cannot_be_inspected_is_an_error() {
        // A 300-byte final component fails lstat with ENAMETOOLONG, which is
        // not "nothing is there" and must not be treated as such.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("x".repeat(300));
        assert!(install(&socket, Path::new("/bin/agent")).is_err());
    }

    #[test]
    fn a_socket_named_askpass_is_not_fought_over() {
        // The wrapper is named after the socket, so the one path that could
        // have collided cannot: `bind` would have refused the file we put there.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("askpass");
        let path = install(&socket, Path::new("/bin/agent")).unwrap();
        assert_ne!(path, socket);
        assert!(!socket.exists(), "the socket path must be left alone");
    }

    #[test]
    fn rewriting_replaces_the_old_one_and_keeps_it_private() {
        // The binary moves with an upgrade, so the wrapper is rewritten every
        // start; a stale one would exec a path that no longer exists.
        let dir = tempfile::tempdir().unwrap();
        install(&socket(&dir), Path::new("/old/agent")).unwrap();
        let path = install(&socket(&dir), Path::new("/new/agent")).unwrap();
        let script = std::fs::read_to_string(&path).unwrap();
        assert!(script.contains("'/new/agent'"), "{script}");
        assert!(!script.contains("/old/agent"), "{script}");
        assert_eq!(mode_of(&path), 0o700);
    }

    #[test]
    fn a_directory_that_cannot_be_written_is_an_error_rather_than_a_panic() {
        let missing = Path::new("/nonexistent/socket/dir/agent.sock");
        assert!(install(missing, Path::new("/bin/agent")).is_err());
    }

    /// A store with whatever answer the case needs, recording what it is asked
    /// to keep so a test can see whether a rollback happened.
    #[derive(Default)]
    struct FakeStore {
        held: Option<std::result::Result<Option<&'static [u8]>, &'static str>>,
        kept: std::sync::Mutex<Option<Vec<u8>>>,
        writes: std::sync::Mutex<usize>,
        forget_fails: bool,
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
            if self.forget_fails {
                return Err("the store would not let go".into());
            }
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
    async fn one_that_does_not_open_the_vault_is_taken_back_out() {
        // A stored password that cannot work is worse than none: every later
        // unlock would prove presence and then fail anyway.
        let store = FakeStore::default();
        let error = seed(&store, b"wrong", &FakeVault(Err("could not decrypt")))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("did not open the vault"), "{error}");
        assert!(error.contains("could not decrypt"), "{error}");
        assert_eq!(store.kept(), None, "nothing may be left behind");
        assert_eq!(
            store.writes(),
            1,
            "it was stored before it could be checked"
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
        let (secret, from) = resolve(MasterPassword::TouchId, &store, &prompt, None)
            .await
            .unwrap();
        assert_eq!(&*secret, b"from the keychain");
        assert_eq!(from, Source::Store, "and it says where it came from");
        assert_eq!(prompt.asked(), 0, "nothing to ask");
    }

    #[tokio::test]
    async fn nothing_stored_yet_falls_through_to_asking() {
        // What `keychain` does before `store-master-password` has been run: it
        // behaves as `prompt` rather than refusing.
        let store = FakeStore::holding(Ok(None));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, from) = resolve(MasterPassword::TouchId, &store, &prompt, None)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
        assert_eq!(from, Source::Prompt, "typing it is not the store answering");
        assert_eq!(prompt.asked(), 1);
    }

    #[tokio::test]
    async fn a_store_that_cannot_be_read_falls_through_too() {
        // Biometry unavailable, presence refused, the item gone: the same
        // secret is still reachable by typing it, so none of these refuse.
        let store = FakeStore::holding(Err("no biometry here"));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::TouchId, &store, &prompt, None)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
        assert_eq!(prompt.asked(), 1);
    }

    #[tokio::test]
    async fn the_prompt_source_never_looks_at_the_store() {
        let store = FakeStore::holding(Ok(Some(b"should not be read")));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::Prompt, &store, &prompt, None)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
    }

    #[tokio::test]
    async fn a_refused_prompt_is_an_error_not_an_empty_answer() {
        // Handing lpass an empty password would be a wrong one, tried silently.
        let store = FakeStore::holding(Ok(None));
        let prompt = FakePrompt::refusing();
        assert!(resolve(MasterPassword::TouchId, &store, &prompt, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn the_store_answers_one_lpass_only_once() {
        // lpass loops forever on a wrong password and cannot tell the helper it
        // is retrying, so the second ask must not spend another fingerprint
        // handing over the same rejected answer.
        let dir = tempfile::tempdir().unwrap();
        let once = dir.path().join("once");
        let store = FakeStore::holding(Ok(Some(b"stored")));
        let prompt = FakePrompt::answering(b"typed");

        let (secret, from) = resolve(MasterPassword::TouchId, &store, &prompt, Some(&once))
            .await
            .unwrap();
        assert_eq!(&*secret, b"stored");
        assert_eq!(from, Source::Store);
        assert!(once.exists(), "the first answer is recorded");

        // And refuses outright rather than prompting: a password typed here
        // would open the vault and be mistaken for proof that the stored one
        // works, so `store-master-password` would keep one that does not.
        let error = resolve(MasterPassword::TouchId, &store, &prompt, Some(&once))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("store-master-password"), "{error}");
        assert_eq!(prompt.asked(), 0, "and does not ask instead");
    }

    #[tokio::test]
    async fn a_store_with_nothing_in_it_leaves_the_prompt_free_to_retry() {
        // Only an answer is remembered. With nothing stored the helper falls
        // through to the prompt, and lpass asking again must reach the prompt
        // again — a typo there is the user's to correct.
        let dir = tempfile::tempdir().unwrap();
        let once = dir.path().join("once");
        let store = FakeStore::holding(Ok(None));
        let prompt = FakePrompt::answering(b"typed");

        for _ in 0..2 {
            let (secret, from) = resolve(MasterPassword::TouchId, &store, &prompt, Some(&once))
                .await
                .unwrap();
            assert_eq!(&*secret, b"typed");
            assert_eq!(from, Source::Prompt);
        }
        assert!(
            !once.exists(),
            "nothing was answered, so nothing is recorded"
        );
        assert_eq!(prompt.asked(), 2);
    }

    #[tokio::test]
    async fn an_unrecordable_answer_is_still_an_answer() {
        // The guard is worth less than the password already in hand: if the
        // marker cannot be written, say so and carry on rather than failing a
        // signature over it.
        let dir = tempfile::tempdir().unwrap();
        let once = dir.path().join("no-such-directory").join("once");
        let store = FakeStore::holding(Ok(Some(b"stored")));
        let prompt = FakePrompt::answering(b"typed");

        let (secret, from) = resolve(MasterPassword::TouchId, &store, &prompt, Some(&once))
            .await
            .unwrap();
        assert_eq!(&*secret, b"stored");
        assert_eq!(from, Source::Store);
    }

    #[tokio::test]
    async fn a_source_that_is_off_refuses_rather_than_prompting() {
        // A running agent whose config is changed under it must honour what it
        // says now: "off" means this agent does not handle the master password.
        let store = FakeStore::holding(Ok(Some(b"stored")));
        let prompt = FakePrompt::answering(b"typed");
        assert!(resolve(MasterPassword::Off, &store, &prompt, None)
            .await
            .is_err());
        assert_eq!(prompt.asked(), 0, "and does not ask either");
    }

    #[tokio::test]
    async fn a_stored_value_too_long_to_be_a_password_is_ignored() {
        // Nothing this agent stores can exceed the cap, so a longer value was
        // put there by something else.
        static HUGE: &[u8] = &[b'x'; crate::passphrase::MAX_PASSPHRASE_BYTES + 1];
        let store = FakeStore::holding(Ok(Some(HUGE)));
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::TouchId, &store, &prompt, None)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed", "it asks instead");
    }

    #[tokio::test]
    async fn a_store_that_will_not_take_it_fails_before_the_vault_is_touched() {
        // A store that refuses to write: there is nothing to check against
        // the vault, and nothing to roll back either.
        let store = FakeStore {
            set_fails: true,
            ..FakeStore::default()
        };
        let error = seed(&store, b"secret", &FakeVault(Err("never reached")))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("could not store the master password"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_failed_replacement_puts_the_working_one_back() {
        // Losing a master password that worked, over a typo in its
        // replacement, would be the worst outcome of trying to change it.
        let store = FakeStore::holding(Ok(Some(b"the one that works")));
        *store.kept.lock().unwrap() = Some(b"the one that works".to_vec());
        assert!(seed(&store, b"a typo", &FakeVault(Err("nope")))
            .await
            .is_err());
        assert_eq!(
            store.kept().as_deref(),
            Some(&b"the one that works"[..]),
            "the previous password must survive"
        );
    }

    #[test]
    fn only_the_store_marks_its_own_answer() {
        assert!(Source::Store.signal_suffix().contains("from store"));
        assert!(Source::Prompt.signal_suffix().is_empty());
    }

    #[tokio::test]
    async fn an_unreadable_store_stops_setup_before_overwriting() {
        // Not knowing what is there is not the same as nothing being there:
        // overwriting and then rolling back to empty would destroy it.
        let store = FakeStore::holding(Err("presence declined"));
        let error = seed(&store, b"new", &FakeVault(Ok(())))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("nothing was changed"), "{error}");
        assert_eq!(store.writes(), 0, "and nothing was written");
    }

    #[tokio::test]
    async fn a_rollback_that_fails_is_reported_but_still_refuses() {
        // The password did not work, and now it cannot be taken back out
        // either. Both facts belong in the log; neither makes it a success.
        let store = FakeStore {
            forget_fails: true,
            ..FakeStore::default()
        };
        assert!(seed(&store, b"wrong", &FakeVault(Err("nope")))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_platform_with_nowhere_to_keep_it_says_so() {
        // Named as well as refusing: a log line about a store has to say which
        // one, and `tracing` never evaluates that argument unless something is
        // listening — so it is asserted here rather than assumed.
        assert!(NoStore.name().contains("no master password store"));
        // And the factory that hands one out, which otherwise only runs inside
        // the helper process the CLI tests spawn. `store_available` goes with
        // it: off macOS it is the constant false, and on macOS it answers from
        // the hardware, so all this can assert is that it answers.
        assert!(!default_store(Path::new("/tmp/agent.sock"))
            .name()
            .is_empty());
        let _: bool = store_available();
        assert!(NoStore.set(b"secret").await.is_err());
        assert!(NoStore.forget().await.is_err());
    }

    #[tokio::test]
    async fn without_a_platform_store_it_asks() {
        let prompt = FakePrompt::answering(b"typed");
        let (secret, _from) = resolve(MasterPassword::TouchId, &NoStore, &prompt, None)
            .await
            .unwrap();
        assert_eq!(&*secret, b"typed");
    }

    #[test]
    fn running_askpass_by_hand_says_what_it_is_for() {
        // The variable is process-global, so this only checks the absent case;
        // the present one is covered end to end by the CLI tests.
        if std::env::var_os(crate::lpass::ASKPASS_MARKER).is_some() {
            return;
        }
        let error = config_from_env().unwrap_err().to_string();
        assert!(error.contains("not a command to run by hand"), "{error}");
    }
}
