use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::platform;

/// How signing requests are confirmed with the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConfirmMode {
    #[cfg_attr(target_os = "macos", default)]
    Osascript,
    #[cfg_attr(not(target_os = "macos"), default)]
    Tty,
    Askpass,
    Off,
}

/// Where an encrypted key's passphrase comes from when the `LastPass` item's
/// own `Passphrase` field is empty.
///
/// This is a *fallback*: a populated `Passphrase` field always wins, and a
/// populated-but-wrong one fails rather than falling through here. Otherwise
/// a local prompt could talk a user into unlocking a key whose passphrase the
/// vault already pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PassphraseFallback {
    /// Ask for it, keeping the passphrase out of the vault entirely.
    #[default]
    Prompt,
    /// Refuse to sign.
    Error,
    /// Remember it in the macOS Keychain, asking only when it is not there
    /// yet — or no longer works. macOS only; rejected at load elsewhere.
    Keychain,
    /// The same, in whichever secret service the desktop runs — gnome-keyring,
    /// `KWallet`, `KeePassXC`. Needs a session bus and a collection that can be
    /// unlocked, so a headless login falls back to asking. Linux only; rejected
    /// at load elsewhere.
    #[serde(rename = "secretservice")]
    SecretService,
}

/// Where the vault's master password comes from when the agent needs the
/// vault and holds no password for it.
///
/// Not about *why* it holds none: the idle time, a screen lock and a fresh
/// start reach here alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MasterPassword {
    /// Asked for through the agent's own prompt, and kept nowhere but in the
    /// running agent's memory.
    #[default]
    Prompt,
    /// Kept encrypted to a key held in the Secure Enclave, which releases it
    /// only on Touch ID — so it cannot be taken silently by anything able to
    /// trigger a signature. Falls back to `prompt` when there is nothing stored
    /// yet, when the fingerprint is declined, or when the key needs seeding
    /// again. macOS only; rejected at load elsewhere.
    #[serde(rename = "touchid")]
    TouchId,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// `LastPass` item id (decimal digits, as shown by `lpass show` / `search`).
    /// Ids are required to be numeric so they can never be mistaken for an
    /// option when passed to lpass as an argument.
    pub id: String,
    /// Display name, used in confirmations and as the SSH key comment.
    #[serde(default)]
    pub name: Option<String>,
    /// Per-key override of the global confirmation setting.
    #[serde(default)]
    pub confirm: Option<bool>,
    /// Per-key override of the global passphrase fallback.
    #[serde(default)]
    pub passphrase_fallback: Option<PassphraseFallback>,
}

impl KeyConfig {
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Path of the agent socket. Defaults to a per-user private directory.
    #[serde(default)]
    pub socket: Option<PathBuf>,

    #[serde(default)]
    pub confirm: ConfirmMode,

    #[serde(default = "default_confirm_timeout")]
    pub confirm_timeout_secs: u64,

    /// Path to the lpass binary; searched on PATH if unset.
    #[serde(default)]
    pub lpass_path: Option<PathBuf>,

    /// External confirmation helper (`SSH_ASKPASS` convention).
    /// Required when `confirm = "askpass"`.
    #[serde(default)]
    pub askpass: Option<PathBuf>,

    /// Where an encrypted key's passphrase comes from when the item's own
    /// `Passphrase` field is empty.
    #[serde(default)]
    pub passphrase_fallback: PassphraseFallback,

    /// How long the agent keeps the master password once it has asked for it,
    /// counted from the last signature that used it.
    ///
    /// Unset is an hour, matching what `lpass` gives a shell. `0` keeps it
    /// until the screen locks or the agent stops — a deliberate footgun rather
    /// than one to forbid. See `master_password_idle`.
    #[serde(default)]
    pub master_password_idle_secs: Option<u64>,

    /// Where the master password comes from when the agent needs the vault
    /// and holds none.
    #[serde(default)]
    pub master_password: MasterPassword,

    /// Forget the master password when the screen locks, so walking away
    /// shuts the vault and not just the display. On by default where the
    /// screen's lock state can be read at all.
    #[serde(default = "default_lock_on_screen_lock")]
    pub lock_on_screen_lock: bool,

    /// Once a signature is approved, approve the same key for the same
    /// requester and hosts without asking, until the vault locks.
    ///
    /// Opt-in: it trades a prompt per signature for a prompt per application
    /// per unlock, and anything driving that application can then sign
    /// unasked while the vault is open.
    #[serde(default)]
    pub remember_approvals: bool,

    #[serde(default)]
    pub keys: Vec<KeyConfig>,
}

const fn default_confirm_timeout() -> u64 {
    30
}

/// On wherever it can work: reading the screen's lock state is the one part a
/// platform has to provide, and macOS and Linux do.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const fn default_lock_on_screen_lock() -> bool {
    true
}

/// Off where the setting is refused, so that an empty config still loads.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const fn default_lock_on_screen_lock() -> bool {
    false
}

/// What `master_password_idle_secs` means when unset.
const DEFAULT_MASTER_PASSWORD_IDLE: Duration = Duration::from_secs(3600);

/// An hour is already far longer than anyone waits at a signing prompt, and
/// the bound keeps `Instant::now() + timeout` well inside what the platform
/// can represent — an overflow there would panic mid-request.
const MAX_CONFIRM_TIMEOUT_SECS: u64 = 3600;

impl Config {
    pub fn default_path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".config/lastpass-ssh-agent/config.toml"))
    }

    /// Like `load`, but a missing file yields the default config (no keys):
    /// running without a config file is ordinary, not an error.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Err(Error::ConfigMissing(_)) => Ok(Self::empty()),
            other => other,
        }
    }

    /// What a setup with no config file gets: exactly what an empty file
    /// parses to.
    ///
    /// Parsed rather than constructed field by field, so it cannot drift.
    /// A hand-written mirror still compiles when a new field's `#[serde(default)]`
    /// says something else, and the two would then disagree about how the agent
    /// behaves depending only on whether a file happens to exist.
    fn empty() -> Self {
        // Every field defaults, so the only way this fails is a bug in the
        // struct's own serde attributes — which every other test would fail on.
        toml::from_str("").expect("a config of nothing but defaults must parse")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::ConfigMissing(path.to_path_buf()))
            }
            Err(e) => {
                return Err(Error::ConfigRead {
                    path: path.to_path_buf(),
                    source: e,
                })
            }
        };
        refuse_misnamed(&raw)?;
        let mut config: Self = toml::from_str(&raw).map_err(|e| Error::ConfigParse {
            path: path.to_path_buf(),
            source: Box::new(e),
        })?;
        config.socket = config.socket.map(expand_tilde);
        config.lpass_path = config.lpass_path.map(expand_tilde);
        config.askpass = config.askpass.map(expand_tilde);
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        for key in &self.keys {
            if !crate::lpass::is_item_id(&key.id) {
                return Err(Error::ConfigInvalid(format!(
                    "key id {:?} must be a numeric LastPass item id (use `lastpass-ssh-agent search` to find it)",
                    key.id
                )));
            }
        }
        let mut ids: Vec<&str> = self.keys.iter().map(|k| k.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != self.keys.len() {
            return Err(Error::ConfigInvalid("duplicate key ids in [[keys]]".into()));
        }
        if let Some(socket) = &self.socket {
            if !socket.is_absolute() {
                return Err(Error::ConfigInvalid(format!(
                    "socket path {} must be absolute — SSH clients resolve SSH_AUTH_SOCK from their own working directory",
                    socket.display()
                )));
            }
        }
        // Resolved from a working directory nothing chooses on purpose — a
        // service's is `/` — and `doctor` and `start` could resolve them from
        // different ones, so what one checks is not what the other runs.
        for (name, path) in [("lpass_path", &self.lpass_path), ("askpass", &self.askpass)] {
            if let Some(path) = path.as_deref().filter(|path| !path.is_absolute()) {
                return Err(Error::ConfigInvalid(format!(
                    "{name} {} must be absolute",
                    path.display()
                )));
            }
        }
        if self.confirm == ConfirmMode::Askpass && self.askpass.is_none() {
            return Err(Error::ConfigInvalid(
                "confirm = \"askpass\" requires `askpass` to point at a helper program".into(),
            ));
        }
        if self.confirm_timeout_secs == 0 || self.confirm_timeout_secs > MAX_CONFIRM_TIMEOUT_SECS {
            return Err(Error::ConfigInvalid(format!(
                "confirm_timeout_secs must be between 1 and {MAX_CONFIRM_TIMEOUT_SECS}"
            )));
        }
        // Refused at load, not at the first signature — and by validation
        // rather than by failing to parse, because the mode is a reasonable
        // thing to write in a config shared between machines and deserves an
        // answer naming the platform.
        //
        // Each check is compiled out on the platform that supports the mode,
        // where it could only ever be false. A runtime `cfg!` would leave a
        // branch no test on either platform can take, which the coverage gate
        // refuses.
        #[cfg(not(target_os = "macos"))]
        if self.uses_fallback(PassphraseFallback::Keychain) {
            return Err(Error::ConfigInvalid(
                "passphrase_fallback = \"keychain\" is only supported on macOS".into(),
            ));
        }
        #[cfg(not(target_os = "linux"))]
        if self.uses_fallback(PassphraseFallback::SecretService) {
            return Err(Error::ConfigInvalid(
                "passphrase_fallback = \"secretservice\" is only supported on Linux".into(),
            ));
        }
        #[cfg(not(target_os = "macos"))]
        if self.master_password == MasterPassword::TouchId {
            return Err(Error::ConfigInvalid(
                "master_password = \"touchid\" is only supported on macOS".into(),
            ));
        }
        // Same treatment, and for the same reason: reading the screen's lock
        // state is the one part of that feature a platform has to provide, and
        // macOS and Linux are the two that do. Refused at load rather than
        // ignored, since a setting silently doing nothing is worse than one that
        // says so.
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        if self.lock_on_screen_lock {
            return Err(Error::ConfigInvalid(
                "lock_on_screen_lock is only supported on macOS and Linux".into(),
            ));
        }
        Ok(())
    }

    /// Whether any key would actually reach for one particular fallback.
    ///
    /// Portable, though each caller is behind a `cfg`: macOS asks about the
    /// secret service and Linux about the Keychain, so both platforms compile
    /// and exercise it.
    fn uses_fallback(&self, wanted: PassphraseFallback) -> bool {
        // With no [[keys]] the agent discovers items and every one of them
        // inherits the global setting, so that setting decides on its own.
        if self.keys.is_empty() {
            return self.passphrase_fallback == wanted;
        }
        // Otherwise only the effective per-key values matter: a global value
        // every key overrides is never used, and rejecting a config for
        // naming a mode it never reaches would be wrong — these settings
        // replace rather than cap each other.
        self.keys
            .iter()
            .any(|key| self.passphrase_fallback(key) == wanted)
    }

    /// How long a held master password may go unused: the configured idle
    /// time, an hour when none is, and no limit for `0`.
    pub const fn master_password_idle(&self) -> Option<Duration> {
        match self.master_password_idle_secs {
            None => Some(DEFAULT_MASTER_PASSWORD_IDLE),
            Some(0) => None,
            Some(seconds) => Some(Duration::from_secs(seconds)),
        }
    }

    /// Resolved socket path (config override or platform default).
    pub fn socket_path(&self) -> Result<PathBuf> {
        self.socket
            .clone()
            .or_else(platform::default_socket_path)
            .ok_or_else(no_socket_path)
    }

    /// Effective confirmation requirement for one key.
    pub fn confirm_required(&self, key: &KeyConfig) -> bool {
        let enabled = self.confirm != ConfirmMode::Off;
        key.confirm.map_or(enabled, |explicit| explicit && enabled)
    }

    /// Effective passphrase fallback for one key. Unlike `confirm`, a per-key
    /// value simply replaces the global one: neither setting is a safety
    /// ceiling for the other, since both merely say where a passphrase the
    /// vault does not hold should come from.
    pub fn passphrase_fallback(&self, key: &KeyConfig) -> PassphraseFallback {
        key.passphrase_fallback.unwrap_or(self.passphrase_fallback)
    }
}

/// Names a setting that is written under another name, and says which.
///
/// Ahead of the parse, because "unknown field" is what the parse would say,
/// and a reader who spelt the idle time as the vault's own timeout would
/// otherwise have nothing pointing at the setting that does what they meant.
fn refuse_misnamed(raw: &str) -> Result<()> {
    const MISNAMED: &str = "vault_unlock_timeout_secs";
    let names_it =
        toml::from_str::<toml::Table>(raw).is_ok_and(|table| table.contains_key(MISNAMED));
    if names_it {
        return Err(Error::ConfigInvalid(format!(
            "`{MISNAMED}` is not a setting: how long the master password is kept is \
             `master_password_idle_secs`"
        )));
    }
    Ok(())
}

/// Reachable only when the platform reports no home directory at all,
/// which cannot be simulated in tests — excluded from coverage.
#[cfg_attr(coverage_nightly, coverage(off))]
fn no_socket_path() -> Error {
    Error::ConfigInvalid("cannot determine a socket path; set `socket` in the config".into())
}

fn expand_tilde(path: PathBuf) -> PathBuf {
    // home_dir is None only in exotic environments with no HOME and no
    // passwd entry; fall back to the literal path there
    let expanded = path
        .strip_prefix("~")
        .ok()
        .and_then(|stripped| dirs::home_dir().map(|home| home.join(stripped)));
    expanded.unwrap_or(path)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Config> {
        refuse_misnamed(s)?;
        let mut config: Config = toml::from_str(s).map_err(|e| Error::ConfigParse {
            path: PathBuf::from("<test>"),
            source: Box::new(e),
        })?;
        config.socket = config.socket.map(expand_tilde);
        config.lpass_path = config.lpass_path.map(expand_tilde);
        config.askpass = config.askpass.map(expand_tilde);
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn default_path_is_under_dot_config() {
        let path = Config::default_path().unwrap();
        assert!(path.ends_with(".config/lastpass-ssh-agent/config.toml"));
    }

    #[test]
    fn load_missing_file_and_load_or_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert!(matches!(Config::load(&path), Err(Error::ConfigMissing(_))));
        let config = Config::load_or_default(&path).unwrap();
        assert!(config.keys.is_empty());
        assert_eq!(config.confirm, ConfirmMode::default());
        assert_eq!(config.confirm_timeout_secs, 30);
        assert!(config.socket.is_none());
        assert!(config.lpass_path.is_none());
        assert!(config.askpass.is_none());
        assert_eq!(config.passphrase_fallback, PassphraseFallback::default());
    }

    #[test]
    fn load_parse_error_is_reported_with_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "not = valid = toml").unwrap();
        assert!(matches!(
            Config::load(&path),
            Err(Error::ConfigParse { .. })
        ));
        // load_or_default only forgives a MISSING file, not a broken one
        assert!(Config::load_or_default(&path).is_err());
    }

    #[test]
    fn load_unreadable_file_is_a_read_error() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root ignores file permissions");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(matches!(Config::load(&path), Err(Error::ConfigRead { .. })));
    }

    #[test]
    fn load_expands_tilde_in_all_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "socket = \"~/s.sock\"\nlpass_path = \"~/bin/lpass\"\naskpass = \"~/bin/ask\"\nconfirm = \"askpass\"\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let home = dirs::home_dir().unwrap();
        assert_eq!(config.socket.unwrap(), home.join("s.sock"));
        assert_eq!(config.lpass_path.unwrap(), home.join("bin/lpass"));
        assert_eq!(config.askpass.unwrap(), home.join("bin/ask"));
    }

    #[test]
    fn socket_path_prefers_config_over_platform_default() {
        let explicit = parse("socket = \"/tmp/x.sock\"").unwrap();
        assert_eq!(
            explicit.socket_path().unwrap(),
            PathBuf::from("/tmp/x.sock")
        );

        let defaulted = parse("").unwrap();
        assert_eq!(
            defaulted.socket_path().unwrap(),
            crate::platform::default_socket_path().unwrap()
        );
    }

    #[test]
    fn relative_socket_paths_are_rejected() {
        assert!(parse("socket = \"run/agent.sock\"").is_err());
        assert!(parse("socket = \"/tmp/agent.sock\"").is_ok());
        // ~ expands to an absolute path before validation
        assert!(parse("socket = \"~/agent.sock\"").is_ok());
    }

    #[test]
    fn confirm_timeout_must_be_within_bounds() {
        assert!(parse("confirm_timeout_secs = 0").is_err());
        // an unbounded value would overflow Instant arithmetic at signing time
        assert!(parse("confirm_timeout_secs = 18446744073709551615").is_err());
        assert!(parse(&format!(
            "confirm_timeout_secs = {MAX_CONFIRM_TIMEOUT_SECS}"
        ))
        .is_ok());
        assert!(parse(&format!(
            "confirm_timeout_secs = {}",
            MAX_CONFIRM_TIMEOUT_SECS + 1
        ))
        .is_err());
    }

    #[test]
    fn full_config_parses() {
        let config = parse(
            r#"
socket = "~/run/agent.sock"
confirm = "tty"
confirm_timeout_secs = 10

[[keys]]
id = "7482913650418273946"
name = "github"
confirm = false
"#,
        )
        .unwrap();
        assert_eq!(config.confirm, ConfirmMode::Tty);
        assert_eq!(config.confirm_timeout_secs, 10);
        assert_eq!(config.keys.len(), 1);
        assert_eq!(config.keys[0].display_name(), "github");
        assert!(!config.socket.as_ref().unwrap().starts_with("~"));
    }

    #[test]
    fn defaults_apply() {
        let config = parse(
            r#"[[keys]]
id = "1"
"#,
        )
        .unwrap();
        assert_eq!(config.confirm, ConfirmMode::default());
        assert_eq!(config.confirm_timeout_secs, 30);
        assert!(config.confirm_required(&config.keys[0]));
    }

    #[test]
    fn passphrase_fallback_defaults_to_prompting() {
        let config = parse("[[keys]]\nid = \"1\"").unwrap();
        assert_eq!(config.passphrase_fallback, PassphraseFallback::Prompt);
        assert_eq!(
            config.passphrase_fallback(&config.keys[0]),
            PassphraseFallback::Prompt
        );
    }

    #[test]
    fn passphrase_fallback_parses_each_mode_and_rejects_others() {
        for (text, expected) in [
            ("prompt", PassphraseFallback::Prompt),
            ("error", PassphraseFallback::Error),
        ] {
            let config = parse(&format!("passphrase_fallback = {text:?}")).unwrap();
            assert_eq!(config.passphrase_fallback, expected);
        }
        assert!(parse("passphrase_fallback = \"Prompt\"").is_err());
        assert!(parse("passphrase_fallback = true").is_err());
    }

    #[test]
    fn the_idle_time_is_an_hour_unless_said_otherwise_and_zero_is_forever() {
        assert_eq!(
            parse("").unwrap().master_password_idle(),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            parse("master_password_idle_secs = 300")
                .unwrap()
                .master_password_idle(),
            Some(Duration::from_secs(300))
        );
        // a footgun, but one a config is entitled to ask for
        assert_eq!(
            parse("master_password_idle_secs = 0")
                .unwrap()
                .master_password_idle(),
            None
        );
    }

    #[test]
    fn the_idle_time_written_as_a_vault_timeout_is_refused_with_its_name() {
        let error = parse("vault_unlock_timeout_secs = 300")
            .unwrap_err()
            .to_string();
        assert!(error.contains("master_password_idle_secs"), "{error}");
        // a broken file is left to the parse to describe
        assert!(parse("not = valid = toml").is_err());
    }

    #[test]
    fn approvals_are_not_remembered_unless_asked_for() {
        assert!(!parse("").unwrap().remember_approvals);
        assert!(
            parse("remember_approvals = true")
                .unwrap()
                .remember_approvals
        );
    }

    #[test]
    fn the_master_password_is_asked_for_by_default() {
        assert_eq!(parse("").unwrap().master_password, MasterPassword::Prompt);
        assert_eq!(
            parse("master_password = \"prompt\"")
                .unwrap()
                .master_password,
            MasterPassword::Prompt
        );
        assert!(
            parse("master_password = \"Prompt\"").is_err(),
            "case matters"
        );
        assert!(parse("master_password = true").is_err(), "not a bool");
        // there is no way to switch this off: an unknown value is refused,
        // never read as a vault that fails every signature
        assert!(parse("master_password = \"off\"").is_err());
    }

    /// `prompt` is deliberately not macOS-only: nothing about being asked for
    /// a password is platform-specific. Only the Touch ID half needs one.
    #[test]
    #[cfg(target_os = "macos")]
    fn the_touchid_source_is_accepted_here() {
        assert_eq!(
            parse("master_password = \"touchid\"")
                .unwrap()
                .master_password,
            MasterPassword::TouchId
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn the_touchid_source_is_refused_here_with_a_reason() {
        let error = parse("master_password = \"touchid\"")
            .unwrap_err()
            .to_string();
        assert!(error.contains("only supported on macOS"), "{error}");
        // and the portable source is unaffected
        assert!(parse("master_password = \"prompt\"").is_ok());
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn lock_on_screen_lock_is_on_here_unless_switched_off() {
        assert!(parse("").unwrap().lock_on_screen_lock);
        assert!(
            !parse("lock_on_screen_lock = false")
                .unwrap()
                .lock_on_screen_lock
        );
    }

    #[test]
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn lock_on_screen_lock_is_refused_here_with_a_reason() {
        // Reading the screen's lock state is the one part a platform has to
        // provide: macOS through its window server, Linux through logind.
        // Refused at load elsewhere, named in the message.
        let error = parse("lock_on_screen_lock = true").unwrap_err().to_string();
        assert!(
            error.contains("only supported on macOS and Linux"),
            "{error}"
        );
        assert!(!parse("").unwrap().lock_on_screen_lock);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn keychain_is_accepted_here() {
        let config = parse("passphrase_fallback = \"keychain\"").unwrap();
        assert_eq!(config.passphrase_fallback, PassphraseFallback::Keychain);
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn keychain_is_refused_here_with_a_reason() {
        // Globally, and per key, and per key even when the global setting is
        // something this platform can do.
        for text in [
            "passphrase_fallback = \"keychain\"",
            "passphrase_fallback = \"keychain\"\n[[keys]]\nid = \"1\"",
            "[[keys]]\nid = \"1\"\npassphrase_fallback = \"keychain\"",
            "passphrase_fallback = \"prompt\"\n[[keys]]\nid = \"1\"\npassphrase_fallback = \"keychain\"",
        ] {
            let error = parse(text).unwrap_err().to_string();
            assert!(error.contains("only supported on macOS"), "{text}: {error}");
        }
        // and a config that never asks for it is unaffected
        assert!(parse("passphrase_fallback = \"prompt\"\n[[keys]]\nid = \"1\"").is_ok());
        // A global value every pinned key overrides is never reached, so it is
        // not grounds for refusing the config.
        assert!(parse(
            "passphrase_fallback = \"keychain\"\n\
             [[keys]]\nid = \"1\"\npassphrase_fallback = \"prompt\"\n\
             [[keys]]\nid = \"2\"\npassphrase_fallback = \"error\""
        )
        .is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn the_secret_service_is_accepted_here() {
        let config = parse("passphrase_fallback = \"secretservice\"").unwrap();
        assert_eq!(
            config.passphrase_fallback,
            PassphraseFallback::SecretService
        );
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn the_secret_service_is_refused_here_with_a_reason() {
        // The same shape as the Keychain's check, so the two modes cannot drift
        // apart: globally, per key, and per key over a global this platform can
        // do.
        for text in [
            "passphrase_fallback = \"secretservice\"",
            "passphrase_fallback = \"secretservice\"\n[[keys]]\nid = \"1\"",
            "[[keys]]\nid = \"1\"\npassphrase_fallback = \"secretservice\"",
            "passphrase_fallback = \"prompt\"\n[[keys]]\nid = \"1\"\npassphrase_fallback = \"secretservice\"",
        ] {
            let error = parse(text).unwrap_err().to_string();
            assert!(error.contains("only supported on Linux"), "{text}: {error}");
        }
        // and a global value every pinned key overrides is never reached
        assert!(parse(
            "passphrase_fallback = \"secretservice\"\n\
             [[keys]]\nid = \"1\"\npassphrase_fallback = \"prompt\"\n\
             [[keys]]\nid = \"2\"\npassphrase_fallback = \"error\""
        )
        .is_ok());
    }

    #[test]
    fn per_key_passphrase_fallback_replaces_the_global_one() {
        let config = parse(
            r#"
passphrase_fallback = "error"
[[keys]]
id = "1"
passphrase_fallback = "prompt"
[[keys]]
id = "2"
"#,
        )
        .unwrap();
        assert_eq!(
            config.passphrase_fallback(&config.keys[0]),
            PassphraseFallback::Prompt
        );
        assert_eq!(
            config.passphrase_fallback(&config.keys[1]),
            PassphraseFallback::Error
        );

        // and in the other direction: unlike `confirm`, neither level is a
        // ceiling for the other
        let config = parse(
            r#"
passphrase_fallback = "prompt"
[[keys]]
id = "1"
passphrase_fallback = "error"
"#,
        )
        .unwrap();
        assert_eq!(
            config.passphrase_fallback(&config.keys[0]),
            PassphraseFallback::Error
        );
    }

    #[test]
    fn unknown_fields_rejected() {
        assert!(parse("keyz = 1").is_err());
        assert!(parse("[[keys]]\nid = \"1\"\nnick = \"x\"").is_err());
    }

    #[test]
    fn non_numeric_id_rejected() {
        for bad in ["", "abc", "--field", "1 2", "Personal/SSH Key"] {
            let toml = format!("[[keys]]\nid = {bad:?}");
            assert!(parse(&toml).is_err(), "id {bad:?} should be rejected");
        }
    }

    #[test]
    fn duplicate_ids_rejected() {
        assert!(parse("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"1\"").is_err());
    }

    #[test]
    fn helper_paths_must_be_absolute() {
        assert!(parse("lpass_path = \"lpass\"").is_err());
        assert!(parse("lpass_path = \"bin/lpass\"").is_err());
        assert!(parse("askpass = \"ssh-askpass\"").is_err());
        assert!(parse("lpass_path = \"/opt/homebrew/bin/lpass\"").is_ok());
        // ~ expands to an absolute path before validation
        assert!(parse("lpass_path = \"~/bin/lpass\"").is_ok());
    }

    #[test]
    fn askpass_mode_requires_helper() {
        assert!(parse("confirm = \"askpass\"").is_err());
        assert!(parse("confirm = \"askpass\"\naskpass = \"/bin/true\"").is_ok());
    }

    #[test]
    fn per_key_confirm_override() {
        let config = parse(
            r#"
[[keys]]
id = "1"
confirm = false
[[keys]]
id = "2"
"#,
        )
        .unwrap();
        assert!(!config.confirm_required(&config.keys[0]));
        assert!(config.confirm_required(&config.keys[1]));

        // confirm = "off" globally wins even over per-key confirm = true
        let config = parse(
            r#"
confirm = "off"
[[keys]]
id = "1"
confirm = true
"#,
        )
        .unwrap();
        assert!(!config.confirm_required(&config.keys[0]));
    }
}
