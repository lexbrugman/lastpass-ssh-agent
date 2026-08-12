use std::path::{Path, PathBuf};

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
}

/// Where the vault's master password comes from when `lpass` has forgotten the
/// key it derived and asks for it again.
///
/// Not about *why* it was forgotten: the hourly timeout and a screen lock reach
/// here alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MasterPassword {
    /// Never asked for. A locked vault fails the signature, and you reopen it
    /// yourself — what the agent did before any of this existed.
    #[default]
    Off,
    /// Asked for through the agent's own prompt, and never kept.
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

    /// How long the vault stays unlocked once `lpass` has derived its key.
    ///
    /// Unset leaves lpass to its own default, an hour. `0` means never expire,
    /// which is lpass's own encoding and a deliberate footgun rather than one
    /// to forbid.
    ///
    /// Only governs an `lpass` agent *this* agent starts: whichever process
    /// gets there first fixes it, so a shell that has already run `lpass` keeps
    /// whatever it set. `lastpass-ssh-agent env` prints this so a shell profile
    /// can take the same value from here rather than repeating it.
    #[serde(default)]
    pub vault_unlock_timeout_secs: Option<u64>,

    /// Where the master password comes from when `lpass` asks for one.
    ///
    /// Opt-in because it changes what a locked vault does to a signature, and
    /// because anything but `off` means the agent handles the master password
    /// at all — which by default it never does.
    #[serde(default)]
    pub master_password: MasterPassword,

    /// Drop the vault's cached key when the screen locks, so walking away
    /// shuts the vault and not just the display.
    ///
    /// Worth pairing with a `master_password` source: without one, every lock
    /// costs one failed signature before you re-authenticate by hand.
    #[serde(default)]
    pub lock_on_screen_lock: bool,

    #[serde(default)]
    pub keys: Vec<KeyConfig>,
}

const fn default_confirm_timeout() -> u64 {
    30
}

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
            if key.id.is_empty() || !key.id.bytes().all(|b| b.is_ascii_digit()) {
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
        // lpass hands this to `alarm`, whose argument is 32-bit: anything
        // larger wraps, and a value that wraps to zero means *never expire* —
        // the opposite of a short timeout, arrived at silently. Refused here
        // rather than discovered by a vault that never locks.
        if self
            .vault_unlock_timeout_secs
            .is_some_and(|seconds| seconds > u64::from(u32::MAX))
        {
            return Err(Error::ConfigInvalid(format!(
                "vault_unlock_timeout_secs must be at most {} — lpass truncates it to 32 \
                 bits, and a larger value can wrap to 0, which means never expire",
                u32::MAX
            )));
        }
        // Refused at load, not at the first signature — and by validation
        // rather than by failing to parse, because the mode is a reasonable
        // thing to write in a config shared between machines and deserves an
        // answer naming the platform.
        //
        // Compiled out on macOS, where it could only ever be false. A runtime
        // `cfg!` would leave a branch no test on either platform can take,
        // which the coverage gate refuses.
        #[cfg(not(target_os = "macos"))]
        if self.uses_keychain() {
            return Err(Error::ConfigInvalid(
                "passphrase_fallback = \"keychain\" is only supported on macOS".into(),
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
        // only macOS does so far. Refused at load rather than ignored, since a
        // setting silently doing nothing is worse than one that says so.
        #[cfg(not(target_os = "macos"))]
        if self.lock_on_screen_lock {
            return Err(Error::ConfigInvalid(
                "lock_on_screen_lock is only supported on macOS".into(),
            ));
        }
        Ok(())
    }

    /// Whether any key would actually reach for the Keychain.
    #[cfg(not(target_os = "macos"))]
    fn uses_keychain(&self) -> bool {
        // With no [[keys]] the agent discovers items and every one of them
        // inherits the global setting, so that setting decides on its own.
        if self.keys.is_empty() {
            return self.passphrase_fallback == PassphraseFallback::Keychain;
        }
        // Otherwise only the effective per-key values matter: a global value
        // every key overrides is never used, and rejecting a config for
        // naming a mode it never reaches would be wrong — these settings
        // replace rather than cap each other.
        self.keys
            .iter()
            .any(|key| self.passphrase_fallback(key) == PassphraseFallback::Keychain)
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
        let mut config: Config = toml::from_str(s).map_err(|e| Error::ConfigParse {
            path: PathBuf::from("<test>"),
            source: Box::new(e),
        })?;
        config.socket = config.socket.map(expand_tilde);
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

    /// `keychain` parses everywhere — it is a reasonable thing to write in a
    /// config shared between machines — and is accepted or refused by platform
    /// at load, never at the first signature.
    #[test]
    fn the_vault_timeout_is_bounded_by_what_lpass_can_hold() {
        assert_eq!(parse("").unwrap().vault_unlock_timeout_secs, None);
        assert_eq!(
            parse("vault_unlock_timeout_secs = 300")
                .unwrap()
                .vault_unlock_timeout_secs,
            Some(300)
        );
        // 0 is lpass's own encoding for "never expire" — a footgun, but its
        // footgun, and one a config is entitled to ask for.
        assert_eq!(
            parse("vault_unlock_timeout_secs = 0")
                .unwrap()
                .vault_unlock_timeout_secs,
            Some(0)
        );
        // the boundary itself is fine; one past it wraps in lpass's `alarm`
        assert!(parse(&format!("vault_unlock_timeout_secs = {}", u32::MAX)).is_ok());
        let error = parse(&format!(
            "vault_unlock_timeout_secs = {}",
            u64::from(u32::MAX) + 1
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("never expire"), "{error}");
    }

    #[test]
    fn the_master_password_source_is_off_by_default() {
        assert_eq!(parse("").unwrap().master_password, MasterPassword::Off);
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
    }

    /// `prompt` is deliberately not macOS-only: `lpass` forgets its key on its
    /// own timeout everywhere, and being asked rather than failing is worth
    /// having on any platform. Only the Touch ID half needs a platform.
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
    #[cfg(target_os = "macos")]
    fn lock_on_screen_lock_is_accepted_here() {
        assert!(
            parse("lock_on_screen_lock = true")
                .unwrap()
                .lock_on_screen_lock
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn lock_on_screen_lock_is_refused_here_with_a_reason() {
        // Reading the screen's lock state is the one part a platform has to
        // provide, and only macOS does. Refused at load, named in the message.
        let error = parse("lock_on_screen_lock = true").unwrap_err().to_string();
        assert!(error.contains("only supported on macOS"), "{error}");
        // and the default is off everywhere, so an ordinary config is fine
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
