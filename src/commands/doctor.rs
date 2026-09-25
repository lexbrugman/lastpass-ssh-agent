//! `doctor`: the setup, checked the way the agent would use it.

use std::path::Path;
use std::sync::Arc;

use crate::config::{self, Config};
use crate::error::{Error, Result};
use crate::lpass::{self, LpassClient};
use crate::{confirm, enclave, identities, keystore, master, socket};

/// One line of the `doctor` checklist.
struct Check {
    ok: bool,
    label: String,
    detail: String,
}

impl Check {
    fn passed(label: &str, detail: String) -> Self {
        Self {
            ok: true,
            label: label.to_string(),
            detail,
        }
    }

    fn failed(label: &str, detail: String) -> Self {
        Self {
            ok: false,
            label: label.to_string(),
            detail,
        }
    }
}

/// Run every check the setup allows, reporting each as it is made.
///
/// A check is skipped rather than failed when what it needs is already missing:
/// there is no login to test without an lpass binary, and no keys to inspect
/// without a login. The failure is already on the checklist, and repeating it
/// under another label would suggest two problems where there is one.
pub async fn run(config_path: &Path, test_confirm: bool) -> Result<()> {
    // Printed as each check finishes rather than collected and printed at the
    // end: the vault checks can take seconds, and a checklist that appears all
    // at once reads as a hang.
    let mut ok = true;
    let mut report = |check: Check| {
        println!(
            "{} {}: {}",
            if check.ok { "✓" } else { "✗" },
            check.label,
            check.detail
        );
        ok &= check.ok;
    };

    let (check, config) = check_config(config_path);
    report(check);

    let (check, client) = check_lpass_binary(config.as_ref())?;
    report(check);

    let (login, logged_in) = check_login(client.as_ref()).await;
    if let Some(check) = login {
        report(check);
    }

    if let (Some(config), Some(client), true) = (&config, &client, logged_in) {
        for check in check_keys(client, config).await {
            report(check);
        }
    }

    if let Some(config) = &config {
        report(check_socket(config));
        for check in check_remembered(config) {
            report(check);
        }
        report(master_password_check(
            config.master_password,
            master::store_available(),
            master_password_seeded(config),
        ));
    }

    if test_confirm {
        if let Some(config) = &config {
            report(check_confirmation(config).await?);
        }
    }

    if ok {
        Ok(())
    } else {
        Err(Error::DoctorFailed)
    }
}

/// The config file, and the config every later check runs against.
///
/// A missing file passes: running without one is ordinary, and the agent falls
/// back to defaults plus auto-discovery.
fn check_config(config_path: &Path) -> (Check, Option<Config>) {
    match Config::load(config_path) {
        Ok(config) => {
            let keys = if config.keys.is_empty() {
                "no [[keys]] — auto-discovery".to_string()
            } else {
                format!("{} pinned key(s)", config.keys.len())
            };
            let detail = format!("{} ({keys})", config_path.display());
            (Check::passed("config", detail), Some(config))
        }
        Err(Error::ConfigMissing(_)) => (
            Check::passed(
                "config",
                format!(
                    "no file at {} — using defaults + auto-discovery",
                    config_path.display()
                ),
            ),
            Config::load_or_default(config_path).ok(),
        ),
        Err(e) => (Check::failed("config", e.to_string()), None),
    }
}

/// The lpass binary, and a client that talks to it.
///
/// The client asks for the master password if the vault turns out to be
/// locked, as the agent would: that arrangement is what `doctor` is checking.
/// Without a config there is nothing to ask through, and beside a running
/// agent nothing may ask; a locked vault is then reported as one.
fn check_lpass_binary(config: Option<&Config>) -> Result<(Check, Option<Arc<dyn LpassClient>>)> {
    let configured = config.and_then(|c| c.lpass_path.as_deref());
    let Some(path) = lpass::resolve_binary(configured) else {
        return Ok((
            Check::failed(
                "lpass binary",
                "not found on PATH (brew install lastpass-cli, or set `lpass_path`)".into(),
            ),
            None,
        ));
    };
    let check = Check::passed("lpass binary", path.display().to_string());
    let source = match config {
        Some(config) => super::one_shot_source(config, &config.socket_path()?)?,
        None => lpass::MasterPasswordSource::None,
    };
    let client: Arc<dyn LpassClient> = Arc::new(lpass::LpassCli::new(path).feeding(source));
    Ok((check, Some(client)))
}

/// Whether the vault opens — with the master password, if it asks for one.
///
/// No check at all without a binary to ask with: that failure is already
/// reported, and a second line about it would only repeat it.
async fn check_login(client: Option<&Arc<dyn LpassClient>>) -> (Option<Check>, bool) {
    let Some(client) = client else {
        return (None, false);
    };
    match client.ls().await {
        Ok(_) => (
            Some(Check::passed(
                "lpass login",
                "logged in, and the vault opens".into(),
            )),
            true,
        ),
        Err(lpass::LpassError::NotLoggedIn) => (
            Some(Check::failed(
                "lpass login",
                "not logged in — run `lpass login <email>`".into(),
            )),
            false,
        ),
        Err(e) => (Some(Check::failed("lpass login", e.to_string())), false),
    }
}

/// One line per key the agent would serve, or one for why there are none.
///
/// The policy itself lives in `keystore::inspect_keys`, which `start` uses too,
/// so what `doctor` reports cannot drift from what the agent does.
async fn check_keys(client: &Arc<dyn LpassClient>, config: &Config) -> Vec<Check> {
    let keys = match keystore::effective_keys(client, config).await {
        Ok(keys) => keys,
        Err(e) => return vec![Check::failed("keys", e.to_string())],
    };
    let mut checks: Vec<Check> = keystore::inspect_keys(client.as_ref(), &keys, config)
        .await
        .into_iter()
        .map(|inspection| match inspection {
            keystore::KeyInspection::Usable(entry) => Check::passed(
                &format!("key {} [id: {}]", entry.name, entry.item_id),
                format!("{} {}", entry.public.algorithm(), entry.fingerprint()),
            ),
            keystore::KeyInspection::Unusable {
                item_id,
                name,
                issue,
            } => Check::failed(&format!("key {name} [id: {item_id}]"), issue.to_string()),
        })
        .collect();
    let served = checks.iter().filter(|check| check.ok).count();
    checks.extend(too_many_keys("key count", served));
    checks
}

/// How many keys `ssh` may offer before a server with `sshd`'s default
/// `MaxAuthTries` drops the connection.
const MAX_AUTH_TRIES: usize = 6;

/// A line for a served set larger than a server will try, since the failure it
/// causes — "Too many authentication failures", on a host whose key is in the
/// set — names neither this agent nor the count.
fn too_many_keys(label: &str, served: usize) -> Option<Check> {
    (served > MAX_AUTH_TRIES).then(|| {
        Check::passed(
            label,
            format!(
                "{served} served, and a server tries {MAX_AUTH_TRIES} by default before \
                 refusing — pin a few in [[keys]], or set `IdentitiesOnly yes` and an \
                 `IdentityFile` per host in ssh_config"
            ),
        )
    })
}

/// The same invariants `start` enforces on the socket directory. A directory
/// that does not exist yet passes, because `start` creates it correctly.
fn check_socket(config: &Config) -> Check {
    let resolved = config.socket_path().and_then(|path| {
        path.parent()
            .filter(|d| !d.as_os_str().is_empty())
            .map_or_else(
                || Err(Error::Socket("socket path has no parent directory".into())),
                socket::validate_dir,
            )
            .map(|()| path)
    });
    match resolved {
        Ok(path) => Check::passed("socket path", path.display().to_string()),
        Err(e) => Check::failed("socket path", e.to_string()),
    }
}

/// What an earlier start wrote down beside the socket, if anything — and,
/// since a start can serve from it with no vault at all, the key-count line
/// for it too.
fn check_remembered(config: &Config) -> Vec<Check> {
    const LABEL: &str = "remembered identities";
    let found = config.socket_path().and_then(|socket| {
        let path = identities::path_for(&socket);
        identities::load(&path).map(|found| (path, found))
    });
    match found {
        Ok((path, Some(remembered))) => {
            let mut checks = vec![Check::passed(
                LABEL,
                format!(
                    "{} at {} — a running agent refreshes them after a signature; `list` \
                     rewrites them for the next start",
                    remembered.keys.len(),
                    path.display()
                ),
            )];
            // Counted as a start would serve them: pinned keys narrow the file.
            let served = keystore::KeyStore::from_remembered(&remembered, config)
                .store
                .entries()
                .count();
            checks.extend(too_many_keys("remembered key count", served));
            checks
        }
        Ok((path, None)) => vec![Check::passed(
            LABEL,
            format!(
                "none yet at {} — the first start writes them",
                path.display()
            ),
        )],
        Err(e) => vec![Check::failed(LABEL, e.to_string())],
    }
}

/// Whether a master password is already stored, which is a question about a
/// file and never about a fingerprint — `doctor` must not cost one.
///
/// A socket path that will not resolve, or a file that will not decode, both
/// come out as "nothing stored": the first is `check_socket`'s to report and
/// the second is answered by the same instruction as an empty store.
fn master_password_seeded(config: &Config) -> bool {
    config
        .socket_path()
        .and_then(|socket| enclave::load(&enclave::path_for(&socket)))
        .is_ok_and(|stored| stored.is_some())
}

/// The master-password line of the checklist.
///
/// Takes the two facts rather than looking them up, so every arm is exercised
/// on both platforms — `touchid` cannot even be parsed into a config off macOS,
/// which would otherwise leave most of this untestable there.
fn master_password_check(source: config::MasterPassword, available: bool, seeded: bool) -> Check {
    const LABEL: &str = "master password";
    match source {
        config::MasterPassword::Prompt => Check::passed(
            LABEL,
            "asked for when the vault needs opening, and held only until it locks".into(),
        ),
        config::MasterPassword::TouchId if !available => Check::failed(
            LABEL,
            "no Secure Enclave on this machine — use master_password = \"prompt\"".into(),
        ),
        config::MasterPassword::TouchId if !seeded => Check::failed(
            LABEL,
            "nothing stored yet — run `lastpass-ssh-agent store-master-password`".into(),
        ),
        config::MasterPassword::TouchId => {
            Check::passed(LABEL, "stored, and released only on Touch ID".into())
        }
    }
}

/// Pop the configured prompt once, for `--test-confirm`.
async fn check_confirmation(config: &Config) -> Result<Check> {
    if config.confirm == config::ConfirmMode::Off {
        // `from_config` hands back the confirmer that approves everything here,
        // so going ahead would report an approval nobody was asked for.
        return Ok(Check::failed(
            "confirmation",
            "confirm = \"off\" — nothing to test; enable a confirm mode first".into(),
        ));
    }
    let confirmer = confirm::from_config(config)?;
    let ctx = confirm::ConfirmContext::describing(
        "doctor test (no real key)".into(),
        "SHA256:this-is-only-a-test".into(),
        "0".into(),
        Some(confirm::PeerInfo {
            pid: Some(std::process::id().cast_signed()),
            // SAFETY: getuid cannot fail and touches no memory.
            uid: unsafe { libc::getuid() },
        }),
        Vec::new(),
    );
    Ok(match confirmer.confirm(&ctx).await {
        confirm::Decision::Approve => {
            Check::passed("confirmation", "user approved the test prompt".into())
        }
        confirm::Decision::Deny => Check::failed(
            "confirmation",
            "denied/timed out (fail-closed works, but approve to pass this check)".into(),
        ),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::testing::{config_with_socket, remembered};
    use super::*;

    #[test]
    fn doctor_reports_the_remembered_identities() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_with_socket(dir.path());
        let none = check_remembered(&config).remove(0);
        assert!(none.ok);
        assert!(none.detail.contains("none yet"), "{}", none.detail);

        remembered(
            dir.path(),
            "[[keys]]\nid = \"1\"\nname = \"n\"\npublic = \"p\"\n",
        );
        let some = check_remembered(&config).remove(0);
        assert!(some.ok);
        assert!(some.detail.starts_with("1 at "), "{}", some.detail);

        // a directory where the file should be cannot be read as one
        std::fs::remove_file(dir.path().join("agent.sock.identities")).unwrap();
        std::fs::create_dir(dir.path().join("agent.sock.identities")).unwrap();
        assert!(!check_remembered(&config)[0].ok);
    }

    #[test]
    fn nothing_is_stored_until_something_is() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_with_socket(dir.path());
        assert!(!master_password_seeded(&config));

        let stored = enclave::Stored {
            blob: vec![1, 2, 3],
            cipher: vec![4, 5, 6],
        };
        let path = dir.path().join("agent.sock.master");
        enclave::save(&path, &stored).unwrap();
        assert!(master_password_seeded(&config));
    }

    #[test]
    fn a_file_that_will_not_decode_counts_as_nothing_stored() {
        // `store-master-password` is the answer either way, and the socket
        // check reports anything wrong with the path itself.
        let dir = tempfile::tempdir().unwrap();
        let config = config_with_socket(dir.path());
        std::fs::write(dir.path().join("agent.sock.master"), b"not ours").unwrap();
        assert!(!master_password_seeded(&config));
    }

    fn expect_check(source: config::MasterPassword, available: bool, seeded: bool) -> Check {
        master_password_check(source, available, seeded)
    }

    #[test]
    fn the_prompt_source_passes_without_needing_anything() {
        let check = expect_check(config::MasterPassword::Prompt, false, false);
        assert!(check.ok, "{}", check.detail);
        assert!(check.detail.contains("held only"), "{}", check.detail);
    }

    #[test]
    fn touchid_without_an_enclave_fails_and_names_the_alternative() {
        let check = expect_check(config::MasterPassword::TouchId, false, false);
        assert!(!check.ok);
        assert!(check.detail.contains("\"prompt\""), "{}", check.detail);
    }

    #[test]
    fn touchid_with_nothing_stored_fails_and_says_what_to_run() {
        let check = expect_check(config::MasterPassword::TouchId, true, false);
        assert!(!check.ok);
        assert!(
            check.detail.contains("store-master-password"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn touchid_once_seeded_passes() {
        let check = expect_check(config::MasterPassword::TouchId, true, true);
        assert!(check.ok, "{}", check.detail);
        assert!(check.detail.contains("Touch ID"), "{}", check.detail);
    }

    #[test]
    fn a_served_set_larger_than_a_server_tries_gets_a_line() {
        assert!(too_many_keys("key count", MAX_AUTH_TRIES).is_none());
        let line = too_many_keys("key count", MAX_AUTH_TRIES + 1).unwrap();
        assert!(line.ok, "a warning, not a failure");
        assert!(line.detail.contains("IdentitiesOnly"), "{}", line.detail);
    }
}
