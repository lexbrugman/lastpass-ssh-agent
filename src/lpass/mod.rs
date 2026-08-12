mod cli;

pub use cli::{LpassCli, ASKPASS_FROM_STORE, ASKPASS_MARKER, ASKPASS_ONCE_MARKER, ASKPASS_SIGNAL};

use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

const MAX_DISCOVERY_PROBES: usize = 8;

/// One vault item as listed by `lpass ls` (names/ids only — no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginStatus {
    LoggedIn(String),
    NotLoggedIn,
}

#[derive(Debug, thiserror::Error)]
pub enum LpassError {
    #[error("not logged in to LastPass — run `lpass login <email>` and retry")]
    NotLoggedIn,

    #[error("LastPass item {0} not found (deleted, or not shared with this account?)")]
    ItemNotFound(String),

    #[error("LastPass item {item} has no {field} field")]
    FieldNotFound { item: String, field: String },

    #[error("lpass did not finish within {0:?} (killed)")]
    Timeout(Duration),

    #[error("lpass returned more than {0} bytes for a single field")]
    FieldTooLarge(usize),

    #[error("failed to run lpass: {0}")]
    Spawn(std::io::Error),

    #[error("lpass exited with {code:?}: {stderr}")]
    CommandFailed { code: Option<i32>, stderr: String },
}

/// The only interface through which the rest of the program talks to
/// `LastPass`. Field values come back in `Zeroizing` buffers; callers must not
/// copy them into non-zeroizing storage.
#[async_trait::async_trait]
pub trait LpassClient: Send + Sync {
    /// Whether a call to this client can put a prompt on the user's screen —
    /// true once lpass has somewhere to ask for the master password.
    ///
    /// The signing path needs to know *before* it calls: a prompt appearing from
    /// inside a fetch would otherwise sit outside the one-interaction-at-a-time
    /// gate, and could share the screen with another request's dialog.
    ///
    /// Required rather than defaulted: an implementation that quietly inherited
    /// "never prompts" while in fact prompting would put a master-password
    /// dialog outside the gate, which is the one thing this exists to prevent.
    fn may_prompt(&self) -> bool;

    /// Whether a call has made the master-password helper run since this
    /// client was built.
    ///
    /// Proof that a password was actually consulted. Setup needs it: an `lpass`
    /// call can succeed on a key that was already cached, which says nothing
    /// about whether the candidate password is right.
    /// Required rather than defaulted, like `may_prompt`: an implementation
    /// inheriting "never asked" would make setup reject passwords that are in
    /// fact correct, and the reason would be invisible.
    fn master_password_came_from_store(&self) -> bool;

    async fn status(&self) -> Result<LoginStatus, LpassError>;

    /// `lpass show --field=<field> <item_id>` — the value with trailing
    /// newlines removed. An existing-but-empty field yields an empty buffer.
    async fn show_field(
        &self,
        item_id: &str,
        field: &str,
    ) -> Result<Zeroizing<Vec<u8>>, LpassError>;

    /// `lpass ls` over the whole vault. Used by interactive `search` and by
    /// agent startup when no keys are pinned in the config.
    async fn ls(&self) -> Result<Vec<ItemSummary>, LpassError>;
}

/// Find the vault's SSH Key items: one `ls` for ids/names (metadata only),
/// then a concurrent `NoteType` probe per item — also metadata, never a
/// secret field. `name_filter` narrows which items get probed.
pub async fn discover_ssh_key_items(
    client: std::sync::Arc<dyn LpassClient>,
    name_filter: Option<&str>,
) -> Result<Vec<ItemSummary>, LpassError> {
    let needle = name_filter.map(str::to_lowercase);
    let candidates: Vec<ItemSummary> = client
        .ls()
        .await?
        .into_iter()
        .filter(|item| {
            needle
                .as_ref()
                .is_none_or(|needle| item.name.to_lowercase().contains(needle))
        })
        .collect();

    // `lpass ls` does not carry the note type, so telling an SSH Key from a
    // credit card costs one `lpass` call per item — which on a large vault is
    // most of a minute before the socket is even bound. Said up front so the
    // wait is explained while it is happening rather than afterwards, and so
    // the way out of it is on screen next to the reason for it.
    tracing::info!(
        items = candidates.len(),
        "probing vault items for SSH Key notes, one lpass call each — pin [[keys]] in the \
         config to skip this"
    );

    let mut probes = tokio::task::JoinSet::new();
    let mut items = candidates.into_iter();
    let mut found = Vec::new();
    loop {
        // Bound both subprocess concurrency and the amount of queued task
        // state: at most MAX_DISCOVERY_PROBES probes exist at any time.
        while probes.len() < MAX_DISCOVERY_PROBES {
            let Some(item) = items.next() else {
                break;
            };
            let client = client.clone();
            probes.spawn(async move {
                match client.show_field(&item.id, "NoteType").await {
                    Ok(note_type) => Ok((item, &*note_type == b"SSH Key")),
                    // The item is simply not a note (ordinary password entries
                    // have no NoteType), or vanished since `ls`.
                    Err(LpassError::FieldNotFound { .. } | LpassError::ItemNotFound(_)) => {
                        Ok((item, false))
                    }
                    // A real vault failure (logged out, timeout, ...) must not
                    // masquerade as "this key does not exist" — serving an
                    // incomplete identity set would silently break signing.
                    Err(e) => Err(e),
                }
            });
        }
        let Some(result) = probes.join_next().await else {
            break;
        };
        // JoinError is unreachable: the probe body cannot panic, and nothing
        // aborts the set.
        let (item, is_ssh_key) = result.expect("discovery probe panicked")?;
        if is_ssh_key {
            found.push(item);
        }
    }
    found.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
    Ok(found)
}

/// The `lpass` agent process, which is where the vault's derived key lives.
///
/// Ending it is the only way to make `lpass` forget that key: there is no
/// "lock" subcommand, and `lpass logout` would discard the session as well,
/// turning a master-password prompt into a full login with a second factor.
///
/// Identified by command line rather than by name: the agent rewrites its argv
/// to `lpass [agent]`, and on macOS the rewritten title runs into the
/// environment that followed it, so only the prefix is dependable. Matching a
/// short-lived `lpass show` too would cost nothing — a signature in flight when
/// the screen locks is one we are about to make ask for a password anyway.
pub struct LpassAgentProcess;

#[async_trait::async_trait]
impl crate::vaultlock::VaultKey for LpassAgentProcess {
    // Excluded from coverage, and deliberately: exercising the path that
    // actually matches something would mean killing a process, and the only
    // pattern worth testing is the real one — which on a developer's own
    // machine is their live vault session. The rules around this call (when it
    // fires, and how often) are `vaultlock`'s, and covered there.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn forget(&self) {
        // `pkill` rather than walking the process table ourselves: finding a
        // process by command line is /proc on Linux and sysctl on macOS, which
        // is exactly the per-platform logic this design keeps out of the way
        // for something the system already exposes as one command.
        let killed = tokio::process::Command::new("pkill")
            .arg("-f")
            .arg(r"^lpass \[a")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status()
            .await;
        // pkill's codes: 0 signalled something, 1 matched nothing, and 2 or 3
        // are its own failures. Only 1 means "there was no key to drop" —
        // folding the rest into it would report a vault as locked while it is
        // still open, which is the one thing this must not get wrong.
        match killed.as_ref().map(std::process::ExitStatus::code) {
            Ok(Some(0)) => {
                tracing::info!("the LastPass agent's cached key has been dropped");
            }
            Ok(Some(1)) => tracing::debug!("no LastPass agent was holding a key"),
            other => tracing::warn!(
                "could not drop the LastPass agent's cached key ({other:?}), so the vault \
                 stays unlocked until it expires on its own"
            ),
        }
    }
}

/// Locate the lpass binary: explicit config path first, then PATH.
pub fn resolve_binary(configured: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = configured {
        return is_executable(path).then(|| path.to_path_buf());
    }
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join("lpass"))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod discovery_tests {
    use super::mock::MockLpass;
    use super::*;
    use std::sync::Arc;

    fn vault() -> Arc<MockLpass> {
        let mut mock = MockLpass::logged_in()
            .with_field("1", "NoteType", b"SSH Key")
            .with_field("1", "Public Key", b"ssh-ed25519 AAA")
            .with_field("2", "NoteType", b"Credit Card")
            .with_field("3", "url", b"https://example.com") // plain password item
            .with_field("4", "NoteType", b"SSH Key")
            .with_field("6", "NoteType", b"SSH Key");
        mock.items = vec![
            ItemSummary {
                id: "1".into(),
                name: "Personal/GitHub Key".into(),
            },
            ItemSummary {
                id: "2".into(),
                name: "Personal/Visa".into(),
            },
            ItemSummary {
                id: "3".into(),
                name: "Work/Portal".into(),
            },
            ItemSummary {
                id: "4".into(),
                name: "Work/Deploy Key".into(),
            },
            ItemSummary {
                id: "5".into(),
                name: "Ghost item".into(),
            }, // no fields -> lpass error
            // same display name as item 4: exercises the id tie-breaker sort
            ItemSummary {
                id: "6".into(),
                name: "Work/Deploy Key".into(),
            },
        ];
        Arc::new(mock)
    }

    #[tokio::test]
    async fn finds_only_ssh_key_items_sorted_by_name_then_id() {
        let found = discover_ssh_key_items(vault(), None).await.unwrap();
        let ids: Vec<_> = found.iter().map(|i| i.id.as_str()).collect();
        // sorted by name (GitHub Key < Work/...), equal names tie-break by id
        assert_eq!(ids, ["1", "4", "6"]);
    }

    #[tokio::test]
    async fn discovery_replenishes_its_bounded_probe_window() {
        // More than MAX_DISCOVERY_PROBES items forces the scheduler to reap
        // completed work and admit later items instead of spawning the whole
        // vault up front.
        let mut mock = MockLpass::logged_in();
        for id in 0..(MAX_DISCOVERY_PROBES + 3) {
            let id = id.to_string();
            mock.items.push(ItemSummary {
                name: format!("Key {id:0>2}"),
                id: id.clone(),
            });
            mock = mock.with_field(&id, "NoteType", b"SSH Key");
        }

        let found = discover_ssh_key_items(Arc::new(mock), None).await.unwrap();
        assert_eq!(found.len(), MAX_DISCOVERY_PROBES + 3);
        assert_eq!(found.first().unwrap().id, "0");
        assert_eq!(found.last().unwrap().id, "10");
    }

    #[tokio::test]
    async fn name_filter_narrows_probes_and_results() {
        let mock = vault();
        let found = discover_ssh_key_items(mock.clone(), Some("work"))
            .await
            .unwrap();
        let ids: Vec<_> = found.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["4", "6"]);
        // items whose names don't match must never be probed at all
        assert!(mock
            .fetch_log
            .lock()
            .unwrap()
            .iter()
            .all(|(id, _)| id == "3" || id == "4" || id == "6"));
    }

    #[tokio::test]
    async fn discovery_never_touches_secret_fields() {
        let mock = vault();
        discover_ssh_key_items(mock.clone(), None).await.unwrap();
        assert!(mock
            .fetch_log
            .lock()
            .unwrap()
            .iter()
            .all(|(_, field)| field == "NoteType"));
    }

    #[tokio::test]
    async fn items_without_a_notetype_field_are_not_ssh_keys() {
        // ordinary password entries: real lpass exits 1 with
        // "Could not find specified field", which is a plain negative
        let mut mock = MockLpass::logged_in()
            .with_field("1", "NoteType", b"SSH Key")
            .with_absent_field("2", "NoteType");
        mock.items = vec![
            ItemSummary {
                id: "1".into(),
                name: "Key".into(),
            },
            ItemSummary {
                id: "2".into(),
                name: "Password".into(),
            },
        ];
        let found = discover_ssh_key_items(Arc::new(mock), None).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "1");
    }

    #[tokio::test]
    async fn a_probe_failure_fails_discovery_rather_than_dropping_a_key() {
        // A logged-out/timed-out probe must not be mistaken for "not an SSH
        // key": serving an incomplete identity set breaks signing silently.
        let mut mock = MockLpass::logged_in()
            .with_field("1", "NoteType", b"SSH Key")
            .with_broken_field("2", "NoteType");
        mock.items = vec![
            ItemSummary {
                id: "1".into(),
                name: "Key".into(),
            },
            ItemSummary {
                id: "2".into(),
                name: "Other".into(),
            },
        ];
        assert!(discover_ssh_key_items(Arc::new(mock), None).await.is_err());
    }

    #[tokio::test]
    async fn discovery_requires_login() {
        let mock = Arc::new(MockLpass::default());
        assert!(matches!(
            discover_ssh_key_items(mock, None).await,
            Err(LpassError::NotLoggedIn)
        ));
    }

    #[test]
    fn resolve_binary_honors_explicit_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = crate::testutil::write_script(dir.path(), "lpass", "");
        assert_eq!(resolve_binary(Some(&bin)), Some(bin.clone()));

        // configured but missing or not executable -> None, no PATH fallback
        assert_eq!(resolve_binary(Some(&dir.path().join("nope"))), None);
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(resolve_binary(Some(&bin)), None);
        // a directory is executable-bit-set but not a file
        assert_eq!(resolve_binary(Some(dir.path())), None);
    }

    #[test]
    fn resolve_binary_searches_path() {
        // the dev machine and CI both have PATH; lpass may or may not be on
        // it — both outcomes exercise the search without asserting presence
        let _ = resolve_binary(None);
    }
}

/// In-memory fake vault for tests.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod mock {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    pub struct MockLpass {
        pub logged_in: bool,
        /// (item id, field name) -> value. Items appear by having fields.
        pub fields: HashMap<(String, String), Vec<u8>>,
        pub items: Vec<ItemSummary>,
        /// Item ids that fail with a generic lpass error on any access.
        pub broken_items: Vec<String>,
        /// (item id, field) pairs that fail on access.
        pub broken_fields: Vec<(String, String)>,
        /// (item id, field) pairs that report the vault as shut.
        pub logged_out_fields: Vec<(String, String)>,
        /// (item id, field) pairs the item simply does not have.
        pub absent_fields: Vec<(String, String)>,
        /// Every (item, field) fetched, for assertions on what was touched.
        pub fetch_log: Mutex<Vec<(String, String)>>,
        /// Stands in for a vault that can ask for the master password.
        pub prompting: bool,
    }

    impl MockLpass {
        pub fn logged_in() -> Self {
            Self {
                logged_in: true,
                ..Self::default()
            }
        }

        pub fn with_field(mut self, item: &str, field: &str, value: &[u8]) -> Self {
            self.fields
                .insert((item.into(), field.into()), value.to_vec());
            self
        }

        /// As a client with an askpass helper installed: fetches from it may
        /// put a prompt on screen.
        pub const fn prompting(mut self) -> Self {
            self.prompting = true;
            self
        }

        pub fn with_broken_item(mut self, item: &str) -> Self {
            self.broken_items.push(item.into());
            self
        }

        /// As a vault whose key has expired: this field reports not-logged-in
        /// while the rest of the client still works.
        pub fn with_logged_out_field(mut self, item: &str, field: &str) -> Self {
            self.logged_out_fields.push((item.into(), field.into()));
            self
        }

        pub fn with_broken_field(mut self, item: &str, field: &str) -> Self {
            self.broken_fields.push((item.into(), field.into()));
            self
        }

        pub fn with_absent_field(mut self, item: &str, field: &str) -> Self {
            self.absent_fields.push((item.into(), field.into()));
            self
        }
    }

    #[async_trait::async_trait]
    impl LpassClient for MockLpass {
        fn master_password_came_from_store(&self) -> bool {
            self.prompting
        }

        fn may_prompt(&self) -> bool {
            self.prompting
        }

        async fn status(&self) -> Result<LoginStatus, LpassError> {
            Ok(if self.logged_in {
                LoginStatus::LoggedIn("mock@example.com".into())
            } else {
                LoginStatus::NotLoggedIn
            })
        }

        async fn show_field(
            &self,
            item_id: &str,
            field: &str,
        ) -> Result<Zeroizing<Vec<u8>>, LpassError> {
            self.fetch_log
                .lock()
                .unwrap()
                .push((item_id.into(), field.into()));
            if !self.logged_in {
                return Err(LpassError::NotLoggedIn);
            }
            if self
                .logged_out_fields
                .iter()
                .any(|(id, f)| id == item_id && f == field)
            {
                return Err(LpassError::NotLoggedIn);
            }
            if self
                .absent_fields
                .iter()
                .any(|(id, f)| id == item_id && f == field)
            {
                return Err(LpassError::FieldNotFound {
                    item: item_id.into(),
                    field: field.into(),
                });
            }
            if self.broken_items.iter().any(|id| id == item_id)
                || self
                    .broken_fields
                    .iter()
                    .any(|(id, f)| id == item_id && f == field)
            {
                return Err(LpassError::CommandFailed {
                    code: Some(1),
                    stderr: "mock: broken item".into(),
                });
            }
            let key = (item_id.to_string(), field.to_string());
            match self.fields.get(&key) {
                Some(value) => Ok(Zeroizing::new(value.clone())),
                // Item exists (has other fields) -> lpass yields empty output;
                // completely unknown item -> not found.
                None if self.fields.keys().any(|(id, _)| id == item_id) => {
                    Ok(Zeroizing::new(Vec::new()))
                }
                None => Err(LpassError::ItemNotFound(item_id.into())),
            }
        }

        async fn ls(&self) -> Result<Vec<ItemSummary>, LpassError> {
            if !self.logged_in {
                return Err(LpassError::NotLoggedIn);
            }
            Ok(self.items.clone())
        }
    }
}
