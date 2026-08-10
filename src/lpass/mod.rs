mod cli;

pub use cli::LpassCli;

use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

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
    async fn status(&self) -> Result<LoginStatus, LpassError>;

    /// `lpass show --field=<field> <item_id>` — the value with trailing
    /// newlines removed. An existing-but-empty field yields an empty buffer.
    async fn show_field(
        &self,
        item_id: &str,
        field: &str,
    ) -> Result<Zeroizing<Vec<u8>>, LpassError>;

    /// `lpass ls` over the whole vault (interactive `search` helper only —
    /// the agent itself never enumerates the vault).
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
    let items = client.ls().await?.into_iter().filter(|item| {
        needle
            .as_ref()
            .is_none_or(|needle| item.name.to_lowercase().contains(needle))
    });

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    let mut probes = tokio::task::JoinSet::new();
    for item in items {
        let client = client.clone();
        let semaphore = semaphore.clone();
        probes.spawn(async move {
            let _permit = semaphore.acquire().await.expect("semaphore never closed");
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

    let mut found = Vec::new();
    while let Some(result) = probes.join_next().await {
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
        let bin = dir.path().join("lpass");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
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
        /// (item id, field) pairs the item simply does not have.
        pub absent_fields: Vec<(String, String)>,
        /// Every (item, field) fetched, for assertions on what was touched.
        pub fetch_log: Mutex<Vec<(String, String)>>,
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

        pub fn with_broken_item(mut self, item: &str) -> Self {
            self.broken_items.push(item.into());
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
