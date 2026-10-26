use std::path::Path;
use std::sync::Arc;

use ssh_key::public::KeyData;
use ssh_key::PublicKey;

use crate::config::{Config, KeyConfig, PassphraseFallback};
use crate::error::{Error, Result};
use crate::identities::{Remembered, RememberedKey};
use crate::lpass::{Access, LpassClient, LpassError};

/// Why a configured/discovered item cannot be served. Shared by startup and
/// `doctor` so the diagnostic command cannot drift from the real policy.
#[derive(Debug, thiserror::Error)]
pub enum KeyIssue {
    #[error("{0}")]
    Fetch(#[from] crate::lpass::LpassError),

    #[error("item has an empty Public Key field")]
    Empty,

    #[error("Public Key field does not parse as an OpenSSH public key: {0}")]
    Malformed(String),

    #[error("this agent cannot sign with {0} keys")]
    Unsupported(String),

    // Rendered by `start` as its own fatal error and by `doctor` as a
    // finding, so it states the problem and the remedy without predicting
    // what either command will do. The remedy has to fit both modes: with
    // [[keys]] pinned the user drops one entry, and under auto-discovery
    // there is no config listing them to remove from in the first place.
    #[error(
        "same public key as item {other_item} — signing would be ambiguous; \
         keep one and pin it with [[keys]]"
    )]
    Duplicate { other_item: String },
}

/// The result of applying the agent's complete public-key policy to one
/// item. Names are display-escaped before either consumer sees them.
#[derive(Debug)]
pub enum KeyInspection {
    Usable(KeyEntry),
    Unusable {
        item_id: String,
        name: String,
        issue: KeyIssue,
    },
}

/// One usable key: the public half plus where to find the private half.
/// The private key is never stored here.
#[derive(Debug)]
pub struct KeyEntry {
    pub item_id: String,
    pub name: String,
    pub public: PublicKey,
    pub confirm: bool,
    /// Where this key's passphrase comes from if the item's own `Passphrase`
    /// field turns out to be empty. Resolved from config at load time so the
    /// signing path never has to consult it again.
    pub passphrase_fallback: PassphraseFallback,
}

impl KeyEntry {
    pub fn fingerprint(&self) -> String {
        self.public
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
    }
}

/// Public-key blob -> `LastPass` item mapping, built once at startup.
#[derive(Debug)]
pub struct KeyStore {
    entries: Vec<KeyEntry>,
    /// Whether the vault answered for every item it was asked about. Its
    /// verdicts — nothing there, nothing this agent can serve — are answers;
    /// an item it could not be asked about is not, and a set missing one is
    /// served but never written down, see `remember_if_complete`.
    complete: bool,
}

/// Fetch and validate every public key, including cross-item duplicate
/// detection. This is the single source of truth for both startup and
/// `doctor`; private fields are never touched.
pub async fn inspect_keys(
    client: &dyn LpassClient,
    keys: &[KeyConfig],
    config: &Config,
    access: Access,
) -> Vec<KeyInspection> {
    let mut inspected = Vec::with_capacity(keys.len());
    let mut seen: Vec<(KeyData, String)> = Vec::new();

    for key in keys {
        let name = crate::text::escape_for_display(key.display_name());
        let public = match client.show_field(&key.id, "Public Key", access).await {
            Ok(raw) => accept(&raw),
            Err(e) => Err(e.into()),
        }
        .and_then(|public| unique(&mut seen, public, &key.id));

        inspected.push(match public {
            Ok(public) => KeyInspection::Usable(KeyEntry {
                item_id: key.id.clone(),
                name,
                public,
                confirm: config.confirm_required(key),
                passphrase_fallback: config.passphrase_fallback(key),
            }),
            Err(issue) => KeyInspection::Unusable {
                item_id: key.id.clone(),
                name,
                issue,
            },
        });
    }

    inspected
}

/// The keys the agent should serve: the configured [[keys]] if any,
/// otherwise every SSH Key item discovered in the vault.
pub async fn effective_keys(
    client: &Arc<dyn LpassClient>,
    config: &Config,
    access: Access,
) -> Result<Vec<KeyConfig>> {
    if !config.keys.is_empty() {
        return Ok(config.keys.clone());
    }
    tracing::info!("no [[keys]] configured — discovering SSH Key items in the vault");
    let found = crate::lpass::discover_ssh_key_items(client.clone(), None, access).await?;
    if found.is_empty() {
        return Err(Error::ConfigInvalid(
            "no SSH Key items found in the vault (create one in LastPass, or pin items with [[keys]] in the config)"
                .into(),
        ));
    }
    Ok(found
        .into_iter()
        .map(|item| KeyConfig {
            id: item.id,
            name: Some(item.name),
            // No per-key overrides for a discovered item: there is no config
            // entry to have written one in, so both fall back to the globals.
            confirm: None,
            passphrase_fallback: None,
        })
        .collect())
}

/// The served set as the running agent holds it, replaceable whole.
///
/// A request takes a snapshot and works from that, so a refresh landing while
/// it runs changes nothing for it; the next request sees the new set. Cheap to
/// take: one reference count, never a copy of the keys.
#[derive(Debug, Clone)]
pub struct Served(Arc<std::sync::RwLock<Arc<KeyStore>>>);

impl Served {
    pub fn new(store: KeyStore) -> Self {
        Self(Arc::new(std::sync::RwLock::new(Arc::new(store))))
    }

    pub fn current(&self) -> Arc<KeyStore> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn replace(&self, store: KeyStore) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(store);
    }
}

/// What one public key has to pass to be served, wherever it came from: it is
/// there, it parses, and this agent can sign with it. One function, so the
/// vault path and the remembered path cannot drift apart.
fn accept(raw: &[u8]) -> Result<PublicKey, KeyIssue> {
    if raw.is_empty() {
        return Err(KeyIssue::Empty);
    }
    let text = String::from_utf8_lossy(raw);
    let public =
        PublicKey::from_openssh(text.trim()).map_err(|e| KeyIssue::Malformed(e.to_string()))?;
    if crate::signing::can_sign(&public.algorithm()) {
        Ok(public)
    } else {
        Err(KeyIssue::Unsupported(public.algorithm().to_string()))
    }
}

/// The rule across items: one public key in two of them would make signing
/// ambiguous, so the second is refused and names the first.
fn unique(
    seen: &mut Vec<(KeyData, String)>,
    public: PublicKey,
    item_id: &str,
) -> Result<PublicKey, KeyIssue> {
    if let Some((_, other_item)) = seen
        .iter()
        .find(|(seen_key, _)| seen_key == public.key_data())
    {
        return Err(KeyIssue::Duplicate {
            other_item: other_item.clone(),
        });
    }
    seen.push((public.key_data().clone(), item_id.to_string()));
    Ok(public)
}

/// Whether an issue is the vault's verdict on a key — there is nothing there, or
/// nothing this agent can serve — as opposed to the vault being unavailable to
/// ask. A verdict is skipped wherever it turns up; an item left unanswered
/// makes the set incomplete, which a start serves anyway (better some keys
/// than none), a refresh refuses to replace a whole set with, and neither
/// writes down.
///
/// Listed positively so that a failure this does not know is treated as the
/// vault being unavailable, which is the side to err on.
const fn is_verdict(issue: &KeyIssue) -> bool {
    matches!(
        issue,
        KeyIssue::Empty
            | KeyIssue::Malformed(_)
            | KeyIssue::Unsupported(_)
            | KeyIssue::Fetch(LpassError::ItemNotFound(_) | LpassError::FieldNotFound { .. })
    )
}

/// The usable entries of a scan, and whether the vault answered for every
/// item. Two outcomes end the scan instead: two items with the same public key,
/// which would make signing ambiguous, and a vault found shut partway — not a
/// fact about one item, and carrying on past it would serve a set quietly
/// missing a key that a later fetch, reopening the vault, would have had.
fn gather(inspections: Vec<KeyInspection>) -> Result<(Vec<KeyEntry>, bool)> {
    let mut entries = Vec::new();
    let mut complete = true;
    for inspection in inspections {
        match inspection {
            KeyInspection::Usable(entry) => entries.push(entry),
            KeyInspection::Unusable {
                item_id,
                name,
                issue: issue @ KeyIssue::Duplicate { .. },
            } => {
                return Err(Error::ConfigInvalid(format!(
                    "item {item_id} ({name}): {issue}"
                )));
            }
            KeyInspection::Unusable {
                issue:
                    KeyIssue::Fetch(
                        shut @ (crate::lpass::LpassError::NotLoggedIn
                        | crate::lpass::LpassError::Locked
                        | crate::lpass::LpassError::WrongMasterPassword
                        | crate::lpass::LpassError::NoMasterPassword(_)),
                    ),
                ..
            } => return Err(shut.into()),
            KeyInspection::Unusable {
                item_id,
                name,
                issue,
            } => {
                if !is_verdict(&issue) {
                    complete = false;
                }
                tracing::warn!(item = %item_id, name = %name, "skipping: {issue}");
            }
        }
    }
    Ok((entries, complete))
}

/// Write a set down for the next start — but only one the vault answered in
/// full. A set missing a key the vault could not be asked about would be
/// trusted until something refreshed it; one missing a key the vault has no
/// answer for is missing nothing.
pub fn remember_if_complete(path: &Path, store: &KeyStore) {
    if store.complete {
        crate::identities::save_best_effort(path, &store.remember());
    } else {
        tracing::warn!(
            "not writing the remembered identities down: a set missing a key the vault \
             did not answer for must not be what the next start trusts"
        );
    }
}

/// What a remembered file yields for one config: the store it can serve at
/// once, and the keys it could not — absent from the file, or in it but not
/// something this build serves. Only the vault can settle those, so the caller
/// decides whether to ask it.
pub struct FromRemembered {
    pub store: KeyStore,
    pub missing: Vec<KeyConfig>,
}

impl KeyStore {
    /// Rebuild the served set from what an earlier start wrote down, under
    /// exactly the policy `load` applies to a fresh fetch.
    ///
    /// Pinned keys are the config's to name and the file's to supply a public
    /// key for. With nothing pinned the file's own list is the served set,
    /// names included.
    pub fn from_remembered(remembered: &Remembered, config: &Config) -> FromRemembered {
        let wanted: Vec<KeyConfig> = if config.keys.is_empty() {
            remembered
                .keys
                .iter()
                .map(|key| KeyConfig {
                    id: key.id.clone(),
                    name: Some(key.name.clone()),
                    confirm: None,
                    passphrase_fallback: None,
                })
                .collect()
        } else {
            config.keys.clone()
        };

        let mut entries = Vec::new();
        let mut missing = Vec::new();
        let mut seen: Vec<(KeyData, String)> = Vec::new();
        for key in wanted {
            let Some(known) = remembered.keys.iter().find(|k| k.id == key.id) else {
                missing.push(key);
                continue;
            };
            let name = crate::text::escape_for_display(key.display_name());
            match accept(known.public.as_bytes())
                .and_then(|public| unique(&mut seen, public, &key.id))
            {
                Ok(public) => entries.push(KeyEntry {
                    item_id: key.id.clone(),
                    name,
                    public,
                    confirm: config.confirm_required(&key),
                    passphrase_fallback: config.passphrase_fallback(&key),
                }),
                // The agent wrote this file, so a key it refuses is a hand edit
                // or one this build can no longer sign with. Either way the
                // vault is the authority, and the next scan rewrites the file.
                Err(issue) => {
                    tracing::warn!(item = %key.id, name = %name,
                        "not serving what was remembered, asking the vault instead: {issue}");
                    missing.push(key);
                }
            }
        }
        FromRemembered {
            // Nothing was asked, so nothing went unanswered.
            store: Self {
                entries,
                complete: true,
            },
            missing,
        }
    }

    /// What to write down for the next start: ids, names and public keys —
    /// everything `request_identities` already hands to any client.
    pub fn remember(&self) -> Remembered {
        Remembered {
            keys: self
                .entries
                .iter()
                .map(|entry| RememberedKey {
                    id: entry.item_id.clone(),
                    name: entry.name.clone(),
                    public: entry.public.to_string(),
                })
                .collect(),
        }
    }

    /// Fetch the public half of every key (explicitly configured or
    /// auto-discovered), asking for the master password if the vault is
    /// locked: this is a start or a listing, and the first call that needs the
    /// vault is the one to ask. Items that fail to load are skipped with a
    /// warning — better some keys than none — and an empty result is an error.
    /// Whether the vault answered for every item is kept, since a set it did
    /// not is served but not written down.
    pub async fn load(
        client: &dyn LpassClient,
        keys: &[KeyConfig],
        config: &Config,
    ) -> Result<Self> {
        let (entries, complete) = gather(inspect_keys(client, keys, config, Access::Asking).await)?;
        if entries.is_empty() {
            return Err(Error::ConfigInvalid(
                "no usable keys: every configured item failed to load (see warnings above)".into(),
            ));
        }
        Ok(Self { entries, complete })
    }

    /// As `load`, for a refresh that will replace a set already being served.
    ///
    /// A scan, so it never asks for the master password and does not count as
    /// using it: with the vault shut it fails fast and nothing changes. And
    /// stricter on one point: only a set the vault answered in full replaces
    /// one. A refresh replacing a complete set with one missing a key because
    /// the vault shut halfway would be a loss dressed as an update, so any
    /// such scan is `None`, and the caller keeps what it has.
    pub async fn load_complete(
        client: &dyn LpassClient,
        keys: &[KeyConfig],
        config: &Config,
    ) -> Option<Self> {
        let (entries, complete) =
            match gather(inspect_keys(client, keys, config, Access::Scanning).await) {
                Ok(gathered) => gathered,
                Err(e) => {
                    tracing::debug!(
                        "keeping the served set as it is, this scan cannot replace it: {e}"
                    );
                    return None;
                }
            };
        if !complete {
            tracing::debug!(
                "keeping the served set as it is: an item went unanswered, so this scan cannot \
                 replace it"
            );
            return None;
        }
        // A scan that found nothing to serve is not one to replace a set with.
        (!entries.is_empty()).then_some(Self { entries, complete })
    }

    pub fn entries(&self) -> impl Iterator<Item = &KeyEntry> {
        self.entries.iter()
    }

    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn lookup(&self, key_data: &KeyData) -> Option<&KeyEntry> {
        self.entries
            .iter()
            .find(|e| e.public.key_data() == key_data)
    }

    #[cfg(test)]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::lpass::mock::MockLpass;

    use crate::testutil::fixtures::*;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    fn config(toml: &str) -> Config {
        init_tracing();
        toml::from_str(toml).unwrap()
    }

    #[tokio::test]
    async fn loads_and_looks_up_keys() {
        let client = MockLpass::logged_in().with_ed25519_public("1").with_field(
            "2",
            "Public Key",
            RSA_PUB.as_bytes(),
        );
        let config =
            config("[[keys]]\nid = \"1\"\nname = \"one\"\n[[keys]]\nid = \"2\"\nname = \"two\"");
        let store = KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap();
        assert_eq!(store.len(), 2);

        let ed = PublicKey::from_openssh(ED25519_PUB.trim()).unwrap();
        let entry = store.lookup(ed.key_data()).unwrap();
        assert_eq!(entry.item_id, "1");
        assert_eq!(entry.name, "one");
        assert!(entry.confirm);
        assert!(entry.fingerprint().starts_with("SHA256:"));
    }

    #[tokio::test]
    async fn failing_item_is_skipped_not_fatal() {
        let client = MockLpass::logged_in()
            .with_ed25519_public("1")
            .with_broken_item("2");
        let config = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let store = KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap();
        assert_eq!(store.len(), 1);
        assert!(!store.complete, "the vault never answered for item 2");
    }

    #[tokio::test]
    async fn empty_public_key_field_is_skipped() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", b"")
            .with_ed25519_public("2");
        let config = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let store = KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.complete, "an empty field is the vault's answer");
    }

    #[tokio::test]
    async fn keys_the_agent_cannot_sign_with_are_not_advertised() {
        // a security-key entry parses fine, but signing happens on the FIDO
        // device — offering it would guarantee a failed signature later
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", SK_ED25519_PUB.as_bytes())
            .with_ed25519_public("2");
        let config = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let store = KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.entries().next().unwrap().item_id, "2");
    }

    #[tokio::test]
    async fn garbage_public_key_is_skipped() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", b"not a key at all")
            .with_ed25519_public("2");
        let config = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let store = KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap();
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn a_shut_vault_stops_the_load_rather_than_dropping_a_key() {
        // Item 1 loads, item 2 finds the vault shut. Carrying on would serve a
        // set quietly missing item 2 — worse than not starting.
        let client = MockLpass::logged_in()
            .with_ed25519_public("1")
            .with_field("2", "Public Key", RSA_PUB.as_bytes())
            .with_logged_out_field("2", "Public Key");
        let config = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let error = KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("not logged in"), "{error}");
    }

    #[tokio::test]
    async fn zero_usable_keys_is_an_error() {
        let client = MockLpass::logged_in().with_broken_item("1");
        let config = config("[[keys]]\nid = \"1\"");
        assert!(KeyStore::load(&client, &config.keys, &config)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn duplicate_public_keys_are_a_hard_error() {
        let client = MockLpass::logged_in()
            .with_ed25519_public("1")
            .with_ed25519_public("2");
        let config = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let err = KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
    }

    #[test]
    fn a_served_set_is_replaced_whole_and_a_snapshot_keeps_the_old_one() {
        let ed = PublicKey::from_openssh(ED25519_PUB.trim()).unwrap();
        let entry = |id: &str, public: &PublicKey| KeyEntry {
            item_id: id.into(),
            name: id.into(),
            public: public.clone(),
            confirm: false,
            passphrase_fallback: PassphraseFallback::default(),
        };
        let served = Served::new(KeyStore {
            entries: vec![entry("1", &ed)],
            complete: true,
        });
        let snapshot = served.current();
        assert_eq!(snapshot.len(), 1);

        let rsa = PublicKey::from_openssh(RSA_PUB.trim()).unwrap();
        served.replace(KeyStore {
            entries: vec![entry("1", &ed), entry("2", &rsa)],
            complete: true,
        });
        assert_eq!(
            served.current().len(),
            2,
            "the next request sees the new set"
        );
        assert_eq!(snapshot.len(), 1, "a request already running keeps its own");
    }

    #[tokio::test]
    async fn a_complete_scan_yields_a_store() {
        let client = MockLpass::logged_in().with_ed25519_public("1").with_field(
            "2",
            "Public Key",
            RSA_PUB.as_bytes(),
        );
        let config = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let store = KeyStore::load_complete(&client, &config.keys, &config)
            .await
            .unwrap();
        assert_eq!(store.len(), 2);
    }

    #[tokio::test]
    async fn a_scan_the_vault_could_not_answer_yields_nothing() {
        // The set being served is complete; a scan missing a key because the
        // vault shut halfway must not replace it.
        let client = MockLpass::logged_in()
            .with_ed25519_public("1")
            .with_broken_item("2");
        let both = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        assert!(KeyStore::load_complete(&client, &both.keys, &both)
            .await
            .is_none());

        let shut = MockLpass::logged_in()
            .with_ed25519_public("1")
            .with_logged_out_field("1", "Public Key");
        let one = config("[[keys]]\nid = \"1\"");
        assert!(KeyStore::load_complete(&shut, &one.keys, &one)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn a_scan_with_a_duplicate_yields_nothing() {
        let client = MockLpass::logged_in()
            .with_ed25519_public("1")
            .with_ed25519_public("2");
        let config = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        assert!(KeyStore::load_complete(&client, &config.keys, &config)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn the_vaults_own_verdicts_are_still_skipped_by_a_refresh() {
        // Not the vault being unavailable: the vault answered, and the answer
        // is a key this agent cannot serve. That is skipped as at startup.
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", SK_ED25519_PUB.as_bytes())
            .with_ed25519_public("2");
        let both = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let store = KeyStore::load_complete(&client, &both.keys, &both)
            .await
            .unwrap();
        assert_eq!(store.len(), 1);

        // and a scan that serves nothing at all is not one to replace a set with
        let none = MockLpass::logged_in().with_field("1", "Public Key", b"not a key");
        let one = config("[[keys]]\nid = \"1\"");
        assert!(KeyStore::load_complete(&none, &one.keys, &one)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn an_item_the_vault_no_longer_has_is_a_verdict_a_refresh_acts_on() {
        // Deleted, or stripped of its field: the vault answered, and the answer
        // is that there is no key. Skipping it is how the refresh stops
        // advertising it — treating it as unavailability would keep the deleted
        // key on offer for as long as the item stayed gone.
        let gone = MockLpass::logged_in().with_ed25519_public("1");
        let both = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let store = KeyStore::load_complete(&gone, &both.keys, &both)
            .await
            .unwrap();
        assert_eq!(store.len(), 1);

        let stripped = MockLpass::logged_in()
            .with_ed25519_public("1")
            .with_absent_field("2", "Public Key");
        let store = KeyStore::load_complete(&stripped, &both.keys, &both)
            .await
            .unwrap();
        assert_eq!(store.len(), 1);
    }

    /// The store a fresh load produces, written down and read back, serves the
    /// same keys — which is the whole point of writing it down.
    #[tokio::test]
    async fn what_a_load_remembers_serves_the_same_keys_again() {
        let client = MockLpass::logged_in().with_ed25519_public("1").with_field(
            "2",
            "Public Key",
            RSA_PUB.as_bytes(),
        );
        let config = config("[[keys]]\nid = \"1\"\nname = \"one\"\n[[keys]]\nid = \"2\"");
        let loaded = KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap();

        let again = KeyStore::from_remembered(&loaded.remember(), &config);
        assert!(again.missing.is_empty());
        assert_eq!(again.store.len(), 2);
        let ed = PublicKey::from_openssh(ED25519_PUB.trim()).unwrap();
        let entry = again.store.lookup(ed.key_data()).unwrap();
        assert_eq!(entry.item_id, "1");
        assert_eq!(entry.name, "one");
        assert!(
            entry.confirm,
            "config policy applies to a remembered key too"
        );
    }

    #[tokio::test]
    async fn a_pinned_key_the_file_lacks_is_reported_not_invented() {
        let client = MockLpass::logged_in().with_ed25519_public("1");
        let one = config("[[keys]]\nid = \"1\"");
        let remembered = KeyStore::load(&client, &one.keys, &one)
            .await
            .unwrap()
            .remember();

        // the config now pins a second key the file has never seen
        let two = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let from = KeyStore::from_remembered(&remembered, &two);
        assert_eq!(from.store.len(), 1);
        assert_eq!(from.missing.len(), 1);
        assert_eq!(from.missing[0].id, "2");
    }

    #[test]
    fn the_config_names_a_pinned_key_whatever_the_file_says() {
        let remembered = Remembered {
            keys: vec![RememberedKey {
                id: "1".into(),
                name: "stale name".into(),
                public: ED25519_PUB.trim().into(),
            }],
        };
        let config = config("[[keys]]\nid = \"1\"\nname = \"config name\"");
        let from = KeyStore::from_remembered(&remembered, &config);
        assert_eq!(from.store.entries().next().unwrap().name, "config name");
    }

    #[test]
    fn with_nothing_pinned_the_file_is_the_served_set() {
        // and its names are untrusted text, escaped like any other
        let remembered = Remembered {
            keys: vec![
                RememberedKey {
                    id: "1".into(),
                    name: "spoof\x1b[2Ksafe".into(),
                    public: ED25519_PUB.trim().into(),
                },
                RememberedKey {
                    id: "2".into(),
                    name: "two".into(),
                    public: RSA_PUB.trim().into(),
                },
            ],
        };
        let from = KeyStore::from_remembered(&remembered, &config(""));
        assert!(from.missing.is_empty());
        assert_eq!(from.store.len(), 2);
        let names: Vec<&str> = from.store.entries().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"spoof\\x1b[2Ksafe"), "{names:?}");
    }

    #[test]
    fn a_remembered_key_this_build_cannot_serve_goes_back_to_the_vault() {
        // A hand edit, or a key type this build no longer signs with: refused
        // under the same policy a fresh fetch faces, and handed back as missing
        // so the vault gets the last word.
        let remembered = Remembered {
            keys: vec![
                RememberedKey {
                    id: "1".into(),
                    name: "sk".into(),
                    public: SK_ED25519_PUB.trim().into(),
                },
                RememberedKey {
                    id: "2".into(),
                    name: "garbage".into(),
                    public: "not a key".into(),
                },
                RememberedKey {
                    id: "3".into(),
                    name: "empty".into(),
                    public: String::new(),
                },
                RememberedKey {
                    id: "4".into(),
                    name: "fine".into(),
                    public: ED25519_PUB.trim().into(),
                },
                // the same key again, under another id
                RememberedKey {
                    id: "5".into(),
                    name: "dup".into(),
                    public: ED25519_PUB.trim().into(),
                },
            ],
        };
        let from = KeyStore::from_remembered(&remembered, &config(""));
        assert_eq!(from.store.len(), 1);
        assert_eq!(from.store.entries().next().unwrap().item_id, "4");
        let missing: Vec<&str> = from.missing.iter().map(|k| k.id.as_str()).collect();
        assert_eq!(missing, ["1", "2", "3", "5"]);
    }

    #[tokio::test]
    async fn load_never_touches_private_fields() {
        let client = MockLpass::logged_in().with_ed25519_public("1").with_field(
            "1",
            "Private Key",
            b"MUST NOT BE READ",
        );
        let config = config("[[keys]]\nid = \"1\"");
        KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap();
        assert!(client
            .fetch_log
            .lock()
            .unwrap()
            .iter()
            .all(|(_, field, _)| field == "Public Key"));
    }
}
