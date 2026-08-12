use ssh_key::public::KeyData;
use ssh_key::PublicKey;

use crate::config::{Config, KeyConfig, PassphraseFallback};
use crate::error::{Error, Result};
use crate::lpass::LpassClient;

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
}

/// Fetch and validate every public key, including cross-item duplicate
/// detection. This is the single source of truth for both startup and
/// `doctor`; private fields are never touched.
pub async fn inspect_keys(
    client: &dyn LpassClient,
    keys: &[KeyConfig],
    config: &Config,
) -> Vec<KeyInspection> {
    let mut inspected = Vec::with_capacity(keys.len());
    let mut seen: Vec<(KeyData, String)> = Vec::new();

    for key in keys {
        let name = crate::text::escape_for_display(key.display_name());
        let public = match client.show_field(&key.id, "Public Key").await {
            Ok(raw) if raw.is_empty() => Err(KeyIssue::Empty),
            Ok(raw) => {
                let text = String::from_utf8_lossy(&raw);
                PublicKey::from_openssh(text.trim())
                    .map_err(|e| KeyIssue::Malformed(e.to_string()))
                    .and_then(|public| {
                        if crate::signing::can_sign(&public.algorithm()) {
                            Ok(public)
                        } else {
                            Err(KeyIssue::Unsupported(public.algorithm().to_string()))
                        }
                    })
            }
            Err(e) => Err(e.into()),
        };

        let public = public.and_then(|public| {
            if let Some((_, other_item)) = seen
                .iter()
                .find(|(seen_key, _)| seen_key == public.key_data())
            {
                Err(KeyIssue::Duplicate {
                    other_item: other_item.clone(),
                })
            } else {
                seen.push((public.key_data().clone(), key.id.clone()));
                Ok(public)
            }
        });

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

impl KeyStore {
    /// Fetch the public half of every key (explicitly configured or
    /// auto-discovered). Items that fail to load are skipped with a warning;
    /// an empty result is an error. Two items with the same public key would
    /// make signing ambiguous — hard error.
    pub async fn load(
        client: &dyn LpassClient,
        keys: &[KeyConfig],
        config: &Config,
    ) -> Result<Self> {
        let mut entries: Vec<KeyEntry> = Vec::new();
        for inspection in inspect_keys(client, keys, config).await {
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
                // A shut vault is not a fact about one item. Skipping it would
                // drop that key and carry on — and if a later key's fetch
                // reopened the vault (a master-password prompt answered on the
                // second attempt, say), the agent would come up serving an
                // identity set quietly missing the first. Discovery refuses the
                // same thing for the same reason.
                KeyInspection::Unusable {
                    issue: KeyIssue::Fetch(crate::lpass::LpassError::NotLoggedIn),
                    ..
                } => return Err(crate::lpass::LpassError::NotLoggedIn.into()),
                KeyInspection::Unusable {
                    item_id,
                    name,
                    issue,
                } => {
                    tracing::warn!(item = %item_id, name = %name, "skipping: {issue}");
                }
            }
        }

        if entries.is_empty() {
            return Err(Error::ConfigInvalid(
                "no usable keys: every configured item failed to load (see warnings above)".into(),
            ));
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> impl Iterator<Item = &KeyEntry> {
        self.entries.iter()
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

    const ED25519_PUB: &str = include_str!("../tests/fixtures/ed25519.pub");
    const RSA_PUB: &str = include_str!("../tests/fixtures/rsa.pub");

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
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            .with_field("2", "Public Key", RSA_PUB.as_bytes());
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
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            .with_broken_item("2");
        let config = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let store = KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap();
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn empty_public_key_field_is_skipped() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", b"")
            .with_field("2", "Public Key", ED25519_PUB.as_bytes());
        let config = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let store = KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap();
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn keys_the_agent_cannot_sign_with_are_not_advertised() {
        // a security-key entry parses fine, but signing happens on the FIDO
        // device — offering it would guarantee a failed signature later
        const SK_PUB: &str = include_str!("../tests/fixtures/sk_ed25519.pub");
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", SK_PUB.as_bytes())
            .with_field("2", "Public Key", ED25519_PUB.as_bytes());
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
            .with_field("2", "Public Key", ED25519_PUB.as_bytes());
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
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
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
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            .with_field("2", "Public Key", ED25519_PUB.as_bytes());
        let config = config("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"");
        let err = KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
    }

    #[tokio::test]
    async fn load_never_touches_private_fields() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            .with_field("1", "Private Key", b"MUST NOT BE READ");
        let config = config("[[keys]]\nid = \"1\"");
        KeyStore::load(&client, &config.keys, &config)
            .await
            .unwrap();
        assert!(client
            .fetch_log
            .lock()
            .unwrap()
            .iter()
            .all(|(_, field)| field == "Public Key"));
    }
}
