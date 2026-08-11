use ssh_key::public::KeyData;
use ssh_key::PublicKey;

use crate::config::{Config, KeyConfig};
use crate::error::{Error, Result};
use crate::lpass::LpassClient;

/// One usable key: the public half plus where to find the private half.
/// The private key is never stored here.
#[derive(Debug)]
pub struct KeyEntry {
    pub item_id: String,
    pub name: String,
    pub public: PublicKey,
    pub confirm: bool,
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
        for key in keys {
            let public = match client.show_field(&key.id, "Public Key").await {
                Ok(raw) if raw.is_empty() => {
                    tracing::warn!(item = %key.id, name = %crate::text::escape_for_display(key.display_name()),
                        "skipping: item has an empty Public Key field");
                    continue;
                }
                Ok(raw) => {
                    let text = String::from_utf8_lossy(&raw);
                    match PublicKey::from_openssh(text.trim()) {
                        Ok(public) if !crate::signing::can_sign(&public.algorithm()) => {
                            // advertising it would mean offering an identity
                            // every signing request then refuses
                            tracing::warn!(item = %key.id, name = %crate::text::escape_for_display(key.display_name()),
                                "skipping: this agent cannot sign with {} keys",
                                public.algorithm());
                            continue;
                        }
                        Ok(public) => public,
                        Err(e) => {
                            tracing::warn!(item = %key.id, name = %crate::text::escape_for_display(key.display_name()),
                                "skipping: Public Key field does not parse as an OpenSSH public key: {e}");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(item = %key.id, name = %crate::text::escape_for_display(key.display_name()),
                        "skipping: {e}");
                    continue;
                }
            };

            if let Some(existing) = entries
                .iter()
                .find(|e| e.public.key_data() == public.key_data())
            {
                return Err(Error::ConfigInvalid(format!(
                    "items {} and {} hold the same public key; signing would be ambiguous — remove one from the config",
                    existing.item_id, key.id
                )));
            }

            entries.push(KeyEntry {
                item_id: key.id.clone(),
                // vault-controlled: rendered by ssh-add, dialogs and logs
                name: crate::text::escape_for_display(key.display_name()),
                public,
                confirm: config.confirm_required(key),
            });
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
