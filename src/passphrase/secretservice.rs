//! The desktop's secret service as a passphrase store.
//!
//! The Linux counterpart of `keychain.rs`, down to the entry it writes: one item
//! per key, keyed by the key's fingerprint, read without a presence prompt, and
//! holding the passphrase and never the private key. That file says why each of
//! those is so; this one covers what is different about reaching a store that
//! lives behind a bus.
//!
//! `org.freedesktop.secrets` rather than any one implementation: gnome-keyring,
//! `KWallet` and `KeePassXC` all answer to it, and which of them is listening is
//! not this agent's business. What it does need is a session bus and a collection
//! that can be unlocked. A headless login has neither, so there this store cannot
//! be read at all — which the portable rules already treat as "ask instead"
//! rather than as a reason to refuse a signature.

use std::collections::HashMap;

use secret_service::{EncryptionType, SecretService};
use zeroize::Zeroizing;

use super::PassphraseStore;

/// Marks every item this agent creates, so they are recognisable in Seahorse or
/// `KeePassXC`, sit together, and cannot collide with anything else. The same
/// string the Keychain uses as its service, for the same reason.
const SERVICE: &str = "lastpass-ssh-agent";

/// What one key's item is found by. `account` is spelled as the Keychain spells
/// it, so an item created here and one created there describe themselves alike.
fn attributes(fingerprint: &str) -> HashMap<&str, &str> {
    HashMap::from([("service", SERVICE), ("account", fingerprint)])
}

/// The item's only human-readable part: a keyring browser lists labels, not the
/// attributes it is actually found by.
fn label(fingerprint: &str) -> String {
    format!("lastpass-ssh-agent: SSH key passphrase ({fingerprint})")
}

pub struct SecretServiceStore;

#[async_trait::async_trait]
impl PassphraseStore for SecretServiceStore {
    fn name(&self) -> &'static str {
        "the desktop secret service"
    }

    /// Excluded from coverage: every line of it talks to whichever secret
    /// service is listening on the bus of whoever runs the tests, and the suite
    /// must never touch that. The rules around this call are covered through
    /// `PassphraseStore` fakes on every platform.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn get(&self, fingerprint: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        // `Dh` negotiates a session key, so the passphrase crosses the bus
        // encrypted rather than in the clear: the message travels through the
        // bus daemon, and there is no reason to let that read it.
        //
        // Connected per call, like every Keychain call is: this runs at most
        // twice per signature that needs a passphrase, and holding a bus
        // connection open for the life of the agent to save a handshake is not
        // a trade worth making.
        let service = SecretService::connect(EncryptionType::Dh)
            .await
            .map_err(|e| e.to_string())?;
        let collection = service
            .get_default_collection()
            .await
            .map_err(|e| e.to_string())?;
        // `unlock`, not `ensure_unlocked`: the latter only reports the state and
        // fails on a locked collection, which would quietly turn this store into
        // `prompt` mode for anyone whose keyring is not open at login. This asks
        // the desktop to unlock it and waits for the answer, and is idempotent —
        // an already-unlocked collection returns without prompting at all. It is
        // also why `Unlocker::unlock_from_store` reads a store from inside the
        // interaction gate: this call can put a dialog on screen.
        collection.unlock().await.map_err(|e| e.to_string())?;
        let found = collection
            .search_items(attributes(fingerprint))
            .await
            .map_err(|e| e.to_string())?;
        // Nothing matching means nothing was ever stored for this key, which is
        // an answer rather than a failure. An item that is there but still
        // cannot be read fails below instead, and an unreadable store already
        // means "ask".
        let Some(item) = found.first() else {
            return Ok(None);
        };
        // Wrapped straight away: the crate hands back a plain `Vec`, and what is
        // in it is a secret.
        Ok(Some(Zeroizing::new(
            item.get_secret().await.map_err(|e| e.to_string())?,
        )))
    }

    /// Excluded for the same reason as `get`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn set(&self, fingerprint: &str, secret: &[u8]) -> Result<(), String> {
        let service = SecretService::connect(EncryptionType::Dh)
            .await
            .map_err(|e| e.to_string())?;
        let collection = service
            .get_default_collection()
            .await
            .map_err(|e| e.to_string())?;
        collection.unlock().await.map_err(|e| e.to_string())?;
        collection
            .create_item(
                &label(fingerprint),
                attributes(fingerprint),
                secret,
                // Replace: a passphrase corrected after the key was re-encrypted
                // must overwrite the stale one, not sit beside it.
                true,
                "text/plain",
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The attributes *are* the item's identity, and nothing fails loudly if they
    /// change: a renamed one simply finds nothing, so every passphrase already
    /// stored becomes unreachable and each key is asked for once more. Written out
    /// literally so that a rename has to be a deliberate one.
    #[test]
    fn an_item_is_identified_by_the_service_and_the_fingerprint() {
        let attributes = attributes("SHA256:abc");
        assert_eq!(attributes.get("service"), Some(&"lastpass-ssh-agent"));
        assert_eq!(attributes.get("account"), Some(&"SHA256:abc"));
        assert_eq!(
            attributes.len(),
            2,
            "an extra attribute narrows the search and orphans what is stored"
        );
    }

    #[test]
    fn the_label_names_the_agent_and_the_key_it_belongs_to() {
        assert_eq!(
            label("SHA256:abc"),
            "lastpass-ssh-agent: SSH key passphrase (SHA256:abc)"
        );
    }

    /// Log lines about a stored passphrase read "stored ... in {name}", so this
    /// has to name somewhere a person can go and look.
    #[test]
    fn the_store_says_where_it_keeps_things() {
        assert_eq!(SecretServiceStore.name(), "the desktop secret service");
    }
}
