//! The macOS Keychain as a passphrase store.
//!
//! One entry per key, keyed by the key's SHA-256 fingerprint rather than its
//! `LastPass` item id or name, so renaming, moving or recreating the vault item
//! still finds the same passphrase — and the account comes from the public key
//! the agent advertised, not from vault-controlled text.
//!
//! Read without a presence prompt on purpose: the agent already asks for
//! approval on every signature, and a second system prompt on top of each one
//! would make normal SSH use impractical. The master password is kept somewhere
//! else entirely and behind Touch ID, because it unlocks the whole vault rather
//! than one key.
//!
//! Only the passphrase is stored. The private key stays in `LastPass`, fetched
//! for every signature.

use zeroize::Zeroizing;

use super::PassphraseStore;
use crate::keychain::Item;

pub struct Keychain;

fn item(fingerprint: &str) -> Item {
    Item::new(fingerprint.to_string())
}

#[async_trait::async_trait]
impl PassphraseStore for Keychain {
    fn name(&self) -> &'static str {
        "the macOS Keychain"
    }

    async fn get(&self, fingerprint: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        item(fingerprint).get().await
    }

    async fn set(&self, fingerprint: &str, secret: &[u8]) -> Result<(), String> {
        item(fingerprint).set(secret).await
    }
}
