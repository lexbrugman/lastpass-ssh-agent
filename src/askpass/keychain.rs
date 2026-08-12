//! The macOS Keychain as a master-password store.
//!
//! One vault, one master password, so the account is a constant rather than
//! anything derived — and named to be obvious to whoever finds it in Keychain
//! Access. `Presence::Required` is what makes storing this secret defensible at
//! all: it opens the entire vault, not one key.
//!
//! The calls themselves live in `crate::keychain`, shared with the passphrase
//! store; what is left here is which item this is and how it is protected.

use zeroize::Zeroizing;

use super::MasterPasswordStore;
use crate::keychain::{Item, Presence};

pub struct Keychain;

fn item() -> Item {
    Item::new("LastPass master password".to_string(), Presence::Required)
}

#[async_trait::async_trait]
impl MasterPasswordStore for Keychain {
    fn name(&self) -> &'static str {
        "the macOS Keychain"
    }

    async fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        item().get().await
    }

    async fn set(&self, secret: &[u8]) -> Result<(), String> {
        item().set(secret).await
    }

    async fn forget(&self) -> Result<(), String> {
        item().forget().await
    }
}
