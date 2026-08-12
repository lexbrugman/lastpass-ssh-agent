//! Generic-password items in the user's login keychain.
//!
//! One thing is kept here: a key's passphrase, keyed by that key's fingerprint
//! and readable without a prompt. The agent already confirms every signature,
//! and a second system prompt on top of each one would make ordinary use
//! impractical.
//!
//! The master password is deliberately *not* here. Protecting a keychain item
//! with user presence needs the data-protection keychain, which needs an
//! entitlement no command line tool can carry. It is held in the Secure
//! Enclave instead, which never involves the keychain; the header of
//! `swift/secure_enclave.swift` says why that route is open and this one is
//! not.
//!
//! No decisions in this file. When to consult a store, what a failure means and
//! what happens when nothing is there are all questions for the modules that
//! call this, where they are tested on every platform.

use security_framework::passwords::{generic_password, set_generic_password_options};
use security_framework::passwords_options::PasswordOptions;
use zeroize::Zeroizing;

/// Keychain "service" for every entry the agent creates, so they are
/// recognisable in Keychain Access, sit together, and cannot collide with
/// anything else.
const SERVICE: &str = "lastpass-ssh-agent";

/// Nothing saved for that account yet. `errSecItemNotFound`, spelled out so
/// this needs one dependency rather than two.
const ITEM_NOT_FOUND: i32 = -25300;

/// One item, identified the way the caller identifies it.
pub struct Item {
    account: String,
}

impl Item {
    pub const fn new(account: String) -> Self {
        Self { account }
    }

    /// What is stored, or `None` when nothing is.
    pub async fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        // Built inside the closure, not passed into it: `PasswordOptions` wraps
        // CoreFoundation types and is not `Send`, so what crosses to the
        // blocking thread is the account it is built from.
        let account = self.account.clone();
        crate::apple::blocking(move || match generic_password(options(&account)) {
            // Wrapped straight away: the crate hands back a plain `Vec`, and
            // what is in it is a secret.
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(e) if e.code() == ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(e.to_string()),
        })
        .await
    }

    /// Store or replace it, which is what a corrected secret needs.
    pub async fn set(&self, secret: &[u8]) -> Result<(), String> {
        let account = self.account.clone();
        // Copied because the blocking task outlives this borrow, and zeroized
        // when that task ends.
        let secret = Zeroizing::new(secret.to_vec());
        crate::apple::blocking(move || {
            set_generic_password_options(&secret, options(&account)).map_err(|e| e.to_string())
        })
        .await
    }
}

/// The query for one item. A free function because it is built on the blocking
/// thread, where there is no `Item` to borrow — `PasswordOptions` cannot cross
/// threads, so only what it is made from does.
fn options(account: &str) -> PasswordOptions {
    PasswordOptions::new_generic_password(SERVICE, account)
}
