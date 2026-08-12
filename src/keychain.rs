//! Generic-password items in the user's login keychain.
//!
//! Two things are kept here, and they want the same handful of calls with
//! different terms: a key's passphrase, keyed by that key's fingerprint and
//! readable without a prompt, and the vault's master password, keyed by nothing
//! and released only on user presence. The difference between them is an
//! account name and one flag; everything else — the service, what "not found"
//! looks like, keeping the call off the runtime thread — is shared, and lives
//! here rather than once in each.
//!
//! No decisions in this file. When to consult a store, what a failure means and
//! what happens when nothing is there are all questions for the modules above,
//! where they are tested on every platform.

use security_framework::passwords::{
    delete_generic_password, generic_password, set_generic_password_options,
};
use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};
use zeroize::Zeroizing;

/// Keychain "service" for every entry the agent creates, so they are
/// recognisable in Keychain Access, sit together, and cannot collide with
/// anything else.
const SERVICE: &str = "lastpass-ssh-agent";

/// Nothing saved for that account yet. `errSecItemNotFound`, spelled out so
/// this needs one dependency rather than two.
const ITEM_NOT_FOUND: i32 = -25300;

/// The user declined, or the system could not ask. `errSecUserCanceled`.
const USER_CANCELED: i32 = -128;

/// Whether reading an item should cost a fingerprint.
#[derive(Clone, Copy)]
pub enum Presence {
    /// Readable by this user without being asked. What a key passphrase takes:
    /// the agent already confirms every signature, and a second system prompt
    /// on top of each would make ordinary use impractical.
    NotRequired,
    /// Released only on biometry or the device passcode. What the master
    /// password takes, because it opens the whole vault rather than one key —
    /// and because without it, anything able to trigger a signature could take
    /// it silently.
    Required,
}

/// One item, identified the way the caller identifies it.
pub struct Item {
    account: String,
    presence: Presence,
}

impl Item {
    pub const fn new(account: String, presence: Presence) -> Self {
        Self { account, presence }
    }

    /// What is stored, or `None` when nothing is.
    pub async fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        // Built inside the closure, not passed into it: `PasswordOptions` wraps
        // CoreFoundation types and is not `Send`, so what crosses to the
        // blocking thread is the account and the flag it is built from.
        let (account, presence) = (self.account.clone(), self.presence);
        blocking(
            move || match generic_password(options(&account, presence)) {
                // Wrapped straight away: the crate hands back a plain `Vec`, and
                // what is in it is a secret.
                Ok(secret) => Ok(Some(Zeroizing::new(secret))),
                Err(e) if e.code() == ITEM_NOT_FOUND => Ok(None),
                // Not a broken store: the caller can ask instead, which is the same
                // secret through a channel the user is evidently present for.
                Err(e) if e.code() == USER_CANCELED => Err("presence was not confirmed".into()),
                Err(e) => Err(e.to_string()),
            },
        )
        .await
    }

    /// Store or replace it, which is what a corrected secret needs.
    pub async fn set(&self, secret: &[u8]) -> Result<(), String> {
        let (account, presence) = (self.account.clone(), self.presence);
        // Copied because the blocking task outlives this borrow, and zeroized
        // when that task ends.
        let secret = Zeroizing::new(secret.to_vec());
        blocking(move || {
            set_generic_password_options(&secret, options(&account, presence))
                .map_err(|e| e.to_string())
        })
        .await
    }

    /// Remove it. Already gone is the state this asks for, so that is success.
    pub async fn forget(&self) -> Result<(), String> {
        let account = self.account.clone();
        blocking(move || match delete_generic_password(SERVICE, &account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(e.to_string()),
        })
        .await
    }
}

/// The query for one item. A free function because it is built on the blocking
/// thread, where there is no `Item` to borrow — `PasswordOptions` cannot cross
/// threads, so only what it is made from does.
fn options(account: &str, presence: Presence) -> PasswordOptions {
    let mut options = PasswordOptions::new_generic_password(SERVICE, account);
    if matches!(presence, Presence::Required) {
        options.set_access_control_options(AccessControlOptions::USER_PRESENCE);
    }
    options
}

/// Run one Keychain call off the runtime thread.
///
/// Never inline: the agent runs on a single thread, and a locked keychain — or
/// a presence constraint — puts a system dialog on screen and waits, freezing
/// every other connection.
///
/// A panic is reported rather than propagated, since the caller can still reach
/// the same secret by asking for it.
async fn blocking<T, F>(call: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|e| format!("the keychain call did not finish: {e}"))?
}
