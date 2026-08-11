//! The macOS Keychain as a passphrase store.
//!
//! Deliberately the thinnest layer that can exist: two calls, no decisions.
//! Everything that decides anything — preferring the vault, verifying before
//! saving, asking again when a saved passphrase stops working — lives in the
//! parent module, where it is tested on every platform. This file is the only
//! part that cannot be, so there is as little of it as possible.
//!
//! Only the passphrase is stored. The private key stays in `LastPass` and is
//! fetched fresh for every signature exactly as before.

use zeroize::Zeroizing;

use super::PassphraseStore;

/// Keychain "service" for every entry the agent creates, so they are
/// recognisable in Keychain Access and cannot collide with anything else.
const SERVICE: &str = "lastpass-ssh-agent";

/// Nothing was saved for that account yet. `errSecItemNotFound`, spelled out
/// rather than pulled from the -sys crate so this file needs one dependency
/// rather than two.
const ITEM_NOT_FOUND: i32 = -25300;

/// Stores passphrases as generic-password items in the user's login keychain.
///
/// The account is the key's SHA-256 fingerprint, not its `LastPass` item id or
/// name: the fingerprint identifies the key material itself, so renaming the
/// vault item, moving it between folders or recreating it all still resolve to
/// the same saved passphrase. It is also derived from the public key the agent
/// already advertised, never from vault-controlled text.
pub struct Keychain;

#[async_trait::async_trait]
impl PassphraseStore for Keychain {
    fn name(&self) -> &'static str {
        "the macOS Keychain"
    }

    async fn get(&self, fingerprint: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let account = fingerprint.to_string();
        // On the blocking pool, not the runtime: the agent runs on a single
        // thread, and a locked keychain can put a system dialog on screen and
        // wait. Called inline, that would freeze every other connection —
        // including the confirmation prompts they are waiting on.
        blocking(move || {
            match security_framework::passwords::get_generic_password(SERVICE, &account) {
                // Wrapped straight away: the crate hands back a plain Vec, and
                // this is a passphrase.
                Ok(secret) => Ok(Some(Zeroizing::new(secret))),
                Err(e) if e.code() == ITEM_NOT_FOUND => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        })
        .await
    }

    async fn set(&self, fingerprint: &str, secret: &[u8]) -> Result<(), String> {
        let account = fingerprint.to_string();
        // Copied because the blocking task outlives this borrow, and zeroized
        // when that task ends.
        let secret = Zeroizing::new(secret.to_vec());
        blocking(move || {
            // Creates or replaces, which is what a corrected passphrase needs.
            // The item takes the login keychain's ordinary protection, with no
            // per-read authorization dialog: the agent already asks for
            // approval on every signature, and a second system prompt on top
            // of each one would make normal SSH use impractical.
            security_framework::passwords::set_generic_password(SERVICE, &account, &secret)
                .map_err(|e| e.to_string())
        })
        .await
    }
}

/// Run one Keychain call off the runtime thread.
///
/// A panic in the blocking task is reported rather than propagated: it would
/// otherwise take down a signing request that can still succeed by asking.
async fn blocking<T, F>(call: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|e| format!("the keychain call did not finish: {e}"))?
}
