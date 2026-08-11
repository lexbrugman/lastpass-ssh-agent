//! The macOS Keychain as a passphrase store.
//!
//! Two calls and no decisions, on purpose. Everything that decides anything
//! lives in the parent module, where it is tested on every platform; this file
//! is the part that cannot be, so there is as little of it as possible.
//!
//! Only the passphrase is stored. The private key stays in `LastPass`, fetched
//! for every signature.

use zeroize::Zeroizing;

use super::PassphraseStore;

/// Keychain "service" for every entry the agent creates, so they are
/// recognisable in Keychain Access and cannot collide with anything else.
const SERVICE: &str = "lastpass-ssh-agent";

/// Nothing saved for that account yet. `errSecItemNotFound`, spelled out so
/// this file needs one dependency rather than two.
const ITEM_NOT_FOUND: i32 = -25300;

/// Stores passphrases as generic-password items in the user's login keychain.
///
/// The account is the key's SHA-256 fingerprint rather than its `LastPass` item
/// id or name, so renaming, moving or recreating the vault item still finds the
/// same passphrase. It also comes from the public key the agent advertised, not
/// from vault-controlled text.
pub struct Keychain;

#[async_trait::async_trait]
impl PassphraseStore for Keychain {
    fn name(&self) -> &'static str {
        "the macOS Keychain"
    }

    async fn get(&self, fingerprint: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let account = fingerprint.to_string();
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
/// Never inline: the agent runs on a single thread, and a locked keychain can
/// put a system dialog on screen and wait, freezing every other connection.
///
/// A panic is reported rather than propagated, since the signing request can
/// still succeed by asking.
async fn blocking<T, F>(call: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|e| format!("the keychain call did not finish: {e}"))?
}
