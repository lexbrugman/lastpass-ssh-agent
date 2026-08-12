//! The Secure Enclave as a master-password store.
//!
//! Three calls into `swift/secure_enclave.swift` and nothing else. Where the
//! file lives, what its contents mean, and what a failed call should do about
//! it are all in `crate::enclave`, which compiles and is tested everywhere —
//! this is only the crossing.
//!
//! Why the Enclave rather than the Keychain: a keychain item released on user
//! presence needs an entitlement no command line tool can carry, while a key
//! the keychain never holds needs none at all. The header of
//! `swift/secure_enclave.swift` has the long version.

use std::path::PathBuf;

use zeroize::Zeroizing;

use super::MasterPasswordStore;
use crate::enclave::{self, Outcome, Stored, MAX_BLOB, MAX_CIPHER};

extern "C" {
    fn lssha_se_available() -> i32;
    fn lssha_se_seal(
        secret: *const u8,
        secret_len: usize,
        blob: *mut u8,
        blob_cap: usize,
        blob_len: *mut usize,
        cipher: *mut u8,
        cipher_cap: usize,
        cipher_len: *mut usize,
        os_error: *mut i32,
    ) -> i32;
    fn lssha_se_open(
        blob: *const u8,
        blob_len: usize,
        cipher: *const u8,
        cipher_len: usize,
        out: *mut u8,
        cap: usize,
        len: *mut usize,
        os_error: *mut i32,
    ) -> i32;
}

/// Whether this Mac has a Secure Enclave, for `doctor` to say so before the
/// user finds out at the first signature.
pub fn available() -> bool {
    unsafe { lssha_se_available() == 1 }
}

/// Make a new key and encrypt the secret to it. Does not prompt: the access
/// control is enforced when a key is used, not when it is made.
fn seal(secret: &[u8]) -> Result<Stored, Outcome> {
    let mut blob = vec![0u8; MAX_BLOB];
    let mut cipher = vec![0u8; MAX_CIPHER];
    let (mut blob_len, mut cipher_len) = (0usize, 0usize);
    let mut os_error = 0i32;

    let stage = unsafe {
        lssha_se_seal(
            secret.as_ptr(),
            secret.len(),
            blob.as_mut_ptr(),
            MAX_BLOB,
            &raw mut blob_len,
            cipher.as_mut_ptr(),
            MAX_CIPHER,
            &raw mut cipher_len,
            &raw mut os_error,
        )
    };

    match enclave::meaning(stage, os_error) {
        Outcome::Done => {
            blob.truncate(blob_len);
            cipher.truncate(cipher_len);
            Ok(Stored { blob, cipher })
        }
        other => Err(other),
    }
}

/// Decrypt, which is where the fingerprint is asked for.
fn open(stored: &Stored) -> Result<Zeroizing<Vec<u8>>, Outcome> {
    // Sized for the padded block rather than the secret, since that is what
    // was sealed. Allocated once, the way every other reader of a secret in
    // this codebase is, so the plaintext never moves between allocations;
    // `enclave::unpad` shortens this same buffer in place afterwards.
    let mut out = Zeroizing::new(vec![0u8; enclave::PADDED_LEN]);
    let mut len = 0usize;
    let mut os_error = 0i32;

    let stage = unsafe {
        lssha_se_open(
            stored.blob.as_ptr(),
            stored.blob.len(),
            stored.cipher.as_ptr(),
            stored.cipher.len(),
            out.as_mut_ptr(),
            enclave::PADDED_LEN,
            &raw mut len,
            &raw mut os_error,
        )
    };

    match enclave::meaning(stage, os_error) {
        Outcome::Done => {
            out.truncate(len);
            Ok(out)
        }
        other => Err(other),
    }
}

pub struct SecureEnclave {
    path: PathBuf,
}

impl SecureEnclave {
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait::async_trait]
impl MasterPasswordStore for SecureEnclave {
    fn name(&self) -> &'static str {
        "the Secure Enclave"
    }

    async fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let Some(stored) = enclave::load(&self.path).map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        // `enclave::unwrapped` decides what a failure means — in particular
        // that an unusable key reads as an empty store, so seeding can replace
        // it. That decision is portable and tested; this is just the crossing.
        crate::apple::blocking(move || enclave::unwrapped(open(&stored))).await
    }

    async fn set(&self, secret: &[u8]) -> Result<(), String> {
        // Padded before it is sealed, so every stored file is the same size
        // whatever the password's length. This is also the copy that crosses to
        // the blocking thread — one allocation, made once, zeroized there.
        let block = enclave::pad(secret).map_err(|e| e.to_string())?;
        let stored =
            crate::apple::blocking(move || seal(&block).map_err(Outcome::describe)).await?;
        enclave::save(&self.path, &stored).map_err(|e| e.to_string())
    }

    async fn forget(&self) -> Result<(), String> {
        enclave::remove(&self.path).map_err(|e| e.to_string())
    }
}
