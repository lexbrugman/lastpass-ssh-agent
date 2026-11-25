//! The Secure Enclave, as `crate::enclave::Enclave`.
//!
//! Three calls into `swift/secure_enclave.swift` and nothing else. What a
//! failed call means, and when a sealed copy is kept or dropped, are all in
//! `crate::enclave`, which compiles and is tested everywhere — this is only
//! the crossing.
//!
//! Why the Enclave rather than the Keychain: a keychain item released on user
//! presence needs an entitlement no command line tool can carry, while a key
//! the keychain never holds needs none at all. The header of
//! `swift/secure_enclave.swift` has the long version.

use zeroize::Zeroizing;

use crate::enclave::{self, Enclave, MAX_BLOB, MAX_CIPHER, Outcome, Sealed};

unsafe extern "C" {
    safe fn lssha_se_available() -> i32;
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
    lssha_se_available() == 1
}

pub struct SecureEnclave;

impl Enclave for SecureEnclave {
    fn seal(&self, secret: &[u8]) -> Result<Sealed, Outcome> {
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
                Ok(Sealed { blob, cipher })
            }
            other => Err(other),
        }
    }

    fn open(&self, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, Outcome> {
        // Allocated once at the most a master password can be, the way every
        // other reader of a secret in this codebase is, so the plaintext never
        // moves between allocations; the shim refuses rather than overruns.
        let cap = crate::passphrase::MAX_PASSPHRASE_BYTES;
        let mut out = Zeroizing::new(vec![0u8; cap]);
        let mut len = 0usize;
        let mut os_error = 0i32;

        let stage = unsafe {
            lssha_se_open(
                sealed.blob.as_ptr(),
                sealed.blob.len(),
                sealed.cipher.as_ptr(),
                sealed.cipher.len(),
                out.as_mut_ptr(),
                cap,
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
}
