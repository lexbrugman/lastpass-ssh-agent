use rsa::pkcs1v15::SigningKey;
use rsa::sha2::{Sha256, Sha512};
use signature::{SignatureEncoding, Signer};
use ssh_agent_lib::proto::signature as sigflag;
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, EcdsaCurve, PrivateKey, Signature};

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("client requested ssh-rsa (SHA-1) — refused; every OpenSSH since 7.2 requests SHA-2")]
    RefusedSha1,

    #[error("unsupported key type {0}")]
    UnsupportedKeyType(String),

    #[error("signing failed: {0}")]
    Crypto(String),
}

/// The algorithms `sign_with_key` can actually produce a signature for.
/// Keys of any other type are not advertised: an identity we would refuse
/// to sign with is worse than no identity at all.
pub const fn can_sign(algorithm: &Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::Ed25519
            | Algorithm::Rsa { .. }
            // only the curves Cargo.toml enables: a P-521 key parses, but
            // signing it would fail after we had already prompted and
            // fetched the private key
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256 | EcdsaCurve::NistP384
            }
    )
}

/// Crypto-layer failures (RSA component conversion, signature encoding,
/// the actual signing operation) are not constructible from a key that
/// parsed correctly, so these error edges are excluded from coverage.
#[cfg_attr(coverage_nightly, coverage(off))]
fn crypto_err<E: std::fmt::Display>(e: E) -> SignError {
    SignError::Crypto(e.to_string())
}

/// Produce an SSH signature honoring the agent-protocol flags.
///
/// RSA cannot go through ssh-key 0.6.7's own `Signer`: it hard-codes
/// rsa-sha2-512 (ignoring the flags) and its `RsaKeypair -> rsa::RsaPrivateKey`
/// conversion is broken (passes `p` twice). We convert manually and pick the
/// digest from the request flags, exactly like the upstream key-storage
/// example does.
pub fn sign_with_key(key: &PrivateKey, data: &[u8], flags: u32) -> Result<Signature, SignError> {
    match key.key_data() {
        KeypairData::Rsa(rsa_keypair) => {
            let private = rsa::RsaPrivateKey::from_components(
                to_biguint(&rsa_keypair.public.n)?,
                to_biguint(&rsa_keypair.public.e)?,
                to_biguint(&rsa_keypair.private.d)?,
                vec![
                    to_biguint(&rsa_keypair.private.p)?,
                    to_biguint(&rsa_keypair.private.q)?,
                ],
            )
            .map_err(crypto_err)?;

            let (algorithm, signature) = if flags & sigflag::RSA_SHA2_512 != 0 {
                ("rsa-sha2-512", sign_rsa::<Sha512>(private, data)?)
            } else if flags & sigflag::RSA_SHA2_256 != 0 {
                ("rsa-sha2-256", sign_rsa::<Sha256>(private, data)?)
            } else {
                return Err(SignError::RefusedSha1);
            };
            Signature::new(Algorithm::new(algorithm).map_err(crypto_err)?, signature)
                .map_err(crypto_err)
        }
        KeypairData::Ed25519(_) | KeypairData::Ecdsa(_) => key.try_sign(data).map_err(crypto_err),
        other => Err(SignError::UnsupportedKeyType(
            other
                .algorithm()
                .map_or_else(|_| "unknown".into(), |a| a.to_string()),
        )),
    }
}

fn sign_rsa<D>(private: rsa::RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>, SignError>
where
    D: rsa::sha2::Digest + rsa::pkcs8::AssociatedOid,
{
    let signature = SigningKey::<D>::new(private)
        .try_sign(data)
        .map_err(crypto_err)?;
    Ok(signature.to_vec())
}

fn to_biguint(mpint: &ssh_key::Mpint) -> Result<rsa::BigUint, SignError> {
    rsa::BigUint::try_from(mpint).map_err(crypto_err)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use signature::Verifier;

    const ED25519: &str = include_str!("../tests/fixtures/ed25519");
    const ED25519_PUB: &str = include_str!("../tests/fixtures/ed25519.pub");
    const RSA: &str = include_str!("../tests/fixtures/rsa");
    const RSA_PUB: &str = include_str!("../tests/fixtures/rsa.pub");
    const ECDSA: &str = include_str!("../tests/fixtures/ecdsa");
    const ECDSA_PUB: &str = include_str!("../tests/fixtures/ecdsa.pub");
    const ED25519_PW: &str = include_str!("../tests/fixtures/ed25519_pw");

    fn keypair(private: &str, public: &str) -> (PrivateKey, ssh_key::PublicKey) {
        (
            PrivateKey::from_openssh(private).unwrap(),
            ssh_key::PublicKey::from_openssh(public.trim()).unwrap(),
        )
    }

    #[test]
    fn ed25519_roundtrip() {
        let (private, public) = keypair(ED25519, ED25519_PUB);
        let sig = sign_with_key(&private, b"data to sign", 0).unwrap();
        assert_eq!(sig.algorithm(), Algorithm::Ed25519);
        public.key_data().verify(b"data to sign", &sig).unwrap();
    }

    #[test]
    fn ecdsa_roundtrip() {
        let (private, public) = keypair(ECDSA, ECDSA_PUB);
        let sig = sign_with_key(&private, b"data to sign", 0).unwrap();
        public.key_data().verify(b"data to sign", &sig).unwrap();
    }

    #[test]
    fn rsa_flags_pick_digest() {
        let (private, public) = keypair(RSA, RSA_PUB);

        let sig256 = sign_with_key(&private, b"data", sigflag::RSA_SHA2_256).unwrap();
        assert_eq!(sig256.algorithm().as_str(), "rsa-sha2-256");
        public.key_data().verify(b"data", &sig256).unwrap();

        let sig512 = sign_with_key(&private, b"data", sigflag::RSA_SHA2_512).unwrap();
        assert_eq!(sig512.algorithm().as_str(), "rsa-sha2-512");
        public.key_data().verify(b"data", &sig512).unwrap();

        // both flags set: prefer the stronger digest
        let both = sign_with_key(
            &private,
            b"data",
            sigflag::RSA_SHA2_256 | sigflag::RSA_SHA2_512,
        )
        .unwrap();
        assert_eq!(both.algorithm().as_str(), "rsa-sha2-512");
    }

    #[test]
    fn rsa_without_flags_is_refused() {
        let (private, _) = keypair(RSA, RSA_PUB);
        let err = sign_with_key(&private, b"data", 0).unwrap_err();
        assert!(matches!(err, SignError::RefusedSha1));
    }

    #[test]
    fn tampered_data_fails_verification() {
        let (private, public) = keypair(ED25519, ED25519_PUB);
        let sig = sign_with_key(&private, b"data to sign", 0).unwrap();
        assert!(public.key_data().verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn only_enabled_algorithms_are_advertised() {
        assert!(can_sign(&Algorithm::Ed25519));
        assert!(can_sign(&Algorithm::Rsa { hash: None }));
        assert!(can_sign(&Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256
        }));
        assert!(can_sign(&Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384
        }));
        // built without the p521 feature: parses, but could never sign
        assert!(!can_sign(&Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521
        }));
        assert!(!can_sign(&Algorithm::SkEd25519));
        assert!(!can_sign(&Algorithm::Dsa));
    }

    #[test]
    fn security_key_types_are_refused() {
        // sk-ed25519 keys sign on the FIDO device, which lpass cannot do.
        let ed = ssh_key::PublicKey::from_openssh(ED25519_PUB.trim()).unwrap();
        let ssh_key::public::KeyData::Ed25519(ed_pub) = ed.key_data() else {
            panic!("fixture is ed25519");
        };
        let sk_public = ssh_key::public::SkEd25519::new(*ed_pub, "ssh:");
        let sk_private = ssh_key::private::SkEd25519::new(sk_public, 0x01, vec![0u8; 16]).unwrap();
        let key = PrivateKey::new(KeypairData::SkEd25519(sk_private), "sk").unwrap();
        let err = sign_with_key(&key, b"data", 0).unwrap_err();
        assert!(
            matches!(err, SignError::UnsupportedKeyType(ref t) if t.contains("sk-ssh-ed25519")),
            "{err}"
        );
    }

    #[test]
    fn undecrypted_key_data_is_refused_as_unknown() {
        // The agent always decrypts before signing; the defensive arm must
        // still refuse encrypted key data cleanly.
        let encrypted = PrivateKey::from_openssh(ED25519_PW).unwrap();
        let err = sign_with_key(&encrypted, b"data", 0).unwrap_err();
        assert!(
            matches!(err, SignError::UnsupportedKeyType(ref t) if t == "unknown"),
            "{err}"
        );
    }

    #[test]
    fn encrypted_key_decrypts_and_signs() {
        let encrypted = PrivateKey::from_openssh(ED25519_PW).unwrap();
        assert!(encrypted.is_encrypted());
        let private = encrypted.decrypt("fixture-passphrase").unwrap();
        let sig = sign_with_key(&private, b"data", 0).unwrap();
        private
            .public_key()
            .key_data()
            .verify(b"data", &sig)
            .unwrap();
    }
}
