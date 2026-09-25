use rsa::pkcs1v15::SigningKey;
use rsa::sha2::{Sha256, Sha512};
use signature::{RandomizedSigner, SignatureEncoding, Signer};
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
/// The session id a userauth request is for, when `data` is one — whole,
/// for `public_key`, and in the host-bound form for `host_key`.
///
/// What `ssh` asks an agent to sign for public-key authentication (RFC 4252
/// §7, and OpenSSH's host-bound variant): the session id, the message
/// number, user, service, method, the flag that a signature follows, the
/// algorithm and the key — and for the host-bound method the server's host
/// key after that, which has to be the one the connection is bound to, or a
/// host in the middle could sign its own session id and pass the request
/// off as one for the host beyond it. Anything shaped otherwise is `None`:
/// a bound connection gets nothing else signed.
pub fn userauth_session_id<'a>(
    data: &'a [u8],
    public_key: &[u8],
    host_key: &[u8],
) -> Option<&'a [u8]> {
    const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
    let mut request = Wire(data);
    let session_id = request.string()?;
    (request.byte()? == SSH_MSG_USERAUTH_REQUEST).then_some(())?;
    let _user = request.string()?;
    (request.string()? == b"ssh-connection").then_some(())?;
    let method = request.string()?;
    let host_bound = method == b"publickey-hostbound-v00@openssh.com";
    (host_bound || method == b"publickey").then_some(())?;
    (request.byte()? == 1).then_some(())?;
    let _algorithm = request.string()?;
    (request.string()? == public_key).then_some(())?;
    if host_bound {
        (request.string()? == host_key).then_some(())?;
    }
    request.0.is_empty().then_some(session_id)
}

/// A cursor over SSH wire encoding: length-prefixed strings and single bytes.
struct Wire<'a>(&'a [u8]);

impl<'a> Wire<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*first)
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(u32::from_be_bytes(self.0.get(..4)?.try_into().ok()?)).ok()?;
        let value = self.0.get(4..4 + len)?;
        self.0 = &self.0[4 + len..];
        Some(value)
    }
}

/// RSA cannot go through ssh-key 0.6.7's own `Signer`: it hard-codes
/// rsa-sha2-512 (ignoring the flags) and its `RsaKeypair -> rsa::RsaPrivateKey`
/// conversion passes `p` twice. So the components are converted here and the
/// digest comes from the request flags.
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
    // rsa 0.9 is not constant-time (RUSTSEC-2023-0071). Supplying fresh OS
    // randomness makes its PKCS#1 v1.5 signer blind the private-key
    // operation, making repeated timings substantially harder to correlate
    // with the client's chosen input. This mitigates the advisory; it does
    // not make the dependency a constant-time implementation, which is why
    // the audit exception and its residual-risk documentation remain.
    let mut rng = rand_core::OsRng;
    let signature = SigningKey::<D>::new(private)
        .try_sign_with_rng(&mut rng, data)
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

    /// A userauth request as `ssh` builds one, field by field.
    fn userauth(fields: &[&[u8]], message: u8, flag: u8) -> Vec<u8> {
        let string = |value: &[u8]| {
            let mut out = u32::try_from(value.len()).unwrap().to_be_bytes().to_vec();
            out.extend_from_slice(value);
            out
        };
        let mut data = string(fields[0]);
        data.push(message);
        data.extend(string(fields[1]));
        data.extend(string(fields[2]));
        data.extend(string(fields[3]));
        data.push(flag);
        for field in &fields[4..] {
            data.extend(string(field));
        }
        data
    }

    #[test]
    fn a_userauth_request_names_its_session_and_anything_else_does_not() {
        let key = b"blob";
        let ok = userauth(
            &[
                b"sid",
                b"user",
                b"ssh-connection",
                b"publickey",
                b"ssh-ed25519",
                key,
            ],
            50,
            1,
        );
        let host = b"host key";
        assert_eq!(userauth_session_id(&ok, key, host), Some(&b"sid"[..]));
        let bound = userauth(
            &[
                b"sid",
                b"user",
                b"ssh-connection",
                b"publickey-hostbound-v00@openssh.com",
                b"ssh-ed25519",
                key,
                b"host key",
            ],
            50,
            1,
        );
        assert_eq!(userauth_session_id(&bound, key, host), Some(&b"sid"[..]));
        // bound to a host, for another: a host in the middle passing a
        // request off as one for the host beyond it
        assert_eq!(userauth_session_id(&bound, key, b"other host"), None);

        // another message, another service, another method, no signature
        // flag, another key, trailing bytes, and a host-bound request
        // without its host key: none of them is this request
        let fields: &[&[u8]] = &[
            b"sid",
            b"user",
            b"ssh-connection",
            b"publickey",
            b"ssh-ed25519",
            key,
        ];
        assert_eq!(
            userauth_session_id(&userauth(fields, 51, 1), key, host),
            None
        );
        assert_eq!(
            userauth_session_id(&userauth(fields, 50, 0), key, host),
            None
        );
        assert_eq!(userauth_session_id(&ok, b"other", host), None);
        let mut trailing = ok;
        trailing.push(0);
        assert_eq!(userauth_session_id(&trailing, key, host), None);
        let wrong_service = userauth(
            &[
                b"sid",
                b"user",
                b"ssh-userauth",
                b"publickey",
                b"ssh-ed25519",
                key,
            ],
            50,
            1,
        );
        assert_eq!(userauth_session_id(&wrong_service, key, host), None);
        let wrong_method = userauth(
            &[
                b"sid",
                b"user",
                b"ssh-connection",
                b"password",
                b"ssh-ed25519",
                key,
            ],
            50,
            1,
        );
        assert_eq!(userauth_session_id(&wrong_method, key, host), None);
        let mut unbound_host = bound.clone();
        unbound_host.truncate(bound.len() - 12);
        assert_eq!(userauth_session_id(&unbound_host, key, host), None);
        // and shapes that are not even a request
        assert_eq!(userauth_session_id(&[0, 0, 0, 3, b'a'], key, host), None);
        assert_eq!(userauth_session_id(&[0, 0], key, host), None);
        assert_eq!(userauth_session_id(&[0, 0, 0, 0], key, host), None);
        assert_eq!(userauth_session_id(b"x", key, host), None);
    }
    use signature::Verifier;

    use crate::testutil::fixtures::*;

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
