use std::sync::Arc;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::extension::{MessageExtension as _, QueryResponse, SessionBind};
use ssh_agent_lib::proto::{Extension, Identity, Request, Response, SignRequest};
use ssh_key::{PrivateKey, Signature};
use zeroize::Zeroizing;

use crate::confirm::{ConfirmContext, Confirmer, Decision, PeerInfo, SessionBinding};
use crate::keystore::{KeyEntry, KeyStore};
use crate::lpass::LpassClient;
use crate::signing;

/// The agent proper. Holds no private-key material — only the public-key ->
/// LastPass-item map and the means to fetch/confirm/sign.
///
/// Cloned once per client connection; shared state lives behind `Arc`s.
#[derive(Clone)]
pub struct LpassAgent {
    store: Arc<KeyStore>,
    lpass: Arc<dyn LpassClient>,
    confirmer: Arc<dyn Confirmer>,
    /// pid/uid of the connected client, filled in per session.
    peer: Option<PeerInfo>,
    /// Hosts this connection has bound itself to, oldest hop first. Per
    /// connection: a fresh session starts with none.
    bindings: Vec<SessionBinding>,
}

/// A forwarded connection is driven by whoever holds the far end, and they
/// can mint a valid binding per host key they control. Without a ceiling
/// they could grow this list — and every confirmation prompt built from it —
/// without bound. OpenSSH's agent uses the same limit.
const MAX_SESSION_BINDINGS: usize = 16;

impl LpassAgent {
    pub fn new(
        store: Arc<KeyStore>,
        lpass: Arc<dyn LpassClient>,
        confirmer: Arc<dyn Confirmer>,
    ) -> Self {
        Self {
            store,
            lpass,
            confirmer,
            peer: None,
            bindings: Vec::new(),
        }
    }

    pub fn with_peer(&self, peer: Option<PeerInfo>) -> Self {
        Self {
            peer,
            ..self.clone()
        }
    }

    /// Record where this connection is bound, so the confirmation prompt
    /// can say whether a request reached us over a forwarded agent.
    ///
    /// `session-bind@openssh.com` is what OpenSSH sends on every connection:
    /// the far host's key, the session id, and that host's signature over
    /// it. Verifying the signature is what makes the hop trustworthy — an
    /// unverifiable binding is refused rather than displayed. (Refusing does
    /// not lock the connection down: an attacker would simply send no
    /// binding at all, so there is nothing to gain by poisoning it.)
    fn handle_extension(&mut self, extension: &Extension) -> Response {
        // A client may ask what we support before using anything. Answering
        // matters: one that negotiates this way would otherwise never send a
        // session binding, and forwarded requests would lose their host
        // chain — silently, since everything else still works.
        if extension.name == QueryResponse::NAME {
            return Extension::new_message(QueryResponse {
                extensions: vec![SessionBind::NAME.into()],
            })
            .map_or(Response::Failure, Response::ExtensionResponse);
        }
        let bind = match extension.parse_message::<SessionBind>() {
            Ok(Some(bind)) => bind,
            // some other vendor extension: unsupported, as advertised
            Ok(None) => {
                tracing::debug!(extension = %extension.name, "refusing unsupported extension");
                return Response::Failure;
            }
            Err(e) => {
                tracing::warn!(extension = %extension.name,
                    "refusing malformed session binding: {e}");
                return Response::Failure;
            }
        };
        if let Err(e) = bind.verify_signature() {
            tracing::warn!("refusing a session binding whose host signature does not verify: {e}");
            return Response::Failure;
        }
        if self.bindings.len() >= MAX_SESSION_BINDINGS {
            tracing::warn!(
                "refusing a session binding: this connection already has \
                 {MAX_SESSION_BINDINGS}"
            );
            return Response::Failure;
        }
        let host_fingerprint = bind
            .host_key
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        // a repeated hop tells the user nothing new
        if self
            .bindings
            .iter()
            .any(|seen| seen.host_fingerprint == host_fingerprint)
        {
            return Response::Success;
        }
        tracing::debug!(host = %host_fingerprint, forwarding = bind.is_forwarding,
            "session bound");
        self.bindings.push(SessionBinding {
            host_fingerprint,
            is_forwarding: bind.is_forwarding,
        });
        Response::Success
    }

    /// Everything that touches the private key, in one place.
    async fn fetch_and_sign(
        &self,
        entry: &KeyEntry,
        data: &[u8],
        flags: u32,
    ) -> Result<Signature, String> {
        let pem: Zeroizing<Vec<u8>> = self
            .lpass
            .show_field(&entry.item_id, "Private Key")
            .await
            .map_err(|e| format!("fetching private key: {e}"))?;
        if pem.is_empty() {
            return Err("item has an empty Private Key field".into());
        }

        let mut key =
            PrivateKey::from_openssh(&*pem).map_err(|e| format!("parsing private key: {e}"))?;
        if key.is_encrypted() {
            let passphrase: Zeroizing<Vec<u8>> = self
                .lpass
                .show_field(&entry.item_id, "Passphrase")
                .await
                .map_err(|e| format!("fetching passphrase: {e}"))?;
            if passphrase.is_empty() {
                return Err(
                    "private key is passphrase-protected but the item's Passphrase field is empty"
                        .into(),
                );
            }
            key = key
                .decrypt(&*passphrase)
                .map_err(|e| format!("decrypting private key: {e}"))?;
        }

        // The vault item could have been edited since startup; never sign
        // with a key other than the one we advertised.
        if key.public_key().key_data() != entry.public.key_data() {
            return Err("private key does not match the advertised public key — vault item changed since startup?".into());
        }

        signing::sign_with_key(&key, data, flags).map_err(|e| e.to_string())
        // `key` (and the encrypted original) zeroize on drop here.
    }
}

#[ssh_agent_lib::async_trait]
impl Session for LpassAgent {
    /// Dispatch every request ourselves.
    ///
    /// The default dispatcher signals a refusal by returning `Err`, and
    /// ssh-agent-lib logs every `Err` at ERROR. That made two entirely
    /// normal things look like agent malfunctions: OpenSSH probes for
    /// vendor extensions on each connection, and a user pressing Deny is a
    /// deliberate outcome we already log ourselves. Refusals are protocol
    /// answers, so they are returned as such — the bytes on the wire are
    /// unchanged (`SSH_AGENT_FAILURE` either way), and the library's own
    /// logging stays on to report faults that really are faults.
    async fn handle(&mut self, message: Request) -> Result<Response, AgentError> {
        Ok(match message {
            Request::RequestIdentities => {
                Response::IdentitiesAnswer(self.request_identities().await?)
            }
            // `sign` has already logged any refusal, with the key it concerns
            Request::SignRequest(request) => self
                .sign(request)
                .await
                .map_or(Response::Failure, Response::SignResponse),
            // Not a key operation: it tells us which host the session is
            // with, which the confirmation prompt then shows.
            Request::Extension(extension) => self.handle_extension(&extension),
            // This agent is read-only: it serves the vault's SSH keys and
            // nothing else. Adding, removing and locking are all refused.
            _ => Response::Failure,
        })
    }

    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(self
            .store
            .entries()
            .map(|entry| Identity {
                credential: entry.public.key_data().clone().into(),
                comment: format!("lastpass:{} ({})", entry.item_id, entry.name),
            })
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let key_data = request.credential.key_data();
        let Some(entry) = self.store.lookup(key_data) else {
            tracing::warn!("sign request for a key this agent does not hold");
            return Err(AgentError::Failure);
        };

        if entry.confirm {
            let ctx = ConfirmContext::new(entry, self.peer, self.bindings.clone());
            match self.confirmer.confirm(&ctx).await {
                Decision::Approve => {}
                Decision::Deny => {
                    tracing::info!(item = %entry.item_id, key = %entry.name,
                        "signature DENIED by user");
                    return Err(AgentError::Failure);
                }
            }
        }

        match self
            .fetch_and_sign(entry, &request.data, request.flags)
            .await
        {
            Ok(signature) => {
                tracing::info!(item = %entry.item_id, key = %entry.name,
                    algorithm = %signature.algorithm(), "signature issued");
                Ok(signature)
            }
            Err(reason) => {
                // `reason` never contains key material — only error summaries.
                tracing::warn!(item = %entry.item_id, key = %entry.name,
                    "signature failed: {reason}");
                Err(AgentError::Failure)
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::confirm::NoConfirmer;
    use crate::lpass::mock::MockLpass;
    use signature::Verifier;
    use ssh_agent_lib::proto::signature as sigflag;

    const ED25519: &str = include_str!("../tests/fixtures/ed25519");
    const ED25519_PUB: &str = include_str!("../tests/fixtures/ed25519.pub");
    const ED25519_PW: &str = include_str!("../tests/fixtures/ed25519_pw");
    const ED25519_PW_PUB: &str = include_str!("../tests/fixtures/ed25519_pw.pub");
    const RSA_PUB: &str = include_str!("../tests/fixtures/rsa.pub");

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    async fn agent_with(client: MockLpass, keys_toml: &str) -> LpassAgent {
        init_tracing();
        let config: Config = toml::from_str(keys_toml).unwrap();
        let client = Arc::new(client);
        let store = Arc::new(
            KeyStore::load(&*client, &config.keys, &config)
                .await
                .unwrap(),
        );
        LpassAgent::new(store, client, Arc::new(NoConfirmer))
    }

    fn sign_request(public: &str, data: &[u8], flags: u32) -> SignRequest {
        let key = ssh_key::PublicKey::from_openssh(public.trim()).unwrap();
        SignRequest {
            credential: key.key_data().clone().into(),
            data: data.to_vec(),
            flags,
        }
    }

    struct DenyAll;
    #[async_trait::async_trait]
    impl Confirmer for DenyAll {
        async fn confirm(&self, _ctx: &ConfirmContext) -> Decision {
            Decision::Deny
        }
    }

    #[tokio::test]
    async fn identities_and_ed25519_signature() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519.as_bytes());
        let mut agent = agent_with(
            client,
            "confirm = \"off\"\n[[keys]]\nid = \"1\"\nname = \"test\"",
        )
        .await;

        let identities = agent.request_identities().await.unwrap();
        assert_eq!(identities.len(), 1);
        assert!(identities[0].comment.contains("lastpass:1"));

        let sig = agent
            .sign(sign_request(ED25519_PUB, b"payload", 0))
            .await
            .unwrap();
        ssh_key::PublicKey::from_openssh(ED25519_PUB.trim())
            .unwrap()
            .key_data()
            .verify(b"payload", &sig)
            .unwrap();
    }

    #[tokio::test]
    async fn with_peer_carries_state_and_peer() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519.as_bytes());
        let agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        let mut session = agent.with_peer(Some(PeerInfo {
            pid: Some(1234),
            uid: 501,
        }));
        assert_eq!(session.request_identities().await.unwrap().len(), 1);
        assert!(session
            .sign(sign_request(ED25519_PUB, b"via peer session", 0))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn empty_private_key_field_fails() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            .with_field("1", "Private Key", b"");
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        assert!(agent
            .sign(sign_request(ED25519_PUB, b"payload", 0))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn identity_comments_neutralize_vault_controlled_names() {
        // `ssh-add -l` prints these comments straight to a terminal
        let client = MockLpass::logged_in().with_field("1", "Public Key", ED25519_PUB.as_bytes());
        let mut agent = agent_with(
            client,
            "confirm = \"off\"\n[[keys]]\nid = \"1\"\nname = \"spoof\\u001b[2Ksafe\"",
        )
        .await;
        let identities = agent.request_identities().await.unwrap();
        assert!(!identities[0].comment.contains('\u{1b}'));
        assert!(identities[0].comment.contains("spoof\\x1b[2Ksafe"));
    }

    #[tokio::test]
    async fn unknown_key_fails() {
        let client = MockLpass::logged_in().with_field("1", "Public Key", ED25519_PUB.as_bytes());
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        assert!(agent
            .sign(sign_request(RSA_PUB, b"payload", sigflag::RSA_SHA2_256))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn denied_confirmation_blocks_and_never_touches_private_key() {
        init_tracing();
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519.as_bytes());
        let config: Config = toml::from_str("[[keys]]\nid = \"1\"").unwrap();
        let client = Arc::new(client);
        let store = Arc::new(
            KeyStore::load(&*client, &config.keys, &config)
                .await
                .unwrap(),
        );
        let mut agent = LpassAgent::new(store, client.clone(), Arc::new(DenyAll));

        assert!(agent
            .sign(sign_request(ED25519_PUB, b"payload", 0))
            .await
            .is_err());
        assert!(
            client
                .fetch_log
                .lock()
                .unwrap()
                .iter()
                .all(|(_, field)| field != "Private Key"),
            "denied request must not fetch the private key"
        );
    }

    #[tokio::test]
    async fn logged_out_mid_session_fails_but_agent_survives() {
        // Store loaded while logged in; then simulate logout by swapping the client.
        let loaded = MockLpass::logged_in().with_field("1", "Public Key", ED25519_PUB.as_bytes());
        let config: Config = toml::from_str("confirm = \"off\"\n[[keys]]\nid = \"1\"").unwrap();
        let store = Arc::new(
            KeyStore::load(&loaded, &config.keys, &config)
                .await
                .unwrap(),
        );
        let logged_out = Arc::new(MockLpass::default()); // logged_in: false
        let mut agent = LpassAgent::new(store, logged_out, Arc::new(NoConfirmer));

        assert!(agent
            .sign(sign_request(ED25519_PUB, b"payload", 0))
            .await
            .is_err());
        // next request still served
        assert_eq!(agent.request_identities().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn mismatched_private_key_is_refused() {
        // Vault item advertises the ed25519_pw public key but returns a
        // different private key (item edited after startup).
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PW_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519.as_bytes());
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        assert!(agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn passphrase_protected_key_signs() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PW_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519_PW.as_bytes())
            .with_field("1", "Passphrase", b"fixture-passphrase");
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        let sig = agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .unwrap();
        ssh_key::PublicKey::from_openssh(ED25519_PW_PUB.trim())
            .unwrap()
            .key_data()
            .verify(b"payload", &sig)
            .unwrap();
    }

    #[tokio::test]
    async fn garbage_private_key_fails() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            .with_field("1", "Private Key", b"this is not a PEM at all");
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        assert!(agent
            .sign(sign_request(ED25519_PUB, b"payload", 0))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn wrong_passphrase_fails() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PW_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519_PW.as_bytes())
            .with_field("1", "Passphrase", b"not the passphrase");
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        assert!(agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn passphrase_fetch_failure_fails() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PW_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519_PW.as_bytes())
            .with_broken_field("1", "Passphrase");
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        assert!(agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn encrypted_key_with_missing_passphrase_fails() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PW_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519_PW.as_bytes());
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        assert!(agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn refusals_are_protocol_answers_not_errors() {
        // Anything ssh-agent-lib would log at ERROR must instead come back
        // as an Ok(Response::Failure): identical on the wire, silent in the
        // log. Extension probes arrive on every OpenSSH connection.
        use ssh_agent_lib::proto::{AddIdentity, Extension, PrivateCredential, RemoveIdentity};

        let client = MockLpass::logged_in().with_field("1", "Public Key", ED25519_PUB.as_bytes());
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        let private = PrivateKey::from_openssh(ED25519).unwrap();

        let refused = [
            // a vendor extension we do not implement
            Request::Extension(Extension {
                name: "restrict-destination-v00@openssh.com".into(),
                details: Vec::new().into(),
            }),
            Request::AddIdentity(AddIdentity {
                credential: PrivateCredential::Key {
                    privkey: private.key_data().clone(),
                    comment: "nope".into(),
                },
            }),
            Request::RemoveIdentity(RemoveIdentity {
                credential: private.public_key().key_data().clone().into(),
            }),
            Request::RemoveAllIdentities,
            Request::Lock("secret".into()),
            Request::Unlock("secret".into()),
        ];
        for request in refused {
            let response = agent.handle(request).await.unwrap();
            assert!(matches!(response, Response::Failure), "{response:?}");
        }

        // and the two operations we do serve still answer normally
        assert!(matches!(
            agent.handle(Request::RequestIdentities).await.unwrap(),
            Response::IdentitiesAnswer(_)
        ));
    }

    /// A binding as OpenSSH sends it: the host signs the session id with
    /// its host key. `host` doubles as the host key here.
    fn session_bind(host: &PrivateKey, session_id: &[u8], is_forwarding: bool) -> Request {
        use signature::Signer as _;
        Request::Extension(
            Extension::new_message(SessionBind {
                host_key: host.public_key().key_data().clone(),
                session_id: session_id.to_vec(),
                signature: host.try_sign(session_id).unwrap(),
                is_forwarding,
            })
            .unwrap(),
        )
    }

    /// Captures the prompt a signing request would have shown.
    #[derive(Default)]
    struct RecordingConfirmer(std::sync::Mutex<Vec<String>>);

    #[async_trait::async_trait]
    impl Confirmer for RecordingConfirmer {
        async fn confirm(&self, ctx: &ConfirmContext) -> Decision {
            self.0
                .lock()
                .unwrap()
                .push(crate::confirm::describe_request(ctx));
            Decision::Approve
        }
    }

    async fn agent_recording(confirmer: Arc<RecordingConfirmer>) -> LpassAgent {
        let client = Arc::new(
            MockLpass::logged_in()
                .with_field("1", "Public Key", ED25519_PUB.as_bytes())
                .with_field("1", "Private Key", ED25519.as_bytes()),
        );
        let config: Config = toml::from_str("[[keys]]\nid = \"1\"").unwrap();
        let store = Arc::new(
            KeyStore::load(&*client, &config.keys, &config)
                .await
                .unwrap(),
        );
        LpassAgent::new(store, client, confirmer)
    }

    #[tokio::test]
    async fn query_advertises_session_bind() {
        // a client that negotiates before binding must be told we bind,
        // or forwarded requests would quietly lose their host chain
        let client = MockLpass::logged_in().with_field("1", "Public Key", ED25519_PUB.as_bytes());
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;

        let response = agent
            .handle(Request::Extension(Extension {
                name: QueryResponse::NAME.into(),
                details: Vec::new().into(),
            }))
            .await
            .unwrap();
        let Response::ExtensionResponse(extension) = response else {
            panic!("expected an extension response, got {response:?}");
        };
        let query = extension
            .parse_message::<QueryResponse>()
            .unwrap()
            .expect("a query response");
        assert_eq!(query.extensions, vec![SessionBind::NAME.to_string()]);
    }

    #[tokio::test]
    async fn a_verified_binding_tells_the_prompt_which_host_asked() {
        let confirmer = Arc::new(RecordingConfirmer::default());
        let mut agent = agent_recording(confirmer.clone()).await;
        let host = PrivateKey::from_openssh(ED25519).unwrap();

        assert!(matches!(
            agent
                .handle(session_bind(&host, b"session-one", false))
                .await
                .unwrap(),
            Response::Success
        ));
        agent
            .handle(Request::SignRequest(sign_request(ED25519_PUB, b"x", 0)))
            .await
            .unwrap();

        let prompts = confirmer.0.lock().unwrap();
        let host_fp = host
            .public_key()
            .key_data()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        assert!(prompts[0].contains(&host_fp), "{}", prompts[0]);
        // not forwarded: no warning
        assert!(!prompts[0].contains("WARNING"), "{}", prompts[0]);
    }

    #[tokio::test]
    async fn a_forwarded_binding_warns_and_shows_the_whole_chain() {
        let confirmer = Arc::new(RecordingConfirmer::default());
        let mut agent = agent_recording(confirmer.clone()).await;
        let first = PrivateKey::from_openssh(ED25519).unwrap();
        let second = PrivateKey::from_openssh(ED25519_PW)
            .unwrap()
            .decrypt("fixture-passphrase")
            .unwrap();

        // ssh -A to `first`, which then opens a session to `second`
        agent
            .handle(session_bind(&first, b"hop-one", true))
            .await
            .unwrap();
        agent
            .handle(session_bind(&second, b"hop-two", false))
            .await
            .unwrap();
        agent
            .handle(Request::SignRequest(sign_request(ED25519_PUB, b"x", 0)))
            .await
            .unwrap();

        let prompts = confirmer.0.lock().unwrap();
        let fp = |key: &PrivateKey| {
            key.public_key()
                .key_data()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string()
        };
        assert!(prompts[0].contains(&fp(&first)), "{}", prompts[0]);
        assert!(prompts[0].contains(&fp(&second)), "{}", prompts[0]);
        assert!(
            prompts[0].contains("forwarding the agent onward"),
            "{}",
            prompts[0]
        );
        assert!(prompts[0].contains("WARNING"), "{}", prompts[0]);
    }

    #[tokio::test]
    async fn bindings_are_capped_and_deduplicated() {
        let confirmer = Arc::new(RecordingConfirmer::default());
        let mut agent = agent_recording(confirmer.clone()).await;
        let host = PrivateKey::from_openssh(ED25519).unwrap();

        // the same hop repeated adds nothing
        for _ in 0..3 {
            assert!(matches!(
                agent
                    .handle(session_bind(&host, b"same-host", false))
                    .await
                    .unwrap(),
                Response::Success
            ));
        }
        assert_eq!(agent.bindings.len(), 1);

        // distinct hops accumulate only up to the protocol limit
        for hop in 0..MAX_SESSION_BINDINGS + 4 {
            let key =
                PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
            let _ = agent
                .handle(session_bind(&key, format!("hop{hop}").as_bytes(), false))
                .await
                .unwrap();
        }
        assert_eq!(agent.bindings.len(), MAX_SESSION_BINDINGS);
    }

    #[tokio::test]
    async fn a_forged_binding_is_refused_and_never_shown() {
        use signature::Signer as _;

        let confirmer = Arc::new(RecordingConfirmer::default());
        let mut agent = agent_recording(confirmer.clone()).await;
        let host = PrivateKey::from_openssh(ED25519).unwrap();
        let impostor = PrivateKey::from_openssh(ED25519_PW)
            .unwrap()
            .decrypt("fixture-passphrase")
            .unwrap();

        // claims to be `host`, but the signature is by someone else
        let forged = Request::Extension(
            Extension::new_message(SessionBind {
                host_key: host.public_key().key_data().clone(),
                session_id: b"session".to_vec(),
                signature: impostor.try_sign(b"session").unwrap(),
                is_forwarding: true,
            })
            .unwrap(),
        );
        assert!(matches!(
            agent.handle(forged).await.unwrap(),
            Response::Failure
        ));

        agent
            .handle(Request::SignRequest(sign_request(ED25519_PUB, b"x", 0)))
            .await
            .unwrap();
        let prompts = confirmer.0.lock().unwrap();
        assert!(!prompts[0].contains("SSH session:"), "{}", prompts[0]);
        assert!(!prompts[0].contains("WARNING"), "{}", prompts[0]);
    }

    #[tokio::test]
    async fn a_malformed_binding_is_refused() {
        use ssh_agent_lib::proto::extension::MessageExtension as _;
        let confirmer = Arc::new(RecordingConfirmer::default());
        let mut agent = agent_recording(confirmer).await;

        // right extension name, payload that cannot decode
        let malformed = Request::Extension(Extension {
            name: SessionBind::NAME.into(),
            details: vec![0xff, 0x00, 0x01].into(),
        });
        assert!(matches!(
            agent.handle(malformed).await.unwrap(),
            Response::Failure
        ));
    }

    #[tokio::test]
    async fn bindings_do_not_leak_between_connections() {
        let confirmer = Arc::new(RecordingConfirmer::default());
        let template = agent_recording(confirmer.clone()).await;
        let host = PrivateKey::from_openssh(ED25519).unwrap();

        let mut bound = template.with_peer(None);
        bound
            .handle(session_bind(&host, b"session", true))
            .await
            .unwrap();

        // a second client connects: it inherits nothing from the first
        let mut fresh = template.with_peer(None);
        fresh
            .handle(Request::SignRequest(sign_request(ED25519_PUB, b"x", 0)))
            .await
            .unwrap();
        let prompts = confirmer.0.lock().unwrap();
        assert!(!prompts[0].contains("SSH session:"), "{}", prompts[0]);
    }

    #[tokio::test]
    async fn a_denied_signature_answers_failure_without_erroring() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519.as_bytes());
        let config: Config = toml::from_str("[[keys]]\nid = \"1\"").unwrap();
        let client = Arc::new(client);
        let store = Arc::new(
            KeyStore::load(&*client, &config.keys, &config)
                .await
                .unwrap(),
        );
        let mut agent = LpassAgent::new(store, client, Arc::new(DenyAll));

        let response = agent
            .handle(Request::SignRequest(sign_request(ED25519_PUB, b"x", 0)))
            .await
            .unwrap();
        assert!(matches!(response, Response::Failure));
    }

    #[tokio::test]
    async fn a_granted_signature_answers_with_the_signature() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519.as_bytes());
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        let response = agent
            .handle(Request::SignRequest(sign_request(ED25519_PUB, b"x", 0)))
            .await
            .unwrap();
        assert!(matches!(response, Response::SignResponse(_)));
    }

    #[tokio::test]
    async fn trait_defaults_still_refuse_direct_calls() {
        use ssh_agent_lib::proto::{AddIdentity, PrivateCredential, RemoveIdentity};
        let client = MockLpass::logged_in().with_field("1", "Public Key", ED25519_PUB.as_bytes());
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;

        let private = PrivateKey::from_openssh(ED25519).unwrap();
        assert!(agent
            .add_identity(AddIdentity {
                credential: PrivateCredential::Key {
                    privkey: private.key_data().clone(),
                    comment: "x".into()
                },
            })
            .await
            .is_err());
        assert!(agent
            .remove_identity(RemoveIdentity {
                credential: private.public_key().key_data().clone().into(),
            })
            .await
            .is_err());
        assert!(agent.lock("secret".into()).await.is_err());
    }
}
