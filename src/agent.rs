use std::sync::Arc;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::extension::{MessageExtension as _, QueryResponse, SessionBind};
use ssh_agent_lib::proto::{Extension, Identity, Request, Response, SignRequest};
use ssh_key::{PrivateKey, Signature};
use zeroize::Zeroizing;

use crate::confirm::{ConfirmContext, Confirmer, Decision, PeerInfo, SessionBinding};
use crate::interaction::InteractionGate;
use crate::keystore::{KeyEntry, KeyStore};
use crate::lpass::LpassClient;
use crate::passphrase::Unlocker;
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
    /// Decrypts the fetched key, resolving a passphrase the vault does not
    /// hold. Reached only for an encrypted key.
    unlocker: Arc<Unlocker>,
    /// Names the hosts a connection is bound to. Read per signature, since
    /// `ssh` records a new host as it agrees to connect — before the signature
    /// the prompt is about.
    host_names: Arc<crate::knownhosts::HostNames>,
    /// One *interaction* at a time, shared by every connection.
    ///
    /// Taken by the first prompt a request shows and held until that request
    /// ends; a request that shows none never takes it and runs alongside the
    /// others. `InteractionGate` documents why it is both late to take and late
    /// to release.
    interaction: Arc<tokio::sync::Mutex<()>>,
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
        unlocker: Arc<Unlocker>,
        host_names: Arc<crate::knownhosts::HostNames>,
    ) -> Self {
        Self {
            store,
            lpass,
            confirmer,
            unlocker,
            host_names,
            interaction: Arc::new(tokio::sync::Mutex::new(())),
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
            // Named when a signature is actually asked for; see `host_names`.
            host_name: None,
            is_forwarding: bind.is_forwarding,
        });
        Response::Success
    }

    /// This connection's bindings, each with the name `known_hosts` gives its
    /// host key, so the prompt can say "github.com" instead of 43 characters
    /// of base64.
    async fn named_bindings(&self) -> Vec<SessionBinding> {
        let mut bindings = self.bindings.clone();
        let fingerprints = bindings
            .iter()
            .map(|bind| bind.host_fingerprint.clone())
            .collect();
        // Fewer names than bindings if the lookup gave up; zip stops at the
        // shorter side and the rest keep their fingerprints.
        for (bind, name) in bindings
            .iter_mut()
            .zip(self.host_names.names_for(fingerprints).await)
        {
            bind.host_name = name;
        }
        bindings
    }

    /// Everything that touches the private key, in one place.
    async fn fetch_and_sign(
        &self,
        entry: &KeyEntry,
        data: &[u8],
        flags: u32,
        gate: &mut InteractionGate,
    ) -> Result<Signature, String> {
        // A fetch can itself put a prompt on screen: with the vault locked to
        // the screen, lpass asks for the master password through a helper of
        // ours. That is an interaction like any other, and it arrives from
        // inside a subprocess where the gate cannot reach it — so the gate is
        // taken here, before the call, rather than after the fact.
        if self.lpass.may_prompt() {
            gate.enter().await;
        }
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

        // The vault item could have been edited since startup; never sign with
        // a key other than the one we advertised.
        //
        // Checked before unlocking, which an OpenSSH key allows because it
        // carries its public half in the clear even while encrypted. Doing it
        // afterwards would mean asking for the passphrase of a replacement key
        // this request is going to refuse anyway — and in `keychain` mode,
        // saving that passphrase over the one belonging to the key still being
        // advertised.
        if key.public_key().key_data() != entry.public.key_data() {
            return Err("private key does not match the advertised public key — vault item changed since startup?".into());
        }

        // Only an encrypted key resolves a passphrase at all: an unencrypted
        // one never fetches the field, never prompts, and costs nothing.
        if key.is_encrypted() {
            // Decryption lives with the passphrase, because "is this the right
            // passphrase?" and "did it decrypt?" are the same question — and a
            // passphrase is only ever saved once that question is answered.
            key = self.unlocker.unlock(entry, &key, gate).await?;
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
    /// ssh-agent-lib logs every `Err` at ERROR — but an extension probe and a
    /// user pressing Deny are protocol answers, not faults, so they are
    /// returned as such. The bytes on the wire are unchanged
    /// (`SSH_AGENT_FAILURE` either way), and the library's own logging stays
    /// on for faults that really are faults.
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

    #[expect(
        clippy::significant_drop_tightening,
        reason = "holding the gate to the end of the request is the point: released \
                  at its last use — after the confirmation — it would leave a gap \
                  for another request's prompt before this one asks for a passphrase"
    )]
    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        // Claimed by the first prompt this request shows, and held from there to
        // the end of it. A request that shows none never claims it; see
        // `InteractionGate`.
        let mut gate = InteractionGate::new(self.interaction.clone());

        let key_data = request.credential.key_data();
        let Some(entry) = self.store.lookup(key_data) else {
            tracing::warn!("sign request for a key this agent does not hold");
            return Err(AgentError::Failure);
        };

        if entry.confirm {
            let ctx = ConfirmContext::new(entry, self.peer, self.named_bindings().await);
            gate.enter().await;
            match self.confirmer.confirm(&ctx).await {
                Decision::Approve => {}
                Decision::Deny => {
                    // Not "denied by user": a prompt that could not be shown
                    // denies too, and claiming a refusal that never happened
                    // sends whoever reads this looking in the wrong place. The
                    // confirmer has just logged which it was.
                    tracing::info!(item = %entry.item_id, key = %entry.name,
                        "signature denied");
                    return Err(AgentError::Failure);
                }
            }
        }

        match self
            .fetch_and_sign(entry, &request.data, request.flags, &mut gate)
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
    use crate::passphrase::{NoPrompt, PassphrasePrompt, PassphraseRequest, PromptError};
    use signature::Verifier;
    use ssh_agent_lib::proto::signature as sigflag;

    /// Types a fixed passphrase and counts how often it was asked, so a test
    /// can prove the vault took precedence.
    #[derive(Default)]
    struct TypedPassphrase {
        secret: Vec<u8>,
        calls: std::sync::Mutex<usize>,
    }

    impl TypedPassphrase {
        fn new(secret: &[u8]) -> Arc<Self> {
            Arc::new(Self {
                secret: secret.to_vec(),
                calls: std::sync::Mutex::new(0),
            })
        }
        fn was_asked(&self) -> bool {
            *self.calls.lock().unwrap() > 0
        }
    }

    #[async_trait::async_trait]
    impl PassphrasePrompt for TypedPassphrase {
        async fn prompt(
            &self,
            _request: &PassphraseRequest,
        ) -> Result<Zeroizing<Vec<u8>>, PromptError> {
            *self.calls.lock().unwrap() += 1;
            Ok(Zeroizing::new(self.secret.clone()))
        }
    }

    const ED25519: &str = include_str!("../tests/fixtures/ed25519");
    const ED25519_PUB: &str = include_str!("../tests/fixtures/ed25519.pub");
    const ED25519_PW: &str = include_str!("../tests/fixtures/ed25519_pw");
    const ED25519_PW_PUB: &str = include_str!("../tests/fixtures/ed25519_pw.pub");
    const RSA_PUB: &str = include_str!("../tests/fixtures/rsa.pub");
    const ECDSA: &str = include_str!("../tests/fixtures/ecdsa");
    const ECDSA_PUB: &str = include_str!("../tests/fixtures/ecdsa.pub");

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    async fn agent_with(client: MockLpass, keys_toml: &str) -> LpassAgent {
        agent_prompting(client, keys_toml, Arc::new(NoPrompt)).await
    }

    /// As `agent_with`, but with a passphrase prompt the test controls.
    async fn agent_prompting(
        client: MockLpass,
        keys_toml: &str,
        prompt: Arc<dyn PassphrasePrompt>,
    ) -> LpassAgent {
        init_tracing();
        let config: Config = toml::from_str(keys_toml).unwrap();
        let client = Arc::new(client);
        let store = Arc::new(
            KeyStore::load(&*client, &config.keys, &config)
                .await
                .unwrap(),
        );
        let unlocker = Arc::new(Unlocker::new(client.clone(), prompt));
        LpassAgent::new(
            store,
            client,
            Arc::new(NoConfirmer),
            unlocker,
            no_host_names(),
        )
    }

    /// No `known_hosts` at all. Every binding then shows its fingerprint, so
    /// these tests read the same on any machine — with the real files, a
    /// fixture key that happened to be in someone's `~/.ssh/known_hosts`
    /// would change what the prompt says.
    fn no_host_names() -> Arc<crate::knownhosts::HostNames> {
        Arc::new(crate::knownhosts::HostNames::with_files(Vec::new()))
    }

    /// The passphrase machinery wired to one prompt, for the direct
    /// `LpassAgent::new` call sites.
    fn unlocking(client: &Arc<MockLpass>, prompt: Arc<dyn PassphrasePrompt>) -> Arc<Unlocker> {
        Arc::new(Unlocker::new(client.clone(), prompt))
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
        let mut agent = LpassAgent::new(
            store,
            client.clone(),
            Arc::new(DenyAll),
            unlocking(&client, Arc::new(NoPrompt)),
            no_host_names(),
        );

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
        let mut agent = LpassAgent::new(
            store,
            logged_out.clone(),
            Arc::new(NoConfirmer),
            unlocking(&logged_out, Arc::new(NoPrompt)),
            no_host_names(),
        );

        assert!(agent
            .sign(sign_request(ED25519_PUB, b"payload", 0))
            .await
            .is_err());
        // next request still served
        assert_eq!(agent.request_identities().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn mismatched_private_key_is_refused_before_any_passphrase_is_asked_for() {
        // Vault item advertises the ed25519_pw public key but returns a
        // different private key (item edited after startup).
        //
        // The mismatch is caught before unlocking, which matters beyond
        // tidiness: asking for the replacement key's passphrase would be a
        // prompt for a signature that is refused regardless, and in `keychain`
        // mode saving it would overwrite the passphrase of the key still being
        // advertised.
        let prompt = TypedPassphrase::new(b"fixture-passphrase");
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PUB.as_bytes())
            // encrypted, and a different key from the advertised one
            .with_field("1", "Private Key", ED25519_PW.as_bytes());
        let mut agent = agent_prompting(
            client,
            "confirm = \"off\"\n[[keys]]\nid = \"1\"",
            prompt.clone(),
        )
        .await;
        assert!(agent
            .sign(sign_request(ED25519_PUB, b"payload", 0))
            .await
            .is_err());
        assert!(
            !prompt.was_asked(),
            "a key we will not sign with must not be unlocked"
        );
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
    async fn encrypted_key_with_missing_passphrase_and_no_prompt_fails() {
        let client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PW_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519_PW.as_bytes());
        let mut agent = agent_with(client, "confirm = \"off\"\n[[keys]]\nid = \"1\"").await;
        assert!(agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .is_err());
    }

    /// An agent serving the passphrase-protected fixture, with whatever
    /// `Passphrase` field and config the case needs.
    async fn pw_agent(
        stored: Option<&[u8]>,
        config: &str,
        prompt: &Arc<TypedPassphrase>,
    ) -> LpassAgent {
        let mut client = MockLpass::logged_in()
            .with_field("1", "Public Key", ED25519_PW_PUB.as_bytes())
            .with_field("1", "Private Key", ED25519_PW.as_bytes());
        if let Some(stored) = stored {
            client = client.with_field("1", "Passphrase", stored);
        }
        agent_prompting(client, config, prompt.clone()).await
    }

    const PW_KEY: &str = "confirm = \"off\"\n[[keys]]\nid = \"1\"";

    #[tokio::test]
    async fn an_empty_passphrase_field_is_typed_instead_and_signs() {
        // The point of the feature: the passphrase lives nowhere but the
        // user's head, and the encrypted key alone sits in the vault.
        let prompt = TypedPassphrase::new(b"fixture-passphrase");
        let mut agent = pw_agent(None, PW_KEY, &prompt).await;
        let sig = agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .unwrap();
        ssh_key::PublicKey::from_openssh(ED25519_PW_PUB.trim())
            .unwrap()
            .key_data()
            .verify(b"payload", &sig)
            .unwrap();
        assert!(prompt.was_asked());
    }

    #[tokio::test]
    async fn a_wrongly_typed_passphrase_fails_the_signature() {
        let prompt = TypedPassphrase::new(b"not the passphrase");
        let mut agent = pw_agent(None, PW_KEY, &prompt).await;
        assert!(agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .is_err());
        assert!(prompt.was_asked());
    }

    #[tokio::test]
    async fn error_mode_refuses_without_ever_asking() {
        let prompt = TypedPassphrase::new(b"fixture-passphrase");
        let mut agent = pw_agent(
            None,
            "confirm = \"off\"\npassphrase_fallback = \"error\"\n[[keys]]\nid = \"1\"",
            &prompt,
        )
        .await;
        assert!(agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .is_err());
        assert!(!prompt.was_asked(), "error mode must not prompt");
    }

    #[tokio::test]
    async fn a_per_key_fallback_overrides_the_global_one() {
        let prompt = TypedPassphrase::new(b"fixture-passphrase");
        let mut agent = pw_agent(
            None,
            "confirm = \"off\"\npassphrase_fallback = \"prompt\"\n\
             [[keys]]\nid = \"1\"\npassphrase_fallback = \"error\"",
            &prompt,
        )
        .await;
        assert!(agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .is_err());
        assert!(!prompt.was_asked());
    }

    #[tokio::test]
    async fn a_populated_field_wins_over_the_prompt() {
        // The vault field is authoritative: a populated one is used, and
        // nothing is asked.
        let prompt = TypedPassphrase::new(b"would be wrong");
        let mut agent = pw_agent(Some(b"fixture-passphrase"), PW_KEY, &prompt).await;
        assert!(agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .is_ok());
        assert!(!prompt.was_asked(), "the vault answered; nothing to ask");
    }

    #[tokio::test]
    async fn a_wrong_field_fails_rather_than_falling_through_to_the_prompt() {
        // Fallback happens on absence, never on failure. Otherwise anything
        // able to draw a prompt could override a passphrase the vault pins.
        let prompt = TypedPassphrase::new(b"fixture-passphrase");
        let mut agent = pw_agent(Some(b"wrong but present"), PW_KEY, &prompt).await;
        assert!(agent
            .sign(sign_request(ED25519_PW_PUB, b"payload", 0))
            .await
            .is_err());
        assert!(
            !prompt.was_asked(),
            "a wrong vault passphrase must not open a prompt"
        );
    }

    /// Notices any two user interactions being in flight at once, whether two
    /// confirmations or a confirmation and a passphrase entry.
    #[derive(Default)]
    struct ChannelWatch {
        busy: std::sync::atomic::AtomicBool,
        overlapped: std::sync::atomic::AtomicBool,
    }

    impl ChannelWatch {
        async fn occupy(&self) {
            use std::sync::atomic::Ordering;
            if self.busy.swap(true, Ordering::SeqCst) {
                self.overlapped.store(true, Ordering::SeqCst);
            }
            // long enough that a concurrent request would land inside it
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            self.busy.store(false, Ordering::SeqCst);
        }
        fn overlapped(&self) -> bool {
            self.overlapped.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    struct WatchingConfirmer(Arc<ChannelWatch>);

    #[async_trait::async_trait]
    impl Confirmer for WatchingConfirmer {
        async fn confirm(&self, _ctx: &ConfirmContext) -> Decision {
            self.0.occupy().await;
            Decision::Approve
        }
    }

    struct WatchingPrompt(Arc<ChannelWatch>, Vec<u8>);

    #[async_trait::async_trait]
    impl PassphrasePrompt for WatchingPrompt {
        async fn prompt(
            &self,
            _request: &PassphraseRequest,
        ) -> Result<Zeroizing<Vec<u8>>, PromptError> {
            self.0.occupy().await;
            Ok(Zeroizing::new(self.1.clone()))
        }
    }

    #[tokio::test]
    async fn a_confirmation_never_shares_the_channel_with_a_passphrase_prompt() {
        // Both prompts have their own lock, so each only stops itself from
        // overlapping. On one terminal the pair still collides, and whichever
        // read first would take the answer meant for the other.
        let watch = Arc::new(ChannelWatch::default());
        let client = Arc::new(
            MockLpass::logged_in()
                .with_field("1", "Public Key", ED25519_PW_PUB.as_bytes())
                .with_field("1", "Private Key", ED25519_PW.as_bytes())
                .with_field("1", "Passphrase", b""),
        );
        // confirmation left on, so every request confirms *and* prompts
        let config: Config = toml::from_str("[[keys]]\nid = \"1\"").unwrap();
        let store = Arc::new(
            KeyStore::load(&*client, &config.keys, &config)
                .await
                .unwrap(),
        );
        let unlocker = unlocking(
            &client,
            Arc::new(WatchingPrompt(
                watch.clone(),
                b"fixture-passphrase".to_vec(),
            )),
        );
        let agent = LpassAgent::new(
            store,
            client,
            Arc::new(WatchingConfirmer(watch.clone())),
            unlocker,
            no_host_names(),
        );

        // two client connections, as separate sessions sharing the agent
        let mut first = agent.with_peer(None);
        let mut second = agent.with_peer(None);
        let (a, b) = tokio::join!(
            first.sign(sign_request(ED25519_PW_PUB, b"first", 0)),
            second.sign(sign_request(ED25519_PW_PUB, b"second", 0)),
        );
        assert!(a.is_ok() && b.is_ok());
        assert!(
            !watch.overlapped(),
            "two prompts were open on the same channel at once"
        );
    }

    /// Waits for the test to let it through, standing in for a human who has
    /// not answered the dialog yet.
    struct BlockUntilReleased(Arc<tokio::sync::Notify>);

    #[async_trait::async_trait]
    impl Confirmer for BlockUntilReleased {
        async fn confirm(&self, _ctx: &ConfirmContext) -> Decision {
            self.0.notified().await;
            Decision::Approve
        }
    }

    #[tokio::test]
    async fn a_signature_that_asks_nothing_does_not_queue_behind_one_waiting_on_a_human() {
        // The gate is for interaction, so it must cost nothing to a request
        // that has none. Item 2 confirms off and its key is unencrypted, so it
        // never prompts; item 1 sits in a confirmation that only completes once
        // item 2 has been signed. Taking the gate at request entry instead
        // would deadlock this exactly — hence the timeout, so the regression
        // fails the test rather than hanging it.
        let release = Arc::new(tokio::sync::Notify::new());
        let client = Arc::new(
            MockLpass::logged_in()
                .with_field("1", "Public Key", ED25519_PUB.as_bytes())
                .with_field("1", "Private Key", ED25519.as_bytes())
                .with_field("2", "Public Key", ECDSA_PUB.as_bytes())
                .with_field("2", "Private Key", ECDSA.as_bytes()),
        );
        let config: Config =
            toml::from_str("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"\nconfirm = false").unwrap();
        let store = Arc::new(
            KeyStore::load(&*client, &config.keys, &config)
                .await
                .unwrap(),
        );
        let agent = LpassAgent::new(
            store,
            client.clone(),
            Arc::new(BlockUntilReleased(release.clone())),
            unlocking(&client, Arc::new(NoPrompt)),
            no_host_names(),
        );

        // two client connections, as separate sessions sharing the agent
        let mut confirming = agent.with_peer(None);
        let mut silent = agent.with_peer(None);
        let finished = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(
                confirming.sign(sign_request(ED25519_PUB, b"needs a human", 0)),
                async {
                    let signed = silent
                        .sign(sign_request(ECDSA_PUB, b"needs nobody", 0))
                        .await;
                    // Only now is the confirmation allowed to finish: reaching
                    // this line at all is what the test is proving.
                    release.notify_one();
                    signed
                }
            )
        })
        .await;

        let (confirmed, unattended) =
            finished.expect("a signature needing no interaction queued behind one that did");
        assert!(confirmed.is_ok() && unattended.is_ok());
    }

    #[tokio::test]
    async fn a_vault_that_can_ask_for_a_password_signs_under_the_gate() {
        // With the vault locked to the screen, the fetch itself may prompt —
        // lpass asks for the master password through a helper of ours, from
        // inside a subprocess the gate cannot see into. So the gate is taken
        // before the fetch, and this pair must not overlap even though neither
        // request confirms.
        let watch = Arc::new(ChannelWatch::default());
        let client = Arc::new(
            MockLpass::logged_in()
                .prompting()
                .with_field("1", "Public Key", ED25519_PW_PUB.as_bytes())
                .with_field("1", "Private Key", ED25519_PW.as_bytes())
                .with_field("1", "Passphrase", b""),
        );
        let config: Config = toml::from_str(PW_KEY).unwrap();
        let store = Arc::new(
            KeyStore::load(&*client, &config.keys, &config)
                .await
                .unwrap(),
        );
        let unlocker = unlocking(
            &client,
            Arc::new(WatchingPrompt(
                watch.clone(),
                b"fixture-passphrase".to_vec(),
            )),
        );
        let agent = LpassAgent::new(
            store,
            client,
            Arc::new(NoConfirmer),
            unlocker,
            no_host_names(),
        );

        let mut first = agent.with_peer(None);
        let mut second = agent.with_peer(None);
        let (a, b) = tokio::join!(
            first.sign(sign_request(ED25519_PW_PUB, b"first", 0)),
            second.sign(sign_request(ED25519_PW_PUB, b"second", 0)),
        );
        assert!(a.is_ok() && b.is_ok());
        assert!(!watch.overlapped(), "two prompts shared one screen");
    }

    #[tokio::test]
    async fn an_unencrypted_key_resolves_no_passphrase_at_all() {
        let prompt = TypedPassphrase::new(b"never needed");
        let client = Arc::new(
            MockLpass::logged_in()
                .with_field("1", "Public Key", ED25519_PUB.as_bytes())
                .with_field("1", "Private Key", ED25519.as_bytes()),
        );
        let config: Config = toml::from_str(PW_KEY).unwrap();
        let store = Arc::new(
            KeyStore::load(&*client, &config.keys, &config)
                .await
                .unwrap(),
        );
        let mut agent = LpassAgent::new(
            store,
            client.clone(),
            Arc::new(NoConfirmer),
            unlocking(&client, prompt.clone()),
            no_host_names(),
        );
        assert!(agent
            .sign(sign_request(ED25519_PUB, b"payload", 0))
            .await
            .is_ok());
        assert!(!prompt.was_asked());
        assert!(
            client
                .fetch_log
                .lock()
                .unwrap()
                .iter()
                .all(|(_, field)| field != "Passphrase"),
            "an unencrypted key must not even read the Passphrase field"
        );
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
        let unlocker = unlocking(&client, Arc::new(NoPrompt));
        LpassAgent::new(store, client, confirmer, unlocker, no_host_names())
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

        // distinct hops accumulate only up to our own cap
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
        let unlocker = unlocking(&client, Arc::new(NoPrompt));
        let mut agent =
            LpassAgent::new(store, client, Arc::new(DenyAll), unlocker, no_host_names());

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
