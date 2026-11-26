use std::sync::Arc;

use crate::keystore::KeyEntry;
use crate::prompt::{Failure, Transport};
use crate::requester::Requester;
use crate::text::{bounded, display_bounded, escape_for_display};

/// What the user is being asked to approve. Everything here may be shown in
/// a dialog; none of it is secret. `key_name` comes from the vault/config
/// and must be treated as untrusted text by implementations.
#[derive(Debug, Clone)]
pub struct ConfirmContext {
    pub key_name: String,
    pub fingerprint: String,
    pub item_id: String,
    /// pid/uid of the connecting process, when the socket tells us.
    pub peer: Option<PeerInfo>,
    /// The process behind that pid, looked up once when this is built, so
    /// the prompt and a remembered approval describe the same snapshot.
    pub requester: Option<Requester>,
    /// Hosts this connection is bound to, oldest hop first. Empty when the
    /// client sent no binding (local tools like `ssh-add`, or OpenSSH < 8.9).
    pub bindings: Vec<SessionBinding>,
    /// The account the request logs in to, as what is being signed names it.
    /// Known only on a bound connection, where nothing but a userauth request
    /// is signed. The requester's to choose, so untrusted — and kept as the
    /// bytes signed, since the server is what decides which of them differ.
    pub user: Option<Vec<u8>>,
    /// The namespace of an `ssh-keygen -Y sign` signature — `git` for a commit
    /// or tag — when that is what is being signed rather than a login. The
    /// requester's to choose, like `user`, and kept as bytes for the same
    /// reason.
    pub namespace: Option<Vec<u8>>,
    /// Whether a yes to this is kept and answers the same question again
    /// until the vault locks, so the prompt can say what the yes covers.
    pub remembered: bool,
    /// The request reached the agent over a forward and does not name its
    /// server, so the last binding is the forwarded side's word and nothing
    /// in what gets signed holds it to that host. See `signing::Userauth`.
    pub unverified_destination: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PeerInfo {
    pub pid: Option<i32>,
    pub uid: u32,
}

/// One verified `session-bind@openssh.com` hop: which host the SSH session
/// is with, and whether the agent is being forwarded onward from it.
#[derive(Debug, Clone)]
pub struct SessionBinding {
    pub host_fingerprint: String,
    /// The name `known_hosts` records for that key, when it records one.
    /// Untrusted text like any other: escaped before display.
    pub host_name: Option<String>,
    pub is_forwarding: bool,
    /// The session the host signed for, which a signature on this connection
    /// has to be for as well.
    pub session_id: Vec<u8>,
    /// The host's key as it travels on the wire, which a host-bound request
    /// has to name.
    pub host_key: Vec<u8>,
}

impl ConfirmContext {
    pub fn new(entry: &KeyEntry, peer: Option<PeerInfo>, bindings: Vec<SessionBinding>) -> Self {
        Self::describing(
            entry.name.clone(),
            entry.fingerprint(),
            entry.item_id.clone(),
            peer,
            bindings,
        )
    }

    /// For a request about no real key — `doctor`'s test prompt.
    pub fn describing(
        key_name: String,
        fingerprint: String,
        item_id: String,
        peer: Option<PeerInfo>,
        bindings: Vec<SessionBinding>,
    ) -> Self {
        Self {
            key_name,
            fingerprint,
            item_id,
            peer,
            requester: peer.and_then(|peer| peer.pid).and_then(Requester::of),
            bindings,
            user: None,
            namespace: None,
            remembered: false,
            unverified_destination: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    /// Denied, timed out, or the confirmer failed — all fail closed.
    Deny,
}

#[async_trait::async_trait]
pub trait Confirmer: Send + Sync {
    async fn confirm(&self, ctx: &ConfirmContext) -> Decision;
}

/// Confirmation over whichever transport reaches the user.
///
/// Fails closed: every way of not getting a yes is a deny. Each is logged as
/// what it was, because a refusal and a prompt that never appeared look
/// identical from outside — both simply stop the signature — and this is the
/// last place that can still tell them apart.
pub struct TransportConfirmer {
    transport: Arc<dyn Transport>,
}

impl TransportConfirmer {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self { transport }
    }
}

#[async_trait::async_trait]
impl Confirmer for TransportConfirmer {
    async fn confirm(&self, ctx: &ConfirmContext) -> Decision {
        match self
            .transport
            .ask_to_confirm(&describe_request(ctx), needs_caution(ctx))
            .await
        {
            Ok(true) => Decision::Approve,
            Ok(false) => {
                tracing::info!("confirmation declined, denying");
                Decision::Deny
            }
            Err(Failure::TimedOut) => {
                tracing::info!("confirmation timed out, denying");
                Decision::Deny
            }
            Err(Failure::TooLong(max)) => {
                tracing::info!(max, "the answer ran past what one can be, denying");
                Decision::Deny
            }
            // Not a refusal: nobody was asked.
            Err(Failure::Unavailable(why)) => {
                tracing::warn!(
                    "the confirmation prompt could not be shown, so the signature is denied — \
                     nobody refused it: {why}"
                );
                Decision::Deny
            }
        }
    }
}

/// Build the confirmer selected by the config.
pub fn from_config(config: &crate::config::Config) -> crate::error::Result<Arc<dyn Confirmer>> {
    Ok(match crate::prompt::from_config(config)? {
        None => Arc::new(NoConfirmer),
        Some(transport) => Arc::new(TransportConfirmer::new(transport)),
    })
}

// What a prompt gives each part that is context rather than the decision.
// The macOS dialog shows a screenful and scrolls for the rest, so what counts
// is what is read without scrolling: everything above the details has a
// bound — `the_longest_prompt_there_can_be_is_bounded` holds that — and
// whatever gives way does so marked. The host, the account and the key name
// keep `text::MAX_DISPLAY_CHARS`: those are compared, and a short cut would
// make two of them read alike. The details are scrolled to on purpose, and
// are cut only where a terminal — which prints all of this above the question
// it then asks, and scrolls nothing back — would lose the question to them.

/// A process in the `From` line: longer than any application's name.
const MAX_ORIGIN_NAME_CHARS: usize = 40;
/// A host in the `Via` line: a fingerprint whole, and most names.
const MAX_HOP_CHARS: usize = 64;
/// How long a chain is shown hop by hop. A longer one shows where it starts,
/// where it ends, and how many hosts lie between.
const MAX_HOPS_SHOWN: usize = 4;
/// The requester's path in the details: any path there is whole, since two
/// that differ only at the end are two programs, and about half a terminal's
/// screen at the most.
const MAX_PATH_CHARS: usize = 1000;

/// Whether a request is one to stop and read: it came over a forwarded agent,
/// or names a destination nothing holds it to. A transport that can show the
/// difference does, so that the unusual request is the one that looks unusual.
pub fn needs_caution(ctx: &ConfirmContext) -> bool {
    ctx.unverified_destination || ctx.bindings.iter().any(|bind| bind.is_forwarding)
}

/// The decision in one line: what saying yes does.
fn headline(ctx: &ConfirmContext) -> String {
    let shown = |bytes: &[u8]| display_bounded(&String::from_utf8_lossy(bytes));
    // Named as it is and no more: the namespace is the requester's word for
    // what it hashed, and the hash is all that arrives here — `git` says a
    // commit or a tag is being signed, and proves neither.
    if let Some(namespace) = &ctx.namespace {
        return format!("Sign data for \"{}\"?", shown(namespace));
    }
    let Some(destination) = ctx.bindings.last() else {
        return "Allow an SSH signature?".into();
    };
    // The name when there is one: a fingerprint identifies the host exactly
    // and says nothing to the person reading it. The log keeps the
    // fingerprint either way.
    let mut line = format!(
        "Sign in to {}",
        display_bounded(
            destination
                .host_name
                .as_ref()
                .unwrap_or(&destination.host_fingerprint)
        )
    );
    if ctx.unverified_destination {
        line.push_str(" (unverified)");
    }
    // Approving a key for a host is approving it for this account there, and
    // one key is often good for several: without the name, a request for
    // `root` reads the same as one for `deploy`.
    if let Some(user) = &ctx.user {
        line.push_str(" as ");
        line.push_str(&shown(user));
    }
    line.push('?');
    line
}

/// What the request came from, outermost first and ending in the requester:
/// "Terminal → zsh → ssh". `ssh` says nothing about whether it was you; what
/// it was started from is what the person reading this recognises, and what a
/// request from somewhere unexpected stands out by.
fn origin(ctx: &ConfirmContext) -> String {
    match (ctx.peer, &ctx.requester) {
        (None, _) => "unknown".into(),
        (Some(_), None) => "unknown process".into(),
        (Some(_), Some(requester)) => {
            let own = crate::requester::display_name(&requester.process);
            let names: Vec<String> = requester
                .origin
                .iter()
                .rev()
                .map(|ancestor| ancestor.name.as_str())
                .chain([own.as_str()])
                .map(|name| bounded(name, MAX_ORIGIN_NAME_CHARS))
                .collect();
            names.join(" → ")
        }
    }
}

/// The requester exactly: its path, which a name cannot stand in for — any
/// file can be called `ssh` — and the pid and uid the socket reported.
fn requester_detail(ctx: &ConfirmContext) -> Option<String> {
    let peer = ctx.peer?;
    Some(match (&ctx.requester, peer.pid) {
        // A requester is only ever looked up by a pid.
        (Some(requester), pid) => format!(
            "{} (pid {}, uid {})",
            bounded(&requester.process, MAX_PATH_CHARS),
            pid.unwrap_or_default(),
            peer.uid
        ),
        (None, Some(pid)) => format!("pid {pid}, uid {}", peer.uid),
        (None, None) => format!("uid {}", peer.uid),
    })
}

/// Human-readable description of a signing request, shared by all confirmers.
///
/// Laid out to be read from the top and stopped at any point: what is wrong
/// with the request if anything is, then the decision in one line, then with
/// which key and where it came from, and last the identifiers that settle a
/// doubt but are not read otherwise. A dialog shows the top and scrolls for
/// the rest, which is the other reason the order is this one.
///
/// The key name, the requester's path, its ancestors' names, the host name,
/// the account and the namespace are all untrusted — the vault, whoever
/// spawned the processes, `known_hosts` and the requester respectively. They
/// only ever travel as data, but control characters could still redraw a TTY
/// prompt and a bidi override could reverse how a line renders, either of
/// which spoofs what is being approved. So everything interpolated here is
/// escaped, and what is as long as its author cared to make it is cut to a
/// bound.
pub fn describe_request(ctx: &ConfirmContext) -> String {
    use std::fmt::Write as _;
    let forwarded = ctx.bindings.iter().any(|bind| bind.is_forwarding);
    let mut text = String::new();
    // Without this, a request relayed from a machine you ran `ssh -A` to is
    // indistinguishable from one you made yourself: both name the local ssh
    // process. Each hop in the chain proved possession of its host key.
    if forwarded {
        text.push_str(
            "WARNING: the agent is forwarded to a host below — this request may have \
             originated there rather than on this machine.\n\n",
        );
    }
    if ctx.unverified_destination {
        text.push_str(
            "UNVERIFIED DESTINATION: this request does not name its server, so the last \
             host below is only what the forwarded side says — the session being signed \
             for may be with a different server.\n\n",
        );
    }
    text.push_str(&headline(ctx));
    // With the question, since it says what the answer to it means.
    if ctx.remembered {
        text.push_str("\nAllow is remembered until the vault locks.");
    }
    // The key straight after, ahead of the lines a process tree and a
    // forwarded peer decide the length of.
    let _ = write!(text, "\n\nKey: {}", display_bounded(&ctx.key_name));
    // Said rather than left out: a client that sends no binding (a local
    // tool, or OpenSSH before 8.9) could be signing in anywhere, and a blank
    // reads as nothing to report.
    if ctx.bindings.is_empty() && ctx.namespace.is_none() {
        text.push_str("\nDestination: not stated by the client");
    }
    // Who is asking ahead of the way there: a forwarded peer decides how
    // long that is, and this is the line a request from somewhere unexpected
    // stands out by.
    let _ = write!(text, "\nFrom: {}", origin(ctx));
    let hops: Vec<String> = ctx
        .bindings
        .iter()
        .map(|bind| {
            let name = bind.host_name.as_ref().unwrap_or(&bind.host_fingerprint);
            let mut hop = bounded(&escape_for_display(name), MAX_HOP_CHARS);
            if bind.is_forwarding {
                hop.push_str(" (forwarding the agent onward)");
            }
            hop
        })
        .collect();
    let summarised = hops.len() > MAX_HOPS_SHOWN;
    // The headline names the destination alone, so the way there is spelled
    // out whenever there is more to it than that — which is whenever a hop
    // forwards, since nothing binds after one that does not.
    if forwarded {
        let chain = match hops.as_slice() {
            [first, between @ .., last] if summarised => {
                format!("{first} → [{} more hosts] → {last}", between.len())
            }
            all => all.join(" → "),
        };
        let _ = write!(text, "\nVia: {chain}");
        if ctx.unverified_destination {
            text.push_str(" (unverified)");
        }
    }
    text.push_str("\n\nDetails");
    if let Some(requester) = requester_detail(ctx) {
        let _ = write!(text, "\nProcess: {requester}");
    }
    // What tells apart two keys the vault gave one name.
    let _ = write!(
        text,
        "\nLastPass item: {}\nFingerprint: {}",
        display_bounded(&ctx.item_id),
        display_bounded(&ctx.fingerprint)
    );
    // Last, where its length costs nothing above it: a chain cut short for
    // the `Via` line is still two different requests when a host in the
    // middle differs, and this is where that can be seen.
    if summarised {
        let _ = write!(text, "\nEvery host on the way: {}", hops.join(" → "));
    }
    text
}

/// What a remembered approval answers for: the key, and everything the
/// prompt says about who asked — the process and its uid, what it was started
/// from, the hosts the session is bound to, the account logged in to and the
/// namespace signed under. The same words on screen are
/// the same question; anything else asks again. The pid is left out, since a
/// new `ssh` has a new one every time and is the point of remembering.
///
/// `None` when the requester cannot be told from another: no pid from the
/// socket, or a pid whose executable cannot be read. An approval for
/// "whatever runs as this uid" would answer for every process, so such a
/// request is asked every time.
///
/// An unverified destination is a different question from the same hosts
/// verified, as it is a different prompt. Whether it is remembered at all is
/// the caller's to decide.
pub fn approval_question(ctx: &ConfirmContext) -> Option<String> {
    // Every piece is escaped text, which cannot contain a control character —
    // so control characters as the separators make the encoding unambiguous:
    // one between the items of a list, another between the fields of a hop,
    // and every field always present. Joining on anything printable would let
    // a process named for the separator make two ancestries read as one.
    const SEP: char = '\x1f';
    const FIELD: char = '\x1e';
    let peer = ctx.peer?;
    let requester = ctx.requester.as_ref()?;
    // Each hop by its fingerprint and by the name the prompt shows for it: the
    // name is looked up per signature, and one that comes and goes changes the
    // words on screen, which is a different question.
    let hosts: Vec<String> = ctx
        .bindings
        .iter()
        .map(|bind| {
            let mut hop = escape_for_display(&bind.host_fingerprint);
            hop.push(FIELD);
            hop.push_str(&bind.host_name.as_deref().map_or_default(escape_for_display));
            hop.push(FIELD);
            if bind.is_forwarding {
                hop.push_str("forwarding");
            }
            hop
        })
        .collect();
    // The fingerprint and name as well as the item: a key rotated or renamed
    // inside its item between two requests is a different question, as the
    // prompt would show.
    let mut question = String::new();
    for piece in [
        escape_for_display(&ctx.item_id),
        escape_for_display(&ctx.fingerprint),
        escape_for_display(&ctx.key_name),
        requester.process.clone(),
        peer.uid.to_string(),
        // By path, not by the name the prompt shows: a name is a file name
        // anything can take, a path at least has to be that file.
        requester
            .origin
            .iter()
            .map(|ancestor| ancestor.path.as_str())
            .collect::<Vec<_>>()
            .join(&SEP.to_string()),
        hosts.join(&SEP.to_string()),
        // The bytes, not the words shown for them: two names the prompt
        // renders alike — invalid UTF-8, or a control character beside its
        // own escape — are two accounts to the server.
        ctx.user.as_deref().map_or_default(hex),
        ctx.namespace.as_deref().map_or_default(hex),
        (if ctx.unverified_destination {
            "unverified"
        } else {
            ""
        })
        .to_string(),
    ] {
        question.push_str(&piece);
        question.push('\n');
    }
    Some(question)
}

/// Bytes as lowercase hex, which no two byte strings share.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Used when `confirm = "off"` globally. A per-key override is handled by not
/// asking at all.
pub struct NoConfirmer;

#[async_trait::async_trait]
impl Confirmer for NoConfirmer {
    async fn confirm(&self, _ctx: &ConfirmContext) -> Decision {
        Decision::Approve
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::requester::Ancestor;

    use crate::testutil::fixtures::*;

    fn entry() -> KeyEntry {
        KeyEntry {
            item_id: "42".into(),
            name: "ctx key".into(),
            public: ssh_key::PublicKey::from_openssh(ED25519_PUB.trim()).unwrap(),
            confirm: true,
            passphrase_fallback: crate::config::PassphraseFallback::default(),
        }
    }

    #[tokio::test]
    async fn no_confirmer_always_approves() {
        let ctx = ConfirmContext::new(&entry(), None, Vec::new());
        assert_eq!(NoConfirmer.confirm(&ctx).await, Decision::Approve);
        assert_eq!(ctx.key_name, "ctx key");
        assert_eq!(ctx.item_id, "42");
        assert!(ctx.fingerprint.starts_with("SHA256:"));
    }

    /// A transport that answers as told, and keeps what it was asked.
    struct FakeTransport {
        verdict: Result<bool, Failure>,
        asked: std::sync::Mutex<Vec<(String, bool)>>,
    }

    #[async_trait::async_trait]
    impl Transport for FakeTransport {
        async fn ask_to_confirm(&self, message: &str, caution: bool) -> Result<bool, Failure> {
            self.asked
                .lock()
                .unwrap()
                .push((message.to_string(), caution));
            self.verdict.clone()
        }
        async fn ask_for_secret(
            &self,
            _message: &str,
        ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, Failure> {
            unreachable!("a confirmer never asks for a secret")
        }
    }

    /// Shared body: what each thing a transport can come back with decides.
    async fn expect_decision(verdict: Result<bool, Failure>, expected: Decision) {
        let transport = Arc::new(FakeTransport {
            verdict: verdict.clone(),
            asked: std::sync::Mutex::new(Vec::new()),
        });
        let confirmer = TransportConfirmer::new(transport.clone());
        let ctx = ConfirmContext::new(&entry(), None, Vec::new());
        assert_eq!(confirmer.confirm(&ctx).await, expected, "{verdict:?}");
        // the question put is the request's description
        let asked = transport.asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0], (describe_request(&ctx), false));
    }

    #[tokio::test]
    async fn a_yes_approves() {
        expect_decision(Ok(true), Decision::Approve).await;
    }

    #[tokio::test]
    async fn a_no_denies() {
        expect_decision(Ok(false), Decision::Deny).await;
    }

    #[tokio::test]
    async fn a_timeout_denies() {
        expect_decision(Err(Failure::TimedOut), Decision::Deny).await;
    }

    #[tokio::test]
    async fn an_overlong_answer_denies() {
        expect_decision(Err(Failure::TooLong(64)), Decision::Deny).await;
    }

    #[tokio::test]
    async fn a_prompt_that_could_not_be_shown_denies() {
        expect_decision(
            Err(Failure::Unavailable("no screen".into())),
            Decision::Deny,
        )
        .await;
    }

    #[test]
    fn from_config_selects_each_mode() {
        let build = |s: &str| {
            let config: Config = toml::from_str(s).unwrap();
            from_config(&config)
        };
        assert!(build("confirm = \"off\"").is_ok());
        assert!(build("confirm = \"osascript\"").is_ok());
        assert!(build("confirm = \"tty\"").is_ok());
        assert!(build("confirm = \"askpass\"\naskpass = \"/bin/true\"").is_ok());
        // config load-time validation normally rejects this; the defensive
        // branch in from_config must fail rather than default to anything
        assert!(build("confirm = \"askpass\"").is_err());
    }

    /// A binding, optionally with the name `known_hosts` gave for it.
    fn bound(host_name: Option<&str>) -> Vec<SessionBinding> {
        vec![SessionBinding {
            host_fingerprint: "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU".into(),
            host_name: host_name.map(str::to_string),
            is_forwarding: false,
            session_id: Vec::new(),
            host_key: Vec::new(),
        }]
    }

    #[test]
    fn a_named_host_is_shown_by_name_rather_than_fingerprint() {
        // What someone approving a signature needs to read in a second is
        // "github.com", not 43 characters of base64.
        let ctx = ConfirmContext::new(&entry(), None, bound(Some("github.com")));
        let text = describe_request(&ctx);
        assert!(text.starts_with("Sign in to github.com?\n"), "{text}");
        assert!(!text.contains("SHA256:+DiY3"), "{text}");
    }

    #[test]
    fn an_unnamed_host_still_shows_its_fingerprint() {
        // No known_hosts entry, a hashed one, or a revoked one: the prompt
        // stays exact rather than saying nothing about the host at all.
        let ctx = ConfirmContext::new(&entry(), None, bound(None));
        assert!(
            describe_request(&ctx).starts_with("Sign in to SHA256:+DiY3"),
            "the fingerprint must remain when there is no name"
        );
    }

    #[test]
    fn a_hostname_from_known_hosts_is_untrusted_text() {
        // known_hosts is an editable file, so a name out of it gets the same
        // treatment as a vault-controlled key name.
        let ctx = ConfirmContext::new(&entry(), None, bound(Some("evil\r\n\x1b[2Jgithub.com")));
        let text = describe_request(&ctx);
        assert!(!text.contains('\x1b'), "{text}");
        assert!(!text.contains('\r'), "{text}");
        assert!(text.contains("\\x1b[2J"), "{text}");
    }

    /// A context for a request from `peer`.
    fn from_peer(peer: Option<PeerInfo>) -> ConfirmContext {
        ConfirmContext::new(&entry(), peer, Vec::new())
    }

    #[test]
    fn describe_request_names_the_requester() {
        let ctx = from_peer(None);
        let text = describe_request(&ctx);
        assert!(text.contains("\nFrom: unknown\n"), "{text}");
        // nothing known of the requester, so nothing of it in the details
        assert!(text.contains("\n\nDetails\nLastPass item: 42\n"), "{text}");

        let ctx = from_peer(Some(PeerInfo {
            pid: None,
            uid: 501,
        }));
        let text = describe_request(&ctx);
        assert!(text.contains("\nFrom: unknown process\n"), "{text}");
        assert!(
            text.contains("\n\nDetails\nProcess: uid 501\nLastPass item: 42\n"),
            "{text}"
        );

        // our own pid resolves to a real executable path
        let ctx = from_peer(Some(PeerInfo {
            pid: Some(std::process::id().cast_signed()),
            uid: 501,
        }));
        let text = describe_request(&ctx);
        assert!(
            text.contains(&format!("pid {}", std::process::id())),
            "{text}"
        );
        assert!(text.contains("ctx key"));
        assert!(text.contains("SHA256:"));
    }

    #[test]
    fn control_characters_in_untrusted_text_are_neutralized() {
        // A vault key name that tries to redraw the terminal and forge a
        // second, friendlier-looking prompt must render inert.
        let spoof = "innocent\r\n\x1b[2JKey: totally-safe-key\nAllow?";
        let mut spoofed = entry();
        spoofed.name = spoof.to_string();
        let text = describe_request(&ConfirmContext::new(&spoofed, None, Vec::new()));

        assert!(!text.contains('\r'), "{text}");
        assert!(!text.contains('\x1b'), "{text}");
        // exactly the lines we wrote ourselves, no injected extras
        assert_eq!(text.lines().filter(|l| l.starts_with("Key: ")).count(), 1);
        assert!(
            text.contains("\\x1b[2J"),
            "escape is shown literally: {text}"
        );
        assert!(text.contains("innocent\\x0d\\x0a"), "{text}");
        // C1 controls (e.g. U+009B, an alternate CSI) are escaped too
        let mut c1 = entry();
        c1.name = "csi\u{9b}2J".to_string();
        assert!(
            describe_request(&ConfirmContext::new(&c1, None, Vec::new())).contains("csi\\x9b2J")
        );
        // A right-to-left override renders everything after it in reverse,
        // so an unescaped one could make the dialog show a different key
        // name than the request it is approving.
        let mut bidi = entry();
        bidi.name = "github\u{202e}yek-live".to_string();
        let text = describe_request(&ConfirmContext::new(&bidi, None, Vec::new()));
        assert!(text.contains("github\\u{202e}yek-live"), "{text}");
        // ordinary text is untouched
        assert!(
            describe_request(&ConfirmContext::new(&entry(), None, Vec::new())).contains("ctx key")
        );
    }

    #[test]
    fn the_request_says_what_it_was_started_from() {
        // This process has a parent (the test runner, at least), so the line
        // is there; pid 1's ancestry is nobody's application, so it is not.
        let ctx = from_peer(Some(PeerInfo {
            pid: Some(std::process::id().cast_signed()),
            uid: 501,
        }));
        let text = describe_request(&ctx);
        assert!(text.contains(" → "), "{text}");
        // a process with no readable ancestry is named without the line
        let rootless = ConfirmContext {
            requester: Some(Requester {
                process: "/usr/bin/ssh".into(),
                origin: Vec::new(),
            }),
            ..ctx
        };
        let text = describe_request(&rootless);
        assert!(text.contains("\nFrom: ssh\n"), "{text}");
        assert!(
            text.contains("\n\nDetails\nProcess: /usr/bin/ssh (pid"),
            "{text}"
        );
    }

    #[test]
    fn the_account_logged_in_to_is_shown_and_is_part_of_the_question() {
        let known = from_peer(Some(PeerInfo {
            pid: Some(std::process::id().cast_signed()),
            uid: 501,
        }));
        let as_user = |user: &[u8]| ConfirmContext {
            user: Some(user.to_vec()),
            bindings: bound(Some("github.com")),
            ..known.clone()
        };
        let text = describe_request(&as_user(b"deploy"));
        assert!(
            text.starts_with("Sign in to github.com as deploy?\n\nKey: "),
            "{text}"
        );
        // the requester's to choose, so it cannot forge a line of the prompt
        let forged = describe_request(&as_user(b"deploy\nFrom: you"));
        assert!(
            forged.starts_with("Sign in to github.com as deploy\\x0aFrom: you?\n"),
            "{forged}"
        );

        // an approval for one account does not answer for another
        assert_ne!(
            approval_question(&as_user(b"deploy")).unwrap(),
            approval_question(&as_user(b"root")).unwrap()
        );
        // nor for one the prompt happens to render the same way: two invalid
        // names, and a control character beside its own escape
        for (one, other) in [(&b"a\xff"[..], &b"a\xfe"[..]), (b"a\n", b"a\\x0a")] {
            assert_eq!(
                describe_request(&as_user(one)),
                describe_request(&as_user(other))
            );
            assert_ne!(
                approval_question(&as_user(one)).unwrap(),
                approval_question(&as_user(other)).unwrap()
            );
        }
    }

    #[test]
    fn a_request_that_names_no_destination_says_so() {
        // A blank would read as nothing to report, where it is the one thing
        // this prompt cannot say.
        let text = describe_request(&from_peer(None));
        assert_eq!(
            text,
            "Allow an SSH signature?\n\nKey: ctx key\n\
             Destination: not stated by the client\nFrom: unknown\n\nDetails\n\
             LastPass item: 42\nFingerprint: \
             SHA256:0WfFJFesqXKxE3C4SGTzZ/+mb3AzYvhjoxgKemT4FQw"
        );
        assert!(!needs_caution(&from_peer(None)));
    }

    #[test]
    fn a_signature_that_is_no_login_says_what_it_signs() {
        let signing = |namespace: &[u8]| ConfirmContext {
            namespace: Some(namespace.to_vec()),
            ..from_peer(None)
        };
        let git = describe_request(&signing(b"git"));
        assert!(git.starts_with("Sign data for \"git\"?\n\nKey: "), "{git}");
        assert!(!git.contains("Destination"), "not a login: {git}");
        // the requester's to choose, so it cannot forge a line of the prompt
        let other = describe_request(&signing(b"file\nFrom: you"));
        assert!(
            other.starts_with("Sign data for \"file\\x0aFrom: you\"?\n"),
            "{other}"
        );
    }

    #[test]
    fn the_prompt_says_when_a_yes_is_remembered() {
        let line = "?\nAllow is remembered until the vault locks.\n\nKey: ctx key\nDestination";
        let once = from_peer(None);
        assert!(!describe_request(&once).contains("remembered"));
        let kept = ConfirmContext {
            remembered: true,
            ..once
        };
        let text = describe_request(&kept);
        assert!(text.contains(line), "{text}");
    }

    #[test]
    fn a_forwarded_request_leads_with_the_warning_and_spells_out_the_way() {
        let hop = |name: &str, is_forwarding| SessionBinding {
            host_fingerprint: "SHA256:fp".into(),
            host_name: Some(name.into()),
            is_forwarding,
            session_id: Vec::new(),
            host_key: Vec::new(),
        };
        let ctx = ConfirmContext {
            user: Some(b"git".to_vec()),
            ..ConfirmContext::new(
                &entry(),
                None,
                vec![hop("build01", true), hop("github.com", false)],
            )
        };
        let text = describe_request(&ctx);
        assert!(
            text.starts_with("WARNING: the agent is forwarded"),
            "{text}"
        );
        assert!(
            text.contains(
                "\n\nSign in to github.com as git?\n\nKey: ctx key\nFrom: unknown\n\
                 Via: build01 (forwarding the agent onward) → github.com\n\nDetails"
            ),
            "{text}"
        );
        assert!(needs_caution(&ctx));

        // one that does not name its server says so three times over: ahead
        // of everything, in the question, and on the way there
        let unverified = ConfirmContext {
            unverified_destination: true,
            ..ctx
        };
        let text = describe_request(&unverified);
        assert!(
            text.contains(".\n\nUNVERIFIED DESTINATION: this request does not name"),
            "{text}"
        );
        assert!(
            text.contains(
                "\n\nSign in to github.com (unverified) as git?\n\nKey: ctx key\nFrom: unknown\n\
                 Via: build01 (forwarding the agent onward) → github.com (unverified)\n\nDetails"
            ),
            "{text}"
        );
        assert!(needs_caution(&unverified));

        // a direct connection is its own destination: nothing to spell out,
        // and nothing to be cautious about
        let direct = ConfirmContext::new(&entry(), None, vec![hop("github.com", false)]);
        assert!(!describe_request(&direct).contains("Via:"));
        assert!(!needs_caution(&direct));
    }

    #[test]
    fn a_long_chain_shows_its_ends_and_counts_what_lies_between() {
        let hop = |name: &str, is_forwarding| SessionBinding {
            host_fingerprint: "SHA256:fp".into(),
            host_name: Some(name.into()),
            is_forwarding,
            session_id: Vec::new(),
            host_key: Vec::new(),
        };
        let chain = |names: &[&str]| {
            let (last, forwarding) = names.split_last().unwrap();
            let mut hops: Vec<SessionBinding> =
                forwarding.iter().map(|name| hop(name, true)).collect();
            hops.push(hop(last, false));
            describe_request(&ConfirmContext::new(&entry(), None, hops))
        };
        let onward = "(forwarding the agent onward)";
        // as many as are shown whole
        let text = chain(&["a", "b", "c", "d"]);
        assert!(
            text.contains(&format!(
                "\nVia: a {onward} → b {onward} → c {onward} → d\n"
            )),
            "{text}"
        );
        // one more than that
        let text = chain(&["a", "b", "c", "d", "e"]);
        assert!(
            text.contains(&format!("\nVia: a {onward} → [3 more hosts] → e\n")),
            "{text}"
        );
        // with the hosts between still there to be read, after everything else
        assert!(
            text.ends_with(&format!(
                "\nEvery host on the way: a {onward} → b {onward} → c {onward} → d {onward} → e"
            )),
            "{text}"
        );
        // and a host in it named at length gives way where the cut is shown
        let long = "h".repeat(70);
        let text = chain(&[&long, "b"]);
        assert!(
            text.contains(&format!(
                "\nVia: {}… [6 more] {onward} → b\n",
                "h".repeat(64)
            )),
            "{text}"
        );
    }

    /// A requester whose ancestors and path are as given, nearest first.
    fn started_from(process: &str, names: &[&str]) -> ConfirmContext {
        ConfirmContext {
            requester: Some(Requester {
                process: process.into(),
                origin: names
                    .iter()
                    .map(|name| Ancestor {
                        name: (*name).into(),
                        path: format!("/bin/{name}"),
                    })
                    .collect(),
            }),
            ..from_peer(Some(PeerInfo {
                pid: Some(7),
                uid: 501,
            }))
        }
    }

    #[test]
    fn a_process_named_at_length_gives_way_and_the_requester_is_still_named() {
        let long = "n".repeat(45);
        let text = describe_request(&started_from("/usr/bin/ssh", &["zsh", &long]));
        assert!(
            text.contains(&format!(
                "\nFrom: {}… [5 more] → zsh → ssh\n\nDetails\nProcess: /usr/bin/ssh (pid 7, uid 501)\n",
                "n".repeat(40)
            )),
            "{text}"
        );
        // a path is whole at any length a path has: two that differ only at
        // the end are two programs
        let deep = format!("/{}/ssh", "d".repeat(500));
        let text = describe_request(&started_from(&deep, &[]));
        assert!(
            text.contains(&format!(
                "\n\nDetails\nProcess: /{}/ssh (pid 7, uid 501)\n",
                "d".repeat(500)
            )),
            "{text}"
        );
        // and gives way past that, before a terminal loses the question to it
        let endless = format!("/{}", "e".repeat(1004));
        let text = describe_request(&started_from(&endless, &[]));
        assert!(
            text.contains(&format!(
                "\n\nDetails\nProcess: /{}… [5 more] (pid 7, uid 501)\n",
                "e".repeat(999)
            )),
            "{text}"
        );
    }

    #[test]
    fn the_longest_prompt_there_can_be_is_bounded() {
        // Every part as long as its author can make it: the vault's key name
        // and item id, the forwarded side's hops and account, and a process
        // tree of the requester's own choosing. What is bounded is what is
        // read without scrolling for it — everything above the details.
        let endless = "x".repeat(10_000);
        let shown = format!("{}… [9800 more]", "x".repeat(200));
        // Both sides of where a chain stops being shown hop by hop: the most
        // hops shown whole, and the most there can be.
        for (hop_count, most) in [(4, 2_200), (16, 2_000)] {
            let hops: Vec<SessionBinding> = (0..hop_count)
                .map(|at| SessionBinding {
                    host_fingerprint: endless.clone(),
                    host_name: Some(endless.clone()),
                    is_forwarding: at + 1 < hop_count,
                    session_id: Vec::new(),
                    host_key: Vec::new(),
                })
                .collect();
            let names = [endless.as_str(); 8];
            let mut ctx = ConfirmContext {
                bindings: hops,
                user: Some(endless.clone().into_bytes()),
                remembered: true,
                unverified_destination: true,
                ..started_from(&endless, &names)
            };
            ctx.key_name.clone_from(&endless);
            ctx.item_id.clone_from(&endless);
            ctx.fingerprint.clone_from(&endless);
            let text = describe_request(&ctx);
            let (above, details) = text.split_once("\n\nDetails\n").unwrap();
            let length = above.chars().count();
            assert!(length < most, "{hop_count} hops: {length} characters");
            // and the details are no more than a terminal can show with it
            let most_below = if hop_count == 4 { 1_500 } else { 3_300 };
            let below = details.chars().count();
            assert!(below < most_below, "{hop_count} hops: {below} below");
            // and what is decided on is all there, ahead of what gave way
            assert!(
                text.contains(&format!(
                    "\n\nSign in to {shown} (unverified) as {shown}?\n\
                     Allow is remembered until the vault locks.\n\nKey: {shown}\n"
                )),
                "{hop_count} hops: {text}"
            );
        }
    }

    #[tokio::test]
    async fn a_request_to_be_cautious_about_is_put_as_one() {
        let transport = Arc::new(FakeTransport {
            verdict: Ok(true),
            asked: std::sync::Mutex::new(Vec::new()),
        });
        let forwarded = ConfirmContext::new(
            &entry(),
            None,
            vec![SessionBinding {
                host_fingerprint: "SHA256:fp".into(),
                host_name: None,
                is_forwarding: true,
                session_id: Vec::new(),
                host_key: Vec::new(),
            }],
        );
        TransportConfirmer::new(transport.clone())
            .confirm(&forwarded)
            .await;
        assert!(transport.asked.lock().unwrap()[0].1);
    }

    #[test]
    fn the_namespace_signed_under_is_part_of_the_question() {
        let known = from_peer(Some(PeerInfo {
            pid: Some(std::process::id().cast_signed()),
            uid: 501,
        }));
        let signing = |namespace: &[u8]| ConfirmContext {
            namespace: Some(namespace.to_vec()),
            ..known.clone()
        };
        // an approval to sign commits does not answer for anything else the
        // same program is asked to sign
        assert_ne!(
            approval_question(&signing(b"git")).unwrap(),
            approval_question(&signing(b"file")).unwrap()
        );
        assert_ne!(
            approval_question(&signing(b"git")).unwrap(),
            approval_question(&known).unwrap()
        );
    }

    #[test]
    fn an_unverified_destination_is_a_question_of_its_own() {
        // an approval given for hosts the request named must not answer for
        // the same hosts as a claim, nor the other way round
        let known = from_peer(Some(PeerInfo {
            pid: Some(std::process::id().cast_signed()),
            uid: 501,
        }));
        let verified = approval_question(&known).unwrap();
        let unverified = approval_question(&ConfirmContext {
            unverified_destination: true,
            ..known
        })
        .unwrap();
        assert_ne!(verified, unverified);
    }

    #[test]
    fn the_approval_question_is_the_prompt_without_the_pid() {
        // A requester that cannot be told from another has no question to
        // remember: no peer, no pid, or a pid with no readable executable.
        assert!(approval_question(&from_peer(None)).is_none());
        assert!(
            approval_question(&from_peer(Some(PeerInfo {
                pid: None,
                uid: 501,
            })))
            .is_none()
        );
        assert!(
            approval_question(&from_peer(Some(PeerInfo {
                pid: Some(0),
                uid: 501,
            })))
            .is_none()
        );

        let pid = std::process::id().cast_signed();
        let mut ctx = from_peer(Some(PeerInfo {
            pid: Some(pid),
            uid: 501,
        }));
        let question = approval_question(&ctx).unwrap();
        assert!(question.starts_with("42\nSHA256:"), "{question}");
        assert!(question.contains("\nctx key\n"), "{question}");
        assert!(!question.contains(&format!("{pid}\n")), "{question}");
        assert!(question.contains("\n501\n"), "{question}");
        // two ancestries that would read alike joined on the arrow the prompt
        // uses are still two questions
        let at = |path: &str| Ancestor {
            name: path.rsplit('/').next().unwrap().to_string(),
            path: path.to_string(),
        };
        let mut split = ctx.clone();
        split.requester = Some(Requester {
            process: "ssh".into(),
            origin: vec![at("/bin/shell"), at("/bin/Terminal")],
        });
        let mut joined = ctx.clone();
        joined.requester = Some(Requester {
            process: "ssh".into(),
            origin: vec![at("/bin/shell → /bin/Terminal")],
        });
        assert_ne!(approval_question(&split), approval_question(&joined));
        // and two ancestries that share names but not paths are two questions
        let mut elsewhere = split.clone();
        elsewhere.requester = Some(Requester {
            process: "ssh".into(),
            origin: vec![at("/tmp/x/shell"), at("/tmp/x/Terminal")],
        });
        assert_ne!(approval_question(&split), approval_question(&elsewhere));

        // the hosts tell two sessions apart, and forwarding is part of that
        ctx.bindings = vec![
            SessionBinding {
                host_fingerprint: "SHA256:aaa".into(),
                host_name: Some("a".into()),
                is_forwarding: true,
                session_id: Vec::new(),
                host_key: Vec::new(),
            },
            SessionBinding {
                host_fingerprint: "SHA256:bbb".into(),
                host_name: None,
                is_forwarding: false,
                session_id: Vec::new(),
                host_key: Vec::new(),
            },
        ];
        ctx.user = Some(b"git".to_vec());
        let bound = approval_question(&ctx).unwrap();
        assert!(
            // then the account, no namespace, and last whether the
            // destination is unverified
            bound.ends_with("\nSHA256:aaa\x1ea\x1eforwarding\x1fSHA256:bbb\x1e\x1e\n676974\n\n\n"),
            "{bound:?}"
        );
        assert_ne!(bound, question);
        // a name that comes or goes is a different question too
        ctx.bindings[0].host_name = None;
        assert_ne!(approval_question(&ctx).unwrap(), bound);
    }

    #[test]
    fn a_pid_with_no_executable_is_named_as_unknown() {
        let bogus = from_peer(Some(PeerInfo {
            pid: Some(0),
            uid: 501,
        }));
        let text = describe_request(&bogus);
        assert!(text.contains("\nFrom: unknown process\n"), "{text}");
        assert!(
            text.contains("\n\nDetails\nProcess: pid 0, uid 501\n"),
            "{text}"
        );
    }
}
