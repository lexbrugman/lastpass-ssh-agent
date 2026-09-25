mod askpass;
mod osascript;
mod tty;

pub use askpass::AskpassConfirmer;
pub use osascript::OsascriptConfirmer;
pub use tty::TtyConfirmer;

use crate::keystore::KeyEntry;
use crate::requester::Requester;
use crate::text::escape_for_display;

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

/// Build the confirmer selected by the config.
pub fn from_config(
    config: &crate::config::Config,
) -> crate::error::Result<std::sync::Arc<dyn Confirmer>> {
    use crate::config::ConfirmMode;
    use std::time::Duration;
    let timeout = Duration::from_secs(config.confirm_timeout_secs);
    Ok(match config.confirm {
        ConfirmMode::Off => std::sync::Arc::new(NoConfirmer),
        ConfirmMode::Osascript => std::sync::Arc::new(OsascriptConfirmer::new(timeout)),
        ConfirmMode::Tty => std::sync::Arc::new(TtyConfirmer::new(timeout)),
        ConfirmMode::Askpass => {
            // validated at config load
            let program = config.askpass.clone().ok_or_else(|| {
                crate::error::Error::ConfigInvalid("askpass mode without helper".into())
            })?;
            std::sync::Arc::new(AskpassConfirmer::new(program, timeout))
        }
    })
}

/// Human-readable description of a signing request, shared by all confirmers.
///
/// The key name, the requester's path, its ancestors' names and the host name
/// are all untrusted — the vault, whoever spawned the processes, and
/// `known_hosts` respectively. They only ever travel as data, but control
/// characters could still redraw a TTY prompt and a bidi override could
/// reverse how a line renders, either of which spoofs what is being approved.
/// So everything interpolated here is escaped.
pub fn describe_request(ctx: &ConfirmContext) -> String {
    use std::fmt::Write as _;
    let requester = match (ctx.peer, &ctx.requester) {
        (None, _) => "unknown".to_string(),
        (Some(peer), None) => peer.pid.map_or_else(
            || format!("uid {}", peer.uid),
            |pid| format!("unknown process (pid {pid}, uid {})", peer.uid),
        ),
        (Some(peer), Some(requester)) => {
            let mut line = format!(
                "{} (pid {}, uid {})",
                requester.process,
                // A requester is only ever looked up by a pid.
                peer.pid.unwrap_or_default(),
                peer.uid
            );
            // `ssh` says nothing about whether it was you. What it was started
            // from — a shell in a terminal, an editor, a build — is what the
            // person reading this recognises, and what a request from
            // somewhere unexpected stands out by.
            if !requester.origin.is_empty() {
                let names: Vec<&str> = requester
                    .origin
                    .iter()
                    .map(|ancestor| ancestor.name.as_str())
                    .collect();
                let _ = write!(line, "\nStarted from: {}", names.join(" → "));
            }
            line
        }
    };
    let mut text = format!(
        "SSH signature request\n\nKey: {}\nFingerprint: {}\nLastPass item: {}\nRequested by: {requester}",
        escape_for_display(&ctx.key_name),
        escape_for_display(&ctx.fingerprint),
        escape_for_display(&ctx.item_id),
    );
    // Without this, a request relayed from a machine you ran `ssh -A` to is
    // indistinguishable from one you made yourself: both name the local ssh
    // process. Each hop in the chain proved possession of its host key.
    if !ctx.bindings.is_empty() {
        let chain: Vec<String> = ctx
            .bindings
            .iter()
            .map(|bind| {
                // The name when there is one: a fingerprint identifies the
                // host exactly and says nothing to the person reading it. The
                // log keeps the fingerprint either way.
                let mut hop =
                    escape_for_display(bind.host_name.as_ref().unwrap_or(&bind.host_fingerprint));
                if bind.is_forwarding {
                    hop.push_str(" (forwarding the agent onward)");
                }
                hop
            })
            .collect();
        // The warning ahead of the hops rather than after them: a chain is as
        // long as a forwarded peer cares to make it, and a dialog clips at the
        // bottom.
        if ctx.bindings.iter().any(|bind| bind.is_forwarding) {
            text.push_str(
                "\n\nWARNING: the agent is forwarded to a host below — this request may \
                 have originated there rather than on this machine.",
            );
        }
        let _ = write!(text, "\nSSH session: {}", chain.join(" → "));
    }
    text
}

/// What a remembered approval answers for: the key, and everything the
/// prompt says about who asked — the process and its uid, what it was started
/// from, and the hosts the session is bound to. The same words on screen are
/// the same question; anything else asks again. The pid is left out, since a
/// new `ssh` has a new one every time and is the point of remembering.
///
/// `None` when the requester cannot be told from another: no pid from the
/// socket, or a pid whose executable cannot be read. An approval for
/// "whatever runs as this uid" would answer for every process, so such a
/// request is asked every time.
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
            hop.push_str(
                &bind
                    .host_name
                    .as_deref()
                    .map_or_else(String::new, escape_for_display),
            );
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
    ] {
        question.push_str(&piece);
        question.push('\n');
    }
    Some(question)
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
        assert!(text.contains("SSH session: github.com"), "{text}");
        assert!(!text.contains("SHA256:+DiY3"), "{text}");
    }

    #[test]
    fn an_unnamed_host_still_shows_its_fingerprint() {
        // No known_hosts entry, a hashed one, or a revoked one: the prompt
        // stays exact rather than saying nothing about the host at all.
        let ctx = ConfirmContext::new(&entry(), None, bound(None));
        assert!(
            describe_request(&ctx).contains("SSH session: SHA256:+DiY3"),
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
        assert!(describe_request(&ctx).contains("Requested by: unknown"));

        let ctx = from_peer(Some(PeerInfo {
            pid: None,
            uid: 501,
        }));
        assert!(describe_request(&ctx).contains("Requested by: uid 501"));

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
        assert!(text.contains("\nStarted from: "), "{text}");
        // a process with no readable ancestry is named without the line
        let rootless = ConfirmContext {
            requester: Some(Requester {
                process: "/usr/bin/ssh".into(),
                origin: Vec::new(),
            }),
            ..ctx
        };
        let text = describe_request(&rootless);
        assert!(text.contains("Requested by: /usr/bin/ssh (pid"), "{text}");
        assert!(!text.contains("Started from"), "{text}");
    }

    #[test]
    fn the_approval_question_is_the_prompt_without_the_pid() {
        // A requester that cannot be told from another has no question to
        // remember: no peer, no pid, or a pid with no readable executable.
        assert!(approval_question(&from_peer(None)).is_none());
        assert!(approval_question(&from_peer(Some(PeerInfo {
            pid: None,
            uid: 501,
        })))
        .is_none());
        assert!(approval_question(&from_peer(Some(PeerInfo {
            pid: Some(0),
            uid: 501,
        })))
        .is_none());

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
        let bound = approval_question(&ctx).unwrap();
        assert!(
            bound.ends_with("\nSHA256:aaa\x1ea\x1eforwarding\x1fSHA256:bbb\x1e\x1e\n"),
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
        assert!(describe_request(&bogus).contains("unknown process (pid 0, uid 501)"));
    }
}
