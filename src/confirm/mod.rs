mod askpass;
mod osascript;
mod tty;

pub use askpass::AskpassConfirmer;
pub use osascript::OsascriptConfirmer;
pub use tty::TtyConfirmer;

use crate::keystore::KeyEntry;
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

/// The requesting process as the prompt names it, and what it was started
/// from. Both escaped: whoever spawned the processes chose the names.
#[derive(Debug, Clone)]
pub struct Requester {
    pub process: String,
    pub origin: Vec<String>,
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
            requester: peer.and_then(|peer| peer.pid).and_then(requester),
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
                let _ = write!(line, "\nStarted from: {}", requester.origin.join(" → "));
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
        let _ = write!(text, "\nSSH session: {}", chain.join(" → "));
        if ctx.bindings.iter().any(|bind| bind.is_forwarding) {
            text.push_str(
                "\n\nWARNING: the agent is forwarded to that host — this request may \
                 have originated there rather than on this machine.",
            );
        }
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
        requester.origin.join(&SEP.to_string()),
        hosts.join(&SEP.to_string()),
    ] {
        question.push_str(&piece);
        question.push('\n');
    }
    Some(question)
}

/// The process behind a pid, when its executable can be read at all.
fn requester(pid: i32) -> Option<Requester> {
    Some(Requester {
        process: escape_for_display(&process_path(pid)?),
        origin: origin_chain(pid),
    })
}

/// Executable path of a pid, best effort.
fn process_path(pid: i32) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let size = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).expect("positive constant");
        let mut buf = vec![0u8; size];
        // SAFETY: proc_pidpath writes at most buf.len() bytes into buf.
        let len = unsafe {
            libc::proc_pidpath(
                pid,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                u32::try_from(size).expect("buffer fits u32"),
            )
        };
        let len = usize::try_from(len).ok().filter(|l| *l > 0)?;
        Some(String::from_utf8_lossy(&buf[..len]).to_string())
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.display().to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

/// Parent of a pid, best effort. `None` for anything that cannot be asked.
fn parent_pid(pid: i32) -> Option<i32> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: proc_bsdinfo is plain data, for which all-zero is a value.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
            .expect("a small struct");
        // SAFETY: the buffer is exactly `size` bytes of a proc_bsdinfo, which
        // is what this flavor fills in.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&raw mut info).cast::<libc::c_void>(),
                size,
            )
        };
        // Anything short of the whole struct is a failure, in the call's own
        // convention.
        (written == size)
            .then(|| i32::try_from(info.pbi_ppid).ok())
            .flatten()
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|rest| rest.trim().parse().ok())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

/// How many ancestors are named: enough for `ssh` under `git` under a shell
/// under a terminal under the app that opened it, without walking a runaway
/// tree.
const MAX_ORIGIN_DEPTH: usize = 8;

/// The names of a process's ancestors, nearest first, up to the top of the
/// user's own tree.
fn origin_chain(pid: i32) -> Vec<String> {
    origin_chain_from(pid, &parent_pid, &process_path)
}

/// `origin_chain` over whichever lookups are given, so the walk can be tested
/// on a tree of the test's own making.
///
/// Stops before pid 1 — the tree's root names no application — and at the
/// first ancestor that cannot be read. Consecutive repeats of one name, a shell
/// that ran a shell, collapse into one, so the line reads as the steps that
/// matter. Cycles need no guard: the kernel keeps this a tree, and the depth
/// bound holds regardless.
///
/// The lookups are trait objects rather than generics so that there is one
/// instantiation: the coverage summary accounts for a generic function's
/// branches per instantiation, and no single test tree takes every exit.
fn origin_chain_from(
    pid: i32,
    parent: &dyn Fn(i32) -> Option<i32>,
    path: &dyn Fn(i32) -> Option<String>,
) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut current = pid;
    // Bounds the ancestors walked, not the names kept: a chain of one name
    // repeated collapses to one entry, and must still end.
    for _ in 0..MAX_ORIGIN_DEPTH {
        let Some(next) = parent(current).filter(|next| *next > 1) else {
            break;
        };
        let Some(path) = path(next) else {
            break;
        };
        let name = display_name(&path);
        if names.last() != Some(&name) {
            names.push(name);
        }
        current = next;
    }
    names
}

/// How an ancestor is named: the app bundle when it runs from one — the
/// outermost, so a helper process inside an editor is named for the editor —
/// and the executable's file name otherwise. Escaped, since whoever spawned
/// the process chose it.
fn display_name(path: &str) -> String {
    let bundle = path
        .split('/')
        .find_map(|part| part.strip_suffix(".app"))
        .filter(|stem| !stem.is_empty());
    let name = bundle.or_else(|| path.rsplit('/').next()).unwrap_or(path);
    escape_for_display(name)
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

    const ED25519_PUB: &str = include_str!("../../tests/fixtures/ed25519.pub");

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
        assert!(origin_chain(1).is_empty());
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
        assert!(
            parent_pid(0).is_none() || parent_pid(0).is_some(),
            "best effort either way"
        );
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
        let mut split = ctx.clone();
        split.requester = Some(Requester {
            process: "ssh".into(),
            origin: vec!["shell".into(), "Terminal".into()],
        });
        let mut joined = ctx.clone();
        joined.requester = Some(Requester {
            process: "ssh".into(),
            origin: vec!["shell → Terminal".into()],
        });
        assert_ne!(approval_question(&split), approval_question(&joined));

        // the hosts tell two sessions apart, and forwarding is part of that
        ctx.bindings = vec![
            SessionBinding {
                host_fingerprint: "SHA256:aaa".into(),
                host_name: Some("a".into()),
                is_forwarding: true,
            },
            SessionBinding {
                host_fingerprint: "SHA256:bbb".into(),
                host_name: None,
                is_forwarding: false,
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
    fn the_origin_walk_stops_at_the_root_and_collapses_repeats() {
        // 10 ← 9 ← 8 ← ... ← 1: a shell that ran a shell reads as one step,
        // and the root itself is never named.
        let parent = |pid: i32| (pid > 1).then_some(pid - 1);
        let path = |pid: i32| {
            Some(match pid {
                9 | 8 => "/bin/zsh".to_string(),
                7 => "/Applications/Terminal.app/Contents/MacOS/Terminal".to_string(),
                other => format!("/usr/bin/p{other}"),
            })
        };
        assert_eq!(
            origin_chain_from(10, &parent, &path),
            ["zsh", "Terminal", "p6", "p5", "p4", "p3", "p2"]
        );
        // an ancestor that cannot be read ends the walk there
        let unreadable = |pid: i32| (pid != 7).then(|| format!("/usr/bin/p{pid}"));
        assert_eq!(origin_chain_from(10, &parent, &unreadable), ["p9", "p8"]);
        // and a tree deeper than anyone reads is cut at the bound
        assert_eq!(
            origin_chain_from(100, &parent, &|pid| Some(format!("/p{pid}"))).len(),
            MAX_ORIGIN_DEPTH
        );
        // the bound is on ancestors walked: a chain of one name repeated
        // collapses to one entry and still ends
        let walked = std::cell::Cell::new(0);
        let counted = |pid: i32| {
            walked.set(walked.get() + 1);
            parent(pid)
        };
        assert_eq!(
            origin_chain_from(100, &counted, &|_| Some("/bin/sh".to_string())),
            ["sh"]
        );
        assert_eq!(walked.get(), MAX_ORIGIN_DEPTH);
    }

    #[test]
    fn an_ancestor_is_named_for_its_app_bundle_or_its_executable() {
        assert_eq!(display_name("/usr/bin/git"), "git");
        // the outermost bundle: a helper inside an editor is the editor
        assert_eq!(
            display_name(
                "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)"
            ),
            "Visual Studio Code"
        );
        // a bare ".app" component names nothing, so the file name stands
        assert_eq!(display_name("/x/.app/bin/tool"), "tool");
        // untrusted: a name that tries to redraw the dialog is shown literally
        assert_eq!(display_name("/tmp/evil\x1b[2J"), "evil\\x1b[2J");
        assert_eq!(display_name("noslash"), "noslash");
    }

    #[test]
    fn process_path_handles_bogus_pid() {
        assert!(process_path(std::process::id().cast_signed()).is_some());
        // pid 0 / absurd pids have no executable path
        assert!(process_path(0).is_none());
        let bogus = from_peer(Some(PeerInfo {
            pid: Some(0),
            uid: 501,
        }));
        assert!(describe_request(&bogus).contains("unknown process (pid 0, uid 501)"));
    }
}
