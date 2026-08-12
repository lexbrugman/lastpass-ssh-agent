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
}

impl ConfirmContext {
    pub fn new(entry: &KeyEntry, peer: Option<PeerInfo>, bindings: Vec<SessionBinding>) -> Self {
        Self {
            key_name: entry.name.clone(),
            fingerprint: entry.fingerprint(),
            item_id: entry.item_id.clone(),
            peer,
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
/// The key name, the requester's path and the host name are all untrusted — the
/// vault, whoever spawned the process, and `known_hosts` respectively. They only
/// ever travel as data, but control characters could still redraw a TTY prompt
/// and a bidi override could reverse how a line renders, either of which spoofs
/// what is being approved. So everything interpolated here is escaped.
pub fn describe_request(ctx: &ConfirmContext) -> String {
    use std::fmt::Write as _;
    let requester = ctx.peer.map_or_else(
        || "unknown".to_string(),
        |peer| {
            peer.pid.map_or_else(
                || format!("uid {}", peer.uid),
                |pid| {
                    let process = process_path(pid)
                        .map_or_else(|| "unknown process".to_string(), |p| escape_for_display(&p));
                    format!("{process} (pid {pid}, uid {})", peer.uid)
                },
            )
        },
    );
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

    #[test]
    fn describe_request_names_the_requester() {
        let mut ctx = ConfirmContext::new(&entry(), None, Vec::new());
        assert!(describe_request(&ctx).contains("Requested by: unknown"));

        ctx.peer = Some(PeerInfo {
            pid: None,
            uid: 501,
        });
        assert!(describe_request(&ctx).contains("Requested by: uid 501"));

        // our own pid resolves to a real executable path
        ctx.peer = Some(PeerInfo {
            pid: Some(std::process::id().cast_signed()),
            uid: 501,
        });
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
    fn process_path_handles_bogus_pid() {
        assert!(process_path(std::process::id().cast_signed()).is_some());
        // pid 0 / absurd pids have no executable path
        assert!(process_path(0).is_none());
        let bogus = ConfirmContext {
            peer: Some(PeerInfo {
                pid: Some(0),
                uid: 501,
            }),
            ..ConfirmContext::new(&entry(), None, Vec::new())
        };
        assert!(describe_request(&bogus).contains("unknown process"));
    }
}
