use std::process::Stdio;
use std::time::Duration;

use super::{ConfirmContext, Confirmer, Decision};

/// Native macOS confirmation dialog via `osascript`.
///
/// Fail-closed by construction:
/// - "Deny" is both the default and the cancel button
/// - the dialog gives up after the timeout (treated as Deny)
/// - any osascript failure — including "No user interaction allowed" when
///   there is no GUI session (e.g. SSH'd into this machine) — is Deny
/// - untrusted text (key names come from the vault) is passed as argv to
///   `on run argv`, never interpolated into `AppleScript` source
///
/// Prompts are shown one at a time. Concurrent signing requests would
/// otherwise stack identical-looking dialogs, and approving the frontmost
/// one would approve whichever request happened to be on top rather than
/// the one just read. Each queued request gets its own dialog and its own
/// full timeout once the screen is free.
pub struct OsascriptConfirmer {
    timeout: Duration,
    /// Extra slack past the dialog's own give-up before we kill osascript.
    grace: Duration,
    program: std::path::PathBuf,
    serialize: tokio::sync::Mutex<()>,
}

const DIALOG_SCRIPT: &str = r#"
on run argv
    set message to item 1 of argv
    set giveUp to (item 2 of argv) as integer
    tell application "System Events"
        activate
        display dialog message with title "lastpass-ssh-agent" ¬
            buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" ¬
            with icon caution giving up after giveUp
    end tell
end run
"#;

impl OsascriptConfirmer {
    pub fn new(timeout: Duration) -> Self {
        Self::with_program(
            "/usr/bin/osascript".into(),
            timeout,
            Duration::from_secs(10),
        )
    }

    /// Tests stub out osascript with a script and shrink the kill backstop.
    pub fn with_program(program: std::path::PathBuf, timeout: Duration, grace: Duration) -> Self {
        Self {
            timeout,
            grace,
            program,
            serialize: tokio::sync::Mutex::new(()),
        }
    }
}

#[async_trait::async_trait]
impl Confirmer for OsascriptConfirmer {
    async fn confirm(&self, ctx: &ConfirmContext) -> Decision {
        // One dialog on screen at a time; see the type's documentation.
        let _one_at_a_time = self.serialize.lock().await;

        let message = super::describe_request(ctx);
        let give_up = self.timeout.as_secs().max(1).to_string();

        let child = tokio::process::Command::new(&self.program)
            .arg("-e")
            .arg(DIALOG_SCRIPT)
            .arg(&message)
            .arg(&give_up)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn();
        let child = match child {
            Ok(child) => child,
            Err(e) => {
                tracing::warn!("cannot spawn osascript, denying: {e}");
                return Decision::Deny;
            }
        };

        // Backstop in case the dialog wedges: osascript enforces the
        // give-up itself; add slack, then kill.
        let output =
            match tokio::time::timeout(self.timeout + self.grace, child.wait_with_output()).await {
                Ok(Ok(output)) => output,
                Ok(Err(e)) => {
                    tracing::warn!("osascript failed, denying: {e}");
                    return Decision::Deny;
                }
                Err(_) => {
                    tracing::warn!("confirmation dialog wedged, denying");
                    return Decision::Deny;
                }
            };

        let stdout = String::from_utf8_lossy(&output.stdout);
        // "giving up after" returns success with `gave up:true` instead of a
        // nonzero exit — an expired dialog must not count as approval.
        let approved = output.status.success()
            && stdout.contains("button returned:Allow")
            && !stdout.contains("gave up:true");
        if !approved && !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No user interaction allowed") {
                tracing::warn!(
                    "no GUI session available for the confirmation dialog — denying \
                     (use confirm = \"tty\" or \"askpass\" in headless setups)"
                );
            }
        }
        if approved {
            Decision::Approve
        } else {
            Decision::Deny
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::confirm::PeerInfo;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn stub(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("osascript-stub");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn ctx() -> ConfirmContext {
        ConfirmContext {
            key_name: "osa test".into(),
            fingerprint: "SHA256:osa".into(),
            item_id: "1".into(),
            peer: None,
            bindings: Vec::new(),
        }
    }

    fn confirmer(dir: &Path, body: &str) -> OsascriptConfirmer {
        OsascriptConfirmer::with_program(
            stub(dir, body),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
    }

    #[tokio::test]
    async fn allow_button_approves() {
        let dir = tempfile::tempdir().unwrap();
        let c = confirmer(dir.path(), "echo 'button returned:Allow'");
        assert_eq!(c.confirm(&ctx()).await, Decision::Approve);
    }

    #[tokio::test]
    async fn deny_button_denies() {
        // osascript exits 1 with "User canceled" when Deny (cancel button) is hit
        let dir = tempfile::tempdir().unwrap();
        let c = confirmer(
            dir.path(),
            "echo 'execution error: User canceled. (-128)' >&2; exit 1",
        );
        assert_eq!(c.confirm(&ctx()).await, Decision::Deny);
    }

    #[tokio::test]
    async fn exit_zero_without_allow_button_denies() {
        let dir = tempfile::tempdir().unwrap();
        let c = confirmer(dir.path(), "echo 'button returned:'");
        assert_eq!(c.confirm(&ctx()).await, Decision::Deny);
    }

    #[tokio::test]
    async fn expired_dialog_denies_despite_exit_zero() {
        let dir = tempfile::tempdir().unwrap();
        let c = confirmer(dir.path(), "echo 'button returned:Allow, gave up:true'");
        assert_eq!(c.confirm(&ctx()).await, Decision::Deny);
    }

    #[tokio::test]
    async fn no_gui_session_denies() {
        let dir = tempfile::tempdir().unwrap();
        let c = confirmer(
            dir.path(),
            "echo 'execution error: No user interaction allowed. (-1713)' >&2; exit 1",
        );
        assert_eq!(c.confirm(&ctx()).await, Decision::Deny);
    }

    #[tokio::test]
    async fn missing_osascript_denies() {
        let c = OsascriptConfirmer::with_program(
            PathBuf::from("/nonexistent/osascript"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        assert_eq!(c.confirm(&ctx()).await, Decision::Deny);
    }

    #[tokio::test]
    async fn wedged_dialog_is_killed_and_denied() {
        let dir = tempfile::tempdir().unwrap();
        let c = OsascriptConfirmer::with_program(
            stub(dir.path(), "sleep 30"),
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        let start = std::time::Instant::now();
        assert_eq!(c.confirm(&ctx()).await, Decision::Deny);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn dialogs_do_not_stack() {
        // Two requests arrive at once. Without serialization both dialogs
        // are up together and a single click answers whichever is on top;
        // the second must not start until the first is done.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("order.txt");
        let confirmer = std::sync::Arc::new(OsascriptConfirmer::with_program(
            stub(
                dir.path(),
                &format!(
                    "printf 'open\\n' >> {log}; sleep 0.3; printf 'close\\n' >> {log}; \
                     echo 'button returned:Allow'",
                    log = log.display()
                ),
            ),
            Duration::from_secs(5),
            Duration::from_secs(5),
        ));

        let (a, b) = tokio::join!(
            {
                let c = confirmer.clone();
                async move { c.confirm(&ctx()).await }
            },
            {
                let c = confirmer.clone();
                async move { c.confirm(&ctx()).await }
            },
        );
        assert_eq!(a, Decision::Approve);
        assert_eq!(b, Decision::Approve);
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "open\nclose\nopen\nclose\n",
            "the second dialog opened before the first closed"
        );
    }

    #[tokio::test]
    async fn message_and_giveup_are_passed_as_argv() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("argv.txt");
        let c = OsascriptConfirmer::with_program(
            stub(
                dir.path(),
                // argv: -e SCRIPT message giveup
                &format!(
                    "printf '%s|%s' \"$3\" \"$4\" > {}; echo 'button returned:Allow'",
                    marker.display()
                ),
            ),
            Duration::from_secs(7),
            Duration::from_secs(5),
        );
        let mut context = ctx();
        context.peer = Some(PeerInfo {
            pid: Some(std::process::id().cast_signed()),
            uid: 501,
        });
        assert_eq!(c.confirm(&context).await, Decision::Approve);
        let recorded = std::fs::read_to_string(&marker).unwrap();
        let (message, give_up) = recorded.split_once('|').unwrap();
        assert!(message.contains("osa test"));
        assert!(message.contains("SHA256:osa"));
        assert_eq!(give_up, "7");
    }
}
