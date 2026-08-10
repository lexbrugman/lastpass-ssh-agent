use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use super::{ConfirmContext, Confirmer, Decision};

/// External helper following the `SSH_ASKPASS` convention: the prompt is
/// passed as the single argument, exit status 0 means approve, anything
/// else (or a timeout, or a spawn failure) denies.
pub struct AskpassConfirmer {
    program: PathBuf,
    timeout: Duration,
}

impl AskpassConfirmer {
    pub const fn new(program: PathBuf, timeout: Duration) -> Self {
        Self { program, timeout }
    }
}

#[async_trait::async_trait]
impl Confirmer for AskpassConfirmer {
    async fn confirm(&self, ctx: &ConfirmContext) -> Decision {
        let message = super::describe_request(ctx);
        let child = tokio::process::Command::new(&self.program)
            .arg(&message)
            // Without this an OpenSSH-compatible helper runs its password
            // prompt, which exits 0 on OK no matter what was typed — every
            // request would be approved. `confirm` demands a yes/no answer.
            .env("SSH_ASKPASS_PROMPT", "confirm")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let child = match child {
            Ok(child) => child,
            Err(e) => {
                tracing::warn!(program = %self.program.display(),
                    "cannot spawn askpass helper, denying: {e}");
                return Decision::Deny;
            }
        };
        match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(output)) if output.status.success() => Decision::Approve,
            Ok(Ok(_)) => Decision::Deny,
            Ok(Err(e)) => {
                tracing::warn!("askpass helper failed, denying: {e}");
                Decision::Deny
            }
            Err(_) => {
                tracing::info!("askpass helper timed out, denying");
                Decision::Deny
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::confirm::PeerInfo;
    use std::os::unix::fs::PermissionsExt;

    fn helper(dir: &std::path::Path, body: &str) -> PathBuf {
        let path = dir.join("askpass");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn ctx() -> ConfirmContext {
        ConfirmContext {
            key_name: "test key".into(),
            fingerprint: "SHA256:xxxx".into(),
            item_id: "1".into(),
            peer: Some(PeerInfo {
                pid: Some(4242),
                uid: 501,
            }),
            bindings: Vec::new(),
        }
    }

    #[tokio::test]
    async fn exit_zero_approves() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = AskpassConfirmer::new(helper(dir.path(), "exit 0"), Duration::from_secs(5));
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Approve);
    }

    #[tokio::test]
    async fn helpers_are_asked_for_confirmation_not_a_password() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("mode.txt");
        let confirmer = AskpassConfirmer::new(
            helper(
                dir.path(),
                &format!(
                    "printf '%s' \"$SSH_ASKPASS_PROMPT\" > {}; exit 0",
                    marker.display()
                ),
            ),
            Duration::from_secs(5),
        );
        confirmer.confirm(&ctx()).await;
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "confirm");
    }

    #[tokio::test]
    async fn nonzero_exit_denies() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = AskpassConfirmer::new(helper(dir.path(), "exit 1"), Duration::from_secs(5));
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Deny);
    }

    #[tokio::test]
    async fn hung_helper_times_out_to_deny() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer =
            AskpassConfirmer::new(helper(dir.path(), "sleep 30"), Duration::from_millis(200));
        let start = std::time::Instant::now();
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Deny);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn missing_helper_denies() {
        let confirmer = AskpassConfirmer::new(
            PathBuf::from("/nonexistent/askpass"),
            Duration::from_secs(5),
        );
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Deny);
    }

    #[tokio::test]
    async fn prompt_receives_request_description() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("prompt.txt");
        let confirmer = AskpassConfirmer::new(
            helper(
                dir.path(),
                &format!("printf '%s' \"$1\" > {}; exit 0", marker.display()),
            ),
            Duration::from_secs(5),
        );
        confirmer.confirm(&ctx()).await;
        let prompt = std::fs::read_to_string(&marker).unwrap();
        assert!(prompt.contains("test key"));
        assert!(prompt.contains("SHA256:xxxx"));
        assert!(prompt.contains("4242"));
    }
}
