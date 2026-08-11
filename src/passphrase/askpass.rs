use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use zeroize::Zeroizing;

use super::{PassphrasePrompt, PassphraseRequest, PromptError};

/// External helper following the `SSH_ASKPASS` convention in its *password*
/// mode: the prompt is the single argument, the secret comes back on stdout,
/// and a nonzero exit means the user dismissed it.
///
/// The confirmation path deliberately sets `SSH_ASKPASS_PROMPT=confirm` to get
/// a yes/no dialog. Here the opposite is wanted, so it is left unset — that is
/// what makes an OpenSSH-compatible helper mask what is typed.
pub struct AskpassPrompt {
    program: PathBuf,
    timeout: Duration,
}

impl AskpassPrompt {
    pub const fn new(program: PathBuf, timeout: Duration) -> Self {
        Self { program, timeout }
    }
}

#[async_trait::async_trait]
impl PassphrasePrompt for AskpassPrompt {
    async fn prompt(&self, request: &PassphraseRequest) -> Result<Zeroizing<Vec<u8>>, PromptError> {
        let child = tokio::process::Command::new(&self.program)
            .arg(request.describe())
            // Removed rather than merely left unset: inheriting
            // `SSH_ASKPASS_PROMPT=confirm` from our own environment would put
            // a compatible helper into yes/no mode, where it returns no
            // secret at all and every prompted signature fails. The
            // confirmation path sets exactly that value on purpose.
            .env_remove("SSH_ASKPASS_PROMPT")
            // stdin closed: a helper must not be able to wait on input that
            // will never arrive, and the secret travels the other way.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(e) => {
                return Err(PromptError::Unavailable(format!(
                    "cannot spawn {}: {e}",
                    self.program.display()
                )))
            }
        };
        let mut stdout_pipe = child.stdout.take().expect("stdout is piped");

        // Read the answer into capped zeroizing storage rather than letting
        // `wait_with_output` collect it: the helper is whatever program the
        // config names, so its output is neither trusted to be small nor
        // something to buffer in a plain growing Vec. A timeout that drops
        // this future still wipes whatever had arrived.
        let io = async {
            let secret = super::read_secret(&mut stdout_pipe).await?;
            let status = super::reap(&mut child).await?;
            Ok::<_, PromptError>((secret, status))
        };
        // kill_on_drop: any exit path from here SIGKILLs the helper.
        let Ok(finished) = tokio::time::timeout(self.timeout, io).await else {
            tracing::info!("askpass passphrase helper timed out");
            return Err(PromptError::Cancelled);
        };
        let (mut secret, status) = finished?;

        if !status.success() {
            // A helper killed by a signal did not ask anyone anything, so
            // saying "cancelled" would blame the user for a crash. Only an
            // ordinary nonzero exit means dismissal — that is what the
            // SSH_ASKPASS convention uses to report one.
            use std::os::unix::process::ExitStatusExt as _;
            if let Some(signal) = status.signal() {
                return Err(PromptError::Unavailable(format!(
                    "{} was killed by signal {signal}",
                    self.program.display()
                )));
            }
            return Err(PromptError::Cancelled);
        }
        super::strip_line_ending(&mut secret);
        Ok(secret)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn helper(dir: &std::path::Path, body: &str) -> PathBuf {
        crate::testutil::write_script(dir, "askpass", body)
    }

    fn request() -> PassphraseRequest {
        PassphraseRequest {
            key_name: "askpass key".into(),
            fingerprint: "SHA256:apk".into(),
            item_id: "7".into(),
        }
    }

    #[tokio::test]
    async fn stdout_is_the_passphrase_with_its_newline_stripped() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = AskpassPrompt::new(
            helper(dir.path(), "echo 'typed secret'"),
            Duration::from_secs(5),
        );
        let secret = prompt.prompt(&request()).await.unwrap();
        assert_eq!(&*secret, b"typed secret");
    }

    #[tokio::test]
    async fn a_crlf_helper_does_not_leak_the_carriage_return() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = AskpassPrompt::new(
            helper(dir.path(), "printf 'secret\\r\\n'"),
            Duration::from_secs(5),
        );
        assert_eq!(&*prompt.prompt(&request()).await.unwrap(), b"secret");
    }

    #[tokio::test]
    async fn a_helper_that_prints_no_newline_is_taken_as_is() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = AskpassPrompt::new(
            helper(dir.path(), "printf 'no trailing newline'"),
            Duration::from_secs(5),
        );
        assert_eq!(
            &*prompt.prompt(&request()).await.unwrap(),
            b"no trailing newline"
        );
    }

    #[tokio::test]
    async fn a_passphrase_with_inner_spaces_survives() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = AskpassPrompt::new(
            helper(dir.path(), "printf 'two words \\n'"),
            Duration::from_secs(5),
        );
        assert_eq!(&*prompt.prompt(&request()).await.unwrap(), b"two words ");
    }

    #[tokio::test]
    async fn a_dismissed_helper_is_a_cancellation_not_an_empty_answer() {
        let dir = tempfile::tempdir().unwrap();
        // prints something and still fails: the exit status decides
        let prompt = AskpassPrompt::new(
            helper(dir.path(), "echo ignored; exit 1"),
            Duration::from_secs(5),
        );
        assert_eq!(
            prompt.prompt(&request()).await.unwrap_err(),
            PromptError::Cancelled
        );
    }

    #[tokio::test]
    async fn the_helper_is_asked_for_a_password_not_a_confirmation() {
        // With SSH_ASKPASS_PROMPT=confirm an OpenSSH helper shows a yes/no
        // dialog and returns no secret at all. The helper must see it unset
        // even if our own environment has it — that case is not exercised
        // here, because setting it would mean mutating this process's
        // environment while other tests read it.
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("mode.txt");
        let prompt = AskpassPrompt::new(
            helper(
                dir.path(),
                &format!(
                    "printf '[%s]' \"$SSH_ASKPASS_PROMPT\" > {}; echo secret",
                    marker.display()
                ),
            ),
            Duration::from_secs(5),
        );
        prompt.prompt(&request()).await.unwrap();
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "[]");
    }

    #[tokio::test]
    async fn the_prompt_argument_says_which_key_is_being_unlocked() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("prompt.txt");
        let prompt = AskpassPrompt::new(
            helper(
                dir.path(),
                &format!("printf '%s' \"$1\" > {}; echo s", marker.display()),
            ),
            Duration::from_secs(5),
        );
        prompt.prompt(&request()).await.unwrap();
        let shown = std::fs::read_to_string(&marker).unwrap();
        assert!(shown.contains("askpass key"), "{shown}");
        assert!(shown.contains("SHA256:apk"), "{shown}");
    }

    #[tokio::test]
    async fn a_hung_helper_times_out_as_a_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = AskpassPrompt::new(helper(dir.path(), "sleep 30"), Duration::from_millis(200));
        let start = std::time::Instant::now();
        assert_eq!(
            prompt.prompt(&request()).await.unwrap_err(),
            PromptError::Cancelled
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_crashed_helper_is_not_reported_as_a_cancellation() {
        // Nobody dismissed anything: the helper died, so the prompt was never
        // available. Calling that "cancelled" would blame the user.
        let dir = tempfile::tempdir().unwrap();
        let prompt = AskpassPrompt::new(helper(dir.path(), "kill -9 $$"), Duration::from_secs(5));
        let error = prompt.prompt(&request()).await.unwrap_err();
        let PromptError::Unavailable(why) = error else {
            panic!("expected unavailable, got {error:?}");
        };
        assert!(why.contains("signal 9"), "{why}");
    }

    #[tokio::test]
    async fn a_spewing_helper_is_refused_rather_than_buffered() {
        // The helper is whatever program the config names, so its output is
        // capped: an unbounded read would let a broken one exhaust memory
        // before the timeout fired.
        let dir = tempfile::tempdir().unwrap();
        let prompt = AskpassPrompt::new(
            helper(dir.path(), "yes doubtful | head -c 20000"),
            Duration::from_secs(10),
        );
        assert!(
            matches!(
                prompt.prompt(&request()).await.unwrap_err(),
                PromptError::TooLong(_)
            ),
            "an oversized answer must be refused"
        );
    }

    #[tokio::test]
    async fn a_missing_helper_reports_no_prompt_available() {
        let prompt = AskpassPrompt::new(
            PathBuf::from("/nonexistent/askpass"),
            Duration::from_secs(5),
        );
        let error = prompt.prompt(&request()).await.unwrap_err();
        assert!(matches!(error, PromptError::Unavailable(_)), "{error:?}");
    }
}
