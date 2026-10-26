use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use zeroize::Zeroizing;

use super::{Failure, Transport};

/// An external helper following the `SSH_ASKPASS` convention: the prompt is
/// the helper's single argument. A yes/no question runs it in confirm mode,
/// where exit status 0 is a yes. A secret runs it in its password mode, where
/// the secret comes back on stdout and a nonzero exit means the user
/// dismissed it.
pub struct AskpassTransport {
    program: PathBuf,
    timeout: Duration,
}

/// Which of the helper's two modes a run uses.
#[derive(Clone, Copy)]
enum Mode {
    Confirm,
    Secret,
}

impl AskpassTransport {
    pub const fn new(program: PathBuf, timeout: Duration) -> Self {
        Self { program, timeout }
    }

    fn spawn(&self, message: &str, mode: Mode) -> Result<tokio::process::Child, Failure> {
        let mut command = tokio::process::Command::new(&self.program);
        command
            .arg(message)
            // stdin closed: a helper must not be able to wait on input that
            // will never arrive, and an answer travels the other way.
            .stdin(Stdio::null())
            .kill_on_drop(true);
        match mode {
            // Without this an OpenSSH-compatible helper runs its password
            // prompt, which exits 0 on OK no matter what was typed — every
            // request would be approved. The exit code is the whole answer,
            // so neither pipe is read.
            Mode::Confirm => command
                .env("SSH_ASKPASS_PROMPT", "confirm")
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            // Removed rather than merely left unset: inheriting
            // `SSH_ASKPASS_PROMPT=confirm` from our own environment would put
            // a compatible helper into yes/no mode, where it returns no
            // secret at all and every prompted signature fails. stderr is
            // discarded, not read: the helper is whatever program the config
            // names, and one that echoes what was typed there would put a
            // passphrase in the log.
            Mode::Secret => command
                .env_remove("SSH_ASKPASS_PROMPT")
                .stdout(Stdio::piped())
                .stderr(Stdio::null()),
        };
        command.spawn().map_err(|e| {
            Failure::Unavailable(format!("cannot spawn {}: {e}", self.program.display()))
        })
    }
}

#[async_trait::async_trait]
impl Transport for AskpassTransport {
    async fn ask_to_confirm(&self, message: &str) -> Result<bool, Failure> {
        let child = self.spawn(message, Mode::Confirm)?;
        let output = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| Failure::TimedOut)?
            .map_err(super::helper_failed)?;
        if output.status.success() {
            return Ok(true);
        }
        // The convention gives one channel for both, so this cannot tell a
        // refusal from a helper that failed to ask — the exit code is all
        // there is, and it is worth logging.
        tracing::info!(code = ?output.status.code(), "askpass helper did not approve");
        Ok(false)
    }

    async fn ask_for_secret(&self, message: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Failure> {
        let mut child = self.spawn(message, Mode::Secret)?;
        let mut stdout_pipe = child.stdout.take().expect("stdout is piped");

        // Read the answer into capped zeroizing storage rather than letting
        // `wait_with_output` collect it: the helper is whatever program the
        // config names, so its output is neither trusted to be small nor
        // something to buffer in a plain growing Vec. A timeout that drops
        // this future still wipes whatever had arrived.
        let io = async {
            let secret = super::read_secret(&mut stdout_pipe).await?;
            let status = super::reap(&mut child).await?;
            Ok::<_, Failure>((secret, status))
        };
        // kill_on_drop: any exit path from here SIGKILLs the helper.
        let Ok(finished) = tokio::time::timeout(self.timeout, io).await else {
            return Err(Failure::TimedOut);
        };
        let (mut secret, status) = finished?;

        if !status.success() {
            // A helper killed by a signal did not ask anyone anything, so
            // saying "dismissed" would blame the user for a crash. Only an
            // ordinary nonzero exit means dismissal — that is what the
            // convention uses to report one.
            use std::os::unix::process::ExitStatusExt as _;
            if let Some(signal) = status.signal() {
                return Err(Failure::Unavailable(format!(
                    "{} was killed by signal {signal}",
                    self.program.display()
                )));
            }
            // A helper that could not ask — no display, no toolkit — exits
            // the same way, and the convention leaves no channel to tell the
            // two apart that is safe to read. The exit code is all there is.
            tracing::info!(code = ?status.code(), "askpass helper returned no secret");
            return Ok(None);
        }
        super::strip_line_ending(&mut secret);
        Ok(Some(secret))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn helper(dir: &std::path::Path, body: &str) -> PathBuf {
        crate::testutil::write_script(dir, "askpass", body)
    }

    fn transport(dir: &std::path::Path, body: &str) -> AskpassTransport {
        AskpassTransport::new(helper(dir, body), Duration::from_secs(5))
    }

    #[tokio::test]
    async fn exit_zero_is_a_yes() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            transport(dir.path(), "exit 0")
                .ask_to_confirm("question")
                .await,
            Ok(true)
        );
    }

    #[tokio::test]
    async fn a_nonzero_exit_is_a_no() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            transport(dir.path(), "exit 1")
                .ask_to_confirm("question")
                .await,
            Ok(false)
        );
    }

    #[tokio::test]
    async fn a_question_puts_the_helper_in_confirm_mode_and_a_secret_does_not() {
        // With SSH_ASKPASS_PROMPT=confirm an OpenSSH helper shows a yes/no
        // dialog and returns no secret at all; without it, a password field
        // that exits 0 whatever was typed. Each question needs the other's
        // mode ruled out. A value already in our own environment is not
        // exercised here, because setting it would mean mutating this
        // process's environment while other tests read it.
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("mode.txt");
        let t = transport(
            dir.path(),
            &format!(
                "printf '[%s]' \"$SSH_ASKPASS_PROMPT\" > {}; echo secret",
                marker.display()
            ),
        );
        t.ask_to_confirm("question").await.unwrap();
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "[confirm]");
        t.ask_for_secret("key").await.unwrap();
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "[]");
    }

    #[tokio::test]
    async fn the_message_is_the_helpers_argument_for_either_question() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("prompt.txt");
        let t = transport(
            dir.path(),
            &format!("printf '%s' \"$1\" > {}; echo s", marker.display()),
        );
        t.ask_to_confirm("approve this?").await.unwrap();
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "approve this?");
        t.ask_for_secret("unlock that").await.unwrap();
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "unlock that");
    }

    #[tokio::test]
    async fn a_hung_helper_times_out_for_either_question() {
        let dir = tempfile::tempdir().unwrap();
        let t = AskpassTransport::new(helper(dir.path(), "sleep 30"), Duration::from_millis(200));
        let start = std::time::Instant::now();
        assert_eq!(t.ask_to_confirm("question").await, Err(Failure::TimedOut));
        assert_eq!(t.ask_for_secret("key").await, Err(Failure::TimedOut));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_missing_helper_is_unavailable_for_either_question() {
        let t = AskpassTransport::new(
            PathBuf::from("/nonexistent/askpass"),
            Duration::from_secs(5),
        );
        assert!(matches!(
            t.ask_to_confirm("question").await,
            Err(Failure::Unavailable(_))
        ));
        assert!(matches!(
            t.ask_for_secret("key").await,
            Err(Failure::Unavailable(_))
        ));
    }

    /// Shared body for the answer-framing cases, so each stays one line and
    /// still gets its own name in the test output.
    async fn expect_answer(printed: &str, expected: &[u8]) {
        let dir = tempfile::tempdir().unwrap();
        let secret = transport(dir.path(), printed)
            .ask_for_secret("key")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            &*secret,
            expected,
            "helper ran `{printed}`, got {:?}",
            String::from_utf8_lossy(&secret)
        );
    }

    #[tokio::test]
    async fn the_trailing_newline_is_framing_not_passphrase() {
        expect_answer("echo 'typed secret'", b"typed secret").await;
    }

    #[tokio::test]
    async fn a_crlf_helper_does_not_leak_the_carriage_return() {
        expect_answer("printf 'secret\\r\\n'", b"secret").await;
    }

    #[tokio::test]
    async fn a_helper_that_prints_no_newline_is_taken_as_is() {
        expect_answer("printf 'no trailing newline'", b"no trailing newline").await;
    }

    #[tokio::test]
    async fn spaces_around_a_passphrase_belong_to_it() {
        expect_answer("printf 'two words \\n'", b"two words ").await;
    }

    #[tokio::test]
    async fn only_one_line_ending_is_ever_removed() {
        expect_answer("printf 'secret\\n\\n'", b"secret\n").await;
    }

    #[tokio::test]
    async fn a_dismissed_helper_is_a_dismissal_not_an_empty_answer() {
        // prints something and still fails: the exit status decides
        let dir = tempfile::tempdir().unwrap();
        let t = transport(dir.path(), "echo ignored; exit 1");
        assert_eq!(t.ask_for_secret("key").await, Ok(None));
    }

    #[tokio::test]
    async fn a_crashed_helper_is_not_reported_as_a_dismissal() {
        // Nobody dismissed anything: the helper died, so the prompt was never
        // available. Calling that a dismissal would blame the user.
        let dir = tempfile::tempdir().unwrap();
        let error = transport(dir.path(), "kill -9 $$")
            .ask_for_secret("key")
            .await
            .unwrap_err();
        let Failure::Unavailable(why) = error else {
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
        let t = AskpassTransport::new(
            helper(dir.path(), "yes doubtful | head -c 20000"),
            Duration::from_secs(10),
        );
        assert!(
            matches!(t.ask_for_secret("key").await, Err(Failure::TooLong(_))),
            "an oversized answer must be refused"
        );
    }
}
