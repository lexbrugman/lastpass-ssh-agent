use std::process::Stdio;
use std::time::Duration;

use zeroize::Zeroizing;

use super::{PassphrasePrompt, PassphraseRequest, PromptError};

/// Native macOS passphrase dialog via `osascript`.
///
/// The dialog uses `with hidden answer`, so the passphrase is masked as it is
/// typed. Untrusted text (the key name comes from the vault) is passed as argv
/// to `on run argv` and never interpolated into `AppleScript` source.
///
/// Dialogs are shown one at a time: two identical-looking passphrase prompts
/// stacked on screen invite typing one key's passphrase into the other's
/// dialog.
pub struct OsascriptPrompt {
    timeout: Duration,
    /// Extra slack past the dialog's own give-up before we kill osascript.
    grace: Duration,
    program: std::path::PathBuf,
    serialize: tokio::sync::Mutex<()>,
}

/// Only the typed text is returned, rather than the whole `display dialog`
/// record. `osascript` renders a record as `button returned:OK, text
/// returned:secret`, which cannot be parsed back safely — a passphrase
/// containing `, ` would be indistinguishable from the field separator.
const DIALOG_SCRIPT: &str = r#"
on run argv
    set message to item 1 of argv
    set giveUp to (item 2 of argv) as integer
    tell application "System Events"
        activate
        set answer to display dialog message with title "lastpass-ssh-agent" ¬
            default answer "" with hidden answer ¬
            buttons {"Cancel", "Unlock"} default button "Unlock" ¬
            cancel button "Cancel" with icon caution giving up after giveUp
    end tell
    if gave up of answer then error "passphrase entry timed out" number -128
    return text returned of answer
end run
"#;

impl OsascriptPrompt {
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
impl PassphrasePrompt for OsascriptPrompt {
    async fn prompt(&self, request: &PassphraseRequest) -> Result<Zeroizing<Vec<u8>>, PromptError> {
        // One dialog on screen at a time; see the type's documentation.
        let _one_at_a_time = self.serialize.lock().await;

        let give_up = self.timeout.as_secs().max(1).to_string();
        let child = tokio::process::Command::new(&self.program)
            .arg("-e")
            .arg(DIALOG_SCRIPT)
            .arg(request.describe())
            .arg(&give_up)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
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
        let mut stderr_pipe = child.stderr.take().expect("stderr is piped");

        // The dialog prints the typed text on stdout, so it goes into capped
        // zeroizing storage rather than a plain Vec grown to fit — the same
        // reason the LastPass field reader is capped. Both pipes are read
        // concurrently: a full stderr would otherwise wedge osascript before
        // it closes stdout.
        let io = async {
            let (secret, diagnostics) = tokio::try_join!(
                super::read_secret(&mut stdout_pipe),
                super::read_diagnostics(&mut stderr_pipe)
            )?;
            let status = super::reap(&mut child).await?;
            Ok::<_, PromptError>((secret, diagnostics, status))
        };

        // osascript enforces the give-up itself; add slack, then kill.
        let Ok(finished) = tokio::time::timeout(self.timeout + self.grace, io).await else {
            tracing::warn!("passphrase dialog wedged");
            return Err(PromptError::Cancelled);
        };
        let (mut secret, diagnostics, status) = finished?;

        if !status.success() {
            // AppleScript error text describes the script and the dismissal,
            // never what was typed into the dialog.
            let stderr = String::from_utf8_lossy(&diagnostics);
            // -1713: no GUI session to draw on (e.g. SSH'd into this machine).
            // Reported as unavailable so the user is pointed at a transport
            // that can work headless, rather than told they cancelled.
            if stderr.contains("No user interaction allowed") {
                return Err(PromptError::Unavailable(
                    "no GUI session for the passphrase dialog — use confirm = \"tty\" or \
                     \"askpass\" in headless setups"
                        .into(),
                ));
            }
            // -128 covers both the Cancel button and our own give-up error.
            if stderr.contains("User canceled") || stderr.contains("passphrase entry timed out") {
                return Err(PromptError::Cancelled);
            }
            return Err(PromptError::Unavailable(format!(
                "osascript exited with {}: {}",
                status,
                crate::text::escape_for_display(stderr.trim())
            )));
        }

        // `return` of a string prints it with a trailing newline, and a
        // single-line dialog field cannot contain one, so exactly one is ours
        // to remove.
        super::strip_line_ending(&mut secret);
        Ok(secret)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Stand-in for osascript: a shell script that ignores the `AppleScript`
    /// arguments and produces whatever the test needs.
    fn stub(dir: &Path, body: &str) -> PathBuf {
        crate::testutil::write_script(dir, "osascript", body)
    }

    fn prompt_with(dir: &Path, body: &str) -> OsascriptPrompt {
        OsascriptPrompt::with_program(
            stub(dir, body),
            Duration::from_secs(5),
            Duration::from_millis(200),
        )
    }

    fn request() -> PassphraseRequest {
        PassphraseRequest {
            key_name: "dialog key".into(),
            fingerprint: "SHA256:dlg".into(),
            item_id: "3".into(),
        }
    }

    #[tokio::test]
    async fn the_typed_text_comes_back_without_its_newline() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = prompt_with(dir.path(), "echo 'dialog secret'");
        assert_eq!(&*prompt.prompt(&request()).await.unwrap(), b"dialog secret");
    }

    #[tokio::test]
    async fn a_passphrase_containing_the_record_separator_survives() {
        // The reason the script returns only `text returned`: parsing a whole
        // dialog record would cut this passphrase in half.
        let dir = tempfile::tempdir().unwrap();
        let prompt = prompt_with(dir.path(), "echo 'a, text returned:b'");
        assert_eq!(
            &*prompt.prompt(&request()).await.unwrap(),
            b"a, text returned:b"
        );
    }

    #[tokio::test]
    async fn the_cancel_button_is_a_cancellation() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = prompt_with(
            dir.path(),
            "echo 'execution error: User canceled. (-128)' >&2; exit 1",
        );
        assert_eq!(
            prompt.prompt(&request()).await.unwrap_err(),
            PromptError::Cancelled
        );
    }

    #[tokio::test]
    async fn giving_up_is_a_cancellation_too() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = prompt_with(
            dir.path(),
            "echo 'execution error: passphrase entry timed out (-128)' >&2; exit 1",
        );
        assert_eq!(
            prompt.prompt(&request()).await.unwrap_err(),
            PromptError::Cancelled
        );
    }

    #[tokio::test]
    async fn no_gui_session_says_the_prompt_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = prompt_with(
            dir.path(),
            "echo 'execution error: No user interaction allowed. (-1713)' >&2; exit 1",
        );
        let error = prompt.prompt(&request()).await.unwrap_err();
        let PromptError::Unavailable(why) = error else {
            panic!("expected unavailable, got {error:?}");
        };
        assert!(why.contains("headless"), "{why}");
    }

    #[tokio::test]
    async fn any_other_failure_is_unavailable_with_the_reason_neutralized() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = prompt_with(dir.path(), "printf 'boom\\x1b[2J' >&2; exit 3");
        let error = prompt.prompt(&request()).await.unwrap_err();
        let PromptError::Unavailable(why) = error else {
            panic!("expected unavailable, got {error:?}");
        };
        assert!(why.contains("boom"), "{why}");
        // the reason is logged and displayed, so control characters from a
        // failing helper must not survive into it
        assert!(!why.contains('\x1b'), "{why}");
    }

    #[tokio::test]
    async fn a_wedged_dialog_is_killed_and_reported_as_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = OsascriptPrompt::with_program(
            stub(dir.path(), "sleep 30"),
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        let start = std::time::Instant::now();
        assert_eq!(
            prompt.prompt(&request()).await.unwrap_err(),
            PromptError::Cancelled
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn an_oversized_answer_is_refused_rather_than_buffered() {
        // The dialog's answer goes into a buffer allocated once, so anything
        // past the cap is refused instead of growing it.
        let dir = tempfile::tempdir().unwrap();
        let prompt = prompt_with(dir.path(), "yes doubtful | head -c 20000");
        assert!(
            matches!(
                prompt.prompt(&request()).await.unwrap_err(),
                PromptError::TooLong(_)
            ),
            "an oversized answer must be refused"
        );
    }

    #[tokio::test]
    async fn a_missing_osascript_reports_no_prompt_available() {
        let prompt = OsascriptPrompt::with_program(
            PathBuf::from("/nonexistent/osascript"),
            Duration::from_secs(1),
            Duration::from_millis(100),
        );
        let error = prompt.prompt(&request()).await.unwrap_err();
        assert!(matches!(error, PromptError::Unavailable(_)), "{error:?}");
    }

    #[tokio::test]
    async fn untrusted_text_reaches_the_dialog_as_data_not_script() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("argv.txt");
        let prompt = prompt_with(
            dir.path(),
            &format!(
                "printf '%s|%s' \"$3\" \"$4\" > {}; echo s",
                marker.display()
            ),
        );
        prompt.prompt(&request()).await.unwrap();
        let argv = std::fs::read_to_string(&marker).unwrap();
        let (message, give_up) = argv.split_once('|').unwrap();
        assert!(message.contains("dialog key"), "{message}");
        assert_eq!(give_up, "5");
    }
}
