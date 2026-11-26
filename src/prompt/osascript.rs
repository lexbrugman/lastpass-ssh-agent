use std::process::Stdio;
use std::time::Duration;

use zeroize::Zeroizing;

use super::{Failure, Transport};

/// Native macOS dialogs via `osascript`.
///
/// Untrusted text — a key name comes from the vault — reaches the dialog as
/// argv to `on run argv`, never interpolated into `AppleScript` source. The
/// dialog gives up after the deadline on its own, and the process is killed a
/// little later in case it wedges.
///
/// Dialogs are shown one at a time. Concurrent requests would otherwise stack
/// identical-looking dialogs, and answering the frontmost one would answer
/// whichever request happened to be on top rather than the one just read.
/// Each queued request gets its own dialog and its own full timeout once the
/// screen is free.
pub struct OsascriptTransport {
    timeout: Duration,
    /// Extra slack past the dialog's own give-up before we kill osascript.
    grace: Duration,
    program: std::path::PathBuf,
    /// The icon an ordinary confirmation wears, when the file is there.
    lock_icon: std::path::PathBuf,
    serialize: tokio::sync::Mutex<()>,
}

/// Fail-closed by construction: "Deny" is both the default and the cancel
/// button, so Escape, Enter on the default and the dialog expiring all deny.
///
/// The caution icon is kept for the request that warrants it. Shown on every
/// dialog it says nothing, and a forwarded request looks like any other. The
/// rest wear the system's padlock — named by its file, since the `note` icon
/// is the icon of the application drawing the dialog and System Events has
/// none — or no icon at all where that file is not to be found.
///
/// The file reference is made outside the `tell`: inside one, `POSIX file` is
/// the application's to interpret.
const CONFIRM_SCRIPT: &str = r#"
on run argv
    set message to item 1 of argv
    set giveUp to (item 2 of argv) as integer
    set iconKind to item 3 of argv
    if iconKind is "lock" then set lockIcon to POSIX file (item 4 of argv)
    tell application "System Events"
        activate
        if iconKind is "caution" then
            set answer to display dialog message with title "lastpass-ssh-agent" ¬
                buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" ¬
                with icon caution giving up after giveUp
        else if iconKind is "lock" then
            set answer to display dialog message with title "lastpass-ssh-agent" ¬
                buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" ¬
                with icon lockIcon giving up after giveUp
        else
            set answer to display dialog message with title "lastpass-ssh-agent" ¬
                buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" ¬
                giving up after giveUp
        end if
    end tell
    return answer
end run
"#;

/// The padlock macOS ships among its own icons.
const LOCK_ICON: &str =
    "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/LockedIcon.icns";

/// `with hidden answer` masks the passphrase as it is typed. Returns only the
/// typed text, not the whole `display dialog` record: `osascript` renders a
/// record as `button returned:OK, text returned:secret`, which cannot be
/// parsed back — a passphrase containing `, ` would be indistinguishable from
/// the separator.
const SECRET_SCRIPT: &str = r#"
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

/// What one dialog came back with.
struct Shown {
    /// What the script returned: a button record, or the typed text.
    stdout: Zeroizing<Vec<u8>>,
    /// `AppleScript`'s error text, which describes the script and the dismissal
    /// and never what was typed into the dialog. Escaped and cut for a log.
    stderr: String,
    status: std::process::ExitStatus,
}

impl OsascriptTransport {
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
            lock_icon: LOCK_ICON.into(),
            serialize: tokio::sync::Mutex::new(()),
        }
    }

    /// Tests say where the padlock is, or that there is none.
    #[cfg(test)]
    #[must_use]
    fn with_lock_icon(mut self, lock_icon: std::path::PathBuf) -> Self {
        self.lock_icon = lock_icon;
        self
    }

    /// Which icon a confirmation wears; see `CONFIRM_SCRIPT`.
    fn icon(&self, caution: bool) -> &'static str {
        if caution {
            "caution"
        } else if self.lock_icon.is_file() {
            "lock"
        } else {
            "plain"
        }
    }

    /// Draw one dialog and collect what osascript said about it.
    async fn show(&self, script: &str, message: &str, icon: &str) -> Result<Shown, Failure> {
        let give_up = self.timeout.as_secs().max(1).to_string();
        let child = tokio::process::Command::new(&self.program)
            .arg("-e")
            .arg(script)
            .arg(message)
            .arg(&give_up)
            .arg(icon)
            .arg(&self.lock_icon)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn();
        let mut child = child.map_err(|e| {
            Failure::Unavailable(format!("cannot spawn {}: {e}", self.program.display()))
        })?;
        let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
        let mut stderr_pipe = child.stderr.take().expect("stderr is piped");

        // The dialog prints the typed text on stdout, so it goes into capped
        // zeroizing storage rather than a plain Vec grown to fit — the same
        // reason the LastPass field reader is capped. Both pipes are read
        // concurrently: a full stderr would otherwise wedge osascript before
        // it closes stdout.
        let io = async {
            let (stdout, diagnostics) = tokio::try_join!(
                super::read_secret(&mut stdout_pipe),
                super::read_diagnostics(&mut stderr_pipe)
            )?;
            let status = super::reap(&mut child).await?;
            Ok::<_, Failure>((stdout, diagnostics, status))
        };
        // osascript enforces the give-up itself; add slack, then kill.
        let Ok(finished) = tokio::time::timeout(self.timeout + self.grace, io).await else {
            tracing::warn!("the dialog wedged");
            return Err(Failure::TimedOut);
        };
        let (stdout, diagnostics, status) = finished?;
        Ok(Shown {
            stdout,
            stderr: crate::text::diagnostics_for_display(&diagnostics),
            status,
        })
    }
}

#[async_trait::async_trait]
impl Transport for OsascriptTransport {
    async fn ask_to_confirm(&self, message: &str, caution: bool) -> Result<bool, Failure> {
        // One dialog on screen at a time; see the type's documentation.
        let _one_at_a_time = self.serialize.lock().await;
        let shown = self
            .show(CONFIRM_SCRIPT, message, self.icon(caution))
            .await?;
        let stdout = String::from_utf8_lossy(&shown.stdout);
        // "giving up after" returns success with `gave up:true` instead of a
        // nonzero exit — an expired dialog must not count as approval.
        if stdout.contains("gave up:true") {
            return Err(Failure::TimedOut);
        }
        if shown.status.success() {
            return Ok(stdout.contains("button returned:Allow"));
        }
        // Deny is the cancel button, which osascript reports as a cancellation.
        if shown.stderr.contains("User canceled") {
            return Ok(false);
        }
        // Not a refusal: nobody was asked. Most often the agent has no GUI
        // session to draw in, or its authorization to drive System Events has
        // lapsed — which macOS does when the binary is replaced, so an upgrade
        // without a restart lands here.
        Err(Failure::Unavailable(format!(
            "osascript exited with {}: {}",
            shown.status, shown.stderr
        )))
    }

    async fn ask_for_secret(&self, message: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Failure> {
        let _one_at_a_time = self.serialize.lock().await;
        let Shown {
            mut stdout,
            stderr,
            status,
        } = self.show(SECRET_SCRIPT, message, "caution").await?;
        if !status.success() {
            // -1713: no GUI session to draw on (e.g. SSH'd into this machine).
            // Reported as unavailable so the user is pointed at a transport
            // that can work headless, rather than told they cancelled.
            if stderr.contains("No user interaction allowed") {
                return Err(Failure::Unavailable(
                    "no GUI session for the passphrase dialog — use confirm = \"tty\" or \
                     \"askpass\" in headless setups"
                        .into(),
                ));
            }
            // Both arrive as -128: the Cancel button, and the script's own
            // error for the dialog giving up.
            if stderr.contains("User canceled") {
                return Ok(None);
            }
            if stderr.contains("passphrase entry timed out") {
                return Err(Failure::TimedOut);
            }
            return Err(Failure::Unavailable(format!(
                "osascript exited with {status}: {stderr}"
            )));
        }
        // `return` of a string prints it with a trailing newline, and a
        // single-line dialog field cannot contain one, so exactly one is ours
        // to remove.
        crate::text::strip_line_ending(&mut stdout);
        Ok(Some(stdout))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::path::{Path, PathBuf};

    fn transport(dir: &Path, body: &str) -> OsascriptTransport {
        OsascriptTransport::with_program(
            crate::testutil::osascript_stub(dir, body),
            Duration::from_secs(5),
            Duration::from_millis(200),
        )
    }

    #[tokio::test]
    async fn the_allow_button_is_a_yes() {
        let dir = tempfile::tempdir().unwrap();
        let t = transport(dir.path(), "echo 'button returned:Allow'");
        assert_eq!(t.ask_to_confirm("question", false).await, Ok(true));
    }

    #[tokio::test]
    async fn the_deny_button_is_a_no() {
        // osascript exits 1 with "User canceled" when Deny (cancel button) is hit
        let dir = tempfile::tempdir().unwrap();
        let t = transport(
            dir.path(),
            "echo 'execution error: User canceled. (-128)' >&2; exit 1",
        );
        assert_eq!(t.ask_to_confirm("question", false).await, Ok(false));
    }

    #[tokio::test]
    async fn exit_zero_without_the_allow_button_is_a_no() {
        let dir = tempfile::tempdir().unwrap();
        let t = transport(dir.path(), "echo 'button returned:'");
        assert_eq!(t.ask_to_confirm("question", false).await, Ok(false));
    }

    #[tokio::test]
    async fn an_expired_dialog_is_a_timeout_despite_exit_zero() {
        let dir = tempfile::tempdir().unwrap();
        let t = transport(dir.path(), "echo 'button returned:Allow, gave up:true'");
        assert_eq!(
            t.ask_to_confirm("question", false).await,
            Err(Failure::TimedOut)
        );
    }

    #[tokio::test]
    async fn no_gui_session_is_unavailable_for_either_question() {
        let dir = tempfile::tempdir().unwrap();
        let t = transport(
            dir.path(),
            "echo 'execution error: No user interaction allowed. (-1713)' >&2; exit 1",
        );
        assert_matches!(
            t.ask_to_confirm("question", false).await,
            Err(Failure::Unavailable(_))
        );
        let error = t.ask_for_secret("key").await.unwrap_err();
        let Failure::Unavailable(why) = error else {
            panic!("expected unavailable, got {error:?}");
        };
        assert!(why.contains("headless"), "{why}");
    }

    #[tokio::test]
    async fn a_missing_osascript_is_unavailable_for_either_question() {
        let t = OsascriptTransport::with_program(
            PathBuf::from("/nonexistent/osascript"),
            Duration::from_secs(1),
            Duration::from_millis(100),
        );
        assert_matches!(
            t.ask_to_confirm("question", false).await,
            Err(Failure::Unavailable(_))
        );
        assert_matches!(t.ask_for_secret("key").await, Err(Failure::Unavailable(_)));
    }

    #[tokio::test]
    async fn a_wedged_dialog_is_killed_and_is_a_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let t = OsascriptTransport::with_program(
            crate::testutil::osascript_stub(dir.path(), "sleep 30"),
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        let start = std::time::Instant::now();
        assert_eq!(
            t.ask_to_confirm("question", false).await,
            Err(Failure::TimedOut)
        );
        assert_eq!(t.ask_for_secret("key").await, Err(Failure::TimedOut));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn dialogs_do_not_stack() {
        // Two requests arrive at once. Without serialization both dialogs
        // are up together and a single click answers whichever is on top;
        // the second must not start until the first is done.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("order.txt");
        let t = std::sync::Arc::new(transport(
            dir.path(),
            &format!(
                "printf 'open\\n' >> {log}; sleep 0.3; printf 'close\\n' >> {log}; \
                 echo 'button returned:Allow'",
                log = log.display()
            ),
        ));

        let (a, b) = tokio::join!(
            {
                let t = t.clone();
                async move { t.ask_to_confirm("question", false).await }
            },
            {
                let t = t.clone();
                async move { t.ask_to_confirm("question", false).await }
            },
        );
        assert_eq!(a, Ok(true));
        assert_eq!(b, Ok(true));
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "open\nclose\nopen\nclose\n",
            "the second dialog opened before the first closed"
        );
    }

    #[tokio::test]
    async fn the_message_and_the_give_up_are_passed_as_argv() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("argv.txt");
        let t = OsascriptTransport::with_program(
            crate::testutil::osascript_stub(
                dir.path(),
                // argv: -e SCRIPT message giveup icon
                &format!(
                    "printf '%s|%s|%s' \"$3\" \"$4\" \"$5\" > {}; echo 'button returned:Allow'",
                    marker.display()
                ),
            ),
            Duration::from_secs(7),
            Duration::from_millis(200),
        );
        // no padlock where this looks for one, so no icon
        let t = t.with_lock_icon(dir.path().join("absent.icns"));
        assert_eq!(t.ask_to_confirm("approve this?", false).await, Ok(true));
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "approve this?|7|plain"
        );
        // and with one, an ordinary question wears it
        let padlock = dir.path().join("padlock.icns");
        std::fs::write(&padlock, b"icon").unwrap();
        let t = t.with_lock_icon(padlock);
        assert_eq!(t.ask_to_confirm("approve this?", false).await, Ok(true));
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "approve this?|7|lock"
        );
        // only a question to stop at wears the caution icon
        assert_eq!(t.ask_to_confirm("stop and read", true).await, Ok(true));
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "stop and read|7|caution"
        );
        t.ask_for_secret("unlock that").await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "unlock that|7|caution"
        );
    }

    /// Shared body, so each case below is one line and still named.
    async fn expect_answer(printed: &str, expected: &str) {
        let dir = tempfile::tempdir().unwrap();
        let secret = transport(dir.path(), printed)
            .ask_for_secret("key")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&secret),
            expected,
            "stub ran `{printed}`"
        );
    }

    #[tokio::test]
    async fn the_typed_text_comes_back_without_its_newline() {
        expect_answer("echo 'dialog secret'", "dialog secret").await;
    }

    #[tokio::test]
    async fn a_passphrase_containing_the_record_separator_survives() {
        // The reason the script returns only `text returned`: parsing a whole
        // dialog record would cut this passphrase in half.
        expect_answer("echo 'a, text returned:b'", "a, text returned:b").await;
    }

    #[tokio::test]
    async fn spaces_around_a_passphrase_belong_to_it() {
        expect_answer("printf '  padded  \\n'", "  padded  ").await;
    }

    #[tokio::test]
    async fn the_cancel_button_is_a_dismissal() {
        let dir = tempfile::tempdir().unwrap();
        let t = transport(
            dir.path(),
            "echo 'execution error: User canceled. (-128)' >&2; exit 1",
        );
        assert_eq!(t.ask_for_secret("key").await, Ok(None));
    }

    #[tokio::test]
    async fn the_dialog_giving_up_is_a_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let t = transport(
            dir.path(),
            "echo 'execution error: passphrase entry timed out (-128)' >&2; exit 1",
        );
        assert_eq!(t.ask_for_secret("key").await, Err(Failure::TimedOut));
    }

    #[tokio::test]
    async fn any_other_failure_is_unavailable_with_the_reason_neutralized() {
        let dir = tempfile::tempdir().unwrap();
        let t = transport(dir.path(), "printf 'boom\\x1b[2J' >&2; exit 3");
        for error in [
            t.ask_for_secret("key").await.unwrap_err(),
            t.ask_to_confirm("question", false).await.unwrap_err(),
        ] {
            let Failure::Unavailable(why) = error else {
                panic!("expected unavailable, got {error:?}");
            };
            assert!(why.contains("boom"), "{why}");
            // the reason is logged and displayed, so control characters from
            // a failing helper must not survive into it
            assert!(!why.contains('\x1b'), "{why}");
        }
    }

    #[tokio::test]
    async fn an_oversized_answer_is_refused_rather_than_buffered() {
        // The dialog's answer goes into a buffer allocated once, so anything
        // past the cap is refused instead of growing it.
        let dir = tempfile::tempdir().unwrap();
        let t = transport(dir.path(), "yes doubtful | head -c 20000");
        assert!(
            matches!(t.ask_for_secret("key").await, Err(Failure::TooLong(_))),
            "an oversized answer must be refused"
        );
    }
}
