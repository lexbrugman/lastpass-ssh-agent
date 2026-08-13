use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use zeroize::Zeroizing;

use super::{ItemSummary, LoginStatus, LpassClient, LpassError};

/// A `show` against the local vault cache takes 100–500 ms, but the first
/// one after a while can trigger a full vault sync, and on a slow link that
/// is the case that matters: failing a signature there costs the user a
/// retry, while waiting costs a pause. Still bounded, so a wedged lpass
/// cannot hang a signing request indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Real lpass subprocess client.
///
/// Secret handling: no shell is involved, secrets never appear in argv or
/// env in either direction, stdout is captured straight into a `Zeroizing`
/// buffer, and a hung lpass is killed after a timeout.
pub struct LpassCli {
    binary: PathBuf,
    timeout: Duration,
    /// This binary and the config it was started with, when lpass should ask
    /// for the master password rather than fail.
    askpass_helper: Option<(PathBuf, PathBuf)>,
    /// How long lpass should keep the key it derives, when the config says.
    vault_unlock_timeout: Option<u64>,
    /// Set once the helper has reported supplying a master password *from the
    /// store*, which is the only thing that verifies what is stored.
    master_password_from_store: std::sync::atomic::AtomicBool,
}

/// Set on the helper's environment to say which config to prompt from. Its
/// presence is what makes this binary a password prompt instead of an agent.
pub const ASKPASS_MARKER: &str = "LASTPASS_SSH_AGENT_ASKPASS_CONFIG";

/// Printed by the helper once it has handed a master password over, so the
/// agent can say so.
///
/// It travels on stderr because that is the only channel back: the helper is a
/// process `lpass` spawns, not one this agent can see, and its stdout is the
/// password itself. A plain line rather than a log line — it is a signal to be
/// recognised, and formatting it twice would read as nonsense in the log.
pub const ASKPASS_SIGNAL: &str = "lastpass-ssh-agent: master password supplied";

/// Appended when the password came out of the store rather than from a prompt.
///
/// Setup needs the difference: if presence fails it falls back to asking, and a
/// correct answer typed there would otherwise certify a stored typo as working.
pub const ASKPASS_FROM_STORE: &str = " (from store)";

/// Names the file the helper touches once it has answered from the store.
///
/// Its path rather than its contents is what matters, and it holds nothing —
/// so it travels in the environment beside the config path, which the helper
/// already reads from there.
pub const ASKPASS_ONCE_MARKER: &str = "LASTPASS_SSH_AGENT_ASKPASS_ONCE";

/// A path unique to one `lpass` run, cleared at both ends by whoever owns it.
///
/// Not a lock and not a secret: it exists so a helper invoked twice by the same
/// `lpass` can tell the second time from the first. Removing it on `Drop` as
/// well as up front means every way out of `run` — including a timeout — leaves
/// nothing behind for the next invocation to trip over.
struct OnceMarker(Option<std::path::PathBuf>);

impl OnceMarker {
    /// Beside the askpass wrapper, which already lives in the agent's own
    /// directory. Named for this process and this call, so two runs at once
    /// cannot answer for each other.
    fn beside(helper: Option<&std::path::PathBuf>) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self(helper.map(|helper| {
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut name = helper.as_os_str().to_os_string();
            name.push(format!(".once.{}.{n}", std::process::id()));
            let path = std::path::PathBuf::from(name);
            let _ = std::fs::remove_file(&path);
            path
        }))
    }

    fn path(&self) -> Option<&std::path::Path> {
        self.0.as_deref()
    }
}

impl Drop for OnceMarker {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl LpassCli {
    pub const fn new(binary: PathBuf) -> Self {
        Self {
            binary,
            timeout: DEFAULT_TIMEOUT,
            askpass_helper: None,
            vault_unlock_timeout: None,
            master_password_from_store: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Ask lpass to forget its derived key after this many seconds.
    ///
    /// Passed on every invocation, because lpass reads it when it starts the
    /// agent that holds the key, and any call might be the one that does.
    #[must_use]
    pub const fn unlocked_for(mut self, seconds: Option<u64>) -> Self {
        self.vault_unlock_timeout = seconds;
        self
    }

    /// Let lpass ask for the master password by running `helper`, which is this
    /// binary, with the config the agent was started from.
    ///
    /// Only the long-running agent sets this, and nothing else can: `command`
    /// withholds an inherited one, so a helper named here is the only one lpass
    /// ever runs. A one-shot command has nowhere to put such a prompt anyway, so
    /// a locked vault fails there in lpass's own words — the right answer for a
    /// command that runs and exits.
    /// `prompt_timeout` is added to the command timeout, because the answer now
    /// arrives at human speed: without it a prompt left open longer than
    /// `DEFAULT_TIMEOUT` would kill the lpass call that opened it, and any
    /// `confirm_timeout_secs` above that could never be answered in time.
    /// `helper` is `None` when the agent was not asked to offer this, which is
    /// the default — taken here rather than branched on by the caller so that
    /// both answers live in one testable place.
    #[must_use]
    pub fn asking_with(
        mut self,
        helper: Option<PathBuf>,
        config: PathBuf,
        prompt_timeout: Duration,
    ) -> Self {
        let Some(helper) = helper else {
            return self;
        };
        self.askpass_helper = Some((helper, config));
        self.timeout = self.timeout.saturating_add(prompt_timeout);
        self
    }

    #[cfg(test)]
    pub const fn with_timeout(binary: PathBuf, timeout: Duration) -> Self {
        Self {
            binary,
            timeout,
            askpass_helper: None,
            vault_unlock_timeout: None,
            master_password_from_store: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn command(&self, args: &[&str], once: Option<&std::path::Path>) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.binary);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env_clear();
        // Allowlist, not blocklist: lpass needs HOME/XDG_* to find its
        // session and LPASS_* for user tuning; nothing else from our
        // environment should leak into it.
        for (key, value) in std::env::vars_os() {
            let name = key.to_string_lossy();
            // Withheld rather than forwarded, unlike every other `LPASS_`: lpass
            // consults it before `LPASS_DISABLE_PINENTRY` can rule a prompt out,
            // so an inherited one opens somebody else's prompt from inside a
            // fetch — outside the interaction gate, and against a timeout with
            // no allowance for a human. Only `askpass_helper` may name one,
            // which leaves `master_password` deciding whether this agent handles
            // that secret at all.
            if name.as_ref() == "LPASS_ASKPASS" {
                continue;
            }
            let pass = matches!(
                name.as_ref(),
                "HOME" | "PATH" | "TMPDIR" | "LANG" | "LC_ALL"
            ) || name.starts_with("LPASS_")
                || name.starts_with("XDG_");
            if pass {
                cmd.env(key, value);
            }
        }
        // Where lpass asks for the master password when its agent no longer
        // holds the derived key — which is the ordinary state after the screen
        // has locked. Pointed at this binary, so the question is put through
        // whichever prompt the config already selected for passphrases.
        //
        // Checked by lpass *before* LPASS_DISABLE_PINENTRY, so the two settings
        // are not in conflict: the fallback still applies when no helper can be
        // named, and then a missing key fails fast rather than blocking on a
        // prompt nobody can answer.
        if let Some((helper, config)) = &self.askpass_helper {
            cmd.env("LPASS_ASKPASS", helper);
            // lpass runs the helper as `<program> "<prompt>"`, with no way to
            // add an argument of our own, so what tells this binary to be the
            // helper rather than the agent travels beside it. It carries the
            // config path too: the helper has to reach for the same prompt the
            // agent was started with, and inherits no `--config`.
            cmd.env(ASKPASS_MARKER, config);
        }
        // Where the helper records that it has already handed the stored
        // password to *this* lpass. It asks again on a wrong password —
        // `agent.c` loops forever and discards the "incorrect" text before the
        // helper could ever see it — and the store would answer the same way
        // every time, so without this the only end is our timeout, a
        // fingerprint per turn until then.
        //
        // Outside the `askpass_helper` block rather than inside it: there is
        // a marker exactly when there is a helper, so nesting it would leave an
        // arm no test on any platform could reach.
        if let Some(once) = once {
            cmd.env(ASKPASS_ONCE_MARKER, once);
        }
        if let Some(seconds) = self.vault_unlock_timeout {
            cmd.env("LPASS_AGENT_TIMEOUT", seconds.to_string());
        }
        // Never let lpass block on an interactive master-password prompt
        // from inside the agent; with stdin closed this makes it fail fast
        // and we surface "run lpass login" instead.
        cmd.env("LPASS_DISABLE_PINENTRY", "1");
        cmd
    }

    async fn run(&self, args: &[&str], max_bytes: usize) -> Result<CmdOutput, LpassError> {
        // Cleared before the run as well as after it, so a marker some earlier
        // crash left behind cannot make this invocation skip the store.
        let once = OnceMarker::beside(self.askpass_helper.as_ref().map(|(helper, _)| helper));
        let mut child = self
            .command(args, once.path())
            .spawn()
            .map_err(LpassError::Spawn)?;
        let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
        let mut stderr_pipe = child.stderr.take().expect("stderr is piped");

        // Read both pipes concurrently — a full stderr pipe would otherwise
        // wedge lpass before it closes stdout — and only then reap. stdout
        // goes straight into zeroizing storage, so a timeout that drops this
        // future still wipes whatever key material had arrived. try_join
        // abandons the other reader (and skips the reap) the moment one
        // fails, so a still-spewing child can never hold us here.
        let io = async {
            let (stdout, stderr) =
                tokio::try_join!(read_output(&mut stdout_pipe, max_bytes), async {
                    read_diagnostics(&mut stderr_pipe)
                        .await
                        .map_err(LpassError::Spawn)
                })?;
            let status = child.wait().await.map_err(LpassError::Spawn)?;
            Ok::<_, LpassError>((stdout, stderr, status))
        };
        // kill_on_drop: dropping the child SIGKILLs lpass on any exit path.
        let (stdout, stderr, status) = tokio::time::timeout(self.timeout, io)
            .await
            .map_err(|_| LpassError::Timeout(self.timeout))??;

        // lpass terminates the value with exactly one newline. Strip that
        // one (and a preceding CR), never more: a passphrase legitimately
        // ending in a newline must survive intact, and `--field` gives no
        // framing that would let us tell the two apart otherwise.
        let mut stdout = stdout;
        if stdout.last() == Some(&b'\n') {
            stdout.pop();
            if stdout.last() == Some(&b'\r') {
                stdout.pop();
            }
        }
        let diagnostics = String::from_utf8_lossy(&stderr);
        // Looked for before `stderr` is truncated, not after: lpass can be
        // talkative, and a few hundred characters of its own warnings would
        // push the signal out of the window and lose the record entirely.
        //
        // The agent never sees the prompt itself — it happens inside a process
        // lpass spawned — so without this, the one moment it handles a master
        // password would pass unrecorded.
        if diagnostics.contains(ASKPASS_SIGNAL) {
            if diagnostics.contains(ASKPASS_FROM_STORE) {
                self.master_password_from_store
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            // Says only what is known here. The helper signals once it has
            // handed the password over, which is before lpass has judged it, so
            // claiming the vault reopened would announce a success that a typo
            // is about to turn into a failure.
            tracing::info!("a master password was supplied to lpass through this agent's prompt");
        }
        // Our own line, dropped before `classify` sees any of this: it would
        // otherwise spend part of the 300-character window, and pushing lpass's
        // own wording ("Not logged in") past the end would turn a diagnosis we
        // have into a generic failure.
        let stderr: String = diagnostics
            .lines()
            .filter(|line| !line.contains(ASKPASS_SIGNAL))
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .chars()
            .take(300)
            .collect();
        Ok(CmdOutput {
            success: status.success(),
            code: status.code(),
            stdout,
            stderr,
        })
    }

    fn classify(item_id: Option<&str>, out: &CmdOutput) -> LpassError {
        if out.stderr.contains("Could not find decryption key")
            || out.stderr.contains("Not logged in")
        {
            return LpassError::NotLoggedIn;
        }
        if let Some(id) = item_id {
            if out.stderr.contains("Could not find specified account") {
                return LpassError::ItemNotFound(id.to_string());
            }
            // lpass exits 1 with this when the item exists but lacks the
            // field — an ordinary answer for us, not a vault failure.
            if let Some(field) = out
                .stderr
                .split_once("Could not find specified field '")
                .and_then(|(_, rest)| rest.split_once('\''))
                .map(|(field, _)| field.to_string())
            {
                return LpassError::FieldNotFound {
                    item: id.to_string(),
                    field,
                };
            }
        }
        LpassError::CommandFailed {
            code: out.code,
            stderr: out.stderr.clone(),
        }
    }
}

/// No field lpass holds for us is remotely this large (a 16384-bit RSA key
/// is ~12 KiB), and the cap is what lets the buffer be allocated once: a
/// `Vec` that never grows can never leave a copy of a secret behind in
/// freed memory.
const MAX_FIELD_BYTES: usize = 64 * 1024;

/// A whole-vault listing is metadata rather than a secret, and it is far
/// larger than any single field: a few thousand entries pass 64 KiB easily,
/// and capping it there would break discovery for big vaults.
const MAX_LISTING_BYTES: usize = 16 * 1024 * 1024;

/// Read a pipe that may carry key material into zeroizing storage.
///
/// For a field-sized read the buffer is allocated once up front, so growth
/// can never leave a half-copied secret behind in freed memory. A listing is
/// allowed to grow past that: item names are not secrets, and refusing to
/// read them would break discovery on any sizeable vault.
async fn read_output(
    pipe: &mut tokio::process::ChildStdout,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, LpassError> {
    use tokio::io::AsyncReadExt as _;
    let mut out = Zeroizing::new(Vec::with_capacity(max_bytes.min(MAX_FIELD_BYTES)));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let read = pipe.read(&mut chunk[..]).await.map_err(LpassError::Spawn)?;
        if read == 0 {
            return Ok(out);
        }
        if out.len() + read > max_bytes {
            return Err(LpassError::FieldTooLarge(max_bytes));
        }
        out.extend_from_slice(&chunk[..read]);
    }
}

/// Read lpass's stderr, which carries diagnostics rather than secrets.
async fn read_diagnostics(pipe: &mut tokio::process::ChildStderr) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt as _;
    let mut out = Vec::new();
    pipe.take(MAX_FIELD_BYTES as u64)
        .read_to_end(&mut out)
        .await?;
    Ok(out)
}

/// Parse one `lpass ls` line: `Group/Name [id: 1234]`. Uses the LAST
/// ` [id: ` marker so names containing the marker text cannot confuse it.
fn parse_ls_line(line: &str) -> Option<ItemSummary> {
    let line = line.trim_end();
    let rest = line.strip_suffix(']')?;
    let (name, id) = rest.rsplit_once(" [id: ")?;
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(ItemSummary {
        id: id.to_string(),
        name: name.to_string(),
    })
}

struct CmdOutput {
    success: bool,
    code: Option<i32>,
    stdout: Zeroizing<Vec<u8>>,
    stderr: String,
}

#[async_trait::async_trait]
impl LpassClient for LpassCli {
    fn master_password_came_from_store(&self) -> bool {
        self.master_password_from_store
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn may_prompt(&self) -> bool {
        self.askpass_helper.is_some()
    }

    async fn status(&self) -> Result<LoginStatus, LpassError> {
        let out = self.run(&["status"], MAX_FIELD_BYTES).await?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        if out.success {
            let user = text
                .trim()
                .strip_prefix("Logged in as ")
                .unwrap_or(&text)
                .trim_end_matches('.')
                .to_string();
            Ok(LoginStatus::LoggedIn(user))
        } else if text.contains("Not logged in") || out.stderr.contains("Not logged in") {
            Ok(LoginStatus::NotLoggedIn)
        } else {
            Err(Self::classify(None, &out))
        }
    }

    async fn show_field(
        &self,
        item_id: &str,
        field: &str,
    ) -> Result<Zeroizing<Vec<u8>>, LpassError> {
        let field_arg = format!("--field={field}");
        let out = self
            .run(&["show", &field_arg, item_id], MAX_FIELD_BYTES)
            .await?;
        if !out.success {
            return Err(Self::classify(Some(item_id), &out));
        }
        Ok(out.stdout)
    }

    async fn ls(&self) -> Result<Vec<ItemSummary>, LpassError> {
        // Plain `ls` output ("Group/Name [id: 123]") is the only listing
        // format documented in every lastpass-cli release; --format is not.
        let out = self
            .run(&["ls", "--color=never"], MAX_LISTING_BYTES)
            .await?;
        if !out.success {
            return Err(Self::classify(None, &out));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(text.lines().filter_map(parse_ls_line).collect())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::path::Path;

    /// Write a fake `lpass` shell script whose behavior is baked in.
    fn fake_lpass(dir: &Path, body: &str) -> PathBuf {
        crate::testutil::write_script(dir, "lpass", body)
    }

    #[tokio::test]
    async fn show_field_returns_trimmed_value() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            r#"[ "$1" = show ] || exit 9
[ "$2" = "--field=Private Key" ] || exit 9
[ "$3" = "42" ] || exit 9
printf 'SECRET-VALUE\n'"#,
        );
        let client = LpassCli::new(bin);
        let value = client.show_field("42", "Private Key").await.unwrap();
        assert_eq!(&*value, b"SECRET-VALUE");
    }

    #[tokio::test]
    async fn only_the_record_terminator_is_stripped() {
        // a value that itself ends in a newline must survive: lpass appends
        // exactly one, so "value\n" + terminator arrives as "value\n\n"
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), r"printf 'pass\n\n'");
        let value = LpassCli::new(bin)
            .show_field("42", "Passphrase")
            .await
            .unwrap();
        assert_eq!(&*value, b"pass\n");

        // CRLF terminator
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), r"printf 'pass\r\n'");
        let value = LpassCli::new(bin)
            .show_field("42", "Passphrase")
            .await
            .unwrap();
        assert_eq!(&*value, b"pass");

        // no terminator at all: nothing is removed
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), r"printf 'pass'");
        let value = LpassCli::new(bin)
            .show_field("42", "Passphrase")
            .await
            .unwrap();
        assert_eq!(&*value, b"pass");
    }

    #[tokio::test]
    async fn a_big_vault_listing_is_not_treated_as_an_oversized_field() {
        // ~1500 entries: past the per-field cap, nowhere near the listing cap
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            r#"[ "$1" = ls ] || exit 9
i=0
while [ $i -lt 1500 ]; do
    printf 'Group/A rather long item name number %s [id: %s]\n' "$i" "$i"
    i=$((i + 1))
done"#,
        );
        let items = LpassCli::new(bin).ls().await.unwrap();
        assert_eq!(items.len(), 1500);
        assert_eq!(items[0].id, "0");
    }

    #[tokio::test]
    async fn absurdly_large_output_is_refused() {
        // the cap keeps the secret buffer single-allocation; anything past
        // it is a broken vault item, not a key
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), "head -c 200000 /dev/zero | tr '\\0' 'x'");
        let err = LpassCli::new(bin).show_field("42", "x").await.unwrap_err();
        assert!(matches!(err, LpassError::FieldTooLarge(_)), "{err:?}");
    }

    #[tokio::test]
    async fn empty_field_is_empty_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), "printf '\\n'");
        let client = LpassCli::new(bin);
        let value = client.show_field("42", "Passphrase").await.unwrap();
        assert!(value.is_empty());
    }

    #[tokio::test]
    async fn not_logged_in_detected_from_show() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            r"echo 'lpass: Error: Could not find decryption key. Perhaps you need to login with `lpass login`.' >&2; exit 1",
        );
        let client = LpassCli::new(bin);
        let err = client.show_field("42", "Private Key").await.unwrap_err();
        assert!(matches!(err, LpassError::NotLoggedIn), "{err:?}");
    }

    #[tokio::test]
    async fn missing_field_is_distinct_from_a_vault_failure() {
        // real lpass wording for an item that simply lacks the field
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            "echo \"Error: Could not find specified field 'NoteType'.\" >&2; exit 1",
        );
        let err = LpassCli::new(bin)
            .show_field("42", "NoteType")
            .await
            .unwrap_err();
        assert!(
            matches!(err, LpassError::FieldNotFound { ref item, ref field }
                if item == "42" && field == "NoteType"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn missing_item_detected() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            "echo 'Error: Could not find specified account(s).' >&2; exit 1",
        );
        let client = LpassCli::new(bin);
        let err = client.show_field("42", "Private Key").await.unwrap_err();
        assert!(
            matches!(err, LpassError::ItemNotFound(ref id) if id == "42"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn hung_lpass_is_killed_after_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), "sleep 30");
        let client = LpassCli::with_timeout(bin, Duration::from_millis(200));
        let start = std::time::Instant::now();
        let err = client.show_field("42", "Private Key").await.unwrap_err();
        assert!(matches!(err, LpassError::Timeout(_)), "{err:?}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn generic_failures_map_to_command_failed() {
        // show_field: unrecognized error with an item id still isn't
        // ItemNotFound unless lpass says so
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), "echo 'Error: something exploded' >&2; exit 3");
        let err = LpassCli::new(bin).show_field("42", "x").await.unwrap_err();
        assert!(
            matches!(err, LpassError::CommandFailed { code: Some(3), ref stderr } if stderr.contains("exploded")),
            "{err:?}"
        );

        // ls: "account not found" without an item id in play falls through
        // to CommandFailed too
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            "echo 'Error: Could not find specified account(s).' >&2; exit 1",
        );
        let err = LpassCli::new(bin).ls().await.unwrap_err();
        assert!(matches!(err, LpassError::CommandFailed { .. }), "{err:?}");

        // status: unrecognized failure propagates as an error
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), "echo 'weird' >&2; exit 9");
        assert!(LpassCli::new(bin).status().await.is_err());

        // ls while logged out
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            "echo 'lpass: Error: Could not find decryption key.' >&2; exit 1",
        );
        assert!(matches!(
            LpassCli::new(bin).ls().await.unwrap_err(),
            LpassError::NotLoggedIn
        ));

        // missing binary -> Spawn
        assert!(matches!(
            LpassCli::new(PathBuf::from("/nonexistent/lpass"))
                .status()
                .await
                .unwrap_err(),
            LpassError::Spawn(_)
        ));
    }

    #[tokio::test]
    async fn status_parses_both_states() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), "echo 'Logged in as user@example.com.'");
        assert_eq!(
            LpassCli::new(bin).status().await.unwrap(),
            LoginStatus::LoggedIn("user@example.com".into())
        );

        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), "echo 'Not logged in.'; exit 1");
        assert_eq!(
            LpassCli::new(bin).status().await.unwrap(),
            LoginStatus::NotLoggedIn
        );
    }

    #[tokio::test]
    async fn environment_is_allowlisted() {
        let dir = tempfile::tempdir().unwrap();
        // Prints the sensitive var (must be scrubbed) and HOME (must survive).
        let bin = fake_lpass(
            dir.path(),
            r#"printf '%s|%s' "$SUPER_SECRET_TOKEN" "$HOME""#,
        );
        // Env vars are process-global; the name is unique to this test so
        // parallel tests cannot collide.
        std::env::set_var("SUPER_SECRET_TOKEN", "leaked");
        let client = LpassCli::new(bin);
        let value = client.show_field("42", "x").await.unwrap();
        let text = String::from_utf8_lossy(&value);
        let (secret, home) = text.split_once('|').unwrap();
        assert_eq!(secret, "", "parent env must not leak into lpass");
        assert!(!home.is_empty(), "HOME must be passed through");
    }

    #[tokio::test]
    async fn allowlisted_variables_pass_through() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            r#"printf '%s|%s|%s' "$LPASS_COVERAGE_PROBE" "$XDG_COVERAGE_PROBE" "$TMPDIR""#,
        );
        // unique names: env is process-global across parallel tests
        std::env::set_var("LPASS_COVERAGE_PROBE", "lp-ok");
        std::env::set_var("XDG_COVERAGE_PROBE", "xdg-ok");
        let value = LpassCli::new(bin).show_field("42", "x").await.unwrap();
        let text = String::from_utf8_lossy(&value).to_string();
        let mut parts = text.split('|');
        assert_eq!(parts.next(), Some("lp-ok"));
        assert_eq!(parts.next(), Some("xdg-ok"));
        // TMPDIR is set on macOS test hosts; empty is fine elsewhere
    }

    #[tokio::test]
    async fn not_logged_in_on_stderr_only_is_detected() {
        // classify: the "Not logged in" wording (as opposed to the
        // decryption-key wording) also means logged out
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), "echo 'lpass: Not logged in.' >&2; exit 1");
        assert!(matches!(
            LpassCli::new(bin).show_field("42", "x").await.unwrap_err(),
            LpassError::NotLoggedIn
        ));

        // status: "Not logged in" printed on stderr instead of stdout
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), "echo 'Not logged in.' >&2; exit 1");
        assert_eq!(
            LpassCli::new(bin).status().await.unwrap(),
            LoginStatus::NotLoggedIn
        );
    }

    #[test]
    fn ls_line_parser_rejects_empty_id() {
        assert!(parse_ls_line("name [id: ]").is_none());
    }

    #[tokio::test]
    async fn the_master_password_helper_is_named_to_lpass() {
        // Both halves matter: LPASS_ASKPASS is what lpass runs, and the marker
        // beside it is what tells that run to be a prompt rather than an agent.
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            r#"printf '%s|%s' "$LPASS_ASKPASS" "$LASTPASS_SSH_AGENT_ASKPASS_CONFIG""#,
        );
        let value = LpassCli::new(bin)
            .asking_with(
                Some(PathBuf::from("/helper")),
                PathBuf::from("/cfg.toml"),
                Duration::from_secs(30),
            )
            .show_field("42", "x")
            .await
            .unwrap();
        assert_eq!(&*value, b"/helper|/cfg.toml");
    }

    #[tokio::test]
    async fn without_a_helper_lpass_is_told_of_none() {
        // Not asked for, so not installed: lpass falls back to the stdin path
        // that fails fast instead of blocking on a prompt nobody can answer.
        //
        // Exported into this process first: with nothing set, the assertion
        // holds on any machine and proves nothing. Safe to leave behind only
        // because of the rule under test — no lpass call sees this variable.
        std::env::set_var("LPASS_ASKPASS", "/nonexistent/inherited-askpass");
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), r#"printf '[%s]' "$LPASS_ASKPASS""#);
        let client = LpassCli::new(bin).asking_with(
            None,
            PathBuf::from("/cfg.toml"),
            Duration::from_secs(30),
        );
        assert!(!client.may_prompt());
        assert_eq!(&*client.show_field("42", "x").await.unwrap(), b"[]");
    }

    #[tokio::test]
    async fn a_master_password_unlock_is_reported_back_to_the_agent() {
        // The helper runs where the agent cannot see it, so the signal on
        // stderr is the only way this reaches a log at all.
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            &format!(
                "echo '{}{}' >&2; printf 'value'",
                super::ASKPASS_SIGNAL,
                super::ASKPASS_FROM_STORE
            ),
        );
        let client = LpassCli::new(bin);
        assert!(
            !client.master_password_came_from_store(),
            "nothing asked yet"
        );
        let value = client.show_field("42", "x").await.unwrap();
        assert_eq!(&*value, b"value");
        // Only the store's own signal counts: a password typed at the fallback
        // prompt says nothing about what is stored.
        assert!(client.master_password_came_from_store());
    }

    #[tokio::test]
    async fn a_typed_password_does_not_pass_for_a_stored_one() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            &format!("echo '{}' >&2; printf 'v'", super::ASKPASS_SIGNAL),
        );
        let client = LpassCli::new(bin);
        client.show_field("42", "x").await.unwrap();
        assert!(!client.master_password_came_from_store());
    }

    #[tokio::test]
    async fn the_signal_does_not_crowd_out_lpass_own_diagnosis() {
        // The marker is ours, not lpass's. Left in the diagnostic it would eat
        // part of the window `classify` reads, and a long enough preamble would
        // push the wording that identifies the failure out of view.
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            &format!(
                "echo '{}' >&2; echo 'lpass: Error: Not logged in.' >&2; exit 1",
                super::ASKPASS_SIGNAL
            ),
        );
        assert!(matches!(
            LpassCli::new(bin).show_field("42", "x").await.unwrap_err(),
            LpassError::NotLoggedIn
        ));
    }

    #[tokio::test]
    async fn the_vault_timeout_is_passed_on_when_configured() {
        // Set on every call, because lpass reads it when it starts the agent
        // that holds the key, and any call might be the one that does.
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), r#"printf '[%s]' "$LPASS_AGENT_TIMEOUT""#);
        let value = LpassCli::new(bin)
            .unlocked_for(Some(300))
            .show_field("42", "x")
            .await
            .unwrap();
        assert_eq!(&*value, b"[300]");
    }

    #[tokio::test]
    async fn without_it_lpass_keeps_its_own_default() {
        // Unset rather than guessed at: an hour is lpass's choice to make.
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), r#"printf '[%s]' "$LPASS_AGENT_TIMEOUT""#);
        let value = LpassCli::new(bin)
            .unlocked_for(None)
            .show_field("42", "x")
            .await
            .unwrap();
        assert_eq!(&*value, b"[]");
    }

    #[tokio::test]
    async fn pinentry_is_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), r#"printf '%s' "$LPASS_DISABLE_PINENTRY""#);
        let client = LpassCli::new(bin);
        let value = client.show_field("42", "x").await.unwrap();
        assert_eq!(&*value, b"1");
    }

    #[tokio::test]
    async fn ls_parses_default_output() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            r#"[ "$1" = ls ] || exit 9
printf 'Personal/SSH Key [id: 123]\nWork/Deploy Key [id: 456]\nmalformed line\n'"#,
        );
        let items = LpassCli::new(bin).ls().await.unwrap();
        assert_eq!(
            items,
            vec![
                ItemSummary {
                    id: "123".into(),
                    name: "Personal/SSH Key".into()
                },
                ItemSummary {
                    id: "456".into(),
                    name: "Work/Deploy Key".into()
                },
            ]
        );
    }

    #[test]
    fn ls_line_parser_handles_hostile_names() {
        // name containing the marker text: last marker wins
        let item = parse_ls_line("evil [id: 999] name [id: 42]").unwrap();
        assert_eq!(item.id, "42");
        assert_eq!(item.name, "evil [id: 999] name");
        assert!(parse_ls_line("no marker here").is_none());
        assert!(parse_ls_line("bad id [id: 12x]").is_none());
        assert!(parse_ls_line("").is_none());
    }
}
