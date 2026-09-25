use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use super::{ItemSummary, LpassClient, LpassError};
use crate::unlock::Unlock;

/// A `show` against the local vault cache takes 100–500 ms, but the first
/// one after a while can trigger a full vault sync, and on a slow link that
/// is the case that matters: failing a signature there costs the user a
/// retry, while waiting costs a pause. Still bounded, so a wedged lpass
/// cannot hang a signing request indefinitely.
///
/// The master password is obtained before lpass is spawned, so a prompt left
/// open never counts against this.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the master password comes from when a call finds the vault locked.
///
/// Every call is first made without one: `lpass` still reads an agent a shell
/// has left running, and a vault the user opened themselves is used as they
/// left it. Only a call that fails for want of the key reaches for this.
pub enum MasterPasswordSource {
    /// Nowhere. A locked vault fails fast, in `LpassError::Locked`.
    None,
    /// This candidate, for `store-master-password` to check against the vault.
    Fixed(Zeroizing<Vec<u8>>),
    /// What the agent holds, asking for it when it holds nothing.
    Unlock(Arc<Unlock>),
    /// What the agent holds, and nothing when it holds nothing — for work that
    /// must never put a prompt on screen.
    HeldOnly(Arc<Unlock>),
}

impl MasterPasswordSource {
    /// The password to feed without asking anyone.
    async fn held(&self) -> Option<Zeroizing<Vec<u8>>> {
        match self {
            Self::None => None,
            Self::Fixed(secret) => Some(secret.clone()),
            // Not asking, so it cannot fail.
            Self::Unlock(unlock) | Self::HeldOnly(unlock) => {
                unlock.password(false).await.unwrap_or_default()
            }
        }
    }

    /// The password after asking for it, when this source may.
    async fn asked(&self) -> Result<Option<Zeroizing<Vec<u8>>>, LpassError> {
        match self {
            Self::Unlock(unlock) => unlock
                .password(true)
                .await
                .map_err(LpassError::NoMasterPassword),
            Self::None | Self::Fixed(_) | Self::HeldOnly(_) => Ok(None),
        }
    }

    /// `lpass` did not accept what it was fed.
    async fn rejected(&self) {
        if let Self::Unlock(unlock) | Self::HeldOnly(unlock) = self {
            unlock.rejected().await;
        }
    }

    /// A call has just finished, so what is held was in use until now.
    ///
    /// Not for `HeldOnly`: the idle time counts signatures, and a background
    /// scan renewing it would keep the password for as long as the vault is
    /// large.
    async fn used(&self) {
        if let Self::Unlock(unlock) = self {
            unlock.touch().await;
        }
    }
}

/// Real lpass subprocess client.
///
/// Secret handling: no shell is involved, secrets never appear in argv or
/// env in either direction, the master password goes in on stdin and field
/// values come out of stdout straight into `Zeroizing` buffers, and a hung
/// lpass is killed after a timeout.
pub struct LpassCli {
    binary: PathBuf,
    timeout: Duration,
    source: MasterPasswordSource,
}

impl LpassCli {
    pub const fn new(binary: PathBuf) -> Self {
        Self {
            binary,
            timeout: DEFAULT_TIMEOUT,
            source: MasterPasswordSource::None,
        }
    }

    #[must_use]
    pub fn feeding(mut self, source: MasterPasswordSource) -> Self {
        self.source = source;
        self
    }

    #[cfg(test)]
    pub const fn with_timeout(binary: PathBuf, timeout: Duration) -> Self {
        Self {
            binary,
            timeout,
            source: MasterPasswordSource::None,
        }
    }

    fn command(&self, args: &[&str], fed: bool) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.binary);
        cmd.args(args)
            .stdin(if fed { Stdio::piped() } else { Stdio::null() })
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
            // so an inherited one would open somebody else's prompt from inside
            // a call — outside the interaction gate, and against a timeout with
            // no allowance for a human. The master password reaches lpass on
            // stdin, from a source this agent controls.
            // `LPASS_AGENT_DISABLE` is withheld too, and decided below per
            // call: inherited, it would keep the unfed probe from reading the
            // agent a shell left running, and an open vault would ask.
            if matches!(name.as_ref(), "LPASS_ASKPASS" | "LPASS_AGENT_DISABLE") {
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
        // The key lpass derives from the password it is fed lives for this one
        // call. Without this it would start an agent of its own holding that
        // key for an hour, for every process on the machine — the whole vault
        // open because one signature needed one key. Only on a fed call: an
        // unfed one has no key to keep, and may read the agent a shell already
        // left running — which lpass 1.6 does with this set too, but the man
        // page promises less, so the probe does not rely on it.
        if fed {
            cmd.env("LPASS_AGENT_DISABLE", "1");
        }
        // With no pinentry, lpass asks for the master password on stdin: what
        // is fed there, or nothing, and then it fails fast rather than block
        // on a prompt nobody can answer.
        cmd.env("LPASS_DISABLE_PINENTRY", "1");
        cmd
    }

    /// Run once without the master password, and again with it if the vault
    /// turns out to need one and the source will supply it.
    async fn run(&self, args: &[&str], max_bytes: usize) -> Result<CmdOutput, LpassError> {
        let held = self.source.held().await;
        let mut out = self
            .exec(args, held.as_ref().map(|held| &held[..]), max_bytes)
            .await?;
        if out.locked() {
            if let Some(password) = self.source.asked().await? {
                out = self.exec(args, Some(&password), max_bytes).await?;
            }
        }
        if out.stderr.contains("Incorrect master password") {
            self.source.rejected().await;
        }
        // Stamped after the call as well as before it, so the idle clock runs
        // from when the password was last needed rather than from when the
        // call began.
        self.source.used().await;
        Ok(out)
    }

    async fn exec(
        &self,
        args: &[&str],
        password: Option<&[u8]>,
        max_bytes: usize,
    ) -> Result<CmdOutput, LpassError> {
        let mut child = self
            .command(args, password.is_some())
            .spawn()
            .map_err(LpassError::Spawn)?;
        let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
        let mut stderr_pipe = child.stderr.take().expect("stderr is piped");

        let io = async {
            if let Some(password) = password {
                let mut stdin = child.stdin.take().expect("stdin is piped");
                feed(&mut stdin, password).await;
                // Dropped here, so lpass reads one answer and then end of
                // file: it asks again after a wrong password, and only the
                // close ends that.
            }
            // Read both pipes concurrently — a full stderr pipe would otherwise
            // wedge lpass before it closes stdout — and only then reap. stdout
            // goes straight into zeroizing storage, so a timeout that drops this
            // future still wipes whatever key material had arrived. try_join
            // abandons the other reader (and skips the reap) the moment one
            // fails, so a still-spewing child can never hold us here.
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
        let stderr: String = String::from_utf8_lossy(&stderr)
            .trim()
            .chars()
            .take(300)
            .collect();
        Ok(CmdOutput {
            success: status.success(),
            code: status.code(),
            fed: password.is_some(),
            stdout,
            stderr,
        })
    }

    fn classify(item_id: Option<&str>, out: &CmdOutput) -> LpassError {
        if out.stderr.contains("Incorrect master password") {
            return LpassError::WrongMasterPassword;
        }
        if out.stderr.contains("Could not find decryption key") {
            // lpass asks for the password only while there is a login to ask
            // it for. Fed one and not even tried, there was no login; not fed
            // one, it may only be locked — which is what the retry finds out.
            return if out.fed {
                LpassError::NotLoggedIn
            } else {
                LpassError::Locked
            };
        }
        if out.stderr.contains("Not logged in") || out.stderr.contains("Could not find session") {
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

/// Hand lpass the master password: the line it would have read from a
/// terminal, in one zeroizing allocation.
///
/// The pipe takes far more than one line without anyone reading, so this
/// never waits on lpass. A vault that was open after all leaves the line
/// unread, and lpass exiting first turns the write into an error that means
/// nothing — see `unread`.
async fn feed(stdin: &mut tokio::process::ChildStdin, password: &[u8]) {
    use tokio::io::AsyncWriteExt as _;
    let mut line = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    line.extend_from_slice(password);
    line.push(b'\n');
    stdin.write_all(&line).await.unwrap_or_else(unread);
}

/// lpass exited before reading its stdin, which a vault already open makes
/// ordinary: the outcome is in its exit status, not here. Excluded from
/// coverage: it takes lpass losing a race a test cannot arrange.
/// (`unwrap_or_else` dictates the by-value signature.)
#[expect(
    clippy::needless_pass_by_value,
    reason = "unwrap_or_else requires FnOnce(io::Error)"
)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn unread(e: std::io::Error) {
    tracing::debug!("lpass did not read the master password: {e}");
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
    /// Whether a master password went in on stdin, which changes what a
    /// missing key means.
    fed: bool,
    stdout: Zeroizing<Vec<u8>>,
    stderr: String,
}

impl CmdOutput {
    /// Whether lpass failed for want of the key, before anything was fed.
    fn locked(&self) -> bool {
        !self.success && !self.fed && self.stderr.contains("Could not find decryption key")
    }
}

#[async_trait::async_trait]
impl LpassClient for LpassCli {
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

    /// What real lpass says when it has no key and nothing answers its prompt.
    const NO_KEY: &str = "echo 'lpass: Error: Could not find decryption key. Perhaps you need to login with `lpass login`.' >&2; exit 1";

    /// A vault that opens with whatever is fed, and is locked when nothing is.
    fn locked_vault(dir: &Path) -> PathBuf {
        fake_lpass(
            dir,
            &format!("if IFS= read -r pw; then printf 'opened with %s' \"$pw\"; else {NO_KEY}; fi"),
        )
    }

    /// An agent's master-password holder whose prompt is a script answering
    /// `answer`, counting its asks in a file beside it.
    fn unlock_answering(dir: &Path, answer: &str) -> (Arc<Unlock>, PathBuf) {
        let asks = dir.join("asks");
        let script = crate::testutil::write_script(
            dir,
            "askpass",
            &format!("echo asked >> '{}'; {answer}", asks.display()),
        );
        let prompt = crate::passphrase::AskpassPrompt::new(script, Duration::from_secs(5));
        let unlock = Unlock::new(
            crate::config::MasterPassword::Prompt,
            Arc::new(crate::master::NoStore),
            Arc::new(prompt),
            None,
        );
        (Arc::new(unlock), asks)
    }

    fn times_asked(asks: &Path) -> usize {
        std::fs::read_to_string(asks).map_or(0, |text| text.lines().count())
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
    async fn without_a_source_a_locked_vault_fails_fast() {
        // Nothing to feed and nobody to ask: the one attempt is the answer.
        let dir = tempfile::tempdir().unwrap();
        let client = LpassCli::new(locked_vault(dir.path()));
        let err = client.show_field("42", "Private Key").await.unwrap_err();
        assert!(matches!(err, LpassError::Locked), "{err:?}");
        assert!(matches!(
            LpassCli::new(locked_vault(dir.path()))
                .ls()
                .await
                .unwrap_err(),
            LpassError::Locked
        ));
    }

    #[tokio::test]
    async fn a_fixed_password_is_fed_on_stdin_and_nothing_is_fed_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            "if IFS= read -r pw; then printf 'fed %s' \"$pw\"; else printf 'nothing'; fi",
        );
        let fixed = LpassCli::new(bin.clone()).feeding(MasterPasswordSource::Fixed(
            Zeroizing::new(b"hunter2".to_vec()),
        ));
        assert_eq!(&*fixed.show_field("42", "x").await.unwrap(), b"fed hunter2");
        assert_eq!(
            &*LpassCli::new(bin).show_field("42", "x").await.unwrap(),
            b"nothing"
        );
    }

    #[tokio::test]
    async fn a_locked_vault_is_tried_first_and_then_asked_for() {
        // The first attempt goes without a password, because a vault the user
        // opened in a shell answers it. Only the locked one costs a prompt —
        // and once answered, the next call is fed what is held.
        let dir = tempfile::tempdir().unwrap();
        let (unlock, asks) = unlock_answering(dir.path(), "echo secret");
        let client = LpassCli::new(locked_vault(dir.path()))
            .feeding(MasterPasswordSource::Unlock(unlock.clone()));
        assert_eq!(
            &*client.show_field("42", "x").await.unwrap(),
            b"opened with secret"
        );
        assert_eq!(times_asked(&asks), 1);
        assert!(unlock.is_held().await);
    }

    #[tokio::test]
    async fn what_is_held_is_fed_without_asking_again() {
        let dir = tempfile::tempdir().unwrap();
        let (unlock, asks) = unlock_answering(dir.path(), "echo secret");
        let client =
            LpassCli::new(locked_vault(dir.path())).feeding(MasterPasswordSource::Unlock(unlock));
        client.show_field("42", "x").await.unwrap();
        client.show_field("42", "x").await.unwrap();
        assert_eq!(times_asked(&asks), 1, "held after the first");
    }

    #[tokio::test]
    async fn a_source_that_may_not_ask_gets_the_locked_answer() {
        // The refresher's client: silent with the vault shut, and served from
        // what the agent holds once a signature has had it asked for.
        let dir = tempfile::tempdir().unwrap();
        let (unlock, asks) = unlock_answering(dir.path(), "echo secret");
        let client = LpassCli::new(locked_vault(dir.path()))
            .feeding(MasterPasswordSource::HeldOnly(unlock.clone()));
        assert!(matches!(
            client.show_field("42", "x").await.unwrap_err(),
            LpassError::Locked
        ));
        assert_eq!(times_asked(&asks), 0);

        unlock.password(true).await.unwrap();
        assert_eq!(
            &*client.show_field("42", "x").await.unwrap(),
            b"opened with secret"
        );
    }

    #[tokio::test]
    async fn a_prompt_that_fails_is_reported_rather_than_retried() {
        let dir = tempfile::tempdir().unwrap();
        let (unlock, _asks) = unlock_answering(dir.path(), "exit 1");
        let client =
            LpassCli::new(locked_vault(dir.path())).feeding(MasterPasswordSource::Unlock(unlock));
        let err = client.show_field("42", "x").await.unwrap_err();
        assert!(matches!(err, LpassError::NoMasterPassword(_)), "{err:?}");
    }

    #[tokio::test]
    async fn a_password_lpass_rejects_is_dropped() {
        // Real lpass asks again after a wrong one and gives up at end of file,
        // so both lines appear; the first is the verdict.
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            &format!(
                "if IFS= read -r pw; then echo 'Incorrect master password; please try again.' >&2; fi; {NO_KEY}"
            ),
        );
        let (unlock, asks) = unlock_answering(dir.path(), "echo typo");
        let client =
            LpassCli::new(bin.clone()).feeding(MasterPasswordSource::Unlock(unlock.clone()));
        let err = client.show_field("42", "x").await.unwrap_err();
        assert!(matches!(err, LpassError::WrongMasterPassword), "{err:?}");
        assert_eq!(times_asked(&asks), 1);
        assert!(
            !unlock.is_held().await,
            "dropped, so the next call asks again"
        );

        // and a fixed candidate is simply reported as wrong
        let fixed = LpassCli::new(bin).feeding(MasterPasswordSource::Fixed(Zeroizing::new(
            b"typo".to_vec(),
        )));
        assert!(matches!(
            fixed.ls().await.unwrap_err(),
            LpassError::WrongMasterPassword
        ));
    }

    #[tokio::test]
    async fn a_password_that_was_never_tried_means_there_is_no_login() {
        // lpass only asks while a login exists to ask for: fed a password and
        // still without a key, the session is gone, not locked.
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), NO_KEY);
        let client = LpassCli::new(bin).feeding(MasterPasswordSource::Fixed(Zeroizing::new(
            b"right".to_vec(),
        )));
        assert!(matches!(
            client.show_field("42", "Private Key").await.unwrap_err(),
            LpassError::NotLoggedIn
        ));
    }

    #[tokio::test]
    async fn not_logged_in_is_detected_from_lpass_own_words() {
        for words in ["lpass: Not logged in.", "Error: Could not find session."] {
            let dir = tempfile::tempdir().unwrap();
            let bin = fake_lpass(dir.path(), &format!("echo '{words}' >&2; exit 1"));
            assert!(
                matches!(
                    LpassCli::new(bin).show_field("42", "x").await.unwrap_err(),
                    LpassError::NotLoggedIn
                ),
                "{words}"
            );
        }
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

        // missing binary -> Spawn
        assert!(matches!(
            LpassCli::new(PathBuf::from("/nonexistent/lpass"))
                .ls()
                .await
                .unwrap_err(),
            LpassError::Spawn(_)
        ));
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
    async fn an_inherited_password_helper_is_withheld() {
        // Exported into this process first: with nothing set, the assertion
        // holds on any machine and proves nothing. Safe to leave behind only
        // because of the rule under test — no lpass call sees this variable.
        std::env::set_var("LPASS_ASKPASS", "/nonexistent/inherited-askpass");
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(dir.path(), r#"printf '[%s]' "$LPASS_ASKPASS""#);
        assert_eq!(
            &*LpassCli::new(bin).show_field("42", "x").await.unwrap(),
            b"[]"
        );
    }

    #[tokio::test]
    async fn lpass_is_kept_from_starting_an_agent_with_what_it_is_fed() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_lpass(
            dir.path(),
            r#"printf '[%s]|%s' "$LPASS_AGENT_DISABLE" "$LPASS_DISABLE_PINENTRY""#,
        );
        // unfed: free to read an agent a shell left running, and with no key
        // of its own to keep — whatever the environment inherited says. Safe
        // to leave set: this is the rule under test.
        std::env::set_var("LPASS_AGENT_DISABLE", "1");
        let value = LpassCli::new(bin.clone())
            .show_field("42", "x")
            .await
            .unwrap();
        assert_eq!(&*value, b"[]|1");
        // fed: the key it derives must not outlive the call
        let fed =
            LpassCli::new(bin).feeding(MasterPasswordSource::Fixed(Zeroizing::new(b"pw".to_vec())));
        assert_eq!(&*fed.show_field("42", "x").await.unwrap(), b"[1]|1");
    }

    #[test]
    fn ls_line_parser_rejects_empty_id() {
        assert!(parse_ls_line("name [id: ]").is_none());
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
