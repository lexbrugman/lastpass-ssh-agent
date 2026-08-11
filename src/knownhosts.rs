//! Putting a name to the host a session binding proves.
//!
//! A binding carries the far host's public key, and it is trustworthy: that
//! host signed the session id with it. What it does not carry is a hostname —
//! the protocol has no field for one — so a confirmation prompt can only show
//! a fingerprint, which tells the person approving a signature almost nothing
//! at a glance.
//!
//! `known_hosts` is where the name lives. Trusting it for a label is no
//! stretch: it is the same file `ssh` consults to decide the host is who it
//! claims to be, so anything able to forge an entry here has already defeated
//! host verification. Names still reach the prompt escaped, because the file
//! is user-editable text like any other.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Resolves host-key fingerprints to the names `known_hosts` records.
///
/// The files are read when a name is actually wanted — once per signature, not
/// once per binding — rather than indexed at startup. Freshness is the reason:
/// `ssh` writes a new host into `known_hosts` while agreeing to connect to it,
/// which is *before* it authenticates and asks for a signature. A snapshot
/// taken when the agent started would show a bare fingerprint for exactly the
/// connection a person is most likely to be reading carefully.
///
/// Reading happens on the blocking pool. The agent runs on one thread, and a
/// peer on a forwarded connection can present a binding per host key it
/// controls, so file work must never sit on the runtime.
#[derive(Debug, Clone)]
pub struct HostNames {
    files: Vec<PathBuf>,
    deadline: std::time::Duration,
}

/// Reading a few small files takes microseconds, so anything approaching this
/// is a filesystem that has stopped answering — a home directory on a stalled
/// network mount, where `O_NONBLOCK` does nothing for a regular file. Giving up
/// matters more than the names do: this is awaited before the confirmation
/// prompt and under the one-signature-at-a-time gate, so without a deadline one
/// hung read would stall every later signature instead of it timing out and
/// denying.
const LOOKUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

impl Default for HostNames {
    fn default() -> Self {
        Self {
            files: default_files(),
            deadline: LOOKUP_DEADLINE,
        }
    }
}

impl HostNames {
    /// Tests point this at their own file, or at none at all, so a prompt's
    /// contents never depend on whose machine the suite runs on.
    ///
    /// Test-only for now. If a `known_hosts` in a non-default location ever
    /// needs supporting, this is where a configured path would arrive.
    #[cfg(test)]
    pub const fn with_files(files: Vec<PathBuf>) -> Self {
        Self {
            files,
            deadline: LOOKUP_DEADLINE,
        }
    }

    /// Name each fingerprint, in the order given.
    ///
    /// One pass over the files for the whole set: a connection may be bound to
    /// several hosts, and re-reading per hop would multiply the work by the
    /// number of hops an untrusted peer chooses to send.
    pub async fn names_for(&self, fingerprints: Vec<String>) -> Vec<Option<String>> {
        // Nothing bound, nothing to name — and no file touched. This is the
        // common case: a local tool, or any client that sends no binding.
        if fingerprints.is_empty() {
            return Vec::new();
        }
        let files = self.files.clone();
        let resolve = move || {
            let index = index_files(&files);
            let names: Vec<Option<String>> = fingerprints
                .iter()
                .map(|fingerprint| index.name_for(fingerprint))
                .collect();
            // Say why, once, when hashing is the likely reason: a prompt
            // showing a fingerprint on a machine whose known_hosts is hashed
            // is working correctly, and that is not guessable from outside.
            if index.hashed > 0 && names.iter().any(Option::is_none) {
                tracing::debug!(
                    hashed = index.hashed,
                    "known_hosts keeps hostnames hashed (HashKnownHosts), so they \
                     cannot be read back — showing fingerprints"
                );
            }
            names
        };
        tokio::time::timeout(self.deadline, tokio::task::spawn_blocking(resolve))
            .await
            .map_or_else(deadline_expired, |joined| {
                joined.unwrap_or_else(lookup_failed)
            })
    }
}

/// The lookup outlasted its deadline, so nothing gets a name.
///
/// Named for the same reason as `lookup_failed`, and excluded for a similar
/// one: provoking it needs a filesystem that stops answering mid-read, which a
/// test cannot arrange without being flaky about it.
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "by value is what map_or_else hands a function"
)]
fn deadline_expired(_: tokio::time::error::Elapsed) -> Vec<Option<String>> {
    tracing::debug!("gave up reading known_hosts; showing fingerprints");
    Vec::new()
}

/// The lookup task did not finish, so nothing gets a name.
///
/// A signature is still perfectly approvable from a fingerprint, so this must
/// never fail one. A named function rather than a closure so its body is not a
/// line of its own in the coverage report: reaching it means `index_files`
/// panicked, which no test can arrange.
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "by value is what unwrap_or_else hands a function; a reference \
              would need a closure, and that closure body is the uncovered \
              line this exists to avoid"
)]
fn lookup_failed(e: tokio::task::JoinError) -> Vec<Option<String>> {
    tracing::debug!("could not read known_hosts: {e}");
    Vec::new()
}

/// Every hostname a set of files records, indexed by fingerprint, plus the
/// keys marked revoked.
#[derive(Debug, Default)]
struct Index {
    names: HashMap<String, Vec<String>>,
    /// Fingerprints an `@revoked` line names, from any file.
    revoked: std::collections::HashSet<String>,
    /// How many entries kept their hostname as a hash. Counted only to
    /// explain a missing name: with `HashKnownHosts` on there is nothing to
    /// read back, and a bare fingerprint is otherwise unaccountable.
    hashed: usize,
}

impl Index {
    /// How a prompt should name this host, or `None` when nothing knows it.
    ///
    /// Every name that matches, not the first: one key can be recorded under
    /// several names, and a binding says nothing about which of them this
    /// session used. Picking one by file order would state something the agent
    /// cannot know, and would be wrong exactly when it matters — a key shared
    /// between two hosts.
    fn name_for(&self, fingerprint: &str) -> Option<String> {
        // A revoked key gets no name, whichever file or line said so. Its
        // ordinary entry may well still be there, and dressing a revoked key
        // in a familiar hostname is the one thing this must never do — the
        // fingerprint is what a person needs to see then.
        if self.revoked.contains(fingerprint) {
            return None;
        }
        self.names.get(fingerprint).map(|names| names.join(", "))
    }

    /// Fold one file's lines in.
    fn add(&mut self, contents: &str) {
        for line in contents.lines() {
            match parse_line(line) {
                Some(Line::Named { fingerprint, hosts }) => {
                    let names = self.names.entry(fingerprint).or_default();
                    // The same host is commonly listed in more than one file,
                    // and naming it twice in a prompt reads like two hosts.
                    if !names.iter().any(|seen| seen == &hosts) {
                        names.push(hosts);
                    }
                }
                Some(Line::Revoked(fingerprint)) => {
                    self.revoked.insert(fingerprint);
                }
                Some(Line::Hashed) => self.hashed += 1,
                None => {}
            }
        }
    }
}

fn index_files(files: &[PathBuf]) -> Index {
    let mut index = Index::default();
    for file in files {
        if let Some(contents) = read_small(file) {
            index.add(&contents);
        }
    }
    index
}

/// What one `known_hosts` line contributes to the index.
#[derive(Debug, PartialEq, Eq)]
enum Line {
    /// A host key and the names recorded against it.
    Named { fingerprint: String, hosts: String },
    /// A key an `@revoked` line names, whatever else claims it.
    Revoked(String),
    /// An entry whose hostname is a hash, so it can name nothing.
    Hashed,
}

/// Read one line.
///
/// Pure, so every shape of line is testable without touching a real
/// `known_hosts`.
fn parse_line(line: &str) -> Option<Line> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // Fields are whitespace-delimited, so the marker is read as a field rather
    // than matched as a text prefix: `@revoked\thost` is as valid as
    // `@revoked host`, and treating one as unmarked would drop a revocation.
    let mut fields = line.split_whitespace();
    let first = fields.next()?;
    let (revoked, hosts) = match first {
        "@revoked" => (true, fields.next()?),
        // A @cert-authority entry is a CA key rather than any host's own, so
        // it names nothing. Same for any marker this does not know: better to
        // say nothing than to guess what it meant.
        _ if first.starts_with('@') => return None,
        _ => (false, first),
    };
    // A hashed entry (HashKnownHosts) keeps the name only as a MAC of it,
    // keyed by a per-entry salt: it can be tested against a hostname but never
    // reversed, and a hostname is the thing missing here. Reported rather than
    // dropped so a bare fingerprint can be explained. A revocation is about
    // the key rather than the name, and the line still carries the key, so
    // only an ordinary line stops here.
    if !revoked && hosts.starts_with("|1|") {
        return Some(Line::Hashed);
    }
    let algorithm = fields.next()?;
    let key = fields.next()?;
    let parsed = ssh_key::PublicKey::from_openssh(&format!("{algorithm} {key}")).ok()?;
    let fingerprint = parsed.fingerprint(ssh_key::HashAlg::Sha256).to_string();
    Some(if revoked {
        Line::Revoked(fingerprint)
    } else {
        Line::Named {
            fingerprint,
            hosts: hosts.to_string(),
        }
    })
}

/// The user's own `known_hosts` files.
///
/// Excluded from coverage: the empty case needs a system reporting no home
/// directory at all, which cannot be simulated in a test — the same reason
/// `config::no_socket_path` is excluded.
#[cfg_attr(coverage_nightly, coverage(off))]
fn user_files() -> Vec<PathBuf> {
    dirs::home_dir().map_or_else(Vec::new, |home| {
        vec![
            home.join(".ssh/known_hosts"),
            home.join(".ssh/known_hosts2"),
        ]
    })
}

/// Where OpenSSH keeps host keys by default: two per-user files and the two
/// system-wide ones its `GlobalKnownHostsFile` default names.
fn default_files() -> Vec<PathBuf> {
    let mut files = user_files();
    files.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
    files.push(PathBuf::from("/etc/ssh/ssh_known_hosts2"));
    files
}

/// A `known_hosts` is lines of text; anything enormous is not one, and this is
/// read while the agent is starting up.
const MAX_KNOWN_HOSTS_BYTES: u64 = 8 * 1024 * 1024;

fn read_small(path: &Path) -> Option<String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    // O_NONBLOCK, and the type checked from the handle rather than the path:
    // opening a FIFO read-only otherwise waits for a writer that never comes,
    // and this is awaited before the confirmation prompt while the one-request
    // gate is held — so a `known_hosts` that was not a file would wedge every
    // later signature instead of timing out.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        tracing::debug!(path = %path.display(), "ignoring a known_hosts that is not a file");
        return None;
    }
    if metadata.len() > MAX_KNOWN_HOSTS_BYTES {
        tracing::debug!(path = %path.display(), "ignoring an implausibly large known_hosts");
        return None;
    }

    // Bounded again while reading, because a file can grow between the check
    // and the read. Decoded lossily rather than rejected: one stray byte in a
    // comment must not hide every host key in the file — the affected line
    // simply stops parsing as a key.
    let mut bytes = Vec::new();
    file.take(MAX_KNOWN_HOSTS_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// GitHub's published ed25519 host key, and its fingerprint. Used because
    /// the fingerprint is public and checkable, not because anything here is
    /// specific to one host.
    const GITHUB_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    const GITHUB_FP: &str = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU";

    fn indexed(contents: &str) -> Index {
        let mut index = Index::default();
        index.add(contents);
        index
    }

    #[test]
    fn the_published_github_key_has_the_fingerprint_everyone_sees() {
        // Anchors these tests to a key whose fingerprint is published, rather
        // than to one the test made up.
        let parsed = ssh_key::PublicKey::from_openssh(GITHUB_KEY).unwrap();
        assert_eq!(
            parsed.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            GITHUB_FP
        );
    }

    #[test]
    fn a_matching_entry_gives_up_its_hostname() {
        let index = indexed(&format!("github.com {GITHUB_KEY}\n"));
        assert_eq!(index.name_for(GITHUB_FP).as_deref(), Some("github.com"));
    }

    /// Every shape a host is written in, since this serves any `ssh` command
    /// and not just the forge everyone tests against. The field is shown as
    /// written: a port or a pattern is information, not noise to strip.
    #[test]
    fn a_host_is_named_however_known_hosts_writes_it() {
        for hosts in [
            "server.internal",
            // a non-default port is bracketed by ssh
            "[server.internal]:2222",
            "192.0.2.10",
            "[2001:db8::1]:2222",
            // patterns are legal, and a prompt saying so is honest
            "*.internal",
            // several names on one line, one of them port-qualified
            "gateway.example,[gateway.example]:2222",
        ] {
            let index = indexed(&format!("{hosts} {GITHUB_KEY}\n"));
            assert_eq!(index.name_for(GITHUB_FP).as_deref(), Some(hosts));
        }
    }

    #[test]
    fn one_key_under_two_names_is_reported_as_both() {
        // A binding proves the key, not which name the session used. Naming
        // only the first would assert something the agent cannot know.
        let index = indexed(&format!(
            "first.example {GITHUB_KEY}\nsecond.example {GITHUB_KEY}\n"
        ));
        assert_eq!(
            index.name_for(GITHUB_FP).as_deref(),
            Some("first.example, second.example")
        );
    }

    #[test]
    fn the_same_name_twice_is_named_once() {
        // ssh writes a host into more than one file readily enough, and
        // "x, x" reads like two hosts.
        let mut index = Index::default();
        index.add(&format!("dup.example {GITHUB_KEY}\n"));
        index.add(&format!("dup.example {GITHUB_KEY}\n"));
        assert_eq!(index.name_for(GITHUB_FP).as_deref(), Some("dup.example"));
    }

    #[test]
    fn a_trailing_comment_field_does_not_confuse_the_parse() {
        let index = indexed(&format!("github.com {GITHUB_KEY} added-by-something\n"));
        assert_eq!(index.name_for(GITHUB_FP).as_deref(), Some("github.com"));
    }

    #[test]
    fn the_matching_line_is_found_among_others() {
        let index = indexed(&format!(
            "# a comment\n\
             \n\
             other.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGarbageNotAKey\n\
             github.com {GITHUB_KEY}\n"
        ));
        assert_eq!(index.name_for(GITHUB_FP).as_deref(), Some("github.com"));
    }

    #[test]
    fn nothing_is_invented_when_no_entry_matches() {
        let index = indexed(&format!("github.com {GITHUB_KEY}\n"));
        assert_eq!(index.name_for("SHA256:something-else"), None);
        assert_eq!(Index::default().name_for(GITHUB_FP), None);
    }

    #[test]
    fn a_hashed_entry_yields_no_name() {
        // HashKnownHosts stores a MAC of the hostname, so there is nothing to
        // read back — the prompt keeps the fingerprint.
        let index = indexed(&format!("|1|F1E2D3=|C4B5A6= {GITHUB_KEY}\n"));
        assert_eq!(index.name_for(GITHUB_FP), None);
    }

    #[test]
    fn a_revoked_or_ca_entry_never_names_a_host() {
        for marker in ["@revoked", "@cert-authority"] {
            let index = indexed(&format!("{marker} github.com {GITHUB_KEY}\n"));
            assert_eq!(index.name_for(GITHUB_FP), None, "{marker}");
        }
    }

    #[test]
    fn a_revocation_outranks_an_ordinary_entry_either_way_round() {
        // The ordinary line is usually still there when a key is revoked.
        // Naming it would dress a refused key in a familiar hostname, so the
        // revocation wins regardless of which line — or which file — came
        // first.
        let ordinary = format!("github.com {GITHUB_KEY}\n");
        let revoked = format!("@revoked github.com {GITHUB_KEY}\n");

        assert_eq!(
            indexed(&format!("{ordinary}{revoked}")).name_for(GITHUB_FP),
            None
        );
        assert_eq!(
            indexed(&format!("{revoked}{ordinary}")).name_for(GITHUB_FP),
            None
        );

        // and across separate files, in both orders
        for pair in [[&ordinary, &revoked], [&revoked, &ordinary]] {
            let mut index = Index::default();
            for contents in pair {
                index.add(contents);
            }
            assert_eq!(index.name_for(GITHUB_FP), None);
        }
    }

    #[test]
    fn fields_may_be_separated_by_any_whitespace() {
        // ssh splits on whitespace, so a tab is as ordinary as a space —
        // including after the marker, where reading it as text rather than as
        // a field would drop the revocation entirely.
        let index = indexed(&format!("github.com\t{GITHUB_KEY}\n"));
        assert_eq!(index.name_for(GITHUB_FP).as_deref(), Some("github.com"));

        let index = indexed(&format!(
            "github.com {GITHUB_KEY}\n@revoked\tgithub.com\t{GITHUB_KEY}\n"
        ));
        assert_eq!(index.name_for(GITHUB_FP), None, "a tabbed revocation");
    }

    #[test]
    fn an_unrecognised_marker_names_nothing() {
        let index = indexed(&format!("@something-new github.com {GITHUB_KEY}\n"));
        assert_eq!(index.name_for(GITHUB_FP), None);
    }

    #[test]
    fn a_hashed_revocation_still_revokes() {
        // Hashing hides the name, not the key. The revocation is about the
        // key, so it must survive a line whose hostname cannot be read.
        let index = indexed(&format!(
            "github.com {GITHUB_KEY}\n@revoked |1|F1E2D3=|C4B5A6= {GITHUB_KEY}\n"
        ));
        assert_eq!(index.name_for(GITHUB_FP), None);
    }

    #[test]
    fn a_truncated_line_is_skipped_rather_than_panicking() {
        for line in ["github.com", "github.com ssh-ed25519", "   "] {
            assert_eq!(indexed(line).name_for(GITHUB_FP), None, "{line:?}");
        }
    }

    #[test]
    fn files_are_all_read_and_missing_ones_are_no_obstacle() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent");
        let first = dir.path().join("known_hosts");
        let second = dir.path().join("known_hosts2");
        std::fs::write(&first, format!("first.example {GITHUB_KEY}\n")).unwrap();
        std::fs::write(&second, format!("second.example {GITHUB_KEY}\n")).unwrap();

        let index = index_files(&[absent.clone(), first, second]);
        assert_eq!(
            index.name_for(GITHUB_FP).as_deref(),
            Some("first.example, second.example")
        );
        assert_eq!(index_files(&[absent]).name_for(GITHUB_FP), None);
        assert_eq!(index_files(&[]).name_for(GITHUB_FP), None);
    }

    #[test]
    fn a_known_hosts_that_is_not_a_file_is_ignored_rather_than_waited_on() {
        // A FIFO would block a read-only open until a writer showed up, and
        // this runs while the one-signature-at-a-time gate is held: every
        // later signature would stall rather than time out. Reaching the
        // assertion at all is the test.
        use std::os::unix::ffi::OsStrExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: mkfifo only reads the path it is given.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        assert_eq!(index_files(&[path]).name_for(GITHUB_FP), None);
    }

    #[test]
    fn one_undecodable_byte_does_not_hide_the_rest_of_the_file() {
        // known_hosts is a byte-oriented line file. A stray byte in a comment
        // must cost that line, not every host key after it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut contents = b"# \xff\xfe not utf-8\n".to_vec();
        contents.extend_from_slice(format!("github.com {GITHUB_KEY}\n").as_bytes());
        std::fs::write(&path, contents).unwrap();

        assert_eq!(
            index_files(&[path]).name_for(GITHUB_FP).as_deref(),
            Some("github.com")
        );
    }

    #[test]
    fn an_implausibly_large_file_is_left_unread() {
        let dir = tempfile::tempdir().unwrap();
        let huge = dir.path().join("known_hosts");
        // one real entry, buried past the cap
        let padding = "#".repeat(usize::try_from(MAX_KNOWN_HOSTS_BYTES).unwrap() + 1);
        std::fs::write(&huge, format!("{padding}\ngithub.com {GITHUB_KEY}\n")).unwrap();
        assert_eq!(index_files(&[huge]).name_for(GITHUB_FP), None);
    }

    #[tokio::test]
    async fn names_come_back_in_the_order_they_were_asked_for() {
        // What the agent actually calls: one pass over the files for every
        // binding on a connection, answers lined up with the questions.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("known_hosts");
        std::fs::write(&file, format!("server.internal {GITHUB_KEY}\n")).unwrap();
        let resolver = HostNames::with_files(vec![file]);

        let names = resolver
            .names_for(vec![
                "SHA256:nothing-knows-this".to_string(),
                GITHUB_FP.to_string(),
            ])
            .await;
        assert_eq!(
            names,
            vec![None, Some("server.internal".to_string())],
            "an unknown host must not borrow the next one's name"
        );
    }

    #[tokio::test]
    async fn a_hashed_file_still_names_what_it_can() {
        // Hashing is per entry, so a plain line beside hashed ones resolves,
        // and only the misses go unexplained-but-logged.
        // a second, unrelated key, generated so the test needs no published
        // constant for it
        let other = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let other_line = other.public_key().to_openssh().unwrap();
        let other_fp = other
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("known_hosts");
        std::fs::write(
            &file,
            format!("|1|F1E2D3=|C4B5A6= {GITHUB_KEY}\nserver.internal {other_line}\n"),
        )
        .unwrap();
        let resolver = HostNames::with_files(vec![file]);

        // the hashed one cannot be named; the plain one still is
        assert_eq!(
            resolver
                .names_for(vec![GITHUB_FP.to_string(), other_fp.clone()])
                .await,
            vec![None, Some("server.internal".to_string())]
        );
        // asking only about the plain one leaves nothing to explain
        assert_eq!(
            resolver.names_for(vec![other_fp]).await,
            vec![Some("server.internal".to_string())]
        );
        // and a file of nothing but hashed entries names nothing at all
        let dir = tempfile::tempdir().unwrap();
        let only_hashed = dir.path().join("known_hosts");
        std::fs::write(&only_hashed, format!("|1|F1E2D3=|C4B5A6= {GITHUB_KEY}\n")).unwrap();
        assert_eq!(
            HostNames::with_files(vec![only_hashed])
                .names_for(vec![GITHUB_FP.to_string()])
                .await,
            vec![None]
        );
    }

    #[tokio::test]
    async fn with_no_files_every_host_stays_a_fingerprint() {
        let resolver = HostNames::with_files(Vec::new());
        assert_eq!(
            resolver.names_for(vec![GITHUB_FP.to_string()]).await,
            vec![None]
        );
        // and asking nothing is not an error
        assert!(resolver.names_for(Vec::new()).await.is_empty());
    }

    #[test]
    fn the_default_files_are_the_ones_openssh_uses() {
        let files = default_files();
        assert!(files.iter().any(|f| f.ends_with(".ssh/known_hosts")));
        assert!(files.contains(&PathBuf::from("/etc/ssh/ssh_known_hosts")));
        assert!(files.contains(&PathBuf::from("/etc/ssh/ssh_known_hosts2")));
        // and reading whatever this machine has must not fail or hang
        assert_eq!(index_files(&files).name_for("SHA256:not-a-host-key"), None);
    }
}
