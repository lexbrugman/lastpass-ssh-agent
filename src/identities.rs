//! The identities the agent serves, written down between starts.
//!
//! Item ids, display names and public keys — what `ssh-add -L` hands to anyone
//! who asks, and nothing else. Kept beside the socket so a start can bind
//! without a vault call: the vault is then opened only when a signature needs
//! it, which is the one moment a prompt is expected anyway.
//!
//! Two rules keep it honest. It is written only from a set the agent is
//! actually serving, never from a scan that failed, so a vault that would not
//! open cannot shrink what the next start offers. And a file that will not
//! decode reads as absent — the next scan rewrites it — where one that cannot
//! be *read* is an error, because something usable may be sitting there.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remembered {
    #[serde(default)]
    pub keys: Vec<RememberedKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RememberedKey {
    pub id: String,
    pub name: String,
    /// One `OpenSSH` public-key line, as `ssh-add -L` prints it.
    pub public: String,
}

/// Thousands of keys fit in a fraction of this, so anything larger is not a
/// file this wrote. Read one byte past it on purpose: an oversized file then
/// fails to decode rather than being cut to a length that happens to parse.
const MAX_BYTES: usize = 1024 * 1024;

/// Beside the socket; see `files::beside`.
pub fn path_for(socket: &Path) -> PathBuf {
    crate::files::beside(socket, ".identities")
}

/// What the last start wrote down, or `None` when nothing is there yet.
pub fn load(path: &Path) -> Result<Option<Remembered>> {
    use std::io::Read as _;

    let Some(file) = crate::files::open_regular(path)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;

    let decoded = if bytes.len() > MAX_BYTES {
        Err("larger than anything this writes".to_string())
    } else {
        String::from_utf8(bytes)
            .map_err(|e| e.to_string())
            .and_then(|text| toml::from_str::<Remembered>(&text).map_err(|e| e.to_string()))
    };
    match decoded {
        Ok(remembered) => Ok(Some(remembered)),
        // Nothing recoverable is in a file that will not decode, and the next
        // successful scan replaces it — so it reads as absent rather than
        // stopping a start over a file nobody needs.
        Err(why) => {
            tracing::warn!(path = %path.display(),
                "ignoring the remembered identities, which will not decode ({why})");
            Ok(None)
        }
    }
}

/// Write them down, replacing whatever was there. 0600 because it is the
/// agent's own state; `files::write_private` says why the write is staged.
pub fn save(path: &Path, remembered: &Remembered) -> Result<()> {
    let text = toml::to_string(remembered).map_err(cannot_encode)?;
    crate::files::write_private(path, text.as_bytes(), 0o600)
}

/// Discard them. Already gone is the state this asks for, so that is success.
pub fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(()) => Ok(()),
    }
}

/// Write them down if that can be done, and say so if not. For the callers that
/// must go on either way: a start that cannot write beside its own socket still
/// serves, and a refresh that cannot is still a refresh of what is served.
pub fn save_best_effort(path: &Path, remembered: &Remembered) {
    save(path, remembered).unwrap_or_else(could_not_save);
}

/// Writing beside a socket that is bound cannot fail in practice, so the edge
/// is excluded from coverage rather than pretended testable.
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "by value is what unwrap_or_else hands a function"
)]
fn could_not_save(e: Error) {
    tracing::warn!("could not write the identities down for the next start: {e}");
}

/// Serialising three strings per key cannot fail for a value this code built,
/// so the edge is excluded from coverage rather than pretended testable.
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "by value is what map_err hands a function"
)]
fn cannot_encode(e: toml::ser::Error) -> Error {
    Error::State(format!("cannot encode the remembered identities: {e}"))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn sample() -> Remembered {
        Remembered {
            keys: vec![
                RememberedKey {
                    id: "1".into(),
                    name: "one".into(),
                    public: "ssh-ed25519 AAAA one".into(),
                },
                RememberedKey {
                    id: "2".into(),
                    name: "two".into(),
                    public: "ssh-rsa BBBB two".into(),
                },
            ],
        }
    }

    #[test]
    fn the_file_sits_beside_the_socket() {
        assert_eq!(
            path_for(Path::new("/run/user/1000/agent.sock")),
            Path::new("/run/user/1000/agent.sock.identities")
        );
    }

    #[test]
    fn what_was_saved_is_what_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities");
        save(&path, &sample()).unwrap();
        assert_eq!(load(&path).unwrap().unwrap(), sample());
    }

    #[test]
    fn nothing_written_yet_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(&dir.path().join("absent")).unwrap(), None);
    }

    #[test]
    fn saving_again_replaces_rather_than_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities");
        save(&path, &sample()).unwrap();
        let fewer = Remembered {
            keys: sample().keys[..1].to_vec(),
        };
        save(&path, &fewer).unwrap();
        assert_eq!(load(&path).unwrap().unwrap(), fewer);
    }

    #[test]
    fn the_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities");
        save(&path, &sample()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    /// Bytes that will not decode read as an empty file rather than a broken
    /// one: the next scan rewrites them, and stopping a start over a file nobody
    /// needs would be the wrong failure.
    fn expect_reads_as_absent(bytes: &[u8], case: &str) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities");
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(load(&path).unwrap(), None, "{case}");
    }

    #[test]
    fn a_file_that_is_not_toml_reads_as_absent() {
        expect_reads_as_absent(b"this is not = toml =", "not toml");
    }

    #[test]
    fn a_file_with_a_field_this_never_wrote_reads_as_absent() {
        // A hand edit adding a field is not something to guess a meaning for.
        expect_reads_as_absent(
            b"[[keys]]\nid = \"1\"\nname = \"n\"\npublic = \"p\"\nextra = 1\n",
            "unknown field",
        );
    }

    #[test]
    fn a_file_that_is_not_utf8_reads_as_absent() {
        expect_reads_as_absent(b"[[keys]]\nid = \"\xff\xfe\"\n", "not utf-8");
    }

    #[test]
    fn a_file_larger_than_anything_this_writes_reads_as_absent() {
        let mut bytes = b"# ".to_vec();
        bytes.resize(MAX_BYTES + 64, b'#');
        expect_reads_as_absent(&bytes, "oversized");
    }

    #[test]
    fn an_empty_file_is_an_empty_list() {
        // Valid TOML with no keys: written by a start that served nothing, so
        // it is a real answer rather than something to reject.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities");
        std::fs::write(&path, b"").unwrap();
        assert_eq!(load(&path).unwrap(), Some(Remembered::default()));
    }

    #[test]
    fn a_file_that_cannot_be_read_is_an_error_not_an_absence() {
        // "Nothing there" and "something there but unreadable" must not look
        // alike: the second may hold a working list a scan would then discard.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities");
        save(&path, &sample()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn discarding_removes_the_file_and_is_content_with_it_already_gone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities");
        save(&path, &sample()).unwrap();
        remove(&path).unwrap();
        assert_eq!(load(&path).unwrap(), None);
        remove(&path).unwrap();
    }

    #[test]
    fn a_discard_that_cannot_happen_is_reported() {
        // A directory in its place: not something this writes, but the error
        // must travel rather than read as "already gone".
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities");
        std::fs::create_dir(&path).unwrap();
        assert!(remove(&path).is_err());
    }

    #[test]
    fn a_symlink_is_refused() {
        // The agent writes this file itself, so a link at its name was put
        // there by something else — `files::open_regular` says why that is
        // refused rather than followed.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        save(&real, &sample()).unwrap();
        let link = dir.path().join("identities");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(load(&link).is_err());
    }
}
