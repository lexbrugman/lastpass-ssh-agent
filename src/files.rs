//! The two file operations this agent does to its own directory.
//!
//! Both are written once here rather than in each caller, because both have a
//! detail that is easy to leave out and invisible when you do: a write that is
//! not atomic can be read half-finished, and an open that trusts a path can
//! block forever on something that is not a file. Neither shows up in testing;
//! both show up when something else is already going wrong.

use std::path::{Path, PathBuf};

use crate::error::Result;

/// Write `contents` to `path`, at `mode`, without the name ever holding a
/// half-written file.
///
/// Staged beside the destination and renamed over it. `rename` swaps the name
/// in one step, so a reader — or an `exec`, for the wrapper — either sees the
/// old file or the new one and never a partial write. Opening the destination
/// with `O_TRUNC` instead would be visible to anything reading it at that
/// moment, and for an executable it is the `ETXTBSY` race `AGENTS.md` describes.
///
/// The staging name carries this process's id, so two agents doing this at once
/// stage into files of their own instead of truncating each other's work or
/// renaming it out from under the other.
///
/// The mode is set twice on purpose: once at creation, so the file is never
/// world-readable even for an instant, and once afterwards, because a staging
/// file left behind by an earlier crash is reopened rather than created and
/// keeps whatever mode it already had.
pub fn write_private(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut staging = path.as_os_str().to_os_string();
    staging.push(format!(".{}", std::process::id()));
    let staging = PathBuf::from(staging);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&staging)?;
    file.write_all(contents)?;
    // Closed before the rename: a descriptor still open for writing is exactly
    // what makes an `exec` of that file fail.
    drop(file);
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&staging, path)?;
    Ok(())
}

/// Open `path`, but only if what is actually opened is a regular file.
///
/// `None` when there is nothing there, which is a state every caller has a
/// meaning for.
///
/// The type is checked on the open file rather than on the path, and the open
/// itself is non-blocking. Both matter. A FIFO opened for reading waits for a
/// writer that may never come, and this runs on the single thread the agent
/// serves every connection from, so one would wedge the whole agent — checking
/// the path first and opening second leaves a window in which the answer can
/// change between the two. `knownhosts::read_small` guards its own read the
/// same way, and for the same reason.
///
/// A symlink is refused outright, which is why `O_NOFOLLOW` is here as well.
/// These are files the agent writes into its own directory, so a link at one of
/// those names was put there by something else — and following it would let
/// that something else choose which file the agent reads, quietly, while every
/// regular-file check still passed. `knownhosts` is deliberately not read this
/// way: a symlinked `known_hosts` is an ordinary thing for a person to have.
pub fn open_regular(path: &Path) -> Result<Option<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
    {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(file) => file,
    };
    if file.metadata()?.file_type().is_file() {
        Ok(Some(file))
    } else {
        Err(crate::error::Error::State(format!(
            "{} is not a regular file — refusing to read it",
            path.display()
        )))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn expect_written(mode: u32) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("written");
        write_private(&path, b"contents", mode).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"contents");
        let got = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(got, mode, "mode was {got:o}");
    }

    #[test]
    fn a_private_file_is_written_at_the_mode_asked_for() {
        expect_written(0o600);
        expect_written(0o700);
    }

    #[test]
    fn writing_again_replaces_what_was_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("written");
        write_private(&path, b"first", 0o600).unwrap();
        write_private(&path, b"second", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn a_staging_file_left_by_a_crash_is_reused_and_re_secured() {
        // Its mode is whatever the crash left, so creating it does not set one.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("written");
        let staging = dir.path().join(format!("written.{}", std::process::id()));
        std::fs::write(&staging, b"stale").unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o666)).unwrap();

        write_private(&path, b"fresh", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"fresh");
        let got = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(got, 0o600, "mode was {got:o}");
    }

    #[test]
    fn writing_somewhere_that_does_not_exist_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(write_private(&dir.path().join("no").join("where"), b"x", 0o600).is_err());
    }

    #[test]
    fn nothing_there_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(open_regular(&dir.path().join("absent")).unwrap().is_none());
    }

    #[test]
    fn a_regular_file_opens_and_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain");
        std::fs::write(&path, b"hello").unwrap();

        let mut read = String::new();
        open_regular(&path)
            .unwrap()
            .unwrap()
            .read_to_string(&mut read)
            .unwrap();
        assert_eq!(read, "hello");
    }

    #[test]
    fn something_that_is_not_a_file_is_refused_rather_than_read() {
        // A FIFO, which is the case that would otherwise block: the open
        // returns because of O_NONBLOCK, and the type is then read from the
        // handle rather than from the path.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo");
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);

        let error = open_regular(&path).unwrap_err().to_string();
        assert!(error.contains("not a regular file"), "{error}");
    }

    #[test]
    fn a_symlink_is_refused_even_when_it_points_at_a_real_file() {
        // Otherwise whoever put the link there chooses which file the agent
        // reads, and every check after the open still passes.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, b"contents").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(open_regular(&link).is_err());
        // and the thing it pointed at is still readable on its own name
        assert!(open_regular(&real).unwrap().is_some());
    }

    #[test]
    fn a_file_that_cannot_be_opened_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let shut = dir.path().join("shut");
        std::fs::create_dir(&shut).unwrap();
        let path = shut.join("inside");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();

        let refused = open_regular(&path).is_err();
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(refused);
    }
}
