//! Helpers shared by the crate's unit tests.

use std::path::{Path, PathBuf};

/// Open a pty pair: the master, a keepalive handle on the slave, and the
/// slave's path.
///
/// The keepalive is not spare: a pty master errors with `EIO` the moment no
/// slave is open, so a test holding only the master would fail for reasons that
/// have nothing to do with what it is testing. Tests drive the prompts through
/// a pty because `/dev/tty` belongs to whoever runs the suite.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn open_pty() -> (std::fs::File, std::fs::File, PathBuf) {
    use std::os::unix::io::FromRawFd as _;

    let mut master: libc::c_int = 0;
    let mut slave: libc::c_int = 0;
    // SAFETY: openpty writes two fds; name/termios/winsize may be null.
    let rc = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty failed");
    // SAFETY: ptsname on a fresh valid master fd.
    let name = unsafe { libc::ptsname(master) };
    assert!(!name.is_null());
    let path = PathBuf::from(
        // SAFETY: ptsname returned a non-null pointer to a NUL-terminated name.
        unsafe { std::ffi::CStr::from_ptr(name) }
            .to_string_lossy()
            .to_string(),
    );
    // SAFETY: master and slave are valid fds we own; File takes ownership.
    let (master, keepalive) = unsafe {
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    };
    (master, keepalive, path)
}

/// Write an executable shell script and return its path.
///
/// Created by a separate process, which looks odd and is not: executing a file
/// any process holds a write descriptor for fails with `ETXTBSY`, and these
/// tests write scripts while spawning processes from several threads, so a fork
/// can inherit the descriptor and hold the file busy. Renaming does not help —
/// the check is against the inode. Letting `cp` own the descriptor keeps it out
/// of this address space entirely, so no fork of ours can inherit it.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    // Only ever written and read, never executed, so a descriptor leaking
    // from here is harmless.
    let staged = dir.join(format!(".{name}.staging"));
    let path = dir.join(name);
    std::fs::write(&staged, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();

    let status = std::process::Command::new("cp")
        .arg("-p")
        .arg(&staged)
        .arg(&path)
        .status()
        .expect("cp is available");
    assert!(status.success(), "cp {staged:?} -> {path:?} failed");
    path
}
