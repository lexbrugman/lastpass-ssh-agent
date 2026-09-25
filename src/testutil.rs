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

/// The script writer the crates under `tests/` use too; one definition.
#[path = "../tests/common/script.rs"]
#[cfg_attr(coverage_nightly, coverage(off))]
mod script;
pub use script::write_script;

/// The throwaway keypairs, one definition for every test that needs one.
#[path = "../tests/common/fixtures.rs"]
pub mod fixtures;

/// Stand-in for `osascript`: a shell script that ignores the `AppleScript`
/// arguments and produces whatever the test needs.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn osascript_stub(dir: &Path, body: &str) -> PathBuf {
    write_script(dir, "osascript", body)
}
