//! Helpers shared by the crate's unit tests.

use std::path::{Path, PathBuf};

/// Write an executable shell script and return its path.
///
/// Executing a file that any process holds a write descriptor for fails with
/// `ETXTBSY`, and these tests reach that race: they write scripts and spawn
/// processes from many threads at once, so a fork can inherit the descriptor
/// this function is writing through and keep the file busy until that child
/// execs. Writing to a staging name and renaming does *not* help — the check
/// is against the inode, which `rename` does not change.
///
/// So the file that gets executed is created by a separate process instead.
/// Its write descriptor never exists in this address space, so none of our
/// forks can inherit one, and `cp` has exited before the script is run.
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
