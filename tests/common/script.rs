//! Executable fixtures for the tests, written so that running them cannot
//! race the writing.
//!
//! Shared by the unit tests (through `testutil`) and the crates under
//! `tests/`, each of which declares this file as a module of its own.
#![allow(dead_code)] // each crate uses the part it needs

use std::path::{Path, PathBuf};

/// Write an executable shell script and return its path.
///
/// Created by a separate process, which looks odd and is not: executing a file
/// any process holds a write descriptor for fails with `ETXTBSY`, and these
/// tests write scripts while spawning processes from several threads, so a fork
/// can inherit the descriptor and hold the file busy. Renaming does not help —
/// the check is against the inode. Letting `cp` own the descriptor keeps it out
/// of this address space entirely, so no fork of ours can inherit it.
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
    assert!(
        status.success(),
        "cp {} -> {} failed",
        staged.display(),
        path.display()
    );
    path
}
