//! Stamps the binary with the commit it was built from, so `--version` can
//! identify an exact build. The package version itself is CalVer
//! (`YYYY.MMDD.PATCH`), so the date is already in `CARGO_PKG_VERSION`.
#![allow(clippy::doc_markdown, reason = "build script, not published docs")]

use std::process::Command;

fn main() {
    // Rebuild when the commit moves. On a branch checkout HEAD only holds
    // `ref: refs/heads/<branch>` and never changes as you commit, so the
    // branch's own ref file has to be watched too — otherwise the stamp
    // silently keeps naming an older commit.
    for path in head_ref_files() {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=LASTPASS_SSH_AGENT_COMMIT");

    let commit = std::env::var("LASTPASS_SSH_AGENT_COMMIT")
        .ok()
        .or_else(git_commit)
        // building from a release tarball: no git, and nothing to guess
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=LASTPASS_SSH_AGENT_COMMIT={commit}");
}

/// Files whose contents decide what HEAD resolves to.
fn head_ref_files() -> Vec<String> {
    let Some(git_dir) = git_dir() else {
        return Vec::new();
    };
    let mut files = vec![format!("{git_dir}/HEAD")];
    if let Ok(head) = std::fs::read_to_string(format!("{git_dir}/HEAD")) {
        if let Some(reference) = head.trim().strip_prefix("ref: ") {
            files.push(format!("{git_dir}/{reference}"));
            // a packed ref has no file of its own; this is where it lives
            files.push(format!("{git_dir}/packed-refs"));
        }
    }
    files
}

/// The real git directory. In a linked worktree `.git` is a file holding a
/// `gitdir:` pointer, so watching `.git/HEAD` blindly would watch nothing
/// and leave the commit stamp frozen at whatever the first build saw.
fn git_dir() -> Option<String> {
    let meta = std::fs::metadata(".git").ok()?;
    if meta.is_dir() {
        return Some(".git".into());
    }
    let pointer = std::fs::read_to_string(".git").ok()?;
    let path = pointer.trim().strip_prefix("gitdir:")?.trim();
    (!path.is_empty()).then(|| path.to_string())
}

fn git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    (!commit.is_empty()).then(|| commit.to_string())
}
