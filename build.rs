//! Stamps the binary with the version and the commit it was built from, so
//! `--version` can identify an exact build.
//!
//! Neither is read from `Cargo.toml`. The released version is decided by the
//! release pipeline and never committed — `[package] version` is a permanent
//! placeholder — so both values arrive the same way: from the environment when
//! CI sets them, from git for a build off a checkout, and as a placeholder for
//! a build from a source tarball that has neither.
#![allow(clippy::doc_markdown, reason = "build script, not published docs")]

use std::process::Command;

fn main() {
    // Re-stamp when the commit moves or a release tag arrives; without this
    // both values freeze at whatever the first build saw.
    for path in stamp_input_files() {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=LASTPASS_SSH_AGENT_COMMIT");
    println!("cargo:rerun-if-env-changed=LASTPASS_SSH_AGENT_VERSION");

    let commit = std::env::var("LASTPASS_SSH_AGENT_COMMIT")
        .ok()
        .or_else(git_commit)
        // building from a release tarball: no git, and nothing to guess
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=LASTPASS_SSH_AGENT_COMMIT={commit}");

    // A release build gets the version from the pipeline that is publishing
    // it. Anything else describes itself against the newest release tag, so a
    // build off dev reports `2026.811.2-5-gabc123def456` — the release it is
    // ahead of, and by how much — rather than claiming to be a release.
    let version = std::env::var("LASTPASS_SSH_AGENT_VERSION")
        .ok()
        .or_else(git_version)
        .unwrap_or_else(|| "dev".into());
    println!("cargo:rustc-env=LASTPASS_SSH_AGENT_VERSION={version}");
}

/// Files whose contents decide what the two stamps resolve to.
///
/// Split across two directories, and in a linked worktree they are not the
/// same one. HEAD is per-worktree; branches and tags belong to the repository
/// and live in its common directory, so watching those under the worktree's
/// own git directory would watch paths that do not exist — and a commit or a
/// fetched tag would leave both stamps frozen at whatever the last build saw.
fn stamp_input_files() -> Vec<String> {
    let mut files = Vec::new();

    if let Some(common) = git_common_dir() {
        // a ref packed by `git gc` has no file of its own; this is where both
        // the branch HEAD names and the release tags end up
        files.push(format!("{common}/packed-refs"));
        // an unpacked tag, so fetching a new release re-stamps the version
        files.push(format!("{common}/refs/tags"));
    }

    let Some(git_dir) = git_dir() else {
        return files;
    };
    files.push(format!("{git_dir}/HEAD"));
    // On a branch checkout HEAD only holds `ref: refs/heads/<branch>` and
    // never changes as you commit, so the branch's own ref file has to be
    // watched too. It is a shared ref, hence the common directory.
    if let Ok(head) = std::fs::read_to_string(format!("{git_dir}/HEAD")) {
        if let Some(reference) = head.trim().strip_prefix("ref: ") {
            if let Some(common) = git_common_dir() {
                files.push(format!("{common}/{reference}"));
            }
        }
    }
    files
}

/// The directory holding what every worktree of this repository shares.
///
/// Equal to `git_dir` in an ordinary checkout, and the main repository's
/// `.git` when this is a linked worktree.
fn git_common_dir() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-common-dir"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let dir = String::from_utf8(output.stdout).ok()?;
    let dir = dir.trim();
    (!dir.is_empty()).then(|| dir.to_string())
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

/// The newest release tag, plus how far past it this build is.
///
/// Restricted to `v<digit>…` so only release tags can name a build; anything
/// else someone tags locally must not turn a dev build into a version that
/// looks published. Fails on a clone with no tags — a shallow one, say — and
/// the caller falls back.
fn git_version() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--match", "v[0-9]*"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let described = String::from_utf8(output.stdout).ok()?;
    // tags carry the `v`, the version itself does not
    let version = described.trim().strip_prefix('v')?;
    (!version.is_empty()).then(|| version.to_string())
}
