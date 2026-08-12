//! Stamps the binary with the version and the commit it was built from, so
//! `--version` can identify an exact build.
//!
//! Neither is read from `Cargo.toml`. The released version is decided by the
//! release pipeline and never committed — `[package] version` is a permanent
//! placeholder — so both values arrive the same way: from the environment when
//! CI sets them, from git for a build off a checkout, and as a placeholder for
//! a build from a source tarball that has neither.
#![allow(clippy::doc_markdown, reason = "build script, not published docs")]

use std::path::{Path, PathBuf};
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

    secure_enclave_shim();
}

/// Path to the Swift half of the Secure Enclave store.
const SHIM: &str = "swift/secure_enclave.swift";

/// Compile `swift/secure_enclave.swift` into the binary, on macOS only.
///
/// Skipped in two cases, and the difference between them matters:
///
/// - Not building for macOS. There is no such code in the crate then, since the
///   store is behind a `cfg`, so there is nothing to link.
/// - Building *for* macOS from somewhere else. `cargo clippy --target
///   aarch64-apple-darwin` runs on the Linux runner and in the container to
///   type-check the macOS-gated code, and type-checking never links — so a
///   missing Swift toolchain must not fail it. A real cross-build would fail at
///   the link step instead, which is honest: the release macOS binaries are
///   built on macOS.
fn secure_enclave_shim() {
    println!("cargo:rerun-if-changed={SHIM}");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    if !cfg!(target_os = "macos") {
        println!("cargo:warning=not on macOS: skipping the Swift Secure Enclave shim (this build can be type-checked but not linked)");
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("cargo always sets OUT_DIR"));
    let object = out_dir.join("secure_enclave.o");
    let archive = out_dir.join("liblssha_secure_enclave.a");

    // Every architecture is built from one macOS runner, so the target cannot
    // be left to swiftc's default — that would compile the host's.
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("cargo always sets TARGET_ARCH");
    let triple = match arch.as_str() {
        "x86_64" => "x86_64-apple-macos11.0",
        _ => "arm64-apple-macos11.0",
    };

    let sdk = xcrun(["--show-sdk-path", "--sdk", "macosx"]);
    let swiftc = xcrun(["--find", "swiftc"]);
    let ar = xcrun(["--find", "ar"]);

    run(
        &swiftc,
        &[
            "-emit-object".as_ref(),
            "-parse-as-library".as_ref(),
            "-O".as_ref(),
            // Said rather than inherited: a bare `swiftc` compiles in whatever
            // language mode its toolchain defaults to, and that default moves.
            // 5 rather than 6 only because `--HEAD` builds on the user's own
            // machine, and asking for 6 would refuse to compile on a toolchain
            // that predates it. The shim does pass Swift 6 mode — strict
            // concurrency included — so raising this is free whenever the
            // oldest Xcode worth supporting has it.
            "-swift-version".as_ref(),
            "5".as_ref(),
            "-target".as_ref(),
            triple.as_ref(),
            "-sdk".as_ref(),
            sdk.as_ref(),
            "-o".as_ref(),
            object.as_os_str(),
            SHIM.as_ref(),
        ],
    );
    run(
        &ar,
        &["rcs".as_ref(), archive.as_os_str(), object.as_os_str()],
    );

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=lssha_secure_enclave");
    // The Swift runtime ships with the OS from 10.14.4 on, so this links
    // against the copy in the SDK rather than carrying one along.
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    // Not the same directory, and both are needed. Building for a deployment
    // target older than the toolchain makes swiftc emit references to
    // back-deployment shims — `swiftCompatibility56` and friends — which exist
    // only in the toolchain, never in the SDK. Without this the link fails on
    // undefined `__swift_FORCE_LOAD_$_swiftCompatibility56`.
    let toolchain = Path::new(&swiftc)
        .ancestors()
        .nth(2)
        .expect("swiftc lives at <toolchain>/usr/bin/swiftc")
        .join("lib/swift/macosx");
    println!("cargo:rustc-link-search=native={}", toolchain.display());
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=Security");
    // For the one sentence the Touch ID sheet shows.
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");
}

/// Ask the active toolchain where something is, by absolute path.
///
/// `/usr/bin/xcrun` rather than a bare `xcrun`, so nothing earlier on `PATH`
/// can substitute a swiftc of its own into an object file that gets linked into
/// the released binary. The idea is GoDaddy's `hardware-enclave`, which
/// documents it as build-time trust; it costs nothing to copy.
fn xcrun<const N: usize>(args: [&str; N]) -> String {
    let output = Command::new("/usr/bin/xcrun")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("cannot run /usr/bin/xcrun {}: {e}", args.join(" ")));
    assert!(
        output.status.success(),
        "/usr/bin/xcrun {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("xcrun prints a path")
        .trim()
        .to_string()
}

/// Run one build step, failing the build with its own diagnostics.
fn run(program: &str, args: &[&std::ffi::OsStr]) {
    let status = Command::new(program)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("cannot run {program}: {e}"));
    assert!(status.success(), "{program} failed");
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
