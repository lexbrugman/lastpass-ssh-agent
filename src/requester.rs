//! Who is asking: the process behind a signing request, and what it was
//! started from.
//!
//! `ssh` says nothing about whether it was you. The chain of parent processes
//! above it — a shell in a terminal, an editor, a build — is what a person
//! recognises in a prompt, and what a request from somewhere unexpected stands
//! out by. Looked up once per request and carried in the confirmation
//! context, so the prompt and a remembered approval describe one snapshot.
//!
//! Every name here is untrusted: whoever spawned the processes chose them, and
//! they are escaped before anything shows them. Reading a process's executable
//! and parent is the one platform-specific part, and it lives in `process_path`
//! and `parent_pid` as plain lookups.

use crate::text::escape_for_display;

/// The requesting process as the prompt names it, and what it was started
/// from. Both escaped: whoever spawned the processes chose the names.
#[derive(Debug, Clone)]
pub struct Requester {
    pub process: String,
    pub origin: Vec<Ancestor>,
}

/// One process above the requester: named for the prompt, and by its whole
/// path for what a remembered approval is keyed on — a name is what a person
/// recognises, and a path is what two processes cannot share by choosing a
/// file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestor {
    pub name: String,
    pub path: String,
}

impl Requester {
    /// The process behind a pid, when its executable can be read at all.
    pub fn of(pid: i32) -> Option<Self> {
        Some(Self {
            process: escape_for_display(&process_path(pid)?),
            origin: origin_chain(pid),
        })
    }
}

/// Executable path of a pid, best effort.
fn process_path(pid: i32) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let size = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).expect("positive constant");
        let mut buf = vec![0u8; size];
        // SAFETY: proc_pidpath writes at most buf.len() bytes into buf.
        let len = unsafe {
            libc::proc_pidpath(
                pid,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                u32::try_from(size).expect("buffer fits u32"),
            )
        };
        let len = usize::try_from(len).ok().filter(|l| *l > 0)?;
        Some(String::from_utf8_lossy(&buf[..len]).to_string())
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.display().to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

/// Parent of a pid, best effort. `None` for anything that cannot be asked.
fn parent_pid(pid: i32) -> Option<i32> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: proc_bsdinfo is plain data, for which all-zero is a value.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
            .expect("a small struct");
        // SAFETY: the buffer is exactly `size` bytes of a proc_bsdinfo, which
        // is what this flavor fills in.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&raw mut info).cast::<libc::c_void>(),
                size,
            )
        };
        // Anything short of the whole struct is a failure, in the call's own
        // convention.
        (written == size)
            .then(|| i32::try_from(info.pbi_ppid).ok())
            .flatten()
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|rest| rest.trim().parse().ok())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

/// How many ancestors are named: enough for `ssh` under `git` under a shell
/// under a terminal under the app that opened it, without walking a runaway
/// tree.
const MAX_ORIGIN_DEPTH: usize = 8;

/// The names of a process's ancestors, nearest first, up to the top of the
/// user's own tree.
fn origin_chain(pid: i32) -> Vec<Ancestor> {
    origin_chain_from(pid, &parent_pid, &process_path)
}

/// `origin_chain` over whichever lookups are given, so the walk can be tested
/// on a tree of the test's own making.
///
/// Stops before pid 1 — the tree's root names no application — and at the
/// first ancestor that cannot be read. Consecutive repeats of one executable, a
/// shell that ran a shell, collapse into one, so the line reads as the steps
/// that matter. Cycles need no guard: the kernel keeps this a tree, and the depth
/// bound holds regardless.
///
/// The lookups are trait objects rather than generics so that there is one
/// instantiation: the coverage summary accounts for a generic function's
/// branches per instantiation, and no single test tree takes every exit.
fn origin_chain_from(
    pid: i32,
    parent: &dyn Fn(i32) -> Option<i32>,
    path: &dyn Fn(i32) -> Option<String>,
) -> Vec<Ancestor> {
    let mut ancestors: Vec<Ancestor> = Vec::new();
    let mut current = pid;
    // Bounds the ancestors walked, not the names kept: a chain of one name
    // repeated collapses to one entry, and must still end.
    for _ in 0..MAX_ORIGIN_DEPTH {
        let Some(next) = parent(current).filter(|next| *next > 1) else {
            break;
        };
        let Some(path) = path(next) else {
            break;
        };
        let path = escape_for_display(&path);
        if ancestors.last().is_none_or(|last| last.path != path) {
            ancestors.push(Ancestor {
                name: display_name(&path),
                path,
            });
        }
        current = next;
    }
    ancestors
}

/// How an ancestor is named: the app bundle when it runs from one — the
/// outermost, so a helper process inside an editor is named for the editor —
/// and the executable's file name otherwise. `path` is escaped text already.
fn display_name(path: &str) -> String {
    let bundle = path
        .split('/')
        .find_map(|part| part.strip_suffix(".app"))
        .filter(|stem| !stem.is_empty());
    bundle
        .or_else(|| path.rsplit('/').next())
        .unwrap_or(path)
        .to_string()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn this_process_has_an_executable_and_an_ancestry_and_pid_zero_has_neither() {
        let pid = std::process::id().cast_signed();
        assert!(process_path(pid).is_some());
        let this = Requester::of(pid).unwrap();
        assert!(!this.process.is_empty());
        assert!(
            !this.origin.is_empty(),
            "the test runner, at least, is above this process"
        );
        assert!(this.origin[0].path.starts_with('/'), "{:?}", this.origin[0]);
        // pid 0 / absurd pids have no executable path, and pid 1's ancestry
        // is nobody's application
        assert!(process_path(0).is_none());
        assert!(Requester::of(0).is_none());
        assert!(origin_chain(1).is_empty());
        let _ = parent_pid(0); // best effort either way
    }

    #[test]
    fn the_origin_walk_stops_at_the_root_and_collapses_repeats() {
        // 10 ← 9 ← 8 ← ... ← 1: a shell that ran a shell reads as one step,
        // and the root itself is never named.
        let parent = |pid: i32| (pid > 1).then_some(pid - 1);
        let path = |pid: i32| {
            Some(match pid {
                9 | 8 => "/bin/zsh".to_string(),
                7 => "/Applications/Terminal.app/Contents/MacOS/Terminal".to_string(),
                other => format!("/usr/bin/p{other}"),
            })
        };
        let names = |chain: Vec<Ancestor>| -> Vec<String> {
            chain.into_iter().map(|ancestor| ancestor.name).collect()
        };
        assert_eq!(
            names(origin_chain_from(10, &parent, &path)),
            ["zsh", "Terminal", "p6", "p5", "p4", "p3", "p2"]
        );
        // the path is kept beside the name, whole
        assert_eq!(
            origin_chain_from(10, &parent, &path)[1].path,
            "/Applications/Terminal.app/Contents/MacOS/Terminal"
        );
        // an ancestor that cannot be read ends the walk there
        let unreadable = |pid: i32| (pid != 7).then(|| format!("/usr/bin/p{pid}"));
        assert_eq!(
            names(origin_chain_from(10, &parent, &unreadable)),
            ["p9", "p8"]
        );
        // and a tree deeper than anyone reads is cut at the bound
        assert_eq!(
            origin_chain_from(100, &parent, &|pid| Some(format!("/p{pid}"))).len(),
            MAX_ORIGIN_DEPTH
        );
        // the bound is on ancestors walked: a chain of one name repeated
        // collapses to one entry and still ends
        let walked = std::cell::Cell::new(0);
        let counted = |pid: i32| {
            walked.set(walked.get() + 1);
            parent(pid)
        };
        assert_eq!(
            names(origin_chain_from(100, &counted, &|_| Some(
                "/bin/sh".to_string()
            ))),
            ["sh"]
        );
        assert_eq!(walked.get(), MAX_ORIGIN_DEPTH);
    }

    #[test]
    fn an_ancestor_is_named_for_its_app_bundle_or_its_executable() {
        assert_eq!(display_name("/usr/bin/git"), "git");
        // the outermost bundle: a helper inside an editor is the editor
        assert_eq!(
            display_name(
                "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)"
            ),
            "Visual Studio Code"
        );
        // a bare ".app" component names nothing, so the file name stands
        assert_eq!(display_name("/x/.app/bin/tool"), "tool");
        assert_eq!(display_name("noslash"), "noslash");
        // untrusted: a path that tries to redraw the dialog is escaped on the
        // way in, so name and path both show it literally
        let evil = origin_chain_from(2, &|pid: i32| (pid == 2).then_some(3), &|_| {
            Some("/tmp/evil\x1b[2J".to_string())
        });
        assert_eq!(evil[0].name, "evil\\x1b[2J");
        assert_eq!(evil[0].path, "/tmp/evil\\x1b[2J");
    }
}
