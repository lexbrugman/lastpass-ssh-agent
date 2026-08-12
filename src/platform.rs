use std::path::PathBuf;

use crate::error::{Error, Result};

/// Process-wide hardening. Must run before anything touches secrets.
///
/// - `RLIMIT_CORE = 0`: a crash while a private key is in memory must not
///   write that memory to a core file.
/// - `umask(077)`: every file/socket we create defaults to owner-only.
///
/// Deliberately NOT done (documented in the README): `mlock/MADV_DONTDUMP`
/// (key material lives milliseconds per signature and macOS swap is
/// encrypted) and `PT_DENY_ATTACH` (an attacker who can attach a debugger can
/// attach to `lpass` itself, which holds the whole vault).
pub fn harden() -> Result<()> {
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a valid rlimit struct and touches no other memory.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const no_core) };
    harden_check(rc)?;
    // SAFETY: umask is async-signal-safe and cannot fail.
    unsafe { libc::umask(0o077) };
    Ok(())
}

/// Lowering `RLIMIT_CORE` to 0/0 cannot fail (no EINVAL/EPERM case applies),
/// so the error edge is untestable and excluded from coverage.
#[cfg_attr(coverage_nightly, coverage(off))]
fn harden_check(rc: libc::c_int) -> Result<()> {
    if rc == 0 {
        return Ok(());
    }
    Err(Error::Harden(format!(
        "setrlimit(RLIMIT_CORE, 0): {}",
        std::io::Error::last_os_error()
    )))
}

/// Default directory for the agent socket. Must be private to the user;
/// socket.rs enforces 0700 on it regardless of what this returns.
pub fn default_socket_dir() -> Option<PathBuf> {
    socket_dir_from(runtime_dir(), dirs::home_dir())
}

/// The per-user runtime directory, where one exists. macOS has no XDG
/// runtime dir, so the socket lives under the home directory there.
#[cfg_attr(
    target_os = "macos",
    expect(clippy::missing_const_for_fn, reason = "not const on other platforms")
)]
fn runtime_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        None
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::runtime_dir()
    }
}

/// Pure so both the runtime-dir and home-dir paths are testable on every
/// platform, not just whichever one the test host happens to provide.
fn socket_dir_from(runtime: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(runtime) = runtime {
        return Some(runtime.join("lastpass-ssh-agent"));
    }
    let home = home?;
    #[cfg(target_os = "macos")]
    {
        Some(home.join("Library/Application Support/lastpass-ssh-agent"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(home.join(".lastpass-ssh-agent"))
    }
}

pub fn default_socket_path() -> Option<PathBuf> {
    default_socket_dir().map(|d| d.join("agent.sock"))
}

/// Whether the login session's screen is locked right now, when the platform
/// can say at all.
///
/// `None` means "no answer available here" rather than "unlocked", and the
/// caller treats it as a reason to stop asking rather than as a state. Keeping
/// the two apart is what lets the watcher above it be one portable piece of
/// logic with no `cfg` in it.
///
/// This is the entire platform surface of the screen-lock feature: a value to
/// look up, with every decision taken by portable code around it.
#[cfg(target_os = "macos")]
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn screen_is_locked() -> Option<bool> {
    use core_foundation::base::{CFType, TCFType as _};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::CFString;

    // SAFETY: the returned dictionary is owned by us (a Copy function), or null
    // when there is no GUI session to describe — a launchd daemon, or ssh into
    // this machine.
    let session: CFDictionaryRef = unsafe { CGSessionCopyCurrentDictionary() };
    if session.is_null() {
        return None;
    }
    // SAFETY: non-null, and created by a Copy function, so the wrapper takes
    // the reference we already own rather than retaining a second one.
    let session: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(session) };

    // Absent while unlocked rather than present-and-false, so a missing key is
    // an answer: not locked.
    session
        .find(CFString::from_static_string("CGSSessionScreenIsLocked"))
        .map_or(Some(false), |locked| {
            Some(locked.downcast::<CFBoolean>().is_some_and(Into::into))
        })
}

#[cfg(target_os = "macos")]
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGSessionCopyCurrentDictionary() -> core_foundation::dictionary::CFDictionaryRef;
}

/// No way to ask on this platform, so nothing watches. Config validation
/// refuses `lock_on_screen_lock` here, so a running agent never calls it.
#[cfg(not(target_os = "macos"))]
pub const fn screen_is_locked() -> Option<bool> {
    None
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn harden_disables_core_dumps_and_tightens_umask() {
        harden().unwrap();

        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: getrlimit writes into a valid rlimit struct.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut limit) },
            0
        );
        assert_eq!(limit.rlim_cur, 0);
        assert_eq!(limit.rlim_max, 0);

        // SAFETY: umask is process-global; read it by setting and restoring.
        let current = unsafe { libc::umask(0o077) };
        assert_eq!(current, 0o077);
    }

    #[test]
    fn socket_dir_prefers_runtime_dir_then_home() {
        let from_runtime = socket_dir_from(Some("/run/user/1".into()), Some("/home/u".into()));
        assert_eq!(
            from_runtime.unwrap(),
            PathBuf::from("/run/user/1/lastpass-ssh-agent")
        );

        let from_home = socket_dir_from(None, Some("/home/u".into())).unwrap();
        assert!(from_home.starts_with("/home/u"));
        assert!(from_home.to_string_lossy().contains("lastpass-ssh-agent"));

        // no runtime dir and no home: nothing to default to
        assert_eq!(socket_dir_from(None, None), None);
    }

    #[test]
    fn the_lock_state_is_either_an_answer_or_unavailable() {
        // Both outcomes are correct: a platform that cannot say returns None,
        // and one that can answers without failing. The point is that asking
        // is always safe — the watcher decides what the answer means.
        let _ = screen_is_locked();
    }

    #[test]
    fn default_socket_location_is_stable() {
        let dir = default_socket_dir().unwrap();
        assert!(dir.to_string_lossy().contains("lastpass-ssh-agent"));
        let path = default_socket_path().unwrap();
        assert!(path.ends_with("agent.sock"));
        assert!(path.starts_with(dir));
    }
}
