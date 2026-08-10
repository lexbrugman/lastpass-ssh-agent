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
    fn default_socket_location_is_stable() {
        let dir = default_socket_dir().unwrap();
        assert!(dir.to_string_lossy().contains("lastpass-ssh-agent"));
        let path = default_socket_path().unwrap();
        assert!(path.ends_with("agent.sock"));
        assert!(path.starts_with(dir));
    }
}
