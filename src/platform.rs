use std::path::PathBuf;

use crate::error::{Error, Result};

/// Process-wide hardening. Must run before anything touches secrets.
///
/// - `RLIMIT_CORE = 0`: a crash while a private key is in memory must not
///   write that memory to a core file.
/// - `umask(077)`: every file/socket we create defaults to owner-only.
/// - No debuggers: nothing else running as this user may attach to this
///   process or read its memory. The master password lives here between
///   signatures, and this is what keeps reading it from being one `ptrace`
///   away for any process of the user's. Root is not kept out, and cannot be.
///
/// The held password is also pinned in RAM, per buffer, by `pin`.
pub fn harden() -> Result<()> {
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a valid rlimit struct and touches no other memory.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const no_core) };
    harden_check(rc, "setrlimit(RLIMIT_CORE, 0)")?;
    harden_check(deny_debuggers(), "refusing debuggers")?;
    // SAFETY: umask is async-signal-safe and cannot fail.
    unsafe { libc::umask(0o077) };
    Ok(())
}

/// Lowering `RLIMIT_CORE` to 0/0 cannot fail (no EINVAL/EPERM case applies),
/// and neither call in `deny_debuggers` can with these arguments, so the error
/// edge is untestable and excluded from coverage.
#[cfg_attr(coverage_nightly, coverage(off))]
fn harden_check(rc: libc::c_int, what: &str) -> Result<()> {
    if rc == 0 {
        return Ok(());
    }
    Err(Error::Harden(format!(
        "{what}: {}",
        std::io::Error::last_os_error()
    )))
}

/// Not dumpable, which on Linux is also what closes `ptrace` and
/// `/proc/<pid>/mem` to other processes of the same user.
#[cfg(target_os = "linux")]
fn deny_debuggers() -> libc::c_int {
    // SAFETY: prctl with these arguments reads no memory.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }
}

/// What ssh-agent does on macOS: no later attach, and a debugger already
/// attached ends the process.
#[cfg(target_os = "macos")]
fn deny_debuggers() -> libc::c_int {
    // SAFETY: PT_DENY_ATTACH takes no pointers and touches no memory.
    unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) }
}

/// Nothing to do here, which is success.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const fn deny_debuggers() -> libc::c_int {
    0
}

/// Keep `len` bytes at `ptr` in RAM and out of any dump: never paged to swap,
/// never written by a crash. Page-granular, so whatever else shares those
/// pages comes along, which costs nothing.
///
/// `ptr` and `len` rather than a slice, so a buffer can be unpinned after it
/// has been wiped and its length zeroed.
pub fn pin(ptr: *const u8, len: usize) -> std::io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    let (start, span) = page_span(ptr as usize, len, page_size());
    // SAFETY: the span is whole pages containing memory this process owns;
    // mlock and madvise read nothing through the pointer.
    os_check(unsafe { libc::mlock(start as *const libc::c_void, span) })?;
    #[cfg(target_os = "linux")]
    os_check(unsafe { libc::madvise(start as *mut libc::c_void, span, libc::MADV_DONTDUMP) })?;
    Ok(())
}

/// Undo `pin`. Best effort: a page that stays locked costs nothing but the
/// page.
pub fn unpin(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let (start, span) = page_span(ptr as usize, len, page_size());
    // SAFETY: as in `pin`.
    let _ = unsafe { libc::munlock(start as *const libc::c_void, span) };
    #[cfg(target_os = "linux")]
    let _ = unsafe { libc::madvise(start as *mut libc::c_void, span, libc::MADV_DODUMP) };
}

/// The whole pages covering `len` bytes at `addr`: where they start, and how
/// long the run is.
const fn page_span(addr: usize, len: usize, page: usize) -> (usize, usize) {
    let start = addr - addr % page;
    let end = (addr + len).div_ceil(page) * page;
    (start, end - start)
}

fn page_size() -> usize {
    // SAFETY: sysconf reads no memory.
    usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096)
}

/// A failing return from a call that, with the arguments `pin` gives it, fails
/// only under a memory-lock limit exhausted by something else — excluded from
/// coverage, since a test cannot arrange that.
#[cfg_attr(coverage_nightly, coverage(off))]
fn os_check(rc: libc::c_int) -> std::io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
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

/// The login session's screen, as this platform can see it.
///
/// This is the entire platform surface of the screen-lock feature: one value to
/// look up, with every decision about what it means taken by `vaultlock`.
pub struct SessionScreen;

#[async_trait::async_trait]
impl crate::vaultlock::ScreenLock for SessionScreen {
    async fn is_locked(&self) -> Option<bool> {
        #[cfg(target_os = "macos")]
        {
            session_dictionary_says_locked()
        }
        #[cfg(target_os = "linux")]
        {
            crate::logind::locked_hint().await
        }
        // No way to ask here, so nothing watches. Config validation refuses
        // `lock_on_screen_lock` on these platforms, so a running agent never
        // reaches this.
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }
}

/// What `CGSessionCopyCurrentDictionary` says about the screen, if it says
/// anything.
#[cfg(target_os = "macos")]
#[cfg_attr(coverage_nightly, coverage(off))]
fn session_dictionary_says_locked() -> Option<bool> {
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

        // and nothing of ours may be attached to
        #[cfg(target_os = "linux")]
        // SAFETY: prctl with this option reads no memory.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);

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

    #[tokio::test]
    async fn the_lock_state_is_either_an_answer_or_unavailable() {
        // Both outcomes are correct: a platform that cannot say returns None,
        // and one that can answers without failing. The point is that asking
        // is always safe — the watcher decides what the answer means.
        use crate::vaultlock::ScreenLock as _;
        let _ = SessionScreen.is_locked().await;
    }

    #[test]
    fn default_socket_location_is_stable() {
        let dir = default_socket_dir().unwrap();
        assert!(dir.to_string_lossy().contains("lastpass-ssh-agent"));
        let path = default_socket_path().unwrap();
        assert!(path.ends_with("agent.sock"));
        assert!(path.starts_with(dir));
    }

    #[test]
    fn a_pinned_buffer_covers_whole_pages_and_comes_back_unpinned() {
        assert_eq!(page_span(4096, 10, 4096), (4096, 4096));
        assert_eq!(page_span(4100, 10, 4096), (4096, 4096));
        assert_eq!(page_span(4100, 4093, 4096), (4096, 8192));
        assert_eq!(page_span(0, 1, 4096), (0, 4096));

        let secret = [7u8; 100];
        pin(secret.as_ptr(), secret.len()).unwrap();
        unpin(secret.as_ptr(), secret.len());
        // nothing to pin is nothing to do
        pin(secret.as_ptr(), 0).unwrap();
        unpin(secret.as_ptr(), 0);
    }
}
