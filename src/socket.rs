use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

use crate::error::{Error, Result};

/// Unlinks the socket when the agent exits (Drop or signal path).
///
/// If someone removes the socket while this agent runs and a replacement
/// agent binds the same path, this unlinks the replacement's socket. That
/// cannot be prevented with filesystem primitives: comparing the inode
/// recorded at bind time does not work, because Linux immediately reuses
/// inode numbers, and the kernel's coarse timestamp granularity gives the
/// replacement an identical ctime as well — the two are indistinguishable.
/// OpenSSH's own ssh-agent unlinks unconditionally for the same reason.
#[derive(Debug)]
pub struct SocketGuard {
    path: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Create the agent socket with a defensive posture:
/// - parent directory must be (or become) 0700, owned by us, not a symlink
/// - a live socket at the path means another agent is running: refuse
/// - a dead leftover socket is removed
/// - the socket itself is chmod 0600 after bind
pub fn bind(path: &Path) -> Result<(UnixListener, SocketGuard)> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| {
            Error::Socket(format!(
                "socket path {} has no parent directory",
                path.display()
            ))
        })?;
    prepare_dir(dir)?;

    match fs::symlink_metadata(path) {
        Ok(meta) if !is_socket(&meta) => {
            return Err(Error::Socket(format!(
                "{} exists and is not a socket — refusing to remove it",
                path.display()
            )));
        }
        Ok(_) => {
            // Socket file exists: live agent or stale leftover? Only a
            // refused connection proves nothing is listening. Treating any
            // failure as proof would let a transient one (EMFILE while the
            // machine is out of descriptors, say) unlink a live agent's
            // socket and cut it off from every future client.
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(Error::Socket(format!(
                        "another agent is already listening on {}",
                        path.display()
                    )))
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tracing::info!(path = %path.display(), "removing stale socket");
                    fs::remove_file(path)?;
                }
                Err(e) => {
                    return Err(Error::Socket(format!(
                        "cannot tell whether an agent is listening on {}: {e} — \
                         refusing to remove it",
                        path.display()
                    )))
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    let listener = UnixListener::bind(path)
        .map_err(|e| Error::Socket(format!("cannot bind {}: {e}", path.display())))?;
    // umask(077) already guarantees this, but be explicit.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok((
        listener,
        SocketGuard {
            path: path.to_path_buf(),
        },
    ))
}

fn prepare_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    validate_dir(dir)
}

/// The invariants `bind` enforces on the socket directory, check-only.
/// Used by `doctor` so it reports what `start` would refuse. A directory
/// that does not exist yet is fine — `bind` creates it correctly.
pub fn validate_dir(dir: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        other => other?,
    };
    if meta.file_type().is_symlink() {
        return Err(Error::Socket(format!(
            "socket directory {} is a symlink — refusing",
            dir.display()
        )));
    }
    if !meta.is_dir() {
        return Err(Error::Socket(format!(
            "socket directory {} is not a directory",
            dir.display()
        )));
    }
    // SAFETY: geteuid cannot fail and touches no memory.
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid {
        return Err(Error::Socket(format!(
            "socket directory {} is owned by uid {}, not us (uid {uid})",
            dir.display(),
            meta.uid()
        )));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(Error::Socket(format!(
            "socket directory {} is accessible by group/others (mode {mode:o}) — run: chmod 700 {}",
            dir.display(),
            dir.display()
        )));
    }
    // Owner needs rwx: without them `start` cannot create or reach the
    // socket, and doctor must not call such a directory healthy.
    if mode & 0o700 != 0o700 {
        return Err(Error::Socket(format!(
            "socket directory {} is not usable by its owner (mode {mode:o}) — run: chmod 700 {}",
            dir.display(),
            dir.display()
        )));
    }
    Ok(())
}

fn is_socket(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    meta.file_type().is_socket()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binds_with_correct_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("agent.sock");
        let (_listener, guard) = bind(&path).unwrap();

        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        let sock_mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(sock_mode & 0o777, 0o600);

        drop(guard);
        assert!(!path.exists(), "guard must unlink the socket");
    }

    #[test]
    fn validate_dir_passes_for_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        validate_dir(&dir.path().join("does-not-exist-yet")).unwrap();
    }

    #[tokio::test]
    async fn refuses_world_readable_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("open");
        fs::create_dir(&sub).unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
        let err = bind(&sub.join("agent.sock")).unwrap_err();
        assert!(err.to_string().contains("group/others"), "{err}");
    }

    #[tokio::test]
    async fn refuses_dir_the_owner_cannot_use() {
        // 0500: private, but `start` cannot create the socket in it, so
        // doctor must not call it healthy either.
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("readonly");
        fs::create_dir(&sub).unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).unwrap();
        let err = bind(&sub.join("agent.sock")).unwrap_err();
        // restore so the tempdir can be cleaned up
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(err.to_string().contains("not usable by its owner"), "{err}");
    }

    #[tokio::test]
    async fn refuses_symlinked_dir() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = bind(&link.join("agent.sock")).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[tokio::test]
    async fn refuses_when_agent_already_listening() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("agent.sock");
        let (_listener, _guard) = bind(&path).unwrap();
        let err = bind(&path).unwrap_err();
        assert!(err.to_string().contains("already listening"), "{err}");
    }

    #[tokio::test]
    async fn replaces_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("agent.sock");
        {
            let (_listener, guard) = bind(&path).unwrap();
            // Simulate a crash: listener closed but file left behind.
            std::mem::forget(guard);
        }
        assert!(path.exists());
        let (_listener, _guard) = bind(&path).unwrap();
    }

    #[tokio::test]
    async fn refuses_when_dir_is_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, "x").unwrap();
        let err = bind(&file.join("agent.sock")).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    #[tokio::test]
    async fn refuses_dir_owned_by_someone_else() {
        // SAFETY: geteuid cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: everything is owned by root when running as root");
            return;
        }
        // "/" is root-owned; the ownership check fires before the mode check.
        let err = validate_dir(Path::new("/")).unwrap_err();
        assert!(err.to_string().contains("owned by uid 0"), "{err}");
    }

    #[tokio::test]
    async fn refuses_socket_path_without_parent() {
        let err = bind(Path::new("/")).unwrap_err();
        assert!(err.to_string().contains("no parent directory"), "{err}");
    }

    #[tokio::test]
    async fn overlong_socket_path_fails_at_bind() {
        // dir + 200-char name: every component is legal for lstat (< 255),
        // but the total always exceeds the sun_path limit (104 macOS / 108 Linux)
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let err = bind(&dir.path().join("s".repeat(200))).unwrap_err();
        assert!(err.to_string().contains("cannot bind"), "{err}");
    }

    #[test]
    fn validate_dir_surfaces_stat_errors() {
        // 300-byte component: lstat fails with ENAMETOOLONG (not NotFound)
        let dir = tempfile::tempdir().unwrap();
        let long = "x".repeat(300);
        assert!(validate_dir(&dir.path().join(long)).is_err());
    }

    #[tokio::test]
    async fn stat_failure_is_surfaced() {
        // A 300-byte final component fails lstat with ENAMETOOLONG,
        // which is not NotFound and must propagate.
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let long = "x".repeat(300);
        assert!(bind(&dir.path().join(long)).is_err());
    }

    #[tokio::test]
    async fn keeps_a_socket_it_cannot_probe() {
        // SAFETY: geteuid cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root bypasses the permission check");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("agent.sock");
        let (_listener, _guard) = bind(&path).unwrap();
        // an unconnectable-but-live socket: connect() fails with EACCES,
        // which proves nothing about whether anyone is listening
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        let err = bind(&path).unwrap_err();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(err.to_string().contains("cannot tell whether"), "{err}");
        assert!(path.exists(), "a socket we could not probe must survive");
    }

    #[tokio::test]
    async fn refuses_non_socket_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("agent.sock");
        fs::write(&path, "not a socket").unwrap();
        let err = bind(&path).unwrap_err();
        assert!(err.to_string().contains("not a socket"), "{err}");
    }
}
