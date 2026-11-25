//! `start`: serve the SSH agent protocol until stopped.

use std::path::Path;
use std::sync::Arc;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::lpass::{self, Access, LpassClient};
use crate::{
    agent, approvals, confirm, identities, keystore, knownhosts, master, passphrase, platform,
    refresh, socket, unlock, vaultlock,
};

/// The store a remembered file can stand in for the vault with, or `None` when
/// the vault has to be asked after all: nothing is written down yet, the file
/// lacks a pinned key that only the vault can supply, or it would serve nothing
/// — which is a state to fail loudly in, as a scan does, rather than bind in.
fn remembered_store(path: &Path, config: &Config) -> Result<Option<keystore::KeyStore>> {
    let Some(remembered) = identities::load(path)? else {
        return Ok(None);
    };
    let from = keystore::KeyStore::from_remembered(&remembered, config);
    if from.store.is_empty() {
        tracing::info!(path = %path.display(),
            "the remembered identities would serve nothing; asking the vault");
        return Ok(None);
    }
    // At info like the other outcome, for the same reason: it says why this
    // start is the slow kind. Pinning a new key earns exactly one such start.
    if !from.missing.is_empty() {
        tracing::info!(path = %path.display(), missing = from.missing.len(),
            "the remembered identities do not cover every pinned key; asking the vault");
        return Ok(None);
    }
    tracing::info!(path = %path.display(),
        "serving the identities the last start wrote down — no vault call needed");
    Ok(Some(from.store))
}

pub async fn run(config_path: &Path) -> Result<()> {
    // Before a line names a key. Here rather than for every command: a
    // one-shot's stderr is whatever its caller pointed it at.
    crate::platform::private_log(std::os::fd::AsFd::as_fd(&std::io::stderr()));
    let config = Arc::new(Config::load_or_default(config_path)?);
    let socket_path = config.socket_path()?;
    let unlock = super::unlock_from(&config, config.master_password)?;
    // One vault, fed what the agent holds. Each call says what it is for —
    // `Access` — and that is what decides whether it may ask for the master
    // password, and whether it counts as using it.
    let vault: Arc<dyn LpassClient> = Arc::new(
        super::client_from(&config)?.feeding(lpass::MasterPasswordSource::Unlock(unlock.clone())),
    );

    // From what the last start wrote down, so binding costs no vault call;
    // otherwise from the vault, and written down for next time. A key added to
    // the vault since is picked up by the refresh a signature triggers, or by
    // `list`.
    //
    // A locked vault is asked for the master password by the first call that
    // needs it, which is the scan's — so a start the file spares never asks,
    // and one that cannot ask says what to do instead of failing bare.
    let remembered_at = identities::path_for(&socket_path);
    // Only a scan is written down: what the file supplied is already in it.
    let (store, scanned) = if let Some(store) = remembered_store(&remembered_at, &config)? {
        (store, false)
    } else {
        let keys = keystore::effective_keys(&vault, &config, Access::Asking)
            .await
            .map_err(first_start_needs_the_vault)?;
        let store = keystore::KeyStore::load(vault.as_ref(), &keys, &config)
            .await
            .map_err(first_start_needs_the_vault)?;
        (store, true)
    };
    let store = keystore::Served::new(store);
    for entry in store.current().entries() {
        tracing::info!(
            key = %entry.name,
            fingerprint = %entry.fingerprint(),
            item = %entry.item_id,
            confirm = entry.confirm,
            passphrase_fallback = ?entry.passphrase_fallback,
            "serving key"
        );
    }

    let confirmer = confirm::from_config(&config)?;
    let unlocker = Arc::new(passphrase::Unlocker::new(
        vault.clone(),
        passphrase::from_config(&config)?,
    ));
    // Before the bind: once the socket exists, a SIGTERM has to reach the
    // shutdown below that unlinks it, rather than the default action that ends
    // the process with the socket left behind.
    let shutdown = shutdown_signal();
    let (listener, guard) = socket::bind(&socket_path)?;
    master::discard_at_rest(&socket_path);
    // After the bind, which is what guarantees the directory exists. Best
    // effort: a start that cannot write beside its own socket still serves.
    if scanned {
        keystore::remember_if_complete(&remembered_at, &store.current());
    }
    let refresher = Arc::new(refresh::Refresher::new(
        store.clone(),
        remembered_at.clone(),
        config.clone(),
        vault.clone(),
        refresh::REFRESH_INTERVAL,
    ));
    // So a restart with the vault open picks up a key added since, off the
    // critical path.
    refresher.at_startup();
    // Logged rather than printed as shell exports. `env` emits those, and they
    // are for a shell to evaluate — which nothing can do with the output of a
    // command that then runs until it is stopped. In a service they went
    // straight into the log, where two `export` lines read as something to copy
    // rather than as a record of where the agent is listening.
    tracing::info!(
        socket = %socket_path.display(),
        master_password_idle_secs = ?config.master_password_idle().map(|idle| idle.as_secs()),
        "listening"
    );

    // Both run beside the agent rather than inside a request: the screen locks,
    // and the idle time passes, when nobody is asking for a signature — which
    // is the whole point of them. The watch is spawned unconditionally, because
    // whether to watch at all is `watch`'s decision.
    tokio::task::spawn(vaultlock::watch(
        config.lock_on_screen_lock,
        Arc::new(platform::SessionScreen),
        unlock.clone(),
        vaultlock::POLL_INTERVAL,
    ));
    let lock_epoch = unlock.lock_epoch();
    tokio::task::spawn(unlock::expire_when_idle(unlock, vaultlock::POLL_INTERVAL));

    let template = agent::LpassAgent::new(
        store,
        vault,
        confirmer,
        unlocker,
        Arc::new(knownhosts::HostNames::default()),
    )
    .with_approvals(Arc::new(
        approvals::Approvals::new(config.remember_approvals, lock_epoch)
            .remembering_unverified(config.remember_unverified_destinations),
    ))
    .with_remembered_file(remembered_at)
    .with_refresher(refresher);
    // Each connection a session of its own, told who is at the other end.
    let serving = crate::serve::listen(listener, move |socket| {
        let peer = socket.peer_cred().ok().map(|cred| confirm::PeerInfo {
            pid: cred.pid(),
            uid: cred.uid(),
        });
        template.with_peer(peer)
    });
    tokio::select! {
        never = serving => match never {},
        () = shutdown => tracing::info!("shutting down"),
    }
    drop(guard); // unlink the socket
    Ok(())
}

/// A start with nothing written down has to read the vault, and one that
/// cannot — locked, with no way to ask, or logged out — should say what gets
/// past that, because under a service manager the bare failure is a restart
/// loop with no clue in it. Any other failure is passed through as it is.
fn first_start_needs_the_vault(e: Error) -> Error {
    match e {
        Error::Lpass(
            lpass::LpassError::Locked
            | lpass::LpassError::NoMasterPassword(_)
            | lpass::LpassError::NotLoggedIn,
        ) => Error::State(format!(
            "{e} — this start has to read the vault, since nothing is written down yet: \
             open it, or run `lastpass-ssh-agent list` while it is open, and start again; \
             later starts need no vault"
        )),
        other => other,
    }
}

/// Installs the handlers now, and resolves on the first SIGTERM or SIGINT from
/// then on.
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("cannot install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("cannot install SIGINT handler");
    async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::testing::remembered;
    use super::*;

    #[test]
    fn a_start_serves_what_was_remembered_for_any_setup() {
        use crate::testutil::fixtures::*;
        let dir = tempfile::tempdir().unwrap();
        let file = format!(
            "[[keys]]\nid = \"1\"\nname = \"one\"\npublic = \"{}\"\n",
            ED25519_PUB.trim()
        );
        let path = remembered(dir.path(), &file);

        // discovered: the file's list is the served set
        let discovering: Config = toml::from_str("").unwrap();
        let store = remembered_store(&path, &discovering).unwrap().unwrap();
        assert_eq!(store.entries().count(), 1);

        // pinned and covered: served
        let pinned: Config = toml::from_str("[[keys]]\nid = \"1\"").unwrap();
        assert!(remembered_store(&path, &pinned).unwrap().is_some());

        // pinned and not covered: the vault has to be asked
        let more: Config = toml::from_str("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"").unwrap();
        assert!(remembered_store(&path, &more).unwrap().is_none());
    }

    #[test]
    fn a_start_never_binds_on_an_empty_remembered_set() {
        // A file that would serve nothing sends the start to the vault, where
        // "no usable keys" fails loudly rather than binding an agent that
        // answers `ssh-add -l` with nothing.
        let dir = tempfile::tempdir().unwrap();
        let path = remembered(dir.path(), "");
        let config: Config = toml::from_str("").unwrap();
        assert!(remembered_store(&path, &config).unwrap().is_none());
        assert!(
            remembered_store(&dir.path().join("absent"), &config)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_first_start_that_cannot_read_the_vault_says_what_gets_past_that() {
        for shut in [
            lpass::LpassError::Locked,
            lpass::LpassError::NoMasterPassword("dismissed".into()),
            lpass::LpassError::NotLoggedIn,
        ] {
            let text = first_start_needs_the_vault(shut.into()).to_string();
            assert!(text.contains("lastpass-ssh-agent list"), "{text}");
        }
        // anything else is not about the vault being shut
        let other = first_start_needs_the_vault(Error::ConfigInvalid("x".into())).to_string();
        assert!(!other.contains("list"), "{other}");
    }
}
