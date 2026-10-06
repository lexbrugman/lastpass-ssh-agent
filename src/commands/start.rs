//! `start`: serve the SSH agent protocol until stopped.

use std::path::Path;
use std::sync::Arc;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::lpass::{self, LpassClient};
use crate::{
    agent, approvals, confirm, identities, keystore, knownhosts, passphrase, platform, refresh,
    socket, unlock, vaultlock,
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
    let config = Arc::new(Config::load_or_default(config_path)?);
    let socket_path = config.socket_path()?;
    let unlock = super::unlock_from(&config, &socket_path)?;
    // Two views of one vault: `asking` reaches for the master password when
    // the vault is locked, `quiet` is fed only what is already held and so
    // can never put a prompt on screen. The agent fetches through `quiet`
    // without taking the interaction gate, and reaches for `asking` only
    // under it.
    let asking: Arc<dyn LpassClient> = Arc::new(
        super::client_from(&config)?.feeding(lpass::MasterPasswordSource::Unlock(unlock.clone())),
    );
    let quiet: Arc<dyn LpassClient> = Arc::new(
        super::client_from(&config)?.feeding(lpass::MasterPasswordSource::HeldOnly(unlock.clone())),
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
    // `scanned_for` is how many keys the scan set out to load, when there was
    // one: what the file is written from has to be checked against it.
    let (store, scanned_for) = if let Some(store) = remembered_store(&remembered_at, &config)? {
        (store, None)
    } else {
        let keys = keystore::effective_keys(&asking, &config)
            .await
            .map_err(first_start_needs_the_vault)?;
        let store = keystore::KeyStore::load(asking.as_ref(), &keys, &config)
            .await
            .map_err(first_start_needs_the_vault)?;
        (store, Some(keys.len()))
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
    // Through `quiet` as well, so an encrypted key's passphrase fetch takes no
    // gate either. A lock landing between that fetch and the private key's
    // fails the signature rather than asking, and the retry asks: rarer than
    // one encrypted-key signature queueing behind another would be common.
    let unlocker = Arc::new(passphrase::Unlocker::new(
        quiet.clone(),
        passphrase::from_config(&config)?,
    ));
    let (listener, guard) = socket::bind(&socket_path)?;
    // After the bind, which is what guarantees the directory exists. Best
    // effort: a start that cannot write beside its own socket still serves.
    if let Some(wanted) = scanned_for {
        super::remember_if_complete(&remembered_at, &store.current(), wanted);
    }
    // Refreshes through a client fed only what is already held, so a scan can
    // never put a prompt on screen: the vault is either open, and the scan is
    // silent, or shut, and it fails fast.
    let refresher = Arc::new(refresh::Refresher::new(
        store.clone(),
        remembered_at.clone(),
        config.clone(),
        quiet.clone(),
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

    let factory = AgentFactory {
        template: agent::LpassAgent::new(
            store,
            quiet,
            confirmer,
            unlocker,
            Arc::new(knownhosts::HostNames::default()),
        )
        .with_asking(asking)
        .with_approvals(Arc::new(approvals::Approvals::new(
            config.remember_approvals,
            lock_epoch,
        )))
        .with_remembered_file(remembered_at)
        .with_refresher(refresher),
    };
    let result = tokio::select! {
        result = ssh_agent_lib::agent::listen(listener, factory) => {
            result.map_err(|e| Error::Agent(e.to_string()))
        }
        () = shutdown_signal() => {
            tracing::info!("shutting down");
            Ok(())
        }
    };
    drop(guard); // unlink the socket
    result
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

struct AgentFactory {
    template: agent::LpassAgent,
}

impl ssh_agent_lib::agent::Agent<tokio::net::UnixListener> for AgentFactory {
    fn new_session(
        &mut self,
        socket: &tokio::net::UnixStream,
    ) -> impl ssh_agent_lib::agent::Session {
        let peer = socket.peer_cred().ok().map(|cred| confirm::PeerInfo {
            pid: cred.pid(),
            uid: cred.uid(),
        });
        self.template.with_peer(peer)
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("cannot install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("cannot install SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
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
        assert!(remembered_store(&dir.path().join("absent"), &config)
            .unwrap()
            .is_none());
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
