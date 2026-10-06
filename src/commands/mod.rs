//! The subcommands, one module each, and what more than one of them needs:
//! the lpass client, the master-password holder, and the identities file.

pub mod doctor;
pub mod env;
pub mod list;
pub mod master_password;
pub mod start;

use std::path::Path;
use std::sync::Arc;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::lpass::{self, LpassClient};
use crate::{identities, keystore, master, passphrase, unlock};

/// The agent's master-password holder, from the config: the platform's store
/// beside the socket, the prompt `confirm` selects, and the idle time.
fn unlock_from(config: &Config, socket_path: &Path) -> Result<Arc<unlock::Unlock>> {
    Ok(Arc::new(unlock::Unlock::new(
        config.master_password,
        master::default_store(socket_path),
        passphrase::from_config(config)?,
        config.master_password_idle(),
    )))
}

/// A client for a command that runs and exits: asks for the master password
/// if the vault turns out to need it, and holds it for the rest of the command.
fn asking_client(config: &Config) -> Result<Arc<dyn LpassClient>> {
    let source = one_shot_source(config, &config.socket_path()?)?;
    Ok(Arc::new(client_from(config)?.feeding(source)))
}

/// Where a command that runs and exits gets the master password: asked for,
/// unless an agent is running.
///
/// Only one thing may talk to the user at a time, and that gate lives inside
/// a running agent — it cannot reach across to this process. So beside one,
/// this process asks nothing: a locked vault fails here, and a signature
/// unlocks it.
fn one_shot_source(config: &Config, socket_path: &Path) -> Result<lpass::MasterPasswordSource> {
    if agent_is_running(socket_path) {
        tracing::info!(
            socket = %socket_path.display(),
            "an agent is running, so this command will not ask for the master password — \
             a locked vault fails here until a signature opens it, or the agent is stopped"
        );
        return Ok(lpass::MasterPasswordSource::None);
    }
    Ok(lpass::MasterPasswordSource::Unlock(unlock_from(
        config,
        socket_path,
    )?))
}

fn agent_is_running(socket_path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket_path).is_ok()
}

/// Build the real lpass client from config.
fn client_from(config: &Config) -> Result<lpass::LpassCli> {
    let binary = lpass::resolve_binary(config.lpass_path.as_deref()).ok_or_else(|| {
        Error::ConfigInvalid(
            "lpass binary not found on PATH (brew install lastpass-cli, or set `lpass_path`)"
                .into(),
        )
    })?;
    Ok(lpass::LpassCli::new(binary))
}

/// Write a scanned set down for the next start — but only a set nothing was
/// skipped from. `KeyStore::load` carries on past an item the vault would not
/// answer for, which is right for serving and wrong for the file: a set missing a
/// key would be trusted until something refreshed it.
fn remember_if_complete(path: &Path, store: &keystore::KeyStore, wanted: usize) {
    let skipped = wanted - store.entries().count();
    if skipped == 0 {
        identities::save_best_effort(path, &store.remember());
    } else {
        tracing::warn!(
            skipped,
            "not writing the remembered identities down: a set missing a key must not be \
             what the next start trusts"
        );
    }
}

/// Fixtures the subcommands' tests share.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod testing {
    use std::path::{Path, PathBuf};

    use crate::config::Config;

    /// A config that names a socket in `dir`, so the stored-master-password
    /// lookup has somewhere to look.
    pub(super) fn config_with_socket(dir: &Path) -> Config {
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            format!("socket = \"{}/agent.sock\"\n", dir.display()),
        )
        .unwrap();
        Config::load_or_default(&path).unwrap()
    }

    pub(super) fn remembered(dir: &Path, toml: &str) -> PathBuf {
        let path = dir.join("agent.sock.identities");
        std::fs::write(&path, toml).unwrap();
        path
    }
}
