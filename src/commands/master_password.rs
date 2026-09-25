//! `store-master-password` and `forget-master-password`.

use std::path::Path;
use std::sync::Arc;

use crate::config::{self, Config};
use crate::error::{Error, Result};
use crate::lpass::{self, LpassClient};
use crate::{master, passphrase};

/// Keep the master password in the platform's store, once it has been shown to
/// open the vault.
pub async fn store(config_path: &Path) -> Result<()> {
    let config = Config::load_or_default(config_path)?;
    let socket_path = config.socket_path()?;
    refuse_while_an_agent_runs(&socket_path)?;
    seed(&config, &socket_path).await
}

/// Remove what `store-master-password` kept. A platform with nowhere to keep
/// it has nothing to remove, which is success too.
pub async fn forget(config_path: &Path) -> Result<()> {
    let config = Config::load_or_default(config_path)?;
    let store = master::default_store(&config.socket_path()?);
    store.forget().await.map_err(Error::State)?;
    tracing::info!(
        store = store.name(),
        "no master password is kept — the vault asks for it when it next needs opening"
    );
    Ok(())
}

/// Setup refuses while an agent is running.
///
/// Kept out of the exempt function below, and testable on any platform: this is
/// the check worth a regression test, since getting it wrong means two prompts
/// on one terminal.
fn refuse_while_an_agent_runs(socket_path: &Path) -> Result<()> {
    // For the reason `one_shot_source` gives — but this command has to ask, so
    // rather than build an interprocess gate for a command run once, refuse: a
    // signing confirmation appearing over this prompt could take the answer
    // meant for it, and a master password would land in a buffer nothing wipes.
    if super::agent_is_running(socket_path) {
        return Err(Error::ConfigInvalid(format!(
            "an agent is running on {} — stop it first (`brew services stop \
             lastpass-ssh-agent`), so nothing else can prompt while this does",
            socket_path.display()
        )));
    }
    Ok(())
}

/// The rest: lock the vault, ask, and keep the answer if it opens it.
///
/// Locked first, because that is what makes checking possible at all: a vault a
/// shell left open would answer without the candidate ever being read. This is
/// the one time this agent ends another process's unlock, and it says so.
///
/// Excluded from coverage, and only this: every line needs a real vault to
/// lock, a real Secure Enclave to write to and a fingerprint to release it, and
/// the one branch a test could take is the one platform where the rest is
/// refused at config load. What it decides is `master::seed`'s, tested with
/// fakes on every platform; that it refuses without somewhere to store is
/// covered end to end by the CLI tests.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn seed(config: &Config, socket_path: &Path) -> Result<()> {
    if config.master_password != config::MasterPassword::TouchId {
        return Err(Error::ConfigInvalid(
            "nothing to store: set master_password = \"touchid\" in the config first".into(),
        ));
    }
    tracing::info!("locking the vault, so the password can be checked against it");
    if !lpass::drop_shell_unlock().await {
        return Err(Error::State(
            "could not lock the vault, so the password cannot be checked — nothing was kept".into(),
        ));
    }
    let secret = passphrase::from_config(config)?
        .prompt(&passphrase::PassphraseRequest::master_password())
        .await
        .map_err(|e| Error::ConfigInvalid(e.to_string()))?;
    let client =
        super::client_from(config)?.feeding(lpass::MasterPasswordSource::Fixed(secret.clone()));
    master::seed(
        master::default_store(socket_path).as_ref(),
        &secret,
        &VaultOpens(Arc::new(client)),
    )
    .await
}

/// Opening the vault means using it for something that needs the derived key
/// and returns no secret: listing what is in it. With the shell's agent ended
/// first, the only way that succeeds is by the candidate fed on stdin.
struct VaultOpens(Arc<dyn LpassClient>);

#[async_trait::async_trait]
impl master::VaultUnlock for VaultOpens {
    /// Excluded from coverage with its caller: this is the one line that needs
    /// a vault.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn attempt(&self) -> std::result::Result<(), String> {
        self.0.ls().await.map(|_| ()).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn setup_refuses_while_an_agent_is_listening() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        // nothing there yet
        refuse_while_an_agent_runs(&socket).unwrap();

        let _listening = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let error = refuse_while_an_agent_runs(&socket).unwrap_err().to_string();
        assert!(error.contains("an agent is running"), "{error}");
    }
}
