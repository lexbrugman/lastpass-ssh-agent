#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod agent;
mod approvals;
// Excluded from coverage: one `spawn_blocking` shared by the two macOS stores,
// whose failure is a panicking Apple call that a test cannot arrange.
#[cfg(target_os = "macos")]
#[cfg_attr(coverage_nightly, coverage(off))]
mod apple;
mod cli;
mod config;
mod confirm;
mod enclave;
mod error;
mod files;
mod identities;
mod interaction;
// Excluded from coverage as a whole, which is the point of it being this small:
// every line talks to the real Keychain of whoever runs the tests. The rules
// around it are covered through store fakes on every platform.
#[cfg(target_os = "macos")]
#[cfg_attr(coverage_nightly, coverage(off))]
mod keychain;
mod keystore;
mod knownhosts;
// Excluded from coverage, and kept small for it: every line talks to the system
// bus of whoever runs the tests. What an answer means is `vaultlock`'s business,
// and covered there on every platform.
#[cfg(target_os = "linux")]
#[cfg_attr(coverage_nightly, coverage(off))]
mod logind;
mod lpass;
mod master;
mod passphrase;
mod platform;
mod refresh;
mod signing;
mod socket;
#[cfg(test)]
mod testutil;
mod text;
mod tty;
mod unlock;
mod vaultlock;

use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::cli::{Cli, Command};
use crate::config::Config;
use crate::error::{Error, Result};
use crate::lpass::LpassClient;

/// setrlimit(0,0)/umask cannot fail in practice; keep the fatal path out of
/// the coverage accounting rather than pretending it's testable.
/// (`unwrap_or_else` dictates the by-value signature.)
#[expect(
    clippy::needless_pass_by_value,
    reason = "unwrap_or_else requires FnOnce(Error)"
)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn hardening_failed(e: Error) {
    eprintln!("fatal: {e}");
    std::process::exit(1);
}

/// Reachable only on systems reporting no home directory, which cannot be
/// simulated in tests — excluded from coverage.
#[cfg_attr(coverage_nightly, coverage(off))]
fn no_home() -> Error {
    Error::ConfigInvalid("cannot determine home directory; pass --config".into())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Before anything else: no core dumps, owner-only file creation.
    platform::harden().unwrap_or_else(hardening_failed);
    // Hard-cap ssh_agent_lib at info even under RUST_LOG=debug: its debug
    // logging Debug-formats whole requests, and an AddIdentity request (which
    // we refuse, but still receive) contains the client's private key. The
    // cap is a separate unconditional layer so that a more-specific RUST_LOG
    // directive (e.g. ssh_agent_lib::agent=debug) cannot override it.
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let secret_cap = tracing_subscriber::filter::filter_fn(|meta| {
        !meta.target().starts_with("ssh_agent_lib") || *meta.level() <= tracing::Level::INFO
    });
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(secret_cap)
                .with_filter(env_filter),
        )
        .init();

    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        tracing::error!("{e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let Cli { config, command } = cli;
    let config_path = config.or_else(Config::default_path).ok_or_else(no_home)?;

    // The config file is optional throughout: without one (or without
    // [[keys]]) the agent auto-discovers the vault's SSH Key items.
    match command {
        Command::Doctor { test_confirm } => doctor(&config_path, test_confirm).await,
        Command::Env => {
            let config = Config::load_or_default(&config_path)?;
            print_env(&config.socket_path()?);
            Ok(())
        }
        // Before the config path is even resolved, so nothing this command can
        // fail on happens unannounced. A service log otherwise begins at
        // whatever went wrong with nothing saying which build it went wrong in,
        // and an agent restarting in a loop reads the same as an upgrade that
        // replaced the binary but not the running process. Paired with the
        // "shutting down" line at the other end.
        Command::Start => {
            tracing::info!(
                version = env!("LASTPASS_SSH_AGENT_VERSION"),
                commit = env!("LASTPASS_SSH_AGENT_COMMIT"),
                "starting"
            );
            start(&config_path).await
        }
        Command::List => {
            let config = Config::load_or_default(&config_path)?;
            let client = asking_client(&config)?;
            let keys = keystore::effective_keys(&client, &config).await?;
            let store = keystore::KeyStore::load(client.as_ref(), &keys, &config).await?;
            // Rewrites what the next start reads. A running agent does not read
            // this; it refreshes itself after a signature.
            // Before the first start there is no socket directory yet, and a file
            // the next start is meant to read cannot go into a directory that
            // is not there.
            let socket_path = config.socket_path()?;
            socket::prepare_parent(&socket_path)?;
            remember_if_complete(&identities::path_for(&socket_path), &store, keys.len());
            for entry in store.entries() {
                println!(
                    "{}  {}  {}  [id: {}]  confirm={}",
                    entry.fingerprint(),
                    entry.public.algorithm(),
                    entry.name,
                    entry.item_id,
                    if entry.confirm { "on" } else { "off" },
                );
            }
            Ok(())
        }
        Command::Search { query } => {
            // Must work before any config exists — it's the setup helper.
            let config = Config::load_or_default(&config_path)?;
            let client = asking_client(&config)?;
            search(&client, query.as_deref()).await
        }
        Command::StoreMasterPassword => store_master_password(&config_path).await,
        Command::ForgetMasterPassword => forget_master_password(&config_path).await,
    }
}

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
/// this process asks nothing: a locked vault fails here, as every one-shot
/// command did before there was anything to ask, and a signature unlocks it.
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

/// Keep the master password in the platform's store, once it has been shown to
/// open the vault.
async fn store_master_password(config_path: &Path) -> Result<()> {
    let config = Config::load_or_default(config_path)?;
    let socket_path = config.socket_path()?;
    refuse_while_an_agent_runs(&socket_path)?;
    seed_master_password(&config, &socket_path).await
}

/// Remove what `store-master-password` kept. A platform with nowhere to keep
/// it has nothing to remove, which is success too.
async fn forget_master_password(config_path: &Path) -> Result<()> {
    let config = Config::load_or_default(config_path)?;
    let store = master::default_store(&config.socket_path()?);
    store.forget().await.map_err(Error::State)?;
    tracing::info!(
        store = store.name(),
        "no master password is kept any more — the vault asks for it when it next needs \
         opening"
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
    if agent_is_running(socket_path) {
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
async fn seed_master_password(config: &Config, socket_path: &Path) -> Result<()> {
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
    let client = client_from(config)?.feeding(lpass::MasterPasswordSource::Fixed(secret.clone()));
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

async fn start(config_path: &Path) -> Result<()> {
    let config = Arc::new(Config::load_or_default(config_path)?);
    let socket_path = config.socket_path()?;
    let unlock = unlock_from(&config, &socket_path)?;
    let client: Arc<dyn LpassClient> = Arc::new(
        client_from(&config)?.feeding(lpass::MasterPasswordSource::Unlock(unlock.clone())),
    );

    // From what the last start wrote down, so binding costs no vault call;
    // otherwise from the vault, and written down for next time. A key added to
    // the vault since is picked up by the refresh a signature triggers, or by
    // `list`.
    //
    // A locked vault is asked for the master password by the first call that
    // needs it, which is the scan's — so a start the file spares never asks.
    let remembered_at = identities::path_for(&socket_path);
    // `scanned_for` is how many keys the scan set out to load, when there was
    // one: what the file is written from has to be checked against it.
    let (store, scanned_for) = if let Some(store) = remembered_store(&remembered_at, &config)? {
        (store, None)
    } else {
        let keys = keystore::effective_keys(&client, &config).await?;
        let store = keystore::KeyStore::load(client.as_ref(), &keys, &config).await?;
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
    let unlocker = Arc::new(passphrase::Unlocker::new(
        client.clone(),
        passphrase::from_config(&config)?,
    ));
    let (listener, guard) = socket::bind(&socket_path)?;
    // After the bind, which is what guarantees the directory exists. Best
    // effort: a start that cannot write beside its own socket still serves.
    if let Some(wanted) = scanned_for {
        remember_if_complete(&remembered_at, &store.current(), wanted);
    }
    // Refreshes through a client fed only what is already held, so a scan can
    // never put a prompt on screen: the vault is either open, and the scan is
    // silent, or shut, and it fails fast.
    let refresher = Arc::new(refresh::Refresher::new(
        store.clone(),
        remembered_at.clone(),
        config.clone(),
        Arc::new(
            client_from(&config)?.feeding(lpass::MasterPasswordSource::HeldOnly(unlock.clone())),
        ),
        refresh::REFRESH_INTERVAL,
    ));
    // So a restart with the vault open picks up a key added since — off the
    // critical path, where the scan used to sit.
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
            client,
            confirmer,
            unlocker,
            Arc::new(knownhosts::HostNames::default()),
        )
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

/// Interactive helper: find the vault's SSH Key items (optionally filtered
/// by name) and print pin-ready config snippets.
async fn search(client: &Arc<dyn LpassClient>, query: Option<&str>) -> Result<()> {
    let found = lpass::discover_ssh_key_items(client.clone(), query).await?;
    if found.is_empty() {
        match query {
            Some(query) => println!("no SSH Key items matching {query:?}"),
            None => println!("no SSH Key items in the vault"),
        }
        return Ok(());
    }

    for item in &found {
        println!(
            "✓ {}  [id: {}]",
            text::escape_for_display(&item.name),
            item.id
        );
    }
    println!(
        "\nthe agent serves all of these automatically; to pin a subset, add to \
         ~/.config/lastpass-ssh-agent/config.toml:"
    );
    for item in &found {
        let name = item.name.rsplit('/').next().unwrap_or(&item.name);
        // Vault names are untrusted: serialize as TOML so quotes,
        // backslashes, and newlines cannot break or extend the snippet.
        println!(
            "\n[[keys]]\nid = {}\nname = {}",
            toml::Value::String(item.id.clone()),
            toml::Value::String(name.to_string()),
        );
    }
    Ok(())
}

fn print_env(socket: &Path) {
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", sh_quote(socket));
}

fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}

/// One line of the `doctor` checklist.
struct Check {
    ok: bool,
    label: String,
    detail: String,
}

impl Check {
    fn passed(label: &str, detail: String) -> Self {
        Self {
            ok: true,
            label: label.to_string(),
            detail,
        }
    }

    fn failed(label: &str, detail: String) -> Self {
        Self {
            ok: false,
            label: label.to_string(),
            detail,
        }
    }
}

/// Run every check the setup allows, reporting each as it is made.
///
/// A check is skipped rather than failed when what it needs is already missing:
/// there is no login to test without an lpass binary, and no keys to inspect
/// without a login. The failure is already on the checklist, and repeating it
/// under another label would suggest two problems where there is one.
async fn doctor(config_path: &Path, test_confirm: bool) -> Result<()> {
    // Printed as each check finishes rather than collected and printed at the
    // end: the vault checks can take seconds, and a checklist that appears all
    // at once reads as a hang.
    let mut ok = true;
    let mut report = |check: Check| {
        println!(
            "{} {}: {}",
            if check.ok { "✓" } else { "✗" },
            check.label,
            check.detail
        );
        ok &= check.ok;
    };

    let (check, config) = check_config(config_path);
    report(check);

    let (check, client) = check_lpass_binary(config.as_ref())?;
    report(check);

    let (login, logged_in) = check_login(client.as_ref()).await;
    if let Some(check) = login {
        report(check);
    }

    if let (Some(config), Some(client), true) = (&config, &client, logged_in) {
        for check in check_keys(client, config).await {
            report(check);
        }
    }

    if let Some(config) = &config {
        report(check_socket(config));
        for check in check_remembered(config) {
            report(check);
        }
        report(master_password_check(
            config.master_password,
            master::store_available(),
            master_password_seeded(config),
        ));
    }

    if test_confirm {
        if let Some(config) = &config {
            report(check_confirmation(config).await?);
        }
    }

    if ok {
        Ok(())
    } else {
        Err(Error::DoctorFailed)
    }
}

/// The config file, and the config every later check runs against.
///
/// A missing file passes: running without one is ordinary, and the agent falls
/// back to defaults plus auto-discovery.
fn check_config(config_path: &Path) -> (Check, Option<Config>) {
    match Config::load(config_path) {
        Ok(config) => {
            let keys = if config.keys.is_empty() {
                "no [[keys]] — auto-discovery".to_string()
            } else {
                format!("{} pinned key(s)", config.keys.len())
            };
            let detail = format!("{} ({keys})", config_path.display());
            (Check::passed("config", detail), Some(config))
        }
        Err(Error::ConfigMissing(_)) => (
            Check::passed(
                "config",
                format!(
                    "no file at {} — using defaults + auto-discovery",
                    config_path.display()
                ),
            ),
            Config::load_or_default(config_path).ok(),
        ),
        Err(e) => (Check::failed("config", e.to_string()), None),
    }
}

/// The lpass binary, and a client that talks to it.
///
/// The client asks for the master password if the vault turns out to be
/// locked, as the agent would: that arrangement is what `doctor` is checking.
/// Without a config there is nothing to ask through, and beside a running
/// agent nothing may ask; a locked vault is then reported as one.
fn check_lpass_binary(config: Option<&Config>) -> Result<(Check, Option<Arc<dyn LpassClient>>)> {
    let configured = config.and_then(|c| c.lpass_path.as_deref());
    let Some(path) = lpass::resolve_binary(configured) else {
        return Ok((
            Check::failed(
                "lpass binary",
                "not found on PATH (brew install lastpass-cli, or set `lpass_path`)".into(),
            ),
            None,
        ));
    };
    let check = Check::passed("lpass binary", path.display().to_string());
    let source = match config {
        Some(config) => one_shot_source(config, &config.socket_path()?)?,
        None => lpass::MasterPasswordSource::None,
    };
    let client: Arc<dyn LpassClient> = Arc::new(lpass::LpassCli::new(path).feeding(source));
    Ok((check, Some(client)))
}

/// Whether the vault opens — with the master password, if it asks for one.
///
/// No check at all without a binary to ask with: that failure is already
/// reported, and a second line about it would only repeat it.
async fn check_login(client: Option<&Arc<dyn LpassClient>>) -> (Option<Check>, bool) {
    let Some(client) = client else {
        return (None, false);
    };
    match client.ls().await {
        Ok(_) => (
            Some(Check::passed(
                "lpass login",
                "logged in, and the vault opens".into(),
            )),
            true,
        ),
        Err(lpass::LpassError::NotLoggedIn) => (
            Some(Check::failed(
                "lpass login",
                "not logged in — run `lpass login <email>`".into(),
            )),
            false,
        ),
        Err(e) => (Some(Check::failed("lpass login", e.to_string())), false),
    }
}

/// One line per key the agent would serve, or one for why there are none.
///
/// The policy itself lives in `keystore::inspect_keys`, which `start` uses too,
/// so what `doctor` reports cannot drift from what the agent does.
async fn check_keys(client: &Arc<dyn LpassClient>, config: &Config) -> Vec<Check> {
    let keys = match keystore::effective_keys(client, config).await {
        Ok(keys) => keys,
        Err(e) => return vec![Check::failed("keys", e.to_string())],
    };
    let mut checks: Vec<Check> = keystore::inspect_keys(client.as_ref(), &keys, config)
        .await
        .into_iter()
        .map(|inspection| match inspection {
            keystore::KeyInspection::Usable(entry) => Check::passed(
                &format!("key {} [id: {}]", entry.name, entry.item_id),
                format!("{} {}", entry.public.algorithm(), entry.fingerprint()),
            ),
            keystore::KeyInspection::Unusable {
                item_id,
                name,
                issue,
            } => Check::failed(&format!("key {name} [id: {item_id}]"), issue.to_string()),
        })
        .collect();
    let served = checks.iter().filter(|check| check.ok).count();
    checks.extend(too_many_keys("key count", served));
    checks
}

/// How many keys `ssh` may offer before a server with `sshd`'s default
/// `MaxAuthTries` drops the connection.
const MAX_AUTH_TRIES: usize = 6;

/// A line for a served set larger than a server will try, since the failure it
/// causes — "Too many authentication failures", on a host whose key is in the
/// set — names neither this agent nor the count.
fn too_many_keys(label: &str, served: usize) -> Option<Check> {
    (served > MAX_AUTH_TRIES).then(|| {
        Check::passed(
            label,
            format!(
                "{served} served, and a server tries {MAX_AUTH_TRIES} by default before \
                 refusing — pin a few in [[keys]], or set `IdentitiesOnly yes` and an \
                 `IdentityFile` per host in ssh_config"
            ),
        )
    })
}

/// The same invariants `start` enforces on the socket directory. A directory
/// that does not exist yet passes, because `start` creates it correctly.
fn check_socket(config: &Config) -> Check {
    let resolved = config.socket_path().and_then(|path| {
        path.parent()
            .filter(|d| !d.as_os_str().is_empty())
            .map_or_else(
                || Err(Error::Socket("socket path has no parent directory".into())),
                socket::validate_dir,
            )
            .map(|()| path)
    });
    match resolved {
        Ok(path) => Check::passed("socket path", path.display().to_string()),
        Err(e) => Check::failed("socket path", e.to_string()),
    }
}

/// What an earlier start wrote down beside the socket, if anything — and,
/// since a start can serve from it with no vault at all, the key-count line
/// for it too.
fn check_remembered(config: &Config) -> Vec<Check> {
    const LABEL: &str = "remembered identities";
    let found = config.socket_path().and_then(|socket| {
        let path = identities::path_for(&socket);
        identities::load(&path).map(|found| (path, found))
    });
    match found {
        Ok((path, Some(remembered))) => {
            let mut checks = vec![Check::passed(
                LABEL,
                format!(
                    "{} at {} — a running agent refreshes them after a signature; `list` \
                     rewrites them for the next start",
                    remembered.keys.len(),
                    path.display()
                ),
            )];
            // Counted as a start would serve them: pinned keys narrow the file.
            let served = keystore::KeyStore::from_remembered(&remembered, config)
                .store
                .entries()
                .count();
            checks.extend(too_many_keys("remembered key count", served));
            checks
        }
        Ok((path, None)) => vec![Check::passed(
            LABEL,
            format!(
                "none yet at {} — the first start writes them",
                path.display()
            ),
        )],
        Err(e) => vec![Check::failed(LABEL, e.to_string())],
    }
}

/// Whether a master password is already stored, which is a question about a
/// file and never about a fingerprint — `doctor` must not cost one.
///
/// A socket path that will not resolve, or a file that will not decode, both
/// come out as "nothing stored": the first is `check_socket`'s to report and
/// the second is answered by the same instruction as an empty store.
fn master_password_seeded(config: &Config) -> bool {
    config
        .socket_path()
        .and_then(|socket| enclave::load(&enclave::path_for(&socket)))
        .is_ok_and(|stored| stored.is_some())
}

/// The master-password line of the checklist.
///
/// Takes the two facts rather than looking them up, so every arm is exercised
/// on both platforms — `touchid` cannot even be parsed into a config off macOS,
/// which would otherwise leave most of this untestable there.
fn master_password_check(source: config::MasterPassword, available: bool, seeded: bool) -> Check {
    const LABEL: &str = "master password";
    match source {
        config::MasterPassword::Prompt => Check::passed(
            LABEL,
            "asked for when the vault needs opening, and held only until it locks".into(),
        ),
        config::MasterPassword::TouchId if !available => Check::failed(
            LABEL,
            "no Secure Enclave on this machine — use master_password = \"prompt\"".into(),
        ),
        config::MasterPassword::TouchId if !seeded => Check::failed(
            LABEL,
            "nothing stored yet — run `lastpass-ssh-agent store-master-password`".into(),
        ),
        config::MasterPassword::TouchId => {
            Check::passed(LABEL, "stored, and released only on Touch ID".into())
        }
    }
}

/// Pop the configured prompt once, for `--test-confirm`.
async fn check_confirmation(config: &Config) -> Result<Check> {
    if config.confirm == config::ConfirmMode::Off {
        // `from_config` hands back the confirmer that approves everything here,
        // so going ahead would report an approval nobody was asked for.
        return Ok(Check::failed(
            "confirmation",
            "confirm = \"off\" — nothing to test; enable a confirm mode first".into(),
        ));
    }
    let confirmer = confirm::from_config(config)?;
    let ctx = confirm::ConfirmContext::describing(
        "doctor test (no real key)".into(),
        "SHA256:this-is-only-a-test".into(),
        "0".into(),
        Some(confirm::PeerInfo {
            pid: Some(std::process::id().cast_signed()),
            // SAFETY: getuid cannot fail and touches no memory.
            uid: unsafe { libc::getuid() },
        }),
        Vec::new(),
    );
    Ok(match confirmer.confirm(&ctx).await {
        confirm::Decision::Approve => {
            Check::passed("confirmation", "user approved the test prompt".into())
        }
        confirm::Decision::Deny => Check::failed(
            "confirmation",
            "denied/timed out (fail-closed works, but approve to pass this check)".into(),
        ),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_survives_spaces_and_quotes() {
        assert_eq!(sh_quote(Path::new("/a b/agent.sock")), "'/a b/agent.sock'");
        assert_eq!(
            sh_quote(Path::new("/a'b/agent.sock")),
            r"'/a'\''b/agent.sock'"
        );
    }

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

    /// A config that names a socket in `dir`, so the stored-master-password
    /// lookup has somewhere to look.
    fn config_with_socket(dir: &Path) -> Config {
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            format!("socket = \"{}/agent.sock\"\n", dir.display()),
        )
        .unwrap();
        Config::load_or_default(&path).unwrap()
    }

    fn remembered(dir: &Path, toml: &str) -> std::path::PathBuf {
        let path = dir.join("agent.sock.identities");
        std::fs::write(&path, toml).unwrap();
        path
    }

    #[test]
    fn a_start_serves_what_was_remembered_for_any_setup() {
        const ED25519_PUB: &str = include_str!("../tests/fixtures/ed25519.pub");
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
    fn doctor_reports_the_remembered_identities() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_with_socket(dir.path());
        let none = check_remembered(&config).remove(0);
        assert!(none.ok);
        assert!(none.detail.contains("none yet"), "{}", none.detail);

        remembered(
            dir.path(),
            "[[keys]]\nid = \"1\"\nname = \"n\"\npublic = \"p\"\n",
        );
        let some = check_remembered(&config).remove(0);
        assert!(some.ok);
        assert!(some.detail.starts_with("1 at "), "{}", some.detail);

        // a directory where the file should be cannot be read as one
        std::fs::remove_file(dir.path().join("agent.sock.identities")).unwrap();
        std::fs::create_dir(dir.path().join("agent.sock.identities")).unwrap();
        assert!(!check_remembered(&config)[0].ok);
    }

    #[test]
    fn nothing_is_stored_until_something_is() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_with_socket(dir.path());
        assert!(!master_password_seeded(&config));

        let stored = enclave::Stored {
            blob: vec![1, 2, 3],
            cipher: vec![4, 5, 6],
        };
        let path = dir.path().join("agent.sock.master");
        enclave::save(&path, &stored).unwrap();
        assert!(master_password_seeded(&config));
    }

    #[test]
    fn a_file_that_will_not_decode_counts_as_nothing_stored() {
        // `store-master-password` is the answer either way, and the socket
        // check reports anything wrong with the path itself.
        let dir = tempfile::tempdir().unwrap();
        let config = config_with_socket(dir.path());
        std::fs::write(dir.path().join("agent.sock.master"), b"not ours").unwrap();
        assert!(!master_password_seeded(&config));
    }

    fn expect_check(source: config::MasterPassword, available: bool, seeded: bool) -> Check {
        master_password_check(source, available, seeded)
    }

    #[test]
    fn the_prompt_source_passes_without_needing_anything() {
        let check = expect_check(config::MasterPassword::Prompt, false, false);
        assert!(check.ok, "{}", check.detail);
        assert!(check.detail.contains("held only"), "{}", check.detail);
    }

    #[test]
    fn touchid_without_an_enclave_fails_and_names_the_alternative() {
        let check = expect_check(config::MasterPassword::TouchId, false, false);
        assert!(!check.ok);
        assert!(check.detail.contains("\"prompt\""), "{}", check.detail);
    }

    #[test]
    fn touchid_with_nothing_stored_fails_and_says_what_to_run() {
        let check = expect_check(config::MasterPassword::TouchId, true, false);
        assert!(!check.ok);
        assert!(
            check.detail.contains("store-master-password"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn touchid_once_seeded_passes() {
        let check = expect_check(config::MasterPassword::TouchId, true, true);
        assert!(check.ok, "{}", check.detail);
        assert!(check.detail.contains("Touch ID"), "{}", check.detail);
    }

    #[test]
    fn a_served_set_larger_than_a_server_tries_gets_a_line() {
        assert!(too_many_keys("key count", MAX_AUTH_TRIES).is_none());
        let line = too_many_keys("key count", MAX_AUTH_TRIES + 1).unwrap();
        assert!(line.ok, "a warning, not a failure");
        assert!(line.detail.contains("IdentitiesOnly"), "{}", line.detail);
    }

    #[test]
    fn print_env_emits_the_export_line() {
        print_env(Path::new("/tmp/agent.sock"));
    }
}
