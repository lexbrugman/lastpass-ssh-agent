#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod agent;
// Excluded from coverage: one `spawn_blocking` shared by the two macOS stores,
// whose failure is a panicking Apple call that a test cannot arrange.
#[cfg(target_os = "macos")]
#[cfg_attr(coverage_nightly, coverage(off))]
mod apple;
mod askpass;
mod cli;
mod config;
mod confirm;
mod enclave;
mod error;
mod files;
mod interaction;
// Excluded from coverage as a whole, which is the point of it being this small:
// every line talks to the real Keychain of whoever runs the tests. The rules
// around it are covered through store fakes on every platform.
#[cfg(target_os = "macos")]
#[cfg_attr(coverage_nightly, coverage(off))]
mod keychain;
mod keystore;
mod knownhosts;
mod lpass;
mod passphrase;
mod platform;
mod signing;
mod socket;
#[cfg(test)]
mod testutil;
mod text;
mod tty;
mod vaultlock;

use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::cli::{Cli, Command};
use crate::config::{Config, KeyConfig};
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

/// This executable, for `lpass` to run when it wants the master password.
///
/// `current_exe` fails only on a system that cannot name its own running
/// binary — excluded from coverage, since a test cannot arrange that. The
/// fallback is the command name: worth trying on `PATH`, and if that is wrong
/// too, lpass falls back to the behaviour it had before there was a helper.
#[cfg_attr(coverage_nightly, coverage(off))]
fn own_binary() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_else(|e| {
        tracing::debug!("cannot locate this binary, so lpass will look on PATH instead: {e}");
        std::path::PathBuf::from("lastpass-ssh-agent")
    })
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
    // Resolved per command rather than up front: `askpass` is told which config
    // to use by the environment the agent set, and must not fail for want of a
    // home directory it was never going to consult.
    let Cli { config, command } = cli;
    let config_path = || {
        config
            .clone()
            .or_else(Config::default_path)
            .ok_or_else(no_home)
    };

    // The config file is optional throughout: without one (or without
    // [[keys]]) the agent auto-discovers the vault's SSH Key items.
    match command {
        Command::Doctor { test_confirm } => doctor(&config_path()?, test_confirm).await,
        Command::Env => {
            let config = Config::load_or_default(&config_path()?)?;
            print_env(&config.socket_path()?, config.vault_unlock_timeout_secs);
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
            start(&config_path()?).await
        }
        Command::List => {
            let config = Config::load_or_default(&config_path()?)?;
            let client: Arc<dyn LpassClient> = Arc::new(client_from(&config)?);
            require_login(client.as_ref()).await?;
            let keys = effective_keys(&client, &config).await?;
            let store = keystore::KeyStore::load(client.as_ref(), &keys, &config).await?;
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
            let config = Config::load_or_default(&config_path()?)?;
            let client: Arc<dyn LpassClient> = Arc::new(client_from(&config)?);
            search(&client, query.as_deref()).await
        }
        Command::StoreMasterPassword => store_master_password(&config_path()?).await,
        // Its config is named by the environment the agent set, not by
        // `--config`: lpass owns this command line and leaves no room for one.
        Command::Askpass { .. } => askpass(&askpass::config_from_env()?).await,
    }
}

/// Keep the master password in the platform's store, once it has been shown to
/// open the vault.
///
/// Locks the vault first, because that is what makes checking possible at all:
/// `lpass` only asks for a password when it has no key. What follows is the
/// production path exactly — the same wrapper, the same helper, the same
/// presence prompt — so setting this up proves the whole arrangement works
/// rather than only that a password was typed.
///
/// Excluded from coverage: it needs a real vault to lock, a real Secure Enclave
/// to write to and a fingerprint to release it, and the one branch a test could take
/// is the one platform where the rest is refused at config load. What it
/// decides is `askpass::seed`'s, tested with fakes on every platform; that it
/// refuses without somewhere to store is covered end to end by the CLI tests.
async fn store_master_password(config_path: &Path) -> Result<()> {
    let config = Config::load_or_default(config_path)?;
    let socket_path = config.socket_path()?;
    refuse_while_an_agent_runs(&socket_path)?;
    seed_master_password(&config, config_path, &socket_path).await
}

/// Setup refuses while an agent is running.
///
/// Kept out of the exempt function below, and testable on any platform: this is
/// the check worth a regression test, since getting it wrong means two prompts
/// on one terminal.
fn refuse_while_an_agent_runs(socket_path: &Path) -> Result<()> {
    // Only one thing may talk to the user at a time, and that gate lives inside
    // a running agent — it cannot reach across to this process. Rather than
    // build an interprocess one for a command run once, refuse: a signing
    // confirmation appearing over this prompt could take the answer meant for
    // it, and a master password would land in a buffer nothing wipes.
    if std::os::unix::net::UnixStream::connect(socket_path).is_ok() {
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
/// Excluded from coverage, and only this: every line needs a real vault to
/// lock, a real Secure Enclave to write to and a fingerprint to release it.
/// What it decides is `askpass::seed`'s, tested with fakes on every platform.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn seed_master_password(
    config: &Config,
    config_path: &Path,
    socket_path: &Path,
) -> Result<()> {
    if config.master_password != config::MasterPassword::TouchId {
        return Err(Error::ConfigInvalid(
            "nothing to store: set master_password = \"touchid\" in the config first".into(),
        ));
    }
    let client: Arc<dyn LpassClient> = Arc::new(asking_client(config, config_path, socket_path)?);
    // No login check first. `lpass status` cannot answer once the key is gone,
    // and a locked vault is the state this command creates — so checking would
    // refuse the second run of a command whose first run failed. A session that
    // is genuinely gone surfaces from the vault call below, in lpass's own
    // words.

    // Shut the vault so lpass has to ask, which is the only way to learn
    // whether what we are about to keep actually opens it.
    tracing::info!("locking the vault, so the password can be checked against it");
    vaultlock::VaultKey::forget(&lpass::LpassAgentProcess).await;

    let secret = passphrase::from_config(config)?
        .prompt(&passphrase::PassphraseRequest::master_password())
        .await
        .map_err(|e| Error::ConfigInvalid(e.to_string()))?;

    askpass::seed(
        askpass::default_store(socket_path).as_ref(),
        &secret,
        &VaultOpens(client),
    )
    .await
}

/// Opening the vault means using it for something that needs the derived key
/// and returns no secret: listing what is in it.
struct VaultOpens(Arc<dyn LpassClient>);

#[async_trait::async_trait]
impl askpass::VaultUnlock for VaultOpens {
    /// Excluded from coverage with its caller: this is the one line that needs
    /// a vault.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn attempt(&self) -> std::result::Result<(), String> {
        self.0.ls().await.map_err(|e| e.to_string())?;
        // Succeeding is not enough: lpass may have used a key it still had
        // cached, in which case the candidate was never looked at and calling
        // it verified would let any typo through. The helper reports itself, so
        // its silence means exactly that.
        if self.0.master_password_came_from_store() {
            Ok(())
        } else {
            Err(
                "the vault was already open, so the password was never used — \
                 lock it and try again"
                    .into(),
            )
        }
    }
}

/// The `LPASS_ASKPASS` helper: ask for the master password, print it, exit.
///
/// Runs as its own short-lived process because that is the contract lpass
/// defines — it names a program and reads its stdout. Nothing is logged and
/// nothing is kept: the answer goes to stdout and the buffer holding it is
/// wiped when this returns.
async fn askpass(config_path: &Path) -> Result<()> {
    let config = Config::load_or_default(config_path)?;
    // Named by the agent that spawned the lpass that spawned this, and absent
    // when nothing asked for the guard.
    let once = std::env::var_os(lpass::ASKPASS_ONCE_MARKER).map(std::path::PathBuf::from);
    let (secret, from) = askpass::resolve(
        config.master_password,
        askpass::default_store(&config.socket_path()?).as_ref(),
        passphrase::from_config(&config)?.as_ref(),
        once.as_deref(),
    )
    .await?;

    // One zeroizing allocation, sized once, carrying the newline lpass expects.
    // `println!` would copy the secret into a `String` on the way past, which
    // is a copy this code owns and therefore one it must not make.
    let mut answer = zeroize::Zeroizing::new(Vec::with_capacity(secret.len() + 1));
    answer.extend_from_slice(&secret);
    answer.push(b'\n');
    write_answer(&answer)?;

    // Tell the agent this happened. Its log is the only place anyone looks, and
    // the agent cannot see this process — lpass spawned it, not us. Which
    // source answered goes with it, because setup trusts only the store's own
    // answer: a password typed at the fallback prompt says nothing about what
    // is kept.
    eprintln!("{}{}", lpass::ASKPASS_SIGNAL, from.signal_suffix());
    Ok(())
}

/// Hand the answer to whatever is reading our stdout — `lpass`, in practice.
///
/// Through the ordinary `Stdout`, which keeps a buffer of its own that this
/// does not reach into. Tempting to write at the descriptor instead and leave
/// no copy behind, but that means manufacturing ownership of fd 1, and a helper
/// launched with stdout closed could then have that descriptor be something
/// else entirely — a master password sent somewhere unrelated is a worse
/// failure than one lingering in a buffer this process is about to exit from.
///
/// The same line the rest of this codebase draws: our own buffers are
/// `Zeroizing` and allocated once, a library's intermediates are left alone.
fn write_answer(bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    out.write_all(bytes).map_err(Error::Io)?;
    out.flush().map_err(Error::Io)
}

/// The keys the agent should serve: the configured [[keys]] if any,
/// otherwise every SSH Key item discovered in the vault.
async fn effective_keys(client: &Arc<dyn LpassClient>, config: &Config) -> Result<Vec<KeyConfig>> {
    if !config.keys.is_empty() {
        return Ok(config.keys.clone());
    }
    tracing::info!("no [[keys]] configured — discovering SSH Key items in the vault");
    let found = lpass::discover_ssh_key_items(client.clone(), None).await?;
    if found.is_empty() {
        return Err(Error::ConfigInvalid(
            "no SSH Key items found in the vault (create one in LastPass, or pin items with [[keys]] in the config)"
                .into(),
        ));
    }
    Ok(found
        .into_iter()
        .map(|item| KeyConfig {
            id: item.id,
            name: Some(item.name),
            // No per-key overrides for a discovered item: there is no config
            // entry to have written one in, so both fall back to the globals.
            confirm: None,
            passphrase_fallback: None,
        })
        .collect())
}

async fn start(config_path: &Path) -> Result<()> {
    let config = Config::load_or_default(config_path)?;
    let socket_path = config.socket_path()?;
    let client: Arc<dyn LpassClient> = Arc::new(asking_client(&config, config_path, &socket_path)?);
    if wants_login_checked(config.master_password) {
        require_login(client.as_ref()).await?;
    }

    let keys = effective_keys(&client, &config).await?;
    let store = Arc::new(keystore::KeyStore::load(client.as_ref(), &keys, &config).await?);
    for entry in store.entries() {
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
    // Logged rather than printed as shell exports. `env` emits those, and they
    // are for a shell to evaluate — which nothing can do with the output of a
    // command that then runs until it is stopped. In a service they went
    // straight into the log, where two `export` lines read as something to copy
    // rather than as a record of where the agent is listening.
    tracing::info!(
        socket = %socket_path.display(),
        vault_unlock_timeout_secs = ?config.vault_unlock_timeout_secs,
        "listening"
    );

    // Runs beside the agent rather than inside a request: the screen locks when
    // nobody is asking for a signature, which is the whole point of it. Spawned
    // unconditionally, because whether to watch at all is `watch`'s decision.
    tokio::task::spawn(vaultlock::watch(
        config.lock_on_screen_lock,
        Arc::new(platform::screen_is_locked),
        Arc::new(lpass::LpassAgentProcess),
        vaultlock::POLL_INTERVAL,
    ));

    let factory = AgentFactory {
        template: agent::LpassAgent::new(
            store,
            client,
            confirmer,
            unlocker,
            Arc::new(knownhosts::HostNames::default()),
        ),
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

/// An lpass client that can have the master password asked for, wrapper and all.
///
/// Shared by `start` and `store-master-password`, which need the same
/// arrangement for the same reason: lpass execs a bare path with one argument,
/// so what it runs is a small wrapper written here, and the wrapper runs an
/// ordinary `askpass` subcommand. Written before any lpass call, because the
/// first one may already need it.
///
/// Only the long-running agent and the setup command do this: the other
/// one-shot commands have a terminal, where lpass asking there directly beats a
/// dialog over the top of it. A socket path with no usable parent falls through
/// to `bind`, which refuses it in words of its own.
fn asking_client(
    config: &Config,
    config_path: &Path,
    socket_path: &Path,
) -> Result<lpass::LpassCli> {
    let helper = match socket_path
        .parent()
        .filter(|_| config.master_password != config::MasterPassword::Off)
    {
        Some(dir) => {
            socket::prepare_dir(dir)?;
            Some(askpass::install(socket_path, &own_binary())?)
        }
        None => None,
    };
    Ok(client_from(config)?.asking_with(
        helper,
        config_path.to_path_buf(),
        std::time::Duration::from_secs(config.confirm_timeout_secs),
    ))
}

/// Build the real lpass client from config.
fn client_from(config: &Config) -> Result<lpass::LpassCli> {
    let binary = lpass::resolve_binary(config.lpass_path.as_deref()).ok_or_else(|| {
        Error::ConfigInvalid(
            "lpass binary not found on PATH (brew install lastpass-cli, or set `lpass_path`)"
                .into(),
        )
    })?;
    Ok(lpass::LpassCli::new(binary).unlocked_for(config.vault_unlock_timeout_secs))
}

/// Whether a locked vault should stop the agent starting.
///
/// `lpass status` cannot answer once the derived key has expired, so it reports
/// a locked vault as a logged-out one. With nowhere to get a master password
/// that is the right answer — nothing here could reopen it, and failing at
/// startup beats failing at the first signature. With a source configured it is
/// wrong: loading the keys is itself a vault call, so it would prompt once and
/// carry on, and refusing first turns a recoverable state into a dead agent
/// that launchd then restarts in a loop.
const fn wants_login_checked(source: config::MasterPassword) -> bool {
    matches!(source, config::MasterPassword::Off)
}

async fn require_login(client: &dyn lpass::LpassClient) -> Result<()> {
    if client.status().await? == lpass::LoginStatus::NotLoggedIn {
        return Err(lpass::LpassError::NotLoggedIn.into());
    }
    Ok(())
}

/// Interactive helper: find the vault's SSH Key items (optionally filtered
/// by name) and print pin-ready config snippets.
async fn search(client: &Arc<dyn LpassClient>, query: Option<&str>) -> Result<()> {
    require_login(client.as_ref()).await?;
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
        // backslashes, and newlines can't break or extend the snippet.
        println!(
            "\n[[keys]]\nid = {}\nname = {}",
            toml::Value::String(item.id.clone()),
            toml::Value::String(name.to_string()),
        );
    }
    Ok(())
}

fn print_env(socket: &Path, vault_unlock_timeout_secs: Option<u64>) {
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", sh_quote(socket));
    // So a shell profile that already evaluates this takes the vault's timeout
    // from the config too, instead of repeating the number in a second place —
    // a shell's own lpass calls start their own agent, and whichever starts it
    // first decides.
    if let Some(seconds) = vault_unlock_timeout_secs {
        println!("LPASS_AGENT_TIMEOUT='{seconds}'; export LPASS_AGENT_TIMEOUT;");
    }
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

    let (check, client) = check_lpass_binary(config.as_ref());
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
        if let Some(check) = master_password_check(
            config.master_password,
            askpass::store_available(),
            master_password_seeded(config),
        ) {
            report(check);
        }
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
fn check_lpass_binary(config: Option<&Config>) -> (Check, Option<Arc<dyn LpassClient>>) {
    let configured = config.and_then(|c| c.lpass_path.as_deref());
    // Carrying the configured timeout, because these calls can be the ones that
    // start the lpass agent — and then its lifetime is fixed, so a `doctor` run
    // before the agent would quietly pin the default hour on everything after.
    let unlocked_for = config.and_then(|c| c.vault_unlock_timeout_secs);
    lpass::resolve_binary(configured).map_or_else(no_lpass_binary, |path| {
        let check = Check::passed("lpass binary", path.display().to_string());
        let client: Arc<dyn LpassClient> =
            Arc::new(lpass::LpassCli::new(path).unlocked_for(unlocked_for));
        (check, Some(client))
    })
}

/// Named rather than written inline, so `map_or_else` reads as the two answers
/// it is choosing between rather than as one buried in its arguments.
fn no_lpass_binary() -> (Check, Option<Arc<dyn LpassClient>>) {
    (
        Check::failed(
            "lpass binary",
            "not found on PATH (brew install lastpass-cli, or set `lpass_path`)".into(),
        ),
        None,
    )
}

/// Whether the vault is unlocked, and who it belongs to.
///
/// No check at all without a binary to ask with: that failure is already
/// reported, and a second line about it would only repeat it.
async fn check_login(client: Option<&Arc<dyn LpassClient>>) -> (Option<Check>, bool) {
    let Some(client) = client else {
        return (None, false);
    };
    match client.status().await {
        Ok(lpass::LoginStatus::LoggedIn(user)) => (Some(Check::passed("lpass login", user)), true),
        Ok(lpass::LoginStatus::NotLoggedIn) => (
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
    let keys = match effective_keys(client, config).await {
        Ok(keys) => keys,
        Err(e) => return vec![Check::failed("keys", e.to_string())],
    };
    keystore::inspect_keys(client.as_ref(), &keys, config)
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
        .collect()
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
fn master_password_check(
    source: config::MasterPassword,
    available: bool,
    seeded: bool,
) -> Option<Check> {
    const LABEL: &str = "master password";
    match source {
        config::MasterPassword::Off => None,
        config::MasterPassword::Prompt => Some(Check::passed(
            LABEL,
            "asked when the vault needs reopening, and never kept".into(),
        )),
        config::MasterPassword::TouchId if !available => Some(Check::failed(
            LABEL,
            "no Secure Enclave on this machine — use master_password = \"prompt\"".into(),
        )),
        config::MasterPassword::TouchId if !seeded => Some(Check::failed(
            LABEL,
            "nothing stored yet — run `lastpass-ssh-agent store-master-password`".into(),
        )),
        config::MasterPassword::TouchId => Some(Check::passed(
            LABEL,
            "stored, and released only on Touch ID".into(),
        )),
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
    let ctx = confirm::ConfirmContext {
        key_name: "doctor test (no real key)".into(),
        fingerprint: "SHA256:this-is-only-a-test".into(),
        item_id: "0".into(),
        peer: Some(confirm::PeerInfo {
            pid: Some(std::process::id().cast_signed()),
            // SAFETY: getuid cannot fail and touches no memory.
            uid: unsafe { libc::getuid() },
        }),
        bindings: Vec::new(),
    };
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
    fn a_locked_vault_only_stops_startup_when_nothing_could_reopen_it() {
        // `lpass status` cannot tell a locked vault from a logged-out one, so
        // the check is only honest when there is no way back.
        assert!(wants_login_checked(config::MasterPassword::Off));
        assert!(!wants_login_checked(config::MasterPassword::Prompt));
        assert!(!wants_login_checked(config::MasterPassword::TouchId));
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
            .unwrap_or_else(|| panic!("{source:?} should report a line"))
    }

    #[test]
    fn an_unconfigured_master_password_reports_nothing() {
        assert!(master_password_check(config::MasterPassword::Off, true, true).is_none());
    }

    #[test]
    fn the_prompt_source_passes_without_needing_anything() {
        let check = expect_check(config::MasterPassword::Prompt, false, false);
        assert!(check.ok, "{}", check.detail);
        assert!(check.detail.contains("never kept"), "{}", check.detail);
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
    fn print_env_emits_export_lines() {
        print_env(Path::new("/tmp/agent.sock"), None);
        print_env(Path::new("/tmp/agent.sock"), Some(300));
    }
}
