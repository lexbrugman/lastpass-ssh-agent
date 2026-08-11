#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod agent;
mod cli;
mod config;
mod confirm;
mod error;
mod keystore;
mod lpass;
mod passphrase;
mod platform;
mod signing;
mod socket;
#[cfg(test)]
mod testutil;
mod text;

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
    let config_path = cli
        .config
        .clone()
        .or_else(Config::default_path)
        .ok_or_else(no_home)?;

    // The config file is optional throughout: without one (or without
    // [[keys]]) the agent auto-discovers the vault's SSH Key items.
    match cli.command {
        Command::Doctor { test_confirm } => doctor(&config_path, test_confirm).await,
        Command::Env => {
            let config = Config::load_or_default(&config_path)?;
            print_env(&config.socket_path()?);
            Ok(())
        }
        Command::Start => start(&config_path).await,
        Command::List => {
            let config = Config::load_or_default(&config_path)?;
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
            let config = Config::load_or_default(&config_path)?;
            let client: Arc<dyn LpassClient> = Arc::new(client_from(&config)?);
            search(&client, query.as_deref()).await
        }
    }
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
    let client: Arc<dyn LpassClient> = Arc::new(client_from(&config)?);
    require_login(client.as_ref()).await?;

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
    let socket_path = config.socket_path()?;
    let (listener, guard) = socket::bind(&socket_path)?;
    print_env(&socket_path);

    let factory = AgentFactory {
        template: agent::LpassAgent::new(store, client, confirmer, unlocker),
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

fn print_env(socket: &Path) {
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", sh_quote(socket));
}

fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}

#[expect(
    clippy::too_many_lines,
    reason = "a linear checklist; splitting it would hurt readability"
)]
async fn doctor(config_path: &Path, test_confirm: bool) -> Result<()> {
    let mut ok = true;
    let mut check = |good: bool, label: &str, detail: String| {
        println!("{} {label}: {detail}", if good { "✓" } else { "✗" });
        ok &= good;
    };

    let config = match Config::load(config_path) {
        Ok(config) => {
            check(
                true,
                "config",
                format!(
                    "{} ({})",
                    config_path.display(),
                    if config.keys.is_empty() {
                        "no [[keys]] — auto-discovery".to_string()
                    } else {
                        format!("{} pinned key(s)", config.keys.len())
                    }
                ),
            );
            Some(config)
        }
        Err(Error::ConfigMissing(_)) => {
            check(
                true,
                "config",
                format!(
                    "no file at {} — using defaults + auto-discovery",
                    config_path.display()
                ),
            );
            Config::load_or_default(config_path).ok()
        }
        Err(e) => {
            check(false, "config", e.to_string());
            None
        }
    };

    let configured = config.as_ref().and_then(|c| c.lpass_path.as_deref());
    let client: Option<Arc<dyn LpassClient>> = if let Some(path) = lpass::resolve_binary(configured)
    {
        check(true, "lpass binary", path.display().to_string());
        Some(Arc::new(lpass::LpassCli::new(path)))
    } else {
        check(
            false,
            "lpass binary",
            "not found on PATH (brew install lastpass-cli, or set `lpass_path`)".into(),
        );
        None
    };

    let logged_in = match &client {
        Some(client) => match client.status().await {
            Ok(lpass::LoginStatus::LoggedIn(user)) => {
                check(true, "lpass login", user);
                true
            }
            Ok(lpass::LoginStatus::NotLoggedIn) => {
                check(
                    false,
                    "lpass login",
                    "not logged in — run `lpass login <email>`".into(),
                );
                false
            }
            Err(e) => {
                check(false, "lpass login", e.to_string());
                false
            }
        },
        None => false,
    };

    if let (Some(config), Some(client), true) = (&config, &client, logged_in) {
        let keys = match effective_keys(client, config).await {
            Ok(keys) => keys,
            Err(e) => {
                check(false, "keys", e.to_string());
                Vec::new()
            }
        };
        for inspection in keystore::inspect_keys(client.as_ref(), &keys, config).await {
            match inspection {
                keystore::KeyInspection::Usable(entry) => check(
                    true,
                    &format!("key {} [id: {}]", entry.name, entry.item_id),
                    format!("{} {}", entry.public.algorithm(), entry.fingerprint()),
                ),
                keystore::KeyInspection::Unusable {
                    item_id,
                    name,
                    issue,
                } => check(
                    false,
                    &format!("key {name} [id: {item_id}]"),
                    issue.to_string(),
                ),
            }
        }
    }

    if let Some(config) = &config {
        // Same invariants `start` enforces; a not-yet-existing directory
        // passes because `start` creates it correctly.
        let socket_check = config.socket_path().and_then(|path| {
            path.parent()
                .filter(|d| !d.as_os_str().is_empty())
                .map_or_else(
                    || Err(Error::Socket("socket path has no parent directory".into())),
                    socket::validate_dir,
                )
                .map(|()| path)
        });
        match socket_check {
            Ok(path) => check(true, "socket path", path.display().to_string()),
            Err(e) => check(false, "socket path", e.to_string()),
        }
    }

    if test_confirm {
        if let Some(config) = &config {
            if config.confirm == config::ConfirmMode::Off {
                check(
                    false,
                    "confirmation",
                    "confirm = \"off\" — nothing to test; enable a confirm mode first".into(),
                );
                return Err(Error::DoctorFailed);
            }
            let confirmer = confirm::from_config(config)?;
            let ctx = confirm::ConfirmContext {
                key_name: "doctor test (no real key)".into(),
                fingerprint: "SHA256:this-is-only-a-test".into(),
                item_id: "0".into(),
                peer: Some(confirm::PeerInfo {
                    pid: Some(std::process::id().cast_signed()),
                    uid: unsafe { libc::getuid() },
                }),
                bindings: Vec::new(),
            };
            match confirmer.confirm(&ctx).await {
                confirm::Decision::Approve => {
                    check(true, "confirmation", "user approved the test prompt".into());
                }
                confirm::Decision::Deny => check(
                    false,
                    "confirmation",
                    "denied/timed out (fail-closed works, but approve to pass this check)".into(),
                ),
            }
        }
    }

    if ok {
        Ok(())
    } else {
        Err(Error::DoctorFailed)
    }
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
    fn print_env_emits_export_line() {
        print_env(Path::new("/tmp/agent.sock"));
    }
}
