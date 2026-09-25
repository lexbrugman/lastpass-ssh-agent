#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod agent;
mod approvals;
// Excluded from coverage: one `spawn_blocking` shared by the two macOS stores,
// whose failure is a panicking Apple call that a test cannot arrange.
#[cfg(target_os = "macos")]
#[cfg_attr(coverage_nightly, coverage(off))]
mod apple;
mod cli;
mod commands;
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
mod requester;
mod signing;
mod socket;
#[cfg(test)]
mod testutil;
mod text;
mod tty;
mod unlock;
mod vaultlock;

use clap::Parser;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::cli::{Cli, Command};
use crate::config::Config;
use crate::error::{Error, Result};

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
        Command::Doctor { test_confirm } => commands::doctor::run(&config_path, test_confirm).await,
        Command::Env => commands::env::run(&config_path),
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
            commands::start::run(&config_path).await
        }
        Command::List => commands::list::list(&config_path).await,
        Command::Search { query } => commands::list::search(&config_path, query.as_deref()).await,
        Command::StoreMasterPassword => commands::master_password::store(&config_path).await,
        Command::ForgetMasterPassword => commands::master_password::forget(&config_path).await,
    }
}
