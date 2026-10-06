//! `list` and `search`: what the agent would serve, and what the vault holds.

use std::path::Path;

use crate::config::Config;
use crate::error::Result;
use crate::{identities, keystore, lpass, socket, text};

/// Print the keys the agent would serve, and write them down for the next
/// start.
pub async fn list(config_path: &Path) -> Result<()> {
    let config = Config::load_or_default(config_path)?;
    let client = super::asking_client(&config)?;
    let keys = keystore::effective_keys(&client, &config).await?;
    let store = keystore::KeyStore::load(client.as_ref(), &keys, &config).await?;
    // Rewrites what the next start reads. A running agent does not read
    // this; it refreshes itself after a signature.
    // Before the first start there is no socket directory yet, and a file
    // the next start is meant to read cannot go into a directory that
    // is not there.
    let socket_path = config.socket_path()?;
    socket::prepare_parent(&socket_path)?;
    super::remember_if_complete(&identities::path_for(&socket_path), &store, keys.len());
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

/// Interactive helper: find the vault's SSH Key items (optionally filtered
/// by name) and print pin-ready config snippets.
pub async fn search(config_path: &Path, query: Option<&str>) -> Result<()> {
    // Must work before any config exists — it's the setup helper.
    let config = Config::load_or_default(config_path)?;
    let client = super::asking_client(&config)?;
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
