//! A fake `lpass` for the tests that drive the real binary: a shell script
//! answering `ls` and `show` for a fixed set of items, reading keys from
//! files it keeps beside itself.
//!
//! Shared by the crates under `tests/`, each of which declares this file as a
//! module of its own, next to `script`.
#![allow(dead_code)] // each crate uses the part it needs

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// One vault item as the script answers for it.
pub struct Item {
    pub id: &'static str,
    pub name: &'static str,
    /// The public key, and the private key when the item holds one. `None`
    /// is an item of some other kind — a credit card, say.
    pub ssh_key: Option<(&'static str, Option<&'static str>)>,
}

/// The script's body, with the key files written into `dir`.
///
/// `ls` lists every item; `show` answers `NoteType`, the two key fields and
/// an empty `Passphrase`, and fails for anything else the way lpass does.
pub fn body(dir: &Path, items: &[Item]) -> String {
    let mut listing = String::new();
    let mut note_types = String::new();
    let mut public = String::new();
    let mut private = String::new();
    for item in items {
        let _ = write!(listing, "'{} [id: {}]' ", item.name, item.id);
        if let Some((public_key, private_key)) = item.ssh_key {
            let _ = write!(note_types, "{}|", item.id);
            let public_path = dir.join(format!("{}.pub", item.id));
            std::fs::write(&public_path, public_key).unwrap();
            let _ = write!(public, "{}) cat \"{}\";; ", item.id, public_path.display());
            if let Some(private_key) = private_key {
                let private_path = dir.join(format!("{}.key", item.id));
                std::fs::write(&private_path, private_key).unwrap();
                let _ = write!(
                    private,
                    "{}) cat \"{}\";; ",
                    item.id,
                    private_path.display()
                );
            }
        }
    }
    let note_types = if note_types.is_empty() {
        "x".to_string()
    } else {
        note_types.trim_end_matches('|').to_string()
    };
    format!(
        r#"case "$1" in
  ls) printf '%s\n' {listing};;
  show)
    case "$2" in
      "--field=NoteType") case "$3" in {note_types}) echo "SSH Key";; *) echo "Credit Card";; esac;;
      "--field=Public Key") case "$3" in {public}*) exit 1;; esac;;
      "--field=Private Key") case "$3" in {private}*) exit 1;; esac;;
      "--field=Passphrase") exit 0;;
      *) exit 1;;
    esac;;
  *) exit 1;;
esac"#
    )
}

/// The script itself, at `dir/lpass`.
pub fn write(dir: &Path, items: &[Item]) -> PathBuf {
    super::script::write_script(dir, "lpass", &body(dir, items))
}
