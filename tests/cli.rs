//! CLI-level coverage of every subcommand and its failure modes, driving
//! the real binary with a fake `lpass`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ED25519_PUB: &str = include_str!("fixtures/ed25519.pub");
const SK_ED25519_PUB: &str = include_str!("fixtures/sk_ed25519.pub");

struct Setup {
    dir: tempfile::TempDir,
    config: PathBuf,
}

fn fake_lpass(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("lpass");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// The standard healthy vault: item 1 is an SSH Key, item 3 is not.
fn healthy_vault_body(dir: &Path) -> String {
    std::fs::write(dir.join("pub"), ED25519_PUB).unwrap();
    format!(
        r#"case "$1" in
  status) echo "Logged in as test@example.com.";;
  ls) printf 'Personal/ed [id: 1]\nPersonal/Visa [id: 3]\n';;
  show)
    case "$2" in
      "--field=NoteType") [ "$3" = 1 ] && echo "SSH Key" || echo "Credit Card";;
      "--field=Public Key") cat "{}/pub";;
      *) exit 1;;
    esac;;
esac"#,
        dir.display()
    )
}

fn setup(lpass_body: &str, config_extra: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let lpass = fake_lpass(dir.path(), lpass_body);
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "socket = \"{}/agent.sock\"\nlpass_path = \"{}\"\n{config_extra}",
            dir.path().display(),
            lpass.display()
        ),
    )
    .unwrap();
    Setup { dir, config }
}

fn run(setup: &Setup, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lastpass-ssh-agent"))
        .arg("--config")
        .arg(&setup.config)
        .args(args)
        .env("HOME", setup.dir.path()) // never touch the real home
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn env_prints_socket_export() {
    let s = setup("exit 0", "");
    let output = run(&s, &["env"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("SSH_AUTH_SOCK='"));
    assert!(stdout(&output).contains("agent.sock'; export SSH_AUTH_SOCK;"));
}

#[test]
fn env_works_without_any_config_file() {
    let s = setup("exit 0", "");
    let output = Command::new(env!("CARGO_BIN_EXE_lastpass-ssh-agent"))
        .args(["--config", "/nonexistent/config.toml", "env"])
        .env("HOME", s.dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(stdout(&output).contains("SSH_AUTH_SOCK="));
}

#[test]
fn list_shows_discovered_keys() {
    let s = setup(&healthy_vault_body_owned(), "");
    let output = run(&s, &["list"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("SHA256:"), "{text}");
    assert!(text.contains("[id: 1]"));
    assert!(text.contains("confirm=on"));
}

// helper indirection: healthy_vault_body needs a dir that outlives setup()
fn healthy_vault_body_owned() -> String {
    let keep = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    healthy_vault_body(keep.path())
}

#[test]
fn list_with_pinned_key_and_confirm_off() {
    let s = setup(
        &healthy_vault_body_owned(),
        "confirm = \"off\"\n[[keys]]\nid = \"1\"\nname = \"pinned\"\n",
    );
    let output = run(&s, &["list"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("pinned"));
    assert!(stdout(&output).contains("confirm=off"));
}

#[test]
fn search_lists_and_filters() {
    let s = setup(&healthy_vault_body_owned(), "");
    let all = run(&s, &["search"]);
    assert!(all.status.success(), "{}", stderr(&all));
    assert!(stdout(&all).contains("Personal/ed"));
    assert!(stdout(&all).contains("[[keys]]"));

    let hit = run(&s, &["search", "ed"]);
    assert!(stdout(&hit).contains("Personal/ed"));

    let miss = run(&s, &["search", "zzz"]);
    assert!(miss.status.success());
    assert!(stdout(&miss).contains("no SSH Key items matching"));
}

#[test]
fn search_no_ssh_items_at_all() {
    let s = setup(
        r#"case "$1" in
  status) echo "Logged in as t@example.com.";;
  ls) printf 'Personal/Visa [id: 3]\n';;
  show) echo "Credit Card";;
esac"#,
        "",
    );
    let output = run(&s, &["search"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("no SSH Key items in the vault"));
}

#[test]
fn search_fails_cleanly_when_logged_out() {
    let s = setup("echo 'Not logged in.'; exit 1", "");
    let output = run(&s, &["search"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("not logged in"));
}

#[test]
fn missing_path_variable_means_no_lpass() {
    // With PATH unset entirely, the PATH search must give up cleanly.
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lastpass-ssh-agent"))
        .args(["--config", "/nonexistent/config.toml", "search"])
        .env("HOME", dir.path())
        .env_remove("PATH")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("lpass binary not found"));
}

#[test]
fn missing_lpass_binary_is_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "lpass_path = \"/nonexistent/lpass\"\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lastpass-ssh-agent"))
        .arg("--config")
        .arg(&config)
        .arg("search")
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("lpass binary not found"));
}

#[test]
fn doctor_all_green() {
    let s = setup(&healthy_vault_body_owned(), "");
    let output = run(&s, &["doctor"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("✓ config"));
    assert!(text.contains("auto-discovery"));
    assert!(text.contains("✓ lpass login: test@example.com"));
    assert!(text.contains("✓ key"));
    assert!(text.contains("✓ socket path"));
    assert!(!text.contains('✗'));
}

#[test]
fn doctor_reports_pinned_keys_and_socket_problems() {
    let s = setup(
        &healthy_vault_body_owned(),
        "[[keys]]\nid = \"1\"\nname = \"pinned\"\n",
    );
    // break the socket dir: point it at a world-readable directory
    let open_dir = s.dir.path().join("open");
    std::fs::create_dir(&open_dir).unwrap();
    std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = std::fs::read_to_string(&s.config).unwrap();
    let config = config.replace(
        &format!("socket = \"{}/agent.sock\"", s.dir.path().display()),
        &format!("socket = \"{}/agent.sock\"", open_dir.display()),
    );
    std::fs::write(&s.config, config).unwrap();

    let output = run(&s, &["doctor"]);
    assert!(!output.status.success());
    let text = stdout(&output);
    assert!(text.contains("1 pinned key(s)"));
    assert!(text.contains("✗ socket path"));
}

#[test]
fn doctor_flags_binary_login_and_key_problems() {
    // bogus lpass binary
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "lpass_path = \"/nonexistent/lpass\"\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lastpass-ssh-agent"))
        .arg("--config")
        .arg(&config)
        .arg("doctor")
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stdout(&output).contains("✗ lpass binary"));

    // not logged in
    let s = setup("echo 'Not logged in.'; exit 1", "");
    let output = run(&s, &["doctor"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("✗ lpass login"));

    // status blows up entirely
    let s = setup("echo boom >&2; exit 9", "");
    let output = run(&s, &["doctor"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("✗ lpass login"));

    // pinned item whose Public Key field is empty / garbage / missing
    for (body, expect) in [
        (
            r#"case "$1" in status) echo "Logged in as t.";; show) printf '';; esac"#,
            "empty Public Key",
        ),
        (
            r#"case "$1" in status) echo "Logged in as t.";; show) echo "not a key";; esac"#,
            "does not parse",
        ),
        (
            r#"case "$1" in status) echo "Logged in as t.";; show) echo 'Error: Could not find specified account(s).' >&2; exit 1;; esac"#,
            "not found",
        ),
    ] {
        let s = setup(body, "[[keys]]\nid = \"1\"\n");
        let output = run(&s, &["doctor"]);
        assert!(!output.status.success());
        assert!(stdout(&output).contains(expect), "{}", stdout(&output));
    }

    // discovery finds nothing -> keys check fails
    let s = setup(
        r#"case "$1" in status) echo "Logged in as t.";; ls) printf 'Personal/Visa [id: 3]\n';; show) echo "Credit Card";; esac"#,
        "",
    );
    let output = run(&s, &["doctor"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("✗ keys"), "{}", stdout(&output));
}

#[test]
fn doctor_flags_a_key_the_agent_cannot_sign_with() {
    // security-key entries sign on the FIDO device; the agent would have to
    // refuse every request, so doctor must say so rather than pass
    let s = setup(
        r#"case "$1" in
  status) echo "Logged in as t.";;
  show) [ "$2" = "--field=Public Key" ] && printf '%s' 'SKPUB' || exit 1;;
esac"#,
        "[[keys]]\nid = \"1\"\n",
    );
    let script = std::fs::read_to_string(s.dir.path().join("lpass")).unwrap();
    std::fs::write(
        s.dir.path().join("lpass"),
        script.replace("SKPUB", SK_ED25519_PUB.trim()),
    )
    .unwrap();
    let output = run(&s, &["doctor"]);
    assert!(!output.status.success());
    assert!(
        stdout(&output).contains("cannot be signed with"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn doctor_flags_duplicate_public_keys() {
    // items 1 and 2 both return the same public key: start would refuse,
    // so doctor must too
    let s = setup(
        r#"case "$1" in
  status) echo "Logged in as t.";;
  show) [ "$2" = "--field=Public Key" ] && printf '%s' 'PUBKEY_PLACEHOLDER' || exit 1;;
esac"#,
        "[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"\n",
    );
    let script = std::fs::read_to_string(s.dir.path().join("lpass")).unwrap();
    std::fs::write(
        s.dir.path().join("lpass"),
        script.replace("PUBKEY_PLACEHOLDER", ED25519_PUB.trim()),
    )
    .unwrap();
    let output = run(&s, &["doctor"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("ambiguous"), "{}", stdout(&output));
}

#[test]
fn doctor_with_broken_config_file() {
    let s = setup("exit 0", "");
    std::fs::write(&s.config, "not = valid = toml").unwrap();
    let output = run(&s, &["doctor"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("✗ config"));

    // --test-confirm with an unusable config skips the confirmation check
    let output = run(&s, &["doctor", "--test-confirm"]);
    assert!(!output.status.success());
    assert!(!stdout(&output).contains("confirmation"));
}

#[test]
fn doctor_rejects_socket_path_without_parent() {
    let s = setup(&healthy_vault_body_owned(), "");
    let config = std::fs::read_to_string(&s.config).unwrap();
    let config = regex_replace_socket(&config, "/");
    std::fs::write(&s.config, config).unwrap();
    let output = run(&s, &["doctor"]);
    assert!(!output.status.success());
    assert!(
        stdout(&output).contains("no parent directory"),
        "{}",
        stdout(&output)
    );
}

fn regex_replace_socket(config: &str, new_socket: &str) -> String {
    config
        .lines()
        .map(|line| {
            if line.starts_with("socket = ") {
                format!("socket = \"{new_socket}\"")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn doctor_without_config_file_uses_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lastpass-ssh-agent"))
        .args(["--config", "/nonexistent/config.toml", "doctor"])
        .env("HOME", dir.path())
        .env("PATH", "/nonexistent") // ensure no real lpass is found
        .output()
        .unwrap();
    assert!(!output.status.success());
    let text = stdout(&output);
    assert!(text.contains("✓ config"));
    assert!(text.contains("using defaults + auto-discovery"));
    assert!(text.contains("✗ lpass binary"));
}

#[test]
fn doctor_test_confirm_modes() {
    // confirm=off: nothing to test -> failure
    let s = setup(&healthy_vault_body_owned(), "confirm = \"off\"\n");
    let output = run(&s, &["doctor", "--test-confirm"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("nothing to test"));

    // askpass helper approving
    let s = setup(
        &healthy_vault_body_owned(),
        "confirm = \"askpass\"\naskpass = \"/usr/bin/true\"\n",
    );
    let output = run(&s, &["doctor", "--test-confirm"]);
    assert!(output.status.success(), "{}", stdout(&output));
    assert!(stdout(&output).contains("user approved"));

    // askpass helper denying
    let s = setup(
        &healthy_vault_body_owned(),
        "confirm = \"askpass\"\naskpass = \"/usr/bin/false\"\n",
    );
    let output = run(&s, &["doctor", "--test-confirm"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("denied/timed out"));
}

#[test]
fn start_refuses_when_logged_out() {
    let s = setup("echo 'Not logged in.'; exit 1", "");
    let output = run(&s, &["start"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("not logged in"));
}

#[test]
fn start_refuses_with_no_ssh_keys_in_vault() {
    let s = setup(
        r#"case "$1" in status) echo "Logged in as t.";; ls) printf 'Personal/Visa [id: 3]\n';; show) echo "Credit Card";; esac"#,
        "",
    );
    let output = run(&s, &["start"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("no SSH Key items found"));
}

#[test]
#[expect(
    clippy::collection_is_never_read,
    reason = "the Vec exists to hold fds open"
)]
fn start_exits_with_error_when_accept_fails() {
    // Exhaust the agent's file-descriptor table: the accept loop then hits
    // EMFILE and `start` must exit nonzero rather than spin forever.
    // Connections are held open so their fds stay occupied.
    let s = setup(&healthy_vault_body_owned(), "confirm = \"off\"\n");
    let socket = s.dir.path().join("agent.sock");
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "ulimit -n 24; exec {} --config '{}' start",
            env!("CARGO_BIN_EXE_lastpass-ssh-agent"),
            s.config.display()
        ))
        .env("HOME", s.dir.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !socket.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "socket never appeared"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Keep opening connections until the agent dies. Machine load only
    // changes how many attempts that takes, never the outcome, so the loop
    // is bounded by a generous wall-clock deadline instead of a fixed count.
    let mut held = Vec::new();
    let mut status = None;
    while std::time::Instant::now() < deadline {
        if let Some(exited) = child.try_wait().unwrap() {
            status = Some(exited);
            break;
        }
        if let Ok(stream) = std::os::unix::net::UnixStream::connect(&socket) {
            held.push(stream);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let Some(status) = status else {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("agent did not exit after fd exhaustion");
    };
    assert!(!status.success(), "accept failure must be fatal");
}
