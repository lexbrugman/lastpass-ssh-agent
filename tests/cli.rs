//! CLI-level coverage of every subcommand and its failure modes, driving
//! the real binary with a fake `lpass`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/script.rs"]
mod script;
#[path = "common/vault.rs"]
mod vault;

use fixtures::{ED25519_PUB, SK_ED25519_PUB};
use script::write_script;

struct Setup {
    dir: tempfile::TempDir,
    config: PathBuf,
}

fn fake_lpass(dir: &Path, body: &str) -> PathBuf {
    write_script(dir, "lpass", body)
}

/// The standard healthy vault: item 1 is an SSH Key, item 3 is not.
fn healthy_vault_body(dir: &Path) -> String {
    vault::body(
        dir,
        &[
            vault::Item {
                id: "1",
                name: "Personal/ed",
                ssh_key: Some((ED25519_PUB, None)),
            },
            vault::Item {
                id: "3",
                name: "Personal/Visa",
                ssh_key: None,
            },
        ],
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

/// What real lpass says on stderr when it has no key and nothing answers
/// its prompt — whether the vault is locked or there is no login at all.
const NO_KEY: &str = "echo 'lpass: Error: Could not find decryption key. Perhaps you need to login with `lpass login`.' >&2; exit 1";

/// A vault that is locked until fed `secret` on stdin, and then healthy; any
/// other password is refused in lpass's words.
fn locked_vault_body() -> String {
    format!(
        r#"if ! IFS= read -r pw; then {NO_KEY}; fi
[ "$pw" = secret ] || {{ echo 'Incorrect master password; please try again.' >&2; {NO_KEY}; }}
{}"#,
        healthy_vault_body_owned()
    )
}

/// `setup`, with the master password asked for through a script answering
/// `answer` — the one prompt transport a test can drive.
fn asking_setup(lpass_body: &str, config_extra: &str, answer: &str) -> Setup {
    let s = setup(lpass_body, config_extra);
    let script = write_script(s.dir.path(), "askpass", answer);
    let config = format!(
        "{}confirm = \"askpass\"\naskpass = {}\n",
        std::fs::read_to_string(&s.config).unwrap(),
        toml::Value::String(script.display().to_string())
    );
    std::fs::write(&s.config, config).unwrap();
    s
}

fn run(setup: &Setup, args: &[&str]) -> Output {
    run_env(setup, args, &[])
}

fn run_env(setup: &Setup, args: &[&str], env: &[(&str, &Path)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lastpass-ssh-agent"))
        .arg("--config")
        .arg(&setup.config)
        .args(args)
        .env("HOME", setup.dir.path()) // never touch the real home
        .envs(env.iter().copied())
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
    // and it is the on-demand refresh of what a start reads
    let remembered = std::fs::read_to_string(s.dir.path().join("agent.sock.identities")).unwrap();
    assert!(remembered.contains("id = \"1\""), "{remembered}");
}

// helper indirection: healthy_vault_body needs a dir that outlives setup()
fn healthy_vault_body_owned() -> String {
    let keep = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    healthy_vault_body(keep.path())
}

#[test]
fn list_on_a_fresh_install_creates_the_socket_directory_and_writes_the_file() {
    // Nothing has ever bound here, so the directory does not exist. `list` is
    // the documented way to write the identities down before a first start
    // against a locked vault, so it has to make the directory itself.
    let s = setup(&healthy_vault_body_owned(), "");
    let fresh = s.dir.path().join("fresh");
    let config = std::fs::read_to_string(&s.config).unwrap();
    let config = regex_replace_socket(&config, &format!("{}/agent.sock", fresh.display()));
    std::fs::write(&s.config, config).unwrap();
    assert!(!fresh.exists());

    let output = run(&s, &["list"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o700,
        "the directory is private, as `start` makes it"
    );
    assert!(fresh.join("agent.sock.identities").exists());
}

#[test]
fn list_writes_nothing_down_from_a_scan_the_vault_did_not_answer_in_full() {
    // Item 2 is pinned and the vault fails on it, without saying it is gone.
    // The listing still shows item 1; the file a start would trust is left
    // alone, since the key may well be there.
    let keep = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    std::fs::write(keep.path().join("pub"), ED25519_PUB).unwrap();
    let body = format!(
        r#"case "$1" in
  status) echo "Logged in as test@example.com.";;
  show)
    case "$3" in
      1) cat "{}/pub";;
      *) echo 'Error: something went wrong.' >&2; exit 1;;
    esac;;
esac"#,
        keep.path().display()
    );
    let s = setup(&body, "[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"\n");
    let output = run(&s, &["list"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("[id: 1]"));
    assert!(
        stderr(&output).contains("not writing the remembered identities down"),
        "{}",
        stderr(&output)
    );
    assert!(!s.dir.path().join("agent.sock.identities").exists());
}

#[test]
fn list_writes_down_a_scan_the_vault_answered_even_when_an_item_is_gone() {
    // Item 2 is pinned but the vault has no such item: that is an answer, and
    // the file records the set without it.
    let keep = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    std::fs::write(keep.path().join("pub"), ED25519_PUB).unwrap();
    let body = format!(
        r#"case "$1" in
  status) echo "Logged in as test@example.com.";;
  show)
    case "$3" in
      1) cat "{}/pub";;
      *) echo 'Error: Could not find specified account(s).' >&2; exit 1;;
    esac;;
esac"#,
        keep.path().display()
    );
    let s = setup(&body, "[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"\n");
    let output = run(&s, &["list"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let written = std::fs::read_to_string(s.dir.path().join("agent.sock.identities")).unwrap();
    assert!(written.contains("id = \"1\""), "{written}");
    assert!(!written.contains("id = \"2\""), "{written}");
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
    // lpass says the same thing for a locked vault and for no login, so the
    // command asks for the master password first; only a vault that does not
    // even try it has no login.
    let s = asking_setup(NO_KEY, "", "echo anything");
    let output = run(&s, &["search"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not logged in"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_command_beside_a_running_agent_never_asks() {
    // The agent's prompts and this one cannot take turns, so a locked vault
    // fails here rather than putting a second prompt on the screen.
    let s = asking_setup(&locked_vault_body(), "", "echo secret");
    let _agent = std::os::unix::net::UnixListener::bind(s.dir.path().join("agent.sock")).unwrap();
    let output = run(&s, &["list"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("the vault is locked"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("will not ask"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_locked_vault_is_asked_for_the_master_password() {
    let s = asking_setup(&locked_vault_body(), "", "echo secret");
    let output = run(&s, &["list"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("[id: 1]"));
    assert!(
        stderr(&output).contains("holding the master password"),
        "{}",
        stderr(&output)
    );

    // and a wrong answer is reported in lpass's own verdict
    let s = asking_setup(&locked_vault_body(), "", "echo typo");
    let output = run(&s, &["list"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("did not accept the master password"),
        "{}",
        stderr(&output)
    );
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
    assert!(text.contains("✓ lpass login: logged in"), "{text}");
    assert!(text.contains("✓ key"));
    assert!(text.contains("✓ socket path"));
    assert!(!text.contains('✗'));
}

#[test]
fn doctor_reports_the_master_password_source() {
    let s = setup(&healthy_vault_body_owned(), "");
    let output = run(&s, &["doctor"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("✓ master password"), "{text}");
    assert!(text.contains("held only"), "{text}");
}

#[test]
fn doctor_opens_a_locked_vault_the_way_the_agent_would() {
    // The arrangement under test is the whole of it: found locked, the vault
    // is asked for the master password through the configured prompt, and
    // the key checks then run against it.
    let s = asking_setup(&locked_vault_body(), "", "echo secret");
    let output = run(&s, &["doctor"]);
    assert!(output.status.success(), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(text.contains("✓ lpass login"), "{text}");
    assert!(text.contains("✓ key"), "{text}");

    let s = asking_setup(&locked_vault_body(), "", "echo typo");
    let output = run(&s, &["doctor"]);
    assert!(!output.status.success());
    assert!(
        stdout(&output).contains("✗ lpass login: LastPass did not accept"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn doctor_beside_a_running_agent_passes_a_locked_vault() {
    // The agent leaves the vault locked between signatures by design, and
    // this command may not ask to open it, so locked is the healthy state
    // here — reported as such, with the key checks left for an open vault.
    // Unfed, lpass says the same whether or not there is a login, so the
    // session lpass writes down is what tells the two apart.
    let s = asking_setup(&locked_vault_body(), "", "echo secret");
    let _agent = std::os::unix::net::UnixListener::bind(s.dir.path().join("agent.sock")).unwrap();
    let lpass_home = s.dir.path().join("lpass-home");
    std::fs::create_dir(&lpass_home).unwrap();
    let env: &[(&str, &Path)] = &[("LPASS_HOME", &lpass_home)];

    let output = run_env(&s, &["doctor"], env);
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("✗ lpass login: not logged in"),
        "{}",
        stdout(&output)
    );

    std::fs::write(lpass_home.join("session_uid"), b"x").unwrap();
    let output = run_env(&s, &["doctor"], env);
    assert!(output.status.success(), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("✓ lpass login: logged in; the vault is locked"),
        "{text}"
    );
    assert!(!text.contains("✓ key "), "{text}");
    assert!(!text.contains('✗'), "{text}");
    assert!(
        stderr(&output).contains("will not ask"),
        "{}",
        stderr(&output)
    );
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

    // not logged in: no key, and a password that was never even tried
    let s = asking_setup(NO_KEY, "", "echo anything");
    let output = run(&s, &["doctor"]);
    assert!(!output.status.success());
    assert!(
        stdout(&output).contains("✗ lpass login: not logged in"),
        "{}",
        stdout(&output)
    );

    // the vault blows up entirely
    let s = setup("echo boom >&2; exit 9", "");
    let output = run(&s, &["doctor"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("✗ lpass login"));

    // pinned item whose Public Key field is empty / garbage / missing
    for (body, expect) in [
        (r#"case "$1" in show) printf '';; esac"#, "empty Public Key"),
        (
            r#"case "$1" in show) echo "not a key";; esac"#,
            "does not parse",
        ),
        (
            r#"case "$1" in show) echo 'Error: Could not find specified account(s).' >&2; exit 1;; esac"#,
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
        r#"case "$1" in ls) printf 'Personal/Visa [id: 3]\n';; show) echo "Credit Card";; esac"#,
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
        stdout(&output).contains("cannot sign with"),
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

    // an lpass found on PATH is still checked, with nothing to ask through
    let output = Command::new(env!("CARGO_BIN_EXE_lastpass-ssh-agent"))
        .arg("--config")
        .arg(&s.config)
        .arg("doctor")
        .env("HOME", s.dir.path())
        .env("PATH", s.dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        stdout(&output).contains("✓ lpass binary"),
        "{}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("✓ lpass login"),
        "{}",
        stdout(&output)
    );
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
fn storing_a_master_password_needs_the_touchid_source() {
    // Nothing to store without somewhere to put it, and saying so beats
    // prompting for a secret that would then have nowhere to go.
    let s = setup(&healthy_vault_body_owned(), "");
    let output = run(&s, &["store-master-password"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("master_password = \"touchid\""),
        "{}",
        stderr(&output)
    );
}

#[test]
fn both_master_password_commands_are_listed_in_help() {
    let s = setup(&healthy_vault_body_owned(), "");
    let help = stdout(&run(&s, &["--help"]));
    assert!(help.contains("store-master-password"), "{help}");
    assert!(help.contains("forget-master-password"), "{help}");
}

#[test]
fn forgetting_a_master_password_that_was_never_kept_is_fine() {
    // Nothing stored here — and off macOS nowhere to store — is the state the
    // command leaves behind, so it is a success either way.
    let s = setup(&healthy_vault_body_owned(), "");
    let output = run(&s, &["forget-master-password"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no master password is kept"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn start_refuses_when_logged_out() {
    let s = asking_setup(NO_KEY, "", "echo anything");
    let output = run(&s, &["start"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not logged in"),
        "{}",
        stderr(&output)
    );
    // and, being a first start, says what gets past a vault it cannot read
    assert!(
        stderr(&output).contains("run `lastpass-ssh-agent list`"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn start_refuses_with_no_ssh_keys_in_vault() {
    let s = setup(
        r#"case "$1" in ls) printf 'Personal/Visa [id: 3]\n';; show) echo "Credit Card";; esac"#,
        "",
    );
    let output = run(&s, &["start"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("no SSH Key items found"));
}

#[test]
fn start_outlives_a_socket_it_cannot_accept_from() {
    // Exhaust the agent's file-descriptor table: the accept loop then hits
    // EMFILE. Whoever holds those connections must not be able to end the
    // agent that way — it waits, and serves again once they let go.
    let s = setup(&healthy_vault_body_owned(), "confirm = \"off\"\n");
    let socket = s.dir.path().join("agent.sock");
    let log_path = s.dir.path().join("stderr.log");
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "ulimit -n 24; exec {} --config '{}' start",
            env!("CARGO_BIN_EXE_lastpass-ssh-agent"),
            s.config.display()
        ))
        .env("HOME", s.dir.path())
        // debug, for the line that says a second attempt failed as well
        .env("RUST_LOG", "debug")
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(&log_path).unwrap())
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

    // More connections than the agent has descriptors for. Connecting
    // succeeds regardless — the kernel queues what is not accepted — so the
    // agent's own word is what says it has met the shortage, and met it
    // again on trying once more.
    let held: Vec<_> = (0..40)
        .map(|_| std::os::unix::net::UnixStream::connect(&socket).unwrap())
        .collect();
    while !std::fs::read_to_string(&log_path)
        .unwrap()
        .contains("still cannot accept an agent connection")
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the agent never reported running out of descriptors"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(
        child.try_wait().unwrap(),
        None,
        "a socket that cannot be accepted from must not end the agent"
    );

    // ...and once they are gone, a new client is answered: SSH_AGENTC_REQUEST_
    // IDENTITIES, and the first byte after the length is the answer's type.
    drop(held);
    let mut client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    std::io::Write::write_all(&mut client, &[0, 0, 0, 1, 11]).unwrap();
    let mut answer = [0; 5];
    std::io::Read::read_exact(&mut client, &mut answer).unwrap();
    assert_eq!(answer[4], 12, "SSH_AGENT_IDENTITIES_ANSWER");

    // SAFETY: signaling the child we spawned.
    unsafe { libc::kill(child.id().cast_signed(), libc::SIGTERM) };
    child.wait().unwrap();
}
