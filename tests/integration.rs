//! End-to-end: spawn the real binary with a fake `lpass`, speak the SSH
//! agent protocol to it over the Unix socket, verify signatures with the
//! public key, and check shutdown cleanup.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use signature::Verifier;
use ssh_agent_lib::agent::service_binding::Binding;
use ssh_agent_lib::client::connect;
use ssh_agent_lib::proto::extension::SessionBind;
use ssh_agent_lib::proto::{
    signature as sigflag, AddIdentity, Extension, PrivateCredential, SignRequest,
};
use ssh_key::{PrivateKey, PublicKey};

const ED25519: &str = include_str!("fixtures/ed25519");
const ED25519_PUB: &str = include_str!("fixtures/ed25519.pub");
const RSA: &str = include_str!("fixtures/rsa");
const RSA_PUB: &str = include_str!("fixtures/rsa.pub");

struct AgentUnderTest {
    child: Child,
    socket: PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for AgentUnderTest {
    fn drop(&mut self) {
        // SIGTERM first: a clean shutdown lets the process flush coverage
        // profiles (SIGKILL would silently drop the whole run's data).
        // SAFETY: signaling the child we spawned.
        unsafe { libc::kill(self.child.id().cast_signed(), libc::SIGTERM) };
        for _ in 0..100 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_fake_lpass(dir: &Path) -> PathBuf {
    for (name, content) in [
        ("ed25519", ED25519),
        ("ed25519.pub", ED25519_PUB),
        ("rsa", RSA),
        ("rsa.pub", RSA_PUB),
    ] {
        std::fs::write(dir.join(name), content).unwrap();
    }
    let script = dir.join("lpass");
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
FIX="{}"
case "$1" in
  status) echo "Logged in as test@example.com."; exit 0;;
  ls)
    printf 'Personal/ed [id: 1]\nWork/rsa [id: 2]\nPersonal/Visa [id: 3]\n';;
  show)
    item="$3"
    case "$2" in
      "--field=NoteType") if [ "$item" = 1 ] || [ "$item" = 2 ]; then echo "SSH Key"; else echo "Credit Card"; fi;;
      "--field=Public Key") cat "$FIX/key$item.pub";;
      "--field=Private Key") cat "$FIX/key$item";;
      "--field=Passphrase") exit 0;;
      *) exit 1;;
    esac;;
  *) exit 1;;
esac
"#,
            dir.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    // key ids map to fixture files: item 1 = ed25519, item 2 = rsa
    std::fs::hard_link(dir.join("ed25519"), dir.join("key1")).unwrap();
    std::fs::hard_link(dir.join("ed25519.pub"), dir.join("key1.pub")).unwrap();
    std::fs::hard_link(dir.join("rsa"), dir.join("key2")).unwrap();
    std::fs::hard_link(dir.join("rsa.pub"), dir.join("key2.pub")).unwrap();
    script
}

fn start_agent() -> AgentUnderTest {
    start_agent_with_keys(
        r#"
[[keys]]
id = "1"
name = "test ed25519"

[[keys]]
id = "2"
name = "test rsa"
"#,
    )
}

/// Empty `keys_toml` exercises auto-discovery (no [[keys]] configured).
fn start_agent_with_keys(keys_toml: &str) -> AgentUnderTest {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let script = write_fake_lpass(dir.path());
    let socket = dir.path().join("agent.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
socket = "{}"
confirm = "off"
lpass_path = "{}"
{keys_toml}"#,
            socket.display(),
            script.display()
        ),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_lastpass-ssh-agent"))
        .args(["--config", config_path.to_str().unwrap(), "start"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    let agent = AgentUnderTest {
        child,
        socket,
        _dir: dir,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !agent.socket.exists() {
        assert!(Instant::now() < deadline, "agent socket never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }
    agent
}

fn pubkey(openssh: &str) -> PublicKey {
    PublicKey::from_openssh(openssh.trim()).unwrap()
}

#[tokio::test]
async fn full_agent_protocol_roundtrip() {
    let agent = start_agent();
    let mut client = connect(Binding::FilePath(agent.socket.clone()).try_into().unwrap()).unwrap();

    // identities
    let identities = client.request_identities().await.unwrap();
    assert_eq!(identities.len(), 2);
    assert!(identities.iter().any(|i| i.comment.contains("lastpass:1")));

    // ed25519 signature verifies against the fixture public key
    let ed = pubkey(ED25519_PUB);
    let sig = client
        .sign(SignRequest {
            credential: ed.key_data().clone().into(),
            data: b"integration payload".to_vec(),
            flags: 0,
        })
        .await
        .unwrap();
    ed.key_data().verify(b"integration payload", &sig).unwrap();

    // rsa honors the SHA-2 flags
    let rsa = pubkey(RSA_PUB);
    let sig = client
        .sign(SignRequest {
            credential: rsa.key_data().clone().into(),
            data: b"integration payload".to_vec(),
            flags: sigflag::RSA_SHA2_256,
        })
        .await
        .unwrap();
    assert_eq!(sig.algorithm().as_str(), "rsa-sha2-256");
    rsa.key_data().verify(b"integration payload", &sig).unwrap();

    // rsa without SHA-2 flags (SHA-1) is refused
    assert!(client
        .sign(SignRequest {
            credential: rsa.key_data().clone().into(),
            data: b"x".to_vec(),
            flags: 0,
        })
        .await
        .is_err());

    // a key the agent does not hold is refused
    let (foreign, _) = new_throwaway_key();
    assert!(client
        .sign(SignRequest {
            credential: foreign.public_key().key_data().clone().into(),
            data: b"x".to_vec(),
            flags: 0,
        })
        .await
        .is_err());

    // adding identities is refused (this agent is read-only by design)
    assert!(client
        .add_identity(AddIdentity {
            credential: PrivateCredential::Key {
                privkey: foreign.key_data().clone(),
                comment: "sneaky".into(),
            },
        })
        .await
        .is_err());

    // ...and the identity list is unchanged afterwards
    assert_eq!(client.request_identities().await.unwrap().len(), 2);
}

#[tokio::test]
async fn auto_discovery_serves_vault_ssh_keys_without_config_keys() {
    // No [[keys]]: the agent must discover items 1 and 2 as SSH Keys via
    // NoteType probes (item 3 is a credit card) and serve them.
    let agent = start_agent_with_keys("");
    let mut client = connect(Binding::FilePath(agent.socket.clone()).try_into().unwrap()).unwrap();

    let identities = client.request_identities().await.unwrap();
    assert_eq!(identities.len(), 2);
    assert!(identities.iter().any(|i| i.comment.contains("lastpass:1")));
    assert!(identities.iter().any(|i| i.comment.contains("lastpass:2")));
    assert!(!identities.iter().any(|i| i.comment.contains("lastpass:3")));

    // and a discovered key actually signs
    let ed = pubkey(ED25519_PUB);
    let sig = client
        .sign(SignRequest {
            credential: ed.key_data().clone().into(),
            data: b"discovered".to_vec(),
            flags: 0,
        })
        .await
        .unwrap();
    ed.key_data().verify(b"discovered", &sig).unwrap();
}

#[tokio::test]
async fn debug_logging_never_dumps_agent_requests() {
    // ssh-agent-lib debug-formats whole requests; an AddIdentity request
    // contains the client's private key. Even with the most specific
    // RUST_LOG directive, the secret cap must keep those dumps off stderr.
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let script = write_fake_lpass(dir.path());
    let socket = dir.path().join("agent.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "socket = \"{}\"\nconfirm = \"off\"\nlpass_path = \"{}\"\n[[keys]]\nid = \"1\"\n",
            socket.display(),
            script.display()
        ),
    )
    .unwrap();
    let stderr_path = dir.path().join("stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_lastpass-ssh-agent"))
        .args(["--config", config_path.to_str().unwrap(), "start"])
        .env("RUST_LOG", "ssh_agent_lib::agent=trace,debug")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_file)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "agent socket never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }

    let mut client = connect(Binding::FilePath(socket).try_into().unwrap()).unwrap();
    let (foreign, _) = new_throwaway_key();
    let _ = client
        .add_identity(AddIdentity {
            credential: PrivateCredential::Key {
                privkey: foreign.key_data().clone(),
                comment: "must never reach the log".into(),
            },
        })
        .await;
    drop(client);

    // stop the agent cleanly so stderr is flushed, then inspect it
    // SAFETY: signaling the child we spawned.
    unsafe { libc::kill(child.id().cast_signed(), libc::SIGTERM) };
    let _ = child.wait();
    let log = std::fs::read_to_string(&stderr_path).unwrap();
    assert!(
        !log.contains("AddIdentity") && !log.contains("must never reach the log"),
        "request dump leaked into the log:\n{log}"
    );
}

#[tokio::test]
async fn routine_traffic_is_not_logged_as_errors() {
    // The refusals a normal session produces — OpenSSH's per-connection
    // extension probe, and anything this read-only agent declines — are
    // protocol answers, so nothing may reach the log at ERROR while
    // ssh-agent-lib's own logging is enabled.
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let script = write_fake_lpass(dir.path());
    let socket = dir.path().join("agent.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "socket = \"{}\"\nconfirm = \"off\"\nlpass_path = \"{}\"\n[[keys]]\nid = \"1\"\n",
            socket.display(),
            script.display()
        ),
    )
    .unwrap();
    let stderr_path = dir.path().join("stderr.log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_lastpass-ssh-agent"))
        .args(["--config", config_path.to_str().unwrap(), "start"])
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "agent socket never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }

    let mut client = connect(Binding::FilePath(socket).try_into().unwrap()).unwrap();
    client.request_identities().await.unwrap();
    // an extension probe, exactly as OpenSSH sends on every connection
    let (foreign, _) = new_throwaway_key();
    let _ = client
        .extension(
            Extension::new_message(SessionBind {
                host_key: foreign.public_key().key_data().clone(),
                session_id: vec![1, 2, 3],
                signature: ssh_key::Signature::new(ssh_key::Algorithm::Ed25519, vec![0u8; 64])
                    .unwrap(),
                is_forwarding: false,
            })
            .unwrap(),
        )
        .await;
    let _ = client
        .add_identity(AddIdentity {
            credential: PrivateCredential::Key {
                privkey: foreign.key_data().clone(),
                comment: "refused".into(),
            },
        })
        .await;
    drop(client);

    // SAFETY: signaling the child we spawned.
    unsafe { libc::kill(child.id().cast_signed(), libc::SIGTERM) };
    let _ = child.wait();
    let log = std::fs::read_to_string(&stderr_path).unwrap();
    assert!(
        !log.contains("ERROR"),
        "routine traffic logged as an error:\n{log}"
    );
    // the agent's own reporting is still there
    assert!(log.contains("serving key"), "{log}");
}

#[tokio::test]
async fn sigterm_removes_socket() {
    let mut agent = start_agent();
    // SAFETY: sending SIGTERM to the child we spawned.
    unsafe { libc::kill(agent.child.id().cast_signed(), libc::SIGTERM) };
    let status = agent.child.wait().unwrap();
    assert!(status.success(), "clean exit on SIGTERM");
    assert!(
        !agent.socket.exists(),
        "socket must be unlinked on shutdown"
    );
}

/// A key generated fresh for the test, never known to the agent.
fn new_throwaway_key() -> (PrivateKey, PublicKey) {
    // Reuse the passphrase-protected fixture decrypted — it's a different
    // keypair from the two the agent serves.
    let private = PrivateKey::from_openssh(include_str!("fixtures/ed25519_pw"))
        .unwrap()
        .decrypt("fixture-passphrase")
        .unwrap();
    let public = private.public_key().clone();
    (private, public)
}
