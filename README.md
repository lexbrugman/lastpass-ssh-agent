# lastpass-ssh-agent

An SSH agent backed by the LastPass CLI. Your SSH private keys live only in
your LastPass vault ("SSH Key" items) — never in `~/.ssh`, never on disk.
Every signature fetches the key from `lpass`, asks you to confirm, signs in
memory, and discards the key material.

```
ssh ──(SSH agent protocol)──▶ lastpass-ssh-agent ──(spawns)──▶ lpass ──▶ LastPass vault
```

## Security model — read this first

What this agent **guarantees**:

- **No filesystem persistence.** The private key is fetched from `lpass`
  over a pipe, parsed in memory, used for one signature, and zeroized. It is
  never written to disk, never passed through a shell, argv, or environment.
- **No caching.** There is deliberately no private-key cache. Each signature
  is a fresh fetch (public keys and item metadata are cached for the agent's
  lifetime — they are not secrets).
- **User-visible signing.** By default every signature pops a native
  confirmation dialog naming the key and the requesting process, with *Deny*
  as the default and cancel button. Timeouts, missing GUI sessions, and
  helper failures all fail closed to Deny.
- **Agent forwarding is visible.** The agent implements
  `session-bind@openssh.com`, so when a request arrives over a connection you
  forwarded with `ssh -A`, the prompt names the host chain (verified by each
  host's own key signature) and warns that the request may have originated
  there rather than on your machine. Without this, a relayed request looks
  identical to one you made yourself. Bindings whose signature does not
  verify are refused and never displayed.
- **Read-only agent.** `ssh-add` (add/remove/lock/unlock) is refused. The
  agent serves the vault's SSH Key items discovered at startup — or, with
  `[[keys]]` pinned in the config, exactly those and nothing else.

What it **cannot** guarantee:

- **The key does leave LastPass.** `lpass` hands the agent the actual
  private-key bytes; this is not an HSM-style `sign(key_id, data)` API.
  During a signature, plaintext key material exists briefly in `lpass`, the
  pipe, and this agent's memory. An attacker who can read this process's
  memory — or who owns your user account — wins regardless.
- Deliberately **not** done, because it would be theater given the above:
  `mlock`/`MADV_DONTDUMP` (key material lives milliseconds and macOS swap is
  encrypted by default) and `PT_DENY_ATTACH` (a local debugger-capable
  attacker can attach to `lpass` itself, which holds the whole vault).
- What **is** done cheaply: core dumps disabled (`RLIMIT_CORE=0`),
  `umask 077`, socket directory forced to `0700`/owner-only with symlink
  refusal, socket `0600`, lpass environment allowlisted, lpass pinentry
  disabled (the agent never handles your master password — log in with
  `lpass login` yourself), `ssh_agent_lib` debug logging capped (its request
  dumps could contain a private key a client tried to add).

## Install

```sh
brew install lexbrugman/tap/lastpass-ssh-agent
```

That pulls a prebuilt binary from the GitHub release for your platform
(macOS arm64/x86_64, Linux arm64/x86_64) and brings in `lastpass-cli`. The
Linux builds are musl-linked, so they do not depend on the host's glibc
version. Each release also carries a shell installer if you would rather not
use Homebrew.

> The tap is populated by the release pipeline. Until the first release has
> run and a `homebrew-tap` repository exists (see [Releasing](#releasing)),
> build from source instead.

Or build it yourself:

```sh
brew install lastpass-cli
cargo build --release        # needs rustup; rust-version >= 1.87
cp target/release/lastpass-ssh-agent /usr/local/bin/  # or anywhere on PATH
```

Versions are CalVer — `YYYY.MMDD.PATCH`, so `2026.810.0` is the first
release on 10 August 2026 and `2026.810.1` a same-day fix. `--version`
spells it out along with the exact commit:

```
$ lastpass-ssh-agent --version
lastpass-ssh-agent 2026.810.0 (2026-08-10, commit 4f2a9c1e77b3)
```

## Setup

No config file is needed. The agent auto-discovers every **SSH Key** item
in your vault (one `lpass ls` plus a `NoteType` metadata probe per item —
no secret fields are touched during discovery).

1. Store your key in LastPass as an **SSH Key** item (it has dedicated
   Private Key / Public Key / Passphrase fields).
2. Log in: `lpass login you@example.com`
3. Check everything: `lastpass-ssh-agent doctor` (add `--test-confirm` to
   try the confirmation dialog once — first use may trigger a macOS
   automation permission prompt for System Events).
   `lastpass-ssh-agent search` lists the SSH Key items it would serve.

### Optional config

`~/.config/lastpass-ssh-agent/config.toml` — for pinning specific items
(the strictest mode: only listed ids are ever served, and startup skips the
vault scan) or tuning behavior:

```toml
# confirm = "osascript"        # default on macOS; tty | askpass | off
# confirm_timeout_secs = 30
# socket = "~/Library/Application Support/lastpass-ssh-agent/agent.sock"
# lpass_path = "/opt/homebrew/bin/lpass"

# Pin items (disables auto-discovery); `search` prints these snippets.
[[keys]]
id = "7482913650418273946"     # stable LastPass item id (names are ambiguous)
name = "github"
# confirm = false              # per-key override
```

## Run

```sh
lastpass-ssh-agent start
# it prints: SSH_AUTH_SOCK='...'; export SSH_AUTH_SOCK;
```

In another shell (or via `lastpass-ssh-agent env`):

```sh
eval "$(lastpass-ssh-agent env)"
ssh-add -l          # lists your LastPass-backed keys
ssh github.com      # pops the confirmation dialog, then signs
```

If you log out of LastPass while the agent runs, signatures fail with a
clear log message; `lpass login` in any terminal and retry — the agent does
not need a restart.

### Start automatically

Installed via Homebrew, one command covers both platforms — it writes a
launchd user agent on macOS and a systemd `--user` unit on Linux:

```sh
brew services start lastpass-ssh-agent
```

Do **not** use `sudo brew services`: as a system daemon the agent has no GUI
session, so every confirmation prompt fails closed and nothing is ever
signed. On Linux a background service also has no terminal, so the default
`tty` confirmation cannot work — set `confirm = "askpass"` with a helper such
as `/usr/bin/ssh-askpass` before starting it.

<details>
<summary>Managing launchd yourself instead</summary>

`~/Library/LaunchAgents/com.lastpass-ssh-agent.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.lastpass-ssh-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/lastpass-ssh-agent</string>
    <string>start</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>EnvironmentVariables</key>
  <dict>
    <!-- launchd's default PATH has no Homebrew dirs; without this the agent
         cannot find lpass (alternatively set `lpass_path` in the config) -->
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>StandardErrorPath</key>
  <string>/tmp/lastpass-ssh-agent.log</string>
</dict>
</plist>
```

```sh
launchctl load ~/Library/LaunchAgents/com.lastpass-ssh-agent.plist
```

</details>

Then set `SSH_AUTH_SOCK` in your shell profile via
`eval "$(lastpass-ssh-agent env)"`, or per host in `~/.ssh/config`:

```
Host github.com
    IdentityAgent "~/Library/Application Support/lastpass-ssh-agent/agent.sock"
```

Note that `IdentityAgent` **overrides `SSH_AUTH_SOCK`**, so once it is set,
pointing `SSH_AUTH_SOCK` at a different agent has no effect for those hosts
— use `ssh -F /dev/null` (or a different `Host` block) when you want to test
another agent.

## Confirmation modes

| mode | behavior |
|---|---|
| `osascript` (macOS default) | Native dialog: key name, fingerprint, requesting process (pid/uid via the socket's peer credentials). Deny is default + cancel; expiry = Deny; no GUI session = Deny. Vault-sourced strings are passed as AppleScript *arguments*, never spliced into code. |
| `tty` (Linux default) | Prompt on the agent's own `/dev/tty`; type `yes` to approve. |
| `askpass` | Runs the program in `askpass` with the prompt as its argument; exit 0 approves. `SSH_ASKPASS_PROMPT=confirm` is set, so OpenSSH-compatible helpers show a yes/no dialog rather than their password prompt — without it, clicking OK would approve whatever was typed. |
| `off` | No confirmation (socket permissions are then your only guard, as with stock ssh-agent). |

## Releasing

Releases are automatic: **every push to `master` that passes the gate
publishes one**, and nothing has to be tagged by hand. `release-on-master.yml`
derives the next version from the date (`2026.810.0`, then `2026.810.1` for a
second release the same day — so every build gets a unique number without
anyone choosing it), commits it, and dispatches the release. Pushes to any
other branch, such as `dev`, only run the tests.

The release itself is [dist](https://github.com/axodotdev/cargo-dist):
`.github/workflows/release.yml` is generated by `dist generate` and should
not be hand-edited — change `[workspace.metadata.dist]` in `Cargo.toml` and
regenerate. dist cross-builds the four targets, packages and checksums them,
publishes the GitHub release, and builds the shell installer.

`publish-homebrew-formula.yml` is ours, wired in as a dist *publish job* so
regeneration cannot clobber it. It generates the formula with
`packaging/homebrew/generate-formula.sh` — the formula is not dist's, because
dist's Homebrew template cannot declare the launchd/systemd service.

The gate runs once, in `release-on-master.yml`, before anything is committed
or dispatched; the release cannot start without it. Dispatching `release.yml`
by hand skips it, which is the only way to release untested code.

To publish to a tap, create a `homebrew-tap` repository and give the release
a deploy key for it:

```sh
ssh-keygen -t ed25519 -N "" -C "lastpass-ssh-agent tap" -f tap-deploy-key
```

- public half → `homebrew-tap` → Settings → Deploy keys, with **Allow write
  access** ticked
- private half → this repository → Settings → Environments → **`release`** →
  add secret `TAP_DEPLOY_KEY`, and set that environment's deployment branch
  policy to `master`

A deploy key rather than a personal access token because it is bound to that
one repository, belongs to no user account, and does not expire. An
*environment* secret rather than a repository secret because anything able
to write the tap can ship a formula to everyone who installs: repository
secrets are readable from every branch, while the `release` environment can
be restricted to `master`. GitHub creates the environment on first use, but
the branch restriction only applies once you set it.

Without the secret the formula is simply attached to each release instead.

## Dependencies

Updates come from [Renovate](https://docs.renovatebot.com); install the app
on the repository and `renovate.json` governs it. That file is plain JSON and
cannot explain itself, so its two exclusions are documented here:

- **`.github/workflows/release.yml` is off-limits.** dist generates that file
  and verifies it byte-for-byte at release time, so a bumped action version
  there fails every release until it is regenerated.
- **`ssh-key` major and minor updates are off.** It is pinned to 0.6.x
  because `ssh-agent-lib` depends on `^0.6`; a 0.7 pull request cannot build
  until that moves first, so Renovate would only reopen a failing one.

Renovate targets `dev` (`"baseBranches"`), not `master`. That matters here:
every merge to `master` publishes a release, so pointing it at `master`
would ship a release per dependency bump. Updates instead accumulate on
`dev` and go out when you promote it.

Renovate only proposes upgrades, so it is silent about a vulnerability with
no fixed version — the one case where you most want to know. `cargo audit`
covers that gap from the other side: CI checks the locked tree against the
[RustSec](https://rustsec.org) database, and a release cannot go out under
an advisory nobody has looked at. Accepted advisories live in
`.cargo/audit.toml`, each with the reasoning for accepting it; anything not
listed there fails.

One is accepted today: **RUSTSEC-2023-0071**, a timing sidechannel in `rsa`
that has no patched release in any version line. Every RSA signature uses
fresh OS randomness to enable the crate's RSA blinding mitigation, and by
default only runs after you approve the request. Blinding is not the same as
a constant-time implementation, so the advisory remains explicitly accepted;
the residual risk matters most with `confirm = "off"` on a forwarded RSA
key. Ed25519 and ECDSA keys do not involve that crate at all.

## Development

The dev environment lives in Docker Compose, so the host needs Docker and
nothing else — no local Rust toolchain, no cargo plugins:

```sh
docker compose run --rm check   # the full local gate (what CI enforces)
docker compose run --rm test    # just the instrumented test suite
docker compose run --rm audit   # cargo audit (fetches the advisory db)
docker compose run --rm shell   # interactive shell in the dev image
```

The container runs unprivileged: root bypasses file permissions, which would
make the tests asserting that the agent refuses an unreadable config or an
unprobeable socket skip themselves and drop coverage below the required 100%.
The gate only reads the mounted checkout, so the container's ids do not have
to match yours — on macOS they never do and it makes no difference. If you do
need them to line up, build with `DEV_UID=$(id -u) DEV_GID=$(id -g) docker
compose build`, and if any service has already run, `docker compose down -v`
first: the cache volumes keep the ownership they were created with.

The first run builds the dev image. Toolchains are baked in, so refresh them
occasionally with `docker compose build --pull --no-cache` — `--pull` alone
only re-fetches the base image, and when nightly or a cargo plugin advances
without that tag moving, the cached layers keep older tooling than CI
installs.

If you work in a linked git worktree, export the commit so the `--version`
stamp survives — `.git` there points at metadata outside the mount, which the
container cannot follow:

```sh
export LASTPASS_SSH_AGENT_COMMIT=$(git rev-parse --short=12 HEAD)
```

The gate itself is `./scripts/check.sh` (which the `check` service runs),
and CI enforces the same on every push: `cargo fmt --check`, `cargo clippy`
with the pedantic and nursery groups and `-D warnings`, and the test suite
on macOS and Linux (`./scripts/test.sh`). If you do have the toolchain
installed, the scripts run directly on the host too.

CI adds one check the gate does not: `cargo audit` (see
[Dependencies](#dependencies)). It is deliberately not in `check.sh`, which
stays offline and hermetic — its result depends on a database fetched over
the network and changes without the code changing, so a local run could fail
for reasons that have nothing to do with your edit. The `audit` compose
service runs it on demand.

The generated dist workflow skips pull requests (`pr-run-mode = "skip"`), so
ordinary branch pushes run only `CI`; the release workflow starts when the
master gate explicitly dispatches it.

Tests always run instrumented, so "the tests pass" means every test passed
*and* every line and branch of production code was covered — anything less
fails. That needs a nightly toolchain for branch instrumentation
(`cargo +nightly llvm-cov --branch`).

Test modules themselves and a handful of provably-unreachable error edges
(e.g. `setrlimit(0,0)` failing) are excluded via
`#[cfg_attr(coverage_nightly, coverage(off))]`, each with a comment
justifying why it cannot be exercised.

## Notes & limitations

- **Passphrase-protected keys** work: the agent reads the item's
  `Passphrase` field and decrypts in memory. Storing key + passphrase in the
  same vault item means the passphrase adds nothing against a vault
  compromise — it only protects the key blob in transit/backups.
- **Certificates** are not served; plain keys only.
- Destination constraints (`ssh-add -h`) are not applicable: this agent
  refuses key addition, and its key set comes from the vault.
- **RSA**: SHA-1 (`ssh-rsa`) signature requests are refused; every OpenSSH
  since 7.2 asks for `rsa-sha2-*`. Supported key types: ed25519, RSA,
  ECDSA p256/p384.
- The `socket` path must be absolute (SSH clients resolve `SSH_AUTH_SOCK`
  from their own working directory), and macOS limits Unix socket paths to
  ~104 bytes (`SUN_LEN`), so keep it short.
- `ssh-agent-lib`'s own logging is off by default: it reports routine
  protocol traffic (OpenSSH's per-connection extension probe, every refusal)
  at ERROR level. Set `RUST_LOG=ssh_agent_lib=info` to see it; it stays
  capped at INFO so request dumps can never reach the log.
- Each signature costs an `lpass show` (~100–500 ms against the local vault
  cache). That is the price of the no-caching design.
- Item lookups use the LastPass **item id**, not the name, so renames are
  safe and duplicate names are ambiguity-free. If the vault item's key is
  edited while the agent runs, the agent notices the public-key mismatch and
  refuses to sign until restarted.
- In auto-discovery mode, an SSH Key item added to the vault is served after
  the next agent restart (discovery runs once at startup). Pin `[[keys]]` if
  you want new vault items to require an explicit opt-in instead.
- `tests/fixtures/` contains throwaway SSH keypairs used by the test suite
  only. They protect nothing and must never be authorized anywhere.
