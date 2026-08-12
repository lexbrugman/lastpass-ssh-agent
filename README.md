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
- **User-visible signing.** By default every signature asks first — a native
  dialog on macOS, a `/dev/tty` prompt on Linux — naming the key and the
  requesting process, with *Deny* as the default and cancel button. Timeouts,
  missing GUI sessions and helper failures all fail closed to Deny.
- **The host is named, and forwarding is visible.** The agent implements
  `session-bind@openssh.com`, so the prompt names the host each request is for
  — by hostname where `known_hosts` records one for that key, by fingerprint
  otherwise — and each hop proved possession of its host key. When the request
  arrived over a connection you forwarded with `ssh -A` it says so and warns
  that it may have originated there rather than on your machine; without that,
  a relayed request looks identical to one you made yourself. Bindings whose
  signature does not verify are refused and never displayed.
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
  refusal, socket `0600`, lpass environment allowlisted, `ssh_agent_lib` debug
  logging capped (its request dumps could contain a private key a client tried
  to add).
- **Your master password**, specifically, and how far you take this is a
  setting. By default (`master_password = "off"`) the agent never sees it:
  lpass's own pinentry is disabled, so a vault that has forgotten its key fails
  the signature and you run `lpass login` yourself.
  [`"prompt"`](#being-asked-for-the-master-password) lets the agent ask and pass
  it to `lpass` over a pipe, in a zeroizing buffer, never logged, never written
  and never placed in argv or the environment.
  [`"touchid"`](#keeping-it-behind-touch-id) goes further and is the only one
  of the three that keeps the master password at rest: it is written to disk,
  encrypted to a key held in this Mac's Secure Enclave that the system will not
  use without your fingerprint. That is a deliberate trade of a stored secret
  for a hardware-enforced gate, and worth reading that section before turning
  it on. (Key *passphrases* are a separate setting with a store of its own —
  see [`passphrase_fallback`](#keeping-the-passphrase-out-of-the-vault).)

## Install

```sh
brew install lexbrugman/tap/lastpass-ssh-agent
```

That pulls a prebuilt binary from the GitHub release for your platform
(macOS arm64/x86_64, Linux arm64/x86_64) and brings in `lastpass-cli`. The
Linux builds are musl-linked, so they do not depend on the host's glibc
version.

Without Homebrew, take the archive for your platform straight from the
[latest release](https://github.com/lexbrugman/lastpass-ssh-agent/releases/latest).
Each one ships beside a `.sha256`, so verify it before unpacking — and install
`lastpass-cli` yourself, since nothing here does it for you:

```sh
target=x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl, *-apple-darwin
curl -fsSLO "https://github.com/lexbrugman/lastpass-ssh-agent/releases/latest/download/lastpass-ssh-agent-${target}.tar.xz"
curl -fsSLO "https://github.com/lexbrugman/lastpass-ssh-agent/releases/latest/download/lastpass-ssh-agent-${target}.tar.xz.sha256"
sha256sum -c "lastpass-ssh-agent-${target}.tar.xz.sha256"   # shasum -a 256 -c on macOS
tar -xJf "lastpass-ssh-agent-${target}.tar.xz"
install -m 755 lastpass-ssh-agent /usr/local/bin/
```

> The tap is populated by the release pipeline. If `brew install` cannot find
> the formula, the tap does not exist yet — build from source.

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

A build that is not a release says so, by naming the release it follows and
how far past it the build is — five commits, here — so a dev install can
never be mistaken for a published one:

```
$ lastpass-ssh-agent --version
lastpass-ssh-agent 2026.810.0-5-g4f2a9c1e77b3 (2026-08-10, commit 4f2a9c1e77b3)
```

### Following the dev branch

The formula carries a `head` spec, so the same formula serves both tracks:

```sh
brew install --HEAD lexbrugman/tap/lastpass-ssh-agent   # dev, from scratch
brew upgrade --fetch-HEAD lastpass-ssh-agent            # move it forward
```

Switching an existing install between the tracks is always uninstall then
install, in both directions — `brew reinstall` has no `--HEAD` option and
cannot move one across:

```sh
brew uninstall lastpass-ssh-agent && brew install --HEAD lastpass-ssh-agent
brew uninstall lastpass-ssh-agent && brew install lastpass-ssh-agent
```

Two things are easy to trip over. A HEAD install builds from source, so
Homebrew installs a Rust toolchain as a build dependency and every update
recompiles, where a release install unpacks a prebuilt binary. And
`--fetch-HEAD` is not optional: without it Homebrew only re-examines the branch
when a new version is released, so a plain `brew upgrade` leaves a dev install
sitting on the commit it was built from.

`brew list --versions` shows `HEAD-<sha>` for a dev install, and `--version`
reports the real commit either way, so it is always clear what is running.
Switching tracks replaces the binary but not the running agent, so restart the
service afterwards; saved Keychain passphrases are keyed by key fingerprint and
are unaffected. A config using a dev-only setting will stop an older release
from starting at all, since unknown values are rejected rather than ignored.

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
   `lastpass-ssh-agent search` finds SSH Key items in the vault and prints
   pin-ready snippets; `lastpass-ssh-agent list` prints the keys the agent
   would actually serve, with fingerprints.

### Optional config

`~/.config/lastpass-ssh-agent/config.toml` — for pinning specific items
(the strictest mode: only listed ids are ever served, and startup skips the
vault scan) or tuning behavior:

```toml
# confirm = "osascript"        # default on macOS; tty | askpass | off
# askpass = "/usr/bin/ssh-askpass"   # required when confirm = "askpass"
# confirm_timeout_secs = 30
# socket = "~/Library/Application Support/lastpass-ssh-agent/agent.sock"
# lpass_path = "/opt/homebrew/bin/lpass"

# Where an encrypted key's passphrase comes from when the item's own
# Passphrase field is empty. "prompt" (default) asks you every time;
# "keychain" (macOS) asks once and remembers; "error" refuses to sign.
# passphrase_fallback = "prompt"

# How long the vault stays unlocked once lpass has derived its key. Unset
# leaves lpass to its own default of an hour; 0 means never expire.
# vault_unlock_timeout_secs = 300

# Where the master password comes from when lpass has forgotten its key.
# "off" (default) fails the signature; "prompt" asks you, any platform;
# "touchid" (macOS) releases it on Touch ID, falling back to asking.
# master_password = "off"

# Shut the vault when the screen locks, not just the display. macOS only.
# lock_on_screen_lock = false

# Pin items (disables auto-discovery); `search` prints these snippets.
[[keys]]
id = "7482913650418273946"     # stable LastPass item id (names are ambiguous)
name = "github"
# confirm = false              # per-key override
# passphrase_fallback = "error"  # per-key override
```

### Keeping the passphrase out of the vault

A populated `Passphrase` field is always used, and nothing else is consulted.
Leave that field **empty** and the agent asks you for the passphrase instead,
which is what separates the two secrets:

```text
encrypted private key -> LastPass
passphrase            -> only ever in your head, typed per session
```

Whoever steals the vault then holds a key they cannot use. The prompt appears
on the same channel as your confirmations (`osascript`, `tty` or `askpass`);
with `confirm = "off"` it uses the platform default, since silencing approval
prompts does not mean you cannot be reached. Set
`passphrase_fallback = "error"` if an encrypted key with an empty `Passphrase`
field should simply refuse to sign instead.

On macOS, `passphrase_fallback = "keychain"` asks once and remembers the
answer, so the separation costs one prompt per key rather than one per
session:

```toml
passphrase_fallback = "keychain"
```

Neither store then holds both halves, so compromising one alone yields nothing
usable. Each key gets its own generic-password entry under the service
`lastpass-ssh-agent`, keyed by the key's SHA-256 fingerprint — so renaming or
recreating the vault item still finds the passphrase, several keys are
remembered independently, and deleting one entry in Keychain Access revokes just
that key.

A passphrase is stored only *after* it has decrypted the key, so a typo never
becomes a stored credential, and one that stops working prompts for a
correction rather than locking the key. The entry takes the login keychain's
ordinary protection, deliberately without a per-signature authorization dialog
on top of the agent's own confirmation.

This mode is macOS-only and rejected at startup elsewhere.

Two properties are what stop a local prompt from becoming a way around the
vault:

- A **wrong** `Passphrase` field fails the signature. Fallback happens when
  the field is *absent*, never when it is present and does not work —
  otherwise anything able to draw a dialog could override a passphrase you
  pinned in the vault.
- Nothing is cached, in any mode. Each signature fetches the key, resolves the
  passphrase, decrypts, signs, and wipes both. The Keychain is a passphrase
  store, not a key store.

### Locking the vault with the screen

`lpass` keeps the key it derived from your master password in an agent process
of its own — for an hour by default. That is what makes each signature cost no
password, and it is also what leaves the **whole vault** readable by anything
running as you until it expires. Locking the screen does not touch it.

```toml
lock_on_screen_lock = true
```

With this on, the agent watches the screen and drops that cached key the moment
it locks. The LastPass *session* survives, so the way back is your master
password, not a fresh login with a second factor — and you are not asked for it
on unlock, only when a signature actually needs the vault again.

macOS only, and refused at startup elsewhere: reading the screen's lock state is
the one part of this a platform has to provide, and only macOS does so far.

On its own, though, a lock costs you a failed `ssh` afterwards — which is what
the setting below is for, and why the two are usually turned on together.

### Being asked for the master password

```toml
master_password = "prompt"     # or "touchid" on macOS
```

`lpass` forgets its cached key on its own hourly timeout as readily as it does
when a screen lock takes it away, and by default either one fails the next
signature with *not logged in* until you re-authenticate by hand. With this on,
the agent asks instead — **it prompts you for the master password itself**,
which it does not do otherwise; see the security model above for how that is
handled.

### Keeping it behind Touch ID

```toml
master_password = "touchid"      # macOS only
```

```sh
lastpass-ssh-agent store-master-password
```

The setup command locks the vault, asks once, checks that what you typed
actually opens it, and keeps it only if it does — so a typo never becomes a
stored credential, and setting it up proves the whole arrangement works rather
than only that a password was typed.

After that a locked vault costs a fingerprint instead of typing your master
password. The password is encrypted to a key generated inside this Mac's
**Secure Enclave**, which will not use that key until the fingerprint sensor
says so. The enforcement is the system's, not this agent's: something able to
trigger signatures can make the prompt appear, but cannot answer it, and copying
the files away gains nothing because the key cannot leave the Enclave. That is
the difference between this and simply storing the password — without the
constraint, anything running as you could take the key to the whole vault
silently.

The Touch ID sheet says what it is for — *unlock your LastPass vault* — rather
than appearing unexplained, so one you were not expecting is one you can refuse.

The key is bound to the fingerprints enrolled when you set it up. Adding or
removing one invalidates it by design, and the agent says so and falls back to
asking until you run `store-master-password` again.

Two things it does not change. The confirmation dialog still runs, separately
and unchanged, naming the key, fingerprint, requester and host — Touch ID
authorises opening the vault, never a signature. And until you have run
`store-master-password`, or on a Mac with no Secure Enclave, or whenever the
fingerprint is declined, it behaves exactly like `"prompt"`.

Deliberately a separate setting from `lock_on_screen_lock`, and deliberately not
macOS-only: nothing about being asked for a password is platform-specific, and
the hourly expiry happens everywhere. The prompt looks like every other one this
agent shows, since it uses whatever `confirm` already selects.

Mechanically, `lpass` runs a password helper as a bare executable path with the
prompt as its only argument — no shell, no room for a subcommand. So the agent
writes a two-line wrapper into its own socket directory and points `lpass` at
that; the wrapper runs `lastpass-ssh-agent askpass`, an ordinary subcommand you
can see in `--help` and in `ps`. It is rewritten on every start, so an upgrade
that moves the binary corrects itself. Run by hand it refuses, because the
config it prompts from is named by an environment variable the agent sets.

### How long the vault stays unlocked

`lpass` keeps the key it derives for an hour by default. To shorten that:

```toml
vault_unlock_timeout_secs = 300
```

Two things are worth knowing. `0` means *never expire*, which is lpass's own
encoding — it disables the timer rather than setting it to nothing. And the
value only governs an `lpass` agent that **this** agent starts: whichever
process runs `lpass` first fixes the timeout for that agent's lifetime, so a
shell that has already used `lpass` keeps whatever it set.

That is why `lastpass-ssh-agent env` prints it too:

```sh
$ lastpass-ssh-agent env
SSH_AUTH_SOCK='/Users/you/…/agent.sock'; export SSH_AUTH_SOCK;
LPASS_AGENT_TIMEOUT='300'; export LPASS_AGENT_TIMEOUT;
```

If your shell profile already runs `eval "$(lastpass-ssh-agent env)"`, both
your shells and the agent take the number from this one file — rather than you
keeping it in `.zshrc` as well and the two drifting apart.

## Run

```sh
lastpass-ssh-agent start
# it logs where it is listening, then serves until stopped
```

In another shell (`start` runs until stopped, so its output is a log rather
than something to evaluate — `env` is what a shell reads):

```sh
eval "$(lastpass-ssh-agent env)"
ssh-add -l          # lists your LastPass-backed keys
ssh github.com      # pops the confirmation dialog, then signs
```

If you log out of LastPass while the agent runs, signatures fail with a
clear log message; `lpass login` in any terminal and retry — the agent does
not need a restart. (With
[`master_password`](#being-asked-for-the-master-password) set, a vault
that has only forgotten its key prompts you instead of failing; a real logout
still needs `lpass login`.)

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
| `osascript` (macOS default) | Native dialog: key name, fingerprint, requesting process (pid/uid via the socket's peer credentials), and the bound host. Deny is default + cancel; expiry = Deny; no GUI session = Deny. Vault-sourced strings are passed as AppleScript *arguments*, never spliced into code. |
| `tty` (Linux default) | Prompt on the agent's own `/dev/tty`; type `yes` to approve. |
| `askpass` | Runs the program in `askpass` with the prompt as its argument; exit 0 approves. `SSH_ASKPASS_PROMPT=confirm` is set, so OpenSSH-compatible helpers show a yes/no dialog rather than their password prompt — without it, clicking OK would approve whatever was typed. |
| `off` | No confirmation (socket permissions are then your only guard, as with stock ssh-agent). |

## Notes & limitations

- **Passphrase-protected keys** work: the agent reads the item's
  `Passphrase` field and decrypts in memory. Storing key + passphrase in the
  same vault item means the passphrase adds nothing against a vault
  compromise — it only protects the key blob in transit/backups. Leaving that
  field empty is what buys the separation; see [Keeping the passphrase out of
  the vault](#keeping-the-passphrase-out-of-the-vault).
- **Secret prompts share `confirm_timeout_secs`** (30s by default) — the key
  passphrase and, with a `master_password` source, the master password. Generous
  for pressing a button, tight for typing a long secret; raise it if entry keeps
  timing out.
- **Suspending a `tty` passphrase prompt leaves the terminal with echo off.**
  Ctrl-Z skips the cleanup a timeout or cancellation runs, so the shell comes
  back not showing what you type and anything half-typed stays queued for it.
  `stty sane` restores it; finishing or cancelling the prompt avoids it.
- **`HashKnownHosts` means the prompt shows fingerprints, not hostnames.** A
  hashed entry stores the name as a salted MAC, which can only be tested
  against a name you already have — and the binding supplies only the key.
  Hashing is per entry, so plain entries in the same file still resolve.
  (Upstream OpenSSH defaults this off; Debian and Ubuntu ship it on.)
- **Certificates** are not served; plain keys only.
- Destination constraints (`ssh-add -h`) are not applicable: this agent
  refuses key addition, and its key set comes from the vault.
- **RSA**: SHA-1 (`ssh-rsa`) signature requests are refused; every OpenSSH
  since 7.2 asks for `rsa-sha2-*`. Supported key types: ed25519, RSA,
  ECDSA p256/p384.
- The `socket` path must be absolute (SSH clients resolve `SSH_AUTH_SOCK`
  from their own working directory), and macOS limits Unix socket paths to
  ~104 bytes (`SUN_LEN`), so keep it short.
- `ssh-agent-lib`'s own logging is capped at INFO even under
  `RUST_LOG=debug`: its debug output Debug-formats whole requests, and an
  `AddIdentity` request carries the client's private key. Routine refusals do
  not reach it at all — this agent answers them itself, so a probe or a Deny
  is never logged as a fault.
- Each signature costs an `lpass show` (~100–500 ms against the local vault
  cache). That is the price of the no-caching design.
- Item lookups use the LastPass **item id**, not the name, so renames are
  safe and duplicate names are ambiguity-free. If the vault item's key is
  edited while the agent runs, the agent notices the public-key mismatch and
  refuses to sign until restarted.
- In auto-discovery mode, an SSH Key item added to the vault is served after
  the next agent restart (discovery runs once at startup). Pin `[[keys]]` if
  you want new vault items to require an explicit opt-in instead.
- With `lock_on_screen_lock`, the vault reopens on the first signature that
  needs it and stays open until the next lock or `vault_unlock_timeout_secs` —
  the lock bounds exposure, it does not make each signature cost a password.
  With `master_password = "off"`, that first signature fails rather than
  prompting.
- Auto-discovery costs one `lpass` call per vault item, eight at a time:
  `lpass ls` reports names and ids but not the note type, so every item has to
  be asked. A few hundred items are quick; a few thousand are most of a minute
  at startup, before the socket exists. The agent logs how many it is about to
  probe. **Pinning `[[keys]]` skips discovery entirely** and is worth it on a
  large vault — `lastpass-ssh-agent search` prints the snippets.
- `tests/fixtures/` contains throwaway SSH keypairs used by the test suite
  only. They protect nothing and must never be authorized anywhere.

## Releasing

Releases are automatic: **every push to `master` that passes the gate
publishes one**, and nothing has to be tagged by hand. The next version comes
from the date (`2026.810.0`, then `2026.810.1` for a second release the same
day — so every build gets a unique number without anyone choosing it). Pushes
to any other branch, such as `dev`, only run the tests.

**Nothing is ever committed to release.** The version lives in the git tag and
nowhere else: `[package] version` in `Cargo.toml` is a permanent `0.0.0`
placeholder, and `build.rs` stamps the real one into the binary at build time.
That is what keeps `master` and `dev` from drifting apart — there is no release
commit on `master` for `dev` to be perpetually behind by.

One push to `master` is one CI run, and the release is the tail of it:

```
ci.yml                          on: push, branches only
├── resolve-release.yml         master → the next CalVer; anything else → ""
├── checks.yml                  the gate, on every branch
├── build-release.yml           the four targets, packaged and checksummed
├── publish-release.yml         draft → assets → publish (this creates the tag)
└── publish-homebrew-formula.yml
```

Whether a push releases is decided in one place, `resolve-release.yml`, and
every job downstream keys off its output rather than testing the branch. The
gate is a dependency of the build, so a release cannot start without it, and
there is no way to trigger one by hand that skips it.

The release is created as a draft, filled with the archives, and only then
published — which is the moment GitHub creates the tag. A run that dies partway
therefore leaves a discardable draft rather than a tag pointing at a release
that was never finished, and because `resolve-release.yml` counts drafts too,
the abandoned number is not handed out again.

`publish-homebrew-formula.yml` runs last, once the release is published: it
generates the formula with `packaging/homebrew/generate-formula.sh` from the
checksums attached to the release, and those URLs do not resolve while the
release is still a draft.

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

This is the pipeline's only credential — everything else runs on the built-in
`GITHUB_TOKEN`, and the tap needs a key of its own solely because it is a
different repository, which that token cannot write to.

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
on the repository and `renovate.json` governs it. Everything carrying a
version is tracked as precisely as its own format allows:

- **Crates** keep caret ranges in `Cargo.toml`, and `Cargo.lock` is
  committed. Cargo's default range strategy resolves to `update-lockfile`,
  so an in-range release arrives as a lock-file-only pull request and the
  manifest stays permissive.
- **The rest of the locked tree** — the transitive crates with no manifest
  entry of their own — is refreshed by `lockFileMaintenance`, weekly. Direct
  dependencies are a small fraction of what actually gets compiled, and
  without this nothing would ever move them.
- **Actions are pinned to exact releases** (`actions/checkout@v7.0.1`, not
  `@v7`), which is what makes a patch release show up as a pull request at
  all; a floating major tag stays silent until the next major. Digests are
  deliberately not pinned (`"pinDigests": false`) — an exact tag is specific
  enough to track and stays readable.
Two things are deliberately not tracked, because a version is the wrong
thing to pin:

- **`dtolnay/rust-toolchain@stable` and `@nightly`** are branch references,
  not versions. The point is to compile against whatever those resolve to
  today, which is also what the dev container does.
- **The `tool:` inputs to `taiki-e/install-action`** name `cargo-audit` and
  `cargo-llvm-cov` without versions, matching how the dev container fetches
  them. Pinning one side only would let CI and the container drift apart.

Three packages are held back together: **`ssh-key`, `signature` and
`rand_core`**, majors and minors off. One chain pins all of them —
`ssh-agent-lib` depends on `ssh-key ^0.6`, which is built on `signature` 2 and
`rand_core` 0.6. The latter two are declared directly here only to import the
traits those crates implement and to guarantee the `getrandom` feature `OsRng`
needs, so their versions are not ours to choose: bumping one alone puts two
incompatible copies of a crate in one binary, and cargo either fails to resolve
or compiles against the wrong traits. They lift together, once `ssh-agent-lib`
ships on `ssh-key` 0.7+ — which is also what would retire the `rsa` advisory
below, since `rsa` 0.10 arrives with the same wave.

Renovate targets `dev` (`"baseBranchPatterns"`), not `master`. That matters
here: every merge to `master` publishes a release, so pointing it at `master`
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

The container runs unprivileged, because root bypasses the file permissions
several tests assert on. The gate only reads the mounted checkout, so its ids
need not match yours — on macOS they never do. If you do need them to line up,
build with `DEV_UID=$(id -u) DEV_GID=$(id -g) docker compose build`, and
`docker compose down -v` first if any service has already run: the cache
volumes keep the ownership they were created with.

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
with the pedantic and nursery groups and `-D warnings`, the archive and
formula-generator checks, and the test suite on macOS and Linux
(`./scripts/test.sh`). If you do have the toolchain installed, the scripts run
directly on the host too.

CI adds one check the gate does not: `cargo audit` (see
[Dependencies](#dependencies)). It is deliberately not in `check.sh`, which
stays offline and hermetic — its result depends on a database fetched over
the network and changes without the code changing, so a local run could fail
for reasons that have nothing to do with your edit. The `audit` compose
service runs it on demand.

Tests always run instrumented, so "the tests pass" means every test passed
*and* every line and branch of production code was covered — anything less
fails. That needs a nightly toolchain for branch instrumentation
(`cargo +nightly llvm-cov --branch`).

Test modules themselves and a handful of provably-unreachable error edges
(e.g. `setrlimit(0,0)` failing) are excluded via
`#[cfg_attr(coverage_nightly, coverage(off))]`, each with a comment
justifying why it cannot be exercised.
