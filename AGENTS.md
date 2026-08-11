# Working agreements

Conventions this repository already follows, written down so they are decided
once rather than rediscovered — by a person or an agent — on every change.
When something here conflicts with what the code does, the code is the bug.

## Environment

Everything runs in Docker Compose; no local toolchain is needed or assumed.

```sh
docker compose run --rm check   # the full gate — run this before every commit
docker compose run --rm test    # instrumented test suite only
docker compose run --rm audit   # cargo audit (needs the network)
docker compose run --rm shell   # anything else, e.g. cargo clippy
```

The container runs unprivileged on purpose: root bypasses file permissions, and
several tests assert the agent *refuses* an unreadable config or an unprobeable
socket. As root those tests skip themselves and coverage silently drops below
the required 100%.

`CARGO_TERM_COLOR=always` is set, so `grep '^error'` over cargo output finds
nothing — the line starts with an escape sequence. Pass
`-e CARGO_TERM_COLOR=never` when grepping.

## The coverage gate

`./scripts/test.sh` requires **100% of lines and 0 missed branches** across
production code. It is a hard gate: "the tests pass" means every line and every
branch destination ran.

Regions are **not** gated, and should not be. A region is llvm-cov's finest
unit — a span with its own execution count, so one line can hold several. A
missed region is almost always the error side of a `?` on a line that otherwise
ran: the OS call succeeded in every test, so the propagation span never
executed. Branch coverage already pins down every decision the code *makes*;
regions additionally demand provoking every failure the environment *could*
have. Chasing them means either faking every syscall failure or scattering
exemptions, so the repo sits at ~97% regions with 100% lines and branches, and
that is the intended resting point. Do not treat a missed region as a defect.

When a line genuinely cannot be reached from a test, exclude it with
`#[cfg_attr(coverage_nightly, coverage(off))]` **and a comment saying why**.
Two rules keep this from becoming a dumping ground:

- Exclude the smallest possible unit. Extract the unreachable glue into its own
  tiny function rather than exempting logic that surrounds it.
- Prefer a named function over an inline closure for error mapping. A closure
  body is a line of its own in the report, so an untestable `map_err(|e| ...)`
  costs a missed *line*; the same mapping as a named function costs only a
  missed region, which is not gated.

Platform-specific behaviour must use `#[cfg(...)]`, never a runtime
`if cfg!(...)`. A runtime check creates a branch that can only go one way on
each platform, so it can never be covered — while `#[cfg]` means the other
platform has no such code to cover.

## Test determinism

Two races are easy to reintroduce, and both were flaky in CI before being
fixed. They are worth knowing before writing a test that spawns a process or
drives a prompt.

- **Never write an executable with `std::fs::write` and then run it.** Executing
  a file that any process holds a write descriptor for fails with `ETXTBSY`, and
  with tests spawning from many threads a fork will sometimes inherit that
  descriptor. Renaming does not help — the check is against the inode.
  `testutil::write_script` sidesteps it by having a separate process create the
  file, so the descriptor never exists here to be inherited.
- **Never sleep a fixed time before answering a prompt.** Input that arrives
  before a prompt is displayed is deliberately discarded, so a slow run
  discards the answer and the test waits out its full timeout. Wait for the
  prompt's own output instead, the way `answer_prompt` does.

## Handling secrets

Private keys and passphrases follow the same discipline.

- Secrets live in `Zeroizing` buffers, never `String`.
- **A buffer holding a secret must be allocated once.** Growing a `Vec` copies
  its bytes into a new allocation and frees the old one unwiped, leaving
  fragments that zeroizing the final buffer cannot reach. Hence every reader is
  capped and preallocated (`MAX_FIELD_BYTES`, `MAX_PASSPHRASE_BYTES`) and
  refuses oversized input rather than growing to fit it. A cap also bounds what
  a misbehaving subprocess can make the agent allocate.
- A secret never appears in a log, a tracing field, argv, an environment
  variable, a temporary file, or an error message. Fingerprints, item ids and
  key names are safe context; prefer them.
- Nothing is cached. Every signature fetches the key, resolves the passphrase,
  decrypts, signs, and drops both. There is no decrypted-key cache and no
  passphrase cache, and adding either is out of scope by design.
- Strip exactly one trailing line ending from subprocess output, never more: a
  secret may legitimately end in whitespace.

## Interacting with the user

- Confirmation **fails closed**: a denial, a timeout, a missing GUI session and
  a crashed helper all mean deny.
- Secret entry does not. A prompt that fails must report *why* — cancelled,
  unavailable, too long — because treating a failure as an empty answer would
  turn "something broke" into a signature attempt with the wrong passphrase.
- Only one interaction happens at a time, and the whole of one signing request
  holds that gate. Two prompts on one terminal would let the answer meant for
  one be read by the other, and a passphrase typed into a yes/no confirmer
  would land in memory nothing wipes.
- Text from the vault or from a requesting process is untrusted. Pass it
  through `escape_for_display` before it reaches a terminal or a dialog: raw
  control characters can redraw a prompt and a bidi override can reverse which
  key it appears to name.
- Untrusted text is passed as data — argv to `on run argv`, never interpolated
  into `AppleScript` source.

## Passphrase precedence

The rule, in one line: **the fallback applies when the vault field is absent,
never when it is wrong.**

A populated `Passphrase` field is authoritative. If it is populated and does
not decrypt the key, the signature fails — it must not fall through to a
prompt, or anything able to draw a dialog could override a passphrase the vault
pins. Only an empty field reaches `passphrase_fallback`.

## Configuration

- `#[serde(deny_unknown_fields)]` everywhere; a typo is an error, not a
  silently ignored key.
- An unimplemented enum value must fail to parse rather than behave like
  something else.
- Validate at load, so a bad config fails at startup instead of at the first
  signature.
- Per-key overrides mirror the global setting's shape. Note the two differ in
  kind: `confirm` treats the global as a ceiling (global `off` wins over a
  per-key `true`), while `passphrase_fallback` is a plain replacement, because
  neither level is safer than the other.

## Dependency versions

Everything carrying a version is tracked as precisely as its format allows, and
Renovate targets `dev`. Crates keep caret ranges with a committed `Cargo.lock`
(cargo's default resolves to `update-lockfile`); `lockFileMaintenance` covers
the transitive tree; actions are pinned to exact releases, since a floating
major tag never produces a pull request. Digests are deliberately not pinned.

Two versions are declared twice and must move together — `cargo-dist-version`
in `Cargo.toml` and `CARGO_DIST_VERSION` in the `Dockerfile`. One Renovate
custom manager matches both so a single pull request bumps them.

A dist bump is only half an upgrade: `release.yml` is generated and verified
byte-for-byte, so it needs regenerating and committing on the same branch.

## Commits

One line, imperative, no body and no attribution trailers.
