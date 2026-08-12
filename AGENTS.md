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

## Keep the logic portable, gate only the adapter

Whatever a platform makes different should be pushed to the smallest possible
edge — a value to look up, an API to call — with every decision taken in code
that compiles and runs everywhere.

This is not only tidiness. Tests only ever run on the platform they are
executed on, so anything behind a `cfg` is tested by one CI job and unverifiable
from the other; a developer without a Mac cannot even compile macOS-gated code,
let alone run it. Logic hidden behind a `cfg` is therefore logic that gets
reviewed less, tested less, and broken more easily.

The code already works this way, and these are the patterns to copy:

- `platform::socket_dir_from` takes the runtime and home directories as
  arguments and is pure, so both of its paths are exercised on every platform.
  Only *which directory* to look in is `cfg`-selected.
- `confirm::process_path` is a per-OS lookup of one string behind a portable
  caller, so the prompt-building logic around it is tested everywhere.
- `PassphraseStore` is a portable trait. Preferring the vault, verifying a
  passphrase before saving it, and asking again when a saved one stops working
  are all portable and fully tested; the macOS Keychain implementation behind
  it is two calls and no decisions.
- `enclave` is the same idea taken as far as it goes, because the thing behind
  the `cfg` there is not even Rust. The Swift shim returns the stage a call
  stopped at and the system's own error code, and nothing else; which stage
  means "ask again", which means "seed again" and which is a fault, along with
  the format the key blob is written in, are all decided in `enclave.rs` and
  tested on Linux as well as macOS. `askpass/enclave.rs` is three foreign calls
  and no judgement.

If a `cfg` block contains a branch, a loop, or an error decision, it is
probably in the wrong place.

## Writing tests

Stay on the built-in test runner. Parameterized cases are written as a shared
body plus one named test per case, which keeps each case a single line while
still giving it a name, an independent result, and a `cargo test <name>` filter:

```rust
async fn expect_answer(printed: &str, expected: &[u8]) {
    …
    assert_eq!(&*secret, expected, "helper ran `{printed}`");
}

#[tokio::test]
async fn a_crlf_helper_does_not_leak_the_carriage_return() {
    expect_answer("printf 'secret\r\n'", b"secret").await;
}
```

That is the whole of what a parameterized-test crate would add, minus the
dependency — and the diagnostics beat a loop's, because a failure names the case
rather than the point where the loop stopped.

A `for` loop over a table is still right where the cases are cheap, pure and
numerous — rejecting a list of malformed ids, escaping a list of strings. Name
the case in the assertion message there, since a loop cannot.

Keep a case out of either form when it exercises a different mechanism rather
than a different input: a timeout, a crashed helper and a missing helper each
deserve their own test even though all three "fail".

Derive nothing from the input to build the expectation. A computed expected
value is a second implementation of the thing under test, and it will agree
with the bug — write both sides out literally.

## Test determinism

Two races are easy to reintroduce. Both make a test fail once in a dozen runs
rather than reliably, so they are worth knowing before writing a test that
spawns a process or drives a prompt.

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
- The rule above governs **buffers this code allocates**. A dependency handing
  back a secret in its own allocation (`security-framework` copies out of a
  CoreFoundation buffer, for instance) is wrapped in `Zeroizing` at the
  boundary and no further: reaching inside to wipe a library's intermediates
  means hand-rolled FFI in exactly the place that is hardest to test. Zeroizing
  shortens a secret's lifetime; it was never a defence against an attacker who
  can already read this process's memory, and the threat model says so.
- A value arriving *from* a store or a subprocess is checked against the cap on
  our side, because its contents are not ours to trust.
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

## Releasing

Work happens on `dev`; `master` releases. **No release ever commits anything**,
which is the property that keeps the two branches from diverging — `master` and
`dev` differ only by real work, and merging one into the other is always a
fast-forward away from a conflict nobody introduced.

The version therefore lives in the git tag and nowhere else. `[package] version`
in `Cargo.toml` is a permanent `0.0.0` placeholder; `build.rs` resolves what
`--version` prints, in this order:

1. `LASTPASS_SSH_AGENT_VERSION`, which `build-release.yml` sets to the version
   being released.
2. `git describe --tags --match "v[0-9]*"`, so a build off `dev` reports
   `2026.811.2-5-gabc123def456` — the release it follows, and by how much.
3. `dev`, for a tree with neither.

Reading `CARGO_PKG_VERSION` anywhere is a bug: it is the placeholder.

One push to `master` is one CI run, and the release is the tail of it:

```
ci.yml                          on: push, branches only
├── resolve-release.yml         master → the next CalVer; anything else → ""
├── checks.yml                  the gate, on every branch
├── build-release.yml           4 targets, only when the version is non-empty
├── publish-release.yml         draft → assets → publish (this creates the tag)
└── publish-homebrew-formula.yml
```

Four invariants hold it together, and each is load-bearing:

- **`resolve-release.yml` is the only place that decides.** Nothing else tests
  the branch; every release job gates on `version != ''`. Adding a second
  `github.ref` check somewhere downstream is how the two get out of step.
- **The tag is created by publishing the release**, not pushed. That is what
  keeps the built-in `GITHUB_TOKEN` sufficient: a token-pushed tag cannot
  trigger a workflow, so anything that needed a tag *event* would need a
  GitHub App or a deploy key. Nothing does. `ci.yml` listens on branches only,
  so the new tag cannot re-enter the pipeline either.
- **The release is drafted, filled, then published.** A draft holds no tag, so
  a run that dies partway leaves something discardable rather than a tag
  pointing at a release that was never finished. `resolve-release.yml` counts
  drafts for exactly this reason.
- **The formula is published last.** It points at the release's download URLs,
  which do not resolve until the release leaves draft.
- **The archive's shape is a contract**, and one nothing notices breaking until
  an install fails: files at the root with no wrapping directory, and a
  `<hash> *<name>` checksum beside each. Both live in `packaging/archive.sh`
  with `test-archive.sh` in the gate, rather than in workflow steps that only
  ever run during a release.

The one credential is `TAP_DEPLOY_KEY`, and only because the tap is a different
repository — `GITHUB_TOKEN` cannot write to one. Without it a release still
publishes and the formula is still attached to it; only the tap goes unupdated.

## Comments

This codebase comments heavily. That only pays while they are true, needed, and
short enough that people still read them — a wall of prose gets skipped as
reliably as no prose at all, and a stale line is worse than a missing one
because it is believed. Four habits keep them worth their space.

**Write for the code as it stands.** The reader is seeing it for the first time
and has no idea what it looked like before. So no diary: "this used to be X",
"the copies had drifted", "we changed this after a bug". They never saw X,
cannot act on it, and now have to work out which half of the sentence still
applies. State the rule in the present tense and leave the history in `git
log`, which is built for it and which nobody has to read by accident.

**Explain a choice only when the alternative is one a reader would reach for**,
and the reason it fails is expensive to rediscover.

- Worth it: why the master password is not a Keychain item (someone will try
  it, and the answer is an entitlement that takes a day to find); why `install`
  does not use `files::open_regular` (the two look interchangeable); why the
  Swift language mode is pinned to 5 when the shim passes 6 (says when to
  raise it).
- Not worth it: which error variant this used to be, which helper this was
  extracted from, what the comment above it said last week.

**Say what the code cannot.** Restating the line beneath doubles the reading,
halves the trust, and goes stale the moment that line changes. Spend the space
on what is invisible: why a bound is that number, what breaks if it moves,
which invariant the next edit must not quietly drop. Anchor to things that
survive — names, invariants, filenames. Not line numbers, not "the function
below", not "currently" or "recently", and not a version that will be bumped by
someone who never reads the sentence beside it.

**Length is earned a point at a time.** One sentence that stops a wrong change
beats a paragraph restating a right one. The same explanation in three places
is a liability rather than thoroughness: two of them will be updated and one
will not, and there is no way to tell which. Give each fact one home and point
at it — `swift/secure_enclave.swift` owns why the keychain is closed,
`enclave.rs` owns what a stage means, and their callers link instead of
retelling.

The test, when unsure: delete the sentence and ask whether anyone could now
make a wrong change safely. If they could, it was diary or decoration.

## Commits

One line, imperative, no body and no attribution trailers.
