# Everything the local gate needs, so the host needs Docker and nothing
# else: stable Rust with rustfmt + clippy for the lint gate, nightly with
# llvm-tools for branch-instrumented coverage, cargo-llvm-cov, and
# cargo-audit. Toolchains float with upstream exactly like CI's, so the gate
# behaves identically in both places.
FROM rust:1.97.1-slim-trixie

# git: build.rs stamps the binary with the current commit.
# curl + ca-certificates: fetching the cargo-llvm-cov release binary below.
# xz-utils: releases are .tar.xz and tar cannot write or read one without it.
# packaging/test-archive.sh builds a real archive in the gate, so this is not
# optional here.
# ruby: only to syntax-check the generated Homebrew formula. It is built by
# substituting into a template, so a broken edit produces a file that looks
# fine and fails at `brew install`; `ruby -c` catches that in the gate.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
        ruby xz-utils \
    && rm -rf /var/lib/apt/lists/*

# The gate must NOT run as root. Several tests assert that the agent refuses
# an unreadable config or an unprobeable socket, and root bypasses file
# permissions entirely — as root those tests skip themselves and coverage
# lands under the required 100%, failing the gate. Running unprivileged also
# keeps the container from writing root-owned files into the bind mount.
#
# Override the ids to match your own if the bind mount needs it:
#   DEV_UID=1001 DEV_GID=1001 docker compose build
#
# The group is only created when that gid is free: an id copied from the host
# can already exist here, and groupadd would fail the build rather than reuse
# it. macOS hits this by default — its primary group is 20, which is dialout
# in Debian.
#
# CARGO_HOME is written by every step below and by cargo at runtime, and its
# registry is where the cache volume mounts; /work/target is where the build
# artifact volume mounts. A fresh named volume inherits the ownership of the
# image directory it covers, so both have to belong to the dev user. They are
# chowned here, while still nearly empty — doing it after the installs would
# duplicate the whole tree in a layer. RUSTUP_HOME is already world-writable
# from the base image, so it needs nothing.
ARG DEV_UID=1000
ARG DEV_GID=1000
RUN set -eux; \
    if ! getent group "${DEV_GID}" >/dev/null; then \
        groupadd --gid "${DEV_GID}" dev; \
    fi; \
    useradd --uid "${DEV_UID}" --gid "${DEV_GID}" --create-home dev; \
    mkdir -p "${CARGO_HOME}/registry" /work/target; \
    chown -R "${DEV_UID}:${DEV_GID}" "${CARGO_HOME}" /work

# --system, not --global: --global would only cover root's config, leaving
# git refusing the host-owned repository ("dubious ownership") for the dev
# user, and the commit stamp in --version silently falling back to "unknown".
RUN git config --system --add safe.directory /work

USER dev

# The slim image ships the minimal profile: rustfmt and clippy have to be
# added, and branch coverage needs nightly (-Z coverage-options) with its
# llvm tools.
# The macOS target is for type-checking, not building: half of this codebase is
# behind `cfg(target_os = "macos")` and never compiles here, so a mistake in it
# used to survive the whole local gate and surface only in CI. `cargo clippy
# --target aarch64-apple-darwin` checks that half without linking anything —
# there is no Apple SDK here and none is needed to find the errors that matter.
RUN rustup component add rustfmt clippy \
    && rustup target add aarch64-apple-darwin \
    && rustup toolchain install nightly --profile minimal \
        --component llvm-tools-preview

# cargo-llvm-cov comes prebuilt from the same release artifacts CI's
# taiki-e/install-action uses. cargo-audit has no single-URL download, so it
# is compiled once here instead.
RUN set -eux; \
    host="$(rustc -vV | sed -n 's/^host: //p')"; \
    curl -fsSL --proto '=https' --tlsv1.2 \
        "https://github.com/taiki-e/cargo-llvm-cov/releases/latest/download/cargo-llvm-cov-${host}.tar.gz" \
        | tar -xzf - -C "${CARGO_HOME}/bin"; \
    cargo install --locked cargo-audit

WORKDIR /work
