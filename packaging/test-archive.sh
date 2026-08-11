#!/bin/sh
# Checks archive.sh produces what the release actually depends on. None of
# this is visible before someone runs `brew install`: a wrapping directory, a
# checksum in the wrong shape, or a dropped file all yield an archive that
# unpacks cleanly and installs nothing.
set -eu
cd "$(dirname "$0")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

src="${work}/src"
out="${work}/out"
mkdir -p "$src"
printf '#!/bin/sh\necho stub\n' > "${src}/lastpass-ssh-agent"
printf 'the readme\n' > "${src}/README.md"

target=x86_64-unknown-linux-musl
archive="lastpass-ssh-agent-${target}.tar.xz"

./archive.sh "$target" "$out" "${src}/lastpass-ssh-agent" "${src}/README.md" \
    > /dev/null

failed=0

if [ ! -s "${out}/${archive}" ]; then
    echo "no archive was written" >&2
    failed=1
fi

# Entries at the root, exactly the files passed and nothing else. A wrapping
# directory is the failure this exists to catch: `bin.install` in the formula
# would find no binary where it looks.
#
# LC_ALL=C because this runs on both platforms and collation is not the same
# in both: the runners' en_US.UTF-8 ignores case and puts lastpass-ssh-agent
# first, while C compares bytes and puts README.md there. Only the sort needs
# pinning — the archive itself is right either way.
entries="$(tar -tJf "${out}/${archive}" | LC_ALL=C sort | tr '\n' ' ')"
if [ "$entries" != "README.md lastpass-ssh-agent " ]; then
    echo "unexpected archive layout: $entries" >&2
    failed=1
fi

# "<hash> *<name>", not a bare hash: generate-formula.sh takes field one, and
# a formula carrying the filename as its sha256 is rejected by Homebrew.
if ! grep -qE '^[0-9a-f]{64} \*'"${archive}"'$' "${out}/${archive}.sha256"; then
    echo "checksum is not '<hash> *<name>':" >&2
    cat "${out}/${archive}.sha256" >&2
    failed=1
fi

# The checksum has to describe the archive next to it, which is what
# publish-release.yml re-verifies before anything is published.
if command -v sha256sum > /dev/null; then
    (cd "$out" && sha256sum -c "${archive}.sha256" > /dev/null) || failed=1
else
    (cd "$out" && shasum -a 256 -c "${archive}.sha256" > /dev/null) || failed=1
fi

# The two platforms take different branches of that conditional, and only one
# of them runs here. Where both tools exist, prove they agree rather than
# assuming it.
if command -v sha256sum > /dev/null && command -v shasum > /dev/null; then
    a="$(cd "$out" && sha256sum -b "$archive")"
    b="$(cd "$out" && shasum -a 256 -b "$archive")"
    if [ "$a" != "$b" ]; then
        echo "sha256sum and shasum disagree:" >&2
        echo "  $a" >&2
        echo "  $b" >&2
        failed=1
    fi
fi

# Contents survive the round trip.
unpacked="${work}/unpacked"
mkdir -p "$unpacked"
tar -xJf "${out}/${archive}" -C "$unpacked"
if ! cmp -s "${src}/lastpass-ssh-agent" "${unpacked}/lastpass-ssh-agent"; then
    echo "the packaged binary does not match the one handed in" >&2
    failed=1
fi

if [ "$failed" -ne 0 ]; then
    exit 1
fi

# A missing input must abort rather than ship an archive without it.
if ./archive.sh "$target" "${work}/never" "${src}/nonexistent" > /dev/null 2>&1; then
    echo "a missing input should have failed the build" >&2
    exit 1
fi

# A dotfile would be staged but skipped by the glob that builds the archive,
# so it must be refused rather than quietly left out.
printf 'hidden\n' > "${src}/.hidden"
if ./archive.sh "$target" "${work}/never" \
    "${src}/lastpass-ssh-agent" "${src}/.hidden" > /dev/null 2>&1; then
    echo "a dotfile input should have failed the build" >&2
    exit 1
fi

# Two inputs with the same basename would silently become one file.
mkdir -p "${work}/other"
printf 'different\n' > "${work}/other/README.md"
if ./archive.sh "$target" "${work}/never" \
    "${src}/README.md" "${work}/other/README.md" > /dev/null 2>&1; then
    echo "colliding basenames should have failed the build" >&2
    exit 1
fi

echo "archive.sh: ok"
