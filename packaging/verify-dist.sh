#!/bin/sh
# Check what the build jobs handed over, and lay it out for the release.
#
#   verify-dist.sh <artifacts-dir> <out-dir>
#
# <artifacts-dir> holds one directory per downloaded artifact, named as
# build-release.yml uploads them. Each must be one of the four it builds and
# hold exactly its archive and that archive's checksum; the eight files are
# then copied flat into <out-dir>, which is what gets attested and published.
# <out-dir> must not exist yet: it is published by glob, so anything already
# in it would go out unchecked.
#
# Everything published is selected here by name, never by pattern: any job in
# the run can upload an artifact, and one that merely looked like a release
# would otherwise be attested and shipped beside the real ones.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: verify-dist.sh <artifacts-dir> <out-dir>" >&2
    exit 1
fi

artifacts="$1"
out="$2"

# build-release.yml's matrix owns this list; test-verify-dist.sh fails when
# the two differ.
targets="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl"

fail() {
    echo "verify-dist.sh: $1" >&2
    exit 1
}

sha256_of() {
    if command -v sha256sum > /dev/null; then
        sha256sum -b "$1" | awk '{print $1}'
    else
        shasum -a 256 -b "$1" | awk '{print $1}'
    fi
}

# LC_ALL=C: the comparison is of two sorted lists, and collation differs
# between the runners' locale and a developer's.
listing() {
    ls -A "$1" | LC_ALL=C sort
}

expected="$(for target in $targets; do echo "release-${target}"; done | LC_ALL=C sort)"
if [ "$(listing "$artifacts")" != "$expected" ]; then
    fail "expected exactly one artifact per target, found: $(listing "$artifacts" | tr '\n' ' ')"
fi

mkdir "$out"
for target in $targets; do
    dir="${artifacts}/release-${target}"
    archive="lastpass-ssh-agent-${target}.tar.xz"
    sum="${archive}.sha256"

    if [ "$(listing "$dir")" != "$(printf '%s\n%s' "$archive" "$sum")" ]; then
        fail "release-${target} should hold ${archive} and its checksum, found: $(listing "$dir" | tr '\n' ' ')"
    fi
    for file in "$archive" "$sum"; do
        if [ -L "${dir}/${file}" ] || [ ! -f "${dir}/${file}" ]; then
            fail "${file} is not a regular file"
        fi
    done

    # The checksum file has to be, byte for byte, the one line archive.sh
    # writes for this archive. Compared whole rather than parsed: the file is
    # published as it is, and the formula picks each hash by the file's name,
    # so a line about another archive, or anything beside the line, would
    # verify field by field and still ship.
    hash="$(sha256_of "${dir}/${archive}")"
    # a tool that failed prints nothing, and nothing would match a checksum
    # file that held no hash either
    if ! printf '%s\n' "$hash" | grep -qxE '[0-9a-f]{64}'; then
        fail "could not compute the sha256 of ${archive}"
    fi
    if ! printf '%s *%s\n' "$hash" "$archive" | cmp -s - "${dir}/${sum}"; then
        fail "${sum} is not the checksum line for ${archive}"
    fi

    cp "${dir}/${archive}" "${dir}/${sum}" "$out/"
done

echo "verify-dist.sh: four archives, each matching the checksum that names it"
