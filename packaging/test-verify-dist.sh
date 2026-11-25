#!/bin/sh
# Checks verify-dist.sh accepts what the build jobs really upload and refuses
# everything else. It only ever runs for real during a release, between jobs,
# where a mistake would be attested and published before anyone saw it.
set -eu
cd "$(dirname "$0")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

targets="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl"

# The list is build-release.yml's to define; a target added there and not to
# verify-dist.sh would fail its first release at the publish step.
built="$(grep -oE 'target: [a-z0-9_-]+' ../.github/workflows/build-release.yml \
    | sed 's/target: //' | LC_ALL=C sort | tr '\n' ' ')"
checked="$(echo "$targets" | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ')"
if [ "$built" != "$checked" ]; then
    echo "build-release.yml builds [$built] but this test covers [$checked]" >&2
    exit 1
fi

# What four build jobs leave behind, made with the script they use.
good="${work}/good"
printf 'stub\n' > "${work}/lastpass-ssh-agent"
for target in $targets; do
    ./archive.sh "$target" "${good}/release-${target}" "${work}/lastpass-ssh-agent" \
        > /dev/null
done

if ! ./verify-dist.sh "$good" "${work}/out" > /dev/null; then
    echo "the build jobs' own output was refused" >&2
    exit 1
fi
if [ "$(ls -A "${work}/out" | wc -l | tr -d ' ')" != 8 ]; then
    echo "expected four archives and four checksums, got: $(ls -A "${work}/out")" >&2
    exit 1
fi

# The output is published by glob, so it has to start empty.
if ./verify-dist.sh "$good" "${work}/out" > /dev/null 2>&1; then
    echo "an output directory that already exists should have been refused" >&2
    exit 1
fi

failed=0
case_dir() {
    rm -rf "${work}/case"
    cp -R "$good" "${work}/case"
}
refused() {
    if ./verify-dist.sh "${work}/case" "${work}/case-out" > /dev/null 2>&1; then
        echo "should have been refused: $1" >&2
        failed=1
    fi
    rm -rf "${work}/case-out"
}

one=release-x86_64-unknown-linux-musl
one_archive=lastpass-ssh-agent-x86_64-unknown-linux-musl.tar.xz
other=release-aarch64-unknown-linux-musl
other_archive=lastpass-ssh-agent-aarch64-unknown-linux-musl.tar.xz

case_dir
cp -R "${work}/case/${one}" "${work}/case/release-probe"
refused "an artifact no build job uploads"

case_dir
rm -rf "${work}/case/${one}"
refused "a missing target"

case_dir
printf 'extra\n' > "${work}/case/${one}/extra.tar.xz"
refused "a file beside the archive and its checksum"

case_dir
printf 'tampered\n' >> "${work}/case/${one}/${one_archive}"
refused "an archive that does not match its checksum"

# Each line is true of the archive it names, which is all `sha256sum -c` asks.
case_dir
cp "${work}/case/${other}/${other_archive}.sha256" "${work}/case/${one}/${one_archive}.sha256"
refused "a checksum file holding another target's line"

case_dir
printf '0|;1s|.*|x|;#\n' | cat - "${good}/${one}/${one_archive}.sha256" \
    > "${work}/case/${one}/${one_archive}.sha256"
refused "a checksum file with a line ahead of the real one"

case_dir
rm "${work}/case/${one}/${one_archive}"
ln -s "../${other}/${other_archive}" "${work}/case/${one}/${one_archive}"
refused "an archive that is a symlink"

if [ "$failed" -ne 0 ]; then
    exit 1
fi
echo "verify-dist.sh: ok"
