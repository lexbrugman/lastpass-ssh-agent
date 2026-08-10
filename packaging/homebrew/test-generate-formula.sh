#!/bin/sh
# Checks generate-formula.sh against checksum files shaped exactly like the
# ones dist publishes: "<hash> *<name>", not a bare hash. Getting this wrong
# produces a formula Homebrew rejects, and a fixture holding only a hash
# would not catch it.
set -eu
cd "$(dirname "$0")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
for target in aarch64-apple-darwin x86_64-apple-darwin \
              aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
    name="lastpass-ssh-agent-${target}.tar.xz"
    printf '%s *%s\n' "$hash" "$name" > "${work}/${name}.sha256"
done

formula="${work}/formula.rb"
./generate-formula.sh 2026.810.0 owner/repo "$work" > "$formula"

failed=0
for value in $(grep -oE 'sha256 "[^"]*"' "$formula" | sed 's/sha256 "//; s/"//'); do
    if ! printf '%s' "$value" | grep -qE '^[0-9a-f]{64}$'; then
        echo "not a bare sha256: $value" >&2
        failed=1
    fi
done
if grep -q '@[A-Z_]*@' "$formula"; then
    echo "unsubstituted placeholder left in the formula" >&2
    failed=1
fi
if [ "$failed" -ne 0 ]; then
    exit 1
fi

# a missing checksum must abort rather than emit an empty sha256
if ./generate-formula.sh 2026.810.0 owner/repo "${work}/nowhere" >/dev/null 2>&1; then
    echo "a missing checksum should have failed the build" >&2
    exit 1
fi

echo "generate-formula.sh: ok"
