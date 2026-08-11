#!/bin/sh
# Package a built binary as the release archive for one target.
#
#   archive.sh <target> <out-dir> <file>...
#
# Writes <out-dir>/lastpass-ssh-agent-<target>.tar.xz and a .sha256 beside it,
# which is what build-release.yml uploads and what generate-formula.sh later
# reads the hashes out of.
#
# The files land at the archive root, not inside a wrapping directory: the
# Homebrew formula installs the binary straight out of the staged extraction,
# so a stray top-level directory would produce an archive that looks fine and
# fails at `brew install`. test-archive.sh pins that down, along with the
# checksum format, because neither is visible until someone installs.
set -eu

if [ "$#" -lt 3 ]; then
    echo "usage: archive.sh <target> <out-dir> <file>..." >&2
    exit 1
fi

target="$1"
out="$2"
shift 2

archive="lastpass-ssh-agent-${target}.tar.xz"

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

for file in "$@"; do
    if [ ! -f "$file" ]; then
        echo "no such file to package: $file" >&2
        exit 1
    fi
    case "$(basename "$file")" in
        .*)
            # The archive is built from a glob, and a glob does not match a
            # leading dot: such a file would be staged, counted, and then left
            # out of the archive without a word. No release ships one, so
            # refuse it rather than carry the machinery to include it.
            echo "refusing to package a dotfile: $file" >&2
            exit 1
            ;;
    esac
    cp "$file" "$staging/"
done

# Everything is copied in by basename, so two inputs from different
# directories can collide and one would vanish from the archive without a
# word. Count instead of trusting the caller.
staged="$(find "$staging" -type f | wc -l)"
if [ "$staged" -ne "$#" ]; then
    echo "two inputs share a basename: $* " >&2
    exit 1
fi

mkdir -p "$out"
out_abs="$(cd "$out" && pwd)"

# Built from inside the staging directory so nothing about the build tree's
# layout can leak into the archive. The glob rather than a built-up string
# keeps a name with a space in it in one piece.
(cd "$staging" && tar -cJf "${out_abs}/${archive}" -- *)

# "<hash> *<name>" from either platform's tool — the shape generate-formula.sh
# parses and `sha256sum -c` accepts. GitHub's Linux runners have sha256sum and
# its macOS ones only shasum, and the two agree on this format.
(
    cd "$out_abs"
    if command -v sha256sum > /dev/null; then
        sha256sum -b "$archive" > "${archive}.sha256"
    else
        shasum -a 256 -b "$archive" > "${archive}.sha256"
    fi
)

cat "${out_abs}/${archive}.sha256"
