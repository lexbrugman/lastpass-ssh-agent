#!/bin/sh
# The full local gate: formatting, strict lints, and the test suite (which
# always runs instrumented and requires 100% line+branch coverage of
# production code). CI runs the same steps.
set -eu
cd "$(dirname "$0")/.."

echo "== rustfmt"
cargo fmt --check
echo "== clippy (pedantic + nursery, warnings are errors)"
cargo clippy --all-targets -- -D warnings
echo "== homebrew formula generator"
./packaging/homebrew/test-generate-formula.sh
echo "== tests (instrumented; 100% line+branch coverage required)"
./scripts/test.sh
