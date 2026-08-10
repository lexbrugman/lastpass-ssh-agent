#!/bin/sh
# Runs the test suite. Tests always run instrumented: passing means every
# test passed AND every line and branch of production code was covered
# (test modules and documented-unreachable error glue are excluded via
# #[cfg_attr(coverage_nightly, coverage(off))]).
#
# Branch instrumentation requires a nightly toolchain (-Z coverage-options),
# hence cargo +nightly. Stale artifacts from other toolchains poison the
# report, so always clean first.
set -eu
cd "$(dirname "$0")/.."

cargo llvm-cov clean --workspace

output=$(cargo +nightly llvm-cov --branch --all-targets \
    --ignore-filename-regex '(^|/)build\.rs$' \
    --fail-under-lines 100 2>&1) || {
    printf '%s\n' "$output" | tail -25
    echo "FAIL: tests failed, or line coverage is below 100%"
    exit 1
}

total=$(printf '%s\n' "$output" | grep '^TOTAL')
printf '%s\n' "$output" | sed -n '/^Filename/,$p'

# --fail-under-branches does not exist yet; enforce from the TOTAL row
# (columns: ... Branches, Missed Branches, Cover)
missed_branches=$(printf '%s\n' "$total" | awk '{print $(NF-1)}')
if [ "$missed_branches" != "0" ]; then
    echo "FAIL: $missed_branches branch destination(s) not covered"
    exit 1
fi
echo "OK: tests pass with 100% line and branch coverage"
