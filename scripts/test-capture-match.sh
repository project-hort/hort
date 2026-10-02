#!/usr/bin/env bash
# scripts/test-capture-match.sh
#
# Regression test for scripts/native-tests/lib/common.sh's capture_match
# helper. Pins the exact trap that motivated it: `producer | grep -q
# PATTERN` under `set -o pipefail` misreports "no match" once PATTERN's
# first hit lands before producer has finished writing a body bigger than
# the pipe buffer (64 KiB) -- grep -q exits at its first match, the
# still-writing producer takes SIGPIPE, and pipefail promotes that exit to
# the pipeline's status.
#
# Asserts directly against the helper, not against a scenario, so this
# test fails on its own if capture_match is ever re-piped into
# `producer | grep -q` internally.
#
# Usage:
#   ./scripts/test-capture-match.sh
#
# Requirements: bash. No compose, no DB, no network, no live stack.
#
# Exit codes:
#   0 — all assertions passed
#   1 — one or more assertions failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# common.sh requires HORT_URL/KEYCLOAK_URL at source time (the native-tests
# scenario harness's env contract); this test never connects to either, so
# dummy values satisfy the guard.
export HORT_URL="http://unused.invalid"
export KEYCLOAK_URL="http://unused.invalid"
# shellcheck source=native-tests/lib/common.sh
# shellcheck disable=SC1091
source "${REPO_ROOT}/scripts/native-tests/lib/common.sh"

PASS=0
FAIL=0

assert() {
    local desc="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (got '$got', want '$want')" >&2
        FAIL=$((FAIL + 1))
    fi
}

# A body over the 64 KiB pipe-buffer threshold (~97 KB, the same order of
# magnitude as the reported gitops smoke's 94 027 B scrape) whose only
# match is on line 1 -- the exact shape that made the original bug
# deterministic rather than flaky.
oversized_body_match_first_line() {
    printf 'MATCH_ON_FIRST_LINE\n'
    local i=0
    while [ "$i" -lt 1200 ]; do
        printf '%080d\n' 0
        i=$((i + 1))
    done
}

body_size="$(oversized_body_match_first_line | wc -c | tr -d '[:space:]')"
if [ "$body_size" -gt 65536 ]; then
    fixture_ok=yes
else
    fixture_ok=no
fi
assert "fixture body (${body_size} bytes) exceeds the 64 KiB pipe buffer" "$fixture_ok" "yes"

if capture_match '^MATCH_ON_FIRST_LINE$' oversized_body_match_first_line; then
    got=match
else
    got=nomatch
fi
assert "capture_match reports a match on line 1 of a >64KiB body" "$got" "match"

if capture_match '^THIS_STRING_IS_NOT_IN_THE_BODY$' oversized_body_match_first_line; then
    got=match
else
    got=nomatch
fi
assert "capture_match correctly reports no-match for an absent pattern" "$got" "nomatch"

# A failing producer must read as no-match, never as a match.
failing_producer() { return 7; }
if capture_match '.*' failing_producer; then
    got=match
else
    got=nomatch
fi
assert "capture_match reports no-match when the producer itself fails" "$got" "nomatch"

echo ""
echo "  passed: $PASS  failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
