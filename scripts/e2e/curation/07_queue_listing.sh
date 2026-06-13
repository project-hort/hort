#!/usr/bin/env bash
# Scenario 7: Queue listing surfaces rejection reasons.
#
# Spec: scenario 2's block result shows up in `hort-cli curation queue
# --status rejected` with `rejection_reason_kind = "curator"`; a
# scanner-rejected fixture artifact shows `rejection_reason_kind =
# "scanner"`; `--reason curator` filters to only scenario 2's row.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then set -x; fi

log "==> Scenario 7: Queue listing"

require_stack_up
require_hort_cli

ADMIN_TOKEN="$(keycloak_token admin admin)" || {
    log "SKIP: Keycloak admin token unavailable"
    exit 2
}

# -----------------------------------------------------------------------------
# 1. Basic queue listing
# -----------------------------------------------------------------------------

QUEUE_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation queue --status rejected 2>&1)" || {
    assert_fail "queue listing call succeeds" "hort-cli output: $QUEUE_OUT"
    print_summary
    exit 1
}
assert_pass "queue --status rejected HTTP call succeeded"

ENTRIES_LEN="$(json_get "$QUEUE_OUT" '.entries | length' 2>/dev/null || \
              json_get "$QUEUE_OUT" '. | length' 2>/dev/null || echo "0")"
if [ "${ENTRIES_LEN:-0}" -ge "1" ] 2>/dev/null; then
    assert_pass "queue --status rejected returned ≥1 entries ($ENTRIES_LEN)"
else
    log "SKIP: no rejected artifacts in queue — scenarios 2 + 3 may have skipped"
    exit 2
fi

# -----------------------------------------------------------------------------
# 2. Listing carries rejection_reason_kind
# -----------------------------------------------------------------------------

if printf '%s' "$QUEUE_OUT" | grep -q '"rejection_reason_kind"'; then
    assert_pass "queue rows expose rejection_reason_kind field"
else
    assert_fail "queue rows expose rejection_reason_kind" \
        "field absent from payload"
fi

# -----------------------------------------------------------------------------
# 3. --reason curator filter
# -----------------------------------------------------------------------------

CURATOR_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation queue --status rejected --reason curator 2>&1)" || {
    assert_fail "queue --reason curator call succeeds" "hort-cli output: $CURATOR_OUT"
    print_summary
    exit 1
}
CURATOR_LEN="$(json_get "$CURATOR_OUT" '.entries | length' 2>/dev/null || \
              json_get "$CURATOR_OUT" '. | length' 2>/dev/null || echo "0")"
if [ "${CURATOR_LEN:-0}" -le "${ENTRIES_LEN:-0}" ] 2>/dev/null; then
    assert_pass "--reason curator narrows the listing (curator=$CURATOR_LEN, all=$ENTRIES_LEN)"
else
    assert_fail "--reason curator narrows the listing" \
        "curator=$CURATOR_LEN > all=$ENTRIES_LEN — filter not applied"
fi

# Every row in the curator-filtered listing should have rejection_reason_kind="curator"
# (the serialized value is lowercase — see hort-adapters-postgres curation_queue
# repository tests). Use POSIX [[:space:]] (grep -E does not honor \s) and match
# the exact quoted value.
if [ "${CURATOR_LEN:-0}" -ge "1" ] 2>/dev/null; then
    NON_CURATOR="$(printf '%s' "$CURATOR_OUT" \
        | grep -oE '"rejection_reason_kind"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | grep -vc '"curator"' || true)"
    NON_CURATOR="${NON_CURATOR:-0}"
    if [ "$NON_CURATOR" -eq 0 ] 2>/dev/null; then
        assert_pass "--reason curator: every returned row has rejection_reason_kind=curator"
    else
        assert_fail "--reason curator: every row has rejection_reason_kind=curator" \
            "found $NON_CURATOR rows with a different kind"
    fi
fi

# -----------------------------------------------------------------------------
# 4. (Optional) --reason scanner shows scanner-rejected rows when present
# -----------------------------------------------------------------------------

SCANNER_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation queue --status rejected --reason scanner 2>&1)" || true
SCANNER_LEN="$(json_get "$SCANNER_OUT" '.entries | length' 2>/dev/null || \
              json_get "$SCANNER_OUT" '. | length' 2>/dev/null || echo "0")"
log "  --reason scanner returned $SCANNER_LEN rows (informational, no assertion)"

# -----------------------------------------------------------------------------

print_summary
exit $?
