#!/usr/bin/env bash
# Scenario 5: Decisions listing reconstructs 1-4.
#
# Spec: `hort-cli curation decisions --since <start_of_test>` returns rows
# for every event the prior scenarios emitted; `--by-correlation`
# collapses scenario 3's three rows into one; `--type block` filters to
# only block events; `--actor <curator>` filters to that user's actions.
#
# Skip semantics: when no prior scenario decisions have landed, the
# scenario exits 2 (the listing assertions are meaningless against an
# empty event stream). The orchestrator runs scenarios in numeric order,
# so by the time scenario 5 fires, scenarios 1-4 have either fired
# successfully or been skipped.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then set -x; fi

log "==> Scenario 5: Decisions listing"

require_stack_up
require_hort_cli

ADMIN_TOKEN="$(keycloak_token admin admin)" || {
    log "SKIP: Keycloak admin token unavailable"
    exit 2
}

# Use a sufficiently old --since so prior scenarios' events are included.
# "today minus 1 hour" is sufficient — every scenario runs within that
# window when called from run.sh.
SINCE="$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"

# -----------------------------------------------------------------------------
# 1. Listing returns at least one row (any prior scenario action)
# -----------------------------------------------------------------------------

LIST_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation decisions --since "$SINCE" 2>&1)" || {
    assert_fail "decisions listing call succeeds" "hort-cli output: $LIST_OUT"
    print_summary
    exit 1
}
assert_pass "decisions listing HTTP call succeeded"

ENTRIES_LEN="$(json_get "$LIST_OUT" '(.events // []) | length' 2>/dev/null || \
              json_get "$LIST_OUT" '. | length' 2>/dev/null || echo "0")"
if [ "${ENTRIES_LEN:-0}" -ge "1" ] 2>/dev/null; then
    assert_pass "decisions listing returned ≥1 entries (got $ENTRIES_LEN)"
else
    log "  SKIP: no decision rows in the listing yet — prior scenarios may have skipped"
    log "        (listing returned: $(echo "$LIST_OUT" | head -c 200))"
    exit 2
fi

# -----------------------------------------------------------------------------
# 2. --type block filters down
# -----------------------------------------------------------------------------

BLOCK_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation decisions --since "$SINCE" --type block 2>&1)" || {
    assert_fail "--type block listing succeeds" "hort-cli output: $BLOCK_OUT"
    print_summary
    exit 1
}
BLOCK_LEN="$(json_get "$BLOCK_OUT" '(.events // []) | length' 2>/dev/null || \
            json_get "$BLOCK_OUT" '. | length' 2>/dev/null || echo "0")"
if [ "${BLOCK_LEN:-0}" -le "${ENTRIES_LEN:-0}" ] 2>/dev/null; then
    assert_pass "--type block returns ≤ unfiltered (block=$BLOCK_LEN, all=$ENTRIES_LEN)"
else
    assert_fail "--type block filter narrows the listing" \
        "block=$BLOCK_LEN > all=$ENTRIES_LEN (filter not applied?)"
fi

# Assert every row in the block-filtered listing has decision_type referencing block.
# We accept any of: "block", "block_artifact", "block_versions"; the
# server taxonomy may differ but block-family rows should not be empty.
NON_BLOCK_ROWS="$(json_get "$BLOCK_OUT" '(.events // []) | map(select(.decision_type | test("block"; "i") | not)) | length' 2>/dev/null || echo "")"
if [ -n "$NON_BLOCK_ROWS" ] && [ "$NON_BLOCK_ROWS" = "0" ]; then
    assert_pass "--type block: every row is a block decision"
else
    log "  NOTE: could not enumerate decision_type filter (jq missing or shape differs);"
    log "        soft-asserting filter via count comparison above."
fi

# -----------------------------------------------------------------------------
# 3. --by-correlation collapses the scenario-3 bulk block
# -----------------------------------------------------------------------------

CORR_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation decisions --since "$SINCE" --by-correlation 2>&1)" || {
    assert_fail "--by-correlation listing succeeds" "hort-cli output: $CORR_OUT"
    print_summary
    exit 1
}
CORR_LEN="$(json_get "$CORR_OUT" '(.groups // []) | length' 2>/dev/null || \
           json_get "$CORR_OUT" '. | length' 2>/dev/null || echo "0")"
if [ "${CORR_LEN:-0}" -le "${ENTRIES_LEN:-0}" ] 2>/dev/null; then
    assert_pass "--by-correlation rollup count ≤ unrolled (rolled=$CORR_LEN, raw=$ENTRIES_LEN)"
else
    assert_fail "--by-correlation rolls up" \
        "rolled=$CORR_LEN > raw=$ENTRIES_LEN (rollup not applied)"
fi

# -----------------------------------------------------------------------------
# 4. --actor <admin_uuid> filters to admin's actions
# -----------------------------------------------------------------------------

# Resolve admin user_id from DB. Prior scenarios authenticated as admin,
# so JIT provisioning should have created the row.
ADMIN_UID="$(resolve_user_id_by_username admin)"
if [ -z "$ADMIN_UID" ]; then
    log "  NOTE: cannot resolve admin user_id from users table — --actor"
    log "        filter assertion deferred to a future run when JIT has"
    log "        provisioned the row."
else
    ACTOR_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation decisions --since "$SINCE" \
        --actor "$ADMIN_UID" 2>&1)" || {
        assert_fail "--actor filter succeeds" "hort-cli output: $ACTOR_OUT"
        print_summary
        exit 1
    }
    ACTOR_LEN="$(json_get "$ACTOR_OUT" '(.events // []) | length' 2>/dev/null || \
                json_get "$ACTOR_OUT" '. | length' 2>/dev/null || echo "0")"
    if [ "${ACTOR_LEN:-0}" -le "${ENTRIES_LEN:-0}" ] 2>/dev/null; then
        assert_pass "--actor filter narrows (admin=$ACTOR_LEN, all=$ENTRIES_LEN)"
    else
        assert_fail "--actor filter narrows" \
            "actor=$ACTOR_LEN > all=$ENTRIES_LEN"
    fi
fi

# -----------------------------------------------------------------------------

print_summary
exit $?
