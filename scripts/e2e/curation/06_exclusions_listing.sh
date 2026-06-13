#!/usr/bin/env bash
# Scenario 6: Exclusions listing.
#
# Spec: `hort-cli curation exclusions --policy <p>` returns one row for
# the CVE added in scenario 4 with `added_by_actor_id` populated.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then set -x; fi

log "==> Scenario 6: Exclusions listing"

require_stack_up
require_hort_cli

ADMIN_TOKEN="$(keycloak_token admin admin)" || {
    log "SKIP: Keycloak admin token unavailable"
    exit 2
}

# -----------------------------------------------------------------------------
# 1. Discover any policy/CVE pair in exclusion_projections
# -----------------------------------------------------------------------------
#
# Scenario 4 adds an exclusion; if it skipped (no shared-CVE fixture),
# we use any exclusion row that exists. If none exist, exit 2.

PROJ_ROW="$(psql_one "SELECT policy_id::text || '|' || cve_id \
    FROM exclusion_projections LIMIT 1;" 2>/dev/null)"

if [ -z "$PROJ_ROW" ]; then
    log "SKIP: no rows in exclusion_projections — scenario 4 may have skipped"
    log "      (no multi-artifact CVE fixture), so there's nothing to list."
    exit 2
fi

POLICY_ID="$(echo "$PROJ_ROW" | cut -d'|' -f1)"
CVE_ID="$(echo "$PROJ_ROW" | cut -d'|' -f2)"

# -----------------------------------------------------------------------------
# 2. Call the listing
# -----------------------------------------------------------------------------

LIST_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation exclusions --policy "$POLICY_ID" 2>&1)" || {
    assert_fail "exclusions listing call succeeds" "hort-cli output: $LIST_OUT"
    print_summary
    exit 1
}
assert_pass "exclusions listing HTTP call succeeded"

# Listing should contain at least one entry for this (policy, cve) pair.
if printf '%s' "$LIST_OUT" | grep -q "$CVE_ID"; then
    assert_pass "listing contains expected CVE ($CVE_ID)"
else
    assert_fail "listing contains expected CVE" \
        "payload: $(echo "$LIST_OUT" | head -c 300)"
fi

# Listing should expose added_by_actor_id (non-null).
if printf '%s' "$LIST_OUT" | grep -qE '"added_by_actor_id"\s*:\s*"[0-9a-f-]+"'; then
    assert_pass "listing exposes added_by_actor_id (non-null)"
else
    assert_fail "listing exposes added_by_actor_id" \
        "no added_by_actor_id field with uuid value in payload"
fi

# -----------------------------------------------------------------------------

print_summary
exit $?
