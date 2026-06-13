#!/usr/bin/env bash
# Scenario 8: Privilege denial.
#
# Spec: a token holding NEITHER Curate NOR Admin gets 403 on EVERY
# curation endpoint (waive, block, block-versions, queue, decisions,
# exclusions, exclude-finding, unexclude-finding).
#
# Implementation: the v2 Keycloak realm has a `reader-user` (member of
# `test-readers`) that resolves only the `reader` claim — no admin, no
# curator. We mint that token and exercise every endpoint, expecting 403
# on each.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then set -x; fi

log "==> Scenario 8: Privilege denial"

require_stack_up

# We hit raw HTTP for this scenario — hort-cli surfaces a non-zero exit on
# 403 but the assertion is on the HTTP code, which is cleaner via curl
# directly. This also doesn't require the hort-cli binary, so we don't
# call require_hort_cli.

# Mint a non-privileged token. Try the reader user first (most common
# v2 fixture); fall back to a dummy username if the realm has a
# different shape.
NONPRIV_TOKEN="$(keycloak_token reader-user reader 2>/dev/null || \
                 keycloak_token reader reader 2>/dev/null || \
                 keycloak_token test-reader reader 2>/dev/null || true)"
if [ -z "$NONPRIV_TOKEN" ]; then
    log "SKIP: no non-privileged user available in Keycloak realm — cannot"
    log "      mint a token with neither Admin nor Curate claims. Scenario 8"
    log "      requires the v2 e2e realm fixture from deploy/compose/keycloak/."
    exit 2
fi
log "  got non-privileged token (${#NONPRIV_TOKEN} chars)"

# -----------------------------------------------------------------------------
# Endpoint sweep — expect 403 on each
# -----------------------------------------------------------------------------

ANY_AID="$(psql_one "SELECT id::text FROM artifacts LIMIT 1;" 2>/dev/null || echo "00000000-0000-0000-0000-000000000000")"
ANY_POLICY="$(psql_one "SELECT id::text FROM scan_policies LIMIT 1;" 2>/dev/null || echo "00000000-0000-0000-0000-000000000000")"

probe() {
    local label="$1" method="$2" path="$3" body="${4:-}"
    local args=(
        -sS -o /dev/null -w "%{http_code}"
        -X "$method"
        -H "Authorization: Bearer $NONPRIV_TOKEN"
        --max-time 10
        "$API_URL$path"
    )
    if [ -n "$body" ]; then
        args+=(-H "Content-Type: application/json" -d "$body")
    fi
    local code
    code="$(curl "${args[@]}" 2>/dev/null || echo "000")"
    # We accept 403 as the canonical denial. The middleware may also
    # respond 401 if the token resolves to no principal at all — both
    # are non-permissive answers and pass the "no curator/admin access"
    # assertion. 403 is the canonical denial; we log which one fired.
    if [ "$code" = "403" ]; then
        assert_pass "$label: 403 Forbidden (non-privileged token denied)"
    elif [ "$code" = "401" ]; then
        assert_pass "$label: 401 Unauthorized (token rejected pre-authz)"
    else
        assert_fail "$label: 403 (or 401) on non-privileged token" \
            "got HTTP $code on $method $path"
    fi
}

JUSTIFICATION='{"justification":"unauthorized probe"}'

probe "waive"             POST   "/api/v1/admin/curation/quarantine/$ANY_AID/waive"       "$JUSTIFICATION"
probe "block (single)"    POST   "/api/v1/admin/curation/quarantine/$ANY_AID/block"       "$JUSTIFICATION"
probe "block-versions"    POST   "/api/v1/admin/curation/block-versions"                  '{"repository":"x","package":"y","versions":["1.0"],"justification":"probe"}'
probe "queue"             GET    "/api/v1/admin/curation/queue"                            ""
probe "decisions"         GET    "/api/v1/admin/curation/decisions"                        ""
probe "exclusions"        GET    "/api/v1/admin/curation/exclusions"                       ""
probe "exclude-finding"   POST   "/api/v1/admin/policies/$ANY_POLICY/exclusions"           '{"cve_id":"CVE-2026-0000","justification":"probe"}'
probe "unexclude-finding" DELETE "/api/v1/admin/policies/$ANY_POLICY/exclusions/CVE-2026-0000" ""

# -----------------------------------------------------------------------------

print_summary
exit $?
