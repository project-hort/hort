#!/usr/bin/env bash
# requires: compose
# Gitops boot-apply smoke against the deploy/compose example-config tree.
#
# Asserts:
#  - metrics endpoint is reachable.
#  - Boot apply fired with result="ok" (hort_gitops_apply_total).
#  - At least one per-object outcome counter (hort_gitops_objects_total) fired.
#  - Each managed repo from deploy/compose/example-config/repositories/ resolves
#    via GET /api/v1/admin/repositories/<key> and reports managed_by="gitops".
#
# The admin token is always fetched from Keycloak (no $ADMIN_TOKEN env input).
# The compose runner guarantees the stack is up before this script is invoked.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

log "==> Gitops smoke"
log "Registry: ${HORT_URL}"
log "Metrics:  ${METRICS_URL}"

# ---------------------------------------------------------------------
# 1. Metrics endpoint is reachable.
# ---------------------------------------------------------------------
log ""
log "--> hort-server is reachable on the metrics port"
if curl -sSf -o /dev/null "${METRICS_URL}" 2>/dev/null; then
    pass "metrics endpoint responds"
else
    fail "metrics endpoint responds" "${METRICS_URL} unreachable"
fi

# Abort early — nothing else is testable if metrics is down.
if [ "${_FAIL}" -gt 0 ]; then summary; fi

# ---------------------------------------------------------------------
# 2. Boot-apply metric fired with result=ok.
# ---------------------------------------------------------------------
log ""
log '--> hort_gitops_apply_total{result="ok"} fired during boot'
SCRAPE=$(curl -sSf "${METRICS_URL}" 2>/dev/null || echo "")
if printf '%s\n' "$SCRAPE" \
    | grep -E '^hort_gitops_apply_total\{[^}]*result="ok"[^}]*\} +[1-9]' >/dev/null; then
    pass 'hort_gitops_apply_total{result=ok} >= 1'
else
    fail 'hort_gitops_apply_total{result=ok} >= 1' \
        "metric absent or zero — gitops boot may have skipped or failed silently"
fi

if printf '%s\n' "$SCRAPE" | grep -E '^hort_gitops_objects_total\{' >/dev/null; then
    pass "hort_gitops_objects_total emitted at least once"
else
    fail "hort_gitops_objects_total emitted" "metric absent in scrape"
fi

# ---------------------------------------------------------------------
# 3. Every declared repo resolves via the admin lookup endpoint and
#    reports managed_by="gitops".
# ---------------------------------------------------------------------
log ""
log "--> example-config repos resolve via GET /api/v1/admin/repositories/<key> with managed_by=gitops"

ADMIN_TOKEN="$(fetch_token admin admin)"
[ -n "$ADMIN_TOKEN" ] || fail "fetch admin token" "empty response from Keycloak"

EXPECTED_KEYS=("npm-public" "pypi-internal" "all-npm" "pypi-e2e" "cargo-e2e" "npm-e2e" "oci-e2e" "oci-mirror-e2e")
for key in "${EXPECTED_KEYS[@]}"; do
    body=$(mktemp)
    status=$(curl -sS -o "$body" -w '%{http_code}' \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        "${HORT_URL}/api/v1/admin/repositories/${key}" || echo 000)
    if [ "$status" != "200" ]; then
        fail "${key} resolves via admin lookup" \
            "got status ${status}, body $(cat "$body" 2>/dev/null || echo '<empty>')"
        rm -f "$body"
        continue
    fi
    managed_by=$(jq -r '.managed_by // empty' "$body" 2>/dev/null || echo "")
    rm -f "$body"
    if [ "$managed_by" = "gitops" ]; then
        pass "${key} resolves with managed_by=gitops"
    else
        fail "${key} carries managed_by=gitops" "got '${managed_by}'"
    fi
done

summary
