#!/usr/bin/env bash
# requires: compose
# Gitops boot-apply smoke against the deploy/compose example-config tree.
#
# Asserts:
#  - metrics endpoint is reachable, boot apply fired with result="ok"
#    (hort_gitops_apply_total), and at least one per-object outcome counter
#    (hort_gitops_objects_total) fired — posture-aware: note-and-skip when no
#    read_metrics bearer is available for this lane, never a scenario FAIL.
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
# 1. Metrics endpoint is reachable, and the boot-apply metrics fired.
#
# Posture-aware (item 084): an empty METRICS_TOKEN is a genuinely-absent
# input (no read_metrics bearer minted for this lane) — note-and-skip,
# same wording family as assert_metric_ingest's unset branch, and must
# not flip this scenario's overall result. A present token that scrapes
# non-2xx stays a loud FAIL carrying the HTTP status
# (metrics_scrape_preflight, lib/common.sh).
# ---------------------------------------------------------------------
log ""
log "--> hort-server metrics are scrapeable"
if metrics_scrape_preflight "gitops boot-apply metrics"; then
    pass "metrics endpoint responds"

    # issue #79 sibling sweep: same shape as assert_metric_ingest's
    # completion-vs-scrape race (a single point-in-time scrape of a metric
    # whose emission the scenario doesn't otherwise directly synchronise
    # with) — bounded_poll instead of one scrape. The boot-apply normally
    # completes long before this scenario container even starts (the
    # compose runner guarantees the stack is up first), so a real run
    # should hit on the first poll attempt; the bound is just headroom for
    # exporter-registration lag, not an expected wait.
    log ""
    log '--> hort_gitops_apply_total{result="ok"} fired during boot'
    if bounded_poll "gitops apply_total(result=ok)" 15 \
        "curl -sSf \"\${METRICS_AUTH_HEADER[@]}\" \"\$METRICS_URL\" 2>/dev/null | grep -Eq '^hort_gitops_apply_total\{[^}]*result=\"ok\"[^}]*\} +[1-9]'"; then
        pass 'hort_gitops_apply_total{result=ok} >= 1'
    else
        fail 'hort_gitops_apply_total{result=ok} >= 1' \
            "metric absent or zero after 15s poll — gitops boot may have skipped or failed silently -- last scrape: $(metrics_scrape_diag "${METRICS_URL}")"
    fi

    if bounded_poll "gitops objects_total emitted" 15 \
        "curl -sSf \"\${METRICS_AUTH_HEADER[@]}\" \"\$METRICS_URL\" 2>/dev/null | grep -Eq '^hort_gitops_objects_total\{'"; then
        pass "hort_gitops_objects_total emitted at least once"
    else
        fail "hort_gitops_objects_total emitted" \
            "metric absent in scrape after 15s poll -- last scrape: $(metrics_scrape_diag "${METRICS_URL}")"
    fi
fi

# Abort early only on a genuine metrics failure above (never on a posture
# skip) — nothing else is testable if the stack itself is down.
if [ "${_FAIL}" -gt 0 ]; then summary; fi

# ---------------------------------------------------------------------
# 2. Every declared repo resolves via the admin lookup endpoint and
#    reports managed_by="gitops".
# ---------------------------------------------------------------------
log ""
log "--> example-config repos resolve via GET /api/v1/admin/repositories/<key> with managed_by=gitops"

ADMIN_TOKEN="$(fetch_token admin admin)"
[ -n "$ADMIN_TOKEN" ] || fail "fetch admin token" "empty response from Keycloak"

EXPECTED_KEYS=("npm-public" "pypi-internal" "all-npm" "pypi-e2e" "cargo-e2e" "npm-e2e" "oci-e2e" "oci-mirror-e2e"
               "npm-dedup-leader-e2e" "npm-dedup-follower-e2e")
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
