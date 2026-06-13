#!/usr/bin/env bash
# requires: egress
# OCI multi-upstream pull-through scenario.
#
# Drives skopeo pulls through the OCI mirror repo to exercise pull-through
# end-to-end: gitops-managed upstream mappings, resolver path-prefix
# routing, upstream proxy fetch + CAS ingest. Verifies cache-hit
# semantics via the `hort_upstream_fetch_total{result="success"}` metric.
#
# Mappings are NOT POSTed at runtime. They are declared in
# `deploy/compose/example-config/upstreams/oci-mirror-e2e-*.yaml` and
# applied by `ApplyConfigUseCase` at boot. The admin repo lookup is a
# sanity check only: a 404 means the gitops apply did not run.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

OCI_REPO_KEY="${OCI_REPO_KEY:-oci-mirror-e2e}"
DOCKERHUB_IMAGE="${DOCKERHUB_IMAGE:-alpine:3.19}"
GHCR_IMAGE="${GHCR_IMAGE:-ghcr.io/oci-playground/hello-world:latest}"
RESOLVER_REFRESH_GUESS="${RESOLVER_REFRESH_GUESS:-8}"

# Strip scheme so skopeo's docker:// transport gets host:port only.
REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

log "==> OCI multi-upstream pull-through scenario (skopeo)"
log "Registry:        ${HORT_URL}"
log "Metrics:         ${METRICS_URL}"
log "Repo key:        ${OCI_REPO_KEY}"
log "Docker Hub img:  ${DOCKERHUB_IMAGE}"
log "GHCR img:        ${GHCR_IMAGE}"

# Tool prereqs
command -v skopeo >/dev/null 2>&1 || skip "skopeo not found"
command -v curl   >/dev/null 2>&1 || skip "curl not found"
command -v awk    >/dev/null 2>&1 || skip "awk not found"

# ---------------------------------------------------------------------
# Preflight: probe the v2 endpoint + outbound to upstream registries.
# 401 from /v2/ counts as reachable (auth required, stack is up).
# ---------------------------------------------------------------------
log ""
log "--- Preflight: probing ${HORT_URL}/v2/"
V2_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${HORT_URL}/v2/" 2>/dev/null || echo "000")
case "$V2_CODE" in
    200|401)
        log "  v2 endpoint reachable (HTTP ${V2_CODE})"
        ;;
    *)
        skip "v2 OCI endpoint not reachable at ${HORT_URL}/v2/ (got HTTP ${V2_CODE})"
        ;;
esac

log "--- Preflight: probing upstream registries from inside the sidecar"
for u in "https://auth.docker.io/token" "https://ghcr.io/v2/"; do
    UP_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$u" 2>/dev/null || echo "000")
    if [ "$UP_CODE" = "000" ]; then
        skip "no outbound network from container to ${u}"
    fi
done
log "  upstream registries reachable"

# ---------------------------------------------------------------------
# Step 1: admin auth + repo UUID lookup.
# ---------------------------------------------------------------------
log ""
log "--- Step 1: Resolve OCI mirror repo UUID via admin lookup"

ADMIN_TOKEN="$(fetch_token admin admin)"
[ -n "$ADMIN_TOKEN" ] || fail "fetch admin token" "empty response from Keycloak"
log "  got admin token (${#ADMIN_TOKEN} chars)"

LOOKUP_TMP=$(mktemp)
LOOKUP_CODE=$(curl -sS -o "$LOOKUP_TMP" -w '%{http_code}' \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    "${HORT_URL}/api/v1/admin/repositories/${OCI_REPO_KEY}" 2>/dev/null || echo "000")
log "  GET /api/v1/admin/repositories/${OCI_REPO_KEY} -> HTTP ${LOOKUP_CODE}"
case "$LOOKUP_CODE" in
    200)
        REPO_ID=$(grep -o '"id":"[^"]*' "$LOOKUP_TMP" | cut -d'"' -f4)
        MANAGED_BY=$(grep -o '"managed_by":"[^"]*' "$LOOKUP_TMP" | cut -d'"' -f4)
        if [ -z "${REPO_ID:-}" ]; then
            cat "$LOOKUP_TMP"
            log ""
            fail "lookup response did not include an id field" ""
        else
            pass "repository resolved (id=${REPO_ID}, managed_by=${MANAGED_BY})"
        fi
        ;;
    404)
        cat "$LOOKUP_TMP"
        log ""
        fail "repo '${OCI_REPO_KEY}' not found" "is deploy/compose/example-config/repositories/oci-mirror-e2e.yaml mounted and the gitops apply succeeding?"
        ;;
    *)
        cat "$LOOKUP_TMP"
        log ""
        fail "lookup returned unexpected HTTP ${LOOKUP_CODE}" ""
        ;;
esac
rm -f "$LOOKUP_TMP"

# Abort early if the repo lookup failed — the pull steps are meaningless.
# (summary would exit 1 anyway, but this avoids misleading pull failures.)
if [ "$_FAIL" -gt 0 ]; then summary; fi

# ---------------------------------------------------------------------
# Step 2: wait for the resolver cache to pick up the gitops-applied
# upstream mappings.
# ---------------------------------------------------------------------
log ""
log "--- Step 2: Wait up to ${RESOLVER_REFRESH_GUESS}s for the resolver cache to pick up the gitops-applied mappings"
sleep "${RESOLVER_REFRESH_GUESS}"

# ---------------------------------------------------------------------
# Helper: read the current value of
# `hort_upstream_fetch_total{result="success"}` summed across all
# label combinations. Empty / no matching lines → 0.
#
# Implemented in one awk pass to avoid `grep | awk` pipefail bites:
# under `set -o pipefail`, grep returning 1 (no matches — the normal
# case BEFORE any pulls have happened) would abort the script via
# `set -e`. awk's regex match always exits 0; missing series → 0.
read_success_metric() {
    # `|| true` guards the curl half: a transient /metrics blip
    # shouldn't abort the test run. The empty input flows through
    # awk and prints 0.
    curl -sf "$METRICS_URL" 2>/dev/null \
        | awk '/^hort_upstream_fetch_total\{[^}]*result="success"[^}]*\}/ { s += $NF } END { printf "%d\n", (s+0) }' \
        || true
}

# ---------------------------------------------------------------------
# Step 3: first pull through each mapping (cache miss).
# ---------------------------------------------------------------------
log ""
log "--- Step 3: First pull through each mapping (cache miss)"

DOCKERHUB_REPO="${DOCKERHUB_IMAGE%%:*}"
DOCKERHUB_TAG="${DOCKERHUB_IMAGE##*:}"
case "$DOCKERHUB_REPO" in
    */*) DOCKERHUB_PATH="${DOCKERHUB_REPO}" ;;
    *)   DOCKERHUB_PATH="library/${DOCKERHUB_REPO}" ;;
esac
DOCKERHUB_REF="${REGISTRY_HOST}/${OCI_REPO_KEY}/dockerhub/${DOCKERHUB_PATH}:${DOCKERHUB_TAG}"
GHCR_REF="${REGISTRY_HOST}/${OCI_REPO_KEY}/ghcr/${GHCR_IMAGE#ghcr.io/}"

DOCKERHUB_ARCHIVE="/tmp/oci-mirror-dockerhub.tar"
GHCR_ARCHIVE="/tmp/oci-mirror-ghcr.tar"

skopeo_pull() {
    local src="$1" dest="$2"
    rm -f "$dest"
    skopeo copy \
        --insecure-policy \
        --src-tls-verify=false \
        "docker://${src}" \
        "oci-archive:${dest}"
}

METRIC_BEFORE=$(read_success_metric)
log "  hort_upstream_fetch_total{result=success} before = ${METRIC_BEFORE}"

if skopeo_pull "$DOCKERHUB_REF" "$DOCKERHUB_ARCHIVE"; then
    pass "first dockerhub pull-through succeeded"
else
    fail "first dockerhub pull-through failed" "network egress? upstream auth?"
fi

if skopeo_pull "$GHCR_REF" "$GHCR_ARCHIVE"; then
    pass "first ghcr pull-through succeeded"
else
    fail "first ghcr pull-through failed" "network egress? image still public?"
fi

# Abort if the pulls failed — the metric delta assertions are meaningless.
if [ "$_FAIL" -gt 0 ]; then summary; fi

METRIC_AFTER_FIRST=$(read_success_metric)
DELTA_FIRST=$((METRIC_AFTER_FIRST - METRIC_BEFORE))
log "  hort_upstream_fetch_total{result=success} after first pulls = ${METRIC_AFTER_FIRST} (Δ${DELTA_FIRST})"
if [ "$DELTA_FIRST" -ge 2 ]; then
    pass "upstream fetch fired on cache-miss pulls (Δ${DELTA_FIRST})"
else
    fail "expected ≥2 upstream-fetch successes on first pulls" "got Δ${DELTA_FIRST}"
fi

# ---------------------------------------------------------------------
# Step 4: second pull (cache-hit semantics).
#
# A second pull of the same tag should serve at least the manifest
# from local CAS. Assert "second-pull delta < first-pull delta" as
# the soft cache-hit signal.
# ---------------------------------------------------------------------
log ""
log "--- Step 4: Second pull of the dockerhub image (cache hit)"
if skopeo_pull "$DOCKERHUB_REF" "$DOCKERHUB_ARCHIVE"; then
    pass "second dockerhub pull succeeded"
else
    fail "second dockerhub pull failed" ""
fi

METRIC_AFTER_SECOND=$(read_success_metric)
DELTA_SECOND=$((METRIC_AFTER_SECOND - METRIC_AFTER_FIRST))
log "  hort_upstream_fetch_total{result=success} after second pull = ${METRIC_AFTER_SECOND} (Δ${DELTA_SECOND})"
if [ "$DELTA_SECOND" -lt "$DELTA_FIRST" ]; then
    pass "second pull served partly/fully from cache (Δ${DELTA_SECOND} < Δ${DELTA_FIRST})"
else
    fail "expected second-pull delta < first-pull delta" "got Δ${DELTA_SECOND} >= Δ${DELTA_FIRST}"
fi

rm -f "$DOCKERHUB_ARCHIVE" "$GHCR_ARCHIVE"

summary
