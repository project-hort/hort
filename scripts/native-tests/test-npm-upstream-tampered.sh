#!/usr/bin/env bash
# npm upstream pull-through tampering smoke (failure path).
#
# Sister script to test-npm-upstream-verification.sh. Same gitops
# config + same wiremock fixture set, but the wiremock instance serves
# a tampered ${PKG_NAME}-${PKG_VERSION}.tgz (bytes flipped after the
# packument is generated) while the packument JSON still advertises
# the *original* dist.integrity (sha512-...).
# The orchestrator must detect the SHA-512 mismatch during streaming
# verify, refuse to write to CAS, return 502 + X-AK-Reason:
# upstream-checksum-mismatch to npm, and emit ChecksumMismatch in
# hort-server logs.
#
# Verification surface (three layers, all must agree):
#   1. npm install exits non-zero (the tarball fetch fails).
#   2. hort_upstream_checksum_total{format=npm,result=mismatch}
#      increments by ≥ 1.
#   3. hort-server logs contain "ChecksumMismatch" within ~30s of the
#      install attempt.
#
# Runs inside a `node:20-bookworm-slim` sidecar attached to the v2
# compose network (see test-npm-upstream-verification.sh's header for
# the full infrastructure dependency list, including the SHA-512 SRI +
# https-prefix-required + SSRF caveats).
#
# Open dependencies (same as the happy-path script):
#   - Gitops YAML at deploy/compose/example-config/{repositories,upstreams}/
#     declaring `npm-upstream-tampered-e2e` as an npm Proxy pointing
#     at WIREMOCK_TAMPERED_URL. Different repo key from the happy path
#     so both can run in the same harness without colliding on the
#     repository_upstream_mappings (repo_id, path_prefix=NULL) row.
#   - Wiremock instance (wiremock-npm-tampered) on the v2 compose
#     network with mappings + __files mounted from
#     scripts/native-tests/fixtures/npm-upstream-tampered/.
#   - HTTPS-prefix + SSRF caveat — see the verification script's header.

set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://hort-server:8080}"
METRICS_URL="${METRICS_URL:-http://hort-server:9090/metrics}"
NPM_REPO_KEY="${NPM_REPO_KEY:-npm-upstream-tampered-e2e}"
WIREMOCK_TAMPERED_URL="${WIREMOCK_TAMPERED_URL:-http://wiremock-npm-tampered:8080}"
HORT_CONTAINER="${HORT_CONTAINER:-hort-hort-server-1}"

KEYCLOAK_TOKEN_URL="${KEYCLOAK_TOKEN_URL:-http://keycloak:8080/realms/hort/protocol/openid-connect/token}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-hort-server}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-hort-server-secret-dev-only}"
KEYCLOAK_USER="${KEYCLOAK_USER:-dev-user}"
KEYCLOAK_PASS="${KEYCLOAK_PASS:-dev}"
KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
KEYCLOAK_ADMIN_PASS="${KEYCLOAK_ADMIN_PASS:-admin}"

PKG_NAME="${PKG_NAME:-tiny-helper}"
PKG_VERSION="${PKG_VERSION:-1.0.0}"

FAILURES=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILURES=$((FAILURES + 1)); }
skip() { echo "SKIP: $1"; exit 0; }

echo "==> npm upstream tampering smoke (failure path)"
echo "Registry:        ${REGISTRY_URL}"
echo "Metrics:         ${METRICS_URL}"
echo "Repo key:        ${NPM_REPO_KEY}"
echo "Wiremock:        ${WIREMOCK_TAMPERED_URL}"
echo "Package:         ${PKG_NAME} ${PKG_VERSION} (tampered tarball body)"

if ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl python3 ca-certificates >/dev/null 2>&1 || true
fi
command -v node >/dev/null 2>&1 || { echo "FAIL: node missing in image" >&2; exit 1; }
command -v npm  >/dev/null 2>&1 || { echo "FAIL: npm missing in image"  >&2; exit 1; }

echo ""
echo "--- Preflight: probing ${REGISTRY_URL}/health"
HEALTH_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${REGISTRY_URL}/health" 2>/dev/null || echo "000")
case "$HEALTH_CODE" in
    200|401|404)
        echo "  v2 endpoint reachable (HTTP ${HEALTH_CODE})"
        ;;
    *)
        skip "v2 endpoint not reachable at ${REGISTRY_URL}/health (got HTTP ${HEALTH_CODE})"
        ;;
esac

echo "--- Preflight: probing tampered wiremock ${WIREMOCK_TAMPERED_URL}/${PKG_NAME}"
WIRE_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${WIREMOCK_TAMPERED_URL}/${PKG_NAME}" 2>/dev/null || echo "000")
if [ "$WIRE_CODE" != "200" ]; then
    skip "tampered wiremock not reachable at ${WIREMOCK_TAMPERED_URL}/${PKG_NAME} (got HTTP ${WIRE_CODE}). Bring up wiremock-npm-tampered from the test stack."
fi
echo "  tampered wiremock reachable (HTTP 200)"

echo ""
echo "--- Step 1: Resolve npm proxy repo UUID via admin lookup"

ADMIN_TOKEN_BODY=$(curl -sf -X POST "$KEYCLOAK_TOKEN_URL" \
    -d grant_type=password \
    -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    -d "username=${KEYCLOAK_ADMIN_USER}" \
    -d "password=${KEYCLOAK_ADMIN_PASS}") || skip "Keycloak token endpoint not reachable"
ADMIN_TOKEN=$(printf '%s' "$ADMIN_TOKEN_BODY" | python3 -c "import sys, json; print(json.loads(sys.stdin.read())['access_token'])")
[ -n "$ADMIN_TOKEN" ] || { echo "FAIL: empty admin access_token from Keycloak"; exit 1; }
echo "  got admin token (${#ADMIN_TOKEN} chars)"

LOOKUP_TMP=$(mktemp)
LOOKUP_CODE=$(curl -sS -o "$LOOKUP_TMP" -w '%{http_code}' \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    "${REGISTRY_URL}/api/v1/admin/repositories/${NPM_REPO_KEY}" || echo "000")
echo "  GET /api/v1/admin/repositories/${NPM_REPO_KEY} -> HTTP ${LOOKUP_CODE}"
case "$LOOKUP_CODE" in
    200)
        REPO_ID=$(python3 -c "import sys, json; print(json.loads(open(sys.argv[1]).read())['id'])" "$LOOKUP_TMP")
        pass "tampered-repo resolved (id=${REPO_ID})"
        ;;
    404)
        cat "$LOOKUP_TMP"
        echo ""
        skip "repo '${NPM_REPO_KEY}' not found — declare it in deploy/compose/example-config/repositories/${NPM_REPO_KEY}.yaml as an npm Proxy + UpstreamMapping pointing at ${WIREMOCK_TAMPERED_URL}"
        ;;
    *)
        cat "$LOOKUP_TMP"
        echo ""
        fail "lookup returned unexpected HTTP ${LOOKUP_CODE}"
        ;;
esac
rm -f "$LOOKUP_TMP"
[ "$FAILURES" -gt 0 ] && exit 1

# ---------------------------------------------------------------------
# Helper: read mismatch metric (emitted by
# IngestUseCase::ingest_verified on integrity-vs-stream-hash divergence).
# Same awk-only shape as the verification script to dodge pipefail
# under set -e when the metric series is missing pre-test.
# ---------------------------------------------------------------------
read_mismatch_metric() {
    curl -sf "$METRICS_URL" 2>/dev/null \
        | awk '/^hort_upstream_checksum_total\{[^}]*format="npm"[^}]*result="mismatch"[^}]*\}/ { s += $NF } END { printf "%d\n", (s+0) }' \
        || true
}

METRIC_BEFORE=$(read_mismatch_metric)
echo "  hort_upstream_checksum_total{format=npm,result=mismatch} before = ${METRIC_BEFORE}"

echo ""
echo "--- Step 2: dev-user token + npm install attempt against tampered upstream"

DEV_TOKEN_BODY=$(curl -sf -X POST "$KEYCLOAK_TOKEN_URL" \
    -d grant_type=password \
    -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    -d "username=${KEYCLOAK_USER}" \
    -d "password=${KEYCLOAK_PASS}") || skip "Keycloak token endpoint not reachable for dev-user"
DEV_TOKEN=$(printf '%s' "$DEV_TOKEN_BODY" | python3 -c "import sys, json; print(json.loads(sys.stdin.read())['access_token'])")
[ -n "$DEV_TOKEN" ] || { echo "FAIL: empty dev-user access_token"; exit 1; }

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"

NPM_REGISTRY_URL="${REGISTRY_URL}/npm/${NPM_REPO_KEY}/"
NPM_HOST_PATH="${NPM_REGISTRY_URL#http*://}"

# Scratch HOME + cache so a prior cached packument/tarball doesn't
# short-circuit the upstream pull (without these, npm could complete
# the install from cache and the mismatch metric would not tick).
export HOME="$WORK_DIR/home"
mkdir -p "$HOME"
export npm_config_cache="$WORK_DIR/npm-cache"

npm config set registry "$NPM_REGISTRY_URL"
npm config delete "//${NPM_HOST_PATH}:_auth" 2>/dev/null || true
npm config delete "//${NPM_HOST_PATH}:_password" 2>/dev/null || true
npm config delete "//${NPM_HOST_PATH}:username" 2>/dev/null || true
npm config set "//${NPM_HOST_PATH}:_authToken" "$DEV_TOKEN"

mkdir -p "$WORK_DIR/consumer"
cd "$WORK_DIR/consumer"
npm init -y >/dev/null 2>&1

echo ""
echo "--- Running: npm install ${PKG_NAME}@${PKG_VERSION} (must FAIL because upstream bytes are tampered)"

# Capture npm's stderr — we want to surface the failure mode but
# we EXPECT a non-zero exit, so don't propagate that to set -e.
NPM_STDERR="$WORK_DIR/npm.stderr"
set +e
npm install --no-audit --no-fund --prefer-online "${PKG_NAME}@${PKG_VERSION}" \
    >"$WORK_DIR/npm.stdout" 2>"$NPM_STDERR"
NPM_EXIT=$?
set -e

echo "  npm install exit code: ${NPM_EXIT}"
if [ "$NPM_EXIT" -eq 0 ]; then
    fail "npm install SUCCEEDED against tampered upstream — verification gate failed to fire"
    echo "  --- npm stdout ---"
    sed 's/^/    /' "$WORK_DIR/npm.stdout"
    echo "  --- npm stderr ---"
    sed 's/^/    /' "$NPM_STDERR"
else
    pass "npm install failed as expected (exit=${NPM_EXIT})"
fi

# ---------------------------------------------------------------------
# Step 3: assert the mismatch metric ticked. The orchestrator's wire-
# map sends 502 + X-AK-Reason: upstream-checksum-mismatch to npm on
# ChecksumMismatch (mirrors the cargo/pypi UpstreamPullError mapping
# in the per-format upstream_pull.rs); the 502 is what makes npm
# install fail above. The metric is the definitive witness — without
# a tick, npm could be failing for unrelated reasons (network blip,
# registry handler bug, packument 404 etc.).
# ---------------------------------------------------------------------
echo ""
echo "--- Step 3: verifying mismatch metric"
METRIC_AFTER=$(read_mismatch_metric)
DELTA=$((METRIC_AFTER - METRIC_BEFORE))
echo "  hort_upstream_checksum_total{format=npm,result=mismatch} after = ${METRIC_AFTER} (Δ${DELTA})"
if [ "$DELTA" -ge 1 ]; then
    pass "upstream verification gate detected the tampered bytes (Δ${DELTA})"
else
    fail "expected ≥1 mismatch metric tick after tampered fetch, got Δ${DELTA}. The tarball body may have been served by local CAS instead of going through upstream pull."
fi

# ---------------------------------------------------------------------
# Step 4: assert hort-server logs contain "ChecksumMismatch". This is
# the audit-trail witness — even if the metric ticked, an operator
# investigating a supply-chain alert should be able to grep the logs
# and find the structured event. Item 8 in the backlog explicitly
# requires "algorithm=Sha512" in the structured event; we grep for
# the event-type string here and rely on the structured logger
# (tracing JSON) to carry the algorithm field.
#
# Reaching the host docker daemon from inside the sidecar requires
# /var/run/docker.sock mounted in. If it isn't, soft-skip this leg —
# the metric assertion above already proves the gate fired.
# ---------------------------------------------------------------------
echo ""
echo "--- Step 4: scanning hort-server logs for ChecksumMismatch"
if [ -S /var/run/docker.sock ] && command -v docker >/dev/null 2>&1; then
    if docker logs "$HORT_CONTAINER" --since 2m 2>&1 | grep -q "ChecksumMismatch"; then
        pass "hort-server logs contain ChecksumMismatch (audit-trail witness)"
    else
        fail "hort-server logs do not contain ChecksumMismatch since the install attempt"
        echo "  --- last 60 lines of hort-server logs ---"
        docker logs "$HORT_CONTAINER" --tail 60 2>&1 | sed 's/^/    /' || true
    fi
else
    echo "  /var/run/docker.sock not mounted in sidecar — skipping log assertion (metric assertion in Step 3 is the binding witness)"
fi

if [ "$FAILURES" -gt 0 ]; then
    echo ""
    echo "==> ${FAILURES} failure(s)"
    exit 1
fi
echo ""
echo "==> OK"
