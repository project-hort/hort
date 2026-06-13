#!/usr/bin/env bash
# npm upstream pull-through verification smoke (happy path).
#
# Drives a real `npm install` through an npm Proxy repository in the
# stack, against a wiremock upstream that serves a synthesised packument
# + tarball. Exercises the full upstream-verification pipeline:
#   packument route → try_upstream_packument_pull → fetch packument →
#   parse_upstream_packument + extract dist.tarball + dist.integrity →
#   tarball route → fetch_artifact (absolute URL leg) →
#   IngestUseCase::ingest_verified (SHA-512 SRI verify) → CAS.
#
# Cache-hit semantics are verified via the
# `hort_upstream_checksum_total{format="npm",result="verified"}` metric
# (emitted by ingest_verified) before and after the install.
#
# Why a synthesised package (not real-world npm package): SHA-512 of
# real-world tarballs drift over time as registries re-tar; pinning a
# real npm package would make this script fragile. Item 8 (the design)
# specifically directs synthesising a package at deploy time so the
# packument-vs-tarball SHA-512 alignment is deterministic. The wiremock
# fixture under scripts/native-tests/fixtures/npm-upstream/ holds the
# synthesised tarball + matching packument with a pre-computed
# dist.integrity.
#
# Runs inside a `node:20-bookworm-slim` sidecar attached to the v2
# compose network. Not intended to be invoked directly from a host shell.
#
# Deferred: will become a scenarios/upstream/* scenario once the SSRF guard
# gains a test-only escape hatch; not currently run by the runner.
#
# Required infrastructure (see "Open dependencies" at the bottom):
#   1. v2 stack reachable on REGISTRY_URL (default: http://hort-server:8080).
#   2. An npm Proxy repository declared via gitops YAML
#      (deploy/compose/example-config/repositories/npm-upstream-e2e.yaml).
#   3. An UpstreamMapping declared via gitops YAML pointing at the
#      wiremock service hostname
#      (deploy/compose/example-config/upstreams/npm-upstream-e2e.yaml).
#   4. Wiremock running on the same compose network at
#      WIREMOCK_HAPPY_URL (default: http://wiremock-npm-upstream:8080),
#      with mappings + __files mounted from
#      scripts/native-tests/fixtures/npm-upstream/.
#   5. hort-formats::npm::extract_upstream_tarball_url enforces a
#      hard `https://` prefix on dist.tarball (crates/hort-formats/
#      src/npm.rs:273). Wiremock served over plain http:// will be
#      rejected before any fetch leg runs. Resolution options for an
#      executable harness:
#        - terminate TLS in front of wiremock with a self-signed cert
#          that hort-server's reqwest client trusts (extra_root_certificates)
#        - relax the prefix check behind a test-only cfg flag in
#          hort-formats::npm
#        - point at a publicly-routable https upstream (defeats the
#          tampered-bytes scenario in the sister script)
#      None of these can be wired without touching code; the script is
#      the design artifact and self-skips with a clear message when the
#      preconditions fail. Same posture as
#      test-pypi-upstream-verification.sh and test-cargo-upstream-verification.sh.
#   6. hort-adapters-upstream-http SSRF guard NOT blocking the wiremock
#      hostname. Compose bridge networks are RFC 1918 (172.x.x.x), which
#      the guard refuses for absolute artifact URLs (the tarball-leg URL
#      is absolute by necessity — registry.npmjs.org publishes tarballs
#      under the same host as the packument, but a mirror can place them
#      anywhere). Resolution options: same as the cargo/pypi scripts'
#      SSRF caveat — `network_mode: host`, an `HORT_UPSTREAM_DISABLE_SSRF=1`
#      flag, or a publicly-routable upstream.
#
# Env (defaults):
#   REGISTRY_URL          http://hort-server:8080
#   METRICS_URL           http://hort-server:9090/metrics
#   NPM_REPO_KEY          npm-upstream-e2e (mounted YAML at
#                         deploy/compose/example-config/repositories/npm-upstream-e2e.yaml)
#   WIREMOCK_HAPPY_URL    http://wiremock-npm-upstream:8080 (probe target)
#   PKG_NAME              tiny-helper (synthesised npm package name)
#   PKG_VERSION           1.0.0
#   KEYCLOAK_TOKEN_URL    http://keycloak:8080/realms/hort/protocol/openid-connect/token
#   KEYCLOAK_CLIENT_ID    hort-server
#   KEYCLOAK_CLIENT_SECRET hort-server-secret-dev-only
#   KEYCLOAK_USER         dev-user
#   KEYCLOAK_PASS         dev
#   KEYCLOAK_ADMIN_USER   admin
#   KEYCLOAK_ADMIN_PASS   admin

set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://hort-server:8080}"
METRICS_URL="${METRICS_URL:-http://hort-server:9090/metrics}"
NPM_REPO_KEY="${NPM_REPO_KEY:-npm-upstream-e2e}"
WIREMOCK_HAPPY_URL="${WIREMOCK_HAPPY_URL:-http://wiremock-npm-upstream:8080}"

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

echo "==> npm upstream pull-through verification smoke (happy path)"
echo "Registry:        ${REGISTRY_URL}"
echo "Metrics:         ${METRICS_URL}"
echo "Repo key:        ${NPM_REPO_KEY}"
echo "Wiremock:        ${WIREMOCK_HAPPY_URL}"
echo "Package:         ${PKG_NAME} ${PKG_VERSION}"

# ---------------------------------------------------------------------
# Tool prereqs — install missing deps quietly. node:*-slim images ship
# with node+npm but no curl/python3 by default.
# ---------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl python3 ca-certificates >/dev/null 2>&1 || true
fi
command -v node >/dev/null 2>&1 || { echo "FAIL: node missing in image" >&2; exit 1; }
command -v npm  >/dev/null 2>&1 || { echo "FAIL: npm missing in image"  >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "FAIL: curl missing — cannot run preflight"; exit 1; }

# ---------------------------------------------------------------------
# Preflight 1: probe v2 endpoint. 401 on /admin/ counts as reachable.
# ---------------------------------------------------------------------
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

# ---------------------------------------------------------------------
# Preflight 2: probe the wiremock upstream. The packument endpoint is
# the cleanest probe: registry.npmjs.org always serves /{name} and the
# wiremock mapping reproduces that contract.
# ---------------------------------------------------------------------
echo "--- Preflight: probing wiremock ${WIREMOCK_HAPPY_URL}/${PKG_NAME}"
WIRE_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${WIREMOCK_HAPPY_URL}/${PKG_NAME}" 2>/dev/null || echo "000")
if [ "$WIRE_CODE" != "200" ]; then
    skip "wiremock upstream not reachable at ${WIREMOCK_HAPPY_URL}/${PKG_NAME} (got HTTP ${WIRE_CODE}). Bring up wiremock-npm-upstream from the test stack."
fi
echo "  wiremock reachable (HTTP 200)"

# ---------------------------------------------------------------------
# Step 1: admin token + repo lookup. Mirrors
# test-pypi-upstream-verification.sh:166-202. The repo is gitops-
# managed; this lookup is a sanity check that it's been declared.
# ---------------------------------------------------------------------
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
        MANAGED_BY=$(python3 -c "import sys, json; print(json.loads(open(sys.argv[1]).read())['managed_by'])" "$LOOKUP_TMP")
        pass "repository resolved (id=${REPO_ID}, managed_by=${MANAGED_BY})"
        ;;
    404)
        cat "$LOOKUP_TMP"
        echo ""
        skip "repo '${NPM_REPO_KEY}' not found — declare it in deploy/compose/example-config/repositories/${NPM_REPO_KEY}.yaml as an npm Proxy + UpstreamMapping pointing at ${WIREMOCK_HAPPY_URL}"
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
# Helper: read the current value of
# `hort_upstream_checksum_total{format="npm",result="verified"}` summed
# across all label combinations. Implemented in one awk pass to avoid
# `grep | awk` pipefail bites (no matches → grep exits 1 → set -o
# pipefail aborts under set -e; awk's regex match always exits 0).
# ---------------------------------------------------------------------
read_verified_metric() {
    curl -sf "$METRICS_URL" 2>/dev/null \
        | awk '/^hort_upstream_checksum_total\{[^}]*format="npm"[^}]*result="verified"[^}]*\}/ { s += $NF } END { printf "%d\n", (s+0) }' \
        || true
}

METRIC_BEFORE=$(read_verified_metric)
echo "  hort_upstream_checksum_total{format=npm,result=verified} before = ${METRIC_BEFORE}"

# ---------------------------------------------------------------------
# Step 2: dev-user token (npm registry auth via _authToken). The
# stack accepts Bearer tokens on the packument + tarball routes
# (same auth shape as all proxy formats; mirrors test-npm.sh:108).
# ---------------------------------------------------------------------
echo ""
echo "--- Step 2: dev-user token + npm install attempt against happy upstream"

DEV_TOKEN_BODY=$(curl -sf -X POST "$KEYCLOAK_TOKEN_URL" \
    -d grant_type=password \
    -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    -d "username=${KEYCLOAK_USER}" \
    -d "password=${KEYCLOAK_PASS}") || skip "Keycloak token endpoint not reachable for dev-user"
DEV_TOKEN=$(printf '%s' "$DEV_TOKEN_BODY" | python3 -c "import sys, json; print(json.loads(sys.stdin.read())['access_token'])")
[ -n "$DEV_TOKEN" ] || { echo "FAIL: empty dev-user access_token"; exit 1; }
echo "  got dev-user token (${#DEV_TOKEN} chars)"

# ---------------------------------------------------------------------
# Step 3: configure npm + install ${PKG_NAME}@${PKG_VERSION}.
# A scratch project + scratch HOME isolates this run from any prior
# state (npm caches packuments + tarballs aggressively under
# ~/.npm; without the override an earlier run could short-circuit
# the upstream pull and the verify metric would fail to tick).
# ---------------------------------------------------------------------
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"

NPM_REGISTRY_URL="${REGISTRY_URL}/npm/${NPM_REPO_KEY}/"
NPM_HOST_PATH="${NPM_REGISTRY_URL#http*://}"
echo ""
echo "--- Step 3: npm install ${PKG_NAME}@${PKG_VERSION} via ${NPM_REGISTRY_URL}"

# Scratch HOME so `npm config set` writes a per-run .npmrc (avoids
# polluting the sidecar's user config and keeps pre-existing
# _authToken values from leaking in).
export HOME="$WORK_DIR/home"
mkdir -p "$HOME"

# Scratch cache so a prior cached packument doesn't short-circuit
# the upstream pull (npm won't re-fetch a packument it already has).
export npm_config_cache="$WORK_DIR/npm-cache"

# Mirror test-npm.sh:104-108: clear any legacy Basic auth, then set
# bearer-form _authToken which produces `Authorization: Bearer ...`.
npm config set registry "$NPM_REGISTRY_URL"
npm config delete "//${NPM_HOST_PATH}:_auth" 2>/dev/null || true
npm config delete "//${NPM_HOST_PATH}:_password" 2>/dev/null || true
npm config delete "//${NPM_HOST_PATH}:username" 2>/dev/null || true
npm config set "//${NPM_HOST_PATH}:_authToken" "$DEV_TOKEN"

mkdir -p "$WORK_DIR/consumer"
cd "$WORK_DIR/consumer"
# init -y is silent and creates a minimal package.json; needed so
# `npm install` writes node_modules/<pkg> at $CWD instead of refusing.
npm init -y >/dev/null 2>&1

if npm install --no-audit --no-fund --prefer-online "${PKG_NAME}@${PKG_VERSION}"; then
    pass "npm install ${PKG_NAME}@${PKG_VERSION} via ${NPM_REPO_KEY} succeeded"
else
    fail "npm install failed — registry packument proxy or upstream-pull misconfigured"
fi
[ "$FAILURES" -gt 0 ] && exit 1

# Verify the installed package is structurally sound. Resolving the
# package's main module via `node -e "require('<pkg>/package.json')"`
# confirms the tarball's bytes were extracted correctly (npm's tar
# extractor would have errored otherwise).
INSTALLED_VERSION=$(node -e "process.stdout.write(require('${PKG_NAME}/package.json').version)" 2>/dev/null || true)
if [ "$INSTALLED_VERSION" = "${PKG_VERSION}" ]; then
    pass "node require('${PKG_NAME}/package.json').version reports ${INSTALLED_VERSION}"
else
    fail "require('${PKG_NAME}/package.json').version reported '${INSTALLED_VERSION}' (expected ${PKG_VERSION})"
fi
[ "$FAILURES" -gt 0 ] && exit 1

# ---------------------------------------------------------------------
# Step 4: verify the verification metric ticked. The verified-ingest
# emission is in IngestUseCase::ingest_verified — if the orchestrator
# took the upstream-pull path AND SHA-512 SRI verification passed,
# this counter went up by exactly 1 (per tarball downloaded; with no
# transitive deps in the synthesised package we only fetched one).
# ---------------------------------------------------------------------
METRIC_AFTER=$(read_verified_metric)
DELTA=$((METRIC_AFTER - METRIC_BEFORE))
echo ""
echo "  hort_upstream_checksum_total{format=npm,result=verified} after = ${METRIC_AFTER} (Δ${DELTA})"
if [ "$DELTA" -ge 1 ]; then
    pass "upstream verification fired and verified the tarball body via SHA-512 SRI (Δ${DELTA})"
else
    fail "expected ≥1 verified upstream-checksum tick after first download, got Δ${DELTA}. Either the install hit a local CAS (test-data leak from a prior run) or the orchestrator did not take the upstream-pull path."
fi

if [ "$FAILURES" -gt 0 ]; then
    echo ""
    echo "==> ${FAILURES} failure(s)"
    exit 1
fi
echo ""
echo "==> OK"
