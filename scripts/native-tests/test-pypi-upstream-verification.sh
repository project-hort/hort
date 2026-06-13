#!/usr/bin/env bash
# PyPI upstream pull-through verification smoke (happy path).
#
# Drives a real `pip install` through a PyPI Proxy repository in the
# stack, against a wiremock upstream that serves real pypi.org +
# files.pythonhosted.org fixtures (requests 2.31.0). Exercises the
# full upstream-verification pipeline:
#   simple-index proxy → URL rewrite from files.pythonhosted.org to
#   /pypi/{repo_key}/simple/... → file route → try_upstream_file_pull
#   → fetch per-version JSON (/pypi/requests/2.31.0/json) →
#   parse_upstream_checksum + extract absolute file URL →
#   fetch_artifact (absolute URL leg) →
#   IngestUseCase::ingest_verified → CAS.
#
# Cache-hit semantics are verified via the
# `hort_upstream_checksum_total{format="pypi",result="verified"}` metric
# (emitted by ingest_verified) before and after the install.
#
# Why pip install (not pip download): pip install exercises the same
# /simple/ + file-fetch pipeline AND additionally validates the wheel
# is structurally sound. requests 2.31.0 has transitive deps
# (charset-normalizer, idna, urllib3, certifi); to keep the verify-
# leg deterministic we use --no-deps so only the requests wheel/sdist
# fetch is checksummed. The Δ assertion (≥1) tolerates either a wheel
# or sdist install path, since pip's choice depends on the Python
# interpreter version in the sidecar image.
#
# Dual-host PyPI vs single-host Cargo: PyPI publishes the simple index
# on pypi.org but the actual files on files.pythonhosted.org. The
# orchestrator's file leg fetches via an ABSOLUTE URL (extracted from
# the per-version JSON's `urls[].url`), not via a path appended to the
# upstream-mapping base. The fixture's JSON body has its `urls[].url`
# values pre-rewritten to point at the wiremock host (the same way
# Cargo's config.json `dl` field is rewritten) so a single wiremock
# instance can stand in for both pypi.org and files.pythonhosted.org.
# The simple-index HTML keeps the original files.pythonhosted.org URLs
# verbatim — the simple-index proxy rewrites them to local
# /pypi/{repo_key}/simple/... paths before serving to pip, so pip
# never tries to GET files.pythonhosted.org directly.
#
# Runs inside a `python:3.12-slim-bookworm` sidecar attached to the v2
# compose network. Not intended to be invoked directly from a host shell.
#
# Deferred: will become a scenarios/upstream/* scenario once the SSRF guard
# gains a test-only escape hatch; not currently run by the runner.
#
# Required infrastructure (see "Open dependencies" at the bottom):
#   1. v2 stack reachable on REGISTRY_URL (default: http://hort-server:8080).
#   2. A PyPI Proxy repository declared via gitops YAML
#      (deploy/compose/example-config/repositories/pypi-upstream-e2e.yaml).
#   3. An UpstreamMapping declared via gitops YAML pointing at the
#      wiremock service hostname
#      (deploy/compose/example-config/upstreams/pypi-upstream-e2e.yaml).
#   4. Wiremock running on the same compose network at
#      WIREMOCK_HAPPY_URL (default: http://wiremock-pypi-upstream:8080),
#      with mappings + __files mounted from
#      scripts/native-tests/fixtures/pypi-upstream/.
#   5. hort-adapters-upstream-http SSRF guard NOT blocking the wiremock
#      hostname. Compose bridge networks are RFC 1918 (172.x.x.x), which
#      the guard refuses for absolute artifact URLs (the file-leg URL
#      is absolute by necessity — files.pythonhosted.org is a different
#      host from pypi.org). Resolution options:
#        - run wiremock under `network_mode: host` on a routable IP
#        - add a runtime HORT_UPSTREAM_DISABLE_SSRF=1 flag to the adapter
#          (gated to test-only deployments)
#        - run the test against a publicly-routable upstream (defeats
#          the tampered-bytes scenario)
#      None of these can be wired without touching code; the script is
#      the design artifact and self-skips with a clear message when the
#      preconditions fail.
#
# Env (defaults):
#   REGISTRY_URL          http://hort-server:8080
#   METRICS_URL           http://hort-server:9090/metrics
#   PYPI_REPO_KEY         pypi-upstream-e2e (mounted YAML at
#                         deploy/compose/example-config/repositories/pypi-upstream-e2e.yaml)
#   WIREMOCK_HAPPY_URL    http://wiremock-pypi-upstream:8080 (probe target)
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
PYPI_REPO_KEY="${PYPI_REPO_KEY:-pypi-upstream-e2e}"
WIREMOCK_HAPPY_URL="${WIREMOCK_HAPPY_URL:-http://wiremock-pypi-upstream:8080}"

KEYCLOAK_TOKEN_URL="${KEYCLOAK_TOKEN_URL:-http://keycloak:8080/realms/hort/protocol/openid-connect/token}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-hort-server}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-hort-server-secret-dev-only}"
KEYCLOAK_USER="${KEYCLOAK_USER:-dev-user}"
KEYCLOAK_PASS="${KEYCLOAK_PASS:-dev}"
KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
KEYCLOAK_ADMIN_PASS="${KEYCLOAK_ADMIN_PASS:-admin}"

PKG_NAME="requests"
PKG_VERSION="2.31.0"
PKG_WHEEL_SHA256="58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"
PKG_SDIST_SHA256="942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1"

FAILURES=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILURES=$((FAILURES + 1)); }
skip() { echo "SKIP: $1"; exit 0; }

echo "==> PyPI upstream pull-through verification smoke (happy path)"
echo "Registry:        ${REGISTRY_URL}"
echo "Metrics:         ${METRICS_URL}"
echo "Repo key:        ${PYPI_REPO_KEY}"
echo "Wiremock:        ${WIREMOCK_HAPPY_URL}"
echo "Package:         ${PKG_NAME} ${PKG_VERSION}"
echo "Wheel sha256:    ${PKG_WHEEL_SHA256}"
echo "Sdist sha256:    ${PKG_SDIST_SHA256}"

# ---------------------------------------------------------------------
# Tool prereqs — install missing deps quietly. python:*-slim images ship
# with python3+pip but no curl by default.
# ---------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null 2>&1 || true
fi
command -v python3 >/dev/null 2>&1 || { echo "FAIL: python3 missing in image" >&2; exit 1; }
command -v pip3    >/dev/null 2>&1 || { echo "FAIL: pip3 missing in image"    >&2; exit 1; }
command -v curl    >/dev/null 2>&1 || { echo "FAIL: curl missing — cannot run preflight"; exit 1; }

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
# Preflight 2: probe the wiremock upstream. If the wiremock sidecar
# isn't up the test cannot run — skip rather than fail (this script
# self-skips like test-cargo-upstream-verification.sh when its
# preconditions are not met). The simple-index endpoint is the cleanest
# probe: pypi.org always serves /simple/{name}/ and the wiremock mapping
# 01-simple-index.json reproduces that contract.
# ---------------------------------------------------------------------
echo "--- Preflight: probing wiremock ${WIREMOCK_HAPPY_URL}/simple/requests/"
WIRE_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${WIREMOCK_HAPPY_URL}/simple/requests/" 2>/dev/null || echo "000")
if [ "$WIRE_CODE" != "200" ]; then
    skip "wiremock upstream not reachable at ${WIREMOCK_HAPPY_URL}/simple/requests/ (got HTTP ${WIRE_CODE}). Bring up wiremock-pypi-upstream from the test stack."
fi
echo "  wiremock reachable (HTTP 200)"

# ---------------------------------------------------------------------
# Step 1: admin token + repo lookup. Mirrors
# test-cargo-upstream-verification.sh:139-176. The repo is gitops-
# managed; this lookup is a sanity check that it's been declared.
# ---------------------------------------------------------------------
echo ""
echo "--- Step 1: Resolve pypi proxy repo UUID via admin lookup"

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
    "${REGISTRY_URL}/api/v1/admin/repositories/${PYPI_REPO_KEY}" || echo "000")
echo "  GET /api/v1/admin/repositories/${PYPI_REPO_KEY} -> HTTP ${LOOKUP_CODE}"
case "$LOOKUP_CODE" in
    200)
        REPO_ID=$(python3 -c "import sys, json; print(json.loads(open(sys.argv[1]).read())['id'])" "$LOOKUP_TMP")
        MANAGED_BY=$(python3 -c "import sys, json; print(json.loads(open(sys.argv[1]).read())['managed_by'])" "$LOOKUP_TMP")
        pass "repository resolved (id=${REPO_ID}, managed_by=${MANAGED_BY})"
        ;;
    404)
        cat "$LOOKUP_TMP"
        echo ""
        skip "repo '${PYPI_REPO_KEY}' not found — declare it in deploy/compose/example-config/repositories/${PYPI_REPO_KEY}.yaml as a PyPI Proxy + UpstreamMapping pointing at ${WIREMOCK_HAPPY_URL}"
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
# `hort_upstream_checksum_total{format="pypi",result="verified"}` summed
# across all label combinations. Implemented in one awk pass to avoid
# `grep | awk` pipefail bites (no matches → grep exits 1 → set -o
# pipefail aborts under set -e; awk's regex match always exits 0).
# ---------------------------------------------------------------------
read_verified_metric() {
    curl -sf "$METRICS_URL" 2>/dev/null \
        | awk '/^hort_upstream_checksum_total\{[^}]*format="pypi"[^}]*result="verified"[^}]*\}/ { s += $NF } END { printf "%d\n", (s+0) }' \
        || true
}

METRIC_BEFORE=$(read_verified_metric)
echo "  hort_upstream_checksum_total{format=pypi,result=verified} before = ${METRIC_BEFORE}"

# ---------------------------------------------------------------------
# Step 2: dev-user token (pip auth via --index-url with userinfo). The
# stack accepts Bearer tokens on the simple-index + file routes
# (same auth shape across all proxy formats).
# ---------------------------------------------------------------------
echo ""
echo "--- Step 2: dev-user token + pip install attempt against happy upstream"

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
# Step 3: configure pip + install requests==2.31.0 with --no-deps so the
# verify metric tick count stays deterministic (one request fetch, no
# transitive charset-normalizer/idna/urllib3/certifi traffic).
#
# Pip's --index-url accepts userinfo-encoded auth. hort-server's auth
# middleware also accepts Bearer tokens via the Authorization header,
# but pip doesn't forward that on its own; the userinfo form is the
# canonical pip-friendly shape (matches test-pypi.sh's twine config).
# ---------------------------------------------------------------------
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"

PYPI_INDEX_URL="${REGISTRY_URL}/pypi/${PYPI_REPO_KEY}/simple/"
echo ""
echo "--- Step 3: pip install ${PKG_NAME}==${PKG_VERSION} via ${PYPI_INDEX_URL}"

# Isolated install tree — no global site-packages pollution between
# script runs. Don't bother with a venv (extra prereq); --target gives
# us the same isolation with one flag.
INSTALL_TARGET="$WORK_DIR/site"
mkdir -p "$INSTALL_TARGET"

# Use a scratch pip cache too so a prior cached requests doesn't
# short-circuit the upstream pull (pip won't hit the index for a
# package already in its HTTP cache).
export PIP_CACHE_DIR="$WORK_DIR/pip-cache"

# No `|| echo` masking — pipefail surfaces real failures (CLAUDE.md
# memory feedback_tdd_enforcement.md). Send the bearer via the
# PIP_INDEX_URL_AUTHORIZATION extra-args form which pip supports via
# the keyring/netrc layer; for direct simplicity we encode the token
# in the URL as the userinfo. The bearer-as-password form works
# because the PyPI handler accepts Basic auth where username is
# unused and password is the bearer token.
PYPI_INDEX_URL_WITH_AUTH="${REGISTRY_URL/http:\/\//http://__token__:${DEV_TOKEN}@}/pypi/${PYPI_REPO_KEY}/simple/"

if pip3 install \
    --no-deps \
    --target "$INSTALL_TARGET" \
    --index-url "$PYPI_INDEX_URL_WITH_AUTH" \
    --no-cache-dir \
    --disable-pip-version-check \
    "${PKG_NAME}==${PKG_VERSION}"; then
    pass "pip install ${PKG_NAME}==${PKG_VERSION} via ${PYPI_REPO_KEY} succeeded"
else
    fail "pip install failed — registry simple-index proxy or upstream-pull misconfigured"
fi
[ "$FAILURES" -gt 0 ] && exit 1

# Verify the installed package is structurally usable. Importing
# requests confirms the wheel's bytes match what Python expects (the
# unzip wouldn't succeed otherwise).
PYTHONPATH="$INSTALL_TARGET" python3 -c "import requests; print(requests.__version__)" \
    > "$WORK_DIR/import.out" 2> "$WORK_DIR/import.err" || true
INSTALLED_VERSION="$(cat "$WORK_DIR/import.out" || true)"
if [ "$INSTALLED_VERSION" = "${PKG_VERSION}" ]; then
    pass "import requests reports ${INSTALLED_VERSION}"
else
    fail "import requests reported '${INSTALLED_VERSION}' (expected ${PKG_VERSION}); err: $(cat "$WORK_DIR/import.err" || true)"
fi
[ "$FAILURES" -gt 0 ] && exit 1

# ---------------------------------------------------------------------
# Step 4: verify the verification metric ticked. The verified-ingest
# emission is in IngestUseCase::ingest_verified — if the orchestrator
# took the upstream-pull path AND verification passed, this counter
# went up by exactly 1 (per file downloaded; --no-deps means we only
# fetched one wheel/sdist for requests itself).
# ---------------------------------------------------------------------
METRIC_AFTER=$(read_verified_metric)
DELTA=$((METRIC_AFTER - METRIC_BEFORE))
echo ""
echo "  hort_upstream_checksum_total{format=pypi,result=verified} after = ${METRIC_AFTER} (Δ${DELTA})"
if [ "$DELTA" -ge 1 ]; then
    pass "upstream verification fired and verified the wheel/sdist body (Δ${DELTA})"
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
