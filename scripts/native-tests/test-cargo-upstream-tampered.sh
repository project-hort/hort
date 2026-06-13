#!/usr/bin/env bash
# Cargo upstream pull-through tampering smoke (failure path).
#
# Sister script to test-cargo-upstream-verification.sh. Same gitops
# config + same wiremock fixture set, but the wiremock instance serves
# a tampered cfg-if-1.0.0.crate (one byte flipped in the middle) while
# the NDJSON index still reports the *original* cksum
# (baf1de43...0fd). The orchestrator must detect the SHA-256 mismatch
# during streaming verify, refuse to write to CAS, return 502 to cargo,
# and emit ChecksumMismatch in hort-server logs.
#
# Verification surface (three layers, all must agree):
#   1. cargo build exits non-zero (the .crate fetch fails).
#   2. hort_upstream_checksum_total{format=cargo,result=mismatch}
#      increments by ≥ 1.
#   3. hort-server logs contain "ChecksumMismatch" within ~30s of the
#      build attempt.
#
# Runs inside a `rust:1.88-slim-bookworm` sidecar attached to the v2
# compose network (see test-cargo-upstream-verification.sh's header
# for the full infrastructure dependency list).
#
# Open dependencies (same as the happy-path script):
#   - Gitops YAML at deploy/compose/example-config/{repositories,upstreams}/
#     declaring `cargo-upstream-tampered-e2e` as a Cargo Proxy pointing
#     at WIREMOCK_TAMPERED_URL. Different repo key from the happy path
#     so both can run in the same harness without colliding on the
#     repository_upstream_mappings (repo_id, path_prefix=NULL) row.
#   - Wiremock instance (wiremock-cargo-tampered) on the v2 compose
#     network with mappings + __files mounted from
#     scripts/native-tests/fixtures/cargo-upstream-tampered/.
#   - SSRF guard caveat — see the verification script's header.

set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://hort-server:8080}"
METRICS_URL="${METRICS_URL:-http://hort-server:9090/metrics}"
CARGO_REPO_KEY="${CARGO_REPO_KEY:-cargo-upstream-tampered-e2e}"
WIREMOCK_TAMPERED_URL="${WIREMOCK_TAMPERED_URL:-http://wiremock-cargo-tampered:8080}"
HORT_CONTAINER="${HORT_CONTAINER:-hort-hort-server-1}"

KEYCLOAK_TOKEN_URL="${KEYCLOAK_TOKEN_URL:-http://keycloak:8080/realms/hort/protocol/openid-connect/token}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-hort-server}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-hort-server-secret-dev-only}"
KEYCLOAK_USER="${KEYCLOAK_USER:-dev-user}"
KEYCLOAK_PASS="${KEYCLOAK_PASS:-dev}"
KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
KEYCLOAK_ADMIN_PASS="${KEYCLOAK_ADMIN_PASS:-admin}"

CRATE_NAME="cfg-if"
CRATE_VERSION="1.0.0"

FAILURES=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILURES=$((FAILURES + 1)); }
skip() { echo "SKIP: $1"; exit 0; }

echo "==> Cargo upstream tampering smoke (failure path)"
echo "Registry:        ${REGISTRY_URL}"
echo "Metrics:         ${METRICS_URL}"
echo "Repo key:        ${CARGO_REPO_KEY}"
echo "Wiremock:        ${WIREMOCK_TAMPERED_URL}"
echo "Crate:           ${CRATE_NAME} ${CRATE_VERSION} (tampered .crate body)"

if ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl python3 ca-certificates >/dev/null 2>&1 || true
fi
command -v cargo >/dev/null 2>&1 || { echo "FAIL: cargo missing in image" >&2; exit 1; }

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

echo "--- Preflight: probing tampered wiremock ${WIREMOCK_TAMPERED_URL}/config.json"
WIRE_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${WIREMOCK_TAMPERED_URL}/config.json" 2>/dev/null || echo "000")
if [ "$WIRE_CODE" != "200" ]; then
    skip "tampered wiremock not reachable at ${WIREMOCK_TAMPERED_URL}/config.json (got HTTP ${WIRE_CODE}). Bring up wiremock-cargo-tampered from the test stack."
fi
echo "  tampered wiremock reachable (HTTP 200)"

echo ""
echo "--- Step 1: Resolve cargo proxy repo UUID via admin lookup"

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
    "${REGISTRY_URL}/api/v1/admin/repositories/${CARGO_REPO_KEY}" || echo "000")
echo "  GET /api/v1/admin/repositories/${CARGO_REPO_KEY} -> HTTP ${LOOKUP_CODE}"
case "$LOOKUP_CODE" in
    200)
        REPO_ID=$(python3 -c "import sys, json; print(json.loads(open(sys.argv[1]).read())['id'])" "$LOOKUP_TMP")
        pass "tampered-repo resolved (id=${REPO_ID})"
        ;;
    404)
        cat "$LOOKUP_TMP"
        echo ""
        skip "repo '${CARGO_REPO_KEY}' not found — declare it in deploy/compose/example-config/repositories/${CARGO_REPO_KEY}.yaml as a Cargo Proxy + UpstreamMapping pointing at ${WIREMOCK_TAMPERED_URL}"
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
# IngestUseCase::ingest_verified on cksum-vs-stream-hash divergence).
# Same awk-only shape as the verification script to dodge pipefail
# under set -e when the metric series is missing pre-test.
# ---------------------------------------------------------------------
read_mismatch_metric() {
    curl -sf "$METRICS_URL" 2>/dev/null \
        | awk '/^hort_upstream_checksum_total\{[^}]*format="cargo"[^}]*result="mismatch"[^}]*\}/ { s += $NF } END { printf "%d\n", (s+0) }' \
        || true
}

METRIC_BEFORE=$(read_mismatch_metric)
echo "  hort_upstream_checksum_total{format=cargo,result=mismatch} before = ${METRIC_BEFORE}"

echo ""
echo "--- Step 2: dev-user token + cargo build attempt against tampered upstream"

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

CARGO_REGISTRY_URL="${REGISTRY_URL}/cargo/${CARGO_REPO_KEY}"
mkdir -p "$WORK_DIR/.cargo"
cat > "$WORK_DIR/.cargo/config.toml" <<EOF
[registries.hort]
index = "sparse+${CARGO_REGISTRY_URL}/"
EOF

export CARGO_REGISTRIES_HORT_TOKEN="Bearer ${DEV_TOKEN}"

mkdir -p "$WORK_DIR/consumer/src"
cat > "$WORK_DIR/consumer/Cargo.toml" <<EOF
[package]
name = "cfg-if-tampered-consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
${CRATE_NAME} = { version = "=${CRATE_VERSION}", registry = "hort" }
EOF
cat > "$WORK_DIR/consumer/src/main.rs" <<'EOF'
fn main() {}
EOF

cd "$WORK_DIR/consumer"
echo ""
echo "--- Running: cargo build (must FAIL because upstream bytes are tampered)"

# Capture cargo's stderr — we want to surface the failure mode but
# we EXPECT a non-zero exit, so don't propagate that to set -e.
CARGO_STDERR="$WORK_DIR/cargo.stderr"
set +e
cargo build --offline=false >"$WORK_DIR/cargo.stdout" 2>"$CARGO_STDERR"
CARGO_EXIT=$?
set -e

echo "  cargo build exit code: ${CARGO_EXIT}"
if [ "$CARGO_EXIT" -eq 0 ]; then
    fail "cargo build SUCCEEDED against tampered upstream — verification gate failed to fire"
    echo "  --- cargo stdout ---"
    sed 's/^/    /' "$WORK_DIR/cargo.stdout"
    echo "  --- cargo stderr ---"
    sed 's/^/    /' "$CARGO_STDERR"
else
    pass "cargo build failed as expected (exit=${CARGO_EXIT})"
fi

# ---------------------------------------------------------------------
# Step 3: assert the mismatch metric ticked. The orchestrator's wire-
# map sends 502 to cargo on ChecksumMismatch (see UpstreamPullError
# documentation in crates/hort-http-cargo/src/upstream_pull.rs); the
# 502 is what makes cargo build fail above. The metric is the
# definitive witness — without a tick, cargo could be failing for
# unrelated reasons (network blip, registry handler bug, etc.).
# ---------------------------------------------------------------------
echo ""
echo "--- Step 3: verifying mismatch metric"
METRIC_AFTER=$(read_mismatch_metric)
DELTA=$((METRIC_AFTER - METRIC_BEFORE))
echo "  hort_upstream_checksum_total{format=cargo,result=mismatch} after = ${METRIC_AFTER} (Δ${DELTA})"
if [ "$DELTA" -ge 1 ]; then
    pass "upstream verification gate detected the tampered bytes (Δ${DELTA})"
else
    fail "expected ≥1 mismatch metric tick after tampered fetch, got Δ${DELTA}. The .crate body may have been served by local CAS instead of going through upstream pull."
fi

# ---------------------------------------------------------------------
# Step 4: assert hort-server logs contain "ChecksumMismatch". This is
# the audit-trail witness — even if the metric ticked, an operator
# investigating a supply-chain alert should be able to grep the logs
# and find the structured event.
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
        fail "hort-server logs do not contain ChecksumMismatch since the build attempt"
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
