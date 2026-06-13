#!/usr/bin/env bash
# Cargo upstream pull-through verification smoke (happy path).
#
# Drives a real `cargo build` through a Cargo Proxy repository in the
# stack, against a wiremock upstream that serves real index.crates.io
# fixtures (cfg-if 1.0.0). Exercises the full upstream-verification
# pipeline: sparse-index handler → try_upstream_crate_pull →
# fetch_metadata (config.json + NDJSON) → parse_upstream_checksum →
# fetch_artifact → IngestUseCase::ingest_verified → CAS.
#
# Cache-hit semantics are verified via the
# `hort_upstream_checksum_total{format="cargo",result="verified"}` metric
# (emitted by ingest_verified) before and after the build.
#
# Why cargo build (not cargo install): cfg-if is a library crate with
# no [[bin]] target; `cargo install cfg-if` would fail at the
# "no binaries to install" guard. The .crate fetch + verification path
# exercised by `cargo build` against a consumer crate is identical —
# the verification gate fires on first download regardless of whether
# the crate is later installed or merely linked.
#
# Runs inside a `rust:1.88-slim-bookworm` sidecar attached to the
# compose network. Not intended to be invoked directly from a host shell.
#
# Deferred: will become a scenarios/upstream/* scenario once the SSRF guard
# gains a test-only escape hatch; not currently run by the runner.
#
# Required infrastructure (see "Open dependencies" at the bottom):
#   1. v2 stack reachable on REGISTRY_URL (default: http://hort-server:8080).
#   2. A Cargo Proxy repository declared via gitops YAML
#      (deploy/compose/example-config/repositories/cargo-upstream-e2e.yaml).
#   3. An UpstreamMapping declared via gitops YAML pointing at the
#      wiremock service hostname
#      (deploy/compose/example-config/upstreams/cargo-upstream-e2e.yaml).
#   4. Wiremock running on the same compose network at
#      WIREMOCK_HAPPY_URL (default: http://wiremock-cargo-upstream:8080),
#      with mappings + __files mounted from
#      scripts/native-tests/fixtures/cargo-upstream/.
#   5. hort-adapters-upstream-http SSRF guard NOT blocking the wiremock
#      hostname. Compose bridge networks are RFC 1918 (172.x.x.x), which
#      the guard refuses for absolute artifact URLs (the download leg
#      composes one from config.json's `dl`). Resolution options:
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
#   CARGO_REPO_KEY        cargo-upstream-e2e (mounted YAML at
#                         deploy/compose/example-config/repositories/cargo-upstream-e2e.yaml)
#   WIREMOCK_HAPPY_URL    http://wiremock-cargo-upstream:8080 (probe target)
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
CARGO_REPO_KEY="${CARGO_REPO_KEY:-cargo-upstream-e2e}"
WIREMOCK_HAPPY_URL="${WIREMOCK_HAPPY_URL:-http://wiremock-cargo-upstream:8080}"

KEYCLOAK_TOKEN_URL="${KEYCLOAK_TOKEN_URL:-http://keycloak:8080/realms/hort/protocol/openid-connect/token}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-hort-server}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-hort-server-secret-dev-only}"
KEYCLOAK_USER="${KEYCLOAK_USER:-dev-user}"
KEYCLOAK_PASS="${KEYCLOAK_PASS:-dev}"
KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
KEYCLOAK_ADMIN_PASS="${KEYCLOAK_ADMIN_PASS:-admin}"

CRATE_NAME="cfg-if"
CRATE_VERSION="1.0.0"
CRATE_EXPECTED_CKSUM="baf1de4339761588bc0619e3cbc0120ee582ebb74b53b4efbf79117bd2da40fd"

FAILURES=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILURES=$((FAILURES + 1)); }
skip() { echo "SKIP: $1"; exit 0; }

echo "==> Cargo upstream pull-through verification smoke (happy path)"
echo "Registry:        ${REGISTRY_URL}"
echo "Metrics:         ${METRICS_URL}"
echo "Repo key:        ${CARGO_REPO_KEY}"
echo "Wiremock:        ${WIREMOCK_HAPPY_URL}"
echo "Crate:           ${CRATE_NAME} ${CRATE_VERSION}"
echo "Expected cksum:  ${CRATE_EXPECTED_CKSUM}"

# ---------------------------------------------------------------------
# Tool prereqs — install missing deps quietly. rust:*-slim images ship
# without curl/jq/python3 by default but `cargo` is present.
# ---------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl python3 ca-certificates >/dev/null 2>&1 || true
fi
command -v cargo >/dev/null 2>&1 || { echo "FAIL: cargo missing in image" >&2; exit 1; }
command -v curl  >/dev/null 2>&1 || { echo "FAIL: curl missing — cannot run preflight"; exit 1; }

# ---------------------------------------------------------------------
# Preflight 1: probe endpoint. 401 on /admin/ counts as reachable.
# ---------------------------------------------------------------------
echo ""
echo "--- Preflight: probing ${REGISTRY_URL}/health"
HEALTH_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${REGISTRY_URL}/health" 2>/dev/null || echo "000")
case "$HEALTH_CODE" in
    200|401|404)
        echo "  endpoint reachable (HTTP ${HEALTH_CODE})"
        ;;
    *)
        skip "endpoint not reachable at ${REGISTRY_URL}/health (got HTTP ${HEALTH_CODE})"
        ;;
esac

# ---------------------------------------------------------------------
# Preflight 2: probe the wiremock upstream. If the wiremock sidecar
# isn't up the test cannot run — skip rather than fail (this script
# self-skips like test-oci-mirror.sh when its preconditions are not
# met).
# ---------------------------------------------------------------------
echo "--- Preflight: probing wiremock ${WIREMOCK_HAPPY_URL}/config.json"
WIRE_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${WIREMOCK_HAPPY_URL}/config.json" 2>/dev/null || echo "000")
if [ "$WIRE_CODE" != "200" ]; then
    skip "wiremock upstream not reachable at ${WIREMOCK_HAPPY_URL}/config.json (got HTTP ${WIRE_CODE}). Bring up wiremock-cargo-upstream from the test stack."
fi
echo "  wiremock reachable (HTTP 200)"

# ---------------------------------------------------------------------
# Step 1: admin token + repo lookup. Mirrors test-oci-mirror.sh:130-183.
# The repo is gitops-managed; this lookup is a sanity check.
# ---------------------------------------------------------------------
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
        MANAGED_BY=$(python3 -c "import sys, json; print(json.loads(open(sys.argv[1]).read())['managed_by'])" "$LOOKUP_TMP")
        pass "repository resolved (id=${REPO_ID}, managed_by=${MANAGED_BY})"
        ;;
    404)
        cat "$LOOKUP_TMP"
        echo ""
        skip "repo '${CARGO_REPO_KEY}' not found — declare it in deploy/compose/example-config/repositories/${CARGO_REPO_KEY}.yaml as a Cargo Proxy + UpstreamMapping pointing at ${WIREMOCK_HAPPY_URL}"
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
# `hort_upstream_checksum_total{format="cargo",result="verified"}` summed
# across all label combinations. Implemented in one awk pass to avoid
# `grep | awk` pipefail bites (no matches → grep exits 1 → set -o
# pipefail aborts under set -e; awk's regex match always exits 0).
# ---------------------------------------------------------------------
read_verified_metric() {
    curl -sf "$METRICS_URL" 2>/dev/null \
        | awk '/^hort_upstream_checksum_total\{[^}]*format="cargo"[^}]*result="verified"[^}]*\}/ { s += $NF } END { printf "%d\n", (s+0) }' \
        || true
}

METRIC_BEFORE=$(read_verified_metric)
echo "  hort_upstream_checksum_total{format=cargo,result=verified} before = ${METRIC_BEFORE}"

# ---------------------------------------------------------------------
# Step 2: dev-user token (cargo registry auth). Cargo sends this
# verbatim as Authorization: Bearer <token> when CARGO_REGISTRIES_*_TOKEN
# starts with "Bearer ".
# ---------------------------------------------------------------------
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
# Step 3: configure cargo + build a consumer that depends on cfg-if.
# Project-local .cargo/config.toml so cargo walks up from $CWD and
# picks the right registry (see scripts/native-tests/scenarios/clients/cargo.sh for
# the auth-shape commentary).
# ---------------------------------------------------------------------
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"

CARGO_REGISTRY_URL="${REGISTRY_URL}/cargo/${CARGO_REPO_KEY}"
echo ""
echo "--- Step 3: configure cargo + build consumer at ${WORK_DIR}"
echo "  registry index: sparse+${CARGO_REGISTRY_URL}/"

mkdir -p "$WORK_DIR/.cargo"
cat > "$WORK_DIR/.cargo/config.toml" <<EOF
[registries.hort]
index = "sparse+${CARGO_REGISTRY_URL}/"
EOF

export CARGO_REGISTRIES_HORT_TOKEN="Bearer ${DEV_TOKEN}"

mkdir -p "$WORK_DIR/consumer/src"
cat > "$WORK_DIR/consumer/Cargo.toml" <<EOF
[package]
name = "cfg-if-consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
${CRATE_NAME} = { version = "=${CRATE_VERSION}", registry = "hort" }
EOF
cat > "$WORK_DIR/consumer/src/main.rs" <<'EOF'
fn main() {
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            println!("unix");
        } else {
            println!("non-unix");
        }
    }
}
EOF

cd "$WORK_DIR/consumer"
echo ""
echo "--- Running: cargo build (sparse+${CARGO_REGISTRY_URL}/)"
# No `|| echo` masking — pipefail surfaces real failures (CLAUDE.md
# memory feedback_tdd_enforcement.md / test-cargo.sh:5-6).
if cargo build --offline=false; then
    pass "cargo build against ${CARGO_REPO_KEY} succeeded"
else
    fail "cargo build failed — registry sparse-index proxy or upstream-pull misconfigured"
fi
[ "$FAILURES" -gt 0 ] && exit 1

OUTPUT="$(./target/debug/cfg-if-consumer)"
case "$OUTPUT" in
    unix|non-unix)
        pass "consumer ran: ${OUTPUT}"
        ;;
    *)
        fail "consumer produced unexpected output: ${OUTPUT}"
        ;;
esac
[ "$FAILURES" -gt 0 ] && exit 1

# ---------------------------------------------------------------------
# Step 4: verify the verification metric ticked. The verified-ingest
# emission is in IngestUseCase::ingest_verified — if the orchestrator
# took the upstream-pull path AND verification passed, this counter
# went up by exactly 1 (per crate downloaded; cfg-if has zero deps in
# its default features so we only fetched one crate).
# ---------------------------------------------------------------------
METRIC_AFTER=$(read_verified_metric)
DELTA=$((METRIC_AFTER - METRIC_BEFORE))
echo ""
echo "  hort_upstream_checksum_total{format=cargo,result=verified} after = ${METRIC_AFTER} (Δ${DELTA})"
if [ "$DELTA" -ge 1 ]; then
    pass "upstream verification fired and verified the .crate body (Δ${DELTA})"
else
    fail "expected ≥1 verified upstream-checksum tick after first download, got Δ${DELTA}. Either the build hit a local CAS (test-data leak from a prior run) or the orchestrator did not take the upstream-pull path."
fi

if [ "$FAILURES" -gt 0 ]; then
    echo ""
    echo "==> ${FAILURES} failure(s)"
    exit 1
fi
echo ""
echo "==> OK"
