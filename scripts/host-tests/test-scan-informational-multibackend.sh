#!/usr/bin/env bash
# Multi-backend informational-classification smoke (the `[trivy, osv]` gap).
#
# Regression guard for the cross-backend merge fail-open fixed in
# `fix(scan): merge preserves the informational classification across backends`
# (`crates/hort-app/src/use_cases/scan_orchestration.rs`):
#
#   A `ScanPolicy` running BOTH backends (`scanBackends: [trivy, osv]`) with
#   `negligibleAction: ignore`, fed a crate carrying a RustSec *informational*
#   advisory (proc-macro-error2@2.0.1 → RUSTSEC-2026-0173 "unmaintained"):
#     - the osv/advisory path classifies it informational (severity Low, no CVSS);
#     - Trivy cannot read the RustSec class and fails the unscored advisory
#       closed to Critical (SUP-4);
#   The merge MUST preserve the informational reading so the artifact is
#   RELEASED, not rejected. Before the fix, the dedup kept Trivy's cosmetic
#   Critical → `informational_class` empty → rejected despite `ignore`.
#
# WHY THIS EXISTS / WHY THE OSV-ONLY SMOKE MISSED IT:
#   `test-vulnerability-scan.sh` pins `scanBackends: [osv]` and so exercises osv
#   in isolation — it can NEVER hit the cross-backend merge. This smoke MUST pin
#   BOTH backends; that is the whole point.
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ VALIDATION STATUS: this script mirrors the proven structure of           │
# │ test-vulnerability-scan.sh (compose lifecycle, worker profile, gitops    │
# │ overlay, psql polling, live-OSV.dev fixture-drift guard) but has NOT yet  │
# │ been executed against a live compose stack. Run it once in CI / local    │
# │ compose and confirm green before relying on it as a gate.                │
# └─────────────────────────────────────────────────────────────────────────┘
#
# Exit codes (mirrors test-vulnerability-scan.sh):
#   0 — pass
#   1 — hard failure (stack/worker unavailable, or the assertion failed)
#   2 — environment unmet (OSV.dev unreachable / Keycloak token unreachable)
#   3 — FIXTURE_DRIFT: RUSTSEC-2026-0173 is no longer an informational advisory
#       for proc-macro-error2 on OSV.dev (update the fixture, not a real failure)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$REPO_ROOT/deploy/compose/docker-compose.yml}"

API_URL="${API_URL:-http://localhost:8080}"
METRICS_URL="${METRICS_URL:-$API_URL/metrics}"
KEYCLOAK_TOKEN_URL="${KEYCLOAK_TOKEN_URL:-http://localhost:8081/realms/hort/protocol/openid-connect/token}"

CARGO_REPO_KEY="${CARGO_REPO_KEY:-cargo-public}"
CRATE_NAME="${CRATE_NAME:-proc-macro-error2}"
CRATE_VERSION="${CRATE_VERSION:-2.0.1}"
ADVISORY_ID="${ADVISORY_ID:-RUSTSEC-2026-0173}"

READY_TIMEOUT_SECS="${READY_TIMEOUT_SECS:-120}"
SCAN_RESULT_TIMEOUT_SECS="${SCAN_RESULT_TIMEOUT_SECS:-120}"

log() { printf '%s\n' "$*" >&2; }
assert_pass() { log "  PASS: $1"; }
assert_fail() { log "  FAIL: $1"; [ -n "${2:-}" ] && log "        $2"; FAILED=1; }
FAILED=0

# --- psql helpers (mirror test-vulnerability-scan.sh) ----------------------
psql_one() {
    docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -tAX -c "$1" 2>/dev/null \
        | tr -d '[:space:]' || true
}
psql_count() { local out; out="$(psql_one "$1")"; [[ "$out" =~ ^[0-9]+$ ]] && echo "$out" || echo 0; }
export -f psql_one psql_count

bounded_poll() {
    local label="$1" timeout="$2" cmd="$3" interval="${4:-2}" deadline
    deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if bash -c "$cmd"; then return 0; fi
        sleep "$interval"
    done
    log "  bounded_poll($label) timed out after ${timeout}s"
    return 1
}

# --- Phase 0: prerequisites + fixture-drift guard --------------------------
log "==> [0] prerequisites"
if ! curl -fsSL -o /dev/null --max-time 5 "$METRICS_URL"; then
    log "SKIP: hort-server not reachable at $METRICS_URL (bring up the compose stack + worker profile first)"
    exit 2
fi
if ! psql_count "SELECT COUNT(*) FROM scanner_registry WHERE worker_id = 'hort-worker-v2';" | grep -q '^[1-9]'; then
    log "SKIP: no worker registered (run 'docker compose --profile worker up -d')"
    exit 1
fi

log "==> [0b] FIXTURE-DRIFT guard: ${ADVISORY_ID} must still be informational on OSV.dev"
if ! osv_json="$(curl -fsSL --max-time 15 "https://api.osv.dev/v1/vulns/${ADVISORY_ID}" 2>/dev/null)"; then
    log "SKIP: OSV.dev unreachable (the scanner pipeline relies on OSV; cannot exercise offline)"
    exit 2
fi
if ! python3 - "$osv_json" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
# RustSec places the informational class at affected[].database_specific.informational.
classes = {
    (a.get("database_specific") or {}).get("informational")
    for a in d.get("affected", [])
}
sys.exit(0 if {"unmaintained", "unsound", "notice"} & classes else 3)
PY
then
    log "FIXTURE_DRIFT: ${ADVISORY_ID} is no longer an informational advisory on OSV.dev — update the fixture."
    exit 3
fi
assert_pass "${ADVISORY_ID} is informational on OSV.dev"

# --- Phase 1: stage cargo-public proxy + [trivy, osv] policy (overlay) ------
# Staged into a transient gitops overlay (NOT the canonical example-config) so
# this smoke does not perturb other compose tests. Mirror the staging+restart
# pattern of test-vulnerability-scan.sh's `stage_config_dir`/overlay if your
# harness already provides it; the three envelopes the policy/repo/mapping need:
#
#   ArtifactRepository cargo-public (format: cargo, type: proxy,
#       indexMode: include_pending, proxy.upstreamUrl: https://index.crates.io)
#   UpstreamMapping   cargo-public (repository: cargo-public, pathPrefix: "",
#       upstreamUrl: https://index.crates.io, auth: anonymous)
#   ScanPolicy        (scope.repository: cargo-public, severityThreshold: critical,
#       quarantineDuration: 0s, provenanceMode: off,
#       scanBackends: [trivy, osv], negligibleAction: ignore)
#
# (Apply via the same gitops-overlay + hort-server restart the sibling smoke
# uses; left as the harness step so this file stays focused on the assertion.)
log "==> [1] apply cargo-public proxy + ScanPolicy{ scanBackends:[trivy,osv], negligibleAction:ignore } (gitops overlay)"
"${STAGE_AND_APPLY:-true}" \
    || { log "FAIL: gitops overlay apply step (STAGE_AND_APPLY) failed"; exit 1; }

# --- Phase 2: ingest the crate via the cargo pull-through ------------------
log "==> [2] ingest ${CRATE_NAME}@${CRATE_VERSION} via ${CARGO_REPO_KEY} pull-through"
DEV_TOKEN="$(
    curl -sS --max-time 15 -X POST "$KEYCLOAK_TOKEN_URL" \
        -d grant_type=client_credentials -d client_id="${HORT_CLIENT_ID:-hort-dev}" \
        -d client_secret="${HORT_CLIENT_SECRET:-dev-secret}" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null || true
)"
[ -z "$DEV_TOKEN" ] && { log "SKIP: Keycloak token endpoint not reachable at $KEYCLOAK_TOKEN_URL"; exit 2; }

DL_URL="$API_URL/cargo/${CARGO_REPO_KEY}/api/v1/crates/${CRATE_NAME}/${CRATE_VERSION}/download"
log "  GET $DL_URL"
HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 90 \
    -H "Authorization: Bearer $DEV_TOKEN" "$DL_URL" || echo 000)"
[ "$HTTP_CODE" = "200" ] \
    && assert_pass "cargo pull-through returned 200 for ${CRATE_NAME}@${CRATE_VERSION}" \
    || { assert_fail "cargo pull-through returned 200" "got HTTP $HTTP_CODE"; exit 1; }

ARTIFACT_ID="$(psql_one "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${CARGO_REPO_KEY}' AND a.name = '${CRATE_NAME}' AND a.version = '${CRATE_VERSION}' ORDER BY a.created_at DESC LIMIT 1;")"
[ -n "$ARTIFACT_ID" ] \
    && assert_pass "artifact row present (id=$ARTIFACT_ID)" \
    || { assert_fail "artifact row present" "no artifacts.id resolved"; exit 1; }

# --- Phase 3: the assertion — RELEASED, never rejected ---------------------
log "==> [3] the artifact must reach 'released' (NOT 'rejected') within ${SCAN_RESULT_TIMEOUT_SECS}s"
if bounded_poll "artifact ${ARTIFACT_ID} → released" "$SCAN_RESULT_TIMEOUT_SECS" \
        "[ \"\$(psql_one \"SELECT quarantine_status FROM artifacts WHERE id = '${ARTIFACT_ID}';\")\" = 'released' ]"; then
    assert_pass "artifact RELEASED — informational classification survived the [trivy, osv] merge"
else
    final="$(psql_one "SELECT quarantine_status FROM artifacts WHERE id = '${ARTIFACT_ID}';")"
    if [ "$final" = "rejected" ]; then
        assert_fail "artifact RELEASED" \
            "status='rejected' — the cross-backend merge discarded the informational class (the bug this smoke guards)"
    else
        assert_fail "artifact RELEASED" "final status='${final}' (expected 'released')"
    fi
fi

# Belt-and-suspenders: it must NOT be rejected and the finding must be negligible.
CRITICAL_REJECT="$(psql_count "SELECT COUNT(*) FROM artifacts WHERE id = '${ARTIFACT_ID}' AND quarantine_status = 'rejected';")"
[ "$CRITICAL_REJECT" -eq 0 ] \
    && assert_pass "artifact is not rejected" \
    || assert_fail "artifact is not rejected" "an informational advisory under negligible=ignore must never reject"

[ "$FAILED" -eq 0 ] && { log "==> PASS"; exit 0; } || { log "==> FAIL"; exit 1; }
