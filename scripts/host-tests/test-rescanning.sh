#!/usr/bin/env bash
# End-to-end smoke for the rescanning + manual-rescan path. Two phases:
#
#   Phase 1 — Helm template smoke:
#     `helm template deploy/helm/hort-server -f test-values-cronjobs.yaml`
#     renders both CronJob templates (cron-rescan-tick and
#     advisory-watch-tick) with the `--idempotency-key` flag wired
#     through. No cluster needed; helm + grep only.
#
#   Phase 2 — Runtime smoke (skips actual CronJob wall-clock; uses
#   hort-cli to invoke the handler directly):
#     1. Bring up hort-server + hort-worker. Both via
#        deploy/compose/docker-compose.yml.
#     2. Mint an hort_svc_* token via `hort-server admin issue-svc-token`
#        (same bootstrap path the task-framework smoke uses).
#     3. Apply ScanPolicy with `rescanIntervalHours: 1` for the
#        npm-public proxy repo.
#     4. Ingest lodash@4.17.20 via the npm-public pull-through proxy.
#        Verify initial ScanCompleted lands on the artifact stream and
#        artifacts.last_scan_at is now ~now() in psql.
#     5. Force the eligibility window: psql UPDATE that backdates
#        last_scan_at by 2 hours (past the 1-hour interval). Test
#        pinning — production never does this; smokes routinely use
#        psql state setup (precedent in gitops-policies + vuln-scan).
#     6. hort-cli admin task invoke cron-rescan-tick → assert 202 +
#        task_job_id.
#     7. Poll for ≥ 2 ScanCompleted events within 30s.
#     8. hort-cli admin rescan $AID → assert 202.
#     9. Poll for the 3rd ScanCompleted within 30s.
#    10. Curl /metrics; assert:
#          - hort_scan_jobs_enqueued_total{trigger_source="cron"} ≥ 1
#          - hort_scan_jobs_enqueued_total{trigger_source="manual"} ≥ 1
#          - hort_admin_tasks_completed_total{kind="cron-rescan-tick"} ≥ 1
#
# The advisory-watch path is NOT exercised here — mock OSV would
# dominate the smoke runtime. A separate `test-advisory-watch.sh` is
# future work.
#
# Same skip / staging idiom as test-vulnerability-scan.sh: a transient
# $HORT_CONFIG_DIR overlay reapplied via a generated docker-compose
# override, EXIT trap restores the canonical example-config bind so
# subsequent tests start clean. Worker brought up via `--profile
# worker`.
#
# Skip semantics:
#   - helm CLI missing → exit 2 (env unmet) for Phase 1.
#   - Compose stack down → exit 2 for Phase 2 (env unmet, NOT failure).
#   - Worker container fails to start / register → exit 1.
#   - hort-cli binary missing under target/{debug,release}/ → exit 2.
#   - Token bootstrap impossible (HORT_TOKEN_ALLOW_ADMIN unset) → exit 2.
#   - 2nd / 3rd ScanCompleted never fires → exit 1 with worker logs.
#
# Exit codes:
#   0 — every assertion passed
#   1 — at least one assertion failed
#   2 — environment unmet (helm/docker missing, stack unreachable,
#       admin-token capability not enabled, hort-cli binary not built)
#
# Debug: HORT_TEST_DEBUG=1 toggles `set -x`.

set -euo pipefail

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

# -----------------------------------------------------------------------------
# Paths + constants
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$REPO_ROOT/deploy/compose/docker-compose.yml}"
EXAMPLE_CONFIG="$REPO_ROOT/deploy/compose/example-config"
HELM_CHART_DIR="$REPO_ROOT/deploy/helm/hort-server"
HELM_TEST_VALUES="$HELM_CHART_DIR/test-values-cronjobs.yaml"

# Host endpoints — match the v2 stack's 25xxx host port mappings.
API_URL="${API_URL:-http://localhost:25080}"
METRICS_URL="${METRICS_URL:-http://localhost:25090/metrics}"

READY_TIMEOUT_SECS="${READY_TIMEOUT_SECS:-90}"
SCAN_FIRST_TIMEOUT_SECS="${SCAN_FIRST_TIMEOUT_SECS:-60}"
SCAN_RESCAN_TIMEOUT_SECS="${SCAN_RESCAN_TIMEOUT_SECS:-30}"

# Pinned fixture identifiers — same package + repo as the
# test-vulnerability-scan.sh smoke. Reuse keeps this smoke aligned
# with the producer-pipeline fixture set so a future fixture refresh
# only has to touch one place. The CVE/severity assertions are NOT
# exercised here — only the rescan-job pipeline.
NPM_PROXY_REPO_KEY="${NPM_PROXY_REPO_KEY:-npm-public}"
LODASH_NAME="lodash"
LODASH_VERSION="4.17.20"
SCAN_POLICY_NAME="rescan-smoke-policy"

# Stage root + override file — same shape as test-vulnerability-scan.sh.
STAGE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/hort-rescan-XXXXXX")"
OVERRIDE_FILE="${STAGE_ROOT}/docker-compose.override.yml"
TOKEN_FILE="${STAGE_ROOT}/svc-token.txt"

PASSED=0
FAIL=0
declare -a FAILURES=()

# -----------------------------------------------------------------------------
# Logging + assertion helpers (matches the gitops + vuln-scan smokes)
# -----------------------------------------------------------------------------

log() { printf '%s\n' "$*"; }

assert_pass() {
    PASSED=$((PASSED + 1))
    log "  PASS: $1"
}
assert_fail() {
    FAIL=$((FAIL + 1))
    FAILURES+=("$1 :: $2")
    printf '  FAIL: %s :: %s\n' "$1" "$2" >&2
}

# -----------------------------------------------------------------------------
# Cleanup — always runs. Registered before any transient resource is
# created so a partial setup still tears down cleanly.
# -----------------------------------------------------------------------------

# shellcheck disable=SC2317  # invoked indirectly via `trap ... EXIT`
cleanup() {
    local ec=$?
    log ""
    log "==> cleanup"
    if [ -f "$OVERRIDE_FILE" ]; then
        rm -f "$OVERRIDE_FILE" || true
    fi
    if compose_available; then
        log "  stopping hort-worker (profile teardown)"
        docker compose -f "$COMPOSE_FILE" --profile worker \
            stop hort-worker >/dev/null 2>&1 || true
        log "  restoring hort-server to example-config mount"
        docker compose -f "$COMPOSE_FILE" restart hort-server >/dev/null 2>&1 || true
    fi
    rm -rf "$STAGE_ROOT" || true
    return "$ec"
}
trap cleanup EXIT

# -----------------------------------------------------------------------------
# Phase 1 — Helm template smoke (no Docker required)
# -----------------------------------------------------------------------------

phase_1_helm_template_smoke() {
    log ""
    log "==> Phase 1 — helm template smoke (CronJob manifests)"

    if ! command -v helm >/dev/null 2>&1; then
        log "SKIP: helm CLI not available — phase 1 cannot run"
        log "      install helm or set PATH; phase 2 will still run independently"
        return 2
    fi

    if [ ! -f "$HELM_TEST_VALUES" ]; then
        log "SKIP: helm test-values fixture not found at $HELM_TEST_VALUES"
        return 2
    fi

    log "  rendering: helm template $HELM_CHART_DIR -f $HELM_TEST_VALUES"
    local manifest
    if ! manifest="$(helm template "$HELM_CHART_DIR" -f "$HELM_TEST_VALUES" 2>&1)"; then
        log "FAIL: helm template invocation failed"
        log "  output (first 60 lines):"
        printf '%s\n' "$manifest" | head -60 | sed 's/^/    /'
        assert_fail \
            "helm template renders without error" \
            "helm template returned non-zero — see output above"
        return 1
    fi

    # Assertion 1.1 — at least one CronJob manifest rendered.
    if printf '%s\n' "$manifest" | grep -q '^kind: CronJob$'; then
        assert_pass "helm template produced at least one CronJob manifest"
    else
        assert_fail \
            "helm template produced at least one CronJob manifest" \
            "no 'kind: CronJob' line in render output"
    fi

    # Assertion 1.2 — cron-rescan-tick CronJob present.
    if printf '%s\n' "$manifest" | grep -q "hort-server.io/job: cron-rescan-tick"; then
        assert_pass "cron-rescan-tick CronJob rendered"
    else
        assert_fail \
            "cron-rescan-tick CronJob rendered" \
            "expected label 'hort-server.io/job: cron-rescan-tick' missing — template not gated on scheduledTasks.cronRescanTick.enabled?"
    fi

    # Assertion 1.3 — advisory-watch-tick CronJob present.
    if printf '%s\n' "$manifest" | grep -q "hort-server.io/job: advisory-watch-tick"; then
        assert_pass "advisory-watch-tick CronJob rendered"
    else
        assert_fail \
            "advisory-watch-tick CronJob rendered" \
            "expected label 'hort-server.io/job: advisory-watch-tick' missing — advisory template not gated correctly?"
    fi

    # Assertion 1.4 — the hort-cli command line carries the
    # --idempotency-key flag for cron-rescan-tick. A
    # `<schedule_window>:<kind>` key is required so a controller-restart
    # double-fire short-circuits at the framework layer.
    local rescan_invoke_line
    rescan_invoke_line="$(printf '%s\n' "$manifest" \
        | grep -E 'hort-cli admin task invoke cron-rescan-tick' || true)"
    if [ -n "$rescan_invoke_line" ] \
       && printf '%s\n' "$rescan_invoke_line" | grep -q -- '--idempotency-key'; then
        assert_pass "cron-rescan-tick command invokes hort-cli with --idempotency-key"
    else
        assert_fail \
            "cron-rescan-tick command invokes hort-cli with --idempotency-key" \
            "expected line containing 'hort-cli admin task invoke cron-rescan-tick ... --idempotency-key' — found: '$rescan_invoke_line'"
    fi

    # Assertion 1.5 — same shape for advisory-watch-tick (the same
    # idempotency wiring is required on both CronJobs).
    local advisory_invoke_line
    advisory_invoke_line="$(printf '%s\n' "$manifest" \
        | grep -E 'hort-cli admin task invoke advisory-watch-tick' || true)"
    if [ -n "$advisory_invoke_line" ] \
       && printf '%s\n' "$advisory_invoke_line" | grep -q -- '--idempotency-key'; then
        assert_pass "advisory-watch-tick command invokes hort-cli with --idempotency-key"
    else
        assert_fail \
            "advisory-watch-tick command invokes hort-cli with --idempotency-key" \
            "expected line containing 'hort-cli admin task invoke advisory-watch-tick ... --idempotency-key' — found: '$advisory_invoke_line'"
    fi

    # Assertion 1.6 — both CronJob containers reference the
    # bootstrap Secret (svc-token-bootstrap-job.yaml) for HORT_TOKEN.
    # This is the chart-level token bootstrap the design requires.
    if printf '%s\n' "$manifest" \
            | grep -q "name: release-name-hort-server-svc-token"; then
        assert_pass "CronJob containers reference the chart-managed svc-token Secret"
    else
        assert_fail \
            "CronJob containers reference the chart-managed svc-token Secret" \
            "expected secretKeyRef pointing at the bootstrap-job Secret — chart wiring drift?"
    fi

    log "  phase 1 OK"
    return 0
}

# -----------------------------------------------------------------------------
# Phase 2 helpers — env / readiness / psql (mirror test-vulnerability-scan.sh)
# -----------------------------------------------------------------------------

compose_available() {
    docker compose -f "$COMPOSE_FILE" ps >/dev/null 2>&1
}

require_stack_up() {
    if ! compose_available; then
        log "SKIP: docker compose stack not running at $COMPOSE_FILE"
        log "      bring it up with: docker compose -f $COMPOSE_FILE up -d"
        exit 2
    fi
    if ! curl -fsSL -o /dev/null --max-time 5 "$METRICS_URL"; then
        log "SKIP: hort-server metrics endpoint unreachable at $METRICS_URL"
        exit 2
    fi
}

# Bounded poll. Returns 0 on success, 1 on timeout. No fixed `sleep N`
# anywhere else — every wait routes through this helper.
bounded_poll() {
    local label="$1"
    local timeout_secs="$2"
    local predicate_cmd="$3"
    local interval="${4:-2}"
    local deadline
    deadline=$(( $(date +%s) + timeout_secs ))
    while :; do
        if bash -c "$predicate_cmd" >/dev/null 2>&1; then
            return 0
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            log "  bounded_poll($label) timed out after ${timeout_secs}s"
            return 1
        fi
        sleep "$interval"
    done
}

wait_for_metrics() {
    bounded_poll "hort-server /metrics ready" "$READY_TIMEOUT_SECS" \
        "curl -fsSL -o /dev/null '$METRICS_URL'"
}

wait_for_worker_ready() {
    # The worker registers itself in the scanner_registry table on
    # startup; readiness is observed via psql polling for at least one
    # row whose `worker_id = 'hort-worker-v2'` (set on the compose
    # service's HORT_WORKER_ID env var).
    bounded_poll "hort-worker registry row" "$READY_TIMEOUT_SECS" \
        "[ \"\$(psql_count \"SELECT COUNT(*) FROM scanner_registry WHERE worker_id = 'hort-worker-v2';\")\" -ge 1 ]" \
        3
}

psql_one() {
    local sql="$1"
    docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -tAX -c "$sql" 2>/dev/null \
        | tr -d '[:space:]'
}

psql_count() {
    local sql="$1"
    local out
    out="$(psql_one "$sql")"
    if [ -z "$out" ]; then
        echo "0"
    else
        echo "$out"
    fi
}

export -f psql_one psql_count
export COMPOSE_FILE

# -----------------------------------------------------------------------------
# Stage management — same as the vuln-scan smoke
# -----------------------------------------------------------------------------

stage_config_dir() {
    local stage_dir="$1"
    rm -rf "$stage_dir"
    mkdir -p "$stage_dir"
    cp -R "$EXAMPLE_CONFIG"/. "$stage_dir"/
    mkdir -p "$stage_dir/policies"
}

write_override() {
    local stage_dir="$1"
    cat > "$OVERRIDE_FILE" <<EOF
# Auto-generated by scripts/host-tests/test-rescanning.sh.
# Re-mounts the staged \$HORT_CONFIG_DIR over the example-config bind so
# the boot apply sees the smoke-test fixture overlay (the ScanPolicy
# with rescanIntervalHours). Removed by the script's EXIT trap.
services:
  hort-server:
    volumes:
      - cas:/var/lib/hort-server/cas
      - ${stage_dir}:/etc/hort/config:ro
EOF
}

restart_hort_server_with_overlay() {
    log "  restarting hort-server with overlay (stage: $STAGE_ROOT/config)"
    docker compose -f "$COMPOSE_FILE" -f "$OVERRIDE_FILE" \
        up -d hort-server >/dev/null
    if ! wait_for_metrics; then
        log "  hort-server logs (last 80 lines):"
        docker compose -f "$COMPOSE_FILE" logs --tail=80 hort-server 2>&1 \
            | sed 's/^/    /' || true
        log "FAIL: hort-server failed to become ready within ${READY_TIMEOUT_SECS}s"
        exit 1
    fi
}

ensure_worker_up() {
    log "  bringing up hort-worker (profile=worker)"
    if ! docker compose -f "$COMPOSE_FILE" --profile worker \
            up -d hort-worker >/dev/null 2>&1; then
        log "  hort-worker compose-up failed:"
        docker compose -f "$COMPOSE_FILE" --profile worker \
            up hort-worker 2>&1 | sed 's/^/    /' | tail -40 || true
        log "FAIL: hort-worker did not start (the hort-worker binary must build)"
        exit 1
    fi
    if ! wait_for_worker_ready; then
        log "  hort-worker logs (last 80 lines):"
        docker compose -f "$COMPOSE_FILE" logs --tail=80 hort-worker 2>&1 \
            | sed 's/^/    /' || true
        log "FAIL: hort-worker did not register a scanner_registry row within ${READY_TIMEOUT_SECS}s"
        exit 1
    fi
    log "  hort-worker ready (worker_id=hort-worker-v2 in scanner_registry)"
}

# -----------------------------------------------------------------------------
# hort-cli locator — looks for the binary under target/{debug,release} or PATH
# -----------------------------------------------------------------------------

locate_hort_cli() {
    if [ -n "${HORT_CLI_BIN:-}" ] && [ -x "$HORT_CLI_BIN" ]; then
        echo "$HORT_CLI_BIN"
        return 0
    fi
    for candidate in \
            "$REPO_ROOT/target/debug/hort-cli" \
            "$REPO_ROOT/target/release/hort-cli"; do
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    if command -v hort-cli >/dev/null 2>&1; then
        command -v hort-cli
        return 0
    fi
    return 1
}

# -----------------------------------------------------------------------------
# Token bootstrap — mint a service-account token via the hort-server admin CLI
# -----------------------------------------------------------------------------

mint_svc_token() {
    local token_name="rescan-smoke-$RANDOM"

    # Check capability flag — same gate as test-task-framework.sh.
    local allow
    allow="$(docker compose -f "$COMPOSE_FILE" \
        exec -T hort-server sh -c 'echo "${HORT_TOKEN_ALLOW_ADMIN:-}"' 2>/dev/null \
        | tr -d '[:space:]' || echo "")"
    if [ "$allow" != "true" ]; then
        log "SKIP: HORT_TOKEN_ALLOW_ADMIN != 'true' in hort-server container env"
        log "      set HORT_TOKEN_ALLOW_ADMIN=true to enable svc-token bootstrap"
        exit 2
    fi

    local raw
    raw="$(docker compose -f "$COMPOSE_FILE" exec -T hort-server \
        /usr/local/bin/hort-server admin issue-svc-token \
        --name="$token_name" \
        --permission=admin_task_invoke \
        --output=stdout 2>/dev/null || true)"
    if [ -z "$raw" ]; then
        log "FAIL: hort-server admin issue-svc-token returned empty token"
        log "  hort-server logs (last 40 lines):"
        docker compose -f "$COMPOSE_FILE" logs --tail=40 hort-server 2>&1 \
            | sed 's/^/    /' || true
        exit 1
    fi

    install -m 0600 /dev/null "$TOKEN_FILE"
    printf '%s' "$raw" > "$TOKEN_FILE"
    log "  minted svc-token (name=$token_name, written to $TOKEN_FILE)"
}

# -----------------------------------------------------------------------------
# YAML fixture writer — ScanPolicy with rescanIntervalHours: 1
# -----------------------------------------------------------------------------

write_rescan_scan_policy_yaml() {
    local stage_dir="$1"
    cat > "$stage_dir/policies/scanpolicy-rescan-smoke.yaml" <<EOF
# Rescanning smoke fixture.
#
# rescanIntervalHours: 1 — whole hours only. The smoke does NOT wait
# one hour; instead it backdates artifacts.last_scan_at by 2 hours
# via psql to make the recently-ingested artifact eligible. Production
# never does this; smokes routinely do (precedent in the gitops +
# vuln-scan smokes).
#
# scanBackends: [osv] — pinned because the adapter doesn't need a
# populated DB cache (osv-scanner queries api.osv.dev directly per
# scan). Same rationale as test-vulnerability-scan.sh.
#
# severityThreshold: high — kept high so the policy actually schedules
# work; the rescan smoke does NOT assert quarantine outcomes
# (test-vulnerability-scan.sh covers that producer-pipeline shape).
# We only assert that ScanCompleted events fire and the metric labels
# emit correctly.
apiVersion: project-hort.de/v1beta1
kind: ScanPolicy
metadata:
  name: ${SCAN_POLICY_NAME}
spec:
  scope: global
  severityThreshold: high
  quarantineDuration: 0s
  requireApproval: false
  # provenance off for permissive e2e (no per-ingest verify job).
  provenanceMode: off
  rescanIntervalHours: 1
  scanBackends:
    - osv
EOF
}

# -----------------------------------------------------------------------------
# Phase 2 — runtime smoke
# -----------------------------------------------------------------------------

phase_2_runtime_smoke() {
    log ""
    log "==> Phase 2 — runtime smoke (rescan + manual-rescan)"
    log "compose : $COMPOSE_FILE"
    log "api     : $API_URL"
    log "metrics : $METRICS_URL"
    log "stage   : $STAGE_ROOT"
    log "fixture : ${LODASH_NAME}@${LODASH_VERSION} (repo=${NPM_PROXY_REPO_KEY})"

    require_stack_up

    # hort-cli binary is needed for steps 6 + 8. We could go via raw
    # curl, but the starter prompt explicitly says "hort-cli admin task
    # invoke cron-rescan-tick" + "hort-cli admin rescan $AID" — the
    # smoke is also a CLI surface check.
    local hort_cli
    if ! hort_cli="$(locate_hort_cli)"; then
        log "SKIP: hort-cli binary not found (looked under target/{debug,release}, PATH, HORT_CLI_BIN)"
        log "      build it with: cargo build -p hort-cli"
        exit 2
    fi
    log "  hort-cli: $hort_cli"

    # 1. Stage + apply the ScanPolicy with rescanIntervalHours: 1.
    log ""
    log "--> [1/8] apply ScanPolicy (rescanIntervalHours=1) via gitops overlay"
    stage_config_dir "$STAGE_ROOT/config"
    write_rescan_scan_policy_yaml "$STAGE_ROOT/config"
    write_override "$STAGE_ROOT/config"
    restart_hort_server_with_overlay

    local policy_active
    policy_active="$(psql_count "SELECT COUNT(*) FROM policy_projections WHERE name = '${SCAN_POLICY_NAME}' AND archived = false;")"
    if [ "$policy_active" = "1" ]; then
        assert_pass "ScanPolicy '${SCAN_POLICY_NAME}' active in policy_projections"
    else
        assert_fail \
            "ScanPolicy '${SCAN_POLICY_NAME}' active" \
            "expected 1 active row, got '$policy_active' — gitops apply did not land the policy"
        return 1
    fi

    # 2. Bring up the worker.
    log ""
    log "--> [1b/8] bring up hort-worker (--profile worker)"
    ensure_worker_up

    # 3. Mint a service-account token for hort-cli.
    log ""
    log "--> [2/8] mint hort_svc_* token via hort-server admin issue-svc-token"
    mint_svc_token
    HORT_TOKEN_VAL="$(cat "$TOKEN_FILE")"
    export HORT_TOKEN="$HORT_TOKEN_VAL"
    export HORT_SERVER="$API_URL"
    assert_pass "HORT_TOKEN + HORT_SERVER exported for hort-cli (token kind expected: hort_svc_*)"

    # Sanity-check hort-cli auth status; soft-asserted because the
    # dispatch path of the test does not strictly require it (we use
    # HORT_TOKEN env for every hort-cli call), but it surfaces token
    # validity early if the bootstrap is broken.
    local whoami_rc=0
    "$hort_cli" auth status >/dev/null 2>&1 || whoami_rc=$?
    if [ $whoami_rc -eq 0 ]; then
        assert_pass "hort-cli auth status accepts the minted token"
    else
        log "  WARN: hort-cli auth status returned $whoami_rc — continuing (env-token path may bypass the persisted-config check)"
    fi

    # 4. Ingest lodash@4.17.20 via the npm-public proxy.
    log ""
    log "--> [3/8] ingest ${LODASH_NAME}@${LODASH_VERSION} via $NPM_PROXY_REPO_KEY (pull-through)"
    local tarball_url
    tarball_url="$API_URL/npm/${NPM_PROXY_REPO_KEY}/${LODASH_NAME}/-/${LODASH_NAME}-${LODASH_VERSION}.tgz"
    log "  GET $tarball_url"
    local http_code
    http_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 60 \
        -H "Authorization: Bearer $HORT_TOKEN_VAL" \
        "$tarball_url" || echo "000")"
    if [ "$http_code" = "200" ]; then
        assert_pass "npm tarball pull-through returned 200 for ${LODASH_NAME}@${LODASH_VERSION}"
    else
        assert_fail \
            "npm tarball pull-through returned 200 for ${LODASH_NAME}@${LODASH_VERSION}" \
            "got HTTP $http_code — npm-public proxy did not ingest"
        return 1
    fi

    local artifact_id
    artifact_id="$(psql_one "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${NPM_PROXY_REPO_KEY}' AND a.name = '${LODASH_NAME}' AND a.version = '${LODASH_VERSION}' ORDER BY a.created_at DESC LIMIT 1;")"
    if [ -z "$artifact_id" ]; then
        assert_fail \
            "artifact row resolved for (${NPM_PROXY_REPO_KEY}, ${LODASH_NAME}, ${LODASH_VERSION})" \
            "psql returned empty id — proxy ingest didn't write the artifact row"
        return 1
    fi
    assert_pass "artifact row resolved (id=$artifact_id)"

    # Wait for the FIRST ScanCompleted (worker has to claim + run).
    log "  waiting for initial ScanCompleted (deadline ${SCAN_FIRST_TIMEOUT_SECS}s)"
    if ! bounded_poll \
            "initial ScanCompleted for ${artifact_id}" \
            "$SCAN_FIRST_TIMEOUT_SECS" \
            "[ \"\$(psql_count \"SELECT COUNT(*) FROM events WHERE event_type = 'ScanCompleted' AND stream_id = '${artifact_id}';\")\" -ge 1 ]" \
            2; then
        assert_fail \
            "initial ScanCompleted within ${SCAN_FIRST_TIMEOUT_SECS}s" \
            "no ScanCompleted event for stream_id=$artifact_id"
        log "  hort-worker logs (last 50 lines):"
        docker compose -f "$COMPOSE_FILE" logs --tail=50 hort-worker 2>&1 \
            | sed 's/^/    /' || true
        return 1
    fi
    assert_pass "initial ScanCompleted fired for $artifact_id"

    # Confirm artifacts.last_scan_at is non-null and recent.
    local last_scan_at
    last_scan_at="$(psql_one "SELECT last_scan_at FROM artifacts WHERE id = '${artifact_id}';")"
    if [ -n "$last_scan_at" ]; then
        assert_pass "artifacts.last_scan_at populated ($last_scan_at)"
    else
        assert_fail \
            "artifacts.last_scan_at populated" \
            "column NULL after initial scan — projector did not advance the timestamp"
    fi

    # 5. Force the eligibility window. Backdate by 2 hours (past the
    # 1-hour interval) so cron-rescan-tick picks the artifact up.
    log ""
    log "--> [4/8] backdate last_scan_at by 2 hours (test pinning)"
    local update_out
    update_out="$(docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -c \
        "UPDATE artifacts SET last_scan_at = NOW() - INTERVAL '2 hours' WHERE id = '${artifact_id}';" 2>&1 \
        || true)"
    if printf '%s\n' "$update_out" | grep -q "UPDATE 1"; then
        assert_pass "psql UPDATE backdated last_scan_at by 2h (artifact eligible for rescan)"
    else
        assert_fail \
            "psql UPDATE backdated last_scan_at" \
            "expected 'UPDATE 1' in output, got: $update_out"
        return 1
    fi

    # 6. Invoke cron-rescan-tick via hort-cli.
    log ""
    log "--> [5/8] hort-cli admin task invoke cron-rescan-tick"
    local invoke_out invoke_rc=0
    invoke_out="$("$hort_cli" admin task invoke cron-rescan-tick \
        --output json 2>&1)" || invoke_rc=$?
    if [ $invoke_rc -ne 0 ]; then
        assert_fail \
            "hort-cli admin task invoke cron-rescan-tick exits 0 with 202" \
            "exit=$invoke_rc, output: $invoke_out"
        return 1
    fi
    local task_job_id
    task_job_id="$(printf '%s' "$invoke_out" \
        | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('task_job_id',''))" 2>/dev/null \
        || echo "")"
    if [ -n "$task_job_id" ]; then
        assert_pass "cron-rescan-tick invoke returned task_job_id ($task_job_id)"
    else
        assert_fail \
            "cron-rescan-tick invoke returned task_job_id" \
            "could not parse task_job_id from CLI output: $invoke_out"
        return 1
    fi

    # 7. Poll for >=2 ScanCompleted events on the artifact stream.
    log ""
    log "--> [6/8] poll for >= 2 ScanCompleted (deadline ${SCAN_RESCAN_TIMEOUT_SECS}s)"
    if bounded_poll \
            "2nd ScanCompleted for ${artifact_id}" \
            "$SCAN_RESCAN_TIMEOUT_SECS" \
            "[ \"\$(psql_count \"SELECT COUNT(*) FROM events WHERE event_type = 'ScanCompleted' AND stream_id = '${artifact_id}';\")\" -ge 2 ]" \
            2; then
        local n
        n="$(psql_count "SELECT COUNT(*) FROM events WHERE event_type = 'ScanCompleted' AND stream_id = '${artifact_id}';")"
        assert_pass "2nd ScanCompleted fired (count=$n)"
    else
        local n
        n="$(psql_count "SELECT COUNT(*) FROM events WHERE event_type = 'ScanCompleted' AND stream_id = '${artifact_id}';" || echo "?")"
        assert_fail \
            "2nd ScanCompleted within ${SCAN_RESCAN_TIMEOUT_SECS}s" \
            "ScanCompleted count for stream_id=$artifact_id stuck at $n — cron handler did not enqueue OR worker did not claim"
        log "  hort-worker logs (last 50 lines):"
        docker compose -f "$COMPOSE_FILE" logs --tail=50 hort-worker 2>&1 \
            | sed 's/^/    /' || true
    fi

    # 8. Manual rescan via hort-cli.
    log ""
    log "--> [7/8] hort-cli admin rescan $artifact_id"
    local rescan_out rescan_rc=0
    rescan_out="$("$hort_cli" admin rescan "$artifact_id" \
        --output json 2>&1)" || rescan_rc=$?
    if [ $rescan_rc -ne 0 ]; then
        assert_fail \
            "hort-cli admin rescan exits 0 (server returns 202)" \
            "exit=$rescan_rc, output: $rescan_out"
    else
        local manual_job_id
        manual_job_id="$(printf '%s' "$rescan_out" \
            | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('task_job_id',''))" 2>/dev/null \
            || echo "")"
        if [ -n "$manual_job_id" ]; then
            assert_pass "manual rescan returned task_job_id ($manual_job_id)"
        else
            assert_fail \
                "manual rescan returned task_job_id" \
                "could not parse task_job_id from CLI output: $rescan_out"
        fi
    fi

    # Poll for the 3rd ScanCompleted.
    log ""
    log "--> [8/8] poll for >= 3 ScanCompleted (deadline ${SCAN_RESCAN_TIMEOUT_SECS}s)"
    if bounded_poll \
            "3rd ScanCompleted for ${artifact_id}" \
            "$SCAN_RESCAN_TIMEOUT_SECS" \
            "[ \"\$(psql_count \"SELECT COUNT(*) FROM events WHERE event_type = 'ScanCompleted' AND stream_id = '${artifact_id}';\")\" -ge 3 ]" \
            2; then
        local n
        n="$(psql_count "SELECT COUNT(*) FROM events WHERE event_type = 'ScanCompleted' AND stream_id = '${artifact_id}';")"
        assert_pass "3rd ScanCompleted fired (count=$n)"
    else
        local n
        n="$(psql_count "SELECT COUNT(*) FROM events WHERE event_type = 'ScanCompleted' AND stream_id = '${artifact_id}';" || echo "?")"
        assert_fail \
            "3rd ScanCompleted within ${SCAN_RESCAN_TIMEOUT_SECS}s" \
            "ScanCompleted count for stream_id=$artifact_id stuck at $n — manual rescan did not run"
        log "  hort-worker logs (last 50 lines):"
        docker compose -f "$COMPOSE_FILE" logs --tail=50 hort-worker 2>&1 \
            | sed 's/^/    /' || true
    fi

    # 9. Metrics assertions.
    log ""
    log "--> metrics assertions on $METRICS_URL"
    local metrics_body
    metrics_body="$(curl -fsSL --max-time 10 "$METRICS_URL" || true)"
    if [ -z "$metrics_body" ]; then
        assert_fail \
            "/metrics scrape returned a body" \
            "empty body — endpoint unreachable mid-test?"
        return 1
    fi

    # hort_scan_jobs_enqueued_total{trigger_source="cron"} >= 1
    if printf '%s\n' "$metrics_body" \
            | grep -E '^hort_scan_jobs_enqueued_total\{[^}]*trigger_source="cron"' \
            | grep -vE ' 0(\.0+)?$' >/dev/null; then
        assert_pass "hort_scan_jobs_enqueued_total{trigger_source=\"cron\"} >= 1"
    else
        assert_fail \
            "hort_scan_jobs_enqueued_total{trigger_source=\"cron\"} >= 1" \
            "metric absent or zero — cron-rescan-tick handler did not emit"
    fi

    # hort_scan_jobs_enqueued_total{trigger_source="manual"} >= 1
    if printf '%s\n' "$metrics_body" \
            | grep -E '^hort_scan_jobs_enqueued_total\{[^}]*trigger_source="manual"' \
            | grep -vE ' 0(\.0+)?$' >/dev/null; then
        assert_pass "hort_scan_jobs_enqueued_total{trigger_source=\"manual\"} >= 1"
    else
        assert_fail \
            "hort_scan_jobs_enqueued_total{trigger_source=\"manual\"} >= 1" \
            "metric absent or zero — ManualRescanUseCase did not emit"
    fi

    # hort_admin_tasks_completed_total{kind="cron-rescan-tick"} >= 1
    if printf '%s\n' "$metrics_body" \
            | grep -E '^hort_admin_tasks_completed_total\{[^}]*kind="cron-rescan-tick"' \
            | grep -vE ' 0(\.0+)?$' >/dev/null; then
        assert_pass "hort_admin_tasks_completed_total{kind=\"cron-rescan-tick\"} >= 1"
    else
        assert_fail \
            "hort_admin_tasks_completed_total{kind=\"cron-rescan-tick\"} >= 1" \
            "metric absent or zero — TaskDispatcher did not record completion"
    fi
}

# -----------------------------------------------------------------------------
# Driver
# -----------------------------------------------------------------------------

log "==> Rescanning + manual-rescan smoke"
log ""

# Phase 1 — runs first because it has no infrastructure dependency.
# A helm-only failure is still a real failure; surface it. SKIP (rc=2)
# is permitted (helm not installed) — the rest of the smoke continues.
PHASE1_RC=0
phase_1_helm_template_smoke || PHASE1_RC=$?
if [ $PHASE1_RC -eq 2 ]; then
    log "  phase 1 SKIPPED (helm not available); continuing to phase 2"
fi

phase_2_runtime_smoke

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

log ""
log "============================================="
log "  passed: $PASSED"
log "  failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    log "  failures:"
    for f in "${FAILURES[@]}"; do
        log "    - $f"
    done
    log "RESULT: FAIL"
    exit 1
fi
log "RESULT: PASS"
exit 0
