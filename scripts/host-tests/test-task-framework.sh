#!/usr/bin/env bash
# End-to-end smoke for the admin-task framework HTTP surface, metric
# emission, and service-account token bootstrapping.
#
# Exercises the chain:
#   hort-server admin issue-svc-token → token file → HORT_TOKEN env →
#   POST /api/v1/admin/tasks/noop (202) →
#   GET  /api/v1/admin/tasks/:id (200, status=pending|completed) →
#   GET  /metrics → all four hort_admin_tasks_* metric names present →
#   Authorization event stream → TaskInvoked event recorded.
#
# Note on task dispatch: the v1 hort-worker only registers a
# ScanTaskHandler (kind="scan"). The noop and staging-sweep kinds ship
# in hort-app but are not registered in the hort-worker composition.
# A general-purpose task worker that can dispatch noop/staging-sweep is
# not yet deployed. The smoke therefore verifies:
#   1. The HTTP enqueue surface (POST → 202, idempotency, token auth).
#   2. The job row is persisted (GET returns the row, status may be
#      "pending" since no worker claims noop jobs).
#   3. hort_admin_tasks_enqueued_total fires on the server (via /metrics).
#   4. The TaskInvoked audit event is recorded.
#
# This set of assertions validates the HTTP enqueue, persisted job row,
# metric emission, and audit event. Worker dispatch for rescan /
# advisory-watch adds the full claim→complete path.
#
# Skip semantics (mirrors test-vulnerability-scan.sh):
#   - Compose stack not reachable → exit 2 (env unmet, NOT failure).
#   - HORT_TOKEN_ALLOW_ADMIN not set → exit 2 (token bootstrap cannot run).
#
# Exit codes:
#   0 — every assertion passed
#   1 — at least one assertion failed
#   2 — environment unmet (compose unavailable, stack unreachable,
#       admin-token capability not enabled)
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

# Host endpoints — match the v2 stack's 25xxx host port mappings.
API_URL="${API_URL:-http://localhost:25080}"
METRICS_URL="${METRICS_URL:-http://localhost:25090/metrics}"

READY_TIMEOUT_SECS="${READY_TIMEOUT_SECS:-60}"
POLL_TIMEOUT_SECS="${POLL_TIMEOUT_SECS:-30}"

TOKEN_FILE="${TMPDIR:-/tmp}/hort-e2e-task-framework-token-$$.txt"
STAGE_ROOT="${TMPDIR:-/tmp}/hort-task-framework-smoke-$$"

PASSED=0
FAIL=0
declare -a FAILURES=()

# -----------------------------------------------------------------------------
# Logging + assertion helpers (matches the vuln-scan smoke style)
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
# Cleanup — always runs on EXIT
# -----------------------------------------------------------------------------

# shellcheck disable=SC2317  # invoked indirectly via `trap ... EXIT`
cleanup() {
    local ec=$?
    log ""
    log "==> cleanup"
    rm -f "$TOKEN_FILE" 2>/dev/null || true
    rm -rf "$STAGE_ROOT" 2>/dev/null || true
    return "$ec"
}
trap cleanup EXIT

# -----------------------------------------------------------------------------
# Environment / readiness helpers
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

# Bounded poll. Returns 0 when the predicate succeeds, 1 on timeout.
# Every wait in this script routes through this helper — no fixed `sleep N`.
# shellcheck disable=SC2317  # invoked indirectly via wait_for_metrics
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

# Wait for the metrics endpoint to become available.
# shellcheck disable=SC2317  # invoked indirectly via require_stack_up
wait_for_metrics() {
    bounded_poll "hort-server /metrics ready" "$READY_TIMEOUT_SECS" \
        "curl -fsSL -o /dev/null '$METRICS_URL'"
}

# -----------------------------------------------------------------------------
# psql helper — used for audit-event assertion
# -----------------------------------------------------------------------------

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
# Phase 0 — preflight
# -----------------------------------------------------------------------------

log "==> Admin-task framework smoke"
log "compose  : $COMPOSE_FILE"
log "api      : $API_URL"
log "metrics  : $METRICS_URL"
log ""

require_stack_up

mkdir -p "$STAGE_ROOT"

# Check that the admin-token bootstrap capability is configured.
# The flag HORT_TOKEN_ALLOW_ADMIN must be "true" in the hort-server environment
# for `admin issue-svc-token` to mint tokens against the DB.
# The v2 example-config sets this when the dev override profile is active.
ALLOW_ADMIN_TOKENS="$(docker compose -f "$COMPOSE_FILE" \
    exec -T hort-server sh -c 'echo "${HORT_TOKEN_ALLOW_ADMIN:-}"' 2>/dev/null \
    | tr -d '[:space:]' || echo "")"
if [ "$ALLOW_ADMIN_TOKENS" != "true" ]; then
    log "SKIP: HORT_TOKEN_ALLOW_ADMIN != 'true' in hort-server container environment"
    log "      set HORT_TOKEN_ALLOW_ADMIN=true in deploy/compose/docker-compose.yml"
    log "      (or set it in your .env override) to enable service-account token bootstrap"
    exit 2
fi

# -----------------------------------------------------------------------------
# Phase 1 — mint a service-account token
# -----------------------------------------------------------------------------

log ""
log "--> [1/5] mint service-account token (hort-server admin issue-svc-token)"

TOKEN_NAME="e2e-task-framework-$RANDOM"

# Run inside the hort-server container so it has DB access.
RAW_TOKEN="$(docker compose -f "$COMPOSE_FILE" exec -T hort-server \
    /usr/local/bin/hort-server admin issue-svc-token \
    --name="$TOKEN_NAME" \
    --permission=admin_task_invoke \
    --output=stdout 2>/dev/null || true)"

if [ -z "$RAW_TOKEN" ]; then
    assert_fail \
        "hort-server admin issue-svc-token returns a non-empty token" \
        "got empty output — check hort-server logs"
    log "  hort-server logs (last 40 lines):"
    docker compose -f "$COMPOSE_FILE" logs --tail=40 hort-server 2>&1 \
        | sed 's/^/    /' || true
    exit 1
fi

# Write to temp file with restricted permissions.
install -m 0600 /dev/null "$TOKEN_FILE"
printf '%s' "$RAW_TOKEN" > "$TOKEN_FILE"
assert_pass "issue-svc-token returned a non-empty token (name=$TOKEN_NAME)"

# -----------------------------------------------------------------------------
# Phase 2 — POST /api/v1/admin/tasks/noop
# -----------------------------------------------------------------------------

log ""
log "--> [2/5] POST /api/v1/admin/tasks/noop (enqueue task)"

INVOKE_RESP="$(curl -sS \
    -w '\n%{http_code}' \
    -X POST "$API_URL/api/v1/admin/tasks/noop" \
    -H "Authorization: Bearer $RAW_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"label":"e2e-item-13-smoke"}' \
    --max-time 15 2>/dev/null || echo "")"

HTTP_CODE="$(printf '%s\n' "$INVOKE_RESP" | tail -1)"
INVOKE_BODY="$(printf '%s\n' "$INVOKE_RESP" | head -1)"

if [ "$HTTP_CODE" = "202" ]; then
    assert_pass "POST /api/v1/admin/tasks/noop returned 202"
else
    assert_fail \
        "POST /api/v1/admin/tasks/noop returned 202" \
        "got HTTP $HTTP_CODE — body: $INVOKE_BODY"
    log "  abort: cannot poll or assert without a task_job_id"
    exit 1
fi

TASK_JOB_ID="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['task_job_id'])" \
    "$INVOKE_BODY" 2>/dev/null || echo "")"

if [ -n "$TASK_JOB_ID" ]; then
    assert_pass "invoke response contains task_job_id ($TASK_JOB_ID)"
else
    assert_fail \
        "invoke response contains task_job_id" \
        "could not parse task_job_id from: $INVOKE_BODY"
    exit 1
fi

# -----------------------------------------------------------------------------
# Phase 3 — idempotency-key dedup round-trip (returns 200, same job id)
# -----------------------------------------------------------------------------

log ""
log "--> [3/5] idempotency-key dedup (same Idempotency-Key → 200 + same job id)"

IDEM_KEY="e2e-item-13-smoke-idem-$(date +%s)"

# First call with the idempotency key — should be 202.
IDEM_RESP1="$(curl -sS \
    -w '\n%{http_code}' \
    -X POST "$API_URL/api/v1/admin/tasks/noop" \
    -H "Authorization: Bearer $RAW_TOKEN" \
    -H "Content-Type: application/json" \
    -H "Idempotency-Key: $IDEM_KEY" \
    -d '{"label":"idem-test"}' \
    --max-time 15 2>/dev/null || echo "")"
IDEM_CODE1="$(printf '%s\n' "$IDEM_RESP1" | tail -1)"
IDEM_BODY1="$(printf '%s\n' "$IDEM_RESP1" | head -1)"
IDEM_ID1="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['task_job_id'])" \
    "$IDEM_BODY1" 2>/dev/null || echo "")"

# Second call with the same idempotency key — should be 200 (cache hit).
IDEM_RESP2="$(curl -sS \
    -w '\n%{http_code}' \
    -X POST "$API_URL/api/v1/admin/tasks/noop" \
    -H "Authorization: Bearer $RAW_TOKEN" \
    -H "Content-Type: application/json" \
    -H "Idempotency-Key: $IDEM_KEY" \
    -d '{"label":"idem-test"}' \
    --max-time 15 2>/dev/null || echo "")"
IDEM_CODE2="$(printf '%s\n' "$IDEM_RESP2" | tail -1)"
IDEM_BODY2="$(printf '%s\n' "$IDEM_RESP2" | head -1)"
IDEM_ID2="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['task_job_id'])" \
    "$IDEM_BODY2" 2>/dev/null || echo "")"

if [ "$IDEM_CODE1" = "202" ] && [ "$IDEM_CODE2" = "200" ] && \
   [ -n "$IDEM_ID1" ] && [ "$IDEM_ID1" = "$IDEM_ID2" ]; then
    assert_pass "idempotency-key dedup: first=202, second=200, same task_job_id ($IDEM_ID1)"
else
    assert_fail \
        "idempotency-key dedup returns 200 + same task_job_id on repeat" \
        "first: code=$IDEM_CODE1 id=$IDEM_ID1 / second: code=$IDEM_CODE2 id=$IDEM_ID2"
fi

# -----------------------------------------------------------------------------
# Phase 4 — GET the job row, assert it exists
# -----------------------------------------------------------------------------

log ""
log "--> [4/5] GET /api/v1/admin/tasks/$TASK_JOB_ID (poll for row)"

GET_RESP="$(curl -sS \
    -w '\n%{http_code}' \
    -X GET "$API_URL/api/v1/admin/tasks/$TASK_JOB_ID" \
    -H "Authorization: Bearer $RAW_TOKEN" \
    --max-time 15 2>/dev/null || echo "")"
GET_CODE="$(printf '%s\n' "$GET_RESP" | tail -1)"
GET_BODY="$(printf '%s\n' "$GET_RESP" | head -1)"

if [ "$GET_CODE" = "200" ]; then
    assert_pass "GET /api/v1/admin/tasks/$TASK_JOB_ID returned 200"
else
    assert_fail \
        "GET /api/v1/admin/tasks/$TASK_JOB_ID returned 200" \
        "got HTTP $GET_CODE — body: $GET_BODY"
fi

JOB_KIND="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('kind',''))" \
    "$GET_BODY" 2>/dev/null || echo "")"
JOB_STATUS="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('status',''))" \
    "$GET_BODY" 2>/dev/null || echo "")"

if [ "$JOB_KIND" = "noop" ]; then
    assert_pass "job row kind='noop'"
else
    assert_fail "job row kind='noop'" "got kind='$JOB_KIND'"
fi

# The job may be pending (no noop worker registered in v1) or completed
# (if a noop-capable worker is active). Both are valid outcomes for v1.
if [ "$JOB_STATUS" = "pending" ] || [ "$JOB_STATUS" = "completed" ] \
   || [ "$JOB_STATUS" = "running" ]; then
    assert_pass "job status is valid (status='$JOB_STATUS')"
else
    assert_fail \
        "job status is pending|running|completed" \
        "got status='$JOB_STATUS' — row may not have been persisted"
fi

# -----------------------------------------------------------------------------
# Phase 5 — /metrics scrape: all four hort_admin_tasks_* names present
# -----------------------------------------------------------------------------

log ""
log "--> [5/5] /metrics scrape: hort_admin_tasks_* metric names wired"

METRICS_BODY="$(curl -fsSL --max-time 10 "$METRICS_URL" || true)"

declare -a METRIC_NAMES=(
    "hort_admin_tasks_enqueued_total"
    "hort_admin_tasks_completed_total"
    "hort_admin_tasks_duration_seconds"
    "hort_admin_tasks_in_flight"
)

for NAME in "${METRIC_NAMES[@]}"; do
    if printf '%s\n' "$METRICS_BODY" | grep -q "$NAME"; then
        assert_pass "/metrics contains $NAME"
    else
        assert_fail \
            "/metrics contains $NAME" \
            "metric name absent from scrape body — wiring may be incomplete"
    fi
done

# Specifically verify that hort_admin_tasks_enqueued_total{result="ok"} fired
# from our POST call (at least one series with kind + result labels).
ENQUEUED_OK="$(printf '%s\n' "$METRICS_BODY" \
    | grep -c 'hort_admin_tasks_enqueued_total{.*result="ok"' || true)"
if [ "${ENQUEUED_OK:-0}" -ge 1 ] 2>/dev/null; then
    assert_pass "hort_admin_tasks_enqueued_total{result=\"ok\"} series present (count=$ENQUEUED_OK)"
else
    assert_fail \
        "hort_admin_tasks_enqueued_total{result=\"ok\"} series present" \
        "no matching line in /metrics — handler may not be emitting the counter"
fi

# Optional audit-event check: poll psql for a TaskInvoked event.
# Soft-asserted — psql access may not be available in all CI environments.
TASK_INVOKED_COUNT="$(psql_count \
    "SELECT COUNT(*) FROM events WHERE event_type = 'TaskInvoked';" 2>/dev/null || echo "")"
if [ -n "$TASK_INVOKED_COUNT" ]; then
    if [ "$TASK_INVOKED_COUNT" -ge 1 ] 2>/dev/null; then
        assert_pass "TaskInvoked event recorded in event store (count=$TASK_INVOKED_COUNT)"
    else
        assert_fail \
            "TaskInvoked event recorded in event store" \
            "count=$TASK_INVOKED_COUNT — event may not have been persisted"
    fi
else
    log "  SKIP: psql not available — skipping TaskInvoked event assertion"
fi

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
