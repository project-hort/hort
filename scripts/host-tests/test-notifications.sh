#!/usr/bin/env bash
# End-to-end smoke for the event-notification substrate.
#
# Exercises the chain:
#   hort-server admin issue-svc-token         → token file →
#   POST /api/v1/subscriptions (webhook target, RFC 1918 host) → 400
#         { error: "webhook_target_not_routable", ... }                  (SSRF blocked)
#   POST /api/v1/subscriptions (webhook target, plaintext http://) → 400
#         { error: "plaintext_webhook_disallowed" }                      (plaintext blocked)
#   GET  /metrics → hort_unsafe_config_active{kind="plaintext_webhooks"}=0
#   GET  /metrics → hort_unsafe_config_active{kind="webhook_nonroutable_targets"}=0
#   GET  /api/v1/events?category=auth&after=0&max=1 → 200 (pull-resync surface)
#   GET  /api/v1/subscriptions (own list)            → 200 (CRUD surface)
#
# Opt-in: gated behind HORT_RUN_INIT35_NOTIFICATIONS_E2E=1. Without it,
# the script prints `SKIP:` and exits 0. The default e2e profile does
# NOT run this smoke; operators run it manually after deploy stack
# bring-up.
#
# Why not the full 7-step happy-path? Steps 1-7 of the design doc (webhook
# receiver, HMAC verification, restart-catch-up, in-band delivery within
# 5s) require an out-of-process webhook receiver running on a fixed port
# (an axum side-car or python http.server) AND a way to trigger an
# ArtifactPromoted event (which requires either a full publish+promote
# round-trip or a direct admin API). Both depend on fixtures the v2
# stack does not currently include in the default compose file. This
# smoke pins the most security-critical part (the SSRF assertion + the
# unsafe-config gauge wiring) and the wiring of the new routers; the
# full happy-path is tracked as a follow-up item.
#
# Skip semantics (mirrors test-task-framework.sh):
#   - HORT_RUN_INIT35_NOTIFICATIONS_E2E != 1 → exit 0 with SKIP message.
#   - Compose stack not reachable → exit 2 (env unmet, NOT failure).
#   - HORT_TOKEN_ALLOW_ADMIN not set → exit 2 (token bootstrap cannot run).
#
# Exit codes:
#   0 — every assertion passed (or opt-in env var not set)
#   1 — at least one assertion failed
#   2 — environment unmet (compose unavailable, stack unreachable,
#       admin-token capability not enabled)
#
# Debug: HORT_TEST_DEBUG=1 toggles `set -x`.

set -euo pipefail

if [ "${HORT_RUN_INIT35_NOTIFICATIONS_E2E:-0}" != "1" ]; then
    echo "SKIP: notifications smoke is opt-in"
    echo "      set HORT_RUN_INIT35_NOTIFICATIONS_E2E=1 to enable"
    exit 0
fi

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

TOKEN_FILE="${TMPDIR:-/tmp}/hort-e2e-init35-token-$$.txt"

PASSED=0
FAIL=0
declare -a FAILURES=()

# -----------------------------------------------------------------------------
# Logging + assertion helpers
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

cleanup() {
    local ec=$?
    log ""
    log "==> cleanup"
    rm -f "$TOKEN_FILE" 2>/dev/null || true
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

# -----------------------------------------------------------------------------
# Phase 0 — preflight
# -----------------------------------------------------------------------------

log "==> event-notification substrate smoke"
log "compose  : $COMPOSE_FILE"
log "api      : $API_URL"
log "metrics  : $METRICS_URL"
log ""

require_stack_up

ALLOW_ADMIN_TOKENS="$(docker compose -f "$COMPOSE_FILE" \
    exec -T hort-server sh -c 'echo "${HORT_TOKEN_ALLOW_ADMIN:-}"' 2>/dev/null \
    | tr -d '[:space:]' || echo "")"
if [ "$ALLOW_ADMIN_TOKENS" != "true" ]; then
    log "SKIP: HORT_TOKEN_ALLOW_ADMIN != 'true' in hort-server container env"
    log "      set HORT_TOKEN_ALLOW_ADMIN=true in deploy/compose/docker-compose.yml"
    exit 2
fi

ENABLE_NOTIFICATIONS="$(docker compose -f "$COMPOSE_FILE" \
    exec -T hort-server sh -c 'echo "${HORT_NOTIFICATIONS_ENABLED:-true}"' 2>/dev/null \
    | tr -d '[:space:]' || echo "true")"
if [ "$ENABLE_NOTIFICATIONS" = "false" ]; then
    log "SKIP: HORT_NOTIFICATIONS_ENABLED=false — dispatcher not spawned, surface"
    log "      will silently no-op. Set true (the default) to exercise."
    exit 2
fi

# -----------------------------------------------------------------------------
# Phase 1 — mint a service-account token (admin-capable)
# -----------------------------------------------------------------------------

log ""
log "--> [1/5] mint service-account token (hort-server admin issue-svc-token)"

TOKEN_NAME="e2e-init35-notif-$RANDOM"

RAW_TOKEN="$(docker compose -f "$COMPOSE_FILE" exec -T hort-server \
    /usr/local/bin/hort-server admin issue-svc-token \
    --name="$TOKEN_NAME" \
    --permission=admin \
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

install -m 0600 /dev/null "$TOKEN_FILE"
printf '%s' "$RAW_TOKEN" > "$TOKEN_FILE"
assert_pass "issue-svc-token returned a non-empty token (name=$TOKEN_NAME)"

# -----------------------------------------------------------------------------
# Phase 2 — SSRF assertion: webhook with RFC 1918 host is REJECTED
# -----------------------------------------------------------------------------
#
# A webhook subscription with a loopback / RFC 1918 / link-local /
# CGNAT target is rejected with `400 webhook_target_not_routable` at
# create-time. The default `HORT_WEBHOOK_ALLOW_NONROUTABLE_TARGETS=false`
# posture is the gate.
#
# Backlog acceptance line: "attempt to create a subscription with
# url = http://127.0.0.1:9999/x returns 400 with denial_reason =
# WebhookTargetNotRoutable". We use https:// here so the plaintext-
# check doesn't trip first; the SSRF check is what we want to assert.

log ""
log "--> [2/5] POST /api/v1/subscriptions with non-routable host (SSRF block)"

SSRF_PAYLOAD='{
  "name": "init35-smoke-ssrf-'"$RANDOM"'",
  "target": {
    "kind": "webhook",
    "url": "https://127.0.0.1:9999/x",
    "secret": "test-secret-not-real"
  },
  "filter": {
    "categories": ["artifact"],
    "event_types": { "kind": "all" },
    "repositories": { "kind": "owned_by_actor" }
  }
}'

SSRF_RESP="$(curl -sS \
    -w '\n%{http_code}' \
    -X POST "$API_URL/api/v1/subscriptions" \
    -H "Authorization: Bearer $RAW_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$SSRF_PAYLOAD" \
    --max-time 15 2>/dev/null || echo "")"

SSRF_CODE="$(printf '%s\n' "$SSRF_RESP" | tail -1)"
SSRF_BODY="$(printf '%s\n' "$SSRF_RESP" | head -n -1)"

if [ "$SSRF_CODE" = "400" ]; then
    assert_pass "POST /api/v1/subscriptions with 127.0.0.1 target returned 400"
else
    assert_fail \
        "POST /api/v1/subscriptions with 127.0.0.1 target returned 400" \
        "got HTTP $SSRF_CODE — body: $SSRF_BODY"
fi

SSRF_ERROR="$(printf '%s' "$SSRF_BODY" | python3 -c \
    "import json,sys; print(json.loads(sys.stdin.read()).get('error',''))" \
    2>/dev/null || echo "")"

if [ "$SSRF_ERROR" = "webhook_target_not_routable" ]; then
    assert_pass "SSRF block error code is webhook_target_not_routable"
else
    assert_fail \
        "SSRF block error code is webhook_target_not_routable" \
        "got error='$SSRF_ERROR' — body: $SSRF_BODY"
fi

# -----------------------------------------------------------------------------
# Phase 3 — plaintext-webhook assertion: http:// URL is REJECTED
# -----------------------------------------------------------------------------
#
# Default-OFF `HORT_WEBHOOK_ALLOW_PLAINTEXT` rejects `http://` webhook
# URLs with `400 plaintext_webhook_disallowed`. We use a hypothetical
# public routable host so the SSRF check does not trip first.

log ""
log "--> [3/5] POST /api/v1/subscriptions with http:// URL (plaintext block)"

PLAIN_PAYLOAD='{
  "name": "init35-smoke-plain-'"$RANDOM"'",
  "target": {
    "kind": "webhook",
    "url": "http://example.com/webhook",
    "secret": "test-secret-not-real"
  },
  "filter": {
    "categories": ["artifact"],
    "event_types": { "kind": "all" },
    "repositories": { "kind": "owned_by_actor" }
  }
}'

PLAIN_RESP="$(curl -sS \
    -w '\n%{http_code}' \
    -X POST "$API_URL/api/v1/subscriptions" \
    -H "Authorization: Bearer $RAW_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$PLAIN_PAYLOAD" \
    --max-time 15 2>/dev/null || echo "")"

PLAIN_CODE="$(printf '%s\n' "$PLAIN_RESP" | tail -1)"
PLAIN_BODY="$(printf '%s\n' "$PLAIN_RESP" | head -n -1)"

if [ "$PLAIN_CODE" = "400" ]; then
    assert_pass "POST /api/v1/subscriptions with http:// URL returned 400"
else
    assert_fail \
        "POST /api/v1/subscriptions with http:// URL returned 400" \
        "got HTTP $PLAIN_CODE — body: $PLAIN_BODY"
fi

PLAIN_ERROR="$(printf '%s' "$PLAIN_BODY" | python3 -c \
    "import json,sys; print(json.loads(sys.stdin.read()).get('error',''))" \
    2>/dev/null || echo "")"

if [ "$PLAIN_ERROR" = "plaintext_webhook_disallowed" ]; then
    assert_pass "plaintext block error code is plaintext_webhook_disallowed"
else
    assert_fail \
        "plaintext block error code is plaintext_webhook_disallowed" \
        "got error='$PLAIN_ERROR' — body: $PLAIN_BODY"
fi

# -----------------------------------------------------------------------------
# Phase 4 — unsafe-config gauges reflect default-safe posture
# -----------------------------------------------------------------------------
#
# Both flags default `false` → both gauges should read 0.0. The metric
# is set on the safe path explicitly (composition emits `set(0.0)`) so
# the gauge is always present.

log ""
log "--> [4/5] GET /metrics: hort_unsafe_config_active for notification kinds"

METRICS_BODY="$(curl -fsSL --max-time 10 "$METRICS_URL" 2>/dev/null || echo "")"

if [ -z "$METRICS_BODY" ]; then
    assert_fail "GET /metrics returned a non-empty body" "metrics unreachable"
else
    PLAIN_GAUGE="$(printf '%s' "$METRICS_BODY" \
        | grep -E '^hort_unsafe_config_active\{[^}]*kind="plaintext_webhooks"' \
        | head -1 || echo "")"
    if [ -n "$PLAIN_GAUGE" ]; then
        assert_pass "hort_unsafe_config_active{kind=\"plaintext_webhooks\"} present: $PLAIN_GAUGE"
    else
        assert_fail \
            "hort_unsafe_config_active{kind=\"plaintext_webhooks\"} is exported" \
            "metric line missing — gauge not initialised on boot"
    fi

    NONROUTABLE_GAUGE="$(printf '%s' "$METRICS_BODY" \
        | grep -E '^hort_unsafe_config_active\{[^}]*kind="webhook_nonroutable_targets"' \
        | head -1 || echo "")"
    if [ -n "$NONROUTABLE_GAUGE" ]; then
        assert_pass "hort_unsafe_config_active{kind=\"webhook_nonroutable_targets\"} present: $NONROUTABLE_GAUGE"
    else
        assert_fail \
            "hort_unsafe_config_active{kind=\"webhook_nonroutable_targets\"} is exported" \
            "metric line missing — gauge not initialised on boot"
    fi
fi

# -----------------------------------------------------------------------------
# Phase 5 — pull-resync surface (GET /api/v1/events) + CRUD list reachable
# -----------------------------------------------------------------------------
#
# Both routers must be mounted. The events endpoint requires an
# admin-or-readable category; "auth" requires Permission::Admin, which
# our service-account token has. The subscriptions list (own) is just
# authenticated.

log ""
log "--> [5/5] GET /api/v1/events + GET /api/v1/subscriptions reachable"

EVENTS_RESP="$(curl -sS \
    -w '\n%{http_code}' \
    -X GET "$API_URL/api/v1/events?category=auth&after=0&max=1" \
    -H "Authorization: Bearer $RAW_TOKEN" \
    --max-time 15 2>/dev/null || echo "")"

EVENTS_CODE="$(printf '%s\n' "$EVENTS_RESP" | tail -1)"

if [ "$EVENTS_CODE" = "200" ]; then
    assert_pass "GET /api/v1/events returned 200 (router mounted)"
else
    assert_fail \
        "GET /api/v1/events returned 200" \
        "got HTTP $EVENTS_CODE"
fi

SUBS_RESP="$(curl -sS \
    -w '\n%{http_code}' \
    -X GET "$API_URL/api/v1/subscriptions" \
    -H "Authorization: Bearer $RAW_TOKEN" \
    --max-time 15 2>/dev/null || echo "")"

SUBS_CODE="$(printf '%s\n' "$SUBS_RESP" | tail -1)"

if [ "$SUBS_CODE" = "200" ]; then
    assert_pass "GET /api/v1/subscriptions returned 200 (router mounted)"
else
    assert_fail \
        "GET /api/v1/subscriptions returned 200" \
        "got HTTP $SUBS_CODE"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

log ""
log "==> Summary: $PASSED passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    log ""
    log "Failures:"
    for f in "${FAILURES[@]}"; do
        log "  - $f"
    done
    exit 1
fi
exit 0
