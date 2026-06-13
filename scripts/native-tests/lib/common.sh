# shellcheck shell=bash
# scripts/native-tests/lib/common.sh
# Sourced by every scenario inside the client container. Centralizes the
# endpoint/env contract, Keycloak token fetch, assertions, and psql access that
# the old per-script smokes each re-implemented (and drifted on).
#
# Required env (set by run.sh): HORT_URL, KEYCLOAK_URL, METRICS_URL,
#   KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET, FIXTURES.
# Optional: HORT_DB_DSN (when the mode provides `db`).
set -euo pipefail

: "${HORT_URL:?HORT_URL must be set by the runner}"
: "${KEYCLOAK_URL:?KEYCLOAK_URL must be set by the runner}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-hort-server}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-hort-server-secret-dev-only}"
METRICS_URL="${METRICS_URL:-}"   # runner sets it; empty in external mode is OK (assert skips)
FIXTURES="${FIXTURES:-/work/fixtures}"

_PASS=0; _FAIL=0; declare -a _FAILURES=()

log()  { printf '%s\n' "$*"; }
pass() { _PASS=$((_PASS+1)); log "  PASS: $1"; }
fail() { _FAIL=$((_FAIL+1)); _FAILURES+=("$1 :: ${2:-}"); printf '  FAIL: %s :: %s\n' "$1" "${2:-}" >&2; }
skip() { log "SKIP: $1"; exit 77; }  # 77 (autotools convention), distinct from a tool's exit 2 — the runner maps anything but 0/77 to FAIL

# Print a summary and exit 0 (all pass) / 1 (any fail). Call at end of scenario.
summary() {
  log ""; log "  passed: $_PASS  failed: $_FAIL"
  if [ "$_FAIL" -gt 0 ]; then
    for f in "${_FAILURES[@]}"; do log "    - $f"; done
    exit 1
  fi
  exit 0
}

# fetch_token <username> <password> -> prints the Keycloak access_token (ROPC).
fetch_token() {
  local user="$1" pass="$2" resp
  resp="$(curl -sS -X POST "${KEYCLOAK_URL%/}/protocol/openid-connect/token" \
    -d grant_type=password -d "client_id=$KEYCLOAK_CLIENT_ID" \
    -d "client_secret=$KEYCLOAK_CLIENT_SECRET" \
    -d "username=$user" -d "password=$pass" 2>/dev/null || true)"
  printf '%s' "$resp" | jq -r '.access_token // empty'
}

# psql_one <sql> -> single value (requires HORT_DB_DSN; only when mode gives db).
psql_one() { psql "${HORT_DB_DSN:?scenario used psql without HORT_DB_DSN (needs requires: db)}" -tAX -c "$1" 2>/dev/null | tr -d '[:space:]'; }
psql_exec() { psql "${HORT_DB_DSN:?scenario used psql without HORT_DB_DSN}" -c "$1" 2>&1; }

# assert_metric_ingest <format> — assert a successful-ingest metric is present.
# Presence check, sound only on a FRESH stack (compose `down -v` -> `up` zeroes
# the counter). On a long-lived external hort a stale tick would make it hollow,
# and /metrics often isn't on the public port (deployment-topology), so:
# it fails ONLY when METRICS_URL is reachable AND the metric is absent; when
# METRICS_URL is unset or unreachable it logs a note and returns 0. The
# publish->install round-trip the scenario already did is the real external gate.
assert_metric_ingest() {
  local fmt="$1" snap
  if [ -z "${METRICS_URL:-}" ]; then log "  note: METRICS_URL unset — skip ingest-metric assert ($fmt)"; return 0; fi
  if ! snap="$(curl -sf "$METRICS_URL" 2>/dev/null)"; then
    log "  note: METRICS_URL ($METRICS_URL) unreachable — skip ingest-metric assert ($fmt)"; return 0
  fi
  if printf '%s' "$snap" | grep -Eq "^hort_ingest_total\{[^}]*format=\"${fmt}\"[^}]*result=\"success\"[^}]*\}"; then
    pass "hort_ingest_total{format=\"$fmt\",result=\"success\"} present"
  else
    fail "ingest metric for $fmt" "no hort_ingest_total{format=\"$fmt\",result=\"success\"} at $METRICS_URL"
  fi
}

# bounded_poll <label> <timeout_secs> <predicate> [interval_secs] — eval the
# predicate string every interval until it succeeds (exit 0) or the timeout
# elapses (returns 1, logs a timeout line). `eval` runs in THIS shell, so the
# predicate sees the lib helpers (psql_one, …) and scenario vars without any
# `export -f` dance. Used by the scanning + quarantine scenarios that wait for an
# async projection/worker outcome instead of sleeping a fixed amount.
bounded_poll() {
  local label="$1" timeout="$2" predicate="$3" interval="${4:-2}" deadline
  deadline=$(( $(date +%s) + timeout ))
  while :; do
    if eval "$predicate" >/dev/null 2>&1; then return 0; fi
    if [ "$(date +%s)" -ge "$deadline" ]; then log "  bounded_poll($label) timed out after ${timeout}s"; return 1; fi
    sleep "$interval"
  done
}
