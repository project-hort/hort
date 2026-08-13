# shellcheck shell=bash
# scripts/native-tests/lib/common.sh
# Sourced by every scenario inside the client container. Centralizes the
# endpoint/env contract, Keycloak token fetch, assertions, and psql access that
# the old per-script smokes each re-implemented (and drifted on).
#
# Required env (set by run.sh): HORT_URL, KEYCLOAK_URL, METRICS_URL,
#   METRICS_TOKEN, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET, FIXTURES.
# Optional: HORT_DB_DSN (when the mode provides `db`).
set -euo pipefail

: "${HORT_URL:?HORT_URL must be set by the runner}"
: "${KEYCLOAK_URL:?KEYCLOAK_URL must be set by the runner}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-hort-server}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-hort-server-secret-dev-only}"
METRICS_URL="${METRICS_URL:-}"   # runner sets it; empty in external mode is OK (assert skips)
# read_metrics-granted bearer for scraping $METRICS_URL (#113 item 5 — the
# anon-hatch retirement means every /metrics scrape needs one). run.sh
# admin-mints this once per compose run against the metrics-scraper SA;
# empty in external mode unless the caller sets it. METRICS_AUTH_HEADER is
# the curl-args array every scrape call site splices in — empty array when
# no token, so an unauthenticated curl (and its now-expected 401) is what
# actually runs rather than the array silently vanishing a flag.
METRICS_TOKEN="${METRICS_TOKEN:-}"
METRICS_AUTH_HEADER=()
if [ -n "$METRICS_TOKEN" ]; then METRICS_AUTH_HEADER=(-H "Authorization: Bearer ${METRICS_TOKEN}"); fi
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

# mint_svc_token <sa-username> <repo-key>[,<repo-key>...] <perm>[,<perm>...] ->
# prints a minted hort_svc_* token on stdout, scoped to the given repos with
# the given declared permissions. Resolves the SA's backing user
# (`sa:<sa-username>`) and each repo's uuid via HORT_DB_DSN psql --
# `repositories.key` holds the scenario-facing repo key, `.name` is only the
# display name -- then admin-mints with BOTH `declared_permissions` AND
# `repository_ids` set, so the mint authorizes against the per-repo
# cap-vs-authority branch (api_token_use_case.rs run_issuance_gates,
# `Some(ids)` arm) instead of the global branch (`None` arm), which a
# repo-scoped-only SA can never satisfy ("a per-repo-only grantee CANNOT
# mint a global token, only a per-repo one").
#
# On ANY failed stage -- admin-token fetch, SA-uid resolution, repo-uuid
# resolution, or the mint POST itself (non-201, or 201 with no `.token`) --
# prints the failing stage, HTTP status where applicable, and a body excerpt
# to stderr, then returns non-zero. Never a silent empty-token success: this
# replaces three bespoke mint blocks whose `| jq -r '.token // empty'`
# swallowed the failure reason.
mint_svc_token() {
  local sa_user="$1" repo_keys_csv="$2" perms_csv="$3"
  local admin_token uid key rid resp http_code body token
  local -a repo_ids=()

  admin_token="$(fetch_token admin admin)"
  if [ -z "$admin_token" ]; then
    echo "mint_svc_token(${sa_user}): [fetch admin token] empty response from Keycloak" >&2
    return 1
  fi

  uid="$(psql_one "SELECT id FROM users WHERE username='sa:${sa_user}';")"
  if [ -z "$uid" ]; then
    echo "mint_svc_token(${sa_user}): [resolve backing user] no users row 'sa:${sa_user}' -- gitops service-accounts/${sa_user}.yaml not applied?" >&2
    return 1
  fi

  IFS=',' read -ra _mint_svc_token_repo_keys <<< "$repo_keys_csv"
  for key in "${_mint_svc_token_repo_keys[@]}"; do
    rid="$(psql_one "SELECT id FROM repositories WHERE key='${key}';")"
    if [ -z "$rid" ]; then
      echo "mint_svc_token(${sa_user}): [resolve repository id] no repositories row with key='${key}'" >&2
      return 1
    fi
    repo_ids+=("$rid")
  done

  resp="$(curl -sS -w '\n%{http_code}' -X POST \
    -H "Authorization: Bearer ${admin_token}" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg name "${sa_user}-e2e-$(date +%s)" \
              --arg perms "$perms_csv" \
              --argjson repo_ids "$(printf '%s\n' "${repo_ids[@]}" | jq -R . | jq -s .)" \
              '{name: $name, declared_permissions: ($perms | split(",")), repository_ids: $repo_ids, expires_in_days: 1}')" \
    "${HORT_URL}/api/v1/admin/users/${uid}/tokens" 2>/dev/null)"
  http_code="${resp##*$'\n'}"
  body="${resp%$'\n'*}"

  if [ "$http_code" != "201" ]; then
    echo "mint_svc_token(${sa_user}): [admin-mint POST /api/v1/admin/users/${uid}/tokens] HTTP ${http_code} -- $(printf '%s' "$body" | head -c 300)" >&2
    return 1
  fi

  token="$(printf '%s' "$body" | jq -r '.token // empty')"
  if [ -z "$token" ]; then
    echo "mint_svc_token(${sa_user}): [admin-mint POST] HTTP 201 with no .token field -- $(printf '%s' "$body" | head -c 300)" >&2
    return 1
  fi

  printf '%s' "$token"
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
    # stderr, not log() (stdout): callers that resolve an id via
    # `x="$(some_fn_calling_bounded_poll ...)"` would otherwise capture this
    # line as part of the id.
    if [ "$(date +%s)" -ge "$deadline" ]; then printf '  bounded_poll(%s) timed out after %ss\n' "$label" "$timeout" >&2; return 1; fi
    sleep "$interval"
  done
}

# metrics_scrape_diag <url> — one-shot GET of a metrics endpoint, echoes
# "HTTP <code> (curl exit <n>)" for FAIL-message diagnostics. `-w
# '%{http_code}'` without `-f` so a non-2xx still yields a real status
# instead of curl swallowing the body and reporting only exit 22; a
# transport-level failure (no response at all) surfaces as HTTP <none>
# with the actual curl exit code. Never itself fails the caller.
metrics_scrape_diag() {
  local url="$1" code rc
  code=$(curl -s "${METRICS_AUTH_HEADER[@]}" -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null)
  rc=$?
  printf 'HTTP %s (curl exit %d)' "${code:-<none>}" "$rc"
}

# metrics_scrape_preflight <label> — posture-aware gate for scenarios that
# read metric VALUES directly (before/after deltas, sums) rather than via
# assert_metric_ingest's single presence poll, where a masked-as-zero scrape
# would misread as "the metric is legitimately absent" instead of "the scrape
# itself failed". Returns 0 when a real scrape is safe to rely on (both
# METRICS_URL and METRICS_TOKEN set, and one reachability probe already
# succeeded); returns 1 otherwise, having already done the right thing for
# each disposition:
#   - METRICS_URL or METRICS_TOKEN unset: a genuinely-absent input (external
#     mode without a minted/supplied credential) — logs a note and returns 1;
#     the caller must skip its metric assertion(s) without touching _FAIL.
#   - both set but the endpoint answers non-2xx: a real regression (grant/
#     token problem, or the stack genuinely isn't up) — calls `fail` with the
#     HTTP status via metrics_scrape_diag and returns 1.
# Mirrors assert_metric_ingest's own unset-branch wording and
# scenarios/proxy/pull-dedup.sh's preflight, generalised for callers that
# need more than a single presence poll.
metrics_scrape_preflight() {
  local label="$1"
  if [ -z "${METRICS_URL:-}" ]; then
    log "  note: METRICS_URL unset — skip ${label}"
    return 1
  fi
  if [ -z "${METRICS_TOKEN:-}" ]; then
    log "  note: METRICS_TOKEN unset (no read_metrics bearer available) — skip ${label}"
    return 1
  fi
  if ! curl -sf "${METRICS_AUTH_HEADER[@]}" -o /dev/null --max-time 5 "$METRICS_URL" 2>/dev/null; then
    fail "${label}" \
      "GET $METRICS_URL with a read_metrics bearer returned non-2xx (grant/token regression, or the stack genuinely isn't up) -- $(metrics_scrape_diag "$METRICS_URL")"
    return 1
  fi
  return 0
}

# assert_metric_ingest <format> — assert a successful-ingest metric is present.
# Presence check, sound only on a FRESH stack (compose `down -v` -> `up` zeroes
# the counter). On a long-lived external hort a stale tick would make it hollow,
# and /metrics often isn't on the public port (deployment-topology), so:
# it fails ONLY when METRICS_URL is reachable AND the metric is absent after
# the poll below; when METRICS_URL is unset or unreachable it logs a note and
# returns 0. The publish->install round-trip the scenario already did is the
# real external gate.
#
# issue #79: a single point-in-time scrape flaked the v0.9.13 release gate
# (clients/pypi failed attempt 1, passed an identical-commit re-run) — a
# classic completion-vs-scrape timing race, the same class maven.sh's own
# ingest-metric check independently diagnosed ("the line is present on the
# same endpoint moments later from an idle probe"). Bounded-poll via the
# shared `bounded_poll` idiom instead of one scrape: a passing run still hits
# on the FIRST poll attempt (no slower than before), a slow-to-render run
# gets up to 60s (2s interval) before this hard-fails. `$METRICS_URL` and
# `${METRICS_AUTH_HEADER[@]}` in the predicate are deliberately deferred
# (escaped) rather than expanded here, so the curl re-runs fresh on every
# poll attempt — mirrors maven.sh's own bounded_poll predicate quoting.
#
# #113 item 5: `/metrics` now always requires a `read_metrics` bearer (no
# anon-scrape opt-out — item 3), so a scrape needs BOTH `METRICS_URL` and
# `METRICS_TOKEN`. Only a genuinely-absent input (either env var unset —
# external-hort mode without a minted/supplied credential) stays a graceful
# skip; once both are present, a non-2xx or an absent metric is a real FAIL
# — the anon-hatch retirement is exactly why this assertion needs a token
# to mean anything again.
assert_metric_ingest() {
  local fmt="$1"
  if [ -z "${METRICS_URL:-}" ]; then log "  note: METRICS_URL unset — skip ingest-metric assert ($fmt)"; return 0; fi
  if [ -z "${METRICS_TOKEN:-}" ]; then
    log "  note: METRICS_TOKEN unset (no read_metrics bearer available) — skip ingest-metric assert ($fmt)"
    return 0
  fi
  if ! curl -sf "${METRICS_AUTH_HEADER[@]}" -o /dev/null --max-time 5 "$METRICS_URL" 2>/dev/null; then
    fail "ingest metric for $fmt" \
      "GET $METRICS_URL with a read_metrics bearer returned non-2xx (grant/token regression, or the stack genuinely isn't up) -- $(metrics_scrape_diag "$METRICS_URL")"
    return
  fi
  if bounded_poll "ingest-metric($fmt)" 60 \
      "curl -sf \"\${METRICS_AUTH_HEADER[@]}\" \"\$METRICS_URL\" 2>/dev/null | grep -Eq '^hort_ingest_total\{[^}]*format=\"${fmt}\"[^}]*result=\"success\"[^}]*\}'"; then
    pass "hort_ingest_total{format=\"$fmt\",result=\"success\"} present"
  else
    fail "ingest metric for $fmt" \
      "no hort_ingest_total{format=\"$fmt\",result=\"success\"} at $METRICS_URL after 60s poll -- last scrape: $(metrics_scrape_diag "$METRICS_URL")"
  fi
}
