#!/usr/bin/env bash
# Shared helpers for the curator-surface E2E scenarios.
#
# Sourced by every scenario script under scripts/e2e/curation/ AND by the
# top-level run.sh orchestrator. Provides:
#
#   1. log/assert helpers (PASS/FAIL counters in scope of the sourcing
#      script — each scenario tracks its own pass/fail counts).
#   2. Compose-stack reachability + readiness probes (mirrors
#      test-task-framework.sh's skip semantics: exit 2 = env unmet).
#   3. Keycloak token-fetch helpers — admin token (via ROPC against the
#      e2e realm, identical pattern to scripts/native-tests/run.sh --hort=compose) and
#      a "curator-only" token (the readers user in the e2e realm — has
#      neither Curate nor Admin claims; used by Scenario 8 negative
#      privilege denial).
#   4. hort-cli wrapper (`run_hort_cli`) that injects HORT_API_URL + HORT_TOKEN
#      so a scenario script can call `run_hort_cli curation waive …`
#      without scattering env-var plumbing through every call site.
#   5. psql one-shot + count helpers for event-stream + projection
#      assertions (same pattern as test-task-framework.sh).
#   6. Curator bootstrap (`setup_curator_grant`) — applies a transient
#      `PermissionGrant kind=User permission=curate` envelope targeting
#      the admin user's UUID via the existing gitops apply path, then
#      restores the canonical config tree on EXIT. Justification: the
#      curator-workflow.md grant flow is the only audited path
#      (direct DB inserts are forbidden), and "claim-based" grants
#      against the dev realm's `test-developers` group conflict with the
#      single-claim-grant linter unless paired with another
#      claim — adding a second claim to the realm is heavier than
#      granting curate to a known user UUID. We grant curate to the
#      `admin` user (which already short-circuits authorize via the
#      `admin` claim — the grant adds Curate without removing Admin) AND
#      separately to a `developer` user (Curate-only, used by several
#      scenarios so the assertions distinguish curator-attribution from
#      admin-attribution).
#
# Exit-code contract (mirrors test-task-framework.sh + test-rescanning.sh):
#   0 — scenario / orchestrator passed
#   1 — at least one assertion failed
#   2 — environment unmet (v2 stack not running, Keycloak unreachable,
#       HORT_TOKEN_ALLOW_ADMIN not set, hort-cli binary missing). Treat as
#       SKIP at the caller layer.
#
# Skip semantics: every scenario's `require_*` preflight bails with
# exit 2 BEFORE counting any failures. The orchestrator (`run.sh`)
# treats exit 2 as SKIP and continues to the next scenario.

# shellcheck disable=SC2034  # PASSED/FAIL declared here, mutated by sourcing script
set -uo pipefail

# -----------------------------------------------------------------------------
# Paths + endpoints
# -----------------------------------------------------------------------------

# REPO_ROOT — derived once; every sourcing script can rely on this.
if [ -z "${REPO_ROOT:-}" ]; then
    # _lib.sh lives at $REPO_ROOT/scripts/e2e/curation/_lib.sh, so go up 3.
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
fi
export REPO_ROOT

COMPOSE_FILE="${COMPOSE_FILE:-$REPO_ROOT/deploy/compose/docker-compose.yml}"
API_URL="${API_URL:-http://localhost:25080}"
METRICS_URL="${METRICS_URL:-http://localhost:25090/metrics}"
KEYCLOAK_TOKEN_URL="${KEYCLOAK_TOKEN_URL:-http://localhost:25082/realms/hort/protocol/openid-connect/token}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-hort-server}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-hort-server-secret-dev-only}"

READY_TIMEOUT_SECS="${READY_TIMEOUT_SECS:-60}"

# hort-cli binary — release-built into target/release by the v2 CI lane;
# fallback to debug if release isn't there.
HORT_CLI_BIN="${HORT_CLI_BIN:-$REPO_ROOT/target/release/hort-cli}"
if [ ! -x "$HORT_CLI_BIN" ]; then
    HORT_CLI_BIN="$REPO_ROOT/target/debug/hort-cli"
fi

# -----------------------------------------------------------------------------
# Logging + assertion helpers
# -----------------------------------------------------------------------------

# Each sourcing script declares its own PASSED / FAIL / FAILURES — these are
# initialised to 0 / 0 / () IF the sourcing script hasn't done so already.
: "${PASSED:=0}"
: "${FAIL:=0}"
if ! declare -p FAILURES >/dev/null 2>&1; then
    declare -ga FAILURES=()
fi

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

print_summary() {
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
        return 1
    fi
    log "RESULT: PASS"
    return 0
}

# -----------------------------------------------------------------------------
# Compose / readiness
# -----------------------------------------------------------------------------

compose_available() {
    docker compose -f "$COMPOSE_FILE" ps >/dev/null 2>&1
}

# Bail with exit 2 (SKIP) when the v2 stack isn't up — the curator E2E
# is meaningless without hort-server + Postgres + Keycloak. Mirrors
# test-task-framework.sh's require_stack_up.
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
    if ! curl -fsSL -o /dev/null --max-time 5 \
        "${KEYCLOAK_TOKEN_URL%/protocol/openid-connect/token}/.well-known/openid-configuration"; then
        log "SKIP: Keycloak unreachable at $KEYCLOAK_TOKEN_URL"
        exit 2
    fi
}

require_hort_cli() {
    if [ ! -x "$HORT_CLI_BIN" ]; then
        log "SKIP: hort-cli binary not found at $HORT_CLI_BIN"
        log "      build it with: cargo build -p hort-cli --release"
        exit 2
    fi
}

# Used by the orchestrator (NOT the individual scenarios, which still call
# require_stack_up): bring the compose stack up if it isn't already, so a
# standalone `run.sh` "just works". Sets STACK_STARTED=1 iff WE started it, so
# teardown_stack_if_started tears down only a stack we own (an already-running
# stack the operator brought up is left alone). Exit 2 if docker is unavailable
# or the stack never becomes ready.
STACK_STARTED=0
ensure_stack_up() {
    if ! command -v docker >/dev/null 2>&1; then
        log "SKIP: docker not available — the curator E2E needs a compose stack"
        exit 2
    fi
    if curl -fsSL -o /dev/null --max-time 3 "$METRICS_URL" 2>/dev/null; then
        log "  using the already-running stack ($METRICS_URL)"
        return 0
    fi
    log "  no stack up — bringing up $COMPOSE_FILE (this can take a minute) ..."
    if ! docker compose -f "$COMPOSE_FILE" up -d --build >/tmp/curation-stack-up.log 2>&1; then
        log "SKIP: 'docker compose up' failed — see /tmp/curation-stack-up.log"
        sed 's/^/    /' /tmp/curation-stack-up.log 2>/dev/null | tail -15
        exit 2
    fi
    STACK_STARTED=1
    local kc_disc deadline
    kc_disc="${KEYCLOAK_TOKEN_URL%/protocol/openid-connect/token}/.well-known/openid-configuration"
    deadline=$(( $(date +%s) + READY_TIMEOUT_SECS ))
    while :; do
        if curl -fsSL -o /dev/null --max-time 3 "$METRICS_URL" 2>/dev/null \
           && curl -fsSL -o /dev/null --max-time 3 "$kc_disc" 2>/dev/null; then
            log "  stack ready"
            return 0
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            log "SKIP: stack did not become ready within ${READY_TIMEOUT_SECS}s"
            exit 2
        fi
        sleep 2
    done
}

# Tear down the stack ONLY if ensure_stack_up started it (and not --keep).
teardown_stack_if_started() {
    [ "${STACK_STARTED:-0}" = "1" ] || return 0
    if [ "${CURATION_KEEP_STACK:-0}" = "1" ]; then
        log "  --keep: leaving the stack up"
        return 0
    fi
    log "  tearing down the stack we started"
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}

# Bounded poll — returns 0 when the predicate succeeds, 1 on timeout.
bounded_poll() {
    local label="$1" timeout_secs="$2" predicate_cmd="$3" interval="${4:-2}"
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

# -----------------------------------------------------------------------------
# Keycloak token-fetch helpers
# -----------------------------------------------------------------------------

# Mint a Keycloak access token via ROPC. Echoes the bare token on stdout.
# Returns non-zero on Keycloak rejection (caller decides whether to exit 1
# or treat as SKIP per its own contract).
keycloak_token() {
    local username="$1" password="$2"
    local resp_file
    resp_file="$(mktemp)"
    local status
    status=$(curl -sS -X POST "$KEYCLOAK_TOKEN_URL" \
        -d "grant_type=password" \
        -d "client_id=$KEYCLOAK_CLIENT_ID" \
        -d "client_secret=$KEYCLOAK_CLIENT_SECRET" \
        -d "username=$username" \
        -d "password=$password" \
        -o "$resp_file" -w "%{http_code}" \
        --max-time 10 2>/dev/null || echo "000")
    if [ "$status" != "200" ]; then
        log "  keycloak_token($username): HTTP $status — body:"
        sed 's/^/    /' "$resp_file" >&2 || true
        rm -f "$resp_file"
        return 1
    fi
    python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["access_token"])' \
        < "$resp_file"
    rm -f "$resp_file"
}

# -----------------------------------------------------------------------------
# hort-cli wrapper — injects HORT_API_URL + token into the call
# -----------------------------------------------------------------------------

# Usage:
#   run_hort_cli <token> -- <hort-cli subcommand and args>
#
# Example:
#   run_hort_cli "$CURATOR_TOKEN" -- curation waive "$AID" --justification "..."
#
# All output captured; exit code preserved. We do NOT use `hort-cli auth login`
# (the v2 dev stack has its own flow) — instead we set HORT_TOKEN env var
# directly via HORT_TOKEN env, and select the server with the global `--server`
# flag (precedence: flag > HORT_SERVER env > ~/.hort/config.toml), so a local
# stack isn't shadowed by a prior `hort-cli auth login` against a real
# deployment. (The flag is honored by `curation`/`admin` as of the fix that
# threads cli.server/cli.token into those subcommands.)
run_hort_cli() {
    local token="$1"
    shift
    # `--` separator is conventional but not required by clap; we accept
    # it and skip it if present.
    if [ "${1:-}" = "--" ]; then
        shift
    fi
    HORT_TOKEN="$token" "$HORT_CLI_BIN" --server "$API_URL" --output json "$@"
}

# Same as run_hort_cli but DOES NOT pass --output json (uses default table).
# A few scenarios prefer the table output for human-readable assertion
# inputs (e.g. assert a specific column highlighted in red).
run_hort_cli_table() {
    local token="$1"
    shift
    if [ "${1:-}" = "--" ]; then
        shift
    fi
    HORT_TOKEN="$token" "$HORT_CLI_BIN" --server "$API_URL" "$@"
}

# -----------------------------------------------------------------------------
# psql helpers — used for event-stream + projection assertions
# -----------------------------------------------------------------------------

# Run a one-shot SQL against the compose Postgres; returns the trimmed output.
# Returns empty string if psql is not reachable.
psql_one() {
    local sql="$1"
    docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -tAX -c "$sql" 2>/dev/null \
        | tr -d '[:space:]'
}

# psql_count — wraps `SELECT COUNT(*) FROM …` and returns 0 on empty.
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

# psql_lines — multi-line output (returns rows separated by newlines).
psql_lines() {
    local sql="$1"
    docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -tAX -c "$sql" 2>/dev/null
}

# Raw psql (stdout+stderr) — for seeding INSERTs where we want to see the
# `INSERT 0 1` affirmation / error text, unlike psql_one which discards stderr.
psql_exec() {
    local sql="$1"
    docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -c "$sql" 2>&1
}

export -f psql_one psql_count psql_lines psql_exec
export COMPOSE_FILE

# -----------------------------------------------------------------------------
# Fixture seeding
# -----------------------------------------------------------------------------
#
# The curator scenarios pick their target artifacts with global
# `... ORDER BY created_at DESC LIMIT 1` queries against the artifacts table, so
# they need pre-existing artifacts in specific quarantine states. On a fresh
# stack none exist and every scenario self-skips. seed_curation_fixtures inserts
# a dedicated repo + a controlled set of artifacts (created_at staged so each
# scenario consumes the row meant for it, even as earlier scenarios mutate
# state); cleanup_curation_fixtures removes them. Direct psql seeding mirrors the
# patch-candidate native scenario — the curator endpoints are the read/decision
# surface under test, and the full ingest+scan pipeline is covered elsewhere.
CURATION_SEED_REPO_ID=""
CURATION_SEED_REPO_KEY=""
CURATION_SEED_SCANNER=""

# _seed_curation_artifact <name> <version> <status> <age_seconds> -> prints id
_seed_curation_artifact() {
    local name="$1" ver="$2" status="$3" age="$4" sha win
    sha="$(printf '%s' "${name}-${ver}-${status}-${CURATION_SEED_SCANNER}" | sha256sum | awk '{print $1}')"
    win="NULL"
    [ "$status" = "quarantined" ] && win="now() + interval '71 hours'"
    psql_exec "INSERT INTO artifacts (
            repository_id, path, name, version, size_bytes, checksum_sha256,
            content_type, storage_key, name_as_published, quarantine_status,
            quarantine_window_start, created_at, updated_at
        ) VALUES (
            '${CURATION_SEED_REPO_ID}', '${name}-${ver}.tgz', '${name}', '${ver}',
            100, '${sha}', 'application/octet-stream', 'curation-e2e/${sha}',
            '${name}', '${status}', ${win},
            now() - interval '${age} seconds', now()
        ) RETURNING id;" | grep -Eo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1
}

seed_curation_fixtures() {
    local nonce
    nonce="$(date +%s)-$$"
    CURATION_SEED_REPO_KEY="curation-e2e-${nonce}"
    CURATION_SEED_SCANNER="curation-e2e-${nonce}"

    local out
    out="$(psql_exec "INSERT INTO repositories (
            key, name, format, repo_type, storage_path, upstream_url
        ) VALUES (
            '${CURATION_SEED_REPO_KEY}', 'curation e2e fixtures', 'npm', 'proxy',
            'curation-e2e', 'https://registry.npmjs.org'
        ) RETURNING id;")"
    CURATION_SEED_REPO_ID="$(printf '%s\n' "$out" | grep -Eo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)"
    if [ -z "$CURATION_SEED_REPO_ID" ]; then
        log "  seed: repository INSERT failed:"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi

    # NEWEST released → scenario 2 blocks this one (not the 4-version package).
    _seed_curation_artifact curblock 1.0 released 1 >/dev/null
    # 2 quarantined → scenarios 1 (newest) and 9 (the other).
    _seed_curation_artifact curq 1.0 quarantined 30 >/dev/null
    _seed_curation_artifact curq 1.1 quarantined 60 >/dev/null
    # 4 released versions of one package → scenario 3 (older than curblock).
    _seed_curation_artifact curbulk 1.0 released 600 >/dev/null
    _seed_curation_artifact curbulk 1.1 released 660 >/dev/null
    _seed_curation_artifact curbulk 1.2 released 720 >/dev/null
    _seed_curation_artifact curbulk 1.3 released 780 >/dev/null
    # NOTE: scenario 4 (finding-exclusion cascade) and 6 (exclusions listing) are
    # deliberately NOT seeded here. Their assertion is a policy re-evaluation
    # cascade: excluding a CVE must re-evaluate the artifacts carrying that finding
    # and RELEASE them. That only fires for artifacts ingested+scanned under a live
    # scan policy — a directly-seeded `rejected` row in a transient repo is not
    # policy-bound, so the cascade can't fire and 04 would fail rather than skip.
    # 04/06 self-skip cleanly ("needs the vuln-scan pipeline"); that flow belongs to
    # the host-side scripts/host-tests/test-vulnerability-scan.sh smoke.

    log "  seeded curation fixtures: repo=${CURATION_SEED_REPO_KEY} (id=${CURATION_SEED_REPO_ID})"
    log "    1 released + 2 quarantined + a 4-version released package"
}

# Remove everything seed_curation_fixtures created (FK order: findings → artifacts → repo).
cleanup_curation_fixtures() {
    [ -n "${CURATION_SEED_REPO_ID:-}" ] || return 0
    psql_exec "DELETE FROM scan_findings WHERE source_scanner = '${CURATION_SEED_SCANNER}';" >/dev/null 2>&1 || true
    psql_exec "DELETE FROM events WHERE stream_id IN (SELECT 'artifact-' || id::text FROM artifacts WHERE repository_id = '${CURATION_SEED_REPO_ID}');" >/dev/null 2>&1 || true
    psql_exec "DELETE FROM artifacts WHERE repository_id = '${CURATION_SEED_REPO_ID}';" >/dev/null 2>&1 || true
    psql_exec "DELETE FROM repositories WHERE id = '${CURATION_SEED_REPO_ID}';" >/dev/null 2>&1 || true
}

# -----------------------------------------------------------------------------
# Curator-grant bootstrap
# -----------------------------------------------------------------------------
#
# The curator grant flow per docs/architecture/how-to/curator-workflow.md
# §1.1 is: write a PermissionGrant YAML envelope, run `hort-cli admin apply`
# against it. The grant is gated by ApplyConfigUseCase + the claim-grant
# linter — there is no direct DB insert path.
#
# For the E2E we cannot mutate the canonical deploy/compose/example-config tree
# (other scenarios + future runs depend on its current state). Instead we:
#   1. Stage a transient overlay dir under $REPO_ROOT/scripts/e2e/curation/.tmp/
#      containing a `auth/curate-e2e.yaml` envelope.
#   2. Apply it via `hort-cli admin apply --file <path>` using the admin token.
#   3. On scenario EXIT, remove the grant (also via apply with an empty
#      bundle that the linter will reconcile to a delete). For v1 we
#      tolerate leaving the grant in place between scenarios — the
#      orchestrator runs scenarios sequentially and reuses the same
#      curator user across them.
#
# v1 simplification: rather than chase the gitops-apply complexity for
# every scenario, we share ONE curator token across all scenarios. The
# token belongs to a dedicated `curator` Keycloak user that the e2e realm
# already has (`developer-curator`, member of `test-developers` + a new
# `curators` group). If the realm doesn't have a curators group, we fall
# back to using the admin user and accept the limitation that "admin
# rejected by lack-of-Curate" assertions (Scenario 8) become impossible
# without a non-curator non-admin token — the readers user covers that
# distinct angle.

# Lookup the user_id of a user by preferred_username via psql. Returns the
# canonical UUID, or empty if the user has not been JIT-provisioned yet.
# JIT provisioning happens on first authenticated call to hort-server, so the
# caller may need to make any authenticated request as that user before
# this returns a non-empty value.
resolve_user_id_by_username() {
    local username="$1"
    psql_one "SELECT id FROM users WHERE username = '$username' OR preferred_username = '$username' LIMIT 1;"
}

# Construct the path to the e2e curator grant overlay YAML. The orchestrator
# stages this once at the start of the run; per-scenario scripts use it
# verbatim. Returns the absolute path.
e2e_curator_grant_yaml() {
    echo "$REPO_ROOT/scripts/e2e/curation/.tmp/curate-e2e.yaml"
}

# Stage the transient curator-grant overlay. Idempotent. The grant subject
# uses `kind: claims` so any member of the test-developers group gets the
# curate permission. This avoids the user-UUID resolution dance.
#
# Note on single-claim grants: a `kind: claims` grant with a single
# required claim is rejected as fan-out-bypassable. We pair `developer`
# with `ci-pusher` (already mapped by ci-pushers.yaml) so the grant is
# two-claim (satisfies the linter).
stage_curator_grant_overlay() {
    local out_dir="$REPO_ROOT/scripts/e2e/curation/.tmp"
    mkdir -p "$out_dir"
    cat >"$out_dir/curate-e2e.yaml" <<'YAML'
# Transient curator grant. Pairs `developer` +
# `ci-pusher` so the test-developers group's resolved claim set
# [developer, ci-pusher] satisfies a two-claim subject (clears the
# single-claim-grant linter check). Scoped globally so the
# curator surface (which has cross-repo finding-exclusion in scope) can
# be exercised end-to-end.
apiVersion: project-hort.de/v1beta1
kind: PermissionGrant
metadata:
  name: curate-e2e
spec:
  subject:
    kind: claims
    required: [developer, ci-pusher]
  permission: curate
YAML
}

# Apply the curator grant via the gitops apply path. Requires an admin
# token. Echoes "applied" on success; non-zero exit on failure (the
# scenario MUST fail loudly if the grant can't be applied — assertions
# downstream would produce confusing 403s).
apply_curator_grant() {
    local admin_token="$1"
    stage_curator_grant_overlay
    local yaml_path
    yaml_path="$(e2e_curator_grant_yaml)"
    # `hort-cli admin apply` may not have a single-file mode in v1 — fall
    # back to a direct POST to /api/v1/admin/config/apply if needed.
    # For v1 the cleanest path is to copy the file into a transient dir
    # and run `apply --dir`. We don't depend on `apply --file` existing.
    local apply_dir
    apply_dir="$(dirname "$yaml_path")/apply"
    mkdir -p "$apply_dir/auth"
    cp "$yaml_path" "$apply_dir/auth/curate-e2e.yaml"
    if HORT_TOKEN="$admin_token" "$HORT_CLI_BIN" --server "$API_URL" \
        admin apply --dir "$apply_dir" >/tmp/hort-curate-apply.log 2>&1; then
        echo "applied"
        return 0
    fi
    log "  apply_curator_grant: FAILED — log dump:"
    sed 's/^/    /' /tmp/hort-curate-apply.log >&2 || true
    return 1
}

# -----------------------------------------------------------------------------
# JSON parsing helper (uses jq if available, else python3)
# -----------------------------------------------------------------------------
json_get() {
    local json="$1" path="$2"
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$json" | jq -r "$path" 2>/dev/null
    else
        # Best-effort: only supports `.field` and `.field.sub` patterns.
        local py_path
        py_path="$(printf '%s' "$path" | sed -e 's/^\.//' -e 's/\./", "/g' -e 's/^/["/' -e 's/$/"]/')"
        python3 -c "import json,sys; d=json.loads(sys.argv[1]); k=$py_path; x=d
for p in k:
    x = x[p] if isinstance(x, dict) else x
print(x)" "$json" 2>/dev/null
    fi
}

# Mark this file as sourced — guards against double-sourcing in scenarios
# that import sibling helpers (none today, but cheap insurance).
_HORT_CURATION_E2E_LIB_SOURCED=1
export _HORT_CURATION_E2E_LIB_SOURCED
