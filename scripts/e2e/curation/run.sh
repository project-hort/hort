#!/usr/bin/env bash
# Orchestrator for the curator-surface E2E.
#
# Runs the nine scenarios in sequence against the v2 stack
# (deploy/compose/docker-compose.yml). Each scenario script is self-contained
# (sources _lib.sh, sets up its own fixtures, runs its assertions, prints
# its summary) and exits with one of:
#   0 — every assertion passed
#   1 — at least one assertion failed
#   2 — environment unmet (treat as SKIP)
#
# The orchestrator aggregates the nine exit codes into a single overall result.
# It brings the compose stack up if one isn't already running (and tears down
# only a stack it started — an operator-provided stack is left alone; --keep
# leaves a started stack up), and seeds the artifact fixtures the data-driven
# scenarios need.
#
# Skip semantics:
#   - If the stack is not reachable at preflight, exit 2 immediately
#     (so the caller can surface a SKIP).
#   - If individual scenarios exit 2 they're counted as SKIPS not FAILURES.
#   - Any scenario exit 1 makes the overall exit 1.
#
# Usage:
#   bash scripts/e2e/curation/run.sh
#   bash scripts/e2e/curation/run.sh --only 01_waive_happy_path
#
# Debug: HORT_TEST_DEBUG=1 toggles `set -x` in scenario scripts.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------

ONLY=""
CURATION_KEEP_STACK="${CURATION_KEEP_STACK:-0}"
while [ $# -gt 0 ]; do
    case "$1" in
        --only)
            ONLY="$2"
            shift 2
            ;;
        --keep)
            # Don't tear down a stack we bring up (debugging).
            CURATION_KEEP_STACK=1
            shift
            ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            log "unknown argument: $1"
            exit 1
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------

log "=============================================="
log "  Curator E2E orchestrator"
log "=============================================="
log "compose : $COMPOSE_FILE"
log "api     : $API_URL"
log "metrics : $METRICS_URL"
log "hort-cli  : $HORT_CLI_BIN"
log ""

require_hort_cli
# Bring the stack up if it isn't already (standalone `run.sh` just works); we
# only tear down a stack WE started — an operator-provided one is left alone.
ensure_stack_up

# -----------------------------------------------------------------------------
# Fixture seed
# -----------------------------------------------------------------------------
#
# The data-driven scenarios pick targets from the artifacts table; on a fresh
# stack none exist and they all self-skip. Seed the needed artifacts now; on
# exit, remove them (then tear the stack down if we started it). Order matters:
# delete the seeded rows while the DB is still up, THEN stop the stack.
trap 'cleanup_curation_fixtures; teardown_stack_if_started' EXIT
if ! seed_curation_fixtures; then
    log "SKIP: could not seed curation fixtures — is Postgres reachable?"
    exit 2
fi

# -----------------------------------------------------------------------------
# Scenario list
# -----------------------------------------------------------------------------

SCENARIOS=(
    "01_waive_happy_path.sh"
    "02_block_happy_path_single.sh"
    "03_bulk_block_by_versions.sh"
    "04_finding_exclusion_cascade.sh"
    "05_decisions_listing.sh"
    "06_exclusions_listing.sh"
    "07_queue_listing.sh"
    "08_privilege_denial.sh"
    "09_curator_waive_then_admin_block.sh"
)

# -----------------------------------------------------------------------------
# Aggregation counters
# -----------------------------------------------------------------------------

declare -i PASS_COUNT=0
declare -i FAIL_COUNT=0
declare -i SKIP_COUNT=0
declare -a FAILED_SCENARIOS=()
declare -a SKIPPED_SCENARIOS=()

# -----------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------

for scenario in "${SCENARIOS[@]}"; do
    if [ -n "$ONLY" ] && [[ "$scenario" != *"$ONLY"* ]]; then
        continue
    fi
    scenario_path="$SCRIPT_DIR/$scenario"
    if [ ! -f "$scenario_path" ]; then
        log "WARN: scenario script missing: $scenario_path"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_SCENARIOS+=("$scenario (missing)")
        continue
    fi

    log ""
    log "----------------------------------------------"
    log " >> $scenario"
    log "----------------------------------------------"

    set +e
    bash "$scenario_path"
    rc=$?
    set -e

    case "$rc" in
        0)
            PASS_COUNT=$((PASS_COUNT + 1))
            ;;
        2)
            SKIP_COUNT=$((SKIP_COUNT + 1))
            SKIPPED_SCENARIOS+=("$scenario")
            ;;
        *)
            FAIL_COUNT=$((FAIL_COUNT + 1))
            FAILED_SCENARIOS+=("$scenario (exit=$rc)")
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

log ""
log "=============================================="
log "  Curator E2E summary"
log "=============================================="
log "  scenarios passed : $PASS_COUNT"
log "  scenarios failed : $FAIL_COUNT"
log "  scenarios skipped: $SKIP_COUNT"

if [ "${#SKIPPED_SCENARIOS[@]}" -gt 0 ]; then
    log "  skipped:"
    for s in "${SKIPPED_SCENARIOS[@]}"; do
        log "    - $s"
    done
fi

if [ "${#FAILED_SCENARIOS[@]}" -gt 0 ]; then
    log "  failed:"
    for s in "${FAILED_SCENARIOS[@]}"; do
        log "    - $s"
    done
    log "RESULT: FAIL"
    exit 1
fi

log "RESULT: PASS"
exit 0
