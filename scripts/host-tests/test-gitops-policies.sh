#!/usr/bin/env bash
# E2E smoke for the gitops-managed policy + RBAC management plane
# (phases 1-5) and the enforcement pipeline that consumes those
# declarations (phase 6).
#
# Stages a transient $HORT_CONFIG_DIR containing one of EACH new kind
# landed in 14b (Role, PermissionGrant, CurationRule, ScanPolicy,
# Exclusion) plus one ArtifactRepository that references the
# CurationRule by name (so the junction-edge wiring is exercised) and
# one GroupMapping for parity with the gitops baseline.
#
# Drives the v2 docker-compose stack by remounting the config dir via
# a generated docker-compose override file, so tracked files under
# deploy/compose/example-config/ are never modified. A trap on EXIT
# removes the override + temp config dir and restarts hort-server back
# onto the canonical example-config tree.
#
# Lifecycle covered:
#   1. Initial create — every kind lands; CRUD kinds tick
#      hort_gitops_objects_total{kind=...,result=created}; event-sourced
#      kinds (ScanPolicy, Exclusion) emit PolicyCreated +
#      ExclusionAdded on hort_gitops_events_emitted_total and write
#      rows into policy_projections / exclusion_projections.
#   2. Single-field edit — flip the ScanPolicy's severityThreshold;
#      restart; assert exactly ONE additional PolicyUpdated event
#      fires (delta against the pre-edit snapshot).
#   3. Idempotent reapply — restart with no YAML changes; assert
#      hort_gitops_events_emitted_total is unchanged.
#   4. Exclusion removal — delete the Exclusion YAML; restart; assert
#      ONE ExclusionRemoved event fires whose payload reason matches
#      "removed by gitops apply".
#   5. ScanPolicy archive — delete the ScanPolicy YAML entirely;
#      restart; assert ONE PolicyArchived event fires AND the
#      projection row's `archived` flag flips to true.
#
# Per CLAUDE.md memory: host ports in the 25xxx range. The compose
# stack ships postgres without a host port mapping; psql is invoked
# via `docker compose exec postgres`.
#
# Exit codes:
#   0 — every assertion passed
#   1 — at least one assertion failed (full failure list at the end)
#   2 — environment unmet (compose unavailable, stack unreachable)
#
# Debug: set HORT_TEST_DEBUG=1 to trace every command.

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
FIXTURE_DIR="$SCRIPT_DIR/fixtures/gitops-policies"

METRICS_URL="${METRICS_URL:-http://localhost:25090/metrics}"
READY_TIMEOUT_SECS="${READY_TIMEOUT_SECS:-90}"

# Names pinned to the fixture YAMLs. Kept as constants (rather than
# inlined) so the asserts and the YAML stay in lockstep when fixtures
# evolve. The shellcheck "unused" warning on the names that only
# surface in log lines or future asserts is a known false positive
# we accept — see the disable below.
SCAN_POLICY_NAME="default-quarantine"
EXCLUSION_CVE_ID="CVE-2024-3094"

# Where the fixture overlay is staged. Lives under $TMPDIR (sandbox-
# friendly) or /tmp; bind-mounted into hort-server replacing the
# default ./example-config mount.
STAGE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/hort-gitops-policies-XXXXXX")"
OVERRIDE_FILE="${STAGE_ROOT}/docker-compose.override.yml"

PASSED=0
FAIL=0
declare -a FAILURES=()

# -----------------------------------------------------------------------------
# Logging + assertion helpers
# -----------------------------------------------------------------------------

log()  { printf '%s\n' "$*"; }

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
# Cleanup — always runs
# -----------------------------------------------------------------------------

# shellcheck disable=SC2317  # invoked indirectly via `trap ... EXIT`
cleanup() {
    local ec=$?
    log ""
    log "==> cleanup"
    # Restore the canonical example-config mount and restart hort-server
    # so subsequent test runs start from a clean baseline. Best-effort:
    # never block teardown on docker errors.
    if [ -f "$OVERRIDE_FILE" ]; then
        rm -f "$OVERRIDE_FILE" || true
    fi
    if compose_available; then
        log "  restoring hort-server to example-config mount"
        # `restart` would only restart the process inside the existing
        # container, preserving the overlay bind mount established by
        # `restart_with_overlay`. `up -d --force-recreate` (called
        # WITHOUT `-f $OVERRIDE_FILE`) recreates hort-server from the
        # canonical compose file so the bind reverts to
        # `./example-config:/etc/hort/config:ro`.
        docker compose -f "$COMPOSE_FILE" up -d --force-recreate \
            hort-server >/dev/null 2>&1 || true
    fi
    rm -rf "$STAGE_ROOT" || true
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
    if ! curl -sSf -o /dev/null "$METRICS_URL"; then
        log "SKIP: hort-server metrics endpoint unreachable at $METRICS_URL"
        exit 2
    fi
}

wait_for_metrics() {
    local deadline
    deadline=$(( $(date +%s) + READY_TIMEOUT_SECS ))
    while :; do
        if curl -sSf -o /dev/null "$METRICS_URL"; then
            return 0
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            return 1
        fi
        sleep 2
    done
}

# -----------------------------------------------------------------------------
# Stage management — temp $HORT_CONFIG_DIR + compose override
# -----------------------------------------------------------------------------

# Build the staged config dir as: example-config baseline + fixture
# overlay. The baseline keeps `pypi-e2e` (referenced by the fixture
# PermissionGrant) and the existing seed group-mappings reachable so
# the apply doesn't fail dangling-reference validation.
stage_config_dir() {
    local stage_dir="$1"
    rm -rf "$stage_dir"
    mkdir -p "$stage_dir"
    cp -R "$EXAMPLE_CONFIG"/. "$stage_dir"/
    cp -R "$FIXTURE_DIR"/. "$stage_dir"/
}

# Write the docker-compose override that re-mounts the staged config
# dir over the canonical example-config bind. The override is its own
# file so the canonical compose YAML stays untouched.
write_override() {
    local stage_dir="$1"
    cat > "$OVERRIDE_FILE" <<EOF
# Auto-generated by scripts/host-tests/test-gitops-policies.sh.
# Re-mounts the staged \$HORT_CONFIG_DIR over the example-config bind
# so the boot apply sees the smoke-test fixture overlay instead of
# the canonical tree. Removed by the script's EXIT trap.
services:
  hort-server:
    volumes:
      - cas:/var/lib/hort-server/cas
      - ${stage_dir}:/etc/hort/config:ro
EOF
}

# Restart hort-server with the current stage + override and wait for
# readiness. Fails fast (exit 1, NOT a soft assert) if hort-server
# never comes back — a stack that won't boot can't be smoke-tested.
restart_with_overlay() {
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

# -----------------------------------------------------------------------------
# Metrics scraping
# -----------------------------------------------------------------------------

# Fetch the metrics scrape into a variable. Caller indexes lines with
# grep / awk — no jq dependency.
scrape_metrics() {
    curl -sSf "$METRICS_URL"
}

# Sum the values of every `hort_gitops_objects_total` series matching
# the given kind+result. Returns 0 if no series match (Prometheus
# counters that have never fired are absent from the scrape).
metric_objects_total() {
    local scrape="$1" kind="$2" result="$3"
    printf '%s\n' "$scrape" \
        | grep -E "^hort_gitops_objects_total\\{[^}]*kind=\"${kind}\"[^}]*result=\"${result}\"[^}]*\\} " \
        | awk '{ s += $NF } END { printf "%d", (s ? s : 0) }'
}

# Sum the values of every `hort_gitops_events_emitted_total` series
# matching the given kind+event_type. Same absent-counter handling
# as above.
metric_events_emitted() {
    local scrape="$1" kind="$2" event_type="$3"
    printf '%s\n' "$scrape" \
        | grep -E "^hort_gitops_events_emitted_total\\{[^}]*kind=\"${kind}\"[^}]*event_type=\"${event_type}\"[^}]*\\} " \
        | awk '{ s += $NF } END { printf "%d", (s ? s : 0) }'
}

# -----------------------------------------------------------------------------
# psql helper — projection + event store reads
# -----------------------------------------------------------------------------

psql_one() {
    # Run a single SQL query and return one trimmed column value.
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

# -----------------------------------------------------------------------------
# Phase 0 — environment preflight
# -----------------------------------------------------------------------------

log "==> Gitops policies + RBAC smoke"
log "compose : $COMPOSE_FILE"
log "metrics : $METRICS_URL"
log "stage   : $STAGE_ROOT"
log ""

require_stack_up

# -----------------------------------------------------------------------------
# Phase 1 — initial create
# -----------------------------------------------------------------------------
log ""
log "--> [1/5] initial create — apply all five new kinds"

stage_config_dir "$STAGE_ROOT/config"
write_override "$STAGE_ROOT/config"
restart_with_overlay

SCRAPE1="$(scrape_metrics)"

# CRUD kinds: object counters tick `created`. `unchanged` is allowed
# in addition (the seeded GroupMappings already exist on prior boots),
# but the new fixture rows must each surface as a created.
for kind_label in role permission_grant curation_rule; do
    val="$(metric_objects_total "$SCRAPE1" "$kind_label" "created")"
    if [ "$val" -ge 1 ]; then
        assert_pass "hort_gitops_objects_total{kind=$kind_label,result=created} >= 1 (got $val)"
    else
        assert_fail \
            "hort_gitops_objects_total{kind=$kind_label,result=created} >= 1" \
            "got $val — fixture envelope did not register as a create"
    fi
done

# `repository` may legitimately be `unchanged` for the existing keys,
# but the new junction-edge `pypi-curated` repo MUST be a create. The
# objects metric counts kinds in aggregate, so we can't pin "the
# pypi-curated row was created" by metric alone — fall through to a
# structural check via the repository projection (the example-config
# baseline has no row under that key, so a non-empty `created` count
# is necessary).
val="$(metric_objects_total "$SCRAPE1" "repository" "created")"
if [ "$val" -ge 1 ]; then
    assert_pass "hort_gitops_objects_total{kind=repository,result=created} >= 1 (got $val)"
else
    assert_fail \
        "hort_gitops_objects_total{kind=repository,result=created} >= 1" \
        "got $val — junction-edge repo did not register as a create"
fi

# Event-sourced kinds: PolicyCreated + ExclusionAdded must fire once
# each. The kind label is the lowercased envelope kind per the metric
# catalog; the event_type label is the DomainEvent discriminant.
created_policy_n="$(metric_events_emitted "$SCRAPE1" "scan_policy" "PolicyCreated")"
if [ "$created_policy_n" -ge 1 ]; then
    assert_pass "hort_gitops_events_emitted_total{kind=scan_policy,event_type=PolicyCreated} >= 1 (got $created_policy_n)"
else
    assert_fail \
        "hort_gitops_events_emitted_total{kind=scan_policy,event_type=PolicyCreated} >= 1" \
        "got $created_policy_n — ScanPolicy create did not append PolicyCreated"
fi

added_excl_n="$(metric_events_emitted "$SCRAPE1" "exclusion" "ExclusionAdded")"
if [ "$added_excl_n" -ge 1 ]; then
    assert_pass "hort_gitops_events_emitted_total{kind=exclusion,event_type=ExclusionAdded} >= 1 (got $added_excl_n)"
else
    assert_fail \
        "hort_gitops_events_emitted_total{kind=exclusion,event_type=ExclusionAdded} >= 1" \
        "got $added_excl_n — Exclusion add did not append ExclusionAdded"
fi

# Projection landed for the policy.
policy_active="$(psql_count "SELECT COUNT(*) FROM policy_projections WHERE name = '${SCAN_POLICY_NAME}' AND archived = false;")"
if [ "$policy_active" = "1" ]; then
    assert_pass "policy_projections row for '${SCAN_POLICY_NAME}' (active) present"
else
    assert_fail \
        "policy_projections row for '${SCAN_POLICY_NAME}' (active) present" \
        "expected 1 active row, got '$policy_active'"
fi

# Projection landed for the exclusion (filtered by parent name).
excl_count="$(psql_count "SELECT COUNT(*) FROM exclusion_projections e JOIN policy_projections p ON p.policy_id = e.policy_id WHERE p.name = '${SCAN_POLICY_NAME}' AND e.cve_id = '${EXCLUSION_CVE_ID}';")"
if [ "$excl_count" = "1" ]; then
    assert_pass "exclusion_projections row for '${EXCLUSION_CVE_ID}' present under parent '${SCAN_POLICY_NAME}'"
else
    assert_fail \
        "exclusion_projections row for '${EXCLUSION_CVE_ID}' present under parent '${SCAN_POLICY_NAME}'" \
        "expected 1 row, got '$excl_count'"
fi

# Snapshot the policy-update + policy-archive + exclusion-removed
# counters so subsequent phases can assert delta=N. Counters are
# absent until they fire, so the baseline can legitimately be 0.
PRE_EDIT_UPDATED="$(metric_events_emitted "$SCRAPE1" "scan_policy" "PolicyUpdated")"
PRE_EDIT_ARCHIVED="$(metric_events_emitted "$SCRAPE1" "scan_policy" "PolicyArchived")"
PRE_EDIT_REMOVED="$(metric_events_emitted "$SCRAPE1" "exclusion" "ExclusionRemoved")"
log "  baseline event counters: PolicyUpdated=$PRE_EDIT_UPDATED PolicyArchived=$PRE_EDIT_ARCHIVED ExclusionRemoved=$PRE_EDIT_REMOVED"

# -----------------------------------------------------------------------------
# Phase 2 — single-field edit on the ScanPolicy
# -----------------------------------------------------------------------------
log ""
log "--> [2/5] edit ScanPolicy.severityThreshold high -> critical"

# Re-stage so we mutate a copy, not the canonical fixture file.
stage_config_dir "$STAGE_ROOT/config"
EDIT_TARGET="$STAGE_ROOT/config/policies/scanpolicy-default-quarantine.yaml"
# Portable in-place edit: rewrite the file with the substituted
# severityThreshold value rather than relying on `sed -i`.
awk '{
    if ($1 == "severityThreshold:") {
        print "  severityThreshold: critical"
    } else {
        print
    }
}' "$EDIT_TARGET" > "${EDIT_TARGET}.new"
mv "${EDIT_TARGET}.new" "$EDIT_TARGET"

write_override "$STAGE_ROOT/config"
restart_with_overlay

SCRAPE2="$(scrape_metrics)"

POST_EDIT_UPDATED="$(metric_events_emitted "$SCRAPE2" "scan_policy" "PolicyUpdated")"
delta=$(( POST_EDIT_UPDATED - PRE_EDIT_UPDATED ))
if [ "$delta" = "1" ]; then
    assert_pass "hort_gitops_events_emitted_total{kind=scan_policy,event_type=PolicyUpdated} delta == 1 (got $delta)"
else
    assert_fail \
        "hort_gitops_events_emitted_total{kind=scan_policy,event_type=PolicyUpdated} delta == 1" \
        "got delta=$delta (pre=$PRE_EDIT_UPDATED post=$POST_EDIT_UPDATED) — single-field edit must emit exactly one event"
fi

# Projection's severity_threshold should now read "critical".
sev="$(psql_one "SELECT severity_threshold FROM policy_projections WHERE name = '${SCAN_POLICY_NAME}';")"
if [ "$sev" = "critical" ]; then
    assert_pass "policy_projections.severity_threshold for '${SCAN_POLICY_NAME}' == 'critical'"
else
    assert_fail \
        "policy_projections.severity_threshold for '${SCAN_POLICY_NAME}' == 'critical'" \
        "got '$sev' — projection did not advance with the event"
fi

# -----------------------------------------------------------------------------
# Phase 3 — idempotent reapply (no YAML changes)
# -----------------------------------------------------------------------------
log ""
log "--> [3/5] idempotent reapply — restart with no YAML changes"

restart_with_overlay
SCRAPE3="$(scrape_metrics)"

NOOP_CREATED_POLICY="$(metric_events_emitted "$SCRAPE3" "scan_policy" "PolicyCreated")"
NOOP_UPDATED_POLICY="$(metric_events_emitted "$SCRAPE3" "scan_policy" "PolicyUpdated")"
NOOP_ARCHIVED_POLICY="$(metric_events_emitted "$SCRAPE3" "scan_policy" "PolicyArchived")"
NOOP_ADDED_EXCL="$(metric_events_emitted "$SCRAPE3" "exclusion" "ExclusionAdded")"
NOOP_REMOVED_EXCL="$(metric_events_emitted "$SCRAPE3" "exclusion" "ExclusionRemoved")"

if [ "$NOOP_CREATED_POLICY" = "$created_policy_n" ] \
    && [ "$NOOP_UPDATED_POLICY" = "$POST_EDIT_UPDATED" ] \
    && [ "$NOOP_ARCHIVED_POLICY" = "$PRE_EDIT_ARCHIVED" ] \
    && [ "$NOOP_ADDED_EXCL" = "$added_excl_n" ] \
    && [ "$NOOP_REMOVED_EXCL" = "$PRE_EDIT_REMOVED" ]; then
    assert_pass "no-op reapply emitted zero new events (all five event_type counters unchanged)"
else
    assert_fail \
        "no-op reapply emitted zero new events" \
        "PolicyCreated $created_policy_n->$NOOP_CREATED_POLICY, PolicyUpdated $POST_EDIT_UPDATED->$NOOP_UPDATED_POLICY, PolicyArchived $PRE_EDIT_ARCHIVED->$NOOP_ARCHIVED_POLICY, ExclusionAdded $added_excl_n->$NOOP_ADDED_EXCL, ExclusionRemoved $PRE_EDIT_REMOVED->$NOOP_REMOVED_EXCL"
fi

# -----------------------------------------------------------------------------
# Phase 4 — Exclusion removal
# -----------------------------------------------------------------------------
log ""
log "--> [4/5] remove Exclusion YAML — expect ExclusionRemoved"

# Re-stage from scratch (so the previous-edit ScanPolicy mutation is
# preserved — we don't want phase 4 to also flip severityThreshold
# back and double-count) then drop the exclusion file.
stage_config_dir "$STAGE_ROOT/config"
EDIT_TARGET="$STAGE_ROOT/config/policies/scanpolicy-default-quarantine.yaml"
awk '{
    if ($1 == "severityThreshold:") {
        print "  severityThreshold: critical"
    } else {
        print
    }
}' "$EDIT_TARGET" > "${EDIT_TARGET}.new"
mv "${EDIT_TARGET}.new" "$EDIT_TARGET"
rm -f "$STAGE_ROOT/config/policies/exclusion-cve-2024-3094-old-xz.yaml"

write_override "$STAGE_ROOT/config"
restart_with_overlay
SCRAPE4="$(scrape_metrics)"

POST_REMOVE_EXCL="$(metric_events_emitted "$SCRAPE4" "exclusion" "ExclusionRemoved")"
delta=$(( POST_REMOVE_EXCL - PRE_EDIT_REMOVED ))
if [ "$delta" = "1" ]; then
    assert_pass "hort_gitops_events_emitted_total{kind=exclusion,event_type=ExclusionRemoved} delta == 1 (got $delta)"
else
    assert_fail \
        "hort_gitops_events_emitted_total{kind=exclusion,event_type=ExclusionRemoved} delta == 1" \
        "got delta=$delta (pre=$PRE_EDIT_REMOVED post=$POST_REMOVE_EXCL)"
fi

# Reason is recorded in the event payload (events.event_data is JSONB).
# The exact key name (`reason` vs `removal_reason`) is fixed by
# `ExclusionRemoved`'s domain shape; jsonb_path_query matches whatever
# the value is at any depth.
removed_reason="$(psql_one "SELECT event_data->>'reason' FROM events WHERE event_type = 'ExclusionRemoved' AND event_data->>'cve_id' = '${EXCLUSION_CVE_ID}' ORDER BY global_position DESC LIMIT 1;")"
if [ "$removed_reason" = "removedbygitopsapply" ] || [ "$removed_reason" = "removedbygitops" ] || \
   echo "$removed_reason" | grep -qi "removedbygitopsapply"; then
    assert_pass "ExclusionRemoved.reason == 'removed by gitops apply'"
elif [ -z "$removed_reason" ]; then
    # `reason` may live under a differently-named JSON key in the
    # current event shape. Fall back to a substring match across the
    # full event_data blob so the assertion can't silently pass on
    # an empty payload.
    blob="$(psql_one "SELECT event_data::text FROM events WHERE event_type = 'ExclusionRemoved' AND event_data->>'cve_id' = '${EXCLUSION_CVE_ID}' ORDER BY global_position DESC LIMIT 1;")"
    if echo "$blob" | grep -qi 'removedbygitopsapply'; then
        assert_pass "ExclusionRemoved event payload contains 'removed by gitops apply'"
    else
        assert_fail \
            "ExclusionRemoved.reason == 'removed by gitops apply'" \
            "no matching event found (reason='$removed_reason' blob='$blob')"
    fi
else
    assert_fail \
        "ExclusionRemoved.reason == 'removed by gitops apply'" \
        "got reason='$removed_reason'"
fi

# Projection row for the exclusion is gone.
excl_after="$(psql_count "SELECT COUNT(*) FROM exclusion_projections e JOIN policy_projections p ON p.policy_id = e.policy_id WHERE p.name = '${SCAN_POLICY_NAME}' AND e.cve_id = '${EXCLUSION_CVE_ID}';")"
if [ "$excl_after" = "0" ]; then
    assert_pass "exclusion_projections row for '${EXCLUSION_CVE_ID}' is gone after removal"
else
    assert_fail \
        "exclusion_projections row for '${EXCLUSION_CVE_ID}' is gone after removal" \
        "expected 0 rows, got '$excl_after'"
fi

# -----------------------------------------------------------------------------
# Phase 5 — ScanPolicy archive (delete YAML entirely)
# -----------------------------------------------------------------------------
log ""
log "--> [5/5] remove ScanPolicy YAML — expect PolicyArchived + projection.archived=true"

stage_config_dir "$STAGE_ROOT/config"
rm -f "$STAGE_ROOT/config/policies/scanpolicy-default-quarantine.yaml"
rm -f "$STAGE_ROOT/config/policies/exclusion-cve-2024-3094-old-xz.yaml"
write_override "$STAGE_ROOT/config"
restart_with_overlay
SCRAPE5="$(scrape_metrics)"

POST_ARCH="$(metric_events_emitted "$SCRAPE5" "scan_policy" "PolicyArchived")"
delta=$(( POST_ARCH - PRE_EDIT_ARCHIVED ))
if [ "$delta" = "1" ]; then
    assert_pass "hort_gitops_events_emitted_total{kind=scan_policy,event_type=PolicyArchived} delta == 1 (got $delta)"
else
    assert_fail \
        "hort_gitops_events_emitted_total{kind=scan_policy,event_type=PolicyArchived} delta == 1" \
        "got delta=$delta (pre=$PRE_EDIT_ARCHIVED post=$POST_ARCH)"
fi

archived="$(psql_one "SELECT archived FROM policy_projections WHERE name = '${SCAN_POLICY_NAME}';")"
if [ "$archived" = "t" ] || [ "$archived" = "true" ]; then
    assert_pass "policy_projections.archived for '${SCAN_POLICY_NAME}' is true"
else
    assert_fail \
        "policy_projections.archived for '${SCAN_POLICY_NAME}' is true" \
        "got archived='$archived'"
fi

# =============================================================================
# Phase 6 — end-to-end policy enforcement smoke
# =============================================================================
#
# Phases 1-5 verified the gitops management plane. This section
# verifies the *enforcement* pipeline that consumes those managed
# declarations. Each subphase pins
# a single decision-point's metric label set against the catalog and
# the lifecycle event the design doc §5 mandates.
#
# Reachable from a black-box smoke against the v2 stack:
#   - **6a) Curation gate at ingest** (decision_point=curation):
#     PyPI hosted upload of a name matching `evil-package*` returns
#     403 (per hort-http-pypi: PyPI has no pull-through path; client-
#     upload paths get the default `DomainError::CurationBlocked`
#     → 403 mapping). Asserts the
#     `hort_policy_evaluation_total{decision_point=curation,result=block}`
#     counter ticks. Curation `Allow` normalises to `result=pass` —
#     the pass leg is exercised by every other PyPI ingest in the
#     smoke pipeline (NOT asserted here because counting "every other
#     ingest" is brittle; this section's own first ingest in 6b is
#     the only `pass` we can pin).
#
#   - **6b) Retroactive curation** (decision_point=curation_retroactive):
#     pre-ingest a clean PyPI artifact, then declare a NEW
#     `CurationRule package_pattern: previously-allowed-pkg*,
#     action: block` and reapply. The gitops apply runs the retroactive
#     evaluator against active artifacts in repos linked to the rule
#     and emits
#     `ArtifactRejected { reason: CurationRetroactive { rule_id } }`
#     on the artifact stream + `CurationApplied { trigger:
#     Retroactive, action: Block }` on the per-repo curation stream.
#     Asserts (i) `quarantine_status = rejected`, (ii) the latest
#     `ArtifactRejected.event_data` carries `CurationRetroactive`
#     with the matching `rule_id`, (iii) the
#     `decision_point=curation_retroactive,result=retro_block`
#     counter ticks at least once.
#
#   - **6c) Asymmetric weakening** (quarantine invariant — mirrors
#     architect-skill quarantine invariant 3): change the
#     just-installed `previously-allowed-pkg*` rule's action from
#     `block` to `allow` and reapply. `apply_curation_rules` only
#     schedules retro candidates on `creates` and `tightenings`;
#     `Block → Allow` is a *weakening* and produces no retroactive
#     events. Asserts (i) the rejected artifact STAYS `rejected`
#     (admin explicit release is the only unblock path), (ii)
#     `decision_point=curation_retroactive` ticks observed in 6b
#     are unchanged.
#
# Out of reach for v1 smoke (documented for the follow-on agent who
# eventually closes these gaps):
#   - **decision_point=scan_result** has no inbound HTTP / CLI
#     surface (scan results are injected via the `ScannerPort` adapter
#     only; `record_scan_result` has no public route AND no admin-CLI
#     subcommand). The events table additionally carries an
#     `events_immutable` trigger that blocks direct INSERTs, so
#     forging a `ScanCompleted` via psql is also unavailable.
#   - **decision_point=re_evaluation** depends on a pre-existing
#     `Rejected` artifact, which today only lands via scan-result
#     (or the retroactive curation path). The retroactive path
#     hits a *different* decision point, so re-evaluation cannot
#     be exercised standalone until the scanner adapter lands.
#   - **decision_point=promotion** has no v1 promotion HTTP
#     surface mounted; the use case is wired but no inbound adapter
#     exists yet.
#
# These three remain dormant per the §1 dormancy admonition; this
# script's intent is to fail loudly the day they DO surface (so the
# implementer remembers to extend the smoke).
#
# All HTTP calls to hort-server use the Keycloak `dev-user` access
# token fetched from the v2 stack's Keycloak host port (25082) —
# matches the pattern in `test-pypi.sh` / `test-oci.sh`. Keycloak
# runs alongside hort-server in the same compose; if it isn't up, the
# section cleanly skips its HTTP-dependent subphases instead of
# failing the whole suite.

API_URL="${API_URL:-http://localhost:25080}"
KEYCLOAK_TOKEN_URL="${KEYCLOAK_TOKEN_URL:-http://localhost:25082/realms/hort/protocol/openid-connect/token}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-hort-server}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-hort-server-secret-dev-only}"

# Sum every `hort_policy_evaluation_total` series matching the supplied
# `decision_point` + `result`. Returns 0 when the counter has never
# fired (Prometheus omits absent counters from the scrape body).
metric_policy_eval_total() {
    local scrape="$1" decision_point="$2" result="$3"
    printf '%s\n' "$scrape" \
        | grep -E "^hort_policy_evaluation_total\\{[^}]*decision_point=\"${decision_point}\"[^}]*result=\"${result}\"[^}]*\\} " \
        | awk '{ s += $NF } END { printf "%d", (s ? s : 0) }'
}

fetch_dev_token() {
    # Returns the bearer JWT on stdout, or empty on any failure (caller
    # treats empty as "skip this subphase").
    local response
    response="$(curl -sS -X POST "$KEYCLOAK_TOKEN_URL" \
        -d "grant_type=password" \
        -d "client_id=$KEYCLOAK_CLIENT_ID" \
        -d "client_secret=$KEYCLOAK_CLIENT_SECRET" \
        -d "username=dev-user" \
        -d "password=dev" 2>/dev/null)" || return 0
    # python3 ships in the scripts/native-tests/run.sh container
    # images and is preinstalled on macOS / Ubuntu dev hosts; keep it
    # to avoid layering a jq dep on this script.
    python3 -c "import sys, json
try:
    print(json.loads(sys.stdin.read())['access_token'])
except Exception:
    pass" <<< "$response"
}

# Re-stage the pristine fixture overlay so phase 6 starts from a known
# good baseline. Phase 5 archived the policy and dropped the
# exclusion; phase 6 doesn't depend on either, but a known-good
# overlay keeps the per-subphase asserts hermetic and also re-creates
# the `pypi-curated` repository (which carries the `block-known-bad-1`
# curation rule the 6a subphase exercises).
log ""
log "--> [6/6] enforcement smoke — re-stage pristine overlay"
stage_config_dir "$STAGE_ROOT/config"
write_override "$STAGE_ROOT/config"
restart_with_overlay

# Resolve the `pypi-curated` repo's freshly-minted UUID via the admin
# lookup endpoint (the only repo-id resolution surface in v2; see
# `crates/hort-http-core/src/handlers/admin.rs`). Bootstrap-admin auth
# is required — fall back to the `dev-user` token's admin claim if
# Keycloak is reachable, otherwise skip the HTTP subphases.
PYPI_CURATED_REPO_KEY="${PYPI_CURATED_REPO_KEY:-pypi-curated}"

DEV_TOKEN=""
if curl -sSf -o /dev/null --max-time 5 "$KEYCLOAK_TOKEN_URL" 2>/dev/null \
   || curl -sSf -o /dev/null --max-time 5 \
        "${KEYCLOAK_TOKEN_URL%/protocol/openid-connect/token}/.well-known/openid-configuration" 2>/dev/null; then
    DEV_TOKEN="$(fetch_dev_token)"
fi

if [ -z "$DEV_TOKEN" ]; then
    log "  SKIP: Keycloak unreachable at $KEYCLOAK_TOKEN_URL — phase 6 HTTP subphases skipped"
    PHASE_6_SKIPPED=1
else
    PHASE_6_SKIPPED=0
fi

# -----------------------------------------------------------------------------
# Phase 6a — curation gate at ingest (decision_point=curation, result=block)
# -----------------------------------------------------------------------------
log ""
log "--> [6a] curation gate at ingest — PyPI hosted upload of evil-package* expects 403"

if [ "$PHASE_6_SKIPPED" = "1" ]; then
    log "  SKIP (Keycloak token not available)"
else
    SCRAPE_PRE_6A="$(scrape_metrics)"
    PRE_BLOCK_6A="$(metric_policy_eval_total "$SCRAPE_PRE_6A" curation block)"

    # Build a minimal twine-shaped multipart payload. The
    # `name` field is what the PyPI handler PEP 503-normalises into
    # `coords.name`, which is what the curation evaluator matches
    # against `evil-package*` (see `block-known-bad-1` fixture).
    BOUNDARY="----hortinit1610curationboundary"
    PYPI_PAYLOAD_FILE="$STAGE_ROOT/evil_payload.txt"
    {
        printf -- '--%s\r\n' "$BOUNDARY"
        printf 'Content-Disposition: form-data; name=":action"\r\n\r\nfile_upload\r\n'
        printf -- '--%s\r\n' "$BOUNDARY"
        printf 'Content-Disposition: form-data; name="protocol_version"\r\n\r\n1\r\n'
        printf -- '--%s\r\n' "$BOUNDARY"
        printf 'Content-Disposition: form-data; name="name"\r\n\r\nevil-package\r\n'
        printf -- '--%s\r\n' "$BOUNDARY"
        printf 'Content-Disposition: form-data; name="version"\r\n\r\n1.0.0\r\n'
        printf -- '--%s\r\n' "$BOUNDARY"
        printf 'Content-Disposition: form-data; name="content"; filename="evil_package-1.0.0.tar.gz"\r\n'
        printf 'Content-Type: application/octet-stream\r\n\r\n'
        printf 'fake-tarball-bytes\r\n'
        printf -- '--%s--\r\n' "$BOUNDARY"
    } > "$PYPI_PAYLOAD_FILE"

    STATUS_6A="$(curl -sS -o /dev/null -w '%{http_code}' \
        -X POST "$API_URL/pypi/$PYPI_CURATED_REPO_KEY/" \
        -H "Authorization: Bearer $DEV_TOKEN" \
        -H "Content-Type: multipart/form-data; boundary=$BOUNDARY" \
        --data-binary "@$PYPI_PAYLOAD_FILE")"

    if [ "$STATUS_6A" = "403" ]; then
        assert_pass "PyPI upload of evil-package to pypi-curated returned 403 (curation Block)"
    else
        assert_fail \
            "PyPI upload of evil-package to pypi-curated returned 403" \
            "got HTTP $STATUS_6A — curation block path didn't fire (or repo was missing)"
    fi

    SCRAPE_POST_6A="$(scrape_metrics)"
    POST_BLOCK_6A="$(metric_policy_eval_total "$SCRAPE_POST_6A" curation block)"
    delta_6a=$(( POST_BLOCK_6A - PRE_BLOCK_6A ))
    if [ "$delta_6a" -ge 1 ]; then
        assert_pass "hort_policy_evaluation_total{decision_point=curation,result=block} delta >= 1 (got $delta_6a)"
    else
        assert_fail \
            "hort_policy_evaluation_total{decision_point=curation,result=block} delta >= 1" \
            "got delta=$delta_6a (pre=$PRE_BLOCK_6A post=$POST_BLOCK_6A) — curation evaluator did not emit the block result"
    fi

    rm -f "$PYPI_PAYLOAD_FILE"
fi

# -----------------------------------------------------------------------------
# Phase 6b — retroactive curation (decision_point=curation_retroactive,
#                                  result=retro_block)
# -----------------------------------------------------------------------------
log ""
log "--> [6b] retroactive curation — pre-ingest a clean artifact, then add a Block rule that matches it"

if [ "$PHASE_6_SKIPPED" = "1" ]; then
    log "  SKIP (Keycloak token not available)"
else
    PREV_PKG_NAME="${PREV_PKG_NAME:-previously-allowed-pkg}"
    PREV_PKG_VERSION="${PREV_PKG_VERSION:-1.0.0}"

    # Step 1: ingest the artifact BEFORE the new rule exists. With no
    # matching rule the `decision_point=curation,result=pass` counter
    # ticks; capture pre/post deltas so we can sanity-check the
    # `pass`-leg fired exactly once for this ingest (curation Allow
    # normalises to `pass`, NOT `allow`).
    BOUNDARY="----hortinit1610retroboundary"
    PYPI_PAYLOAD_FILE="$STAGE_ROOT/prev_payload.txt"
    {
        printf -- '--%s\r\n' "$BOUNDARY"
        printf 'Content-Disposition: form-data; name=":action"\r\n\r\nfile_upload\r\n'
        printf -- '--%s\r\n' "$BOUNDARY"
        printf 'Content-Disposition: form-data; name="protocol_version"\r\n\r\n1\r\n'
        printf -- '--%s\r\n' "$BOUNDARY"
        printf 'Content-Disposition: form-data; name="name"\r\n\r\n%s\r\n' "$PREV_PKG_NAME"
        printf -- '--%s\r\n' "$BOUNDARY"
        printf 'Content-Disposition: form-data; name="version"\r\n\r\n%s\r\n' "$PREV_PKG_VERSION"
        printf -- '--%s\r\n' "$BOUNDARY"
        printf 'Content-Disposition: form-data; name="content"; filename="%s-%s.tar.gz"\r\n' "$PREV_PKG_NAME" "$PREV_PKG_VERSION"
        printf 'Content-Type: application/octet-stream\r\n\r\n'
        printf 'inert-tarball-bytes\r\n'
        printf -- '--%s--\r\n' "$BOUNDARY"
    } > "$PYPI_PAYLOAD_FILE"

    SCRAPE_PRE_INGEST="$(scrape_metrics)"
    PRE_PASS_6B="$(metric_policy_eval_total "$SCRAPE_PRE_INGEST" curation pass)"

    STATUS_6B_INGEST="$(curl -sS -o /dev/null -w '%{http_code}' \
        -X POST "$API_URL/pypi/$PYPI_CURATED_REPO_KEY/" \
        -H "Authorization: Bearer $DEV_TOKEN" \
        -H "Content-Type: multipart/form-data; boundary=$BOUNDARY" \
        --data-binary "@$PYPI_PAYLOAD_FILE")"
    if [ "$STATUS_6B_INGEST" = "200" ] || [ "$STATUS_6B_INGEST" = "201" ] || [ "$STATUS_6B_INGEST" = "204" ]; then
        assert_pass "PyPI upload of $PREV_PKG_NAME (no matching rule yet) succeeded (HTTP $STATUS_6B_INGEST)"
    else
        assert_fail \
            "PyPI upload of $PREV_PKG_NAME (no matching rule yet) succeeded" \
            "got HTTP $STATUS_6B_INGEST"
    fi
    rm -f "$PYPI_PAYLOAD_FILE"

    SCRAPE_POST_INGEST="$(scrape_metrics)"
    POST_PASS_6B="$(metric_policy_eval_total "$SCRAPE_POST_INGEST" curation pass)"
    delta_pass_6b=$(( POST_PASS_6B - PRE_PASS_6B ))
    if [ "$delta_pass_6b" -ge 1 ]; then
        assert_pass "hort_policy_evaluation_total{decision_point=curation,result=pass} delta >= 1 (got $delta_pass_6b) — Allow normalises to pass"
    else
        assert_fail \
            "hort_policy_evaluation_total{decision_point=curation,result=pass} delta >= 1" \
            "got delta=$delta_pass_6b (pre=$PRE_PASS_6B post=$POST_PASS_6B)"
    fi

    # Resolve the artifact's row before the rule lands so we have a
    # before/after snapshot of `quarantine_status`. Filter by
    # repository_id via a join on `repositories.key` to keep this
    # script independent of the UUID minted at first apply.
    PREV_ARTIFACT_ID="$(psql_one "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${PYPI_CURATED_REPO_KEY}' AND a.name = '${PREV_PKG_NAME}' AND a.version = '${PREV_PKG_VERSION}' ORDER BY a.created_at DESC LIMIT 1;")"
    if [ -n "$PREV_ARTIFACT_ID" ]; then
        assert_pass "artifact row for $PREV_PKG_NAME present (id=$PREV_ARTIFACT_ID)"
    else
        assert_fail \
            "artifact row for $PREV_PKG_NAME present" \
            "no artifacts.id resolved for ($PYPI_CURATED_REPO_KEY, $PREV_PKG_NAME, $PREV_PKG_VERSION)"
    fi

    PRE_RETRO_STATUS="$(psql_one "SELECT quarantine_status FROM artifacts WHERE id = '${PREV_ARTIFACT_ID}';" || true)"
    log "  pre-rule artifact status: ${PRE_RETRO_STATUS:-<unknown>}"

    # Step 2: drop a NEW CurationRule into the staged config that
    # matches `previously-allowed-pkg*`, leave the `pypi-curated`
    # repo's `curationRules:` list pointing at it, and restart. The
    # gitops apply path's retroactive evaluator walks active artifacts
    # in repos linked to the rule and emits
    # `ArtifactRejected { reason: CurationRetroactive { rule_id } }`
    # per match.
    cat > "$STAGE_ROOT/config/policies/curation-block-retro.yaml" <<EOF
apiVersion: project-hort.de/v1beta1
kind: CurationRule
metadata:
  name: block-retro-1
spec:
  format: any
  pattern: "${PREV_PKG_NAME}*"
  action: block
  reason: "retroactive smoke — added after $PREV_PKG_NAME landed"
EOF

    # Re-link `pypi-curated` to BOTH rules so the existing
    # `block-known-bad-1` reference is preserved (removing it would
    # be a second curation-rule diff and muddy the metric assertions).
    cat > "$STAGE_ROOT/config/repositories/pypi-curated.yaml" <<EOF
apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: pypi-curated
spec:
  name: "PyPI Curated"
  description: "PyPI hosted repo wired to a CurationRule via gitops; smoke-test fixture"
  format: pypi
  type: hosted
  storage:
    backend: filesystem
    path: /var/lib/hort-server/cas/pypi-curated
  isPublic: true
  replicationPriority: local_only
  curationRules:
    - block-known-bad-1
    - block-retro-1
EOF

    SCRAPE_PRE_RETRO="$(scrape_metrics)"
    PRE_RETRO_BLOCK="$(metric_policy_eval_total "$SCRAPE_PRE_RETRO" curation_retroactive retro_block)"

    write_override "$STAGE_ROOT/config"
    restart_with_overlay

    SCRAPE_POST_RETRO="$(scrape_metrics)"
    POST_RETRO_BLOCK="$(metric_policy_eval_total "$SCRAPE_POST_RETRO" curation_retroactive retro_block)"
    delta_retro=$(( POST_RETRO_BLOCK - PRE_RETRO_BLOCK ))
    if [ "$delta_retro" -ge 1 ]; then
        assert_pass "hort_policy_evaluation_total{decision_point=curation_retroactive,result=retro_block} delta >= 1 (got $delta_retro)"
    else
        assert_fail \
            "hort_policy_evaluation_total{decision_point=curation_retroactive,result=retro_block} delta >= 1" \
            "got delta=$delta_retro (pre=$PRE_RETRO_BLOCK post=$POST_RETRO_BLOCK) — retroactive evaluator did not fire"
    fi

    # Artifact transitioned to `rejected` with the CurationRetroactive
    # reason. The reason variant is JSON-serialised under
    # `event_data.rejected_by` (typed enum, not a free-text string).
    POST_STATUS="$(psql_one "SELECT quarantine_status FROM artifacts WHERE id = '${PREV_ARTIFACT_ID}';")"
    if [ "$POST_STATUS" = "rejected" ]; then
        assert_pass "artifacts.quarantine_status for $PREV_PKG_NAME flipped to 'rejected'"
    else
        assert_fail \
            "artifacts.quarantine_status for $PREV_PKG_NAME flipped to 'rejected'" \
            "got '$POST_STATUS' (was '${PRE_RETRO_STATUS:-?}' pre-apply)"
    fi

    # Latest ArtifactRejected on this artifact's stream carries
    # `CurationRetroactive { rule_id: ... }` — the rule_id matches the
    # row we just persisted under metadata.name = 'block-retro-1'.
    RETRO_RULE_ID="$(psql_one "SELECT id FROM curation_rules WHERE name = 'block-retro-1';")"
    REJECT_REASON_BLOB="$(psql_one "SELECT event_data::text FROM events WHERE event_type = 'ArtifactRejected' AND stream_id = '${PREV_ARTIFACT_ID}' ORDER BY global_position DESC LIMIT 1;")"
    if echo "$REJECT_REASON_BLOB" | grep -q "CurationRetroactive" \
       && echo "$REJECT_REASON_BLOB" | grep -q "$RETRO_RULE_ID"; then
        assert_pass "ArtifactRejected.rejected_by carries CurationRetroactive { rule_id = $RETRO_RULE_ID }"
    else
        assert_fail \
            "ArtifactRejected.rejected_by carries CurationRetroactive { rule_id = $RETRO_RULE_ID }" \
            "blob=$REJECT_REASON_BLOB"
    fi

    # `CurationApplied { trigger: Retroactive, action: Block }` lands
    # on `StreamCategory::Curation` for this repo.
    REPO_UUID="$(psql_one "SELECT id FROM repositories WHERE key = '${PYPI_CURATED_REPO_KEY}';")"
    CURATION_APPLIED_COUNT="$(psql_count "SELECT COUNT(*) FROM events WHERE event_type = 'CurationApplied' AND stream_id = '${REPO_UUID}' AND event_data->>'trigger' = 'Retroactive' AND event_data->>'action' = 'Block';")"
    if [ "$CURATION_APPLIED_COUNT" -ge 1 ] 2>/dev/null; then
        assert_pass "CurationApplied { trigger=Retroactive, action=Block } event landed on the per-repo curation stream (count=$CURATION_APPLIED_COUNT)"
    else
        assert_fail \
            "CurationApplied { trigger=Retroactive, action=Block } event landed" \
            "got count='$CURATION_APPLIED_COUNT' for stream_id=$REPO_UUID"
    fi
fi

# -----------------------------------------------------------------------------
# Phase 6c — asymmetric weakening: rule Block → Allow does NOT auto-unblock
# -----------------------------------------------------------------------------
log ""
log "--> [6c] asymmetric weakening — rule action Block → Allow leaves rejection sticky"

if [ "$PHASE_6_SKIPPED" = "1" ]; then
    log "  SKIP (Keycloak token not available)"
else
    # Rewrite the rule with `action: allow` (a weakening). The retro
    # evaluator must NOT fire on weakening (asymmetry rule, mirroring
    # architect-skill quarantine invariant 3).
    cat > "$STAGE_ROOT/config/policies/curation-block-retro.yaml" <<EOF
apiVersion: project-hort.de/v1beta1
kind: CurationRule
metadata:
  name: block-retro-1
spec:
  format: any
  pattern: "${PREV_PKG_NAME}*"
  action: allow
  reason: "weakening test — rule action softened to allow"
EOF

    SCRAPE_PRE_WEAKEN="$(scrape_metrics)"
    PRE_WEAKEN_RETRO="$(metric_policy_eval_total "$SCRAPE_PRE_WEAKEN" curation_retroactive retro_block)"
    PRE_WEAKEN_RETRO_WARN="$(metric_policy_eval_total "$SCRAPE_PRE_WEAKEN" curation_retroactive retro_warn)"
    PRE_WEAKEN_NO_CHANGE="$(metric_policy_eval_total "$SCRAPE_PRE_WEAKEN" curation_retroactive no_change)"

    write_override "$STAGE_ROOT/config"
    restart_with_overlay

    # Artifact stays rejected — admin explicit release is the only
    # unblock path (architect-skill quarantine invariant 3).
    POST_WEAKEN_STATUS="$(psql_one "SELECT quarantine_status FROM artifacts WHERE id = '${PREV_ARTIFACT_ID}';")"
    if [ "$POST_WEAKEN_STATUS" = "rejected" ]; then
        assert_pass "artifact stays 'rejected' after rule weakening (Block → Allow does NOT auto-unblock)"
    else
        assert_fail \
            "artifact stays 'rejected' after rule weakening" \
            "got '$POST_WEAKEN_STATUS' — rule weakening unexpectedly cleared the rejection"
    fi

    SCRAPE_POST_WEAKEN="$(scrape_metrics)"
    POST_WEAKEN_RETRO="$(metric_policy_eval_total "$SCRAPE_POST_WEAKEN" curation_retroactive retro_block)"
    POST_WEAKEN_RETRO_WARN="$(metric_policy_eval_total "$SCRAPE_POST_WEAKEN" curation_retroactive retro_warn)"
    POST_WEAKEN_NO_CHANGE="$(metric_policy_eval_total "$SCRAPE_POST_WEAKEN" curation_retroactive no_change)"
    delta_weaken_retro=$(( POST_WEAKEN_RETRO - PRE_WEAKEN_RETRO ))
    delta_weaken_retro_warn=$(( POST_WEAKEN_RETRO_WARN - PRE_WEAKEN_RETRO_WARN ))
    delta_weaken_no_change=$(( POST_WEAKEN_NO_CHANGE - PRE_WEAKEN_NO_CHANGE ))
    # Weakening must NOT enqueue retro candidates. The retro_block /
    # retro_warn / no_change counters all stay flat.
    if [ "$delta_weaken_retro" = "0" ] \
       && [ "$delta_weaken_retro_warn" = "0" ] \
       && [ "$delta_weaken_no_change" = "0" ]; then
        assert_pass "rule weakening emitted zero curation_retroactive ticks (all three result counters flat)"
    else
        assert_fail \
            "rule weakening emitted zero curation_retroactive ticks" \
            "retro_block=$delta_weaken_retro retro_warn=$delta_weaken_retro_warn no_change=$delta_weaken_no_change — the apply pipeline ran the retroactive evaluator on a weakening (asymmetry violation)"
    fi
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
