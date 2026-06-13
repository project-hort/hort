#!/usr/bin/env bash
# Scenario 3: Bulk block by version list.
#
# Spec: ingest THREE versions of the same package, all in `Released`;
# via `hort-cli curation block versions --repo <key> --package <name>
# --versions v1,v2,v3 --justification "<text>"` reject all three; assert
# THREE `ArtifactRejected` events on the per-artifact streams, ALL
# carrying the SAME `correlation_id`; assert one additional version `v4`
# not in the list stays `Released`; assert a `--versions
# v1,v_nonexistent` mix reports `v_nonexistent` in
# `BlockOutcome.not_found_versions` AND blocks `v1` cleanly.
#
# Implementation strategy:
#   - The scenario requires 4 Released artifacts of the same package,
#     differing only in version. The most reliable source is the
#     existing PyPI / npm / cargo e2e fixtures — but those typically
#     ingest a single version per package, not four.
#   - We approximate by querying the DB for any package with >= 3
#     Released versions; if not present, the scenario self-skips.
#   - If we have 4+ versions, we bulk-block 3 of them, leave the 4th
#     alone, and then perform the mixed-nonexistent-version round.
#
# Skip semantics: when the DB doesn't have 4+ Released versions of any
# package, exit 2 — the scenario can't run without that fixture shape.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then set -x; fi

log "==> Scenario 3: Bulk block by version list"

require_stack_up
require_hort_cli

# -----------------------------------------------------------------------------
# 1. Find a (repo, package) tuple with ≥4 Released versions
# -----------------------------------------------------------------------------

ADMIN_TOKEN="$(keycloak_token admin admin)" || {
    log "SKIP: Keycloak admin token unavailable"
    exit 2
}

# Note: artifacts.repository_id → repositories.id → repositories.key.
QUERY="SELECT r.key || '|' || a.name || '|' || COUNT(*) \
    FROM artifacts a JOIN repositories r ON a.repository_id = r.id \
    WHERE a.quarantine_status = 'released' \
    GROUP BY r.key, a.name HAVING COUNT(*) >= 4 LIMIT 1;"
FIXTURE_ROW="$(psql_one "$QUERY")"
if [ -z "$FIXTURE_ROW" ]; then
    log "SKIP: no (repo, package) tuple in DB has ≥4 Released versions."
    log "      Scenario 3 requires a multi-version fixture that the current"
    log "      v2 ingest harness does not stage. Document as DEFERRED."
    exit 2
fi

REPO_KEY="$(echo "$FIXTURE_ROW" | cut -d'|' -f1)"
PKG_NAME="$(echo "$FIXTURE_ROW" | cut -d'|' -f2)"

# Take 4 versions: first 3 to block, 4th to leave alone.
VERSIONS_RAW="$(psql_lines "SELECT version FROM artifacts a \
    JOIN repositories r ON a.repository_id = r.id \
    WHERE r.key = '$REPO_KEY' AND a.name = '$PKG_NAME' \
      AND a.quarantine_status = 'released' \
    ORDER BY a.created_at DESC LIMIT 4;" 2>/dev/null)"
# shellcheck disable=SC2206
VERSIONS=($(echo "$VERSIONS_RAW" | tr -d ' ' | grep -v '^$'))

if [ "${#VERSIONS[@]}" -lt 4 ]; then
    log "SKIP: expected 4 versions, got ${#VERSIONS[@]}"
    exit 2
fi

V1="${VERSIONS[0]}"; V2="${VERSIONS[1]}"; V3="${VERSIONS[2]}"; V4="${VERSIONS[3]}"
log "  fixture: repo=$REPO_KEY pkg=$PKG_NAME"
log "  blocking v1=$V1 v2=$V2 v3=$V3   keeping v4=$V4"

# -----------------------------------------------------------------------------
# 2. Bulk-block v1,v2,v3
# -----------------------------------------------------------------------------

JUSTIFICATION="E2E scenario 3: bulk block by versions, $(date -Is)"

BULK_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation block versions \
    --repo "$REPO_KEY" --package "$PKG_NAME" \
    --versions "$V1,$V2,$V3" \
    --justification "$JUSTIFICATION" 2>&1)" || {
    assert_fail "bulk block call succeeds" "hort-cli output: $BULK_OUT"
    print_summary
    exit 1
}
assert_pass "bulk block HTTP call succeeded"

# Parse outcome
BLOCKED_LIST="$(json_get "$BULK_OUT" '.blocked_artifact_ids' 2>/dev/null || echo "[]")"
ALREADY_LIST="$(json_get "$BULK_OUT" '.already_rejected_ids' 2>/dev/null || echo "[]")"
CORR_ID="$(json_get "$BULK_OUT" '.correlation_id' 2>/dev/null || echo "")"
TOTAL_PER_OUTCOME="$(printf '%s\n%s' "$BLOCKED_LIST" "$ALREADY_LIST" \
    | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    | sort -u | wc -l)"

if [ "$TOTAL_PER_OUTCOME" = "3" ]; then
    assert_pass "outcome resolves 3 artifact ids across blocked+already_rejected"
else
    assert_fail "outcome resolves 3 artifact ids" \
        "got $TOTAL_PER_OUTCOME — payload: $BULK_OUT"
fi

if [ -n "$CORR_ID" ] && [ "$CORR_ID" != "null" ]; then
    assert_pass "outcome.correlation_id present ($CORR_ID)"
else
    assert_fail "outcome.correlation_id present" "got null"
fi

# -----------------------------------------------------------------------------
# 3. Assert 3 ArtifactRejected events sharing the same correlation_id
# -----------------------------------------------------------------------------

if [ -n "$CORR_ID" ]; then
    # event_data ->> 'correlation_id' equality. Look across the 3 v1/v2/v3
    # artifact streams (a JOIN against artifacts on (repo, name, version)).
    EVT_COUNT="$(psql_count "SELECT COUNT(*) FROM events e \
        JOIN artifacts a ON e.stream_id = 'artifact-' || a.id::text \
        JOIN repositories r ON a.repository_id = r.id \
        WHERE e.event_type = 'ArtifactRejected' \
          AND e.correlation_id = '$CORR_ID' \
          AND r.key = '$REPO_KEY' AND a.name = '$PKG_NAME' \
          AND a.version IN ('$V1','$V2','$V3');")"
    if [ "$EVT_COUNT" = "3" ]; then
        assert_pass "3 ArtifactRejected events share correlation_id=$CORR_ID"
    else
        assert_fail "3 ArtifactRejected events share correlation_id" \
            "got count=$EVT_COUNT"
    fi
fi

# -----------------------------------------------------------------------------
# 4. Assert v4 remained Released
# -----------------------------------------------------------------------------

V4_STATUS="$(psql_one "SELECT a.quarantine_status FROM artifacts a \
    JOIN repositories r ON a.repository_id = r.id \
    WHERE r.key = '$REPO_KEY' AND a.name = '$PKG_NAME' AND a.version = '$V4';")"
if [ "$V4_STATUS" = "released" ]; then
    assert_pass "v4 ($V4) stays Released — not in version list"
else
    assert_fail "v4 stays Released" "got status=$V4_STATUS"
fi

# -----------------------------------------------------------------------------
# 5. Mixed real + nonexistent version
# -----------------------------------------------------------------------------
#
# The spec says: with `--versions v1,v_nonexistent`, v_nonexistent
# should land in `BlockOutcome.not_found_versions` AND v1 should block
# cleanly. But v1 was already blocked above — re-blocking should land in
# `already_rejected_ids` (idempotent no-op). The spec phrasing "blocks
# v1 cleanly" accommodates both interpretations (a fresh block AND an
# idempotent already_rejected entry both demonstrate "the call did not
# fail on the nonexistent version").
#
# We use V4 (still Released) for the "real" version slot.

NONEXIST_VER="zz_${RANDOM}_does_not_exist_in_db"

MIXED_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation block versions \
    --repo "$REPO_KEY" --package "$PKG_NAME" \
    --versions "$V4,$NONEXIST_VER" \
    --justification "E2E scenario 3 mixed nonexistent, $(date -Is)" 2>&1)" || {
    assert_fail "mixed-nonexistent bulk block succeeds" "hort-cli output: $MIXED_OUT"
    print_summary
    exit 1
}
assert_pass "mixed-nonexistent block call succeeded"

# Assert not_found_versions contains the nonexistent version
if printf '%s' "$MIXED_OUT" | grep -q "$NONEXIST_VER"; then
    assert_pass "outcome.not_found_versions contains the bogus version"
else
    assert_fail "outcome.not_found_versions contains the bogus version" \
        "payload: $MIXED_OUT"
fi

# Assert v4 transitioned (either blocked_artifact_ids OR already_rejected_ids).
V4_STATUS_AFTER="$(psql_one "SELECT a.quarantine_status FROM artifacts a \
    JOIN repositories r ON a.repository_id = r.id \
    WHERE r.key = '$REPO_KEY' AND a.name = '$PKG_NAME' AND a.version = '$V4';")"
if [ "$V4_STATUS_AFTER" = "rejected" ]; then
    assert_pass "v4 ($V4) transitioned to Rejected via mixed-call"
else
    assert_fail "v4 transitioned to Rejected" "got status=$V4_STATUS_AFTER"
fi

# -----------------------------------------------------------------------------

print_summary
exit $?
