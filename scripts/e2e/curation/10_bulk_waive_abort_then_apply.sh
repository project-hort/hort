#!/usr/bin/env bash
# Scenario 10: Bulk waive — abort on one unresolvable entry, then apply.
#
# The bulk waive is the only FAIL-OPEN surface in curation: it releases,
# and `ArtifactReleased` is history that cannot be retracted. Its whole
# safety rests on one promise — ONE invalid entry releases NOTHING — and
# that promise is a pre-validation pass over every entry of the batch
# that runs before the first append (`CurationUseCase::waive_bulk`
# step 5; the refusal is `409 Conflict` carrying the per-entry report,
# ADR 0025). The promise holds in unit tests against a mock HTTP server;
# this scenario is where it meets a real Postgres, the real digest
# resolver and a real HTTP boundary — which is where a property of this
# shape usually breaks.
#
# Three acts:
#
#   1. Two artifacts held. Seed them, then assert BOTH are held by
#      reading the server's own curation queue. A scenario that starts
#      from an unverified premise proves nothing about the step that
#      follows it.
#   2. The abort. `curation waive digests` with one resolvable digest and
#      one that resolves to nothing, one justification. Assert three
#      things, and the second is the point:
#        - the CLI exits 3 — the distinct abort code
#          (`hort_cli::curation::waive::WAIVE_ABORTED_EXIT`), not merely
#          non-zero;
#        - BOTH artifacts are STILL held, read back from the server's
#          curation queue, NOT inferred from the exit code. The exit code
#          says the CLI refused; only the hold says nothing was released,
#          and those are two different claims;
#        - the printed report names both entries — the resolvable one and
#          the unresolvable one — so an operator can see which half was
#          the problem without bisecting their list.
#   3. The apply. The same call with the bogus digest replaced by the
#      second artifact's real digest → exit 0 and both artifacts
#      released, each asserted on its own.
#
# WHY THE UNRESOLVABLE DIGEST IS WELL-FORMED 64-HEX, AND NOT A MALFORMED
# STRING. These are two different arms of the code and only one of them
# is this scenario's subject:
#
#   - A malformed digest (wrong length, uppercase hex, a `sha512:`
#     prefix) fails VALIDATION. `normalize_digest` in the CLI refuses it
#     before any HTTP call at all, and `normalize_curation_digest` in the
#     use case refuses the whole request before a single row is read.
#     That path exits 1 / answers 400 and never reaches pre-validation.
#   - A well-formed 64-lowercase-hex digest that simply matches no row
#     passes both validators, reaches the digest resolver, resolves to
#     `EntryResolution::None` → `WaiveEntryVerdict::Unresolvable`, and is
#     what makes the PRE-VALIDATION ABORT fire — the all-or-nothing
#     contract this scenario exists for.
#
# So the bogus digest below is generated as a SHA-256 of a unique string,
# and the scenario asserts both halves of that premise before using it:
# that it is 64 lowercase hex, and that it matches no stored artifact.
#
# Fixtures: the scenario seeds its OWN set via the suite's
# `seed_curation_fixtures`, because scenarios 1 and 9 consume the two
# quarantined rows the orchestrator seeded (1 releases one, 9 releases
# and then blocks the other). The seeded set lands in its own transient
# repository with its own digests, so everything here is scoped to this
# scenario's repo key and cannot pick up another scenario's rows; the
# EXIT trap removes it so a later run starts clean.
#
# Skip semantics:
#   - v2 stack unreachable → exit 2 (via _lib.sh require_stack_up).
#   - hort-cli not built → exit 2.
#   - fixtures cannot be seeded (Postgres unreachable) → exit 2.
#   - Keycloak admin token unavailable → exit 2.
# Everything past the seed is a genuine assertion: exit 1 on failure.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCRIPT_DIR/_lib.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then set -x; fi

log "==> Scenario 10: Bulk waive — abort on one unresolvable entry, then apply"

require_stack_up
require_hort_cli

ADMIN_TOKEN="$(keycloak_token admin admin)" || {
    log "SKIP: Keycloak admin token unavailable"
    exit 2
}
log "  got admin token"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
#
# Substring matching uses bash's own `[[ "$haystack" == *"$needle"* ]]`
# rather than a pipe into `grep -q`: the needles here are fixed strings
# (UUIDs, digests, verdict discriminators) with no regex metacharacters,
# and a `[[ ]]` match has none of the SIGPIPE/pipefail hazard that the
# suite's `Bounded:` notes exist to bound.

# Read the hold from the SERVER and assert both fixtures are still held.
# The curation queue serves only curator-actionable rows (Quarantined /
# Rejected / ScanIndeterminate), so a row present under
# `--status quarantined` is the server itself stating the artifact is
# held — not a status this script inferred from an exit code.
# $1: the moment being asserted, used in the assertion label.
assert_both_held() {
    local stage="$1"
    local out rc held aid
    out="$(run_hort_cli "$ADMIN_TOKEN" -- curation queue \
        --repo "$CURATION_SEED_REPO_KEY" --status quarantined 2>&1)"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        assert_fail "$stage: curation queue read succeeds" "exit=$rc output: $out"
        return 1
    fi
    held=0
    for aid in "$AID_A" "$AID_B"; do
        if [[ "$out" == *"$aid"* ]]; then
            assert_pass "$stage: $aid still held (server curation queue, status=quarantined)"
            held=$((held + 1))
        else
            assert_fail "$stage: $aid still held" \
                "artifact_id absent from the repo's quarantined queue — payload: $out"
        fi
    done
    [ "$held" -eq 2 ]
}

# Verdict the abort report recorded for one entry key, or empty when the
# body is not the report or carries no such entry. Bound to the KEY
# rather than matched loose against the whole body: "some entry says
# unresolvable" and "THIS entry says unresolvable" are different claims,
# and only the second one is worth asserting.
#
# python3 is already a hard dependency of this suite — `keycloak_token`
# parses its token response with it — so the scenario cannot have reached
# this line without it.
# $1: report body. $2: entry key.
abort_verdict() {
    printf '%s' "$1" | python3 -c '
import json, sys
try:
    body = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for entry in body.get("entries", []):
    if entry.get("key") == sys.argv[1]:
        print(entry.get("verdict", ""))
        break
' "$2" 2>/dev/null
}

# Exit 0 iff <artifact_id> is a member of list field <field> of the
# applied-batch envelope. Membership is decided on the PARSED list and
# never on a substring of the whole body: `released_artifact_ids` and
# `already_released_ids` are deliberately separate facts — a converged
# re-apply must not read as a release that just happened — and a
# substring match cannot tell which of the two an id landed in.
# $1: envelope body. $2: field name. $3: artifact id.
outcome_has_id() {
    printf '%s' "$1" | python3 -c '
import json, sys
try:
    body = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if sys.argv[2] in body.get(sys.argv[1], []) else 1)
' "$2" "$3" 2>/dev/null
}

# Count ArtifactReleased events on one artifact's stream.
released_event_count() {
    psql_count "SELECT COUNT(*) FROM events \
        WHERE stream_id = 'artifact-$1' AND event_type = 'ArtifactReleased';"
}

# -----------------------------------------------------------------------------
# ACT 1 — two artifacts held
# -----------------------------------------------------------------------------

STDERR_FILE="$(mktemp)"
# Installed BEFORE the seed so a half-created fixture set is still torn
# down; `cleanup_curation_fixtures` no-ops when no repository was made.
trap 'cleanup_curation_fixtures; rm -f "$STDERR_FILE"' EXIT

if ! seed_curation_fixtures; then
    log "SKIP: could not seed curation fixtures — is Postgres reachable?"
    exit 2
fi

# The two quarantined rows of THIS scenario's repo, each with the digest
# that addresses it. `btrim` because `artifacts.checksum_sha256` is
# `character(64)` and so blank-padded on read for a shorter value.
PAIRS_RAW="$(psql_lines "SELECT a.id::text || '|' || btrim(a.checksum_sha256) \
    FROM artifacts a \
    WHERE a.repository_id = '$CURATION_SEED_REPO_ID' \
      AND a.quarantine_status = 'quarantined' \
      AND a.deleted_at IS NULL \
    ORDER BY a.created_at DESC;")"
# `[:blank:]` and not `[:space:]`: the latter deletes the row separators
# too and collapses both rows onto one line.
mapfile -t PAIRS < <(printf '%s\n' "$PAIRS_RAW" | tr -d '[:blank:]' | grep -v '^$')

# Not a SKIP: the seed above succeeded, so a wrong fixture count means
# the suite's own seeded shape changed under this scenario rather than
# that the environment is unmet — and that has to be visible as a
# failure in the scenario that depends on it.
if [ "${#PAIRS[@]}" -ne 2 ]; then
    assert_fail "seeded fixture carries exactly 2 quarantined artifacts" \
        "got ${#PAIRS[@]}: ${PAIRS[*]:-<none>}"
    print_summary
    exit 1
fi

AID_A="${PAIRS[0]%%|*}"
DIGEST_A="${PAIRS[0]##*|}"
AID_B="${PAIRS[1]%%|*}"
DIGEST_B="${PAIRS[1]##*|}"

log "  repo        : $CURATION_SEED_REPO_KEY"
log "  artifact A  : $AID_A  digest ${DIGEST_A:0:12}…"
log "  artifact B  : $AID_B  digest ${DIGEST_B:0:12}…"

if ! assert_both_held "act 1 premise"; then
    log "  the premise does not hold — the acts below would prove nothing"
    print_summary
    exit 1
fi

# -----------------------------------------------------------------------------
# ACT 2 — the abort
# -----------------------------------------------------------------------------
#
# One resolvable digest and one that resolves to nothing. The resolvable
# one is FIRST on purpose: the batch must release nothing even though its
# leading entry pre-validated fine, which is what distinguishes "nothing
# was applied" from "the refusal short-circuited before it got there".

BOGUS_DIGEST="$(printf 'curation-e2e-scenario-10-no-such-content-%s-%s' \
    "$(date +%s%N)" "$$" | sha256sum | awk '{print $1}')"

# The load-bearing premise of this whole scenario, asserted rather than
# assumed — see the header: a malformed digest exercises validation, and
# only a WELL-FORMED digest that matches no row reaches the
# pre-validation abort.
if [[ "$BOGUS_DIGEST" =~ ^[0-9a-f]{64}$ ]]; then
    assert_pass "bogus digest is well-formed 64-lowercase-hex (exercises resolution, not validation)"
else
    assert_fail "bogus digest is well-formed 64-lowercase-hex" "got: $BOGUS_DIGEST"
    print_summary
    exit 1
fi

BOGUS_MATCHES="$(psql_count "SELECT COUNT(*) FROM artifacts \
    WHERE btrim(checksum_sha256) = '$BOGUS_DIGEST';")"
if [ "$BOGUS_MATCHES" = "0" ]; then
    assert_pass "bogus digest matches no stored artifact (resolves to nothing)"
else
    assert_fail "bogus digest matches no stored artifact" \
        "got $BOGUS_MATCHES row(s) — the entry would not be unresolvable"
    print_summary
    exit 1
fi

PRE_REL_A="$(released_event_count "$AID_A")"
PRE_REL_B="$(released_event_count "$AID_B")"

ABORT_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation waive digests \
    --repo "$CURATION_SEED_REPO_KEY" \
    --digests "$DIGEST_A,$BOGUS_DIGEST" \
    --justification "E2E scenario 10 act 2: one entry resolves to nothing, $(date -Is)" \
    2>"$STDERR_FILE")"
ABORT_RC=$?
ABORT_ERR="$(cat "$STDERR_FILE")"

# 2a — the distinct abort code, not merely non-zero. 3 separates "the
# batch was refused whole, nothing released" from 0 (applied) and from 1
# (a 403, a 404, a transport failure — the command never got an answer
# it could read), which an unattended caller must be able to tell apart
# without re-reading the output it just wrote.
if [ "$ABORT_RC" -eq 3 ]; then
    assert_pass "aborted bulk waive exits 3 (the distinct abort code)"
else
    assert_fail "aborted bulk waive exits 3" \
        "got exit=$ABORT_RC  stdout: $ABORT_OUT  stderr: $ABORT_ERR"
fi

# 2b — THE POINT. The hold is read back from the server. The exit code
# above says the CLI refused the batch; only this says nothing was
# released.
assert_both_held "act 2 after abort"

# The same claim on the axis that cannot be retracted: no
# `ArtifactReleased` was appended to either stream. A status that was
# re-held would still leave the event behind, and the event is the
# history the all-or-nothing contract protects.
POST_REL_A="$(released_event_count "$AID_A")"
POST_REL_B="$(released_event_count "$AID_B")"
if [ "$POST_REL_A" = "$PRE_REL_A" ] && [ "$POST_REL_B" = "$PRE_REL_B" ]; then
    assert_pass "no ArtifactReleased appended by the aborted batch (A=$POST_REL_A B=$POST_REL_B)"
else
    assert_fail "no ArtifactReleased appended by the aborted batch" \
        "A: $PRE_REL_A -> $POST_REL_A   B: $PRE_REL_B -> $POST_REL_B"
fi

# 2c — the report names BOTH entries, so an operator can see which half
# was the problem. Each verdict is read off the entry carrying that key.
VERDICT_A="$(abort_verdict "$ABORT_OUT" "$DIGEST_A")"
VERDICT_BOGUS="$(abort_verdict "$ABORT_OUT" "$BOGUS_DIGEST")"

if [ "$VERDICT_A" = "releasable" ]; then
    assert_pass "report names the resolvable entry, verdict=releasable"
else
    assert_fail "report names the resolvable entry with verdict=releasable" \
        "got verdict='$VERDICT_A' for $DIGEST_A — payload: $ABORT_OUT"
fi

if [ "$VERDICT_BOGUS" = "unresolvable" ]; then
    assert_pass "report names the unresolvable entry, verdict=unresolvable"
else
    assert_fail "report names the unresolvable entry with verdict=unresolvable" \
        "got verdict='$VERDICT_BOGUS' for $BOGUS_DIGEST — payload: $ABORT_OUT"
fi

# -----------------------------------------------------------------------------
# ACT 3 — the apply
# -----------------------------------------------------------------------------
#
# The same call with only the bogus digest replaced by artifact B's real
# one — which is what an operator does after reading an abort report.

APPLY_OUT="$(run_hort_cli "$ADMIN_TOKEN" -- curation waive digests \
    --repo "$CURATION_SEED_REPO_KEY" \
    --digests "$DIGEST_A,$DIGEST_B" \
    --justification "E2E scenario 10 act 3: both entries resolve, $(date -Is)" \
    2>"$STDERR_FILE")"
APPLY_RC=$?
APPLY_ERR="$(cat "$STDERR_FILE")"

if [ "$APPLY_RC" -eq 0 ]; then
    assert_pass "applied bulk waive exits 0"
else
    assert_fail "applied bulk waive exits 0" \
        "got exit=$APPLY_RC  stdout: $APPLY_OUT  stderr: $APPLY_ERR"
    print_summary
    exit 1
fi

# Both released, asserted individually — on the envelope and then on the
# server's own state. `released_artifact_ids` and not merely "named
# somewhere in the body": these artifacts were held, so a release that
# landed in `already_released_ids` would mean the waiver took effect
# earlier, which is a different fact.
for aid in "$AID_A" "$AID_B"; do
    if outcome_has_id "$APPLY_OUT" released_artifact_ids "$aid"; then
        assert_pass "$aid is in released_artifact_ids (released by this call)"
    else
        assert_fail "$aid is in released_artifact_ids" "payload: $APPLY_OUT"
    fi

    STATUS="$(psql_one "SELECT quarantine_status FROM artifacts WHERE id = '$aid';")"
    if [ "$STATUS" = "released" ]; then
        assert_pass "$aid transitioned to released"
    else
        assert_fail "$aid transitioned to released" "got status=$STATUS"
    fi
done

# The batch applied as ONE decision: both ArtifactReleased events carry
# the call's correlation_id, the waive-side counterpart of what scenario
# 3 asserts for a bulk block.
CORR_ID="$(json_get "$APPLY_OUT" '.correlation_id' 2>/dev/null || echo "")"
if [ -n "$CORR_ID" ] && [ "$CORR_ID" != "null" ]; then
    CORR_COUNT="$(psql_count "SELECT COUNT(*) FROM events \
        WHERE event_type = 'ArtifactReleased' \
          AND correlation_id = '$CORR_ID' \
          AND stream_id IN ('artifact-$AID_A', 'artifact-$AID_B');")"
    if [ "$CORR_COUNT" = "2" ]; then
        assert_pass "both ArtifactReleased events share correlation_id=$CORR_ID"
    else
        assert_fail "both ArtifactReleased events share one correlation_id" \
            "got count=$CORR_COUNT for correlation_id=$CORR_ID"
    fi
else
    assert_fail "applied outcome carries a correlation_id" "payload: $APPLY_OUT"
fi

# -----------------------------------------------------------------------------

print_summary
exit $?
