#!/usr/bin/env bash
# requires: db
# End-to-end smoke for the patch-candidate workflow.
#
#   1. Seed a transient npm proxy repo via psql.
#   2. Seed pkg@1.0 (released) + one High-severity scan_findings row.
#   3. Seed pkg@1.1 (quarantined, quarantine_window_start anchored +71h
#      so the computed release deadline stays in the future, no findings).
#   4. `hort-cli admin quarantine list-patch-candidates --output json`
#      → assert exactly one candidate row matching the seeded pair
#        (vulnerable=pkg@1.0, quarantined=pkg@1.1, severity="high",
#         finding count=1).
#   5. `hort-cli admin quarantine release <pkg@1.1 id>
#         --justification "patch-candidate smoke release"` → assert exit 0.
#   6. Assert artifacts.quarantine_status='released' for pkg@1.1.
#   7. Assert the latest `ArtifactReleased` event on the
#      `artifact-<pkg@1.1 id>` stream carries:
#        - `event_data->'data'->>'released_by_user_id' IS NOT NULL`
#        - `event_data->'data'->>'justification' = 'patch-candidate smoke release'`
#
# Assertion 7 is the load-bearing audit-trail invariant — it's what
# makes this smoke distinct from "just release a quarantined artifact"
# coverage.
#
# Direct psql seeding is intentional: the patch-candidate surface is
# READ-SIDE; this smoke exercises the read path + the existing release
# endpoint. The full ingest+scan pipeline is covered by
# test-vulnerability-scan.sh — duplicating it here would dilate runtime
# and bring back the OSV fixture-drift surface area.
#
# Skip semantics:
#   - Admin token fetch fails → skip (stack/realm not ready).
#   - hort-cli not on PATH → skip.
#   - Seeded psql INSERTs fail → fail (schema drift against migration column list).
#
# Cleanup trap removes every seeded row so subsequent smokes start
# clean. The cleanup runs unconditionally (registered BEFORE the
# first INSERT) so a partial setup still tears down.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Per-run nonce so the seeded repo key + scanner name are unique. Two
# concurrent runs of this smoke in the same DB do not collide.
NONCE="$(date +%s)-$$"
REPO_KEY="test-patch-candidate-${NONCE}"
SCANNER_NAME="init36-smoke-${NONCE}"
PKG_NAME="init36-pkg-${NONCE}"
JUSTIFICATION="patch-candidate smoke release"

# Deterministic SHA-256 placeholders. The values are SHA-256 of literal
# ASCII text — never collide with real CAS blobs because no upload path
# ever stores these exact strings.
V_SHA256="$(printf '%s' "init36-vulnerable-${NONCE}" | sha256sum | awk '{print $1}')"
Q_SHA256="$(printf '%s' "init36-quarantined-${NONCE}" | sha256sum | awk '{print $1}')"

# UUIDs are minted by Postgres `gen_random_uuid()` defaults; the script
# reads back the rowids after each INSERT (RETURNING id).

REPO_ID=""
V_ID=""           # vulnerable artifact (pkg@1.0, released)
Q_ID=""           # quarantined artifact (pkg@1.1)
SCAN_ID=""        # scan_findings.scan_id — synthetic UUID

# -----------------------------------------------------------------------------
# psql_count wrapper — empty result → "0", delegates to lib's psql_one
# -----------------------------------------------------------------------------

psql_count() {
    local out
    out="$(psql_one "$1")"
    if [ -z "$out" ]; then
        echo "0"
    else
        echo "$out"
    fi
}

# -----------------------------------------------------------------------------
# Cleanup — registered BEFORE the first INSERT so a partial setup still
# tears down. The DELETE order respects FK direction:
#   scan_findings → artifacts → repositories
#   events → (no FK; filter by stream_id prefix)
# `release_justification` is the join key for the events filter — the
# admin_release path always sets it to a non-empty string.
# -----------------------------------------------------------------------------

# shellcheck disable=SC2317  # invoked indirectly via `trap ... EXIT`
cleanup() {
    local ec=$?
    log ""
    log "==> cleanup"
    if [ -n "$REPO_ID" ]; then
        # Best-effort — swallow errors so the trap never masks the real exit code.
        psql_exec "DELETE FROM scan_findings WHERE source_scanner = '${SCANNER_NAME}';" \
            >/dev/null 2>&1 || true
        psql_exec "DELETE FROM events WHERE stream_category = 'artifact' AND event_data->'data'->>'justification' = '${JUSTIFICATION}';" \
            >/dev/null 2>&1 || true
        psql_exec "DELETE FROM artifacts WHERE repository_id = '${REPO_ID}';" \
            >/dev/null 2>&1 || true
        psql_exec "DELETE FROM repositories WHERE id = '${REPO_ID}';" \
            >/dev/null 2>&1 || true
    fi
    return "$ec"
}
trap cleanup EXIT

# -----------------------------------------------------------------------------
# Seeding helpers
# -----------------------------------------------------------------------------

seed_repository() {
    local out
    out="$(psql_exec "INSERT INTO repositories (
            key, name, format, repo_type, storage_path, upstream_url
        ) VALUES (
            '${REPO_KEY}',
            'patch-candidate smoke',
            'npm',
            'proxy',
            'init36-smoke',
            'https://registry.npmjs.org'
        ) RETURNING id;")"
    REPO_ID="$(printf '%s\n' "$out" | grep -Eo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)"
    if [ -z "$REPO_ID" ]; then
        log "  INSERT INTO repositories failed:"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    log "  seeded repository ${REPO_KEY} (id=${REPO_ID})"
}

seed_vulnerable_artifact() {
    # pkg@1.0 — released, with one High finding. `created_at` is
    # backdated 1 day so the self-join
    # (`v.created_at < q.created_at`) admits this row.
    local out
    out="$(psql_exec "INSERT INTO artifacts (
            repository_id, path, name, version, size_bytes,
            checksum_sha256, content_type, storage_key, name_as_published,
            quarantine_status, quarantine_window_start,
            created_at, updated_at
        ) VALUES (
            '${REPO_ID}',
            '${PKG_NAME}-1.0.tgz',
            '${PKG_NAME}',
            '1.0',
            100,
            '${V_SHA256}',
            'application/octet-stream',
            'init36-smoke/${V_SHA256}',
            '${PKG_NAME}',
            'released',
            NULL,
            now() - interval '1 day',
            now() - interval '1 day'
        ) RETURNING id;")"
    V_ID="$(printf '%s\n' "$out" | grep -Eo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)"
    if [ -z "$V_ID" ]; then
        log "  INSERT INTO artifacts (vulnerable) failed:"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    log "  seeded vulnerable artifact ${PKG_NAME}@1.0 (id=${V_ID})"
}

seed_quarantined_artifact() {
    # pkg@1.1 — quarantined. The schema stores the window ANCHOR
    # (quarantine_window_start), not an absolute deadline; the release
    # deadline is anchor + the policy's quarantine_duration. Anchoring it
    # 71h ahead keeps the deadline well in the future so the timer sweep
    # won't release it mid-test (the test releases it explicitly in step 5).
    # The patch-candidate query filters on quarantine_status='quarantined'
    # only, so a future anchor does not hide the row.
    local out
    out="$(psql_exec "INSERT INTO artifacts (
            repository_id, path, name, version, size_bytes,
            checksum_sha256, content_type, storage_key, name_as_published,
            quarantine_status, quarantine_window_start,
            created_at, updated_at
        ) VALUES (
            '${REPO_ID}',
            '${PKG_NAME}-1.1.tgz',
            '${PKG_NAME}',
            '1.1',
            100,
            '${Q_SHA256}',
            'application/octet-stream',
            'init36-smoke/${Q_SHA256}',
            '${PKG_NAME}',
            'quarantined',
            now() + interval '71 hours',
            now(),
            now()
        ) RETURNING id;")"
    Q_ID="$(printf '%s\n' "$out" | grep -Eo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)"
    if [ -z "$Q_ID" ]; then
        log "  INSERT INTO artifacts (quarantined) failed:"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    log "  seeded quarantined artifact ${PKG_NAME}@1.1 (id=${Q_ID})"
}

seed_finding() {
    # Synthetic scan_id — the migration only requires uuid+NOT NULL
    SCAN_ID="$(psql_one "SELECT gen_random_uuid();")"
    if [ -z "$SCAN_ID" ]; then
        log "  gen_random_uuid() returned empty — DB unreachable?"
        return 1
    fi
    local out
    out="$(psql_exec "INSERT INTO scan_findings (
            artifact_id, scan_id, purl, vulnerability_id, severity,
            cvss_score, source_scanner, title, detected_at
        ) VALUES (
            '${V_ID}',
            '${SCAN_ID}',
            'pkg:npm/${PKG_NAME}@1.0',
            'GHSA-test-init36',
            'high',
            7.5,
            '${SCANNER_NAME}',
            'smoke synthetic finding',
            now() - interval '1 hour'
        );")"
    if ! printf '%s\n' "$out" | grep -q 'INSERT 0 1'; then
        log "  INSERT INTO scan_findings failed:"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    log "  seeded scan_finding (scan_id=${SCAN_ID}, severity=high)"
}

# -----------------------------------------------------------------------------
# Driver
# -----------------------------------------------------------------------------

log "==> Patch-candidate quarantine release smoke"
log "api      : $HORT_URL"
log "metrics  : ${METRICS_URL:-<unset>}"
log "repo_key : $REPO_KEY"
log "pkg_name : $PKG_NAME"
log ""

# hort-cli is mandatory — the smoke is also a CLI surface check.
# Falling back to raw curl would skip the list-patch-candidates surface.
command -v hort-cli >/dev/null 2>&1 || skip "hort-cli missing in image"
HORT_CLI=hort-cli

# -----------------------------------------------------------------------------
# [1/5] Seed the repo + artifacts + finding
# -----------------------------------------------------------------------------

log ""
log "--> [1/5] seed transient repo + artifacts + scan_findings row"

if ! seed_repository; then
    fail "seed repository ${REPO_KEY}" "INSERT failed; see psql output above"
    summary
fi
pass "seeded repository ${REPO_KEY} (id=${REPO_ID})"

if ! seed_vulnerable_artifact; then
    fail "seed ${PKG_NAME}@1.0 (released)" "INSERT failed; see psql output above"
    summary
fi
pass "seeded ${PKG_NAME}@1.0 (released, id=${V_ID})"

if ! seed_quarantined_artifact; then
    fail "seed ${PKG_NAME}@1.1 (quarantined)" "INSERT failed; see psql output above"
    summary
fi
pass "seeded ${PKG_NAME}@1.1 (quarantined, id=${Q_ID})"

if ! seed_finding; then
    fail "seed scan_findings row for ${PKG_NAME}@1.0" \
        "INSERT failed; see psql output above"
    summary
fi
pass "seeded scan_findings row (severity=high) on ${PKG_NAME}@1.0"

# -----------------------------------------------------------------------------
# [2/5] Fetch a Keycloak admin token + export HORT_TOKEN / HORT_SERVER
# -----------------------------------------------------------------------------

log ""
log "--> [2/5] fetch admin access token from Keycloak (ROPC, user=admin)"
HORT_TOKEN_VAL="$(fetch_token admin admin)"
if [ -z "$HORT_TOKEN_VAL" ]; then
    skip "could not fetch admin token"
fi
export HORT_TOKEN="$HORT_TOKEN_VAL"
export HORT_SERVER="$HORT_URL"
pass "HORT_TOKEN (Keycloak admin JWT) + HORT_SERVER exported for hort-cli"

# -----------------------------------------------------------------------------
# [3/5] hort-cli admin quarantine list-patch-candidates --output json
# -----------------------------------------------------------------------------

log ""
# `--repo` is the repository KEY (free-form), not the UUID — the handler does
# `RepositoryRepository::find_by_key` and 404s on a miss (list_patch_candidates.rs).
log "--> [3/5] hort-cli admin quarantine list-patch-candidates --repo ${REPO_KEY} --output json"

LIST_OUT=""
LIST_RC=0
LIST_OUT="$("$HORT_CLI" admin quarantine list-patch-candidates \
    --repo "$REPO_KEY" \
    --output json 2>&1)" || LIST_RC=$?

if [ "$LIST_RC" -ne 0 ]; then
    fail "hort-cli admin quarantine list-patch-candidates exits 0" \
        "exit=${LIST_RC}, output: ${LIST_OUT}"
    summary
fi
pass "hort-cli admin quarantine list-patch-candidates exits 0"

# Parse the JSON via python3. The CLI emits the response envelope
# `{"candidates": [...]}` verbatim from the server (see
# list_patch_candidates.rs:127). Use a small python script rather than
# jq so the smoke doesn't grow a new dependency — the sibling vuln-scan
# smoke uses the same pattern. Pipe LIST_OUT via stdin (NOT
# substituted into a heredoc) so JSON escape sequences can't fight any
# string-literal escape rules; use `python3 -c '<script>'` so the
# heredoc / stdin slots stay free for the JSON payload.
parsed="$(printf '%s' "$LIST_OUT" | python3 -c '
import json, sys
target_q_id = sys.argv[1]
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except Exception as e:
    print("PARSE_ERROR", e)
    sys.exit(1)
candidates = data.get("candidates", [])
print("COUNT", len(candidates))
match = None
for c in candidates:
    if c.get("quarantined_artifact_id") == target_q_id:
        match = c
        break
if match is None:
    print("NO_MATCH")
    sys.exit(0)
print("VULN_ID", match.get("vulnerable_artifact_id", ""))
print("VULN_VER", match.get("vulnerable_version", ""))
print("QUAR_VER", match.get("quarantined_version", ""))
print("SEVERITY", match.get("vulnerable_max_severity", ""))
print("FINDINGS", match.get("vulnerable_finding_count", -1))
print("PKG", match.get("package_name", ""))
print("FORMAT", match.get("format", ""))
' "$Q_ID" 2>&1)"

# The python script writes labeled key=value lines; pull them out with
# grep so the assertions stay readable.
parsed_field() {
    printf '%s\n' "$parsed" | awk -v k="$1" '$1 == k { $1=""; sub(/^ /,""); print; exit }'
}

COUNT_VAL="$(parsed_field COUNT)"
VULN_ID_VAL="$(parsed_field VULN_ID)"
VULN_VER_VAL="$(parsed_field VULN_VER)"
QUAR_VER_VAL="$(parsed_field QUAR_VER)"
SEV_VAL="$(parsed_field SEVERITY)"
FIND_VAL="$(parsed_field FINDINGS)"
PKG_VAL="$(parsed_field PKG)"
FORMAT_VAL="$(parsed_field FORMAT)"

# Repo-scoped filter (--repo $REPO_KEY) returns *only* candidates from
# that repo. The transient repo has exactly one quarantined+vulnerable
# pair so the response must be a single-element array.
if [ "$COUNT_VAL" = "1" ]; then
    pass "list-patch-candidates returned exactly 1 candidate (repo-scoped)"
else
    fail "list-patch-candidates returned exactly 1 candidate" \
        "got count=${COUNT_VAL}; raw response: ${LIST_OUT}"
fi

if [ "$VULN_ID_VAL" = "$V_ID" ]; then
    pass "candidate.vulnerable_artifact_id == ${PKG_NAME}@1.0 id"
else
    fail "candidate.vulnerable_artifact_id == ${V_ID}" \
        "got '${VULN_ID_VAL}'"
fi

if [ "$VULN_VER_VAL" = "1.0" ] && [ "$QUAR_VER_VAL" = "1.1" ]; then
    pass "candidate version pair = 1.0 -> 1.1"
else
    fail "candidate version pair = 1.0 -> 1.1" \
        "got vulnerable='${VULN_VER_VAL}' quarantined='${QUAR_VER_VAL}'"
fi

# Server-side SeverityThreshold::Display renders lowercase ("high"); see
# admin.rs:853 — the CLI passes it through unchanged.
if [ "$SEV_VAL" = "high" ]; then
    pass "candidate.vulnerable_max_severity == 'high'"
else
    fail "candidate.vulnerable_max_severity == 'high'" \
        "got '${SEV_VAL}'"
fi

if [ "$FIND_VAL" = "1" ]; then
    pass "candidate.vulnerable_finding_count == 1"
else
    fail "candidate.vulnerable_finding_count == 1" \
        "got ${FIND_VAL}"
fi

if [ "$PKG_VAL" = "$PKG_NAME" ] && [ "$FORMAT_VAL" = "npm" ]; then
    pass "candidate.package_name=${PKG_NAME} format=npm"
else
    fail "candidate package + format match seed" \
        "got package_name='${PKG_VAL}' format='${FORMAT_VAL}'"
fi

# -----------------------------------------------------------------------------
# [4/5] hort-cli admin quarantine release <Q_ID> --justification ...
# -----------------------------------------------------------------------------

log ""
log "--> [4/5] hort-cli admin quarantine release ${Q_ID} --justification '${JUSTIFICATION}'"

REL_OUT=""
REL_RC=0
REL_OUT="$("$HORT_CLI" admin quarantine release "$Q_ID" \
    --justification "$JUSTIFICATION" \
    --output json 2>&1)" || REL_RC=$?
if [ "$REL_RC" -eq 0 ]; then
    pass "hort-cli admin quarantine release exits 0"
else
    fail "hort-cli admin quarantine release exits 0" \
        "exit=${REL_RC}, output: ${REL_OUT}"
    summary
fi

# -----------------------------------------------------------------------------
# [5/5] Assert artifact state + audit-event invariant
# -----------------------------------------------------------------------------

log ""
log "--> [5/5] assert quarantine_status='released' + ArtifactReleased audit invariant"

# The release endpoint is event-sourced; the artifacts projection
# updates in the same Postgres transaction as the event append
# (`QuarantineUseCase::admin_release` writes both via the projection
# runner's at-most-once write path). In practice the row is
# `released` immediately on the next read, but use bounded_poll to be
# robust to projection-runner clock skew (≤ 15s deadline so a stuck
# projection still surfaces as a real failure, not a 60s hang).
if bounded_poll \
        "artifact ${Q_ID} → released" \
        15 \
        "[ \"\$(psql_one \"SELECT quarantine_status FROM artifacts WHERE id = '${Q_ID}';\")\" = 'released' ]" \
        1; then
    pass "artifacts.quarantine_status='released' for ${PKG_NAME}@1.1"
else
    final_status="$(psql_one "SELECT quarantine_status FROM artifacts WHERE id = '${Q_ID}';" || true)"
    fail "artifacts.quarantine_status='released' for ${PKG_NAME}@1.1" \
        "final status='${final_status}' — projection did not advance after release"
fi

# Audit-trail invariant. event_data is the typed-event envelope
# `{ "type": ..., "data": { ... } }`, so the payload fields live under
# `->'data'`. The releasing admin is recorded as `released_by_user_id`
# (there is no `admin_id` field); the justification is captured verbatim:
# `event_data->'data'->>'released_by_user_id' IS NOT NULL` AND
# `event_data->'data'->>'justification' = '${JUSTIFICATION}'` on the latest
# ArtifactReleased event of the stream. Stream id format is
# `artifact-{uuid}` per crates/hort-domain/src/events/mod.rs:133 (note:
# hyphen, not colon — the design-doc snippet was illustrative).
STREAM_ID="artifact-${Q_ID}"

RELEASED_BY_VAL="$(psql_one "SELECT event_data->'data'->>'released_by_user_id' FROM events \
    WHERE event_type = 'ArtifactReleased' AND stream_id = '${STREAM_ID}' \
    ORDER BY stream_position DESC LIMIT 1;")"
JUSTIF_VAL="$(psql_one "SELECT event_data->'data'->>'justification' FROM events \
    WHERE event_type = 'ArtifactReleased' AND stream_id = '${STREAM_ID}' \
    ORDER BY stream_position DESC LIMIT 1;")"

if [ -n "$RELEASED_BY_VAL" ]; then
    pass "latest ArtifactReleased event carries released_by_user_id (=${RELEASED_BY_VAL})"
else
    fail "latest ArtifactReleased event carries released_by_user_id" \
        "event_data->'data'->>'released_by_user_id' is NULL or event missing on ${STREAM_ID}"
fi

# psql_one strips whitespace — the justification string has none so the
# equality comparison is safe.
EXPECTED_JUSTIF_STRIPPED="$(printf '%s' "$JUSTIFICATION" | tr -d '[:space:]')"
if [ "$JUSTIF_VAL" = "$EXPECTED_JUSTIF_STRIPPED" ]; then
    pass "latest ArtifactReleased event carries justification='${JUSTIFICATION}'"
else
    fail "latest ArtifactReleased event carries justification='${JUSTIFICATION}'" \
        "event_data->'data'->>'justification' = '${JUSTIF_VAL}' (expected stripped: '${EXPECTED_JUSTIF_STRIPPED}')"
fi

summary
