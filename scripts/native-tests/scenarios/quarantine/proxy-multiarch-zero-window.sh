#!/usr/bin/env bash
# requires: egress db
#
# Proxy multi-arch pull-through -> #46 Item 2 zero-window descendant release
# (issue #50 / backlog/037). Regression gate for the composition of
# pull-through edge-write x ingest target-check x release-eligibility that
# shipped broken once (hosted-push path only) and had to be re-fixed
# (`58b8548c`, the pull-through path) with no automated E2E catching either
# failure — only prod validation did.
#
# ---------------------------------------------------------------------------
# WHY A DIFFERENTIAL ASSERTION, NOT "the child releases on its own
# ScanSucceeded" (the issue's literal acceptance criterion).
# ---------------------------------------------------------------------------
# It cannot assert that here. `deploy/compose/example-config/policies/
# oci-quarantine-e2e-quarantine.yaml` records why: the compose stack runs NO
# hort-worker, so no scan ever completes — `scanBackends: []` keeps the hold
# purely time-based on purpose. Chasing `ScanSucceeded` would mean standing up
# machinery that does not exist in this harness (explicitly out of scope —
# see the directive's "Do NOT" list).
#
# The substitute — under ONE policy (quarantineDuration: 24h), pulled in ONE
# proxy fetch — compares two artifacts from the same pull:
#
#   | Artifact                         | Expected quarantine_window_start |
#   |-----------------------------------|-----------------------------------|
#   | the INDEX (not a content_references TARGET of anything) | == the earliest observation of its OWN bytes, `MIN(created_at)` over every `artifacts` row sharing its checksum (ADR 0054) |
#   | a CHILD MANIFEST (a referenced descendant — the index's `oci_index_member` target) | == created_at - 24h (zero window, #46 Item 2 carve-out) |
#
# This proves the #46 Item 2 carve-out fires for PROXY-PULLED trees
# specifically (the pull-through path #50 was filed against, not the hosted
# push path `quarantine/oci-image-index.sh` already covers), needs no worker,
# and — per the hollowness trap below — cannot pass no matter what the code
# does.
#
# ---------------------------------------------------------------------------
# WHY THE INDEX'S EXPECTED ANCHOR IS NOT `created_at` — CROSS-REPOSITORY AGE
# EVIDENCE IS THE MECHANISM UNDER TEST HERE, NOT AN EXCEPTION TO IT.
# ---------------------------------------------------------------------------
# ADR 0054 anchors a non-descendant's window on the earliest DEFENSIBLE
# EVIDENCE of the content's age, and its primary source is hort's own
# earliest observation of those exact bytes in ANY of its repositories —
# `first_seen_for_checksum`, a live `MIN(created_at)` over the `artifacts`
# rows sharing the checksum, unscoped by repository and unfiltered by
# `is_deleted` (crates/hort-adapters-postgres/src/artifact_repo.rs). The
# per-row `created_at` is only the answer when hort holds NO earlier
# observation.
#
# In this suite it does hold one. `scenarios/proxy/oci-mirror.sh` sorts
# before this file (run.sh walks `find … | sort`, and `proxy/` precedes
# `quarantine/`) and pulls the SAME alpine:3.19 index through a DIFFERENT
# repository minutes earlier. So by the time this scenario mints its own
# row, hort has genuinely observed these bytes already, and the derivation
# correctly takes that earlier instant — the world has had exactly that much
# longer to look at them, which is the entire proposition the window proxies.
# An `== created_at` assertion here encodes the pre-0054 model, in which a
# fresh row always anchored at `now` unless the descendant carve-out applied;
# it fails on a correct build the moment another scenario shares the content.
#
# The assertion below is therefore stated as the invariant itself: anchor ==
# `MIN(created_at)` over the index's own checksum. For genuinely cold content
# that reduces to `created_at` and asserts exactly what the old form did, so
# nothing is weakened; here it matches the `proxy/oci-mirror.sh` row, and the
# scenario LOGS which of the two cases it observed. The differential's other
# half is unaffected: the child's carve-out contributes `minted_at - 24h`,
# which is the minimum against any observation made minutes ago, so a warm
# child still anchors at exactly `created_at - 24h`. (Only an observation
# older than the full 24h window could beat the carve-out — impossible
# within one compose run, and Step 7 names it if a long-lived stack ever
# produces one.) That the index did NOT take the carve-out is proven by
# Step 7: a carve-out anchor is immediately release-eligible, and Step 7
# asserts the index is not.
#
# ---------------------------------------------------------------------------
# THE HOLLOWNESS TRAP — DO NOT "SIMPLIFY" THIS ONTO oci-mirror-e2e.
# ---------------------------------------------------------------------------
# oci-mirror-e2e's ScanPolicy is quarantineDuration: 0s. Reaching for that
# existing permissive repo is the obvious shortcut, and it SILENTLY GUTS this
# scenario: with duration=0, `created_at` and `created_at - duration` are the
# literal same instant, so "index window == created_at" and "child window ==
# created_at - duration" both trivially hold REGARDLESS of whether the #46
# Item 2 carve-out is even wired — the assertion would pass on code that
# never anchors a zero window at all. That is exactly the class of gap #50
# exists to close (the fix shipped broken once with no test to catch it).
# This is why a DEDICATED, NON-ZERO-DURATION repo+policy
# (oci-proxy-quarantine-e2e, quarantineDuration: 24h) exists rather than
# reusing oci-mirror-e2e or oci-quarantine-e2e (that one's push-based, not
# proxy pull-through). See backlog/037's "hollowness trap" section — the same
# failure mode backlog/036 guards against with its >5 MiB blob-size floor.
#
# ---------------------------------------------------------------------------
# WHY "releasable-OR-released" — the eligibility predicate.
# ---------------------------------------------------------------------------
# The child's window anchor (created_at - 24h) means its computed deadline
# (anchor + 24h == created_at) has ALREADY PASSED the instant it is ingested.
# This scenario's own `requires:` line (egress db) does not need a worker, so
# in an ISOLATED run (e.g. `--scenario`) nothing ever claims the
# `quarantine-release-sweep` job and the row just sits ELIGIBLE. But
# `scripts/native-tests/run.sh` computes `--profile worker` ONCE, over the
# union of every selected scenario's `requires:` — so in a combined/full run
# that also selects a worker-requiring scenario (e.g.
# `proxy-required-multilayer.sh`), the shared compose stack's hort-worker AND
# `hort-sweep-ticker` (also `profile: worker`) are BOTH live for this
# scenario's entire run too. The ticker's cadence is `SWEEP_TICK_SECS`
# (dev/CI default 30s, see deploy/compose/docker-compose.yml) — fast enough
# that the sweep can legitimately claim and release this already-eligible
# child mid-scenario. A `released` status is a STRICTLY STRONGER proof that
# the release-sweep selection predicate held (it only fires post-hoc on rows
# that satisfied it) than an unconsumed `eligible` reading — so every
# assertion below that touches the child's `quarantine_status` accepts
# EITHER outcome. The exact predicate
# `crates/hort-adapters-postgres/src/quarantine_release_candidates.rs`'s
# `select_expired` query uses — `quarantine_status = 'quarantined' AND
# quarantine_window_start <= now() - duration` — is evaluated directly via
# `psql_one` for the eligible case; it needs no sweep task to actually run to
# be true or false right now, and it is exactly what "becomes releasable at
# the next sweep" means operationally: the row satisfies the sweep's own
# selection query, whenever a worker next polls it. The index's window is a
# full, fresh 24h — it cannot elapse mid-run — so index assertions stay
# strict (`quarantined` / not-eligible only).
#
# ---------------------------------------------------------------------------
# WHY alpine:3.19, WHY digests not counts.
# ---------------------------------------------------------------------------
# alpine:3.19 is a genuine multi-arch OCI image index and is already the
# upstream fixture `proxy/oci-mirror.sh` pulls — no new external dependency.
# Per #51 (merged): blob warming now fires on the digest path, so pulling the
# child manifest also spawns BACKGROUND pull-throughs of its config + layer
# blobs. Extra artifacts appearing shortly after are expected and correct,
# not a leak — so every assertion below targets a SPECIFIC digest (parsed out
# of the actual served index/manifest JSON), never a row count.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

REPO_KEY="oci-proxy-quarantine-e2e"
IMAGE="${IMAGE:-alpine:3.19}"
RESOLVER_REFRESH_GUESS="${RESOLVER_REFRESH_GUESS:-8}"

OCI_INDEX_MEDIA="application/vnd.oci.image.index.v1+json"
DOCKER_LIST_MEDIA="application/vnd.docker.distribution.manifest.list.v2+json"
OCI_MANIFEST_MEDIA="application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST_MEDIA="application/vnd.docker.distribution.manifest.v2+json"

command -v jq >/dev/null 2>&1 || skip "jq not found"
command -v curl >/dev/null 2>&1 || skip "curl not found"

IMAGE_REPO="${IMAGE%%:*}"
IMAGE_TAG="${IMAGE##*:}"
case "$IMAGE_REPO" in
    */*) IMAGE_PATH="${IMAGE_REPO}" ;;
    *)   IMAGE_PATH="library/${IMAGE_REPO}" ;;
esac

BASE_URL="${HORT_URL}/v2/${REPO_KEY}/dockerhub/${IMAGE_PATH}"

log "==> Proxy multi-arch pull -> zero-window descendant release (issue #50)"
log "Registry:  ${HORT_URL}"
log "Repo key:  ${REPO_KEY}"
log "Image:     ${IMAGE} (${IMAGE_PATH})"

# ---------------------------------------------------------------------
# Preflight: the resolver cache picks up gitops-applied upstream mappings
# on its own refresh cadence (mirrors proxy/oci-mirror.sh's wait).
# ---------------------------------------------------------------------
log ""
log "--- Preflight: waiting up to ${RESOLVER_REFRESH_GUESS}s for the resolver cache"
sleep "${RESOLVER_REFRESH_GUESS}"

# ---------------------------------------------------------------------
# Step 0: ANONYMOUS cold-pull of the INDEX by tag. This is the triggering
# fetch — it performs the cold ingest — and the designed proxy read path
# never hands an unprivileged caller the freshly-ingested, still-quarantined
# manifest: the response is 503 with a Retry-After header and an
# UNAVAILABLE error body, not the manifest itself. This is the regression
# pin for that hold.
# ---------------------------------------------------------------------
log ""
log "--- Step 0: ANONYMOUS GET the index by tag (cold ingest; must hold, not serve)"

ANON_HEADERS="$(mktemp)"
ANON_BODY="$(mktemp)"
trap 'rm -f "$ANON_HEADERS" "$ANON_BODY" "${INDEX_HEADERS:-}" "${INDEX_BODY:-}" "${CHILD_HEADERS:-}" "${CHILD_BODY:-}"' EXIT

ANON_CODE="$(curl -sS -o "$ANON_BODY" -D "$ANON_HEADERS" -w '%{http_code}' \
    -H "Accept: ${OCI_INDEX_MEDIA}, ${DOCKER_LIST_MEDIA}" \
    "${BASE_URL}/manifests/${IMAGE_TAG}" 2>/dev/null || echo 000)"
if [ "$ANON_CODE" = "503" ]; then
    pass "ANONYMOUS GET index by tag -> 503 (quarantined; cold ingest performed)"
else
    fail "ANONYMOUS GET index by tag -> 503" "got HTTP ${ANON_CODE} (egress? upstream reachable? gitops applied?)"
    summary
fi

if grep -qi '^retry-after:' "$ANON_HEADERS"; then
    pass "ANONYMOUS 503 carries a Retry-After header"
else
    fail "ANONYMOUS 503 carries a Retry-After header" "no Retry-After header in response"
fi

ANON_ERROR_CODE="$(jq -r '.errors[0].code // empty' "$ANON_BODY" 2>/dev/null)"
if [ "$ANON_ERROR_CODE" = "UNAVAILABLE" ]; then
    pass "ANONYMOUS 503 body errors[0].code == UNAVAILABLE"
else
    fail "ANONYMOUS 503 body errors[0].code == UNAVAILABLE" "got '${ANON_ERROR_CODE:-<empty>}'"
fi

# ---------------------------------------------------------------------
# Auth: the write-authorized hold-read exemption (ADR 0039 §10) keys on
# GRANTED write authority, so steps 1/2 authenticate as dev-user
# (write-granted on this repo — see deploy/compose/example-config/auth/
# dev-write-oci-proxy-quarantine-e2e.yaml) to read the still-held manifests.
# ---------------------------------------------------------------------
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"
[ -n "$DEV_TOKEN" ] || summary

# ---------------------------------------------------------------------
# Step 1: AUTHENTICATED re-GET of the INDEX by tag — the write-authorized
# hold-read exemption serves the already-quarantined manifest.
# ---------------------------------------------------------------------
log ""
log "--- Step 1: AUTHENTICATED GET the index by tag (write-authorized hold-read)"

INDEX_HEADERS="$(mktemp)"
INDEX_BODY="$(mktemp)"

INDEX_CODE="$(curl -sS -o "$INDEX_BODY" -D "$INDEX_HEADERS" -w '%{http_code}' \
    -H "Authorization: Bearer ${DEV_TOKEN}" \
    -H "Accept: ${OCI_INDEX_MEDIA}, ${DOCKER_LIST_MEDIA}" \
    "${BASE_URL}/manifests/${IMAGE_TAG}" 2>/dev/null || echo 000)"
if [ "$INDEX_CODE" = "200" ]; then
    pass "AUTHENTICATED GET index by tag -> 200 (write-authorized hold-read exemption)"
else
    fail "AUTHENTICATED GET index by tag -> 200" "got HTTP ${INDEX_CODE}"
    summary
fi

INDEX_DIGEST="$(tr -d '\r' < "$INDEX_HEADERS" | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2; exit}')"
if [ -n "$INDEX_DIGEST" ]; then
    pass "index resolved: Docker-Content-Digest=${INDEX_DIGEST}"
else
    fail "index Docker-Content-Digest header present" "no header on the index response"
    summary
fi
INDEX_HASH="${INDEX_DIGEST#sha256:}"

# A real client picks one platform child after reading the index. Filter to
# a genuine linux/amd64 IMAGE manifest — some multi-arch sources interleave
# attestation manifests in `.manifests[]`, and we want the real image child.
CHILD_DIGEST="$(jq -r '.manifests[]? | select(.platform.architecture=="amd64" and .platform.os=="linux") | .digest' "$INDEX_BODY" 2>/dev/null | head -1)"
if [ -n "$CHILD_DIGEST" ]; then
    pass "resolved linux/amd64 child manifest digest: ${CHILD_DIGEST}"
else
    fail "resolve linux/amd64 child digest from served index" \
        "no .manifests[] entry with platform.architecture=amd64, platform.os=linux"
    summary
fi
CHILD_HASH="${CHILD_DIGEST#sha256:}"

# ---------------------------------------------------------------------
# Step 2: AUTHENTICATED pull of the platform-specific child manifest BY
# DIGEST — the write-authorized hold-read exemption again (the child is
# also still quarantined), and the leg that spawns #51's background blob
# warming.
# ---------------------------------------------------------------------
log ""
log "--- Step 2: AUTHENTICATED GET the child manifest by digest"

CHILD_HEADERS="$(mktemp)"
CHILD_BODY="$(mktemp)"

CHILD_CODE="$(curl -sS -o "$CHILD_BODY" -D "$CHILD_HEADERS" -w '%{http_code}' \
    -H "Authorization: Bearer ${DEV_TOKEN}" \
    -H "Accept: ${OCI_MANIFEST_MEDIA}, ${DOCKER_MANIFEST_MEDIA}" \
    "${BASE_URL}/manifests/${CHILD_DIGEST}" 2>/dev/null || echo 000)"
if [ "$CHILD_CODE" = "200" ]; then
    pass "AUTHENTICATED GET child manifest by digest -> 200 (write-authorized hold-read exemption)"
else
    fail "AUTHENTICATED GET child manifest by digest -> 200" "got HTTP ${CHILD_CODE}"
    summary
fi

CONFIG_DIGEST="$(jq -r '.config.digest // empty' "$CHILD_BODY" 2>/dev/null)"
LAYER_DIGEST="$(jq -r '.layers[0].digest // empty' "$CHILD_BODY" 2>/dev/null)"
if [ -z "$CONFIG_DIGEST" ] || [ -z "$LAYER_DIGEST" ]; then
    fail "resolve child .config.digest and .layers[0].digest" \
        "config='${CONFIG_DIGEST:-<empty>}' layer='${LAYER_DIGEST:-<empty>}'"
    summary
fi
CONFIG_HASH="${CONFIG_DIGEST#sha256:}"
LAYER_HASH="${LAYER_DIGEST#sha256:}"
log "  child config digest = ${CONFIG_DIGEST}"
log "  child layer[0] digest = ${LAYER_DIGEST}"

# ---------------------------------------------------------------------
# Step 3: resolve the repo id + both artifact ids. Synchronous ingest —
# the row exists by the time the GET above returned — but poll briefly
# as defence-in-depth against projection-visibility lag (same caution
# `patch-candidate.sh` takes around `bounded_poll`).
# ---------------------------------------------------------------------
log ""
log "--- Step 3: resolve repository + artifact ids via psql"

REPO_ID="$(psql_one "SELECT id FROM repositories WHERE key = '${REPO_KEY}';")"
if [ -z "$REPO_ID" ]; then
    fail "resolve repository id for ${REPO_KEY}" \
        "no row in repositories — is deploy/compose/example-config/repositories/oci-proxy-quarantine-e2e.yaml mounted and gitops apply succeeding?"
    summary
fi
pass "repository resolved (id=${REPO_ID})"

find_artifact_id() {
    local hash="$1" label="$2" id=""
    bounded_poll "artifact ${label} (sha256:${hash}) ingested" 15 \
        "[ -n \"\$(psql_one \"SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND checksum_sha256 = '${hash}';\")\" ]" \
        1 || true
    id="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND checksum_sha256 = '${hash}';")"
    # defense in depth: a captured id must be UUID-shaped or downstream
    # `[ -n ]`/WHERE-clause guards could be satisfied by garbage — never
    # return anything else, even with the poll's own output routed away.
    if [[ ! "$id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        id=""
    fi
    printf '%s' "$id"
}

INDEX_ID="$(find_artifact_id "$INDEX_HASH" "index")"
CHILD_ID="$(find_artifact_id "$CHILD_HASH" "child manifest")"
if [ -z "$INDEX_ID" ]; then
    fail "resolve index artifact row" "no artifacts row for checksum_sha256='${INDEX_HASH}'"
    summary
fi
if [ -z "$CHILD_ID" ]; then
    fail "resolve child artifact row" "no artifacts row for checksum_sha256='${CHILD_HASH}'"
    summary
fi
pass "index artifact id=${INDEX_ID}, child artifact id=${CHILD_ID}"

# ---------------------------------------------------------------------
# Step 4: content_references — the pull-through edge-write half of the
# composition #46/#50 gate. Target SPECIFIC digests (never a count —
# #51's background blob warming means unrelated rows can appear).
# ---------------------------------------------------------------------
log ""
log "--- Step 4: content_references edges"

member_row="$(psql_one "SELECT count(*) FROM content_references \
    WHERE repository_id = '${REPO_ID}' AND source_artifact_id = '${INDEX_ID}' \
      AND target_content_hash = '${CHILD_HASH}' AND kind = 'oci_index_member';")"
if [ "$member_row" = "1" ]; then
    pass "content_references: index -> child (kind=oci_index_member) edge present"
else
    fail "content_references oci_index_member edge (index -> child)" "count=${member_row:-0}"
fi

config_row="$(psql_one "SELECT count(*) FROM content_references \
    WHERE repository_id = '${REPO_ID}' AND source_artifact_id = '${CHILD_ID}' \
      AND target_content_hash = '${CONFIG_HASH}' AND kind = 'oci_config';")"
if [ "$config_row" = "1" ]; then
    pass "content_references: child -> config blob (kind=oci_config) edge present"
else
    fail "content_references oci_config edge (child -> config)" "count=${config_row:-0}"
fi

layer_row="$(psql_one "SELECT count(*) FROM content_references \
    WHERE repository_id = '${REPO_ID}' AND source_artifact_id = '${CHILD_ID}' \
      AND target_content_hash = '${LAYER_HASH}' AND kind = 'oci_layer';")"
if [ "$layer_row" = "1" ]; then
    pass "content_references: child -> layer blob (kind=oci_layer) edge present"
else
    fail "content_references oci_layer edge (child -> layer[0])" "count=${layer_row:-0}"
fi

# ---------------------------------------------------------------------
# Step 5: sanity — both artifacts actually quarantined (proves the 24h
# policy is in effect at all, before the differential means anything).
# ---------------------------------------------------------------------
log ""
log "--- Step 5: sanity — both artifacts are quarantined"

index_status="$(psql_one "SELECT quarantine_status FROM artifacts WHERE id = '${INDEX_ID}';")"
child_status="$(psql_one "SELECT quarantine_status FROM artifacts WHERE id = '${CHILD_ID}';")"
if [ "$index_status" = "quarantined" ]; then
    pass "index quarantine_status = quarantined"
else
    fail "index quarantine_status = quarantined" "got '${index_status}'"
fi
# released-OR-quarantined: see "WHY releasable-OR-released" above — a fast
# sweep tick can legitimately release the zero-window child before this
# check runs when a worker-requiring scenario shares the stack.
if [ "$child_status" = "quarantined" ] || [ "$child_status" = "released" ]; then
    pass "child quarantine_status = quarantined (or already released by a fast sweep tick)"
else
    fail "child quarantine_status = quarantined (or released)" "got '${child_status}'"
fi

# ---------------------------------------------------------------------
# Step 6: THE assertion — the index/child quarantine_window_start
# differential. This is the one that would have caught the original #46
# breakage; see the header comment for why it must be run against a
# non-zero-duration policy to mean anything.
# ---------------------------------------------------------------------
log ""
log "--- Step 6: quarantine_window_start differential (the #46 Item 2 gate) — index anchored on ADR 0054 age evidence, child on the descendant carve-out"

# The index is not a content_references target, so no carve-out applies and
# its anchor is ADR 0054's age evidence: the earliest observation of its own
# bytes anywhere in this hort. Same predicate the server derives from —
# `MIN(created_at)` over the rows sharing the checksum, no repository scope,
# no `is_deleted` filter — so a build that scoped the evidence per-repository
# (or dropped it and fell back to `now`) fails here.
INDEX_FIRST_SEEN="$(psql_one "SELECT replace(MIN(created_at)::text, ' ', 'T') FROM artifacts WHERE checksum_sha256 = '${INDEX_HASH}';")"
INDEX_OWN_CREATED="$(psql_one "SELECT replace(created_at::text, ' ', 'T') FROM artifacts WHERE id = '${INDEX_ID}';")"
INDEX_OBSERVATIONS="$(psql_one "SELECT count(*) FROM artifacts WHERE checksum_sha256 = '${INDEX_HASH}';")"
log "  index bytes are held by ${INDEX_OBSERVATIONS} artifact row(s) across all repositories"
log "  earliest observation (first_seen) = ${INDEX_FIRST_SEEN}; this row's created_at = ${INDEX_OWN_CREATED}"

index_anchored_on_evidence="$(psql_one "SELECT (quarantine_window_start = \
    (SELECT MIN(created_at) FROM artifacts WHERE checksum_sha256 = '${INDEX_HASH}')) \
    FROM artifacts WHERE id = '${INDEX_ID}';")"
if [ "$index_anchored_on_evidence" = "t" ]; then
    if [ "$INDEX_FIRST_SEEN" = "$INDEX_OWN_CREATED" ]; then
        pass "index: quarantine_window_start == earliest observation of its own bytes — no earlier observation exists, so it reduces to created_at (a full 24h window)"
    else
        pass "index: quarantine_window_start == earliest observation of its own bytes, made in ANOTHER repository (ADR 0054 cross-repository age evidence applied — proxy/oci-mirror.sh pulled this same index earlier in the suite)"
    fi
else
    index_window_start="$(psql_one "SELECT replace(quarantine_window_start::text, ' ', 'T') FROM artifacts WHERE id = '${INDEX_ID}';")"
    fail "index quarantine_window_start == MIN(created_at) over artifacts sharing checksum ${INDEX_HASH}" \
        "got '${index_anchored_on_evidence}' (expected t): window_start=${index_window_start} first_seen=${INDEX_FIRST_SEEN} own created_at=${INDEX_OWN_CREATED}"
fi

# Unchanged by ADR 0054 and deliberately still exact: the carve-out
# contributes `minted_at - 24h`, which is the minimum against any observation
# hort could have made during this run, so the child's anchor is that value
# whether or not its bytes were seen earlier.
child_zero_window="$(psql_one "SELECT (quarantine_window_start = created_at - interval '24 hours') FROM artifacts WHERE id = '${CHILD_ID}';")"
if [ "$child_zero_window" = "t" ]; then
    pass "child: quarantine_window_start == created_at - 24h (zero window — the #46 Item 2 referenced-tree-descendant carve-out fired)"
else
    fail "child quarantine_window_start == created_at - 24h" "got '${child_zero_window}' (expected t)"
fi

# ---------------------------------------------------------------------
# Step 7: release ELIGIBILITY (not release — see the header comment).
# Exact predicate crates/hort-adapters-postgres/src/
# quarantine_release_candidates.rs's select_expired query uses.
# ---------------------------------------------------------------------
log ""
log "--- Step 7: release-eligibility predicate (child eligible now, index not)"

child_status_now="$(psql_one "SELECT quarantine_status FROM artifacts WHERE id = '${CHILD_ID}';")"
child_window_elapsed="$(psql_one "SELECT (quarantine_window_start <= now() - interval '24 hours') FROM artifacts WHERE id = '${CHILD_ID}';")"
# released-OR-eligible: quarantine_status = 'released' is a strictly
# stronger proof the sweep's predicate held (see "WHY releasable-OR-released"
# above) than an unconsumed eligible reading — a fast sweep tick sharing the
# stack can legitimately claim this row before this line runs.
if [ "$child_status_now" = "released" ] || \
   { [ "$child_status_now" = "quarantined" ] && [ "$child_window_elapsed" = "t" ]; }; then
    pass "child satisfies the release-sweep selection predicate NOW (releasable at the next sweep, or already released by a fast tick)"
else
    fail "child satisfies the release-sweep selection predicate" \
        "got status='${child_status_now}' window_elapsed='${child_window_elapsed}' (expected quarantined+elapsed or released)"
fi

# Still strict, and it is also what proves the index did not take the
# descendant carve-out: a carve-out anchor is release-eligible the instant it
# is stamped. Its anchor is the age evidence Step 6 pinned, which in this
# suite is minutes old against a 24h window — so the only way this flips is a
# stack that has held these exact bytes for more than 24h (a long-lived DB
# volume reused across days), which is a stale-fixture condition, not a
# regression.
index_eligible="$(psql_one "SELECT (quarantine_status = 'quarantined' AND quarantine_window_start <= now() - interval '24 hours') FROM artifacts WHERE id = '${INDEX_ID}';")"
if [ "$index_eligible" = "f" ]; then
    pass "index does NOT satisfy the release-sweep selection predicate (still mid-window)"
else
    index_anchor_age="$(psql_one "SELECT (now() - quarantine_window_start)::text FROM artifacts WHERE id = '${INDEX_ID}';")"
    fail "index does NOT satisfy the release-sweep selection predicate" \
        "got '${index_eligible}' (expected f): its age-evidence anchor is already ${index_anchor_age} old, i.e. hort has held these exact bytes for over 24h — a database volume carried over from an earlier run, not a code defect"
fi

summary
