#!/usr/bin/env bash
# requires: egress db
#
# Proxy multi-arch pull-through -> a referenced-tree descendant keeps its
# observation window while every referencing parent is still held. Regression
# gate for the composition of pull-through edge-write x ingest target-check x
# release-eligibility that shipped broken once (hosted-push path only) and had
# to be re-fixed (`58b8548c`, the pull-through path) with no automated E2E
# catching either failure — only prod validation did.
#
# ---------------------------------------------------------------------------
# THE FILE NAME IS HISTORICAL. KEPT ON PURPOSE.
# ---------------------------------------------------------------------------
# "zero-window" named what this scenario asserted before ADR 0007's
# "The carve-out is conditional on inherited trust" amendment: a
# `content_references` target waived its observation window unconditionally,
# so a proxy-pulled index's child manifest was stamped
# `created_at - quarantineDuration` and was release-eligible the instant it
# existed. The waiver is now conditional on at least one referencing parent
# being itself `Released`, and in this repository none ever is inside a smoke
# run, so what this file pins is the OTHER side of that condition — the full
# window a held-parent descendant keeps. The name is left alone because
# `run.sh --list` prints it as the inventory and several sibling fixtures and
# scenarios cross-reference it by name; a rename is a sweep of its own, not a
# side effect of this correction. Read the assertions, not the file name.
#
# ---------------------------------------------------------------------------
# WHY A DIFFERENTIAL ASSERTION, NOT "the child releases on its own
# ScanSucceeded" (the original acceptance criterion this file was built for).
# ---------------------------------------------------------------------------
# It cannot assert that here. `deploy/compose/example-config/policies/
# oci-proxy-quarantine-e2e-quarantine.yaml` records why: the 24h window
# outlasts any smoke run and `enforcement: record` makes a Trivy verdict a
# timer authority rather than a gate, so before the deadline there is no
# release authority for a scan to supply and the hold is purely time-based.
# Chasing `ScanSucceeded` would mean standing up machinery this harness does
# not have.
#
# The substitute — under ONE policy (quarantineDuration: 24h), pulled in ONE
# proxy fetch — compares two artifacts from the same pull:
#
#   | Artifact                         | Expected quarantine_window_start |
#   |-----------------------------------|-----------------------------------|
#   | the INDEX (not a content_references TARGET of anything) | == the earliest observation of its OWN bytes, `MIN(created_at)` over every `artifacts` row sharing its checksum (ADR 0054) |
#   | a CHILD MANIFEST (a referenced descendant — the index's `oci_index_member` target, whose only referencing parent is that still-held index) | == the SAME thing: `MIN(created_at)` over its own checksum. No waiver, because there is no released parent to inherit one from |
#
# The two rows are the differential: they are the two sides of the predicate
# `is this content a target of a parent that is itself Released`, which is
# `false` for both here — once because the index is nobody's target at all,
# once because its child's only parent is held. A build carrying the
# unconditional carve-out answers `created_at - 24h` for the second row and
# fails; a build that lost the ADR 0054 age evidence answers `created_at` for
# the first row and fails. It pins the PROXY-PULLED path specifically (the
# pull-through path the original defect was filed against, not the hosted push
# path `quarantine/oci-image-index.sh` already covers), needs no worker, and —
# per the hollowness trap below — cannot pass on a build that gets either row
# wrong.
#
# ---------------------------------------------------------------------------
# WHAT THIS SCENARIO DOES NOT COVER, AND WHY IT CANNOT.
# ---------------------------------------------------------------------------
# The condition's OTHER side — a descendant minted while a referencing parent
# is ALREADY `Released`, which must then take the waiver — is not asserted
# anywhere below. It is not producible through an index, and the reason is
# worth stating because it is a property of the ingest path, not a gap in
# this file.
#
# A proxy pull-through of an index completes the whole tree up front. The
# index's own ingest enqueues one `oci-index-child-ingest` row per declared
# child (ungated, `crates/hort-http-oci/src/manifests.rs`), and the handler
# behind those rows ingests the child AND warms its config + layer blobs in
# the same run, explicitly not conditional on `prefetch_policy.enabled`
# (`crates/hort-app/src/task_handlers/oci_index_child_ingest.rs`, step 8). So
# every descendant of the index is minted within seconds of the index itself,
# while the index and each child manifest are still held — long before any
# window in the tree could close. The one instrument that CAN release a
# parent inside a smoke run (the curator waive,
# `POST /api/v1/admin/curation/quarantine/:id/waive`) therefore has no
# un-minted descendant left to act on, whatever order it is used in.
#
# A worker is what drains those rows, and this scenario's `requires:` line
# does not ask for one — so in a run where no selected scenario asks for a
# worker, the children stay un-minted and waiving the index first WOULD
# produce the released-parent case. That is not a premise anything here can
# assert on: `run.sh` decides `--profile worker` ONCE from the union of every
# selected scenario's `requires:`, the full CI gate selects worker-requiring
# scenarios and so runs with the profile up, and a scenario cannot observe
# which way that went. A second side that quietly becomes a cache hit in the
# gate run is the hollowness trap below in a different costume.
#
# The remaining route is the Referrers flow, where `oci_subject` is
# deliberately NOT gated on the subject being present
# (`manifest_ingest_claims`, crates/hort-http-oci/src/manifests_write.rs):
# a referrer pushed for a subject this repository has not got writes a tree
# edge onto an absent target, so releasing that referrer and THEN ingesting
# the subject does produce a descendant with a released parent. That is a
# hosted-push referrer fixture rather than anything this proxy-multi-arch
# scenario drives, and no scenario in this harness pushes a hand-built
# referrer today. It is the shape to build the positive case from; asserting
# it here would mean asserting it on content this scenario never mints.
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
# Both assertions below are therefore stated as the invariant itself: anchor
# == `MIN(created_at)` over that row's own checksum. For genuinely cold
# content it reduces to `created_at`, so nothing is weakened; here the index
# matches the `proxy/oci-mirror.sh` row, and the scenario LOGS which of the
# two cases it observed.
#
# The child takes the SAME form for a different reason, and that is the point
# of the pairing. It IS a `content_references` target, so the pre-amendment
# code answered `created_at - 24h` for it. Its only referencing parent is the
# index, which is held for a fresh 24h and cannot release inside a smoke run,
# so the waiver's condition — at least one parent itself `Released` — is
# unmet and the child falls through to exactly the age evidence the index
# gets. `proxy/oci-mirror.sh` pulls the amd64 child too (a bare `skopeo copy`
# resolves and fetches the host platform's manifest), so the child is
# typically WARM in the same way the index is, and the invariant form covers
# both cases without a coldness premise.
#
# That neither row took the waiver is proven twice over: by the anchors here,
# and by Step 7 — a waived anchor is release-eligible the instant it is
# stamped, and Step 7 asserts NEITHER row is.
#
# ---------------------------------------------------------------------------
# THE HOLLOWNESS TRAP — DO NOT "SIMPLIFY" THIS ONTO oci-mirror-e2e.
# ---------------------------------------------------------------------------
# oci-mirror-e2e's ScanPolicy is quarantineDuration: 0s. Reaching for that
# existing permissive repo is the obvious shortcut, and it SILENTLY GUTS this
# scenario — in both directions, which is why the trap survives the
# amendment rather than being a note about the old assertion:
#
#  - the ANCHOR half stops discriminating. With duration=0, `created_at` and
#    `created_at - duration` are the literal same instant, so "anchor ==
#    MIN(created_at)" holds on a build carrying the unconditional carve-out
#    exactly as it does on a correct one. The assertion would pass on code
#    that waives a window it must not waive.
#  - the ELIGIBILITY half stops being satisfiable at all. `quarantine_window_
#    start <= now() - 0` is true of any past anchor, so "the child is NOT
#    release-eligible" would fail on a correct build. A zero-duration policy
#    has no observation window to have an opinion about.
#
# This is why a DEDICATED, NON-ZERO-DURATION repo+policy
# (oci-proxy-quarantine-e2e, quarantineDuration: 24h) exists rather than
# reusing oci-mirror-e2e or oci-quarantine-e2e (that one's push-based, not
# proxy pull-through). The same failure mode the >5 MiB blob-size floor in
# the large-blob proxy fixture guards against.
#
# ---------------------------------------------------------------------------
# WHY EVERY STATUS ASSERTION BELOW IS STRICT — nothing here can release.
# ---------------------------------------------------------------------------
# Both rows carry a full, fresh 24h window: the index because it is nobody's
# `content_references` target, the child because its only parent is that
# still-held index. Neither window can elapse inside a smoke run, and
# `enforcement: record` makes a Trivy verdict a timer authority rather than a
# gate, so no scan outcome can release either row early and none can reject
# one. So `quarantined` is the only status either row may carry, and
# `quarantine_status = 'released'` is not tolerated anywhere below.
#
# That strictness is new and it is the POINT: while the carve-out was
# unconditional the child was release-eligible from the instant it was
# minted, and `scripts/native-tests/run.sh` computes `--profile worker` ONCE
# over the union of every selected scenario's `requires:` — so in a
# combined/full run the `hort-sweep-ticker` (`profile: worker`) could
# legitimately claim and release that child mid-scenario, and every child
# status assertion had to accept `released` as well. Under the condition
# there is nothing for the sweep to claim, so a `released` child is now a
# real finding rather than a fast tick: it means something waived a window
# with no released parent to inherit from.
#
# The eligibility assertions evaluate the exact predicate
# `crates/hort-adapters-postgres/src/quarantine_release_candidates.rs`'s
# `select_expired` query uses — `quarantine_status = 'quarantined' AND
# quarantine_window_start <= now() - duration` — directly via `psql_one`. It
# needs no sweep task to actually run to be true or false right now, and it
# is exactly what "would become releasable at the next sweep" means
# operationally: whether the row satisfies the sweep's own selection query
# whenever a worker next polls it.
#
# ---------------------------------------------------------------------------
# WHY alpine:3.19, WHY digests not counts.
# ---------------------------------------------------------------------------
# alpine:3.19 is a genuine multi-arch OCI image index and is already the
# upstream fixture `proxy/oci-mirror.sh` pulls — no new external dependency.
# Rows this scenario never asked for appear in this repository and are
# expected: the index's own ingest enqueues one `oci-index-child-ingest` row
# per declared child, and a worker that picks those up ingests EVERY platform
# child and warms each one's config and layer blobs. (Which rows exist
# therefore depends on whether the shared stack happens to have the worker
# profile up — see the `--profile worker` note above.) So every assertion
# below targets a SPECIFIC digest, parsed out of the actual served
# index/manifest JSON, and never a row count.

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

log "==> Proxy multi-arch pull -> a held-parent descendant keeps its observation window"
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
    # Logged, not asserted: the value is the window LEFT, measured from the
    # derived anchor (ADR 0054 — the minimum over the age sources), so an
    # inherited anchor legitimately shortens it. Expect at most 86400
    # (the repo's 24h quarantineDuration) and never a flat 3600, which was the
    # deadline-unknown fallback this response used to fall back on because
    # nothing on the ingest path hydrated the transient deadline.
    log "  INFO: Retry-After = $(grep -i '^retry-after:' "$ANON_HEADERS" | tr -d '\r' | awk '{print $2}') (expected <= 86400, never 3600)"
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
# also still quarantined).
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
# composition under test. The edges are the INPUT to the carve-out's
# condition: without the index -> child edge the child is not a
# referenced-tree descendant at all, and Step 6 would then be asserting the
# default window of an unrelated artifact rather than the condition's
# held-parent side. Target SPECIFIC digests, never a count — the eager
# index-child ingest legitimately adds rows this scenario never asked for.
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
# Strict, and deliberately: see "WHY EVERY STATUS ASSERTION BELOW IS STRICT"
# above. The child's parent is held for a fresh 24h, so under the carve-out's
# inherited-trust condition the child carries a full window too and no sweep
# tick has anything to claim. A `released` reading here is the signature of a
# window waived with no released parent to inherit it from.
if [ "$child_status" = "quarantined" ]; then
    pass "child quarantine_status = quarantined"
else
    fail "child quarantine_status = quarantined" \
        "got '${child_status}'. 'released' means something waived this descendant's window while its only referencing parent (the index) was still held — the unconditional carve-out ADR 0007's inherited-trust amendment retired. 'scan_indeterminate' is a different axis: a scan that abstained and fell to the fail-closed hold, which this repository's enforcement:record policy is not supposed to reach."
fi

# ---------------------------------------------------------------------
# Step 6: THE assertion — the index/child quarantine_window_start
# differential. See the header comment for why it must be run against a
# non-zero-duration policy to mean anything.
# ---------------------------------------------------------------------
log ""
log "--- Step 6: quarantine_window_start — both rows anchored on ADR 0054 age evidence, neither on the descendant carve-out"

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

# The child IS a content_references target — Step 4 asserted the index ->
# child `oci_index_member` edge — so this is the carve-out's condition being
# evaluated, not a row the condition never reached. Two premises make that
# precise, and both are asserted rather than assumed:
#
#  - the edge existed when the child was MINTED, not merely now. It commits
#    in the index's own ingest transition, so `child.created_at >
#    index.created_at` is what makes it reachable by the child's own
#    carve-out probe. (If it were the other way round the child would not be
#    a descendant at all, its anchor would be the same value asserted below,
#    and the assertion would pass while exercising nothing — which is why
#    this is a separate check and not a comment.)
#  - the parent was HELD at that moment. Step 5 asserted the index is still
#    `quarantined`, and with a fresh 24h window it cannot have been released
#    and re-held in between — release is one-way and needs the timer — so
#    "held now" is also "held when this child was minted".
child_minted_after_index="$(psql_one "SELECT (c.created_at > p.created_at) \
    FROM artifacts c, artifacts p WHERE c.id = '${CHILD_ID}' AND p.id = '${INDEX_ID}';")"
if [ "$child_minted_after_index" = "t" ]; then
    pass "child was minted AFTER the index, so the index -> child edge already existed at the child's own mint (the carve-out's condition was genuinely evaluated for it)"
else
    fail "child was minted after the index" \
        "got '${child_minted_after_index:-<null>}' (expected t) — the child row predates the index row in this repository, so there was no oci_index_member edge for the carve-out to find and this row is not exercising the condition at all. Something ingested the child manifest into ${REPO_KEY} before the index that references it"
fi

# With no released parent to inherit trust from, the waiver does not apply
# and the child falls through to exactly the age evidence the index got —
# asserted in the same invariant form, for the same reason: `oci-mirror.sh`
# pulls this platform's child manifest too, so these bytes are typically
# already observed and `created_at` is the answer only when they are not.
CHILD_FIRST_SEEN="$(psql_one "SELECT replace(MIN(created_at)::text, ' ', 'T') FROM artifacts WHERE checksum_sha256 = '${CHILD_HASH}';")"
CHILD_OWN_CREATED="$(psql_one "SELECT replace(created_at::text, ' ', 'T') FROM artifacts WHERE id = '${CHILD_ID}';")"
CHILD_OBSERVATIONS="$(psql_one "SELECT count(*) FROM artifacts WHERE checksum_sha256 = '${CHILD_HASH}';")"
log "  child bytes are held by ${CHILD_OBSERVATIONS} artifact row(s) across all repositories"
log "  earliest observation (first_seen) = ${CHILD_FIRST_SEEN}; this row's created_at = ${CHILD_OWN_CREATED}"

child_anchored_on_evidence="$(psql_one "SELECT (quarantine_window_start = \
    (SELECT MIN(created_at) FROM artifacts WHERE checksum_sha256 = '${CHILD_HASH}')) \
    FROM artifacts WHERE id = '${CHILD_ID}';")"
if [ "$child_anchored_on_evidence" = "t" ]; then
    pass "child: quarantine_window_start == earliest observation of its own bytes — a referenced-tree descendant whose only parent is held inherits no trust, so it keeps its full observation window (ADR 0007, the carve-out is conditional on inherited trust)"
else
    child_window_start="$(psql_one "SELECT replace(quarantine_window_start::text, ' ', 'T') FROM artifacts WHERE id = '${CHILD_ID}';")"
    child_took_waiver="$(psql_one "SELECT (quarantine_window_start = created_at - interval '24 hours') FROM artifacts WHERE id = '${CHILD_ID}';")"
    if [ "$child_took_waiver" = "t" ]; then
        fail "child quarantine_window_start == MIN(created_at) over artifacts sharing checksum ${CHILD_HASH}" \
            "the child is anchored at created_at - 24h, i.e. it WAIVED its observation window while its only referencing parent was still quarantined. That is the unconditional referenced-tree-descendant carve-out ADR 0007's inherited-trust amendment retired: window_start=${child_window_start} own created_at=${CHILD_OWN_CREATED}"
    else
        fail "child quarantine_window_start == MIN(created_at) over artifacts sharing checksum ${CHILD_HASH}" \
            "got '${child_anchored_on_evidence}' (expected t), and it is not the retired waiver's value either: window_start=${child_window_start} first_seen=${CHILD_FIRST_SEEN} own created_at=${CHILD_OWN_CREATED}"
    fi
fi

# ---------------------------------------------------------------------
# Step 7: release ELIGIBILITY (not release — see the header comment).
# Exact predicate crates/hort-adapters-postgres/src/
# quarantine_release_candidates.rs's select_expired query uses.
# ---------------------------------------------------------------------
log ""
log "--- Step 7: release-eligibility predicate (NEITHER row eligible — both hold a full window)"

# Both legs run the same query, which is what makes "the child is treated
# like any other fresh artifact" an assertion rather than a claim. A waived
# anchor is release-eligible the instant it is stamped, so this is the
# operational form of Step 6: it reads the sweep's own selection predicate
# instead of the anchor column, and it fails on a build that waives either
# row's window.
#
# The only way either leg flips without a code defect is a stack that has
# held these exact bytes for more than 24h — a database volume carried over
# across days, which `run.sh`'s own `compose down -v` prevents but a
# long-lived `--hort=external` instance does not. The failure messages name
# that, because it is a stale-fixture condition and reads identically to the
# regression otherwise.
assert_not_release_eligible() {
    local id="$1" label="$2" eligible anchor_age status
    eligible="$(psql_one "SELECT (quarantine_status = 'quarantined' AND quarantine_window_start <= now() - interval '24 hours') FROM artifacts WHERE id = '${id}';")"
    if [ "$eligible" = "f" ]; then
        pass "${label} does NOT satisfy the release-sweep selection predicate (still mid-window)"
    else
        anchor_age="$(psql_one "SELECT (now() - quarantine_window_start)::text FROM artifacts WHERE id = '${id}';")"
        status="$(psql_one "SELECT quarantine_status FROM artifacts WHERE id = '${id}';")"
        fail "${label} does NOT satisfy the release-sweep selection predicate" \
            "got '${eligible}' (expected f): status='${status}', and its anchor is already ${anchor_age} old against a 24h window. Either a window was waived at mint (see Step 6's verdict for which value was stamped) or hort has genuinely held these exact bytes for over 24h — a database volume carried over from an earlier run, not a code defect"
    fi
}
assert_not_release_eligible "$CHILD_ID" "child (a held-parent referenced-tree descendant)"
assert_not_release_eligible "$INDEX_ID" "index (nobody's content_references target)"

summary
