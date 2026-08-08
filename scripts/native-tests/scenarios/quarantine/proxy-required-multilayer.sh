#!/usr/bin/env bash
# requires: egress worker db compose
# Proxy pull-through x provenance_mode:Required, multi-layer image — #115
# Item 4 regression E2E for the defect Item 3 fixed.
#
# ---------------------------------------------------------------------------
# THE DEFECT (issue #115, defect (b)) AND WHAT THIS PINS.
# ---------------------------------------------------------------------------
# Before Item 3, `Artifact::complete_provenance`'s NoAttestation x Required
# arm only HELD (stayed Quarantined, no terminal decision) when the
# artifact's own observation window was still open (`window_open`). A
# referenced-tree descendant (#46 Item 2) gets a ZERO-length window by
# design (anchor = ingested_at - duration), so for a proxy-pulled tree every
# constituent — the platform-specific child manifest, its config blob, its
# layer blobs — had `window_open == false` from the instant it was ingested,
# and the OLD code TERMINALLY REJECTED it as `Unsigned` before the parent
# index (the actual signable subject) ever got a chance to be signed. Item 3
# widened the hold condition to `window_open || is_referenced_descendant`,
# so a descendant now HOLDS unconditionally — independent of whether its
# subject is ever signed — and clears later via cascade
# (`cascade_provenance_clearance`, ADR 0039 §11) once the subject verifies.
#
# This scenario drives that composition for real: pull a genuine multi-layer
# OCI image INDEX through a `provenance_mode: Required` PROXY repo, sign the
# INDEX (the real subject), and assert:
#   (a) the pull EVENTUALLY SUCCEEDS (subject verifies, cascade clears the
#       child manifest + its config/layer blobs, the quarantine window
#       elapses, the whole tree becomes anonymously pullable);
#   (b) NONE of the constituents (child manifest, config blob, every layer
#       blob) EVER emits `ProvenanceRejected` — the exact defect signature
#       Item 3 fixed (pre-fix, each would have terminally rejected as
#       Unsigned within moments of ingest, long before this scenario's
#       later assertions even run).
#
# ---------------------------------------------------------------------------
# MODEL SCENARIOS COMBINED, NOT REINVENTED.
# ---------------------------------------------------------------------------
# - Proxy pull-through mechanics (cold GET by tag -> resolve a linux/amd64
#   child by digest -> GET the child -> content_references edge assertions
#   -> quarantine_window_start differential) are
#   scenarios/quarantine/proxy-multiarch-zero-window.sh's pattern.
# - Keyed cosign signing mechanics (env-var contract, tool-availability
#   self-skip, the committed test keypair, dual native-token/legacy auth,
#   `cosign sign --key --registry-referrers-mode=oci-1-1`, the
#   ProvenanceVerified poll) are
#   scenarios/quarantine/provenance-push-then-sign.sh's pattern.
# Unlike that script, this repo is PUBLIC (isPublic:true, like
# oci-proxy-quarantine-e2e) — the private-repo visibility x hold interaction
# (ADR 0045) is already covered there; this scenario stays focused on the
# proxy x Required x descendant-hold composition. The FIRST-touch cold index
# GET (Step 0) is the fetch that performs the ingest, and — mirroring
# proxy-multiarch-zero-window.sh's own Step 0 — the designed proxy read path
# never hands that fetch's caller the freshly-ingested, still-quarantined
# manifest even though it is the one that populated it: an anonymous caller
# gets 503 + Retry-After + an UNAVAILABLE body, not the manifest. Every
# subsequent manifest READ (index re-GET, child GET) authenticates with the
# credential already fetched below (PUSH_USER/PUSH_SECRET) and relies on the
# write-authorized hold-read exemption (ADR 0039 §10) to see the held
# content — the same exemption the cosign sign step's own subject-resolution
# GET needs, so signing needs no separate credential dance.
#
# ---------------------------------------------------------------------------
# WHY A NEW REPO+POLICY+SA, NOT A REUSE.
# ---------------------------------------------------------------------------
# ScanPolicy scope is 1:1 per-repository (see
# oci-provenance-proxy-e2e-required.yaml's header): oci-provenance-e2e is
# hosted-push-only (no upstream mapping — cannot proxy-pull), and
# oci-proxy-quarantine-e2e's policy is provenanceMode:off and load-bearing
# for the sibling zero-window scenario. So this item adds ONE new repository
# + upstream mapping + policy + a per-repo service account + its
# PermissionGrants (write, read) + a per-repo dev-user write grant — the same
# fixture multiplication provenance-push-then-sign.sh's own repo needed,
# mirrored rather than invented (see each new file's own header comment).
#
# ---------------------------------------------------------------------------
# WHY redis:7-alpine, WHY LENGTH ASSERTED AT RUNTIME NOT HARDCODED.
# ---------------------------------------------------------------------------
# `redis:7-alpine` is a genuine Docker Hub multi-arch image INDEX with
# multiple layers per platform child. The layer COUNT is never assumed —
# `.layers | length` is asserted `>= 2` against the manifest hort actually
# served, so a future upstream retag that collapses to a single layer fails
# loudly instead of silently testing nothing (same discipline as the
# zero-window scenario's digest-not-count assertions).
#
# ---------------------------------------------------------------------------
# WHY THIS MAY SELF-SKIP — see provenance-push-then-sign.sh's identical note.
# ---------------------------------------------------------------------------
# Same three preconditions (cosign+buildah in the client image, a keyed
# signing keypair, a required+cosign-key repo in the mounted gitops config) —
# this item's gitops config supplies the third; the first two are a CI
# provisioner concern this item's directive explicitly does not touch.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

# -----------------------------------------------------------------------------
# Env contract (CI provisioner overrides; sensible defaults otherwise)
# -----------------------------------------------------------------------------
REPO_KEY="${PROVENANCE_PROXY_REPO_KEY:-oci-provenance-proxy-e2e}"
COSIGN_KEY="${COSIGN_KEY:-${FIXTURES:-}/cosign/cosign.key}"
export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"
IMAGE="${IMAGE:-redis:7-alpine}"
RESOLVER_REFRESH_GUESS="${RESOLVER_REFRESH_GUESS:-8}"
WINDOW_WAIT_SECS="${PROVENANCE_WINDOW_WAIT_SECS:-300}"

REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

OCI_INDEX_MEDIA="application/vnd.oci.image.index.v1+json"
DOCKER_LIST_MEDIA="application/vnd.docker.distribution.manifest.list.v2+json"
OCI_MANIFEST_MEDIA="application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST_MEDIA="application/vnd.docker.distribution.manifest.v2+json"

command -v jq >/dev/null 2>&1 || skip "jq not found"
command -v curl >/dev/null 2>&1 || skip "curl not found"
command -v skopeo >/dev/null 2>&1 || skip "skopeo not found in client image"
command -v cosign >/dev/null 2>&1 || \
    skip "cosign not in client image — provision cosign + a keyed key + this item's required/cosign-key repo, then re-run (see header)"
[ -n "$COSIGN_KEY" ] || \
    skip "COSIGN_KEY unset — no keyed cosign private key to sign with (its public half must be the worker's registered cosign-key)"
[ -f "$COSIGN_KEY" ] || \
    skip "keyed cosign private key '$COSIGN_KEY' not found (expected the committed fixture at \$FIXTURES/cosign/cosign.key, or a CI-provided COSIGN_KEY)"

IMAGE_REPO="${IMAGE%%:*}"
IMAGE_TAG="${IMAGE##*:}"
case "$IMAGE_REPO" in
    */*) IMAGE_PATH="${IMAGE_REPO}" ;;
    *)   IMAGE_PATH="library/${IMAGE_REPO}" ;;
esac
BASE_URL="${HORT_URL}/v2/${REPO_KEY}/dockerhub/${IMAGE_PATH}"
PULLED_ARCHIVE="/tmp/prov-proxy-pulled-$$.tar"
trap 'rm -f "$PULLED_ARCHIVE" "${ANON_HEADERS:-}" "${ANON_BODY:-}" "${INDEX_HEADERS:-}" "${INDEX_BODY:-}" "${CHILD_HEADERS:-}" "${CHILD_BODY:-}"' EXIT

log "==> Proxy pull-through x provenance_mode:Required, multi-layer image (issue #115 Item 4)"
log "Registry : ${HORT_URL}"
log "Repo key : ${REPO_KEY} (expected: provenanceMode=required, provenanceBackends=[cosign-key])"
log "Image    : ${IMAGE} (${IMAGE_PATH})"

# -----------------------------------------------------------------------------
# Credential mode for the authenticated manifest reads (Steps 1-2) and the
# SIGN step (mirrors provenance-push-then-sign.sh's dual native-token/legacy
# auth) — the repo is public, so only the write-authorized hold-read
# exemption needs a credential at all; the cold-ingest GET (Step 0) stays
# anonymous.
# -----------------------------------------------------------------------------
NATIVE_TOKENS=0
case " ${HORT_COMPOSE_OVERLAYS:-} " in
    *" native-tokens "*) NATIVE_TOKENS=1 ;;
esac

if [ "$NATIVE_TOKENS" = "1" ]; then
    log "[auth] native-token mode: admin-minting an hort_svc_* token for service account provenance-proxy-ci"
    ADMIN_TOKEN="$(fetch_token admin admin)"
    [ -n "$ADMIN_TOKEN" ] || { fail "fetch admin token" "empty response from Keycloak"; summary; }
    SA_UID="$(psql_one "SELECT id FROM users WHERE username='sa:provenance-proxy-ci';")"
    [ -n "$SA_UID" ] || { fail "resolve provenance-proxy-ci backing user" \
        "no users row 'sa:provenance-proxy-ci' — gitops service-accounts/provenance-proxy-ci.yaml not applied?"; summary; }
    SVC_TOKEN="$(curl -sS -X POST \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
        -d "{\"name\":\"provenance-proxy-e2e-$(date +%s)\",\"declared_permissions\":[\"read\",\"write\"],\"expires_in_days\":1}" \
        "${HORT_URL}/api/v1/admin/users/${SA_UID}/tokens" 2>/dev/null | jq -r '.token // empty')"
    [ -n "$SVC_TOKEN" ] || { fail "admin-mint provenance-proxy-ci svc token" \
        "POST /api/v1/admin/users/${SA_UID}/tokens returned no token"; summary; }
    PUSH_USER="provenance-proxy-ci"; PUSH_SECRET="$SVC_TOKEN"
    log "[auth] svc token minted for the sign step"
else
    DEV_TOKEN="$(fetch_token dev-user dev)"
    [ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"
    [ -n "$DEV_TOKEN" ] || summary
    PUSH_USER="dev-user"; PUSH_SECRET="$DEV_TOKEN"
    log "[auth] legacy mode: fetched DEV_TOKEN from Keycloak (dev-user write-authorized for ${REPO_KEY})"
fi

# ---------------------------------------------------------------------
# Preflight: the resolver cache picks up gitops-applied upstream mappings
# on its own refresh cadence (mirrors proxy-multiarch-zero-window.sh).
# ---------------------------------------------------------------------
log ""
log "--- Preflight: waiting up to ${RESOLVER_REFRESH_GUESS}s for the resolver cache"
sleep "${RESOLVER_REFRESH_GUESS}"

# ---------------------------------------------------------------------
# Step 0: ANONYMOUS cold-pull of the INDEX by tag. This is the triggering
# fetch — it performs the cold ingest — and the designed proxy read path
# never hands an unprivileged caller the freshly-ingested, still-quarantined
# manifest: the response is 503 with a Retry-After header and an
# UNAVAILABLE error body, not the manifest itself (mirrors
# proxy-multiarch-zero-window.sh's Step 0 — the regression pin for the hold).
# ---------------------------------------------------------------------
log ""
log "--- Step 0: ANONYMOUS GET the index by tag (cold ingest; must hold, not serve)"

ANON_HEADERS="$(mktemp)"
ANON_BODY="$(mktemp)"

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
# Step 1: AUTHENTICATED re-GET of the INDEX by tag — the write-authorized
# hold-read exemption (ADR 0039 §10) serves the already-quarantined index to
# the credential fetched above (PUSH_USER/PUSH_SECRET).
# ---------------------------------------------------------------------
log ""
log "--- Step 1: AUTHENTICATED GET the index by tag (write-authorized hold-read)"

INDEX_HEADERS="$(mktemp)"
INDEX_BODY="$(mktemp)"

INDEX_CODE="$(curl -sS -o "$INDEX_BODY" -D "$INDEX_HEADERS" -w '%{http_code}' \
    -H "Authorization: Bearer ${PUSH_SECRET}" \
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
# Step 2: AUTHENTICATED pull of the child manifest BY DIGEST — the
# write-authorized hold-read exemption again (the child is also still
# quarantined), and the leg that spawns #51's background config/layer blob
# warming.
# ---------------------------------------------------------------------
log ""
log "--- Step 2: AUTHENTICATED GET the child manifest by digest"

CHILD_HEADERS="$(mktemp)"
CHILD_BODY="$(mktemp)"

CHILD_CODE="$(curl -sS -o "$CHILD_BODY" -D "$CHILD_HEADERS" -w '%{http_code}' \
    -H "Authorization: Bearer ${PUSH_SECRET}" \
    -H "Accept: ${OCI_MANIFEST_MEDIA}, ${DOCKER_MANIFEST_MEDIA}" \
    "${BASE_URL}/manifests/${CHILD_DIGEST}" 2>/dev/null || echo 000)"
if [ "$CHILD_CODE" = "200" ]; then
    pass "AUTHENTICATED GET child manifest by digest -> 200 (write-authorized hold-read exemption)"
else
    fail "AUTHENTICATED GET child manifest by digest -> 200" "got HTTP ${CHILD_CODE}"
    summary
fi

CONFIG_DIGEST="$(jq -r '.config.digest // empty' "$CHILD_BODY" 2>/dev/null)"
LAYER_COUNT="$(jq -r '.layers | length' "$CHILD_BODY" 2>/dev/null || echo 0)"
if [ -n "$CONFIG_DIGEST" ] && [ "$LAYER_COUNT" -ge 2 ] 2>/dev/null; then
    pass "child manifest carries a config digest and ${LAYER_COUNT} layers (>= 2, verified at runtime — the item's multi-layer requirement)"
else
    fail "resolve child .config.digest and >= 2 .layers[]" \
        "config='${CONFIG_DIGEST:-<empty>}' layers=${LAYER_COUNT:-0} (expected >= 2 — try a different IMAGE if the upstream tag changed shape)"
    summary
fi
CONFIG_HASH="${CONFIG_DIGEST#sha256:}"
mapfile -t LAYER_DIGESTS < <(jq -r '.layers[].digest' "$CHILD_BODY" 2>/dev/null)
LAYER_HASHES=()
for d in "${LAYER_DIGESTS[@]}"; do LAYER_HASHES+=("${d#sha256:}"); done
log "  child config digest = ${CONFIG_DIGEST}"
log "  child layer digests = ${LAYER_DIGESTS[*]}"

# ---------------------------------------------------------------------
# Step 3: SIGN the index (the real subject) — cosign sign --key
# --registry-referrers-mode=oci-1-1 against the SAME repo namespace the
# image was proxy-pulled into (confirmed: cosign-key verification resolves
# referrers repo-scoped-first, landing an upstream-fetched referrer back
# into the same local index — a directly-pushed referrer is found the same
# way). Signing early gives the worker's cascade the most wall-clock before
# this scenario's later assertions poll for it.
# ---------------------------------------------------------------------
log ""
log "--- Step 3: cosign sign --key ... --registry-referrers-mode=oci-1-1 ${REPO_KEY}/dockerhub/${IMAGE_PATH}@${INDEX_DIGEST}"
export COSIGN_DOCKER_MEDIA_TYPES=1
export COSIGN_EXPERIMENTAL=1
SIGN_OUT=""
SIGN_RC=0
SIGN_OUT="$(cosign sign --yes \
    --key "$COSIGN_KEY" \
    --registry-referrers-mode=oci-1-1 \
    --registry-username="$PUSH_USER" \
    --registry-password="$PUSH_SECRET" \
    --allow-insecure-registry \
    --allow-http-registry \
    "${REGISTRY_HOST}/${REPO_KEY}/dockerhub/${IMAGE_PATH}@${INDEX_DIGEST}" 2>&1)" || SIGN_RC=$?
if [ "$SIGN_RC" -eq 0 ]; then
    pass "cosign sign (keyed, oci referrers) succeeded against the proxy-pulled subject"
else
    log "[cosign output]"; printf '%s\n' "$SIGN_OUT" | sed 's/^/    /'
    if printf '%s' "$SIGN_OUT" | grep -Eqi 'GET .*/manifests/.*503|503 .*manifests'; then
        fail "cosign sign hold-read exemption on a proxy-pulled subject" \
             "cosign got a 503 on a manifest GET during signing -> the write-authorized manifest hold-read exemption (ADR 0039 §10) is not serving the held, proxy-pulled subject to the signer"
    else
        fail "cosign sign (keyed, oci referrers) against a proxy-pulled subject" \
             "cosign exited ${SIGN_RC}; see output above"
    fi
    summary
fi

# ---------------------------------------------------------------------
# Step 4: force constituent ingest — explicit GET of the config blob and
# every layer blob through the proxy, run AFTER the sign (Step 3), never
# before it. Two invariants converge on this ordering:
#   (a) it removes the race against best-effort background blob warming
#       (prefetch.rs, fired off the child-manifest GET, with no retry and no
#       ordering guarantee against a poll that starts immediately after) — a
#       direct blob GET performs the SAME synchronous cold-pull ingest as
#       Step 0's index GET regardless of whether the response is 200 or a
#       designed hold-503, so by the time this loop returns every
#       constituent row already exists;
#   (b) under a required provenance policy, the observation window's end IS
#       the signing deadline — a subject still unsigned when the window
#       closes terminally rejects, so anything placed between ingest and
#       sign eats into that window. This scenario's window is deliberately
#       short to keep the release-wait cheap, so any step with no
#       dependency on the sign belongs after it, never between ingest and
#       sign.
# Statuses are deliberately NOT asserted beyond "curl completed" — this is a
# forcing step, not an assertion; the 60s polls in Step 6/8 stay as a
# backstop.
# ---------------------------------------------------------------------
log ""
log "--- Step 4: force constituent ingest (config blob + every layer blob)"

curl -sS -o /dev/null \
    -H "Authorization: Bearer ${PUSH_SECRET}" \
    "${BASE_URL}/blobs/sha256:${CONFIG_HASH}" 2>/dev/null || true
for h in "${LAYER_HASHES[@]}"; do
    curl -sS -o /dev/null \
        -H "Authorization: Bearer ${PUSH_SECRET}" \
        "${BASE_URL}/blobs/sha256:${h}" 2>/dev/null || true
done
log "  forcing GETs issued for config blob + ${#LAYER_HASHES[@]} layer blob(s)"

# ---------------------------------------------------------------------
# Step 5: resolve repository + artifact ids via psql (defence-in-depth poll,
# mirrors proxy-multiarch-zero-window.sh's find_artifact_id).
# ---------------------------------------------------------------------
log ""
log "--- Step 5: resolve repository + artifact ids via psql"

REPO_ID="$(psql_one "SELECT id FROM repositories WHERE key = '${REPO_KEY}';")"
if [ -z "$REPO_ID" ]; then
    fail "resolve repository id for ${REPO_KEY}" \
        "no row in repositories — is deploy/compose/example-config/repositories/oci-provenance-proxy-e2e.yaml mounted and gitops apply succeeding?"
    summary
fi
pass "repository resolved (id=${REPO_ID})"

find_artifact_id() {
    local hash="$1" label="$2" id=""
    bounded_poll "artifact ${label} (sha256:${hash}) ingested" 60 \
        "[ -n \"\$(psql_one \"SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND checksum_sha256 = '${hash}';\")\" ]" \
        2 || true
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
CONFIG_ID="$(find_artifact_id "$CONFIG_HASH" "config blob")"
[ -n "$INDEX_ID" ] || { fail "resolve index artifact row" "no artifacts row for checksum_sha256='${INDEX_HASH}'"; summary; }
[ -n "$CHILD_ID" ] || { fail "resolve child artifact row" "no artifacts row for checksum_sha256='${CHILD_HASH}'"; summary; }
[ -n "$CONFIG_ID" ] || { fail "resolve config artifact row (background blob warming, #51)" "no artifacts row for checksum_sha256='${CONFIG_HASH}'"; summary; }
pass "index artifact id=${INDEX_ID}, child artifact id=${CHILD_ID}, config artifact id=${CONFIG_ID}"

LAYER_IDS=()
for h in "${LAYER_HASHES[@]}"; do
    lid="$(find_artifact_id "$h" "layer blob")"
    [ -n "$lid" ] || { fail "resolve layer artifact row (background blob warming, #51)" "no artifacts row for checksum_sha256='${h}'"; summary; }
    LAYER_IDS+=("$lid")
done
pass "all ${#LAYER_IDS[@]} layer artifact rows resolved"

# ---------------------------------------------------------------------
# Step 6: content_references edges — the pull-through edge-write half of the
# composition this scenario exercises (targets specific digests, never a
# count — #51 background warming means unrelated rows can appear).
# ---------------------------------------------------------------------
log ""
log "--- Step 6: content_references edges"

assert_edge() {
    local source_id="$1" target_hash="$2" kind="$3" label="$4" row
    bounded_poll "content_references ${label}" 30 \
        "[ \"\$(psql_one \"SELECT count(*) FROM content_references WHERE repository_id = '${REPO_ID}' AND source_artifact_id = '${source_id}' AND target_content_hash = '${target_hash}' AND kind = '${kind}';\")\" = '1' ]" \
        2 || true
    row="$(psql_one "SELECT count(*) FROM content_references WHERE repository_id = '${REPO_ID}' AND source_artifact_id = '${source_id}' AND target_content_hash = '${target_hash}' AND kind = '${kind}';")"
    if [ "$row" = "1" ]; then
        pass "content_references: ${label} (kind=${kind}) edge present"
    else
        fail "content_references ${label} (kind=${kind}) edge" "count=${row:-0}"
    fi
}

assert_edge "$INDEX_ID" "$CHILD_HASH" "oci_index_member" "index -> child"
assert_edge "$CHILD_ID" "$CONFIG_HASH" "oci_config" "child -> config blob"
for i in "${!LAYER_HASHES[@]}"; do
    assert_edge "$CHILD_ID" "${LAYER_HASHES[$i]}" "oci_layer" "child -> layer[$i] blob"
done

# ---------------------------------------------------------------------
# Step 7: sanity — index (NOT a descendant) got the full window; every
# constituent (a referenced-tree descendant) got the #46 Item 2 zero window
# — the same mechanism that makes Item 3's hold observable without waiting
# out a full-length window.
# ---------------------------------------------------------------------
log ""
log "--- Step 7: quarantine_window_start — index full window, constituents zero window"

index_full_window="$(psql_one "SELECT (quarantine_window_start = created_at) FROM artifacts WHERE id = '${INDEX_ID}';")"
if [ "$index_full_window" = "t" ]; then
    pass "index: quarantine_window_start == created_at (full window — not a content_references target)"
else
    fail "index quarantine_window_start == created_at" "got '${index_full_window}' (expected t)"
fi

# Duration is the literal `quarantineDuration: 30s` in
# oci-provenance-proxy-e2e-required.yaml — hardcoded here rather than
# resolved from `policy_projections` (mirrors proxy-multiarch-zero-window.sh,
# which hardcodes its own policy's 24h for the identical reason: the
# `scope` column is jsonb keyed by repository NAME, not a `repository_id`
# foreign key, so a dynamic lookup would need the same scope-resolution
# logic the application layer already owns — out of scope for a scenario
# script to reimplement).
QUARANTINE_DURATION_SQL="interval '30 seconds'"
assert_zero_window() {
    local id="$1" label="$2" got
    got="$(psql_one "SELECT (quarantine_window_start = created_at - ${QUARANTINE_DURATION_SQL}) FROM artifacts WHERE id = '${id}';")"
    if [ "$got" = "t" ]; then
        pass "${label}: quarantine_window_start == created_at - duration (zero window — referenced-tree-descendant carve-out fired)"
    else
        fail "${label} quarantine_window_start == created_at - duration" "got '${got}' (expected t)"
    fi
}
assert_zero_window "$CHILD_ID" "child manifest"
assert_zero_window "$CONFIG_ID" "config blob"
for i in "${!LAYER_IDS[@]}"; do
    assert_zero_window "${LAYER_IDS[$i]}" "layer[$i] blob"
done

# ---------------------------------------------------------------------
# Step 8: await ProvenanceVerified on the SIGNED SUBJECT (the index) — the
# real-verifier clearance the whole chain hangs off.
# ---------------------------------------------------------------------
log ""
log "--- Step 8: await ProvenanceVerified on the signed index"
if bounded_poll \
        "ProvenanceVerified for index sha256:${INDEX_HASH}" \
        "$WINDOW_WAIT_SECS" \
        "[ -n \"\$(psql_one \"SELECT 1 FROM events WHERE stream_id = 'artifact-${INDEX_ID}' AND event_type = 'ProvenanceVerified' LIMIT 1;\")\" ]" \
        5; then
    pass "ProvenanceVerified emitted for the signed index subject"
else
    fail "ProvenanceVerified for the signed index" \
         "no ProvenanceVerified event for checksum ${INDEX_HASH} within ${WINDOW_WAIT_SECS}s (signature not linked — referrers mode? public key mismatch?)"
fi

# ---------------------------------------------------------------------
# Step 9 [Acceptance (a)]: the pull EVENTUALLY SUCCEEDS — anonymous, proving
# the whole tree (index + child + config + every layer) is genuinely
# consumable once cleared + released, not merely "not rejected in the DB".
# ---------------------------------------------------------------------
log ""
log "--- Step 9: await release + anonymous pull of the full multi-layer image"
rm -f "$PULLED_ARCHIVE"
if bounded_poll \
        "signed image pullable (anonymous)" \
        "$WINDOW_WAIT_SECS" \
        "skopeo copy --all --insecure-policy --src-tls-verify=false 'docker://${REGISTRY_HOST}/${REPO_KEY}/dockerhub/${IMAGE_PATH}@${INDEX_DIGEST}' 'oci-archive:${PULLED_ARCHIVE}'" \
        5; then
    pass "the signed+cleared multi-layer image released and pulled anonymously after the quarantine window (Cleared + timer gate satisfied)"
else
    fail "signed image releases + pulls anonymously" \
         "the signed+cleared image never became anonymously pullable within ${WINDOW_WAIT_SECS}s (window, cascade, or release-sweep gate not satisfied)"
fi

# ---------------------------------------------------------------------
# Step 10 [Acceptance (b), THE regression pin]: no constituent — child
# manifest, config blob, any layer blob — EVER emitted ProvenanceRejected.
# By this point the full lifecycle (sign -> verify -> cascade -> release ->
# pull) has completed or timed out, so if the pre-Item-3 defect were present
# the terminal Rejected{Unsigned} decision would already have landed (it
# fired within moments of ingest, well before this poll).
# ---------------------------------------------------------------------
log ""
log "--- Step 10: THE #115 Item 3 regression pin — no constituent ever rejected"

# Queried by artifact id (stream_id = 'artifact-<id>'), not checksum —
# checksum alone is not repository-scoped, and an unrelated fixture
# elsewhere could in principle share a content-addressed digest.
assert_never_rejected() {
    local id="$1" label="$2" row
    row="$(psql_one "SELECT 1 FROM events WHERE stream_id = 'artifact-${id}' AND event_type = 'ProvenanceRejected' LIMIT 1;")"
    if [ -z "$row" ]; then
        pass "${label}: no ProvenanceRejected ever emitted (#115 Item 3 hold-not-reject held)"
    else
        fail "${label}: no ProvenanceRejected ever emitted" \
             "found a ProvenanceRejected event for artifact ${id} — the referenced-tree-descendant hold (#115 Item 3) did not fire; this constituent terminally rejected instead of holding for cascade clearance"
    fi
}
assert_never_rejected "$INDEX_ID" "index (control — the signed subject itself must not reject)"
assert_never_rejected "$CHILD_ID" "child manifest"
assert_never_rejected "$CONFIG_ID" "config blob"
for i in "${!LAYER_IDS[@]}"; do
    assert_never_rejected "${LAYER_IDS[$i]}" "layer[$i] blob"
done

summary
