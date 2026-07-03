#!/usr/bin/env bash
# requires: egress worker db compose
# Provenance hold-until-signed — the push-then-sign round-trip (issue #13).
#
# This is the first REAL-VERIFIER worker->release-gate provenance E2E (ADR 0000
# open-items register, "Combined real-verifier provenance E2E"). It drives the
# canonical CI flow end to end against a HOSTED OCI repo governed by a
# `provenanceMode: required` + `provenanceBackends: [cosign-key]` ScanPolicy, and
# asserts the four states the hold-until-signed lifecycle promises.
#
# The push is an IMAGE INDEX (multi-arch, `skopeo copy --all`), not a single
# manifest: cosign signs the top-level index digest, so this exercises the real
# index-shaped push-then-sign (issue #15). A single-manifest push returns 200
# and gives false confidence — that the index PUT never failed — which is the
# exact gap issue #15 closed. The digest cosign signs is the index digest.
#
#   [1] PUSH (unsigned)      — a keyed `required` image is HELD, not rejected:
#                               * an anonymous manifest GET/pull -> 503 (held,
#                                 not consumable);
#                               * a WRITE-authorized manifest HEAD -> 200/exists
#                                 (the hold-read exemption, so the signer's
#                                 cosign preflight can resolve the digest and
#                                 ATTACH the signature). An anonymous GET stays
#                                 503.
#   [2] SIGN                  — `cosign sign --key <keyed> --registry-referrers-mode=oci-1-1
#                               <ref>@<digest>` attaches a subject-linked referrer.
#                               hort re-verifies the SUBJECT image (S3), emits
#                               `ProvenanceVerified`, clearance -> Cleared.
#   [3] RELEASE               — once the quarantine window elapses AND provenance
#                               is Cleared, the image RELEASES and PULLS.
#   [4] NEGATIVE (never-sign) — a second image (a DISTINCT digest — same bytes
#                               would CAS-dedup to the signed artifact) is
#                               pushed and never signed; at `quarantineDuration`
#                               expiry the backstop (S4) makes the TERMINAL
#                               decision -> `ProvenanceRejected{Unsigned}`; an
#                               anonymous manifest GET transitions 503 (held)
#                               -> 404 (MANIFEST_UNKNOWN).
#
# -----------------------------------------------------------------------------
# COSIGN RESOLVES THE SUBJECT BY GET (ADR 0039 §10).
# -----------------------------------------------------------------------------
# Keyed `cosign sign` resolves the subject manifest by a `GET manifests/<digest>`
# (not only a `HEAD`) before it attaches the signature manifest. The manifest
# hold exemption therefore covers a write-authorized manifest HEAD AND GET, so a
# held subject is signable: the manifest is metadata (config + layer digests),
# not runnable content; the layer blobs keep their HEAD-only probe, so no
# runnable bytes leave quarantine and a non-writer / anonymous read stays 503.
# Step [3] below runs the sign for real against that widened exemption and
# asserts the full round-trip (sign -> re-verify -> release -> pull) completes.
#
# -----------------------------------------------------------------------------
# WHY THIS MAY SELF-SKIP on the current compose stack.
# -----------------------------------------------------------------------------
# Running the round-trip for real needs three things the base harness does not
# ship yet, so the scenario `skip`s (exit 77 — NEVER a false pass) when any is
# absent rather than faking a result:
#
#   * `cosign` + `buildah` in the client image (Dockerfile.client carries skopeo,
#     not cosign/buildah today);
#   * a keyed cosign signing key pair — the private key to sign with, and its
#     public key mounted into the worker (`HORT_COSIGN_PUBLIC_KEYS_FILE` /
#     values `cosign.publicKeysFile`) so the worker REGISTERS the `cosign-key`
#     backend (ADR 0039). The base compose worker has no cosign env, so
#     `cosign-key` is not registered there;
#   * a hosted OCI repo + ScanPolicy with `provenanceMode: required` +
#     `provenanceBackends: [cosign-key]` and a SHORT `quarantineDuration` (so the
#     window elapses within a smoke run) in the mounted gitops config.
#
# The env contract below lets a CI job that provisions these point the scenario
# at them; absent them, it skips. Skopeo (present) does the push/pull legs;
# cosign does only the signing leg.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

# -----------------------------------------------------------------------------
# Env contract (CI provisioner overrides; sensible defaults otherwise)
# -----------------------------------------------------------------------------
# Repo governed by required+cosign-key. Default matches the fixture name a CI
# provisioner is expected to add to the mounted gitops config.
REPO_KEY="${PROVENANCE_REPO_KEY:-oci-provenance-e2e}"
# Keyed cosign private key to SIGN with (cosign --key). Its PUBLIC half must be
# the one the worker loaded to register `cosign-key`, or the verify will Reject.
# Defaults to the committed test-only fixture keypair whose public half the
# compose worker mounts (deploy/compose/example-config/provenance/cosign.pub);
# $FIXTURES is set by the native-tests runner (=/work/fixtures). A CI job with a
# different keypair overrides COSIGN_KEY.
COSIGN_KEY="${COSIGN_KEY:-${FIXTURES:-}/cosign/cosign.key}"
# cosign needs a password for a file-based key; empty for a keyless-file setup.
export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"
# Source image to push — a genuine multi-arch IMAGE INDEX (ghcr.io, no Docker
# Hub rate limit). Pushed with `skopeo copy --all` so the tag resolves to the
# top-level index digest, and cosign signs THAT index digest (issue #15:
# index-shaped push-then-sign). ghcr.io/stefanprodan/podinfo is an OCI image
# index (mediaType application/vnd.oci.image.index.v1+json).
SOURCE_IMAGE="${SOURCE_IMAGE:-ghcr.io/stefanprodan/podinfo:latest}"
# The never-signed image for the [6/6] negative leg MUST have a DIFFERENT
# digest than SOURCE_IMAGE: storage is content-addressed, so pushing the same
# bytes under a second name dedups to the SAME artifact — and once the signed
# leg's signature verifies THAT digest, the "unsigned" name serves the
# already-released artifact (a cosign signature covers the digest, not the
# name; 200 there is the registry being correct, not a hold bypass). A pinned
# older podinfo tag is likewise a multi-arch OCI image index.
UNSIGNED_SOURCE_IMAGE="${UNSIGNED_SOURCE_IMAGE:-ghcr.io/stefanprodan/podinfo:6.5.0}"
# How long the scenario is willing to wait for the window to elapse + the
# release/expiry sweep to run. The gitops policy's quarantineDuration MUST be
# <= this for the release/reject legs to complete in-run.
WINDOW_WAIT_SECS="${PROVENANCE_WINDOW_WAIT_SECS:-180}"

# Strip scheme so skopeo/cosign's docker:// transport gets host:port only.
REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

SIGNED_NAME="${SIGNED_NAME:-provsigned}"
UNSIGNED_NAME="${UNSIGNED_NAME:-provunsigned}"
DEST_SIGNED="${REGISTRY_HOST}/${REPO_KEY}/${SIGNED_NAME}:v1"
DEST_UNSIGNED="${REGISTRY_HOST}/${REPO_KEY}/${UNSIGNED_NAME}:v1"
PULLED_ARCHIVE="/tmp/prov-pulled-${SIGNED_NAME}.tar"

log "==> Provenance hold-until-signed round-trip (push-then-sign, keyed)"
log "Registry : ${HORT_URL}"
log "Repo key : ${REPO_KEY} (expected: provenanceMode=required, provenanceBackends=[cosign-key])"
log "Source   : ${SOURCE_IMAGE}"

# ---- Tool + config availability -> self-skip (never a false pass) ----
command -v skopeo >/dev/null 2>&1 || skip "skopeo not found in client image"
command -v cosign >/dev/null 2>&1 || \
    skip "cosign not in client image — provision cosign + a keyed key + a required/cosign-key repo, then re-run (see header)"
[ -n "$COSIGN_KEY" ] || \
    skip "COSIGN_KEY unset — no keyed cosign private key to sign with (its public half must be the worker's registered cosign-key)"
[ -f "$COSIGN_KEY" ] || \
    skip "keyed cosign private key '$COSIGN_KEY' not found (expected the committed fixture at \$FIXTURES/cosign/cosign.key, or a CI-provided COSIGN_KEY)"

trap 'rm -f "$PULLED_ARCHIVE"' EXIT

# dev-user is the write-authorized pusher/signer (mirrors the other OCI
# scenarios). The public half of COSIGN_KEY must match the worker's registered
# key or step [2] will Reject instead of Verify.
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"
[ -n "$DEV_TOKEN" ] || summary
DEST_CREDS="dev-user:${DEV_TOKEN}"
log "[auth] fetched DEV_TOKEN from Keycloak (dev-user write-authorized for ${REPO_KEY})"

# push_source_index <dest-ref> [<src-ref>] — `skopeo copy --all` a multi-arch
# source (default SOURCE_IMAGE) to a hosted dest, with a bounded retry. The
# pull leg reaches out to a public registry (ghcr.io) for four per-arch images;
# a cold-cache pull occasionally drops a blob mid-copy (transient egress, not a
# Hort defect), and skopeo is not idempotent-resumable on that failure. Three
# attempts make the source pull deterministic without masking a genuine PUT
# rejection (the #15 regression): on a real MANIFEST_INVALID the dest PUT fails
# every attempt. Returns skopeo's last exit status. Runs under
# `set -euo pipefail`, so the `if` consumes each non-final failure's status.
push_source_index() {
    local dest="$1" src="${2:-$SOURCE_IMAGE}" attempt rc=1
    for attempt in 1 2 3; do
        # `|| rc=$?` captures skopeo's real exit under `set -e` (a bare failing
        # command in an `if` would leave `$?`=0 for the whole compound). rc reset
        # to 0 first so a success leaves it 0.
        rc=0
        skopeo copy --all --insecure-policy --dest-tls-verify=false \
              --dest-creds "$DEST_CREDS" \
              "docker://${src}" "docker://${dest}" >/dev/null 2>&1 || rc=$?
        [ "$rc" -eq 0 ] && break
        log "  [push retry] skopeo copy --all ${src} -> ${dest} failed (attempt ${attempt}/3, rc=${rc}); retrying"
        sleep 3
    done
    return "$rc"
}

# =============================================================================
# [1/6] PUSH (unsigned) — accepted, held (write path ungated by the hold)
# =============================================================================
log "==> [1/6] Push --all ${SOURCE_IMAGE} -> docker://${DEST_SIGNED} (to-be-signed image INDEX)"
if push_source_index "$DEST_SIGNED"; then
    pass "push of the to-be-signed image INDEX accepted (index PUT ungated; was MANIFEST_INVALID before issue #15; held under required)"
else
    fail "index push to required+cosign-key repo" \
         "skopeo copy --all -> ${DEST_SIGNED} exited non-zero after retries (a hosted index PUT under required must still be accepted, then HELD — a rejected index PUT is the #15 regression)"
    summary
fi

# Resolve the pushed digest (cosign signs <ref>@<digest>, not the tag).
# `skopeo inspect` issues a manifest GET, which the hold answers with 503 — an
# EXPECTED non-zero exit. common.sh runs the scenario under `set -euo pipefail`,
# so the failing command substitution must be neutralised with `|| true` or
# errexit aborts the script before the write-authorized-HEAD fallback below can
# run (that fallback is the whole point: the HEAD exemption serves the digest
# while GET stays 503).
DIGEST="$(skopeo inspect --tls-verify=false --creds "$DEST_CREDS" \
    "docker://${DEST_SIGNED}" 2>/dev/null | jq -r '.Digest // empty' || true)"
if [ -z "$DIGEST" ]; then
    # Fall back to the Docker-Content-Digest header of a write-authorized HEAD,
    # which the existence-probe exemption serves (200) even under the hold.
    DIGEST="$(curl -sSI -H "Authorization: Bearer ${DEV_TOKEN}" \
        "${HORT_URL}/v2/${REPO_KEY}/${SIGNED_NAME}/manifests/v1" 2>/dev/null \
        | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}' || true)"
fi
[ -n "$DIGEST" ] || { fail "resolve pushed digest" "neither skopeo inspect nor a write-authorized HEAD returned a digest"; summary; }
log "[digest] pushed manifest digest = ${DIGEST}"

# =============================================================================
# [2/6] HELD — anonymous manifest pull 503; write-authorized manifest HEAD 200
# =============================================================================
log "==> [2/6] Assert HELD: anonymous manifest GET -> 503, write-authorized HEAD -> exists"

ANON_GET_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
    "${HORT_URL}/v2/${REPO_KEY}/${SIGNED_NAME}/manifests/${DIGEST}" 2>/dev/null || echo 000)"
if [ "$ANON_GET_CODE" = "503" ]; then
    pass "anonymous manifest GET on held image -> 503 (not consumable)"
else
    fail "anonymous manifest GET -> 503" "got HTTP ${ANON_GET_CODE} (a held required image must 503 to pullers)"
fi

WRITE_HEAD_CODE="$(curl -s -o /dev/null -w '%{http_code}' -I \
    -H "Authorization: Bearer ${DEV_TOKEN}" \
    "${HORT_URL}/v2/${REPO_KEY}/${SIGNED_NAME}/manifests/${DIGEST}" 2>/dev/null || echo 000)"
if [ "$WRITE_HEAD_CODE" = "200" ]; then
    pass "write-authorized manifest HEAD on held image -> 200/exists (hold-read exemption; signer can preflight)"
else
    fail "write-authorized manifest HEAD -> 200" \
         "got HTTP ${WRITE_HEAD_CODE} (the write-authorized manifest hold-read exemption must report exists so cosign can preflight)"
fi

# Keyed cosign resolves the subject by GET too (ADR 0039 §10): a write-authorized
# manifest GET of the held subject SERVES (200), so the sign in [3] can resolve
# the subject. The manifest is metadata, not runnable content; layer bytes stay
# held (anonymous GET above is 503, layer blobs stay HEAD-only).
WRITE_GET_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${DEV_TOKEN}" \
    "${HORT_URL}/v2/${REPO_KEY}/${SIGNED_NAME}/manifests/${DIGEST}" 2>/dev/null || echo 000)"
if [ "$WRITE_GET_CODE" = "200" ]; then
    pass "write-authorized manifest GET on held image -> 200/serves (hold-read exemption; keyed cosign resolves the subject by GET)"
else
    fail "write-authorized manifest GET -> 200" \
         "got HTTP ${WRITE_GET_CODE} (ADR 0039 §10: a write-authorized GET of a held manifest must SERVE so keyed cosign can resolve the subject before signing)"
fi

# =============================================================================
# [3/6] SIGN — cosign sign --key --registry-referrers-mode=oci-1-1 <ref>@<digest>
# =============================================================================
# Keyed cosign resolves the subject by GET (ADR 0039 §10); the widened manifest
# hold-read exemption serves that GET to the write-authorized signer, so the
# sign must COMPLETE against the held subject. Capture cosign's output so a
# reviewer can see the exact blocked op if it ever regresses.
log "==> [3/6] cosign sign --key ... --registry-referrers-mode=oci-1-1 ${DEST_SIGNED%:*}@${DIGEST}"
export COSIGN_DOCKER_MEDIA_TYPES=1
# cosign v3 still gates `--registry-referrers-mode=oci-1-1` (the subject-based
# OCI 1.1 referrers carriage ADR 0039 §9 REQUIRES for hosted keyed signing)
# behind COSIGN_EXPERIMENTAL=1; without it cosign errors out before any registry
# call. The operator running `cosign v3.0.4` sets the same flag.
export COSIGN_EXPERIMENTAL=1
SIGN_OUT=""
SIGN_RC=0
SIGN_OUT="$(cosign sign --yes \
    --key "$COSIGN_KEY" \
    --registry-referrers-mode=oci-1-1 \
    --registry-username=dev-user \
    --registry-password="$DEV_TOKEN" \
    --allow-insecure-registry \
    --allow-http-registry \
    "${REGISTRY_HOST}/${REPO_KEY}/${SIGNED_NAME}@${DIGEST}" 2>&1)" || SIGN_RC=$?
if [ "$SIGN_RC" -eq 0 ]; then
    pass "cosign sign (keyed, oci referrers) succeeded — the write-authorized manifest HEAD-and-GET hold-read exemption served the subject to the signer"
else
    log "[cosign output]"; printf '%s\n' "$SIGN_OUT" | sed 's/^/    /'
    if printf '%s' "$SIGN_OUT" | grep -Eqi 'GET .*/manifests/.*503|503 .*manifests'; then
        fail "cosign sign hold-read exemption regressed" \
             "cosign got a 503 on a manifest GET during signing -> the write-authorized manifest hold-read exemption (ADR 0039 §10) is not serving the held subject to the signer; the exemption regressed to HEAD-only"
    else
        fail "cosign sign (keyed, oci referrers)" \
             "cosign exited ${SIGN_RC}; see output above (not obviously a manifest-GET 503 — inspect the cosign error)"
    fi
    summary
fi

# =============================================================================
# [4/6] VERIFIED — worker re-verifies the subject (S3) -> ProvenanceVerified
# =============================================================================
log "==> [4/6] Await ProvenanceVerified on the subject image (worker S3 re-verify)"
# The subject artifact id is resolved by content hash = the pushed digest hex.
DIGEST_HEX="${DIGEST#sha256:}"
if bounded_poll \
        "ProvenanceVerified for ${SIGNED_NAME}@${DIGEST}" \
        "$WINDOW_WAIT_SECS" \
        "[ -n \"\$(psql_one \"SELECT 1 FROM events e JOIN artifacts a ON e.stream_id = 'artifact-' || a.id::text WHERE a.checksum_sha256 = '${DIGEST_HEX}' AND e.event_type = 'ProvenanceVerified' LIMIT 1;\")\" ]" \
        5; then
    pass "ProvenanceVerified emitted for the signed subject image (real-verifier clearance)"
else
    fail "ProvenanceVerified for the signed image" \
         "no ProvenanceVerified event for checksum ${DIGEST_HEX} within ${WINDOW_WAIT_SECS}s — signature not linked (referrers mode?) or public key mismatch"
fi

# =============================================================================
# [5/6] RELEASE — after the window + Cleared, the image pulls
# =============================================================================
log "==> [5/6] Await release + pull of the signed image (window elapsed + Cleared)"
rm -f "$PULLED_ARCHIVE"
if bounded_poll \
        "signed image pullable" \
        "$WINDOW_WAIT_SECS" \
        "skopeo copy --all --insecure-policy --src-tls-verify=false --src-creds '${DEST_CREDS}' 'docker://${DEST_SIGNED}' 'oci-archive:${PULLED_ARCHIVE}'" \
        5; then
    pass "signed image index released and pulled after the quarantine window (Cleared + timer gate satisfied)"
else
    fail "signed image releases + pulls" \
         "the signed+cleared image never became pullable within ${WINDOW_WAIT_SECS}s (window or provenance gate not satisfied)"
fi

# =============================================================================
# [6/6] NEGATIVE — never-signed image -> terminal Rejected{Unsigned} at expiry
# =============================================================================
log "==> [6/6] NEGATIVE: push an image INDEX (distinct digest), never sign it -> terminal Rejected{Unsigned} at window expiry"
# Distinct-digest source (UNSIGNED_SOURCE_IMAGE) — same-bytes would CAS-dedup
# to the signed leg's already-released artifact (see the env-contract comment).
if push_source_index "$DEST_UNSIGNED" "$UNSIGNED_SOURCE_IMAGE"; then
    log "  pushed never-to-be-signed image index ${UNSIGNED_SOURCE_IMAGE} -> ${DEST_UNSIGNED}"
else
    fail "push never-signed image index" "skopeo copy --all ${UNSIGNED_SOURCE_IMAGE} -> ${DEST_UNSIGNED} exited non-zero"
    summary
fi

# At window expiry the release sweep enqueues a final provenance-verify with
# window_open=false; complete_provenance then emits ProvenanceRejected{Unsigned}
# and the manifest transitions from 503 (held) to 404 (MANIFEST_UNKNOWN).
#
# Poll ANONYMOUSLY: the hold-read exemption (ADR 0039 §10) legitimately serves
# 200 to a WRITE-authorized manifest GET while held, so a credentialed poll
# cannot observe the held state at all. The anonymous view is the puller's
# view and traverses the exact transition the lifecycle promises: 503 (held)
# -> 404 (terminal Rejected{Unsigned}).
ANON_UNSIGNED_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
    "${HORT_URL}/v2/${REPO_KEY}/${UNSIGNED_NAME}/manifests/v1" 2>/dev/null || echo 000)"
if [ "$ANON_UNSIGNED_CODE" = "503" ]; then
    pass "never-signed image starts HELD (anonymous manifest GET -> 503)"
elif [ "$ANON_UNSIGNED_CODE" = "404" ]; then
    # The window (30s in the compose fixture) can expire before this probe
    # runs — e.g. the [5/6] poll above consumed it. Already-terminal is the
    # SAME correct end state, just observed late; only a non-{503,404} code
    # (200 = released-unsigned!) is a real failure.
    pass "never-signed image already terminal at first probe (anonymous GET -> 404; window expired during [5/6])"
else
    fail "never-signed image held (anonymous GET -> 503)" \
         "got HTTP ${ANON_UNSIGNED_CODE} (a held required image must 503 anonymously; 200 would mean an unsigned image is being served)"
fi
if bounded_poll \
        "never-signed manifest -> 404 (terminal Rejected{Unsigned})" \
        "$WINDOW_WAIT_SECS" \
        "[ \"\$(curl -s -o /dev/null -w '%{http_code}' '${HORT_URL}/v2/${REPO_KEY}/${UNSIGNED_NAME}/manifests/v1' 2>/dev/null)\" = '404' ]" \
        5; then
    pass "never-signed image is terminally Rejected{Unsigned} at window expiry (anonymous manifest 503 -> 404, not released)"
else
    LAST_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
        "${HORT_URL}/v2/${REPO_KEY}/${UNSIGNED_NAME}/manifests/v1" 2>/dev/null || echo 000)"
    fail "never-signed image -> terminal Rejected{Unsigned}" \
         "anonymous manifest GET still HTTP ${LAST_CODE} after ${WINDOW_WAIT_SECS}s (expected 404; the expiry backstop should have made the terminal Unsigned decision)"
fi

summary
