#!/usr/bin/env bash
# requires: db worker scanner egress
# A layer whose materialised tree no analyzer claimed releases and SERVES, because that absence belongs to the composition.
#
# THE INVARIANT THIS PINS. ADR 0064 D2 draws one line: whether what the
# scan says is about THE BYTES or about THE RESULTING FILESYSTEM — and it
# governs the ABSENCE of an assessment exactly as it governs a finding.
# "No analyzer claimed anything in this layer" is an absence of analysis,
# not a statement that the layer's bytes are dangerous, so on a layer
# whose composition is the unit of filesystem assessment it belongs to the
# composition. The layer must therefore not be held for it, and must
# serve.
#
# WHAT IT LOOKED LIKE WHEN IT DID NOT. A real `library/sonarqube` image
# sat `released` and served its manifest with 200 while four of its layer
# blobs served 503: each of those layers' scan jobs was terminally
# `failed` with `trivy=no_analyzer_matched` for `kind oci_blob`, and each
# row was `scan_indeterminate` with `last_scan_at` NULL. A client that
# resolves a manifest and fetches the layers it names fails on an artifact
# hort reports as deliverable, and nothing but the client notices.
#
# WHY THE SIBLING SCENARIO CANNOT SEE THIS, which is the reason this file
# exists rather than a fifth leg over there. `trivy-oci-not-applicable.sh`
# runs against `oci-trivy-e2e`, whose policy is `enforcement: record`:
# under `record` no verdict gates anything, so a run there cannot
# distinguish "this absence of assessment moved to the composition" from
# "nothing was gating in the first place".
# Its synthetic layer also lands on `not_applicable` — the arm that has
# never gated — never on `no_analyzer_matched`. So it proves every OCI row
# receives a completed assessment; it cannot prove that a GATING
# repository serves this layer.
#
# THE FIXTURE, AND WHY IT IS ONE SYMLINK AWAY FROM THE SIBLING'S. Source
# is a single-arch Alpine base (a real apk database — so the composition
# whose verdict gates this image has a genuine package surface to assess)
# plus one
# synthetic layer appended locally. That layer is byte-for-byte the shape
# of the sibling scenario's package-less layer — one certificate file, no
# package database — PLUS a symlink beside it, and that one entry is the
# whole difference between the two outcomes:
#   - the extractor never materialises a link entry (a link carries no
#     bytes of its own, and materialising one is the escape-through-a-
#     symlink hazard the extractor exists to refuse), so the tree handed
#     to the analyzers is missing a path the archive declared;
#   - Trivy selects analyzers by path, so "every analyzer agreed there is
#     no package surface" is no longer a statement about this artifact,
#     and the adapter withdraws the `not_applicable` narrowing and reports
#     `no_analyzer_matched` instead.
# Appending the layer in-process (`skopeo copy … dir:`, then a synthetic
# layer + config edited in place) rather than pulling an image that
# happens to have this shape is what keeps the layer's contents pinned: an
# upstream retag cannot change what this scenario tests.
#
# ORDER OF THE LEGS IS LOAD-BEARING, for the same reason as the sibling's:
# while a row is held, reading it back over HTTP is a 503 by design. So
# every digest this scenario needs is captured while the fixture is being
# assembled, the rows are waited out through the database, and only the
# final leg goes over HTTP.
#
# WHAT IS DELIBERATELY NOT ASSERTED. The MANIFEST row's own verdict. Under
# `enforcement: reject` the composite assessment of the assembled image
# is the manifest's verdict, so whether the manifest releases or is
# rejected depends on which CVEs the Alpine base carries on the day the
# suite runs — exactly the dependency the sibling fixture chose `record`
# to avoid. That is ADR 0064 D2 working as intended and it is not this
# scenario's claim; the claim is about the layer, which is the row the
# defect stranded.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

command -v skopeo >/dev/null 2>&1 || skip "skopeo not found in PATH"
command -v jq     >/dev/null 2>&1 || skip "jq not found in PATH"

REPO_KEY="${TRIVY_COMPOSITE_REPO_KEY:-oci-trivy-composite-e2e}"
# Strip scheme so skopeo's docker:// transport gets host:port only.
REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

# Single-arch, single-layer, apk-database-carrying base for the fixture.
SOURCE_IMAGE="${SOURCE_IMAGE:-alpine:3.19}"
TEST_IMAGE_NAME="${TEST_IMAGE_NAME:-linkimg}"
TEST_TAG="${TEST_TAG:-v0}"

DEST_IMAGE="${REGISTRY_HOST}/${REPO_KEY}/${TEST_IMAGE_NAME}:${TEST_TAG}"
BLOB_URL_BASE="${HORT_URL}/v2/${REPO_KEY}/${TEST_IMAGE_NAME}/blobs"
FIXTURE_DIR="$(mktemp -d)"
BASE_LAYOUT="${FIXTURE_DIR}/base"

# The policy's `quarantineDuration`. Kept as a variable so the waits below
# read as "the window plus scan turnaround", not as magic numbers.
WINDOW_SECS="${TRIVY_COMPOSITE_WINDOW_SECS:-20}"

# 1 manifest + 1 config blob + 2 layer blobs (the apk-database base layer
# and the synthetic link-carrying layer). Asserted rather than assumed: a
# change to how the fixture is assembled would otherwise silently change
# what the legs below are actually testing.
EXPECTED_ROWS="${TRIVY_COMPOSITE_EXPECTED_ROWS:-4}"

log "==> Trivy OCI constituent-abstention e2e (ADR 0064 D2)"
log "registry : ${HORT_URL}"
log "repo     : ${REPO_KEY} (trivy, ${WINDOW_SECS}s window, enforcement=reject)"
log "source   : ${SOURCE_IMAGE} + one synthetic link-carrying layer"
log "dest     : ${DEST_IMAGE}"

trap 'rm -rf "$FIXTURE_DIR"' EXIT

REPO_ID="$(psql_one "SELECT id FROM repositories WHERE key = '${REPO_KEY}' LIMIT 1;")"
[ -n "$REPO_ID" ] || skip "repositories row for key='${REPO_KEY}' absent — gitops apply has not run against this DB"
log "repository id=${REPO_ID}"

# Belt and braces on the posture the whole scenario rests on. A policy
# that silently stopped enforcing would make every assertion below fail
# for a reason that has nothing to do with the code under test, and the
# failure would read as a regression in the release path.
#
# Only `enforcement` is read. The composed image's verdict is the
# manifest's unconditionally (ADR 0064 D2) — there is no second posture to
# confirm, and `policy_projections.composite_verdict_mode` is a retired
# column nothing reads, so asserting on it would be asserting on a stored
# byte no decision consults.
#
# `policy_projections.scope` is the externally-tagged `PolicyScope`, so a
# repository-scoped row carries `{"Repository": "<uuid>"}` — matched on the
# repository id rather than on the policy's name, because what governs this
# push is whichever active policy resolves for THIS repository.
POSTURE="$(psql_one "SELECT enforcement
                     FROM policy_projections
                     WHERE archived = false
                       AND scope->>'Repository' = '${REPO_ID}'
                     LIMIT 1;")"
if [ "$POSTURE" = "reject" ]; then
    pass "(0) the resolved policy is enforcement=reject"
else
    fail "(0) the resolved policy must be enforcement=reject" \
        "got '${POSTURE:-<no repository-scoped scan policy>}' for repository_id='${REPO_ID}'. Without reject nothing gates and this scenario is asserting nothing."
    summary
fi

# -----------------------------------------------------------------------------
# Credential mode: legacy (Basic / IdP-JWT) vs native tokens. Mirrors
# scenarios/quarantine/trivy-oci-not-applicable.sh — under the `native-tokens`
# overlay the /v2/auth mint validates the Basic password strictly as a native
# PAT, which dev-user's Keycloak JWT can never satisfy.
# -----------------------------------------------------------------------------
NATIVE_TOKENS=0
case " ${HORT_COMPOSE_OVERLAYS:-} " in
    *" native-tokens "*) NATIVE_TOKENS=1 ;;
esac

if [ "$NATIVE_TOKENS" = "1" ]; then
    log "[auth] native-token mode: admin-minting an hort_svc_* token for service account ${REPO_KEY}-ci"
    SVC_TOKEN="$(mint_svc_token "${REPO_KEY}-ci" "$REPO_KEY" read,write)" || {
        fail "admin-mint ${REPO_KEY}-ci svc token" "mint_svc_token failed -- see stderr diagnostics above"; summary; }
    DEST_CREDS="${REPO_KEY}-ci:${SVC_TOKEN}"
else
    DEV_TOKEN="$(fetch_token dev-user dev)"
    [ -n "$DEV_TOKEN" ] || skip "could not fetch dev-user token from Keycloak — stack not ready"
    DEST_CREDS="dev-user:${DEV_TOKEN}"
    log "[auth] legacy mode: dev-user carries [developer, ci-pusher] -> write on ${REPO_KEY}"
fi

# ---------------------------------------------------------------------------
# (1a) Assemble the fixture locally: pull the Alpine base into an OCI `dir:`
# layout, then append the synthetic link-carrying layer and fold its diff ID
# into the config. `dir:` lays each blob out as a plain file named by its hex
# digest plus a `manifest.json`, which is what makes editing it in place
# possible without a container build tool.
# ---------------------------------------------------------------------------
log ""
log "--- (1a) Pull ${SOURCE_IMAGE} into a local OCI layout"
if ! skopeo copy --insecure-policy "docker://${SOURCE_IMAGE}" "dir:${BASE_LAYOUT}" 2>&1; then
    fail "(1a) pull ${SOURCE_IMAGE} into a local OCI layout" \
        "skopeo copy docker://${SOURCE_IMAGE} -> dir:${BASE_LAYOUT} exited non-zero; is docker.io reachable?"
    summary
fi

BASE_MANIFEST="${BASE_LAYOUT}/manifest.json"
BASE_LAYER_COUNT="$(jq '.layers | length' "$BASE_MANIFEST")"
if [ "$BASE_LAYER_COUNT" -ne 1 ]; then
    fail "(1a) ${SOURCE_IMAGE} must be a single-layer base for this fixture" \
        "found ${BASE_LAYER_COUNT} layers in the pulled manifest -- pick an Alpine tag with one layer, or teach this scenario to locate the apk-database layer instead of assuming index 0."
    summary
fi
BASE_LAYER_DIGEST="$(jq -r '.layers[0].digest' "$BASE_MANIFEST")"
BASE_LAYER_MEDIA_TYPE="$(jq -r '.layers[0].mediaType' "$BASE_MANIFEST")"
BASE_CONFIG_DIGEST="$(jq -r '.config.digest' "$BASE_MANIFEST")"
BASE_CONFIG_MEDIA_TYPE="$(jq -r '.config.mediaType' "$BASE_MANIFEST")"
BASE_CONFIG_HEX="${BASE_CONFIG_DIGEST#sha256:}"
log "  base layer  : ${BASE_LAYER_DIGEST} (apk database)"

# The synthetic layer: the sibling scenario's package-less certificate
# layer PLUS one symlink. The certificate gives the analyzers a path to
# walk and nothing to claim; the symlink is the entry the extractor skips,
# which is what makes the walked tree a strict subset of the archive and
# so withdraws the `not_applicable` reading.
LAYER_ROOT="${FIXTURE_DIR}/layer-root/usr/share/ca-certificates"
mkdir -p "$LAYER_ROOT"
cat > "${LAYER_ROOT}/hort-e2e-fixture.crt" <<'CERT'
-----BEGIN CERTIFICATE-----
hort e2e fixture -- not a real certificate, no package database nearby
-----END CERTIFICATE-----
CERT
ln -s "hort-e2e-fixture.crt" "${LAYER_ROOT}/hort-e2e-fixture-alias.crt"

LAYER_TAR="${FIXTURE_DIR}/linked-layer.tar"
LAYER_TAR_GZ="${FIXTURE_DIR}/linked-layer.tar.gz"
# No `-h`/`--dereference`: the symlink must land in the archive AS a
# symlink entry, because that is the entry class the extractor skips and
# the whole point of this fixture.
tar --numeric-owner --owner=0 --group=0 -cf "$LAYER_TAR" -C "${FIXTURE_DIR}/layer-root" .
# Through `capture_match` rather than a pipe into `grep -q`: under this
# file's `set -o pipefail` a `grep -q` that exits at its first match
# SIGPIPEs the still-writing producer, and pipefail promotes that to the
# pipeline's status — indistinguishable from a genuine no-match.
if ! capture_match '^l' tar -tvf "$LAYER_TAR"; then
    fail "(1a) the synthetic layer must carry a symlink ENTRY" \
        "no entry of type 'l' in ${LAYER_TAR} -- tar dereferenced the link, so the extractor will skip nothing and the layer will land on 'not_applicable' instead of 'no_analyzer_matched'. This scenario would then pass while testing nothing."
    summary
fi
pass "(1a) the synthetic layer carries a symlink entry (the skipped entry the outcome turns on)"

NEW_DIFF_ID="sha256:$(sha256sum "$LAYER_TAR" | cut -d' ' -f1)"
gzip -c "$LAYER_TAR" > "$LAYER_TAR_GZ"
NEW_LAYER_HEX="$(sha256sum "$LAYER_TAR_GZ" | cut -d' ' -f1)"
NEW_LAYER_SIZE="$(stat -c%s "$LAYER_TAR_GZ")"
cp "$LAYER_TAR_GZ" "${BASE_LAYOUT}/${NEW_LAYER_HEX}"
log "  new layer   : sha256:${NEW_LAYER_HEX} (one certificate + one symlink, no package database)"

# Fold the new layer's diff ID into a copy of the base config -- this is
# the only edit that makes the appended layer part of the image's rootfs
# rather than an orphaned blob the manifest happens to also list.
NEW_CONFIG="${FIXTURE_DIR}/config.json"
jq --arg diffid "$NEW_DIFF_ID" \
   '.rootfs.diff_ids += [$diffid]
    | .history += [{"created": "1970-01-01T00:00:00Z",
                     "comment": "hort e2e fixture: link-carrying certificate layer",
                     "empty_layer": false}]' \
   "${BASE_LAYOUT}/${BASE_CONFIG_HEX}" > "$NEW_CONFIG"
NEW_CONFIG_HEX="$(sha256sum "$NEW_CONFIG" | cut -d' ' -f1)"
NEW_CONFIG_SIZE="$(stat -c%s "$NEW_CONFIG")"
cp "$NEW_CONFIG" "${BASE_LAYOUT}/${NEW_CONFIG_HEX}"

jq --arg cfgmt "$BASE_CONFIG_MEDIA_TYPE" --arg cfgdigest "sha256:${NEW_CONFIG_HEX}" --argjson cfgsize "$NEW_CONFIG_SIZE" \
   --arg lmt "$BASE_LAYER_MEDIA_TYPE" --arg ldigest "sha256:${NEW_LAYER_HEX}" --argjson lsize "$NEW_LAYER_SIZE" \
   '.config = {mediaType: $cfgmt, digest: $cfgdigest, size: $cfgsize}
    | .layers += [{mediaType: $lmt, digest: $ldigest, size: $lsize}]' \
   "$BASE_MANIFEST" > "${BASE_MANIFEST}.new"
mv "${BASE_MANIFEST}.new" "$BASE_MANIFEST"

# ---------------------------------------------------------------------------
# (1b) Push the assembled fixture. The write path is ungated by the
# quarantine hold, so this must succeed even though every ingested row lands
# `quarantined`.
# ---------------------------------------------------------------------------
log ""
log "--- (1b) Push the two-layer fixture -> docker://${DEST_IMAGE}"
if skopeo copy \
        --insecure-policy \
        --dest-tls-verify=false \
        --dest-creds "$DEST_CREDS" \
        "dir:${BASE_LAYOUT}" \
        "docker://${DEST_IMAGE}" 2>&1; then
    pass "(1) push of the fixture to the enforcing repo succeeded"
else
    fail "(1) push of the fixture to the enforcing repo" \
        "skopeo copy dir:${BASE_LAYOUT} -> ${DEST_IMAGE} exited non-zero. A 400 MANIFEST_BLOB_UNKNOWN naming sha256:${NEW_LAYER_HEX} is the defect this scenario is about, reached one step earlier than the blob fetch below: the manifest PUT refuses a constituent already in a terminal state, and a layer whose scan abstained with no_analyzer_matched lands scan_indeterminate within seconds of its upload. Check the worker log for 'no scan backend produced a verdict'."
    summary
fi

# ---------------------------------------------------------------------------
# (2) Row census. Read through the database, not over HTTP: the content is
# held at this point and a manifest GET is a 503 by design.
# ---------------------------------------------------------------------------
log ""
log "--- (2) Row census"
ROW_COUNT="$(psql_one "SELECT count(*) FROM artifacts WHERE repository_id = '${REPO_ID}';")"
if [ "${ROW_COUNT:-0}" -ne "$EXPECTED_ROWS" ]; then
    fail "(2) the push must ingest exactly ${EXPECTED_ROWS} rows (manifest + config + 2 layers)" \
        "found ${ROW_COUNT:-0} artifacts rows for repository_id='${REPO_ID}' -- an unexpected fixture shape changes what the legs below test; set TRIVY_COMPOSITE_EXPECTED_ROWS if that is intended."
    summary
fi
pass "(2) ${EXPECTED_ROWS} rows ingested"

LINK_LAYER_ID="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = 'blobs/sha256:${NEW_LAYER_HEX}';")"
BASE_LAYER_ID="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = 'blobs/${BASE_LAYER_DIGEST}';")"
if [ -z "$LINK_LAYER_ID" ] || [ -z "$BASE_LAYER_ID" ]; then
    fail "(2) both layer rows must be locatable by the digest the fixture pushed" \
        "link-carrying layer id='${LINK_LAYER_ID:-<none>}' (blobs/sha256:${NEW_LAYER_HEX}), base layer id='${BASE_LAYER_ID:-<none>}' (blobs/${BASE_LAYER_DIGEST})"
    summary
fi
log "  link-carrying layer row : ${LINK_LAYER_ID}"
log "  apk-database layer row  : ${BASE_LAYER_ID}"

# ---------------------------------------------------------------------------
# (3) The link-carrying layer records a COMPLETED scan.
#
# `record_scan_indeterminate` does not advance `last_scan_at`, so this poll
# is the exact discriminator: before ADR 0064 D2's abstention rule reached
# `no_analyzer_matched`, this row's scan abstained, the abstention gated,
# the row went terminally `scan_indeterminate` and `last_scan_at` stayed
# NULL forever. No budget makes that poll succeed.
# ---------------------------------------------------------------------------
log ""
log "--- (3) Awaiting a completed scan for the link-carrying layer"
if bounded_poll "link layer scanned" 240 \
        "[ -n \"\$(psql_one \"SELECT 1 FROM artifacts WHERE id = '${LINK_LAYER_ID}' AND last_scan_at IS NOT NULL;\")\" ]" \
        5; then
    pass "(3) the link-carrying layer recorded a completed scan"
else
    STATE="$(psql_one "SELECT COALESCE(quarantine_status::text,'null') || ' last_scan_at=' || COALESCE(last_scan_at::text,'NULL') FROM artifacts WHERE id = '${LINK_LAYER_ID}';")"
    fail "(3) the link-carrying layer must record a completed scan within 240s" \
        "row state: ${STATE:-<row gone>}. 'scan_indeterminate' with last_scan_at=NULL is THE defect: the scan abstained with no_analyzer_matched and that abstention held the layer, even though the composition above it is the unit of filesystem assessment and carries its verdict. Check the worker log for 'no scan backend produced a verdict' naming kind oci_blob."
    summary
fi

# The counter-assertion's row needs its own wait, and for a different
# reason: the apk-database layer runs a real vulnerability scan against
# Trivy's database, which is the slowest scan in this fixture. Without
# this poll leg (4) would read an absent `ScanCompleted` as a wrong
# assessment and fail the counter-assertion on a race.
log ""
log "--- (3b) Awaiting a completed scan for the apk-database layer"
if bounded_poll "base layer scanned" 240 \
        "[ -n \"\$(psql_one \"SELECT 1 FROM artifacts WHERE id = '${BASE_LAYER_ID}' AND last_scan_at IS NOT NULL;\")\" ]" \
        5; then
    pass "(3b) the apk-database layer recorded a completed scan"
else
    STATE="$(psql_one "SELECT COALESCE(quarantine_status::text,'null') || ' last_scan_at=' || COALESCE(last_scan_at::text,'NULL') FROM artifacts WHERE id = '${BASE_LAYER_ID}';")"
    fail "(3b) the apk-database layer must record a completed scan within 240s" \
        "row state: ${STATE:-<row gone>}. This row is the fixture's control: it carries an analysable package surface, so a scan that never completes here is a scanner or Trivy-database problem rather than anything to do with the abstention rule."
    summary
fi

# ---------------------------------------------------------------------------
# (4) The recorded assessment, per layer. This is the honest trail: a zero
# finding_count alone cannot tell "examined and clean" from "nothing here
# for this artifact to be held for", which is what the event field records.
#
# `events.event_data` is the typed envelope `{"type": …, "data": {fields}}`,
# so the payload field is reached through `->'data'`. The default assessment
# is deliberately NOT written to the wire (writing it would change the
# canonical bytes of every event appended before the field existed and break
# the tamper-evident chain), so an absent key means `analysed`.
# ---------------------------------------------------------------------------
log ""
log "--- (4) Recorded assessment per layer"
assessment_of() {
    psql_one "SELECT COALESCE(event_data->'data'->>'assessment', 'analysed')
              FROM events
              WHERE stream_id = 'artifact-${1}' AND event_type = 'ScanCompleted'
              ORDER BY stream_position DESC LIMIT 1;"
}

GOT_LINK="$(assessment_of "$LINK_LAYER_ID")"
if [ "$GOT_LINK" = "not_applicable" ]; then
    pass "(4) link-carrying layer recorded 'not_applicable' (a completed assessment with nothing of this layer's to assess)"
else
    fail "(4) link-carrying layer must record 'not_applicable'" \
        "latest ScanCompleted for artifact-${LINK_LAYER_ID} carries assessment='${GOT_LINK:-<no ScanCompleted>}'. 'analysed' would claim an examination that never happened -- no analyzer claimed anything in this tree."
fi

# The counter-assertion, and the reason the Alpine base is in the fixture
# at all: a layer that DOES carry a package database is still really
# analysed. Without this, a fixture that had silently stopped running the
# scanner would satisfy every other assertion in this file.
GOT_BASE="$(assessment_of "$BASE_LAYER_ID")"
if [ "$GOT_BASE" = "analysed" ]; then
    pass "(4) apk-database layer recorded 'analysed' (the scanner really ran; the abstention above is not a disabled backend)"
else
    fail "(4) apk-database layer must record 'analysed'" \
        "latest ScanCompleted for artifact-${BASE_LAYER_ID} carries assessment='${GOT_BASE:-<no ScanCompleted>}'. An apk database is an analysable surface; 'not_applicable' here means the fixture is no longer exercising the scanner and every other assertion in this file is vacuous."
fi

# ---------------------------------------------------------------------------
# (5) Release. The window -- not a scan verdict -- is what the layer's
# release waits on, so poll past it rather than asserting immediately.
# ADR 0064 D2 leaves ADR 0007's release predicate untouched: the layer
# still releases on its own `ScanCompleted` plus its own time gate.
# ---------------------------------------------------------------------------
log ""
log "--- (5) Awaiting release of the link-carrying layer (window ${WINDOW_SECS}s)"
if bounded_poll "link layer released" 240 \
        "[ \"\$(psql_one \"SELECT quarantine_status FROM artifacts WHERE id = '${LINK_LAYER_ID}';\")\" = 'released' ]" \
        5; then
    pass "(5) the link-carrying layer released"
else
    STATE="$(psql_one "SELECT COALESCE(quarantine_status::text,'null') FROM artifacts WHERE id = '${LINK_LAYER_ID}';")"
    fail "(5) the link-carrying layer must release once the window elapses" \
        "quarantine_status='${STATE:-<row gone>}' after 240s (window is ${WINDOW_SECS}s). 'quarantined' means no release authority was resolved; 'scan_indeterminate' means the abstention held the layer; 'rejected' means something condemned it, which no absence of assessment may do."
    summary
fi

# ---------------------------------------------------------------------------
# (6) THE assertion: the layer blob SERVES. Anonymously, because the
# repository is public and an authenticated fetch could not tell a released
# row from the write-authorized hold-read exemption -- and over HTTP,
# because the database agreeing the row is released is not the same claim
# as the registry handing a client the bytes. This is the request that
# answered 503 on the reported instance while the manifest naming it
# answered 200.
# ---------------------------------------------------------------------------
log ""
log "--- (6) ANONYMOUS GET the released layer blob by digest"
BLOB_CODE="$(curl -sS -o /dev/null -w '%{http_code}' \
    "${BLOB_URL_BASE}/sha256:${NEW_LAYER_HEX}" 2>/dev/null || echo 000)"
if [ "$BLOB_CODE" = "200" ]; then
    pass "(6) ANONYMOUS GET layer blob sha256:${NEW_LAYER_HEX} -> 200"
else
    fail "(6) ANONYMOUS GET the released layer blob -> 200" \
        "got HTTP ${BLOB_CODE} for ${BLOB_URL_BASE}/sha256:${NEW_LAYER_HEX}. 503 is the reported symptom: a layer hort will not serve, named by a manifest hort advertises. 401/404 instead means the repository stopped being public or the digest is not the one that was pushed."
fi

# ---------------------------------------------------------------------------
summary
