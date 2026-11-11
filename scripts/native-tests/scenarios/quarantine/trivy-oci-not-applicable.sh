#!/usr/bin/env bash
# requires: db worker scanner egress
# A Trivy-policed OCI image releases: manifest records its composition's verdict, config + package-less layer "not applicable", attestation manifest neither.
#
# THE INVARIANT THIS PINS. Every OCI row records a completed assessment of
# its own, and the four rows of one image do not all record the same one —
# nor does the artifact manifest leg (6) pushes beside them.
# The manifest's is its COMPOSITION's: the config and the ordered layers
# are assembled into one image, handed to the scanner as one image, and
# that verdict is the manifest's (ADR 0064 D1, D2). So a manifest whose
# composition was assembled and examined records `analysed` — an image
# manifest is no longer on the "no package surface by construction" list,
# which is exactly what ADR 0064 took it off. A non-tar blob (the image
# config JSON) composes nothing and is not a layer, and a layer that
# carries files but no package database has no package surface of its own;
# those record `not_applicable`, and no scanner can ever find a threat
# level in either. While every abstention was treated alike, that was a
# fail-closed hold, and a hold with nothing to wait on never lifts: a
# Trivy-policed OCI repository held every image it ingested, forever. The
# unit tests prove the outcome partition; only an end-to-end push can prove
# the whole image becomes pullable, because that needs the real Trivy
# adapter to classify a real manifest, a real config blob and a real layer
# tarball.
#
# Fixture: `oci-trivy-e2e`, a PUBLIC hosted OCI repo with a
# `ScanPolicy { scanBackends: ["trivy"], enforcement: record,
# quarantineDuration: 20s }` (deploy/compose/example-config/
# {repositories,policies,auth,service-accounts}/*oci-trivy-e2e*). record
# mode means a Trivy verdict never gates the image, so the release
# assertions do not depend on which CVEs the base image carries today —
# only on whether each row got a completed assessment at all.
#
# Source image: a TWO-LAYER fixture built from a single-arch Alpine base
# plus one synthetic package-less layer appended locally (a lone
# certificate file, no package database — the shape a `ca-certificates`
# layer takes in a real multi-arch image such as `nginx:alpine`). A
# MULTI-LAYER source is load-bearing: every layer is still materialised
# and scanned as a root filesystem of its own, and still records a result
# of its own. (Not every analyzer runs over every layer — the OS-package
# analyzer is skipped on a tree carrying no OS marker, which is the
# measured gap ADR 0064 D1 closes by scanning the composed image — but
# each layer does get a result, and that is what this fixture needs.) A
# single-layer Alpine base can only ever exercise the "layer carries a
# package database" outcome; the defect this scenario pins is specific to
# the OTHER outcome — a layer that carries files but no package database
# at all, which every analyzer agrees has nothing to assess and which must
# record `not_applicable`, not the fail-closed `no_analyzer_matched` hold
# that used to apply there. A single-layer source cannot produce that
# second outcome, so the regression it caused (every multi-layer image
# holding forever) was invisible to it. The fixture is assembled in-process
# (`skopeo copy ... dir:`, then a synthetic layer + config edited in
# place) rather than pulling a real multi-layer image, so the layer count
# and contents are pinned and cannot drift out from under this scenario
# the way an upstream tag's shape can.
#
# ORDER OF THE LEGS IS LOAD-BEARING. The per-row digest resolution reads
# the manifest back over HTTP, and while the content is held that read is
# a 503 by design (that is the hold working). So the scenario waits the
# rows out through the database first, pulls once they are released, and
# only then maps digests to rows:
#
#   1. Assemble the two-layer fixture locally, then push it. The write
#      path is ungated, so every row is ingested and held.
#   2. DB: four rows appear (1 manifest + 1 config + 2 layers) and every
#      one of them records a COMPLETED scan. `record_scan_indeterminate`
#      does not advance `last_scan_at`, so a row still NULL here took the
#      hold path — which is exactly the regression this scenario exists
#      to catch.
#   3. DB: every row reaches `released` once the window elapses.
#   4. ANONYMOUS pull of the whole image. A released image must serve
#      without credentials; an authenticated pull could not tell a
#      released row from a read-authorized hold exemption.
#   5. Now that the content serves, read the manifest, map its config and
#      layer digests onto the rows, and assert the ASSESSMENT recorded for
#      each: the manifest = `analysed` (its composition was assembled and
#      examined), the config = `not_applicable`, the apk-database layer =
#      `analysed`, the package-less layer = `not_applicable`. This is the
#      point of the whole scenario — a row with nothing to assess must
#      never read as "analysed, clean", an assessed composition and an
#      analysable layer must never read as "not applicable", and a
#      package-less layer must never read as an unassessed hold.
#   6. The SIXTH row class, pushed last because it needs (5)'s manifest
#      digest as its index sibling: a BuildKit attestation manifest, whose
#      config is image-shaped and whose single layer is an in-toto
#      Statement. It must record a completed `not_applicable` assessment,
#      carry no `ScanIndeterminate`, record `nothing_to_compose` on the
#      composite axis, and release. See the leg's own header for the
#      production evidence of what it did instead.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

command -v skopeo >/dev/null 2>&1 || skip "skopeo not found in PATH"
command -v jq     >/dev/null 2>&1 || skip "jq not found in PATH"

REPO_KEY="${TRIVY_OCI_REPO_KEY:-oci-trivy-e2e}"
# Strip scheme so skopeo's docker:// transport gets host:port only.
REGISTRY_HOST="${HORT_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

# Single-arch, single-layer, apk-database-carrying base for the fixture.
# See header for why a second, package-less layer is appended locally.
SOURCE_IMAGE="${SOURCE_IMAGE:-alpine:3.19}"
TEST_IMAGE_NAME="${TEST_IMAGE_NAME:-trivyimg}"
TEST_TAG="${TEST_TAG:-v0}"

DEST_IMAGE="${REGISTRY_HOST}/${REPO_KEY}/${TEST_IMAGE_NAME}:${TEST_TAG}"
PULLED_ARCHIVE="/tmp/oci-trivy-pulled-${TEST_IMAGE_NAME}.tar"
RAW_MANIFEST_FILE="$(mktemp)"
FIXTURE_DIR="$(mktemp -d)"
BASE_LAYOUT="${FIXTURE_DIR}/base"

# The policy's `quarantineDuration`. Kept as a variable so the waits below
# read as "the window plus scan turnaround", not as magic numbers.
WINDOW_SECS="${TRIVY_OCI_WINDOW_SECS:-20}"

# 1 manifest + 1 config blob + 2 layer blobs (the apk-database base layer
# and the synthetic package-less layer). Asserted rather than assumed: a
# change to how the fixture is assembled would otherwise silently change
# what the legs below are actually testing.
EXPECTED_ROWS="${TRIVY_OCI_EXPECTED_ROWS:-4}"

log "==> Trivy OCI not-applicable e2e"
log "registry : ${HORT_URL}"
log "repo     : ${REPO_KEY} (trivy ScanPolicy, ${WINDOW_SECS}s window, record mode)"
log "source   : ${SOURCE_IMAGE} + one synthetic package-less layer"
log "dest     : ${DEST_IMAGE}"

trap 'rm -f "$PULLED_ARCHIVE" "$RAW_MANIFEST_FILE"; rm -rf "$FIXTURE_DIR"' EXIT

REPO_ID="$(psql_one "SELECT id FROM repositories WHERE key = '${REPO_KEY}' LIMIT 1;")"
[ -n "$REPO_ID" ] || skip "repositories row for key='${REPO_KEY}' absent — gitops apply has not run against this DB"
log "repository id=${REPO_ID}"

# -----------------------------------------------------------------------------
# Credential mode: legacy (Basic / IdP-JWT) vs native tokens. Mirrors
# scenarios/clients/oci-push-under-quarantine.sh — under the `native-tokens`
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
# (1a) Assemble the two-layer fixture locally: pull the Alpine base into an
# OCI `dir:` layout, then append one synthetic package-less layer (a lone
# certificate file) and fold its diff ID into the config. `dir:` lays each
# blob out as a plain file named by its hex digest plus a `manifest.json`,
# which is what makes editing it in place possible without a container
# build tool.
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

# The synthetic package-less layer: one certificate file, no package
# database at all -- the shape a `ca-certificates` layer takes in a real
# image, and the layer class no OS-package/language/binary analyzer can
# ever claim anything in.
LAYER_ROOT="${FIXTURE_DIR}/layer-root/usr/share/ca-certificates"
mkdir -p "$LAYER_ROOT"
cat > "${LAYER_ROOT}/hort-e2e-fixture.crt" <<'CERT'
-----BEGIN CERTIFICATE-----
hort e2e fixture -- not a real certificate, no package database nearby
-----END CERTIFICATE-----
CERT

LAYER_TAR="${FIXTURE_DIR}/pkgless-layer.tar"
LAYER_TAR_GZ="${FIXTURE_DIR}/pkgless-layer.tar.gz"
# `-C dir .` puts the archive's own root directory (`./`) in as the first
# entry, the shape every tar-based layer builder emits -- this scenario is
# the representative fixture for that producer shape, left as-is on purpose.
tar --numeric-owner --owner=0 --group=0 -cf "$LAYER_TAR" -C "${FIXTURE_DIR}/layer-root" .
NEW_DIFF_ID="sha256:$(sha256sum "$LAYER_TAR" | cut -d' ' -f1)"
gzip -c "$LAYER_TAR" > "$LAYER_TAR_GZ"
NEW_LAYER_HEX="$(sha256sum "$LAYER_TAR_GZ" | cut -d' ' -f1)"
NEW_LAYER_SIZE="$(stat -c%s "$LAYER_TAR_GZ")"
cp "$LAYER_TAR_GZ" "${BASE_LAYOUT}/${NEW_LAYER_HEX}"
log "  new layer   : sha256:${NEW_LAYER_HEX} (package-less)"

# Fold the new layer's diff ID into a copy of the base config -- this is
# the only edit that makes the appended layer part of the image's rootfs
# rather than an orphaned blob the manifest happens to also list.
NEW_CONFIG="${FIXTURE_DIR}/config.json"
jq --arg diffid "$NEW_DIFF_ID" \
   '.rootfs.diff_ids += [$diffid]
    | .history += [{"created": "1970-01-01T00:00:00Z",
                     "comment": "hort e2e fixture: package-less ca-certificates layer",
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
# (1b) Push the assembled two-layer fixture. The write path is ungated by
# the quarantine hold, so this must succeed even though every ingested row
# lands `quarantined`.
# ---------------------------------------------------------------------------
log ""
log "--- (1b) Push the two-layer fixture -> docker://${DEST_IMAGE}"
if skopeo copy \
        --insecure-policy \
        --dest-tls-verify=false \
        --dest-creds "$DEST_CREDS" \
        "dir:${BASE_LAYOUT}" \
        "docker://${DEST_IMAGE}" 2>&1; then
    pass "(1) push of the two-layer fixture to the Trivy-policed repo succeeded"
else
    fail "(1) push of the two-layer fixture to the Trivy-policed repo" \
        "skopeo copy dir:${BASE_LAYOUT} -> ${DEST_IMAGE} exited non-zero"
    summary
fi

# ---------------------------------------------------------------------------
# (2) Every ingested row must record a COMPLETED scan. Read through the
# database, not over HTTP: the content is held at this point and a manifest
# GET is a 503 by design.
# ---------------------------------------------------------------------------
log ""
log "--- (2) Awaiting a completed scan for all ${EXPECTED_ROWS} rows"
ROW_COUNT="$(psql_one "SELECT count(*) FROM artifacts WHERE repository_id = '${REPO_ID}';")"
if [ "${ROW_COUNT:-0}" -ne "$EXPECTED_ROWS" ]; then
    fail "(2) the push must ingest exactly ${EXPECTED_ROWS} rows (manifest + config + 2 layers)" \
        "found ${ROW_COUNT:-0} artifacts rows for repository_id='${REPO_ID}' -- an unexpected fixture shape changes what the legs below test; set TRIVY_OCI_EXPECTED_ROWS if that is intended."
    summary
fi
pass "(2) ${EXPECTED_ROWS} rows ingested"

if bounded_poll "all rows scanned" 240 \
        "[ \"\$(psql_one \"SELECT count(*) FROM artifacts WHERE repository_id = '${REPO_ID}' AND last_scan_at IS NULL;\")\" = '0' ]" \
        5; then
    pass "(2) every row recorded a completed scan"
else
    UNSCANNED="$(psql_one "SELECT string_agg(path || '=' || COALESCE(quarantine_status::text,'null'), ' ') FROM artifacts WHERE repository_id = '${REPO_ID}' AND last_scan_at IS NULL;")"
    fail "(2) every OCI row must record a completed scan within 240s" \
        "artifacts.last_scan_at still NULL for: ${UNSCANNED:-<none>}. 'scan_indeterminate' here means the row took the fail-closed hold -- a row with nothing to assess (the config blob, the package-less layer) must record a not-applicable assessment instead, the apk-database layer must record a real verdict, and the manifest must record its composition's. Check the worker log for 'nothing to analyse', and for 'composite scan' if the NULL row is the manifest."
    summary
fi

# ---------------------------------------------------------------------------
# (3) Release. The window — not a scan verdict — is what the release waits
# on, so poll past it rather than asserting immediately.
# ---------------------------------------------------------------------------
log ""
log "--- (3) Awaiting release of every row (window ${WINDOW_SECS}s)"
if bounded_poll "all rows released" 240 \
        "[ \"\$(psql_one \"SELECT count(*) FROM artifacts WHERE repository_id = '${REPO_ID}' AND quarantine_status IS DISTINCT FROM 'released';\")\" = '0' ]" \
        5; then
    pass "(3) every row released"
else
    HELD="$(psql_one "SELECT string_agg(path || '=' || COALESCE(quarantine_status::text,'null'), ' ') FROM artifacts WHERE repository_id = '${REPO_ID}' AND quarantine_status IS DISTINCT FROM 'released';")"
    fail "(3) every row must release once the window elapses" \
        "still not released after 240s (window is ${WINDOW_SECS}s): ${HELD:-<none>}. 'quarantined' means no release authority was resolved; 'scan_indeterminate' means the row took the fail-closed hold."
    summary
fi

# ---------------------------------------------------------------------------
# (4) Anonymous pull. The repository is public and every row is released, so
# the image must serve with no credentials at all.
# ---------------------------------------------------------------------------
log ""
log "--- (4) Anonymous pull ${DEST_IMAGE} -> oci-archive"
if skopeo copy \
        --insecure-policy \
        --src-tls-verify=false \
        "docker://${DEST_IMAGE}" \
        "oci-archive:${PULLED_ARCHIVE}" 2>&1; then
    pass "(4) anonymous pull of the released image succeeded"
else
    fail "(4) anonymous pull of the released image" \
        "skopeo copy docker://${DEST_IMAGE} -> oci-archive exited non-zero. A 503 on a blob or the manifest means that row is still held despite (3)."
fi

# ---------------------------------------------------------------------------
# (5) The assessment recorded for each row. This is the honest trail: a zero
# finding_count alone cannot tell "examined and clean" from "nothing to
# examine", which is exactly what the event field records.
#
# `events.event_data` is the typed envelope `{"type": …, "data": {fields}}`,
# so the payload field is reached through `->'data'`. The default assessment
# is deliberately NOT written to the wire (writing it would change the
# canonical bytes of every event appended before the field existed and break
# the tamper-evident chain), so an absent key means `analysed` — which is
# also how every pre-release event reads.
#
# That default is also why the manifest's expectation below is a real
# assertion and not a tautology. A manifest's own bytes abstain
# non-gatingly on every run, so the only way its `ScanCompleted` reads
# `analysed` is the COMPOSITION's verdict having been folded into the same
# bookkeeping a backend's answer goes into; the value this discriminates
# against is the `not_applicable` the same row recorded before ADR 0064,
# written explicitly. And an absent `ScanCompleted` is not the default
# either — the read returns nothing and the assertion fails saying so,
# with (2) having already established that a completed scan exists.
# ---------------------------------------------------------------------------
log ""
log "--- (5) Recorded assessment per row"
# `--raw` fetches only the manifest bytes; anonymous, now that it serves.
if ! skopeo inspect --raw --tls-verify=false "docker://${DEST_IMAGE}" \
        > "$RAW_MANIFEST_FILE" 2>/dev/null || [ ! -s "$RAW_MANIFEST_FILE" ]; then
    fail "(5) read back the released manifest" \
        "skopeo inspect --raw returned nothing for ${DEST_IMAGE}"
    summary
fi

# The manifest artifact is stored at `manifests/<digest>`, and the digest is
# SHA-256 over the exact bytes — hence the file rather than a shell variable,
# which would strip a trailing newline.
MANIFEST_DIGEST="sha256:$(sha256sum < "$RAW_MANIFEST_FILE" | cut -d' ' -f1)"
CONFIG_DIGEST="$(jq -r '.config.digest // empty' < "$RAW_MANIFEST_FILE")"
mapfile -t LAYER_DIGESTS < <(jq -r '.layers[]?.digest // empty' < "$RAW_MANIFEST_FILE")
if [ -z "$CONFIG_DIGEST" ] || [ "${#LAYER_DIGESTS[@]}" -eq 0 ]; then
    fail "(5) the manifest must name a config and at least one layer" \
        "config='${CONFIG_DIGEST:-<none>}' layers=${#LAYER_DIGESTS[@]} -- is ${SOURCE_IMAGE} an index rather than an image manifest? This scenario pushes a single-arch image on purpose."
    summary
fi
log "  manifest: ${MANIFEST_DIGEST}"
log "  config  : ${CONFIG_DIGEST}"
log "  layers  : ${LAYER_DIGESTS[*]}"

MANIFEST_ID="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = 'manifests/${MANIFEST_DIGEST}';")"
if [ -z "$MANIFEST_ID" ]; then
    # Fall back to the repository's only manifest row: the digest is over
    # the exact served bytes, and a re-encode should not turn into an
    # unexplained miss.
    log "  (no row at manifests/${MANIFEST_DIGEST} — falling back to the repository's newest manifest row)"
    MANIFEST_ID="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path LIKE 'manifests/%' ORDER BY created_at DESC LIMIT 1;")"
fi
CONFIG_ID="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = 'blobs/${CONFIG_DIGEST}';")"
if [ -z "$MANIFEST_ID" ] || [ -z "$CONFIG_ID" ]; then
    fail "(5) manifest and config rows must be locatable" \
        "manifest id='${MANIFEST_ID:-<none>}' config id='${CONFIG_ID:-<none>}' for repository_id='${REPO_ID}'"
    summary
fi

assessment_of() {
    psql_one "SELECT COALESCE(event_data->'data'->>'assessment', 'analysed')
              FROM events
              WHERE stream_id = 'artifact-${1}' AND event_type = 'ScanCompleted'
              ORDER BY stream_position DESC LIMIT 1;"
}

# One assert for every row below, because three structurally identical
# blocks is where this file would start duplicating itself. `why` is the
# per-row half: what the expectation follows from, which is a different
# statement for each of the four rows.
assert_assessment() {
    local what="$1" aid="$2" expected="$3" why="$4" got
    got="$(assessment_of "$aid")"
    if [ "$got" = "$expected" ]; then
        pass "(5) ${what} recorded '${got}' as expected"
    else
        fail "(5) ${what} must record '${expected}'" \
            "latest ScanCompleted for artifact-${aid} carries assessment='${got:-<no ScanCompleted>}'. ${why}"
    fi
}

# The manifest and its config land on OPPOSITE sides of the split, and for
# different reasons, so each carries its own expectation and its own
# reason rather than sharing one.
assert_assessment "manifest row" "$MANIFEST_ID" "analysed" \
    "An image manifest's assessment is its COMPOSITION's (ADR 0064 D1, D2): the config and the ordered layers are assembled into one image and handed to the scanner, so a manifest whose composition was assembled and examined records 'analysed'. This fixture's composition is a two-layer Alpine image with an apk database -- genuinely assessable. A composition that was REFUSED never reaches here, because its absence gates the manifest and (2) fails first; 'not_applicable' at this point therefore means the resolution decided this manifest is not a composed image at all. Check the worker log for 'composite scan: this manifest is not a composed image'."
assert_assessment "config row" "$CONFIG_ID" "not_applicable" \
    "An image config blob composes nothing and is not a layer, so no scanner can ever find a threat level in it; recording it as 'analysed' would claim an examination that never happened."

# The two layers must land on OPPOSITE sides of the assessment split, so
# each is matched against the digest it is known to be (captured while
# assembling the fixture in (1a)) rather than by position -- this is what
# actually distinguishes "the apk-database layer stayed analysable" from
# "the package-less layer stopped being held".
if [ "${#LAYER_DIGESTS[@]}" -ne 2 ]; then
    fail "(5) the manifest must name exactly 2 layers" \
        "found ${#LAYER_DIGESTS[@]}: ${LAYER_DIGESTS[*]:-<none>}"
fi
for d in "${LAYER_DIGESTS[@]}"; do
    lid="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = 'blobs/${d}';")"
    if [ -z "$lid" ]; then
        fail "(5) layer row must be locatable" \
            "no artifacts row for repository_id='${REPO_ID}' path='blobs/${d}'"
        continue
    fi
    if [ "$d" = "$BASE_LAYER_DIGEST" ]; then
        label="apk-database base layer"
        expected="analysed"
        why="An apk database is an analysable surface; 'not_applicable' here means the fixture is no longer exercising the scanner and the split this leg asserts is vacuous."
    elif [ "$d" = "sha256:${NEW_LAYER_HEX}" ]; then
        label="package-less (ca-certificate) layer"
        expected="not_applicable"
        why="A layer carrying files but no package database has nothing for an analyzer to assess; 'analysed' would claim an examination that never happened, and a missing ScanCompleted means it took the fail-closed hold instead."
    else
        fail "(5) unrecognised layer digest ${d}" \
            "matches neither the base layer (${BASE_LAYER_DIGEST}) nor the synthetic layer (sha256:${NEW_LAYER_HEX})"
        continue
    fi
    assert_assessment "$label" "$lid" "$expected" "$why"
done


# ---------------------------------------------------------------------------
# (6) THE SIXTH ROW CLASS: AN INDEX CHILD THAT WAS NEVER AN IMAGE.
#
# A BuildKit attestation manifest -- the SLSA-provenance sibling every
# multi-arch index `docker buildx` produces binds beside its platform
# children. It is an OCI ARTIFACT manifest: its single layer is an in-toto
# Statement (`application/vnd.in-toto+json`), a JSON document and not a
# filesystem changeset.
#
# WHY IT NEEDS ITS OWN LEG RATHER THAN BEING COVERED BY (5). Every other
# artifact manifest in this suite -- a cosign signature, an SBOM
# attachment, a Helm chart -- says "I am not an image" in its CONFIG, which
# declares no layered root filesystem. This one does not: BuildKit
# synthesises an IMAGE-SHAPED config for it, `rootfs.type: layers` with one
# `diff_id` for its one layer. So the config is read, passes the
# layered-rootfs check AND the arity check, and the only statement in
# either document that this was never an image is the layer's declared
# payload format. A fixture whose config gives the answer cannot see this,
# which is how it survived seven green slices of the initiative.
#
# WHAT IT LOOKED LIKE WHEN IT DID NOT WORK, from a compose run of a
# pull-through `redis:7-alpine`: eight manifest rows terminally
# `scan_indeterminate`, their scan jobs `completed` with `attempts=1` and an
# empty `last_error`, their `ScanIndeterminate` reason
# `trivy=not_applicable,composite=incomplete_composition`, and a
# `composite_scan_observations` row each reading
# `assessment=deterministic_refusal` with "layers[0] declares a container
# the composition cannot be described with: application/vnd.in-toto+json".
# The composite had said INCOMPLETE COMPOSITION -- a runnable image hort
# holds only part of -- about a manifest that was never an image, and an
# absent filesystem verdict is what the release gate fails closed on. A
# rescan reproduces it exactly, so nothing lifts that hold.
#
# WHY THE FIXTURE IS ASSEMBLED HERE RATHER THAN PROXIED. A real BuildKit
# image would do, and would also pin this scenario to whatever an upstream
# tag's attestation shape is on the day the suite runs. Building the three
# documents locally pins the one property under test -- an image-shaped
# config over a non-filesystem layer -- and makes the leg independent of
# egress to any particular registry.
#
# WHAT IS DELIBERATELY NOT KEYED ON. The index entry carries
# `platform: unknown/unknown` and the
# `vnd.docker.reference.type=attestation-manifest` annotation, and both are
# written here because BuildKit writes them. Neither may be what hort
# decides on: a composition is resolved from a manifest row's own bytes and
# its config (ADR 0064 D1), and the index descriptor that referenced it is
# not an input -- a child manifest is a scan unit whether or not an index in
# this registry still names it. They are in the fixture so that a future
# shortcut on either one is still looking at the real shape.
# ---------------------------------------------------------------------------
log ""
log "--- (6) A BuildKit attestation manifest as an index child"

ATT_DIR="${FIXTURE_DIR}/attestation"
mkdir -p "$ATT_DIR"

# -- the three documents, byte-exact: each is hashed and PUT from the same file.

# The in-toto Statement the attestation carries, binding the image manifest
# pushed in (1b) as its subject -- the real shape, so nothing here depends on
# the payload being degenerate.
jq -n --arg subject "${MANIFEST_DIGEST#sha256:}" \
   '{"_type": "https://in-toto.io/Statement/v0.1",
     "predicateType": "https://slsa.dev/provenance/v0.2",
     "subject": [{"name": "hort-e2e-fixture", "digest": {"sha256": $subject}}],
     "predicate": {"buildType": "https://mobyproject.org/buildkit@v1"}}' \
   > "${ATT_DIR}/payload.json"
ATT_LAYER_HEX="$(sha256sum "${ATT_DIR}/payload.json" | cut -d' ' -f1)"
ATT_LAYER_SIZE="$(stat -c%s "${ATT_DIR}/payload.json")"

# The image-shaped config BuildKit synthesises for an attestation manifest.
# `rootfs.type: layers` plus exactly one `diff_id` for exactly one layer is
# what makes both config-side checks PASS -- the property that put these rows
# on the fail-closed arm.
jq -n --arg diffid "sha256:${ATT_LAYER_HEX}" \
   '{"architecture": "unknown", "os": "unknown", "config": {},
     "rootfs": {"type": "layers", "diff_ids": [$diffid]},
     "history": [{"created": "1970-01-01T00:00:00Z"}]}' \
   > "${ATT_DIR}/config.json"
ATT_CONFIG_HEX="$(sha256sum "${ATT_DIR}/config.json" | cut -d' ' -f1)"
ATT_CONFIG_SIZE="$(stat -c%s "${ATT_DIR}/config.json")"

OCI_MANIFEST_MEDIA="application/vnd.oci.image.manifest.v1+json"
IN_TOTO_MEDIA="application/vnd.in-toto+json"
OCI_INDEX_MEDIA="application/vnd.oci.image.index.v1+json"

jq -n --arg cfgdigest "sha256:${ATT_CONFIG_HEX}" --argjson cfgsize "$ATT_CONFIG_SIZE" \
   --arg ldigest "sha256:${ATT_LAYER_HEX}" --argjson lsize "$ATT_LAYER_SIZE" \
   --arg mt "$OCI_MANIFEST_MEDIA" --arg lmt "$IN_TOTO_MEDIA" \
   '{"schemaVersion": 2, "mediaType": $mt,
     "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": $cfgdigest, "size": $cfgsize},
     "layers": [{"mediaType": $lmt, "digest": $ldigest, "size": $lsize,
                 "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2"}}]}' \
   > "${ATT_DIR}/manifest.json"
ATT_MANIFEST_HEX="$(sha256sum "${ATT_DIR}/manifest.json" | cut -d' ' -f1)"
ATT_MANIFEST_SIZE="$(stat -c%s "${ATT_DIR}/manifest.json")"
log "  attestation manifest: sha256:${ATT_MANIFEST_HEX}"
log "  in-toto payload     : sha256:${ATT_LAYER_HEX} (${IN_TOTO_MEDIA})"

# The index that binds both children -- the image manifest from (1b) and the
# attestation manifest above. The image child's digest and size are the
# SERVED bytes read back in (5), which are the bytes hort stored.
IMAGE_MANIFEST_MEDIA="$(jq -r '.mediaType // empty' < "$RAW_MANIFEST_FILE")"
[ -n "$IMAGE_MANIFEST_MEDIA" ] || IMAGE_MANIFEST_MEDIA="$OCI_MANIFEST_MEDIA"
IMAGE_MANIFEST_SIZE="$(stat -c%s "$RAW_MANIFEST_FILE")"
jq -n --arg imt "$IMAGE_MANIFEST_MEDIA" --arg idigest "$MANIFEST_DIGEST" \
   --argjson isize "$IMAGE_MANIFEST_SIZE" \
   --arg amt "$OCI_MANIFEST_MEDIA" --arg adigest "sha256:${ATT_MANIFEST_HEX}" \
   --argjson asize "$ATT_MANIFEST_SIZE" --arg xmt "$OCI_INDEX_MEDIA" \
   '{"schemaVersion": 2, "mediaType": $xmt,
     "manifests": [
       {"mediaType": $imt, "digest": $idigest, "size": $isize,
        "platform": {"architecture": "amd64", "os": "linux"}},
       {"mediaType": $amt, "digest": $adigest, "size": $asize,
        "platform": {"architecture": "unknown", "os": "unknown"},
        "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                        "vnd.docker.reference.digest": $idigest}}]}' \
   > "${ATT_DIR}/index.json"
ATT_INDEX_HEX="$(sha256sum "${ATT_DIR}/index.json" | cut -d' ' -f1)"

# -- credentials for the raw pushes. skopeo negotiated its own transport in
# (1b); curl does not, so under the `native-tokens` overlay these need an
# already-minted capability JWT scoped to this image (mirrors
# quarantine/oci-image-index.sh's mint_cap_jwt). Legacy mode: Basic, as (1b).
OCI_AUTH=()
if [ "$NATIVE_TOKENS" = "1" ]; then
    PUSH_BEARER="$(curl -sS -u "${REPO_KEY}-ci:${SVC_TOKEN}" \
        "${HORT_URL}/v2/auth?service=${REGISTRY_HOST}&scope=repository:${REPO_KEY}/${TEST_IMAGE_NAME}:pull,push" \
        2>/dev/null | jq -r '.token // empty')"
    if [ -z "$PUSH_BEARER" ]; then
        fail "(6) mint a push-scoped capability JWT" \
            "GET /v2/auth (Basic <svc-token>, scope repository:${REPO_KEY}/${TEST_IMAGE_NAME}:pull,push) returned no token"
        summary
    fi
    OCI_AUTH=(-H "Authorization: Bearer ${PUSH_BEARER}")
else
    OCI_AUTH=(-u "$DEST_CREDS")
fi

# push_blob <hex> <file> — OCI monolithic blob upload (one request, digest
# declared up front; mirrors scenarios/storage/s3-multipart-blob.sh).
push_blob() {
    curl -sS -o /dev/null -w '%{http_code}' -X POST "${OCI_AUTH[@]}" \
        -H 'Content-Type: application/octet-stream' \
        --data-binary "@$2" \
        "${HORT_URL}/v2/${REPO_KEY}/${TEST_IMAGE_NAME}/blobs/uploads/?digest=sha256:$1" \
        2>/dev/null || echo 000
}

# put_manifest <reference> <file> <content-type>
put_manifest() {
    curl -sS -o /dev/null -w '%{http_code}' -X PUT "${OCI_AUTH[@]}" \
        -H "Content-Type: $3" --data-binary "@$2" \
        "${HORT_URL}/v2/${REPO_KEY}/${TEST_IMAGE_NAME}/manifests/$1" \
        2>/dev/null || echo 000
}

# Blobs first, manifest last -- the distribution spec's push order, and the
# order hort's membership-claim resolution requires.
for pair in "${ATT_LAYER_HEX}:${ATT_DIR}/payload.json" "${ATT_CONFIG_HEX}:${ATT_DIR}/config.json"; do
    hex="${pair%%:*}"; file="${pair#*:}"
    code="$(push_blob "$hex" "$file")"
    if [ "$code" != "201" ]; then
        fail "(6) push the attestation's $(basename "$file") blob" \
            "POST /v2/${REPO_KEY}/${TEST_IMAGE_NAME}/blobs/uploads/?digest=sha256:${hex} returned HTTP ${code}, expected 201"
        summary
    fi
done
pass "(6) the in-toto payload and the attestation config pushed as blobs"

ATT_PUT="$(put_manifest "sha256:${ATT_MANIFEST_HEX}" "${ATT_DIR}/manifest.json" "$OCI_MANIFEST_MEDIA")"
if [ "$ATT_PUT" = "201" ]; then
    pass "(6) the attestation manifest PUT was accepted (an artifact manifest is pushable)"
else
    fail "(6) PUT the attestation manifest" \
        "PUT /manifests/sha256:${ATT_MANIFEST_HEX} returned HTTP ${ATT_PUT}, expected 201. A 400 MANIFEST_INVALID here means the admission gate refused an OCI artifact manifest whose layer is an in-toto Statement -- which is a push-path regression, not the scan-path one this leg is about."
    summary
fi

IDX_PUT="$(put_manifest "${TEST_TAG}-idx" "${ATT_DIR}/index.json" "$OCI_INDEX_MEDIA")"
if [ "$IDX_PUT" = "201" ]; then
    pass "(6) the index binding both children PUT was accepted"
else
    fail "(6) PUT the index binding the image and the attestation manifest" \
        "PUT /manifests/${TEST_TAG}-idx returned HTTP ${IDX_PUT}, expected 201. A 404 MANIFEST_BLOB_UNKNOWN means a child descriptor did not match a stored row: the image child is declared as ${MANIFEST_DIGEST} size ${IMAGE_MANIFEST_SIZE}, read back from the served manifest in (5)."
    summary
fi

# The fixture shape, pinned: four new rows -- the in-toto payload blob, the
# attestation config blob, the attestation manifest and the index.
ATT_EXPECTED_ROWS=$(( EXPECTED_ROWS + 4 ))
ROW_COUNT_6="$(psql_one "SELECT count(*) FROM artifacts WHERE repository_id = '${REPO_ID}';")"
if [ "${ROW_COUNT_6:-0}" -eq "$ATT_EXPECTED_ROWS" ]; then
    pass "(6) ${ATT_EXPECTED_ROWS} rows ingested (the image's ${EXPECTED_ROWS} plus the attestation's 4)"
else
    fail "(6) the attestation push must ingest exactly 4 more rows" \
        "found ${ROW_COUNT_6:-0} artifacts rows for repository_id='${REPO_ID}', expected ${ATT_EXPECTED_ROWS} -- an unexpected fixture shape changes what the assertions below test."
fi

ATT_ID="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = 'manifests/sha256:${ATT_MANIFEST_HEX}';")"
IDX_ID="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = 'manifests/sha256:${ATT_INDEX_HEX}';")"
if [ -z "$ATT_ID" ] || [ -z "$IDX_ID" ]; then
    fail "(6) the attestation manifest and index rows must be locatable" \
        "attestation id='${ATT_ID:-<none>}' index id='${IDX_ID:-<none>}' for repository_id='${REPO_ID}'"
    summary
fi
log "  attestation manifest row: ${ATT_ID}"
log "  index row               : ${IDX_ID}"

# ---- (6a) a completed scan, which is the half that used to be absent -----
if bounded_poll "attestation rows scanned" 240 \
        "[ \"\$(psql_one \"SELECT count(*) FROM artifacts WHERE id IN ('${ATT_ID}','${IDX_ID}') AND last_scan_at IS NULL;\")\" = '0' ]" \
        5; then
    pass "(6a) the attestation manifest and the index both recorded a completed scan"
else
    ATT_STATE="$(psql_one "SELECT string_agg(path || '=' || COALESCE(quarantine_status::text,'null'), ' ') FROM artifacts WHERE id IN ('${ATT_ID}','${IDX_ID}') AND last_scan_at IS NULL;")"
    fail "(6a) an attestation manifest must record a completed scan within 240s" \
        "artifacts.last_scan_at still NULL for: ${ATT_STATE:-<none>}. 'scan_indeterminate' here IS the regression: the composite resolution called this manifest an incomplete composition of a runnable image instead of an artifact manifest, and an absent filesystem verdict holds the row with nothing to wait for. Check the worker log for 'composite scan' on this artifact id, and the ScanIndeterminate event's reason for 'composite=incomplete_composition'."
    summary
fi

# ---- (6b) no hold: the event the eight rows carried is absent ------------
ATT_INDETERMINATE="$(psql_one "SELECT count(*) FROM events WHERE stream_id = 'artifact-${ATT_ID}' AND event_type = 'ScanIndeterminate';")"
if [ "${ATT_INDETERMINATE:-1}" = "0" ]; then
    pass "(6b) no ScanIndeterminate on the attestation manifest's stream (no hold)"
else
    ATT_REASON="$(psql_one "SELECT event_data->'data'->>'reason' FROM events WHERE stream_id = 'artifact-${ATT_ID}' AND event_type = 'ScanIndeterminate' ORDER BY stream_position DESC LIMIT 1;")"
    fail "(6b) an attestation manifest must not be held scan_indeterminate" \
        "${ATT_INDETERMINATE} ScanIndeterminate event(s) on stream artifact-${ATT_ID}, latest reason='${ATT_REASON:-<none>}'. A reason containing 'composite=incomplete_composition' is the exact defect: the composition was refused as an image rather than recognised as an artifact manifest."
fi

# ---- (6c) the assessment each row recorded -------------------------------
assert_assessment "attestation manifest row" "$ATT_ID" "not_applicable" \
    "An attestation manifest binds an in-toto Statement, not a root filesystem, so there is no composition for the composite axis to assess and the manifest's own bytes carry no package surface. 'analysed' would claim a composition was assembled and examined; no ScanCompleted at all means the row took the fail-closed hold that (6b) checks for."
assert_assessment "index row" "$IDX_ID" "not_applicable" \
    "An image index binds references, not a runnable filesystem (ADR 0064 D5), so each child is its own scan unit and the index itself has nothing to compose."

# ---- (6d) and the composite's own record of why --------------------------
# The verdict the composite contributed is `Withheld`, and this row is where
# that is readable: `nothing_to_compose` is the assessment whose verdict is
# withheld, and `deterministic_refusal` is the one that holds. The eight rows
# in evidence carried the second.
ATT_COMPOSITE="$(psql_one "SELECT assessment FROM composite_scan_observations WHERE artifact_id = '${ATT_ID}';")"
if [ "$ATT_COMPOSITE" = "nothing_to_compose" ]; then
    pass "(6d) the composite observation records 'nothing_to_compose' (verdict withheld)"
else
    ATT_COMPOSITE_REASON="$(psql_one "SELECT reason FROM composite_scan_observations WHERE artifact_id = '${ATT_ID}';")"
    fail "(6d) the composite observation must record 'nothing_to_compose'" \
        "composite_scan_observations.assessment='${ATT_COMPOSITE:-<no row>}' reason='${ATT_COMPOSITE_REASON:-<none>}' for artifact_id='${ATT_ID}'. 'deterministic_refusal' is the arm the eight held manifests landed on, and its reason named the in-toto media type as a container the composition could not be described with."
fi

# ---- (6e) and the end state: it releases on the window ------------------
if bounded_poll "attestation rows released" 240 \
        "[ \"\$(psql_one \"SELECT count(*) FROM artifacts WHERE id IN ('${ATT_ID}','${IDX_ID}') AND quarantine_status IS DISTINCT FROM 'released';\")\" = '0' ]" \
        5; then
    pass "(6e) the attestation manifest and the index both released once the window elapsed"
else
    ATT_HELD="$(psql_one "SELECT string_agg(path || '=' || COALESCE(quarantine_status::text,'null'), ' ') FROM artifacts WHERE id IN ('${ATT_ID}','${IDX_ID}') AND quarantine_status IS DISTINCT FROM 'released';")"
    fail "(6e) an attestation manifest must release once its window elapses" \
        "still not released after 240s (window is ${WINDOW_SECS}s): ${ATT_HELD:-<none>}. 'scan_indeterminate' is the terminal hold this leg exists to catch; 'quarantined' means no release authority was resolved at all."
fi

# ---------------------------------------------------------------------------
summary
