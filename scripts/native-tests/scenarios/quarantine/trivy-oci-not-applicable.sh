#!/usr/bin/env bash
# requires: db worker scanner egress
# A Trivy-policed OCI image releases: manifest + config record "not applicable", layers record verdicts.
#
# THE INVARIANT THIS PINS. Every OCI row is scanned on its own. A manifest
# row and a non-tar blob (the image config JSON) carry no package surface
# by construction — no scanner can ever find a threat level in them. While
# every abstention was treated alike, that was a fail-closed hold, and a
# hold with nothing to wait on never lifts: a Trivy-policed OCI repository
# held every image it ingested, forever. The unit tests prove the outcome
# partition; only an end-to-end push can prove the whole image becomes
# pullable, because that needs the real Trivy adapter to classify a real
# manifest, a real config blob and a real layer tarball.
#
# Fixture: `oci-trivy-e2e`, a PUBLIC hosted OCI repo with a
# `ScanPolicy { scanBackends: ["trivy"], enforcement: record,
# quarantineDuration: 20s }` (deploy/compose/example-config/
# {repositories,policies,auth,service-accounts}/*oci-trivy-e2e*). record
# mode means a Trivy verdict never gates the image, so the release
# assertions do not depend on which CVEs the base image carries today —
# only on whether each row got a completed assessment at all.
#
# Source image: a single-arch, single-layer Alpine. Single-layer matters:
# every layer has to become releasable for the pull to succeed, and an
# Alpine rootfs carries an apk database, which is the thing Trivy's
# `rootfs` target actually analyses. A layer with no package database
# would abstain with `no_analyzer_matched` — a genuine, still-correct
# fail-closed hold — and this scenario would (rightly) fail for a reason
# that is not what it is testing.
#
# ORDER OF THE LEGS IS LOAD-BEARING. The per-row digest resolution reads
# the manifest back over HTTP, and while the content is held that read is
# a 503 by design (that is the hold working). So the scenario waits the
# rows out through the database first, pulls once they are released, and
# only then maps digests to rows:
#
#   1. Push. The write path is ungated, so every row is ingested and held.
#   2. DB: three rows appear (1 manifest + 2 blobs) and every one of them
#      records a COMPLETED scan. `record_scan_indeterminate` does not
#      advance `last_scan_at`, so a row still NULL here took the hold path
#      — which is exactly the regression this scenario exists to catch.
#   3. DB: every row reaches `released` once the window elapses.
#   4. ANONYMOUS pull of the whole image. A released image must serve
#      without credentials; an authenticated pull could not tell a
#      released row from a read-authorized hold exemption.
#   5. Now that the content serves, read the manifest, map its config and
#      layer digests onto the rows, and assert the ASSESSMENT recorded for
#      each: manifest and config = `not_applicable`, layers = `analysed`.
#      This is the point of the whole item — a not-applicable row must
#      never read as "analysed, clean", and a layer must never read as
#      "not applicable".

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

# Single-arch, single-layer, apk-database-carrying source. See header.
SOURCE_IMAGE="${SOURCE_IMAGE:-alpine:3.19}"
TEST_IMAGE_NAME="${TEST_IMAGE_NAME:-trivyimg}"
TEST_TAG="${TEST_TAG:-v0}"

DEST_IMAGE="${REGISTRY_HOST}/${REPO_KEY}/${TEST_IMAGE_NAME}:${TEST_TAG}"
PULLED_ARCHIVE="/tmp/oci-trivy-pulled-${TEST_IMAGE_NAME}.tar"
RAW_MANIFEST_FILE="$(mktemp)"

# The policy's `quarantineDuration`. Kept as a variable so the waits below
# read as "the window plus scan turnaround", not as magic numbers.
WINDOW_SECS="${TRIVY_OCI_WINDOW_SECS:-20}"

# 1 manifest + 1 config blob + 1 layer blob. Asserted rather than assumed:
# a multi-layer or multi-arch source would silently change what the legs
# below are actually testing.
EXPECTED_ROWS="${TRIVY_OCI_EXPECTED_ROWS:-3}"

log "==> Trivy OCI not-applicable e2e"
log "registry : ${HORT_URL}"
log "repo     : ${REPO_KEY} (trivy ScanPolicy, ${WINDOW_SECS}s window, record mode)"
log "source   : ${SOURCE_IMAGE}"
log "dest     : ${DEST_IMAGE}"

trap 'rm -f "$PULLED_ARCHIVE" "$RAW_MANIFEST_FILE"' EXIT

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
# (1) Push. The write path is ungated by the quarantine hold, so this must
# succeed even though every ingested row lands `quarantined`.
# ---------------------------------------------------------------------------
log ""
log "--- (1) Push ${SOURCE_IMAGE} -> docker://${DEST_IMAGE}"
if skopeo copy \
        --insecure-policy \
        --dest-tls-verify=false \
        --dest-creds "$DEST_CREDS" \
        "docker://${SOURCE_IMAGE}" \
        "docker://${DEST_IMAGE}" 2>&1; then
    pass "(1) push to the Trivy-policed repo succeeded"
else
    fail "(1) push to the Trivy-policed repo" \
        "skopeo copy ${SOURCE_IMAGE} -> ${DEST_IMAGE} exited non-zero; is the source registry reachable?"
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
    fail "(2) the push must ingest exactly ${EXPECTED_ROWS} rows (manifest + config + layer)" \
        "found ${ROW_COUNT:-0} artifacts rows for repository_id='${REPO_ID}' -- a multi-layer or multi-arch ${SOURCE_IMAGE} changes what the legs below test; set TRIVY_OCI_EXPECTED_ROWS if that is intended."
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
        "artifacts.last_scan_at still NULL for: ${UNSCANNED:-<none>}. 'scan_indeterminate' here means the row took the fail-closed hold -- an artifact with no package surface must record a not-applicable assessment instead, and a layer must record a real verdict. Check the worker log for 'nothing to analyse'."
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

for pair in "manifest:${MANIFEST_ID}" "config:${CONFIG_ID}"; do
    what="${pair%%:*}"; aid="${pair#*:}"
    got="$(assessment_of "$aid")"
    if [ "$got" = "not_applicable" ]; then
        pass "(5) ${what} row recorded 'not_applicable' (a completed assessment with nothing to assess)"
    else
        fail "(5) ${what} row must record 'not_applicable'" \
            "latest ScanCompleted for artifact-${aid} carries assessment='${got:-<no ScanCompleted>}'. An OCI ${what} carries no package surface; recording it as 'analysed' would claim an examination that never happened."
    fi
done

for d in "${LAYER_DIGESTS[@]}"; do
    lid="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = 'blobs/${d}';")"
    if [ -z "$lid" ]; then
        fail "(5) layer row must be locatable" \
            "no artifacts row for repository_id='${REPO_ID}' path='blobs/${d}'"
        continue
    fi
    got="$(assessment_of "$lid")"
    if [ "$got" = "analysed" ]; then
        pass "(5) layer row ${lid} recorded 'analysed' (a real verdict)"
    else
        fail "(5) layer rows must still record a real verdict" \
            "latest ScanCompleted for artifact-${lid} carries assessment='${got:-<no ScanCompleted>}'. A layer rootfs IS analysable; 'not_applicable' here means the adapter stopped classifying layer content as a scannable surface."
    fi
done

# ---------------------------------------------------------------------------
summary
