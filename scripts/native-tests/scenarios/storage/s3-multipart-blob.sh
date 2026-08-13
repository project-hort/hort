#!/usr/bin/env bash
# requires: compose:s3
#
# S3/Garage large-blob round-trip: push a blob strictly larger than
# MIN_PART_SIZE (5 MiB), pull it back, assert the SHA-256 digest round-trips
# byte-for-byte.
#
# ---------------------------------------------------------------------------
# WHY 8 MiB, AND WHY IT MUST STAY ABOVE 5 MiB — DO NOT "OPTIMISE" THIS DOWN.
# ---------------------------------------------------------------------------
# `ObjectStoreStorage::put` (crates/hort-adapters-storage/src/object_store_backend.rs)
# ALWAYS drives the object_store multipart API (`put_multipart` -> N x
# `put_part` -> `complete`), even for a 1-byte blob — a small blob just
# yields exactly ONE `put_part` call (the trailing flush after a loop that
# never filled a full part). The thing that is genuinely S3-backend-specific
# — the thing this scenario exists to cover — is a blob that forces MORE
# THAN ONE `put_part` call: `MIN_PART_SIZE` is a hardcoded 5 MiB
# (object_store_backend.rs's `MIN_PART_SIZE` constant), and the accumulator
# only flushes an interior part once it reaches that size
# (`part_buf.len() >= MIN_PART_SIZE`), with any remainder flushed as a final
# part after the read loop ends.
#
# So the boundary is size STRICTLY GREATER than 5 MiB:
#   - exactly 5 MiB: the read loop's `>= MIN_PART_SIZE` check fires right as
#     the buffer reaches 5 MiB, uploads it as the one-and-only part, and the
#     final flush is empty (0 remaining bytes) -- still only ONE `put_part`
#     call, i.e. NOT the genuinely divergent path.
#   - > 5 MiB (this scenario uses 8 MiB): the interior flush uploads part 1
#     (5 MiB) mid-loop, and the loop's remainder (3 MiB) is uploaded as part
#     2 after the loop -- TWO `put_part` calls, a real multi-part sequence
#     (matches crates/hort-adapters-storage/tests/s3_multipart.rs's own
#     "at least 2 put_part calls plus a final partial part" framing).
# Any blob at or below 5 MiB silently reduces this scenario to exercising
# the exact same single-`put_part` path every OTHER scenario's small
# fixtures already cover on every backend — it would stop testing anything
# S3-specific. 8 MiB (not e.g. 5 MiB + 1 byte) is a comfortable margin above
# the boundary while staying small enough to keep the smoke fast.
#
# ---------------------------------------------------------------------------
# WHY A RAW BLOB PUSH/PULL, NOT A FULL skopeo IMAGE COPY.
# ---------------------------------------------------------------------------
# `StoragePort::put` is invoked identically regardless of what OCI construct
# the bytes belong to (layer, config, or a manifest referenced by neither) --
# ADR 0006's CAS guarantee is content-hash-addressed, not shape-addressed.
# A raw OCI monolithic blob push (`POST .../blobs/uploads/?digest=sha256:...`
# with the entire body in one request -- crates/hort-http-oci/src/uploads.rs
# `handle_monolithic`) streams straight into the same `IngestUseCase::ingest_verified`
# -> `StoragePort::put` path a `skopeo copy` layer push would, without the
# extra moving parts (constructing a synthetic OCI image layout, a manifest,
# a config blob) that add nothing to what this scenario is verifying.
#
# ---------------------------------------------------------------------------
# EVIDENCE THIS EXERCISES MULTIPART, NOT JUST "IT PASSED": this scenario
# cannot see hort-server's own logs (different container). To confirm the
# server actually took the 2-part path (not merely that the digest matched,
# which a single-part path would also satisfy), inspect the server's debug
# log for two "part uploaded" lines from this push:
#   docker compose -f deploy/compose/docker-compose.yml \
#                   -f deploy/compose/docker-compose.s3.yml \
#     logs hort-server | grep 'part uploaded'
# (requires RUST_LOG=hort_adapters_storage=debug, already set for
# hort-adapters-storage in the base compose file's hort-server RUST_LOG.)

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

REPO_KEY="oci-s3-e2e"
IMAGE_NAME="${IMAGE_NAME:-bigblob}"
BLOB_MIB=8

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
BLOB_FILE="${WORK_DIR}/blob.bin"
PULLED_FILE="${WORK_DIR}/pulled.bin"
HEADERS_FILE="${WORK_DIR}/push_headers.txt"

log "==> S3/Garage large-blob multipart round-trip"
log "Registry:  ${HORT_URL}"
log "Repo key:  ${REPO_KEY}"
log "Blob size: ${BLOB_MIB} MiB (> 5 MiB MIN_PART_SIZE -- forces a genuine multi-part upload; see header comment)"

dd if=/dev/urandom of="$BLOB_FILE" bs=1M count="$BLOB_MIB" status=none
BLOB_HASH="$(sha256sum "$BLOB_FILE" | awk '{print $1}')"
log "  blob sha256: ${BLOB_HASH}"

DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"

UPLOAD_URL="${HORT_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/uploads/?digest=sha256:${BLOB_HASH}"

# ---- Test 1: monolithic push (single request, digest declared up front) --
log "==> [1/2] Push ${BLOB_MIB} MiB blob (monolithic, digest-qualified)"
PUSH_STATUS="$(curl -sS -o /dev/null -D "$HEADERS_FILE" -w '%{http_code}' \
  -X POST \
  -u "dev-user:${DEV_TOKEN}" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary "@${BLOB_FILE}" \
  "$UPLOAD_URL" 2>/dev/null || echo 000)"
if [ "$PUSH_STATUS" = "201" ]; then
  pass "monolithic push -> 201 Created"
else
  fail "monolithic push" "expected 201, got ${PUSH_STATUS}"
  summary
fi

PUSHED_DIGEST="$(tr -d '\r' < "$HEADERS_FILE" | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2; exit}')"
if [ "$PUSHED_DIGEST" = "sha256:${BLOB_HASH}" ]; then
  pass "Docker-Content-Digest on push response matches the declared digest"
else
  fail "Docker-Content-Digest on push response" "got '${PUSHED_DIGEST}', want 'sha256:${BLOB_HASH}'"
fi

# ---- Test 2: pull back + byte-for-byte / digest round-trip ----------------
log "==> [2/2] Pull the blob back and verify the round-trip"
PULL_STATUS="$(curl -sS -o "$PULLED_FILE" -w '%{http_code}' \
  -u "dev-user:${DEV_TOKEN}" \
  "${HORT_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/sha256:${BLOB_HASH}" 2>/dev/null || echo 000)"
if [ "$PULL_STATUS" = "200" ]; then
  pass "pull -> 200 OK"
else
  fail "pull" "expected 200, got ${PULL_STATUS}"
  summary
fi

PULLED_HASH="$(sha256sum "$PULLED_FILE" | awk '{print $1}')"
if [ "$PULLED_HASH" = "$BLOB_HASH" ]; then
  pass "digest round-trip: pushed == pulled == ${BLOB_HASH}"
else
  fail "digest round-trip mismatch" "pushed=${BLOB_HASH} pulled=${PULLED_HASH}"
fi

if cmp -s "$BLOB_FILE" "$PULLED_FILE"; then
  pass "byte-for-byte round-trip (cmp)"
else
  fail "byte-for-byte round-trip" "pulled bytes differ from the pushed blob (cmp)"
fi

summary
