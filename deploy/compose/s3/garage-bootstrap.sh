#!/bin/sh
# deploy/compose/s3/garage-bootstrap.sh
#
# One-shot cluster bootstrap for the `s3` compose overlay's Garage service,
# run by the `garage-bootstrap` one-shot container (see docker-compose.s3.yml).
#
# WHY THE ADMIN API, NOT THE `garage` CLI: `dxflrs/garage` ships as a
# shell-free `scratch` image (no /bin/sh, no coreutils — only the `/garage`
# binary). The historical bootstrap approach (see
# crates/hort-adapters-storage/tests/s3_multipart.rs and the sbx sidecar's
# `.agents/manifest.yaml`) drives the CLI via an orchestrator that execs
# `/garage <argv>` directly (no shell) and captures each step's stdout on the
# HOST side to feed the next step (e.g. `garage node id -q` -> NODE_ID ->
# `garage layout assign ... "$NODE_ID"`). docker-compose has no equivalent
# "capture this container's stdout into the next service's command" facility,
# and there is no docker socket / CLI available inside this stack to shell
# out to `docker compose exec` ourselves without a much larger blast radius
# (mounting the host docker socket into a compose service).
#
# Garage's Admin API (bound at :3903 in garage.toml, `[admin] admin_token`)
# sidesteps the whole problem: it is a plain HTTP+JSON API reachable from any
# ordinary container with curl+jq, needs no shell inside the Garage
# container, and every step below is exactly the v2 CLI bootstrap
# (layout assign/apply, bucket create, key import, bucket allow) expressed as
# the equivalent `/v2/...` admin call. Reference:
# https://garagehq.deuxfleurs.fr/documentation/reference-manual/admin-api/
set -eu

ADMIN="http://garage:3903"
AUTH_HDR="Authorization: Bearer ${GARAGE_ADMIN_TOKEN}"
JSON_HDR="Content-Type: application/json"

echo "[s3-bootstrap] waiting for the Garage admin API..."
i=0
while ! curl -fsS -H "$AUTH_HDR" "$ADMIN/v2/GetClusterStatus" -o /tmp/status.json 2>/tmp/status.err; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then
    echo "[s3-bootstrap] FAILED: admin API did not become ready after 60s" >&2
    cat /tmp/status.err >&2
    exit 1
  fi
  sleep 1
done
echo "[s3-bootstrap] admin API is up (after ${i}s)"

NODE_ID=$(jq -r '.nodes[0].id' /tmp/status.json)
if [ -z "$NODE_ID" ] || [ "$NODE_ID" = "null" ]; then
  echo "[s3-bootstrap] FAILED: could not read this node's id from GetClusterStatus" >&2
  cat /tmp/status.json >&2
  exit 1
fi
echo "[s3-bootstrap] node id: ${NODE_ID}"

echo "[s3-bootstrap] staging single-node layout (zone=dc1, capacity=1GB)"
curl -fsS -X POST -H "$AUTH_HDR" -H "$JSON_HDR" \
  -d "{\"roles\":[{\"id\":\"${NODE_ID}\",\"zone\":\"dc1\",\"capacity\":1000000000,\"tags\":[]}]}" \
  "$ADMIN/v2/UpdateClusterLayout" -o /tmp/staged.json
CURRENT_VERSION=$(jq -r '.version' /tmp/staged.json)
APPLY_VERSION=$((CURRENT_VERSION + 1))

echo "[s3-bootstrap] applying layout version ${APPLY_VERSION}"
curl -fsS -X POST -H "$AUTH_HDR" -H "$JSON_HDR" \
  -d "{\"version\": ${APPLY_VERSION}}" \
  "$ADMIN/v2/ApplyClusterLayout" -o /tmp/applied.json
cat /tmp/applied.json

echo "[s3-bootstrap] creating bucket ${GARAGE_BUCKET}"
curl -fsS -X POST -H "$AUTH_HDR" -H "$JSON_HDR" \
  -d "{\"globalAlias\": \"${GARAGE_BUCKET}\"}" \
  "$ADMIN/v2/CreateBucket" -o /tmp/bucket.json
BUCKET_ID=$(jq -r '.id' /tmp/bucket.json)
if [ -z "$BUCKET_ID" ] || [ "$BUCKET_ID" = "null" ]; then
  echo "[s3-bootstrap] FAILED: CreateBucket returned no bucket id" >&2
  cat /tmp/bucket.json >&2
  exit 1
fi
echo "[s3-bootstrap] bucket id: ${BUCKET_ID}"

echo "[s3-bootstrap] importing key ${GARAGE_ACCESS_KEY}"
curl -fsS -X POST -H "$AUTH_HDR" -H "$JSON_HDR" \
  -d "{\"accessKeyId\": \"${GARAGE_ACCESS_KEY}\", \"secretAccessKey\": \"${GARAGE_SECRET_KEY}\", \"name\": \"hort-s3-e2e\"}" \
  "$ADMIN/v2/ImportKey" -o /tmp/key.json
cat /tmp/key.json

echo "[s3-bootstrap] granting read/write/owner on ${GARAGE_BUCKET} to ${GARAGE_ACCESS_KEY}"
curl -fsS -X POST -H "$AUTH_HDR" -H "$JSON_HDR" \
  -d "{\"bucketId\": \"${BUCKET_ID}\", \"accessKeyId\": \"${GARAGE_ACCESS_KEY}\", \"permissions\": {\"read\": true, \"write\": true, \"owner\": true}}" \
  "$ADMIN/v2/AllowBucketKey" -o /tmp/allow.json
cat /tmp/allow.json

echo "[s3-bootstrap] BOOTSTRAP_OK"
