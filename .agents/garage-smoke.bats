#!/usr/bin/env bats
SBX="${SBX_BIN:-/home/tom/proj/auto-agents/bin/sbx}"
HORT="/home/tom/proj/hort"

setup() { command -v podman >/dev/null || skip "no podman"; }
teardown() { "$SBX" -C "$HORT" sidecar down || true; }

@test "garage sidecar: up, bucket usable via S3, idempotent re-up" {
  "$SBX" -C "$HORT" sidecar up
  run podman exec sbx-hort-garage /garage bucket list
  [ "$status" -eq 0 ]
  echo "$output" | grep -q "hort-dev-cas"
  # S3 PUT/GET from an aws-cli container on the same network
  run podman run --rm --network sbx-hort-net \
    -e AWS_ACCESS_KEY_ID=GKdeadbeefdeadbeefdeadbeef \
    -e AWS_SECRET_ACCESS_KEY=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef \
    mirror.kdp.kloni.cloud/docker.io/amazon/aws-cli:2.17.0 \
    --endpoint-url http://sbx-hort-garage:3900 --region garage \
    s3 cp /etc/hostname s3://hort-dev-cas/probe
  [ "$status" -eq 0 ]
  run podman run --rm --network sbx-hort-net \
    -e AWS_ACCESS_KEY_ID=GKdeadbeefdeadbeefdeadbeef \
    -e AWS_SECRET_ACCESS_KEY=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef \
    mirror.kdp.kloni.cloud/docker.io/amazon/aws-cli:2.17.0 \
    --endpoint-url http://sbx-hort-garage:3900 --region garage \
    s3 cp s3://hort-dev-cas/probe -
  [ "$status" -eq 0 ]
  # idempotent: second up is a no-op and stays healthy
  "$SBX" -C "$HORT" sidecar up
  run podman exec sbx-hort-garage /garage status
  [ "$status" -eq 0 ]
}
