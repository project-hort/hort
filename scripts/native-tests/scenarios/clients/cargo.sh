#!/usr/bin/env bash
# requires:
# Cargo scenario: push (cargo publish) and pull (cargo build against published crate).

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

REPO_KEY="${CARGO_REPO_KEY:-cargo-e2e}"
CARGO_REGISTRY_URL="${HORT_URL%/}/cargo/${REPO_KEY}"
TEST_VERSION="1.0.$(date +%s)"

log "==> Cargo Native Client Test"
log "Registry: $CARGO_REGISTRY_URL"
log "Version:  $TEST_VERSION"

# Fetch tokens via the shared lib
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ]    || fail "fetch dev-user token"    "empty response from Keycloak"

READER_TOKEN="$(fetch_token reader-user reader)"
[ -n "$READER_TOKEN" ] || fail "fetch reader-user token" "empty response from Keycloak"

log "[auth] fetched DEV_TOKEN + READER_TOKEN from Keycloak"

# Generate test crate
log "==> Generating test crate..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR" || { fail "cd into WORK_DIR" "$WORK_DIR"; summary; }
mkdir -p src

cat > Cargo.toml << EOF
[package]
name = "test-crate-native"
version = "$TEST_VERSION"
edition = "2021"
description = "Test crate for native client E2E testing"
license = "MIT"

[lib]
name = "test_crate_native"
path = "src/lib.rs"
EOF

cat > src/lib.rs << 'EOF'
pub fn hello() -> &'static str {
    "Hello from test-crate-native!"
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hello() {
        assert_eq!(hello(), "Hello from test-crate-native!");
    }
}
EOF

# Configure cargo registry (PROJECT-LOCAL — cargo walks up from $CWD to
# find `.cargo/config.toml`, so one write here covers both the publish
# step (run from $WORK_DIR) and the consumer-build step (run from
# $WORK_DIR/test-install/, which walks up).
log "==> Configuring cargo registry..."
mkdir -p "$WORK_DIR/.cargo"
cat > "$WORK_DIR/.cargo/config.toml" << EOF
[registries.test-registry]
index = "sparse+$CARGO_REGISTRY_URL/"

[registry]
default = "test-registry"
EOF

# Cargo reads the token from this env var — one per registry name. Cargo
# sends the value VERBATIM as the Authorization header, so including the
# `Bearer ` scheme here is the canonical pattern.
export CARGO_REGISTRIES_TEST_REGISTRY_TOKEN="Bearer $DEV_TOKEN"

# ---- Test 1: cargo package ----
log "==> [1/4] Packaging crate..."
if cargo package --allow-dirty --no-verify 2>&1 | tail -5; then
  pass "cargo package succeeded"
else
  fail "cargo package" "cargo package exited non-zero"
fi

# ---- Test 2: cargo publish ----
log "==> [2/4] Publishing crate with cargo..."
if cargo publish --registry test-registry --allow-dirty --no-verify 2>&1 | tail -5; then
  pass "cargo publish succeeded"
else
  fail "cargo publish" "cargo publish exited non-zero"
fi

# ---- Test 3: consumer build + run ----
# The consumer build IS the pull verification: if the sparse index does not
# list the just-published version, or the .crate file is not fetchable,
# `cargo build` exits non-zero.
log "==> [3/4] Installing crate with cargo (consumer build)..."
mkdir -p "$WORK_DIR/test-install"
cd "$WORK_DIR/test-install" || { fail "cd into test-install" "$WORK_DIR/test-install"; summary; }
cargo init --name test-consumer --bin -q
cat >> Cargo.toml << EOF
test-crate-native = { version = "=$TEST_VERSION", registry = "test-registry" }
EOF
cat > src/main.rs << 'EOF'
fn main() {
    println!("{}", test_crate_native::hello());
}
EOF

if cargo build 2>&1 | tail -5; then
  OUTPUT="$(./target/debug/test-consumer)"
  if [ "$OUTPUT" = "Hello from test-crate-native!" ]; then
    pass "consumer build + run succeeded"
  else
    fail "consumer run output" "expected 'Hello from test-crate-native!' got '$OUTPUT'"
  fi
else
  fail "consumer build" "cargo build exited non-zero"
fi

# ---- Negative assertions ----
#
# The cargo publish handler resolves the actor + runs authorize()
# BEFORE parsing the publish body, so an empty body is fine — we only
# care about the status code.

CARGO_PUBLISH_URL="$CARGO_REGISTRY_URL/api/v1/crates/new"

log "[auth] negative test 1/2: publish without credentials must 401"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X PUT "$CARGO_PUBLISH_URL" \
    -d '')
if [ "$STATUS" = "401" ]; then
  pass "no-auth cargo publish -> 401"
else
  fail "no-auth cargo publish expected 401" "got $STATUS"
fi

log "[auth] negative test 2/2: publish with reader token must 403"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X PUT "$CARGO_PUBLISH_URL" \
    -H "Authorization: Bearer $READER_TOKEN" \
    -d '')
if [ "$STATUS" = "403" ]; then
  pass "reader-token cargo publish -> 403"
else
  fail "reader-token cargo publish expected 403" "got $STATUS"
fi

assert_metric_ingest cargo
summary
