#!/usr/bin/env bash
# requires:
# npm scenario: a fresh, lockfile-free `npm install` of a package that
# declares a dependency must materialise that dependency.
#
# This is the install shape that reads `versions[v].dependencies` off the
# served packument. A lockfile install pins every tarball URL up front and
# so passes even when the packument advertises no dependencies at all —
# which is exactly how a dependency-free served packument shipped
# unnoticed. Publishing two packages and resolving the root from a cold
# npm cache with no lockfile is the only client-observable check that the
# per-version manifest fields are on the wire.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

REPO_KEY="${NPM_REPO_KEY:-npm-e2e}"
NPM_REGISTRY="${HORT_URL%/}/npm/${REPO_KEY}/"
TEST_VERSION="1.0.$(date +%s)"
DEP_NAME="@test/hort-dep-$(date +%s)"
ROOT_NAME="@test/hort-root-$(date +%s)"

log "==> NPM transitive-dependency resolution test"
log "Registry: $NPM_REGISTRY"
log "Root:     $ROOT_NAME@$TEST_VERSION"
log "Dep:      $DEP_NAME@$TEST_VERSION"

DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# A cache dir private to this run, so the resolve below cannot be served
# from a warm npm cache populated by an earlier scenario.
export npm_config_cache="$WORK_DIR/npm-cache"

NPM_HOST_PATH="${NPM_REGISTRY#http*://}"
npm config set registry "$NPM_REGISTRY"
npm config delete "//${NPM_HOST_PATH}:_auth"     2>/dev/null || true
npm config delete "//${NPM_HOST_PATH}:_password" 2>/dev/null || true
npm config delete "//${NPM_HOST_PATH}:username"  2>/dev/null || true
npm config set "//${NPM_HOST_PATH}:_authToken" "$DEV_TOKEN"

# ---- Publish the dependency ----
log "==> [1/3] Publishing the dependency $DEP_NAME@$TEST_VERSION..."
mkdir -p "$WORK_DIR/dep"
cd "$WORK_DIR/dep" || { fail "cd into dep dir" "$WORK_DIR/dep"; summary; }
cat > package.json << EOF
{
  "name": "$DEP_NAME",
  "version": "$TEST_VERSION",
  "description": "Transitive-dependency fixture (leaf)",
  "main": "index.js",
  "license": "MIT"
}
EOF
cat > index.js << 'EOF'
module.exports = { marker: "hort-transitive-dep-ok" };
EOF
if npm publish --access public 2>&1 | tail -5; then
  pass "dependency published"
else
  fail "npm publish (dependency)" "npm publish exited non-zero"
fi

# ---- Publish the root, declaring an exact dependency on the leaf ----
log "==> [2/3] Publishing the root $ROOT_NAME@$TEST_VERSION..."
mkdir -p "$WORK_DIR/root"
cd "$WORK_DIR/root" || { fail "cd into root dir" "$WORK_DIR/root"; summary; }
cat > package.json << EOF
{
  "name": "$ROOT_NAME",
  "version": "$TEST_VERSION",
  "description": "Transitive-dependency fixture (root)",
  "main": "index.js",
  "license": "MIT",
  "dependencies": {
    "$DEP_NAME": "$TEST_VERSION"
  }
}
EOF
cat > index.js << EOF
module.exports = require("$DEP_NAME");
EOF
if npm publish --access public 2>&1 | tail -5; then
  pass "root published"
else
  fail "npm publish (root)" "npm publish exited non-zero"
fi

# ---- Fresh, lockfile-free install of the root ----
log "==> [3/3] Fresh npm install of the root (cold cache, no lockfile)..."
mkdir -p "$WORK_DIR/install"
cd "$WORK_DIR/install" || { fail "cd into install dir" "$WORK_DIR/install"; summary; }
npm init -y >/dev/null 2>&1
rm -f package-lock.json

if npm install --no-audit --no-fund "$ROOT_NAME@$TEST_VERSION" 2>&1 | tail -10; then
  pass "npm install of the root succeeded"
else
  fail "npm install (root)" "npm install exited non-zero"
fi

if [ -f "node_modules/$DEP_NAME/package.json" ]; then
  pass "the declared dependency was materialised in node_modules"
else
  fail "transitive dependency missing" \
    "node_modules/$DEP_NAME/package.json absent — the served packument advertised no dependencies for $ROOT_NAME@$TEST_VERSION"
fi

# The require chain only resolves when the leaf is actually installed;
# it fails loudly rather than yielding a half-materialised tree.
OUTPUT="$(node -e "console.log(require('$ROOT_NAME').marker);" 2>&1 || true)"
if [ "$OUTPUT" = "hort-transitive-dep-ok" ]; then
  pass "require() through the root reaches the dependency"
else
  fail "require through the root" "expected 'hort-transitive-dep-ok', got '$OUTPUT'"
fi

# The packument itself must carry the field the resolver read.
log "==> Asserting the served packument advertises the dependency..."
PACKUMENT="$(curl -sS -H "Authorization: Bearer $DEV_TOKEN" \
  "${NPM_REGISTRY}${ROOT_NAME}")"
if [ "$(printf '%s' "$PACKUMENT" | jq -r ".versions[\"$TEST_VERSION\"].dependencies[\"$DEP_NAME\"]")" = "$TEST_VERSION" ]; then
  pass "packument versions[$TEST_VERSION].dependencies carries the declared range"
else
  fail "packument dependencies" \
    "versions[$TEST_VERSION].dependencies[$DEP_NAME] did not equal $TEST_VERSION"
fi

summary
