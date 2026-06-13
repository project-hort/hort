#!/usr/bin/env bash
# requires:
# PyPI scenario: push (twine) and pull (pip) operations via PEP 503 Simple
# Repository API. Also validates PEP 691 JSON API and PEP 658 metadata.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

PYPI_REPO_KEY="${PYPI_REPO_KEY:-pypi-e2e}"
PYPI_URL="${HORT_URL%/}/pypi/${PYPI_REPO_KEY}"
TEST_VERSION="1.0.$(date +%s)"

log "==> PyPI Native Client Test (PEP 503)"
log "Registry: $PYPI_URL"
log "Version:  $TEST_VERSION"

# Check prerequisites
command -v python3 >/dev/null || skip "python3 not found"
command -v pip3    >/dev/null || skip "pip3 not found"

# Fetch tokens via the shared lib
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ]    || fail "fetch dev-user token"    "empty response from Keycloak"

READER_TOKEN="$(fetch_token reader-user reader)"
[ -n "$READER_TOKEN" ] || fail "fetch reader-user token" "empty response from Keycloak"

log "[auth] fetched DEV_TOKEN + READER_TOKEN from Keycloak"

# Generate test package
log "==> Generating test package..."
WORK_DIR="$(mktemp -d)"
VENV_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR" "$VENV_DIR"' EXIT

cd "$WORK_DIR" || { fail "cd into WORK_DIR" "$WORK_DIR"; summary; }
mkdir -p src/test_package_native

cat > pyproject.toml << EOF
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "test-package-native"
version = "$TEST_VERSION"
description = "Test package for hort PyPI E2E"
requires-python = ">=3.8"
EOF

cat > src/test_package_native/__init__.py << EOF
__version__ = "$TEST_VERSION"
def hello():
    return "Hello from test-package-native!"
EOF

# Build package (build + twine are baked into the client image)
log "==> Building package..."
python3 -m build --wheel --sdist 2>&1 | tail -3

# ---- Test 1: Twine upload ----
# Twine emits HTTP Basic only. The auth middleware treats a Basic password
# as a bearer-token shim when the username is `__token__`, so we stash
# the minted registry JWT in TWINE_PASSWORD.
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="$DEV_TOKEN"
log "==> [1/6] Pushing package with twine..."
if twine upload \
      --repository-url "$PYPI_URL/" \
      dist/* 2>&1 | tail -5; then
  pass "Twine upload succeeded"
else
  fail "Twine upload" "twine exited non-zero"
fi

# ---- Test 2: PEP 503 root index ----
log "==> [2/6] Verifying PEP 503 root index..."
ROOT_INDEX=$(curl -sf "$PYPI_URL/simple/")
if printf '%s' "$ROOT_INDEX" | grep -q "test-package-native"; then
  pass "Root index contains package"
else
  fail "Root index contains package" "test-package-native not found in $PYPI_URL/simple/"
fi

# ---- Test 3: PEP 503 package index ----
log "==> [3/6] Verifying PEP 503 package index..."
PKG_INDEX=$(curl -sf "$PYPI_URL/simple/test-package-native/")
pkg_ok=1
printf '%s' "$PKG_INDEX" | grep -q ".whl" \
  || { fail "Wheel in package index"           "no .whl link found";              pkg_ok=0; }
printf '%s' "$PKG_INDEX" | grep -q ".tar.gz" \
  || { fail "Sdist in package index"           "no .tar.gz link found";           pkg_ok=0; }
printf '%s' "$PKG_INDEX" | grep -q "sha256=" \
  || { fail "sha256 hash in package index"     "no sha256= attribute found";      pkg_ok=0; }
printf '%s' "$PKG_INDEX" | grep -q "data-requires-python" \
  || { fail "requires-python in package index" "no data-requires-python found";   pkg_ok=0; }
if [ "$pkg_ok" = 1 ]; then pass "Package index correct with hashes and requires-python"; fi

# ---- Test 4: PEP 691 JSON API ----
log "==> [4/6] Verifying PEP 691 JSON API..."
JSON_RESP=$(curl -sf -H "Accept: application/vnd.pypi.simple.v1+json" "$PYPI_URL/simple/test-package-native/")
if printf '%s' "$JSON_RESP" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert data['meta']['api-version'] == '1.1', 'Wrong API version'
assert data['name'] == 'test-package-native', 'Wrong name'
assert len(data['files']) == 2, f'Expected 2 files, got {len(data[\"files\"])}'
assert '$TEST_VERSION' in data['versions'], 'Version not listed'
print('  JSON response valid')
"; then
  pass "PEP 691 JSON API works"
else
  fail "PEP 691 JSON API" "unexpected JSON response structure"
fi

# ---- Test 5: pip install (venv — PEP 668 externally-managed host) ----
log "==> [5/6] Installing package with pip..."
VENV="$VENV_DIR/v"
python3 -m venv "$VENV"
# Wrap install + import in one `if` so a pip failure is a clean FAIL routed
# through `summary` (not a set -e abort that exits with pip's own code).
if "$VENV/bin/pip" install \
      --index-url "$PYPI_URL/simple/" \
      --trusted-host "$(printf '%s' "$HORT_URL" | sed -E 's#^https?://##' | cut -d/ -f1 | cut -d: -f1)" \
      "test-package-native==$TEST_VERSION" 2>&1 | tail -5 \
   && "$VENV/bin/python" -c \
      "from test_package_native import hello; assert hello() == 'Hello from test-package-native!'"; then
  pass "pip install + import succeeded"
else
  fail "pip install + import" "pip install or import/assert failed"
fi

# ---- Test 6: PEP 658 metadata ----
log "==> [6/6] Verifying PEP 658 metadata endpoint..."
WHL_FILE=$(ls dist/*.whl | head -1 | xargs basename)
METADATA=$(curl -sf "$PYPI_URL/simple/test-package-native/${WHL_FILE}.metadata")
meta_ok=1
printf '%s' "$METADATA" | grep -q "Name: test-package-native" \
  || { fail "PEP 658 metadata Name field"    "Name: test-package-native not found"; meta_ok=0; }
printf '%s' "$METADATA" | grep -q "Version: $TEST_VERSION" \
  || { fail "PEP 658 metadata Version field" "Version: $TEST_VERSION not found";     meta_ok=0; }
if [ "$meta_ok" = 1 ]; then pass "PEP 658 metadata extraction works"; fi

# ---------------------------------------------------------------------
# Negative assertions
#
# The upload handler resolves the actor + runs authorize() BEFORE any
# multipart parsing, so a dummy multipart body is fine — we only care
# about the status code.
# ---------------------------------------------------------------------

log "[auth] negative test 1/2: publish without credentials must 401"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "$PYPI_URL/" \
    -F ':action=file_upload' \
    -F 'protocol_version=1' \
    -F 'name=denied' \
    -F 'version=0.0.1' \
    -F 'content=@/dev/null;filename=denied-0.0.1.tar.gz')
if [ "$STATUS" = "401" ]; then
  pass "no-auth pypi upload -> 401"
else
  fail "no-auth pypi upload expected 401" "got $STATUS"
fi

log "[auth] negative test 2/2: publish with reader token must 403"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "$PYPI_URL/" \
    -H "Authorization: Bearer $READER_TOKEN" \
    -F ':action=file_upload' \
    -F 'protocol_version=1' \
    -F 'name=denied' \
    -F 'version=0.0.1' \
    -F 'content=@/dev/null;filename=denied-0.0.1.tar.gz')
if [ "$STATUS" = "403" ]; then
  pass "reader-token pypi upload -> 403"
else
  fail "reader-token pypi upload expected 403" "got $STATUS"
fi

assert_metric_ingest pypi
summary
