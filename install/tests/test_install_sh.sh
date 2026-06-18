#!/bin/sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=install/tests/lib.sh
. "$here/lib.sh"

work="$(mktemp -d)"
trap 'stop_fixture; rm -rf "$work"' EXIT

sh "$here/make_fixture.sh" "$work/site"
start_fixture "$work/site"

# cosign stub on PATH: `version` reports >= v3 (so the installer uses it, no bootstrap),
# `verify-blob` exits 0. The shipped script has NO verification bypass — tests stub the
# real binary instead, so the genuine cosign_verify path is exercised end to end.
mkdir -p "$work/stubbin"
cat > "$work/stubbin/cosign" <<'STUB'
#!/bin/sh
case "$1" in
  version) echo "GitVersion: v3.1.1" ;;
  verify-blob) exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$work/stubbin/cosign"
STUB_PATH="$work/stubbin:$PATH"

# 1) happy path: explicit version, stubbed cosign on PATH, fixture download base
out="$(PATH="$STUB_PATH" HORT_DL_BASE="$FIXTURE_URL/releases/download" \
  HORT_VERSION=v9.9.9-beta.1 sh "$here/../install-cli.sh" --dir "$work/bin" 2>&1)" \
  || { echo "$out"; echo "FAIL: installer errored"; exit 1; }
[ -x "$work/bin/hort-cli" ] || { echo "$out"; echo "FAIL: hort-cli not installed"; exit 1; }
assert_contains "$out" "verified" "should report verification"
echo "PASS: happy path"

# 2) prerelease-aware resolver: no --version, API pointed at fixture -> picks the prerelease tag
out="$(PATH="$STUB_PATH" HORT_DL_BASE="$FIXTURE_URL/releases/download" \
  HORT_API="$FIXTURE_URL" sh "$here/../install-cli.sh" --dir "$work/bin2" 2>&1)" \
  || { echo "$out"; echo "FAIL: resolver path errored"; exit 1; }
assert_contains "$out" "v9.9.9-beta.1" "resolver should pick the prerelease tag"
[ -x "$work/bin2/hort-cli" ] || { echo "$out"; echo "FAIL: resolver-path install missing"; exit 1; }
echo "PASS: prerelease-aware resolver"

# 3) tampered archive -> SHA-256 abort, nothing installed (SHA gate runs before cosign)
arch="$(find "$work/site/releases/download/v9.9.9-beta.1" -name 'hort-cli-*.tar.gz' | head -1)"
printf 'TAMPER' >> "$arch"
if PATH="$STUB_PATH" HORT_DL_BASE="$FIXTURE_URL/releases/download" \
     HORT_VERSION=v9.9.9-beta.1 sh "$here/../install-cli.sh" --dir "$work/bin3" >/dev/null 2>&1; then
  echo "FAIL: tampered archive was accepted"; exit 1
fi
[ ! -e "$work/bin3/hort-cli" ] || { echo "FAIL: binary installed despite SHA mismatch"; exit 1; }
echo "PASS: tampered archive rejected"
