#!/usr/bin/env bash
# scripts/test-crate-version-in-index.sh
#
# Tests for the publish-time index check that makes a crates release
# resumable — scripts/ci/crate-version-in-index.sh and the sparse-index
# path rule it shares with the vetted-index preflight.
#
# The check decides, before each `cargo publish`, whether that exact
# version is already in the registry index and should be skipped. It is
# release-critical and it is exercised roughly once per release, so it is
# tested here against fixture index documents rather than discovered to be
# wrong during a release: the two failed attempts that motivated it each
# cost a version number that can never be reused.
#
# The property under test is one-directional. Reporting "not published"
# when it is costs one redundant attempt that cargo then refuses loudly;
# reporting "already published" when it is not silently drops a crate from
# a shipped release. So every ambiguous input below must come back "not
# published".
#
# Usage:
#   ./scripts/test-crate-version-in-index.sh
#
# Requirements: bash, jq. No network, no registry, no cargo — the check
# reads its index document from HORT_INDEX_FIXTURE_DIR.
#
# Exit codes:
#   0 — all assertions passed
#   1 — one or more assertions failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${REPO_ROOT}/scripts/ci/crate-version-in-index.sh"

# shellcheck source=scripts/ci/lib-cargo-sparse-index.sh
source "${REPO_ROOT}/scripts/ci/lib-cargo-sparse-index.sh"

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq not found — the index check parses NDJSON index documents with it." >&2
  exit 1
fi

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  ok   — $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL — $1"; }

# ── Fixture index ─────────────────────────────────────────────────────────────
#
# A hort sparse index serves NDJSON, one object per version, at the
# RFC 2789 prefixed path for the crate name.

FIXTURE_DIR="$(mktemp -d)"
trap 'rm -rf "${FIXTURE_DIR}"' EXIT

# Writes one crate's index document under ${INDEX_BASE} (the fixture index
# by default), at the prefixed path a real sparse index would serve it from.
INDEX_BASE=""
write_index() {
  local name="$1"; shift
  local path target
  path="$(cargo_sparse_index_path "${name}")"
  target="${INDEX_BASE:-${FIXTURE_DIR}}/${path}"
  mkdir -p "$(dirname "${target}")"
  printf '%s\n' "$@" > "${target}"
}

json_line() {
  # name, vers, yanked
  printf '{"name":"%s","vers":"%s","deps":[],"cksum":"%s","features":{},"yanked":%s}' \
    "$1" "$2" "$(printf '0%.0s' {1..64})" "$3"
}

write_index hort-domain \
  "$(json_line hort-domain 0.11.0-beta.6 false)" \
  "$(json_line hort-domain 0.11.0-beta.7 false)"

# A crate whose only published version was yanked.
write_index hort-config "$(json_line hort-config 0.11.0-beta.7 true)"

# A body that is not NDJSON at all — an error page, a truncated response.
mkdir -p "${FIXTURE_DIR}/$(dirname "$(cargo_sparse_index_path hort-broken)")"
printf '<html>502 Bad Gateway</html>\n' > "${FIXTURE_DIR}/$(cargo_sparse_index_path hort-broken)"

# ── verdict helper ────────────────────────────────────────────────────────────
#
# 0 = already published (skip), 1 = publish, 2 = usage error.

verdict() {
  local rc=0
  HORT_INDEX_FIXTURE_DIR="${FIXTURE_DIR}" \
    "${CHECK}" https://registry.example hort-crates "$1" "$2" >/dev/null 2>&1 || rc=$?
  echo "${rc}"
}

expect_verdict() {
  local name="$1" version="$2" want="$3" desc="$4" got
  got="$(verdict "${name}" "${version}")"
  if [[ "${got}" == "${want}" ]]; then
    pass "${desc}"
  else
    fail "${desc} (want exit ${want}, got ${got})"
  fi
}

echo "── Sparse-index path rule ─────────────────────────────────────────────"

expect_path() {
  local name="$1" want="$2" got
  got="$(cargo_sparse_index_path "${name}")"
  if [[ "${got}" == "${want}" ]]; then
    pass "${name} -> ${want}"
  else
    fail "${name} -> ${want} (got ${got})"
  fi
}

# The rule cargo itself implements. A wrong path is a 404, and a 404 reads
# as "not published" — the same answer a correct lookup gives for an
# unpublished crate, so an error here is invisible until a release skips
# nothing it should have skipped, or (worse, if the rule ever moved the
# other way) skips something it should not have.
expect_path a 1/a
expect_path ab 2/ab
expect_path abc 3/a/abc
expect_path abcd ab/cd/abcd
expect_path hort-domain ho/rt/hort-domain
expect_path Hort-Domain ho/rt/hort-domain

echo
echo "── Verdicts against a fixture index ───────────────────────────────────"

expect_verdict hort-domain 0.11.0-beta.7 0 \
  "a version present in the index is already published (skip it)"

expect_verdict hort-domain 0.11.0-beta.6 0 \
  "an earlier version in the same document is matched too"

expect_verdict hort-domain 0.11.0-beta.8 1 \
  "a version absent from an existing crate's document is not published"

expect_verdict hort-formats 0.11.0-beta.7 1 \
  "a crate with no index document at all is not published"

expect_verdict hort-config 0.11.0-beta.7 0 \
  "a yanked version still occupies its number — cargo refuses to republish it"

echo
echo "── Exactness ──────────────────────────────────────────────────────────"

# Version comparison is string equality on `vers`, never a prefix or
# substring test. `0.11.0` is a different release from `0.11.0-beta.7`, and
# treating either as the other would skip a crate that was never uploaded.
expect_verdict hort-domain 0.11.0 1 \
  "a release version is not matched by its own pre-release"
expect_verdict hort-domain 0.11.0-beta 1 \
  "a version prefix does not match the longer version"
expect_verdict hort-domain 11.0-beta.7 1 \
  "a version substring does not match"

echo
echo "── Ambiguity resolves to \"publish\", never to \"skip\" ──────────────────"

expect_verdict hort-broken 0.11.0-beta.7 1 \
  "an unparseable index body is not evidence of publication"

# Usage errors must be distinguishable from both verdicts: a caller that
# invoked this wrongly must not read the failure as either answer.
rc=0
HORT_INDEX_FIXTURE_DIR="${FIXTURE_DIR}" "${CHECK}" https://registry.example hort-crates \
  >/dev/null 2>&1 || rc=$?
if [[ "${rc}" == "2" ]]; then
  pass "too few arguments exits 2, distinct from both verdicts"
else
  fail "too few arguments exits 2, distinct from both verdicts (got ${rc})"
fi

echo
echo "── Publish order carries the fields the check needs ───────────────────"

# The check is addressed by name and version; the publish loop gets both
# from the order script rather than inferring them from a directory name.
if command -v cargo &>/dev/null; then
  order_out="$("${REPO_ROOT}/scripts/ci/publishable-crates-in-order.sh" 2>/dev/null || true)"
  if [[ -z "${order_out}" ]]; then
    fail "publishable-crates-in-order.sh produced no output"
  else
    bad=0
    while IFS=$'\t' read -r dir name version; do
      [[ -n "${dir}" && -n "${name}" && -n "${version}" ]] || bad=1
      [[ -d "${REPO_ROOT}/${dir}" ]] || bad=1
    done <<< "${order_out}"
    if [[ "${bad}" == "0" ]]; then
      pass "every record is <dir>TAB<name>TAB<version> with an existing directory"
    else
      fail "every record is <dir>TAB<name>TAB<version> with an existing directory"
    fi
  fi
else
  echo "  skip — cargo not on PATH (the real workspace read needs it)"
fi

echo
echo "── The publish loop ───────────────────────────────────────────────────"

# The loop is driven end to end against a stub `cargo` and a fixture index.
# `cargo metadata` is stubbed too, so these run with neither a registry nor
# a Rust toolchain — the constraints below are the ones a release depends
# on, and they must not be gated behind an optional tool.
#
# The fixture graph is alpha <- beta <- gamma, so the publish order is
# forced and a stop-at-failure is observable as gamma's absence.

STUB_DIR="$(mktemp -d)"
trap 'rm -rf "${FIXTURE_DIR}" "${STUB_DIR}"' EXIT
mkdir -p "${STUB_DIR}/bin"

cat > "${STUB_DIR}/metadata.json" <<JSON
{"packages":[
 {"name":"alpha","version":"1.0.0","manifest_path":"${REPO_ROOT}/fx/alpha/Cargo.toml",
  "publish":["hort-crates"],"dependencies":[]},
 {"name":"beta","version":"1.0.0","manifest_path":"${REPO_ROOT}/fx/beta/Cargo.toml",
  "publish":["hort-crates"],"dependencies":[{"name":"alpha","kind":null}]},
 {"name":"gamma","version":"1.0.0","manifest_path":"${REPO_ROOT}/fx/gamma/Cargo.toml",
  "publish":["hort-crates"],"dependencies":[{"name":"beta","kind":null}]}
]}
JSON

# Stub cargo: `metadata` returns the fixture graph, `publish` records the
# crate it was asked to upload and fails for whatever CARGO_STUB_FAIL_ON
# names. Anything else is a hard error, so a changed call shape surfaces
# here rather than passing silently.
cat > "${STUB_DIR}/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  metadata) cat "${CARGO_STUB_DIR}/metadata.json" ;;
  publish)
    manifest=""
    while [[ $# -gt 0 ]]; do
      [[ "$1" == "--manifest-path" ]] && manifest="$2"
      shift
    done
    crate="$(basename "$(dirname "${manifest}")")"
    echo "${crate}" >> "${CARGO_STUB_DIR}/published.log"
    if [[ "${crate}" == "${CARGO_STUB_FAIL_ON:-}" ]]; then
      echo "stub: upload failed" >&2
      exit 1
    fi
    ;;
  *) echo "stub cargo: unexpected subcommand '${1:-}'" >&2; exit 99 ;;
esac
STUB
chmod +x "${STUB_DIR}/bin/cargo"

# Fixture index for the loop: alpha 1.0.0 is already published, beta and
# gamma are not — a partly-published tag, exactly the situation being
# resumed.
LOOP_INDEX="${STUB_DIR}/index"
mkdir -p "${LOOP_INDEX}"
INDEX_BASE="${LOOP_INDEX}" write_index alpha "$(json_line alpha 1.0.0 false)"

run_loop() {
  # Args: <index-dir> [crate-to-fail-on]; echoes the exit status.
  local rc=0
  rm -f "${STUB_DIR}/published.log"
  : > "${STUB_DIR}/published.log"
  PATH="${STUB_DIR}/bin:${PATH}" \
  CARGO_STUB_DIR="${STUB_DIR}" \
  CARGO_STUB_FAIL_ON="${2:-}" \
  HORT_INDEX_FIXTURE_DIR="$1" \
  HORT_PUBLISH_PROPAGATION_SLEEP=0 \
    "${REPO_ROOT}/scripts/ci/publish-crates.sh" https://registry.example hort-crates \
    > "${STUB_DIR}/run.log" 2>&1 || rc=$?
  echo "${rc}"
}

published_log() { tr '\n' ' ' < "${STUB_DIR}/published.log" | sed 's/ $//'; }

# 1. Resume over a partly-published tag.
rc="$(run_loop "${LOOP_INDEX}")"
if [[ "${rc}" == "0" ]]; then
  pass "a resumed publish exits 0"
else
  fail "a resumed publish exits 0 (got ${rc}); log: $(cat "${STUB_DIR}/run.log")"
fi

if [[ "$(published_log)" == "beta gamma" ]]; then
  pass "the already-published crate is skipped and the rest are uploaded, in order"
else
  fail "expected 'beta gamma' uploaded, got '$(published_log)'"
fi

if grep -q "Skipping .*alpha 1.0.0 is already published" "${STUB_DIR}/run.log"; then
  pass "the skip is logged by crate and version"
else
  fail "the skip is logged by crate and version; log: $(cat "${STUB_DIR}/run.log")"
fi

# 2. A fresh publish uploads everything.
EMPTY_INDEX="${STUB_DIR}/empty-index"
mkdir -p "${EMPTY_INDEX}"
rc="$(run_loop "${EMPTY_INDEX}")"
if [[ "${rc}" == "0" && "$(published_log)" == "alpha beta gamma" ]]; then
  pass "a fresh publish uploads the whole set in dependency order"
else
  fail "a fresh publish uploads the whole set in dependency order (exit ${rc}, got '$(published_log)')"
fi

# 3. THE constraint: a failing upload is never treated as a skip.
#
# This is the one that must never regress. A loop that continued past a
# non-zero `cargo publish` would ship a release with crates missing and
# say nothing, which is strictly worse than the loud break it replaced.
rc="$(run_loop "${EMPTY_INDEX}" beta)"
if [[ "${rc}" != "0" ]]; then
  pass "a failing upload fails the run"
else
  fail "a failing upload fails the run (got exit 0)"
fi

if [[ "$(published_log)" == "alpha beta" ]]; then
  pass "the run stops at the failure — nothing after it is attempted"
else
  fail "the run stops at the failure (expected 'alpha beta', got '$(published_log)')"
fi

echo
echo "──────────────────────────────────────────────────────────────────────"
echo "passed: ${PASS}   failed: ${FAIL}"
[[ "${FAIL}" -eq 0 ]]
