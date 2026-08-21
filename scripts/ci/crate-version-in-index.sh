#!/usr/bin/env bash
#
# scripts/ci/crate-version-in-index.sh — is this exact crate version already
# in a hort cargo index?
#
# Usage:
#   scripts/ci/crate-version-in-index.sh <hort-base-url> <repo-key> <name> <version>
#
# Exit status IS the verdict:
#   0 — the exact name@version is present in the served index. A publish of
#       it would be refused by cargo, so the caller should SKIP it.
#   1 — not present, or presence could not be established. The caller should
#       PUBLISH.
#   2 — usage error (wrong argument count).
#
# Environment:
#   HORT_TOKEN              optional bearer for the index read (see below)
#   HORT_INDEX_FIXTURE_DIR  optional; read the index document from a local
#                           tree instead of fetching (see "Offline mode")
#
# ── Why the verdict is one-directional ──────────────────────────────────────
#
# Only a POSITIVE observation — a served index document containing the exact
# version string — yields 0. A 404, a non-200, an unreachable index, a
# malformed body: every one of those is 1.
#
# That asymmetry is the whole safety argument. A wrong 1 costs nothing: the
# caller publishes, and if the version really was there, cargo refuses and
# the job fails loudly exactly as it does today. A wrong 0 is a silently
# skipped crate in a shipped release. So this script never infers presence,
# and it never reports presence from an error it merely failed to interpret.
#
# For the same reason the decision must be made BEFORE the publish attempt,
# never from cargo's exit status afterwards: at that point a refusal to
# republish and a genuine upload failure are the same non-zero, and a loop
# that continues past either one ships a release with crates missing.
#
# ── Why the read is authenticated ───────────────────────────────────────────
#
# Not because the index requires it — a public repository serves its index to
# anyone. Because hort's served index is IDENTITY-DEPENDENT: a principal with
# granted write authority on a repository also resolves versions still inside
# that repository's observation window, which no anonymous reader sees
# (ADR 0055). Cargo performs its own refusal check against the index AS THE
# PUBLISHING IDENTITY, so a check made under a narrower identity can answer a
# different question than the one cargo is about to ask.
#
# The token is therefore optional but wanted: pass the publishing identity's
# and this observes what cargo will observe. Without it the read still works
# against a public repo and can only ever see FEWER versions, which by the
# asymmetry above degrades to a redundant publish attempt, never to a wrong
# skip.
#
# ── Offline mode ────────────────────────────────────────────────────────────
#
# With HORT_INDEX_FIXTURE_DIR set, the index document is read from
# "${HORT_INDEX_FIXTURE_DIR}/<sparse-index-path>" and no network call is
# made; a missing file is the 404 case. This is what makes the verdict
# testable without a live registry — see scripts/test-crate-version-in-index.sh.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci/lib-cargo-sparse-index.sh
source "${script_dir}/lib-cargo-sparse-index.sh"

if [[ $# -ne 4 ]]; then
  echo "usage: $(basename "$0") <hort-base-url> <repo-key> <name> <version>" >&2
  exit 2
fi

hort_url="${1%/}"
repo_key="$2"
name="$3"
version="$4"

path="$(cargo_sparse_index_path "${name}")"

body="$(mktemp)"
trap 'rm -f "${body}"' EXIT

if [[ -n "${HORT_INDEX_FIXTURE_DIR:-}" ]]; then
  fixture="${HORT_INDEX_FIXTURE_DIR}/${path}"
  if [[ ! -f "${fixture}" ]]; then
    echo "index: ${name} not in fixture index (${fixture})" >&2
    exit 1
  fi
  cat "${fixture}" > "${body}"
else
  auth=()
  if [[ -n "${HORT_TOKEN:-}" ]]; then
    auth=(-H "Authorization: Bearer ${HORT_TOKEN}")
  else
    echo "index: no HORT_TOKEN — reading ${repo_key} anonymously, which sees only released versions" >&2
  fi

  # "${auth[@]+...}" — an unset-safe expansion of a possibly-empty array,
  # which a bare "${auth[@]}" is not under `set -u` on older bash.
  status=$(curl -sS -o "${body}" -w '%{http_code}' \
    "${auth[@]+"${auth[@]}"}" \
    "${hort_url}/cargo/${repo_key}/${path}") || status=000

  if [[ "${status}" == "404" ]]; then
    echo "index: ${name} not in ${repo_key} index" >&2
    exit 1
  fi
  if [[ "${status}" != "200" ]]; then
    # Undetermined, not absent — say so, then answer "publish". Cargo is
    # about to read the same index and will produce the authoritative
    # error if this was a real outage.
    echo "index: ${repo_key} returned HTTP ${status} for ${name} — treating as not published" >&2
    exit 1
  fi
fi

# The served document is NDJSON, one object per version. Presence is decided
# on `vers` alone: a yanked version still occupies its version number and
# cargo still refuses to republish over it, so `yanked` is deliberately not
# consulted.
if jq -e --arg v "${version}" 'select(.vers == $v)' "${body}" >/dev/null 2>&1; then
  echo "index: ${name} ${version} is already published to ${repo_key}" >&2
  exit 0
fi

echo "index: ${name} ${version} is not in the ${repo_key} index" >&2
exit 1
