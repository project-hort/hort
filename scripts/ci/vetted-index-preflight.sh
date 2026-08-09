#!/usr/bin/env bash
#
# scripts/ci/vetted-index-preflight.sh — cold-dep check against a vetted
# (released_only) cargo index.
#
# Usage:
#   scripts/ci/locked-registry-deps.sh | \
#     scripts/ci/vetted-index-preflight.sh <hort-base-url> <repo-key>
#
#   Reads the locked set as "name version" pairs, one per line, on stdin
#   (the output shape of locked-registry-deps.sh). Positional args carry the
#   non-secret call shape (base URL, repo key); the bearer is intentionally
#   NOT a positional arg (it would leak into `ps`/CI job logs echoing the
#   command line) — it comes from the HORT_TOKEN environment variable.
#
# Behaviour:
#   cargo-virtual (and any released_only repo) is released_only
#   (NonServableStatusFilter + IndexModeFilter, hort-http-cargo/src/serve.rs):
#   a locked dep hort has never ingested, or is still inside its quarantine
#   window, is simply absent from the served index. This script enumerates
#   every such cold dep up front instead of discovering them one at a time
#   via a serial `cargo publish`/`cargo fetch` failure.
#
#   Prints every cold "name version" pair to stdout and exits non-zero iff
#   the cold set is non-empty. Performs NO side effects — no prefetch POST.
#   The caller decides whether, and how, to warm the cold set and whether a
#   non-empty cold set is fatal.
#
# Extracted verbatim-in-behavior from the inline preflight block #137 landed
# in .github/workflows/release.yml (issue #138 / backlog 097) — this is the
# single implementation now shared by that workflow's preflight step and the
# GitLab `prefetch:warm` / `prefetch:verify` jobs.

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $(basename "$0") <hort-base-url> <repo-key>  (bearer via \$HORT_TOKEN)" >&2
  exit 2
fi

hort_url="$1"
repo_key="$2"
: "${HORT_TOKEN:?HORT_TOKEN must be set to a bearer token}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

locked_file="${tmpdir}/locked.txt"
cat > "${locked_file}"

locked_count=$(wc -l < "${locked_file}")
cut -d' ' -f1 "${locked_file}" | sort -u > "${tmpdir}/names.txt"
name_count=$(wc -l < "${tmpdir}/names.txt")
echo "Locked registry deps: ${locked_count} (${name_count} distinct names)" >&2

# Cargo sparse-index prefix rule (lowercased name):
#   1 char  -> 1/{n}
#   2 chars -> 2/{n}
#   3 chars -> 3/{n[0]}/{n}
#   else    -> {n[0:2]}/{n[2:4]}/{n}
prefix_path() {
  local n len
  n=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  len=${#n}
  if [ "${len}" -eq 1 ]; then
    printf '1/%s' "${n}"
  elif [ "${len}" -eq 2 ]; then
    printf '2/%s' "${n}"
  elif [ "${len}" -eq 3 ]; then
    printf '3/%s/%s' "${n:0:1}" "${n}"
  else
    printf '%s/%s/%s' "${n:0:2}" "${n:2:2}" "${n}"
  fi
}
export -f prefix_path

# One GET per distinct name, bounded parallelism. A non-200 (or a curl
# failure) is recorded as an empty served set — fail closed, since an index
# we could not reach must be treated as not having the version yet, not as
# silently passing the check.
fetch_one() {
  local name path outfile status
  name="$1"
  path="$(prefix_path "${name}")"
  outfile="${tmpdir}/served/${name}"
  status=$(curl -sS -o "${outfile}" -w '%{http_code}' \
    -H "Authorization: Bearer ${HORT_TOKEN}" \
    "${hort_url}/cargo/${repo_key}/${path}") || status=000
  if [ "${status}" != "200" ]; then
    : > "${outfile}"
  fi
}
export -f fetch_one
export tmpdir hort_url repo_key HORT_TOKEN

mkdir -p "${tmpdir}/served"
xargs -P8 -I{} bash -c 'fetch_one "$@"' _ {} < "${tmpdir}/names.txt"

# A locked (name, version) is COLD if its name's served set is empty
# (non-200 above) or the exact version string is absent from the served
# `.vers` entries.
cold_file="${tmpdir}/cold.txt"
: > "${cold_file}"
while read -r name version; do
  served="${tmpdir}/served/${name}"
  if [ ! -s "${served}" ] || \
     ! jq -e --arg v "${version}" 'select(.vers == $v)' "${served}" >/dev/null 2>&1; then
    echo "${name} ${version}" >> "${cold_file}"
  fi
done < "${locked_file}"

if [ -s "${cold_file}" ]; then
  cold_count=$(wc -l < "${cold_file}")
  echo "${cold_count} locked dependency version(s) are cold (not served by ${repo_key}):" >&2
  cat "${cold_file}"
  exit 1
fi

echo "Vetted-index preflight OK — ${locked_count} locked deps (${name_count} distinct names) all served by ${repo_key}." >&2
exit 0
