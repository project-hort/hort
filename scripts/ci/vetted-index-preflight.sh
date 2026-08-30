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
# Single implementation, shared by .github/workflows/release.yml's preflight
# step and the GitLab `prefetch:warm` / `prefetch:verify` jobs.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci/lib-cargo-sparse-index.sh
source "${script_dir}/lib-cargo-sparse-index.sh"

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

# The sparse-index prefix rule lives in lib-cargo-sparse-index.sh, shared
# with the publish-time index check. `export -f` carries it into the `xargs
# bash -c` subshells below, which do not inherit it by sourcing.
export -f cargo_sparse_index_path

# One GET per distinct name, bounded parallelism. A non-200 (or a curl
# failure) is recorded as an empty served set — fail closed, since an index
# we could not reach must be treated as not having the version yet, not as
# silently passing the check.
fetch_one() {
  local name path outfile status
  name="$1"
  path="$(cargo_sparse_index_path "${name}")"
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

# Best-effort per-dep release-time annotation (stderr only — see the
# stdout-contract note at the call site). Resolves the repo's `dl`
# download-URL template once via the served config.json (the same shape a
# real cargo client uses; RFC 3231 does not fix it, so hard-coding the
# `api/v1/crates` path here would silently drift if the served template
# ever changes), then does one read-only probe per cold dep against
# `{dl}/{name}/{version}/download` and reads the quarantine gate's own
# `Retry-After` (render_cargo_crate_response, hort-http-cargo) to report an
# absolute release time instead of leaving the operator to poll blind.
#
# A 404 gets no derived time: released_only omits an unreleased version
# from the index the same way it omits a still-quarantined one, so a 404
# here means hort has never even started that dep's quarantine window —
# there is no deadline yet to report, and printing one would fabricate a
# guarantee the server never made.
annotate_cold_deps() {
  local cold="$1"
  local config_body config_status dl_template
  local probe_headers name version probe_status retry_after release_time
  local -a release_timestamps=()
  local saw_404=0

  config_body="${tmpdir}/config.json"
  config_status=$(curl -sS -o "${config_body}" -w '%{http_code}' --max-time 10 \
    -H "Authorization: Bearer ${HORT_TOKEN}" \
    "${hort_url}/cargo/${repo_key}/config.json") || config_status=000

  dl_template=""
  if [ "${config_status}" = "200" ]; then
    dl_template=$(jq -r '.dl // empty' "${config_body}" 2>/dev/null) || dl_template=""
  fi
  if [ -z "${dl_template}" ]; then
    echo "vetted-index-preflight: config.json fetch failed (status ${config_status}) or missing 'dl' — falling back to the crates api path for release-time annotation" >&2
    dl_template="${hort_url}/cargo/${repo_key}/api/v1/crates"
  fi

  probe_headers="${tmpdir}/probe_headers"
  while read -r name version; do
    : > "${probe_headers}"
    # Same bearer as every other request in this script: the vetted repo is
    # auth-required in CI, and an unauthenticated probe would answer 401 for
    # every dep — honest but useless annotation.
    probe_status=$(curl -sS -o /dev/null -D "${probe_headers}" -w '%{http_code}' --max-time 10 \
      -H "Authorization: Bearer ${HORT_TOKEN}" \
      "${dl_template}/${name}/${version}/download") || probe_status=000

    case "${probe_status}" in
      503)
        retry_after=$(grep -i '^retry-after:' "${probe_headers}" | tail -n1 | cut -d: -f2- | tr -d ' \r\t') \
          || retry_after=""
        release_time=""
        if [[ "${retry_after}" =~ ^[0-9]+$ ]]; then
          release_time=$(date -u -d "+${retry_after} seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) \
            || release_time=""
        fi
        if [ -n "${release_time}" ]; then
          echo "  ${name} ${version} — releases at ${release_time}" >&2
          release_timestamps+=("${release_time}")
        else
          echo "  ${name} ${version} — 503 (no usable Retry-After header)" >&2
        fi
        ;;
      404)
        echo "  ${name} ${version} — not yet ingested (window starts when the warm's fetch lands)" >&2
        saw_404=1
        ;;
      200)
        echo "  ${name} ${version} — already released (index refresh pending)" >&2
        ;;
      *)
        echo "  ${name} ${version} — ${probe_status}" >&2
        ;;
    esac
  done < "${cold}"

  if [ "${#release_timestamps[@]}" -gt 0 ]; then
    # The window closes only once every 503-derived dep has cleared, so the
    # useful "re-run after" instant is the MAX (latest) of the individual
    # release times, not the earliest.
    local earliest_clean
    earliest_clean=$(printf '%s\n' "${release_timestamps[@]}" | sort | tail -n1)
    local summary="earliest clean re-run: ${earliest_clean}"
    if [ "${saw_404}" -eq 1 ]; then
      summary="${summary} (plus deps not yet ingested — their windows have not started)"
    fi
    echo "${summary}" >&2
  fi
}

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
  # stdout below is a machine contract: release.yml captures it verbatim
  # into cold.txt and feeds the prefetch-warm POST from it (and the
  # GitLab prefetch:warm/verify jobs share this same script). Everything
  # from here to exit is stderr-only annotation and must never reorder,
  # filter or otherwise touch what has already gone to stdout, and must
  # never change the exit code below — a probe outage must degrade the
  # operator's context, not the check's fail-closed pass/fail result.
  cat "${cold_file}"

  annotate_cold_deps "${cold_file}"

  exit 1
fi

echo "Vetted-index preflight OK — ${locked_count} locked deps (${name_count} distinct names) all served by ${repo_key}." >&2
exit 0
