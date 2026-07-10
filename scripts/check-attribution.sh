#!/usr/bin/env bash
#
# scripts/check-attribution.sh — third-party attribution staleness +
# allowlist-parity gate.
#
# Two independent checks:
#
#   1. Staleness: runs `scripts/regenerate-attribution.sh` (the same script a
#      developer runs locally) and diffs its output against the committed
#      `THIRD-PARTY-LICENSES.{md,json}`. A non-empty diff means the compiled
#      dependency graph moved since the committed artifacts were generated
#      (typically: a dependency was added/changed/removed and the attribution
#      wasn't regenerated in the same change). Delegating to the regenerate
#      script — rather than reimplementing its `cargo about generate` calls —
#      means this gate automatically inherits the exact CRLF-normalization and
#      JSON trailing-comma handling the regenerate script performs, so the
#      comparison never spuriously fails on line-ending or formatting noise.
#   2. Allowlist parity: `about.toml`'s `accepted` license list must equal
#      `deny.toml`'s `[licenses] allow` list (same SPDX set, same permissive
#      graph — see the header comments on both files). A divergence means a
#      license `cargo deny check licenses` would accept could ship with no
#      corresponding attribution entry, or vice versa.
#
# Run by:
#   - `.gitlab-ci.yml`               (security:attribution-sync stage)
#   - `.github/workflows/ci.yml`     (attribution-sync job)
#   - locally before pushing a dependency change
#
# Requires `cargo-about` on PATH (same requirement as
# `scripts/regenerate-attribution.sh`, which this script calls).

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

about_toml="${repo_root}/about.toml"
deny_toml="${repo_root}/deny.toml"
md_file="THIRD-PARTY-LICENSES.md"
json_file="THIRD-PARTY-LICENSES.json"

for f in "${about_toml}" "${deny_toml}" "${md_file}" "${json_file}"; do
    if [[ ! -f "$f" ]]; then
        echo "error: $f not found" >&2
        exit 2
    fi
done

# ---------------------------------------------------------------------------
# Check 1: staleness — regenerate in place, then diff against the committed
# copies. `regenerate-attribution.sh` writes both files in place (the same
# artifacts `git diff` below inspects), so a tree that was already in sync
# comes out of this step byte-identical to how it went in.
# ---------------------------------------------------------------------------
echo "Regenerating third-party attribution artifacts for comparison..." >&2
bash "${repo_root}/scripts/regenerate-attribution.sh" >&2

if ! git diff --exit-code -- "${md_file}" "${json_file}"; then
    echo "" >&2
    echo "error: third-party attribution is stale — run scripts/regenerate-attribution.sh and commit the result" >&2
    exit 1
fi
echo "Third-party attribution staleness check: OK (committed artifacts match a fresh regeneration)"

# ---------------------------------------------------------------------------
# Check 2: allowlist parity — about.toml's `accepted` array must be the same
# SPDX set as deny.toml's `[licenses] allow` array. Both arrays open with
# "<name> = [" and close with "]" alone on its own line (true for both files
# today), so a line-range extraction is safe without a real TOML parser —
# BUT deny.toml also has an unrelated `[bans] allow = []` a few sections
# later, so the extraction must first clip to the `[licenses]` table (from
# its header line up to, but excluding, the next line that opens a new
# table) before searching for the array; otherwise the line-range would
# reopen at the `[bans]` occurrence and run all the way to a much later
# closing bracket, sweeping in unrelated entries.
# ---------------------------------------------------------------------------
extract_array() {
    # Args: <file> <array-name> [<section-header-exact-line>]
    local file="$1" array_name="$2" section_header="${3:-}" content
    if [[ -n "${section_header}" ]]; then
        content=$(awk -v hdr="${section_header}" '
            $0 == hdr { in_section=1; next }
            in_section && /^\[/ { in_section=0 }
            in_section { print }
        ' "${file}")
    else
        content=$(cat "${file}")
    fi
    echo "${content}" | sed -n "/^${array_name} = \[/,/^\]/p" | grep -oE '"[^"]*"' | tr -d '"' | sort -u
}

accepted_licenses=$(extract_array "${about_toml}" "accepted")
allow_licenses=$(extract_array "${deny_toml}" "allow" "[licenses]")

if [[ -z "${accepted_licenses}" ]]; then
    echo "error: could not extract about.toml's 'accepted' array (empty or missing)" >&2
    exit 2
fi
if [[ -z "${allow_licenses}" ]]; then
    echo "error: could not extract deny.toml's '[licenses] allow' array (empty or missing)" >&2
    exit 2
fi

# `comm` requires sorted input (extract_array already sorts); -23 = lines
# only in file 1, -13 = lines only in file 2.
only_in_about=$(comm -23 <(echo "${accepted_licenses}") <(echo "${allow_licenses}") || true)
only_in_deny=$(comm -13 <(echo "${accepted_licenses}") <(echo "${allow_licenses}") || true)

if [[ -n "${only_in_about}" || -n "${only_in_deny}" ]]; then
    echo "error: about.toml 'accepted' and deny.toml '[licenses] allow' diverge:" >&2
    if [[ -n "${only_in_about}" ]]; then
        echo "  only in about.toml 'accepted':" >&2
        while IFS= read -r id; do
            echo "    - ${id}" >&2
        done <<< "${only_in_about}"
    fi
    if [[ -n "${only_in_deny}" ]]; then
        echo "  only in deny.toml '[licenses] allow':" >&2
        while IFS= read -r id; do
            echo "    - ${id}" >&2
        done <<< "${only_in_deny}"
    fi
    echo "" >&2
    echo "Update both files so they match — see the parity note in about.toml's" >&2
    echo "header comment and deny.toml's [licenses] section." >&2
    exit 1
fi

count=$(echo "${accepted_licenses}" | grep -c . || true)
echo "Attribution allowlist parity: OK (${count} shared SPDX identifier(s))"
