#!/usr/bin/env bash
#
# scripts/check-attribution.sh — third-party attribution staleness +
# allowlist-parity gate.
#
# Two independent checks:
#
#   1. Staleness (structural): regenerates the attribution and compares the
#      per-crate (name, version, SPDX, URL) SET of the fresh JSON against the
#      committed JSON. That set is the dependency graph's identity — a
#      crate@version's license is immutable on crates.io, so once the set
#      matches, the committed attribution is not stale. The raw license TEXT is
#      deliberately NOT byte-compared: cargo-about, for a crate shipping several
#      license files with the same SPDX (e.g. miniz_oxide ships both `LICENSE`
#      and `LICENSE-MIT.md`, both MIT, differing only by a blank line), selects
#      one by filesystem-enumeration order, which is not stable across
#      environments. A byte-diff flakes on that cosmetic, legally-meaningless
#      difference. The SPDX field is part of the compared tuple, so a pick of a
#      genuinely different license (a different SPDX) IS caught; only same-SPDX
#      whitespace variance is tolerated. A real change — dependency
#      added/removed, or version/SPDX/URL changed — still fails and names the
#      crate.
#   2. Allowlist parity: about.toml's `accepted` license list must equal
#      deny.toml's `[licenses] allow` list (same SPDX set — see both files'
#      header comments). A divergence means a license `cargo deny check
#      licenses` would accept could ship with no corresponding attribution
#      entry, or vice versa.
#
# Run by:
#   - `.gitlab-ci.yml`               (security:attribution-sync stage)
#   - `.github/workflows/ci.yml`     (attribution-sync job)
#   - locally before pushing a dependency change
#
# Requires `cargo-about` (via scripts/regenerate-attribution.sh, which this
# calls and which prepends $CARGO_HOME/bin to PATH so a CI-binstalled binary is
# found under GitLab's project-local CARGO_HOME).

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
# Check 1: structural staleness. Regenerate, snapshot the fresh JSON, restore
# the working tree, then compare the (name, version, SPDX, URL) set. See the
# header note for why the license text itself is not byte-compared.
# ---------------------------------------------------------------------------
committed_json="$(mktemp)"
fresh_json="$(mktemp)"
trap 'rm -f "${committed_json}" "${fresh_json}"' EXIT

git show "HEAD:${json_file}" > "${committed_json}"

echo "Regenerating third-party attribution for structural comparison..." >&2
bash "${repo_root}/scripts/regenerate-attribution.sh" >&2
cp "${json_file}" "${fresh_json}"

# regenerate-attribution.sh rewrote the artifacts in place; restore the working
# tree so a cosmetic license-text difference (the thing we intentionally ignore)
# does not leave it dirty for callers.
git checkout -- "${md_file}" "${json_file}"

if ! python3 - "${committed_json}" "${fresh_json}" <<'PY'
import json
import sys


def graph(path):
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    # Structural identity of the dependency graph. license_text is excluded on
    # purpose (see the script header): a crate@version's license is immutable,
    # so this set fully captures whether the committed attribution is stale.
    return {
        (e["name"], e["version"], e.get("spdx", ""), e.get("url", ""))
        for e in doc
    }


committed = graph(sys.argv[1])
fresh = graph(sys.argv[2])

if committed == fresh:
    print(
        "Third-party attribution staleness check: OK "
        f"({len(fresh)} crates; dependency graph matches the committed attribution)"
    )
    sys.exit(0)

removed = sorted(committed - fresh)
added = sorted(fresh - committed)
print(
    "error: third-party attribution is stale — the compiled dependency graph "
    "changed but THIRD-PARTY-LICENSES.{md,json} were not regenerated:",
    file=sys.stderr,
)
for name, ver, spdx, _ in removed:
    print(f"  - {name} {ver} ({spdx})", file=sys.stderr)
for name, ver, spdx, _ in added:
    print(f"  + {name} {ver} ({spdx})", file=sys.stderr)
print(
    "\n  run scripts/regenerate-attribution.sh and commit the result.",
    file=sys.stderr,
)
sys.exit(1)
PY
then
    exit 1
fi

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
