#!/usr/bin/env bash
#
# scripts/check-advisory-sync.sh — advisory ignore-list parity gate.
#
# Asserts two independent parity axes:
#
# 1. (original) The RUSTSEC advisory ignore list in `.cargo/audit.toml`
#    (single source of truth, consumed by `cargo audit`) and the matching
#    list in `deny.toml`'s `[advisories.ignore]` (consumed by `cargo deny
#    check`) are byte-identical sets. A divergence means one tool blocks
#    CI on an advisory the other accepts, leaving an unobserved gap.
#
# 2. (issue #80) Every build-side ignore in `.cargo/audit.toml` has a
#    matching `kind: Exclusion` object somewhere under
#    `deploy/ansible/files/gitops/` (unless marked `REGISTRY-EXEMPT`, the
#    same marker-naming convention as AUDIT-ONLY/DENY-ONLY). Without a
#    registry-side mirror, hort's own quarantine gate can reject a package
#    the build side has already decided is safe — exactly the failure
#    mode issue #80 hit once self-service prefetch let CI warm its own
#    dependency closure through `crates-proxy`. The REVERSE direction (a
#    registry Exclusion with no build-side acceptance) is reported as a
#    **warning only** — the registry may legitimately exclude more than
#    hort's own Cargo.lock ever ignores (e.g. a finding on a dependency of
#    some OTHER scanned package, not hort itself), and a GHSA-keyed
#    registry Exclusion that aliases an already-covered RUSTSEC id (see
#    `hort_domain::policy::exclusion::cve_matches`'s alias matching) will
#    always show up here too — this script does not resolve advisory
#    aliases, by design (same "no external parser" trade-off as below).
#
# Run by:
#   - `.github/workflows/ci.yml`            (security-audit-sync job)
#   - `.gitlab-ci.yml`                      (security:advisory-sync stage)
#   - locally before pushing audit-config changes
#
# Implementation: plain bash + grep + sort + comm. No external TOML/YAML
# parser — the ignore lists are flat `"RUSTSEC-YYYY-NNNN"` arrays with
# `#`-prefixed comments inside, and the gitops `Exclusion` objects are
# flat `cveId: <ID>` lines, both of which a regex pass extracts cleanly.
# The trade-off vs `dasel` / `yq` is intentional: the CI image
# (`rust:1.94-slim`) ships neither, and pulling one in just for this
# script enlarges the supply-chain surface the gate is meant to guard.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
audit_toml="${repo_root}/.cargo/audit.toml"
deny_toml="${repo_root}/deny.toml"
gitops_root="${repo_root}/deploy/ansible/files/gitops"

if [[ ! -f "${audit_toml}" ]]; then
    echo "error: ${audit_toml} not found" >&2
    exit 2
fi
if [[ ! -f "${deny_toml}" ]]; then
    echo "error: ${deny_toml} not found" >&2
    exit 2
fi
if [[ ! -d "${gitops_root}" ]]; then
    echo "error: ${gitops_root} not found" >&2
    exit 2
fi

# Accumulates across BOTH axes so a run reports every problem at once
# rather than stopping at the first.
failed=0

# Extract every QUOTED RUSTSEC-YYYY-NNNN token, i.e. an actual ignore-
# list entry (`"RUSTSEC-YYYY-NNNN"`). Both files share the same shape:
#
#     ignore = [
#         # rationale comment
#         "RUSTSEC-YYYY-NNNN",
#         ...
#     ]
#
# Quoting is the discriminator that separates a real ignore entry from
# a prose mention of an ID in some other comment block (e.g. a
# `[bans]`-section comment that cites an advisory by ID without
# ignoring it). The regex therefore requires the surrounding double
# quotes, not just the ID body.
#
# Tool-specific exceptions: an entry whose preceding comment block
# contains `AUDIT-ONLY: RUSTSEC-YYYY-NNNN` (in `.cargo/audit.toml`) or
# `DENY-ONLY: RUSTSEC-YYYY-NNNN` (in `deny.toml`) is intentionally
# unsynced. The two tools walk the dependency graph differently —
# `cargo audit` over `Cargo.lock`, `cargo deny` over the active build
# graph excluding unused features — so an advisory reachable only via
# an unused feature must be ignored by `cargo audit` while `cargo
# deny` rejects the same ignore as `advisory-not-detected`. The
# marker tags the divergence as deliberate. The marker line MUST
# name the exact ID it exempts so a later edit cannot drift from it.
#
# `grep -oE` extracts each match on its own line; `tr` strips the
# quotes; `sort -u` deduplicates.
extract_ids() {
    grep -oE '"RUSTSEC-[0-9]{4}-[0-9]{4}"' "$1" | tr -d '"' | sort -u
}

extract_exemptions() {
    # Args: <file> <marker-prefix>   (e.g. AUDIT-ONLY or DENY-ONLY)
    # `grep` returns 1 when no match; under `set -e -o pipefail` that
    # would kill the script. The `|| true` is intentional — an empty
    # exemption set is a legitimate, common state.
    { grep -oE "${2}: RUSTSEC-[0-9]{4}-[0-9]{4}" "$1" || true; } \
        | awk '{print $2}' \
        | sort -u
}

audit_ids=$(extract_ids "${audit_toml}")
deny_ids=$(extract_ids "${deny_toml}")

audit_only_exempt=$(extract_exemptions "${audit_toml}" "AUDIT-ONLY")
deny_only_exempt=$(extract_exemptions "${deny_toml}" "DENY-ONLY")

# An exemption marker only counts when the named ID is actually present
# in its own file. A typo / orphan marker is a hard failure.
orphan_audit_markers=$(comm -23 <(echo "${audit_only_exempt}") <(echo "${audit_ids}") || true)
orphan_deny_markers=$(comm -23 <(echo "${deny_only_exempt}") <(echo "${deny_ids}") || true)
if [[ -n "${orphan_audit_markers}" || -n "${orphan_deny_markers}" ]]; then
    echo "Orphan exemption marker(s) (named ID not present in same file):" >&2
    [[ -n "${orphan_audit_markers}" ]] && echo "  .cargo/audit.toml AUDIT-ONLY: ${orphan_audit_markers}" >&2
    [[ -n "${orphan_deny_markers}" ]]  && echo "  deny.toml DENY-ONLY: ${orphan_deny_markers}" >&2
    failed=1
fi

# Comparison sets exclude the IDs explicitly exempted from sync.
audit_ids_synced=$(comm -23 <(echo "${audit_ids}") <(echo "${audit_only_exempt}") || true)
deny_ids_synced=$(comm -23 <(echo "${deny_ids}")  <(echo "${deny_only_exempt}")  || true)

# `comm` requires sorted input (we sort above); -23 = lines only in 1,
# -13 = lines only in 2.
only_in_audit=$(comm -23 <(echo "${audit_ids_synced}") <(echo "${deny_ids_synced}") || true)
only_in_deny=$(comm -13 <(echo "${audit_ids_synced}") <(echo "${deny_ids_synced}") || true)

if [[ -n "${only_in_audit}" || -n "${only_in_deny}" ]]; then
    echo "Advisory ignore-list mismatch (audit.toml <-> deny.toml):" >&2
    if [[ -n "${only_in_audit}" ]]; then
        echo "  only in .cargo/audit.toml:" >&2
        while IFS= read -r id; do
            echo "    - ${id}" >&2
        done <<< "${only_in_audit}"
    fi
    if [[ -n "${only_in_deny}" ]]; then
        echo "  only in deny.toml:" >&2
        while IFS= read -r id; do
            echo "    - ${id}" >&2
        done <<< "${only_in_deny}"
    fi
    echo "" >&2
    echo "Update both files so they match. The single source of truth is" >&2
    echo ".cargo/audit.toml; deny.toml's [advisories.ignore] is kept in sync" >&2
    echo "by this script." >&2
    failed=1
fi

# ---------------------------------------------------------------------------
# Axis 2 (issue #80): build-side ignore <-> registry Exclusion parity.
# ---------------------------------------------------------------------------

registry_only_exempt=$(extract_exemptions "${audit_toml}" "REGISTRY-EXEMPT")

orphan_registry_markers=$(comm -23 <(echo "${registry_only_exempt}") <(echo "${audit_ids}") || true)
if [[ -n "${orphan_registry_markers}" ]]; then
    echo "Orphan exemption marker(s) (named ID not present in .cargo/audit.toml):" >&2
    echo "  REGISTRY-EXEMPT: ${orphan_registry_markers}" >&2
    failed=1
fi

# Every kind: Exclusion object anywhere under deploy/ansible/files/gitops/
# (recursive -- the apply-time gitops loader walks the tree the same way,
# see crates/hort-server/src/gitops_boot.rs). A file is scanned for
# `cveId:` lines only when it also declares `kind: Exclusion`, so a
# same-named field on some other kind can never be mistaken for one.
registry_exclusion_ids=$(
    { grep -lZ -r "^kind: Exclusion" "${gitops_root}" --include="*.yaml" 2>/dev/null || true; } \
        | xargs -0 -r grep -hoE '^[[:space:]]*cveId:[[:space:]]*[^[:space:]]+' \
        | awk '{print $2}' \
        | sort -u
)

audit_ids_needing_registry=$(comm -23 <(echo "${audit_ids}") <(echo "${registry_only_exempt}") || true)

only_in_audit_no_registry=$(comm -23 <(echo "${audit_ids_needing_registry}") <(echo "${registry_exclusion_ids}") || true)
only_in_registry_no_audit=$(comm -13 <(echo "${audit_ids}") <(echo "${registry_exclusion_ids}") || true)

if [[ -n "${only_in_audit_no_registry}" ]]; then
    echo "Build-side advisory ignore(s) with no registry Exclusion mirror:" >&2
    while IFS= read -r id; do
        echo "    - ${id}" >&2
    done <<< "${only_in_audit_no_registry}"
    echo "" >&2
    echo "Add a matching kind: Exclusion under deploy/ansible/files/gitops/" >&2
    echo "(see policies/exclusions/ for examples), or mark the .cargo/audit.toml" >&2
    echo "entry REGISTRY-EXEMPT: <ID> with a one-line rationale if hort's own" >&2
    echo "scan surface genuinely does not need to mirror this acceptance." >&2
    failed=1
fi

if [[ -n "${only_in_registry_no_audit}" ]]; then
    echo "NOTE (warning only, not a failure): registry Exclusion(s) with no" >&2
    echo "matching .cargo/audit.toml build-side acceptance -- the registry may" >&2
    echo "legitimately exclude more than hort's own build ignores (or this is a" >&2
    echo "GHSA alias of an already-covered RUSTSEC id -- this script does not" >&2
    echo "resolve advisory aliases):" >&2
    while IFS= read -r id; do
        echo "    - ${id}" >&2
    done <<< "${only_in_registry_no_audit}"
fi

if [[ "${failed}" -ne 0 ]]; then
    exit 1
fi

audit_deny_count=$(echo "${audit_ids_synced}" | grep -c . || true)
audit_only_count=$(echo "${audit_only_exempt}" | grep -c . || true)
deny_only_count=$(echo "${deny_only_exempt}"  | grep -c . || true)
registry_count=$(echo "${audit_ids_needing_registry}" | grep -c . || true)
registry_exempt_count=$(echo "${registry_only_exempt}" | grep -c . || true)
echo "Advisory ignore-list sync: OK (${audit_deny_count} audit<->deny shared ID(s);" \
     "${audit_only_count} AUDIT-ONLY; ${deny_only_count} DENY-ONLY;" \
     "${registry_count} build-ignore(s) with a registry Exclusion mirror;" \
     "${registry_exempt_count} REGISTRY-EXEMPT)"
exit 0
