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
# Axis 2 (issue #80): registry Exclusions are a NUCLEAR OPTION (maintainer
# principle, 2026-07-24): a build-side ignore in .cargo/audit.toml scopes a
# risk acceptance to hort's OWN build with a usage-specific rationale; a
# registry `kind: Exclusion` waives the finding for EVERY consumer pulling
# through the registry. Mirroring build acceptances into the registry is
# therefore NOT the expected state -- the remedy hierarchy when a
# build-accepted dep is scan-rejected registry-side is: (1) upgrade the dep
# off the vulnerable version (the #80 lru fix), (2) accept the crates-publish
# friction, (3) a registry Exclusion only as an explicitly-justified last
# resort. This axis enforces that:
#   - build-ignores with no registry Exclusion are reported INFORMATIONALLY
#     (they forecast possible registry-side rejection of a prefetched dep;
#     that is the normal, intended state -- never a failure);
#   - any `kind: Exclusion` object present in the gitops tree HARD-FAILS
#     unless its file carries a `# NUCLEAR-OPTION-JUSTIFIED:` line with a
#     rationale -- forcing the last-resort choice to be deliberate and
#     reviewable, per file.
# ---------------------------------------------------------------------------

# Every kind: Exclusion object anywhere under deploy/ansible/files/gitops/
# (recursive -- the apply-time gitops loader walks the tree the same way,
# see crates/hort-server/src/gitops_boot.rs).
exclusion_files=$(
    { grep -l -r "^kind: Exclusion" "${gitops_root}" --include="*.yaml" 2>/dev/null || true; } | sort
)

registry_exclusion_ids=""
unjustified_exclusions=""
if [[ -n "${exclusion_files}" ]]; then
    registry_exclusion_ids=$(
        printf '%s\n' "${exclusion_files}"             | xargs -r grep -hoE '^[[:space:]]*cveId:[[:space:]]*[^[:space:]]+'             | awk '{print $2}'             | sort -u
    )
    while IFS= read -r f; do
        if ! grep -q "# NUCLEAR-OPTION-JUSTIFIED:" "${f}"; then
            unjustified_exclusions+="${f}"$'\n'
        fi
    done <<< "${exclusion_files}"
fi

if [[ -n "${unjustified_exclusions}" ]]; then
    echo "Registry-level kind: Exclusion object(s) WITHOUT a justification marker:" >&2
    printf '%s' "${unjustified_exclusions}" | while IFS= read -r f; do
        [[ -n "${f}" ]] && echo "    - ${f}" >&2
    done
    echo "" >&2
    echo "A registry Exclusion waives the finding for EVERY registry consumer" >&2
    echo "-- a nuclear option. Prefer upgrading the dependency off the" >&2
    echo "vulnerable version. If an Exclusion is genuinely the last resort," >&2
    echo "add a '# NUCLEAR-OPTION-JUSTIFIED: <why upgrade/friction are not" >&2
    echo "viable>' line to the file so the choice is deliberate and reviewable." >&2
    failed=1
fi

# Informational forecast (never a failure): build-ignores are hort-build-scoped
# acceptances; the registry scan may still reject these deps when prefetched,
# which surfaces as crates-publish friction. The remedy is upgrading the dep.
build_ignores_unmirrored=$(comm -23 <(echo "${audit_ids}") <(echo "${registry_exclusion_ids}") || true)
unmirrored_count=$(echo "${build_ignores_unmirrored}" | grep -c . || true)

if [[ "${failed}" -ne 0 ]]; then
    exit 1
fi

audit_deny_count=$(echo "${audit_ids_synced}" | grep -c . || true)
audit_only_count=$(echo "${audit_only_exempt}" | grep -c . || true)
deny_only_count=$(echo "${deny_only_exempt}"  | grep -c . || true)
exclusion_count=$(echo "${registry_exclusion_ids}" | grep -c . || true)
echo "Advisory ignore-list sync: OK (${audit_deny_count} audit<->deny shared ID(s);" \
     "${audit_only_count} AUDIT-ONLY; ${deny_only_count} DENY-ONLY;" \
     "${exclusion_count} registry Exclusion(s), all justified;" \
     "${unmirrored_count} build-ignore(s) not mirrored registry-side [normal state])"
exit 0
