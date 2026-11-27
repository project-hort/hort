#!/usr/bin/env bash
#
# scripts/check-osv-scanner-version.sh — osv-scanner version lockstep gate.
#
# Asserts that the three independent osv-scanner version statements stay
# identical:
#
#   1. `docker/Dockerfile.worker` `ARG OSV_SCANNER_VERSION=...` — the version
#      baked into the worker container; the version the osv adapter
#      (`hort-adapters-scanner-osv`) is built and tested against.
#   2. `deploy/ansible/roles/hort_systemd/defaults/main.yml`
#      `hort_systemd_osv_version: "..."` — the version the native (non-k8s)
#      deploy downloads and installs on the host.
#   3. `docs/attribution/image-notice.md` — the hand-maintained NOTICE that
#      tells a reader which osv-scanner the shipped image bundles. It asks
#      for its own update in its own prose, which is an obligation a sentence
#      cannot hold; this gate holds it instead.
#
# Why this matters: the osv adapter invokes the v2 CLI
# (`osv-scanner scan source --format json --sbom <path>`). A v1.x binary has
# no `scan source` subcommand, so every scan exits non-zero, no artifact ever
# earns release authority, and the pull-through registry serves nothing
# (everything quarantines forever). Drift between the container pin (moved to
# v2) and the native pin (left on v1.9.1) is exactly that failure, and it is
# invisible to `helm template`, `cargo build`, and the Ansible lint — only a
# lint like this catches it.
#
# Comparison is EXACT (full version): the native binary must be the same
# osv-scanner the adapter was tested against, so even a patch difference is a
# drift worth flagging.
#
# Run by:
#   - the GitLab `quality:chart-and-rust-pin-sync` job
#   - locally before pushing changes to any of the three files
#
# No external TOML/YAML/Dockerfile parser — all three inputs are tiny and
# regular; bash + grep is enough and avoids enlarging the supply chain for
# one lint.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
dockerfile="${repo_root}/docker/Dockerfile.worker"
role_defaults="${repo_root}/deploy/ansible/roles/hort_systemd/defaults/main.yml"
image_notice="${repo_root}/docs/attribution/image-notice.md"

for f in "${dockerfile}" "${role_defaults}" "${image_notice}"; do
    if [[ ! -f "$f" ]]; then
        echo "error: $f not found" >&2
        exit 2
    fi
done

# Every occurrence a site's pattern matches is collected and reduced with
# `sort -u`, never `head -n1`. A file that grew a second osv-scanner version
# statement is exactly the drift this gate exists to catch, and taking the
# first match would check one and silently pass the other — a gate that
# cannot see one shape of the drift it is named for.
pins_matching() {
    grep -oE "$2" "$1" \
        | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' \
        | sort -u
}

# One unique version per site, or a diagnosis. `$1` names the site.
one_pin() {
    local label="$1" file="$2" pattern="$3" pins count
    pins=$(pins_matching "${file}" "${pattern}")
    count=$(printf '%s' "${pins}" | grep -c . || true)
    if [[ "${count}" -eq 0 ]]; then
        echo "error: could not extract an osv-scanner version from ${label}" >&2
        exit 2
    fi
    if [[ "${count}" -gt 1 ]]; then
        echo "error: ${label} names more than one osv-scanner version:" >&2
        printf '  %s\n' ${pins} >&2
        echo "Every osv-scanner reference in one file must name the same release." >&2
        exit 1
    fi
    printf '%s' "${pins}"
}

# `ARG OSV_SCANNER_VERSION=2.7.1` → 2.7.1
dockerfile_pin=$(one_pin \
    "docker/Dockerfile.worker ARG OSV_SCANNER_VERSION" \
    "${dockerfile}" \
    '^ARG[[:space:]]+OSV_SCANNER_VERSION[[:space:]]*=[0-9]+\.[0-9]+(\.[0-9]+)?')

# `hort_systemd_osv_version: "2.7.1"` → 2.7.1
role_pin=$(one_pin \
    "hort_systemd/defaults hort_systemd_osv_version" \
    "${role_defaults}" \
    '^[[:space:]]*hort_systemd_osv_version[[:space:]]*:[[:space:]]*"[0-9]+\.[0-9]+(\.[0-9]+)?"')

# `| osv-scanner | 2.7.1 | https://… | Apache-2.0 |` → 2.7.1
image_notice_pin=$(one_pin \
    "docs/attribution/image-notice.md" \
    "${image_notice}" \
    '^\|[[:space:]]*osv-scanner[[:space:]]*\|[[:space:]]*[0-9]+\.[0-9]+(\.[0-9]+)?[[:space:]]*\|')

if [[ "${dockerfile_pin}" == "${role_pin}" \
    && "${dockerfile_pin}" == "${image_notice_pin}" ]]; then
    echo "osv-scanner pin sync: OK (Dockerfile.worker=${dockerfile_pin}, hort_systemd_osv_version=${role_pin}, image-notice=${image_notice_pin})"
    exit 0
fi

echo "osv-scanner version pin mismatch:" >&2
printf '  %-52s = %s\n' "docker/Dockerfile.worker ARG OSV_SCANNER_VERSION" "${dockerfile_pin}" >&2
printf '  %-52s = %s\n' "hort_systemd/defaults hort_systemd_osv_version" "${role_pin}" >&2
printf '  %-52s = %s\n' "docs/attribution/image-notice.md" "${image_notice_pin}" >&2
echo "" >&2
echo "Set all three to the same osv-scanner release. The osv adapter uses the" >&2
echo "v2 'scan source' CLI; a native binary on a different (especially v1.x)" >&2
echo "version fails every scan and strands all proxied artifacts in" >&2
echo "quarantine, and a NOTICE naming a version the image does not carry is a" >&2
echo "false statement about what ships." >&2
exit 1
