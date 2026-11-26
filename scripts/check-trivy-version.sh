#!/usr/bin/env bash
#
# scripts/check-trivy-version.sh — Trivy version lockstep gate.
#
# Asserts that the four independent Trivy version statements stay identical:
#
#   1. `docker/Dockerfile.worker` `ARG TRIVY_VERSION=...` — the version baked
#      into the worker container; the version the scan use case is built and
#      tested against.
#   2. `.github/workflows/scheduled-container-scan.yml` — the weekly scan
#      workflow's own Trivy install, extracted from the published GHCR image.
#   3. `.github/workflows/docker-publish.yml` — the publish-gating scan's
#      Trivy install, same install method.
#   4. `docs/attribution/image-notice.md` — the hand-maintained NOTICE that
#      tells a reader which Trivy the shipped image bundles.
#
# Why this matters: the two CI workflows judge the images this project ships
# with a *different* Trivy binary than the one that gates artifacts at
# runtime. A CI pin left behind the worker's pin means CI's verdict comes
# from an older ruleset than the one operators actually rely on — exactly
# the drift this gate exists to catch before it ships quietly. The NOTICE is
# the same drift pointed at a reader instead of at a scan: it is the only
# place that answers "which Trivy is in this image" for someone who cannot
# read the Dockerfile, and it asks for its own update in its own prose —
# which is precisely the kind of obligation that a sentence cannot hold.
#
# Comparison is EXACT (full version): CI's Trivy must be the one the project
# pins and ships, so even a patch difference is a drift worth flagging.
#
# GitHub Actions workflow YAML cannot read another file at parse time, so the
# two workflow pins are literals rather than a shared reference — this gate
# is the only thing that notices them drift apart from the Dockerfile or
# from each other. The NOTICE is prose and has no reference mechanism at all.
#
# Run by:
#   - the GitLab `quality:chart-and-rust-pin-sync` job
#   - locally before pushing changes to the Dockerfile pin, either workflow,
#     or the NOTICE
#
# No external TOML/YAML/Dockerfile parser — all four inputs are tiny and
# regular; bash + grep is enough and avoids enlarging the supply chain for
# one lint.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
dockerfile="${repo_root}/docker/Dockerfile.worker"
scheduled_scan="${repo_root}/.github/workflows/scheduled-container-scan.yml"
docker_publish="${repo_root}/.github/workflows/docker-publish.yml"
image_notice="${repo_root}/docs/attribution/image-notice.md"

for f in "${dockerfile}" "${scheduled_scan}" "${docker_publish}" "${image_notice}"; do
    if [[ ! -f "$f" ]]; then
        echo "error: $f not found" >&2
        exit 2
    fi
done

# Every occurrence a site's pattern matches is collected and reduced with
# `sort -u`, never `head -n1`. A file that grew a second Trivy version
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
        echo "error: could not extract a Trivy version from ${label}" >&2
        exit 2
    fi
    if [[ "${count}" -gt 1 ]]; then
        echo "error: ${label} names more than one Trivy version:" >&2
        printf '  %s\n' ${pins} >&2
        echo "Every Trivy reference in one file must name the same release." >&2
        exit 1
    fi
    printf '%s' "${pins}"
}

# `ARG TRIVY_VERSION=0.76.2` → 0.76.2
dockerfile_pin=$(one_pin \
    "docker/Dockerfile.worker ARG TRIVY_VERSION" \
    "${dockerfile}" \
    '^ARG[[:space:]]+TRIVY_VERSION[[:space:]]*=[0-9]+\.[0-9]+(\.[0-9]+)?')

# `docker create ghcr.io/aquasecurity/trivy:0.76.2` → 0.76.2
scheduled_scan_pin=$(one_pin \
    ".github/workflows/scheduled-container-scan.yml" \
    "${scheduled_scan}" \
    'ghcr\.io/aquasecurity/trivy:[0-9]+\.[0-9]+(\.[0-9]+)?')
docker_publish_pin=$(one_pin \
    ".github/workflows/docker-publish.yml" \
    "${docker_publish}" \
    'ghcr\.io/aquasecurity/trivy:[0-9]+\.[0-9]+(\.[0-9]+)?')

# `| Trivy | 0.76.2 | https://… | Apache-2.0 |` → 0.76.2
image_notice_pin=$(one_pin \
    "docs/attribution/image-notice.md" \
    "${image_notice}" \
    '^\|[[:space:]]*Trivy[[:space:]]*\|[[:space:]]*[0-9]+\.[0-9]+(\.[0-9]+)?[[:space:]]*\|')

if [[ "${dockerfile_pin}" == "${scheduled_scan_pin}" \
    && "${dockerfile_pin}" == "${docker_publish_pin}" \
    && "${dockerfile_pin}" == "${image_notice_pin}" ]]; then
    echo "trivy pin sync: OK (Dockerfile.worker=${dockerfile_pin}, scheduled-container-scan=${scheduled_scan_pin}, docker-publish=${docker_publish_pin}, image-notice=${image_notice_pin})"
    exit 0
fi

echo "trivy version pin mismatch:" >&2
printf '  %-58s = %s\n' "docker/Dockerfile.worker ARG TRIVY_VERSION" "${dockerfile_pin}" >&2
printf '  %-58s = %s\n' ".github/workflows/scheduled-container-scan.yml" "${scheduled_scan_pin}" >&2
printf '  %-58s = %s\n' ".github/workflows/docker-publish.yml" "${docker_publish_pin}" >&2
printf '  %-58s = %s\n' "docs/attribution/image-notice.md" "${image_notice_pin}" >&2
echo "" >&2
echo "Set all four to the same Trivy release. A CI workflow scanning with an" >&2
echo "older Trivy than the worker container judges images with a ruleset" >&2
echo "behind the one that gates artifacts at runtime, and a NOTICE naming a" >&2
echo "version the image does not carry is a false statement about what ships." >&2
exit 1
