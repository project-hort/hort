#!/usr/bin/env bash
# Emit the unique digest references used by release and compose Dockerfiles.
set -euo pipefail

cd "$(dirname "$0")/../.."
dockerfiles=(docker/Dockerfile.hort-server docker/Dockerfile.worker deploy/compose/Dockerfile)
# Pinned, deliberately OUTSIDE the release set. The release set exists to
# pre-warm and scan the bases that ship inside a product artifact; a harness
# image's bases ship in nothing. Pulling them into the release set would make
# every harness digest bump wait out a cold-digest quarantine window for no
# product benefit — so they are pinned here and listed here, and the reason
# lives at the list rather than in a separate exemption file.
harness_dockerfiles=(scripts/native-tests/Dockerfile.client)

for file in "${dockerfiles[@]}"; do
    if [[ ! -f "${file}" ]]; then
        echo "error: pinned base-image Dockerfile missing: ${file}" >&2
        exit 1
    fi
done

while IFS= read -r file; do
    file="${file#./}"
    [[ " $(printf '%s ' "${dockerfiles[@]}") " == *" ${file} "* ]] && continue
    [[ " $(printf '%s ' "${harness_dockerfiles[@]}") " == *" ${file} "* ]] && continue
    if grep -E '^[[:space:]]*FROM[[:space:]].*@sha256:' "${file}" >/dev/null; then
        echo "error: ${file} pins a base-image digest but is in neither set in scripts/ci/base-image-refs.sh; add it to the release set if its bases ship inside a product artifact (they are then pre-warmed and scanned), or to the harness-only set if they do not" >&2
        exit 1
    fi
done < <(find . -type f -name 'Dockerfile*' -not -path './target/*' | sort)

declare -A seen=()
count=0
for file in "${dockerfiles[@]}"; do
    while IFS= read -r line; do
        [[ "${line}" =~ ^[[:space:]]*FROM[[:space:]] ]] || continue
        if [[ ! "${line}" =~ ([^[:space:]@]+)@(sha256:[0-9a-f]{64}) ]]; then
            continue
        fi
        nametag="${BASH_REMATCH[1]}"
        digest="${BASH_REMATCH[2]}"
        repo="${nametag}"
        case "${nametag##*/}" in
            *:*) repo="${nametag%:*}" ;;
        esac
        ref="${repo}@${digest}"
        if [[ ! -v seen[${ref}] ]]; then
            seen["${ref}"]=1
            printf '%s\n' "${ref}"
            count=$((count + 1))
        fi
    done < "${file}"
done

if [[ "${count}" -eq 0 ]]; then
    echo 'error: no digest-pinned FROM lines found' >&2
    exit 1
fi
