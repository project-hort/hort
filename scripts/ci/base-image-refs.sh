#!/usr/bin/env bash
# Emit the unique digest references used by release and compose Dockerfiles.
set -euo pipefail

cd "$(dirname "$0")/../.."
dockerfiles=(docker/Dockerfile.hort-server docker/Dockerfile.worker deploy/compose/Dockerfile)

for file in "${dockerfiles[@]}"; do
    if [[ ! -f "${file}" ]]; then
        echo "error: pinned base-image Dockerfile missing: ${file}" >&2
        exit 1
    fi
done

while IFS= read -r file; do
    file="${file#./}"
    [[ " $(printf '%s ' "${dockerfiles[@]}") " == *" ${file} "* ]] && continue
    if grep -E '^[[:space:]]*FROM[[:space:]].*@sha256:' "${file}" >/dev/null; then
        echo "error: ${file} pins a base-image digest but is absent from the release set; add it to scripts/ci/base-image-refs.sh or its base images stay cold until a build requests them" >&2
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
