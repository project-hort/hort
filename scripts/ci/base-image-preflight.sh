#!/usr/bin/env bash
# Refuse release builds until each pinned manifest answers through the
# runner's registry rules. A missing answer is never availability.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
build_login_host="${REGISTRY:-}"
build_login_host="${build_login_host#*://}"
build_login_host="${build_login_host%%/*}"
build_login_host="${build_login_host:-<unset>}"
curl_config=""
trap 'if [[ -n "${curl_config}" ]]; then rm -f -- "${curl_config}"; fi' EXIT

escape_curl_config() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '%s' "${value}"
}

config_files=()
if [[ -n "${BASE_IMAGE_REGISTRIES_CONF:-}" ]]; then
    IFS=: read -r -a config_files <<< "${BASE_IMAGE_REGISTRIES_CONF}"
else
    for file in /etc/containers/registries.conf /etc/containers/registries.conf.d/*.conf; do
        [[ -f "${file}" ]] && config_files+=("${file}")
    done
fi

# Read aliases, prefix rewrites, and digest-eligible mirrors from the
# configured registry files. Only the longest matching registry prefix applies.
registry_rows=()
mirror_rows=()
declare -A aliases=() alias_files=()
section=""
prefix=""
location=""
mirror=""
policy=""
flush_mirror() {
    local source="${prefix:-${location}}"
    if [[ -n "${source}" && -n "${mirror}" && "${policy}" != tag-only ]]; then
        mirror_rows+=("${source}|${mirror}")
    fi
    mirror="" policy=""
}
flush_registry() {
    local source="${prefix:-${location}}"
    if [[ -n "${source}" ]]; then
        registry_rows+=("${source}|${location:-${source}}")
    fi
}
for file in "${config_files[@]}"; do
    if [[ ! -r "${file}" ]]; then
        echo "INDETERMINATE — registry config unreadable: ${file}" >&2
        exit 1
    fi
    while IFS= read -r line || [[ -n "${line}" ]]; do
        case "${line}" in
            '[[registry]]')
                flush_mirror
                flush_registry
                section=registry prefix="" location="" mirror="" policy=""
                continue
                ;;
            '[[registry.mirror]]') flush_mirror; section=mirror; continue ;;
            '[aliases]') section=aliases; continue ;;
        esac
        if [[ "${line}" =~ ^[[:space:]]*(prefix|location|pull-from-mirror)[[:space:]]*=[[:space:]]*\"([^\"]+)\" ]]; then
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            if [[ "${section}" == registry ]]; then
                case "${key}" in
                    prefix) prefix="${value}" ;;
                    location) location="${value}" ;;
                esac
            elif [[ "${section}" == mirror ]]; then
                case "${key}" in
                    location) [[ -n "${mirror}" ]] || mirror="${value}" ;;
                    pull-from-mirror) policy="${value}" ;;
                esac
            fi
        elif [[ "${section}" == aliases && "${line}" =~ ^[[:space:]]*\"([^\"]+)\"[[:space:]]*=[[:space:]]*\"([^\"]+)\" ]]; then
            aliases["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
            alias_files["${BASH_REMATCH[1]}"]="${file##*/}"
        fi
    done < "${file}"
    flush_mirror
    flush_registry
    section="" prefix="" location="" mirror="" policy=""
done

resolve_url() {
    local ref="$1" repo="${1%@*}" digest="${1##*@}" first
    local row source location mirror selected_prefix="" selected_location="" candidate
    local alias_rule=""
    resolved_url=""
    resolution="no rule applied"
    first="${repo%%/*}"
    if [[ "${first}" != *.* && "${first}" != *:* && "${first}" != localhost ]]; then
        if [[ ! -v aliases[${repo}] ]]; then
            resolution="no short-name alias for ${repo}; runner pull target is unresolved"
            return
        fi
        alias_rule="short-name alias ${alias_files[${repo}]}: ${repo} -> ${aliases[${repo}]}"
        repo="${aliases[${repo}]}"
        resolution="${alias_rule}"
    fi
    for row in "${registry_rows[@]}"; do
        IFS='|' read -r source location <<< "${row}"
        if [[ "${repo}" == "${source}"/* || "${repo}" == "${source}" ]]; then
            if ((${#source} > ${#selected_prefix})); then
                selected_prefix="${source}"
                selected_location="${location}"
            fi
        fi
    done
    if [[ -n "${selected_prefix}" ]]; then
        candidate="${selected_location}${repo#"${selected_prefix}"}"
        [[ -z "${alias_rule}" ]] || alias_rule+="; "
        resolution="${alias_rule}prefix rewrite ${selected_prefix} -> ${selected_location}"
        for row in "${mirror_rows[@]}"; do
            IFS='|' read -r source mirror <<< "${row}"
            if [[ "${source}" == "${selected_prefix}" ]]; then
                candidate="${mirror}${repo#"${selected_prefix}"}"
                resolution="${alias_rule}mirror ${selected_prefix} -> ${mirror}"
                break
            fi
        done
    else
        candidate="${repo}"
    fi
    resolved_url="https://${candidate%%/*}/v2/${candidate#*/}/manifests/${digest}"
}

refs="$(bash "${root}/scripts/ci/base-image-refs.sh")"
failed=0
while IFS= read -r ref; do
    [[ -n "${ref}" ]] || continue
    resolve_url "${ref}"
    if [[ -z "${resolved_url}" ]]; then
        echo "${ref}: INDETERMINATE — ${resolution}" >&2
        failed=1
        continue
    fi
    url="${resolved_url}"
    resolved_host="${url#https://}"
    resolved_host="${resolved_host%%/*}"
    if [[ "${resolution}" != "no rule applied" && "${resolved_host,,}" != "${build_login_host,,}" ]]; then
        echo "${ref}: INDETERMINATE — resolved ${url} (resolution: ${resolution}); resolved host ${resolved_host} differs from build login host ${build_login_host}; manifest HEAD not attempted" >&2
        failed=1
        continue
    fi
    context="checked ${url} (resolution: ${resolution}"
    if [[ "${resolution}" == "no rule applied" ]]; then
        context+="; upstream, NOT GATED"
    else
        context+="; build registry credential"
    fi
    context+=")"
    headers="$(mktemp)"
    curl_args=(-q -sS -I --connect-timeout 10 --max-time 30 -D "${headers}" -o /dev/null -w '%{http_code}')
    if [[ "${resolution}" != "no rule applied" ]]; then
        if [[ -z "${REGISTRY_USER:-}" || -z "${REGISTRY_PASSWORD:-}" ]]; then
            echo "${ref}: INDETERMINATE — resolved ${url} (resolution: ${resolution}); no build registry credential for ${build_login_host}; manifest HEAD not attempted" >&2
            failed=1
            rm -f -- "${headers}"
            continue
        fi
        if [[ -z "${curl_config}" ]]; then
            curl_config="$(mktemp)"
            credential="$(escape_curl_config "${REGISTRY_USER}:${REGISTRY_PASSWORD}")"
            printf 'user = "%s"\n' "${credential}" > "${curl_config}"
            unset credential
        fi
        curl_args+=(--config "${curl_config}")
    fi
    rc=0
    status="$(curl "${curl_args[@]}" "${url}")" || rc=$?
    retry=""
    while IFS= read -r header; do
        if [[ "${header%%:*}" == [Rr][Ee][Tt][Rr][Yy]-[Aa][Ff][Tt][Ee][Rr] ]]; then
            retry="${header#*:}"
            retry="${retry# }"
            retry="${retry%$'\r'}"
        fi
    done < "${headers}"
    rm -f -- "${headers}"
    if [[ "${rc}" -ne 0 ]]; then
        echo "${ref}: INDETERMINATE — ${context}; manifest HEAD failed (curl exit ${rc})" >&2
        failed=1
    elif [[ "${status}" == 200 ]]; then
        echo "${ref}: AVAILABLE — ${context}; manifest HEAD returned HTTP 200"
    elif [[ "${status}" == 503 && -n "${retry}" ]]; then
        if [[ "${retry}" =~ ^[0-9]+$ ]]; then
            ready="$(date -u -d "+${retry} seconds" '+%Y-%m-%d %H:%M:%S UTC')"
            echo "${ref}: QUARANTINED — ${context}; Retry-After: ${retry} seconds; earliest retry at ${ready} (allow for release sweep latency)" >&2
        else
            echo "${ref}: QUARANTINED — ${context}; Retry-After: ${retry}" >&2
        fi
        failed=1
    else
        echo "${ref}: INDETERMINATE — ${context}; manifest HEAD returned HTTP ${status} (Retry-After: ${retry:-absent})" >&2
        failed=1
    fi
done <<< "${refs}"
exit "${failed}"
