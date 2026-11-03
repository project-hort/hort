#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "${tmp}"' EXIT

cat > "${tmp}/registries.conf" <<'CONF'
[[registry]]
prefix = "docker.io"
location = "registry.example.invalid/dockerhub-proxy"
CONF

cat > "${tmp}/000-shortnames.conf" <<'CONF'
[aliases]
"rust" = "docker.io/library/rust"
"debian" = "docker.io/library/debian"
CONF

cat > "${tmp}/curl" <<'CURL'
#!/usr/bin/env bash
args=("$@")
[[ "${args[0]}" == -q ]] || exit 89
url="${args[${#args[@]}-1]}"
auth=none
head=no
for ((i=0; i<${#args[@]}; i++)); do
  [[ -z "${REGISTRY_PASSWORD:-}" || "${args[i]}" != *"${REGISTRY_PASSWORD}"* ]] || exit 90
  [[ "${args[i]}" != -u && "${args[i]}" != --user && "${args[i]}" != --user=* ]] || exit 91
  [[ "${args[i]}" != -I ]] || head=yes
  if [[ "${args[i]}" == --config ]]; then
    auth=config
    config="${args[i+1]}"
    [[ "$(stat -c %a "${config}")" == 600 ]] || exit 92
    grep -Fxq "${CURL_EXPECT_CONFIG}" "${config}" || exit 93
  fi
done
printf '%s auth=%s head=%s\n' "${url}" "${auth}" "${head}" >> "${CURL_CALLS}"
headers='HTTP/1.1 200 OK\r\n\r\n'
status=200
if [[ "${url}" == https://registry.example.invalid/* ]]; then
  case "${CURL_CASE}" in
    quarantine) headers='HTTP/1.1 503 Service Unavailable\r\nRetry-After: 120\r\n\r\n'; status=503 ;;
    unauthorized) headers='HTTP/1.1 401 Unauthorized\r\n\r\n'; status=401 ;;
  esac
fi
while (($#)); do
  if [[ "$1" == "-D" ]]; then shift; printf '%b' "${headers}" > "$1"; fi
  shift
done
printf '%s' "${status}"
CURL
chmod +x "${tmp}/curl"
printf '#!/usr/bin/env bash\nprintf "2026-11-03 12:02:00 UTC\\n"\n' > "${tmp}/date"
chmod +x "${tmp}/date"

refs="$(bash "${root}/scripts/ci/base-image-refs.sh")"
[[ "$(printf '%s\n' "${refs}" | wc -l)" -eq 3 ]]
[[ "${refs}" =~ debian@sha256:[0-9a-f]{64} ]]
while IFS= read -r ref; do
  case "${ref}" in
    rust@*) rust_ref="${ref}" ;;
    debian@*) debian_ref="${ref}" ;;
    gcr.io/*) distroless_ref="${ref}" ;;
  esac
done <<< "${refs}"
[[ -n "${rust_ref:-}" && -n "${debian_ref:-}" && -n "${distroless_ref:-}" ]]

export BASE_IMAGE_REGISTRIES_CONF="${tmp}/registries.conf:${tmp}/000-shortnames.conf"
export HORT_BUILD_URL=https://api.example.invalid
export REGISTRY=registry.example.invalid
export REGISTRY_USER=fixture-user
export REGISTRY_PASSWORD=fixture-secret
export CURL_EXPECT_CONFIG='user = "fixture-user:fixture-secret"'
export CURL_CALLS="${tmp}/calls"
export PATH="${tmp}:${PATH}"

for case_name in available quarantine unauthorized; do
  export CURL_CASE="${case_name}"
  case "${case_name}" in
    available) verdict=AVAILABLE; response='manifest HEAD returned HTTP 200' ;;
    quarantine) verdict=QUARANTINED; response='Retry-After: 120 seconds; earliest retry at 2026-11-03 12:02:00 UTC (allow for release sweep latency)' ;;
    unauthorized) verdict=INDETERMINATE; response='manifest HEAD returned HTTP 401 (Retry-After: absent)' ;;
  esac
  : > "${CURL_CALLS}"
  rc=0
  bash "${root}/scripts/ci/base-image-preflight.sh" > "${tmp}/out" 2>&1 || rc=$?
  case "${case_name}" in
    available) [[ "${rc}" -eq 0 ]] && grep -q 'AVAILABLE' "${tmp}/out" ;;
    quarantine)
      [[ "${rc}" -eq 1 ]]
      grep -q 'Retry-After: 120 seconds; earliest retry at 2026-11-03 12:02:00 UTC (allow for release sweep latency)' "${tmp}/out"
      ;;
    unauthorized)
      [[ "${rc}" -eq 1 ]]
      grep -q 'manifest HEAD returned HTTP 401' "${tmp}/out"
      ;;
  esac
  [[ "$(wc -l < "${CURL_CALLS}")" -eq 3 ]]
  grep -Fq "https://registry.example.invalid/v2/dockerhub-proxy/library/rust/manifests/${rust_ref##*@}" "${CURL_CALLS}"
  grep -Fq "https://registry.example.invalid/v2/dockerhub-proxy/library/debian/manifests/${debian_ref##*@}" "${CURL_CALLS}"
  grep -Fq "https://gcr.io/v2/distroless/cc-debian13/manifests/${distroless_ref##*@}" "${CURL_CALLS}"
  grep -Fxq "${rust_ref}: ${verdict} — checked https://registry.example.invalid/v2/dockerhub-proxy/library/rust/manifests/${rust_ref##*@} (resolution: short-name alias 000-shortnames.conf: rust -> docker.io/library/rust; prefix rewrite docker.io -> registry.example.invalid/dockerhub-proxy; build registry credential); ${response}" "${tmp}/out"
  grep -Fxq "${debian_ref}: ${verdict} — checked https://registry.example.invalid/v2/dockerhub-proxy/library/debian/manifests/${debian_ref##*@} (resolution: short-name alias 000-shortnames.conf: debian -> docker.io/library/debian; prefix rewrite docker.io -> registry.example.invalid/dockerhub-proxy; build registry credential); ${response}" "${tmp}/out"
  grep -Fxq "${distroless_ref}: AVAILABLE — checked https://gcr.io/v2/distroless/cc-debian13/manifests/${distroless_ref##*@} (resolution: no rule applied; upstream, NOT GATED); manifest HEAD returned HTTP 200" "${tmp}/out"
  while IFS= read -r call; do
    if [[ "${call}" == *gcr.io* ]]; then
      [[ "${call}" == *' auth=none head=yes' ]]
    else
      [[ "${call}" == *' auth=config head=yes' ]]
    fi
  done < "${CURL_CALLS}"
  ! grep -Fq "${REGISTRY_PASSWORD}" "${CURL_CALLS}"
  ! grep -Fq "${REGISTRY_PASSWORD}" "${tmp}/out"
  if [[ "${case_name}" == available && "${PREFLIGHT_FIXTURE_LOG:-}" == 1 ]]; then
    cat "${tmp}/out"
  fi
done

export REGISTRY_PASSWORD='fixt"ure\secret'
export CURL_EXPECT_CONFIG='user = "fixture-user:fixt\"ure\\secret"'
export CURL_CASE=available
: > "${CURL_CALLS}"
bash "${root}/scripts/ci/base-image-preflight.sh" > "${tmp}/out" 2>&1
[[ "$(wc -l < "${CURL_CALLS}")" -eq 3 ]]
! grep -Fq "${REGISTRY_PASSWORD}" "${CURL_CALLS}"
! grep -Fq "${REGISTRY_PASSWORD}" "${tmp}/out"
export REGISTRY_PASSWORD=fixture-secret
export CURL_EXPECT_CONFIG='user = "fixture-user:fixture-secret"'

unset REGISTRY_PASSWORD
: > "${CURL_CALLS}"
rc=0
bash "${root}/scripts/ci/base-image-preflight.sh" > "${tmp}/out" 2>&1 || rc=$?
[[ "${rc}" -eq 1 ]]
[[ "$(wc -l < "${CURL_CALLS}")" -eq 1 ]]
grep -Fq 'manifest HEAD not attempted' "${tmp}/out"
grep -Eq 'no build registry credential for [^;]+; manifest HEAD not attempted' "${tmp}/out"
! grep -Fq 'build registry credential)' "${tmp}/out"
export REGISTRY_PASSWORD=fixture-secret

export REGISTRY=other.example.invalid
: > "${CURL_CALLS}"
rc=0
bash "${root}/scripts/ci/base-image-preflight.sh" > "${tmp}/out" 2>&1 || rc=$?
[[ "${rc}" -eq 1 ]]
[[ "$(wc -l < "${CURL_CALLS}")" -eq 1 ]]
grep -Fq 'https://gcr.io/v2/distroless/cc-debian13/' "${CURL_CALLS}"
grep -Fxq "${rust_ref}: INDETERMINATE — resolved https://registry.example.invalid/v2/dockerhub-proxy/library/rust/manifests/${rust_ref##*@} (resolution: short-name alias 000-shortnames.conf: rust -> docker.io/library/rust; prefix rewrite docker.io -> registry.example.invalid/dockerhub-proxy); resolved host registry.example.invalid differs from build login host other.example.invalid; manifest HEAD not attempted" "${tmp}/out"
grep -Fxq "${debian_ref}: INDETERMINATE — resolved https://registry.example.invalid/v2/dockerhub-proxy/library/debian/manifests/${debian_ref##*@} (resolution: short-name alias 000-shortnames.conf: debian -> docker.io/library/debian; prefix rewrite docker.io -> registry.example.invalid/dockerhub-proxy); resolved host registry.example.invalid differs from build login host other.example.invalid; manifest HEAD not attempted" "${tmp}/out"
[[ "$(grep -Fc 'manifest HEAD not attempted' "${tmp}/out")" -eq 2 ]]
! grep -Fq 'NOT GATED' <(grep -F 'INDETERMINATE' "${tmp}/out")
export REGISTRY=registry.example.invalid

cat > "${tmp}/longest.conf" <<'CONF'
[[registry]]
prefix = "docker.io"
location = "registry.example.invalid/dockerhub-proxy"
[[registry]]
prefix = "docker.io/library/rust"
location = "registry.example.invalid/rust-proxy"
CONF
export BASE_IMAGE_REGISTRIES_CONF="${tmp}/longest.conf:${tmp}/000-shortnames.conf"
export CURL_CASE=available
: > "${CURL_CALLS}"
bash "${root}/scripts/ci/base-image-preflight.sh" > "${tmp}/out" 2>&1
grep -Fq "https://registry.example.invalid/v2/rust-proxy/manifests/${rust_ref##*@}" "${CURL_CALLS}"
grep -Fq "https://registry.example.invalid/v2/dockerhub-proxy/library/debian/manifests/${debian_ref##*@}" "${CURL_CALLS}"

cat > "${tmp}/050-override.conf" <<'CONF'
[[registry]]
prefix = "docker.io"
location = "registry.example.invalid/dockerhub-override"
CONF
export BASE_IMAGE_REGISTRIES_CONF="${tmp}/registries.conf:${tmp}/000-shortnames.conf:${tmp}/050-override.conf"
: > "${CURL_CALLS}"
bash "${root}/scripts/ci/base-image-preflight.sh" > "${tmp}/out" 2>&1
expected="https://registry.example.invalid/v2/dockerhub-override/library/rust/manifests/${rust_ref##*@}"
actual="$(grep -F "/library/rust/manifests/${rust_ref##*@}" "${CURL_CALLS}" | cut -d ' ' -f 1)"
printf 'duplicate-prefix resolved URL: %s\n' "${actual}"
fixture_failed=0
[[ "${actual}" == "${expected}" ]] || fixture_failed=1

cat > "${tmp}/mirror.conf" <<'CONF'
[[registry]]
prefix = "docker.io"
location = "docker.io"
[[registry.mirror]]
location = "registry.example.invalid/dockerhub-mirror"
pull-from-mirror = "digest-only"
CONF
export BASE_IMAGE_REGISTRIES_CONF="${tmp}/mirror.conf:${tmp}/000-shortnames.conf"
export CURL_CASE=available
: > "${CURL_CALLS}"
bash "${root}/scripts/ci/base-image-preflight.sh" > "${tmp}/out" 2>&1
grep -Fq "https://registry.example.invalid/v2/dockerhub-mirror/library/rust/manifests/${rust_ref##*@}" "${CURL_CALLS}"
grep -Fq 'mirror docker.io -> registry.example.invalid/dockerhub-mirror' "${tmp}/out"

cat > "${tmp}/050-mirror-override.conf" <<'CONF'
[[registry]]
prefix = "docker.io"
location = "docker.io"
[[registry.mirror]]
location = "registry.example.invalid/mirror-override"
pull-from-mirror = "digest-only"
CONF
export BASE_IMAGE_REGISTRIES_CONF="${tmp}/mirror.conf:${tmp}/000-shortnames.conf:${tmp}/050-mirror-override.conf"
: > "${CURL_CALLS}"
bash "${root}/scripts/ci/base-image-preflight.sh" > "${tmp}/out" 2>&1
expected="https://registry.example.invalid/v2/mirror-override/library/rust/manifests/${rust_ref##*@}"
actual="$(grep -F "/library/rust/manifests/${rust_ref##*@}" "${CURL_CALLS}" | cut -d ' ' -f 1)"
printf 'duplicate-prefix mirror URL: %s\n' "${actual}"
[[ "${actual}" == "${expected}" ]] || fixture_failed=1

export BASE_IMAGE_REGISTRIES_CONF="${tmp}/mirror.conf:${tmp}/000-shortnames.conf:${tmp}/050-override.conf"
: > "${CURL_CALLS}"
bash "${root}/scripts/ci/base-image-preflight.sh" > "${tmp}/out" 2>&1
expected="https://registry.example.invalid/v2/dockerhub-override/library/rust/manifests/${rust_ref##*@}"
actual="$(grep -F "/library/rust/manifests/${rust_ref##*@}" "${CURL_CALLS}" | cut -d ' ' -f 1)"
printf 'overridden mirror resolved URL: %s\n' "${actual}"
[[ "${actual}" == "${expected}" ]] || fixture_failed=1
[[ "${fixture_failed}" -eq 0 ]]

export BASE_IMAGE_REGISTRIES_CONF="${tmp}/mirror.conf:${tmp}/000-shortnames.conf"
sed -i 's/pull-from-mirror = "digest-only"/pull-from-mirror = "tag-only"/' "${tmp}/mirror.conf"
: > "${CURL_CALLS}"
rc=0
bash "${root}/scripts/ci/base-image-preflight.sh" > "${tmp}/out" 2>&1 || rc=$?
[[ "${rc}" -eq 1 ]]
[[ "$(wc -l < "${CURL_CALLS}")" -eq 1 ]]
grep -Fq "resolved https://docker.io/v2/library/rust/manifests/${rust_ref##*@}" "${tmp}/out"
grep -Fq 'prefix rewrite docker.io -> docker.io' "${tmp}/out"
grep -Fq 'resolved host docker.io differs from build login host registry.example.invalid' "${tmp}/out"

export BASE_IMAGE_REGISTRIES_CONF="${tmp}/registries.conf"
: > "${CURL_CALLS}"
rc=0
bash "${root}/scripts/ci/base-image-preflight.sh" > "${tmp}/out" 2>&1 || rc=$?
[[ "${rc}" -eq 1 ]]
grep -Fq 'no short-name alias for rust; runner pull target is unresolved' "${tmp}/out"
grep -Fq 'no short-name alias for debian; runner pull target is unresolved' "${tmp}/out"
[[ "$(wc -l < "${CURL_CALLS}")" -eq 1 ]]

echo 'base-image preflight fixture: authenticated rewrite, unauthenticated upstream, mismatched login host, aliases, longest prefix rewrite, mirror, tag-only exclusion, missing alias, HEAD URLs, and all three outcomes passed'
