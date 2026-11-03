#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf -- "${fixture}"' EXIT
mkdir -p "${fixture}/scripts"
cat > "${fixture}/.gitlab-ci.yml" <<'CI'
script:
  - bash scripts/run-shell-guards.sh scripts/check-ok.sh
  - bash scripts/run-shell-guards.sh scripts/test-unavailable.sh
CI
printf '#!/usr/bin/env bash\nexit 0\n' > "${fixture}/scripts/check-ok.sh"
printf '#!/usr/bin/env bash\nexit 2\n' > "${fixture}/scripts/test-unavailable.sh"

rc=0
SHELL_GUARD_ROOT="${fixture}" bash "${root}/scripts/run-shell-guards.sh" > "${fixture}/out" 2>&1 || rc=$?
[[ "${rc}" -eq 2 ]]
grep -q '^PASS scripts/check-ok.sh$' "${fixture}/out"
grep -q '^NOT RUNNABLE scripts/test-unavailable.sh (exit 2)' "${fixture}/out"

rc=0
SHELL_GUARD_ROOT="${fixture}" bash "${root}/scripts/run-shell-guards.sh" scripts/check-ok.sh > "${fixture}/out" 2>&1 || rc=$?
[[ "${rc}" -eq 0 ]]

printf '#!/usr/bin/env bash\nexit 1\n' > "${fixture}/scripts/check-ok.sh"
rc=0
SHELL_GUARD_ROOT="${fixture}" bash "${root}/scripts/run-shell-guards.sh" scripts/check-ok.sh > "${fixture}/out" 2>&1 || rc=$?
[[ "${rc}" -eq 1 ]]
grep -q '^FAIL scripts/check-ok.sh (exit 1)' "${fixture}/out"

printf '#!/usr/bin/env bash\nexit 0\n' > "${fixture}/scripts/check-orphan.sh"
rc=0
SHELL_GUARD_ROOT="${fixture}" bash "${root}/scripts/run-shell-guards.sh" > "${fixture}/out" 2>&1 || rc=$?
[[ "${rc}" -eq 1 ]]
grep -q 'namespace only: scripts/check-orphan.sh' "${fixture}/out"

rm "${fixture}/scripts/check-orphan.sh"
printf '  - bash scripts/run-shell-guards.sh scripts/check-missing.sh\n' >> "${fixture}/.gitlab-ci.yml"
rc=0
SHELL_GUARD_ROOT="${fixture}" bash "${root}/scripts/run-shell-guards.sh" > "${fixture}/out" 2>&1 || rc=$?
[[ "${rc}" -eq 1 ]]
grep -q 'CI only: scripts/check-missing.sh' "${fixture}/out"

sed -i '/check-missing.sh/d' "${fixture}/.gitlab-ci.yml"
printf '  - bash scripts/run-shell-guards.sh scripts/check-attribution.sh\n' >> "${fixture}/.gitlab-ci.yml"
printf '#!/usr/bin/env bash\necho overwritten > THIRD-PARTY-LICENSES.md\n' > "${fixture}/scripts/check-attribution.sh"
printf 'committed\n' > "${fixture}/THIRD-PARTY-LICENSES.md"
printf '[]\n' > "${fixture}/THIRD-PARTY-LICENSES.json"
git -C "${fixture}" init -q
git -C "${fixture}" -c user.name=Fixture -c user.email=fixture@example.invalid add .
git -C "${fixture}" -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm fixture
printf 'uncommitted\n' > "${fixture}/THIRD-PARTY-LICENSES.md"
rc=0
SHELL_GUARD_ROOT="${fixture}" bash "${root}/scripts/run-shell-guards.sh" scripts/check-attribution.sh > "${fixture}/out" 2>&1 || rc=$?
[[ "${rc}" -eq 2 ]]
grep -q 'dirty attribution files' "${fixture}/out"
[[ "$(cat "${fixture}/THIRD-PARTY-LICENSES.md")" == uncommitted ]]

echo 'shell guard runner fixture: pass, unavailable, fail, both drift directions, and dirty attribution passed'
