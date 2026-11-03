#!/usr/bin/env bash
# Run the shell guard namespace locally, or one named guard in CI.
# Exit 0 means every selected guard passed, 1 means failure or namespace drift,
# and 2 means no failure but at least one guard could not run here. A guard's
# exit 2 is the shared missing-precondition convention; exit 1 is a failure.
set -euo pipefail

root="${SHELL_GUARD_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "${root}"

mapfile -t disk_guards < <(find scripts -maxdepth 1 -type f \( -name 'check-*.sh' -o -name 'test-*.sh' \) -print | sort)
mapfile -t ci_guards < <(grep -E '^[[:space:]]*-[[:space:]]+bash scripts/(run-shell-guards\.sh scripts/)?(check|test)-[a-z0-9-]+\.sh' .gitlab-ci.yml \
    | grep -oE 'scripts/(check|test)-[a-z0-9-]+\.sh' | sort -u)

declare -A on_disk=() in_ci=()
for guard in "${disk_guards[@]}"; do on_disk["${guard}"]=1; done
for guard in "${ci_guards[@]}"; do in_ci["${guard}"]=1; done

echo "guard census: CI=${#ci_guards[@]} namespace=${#disk_guards[@]}"
if ((${#ci_guards[@]} == 0 || ${#disk_guards[@]} == 0)); then
    echo 'guard drift: empty guard inventory' >&2
    exit 1
fi
drift=0
for guard in "${ci_guards[@]}"; do
    if [[ ! -v on_disk[${guard}] ]]; then
        echo "guard drift: CI only: ${guard}" >&2
        drift=1
    fi
done
for guard in "${disk_guards[@]}"; do
    if [[ ! -v in_ci[${guard}] ]]; then
        echo "guard drift: namespace only: ${guard}; add a CI call site through scripts/run-shell-guards.sh" >&2
        drift=1
    fi
done
if [[ "${drift}" -ne 0 ]]; then exit 1; fi
echo 'guard drift: none'

if (($#)); then
    if (($# != 1)) || [[ ! -v on_disk[$1] ]]; then
        echo "error: expected one guard from scripts/check-*.sh or scripts/test-*.sh" >&2
        exit 1
    fi
    selected=("$1")
else
    selected=("${disk_guards[@]}")
fi

passed=0
unavailable=0
failed=0
for guard in "${selected[@]}"; do
    if [[ "${guard}" == scripts/check-attribution.sh ]] &&
        [[ -n "$(git status --porcelain -- THIRD-PARTY-LICENSES.md THIRD-PARTY-LICENSES.json)" ]]; then
        echo "NOT RUNNABLE ${guard} (dirty attribution files; regeneration would discard uncommitted work)"
        unavailable=$((unavailable + 1))
        continue
    fi

    log="$(mktemp)"
    rc=0
    bash "${guard}" > "${log}" 2>&1 || rc=$?
    case "${rc}" in
        0)
            echo "PASS ${guard}"
            passed=$((passed + 1))
            ;;
        2)
            echo "NOT RUNNABLE ${guard} (exit 2)"
            sed 's/^/  | /' "${log}"
            unavailable=$((unavailable + 1))
            ;;
        *)
            echo "FAIL ${guard} (exit ${rc})"
            sed 's/^/  | /' "${log}"
            failed=$((failed + 1))
            ;;
    esac
    rm -f -- "${log}"
done

echo "guard summary: passed=${passed} not_runnable=${unavailable} failed=${failed}"
if ((failed)); then exit 1; fi
if ((unavailable)); then exit 2; fi
exit 0
