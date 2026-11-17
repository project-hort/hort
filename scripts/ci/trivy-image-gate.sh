#!/usr/bin/env bash
# Scan the images hort builds and the base images it pins for fixable CRITICAL
# CVEs, and answer in the exit code. What a finding COSTS is the calling job's
# `allow_failure:`, not this script's — see "Exit codes" below.
#
# usage: trivy-image-gate.sh [--pull] <image-ref>...
#
#   --pull  `buildah pull` each reference before scanning it (the
#           pinned-base-image scan). WITHOUT it every reference must already
#           be in the runner's local container store — the post-build,
#           pre-push scan, where pulling would hide a build that never
#           produced the tag.
#
# Why the bytes reach Trivy through the local container store and a
# `docker-archive` export instead of `trivy image <ref>`: the runner resolves
# a registry reference through `/etc/containers/registries.conf` — short-name
# aliases, prefix rewrites and digest-eligible mirrors — and authenticates
# with the credential `buildah login` already holds. Trivy talks to a registry
# directly and honours none of that, so `trivy image <ref>` would reach a
# different registry than the build reaches, and on a mirror-only runner would
# reach nothing at all. buildah fetches; Trivy reads exactly the bytes buildah
# got, which are the bytes the build consumed.
#
# The verdict is three-valued, and the third value is the point:
#   CLEAN          no fixable CRITICAL in this reference.          exit 0
#   CRITICAL       at least one — the only CVE verdict.            exit 2
#   INDETERMINATE  the scan did not run (pull refused, export      exit 1
#                  failed, scanner error, database unavailable).
#
# INDETERMINATE is non-zero like CRITICAL, because an image nobody scanned must
# never read as an image with no findings — and labelled apart from it, because
# an unavailable mirror or a quarantined digest is not a CVE and reading it as
# one sends the next reader hunting a vulnerability that is not there.
#
# Exit codes, and why they are two rather than one. The same CVE verdict does
# not cost the same everywhere. In an image THIS PIPELINE BUILDS it is ours to
# fix, and the image must not reach the registry or receive a cosign signature;
# in a base image this pipeline only PINS it is cleared by an upstream rebuild,
# which no change in this repository can produce, so the caller reports it and
# the pipeline goes on. A cost belongs to the job, not to the scanner — and a
# job can only separate the two with `allow_failure: exit_codes:` if they leave
# under different codes, which is the whole reason there are two.
#
# INDETERMINATE keeps exit 1: "this failed for a reason you must act on", which
# is what every other failure in .gitlab-ci.yml means. A scan that did not run
# is this pipeline breaking, never an upstream CVE, so it is the one verdict no
# caller may allow — and it outranks CRITICAL when a single run produces both,
# because the run has to leave under a code that still fails.
#
# An unplanned `set -e` abort leaves under INDETERMINATE too, via the ERR trap
# below, rather than under whatever status the tool that died happened to pick:
# both sed and grep answer 2 on an unreadable file, and 2 is the CVE code, so
# without the trap a vanished temp file would report a scan that never ran as
# an allowed CVE warning. Nothing but the deliberate verdict below may leave
# under the CVE code.
#
# Policy, identical to the ghcr publish gate in
# `.github/workflows/docker-publish.yml`: severity CRITICAL, fixable only. A
# CVE with no published fix is the base-image maintainers' to patch and
# nothing in this repository can clear it, so gating on it would make every
# push red for something no change here can fix.
#
# Scanner scope is `vuln`. Trivy's secret scanner is a second verdict class
# over third-party base-image contents that no change here can act on either;
# the publish gate still runs it over the images hort itself ships.
#
# `.trivyignore` (repo root) is honoured — one suppression list, maintainer-
# owned, shared with the publish gate, so an accepted CVE does not mean one
# gate green and the other permanently red. Its active entries are printed
# below before any scan runs: a suppressed finding is a visible decision here,
# never a silent one.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${root}"

# The two non-zero verdicts leave under different codes so a caller can allow
# one without allowing the other; see "Exit codes" in the header. Named rather
# than spelled at the `exit`s, because the distinction is the point and a bare
# `exit 2` four screens down reads as an arbitrary number.
EXIT_SCAN_DID_NOT_RUN=1
EXIT_CVE_FINDING=2

# Every unplanned abort is the scan not running. Without this it would leave
# under the failing tool's own status, and the two tools this script pipes
# logs through — sed and grep — both answer 2 on an unreadable file, which is
# exactly the code a caller is allowed to wave through.
trap 'exit "${EXIT_SCAN_DID_NOT_RUN}"' ERR

pull=0
if [[ "${1:-}" == "--pull" ]]; then
    pull=1
    shift
fi

if (($# == 0)); then
    echo "usage: $(basename "$0") [--pull] <image-ref>..." >&2
    exit "${EXIT_SCAN_DID_NOT_RUN}"
fi

severity="CRITICAL"
export TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/tmp/hort-trivy-cache}"
# One literal path, reused per reference and removed after each scan: a
# destructive command on a variable path is what hangs a headless runner on an
# un-bypassable confirmation.
archive="/tmp/hort-image-scan.tar"
trap 'rm -f -- "/tmp/hort-image-scan.tar"' EXIT

if ! bash "${root}/scripts/ci/install-trivy.sh"; then
    echo ""
    echo "INDETERMINATE — the scanner could not be installed; nothing was scanned."
    echo "  Not a CVE verdict; the message above says what refused."
    exit "${EXIT_SCAN_DID_NOT_RUN}"
fi

echo ""
echo "=== scan policy ==="
echo "  severity:   ${severity}"
echo "  fixable:    only (--ignore-unfixed)"
echo "  scanners:   vuln"
trivy_version="$(mktemp)"
trivy --version > "${trivy_version}" 2>&1 || true
echo "  trivy:      $(sed -n '1p' "${trivy_version}")"
rm -f -- "${trivy_version}"
echo "  cache dir:  ${TRIVY_CACHE_DIR}"
if [[ -r .trivyignore ]]; then
    accepted="$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' .trivyignore)"
    if [[ -n "${accepted}" ]]; then
        echo "  accepted CVEs (.trivyignore) — these are suppressed by maintainer decision:"
        printf '%s\n' "${accepted}" | sed 's/^/    /'
    else
        echo "  accepted CVEs (.trivyignore): none"
    fi
else
    echo "  accepted CVEs: no .trivyignore present"
fi
echo "==================="

# Download the vulnerability database as its own attributable step. Folded
# into the first scan, a database that cannot be fetched looks exactly like a
# scanner error on that one image; on its own it reads as what it is.
echo ""
echo "--- vulnerability database"
db_log="$(mktemp)"
db_rc=0
trivy image --download-db-only --skip-version-check > "${db_log}" 2>&1 || db_rc=$?
sed 's/^/    | /' "${db_log}"
rm -f -- "${db_log}"
if [[ "${db_rc}" -ne 0 ]]; then
    echo ""
    echo "INDETERMINATE — the vulnerability database could not be downloaded (trivy exit ${db_rc})."
    echo "  This is the scan failing to run, NOT a CVE verdict: nothing was scanned."
    echo "  The job needs HTTPS egress to the database repository, which trivy reads"
    echo "  from mirror.gcr.io/aquasec/trivy-db:2 and falls back to"
    echo "  ghcr.io/aquasecurity/trivy-db:2. Note this fetch does NOT go through the"
    echo "  runner's registries.conf — trivy speaks to that registry itself — so an"
    echo "  air-gapped runner needs TRIVY_DB_REPOSITORY pointed at a local mirror."
    exit "${EXIT_SCAN_DID_NOT_RUN}"
fi

clean=0
critical=0
indeterminate=0
critical_refs=()
indeterminate_refs=()

for ref in "$@"; do
    echo ""
    echo "=== ${ref}"

    if [[ "${pull}" -eq 1 ]]; then
        pull_log="$(mktemp)"
        pull_rc=0
        buildah pull "${ref}" > "${pull_log}" 2>&1 || pull_rc=$?
        sed 's/^/    | /' "${pull_log}"
        quarantined=0
        # containers/image prints "received unexpected HTTP status: 503" —
        # match that shape, not a bare "503", which a digest can contain.
        if grep -qF 'HTTP status: 503' "${pull_log}"; then
            quarantined=1
        fi
        rm -f -- "${pull_log}"
        if [[ "${pull_rc}" -ne 0 ]]; then
            echo "    INDETERMINATE — buildah pull failed (exit ${pull_rc}); nothing was scanned."
            if [[ "${quarantined}" -eq 1 ]]; then
                echo "    The pull saw a 503. Through hort's pull-through proxy that is the"
                echo "    quarantine answer for a freshly-ingested digest, which clears with the"
                echo "    observation window — the same state base-images:preflight reports as"
                echo "    QUARANTINED. It is not a CVE and not a scan result."
            fi
            indeterminate=$((indeterminate + 1))
            indeterminate_refs+=("${ref}")
            continue
        fi
    fi

    # Presence, asserted before the export so "not in the store" reads as
    # itself rather than as an export failure. No --format: a template key is
    # one more thing that can change under the gate.
    if ! buildah inspect --type image "${ref}" > /dev/null 2>&1; then
        echo "    INDETERMINATE — not in the runner's local container store; nothing was scanned."
        echo "    Without --pull this scan is the post-build one: the reference it is handed"
        echo "    is the tag the build just produced, so an absent one means the build and the"
        echo "    scan disagree about what was built."
        indeterminate=$((indeterminate + 1))
        indeterminate_refs+=("${ref}")
        continue
    fi

    rm -f -- "${archive}"
    export_log="$(mktemp)"
    export_rc=0
    buildah push "${ref}" "docker-archive:${archive}:localhost/hort-image-scan:current" \
        > "${export_log}" 2>&1 || export_rc=$?
    if [[ "${export_rc}" -ne 0 ]]; then
        sed 's/^/    | /' "${export_log}"
        rm -f -- "${export_log}"
        echo "    INDETERMINATE — export to a docker-archive failed (exit ${export_rc}); nothing was scanned."
        indeterminate=$((indeterminate + 1))
        indeterminate_refs+=("${ref}")
        continue
    fi
    rm -f -- "${export_log}"

    # The gate run. `--exit-code 1` makes a finding non-zero; a scanner error
    # is ALSO non-zero, so a non-zero result is disambiguated by one more run
    # with `--exit-code 0`, where only an error can still be non-zero. That is
    # the whole reason this script can tell a CVE from a broken scan without
    # parsing a report format.
    scan_log="$(mktemp)"
    scan_rc=0
    trivy image \
        --input "${archive}" \
        --scanners vuln \
        --severity "${severity}" \
        --ignore-unfixed \
        --skip-db-update \
        --skip-version-check \
        --format table \
        --exit-code 1 \
        > "${scan_log}" 2>&1 || scan_rc=$?

    if [[ "${scan_rc}" -eq 0 ]]; then
        sed 's/^/    | /' "${scan_log}"
        rm -f -- "${scan_log}"
        rm -f -- "${archive}"
        echo "    CLEAN — no fixable ${severity}."
        clean=$((clean + 1))
        continue
    fi

    probe_log="$(mktemp)"
    probe_rc=0
    trivy image \
        --input "${archive}" \
        --scanners vuln \
        --severity "${severity}" \
        --ignore-unfixed \
        --skip-db-update \
        --skip-version-check \
        --format table \
        --exit-code 0 \
        > "${probe_log}" 2>&1 || probe_rc=$?
    rm -f -- "${archive}"

    if [[ "${probe_rc}" -eq 0 ]]; then
        sed 's/^/    | /' "${probe_log}"
        echo "    ${severity} — fixable ${severity} finding(s) above."
        critical=$((critical + 1))
        critical_refs+=("${ref}")
    else
        sed 's/^/    | /' "${scan_log}"
        echo "    INDETERMINATE — trivy exited ${scan_rc} with findings reporting off too"
        echo "    (exit ${probe_rc}), so the non-zero result is a scanner error and not a"
        echo "    ${severity} verdict. Nothing was scanned."
        indeterminate=$((indeterminate + 1))
        indeterminate_refs+=("${ref}")
    fi
    rm -f -- "${scan_log}" "${probe_log}"
done

echo ""
echo "=== image CVE gate summary ==="
echo "  references:    $#"
echo "  clean:         ${clean}"
echo "  ${severity}:      ${critical}"
echo "  INDETERMINATE: ${indeterminate}"
if ((critical)); then
    echo ""
    echo "  fixable ${severity} in:"
    for ref in "${critical_refs[@]}"; do echo "    ${ref}"; done
    echo "  Cleared by moving the pin forward to a base image that carries the fix,"
    echo "  or by upgrading the affected layer. Suppressing it in .trivyignore is a"
    echo "  maintainer decision with a written reason, never the routine answer."
    echo ""
    echo "  This verdict leaves with exit ${EXIT_CVE_FINDING}. Whether that stops the pipeline is the"
    echo "  calling job's \`allow_failure:\`, not this script's, and it differs by what the"
    echo "  image IS: one this pipeline BUILDS is refused outright, because the finding"
    echo "  is ours to fix and the image must not reach the registry or receive a cosign"
    echo "  signature; a base image it only PINS is reported and the pipeline goes on,"
    echo "  because the fix is an upstream rebuild no change here can produce. Either"
    echo "  way the finding above is the same finding, and so is the work it names."
fi
if ((indeterminate)); then
    echo ""
    echo "  scan did not run for:"
    for ref in "${indeterminate_refs[@]}"; do echo "    ${ref}"; done
    echo "  These are NOT CVE findings. Each line above says what refused."
    echo "  This verdict leaves with exit ${EXIT_SCAN_DID_NOT_RUN}, which no caller is allowed to wave"
    echo "  through: an image nobody scanned must never read as one with no findings."
fi
echo "=============================="

# INDETERMINATE first: a run that both found a CVE and failed to scan something
# must leave under the code no caller is allowed to wave through, or the half
# that did not run disappears behind the half that did.
if ((indeterminate)); then exit "${EXIT_SCAN_DID_NOT_RUN}"; fi
if ((critical)); then exit "${EXIT_CVE_FINDING}"; fi
exit 0
