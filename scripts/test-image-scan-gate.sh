#!/usr/bin/env bash
#
# scripts/test-image-scan-gate.sh — the image CVE gate is wired where it has
# to be wired, its policy is still the policy, and its two verdicts still cost
# different things.
#
# Three invariants, none of which convention holds on its own.
#
#   1. Every job that BUILDS a container image calls
#      `scripts/ci/trivy-image-gate.sh`, and calls it BEFORE that job's first
#      `buildah push`. A third image-build job added next to the two that
#      exist today would compile, run, push and cosign-sign an unscanned
#      image, and nothing else in the pipeline would notice: the ghcr publish
#      gate only ever sees what GitHub's workflow publishes, which is not
#      what this pipeline pushes. The order matters just as much as the call
#      — a scan after the push has already handed the registry the bytes it
#      was supposed to refuse, and the signature over them.
#
#   2. The pinned-base scan reads its reference set from
#      `scripts/ci/base-image-refs.sh` and runs on code-changing pushes. A
#      second reference list drifts the moment a Dockerfile gains a stage,
#      and the stale half is the half nobody scans; a tag-scoped rule makes
#      the gate miss the run that introduced the problem, which is the only
#      run where it is cheap to fix.
#
#   3. The gate's two non-zero verdicts leave under DIFFERENT exit codes, and
#      each caller allows exactly the ones it is meant to:
#        - a CVE finding and a scan that did not run must not share a code.
#          The moment they do, the only way to warn on one is to warn on both,
#          and "the scanner has been broken for three weeks" renders as the
#          same yellow square as "upstream has a CVE we are waiting out".
#        - `security:base-image-scan` allows the CVE code and NOTHING else. A
#          base image's CRITICAL waits on an upstream rebuild no change here
#          can produce, so blocking on it costs availability and buys nothing;
#          an INDETERMINATE there is this pipeline breaking and must stay red.
#        - `build-images:*` allow NEITHER, inherited `allow_failure` included.
#          Those are images hort produces: a fixable CRITICAL is ours to fix
#          and must not reach the registry or receive a cosign signature.
#
# The corpus is DERIVED, not listed: a job is an image build because its
# script runs `buildah bud`, and the pinned-base scan is the job that calls
# the gate with `--pull`. A new one joins the corpus by existing. There is no
# allow-list — a build that should not be scanned, or a scan that should be
# allowed to fail differently, is a review conversation, not an exemption
# entry. The exit codes themselves are read out of the gate script rather than
# restated here, so the YAML and the script cannot drift apart without this
# scan seeing it.
#
# Counter-assertions, so a rename cannot make this vacuously green: the
# `buildah bud` corpus must be non-empty, the gate script must still define
# the CRITICAL/fixable-only policy, both exit-code constants and both verdict
# `exit`s, the enumeration script must still exist, and the Trivy version pin
# `install-trivy.sh` reads out of `docker/Dockerfile.worker` must still be
# there under the names it reads. Then four mutation checks, each one a
# specific way this could silently come apart: the gate calls stripped out of
# `.gitlab-ci.yml`; the base-image job's allowed list widened to cover a scan
# that did not run; the two exit-code constants set to the same number; and
# the two verdict `exit`s merged back into one.
#
# Blind spots, named: a gate call assembled through a YAML anchor or reached
# through a differently-named wrapper script reads as missing; an `extends:`
# chain more than one hop deep is not followed, so an `allow_failure` on a
# template that another template extends is not seen. All three are false
# negatives on the permissive side of a review conversation, not silent
# passes of a known-bad shape.
#
# Run by:
#   - `.gitlab-ci.yml`   (quality:image-scan-gate-guard)
#   - locally before pushing, via scripts/run-shell-guards.sh
#
# Implementation: pure bash, no database, sub-second. No awk: the CI job runs
# this on alpine, where awk is busybox's.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

gate_script="scripts/ci/trivy-image-gate.sh"
refs_script="scripts/ci/base-image-refs.sh"
install_script="scripts/ci/install-trivy.sh"
worker_dockerfile="docker/Dockerfile.worker"

# A top-level key in .gitlab-ci.yml: a job, or a `.`-prefixed template/anchor.
# Templates are blocks of their own precisely so an `extends:` target can be
# looked up — without the leading `.`, `.docker`'s body reads as a trailing
# part of whatever job happens to precede it.
key_re='^(\.?[A-Za-z_][A-Za-z0-9_:.-]*):'

failures=0
fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

# A line's CODE part is whatever precedes its first `#`. A comment that
# discusses `buildah push` or names the gate script — this file's own header
# does both, and so does the base-image job's — must not be read as doing
# either.
code_of() {
    local line="$1"
    printf '%s' "${line%%#*}"
}

rtrim() {
    local v="$1"
    printf '%s' "${v%"${v##*[![:space:]]}"}"
}

# `allow_failure:` of one top-level block, flattened to a verdict string:
#   absent            the block has no allow_failure key
#   true | false      an inline scalar
#   exit_codes:A,B    the per-code form, codes in file order
#   block-without-exit-codes
#                     the block form, but with no `exit_codes:` list under it
#
# Read from the file rather than from an accumulated job block, because a job
# can inherit one through `extends:` and the template is a different block.
block_allow_failure() {
    local file="$1" want="$2"
    local -a lines=()
    mapfile -t lines < "${file}"

    local cur="" verdict="absent" codes="" in_af=0 af_indent=0 has_exit_codes=0
    local raw code value indent
    for raw in "${lines[@]}"; do
        if [[ "${raw}" =~ ${key_re} ]]; then
            cur="${BASH_REMATCH[1]}"
            in_af=0
            continue
        fi
        [[ "${cur}" == "${want}" ]] || continue
        code="$(code_of "${raw}")"
        if [[ "${code}" =~ ^([[:space:]]*)allow_failure:(.*)$ ]]; then
            af_indent="${#BASH_REMATCH[1]}"
            value="$(rtrim "${BASH_REMATCH[2]}")"
            value="${value#"${value%%[![:space:]]*}"}"
            if [[ -n "${value}" ]]; then
                verdict="${value}"
                in_af=0
            else
                verdict="block-without-exit-codes"
                in_af=1
            fi
            continue
        fi
        ((in_af)) || continue
        [[ -n "${code//[[:space:]]/}" ]] || continue
        [[ "${code}" =~ ^([[:space:]]*) ]]
        indent="${#BASH_REMATCH[1]}"
        if ((indent <= af_indent)); then
            in_af=0
            continue
        fi
        if [[ "${code}" =~ ^[[:space:]]*exit_codes: ]]; then
            has_exit_codes=1
            continue
        fi
        if [[ "${code}" =~ ^[[:space:]]*-[[:space:]]*([0-9]+)[[:space:]]*$ ]] && ((has_exit_codes)); then
            codes="${codes:+${codes},}${BASH_REMATCH[1]}"
            verdict="exit_codes"
        fi
    done

    if [[ "${verdict}" == "exit_codes" ]]; then
        printf 'exit_codes:%s' "${codes}"
    else
        printf '%s' "${verdict}"
    fi
}

# The templates one top-level block `extends:`, one per line. Inline scalar
# (`extends: .docker`) and sequence forms both.
block_extends() {
    local file="$1" want="$2"
    local -a lines=()
    mapfile -t lines < "${file}"

    local cur="" in_ex=0 ex_indent=0
    local raw code value indent
    for raw in "${lines[@]}"; do
        if [[ "${raw}" =~ ${key_re} ]]; then
            cur="${BASH_REMATCH[1]}"
            in_ex=0
            continue
        fi
        [[ "${cur}" == "${want}" ]] || continue
        code="$(code_of "${raw}")"
        if [[ "${code}" =~ ^([[:space:]]*)extends:(.*)$ ]]; then
            ex_indent="${#BASH_REMATCH[1]}"
            value="$(rtrim "${BASH_REMATCH[2]}")"
            value="${value#"${value%%[![:space:]]*}"}"
            if [[ -n "${value}" ]]; then
                printf '%s\n' "${value}"
                in_ex=0
            else
                in_ex=1
            fi
            continue
        fi
        ((in_ex)) || continue
        [[ -n "${code//[[:space:]]/}" ]] || continue
        [[ "${code}" =~ ^([[:space:]]*) ]]
        indent="${#BASH_REMATCH[1]}"
        if ((indent <= ex_indent)); then
            in_ex=0
            continue
        fi
        if [[ "${code}" =~ ^[[:space:]]*-[[:space:]]*(.+)$ ]]; then
            printf '%s\n' "$(rtrim "${BASH_REMATCH[1]}")"
        fi
    done
}

# Scan one .gitlab-ci.yml for invariants 1-3. Findings go to stderr via
# `fail`; the census — image-build jobs, pinned-base-scan jobs, and the name
# of the first pinned-base-scan job — is written to the file named by $3.
#
# NOT called in a command substitution, deliberately: that runs the function
# in a subshell, where every `fail` increments a copy of the counter that is
# discarded on return — the guard would print its findings and still exit 0,
# which is the exact failure mode a guard must not have. The census leaves
# through a file so the counter can stay in this shell.
scan_ci_file() {
    local file="$1" label="$2" census_out="$3" cve_code="$4" indet_code="$5"
    local -a lines=()
    mapfile -t lines < "${file}"

    local job="" job_start=0
    local bud_jobs=0 pull_jobs=0 pull_job_name=""
    local -a job_lines=()

    # Verdict for one accumulated job block.
    check_job() {
        local name="$1"
        local i code af
        local has_bud=0 gate_line=-1 push_line=-1 refs_line=-1
        local has_pull=0 has_rules_anchor=0 has_own_rules=0
        for i in "${!job_lines[@]}"; do
            code="$(code_of "${job_lines[$i]}")"
            [[ -n "${code}" ]] || continue
            [[ "${code}" == *"buildah bud"* ]] && has_bud=1
            if [[ "${code}" == *"${gate_script}"* ]]; then
                ((gate_line >= 0)) || gate_line=$i
                [[ "${code}" == *"--pull"* ]] && has_pull=1
            fi
            if [[ "${code}" == *"buildah push"* ]] && ((push_line < 0)); then
                push_line=$i
            fi
            [[ "${code}" == *"${refs_script}"* ]] && refs_line=$i
            [[ "${code}" == *"<<: *rules-code-changed"* ]] && has_rules_anchor=1
            [[ "${code}" =~ ^[[:space:]]+rules:[[:space:]]*$ ]] && has_own_rules=1
        done

        if ((has_bud)); then
            bud_jobs=$((bud_jobs + 1))
            if ((gate_line < 0)); then
                fail "${label}: job '${name}' runs \`buildah bud\` but never calls ${gate_script} — it would push and sign an unscanned image"
            elif ((push_line >= 0 && gate_line > push_line)); then
                fail "${label}: job '${name}' calls ${gate_script} AFTER its first \`buildah push\` — the registry already has the bytes the gate exists to refuse"
            fi

            # Invariant 3, build side: neither verdict may be waved through,
            # whether the allowance is written on the job or inherited.
            af="$(block_allow_failure "${file}" "${name}")"
            if [[ "${af}" != "absent" && "${af}" != "false" ]]; then
                fail "${label}: job '${name}' builds an image and carries \`allow_failure: ${af}\` — a fixable CRITICAL in an image hort PRODUCES is ours to fix, and allowing the gate to fail pushes and cosign-signs it anyway"
            fi
            local template
            while IFS= read -r template; do
                [[ -n "${template}" ]] || continue
                af="$(block_allow_failure "${file}" "${template}")"
                if [[ "${af}" != "absent" && "${af}" != "false" ]]; then
                    fail "${label}: job '${name}' inherits \`allow_failure: ${af}\` from '${template}' — same effect as writing it on the job: the image it built is pushed and signed despite the gate's verdict"
                fi
            done < <(block_extends "${file}" "${name}")
        fi

        if ((has_pull)); then
            pull_jobs=$((pull_jobs + 1))
            [[ -n "${pull_job_name}" ]] || pull_job_name="${name}"
            if ((refs_line < 0)); then
                fail "${label}: job '${name}' scans pinned base images but does not read ${refs_script} — a second reference list drifts from the pinned set"
            fi
            if ((has_rules_anchor == 0 || has_own_rules == 1)); then
                fail "${label}: job '${name}' must carry \`<<: *rules-code-changed\` and no \`rules:\` of its own — a release-scoped base-image scan misses the push that introduced the finding"
            fi

            # Invariant 3, pinned-base side: the CVE code is allowed, and it
            # is the ONLY thing allowed.
            af="$(block_allow_failure "${file}" "${name}")"
            if [[ "${af}" != "exit_codes:${cve_code}" ]]; then
                fail "${label}: job '${name}' must carry exactly \`allow_failure: {exit_codes: [${cve_code}]}\`, found \`${af}\` — ${cve_code} is the gate's CVE verdict, which a base image clears only through an upstream rebuild, and it is the one code this job may fail with"
            fi
            # Membership, not substring: with the codes spelled `21` or `12`
            # a `*1*` test would report a job that does not allow 1 at all.
            local allows_indet=0
            case "${af}" in
                true) allows_indet=1 ;;
                exit_codes:*)
                    case ",${af#exit_codes:}," in
                        *",${indet_code},"*) allows_indet=1 ;;
                    esac
                    ;;
            esac
            if ((allows_indet)); then
                fail "${label}: job '${name}' allows exit ${indet_code} (\`${af}\`) — that is the gate's 'the scan did not run' verdict: a refused pull, an undownloadable database or a scanner error would report as a warning, and an image nobody scanned must never read as an image with no findings"
            fi
        fi
    }

    for ((job_start = 0; job_start < ${#lines[@]}; job_start++)); do
        if [[ "${lines[$job_start]}" =~ ${key_re} ]]; then
            # Read the capture BEFORE check_job runs: it matches regexes of
            # its own, and BASH_REMATCH is global.
            local next_job="${BASH_REMATCH[1]}"
            if [[ -n "${job}" ]]; then check_job "${job}"; fi
            job="${next_job}"
            job_lines=()
            continue
        fi
        if [[ -n "${job}" ]]; then job_lines+=("${lines[$job_start]}"); fi
    done
    if [[ -n "${job}" ]]; then check_job "${job}"; fi

    printf '%s %s %s\n' "${bud_jobs}" "${pull_jobs}" "${pull_job_name}" > "${census_out}"
}

# The gate script's own counter-assertions, parameterised by path so a mutant
# copy can be put through exactly the same scan. The two exit-code constants
# are written to the file named by $3 for the caller to consume.
check_gate_script() {
    local path="$1" label="$2" codes_out="$3"
    local needle cve indet

    if [[ ! -f "${path}" ]]; then
        fail "counter-assertion: ${label} is missing"
        : > "${codes_out}"
        return
    fi

    for needle in 'severity="CRITICAL"' '--ignore-unfixed' '--exit-code 1' '--scanners vuln'; do
        if ! grep -qF -- "${needle}" "${path}"; then
            fail "counter-assertion: ${label} no longer carries '${needle}' — the call sites would still be there while the policy went away"
        fi
    done

    cve="$(sed -n 's/^EXIT_CVE_FINDING=\([0-9][0-9]*\)$/\1/p' "${path}" | sed -n '1p')"
    indet="$(sed -n 's/^EXIT_SCAN_DID_NOT_RUN=\([0-9][0-9]*\)$/\1/p' "${path}" | sed -n '1p')"
    if [[ -z "${cve}" || -z "${indet}" ]]; then
        fail "counter-assertion: ${label} no longer defines both EXIT_CVE_FINDING and EXIT_SCAN_DID_NOT_RUN as plain numeric assignments — the YAML's \`allow_failure: exit_codes:\` is written against those values and this scan reads them from here rather than restating them"
        : > "${codes_out}"
        return
    fi
    if [[ "${cve}" == "${indet}" ]]; then
        fail "counter-assertion: ${label} gives a CVE finding and a scan that did not run the same exit code (${cve}) — a caller can then only warn on both or block on both, and 'the scanner has been broken for weeks' renders as the same yellow square as 'upstream has a CVE we are waiting out'"
    fi
    if [[ "${indet}" != "1" ]]; then
        fail "counter-assertion: ${label} sets EXIT_SCAN_DID_NOT_RUN=${indet}; it must stay 1, which is what every other failure in .gitlab-ci.yml means — 'this failed for a reason you must act on'"
    fi
    if [[ "${cve}" == "0" ]]; then
        fail "counter-assertion: ${label} sets EXIT_CVE_FINDING=0 — a finding that exits successfully is not a finding"
    fi

    for needle in 'if ((indeterminate)); then exit "${EXIT_SCAN_DID_NOT_RUN}"; fi' \
        'if ((critical)); then exit "${EXIT_CVE_FINDING}"; fi'; do
        if ! grep -qF -- "${needle}" "${path}"; then
            fail "counter-assertion: ${label} no longer ends with \`${needle}\` — the two verdicts must leave through two separate \`exit\`s in this order, so that a run which both found a CVE and failed to scan something leaves under the code no caller may allow"
        fi
    done

    printf '%s %s\n' "${cve}" "${indet}" > "${codes_out}"
}

# ---- the gate script, and the exit codes everything else is checked against
codes_file="$(mktemp)"
check_gate_script "${gate_script}" "${gate_script}" "${codes_file}"
cve_code=""
indet_code=""
read -r cve_code indet_code < "${codes_file}" || true
rm -f -- "${codes_file}"
if [[ -z "${cve_code}" || -z "${indet_code}" ]]; then
    echo "image scan gate: ${failures} violation(s)" >&2
    echo "FAIL: the exit codes could not be read from ${gate_script}; the wiring checks below have nothing to check against" >&2
    exit 1
fi
echo "exit codes (read from ${gate_script}): CVE finding=${cve_code} scan did not run=${indet_code}"

# ---- invariants 1-3, on the real file -------------------------------------
census_file="$(mktemp)"
scan_ci_file .gitlab-ci.yml '.gitlab-ci.yml' "${census_file}" "${cve_code}" "${indet_code}"
read -r bud_count pull_count pull_job < "${census_file}"
rm -f -- "${census_file}"
echo "census: image-build jobs=${bud_count} pinned-base-scan jobs=${pull_count} (${pull_job:-none})"

# ---- counter-assertion: the corpus is real -------------------------------
# Nine of ten structural guards that go quietly green do it because the thing
# they scan for stopped being spelled that way.
if ((bud_count < 2)); then
    fail "counter-assertion: expected at least 2 jobs running \`buildah bud\` (hort-server + hort-worker), found ${bud_count} — the corpus this guard derives has moved, so its green result means nothing"
fi
if ((pull_count < 1)); then
    fail "counter-assertion: no job calls ${gate_script} --pull — the pinned-base-image scan is gone"
fi

if [[ ! -f "${refs_script}" ]]; then
    fail "counter-assertion: ${refs_script} is missing — the one enumeration both the availability check and the scan consume"
fi

# ---- counter-assertion: the Trivy pin is where the installer reads it ----
# install-trivy.sh fails loudly on a renamed ARG, but it fails IN CI. Catch it
# here, where the rename is still in front of whoever made it.
if [[ ! -f "${install_script}" || ! -f "${worker_dockerfile}" ]]; then
    fail "counter-assertion: ${install_script} or ${worker_dockerfile} is missing"
else
    for arg in TRIVY_VERSION TRIVY_SHA256_AMD64 TRIVY_SHA256_ARM64; do
        if ! grep -qF "${arg}" "${install_script}"; then
            fail "counter-assertion: ${install_script} no longer reads ${arg}"
        fi
        if ! grep -qE "^ARG ${arg}=" "${worker_dockerfile}"; then
            fail "counter-assertion: no 'ARG ${arg}=' in ${worker_dockerfile} — the scanner pin the CI gate shares with the shipped worker image has moved, and the gate would install an unpinned scanner"
        fi
    done
fi

# ---- mutation checks: this scan can still fail ---------------------------
# Each mutant is a specific way this could silently come apart, applied to a
# copy of the real on-disk file. A guard that cannot be made to fail is a
# guard that proves nothing.
mutant_out="$(mktemp)"
scratch="$(mktemp)"
expect_red() {
    local what="$1" before="${failures}"
    shift
    "$@" 2> "${mutant_out}"
    if [[ "${failures}" -le "${before}" ]]; then
        echo "FAIL: mutation check: ${what} left this scan green — the predicate does not test what it claims" >&2
        failures=$((before + 1))
    else
        # The mutant's findings are the expected ones; discard them.
        failures="${before}"
        echo "mutation check: ${what} turns this scan red, as it must"
    fi
}

scan_mutant_ci() {
    local census="$1"
    scan_ci_file "${scratch}" 'MUTANT' "${census}" "${cve_code}" "${indet_code}"
}

# M1 — every gate call removed from the pipeline.
mutant_census="$(mktemp)"
grep -vF "${gate_script}" .gitlab-ci.yml > "${scratch}"
expect_red "removing every ${gate_script} call" scan_mutant_ci "${mutant_census}"

# M2 — the base-image job's allowed list widened to cover a scan that did not
# run, which is the collapse this whole distinction exists to prevent.
: > "${scratch}"
cur_block=""
while IFS= read -r raw_line; do
    if [[ "${raw_line}" =~ ${key_re} ]]; then cur_block="${BASH_REMATCH[1]}"; fi
    printf '%s\n' "${raw_line}" >> "${scratch}"
    if [[ "${cur_block}" == "${pull_job}" ]] &&
        [[ "${raw_line}" =~ ^([[:space:]]+)-[[:space:]]*[0-9]+[[:space:]]*$ ]]; then
        printf '%s- %s\n' "${BASH_REMATCH[1]}" "${indet_code}" >> "${scratch}"
    fi
done < .gitlab-ci.yml
expect_red "letting '${pull_job}' also allow exit ${indet_code}" scan_mutant_ci "${mutant_census}"
rm -f -- "${mutant_census}"

# M3 — the two exit-code constants set to the same number.
mutant_codes="$(mktemp)"
sed "s/^EXIT_CVE_FINDING=.*/EXIT_CVE_FINDING=${indet_code}/" "${gate_script}" > "${scratch}"
expect_red "re-merging the gate's two exit codes into ${indet_code}" \
    check_gate_script "${scratch}" 'MUTANT' "${mutant_codes}"

# M4 — the two verdict `exit`s merged back into one.
sed -e 's/^if ((indeterminate)); then exit .*/if ((critical || indeterminate)); then exit 1; fi/' \
    -e '/^if ((critical)); then exit /d' "${gate_script}" > "${scratch}"
expect_red "merging the gate's two verdict exits back into one" \
    check_gate_script "${scratch}" 'MUTANT' "${mutant_codes}"
rm -f -- "${mutant_codes}"

rm -f -- "${scratch}" "${mutant_out}"

if ((failures)); then
    echo "image scan gate: ${failures} violation(s)" >&2
    exit 1
fi
echo 'image scan gate: the gate is called in every image build before its push, the pinned-base scan reads the one enumeration on every code-changing push, and the two verdicts still cost what they are meant to — the builds allow neither, the pinned-base scan allows the CVE code alone'
