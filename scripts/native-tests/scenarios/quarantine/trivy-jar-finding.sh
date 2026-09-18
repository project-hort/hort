#!/usr/bin/env bash
# requires: db worker scanner egress
# Trivy materialisation e2e: a known-vulnerable JAR through a Trivy-policy proxy must yield a finding.
#
# THE INVARIANT THIS PINS. A Trivy scan of a real hort artifact must be able
# to produce a finding. That takes two things the unit tests cannot prove
# together, because both are facts about Trivy rather than about hort's code:
# the artifact has to be materialised under a name and layout an analyzer
# claims, AND it has to be scanned with the subcommand that analyzer runs
# under (a Java archive is post-build, so only the Image and Rootfs targets
# read it — `trivy fs` on a correctly-named JAR still analyses nothing). Get
# either half wrong and the report carries no analysed target, which is
# indistinguishable from a clean scan unless something asserts a real
# finding. This scenario is that assertion.
#
# Fixture: `maven-trivy-e2e`, a private Maven Central pull-through repo with
# a `ScanPolicy { scanBackends: ["trivy"], enforcement: record,
# quarantineDuration: 20s }` (deploy/compose/example-config/{repositories,
# upstreams,policies,auth}/*maven-trivy-e2e*). record mode means a Trivy
# verdict never gates the artifact, so the scenario's assertions are never at
# the mercy of the policy's enforcement arm — only of whether Trivy actually
# found anything.
#
#   1. Authenticated (dev-user) pull-through of
#      org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar
#      (CVE-2021-44228, a canonical, long-standing, still-listed Log4Shell
#      advisory) — triggers ingest. The private repo's short quarantine
#      window means this first fetch may itself come back 503 (mirrors the
#      dogfood crates-proxy leg); that is expected and not asserted against —
#      what matters is that the artifact row exists afterwards.
#   2. Locate the ingested JAR by (repository_id, path) — `path`, not
#      (name, version): the `.pom` negative control below shares the same
#      Maven coordinate (name + version) and is distinguished only by path.
#   3. Bounded-poll `artifacts.last_scan_at` for the JAR (worker + trivy
#      backend async).
#   4. Assert `scan_findings` carries >= 1 row for this artifact with
#      vulnerability_id = CVE-2021-44228 and source_scanner = trivy. Zero
#      findings here means the JAR reached no analyzer — the failure message
#      names that rather than the count alone.
#   5. Negative control: pull the `.pom` of the same coordinate through the
#      same repo. A POM is a pre-build declaration and takes the other
#      subcommand (`fs`), so this leg is what would catch a change that moved
#      every kind to one target. Assert the scan completes (no worker crash)
#      and the artifact is not left in `scan_indeterminate` (the fail-closed
#      state for "every scan backend errored") — which findings it carries is
#      the adapter's concern, not this scenario's.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

command -v curl >/dev/null 2>&1 || skip "curl not found in PATH"
command -v jq   >/dev/null 2>&1 || skip "jq not found in PATH"

REPO_KEY="${TRIVY_MAVEN_REPO_KEY:-maven-trivy-e2e}"
REPO_URL="${HORT_URL%/}/maven/${REPO_KEY}"

GROUP_PATH="org/apache/logging/log4j"
ARTIFACT="log4j-core"
VERSION="2.14.1"
CVE="CVE-2021-44228"

JAR_PATH="${GROUP_PATH}/${ARTIFACT}/${VERSION}/${ARTIFACT}-${VERSION}.jar"
POM_PATH="${GROUP_PATH}/${ARTIFACT}/${VERSION}/${ARTIFACT}-${VERSION}.pom"

log "==> Trivy materialisation e2e"
log "repo : ${REPO_URL}"
log "jar  : ${JAR_PATH}"
log "pom  : ${POM_PATH}"

# ---------------------------------------------------------------------------
# Preflight: the repo must be mounted (compose example-config, or an
# equivalent gitops-applied posture on an external hort). Absent -> skip,
# never fail: an external hort without this dogfood-style fixture is a fact
# about that instance, not a defect in this run.
# ---------------------------------------------------------------------------
# Presence: the repository is private (isPublic: false), so an anonymous HTTP
# probe answers 404 for "exists but invisible to you" exactly as for "absent".
# The scenario requires the database anyway, so presence is read from the
# repository row (REPO_ID below); the HTTP probe only proves the server answers.
PREFLIGHT_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "${REPO_URL}/" 2>/dev/null || echo "000")"
case "$PREFLIGHT_CODE" in
    200|401|403|404) : ;;
    *) skip "hort-server unreachable at ${REPO_URL} (HTTP ${PREFLIGHT_CODE})" ;;
esac
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || skip "could not fetch dev-user token from Keycloak — stack not ready"
log "[auth] DEV_TOKEN fetched from Keycloak"

REPO_ID="$(psql_one "SELECT id FROM repositories WHERE key = '${REPO_KEY}' LIMIT 1;")"
[ -n "$REPO_ID" ] || skip "repositories row for key='${REPO_KEY}' absent — gitops apply has not run against this DB"
log "repository id=${REPO_ID}"

# ---------------------------------------------------------------------------
# (1) Authenticated pull-through of the JAR. A 503 (quarantined) is an
# expected outcome here, not a failure -- see header. Only a transport-level
# miss (000) or an unrelated server error means the ingest never happened.
# ---------------------------------------------------------------------------
log ""
log "--- (1) Authenticated pull-through: ${JAR_PATH}"
JAR_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 60 \
    -H "Authorization: Bearer ${DEV_TOKEN}" \
    "${REPO_URL}/${JAR_PATH}" 2>/dev/null || echo "000")"
log "  GET ${JAR_PATH} -> HTTP ${JAR_CODE}"
case "$JAR_CODE" in
    200|503) pass "(1) authenticated pull-through of the JAR triggered ingest (HTTP ${JAR_CODE})" ;;
    *) fail "(1) authenticated pull-through of the JAR" \
        "expected 200 (served) or 503 (quarantined, ingest still happened) — got HTTP ${JAR_CODE}; is Maven Central reachable?" ;;
esac

# ---------------------------------------------------------------------------
# (2) Locate the ingested JAR by (repository_id, path).
# ---------------------------------------------------------------------------
JAR_ID=""
if bounded_poll "JAR ingested" 30 \
        "[ -n \"\$(psql_one \"SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = '${JAR_PATH}';\")\" ]" \
        2; then
    JAR_ID="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = '${JAR_PATH}';")"
    pass "(2) JAR ingested as artifact id=${JAR_ID}"
else
    fail "(2) JAR must be ingested within 30s of the pull-through GET" \
        "no artifacts row for repository_id='${REPO_ID}' path='${JAR_PATH}'"
fi

# ---------------------------------------------------------------------------
# (3)+(4) Await the scan, then assert the finding.
# ---------------------------------------------------------------------------
if [ -n "$JAR_ID" ]; then
    log ""
    log "--- (3) Awaiting ScanCompleted for the JAR (artifact id=${JAR_ID})"
    if bounded_poll \
            "scan completed for ${JAR_ID}" \
            180 \
            "[ -n \"\$(psql_one \"SELECT last_scan_at FROM artifacts WHERE id = '${JAR_ID}' AND last_scan_at IS NOT NULL;\")\" ]" \
            5; then
        pass "(3) scan completed for the JAR (artifacts.last_scan_at set)"

        log ""
        log "--- (4) Trivy finding for ${CVE}"
        FINDING_HIT="$(psql_one "SELECT count(*) FROM scan_findings WHERE artifact_id = '${JAR_ID}' AND vulnerability_id = '${CVE}' AND source_scanner = 'trivy';")"
        if [ "${FINDING_HIT:-0}" -ge 1 ]; then
            pass "(4) Trivy reported ${CVE} for the JAR (${FINDING_HIT} row(s))"
        else
            ALL_FINDINGS="$(psql_one "SELECT string_agg(DISTINCT source_scanner || ':' || vulnerability_id, ',') FROM scan_findings WHERE artifact_id = '${JAR_ID}';" || true)"
            fail "(4) 0 findings for a known-vulnerable JAR" \
                "expected >= 1 scan_findings row for artifact_id='${JAR_ID}' vulnerability_id='${CVE}' source_scanner='trivy' -- all findings on this artifact: ${ALL_FINDINGS:-<none>}. Zero findings means the JAR reached no analyzer: check the worker log for 'report carries no analysed target' and the subcommand + materialised listing it carries -- a Java archive must be materialised under its .jar name AND scanned with 'rootfs'."
        fi
    else
        fail "(3) scan did not complete for the JAR within 180s" \
            "artifacts.last_scan_at still NULL for id='${JAR_ID}' -- is a worker with the trivy backend running against this instance?"
    fi
else
    log "  (3)+(4) skipped: the JAR was not ingested, already reported above"
fi

# ---------------------------------------------------------------------------
# (5) Negative control: the .pom of the same coordinate. Same name+version as
# the JAR, distinguished only by path -- no crash, a verdict is recorded.
# ---------------------------------------------------------------------------
log ""
log "--- (5) Negative control: ${POM_PATH}"
POM_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 60 \
    -H "Authorization: Bearer ${DEV_TOKEN}" \
    "${REPO_URL}/${POM_PATH}" 2>/dev/null || echo "000")"
log "  GET ${POM_PATH} -> HTTP ${POM_CODE}"
case "$POM_CODE" in
    200|503) pass "(5) authenticated pull-through of the .pom triggered ingest (HTTP ${POM_CODE})" ;;
    *) fail "(5) authenticated pull-through of the .pom" \
        "expected 200 or 503 -- got HTTP ${POM_CODE}" ;;
esac

POM_ID=""
if bounded_poll "POM ingested" 30 \
        "[ -n \"\$(psql_one \"SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = '${POM_PATH}';\")\" ]" \
        2; then
    POM_ID="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${REPO_ID}' AND path = '${POM_PATH}';")"
    pass "(5) .pom ingested as artifact id=${POM_ID}"
else
    fail "(5) .pom must be ingested within 30s of the pull-through GET" \
        "no artifacts row for repository_id='${REPO_ID}' path='${POM_PATH}'"
fi

if [ -n "$POM_ID" ]; then
    if bounded_poll \
            "scan completed for ${POM_ID}" \
            180 \
            "[ -n \"\$(psql_one \"SELECT last_scan_at FROM artifacts WHERE id = '${POM_ID}' AND last_scan_at IS NOT NULL;\")\" ]" \
            5; then
        POM_STATUS="$(psql_one "SELECT COALESCE(quarantine_status::text, 'null') FROM artifacts WHERE id = '${POM_ID}';")"
        if [ "$POM_STATUS" = "scan_indeterminate" ]; then
            fail "(5) .pom scan must not crash every backend" \
                "quarantine_status='scan_indeterminate' -- the trivy backend errored on the .pom instead of recording a (possibly empty) verdict"
        else
            pass "(5) .pom scan completed without a backend crash (quarantine_status='${POM_STATUS}', a verdict is recorded)"
        fi
    else
        fail "(5) scan did not complete for the .pom within 180s" \
            "artifacts.last_scan_at still NULL for id='${POM_ID}'"
    fi
else
    log "  (5) scan check skipped: the .pom was not ingested, already reported above"
fi

# ---------------------------------------------------------------------------
summary
