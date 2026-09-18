#!/usr/bin/env bash
# requires: db worker scanner egress
# Maven OSV-scan smoke — proves MavenFormatHandler's PayloadSbom extraction
# feeds a real osv-scanner run, mirroring the record-mode pattern in
# registry-supply-chain.sh part (h) but scoped to one Maven-specific claim.
#
# Publishing a Maven POM declaring a known-affected coordinate
# (org.apache.logging.log4j:log4j-core:2.14.1 — Log4Shell, CVE-2021-44228)
# to a repository with `scanBackends: ["osv"]` must produce:
#
#   1. A `ScanCompleted` event on the artifact's own stream.
#   2. An SBOM component naming the dependency at its exact declared
#      version — proof the POM was actually read, not just the subject.
#   3. At least one recorded `osv` finding for that component.
#
# Without a Maven SBOM this whole chain scans nothing: `FormatHandler::extract_sbom`
# defaulted to `Ok(None)` for Maven, so `OsvScanner::scan` always logged
# "scan skipped — no SBOM provided" and (1)-(3) never happened.
#
# Repository: maven-osv-e2e (deploy/compose/example-config/repositories/
# maven-osv-e2e.yaml), policy: maven-osv-e2e-scan.yaml (scanBackends: ["osv"],
# enforcement: record, quarantineDuration: 0s — the publish itself must never
# be gated by the verdict this scenario is trying to observe).
#
# A standalone `.pom` PUT is enough: the Maven handler's group-membership
# model tolerates a pom-only artifact (a parent POM / BOM has no `jar`
# member), and the SBOM extractor's `.pom` branch does not need a sibling
# jar. A raw PUT keeps the scenario free of `mvn` and its tool dependencies;
# the scan/verdict half mirrors registry-supply-chain.sh part (h).

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

REPO_KEY="${MAVEN_OSV_REPO_KEY:-maven-osv-e2e}"
MAVEN_URL="${HORT_URL%/}/maven/${REPO_KEY}"

STAMP="$(date +%s).$$"
GROUP_ID="de.hort.e2e.osvscan"
GROUP_PATH="${GROUP_ID//./\/}"
ARTIFACT_ID="maven-osv-scan-e2e"
VERSION="1.0.${STAMP}"

VULN_GROUP_ID="org.apache.logging.log4j"
VULN_ARTIFACT_ID="log4j-core"
VULN_VERSION="2.14.1"
VULN_PURL="pkg:maven/${VULN_GROUP_ID}/${VULN_ARTIFACT_ID}@${VULN_VERSION}"

log "==> Maven OSV Scan E2E"
log "Repo: $MAVEN_URL"
log "GAV:  ${GROUP_ID}:${ARTIFACT_ID}:${VERSION}"
log "Vulnerable dependency: ${VULN_PURL} (CVE-2021-44228)"

ADMIN_TOKEN="$(fetch_token admin admin)"
[ -n "$ADMIN_TOKEN" ] || fail "fetch admin token" "empty response from Keycloak"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

POM_FILE="$WORK_DIR/${ARTIFACT_ID}-${VERSION}.pom"
cat > "$POM_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${VERSION}</version>
  <packaging>pom</packaging>
  <dependencies>
    <dependency>
      <groupId>${VULN_GROUP_ID}</groupId>
      <artifactId>${VULN_ARTIFACT_ID}</artifactId>
      <version>${VULN_VERSION}</version>
    </dependency>
  </dependencies>
</project>
EOF

# ---- (1) publish the .pom ----
POM_PATH="${GROUP_PATH}/${ARTIFACT_ID}/${VERSION}/${ARTIFACT_ID}-${VERSION}.pom"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X PUT "${MAVEN_URL}/${POM_PATH}" \
    -u "__token__:${ADMIN_TOKEN}" \
    -T "$POM_FILE")
if [ "$STATUS" = "201" ]; then
    pass "(1) PUT ${POM_PATH} -> 201"
else
    fail "(1) PUT ${POM_PATH} expected 201" "got $STATUS"
    summary
fi

# ---- (2) locate the published artifact ----
ARTIFACT_ID_DB="$(psql_one "SELECT id FROM artifacts WHERE name = '${GROUP_ID}:${ARTIFACT_ID}' AND version = '${VERSION}' LIMIT 1;")"
if [ -z "$ARTIFACT_ID_DB" ]; then
    fail "(2) locate published artifact via psql" \
        "${GROUP_ID}:${ARTIFACT_ID}@${VERSION} absent from the artifacts table after a successful publish"
    summary
fi
log "  artifact id=${ARTIFACT_ID_DB}"

# ---- (3) wait for the scan to complete ----
if bounded_poll \
        "scan completed for ${ARTIFACT_ID_DB}" \
        180 \
        "[ -n \"\$(psql_one \"SELECT last_scan_at FROM artifacts WHERE id = '${ARTIFACT_ID_DB}' AND last_scan_at IS NOT NULL;\")\" ]" \
        5; then
    pass "(3) scan completed for the published pom (artifacts.last_scan_at set)"
else
    fail "(3) scan did not complete within 180s" \
        "artifacts.last_scan_at still NULL — is a worker with the osv backend running against this instance?"
    summary
fi

# record mode: a critical finding must not reject the artifact.
STATUS_DB="$(psql_one "SELECT COALESCE(quarantine_status::text, 'null') FROM artifacts WHERE id = '${ARTIFACT_ID_DB}';")"
if [ "$STATUS_DB" = "rejected" ]; then
    fail "(3) artifact must not be rejected under enforcement: record" \
        "quarantine_status='rejected' — the policy is enforcing, not recording"
else
    pass "(3) quarantine_status='${STATUS_DB}' (not rejected — verdict recorded, not enforced)"
fi

# ---- (4) a ScanCompleted event landed on the artifact's own stream ----
SCAN_COMPLETED_HIT="$(psql_one "SELECT count(*) FROM events WHERE stream_id = 'artifact-${ARTIFACT_ID_DB}' AND event_type = 'ScanCompleted';")"
if [ "${SCAN_COMPLETED_HIT:-0}" -ge 1 ]; then
    pass "(4) ScanCompleted event recorded on artifact-${ARTIFACT_ID_DB}"
else
    fail "(4) a ScanCompleted event must exist for the published pom" \
        "no matching row in events — the scan ran (last_scan_at is set) but produced no event"
fi

# ---- (5) the SBOM carries the declared dependency at its exact version ----
SBOM_HIT="$(psql_one "SELECT count(*) FROM sbom_components WHERE artifact_id = '${ARTIFACT_ID_DB}' AND purl = '${VULN_PURL}';")"
if [ "${SBOM_HIT:-0}" -ge 1 ]; then
    pass "(5) SBOM carries the declared component ${VULN_PURL}"
else
    ACTUAL_PURLS="$(psql_one "SELECT string_agg(purl, ' ') FROM sbom_components WHERE artifact_id = '${ARTIFACT_ID_DB}';" || true)"
    fail "(5) SBOM must carry ${VULN_PURL}" \
        "components were: ${ACTUAL_PURLS:-<none>} — the .pom's declared dependency was not extracted"
fi

# ---- (6) at least one osv finding is queryable for that component ----
FINDING_HIT="$(psql_one "SELECT count(*) FROM scan_findings WHERE artifact_id = '${ARTIFACT_ID_DB}' AND purl = '${VULN_PURL}' AND source_scanner = 'osv';")"
if [ "${FINDING_HIT:-0}" -ge 1 ]; then
    FINDING_IDS="$(psql_one "SELECT string_agg(DISTINCT vulnerability_id, ',') FROM scan_findings WHERE artifact_id = '${ARTIFACT_ID_DB}' AND purl = '${VULN_PURL}' AND source_scanner = 'osv';" || true)"
    pass "(6) osv finding recorded for ${VULN_PURL} (${FINDING_IDS:-?})"
else
    fail "(6) an osv finding must be recorded for ${VULN_PURL}" \
        "no scan_findings row with source_scanner='osv' — either osv returned nothing for this purl or the finding was not persisted"
fi

summary
