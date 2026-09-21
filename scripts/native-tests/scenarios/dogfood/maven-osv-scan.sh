#!/usr/bin/env bash
# requires: db worker scanner egress
# Maven OSV-scan smoke — proves the payload SBOM extractor feeds a real
# osv-scanner run on EVERY Maven repository class, not just a hosted
# publish. A format that only extracts a payload SBOM for a direct PUT and
# silently skips it on a pull-through would leave every proxied dependency
# unscanned in practice, since proxies are how most real Maven consumption
# happens — so this scenario runs the same extract→scan→finding chain twice,
# once per repository class:
#
#   Leg 1 (hosted, maven-osv-e2e): a direct PUT of a `.pom` declaring a
#   known-affected coordinate.
#   Leg 2 (proxy, maven-osv-proxy-e2e): an authenticated pull-through of a
#   real Maven Central coordinate through a private, quarantined proxy.
#
# Both legs assert the same three facts against a repository with
# `scanBackends: ["osv"]`:
#
#   1. A `ScanCompleted` event / `artifacts.last_scan_at` set.
#   2. An SBOM component naming a dependency the artifact's own `.pom`
#      declares — proof the POM was actually read, not just the subject.
#   3. At least one recorded `osv` finding for the artifact.
#
# Without a Maven SBOM this whole chain scans nothing: `FormatHandler::extract_sbom`
# defaulted to `Ok(None)` for Maven, so `OsvScanner::scan` always logged
# "scan skipped — no SBOM provided" and (1)-(3) never happened, on either
# repository class.
#
# Leg 1 repository: maven-osv-e2e (deploy/compose/example-config/repositories/
# maven-osv-e2e.yaml), policy: maven-osv-e2e-scan.yaml (scanBackends: ["osv"],
# enforcement: record, quarantineDuration: 0s — the publish itself must never
# be gated by the verdict this scenario is trying to observe).
#
# A standalone `.pom` PUT is enough for leg 1: the Maven handler's
# group-membership model tolerates a pom-only artifact (a parent POM / BOM
# has no `jar` member), and the SBOM extractor's `.pom` branch does not need
# a sibling jar. A raw PUT keeps the scenario free of `mvn` and its tool
# dependencies; the scan/verdict half mirrors registry-supply-chain.sh part
# (h).
#
# Leg 2 repository: maven-osv-proxy-e2e (deploy/compose/example-config/
# repositories/maven-osv-proxy-e2e.yaml), policy: maven-osv-proxy-e2e-scan.yaml
# (scanBackends: ["osv"], enforcement: record, quarantineDuration: 20s,
# provenanceMode: off). The subject is spring-web 5.2.0.RELEASE, pulled
# through as dev-user; a 503 on the first fetch means the proxy quarantined
# the ingest, which is expected, not a failure — the point is that the
# artifact exists afterwards with a payload SBOM. The reader
# (`parse_pom_dependencies`, crates/hort-formats/src/maven/pom.rs) only emits
# a dependency it can compute a version for from the POM's own tree; a
# dependency whose version comes from a parent POM or an imported BOM is a
# counted skip (`PomSkipReason::VersionFromParentOrBom`), not an emission.
# spring-web's own `.pom` declares its dependencies with literal, non-managed
# `<version>` tags, so the reader emits them without needing this scenario to
# follow the parent chain.

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

# ===========================================================================
# Leg 2: proxy pull-through (maven-osv-proxy-e2e)
# ===========================================================================
PROXY_REPO_KEY="${MAVEN_OSV_PROXY_REPO_KEY:-maven-osv-proxy-e2e}"
PROXY_URL="${HORT_URL%/}/maven/${PROXY_REPO_KEY}"

# spring-web 5.2.0.RELEASE, not log4j-core: its own `.pom` declares literal,
# compile-scoped versions for its two dependencies (spring-beans, spring-core)
# rather than deferring them to a parent POM, so `parse_pom_dependencies` can
# emit them from this POM alone — see the file header for why that matters.
PROXY_GROUP_PATH="org/springframework"
PROXY_ARTIFACT="spring-web"
PROXY_VERSION="5.2.0.RELEASE"
PROXY_POM_PATH="${PROXY_GROUP_PATH}/${PROXY_ARTIFACT}/${PROXY_VERSION}/${PROXY_ARTIFACT}-${PROXY_VERSION}.pom"

PROXY_VULN_GROUP_ID="org.springframework"
PROXY_VULN_ARTIFACT_ID="spring-beans"
PROXY_VULN_VERSION="5.2.0.RELEASE"
PROXY_VULN_PURL="pkg:maven/${PROXY_VULN_GROUP_ID}/${PROXY_VULN_ARTIFACT_ID}@${PROXY_VULN_VERSION}"

log ""
log "==> Proxy leg: pull-through of ${PROXY_POM_PATH} via ${PROXY_URL}"

DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"

PROXY_REPO_ID="$(psql_one "SELECT id FROM repositories WHERE key = '${PROXY_REPO_KEY}' LIMIT 1;")"
if [ -z "$PROXY_REPO_ID" ]; then
    fail "(7) locate ${PROXY_REPO_KEY} repository" \
        "no repositories row for key='${PROXY_REPO_KEY}' — has gitops apply run against this DB?"
    summary
fi
log "  repository id=${PROXY_REPO_ID}"

# ---- (7) authenticated pull-through of the .pom (200 and 503 both mean
# "ingested" — a private, quarantined proxy's first fetch legitimately
# 503s while the artifact sits in its observation window; an anonymous 404
# on a private repo would NOT mean absence, but this fetch is authenticated) ----
PROXY_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 60 \
    -H "Authorization: Bearer ${DEV_TOKEN}" \
    "${PROXY_URL}/${PROXY_POM_PATH}" 2>/dev/null || echo "000")"
log "  GET ${PROXY_POM_PATH} -> HTTP ${PROXY_CODE}"
case "$PROXY_CODE" in
    200|503) pass "(7) authenticated pull-through of the .pom triggered ingest (HTTP ${PROXY_CODE})" ;;
    *)
        fail "(7) authenticated pull-through of the .pom" \
            "expected 200 (served) or 503 (quarantined, ingest still happened) — got HTTP ${PROXY_CODE}; is Maven Central reachable?"
        summary
        ;;
esac

# ---- (8) locate the ingested artifact by (repository_id, path) ----
PROXY_ARTIFACT_ID=""
if bounded_poll "proxy pom ingested" 30 \
        "[ -n \"\$(psql_one \"SELECT id FROM artifacts WHERE repository_id = '${PROXY_REPO_ID}' AND path = '${PROXY_POM_PATH}';\")\" ]" \
        2; then
    PROXY_ARTIFACT_ID="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${PROXY_REPO_ID}' AND path = '${PROXY_POM_PATH}';")"
    pass "(8) proxy pom ingested as artifact id=${PROXY_ARTIFACT_ID}"
else
    fail "(8) proxy pom must be ingested within 30s of the pull-through GET" \
        "no artifacts row for repository_id='${PROXY_REPO_ID}' path='${PROXY_POM_PATH}'"
    summary
fi

# ---- (9) wait for the scan to complete ----
if bounded_poll \
        "scan completed for ${PROXY_ARTIFACT_ID}" \
        180 \
        "[ -n \"\$(psql_one \"SELECT last_scan_at FROM artifacts WHERE id = '${PROXY_ARTIFACT_ID}' AND last_scan_at IS NOT NULL;\")\" ]" \
        5; then
    pass "(9) scan completed for the proxied pom (artifacts.last_scan_at set)"
else
    fail "(9) scan did not complete within 180s" \
        "artifacts.last_scan_at still NULL for id='${PROXY_ARTIFACT_ID}' — is a worker with the osv backend running against this instance?"
    summary
fi

# record mode: a finding must not reject the artifact.
PROXY_STATUS_DB="$(psql_one "SELECT COALESCE(quarantine_status::text, 'null') FROM artifacts WHERE id = '${PROXY_ARTIFACT_ID}';")"
if [ "$PROXY_STATUS_DB" = "rejected" ]; then
    fail "(9) proxied artifact must not be rejected under enforcement: record" \
        "quarantine_status='rejected' — the policy is enforcing, not recording"
else
    pass "(9) quarantine_status='${PROXY_STATUS_DB}' (not rejected — verdict recorded, not enforced)"
fi

# ---- (10) the SBOM carries the declared dependency at its exact version ----
PROXY_SBOM_TOTAL="$(psql_one "SELECT count(*) FROM sbom_components WHERE artifact_id = '${PROXY_ARTIFACT_ID}';")"
log "  proxied pom SBOM: ${PROXY_SBOM_TOTAL:-0} total component(s)"
PROXY_SBOM_HIT="$(psql_one "SELECT count(*) FROM sbom_components WHERE artifact_id = '${PROXY_ARTIFACT_ID}' AND purl = '${PROXY_VULN_PURL}';")"
if [ "${PROXY_SBOM_HIT:-0}" -ge 1 ]; then
    pass "(10) SBOM carries the declared component ${PROXY_VULN_PURL}"
else
    ACTUAL_PROXY_PURLS="$(psql_one "SELECT string_agg(purl, ' ') FROM sbom_components WHERE artifact_id = '${PROXY_ARTIFACT_ID}';" || true)"
    fail "(10) SBOM must carry ${PROXY_VULN_PURL}" \
        "components were: ${ACTUAL_PROXY_PURLS:-<none>} — the proxied pom's declared dependency was not extracted"
fi

# ---- (11) at least one osv finding is queryable for that component ----
PROXY_FINDING_HIT="$(psql_one "SELECT count(*) FROM scan_findings WHERE artifact_id = '${PROXY_ARTIFACT_ID}' AND purl = '${PROXY_VULN_PURL}' AND source_scanner = 'osv';")"
if [ "${PROXY_FINDING_HIT:-0}" -ge 1 ]; then
    PROXY_FINDING_IDS="$(psql_one "SELECT string_agg(DISTINCT vulnerability_id, ',') FROM scan_findings WHERE artifact_id = '${PROXY_ARTIFACT_ID}' AND purl = '${PROXY_VULN_PURL}' AND source_scanner = 'osv';" || true)"
    pass "(11) osv finding recorded for ${PROXY_VULN_PURL} (${PROXY_FINDING_IDS:-?})"
else
    fail "(11) an osv finding must be recorded for ${PROXY_VULN_PURL}" \
        "no scan_findings row with source_scanner='osv' and purl='${PROXY_VULN_PURL}' for artifact_id='${PROXY_ARTIFACT_ID}'"
fi

summary
