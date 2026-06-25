#!/usr/bin/env bash
# requires: egress
# Virtual (aggregated) Maven repository scenario (ADR 0031). Drives the REAL
# `mvn` client against `maven-virt-e2e`, a `type: virtual` repo aggregating a
# PRIVATE hosted member (`maven-virt-internal`, highest priority) + the Maven
# Central proxy (`maven-central-e2e`). Mirrors the npm/pypi virtual scenarios.
#
#   1. `mvn deploy` a first-party release to the private member, then
#      `mvn dependency:get` it back THROUGH the virtual (merged A-level
#      metadata + first-authoritative file download from the owning member);
#   2. the server-generated A-level `maven-metadata.xml` THROUGH the virtual
#      lists the deployed version;
#   3. a PUT to the virtual is rejected 400 (read-only aggregator), observed as
#      admin so the request clears the authz gate and reaches the repo-type
#      guard;
#   4. an anonymous read THROUGH the virtual does not leak the private member's
#      artifact.
#
# `requires: egress` — `mvn` fetches its own plugins from Central (a fresh
# HOME/.m2 per run). The first-party artifact's group:artifact is OWNED by the
# private member, so name-level pinning excludes the Central proxy member for it
# (the merge itself needs no egress; only mvn's plugin bootstrap does).

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

command -v java >/dev/null 2>&1 || skip "java not found"
command -v mvn  >/dev/null 2>&1 || skip "mvn not found"

MEMBER_KEY="${MAVEN_VIRT_MEMBER_KEY:-maven-virt-internal}"
VIRTUAL_KEY="${MAVEN_VIRT_KEY:-maven-virt-e2e}"
MEMBER_URL="${HORT_URL%/}/maven/${MEMBER_KEY}"
VIRTUAL_URL="${HORT_URL%/}/maven/${VIRTUAL_KEY}"

STAMP="$(date +%s)"
GROUP_ID="de.hort.e2e.virt"
ARTIFACT_ID="maven-virt-native-e2e"
RELEASE_VERSION="1.0.${STAMP}"
GA_PATH="$(printf '%s' "$GROUP_ID" | tr '.' '/')/${ARTIFACT_ID}"
JAR_REL="${GA_PATH}/${RELEASE_VERSION}/${ARTIFACT_ID}-${RELEASE_VERSION}.jar"

log "==> Virtual (aggregated) Maven repository test (ADR 0031)"
log "Member (private): $MEMBER_URL"
log "Virtual:          $VIRTUAL_URL"
log "Artifact:         ${GROUP_ID}:${ARTIFACT_ID}:${RELEASE_VERSION}"

DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || fail "fetch dev-user token" "empty response from Keycloak"
ADMIN_TOKEN="$(fetch_token admin admin)"
[ -n "$ADMIN_TOKEN" ] || fail "fetch admin token" "empty response from Keycloak"
log "[auth] fetched DEV_TOKEN (read+write maven-virt-internal) + ADMIN_TOKEN (global write)"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR" || { fail "cd into WORK_DIR" "$WORK_DIR"; summary; }
mkdir -p .m2 home
export HOME="$WORK_DIR/home"

# settings.xml: a <server> for the deploy-to-member id and one for the
# resolve-through-virtual id, both carrying the token as the Basic password
# (auth-catalog Entry 8). The <mirrors> block re-declares Maven's built-in
# http-blocker as non-blocking so the HTTP-only compose hort is reachable (see
# maven.sh for the full rationale).
cat > .m2/settings.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <servers>
    <server>
      <id>hort-maven-virt-internal</id>
      <username>__token__</username>
      <password>${DEV_TOKEN}</password>
    </server>
    <server>
      <id>hort-maven-virt</id>
      <username>__token__</username>
      <password>${DEV_TOKEN}</password>
    </server>
  </servers>
  <mirrors>
    <mirror>
      <id>maven-default-http-blocker</id>
      <mirrorOf>dummy-never-matches</mirrorOf>
      <name>Override the built-in http blocker for the in-network compose hort (HTTP-only)</name>
      <url>http://0.0.0.0/</url>
      <blocked>false</blocked>
    </mirror>
  </mirrors>
</settings>
EOF
# `aether.connector.http.preemptiveAuth=true` (Maven Resolver 1.9+, bundled
# with Maven 3.9): send the configured Basic credential PREEMPTIVELY rather
# than only after a 401 challenge. The member is PRIVATE behind a PUBLIC
# virtual, so an anonymous GET is NOT met with a 401 (hort returns the
# anti-enumeration 404 / proxy fall-through instead of leaking that a private
# member owns the artifact). Without preemptive auth, mvn would resolve
# anonymously, the private member would be skipped, and the resolve would fall
# through to the Central proxy member. Creds are only sent to servers with a
# matching settings.xml <server> id (the hort repos) — never to Central.
MVN_GLOBAL=(
  -q -B
  -s "$WORK_DIR/.m2/settings.xml"
  -Dmaven.repo.local="$WORK_DIR/.m2/repository"
  -Daether.connector.http.preemptiveAuth=true
)

# ---- Step 0: deploy a first-party release to the PRIVATE MEMBER ----
mkdir -p proj/src/main/java/de/hort/e2e/virt
cat > proj/src/main/java/de/hort/e2e/virt/Greeter.java << 'EOF'
package de.hort.e2e.virt;
public final class Greeter {
    public String hello() { return "Hello from the private member!"; }
}
EOF
cat > proj/pom.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${RELEASE_VERSION}</version>
  <packaging>jar</packaging>
  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <distributionManagement>
    <repository>
      <id>hort-maven-virt-internal</id>
      <url>${MEMBER_URL}</url>
    </repository>
  </distributionManagement>
</project>
EOF

log "==> Deploying ${ARTIFACT_ID}:${RELEASE_VERSION} to the private member..."
if (cd proj && mvn "${MVN_GLOBAL[@]}" deploy) 2>&1 | tail -8; then
  pass "mvn deploy to private member succeeded"
else
  fail "mvn deploy to private member" "mvn deploy exited non-zero"
fi

# ---- Test 1: resolve THROUGH the virtual (merged index + member download) ----
log "==> [1/4] Resolving ${ARTIFACT_ID} THROUGH the virtual (dev, fresh local repo)..."
FRESH="$WORK_DIR/.m2-fresh"
if mvn "${MVN_GLOBAL[@]}" -Dmaven.repo.local="$FRESH" \
      org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get \
      -DremoteRepositories="hort-maven-virt::::${VIRTUAL_URL}" \
      -Dartifact="${GROUP_ID}:${ARTIFACT_ID}:${RELEASE_VERSION}" \
      -Dtransitive=false 2>&1 | tail -8 && [ -f "${FRESH}/${JAR_REL}" ]; then
  pass "mvn dependency:get resolved the artifact through the virtual"
else
  fail "resolve through virtual" "dependency:get via the virtual did not produce ${JAR_REL}"
fi

# ---- Test 2: A-level metadata THROUGH the virtual lists the version ----
log "==> [2/4] A-level maven-metadata.xml through the virtual (authed)..."
META_A="$(curl -sf -u "__token__:${DEV_TOKEN}" "${VIRTUAL_URL}/${GA_PATH}/maven-metadata.xml" 2>/dev/null || true)"
if printf '%s' "$META_A" | grep -q "<version>${RELEASE_VERSION}</version>"; then
  pass "virtual A-level metadata lists $RELEASE_VERSION (merged from the member)"
else
  fail "virtual A-level metadata" "missing <version>${RELEASE_VERSION}</version> in: $META_A"
fi

# ---- Test 3: write to the virtual must be rejected (read-only aggregator) ----
# As ADMIN: global write clears the authz gate, so the request reaches
# `reject_write_to_virtual` and gets the 400. (A non-writer would 403 first.)
log "==> [3/4] PUT to the virtual must be rejected (admin)..."
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X PUT "${VIRTUAL_URL}/${GA_PATH}/9.9.9/${ARTIFACT_ID}-9.9.9.jar" \
    -u "__token__:${ADMIN_TOKEN}" --data-binary 'x')
if [ "$STATUS" = "400" ]; then
  pass "PUT to virtual -> 400 (read-only aggregator)"
else
  fail "PUT to virtual expected 400" "got $STATUS"
fi

# ---- Test 4: anonymous read through the virtual must not leak the member ----
# The virtual is public; the member is private. An anonymous A-level read skips
# the private member (resolve_members visibility), so the private version must
# not surface. (--max-time bounds the proxy-member fall-through to Central.)
log "==> [4/4] Anonymous read through the virtual must not leak the private artifact..."
ANON_META="$(curl -sS --max-time 30 "${VIRTUAL_URL}/${GA_PATH}/maven-metadata.xml" 2>/dev/null || true)"
if printf '%s' "$ANON_META" | grep -q "${RELEASE_VERSION}"; then
  fail "anonymous read leaked the private artifact" "version $RELEASE_VERSION visible anonymously"
else
  pass "anonymous read through the virtual does not leak the private artifact"
fi

summary
