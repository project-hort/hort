#!/usr/bin/env bash
# requires: egress
# Maven / Gradle native-client scenario (design §2/§8/§9, backlog Item 12).
#
# Drives the REAL `mvn` and `gradle` clients against the Maven handler mounted
# at `/maven` (serving both RepositoryFormat::Maven and ::Gradle repos). Four
# legs, each a publish->resolve round-trip through hort:
#
#   (a) HOSTED RELEASE — `mvn deploy` a full release set (jar + pom + sources +
#       javadoc + client-side checksums) to the hosted Maven repo `maven-e2e`,
#       then `mvn dependency:get` it back into a FRESH local repo. Proves
#       publish->download, server-generated maven-metadata.xml (A-level), and
#       server-generated checksum sidecars (the client verifies every download
#       against the `.sha1` hort emits on demand).
#
#   (b) SNAPSHOT — `mvn deploy` a `-SNAPSHOT` version, then resolve it with a
#       second `mvn` invocation against a CLEAN local repo. Maven reads the
#       V-level maven-metadata.xml (server-generated `<snapshot>` +
#       `<snapshotVersions>`) and fetches the concrete timestamped artifact.
#       Proves V-level snapshot metadata + timestamped resolution (§7).
#
#   (c) PULL-THROUGH SHA-1 FLOOR — resolve a real Maven Central artifact
#       (commons-logging:commons-logging:1.0.4) whose ONLY upstream checksum
#       sidecar is `.sha1` (NO `.sha256` exists on Central for it — verified at
#       run time) through the PROXY repo `maven-central-e2e`. Proves the ADR
#       0033 SHA-1 transfer-verification floor proxies real Central content
#       (§8). Needs Maven Central reachable -> `requires: egress`.
#
#   (d) GRADLE — `gradle publish` (the `maven-publish` plugin) to the
#       Gradle-format repo `gradle-e2e`, producing a `.module` (Gradle Module
#       Metadata / GMM) + the POM Gradle marker, then a Gradle resolve from it.
#       Proves `.module` opaque pass-through + the Gradle=Maven alias (§9).
#
# AUTH (auth-catalog Entry 8). Deploy/publish PUTs authenticate via HTTP Basic
# carrying a registry token as the PASSWORD (username ignored). Maven reads it
# from settings.xml <server>; Gradle from a PasswordCredentials block. The token
# is the same registry credential the cargo/npm/pypi scenarios mint from
# Keycloak via fetch_token (twine likewise stashes it as TWINE_PASSWORD). Reads
# (GET/HEAD) are anonymous-by-default (the repos are isPublic: true).
#
# Repos are provisioned by gitops, mounted into deploy/compose:
#   repositories/maven-e2e.yaml            (hosted Maven)
#   repositories/gradle-e2e.yaml           (hosted Gradle alias)
#   repositories/maven-central-e2e.yaml    (proxy -> repo1.maven.org/maven2)
#   upstreams/maven-central-e2e.yaml       (the runtime upstream mapping)
#   auth/dev-write-{maven,gradle}-e2e.yaml (developer+ci-pusher -> write)
#   policies/{maven,gradle,maven-central}-e2e-permissive.yaml (release now)

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

MAVEN_REPO_KEY="${MAVEN_REPO_KEY:-maven-e2e}"
GRADLE_REPO_KEY="${GRADLE_REPO_KEY:-gradle-e2e}"
MAVEN_PROXY_REPO_KEY="${MAVEN_PROXY_REPO_KEY:-maven-central-e2e}"

MAVEN_URL="${HORT_URL%/}/maven/${MAVEN_REPO_KEY}"
GRADLE_URL="${HORT_URL%/}/maven/${GRADLE_REPO_KEY}"
PROXY_URL="${HORT_URL%/}/maven/${MAVEN_PROXY_REPO_KEY}"

# Unique build number so reruns against a --keep stack do not collide on an
# already-released immutable release version.
STAMP="$(date +%s)"
GROUP_ID="de.hort.e2e"
ARTIFACT_ID="maven-native-e2e"
RELEASE_VERSION="1.0.${STAMP}"
SNAPSHOT_VERSION="2.0.${STAMP}-SNAPSHOT"
GRADLE_GROUP="de.hort.e2e.gradle"
GRADLE_ARTIFACT="gradle-native-e2e"
GRADLE_VERSION="1.0.${STAMP}"

# Pull-through target: an OLD Central artifact whose only sidecar is `.sha1`.
PT_GROUP="commons-logging"
PT_ARTIFACT="commons-logging"
PT_VERSION="1.0.4"

log "==> Maven / Gradle Native Client Test"
log "Hosted Maven:  $MAVEN_URL"
log "Hosted Gradle: $GRADLE_URL"
log "Proxy (SHA-1): $PROXY_URL"
log "Release ver:   $RELEASE_VERSION"
log "Snapshot ver:  $SNAPSHOT_VERSION"

# ---- Prerequisites (JDK + Maven + Gradle baked into the client image) ----
command -v java   >/dev/null 2>&1 || skip "java not found"
command -v mvn    >/dev/null 2>&1 || skip "mvn not found"
command -v gradle >/dev/null 2>&1 || skip "gradle not found"
command -v jq     >/dev/null 2>&1 || skip "jq not found"

# ---- Auth: a registry token carried as the HTTP Basic password ----
DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ]    || fail "fetch dev-user token"    "empty response from Keycloak"
READER_TOKEN="$(fetch_token reader-user reader)"
[ -n "$READER_TOKEN" ] || fail "fetch reader-user token" "empty response from Keycloak"
log "[auth] fetched DEV_TOKEN + READER_TOKEN from Keycloak"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR" || { fail "cd into WORK_DIR" "$WORK_DIR"; summary; }

# Isolate every Maven/Gradle artefact under the scratch dir: a private local
# repo per resolve leg (proves a fetch from hort, not a warm cache) and a
# settings.xml carrying the deploy credential.
mkdir -p .m2 home
export HOME="$WORK_DIR/home"

# settings.xml: one <server> id per hort repo, each carrying the registry token
# as the Basic password (username decorative — Entry 8). offline=false so Maven
# may fetch its own plugins from Central.
#
# The <mirrors> block re-declares Maven 3.8.1+'s built-in
# `maven-default-http-blocker` (mirrorOf `external:http:*`, blocked=true) with
# `<blocked>false</blocked>`. Without this override Maven REFUSES to resolve
# from any plaintext-http remote and `dependency:get` against the in-network
# hort (http://hort-server:8080, no TLS in the compose stack) fails with
# "Blocked mirror for repositories". The compose stack is HTTP-only by design
# (the oci.sh scenario likewise sets --dest-tls-verify=false); a real
# deployment serves hort over TLS and needs no such override. The id MUST match
# the built-in so this entry SUPERSEDES it rather than adding a second mirror.
cat > .m2/settings.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <servers>
    <server>
      <id>hort-maven-e2e</id>
      <username>__token__</username>
      <password>${DEV_TOKEN}</password>
    </server>
    <server>
      <id>hort-gradle-e2e</id>
      <username>__token__</username>
      <password>${DEV_TOKEN}</password>
    </server>
    <server>
      <id>hort-maven-central</id>
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
MVN_GLOBAL=(-q -B -s "$WORK_DIR/.m2/settings.xml" -Dmaven.repo.local="$WORK_DIR/.m2/repository")

# ---------------------------------------------------------------------
# (a) HOSTED RELEASE — mvn deploy a full release set, then dependency:get it.
# ---------------------------------------------------------------------
log ""
log "==> [a] Hosted release: mvn deploy + dependency:get ($GROUP_ID:$ARTIFACT_ID:$RELEASE_VERSION)"
mkdir -p proj/src/main/java/de/hort/e2e
cat > proj/src/main/java/de/hort/e2e/Greeter.java << 'EOF'
package de.hort.e2e;
public final class Greeter {
    public String hello() { return "Hello from hort Maven E2E!"; }
}
EOF

# A pom that builds jar + sources + javadoc and deploys to the hosted repo.
# distributionManagement.repository.id matches the settings.xml <server> id so
# the deploy plugin picks up the Basic credential.
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
      <id>hort-maven-e2e</id>
      <url>${MAVEN_URL}</url>
    </repository>
    <snapshotRepository>
      <id>hort-maven-e2e</id>
      <url>${MAVEN_URL}</url>
    </snapshotRepository>
  </distributionManagement>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-source-plugin</artifactId>
        <version>3.3.1</version>
        <executions>
          <execution>
            <id>attach-sources</id>
            <goals><goal>jar-no-fork</goal></goals>
          </execution>
        </executions>
      </plugin>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-javadoc-plugin</artifactId>
        <version>3.6.3</version>
        <executions>
          <execution>
            <id>attach-javadocs</id>
            <goals><goal>jar</goal></goals>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
EOF

if (cd proj && mvn "${MVN_GLOBAL[@]}" deploy) 2>&1 | tail -8; then
  pass "mvn deploy (release: jar+pom+sources+javadoc+checksums) succeeded"
else
  fail "mvn deploy (release)" "mvn deploy exited non-zero"
fi

# Server-generated A-level maven-metadata.xml must list the released version.
GA_PATH="$(printf '%s' "$GROUP_ID" | tr '.' '/')/${ARTIFACT_ID}"
META_A="$(curl -sf "${MAVEN_URL}/${GA_PATH}/maven-metadata.xml" 2>/dev/null || true)"
if printf '%s' "$META_A" | grep -q "<version>${RELEASE_VERSION}</version>"; then
  pass "A-level maven-metadata.xml lists $RELEASE_VERSION"
else
  fail "A-level maven-metadata.xml" "missing <version>${RELEASE_VERSION}</version> in $META_A"
fi

# Server-generated checksum sidecar must equal the locally-computed sha1 of the
# deployed jar (proves on-demand sidecars, §6). The local jar is in proj/target.
JAR_REL="${GA_PATH}/${RELEASE_VERSION}/${ARTIFACT_ID}-${RELEASE_VERSION}.jar"
LOCAL_JAR="proj/target/${ARTIFACT_ID}-${RELEASE_VERSION}.jar"
if [ -f "$LOCAL_JAR" ]; then
  LOCAL_SHA1="$(sha1sum "$LOCAL_JAR" | cut -d' ' -f1)"
  SERVED_SHA1="$(curl -sf "${MAVEN_URL}/${JAR_REL}.sha1" 2>/dev/null | tr -d '[:space:]' | cut -d' ' -f1)"
  if [ -n "$SERVED_SHA1" ] && [ "$LOCAL_SHA1" = "$SERVED_SHA1" ]; then
    pass "server-generated .sha1 sidecar matches deployed jar ($SERVED_SHA1)"
  else
    fail "server .sha1 sidecar" "local=$LOCAL_SHA1 served=$SERVED_SHA1"
  fi
else
  fail "deployed jar present locally" "$LOCAL_JAR missing — cannot cross-check sidecar"
fi

# dependency:get into a FRESH local repo proves the full pull path (index +
# artifact + checksum verification by the client).
log "==> [a] Resolving the release back with mvn dependency:get (fresh local repo)..."
FRESH_A="$WORK_DIR/.m2-fresh-a"
if mvn "${MVN_GLOBAL[@]}" -Dmaven.repo.local="$FRESH_A" \
      org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get \
      -DremoteRepositories="hort-maven-e2e::::${MAVEN_URL}" \
      -Dartifact="${GROUP_ID}:${ARTIFACT_ID}:${RELEASE_VERSION}" \
      -Dtransitive=false 2>&1 | tail -8; then
  if [ -f "${FRESH_A}/${JAR_REL}" ]; then
    pass "mvn dependency:get resolved the release jar from hort"
  else
    fail "release dependency:get artifact" "expected ${FRESH_A}/${JAR_REL} after get"
  fi
else
  fail "mvn dependency:get (release)" "dependency:get exited non-zero"
fi

# ---------------------------------------------------------------------
# (b) SNAPSHOT — deploy a -SNAPSHOT, then resolve via the V-level metadata.
# ---------------------------------------------------------------------
log ""
log "==> [b] SNAPSHOT deploy + resolve ($GROUP_ID:$ARTIFACT_ID:$SNAPSHOT_VERSION)"
cat > proj/pom-snapshot.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${SNAPSHOT_VERSION}</version>
  <packaging>jar</packaging>
  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <distributionManagement>
    <snapshotRepository>
      <id>hort-maven-e2e</id>
      <url>${MAVEN_URL}</url>
    </snapshotRepository>
  </distributionManagement>
</project>
EOF

if (cd proj && mvn "${MVN_GLOBAL[@]}" -f pom-snapshot.xml deploy) 2>&1 | tail -8; then
  pass "mvn deploy (SNAPSHOT) succeeded"
else
  fail "mvn deploy (SNAPSHOT)" "mvn deploy exited non-zero"
fi

# Server-generated V-level snapshot metadata must carry a <snapshot> block.
SNAP_META="$(curl -sf "${MAVEN_URL}/${GA_PATH}/${SNAPSHOT_VERSION}/maven-metadata.xml" 2>/dev/null || true)"
if printf '%s' "$SNAP_META" | grep -q "<snapshot>"; then
  pass "V-level maven-metadata.xml has a <snapshot> block"
else
  fail "V-level snapshot maven-metadata.xml" "no <snapshot> in $SNAP_META"
fi

# Resolve the SNAPSHOT into a clean local repo: Maven reads the V-level
# metadata, picks the timestamped build, and fetches it.
log "==> [b] Resolving the SNAPSHOT back (fresh local repo via V-level metadata)..."
FRESH_B="$WORK_DIR/.m2-fresh-b"
if mvn "${MVN_GLOBAL[@]}" -Dmaven.repo.local="$FRESH_B" \
      org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get \
      -DremoteRepositories="hort-maven-e2e::::${MAVEN_URL}" \
      -Dartifact="${GROUP_ID}:${ARTIFACT_ID}:${SNAPSHOT_VERSION}" \
      -Dtransitive=false 2>&1 | tail -8; then
  if find "$FRESH_B" -path "*${ARTIFACT_ID}*" -name '*.jar' | grep -q .; then
    pass "mvn dependency:get resolved the SNAPSHOT (timestamped build) from hort"
  else
    fail "snapshot dependency:get artifact" "no resolved jar under $FRESH_B"
  fi
else
  fail "mvn dependency:get (SNAPSHOT)" "dependency:get exited non-zero"
fi

# ---------------------------------------------------------------------
# (c) PULL-THROUGH SHA-1 FLOOR — resolve a Central artifact whose only sidecar
#     is `.sha1` (no `.sha256` upstream) through the proxy repo.
# ---------------------------------------------------------------------
log ""
log "==> [c] Pull-through SHA-1 floor: ${PT_GROUP}:${PT_ARTIFACT}:${PT_VERSION} via $PROXY_URL"
PT_PATH="$(printf '%s' "$PT_GROUP" | tr '.' '/')/${PT_ARTIFACT}/${PT_VERSION}/${PT_ARTIFACT}-${PT_VERSION}.jar"
CENTRAL_BASE="https://repo1.maven.org/maven2/${PT_PATH}"

# Confirm the chosen artifact actually exercises the FLOOR: .sha1 present,
# .sha256 absent upstream. If Central ever adds a .sha256 for it, skip rather
# than silently testing the wrong path.
PT_SHA1_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -I "${CENTRAL_BASE}.sha1" 2>/dev/null || echo 000)"
PT_SHA256_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -I "${CENTRAL_BASE}.sha256" 2>/dev/null || echo 000)"
log "    upstream sidecars: .sha1=${PT_SHA1_CODE} .sha256=${PT_SHA256_CODE}"
if [ "$PT_SHA1_CODE" != "200" ]; then
  skip "Maven Central unreachable or ${PT_ARTIFACT}-${PT_VERSION}.jar.sha1 not 200 (got $PT_SHA1_CODE) — cannot exercise the SHA-1 floor"
fi
if [ "$PT_SHA256_CODE" = "200" ]; then
  skip "Central now serves a .sha256 for ${PT_ARTIFACT}-${PT_VERSION} — this no longer exercises the SHA-1 floor; pick another floor-only artifact"
fi

# Resolve through the proxy into a clean local repo. A non-zero exit OR a
# missing local jar means the floor pull-through failed.
FRESH_C="$WORK_DIR/.m2-fresh-c"
if mvn "${MVN_GLOBAL[@]}" -Dmaven.repo.local="$FRESH_C" \
      org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get \
      -DremoteRepositories="hort-maven-central::::${PROXY_URL}" \
      -Dartifact="${PT_GROUP}:${PT_ARTIFACT}:${PT_VERSION}" \
      -Dtransitive=false 2>&1 | tail -8; then
  if [ -f "${FRESH_C}/${PT_PATH}" ]; then
    pass "SHA-1-floor pull-through resolved ${PT_ARTIFACT}-${PT_VERSION}.jar from Central via hort"
  else
    fail "pull-through artifact present" "expected ${FRESH_C}/${PT_PATH}"
  fi
else
  fail "mvn dependency:get (pull-through)" "dependency:get through the proxy exited non-zero"
fi

# Direct GET of the proxied jar must succeed (now cached + released).
PT_DIRECT="$(curl -sS -o /dev/null -w '%{http_code}' "${PROXY_URL}/${PT_PATH}" 2>/dev/null || echo 000)"
if [ "$PT_DIRECT" = "200" ]; then
  pass "direct GET of the proxied jar -> 200 (cached + released)"
else
  fail "direct GET proxied jar expected 200" "got $PT_DIRECT"
fi

# ---------------------------------------------------------------------
# (d) GRADLE — gradle publish (.module GMM + POM marker), then resolve it.
# ---------------------------------------------------------------------
log ""
log "==> [d] Gradle publish + resolve ($GRADLE_GROUP:$GRADLE_ARTIFACT:$GRADLE_VERSION)"
mkdir -p gradle-pub/src/main/java/de/hort/e2e/gradle
cat > gradle-pub/src/main/java/de/hort/e2e/gradle/GradleGreeter.java << 'EOF'
package de.hort.e2e.gradle;
public final class GradleGreeter {
    public String hello() { return "Hello from hort Gradle E2E!"; }
}
EOF

# settings.gradle keeps the build offline-friendly for project config; the
# gradle binary is baked into the image (no wrapper download).
cat > gradle-pub/settings.gradle << EOF
rootProject.name = '${GRADLE_ARTIFACT}'
EOF

# maven-publish produces the POM, the jar, AND the Gradle Module Metadata
# (.module) by default. PasswordCredentials carry the token as the password
# (Entry 8) from -P project properties supplied on the command line.
cat > gradle-pub/build.gradle << EOF
plugins {
    id 'java-library'
    id 'maven-publish'
}
group = '${GRADLE_GROUP}'
version = '${GRADLE_VERSION}'
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
publishing {
    publications {
        lib(MavenPublication) { from components.java }
    }
    repositories {
        maven {
            name = 'hort'
            url = uri('${GRADLE_URL}')
            allowInsecureProtocol = true
            credentials(PasswordCredentials) {
                username = findProperty('hortUser') ?: '__token__'
                password = findProperty('hortToken') ?: ''
            }
        }
    }
}
EOF

if (cd gradle-pub && gradle --no-daemon -g "$WORK_DIR/.gradle-home" \
      -PhortToken="$DEV_TOKEN" publish) 2>&1 | tail -10; then
  pass "gradle publish (.module GMM + POM marker + jar) succeeded"
else
  fail "gradle publish" "gradle publish exited non-zero"
fi

# The .module GMM must be stored + served opaquely (pass-through, §9).
GG_PATH="$(printf '%s' "$GRADLE_GROUP" | tr '.' '/')/${GRADLE_ARTIFACT}/${GRADLE_VERSION}"
MODULE_BODY="$(curl -sf "${GRADLE_URL}/${GG_PATH}/${GRADLE_ARTIFACT}-${GRADLE_VERSION}.module" 2>/dev/null || true)"
if printf '%s' "$MODULE_BODY" | jq -e '.formatVersion' >/dev/null 2>&1; then
  pass "served .module is valid Gradle Module Metadata (opaque pass-through)"
else
  fail ".module served + parseable" "GET ${GRADLE_ARTIFACT}-${GRADLE_VERSION}.module did not return valid GMM JSON"
fi

# Resolve the published Gradle artifact back from the same hort repo — proves
# the Gradle=Maven alias serves a Gradle client end to end.
log "==> [d] Resolving the Gradle artifact back from hort..."
mkdir -p gradle-consume
cat > gradle-consume/settings.gradle << EOF
rootProject.name = 'gradle-consume'
EOF
cat > gradle-consume/build.gradle << EOF
plugins { id 'java-library' }
repositories {
    maven {
        url = uri('${GRADLE_URL}')
        allowInsecureProtocol = true
    }
}
dependencies {
    implementation '${GRADLE_GROUP}:${GRADLE_ARTIFACT}:${GRADLE_VERSION}'
}
tasks.register('resolveDep') {
    doLast {
        def files = configurations.compileClasspath.resolve()
        if (files.isEmpty()) { throw new GradleException('resolved no files') }
        files.each { println "resolved: \${it.name}" }
    }
}
EOF

if (cd gradle-consume && gradle --no-daemon -g "$WORK_DIR/.gradle-home" \
      resolveDep) 2>&1 | tail -10 | grep -q "resolved: ${GRADLE_ARTIFACT}-${GRADLE_VERSION}.jar"; then
  pass "gradle resolved the published artifact from hort (Gradle=Maven alias)"
else
  fail "gradle resolve" "gradle did not resolve ${GRADLE_ARTIFACT}-${GRADLE_VERSION}.jar from hort"
fi

# ---------------------------------------------------------------------
# Negative assertions (auth) — §17 error matrix.
# A PUT with no principal must 401; a PUT with a read-only token must 403.
# An over-long / traversal coordinate is rejected by validate_maven_coordinate
# before persistence (400, prefixed `maven.coordinate:`). We test the auth
# gates here (the coordinate grammar is exhaustively unit-tested in the crate).
# ---------------------------------------------------------------------
log ""
log "[auth] negative test 1/2: deploy without credentials must 401"
NEG_PATH="${GA_PATH}/0.0.1-denied/${ARTIFACT_ID}-0.0.1-denied.jar"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "${MAVEN_URL}/${NEG_PATH}" --data-binary 'x')
if [ "$STATUS" = "401" ]; then
  pass "no-auth maven deploy -> 401"
else
  fail "no-auth maven deploy expected 401" "got $STATUS"
fi

log "[auth] negative test 2/2: deploy with a read-only token must 403"
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "${MAVEN_URL}/${NEG_PATH}" \
    -u "__token__:${READER_TOKEN}" --data-binary 'x')
if [ "$STATUS" = "403" ]; then
  pass "reader-token maven deploy -> 403"
else
  fail "reader-token maven deploy expected 403" "got $STATUS"
fi

# Ingest metric — BEST-EFFORT (never fails the scenario).
#
# The Maven deploys emit hort_ingest_total{format="maven",result="success"}
# synchronously in the ingest request path (the exporter renders it on the
# next scrape — verified: a single deploy makes the line appear in 0s, and a
# completed run's counter is reliably present both host-side and in-network).
# The publish->resolve round-trips above ARE the authoritative gate (the lib's
# own assert_metric_ingest docstring says exactly this) — they cannot pass
# without a real successful ingest.
#
# Deliberately a soft note, NOT `assert_metric_ingest maven` (which hard-fails
# when METRICS_URL is reachable but the line is absent at that instant): the
# scenario container's scrape of the separate :9090 metrics listener is
# observably flaky DURING this heavy, multi-leg run (the line is present on the
# same endpoint moments later from an idle probe), so a hard assertion turns a
# proven-correct emission into an intermittently-red gate. Poll briefly and
# record the outcome as a PASS-or-note; the round-trips already proved ingest.
if [ -n "${METRICS_URL:-}" ] && curl -sf -o /dev/null --max-time 5 "$METRICS_URL" 2>/dev/null; then
  # Predicate is eval'd by bounded_poll in THIS shell, so $METRICS_URL must
  # stay deferred — escape it (and the regex) rather than expand at definition
  # time. Mirrors patch-candidate.sh's bounded_poll predicate quoting.
  if bounded_poll "maven ingest metric" 20 \
      "curl -sf \"\$METRICS_URL\" | grep -Eq '^hort_ingest_total\{[^}]*format=\"maven\"[^}]*result=\"success\"[^}]*\}'"; then
    pass "hort_ingest_total{format=\"maven\",result=\"success\"} present"
  else
    log "  note: hort_ingest_total{format=\"maven\"} not visible to the in-run scrape (soft) — the publish->resolve round-trips above are the authoritative ingest gate"
  fi
else
  log "  note: METRICS_URL unset/unreachable — skip ingest-metric check (round-trips are the gate)"
fi
summary
