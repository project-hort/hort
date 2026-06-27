//! Inline handler tests for the hosted Maven path (Item 6).
//!
//! Drives [`maven_routes`] through `tower::ServiceExt::oneshot` against an
//! adapter-free [`build_mock_ctx`] context. Covers: publish→download
//! roundtrip (any PUT order; group membership; `ArtifactIngested`),
//! server-generated A-level `maven-metadata.xml` (ordering, latest/release,
//! quarantined version excluded), the quarantine / rejected / sidecar /
//! metadata-PUT response shapes (design §17), and the anonymous-on-private
//! anti-enumeration 404.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;

use hort_app::rbac::RbacEvaluator;
use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
use hort_app::use_cases::test_support::{sample_artifact, sample_repository};
use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::entities::repository::{Repository, RepositoryFormat, RepositoryType};
use hort_domain::events::DomainEvent;
use hort_domain::ports::artifact_group_repository::ArtifactGroupRepository;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_http_core::test_support::{build_mock_ctx, with_repository_access, MockPorts};

use super::*;

fn handle() -> metrics_exporter_prometheus::PrometheusHandle {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .build_recorder()
        .handle()
}

fn router(ctx: Arc<AppContext>) -> Router {
    Router::new().nest("/maven", maven_routes()).with_state(ctx)
}

fn insert_repo(mocks: &MockPorts, key: &str, format: RepositoryFormat) -> Repository {
    let mut repo = sample_repository();
    repo.key = key.to_string();
    repo.format = format;
    repo.repo_type = RepositoryType::Hosted;
    mocks.repositories.insert(repo.clone());
    repo
}

/// Seed an already-stored Maven artifact row + its CAS bytes directly (for
/// GET-only tests that don't exercise the PUT path).
fn insert_file(
    mocks: &MockPorts,
    repo_id: Uuid,
    name: &str,
    version: &str,
    path: &str,
    content: &[u8],
    status: QuarantineStatus,
) -> Artifact {
    use sha2::{Digest, Sha256};
    let sha256 = format!("{:x}", Sha256::digest(content)).parse().unwrap();
    let mut artifact = sample_artifact(status);
    artifact.repository_id = repo_id;
    artifact.name = name.to_string();
    artifact.name_as_published = name.to_string();
    artifact.version = Some(version.to_string());
    artifact.path = path.to_string();
    artifact.sha256_checksum = sha256;
    artifact.size_bytes = content.len() as i64;
    mocks.artifacts.insert(artifact.clone());
    mocks
        .storage
        .insert_content(artifact.sha256_checksum.clone(), content.to_vec());
    artifact
}

async fn put(router: &Router, path: &str, body: &[u8]) -> StatusCode {
    let res = router
        .clone()
        .oneshot(Request::put(path).body(Body::from(body.to_vec())).unwrap())
        .await
        .unwrap();
    res.status()
}

async fn get(router: &Router, path: &str) -> (StatusCode, Vec<u8>) {
    let res = router
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

// ---------------------------------------------------------------------------
// publish → download roundtrip + group membership + events
// ---------------------------------------------------------------------------

/// PUT a `.pom` BEFORE its `.jar` (PUT order is not spec-guaranteed —
/// design §5). Both are retrievable by exact path, both emit
/// `ArtifactIngested`, and a single jar+pom group forms with the jar as
/// the primary member.
#[tokio::test]
async fn publish_download_roundtrip_pom_before_jar_forms_group() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);

    let pom_path = "/maven/mvn/com/example/foo/1.0/foo-1.0.pom";
    let jar_path = "/maven/mvn/com/example/foo/1.0/foo-1.0.jar";

    // .pom first, .jar second.
    assert_eq!(
        put(&router, pom_path, b"<project/>").await,
        StatusCode::CREATED
    );
    assert_eq!(
        put(&router, jar_path, b"JARBYTES").await,
        StatusCode::CREATED
    );

    // Both retrievable by exact path with the right bytes.
    let (st, body) = get(&router, jar_path).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"JARBYTES");
    let (st, body) = get(&router, pom_path).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"<project/>");

    // Two ArtifactIngested events — ingest rides on the lifecycle port's
    // `commit_transition` (the artifact-stream batch), not the event
    // publisher, so assert via `committed_transitions()` (same as pypi).
    let ingested = mocks
        .lifecycle
        .committed_transitions()
        .iter()
        .flat_map(|(_a, batch, _m)| batch.events.iter())
        .filter(|e| matches!(e.event, DomainEvent::ArtifactIngested(_)))
        .count();
    assert_eq!(ingested, 2, "one ArtifactIngested per file");

    // A jar+pom group formed (the post-commit classify_group_member hook).
    let jar = hort_domain::ports::artifact_repository::ArtifactRepository::find_by_path(
        mocks.artifacts.as_ref(),
        repo.id,
        "com/example/foo/1.0/foo-1.0.jar",
    )
    .await
    .unwrap()
    .expect("jar row stored");
    let group = mocks
        .artifact_groups
        .find_by_member(jar.id)
        .await
        .unwrap()
        .expect("jar belongs to a group");
    assert_eq!(group.coords.name, "com.example:foo");
    assert_eq!(group.coords.version.as_deref(), Some("1.0"));
    assert_eq!(group.members.len(), 2, "jar + pom are both members");
    assert_eq!(group.primary_role, "jar", "jar is the primary role");
    let roles: std::collections::BTreeSet<&str> =
        group.members.iter().map(|m| m.role.as_str()).collect();
    assert!(roles.contains("jar"));
    assert!(roles.contains("pom"));
}

/// HEAD on a stored file returns 200 + headers and an empty body.
#[tokio::test]
async fn head_file_returns_headers_no_body() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        b"JARBYTES",
        QuarantineStatus::Released,
    );
    let router = router(ctx);

    let res = router
        .oneshot(
            Request::head("/maven/mvn/com/example/foo/1.0/foo-1.0.jar")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(CONTENT_LENGTH).unwrap(), "8");
    let body = to_bytes(res.into_body(), 1024).await.unwrap();
    assert!(body.is_empty(), "HEAD body must be empty");
}

/// A Gradle-format repo is served by the same handler (Maven alias).
#[tokio::test]
async fn gradle_format_repo_is_served() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "gradle-repo", RepositoryFormat::Gradle);
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        b"GRADLE",
        QuarantineStatus::Released,
    );
    let router = router(ctx);
    let (st, body) = get(
        &router,
        "/maven/gradle-repo/com/example/foo/1.0/foo-1.0.jar",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"GRADLE");
}

/// Gradle Module Metadata (`.module`) publish→download roundtrip (design §9):
/// the `.module` JSON is stored opaquely, served byte-for-byte, joins the
/// jar+pom group as a `module`-role member, and its on-demand `.sha256`
/// sidecar (Item 7) matches the stored bytes. No GMM variant parsing — the
/// body is opaque CAS pass-through.
#[tokio::test]
async fn gmm_module_roundtrip_is_group_member_with_matching_sidecar() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "gradle-repo", RepositoryFormat::Gradle);
    let router = router(ctx);

    // A realistic-but-opaque GMM body — Hort never parses these variants.
    let module_body = br#"{"formatVersion":"1.1","component":{"group":"com.example","module":"foo","version":"1.0"},"variants":[]}"#;
    let jar_path = "/maven/gradle-repo/com/example/foo/1.0/foo-1.0.jar";
    let module_path = "/maven/gradle-repo/com/example/foo/1.0/foo-1.0.module";

    assert_eq!(
        put(&router, jar_path, b"JARBYTES").await,
        StatusCode::CREATED
    );
    assert_eq!(
        put(&router, module_path, module_body).await,
        StatusCode::CREATED
    );

    // The `.module` is served back byte-for-byte (opaque pass-through).
    let (st, body) = get(&router, module_path).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, module_body, ".module is stored and served verbatim");

    // It joins the artifact group as a `module`-role member alongside the jar.
    let module = hort_domain::ports::artifact_repository::ArtifactRepository::find_by_path(
        mocks.artifacts.as_ref(),
        repo.id,
        "com/example/foo/1.0/foo-1.0.module",
    )
    .await
    .unwrap()
    .expect("module row stored");
    let group = mocks
        .artifact_groups
        .find_by_member(module.id)
        .await
        .unwrap()
        .expect("module belongs to a group");
    let roles: std::collections::BTreeSet<&str> =
        group.members.iter().map(|m| m.role.as_str()).collect();
    assert!(
        roles.contains("module"),
        "the .module joins the group with role `module`: {roles:?}"
    );
    assert!(roles.contains("jar"), "the jar is also a member");

    // The server-generated `.sha256` sidecar (Item 7) is the digest of the
    // stored `.module` bytes.
    let (st, body) = get(&router, &format!("{module_path}.sha256")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        expected_sha256(module_body),
        ".module .sha256 sidecar matches the stored bytes"
    );
}

/// The POM Gradle-metadata marker comment is client-authored and round-trips
/// verbatim (design §9): Hort stores the POM as opaque CAS bytes and neither
/// synthesises nor strips the `published-with-gradle-metadata` marker — GET
/// returns the exact bytes that were PUT.
#[tokio::test]
async fn pom_gradle_marker_comment_round_trips_verbatim() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "gradle-repo", RepositoryFormat::Gradle);
    let router = router(ctx);

    // A POM carrying the Gradle marker comment exactly as Gradle authors it.
    let pom_bytes = br#"<?xml version="1.0" encoding="UTF-8"?>
<!-- do_not_remove: published-with-gradle-metadata -->
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>foo</artifactId>
  <version>1.0</version>
</project>
"#;
    let pom_path = "/maven/gradle-repo/com/example/foo/1.0/foo-1.0.pom";

    assert_eq!(put(&router, pom_path, pom_bytes).await, StatusCode::CREATED);

    let (st, body) = get(&router, pom_path).await;
    assert_eq!(st, StatusCode::OK);
    // Exact-bytes equality: the marker is neither stripped nor synthesised.
    assert_eq!(
        body, pom_bytes,
        "the POM (incl. the Gradle marker comment) is stored and served verbatim"
    );
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("<!-- do_not_remove: published-with-gradle-metadata -->"),
        "the marker comment survives the roundtrip"
    );
}

// ---------------------------------------------------------------------------
// A-level maven-metadata.xml (server-generated)
// ---------------------------------------------------------------------------

/// Extract the text of every `<{tag}>…</{tag}>` occurrence, in order.
fn extract_all<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else { break };
        out.push(&after[..end]);
        rest = &after[end + close.len()..];
    }
    out
}

fn extract_one<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    extract_all(xml, tag).into_iter().next()
}

/// A-level GET reflects the published versions ordered by
/// MavenVersionOrdering with correct `<latest>`/`<release>`, and a
/// quarantined version is excluded from `<versions>`.
#[tokio::test]
async fn a_level_metadata_reflects_versions_and_excludes_quarantined() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    // Released: 1.0, 1.10, 2.0-SNAPSHOT. Quarantined: 1.2 (must be absent).
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        b"a",
        QuarantineStatus::Released,
    );
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.10",
        "com/example/foo/1.10/foo-1.10.jar",
        b"bb",
        QuarantineStatus::Released,
    );
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "2.0-SNAPSHOT",
        "com/example/foo/2.0-SNAPSHOT/foo-2.0-SNAPSHOT.jar",
        b"ccc",
        QuarantineStatus::Released,
    );
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.2",
        "com/example/foo/1.2/foo-1.2.jar",
        b"dddd",
        QuarantineStatus::Quarantined,
    );
    let router = router(ctx);

    let (st, body) = get(&router, "/maven/mvn/com/example/foo/maven-metadata.xml").await;
    assert_eq!(st, StatusCode::OK);
    let xml = std::str::from_utf8(&body).unwrap();

    let versions = extract_all(xml, "version");
    // Quarantined 1.2 is filtered; survivors in Maven order:
    // 1.0 < 1.10 < 2.0-SNAPSHOT.
    assert_eq!(
        versions,
        vec!["1.0", "1.10", "2.0-SNAPSHOT"],
        "quarantined 1.2 excluded; survivors in MavenVersionOrdering order: {xml}"
    );
    // latest = highest overall (the snapshot); release = highest non-snapshot.
    assert_eq!(extract_one(xml, "latest"), Some("2.0-SNAPSHOT"));
    assert_eq!(extract_one(xml, "release"), Some("1.10"));
    assert_eq!(extract_one(xml, "groupId"), Some("com.example"));
    assert_eq!(extract_one(xml, "artifactId"), Some("foo"));
}

/// A-level GET for an unknown artifact → 404.
#[tokio::test]
async fn a_level_metadata_unknown_artifact_is_404() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);
    let (st, _) = get(&router, "/maven/mvn/com/example/nope/maven-metadata.xml").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// Content-Type of the generated metadata is text/xml.
#[tokio::test]
async fn a_level_metadata_content_type_is_text_xml() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        b"a",
        QuarantineStatus::Released,
    );
    let router = router(ctx);
    let res = router
        .oneshot(
            Request::get("/maven/mvn/com/example/foo/maven-metadata.xml")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(CONTENT_TYPE).unwrap(), "text/xml");
}

// ---------------------------------------------------------------------------
// quarantine gate + rejected (design §11/§17)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn quarantined_file_get_returns_503_with_retry_after() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        b"x",
        QuarantineStatus::Quarantined,
    );
    let router = router(ctx);
    let res = router
        .oneshot(
            Request::get("/maven/mvn/com/example/foo/1.0/foo-1.0.jar")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(res.headers().get("Retry-After").is_some());
}

#[tokio::test]
async fn rejected_file_get_returns_403() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        b"x",
        QuarantineStatus::Rejected,
    );
    let router = router(ctx);
    let (st, _) = get(&router, "/maven/mvn/com/example/foo/1.0/foo-1.0.jar").await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn missing_file_get_returns_404() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);
    let (st, _) = get(&router, "/maven/mvn/com/example/foo/1.0/foo-1.0.jar").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// anonymous read of a private repo → 404 (anti-enumeration)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn anonymous_read_private_repo_is_404_not_403() {
    let (ctx, mocks) = build_mock_ctx(handle());
    // Empty RBAC evaluator (no claims grant any access), auth enabled.
    let access = Arc::new(RepositoryAccessUseCase::new(
        mocks.repositories.clone(),
        RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
            RbacEvaluator::new(Vec::new()),
        ))),
        true,
    ));
    let ctx = with_repository_access(&ctx, access);

    let mut repo = sample_repository();
    repo.key = "private-mvn".into();
    repo.format = RepositoryFormat::Maven;
    repo.repo_type = RepositoryType::Hosted;
    repo.is_public = false;
    mocks.repositories.insert(repo.clone());
    insert_file(
        &mocks,
        repo.id,
        "com.example:secret",
        "1.0",
        "com/example/secret/1.0/secret-1.0.jar",
        b"top-secret",
        QuarantineStatus::Released,
    );
    let router = router(ctx);

    // Both the file and the metadata path must 404 (never 403).
    let (st, _) = get(
        &router,
        "/maven/private-mvn/com/example/secret/1.0/secret-1.0.jar",
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "private file → 404, never 403");
    let (st, _) = get(
        &router,
        "/maven/private-mvn/com/example/secret/maven-metadata.xml",
    )
    .await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "private metadata → 404, never 403"
    );
}

/// A request to a non-Maven/Gradle repo key under /maven → 404 (no
/// format oracle).
#[tokio::test]
async fn wrong_format_repo_is_404() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "py", RepositoryFormat::Pypi);
    let router = router(ctx);
    let (st, _) = get(&router, "/maven/py/com/example/foo/1.0/foo-1.0.jar").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// metadata / sidecar PUT accepted-and-discarded; sidecar GET 404
// ---------------------------------------------------------------------------

/// A client maven-metadata.xml PUT is accepted (200) and NOT stored — a
/// subsequent metadata GET is the server-generated copy (reflecting actual
/// published versions), not the client's bytes.
#[tokio::test]
async fn metadata_put_accepted_and_discarded() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    // One real published version, so the generated metadata is non-empty.
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        b"a",
        QuarantineStatus::Released,
    );
    let router = router(ctx);

    // A bogus client metadata advertising a version that does not exist.
    let bogus = b"<metadata><versioning><versions><version>9.9.9</version></versions></versioning></metadata>";
    assert_eq!(
        put(
            &router,
            "/maven/mvn/com/example/foo/maven-metadata.xml",
            bogus
        )
        .await,
        StatusCode::OK,
        "client metadata PUT accepted"
    );

    // No ArtifactIngested fired (metadata is discarded, not stored).
    let ingested = mocks
        .lifecycle
        .committed_transitions()
        .iter()
        .flat_map(|(_a, batch, _m)| batch.events.iter())
        .filter(|e| matches!(e.event, DomainEvent::ArtifactIngested(_)))
        .count();
    assert_eq!(ingested, 0, "metadata PUT must not ingest an artifact");

    // The served metadata is the GENERATED copy — it lists 1.0, NOT 9.9.9.
    let (st, body) = get(&router, "/maven/mvn/com/example/foo/maven-metadata.xml").await;
    assert_eq!(st, StatusCode::OK);
    let xml = std::str::from_utf8(&body).unwrap();
    let versions = extract_all(xml, "version");
    assert_eq!(
        versions,
        vec!["1.0"],
        "served metadata is generated, not the client's: {xml}"
    );
    assert!(
        !xml.contains("9.9.9"),
        "client-advertised version must not appear"
    );
}

/// A checksum-sidecar PUT is accepted (200) and discarded; a sidecar GET of
/// a NON-existent target file is 404 (a sidecar of nothing), independent of
/// any client-PUT bytes.
#[tokio::test]
async fn sidecar_put_accepted_and_sidecar_get_of_missing_file_is_404() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);

    assert_eq!(
        put(
            &router,
            "/maven/mvn/com/example/foo/1.0/foo-1.0.jar.sha1",
            b"abc123",
        )
        .await,
        StatusCode::OK,
        "sidecar PUT accepted"
    );
    // No artifact ingested for the sidecar.
    let ingested = mocks
        .lifecycle
        .committed_transitions()
        .iter()
        .flat_map(|(_a, batch, _m)| batch.events.iter())
        .filter(|e| matches!(e.event, DomainEvent::ArtifactIngested(_)))
        .count();
    assert_eq!(ingested, 0, "sidecar PUT must not ingest an artifact");

    // The target `.jar` does not exist → its sidecar is a 404 (the client
    // PUT was discarded; nothing is stored under the sidecar path).
    let (st, _) = get(&router, "/maven/mvn/com/example/foo/1.0/foo-1.0.jar.sha1").await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "sidecar GET of a missing target file → 404"
    );
}

// ---------------------------------------------------------------------------
// on-demand checksum sidecars (Item 7, design §6 / §11)
// ---------------------------------------------------------------------------

/// Independently compute the expected lowercase hex digest of `content`
/// under each algorithm — the test's own oracle, not the handler's code.
fn expected_sha1(content: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    hex::encode(Sha1::digest(content))
}
fn expected_sha256(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(content))
}
fn expected_sha512(content: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    hex::encode(Sha512::digest(content))
}
fn expected_md5(content: &[u8]) -> String {
    use md5::{Digest, Md5};
    hex::encode(Md5::digest(content))
}

/// Each algorithm's sidecar GET returns the correct digest of the stored
/// file's bytes, as bare lowercase hex with `text/plain`.
#[tokio::test]
async fn sidecar_get_returns_correct_digest_for_each_algorithm() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let content = b"JARBYTES-payload-1234567890";
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        content,
        QuarantineStatus::Released,
    );
    let router = router(ctx);
    let base = "/maven/mvn/com/example/foo/1.0/foo-1.0.jar";

    for (ext, expected) in [
        ("sha1", expected_sha1(content)),
        ("sha256", expected_sha256(content)),
        ("sha512", expected_sha512(content)),
        ("md5", expected_md5(content)),
    ] {
        let res = router
            .clone()
            .oneshot(
                Request::get(format!("{base}.{ext}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{ext} sidecar → 200");
        assert_eq!(
            res.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain",
            "{ext} sidecar is text/plain"
        );
        let body = to_bytes(res.into_body(), 4096).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            expected,
            "{ext} sidecar is the bare lowercase hex of the stored bytes"
        );
    }
}

/// `.sha256` short-circuits to the artifact's CAS ContentHash (no stream,
/// no cache entry written).
#[tokio::test]
async fn sha256_sidecar_is_cas_content_hash_and_not_cached() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let content = b"cas-hash-source";
    let artifact = insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        content,
        QuarantineStatus::Released,
    );
    let router = router(ctx);

    let (st, body) = get(&router, "/maven/mvn/com/example/foo/1.0/foo-1.0.jar.sha256").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        artifact.sha256_checksum.as_ref(),
        ".sha256 sidecar is exactly the CAS ContentHash"
    );
    // No `mavensum:...:sha256` cache entry — sha256 is served free.
    let key = format!("mavensum:{}:sha256", artifact.sha256_checksum.as_ref());
    assert!(
        mocks.ephemeral_evictable.get(&key).await.unwrap().is_none(),
        ".sha256 must NOT write a mavensum cache entry"
    );
}

/// A `.sha1` sidecar GET memoises the digest in the `mavensum:` keyspace,
/// and a second GET is served from cache (the cache entry pre-exists; the
/// served value matches what was memoised).
#[tokio::test]
async fn sha1_sidecar_is_memoised_and_second_get_hits_cache() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let content = b"memoise-me";
    let artifact = insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        content,
        QuarantineStatus::Released,
    );
    let router = router(ctx);
    let path = "/maven/mvn/com/example/foo/1.0/foo-1.0.jar.sha1";
    let cache_key = format!("mavensum:{}:sha1", artifact.sha256_checksum.as_ref());

    // Before any GET: no cache entry.
    assert!(
        mocks
            .ephemeral_evictable
            .get(&cache_key)
            .await
            .unwrap()
            .is_none(),
        "no mavensum entry before the first sidecar GET"
    );

    // First GET computes + memoises.
    let (st, body1) = get(&router, path).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&body1).unwrap(), expected_sha1(content));

    // The cache now holds the digest.
    let cached = mocks
        .ephemeral_evictable
        .get(&cache_key)
        .await
        .unwrap()
        .expect("mavensum entry memoised after first GET");
    assert_eq!(
        std::str::from_utf8(&cached).unwrap(),
        expected_sha1(content),
        "memoised hex matches the computed digest"
    );

    // Cache-hit proof: overwrite the cache with a SENTINEL value; the
    // second GET must serve the SENTINEL (proving it read the cache and did
    // NOT re-hash the blob). The digest of immutable content can never
    // legitimately differ, so a divergent served value can only come from
    // the cache path.
    let sentinel = "cccccccccccccccccccccccccccccccccccccccc";
    mocks
        .ephemeral_evictable
        .put(
            &cache_key,
            Bytes::from_static(sentinel.as_bytes()),
            std::time::Duration::from_secs(3600),
        )
        .await
        .unwrap();

    let (st, body2) = get(&router, path).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&body2).unwrap(),
        sentinel,
        "second GET is served from the mavensum cache (not a re-hash)"
    );
}

/// A sidecar GET of a QUARANTINED target inherits the file's 503 +
/// Retry-After and never leaks the digest.
#[tokio::test]
async fn sidecar_of_quarantined_file_is_503_no_digest_leak() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let content = b"held-bytes";
    let artifact = insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        content,
        QuarantineStatus::Quarantined,
    );
    let router = router(ctx);

    let res = router
        .clone()
        .oneshot(
            Request::get("/maven/mvn/com/example/foo/1.0/foo-1.0.jar.sha1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE, "503");
    assert!(
        res.headers().get("Retry-After").is_some(),
        "Retry-After present"
    );
    let body = to_bytes(res.into_body(), 4096).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains(&expected_sha1(content)),
        "the held file's digest must NOT appear in the 503 body"
    );
    // The digest of a held version is never computed → no cache entry.
    let key = format!("mavensum:{}:sha1", artifact.sha256_checksum.as_ref());
    assert!(
        mocks.ephemeral_evictable.get(&key).await.unwrap().is_none(),
        "a held sidecar GET must not compute or memoise the digest"
    );
}

/// A sidecar GET of a REJECTED target inherits the file's 403.
#[tokio::test]
async fn sidecar_of_rejected_file_is_403() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        b"rejected-bytes",
        QuarantineStatus::Rejected,
    );
    let router = router(ctx);
    let (st, _) = get(&router, "/maven/mvn/com/example/foo/1.0/foo-1.0.jar.sha1").await;
    assert_eq!(st, StatusCode::FORBIDDEN, "rejected target → 403");
}

/// A HEAD on a sidecar returns 200 + text/plain headers and an empty body.
#[tokio::test]
async fn sidecar_head_returns_headers_no_body() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        b"head-bytes",
        QuarantineStatus::Released,
    );
    let router = router(ctx);
    let res = router
        .oneshot(
            Request::head("/maven/mvn/com/example/foo/1.0/foo-1.0.jar.sha1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(CONTENT_TYPE).unwrap(), "text/plain");
    let body = to_bytes(res.into_body(), 4096).await.unwrap();
    assert!(body.is_empty(), "HEAD sidecar body is empty");
}

/// A client `.sha1` PUT is accepted and discarded: the subsequent sidecar
/// GET returns the SERVER-computed digest of the stored file, independent
/// of the (wrong) bytes the client PUT.
#[tokio::test]
async fn client_sidecar_put_discarded_get_returns_server_digest() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);
    let jar = "/maven/mvn/com/example/foo/1.0/foo-1.0.jar";
    let content = b"server-authoritative";

    // Publish the real jar.
    assert_eq!(put(&router, jar, content).await, StatusCode::CREATED);
    // Client PUTs a WRONG sidecar digest — accepted and discarded.
    assert_eq!(
        put(
            &router,
            &format!("{jar}.sha1"),
            b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        )
        .await,
        StatusCode::OK,
        "client sidecar PUT accepted"
    );

    // The GET returns the SERVER digest, not the client's wrong value.
    let (st, body) = get(&router, &format!("{jar}.sha1")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        expected_sha1(content),
        "served sidecar is the server-computed digest, not the client PUT"
    );
}

/// An A-level `maven-metadata.xml.sha1` GET returns the SHA-1 of the
/// server-generated A-level XML bytes (the same bytes the metadata GET
/// serves).
#[tokio::test]
async fn metadata_sidecar_matches_sha1_of_generated_a_level_xml() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        b"a",
        QuarantineStatus::Released,
    );
    let router = router(ctx);

    // Fetch the generated XML the metadata GET would serve.
    let (st, xml) = get(&router, "/maven/mvn/com/example/foo/maven-metadata.xml").await;
    assert_eq!(st, StatusCode::OK);

    // The sidecar GET must equal SHA-1 of exactly those bytes.
    let (st, body) = get(
        &router,
        "/maven/mvn/com/example/foo/maven-metadata.xml.sha1",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        expected_sha1(&xml),
        "metadata sidecar is SHA-1 over the generated A-level XML"
    );
}

/// Every metadata-sidecar algorithm (sha1, sha256, sha512, md5) returns the
/// digest of exactly the server-generated A-level XML bytes the metadata GET
/// serves. The plain sha1 case is pinned above; this exercises the other
/// three `serve_metadata_sidecar` → `digest_bytes` arms (notably `.sha256`,
/// which the stored-file path short-circuits but the generated-document path
/// must hash over the produced bytes).
#[tokio::test]
async fn metadata_sidecar_matches_every_algorithm_of_generated_a_level_xml() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        b"a",
        QuarantineStatus::Released,
    );
    let router = router(ctx);

    // The exact bytes the metadata GET serves are the hash oracle.
    let (st, xml) = get(&router, "/maven/mvn/com/example/foo/maven-metadata.xml").await;
    assert_eq!(st, StatusCode::OK);

    for (ext, expected) in [
        ("sha1", expected_sha1(&xml)),
        ("sha256", expected_sha256(&xml)),
        ("sha512", expected_sha512(&xml)),
        ("md5", expected_md5(&xml)),
    ] {
        let (st, body) = get(
            &router,
            &format!("/maven/mvn/com/example/foo/maven-metadata.xml.{ext}"),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{ext} metadata sidecar → 200");
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            expected,
            "{ext} metadata sidecar is the digest of the generated A-level XML"
        );
    }
}

/// A corrupt (non-utf8) cached sidecar value falls through and is recomputed:
/// the GET still serves the CORRECT digest, never the corrupt cache bytes.
/// Pins the `compute_or_cache_digest` non-utf8 cache-corruption fall-through.
#[tokio::test]
async fn sidecar_non_utf8_cache_value_falls_through_and_recomputes() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let content = b"recompute-after-corruption";
    let artifact = insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0",
        "com/example/foo/1.0/foo-1.0.jar",
        content,
        QuarantineStatus::Released,
    );
    let router = router(ctx);
    let path = "/maven/mvn/com/example/foo/1.0/foo-1.0.jar.sha1";
    let cache_key = format!("mavensum:{}:sha1", artifact.sha256_checksum.as_ref());

    // Pre-seed the cache with a NON-utf8 (corrupt) value at the sidecar key.
    mocks
        .ephemeral_evictable
        .put(
            &cache_key,
            Bytes::from_static(&[0xff, 0xfe, 0x00, 0x80]),
            std::time::Duration::from_secs(3600),
        )
        .await
        .unwrap();

    // The GET must fall through the corrupt entry and recompute the digest.
    let (st, body) = get(&router, path).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        expected_sha1(content),
        "a non-utf8 cache value is treated as corruption and recomputed"
    );

    // The recompute also re-memoised a now-valid (utf8) digest.
    let cached = mocks
        .ephemeral_evictable
        .get(&cache_key)
        .await
        .unwrap()
        .expect("recompute re-memoises the digest");
    assert_eq!(
        std::str::from_utf8(&cached).unwrap(),
        expected_sha1(content),
        "the corrupt entry is overwritten with the correct hex"
    );
}

/// A metadata-sidecar GET for an unknown artifact is 404 (same as the plain
/// metadata GET) — the sidecar reuses the metadata producer's
/// unknown-artifact 404.
#[tokio::test]
async fn metadata_sidecar_unknown_artifact_is_404() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);
    let (st, _) = get(
        &router,
        "/maven/mvn/com/example/nope/maven-metadata.xml.sha1",
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// coordinate validation reject → 400 maven.coordinate:
// ---------------------------------------------------------------------------

#[tokio::test]
async fn traversal_coordinate_get_is_400_maven_coordinate() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);
    // A `..` traversal segment in the artifactId position. The parser runs
    // validate_maven_coordinate, which rejects it before any lookup.
    let res = router
        .oneshot(
            Request::get("/maven/mvn/com/example/../1.0/foo-1.0.jar")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), 4096).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert_eq!(status, StatusCode::BAD_REQUEST, "traversal → 400");
    assert!(
        text.contains("maven.coordinate"),
        "error body carries the maven.coordinate: prefix: {text}"
    );
}

#[tokio::test]
async fn traversal_coordinate_put_is_400_maven_coordinate() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);
    let res = router
        .oneshot(
            Request::put("/maven/mvn/com/example/../1.0/foo-1.0.jar")
                .body(Body::from("x"))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), 4096).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert_eq!(status, StatusCode::BAD_REQUEST, "traversal PUT → 400");
    assert!(
        text.contains("maven.coordinate"),
        "maven.coordinate prefix: {text}"
    );
}

/// Re-PUT of an existing path with the same bytes (the idempotent
/// redeploy the ingest layer supports as same-path-same-hash dedup)
/// returns 200, not 201 (design §17). A real Maven SNAPSHOT redeploy
/// uploads NEW timestamped filenames (unique paths → 201 each); the
/// same-path-different-bytes case is a genuine `409 Conflict` at the
/// ingest layer, which is correct (immutable CAS path content).
#[tokio::test]
async fn idempotent_redeploy_same_path_same_bytes_returns_200() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);
    let path = "/maven/mvn/com/example/foo/1.0-SNAPSHOT/foo-1.0-SNAPSHOT.jar";
    assert_eq!(
        put(&router, path, b"snap").await,
        StatusCode::CREATED,
        "first PUT → 201"
    );
    assert_eq!(
        put(&router, path, b"snap").await,
        StatusCode::OK,
        "idempotent re-PUT same path+bytes → 200"
    );
}

/// Same path with DIFFERENT bytes is a 409 Conflict at the ingest layer
/// (immutable CAS content) — pins the design §17 / §11 invariant.
#[tokio::test]
async fn redeploy_same_path_different_bytes_is_409_conflict() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);
    let path = "/maven/mvn/com/example/foo/1.0/foo-1.0.jar";
    assert_eq!(put(&router, path, b"v1").await, StatusCode::CREATED);
    assert_eq!(
        put(&router, path, b"v2").await,
        StatusCode::CONFLICT,
        "same path, different bytes → 409 (immutable CAS content)"
    );
}

// ---------------------------------------------------------------------------
// SNAPSHOT serving (Item 8, design §7)
// ---------------------------------------------------------------------------
//
// Snapshot deploys store ONLY timestamped files under the base
// `X-SNAPSHOT` group (`foo-1.0-{yyyyMMdd.HHmmss}-{N}[-classifier].ext`); the
// V-level `maven-metadata.xml` and the unresolved `foo-1.0-SNAPSHOT.jar`
// form are both server-side derived from those stored rows.

/// Seed one stored timestamped snapshot build under the base `-SNAPSHOT`
/// group, the way Item 6 ingest stores them: group version = base
/// `X-SNAPSHOT`; the file `path` keeps the timestamped filename.
#[allow(clippy::too_many_arguments)]
fn insert_snapshot_build(
    mocks: &MockPorts,
    repo_id: Uuid,
    name: &str,                 // GA, e.g. "com.example:foo"
    base_version: &str,         // "1.0-SNAPSHOT"
    timestamped_filename: &str, // "foo-1.0-20231201.120000-3.jar"
    content: &[u8],
    status: QuarantineStatus,
) -> Artifact {
    // The stored directory is `{group-slashes}/{artifactId}/{base}/`.
    let (group, artifact_id) = name.split_once(':').unwrap();
    let group_path = group.replace('.', "/");
    let path = format!("{group_path}/{artifact_id}/{base_version}/{timestamped_filename}");
    insert_file(mocks, repo_id, name, base_version, &path, content, status)
}

/// Deploying two timestamped builds of the main jar (different
/// `(timestamp, buildNumber)`) plus a `-sources` build → the V-level
/// `maven-metadata.xml` GET: `<snapshot>` reflects the LATEST build's dotted
/// timestamp + buildNumber; `<snapshotVersions>` carries one entry per
/// `(classifier, extension)` pointing at the most-recent `value`; the two
/// timestamp formats (dotted vs non-dotted) are correct.
#[tokio::test]
async fn v_level_metadata_reflects_latest_build_per_classifier_extension() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    // Two main-jar builds (build 1 then build 3 — keep 3) + one sources jar.
    insert_snapshot_build(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0-SNAPSHOT",
        "foo-1.0-20231201.120000-1.jar",
        b"jar-build-1",
        QuarantineStatus::Released,
    );
    insert_snapshot_build(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0-SNAPSHOT",
        "foo-1.0-20231205.080000-3.jar",
        b"jar-build-3",
        QuarantineStatus::Released,
    );
    insert_snapshot_build(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0-SNAPSHOT",
        "foo-1.0-20231202.090000-2-sources.jar",
        b"sources-build-2",
        QuarantineStatus::Released,
    );
    let router = router(ctx);

    let (st, body) = get(
        &router,
        "/maven/mvn/com/example/foo/1.0-SNAPSHOT/maven-metadata.xml",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let xml = std::str::from_utf8(&body).unwrap();

    // Header carries the base version.
    assert_eq!(extract_one(xml, "groupId"), Some("com.example"));
    assert_eq!(extract_one(xml, "artifactId"), Some("foo"));
    assert_eq!(extract_one(xml, "version"), Some("1.0-SNAPSHOT"));

    // <snapshot> block = the HIGHEST build overall (the main jar build 3 at
    // 20231205.080000). The timestamp is the DOTTED form.
    assert_eq!(
        extract_one(xml, "timestamp"),
        Some("20231205.080000"),
        "snapshot/timestamp = highest build, dotted: {xml}"
    );
    assert_eq!(extract_one(xml, "buildNumber"), Some("3"));

    // Exactly two <snapshotVersion> blocks (main jar + sources jar).
    let extensions = extract_all(xml, "extension");
    assert_eq!(extensions.len(), 2, "one snapshotVersion per key: {xml}");

    // The main jar resolves to its MOST-RECENT build (build 3), the older
    // build 1 must be dropped.
    let values = extract_all(xml, "value");
    assert!(
        values.contains(&"1.0-20231205.080000-3"),
        "main-jar value = most-recent build: {values:?}"
    );
    assert!(
        !values.contains(&"1.0-20231201.120000-1"),
        "older main-jar build dropped: {values:?}"
    );
    assert!(
        values.contains(&"1.0-20231202.090000-2"),
        "sources value present: {values:?}"
    );

    // The sources classifier is present (exactly once).
    assert_eq!(extract_all(xml, "classifier"), vec!["sources"]);

    // Two distinct timestamp formats: <snapshot><timestamp> dotted;
    // every <updated>/<lastUpdated> non-dotted.
    let updated = extract_all(xml, "updated");
    assert!(
        updated.iter().all(|u| !u.contains('.')),
        "<updated> must be NON-dotted: {updated:?}"
    );
    assert!(
        updated.contains(&"20231205080000"),
        "main jar updated is the non-dotted form: {updated:?}"
    );
    let last_updated = extract_one(xml, "lastUpdated").unwrap();
    assert!(
        !last_updated.contains('.'),
        "lastUpdated non-dotted: {last_updated}"
    );
    // lastUpdated = max updated across builds (build 3 at 20231205).
    assert_eq!(last_updated, "20231205080000");
}

/// Multi-classifier divergent-timestamp: the main jar and the `-sources`
/// jar carry DIFFERENT latest timestamps; each resolves to its own
/// most-recent build independently.
#[tokio::test]
async fn v_level_multi_classifier_divergent_timestamps_resolve_independently() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    // Main jar's latest is build 3 (earlier day); sources' latest is build 5
    // (later day) — divergent timestamps.
    for (fname, body) in [
        ("foo-1.0-20231201.120000-3.jar", &b"main3"[..]),
        ("foo-1.0-20231201.120000-3-sources.jar", &b"src3"[..]),
        ("foo-1.0-20231210.090000-5-sources.jar", &b"src5"[..]),
    ] {
        insert_snapshot_build(
            &mocks,
            repo.id,
            "com.example:foo",
            "1.0-SNAPSHOT",
            fname,
            body,
            QuarantineStatus::Released,
        );
    }
    let router = router(ctx);

    let (st, body) = get(
        &router,
        "/maven/mvn/com/example/foo/1.0-SNAPSHOT/maven-metadata.xml",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let xml = std::str::from_utf8(&body).unwrap();

    let values = extract_all(xml, "value");
    // Main jar = build 3 (20231201); sources = build 5 (20231210).
    assert!(
        values.contains(&"1.0-20231201.120000-3"),
        "main jar resolves to its own latest (build 3): {values:?}"
    );
    assert!(
        values.contains(&"1.0-20231210.090000-5"),
        "sources resolves to its own (later) latest (build 5): {values:?}"
    );
    // Document <snapshot> block = the SINGLE highest build overall = sources
    // build 5 at 20231210.
    assert_eq!(extract_one(xml, "timestamp"), Some("20231210.090000"));
    assert_eq!(extract_one(xml, "buildNumber"), Some("5"));
}

/// A V-level metadata GET for an UNKNOWN base-snapshot artifact (no stored
/// rows for that version) → 404.
#[tokio::test]
async fn v_level_metadata_unknown_snapshot_is_404() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);
    let (st, _) = get(
        &router,
        "/maven/mvn/com/example/nope/9.9-SNAPSHOT/maven-metadata.xml",
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// Unresolved GET `foo-1.0-SNAPSHOT.jar` resolves to the highest timestamped
/// build and streams ITS bytes; `foo-1.0-SNAPSHOT-sources.jar` resolves to
/// the sources build.
#[tokio::test]
async fn unresolved_snapshot_get_resolves_to_latest_build_and_streams_bytes() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    insert_snapshot_build(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0-SNAPSHOT",
        "foo-1.0-20231201.120000-1.jar",
        b"main-old",
        QuarantineStatus::Released,
    );
    insert_snapshot_build(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0-SNAPSHOT",
        "foo-1.0-20231205.080000-3.jar",
        b"main-latest",
        QuarantineStatus::Released,
    );
    insert_snapshot_build(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0-SNAPSHOT",
        "foo-1.0-20231202.090000-2-sources.jar",
        b"sources-bytes",
        QuarantineStatus::Released,
    );
    let router = router(ctx);

    // The unresolved main jar resolves to the LATEST build (build 3).
    let (st, body) = get(
        &router,
        "/maven/mvn/com/example/foo/1.0-SNAPSHOT/foo-1.0-SNAPSHOT.jar",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        body, b"main-latest",
        "unresolved jar serves the highest timestamped build's bytes"
    );

    // The unresolved sources jar resolves to the sources build.
    let (st, body) = get(
        &router,
        "/maven/mvn/com/example/foo/1.0-SNAPSHOT/foo-1.0-SNAPSHOT-sources.jar",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        body, b"sources-bytes",
        "unresolved sources jar serves the sources build's bytes"
    );
}

/// An unresolved SNAPSHOT GET against an UNKNOWN base (no builds stored) →
/// 404.
#[tokio::test]
async fn unresolved_snapshot_get_unknown_base_is_404() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);
    let (st, _) = get(
        &router,
        "/maven/mvn/com/example/foo/1.0-SNAPSHOT/foo-1.0-SNAPSHOT.jar",
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "unknown snapshot base → 404");
}

/// An unresolved SNAPSHOT GET that resolves to a QUARANTINED build inherits
/// the build's status gate: 503 + Retry-After (the gate applies
/// post-resolution).
#[tokio::test]
async fn unresolved_snapshot_get_resolved_build_quarantined_is_503() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    // The single (latest) build is quarantined.
    insert_snapshot_build(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0-SNAPSHOT",
        "foo-1.0-20231205.080000-3.jar",
        b"held",
        QuarantineStatus::Quarantined,
    );
    let router = router(ctx);

    let res = router
        .oneshot(
            Request::get("/maven/mvn/com/example/foo/1.0-SNAPSHOT/foo-1.0-SNAPSHOT.jar")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "resolved-but-quarantined build → 503 (status gate post-resolution)"
    );
    assert!(res.headers().get("Retry-After").is_some());
}

/// The base `X-SNAPSHOT` appears in the A-level `<versions>` alongside
/// release versions — the stored rows' `version` is the base, so the A-level
/// source lists it (deduped to a single entry across the timestamped
/// builds).
#[tokio::test]
async fn a_level_versions_includes_snapshot_base() {
    let (ctx, mocks) = build_mock_ctx(handle());
    let repo = insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    // A release version + multiple timestamped builds of one base SNAPSHOT.
    insert_file(
        &mocks,
        repo.id,
        "com.example:foo",
        "0.9",
        "com/example/foo/0.9/foo-0.9.jar",
        b"rel",
        QuarantineStatus::Released,
    );
    insert_snapshot_build(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0-SNAPSHOT",
        "foo-1.0-20231201.120000-1.jar",
        b"snap1",
        QuarantineStatus::Released,
    );
    insert_snapshot_build(
        &mocks,
        repo.id,
        "com.example:foo",
        "1.0-SNAPSHOT",
        "foo-1.0-20231205.080000-3.jar",
        b"snap3",
        QuarantineStatus::Released,
    );
    let router = router(ctx);

    let (st, body) = get(&router, "/maven/mvn/com/example/foo/maven-metadata.xml").await;
    assert_eq!(st, StatusCode::OK);
    let xml = std::str::from_utf8(&body).unwrap();

    let versions = extract_all(xml, "version");
    // The base -SNAPSHOT appears EXACTLY ONCE (deduped across builds), in
    // Maven order after the release (0.9 < 1.0-SNAPSHOT).
    assert_eq!(
        versions,
        vec!["0.9", "1.0-SNAPSHOT"],
        "A-level lists the base -SNAPSHOT once, alongside the release: {xml}"
    );
    // latest = highest overall (the snapshot); release = highest non-snapshot.
    assert_eq!(extract_one(xml, "latest"), Some("1.0-SNAPSHOT"));
    assert_eq!(extract_one(xml, "release"), Some("0.9"));
}

/// End-to-end via the PUT path: `mvn deploy`-shaped uploads of timestamped
/// builds (any order, with sidecars + V-level metadata accepted-discarded)
/// produce a correct server-generated V-level document and a resolvable
/// unresolved GET — proving Item 6 ingest + Item 8 serve compose.
#[tokio::test]
async fn snapshot_deploy_put_then_v_level_and_unresolved_get() {
    let (ctx, mocks) = build_mock_ctx(handle());
    insert_repo(&mocks, "mvn", RepositoryFormat::Maven);
    let router = router(ctx);
    let dir = "/maven/mvn/com/example/foo/1.0-SNAPSHOT";

    // A mvn-deploy-shaped sequence: two timestamped jar builds + a pom build,
    // their sidecars, and the V-level metadata (accepted-discarded).
    assert_eq!(
        put(
            &router,
            &format!("{dir}/foo-1.0-20231201.120000-1.jar"),
            b"build1"
        )
        .await,
        StatusCode::CREATED
    );
    assert_eq!(
        put(
            &router,
            &format!("{dir}/foo-1.0-20231201.120000-1.jar.sha1"),
            b"clientsha"
        )
        .await,
        StatusCode::OK,
        "sidecar PUT accepted-discarded"
    );
    assert_eq!(
        put(
            &router,
            &format!("{dir}/foo-1.0-20231205.080000-2.jar"),
            b"build2"
        )
        .await,
        StatusCode::CREATED
    );
    assert_eq!(
        put(
            &router,
            &format!("{dir}/foo-1.0-20231205.080000-2.pom"),
            b"<project/>"
        )
        .await,
        StatusCode::CREATED
    );
    // V-level client metadata PUT accepted-discarded.
    assert_eq!(
        put(
            &router,
            &format!("{dir}/maven-metadata.xml"),
            b"<metadata/>"
        )
        .await,
        StatusCode::OK,
        "V-level metadata PUT accepted-discarded"
    );

    // Server-generated V-level metadata reflects the LATEST jar build (build
    // 2 at 20231205) + the pom build.
    let (st, body) = get(&router, &format!("{dir}/maven-metadata.xml")).await;
    assert_eq!(st, StatusCode::OK);
    let xml = std::str::from_utf8(&body).unwrap();
    assert_eq!(extract_one(xml, "version"), Some("1.0-SNAPSHOT"));
    // Highest build overall = build 2 (20231205) — both the jar and pom share
    // that timestamp/build, so the <snapshot> block points there.
    assert_eq!(extract_one(xml, "timestamp"), Some("20231205.080000"));
    assert_eq!(extract_one(xml, "buildNumber"), Some("2"));
    let values = extract_all(xml, "value");
    assert!(
        values.contains(&"1.0-20231205.080000-2"),
        "latest jar build value present: {values:?}"
    );
    assert!(
        !values.contains(&"1.0-20231201.120000-1"),
        "older jar build dropped from snapshotVersions: {values:?}"
    );
    // jar + pom keys → two snapshotVersion blocks.
    let extensions = extract_all(xml, "extension");
    let ext_set: std::collections::BTreeSet<&str> = extensions.iter().copied().collect();
    assert!(ext_set.contains("jar"), "jar key present: {ext_set:?}");
    assert!(ext_set.contains("pom"), "pom key present: {ext_set:?}");

    // The unresolved GET serves the LATEST jar build's bytes.
    let (st, body) = get(&router, &format!("{dir}/foo-1.0-SNAPSHOT.jar")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"build2", "unresolved jar = latest timestamped build");
}

// ---------------------------------------------------------------------------
// Proxy-repo pull-through wiring (Item 9, design §8, ADR 0033)
// ---------------------------------------------------------------------------
//
// Regression coverage for the cache-miss + Proxy branch in `serve_file`. The
// fixture loop mirrors `upstream_pull::tests`: seed a Maven Proxy repo +
// upstream mapping, preload the strongest sidecar + the artifact body on the
// mock upstream proxy, then exercise the GET route end-to-end. A Proxy cache
// miss routes through `try_upstream_maven_pull`, verifies + ingests the
// fetched bytes, and serves them through the existing quarantine + streaming
// path (200 on the happy path). Hosted repos must NOT enter the Proxy branch.

mod proxy_pull_through {
    use chrono::Utc;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };

    use super::*;

    fn proxy_repo(mocks: &MockPorts, key: &str) -> Repository {
        let mut repo = sample_repository();
        repo.key = key.to_string();
        repo.format = RepositoryFormat::Maven;
        repo.repo_type = RepositoryType::Proxy;
        repo.upstream_url = Some("https://repo1.maven.org/maven2".into());
        mocks.repositories.insert(repo.clone());
        repo
    }

    fn seed_mapping(mocks: &MockPorts, repo_id: Uuid) {
        let now = Utc::now();
        mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            path_prefix: "".into(),
            upstream_url: "https://repo1.maven.org/maven2".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        });
    }

    fn sha256_hex(content: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(content))
    }

    const REL: &str = "com/example/foo/1.0/foo-1.0.jar";

    /// Proxy cache miss + happy upstream → 200 with the verified bytes.
    #[tokio::test]
    async fn proxy_cache_miss_success_returns_200() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_repo(&mocks, "mvn-mirror");
        seed_mapping(&mocks, repo.id);

        let body = b"the actual jar body".to_vec();
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{REL}.sha256"),
            sha256_hex(&body).into_bytes(),
        );
        mocks.upstream_proxy.insert_artifact("", REL, body.clone());

        let router = router(ctx);
        let (st, got) = get(&router, &format!("/maven/mvn-mirror/{REL}")).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(got, body, "pulled + verified bytes are served");
    }

    /// Proxy cache miss with NO sidecar upstream → 502 (unproxiable, ADR 0006).
    #[tokio::test]
    async fn proxy_cache_miss_no_sidecar_returns_502() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_repo(&mocks, "mvn-mirror");
        seed_mapping(&mocks, repo.id);

        // Body present but no sidecar → unproxiable.
        mocks
            .upstream_proxy
            .insert_artifact("", REL, b"unverifiable".to_vec());

        let router = router(ctx);
        let (st, _) = get(&router, &format!("/maven/mvn-mirror/{REL}")).await;
        assert_eq!(st, StatusCode::BAD_GATEWAY);
    }

    /// Proxy cache miss with a tampered body (sidecar ≠ bytes) → 502, nothing
    /// served.
    #[tokio::test]
    async fn proxy_cache_miss_checksum_mismatch_returns_502() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_repo(&mocks, "mvn-mirror");
        seed_mapping(&mocks, repo.id);

        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{REL}.sha256"),
            sha256_hex(b"different bytes").into_bytes(),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", REL, b"actual bytes".to_vec());

        let router = router(ctx);
        let (st, _) = get(&router, &format!("/maven/mvn-mirror/{REL}")).await;
        assert_eq!(st, StatusCode::BAD_GATEWAY);
    }

    /// Proxy cache miss where the upstream artifact body is absent (404) → 404.
    #[tokio::test]
    async fn proxy_cache_miss_upstream_artifact_404_returns_404() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_repo(&mocks, "mvn-mirror");
        seed_mapping(&mocks, repo.id);

        // Sidecar resolves but the artifact body is not seeded.
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{REL}.sha256"),
            sha256_hex(b"whatever").into_bytes(),
        );

        let router = router(ctx);
        let (st, _) = get(&router, &format!("/maven/mvn-mirror/{REL}")).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }

    /// A HOSTED-repo cache miss stays 404 — it must NOT enter the Proxy
    /// pull-through branch even with upstream fixtures + a mapping seeded.
    #[tokio::test]
    async fn hosted_cache_miss_stays_404() {
        let (ctx, mocks) = build_mock_ctx(handle());
        // Hosted (default in `insert_repo`), not Proxy.
        let repo = insert_repo(&mocks, "mvn-hosted", RepositoryFormat::Maven);
        // Even if a mapping + upstream fixtures exist, a Hosted repo never
        // pulls.
        seed_mapping(&mocks, repo.id);
        let body = b"would-be-pulled".to_vec();
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{REL}.sha256"),
            sha256_hex(&body).into_bytes(),
        );
        mocks.upstream_proxy.insert_artifact("", REL, body);

        let router = router(ctx);
        let (st, _) = get(&router, &format!("/maven/mvn-hosted/{REL}")).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "hosted miss never pulls");
    }

    /// A pulled-but-quarantined artifact → 503 + Retry-After. A repo-scoped
    /// `ScanPolicy` with a non-zero `quarantine_duration_secs` (which beats
    /// the permissive global seed) makes `ingest_verified` land the
    /// freshly-pulled artifact in `Quarantined`, so the shared
    /// `render_file_response` gate fires on the pulled row.
    #[tokio::test]
    async fn proxy_cache_miss_pulled_artifact_quarantined_returns_503() {
        use hort_domain::entities::scan_policy::{
            NegligibleAction, ProvenanceMode, ScanPolicyProjection, SeverityThreshold,
        };
        use hort_domain::events::PolicyScope;

        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_repo(&mocks, "mvn-mirror");
        seed_mapping(&mocks, repo.id);

        // Repo-scoped quarantining policy — `resolve_active_policy_for_repo`
        // prefers a repo-scoped match over the permissive global seed.
        let now = Utc::now();
        mocks.policy_projections.insert(ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: "quarantine-mvn-mirror".to_string(),
            scope: PolicyScope::Repository(repo.id),
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs: 3600, // 1h hold → Quarantined on ingest
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            stream_version: 0,
            created_at: now,
            updated_at: now,
        });

        let body = b"the actual jar body".to_vec();
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{REL}.sha256"),
            sha256_hex(&body).into_bytes(),
        );
        mocks.upstream_proxy.insert_artifact("", REL, body);

        let router = router(ctx);
        let res = router
            .clone()
            .oneshot(
                Request::get(format!("/maven/mvn-mirror/{REL}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            res.headers().get("Retry-After").is_some(),
            "quarantined pull must carry Retry-After"
        );
    }
}

// ---------------------------------------------------------------------------
// Virtual (aggregating) repository — ADR 0031
// ---------------------------------------------------------------------------
mod virtual_repo {
    use super::*;

    /// Insert a `type: virtual` Maven repo aggregating `members` in priority
    /// order (index 0 = highest).
    fn insert_virtual_repo(mocks: &MockPorts, key: &str, members: &[&Repository]) -> Repository {
        let mut repo = sample_repository();
        repo.key = key.to_string();
        repo.format = RepositoryFormat::Maven;
        repo.repo_type = RepositoryType::Virtual;
        mocks.repositories.insert(repo.clone());
        for m in members {
            mocks.repositories.seed_virtual_member(repo.id, m.id);
        }
        repo
    }

    /// A-level `maven-metadata.xml` through a virtual unions the members'
    /// version lists (the `aggregate_virtual_index` merge).
    #[tokio::test]
    async fn virtual_a_level_metadata_merges_member_versions() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let a = insert_repo(&mocks, "mvn-a", RepositoryFormat::Maven);
        let b = insert_repo(&mocks, "mvn-b", RepositoryFormat::Maven);
        insert_file(
            &mocks,
            a.id,
            "com.example:foo",
            "1.0",
            "com/example/foo/1.0/foo-1.0.jar",
            b"A",
            QuarantineStatus::Released,
        );
        insert_file(
            &mocks,
            b.id,
            "com.example:foo",
            "2.0",
            "com/example/foo/2.0/foo-2.0.jar",
            b"B",
            QuarantineStatus::Released,
        );
        let _virt = insert_virtual_repo(&mocks, "mvn-virt", &[&a, &b]);
        let router = router(ctx);

        let (st, body) = get(
            &router,
            "/maven/mvn-virt/com/example/foo/maven-metadata.xml",
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let xml = String::from_utf8(body).unwrap();
        assert!(
            xml.contains("<version>1.0</version>"),
            "member a version: {xml}"
        );
        assert!(
            xml.contains("<version>2.0</version>"),
            "member b version: {xml}"
        );
    }

    /// Dependency-confusion pinning (same-version): the higher-priority member
    /// holds 1.0 Quarantined; a lower-priority member has the SAME version
    /// Released. The held copy wins the authoritative merge and is then
    /// filtered out — it is NOT replaced by the secondary's released copy, so
    /// 1.0 is absent from the served document. Mirrors the pypi/npm regression.
    #[tokio::test]
    async fn virtual_a_level_held_primary_not_replaced_by_secondary() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let primary = insert_repo(&mocks, "mvn-primary", RepositoryFormat::Maven);
        let secondary = insert_repo(&mocks, "mvn-secondary", RepositoryFormat::Maven);
        insert_file(
            &mocks,
            primary.id,
            "com.example:foo",
            "1.0",
            "com/example/foo/1.0/foo-1.0.jar",
            b"held",
            QuarantineStatus::Quarantined,
        );
        insert_file(
            &mocks,
            secondary.id,
            "com.example:foo",
            "1.0",
            "com/example/foo/1.0/foo-1.0.jar",
            b"released",
            QuarantineStatus::Released,
        );
        let _virt = insert_virtual_repo(&mocks, "mvn-virt", &[&primary, &secondary]);
        let router = router(ctx);

        let (st, body) = get(
            &router,
            "/maven/mvn-virt/com/example/foo/maven-metadata.xml",
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let xml = String::from_utf8(body).unwrap();
        assert!(
            !xml.contains("<version>1.0</version>"),
            "held primary copy filtered out, NOT replaced by the secondary's released copy: {xml}"
        );
    }

    /// V-level (snapshot) `maven-metadata.xml` through a virtual resolves to
    /// the authoritative member that owns the `-SNAPSHOT` version and serves
    /// ITS build list (no cross-member interleaving).
    #[tokio::test]
    async fn virtual_v_level_routes_to_authoritative_member() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let a = insert_repo(&mocks, "mvn-a", RepositoryFormat::Maven);
        let b = insert_repo(&mocks, "mvn-b", RepositoryFormat::Maven);
        // Only member a owns the snapshot.
        insert_snapshot_build(
            &mocks,
            a.id,
            "com.example:foo",
            "1.0-SNAPSHOT",
            "foo-1.0-20231201.120000-1.jar",
            b"build1",
            QuarantineStatus::Released,
        );
        let _virt = insert_virtual_repo(&mocks, "mvn-virt", &[&a, &b]);
        let router = router(ctx);

        let (st, body) = get(
            &router,
            "/maven/mvn-virt/com/example/foo/1.0-SNAPSHOT/maven-metadata.xml",
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let xml = String::from_utf8(body).unwrap();
        assert!(
            xml.contains("20231201.120000"),
            "authoritative member's snapshot build timestamp must be served: {xml}"
        );
    }

    /// A virtual file download routes through the owning member's full
    /// per-member serve path (CAS bytes returned).
    #[tokio::test]
    async fn virtual_file_download_routes_to_member() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let a = insert_repo(&mocks, "mvn-a", RepositoryFormat::Maven);
        insert_file(
            &mocks,
            a.id,
            "com.example:foo",
            "1.0",
            "com/example/foo/1.0/foo-1.0.jar",
            b"JARBYTES",
            QuarantineStatus::Released,
        );
        let _virt = insert_virtual_repo(&mocks, "mvn-virt", &[&a]);
        let router = router(ctx);

        let (st, body) = get(&router, "/maven/mvn-virt/com/example/foo/1.0/foo-1.0.jar").await;
        assert_eq!(
            st,
            StatusCode::OK,
            "virtual file download must route to the member"
        );
        assert_eq!(body, b"JARBYTES");
    }

    /// A virtual file download for a coordinate no member has → 404 (the owner
    /// of the name lacks this version; no proxy fall-through).
    #[tokio::test]
    async fn virtual_file_download_absent_coordinate_returns_404() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let a = insert_repo(&mocks, "mvn-a", RepositoryFormat::Maven);
        insert_file(
            &mocks,
            a.id,
            "com.example:foo",
            "1.0",
            "com/example/foo/1.0/foo-1.0.jar",
            b"JARBYTES",
            QuarantineStatus::Released,
        );
        let _virt = insert_virtual_repo(&mocks, "mvn-virt", &[&a]);
        let router = router(ctx);

        // Member a owns `com.example:foo` but has no 3.0 → 404.
        let (st, _body) = get(&router, "/maven/mvn-virt/com/example/foo/3.0/foo-3.0.jar").await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }
}
