//! OCI tags list — `GET /v2/<repo_key>/<name>/tags/list`.
//!
//! Drives [`hort_app::use_cases::ref_use_case::RefUseCase::list`] over
//! the `(repo_id, namespace=name)` pair. The cursor walk is byte-stable;
//! the handler forwards `?n=` / `?last=` query params unchanged.
//!
//! Response envelope (spec):
//! ```json
//! { "name": "library/nginx", "tags": ["v1", "v2", "latest"] }
//! ```
//!
//! `Link: </v2/<repo_key>/<name>/tags/list?n=&last=...>; rel="next"`
//! is emitted only when the page is saturated (a subsequent page
//! exists). Non-saturated terminal pages omit the header — clients
//! treat its absence as "end of enumeration".
//!
//! # This document names nothing it will not serve (ADR 0062)
//!
//! `tags/list` is a document **hort builds**, so the enforcement shape
//! for it is omission: a tag whose target manifest carries a terminal
//! status — or binds anything that does — is simply not listed. Before
//! this the list applied no status filter of any kind, so it named a tag
//! the client's next `GET …/manifests/<tag>` then refused, and nothing
//! withdraws a tag when its target goes terminal (`RefUseCase::retire`
//! has only explicit-client-delete callers).
//!
//! Unlike the referrers index, this handler loads no artifact, so
//! **both** halves of the question — the target's own status and its
//! closure — come from the census,
//! `ListDeliverabilityUseCase::non_deliverable_in`, in one call for the
//! page. A tag whose target is merely held or not yet ingested stays
//! listed; a hold is "not yet" and absence is the ordinary state of a
//! cold pull-through. A tag whose `RefTarget` is a **version string**
//! rather than a content hash is not an OCI manifest pointer at all, so
//! it is left alone rather than guessed at.
//!
//! **The omission does not move the diagnosis**: asked for the same tag
//! directly, `GET /v2/<name>/manifests/<tag>` still answers with its
//! verdict and axis (ADR 0055). The list omits, the direct ask explains.
//!
//! ## The cursor comes from the unfiltered page
//!
//! Pagination happens before the filter, so the `Link` cursor is the
//! **page's** last ref name, not the last surviving tag's. The
//! difference is not cosmetic: a page whose last tag is omitted would
//! otherwise advertise an earlier tag as the cursor and the next page
//! would re-serve everything between, and a page whose tags are *all*
//! omitted would carry no cursor at all and silently truncate the
//! client's enumeration at that point. With the page's own boundary as
//! the cursor, a client walks the same sequence of pages it always did
//! and simply sees fewer names in some of them. `saturated` is likewise
//! the page's, so an entirely-omitted page still links to its successor.

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use urlencoding::encode as urlencode;

use hort_app::error::AppError;
use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::mutable_ref::RefTarget;
use hort_domain::error::DomainError;
use hort_domain::types::ContentHash;

use hort_http_core::context::AppContext;

/// Query parameters for tags list + catalog endpoints. Both surfaces
/// use the same shape (`?n=<limit>&last=<cursor>`), so the struct is
/// shared via `super::` in `catalog.rs` and via the pull dispatcher
/// in `mod.rs`. Missing fields deserialize to `None` (axum's `Query`
/// extractor tolerates absent query strings when every field is
/// `Option<_>`).
#[derive(Debug, Deserialize, Default, Clone)]
pub struct PageQuery {
    /// Per-page limit. `None` or `0` falls through to the use-case
    /// default (100). Clamped to `[1, 1000]` by the use case.
    #[serde(default)]
    pub n: Option<u32>,
    /// Cursor — the last `ref_name` (or qualified group name) from
    /// the previous page. Pagination returns `> last` under byte
    /// ordering.
    #[serde(default)]
    pub last: Option<String>,
}

pub async fn serve(
    ctx: Arc<AppContext>,
    repo_key: &str,
    name: &str,
    query: PageQuery,
    actor: Option<&CallerPrincipal>,
) -> Response {
    // Visibility-checked repo resolve (ADR 0008). Missing or
    // invisible-to-actor private repo collapse to NAME_UNKNOWN
    // (anti-enumeration). The use case enforces Read on the repo
    // before the path lookup, closing anonymous read on private repos.
    let repo = match ctx
        .repository_access_use_case
        .resolve(repo_key, actor, AccessLevel::Read)
        .await
    {
        Ok(r) => r,
        Err(AppError::Domain(DomainError::NotFound { .. })) => {
            // Repo-level read denial: 401 + mode-aware challenge for an
            // anonymous caller, NAME_UNKNOWN 404 anti-enumeration for an
            // authenticated one (D1/D2, ADR 0021).
            let path = format!("/v2/{repo_key}/{name}/tags/list");
            return crate::middleware::oci_auth::read_denied_response(
                &ctx,
                actor,
                &axum::http::Method::GET,
                &path,
                repo_key,
            );
        }
        Err(e) => {
            tracing::error!(
                repo_key = %repo_key,
                error = %e,
                "repo lookup failed during OCI tags list"
            );
            return internal_error_response();
        }
    };

    let n = query.n.unwrap_or(0);
    let after = query.last.as_deref();

    let page = match ctx.ref_use_case.list(repo.id, name, after, n).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(
                repo_key = %repo_key,
                namespace = %name,
                error = %e,
                "ref list failed"
            );
            return internal_error_response();
        }
    };

    // The page's own boundary, captured before the ADR 0062 filter
    // below removes anything: the cursor is where the *enumeration*
    // reached, not where the surviving list ends. See the module doc.
    let page_cursor = page.items.last().map(|r| r.ref_name.clone());

    // Both halves of the deliverability question in one census call —
    // this handler loads no artifact, so unlike the referrers index it
    // gets no own-status half for free. A version-targeted ref is not an
    // OCI manifest pointer and is not a candidate.
    let candidates: Vec<ContentHash> = page
        .items
        .iter()
        .filter_map(|r| match &r.target {
            RefTarget::ContentHash(hash) => Some(hash.clone()),
            RefTarget::Version(_) => None,
        })
        .collect();
    let withheld: HashSet<ContentHash> = if candidates.is_empty() {
        // Nothing to ask about. Not merely an optimisation: the port
        // contract is that an empty candidate set never reaches the
        // database.
        HashSet::new()
    } else {
        match ctx
            .list_deliverability_use_case
            .non_deliverable_in(repo.id, &candidates)
            .await
        {
            Ok(set) => set,
            Err(e) => {
                tracing::error!(
                    repo_key = %repo_key,
                    namespace = %name,
                    candidate_count = candidates.len(),
                    error = %e,
                    "tags deliverability census failed; refusing to serve a list that may \
                     name what the pull would refuse"
                );
                return internal_error_response();
            }
        }
    };

    let tags: Vec<String> = page
        .items
        .iter()
        .filter(|r| match &r.target {
            RefTarget::ContentHash(hash) => !withheld.contains(hash),
            // Not an OCI manifest pointer; the census was never asked
            // about it and this handler does not guess.
            RefTarget::Version(_) => true,
        })
        .map(|r| r.ref_name.clone())
        .collect();
    let body_value = serde_json::json!({
        "name": name,
        "tags": tags,
    });
    let body_bytes = serde_json::to_vec(&body_value).expect("static-shape JSON serialises");

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json");

    if page.saturated {
        if let Some(last_tag) = page_cursor.as_deref() {
            let link = format_next_link(repo_key, name, n, last_tag);
            // `Link` header values are ASCII; construction cannot
            // fail unless the inputs contain a CR/LF — which
            // `format_next_link`'s urlencode defence prevents.
            if let Ok(v) = HeaderValue::from_str(&link) {
                builder = builder.header("Link", v);
            }
        }
    }

    builder.body(Body::from(body_bytes)).unwrap()
}

/// Build the OCI spec Link header value for the next page of tags.
///
/// `last` is URL-encoded so tag names with `+`, `%`, or `/` don't break the Link syntax.
fn format_next_link(repo_key: &str, name: &str, n: u32, last: &str) -> String {
    let last_enc = urlencode(last);
    // `n = 0` is the "unspecified" shape upstream; preserve the same
    // shape on the `next` link so the client walks with the server's
    // default limit unless they originally passed `?n=`.
    if n == 0 {
        format!("</v2/{repo_key}/{name}/tags/list?last={last_enc}>; rel=\"next\"")
    } else {
        format!("</v2/{repo_key}/{name}/tags/list?n={n}&last={last_enc}>; rel=\"next\"")
    }
}

fn internal_error_response() -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"errors":[{"code":"UNSUPPORTED","message":"internal error","detail":null}]}"#,
        ))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------- format_next_link ----------------

    #[test]
    fn link_format_with_n() {
        let l = format_next_link("myrepo", "library/nginx", 10, "v1.0");
        assert_eq!(
            l,
            "</v2/myrepo/library/nginx/tags/list?n=10&last=v1.0>; rel=\"next\""
        );
    }

    #[test]
    fn link_format_without_n_omits_n_param() {
        let l = format_next_link("myrepo", "library/nginx", 0, "v1.0");
        assert_eq!(
            l,
            "</v2/myrepo/library/nginx/tags/list?last=v1.0>; rel=\"next\""
        );
    }

    #[test]
    fn link_format_url_encodes_last() {
        // `+` and `/` in tag names must percent-encode. Otherwise the
        // Link header wouldn't round-trip through the client's
        // query-string parser.
        let l = format_next_link("myrepo", "nginx", 10, "v1.0+build");
        assert!(l.contains("last=v1.0%2Bbuild"), "unexpected encoding: {l}");
    }

    // ---------------- Handler-level ----------------
    //
    // The happy-path / saturated-Link-header / router-level tests live
    // alongside the dispatcher in `lib.rs::tests` (they drive the
    // `/v2/:repo_key/*tail` route end-to-end via `oneshot`). The
    // read-denial representation (D1/D2) is exercised here by calling
    // `serve` directly with an explicit `actor`.

    use metrics_exporter_prometheus::PrometheusBuilder;

    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_http_core::test_support::build_mock_ctx;

    fn run<F, T>(f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn oci_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Oci;
        r
    }

    // ------- ADR 0062 — the list omits what the pull would refuse -------

    use chrono::Utc;
    use hort_app::use_cases::test_support::{
        persisted_artifact_rejected, sample_artifact, MockContentReferenceIndex,
        MockRefRegistryPort,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::mutable_ref::MutableRef;
    use hort_domain::events::{RejectionReason, StreamId};
    use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
    use hort_http_core::test_support::MockPorts;
    use uuid::Uuid;

    const NAMESPACE: &str = "library/nginx";

    /// A distinct synthetic sha256 per `seed` byte.
    fn hash_of(seed: u8) -> ContentHash {
        format!("{seed:02x}")
            .repeat(32)
            .parse()
            .expect("synthetic sha256")
    }

    /// Seed an OCI manifest artifact at `hash_of(seed)` carrying
    /// `status`, reachable by the manifest route's own coords path, and
    /// optionally an `ArtifactRejected` on its stream so the rejection
    /// axis is recoverable the way production recovers it (the
    /// `artifacts` projection carries no such column).
    fn seed_manifest_artifact(
        mocks: &MockPorts,
        repo_id: Uuid,
        seed: u8,
        status: QuarantineStatus,
        axis: Option<RejectionReason>,
    ) -> (Uuid, ContentHash) {
        let hash = hash_of(seed);
        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = repo_id;
        a.path = format!("manifests/sha256:{}", hash.as_ref());
        a.sha256_checksum = hash.clone();
        a.quarantine_status = status;
        if matches!(status, QuarantineStatus::Quarantined) {
            a.quarantine_window_start = Some(Utc::now());
        }
        let id = a.id;
        mocks.artifacts.insert(a);
        if let Some(reason) = axis {
            mocks.events.set_stream(
                &StreamId::artifact(id),
                vec![persisted_artifact_rejected(id, reason, 1)],
            );
        }
        (id, hash)
    }

    /// A blob constituent: a catalog row and nothing else. The census
    /// reads no bytes, so storing content would hide a dependency on it.
    /// The optional axis is seeded on the blob's own stream, which is
    /// where the direct ask recovers it from.
    fn seed_blob(
        mocks: &MockPorts,
        repo_id: Uuid,
        seed: u8,
        status: QuarantineStatus,
        axis: Option<RejectionReason>,
    ) -> ContentHash {
        let hash = hash_of(seed);
        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = repo_id;
        a.path = format!("blobs/sha256:{}", hash.as_ref());
        a.sha256_checksum = hash.clone();
        a.quarantine_status = status;
        if matches!(status, QuarantineStatus::Quarantined) {
            a.quarantine_window_start = Some(Utc::now());
        }
        let id = a.id;
        mocks.artifacts.insert(a);
        if let Some(reason) = axis {
            mocks.events.set_stream(
                &StreamId::artifact(id),
                vec![persisted_artifact_rejected(id, reason, 1)],
            );
        }
        hash
    }

    async fn seed_closure_edge(
        content_references: &MockContentReferenceIndex,
        repo_id: Uuid,
        source: Uuid,
        kind: &str,
        target: &ContentHash,
    ) {
        content_references
            .insert(ContentReference {
                source_artifact_id: source,
                target_content_hash: target.clone(),
                kind: kind.to_string(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo_id,
                recorded_at: Utc::now(),
            })
            .await
            .expect("seed membership edge");
    }

    fn seed_ref(refs: &MockRefRegistryPort, repo_id: Uuid, tag: &str, target: RefTarget) {
        refs.insert(MutableRef {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            namespace: NAMESPACE.to_string(),
            ref_name: tag.to_string(),
            target,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
    }

    /// Serve `tags/list` and return `(status, tags, Link header)`.
    async fn tags_list(
        ctx: Arc<AppContext>,
        query: PageQuery,
    ) -> (StatusCode, Vec<String>, Option<String>) {
        let resp = serve(ctx, "myrepo", NAMESPACE, query, None).await;
        let status = resp.status();
        let link = resp
            .headers()
            .get("Link")
            .map(|v| v.to_str().expect("ascii Link header").to_string());
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("the tags body is small")
            .to_vec();
        if status != StatusCode::OK {
            return (status, Vec::new(), link);
        }
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("the tags body is JSON");
        let tags = parsed["tags"]
            .as_array()
            .expect("the envelope carries a tags array")
            .iter()
            .map(|v| v.as_str().expect("tag names are strings").to_string())
            .collect();
        (status, tags, link)
    }

    /// Ask the **manifest** route for `reference` directly and return
    /// `(status, parsed body)`. ADR 0055 keeps the diagnosis on the
    /// direct request, so what the list omits the direct ask must still
    /// explain.
    async fn direct_manifest_ask(
        ctx: Arc<AppContext>,
        reference: &str,
    ) -> (StatusCode, serde_json::Value) {
        let resp = crate::manifests::serve(
            ctx,
            "myrepo",
            NAMESPACE,
            reference,
            &axum::http::HeaderMap::new(),
            /* head = */ false,
            /* anonymous */ None,
        )
        .await;
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("the refusal body is small")
            .to_vec();
        let parsed: serde_json::Value = serde_json::from_slice(&body)
            .unwrap_or_else(|e| panic!("expected a JSON envelope, got {e}"));
        (status, parsed)
    }

    /// A tag whose target manifest is **itself** terminal is not listed —
    /// and asked for by name, it still answers `403 DENIED` with its
    /// axis.
    ///
    /// Both halves in one test on purpose: the list omits and the direct
    /// ask explains, and that split is what keeps ADR 0055 intact while
    /// ADR 0062's omission rule holds.
    #[test]
    fn a_tag_over_a_terminal_manifest_is_omitted_and_403_with_the_axis_when_named() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);
            let (_id, hash) = seed_manifest_artifact(
                &mocks,
                repo_id,
                0x11,
                QuarantineStatus::Rejected,
                Some(RejectionReason::Scanner),
            );
            seed_ref(
                &mocks.refs,
                repo_id,
                "blocked",
                RefTarget::ContentHash(hash),
            );
            let (_clean_id, clean) =
                seed_manifest_artifact(&mocks, repo_id, 0x12, QuarantineStatus::Released, None);
            seed_ref(&mocks.refs, repo_id, "good", RefTarget::ContentHash(clean));
            let ctx = hort_http_core::test_support::with_provenance_hold_hydration(&base);

            let (status, tags, _link) = tags_list(ctx.clone(), PageQuery::default()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                tags,
                vec!["good".to_string()],
                "a tag over a terminally rejected manifest must not be advertised"
            );

            let (status, parsed) = direct_manifest_ask(ctx, "blocked").await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "the direct ask keeps its verdict: {parsed}"
            );
            assert_eq!(parsed["errors"][0]["code"], "DENIED");
            assert_eq!(
                parsed["errors"][0]["detail"]["axis"], "scanner",
                "the omission must not take the axis with it: {parsed}"
            );
        });
    }

    /// The case a cheap own-status-only filter misses, and therefore the
    /// one that proves the closure half works: the target manifest's own
    /// row is clean and the layer it binds is terminal.
    #[test]
    fn a_tag_over_a_terminal_constituent_is_omitted_and_the_direct_ask_names_the_constituent() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);
            let (manifest_id, hash) =
                seed_manifest_artifact(&mocks, repo_id, 0x21, QuarantineStatus::Released, None);
            seed_ref(
                &mocks.refs,
                repo_id,
                "latest",
                RefTarget::ContentHash(hash.clone()),
            );
            let layer = seed_blob(
                &mocks,
                repo_id,
                0x22,
                QuarantineStatus::Rejected,
                Some(RejectionReason::Scanner),
            );
            seed_closure_edge(
                &mocks.content_references,
                repo_id,
                manifest_id,
                "oci_layer",
                &layer,
            )
            .await;
            // The direct ask derives the same closure from the bytes, so
            // the manifest's CAS body has to name the layer.
            mocks.storage.insert_content(
                hash.clone(),
                serde_json::json!({
                    "schemaVersion": 2,
                    "config": { "digest": format!("sha256:{}", hash_of(0x29).as_ref()), "size": 2 },
                    "layers": [{ "digest": format!("sha256:{}", layer.as_ref()), "size": 2 }],
                })
                .to_string()
                .into_bytes(),
            );
            let ctx = hort_http_core::test_support::with_provenance_hold_hydration(&base);

            let (status, tags, _link) = tags_list(ctx.clone(), PageQuery::default()).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                tags.is_empty(),
                "a tag whose target binds a terminal layer must not be advertised: {tags:?}"
            );

            let (status, parsed) = direct_manifest_ask(ctx, "latest").await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "the direct ask keeps its verdict: {parsed}"
            );
            assert_eq!(
                parsed["errors"][0]["detail"]["subject"],
                format!("sha256:{}", layer.as_ref()),
                "the direct refusal names the offending constituent, not the tag: {parsed}"
            );
            assert_eq!(parsed["errors"][0]["detail"]["axis"], "scanner");
        });
    }

    /// A tag whose target is merely **not ingested** stays listed.
    /// Absence is the ordinary state of a cold pull-through, not a
    /// verdict, and the inversion that treats it as terminal empties
    /// `tags/list` for every proxied repository.
    #[test]
    fn a_tag_over_a_not_ingested_target_stays_listed() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);
            // No artifact row at all — a tag a pull-through projected
            // from upstream before the manifest arrived.
            seed_ref(
                &mocks.refs,
                repo_id,
                "cold",
                RefTarget::ContentHash(hash_of(0x31)),
            );
            // Present, clean, and over a constituent that is likewise
            // not ingested.
            let (manifest_id, hash) =
                seed_manifest_artifact(&mocks, repo_id, 0x32, QuarantineStatus::Released, None);
            seed_ref(&mocks.refs, repo_id, "warm", RefTarget::ContentHash(hash));
            seed_closure_edge(
                &mocks.content_references,
                repo_id,
                manifest_id,
                "oci_layer",
                &hash_of(0x33),
            )
            .await;

            let (status, tags, _link) = tags_list(base, PageQuery::default()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                tags,
                vec!["cold".to_string(), "warm".to_string()],
                "a not-yet-ingested target is not a verdict"
            );
        });
    }

    /// A `Quarantined` target stays listed: a hold means "not yet", the
    /// manifest route's own `503` is that answer, and ADR 0062 decision 3
    /// leaves the per-child model standing for holds. Asserted on both
    /// halves — the target itself and a constituent.
    #[test]
    fn a_held_target_and_a_held_constituent_both_stay_listed() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);
            let (_held_id, held) =
                seed_manifest_artifact(&mocks, repo_id, 0x41, QuarantineStatus::Quarantined, None);
            seed_ref(&mocks.refs, repo_id, "held", RefTarget::ContentHash(held));
            let (over_held_id, over_held) =
                seed_manifest_artifact(&mocks, repo_id, 0x42, QuarantineStatus::Released, None);
            seed_ref(
                &mocks.refs,
                repo_id,
                "over-held",
                RefTarget::ContentHash(over_held),
            );
            let held_layer = seed_blob(&mocks, repo_id, 0x43, QuarantineStatus::Quarantined, None);
            seed_closure_edge(
                &mocks.content_references,
                repo_id,
                over_held_id,
                "oci_layer",
                &held_layer,
            )
            .await;

            let (status, tags, _link) = tags_list(base, PageQuery::default()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                tags,
                vec!["held".to_string(), "over-held".to_string()],
                "neither a held target nor a held constituent withdraws a tag"
            );
        });
    }

    /// A ref whose target is a **version string** is not an OCI manifest
    /// pointer. It is never a census candidate and it is never omitted —
    /// guessing at what it means is the alternative this rejects.
    #[test]
    fn a_version_targeted_ref_is_never_a_candidate() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);
            // A version string that happens to be a valid sha256 hex, so
            // the test fails if the handler reads the target by its
            // *text* rather than by its variant.
            let rejected = seed_blob(&mocks, repo_id, 0x51, QuarantineStatus::Rejected, None);
            seed_ref(
                &mocks.refs,
                repo_id,
                "versioned",
                RefTarget::Version(rejected.as_ref().to_string()),
            );

            let (status, tags, _link) = tags_list(base.clone(), PageQuery::default()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(tags, vec!["versioned".to_string()]);
            assert_eq!(
                mocks.list_deliverability.calls(),
                0,
                "a page with no hash-targeted ref must not reach the census at all"
            );
        });
    }

    /// One census call for the page, carrying exactly the hash-targeted
    /// refs — never one call per tag.
    #[test]
    fn the_census_is_asked_once_for_the_hash_targeted_refs() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);
            let mut expected = Vec::new();
            for (tag, seed) in [("a", 0x61_u8), ("b", 0x62), ("c", 0x63)] {
                let (_id, hash) =
                    seed_manifest_artifact(&mocks, repo_id, seed, QuarantineStatus::Released, None);
                seed_ref(
                    &mocks.refs,
                    repo_id,
                    tag,
                    RefTarget::ContentHash(hash.clone()),
                );
                expected.push(hash);
            }
            seed_ref(
                &mocks.refs,
                repo_id,
                "d",
                RefTarget::Version("1.0.0".to_string()),
            );

            let (status, tags, _link) = tags_list(base, PageQuery::default()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(tags.len(), 4);
            assert_eq!(
                mocks.list_deliverability.calls(),
                1,
                "one census for the whole page — a per-tag fan-out would put a round trip \
                 on every name a client resolves against"
            );
            assert_eq!(
                mocks.list_deliverability.last_candidates(),
                expected,
                "the ask carries the page's hash-targeted refs in page order, and nothing else"
            );
        });
    }

    /// The cursor is the **page's** last ref name, not the last
    /// surviving tag's.
    ///
    /// Two failure modes this pins, and neither is cosmetic: with the
    /// cursor taken from the filtered list, a page whose last tag is
    /// omitted advertises an earlier tag and the next page re-serves
    /// everything between it and the boundary; and a page whose tags are
    /// *all* omitted carries no cursor at all, so the client's
    /// enumeration stops there and never sees the pages behind it.
    #[test]
    fn the_cursor_is_the_pages_boundary_not_the_last_surviving_tag() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);
            // Four tags, byte-ordered a < b < c < d. `b` is terminal, so
            // a page of two ends on an omitted tag.
            for (tag, seed, status) in [
                ("a", 0x71_u8, QuarantineStatus::Released),
                ("b", 0x72, QuarantineStatus::Rejected),
                ("c", 0x73, QuarantineStatus::Rejected),
                ("d", 0x74, QuarantineStatus::Released),
            ] {
                let (_id, hash) = seed_manifest_artifact(&mocks, repo_id, seed, status, None);
                seed_ref(&mocks.refs, repo_id, tag, RefTarget::ContentHash(hash));
            }

            let (status, tags, link) = tags_list(
                base.clone(),
                PageQuery {
                    n: Some(2),
                    last: None,
                },
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(tags, vec!["a".to_string()], "b is omitted");
            assert_eq!(
                link.as_deref(),
                Some("</v2/myrepo/library/nginx/tags/list?n=2&last=b>; rel=\"next\""),
                "the cursor must be the page's boundary `b`, not the surviving `a` — \
                 otherwise the next page re-serves b"
            );

            // The second page is entirely omitted: empty tags, and a
            // cursor that still carries the walk forward.
            let (status, tags, link) = tags_list(
                base.clone(),
                PageQuery {
                    n: Some(1),
                    last: Some("b".to_string()),
                },
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(tags.is_empty(), "c is omitted, leaving the page empty");
            assert_eq!(
                link.as_deref(),
                Some("</v2/myrepo/library/nginx/tags/list?n=1&last=c>; rel=\"next\""),
                "an entirely-omitted page must still link to its successor, or the client's \
                 enumeration silently stops before `d`"
            );

            // Following that cursor reaches `d` — the walk is complete.
            let (status, tags, link) = tags_list(
                base,
                PageQuery {
                    n: Some(1),
                    last: Some("c".to_string()),
                },
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(tags, vec!["d".to_string()]);
            assert_eq!(link, None, "the terminal page carries no Link header");
        });
    }

    /// A census failure refuses the whole list. Not knowing what the list
    /// would refuse is not the same as knowing it would refuse nothing
    /// (ADR 0007), and serving the unfiltered list is the posture ADR
    /// 0062 replaced.
    #[test]
    fn a_census_failure_refuses_the_list() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);
            let (_id, hash) =
                seed_manifest_artifact(&mocks, repo_id, 0x81, QuarantineStatus::Released, None);
            seed_ref(&mocks.refs, repo_id, "latest", RefTarget::ContentHash(hash));
            mocks
                .list_deliverability
                .fail_next(DomainError::Invariant("census exploded".into()));

            let (status, _tags, _link) = tags_list(base, PageQuery::default()).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        });
    }

    /// Repo-level read denial (D1/D2, ADR 0021): an anonymous tags-list on
    /// a denied repo is challenged with 401 + the mode-aware
    /// `WWW-Authenticate` in BOTH signing-key states; an
    /// authenticated-but-unauthorized caller keeps the `NAME_UNKNOWN` 404
    /// anti-enumeration envelope.
    #[test]
    fn tags_read_denial_challenges_anonymous_and_404s_authenticated() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            // (1) anonymous, signing key UNWIRED → 401 Basic.
            crate::test_authz::assert_basic_challenge(
                &serve(
                    crate::test_authz::denied_ctx(&base, mocks.repositories.clone()),
                    "ghost",
                    "library/nginx",
                    PageQuery::default(),
                    None,
                )
                .await,
            );
            // (2) anonymous, signing key WIRED → 401 Bearer /v2/auth.
            crate::test_authz::assert_bearer_challenge(
                &serve(
                    crate::test_authz::denied_ctx_bearer(&base, mocks.repositories.clone()),
                    "ghost",
                    "library/nginx",
                    PageQuery::default(),
                    None,
                )
                .await,
                r#"scope="repository:ghost/library/nginx:pull""#,
            );
            // (3) authenticated but unauthorized → 404 NAME_UNKNOWN.
            let principal = crate::test_authz::grantless_principal();
            crate::test_authz::assert_name_unknown_404(
                serve(
                    crate::test_authz::denied_ctx(&base, mocks.repositories.clone()),
                    "ghost",
                    "library/nginx",
                    PageQuery::default(),
                    Some(&principal),
                )
                .await,
            )
            .await;
        });
    }

    /// Anti-enumeration equivalence (ADR 0021): anonymous denial for a
    /// NONEXISTENT repo is byte-identical to one for an EXISTING PRIVATE
    /// repo (Basic mode → no `scope=`).
    #[test]
    fn tags_anonymous_denial_uniform_nonexistent_vs_private() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, mocks) = build_mock_ctx(handle);
            let mut priv_repo = oci_repo("private-repo");
            priv_repo.is_public = false;
            mocks.repositories.insert(priv_repo);
            let ctx = crate::test_authz::denied_ctx(&base, mocks.repositories.clone());
            let nonexistent = serve(
                ctx.clone(),
                "ghost",
                "library/nginx",
                PageQuery::default(),
                None,
            )
            .await;
            let private = serve(
                ctx,
                "private-repo",
                "library/nginx",
                PageQuery::default(),
                None,
            )
            .await;
            assert_eq!(
                crate::test_authz::denial_snapshot(nonexistent).await,
                crate::test_authz::denial_snapshot(private).await,
                "anonymous nonexistent vs existing-private must be byte-identical"
            );
        });
    }
}
