//! `POST /api/v1/admin/curation/waive-versions` and
//! `POST /api/v1/admin/curation/waive-digests`.
//!
//! Bulk curator release, addressed by what was reviewed: a version list
//! for the formats where `artifacts.version` is populated and immutable,
//! a digest list for OCI and everything else content-addressed. Both
//! wrap [`CurationUseCase::waive_bulk`](hort_app::use_cases::curation_use_case::CurationUseCase::waive_bulk);
//! the per-artifact `…/quarantine/{artifact_id}/waive` route is
//! unchanged and remains the one-off.
//!
//! **One module, two routes, because they differ only in how an entry
//! names its row.** The outcome DTO, the boundary checks and the
//! status-code mapping are one implementation; a second copy of them is
//! how the two addressing modes would start answering differently.
//!
//! ## All-or-nothing, not continue-on-error
//!
//! This is the fail-open half of curation and its contract is the
//! inverse of `block-versions`'. One entry that is unresolvable,
//! ambiguous, or in a state a bulk waive does not reach aborts the whole
//! batch: **`409 Conflict` carrying the full per-entry report, and zero
//! releases applied.** That is not a missing kindness — `ArtifactReleased`
//! is history that cannot be retracted, so releasing the resolvable
//! subset of a list the curator wrote wrongly is the defect this contract
//! exists to prevent.
//!
//! The report names **every** entry, the fine ones included, so a curator
//! who asked for five releases and got none can see which entry stopped
//! the batch without bisecting their list.
//!
//! Status-code mapping:
//! - `200 OK` with [`WaiveOutcomeDto`] — every entry pre-validated. The
//!   body partitions the call into `released_artifact_ids`,
//!   `already_released_ids` and `failed`; a non-empty `failed` is still
//!   `200`, because those entries are per-artifact apply failures inside
//!   an otherwise-valid batch and the envelope is how the operator learns
//!   which
//! - `400 Bad Request` — empty / oversize justification; `versions` /
//!   `digests` empty or over the 25-entry cap; a digest that is not a
//!   bare 64-hex SHA-256 or a `sha256:`-prefixed one
//! - `403 Forbidden` — principal lacks both Curate and Admin
//! - `404 Not Found` — the `repository` key does not resolve
//! - `409 Conflict` with [`WaiveAbortDto`] — pre-validation aborted the
//!   batch (ADR 0025). Nothing was released
//! - `500 Internal Server Error` — infrastructure failure

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::use_cases::curation_use_case::{
    WaiveApplied, WaiveEntryReport, WaiveEntryVerdict, WaiveOutcome, WaiveTarget,
};
use hort_domain::events::ApiActor;

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

use super::block_versions::FailedBlockEntryDto;
use super::{
    check_entry_count, check_justification, curator_privileges, MAX_WAIVE_ENTRIES_PER_CALL,
};

/// Request DTO for `POST /api/v1/admin/curation/waive-versions`.
///
/// `repository` is the operator-facing **stable key**; the handler
/// resolves it to a UUID via `RepositoryUseCase::get_by_key` and a miss
/// is a 404. `package` and `versions` are matched against `artifacts`
/// rows exactly as `block-versions` matches them — one resolver, so the
/// two verbs cannot disagree about which row a version names.
#[derive(Debug, Deserialize)]
pub struct WaiveVersionsRequestDto {
    repository: String,
    package: String,
    versions: Vec<String>,
    justification: String,
}

/// Request DTO for `POST /api/v1/admin/curation/waive-digests`.
///
/// Each entry of `digests` is a bare 64-lowercase-hex SHA-256 or the
/// same value carrying a `sha256:` prefix; the two spellings are one
/// address and resolve identically. Any other algorithm prefix is a
/// `400` rather than a silent strip — hort addresses content by SHA-256
/// (ADR 0003), so a `sha512:` digest cannot match a stored row, and
/// dropping its prefix would answer "not found" to a request that was
/// simply written wrongly.
///
/// There is **no `tags` field and there will not be one.** A tag is a
/// mutable pointer; a curation decision binds to the bytes that were
/// reviewed. The curation queue renders tags as an annotation so a
/// curator can recognise a row, never as the key they decide with.
#[derive(Debug, Deserialize)]
pub struct WaiveDigestsRequestDto {
    repository: String,
    digests: Vec<String>,
    justification: String,
}

/// HTTP-layer mirror of [`WaiveApplied`] — the body of a `200`.
///
/// `failed` reuses [`FailedBlockEntryDto`], which is the same
/// `(artifact_id, AppError)` projection with the same sanitisation
/// contract: a per-entry apply failure is the same wire shape whichever
/// verb produced it, and a second copy of that `AppError` match is a
/// second place for an un-sanitised variant to appear.
#[derive(Debug, Serialize)]
pub(crate) struct WaiveOutcomeDto {
    /// Shared by every `ArtifactReleased` this call emitted.
    pub correlation_id: Uuid,
    /// Artifacts released on this call — one `ArtifactReleased` each.
    pub released_artifact_ids: Vec<Uuid>,
    /// Artifacts already `Released`: idempotent successes with no event.
    /// Distinct from `released_artifact_ids` on purpose — an operator
    /// must not read a converged re-apply as a release that just
    /// happened.
    pub already_released_ids: Vec<Uuid>,
    /// Per-artifact apply failures inside an otherwise-valid batch.
    pub failed: Vec<FailedBlockEntryDto>,
}

impl WaiveOutcomeDto {
    fn from_domain(applied: WaiveApplied) -> Self {
        Self {
            correlation_id: applied.correlation_id,
            released_artifact_ids: applied.released_artifact_ids,
            already_released_ids: applied.already_released_ids,
            failed: applied
                .failed
                .iter()
                .map(|(id, e)| FailedBlockEntryDto::from_app_error(*id, e))
                .collect(),
        }
    }
}

/// The body of a `409` — the full per-entry pre-validation report.
///
/// `released_artifact_ids` is deliberately absent rather than empty:
/// there is no partial-application half of this answer to describe, and
/// an empty list beside a report would invite a client to treat the two
/// bodies as one shape with some fields missing.
#[derive(Debug, Serialize)]
pub(crate) struct WaiveAbortDto {
    /// Fixed discriminator, so a client can branch on the body as well as
    /// on the status code.
    pub outcome: &'static str,
    /// Every entry of the request, in the order it was written.
    pub entries: Vec<WaiveEntryReportDto>,
}

/// One entry of the pre-validation report.
#[derive(Debug, Serialize)]
pub(crate) struct WaiveEntryReportDto {
    /// The addressing key verbatim as the caller supplied it, so the
    /// report line matches the decision file that produced it.
    pub key: String,
    /// The resolved row, when resolution produced exactly one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<Uuid>,
    /// Stable verdict discriminator: `releasable`, `already_released`,
    /// `unresolvable`, `ambiguous`, `state_not_releasable`.
    pub verdict: &'static str,
    /// For `ambiguous`: every live artifact id carrying these bytes.
    /// This is the field the curator re-addresses the decision with, and
    /// the reason the refusal is worth more than a 404 would be.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidate_artifact_ids: Vec<Uuid>,
    /// For `state_not_releasable`: the state the row is actually in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

impl WaiveEntryReportDto {
    fn from_domain(entry: WaiveEntryReport) -> Self {
        let verdict = entry.verdict.wire_kind();
        let (candidate_artifact_ids, status) = match entry.verdict {
            WaiveEntryVerdict::Ambiguous(ids) => (ids, None),
            WaiveEntryVerdict::StateNotReleasable(status) => (Vec::new(), Some(status.to_string())),
            WaiveEntryVerdict::Releasable
            | WaiveEntryVerdict::AlreadyReleased
            | WaiveEntryVerdict::Unresolvable => (Vec::new(), None),
        };
        Self {
            key: entry.key,
            artifact_id: entry.artifact_id,
            verdict,
            candidate_artifact_ids,
            status,
        }
    }
}

/// Map a [`WaiveOutcome`] onto the wire — the one place the
/// all-or-nothing contract becomes a status code.
fn outcome_response(outcome: WaiveOutcome) -> Response {
    match outcome {
        WaiveOutcome::Applied(applied) => {
            (StatusCode::OK, Json(WaiveOutcomeDto::from_domain(applied))).into_response()
        }
        // ADR 0025 — a state precondition the caller can see and act on.
        // The report is the body, not a message: the curator needs the
        // per-entry verdicts and, for an ambiguous digest, the candidate
        // ids.
        WaiveOutcome::Aborted { entries } => (
            StatusCode::CONFLICT,
            Json(WaiveAbortDto {
                outcome: "aborted",
                entries: entries
                    .into_iter()
                    .map(WaiveEntryReportDto::from_domain)
                    .collect(),
            }),
        )
            .into_response(),
    }
}

/// `POST /api/v1/admin/curation/waive-versions`. See module docs.
#[tracing::instrument(skip(ctx, principal, body))]
pub async fn post_waive_versions(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<WaiveVersionsRequestDto>,
) -> Result<Response, ApiError> {
    // Boundary checks fire BEFORE the repository-key resolution so a
    // malformed body never spends a DB round-trip. The use case re-checks
    // every one of them — these are defence in depth, not the gate.
    check_justification(&body.justification)?;
    check_entry_count("versions", body.versions.len(), MAX_WAIVE_ENTRIES_PER_CALL)?;

    let repository_id = ctx
        .repository_use_case
        .get_by_key(&body.repository)
        .await?
        .id;

    let outcome = ctx
        .curation_use_case
        .waive_bulk(
            WaiveTarget::VersionList {
                repository_id,
                package: body.package,
                versions: body.versions,
            },
            ApiActor {
                user_id: principal.0.user_id,
            },
            curator_privileges(),
            body.justification,
        )
        .await?;

    Ok(outcome_response(outcome))
}

/// `POST /api/v1/admin/curation/waive-digests`. See module docs.
#[tracing::instrument(skip(ctx, principal, body))]
pub async fn post_waive_digests(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<WaiveDigestsRequestDto>,
) -> Result<Response, ApiError> {
    check_justification(&body.justification)?;
    check_entry_count("digests", body.digests.len(), MAX_WAIVE_ENTRIES_PER_CALL)?;

    let repository_id = ctx
        .repository_use_case
        .get_by_key(&body.repository)
        .await?
        .id;

    let outcome = ctx
        .curation_use_case
        .waive_bulk(
            WaiveTarget::DigestList {
                repository_id,
                digests: body.digests,
            },
            ApiActor {
                user_id: principal.0.user_id,
            },
            curator_privileges(),
            body.justification,
        )
        .await?;

    Ok(outcome_response(outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::Router;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, MockIdentityProvider,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::events::StreamId;
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;

    use crate::context::AuthContext;
    use crate::test_support::{build_mock_ctx, with_auth, MockPorts};

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const REPO_KEY: &str = "curate-target";

    fn curate_claim_grant() -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["curate".into()]),
            repository_id: None,
            permission: Permission::Curate,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

    fn principal_with_claims(claims: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "curator".into(),
            email: "curator@example.com".into(),
            claims: claims.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    /// Mounts the real curation sub-router, so the tests exercise the
    /// routes at the paths `curation_routes()` actually registers rather
    /// than at paths only the test knows about.
    fn harness() -> (Router, MockPorts) {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (base, mocks) = build_mock_ctx(metrics);
        let idp = Arc::new(MockIdentityProvider::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            mocks.users.clone() as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let rbac = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(vec![
            curate_claim_grant(),
        ])));
        let ctx = with_auth(
            &base,
            AuthContext::Enabled {
                authenticate,
                rbac,
                issuer_url: None,
            },
        );
        let router = Router::new()
            .nest("/api/v1/admin/curation", super::super::curation_routes())
            .with_state(ctx);
        (router, mocks)
    }

    fn post_json(path: &str, body: &str, p: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        if let Some(p) = p {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn seed_repo(mocks: &MockPorts) -> Uuid {
        let mut repo = sample_repository();
        repo.key = REPO_KEY.into();
        let repo_id = repo.id;
        mocks.repositories.insert(repo);
        repo_id
    }

    /// Seed an artifact carrying `digest` at `path`, with a one-event
    /// stream so the apply step's optimistic pairing resolves.
    fn seed_digest(
        mocks: &MockPorts,
        repo_id: Uuid,
        digest: &str,
        path: &str,
        status: QuarantineStatus,
    ) -> Uuid {
        let mut a = sample_artifact(status);
        a.repository_id = repo_id;
        a.sha256_checksum = digest.parse().expect("64 lowercase hex");
        a.path = path.into();
        a.version = None;
        let id = a.id;
        let stream_id = StreamId::artifact(id);
        mocks.events.set_stream(
            &stream_id,
            vec![hort_app::use_cases::test_support::dummy_persisted_event(
                &stream_id, id, 0,
            )],
        );
        mocks.artifacts.insert(a);
        id
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Happy path at the real route path: 200, the envelope, and the
    /// released/already-released lists kept distinguishable.
    #[tokio::test]
    async fn waive_digests_happy_path_returns_200_with_the_envelope() {
        let (router, mocks) = harness();
        let repo_id = seed_repo(&mocks);
        let released = seed_digest(
            &mocks,
            repo_id,
            DIGEST_A,
            "blobs/a",
            QuarantineStatus::Quarantined,
        );
        let converged = seed_digest(
            &mocks,
            repo_id,
            DIGEST_B,
            "blobs/b",
            QuarantineStatus::Released,
        );

        let body = format!(
            r#"{{"repository":"{REPO_KEY}","digests":["sha256:{DIGEST_A}","{DIGEST_B}"],"justification":"reviewed against the publisher page"}}"#
        );
        let resp = router
            .oneshot(post_json(
                "/api/v1/admin/curation/waive-digests",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let v = body_json(resp).await;
        assert!(v["correlation_id"].is_string());
        assert_eq!(v["released_artifact_ids"][0], released.to_string());
        assert_eq!(v["already_released_ids"][0], converged.to_string());
        assert!(v["failed"].as_array().unwrap().is_empty());
    }

    /// One bad entry: 409, the per-entry report, zero releases. Both
    /// entries are named, and the ambiguous case carries the candidate
    /// ids the curator re-addresses with.
    #[tokio::test]
    async fn waive_digests_aborted_batch_returns_409_with_the_report() {
        let (router, mocks) = harness();
        let repo_id = seed_repo(&mocks);
        seed_digest(
            &mocks,
            repo_id,
            DIGEST_A,
            "blobs/a",
            QuarantineStatus::Quarantined,
        );
        let twin_one = seed_digest(
            &mocks,
            repo_id,
            DIGEST_B,
            "blobs/b1",
            QuarantineStatus::Quarantined,
        );
        let twin_two = seed_digest(
            &mocks,
            repo_id,
            DIGEST_B,
            "blobs/b2",
            QuarantineStatus::Quarantined,
        );

        let body = format!(
            r#"{{"repository":"{REPO_KEY}","digests":["{DIGEST_A}","{DIGEST_B}"],"justification":"valid"}}"#
        );
        let resp = router
            .oneshot(post_json(
                "/api/v1/admin/curation/waive-digests",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "a state-precondition abort is 409 (ADR 0025), not 200-with-an-empty-list"
        );

        let v = body_json(resp).await;
        assert_eq!(v["outcome"], "aborted");
        let entries = v["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2, "every entry is reported");
        assert_eq!(entries[0]["verdict"], "releasable");
        assert_eq!(entries[1]["verdict"], "ambiguous");
        let candidates: Vec<String> = entries[1]["candidate_artifact_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(candidates.contains(&twin_one.to_string()));
        assert!(candidates.contains(&twin_two.to_string()));
        assert!(
            mocks.lifecycle.committed_transitions().is_empty(),
            "zero events on an aborted batch"
        );
        assert!(
            v.get("released_artifact_ids").is_none(),
            "there is no partial-application half of a 409 to describe"
        );
    }

    /// The `state_not_releasable` verdict renders the state the row is
    /// actually in — the curator has to be able to tell a terminal
    /// rejection from an unresolvable digest.
    #[tokio::test]
    async fn waive_digests_report_names_the_state_that_blocked_the_entry() {
        let (router, mocks) = harness();
        let repo_id = seed_repo(&mocks);
        seed_digest(
            &mocks,
            repo_id,
            DIGEST_A,
            "blobs/a",
            QuarantineStatus::Rejected,
        );
        let body = format!(
            r#"{{"repository":"{REPO_KEY}","digests":["{DIGEST_A}","{DIGEST_B}"],"justification":"valid"}}"#
        );
        let resp = router
            .oneshot(post_json(
                "/api/v1/admin/curation/waive-digests",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let v = body_json(resp).await;
        assert_eq!(v["entries"][0]["verdict"], "state_not_releasable");
        assert_eq!(v["entries"][0]["status"], "rejected");
        assert_eq!(v["entries"][1]["verdict"], "unresolvable");
        assert!(
            v["entries"][1].get("artifact_id").is_none(),
            "an unresolvable entry names no row"
        );
    }

    /// The 25-entry cap is enforced at the handler, before the
    /// repository-key resolution and before the use case is reached.
    #[tokio::test]
    async fn waive_digests_over_the_cap_returns_400_at_the_handler() {
        let (router, mocks) = harness();
        seed_repo(&mocks);
        let digests: Vec<String> = (0..=MAX_WAIVE_ENTRIES_PER_CALL)
            .map(|n| format!("\"{n:064x}\""))
            .collect();
        let body = format!(
            r#"{{"repository":"{REPO_KEY}","digests":[{}],"justification":"valid"}}"#,
            digests.join(",")
        );
        let resp = router
            .oneshot(post_json(
                "/api/v1/admin/curation/waive-digests",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_json(resp).await;
        assert!(
            v["error"].as_str().unwrap().contains("exceeds 25 cap"),
            "got: {v}"
        );
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// 26 digests are refused here while the same list is inside the
    /// bulk-block cap — the asymmetry, asserted across the two routes.
    #[tokio::test]
    async fn the_same_list_is_over_the_waive_cap_and_under_the_block_cap() {
        let (router, mocks) = harness();
        seed_repo(&mocks);
        let digests: Vec<String> = (0..26).map(|n| format!("\"{n:064x}\"")).collect();
        let body = format!(
            r#"{{"repository":"{REPO_KEY}","digests":[{}],"justification":"valid"}}"#,
            digests.join(",")
        );
        let waive = router
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/curation/waive-digests",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(waive.status(), StatusCode::BAD_REQUEST);

        let block = router
            .oneshot(post_json(
                "/api/v1/admin/curation/block-digests",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(
            block.status(),
            StatusCode::OK,
            "the fail-safe verb accepts the list the fail-open one refuses"
        );
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// An empty list, and each justification failure, at the handler
    /// boundary.
    #[tokio::test]
    async fn waive_digests_boundary_failures_return_400() {
        let (router, mocks) = harness();
        seed_repo(&mocks);
        let oversize = "x".repeat(513);
        for body in [
            format!(r#"{{"repository":"{REPO_KEY}","digests":[],"justification":"valid"}}"#),
            format!(r#"{{"repository":"{REPO_KEY}","digests":["{DIGEST_A}"],"justification":""}}"#),
            format!(
                r#"{{"repository":"{REPO_KEY}","digests":["{DIGEST_A}"],"justification":"   \n "}}"#
            ),
            format!(
                r#"{{"repository":"{REPO_KEY}","digests":["{DIGEST_A}"],"justification":"{oversize}"}}"#
            ),
        ] {
            let resp = router
                .clone()
                .oneshot(post_json(
                    "/api/v1/admin/curation/waive-digests",
                    &body,
                    Some(principal_with_claims(&["curate"])),
                ))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "boundary failure must not reach the use case: {body}"
            );
        }
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// A wrong algorithm prefix is a 400 from the use case's own
    /// normaliser, and the message does not echo the algorithm back.
    #[tokio::test]
    async fn waive_digests_wrong_algorithm_prefix_returns_400() {
        let (router, mocks) = harness();
        seed_repo(&mocks);
        let body = format!(
            r#"{{"repository":"{REPO_KEY}","digests":["sha512:{}"],"justification":"valid"}}"#,
            "a".repeat(128)
        );
        let resp = router
            .oneshot(post_json(
                "/api/v1/admin/curation/waive-digests",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_json(resp).await;
        let message = v["error"].as_str().unwrap();
        assert!(message.contains("entry 0"), "got: {message}");
        assert!(!message.contains("sha512"), "got: {message}");
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// Unknown repository key → 404; unprivileged caller → 403.
    #[tokio::test]
    async fn waive_digests_unknown_repository_404_and_unprivileged_403() {
        let (router, mocks) = harness();
        seed_repo(&mocks);
        let body = format!(
            r#"{{"repository":"no-such-repo","digests":["{DIGEST_A}"],"justification":"valid"}}"#
        );
        let resp = router
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/curation/waive-digests",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = format!(
            r#"{{"repository":"{REPO_KEY}","digests":["{DIGEST_A}"],"justification":"valid"}}"#
        );
        let resp = router
            .oneshot(post_json(
                "/api/v1/admin/curation/waive-digests",
                &body,
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// The version-addressed route is mounted and carries the same
    /// contract: a resolvable list applies, an unresolvable entry is a
    /// 409 report.
    #[tokio::test]
    async fn waive_versions_applies_and_aborts_at_its_own_route() {
        let (router, mocks) = harness();
        let repo_id = seed_repo(&mocks);
        let mut a = sample_artifact(QuarantineStatus::Quarantined);
        a.repository_id = repo_id;
        a.name = "left-pad".into();
        a.version = Some("1.3.0".into());
        let id = a.id;
        let stream_id = StreamId::artifact(id);
        mocks.events.set_stream(
            &stream_id,
            vec![hort_app::use_cases::test_support::dummy_persisted_event(
                &stream_id, id, 0,
            )],
        );
        mocks.artifacts.insert(a);

        let body = format!(
            r#"{{"repository":"{REPO_KEY}","package":"left-pad","versions":["1.3.0","9.9.9"],"justification":"valid"}}"#
        );
        let resp = router
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/curation/waive-versions",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let v = body_json(resp).await;
        assert_eq!(v["entries"][1]["verdict"], "unresolvable");
        assert!(mocks.lifecycle.committed_transitions().is_empty());

        let body = format!(
            r#"{{"repository":"{REPO_KEY}","package":"left-pad","versions":["1.3.0"],"justification":"valid"}}"#
        );
        let resp = router
            .oneshot(post_json(
                "/api/v1/admin/curation/waive-versions",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["released_artifact_ids"][0], id.to_string());
        assert_eq!(mocks.lifecycle.committed_transitions().len(), 1);
    }

    /// `waive-versions` enforces the same 25-entry cap and the same
    /// justification gate at its own boundary.
    #[tokio::test]
    async fn waive_versions_boundary_failures_return_400() {
        let (router, mocks) = harness();
        seed_repo(&mocks);
        let versions: Vec<String> = (0..=MAX_WAIVE_ENTRIES_PER_CALL)
            .map(|n| format!("\"{n}.0.0\""))
            .collect();
        for body in [
            format!(
                r#"{{"repository":"{REPO_KEY}","package":"p","versions":[{}],"justification":"v"}}"#,
                versions.join(",")
            ),
            format!(
                r#"{{"repository":"{REPO_KEY}","package":"p","versions":[],"justification":"v"}}"#
            ),
            format!(
                r#"{{"repository":"{REPO_KEY}","package":"p","versions":["1.0.0"],"justification":""}}"#
            ),
        ] {
            let resp = router
                .clone()
                .oneshot(post_json(
                    "/api/v1/admin/curation/waive-versions",
                    &body,
                    Some(principal_with_claims(&["curate"])),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "for body {body}");
        }
        assert!(mocks.lifecycle.committed_transitions().is_empty());
    }

    /// No addressing path on either route accepts a tag: a
    /// tag-shaped field is ignored by the request DTO, which carries no
    /// such field, and the request is decided on its digests alone.
    #[tokio::test]
    async fn a_tag_shaped_field_is_not_an_addressing_key() {
        let (router, mocks) = harness();
        let repo_id = seed_repo(&mocks);
        let id = seed_digest(
            &mocks,
            repo_id,
            DIGEST_A,
            "blobs/a",
            QuarantineStatus::Quarantined,
        );
        let body = format!(
            r#"{{"repository":"{REPO_KEY}","digests":["{DIGEST_A}"],"tags":["latest"],"tag":"latest","justification":"valid"}}"#
        );
        let resp = router
            .oneshot(post_json(
                "/api/v1/admin/curation/waive-digests",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(
            v["released_artifact_ids"][0],
            id.to_string(),
            "the decision was addressed by the bytes, not by the tag"
        );
    }

    /// The per-entry report DTO, verdict by verdict — the one place the
    /// domain verdicts become wire discriminators, so every arm is
    /// pinned here rather than only through a route that happens to
    /// produce it.
    #[test]
    fn every_entry_verdict_has_a_wire_projection() {
        let id = Uuid::new_v4();
        let twins = vec![Uuid::new_v4(), Uuid::new_v4()];
        let cases = vec![
            (
                WaiveEntryReport {
                    key: "k".into(),
                    artifact_id: Some(id),
                    verdict: WaiveEntryVerdict::Releasable,
                },
                "releasable",
            ),
            (
                WaiveEntryReport {
                    key: "k".into(),
                    artifact_id: Some(id),
                    verdict: WaiveEntryVerdict::AlreadyReleased,
                },
                "already_released",
            ),
            (
                WaiveEntryReport {
                    key: "k".into(),
                    artifact_id: None,
                    verdict: WaiveEntryVerdict::Unresolvable,
                },
                "unresolvable",
            ),
            (
                WaiveEntryReport {
                    key: "k".into(),
                    artifact_id: None,
                    verdict: WaiveEntryVerdict::Ambiguous(twins.clone()),
                },
                "ambiguous",
            ),
            (
                WaiveEntryReport {
                    key: "k".into(),
                    artifact_id: Some(id),
                    verdict: WaiveEntryVerdict::StateNotReleasable(
                        QuarantineStatus::ScanIndeterminate,
                    ),
                },
                "state_not_releasable",
            ),
        ];
        for (entry, expected) in cases {
            let dto = WaiveEntryReportDto::from_domain(entry);
            assert_eq!(dto.verdict, expected);
            let json = serde_json::to_value(&dto).unwrap();
            assert_eq!(json["key"], "k");
            match expected {
                "ambiguous" => {
                    assert_eq!(json["candidate_artifact_ids"].as_array().unwrap().len(), 2);
                    assert!(json.get("status").is_none());
                }
                "state_not_releasable" => {
                    assert_eq!(json["status"], "scan_indeterminate");
                    assert!(json.get("candidate_artifact_ids").is_none());
                }
                _ => {
                    assert!(json.get("candidate_artifact_ids").is_none());
                    assert!(json.get("status").is_none());
                }
            }
        }
    }

    /// A per-entry apply failure reuses the block envelope's sanitised
    /// projection, so the two bulk verbs cannot diverge on what an error
    /// reveals.
    #[test]
    fn an_apply_failure_renders_through_the_shared_sanitised_projection() {
        let dto = WaiveOutcomeDto::from_domain(WaiveApplied {
            correlation_id: Uuid::new_v4(),
            released_artifact_ids: Vec::new(),
            already_released_ids: Vec::new(),
            failed: vec![(
                Uuid::new_v4(),
                hort_app::error::AppError::External("postgres://internal".into()),
            )],
        });
        assert_eq!(dto.failed[0].error_kind, "external");
        assert_eq!(dto.failed[0].message, "upstream unavailable");
    }
}
