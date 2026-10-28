//! HTTP write surface for scan-policy
//! exclusions.
//!
//! Two endpoints, both gated by [`CurateOrAdminPrincipal`]:
//!
//! - `POST   /api/v1/admin/policies/:policy_id/exclusions`
//!   ([`post_exclusion`])
//! - `DELETE /api/v1/admin/policies/:policy_id/exclusions/:cve_id`
//!   ([`delete_exclusion`])
//!
//! Both delegate to the existing
//! `PolicyUseCase::{add_exclusion, remove_exclusion}` methods. The
//! use-case signature is `(cmd, actor: Actor)` and contains NO
//! permission check — the gitops apply pipeline continues to call the
//! same methods with `Actor::Gitops`. The HTTP layer is the single
//! permission source of truth for the user-driven surface (see module
//! docs in the parent `mod.rs`).
//!
//! ## DELETE `:cve_id` resolution
//!
//! The URL carries `:cve_id` (e.g. `CVE-2026-0001`). The use case
//! takes an `exclusion_id` (UUID) — the
//! curator-facing identifier is the CVE, the internal projection-key
//! is the exclusion_id. The handler resolves CVE → exclusion_id by
//! reading `policy_projections.list_exclusions_for_policy(policy_id)`
//! and matching `cve_id`. A missing match surfaces as 404 BEFORE the
//! use case is touched; this also closes the otherwise-confusing
//! `Validation(policy not exist)` 400 (from the use case) that would
//! fire if a caller URL-encoded a stale policy id.
//!
//! A CVE can name **several** exclusions on one policy — the rows
//! differ only in `package_pattern` — so that resolution is one-to-many
//! and the row's identity is its `exclusion_id`, not its CVE. With more
//! than one match the request must say which row it means, via the
//! optional `exclusion_id` in [`RemoveExclusionRequestDto`]; without it
//! the handler answers `409` and lists the candidates as members of the
//! body (`exclusion_id` + `package_pattern` each), because the caller
//! resolves the ambiguity by repeating the request with one of those
//! ids. Resolving it here instead — taking the first match — would end
//! a suppression the operator did not choose to end and leave the
//! others unreachable through this route.
//!
//! The body's `exclusion_id` selects **within** the path's CVE. An id
//! that names a row under a different CVE on the same policy is a
//! `400`: the path stays the authority on which CVE is being withdrawn,
//! and the body never overrides it silently.
//!
//! ## Repository scope is refused on the way in, not on the way out
//!
//! A `scope` naming a repository cannot be **written**.
//! `hort_domain::policy::SCOPE_NOT_ENFORCED` is the rationale: the
//! finding filter never reads the scope, so such an exclusion clears
//! its CVE for every repository the parent policy governs rather than
//! the one it names. The refusal lives in
//! `PolicyUseCase::add_exclusion` — the application-layer write seam
//! every inbound writer (this handler, the gitops apply pipeline)
//! passes through, so the rule cannot be bypassed by a future caller.
//! Surfaces here as `400`.
//!
//! **Removing** such a row is not refused, by this handler or by
//! `PolicyUseCase::remove_exclusion`. The two directions are not
//! symmetric: creating one records an assurance nothing honours,
//! removing it withdraws that assurance. A removal only ever stops
//! suppressing a finding — it releases nothing, so there is no
//! fail-closed reading under which refusing it is the safe choice. It
//! would also be a control the neighbour lifts: the same use-case
//! method is the gitops applier's removal path and stays open, so
//! refusing here would leave only the operator without a declared tree
//! stuck with a row that keeps clearing its CVE globally. What the
//! operator does need is the removal's real reach, which the handler
//! writes to the log (`policy_id`, `cve_id`, the stored
//! `repository_id`, and the rationale verbatim).
//!
//! Only a row written before the add-side refusal shipped can carry
//! such a scope; nothing rewrites those rows.
//!
//! Status-code mapping:
//! - **POST** — `201 Created` with `{ "exclusion_id": "<uuid>" }` on
//!   success; `400` (validation — empty reason / oversize / bad
//!   cve_id format / policy id mis-parsed / repository-scoped request);
//!   `403` (extractor); `404`
//!   (policy not found — note: the use case currently emits this as
//!   `Validation` so it would surface as 400; the handler runs a
//!   `policy_projections.find_by_id` pre-check that promotes the
//!   missing-policy case to 404 BEFORE the use case is touched);
//!   `409` (event-store conflict); `500` (infrastructure)
//! - **DELETE** — `204 No Content` on success; `400` / `403` / `404`
//!   / `409` / `500` (same shape), where the `400`s also cover an
//!   `exclusion_id` that names no row under the path's CVE, and the
//!   `409`s also cover an unqualified request whose CVE names several
//!   rows (body: `cve_id` + `candidates[]`). A *stored* repository
//!   scope is not among the `400`s — see above.
//!
//! **`#[tracing::instrument]` deliberately WITHOUT `err`** — denial
//! and validation outcomes are info-level events (architect rule);
//! promoting them to `err` would surface every 4xx as ERROR in
//! operator logs. Mirrors the curation decision handlers.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::{AddExclusionCommand, RemoveExclusionCommand};
use hort_domain::entities::scan_policy::ExclusionProjection;
use hort_domain::error::{DomainError, ExclusionCandidate};
use hort_domain::events::{Actor, ApiActor, PolicyScope};

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

use super::MAX_JUSTIFICATION_BYTES;

// ---------------------------------------------------------------------------
// Wire-format DTOs
// ---------------------------------------------------------------------------

/// Wire-format `scope` discriminator for [`AddExclusionRequestDto`].
///
/// Maps onto the domain [`PolicyScope`] via `ScopeDto::into_domain`.
/// Defined as a handler-local DTO because the domain type's default
/// serde shape leaks the Rust enum representation
/// (`{"Repository":"<uuid>"}` etc.) — the stable wire surface uses a
/// tagged-union shape:
///
/// ```json
/// { "kind": "global" }
/// { "kind": "repository", "repository_id": "<uuid>" }
/// ```
///
/// Mirrors the `scope` projection in handlers/admin/curation/exclusions.rs
/// (`CurationExclusionEntryDto`), so the read and write surfaces are
/// byte-symmetric.
///
/// The `Repository` arm stays on the wire — the read surface renders it
/// for rows stored before the add-side refusal, and dropping the arm
/// would turn an operator's repository-scoped request into an
/// unexplained deserialisation failure instead of the refusal that
/// names what is missing. Writing such a scope is refused: see
/// [`hort_domain::policy::SCOPE_NOT_ENFORCED`].
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeDto {
    Global,
    Repository { repository_id: Uuid },
}

impl ScopeDto {
    fn into_domain(self) -> PolicyScope {
        match self {
            ScopeDto::Global => PolicyScope::Global,
            ScopeDto::Repository { repository_id } => PolicyScope::Repository(repository_id),
        }
    }
}

/// Request body for `POST /api/v1/admin/policies/:policy_id/exclusions`.
///
/// Domain types (`AddExclusionCommand`, `PolicyScope`) are NEVER
/// deserialised directly from request input (architect anti-pattern A
/// — DTO discipline). This struct carries only primitive types and
/// the [`ScopeDto`] wire-shape; the handler maps it into
/// [`AddExclusionCommand`] inside its body.
///
/// `reason` is the operator-supplied justification recorded on
/// `ExclusionAdded.reason`. MUST be non-empty and ≤ 512 bytes — the
/// handler enforces both gates before the use-case call.
#[derive(Debug, Deserialize)]
pub struct AddExclusionRequestDto {
    pub cve_id: String,
    #[serde(default)]
    pub package_pattern: Option<String>,
    pub scope: ScopeDto,
    pub reason: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Response body for `POST /api/v1/admin/policies/:policy_id/exclusions`.
///
/// The exclusion_id is server-minted (see `PolicyUseCase::add_exclusion`
/// — `Uuid::new_v4()` inside the use case) and returned so the caller
/// can reference it on a follow-up DELETE if the projection-side CVE
/// lookup is undesirable.
#[derive(Debug, Serialize)]
pub struct AddExclusionResponseDto {
    pub exclusion_id: Uuid,
}

/// Optional request body for
/// `DELETE /api/v1/admin/policies/:policy_id/exclusions/:cve_id`.
///
/// The DELETE is RESTfully body-optional; an absent body is treated
/// the same as `{ "reason": "" }` (which is then rejected as empty by
/// the same handler gate that catches an empty POST reason). The
/// reason rides the emitted `ExclusionRemoved.reason` payload — the
/// curator's audit anchor for the removal.
#[derive(Debug, Deserialize, Default)]
pub struct RemoveExclusionRequestDto {
    #[serde(default)]
    pub reason: String,
    /// Which exclusion to remove, when the path's CVE names more than
    /// one of them on this policy. Optional: a CVE that names exactly
    /// one exclusion needs no disambiguator, so every body that worked
    /// before this field existed still works.
    ///
    /// It selects **within** the path's CVE and never replaces it — an
    /// id that is not among that CVE's rows is refused rather than
    /// obeyed, so the path stays the authority on which CVE is being
    /// withdrawn. The value is the one `POST` returned
    /// ([`AddExclusionResponseDto::exclusion_id`]).
    #[serde(default)]
    pub exclusion_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/admin/policies/:policy_id/exclusions`.
///
/// Validates the request body at the boundary, constructs an
/// [`AddExclusionCommand`] from the DTO + path parameter, builds the
/// [`Actor::Api`] from the validated principal, and delegates to
/// `PolicyUseCase::add_exclusion`. The use case mints the
/// `exclusion_id` server-side; the response body carries it back so
/// the caller doesn't need a follow-up GET to learn the value.
///
/// See module docs for the full status-code map.
#[tracing::instrument(skip(ctx, principal, body))]
pub async fn post_exclusion(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path(policy_id): Path<Uuid>,
    Json(body): Json<AddExclusionRequestDto>,
) -> Result<Response, ApiError> {
    // Justification cap — 512-byte, same as the curation decision endpoints. The
    // domain `ExclusionAdded::validate` enforces a wider 4096-byte
    // cap on the underlying `reason`; this handler tightens the HTTP
    // bound to 512 to match every other curator-facing justification
    // field. Trim + empty check first so whitespace-only input is the
    // same UX failure as missing.
    let trimmed_reason = body.reason.trim();
    if trimmed_reason.is_empty() {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            "reason must not be empty".into(),
        ))));
    }
    if body.reason.len() > MAX_JUSTIFICATION_BYTES {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!(
                "reason exceeds {MAX_JUSTIFICATION_BYTES} bytes (got {})",
                body.reason.len()
            ),
        ))));
    }

    // Pre-check policy existence so the response surface is 404 (not
    // the use case's 400-via-Validation) for an unknown policy. This
    // is the same shape the curation read endpoints use for unknown
    // entities; matches operator expectations of REST semantics.
    let projection = ctx.policy_projections.find_by_id(policy_id).await?;
    if projection.is_none() {
        return Err(ApiError(AppError::Domain(DomainError::NotFound {
            entity: "ScanPolicy",
            id: policy_id.to_string(),
        })));
    }

    let cmd = AddExclusionCommand {
        policy_id,
        cve_id: body.cve_id,
        package_pattern: body.package_pattern,
        scope: body.scope.into_domain(),
        reason: body.reason,
        expires_at: body.expires_at,
    };

    let actor = Actor::Api(ApiActor {
        user_id: principal.0.user_id,
    });

    let exclusion_id = ctx.policy_use_case.add_exclusion(cmd, actor).await?;

    Ok((
        StatusCode::CREATED,
        Json(AddExclusionResponseDto { exclusion_id }),
    )
        .into_response())
}

/// `DELETE /api/v1/admin/policies/:policy_id/exclusions/:cve_id`.
///
/// Resolves the CVE → exclusion_id by reading the policy's exclusion
/// projection, then delegates to `PolicyUseCase::remove_exclusion`.
/// A missing CVE surfaces as 404 BEFORE the use case is touched (so
/// the use-case's policy-existence guard is reached only when a
/// matching exclusion's `policy_id` lookup confirms the policy
/// exists).
///
/// A CVE that names several of the policy's exclusions is answered with
/// a 409 carrying the candidates, unless the body's optional
/// `exclusion_id` says which row to remove — the row's identity, not
/// its CVE, is what the removal acts on.
///
/// A *stored* repository scope does not block the removal — it is
/// logged, not refused (see the module docs for why the add side and
/// the removal side are deliberately asymmetric).
///
/// See module docs for the full status-code map.
#[tracing::instrument(skip(ctx, principal, body))]
pub async fn delete_exclusion(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Path((policy_id, cve_id)): Path<(Uuid, String)>,
    body: Option<Json<RemoveExclusionRequestDto>>,
) -> Result<Response, ApiError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let trimmed_reason = body.reason.trim();
    if trimmed_reason.is_empty() {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            "reason must not be empty".into(),
        ))));
    }
    if body.reason.len() > MAX_JUSTIFICATION_BYTES {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!(
                "reason exceeds {MAX_JUSTIFICATION_BYTES} bytes (got {})",
                body.reason.len()
            ),
        ))));
    }

    // Bounded CVE identifier — defence-in-depth so a pathological URL
    // doesn't bloat downstream logs / projection scans. Mirrors the
    // domain-layer `MAX_CVE_ID_LEN = 64` constant on
    // `ExclusionAdded::validate`. We don't try to parse CVE-XXXX-YYYY
    // structurally — operators sometimes use vendor advisory IDs that
    // don't match the canonical shape.
    if cve_id.is_empty() || cve_id.len() > 64 {
        return Err(ApiError(AppError::Domain(DomainError::Validation(
            format!("invalid cve_id length: {}", cve_id.len()),
        ))));
    }

    // Resolve the CVE to the rows that carry it. The projection port's
    // contract is `list_exclusions_for_policy` returns ONLY rows for
    // `policy_id`, so the linear scan here is bounded by the number of
    // exclusions on the policy (typically single digits in typical
    // deployments).
    let exclusions = ctx
        .policy_projections
        .list_exclusions_for_policy(policy_id)
        .await?;
    let matches: Vec<ExclusionProjection> = exclusions
        .into_iter()
        .filter(|e| e.cve_id == cve_id)
        .collect();

    // A CVE names a *set* of exclusions, not one: a policy may hold one
    // row per `package_pattern` for the same CVE. The row's identity is
    // its `exclusion_id`, which is what `RemoveExclusionCommand` takes
    // and what the POST hands back — so when the CVE names several rows
    // the request has to say which, and the handler reports the
    // ambiguity instead of letting the projection's ordering decide. The
    // alternative is worse than a wrong answer: picking the first match
    // ends a suppression the operator did not choose to end AND leaves
    // the remaining rows unreachable through this route, so a
    // suppression outlives the decision to withdraw it.
    let found = match (body.exclusion_id, matches.as_slice()) {
        // No row carries that CVE on this policy. The path target does
        // not exist, whether or not the body named a row — an optional
        // disambiguator that only narrows within the CVE must not change
        // the answer for a CVE that is not there.
        (_, []) => {
            return Err(ApiError(AppError::Domain(DomainError::NotFound {
                entity: "Exclusion",
                id: format!("policy={policy_id} cve={cve_id}"),
            })));
        }
        // The body names the row: selection happens within the CVE the
        // path names, so an id that belongs to another of the policy's
        // CVEs is refused. Obeying it would make the body a second,
        // silently-winning way to say which row dies.
        (Some(requested), rows) => {
            let Some(found) = rows.iter().find(|e| e.exclusion_id == requested) else {
                return Err(ApiError(AppError::Domain(DomainError::Validation(
                    format!(
                        "exclusion_id {requested} is not an exclusion for {cve_id} on this policy"
                    ),
                ))));
            };
            found.clone()
        }
        // Exactly one row carries the CVE — nothing to disambiguate.
        (None, [single]) => single.clone(),
        // Several rows and nothing said which: answered, not guessed.
        // The candidates travel as data so the caller can repeat the
        // request naming one of them.
        (None, rows) => {
            return Err(ApiError(AppError::Domain(
                DomainError::AmbiguousExclusion {
                    cve_id,
                    candidates: rows
                        .iter()
                        .map(|e| ExclusionCandidate {
                            exclusion_id: e.exclusion_id,
                            package_pattern: e.package_pattern.clone(),
                        })
                        .collect(),
                },
            )));
        }
    };

    // A stored repository scope is reported, not refused. Writing one is
    // refused (`PolicyUseCase::add_exclusion`) because it records an
    // assurance the finding filter cannot honour; removing the row is
    // what withdraws that assurance, and a removal only ever stops
    // suppressing a finding. Refusing it would make such a row
    // unremovable through the API while the same use-case method keeps
    // draining it for the gitops applier — a control the neighbour lifts,
    // paid for only by the operator without a declared tree.
    //
    // The removal's reach is still not the one the row advertises: the
    // scope never narrowed anything, so the exclusion was live for every
    // repository the parent policy governs and the removal re-rejects
    // artifacts across all of them, not just the one named. That is real
    // information about what is about to happen, so it goes to the log
    // with the same rationale every other surface states.
    if let PolicyScope::Repository(repo_id) = &found.scope {
        tracing::info!(
            policy_id = %policy_id,
            cve_id = %cve_id,
            repository_id = %repo_id,
            rationale = hort_domain::policy::SCOPE_NOT_ENFORCED,
            "delete_exclusion removing an exclusion that carries a repository scope: \
             its reach is every repository the parent policy governs, not the one the \
             scope names",
        );
    }

    let cmd = RemoveExclusionCommand {
        policy_id,
        exclusion_id: found.exclusion_id,
        reason: body.reason,
    };

    let actor = Actor::Api(ApiActor {
        user_id: principal.0.user_id,
    });

    ctx.policy_use_case.remove_exclusion(cmd, actor).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    //! Handler-layer assertions for each status code on both endpoints,
    //! plus a regression test pinning that a curator-driven POST calls
    //! the use case with the same shape an admin-driven POST would (the
    //! use-case-side re-evaluation cascade is itself exercised by
    //! `policy_use_case.rs::tests`; the HTTP wiring just must not drop
    //! attribution).
    //!
    //! All tests use [`build_mock_ctx`] (architect rule — no
    //! hand-rolled `AppContext`).

    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::Router;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::entities::scan_policy::{
        CompositeVerdictMode, NegligibleAction, ProvenanceMode, ScanEnforcement,
        ScanPolicyProjection, SeverityThreshold,
    };
    use hort_domain::policy::filter_excluded_findings;
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
    use hort_domain::ports::user_repository::UserRepository;
    use hort_domain::types::{ArtifactCoords, ComponentRelation, Finding, SeverityBasis};

    use crate::context::AuthContext;
    use crate::test_support::{build_mock_ctx, with_auth, MockPorts};

    // -----------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------

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
            .nest("/api/v1/admin/policies", super::super::policies_routes())
            .with_state(ctx);
        (router, mocks)
    }

    /// Seed a non-archived scan policy onto the mock projections so
    /// the handler's `find_by_id` pre-check + the use-case's
    /// `find_by_id` lookup both succeed. Returns the seeded policy id.
    fn seed_policy(mocks: &MockPorts) -> Uuid {
        let policy_id = Uuid::new_v4();
        let now = Utc::now();
        mocks.policy_projections.insert(ScanPolicyProjection {
            policy_id,
            name: format!("test-policy-{policy_id}"),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs: 0,
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".into()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            composite_verdict_mode: CompositeVerdictMode::Observed,
            stream_version: 0,
            created_at: now,
            updated_at: now,
        });
        policy_id
    }

    /// Seed an exclusion for the given policy → returns
    /// (exclusion_id, cve_id). Used by the DELETE tests.
    fn seed_exclusion(mocks: &MockPorts, policy_id: Uuid, cve: &str) -> (Uuid, String) {
        seed_exclusion_with_scope(mocks, policy_id, cve, PolicyScope::Global)
    }

    /// Seed an exclusion carrying `scope`. A `Repository` scope models a
    /// row stored before the refusal shipped — nothing writes one now.
    fn seed_exclusion_with_scope(
        mocks: &MockPorts,
        policy_id: Uuid,
        cve: &str,
        scope: PolicyScope,
    ) -> (Uuid, String) {
        let exclusion_id = Uuid::new_v4();
        mocks
            .policy_projections
            .insert_exclusion(ExclusionProjection {
                exclusion_id,
                policy_id,
                cve_id: cve.to_string(),
                package_pattern: None,
                scope,
                reason: "seeded".into(),
                added_by_actor_id: None,
                expires_at: None,
            });
        (exclusion_id, cve.to_string())
    }

    /// Seed an exclusion for `cve` carrying `package_pattern` — the one
    /// field that tells two rows for the same CVE apart, and so the one
    /// the ambiguity report has to carry. Returns its id.
    fn seed_exclusion_with_pattern(
        mocks: &MockPorts,
        policy_id: Uuid,
        cve: &str,
        package_pattern: &str,
    ) -> Uuid {
        let exclusion_id = Uuid::new_v4();
        mocks
            .policy_projections
            .insert_exclusion(ExclusionProjection {
                exclusion_id,
                policy_id,
                cve_id: cve.to_string(),
                package_pattern: Some(package_pattern.to_string()),
                scope: PolicyScope::Global,
                reason: "seeded".into(),
                added_by_actor_id: None,
                expires_at: None,
            });
        exclusion_id
    }

    /// The exclusion ids currently on the policy, in projection order.
    async fn remaining_exclusion_ids(mocks: &MockPorts, policy_id: Uuid) -> Vec<Uuid> {
        mocks
            .policy_projections
            .list_exclusions_for_policy(policy_id)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.exclusion_id)
            .collect()
    }

    /// One scan finding for `cve`, severity-assessed so nothing routes
    /// it onto the non-enforcing negligible lane. Feeds
    /// [`filter_excluded_findings`] in the end-to-end removal test.
    fn finding_for(cve: &str) -> Finding {
        Finding {
            purl: "pkg:npm/left-pad@1.0.0".into(),
            vulnerability_id: cve.to_string(),
            severity: SeverityThreshold::Critical,
            cvss_score: Some(9.8),
            title: "seeded for the exclusion filter".into(),
            fixed_versions: Vec::new(),
            source_scanner: "trivy".into(),
            references: Vec::new(),
            aliases: Vec::new(),
            informational_class: None,
            severity_basis: SeverityBasis::Assessed,
            component_relation: ComponentRelation::NotEstablished,
            statement: hort_domain::types::FindingStatement::Unstated,
            advisory_published_at: None,
        }
    }

    /// Coordinates for the artifact the filter is asked about. They
    /// carry no repository identity — which is exactly why a stored
    /// repository scope cannot narrow anything.
    fn any_coords() -> ArtifactCoords {
        ArtifactCoords {
            name: "left-pad".into(),
            name_as_published: "left-pad".into(),
            version: Some("1.0.0".into()),
            path: "left-pad/-/left-pad-1.0.0.tgz".into(),
            format: RepositoryFormat::Npm,
            metadata: serde_json::Value::Null,
        }
    }

    /// Drive a future to completion on a fresh current-thread runtime.
    /// `#[tracing_test::traced_test]` installs its subscriber for the
    /// scope of a sync test function, so a log-asserting test cannot be
    /// a `#[tokio::test]`. Mirrors `authz::extractors::tests`.
    fn run_async<F: std::future::Future<Output = T>, T>(f: F) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// The response body as a string — the refusal tests read the
    /// rationale out of it, because "a 400 happened" is not evidence the
    /// operator was told what is missing.
    async fn body_text(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// The response body parsed as JSON — the ambiguity tests read the
    /// candidates out of it as *members*, because a caller that has to
    /// parse an error sentence to recover a UUID has not been told
    /// anything it can act on.
    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).expect("response body must be JSON")
    }

    fn post_req(policy_id: Uuid, body: &str, p: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::post(format!("/api/v1/admin/policies/{policy_id}/exclusions"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        if let Some(p) = p {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn delete_req(
        policy_id: Uuid,
        cve: &str,
        body: &str,
        p: Option<CallerPrincipal>,
    ) -> Request<Body> {
        let mut req = Request::delete(format!(
            "/api/v1/admin/policies/{policy_id}/exclusions/{cve}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
        if let Some(p) = p {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    // -----------------------------------------------------------------
    // POST /api/v1/admin/policies/:policy_id/exclusions
    // -----------------------------------------------------------------

    /// Happy path: curator caller + valid body + seeded policy → 201
    /// CREATED with `{exclusion_id}` body. The use case mints a fresh
    /// UUID and the response surface carries it back.
    #[tokio::test]
    async fn post_exclusion_happy_path_returns_201_with_exclusion_id() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);

        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": "upstream advisory withdrawn"
        })
        .to_string();

        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = to_bytes(resp.into_body(), 4 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let returned = v["exclusion_id"]
            .as_str()
            .expect("exclusion_id must be present as a string");
        let returned = Uuid::parse_str(returned).expect("must parse as UUID");

        // Projection upsert confirms the use case ran with the
        // expected payload. The mock's `insert_exclusion` is also
        // exercised by the use-case-internal upsert.
        let upserts = mocks.policy_projections.exclusion_upserts();
        // The use case writes exactly one ExclusionProjection upsert
        // per add_exclusion call. We assert on the recorded upsert
        // because it's the cleanest signal the use case ran the full
        // happy path (event-store append + projection write).
        assert!(
            upserts.iter().any(|e| e.exclusion_id == returned
                && e.cve_id == "CVE-2026-1234"
                && e.reason == "upstream advisory withdrawn"),
            "expected upsert for newly-minted exclusion id, got: {upserts:?}",
        );
    }

    /// Admin caller (no Curate grant) also passes — confirms the
    /// either-OR gate semantics carry through to the POST surface.
    #[tokio::test]
    async fn post_exclusion_admin_caller_also_returns_201() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-9999",
            "scope": { "kind": "global" },
            "reason": "admin override"
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    /// Regression test — a curator-driven POST and an admin-driven POST
    /// produce the same use-case effect: one
    /// exclusion row appended to the projection, with the body's
    /// reason verbatim. The use-case-side re-evaluation cascade is
    /// exercised by `policy_use_case.rs::tests`; the HTTP wiring just
    /// must not drop attribution.
    ///
    /// Pins: (1) both paths reach the use case (no extractor
    /// short-circuit), (2) both produce one new projection row,
    /// (3) the row carries the reason text verbatim regardless of
    /// caller role.
    #[tokio::test]
    async fn curator_and_admin_drive_identical_use_case_call() {
        // Curator path
        let (router_c, mocks_c) = harness();
        let policy_c = seed_policy(&mocks_c);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-0001",
            "scope": { "kind": "global" },
            "reason": "re-eval cascade regression test"
        })
        .to_string();
        let resp = router_c
            .oneshot(post_req(
                policy_c,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let upserts_c = mocks_c.policy_projections.exclusion_upserts();
        assert_eq!(upserts_c.len(), 1);
        assert_eq!(upserts_c[0].cve_id, "CVE-2026-0001");
        assert_eq!(upserts_c[0].reason, "re-eval cascade regression test");

        // Admin path on a SEPARATE harness — same body, same outcome.
        let (router_a, mocks_a) = harness();
        let policy_a = seed_policy(&mocks_a);
        let resp = router_a
            .oneshot(post_req(
                policy_a,
                &body,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let upserts_a = mocks_a.policy_projections.exclusion_upserts();
        assert_eq!(upserts_a.len(), 1);
        // The HTTP wiring drops nothing: cve_id, reason, scope all
        // arrive at the use case verbatim regardless of caller role.
        assert_eq!(upserts_a[0].cve_id, upserts_c[0].cve_id);
        assert_eq!(upserts_a[0].reason, upserts_c[0].reason);
        assert_eq!(upserts_a[0].scope, upserts_c[0].scope);
    }

    /// Empty `reason` → 400.
    #[tokio::test]
    async fn post_exclusion_empty_reason_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": ""
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            mocks.policy_projections.exclusion_upserts().is_empty(),
            "validation must fire before the use case is called",
        );
    }

    /// Whitespace-only `reason` → 400 (same UX as empty).
    #[tokio::test]
    async fn post_exclusion_whitespace_reason_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": "   \n\t  "
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 513-byte `reason` → 400. One byte over the 512-byte cap.
    #[tokio::test]
    async fn post_exclusion_oversize_reason_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let oversize = "x".repeat(513);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": oversize
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Unauthorised caller (no curate, no admin) → 403 via the
    /// `CurateOrAdminPrincipal` extractor short-circuit; the use case
    /// is never reached. Body shape matches the extractor's 403 denial.
    #[tokio::test]
    async fn post_exclusion_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": "valid"
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], br#"{"error":"insufficient permissions"}"#);
        assert!(
            mocks.policy_projections.exclusion_upserts().is_empty(),
            "extractor short-circuit must not reach the use case",
        );
    }

    /// Unknown policy → 404. The handler's pre-check fires before the
    /// use case; the projection never grows.
    #[tokio::test]
    async fn post_exclusion_unknown_policy_returns_404() {
        let (router, mocks) = harness();
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "global" },
            "reason": "valid"
        })
        .to_string();
        let unknown = Uuid::new_v4();
        let resp = router
            .oneshot(post_req(
                unknown,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            mocks.policy_projections.exclusion_upserts().is_empty(),
            "404 pre-check must not reach the use case",
        );
    }

    /// Path UUID parse failure → 400 (axum's `Path<Uuid>` extractor
    /// surfaces this before the handler body runs). Pins the URI
    /// shape rather than the response body — axum's extractor
    /// formatting is the canonical surface.
    #[tokio::test]
    async fn post_exclusion_malformed_policy_id_returns_400() {
        let (router, _mocks) = harness();
        let mut req = Request::post("/api/v1/admin/policies/not-a-uuid/exclusions")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"cve_id":"CVE-2026-1234","scope":{"kind":"global"},"reason":"v"}"#,
            ))
            .unwrap();
        crate::middleware::auth::test_support::inject_principal(
            &mut req,
            principal_with_claims(&["curate"]),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 409 — wire-shape pin. The mock event store doesn't synthesise
    /// concurrent-append conflicts; the `ApiError::into_response`
    /// unit tests (`error.rs::tests::conflict_is_409`) are the
    /// canonical pin for the `Conflict → 409` mapping. We mirror the
    /// curation handler's approach: pin the boundary here so a
    /// future regression that changes the conflict mapping is loud.
    #[tokio::test]
    async fn post_exclusion_conflict_wire_shape_is_pinned_by_apierror() {
        let api_err = ApiError(AppError::Domain(DomainError::Conflict(
            "stream version mismatch".into(),
        )));
        let resp = api_err.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    /// 500 — wire-shape pin for infrastructure failures. Same
    /// rationale as the conflict pin above.
    #[tokio::test]
    async fn post_exclusion_repository_error_wire_shape_is_500() {
        let api_err = ApiError(AppError::Repository("db down".into()));
        let resp = api_err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Scope `kind: repository` still round-trips through the DTO
    /// mapping — and is then **refused** with the same rationale the
    /// gitops apply path states: the finding filter never reads the
    /// scope, so the waiver would clear its CVE for every repository the
    /// policy governs.
    ///
    /// The DTO arm is deliberately still there (the read surface renders
    /// it for rows stored before the refusal), so this test is what pins
    /// that accepting the shape does not mean accepting the write.
    #[tokio::test]
    async fn post_exclusion_repository_scope_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let repo_id = Uuid::new_v4();
        let body = serde_json::json!({
            "cve_id": "CVE-2026-1234",
            "scope": { "kind": "repository", "repository_id": repo_id },
            "reason": "valid"
        })
        .to_string();
        let resp = router
            .oneshot(post_req(
                policy_id,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_text(resp).await;
        assert!(
            body.contains("not enforced") && body.contains("never reads"),
            "the refusal must carry the apply path's rationale: {body}"
        );
        assert!(
            body.contains(&repo_id.to_string()),
            "the refusal must name the repository the caller asked for: {body}"
        );
        assert!(
            mocks.policy_projections.exclusion_upserts().is_empty(),
            "a refused exclusion must write no projection row",
        );
    }

    // -----------------------------------------------------------------
    // DELETE /api/v1/admin/policies/:policy_id/exclusions/:cve_id
    // -----------------------------------------------------------------

    /// Happy path: curator + seeded exclusion → 204 NO CONTENT and
    /// the projection records exactly one delete for the resolved
    /// exclusion_id (the use case's `remove_exclusion` invokes
    /// `delete_exclusion` on the projection port after the
    /// event-store append).
    #[tokio::test]
    async fn delete_exclusion_happy_path_returns_204() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-5678");

        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":"superseded by upstream patch"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let deletes = mocks.policy_projections.exclusion_deletes();
        assert_eq!(deletes.len(), 1);
        assert_eq!(
            deletes[0], eid,
            "the CVE → exclusion_id resolution must drive the use case with the seeded id",
        );
    }

    /// Admin caller also passes the gate.
    #[tokio::test]
    async fn delete_exclusion_admin_caller_also_returns_204() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (_eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-1111");
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":"admin override"}"#,
                Some(principal_with_claims(&["admin"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    /// A stored repository scope → 204, and the row is gone.
    ///
    /// Only a row written before the add-side refusal can be in this
    /// shape; nothing rewrites those rows, so the removal path is the
    /// only way an operator without a declared gitops tree gets rid of
    /// one. Refusing the removal would make a row that keeps clearing
    /// its CVE for every repository the parent policy governs
    /// unremovable through the API, while the same use-case method
    /// stays open for the gitops applier — so this asserts the removal
    /// succeeds, not that it is gated.
    #[tokio::test]
    async fn delete_exclusion_with_a_stored_repository_scope_returns_204() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let repo_id = Uuid::new_v4();
        let (eid, cve) = seed_exclusion_with_scope(
            &mocks,
            policy_id,
            "CVE-2026-9090",
            PolicyScope::Repository(repo_id),
        );

        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":"cleaning up a legacy row"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            mocks.policy_projections.exclusion_deletes(),
            vec![eid],
            "the removal must reach the use case with the resolved exclusion id",
        );
        assert!(
            mocks
                .policy_projections
                .list_exclusions_for_policy(policy_id)
                .await
                .unwrap()
                .is_empty(),
            "the stored row must be gone after the removal",
        );
    }

    /// The whole way through, on the shape that made this endpoint
    /// matter: a repository-scoped row exists (seeded past the add-side
    /// refusal, which is how the stored ones came about), the finding
    /// filter is suppressing its CVE, the API removes it, and the CVE
    /// is enforced again.
    ///
    /// The *before* half is the defect itself — the filter drops the
    /// finding although the artifact's coordinates belong to no
    /// particular repository, which is what
    /// [`hort_domain::policy::SCOPE_NOT_ENFORCED`] says and why the
    /// write is refused. The *after* half is what this endpoint owes
    /// the operator: one `DELETE` and the suppression is gone. An
    /// assertion on the 204 alone would not have shown the second half.
    #[tokio::test]
    async fn removing_a_stored_repository_scoped_exclusion_re_enforces_the_cve() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (_eid, cve) = seed_exclusion_with_scope(
            &mocks,
            policy_id,
            "CVE-2026-7070",
            PolicyScope::Repository(Uuid::new_v4()),
        );
        let findings = vec![finding_for(&cve)];
        let coords = any_coords();
        let now = Utc::now();

        // Before: the stored row suppresses the CVE — for this
        // artifact, and for every other one the policy governs.
        let before = mocks
            .policy_projections
            .list_exclusions_for_policy(policy_id)
            .await
            .unwrap();
        let filtered = filter_excluded_findings(&findings, &before, &coords, now);
        assert_eq!(
            filtered.excluded_count, 1,
            "the seeded row must be suppressing the CVE before the removal",
        );

        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":"the scope never narrowed anything"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // After: nothing excludes the CVE any more.
        let after = mocks
            .policy_projections
            .list_exclusions_for_policy(policy_id)
            .await
            .unwrap();
        let filtered = filter_excluded_findings(&findings, &after, &coords, now);
        assert_eq!(
            filtered.excluded_count, 0,
            "the CVE must no longer be excluded after the removal",
        );
        assert_eq!(
            filtered.remaining_findings, findings,
            "the finding must survive the filter unchanged",
        );
    }

    /// The removal states its real reach. The stored scope narrowed
    /// nothing, so the row was live for every repository the parent
    /// policy governs and the removal lands in all of them — that is
    /// information the operator acts on, and the only place a `204 No
    /// Content` can carry it is the log.
    ///
    /// Pins, on a single line, the three identifiers an operator
    /// correlates on (`policy_id`, `cve_id`, the stored
    /// `repository_id`) plus the shared rationale, so the line cannot
    /// decay into a bare "removed an exclusion" while still looking
    /// deliberate.
    #[tracing_test::traced_test]
    #[test]
    fn delete_exclusion_logs_the_real_reach_of_a_stored_repository_scope() {
        // `harness()` wires an in-memory `EphemeralStore` that spawns
        // its reaper on construction, so the whole fixture has to be
        // built inside the runtime.
        let repo_id = Uuid::new_v4();
        let (policy_id, cve, status) = run_async(async {
            let (router, mocks) = harness();
            let policy_id = seed_policy(&mocks);
            let (_eid, cve) = seed_exclusion_with_scope(
                &mocks,
                policy_id,
                "CVE-2026-6060",
                PolicyScope::Repository(repo_id),
            );
            let status = router
                .oneshot(delete_req(
                    policy_id,
                    &cve,
                    r#"{"reason":"legacy row"}"#,
                    Some(principal_with_claims(&["curate"])),
                ))
                .await
                .unwrap()
                .status();
            (policy_id, cve, status)
        });
        assert_eq!(status, StatusCode::NO_CONTENT);

        // On *one* line, not scattered across the span and the record:
        // a correlation that needs two log lines joined is not the one
        // an operator gets out of a log search.
        logs_assert(|lines: &[&str]| {
            let hits: Vec<&&str> = lines
                .iter()
                .filter(|l| l.contains("carries a repository scope"))
                .collect();
            let [line] = hits[..] else {
                return Err(format!("expected exactly one reach line, got {hits:?}"));
            };
            for needle in [
                policy_id.to_string().as_str(),
                cve.as_str(),
                repo_id.to_string().as_str(),
                // The rationale every other surface states verbatim.
                "never reads",
                // Not a denial: the row is on its way out.
                "INFO",
            ] {
                if !line.contains(needle) {
                    return Err(format!("reach line is missing {needle:?}: {line}"));
                }
            }
            Ok(())
        });
    }

    // -----------------------------------------------------------------
    // DELETE resolves a row by its identity, not by its CVE
    //
    // A policy can hold several exclusions for one CVE differing only
    // in `package_pattern`. Picking one of them by CVE lets the
    // projection's ordering decide which suppression ends and strands
    // the rest; the tests below pin that the ambiguity is reported with
    // the candidates as data, and that every row stays reachable.
    // -----------------------------------------------------------------

    /// Two rows for one CVE and nothing saying which → `409`, and the
    /// candidates are **members of the body**: a caller reads each
    /// `exclusion_id` as a field and repeats the request with it.
    ///
    /// Kills: resolving the ambiguity server-side (any 2xx here means a
    /// row the operator did not name was removed), and reporting it as
    /// prose (the ids must not be reachable only by parsing the
    /// message).
    #[tokio::test]
    async fn delete_exclusion_two_rows_for_one_cve_is_409_with_both_candidates() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let cve = "CVE-2026-8001";
        let first = seed_exclusion_with_pattern(&mocks, policy_id, cve, "pkg:npm/left-pad@*");
        let (second, _) = seed_exclusion(&mocks, policy_id, cve);

        let resp = router
            .oneshot(delete_req(
                policy_id,
                cve,
                r#"{"reason":"withdrawing one of them"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .expect("Content-Type must be present")
                .to_str()
                .unwrap(),
            "application/json",
        );

        let v = body_json(resp).await;
        assert_eq!(v["cve_id"], cve);
        let candidates = v["candidates"]
            .as_array()
            .expect("candidates must be a JSON array, not text inside the message");
        assert_eq!(candidates.len(), 2, "both rows must be offered: {v}");

        // Each candidate's identity is readable as a field, and so is
        // the discriminator — including the `null` that says "this row
        // carries no pattern", which a caller could not tell from a
        // missing member.
        let by_id: std::collections::HashMap<String, &serde_json::Value> = candidates
            .iter()
            .map(|c| {
                (
                    c["exclusion_id"]
                        .as_str()
                        .expect("exclusion_id must be a string member")
                        .to_string(),
                    &c["package_pattern"],
                )
            })
            .collect();
        assert_eq!(
            by_id.get(&first.to_string()).map(|p| p.as_str()),
            Some(Some("pkg:npm/left-pad@*")),
            "the patterned row must be offered with its pattern: {v}",
        );
        assert!(
            by_id
                .get(&second.to_string())
                .expect("the pattern-less row must be offered too")
                .is_null(),
            "a row with no pattern must say so with null, not by omitting the member: {v}",
        );

        // The ids travel as data. If the message were the only place
        // they appeared, every caller would be writing a parser.
        let message = v["error"].as_str().expect("error must be a string member");
        assert!(
            !message.contains(&first.to_string()) && !message.contains(&second.to_string()),
            "the candidates belong in the members, not in the message: {message}",
        );

        // Nothing was removed, and the use case was never reached.
        assert!(
            mocks.policy_projections.exclusion_deletes().is_empty(),
            "an unanswered ambiguity must remove nothing",
        );
        assert_eq!(
            remaining_exclusion_ids(&mocks, policy_id).await,
            vec![first, second],
            "both rows must survive a refused removal",
        );
    }

    /// The acceptance case: with two rows for one CVE, each is
    /// removable by naming its `exclusion_id` — and naming one removes
    /// **exactly** that row.
    ///
    /// Kills the `find(|e| e.cve_id == cve_id)` predicate directly, and
    /// does it without leaning on the read model's ordering: the first
    /// request names the row the projection lists **second**, so a
    /// predicate that resolves by CVE removes the other one and the
    /// assertion fails. (Naming the first-listed row would have passed
    /// on both the right implementation and the wrong one — which is
    /// the whole shape of the defect: the ordering agreeing with the
    /// caller's intent is luck, not behaviour.) The second request then
    /// reaches the row the first left behind, so neither is stranded.
    #[tokio::test]
    async fn delete_exclusion_by_identity_reaches_each_of_two_rows_for_one_cve() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let cve = "CVE-2026-8002";
        let listed_first =
            seed_exclusion_with_pattern(&mocks, policy_id, cve, "pkg:npm/left-pad@*");
        let listed_second =
            seed_exclusion_with_pattern(&mocks, policy_id, cve, "pkg:npm/right-pad@*");
        assert_eq!(
            remaining_exclusion_ids(&mocks, policy_id).await,
            vec![listed_first, listed_second],
            "the test's premise is this listing order",
        );

        let body = serde_json::json!({
            "reason": "right-pad is patched upstream",
            "exclusion_id": listed_second,
        })
        .to_string();
        let resp = router
            .clone()
            .oneshot(delete_req(
                policy_id,
                cve,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            mocks.policy_projections.exclusion_deletes(),
            vec![listed_second],
            "the named row, and only it, must reach the use case",
        );
        assert_eq!(
            remaining_exclusion_ids(&mocks, policy_id).await,
            vec![listed_first],
            "the row the caller did not name must still be there",
        );

        // The CVE now names exactly one row, so the second removal
        // needs no disambiguator — but naming it must work too, and
        // must reach the row the first call left behind.
        let body = serde_json::json!({
            "reason": "left-pad too",
            "exclusion_id": listed_first,
        })
        .to_string();
        let resp = router
            .oneshot(delete_req(
                policy_id,
                cve,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            mocks.policy_projections.exclusion_deletes(),
            vec![listed_second, listed_first],
            "both rows must be reachable; neither is stranded",
        );
        assert!(
            remaining_exclusion_ids(&mocks, policy_id).await.is_empty(),
            "the policy must hold no exclusion for the CVE afterwards",
        );
    }

    /// An `exclusion_id` that exists on the policy but under a
    /// different CVE → `400`, and the use case is not called.
    ///
    /// Kills the reading where the body is a second way to say which
    /// row dies: on that reading this request would remove the other
    /// CVE's row, which the path never named.
    #[tokio::test]
    async fn delete_exclusion_with_an_exclusion_id_from_another_cve_is_refused() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (target_row, target_cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-8003");
        let (other_cve_row, _) = seed_exclusion(&mocks, policy_id, "CVE-2026-8004");

        let body = serde_json::json!({
            "reason": "wrong row named",
            "exclusion_id": other_cve_row,
        })
        .to_string();
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &target_cve,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            mocks.policy_projections.exclusion_deletes().is_empty(),
            "a body naming another CVE's row must not reach the use case",
        );
        assert_eq!(
            remaining_exclusion_ids(&mocks, policy_id).await,
            vec![target_row, other_cve_row],
            "neither the path's row nor the named row may be removed",
        );
    }

    /// A CVE with no rows is `404` even when the body names a real
    /// exclusion of the policy — the optional disambiguator narrows
    /// within the path's CVE and cannot conjure a target for a CVE that
    /// is not there.
    #[tokio::test]
    async fn delete_exclusion_unknown_cve_with_an_exclusion_id_is_still_404() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (existing, _) = seed_exclusion(&mocks, policy_id, "CVE-2026-8005");

        let body = serde_json::json!({
            "reason": "valid",
            "exclusion_id": existing,
        })
        .to_string();
        let resp = router
            .oneshot(delete_req(
                policy_id,
                "CVE-2026-NONE",
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            remaining_exclusion_ids(&mocks, policy_id).await,
            vec![existing],
            "the row the body named must survive a 404 on another CVE",
        );
    }

    /// The single-match path is byte-for-byte what it was: the use case
    /// is driven with the same `RemoveExclusionCommand` — the policy,
    /// the resolved exclusion id, and the body's reason verbatim — and
    /// the request carries no `exclusion_id` at all.
    ///
    /// Read off the appended `ExclusionRemoved`, whose three fields
    /// *are* the command's three fields, so the assertion cannot pass
    /// on a command that lost one of them.
    #[tokio::test]
    async fn delete_exclusion_single_match_drives_the_unchanged_command() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-8006");

        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":"superseded by upstream patch"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let removed: Vec<hort_domain::events::ExclusionRemoved> = mocks
            .events
            .appended_batches()
            .into_iter()
            .flat_map(|b| b.events)
            .filter_map(|e| match e.event {
                hort_domain::events::DomainEvent::ExclusionRemoved(ev) => Some(ev),
                _ => None,
            })
            .collect();
        assert_eq!(removed.len(), 1, "exactly one removal must be recorded");
        assert_eq!(removed[0].policy_id, policy_id);
        assert_eq!(
            removed[0].exclusion_id, eid,
            "the CVE → exclusion_id resolution must still drive the use case with the \
             single matching row",
        );
        assert_eq!(removed[0].reason, "superseded by upstream patch");
    }

    /// Naming the row on a CVE that has only one is allowed, not
    /// rejected as redundant — the field narrows, and the narrowing is
    /// satisfied.
    #[tokio::test]
    async fn delete_exclusion_naming_the_only_row_for_a_cve_returns_204() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-8007");

        let body = serde_json::json!({ "reason": "valid", "exclusion_id": eid }).to_string();
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(mocks.policy_projections.exclusion_deletes(), vec![eid]);
    }

    /// A malformed request against an ambiguous CVE is answered as
    /// malformed: the `reason` gate runs before the lookup, so the
    /// caller is told what is wrong with the request they sent rather
    /// than being handed candidates for a request that could not have
    /// succeeded anyway.
    ///
    /// Kills a reordering that hoists the ambiguity report above the
    /// body validation — the 409 would then teach the caller to fix the
    /// wrong thing, and a request with no justification would be one
    /// `exclusion_id` away from removing a suppression unaudited.
    #[tokio::test]
    async fn delete_exclusion_empty_reason_beats_the_ambiguity_report() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let cve = "CVE-2026-8008";
        let first = seed_exclusion_with_pattern(&mocks, policy_id, cve, "pkg:npm/left-pad@*");
        let (second, _) = seed_exclusion(&mocks, policy_id, cve);

        let resp = router
            .oneshot(delete_req(
                policy_id,
                cve,
                r#"{"reason":"   "}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            body_text(resp).await.contains("reason"),
            "the answer must name the malformed field, not the ambiguity",
        );
        assert_eq!(
            remaining_exclusion_ids(&mocks, policy_id).await,
            vec![first, second],
            "nothing is removed either way",
        );
    }

    /// Empty `reason` → 400.
    #[tokio::test]
    async fn delete_exclusion_empty_reason_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (_eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-2222");
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":""}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            mocks.policy_projections.exclusion_deletes().is_empty(),
            "validation must fire BEFORE the use case runs (no delete recorded)",
        );
    }

    /// Missing body entirely → 400 (treated as empty reason).
    #[tokio::test]
    async fn delete_exclusion_no_body_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (_eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-3333");
        let mut req = Request::delete(format!(
            "/api/v1/admin/policies/{policy_id}/exclusions/{cve}"
        ))
        .body(Body::empty())
        .unwrap();
        crate::middleware::auth::test_support::inject_principal(
            &mut req,
            principal_with_claims(&["curate"]),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 513-byte reason → 400.
    #[tokio::test]
    async fn delete_exclusion_oversize_reason_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (_eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-4444");
        let oversize = "x".repeat(513);
        let body = format!(r#"{{"reason":"{oversize}"}}"#);
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                &body,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Unauthorised caller → 403 via the extractor.
    #[tokio::test]
    async fn delete_exclusion_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let (_eid, cve) = seed_exclusion(&mocks, policy_id, "CVE-2026-5555");
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":"valid"}"#,
                Some(principal_with_claims(&["reader"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], br#"{"error":"insufficient permissions"}"#);
    }

    /// Unknown CVE on a known policy → 404. The handler's
    /// `list_exclusions_for_policy` returns no match.
    #[tokio::test]
    async fn delete_exclusion_unknown_cve_returns_404() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let resp = router
            .oneshot(delete_req(
                policy_id,
                "CVE-2026-NONE",
                r#"{"reason":"valid"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Unknown policy → 404. With no exclusions on that policy_id,
    /// `list_exclusions_for_policy` returns empty and the handler
    /// surfaces 404.
    #[tokio::test]
    async fn delete_exclusion_unknown_policy_returns_404() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(delete_req(
                Uuid::new_v4(),
                "CVE-2026-1234",
                r#"{"reason":"valid"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Oversize CVE id (65 chars) → 400.
    #[tokio::test]
    async fn delete_exclusion_oversize_cve_returns_400() {
        let (router, mocks) = harness();
        let policy_id = seed_policy(&mocks);
        let cve = "C".repeat(65);
        let resp = router
            .oneshot(delete_req(
                policy_id,
                &cve,
                r#"{"reason":"valid"}"#,
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 409 / 500 wire-shape pins — same rationale as on POST.
    #[tokio::test]
    async fn delete_exclusion_conflict_wire_shape_is_pinned_by_apierror() {
        let api_err = ApiError(AppError::Domain(DomainError::Conflict(
            "stream version mismatch".into(),
        )));
        let resp = api_err.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn delete_exclusion_repository_error_wire_shape_is_500() {
        let api_err = ApiError(AppError::Repository("db down".into()));
        let resp = api_err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
