//! `GET /api/v1/admin/curation/decisions`.
//!
//! Paginated event-log scan of curator decisions. The
//! port returns ONE row per event; the HTTP
//! layer optionally collapses correlated rows server-side via the
//! `?by_correlation=true` flag.
//!
//! Query parameters (design §2.7 + §2.9):
//! - `type` — one of `waive | block | exclude_finding | unexclude_finding`
//!   (closed set). Invalid value → 400.
//! - `actor` — actor user_id (UUID); the use case forwards verbatim.
//!   Invalid UUID → 400.
//! - `repository` — stable repository key; resolves to UUID via
//!   [`hort_app::use_cases::repository_use_case::RepositoryUseCase::get_by_key`].
//!   Unknown key → 404.
//! - `package` — substring / exact-match on package name; the use case
//!   forwards verbatim (the adapter applies the SQL semantics).
//! - `since` — RFC 3339 (ISO-8601) timestamp; parsing failure → 400.
//! - `limit` — 1..=500. Default 100. Invalid range → 400.
//! - `by_correlation` — bool. When `true`, the handler groups the port's
//!   one-row-per-event result by `correlation_id` and emits ONE rollup
//!   DTO per group (operator surface — design §2.9 "collapses
//!   correlated events into the operator's intent"). Default `false`
//!   (events-first; matches the audit-log mental model).
//!
//! Status-code map (design §3):
//! - `200 OK` — body is [`CurationDecisionsResponseDto`]
//! - `400 Bad Request` — any param fails validation (closed-set,
//!   UUID, RFC-3339, limit window)
//! - `403 Forbidden` — caller lacks Curate AND Admin
//! - `404 Not Found` — `repository` key does not resolve
//! - `500 Internal Server Error` — infrastructure failure
//!
//! # `by_correlation` rollup shape
//!
//! The design §2.7/§2.9 does not pin the exact rollup shape — it names
//! the affordance ("collapses correlated events into the curator's
//! intent") and lists candidate fields. We pick the **low-payload**
//! shape (one rollup DTO per `correlation_id`, no inner event list)
//! because:
//!
//! 1. The task spec leans this way ("lean toward 'one DTO per group
//!    with metadata + a count, not the underlying event list' for low
//!    payload size").
//! 2. Operator tooling that needs the events drills in via
//!    `?by_correlation=false` on the same endpoint with a matching
//!    filter — there's no information loss, just deferral.
//! 3. The shared-justification invariant (Item 5: every event in a
//!    `VersionList` block carries the SAME justification) means a
//!    single string suffices; rolling up does not lose audit content.
//!
//! Fields per rollup row: `{ correlation_id, kind, actor_id,
//!   event_count, first_occurred_at, last_occurred_at, justification }`.
//! Tied to the test `decisions_by_correlation_collapses_two_correlated_events`.
//!
//! **`#[tracing::instrument]` deliberately WITHOUT `err`** — same
//! rationale as `queue.rs`.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::CallerPrivileges;
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::ports::curation_decisions_repository::{
    CurationDecisionEntry, CurationDecisionFilter, CurationDecisionKind,
};

use crate::authz::CurateOrAdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

use super::MAX_LIST_LIMIT;

/// Query parameters for `GET /api/v1/admin/curation/decisions`.
#[derive(Debug, Deserialize)]
pub struct DecisionsQueryParams {
    #[serde(rename = "type")]
    type_: Option<String>,
    actor: Option<String>,
    repository: Option<String>,
    package: Option<String>,
    since: Option<String>,
    limit: Option<u32>,
    by_correlation: Option<bool>,
}

/// Response DTO for `GET /api/v1/admin/curation/decisions`.
///
/// Carries EITHER per-event rows (`by_correlation=false`, default) OR
/// per-correlation-group rollups (`by_correlation=true`). The two
/// shapes are tagged via the `by_correlation` field — a single
/// response shape simplifies the client; only one of `events` or
/// `groups` is populated per response.
///
/// Each row is **one event**. The listing does not
/// merge events into a per-package or per-correlation rollup by
/// default; `--by-correlation` is an opt-in flag that collapses
/// correlated events.
#[derive(Debug, Serialize)]
pub struct CurationDecisionsResponseDto {
    pub by_correlation: bool,
    /// Per-event rows when `by_correlation = false`. Empty when
    /// `by_correlation = true`.
    pub events: Vec<CurationDecisionRowDto>,
    /// Per-correlation rollup rows when `by_correlation = true`.
    /// Empty when `by_correlation = false`.
    pub groups: Vec<CurationDecisionGroupDto>,
}

/// Wire-format per-event row.
///
/// Mirrors [`CurationDecisionEntry`] one-to-one; the `kind` enum
/// projects through the wire-stable lowercase string (`waive`,
/// `block`, `exclude_finding`, `unexclude_finding`) so operators
/// script against names not variant ordinals.
#[derive(Debug, Serialize)]
pub struct CurationDecisionRowDto {
    pub event_id: Uuid,
    pub kind: String,
    pub actor_id: Uuid,
    pub artifact_id: Option<Uuid>,
    pub policy_id: Option<Uuid>,
    pub cve_id: Option<String>,
    pub justification: String,
    pub correlation_id: Uuid,
    pub occurred_at: DateTime<Utc>,
}

/// Wire-format per-correlation-group rollup row (Item 10 design
/// choice — see module docs for the shape rationale).
///
/// Fields:
/// - `correlation_id` — shared across every event in the group
/// - `kind` — taken from the first event in the group; in practice
///   every event in a single `VersionList` block has the same kind
///   (Item 5 invariant: the bulk call emits only `ArtifactRejected`)
/// - `actor_id` — taken from the first event in the group; Item 5
///   ensures one actor per correlation
/// - `event_count` — number of events grouped under this correlation
/// - `first_occurred_at` / `last_occurred_at` — temporal span of the
///   group (typically tightly clustered for a `VersionList` block,
///   but the rollup preserves the range)
/// - `justification` — shared across the group (Item 5 invariant —
///   every event in a `VersionList` call carries the same string)
#[derive(Debug, Serialize)]
pub struct CurationDecisionGroupDto {
    pub correlation_id: Uuid,
    pub kind: String,
    pub actor_id: Uuid,
    pub event_count: u32,
    pub first_occurred_at: DateTime<Utc>,
    pub last_occurred_at: DateTime<Utc>,
    pub justification: String,
}

impl CurationDecisionRowDto {
    fn from_domain(e: CurationDecisionEntry) -> Self {
        Self {
            event_id: e.event_id,
            kind: kind_wire_name(e.kind).to_string(),
            actor_id: e.actor_id,
            artifact_id: e.artifact_id,
            policy_id: e.policy_id,
            cve_id: e.cve_id,
            justification: e.justification,
            correlation_id: e.correlation_id,
            occurred_at: e.occurred_at,
        }
    }
}

/// Closed-set string ↔ enum projection for [`CurationDecisionKind`].
/// Kept as a free fn (no `Display` on the domain type — `Display` would
/// pin a wire name, which the design defers to the HTTP layer).
fn kind_wire_name(k: CurationDecisionKind) -> &'static str {
    match k {
        CurationDecisionKind::Waive => "waive",
        CurationDecisionKind::Block => "block",
        CurationDecisionKind::ExcludeFinding => "exclude_finding",
        CurationDecisionKind::UnexcludeFinding => "unexclude_finding",
    }
}

fn parse_kind(s: &str) -> Result<CurationDecisionKind, ApiError> {
    match s {
        "waive" => Ok(CurationDecisionKind::Waive),
        "block" => Ok(CurationDecisionKind::Block),
        "exclude_finding" => Ok(CurationDecisionKind::ExcludeFinding),
        "unexclude_finding" => Ok(CurationDecisionKind::UnexcludeFinding),
        _ => Err(ApiError(AppError::Domain(DomainError::Validation(
            format!(
                "invalid type {s:?} (expected waive | block | exclude_finding | unexclude_finding)"
            ),
        )))),
    }
}

/// Server-side rollup: group port rows by `correlation_id` preserving
/// first-seen ordering. The first event in the group supplies `kind`,
/// `actor_id`, and `justification`; subsequent events extend the
/// `event_count` and `last_occurred_at`. `first_occurred_at` is the
/// earliest `occurred_at` in the group; `last_occurred_at` is the
/// latest.
fn collapse_by_correlation(events: Vec<CurationDecisionEntry>) -> Vec<CurationDecisionGroupDto> {
    // BTreeMap ordered by correlation_id keeps the rollup deterministic
    // for tests; the design does not pin a wire ordering.
    let mut groups: BTreeMap<Uuid, CurationDecisionGroupDto> = BTreeMap::new();
    for e in events {
        groups
            .entry(e.correlation_id)
            .and_modify(|g| {
                g.event_count += 1;
                if e.occurred_at < g.first_occurred_at {
                    g.first_occurred_at = e.occurred_at;
                }
                if e.occurred_at > g.last_occurred_at {
                    g.last_occurred_at = e.occurred_at;
                }
            })
            .or_insert_with(|| CurationDecisionGroupDto {
                correlation_id: e.correlation_id,
                kind: kind_wire_name(e.kind).to_string(),
                actor_id: e.actor_id,
                event_count: 1,
                first_occurred_at: e.occurred_at,
                last_occurred_at: e.occurred_at,
                justification: e.justification,
            });
    }
    groups.into_values().collect()
}

/// `GET /api/v1/admin/curation/decisions`.
#[tracing::instrument(skip(ctx, principal))]
pub async fn get_decisions(
    principal: CurateOrAdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
    Query(query): Query<DecisionsQueryParams>,
) -> Result<Response, ApiError> {
    // `?limit=` validation (1..=MAX).
    let limit = match query.limit {
        None => CurationDecisionFilter::default().limit,
        Some(0) => {
            return Err(ApiError(AppError::Domain(DomainError::Validation(
                "limit must be >= 1".into(),
            ))));
        }
        Some(n) if n > MAX_LIST_LIMIT => {
            return Err(ApiError(AppError::Domain(DomainError::Validation(
                format!("limit {n} exceeds maximum {MAX_LIST_LIMIT}"),
            ))));
        }
        Some(n) => n,
    };

    // `?type=` closed-set validation.
    let kind = match query.type_.as_deref() {
        None => None,
        Some(s) => Some(parse_kind(s)?),
    };

    // `?actor=` UUID validation.
    let actor_id = match query.actor.as_deref() {
        None => None,
        Some(s) => Some(Uuid::from_str(s).map_err(|e| {
            ApiError(AppError::Domain(DomainError::Validation(format!(
                "invalid actor UUID {s:?}: {e}"
            ))))
        })?),
    };

    // `?since=` RFC 3339 / ISO-8601 validation.
    let since = match query.since.as_deref() {
        None => None,
        Some(s) => Some(
            DateTime::parse_from_rfc3339(s)
                .map_err(|e| {
                    ApiError(AppError::Domain(DomainError::Validation(format!(
                        "invalid since timestamp {s:?}: {e}"
                    ))))
                })?
                .with_timezone(&Utc),
        ),
    };

    // `?repository=` key → UUID. Miss → 404 via the standard
    // `AppError::Domain(DomainError::NotFound)` → `ApiError` map.
    let repository_id = match query.repository.as_deref() {
        None => None,
        Some(key) => Some(ctx.repository_use_case.get_by_key(key).await?.id),
    };

    let by_correlation = query.by_correlation.unwrap_or(false);

    let filter = CurationDecisionFilter {
        kind,
        actor_id,
        repository_id,
        package: query.package,
        since,
        limit,
    };

    let actor = ApiActor {
        user_id: principal.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: false,
        is_reviewer: false,
        is_curator: true,
        writable_repository_ids: Vec::new(),
    };

    let entries = ctx
        .curation_use_case
        .list_decisions(actor, privileges, filter)
        .await?;

    let body = if by_correlation {
        CurationDecisionsResponseDto {
            by_correlation: true,
            events: Vec::new(),
            groups: collapse_by_correlation(entries),
        }
    } else {
        CurationDecisionsResponseDto {
            by_correlation: false,
            events: entries
                .into_iter()
                .map(CurationDecisionRowDto::from_domain)
                .collect(),
            groups: Vec::new(),
        }
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use chrono::TimeZone;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::{sample_repository, MockIdentityProvider};
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;

    use crate::context::AuthContext;
    use crate::test_support::{build_mock_ctx, with_auth, MockPorts};

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
            .route("/api/v1/admin/curation/decisions", get(get_decisions))
            .with_state(ctx);
        (router, mocks)
    }

    fn decisions_get(query: &str, principal: Option<CallerPrincipal>) -> Request<Body> {
        let uri = if query.is_empty() {
            "/api/v1/admin/curation/decisions".to_string()
        } else {
            format!("/api/v1/admin/curation/decisions?{query}")
        };
        let mut req = Request::get(uri).body(Body::empty()).unwrap();
        if let Some(p) = principal {
            crate::middleware::auth::test_support::inject_principal(&mut req, p);
        }
        req
    }

    fn sample_event(
        kind: CurationDecisionKind,
        correlation_id: Uuid,
        occurred_at: DateTime<Utc>,
    ) -> CurationDecisionEntry {
        CurationDecisionEntry {
            event_id: Uuid::new_v4(),
            kind,
            actor_id: Uuid::new_v4(),
            artifact_id: Some(Uuid::new_v4()),
            policy_id: None,
            cve_id: None,
            justification: "shared justification".into(),
            correlation_id,
            occurred_at,
        }
    }

    /// Happy path — curator + seeded events (no `by_correlation`).
    #[tokio::test]
    async fn decisions_happy_path_returns_200() {
        let (router, mocks) = harness();
        let e1 = sample_event(CurationDecisionKind::Waive, Uuid::new_v4(), Utc::now());
        let expected_kind = "waive";
        mocks.curation_decisions.set_result(Ok(vec![e1]));

        let resp = router
            .oneshot(decisions_get("", Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["by_correlation"], false);
        assert_eq!(body["events"][0]["kind"], expected_kind);
        assert!(body["groups"].as_array().unwrap().is_empty());

        let recorded = mocks.curation_decisions.recorded_filters();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].limit, 100);
        assert!(recorded[0].kind.is_none());
    }

    /// 403 — caller lacks both grants.
    #[tokio::test]
    async fn decisions_unauthorized_returns_403() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(decisions_get("", Some(principal_with_claims(&["reader"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(mocks.curation_decisions.recorded_filters().is_empty());
    }

    /// 400 — `?type=bogus` (outside the closed set).
    #[tokio::test]
    async fn decisions_invalid_type_returns_400() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(decisions_get(
                "type=bogus",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(mocks.curation_decisions.recorded_filters().is_empty());
    }

    /// 200 — `?type=exclude_finding` accepted and threaded into filter.
    #[tokio::test]
    async fn decisions_type_exclude_finding_threaded() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(decisions_get(
                "type=exclude_finding",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let recorded = mocks.curation_decisions.recorded_filters();
        assert_eq!(recorded[0].kind, Some(CurationDecisionKind::ExcludeFinding));
    }

    /// 400 — `?actor=not-a-uuid`.
    #[tokio::test]
    async fn decisions_invalid_actor_uuid_returns_400() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(decisions_get(
                "actor=not-a-uuid",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 400 — `?since=` is not a valid RFC 3339 timestamp.
    #[tokio::test]
    async fn decisions_invalid_since_returns_400() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(decisions_get(
                "since=not-a-timestamp",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 200 — `?since=<iso>` accepted and threaded as DateTime<Utc>.
    #[tokio::test]
    async fn decisions_valid_since_threaded() {
        let (router, mocks) = harness();
        let resp = router
            .oneshot(decisions_get(
                "since=2026-05-01T00:00:00Z",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let recorded = mocks.curation_decisions.recorded_filters();
        let expected = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        assert_eq!(recorded[0].since, Some(expected));
    }

    /// 400 — `?limit=501`.
    #[tokio::test]
    async fn decisions_oversize_limit_returns_400() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(decisions_get(
                "limit=501",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 404 — `?repository=<unknown>`.
    #[tokio::test]
    async fn decisions_unknown_repository_returns_404() {
        let (router, _mocks) = harness();
        let resp = router
            .oneshot(decisions_get(
                "repository=does-not-exist",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// 200 — `?repository=<known>` resolves and threads into the filter.
    #[tokio::test]
    async fn decisions_known_repository_threaded() {
        let (router, mocks) = harness();
        let mut repo = sample_repository();
        repo.key = "npm-main".into();
        let expected_id = repo.id;
        mocks.repositories.insert(repo);
        let resp = router
            .oneshot(decisions_get(
                "repository=npm-main",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let recorded = mocks.curation_decisions.recorded_filters();
        assert_eq!(recorded[0].repository_id, Some(expected_id));
    }

    /// 500 — adapter failure surfaces with no internal leakage.
    #[tokio::test]
    async fn decisions_adapter_error_returns_500() {
        let (router, mocks) = harness();
        mocks
            .curation_decisions
            .set_result(Err(DomainError::Invariant(
                "synthetic decisions adapter failure".into(),
            )));
        let resp = router
            .oneshot(decisions_get("", Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        crate::error::assert_no_internal_leakage(StatusCode::INTERNAL_SERVER_ERROR, &bytes);
    }

    /// **Load-bearing rollup test (task spec).** `by_correlation=true`
    /// collapses two events sharing a `correlation_id` into ONE group
    /// DTO carrying `event_count = 2` and the temporal span. Two
    /// events with DISTINCT correlation_ids stay in separate groups.
    #[tokio::test]
    async fn decisions_by_correlation_collapses_two_correlated_events() {
        let (router, mocks) = harness();
        let corr_a = Uuid::new_v4();
        let corr_b = Uuid::new_v4();
        let t0 = Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap();
        let t1 = Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 5).unwrap();
        let t2 = Utc.with_ymd_and_hms(2026, 5, 1, 13, 0, 0).unwrap();

        let actor_a = Uuid::new_v4();
        let mut e1 = sample_event(CurationDecisionKind::Block, corr_a, t0);
        e1.actor_id = actor_a;
        let mut e2 = sample_event(CurationDecisionKind::Block, corr_a, t1);
        e2.actor_id = actor_a;
        let e3 = sample_event(CurationDecisionKind::Waive, corr_b, t2);

        mocks.curation_decisions.set_result(Ok(vec![e1, e2, e3]));

        let resp = router
            .oneshot(decisions_get(
                "by_correlation=true",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["by_correlation"], true);
        assert!(body["events"].as_array().unwrap().is_empty());

        // Two groups (one per distinct correlation_id).
        let groups = body["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2, "two distinct correlation_ids → two groups");

        // Find the correlated-pair group; assert event_count = 2 and
        // the [first, last]_occurred_at span matches.
        let block_group = groups
            .iter()
            .find(|g| g["correlation_id"] == corr_a.to_string())
            .expect("group for corr_a missing");
        assert_eq!(block_group["event_count"], 2);
        assert_eq!(block_group["kind"], "block");
        assert_eq!(block_group["actor_id"], actor_a.to_string());
        assert_eq!(
            block_group["first_occurred_at"],
            t0.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );
        assert_eq!(
            block_group["last_occurred_at"],
            t1.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );
        assert_eq!(block_group["justification"], "shared justification");

        // Singleton group (corr_b) — event_count = 1, both spans match
        // its sole event.
        let waive_group = groups
            .iter()
            .find(|g| g["correlation_id"] == corr_b.to_string())
            .expect("group for corr_b missing");
        assert_eq!(waive_group["event_count"], 1);
        assert_eq!(waive_group["kind"], "waive");
    }

    /// `by_correlation=false` (explicit) → events list populated,
    /// groups empty. Same as default — pin the explicit-false case.
    #[tokio::test]
    async fn decisions_by_correlation_false_keeps_events() {
        let (router, mocks) = harness();
        mocks.curation_decisions.set_result(Ok(vec![sample_event(
            CurationDecisionKind::Waive,
            Uuid::new_v4(),
            Utc::now(),
        )]));
        let resp = router
            .oneshot(decisions_get(
                "by_correlation=false",
                Some(principal_with_claims(&["curate"])),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["by_correlation"], false);
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert!(body["groups"].as_array().unwrap().is_empty());
    }
}
