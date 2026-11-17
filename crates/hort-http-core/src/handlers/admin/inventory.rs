//! `GET /api/v1/admin/inventory`.
//!
//! The admin readout of what each repository's live catalog holds: the
//! live artifact-row count, the distinct-content count, and the weight
//! of those distinct contents. A retention concept without a
//! before/after measurement is not verifiable, and until this surface
//! existed the inventory had to be taken by hand with read-only SQL
//! against a production database.
//!
//! # A readout, not a gauge
//!
//! No metric is emitted. This answers the interactive question an
//! operator asks; the precedent for that shape is the removal of the two
//! provenance-hold gauges, which went with *"no replacement metric; the
//! operator's view of the held set is the admin curation queue."* That
//! decision was about the held set rather than about an inventory, so it
//! bars no inventory gauge on its own terms — whether one is worth
//! having is a separate decision on freshness, scrape cost and whether
//! anyone needs to alert on this. This endpoint neither builds nor
//! forecloses it.
//!
//! # `live_primary_content_bytes` is a catalog weight
//!
//! The field name is the first line of defence and the documentation is
//! the rest of it. **This number is not disk usage.** All three parts of
//! that, because every one of them is a way to misread it:
//!
//! - **It is not additive across repositories.** One CAS entry can
//!   carry artifact rows in several repositories (ADR 0054), so each
//!   repository's figure counts that same physical blob in full. Adding
//!   the figures double-counts it, and there is no unique
//!   per-repository physical ownership to report instead.
//! - **It is not a measurement of bytes at rest.** It sums only the
//!   *primary* content of the artifact rows — which is what the name
//!   says — and so omits CAS-resident metadata and every other
//!   content-reference target kind.
//! - **It is not reclaimable space.** A soft-deleted row is excluded
//!   from every number here while its bytes stay resident until
//!   refcount-gated GC, and what a disposal would actually free depends
//!   on every surviving claim — the question the retention preview and
//!   purge GC model, not this one.
//!
//! What it *is*: how much this repository's served catalog weighs,
//! counting each distinct content once. `artifact_count` and
//! `distinct_content_count` genuinely differ, because CAS shares content
//! — the first real retention dry run reported 3 647 rows against 3 608
//! distinct contents.
//!
//! # This is not the held-set overview
//!
//! `GET /api/v1/admin/retention/overview` reports the same first two
//! quantities, under the same two field names on purpose, over the
//! **held-pending-signature** slice; it carries no byte figure because
//! it previews a *disposal*, where the honest number is refcount-gated
//! and so is not computable from the rows. This endpoint reports a
//! *catalog weight*, which is computable and is not reclaimable space.
//! Same discipline, two different questions.
//!
//! # No quota figure
//!
//! `quota_bytes` is deliberately absent, and there is no longer a quota
//! to be absent *of*: the operator surface was retired, so a gitops
//! apply declaring `quotaBytes` is refused
//! (`hort_config::desired::validate_repository_quota_bytes_retired`) and
//! no surface reports the column. Nothing ever enforced it — reporting a
//! stored leftover beside a usage figure would make this readout look
//! like quota monitoring while no quota exists to monitor.
//!
//! No query parameters.
//!
//! Status-code map:
//! - `200 OK` — success, body is [`CatalogInventoryDto`]
//! - `403 Forbidden` — caller lacks `Permission::Admin` (the
//!   [`AdminPrincipal`] extractor short-circuits before the handler
//!   body)
//! - `500 Internal Server Error` — infrastructure failure. An inventory
//!   that answered "every repository is empty" because the database is
//!   down would be the worst available answer for a before/after
//!   measurement.
//!
//! **`#[tracing::instrument]` deliberately WITHOUT `err`** — a privilege
//! denial is an audit fact, not an error (architect Observability rule).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use hort_app::use_cases::repository_inventory_use_case::CatalogInventory;
use hort_app::use_cases::CallerPrivileges;
use hort_domain::events::ApiActor;
use hort_domain::ports::repository_inventory_reader::RepositoryInventory;

use crate::authz::AdminPrincipal;
use crate::context::AppContext;
use crate::error::ApiError;

/// One repository's three numbers on the wire.
#[derive(Debug, Serialize)]
pub struct RepositoryInventoryDto {
    pub repository_id: Uuid,
    pub repository_key: String,
    /// Live `artifacts` rows in this repository — `deleted_at IS NULL`.
    pub artifact_count: u64,
    /// Distinct `checksum_sha256` values across those rows. **Not** the
    /// same number as `artifact_count` (CAS shares content across
    /// artifacts) and not a byte figure — see the module docs.
    pub distinct_content_count: u64,
    /// `size_bytes` summed over **distinct contents**, each counted once
    /// however many rows name it.
    ///
    /// **A catalog weight: non-additive across repositories, not disk
    /// usage, and not reclaimable space.** The module docs carry all
    /// three; the short form is that one CAS entry can carry rows in
    /// several repositories, so adding these figures double-counts a
    /// shared blob, and that this omits CAS-resident metadata and every
    /// other content-reference target kind.
    pub live_primary_content_bytes: u64,
}

impl RepositoryInventoryDto {
    fn from_domain(row: RepositoryInventory) -> Self {
        Self {
            repository_id: row.repository_id,
            repository_key: row.repository_key,
            artifact_count: row.artifact_count,
            distinct_content_count: row.distinct_content_count,
            live_primary_content_bytes: row.live_primary_content_bytes,
        }
    }
}

/// `GET /api/v1/admin/inventory` response body.
#[derive(Debug, Serialize)]
pub struct CatalogInventoryDto {
    /// The instant this reading describes. Carried because the surface's
    /// whole value is comparing two readings, and a reader holding a
    /// before and an after has to know which instants they are
    /// comparing.
    pub measured_at: DateTime<Utc>,
    /// One entry per repository, ordered by key, **including the
    /// repositories holding nothing** — those report zeros. "This
    /// repository is now empty" is the result a retention before/after
    /// is looking for, and an omitted entry cannot be told apart from a
    /// repository the readout never saw.
    pub repositories: Vec<RepositoryInventoryDto>,
}

impl CatalogInventoryDto {
    fn from_domain(inventory: CatalogInventory) -> Self {
        Self {
            measured_at: inventory.measured_at,
            repositories: inventory
                .repositories
                .into_iter()
                .map(RepositoryInventoryDto::from_domain)
                .collect(),
        }
    }
}

/// `GET /api/v1/admin/inventory`.
#[tracing::instrument(skip(ctx, admin))]
pub async fn get_inventory(
    admin: AdminPrincipal,
    State(ctx): State<Arc<AppContext>>,
) -> Result<Response, ApiError> {
    // The `AdminPrincipal` extractor already enforced `Permission::Admin`
    // at the request edge; pass `is_admin: true` so the use-case-side
    // gate is a no-op for this caller rather than a duplicate authz
    // call, while staying engaged for non-HTTP callers — the use case is
    // the canonical denial-log site. Mirrors `get_scanner_workers`.
    let actor = ApiActor {
        user_id: admin.0.user_id,
    };
    let privileges = CallerPrivileges {
        is_admin: true,
        is_reviewer: false,
        is_curator: false,
        writable_repository_ids: Vec::new(),
    };

    // One `now` for the whole response: every number in this body
    // describes the same instant, and the body says which one.
    let inventory = ctx
        .repository_inventory_use_case
        .inventory(actor, privileges, Utc::now())
        .await?;

    Ok((
        StatusCode::OK,
        Json(CatalogInventoryDto::from_domain(inventory)),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    //! `GET /inventory` handler-layer assertions.
    //!
    //! Uses [`build_mock_ctx`] (the anti-pattern checklist forbids
    //! hand-rolling `AppContext`); rows are seeded on
    //! `mocks.repository_inventory`.

    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::test_support::MockIdentityProvider;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::error::DomainError;
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;

    use crate::context::AuthContext;
    use crate::test_support::{build_mock_ctx, with_auth, MockPorts};

    fn admin_claim_grant() -> PermissionGrant {
        PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["admin".into()]),
            repository_id: None,
            permission: Permission::Admin,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            created_at: Utc::now(),
        }
    }

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
            username: "operator".into(),
            email: "operator@example.com".into(),
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
            admin_claim_grant(),
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
            .route("/api/v1/admin/inventory", get(get_inventory))
            .with_state(ctx);
        (router, mocks)
    }

    /// Build the request in the shape **production** produces for this
    /// route. `GET` dispatches through `extract_optional_principal`, so
    /// the slot the auth layer writes is
    /// `Option<AuthenticatedPrincipal>` — `Some(p)` for an
    /// authenticated caller and an explicit `None` for an anonymous
    /// one. Injecting the bare `AuthenticatedPrincipal` slot instead
    /// would test a shape no GET request ever carries.
    fn inventory_get(principal: Option<CallerPrincipal>) -> Request<Body> {
        let mut req = Request::get("/api/v1/admin/inventory")
            .body(Body::empty())
            .unwrap();
        match principal {
            Some(p) => {
                crate::middleware::auth::test_support::inject_optional_principal_some(&mut req, p)
            }
            None => crate::middleware::auth::test_support::inject_optional_principal_none(&mut req),
        }
        req
    }

    async fn body_of(router: Router, principal: Option<CallerPrincipal>) -> serde_json::Value {
        let resp = router.oneshot(inventory_get(principal)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn sample_row() -> RepositoryInventory {
        RepositoryInventory {
            repository_id: Uuid::new_v4(),
            repository_key: "oci-main".into(),
            artifact_count: 3_647,
            distinct_content_count: 3_608,
            live_primary_content_bytes: 142_000_000,
        }
    }

    /// Happy path: an admin gets 200 and all three numbers, each under
    /// the name that says which one it is.
    #[tokio::test]
    async fn inventory_reports_three_numbers_per_repository() {
        let (router, mocks) = harness();
        mocks
            .repository_inventory
            .set_inventory(Ok(vec![sample_row()]));

        let body = body_of(router, Some(principal_with_claims(&["admin"]))).await;

        let cell = &body["repositories"][0];
        assert_eq!(cell["repository_key"], "oci-main");
        assert_eq!(cell["artifact_count"], 3_647);
        assert_eq!(cell["distinct_content_count"], 3_608);
        assert_eq!(cell["live_primary_content_bytes"], 142_000_000u64);
        assert!(body.get("measured_at").is_some());
    }

    /// **The two field names are the ones already on the wire.**
    ///
    /// The held-set overview put `artifact_count` and
    /// `distinct_content_count` on the wire for the same two quantities;
    /// a second vocabulary for one pair of numbers is the defect this
    /// pins against.
    #[tokio::test]
    async fn inventory_reuses_the_held_overviews_two_field_names() {
        let (router, mocks) = harness();
        mocks
            .repository_inventory
            .set_inventory(Ok(vec![sample_row()]));

        let body = body_of(router, Some(principal_with_claims(&["admin"]))).await;
        let cell = &body["repositories"][0];

        for field in ["artifact_count", "distinct_content_count"] {
            assert!(
                cell.get(field).is_some(),
                "{field} is the name the held-set overview already uses: {body}"
            );
        }
        // And no synonym for either of them has been invented beside it.
        for invented in [
            "artifacts",
            "row_count",
            "content_count",
            "distinct_contents",
            "unique_content_count",
        ] {
            assert!(
                cell.get(invented).is_none(),
                "{invented} is a second vocabulary for a number already named: {body}"
            );
        }
    }

    /// **Nothing in the response calls a row count a byte count**, and
    /// the byte figure's own name refuses to be read as storage.
    #[tokio::test]
    async fn no_field_name_lets_a_count_read_as_a_byte_figure() {
        let (router, mocks) = harness();
        mocks
            .repository_inventory
            .set_inventory(Ok(vec![sample_row()]));

        let body = body_of(router, Some(principal_with_claims(&["admin"]))).await;
        let cell = &body["repositories"][0];

        assert!(
            cell.get("live_primary_content_bytes").is_some(),
            "the byte figure is named for what it sums: {body}"
        );
        // None of the names a reader would take for disk usage, and no
        // bare `size`/`bytes` field that says nothing about its scope.
        for misleading in [
            "size_bytes",
            "bytes",
            "storage_bytes",
            "disk_usage",
            "disk_bytes",
            "storage_usage",
            "total_bytes",
            "reclaimable_bytes",
        ] {
            assert!(
                cell.get(misleading).is_none(),
                "{misleading} would read as a measurement of bytes at rest: {body}"
            );
        }
    }

    /// **`quota_bytes` does not appear in the response** — anywhere in
    /// it, not just on the repository entry. The quota surface is
    /// retired and nothing ever enforced it, so a quota beside a usage
    /// figure would make this readout look like quota monitoring over a
    /// limit no apply can even declare.
    #[tokio::test]
    async fn no_quota_field_reaches_the_wire() {
        let (router, mocks) = harness();
        mocks
            .repository_inventory
            .set_inventory(Ok(vec![sample_row()]));

        let body = body_of(router, Some(principal_with_claims(&["admin"]))).await;

        let serialized = body.to_string().to_lowercase();
        assert!(
            !serialized.contains("quota"),
            "nothing quota-shaped belongs in a readout nothing enforces: {body}"
        );
    }

    /// A repository holding nothing is an entry of zeros, not an absent
    /// entry: "retention emptied this repository" must be legible.
    #[tokio::test]
    async fn an_empty_repository_is_reported_as_zeros() {
        let (router, mocks) = harness();
        mocks
            .repository_inventory
            .set_inventory(Ok(vec![RepositoryInventory {
                repository_id: Uuid::new_v4(),
                repository_key: "drained".into(),
                artifact_count: 0,
                distinct_content_count: 0,
                live_primary_content_bytes: 0,
            }]));

        let body = body_of(router, Some(principal_with_claims(&["admin"]))).await;

        let cell = &body["repositories"][0];
        assert_eq!(cell["repository_key"], "drained");
        assert_eq!(cell["artifact_count"], 0);
        assert_eq!(cell["distinct_content_count"], 0);
        assert_eq!(cell["live_primary_content_bytes"], 0);
    }

    /// An installation with no repositories is an empty list, not an
    /// absent field: an operator mid-incident must be able to tell
    /// "nothing is held anywhere" from "this endpoint told me nothing".
    #[tokio::test]
    async fn an_empty_installation_is_an_empty_list() {
        let (router, _mocks) = harness();

        let body = body_of(router, Some(principal_with_claims(&["admin"]))).await;

        assert_eq!(body["repositories"], serde_json::json!([]));
    }

    /// **A curator is not an admin here.** The held-set overview admits
    /// `Curate`; this readout spans every repository in the
    /// installation and takes the admin gate, so a curator-only caller
    /// is refused and the port is never reached.
    #[tokio::test]
    async fn a_curator_without_admin_is_forbidden_and_the_port_is_not_read() {
        let (router, mocks) = harness();
        mocks
            .repository_inventory
            .set_inventory(Ok(vec![sample_row()]));

        let resp = router
            .oneshot(inventory_get(Some(principal_with_claims(&["curate"]))))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            mocks.repository_inventory.calls(),
            0,
            "a forbidden caller must not reach the port"
        );
    }

    /// **An anonymous caller is refused.** Every `GET` in this server
    /// is dispatched through `extract_optional_principal`, so anonymous
    /// reaches the handler's extractor rather than being stopped by the
    /// method layer — the extractor is the only gate in front of this
    /// readout, and it holds. Asserted against the real "auth ran, no
    /// token" sentinel, not against an absent extension slot (which
    /// would only prove the test harness has no middleware).
    #[tokio::test]
    async fn an_anonymous_caller_is_refused() {
        let (router, mocks) = harness();

        let resp = router.oneshot(inventory_get(None)).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an anonymous caller must not be served this readout"
        );
        assert_eq!(
            mocks.repository_inventory.calls(),
            0,
            "an anonymous caller must not reach the port"
        );
    }

    /// An infrastructure failure is a 500, not an empty inventory. A
    /// readout that answers "every repository is empty" because the
    /// database is down inverts the measurement it exists to support.
    #[tokio::test]
    async fn a_port_failure_returns_500_rather_than_an_empty_catalog() {
        let (router, mocks) = harness();
        mocks
            .repository_inventory
            .set_inventory(Err(DomainError::Invariant("db down".into())));

        let resp = router
            .oneshot(inventory_get(Some(principal_with_claims(&["admin"]))))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
