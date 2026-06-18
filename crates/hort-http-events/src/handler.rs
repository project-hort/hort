//! `GET /api/v1/events` handler.
//!
//! Single route, single handler. Per-category authz table:
//!
//! | Category                                                              | Authz                            |
//! |-----------------------------------------------------------------------|----------------------------------|
//! | `Artifact` / `ArtifactGroup` / `Ref` / `Curation` / `Repository`      | Non-admin allowed; per-event filtered to repos the caller can `Read`. |
//! | `Policy` / `Admin` / `Authorization` / `User` / `AuthAttempts`        | `Permission::Admin` required.    |
//!
//! Long-poll path:
//! - `wait_ms == 0`: one [`EventStore::read_category`] call, return whatever
//!   matches.
//! - `wait_ms > 0`: read once first. If non-empty, return immediately. If
//!   empty AND the publisher exposes a broadcast receiver, subscribe and
//!   wait up to `wait_ms`. On the first matching event we re-read to
//!   backfill the page (the broadcast is a wake-up signal, not the
//!   payload — the event-store is the source of truth).
//!
//! `next_after` is the unfiltered last-seen position so a non-admin
//! caller re-querying does NOT replay events that filtered out.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;

use hort_app::metrics::{emit_events_pull, EventsPullResult};

use hort_domain::entities::rbac::Permission;
use hort_domain::entities::subscription::EventTypeKind;
use hort_domain::events::StreamCategory;
use hort_domain::ports::event_store::{EventStore, SubscribeFrom};

use hort_http_core::authz::extractors::AuthenticatedCaller;
use hort_http_core::context::{AppContext, AuthContext};

use crate::dto::{
    map_event, parse_category, stream_category_wire, EventsQuery, EventsQueryError, EventsResponse,
    PersistedEventDto,
};

/// True for categories that require `Permission::Admin`. False for
/// per-repo categories where per-event filtering applies.
///
/// The table itself lives in `hort-domain` as
/// [`StreamCategory::requires_admin`] — the single source of truth shared
/// with the subscription create/update + dispatch gate in `hort-app`
/// (which cannot import this private fn: `hort-http-events` depends on
/// `hort-app`, so the reverse would be a circular crate dependency). This
/// fn is a thin delegator so the events-read gate and the subscription gate
/// can never drift. A new `StreamCategory` variant fails to compile in the
/// domain predicate's exhaustive match, not here.
fn category_requires_admin(category: StreamCategory) -> bool {
    category.requires_admin()
}

/// `GET /api/v1/events?category=<cat>&after=<u64>&max=<u32>&wait_ms=<u32>`.
pub async fn get_events(
    State(ctx): State<Arc<AppContext>>,
    AuthenticatedCaller(principal): AuthenticatedCaller,
    Query(query): Query<EventsQuery>,
) -> Result<Json<EventsResponse>, EventsHandlerError> {
    // Wall-clock start for the `hort_events_pull_duration_seconds`
    // histogram. Captured before any work — every exit path that is
    // metered records against this. The bad-request exit (unknown
    // `category`) intentionally does NOT emit the metric: only
    // `result ∈ {success, no_match, forbidden}` is metered, and the
    // request never reaches the read path.
    let started = Instant::now();

    // 1. Parse category — closed match, 400 on unknown.
    //    Intentionally NOT metered (see comment above).
    let category = parse_category(&query.category)
        .map_err(|e| EventsHandlerError::BadRequest(e.to_string()))?;
    let category_label = stream_category_wire(category);

    // 2. Per-category authz gate. Admin-only categories require
    //    `Permission::Admin` upfront; per-repo categories defer to the
    //    per-event filter below. Under `AuthContext::Disabled` every
    //    extractor in the workspace grants — preserve that contract
    //    here too (no extra gate when auth is off).
    let admin_required = category_requires_admin(category);
    if admin_required {
        if let AuthContext::Enabled { rbac, .. } = &ctx.auth {
            let evaluator = rbac.load();
            if !evaluator.authorize(&principal, Permission::Admin, None) {
                emit_events_pull(
                    category_label,
                    EventsPullResult::Forbidden,
                    started.elapsed().as_secs_f64(),
                );
                return Err(EventsHandlerError::Forbidden);
            }
        }
    }

    let max = query.resolved_max();
    let wait_ms = query.resolved_wait_ms();
    let after = query.after;

    // 3. Fetch the page. Long-poll path subscribes to the publisher
    //    broadcast and waits for a wake-up signal; the read_category
    //    call remains the source of truth.
    //
    //    Infrastructure failure surfaces as a 500; the metric stays
    //    silent because `error` is not an enumerated result variant.
    //    Operators detect 5xx via the HTTP histogram.
    let events = if wait_ms > 0 {
        long_poll_events(&ctx, category, after, max, wait_ms).await?
    } else {
        ctx.event_store
            .read_category(category, SubscribeFrom::AfterGlobal(after), u64::from(max))
            .await
            .map_err(EventsHandlerError::Infrastructure)?
    };

    // 4. Pre-filter accounting — `next_after` is the last-seen position
    //    regardless of filtering. A non-admin caller whose Read scope
    //    shrinks between calls MUST NOT replay events that filtered out:
    //    same trade-off the dispatcher makes.
    let next_after = events
        .iter()
        .map(|e| e.global_position)
        .max()
        .unwrap_or(after);
    let has_more = (events.len() as u32) >= max;

    // 5. Per-repo filter (only for per-repo categories — admin-only
    //    categories already passed the upfront gate, and `Disabled`
    //    auth grants everything).
    //
    //    **Type-not-category admin gate.** Some privileged event TYPES ride
    //    a non-admin stream category
    //    because they are repo-associated: a repo-scoped
    //    `PermissionGrant{Applied,Revoked}` / `RepositoryUpstreamMappingChanged`
    //    lands on `StreamCategory::Repository` (non-admin), so this per-repo
    //    branch would otherwise leak grant / upstream-mapping topology to a
    //    `Read`-on-repo caller. When the event TYPE is an
    //    authorization-model mutation or a privileged-audit observation,
    //    require live `Permission::Admin` regardless of the carrying
    //    category — matching the upfront admin-category gate and the
    //    subscription dispatch gate. (Admin-only categories never reach this
    //    branch; they already passed the upfront gate.)
    //
    //    `type_gated_drops` counts events dropped specifically by the
    //    type gate so we can emit ONE aggregate `info!` audit record per
    //    request — never per-event (that would tank the read hot path),
    //    and never `err`/error-level (this is an authz audit fact, not a
    //    server error). The event id is never logged.
    let mut type_gated_drops: u32 = 0;
    let dto_events: Vec<PersistedEventDto> = if !admin_required {
        match &ctx.auth {
            AuthContext::Disabled => events.iter().map(map_event).collect(),
            AuthContext::Enabled { rbac, .. } | AuthContext::BearerOnly { rbac, .. } => {
                let evaluator = rbac.load();
                events
                    .iter()
                    .filter(|e| {
                        if e.event.is_authorization_model_mutation()
                            || e.event.is_privileged_audit()
                        {
                            let allowed = evaluator.authorize(&principal, Permission::Admin, None);
                            if !allowed {
                                type_gated_drops += 1;
                            }
                            return allowed;
                        }
                        // Per-event repo association via the same helper the
                        // dispatcher uses. Events with no repo association
                        // (e.g. `RefMoved` carries one, but
                        // `ArtifactQuarantined` does not — see
                        // `EventTypeKind::repository_id` for the full
                        // table) pass through under the closed-list
                        // categories: an artifact-stream event that lacks
                        // a direct repo column still belongs to the
                        // artifact aggregate; the dispatcher applies the
                        // same convention.
                        match EventTypeKind::repository_id(&e.event) {
                            None => true,
                            Some(repo_id) => {
                                evaluator.authorize(&principal, Permission::Read, Some(repo_id))
                            }
                        }
                    })
                    .map(map_event)
                    .collect()
            }
        }
    } else {
        events.iter().map(map_event).collect()
    };

    // One aggregate audit record per request for type-based Admin-required
    // denials. `info!`, not `err`: this is an expected authz outcome, not a
    // server error. Carries the category and a drop count only — never an
    // event id or payload.
    if type_gated_drops > 0 {
        tracing::info!(
            category = category_label,
            denied_count = type_gated_drops,
            "events read: filtered authorization-model / privileged-audit \
             event types for a non-admin caller"
        );
    }

    // 6. Emit pull metrics. `success` vs `no_match` is decided on the
    //    pre-filter `events` page: an admin-only category that read
    //    rows from the store but returned zero matches still counts as
    //    `success` (the matter is whether the read had a hit). For
    //    per-repo categories that read rows but filtered everything
    //    out per principal grants, the page-level read DID match —
    //    that stays `success` too (mirroring the rule that `next_after`
    //    is unfiltered).
    let result = if events.is_empty() {
        EventsPullResult::NoMatch
    } else {
        EventsPullResult::Success
    };
    emit_events_pull(category_label, result, started.elapsed().as_secs_f64());

    Ok(Json(EventsResponse {
        events: dto_events,
        next_after,
        has_more,
    }))
}

/// Long-poll fast/slow split. The slow path subscribes to the
/// publisher's broadcast channel and waits up to `wait_ms` for a
/// matching event to land. On a wake-up we re-read the category page
/// rather than returning the broadcast payload directly — the
/// event-store is the authoritative source.
///
/// When the publisher exposes no broadcast sender (notifications
/// disabled / mock publisher), the slow path collapses to the empty
/// result the initial read already returned.
async fn long_poll_events(
    ctx: &Arc<AppContext>,
    category: StreamCategory,
    after: u64,
    max: u32,
    wait_ms: u32,
) -> Result<Vec<hort_domain::events::PersistedEvent>, EventsHandlerError> {
    // Fast path: one read. If we already have something to ship, skip
    // the broadcast subscription entirely (cheap path on busy streams).
    let initial = ctx
        .event_store
        .read_category(category, SubscribeFrom::AfterGlobal(after), u64::from(max))
        .await
        .map_err(EventsHandlerError::Infrastructure)?;
    if !initial.is_empty() {
        return Ok(initial);
    }

    // Slow path: subscribe + wait. If notifications are off, there is
    // no sender to subscribe to — return the empty result.
    let Some(mut receiver) = ctx.event_store.subscribe() else {
        return Ok(initial);
    };

    let timeout = Duration::from_millis(u64::from(wait_ms));
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        match tokio::time::timeout_at(deadline, receiver.recv()).await {
            Ok(Ok(event)) => {
                if event.stream_id.category == category && event.global_position > after {
                    // Re-read the page to assemble the response — the
                    // broadcast is a wake-up signal, not the wire
                    // payload. This keeps the event-store
                    // authoritative on ordering / stored_at.
                    return ctx
                        .event_store
                        .read_category(category, SubscribeFrom::AfterGlobal(after), u64::from(max))
                        .await
                        .map_err(EventsHandlerError::Infrastructure);
                }
                // Wrong category or already-seen position — keep
                // waiting until the deadline.
            }
            // Channel closed or lagged: not the handler's problem;
            // collapse to empty. The next consumer call will re-read
            // from the authoritative event store anyway.
            Ok(Err(_)) => return Ok(Vec::new()),
            // Timed out — empty response, consumer polls again.
            Err(_) => return Ok(Vec::new()),
        }
    }
}

/// Handler-level error shape. 400 on bad input, 403 on
/// admin-only-without-admin, 500 on infrastructure failure. The
/// wire body uses the project's stable `{"error":..., "message":...}`
/// envelope.
#[derive(Debug, thiserror::Error)]
pub enum EventsHandlerError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("forbidden")]
    Forbidden,
    #[error("infrastructure failure")]
    Infrastructure(#[from] hort_domain::error::DomainError),
}

impl From<EventsQueryError> for EventsHandlerError {
    fn from(e: EventsQueryError) -> Self {
        EventsHandlerError::BadRequest(e.to_string())
    }
}

impl axum::response::IntoResponse for EventsHandlerError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match self {
            EventsHandlerError::BadRequest(m) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": "bad_request", "message": m}),
            ),
            EventsHandlerError::Forbidden => (
                StatusCode::FORBIDDEN,
                serde_json::json!({
                    "error": "forbidden",
                    "message": "category requires admin authority",
                }),
            ),
            EventsHandlerError::Infrastructure(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"error": "internal_server_error"}),
            ),
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_requires_admin_table_matches_design_doc_table() {
        // Per-repo categories — non-admin allowed, per-event filtered.
        for cat in [
            StreamCategory::Artifact,
            StreamCategory::ArtifactGroup,
            StreamCategory::Ref,
            StreamCategory::Curation,
            StreamCategory::Repository,
        ] {
            assert!(
                !category_requires_admin(cat),
                "{cat:?} must be per-repo (non-admin allowed)"
            );
        }
        // Admin-only categories — Permission::Admin upfront.
        for cat in [
            StreamCategory::Policy,
            StreamCategory::Admin,
            StreamCategory::Authorization,
            StreamCategory::User,
            StreamCategory::AuthAttempts,
        ] {
            assert!(
                category_requires_admin(cat),
                "{cat:?} must require Permission::Admin"
            );
        }
    }

    /// Delegation guard: the events-read gate
    /// (`category_requires_admin`) MUST be a thin delegator to the
    /// hoisted `hort-domain` `StreamCategory::requires_admin` predicate —
    /// **not** an independent re-encoding of the table. Drift between
    /// the read gate and the subscription gate is a bug; asserting
    /// equality for every variant catches a future re-encoding
    /// regression in either crate (the subscription / dispatch gate in
    /// `hort-app` calls the domain predicate directly).
    #[test]
    fn category_requires_admin_delegates_to_domain_predicate() {
        for cat in [
            StreamCategory::Artifact,
            StreamCategory::ArtifactGroup,
            StreamCategory::Ref,
            StreamCategory::Curation,
            StreamCategory::Repository,
            StreamCategory::Policy,
            StreamCategory::Admin,
            StreamCategory::Authorization,
            StreamCategory::User,
            StreamCategory::AuthAttempts,
        ] {
            assert_eq!(
                category_requires_admin(cat),
                cat.requires_admin(),
                "{cat:?}: events-read gate must delegate to \
                 StreamCategory::requires_admin (single source of truth)"
            );
        }
    }
}
