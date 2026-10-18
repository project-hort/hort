//! Batch resolution of event aggregates to their owning repository.
//!
//! [`EventTypeKind::disclosed_repositories`] classifies what an event
//! payload discloses. For the artifact-stream and artifact-group events
//! it answers with an aggregate id rather than a repository id — the
//! post-ingest artifact lifecycle (quarantine, scan verdicts, release,
//! rejection, provenance, expiry, purge) never carries a repository
//! column, because the artifact aggregate already owns exactly one. This
//! port is what turns those aggregate ids into repository ids.
//!
//! [`EventTypeKind::disclosed_repositories`]:
//!     crate::entities::subscription::EventTypeKind::disclosed_repositories
//!
//! # Why one batch method and not a per-event lookup
//!
//! Both consumers hold a *page* of events when they need the answer: the
//! `GET /api/v1/events` handler has just read one, and the notification
//! dispatcher's catch-up walk reads `CATCHUP_PAGE` at a time. A
//! per-event resolution would put one round trip on each event of the
//! read hot path. The port therefore takes the whole page's aggregate
//! ids at once and the adapter answers in a single statement.
//!
//! # Identity, not liveness
//!
//! An implementation MUST resolve by identity and MUST NOT filter on
//! `deleted_at` / `is_deleted`. Retirement does not remove the
//! projection row (purge sets `artifacts.deleted_at`), and the events of
//! a retired artifact are exactly the ones a reader is still being gated
//! against — an `ArtifactPurged` whose row filtered out would resolve to
//! nothing and fail closed for everyone, including the repository's own
//! readers.
//!
//! A genuinely absent row (the repository was deleted, cascading its
//! artifacts away) is reported by *omission*: the id simply has no entry
//! in the returned map, and the consumer fails closed on it.

use std::collections::HashMap;

use uuid::Uuid;

use crate::error::DomainResult;

use super::BoxFuture;

/// Aggregate-id → repository-id maps for one resolution call.
///
/// Absence is meaningful: an id the caller asked about and that is not a
/// key here has no projection row, and the caller must fail closed on
/// it rather than treat it as unscoped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventAggregateRepositories {
    /// `artifacts.id` → `artifacts.repository_id`.
    pub artifacts: HashMap<Uuid, Uuid>,
    /// `artifact_groups.id` → `artifact_groups.repository_id`.
    pub artifact_groups: HashMap<Uuid, Uuid>,
}

/// Resolves the repository association of the aggregates an event page's
/// payloads name.
pub trait EventRepositoryResolver: Send + Sync {
    /// Resolve both aggregate kinds in one call.
    ///
    /// The caller is expected to pass deduplicated id slices. An empty
    /// pair of slices MUST NOT reach the database — a page whose every
    /// event carries its repository in the payload costs no round trip.
    fn resolve_event_aggregates<'a>(
        &'a self,
        artifact_ids: &'a [Uuid],
        artifact_group_ids: &'a [Uuid],
    ) -> BoxFuture<'a, DomainResult<EventAggregateRepositories>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time dyn-compatibility assertion (mirrors the pattern in
    /// [`crate::ports::retention_preview`]).
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn EventRepositoryResolver>();
    }

    /// A no-op impl proves the trait can be `dyn`-cast and documents the
    /// fail-closed-by-omission contract: an implementation that knows
    /// nothing answers with empty maps, never with a default repository.
    struct EmptyResolver;
    impl EventRepositoryResolver for EmptyResolver {
        fn resolve_event_aggregates<'a>(
            &'a self,
            _artifact_ids: &'a [Uuid],
            _artifact_group_ids: &'a [Uuid],
        ) -> BoxFuture<'a, DomainResult<EventAggregateRepositories>> {
            Box::pin(async { Ok(EventAggregateRepositories::default()) })
        }
    }

    #[tokio::test]
    async fn an_implementation_that_knows_nothing_omits_rather_than_defaults() {
        let port: &dyn EventRepositoryResolver = &EmptyResolver;
        let asked = [Uuid::new_v4()];
        let resolved = port
            .resolve_event_aggregates(&asked, &[])
            .await
            .expect("the no-op resolver cannot fail");
        assert!(
            resolved.artifacts.is_empty(),
            "an unresolved id must be absent, not mapped to some fallback"
        );
        assert!(resolved.artifact_groups.is_empty());
    }
}
