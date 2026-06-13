//! Outbound port for the `retention_policy_projections` table.
//!
//! The projection is the materialised current state derived from the
//! per-policy event stream
//! ([`StreamCategory::RetentionPolicy`](crate::events::StreamCategory::RetentionPolicy),
//! [`DomainEvent::RetentionPolicyChanged`](crate::events::DomainEvent::RetentionPolicyChanged)
//! wrapping B1's
//! [`RetentionPolicyEvent`](crate::retention::RetentionPolicyEvent)). It
//! exists so `RetentionEvaluateHandler` can read every active policy
//! ([`list_active`](RetentionPolicyProjectionRepository::list_active))
//! as an O(1) indexed read each sweep instead of replaying every
//! stream — the exact same rationale as the scan-policy
//! [`PolicyProjectionRepository`](super::policy_projection_repository::PolicyProjectionRepository).
//!
//! ## Write contract
//!
//! `RetentionPolicyUseCase` (the gitops-authored
//! create/update/archive path) calls
//! [`upsert`](RetentionPolicyProjectionRepository::upsert) immediately
//! after each successful event append, in lockstep with the
//! event-store append (append-then-upsert; `stream_version` on the
//! supplied row is the post-append `AppendResult.stream_position` —
//! the optimistic-concurrency anchor for the next mutation — the
//! same trade-off as the scan-policy projection). All writes are
//! gitops-authored; there is no
//! imperative HTTP API.
//!
//! ## Dedicated type, deliberate divergence
//!
//! This is a **separate** port from
//! [`PolicyProjectionRepository`](super::policy_projection_repository::PolicyProjectionRepository),
//! not a generalisation of it: the
//! retention model is deliberately type-distinct from the
//! scan-policy model (`RetentionScope` ≠ `events::PolicyScope`), and
//! the scan-policy projection (`severity_threshold` / `scan_backends`
//! / `quarantine_duration_secs`) is structurally incompatible with a
//! retention-policy predicate-tree projection.

use uuid::Uuid;

use crate::error::DomainResult;
use crate::retention::RetentionPolicy;

use super::BoxFuture;

/// Persistence DTO for one `retention_policy_projections` row.
///
/// Carries every field the gitops apply-pipeline diff needs (id,
/// name, the serde-shaped predicate + scope, archived flag, the
/// optimistic-concurrency `stream_version`). [`Self::into_policy`]
/// reconstructs B1's replayed [`RetentionPolicy`] aggregate directly
/// from the columns — the projection IS the materialised replay (the
/// adapter does not re-fold the event stream on every read; same shape
/// as `PgPolicyProjectionRepository` constructing `ScanPolicyProjection`
/// from columns).
#[derive(Debug, Clone, PartialEq)]
pub struct RetentionPolicyRow {
    pub policy_id: Uuid,
    pub name: String,
    /// serde of B1's [`PolicyPredicate`](crate::retention::PolicyPredicate).
    pub predicate: crate::retention::PolicyPredicate,
    /// serde of B1's [`RetentionScope`](crate::retention::RetentionScope).
    pub scope: crate::retention::RetentionScope,
    pub archived: bool,
    /// 0-based position of the last applied event — the
    /// optimistic-concurrency anchor (scan-policy-projection parity).
    /// A single-event
    /// (`Created`-only) stream is at version 0.
    pub stream_version: u64,
    pub last_evaluated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_matched_count: u32,
    pub last_expired_count: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl RetentionPolicyRow {
    /// Reconstruct B1's replayed [`RetentionPolicy`] aggregate from the
    /// projection columns. Pure — the projection IS the materialised
    /// fold, so this is a direct field copy, NOT an event replay (the
    /// `PgPolicyProjectionRepository` pattern).
    #[must_use]
    pub fn into_policy(self) -> RetentionPolicy {
        RetentionPolicy {
            id: self.policy_id,
            name: self.name,
            predicate: self.predicate,
            scope: self.scope,
            archived: self.archived,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_evaluated_at: self.last_evaluated_at,
            last_matched_count: self.last_matched_count,
            last_expired_count: self.last_expired_count,
            stream_version: self.stream_version,
        }
    }
}

/// Outbound port for the `retention_policy_projections` table. All
/// writes are gitops-authored via `RetentionPolicyUseCase`; there is
/// no imperative HTTP API (same posture as the scan-policy
/// `PolicyProjectionRepository`).
pub trait RetentionPolicyProjectionRepository: Send + Sync {
    /// Every active (non-archived) retention policy, projected to B1's
    /// replayed [`RetentionPolicy`] aggregate. Used by
    /// `RetentionEvaluateHandler` once per sweep — the whole point of
    /// the projection (vs. replaying every stream).
    fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicy>>>;

    /// Look up an active (non-archived) policy by name. Backed by the
    /// partial index `idx_retention_policy_projections_active_name`
    /// (`005_policy.sql`) so archived rows do not collide with a
    /// re-declared policy of the same name. `Ok(None)` when no active
    /// row exists.
    fn find_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>>;

    /// Look up a policy by name **including archived rows**. Used by
    /// the gitops apply pipeline to distinguish "never existed" from
    /// "archived row of the same name exists" (the terminal-archive
    /// model: a re-declared archived name mints a fresh `policy_id` —
    /// there is no retention `Reactivated` event, unlike the
    /// scan-policy model). The
    /// caller inspects [`RetentionPolicyRow::archived`].
    fn find_by_name_including_archived(
        &self,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>>;

    /// Every active (non-archived) projection row (carries
    /// `stream_version` for the apply-pipeline diff). Used by the
    /// gitops apply pass to find projected policies absent from the
    /// desired YAML (→ archive).
    fn list_active_rows(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicyRow>>>;

    /// INSERT-or-UPDATE the projection row in lockstep with the
    /// event-store append. `stream_version` on the supplied row is the
    /// post-append `AppendResult.stream_position` — the use case
    /// writes both as part of the same append-then-upsert step.
    fn upsert(&self, row: &RetentionPolicyRow) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention::{PolicyPredicate, RetentionScope};

    /// Compile-time dyn-compatibility assertion. Mirrors the pattern
    /// in [`super::super::policy_projection_repository`].
    fn _assert_dyn_compatible(_: Box<dyn RetentionPolicyProjectionRepository>) {}

    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn RetentionPolicyProjectionRepository>();
    }

    fn sample_row() -> RetentionPolicyRow {
        RetentionPolicyRow {
            policy_id: Uuid::nil(),
            name: "retain-proxied-30d".into(),
            predicate: PolicyPredicate::AgeExceeds(2_592_000),
            scope: RetentionScope::AllRepos,
            archived: false,
            stream_version: 3,
            last_evaluated_at: None,
            last_matched_count: 0,
            last_expired_count: 0,
            created_at: chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
            updated_at: chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
        }
    }

    /// `into_policy` is a faithful field copy — the projection IS the
    /// materialised replay (no event re-fold).
    #[test]
    fn row_into_policy_is_faithful_field_copy() {
        let row = sample_row();
        let policy = row.clone().into_policy();
        assert_eq!(policy.id, row.policy_id);
        assert_eq!(policy.name, row.name);
        assert_eq!(policy.predicate, row.predicate);
        assert_eq!(policy.scope, row.scope);
        assert_eq!(policy.archived, row.archived);
        assert_eq!(policy.stream_version, row.stream_version);
        assert_eq!(policy.last_evaluated_at, row.last_evaluated_at);
        assert_eq!(policy.last_matched_count, row.last_matched_count);
        assert_eq!(policy.last_expired_count, row.last_expired_count);
        assert_eq!(policy.created_at, row.created_at);
        assert_eq!(policy.updated_at, row.updated_at);
    }

    #[test]
    fn row_is_clone_and_partial_eq() {
        let a = sample_row();
        let b = a.clone();
        assert_eq!(a, b);
    }

    /// A trait-object smoke test proving `BoxFuture` dispatch + the
    /// signature compile (mirrors the `rescan_candidates` precedent).
    #[tokio::test]
    async fn list_active_dispatches_through_trait_object() {
        struct Stub;
        impl RetentionPolicyProjectionRepository for Stub {
            fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicy>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn find_by_name(
                &self,
                _name: &str,
            ) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>> {
                Box::pin(async { Ok(None) })
            }
            fn find_by_name_including_archived(
                &self,
                _name: &str,
            ) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>> {
                Box::pin(async { Ok(None) })
            }
            fn list_active_rows(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicyRow>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn upsert(&self, _row: &RetentionPolicyRow) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
        }
        let port: Box<dyn RetentionPolicyProjectionRepository> = Box::new(Stub);
        assert!(port.list_active().await.expect("Ok").is_empty());
        assert!(port.find_by_name("x").await.expect("Ok").is_none());
        assert!(port
            .find_by_name_including_archived("x")
            .await
            .expect("Ok")
            .is_none());
        assert!(port.list_active_rows().await.expect("Ok").is_empty());
        port.upsert(&sample_row()).await.expect("Ok");
    }
}
