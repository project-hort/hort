//! `RetentionPolicyUseCase`.
//!
//! The gitops-authored create / update / archive path for the
//! event-sourced retention-policy aggregate. Mirrors the
//! [`PolicyUseCase`](super::policy_use_case::PolicyUseCase)
//! append-then-upsert shape 1:1:
//!
//! 1. append a [`DomainEvent::RetentionPolicyChanged`] (wrapping B1's
//!    [`RetentionPolicyEvent`]) to
//!    [`StreamId::retention_policy`](hort_domain::events::StreamId::retention_policy)
//!    — `ExpectedVersion::NoStream` for create, `Exact(stream_version)`
//!    for update / archive;
//! 2. then `RetentionPolicyProjectionRepository::upsert` the new
//!    projection state in lockstep (the append-then-upsert
//!    trade-off: a successful append followed by a failing upsert
//!    leaves the projection stale-until-rebuild — never an orphan
//!    stream position; the converse would let a row claim a
//!    `stream_version` that was never persisted).
//!
//! ## No reactivation (B1 terminal-archive model)
//!
//! B1's aggregate is **create / update / archive / evaluate only** —
//! there is no `Reactivated` event (unlike the scan-policy
//! aggregate). A gitops
//! re-declaration of an archived policy name is handled by the apply
//! pipeline as a **fresh `policy_id`** (the archived row stays as
//! audit history; the partial-unique-on-active-name index does not
//! collide because it only covers `archived = false`). This use case
//! therefore exposes no `reactivate` method by design.
//!
//! Actor: the apply pipeline passes the gitops actor (these mutations
//! are gitops-authored, exactly like `ScanPolicy`). The
//! `RetentionScheduler` actor is for the runtime `Evaluated`
//! breadcrumb (`RetentionEvaluateHandler`), NOT these lifecycle
//! mutations.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use hort_domain::error::DomainError;
use hort_domain::events::{Actor, DomainEvent, StreamId};
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::ports::retention_policy_projection_repository::{
    RetentionPolicyProjectionRepository, RetentionPolicyRow,
};
use hort_domain::retention::{PolicyPredicate, RetentionPolicyEvent, RetentionScope};

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;

/// Command to create a new retention policy.
#[derive(Debug, Clone)]
pub struct CreateRetentionPolicyCommand {
    pub name: String,
    pub predicate: PolicyPredicate,
    pub scope: RetentionScope,
}

/// Command to replace an existing retention policy's predicate +
/// scope wholesale (B1's `Updated` semantics — retention has a single
/// predicate tree per policy, so an update replaces it rather than
/// field-patching).
#[derive(Debug, Clone)]
pub struct UpdateRetentionPolicyCommand {
    pub policy_id: Uuid,
    pub predicate: PolicyPredicate,
    pub scope: RetentionScope,
}

/// The gitops-authored retention-policy lifecycle use
/// case. Append-then-upsert over the event store + the
/// `retention_policy_projections` port.
pub struct RetentionPolicyUseCase {
    events: Arc<EventStorePublisher>,
    projections: Arc<dyn RetentionPolicyProjectionRepository>,
}

impl RetentionPolicyUseCase {
    pub fn new(
        events: Arc<EventStorePublisher>,
        projections: Arc<dyn RetentionPolicyProjectionRepository>,
    ) -> Self {
        Self {
            events,
            projections,
        }
    }

    /// Create a new retention policy: mint a fresh `policy_id`, append
    /// one `RetentionPolicyChanged(Created)` with
    /// `ExpectedVersion::NoStream`, then upsert the projection.
    ///
    /// Rejects with [`DomainError::Conflict`] if a non-archived policy
    /// already exists with the same name (pre-checked before the
    /// append so a duplicate name does not burn a stream position; the
    /// partial-unique index is the DB-side backstop). The embedded
    /// predicate/scope are domain-validated on append (the
    /// `DomainEvent::validate` dispatch).
    #[tracing::instrument(skip(self, cmd))]
    pub async fn create_policy(
        &self,
        cmd: CreateRetentionPolicyCommand,
        actor: Actor,
    ) -> AppResult<Uuid> {
        if let Some(existing) = self.projections.find_by_name(&cmd.name).await? {
            tracing::info!(
                policy_id = %existing.policy_id,
                name = %cmd.name,
                "create_retention_policy rejected: name already in use",
            );
            return Err(DomainError::Conflict(format!(
                "retention policy with name '{}' already exists",
                cmd.name
            ))
            .into());
        }

        let policy_id = Uuid::new_v4();
        let now = Utc::now();
        let event = RetentionPolicyEvent::Created {
            id: policy_id,
            name: cmd.name.clone(),
            predicate: cmd.predicate.clone(),
            scope: cmd.scope.clone(),
            created_at: now,
        };
        // Domain-validate before the append (defence in depth — the
        // event store also validates on append).
        event.validate().map_err(AppError::Domain)?;

        let result = self
            .events
            .append(AppendEvents {
                stream_id: StreamId::retention_policy(policy_id),
                expected_version: ExpectedVersion::NoStream,
                events: vec![EventToAppend::new(DomainEvent::RetentionPolicyChanged(
                    event,
                ))],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor,
            })
            .await?;

        let row = RetentionPolicyRow {
            policy_id,
            name: cmd.name,
            predicate: cmd.predicate,
            scope: cmd.scope,
            archived: false,
            stream_version: result.stream_position,
            last_evaluated_at: None,
            last_matched_count: 0,
            last_expired_count: 0,
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = self.projections.upsert(&row).await {
            tracing::error!(
                policy_id = %policy_id,
                error = %e,
                "retention policy projection upsert failed after successful \
                 event append — projection stale until rebuild",
            );
            return Err(e.into());
        }

        tracing::info!(
            policy_id = %policy_id,
            event_type = "RetentionPolicyCreated",
            "retention policy created",
        );
        Ok(policy_id)
    }

    /// Replace an existing policy's predicate + scope. Appends one
    /// `RetentionPolicyChanged(Updated)` with
    /// `ExpectedVersion::Exact(stream_version)`, then upserts.
    ///
    /// - Same-value update yields **zero** events (idempotent — no
    ///   append, no upsert, `Ok(())`).
    /// - Stale `ExpectedVersion::Exact` → [`DomainError::Conflict`].
    /// - Updating an archived policy is rejected
    ///   ([`DomainError::Validation`]) — B1's terminal-archive model.
    #[tracing::instrument(skip(self, cmd))]
    pub async fn update_policy(
        &self,
        cmd: UpdateRetentionPolicyCommand,
        actor: Actor,
    ) -> AppResult<()> {
        let mut row = self
            .find_active_row_by_id(cmd.policy_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                entity: "RetentionPolicy",
                id: cmd.policy_id.to_string(),
            })?;

        if row.archived {
            return Err(DomainError::Validation(format!(
                "retention policy '{}' is archived",
                row.name
            ))
            .into());
        }

        if row.predicate == cmd.predicate && row.scope == cmd.scope {
            tracing::debug!(
                policy_id = %cmd.policy_id,
                "update_retention_policy: no change — skipping append",
            );
            return Ok(());
        }

        let now = Utc::now();
        let event = RetentionPolicyEvent::Updated {
            id: cmd.policy_id,
            predicate: cmd.predicate.clone(),
            scope: cmd.scope.clone(),
            updated_at: now,
        };
        event.validate().map_err(AppError::Domain)?;

        let result = self
            .events
            .append(AppendEvents {
                stream_id: StreamId::retention_policy(cmd.policy_id),
                expected_version: ExpectedVersion::Exact(row.stream_version),
                events: vec![EventToAppend::new(DomainEvent::RetentionPolicyChanged(
                    event,
                ))],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor,
            })
            .await?;

        row.predicate = cmd.predicate;
        row.scope = cmd.scope;
        row.stream_version = result.stream_position;
        row.updated_at = now;
        if let Err(e) = self.projections.upsert(&row).await {
            tracing::error!(
                policy_id = %cmd.policy_id,
                error = %e,
                "retention policy projection upsert failed after successful \
                 event append — projection stale until rebuild",
            );
            return Err(e.into());
        }

        tracing::info!(
            policy_id = %cmd.policy_id,
            event_type = "RetentionPolicyUpdated",
            "retention policy updated",
        );
        Ok(())
    }

    /// Archive an existing policy. Appends one
    /// `RetentionPolicyChanged(Archived)` with
    /// `ExpectedVersion::Exact`, then upserts `archived = true`.
    /// Idempotent-ish: archiving an already-archived policy is
    /// rejected ([`DomainError::Validation`]) — the apply pipeline
    /// only archives active projections so this is defence-in-depth.
    #[tracing::instrument(skip(self))]
    pub async fn archive_policy(
        &self,
        policy_id: Uuid,
        archived_by: Uuid,
        actor: Actor,
    ) -> AppResult<()> {
        let mut row = self
            .find_active_row_by_id(policy_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                entity: "RetentionPolicy",
                id: policy_id.to_string(),
            })?;
        if row.archived {
            return Err(DomainError::Validation(format!(
                "retention policy '{}' is already archived",
                row.name
            ))
            .into());
        }

        let now = Utc::now();
        let event = RetentionPolicyEvent::Archived {
            id: policy_id,
            by: archived_by,
            archived_at: now,
        };
        event.validate().map_err(AppError::Domain)?;

        let result = self
            .events
            .append(AppendEvents {
                stream_id: StreamId::retention_policy(policy_id),
                expected_version: ExpectedVersion::Exact(row.stream_version),
                events: vec![EventToAppend::new(DomainEvent::RetentionPolicyChanged(
                    event,
                ))],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor,
            })
            .await?;

        row.archived = true;
        row.stream_version = result.stream_position;
        row.updated_at = now;
        if let Err(e) = self.projections.upsert(&row).await {
            tracing::error!(
                policy_id = %policy_id,
                error = %e,
                "retention policy projection upsert failed after successful \
                 event append — projection stale until rebuild",
            );
            return Err(e.into());
        }

        tracing::info!(
            policy_id = %policy_id,
            event_type = "RetentionPolicyArchived",
            "retention policy archived",
        );
        Ok(())
    }

    /// Resolve the active projection row for `policy_id`. The port
    /// exposes name-keyed lookups (the apply diff is name-keyed); the
    /// id lookup is `list_active_rows().find(id)` — the active set is
    /// small (operator-authored retention policies) so this is O(n)
    /// over a tiny n, no extra port method needed.
    async fn find_active_row_by_id(
        &self,
        policy_id: Uuid,
    ) -> AppResult<Option<RetentionPolicyRow>> {
        Ok(self
            .projections
            .list_active_rows()
            .await?
            .into_iter()
            .find(|r| r.policy_id == policy_id))
    }
}

#[cfg(test)]
#[path = "retention_policy_use_case_tests.rs"]
mod tests;
