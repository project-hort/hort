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
//!    leaves the projection behind its stream — never an orphan
//!    stream position; the converse would let a row claim a
//!    `stream_version` that was never persisted).
//!
//! ## The projection repairs itself from its stream
//!
//! The row carries `stream_version` and the next mutation passes it as
//! `ExpectedVersion::Exact`, so a row one version behind its stream used
//! to refuse every later mutation — `Conflict`, returned before reaching
//! the `upsert` that would have fixed it, and a strict-atomic abort of the
//! whole gitops apply.
//!
//! On `Conflict` each expected-version mutation now re-reads the stream,
//! folds it with [`RetentionPolicy::project`] — the pure replay B1 already
//! had — turns the result back into a row with
//! [`RetentionPolicyRow::from_policy`], re-decides its intent against that
//! state and appends once more (ADR 0060's read-decide-append contract).
//! Fail-closed: a stream that cannot be read, or that the replay refuses,
//! rewrites nothing. `create_policy` is excluded by construction — it
//! appends with `NoStream` onto a freshly minted `policy_id`, so there is
//! no projection version to re-base onto.
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
use hort_domain::ports::event_store::{
    AppendEvents, EventStore, EventToAppend, ExpectedVersion, ReadFrom,
};
use hort_domain::ports::retention_policy_projection_repository::{
    RetentionPolicyProjectionRepository, RetentionPolicyRow,
};
use hort_domain::retention::{
    PolicyPredicate, RetentionPolicy, RetentionPolicyEvent, RetentionScope,
};

use crate::append_conflict::{append_with_conflict_retry, ConflictCycleOutcome};
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

/// How many read-decide-append attempts one retention-policy mutation
/// gets: the first on the row the caller read, the second on the row
/// re-derived from the stream. A third would add nothing — the second
/// attempt's expected version came from the stream itself, so losing it
/// again is a concurrent writer, not something a further re-base resolves.
const RETENTION_APPEND_ATTEMPTS: u8 = 2;

/// What a self-healing retention-policy mutation left behind.
struct HealedRetentionMutation {
    /// The row to write: the replay of the stream the append extended, or
    /// — when the state already satisfied the intent — that state itself.
    row: RetentionPolicyRow,
    /// `false` when nothing was appended because the state already stated
    /// the intent (ADR 0060's idempotent success).
    appended: bool,
    /// `true` when the caller's row version was refused and the row was
    /// re-derived from the stream.
    healed: bool,
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

    /// Write the row a mutation produced.
    ///
    /// A failure here is the defect this use case's repair exists for, and
    /// the log says so: the row is left behind its stream, and the next
    /// mutation re-derives it rather than refusing forever on the stale
    /// version.
    async fn write_row(&self, policy_id: Uuid, row: &RetentionPolicyRow) -> AppResult<()> {
        self.projections.upsert(row).await.map_err(|e| {
            tracing::error!(
                policy_id = %policy_id,
                error = %e,
                "retention policy projection upsert failed after a successful \
                 event append — the row is behind its stream; the next mutation \
                 re-derives it from the stream",
            );
            AppError::from(e)
        })
    }

    /// Re-derive a retention policy's row from its own event stream.
    ///
    /// The repair half of the append-then-upsert trade-off: the stream is
    /// the source of truth, so a row that disagrees with it is simply
    /// wrong. B1 already had the pure replay ([`RetentionPolicy::project`]);
    /// this is the half that was missing — turning the replay back into the
    /// row to write.
    ///
    /// The read is unbounded (`u64::MAX`): a retention stream has no event
    /// cap, and a budget that truncated it would hand back a row derived
    /// from the oldest N events while looking exactly like one derived from
    /// the whole stream. `stream_version` comes from the tail event's own
    /// `stream_position` rather than from the replay's event count, because
    /// it is the append's expected version that has to be right.
    ///
    /// **Fail-closed.** A read failure, a stream the replay refuses, or an
    /// event on it that is not a `RetentionPolicyChanged` all propagate:
    /// the caller writes nothing rather than repairing a row to a state the
    /// stream does not support.
    async fn rebase_from_stream(&self, policy_id: Uuid) -> AppResult<RetentionPolicyRow> {
        let stream_id = StreamId::retention_policy(policy_id);
        let persisted = self
            .events
            .read_stream(&stream_id, ReadFrom::Start, u64::MAX)
            .await?;

        let mut events = Vec::with_capacity(persisted.len());
        for event in &persisted {
            match &event.event {
                DomainEvent::RetentionPolicyChanged(changed) => events.push(changed.clone()),
                other => {
                    return Err(DomainError::Invariant(format!(
                        "{} at position {} does not belong on retention policy \
                         stream {policy_id}; no row is derived from a stream this \
                         replay cannot read in full",
                        other.event_type(),
                        event.stream_position
                    ))
                    .into());
                }
            }
        }

        let replayed = RetentionPolicy::project(&events).map_err(AppError::Domain)?;
        let mut row = RetentionPolicyRow::from_policy(replayed);
        row.stream_version = persisted
            .last()
            .expect("project() refuses an empty stream, so there is a tail event")
            .stream_position;
        Ok(row)
    }

    /// Append one event to a retention-policy stream, repairing a stale
    /// projection version on the way (ADR 0060's read-decide-append
    /// contract).
    ///
    /// `decide` is the mutation's intent against whatever state the current
    /// attempt stands on, re-run per attempt so the batch and the expected
    /// version always come from the same observation. `None` means the
    /// state already states the intent: nothing is appended, and writing
    /// the returned row still repairs it.
    ///
    /// A `Conflict` that survives the re-base is a genuine concurrent
    /// writer and surfaces as [`DomainError::Contended`] — the
    /// retryable-busy outcome ADR 0060 (d) mandates.
    async fn mutate_policy_stream(
        &self,
        policy_id: Uuid,
        base: &RetentionPolicyRow,
        actor: &Actor,
        decide: impl Fn(&RetentionPolicyRow) -> AppResult<Option<RetentionPolicyEvent>>,
    ) -> AppResult<HealedRetentionMutation> {
        // Shared references so each attempt's future can capture by copy.
        let stream_id = &StreamId::retention_policy(policy_id);
        let decide = &decide;
        append_with_conflict_retry(RETENTION_APPEND_ATTEMPTS, |attempt| async move {
            let healed = attempt > 1;
            let row = if healed {
                let row = self.rebase_from_stream(policy_id).await?;
                tracing::info!(
                    policy_id = %policy_id,
                    projection_version = base.stream_version,
                    stream_version = row.stream_version,
                    "retention policy projection re-derived from its event stream \
                     after an expected-version refusal; retrying the mutation \
                     against the stream's state",
                );
                row
            } else {
                base.clone()
            };

            let Some(event) = decide(&row)? else {
                return Ok(ConflictCycleOutcome::Satisfied(HealedRetentionMutation {
                    row,
                    appended: false,
                    healed,
                }));
            };
            event.validate().map_err(AppError::Domain)?;

            let result = match self
                .events
                .append(AppendEvents {
                    stream_id: stream_id.clone(),
                    expected_version: ExpectedVersion::Exact(row.stream_version),
                    events: vec![EventToAppend::new(DomainEvent::RetentionPolicyChanged(
                        event.clone(),
                    ))],
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor: actor.clone(),
                })
                .await
            {
                Ok(result) => result,
                Err(DomainError::Conflict(msg)) if healed => {
                    // The expected version came from the stream itself a
                    // moment ago, so this is not a stale row: somebody else
                    // appended in between. "Concurrent modification" names
                    // only this case.
                    tracing::warn!(
                        policy_id = %policy_id,
                        expected = row.stream_version,
                        conflict_message = %msg,
                        "concurrent retention policy modification rejected",
                    );
                    return Ok(ConflictCycleOutcome::Retry);
                }
                Err(DomainError::Conflict(msg)) => {
                    tracing::warn!(
                        policy_id = %policy_id,
                        expected = row.stream_version,
                        conflict_message = %msg,
                        "retention policy projection version refused by the event \
                         store — re-deriving the row from its stream",
                    );
                    return Ok(ConflictCycleOutcome::Retry);
                }
                Err(other) => return Err(other.into()),
            };

            // The row to write is the replay of the stream the append just
            // extended — the same fold that reads it back, so the row
            // cannot drift from the event that produced it.
            let mut replayed = row.clone().into_policy();
            replayed.apply_appended(&event).map_err(AppError::Domain)?;
            let mut row = RetentionPolicyRow::from_policy(replayed);
            row.stream_version = result.stream_position;
            Ok(ConflictCycleOutcome::Satisfied(HealedRetentionMutation {
                row,
                appended: true,
                healed,
            }))
        })
        .await
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
    /// `ExpectedVersion::Exact(stream_version)`, then upserts the row
    /// **replayed from that same event**.
    ///
    /// - Same-value update yields **zero** events (idempotent — no
    ///   append, no upsert, `Ok(())`).
    /// - A refused `ExpectedVersion::Exact` re-derives the row from the
    ///   stream, re-decides against it and appends once more; a second
    ///   refusal is a concurrent writer and surfaces as
    ///   [`DomainError::Contended`]. A stream that already states this
    ///   predicate + scope is an idempotent success that repairs the row.
    /// - Updating an archived policy is rejected
    ///   ([`DomainError::Validation`]) — B1's terminal-archive model —
    ///   and the rejection is re-checked against the stream-derived
    ///   state, so a policy archived concurrently is not updated on the
    ///   retry.
    #[tracing::instrument(skip(self, cmd))]
    pub async fn update_policy(
        &self,
        cmd: UpdateRetentionPolicyCommand,
        actor: Actor,
    ) -> AppResult<()> {
        let row = self
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

        let outcome = self
            .mutate_policy_stream(cmd.policy_id, &row, &actor, |state| {
                if state.archived {
                    return Err(DomainError::Validation(format!(
                        "retention policy '{}' is archived",
                        state.name
                    ))
                    .into());
                }
                if state.predicate == cmd.predicate && state.scope == cmd.scope {
                    return Ok(None);
                }
                Ok(Some(RetentionPolicyEvent::Updated {
                    id: cmd.policy_id,
                    predicate: cmd.predicate.clone(),
                    scope: cmd.scope.clone(),
                    updated_at: Utc::now(),
                }))
            })
            .await?;

        self.write_row(cmd.policy_id, &outcome.row).await?;

        tracing::info!(
            policy_id = %cmd.policy_id,
            event_type = "RetentionPolicyUpdated",
            appended = outcome.appended,
            healed = outcome.healed,
            "retention policy updated",
        );
        Ok(())
    }

    /// Archive an existing policy. Appends one
    /// `RetentionPolicyChanged(Archived)` with
    /// `ExpectedVersion::Exact`, then upserts the replayed row.
    /// Idempotent-ish: archiving an already-archived policy is
    /// rejected ([`DomainError::Validation`]) — the apply pipeline
    /// only archives active projections so this is defence-in-depth.
    ///
    /// A refused expected version re-derives the row from the stream and
    /// retries once. If the stream turns out to already say archived, the
    /// intent is satisfied: the call succeeds and the stale row is
    /// repaired rather than being answered with a `Validation` error about
    /// a state the caller could not have seen.
    #[tracing::instrument(skip(self))]
    pub async fn archive_policy(
        &self,
        policy_id: Uuid,
        archived_by: Uuid,
        actor: Actor,
    ) -> AppResult<()> {
        let row = self
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

        let outcome = self
            .mutate_policy_stream(policy_id, &row, &actor, |state| {
                if state.archived {
                    return Ok(None);
                }
                Ok(Some(RetentionPolicyEvent::Archived {
                    id: policy_id,
                    by: archived_by,
                    archived_at: Utc::now(),
                }))
            })
            .await?;

        self.write_row(policy_id, &outcome.row).await?;

        tracing::info!(
            policy_id = %policy_id,
            event_type = "RetentionPolicyArchived",
            appended = outcome.appended,
            healed = outcome.healed,
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
