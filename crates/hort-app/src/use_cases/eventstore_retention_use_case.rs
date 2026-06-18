//! `EventStoreRetentionUseCase::archive_terminal_streams` — the
//! **audit-retention stream sweep**: seals whole
//! terminal / age-gated streams once their audit-retention
//! floor has elapsed, routing every seal through the **adapter seal
//! chokepoint**
//! (`EventStore::delete_stream` / `archive_stream`) so the
//! `StreamSealed` tombstone is emitted exactly once by the adapter.
//! The sweep NEVER reimplements or bypasses the tombstone.
//!
//! It is NOT a scheduler — `EventStoreArchiveHandler` (a
//! `TaskHandler`) calls this pure orchestration. The
//! `hort_retention_role` DSN/pool is wired by the `hort-worker`
//! composition root: when `HORT_RETENTION_DATABASE_URL` is set the seal
//! chokepoint runs as the DELETE-capable retention role; when it is
//! unset the unprivileged runtime role's still-active
//! `events_immutable` trigger blocks the chokepoint DELETE and the seal
//! transaction rolls back fail-safe; the per-stream error path maps
//! that to `summary.errors += 1` + `tracing::error!` + continue (the
//! retention sweep is correctly non-destructive without the retention
//! role — see [`EventStoreRetentionUseCase::seal_one`]).
//!
//! # Two seal modes
//!
//! Per-category retention rules are a use-case-held registration
//! ([`CategoryRetentionRule`]: category → { floor, [`SealMode`] }).
//! Both modes ship, so a new audit category only has to *register* its
//! category+floor+mode and never re-open the sweep:
//!
//! - [`SealMode::TerminalGated`] — artifact-category streams: seal
//!   only if the stream's **last** event type equals the category
//!   terminal (`ArtifactPurged` for `StreamCategory::Artifact`).
//! - [`SealMode::AgeGated`] — rotated audit streams (`auth-{date}`,
//!   per-use token streams) have **no terminal**; seal
//!   purely on the audit-retention floor vs the stream's *oldest* event.
//!
//! The composition root builds the rule set from
//! `AuditRetentionFloors::floor_for` (the single, exhaustive
//! `StreamCategory → floor` mapping site).
//!
//! # Precondition proof, per candidate, in order:
//!
//! 1. **Meta-stream guard** — `stream_id ==
//!    StreamId::eventstore_retention()` ⇒ skip + `warn!`
//!    (`skipped_meta_stream`). Sealing the never-deleted audit-meta
//!    stream would truncate the very audit trail of every seal. The
//!    adapter pre-filters it too — this is double defence-in-depth.
//! 2. **Registered-rule lookup** — no rule for the candidate's
//!    category ⇒ skip + `debug!` (`skipped_unregistered_category`),
//!    continue.
//! 3. **Terminal proof** (`TerminalGated` only) — `read_stream(.. ,
//!    Start, LIMIT)`: an empty read ⇒ `already_sealed` + `debug!`
//!    (idempotent re-run); a last event whose
//!    [`DomainEvent::event_type`] ≠ the category terminal ⇒
//!    `skipped_non_terminal` + `warn!` (NOT an error), continue.
//! 4. **C-1 floor proof** — `now - first_event_at < floor` ⇒
//!    `skipped_floor_not_elapsed` + `debug!`, continue. The floor is
//!    proven against the **oldest** event's `stored_at` (every later
//!    event is at-or-after it); never a payload timestamp, never the
//!    chain head.
//!
//! Only when every applicable precondition passes does the use case
//! call the retention chokepoint per the one global [`StreamRetentionModeRef`]
//! (`Delete` → `delete_stream`, `Archive` → `archive_stream` with a
//! target of `format!("{prefix}/{stream_id}")` — opaque per
//! `event_store.rs:191-199`; designing the cold-storage *write* is
//! future work). A chokepoint `Err` is per-stream:
//! `summary.errors += 1`, `tracing::error!`, **continue** (mirrors
//! `purge_use_case.rs` per-artifact handling). A `list_*` enumeration
//! error aborts the whole sweep (`Err`) — distinct from per-stream
//! continuation.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use hort_domain::events::StreamId;
use hort_domain::ports::event_store::{EventStore, ReadFrom};
use hort_domain::ports::terminal_stream_reader::{TerminalStreamCandidate, TerminalStreamReader};

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{emit_streams_archived, StreamsArchivedResult};

/// How many events to read when proving a `TerminalGated` stream's
/// tail. We only need the last event's type; the stream is read from
/// `Start` (so an empty read is the idempotent already-sealed signal),
/// and the largest `stream_position` in the page is the tail. Terminal
/// artifact streams are short (ingest → … → purge); ~200 covers any
/// realistic lifecycle with margin, and the read is bounded so a
/// pathological stream cannot OOM the sweep.
const TERMINAL_PROOF_READ_LIMIT: u64 = 200;

/// Per-category seal rule. `TerminalGated` artifact-category streams
/// seal only on a matching terminal tail; `AgeGated` rotated audit
/// streams seal purely on the C-1 floor (no terminal exists).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealMode {
    /// Seal only if the stream's last event type equals
    /// `terminal_event_type` (e.g. `"ArtifactPurged"` —
    /// [`DomainEvent::event_type`] of the artifact terminal).
    TerminalGated { terminal_event_type: &'static str },
    /// Seal purely on the C-1 floor vs the oldest event — the stream
    /// has no terminal (rotated audit streams: B14 `auth-{date}`, B13
    /// per-use). The terminal `read_stream` proof is skipped entirely.
    AgeGated,
}

/// The artifact-lifecycle terminal event type. A `TerminalGated`
/// artifact-category stream is sealed only when its **last** event's
/// [`hort_domain::events::DomainEvent::event_type`] equals this — i.e.
/// the artifact has been purged (the terminal of
/// [`hort_domain::events::StreamCategory::Artifact`]).
const ARTIFACT_LIFECYCLE_TERMINAL: &str = "ArtifactPurged";

/// **The canonical production retention rule-set builder.**
///
/// The concrete form of the sweep's registration seam:
/// [`SealMode`] / [`CategoryRetentionRule`] and the
/// [`EventStoreRetentionUseCase::new`] `rules` parameter accept any
/// rule set; this builder assembles the canonical production
/// `Vec<CategoryRetentionRule>` (no test helper is authoritative).
///
/// # Layering (load-bearing)
///
/// This is a **pure `hort-app` function**. It takes the resolved
/// audit-retention floor values as explicit [`chrono::Duration`]
/// parameters, **never**
/// the `hort-server` `AuditRetentionFloors` struct. `CategoryRetentionRule`
/// / `SealMode` live in `hort-app`; `AuditRetentionFloors` lives in
/// `hort-server` config; the dependency direction is
/// `hort-server`/`hort-worker` → `hort-app`, so `hort-app` MUST NOT depend on
/// `hort-server`. Passing the floors in as `Duration`s keeps this fn
/// pure, deterministic, and 100%-unit-testable without an adapter.
///
/// # Who calls this
///
/// **The `hort-worker` composition root** calls this with the resolved
/// `AuditRetentionFloors` values — e.g.
/// `canonical_retention_rules(floors.authentication(),
/// floors.artifact_lifecycle(), floors.artifact_downloaded())` — and
/// threads the result into [`EventStoreRetentionUseCase::new`].
///
/// # Seeded categories
///
/// - [`hort_domain::events::StreamCategory::AuthAttempts`] →
///   `{ floor: authentication_floor, mode: SealMode::AgeGated }`. The
///   rotated `auth-{date}` audit
///   streams ([`hort_domain::events::StreamId::auth_attempts`])
///   have no terminal event; they seal purely on the ≥6mo
///   Authentication audit-retention floor vs the stream's oldest event.
/// - [`hort_domain::events::StreamCategory::Artifact`] →
///   `{ floor: artifact_lifecycle_floor, mode: SealMode::TerminalGated
///   { terminal_event_type: "ArtifactPurged" } }` — the core
///   artifact-lifecycle terminal-gated path
///   ([`ARTIFACT_LIFECYCLE_TERMINAL`]).
/// - `ArtifactDownloaded` per-`(repo, UTC-date)` download-audit
///   category — `{ floor: download_audit_floor (≥90d),
///   mode: SealMode::AgeGated }`.
/// - `ApiTokenUsed` per-use credential-audit category —
///   `{ floor: api_token_used_floor (≥36mo),
///   mode: SealMode::AgeGated }` on `StreamCategory::TokenUse`.
///
/// New categories register here by adding a floor parameter and pushing
/// one more [`CategoryRetentionRule`] onto the returned `Vec` — never by
/// re-opening the sweep itself. The
/// `AuditRetentionFloors::floor_for` mapping in `hort-server` config is
/// the single exhaustive `StreamCategory → floor` site the worker
/// composition resolves the per-category `Duration`s from before
/// calling this builder; the other artifact-lifecycle categories
/// (`Ref` / `ArtifactGroup` / `Curation` / `Repository`) share the
/// `artifact_lifecycle` floor there — registering them here as
/// additional `TerminalGated` rules (if their per-category terminals
/// differ) is a composition concern, not this builder's scope.
///
/// Order is deterministic (AuthAttempts, Artifact, DownloadAudit,
/// TokenUse) so the output is byte-stable for given `Duration`s.
pub fn canonical_retention_rules(
    authentication_floor: chrono::Duration,
    artifact_lifecycle_floor: chrono::Duration,
    download_audit_floor: chrono::Duration,
    api_token_used_floor: chrono::Duration,
) -> Vec<CategoryRetentionRule> {
    vec![
        // ≥6mo Authentication audit-retention floor.
        // Rotated `auth-{date}` audit streams — no terminal, AgeGated.
        CategoryRetentionRule {
            category: hort_domain::events::StreamCategory::AuthAttempts,
            floor: authentication_floor,
            mode: SealMode::AgeGated,
        },
        // Artifact-lifecycle terminal-gated rule.
        CategoryRetentionRule {
            category: hort_domain::events::StreamCategory::Artifact,
            floor: artifact_lifecycle_floor,
            mode: SealMode::TerminalGated {
                terminal_event_type: ARTIFACT_LIFECYCLE_TERMINAL,
            },
        },
        // Extension point: opt-in per-(repo, UTC-date) download-audit
        // streams seal on the ≥90d `artifact_downloaded` floor. Rotated
        // audit streams — no terminal event, AgeGated (same shape as the
        // AuthAttempts rule above). The composition root resolves this
        // `Duration` from `AuditRetentionFloors::floor_for(C::DownloadAudit)`.
        CategoryRetentionRule {
            category: hort_domain::events::StreamCategory::DownloadAudit,
            floor: download_audit_floor,
            mode: SealMode::AgeGated,
        },
        // Throttled per-(token_id, UTC-date) token-use audit streams seal
        // on the ≥36mo `api_token_used` credential-audit floor. Rotated
        // audit streams — no terminal event, AgeGated (same shape as the
        // AuthAttempts / DownloadAudit rules above). The composition root
        // resolves this `Duration` from
        // `AuditRetentionFloors::floor_for(C::TokenUse)` (which routes
        // to the same `api_token_used` field as `C::User`).
        CategoryRetentionRule {
            category: hort_domain::events::StreamCategory::TokenUse,
            floor: api_token_used_floor,
            mode: SealMode::AgeGated,
        },
    ]
}

/// One registered per-category retention rule: the C-1 floor and the
/// seal mode for a [`hort_domain::events::StreamCategory`]. The use case
/// holds a `Vec` of these — the registration seam. Adding a new
/// category only pushes a new rule; it does not modify the use-case logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryRetentionRule {
    pub category: hort_domain::events::StreamCategory,
    /// The audit-retention floor for this category (resolved by the
    /// composition root from `AuditRetentionFloors::floor_for`).
    pub floor: chrono::Duration,
    pub mode: SealMode,
}

/// The ONE global stream-retention mode threaded into the use case
/// (the `hort-app` mirror of `hort-server::config::StreamRetentionMode` —
/// `hort-app` must not depend on `hort-server`, so the resolved mode is
/// passed in as this small value). Per-stream-granular config is
/// explicitly out of v1 scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamRetentionModeRef {
    /// `EventStore::delete_stream` (the v1 default).
    Delete,
    /// `EventStore::archive_stream` with target
    /// `format!("{target_prefix}/{stream_id}")`.
    Archive { target_prefix: String },
}

/// Outcome summary of one `archive_terminal_streams` pass — the
/// `result_summary` JSON shape the task handler surfaces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionArchiveSummary {
    /// Candidate streams the sweep visited.
    pub candidates_visited: u64,
    /// Streams sealed via `archive_stream` (`Archive` mode).
    pub archived: u64,
    /// Streams sealed via `delete_stream` (`Delete` mode).
    pub deleted: u64,
    /// `TerminalGated` candidates whose tail was not the category
    /// terminal — skipped, not sealed.
    pub skipped_non_terminal: u64,
    /// Candidates whose C-1 floor had not elapsed — skipped.
    pub skipped_floor_not_elapsed: u64,
    /// The meta-stream guard fired (`StreamId::eventstore_retention()`).
    pub skipped_meta_stream: u64,
    /// `TerminalGated` candidate whose `read_stream` was empty — an
    /// idempotent re-run of an already-sealed stream.
    pub skipped_already_sealed: u64,
    /// Candidate whose category has no registered retention rule.
    pub skipped_unregistered_category: u64,
    /// Per-stream failures (terminal-proof read / seal chokepoint). The
    /// stream is NOT sealed; the next sweep retries it (fail-safe).
    pub errors: u64,
}

/// The audit-retention stream sweep. Pure orchestration
/// over the additive [`TerminalStreamReader`] and the event store
/// via [`EventStorePublisher`]. 100% mock-testable
/// per the `hort-app` coverage tier.
pub struct EventStoreRetentionUseCase {
    reader: Arc<dyn TerminalStreamReader>,
    events: Arc<EventStorePublisher>,
    /// The per-category registration. Looked up by candidate category;
    /// an unregistered category is skipped.
    rules: Vec<CategoryRetentionRule>,
    /// The one global v1 retention mode.
    mode: StreamRetentionModeRef,
}

impl EventStoreRetentionUseCase {
    /// Construct the use case. `rules` is the per-category retention
    /// registration the composition root builds from
    /// `AuditRetentionFloors::floor_for`; `mode` is the one global v1
    /// retention mode resolved from `hort-server` config.
    pub fn new(
        reader: Arc<dyn TerminalStreamReader>,
        events: Arc<EventStorePublisher>,
        rules: Vec<CategoryRetentionRule>,
        mode: StreamRetentionModeRef,
    ) -> Self {
        Self {
            reader,
            events,
            rules,
            mode,
        }
    }

    /// Run the audit-retention sweep at wall-clock `now` (`now` is
    /// injected so it is coherent across retries and pinnable in tests).
    ///
    /// One bad candidate (terminal-proof read / seal chokepoint failure)
    /// is recorded in [`RetentionArchiveSummary::errors`] and the sweep
    /// continues — the stream is not sealed and the next sweep retries
    /// (fail-safe; this also covers the unprivileged-role DELETE block
    /// when the retention role / `HORT_RETENTION_DATABASE_URL` is not
    /// configured). A
    /// [`TerminalStreamReader::list_terminal_candidates`] failure
    /// aborts the whole sweep with `AppError::Domain`.
    #[tracing::instrument(skip(self))]
    pub async fn archive_terminal_streams(
        &self,
        now: DateTime<Utc>,
    ) -> AppResult<RetentionArchiveSummary> {
        let candidates = self
            .reader
            .list_terminal_candidates()
            .await
            .map_err(AppError::Domain)?;
        tracing::info!(
            candidate_count = candidates.len(),
            "audit-retention stream sweep starting"
        );

        let mut summary = RetentionArchiveSummary::default();
        for candidate in &candidates {
            summary.candidates_visited += 1;
            self.process_one(now, candidate, &mut summary).await;
        }

        tracing::info!(
            candidates_visited = summary.candidates_visited,
            archived = summary.archived,
            deleted = summary.deleted,
            skipped_non_terminal = summary.skipped_non_terminal,
            skipped_floor_not_elapsed = summary.skipped_floor_not_elapsed,
            skipped_meta_stream = summary.skipped_meta_stream,
            skipped_already_sealed = summary.skipped_already_sealed,
            skipped_unregistered_category = summary.skipped_unregistered_category,
            errors = summary.errors,
            "audit-retention stream sweep complete"
        );
        Ok(summary)
    }

    /// Process one candidate stream. Isolated so any per-stream failure
    /// maps to a [`RetentionArchiveSummary::errors`] increment and the
    /// sweep continues.
    async fn process_one(
        &self,
        now: DateTime<Utc>,
        candidate: &TerminalStreamCandidate,
        summary: &mut RetentionArchiveSummary,
    ) {
        // -- (1) meta-stream guard (double defence-in-depth) ------------
        let meta_stream_id = StreamId::eventstore_retention().to_string();
        if candidate.stream_id == meta_stream_id {
            summary.skipped_meta_stream += 1;
            emit_streams_archived(StreamsArchivedResult::Skipped);
            tracing::warn!(
                stream_id = %candidate.stream_id,
                "meta-stream guard: refusing to seal the never-deleted \
                 audit-meta stream (StreamId::eventstore_retention()) — \
                 sealing it would truncate the audit trail of every seal. \
                 The adapter pre-filters it too; re-asserted here."
            );
            return;
        }

        // -- (2) registered-rule lookup --------------------------------
        let Some(rule) = self.rules.iter().find(|r| r.category == candidate.category) else {
            summary.skipped_unregistered_category += 1;
            emit_streams_archived(StreamsArchivedResult::Skipped);
            tracing::debug!(
                stream_id = %candidate.stream_id,
                category = ?candidate.category,
                "no registered retention rule for this category — skipped"
            );
            return;
        };

        // -- (3) terminal proof (TerminalGated only) -------------------
        if let SealMode::TerminalGated {
            terminal_event_type,
        } = rule.mode
        {
            match self.prove_terminal(candidate, terminal_event_type).await {
                TerminalProof::Sealed => {
                    summary.skipped_already_sealed += 1;
                    emit_streams_archived(StreamsArchivedResult::Skipped);
                    tracing::debug!(
                        stream_id = %candidate.stream_id,
                        "terminal-proof read empty — stream already sealed \
                         (idempotent re-run); skipped"
                    );
                    return;
                }
                TerminalProof::NotTerminal { last_event_type } => {
                    summary.skipped_non_terminal += 1;
                    emit_streams_archived(StreamsArchivedResult::Skipped);
                    tracing::warn!(
                        stream_id = %candidate.stream_id,
                        expected_terminal = terminal_event_type,
                        last_event_type = %last_event_type,
                        "TerminalGated stream's last event is not the category \
                         terminal — NOT sealed (not an error; a later sweep \
                         seals it once it terminates)"
                    );
                    return;
                }
                TerminalProof::ReadError => {
                    summary.errors += 1;
                    // error! already emitted in prove_terminal; the
                    // ArtifactExpired-style decision survives (nothing
                    // sealed) and the next sweep retries.
                    return;
                }
                TerminalProof::Terminal => { /* fall through to floor */ }
            }
        }

        // -- (4) C-1 floor proof (against the OLDEST event) ------------
        let elapsed = now - candidate.first_event_at;
        if elapsed < rule.floor {
            summary.skipped_floor_not_elapsed += 1;
            emit_streams_archived(StreamsArchivedResult::Skipped);
            tracing::debug!(
                stream_id = %candidate.stream_id,
                first_event_at = %candidate.first_event_at,
                floor_days = rule.floor.num_days(),
                elapsed_days = elapsed.num_days(),
                "C-1 audit-retention floor not yet elapsed — skipped"
            );
            return;
        }

        // -- all preconditions passed: route through the seal chokepoint -
        self.seal_one(candidate, summary).await;
    }

    /// Prove a `TerminalGated` stream's tail via a bounded
    /// `read_stream` from `Start`. The largest `stream_position` in
    /// the page is the tail. An empty read ⇒ already sealed
    /// (idempotent). A read failure ⇒ `error!` + the use case records
    /// an error and continues (the stream is NOT sealed).
    async fn prove_terminal(
        &self,
        candidate: &TerminalStreamCandidate,
        terminal_event_type: &'static str,
    ) -> TerminalProof {
        let stream_id: StreamId = match candidate.stream_id.parse() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    stream_id = %candidate.stream_id,
                    error = %e,
                    "candidate stream id did not parse — NOT sealed, retried \
                     next sweep"
                );
                return TerminalProof::ReadError;
            }
        };
        let events = match self
            .events
            .read_stream(&stream_id, ReadFrom::Start, TERMINAL_PROOF_READ_LIMIT)
            .await
        {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(
                    stream_id = %candidate.stream_id,
                    error = %e,
                    "terminal-proof read_stream failed — NOT sealed, retried \
                     next sweep (fail-safe)"
                );
                return TerminalProof::ReadError;
            }
        };
        let Some(tail) = events.iter().max_by_key(|e| e.stream_position) else {
            return TerminalProof::Sealed;
        };
        let last_event_type = tail.event.event_type();
        if last_event_type == terminal_event_type {
            TerminalProof::Terminal
        } else {
            TerminalProof::NotTerminal {
                last_event_type: last_event_type.to_owned(),
            }
        }
    }

    /// Route the proven candidate through the seal chokepoint per the
    /// one global retention mode. A chokepoint `Err` is per-stream:
    /// `errors += 1`, `error!`, continue (fail-safe — covers the
    /// unprivileged-role DELETE block when the retention role is not
    /// configured). The `StreamSealed` tombstone is emitted by the
    /// adapter's `seal_and_remove`, not here.
    async fn seal_one(
        &self,
        candidate: &TerminalStreamCandidate,
        summary: &mut RetentionArchiveSummary,
    ) {
        let stream_id: StreamId = match candidate.stream_id.parse() {
            Ok(s) => s,
            Err(e) => {
                summary.errors += 1;
                tracing::error!(
                    stream_id = %candidate.stream_id,
                    error = %e,
                    "candidate stream id did not parse at seal — NOT sealed"
                );
                return;
            }
        };

        match &self.mode {
            StreamRetentionModeRef::Delete => match self.events.delete_stream(stream_id).await {
                Ok(()) => {
                    summary.deleted += 1;
                    emit_streams_archived(StreamsArchivedResult::Deleted);
                    tracing::info!(
                        stream_id = %candidate.stream_id,
                        target = "delete",
                        "stream sealed + deleted (adapter emitted \
                         the StreamSealed tombstone)"
                    );
                }
                Err(e) => {
                    summary.errors += 1;
                    tracing::error!(
                        stream_id = %candidate.stream_id,
                        error = %e,
                        "delete_stream failed — stream NOT sealed, retried \
                         next sweep. Expected & \
                         fail-safe when the retention role is not \
                         configured (the events_immutable trigger blocks \
                         the unprivileged-role DELETE; zero rows removed, \
                         no orphan tombstone)."
                    );
                }
            },
            StreamRetentionModeRef::Archive { target_prefix } => {
                let target = format!("{target_prefix}/{}", candidate.stream_id);
                match self.events.archive_stream(stream_id, &target).await {
                    Ok(()) => {
                        summary.archived += 1;
                        emit_streams_archived(StreamsArchivedResult::Archived);
                        tracing::info!(
                            stream_id = %candidate.stream_id,
                            target = %target,
                            "stream sealed + archived (adapter emitted \
                             the StreamSealed tombstone)"
                        );
                    }
                    Err(e) => {
                        summary.errors += 1;
                        tracing::error!(
                            stream_id = %candidate.stream_id,
                            target = %target,
                            error = %e,
                            "archive_stream failed — stream \
                             NOT sealed, retried next sweep (fail-safe; see \
                             the delete_stream note re: hort_retention_role)."
                        );
                    }
                }
            }
        }
    }
}

/// Outcome of [`EventStoreRetentionUseCase::prove_terminal`].
enum TerminalProof {
    /// Tail event type equals the category terminal — proceed to the
    /// floor proof.
    Terminal,
    /// Tail event type is not the category terminal — skip (not an
    /// error).
    NotTerminal { last_event_type: String },
    /// `read_stream` was empty — the stream is already sealed
    /// (idempotent re-run).
    Sealed,
    /// `read_stream` (or the stream-id parse) failed — record an error
    /// and continue (the stream is NOT sealed; fail-safe).
    ReadError,
}

#[cfg(test)]
#[path = "eventstore_retention_use_case_tests.rs"]
mod tests;
