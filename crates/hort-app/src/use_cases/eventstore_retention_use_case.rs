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
//! 3. **Terminal proof** (`TerminalGated` only) — one full-stream read
//!    via [`read_artifact_stream`](crate::use_cases::read_artifact_stream):
//!    an empty read ⇒ `already_sealed` + `debug!`
//!    (idempotent re-run); a last event whose
//!    [`DomainEvent::event_type`] ≠ the category terminal ⇒
//!    `skipped_non_terminal` + `warn!` (NOT an error), continue. A stream
//!    that breached `STREAM_EVENT_CAP` cannot be read to its tail, so it
//!    is reported as a read error (`errors += 1`, never sealed) rather
//!    than sealed on the 200th event as if that were the terminal.
//! 4. **C-1 floor proof** — `now - first_event_at < floor` ⇒
//!    `skipped_floor_not_elapsed` + `debug!`, continue. The floor is
//!    proven against the **oldest** event's `stored_at` (every later
//!    event is at-or-after it); never a payload timestamp, never the
//!    chain head.
//!
//! # The proofs are paired with the version that authorizes them
//!
//! Proving a stream terminal and past its floor, and removing it, are
//! two observations of a stream nothing holds still — the append path
//! takes no row lock, so there is none a seal could take either. The
//! sweep therefore hands the chokepoint the tail its proof read
//! ([`SealAuthority`]), and the chokepoint removes nothing unless the
//! stream is still there. A refusal comes back as
//! [`SealOutcome::NotAtProvenVersion`] and is counted as a *skip*, not
//! an error: an event landing in that window is the check working.
//!
//! For a `TerminalGated` category the authority is the tail of the
//! terminal-proof read — the same row the verdict came from. For an
//! `AgeGated` category there is no proof read, so it is the tail of the
//! enumeration row the floor facts came from.
//!
//! Only when every applicable precondition passes does the use case
//! call the retention chokepoint per the one global [`StreamRetentionModeRef`]
//! (`Delete` → `delete_stream`, `Archive` → `archive_stream` with a
//! target of `format!("{prefix}/{stream_id}")` — opaque per
//! `EventStore::archive_stream`). Only `Delete` is reachable in a
//! shipped deployment: the cold-storage *write* is deferred post-v1, so
//! `archive_stream` deletes the stream exactly as `delete_stream` does
//! and both binaries refuse `HORT_RETENTION_STREAM_MODE=archive` at
//! config parsing rather than report a delete as an archive. A
//! chokepoint `Err` is per-stream:
//! `summary.errors += 1`, `tracing::error!`, **continue** (mirrors
//! `purge_use_case.rs` per-artifact handling). A `list_*` enumeration
//! error aborts the whole sweep (`Err`) — distinct from per-stream
//! continuation.
//!
//! # The seals this sweep made still have to be anchored
//!
//! A `StreamSealed` tombstone is only tamper-evident once a checkpoint
//! that post-dates it anchors its head; until then the offline verifier
//! records `AnchorBreak::SealUnanchored`
//! (`hort_domain::events::chain`). Anchoring is **not** this use case's
//! job: it is one emission for the whole pass, not one per stream, and
//! it has to happen after the seals are committed (the adapter's
//! `seal_and_remove` appends the tombstone and deletes the rows in one
//! transaction per ADR 0020, so there is no instant in between that an
//! independent reader could observe). This pass therefore reports
//! **which** streams it sealed in
//! [`RetentionArchiveSummary::sealed_stream_ids`] and leaves the single
//! post-pass emission to its caller, `EventStoreArchiveHandler`.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use hort_domain::events::StreamId;
use hort_domain::ports::event_store::{EventStore, SealAuthority, SealOutcome};
use hort_domain::ports::terminal_stream_reader::{TerminalStreamCandidate, TerminalStreamReader};

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{emit_streams_archived, StreamsArchivedResult};

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
    /// `EventStore::delete_stream` (the v1 default, and the only mode a
    /// shipped deployment can select).
    Delete,
    /// `EventStore::archive_stream` with target
    /// `format!("{target_prefix}/{stream_id}")`.
    ///
    /// **Only tests construct this.** No `EventStore` implementation
    /// writes to cold storage yet — the Postgres adapter's
    /// `archive_stream` seals and deletes exactly like the delete path —
    /// so `HORT_RETENTION_STREAM_MODE=archive` is refused at config
    /// parsing in both binaries and the composition root never produces
    /// this variant. The arm below stays so the routing does not have to
    /// be reconstructed when the cold-storage writer ships; it must not
    /// be made reachable before then, because its `Ok` path increments
    /// [`RetentionArchiveSummary::archived`] for events that were
    /// removed.
    Archive { target_prefix: String },
}

/// Outcome summary of one `archive_terminal_streams` pass — the
/// `result_summary` JSON shape the task handler surfaces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionArchiveSummary {
    /// Candidate streams the sweep visited.
    pub candidates_visited: u64,
    /// Streams sealed via `archive_stream` (`Archive` mode). Always `0`
    /// in a shipped deployment — `Archive` is unreachable while the
    /// cold-storage writer is deferred post-v1 (see
    /// [`StreamRetentionModeRef::Archive`]).
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
    /// Candidates the chokepoint refused because the stream had moved
    /// past the tail the sweep proved it at — an event landed between
    /// the proof and the seal. Nothing was removed and no tombstone was
    /// written; the next sweep re-evaluates from a fresh proof.
    ///
    /// Deliberately **not** [`Self::errors`]: nothing failed. A stream
    /// that receives a late event is the optimistic check doing its job,
    /// and counting it as an error would make a healthy sweep read as a
    /// broken one.
    pub skipped_stream_changed: u64,
    /// Per-stream failures (terminal-proof read / seal chokepoint). The
    /// stream is NOT sealed; the next sweep retries it (fail-safe).
    pub errors: u64,
    /// The stream ids this pass actually sealed, in sweep order — one
    /// entry per chokepoint call that answered
    /// [`SealOutcome::Sealed`], so `len()` always equals
    /// `archived + deleted`.
    ///
    /// Ids rather than only a count because the caller has to be able
    /// to **name** them. A `StreamSealed` tombstone is only
    /// tamper-evident once a checkpoint that post-dates it anchors its
    /// head; until then the offline verifier records
    /// `AnchorBreak::SealUnanchored`
    /// (`hort_domain::events::chain`). The caller anchors this pass's
    /// seals once the pass is done
    /// (`EventStoreArchiveHandler`), and when that anchoring fails the
    /// operator needs to know *which* streams are sealed-but-unanchored,
    /// not just how many.
    pub sealed_stream_ids: Vec<String>,
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
            skipped_stream_changed = summary.skipped_stream_changed,
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
        //
        // The tail position the proof read is kept, not just the verdict:
        // it is what authorizes the seal. For an `AgeGated` category
        // there is no proof read at all (rotated audit streams have no
        // terminal), so the authority is the enumeration's own tail —
        // the observation the floor facts came from.
        let mut proven_final_position = candidate.last_stream_position;

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
                TerminalProof::Terminal {
                    final_stream_position,
                } => {
                    // The authority is this read's tail, not the
                    // enumeration's: the proof that the tail is the
                    // category terminal and the position it was read at
                    // come from the same row of the same read, so there
                    // is no second observation for a late event to hide
                    // between.
                    proven_final_position = final_stream_position;
                }
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
        //
        // The floor proof reads nothing new, so the tail carried here is
        // still the one both proofs rest on. The chokepoint refuses if
        // the stream has moved since.
        let authority = SealAuthority {
            final_stream_position: proven_final_position,
        };
        self.seal_one(candidate, authority, summary).await;
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
        // The tail is the whole point of this read, so it must be a read
        // that can prove it reached the tail: `read_artifact_stream` reads
        // one event past `STREAM_EVENT_CAP` and refuses a stream longer
        // than that. Sealing deletes a stream — deciding "terminal" from
        // the 200th event of a longer stream would delete an audit trail
        // that had not terminated.
        let events = match crate::use_cases::read_artifact_stream(&*self.events, &stream_id).await {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(
                    stream_id = %candidate.stream_id,
                    error = %e,
                    "terminal-proof stream read failed — NOT sealed, retried \
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
            // The verdict and the version it holds for are the same row
            // of the same read — the pairing the seal needs, with no
            // second read for an append to slip between.
            TerminalProof::Terminal {
                final_stream_position: tail.stream_position,
            }
        } else {
            TerminalProof::NotTerminal {
                last_event_type: last_event_type.to_owned(),
            }
        }
    }

    /// Route the proven candidate through the seal chokepoint per the
    /// one global retention mode, carrying the `authority` its proofs
    /// were read at. A chokepoint `Err` is per-stream:
    /// `errors += 1`, `error!`, continue (fail-safe — covers the
    /// unprivileged-role DELETE block when the retention role is not
    /// configured). The `StreamSealed` tombstone is emitted by the
    /// adapter's `seal_and_remove`, not here.
    ///
    /// [`SealOutcome::NotAtProvenVersion`] is a third answer and is
    /// neither counted nor logged as the other two: the stream received
    /// an event after the sweep proved it, so nothing was removed and
    /// nothing failed. It lands in
    /// [`RetentionArchiveSummary::skipped_stream_changed`] beside the
    /// other skips.
    async fn seal_one(
        &self,
        candidate: &TerminalStreamCandidate,
        authority: SealAuthority,
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
            StreamRetentionModeRef::Delete => {
                match self.events.delete_stream(stream_id, authority).await {
                    Ok(SealOutcome::Sealed) => {
                        summary.deleted += 1;
                        summary.sealed_stream_ids.push(candidate.stream_id.clone());
                        emit_streams_archived(StreamsArchivedResult::Deleted);
                        tracing::info!(
                            stream_id = %candidate.stream_id,
                            target = "delete",
                            "stream sealed + deleted (adapter emitted \
                             the StreamSealed tombstone)"
                        );
                    }
                    Ok(SealOutcome::NotAtProvenVersion) => {
                        self.record_stream_changed(candidate, authority, summary);
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
                }
            }
            // Unreachable in a shipped deployment: both binaries refuse
            // `HORT_RETENTION_STREAM_MODE=archive` at config parsing while
            // the cold-storage writer is deferred post-v1, because
            // `archive_stream` deletes the stream exactly as
            // `delete_stream` does. The `Sealed` arm below therefore
            // counts and logs an archive that did not happen — do not
            // make this path reachable before an `EventStore`
            // implementation actually writes the stream somewhere.
            StreamRetentionModeRef::Archive { target_prefix } => {
                let target = format!("{target_prefix}/{}", candidate.stream_id);
                match self
                    .events
                    .archive_stream(stream_id, &target, authority)
                    .await
                {
                    Ok(SealOutcome::Sealed) => {
                        summary.archived += 1;
                        summary.sealed_stream_ids.push(candidate.stream_id.clone());
                        emit_streams_archived(StreamsArchivedResult::Archived);
                        tracing::info!(
                            stream_id = %candidate.stream_id,
                            target = %target,
                            "stream sealed + archived (adapter emitted \
                             the StreamSealed tombstone)"
                        );
                    }
                    Ok(SealOutcome::NotAtProvenVersion) => {
                        self.record_stream_changed(candidate, authority, summary);
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

    /// The chokepoint refused because the stream moved past the tail
    /// this sweep proved it at. Shared by both retention modes: the
    /// outcome does not depend on which verb was called, and recording
    /// it twice would let the two drift.
    fn record_stream_changed(
        &self,
        candidate: &TerminalStreamCandidate,
        authority: SealAuthority,
        summary: &mut RetentionArchiveSummary,
    ) {
        summary.skipped_stream_changed += 1;
        emit_streams_archived(StreamsArchivedResult::Skipped);
        tracing::warn!(
            stream_id = %candidate.stream_id,
            proven_final_stream_position = authority.final_stream_position,
            "seal refused: an event landed on the stream after this sweep \
             proved it terminal and past its retention floor — nothing \
             removed, no tombstone written (not an error; the next sweep \
             re-evaluates from a fresh proof)"
        );
    }
}

/// Outcome of [`EventStoreRetentionUseCase::prove_terminal`].
enum TerminalProof {
    /// Tail event type equals the category terminal — proceed to the
    /// floor proof. Carries the `stream_position` of that same tail
    /// event, which is what authorizes the seal: the proof and the
    /// version it holds for must be one observation, or an event landing
    /// between them is removed by a seal that never saw it.
    Terminal { final_stream_position: u64 },
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
