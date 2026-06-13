//! `RetentionUseCase::evaluate_policies` — stage one of the two-stage
//! retention split.
//!
//! The runtime retention **evaluator**: for each replayed
//! [`RetentionPolicy`] and each candidate [`Artifact`], decide whether
//! the policy predicate matches and, on a match, append one
//! [`DomainEvent::ArtifactExpired`] to the artifact stream. It does NOT
//! delete storage — that is the two-stage split's second stage
//! (`PurgeUseCase`). It does NOT register a scheduler — that
//! is the `RetentionEvaluateHandler` `TaskHandler`; this use case
//! is the pure orchestration the handler calls.
//!
//! # What the evaluator enforces
//!
//! - **inv 1 — quarantine/rejected GC-protection.** Any artifact whose
//!   `quarantine_status ∈ {quarantined, rejected}` is filtered *before*
//!   any predicate runs (`skipped_quarantined` / `skipped_rejected`
//!   metric, no event). `scan_indeterminate` is treated the same as
//!   `rejected` for protection — a terminal-failure artifact is
//!   evidence, not GC fodder (ADR 0007;
//!   `ScanIndeterminate` recovery is admin-only). `none` / `released`
//!   are eligible.
//! - **inv 7 — scan-data freshness gate (per-artifact).** Before a
//!   *security-driven* predicate evaluates, **this artifact's own**
//!   most-recent `ScanCompleted.stored_at` on its `artifact:<id>`
//!   stream must be within `2 × resolved_rescan_interval` of `now`; an
//!   artifact with no `ScanCompleted` on its own stream cannot prove
//!   per-artifact freshness and is treated as stale (fail-safe).
//!   (Per-artifact — deliberately tighter than the per-repo
//!   `repo_security_score.last_scan_at` reading.) Stale →
//!   `skipped_stale_scan` metric + `tracing::debug!`,
//!   NOT an error, the sweep continues. The interval is resolved per
//!   the policy chain (repo-scoped scan policy → … → default
//!   24 h); the evaluator consumes the resolved value supplied by the
//!   caller (the policy-chain resolver is not
//!   re-implemented here — the evaluator takes the resolved hours as an
//!   input so it stays a pure orchestration step and the chain
//!   resolution stays single-sourced).
//! - **inv 8 — direct-upload protection.** Resolved at scope time. When
//!   a security predicate's scope does not exclude `IngestSource(Direct)`,
//!   evaluation **proceeds** — the policy is the operator's stated
//!   intent and the apply pipeline already surfaced the warning.
//!   The runtime evaluator does NOT block here.
//! - **idempotent on `(policy_id, artifact_id)`.** Before appending, the
//!   artifact stream is scanned for an existing `ArtifactExpired` with
//!   the same `policy_id`; if present the decision is a no-op. Running
//!   the sweep twice yields exactly one `ArtifactExpired`.
//!
//! ## `HasFindingDetectedFor` anchor
//!
//! The grace-period anchor is the **earliest** `ScanCompleted` on the
//! artifact stream that carries a finding the policy matched, OR the
//! O(1) `ArtifactBecameVulnerable.previously_clean_at` when that event
//! exists, falling back to the artifact's `created_at` (cold data) with
//! a `tracing::warn!`. The evaluator resolves this anchor and feeds it
//! into the pure [`hort_domain::retention::evaluate`].
//!
//! ## Deliberately not here
//!
//! - The apply-pipeline `info!`-level direct-upload-scope warning →
//!   the apply path (the domain layer is
//!   zero-`tracing`; the warning lives where the YAML is applied).
//! - `RetentionPurgeHandler` / `TaskHandler` registration → the worker
//!   composition root.
//! - Blob-sourced `fixed_versions` precision for `HasFixAvailable`
//!   (the projection does not carry `fixed_versions`; see
//!   [`hort_domain::ports::retention_scan_reader`] module docs) → the
//!   out-of-scope "successor-in-our-repo /
//!   per-finding first-seen" refinement family.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::events::{retention_scheduler_actor, DomainEvent, StreamId};
use hort_domain::ports::event_store::{
    AppendEvents, EventStore, EventToAppend, ExpectedVersion, ReadFrom,
};
use hort_domain::ports::retention_scan_reader::RetentionScanReader;
use hort_domain::retention::{
    evaluate, EvaluationInputs, EvaluationOutcome, ExpirationReason, RetentionPolicy,
};
use hort_domain::types::Finding;

use crate::error::{AppError, AppResult};
use crate::event_store_publisher::EventStorePublisher;
use crate::metrics::{
    emit_retention_evaluation, emit_retention_expired, RetentionEvaluationResult,
};

/// Per-artifact-stream read cap. Mirrors the
/// `quarantine_use_case::STREAM_READ_LIMIT` value — an artifact stream
/// in v2 is short (ingest → scan(s) → release/reject → maybe expire);
/// 200 events is far beyond any real stream.
const STREAM_READ_LIMIT: u64 = 200;

/// Default rescan interval (hours) when the caller resolved no policy
/// interval. Mirrors the policy chain's "default 24 h" tail
/// (`DefaultPolicy::rescan_interval_hours`). The freshness window is
/// `2 ×` this.
const DEFAULT_RESCAN_INTERVAL_HOURS: i64 = 24;

/// One artifact the caller wants evaluated against the policy set,
/// plus the resolved rescan interval for its repository (the
/// freshness-window input). The interval is resolved by the caller via
/// the existing policy chain (repo-scoped → global →
/// default 24 h); the evaluator does not re-implement chain resolution.
#[derive(Debug, Clone)]
pub struct RetentionCandidate {
    /// The artifact under evaluation.
    pub artifact: Artifact,
    /// The artifact's repository [`RepositoryFormat`] — the
    /// `RetentionScope::Format` input. Resolved by the caller from the
    /// joined `repositories.format` column (the `RetentionCandidateRow`
    /// port DTO carries it; B6's handler copies it across). `Artifact`
    /// has no `format` field, so the scope gate needs it carried
    /// alongside.
    pub format: RepositoryFormat,
    /// The resolved `rescan_interval_hours` for the artifact's
    /// repository. `0` is meaningful (rescanning disabled) — it still
    /// yields a `2 × 0 = 0`-second freshness window, i.e. a
    /// security-driven predicate on a no-rescan repo is effectively
    /// always stale (fail-safe: it never expires). `None` → the
    /// default 24 h.
    pub resolved_rescan_interval_hours: Option<i64>,
}

/// Outcome summary of one `evaluate_policies` pass — the
/// `result_summary` JSON shape Item B6's `TaskHandler` will surface
/// (B3 returns the typed struct; the JSON projection is B6's job).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvaluateSummary {
    /// Total (policy, artifact) pairs the sweep evaluated.
    pub evaluated: u64,
    /// Pairs that matched and produced an `ArtifactExpired` append.
    pub expired: u64,
    /// Pairs skipped because the artifact was already expired by this
    /// policy (idempotent no-op).
    pub already_expired: u64,
    /// Pairs skipped by the §6-invariant-1 quarantine/rejected filter.
    pub skipped_protected: u64,
    /// Pairs skipped by the §6-invariant-7 stale-scan freshness gate.
    pub skipped_stale_scan: u64,
    /// Pairs where a port read failed (sweep continued).
    pub errors: u64,
}

/// The retention evaluator. Pure orchestration over the
/// [`RetentionScanReader`] port + the existing event store; the
/// match decision itself is the pure
/// [`hort_domain::retention::evaluate`].
pub struct RetentionUseCase {
    events: Arc<EventStorePublisher>,
    scan_reader: Arc<dyn RetentionScanReader>,
}

impl RetentionUseCase {
    /// Construct the use case from the event store wrapper and the
    /// scan-projection reader port.
    pub fn new(
        events: Arc<EventStorePublisher>,
        scan_reader: Arc<dyn RetentionScanReader>,
    ) -> Self {
        Self {
            events,
            scan_reader,
        }
    }

    /// Evaluate every (non-archived) policy in `policies` against every
    /// `candidates` artifact at wall-clock `now`, appending one
    /// `ArtifactExpired` per fresh match.
    ///
    /// `now` is passed in (not read via `Utc::now()` inside) so the
    /// sweep's comparison time is coherent across retries and pinnable
    /// in tests — the same convention as
    /// `RescanCandidatesRepository::select_eligible`.
    ///
    /// Returns the aggregate [`EvaluateSummary`]. One bad (policy,
    /// artifact) pair (a port read error) is recorded and skipped; it
    /// never aborts the whole sweep (§7 — "Policy evaluation rejected …
    /// `error!` … retried on next sweep" is per-pair, not fatal).
    #[tracing::instrument(skip(self, policies, candidates), fields(
        policy_count = policies.len(),
        candidate_count = candidates.len(),
    ))]
    pub async fn evaluate_policies(
        &self,
        now: DateTime<Utc>,
        policies: &[RetentionPolicy],
        candidates: &[RetentionCandidate],
    ) -> AppResult<EvaluateSummary> {
        let mut summary = EvaluateSummary::default();

        for policy in policies {
            if policy.archived {
                tracing::debug!(
                    policy_id = %policy.id,
                    policy_name = %policy.name,
                    "skipping archived retention policy"
                );
                continue;
            }
            let policy_id_label = policy.id.to_string();
            let mut matched_count: u32 = 0;
            let mut expired_count: u32 = 0;

            for candidate in candidates {
                summary.evaluated += 1;
                match self
                    .evaluate_one(now, policy, &policy_id_label, candidate)
                    .await
                {
                    EvalStep::Matched => {
                        summary.expired += 1;
                        matched_count += 1;
                        expired_count += 1;
                    }
                    EvalStep::NoMatch => {
                        matched_count += 0;
                    }
                    EvalStep::AlreadyExpired => {
                        summary.already_expired += 1;
                        // An already-expired artifact still counts as a
                        // policy match for the per-policy audit summary.
                        matched_count += 1;
                    }
                    EvalStep::SkippedProtected => summary.skipped_protected += 1,
                    EvalStep::SkippedStaleScan => summary.skipped_stale_scan += 1,
                    EvalStep::Errored => summary.errors += 1,
                }
            }

            tracing::info!(
                policy_id = %policy.id,
                policy_name = %policy.name,
                scope = ?policy.scope,
                matched_count,
                expired_count,
                "retention policy evaluated"
            );
        }

        Ok(summary)
    }

    /// Evaluate one policy against one candidate. Isolated so a port
    /// error on one pair maps to [`EvalStep::Errored`] and the caller
    /// keeps sweeping.
    async fn evaluate_one(
        &self,
        now: DateTime<Utc>,
        policy: &RetentionPolicy,
        policy_id_label: &str,
        candidate: &RetentionCandidate,
    ) -> EvalStep {
        let artifact = &candidate.artifact;

        // -- §6 invariant 1: quarantine / rejected GC-protection ----------
        match artifact.quarantine_status {
            QuarantineStatus::Quarantined => {
                emit_retention_evaluation(
                    policy_id_label,
                    RetentionEvaluationResult::SkippedQuarantined,
                );
                tracing::debug!(
                    policy_id = %policy.id, artifact_id = %artifact.id,
                    "inv1: artifact quarantined — GC-protected, skipped"
                );
                return EvalStep::SkippedProtected;
            }
            QuarantineStatus::Rejected | QuarantineStatus::ScanIndeterminate => {
                emit_retention_evaluation(
                    policy_id_label,
                    RetentionEvaluationResult::SkippedRejected,
                );
                tracing::debug!(
                    policy_id = %policy.id, artifact_id = %artifact.id,
                    status = %artifact.quarantine_status,
                    "inv1: artifact rejected/indeterminate — evidence, skipped"
                );
                return EvalStep::SkippedProtected;
            }
            QuarantineStatus::None | QuarantineStatus::Released => {}
        }

        // -- idempotency on (policy_id, artifact_id) ----------------------
        let stream_id = StreamId::artifact(artifact.id);
        let stream = match self
            .events
            .read_stream(&stream_id, ReadFrom::Start, STREAM_READ_LIMIT)
            .await
        {
            Ok(s) => s,
            Err(e) => return self.errored(policy_id_label, policy, artifact, "read_stream", e),
        };
        if stream.iter().any(
            |ev| matches!(&ev.event, DomainEvent::ArtifactExpired(x) if x.policy_id == policy.id),
        ) {
            tracing::debug!(
                policy_id = %policy.id, artifact_id = %artifact.id,
                "idempotent: artifact already expired by this policy — no-op"
            );
            return EvalStep::AlreadyExpired;
        }

        // -- §4 scope gate ------------------------------------------------
        // A scoped policy must never expire an artifact it does not
        // cover. `RetentionScope::matches` is the pure §4 decision; the
        // candidate-reader does NO scope SQL pre-filter (see the
        // `RetentionCandidateReader` port docstring), so the gate lives
        // here, before the predicate `evaluate()` call. `ingest_source`
        // is the `ArtifactIngested.source` — the genesis event on every
        // artifact stream. If it is somehow absent (it cannot be: it is
        // the first event of the aggregate), fail SAFE: treat the scope
        // as a non-match so the artifact is never expired, and `warn!`
        // — the same fail-safe posture inv7 takes when it cannot prove
        // scan freshness.
        let Some(ingest_source) = stream.iter().find_map(|ev| match &ev.event {
            DomainEvent::ArtifactIngested(e) => Some(e.source),
            _ => None,
        }) else {
            tracing::warn!(
                policy_id = %policy.id, artifact_id = %artifact.id,
                "scope gate: no ArtifactIngested on the artifact stream — \
                 cannot resolve IngestSource; failing safe (treating scope \
                 as non-match, artifact will not expire this pass)"
            );
            emit_retention_evaluation(policy_id_label, RetentionEvaluationResult::NoMatch);
            return EvalStep::NoMatch;
        };
        if !policy.scope.matches(
            artifact.repository_id,
            &candidate.format,
            &artifact.name,
            ingest_source,
        ) {
            tracing::debug!(
                policy_id = %policy.id, artifact_id = %artifact.id,
                scope = ?policy.scope,
                "scope gate: policy scope does not cover this artifact — \
                 not evaluated (no-match)"
            );
            emit_retention_evaluation(policy_id_label, RetentionEvaluationResult::NoMatch);
            return EvalStep::NoMatch;
        }

        // -- read the per-finding projection ------------------------------
        let findings = match self
            .scan_reader
            .list_findings_for_artifact(artifact.id)
            .await
        {
            Ok(f) => f,
            Err(e) => return self.errored(policy_id_label, policy, artifact, "list_findings", e),
        };

        // This artifact's most-recent `ScanCompleted` on its OWN stream
        // — the per-artifact §6-inv-7 freshness signal (Finding #2;
        // tightened from the per-repo `repo_security_scores.last_scan_at`
        // MAX). `None` = no scan on this artifact's stream.
        let latest_scan_at_opt = self.latest_scan_at(&stream);

        // -- §6 invariant 7: scan-data freshness gate (PER ARTIFACT) ------
        if policy.predicate.is_security_driven()
            && !self.scan_is_fresh(now, candidate, latest_scan_at_opt)
        {
            emit_retention_evaluation(policy_id_label, RetentionEvaluationResult::SkippedStaleScan);
            tracing::debug!(
                policy_id = %policy.id, artifact_id = %artifact.id,
                "inv7: this artifact's scan data stale (> 2x rescan \
                 interval) or absent — security predicate skipped this pass"
            );
            return EvalStep::SkippedStaleScan;
        }

        // -- resolve the HasFindingDetectedFor anchor + latest scan -------
        let latest_scan_at = latest_scan_at_opt.unwrap_or(artifact.created_at);
        let first_detected_at = self
            .resolve_first_detected_at(&stream, artifact, &findings)
            .await;

        // -- pure evaluate ------------------------------------------------
        let inputs = EvaluationInputs {
            now,
            created_at: artifact.created_at,
            // `UnusedFor` / `KeepLastN` inputs are not in B3's bounded
            // scope (no download-timeseries / sibling-rank port); the
            // pure evaluator fails them safe (never expire) when these
            // are absent. Security-driven + age predicates — B3's
            // focus — do not need them.
            last_downloaded_at: None,
            keep_rank: None,
            findings: &findings,
            first_detected_at,
            latest_scan_at,
        };

        match evaluate(&policy.predicate, &inputs) {
            EvaluationOutcome::NoMatch => {
                emit_retention_evaluation(policy_id_label, RetentionEvaluationResult::NoMatch);
                tracing::debug!(
                    policy_id = %policy.id, artifact_id = %artifact.id,
                    "retention predicate did not match"
                );
                EvalStep::NoMatch
            }
            EvaluationOutcome::Matched(reason) => {
                match self
                    .append_expired(
                        &stream_id,
                        artifact,
                        policy,
                        reason.clone(),
                        now,
                        stream.len() as u64,
                    )
                    .await
                {
                    Ok(()) => {
                        emit_retention_evaluation(
                            policy_id_label,
                            RetentionEvaluationResult::Matched,
                        );
                        emit_retention_expired(policy_id_label, reason.metric_label());
                        tracing::info!(
                            policy_id = %policy.id,
                            policy_name = %policy.name,
                            artifact_id = %artifact.id,
                            reason = reason.metric_label(),
                            "artifact expired by retention policy"
                        );
                        EvalStep::Matched
                    }
                    Err(e) => self.errored(policy_id_label, policy, artifact, "append_expired", e),
                }
            }
        }
    }

    /// §6-invariant-7 freshness gate, evaluated **per artifact** (not
    /// per repo). `true` = fresh, evaluate the security predicate;
    /// `false` = stale, skip it (NOT an error — the predicate just does
    /// not run this pass; the artifact becomes eligible again when its
    /// next scan completes).
    ///
    /// `latest_scan_at` is this artifact's most-recent
    /// `ScanCompleted.stored_at` on its **own** stream
    /// (`self.latest_scan_at(&stream)`), per §6 invariant 7 ("most
    /// recent `ScanCompleted`" — of *this* artifact). This is tightened
    /// from the weaker `repo_security_scores.last_scan_at` reading,
    /// which is a per-repo MAX: a fresh scan on a *different* artifact
    /// in the same repo would otherwise wrongly rescue a stale one
    /// (Finding #2). `None` (no `ScanCompleted` on the artifact's
    /// stream) ⇒ cannot prove per-artifact freshness ⇒ stale
    /// (fail-safe: a security predicate must never expire an artifact
    /// whose scan freshness is unprovable). No port read here — the
    /// signal is already on the stream the caller read.
    fn scan_is_fresh(
        &self,
        now: DateTime<Utc>,
        candidate: &RetentionCandidate,
        latest_scan_at: Option<DateTime<Utc>>,
    ) -> bool {
        let interval_hours = candidate
            .resolved_rescan_interval_hours
            .unwrap_or(DEFAULT_RESCAN_INTERVAL_HOURS)
            .max(0);
        let window = chrono::Duration::hours(2 * interval_hours);

        // No ScanCompleted on this artifact's own stream → cannot prove
        // per-artifact freshness → fail safe (treat as stale).
        let Some(last_scan_at) = latest_scan_at else {
            return false;
        };
        let age = now.signed_duration_since(last_scan_at);
        age <= window && age >= chrono::Duration::zero()
    }

    /// Earliest `ScanCompleted.stored_at` on the stream is the
    /// most-conservative "finding present since" anchor for
    /// `HasFindingDetectedFor`. The §4 ladder:
    /// 1. `ArtifactBecameVulnerable.previously_clean_at` (O(1), exact)
    ///    if such an event exists for the matched findings;
    /// 2. else the earliest `ScanCompleted` on the stream;
    /// 3. else (cold data — no scan event at all) the artifact's
    ///    `created_at`, with a `warn!`.
    async fn resolve_first_detected_at(
        &self,
        stream: &[hort_domain::events::PersistedEvent],
        artifact: &Artifact,
        findings: &[Finding],
    ) -> DateTime<Utc> {
        if findings.is_empty() {
            // No findings → `HasFindingDetectedFor` cannot match
            // anyway; the anchor value is irrelevant. Use created_at.
            return artifact.created_at;
        }
        // 1. O(1) ArtifactBecameVulnerable anchor.
        if let Some(pcv) = stream.iter().find_map(|ev| match &ev.event {
            DomainEvent::ArtifactBecameVulnerable(v) => Some(v.previously_clean_at),
            _ => None,
        }) {
            return pcv;
        }
        // 2. Earliest ScanCompleted on the stream.
        if let Some(first_scan) = stream.iter().find_map(|ev| match &ev.event {
            DomainEvent::ScanCompleted(_) => Some(ev.stored_at),
            _ => None,
        }) {
            return first_scan;
        }
        // 3. Cold-data fallback.
        tracing::warn!(
            artifact_id = %artifact.id,
            "HasFindingDetectedFor anchor: no prior ScanCompleted nor \
             ArtifactBecameVulnerable on the stream — falling back to \
             artifact.created_at (cold data)"
        );
        artifact.created_at
    }

    /// Most recent `ScanCompleted.stored_at` on the stream (the
    /// freshness/`latest_scan_at` snapshot fed into the
    /// `SecurityFinding` reason). `None` when the stream carries no
    /// scan event.
    fn latest_scan_at(
        &self,
        stream: &[hort_domain::events::PersistedEvent],
    ) -> Option<DateTime<Utc>> {
        stream.iter().rev().find_map(|ev| match &ev.event {
            DomainEvent::ScanCompleted(_) => Some(ev.stored_at),
            _ => None,
        })
    }

    /// Append the `ArtifactExpired` event. The reason snapshot is
    /// validated by the domain on append (the `DomainEvent::validate`
    /// dispatch); a malformed snapshot surfaces as `AppError::Domain`.
    /// `ExpectedVersion::Any` — the sweep races nothing on the artifact
    /// stream for the expiry decision (idempotency is enforced by the
    /// read-then-check above, not by optimistic concurrency; a
    /// concurrent ingest appending in between is harmless — it cannot
    /// produce a duplicate `ArtifactExpired` for the same policy).
    async fn append_expired(
        &self,
        stream_id: &StreamId,
        artifact: &Artifact,
        policy: &RetentionPolicy,
        reason: ExpirationReason,
        now: DateTime<Utc>,
        _stream_len: u64,
    ) -> AppResult<()> {
        let event = hort_domain::events::ArtifactExpired {
            artifact_id: artifact.id,
            policy_id: policy.id,
            policy_name: policy.name.clone(),
            reason,
            eligible_at: now,
        };
        event.validate().map_err(AppError::Domain)?;
        let batch = AppendEvents {
            stream_id: stream_id.clone(),
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(DomainEvent::ArtifactExpired(event))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            // The retention-evaluate sweep's
            // `ArtifactExpired` decision is attributed to the
            // RetentionScheduler, NOT the generic system actor —
            // destructive-retention audit must be distinguishable from
            // other background work. Use-case-internal one-line actor
            // swap (NOT a port/signature change).
            actor: retention_scheduler_actor(),
        };
        self.events.append(batch).await.map_err(AppError::Domain)?;
        Ok(())
    }

    /// Record a per-pair port error: `error` metric + `error!` log,
    /// returns [`EvalStep::Errored`] so the sweep continues.
    fn errored<E: std::fmt::Display>(
        &self,
        policy_id_label: &str,
        policy: &RetentionPolicy,
        artifact: &Artifact,
        op: &str,
        err: E,
    ) -> EvalStep {
        emit_retention_evaluation(policy_id_label, RetentionEvaluationResult::Error);
        tracing::error!(
            policy_id = %policy.id,
            artifact_id = %artifact.id,
            op,
            error = %err,
            "retention evaluation failed for this (policy, artifact) pair — \
             skipped, retried on next sweep"
        );
        EvalStep::Errored
    }
}

/// Per-pair evaluation result, folded into [`EvaluateSummary`] by the
/// caller. Internal — the public surface is [`EvaluateSummary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvalStep {
    Matched,
    NoMatch,
    AlreadyExpired,
    SkippedProtected,
    SkippedStaleScan,
    Errored,
}

#[cfg(test)]
#[path = "retention_use_case_tests.rs"]
mod tests;
