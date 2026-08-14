//! Single-source cross-axis release-clearance helpers (ADR 0027 + 0041).
//!
//! The provenance side of the fail-closed release gate is computed in
//! exactly **one** place here so the two release-gating callers cannot
//! drift:
//!
//! - [`QuarantineUseCase::resolve_provenance_clearance`](crate::use_cases::quarantine_use_case)
//!   — the timer-sweep release path (ADR 0027); and
//! - the `Rejected`-artifact re-evaluation callers (the policy-mutation
//!   population pass's loosen direction in
//!   [`PolicyUseCase`](crate::use_cases::policy_use_case), and the
//!   curator-invoked single-artifact endpoint in
//!   [`CurationUseCase`](crate::use_cases::curation_use_case)) — the
//!   cross-axis conjunction `scan ∧ curation ∧ provenance` (ADR 0041,
//!   invariant #6).
//!
//! Two independent release-gating provenance computations is exactly the
//! drift that produced the MR !39 `negligible_action` HIGH finding; this
//! module is the structural close. [`resolve_curation_clearance`] closes
//! the same drift risk for the curation side of the conjunction — both
//! `Rejected`-re-evaluation callers above call it rather than each
//! resolving the active curation-rule verdict themselves.
//!
//! Pure orchestration — wraps an [`EventStore`] read (provenance) or a
//! [`CurationRuleRepository`] + repository-format read (curation) with
//! the same predicate the timer sweep uses. No state mutation, no metric
//! emission.

use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, CurationClearance, ProvenanceClearance};
use hort_domain::entities::scan_policy::ProvenanceMode;
use hort_domain::events::{DomainEvent, StreamId};
use hort_domain::policy::{evaluate_curation, CurationOutcome};
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;
use hort_domain::ports::event_store::{EventStore, ReadFrom};
use hort_domain::types::ArtifactCoords;

use crate::error::AppResult;
use crate::use_cases::repository_access::RepositoryAccessUseCase;

/// Cap on the number of events read when scanning an artifact stream for
/// a `ProvenanceVerified` event. Mirrors the `STREAM_READ_LIMIT` /
/// `STREAM_EVENT_CAP` (200) used by the quarantine use case and
/// `scan_history`; every artifact stream begins well within this bound.
const STREAM_READ_LIMIT: u64 = 200;

/// Compute the provenance side of the release gate for a candidate
/// artifact under the given [`ProvenanceMode`] (ADR 0027). This is the
/// **single source** both the timer sweep and the ADR 0041 re-evaluation
/// pass call — see the module rustdoc.
///
/// - `provenance_mode ∈ {Off, VerifyIfPresent}` ⇒
///   [`ProvenanceClearance::NotRequired`]. `VerifyIfPresent` never gates
///   release — its protection is `complete_provenance(Rejected) ->
///   rejected`, which removes a bad artifact from candidacy, not a
///   release-gate.
/// - `provenance_mode == Required` ⇒ [`ProvenanceClearance::Cleared`] iff
///   a [`DomainEvent::ProvenanceVerified`] exists anywhere on the
///   artifact stream, else [`ProvenanceClearance::Pending`] (fail-closed
///   — a never-verified `Required` artifact does not release before
///   verification completes).
///
/// The caller resolves the artifact's active [`ProvenanceMode`] (an
/// absent policy resolves to the default `VerifyIfPresent` ⇒
/// `NotRequired`); this helper owns only the stream read + the verdict
/// mapping so the two callers cannot diverge.
pub(crate) async fn resolve_provenance_clearance(
    events: &dyn EventStore,
    artifact_id: Uuid,
    mode: ProvenanceMode,
) -> AppResult<ProvenanceClearance> {
    match mode {
        // VerifyIfPresent never gates release; Off is inert.
        ProvenanceMode::Off | ProvenanceMode::VerifyIfPresent => {
            Ok(ProvenanceClearance::NotRequired)
        }
        ProvenanceMode::Required => {
            let stream_id = StreamId::artifact(artifact_id);
            let persisted = events
                .read_stream(&stream_id, ReadFrom::Start, STREAM_READ_LIMIT)
                .await?;
            let verified = persisted
                .iter()
                .any(|e| matches!(e.event, DomainEvent::ProvenanceVerified(_)));
            Ok(if verified {
                ProvenanceClearance::Cleared
            } else {
                ProvenanceClearance::Pending
            })
        }
    }
}

/// Compute the **active curation precondition** of the cross-axis
/// release conjunction (ADR 0041 invariant #6 (c)) for one artifact.
///
/// Lists the artifact's repository's live curation rules
/// (`list_for_repo`) and runs the pure `evaluate_curation` over coords
/// built from the artifact (format resolved from the repository — the
/// format gate input). Returns [`CurationClearance::Blocked`] iff a
/// currently-active rule yields `CurationOutcome::Block`; `Warn` /
/// `Allow` / no-match all resolve to [`CurationClearance::Cleared`].
pub(crate) async fn resolve_curation_clearance(
    curation_rules: &dyn CurationRuleRepository,
    repository_access: &RepositoryAccessUseCase,
    artifact: &Artifact,
) -> AppResult<CurationClearance> {
    let rules = curation_rules.list_for_repo(artifact.repository_id).await?;
    if rules.is_empty() {
        // Fast path: no rules → cleared, no format lookup needed.
        return Ok(CurationClearance::Cleared);
    }
    // The curation format gate needs the repository's format; every
    // artifact in a repo shares it. A missing repo row resolves to the
    // `Generic` format (the curation evaluator's `any`-format rules
    // still apply; a format-specific rule simply won't match a Generic
    // coord — the same no-match→Cleared path).
    let format = repository_access
        .repository_format(artifact.repository_id)
        .await?
        .unwrap_or(hort_domain::entities::repository::RepositoryFormat::Generic);
    let coords = ArtifactCoords {
        name: artifact.name.clone(),
        name_as_published: artifact.name_as_published.clone(),
        version: artifact.version.clone(),
        path: artifact.path.clone(),
        format,
        metadata: serde_json::Value::Null,
    };
    Ok(match evaluate_curation(&coords, &rules) {
        CurationOutcome::Block { .. } => CurationClearance::Blocked,
        CurationOutcome::Warn { .. } | CurationOutcome::Allow => CurationClearance::Cleared,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use chrono::Utc;
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::events::{
        ArtifactQuarantined, PersistedEvent, ProvenanceVerified, StreamCategory,
    };
    use hort_domain::ports::event_store::{AppendEvents, AppendResult, SubscribeFrom};
    use hort_domain::ports::provenance::SignerIdentity;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ContentHash;

    use crate::use_cases::test_support::MockEventStore;

    const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn persisted(stream_id: StreamId, position: u64, event: DomainEvent) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id,
            stream_position: position,
            global_position: position,
            event,
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: hort_domain::events::system_actor(),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    fn verified_event(artifact_id: Uuid) -> DomainEvent {
        DomainEvent::ProvenanceVerified(ProvenanceVerified {
            artifact_id,
            content_hash: VALID_SHA256.parse::<ContentHash>().unwrap(),
            backend: "cosign".into(),
            signer: SignerIdentity {
                issuer: "iss".into(),
                san: "san".into(),
            },
            predicate_type: None,
            cascaded_from: None,
        })
    }

    fn other_event(artifact_id: Uuid) -> DomainEvent {
        DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
            artifact_id,
            quarantine_window_start: Utc::now(),
        })
    }

    /// `Off` ⇒ NotRequired with no stream read.
    #[tokio::test]
    async fn off_is_not_required() {
        let events = Arc::new(MockEventStore::new());
        let out = resolve_provenance_clearance(&*events, Uuid::new_v4(), ProvenanceMode::Off)
            .await
            .unwrap();
        assert_eq!(out, ProvenanceClearance::NotRequired);
    }

    /// `VerifyIfPresent` ⇒ NotRequired with no stream read.
    #[tokio::test]
    async fn verify_if_present_is_not_required() {
        let events = Arc::new(MockEventStore::new());
        let out =
            resolve_provenance_clearance(&*events, Uuid::new_v4(), ProvenanceMode::VerifyIfPresent)
                .await
                .unwrap();
        assert_eq!(out, ProvenanceClearance::NotRequired);
    }

    /// `Required` + a `ProvenanceVerified` on the stream ⇒ Cleared.
    #[tokio::test]
    async fn required_with_verified_is_cleared() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let sid = StreamId::artifact(artifact_id);
        events.set_stream(
            &sid,
            vec![
                persisted(sid.clone(), 0, other_event(artifact_id)),
                persisted(sid.clone(), 1, verified_event(artifact_id)),
            ],
        );
        let out = resolve_provenance_clearance(&*events, artifact_id, ProvenanceMode::Required)
            .await
            .unwrap();
        assert_eq!(out, ProvenanceClearance::Cleared);
    }

    /// `Required` + no `ProvenanceVerified` ⇒ Pending (fail-closed).
    #[tokio::test]
    async fn required_without_verified_is_pending() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let sid = StreamId::artifact(artifact_id);
        events.set_stream(
            &sid,
            vec![persisted(sid.clone(), 0, other_event(artifact_id))],
        );
        let out = resolve_provenance_clearance(&*events, artifact_id, ProvenanceMode::Required)
            .await
            .unwrap();
        assert_eq!(out, ProvenanceClearance::Pending);
    }

    /// `Required` over an empty stream ⇒ Pending.
    #[tokio::test]
    async fn required_empty_stream_is_pending() {
        let events = Arc::new(MockEventStore::new());
        let out = resolve_provenance_clearance(&*events, Uuid::new_v4(), ProvenanceMode::Required)
            .await
            .unwrap();
        assert_eq!(out, ProvenanceClearance::Pending);
    }

    /// A stream-read error propagates (does not silently clear) — the
    /// fail-closed posture: an infrastructure failure must surface as an
    /// `Err`, never a degraded `Cleared`.
    #[tokio::test]
    async fn required_propagates_read_error() {
        /// Minimal `EventStore` whose `read_stream` always errors.
        struct FailingReadStore;
        impl EventStore for FailingReadStore {
            fn append(&self, _b: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
                Box::pin(async { unreachable!("append not exercised") })
            }
            fn read_stream(
                &self,
                _s: &StreamId,
                _f: ReadFrom,
                _m: u64,
            ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                Box::pin(async { Err(DomainError::Invariant("event store down".into())) })
            }
            fn read_category(
                &self,
                _c: StreamCategory,
                _f: SubscribeFrom,
                _m: u64,
            ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                Box::pin(async { unreachable!("read_category not exercised") })
            }
            fn delete_stream(&self, _s: StreamId) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unreachable!() })
            }
            fn archive_stream(&self, _s: StreamId, _t: &str) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unreachable!() })
            }
        }
        let events = FailingReadStore;
        let err = resolve_provenance_clearance(&events, Uuid::new_v4(), ProvenanceMode::Required)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("event store down"));
    }
}
