//! Shared readers for the questions an artifact's **already-read** event
//! stream answers about its scan history.
//!
//! Shared so every caller that re-derives a verdict — the policy-mutation
//! re-evaluation pass, the curator-invoked single-artifact endpoint, the
//! promotion gate — asks the same question of the same evidence and
//! cannot drift on how "the latest scan" is found.
//!
//! The surface is a [`ScanCompletedSnapshot`] carrying both the cached
//! aggregate AND the `findings_blob` hash so a caller can either run
//! aggregate-summary evaluation cheaply or hydrate the per-finding
//! `Vec<Finding>` from CAS and use exact CVE-ID matching (avoiding the
//! "one exclusion drops one count" limitation called out in
//! `crates/hort-domain/src/policy/exclusion.rs`).
//!
//! **These readers take the stream, they do not read it.** The stream a
//! decision rests on arrives from
//! [`ArtifactAtVersion`](crate::use_cases::ArtifactAtVersion), paired in
//! one observation with the `ExpectedVersion` the committing append will
//! carry — see that type's contract for why a reader that fetched the
//! stream for itself would reopen the window the pairing closes. Pure
//! scans over that slice: no I/O apart from the CAS fetch in
//! [`last_findings`], no state mutation, no metric emission.

use std::sync::Arc;

use tokio::io::AsyncReadExt;
use uuid::Uuid;

use hort_domain::events::{
    DomainEvent, PersistedEvent, RejectionReason, ScanCompleted, SeveritySummary,
};
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::{ContentHash, Finding};

/// Snapshot of the artifact's most recent `ScanCompleted` event,
/// surfaced by [`last_scan_completed`]. Carries both the cached
/// aggregate (`summary`) and the `findings_blob` hash so callers can
/// either run aggregate-summary evaluation cheaply or
/// hydrate per-finding detail from CAS for exact CVE-ID matching.
///
/// `findings_blob` is `None` iff the latest scan was clean (no
/// findings) — the `ScanCompleted` invariant
/// (`finding_count == 0 ⇔ findings_blob.is_none()`) carries through
/// here unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanCompletedSnapshot {
    pub summary: SeveritySummary,
    pub findings_blob: Option<ContentHash>,
}

/// Scan `stream` in reverse and return the most recent [`ScanCompleted`]
/// payload as a [`ScanCompletedSnapshot`].
///
/// `None` means the stream carries no `ScanCompleted` (never scanned).
/// Callers treat that as a clean baseline — see
/// [`crate::use_cases::promotion_use_case::PromotionUseCase::evaluate_and_promote`]
/// for the "missing scan summary == empty findings" rule and the
/// `Rejected`-re-evaluation callers for the "skip artifact" rule.
///
/// The reverse scan is only an answer about "the latest" if `stream` is
/// the whole stream, which is exactly what
/// [`ArtifactAtVersion::evidence`](crate::use_cases::ArtifactAtVersion::evidence)
/// guarantees and refuses to fake: over an oldest-prefix of a stream
/// that breached the event cap, the first `ScanCompleted` found walking
/// back is a *superseded* one, and the rejection that superseded it is
/// past the end of the slice.
pub(crate) fn last_scan_completed(stream: &[PersistedEvent]) -> Option<ScanCompletedSnapshot> {
    // Iterate in reverse — `ScanCompleted` is typically near the end
    // (post-quarantine, pre-rejection on the same stream).
    stream.iter().rev().find_map(|event| match &event.event {
        DomainEvent::ScanCompleted(ScanCompleted {
            severity_summary,
            findings_blob,
            ..
        }) => Some(ScanCompletedSnapshot {
            summary: severity_summary.clone(),
            findings_blob: findings_blob.clone(),
        }),
        _ => None,
    })
}

/// Scan `stream` in reverse and return the most recent
/// `ArtifactRejected.rejected_by` reason, `None` if the artifact has
/// never been rejected.
///
/// Shared by every caller that re-derives a `Rejected` artifact's
/// verdict — the eligibility guard downstream
/// ([`hort_domain::entities::artifact::is_scan_clearable`]) reads this
/// value, and the artifact entity loaded via
/// `ArtifactRepository::find_by_id` does not carry it (rejection reason
/// is not a stored column; it is reconstructed from the event log on
/// demand).
pub(crate) fn last_rejection_reason(stream: &[PersistedEvent]) -> Option<RejectionReason> {
    stream.iter().rev().find_map(|e| match &e.event {
        DomainEvent::ArtifactRejected(r) => Some(r.rejected_by.clone()),
        _ => None,
    })
}

/// Resolve the stream's most recent `ScanCompleted.findings_blob` to the
/// underlying `Vec<Finding>` via [`StoragePort::get`] and JSON decode.
/// The `Rejected`-re-evaluation callers use this to enable exact CVE-ID
/// matching via
/// [`hort_domain::policy::exclusion::filter_excluded_findings`].
///
/// Returns `None` for any best-effort failure mode (no `ScanCompleted`
/// on the stream, clean scan with no blob, missing CAS object, or
/// deserialise failure). The caller falls back to the aggregate-summary
/// path on `None`.
///
/// Failure modes (missing blob, malformed blob) log a
/// `tracing::warn!` so operators can correlate a silent fallback with
/// CAS rot. The aggregate-summary fallback is still safe — it
/// preserves the highest-tier-first decrement semantics — so
/// degrading gracefully here is the right tradeoff (the alternative
/// would be skipping the artifact entirely, which is worse from an
/// operator's perspective).
pub(crate) async fn last_findings(
    stream: &[PersistedEvent],
    storage: &Arc<dyn StoragePort>,
    artifact_id: Uuid,
) -> Option<Vec<Finding>> {
    let blob_hash = last_scan_completed(stream)?.findings_blob?;

    let mut reader = match storage.get(&blob_hash).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                artifact_id = %artifact_id,
                findings_blob = %blob_hash,
                error = %e,
                "findings_blob absent from CAS; falling back to aggregate-summary re-evaluation",
            );
            return None;
        }
    };

    let mut buf = Vec::new();
    if let Err(e) = reader.read_to_end(&mut buf).await {
        tracing::warn!(
            artifact_id = %artifact_id,
            findings_blob = %blob_hash,
            error = %e,
            "findings_blob read failed; falling back to aggregate-summary re-evaluation",
        );
        return None;
    }

    match serde_json::from_slice::<Vec<Finding>>(&buf) {
        Ok(findings) => Some(findings),
        Err(e) => {
            tracing::warn!(
                artifact_id = %artifact_id,
                findings_blob = %blob_hash,
                error = %e,
                "findings_blob malformed; falling back to aggregate-summary re-evaluation",
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use hort_domain::entities::scan_policy::SeverityThreshold;
    use hort_domain::events::{
        Actor, ApprovalDecided, ApprovalDecision, ArtifactQuarantined, ArtifactRejected,
        DomainEvent, PersistedEvent, RejectionReason, ScanAssessment, ScanCompleted,
        SeveritySummary, StreamId,
    };
    use hort_domain::ports::storage::StoragePort;
    use hort_domain::types::{ContentHash, Finding};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    /// Non-clean `ScanCompleted` carries a `ContentHash`
    /// referencing the per-finding blob in CAS. The placeholder used
    /// here (SHA-256 of empty input) is sufficient — these tests never
    /// dereference the hash.
    fn placeholder_findings_blob() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .expect("static valid SHA-256 hex")
    }

    use super::*;
    use crate::use_cases::test_support::*;

    fn persisted(stream_id: &StreamId, position: u64, event: DomainEvent) -> PersistedEvent {
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: stream_id.clone(),
            stream_position: position,
            global_position: position + 1,
            event,
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(api_actor()),
            event_version: 1,
            stored_at: Utc::now(),
        }
    }

    fn summary(critical: u32) -> SeveritySummary {
        SeveritySummary {
            critical,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        }
    }

    fn finding(vuln: &str, sev: SeverityThreshold) -> Finding {
        Finding {
            purl: "pkg:npm/lodash@4.17.20".into(),
            vulnerability_id: vuln.into(),
            severity: sev,
            cvss_score: None,
            title: "test finding".into(),
            fixed_versions: vec![],
            source_scanner: "osv".into(),
            references: vec![],
            aliases: vec![],
            informational_class: None,
            severity_basis: hort_domain::types::SeverityBasis::Assessed,
        }
    }

    #[test]
    fn returns_none_when_stream_empty() {
        assert!(last_scan_completed(&[]).is_none());
    }

    #[test]
    fn returns_none_when_stream_has_no_scan_completed() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id,
                quarantine_window_start: Utc::now(),
            }),
        )];

        assert!(last_scan_completed(&stream).is_none());
    }

    // -- last_rejection_reason -----------------------------------------------

    #[test]
    fn last_rejection_reason_none_when_stream_has_no_rejection() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id,
                quarantine_window_start: Utc::now(),
            }),
        )];

        assert!(last_rejection_reason(&stream).is_none());
    }

    #[test]
    fn last_rejection_reason_returns_most_recent() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let stream = vec![
            persisted(
                &stream_id,
                0,
                DomainEvent::ArtifactRejected(ArtifactRejected {
                    artifact_id,
                    rejected_by: RejectionReason::Curator {
                        curator_id: Uuid::new_v4(),
                    },
                    reason: "stale".into(),
                }),
            ),
            persisted(
                &stream_id,
                1,
                DomainEvent::ArtifactRejected(ArtifactRejected {
                    artifact_id,
                    rejected_by: RejectionReason::Scanner,
                    reason: "current".into(),
                }),
            ),
        ];

        assert_eq!(
            last_rejection_reason(&stream),
            Some(RejectionReason::Scanner)
        );
    }

    #[test]
    fn returns_summary_and_blob_from_only_scan_completed() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let blob = placeholder_findings_blob();

        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "trivy".into(),
                finding_count: 3,
                severity_summary: summary(3),
                findings_blob: Some(blob.clone()),
                assessment: ScanAssessment::Analysed,
            }),
        )];

        let snapshot = last_scan_completed(&stream).expect("ScanCompleted on stream");
        assert_eq!(snapshot.summary.critical, 3);
        assert_eq!(snapshot.findings_blob, Some(blob));
    }

    #[test]
    fn returns_most_recent_scan_completed_when_multiple() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let stream = vec![
            persisted(
                &stream_id,
                0,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "trivy".into(),
                    finding_count: 1,
                    severity_summary: summary(1),
                    findings_blob: Some(placeholder_findings_blob()),
                    assessment: ScanAssessment::Analysed,
                }),
            ),
            persisted(
                &stream_id,
                1,
                DomainEvent::ApprovalDecided(ApprovalDecided {
                    artifact_id,
                    decision: ApprovalDecision::Approved,
                    notes: None,
                }),
            ),
            persisted(
                &stream_id,
                2,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "trivy".into(),
                    finding_count: 5,
                    severity_summary: summary(5),
                    findings_blob: Some(placeholder_findings_blob()),
                    assessment: ScanAssessment::Analysed,
                }),
            ),
        ];

        let snapshot = last_scan_completed(&stream).expect("ScanCompleted on stream");
        // The reverse-scan must pick the second (latest) ScanCompleted.
        assert_eq!(snapshot.summary.critical, 5);
    }

    #[test]
    fn ignores_non_scan_events_after_a_scan_completed() {
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let stream = vec![
            persisted(
                &stream_id,
                0,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "trivy".into(),
                    finding_count: 7,
                    severity_summary: summary(7),
                    findings_blob: Some(placeholder_findings_blob()),
                    assessment: ScanAssessment::Analysed,
                }),
            ),
            persisted(
                &stream_id,
                1,
                DomainEvent::ApprovalDecided(ApprovalDecided {
                    artifact_id,
                    decision: ApprovalDecision::Rejected,
                    notes: None,
                }),
            ),
        ];

        let snapshot = last_scan_completed(&stream).expect("ScanCompleted on stream");
        assert_eq!(snapshot.summary.critical, 7);
    }

    // ---- last_findings -----------------------------------------------------

    #[tokio::test]
    async fn last_findings_returns_none_when_no_scan_completed() {
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        assert!(last_findings(&[], &storage, Uuid::new_v4()).await.is_none());
    }

    #[tokio::test]
    async fn last_findings_returns_none_when_scan_was_clean() {
        // Clean scan: `findings_blob = None`. Caller falls back to
        // aggregate-summary path (which sees an empty summary).
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "osv".into(),
                finding_count: 0,
                severity_summary: summary(0),
                findings_blob: None,
                assessment: ScanAssessment::Analysed,
            }),
        )];

        assert!(last_findings(&stream, &storage, artifact_id)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn last_findings_hydrates_blob_from_storage() {
        let mock_storage = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        // Seed CAS with a serialised Vec<Finding>.
        let findings = vec![
            finding("CVE-2021-23337", SeverityThreshold::High),
            finding("CVE-OTHER", SeverityThreshold::Medium),
        ];
        let bytes = serde_json::to_vec(&findings).unwrap();
        let hash_hex = hex::encode(Sha256::digest(&bytes));
        let blob_hash: ContentHash = hash_hex.parse().unwrap();
        mock_storage.insert_content(blob_hash.clone(), bytes);

        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "osv".into(),
                finding_count: 2,
                severity_summary: SeveritySummary {
                    critical: 0,
                    high: 1,
                    medium: 1,
                    low: 0,
                    negligible: 0,
                },
                findings_blob: Some(blob_hash),
                assessment: ScanAssessment::Analysed,
            }),
        )];

        let storage: Arc<dyn StoragePort> = mock_storage;
        let hydrated = last_findings(&stream, &storage, artifact_id)
            .await
            .expect("findings hydrated from CAS");
        assert_eq!(hydrated.len(), 2);
        assert_eq!(hydrated[0].vulnerability_id, "CVE-2021-23337");
        assert_eq!(hydrated[1].vulnerability_id, "CVE-OTHER");
    }

    #[tokio::test]
    async fn last_findings_returns_none_when_blob_missing_from_storage() {
        // The `ScanCompleted` event references a hash that is NOT in
        // CAS — best-effort: log warn, return None, caller falls back.
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "osv".into(),
                finding_count: 1,
                severity_summary: summary(1),
                findings_blob: Some(placeholder_findings_blob()),
                assessment: ScanAssessment::Analysed,
            }),
        )];

        assert!(last_findings(&stream, &storage, artifact_id)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn last_findings_returns_none_when_blob_is_malformed_json() {
        // The blob bytes are present but don't deserialise as
        // `Vec<Finding>` — best-effort: log warn, return None.
        let mock_storage = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        // Inject garbage at a fabricated hash. We have to fabricate the
        // hash explicitly because the production path always writes
        // hash(content) → content; here we want hash X to map to
        // garbage Y. MockStoragePort's `insert_content` does not enforce
        // the CAS invariant, exactly so tests can stage this kind of
        // failure mode.
        let blob_hash = placeholder_findings_blob();
        mock_storage.insert_content(blob_hash.clone(), b"not valid JSON".to_vec());

        let stream = vec![persisted(
            &stream_id,
            0,
            DomainEvent::ScanCompleted(ScanCompleted {
                artifact_id,
                scanner: "osv".into(),
                finding_count: 1,
                severity_summary: summary(1),
                findings_blob: Some(blob_hash),
                assessment: ScanAssessment::Analysed,
            }),
        )];

        let storage: Arc<dyn StoragePort> = mock_storage;
        assert!(last_findings(&stream, &storage, artifact_id)
            .await
            .is_none());
    }
}
