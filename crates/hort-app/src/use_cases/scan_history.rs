//! Shared helper for reading the artifact's most recent scan summary
//! from the event store.
//!
//! Shared so both `PolicyUseCase::add_exclusion` (post-
//! exclusion-add re-evaluation pass) and
//! `PromotionUseCase::evaluate_and_promote` (promotion gate) can call
//! a single source of truth.
//!
//! The surface is a [`ScanCompletedSnapshot`] carrying both the cached
//! aggregate AND the `findings_blob` hash so the post-exclusion-add
//! re-evaluation pass can hydrate the per-finding `Vec<Finding>` from
//! CAS and use exact CVE-ID matching (avoiding the "one exclusion
//! drops one count" limitation called out in
//! `crates/hort-domain/src/policy/exclusion.rs`).
//!
//! Pure orchestration — wraps an [`EventStore`] read with a reverse-
//! scan for the most recent [`DomainEvent::ScanCompleted`] payload.
//! No state mutation, no metric emission, no domain logic.

use std::sync::Arc;

use tokio::io::AsyncReadExt;
use uuid::Uuid;

use hort_domain::events::{DomainEvent, ScanCompleted, SeveritySummary, StreamId};
use hort_domain::ports::event_store::{EventStore, ReadFrom};
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::{ContentHash, Finding};

use crate::error::AppResult;

/// Cap on the number of events read when scanning for the most recent
/// `ScanCompleted`. Mirrors `use_cases::STREAM_EVENT_CAP` (200) — that
/// constant is `pub(crate)` so duplicating the literal here is cheaper
/// than re-exporting it. The two values must move together; if the
/// cap ever changes, update both sites.
const READ_LIMIT: u64 = 200;

/// Snapshot of the artifact's most recent `ScanCompleted` event,
/// surfaced by [`read_last_scan_completed`]. Carries both the cached
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

/// Scan the artifact's stream in reverse and return the most recent
/// [`ScanCompleted`] payload as a [`ScanCompletedSnapshot`].
///
/// `Ok(None)` means the artifact has no `ScanCompleted` on its stream
/// (never scanned). Callers treat that as a clean baseline — see
/// [`crate::use_cases::promotion_use_case::PromotionUseCase::evaluate_and_promote`]
/// for the "missing scan summary == empty findings" rule and
/// [`crate::use_cases::policy_use_case::PolicyUseCase::add_exclusion`]
/// for the "skip artifact" rule on the re-evaluation pass.
///
/// Performance: reads up to [`READ_LIMIT`] events. For typical artifact
/// streams (5–15 events) the linear scan is essentially free; the
/// payload size is small (`ScanCompleted` carries a `SeveritySummary` +
/// scanner name + an `Option<ContentHash>`) so cumulative
/// deserialisation cost is bounded.
pub(crate) async fn read_last_scan_completed(
    events: &dyn EventStore,
    artifact_id: Uuid,
) -> AppResult<Option<ScanCompletedSnapshot>> {
    let stream_id = StreamId::artifact(artifact_id);
    let persisted = events
        .read_stream(&stream_id, ReadFrom::Start, READ_LIMIT)
        .await?;
    // Iterate in reverse — `ScanCompleted` is typically near the end
    // (post-quarantine, pre-rejection on the same stream).
    for event in persisted.iter().rev() {
        if let DomainEvent::ScanCompleted(ScanCompleted {
            severity_summary,
            findings_blob,
            ..
        }) = &event.event
        {
            return Ok(Some(ScanCompletedSnapshot {
                summary: severity_summary.clone(),
                findings_blob: findings_blob.clone(),
            }));
        }
    }
    Ok(None)
}

/// Resolve the artifact's most recent `ScanCompleted.findings_blob` to
/// the underlying `Vec<Finding>` via [`StoragePort::get`] and JSON
/// decode. The post-exclusion-add re-evaluation pass
/// uses this to enable exact CVE-ID matching via
/// [`hort_domain::policy::exclusion::filter_excluded_findings`].
///
/// Returns `Ok(None)` for any best-effort failure mode (no
/// `ScanCompleted` on stream, clean scan with no blob, missing CAS
/// object, or deserialise failure). The caller falls back to the
/// aggregate-summary path on `None`. Only event-store read failures
/// propagate as `Err` (those are infrastructure errors the outer
/// orchestration must see).
///
/// Failure modes (missing blob, malformed blob) log a
/// `tracing::warn!` so operators can correlate a silent fallback with
/// CAS rot. The aggregate-summary fallback is still safe — it
/// preserves the highest-tier-first decrement semantics — so
/// degrading gracefully here is the right tradeoff (the alternative
/// would be skipping the artifact entirely, which is worse from an
/// operator's perspective).
pub(crate) async fn read_last_findings(
    events: &dyn EventStore,
    storage: &Arc<dyn StoragePort>,
    artifact_id: Uuid,
) -> AppResult<Option<Vec<Finding>>> {
    let Some(snapshot) = read_last_scan_completed(events, artifact_id).await? else {
        return Ok(None);
    };
    let Some(blob_hash) = snapshot.findings_blob else {
        // Clean scan — no blob to hydrate. The caller treats this as
        // "no per-finding rows to feed in" and falls back to the
        // aggregate-summary path (which will also see the empty
        // summary and short-circuit cleanly).
        return Ok(None);
    };

    let mut reader = match storage.get(&blob_hash).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                artifact_id = %artifact_id,
                findings_blob = %blob_hash,
                error = %e,
                "findings_blob absent from CAS; falling back to aggregate-summary re-evaluation",
            );
            return Ok(None);
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
        return Ok(None);
    }

    match serde_json::from_slice::<Vec<Finding>>(&buf) {
        Ok(findings) => Ok(Some(findings)),
        Err(e) => {
            tracing::warn!(
                artifact_id = %artifact_id,
                findings_blob = %blob_hash,
                error = %e,
                "findings_blob malformed; falling back to aggregate-summary re-evaluation",
            );
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use hort_domain::entities::scan_policy::SeverityThreshold;
    use hort_domain::events::{
        Actor, ApprovalDecided, ApprovalDecision, ArtifactQuarantined, DomainEvent, PersistedEvent,
        ScanCompleted, SeveritySummary, StreamId,
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
        }
    }

    #[tokio::test]
    async fn returns_none_when_stream_empty() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();

        let result = read_last_scan_completed(&*events, artifact_id)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn returns_none_when_stream_has_no_scan_completed() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        events.set_stream(
            &stream_id,
            vec![persisted(
                &stream_id,
                0,
                DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                    artifact_id,
                    quarantine_window_start: Utc::now(),
                }),
            )],
        );

        let result = read_last_scan_completed(&*events, artifact_id)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn returns_summary_and_blob_from_only_scan_completed() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);
        let blob = placeholder_findings_blob();

        events.set_stream(
            &stream_id,
            vec![persisted(
                &stream_id,
                0,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "trivy".into(),
                    finding_count: 3,
                    severity_summary: summary(3),
                    findings_blob: Some(blob.clone()),
                }),
            )],
        );

        let snapshot = read_last_scan_completed(&*events, artifact_id)
            .await
            .unwrap()
            .expect("ScanCompleted on stream");
        assert_eq!(snapshot.summary.critical, 3);
        assert_eq!(snapshot.findings_blob, Some(blob));
    }

    #[tokio::test]
    async fn returns_most_recent_scan_completed_when_multiple() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        events.set_stream(
            &stream_id,
            vec![
                persisted(
                    &stream_id,
                    0,
                    DomainEvent::ScanCompleted(ScanCompleted {
                        artifact_id,
                        scanner: "trivy".into(),
                        finding_count: 1,
                        severity_summary: summary(1),
                        findings_blob: Some(placeholder_findings_blob()),
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
                    }),
                ),
            ],
        );

        let snapshot = read_last_scan_completed(&*events, artifact_id)
            .await
            .unwrap()
            .expect("ScanCompleted on stream");
        // The reverse-scan must pick the second (latest) ScanCompleted.
        assert_eq!(snapshot.summary.critical, 5);
    }

    #[tokio::test]
    async fn ignores_non_scan_events_after_a_scan_completed() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        events.set_stream(
            &stream_id,
            vec![
                persisted(
                    &stream_id,
                    0,
                    DomainEvent::ScanCompleted(ScanCompleted {
                        artifact_id,
                        scanner: "trivy".into(),
                        finding_count: 7,
                        severity_summary: summary(7),
                        findings_blob: Some(placeholder_findings_blob()),
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
            ],
        );

        let snapshot = read_last_scan_completed(&*events, artifact_id)
            .await
            .unwrap()
            .expect("ScanCompleted on stream");
        assert_eq!(snapshot.summary.critical, 7);
    }

    // ---- read_last_findings ------------------------------------------------

    #[tokio::test]
    async fn read_last_findings_returns_none_when_no_scan_completed() {
        let events = Arc::new(MockEventStore::new());
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();

        let result = read_last_findings(&*events, &storage, artifact_id)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn read_last_findings_returns_none_when_scan_was_clean() {
        // Clean scan: `findings_blob = None`. Caller falls back to
        // aggregate-summary path (which sees an empty summary).
        let events = Arc::new(MockEventStore::new());
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        events.set_stream(
            &stream_id,
            vec![persisted(
                &stream_id,
                0,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "osv".into(),
                    finding_count: 0,
                    severity_summary: summary(0),
                    findings_blob: None,
                }),
            )],
        );

        let result = read_last_findings(&*events, &storage, artifact_id)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn read_last_findings_hydrates_blob_from_storage() {
        let events = Arc::new(MockEventStore::new());
        let mock_storage = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        // Seed CAS with a serialised Vec<Finding>.
        let findings = vec![
            finding("CVE-2021-23337", SeverityThreshold::High),
            finding("CVE-OTHER", SeverityThreshold::Medium),
        ];
        let bytes = serde_json::to_vec(&findings).unwrap();
        let hash_hex = format!("{:x}", Sha256::digest(&bytes));
        let blob_hash: ContentHash = hash_hex.parse().unwrap();
        mock_storage.insert_content(blob_hash.clone(), bytes);

        events.set_stream(
            &stream_id,
            vec![persisted(
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
                }),
            )],
        );

        let storage: Arc<dyn StoragePort> = mock_storage;
        let hydrated = read_last_findings(&*events, &storage, artifact_id)
            .await
            .unwrap()
            .expect("findings hydrated from CAS");
        assert_eq!(hydrated.len(), 2);
        assert_eq!(hydrated[0].vulnerability_id, "CVE-2021-23337");
        assert_eq!(hydrated[1].vulnerability_id, "CVE-OTHER");
    }

    #[tokio::test]
    async fn read_last_findings_returns_none_when_blob_missing_from_storage() {
        // The `ScanCompleted` event references a hash that is NOT in
        // CAS — best-effort: log warn, return None, caller falls back.
        let events = Arc::new(MockEventStore::new());
        let storage: Arc<dyn StoragePort> = Arc::new(MockStoragePort::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        events.set_stream(
            &stream_id,
            vec![persisted(
                &stream_id,
                0,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "osv".into(),
                    finding_count: 1,
                    severity_summary: summary(1),
                    findings_blob: Some(placeholder_findings_blob()),
                }),
            )],
        );

        let result = read_last_findings(&*events, &storage, artifact_id)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn read_last_findings_returns_none_when_blob_is_malformed_json() {
        // The blob bytes are present but don't deserialise as
        // `Vec<Finding>` — best-effort: log warn, return None.
        let events = Arc::new(MockEventStore::new());
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

        events.set_stream(
            &stream_id,
            vec![persisted(
                &stream_id,
                0,
                DomainEvent::ScanCompleted(ScanCompleted {
                    artifact_id,
                    scanner: "osv".into(),
                    finding_count: 1,
                    severity_summary: summary(1),
                    findings_blob: Some(blob_hash),
                }),
            )],
        );

        let storage: Arc<dyn StoragePort> = mock_storage;
        let result = read_last_findings(&*events, &storage, artifact_id)
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
