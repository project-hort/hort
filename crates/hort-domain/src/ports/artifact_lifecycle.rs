use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::entities::artifact::{Artifact, ArtifactMetadata};
use crate::error::DomainResult;
use crate::ports::event_store::{AppendEvents, AppendResult};
use crate::ports::repo_security_score_repository::ScoreDelta;
use crate::ports::scan_findings_repository::ScanFindingsRow;
use crate::types::sbom::SbomComponent;

use super::BoxFuture;

/// An ingest-time job to enqueue **atomically** with the artifact's creation
/// transition. The common job fields (`artifact_id`, `repository_id`,
/// `content_hash`) come from the `artifact` the commit method already carries;
/// each variant adds only its kind-specific parameters.
///
/// Consumed by [`ArtifactLifecyclePort::commit_transition_with_enqueues`] to
/// close the ingest dual-write hazard — an artifact must never be left with a
/// `ScanRequested` / provenance-gate event but no `jobs` row, which strands it
/// in quarantine (unscanned/unverified, recoverable only by a manual rescan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestEnqueue {
    /// A `kind='scan'` job — the ingest-time auto-scan. **Idempotent** on the
    /// `(artifact_id) WHERE kind='scan'` partial-unique index: a pre-existing
    /// scan job is a benign no-op, NOT a commit rollback.
    Scan {
        format: String,
        priority: i16,
        trigger_source: String,
    },
    /// A `kind='provenance-verify'` job — the ingest-time provenance gate
    /// (ADR 0027). The `jobs.params` is `{"artifact_id": <artifact.id>}`,
    /// derived from the artifact; no idempotency key (one verify per ingest).
    ProvenanceVerify {
        priority: i16,
        trigger_source: String,
    },
}

/// Outbound port for atomic artifact lifecycle transitions.
///
/// Each call persists both the domain events and the mutated artifact state
/// in a single transaction. This eliminates the dual-write hazard where
/// `EventStore::append` + `ArtifactRepository::save` could leave the
/// event log and artifact table inconsistent if a crash occurs between them.
pub trait ArtifactLifecyclePort: Send + Sync {
    /// Atomically append events to the artifact's stream, persist the
    /// artifact's updated state, and optionally upsert the
    /// `artifact_metadata` projection row.
    ///
    /// `metadata` is `Some` only on the ingest path where the format
    /// handler produced an upload-payload metadata blob. State
    /// transitions (quarantine, release, promotion) pass `None` —
    /// metadata is ingest-time-only and is never overwritten by later
    /// transitions today.
    fn commit_transition(
        &self,
        artifact: &Artifact,
        events: AppendEvents,
        metadata: Option<ArtifactMetadata>,
    ) -> BoxFuture<'_, DomainResult<AppendResult>>;

    /// `commit_transition` extended with an optional
    /// `repo_security_scores` projection bump.
    ///
    /// `score_delta` is `Some((repository_id, delta))` when the caller
    /// has computed a non-zero delta to apply to the
    /// `repo_security_scores` row in the same transaction. The Postgres
    /// adapter applies the delta inside the existing event-append +
    /// artifact-save transaction so the projection never falls out of
    /// sync with the event log; mock impls used by `hort-app` tests
    /// record the delta for assertion.
    ///
    /// Default impl forwards to [`Self::commit_transition`] and drops
    /// the delta — adequate for legacy callers and inbound-HTTP test
    /// fixtures that don't exercise the score projection. Real
    /// production impls (the Postgres adapter and the application-layer
    /// `MockArtifactLifecycle`) override this method.
    fn commit_transition_with_score<'a>(
        &'a self,
        artifact: &'a Artifact,
        events: AppendEvents,
        metadata: Option<ArtifactMetadata>,
        _score_delta: Option<(Uuid, ScoreDelta)>,
    ) -> BoxFuture<'a, DomainResult<AppendResult>> {
        // The default forward keeps the behaviour identical for
        // legacy callers. Adapters that care about the score
        // projection override the body to apply the delta in-tx.
        self.commit_transition(artifact, events, metadata)
    }

    /// Atomic dual-write for a scan
    /// result.
    ///
    /// Persists, in a single SQL transaction:
    ///
    /// 1. The supplied `events` batch (typically `ScanCompleted` plus
    ///    optional `ArtifactBecameVulnerable` and the policy-driven
    ///    `PolicyEvaluated(Fail) + ArtifactRejected` reject path).
    /// 2. The per-finding rows in `scan_findings_rows` — invariant:
    ///    per-finding rows must NEVER land without a
    ///    corresponding `ScanCompleted` event.
    /// 3. The artifact state mutation (`artifact`) — already mutated
    ///    by the use case, just persisted here.
    /// 4. `artifacts.last_scan_at = last_scan_at`.
    /// 5. Optional `repo_security_scores` projection bump
    ///    (`score_delta`).
    /// 6. Optional `sbom_components` REPLACE for the
    ///    artifact. When `sbom_components` is `Some(slice)`, the
    ///    adapter DELETEs every existing `(artifact_id, purl)` row for
    ///    `artifact.id` and INSERTs the supplied components — both
    ///    inside the same scan transaction. `None` skips the projection
    ///    write entirely (contract: the artifact had no
    ///    extractable SBOM; existing rows stay; eventual cleanup is a
    ///    future concern).
    ///
    /// Existing [`commit_transition`] stays for non-scan transitions.
    ///
    /// This method deliberately has no default impl. The
    /// previous default returned a `DomainError::Invariant` carrying
    /// the magic string `"commit_scan_result not implemented"`, which
    /// the application-layer `QuarantineUseCase` then string-matched
    /// to fall back to a per-row + transition path. Forcing every
    /// `ArtifactLifecyclePort` impl to implement this method removes
    /// the string-match dispatch.
    fn commit_scan_result_with_score<'a>(
        &'a self,
        artifact: &'a Artifact,
        events: AppendEvents,
        scan_findings_rows: &'a [ScanFindingsRow],
        last_scan_at: DateTime<Utc>,
        score_delta: Option<(Uuid, ScoreDelta)>,
        sbom_components: Option<&'a [SbomComponent]>,
    ) -> BoxFuture<'a, DomainResult<AppendResult>>;

    /// Atomically commit a **creation transition** and enqueue its
    /// ingest-time jobs (the auto-scan and the provenance gate).
    ///
    /// ## No-strand guarantee (backend-defined)
    ///
    /// Commits the `events` batch + artifact state + optional `metadata`
    /// **and** ensures every [`IngestEnqueue`] in `enqueues` becomes a durable
    /// `jobs` row, such that **no event-without-job intermediate state is ever
    /// observable**: an artifact must never carry a `ScanRequested` /
    /// provenance-gate event without its corresponding `jobs` row, which would
    /// strand it in quarantine (unscanned / unverified — fail-closed, but
    /// recoverable only by an operator-triggered manual rescan).
    ///
    /// *How* the guarantee is met is the adapter's choice — it is **not** part
    /// of the contract, so callers must never assume a shared backend:
    /// - The Postgres adapter spans **one SQL transaction** (events, artifact,
    ///   metadata, and the `jobs` inserts commit-or-roll-back together) — the
    ///   transparent fast path while the event store and the `jobs` table share
    ///   one database.
    /// - A **native event-store** adapter (a different backend from the
    ///   Postgres `jobs` table) MUST NOT assume a shared transaction; it
    ///   fulfils the same guarantee via a transactional outbox / event-stream
    ///   materialization (the durable `ScanRequested` event is the enqueue
    ///   intent; a subscriber materializes the `jobs` row, idempotent on the
    ///   `(artifact_id) WHERE kind='scan'` partial-unique index). Tracked in
    ///   the open-items register ("native event-store ingest-enqueue
    ///   no-strand").
    ///
    /// The scan enqueue is **idempotent** (`ON CONFLICT DO NOTHING` on that
    /// partial-unique index): a pre-existing scan job is a benign no-op, never
    /// a rollback. Any *other* enqueue failure rolls back the whole transition
    /// — the artifact is simply not ingested (the caller's upload fails and is
    /// retriable), never ingested-but-stranded.
    ///
    /// ## Default impl — test doubles only
    ///
    /// The default forwards to [`Self::commit_transition`] and **drops** the
    /// enqueues; it does **not** fulfil the no-strand guarantee and exists only
    /// so transition-only test doubles compile (mirrors the lossy default on
    /// [`Self::commit_transition_with_score`]). **Every production adapter MUST
    /// override it.**
    fn commit_transition_with_enqueues<'a>(
        &'a self,
        artifact: &'a Artifact,
        events: AppendEvents,
        metadata: Option<ArtifactMetadata>,
        enqueues: &'a [IngestEnqueue],
    ) -> BoxFuture<'a, DomainResult<AppendResult>> {
        let _ = enqueues;
        self.commit_transition(artifact, events, metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `ArtifactLifecyclePort` is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: size_of call executes in the test body for coverage.
        let _ = size_of::<&dyn ArtifactLifecyclePort>();
    }

    /// Default `commit_transition_with_score` forwards to
    /// `commit_transition` and ignores the score delta. A mock that
    /// overrides only `commit_transition` and inherits the default
    /// must observe both calls landing through `commit_transition`.
    #[tokio::test]
    async fn default_commit_transition_with_score_forwards_to_commit_transition() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingLifecycle {
            calls: Arc<AtomicUsize>,
        }
        impl ArtifactLifecyclePort for CountingLifecycle {
            fn commit_transition(
                &self,
                _artifact: &Artifact,
                _events: AppendEvents,
                _metadata: Option<ArtifactMetadata>,
            ) -> BoxFuture<'_, DomainResult<AppendResult>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    Ok(AppendResult {
                        stream_position: 0,
                        global_positions: vec![0],
                    })
                })
            }

            // `commit_scan_result_with_score`
            // is deliberately not defaulted; this stub is unreachable in the
            // current test (which only drives `commit_transition_with_score`).
            fn commit_scan_result_with_score<'a>(
                &'a self,
                _artifact: &'a Artifact,
                _events: AppendEvents,
                _scan_findings_rows: &'a [ScanFindingsRow],
                _last_scan_at: DateTime<Utc>,
                _score_delta: Option<(Uuid, ScoreDelta)>,
                _sbom_components: Option<&'a [SbomComponent]>,
            ) -> BoxFuture<'a, DomainResult<AppendResult>> {
                Box::pin(async { unreachable!() })
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let l = CountingLifecycle {
            calls: calls.clone(),
        };

        let artifact = Artifact {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            name: "n".into(),
            name_as_published: "n".into(),
            version: None,
            path: "/".into(),
            size_bytes: 0,
            sha256_checksum: "a".repeat(64).parse().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: crate::entities::artifact::QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let events = AppendEvents {
            stream_id: crate::events::StreamId::artifact(Uuid::nil()),
            expected_version: crate::ports::event_store::ExpectedVersion::NoStream,
            events: vec![],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: crate::events::system_actor(),
        };

        // Without score delta — forwards.
        l.commit_transition_with_score(&artifact, events.clone(), None, None)
            .await
            .unwrap();
        // With score delta — also forwards (delta is dropped by the
        // default; concrete impls apply it).
        l.commit_transition_with_score(
            &artifact,
            events,
            None,
            Some((Uuid::nil(), ScoreDelta::default())),
        )
        .await
        .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// The defaulted `commit_transition_with_enqueues` forwards to
    /// `commit_transition` and DROPS the enqueues — the test-double-only
    /// behaviour (production adapters override to commit them atomically).
    /// Also exercises the `IngestEnqueue` value type.
    #[tokio::test]
    async fn default_commit_transition_with_enqueues_forwards_and_drops() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingLifecycle {
            calls: Arc<AtomicUsize>,
        }
        impl ArtifactLifecyclePort for CountingLifecycle {
            fn commit_transition(
                &self,
                _artifact: &Artifact,
                _events: AppendEvents,
                _metadata: Option<ArtifactMetadata>,
            ) -> BoxFuture<'_, DomainResult<AppendResult>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    Ok(AppendResult {
                        stream_position: 0,
                        global_positions: vec![0],
                    })
                })
            }
            fn commit_scan_result_with_score<'a>(
                &'a self,
                _artifact: &'a Artifact,
                _events: AppendEvents,
                _scan_findings_rows: &'a [ScanFindingsRow],
                _last_scan_at: DateTime<Utc>,
                _score_delta: Option<(Uuid, ScoreDelta)>,
                _sbom_components: Option<&'a [SbomComponent]>,
            ) -> BoxFuture<'a, DomainResult<AppendResult>> {
                Box::pin(async { unreachable!() })
            }
        }

        // `IngestEnqueue` value type: Clone + PartialEq + Debug.
        let scan = IngestEnqueue::Scan {
            format: "pypi".into(),
            priority: 0,
            trigger_source: "ingest".into(),
        };
        let prov = IngestEnqueue::ProvenanceVerify {
            priority: 0,
            trigger_source: "ingest".into(),
        };
        assert_eq!(scan.clone(), scan);
        assert_ne!(scan, prov);
        assert!(format!("{scan:?}").contains("Scan"));

        let calls = Arc::new(AtomicUsize::new(0));
        let l = CountingLifecycle {
            calls: calls.clone(),
        };

        let artifact = Artifact {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            name: "n".into(),
            name_as_published: "n".into(),
            version: None,
            path: "/".into(),
            size_bytes: 0,
            sha256_checksum: "a".repeat(64).parse().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: crate::entities::artifact::QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let events = AppendEvents {
            stream_id: crate::events::StreamId::artifact(Uuid::nil()),
            expected_version: crate::ports::event_store::ExpectedVersion::NoStream,
            events: vec![],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: crate::events::system_actor(),
        };

        // The default forwards to commit_transition (dropping the enqueues).
        l.commit_transition_with_enqueues(&artifact, events.clone(), None, &[scan, prov])
            .await
            .unwrap();
        // Empty enqueues also forward.
        l.commit_transition_with_enqueues(&artifact, events, None, &[])
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// `commit_scan_result_with_score` is
    /// non-defaulted on the trait. Every impl must provide a body, so
    /// any forwarding it does is its own choice (not the trait's).
    /// This compile-time witness confirms the method is required: a
    /// trait impl that omits `commit_scan_result_with_score` does not
    /// compile.
    #[tokio::test]
    async fn commit_scan_result_with_score_is_a_required_method() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct ScanResultLifecycle {
            calls: Arc<AtomicUsize>,
        }
        impl ArtifactLifecyclePort for ScanResultLifecycle {
            fn commit_transition(
                &self,
                _artifact: &Artifact,
                _events: AppendEvents,
                _metadata: Option<ArtifactMetadata>,
            ) -> BoxFuture<'_, DomainResult<AppendResult>> {
                Box::pin(async { unreachable!() })
            }

            fn commit_scan_result_with_score<'a>(
                &'a self,
                _artifact: &'a Artifact,
                _events: AppendEvents,
                _scan_findings_rows: &'a [ScanFindingsRow],
                _last_scan_at: DateTime<Utc>,
                _score_delta: Option<(Uuid, ScoreDelta)>,
                _sbom_components: Option<&'a [SbomComponent]>,
            ) -> BoxFuture<'a, DomainResult<AppendResult>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    Ok(AppendResult {
                        stream_position: 0,
                        global_positions: vec![],
                    })
                })
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let l = ScanResultLifecycle {
            calls: calls.clone(),
        };
        let artifact = Artifact {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            name: "n".into(),
            name_as_published: "n".into(),
            version: None,
            path: "/".into(),
            size_bytes: 0,
            sha256_checksum: "a".repeat(64).parse().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: crate::entities::artifact::QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let events = AppendEvents {
            stream_id: crate::events::StreamId::artifact(Uuid::nil()),
            expected_version: crate::ports::event_store::ExpectedVersion::NoStream,
            events: vec![],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: crate::events::system_actor(),
        };
        l.commit_scan_result_with_score(&artifact, events, &[], Utc::now(), None, None)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// The `sbom_components` parameter is `Option`, so
    /// passing `None` (no SBOM) and `Some(&[])` (extracted SBOM with no
    /// listed components) are observably distinct call shapes. Pin the
    /// trait shape with a lifecycle that records which arm fired.
    #[tokio::test]
    async fn commit_scan_result_with_score_threads_sbom_components_argument() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct RecordingLifecycle {
            none_calls: Arc<AtomicUsize>,
            some_empty_calls: Arc<AtomicUsize>,
            some_nonempty_calls: Arc<AtomicUsize>,
        }
        impl ArtifactLifecyclePort for RecordingLifecycle {
            fn commit_transition(
                &self,
                _artifact: &Artifact,
                _events: AppendEvents,
                _metadata: Option<ArtifactMetadata>,
            ) -> BoxFuture<'_, DomainResult<AppendResult>> {
                Box::pin(async { unreachable!() })
            }

            fn commit_scan_result_with_score<'a>(
                &'a self,
                _artifact: &'a Artifact,
                _events: AppendEvents,
                _scan_findings_rows: &'a [ScanFindingsRow],
                _last_scan_at: DateTime<Utc>,
                _score_delta: Option<(Uuid, ScoreDelta)>,
                sbom_components: Option<&'a [SbomComponent]>,
            ) -> BoxFuture<'a, DomainResult<AppendResult>> {
                match sbom_components {
                    None => self.none_calls.fetch_add(1, Ordering::SeqCst),
                    Some([]) => self.some_empty_calls.fetch_add(1, Ordering::SeqCst),
                    Some(_) => self.some_nonempty_calls.fetch_add(1, Ordering::SeqCst),
                };
                Box::pin(async {
                    Ok(AppendResult {
                        stream_position: 0,
                        global_positions: vec![],
                    })
                })
            }
        }

        let none_calls = Arc::new(AtomicUsize::new(0));
        let some_empty_calls = Arc::new(AtomicUsize::new(0));
        let some_nonempty_calls = Arc::new(AtomicUsize::new(0));
        let l = RecordingLifecycle {
            none_calls: none_calls.clone(),
            some_empty_calls: some_empty_calls.clone(),
            some_nonempty_calls: some_nonempty_calls.clone(),
        };
        let artifact = Artifact {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            name: "n".into(),
            name_as_published: "n".into(),
            version: None,
            path: "/".into(),
            size_bytes: 0,
            sha256_checksum: "a".repeat(64).parse().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".into(),
            quarantine_status: crate::entities::artifact::QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let events = AppendEvents {
            stream_id: crate::events::StreamId::artifact(Uuid::nil()),
            expected_version: crate::ports::event_store::ExpectedVersion::NoStream,
            events: vec![],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: crate::events::system_actor(),
        };

        l.commit_scan_result_with_score(&artifact, events.clone(), &[], Utc::now(), None, None)
            .await
            .unwrap();
        l.commit_scan_result_with_score(
            &artifact,
            events.clone(),
            &[],
            Utc::now(),
            None,
            Some(&[]),
        )
        .await
        .unwrap();
        let comp = SbomComponent {
            purl: "pkg:npm/foo@1".into(),
            name: "foo".into(),
            version: Some("1".into()),
            ecosystem: crate::types::sbom::Ecosystem::Npm,
            licenses: vec![],
            direct_dependency: true,
        };
        let comps = [comp];
        l.commit_scan_result_with_score(&artifact, events, &[], Utc::now(), None, Some(&comps))
            .await
            .unwrap();

        assert_eq!(none_calls.load(Ordering::SeqCst), 1);
        assert_eq!(some_empty_calls.load(Ordering::SeqCst), 1);
        assert_eq!(some_nonempty_calls.load(Ordering::SeqCst), 1);
    }
}
