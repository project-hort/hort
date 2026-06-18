//! `RetentionUseCase::evaluate_policies` unit tests.
//!
//! `hort-app` is the 100%-coverage tier (mock all ports). Every branch
//! of the use case is pinned here: the quarantine/rejected GC-protection
//! filter (quarantined / rejected / scan_indeterminate / none / released),
//! the scan-data freshness gate (fresh / stale / no-row / no-last-scan /
//! score-read-error / disabled-rescan),
//! idempotency (already-expired no-op), the `HasFindingDetectedFor`
//! anchor ladder (ABV → earliest ScanCompleted → created_at cold-data
//! fallback), the archived-policy skip, the per-pair port-error path,
//! and a `DebuggingRecorder` assertion that
//! `hort_retention_evaluations_total{result="skipped_stale_scan"}` (and
//! the matched / no_match / expired counters) fire with the documented
//! `policy_id` + `result` / `reason` labels.

use std::sync::Arc;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{
    ArtifactBecameVulnerable, DomainEvent, IngestSource, PersistedEvent, ScanCompleted,
    SeveritySummary, StreamId,
};
use hort_domain::ports::repo_security_score_repository::RepoSecurityScore;
use hort_domain::ports::retention_scan_reader::RetentionScanReader;
use hort_domain::ports::BoxFuture;
use hort_domain::retention::{
    BooleanOp, ExpirationReason, PolicyPredicate, RetentionPolicy, RetentionPolicyEvent,
    RetentionScope,
};
use hort_domain::types::Finding;

use crate::event_store_publisher::wrap_for_test;
use crate::use_cases::retention_use_case::{RetentionCandidate, RetentionUseCase};
use crate::use_cases::test_support::{api_actor, sample_artifact, MockEventStore};

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).unwrap()
}

// ---------------------------------------------------------------------------
// MockRetentionScanReader
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockRetentionScanReader {
    findings: Mutex<Vec<Finding>>,
    findings_err: Mutex<bool>,
    score: Mutex<Option<RepoSecurityScore>>,
    score_err: Mutex<bool>,
}

impl MockRetentionScanReader {
    fn new() -> Self {
        Self::default()
    }
    fn with_findings(self, f: Vec<Finding>) -> Self {
        *self.findings.lock().unwrap() = f;
        self
    }
    fn with_score(self, s: RepoSecurityScore) -> Self {
        *self.score.lock().unwrap() = Some(s);
        self
    }
    fn with_findings_err(self) -> Self {
        *self.findings_err.lock().unwrap() = true;
        self
    }
    fn with_score_err(self) -> Self {
        *self.score_err.lock().unwrap() = true;
        self
    }
}

impl RetentionScanReader for MockRetentionScanReader {
    fn list_findings_for_artifact(
        &self,
        _artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<Finding>>> {
        let err = *self.findings_err.lock().unwrap();
        let f = self.findings.lock().unwrap().clone();
        Box::pin(async move {
            if err {
                Err(DomainError::Invariant("findings read failed".into()))
            } else {
                Ok(f)
            }
        })
    }
    fn repo_security_score(
        &self,
        _repo_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Option<RepoSecurityScore>>> {
        let err = *self.score_err.lock().unwrap();
        let s = self.score.lock().unwrap().clone();
        Box::pin(async move {
            if err {
                Err(DomainError::Invariant("score read failed".into()))
            } else {
                Ok(s)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

fn finding(sev: SeverityThreshold, cvss: Option<f32>, fixed: Vec<&str>) -> Finding {
    Finding {
        purl: "pkg:npm/x@1".into(),
        vulnerability_id: "CVE-1".into(),
        severity: sev,
        cvss_score: cvss,
        title: "t".into(),
        fixed_versions: fixed.into_iter().map(String::from).collect(),
        source_scanner: "trivy".into(),
        references: vec![],
        aliases: vec![],
    }
}

fn score(repo_id: Uuid, last_scan_at: Option<DateTime<Utc>>) -> RepoSecurityScore {
    RepoSecurityScore {
        repository_id: repo_id,
        quarantined_count: 0,
        rejected_count: 0,
        released_count: 1,
        critical_count: 0,
        high_count: 1,
        medium_count: 0,
        low_count: 0,
        last_scan_at,
        updated_at: Utc::now(),
    }
}

fn policy(predicate: PolicyPredicate, scope: RetentionScope) -> RetentionPolicy {
    let id = Uuid::new_v4();
    RetentionPolicy::project(&[RetentionPolicyEvent::Created {
        id,
        name: "test-policy".into(),
        predicate,
        scope,
        created_at: ts(0),
    }])
    .unwrap()
}

fn archived_policy() -> RetentionPolicy {
    let id = Uuid::new_v4();
    RetentionPolicy::project(&[
        RetentionPolicyEvent::Created {
            id,
            name: "arch".into(),
            predicate: PolicyPredicate::AgeExceeds(1),
            scope: RetentionScope::AllRepos,
            created_at: ts(0),
        },
        RetentionPolicyEvent::Archived {
            id,
            by: Uuid::nil(),
            archived_at: ts(10),
        },
    ])
    .unwrap()
}

fn persisted(
    stream: &StreamId,
    pos: u64,
    stored_at: DateTime<Utc>,
    ev: DomainEvent,
) -> PersistedEvent {
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: stream.clone(),
        stream_position: pos,
        global_position: pos + 1,
        event: ev,
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: hort_domain::events::Actor::Api(api_actor()),
        event_version: 1,
        stored_at,
    }
}

fn scan_completed(artifact_id: Uuid) -> DomainEvent {
    DomainEvent::ScanCompleted(ScanCompleted {
        artifact_id,
        scanner: "trivy".into(),
        finding_count: 0,
        severity_summary: SeveritySummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            negligible: 0,
        },
        findings_blob: None,
    })
}

/// `ArtifactIngested` genesis event for `artifact_id` with the given
/// `source`. Every real artifact stream starts with this event — the
/// scope gate resolves `IngestSource` from it, so the retention
/// fixtures seed a realistic stream rather than an empty one.
fn ingested(artifact_id: Uuid, source: IngestSource) -> DomainEvent {
    DomainEvent::ArtifactIngested(hort_domain::events::ArtifactIngested {
        artifact_id,
        repository_id: Uuid::new_v4(),
        name: "my-pkg".into(),
        version: Some("1.0.0".into()),
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap(),
        size_bytes: 2048,
        source,
        metadata: serde_json::Value::Null,
        metadata_blob: None,
        upstream_published_at: None,
    })
}

fn build(reader: MockRetentionScanReader) -> (RetentionUseCase, Arc<MockEventStore>) {
    let store = Arc::new(MockEventStore::new());
    let events = wrap_for_test(store.clone());
    let uc = RetentionUseCase::new(events, Arc::new(reader));
    (uc, store)
}

fn candidate(status: QuarantineStatus, created_at: DateTime<Utc>) -> RetentionCandidate {
    let mut a = sample_artifact(status);
    a.created_at = created_at;
    RetentionCandidate {
        artifact: a,
        format: hort_domain::entities::repository::RepositoryFormat::Generic,
        resolved_rescan_interval_hours: Some(24),
    }
}

/// Seed the candidate's artifact stream with a realistic genesis
/// `ArtifactIngested` (the scope gate needs it) followed by any
/// `extra` events, renumbering stream positions from 0. Returns the
/// `StreamId` for convenience. Use `IngestSource::Proxied` for the
/// genesis unless a scope test needs a specific source.
fn seed_stream(
    store: &MockEventStore,
    c: &RetentionCandidate,
    source: IngestSource,
    extra: Vec<DomainEvent>,
) -> StreamId {
    let stream_id = StreamId::artifact(c.artifact.id);
    let mut events = vec![persisted(
        &stream_id,
        0,
        c.artifact.created_at,
        ingested(c.artifact.id, source),
    )];
    for (i, ev) in extra.into_iter().enumerate() {
        events.push(persisted(
            &stream_id,
            (i + 1) as u64,
            c.artifact.created_at,
            ev,
        ));
    }
    store.set_stream(&stream_id, events);
    stream_id
}

/// Seed a realistic security-driven-retention stream: genesis
/// `ArtifactIngested` then a `ScanCompleted` that is **fresh** for
/// `now` (1h old, well inside the default 2×24h window). The
/// scan-data freshness gate is per-artifact, so a security predicate
/// only evaluates against an artifact whose own most-recent scan is
/// fresh — every security-predicate fixture must therefore put a
/// recent `ScanCompleted` on the artifact's own stream. `extra` events
/// follow the scan (positions renumbered from 0).
fn seed_fresh_scanned_stream(
    store: &MockEventStore,
    c: &RetentionCandidate,
    now: DateTime<Utc>,
    extra: Vec<DomainEvent>,
) -> StreamId {
    let stream_id = StreamId::artifact(c.artifact.id);
    let mut events = vec![
        persisted(
            &stream_id,
            0,
            c.artifact.created_at,
            ingested(c.artifact.id, IngestSource::Proxied),
        ),
        persisted(
            &stream_id,
            1,
            now - Duration::hours(1),
            scan_completed(c.artifact.id),
        ),
    ];
    for (i, ev) in extra.into_iter().enumerate() {
        events.push(persisted(
            &stream_id,
            (i + 2) as u64,
            now - Duration::hours(1),
            ev,
        ));
    }
    store.set_stream(&stream_id, events);
    stream_id
}

// ===========================================================================
// Quarantine / rejected GC-protection
// ===========================================================================

#[tokio::test]
async fn inv1_quarantined_is_skipped_no_event() {
    let (uc, store) = build(MockRetentionScanReader::new());
    let p = policy(PolicyPredicate::AgeExceeds(1), RetentionScope::AllRepos);
    let c = candidate(QuarantineStatus::Quarantined, ts(0));
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(s.skipped_protected, 1);
    assert_eq!(s.expired, 0);
    assert!(store.appended_batches().is_empty());
}

#[tokio::test]
async fn inv1_rejected_is_skipped_no_event() {
    let (uc, store) = build(MockRetentionScanReader::new());
    let p = policy(PolicyPredicate::AgeExceeds(1), RetentionScope::AllRepos);
    let c = candidate(QuarantineStatus::Rejected, ts(0));
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(s.skipped_protected, 1);
    assert!(store.appended_batches().is_empty());
}

#[tokio::test]
async fn inv1_scan_indeterminate_is_protected_like_rejected() {
    let (uc, store) = build(MockRetentionScanReader::new());
    let p = policy(PolicyPredicate::AgeExceeds(1), RetentionScope::AllRepos);
    let c = candidate(QuarantineStatus::ScanIndeterminate, ts(0));
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(s.skipped_protected, 1);
    assert!(store.appended_batches().is_empty());
}

#[tokio::test]
async fn inv1_none_and_released_are_eligible() {
    for status in [QuarantineStatus::None, QuarantineStatus::Released] {
        let (uc, store) = build(MockRetentionScanReader::new());
        let p = policy(PolicyPredicate::AgeExceeds(1), RetentionScope::AllRepos);
        let c = candidate(status, ts(0));
        seed_stream(&store, &c, IngestSource::Proxied, vec![]);
        let s = uc
            .evaluate_policies(ts(1_000_000), &[p], &[c])
            .await
            .unwrap();
        assert_eq!(s.skipped_protected, 0, "status {status:?} must be eligible");
        assert_eq!(s.expired, 1, "status {status:?} must expire on age match");
        assert_eq!(store.appended_batches().len(), 1);
    }
}

// ===========================================================================
// Scan-data freshness gate
// ===========================================================================

#[tokio::test]
async fn inv7_fresh_scan_allows_security_predicate() {
    let repo_id = {
        let c = candidate(QuarantineStatus::Released, ts(0));
        c.artifact.repository_id
    };
    // This artifact's own ScanCompleted is 1h ago, 24h interval → 48h
    // window → fresh (per-artifact freshness gate).
    let reader = MockRetentionScanReader::new().with_findings(vec![finding(
        SeverityThreshold::Critical,
        Some(9.8),
        vec![],
    )]);
    let (uc, store) = build(reader);
    let mut c = candidate(QuarantineStatus::Released, ts(0));
    c.artifact.repository_id = repo_id;
    seed_fresh_scanned_stream(&store, &c, ts(1_000_000), vec![]);
    let p = policy(
        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
        RetentionScope::AllRepos,
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(s.expired, 1);
    assert_eq!(s.skipped_stale_scan, 0);
    assert_eq!(store.appended_batches().len(), 1);
}

#[tokio::test]
async fn inv7_stale_scan_skips_security_predicate_not_an_error() {
    let repo_id = Uuid::new_v4();
    // last_scan 100h ago, 24h interval → 48h window → STALE.
    let reader = MockRetentionScanReader::new()
        .with_findings(vec![finding(
            SeverityThreshold::Critical,
            Some(9.8),
            vec![],
        )])
        .with_score(score(repo_id, Some(ts(1_000_000) - Duration::hours(100))));
    let (uc, store) = build(reader);
    let mut c = candidate(QuarantineStatus::Released, ts(0));
    c.artifact.repository_id = repo_id;
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);
    let p = policy(
        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
        RetentionScope::AllRepos,
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(s.skipped_stale_scan, 1);
    assert_eq!(s.expired, 0);
    assert_eq!(s.errors, 0, "stale is NOT an error");
    assert!(store.appended_batches().is_empty());
}

#[tokio::test]
async fn inv7_no_score_row_treats_security_predicate_as_stale() {
    let reader = MockRetentionScanReader::new().with_findings(vec![finding(
        SeverityThreshold::Critical,
        Some(9.8),
        vec![],
    )]);
    let (uc, store) = build(reader);
    let c = candidate(QuarantineStatus::Released, ts(0));
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);
    let p = policy(
        PolicyPredicate::HasFindingAboveCvss(7.0),
        RetentionScope::AllRepos,
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(s.skipped_stale_scan, 1);
    assert_eq!(s.errors, 0);
}

#[tokio::test]
async fn inv7_score_row_without_last_scan_is_stale() {
    let repo_id = Uuid::new_v4();
    let reader = MockRetentionScanReader::new()
        .with_findings(vec![finding(
            SeverityThreshold::Critical,
            Some(9.8),
            vec![],
        )])
        .with_score(score(repo_id, None));
    let (uc, store) = build(reader);
    let mut c = candidate(QuarantineStatus::Released, ts(0));
    c.artifact.repository_id = repo_id;
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);
    let p = policy(PolicyPredicate::HasFixAvailable, RetentionScope::AllRepos);
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(s.skipped_stale_scan, 1);
}

#[tokio::test]
async fn inv7_score_read_error_fails_safe_to_stale() {
    let reader = MockRetentionScanReader::new()
        .with_findings(vec![finding(
            SeverityThreshold::Critical,
            Some(9.8),
            vec![],
        )])
        .with_score_err();
    let (uc, store) = build(reader);
    let c = candidate(QuarantineStatus::Released, ts(0));
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);
    let p = policy(
        PolicyPredicate::HasFindingAboveCvss(1.0),
        RetentionScope::AllRepos,
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    // Score-read failure → cannot prove freshness → treated as stale,
    // NOT a hard error (the security predicate just does not run).
    assert_eq!(s.skipped_stale_scan, 1);
    assert_eq!(s.errors, 0);
}

#[tokio::test]
async fn inv7_does_not_gate_non_security_predicate() {
    // AgeExceeds is not security-driven → no freshness gate, no score
    // needed; it expires purely on age.
    let (uc, store) = build(MockRetentionScanReader::new());
    let p = policy(PolicyPredicate::AgeExceeds(1), RetentionScope::AllRepos);
    let c = candidate(QuarantineStatus::Released, ts(0));
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(s.expired, 1);
    assert_eq!(s.skipped_stale_scan, 0);
    assert_eq!(store.appended_batches().len(), 1);
}

// ===========================================================================
// The scan-data freshness gate is PER-ARTIFACT. The repo_security_score
// .last_scan_at is a per-repo MAX — a fresh scan on a *different*
// artifact in the same repo must NOT make THIS artifact look fresh.
// The freshness signal is this artifact's most-recent ScanCompleted
// on its own stream (`latest_scan_at`), tightened from the weaker
// repo-score reading.
// ===========================================================================

#[tokio::test]
async fn inv7_per_artifact_stale_even_when_repo_score_is_fresh() {
    let repo_id = Uuid::new_v4();
    // repo_security_score.last_scan_at is FRESH (1h ago) — a scan on
    // some OTHER artifact in the same repo. The per-repo MAX must NOT
    // rescue THIS artifact, whose own latest ScanCompleted is 200h old
    // (>> 2×24h window) → stale → security predicate skipped.
    let reader = MockRetentionScanReader::new()
        .with_findings(vec![finding(
            SeverityThreshold::Critical,
            Some(9.8),
            vec![],
        )])
        .with_score(score(repo_id, Some(ts(1_000_000) - Duration::hours(1))));
    let (uc, store) = build(reader);
    let mut c = candidate(QuarantineStatus::Released, ts(0));
    c.artifact.repository_id = repo_id;
    // This artifact's own stream: genesis + a STALE ScanCompleted.
    let stream_id = StreamId::artifact(c.artifact.id);
    store.set_stream(
        &stream_id,
        vec![
            persisted(
                &stream_id,
                0,
                c.artifact.created_at,
                ingested(c.artifact.id, IngestSource::Proxied),
            ),
            persisted(
                &stream_id,
                1,
                ts(1_000_000) - Duration::hours(200),
                scan_completed(c.artifact.id),
            ),
        ],
    );
    let p = policy(
        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
        RetentionScope::AllRepos,
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(
        s.skipped_stale_scan, 1,
        "per-artifact freshness: a fresh repo-score MAX must not rescue \
         an artifact whose own latest scan is stale"
    );
    assert_eq!(s.expired, 0, "stale artifact must NOT be expired");
    assert_eq!(s.errors, 0, "stale is NOT an error");
    assert!(store.appended_batches().is_empty());
}

#[tokio::test]
async fn inv7_per_artifact_fresh_scan_on_own_stream_allows_predicate() {
    let repo_id = Uuid::new_v4();
    // No repo-score row at all (would have been STALE under the old
    // per-repo reading) — but THIS artifact has a FRESH ScanCompleted
    // on its own stream → per-artifact freshness allows the predicate.
    let reader = MockRetentionScanReader::new().with_findings(vec![finding(
        SeverityThreshold::Critical,
        Some(9.8),
        vec![],
    )]);
    let (uc, store) = build(reader);
    let mut c = candidate(QuarantineStatus::Released, ts(0));
    c.artifact.repository_id = repo_id;
    let stream_id = StreamId::artifact(c.artifact.id);
    store.set_stream(
        &stream_id,
        vec![
            persisted(
                &stream_id,
                0,
                c.artifact.created_at,
                ingested(c.artifact.id, IngestSource::Proxied),
            ),
            persisted(
                &stream_id,
                1,
                ts(1_000_000) - Duration::hours(1),
                scan_completed(c.artifact.id),
            ),
        ],
    );
    let p = policy(
        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
        RetentionScope::AllRepos,
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(s.skipped_stale_scan, 0, "own fresh scan → not stale");
    assert_eq!(s.expired, 1, "fresh per-artifact scan → predicate runs");
}

#[tokio::test]
async fn inv7_per_artifact_no_scan_on_stream_is_stale_fail_safe() {
    let repo_id = Uuid::new_v4();
    // Fresh repo-score MAX, but THIS artifact has NO ScanCompleted on
    // its stream at all → cannot prove per-artifact freshness → stale
    // (fail-safe: never expire on an unprovable security predicate).
    let reader = MockRetentionScanReader::new()
        .with_findings(vec![finding(
            SeverityThreshold::Critical,
            Some(9.8),
            vec![],
        )])
        .with_score(score(repo_id, Some(ts(1_000_000) - Duration::hours(1))));
    let (uc, store) = build(reader);
    let mut c = candidate(QuarantineStatus::Released, ts(0));
    c.artifact.repository_id = repo_id;
    // Genesis only — no scan event.
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);
    let p = policy(
        PolicyPredicate::HasFindingAboveCvss(7.0),
        RetentionScope::AllRepos,
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(s.skipped_stale_scan, 1);
    assert_eq!(s.errors, 0);
    assert!(store.appended_batches().is_empty());
}

// ===========================================================================
// Scope gate: scoped policies must not apply cluster-wide. The
// data-loss blocker — a `Repos([other])` / `Format(other)` /
// `IngestSource(other)` / `PackageNamePattern(non-match)` policy must
// NOT expire every artifact the candidate-reader returns, ignoring its
// declared scope.
// ===========================================================================

#[tokio::test]
async fn scope_repos_miss_does_not_expire_out_of_scope_artifact() {
    let (uc, store) = build(MockRetentionScanReader::new());
    // Policy scoped to a DIFFERENT repository than the candidate's.
    let other_repo = Uuid::new_v4();
    let p = policy(
        PolicyPredicate::AgeExceeds(1),
        RetentionScope::Repos(vec![other_repo]),
    );
    let c = candidate(QuarantineStatus::Released, ts(0));
    assert_ne!(c.artifact.repository_id, other_repo);
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);

    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(s.expired, 0, "out-of-scope artifact must NOT be expired");
    assert_eq!(s.evaluated, 1);
    assert!(
        store.appended_batches().is_empty(),
        "no ArtifactExpired may be appended for an out-of-scope artifact"
    );
}

#[tokio::test]
async fn scope_repos_hit_still_expires_in_scope_artifact() {
    let (uc, store) = build(MockRetentionScanReader::new());
    let c = candidate(QuarantineStatus::Released, ts(0));
    // Policy scoped to the candidate's OWN repository.
    let p = policy(
        PolicyPredicate::AgeExceeds(1),
        RetentionScope::Repos(vec![c.artifact.repository_id]),
    );
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);

    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(s.expired, 1, "in-scope artifact must still expire");
    assert_eq!(store.appended_batches().len(), 1);
}

#[tokio::test]
async fn scope_format_miss_does_not_expire() {
    let (uc, store) = build(MockRetentionScanReader::new());
    // candidate() builds RepositoryFormat::Generic — scope to Npm.
    let p = policy(
        PolicyPredicate::AgeExceeds(1),
        RetentionScope::Format(hort_domain::entities::repository::RepositoryFormat::Npm),
    );
    let c = candidate(QuarantineStatus::Released, ts(0));
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);

    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(s.expired, 0);
    assert!(store.appended_batches().is_empty());
}

#[tokio::test]
async fn scope_format_hit_expires() {
    let (uc, store) = build(MockRetentionScanReader::new());
    let p = policy(
        PolicyPredicate::AgeExceeds(1),
        RetentionScope::Format(hort_domain::entities::repository::RepositoryFormat::Generic),
    );
    let c = candidate(QuarantineStatus::Released, ts(0));
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);

    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(s.expired, 1);
}

#[tokio::test]
async fn scope_ingest_source_miss_does_not_expire() {
    let (uc, store) = build(MockRetentionScanReader::new());
    // Policy scoped to Direct uploads; the artifact's genesis is Proxied.
    let p = policy(
        PolicyPredicate::AgeExceeds(1),
        RetentionScope::IngestSource(IngestSource::Direct),
    );
    let c = candidate(QuarantineStatus::Released, ts(0));
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);

    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(
        s.expired, 0,
        "Proxied artifact out of a Direct-scoped policy"
    );
    assert!(store.appended_batches().is_empty());
}

#[tokio::test]
async fn scope_ingest_source_hit_expires() {
    let (uc, store) = build(MockRetentionScanReader::new());
    let p = policy(
        PolicyPredicate::AgeExceeds(1),
        RetentionScope::IngestSource(IngestSource::Proxied),
    );
    let c = candidate(QuarantineStatus::Released, ts(0));
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);

    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(s.expired, 1);
}

#[tokio::test]
async fn scope_package_name_pattern_miss_does_not_expire() {
    let (uc, store) = build(MockRetentionScanReader::new());
    // sample_artifact() names the package "my-pkg"; pattern wants xz-*.
    let p = policy(
        PolicyPredicate::AgeExceeds(1),
        RetentionScope::PackageNamePattern("xz-*".into()),
    );
    let c = candidate(QuarantineStatus::Released, ts(0));
    assert_eq!(c.artifact.name, "my-pkg");
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);

    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(s.expired, 0);
    assert!(store.appended_batches().is_empty());
}

#[tokio::test]
async fn scope_package_name_pattern_hit_expires() {
    let (uc, store) = build(MockRetentionScanReader::new());
    let p = policy(
        PolicyPredicate::AgeExceeds(1),
        RetentionScope::PackageNamePattern("my-*".into()),
    );
    let c = candidate(QuarantineStatus::Released, ts(0));
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);

    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(s.expired, 1);
}

#[tokio::test]
async fn scope_gate_fails_safe_when_no_artifact_ingested_on_stream() {
    // The genesis event cannot really be absent, but the gate must
    // fail SAFE (never expire) + not error if it ever is. AllRepos
    // scope would otherwise match — proving the gate is the thing
    // short-circuiting, not the scope.
    let (uc, store) = build(MockRetentionScanReader::new());
    let p = policy(PolicyPredicate::AgeExceeds(1), RetentionScope::AllRepos);
    let c = candidate(QuarantineStatus::Released, ts(0));
    // Deliberately seed a stream WITHOUT an ArtifactIngested event.
    let stream_id = StreamId::artifact(c.artifact.id);
    store.set_stream(
        &stream_id,
        vec![persisted(
            &stream_id,
            0,
            ts(0),
            scan_completed(c.artifact.id),
        )],
    );

    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], std::slice::from_ref(&c))
        .await
        .unwrap();
    assert_eq!(s.expired, 0, "fail-safe: no genesis → never expire");
    assert_eq!(s.errors, 0, "fail-safe is NOT an error");
    assert!(store.appended_batches().is_empty());
}

// ===========================================================================
// Idempotency on (policy_id, artifact_id)
// ===========================================================================

#[tokio::test]
async fn idempotent_running_twice_yields_one_artifact_expired() {
    let (uc, store) = build(MockRetentionScanReader::new());
    let p = policy(PolicyPredicate::AgeExceeds(1), RetentionScope::AllRepos);
    let c = candidate(QuarantineStatus::Released, ts(0));
    let stream_id = seed_stream(&store, &c, IngestSource::Proxied, vec![]);

    // First pass: matches and appends.
    let s1 = uc
        .evaluate_policies(
            ts(1_000_000),
            std::slice::from_ref(&p),
            std::slice::from_ref(&c),
        )
        .await
        .unwrap();
    assert_eq!(s1.expired, 1);
    assert_eq!(store.appended_batches().len(), 1);

    // Seed the stream with the genesis + the ArtifactExpired the mock
    // would now hold (MockEventStore.append does not auto-populate
    // read_stream).
    let appended = &store.appended_batches()[0];
    let expired_ev = appended.events[0].event.clone();
    store.set_stream(
        &stream_id,
        vec![
            persisted(
                &stream_id,
                0,
                c.artifact.created_at,
                ingested(c.artifact.id, IngestSource::Proxied),
            ),
            persisted(&stream_id, 1, ts(1_000_000), expired_ev),
        ],
    );

    // Second pass: must be an idempotent no-op.
    let s2 = uc
        .evaluate_policies(ts(2_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(s2.expired, 0, "second pass must not re-expire");
    assert_eq!(s2.already_expired, 1);
    assert_eq!(
        store.appended_batches().len(),
        1,
        "no second ArtifactExpired append"
    );
}

#[tokio::test]
async fn idempotency_is_scoped_per_policy_id() {
    // An ArtifactExpired from policy A must NOT suppress policy B.
    let (uc, store) = build(MockRetentionScanReader::new());
    let pa = policy(PolicyPredicate::AgeExceeds(1), RetentionScope::AllRepos);
    let pb = policy(PolicyPredicate::AgeExceeds(1), RetentionScope::AllRepos);
    let c = candidate(QuarantineStatus::Released, ts(0));

    // Genesis + an ArtifactExpired authored by policy A.
    let prior = DomainEvent::ArtifactExpired(hort_domain::events::ArtifactExpired {
        artifact_id: c.artifact.id,
        policy_id: pa.id,
        policy_name: pa.name.clone(),
        reason: ExpirationReason::AgeExceeded {
            published_at: ts(0),
            ttl_secs: 1,
        },
        eligible_at: ts(500_000),
    });
    seed_stream(&store, &c, IngestSource::Proxied, vec![prior]);

    let s = uc
        .evaluate_policies(ts(1_000_000), &[pb], &[c])
        .await
        .unwrap();
    assert_eq!(s.expired, 1, "policy B is independent of policy A's expiry");
    assert_eq!(s.already_expired, 0);
}

// ===========================================================================
// HasFindingDetectedFor anchor ladder
// ===========================================================================

#[tokio::test]
async fn detected_for_uses_artifact_became_vulnerable_anchor_o1() {
    let repo_id = Uuid::new_v4();
    let reader = MockRetentionScanReader::new().with_findings(vec![finding(
        SeverityThreshold::High,
        Some(7.0),
        vec![],
    )]);
    let (uc, store) = build(reader);
    let mut c = candidate(QuarantineStatus::Released, ts(990_000));
    c.artifact.repository_id = repo_id;
    // ABV says "previously clean at" ts(0) — well past the 7d grace.
    // The anchor ladder prefers ABV (step 1) over the fresh
    // ScanCompleted the per-artifact freshness gate requires (step 2),
    // so the fresh scan satisfies the per-artifact freshness gate without moving the anchor.
    let abv = DomainEvent::ArtifactBecameVulnerable(ArtifactBecameVulnerable {
        artifact_id: c.artifact.id,
        new_findings: vec![finding(SeverityThreshold::High, Some(7.0), vec![])],
        previously_clean_at: ts(0),
    });
    seed_fresh_scanned_stream(&store, &c, ts(1_000_000), vec![abv]);

    let p = policy(
        PolicyPredicate::HasFindingDetectedFor(7 * 24 * 3600),
        RetentionScope::AllRepos,
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(s.expired, 1, "ABV anchor at ts(0) → > 7d → match");
}

#[tokio::test]
async fn detected_for_uses_earliest_scan_completed_when_no_abv() {
    let repo_id = Uuid::new_v4();
    let reader = MockRetentionScanReader::new()
        .with_findings(vec![finding(SeverityThreshold::High, Some(7.0), vec![])])
        .with_score(score(repo_id, Some(ts(1_000_000) - Duration::hours(1))));
    let (uc, store) = build(reader);
    let mut c = candidate(QuarantineStatus::Released, ts(0));
    c.artifact.repository_id = repo_id;
    let stream_id = StreamId::artifact(c.artifact.id);
    // Genesis at created_at, then the earliest (only) ScanCompleted
    // very recent → NOT past the 7d grace. The anchor ladder step 2
    // still resolves to this ScanCompleted (genesis is
    // ArtifactIngested, not a scan event).
    let sc = scan_completed(c.artifact.id);
    store.set_stream(
        &stream_id,
        vec![
            persisted(
                &stream_id,
                0,
                c.artifact.created_at,
                ingested(c.artifact.id, IngestSource::Proxied),
            ),
            persisted(&stream_id, 1, ts(1_000_000) - Duration::hours(1), sc),
        ],
    );
    let p = policy(
        PolicyPredicate::HasFindingDetectedFor(7 * 24 * 3600),
        RetentionScope::AllRepos,
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(
        s.expired, 0,
        "earliest ScanCompleted 1h ago → within grace → no match"
    );
}

#[tokio::test]
async fn detected_for_never_scanned_artifact_is_skipped_per_inv7() {
    // Was `detected_for_falls_back_to_created_at_cold_data`: under the
    // weaker per-repo freshness reading a never-scanned artifact with a
    // fresh repo-score MAX would reach the `resolve_first_detected_at`
    // step-3 created_at fallback and EXPIRE. The per-artifact freshness
    // gate correctly blocks first: an artifact with NO ScanCompleted on
    // its own stream cannot prove freshness for a security-driven
    // predicate, so it is skipped_stale_scan (fail-safe — never expire
    // on an unprovable security predicate). The
    // `resolve_first_detected_at` cold-data fallback stays in the code
    // as defense-in-depth but is no longer reachable for a
    // security-driven predicate on a never-scanned artifact.
    let repo_id = Uuid::new_v4();
    let reader = MockRetentionScanReader::new()
        .with_findings(vec![finding(SeverityThreshold::High, Some(7.0), vec![])])
        .with_score(score(repo_id, Some(ts(1_000_000) - Duration::hours(1))));
    let (uc, store) = build(reader);
    // Only the genesis on the stream — no scan event at all.
    let mut c = candidate(QuarantineStatus::Released, ts(0));
    c.artifact.repository_id = repo_id;
    seed_stream(&store, &c, IngestSource::Proxied, vec![]);
    let p = policy(
        PolicyPredicate::HasFindingDetectedFor(7 * 24 * 3600),
        RetentionScope::AllRepos,
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(
        s.skipped_stale_scan, 1,
        "never-scanned artifact: per-artifact freshness gate fail-safe skip \
         (a fresh repo-score MAX must not rescue it)"
    );
    assert_eq!(s.expired, 0, "never-scanned → must NOT expire");
    assert!(store.appended_batches().is_empty());
}

// ===========================================================================
// Per-predicate-variant coverage through the use case
// ===========================================================================

async fn expire_with_security_predicate(p: PolicyPredicate, findings: Vec<Finding>) -> u64 {
    let repo_id = Uuid::new_v4();
    let reader = MockRetentionScanReader::new().with_findings(findings);
    let (uc, store) = build(reader);
    let mut c = candidate(QuarantineStatus::Released, ts(0));
    c.artifact.repository_id = repo_id;
    // Per-artifact freshness gate: security predicates only evaluate
    // against an artifact whose own most-recent scan is fresh.
    seed_fresh_scanned_stream(&store, &c, ts(1_000_000), vec![]);
    let pol = policy(p, RetentionScope::AllRepos);
    uc.evaluate_policies(ts(1_000_000), &[pol], &[c])
        .await
        .unwrap()
        .expired
}

#[tokio::test]
async fn variant_severity_zero_findings_no_expire() {
    let n = expire_with_security_predicate(
        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
        vec![],
    )
    .await;
    assert_eq!(n, 0);
}

#[tokio::test]
async fn variant_severity_just_below_and_just_above() {
    let below = expire_with_security_predicate(
        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
        vec![finding(SeverityThreshold::Medium, None, vec![])],
    )
    .await;
    assert_eq!(below, 0);
    let above = expire_with_security_predicate(
        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
        vec![finding(SeverityThreshold::Critical, None, vec![])],
    )
    .await;
    assert_eq!(above, 1);
}

#[tokio::test]
async fn variant_cvss_missing_and_present() {
    let missing = expire_with_security_predicate(
        PolicyPredicate::HasFindingAboveCvss(7.0),
        vec![finding(SeverityThreshold::Critical, None, vec![])],
    )
    .await;
    assert_eq!(missing, 0, "NULL cvss counts as not-matched");
    let present = expire_with_security_predicate(
        PolicyPredicate::HasFindingAboveCvss(7.0),
        vec![finding(SeverityThreshold::High, Some(7.0), vec![])],
    )
    .await;
    assert_eq!(present, 1);
}

#[tokio::test]
async fn variant_fix_available_empty_and_nonempty() {
    let empty = expire_with_security_predicate(
        PolicyPredicate::HasFixAvailable,
        vec![finding(SeverityThreshold::High, Some(7.0), vec![])],
    )
    .await;
    assert_eq!(empty, 0);
    let nonempty = expire_with_security_predicate(
        PolicyPredicate::HasFixAvailable,
        vec![finding(SeverityThreshold::High, Some(7.0), vec!["1.2.4"])],
    )
    .await;
    assert_eq!(nonempty, 1);
}

#[tokio::test]
async fn variant_mixed_severity_expires_on_strongest() {
    let n = expire_with_security_predicate(
        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::Critical),
        vec![
            finding(SeverityThreshold::Low, Some(2.0), vec![]),
            finding(SeverityThreshold::Critical, Some(9.9), vec![]),
        ],
    )
    .await;
    assert_eq!(n, 1);
}

#[tokio::test]
async fn variant_canonical_composite_and_pattern() {
    let p = PolicyPredicate::Composite(
        BooleanOp::And,
        vec![
            PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
            PolicyPredicate::HasFixAvailable,
            PolicyPredicate::HasFindingDetectedFor(7 * 24 * 3600),
        ],
    );
    let repo_id = Uuid::new_v4();
    let reader = MockRetentionScanReader::new().with_findings(vec![finding(
        SeverityThreshold::High,
        Some(8.0),
        vec!["2.0"],
    )]);
    let (uc, store) = build(reader);
    let mut c = candidate(QuarantineStatus::Released, ts(0)); // created long ago → > 7d
    c.artifact.repository_id = repo_id;
    // Genesis (Proxied → IngestSource(Proxied) scope matches), then an
    // OLD ScanCompleted (> 7d ago → HasFindingDetectedFor anchor is
    // past the 7d grace) AND a FRESH ScanCompleted (1h ago → per-artifact
    // freshness gate passes). `latest_scan_at` = the fresh one;
    // the `HasFindingDetectedFor` anchor = the earliest (old) one.
    let stream_id = StreamId::artifact(c.artifact.id);
    store.set_stream(
        &stream_id,
        vec![
            persisted(
                &stream_id,
                0,
                c.artifact.created_at,
                ingested(c.artifact.id, IngestSource::Proxied),
            ),
            persisted(
                &stream_id,
                1,
                ts(1_000_000) - Duration::days(30),
                scan_completed(c.artifact.id),
            ),
            persisted(
                &stream_id,
                2,
                ts(1_000_000) - Duration::hours(1),
                scan_completed(c.artifact.id),
            ),
        ],
    );
    let pol = policy(p, RetentionScope::IngestSource(IngestSource::Proxied));
    let s = uc
        .evaluate_policies(ts(1_000_000), &[pol], &[c])
        .await
        .unwrap();
    assert_eq!(s.expired, 1);
    // The appended event carries a SecurityFinding reason.
    let batch = &store.appended_batches()[0];
    match &batch.events[0].event {
        DomainEvent::ArtifactExpired(x) => {
            assert!(matches!(x.reason, ExpirationReason::SecurityFinding { .. }));
        }
        other => panic!("expected ArtifactExpired, got {other:?}"),
    }
}

// ===========================================================================
// Direct-upload scope proceeds (does NOT block at runtime)
// ===========================================================================

#[tokio::test]
async fn inv8_direct_upload_scope_proceeds_not_blocked() {
    // A security predicate whose scope is IngestSource(Direct) (does
    // not exclude direct) must still evaluate + expire at runtime —
    // the apply-pipeline warning is the operator's gate, not this one.
    let repo_id = Uuid::new_v4();
    let reader = MockRetentionScanReader::new().with_findings(vec![finding(
        SeverityThreshold::Critical,
        Some(9.8),
        vec![],
    )]);
    let (uc, store) = build(reader);
    let mut c = candidate(QuarantineStatus::Released, ts(0));
    c.artifact.repository_id = repo_id;
    // The artifact was a direct upload (genesis source = Direct) so the
    // IngestSource(Direct) scope gate matches; plus a fresh
    // ScanCompleted so the per-artifact freshness gate passes — the
    // concern here is the apply-pipeline warning, not a runtime block.
    let stream_id = StreamId::artifact(c.artifact.id);
    store.set_stream(
        &stream_id,
        vec![
            persisted(
                &stream_id,
                0,
                c.artifact.created_at,
                ingested(c.artifact.id, IngestSource::Direct),
            ),
            persisted(
                &stream_id,
                1,
                ts(1_000_000) - Duration::hours(1),
                scan_completed(c.artifact.id),
            ),
        ],
    );
    let pol = policy(
        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
        RetentionScope::IngestSource(IngestSource::Direct),
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[pol], &[c])
        .await
        .unwrap();
    assert_eq!(
        s.expired, 1,
        "runtime evaluator does not block direct-upload artifacts"
    );
    assert_eq!(store.appended_batches().len(), 1);
}

// ===========================================================================
// Archived-policy skip + per-pair error path
// ===========================================================================

#[tokio::test]
async fn archived_policy_is_not_evaluated() {
    let (uc, store) = build(MockRetentionScanReader::new());
    let p = archived_policy();
    let c = candidate(QuarantineStatus::Released, ts(0));
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c])
        .await
        .unwrap();
    assert_eq!(s.evaluated, 0, "archived policy is skipped entirely");
    assert_eq!(s.expired, 0);
    assert!(store.appended_batches().is_empty());
}

#[tokio::test]
async fn findings_read_error_is_recorded_and_sweep_continues() {
    let repo_id = Uuid::new_v4();
    let reader = MockRetentionScanReader::new()
        .with_findings_err()
        .with_score(score(repo_id, Some(ts(1_000_000) - Duration::hours(1))));
    let (uc, store) = build(reader);
    let mut c1 = candidate(QuarantineStatus::Released, ts(0));
    c1.artifact.repository_id = repo_id;
    // Two candidates: first errors on findings read, second is a clean
    // age match → sweep must continue past the error.
    let mut c2 = candidate(QuarantineStatus::Released, ts(0));
    c2.artifact.repository_id = repo_id;
    seed_stream(&store, &c1, IngestSource::Proxied, vec![]);
    seed_stream(&store, &c2, IngestSource::Proxied, vec![]);
    let p = policy(
        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::Low),
        RetentionScope::AllRepos,
    );
    let s = uc
        .evaluate_policies(ts(1_000_000), &[p], &[c1, c2])
        .await
        .unwrap();
    assert_eq!(s.errors, 2, "both pairs hit the findings-read error");
    assert_eq!(s.expired, 0);
    assert!(store.appended_batches().is_empty());
}

#[tokio::test]
async fn empty_policy_set_is_a_noop() {
    let (uc, store) = build(MockRetentionScanReader::new());
    let c = candidate(QuarantineStatus::Released, ts(0));
    let s = uc.evaluate_policies(ts(1), &[], &[c]).await.unwrap();
    assert_eq!(s, Default::default());
    assert!(store.appended_batches().is_empty());
}

// ===========================================================================
// Metrics — DebuggingRecorder label assertions
// ===========================================================================

mod metrics {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::MetricKind;
    use std::collections::HashMap;

    fn run<F>(f: F) -> Vec<(metrics_util::CompositeKey, DebugValue)>
    where
        F: FnOnce() -> futures::future::BoxFuture<'static, ()>,
    {
        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        ::metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f());
        });
        snap.snapshot()
            .into_vec()
            .into_iter()
            .map(|(k, _, _, v)| (k, v))
            .collect()
    }

    fn counter(
        snap: &[(metrics_util::CompositeKey, DebugValue)],
        name: &str,
        want: &[(&str, &str)],
    ) -> Option<u64> {
        for (k, v) in snap {
            if k.kind() != MetricKind::Counter || k.key().name() != name {
                continue;
            }
            let labels: HashMap<&str, &str> =
                k.key().labels().map(|l| (l.key(), l.value())).collect();
            if want.iter().all(|(lk, lv)| labels.get(lk) == Some(lv)) {
                if let DebugValue::Counter(n) = v {
                    return Some(*n);
                }
            }
        }
        None
    }

    #[test]
    fn skipped_stale_scan_label_fires_when_freshness_gate_trips() {
        let repo_id = Uuid::new_v4();
        let pid = Uuid::new_v4();
        let snap = run(move || {
            Box::pin(async move {
                let reader = MockRetentionScanReader::new()
                    .with_findings(vec![finding(
                        SeverityThreshold::Critical,
                        Some(9.0),
                        vec![],
                    )])
                    .with_score(score(repo_id, Some(ts(1_000_000) - Duration::hours(200))));
                let store = Arc::new(MockEventStore::new());
                let uc = RetentionUseCase::new(wrap_for_test(store.clone()), Arc::new(reader));
                let p = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
                    id: pid,
                    name: "stale-test".into(),
                    predicate: PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
                    scope: RetentionScope::AllRepos,
                    created_at: ts(0),
                }])
                .unwrap();
                let mut c = candidate(QuarantineStatus::Released, ts(0));
                c.artifact.repository_id = repo_id;
                seed_stream(&store, &c, IngestSource::Proxied, vec![]);
                uc.evaluate_policies(ts(1_000_000), &[p], &[c])
                    .await
                    .unwrap();
            })
        });
        let pid_s = pid.to_string();
        assert_eq!(
            counter(
                &snap,
                "hort_retention_evaluations_total",
                &[
                    ("policy_id", pid_s.as_str()),
                    ("result", "skipped_stale_scan")
                ],
            ),
            Some(1),
            "skipped_stale_scan must fire (operator alarm path depends on it)"
        );
    }

    #[test]
    fn matched_and_expired_counters_fire_with_policy_id_and_reason() {
        let pid = Uuid::new_v4();
        let snap = run(move || {
            Box::pin(async move {
                let store = Arc::new(MockEventStore::new());
                let uc = RetentionUseCase::new(
                    wrap_for_test(store.clone()),
                    Arc::new(MockRetentionScanReader::new()),
                );
                let p = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
                    id: pid,
                    name: "age".into(),
                    predicate: PolicyPredicate::AgeExceeds(1),
                    scope: RetentionScope::AllRepos,
                    created_at: ts(0),
                }])
                .unwrap();
                let c = candidate(QuarantineStatus::Released, ts(0));
                seed_stream(&store, &c, IngestSource::Proxied, vec![]);
                uc.evaluate_policies(ts(1_000_000), &[p], &[c])
                    .await
                    .unwrap();
            })
        });
        let pid_s = pid.to_string();
        assert_eq!(
            counter(
                &snap,
                "hort_retention_evaluations_total",
                &[("policy_id", pid_s.as_str()), ("result", "matched")],
            ),
            Some(1)
        );
        assert_eq!(
            counter(
                &snap,
                "hort_retention_expired_total",
                &[("policy_id", pid_s.as_str()), ("reason", "age_exceeded")],
            ),
            Some(1)
        );
    }

    #[test]
    fn no_match_and_skipped_quarantined_labels_fire() {
        let pid_nm = Uuid::new_v4();
        let pid_q = Uuid::new_v4();
        let snap = run(move || {
            Box::pin(async move {
                let store = Arc::new(MockEventStore::new());
                let uc = RetentionUseCase::new(
                    wrap_for_test(store),
                    Arc::new(MockRetentionScanReader::new()),
                );
                // no_match: AgeExceeds(huge) on a young artifact.
                let p_nm = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
                    id: pid_nm,
                    name: "nm".into(),
                    predicate: PolicyPredicate::AgeExceeds(u64::MAX),
                    scope: RetentionScope::AllRepos,
                    created_at: ts(0),
                }])
                .unwrap();
                let c_ok = candidate(QuarantineStatus::Released, ts(999_999));
                // skipped_quarantined.
                let p_q = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
                    id: pid_q,
                    name: "q".into(),
                    predicate: PolicyPredicate::AgeExceeds(1),
                    scope: RetentionScope::AllRepos,
                    created_at: ts(0),
                }])
                .unwrap();
                let c_q = candidate(QuarantineStatus::Quarantined, ts(0));
                uc.evaluate_policies(ts(1_000_000), &[p_nm], &[c_ok])
                    .await
                    .unwrap();
                uc.evaluate_policies(ts(1_000_000), &[p_q], &[c_q])
                    .await
                    .unwrap();
            })
        });
        assert_eq!(
            counter(
                &snap,
                "hort_retention_evaluations_total",
                &[
                    ("policy_id", pid_nm.to_string().as_str()),
                    ("result", "no_match"),
                ],
            ),
            Some(1)
        );
        assert_eq!(
            counter(
                &snap,
                "hort_retention_evaluations_total",
                &[
                    ("policy_id", pid_q.to_string().as_str()),
                    ("result", "skipped_quarantined"),
                ],
            ),
            Some(1)
        );
    }

    #[test]
    fn no_forbidden_high_cardinality_labels() {
        let pid = Uuid::new_v4();
        let snap = run(move || {
            Box::pin(async move {
                let store = Arc::new(MockEventStore::new());
                let uc = RetentionUseCase::new(
                    wrap_for_test(store),
                    Arc::new(MockRetentionScanReader::new()),
                );
                let p = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
                    id: pid,
                    name: "age".into(),
                    predicate: PolicyPredicate::AgeExceeds(1),
                    scope: RetentionScope::AllRepos,
                    created_at: ts(0),
                }])
                .unwrap();
                let c = candidate(QuarantineStatus::Released, ts(0));
                uc.evaluate_policies(ts(1_000_000), &[p], &[c])
                    .await
                    .unwrap();
            })
        });
        for (k, _) in &snap {
            if !k.key().name().starts_with("hort_retention_") {
                continue;
            }
            for l in k.key().labels() {
                assert!(
                    !["artifact_id", "content_hash", "purl", "vulnerability_id"].contains(&l.key()),
                    "forbidden high-cardinality label `{}` on {}",
                    l.key(),
                    k.key().name()
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Metric-label completeness — the residual `result` / `reason`
    // arms not asserted by the four tests above. The summary-struct tests
    // (`inv1_rejected_is_skipped_no_event`, the `s.errors` cases) already
    // cover the *behaviour*; these add the missing `DebuggingRecorder`
    // assertion that `hort_retention_evaluations_total{result=…}` /
    // `hort_retention_expired_total{reason=…}` actually fire with the
    // catalogued label *value* — the hort-app 100%-coverage tier requires
    // every `RetentionEvaluationResult` arm and the `security_finding`
    // reason to be pinned at the metric layer, not only via the summary
    // counter. This is test-only closure of the catalog↔code label set.
    // -----------------------------------------------------------------------

    #[test]
    fn skipped_rejected_label_fires_for_rejected_and_scan_indeterminate() {
        let pid_r = Uuid::new_v4();
        let pid_i = Uuid::new_v4();
        let snap = run(move || {
            Box::pin(async move {
                let store = Arc::new(MockEventStore::new());
                let uc = RetentionUseCase::new(
                    wrap_for_test(store),
                    Arc::new(MockRetentionScanReader::new()),
                );
                let p_r = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
                    id: pid_r,
                    name: "r".into(),
                    predicate: PolicyPredicate::AgeExceeds(1),
                    scope: RetentionScope::AllRepos,
                    created_at: ts(0),
                }])
                .unwrap();
                let p_i = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
                    id: pid_i,
                    name: "i".into(),
                    predicate: PolicyPredicate::AgeExceeds(1),
                    scope: RetentionScope::AllRepos,
                    created_at: ts(0),
                }])
                .unwrap();
                let c_r = candidate(QuarantineStatus::Rejected, ts(0));
                let c_i = candidate(QuarantineStatus::ScanIndeterminate, ts(0));
                uc.evaluate_policies(ts(1_000_000), &[p_r], &[c_r])
                    .await
                    .unwrap();
                uc.evaluate_policies(ts(1_000_000), &[p_i], &[c_i])
                    .await
                    .unwrap();
            })
        });
        // GC-protection: both `rejected` and `scan_indeterminate`
        // (terminal evidence) collapse to the same bounded label value.
        assert_eq!(
            counter(
                &snap,
                "hort_retention_evaluations_total",
                &[
                    ("policy_id", pid_r.to_string().as_str()),
                    ("result", "skipped_rejected"),
                ],
            ),
            Some(1)
        );
        assert_eq!(
            counter(
                &snap,
                "hort_retention_evaluations_total",
                &[
                    ("policy_id", pid_i.to_string().as_str()),
                    ("result", "skipped_rejected"),
                ],
            ),
            Some(1)
        );
    }

    #[test]
    fn error_label_fires_when_a_port_read_fails_for_the_pair() {
        let pid = Uuid::new_v4();
        let snap = run(move || {
            Box::pin(async move {
                // `list_findings` fails → the per-pair `errored()` path
                // emits `result="error"` and the sweep continues
                // (one bad row never aborts the pass).
                let reader = MockRetentionScanReader::new().with_findings_err();
                let store = Arc::new(MockEventStore::new());
                let uc = RetentionUseCase::new(wrap_for_test(store.clone()), Arc::new(reader));
                let p = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
                    id: pid,
                    name: "err".into(),
                    predicate: PolicyPredicate::AgeExceeds(1),
                    scope: RetentionScope::AllRepos,
                    created_at: ts(0),
                }])
                .unwrap();
                let c = candidate(QuarantineStatus::Released, ts(0));
                seed_stream(&store, &c, IngestSource::Proxied, vec![]);
                uc.evaluate_policies(ts(1_000_000), &[p], &[c])
                    .await
                    .unwrap();
            })
        });
        assert_eq!(
            counter(
                &snap,
                "hort_retention_evaluations_total",
                &[("policy_id", pid.to_string().as_str()), ("result", "error")],
            ),
            Some(1),
            "the per-pair port-error path must surface as result=\"error\""
        );
    }

    #[test]
    fn expired_reason_security_finding_label_fires() {
        let repo_id = Uuid::new_v4();
        let pid = Uuid::new_v4();
        let snap = run(move || {
            Box::pin(async move {
                // Fresh per-artifact ScanCompleted (1h old, well within
                // 2×24h) + a matching Critical finding →
                // `HasFindingAboveSeverity` matches and the canonical
                // `ExpirationReason::SecurityFinding` →
                // `reason="security_finding"`.
                let reader = MockRetentionScanReader::new().with_findings(vec![finding(
                    SeverityThreshold::Critical,
                    Some(9.0),
                    vec![],
                )]);
                let store = Arc::new(MockEventStore::new());
                let uc = RetentionUseCase::new(wrap_for_test(store.clone()), Arc::new(reader));
                let p = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
                    id: pid,
                    name: "sec".into(),
                    predicate: PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
                    scope: RetentionScope::AllRepos,
                    created_at: ts(0),
                }])
                .unwrap();
                let mut c = candidate(QuarantineStatus::Released, ts(0));
                c.artifact.repository_id = repo_id;
                seed_fresh_scanned_stream(&store, &c, ts(1_000_000), vec![]);
                uc.evaluate_policies(ts(1_000_000), &[p], &[c])
                    .await
                    .unwrap();
            })
        });
        let pid_s = pid.to_string();
        // The match also ticks the evaluations counter with `matched`.
        assert_eq!(
            counter(
                &snap,
                "hort_retention_evaluations_total",
                &[("policy_id", pid_s.as_str()), ("result", "matched")],
            ),
            Some(1)
        );
        assert_eq!(
            counter(
                &snap,
                "hort_retention_expired_total",
                &[
                    ("policy_id", pid_s.as_str()),
                    ("reason", "security_finding"),
                ],
            ),
            Some(1),
            "security-driven expiry must carry reason=\"security_finding\""
        );
    }
}
