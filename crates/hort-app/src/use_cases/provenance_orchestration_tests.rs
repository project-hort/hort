//! Unit tests for `ProvenanceOrchestrationUseCase`.
//!
//! Acceptance cases:
//! - `VerifyIfPresent` + forged sig → `ProvenanceRejected` (`rejected`);
//!   a verified sig under `VerifyIfPresent` → no status change.
//! - `VerifyIfPresent` + fetch-failure → `NoAttestation` (allow, not
//!   fail-closed: no event, status unchanged).
//! - `Required` + fetch-exhausted → fail-closed
//!   `ProvenanceRejected{RekorNotFound}` (status → `rejected`).
//! - `Off` policy → no verifier runs (skip).
//! - No applicable verifier (non-OCI) → skip.
//! - `Required` + verified → `ProvenanceVerified`, status unchanged.
//! - `Required` + unsigned (NoAttestation from verifier) →
//!   `ProvenanceRejected{Unsigned}` (status → `rejected`).
//! - Multi-verifier fold (`fold_two`).

use std::sync::{Arc, Mutex};

use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::entities::repository::{Repository, RepositoryFormat};
use hort_domain::entities::scan_policy::{
    ProvenanceMode, ScanPolicyProjection, SignerIdentityPattern,
};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{DomainEvent, PolicyScope};
use hort_domain::ports::content_reference_index::ContentReference;
use hort_domain::ports::provenance::{
    AttestationBundle, ProvenanceOutcome, ProvenancePort, ProvenanceRejectReason,
    ProvenanceRequirements, ProvenanceSubject, ProvenanceVerdict, SignerIdentity,
};
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, UpstreamAuth,
};
use hort_domain::ports::upstream_proxy::{ManifestFetch, ReferrerDescriptor};
use hort_domain::ports::BoxFuture;
use hort_domain::types::ContentHash;
use sha2::Digest;

use super::*;
use crate::use_cases::test_support::*;

// ---------------------------------------------------------------------------
// Mock ProvenancePort
// ---------------------------------------------------------------------------

/// A verifier mock whose verdict is pre-programmed. Records the
/// `(bundle_count, payload_len)` it was handed so tests can assert the
/// orchestrator fetched bundles + supplied the CAS preimage.
struct MockProvenancePort {
    name: &'static str,
    applies_format: &'static str,
    /// Pre-programmed verdict to return. `None` → return an `Err`
    /// (verifier infra fault).
    verdict: Mutex<Option<ProvenanceVerdict>>,
    /// `(bundle_count, payload_len)` of the last `verify` call.
    last_inputs: Mutex<Option<(usize, usize)>>,
}

impl MockProvenancePort {
    fn cosign_returning(verdict: ProvenanceVerdict) -> Self {
        Self {
            name: "cosign",
            applies_format: "oci",
            verdict: Mutex::new(Some(verdict)),
            last_inputs: Mutex::new(None),
        }
    }

    fn cosign_erroring() -> Self {
        Self {
            name: "cosign",
            applies_format: "oci",
            verdict: Mutex::new(None),
            last_inputs: Mutex::new(None),
        }
    }

    fn last_inputs(&self) -> Option<(usize, usize)> {
        *self.last_inputs.lock().unwrap()
    }
}

impl ProvenancePort for MockProvenancePort {
    fn name(&self) -> &str {
        self.name
    }

    fn applies_to(&self, format: &str) -> bool {
        format == self.applies_format
    }

    fn verify<'a>(
        &'a self,
        artifact: &'a ProvenanceSubject<'a>,
        bundles: &'a [AttestationBundle],
        _policy: &'a ProvenanceRequirements<'a>,
    ) -> BoxFuture<'a, DomainResult<ProvenanceVerdict>> {
        *self.last_inputs.lock().unwrap() = Some((bundles.len(), artifact.payload.len()));
        let verdict = self.verdict.lock().unwrap().clone();
        Box::pin(async move {
            match verdict {
                Some(v) => Ok(v),
                None => Err(DomainError::Invariant("mock verifier infra fault".into())),
            }
        })
    }

    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

const ARTIFACT_PAYLOAD: &[u8] = b"{\"schemaVersion\":2,\"manifest\":true}";

fn sample_identity() -> SignerIdentity {
    SignerIdentity {
        issuer: "https://token.actions.githubusercontent.com".into(),
        san: "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main".into(),
    }
}

fn sample_pattern() -> SignerIdentityPattern {
    SignerIdentityPattern::new(
        "https://token.actions.githubusercontent.com",
        "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main",
    )
    .expect("valid pattern")
}

struct Fixture {
    uc: ProvenanceOrchestrationUseCase,
    artifacts: Arc<MockArtifactRepository>,
    repositories: Arc<MockRepositoryRepository>,
    projections: Arc<MockPolicyProjectionRepository>,
    content_references: Arc<MockContentReferenceIndex>,
    storage: Arc<MockStoragePort>,
    lifecycle: Arc<MockArtifactLifecycle>,
    /// The proxy + resolver the orchestrator uses for the
    /// upstream referrer-fetch arm. `build()` leaves both unseeded (a hosted
    /// repo: `resolve → None`, no referrers); the proxy-arm tests seed them
    /// via [`make_proxy`] / [`MockUpstreamProxy::insert_referrers`].
    upstream_proxy: Arc<MockUpstreamProxy>,
    upstream_resolver: Arc<MockUpstreamResolver>,
    artifact_id: Uuid,
    repository_id: Uuid,
    content_hash: ContentHash,
}

/// Build the fixture: one OCI repo, one quarantined artifact whose CAS
/// content is `ARTIFACT_PAYLOAD`, and a use case wired with `ports`.
fn build(
    format: RepositoryFormat,
    mode: Option<ProvenanceMode>,
    identities: Vec<SignerIdentityPattern>,
    ports: Vec<Arc<dyn ProvenancePort>>,
) -> Fixture {
    let artifacts = Arc::new(MockArtifactRepository::new());
    let repositories = Arc::new(MockRepositoryRepository::new());
    let projections = Arc::new(MockPolicyProjectionRepository::new());
    let content_references = Arc::new(MockContentReferenceIndex::new());
    let storage = Arc::new(MockStoragePort::new());
    let events = Arc::new(MockEventStore::new());
    let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
    let upstream_proxy = Arc::new(MockUpstreamProxy::new());
    let upstream_resolver = Arc::new(MockUpstreamResolver::new());

    let mut repo: Repository = sample_repository();
    repo.format = format;
    let repository_id = repo.id;
    repositories.insert(repo);

    let mut artifact: Artifact = sample_artifact(QuarantineStatus::Quarantined);
    artifact.repository_id = repository_id;
    // Pin the CAS hash to the digest of ARTIFACT_PAYLOAD so the stored
    // bytes round-trip (sha256(payload) == content_hash).
    let hash_hex = format!("{:x}", sha2::Sha256::digest(ARTIFACT_PAYLOAD));
    let content_hash: ContentHash = hash_hex.parse().expect("valid sha256");
    artifact.sha256_checksum = content_hash.clone();
    let artifact_id = artifact.id;
    artifacts.insert(artifact);
    storage.insert_content(content_hash.clone(), ARTIFACT_PAYLOAD.to_vec());

    if let Some(m) = mode {
        let mut p = projection(PolicyScope::Repository(repository_id), m, identities);
        p.scan_backends = vec!["trivy".to_string()];
        projections.insert(p);
    }

    let uc = ProvenanceOrchestrationUseCase::new(
        artifacts.clone(),
        repositories.clone(),
        projections.clone(),
        content_references.clone(),
        storage.clone(),
        lifecycle.clone(),
        crate::event_store_publisher::wrap_for_test(events.clone()),
        ports,
        upstream_proxy.clone(),
        upstream_resolver.clone(),
    );

    Fixture {
        uc,
        artifacts,
        repositories,
        projections,
        content_references,
        storage,
        lifecycle,
        upstream_proxy,
        upstream_resolver,
        artifact_id,
        repository_id,
        content_hash,
    }
}

fn projection(
    scope: PolicyScope,
    mode: ProvenanceMode,
    identities: Vec<SignerIdentityPattern>,
) -> ScanPolicyProjection {
    use chrono::Utc;
    use hort_domain::entities::scan_policy::SeverityThreshold;
    ScanPolicyProjection {
        policy_id: Uuid::new_v4(),
        name: format!("test-policy-{}", Uuid::new_v4()),
        scope,
        severity_threshold: SeverityThreshold::Critical,
        quarantine_duration_secs: 0,
        require_approval: false,
        provenance_mode: mode,
        provenance_backends: vec!["cosign".to_string()],
        provenance_identities: identities,
        max_artifact_age_secs: None,
        license_policy: serde_json::Value::Null,
        archived: false,
        scan_backends: vec!["trivy".to_string()],
        rescan_interval_hours: 24,
        stream_version: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Seed a cosign signature bundle (manifest + blob contract): the
/// `oci_subject` source artifact's CAS bytes are a referrer **manifest**
/// whose single Sigstore-bundle layer references `bundle_bytes` (stored as
/// its own CAS blob), plus an `oci_subject` content-reference pointing at the
/// signed artifact's content hash. The orchestrator must resolve the manifest
/// → bundle-layer-blob and hand the verifier the **blob**, not the manifest.
fn seed_bundle(f: &Fixture, bundle_bytes: &[u8]) {
    let _ = seed_manifest_and_bundle(f, bundle_bytes);
}

/// `decode_simplesigning_signature` (ADR 0039 §8): standard base64 → raw bytes;
/// whitespace trimmed; non-base64 → `None` (the carriage skips it).
#[test]
fn decode_simplesigning_signature_decodes_b64_and_rejects_garbage() {
    use base64::Engine as _;
    let raw: &[u8] = b"\x30\x45\x02\x21\x00sigbytes";
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    assert_eq!(decode_simplesigning_signature(&b64).as_deref(), Some(raw));
    assert_eq!(
        decode_simplesigning_signature(&format!("  {b64}\n")).as_deref(),
        Some(raw),
        "annotation whitespace is trimmed"
    );
    assert_eq!(decode_simplesigning_signature("!!!not base64!!!"), None);
}

// ===========================================================================
// (Off) — provenance inert; no verifier runs.
// ===========================================================================

#[tokio::test]
async fn off_mode_skips_without_running_a_verifier() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Off),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(outcome, ProvenanceRunOutcome::SkippedOff);
    assert!(port.last_inputs().is_none(), "Off must not call verify");
    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "Off appends no event"
    );
}

// ===========================================================================
// No applicable verifier (non-OCI format under VerifyIfPresent) — skip.
// ===========================================================================

#[tokio::test]
async fn no_applicable_verifier_skips() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    // npm format — cosign applies only to "oci".
    let f = build(
        RepositoryFormat::Npm,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(outcome, ProvenanceRunOutcome::SkippedNoVerifier);
    assert!(
        port.last_inputs().is_none(),
        "no-apply must not call verify"
    );
    assert!(f.lifecycle.committed_transitions().is_empty());
}

// ===========================================================================
// VerifyIfPresent + forged/untrusted sig → rejected.
// ===========================================================================

#[tokio::test]
async fn verify_if_present_forged_signature_rejects() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    seed_bundle(&f, b"forged-bundle-bytes");

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::UntrustedIdentity),
        }
    );

    // The verifier was handed exactly one bundle + the CAS preimage.
    assert_eq!(
        port.last_inputs(),
        Some((1, ARTIFACT_PAYLOAD.len())),
        "verifier must receive the fetched bundle and the CAS preimage payload"
    );

    // Status → rejected + a ProvenanceRejected event.
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1);
    let DomainEvent::ProvenanceRejected(ev) = &transitions[0].1.events[0].event else {
        panic!("expected ProvenanceRejected");
    };
    assert_eq!(ev.reason, ProvenanceRejectReason::UntrustedIdentity);
}

// ===========================================================================
// VerifyIfPresent + verified sig → ProvenanceVerified, status
// UNCHANGED (a Verified must NOT release early).
// ===========================================================================

#[tokio::test]
async fn verify_if_present_verified_signature_records_but_does_not_change_status() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(
            sample_identity(),
            Some("https://slsa.dev/provenance/v1".into()),
        ),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    seed_bundle(&f, b"valid-bundle-bytes");

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Verified,
        }
    );

    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Quarantined,
        "a Verified attestation is a success record — it must NOT release early"
    );
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1);
    assert!(matches!(
        &transitions[0].1.events[0].event,
        DomainEvent::ProvenanceVerified(_)
    ));
}

// ===========================================================================
// VerifyIfPresent + bundle-fetch failure → NoAttestation (allow), NOT
// fail-closed. No event, status unchanged.
// ===========================================================================

#[tokio::test]
async fn verify_if_present_fetch_failure_degrades_to_no_attestation_allow() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // Force the bundle fetch to fail: a content-reference points at a
    // source artifact that does not exist → find_by_id NotFound on every
    // retry → fetch exhausted.
    futures::executor::block_on(async {
        f.content_references
            .insert(ContentReference {
                source_artifact_id: Uuid::new_v4(), // dangling — no such artifact
                target_content_hash: f.content_hash.clone(),
                kind: "oci_subject".to_string(),
                metadata: serde_json::Value::Null,
                repository_id: f.repository_id,
                recorded_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
    });

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
        "VerifyIfPresent fetch failure must degrade to NoAttestation (allow): no event"
    );

    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Quarantined,
        "VerifyIfPresent must NEVER fail-closed on infra flakiness"
    );
    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "no event appended on the VerifyIfPresent degrade path"
    );
    assert!(
        port.last_inputs().is_none(),
        "fetch failed before the verifier ran"
    );
}

// ===========================================================================
// Required + bundle-fetch exhausted → fail-closed
// ProvenanceRejected{RekorNotFound}, status → rejected.
// ===========================================================================

#[tokio::test]
async fn required_fetch_exhausted_fails_closed_rekor_not_found() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    futures::executor::block_on(async {
        f.content_references
            .insert(ContentReference {
                source_artifact_id: Uuid::new_v4(), // dangling
                target_content_hash: f.content_hash.clone(),
                kind: "oci_subject".to_string(),
                metadata: serde_json::Value::Null,
                repository_id: f.repository_id,
                recorded_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
    });

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::RekorNotFound),
        }
    );

    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Rejected,
        "Required fetch-exhausted must fail-closed → rejected"
    );
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1);
    let DomainEvent::ProvenanceRejected(ev) = &transitions[0].1.events[0].event else {
        panic!("expected ProvenanceRejected");
    };
    assert_eq!(ev.reason, ProvenanceRejectReason::RekorNotFound);
    assert!(
        port.last_inputs().is_none(),
        "Required fetch failed before the verifier ran"
    );
}

// ===========================================================================
// Required + verified → ProvenanceVerified, status unchanged.
// ===========================================================================

#[tokio::test]
async fn required_verified_records_clearance_event_status_unchanged() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    seed_bundle(&f, b"valid-bundle-bytes");

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Verified,
        }
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1);
    assert!(matches!(
        &transitions[0].1.events[0].event,
        DomainEvent::ProvenanceVerified(_)
    ));
}

// ===========================================================================
// Required + no bundles (verifier returns NoAttestation) →
// ProvenanceRejected{Unsigned}, status → rejected.
// ===========================================================================

#[tokio::test]
async fn required_unsigned_rejects_unsigned() {
    // No bundle seeded → fetch returns an empty Vec → the verifier
    // returns NoAttestation → complete_provenance under Required maps it
    // to Rejected{Unsigned}.
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::Unsigned),
        }
    );
    // The verifier ran with zero bundles (the empty/unsigned case).
    assert_eq!(port.last_inputs(), Some((0, ARTIFACT_PAYLOAD.len())));

    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1);
    let DomainEvent::ProvenanceRejected(ev) = &transitions[0].1.events[0].event else {
        panic!("expected ProvenanceRejected");
    };
    assert_eq!(ev.reason, ProvenanceRejectReason::Unsigned);
}

// ===========================================================================
// No policy at all → mode defaults to VerifyIfPresent; an empty bundle set
// → NoAttestation (allow), no event.
// ===========================================================================

#[tokio::test]
async fn absent_policy_defaults_to_verify_if_present_allows_unsigned() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None, // no policy seeded
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        }
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
    assert!(f.lifecycle.committed_transitions().is_empty());
}

// ===========================================================================
// VerifyIfPresent + verifier infra fault → degrade to NoAttestation (allow).
// ===========================================================================

#[tokio::test]
async fn verify_if_present_verifier_error_degrades_to_allow() {
    let port = Arc::new(MockProvenancePort::cosign_erroring());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    seed_bundle(&f, b"some-bundle");

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
        "a verifier infra fault under VerifyIfPresent degrades to allow"
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
}

// ===========================================================================
// Required + verifier infra fault → fail-closed RekorNotFound.
// ===========================================================================

#[tokio::test]
async fn required_verifier_error_fails_closed() {
    let port = Arc::new(MockProvenancePort::cosign_erroring());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    seed_bundle(&f, b"some-bundle");

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::RekorNotFound),
        }
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
    let transitions = f.lifecycle.committed_transitions();
    let DomainEvent::ProvenanceRejected(ev) = &transitions[0].1.events[0].event else {
        panic!("expected ProvenanceRejected");
    };
    assert_eq!(ev.reason, ProvenanceRejectReason::RekorNotFound);
}

// ===========================================================================
// Global policy applies when no repo-scoped policy is active.
// ===========================================================================

#[tokio::test]
async fn global_policy_applies_when_no_repo_scoped() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None,
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // Seed a GLOBAL Required policy. Required + no bundle → Rejected{Unsigned}.
    f.projections.insert(projection(
        PolicyScope::Global,
        ProvenanceMode::Required,
        vec![sample_pattern()],
    ));

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::Unsigned),
        }
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
}

// ===========================================================================
// fold_two — the multi-verifier fold rule.
// ===========================================================================

#[test]
fn fold_two_rejected_dominates_verified() {
    let rej = ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity);
    let ver = ProvenanceVerdict::verified(sample_identity(), None);
    assert!(matches!(
        fold_two(rej.clone(), ver.clone()).outcome,
        ProvenanceOutcome::Rejected(_)
    ));
    assert!(matches!(
        fold_two(ver, rej).outcome,
        ProvenanceOutcome::Rejected(_)
    ));
}

#[test]
fn fold_two_verified_dominates_no_attestation() {
    let ver = ProvenanceVerdict::verified(sample_identity(), None);
    let none = ProvenanceVerdict::no_attestation();
    assert!(matches!(
        fold_two(ver.clone(), none.clone()).outcome,
        ProvenanceOutcome::Verified { .. }
    ));
    assert!(matches!(
        fold_two(none, ver).outcome,
        ProvenanceOutcome::Verified { .. }
    ));
}

#[test]
fn fold_two_no_attestation_both() {
    let a = ProvenanceVerdict::no_attestation();
    let b = ProvenanceVerdict::no_attestation();
    assert!(matches!(
        fold_two(a, b).outcome,
        ProvenanceOutcome::NoAttestation
    ));
}

#[test]
fn fold_two_backend_attributes_the_deciding_verifier() {
    let verified = || ProvenanceVerdict::verified(sample_identity(), None);
    let none = ProvenanceVerdict::no_attestation;
    let rejected = || ProvenanceVerdict::rejected(ProvenanceRejectReason::CertChainInvalid);

    // Verified ⊳ NoAttestation — the keyed verifier that Verified is attributed
    // (so the metric labels `cosign-key`, not the first-listed `cosign`).
    let (v, b) = fold_two_backend((none(), "cosign".into()), (verified(), "cosign-key".into()));
    assert!(matches!(v.outcome, ProvenanceOutcome::Verified { .. }));
    assert_eq!(b, "cosign-key");

    // Rejected ⊳ Verified — the rejecting backend is attributed.
    let (v, b) = fold_two_backend(
        (rejected(), "cosign".into()),
        (verified(), "cosign-key".into()),
    );
    assert!(matches!(v.outcome, ProvenanceOutcome::Rejected(_)));
    assert_eq!(b, "cosign");

    // Order-independence: Verified on the left still wins over NoAttestation.
    let (v, b) = fold_two_backend((verified(), "cosign-key".into()), (none(), "cosign".into()));
    assert!(matches!(v.outcome, ProvenanceOutcome::Verified { .. }));
    assert_eq!(b, "cosign-key");
}

// ===========================================================================
// Multiple applicable verifiers — both run, verdicts fold.
// ===========================================================================

#[tokio::test]
async fn two_applicable_verifiers_fold_rejected_wins() {
    let verifier_ok = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let verifier_bad = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::rejected(ProvenanceRejectReason::CertChainInvalid),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![
            verifier_ok.clone() as Arc<dyn ProvenancePort>,
            verifier_bad.clone() as Arc<dyn ProvenancePort>,
        ],
    );
    seed_bundle(&f, b"bundle");

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::CertChainInvalid),
        }
    );
    // Both verifiers ran.
    assert!(verifier_ok.last_inputs().is_some());
    assert!(verifier_bad.last_inputs().is_some());
    // Rejected dominates.
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
}

// ===========================================================================
// Identities are threaded into the verifier requirements.
// ===========================================================================

#[tokio::test]
async fn allowed_identities_threaded_into_requirements() {
    // A verifier that asserts it received a non-empty identity slice.
    struct AssertingPort {
        observed_identity_count: Mutex<Option<usize>>,
    }
    impl ProvenancePort for AssertingPort {
        fn name(&self) -> &str {
            "cosign"
        }
        fn applies_to(&self, format: &str) -> bool {
            format == "oci"
        }
        fn verify<'a>(
            &'a self,
            _artifact: &'a ProvenanceSubject<'a>,
            _bundles: &'a [AttestationBundle],
            policy: &'a ProvenanceRequirements<'a>,
        ) -> BoxFuture<'a, DomainResult<ProvenanceVerdict>> {
            *self.observed_identity_count.lock().unwrap() = Some(policy.allowed_identities.len());
            Box::pin(async { Ok(ProvenanceVerdict::no_attestation()) })
        }
        fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let port = Arc::new(AssertingPort {
        observed_identity_count: Mutex::new(None),
    });
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );

    f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        *port.observed_identity_count.lock().unwrap(),
        Some(1),
        "the policy's provenance_identities slice must reach the verifier"
    );
}

// ===========================================================================
// Artifact-not-found surfaces as an error (not a silent skip).
// ===========================================================================

#[tokio::test]
async fn unknown_artifact_surfaces_error() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    let _ = &f.repositories;
    let _ = &f.storage;
    let err = f.uc.verify_artifact(Uuid::new_v4()).await.unwrap_err();
    assert!(matches!(err, crate::error::AppError::Domain(_)));
}

// ===========================================================================
// Metrics emission.
//
// `hort_provenance_verify_total{backend, mode, result}` fires once per
// applied verdict; `hort_provenance_reject_total{backend, reason}` fires
// alongside on a rejection. Asserted with `with_local_recorder` +
// `DebuggingRecorder` (the catalog-same-PR rule binds the emission to its
// catalog entry + this test). `mode` carries the resolved
// `ProvenanceMode` wire-form; NO high-cardinality labels.
// ===========================================================================

/// Snapshot the counter increments emitted while running `f` (which
/// builds + drives a fixture). `capture_metrics` takes a sync closure, so
/// the async body runs on a nested current-thread runtime.
fn capture_provenance_metrics<F>(
    f: F,
) -> Vec<(
    metrics_util::CompositeKey,
    metrics_util::debugging::DebugValue,
)>
where
    F: FnOnce() -> futures::future::BoxFuture<'static, ()>,
{
    crate::metrics::capture_metrics(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(f());
    })
    .into_vec()
    .into_iter()
    .map(|(k, _u, _d, v)| (k, v))
    .collect()
}

/// Find the single counter row for `name` whose labels are a superset of
/// `expect`, returning its value. Asserts every expected label is present
/// with the expected value.
fn counter_with_labels(
    snap: &[(
        metrics_util::CompositeKey,
        metrics_util::debugging::DebugValue,
    )],
    name: &str,
    expect: &[(&str, &str)],
) -> Option<u64> {
    use std::collections::HashMap;
    for (key, value) in snap {
        if key.key().name() != name {
            continue;
        }
        let labels: HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        if expect.iter().all(|(k, v)| labels.get(k) == Some(v)) {
            if let metrics_util::debugging::DebugValue::Counter(v) = value {
                return Some(*v);
            }
        }
    }
    None
}

#[test]
fn metric_verified_fires_with_backend_mode_result_labels() {
    let snap = capture_provenance_metrics(|| {
        Box::pin(async {
            let port = Arc::new(MockProvenancePort::cosign_returning(
                ProvenanceVerdict::verified(sample_identity(), None),
            ));
            let f = build(
                RepositoryFormat::Oci,
                Some(ProvenanceMode::VerifyIfPresent),
                vec![sample_pattern()],
                vec![port as Arc<dyn ProvenancePort>],
            );
            seed_bundle(&f, b"valid-bundle-bytes");
            f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
        })
    });
    assert_eq!(
        counter_with_labels(
            &snap,
            "hort_provenance_verify_total",
            &[("backend", "cosign"), ("mode", "verify_if_present"), ("result", "verified")],
        ),
        Some(1),
        "verified verdict must tick hort_provenance_verify_total{{backend=cosign,mode=verify_if_present,result=verified}}",
    );
    // A verified verdict must NOT tick the reject counter.
    assert!(
        snap.iter()
            .all(|(k, _)| k.key().name() != "hort_provenance_reject_total"),
        "a verified verdict must not emit hort_provenance_reject_total",
    );
}

#[test]
fn metric_rejected_fires_verify_and_reject_with_reason() {
    let snap = capture_provenance_metrics(|| {
        Box::pin(async {
            let port = Arc::new(MockProvenancePort::cosign_returning(
                ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity),
            ));
            let f = build(
                RepositoryFormat::Oci,
                Some(ProvenanceMode::Required),
                vec![sample_pattern()],
                vec![port as Arc<dyn ProvenancePort>],
            );
            seed_bundle(&f, b"forged-bundle-bytes");
            f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
        })
    });
    assert_eq!(
        counter_with_labels(
            &snap,
            "hort_provenance_verify_total",
            &[
                ("backend", "cosign"),
                ("mode", "required"),
                ("result", "rejected")
            ],
        ),
        Some(1),
        "rejected verdict must tick hort_provenance_verify_total{{...,result=rejected}}",
    );
    assert_eq!(
        counter_with_labels(
            &snap,
            "hort_provenance_reject_total",
            &[("backend", "cosign"), ("reason", "untrusted_identity")],
        ),
        Some(1),
        "rejected verdict must tick hort_provenance_reject_total{{backend=cosign,reason=untrusted_identity}}",
    );
}

#[test]
fn metric_no_attestation_fires_verify_only() {
    let snap = capture_provenance_metrics(|| {
        Box::pin(async {
            let port = Arc::new(MockProvenancePort::cosign_returning(
                ProvenanceVerdict::no_attestation(),
            ));
            let f = build(
                RepositoryFormat::Oci,
                Some(ProvenanceMode::VerifyIfPresent),
                vec![sample_pattern()],
                vec![port as Arc<dyn ProvenancePort>],
            );
            // No bundle seeded → the verifier returns NoAttestation; under
            // VerifyIfPresent this is the allowed-unsigned no-op.
            f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
        })
    });
    assert_eq!(
        counter_with_labels(
            &snap,
            "hort_provenance_verify_total",
            &[("backend", "cosign"), ("mode", "verify_if_present"), ("result", "no_attestation")],
        ),
        Some(1),
        "no-attestation (allowed) must tick hort_provenance_verify_total{{...,result=no_attestation}}",
    );
    assert!(
        snap.iter()
            .all(|(k, _)| k.key().name() != "hort_provenance_reject_total"),
        "the allowed-unsigned case must not emit hort_provenance_reject_total",
    );
}

// ===========================================================================
// Bundle-blob resolution (the manifest-vs-blob root fix).
//
// `fetch_bundles_once` must hand the verifier the Sigstore **bundle JSON
// blob** the referrer manifest references — NOT the referrer manifest bytes.
// Before this fix the orchestrator read the `oci_subject` source artifact's
// CAS bytes (= the manifest) and pushed those as the `AttestationBundle`, so
// the verifier saw a manifest, not a bundle → `BundleMalformed`, never a
// verdict against the parsed bundle.
// ===========================================================================

/// The real committed cosign v0.3 bundle the sigstore verifier parses
/// (`hort-adapters-provenance-sigstore/tests/fixtures/`). A genuine
/// `application/vnd.dev.sigstore.bundle.v0.3+json` document — top-level
/// `mediaType`, `verificationMaterial`, `dsseEnvelope`.
const COSIGN_BUNDLE_V03_FIXTURE: &[u8] = include_bytes!(
    "../../../hort-adapters-provenance-sigstore/tests/fixtures/cosign_bundle_v03_kubewarden.json"
);

/// A capturing `ProvenancePort` that records the **raw bytes** of every
/// bundle it is handed, and maps its verdict the way the *real*
/// sigstore verifier does (`verifier.rs`):
/// - bytes that parse as a Sigstore bundle (top-level `mediaType ==
///   SIGSTORE_BUNDLE_MEDIA_TYPE`) but do not chain to the trust root →
///   `Rejected(CertChainInvalid)` — the verifier's verdict for the real
///   fixture against the empty fixture trust root (`lib.rs:367`);
/// - any other bytes (a referrer *manifest*, junk) → `Rejected(BundleMalformed)`
///   — the verifier's verdict for un-parseable / non-bundle input
///   (`verifier.rs:162-176`).
///
/// This reproduces the verifier's *reason mapping* without `hort-app`
/// depending on the adapter crate (a layering inversion), so the end-to-end
/// test proves the bundle reached the port **parsed as a Bundle**: today's
/// manifest-bytes path yields `BundleMalformed`; the fixed bundle-blob path
/// yields `CertChainInvalid`.
struct CapturingBundleAwarePort {
    /// The raw bytes of every bundle handed to the most recent `verify`
    /// call, in order.
    captured: Mutex<Vec<Vec<u8>>>,
}

impl CapturingBundleAwarePort {
    fn new() -> Self {
        Self {
            captured: Mutex::new(Vec::new()),
        }
    }

    fn captured_bundles(&self) -> Vec<Vec<u8>> {
        self.captured.lock().unwrap().clone()
    }
}

/// `true` iff `bytes` parse as JSON whose top-level `mediaType` is the
/// Sigstore bundle media type — the same discriminator the real verifier's
/// parse step keys on.
fn parses_as_sigstore_bundle(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| {
            v.get("mediaType")
                .and_then(|m| m.as_str())
                .map(|m| m == hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE)
        })
        .unwrap_or(false)
}

impl ProvenancePort for CapturingBundleAwarePort {
    fn name(&self) -> &str {
        "cosign"
    }

    fn applies_to(&self, format: &str) -> bool {
        format == "oci"
    }

    fn verify<'a>(
        &'a self,
        _artifact: &'a ProvenanceSubject<'a>,
        bundles: &'a [AttestationBundle],
        _policy: &'a ProvenanceRequirements<'a>,
    ) -> BoxFuture<'a, DomainResult<ProvenanceVerdict>> {
        *self.captured.lock().unwrap() = bundles.iter().map(|b| b.bytes.clone()).collect();
        // Mirror the verifier's reason mapping over the FIRST bundle.
        let verdict = match bundles.first() {
            None => ProvenanceVerdict::no_attestation(),
            Some(b) if parses_as_sigstore_bundle(&b.bytes) => {
                ProvenanceVerdict::rejected(ProvenanceRejectReason::CertChainInvalid)
            }
            Some(_) => ProvenanceVerdict::rejected(ProvenanceRejectReason::BundleMalformed),
        };
        Box::pin(async move { Ok(verdict) })
    }

    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Build a minimal OCI referrer manifest JSON whose single layer is a
/// Sigstore bundle pointing at `blob_hash` (digest `sha256:<blob_hash>`).
fn referrer_manifest_for(blob_hash: &ContentHash) -> Vec<u8> {
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE,
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "size": 2
        },
        "layers": [
            {
                "mediaType": hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE,
                "digest": format!("sha256:{blob_hash}"),
                "size": COSIGN_BUNDLE_V03_FIXTURE.len()
            }
        ]
    })
    .to_string()
    .into_bytes()
}

/// Seed a referrer manifest + its bundle blob into CAS (the manifest+blob
/// shape): the `oci_subject` source artifact's CAS bytes are the **manifest**,
/// and the bundle JSON blob lives at the hash the manifest's layer declares.
/// Returns the bundle-blob content hash.
fn seed_manifest_and_bundle(f: &Fixture, bundle_bytes: &[u8]) -> ContentHash {
    // The bundle blob lives at its own content hash (= the layer digest).
    let blob_hash_hex = format!("{:x}", sha2::Sha256::digest(bundle_bytes));
    let blob_hash: ContentHash = blob_hash_hex.parse().expect("valid sha256");
    f.storage
        .insert_content(blob_hash.clone(), bundle_bytes.to_vec());

    // The referrer manifest references that blob as its (single) layer.
    let manifest_bytes = referrer_manifest_for(&blob_hash);
    let manifest_hash_hex = format!("{:x}", sha2::Sha256::digest(&manifest_bytes));
    let manifest_hash: ContentHash = manifest_hash_hex.parse().expect("valid sha256");

    let mut sig_artifact: Artifact = sample_artifact(QuarantineStatus::Released);
    sig_artifact.repository_id = f.repository_id;
    sig_artifact.sha256_checksum = manifest_hash.clone();
    let sig_id = sig_artifact.id;
    f.artifacts.insert(sig_artifact);
    f.storage.insert_content(manifest_hash, manifest_bytes);

    futures::executor::block_on(async {
        f.content_references
            .insert(ContentReference {
                source_artifact_id: sig_id,
                target_content_hash: f.content_hash.clone(),
                kind: "oci_subject".to_string(),
                metadata: serde_json::Value::Null,
                repository_id: f.repository_id,
                recorded_at: chrono::Utc::now(),
            })
            .await
            .expect("seed content-reference");
    });
    blob_hash
}

// ---------------------------------------------------------------------------
// Keyed simplesigning carriage (ADR 0039 §8) — fetch_bundles collects the
// legacy `.sig` as a SIGNED AttestationBundle (payload blob + decoded sig).
// ---------------------------------------------------------------------------

/// A referrer manifest carrying ONE cosign `simplesigning` layer — the payload
/// blob digest + the base64 signature on the `dev.cosignproject.cosign/signature`
/// annotation (ADR 0039 §8).
fn referrer_manifest_for_simplesigning(
    payload_blob_hash: &ContentHash,
    signature_b64: &str,
    payload_len: usize,
) -> Vec<u8> {
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "size": 2
        },
        "layers": [
            {
                "mediaType": hort_domain::oci::COSIGN_SIMPLESIGNING_MEDIA_TYPE,
                "digest": format!("sha256:{payload_blob_hash}"),
                "size": payload_len,
                "annotations": { "dev.cosignproject.cosign/signature": signature_b64 }
            }
        ]
    })
    .to_string()
    .into_bytes()
}

/// Seed a keyed simplesigning `.sig` referrer: the payload-layer blob in CAS,
/// the referrer manifest (the `oci_subject` source) pointing at it with the
/// signature annotation, and the `oci_subject` row pointing at the signed
/// artifact's content hash.
fn seed_simplesigning(f: &Fixture, payload_bytes: &[u8], signature_b64: &str) {
    let payload_hash_hex = format!("{:x}", sha2::Sha256::digest(payload_bytes));
    let payload_hash: ContentHash = payload_hash_hex.parse().expect("valid sha256");
    f.storage
        .insert_content(payload_hash.clone(), payload_bytes.to_vec());

    let manifest_bytes =
        referrer_manifest_for_simplesigning(&payload_hash, signature_b64, payload_bytes.len());
    let manifest_hash_hex = format!("{:x}", sha2::Sha256::digest(&manifest_bytes));
    let manifest_hash: ContentHash = manifest_hash_hex.parse().expect("valid sha256");

    let mut sig_artifact: Artifact = sample_artifact(QuarantineStatus::Released);
    sig_artifact.repository_id = f.repository_id;
    sig_artifact.sha256_checksum = manifest_hash.clone();
    let sig_id = sig_artifact.id;
    f.artifacts.insert(sig_artifact);
    f.storage.insert_content(manifest_hash, manifest_bytes);

    futures::executor::block_on(async {
        f.content_references
            .insert(ContentReference {
                source_artifact_id: sig_id,
                target_content_hash: f.content_hash.clone(),
                kind: "oci_subject".to_string(),
                metadata: serde_json::Value::Null,
                repository_id: f.repository_id,
                recorded_at: chrono::Utc::now(),
            })
            .await
            .expect("seed content-reference");
    });
}

/// Captures the `(bytes, signature)` of each bundle handed to `verify` so a
/// test can assert the keyed carriage produced a SIGNED bundle. Returns
/// `NoAttestation` (the carriage, not the verdict, is under test).
/// `(payload bytes, optional detached signature)` of a captured bundle.
type CapturedBundle = (Vec<u8>, Option<Vec<u8>>);

struct CapturingSignaturePort {
    captured: Mutex<Vec<CapturedBundle>>,
}
impl CapturingSignaturePort {
    fn new() -> Self {
        Self {
            captured: Mutex::new(Vec::new()),
        }
    }
    fn captured(&self) -> Vec<CapturedBundle> {
        self.captured.lock().unwrap().clone()
    }
}
impl ProvenancePort for CapturingSignaturePort {
    fn name(&self) -> &str {
        "cosign-key"
    }
    fn applies_to(&self, format: &str) -> bool {
        format == "oci"
    }
    fn verify<'a>(
        &'a self,
        _artifact: &'a ProvenanceSubject<'a>,
        bundles: &'a [AttestationBundle],
        _policy: &'a ProvenanceRequirements<'a>,
    ) -> BoxFuture<'a, DomainResult<ProvenanceVerdict>> {
        *self.captured.lock().unwrap() = bundles
            .iter()
            .map(|b| (b.bytes.clone(), b.signature.clone()))
            .collect();
        Box::pin(async { Ok(ProvenanceVerdict::no_attestation()) })
    }
    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn fetch_bundles_collects_simplesigning_as_signed_bundle() {
    use base64::Engine as _;
    let port = Arc::new(CapturingSignaturePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    let payload: &[u8] = br#"{"critical":{"image":{"docker-manifest-digest":"sha256:abc"}}}"#;
    let raw_sig: &[u8] = b"\x30\x44the-detached-signature-bytes";
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(raw_sig);
    seed_simplesigning(&f, payload, &sig_b64);

    f.uc.verify_artifact(f.artifact_id).await.expect("Ok");

    let captured = port.captured();
    assert_eq!(
        captured.len(),
        1,
        "the legacy simplesigning .sig is collected (not dropped) as one bundle"
    );
    let (bytes, signature) = &captured[0];
    assert_eq!(
        bytes.as_slice(),
        payload,
        "bundle.bytes is the simplesigning PAYLOAD blob, not the referrer manifest"
    );
    assert_eq!(
        signature.as_deref(),
        Some(raw_sig),
        "the base64 annotation is decoded into bundle.signature (ADR 0039 §8)"
    );
}

#[tokio::test]
async fn fetch_resolves_bundle_blob_not_manifest_real_fixture() {
    // Seed the real cosign v0.3 bundle as the BLOB, with a referrer manifest
    // (the `oci_subject` source) pointing at it.
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    let blob_hash = seed_manifest_and_bundle(&f, COSIGN_BUNDLE_V03_FIXTURE);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::CertChainInvalid),
        }
    );

    // (1) The verdict is the verifier's REAL verdict for that fixture:
    // a well-formed bundle that does NOT chain to the (empty) fixture trust
    // root → Rejected{CertChainInvalid} (lib.rs:367). The pre-fix path would
    // have handed the verifier the MANIFEST bytes → BundleMalformed — a
    // DIFFERENT reason. So this asserts the bundle reached the port parsed as
    // a Bundle.
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1);
    let DomainEvent::ProvenanceRejected(ev) = &transitions[0].1.events[0].event else {
        panic!("expected ProvenanceRejected");
    };
    assert_eq!(
        ev.reason,
        ProvenanceRejectReason::CertChainInvalid,
        "the bundle must reach the verifier parsed as a Bundle (CertChainInvalid), \
         not as a manifest (BundleMalformed)"
    );

    // (2) The bytes handed to the port equal the bundle BLOB, byte-for-byte,
    // and are NOT the referrer manifest bytes.
    let captured = port.captured_bundles();
    assert_eq!(captured.len(), 1, "exactly one bundle resolved");
    assert_eq!(
        captured[0], COSIGN_BUNDLE_V03_FIXTURE,
        "the port must receive the bundle blob bytes, not the manifest bytes"
    );
    // Sanity: the blob hash is the sha256 of what the port received.
    assert_eq!(
        format!("{:x}", sha2::Sha256::digest(&captured[0])),
        blob_hash.as_ref(),
        "captured bytes hash to the bundle-blob content hash",
    );
    // And the bytes are emphatically NOT a referrer manifest.
    let manifest_bytes = referrer_manifest_for(&blob_hash);
    assert_ne!(
        captured[0], manifest_bytes,
        "the port must NOT receive the referrer manifest bytes",
    );
}

#[tokio::test]
async fn referrer_manifest_with_no_bundle_layer_contributes_nothing() {
    // The `oci_subject` source artifact's CAS bytes are a manifest carrying
    // only a non-Sigstore (tar+gzip) layer → `sigstore_bundle_layers` yields
    // nothing → the referrer contributes no bundle → the verifier runs with
    // zero bundles. Under VerifyIfPresent that is the allowed-unsigned no-op.
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );

    // A manifest with a single NON-bundle layer.
    let manifest_bytes = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "size": 10
            }
        ]
    })
    .to_string()
    .into_bytes();
    let manifest_hash_hex = format!("{:x}", sha2::Sha256::digest(&manifest_bytes));
    let manifest_hash: ContentHash = manifest_hash_hex.parse().unwrap();
    let mut sig_artifact: Artifact = sample_artifact(QuarantineStatus::Released);
    sig_artifact.repository_id = f.repository_id;
    sig_artifact.sha256_checksum = manifest_hash.clone();
    let sig_id = sig_artifact.id;
    f.artifacts.insert(sig_artifact);
    f.storage.insert_content(manifest_hash, manifest_bytes);
    futures::executor::block_on(async {
        f.content_references
            .insert(ContentReference {
                source_artifact_id: sig_id,
                target_content_hash: f.content_hash.clone(),
                kind: "oci_subject".to_string(),
                metadata: serde_json::Value::Null,
                repository_id: f.repository_id,
                recorded_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
    });

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
        "a referrer with no bundle layer contributes no bundle → NoAttestation (allow)",
    );
    assert_eq!(
        port.captured_bundles(),
        Vec::<Vec<u8>>::new(),
        "the verifier must be handed zero bundles when no bundle layer is present",
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
    assert!(f.lifecycle.committed_transitions().is_empty());
}

#[tokio::test]
async fn bundle_blob_absent_from_cas_surfaces_fetch_failure_not_panic() {
    // The referrer manifest references a bundle-layer digest, but that blob
    // is NOT in CAS. The blob read fails on every retry → the fetch-failure
    // path decides mode-dependently. Under Required → fail-closed
    // Rejected{RekorNotFound}; it must NEVER panic.
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );

    // A manifest whose declared bundle-layer blob is absent from CAS.
    let absent_blob: ContentHash =
        "2222222222222222222222222222222222222222222222222222222222222222"
            .parse()
            .unwrap();
    let manifest_bytes = referrer_manifest_for(&absent_blob);
    let manifest_hash_hex = format!("{:x}", sha2::Sha256::digest(&manifest_bytes));
    let manifest_hash: ContentHash = manifest_hash_hex.parse().unwrap();
    let mut sig_artifact: Artifact = sample_artifact(QuarantineStatus::Released);
    sig_artifact.repository_id = f.repository_id;
    sig_artifact.sha256_checksum = manifest_hash.clone();
    let sig_id = sig_artifact.id;
    f.artifacts.insert(sig_artifact);
    f.storage.insert_content(manifest_hash, manifest_bytes);
    // NOTE: the bundle blob at `absent_blob` is deliberately NOT inserted.
    futures::executor::block_on(async {
        f.content_references
            .insert(ContentReference {
                source_artifact_id: sig_id,
                target_content_hash: f.content_hash.clone(),
                kind: "oci_subject".to_string(),
                metadata: serde_json::Value::Null,
                repository_id: f.repository_id,
                recorded_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
    });

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::RekorNotFound),
        }
    );
    // Required + an absent bundle blob is a fetch failure → fail-closed.
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Rejected,
        "an absent bundle blob under Required must fail-closed, never panic",
    );
    let transitions = f.lifecycle.committed_transitions();
    let DomainEvent::ProvenanceRejected(ev) = &transitions[0].1.events[0].event else {
        panic!("expected ProvenanceRejected");
    };
    assert_eq!(ev.reason, ProvenanceRejectReason::RekorNotFound);
    assert!(
        port.captured_bundles().is_empty(),
        "the verifier never ran — the blob fetch failed first",
    );
}

// ===========================================================================
// The proxy referrer-fetch arm.
//
// On a PROXY/pull-through OCI scope with provenance enabled, when no
// signature bundle exists locally, the orchestrator fetches the image's
// Sigstore referrer(s) from upstream, ingests the referrer manifest + its
// bundle blob into local CAS via a NARROW CREATE (held ports — no
// `IngestUseCase`, no scan/provenance enqueue), writes the `oci_subject`
// row, re-reads local bundles, then verifies. A hosted repo (`resolve →
// None`) with no local bundle stays `NoAttestation` (nothing to fetch).
// ===========================================================================

/// The `path_prefix` the proxy mapping is keyed on. Empty ⇒ catch-all, so
/// `resolve(repo.id, "my-pkg")` matches and strips to `"my-pkg"` (no Docker
/// Hub `library/` rewrite under `Anonymous`).
const PROXY_PATH_PREFIX: &str = "";

/// Build a `RepositoryUpstreamMapping` for `repo_id` that the
/// `MockUpstreamResolver` will match as a catch-all proxy (empty prefix,
/// Anonymous auth → name passes through unchanged).
fn proxy_mapping(repo_id: Uuid) -> RepositoryUpstreamMapping {
    let now = chrono::Utc::now();
    RepositoryUpstreamMapping {
        id: Uuid::new_v4(),
        repository_id: repo_id,
        path_prefix: PROXY_PATH_PREFIX.into(),
        upstream_url: "https://registry.example".into(),
        upstream_name_prefix: None,
        upstream_auth: UpstreamAuth::Anonymous,
        secret_ref: None,
        managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
        managed_by_digest: None,
        insecure_upstream_url: false,
        trust_upstream_publish_time: false,
        mtls_cert_ref: None,
        mtls_key_ref: None,
        ca_bundle_ref: None,
        pinned_cert_sha256: None,
        created_at: now,
        updated_at: now,
    }
}

/// The `sha256:<hex>` digest string the orchestrator passes to
/// `fetch_referrers` / keys the upstream fixtures on — the proxied image's
/// content hash.
fn image_digest_str(content_hash: &ContentHash) -> String {
    format!("sha256:{content_hash}")
}

/// Seed the proxy + resolver so the fixture's repo is a proxy whose upstream
/// publishes ONE Sigstore-bundle referrer for the image. Returns the
/// `(referrer_manifest_digest, bundle_blob_hash)` so callers can assert the
/// `oci_subject` row + the verdict.
///
/// The wiring mirrors the production arm exactly: a referrer descriptor
/// (`artifact_type = SIGSTORE_BUNDLE_MEDIA_TYPE`) → `fetch_manifest` returns
/// the referrer manifest → `sigstore_bundle_layers` extracts the bundle
/// layer digest → `fetch_blob` returns the bundle blob bytes.
fn seed_upstream_referrer(f: &Fixture, bundle_bytes: &[u8]) -> (String, ContentHash) {
    f.upstream_resolver.insert(proxy_mapping(f.repository_id));

    // The bundle blob lives at its own content hash (= the manifest's layer
    // digest). `fetch_blob` is keyed on (path_prefix, upstream_name, digest).
    let blob_hash_hex = format!("{:x}", sha2::Sha256::digest(bundle_bytes));
    let blob_hash: ContentHash = blob_hash_hex.parse().expect("valid sha256");
    let blob_digest = format!("sha256:{blob_hash}");

    // The referrer manifest references that blob as its single bundle layer.
    let manifest_bytes = referrer_manifest_for(&blob_hash);
    let manifest_hash_hex = format!("{:x}", sha2::Sha256::digest(&manifest_bytes));
    let manifest_digest = format!("sha256:{manifest_hash_hex}");

    let image_digest = image_digest_str(&f.content_hash);
    let upstream_name = f.artifacts.get(f.artifact_id).unwrap().name;

    // 1. The Referrers API returns one Sigstore-bundle descriptor for the image.
    f.upstream_proxy.insert_referrers(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &image_digest,
        vec![ReferrerDescriptor {
            digest: manifest_digest.clone(),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            artifact_type: Some(hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE.into()),
        }],
    );

    // 2. `fetch_manifest(referrer digest)` returns the referrer manifest bytes.
    f.upstream_proxy.insert_manifest(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &manifest_digest,
        ManifestFetch {
            bytes: manifest_bytes,
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            declared_digest: Some(manifest_digest.clone()),
            last_modified: None,
        },
    );

    // 3. `fetch_blob(bundle layer digest)` returns the bundle blob bytes.
    f.upstream_proxy.insert_blob(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &blob_digest,
        bundle_bytes.to_vec(),
        Some(blob_digest.clone()),
    );

    (manifest_digest, blob_hash)
}

/// Mirror of [`seed_upstream_referrer`] for a keyed simplesigning `.sig`
/// (ADR 0039 §8): a well-typed simplesigning referrer descriptor + its manifest
/// (carrying the signature annotation) + the payload-layer blob, on a PROXY scope.
fn seed_upstream_simplesigning_referrer(f: &Fixture, payload_bytes: &[u8], signature_b64: &str) {
    f.upstream_resolver.insert(proxy_mapping(f.repository_id));

    let payload_hash_hex = format!("{:x}", sha2::Sha256::digest(payload_bytes));
    let payload_hash: ContentHash = payload_hash_hex.parse().expect("valid sha256");
    let blob_digest = format!("sha256:{payload_hash}");

    let manifest_bytes =
        referrer_manifest_for_simplesigning(&payload_hash, signature_b64, payload_bytes.len());
    let manifest_hash_hex = format!("{:x}", sha2::Sha256::digest(&manifest_bytes));
    let manifest_digest = format!("sha256:{manifest_hash_hex}");

    let image_digest = image_digest_str(&f.content_hash);
    let upstream_name = f.artifacts.get(f.artifact_id).unwrap().name;

    f.upstream_proxy.insert_referrers(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &image_digest,
        vec![ReferrerDescriptor {
            digest: manifest_digest.clone(),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            artifact_type: Some(hort_domain::oci::COSIGN_SIMPLESIGNING_MEDIA_TYPE.into()),
        }],
    );
    f.upstream_proxy.insert_manifest(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &manifest_digest,
        ManifestFetch {
            bytes: manifest_bytes,
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            declared_digest: Some(manifest_digest.clone()),
            last_modified: None,
        },
    );
    f.upstream_proxy.insert_blob(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &blob_digest,
        payload_bytes.to_vec(),
        Some(blob_digest.clone()),
    );
}

#[tokio::test]
async fn proxy_lands_upstream_simplesigning_referrer_as_signed_bundle() {
    use base64::Engine as _;
    let port = Arc::new(CapturingSignaturePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // No LOCAL bundle — the orchestrator fetches the simplesigning referrer from
    // upstream, lands the payload blob + manifest, then re-reads it (ADR 0039 §8).
    let payload: &[u8] = br#"{"critical":{"image":{"docker-manifest-digest":"sha256:abc"}}}"#;
    let raw_sig: &[u8] = b"\x30\x44proxied-detached-signature";
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(raw_sig);
    seed_upstream_simplesigning_referrer(&f, payload, &sig_b64);

    f.uc.verify_artifact(f.artifact_id).await.expect("Ok");

    let captured = port.captured();
    assert_eq!(
        captured.len(),
        1,
        "the proxied simplesigning .sig is landed from upstream + read as one bundle"
    );
    let (bytes, signature) = &captured[0];
    assert_eq!(
        bytes.as_slice(),
        payload,
        "the landed simplesigning payload blob reaches the verifier"
    );
    assert_eq!(
        signature.as_deref(),
        Some(raw_sig),
        "the annotation signature is carried through the proxy landing"
    );
}

// ---------------------------------------------------------------------------
// Proxy repo + empty local bundles + upstream Sigstore referrer →
// oci_subject row written, NO scan/provenance job enqueued, verdict
// reached (the capturing port receives the bundle blob).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proxy_fetches_upstream_referrer_writes_oci_subject_and_reaches_verdict() {
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // No LOCAL bundle seeded — the orchestrator must go upstream.
    let (_manifest_digest, blob_hash) = seed_upstream_referrer(&f, COSIGN_BUNDLE_V03_FIXTURE);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::CertChainInvalid),
        }
    );

    // (1) The capturing port received the bundle BLOB bytes (byte-for-byte),
    //     proving the upstream-fetched bundle flowed all the way to the
    //     verifier through the narrow-create + the local re-read.
    let captured = port.captured_bundles();
    assert_eq!(
        captured.len(),
        1,
        "exactly one bundle resolved from upstream"
    );
    assert_eq!(
        captured[0], COSIGN_BUNDLE_V03_FIXTURE,
        "the verifier must receive the upstream bundle blob, not the manifest"
    );
    assert_eq!(
        format!("{:x}", sha2::Sha256::digest(&captured[0])),
        blob_hash.as_ref(),
    );
    // The verdict is the verifier's REAL verdict for the fixture (a parsed
    // Bundle that does not chain to the empty fixture root → CertChainInvalid).
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
    let rejected_ev = f
        .lifecycle
        .committed_transitions()
        .into_iter()
        .find_map(|(_, ev, _)| match &ev.events[0].event {
            DomainEvent::ProvenanceRejected(e) => Some(e.reason),
            _ => None,
        })
        .expect("a ProvenanceRejected verdict was committed");
    assert_eq!(rejected_ev, ProvenanceRejectReason::CertChainInvalid);

    // (2) The `oci_subject` content-reference row was written, pointing AT the
    //     image content hash. `find_by_target` returns it under the
    //     "oci_subject" kind.
    let rows = f
        .content_references
        .find_by_target(f.repository_id, &f.content_hash, Some("oci_subject"))
        .await
        .expect("find_by_target");
    assert_eq!(
        rows.len(),
        1,
        "the proxy narrow-create must write exactly one oci_subject row"
    );
    assert_eq!(rows[0].kind, "oci_subject");
    assert_eq!(rows[0].target_content_hash, f.content_hash);

    // (3) The referrer manifest was landed via `commit_transition` as a
    //     status-`None` artifact (the narrow create) — NOT quarantined.
    let referrer_artifact = f.artifacts.get(rows[0].source_artifact_id).unwrap();
    assert_eq!(
        referrer_artifact.quarantine_status,
        QuarantineStatus::None,
        "the referrer manifest is an internal bookkeeping artifact — status None"
    );

    // (4) An `ArtifactIngested` transition was committed for the referrer
    //     manifest (the narrow create), in addition to the verdict event.
    let ingested = f
        .lifecycle
        .committed_transitions()
        .into_iter()
        .filter(|(_, ev, _)| matches!(ev.events[0].event, DomainEvent::ArtifactIngested(_)))
        .count();
    assert_eq!(
        ingested, 1,
        "the proxy narrow-create commits exactly one ArtifactIngested"
    );
}

// ---------------------------------------------------------------------------
// Hosted repo (resolver → None) + empty local bundle → no upstream
// fetch, NoAttestation.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hosted_repo_with_no_local_bundle_does_not_fetch_upstream() {
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // Seed the upstream proxy with a referrer + bundle, but DO NOT seed the
    // resolver → the repo is hosted → `resolve` returns None → the
    // orchestrator must NOT consult the proxy.
    let upstream_name = f.artifacts.get(f.artifact_id).unwrap().name;
    let blob = COSIGN_BUNDLE_V03_FIXTURE;
    let blob_hash: ContentHash = format!("{:x}", sha2::Sha256::digest(blob)).parse().unwrap();
    f.upstream_proxy.insert_referrers(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &image_digest_str(&f.content_hash),
        vec![ReferrerDescriptor {
            digest: format!("sha256:{}", "0".repeat(64)),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            artifact_type: Some(hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE.into()),
        }],
    );
    let _ = blob_hash; // referrer seeded but must never be consulted.

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
        "a hosted repo with no local bundle stays NoAttestation (allow) — no fetch",
    );
    assert!(
        port.captured_bundles().is_empty(),
        "the verifier ran with zero bundles — no upstream fetch happened",
    );
    // No `oci_subject` row was written (the narrow-create never ran).
    let rows = f
        .content_references
        .find_by_target(f.repository_id, &f.content_hash, Some("oci_subject"))
        .await
        .unwrap();
    assert!(rows.is_empty(), "hosted path writes no oci_subject row");
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
    assert!(f.lifecycle.committed_transitions().is_empty());
}

// ---------------------------------------------------------------------------
// Required on a proxy whose upstream returns NO Sigstore bundle (empty
// referrers) → ProvenanceRejected{Unsigned}.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn required_on_proxy_with_no_upstream_bundle_rejects_unsigned() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // Proxy repo (resolver seeded) but the upstream publishes NO referrers
    // (the unseeded key returns the empty "no referrers" default).
    f.upstream_resolver.insert(proxy_mapping(f.repository_id));

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::Unsigned),
        }
    );
    // The verifier ran with ZERO bundles (the upstream has none) → under
    // Required, `complete_provenance` maps NoAttestation to Rejected{Unsigned}.
    assert_eq!(port.last_inputs(), Some((0, ARTIFACT_PAYLOAD.len())));
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
    let transitions = f.lifecycle.committed_transitions();
    let DomainEvent::ProvenanceRejected(ev) = &transitions[0].1.events[0].event else {
        panic!("expected ProvenanceRejected");
    };
    assert_eq!(
        ev.reason,
        ProvenanceRejectReason::Unsigned,
        "Required on a proxy whose upstream is genuinely unsigned is correct — \
         no apply-time guard required",
    );
    // No `oci_subject` row — there was nothing to land.
    let rows = f
        .content_references
        .find_by_target(f.repository_id, &f.content_hash, Some("oci_subject"))
        .await
        .unwrap();
    assert!(rows.is_empty());
}

// ---------------------------------------------------------------------------
// VerifyIfPresent + an upstream fetch error → degrade to NoAttestation
// (the existing `apply_fetch_failure` arm; never fail-closed on a proxy).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_if_present_upstream_fetch_error_degrades_to_no_attestation() {
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // Proxy repo: resolver seeded so the arm fires, and the upstream returns a
    // Sigstore-bundle descriptor — but `fetch_manifest` is armed to error, so
    // the upstream fetch fails mid-flight.
    let upstream_name = f.artifacts.get(f.artifact_id).unwrap().name;
    f.upstream_resolver.insert(proxy_mapping(f.repository_id));
    f.upstream_proxy.insert_referrers(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &image_digest_str(&f.content_hash),
        vec![ReferrerDescriptor {
            digest: format!("sha256:{}", "a".repeat(64)),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            artifact_type: Some(hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE.into()),
        }],
    );
    f.upstream_proxy
        .fail_next_manifest_with(DomainError::Invariant("upstream:unavailable:boom".into()));

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
        "a VerifyIfPresent proxy fetch error degrades to NoAttestation (allow), never fail-closed",
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Quarantined,
        "VerifyIfPresent must NEVER fail-closed on upstream flakiness",
    );
    assert!(f.lifecycle.committed_transitions().is_empty());
    assert!(
        port.captured_bundles().is_empty(),
        "the verifier never ran — the upstream fetch failed first",
    );
}

// ---------------------------------------------------------------------------
// Blob integrity: the put-returned hash != the manifest-declared
// digest → that referrer is SKIPPED (read blobs back by DECLARED digest).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_returned_hash_mismatch_skips_referrer_blob_integrity() {
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    f.upstream_resolver.insert(proxy_mapping(f.repository_id));
    let upstream_name = f.artifacts.get(f.artifact_id).unwrap().name;

    // The referrer manifest DECLARES a bundle-layer digest, but the bytes the
    // upstream serves for that blob hash to a DIFFERENT value — so the
    // `put`-returned hash (sha256 of the served bytes) != the declared digest.
    // The declared-digest integrity check requires the referrer be SKIPPED on mismatch.
    let declared_blob_hash: ContentHash = format!("{:x}", sha2::Sha256::digest(b"DECLARED-bytes"))
        .parse()
        .unwrap();
    let declared_blob_digest = format!("sha256:{declared_blob_hash}");
    let manifest_bytes = referrer_manifest_for(&declared_blob_hash);
    let manifest_hash_hex = format!("{:x}", sha2::Sha256::digest(&manifest_bytes));
    let manifest_digest = format!("sha256:{manifest_hash_hex}");

    f.upstream_proxy.insert_referrers(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &image_digest_str(&f.content_hash),
        vec![ReferrerDescriptor {
            digest: manifest_digest.clone(),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            artifact_type: Some(hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE.into()),
        }],
    );
    f.upstream_proxy.insert_manifest(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &manifest_digest,
        ManifestFetch {
            bytes: manifest_bytes,
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            declared_digest: Some(manifest_digest.clone()),
            last_modified: None,
        },
    );
    // The blob is keyed on the DECLARED digest, but its BYTES differ — so the
    // put-returned hash will not equal the declared digest.
    f.upstream_proxy.insert_blob(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &declared_blob_digest,
        b"TAMPERED-bytes-that-do-not-match-the-declared-digest".to_vec(),
        Some(declared_blob_digest.clone()),
    );

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
        "a blob whose put-returned hash != declared digest is skipped → no bundle → NoAttestation",
    );
    assert!(
        port.captured_bundles().is_empty(),
        "the integrity-failing referrer contributes no bundle",
    );
    // No `oci_subject` row was written for the skipped referrer.
    let rows = f
        .content_references
        .find_by_target(f.repository_id, &f.content_hash, Some("oci_subject"))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "a referrer skipped on the declared-digest integrity check writes no oci_subject row",
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
}

// ---------------------------------------------------------------------------
// A referrer descriptor whose digest is NOT a sha256 CAS digest →
// skipped (the `parse_sha256_digest` None arm — the manifest is
// content-addressed; a non-sha256 reference is not landable).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_sha256_referrer_digest_is_skipped() {
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    f.upstream_resolver.insert(proxy_mapping(f.repository_id));
    let upstream_name = f.artifacts.get(f.artifact_id).unwrap().name;
    // A Sigstore-bundle descriptor whose digest uses a NON-sha256 algorithm.
    f.upstream_proxy.insert_referrers(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &image_digest_str(&f.content_hash),
        vec![ReferrerDescriptor {
            digest: format!("sha512:{}", "a".repeat(128)),
            media_type: hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE.into(),
            artifact_type: Some(hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE.into()),
        }],
    );

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
        "a non-sha256 referrer digest is skipped → no bundle → NoAttestation",
    );
    assert!(port.captured_bundles().is_empty());
    let rows = f
        .content_references
        .find_by_target(f.repository_id, &f.content_hash, Some("oci_subject"))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "a skipped referrer writes no oci_subject row"
    );
}

// ---------------------------------------------------------------------------
// A Sigstore descriptor (matched via `media_type`, NOT `artifact_type`)
// whose fetched manifest carries NO bundle layer → contributes nothing
// (the `blob_hashes.is_empty()` skip arm). Also covers the `media_type`
// leg of the is-Sigstore filter.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn referrer_manifest_with_no_bundle_layer_is_skipped() {
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    f.upstream_resolver.insert(proxy_mapping(f.repository_id));
    let upstream_name = f.artifacts.get(f.artifact_id).unwrap().name;

    // A manifest with ONLY a non-bundle (tar+gzip) layer → no bundle digest.
    let manifest_bytes = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{}", "1".repeat(64)),
                "size": 10
            }
        ]
    })
    .to_string()
    .into_bytes();
    let manifest_hash_hex = format!("{:x}", sha2::Sha256::digest(&manifest_bytes));
    let manifest_digest = format!("sha256:{manifest_hash_hex}");

    // Descriptor matched by `media_type` (the artifact_type leg is None).
    f.upstream_proxy.insert_referrers(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &image_digest_str(&f.content_hash),
        vec![ReferrerDescriptor {
            digest: manifest_digest.clone(),
            media_type: hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE.into(),
            artifact_type: None,
        }],
    );
    f.upstream_proxy.insert_manifest(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &manifest_digest,
        ManifestFetch {
            bytes: manifest_bytes,
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            declared_digest: Some(manifest_digest.clone()),
            last_modified: None,
        },
    );

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
    );
    assert!(port.captured_bundles().is_empty());
    let rows = f
        .content_references
        .find_by_target(f.repository_id, &f.content_hash, Some("oci_subject"))
        .await
        .unwrap();
    assert!(rows.is_empty());
}

// ---------------------------------------------------------------------------
// The REFERRER MANIFEST's put-returned hash != the descriptor's declared
// digest → skipped (the manifest-mismatch arm). The upstream lies about
// the referrer manifest's own digest: a valid bundle blob is served
// (step c passes) but the manifest bytes do not hash to the descriptor
// digest.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn referrer_manifest_digest_mismatch_is_skipped() {
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    f.upstream_resolver.insert(proxy_mapping(f.repository_id));
    let upstream_name = f.artifacts.get(f.artifact_id).unwrap().name;

    // A genuine bundle blob (step c will pass — its put-hash matches the
    // layer digest the manifest declares).
    let bundle = COSIGN_BUNDLE_V03_FIXTURE;
    let blob_hash: ContentHash = format!("{:x}", sha2::Sha256::digest(bundle))
        .parse()
        .unwrap();
    let blob_digest = format!("sha256:{blob_hash}");
    let manifest_bytes = referrer_manifest_for(&blob_hash);

    // The descriptor LIES about the manifest's digest — it advertises a
    // digest that the manifest bytes do not hash to.
    let lying_manifest_digest = format!("sha256:{}", "e".repeat(64));

    f.upstream_proxy.insert_referrers(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &image_digest_str(&f.content_hash),
        vec![ReferrerDescriptor {
            digest: lying_manifest_digest.clone(),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            artifact_type: Some(hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE.into()),
        }],
    );
    // `fetch_manifest(lying_digest)` returns the real manifest bytes (whose
    // actual hash != lying_digest).
    f.upstream_proxy.insert_manifest(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &lying_manifest_digest,
        ManifestFetch {
            bytes: manifest_bytes,
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            declared_digest: Some(lying_manifest_digest.clone()),
            last_modified: None,
        },
    );
    // The bundle blob is valid (so step c passes; only the manifest digest
    // mismatch in step d fires).
    f.upstream_proxy.insert_blob(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &blob_digest,
        bundle.to_vec(),
        Some(blob_digest.clone()),
    );

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
        "a referrer-manifest digest mismatch skips the referrer → NoAttestation",
    );
    // The referrer was skipped at step d (after the blob put) — so no
    // oci_subject row was written and no verdict reached.
    let rows = f
        .content_references
        .find_by_target(f.repository_id, &f.content_hash, Some("oci_subject"))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "a manifest-digest-mismatched referrer writes no oci_subject row",
    );
    let saved2 = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved2.quarantine_status, QuarantineStatus::Quarantined);
}

// ---------------------------------------------------------------------------
// (i) the upstream REFERRER DISCOVERY itself errors (`fetch_referrers` →
//     Err). The arm logs a `warn!` and propagates the error to the caller's
//     mode-dependent `apply_fetch_failure` ("upstream referrer fetch").
//     Under VerifyIfPresent that degrades to NoAttestation (allow) — never
//     fail-closed on a proxy. Drives the `fetch_referrers` error path
//     (provenance_orchestration.rs `fetch_and_land_upstream_referrers`
//     `.map_err(..)?`) + the upstream-referrer-fetch `apply_fetch_failure`
//     arm in `verify_artifact`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_if_present_upstream_referrer_discovery_error_degrades_to_no_attestation() {
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // Proxy repo (resolver seeded so the arm fires) but the referrer
    // DISCOVERY call is armed to error — `fetch_referrers` returns Err
    // before any descriptor is examined.
    f.upstream_resolver.insert(proxy_mapping(f.repository_id));
    f.upstream_proxy
        .fail_next_referrers_with(DomainError::Invariant(
            "upstream:unavailable:referrers".into(),
        ));

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
        "a VerifyIfPresent referrer-discovery error degrades to NoAttestation (allow), \
         never fail-closed",
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Quarantined,
        "VerifyIfPresent must NEVER fail-closed on upstream referrer-discovery flakiness",
    );
    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "no event appended on the VerifyIfPresent degrade path; nothing was landed",
    );
    assert!(
        port.captured_bundles().is_empty(),
        "the verifier never ran — referrer discovery failed first",
    );
    // No `oci_subject` row was written (the narrow-create never started).
    let rows = f
        .content_references
        .find_by_target(f.repository_id, &f.content_hash, Some("oci_subject"))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "a failed referrer discovery lands nothing → no oci_subject row",
    );
}

// ---------------------------------------------------------------------------
// The post-proxy bundle RE-READ errors. The upstream referrer is landed
// successfully (oci_subject row written, referrer manifest committed),
// but the immediately-following local `fetch_bundles` re-read fails on
// EVERY retry attempt (the landed referrer manifest's CAS bytes are
// unreadable) → the caller's "post-proxy bundle re-read"
// `apply_fetch_failure` arm fires. Under VerifyIfPresent that degrades
// to NoAttestation (allow). Drives the `Err(e)` re-read arm inside
// `verify_artifact`'s proxy block (the second `fetch_bundles` match).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_proxy_bundle_reread_error_degrades_to_no_attestation() {
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // Full upstream referrer wired so the LANDING succeeds (oci_subject row +
    // referrer manifest committed). No local bundle → the proxy arm fires.
    let (_manifest_digest, blob_hash) = seed_upstream_referrer(&f, COSIGN_BUNDLE_V03_FIXTURE);

    // The landed referrer manifest's CAS hash is deterministic — it is the
    // sha256 of `referrer_manifest_for(blob_hash)` (the same bytes the proxy
    // stores via `storage.put` during landing). Arm a PERSISTENT get failure
    // on it so the post-proxy re-read's `read_bounded` fails on every one of
    // the 3 `fetch_bundles` attempts (a one-shot failure would recover on the
    // second). The landing itself only `put`s — never `get`s — so it is
    // unaffected, as is the image-preimage read (a different hash).
    let landed_manifest_bytes = referrer_manifest_for(&blob_hash);
    let landed_manifest_hash: ContentHash =
        format!("{:x}", sha2::Sha256::digest(&landed_manifest_bytes))
            .parse()
            .expect("valid sha256");
    f.storage.fail_get_persistent(landed_manifest_hash);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
        "a VerifyIfPresent post-proxy re-read failure degrades to NoAttestation (allow)",
    );

    // Proof we reached the RE-READ arm (not an earlier failure): the landing
    // ran to completion — the oci_subject row was written and the referrer
    // manifest was committed via the narrow create.
    let rows = f
        .content_references
        .find_by_target(f.repository_id, &f.content_hash, Some("oci_subject"))
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the landing completed before the re-read failed — oci_subject row present",
    );
    let ingested = f
        .lifecycle
        .committed_transitions()
        .into_iter()
        .filter(|(_, ev, _)| matches!(ev.events[0].event, DomainEvent::ArtifactIngested(_)))
        .count();
    assert_eq!(
        ingested, 1,
        "the narrow create committed the referrer manifest before the re-read failed",
    );
    // No provenance verdict event — the re-read failed under VerifyIfPresent,
    // so the degrade-to-allow path appends nothing.
    let provenance_events = f
        .lifecycle
        .committed_transitions()
        .into_iter()
        .filter(|(_, ev, _)| {
            matches!(
                ev.events[0].event,
                DomainEvent::ProvenanceVerified(_) | DomainEvent::ProvenanceRejected(_)
            )
        })
        .count();
    assert_eq!(
        provenance_events, 0,
        "the VerifyIfPresent re-read failure appends no provenance verdict event",
    );
    // The IMAGE artifact's status is unchanged (VerifyIfPresent never
    // fail-closes on infra flakiness).
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
    assert!(
        port.captured_bundles().is_empty(),
        "the verifier never ran — the re-read failed before dispatch",
    );
}

// ---------------------------------------------------------------------------
// (k) a Sigstore referrer whose upstream `fetch_manifest` yields NO cached
//     body (`cache_handle: None`) → `land_one_referrer` skips it (returns
//     Ok(false)) → nothing landed → the re-read finds no bundle →
//     NoAttestation. Drives the `let Some(handle) = outcome.cache_handle
//     else { return Ok(false) }` skip arm in `land_one_referrer`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn referrer_manifest_with_no_cache_handle_is_skipped() {
    let port = Arc::new(CapturingBundleAwarePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    f.upstream_resolver.insert(proxy_mapping(f.repository_id));
    let upstream_name = f.artifacts.get(f.artifact_id).unwrap().name;

    // A well-formed Sigstore-bundle referrer descriptor whose digest IS a
    // valid sha256 (so `parse_sha256_digest` passes and the arm calls
    // `fetch_manifest`) — but `fetch_manifest` is armed to return an outcome
    // with `cache_handle: None`, so `land_one_referrer` short-circuits to
    // Ok(false) before reading any manifest body.
    let referrer_digest = format!("sha256:{}", "c".repeat(64));
    f.upstream_proxy.insert_referrers(
        PROXY_PATH_PREFIX,
        &upstream_name,
        &image_digest_str(&f.content_hash),
        vec![ReferrerDescriptor {
            digest: referrer_digest,
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            artifact_type: Some(hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE.into()),
        }],
    );
    f.upstream_proxy.next_manifest_yields_no_cache_handle();

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::NoAttestation,
        },
        "a referrer whose manifest fetch yields no cached body is skipped → \
         no bundle → NoAttestation (allow)",
    );
    assert!(
        port.captured_bundles().is_empty(),
        "the skipped referrer contributes no bundle — the verifier ran with zero bundles",
    );
    // Nothing was landed — no oci_subject row, no committed transition.
    let rows = f
        .content_references
        .find_by_target(f.repository_id, &f.content_hash, Some("oci_subject"))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "a referrer skipped on the no-cache-handle arm writes no oci_subject row",
    );
    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "nothing landed → no narrow-create transition, no verdict event",
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
}
