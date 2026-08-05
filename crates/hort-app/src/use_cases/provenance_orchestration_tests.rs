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
    NegligibleAction, ProvenanceMode, ScanPolicyProjection, SignerIdentityPattern,
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
use crate::use_cases::quarantine_use_case::QuarantineUseCase;
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
    /// The mock event store behind the publisher — the cascade tests seed
    /// artifact streams here (an existing `ProvenanceVerified` drives the
    /// already-cleared verify skip and the cascade idempotency check).
    events: Arc<MockEventStore>,
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
    build_with_payload(format, mode, identities, ports, ARTIFACT_PAYLOAD)
}

/// [`build`] with the subject artifact's CAS bytes parameterized. The
/// subject's `content_hash` is pinned to `sha256(payload)` and the
/// `oci_subject` referrer written by [`seed_manifest_and_bundle`] targets
/// that hash — so supplying an image-index body makes the SIGNED subject
/// an index, and the whole provenance path (fetch bundles → verify →
/// clearance) runs against the index digest unchanged. This is the
/// mechanized proof of design §2 D4's push-then-sign payoff: cosign signs
/// the index digest and the existing `oci_subject` + provenance-verify
/// path targets it by hash, shape-agnostically.
fn build_with_payload(
    format: RepositoryFormat,
    mode: Option<ProvenanceMode>,
    identities: Vec<SignerIdentityPattern>,
    ports: Vec<Arc<dyn ProvenancePort>>,
    payload: &[u8],
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
    // Pin the CAS hash to the digest of `payload` so the stored bytes
    // round-trip (sha256(payload) == content_hash).
    let hash_hex = format!("{:x}", sha2::Sha256::digest(payload));
    let content_hash: ContentHash = hash_hex.parse().expect("valid sha256");
    artifact.sha256_checksum = content_hash.clone();
    let artifact_id = artifact.id;
    artifacts.insert(artifact);
    storage.insert_content(content_hash.clone(), payload.to_vec());

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
        events,
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
        negligible_action: NegligibleAction::Ignore,
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

/// A minimal keyed cosign v3 Sigstore v0.3 bundle (bare `publicKey`, DSSE
/// envelope over an in-toto Statement binding `digest_hex`), signed opaquely.
fn keyed_v03_bundle_json(digest_hex: &str, sig_bytes: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let eng = base64::engine::general_purpose::STANDARD;
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [ { "digest": { "sha256": digest_hex }, "annotations": {} } ],
        "predicateType": "https://sigstore.dev/cosign/sign/v1"
    })
    .to_string();
    serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": { "publicKey": { "hint": "abc" } },
        "dsseEnvelope": {
            "payload": eng.encode(statement.as_bytes()),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [ { "sig": eng.encode(sig_bytes) } ]
        }
    })
    .to_string()
    .into_bytes()
}

/// `build_bundle` (ADR 0039 §8): a cosign v3 keyed v0.3 bundle is wrapped
/// `new_signed` (the keyed verifier's) carrying the raw DSSE signature, so the
/// two verifiers self-select by signature-presence.
#[test]
fn build_bundle_wraps_keyed_v03_as_signed_with_the_dsse_signature() {
    let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let raw_sig = vec![0x30, 0x44, 0x02, 0x20, 0xde, 0xad];
    let bundle_json = keyed_v03_bundle_json(digest, &raw_sig);
    let bundle = build_bundle(bundle_json.clone());
    assert_eq!(
        bundle.signature.as_deref(),
        Some(raw_sig.as_slice()),
        "a keyed v0.3 bundle carries its raw DSSE signature so the keyed verifier claims it"
    );
    assert_eq!(bundle.bytes, bundle_json, "bytes stay the full bundle blob");
}

/// A keyless (Fulcio-cert) v0.3 bundle is wrapped `new` (`signature == None`)
/// — the Sigstore verifier's, byte-for-byte the prior behaviour.
#[test]
fn build_bundle_wraps_keyless_cert_bundle_as_unsigned() {
    let keyless = br#"{
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": { "certificate": { "rawBytes": "AAAA" } },
        "dsseEnvelope": {
            "payload": "eyJzdWJqZWN0IjpbeyJkaWdlc3QiOnsic2hhMjU2IjoiYWEifX1dfQ==",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [ { "sig": "AAAA" } ]
        }
    }"#
    .to_vec();
    let bundle = build_bundle(keyless.clone());
    assert_eq!(
        bundle.signature, None,
        "a keyless bundle stays unsigned (the Sigstore verifier's)"
    );
    assert_eq!(bundle.bytes, keyless);
}

/// A bundle the keyed extractor cannot claim (not a bundle at all, or a
/// keyed-shaped bundle with undecodable DSSE material) is wrapped `new` — the
/// Sigstore verifier folds a truly malformed one to BundleMalformed; a
/// non-keyed one is simply its shape. Never routed to the keyed verifier.
#[test]
fn build_bundle_wraps_unclaimable_bytes_as_unsigned() {
    // Not a bundle object at all.
    let b1 = build_bundle(b"not a bundle".to_vec());
    assert_eq!(b1.signature, None);
    // Keyed-shaped but the DSSE payload is not valid base64 → extractor errs →
    // routed unsigned (never keyed).
    let malformed_keyed = br#"{"verificationMaterial":{"publicKey":{"hint":"x"}},"dsseEnvelope":{"payload":"!!nob64!!","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"AA=="}]}}"#.to_vec();
    let b2 = build_bundle(malformed_keyed);
    assert_eq!(
        b2.signature, None,
        "an unparseable-as-keyed bundle is not routed to the keyed verifier"
    );
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
// window_open computation + threading (issue #13, Item 2 / design §2 S1/S4).
//
// `verify_artifact` computes
//   window_open = effective_quarantine_deadline(quarantine_window_start,
//                   resolved ScanPolicy.quarantineDuration) > now
// and threads it into `complete_provenance`. The default fixture policy
// (`quarantine_duration_secs: 0`) yields `window_open = false` (deadline ==
// anchor == now, and `now > now` is false), which is why every existing
// `Required + unsigned` test above still terminally rejects. These tests
// seed a POSITIVE duration so the window is open, and cover the
// missing-anchor + fetch-failure-stays-closed edges.
// ===========================================================================

/// Seed a `Required` policy for the fixture's repo whose quarantine window
/// is `duration_secs` wide (repo-scoped). Build the fixture with `mode:
/// None` so this is the ONLY active policy (no duplicate repo-scoped rows).
fn seed_required_policy_with_duration(f: &Fixture, duration_secs: i64) {
    let mut p = projection(
        PolicyScope::Repository(f.repository_id),
        ProvenanceMode::Required,
        vec![sample_pattern()],
    );
    p.quarantine_duration_secs = duration_secs;
    f.projections.insert(p);
}

// ---------------------------------------------------------------------------
// Required + unsigned + observation window STILL OPEN → HELD.
// `complete_provenance` returns Ok(None); no event is appended; the artifact
// stays `Quarantined` (the release gate reads it as Pending / held). This is
// the push-then-sign round-trip's core: an unsigned image is not rejected at
// the first verify while it may yet be signed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn required_unsigned_window_open_holds_pending_no_event() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None, // no default policy — seed the positive-duration one below
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // A wide window (24h) with the fixture's fresh `quarantine_window_start`
    // (= now) ⇒ deadline is far in the future ⇒ window_open = true.
    seed_required_policy_with_duration(&f, 24 * 3600);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::HeldPendingSignature,
        },
        "Required + unsigned mid-window must HOLD (no event) as HeldPendingSignature, not reject \
         and not conflated with the allowed-unsigned NoAttestation no-op",
    );
    // The verifier ran (with zero bundles — genuinely unsigned).
    assert_eq!(port.last_inputs(), Some((0, ARTIFACT_PAYLOAD.len())));
    // Status is UNCHANGED — held Quarantined, not Rejected.
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Quarantined,
        "an unsigned Required artifact holds Quarantined while the window is open",
    );
    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "the hold path appends NO provenance verdict event",
    );
}

// ---------------------------------------------------------------------------
// Required + unsigned + observation window CLOSED → terminal Rejected{Unsigned}.
// A zero-width window (anchor == deadline == now, `now > now` is false) makes
// window_open = false, so `complete_provenance` maps NoAttestation to the
// terminal rejection. This is the window-closed terminal branch reached via
// the app-computed window_open (distinct from the always-closed default
// fixture: here the policy IS Required with an explicit anchor).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn required_unsigned_window_closed_rejects_unsigned() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None,
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // A zero-width window: deadline == anchor == now ⇒ `now > now` == false ⇒
    // window_open = false ⇒ terminal rejection at this verify.
    seed_required_policy_with_duration(&f, 0);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::Unsigned),
        },
        "Required + unsigned + window closed must terminally reject Unsigned",
    );
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
// Issue #115 defect (b) — referenced-tree descendants HOLD on
// NoAttestation × Required, even with the window closed.
//
// The defect: OCI pull-through writes `oci_config`/`oci_layer` edges before
// the blobs are pulled, so each layer ingests as a ZERO-WINDOW descendant
// (#46: anchor = ingested_at − duration ⇒ window_open == false immediately).
// Under `Required`, the ingest-enqueued verify found no bundle for the layer
// digest (cosign signs only the top-level digest) and terminally rejected it
// as `Unsigned` — BEFORE the subject's cascade could clear it. The cascade
// then refuses the rejected constituent ("terminal is terminal"), so a
// correctly-signed image became permanently unpullable.
// ===========================================================================

/// Seed an `oci_layer` content-reference edge making the fixture's subject
/// artifact a referenced-tree descendant of some other artifact — the exact
/// shape the OCI pull-through edge writer produces for a manifest's layer
/// blob before the blob itself is pulled.
fn seed_descendant_edge(f: &Fixture) {
    futures::executor::block_on(async {
        f.content_references
            .insert(ContentReference {
                source_artifact_id: Uuid::new_v4(), // the parent manifest
                target_content_hash: f.content_hash.clone(),
                kind: "oci_layer".to_string(),
                metadata: serde_json::Value::Null,
                repository_id: f.repository_id,
                recorded_at: chrono::Utc::now(),
            })
            .await
            .expect("seed descendant content-reference edge");
    });
}

/// **The regression test for #115 defect (b).** Identical setup to
/// `required_unsigned_window_closed_rejects_unsigned` above (zero-width
/// window ⇒ `window_open == false`) except the artifact carries an
/// `oci_layer` edge making it a referenced-tree descendant. It must HOLD as
/// `HeldPendingSignature` instead of terminally rejecting, so the parent's
/// later cascade can still clear it.
#[tokio::test]
async fn required_unsigned_window_closed_descendant_holds_instead_of_rejecting() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None,
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    seed_required_policy_with_duration(&f, 0); // window CLOSED
    seed_descendant_edge(&f); // …but it IS a descendant

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: false,
            verdict: ProvenanceVerdictSummary::HeldPendingSignature,
        },
        "a zero-window referenced-tree descendant must HOLD (issue #115 defect (b)), \
         not terminally reject as Unsigned — and must report the existing \
         HeldPendingSignature summary, not the allowed-unsigned NoAttestation no-op",
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Quarantined,
        "held descendant stays Quarantined so the parent's cascade can clear it",
    );
    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "the descendant hold appends NO provenance verdict event",
    );
}

/// The carve-out is scoped to the unsigned arm: a descendant whose
/// signature is genuinely BAD still rejects terminally. A blanket
/// "descendants are never rejected" would let a tampered layer through.
#[tokio::test]
async fn required_descendant_with_bad_signature_still_rejects() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None,
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    seed_required_policy_with_duration(&f, 24 * 3600); // even mid-window
    seed_descendant_edge(&f);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::UntrustedIdentity),
        },
        "a BAD signature on a descendant is position-independent and still terminal",
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
}

/// **Error-direction regression (the load-bearing half).** A
/// `content_references` lookup failure at VERDICT time must PROPAGATE —
/// the job fails, the dispatcher retries, and the artifact stays
/// `Quarantined`. Degrading to `false` (the correct default at INGEST,
/// where it means "keep the full window") would here mean "no descendant
/// hold" and fall straight into the terminal `Rejected{Unsigned}` arm,
/// turning a transient read error into an unrecoverable rejection of a
/// legitimately-signed image's layer.
#[tokio::test]
async fn verdict_time_descendant_lookup_failure_propagates_and_applies_no_verdict() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None,
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // Window CLOSED — so a degrade-to-`false` bug would terminally reject.
    seed_required_policy_with_duration(&f, 0);
    f.content_references
        .fail_next_find_by_target(DomainError::Invariant("content_references down".into()));

    let err =
        f.uc.verify_artifact(f.artifact_id)
            .await
            .expect_err("a verdict-time descendant-lookup failure must propagate, not degrade");
    assert!(
        format!("{err}").contains("content_references down"),
        "the underlying lookup error must surface verbatim: {err}"
    );

    // The load-bearing assertions: NO verdict was applied.
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Quarantined,
        "a propagated lookup failure must leave the artifact Quarantined — \
         never terminally rejected on a read error",
    );
    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "no provenance verdict event may be appended when the lookup failed",
    );
}

// ---------------------------------------------------------------------------
// Required + unsigned + MISSING quarantine_window_start on an ALREADY
// `Quarantined` artifact → window_open = false (defensive-only branch,
// design §2 S1/S4). `Quarantined` status with a `None` anchor is an
// anomalous/corrupted shape — `Artifact::quarantine` always sets both
// together — not the issue #90 TOCTOU symptom (which shows `None` status;
// see `required_unsigned_none_status_*` below, the bounded-requeue
// defense-in-depth). This anomalous shape must still resolve
// fail-closed-safely to a CLOSED window (terminal reject) rather than HOLD
// indefinitely — the `commit_provenance_verdict` bounded-requeue guard only
// engages for `QuarantineStatus::None`, so it is inert here. Even with a
// wide (24h) configured duration, the absent anchor ⇒ no window ⇒ reject.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn required_unsigned_missing_window_start_resolves_closed_and_rejects() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None,
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // A WIDE window would hold IF an anchor were present — prove the missing
    // anchor (not the duration) forces the closed/terminal resolution.
    seed_required_policy_with_duration(&f, 24 * 3600);
    // Overwrite the fixture artifact with a NULL quarantine anchor.
    let mut artifact = f.artifacts.get(f.artifact_id).unwrap();
    artifact.quarantine_window_start = None;
    f.artifacts.insert(artifact);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::Unsigned),
        },
        "a missing quarantine_window_start resolves window_open=false → terminal reject \
         (a defensive/mis-ordered run must not hold indefinitely)",
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1);
    let DomainEvent::ProvenanceRejected(ev) = &transitions[0].1.events[0].event else {
        panic!("expected ProvenanceRejected");
    };
    assert_eq!(ev.reason, ProvenanceRejectReason::Unsigned);
}

// ---------------------------------------------------------------------------
// issue #90 — bounded requeue defense-in-depth. Required + unsigned + a
// `None`-status, anchor-less, RECENTLY-INGESTED artifact must NOT resolve
// terminally: this is the exact shape a job racing the (now-atomic)
// ingest+quarantine commit would have observed pre-fix. Past the grace
// window the SAME shape (permissive `quarantine_duration_secs == 0`, which
// never quarantines — a legitimate permanent `None`-status steady state)
// still resolves to the pre-existing terminal behavior.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn required_unsigned_none_status_young_artifact_requeues_instead_of_rejecting() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None,
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    seed_required_policy_with_duration(&f, 24 * 3600);
    // None status, no anchor, created just now — exactly the TOCTOU shape.
    let mut artifact = f.artifacts.get(f.artifact_id).unwrap();
    artifact.quarantine_status = QuarantineStatus::None;
    artifact.quarantine_window_start = None;
    artifact.created_at = chrono::Utc::now();
    f.artifacts.insert(artifact);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::RequeuedNoAnchor,
        "a None-status, anchor-less, recently-ingested artifact must requeue, not terminally \
         reject — it may be mid-transition to Quarantined",
    );

    // No verdict was applied: no event committed, no state transition.
    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "the bounded-requeue guard must short-circuit before any commit"
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::None,
        "status must be untouched by the requeue"
    );
}

#[tokio::test]
async fn required_unsigned_none_status_old_artifact_past_grace_still_rejects() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None,
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    seed_required_policy_with_duration(&f, 24 * 3600);
    // Same None-status/no-anchor shape, but ingested well outside the grace
    // window — the steady-state permissive-policy case, not a transient
    // race. Must fall through to the pre-existing terminal resolution.
    let mut artifact = f.artifacts.get(f.artifact_id).unwrap();
    artifact.quarantine_status = QuarantineStatus::None;
    artifact.quarantine_window_start = None;
    artifact.created_at = chrono::Utc::now() - chrono::Duration::hours(1);
    f.artifacts.insert(artifact);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::Unsigned),
        },
        "past the grace window the None-status/no-anchor shape resolves terminally, exactly as \
         it did before issue #90 (a permissive-policy artifact never gets an anchor)",
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1);
    let DomainEvent::ProvenanceRejected(ev) = &transitions[0].1.events[0].event else {
        panic!("expected ProvenanceRejected");
    };
    assert_eq!(ev.reason, ProvenanceRejectReason::Unsigned);
}

// The bounded-requeue guard is scoped to `NoAttestation` ONLY — a forged
// signature on a young, `None`-status artifact must still reject
// IMMEDIATELY, not get a free pass via requeue. Proves the guard cannot be
// used to stall out a genuine bad-signature rejection.
#[tokio::test]
async fn required_young_none_status_forged_signature_still_rejects_immediately() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None,
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    seed_required_policy_with_duration(&f, 24 * 3600);
    seed_bundle(&f, b"forged-bundle-bytes");
    // Same young/None-status/no-anchor shape as the requeue test above —
    // the only difference is the verifier's verdict.
    let mut artifact = f.artifacts.get(f.artifact_id).unwrap();
    artifact.quarantine_status = QuarantineStatus::None;
    artifact.quarantine_window_start = None;
    artifact.created_at = chrono::Utc::now();
    f.artifacts.insert(artifact);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::UntrustedIdentity),
        },
        "a forged/untrusted signature must reject immediately — the requeue guard only ever \
         applies to NoAttestation, never to a Rejected verdict",
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Rejected);
}

// ---------------------------------------------------------------------------
// issue #90 facet 2, AMENDED BY issue #108 (H2b) — a provenance-verdict
// commit built from a stale in-memory `Artifact` snapshot must not clobber
// EITHER the anchor a concurrently-committed transition wrote (#90) NOR the
// `quarantine_status` that transition wrote (#108).
//
// **This test previously asserted the opposite of what it asserts now, and
// the flip is the point.** As written for #90 it ended with "the verdict's
// own status change must land" — i.e. it CODIFIED the status clobber as the
// contract, protecting only `quarantine_window_start`. #90 scoped the write
// to the status column, which hardened every OTHER column against the stale
// snapshot but left the security-load-bearing one written unconditionally
// from it. The scenario is now oriented the way the real defect runs: the
// CONCURRENT writer commits `Rejected` (a scan verdict), and the stale
// provenance verdict resolves `Verified` — which leaves the status
// `Quarantined`, exactly equal to what it loaded. Under the skip-unchanged
// rule that is no status write at all, so the concurrent `Rejected`
// survives. Pre-#108 the same commit wrote `Quarantined` back over
// `Rejected`, resurrecting a rejected artifact into a timer-releasable
// state. The #90 anchor-survival assertion is kept verbatim alongside it.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provenance_verdict_commit_does_not_clobber_concurrently_written_status_or_anchor() {
    let f = build(RepositoryFormat::Oci, None, vec![], vec![]);

    // A STALE in-memory snapshot — as if `verify_artifact` loaded the
    // artifact BEFORE the concurrent scan verdict below landed:
    // `Quarantined`, no anchor yet.
    let mut stale = f.artifacts.get(f.artifact_id).unwrap();
    stale.quarantine_status = QuarantineStatus::Quarantined;
    stale.quarantine_window_start = None;
    // What the verify path loaded — the guard the conditional write keys on.
    let prior_status = stale.quarantine_status;

    // The concurrent scan verdict commits `Rejected` AND sets the anchor —
    // AFTER the stale snapshot above was captured.
    let anchor = chrono::Utc::now();
    let mut current = f.artifacts.get(f.artifact_id).unwrap();
    current.quarantine_status = QuarantineStatus::Rejected;
    current.quarantine_window_start = Some(anchor);
    f.artifacts.insert(current);

    // The (stale) provenance verdict now commits `Verified`. Per
    // `Artifact::complete_provenance`'s `Verified` arm the status is left
    // untouched — still `Quarantined` on the stale snapshot, i.e. EQUAL to
    // `prior_status`.
    let event = DomainEvent::ProvenanceVerified(hort_domain::events::ProvenanceVerified {
        artifact_id: f.artifact_id,
        content_hash: f.content_hash.clone(),
        backend: "cosign".to_string(),
        signer: sample_identity(),
        predicate_type: None,
        cascaded_from: None,
    });
    f.lifecycle
        .commit_provenance_verdict(
            &stale,
            AppendEvents {
                stream_id: StreamId::artifact(f.artifact_id),
                expected_version: ExpectedVersion::Any,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: system_actor(),
            },
            prior_status,
        )
        .await
        .expect("commit_provenance_verdict");

    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Rejected,
        "issue #108: the concurrently-committed Rejected must SURVIVE — a Verified verdict \
         leaves the status unchanged from what it loaded, so it must write no status at all. \
         Reverting it to Quarantined here is the resurrect-then-timer-release defect."
    );
    assert_eq!(
        saved.quarantine_window_start,
        Some(anchor),
        "the concurrently-committed anchor must survive — a column-scoped verdict commit must \
         not clobber it with the stale snapshot's None"
    );
}

// ---------------------------------------------------------------------------
// issue #108 H2b, the OTHER arm — when the verdict DOES change the status
// (a genuine `Rejected` decision, not the skip-unchanged `Verified` case)
// and the persisted row has meanwhile moved off the loaded status, the
// conditional write must fail `Conflict` rather than overwrite. This is the
// defense-in-depth backstop behind the event-store OCC: it fires even on a
// path whose append did not conflict (here, `ExpectedVersion::Any`).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provenance_verdict_commit_conflicts_when_status_moved_under_it() {
    let f = build(RepositoryFormat::Oci, None, vec![], vec![]);

    let mut stale = f.artifacts.get(f.artifact_id).unwrap();
    stale.quarantine_status = QuarantineStatus::Quarantined;
    let prior_status = stale.quarantine_status;

    // Concurrent writer moves the row off `prior_status`.
    let mut current = f.artifacts.get(f.artifact_id).unwrap();
    current.quarantine_status = QuarantineStatus::Released;
    f.artifacts.insert(current);

    // The stale verdict decides `Rejected` — a real status CHANGE, so
    // skip-unchanged does not apply and the conditional write is reached.
    stale.quarantine_status = QuarantineStatus::Rejected;
    let event = DomainEvent::ProvenanceRejected(hort_domain::events::ProvenanceRejected {
        artifact_id: f.artifact_id,
        content_hash: f.content_hash.clone(),
        backend: "(policy)".to_string(),
        reason: ProvenanceRejectReason::Unsigned,
    });
    let err = f
        .lifecycle
        .commit_provenance_verdict(
            &stale,
            AppendEvents {
                stream_id: StreamId::artifact(f.artifact_id),
                expected_version: ExpectedVersion::Any,
                events: vec![EventToAppend::new(event)],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: system_actor(),
            },
            prior_status,
        )
        .await
        .expect_err("a status that moved under the verdict must Conflict, not be overwritten");
    assert!(
        matches!(err, DomainError::Conflict(_)),
        "expected Conflict (distinct from NotFound, which stays reserved for an absent id); \
         got {err:?}"
    );
    assert_eq!(
        f.artifacts.get(f.artifact_id).unwrap().quarantine_status,
        QuarantineStatus::Released,
        "the concurrent writer's status must be left exactly as it was"
    );
}

// ---------------------------------------------------------------------------
// issue #108 Item 4 — true-concurrency interleave regression pin.
//
// The two #90-lineage tests above (flipped by Item 1) call
// `commit_provenance_verdict` DIRECTLY with a hand-built "stale" `Artifact`
// and `ExpectedVersion::Any` — they never drive `verify_artifact`'s own
// early-version-read code, and `ExpectedVersion::Any` means no OCC check is
// even attempted. This test is the composed end-to-end proof: it drives the
// REAL `verify_artifact` entry point (issue #108's actual production code
// path, including Item 1's early `read_expected_version` call and #115
// Item 3's descendant resolution — nothing here is hand-rolled), and injects
// a concurrent scan-verdict commit exactly inside the H2a race window: after
// `verify_artifact`'s own artifact load + early version read (both happen
// at the very top of the function, before any bundle-fetch/verify round
// trip), but before its own `commit_provenance_verdict` call at the end.
//
// The injection point is the `ProvenancePort::verify()` call itself —
// `verify_artifact` awaits it well inside the H2a window (after the load +
// early read, before the commit), so a verifier stub that performs the
// "concurrent write" as a side effect of answering the verify request lands
// it at exactly the right point in the REAL control flow, with no manual
// pausing/resuming of `verify_artifact` and no direct call to any of its
// private helper methods.
//
// **Documented mock limitation (per the directive's explicit fallback
// clause):** `MockArtifactLifecycle::commit_provenance_verdict` does not
// consult `self.event_store` for `expected_version` validation at all —
// unlike `commit_scan_result_with_score`, which CAN be wired to a shared
// `MockEventStore` via `with_scan_result_paired_mocks` and genuinely
// `append`s through it, `commit_provenance_verdict`'s test double only ever
// records into `self.transitions` / `self.artifacts`, so it can never
// observe an event-store version conflict regardless of what
// `expected_version` the real early-read computed. Item 1's event-store OCC
// (layer 1) therefore cannot be exercised end-to-end through this mock; the
// event-store-backed Postgres adapter tests already added in Item 1
// (`save_verdict_status_in_tx_conflicts_when_prior_status_changed` and
// siblings, run live against a real Postgres in that item's report) are
// what actually proves layer 1 works. This test instead pins the STRONGEST
// property reachable through `verify_artifact`'s real control flow: layer 2
// (skip-unchanged). The interleaved verdict here is `Verified` — per
// `Artifact::complete_provenance`'s `Verified` arm (ADR 0007: "a Verified
// outcome does not release the artifact early"), the domain transition
// leaves `quarantine_status` unchanged from what `verify_artifact` loaded,
// so `prior_status == artifact.quarantine_status` always holds and the
// status-column write is skipped ENTIRELY — not merely refused via a
// conditional-write Conflict (layer 3). This is precisely the ORIGINAL H2
// defect shape from the design doc's own Context section ("a signed image
// that also trips a scan policy resurrects Rejected -> Quarantined") — the
// composed proof the directive asks for.
/// Test-only `ProvenancePort` whose `verify()` call injects the concurrent
/// scan-rejection commit as a side effect of answering the verify request —
/// see the regression pin below for why this lands the write genuinely
/// inside `verify_artifact`'s real H2a race window (after its load + early
/// version read, before its own commit), with no manual pausing of the
/// function under test and no direct call to any of its private helpers.
struct InterleavingProvenancePort {
    artifacts: Arc<MockArtifactRepository>,
    events: Arc<MockEventStore>,
    artifact_id: Uuid,
}

impl ProvenancePort for InterleavingProvenancePort {
    fn name(&self) -> &str {
        "cosign"
    }

    fn applies_to(&self, format: &str) -> bool {
        format == "oci"
    }

    fn verify<'a>(
        &'a self,
        _subject: &'a ProvenanceSubject<'a>,
        _bundles: &'a [AttestationBundle],
        _requirements: &'a ProvenanceRequirements<'a>,
    ) -> BoxFuture<'a, DomainResult<ProvenanceVerdict>> {
        Box::pin(async move {
            // The concurrent writer's own load-modify-commit, via the SAME
            // real domain transition `record_scan_result`'s reject branch
            // uses — landing here, squarely inside `verify_artifact`'s
            // window between its early version read (already executed by
            // the time this runs) and its eventual `commit_provenance_verdict`
            // call (not yet run).
            let mut concurrent = self
                .artifacts
                .get(self.artifact_id)
                .expect("artifact seeded before verify_artifact was called");
            concurrent
                .reject_from_scan("critical severity finding".into())
                .expect("Quarantined -> Rejected is a valid domain transition");
            self.artifacts.insert(concurrent);

            // The matching stream tail a real `record_scan_result` reject
            // commit appends: ScanCompleted (dirty, first in the batch)
            // then ArtifactRejected — the exact shape issue #108 H3 (Item
            // 3) reads to deny release authority.
            let stream_id = StreamId::artifact(self.artifact_id);
            let quarantined = dummy_persisted_event(&stream_id, self.artifact_id, 0);
            let scan_completed = PersistedEvent {
                event_id: Uuid::new_v4(),
                stream_id: stream_id.clone(),
                stream_position: 1,
                global_position: 2,
                event: DomainEvent::ScanCompleted(hort_domain::events::ScanCompleted {
                    artifact_id: self.artifact_id,
                    scanner: "trivy".into(),
                    finding_count: 1,
                    severity_summary: hort_domain::events::SeveritySummary {
                        critical: 1,
                        high: 0,
                        medium: 0,
                        low: 0,
                        negligible: 0,
                    },
                    findings_blob: Some("f".repeat(64).parse().unwrap()),
                }),
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: system_actor(),
                event_version: 1,
                stored_at: chrono::Utc::now(),
            };
            let rejected = PersistedEvent {
                event_id: Uuid::new_v4(),
                stream_id: stream_id.clone(),
                stream_position: 2,
                global_position: 3,
                event: DomainEvent::ArtifactRejected(hort_domain::events::ArtifactRejected {
                    artifact_id: self.artifact_id,
                    rejected_by: hort_domain::events::RejectionReason::Scanner,
                    reason: "critical severity finding".into(),
                }),
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: system_actor(),
                event_version: 1,
                stored_at: chrono::Utc::now(),
            };
            self.events
                .set_stream(&stream_id, vec![quarantined, scan_completed, rejected]);

            Ok(ProvenanceVerdict::verified(sample_identity(), None))
        })
    }

    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn verify_artifact_interleaved_with_concurrent_reject_does_not_resurrect_and_stays_unreleasable(
) {
    // Hand-built fixture (not `build()`/`build_with_payload()`): the
    // interleaving port needs `Arc` handles to `artifacts` + `events`
    // BEFORE the use case exists, and `build()` constructs both internally.
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
    repo.format = RepositoryFormat::Oci;
    let repository_id = repo.id;
    repositories.insert(repo);

    let payload = b"{\"schemaVersion\":2,\"manifest\":true}".to_vec();
    let content_hash: ContentHash = format!("{:x}", sha2::Sha256::digest(&payload))
        .parse()
        .expect("valid sha256");
    let mut artifact: Artifact = sample_artifact(QuarantineStatus::Quarantined);
    artifact.repository_id = repository_id;
    artifact.sha256_checksum = content_hash.clone();
    let artifact_id = artifact.id;
    artifacts.insert(artifact);
    storage.insert_content(content_hash, payload);

    // `VerifyIfPresent`, deliberately NOT `Required`: verification is
    // still ATTEMPTED either way (`dispatch_and_fold` calls every
    // applicable port regardless of mode — only `complete_provenance`'s
    // INTERPRETATION of the verdict is mode-dependent), so this does not
    // weaken assertion (a) at all. It matters for assertion (b): under
    // `Required`, `resolve_provenance_clearance` independently resolves
    // `Pending` whenever no REAL `ProvenanceVerified` event exists on the
    // stream (ADR 0027) — and the mock `commit_provenance_verdict` never
    // actually appends one to `events` (documented above), so a `Required`
    // policy would deny release via the UNRELATED provenance gate
    // regardless of whether Item 3's scan-authority fix works at all,
    // confounding assertion (b). `VerifyIfPresent` resolves provenance
    // clearance to `NotRequired` (never gates release), isolating (b) to
    // exactly the scan-authority derivation issue #108 Item 3 fixed.
    let mut policy = projection(
        PolicyScope::Repository(repository_id),
        ProvenanceMode::VerifyIfPresent,
        vec![sample_pattern()],
    );
    policy.scan_backends = vec!["trivy".to_string()];
    projections.insert(policy);

    // The artifact's OWN stream, as if freshly ingested — the state
    // `verify_artifact`'s early version read observes BEFORE the
    // interleave. `dummy_persisted_event` also seeds `f.artifacts`-style
    // realism: a real ingest always has SOME event at position 0.
    let stream_id = StreamId::artifact(artifact_id);
    events.set_stream(
        &stream_id,
        vec![dummy_persisted_event(&stream_id, artifact_id, 0)],
    );

    let interleaving_port: Arc<dyn ProvenancePort> = Arc::new(InterleavingProvenancePort {
        artifacts: artifacts.clone(),
        events: events.clone(),
        artifact_id,
    });

    let uc = ProvenanceOrchestrationUseCase::new(
        artifacts.clone(),
        repositories,
        projections.clone(),
        content_references,
        storage,
        lifecycle,
        crate::event_store_publisher::wrap_for_test(events.clone()),
        vec![interleaving_port],
        upstream_proxy,
        upstream_resolver,
    );

    let outcome = uc
        .verify_artifact(artifact_id)
        .await
        .expect("verify_artifact must not itself error");
    assert!(
        matches!(
            outcome,
            ProvenanceRunOutcome::Applied {
                verdict: ProvenanceVerdictSummary::Verified,
                ..
            }
        ),
        "the (stale) verdict is Verified — the interleave targets the commit's status \
         write, not the verify dispatch itself; got {outcome:?}"
    );

    // (a) The final persisted status is the concurrently-committed
    // Rejected — the provenance commit's stale Verified-from-Quarantined
    // snapshot did NOT resurrect it.
    assert_eq!(
        artifacts.get(artifact_id).unwrap().quarantine_status,
        QuarantineStatus::Rejected,
        "issue #108: a signed subject's provenance commit, racing a concurrent scan \
         rejection, must never resurrect Rejected back to Quarantined"
    );

    // (b) Not timer-releasable afterward — drives the REAL
    // `QuarantineUseCase::release_expired`, sharing the SAME `artifacts` +
    // `events` state this test just produced.
    //
    // **Verified by deliberately breaking each layer in isolation** (not
    // left in the committed test — done by hand while writing this pin):
    // reverting Item 1 alone makes assertion (a) fail (the status
    // resurrects to `Quarantined`, exactly the pre-#108 defect). Reverting
    // Item 3 alone (presence-only `resolve_release_authority`) does NOT
    // make assertion (b) fail here — `released` stays empty regardless,
    // because by the time `release_expired` runs, Item 1 has already left
    // the persisted status at `Rejected`, and `Artifact::release`'s OWN
    // pre-existing domain guard (`crates/hort-domain/src/entities/
    // artifact.rs`, `source_state_ok`) refuses release from any status
    // other than `Quarantined`/`ScanIndeterminate` — a SEPARATE,
    // pre-#108 protection that also happens to cover this exact scenario.
    // This is expected, not a gap: Item 3 was scoped as defense-in-depth
    // for exactly the case "H2 is somehow still broken" (its own
    // directive's framing) — in the scenario where H2 (Item 1) DOES hold,
    // as it does here, Item 3's own independent contribution is
    // legitimately redundant with the domain guard. Item 3's
    // INDEPENDENTLY-isolated proof (the authority predicate denying while
    // the candidate's PROJECTED status is still `Quarantined`, matching
    // its own threat model) already lives in
    // `quarantine_use_case.rs`'s `release_expired_denies_release_when_latest_scan_is_dirty`
    // / `_when_clean_scan_followed_by_later_reject` — not duplicated
    // here. This test's assertion (b) is the honest composed-stack
    // property: after a real interleave, NOTHING in the stack (Item 1,
    // Item 3, or the domain guard, whichever ends up load-bearing) lets
    // the artifact through.
    let quarantine_repositories = Arc::new(MockRepositoryRepository::new());
    let mut quarantine_repo = sample_repository();
    quarantine_repo.id = repository_id;
    quarantine_repositories.insert(quarantine_repo);
    let quarantine_uc = QuarantineUseCase::new(
        artifacts.clone(),
        crate::event_store_publisher::wrap_for_test(events.clone()),
        Arc::new(MockArtifactLifecycle::new(artifacts.clone())),
        quarantine_repositories,
        projections,
        Arc::new(MockContentReferenceIndex::new()),
        Arc::new(MockStoragePort::new()),
        Arc::new(MockJobsRepository::new()),
    );
    let released = quarantine_uc
        .release_expired(vec![artifact_id])
        .await
        .expect("release_expired must not itself error");
    assert!(
        released.is_empty(),
        "issue #108 Item 3: the artifact must NOT be timer-releasable — its latest \
         ScanCompleted is dirty, so resolve_release_authority must deny; got {released:?}"
    );
}

// ---------------------------------------------------------------------------
// Required + bundle-fetch EXHAUSTED + window STILL OPEN → STILL fail-closed
// Rejected{RekorNotFound}. A fetch failure is NOT an unsigned-hold: it
// produces a `Rejected` verdict, and `complete_provenance`'s `Rejected` arm
// never consults window_open. Threading window_open=true through
// `apply_fetch_failure` must NOT weaken the Required fail-closed guarantee
// (design §2 S1: only NoAttestation×Required×window-open holds).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn required_fetch_failure_stays_fail_closed_even_with_window_open() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None,
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // A WIDE OPEN window (24h) — proves the fetch-failure fail-closed path is
    // NOT gated by window_open (an unsigned HOLD would be Ok(None); this must
    // still terminally reject).
    seed_required_policy_with_duration(&f, 24 * 3600);
    // Force the bundle fetch to exhaust: a content-reference to a nonexistent
    // source artifact → find_by_id NotFound on every retry.
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

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::RekorNotFound),
        },
        "a Required fetch failure stays fail-closed (RekorNotFound) even mid-window — \
         window_open gates only NoAttestation, never a Rejected verdict",
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Rejected,
        "the fetch-failure fail-closed guarantee is not weakened by an open window",
    );
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1);
    let DomainEvent::ProvenanceRejected(ev) = &transitions[0].1.events[0].event else {
        panic!("expected ProvenanceRejected");
    };
    assert_eq!(ev.reason, ProvenanceRejectReason::RekorNotFound);
    assert!(
        port.last_inputs().is_none(),
        "the fetch failed before the verifier ran",
    );
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

/// Issue #13 / Item 5: the S1 hold path — Required + unsigned + observation
/// window OPEN — ticks the DISTINCT `held_pending_signature` result value
/// (an image *waiting to be signed*), NOT `no_attestation` (which is strictly
/// the allowed-unsigned no-op) and NOT `rejected`. No reject-counter tick (no
/// verdict event is appended on a hold).
#[test]
fn metric_held_pending_signature_fires_on_required_window_open_hold() {
    let snap = capture_provenance_metrics(|| {
        Box::pin(async {
            let port = Arc::new(MockProvenancePort::cosign_returning(
                ProvenanceVerdict::no_attestation(),
            ));
            let f = build(
                RepositoryFormat::Oci,
                None, // seed the positive-duration Required policy below
                vec![],
                vec![port as Arc<dyn ProvenancePort>],
            );
            // Wide window (24h) + the fixture's fresh quarantine anchor (= now)
            // ⇒ window_open = true ⇒ an unsigned Required artifact is HELD.
            seed_required_policy_with_duration(&f, 24 * 3600);
            f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
        })
    });
    assert_eq!(
        counter_with_labels(
            &snap,
            "hort_provenance_verify_total",
            &[("backend", "cosign"), ("mode", "required"), ("result", "held_pending_signature")],
        ),
        Some(1),
        "Required + unsigned mid-window must tick hort_provenance_verify_total{{...,result=held_pending_signature}}",
    );
    // The hold path must NOT tick `no_attestation` (that is the allowed-unsigned
    // no-op) nor `rejected` (no verdict is decided while held).
    assert_eq!(
        counter_with_labels(
            &snap,
            "hort_provenance_verify_total",
            &[
                ("backend", "cosign"),
                ("mode", "required"),
                ("result", "no_attestation")
            ],
        ),
        None,
        "a Required hold must NOT be conflated with the allowed-unsigned no_attestation count",
    );
    assert!(
        snap.iter()
            .all(|(k, _)| k.key().name() != "hort_provenance_reject_total"),
        "a held (no-verdict) artifact must not emit hort_provenance_reject_total",
    );
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
        None,
        "a held artifact is not rejected — no rejected tick",
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

/// The real committed cosign **v3 KEYED** Sigstore v0.3 bundle
/// (`hort-adapters-provenance-cosign-key/tests/fixtures/`) — produced by
/// `cosign v3 sign --key --registry-referrers-mode=oci-1-1`. A DSSE envelope
/// over an in-toto Statement, `verificationMaterial.publicKey` (no Fulcio
/// cert), so the keyed carriage routes it SIGNED to the keyed verifier
/// (ADR 0039 §8, issue #14).
const KEYED_V03_BUNDLE_FIXTURE: &str = include_str!(
    "../../../hort-adapters-provenance-cosign-key/tests/fixtures/keyed_v03_bundle.json"
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

/// The cosign v3 keyed carriage (ADR 0039 §8, issue #14): a keyed Sigstore
/// v0.3 bundle referrer (bundle blob, `verificationMaterial.publicKey`, DSSE
/// envelope) reaches the keyed verifier as a **SIGNED** bundle carrying the raw
/// DSSE signature — NOT dropped as an unsigned bundle. This is the exact defect:
/// pre-fix the carriage wrapped it `new` (signature None) so the keyed verifier
/// skipped it → NoAttestation → Rejected{Unsigned}.
#[tokio::test]
async fn fetch_bundles_routes_keyed_v03_bundle_to_the_keyed_verifier_signed() {
    let port = Arc::new(CapturingSignaturePort::new());
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    // The real cosign v3 keyed v0.3 bundle (committed fixture).
    let bundle_bytes = KEYED_V03_BUNDLE_FIXTURE.as_bytes();
    seed_manifest_and_bundle(&f, bundle_bytes);

    f.uc.verify_artifact(f.artifact_id).await.expect("Ok");

    let captured = port.captured();
    assert_eq!(
        captured.len(),
        1,
        "the keyed v0.3 bundle is collected as one bundle"
    );
    let (bytes, signature) = &captured[0];
    assert_eq!(
        bytes.as_slice(),
        bundle_bytes,
        "bundle.bytes is the v0.3 bundle blob (the keyed verifier re-derives the DSSE PAE from it)"
    );
    // The signature carried is the raw DSSE signature extracted from the bundle.
    let expected_sig = hort_domain::provenance_bundle::extract_keyed_dsse_signature(bundle_bytes)
        .expect("fixture parses")
        .expect("fixture is keyed")
        .signature;
    assert_eq!(
        signature.as_deref(),
        Some(expected_sig.as_slice()),
        "a keyed v0.3 bundle reaches the keyed verifier SIGNED (was dropped as unsigned before issue #14)"
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

// ===========================================================================
// Item 4 (issue #15) — an image-INDEX subject rides the generic provenance
// path. Design §2 D4: the index carries no runnable bytes, so it rides the
// issue-#13 provenance hold + re-verify-on-signature unchanged. cosign signs
// the INDEX digest → the `oci_subject.subject.digest` = index digest → the
// existing verify path targets the index artifact by hash, shape-agnostically.
//
// These reuse the provenance-orchestration harness verbatim; the only change
// is that the SIGNED subject's CAS bytes are an image-index body (so its
// content hash — the `oci_subject` target — is the index digest).
// ===========================================================================

/// A minimal OCI image-index body carrying one child platform descriptor.
/// `is_image_index` (Item 1) is `true` for it; the provenance path never
/// parses `manifests[]`, so any well-formed index body exercises the same
/// generic verify-by-hash path.
fn index_subject_payload() -> Vec<u8> {
    let body = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size": 528,
                "platform": { "architecture": "amd64", "os": "linux" }
            }
        ]
    })
    .to_string()
    .into_bytes();
    // Guard: a fixture that degenerated into a single-image manifest would
    // make "the index rides the generic path" vacuous.
    assert!(
        hort_domain::oci::is_image_index(&body),
        "the Item-4 provenance subject fixture must be an image index"
    );
    body
}

/// (c) Required + verified signature TARGETING THE INDEX DIGEST → the index
/// is CLEARED (a `ProvenanceVerified` clearance event is recorded). This is
/// the push-then-sign payoff: cosign signed the index digest, the
/// `oci_subject` referrer targets the index's content hash, and the verifier
/// was handed the INDEX CAS preimage. Status stays `Quarantined` here — a
/// `Verified` under `Required` records clearance and the generic timer/scan
/// release path (quarantine_use_case `release_expired`, exercised separately)
/// then reads the recorded clearance and releases; the provenance use case
/// itself never releases early (mirrors the single-image
/// `required_verified_records_clearance_event_status_unchanged`).
#[tokio::test]
async fn item4_required_verified_index_records_clearance_targeting_index_digest() {
    let payload = index_subject_payload();
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
        &payload,
    );
    // The `oci_subject` referrer targets `f.content_hash` = sha256(index).
    seed_bundle(&f, b"valid-index-signature-bundle");

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Verified,
        },
        "a verified signature on the index digest must record a clearance"
    );

    // The verifier ran against the INDEX CAS preimage (one bundle + the
    // index body), proving the subject that was verified is the index.
    assert_eq!(
        port.last_inputs(),
        Some((1, payload.len())),
        "the verifier must receive the fetched bundle and the INDEX CAS preimage"
    );

    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Quarantined,
        "clearance is recorded — the generic release path releases later, not the verifier"
    );
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1);
    assert!(
        matches!(
            &transitions[0].1.events[0].event,
            DomainEvent::ProvenanceVerified(_)
        ),
        "a ProvenanceVerified clearance event must be appended for the signed index"
    );
}

/// (c) Companion / negative: Required + UNSIGNED index (no bundle) rejects
/// `Unsigned`, exactly like a single-image manifest under `Required`. Proves
/// the index rides the same fail-closed `Required` gate — it is not silently
/// exempted from provenance because of its shape.
#[tokio::test]
async fn item4_required_unsigned_index_rejects_unsigned() {
    let payload = index_subject_payload();
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
        &payload,
    );
    // No bundle seeded → the verifier is handed zero bundles.

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::Unsigned),
        },
    );
    assert_eq!(
        port.last_inputs(),
        Some((0, payload.len())),
        "the verifier ran against the INDEX preimage with zero bundles"
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Rejected,
        "an unsigned Required index rejects — no shape-based exemption from the provenance gate"
    );
}

// ===========================================================================
// Provenance-clearance cascade (ADR 0039 cascade, issue #14).
//
// A `Verified` verdict under `Required` cascades the subject's clearance to
// the constituents the verified CAS bytes bind: an index's `manifests[]`
// children (each digest is inside the signed index bytes) and, per manifest,
// its `config`/`layers` digests (inside the manifest's bytes) — a Merkle-like
// chain, so the signature over the root digest covers exactly this set. The
// cascade is repo-scoped, held-(`Quarantined`)-only, idempotent, best-effort
// (never blocks the subject's own committed clearance), and clears ONLY the
// provenance authority — scan + window gates stay per-artifact.
// ===========================================================================

use hort_domain::events::{system_actor as cascade_system_actor, PersistedEvent, StreamId};

/// A distinct, valid sha256 built from a repeating hex char. The mock repos
/// never verify bytes↔hash for seeded rows, so any 64-hex string works.
fn hexhash(c: char) -> ContentHash {
    std::iter::repeat_n(c, 64)
        .collect::<String>()
        .parse()
        .expect("valid sha256")
}

/// Seed a `Quarantined` artifact with `hash` in `repo`; returns its id.
fn seed_held_artifact(f: &Fixture, repo: Uuid, hash: &ContentHash) -> Uuid {
    let mut a: Artifact = sample_artifact(QuarantineStatus::Quarantined);
    a.repository_id = repo;
    a.sha256_checksum = hash.clone();
    let id = a.id;
    f.artifacts.insert(a);
    id
}

/// A single-image manifest body referencing `config` + `layers`.
fn image_manifest_body(config: &ContentHash, layers: &[&ContentHash]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": format!("sha256:{config}"),
            "size": 7,
        },
        "layers": layers
            .iter()
            .map(|l| serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{l}"),
                "size": 42,
            }))
            .collect::<Vec<_>>(),
    }))
    .expect("manifest json")
}

/// An image-index body whose `manifests[]` children are `children`.
fn image_index_body(children: &[&ContentHash]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE,
        "manifests": children
            .iter()
            .map(|c| serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{c}"),
                "size": 528,
                "platform": { "architecture": "amd64", "os": "linux" },
            }))
            .collect::<Vec<_>>(),
    }))
    .expect("index json")
}

/// A persisted `ProvenanceVerified` for seeding a constituent's stream
/// (`cascaded_from` parameterized: `Some` models an earlier cascade, `None`
/// a direct verification — the skip logic treats both as cleared).
fn persisted_verified(artifact_id: Uuid, cascaded_from: Option<ContentHash>) -> PersistedEvent {
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: StreamId::artifact(artifact_id),
        stream_position: 0,
        global_position: 0,
        event: DomainEvent::ProvenanceVerified(hort_domain::events::ProvenanceVerified {
            artifact_id,
            content_hash: hexhash('9'),
            backend: "cosign".into(),
            signer: sample_identity(),
            predicate_type: None,
            cascaded_from,
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: cascade_system_actor(),
        event_version: 1,
        stored_at: chrono::Utc::now(),
    }
}

/// A persisted non-provenance event (`ArtifactIngested`) for seeding a
/// constituent's stream — exercises the clearance read's "other event"
/// arm (not a `ProvenanceVerified` ⇒ not cleared) and gives the cascade
/// append a real `Exact` position to race against.
fn persisted_ingested(artifact_id: Uuid, hash: &ContentHash) -> PersistedEvent {
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: StreamId::artifact(artifact_id),
        stream_position: 0,
        global_position: 0,
        event: DomainEvent::ArtifactIngested(ArtifactIngested {
            artifact_id,
            repository_id: Uuid::new_v4(),
            name: "pkg".into(),
            version: None,
            sha256: hash.clone(),
            size_bytes: 1,
            source: IngestSource::Proxied,
            metadata: serde_json::Value::Null,
            metadata_blob: None,
            upstream_published_at: None,
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: cascade_system_actor(),
        event_version: 1,
        stored_at: chrono::Utc::now(),
    }
}

/// Collect `(artifact_id, event)` for every cascaded `ProvenanceVerified`
/// (`cascaded_from: Some(_)`) the lifecycle committed.
fn cascaded_events(f: &Fixture) -> Vec<(Uuid, hort_domain::events::ProvenanceVerified)> {
    f.lifecycle
        .committed_transitions()
        .iter()
        .filter_map(|(artifact, batch, _)| match &batch.events[0].event {
            DomainEvent::ProvenanceVerified(e) if e.cascaded_from.is_some() => {
                Some((artifact.id, e.clone()))
            }
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Verified INDEX → children + their config/layer blobs cascade, attributed;
// a digest with no artifact row is skipped; an artifact outside the signed
// tree (same repo, different digest) is untouched; a blob shared across
// children is cleared exactly once (dedupe).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_verified_index_clears_children_and_their_blobs_with_attribution() {
    let (config_a, layer_a) = (hexhash('a'), hexhash('b'));
    let config_b = hexhash('c');
    let shared_layer = hexhash('d'); // referenced by BOTH children
    let ghost = hexhash('e'); // in child2's manifest, NO artifact row
    let child1 = hexhash('1');
    let child2 = hexhash('2');

    let payload = image_index_body(&[&child1, &child2]);
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
        &payload,
    );
    seed_bundle(&f, b"valid-index-signature-bundle");

    // The child manifests' CAS bytes — the source of the blob digests.
    f.storage.insert_content(
        child1.clone(),
        image_manifest_body(&config_a, &[&layer_a, &shared_layer]),
    );
    f.storage.insert_content(
        child2.clone(),
        image_manifest_body(&config_b, &[&shared_layer, &ghost]),
    );

    // Held constituents in the SUBJECT's repo.
    let expected: Vec<(&ContentHash, Uuid)> = vec![
        (&child1, seed_held_artifact(&f, f.repository_id, &child1)),
        (
            &config_a,
            seed_held_artifact(&f, f.repository_id, &config_a),
        ),
        (&layer_a, seed_held_artifact(&f, f.repository_id, &layer_a)),
        (
            &shared_layer,
            seed_held_artifact(&f, f.repository_id, &shared_layer),
        ),
        (&child2, seed_held_artifact(&f, f.repository_id, &child2)),
        (
            &config_b,
            seed_held_artifact(&f, f.repository_id, &config_b),
        ),
    ];
    // Same repo + same name, but a digest NOT bound by the signed bytes —
    // must never be cleared (the name-keyed group model is NOT the source).
    let outside_tree = hexhash('f');
    seed_held_artifact(&f, f.repository_id, &outside_tree);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Verified,
        },
    );

    let transitions = f.lifecycle.committed_transitions();
    // 1 subject clearance + 6 cascaded constituents (ghost skipped — no
    // artifact row; outside_tree untouched; shared_layer once).
    assert_eq!(
        transitions.len(),
        7,
        "expected the subject + exactly the 6 signed-tree constituents"
    );
    // The subject's own event is a DIRECT verification (no attribution).
    let DomainEvent::ProvenanceVerified(subject_ev) = &transitions[0].1.events[0].event else {
        panic!("first transition must be the subject's ProvenanceVerified");
    };
    assert_eq!(subject_ev.cascaded_from, None);

    let cascaded = cascaded_events(&f);
    assert_eq!(cascaded.len(), 6);
    for (hash, id) in &expected {
        let (_, ev) = cascaded
            .iter()
            .find(|(aid, _)| aid == id)
            .unwrap_or_else(|| panic!("constituent {hash} was not cascaded"));
        assert_eq!(ev.artifact_id, *id);
        assert_eq!(
            &ev.content_hash, *hash,
            "event records the constituent's own hash"
        );
        assert_eq!(
            ev.cascaded_from.as_ref(),
            Some(&f.content_hash),
            "attribution: cleared via the signature over the ROOT (index) digest"
        );
        assert_eq!(
            ev.signer,
            sample_identity(),
            "the subject's verified signer rides along"
        );
        assert_eq!(ev.backend, "cosign");
        // Only the provenance authority cascades — the constituent stays
        // HELD (its own scan + window gates release it later).
        let saved = f.artifacts.get(*id).unwrap();
        assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
    }
    // The shared blob was cleared exactly once (dedupe across children).
    assert_eq!(
        cascaded
            .iter()
            .filter(|(_, e)| e.content_hash == shared_layer)
            .count(),
        1,
    );
    // Nothing outside the signed tree was touched.
    assert!(
        !cascaded.iter().any(|(_, e)| e.content_hash == outside_tree),
        "an artifact whose digest is not bound by the signed bytes must not be cleared"
    );
    assert!(
        !cascaded.iter().any(|(_, e)| e.content_hash == ghost),
        "a digest with no artifact row cascades nothing"
    );
}

// ---------------------------------------------------------------------------
// Verified SINGLE-IMAGE manifest → its own config + layers cascade.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_verified_single_image_manifest_clears_config_and_layers() {
    let (config, layer_a, layer_b) = (hexhash('a'), hexhash('b'), hexhash('c'));
    let payload = image_manifest_body(&config, &[&layer_a, &layer_b]);
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
        &payload,
    );
    seed_bundle(&f, b"valid-manifest-signature-bundle");
    for h in [&config, &layer_a, &layer_b] {
        seed_held_artifact(&f, f.repository_id, h);
    }

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert!(matches!(
        outcome,
        ProvenanceRunOutcome::Applied {
            verdict: ProvenanceVerdictSummary::Verified,
            ..
        }
    ));
    let cascaded = cascaded_events(&f);
    assert_eq!(
        cascaded.len(),
        3,
        "config + both layers of the signed manifest are cleared"
    );
    for h in [&config, &layer_a, &layer_b] {
        assert!(
            cascaded
                .iter()
                .any(|(_, e)| &e.content_hash == h
                    && e.cascaded_from.as_ref() == Some(&f.content_hash)),
            "constituent {h} must carry the root-digest attribution"
        );
    }
}

// ---------------------------------------------------------------------------
// issue #108 H2c — `commit_cascade_event` must not clobber a concurrently-
// written column on the constituent's stream, the same class of defect
// Item 1 closed on the two primary verdict paths. The cascade's
// `ProvenanceVerified` always leaves `quarantine_status` unchanged
// (`Artifact::cascade_provenance_clearance` takes `&self`), so
// skip-unchanged means the routed-through `commit_provenance_verdict` call
// makes NO status-column write at all — proven here by calling
// `commit_cascade_event` directly (mirrors
// `provenance_verdict_commit_does_not_clobber_concurrently_written_status_or_anchor`'s
// stale-vs-concurrent construction) with a STALE constituent snapshot while
// a "concurrently committed" DIFFERENT snapshot sits in the mock's queryable
// projection. Pre-#108 (full-row `commit_transition`) the stale snapshot's
// columns would have overwritten the concurrent write; post-#108 the
// cascaded event still appends but the concurrent write survives untouched.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_commit_does_not_clobber_concurrently_written_anchor() {
    let f = build(RepositoryFormat::Oci, None, vec![], vec![]);
    let subject_hash = f.content_hash.clone();
    let config = hexhash('a');

    // A STALE constituent snapshot — as if `cascade_one` had loaded it
    // BEFORE a concurrent transition (e.g. the constituent's own ingest
    // finishing its quarantine stamp) landed: no anchor yet.
    let mut stale = sample_artifact(QuarantineStatus::Quarantined);
    stale.repository_id = f.repository_id;
    stale.sha256_checksum = config.clone();
    stale.quarantine_window_start = None;
    let constituent_id = stale.id;

    // The event `cascade_provenance_clearance` would produce for this
    // constituent — built from the SAME stale snapshot (its identity/hash
    // never changes), matching what `cascade_one` passes to
    // `commit_cascade_event`.
    let event = stale
        .cascade_provenance_clearance(subject_hash.clone(), sample_identity(), None, "cosign-key")
        .expect("Quarantined constituent takes the cascaded clearance");

    // The concurrent transition commits, setting the anchor — AFTER the
    // stale snapshot above was captured.
    let anchor = chrono::Utc::now();
    let mut current = stale.clone();
    current.quarantine_window_start = Some(anchor);
    f.artifacts.insert(current);

    f.uc.commit_cascade_event(&stale, event, ExpectedVersion::Any)
        .await
        .expect("commit_cascade_event");

    let cascaded = cascaded_events(&f);
    assert_eq!(
        cascaded.len(),
        1,
        "the cascaded ProvenanceVerified must still append"
    );
    assert_eq!(cascaded[0].0, constituent_id);

    let saved = f.artifacts.get(constituent_id).unwrap();
    assert_eq!(
        saved.quarantine_window_start,
        Some(anchor),
        "issue #108 H2c: the concurrently-committed anchor must survive — commit_cascade_event \
         must not clobber it with the stale snapshot's None. Routing through the full-row \
         commit_transition (the pre-fix shape) is exactly the regression this pins."
    );
}

// ---------------------------------------------------------------------------
// Terminal is terminal: an already-rejected constituent is NOT resurrected.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_never_resurrects_a_terminally_rejected_constituent() {
    let child = hexhash('1');
    let payload = image_index_body(&[&child]);
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
        &payload,
    );
    seed_bundle(&f, b"valid-bundle");

    let mut rejected: Artifact = sample_artifact(QuarantineStatus::Rejected);
    rejected.repository_id = f.repository_id;
    rejected.sha256_checksum = child.clone();
    let rejected_id = rejected.id;
    f.artifacts.insert(rejected);
    // No child-manifest bytes needed: the status guard skips before blobs
    // matter (and a CAS miss is warn-and-continue anyway).

    f.uc.verify_artifact(f.artifact_id).await.expect("Ok");

    assert!(
        cascaded_events(&f).is_empty(),
        "a terminally rejected constituent takes no cascaded clearance"
    );
    let saved = f.artifacts.get(rejected_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Rejected,
        "the operator re-pushes; the cascade never resurrects"
    );
}

// ---------------------------------------------------------------------------
// Repo scoping: the same digest held in ANOTHER repo is never touched.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_is_repo_scoped_same_digest_in_another_repo_untouched() {
    let child = hexhash('1');
    let payload = image_index_body(&[&child]);
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
        &payload,
    );
    seed_bundle(&f, b"valid-bundle");

    // Same digest, DIFFERENT repository — outside the cascade's authority.
    let other_repo = Uuid::new_v4();
    let foreign_id = seed_held_artifact(&f, other_repo, &child);

    f.uc.verify_artifact(f.artifact_id).await.expect("Ok");

    assert!(
        cascaded_events(&f).is_empty(),
        "the cascade must never cross repositories"
    );
    let saved = f.artifacts.get(foreign_id).unwrap();
    assert_eq!(saved.quarantine_status, QuarantineStatus::Quarantined);
}

// ---------------------------------------------------------------------------
// Unparseable subject bytes: cascade to NOTHING; the subject's own committed
// clearance stands (warn + continue, never an error path).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_unparseable_subject_bytes_skips_cascade_subject_still_clears() {
    let payload = b"not an oci manifest at all";
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
        payload,
    );
    seed_bundle(&f, b"valid-bundle");

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Verified,
        },
        "an unparseable subject must still clear — the cascade is best-effort"
    );
    let transitions = f.lifecycle.committed_transitions();
    assert_eq!(transitions.len(), 1, "subject clearance only; no cascade");
    assert!(cascaded_events(&f).is_empty());
}

// ---------------------------------------------------------------------------
// A child manifest whose CAS bytes are missing / unparseable: the CHILD
// itself still cascades (its digest is bound into the signed index bytes);
// only its config/layer blobs are skipped.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_child_manifest_cas_read_failure_still_clears_the_child() {
    let child = hexhash('1');
    let payload = image_index_body(&[&child]);
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
        &payload,
    );
    seed_bundle(&f, b"valid-bundle");
    let child_id = seed_held_artifact(&f, f.repository_id, &child);
    // Deliberately NO storage content for `child` — the CAS read fails.

    f.uc.verify_artifact(f.artifact_id).await.expect("Ok");

    let cascaded = cascaded_events(&f);
    assert_eq!(
        cascaded.len(),
        1,
        "the child itself is still in the signed tree"
    );
    assert_eq!(cascaded[0].0, child_id);
}

#[tokio::test]
async fn cascade_child_manifest_unparseable_still_clears_the_child() {
    let child = hexhash('1');
    let payload = image_index_body(&[&child]);
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
        &payload,
    );
    seed_bundle(&f, b"valid-bundle");
    let child_id = seed_held_artifact(&f, f.repository_id, &child);
    f.storage
        .insert_content(child.clone(), b"garbage, not a manifest".to_vec());

    f.uc.verify_artifact(f.artifact_id).await.expect("Ok");

    let cascaded = cascaded_events(&f);
    assert_eq!(cascaded.len(), 1);
    assert_eq!(cascaded[0].0, child_id);
}

// ---------------------------------------------------------------------------
// Idempotency: a constituent already carrying a ProvenanceVerified (its own
// verification or an earlier cascade) is not double-cleared.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_skips_already_cleared_constituent() {
    let child = hexhash('1');
    let payload = image_index_body(&[&child]);
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
        &payload,
    );
    seed_bundle(&f, b"valid-bundle");
    let child_id = seed_held_artifact(&f, f.repository_id, &child);
    f.events.set_stream(
        &StreamId::artifact(child_id),
        vec![persisted_verified(child_id, Some(hexhash('8')))],
    );

    f.uc.verify_artifact(f.artifact_id).await.expect("Ok");

    assert!(
        cascaded_events(&f).is_empty(),
        "an already-cleared constituent takes no duplicate clearance event"
    );
}

// ---------------------------------------------------------------------------
// Mode scoping: under VerifyIfPresent nothing has a pending provenance gate,
// so a Verified subject cascades nothing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_under_verify_if_present_does_not_fire() {
    let (config, layer) = (hexhash('a'), hexhash('b'));
    let payload = image_manifest_body(&config, &[&layer]);
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::VerifyIfPresent),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
        &payload,
    );
    seed_bundle(&f, b"valid-bundle");
    for h in [&config, &layer] {
        seed_held_artifact(&f, f.repository_id, h);
    }

    f.uc.verify_artifact(f.artifact_id).await.expect("Ok");

    assert_eq!(
        f.lifecycle.committed_transitions().len(),
        1,
        "VerifyIfPresent records the subject's success only — no cascade"
    );
    assert!(cascaded_events(&f).is_empty());
}

// ---------------------------------------------------------------------------
// Already-cleared verify skip (the cascade's no-re-reject half). A cleared
// artifact — most importantly a cascade-cleared constituent whose S4 expiry
// backstop verify was enqueued while it was still Pending — is a no-op:
// without the skip, the window-closed re-verify would find no bundle (a
// constituent has no referrer surface of its own) and terminally reject a
// cleared artifact as Unsigned.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn already_cleared_required_subject_skips_verify_entirely() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    f.events.set_stream(
        &StreamId::artifact(f.artifact_id),
        vec![persisted_verified(f.artifact_id, None)],
    );

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(outcome, ProvenanceRunOutcome::SkippedAlreadyCleared);
    assert!(
        port.last_inputs().is_none(),
        "no verifier runs for an already-cleared artifact"
    );
    assert!(f.lifecycle.committed_transitions().is_empty());
}

#[tokio::test]
async fn cascade_cleared_constituent_expiry_verify_is_noop_not_rereject() {
    // The acceptance pin: a cascade-cleared constituent (stream carries an
    // attributed ProvenanceVerified) whose FINAL verify runs at window
    // close (`quarantine_duration_secs: 0` ⇒ window_open = false) must NOT
    // be re-judged into Rejected{Unsigned} — the exact mirror of
    // `required_unsigned_window_closed_rejects_unsigned`, flipped by the
    // pre-existing clearance.
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::no_attestation(),
    ));
    let f = build(
        RepositoryFormat::Oci,
        None,
        vec![],
        vec![port.clone() as Arc<dyn ProvenancePort>],
    );
    seed_required_policy_with_duration(&f, 0); // window CLOSED
    f.events.set_stream(
        &StreamId::artifact(f.artifact_id),
        vec![persisted_verified(f.artifact_id, Some(hexhash('7')))],
    );

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::SkippedAlreadyCleared,
        "a cleared constituent's expiry-time verify is a no-op, never a re-reject"
    );
    let saved = f.artifacts.get(f.artifact_id).unwrap();
    assert_eq!(
        saved.quarantine_status,
        QuarantineStatus::Quarantined,
        "still held for the release sweep (which reads the clearance), not Rejected"
    );
    assert!(f.lifecycle.committed_transitions().is_empty());
}

// ---------------------------------------------------------------------------
// Best-effort continuation: a per-constituent commit failure is warn+skip;
// the remaining constituents still cascade. (Direct call — the failure is
// injected on the FIRST post-subject commit.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_commit_failure_warns_and_continues_with_remaining() {
    let (config, layer) = (hexhash('a'), hexhash('b'));
    let payload = image_manifest_body(&config, &[&layer]);
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![],
    );
    seed_held_artifact(&f, f.repository_id, &config);
    let layer_id = seed_held_artifact(&f, f.repository_id, &layer);

    // The first constituent's commit fails; the loop must continue.
    f.lifecycle
        .fail_next_commit(DomainError::Invariant("injected commit failure".into()));

    f.uc.cascade_clearance(
        f.repository_id,
        &f.content_hash,
        &payload,
        &sample_identity(),
        None,
        "cosign-key",
    )
    .await;

    let cascaded = cascaded_events(&f);
    assert_eq!(
        cascaded.len(),
        1,
        "the failed constituent is skipped; the next still cascades"
    );
    assert_eq!(cascaded[0].0, layer_id);
    assert_eq!(cascaded[0].1.backend, "cosign-key");
}

// ---------------------------------------------------------------------------
// Cascade liveness: a version conflict on the constituent append (its own
// ScanCompleted landing between the read and the append — scan and sign both
// land seconds after push) is retried ONCE with a fresh read; a second
// conflict falls back to warn+skip; a ProvenanceVerified that appeared
// between the reads makes the retry a no-op (idempotency re-check).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_version_conflict_retries_once_and_lands() {
    let (config, layer) = (hexhash('a'), hexhash('b'));
    let payload = image_manifest_body(&config, &[&layer]);
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![],
    );
    let config_id = seed_held_artifact(&f, f.repository_id, &config);
    let layer_id = seed_held_artifact(&f, f.repository_id, &layer);
    // A non-provenance event on the constituent's stream: not cleared
    // (the clearance read skips it), and the append races against a real
    // `Exact` position.
    f.events.set_stream(
        &StreamId::artifact(config_id),
        vec![persisted_ingested(config_id, &config)],
    );

    // The first constituent's first append loses a version race.
    f.lifecycle
        .fail_next_commit(DomainError::Conflict("stream moved".into()));

    f.uc.cascade_clearance(
        f.repository_id,
        &f.content_hash,
        &payload,
        &sample_identity(),
        None,
        "cosign-key",
    )
    .await;

    let cascaded = cascaded_events(&f);
    assert_eq!(
        cascaded.len(),
        2,
        "the conflicted append retries once with a fresh read and lands"
    );
    assert!(cascaded.iter().any(|(id, _)| *id == config_id));
    assert!(cascaded.iter().any(|(id, _)| *id == layer_id));
}

#[tokio::test]
async fn cascade_version_conflict_twice_warns_and_skips_remaining_still_cascade() {
    let (config, layer) = (hexhash('a'), hexhash('b'));
    let payload = image_manifest_body(&config, &[&layer]);
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![],
    );
    seed_held_artifact(&f, f.repository_id, &config);
    let layer_id = seed_held_artifact(&f, f.repository_id, &layer);

    // The first constituent conflicts on BOTH the append and the retry —
    // one retry only, then the existing warn+skip; the next constituent
    // still cascades.
    f.lifecycle
        .fail_next_commit(DomainError::Conflict("stream moved".into()));
    f.lifecycle
        .fail_next_commit(DomainError::Conflict("stream moved again".into()));

    f.uc.cascade_clearance(
        f.repository_id,
        &f.content_hash,
        &payload,
        &sample_identity(),
        None,
        "cosign-key",
    )
    .await;

    let cascaded = cascaded_events(&f);
    assert_eq!(
        cascaded.len(),
        1,
        "a second conflict is warn+skip — never a third attempt"
    );
    assert_eq!(cascaded[0].0, layer_id);
}

#[tokio::test]
async fn cascade_version_conflict_retry_observes_clearance_appeared_and_skips() {
    let (config, layer) = (hexhash('a'), hexhash('b'));
    let payload = image_manifest_body(&config, &[&layer]);
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![],
    );
    let config_id = seed_held_artifact(&f, f.repository_id, &config);
    // NO artifact row for `layer` — the only constituent in play is config.

    // The append conflicts, and the concurrent event that won the race WAS
    // a ProvenanceVerified (another cascade / its own verification): the
    // retry's fresh read observes it and skips — no duplicate append.
    f.lifecycle
        .fail_next_commit(DomainError::Conflict("stream moved".into()));
    f.events.set_stream_after_next_read(
        &StreamId::artifact(config_id),
        vec![persisted_verified(config_id, Some(hexhash('8')))],
    );

    f.uc.cascade_clearance(
        f.repository_id,
        &f.content_hash,
        &payload,
        &sample_identity(),
        None,
        "cosign-key",
    )
    .await;

    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "the retry re-checks idempotency — a clearance that appeared \
         between the reads takes no duplicate append"
    );
}

// ---------------------------------------------------------------------------
// Cascade re-drive on the already-cleared skip (ADR 0039 §11): a re-verify of
// a DIRECTLY cleared subject (cascaded_from: None — a re-sign's S3 enqueue,
// a duplicate verify) re-runs the idempotent cascade before skipping, healing
// a constituent whose cascaded append lost the version race. Gated: a
// CASCADED clearance never re-walks bytes (no CAS read); best-effort — a
// re-drive failure never changes the skip outcome.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn already_cleared_direct_subject_redrives_cascade_to_missed_constituents() {
    let (config, layer) = (hexhash('a'), hexhash('b'));
    let payload = image_manifest_body(&config, &[&layer]);
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port.clone() as Arc<dyn ProvenancePort>],
        &payload,
    );
    // The subject's stream carries a DIRECT clearance (its own earlier
    // verification); its constituents were missed (the original cascade
    // lost the race / crashed mid-loop) and are still held.
    f.events.set_stream(
        &StreamId::artifact(f.artifact_id),
        vec![persisted_verified(f.artifact_id, None)],
    );
    let config_id = seed_held_artifact(&f, f.repository_id, &config);
    let layer_id = seed_held_artifact(&f, f.repository_id, &layer);

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::SkippedAlreadyCleared,
        "the re-drive rides the skip path — the outcome is unchanged"
    );
    assert!(
        port.last_inputs().is_none(),
        "no verifier re-runs on the skip path"
    );

    let cascaded = cascaded_events(&f);
    assert_eq!(
        cascaded.len(),
        2,
        "the previously-missed constituents are cleared by the re-drive"
    );
    for (hash, id) in [(&config, config_id), (&layer, layer_id)] {
        let (_, ev) = cascaded
            .iter()
            .find(|(aid, _)| *aid == id)
            .unwrap_or_else(|| panic!("constituent {hash} was not re-driven"));
        assert_eq!(&ev.content_hash, hash);
        assert_eq!(
            ev.cascaded_from.as_ref(),
            Some(&f.content_hash),
            "attribution: cleared via the signature over the ROOT digest"
        );
        assert_eq!(
            ev.signer,
            sample_identity(),
            "the signer is recovered from the STORED ProvenanceVerified"
        );
        assert_eq!(ev.backend, "cosign");
    }
}

#[tokio::test]
async fn already_cleared_cascaded_constituent_never_redrives_no_cas_read() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
    );
    // A CASCADED clearance (cascaded_from: Some) — the artifact is a
    // constituent, not a signed subject.
    f.events.set_stream(
        &StreamId::artifact(f.artifact_id),
        vec![persisted_verified(f.artifact_id, Some(hexhash('8')))],
    );

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(outcome, ProvenanceRunOutcome::SkippedAlreadyCleared);
    assert_eq!(
        f.storage.get_call_count(),
        0,
        "a cascaded clearance's skip-verify must not re-walk CAS bytes — \
         constituent bytes cannot cascade and a child index must not recurse"
    );
    assert!(f.lifecycle.committed_transitions().is_empty());
}

#[tokio::test]
async fn already_cleared_redrive_cas_read_failure_keeps_skip_outcome() {
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
    );
    f.events.set_stream(
        &StreamId::artifact(f.artifact_id),
        vec![persisted_verified(f.artifact_id, None)],
    );
    // The subject's CAS bytes are unreadable — the re-drive is
    // best-effort and must not disturb the skip.
    f.storage.fail_get_persistent(f.content_hash.clone());

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::SkippedAlreadyCleared,
        "a re-drive CAS failure never changes the already-cleared outcome"
    );
    assert!(f.lifecycle.committed_transitions().is_empty());
}

// ---------------------------------------------------------------------------
// Defensive self-reference guard: a constituent digest equal to the subject
// hash is never re-appended to the subject's stream.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_skips_a_self_referencing_digest() {
    let selfhash = hexhash('a');
    // A manifest whose config AND layer both claim the subject's own hash
    // (impossible in real content — a self-referential digest — but the
    // guard must hold for any bytes).
    let payload = image_manifest_body(&selfhash, &[&selfhash]);
    let f = build(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![],
    );
    seed_held_artifact(&f, f.repository_id, &selfhash);

    f.uc.cascade_clearance(
        f.repository_id,
        &selfhash, // subject == the referenced digest
        &payload,
        &sample_identity(),
        None,
        "cosign",
    )
    .await;

    assert!(
        f.lifecycle.committed_transitions().is_empty(),
        "the subject's own hash is never cascaded onto itself"
    );
}

// ---------------------------------------------------------------------------
// Bounded: an index declaring more children than the domain cap
// (MAX_INDEX_CHILDREN) parses as an index but its child extraction is
// REJECTED — the cascade degrades to nothing and the subject's clearance
// stands (same warn-and-continue arm as unparseable bytes).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cascade_over_cap_index_cascades_nothing_subject_still_clears() {
    // 1025 children — one over the domain's MAX_INDEX_CHILDREN (1024).
    let children: Vec<serde_json::Value> = (0..1025)
        .map(|i| serde_json::json!({ "digest": format!("sha256:{i:064x}") }))
        .collect();
    let payload = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE,
        "manifests": children,
    }))
    .expect("index json");
    let port = Arc::new(MockProvenancePort::cosign_returning(
        ProvenanceVerdict::verified(sample_identity(), None),
    ));
    let f = build_with_payload(
        RepositoryFormat::Oci,
        Some(ProvenanceMode::Required),
        vec![sample_pattern()],
        vec![port as Arc<dyn ProvenancePort>],
        &payload,
    );
    seed_bundle(&f, b"valid-bundle");

    let outcome = f.uc.verify_artifact(f.artifact_id).await.expect("Ok");
    assert_eq!(
        outcome,
        ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Verified,
        },
    );
    assert_eq!(
        f.lifecycle.committed_transitions().len(),
        1,
        "an over-cap index is refused by the parser — cascade to nothing, never truncation"
    );
    assert!(cascaded_events(&f).is_empty());
}
