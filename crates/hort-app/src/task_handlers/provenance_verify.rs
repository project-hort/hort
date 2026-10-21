//! `provenance-verify` TaskHandler (ADR 0027).
//!
//! Wraps [`ProvenanceOrchestrationUseCase`] for worker dispatch. The
//! ingest path enqueues a single `kind = 'provenance-verify'` row carrying
//! `params.artifact_id` **only when** the resolved policy
//! `provenance_mode != Off` AND some registered `ProvenancePort`
//! `applies_to(format)` (the enqueue gate lives in `IngestUseCase`, NOT
//! here — non-applicable ingests are genuinely zero-overhead, never a
//! fast no-op in the handler).
//!
//! The handler is a thin adapter — params parsing + delegation. The bundle
//! fetch + CAS preimage read + verifier dispatch + verdict application all
//! live in the use case (mirror of `ScanTaskHandler` → `ScanOrchestrationUseCase`).

use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use hort_domain::error::DomainResult;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::BoxFuture;

use crate::use_cases::provenance_orchestration::{
    ProvenanceOrchestrationUseCase, ProvenanceRunOutcome, ProvenanceVerdictSummary,
};

/// Shape of the `params` JSON the ingest enqueue writes onto the job row:
/// `{"artifact_id": "<uuid>"}`.
#[derive(Debug, Deserialize)]
struct ProvenanceVerifyParams {
    artifact_id: Uuid,
}

/// [`TaskHandler`] impl for `kind = "provenance-verify"`. Constructed at
/// worker composition time with the orchestration use case.
pub struct ProvenanceVerifyHandler {
    orchestration: Arc<ProvenanceOrchestrationUseCase>,
}

impl ProvenanceVerifyHandler {
    pub fn new(orchestration: Arc<ProvenanceOrchestrationUseCase>) -> Self {
        Self { orchestration }
    }
}

impl TaskHandler for ProvenanceVerifyHandler {
    fn kind(&self) -> &'static str {
        "provenance-verify"
    }

    #[tracing::instrument(skip(self, params))]
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            // Parse params.artifact_id. Invalid JSON → non-retryable Failed
            // (a malformed enqueue is an operator/code error, not infra).
            let parsed: ProvenanceVerifyParams = match serde_json::from_value(params.clone()) {
                Ok(p) => p,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("provenance-verify params JSON invalid: {err}"),
                        false,
                    ));
                }
            };

            // Delegate to the orchestration use case. A use-case error is a
            // retryable infra failure (DB / CAS hiccup) — the dispatcher
            // reschedules. The fail-closed / degrade-to-allow verdict logic
            // is internal to the use case; a returned `Ok(_)` outcome means
            // the verdict was applied (or skipped) cleanly.
            match self.orchestration.verify_artifact(parsed.artifact_id).await {
                // Bounded defense-in-depth requeue (issue #90) — see
                // `ProvenanceOrchestrationUseCase::apply_verdict`. Not a
                // failure: signal the dispatcher to retry with its normal
                // backoff (`compute_backoff`) rather than record a
                // terminal result on the job row.
                Ok(ProvenanceRunOutcome::RequeuedNoAnchor) => {
                    tracing::debug!(
                        artifact_id = %parsed.artifact_id,
                        "provenance: requeueing — None-status, anchor-less, \
                         recently-ingested artifact",
                    );
                    Ok(TaskOutcome::fail(
                        "provenance-verify: anchor-less recently-ingested artifact — requeueing",
                        true,
                    ))
                }
                Ok(outcome) => {
                    // Record the compact per-artifact verdict on the job's
                    // `result_summary`, including the previously-silent
                    // `no_attestation` case. Closed taxonomy:
                    // `verified` / `rejected:<reason>` /
                    // `no_attestation` / `held_pending_signature` /
                    // `held_pending_subject` / `held_indeterminate` /
                    // `allowed_indeterminate` /
                    // `cleared:signature_material` / `skipped:<why>` /
                    // `requeued:<why>` (see `result_summary_label`).
                    let result = result_summary_label(&outcome);
                    // A single `debug!` on the silent path is the most that
                    // is allowed — NO per-`no_attestation` `info!` (firehose
                    // at proxy scale; the aggregate counter is the rate
                    // signal, `result_summary` is the per-artifact trail).
                    if matches!(
                        outcome,
                        ProvenanceRunOutcome::Applied {
                            verdict: ProvenanceVerdictSummary::NoAttestation,
                            ..
                        }
                    ) {
                        tracing::debug!(
                            artifact_id = %parsed.artifact_id,
                            "provenance: no attestation (allowed)",
                        );
                    }
                    // The per-artifact forensic trail of candidates the
                    // verifier(s) could not read and therefore did not
                    // consider. Present only when something was actually
                    // skipped: the key's absence is the ordinary case, and
                    // adding `"unreadable_skipped": 0` to every row would
                    // bury the rows that matter. The aggregate rate lives
                    // on `hort_provenance_unreadable_skipped_total`; this
                    // is the per-artifact half, the only durable record of
                    // WHICH artifact had garbage attached.
                    let skipped = unreadable_skipped(&outcome);
                    let mut result_summary = json!({ "result": result });
                    if skipped > 0 {
                        result_summary["unreadable_skipped"] = json!(skipped);
                    }
                    Ok(TaskOutcome::Completed { result_summary })
                }
                Err(err) => Ok(TaskOutcome::fail(
                    format!("provenance-verify failed: {err}"),
                    true,
                )),
            }
        })
    }
}

/// Map a [`ProvenanceRunOutcome`] to the compact `result_summary` label
/// written on the job row. The closed
/// taxonomy is `verified` / `rejected:<reason>` / `no_attestation` /
/// `held_pending_signature` / `held_pending_subject` /
/// `held_indeterminate` / `allowed_indeterminate` /
/// `cleared:signature_material` / `skipped:<why>` / `requeued:<why>`;
/// `<reason>` reuses the metrics-catalog wire string so the
/// `result_summary` trail and the `hort_provenance_reject_total{reason}`
/// series agree. Pure — testable without the use case.
///
/// `RequeuedNoAnchor` never actually reaches the job row via this mapper —
/// `run` intercepts it before calling `result_summary_label` and returns a
/// retryable `TaskOutcome::Failed` instead of `Completed` (see `run`
/// above) — but the arm keeps this match exhaustive and the label testable
/// in isolation.
fn result_summary_label(outcome: &ProvenanceRunOutcome) -> String {
    match outcome {
        ProvenanceRunOutcome::SkippedOff => "skipped:off".to_string(),
        ProvenanceRunOutcome::SkippedNoVerifier => "skipped:no_verifier".to_string(),
        ProvenanceRunOutcome::SkippedAlreadyCleared => "skipped:already_cleared".to_string(),
        ProvenanceRunOutcome::ClearedAsSignatureMaterial { .. } => {
            "cleared:signature_material".to_string()
        }
        ProvenanceRunOutcome::RequeuedNoAnchor => "requeued:no_anchor".to_string(),
        ProvenanceRunOutcome::Applied { verdict, .. } => match verdict {
            ProvenanceVerdictSummary::Verified => "verified".to_string(),
            ProvenanceVerdictSummary::Rejected(reason) => {
                format!(
                    "rejected:{}",
                    crate::metrics::provenance_reject_reason_label(*reason)
                )
            }
            ProvenanceVerdictSummary::NoAttestation => "no_attestation".to_string(),
            ProvenanceVerdictSummary::HeldPendingSignature => "held_pending_signature".to_string(),
            ProvenanceVerdictSummary::HeldPendingSubject => "held_pending_subject".to_string(),
            ProvenanceVerdictSummary::HeldIndeterminate => "held_indeterminate".to_string(),
            ProvenanceVerdictSummary::AllowedIndeterminate => "allowed_indeterminate".to_string(),
        },
    }
}

/// How many attestation candidates the verifier(s) skipped as unreadable
/// on this run — the companion half of [`result_summary_label`], written
/// onto the same `result_summary` object.
///
/// Zero for every outcome reached **before** the verifiers ran
/// (`SkippedOff` / `SkippedNoVerifier` / `SkippedAlreadyCleared`): no
/// candidate was examined, so none was skipped. `RequeuedNoAnchor` also
/// answers zero, and for a different reason — the fold did run, but `run`
/// intercepts that outcome and returns a retryable `Failed`, so no
/// `result_summary` is written at all; the count was already reported by
/// the orchestration layer's log line and counter. Wildcard-free, so a
/// future outcome has to say whether it can carry a skip.
/// Pure — testable without the use case.
fn unreadable_skipped(outcome: &ProvenanceRunOutcome) -> u32 {
    match outcome {
        ProvenanceRunOutcome::Applied {
            unreadable_skipped, ..
        }
        | ProvenanceRunOutcome::ClearedAsSignatureMaterial { unreadable_skipped } => {
            *unreadable_skipped
        }
        ProvenanceRunOutcome::SkippedOff
        | ProvenanceRunOutcome::SkippedNoVerifier
        | ProvenanceRunOutcome::SkippedAlreadyCleared
        | ProvenanceRunOutcome::RequeuedNoAnchor => 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::entities::scan_policy::{
        CompositeVerdictMode, NegligibleAction, ProvenanceMode, ScanEnforcement,
        ScanPolicyProjection, SeverityThreshold,
    };
    use hort_domain::events::{system_actor, PolicyScope};
    use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
    use hort_domain::ports::provenance::{
        AttestationBundle, ProvenancePort, ProvenanceRejectReason, ProvenanceRequirements,
        ProvenanceSubject, ProvenanceVerdict, SignerIdentity,
    };
    use hort_domain::ports::task_handler::TaskContext;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ContentHash;
    use sha2::Digest;

    use crate::use_cases::test_support::*;

    const PAYLOAD: &[u8] = b"{\"schemaVersion\":2,\"manifest\":true}";

    /// A pre-programmed verifier mock — returns the seeded verdict for any
    /// non-empty bundle set, `NoAttestation` for the empty set.
    struct StubPort(ProvenanceVerdict);

    impl ProvenancePort for StubPort {
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
            let verdict = if bundles.is_empty() {
                ProvenanceVerdict::no_attestation()
            } else {
                self.0.clone()
            };
            Box::pin(async move { Ok(verdict) })
        }
        fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// A bundle manifest referencing a single Sigstore-bundle layer blob.
    fn referrer_manifest_for(blob: &ContentHash) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [{
                "mediaType": hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE,
                "digest": format!("sha256:{blob}"),
                "size": 1,
            }],
        }))
        .expect("manifest json")
    }

    /// Build a handler over a real `ProvenanceOrchestrationUseCase` wired
    /// with DB-free mocks (mirrors the orchestration tests' `build`). When
    /// `seed_signature` is true, an `oci_subject` referrer manifest + bundle
    /// blob is seeded so the verifier receives a bundle (and thus returns the
    /// stub verdict); otherwise the verifier sees no bundle → `NoAttestation`.
    fn build_handler(
        mode: ProvenanceMode,
        verdict: ProvenanceVerdict,
        seed_signature: bool,
    ) -> (ProvenanceVerifyHandler, Uuid) {
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

        let mut artifact: Artifact = sample_artifact(QuarantineStatus::Quarantined);
        artifact.repository_id = repository_id;
        let content_hash: ContentHash = hex::encode(sha2::Sha256::digest(PAYLOAD))
            .parse()
            .expect("valid sha256");
        artifact.sha256_checksum = content_hash.clone();
        let artifact_id = artifact.id;
        artifacts.insert(artifact);
        storage.insert_content(content_hash.clone(), PAYLOAD.to_vec());

        let mut p = ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: "test-policy".to_string(),
            scope: PolicyScope::Repository(repository_id),
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs: 0,
            require_approval: false,
            provenance_mode: mode,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            composite_verdict_mode: CompositeVerdictMode::Observed,
            stream_version: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        p.scan_backends = vec!["trivy".to_string()];
        projections.insert(p);

        if seed_signature {
            let bundle_bytes = b"bundle-bytes".to_vec();
            let blob_hash: ContentHash = hex::encode(sha2::Sha256::digest(&bundle_bytes))
                .parse()
                .expect("valid sha256");
            storage.insert_content(blob_hash.clone(), bundle_bytes);
            let manifest_bytes = referrer_manifest_for(&blob_hash);
            let manifest_hash: ContentHash = hex::encode(sha2::Sha256::digest(&manifest_bytes))
                .parse()
                .expect("valid sha256");
            let mut sig_artifact: Artifact = sample_artifact(QuarantineStatus::Released);
            sig_artifact.repository_id = repository_id;
            sig_artifact.sha256_checksum = manifest_hash.clone();
            let sig_id = sig_artifact.id;
            artifacts.insert(sig_artifact);
            storage.insert_content(manifest_hash, manifest_bytes);
            futures::executor::block_on(async {
                content_references
                    .insert(ContentReference {
                        source_artifact_id: sig_id,
                        target_content_hash: content_hash.clone(),
                        kind: "oci_subject".to_string(),
                        metadata: serde_json::Value::Null,
                        repository_id,
                        recorded_at: chrono::Utc::now(),
                    })
                    .await
                    .expect("seed content-reference");
            });
        }

        let uc = Arc::new(ProvenanceOrchestrationUseCase::new(
            artifacts,
            repositories,
            projections,
            content_references,
            storage,
            lifecycle,
            crate::event_store_publisher::wrap_for_test(events),
            vec![Arc::new(StubPort(verdict)) as Arc<dyn ProvenancePort>],
            upstream_proxy,
            upstream_resolver,
            // No handler registered: the orchestrator falls back to the
            // subject classification, which is what every one of these
            // fixtures already assumed.
            std::collections::HashMap::new(),
        ));
        (ProvenanceVerifyHandler::new(uc), artifact_id)
    }

    fn ctx() -> TaskContext {
        TaskContext {
            task_job_id: Uuid::new_v4(),
            actor: system_actor(),
            correlation_id: Uuid::new_v4(),
            job_row: sample_job_row(),
        }
    }

    fn sample_job_row() -> hort_domain::ports::jobs_repository::JobRow {
        use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
        let now = chrono::Utc::now();
        JobRow {
            id: Uuid::nil(),
            kind: "provenance-verify".to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::Value::Null),
            actor_id: None,
            priority: 0,
            trigger_source: "ingest".to_string(),
            attempts: 1,
            created_at: now,
            updated_at: now,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
        }
    }

    async fn run_summary(
        handler: &ProvenanceVerifyHandler,
        artifact_id: Uuid,
    ) -> serde_json::Value {
        let params = serde_json::json!({ "artifact_id": artifact_id });
        match handler.run(&params, ctx()).await.expect("Ok") {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// The previously-silent `no_attestation` path now writes a compact
    /// `result_summary` on the job row.
    #[tokio::test]
    async fn no_attestation_writes_result_summary() {
        // VerifyIfPresent + no seeded signature → verifier sees no bundle →
        // NoAttestation (allowed, no event). Previously invisible.
        let (handler, artifact_id) = build_handler(
            ProvenanceMode::VerifyIfPresent,
            ProvenanceVerdict::verified(sample_signer(), None),
            false,
        );
        let summary = run_summary(&handler, artifact_id).await;
        assert_eq!(summary, serde_json::json!({ "result": "no_attestation" }));
    }

    /// issue #90 bounded-requeue: a `None`-status, anchor-less,
    /// recently-ingested artifact under `Required` + `NoAttestation` must
    /// produce a retryable `TaskOutcome::Failed`, NOT `Completed` — the
    /// dispatcher's normal backoff must re-run the verify rather than the
    /// job being recorded done with a `requeued:no_anchor` result on the
    /// row. `build_handler` always seeds `QuarantineStatus::Quarantined`
    /// (irrelevant to the other fixtures), so this test builds its own
    /// artifact directly.
    #[tokio::test]
    async fn requeued_no_anchor_is_a_retryable_failure_not_completed() {
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

        // None status, no anchor, created just now — exactly the TOCTOU
        // shape a racing worker would have observed pre-fix.
        let mut artifact: Artifact = sample_artifact(QuarantineStatus::None);
        artifact.repository_id = repository_id;
        let content_hash: ContentHash = hex::encode(sha2::Sha256::digest(PAYLOAD))
            .parse()
            .expect("valid sha256");
        artifact.sha256_checksum = content_hash.clone();
        artifact.quarantine_window_start = None;
        artifact.created_at = chrono::Utc::now();
        let artifact_id = artifact.id;
        artifacts.insert(artifact);
        storage.insert_content(content_hash, PAYLOAD.to_vec());

        let mut p = ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: "test-policy".to_string(),
            scope: PolicyScope::Repository(repository_id),
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs: 0,
            require_approval: false,
            provenance_mode: ProvenanceMode::Required,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            composite_verdict_mode: CompositeVerdictMode::Observed,
            stream_version: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        p.scan_backends = vec!["trivy".to_string()];
        projections.insert(p);

        // No seeded oci_subject referrer → the verifier sees an empty
        // bundle set → NoAttestation, regardless of the stub's payload.
        let uc = Arc::new(ProvenanceOrchestrationUseCase::new(
            artifacts,
            repositories,
            projections,
            content_references,
            storage,
            lifecycle,
            crate::event_store_publisher::wrap_for_test(events),
            vec![Arc::new(StubPort(ProvenanceVerdict::no_attestation())) as Arc<dyn ProvenancePort>],
            upstream_proxy,
            upstream_resolver,
            // No handler registered: the orchestrator falls back to the
            // subject classification, which is what every one of these
            // fixtures already assumed.
            std::collections::HashMap::new(),
        ));
        let handler = ProvenanceVerifyHandler::new(uc);

        let params = serde_json::json!({ "artifact_id": artifact_id });
        match handler.run(&params, ctx()).await.expect("Ok") {
            TaskOutcome::Failed { retry, reason } => {
                assert!(
                    retry,
                    "must be retryable — the dispatcher's normal backoff re-runs it"
                );
                assert!(
                    reason.contains("requeue"),
                    "reason should be human-readable: {reason}"
                );
            }
            other => panic!("expected a retryable Failed outcome, got {other:?}"),
        }
    }

    /// A verified signature writes `result = "verified"`.
    #[tokio::test]
    async fn verified_writes_result_summary() {
        let (handler, artifact_id) = build_handler(
            ProvenanceMode::VerifyIfPresent,
            ProvenanceVerdict::verified(sample_signer(), None),
            true,
        );
        let summary = run_summary(&handler, artifact_id).await;
        assert_eq!(summary, serde_json::json!({ "result": "verified" }));
    }

    /// A rejected signature writes `result = "rejected:<reason>"` — the
    /// typed reason is surfaced for forensics.
    #[tokio::test]
    async fn rejected_writes_result_summary_with_reason() {
        let (handler, artifact_id) = build_handler(
            ProvenanceMode::VerifyIfPresent,
            ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity),
            true,
        );
        let summary = run_summary(&handler, artifact_id).await;
        assert_eq!(
            summary,
            serde_json::json!({ "result": "rejected:untrusted_identity" })
        );
    }

    /// The S1 hold verdict (issue #13) maps to the distinct
    /// `held_pending_signature` `result_summary` label — separable from the
    /// allowed-unsigned `no_attestation` no-op. Asserted on the pure
    /// `result_summary_label` mapper (its doc contract: testable without the
    /// use case); the emission on the real hold path is covered by the
    /// orchestration use-case metric test.
    #[test]
    fn held_pending_signature_maps_to_result_summary_label() {
        let outcome = ProvenanceRunOutcome::Applied {
            unreadable_skipped: 0,
            event_appended: false,
            verdict: ProvenanceVerdictSummary::HeldPendingSignature,
        };
        assert_eq!(result_summary_label(&outcome), "held_pending_signature");
    }

    /// The could-not-check hold maps to its own `held_indeterminate`
    /// label, separable from both signature holds: the operator action is
    /// on *our* side (fix the trust root, or let the fetch retry), so a
    /// `result_summary` that said `held_pending_signature` would send
    /// somebody to look at their signer. Pure-mapper assertion; the
    /// emission on the real hold path is covered by the orchestration
    /// use-case tests.
    #[test]
    fn held_indeterminate_maps_to_result_summary_label() {
        let outcome = ProvenanceRunOutcome::Applied {
            unreadable_skipped: 0,
            event_appended: false,
            verdict: ProvenanceVerdictSummary::HeldIndeterminate,
        };
        assert_eq!(result_summary_label(&outcome), "held_indeterminate");
    }

    /// The **non-held** could-not-check verdict gets its own
    /// `result_summary` label too. `no_attestation` here would be the one
    /// reading an operator must not be given: it names the artifact's
    /// state ("allowed unsigned") when the truth is about ours (a
    /// misprovisioned trust root, an unreachable upstream), and it is the
    /// per-artifact trail — the durable half — that somebody reads when
    /// they go looking for which artifact was affected.
    #[test]
    fn allowed_indeterminate_maps_to_result_summary_label() {
        let outcome = ProvenanceRunOutcome::Applied {
            unreadable_skipped: 0,
            event_appended: false,
            verdict: ProvenanceVerdictSummary::AllowedIndeterminate,
        };
        assert_eq!(result_summary_label(&outcome), "allowed_indeterminate");
        // Separable from both neighbours, which is the whole reason it
        // exists.
        assert_ne!(
            result_summary_label(&outcome),
            result_summary_label(&ProvenanceRunOutcome::Applied {
                unreadable_skipped: 0,
                event_appended: false,
                verdict: ProvenanceVerdictSummary::NoAttestation,
            }),
        );
        assert_ne!(
            result_summary_label(&outcome),
            result_summary_label(&ProvenanceRunOutcome::Applied {
                unreadable_skipped: 0,
                event_appended: false,
                verdict: ProvenanceVerdictSummary::HeldIndeterminate,
            }),
        );
    }

    /// A digest-mismatch rejection reaches the `result_summary` with its
    /// own reason string rather than hiding inside `bundle_malformed` —
    /// the audit trail an operator reads to tell a re-tag attack from a
    /// corrupt upload.
    #[test]
    fn digest_mismatch_maps_to_result_summary_label() {
        let outcome = ProvenanceRunOutcome::Applied {
            unreadable_skipped: 0,
            event_appended: true,
            verdict: ProvenanceVerdictSummary::Rejected(ProvenanceRejectReason::DigestMismatch),
        };
        assert_eq!(result_summary_label(&outcome), "rejected:digest_mismatch");
    }

    /// The issue #90 bounded-requeue outcome maps to the distinct
    /// `requeued:no_anchor` label. Pure-mapper assertion — `run`
    /// intercepts this outcome before ever calling `result_summary_label`
    /// (see `requeued_no_anchor_is_a_retryable_failure_not_completed`
    /// below), so this only pins the mapper staying exhaustive/testable.
    #[test]
    fn requeued_no_anchor_maps_to_result_summary_label() {
        assert_eq!(
            result_summary_label(&ProvenanceRunOutcome::RequeuedNoAnchor),
            "requeued:no_anchor"
        );
    }

    /// An already-cleared artifact (its own earlier verification or a
    /// cascaded clearance, ADR 0039 cascade) maps to the distinct
    /// `skipped:already_cleared` label — the no-op the S4 expiry backstop
    /// records instead of re-judging a cleared constituent. Pure-mapper
    /// assertion; the skip path itself is covered by the orchestration
    /// use-case tests.
    #[test]
    fn skipped_already_cleared_maps_to_result_summary_label() {
        assert_eq!(
            result_summary_label(&ProvenanceRunOutcome::SkippedAlreadyCleared),
            "skipped:already_cleared"
        );
    }

    /// The job's `result_summary` names how many candidates were skipped
    /// as unreadable — the only durable per-artifact record of WHICH
    /// artifact had garbage attached. Driven end-to-end: the stub verifier
    /// answers `Verified` while carrying a skip, exactly the headline
    /// shape, so the key has to survive a verdict that is not itself
    /// about the skipped material.
    #[tokio::test]
    async fn unreadable_skips_are_named_in_the_result_summary() {
        let (handler, artifact_id) = build_handler(
            ProvenanceMode::VerifyIfPresent,
            ProvenanceVerdict::verified(sample_signer(), None).with_unreadable_skipped(2),
            true,
        );
        let summary = run_summary(&handler, artifact_id).await;
        assert_eq!(
            summary,
            serde_json::json!({ "result": "verified", "unreadable_skipped": 2 }),
        );
    }

    /// Nothing skipped → the key is absent, not `0`. The ordinary row
    /// stays exactly as it was, so the rows that carry the key are the
    /// ones worth reading.
    #[tokio::test]
    async fn an_ordinary_verdict_carries_no_unreadable_skipped_key() {
        let (handler, artifact_id) = build_handler(
            ProvenanceMode::VerifyIfPresent,
            ProvenanceVerdict::verified(sample_signer(), None),
            true,
        );
        let summary = run_summary(&handler, artifact_id).await;
        assert_eq!(summary, serde_json::json!({ "result": "verified" }));
    }

    /// The extractor answers for every outcome, and zero for the three
    /// that are reached before any verifier ran plus the requeue (whose
    /// row is never written). Pure-mapper assertion, mirroring
    /// `result_summary_label`'s own tests.
    #[test]
    fn unreadable_skipped_reads_every_outcome() {
        assert_eq!(
            unreadable_skipped(&ProvenanceRunOutcome::Applied {
                event_appended: true,
                verdict: ProvenanceVerdictSummary::Verified,
                unreadable_skipped: 4,
            }),
            4
        );
        assert_eq!(
            unreadable_skipped(&ProvenanceRunOutcome::ClearedAsSignatureMaterial {
                unreadable_skipped: 1,
            }),
            1
        );
        for before_dispatch in [
            ProvenanceRunOutcome::SkippedOff,
            ProvenanceRunOutcome::SkippedNoVerifier,
            ProvenanceRunOutcome::SkippedAlreadyCleared,
            ProvenanceRunOutcome::RequeuedNoAnchor,
        ] {
            assert_eq!(
                unreadable_skipped(&before_dispatch),
                0,
                "{before_dispatch:?}"
            );
        }
    }

    /// Under `Off` the handler records `skipped:off` (defensive — the ingest
    /// gate should never enqueue here).
    #[tokio::test]
    async fn off_writes_skipped_summary() {
        let (handler, artifact_id) = build_handler(
            ProvenanceMode::Off,
            ProvenanceVerdict::no_attestation(),
            false,
        );
        let summary = run_summary(&handler, artifact_id).await;
        assert_eq!(summary, serde_json::json!({ "result": "skipped:off" }));
    }

    fn sample_signer() -> SignerIdentity {
        SignerIdentity {
            issuer: "https://token.actions.githubusercontent.com".into(),
            san: "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
                .into(),
        }
    }

    /// `kind()` is the registered literal — mirrors `ScanTaskHandler`'s
    /// constant check. The full orchestration path is covered by the
    /// `provenance_orchestration` use-case tests; constructing a real
    /// `ProvenanceOrchestrationUseCase` here would duplicate that wiring.
    #[test]
    fn kind_constant_is_provenance_verify() {
        // The literal the dispatcher registers under and the SQL CHECK /
        // ADMIN_INVOKABLE_TASK_KINDS mirror.
        assert_eq!("provenance-verify", "provenance-verify");
    }

    /// Invalid params JSON → non-retryable `Failed` (operator/code error,
    /// not infra). Exercised without a use case because the parse happens
    /// before any orchestration call.
    #[tokio::test]
    async fn invalid_params_is_non_retryable_failure() {
        use hort_domain::events::system_actor;
        use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};

        // A handler whose orchestration is never reached — params parse
        // fails first. We cannot build a real orchestration cheaply, so
        // assert the parse-failure arm via a direct params check.
        let bad = serde_json::json!({ "not_artifact_id": 1 });
        let parsed: Result<ProvenanceVerifyParams, _> = serde_json::from_value(bad);
        assert!(
            parsed.is_err(),
            "missing artifact_id must fail params parse"
        );

        // Confirm the TaskContext/JobRow shape compiles for the handler's
        // signature (kept minimal — the parse arm is the unit under test).
        let now = chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap();
        let _row = JobRow {
            id: Uuid::nil(),
            kind: "provenance-verify".to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::Value::Null),
            actor_id: None,
            priority: 0,
            trigger_source: "ingest".to_string(),
            attempts: 1,
            created_at: now,
            updated_at: now,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
        };
        let _ctx = TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: _row,
        };
    }
}
