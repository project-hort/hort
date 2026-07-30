//! Provenance-orchestration use case (ADR 0027).
//!
//! The worker-side flow for the `provenance-verify` job: load the
//! artifact + its resolved `ScanPolicy`, fetch the attestation bundles
//! (OCI: the Referrers / content-reference surface — possibly empty),
//! stream the artifact preimage from CAS, dispatch each applicable
//! [`ProvenancePort`], fold the per-verifier verdicts to one, and apply
//! [`Artifact::complete_provenance`] — persisting the returned event (if
//! any) via the artifact lifecycle port.
//!
//! Mirrors [`ScanOrchestrationUseCase`](super::scan_orchestration::ScanOrchestrationUseCase):
//! port-only `Arc<dyn _Port>` dependencies, no concrete use-case handles.
//!
//! # Fail-closed semantics
//!
//! - Under [`ProvenanceMode::Required`], a bundle-fetch / CAS-read failure
//!   that retries cannot resolve → fold to
//!   `ProvenanceRejected{RekorNotFound}` so a **never-verified** `Required`
//!   artifact never timer-releases (it stays `Pending` in the release
//!   sweep's clearance computation).
//! - Under [`ProvenanceMode::VerifyIfPresent`], the same unresolved
//!   infra/fetch failure **degrades to `NoAttestation` (allow)** — it must
//!   NEVER make the proxy fail-closed on flakiness. `VerifyIfPresent` only
//!   ever *adds* a rejection on a forged/untrusted signature.
//! - [`ProvenanceMode::Off`] never enqueues a `provenance-verify` job
//!   (the gate is at ingest-enqueue time); the orchestrator returns a
//!   no-op skip if it is ever invoked for an `Off` policy.
//!
//! # Tracing
//!
//! `info!` on `ProvenanceVerified` and on `ProvenanceRejected` (these are
//! supply-chain audit decisions, NOT `err`); no `#[instrument(err)]`. The
//! domain stays tracing-free. Metrics are emitted by the callers per the
//! catalog-same-PR rule (binds metric emission to its `docs/metrics-catalog.md`
//! entry + a `with_local_recorder` test).

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::entities::scan_policy::ProvenanceMode;
use hort_domain::events::{system_actor, ArtifactIngested, DomainEvent, IngestSource};
use hort_domain::policy::{effective_quarantine_deadline, DefaultPolicy};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::ports::event_store::{
    AppendEvents, EventStore, EventToAppend, ExpectedVersion, ReadFrom,
};
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::provenance::{
    AttestationBundle, ProvenancePort, ProvenanceRejectReason, ProvenanceRequirements,
    ProvenanceSubject, ProvenanceVerdict, SignerIdentity,
};
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping;
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::upstream_proxy::{IdentityProjector, UpstreamProxy};
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_domain::types::ContentHash;

use tokio::io::AsyncReadExt;
use tokio_util::io::StreamReader;

use crate::error::AppResult;
use crate::event_store_publisher::EventStorePublisher;
use crate::use_cases::policy_resolution::resolve_active_policy_for_repo;
use crate::use_cases::read_expected_version;

/// The `kind` filter used to read cosign attestation bundles off the
/// content-reference / OCI Referrers surface. A cosign signature manifest
/// is recorded as an `"oci_subject"` row pointing AT the signed artifact's
/// content hash (the OCI Referrers projection).
const OCI_SUBJECT_KIND: &str = "oci_subject";

/// Upper bound on bytes read from CAS for the artifact preimage / a single
/// attestation bundle. For OCI cosign the subject is the manifest (small);
/// the bundle is a Sigstore JSON blob. A generous backstop that keeps a
/// pathological CAS object from buffering unbounded into memory on the
/// verify path. 16 MiB.
const MAX_PROVENANCE_READ_BYTES: u64 = 16 * 1024 * 1024;

/// Number of attempts (1 initial + N-1 retries) the orchestrator makes to
/// fetch the bundle set / read the CAS preimage before giving up. On
/// exhaustion the mode decides: `Required` → fail-closed
/// `Rejected{RekorNotFound}`; `VerifyIfPresent` → degrade to
/// `NoAttestation` (allow).
const FETCH_ATTEMPTS: u32 = 3;

/// Cap on the number of events read when scanning an artifact stream for an
/// existing `ProvenanceVerified` (the already-cleared no-op skip and the
/// cascade's idempotency check). Mirrors `STREAM_READ_LIMIT` in
/// `release_clearance` (the release gate's own clearance read); every
/// artifact stream begins well within this bound.
const STREAM_READ_LIMIT: u64 = 200;

/// The verdict reached on an `Applied` run, surfaced to the task handler
/// so it can record a compact per-artifact `result_summary` on the job
/// row.
///
/// This is **coarser than** the full [`ProvenanceVerdict`]: the handler
/// only needs the bucket (`verified` / `rejected:<reason>` / `no_attestation`)
/// for the forensic trail — not the signer identity / predicate type, which
/// already ride the persisted `ProvenanceVerified` / `ProvenanceRejected`
/// event. `Rejected` keeps the typed reason so the previously-opaque
/// rejection cause is visible in `result_summary` without re-reading the
/// event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceVerdictSummary {
    /// A trusted signature was verified (`ProvenanceVerified` emitted).
    Verified,
    /// A typed rejection (`ProvenanceRejected` emitted), carrying the typed
    /// reason. Covers both the `Required` unsigned mapping
    /// (`Rejected{Unsigned}`) and the fail-closed `Rejected{RekorNotFound}`
    /// path.
    Rejected(ProvenanceRejectReason),
    /// No bundle was found / passed and the mode allowed it
    /// (`VerifyIfPresent`/`Off` no-op, no event) — a previously-silent
    /// case, made observable here.
    NoAttestation,
    /// A `Required`-mode artifact was found unsigned while its quarantine
    /// observation window is still open (issue #13): no event, status stays
    /// `Quarantined` (HELD, read as `Pending` by the release gate). Distinct
    /// from `NoAttestation` so the task handler's `result_summary`
    /// separates "waiting to be signed" from "allowed unsigned".
    HeldPendingSignature,
}

/// Result of a single `verify` invocation, before the job row is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceRunOutcome {
    /// The policy resolved `provenance_mode == Off` (the orchestrator was
    /// invoked anyway — defensive; the ingest gate should never enqueue
    /// here) → no verifier ran, no event appended.
    SkippedOff,
    /// No registered verifier `applies_to` the artifact's format → no-op
    /// (defensive; the ingest gate should never enqueue here either).
    SkippedNoVerifier,
    /// The artifact's stream already carries a `ProvenanceVerified` — its
    /// own earlier verification or a cascaded clearance from a verified
    /// subject (ADR 0039 cascade) — so the verify is a no-op. Re-judging a
    /// cleared artifact could only harm it: a cascade-cleared constituent
    /// has no referrer surface of its own (cosign signs only the top-level
    /// digest), so re-running the pipeline with the window closed (the S4
    /// expiry backstop racing the cascade) would terminally reject a
    /// cleared artifact as `Unsigned`. `Required` mode only.
    SkippedAlreadyCleared,
    /// A verdict was produced and applied. `event_appended` is `true` when
    /// `complete_provenance` emitted an event (Verified / Rejected) and
    /// `false` for the `NoAttestation`-under-`VerifyIfPresent` no-op.
    /// `verdict` carries the coarse outcome bucket the task handler maps to
    /// `result_summary`.
    Applied {
        event_appended: bool,
        verdict: ProvenanceVerdictSummary,
    },
}

/// Provenance-orchestration use case (mirror of `ScanOrchestrationUseCase`).
pub struct ProvenanceOrchestrationUseCase {
    artifacts: Arc<dyn ArtifactRepository>,
    repositories: Arc<dyn RepositoryRepository>,
    policy_projections: Arc<dyn PolicyProjectionRepository>,
    content_references: Arc<dyn ContentReferenceIndex>,
    storage: Arc<dyn StoragePort>,
    lifecycle: Arc<dyn ArtifactLifecyclePort>,
    events: Arc<EventStorePublisher>,
    /// Registered verifier set (Tier-1: cosign). The orchestrator
    /// dispatches every port whose `applies_to(format)` matches and folds
    /// their verdicts to one. Held as a `Vec` (not a `HashMap` keyed by
    /// `name`) because dispatch is by `applies_to(format)`, not by name.
    provenance_ports: Vec<Arc<dyn ProvenancePort>>,
    /// Upstream pull-through proxy. On a proxy scope
    /// with no local bundle, the orchestrator fetches the image's Sigstore
    /// referrer(s) + bundle blob(s) from upstream through this port.
    /// Port-only, mirroring the other `Arc<dyn _>` deps.
    upstream_proxy: Arc<dyn UpstreamProxy>,
    /// Upstream resolver. `resolve(repo_id, name)`
    /// is `Some` iff the repo is a proxy/pull-through scope — the trigger
    /// for the upstream referrer-fetch arm.
    upstream_resolver: Arc<dyn UpstreamResolver>,
}

impl ProvenanceOrchestrationUseCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifacts: Arc<dyn ArtifactRepository>,
        repositories: Arc<dyn RepositoryRepository>,
        policy_projections: Arc<dyn PolicyProjectionRepository>,
        content_references: Arc<dyn ContentReferenceIndex>,
        storage: Arc<dyn StoragePort>,
        lifecycle: Arc<dyn ArtifactLifecyclePort>,
        events: Arc<EventStorePublisher>,
        provenance_ports: Vec<Arc<dyn ProvenancePort>>,
        upstream_proxy: Arc<dyn UpstreamProxy>,
        upstream_resolver: Arc<dyn UpstreamResolver>,
    ) -> Self {
        Self {
            artifacts,
            repositories,
            policy_projections,
            content_references,
            storage,
            lifecycle,
            events,
            provenance_ports,
            upstream_proxy,
            upstream_resolver,
        }
    }

    /// Verify the provenance of `artifact_id` and apply the verdict.
    ///
    /// Pure orchestration: loads the artifact + policy + bundles, dispatches
    /// the verifier(s), and threads the folded verdict through
    /// [`Artifact::complete_provenance`], persisting the event (if any).
    pub async fn verify_artifact(&self, artifact_id: Uuid) -> AppResult<ProvenanceRunOutcome> {
        let artifact = self.artifacts.find_by_id(artifact_id).await?;
        let repo = self.repositories.find_by_id(artifact.repository_id).await?;
        let format = repo.format.to_string();

        // Resolve the policy (repo-scoped → global). Mode drives every
        // downstream decision.
        let policy =
            resolve_active_policy_for_repo(&*self.policy_projections, artifact.repository_id)
                .await?;
        let mode = policy
            .as_ref()
            .map(|p| p.provenance_mode)
            .unwrap_or_default();

        // Compute the observation-window state (issue #13, design §2 S1/S4).
        // A missing signature under `Required` is time-dependent — the
        // artifact may yet be signed — so it is HELD while this window is
        // open (mirroring an incomplete scan) rather than terminally rejected
        // at the first verify. The deadline is derived (never persisted) from
        // the artifact's immutable quarantine anchor + the resolved
        // `ScanPolicy.quarantineDuration` (or the default), through the SAME
        // `effective_quarantine_deadline` helper the release sweep uses.
        //
        // A missing `quarantine_window_start` resolves `window_open = false`:
        // the ingest path always quarantines an OCI subject before enqueuing
        // the verify, so a `None` anchor here is a defensive / mis-ordered run
        // only — and a defensive run must not HOLD indefinitely (no anchor ⇒
        // no window ⇒ terminal). `window_open` gates only the
        // `NoAttestation × Required` arm in `complete_provenance`; the expiry
        // backstop (`release_expired`) re-runs the verify after the deadline,
        // where this resolves to `false` by construction.
        let effective_duration_secs: i64 = policy
            .as_ref()
            .map(|p| p.quarantine_duration_secs)
            .unwrap_or_else(DefaultPolicy::quarantine_duration_secs);
        let now = chrono::Utc::now();
        let window_open = artifact
            .quarantine_window_start
            .map(|anchor| {
                effective_quarantine_deadline(
                    anchor,
                    chrono::Duration::seconds(effective_duration_secs),
                ) > now
            })
            .unwrap_or(false);

        // Off — provenance is inert for this scope. The ingest gate should
        // never enqueue here; the orchestrator no-ops defensively.
        if mode == ProvenanceMode::Off {
            return Ok(ProvenanceRunOutcome::SkippedOff);
        }

        // Select the applicable verifiers (Tier-1: cosign → OCI). The
        // ingest gate already filters non-applicable formats; if none
        // apply at runtime (mis-registration), no-op — a `Required`
        // artifact then stays `Pending` (fail-closed at the release gate).
        let applicable: Vec<&Arc<dyn ProvenancePort>> = self
            .provenance_ports
            .iter()
            .filter(|p| p.applies_to(&format))
            .collect();
        if applicable.is_empty() {
            return Ok(ProvenanceRunOutcome::SkippedNoVerifier);
        }

        // Already-cleared no-op (ADR 0039 cascade). Under `Required`, an
        // artifact whose stream already carries a `ProvenanceVerified` — its
        // own earlier verification or a clearance cascaded from a verified
        // subject — is cleared, and re-judging it can only harm: a
        // cascade-cleared constituent has no referrer surface of its own
        // (cosign signs only the top-level digest), so a verify that lands
        // after the cascade (the S4 expiry backstop enqueued while the
        // artifact was still `Pending`, a duplicate S3 enqueue) would re-run
        // the pipeline to `NoAttestation` and — window closed — terminally
        // reject a cleared artifact as `Unsigned`. Skip instead.
        // `VerifyIfPresent`/`Off` never consult the clearance, so their
        // re-verify behaviour is unchanged.
        if mode == ProvenanceMode::Required {
            let (cleared, _) = self.read_clearance_state(artifact.id).await?;
            if let Some(existing) = cleared {
                tracing::debug!(
                    artifact_id = %artifact.id,
                    "provenance: already cleared — skipping verify",
                );
                // Cascade re-drive: when the stored clearance is a DIRECT
                // verification (`cascaded_from == None`), this artifact is a
                // signed SUBJECT whose bytes bind constituents — re-run the
                // idempotent cascade before skipping, so a constituent whose
                // cascaded append lost a version race heals on the next
                // verify of the subject (an operator re-signs → S3
                // re-enqueue → this skip path → the missed constituent
                // clears). Gated on direct clearance: a CASCADED
                // constituent's own bytes cannot cascade (config/layer
                // blobs are not manifests) and a cascaded child index must
                // not recurse — so a cascaded clearance never re-walks CAS
                // bytes here. Best-effort: no failure in the re-drive
                // changes the skip outcome (the subject's clearance stands).
                if existing.cascaded_from.is_none() {
                    match self.read_bounded(&artifact.sha256_checksum).await {
                        Ok(payload) => {
                            self.cascade_clearance(
                                artifact.repository_id,
                                &artifact.sha256_checksum,
                                &payload,
                                &existing.signer,
                                existing.predicate_type.as_deref(),
                                &existing.backend,
                            )
                            .await;
                        }
                        Err(e) => tracing::warn!(
                            artifact_id = %artifact.id,
                            error = %e,
                            "provenance: cascade re-drive CAS read failed — \
                             skipping re-drive (already-cleared outcome stands)",
                        ),
                    }
                }
                return Ok(ProvenanceRunOutcome::SkippedAlreadyCleared);
            }
        }

        // Fetch the attestation bundles off the OCI Referrers /
        // content-reference surface (possibly empty), with bounded
        // retries. A fetch failure that retries cannot resolve folds to a
        // mode-dependent verdict (Required → fail-closed; VerifyIfPresent
        // → allow).
        // The backend label for the metrics. Tier-1 is a single verifier
        // (cosign); for a future multi-verifier set the first applicable
        // port names the metric series — the representative backend that
        // ran for this format. Captured before any fetch-failure
        // early-return so the fail-closed / degrade verdicts carry the
        // same label.
        let backend = applicable[0].name().to_string();

        let mut bundles = match self
            .fetch_bundles(artifact.repository_id, &artifact.sha256_checksum)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                return self
                    .apply_fetch_failure(artifact, &backend, mode, window_open, "bundle fetch", e)
                    .await;
            }
        };

        // The proxy referrer-fetch arm. When NO local
        // bundle was found AND the repo is a proxy/pull-through scope
        // (`upstream_resolver.resolve(..).is_some()`), fetch the image's
        // Sigstore referrer(s) from upstream, land them into local CAS via the
        // narrow create, then re-read the local bundle set once. A
        // hosted repo (`resolve → None`) with no local bundle is left
        // unchanged (nothing to fetch → stays `NoAttestation`). An upstream
        // fetch error follows the SAME `apply_fetch_failure` arm as a local
        // bundle-fetch failure (VerifyIfPresent → degrade-to-allow; Required →
        // fail-closed).
        if bundles.is_empty() {
            if let Some((mapping, upstream_name)) = self
                .upstream_resolver
                .resolve(artifact.repository_id, &artifact.name)
            {
                match self
                    .fetch_and_land_upstream_referrers(&artifact, mapping, upstream_name)
                    .await
                {
                    Ok(()) => {
                        // Re-read the local bundle set ONCE — the narrow create
                        // above wrote the `oci_subject` row(s) + bundle blob(s)
                        // that `fetch_bundles_once` now resolves.
                        bundles = match self
                            .fetch_bundles(artifact.repository_id, &artifact.sha256_checksum)
                            .await
                        {
                            Ok(b) => b,
                            Err(e) => {
                                return self
                                    .apply_fetch_failure(
                                        artifact,
                                        &backend,
                                        mode,
                                        window_open,
                                        "post-proxy bundle re-read",
                                        e,
                                    )
                                    .await;
                            }
                        };
                    }
                    Err(e) => {
                        return self
                            .apply_fetch_failure(
                                artifact,
                                &backend,
                                mode,
                                window_open,
                                "upstream referrer fetch",
                                e,
                            )
                            .await;
                    }
                }
            }
        }

        // Stream the artifact preimage from CAS (bounded). For OCI cosign
        // the subject is the manifest — small. This is the
        // `ProvenanceSubject.payload` the verifier feeds to its hasher.
        let payload = match self.read_preimage(&artifact.sha256_checksum).await {
            Ok(bytes) => bytes,
            Err(e) => {
                return self
                    .apply_fetch_failure(
                        artifact,
                        &backend,
                        mode,
                        window_open,
                        "CAS preimage read",
                        e,
                    )
                    .await;
            }
        };

        // Build the verifier inputs. `provenance_identities` is the slice
        // of allowed signer patterns; an empty slice under `Required` is
        // rejected at apply time — the verifier treats it as verify-time
        // input only.
        let empty_identities = Vec::new();
        let allowed_identities = policy
            .as_ref()
            .map(|p| p.provenance_identities.as_slice())
            .unwrap_or(empty_identities.as_slice());

        let subject = ProvenanceSubject {
            content_hash: &artifact.sha256_checksum,
            payload: &payload,
            name: &artifact.name,
            version: artifact.version.as_deref(),
        };
        let requirements = ProvenanceRequirements { allowed_identities };

        // Dispatch each applicable verifier and fold to one verdict.
        let (verdict, verdict_backend) = self
            .dispatch_and_fold(&applicable, &subject, &bundles, &requirements, mode)
            .await;

        // Label the metric with the backend that DECIDED the folded verdict
        // (ADR 0039 §6), not `applicable[0]`. The dead-defensive empty case (no
        // verifier ran — impossible since `applicable` is non-empty) falls back
        // to the representative `backend`.
        let metric_backend = if verdict_backend.is_empty() {
            backend
        } else {
            verdict_backend
        };

        // Capture the cascade seed BEFORE the verdict is moved into
        // `apply_verdict`: a `Verified` verdict of the real verifier under
        // `Required` cascades the subject's clearance to the constituents
        // its signed bytes bind (ADR 0039 cascade). Under
        // `VerifyIfPresent`/`Off` no constituent has a pending provenance
        // gate, so there is nothing to cascade.
        let cascade_seed = match (&verdict.outcome, mode) {
            (
                hort_domain::ports::provenance::ProvenanceOutcome::Verified {
                    signer,
                    predicate_type,
                },
                ProvenanceMode::Required,
            ) => Some((signer.clone(), predicate_type.clone())),
            _ => None,
        };
        let repository_id = artifact.repository_id;
        let subject_hash = artifact.sha256_checksum.clone();

        let outcome = self
            .apply_verdict(artifact, &metric_backend, verdict, mode, window_open)
            .await?;

        // The cascade fires only after the subject's own clearance
        // committed (`apply_verdict` returning `Ok` on a Verified verdict
        // means the `ProvenanceVerified` event is persisted — an append
        // failure propagates above). Best-effort by construction: nothing
        // in the cascade can retract or block the already-committed
        // subject clearance.
        if let Some((signer, predicate_type)) = cascade_seed {
            self.cascade_clearance(
                repository_id,
                &subject_hash,
                &payload,
                &signer,
                predicate_type.as_deref(),
                &metric_backend,
            )
            .await;
        }
        Ok(outcome)
    }

    // -----------------------------------------------------------------
    // Bundle fetch + preimage read
    // -----------------------------------------------------------------

    /// Fetch every attestation bundle pointing at `content_hash` on the OCI
    /// Referrers surface, reading each referencing source artifact's bytes
    /// from CAS. Bounded retries; the whole operation either succeeds (with
    /// a possibly-empty `Vec`) or returns the last error.
    async fn fetch_bundles(
        &self,
        repository_id: Uuid,
        content_hash: &ContentHash,
    ) -> AppResult<Vec<AttestationBundle>> {
        let mut last_err = None;
        for _ in 0..FETCH_ATTEMPTS {
            match self.fetch_bundles_once(repository_id, content_hash).await {
                Ok(bundles) => return Ok(bundles),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.expect("FETCH_ATTEMPTS >= 1 so at least one error was recorded"))
    }

    async fn fetch_bundles_once(
        &self,
        repository_id: Uuid,
        content_hash: &ContentHash,
    ) -> AppResult<Vec<AttestationBundle>> {
        // The cosign signature manifests are recorded as `oci_subject`
        // content-references pointing AT the signed artifact's content
        // hash. The source artifact's CAS bytes are the referrer
        // **manifest** — NOT the bundle. The bundle JSON the
        // verifier consumes is a *blob* the manifest references; the OCI
        // layer digest is the CAS content hash (both SHA-256 of the raw
        // bytes), so each bundle blob is readable from storage by its
        // digest with no extra artifact lookup.
        let refs = self
            .content_references
            .find_by_target(repository_id, content_hash, Some(OCI_SUBJECT_KIND))
            .await?;

        let mut bundles = Vec::new();
        for reference in refs {
            // Resolve the source artifact to its CAS hash, then read the
            // referrer manifest bytes. A missing source row is a
            // projection inconsistency, not an attestation failure —
            // surface it so the retry/mode logic decides.
            let source = self
                .artifacts
                .find_by_id(reference.source_artifact_id)
                .await?;
            let manifest_bytes = self.read_bounded(&source.sha256_checksum).await?;

            // Parse the referrer manifest and keep only the Sigstore-bundle
            // layer blobs (the pure `sigstore_bundle_layers` helper). A referrer that
            // carries no Sigstore-bundle layer (a non-cosign referrer — SBOM,
            // an attestation of another predicate, an ordinary manifest)
            // contributes nothing — skipped, not errored.
            let blob_hashes = hort_domain::oci::sigstore_bundle_layers(&manifest_bytes)?;
            for blob_hash in blob_hashes {
                // The bundle blob digest IS its CAS content hash. A blob
                // referenced by the manifest but absent from CAS surfaces as
                // a `read_bounded` error → the existing fetch-failure path
                // (mode-dependent), never a panic.
                let bundle_bytes = self.read_bounded(&blob_hash).await?;
                bundles.push(build_bundle(bundle_bytes));
            }

            // Keyed (ADR 0039 §8): collect any legacy cosign `simplesigning`
            // signatures on the same referrer. Each yields a SIGNED bundle —
            // `bytes` = the simplesigning payload-layer blob, `signature` = the
            // base64 `dev.cosignproject.cosign/signature` annotation decoded. An
            // undecodable annotation can never be a valid signature → skipped
            // (under `Required`, no valid bundle folds to `Rejected{Unsigned}`).
            let sig_layers = hort_domain::oci::simplesigning_signature_layers(&manifest_bytes)?;
            for sig in sig_layers {
                let payload_bytes = self.read_bounded(&sig.payload_layer).await?;
                let Some(sig_bytes) = decode_simplesigning_signature(&sig.signature) else {
                    continue;
                };
                bundles.push(AttestationBundle::new_signed(payload_bytes, sig_bytes));
            }
        }
        Ok(bundles)
    }

    // -----------------------------------------------------------------
    // Proxy referrer fetch + narrow create
    // -----------------------------------------------------------------

    /// Fetch the image's Sigstore referrer(s) from upstream and land each one
    /// (referrer manifest + its bundle blob) into local CAS via the **narrow
    /// create** — NOT `ingest_verified`. Per landed referrer this
    /// writes a status-`None` referrer-manifest artifact (via
    /// `commit_transition` + `ArtifactIngested`, with **no** scan/provenance
    /// enqueue) and the `oci_subject` content-reference row pointing AT the
    /// proxied image's content hash. `fetch_bundles_once` then resolves the
    /// bundle blob from CAS on the subsequent re-read.
    ///
    /// `#[instrument]` without `err` (the upstream fetch is a normal
    /// operation; a failure is reported by the caller's `apply_fetch_failure`
    /// arm, mode-dependently). `info!` on a fetch that yielded ≥1 bundle;
    /// `warn!` on a fetch error. No per-`no_attestation` log.
    #[tracing::instrument(skip(self, artifact, mapping))]
    async fn fetch_and_land_upstream_referrers(
        &self,
        artifact: &Artifact,
        mapping: RepositoryUpstreamMapping,
        upstream_name: String,
    ) -> AppResult<()> {
        let image_digest = format!("sha256:{}", artifact.sha256_checksum);

        // 1. Discover the upstream referrers for this image's digest
        //    (Referrers API + cosign `.sig` tag-scheme fallback in the
        //    adapter). A fetch error propagates to the caller's
        //    mode-dependent `apply_fetch_failure` arm.
        let descriptors = self
            .upstream_proxy
            .fetch_referrers(mapping.clone(), upstream_name.clone(), image_digest.clone())
            .await
            .map_err(|e| {
                tracing::warn!(
                    artifact_id = %artifact.id,
                    error = %e,
                    "provenance: upstream referrer discovery failed",
                );
                e
            })?;

        // 2. Keep only Sigstore-bundle referrers (by `artifact_type` or
        //    `media_type`); land each. A referrer that yields no bundle layer
        //    (or fails the declared-digest integrity check) is skipped.
        let mut landed_bundles = 0usize;
        for descriptor in descriptors {
            // Keyless Sigstore-bundle OR keyed simplesigning referrers (ADR 0039
            // §8). A well-typed referrer (Referrers API `artifactType`) is caught
            // here; the legacy `sha256-<hex>.sig` tag-scheme `.sig` carries the
            // simplesigning type on the LAYER not the descriptor, so proxying that
            // shape is not auto-discovered (keyed images are first-party/hosted;
            // proxied third-party content uses keyless cosign).
            let is_signature_referrer = descriptor.artifact_type.as_deref()
                == Some(hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE)
                || descriptor.media_type == hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE
                || descriptor.artifact_type.as_deref()
                    == Some(hort_domain::oci::COSIGN_SIMPLESIGNING_MEDIA_TYPE);
            if !is_signature_referrer {
                continue;
            }
            if self
                .land_one_referrer(artifact, &mapping, &upstream_name, &descriptor.digest)
                .await?
            {
                landed_bundles += 1;
            }
        }

        if landed_bundles > 0 {
            tracing::info!(
                artifact_id = %artifact.id,
                upstream_name = %upstream_name,
                referrers = landed_bundles,
                "provenance: fetched upstream Sigstore referrer(s)",
            );
        }
        Ok(())
    }

    /// Land a single upstream referrer: fetch its manifest, store the
    /// manifest + each Sigstore-bundle blob into CAS with a
    /// declared-digest integrity check, commit the status-`None`
    /// referrer-manifest artifact, and write the `oci_subject` row. Returns
    /// `Ok(true)` when ≥1 bundle blob was landed, `Ok(false)` when the
    /// referrer was skipped (non-bundle manifest, or digest integrity
    /// mismatch). An upstream / CAS error propagates (mode-dependent).
    async fn land_one_referrer(
        &self,
        artifact: &Artifact,
        mapping: &RepositoryUpstreamMapping,
        upstream_name: &str,
        referrer_digest: &str,
    ) -> AppResult<bool> {
        // The referrer manifest's own declared digest (the manifest is
        // content-addressed; a `sha256:` reference is required, else skip).
        let Some(declared_manifest_hash) = parse_sha256_digest(referrer_digest) else {
            return Ok(false);
        };

        // a. Fetch the referrer manifest bytes (cached on disk; read via the
        //    IdentityProjector). `accept`-empty defers to the adapter default.
        let outcome = self
            .upstream_proxy
            .fetch_manifest(
                mapping.clone(),
                upstream_name.to_string(),
                referrer_digest.to_string(),
                Vec::new(),
            )
            .await?;
        let Some(handle) = outcome.cache_handle else {
            return Ok(false);
        };
        let manifest_bytes = crate::project::project_cached(&handle, IdentityProjector).await?;
        crate::project::remove_cached_body(&handle).await;

        // b. Parse the manifest → the signature-material blob digest(s) to land:
        //    keyless Sigstore-bundle layers AND keyed simplesigning payload
        //    layers (ADR 0039 §8 — proxying a keyed image). A referrer with
        //    neither yields nothing → skip. The signature itself (for the keyed
        //    shape) rides the manifest annotation, which is stored verbatim in
        //    step d, so only the payload-layer blob needs landing here.
        let mut blob_hashes = hort_domain::oci::sigstore_bundle_layers(&manifest_bytes)?;
        blob_hashes.extend(
            hort_domain::oci::simplesigning_signature_layers(&manifest_bytes)?
                .into_iter()
                .map(|s| s.payload_layer),
        );
        if blob_hashes.is_empty() {
            return Ok(false);
        }

        // c. Fetch + store each bundle blob. The put-returned hash MUST
        //    equal the manifest-DECLARED layer digest; on mismatch the whole
        //    referrer is skipped (fail-closed — never land a tampered blob).
        //    Note: blobs are put BEFORE the digest check, so a mismatch here
        //    (or on the manifest in step d) leaves any already-stored blob(s)
        //    as unreferenced CAS orphans — content-addressed, never served as
        //    a bundle without an `oci_subject` row, and reaped by GC. This is
        //    the deliberate put-then-verify trade (CAS keys on the content, so
        //    we can only learn the real hash after the streaming write).
        for blob_hash in &blob_hashes {
            let blob = self
                .upstream_proxy
                .fetch_blob(
                    mapping.clone(),
                    upstream_name.to_string(),
                    format!("sha256:{blob_hash}"),
                )
                .await?;
            let reader: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
                Box::new(StreamReader::new(blob.stream));
            let put = self.storage.put(reader).await?;
            if &put.hash != blob_hash {
                tracing::warn!(
                    artifact_id = %artifact.id,
                    declared = %blob_hash,
                    stored = %put.hash,
                    "provenance: upstream bundle blob digest mismatch — skipping referrer",
                );
                return Ok(false);
            }
        }

        // d. Store the referrer manifest in CAS — its put-returned hash must
        //    equal the descriptor's declared digest.
        let manifest_put = self
            .storage
            .put(Box::new(std::io::Cursor::new(manifest_bytes)))
            .await?;
        if manifest_put.hash != declared_manifest_hash {
            tracing::warn!(
                artifact_id = %artifact.id,
                declared = %declared_manifest_hash,
                stored = %manifest_put.hash,
                "provenance: upstream referrer manifest digest mismatch — skipping",
            );
            return Ok(false);
        }

        // e. Narrow create — the referrer-manifest `artifacts` row. Built with
        //    the already-held `lifecycle` port (NOT `IngestUseCase`):
        //    `quarantine_status = None` (an internal provenance-bookkeeping
        //    artifact, outside the scan/quarantine/provenance lifecycle) and
        //    NO `jobs.enqueue_*` — the whole point of the narrow create.
        let manifest_artifact = self
            .commit_referrer_manifest(artifact, manifest_put.hash, manifest_put.size_bytes)
            .await?;

        // f. The `oci_subject` content-reference row — source is the referrer
        //    manifest artifact, target is the proxied image's content hash
        //    (mirrors the push-path row shape in manifests_write.rs). Upsert
        //    on PK → idempotent re-run.
        self.content_references
            .insert(ContentReference {
                source_artifact_id: manifest_artifact.id,
                target_content_hash: artifact.sha256_checksum.clone(),
                kind: OCI_SUBJECT_KIND.to_string(),
                metadata: serde_json::json!({
                    "artifact_type": hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE,
                    "media_type": "application/vnd.oci.image.manifest.v1+json",
                }),
                repository_id: artifact.repository_id,
                recorded_at: chrono::Utc::now(),
            })
            .await?;

        Ok(true)
    }

    /// Commit the status-`None` referrer-manifest artifact via
    /// `commit_transition` + a single `ArtifactIngested` event — the same
    /// create primitive `IngestUseCase::ingest_signature_manifest` uses,
    /// inlined here against the already-held ports. NO scan / provenance
    /// enqueue. Returns the created `Artifact`.
    async fn commit_referrer_manifest(
        &self,
        image: &Artifact,
        manifest_hash: ContentHash,
        size_bytes: u64,
    ) -> AppResult<Artifact> {
        let artifact_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let artifact = Artifact {
            id: artifact_id,
            repository_id: image.repository_id,
            name: image.name.clone(),
            name_as_published: image.name_as_published.clone(),
            version: image.version.clone(),
            path: image.path.clone(),
            size_bytes: size_bytes as i64,
            sha256_checksum: manifest_hash.clone(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            quarantine_status: QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: now,
            updated_at: now,
        };

        let ingested_event = ArtifactIngested {
            artifact_id,
            repository_id: image.repository_id,
            name: artifact.name.clone(),
            version: artifact.version.clone(),
            sha256: manifest_hash,
            size_bytes: artifact.size_bytes,
            source: IngestSource::Proxied,
            metadata: serde_json::Value::Null,
            metadata_blob: None,
            upstream_published_at: None,
        };

        let stream_id = hort_domain::events::StreamId::artifact(artifact_id);
        let expected_version = read_expected_version(&*self.events, &stream_id, true).await?;

        self.lifecycle
            .commit_transition(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![EventToAppend::new(DomainEvent::ArtifactIngested(
                        ingested_event,
                    ))],
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor: system_actor(),
                },
                None,
            )
            .await?;

        Ok(artifact)
    }

    /// Read the artifact preimage from CAS (bounded). Returns the bytes
    /// `ProvenanceSubject.payload` is built over.
    async fn read_preimage(&self, content_hash: &ContentHash) -> AppResult<Vec<u8>> {
        let mut last_err = None;
        for _ in 0..FETCH_ATTEMPTS {
            match self.read_bounded(content_hash).await {
                Ok(bytes) => return Ok(bytes),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.expect("FETCH_ATTEMPTS >= 1 so at least one error was recorded"))
    }

    /// Read up to [`MAX_PROVENANCE_READ_BYTES`] from the CAS object at
    /// `hash`. A read error surfaces as `Err`. Over-cap content is
    /// truncated at the cap (the verify path does not need the full blob
    /// for the manifest-shaped subjects Tier-1 covers; a larger artifact
    /// simply hashes wrong and is rejected by the verifier, never a panic).
    async fn read_bounded(&self, hash: &ContentHash) -> AppResult<Vec<u8>> {
        let reader = self.storage.get(hash).await?;
        let mut limited = reader.take(MAX_PROVENANCE_READ_BYTES);
        let mut buf = Vec::new();
        limited.read_to_end(&mut buf).await.map_err(|e| {
            hort_domain::error::DomainError::Invariant(format!(
                "provenance: CAS read failed for {hash}: {e}"
            ))
        })?;
        Ok(buf)
    }

    // -----------------------------------------------------------------
    // Provenance-clearance cascade (ADR 0039)
    // -----------------------------------------------------------------

    /// Cascade the verified subject's provenance clearance to the
    /// constituents its signed bytes bind (ADR 0039 cascade).
    ///
    /// The constituent set derives from the subject's **verified CAS
    /// bytes** — never from DB edges (`content_references` /
    /// `oci_index_member` rows are mutable projections; the signed bytes
    /// are the cryptographic authority). An image index yields its
    /// `manifests[]` children plus, per child manifest read back from CAS,
    /// that manifest's `config`/`layers` digests; a single-image manifest
    /// yields its own `config`/`layers`. Each digest sits inside its signed
    /// parent's bytes (a Merkle-like chain), so the signature over the
    /// subject digest covers exactly these constituents — and nothing else.
    ///
    /// Best-effort end to end: the subject's own clearance is already
    /// committed when this runs, and no failure here may retract or block
    /// it — every error is `warn!` + continue. Only the provenance
    /// authority cascades; the scan gate and observation window stay
    /// per-artifact (ADR 0007 / ADR 0043).
    async fn cascade_clearance(
        &self,
        repository_id: Uuid,
        subject_hash: &ContentHash,
        subject_bytes: &[u8],
        signer: &SignerIdentity,
        predicate_type: Option<&str>,
        backend: &str,
    ) {
        let digests = match self.constituent_digests(subject_bytes).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    subject = %subject_hash,
                    error = %e,
                    "provenance cascade: subject bytes did not parse as an OCI \
                     index/manifest — cascading to nothing",
                );
                return;
            }
        };

        let mut cascaded = 0usize;
        for digest in &digests {
            // Defensive self-reference guard: a subject cannot reference its
            // own hash in real content (self-referential digest), but the
            // cascade must never re-append to the subject's stream.
            if digest == subject_hash {
                continue;
            }
            match self
                .cascade_one(
                    repository_id,
                    subject_hash,
                    digest,
                    signer,
                    predicate_type,
                    backend,
                )
                .await
            {
                Ok(true) => cascaded += 1,
                Ok(false) => {}
                Err(e) => tracing::warn!(
                    subject = %subject_hash,
                    constituent = %digest,
                    error = %e,
                    "provenance cascade: constituent clearance failed — skipped",
                ),
            }
        }
        if cascaded > 0 {
            tracing::info!(
                subject = %subject_hash,
                constituents = cascaded,
                backend = %backend,
                "provenance: cascaded clearance to signed constituents",
            );
        }
    }

    /// Derive the constituent digest set from the verified subject bytes.
    ///
    /// Index → `manifests[]` children (capped by the domain's
    /// `MAX_INDEX_CHILDREN`) plus each child manifest's `config`/`layers`
    /// digests read back from the child's own CAS bytes (capped per
    /// manifest by `MAX_MANIFEST_BLOBS`); single-image manifest → its own
    /// `config`/`layers`. A child whose CAS bytes cannot be read or parsed
    /// contributes the child digest itself (it is bound into the signed
    /// index bytes regardless) but no blobs — `warn!` + continue.
    /// Deduplicated (a blob shared across children appears once),
    /// order-preserving.
    async fn constituent_digests(&self, subject_bytes: &[u8]) -> AppResult<Vec<ContentHash>> {
        let mut out: Vec<ContentHash> = Vec::new();
        if hort_domain::oci::is_image_index(subject_bytes) {
            for child in hort_domain::oci::index_child_digests(subject_bytes)? {
                out.push(child.clone());
                let child_bytes = match self.read_bounded(&child).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            child = %child,
                            error = %e,
                            "provenance cascade: child manifest CAS read failed — \
                             its config/layer blobs are not cascaded",
                        );
                        continue;
                    }
                };
                match hort_domain::oci::manifest_blob_digests(&child_bytes) {
                    Ok(blobs) => out.extend(blobs),
                    Err(e) => tracing::warn!(
                        child = %child,
                        error = %e,
                        "provenance cascade: child manifest did not parse — \
                         its config/layer blobs are not cascaded",
                    ),
                }
            }
        } else {
            out.extend(hort_domain::oci::manifest_blob_digests(subject_bytes)?);
        }
        let mut seen = std::collections::HashSet::new();
        out.retain(|h| seen.insert(h.clone()));
        Ok(out)
    }

    /// Cascade the clearance to ONE constituent digest. Returns `Ok(true)`
    /// when a cascaded `ProvenanceVerified` was committed, `Ok(false)` on
    /// the deliberate skips:
    ///
    /// - no artifact row for the digest **in the subject's repository**
    ///   (the lookup is repo-scoped — a same-digest artifact in another
    ///   repo is never touched);
    /// - a constituent that is not currently held (the domain guard in
    ///   [`Artifact::cascade_provenance_clearance`] refuses every
    ///   non-`Quarantined` state — terminally rejected stays rejected,
    ///   `Released`/status-`None` need no clearance);
    /// - a constituent already carrying a `ProvenanceVerified` (its own
    ///   verification or an earlier cascade) — idempotent re-runs append
    ///   no duplicate.
    async fn cascade_one(
        &self,
        repository_id: Uuid,
        subject_hash: &ContentHash,
        digest: &ContentHash,
        signer: &SignerIdentity,
        predicate_type: Option<&str>,
        backend: &str,
    ) -> AppResult<bool> {
        let Some(constituent) = self
            .artifacts
            .find_by_repo_and_checksum(repository_id, digest)
            .await?
        else {
            return Ok(false);
        };

        // The domain guard: only a held (`Quarantined`) constituent takes
        // a cascaded clearance. The `Err` is the guard refusing a
        // non-held state — a deliberate skip, not an infra failure.
        let Ok(event) = constituent.cascade_provenance_clearance(
            subject_hash.clone(),
            signer.clone(),
            predicate_type.map(str::to_string),
            backend,
        ) else {
            tracing::debug!(
                artifact_id = %constituent.id,
                status = %constituent.quarantine_status,
                "provenance cascade: constituent not held — skipped",
            );
            return Ok(false);
        };

        let (cleared, expected_version) = self.read_clearance_state(constituent.id).await?;
        if cleared.is_some() {
            return Ok(false);
        }

        // Append at the just-read version. A version conflict means a
        // concurrent append bumped the stream between the read and this
        // append (the constituent's own `ScanCompleted` is the realistic
        // race — scan and sign both land seconds after push): re-read
        // once, re-check idempotency (the concurrent event may itself
        // have been a `ProvenanceVerified`), and re-append at the fresh
        // version. ONE retry only — a second conflict, or any
        // non-conflict error, propagates to the caller's warn+skip.
        if let Err(err) = self
            .commit_cascade_event(&constituent, event.clone(), expected_version)
            .await
        {
            if !matches!(err, hort_domain::error::DomainError::Conflict(_)) {
                return Err(err.into());
            }
            tracing::debug!(
                artifact_id = %constituent.id,
                "provenance cascade: version conflict — retrying once with a fresh read",
            );
            let (cleared, fresh_version) = self.read_clearance_state(constituent.id).await?;
            if cleared.is_some() {
                return Ok(false);
            }
            self.commit_cascade_event(&constituent, event, fresh_version)
                .await?;
        }

        tracing::info!(
            artifact_id = %constituent.id,
            constituent = %digest,
            subject = %subject_hash,
            backend = %backend,
            "provenance: clearance cascaded from verified subject",
        );
        Ok(true)
    }

    /// Append one cascaded `ProvenanceVerified` to `constituent`'s stream
    /// at `expected_version`. Split out of [`Self::cascade_one`] so the
    /// version-conflict retry re-appends through the identical path;
    /// returns the raw [`DomainResult`] so the caller can match the
    /// event store's `Conflict` shape before converting to `AppError`.
    async fn commit_cascade_event(
        &self,
        constituent: &Artifact,
        event: hort_domain::events::ProvenanceVerified,
        expected_version: ExpectedVersion,
    ) -> hort_domain::error::DomainResult<()> {
        self.lifecycle
            .commit_transition(
                constituent,
                AppendEvents {
                    stream_id: hort_domain::events::StreamId::artifact(constituent.id),
                    expected_version,
                    events: vec![EventToAppend::new(DomainEvent::ProvenanceVerified(event))],
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor: system_actor(),
                },
                None,
            )
            .await
            .map(|_| ())
    }

    /// Read the artifact's event stream once, reporting the existing
    /// `ProvenanceVerified` (if any) plus the expected version for a
    /// subsequent append — a single read serving the already-cleared
    /// verify skip (which inspects the event's `cascaded_from` / signer
    /// for the cascade re-drive) and the cascade's idempotency check +
    /// append.
    async fn read_clearance_state(
        &self,
        artifact_id: Uuid,
    ) -> AppResult<(
        Option<hort_domain::events::ProvenanceVerified>,
        ExpectedVersion,
    )> {
        let stream_id = hort_domain::events::StreamId::artifact(artifact_id);
        let persisted = self
            .events
            .read_stream(&stream_id, ReadFrom::Start, STREAM_READ_LIMIT)
            .await?;
        let cleared = persisted.iter().find_map(|e| match &e.event {
            DomainEvent::ProvenanceVerified(ev) => Some(ev.clone()),
            _ => None,
        });
        let expected = match persisted.last() {
            Some(last) => ExpectedVersion::Exact(last.stream_position),
            None => ExpectedVersion::NoStream,
        };
        Ok((cleared, expected))
    }

    // -----------------------------------------------------------------
    // Verdict dispatch / fold / apply
    // -----------------------------------------------------------------

    /// Dispatch each applicable verifier and fold the verdicts to one. In
    /// the Tier-1 single-verifier deployment this is a single call; the
    /// fold rule keeps the orchestrator total for a future multi-verifier
    /// set:
    ///
    /// - any `Rejected` verdict wins (most restrictive — a forged/untrusted
    ///   signature from any verifier rejects the artifact);
    /// - else any `Verified` verdict wins (a trusted signature from any
    ///   verifier clears it);
    /// - else `NoAttestation` (no verifier found a bundle).
    ///
    /// A verifier that itself errors (an adapter bug / infra fault) is
    /// folded mode-dependently: under `Required` it contributes a
    /// `Rejected{RekorNotFound}` (fail-closed); under `VerifyIfPresent` it
    /// is treated as `NoAttestation` (the verifier could not decide; do
    /// not block on flakiness).
    async fn dispatch_and_fold(
        &self,
        applicable: &[&Arc<dyn ProvenancePort>],
        subject: &ProvenanceSubject<'_>,
        bundles: &[AttestationBundle],
        requirements: &ProvenanceRequirements<'_>,
        mode: ProvenanceMode,
    ) -> (ProvenanceVerdict, String) {
        use hort_domain::ports::provenance::ProvenanceOutcome;

        let mut folded: Option<(ProvenanceVerdict, String)> = None;
        for port in applicable {
            let verdict = match port.verify(subject, bundles, requirements).await {
                Ok(v) => v,
                Err(e) => {
                    // Verifier infra fault. Mode decides fail-closed vs
                    // degrade-to-allow.
                    tracing::warn!(
                        backend = port.name(),
                        error = %e,
                        "provenance verifier errored; folding mode-dependently",
                    );
                    match mode {
                        ProvenanceMode::Required => {
                            ProvenanceVerdict::rejected(ProvenanceRejectReason::RekorNotFound)
                        }
                        ProvenanceMode::VerifyIfPresent | ProvenanceMode::Off => {
                            ProvenanceVerdict::no_attestation()
                        }
                    }
                }
            };
            // Carry the deciding backend alongside the verdict so the metric
            // labels the verifier that produced the folded result, not
            // `applicable[0]` (ADR 0039 §6).
            let candidate = (verdict, port.name().to_string());
            folded = Some(match folded {
                None => candidate,
                Some(prev) => fold_two_backend(prev, candidate),
            });
        }
        // `applicable` is non-empty (checked by the caller), so `folded`
        // is always `Some`. Defensive default keeps the fn total.
        folded.unwrap_or_else(|| {
            (
                ProvenanceVerdict {
                    outcome: ProvenanceOutcome::NoAttestation,
                },
                String::new(),
            )
        })
    }

    /// Apply a folded verdict via [`Artifact::complete_provenance`] and
    /// persist the returned event (if any). Mirrors how scan orchestration
    /// persists `ScanCompleted` through the lifecycle port.
    async fn apply_verdict(
        &self,
        mut artifact: Artifact,
        backend: &str,
        verdict: ProvenanceVerdict,
        mode: ProvenanceMode,
        window_open: bool,
    ) -> AppResult<ProvenanceRunOutcome> {
        // Under `Required` an unsigned-but-still-in-window artifact is HELD
        // (issue #13): `complete_provenance` returns `Ok(None)` and leaves
        // the status `Quarantined` → the release gate reads it as `Pending`
        // (fail-closed / held), not an allowed-unsigned no-op. Captured
        // before the value is moved into `complete_provenance` so the `None`
        // branch can distinguish the hold from the VerifyIfPresent/Off allow.
        let held_pending_signature = mode == ProvenanceMode::Required
            && window_open
            && matches!(
                verdict.outcome,
                hort_domain::ports::provenance::ProvenanceOutcome::NoAttestation
            );
        let event = artifact.complete_provenance(verdict, mode, backend, window_open)?;

        let Some(event) = event else {
            if held_pending_signature {
                // Hold-pending-signature: no event, status stays Quarantined.
                // `info!` (no `err`) — the operator audit signal that an image
                // is waiting to be signed. Ticks the distinct
                // `held_pending_signature` result value (NOT `no_attestation`),
                // so a `Required` hold is separable from the allowed-unsigned
                // no-op. Single emission layer — the orchestration use case.
                tracing::info!(
                    artifact_id = %artifact.id,
                    backend = %backend,
                    "provenance held pending signature (Required, observation window open)",
                );
                crate::metrics::emit_provenance_verify(
                    backend,
                    mode,
                    crate::metrics::ProvenanceVerifyResult::HeldPendingSignature,
                );
                return Ok(ProvenanceRunOutcome::Applied {
                    event_appended: false,
                    verdict: ProvenanceVerdictSummary::HeldPendingSignature,
                });
            }
            // NoAttestation under VerifyIfPresent / Off — no event, status
            // unchanged. The allowed-unsigned case ticks `no_attestation`
            // (no reject sibling). Single emission layer — the
            // orchestration use case.
            crate::metrics::emit_provenance_verify(
                backend,
                mode,
                crate::metrics::ProvenanceVerifyResult::NoAttestation,
            );
            return Ok(ProvenanceRunOutcome::Applied {
                event_appended: false,
                verdict: ProvenanceVerdictSummary::NoAttestation,
            });
        };

        // Tracing: info! on the supply-chain decision — audit signal, not
        // `err`. Domain stays tracing-free. Metrics fire alongside, once
        // per applied verdict, at this single layer:
        // `hort_provenance_verify_total{backend, mode, result}` always, +
        // `hort_provenance_reject_total{backend, reason}` on a rejection.
        // The coarse verdict bucket surfaced to the task handler's
        // `result_summary`. Derived from the same event the
        // metrics below tick — Verified / Rejected(reason); a non-provenance
        // event here is unreachable (`complete_provenance` only ever emits
        // these two), so the defensive default keeps the match total.
        let verdict_summary = match &event {
            DomainEvent::ProvenanceVerified(e) => {
                tracing::info!(
                    artifact_id = %artifact.id,
                    backend = %e.backend,
                    "provenance verified",
                );
                crate::metrics::emit_provenance_verify(
                    backend,
                    mode,
                    crate::metrics::ProvenanceVerifyResult::Verified,
                );
                ProvenanceVerdictSummary::Verified
            }
            DomainEvent::ProvenanceRejected(e) => {
                tracing::info!(
                    artifact_id = %artifact.id,
                    backend = %e.backend,
                    reason = ?e.reason,
                    "provenance rejected",
                );
                crate::metrics::emit_provenance_verify(
                    backend,
                    mode,
                    crate::metrics::ProvenanceVerifyResult::Rejected,
                );
                crate::metrics::emit_provenance_reject(backend, e.reason);
                ProvenanceVerdictSummary::Rejected(e.reason)
            }
            _ => ProvenanceVerdictSummary::NoAttestation,
        };

        let stream_id = hort_domain::events::StreamId::artifact(artifact.id);
        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;
        let correlation_id = Uuid::new_v4();

        self.lifecycle
            .commit_transition(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![EventToAppend::new(event)],
                    correlation_id,
                    causation_id: None,
                    actor: system_actor(),
                },
                None,
            )
            .await?;

        Ok(ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: verdict_summary,
        })
    }

    /// Handle a bundle-fetch / CAS-read failure mode-dependently:
    ///
    /// - `Required` → fail-closed `Rejected{RekorNotFound}` (a never-
    ///   verified `Required` artifact must never timer-release);
    /// - `VerifyIfPresent` / `Off` → degrade to `NoAttestation` (allow —
    ///   never fail-closed on infra flakiness).
    ///
    /// `window_open` is threaded to `apply_verdict` for signature parity with
    /// the verdict path, but is **inert on the `Required` arm**: a fetch
    /// failure produces a `Rejected{RekorNotFound}` verdict, and
    /// `complete_provenance`'s `Rejected` arm never consults `window_open` — a
    /// fetch failure is NOT an unsigned-hold, so it stays fail-closed even
    /// mid-window (issue #13, design §2 S1). Threading the value through does
    /// not weaken this.
    async fn apply_fetch_failure(
        &self,
        artifact: Artifact,
        backend: &str,
        mode: ProvenanceMode,
        window_open: bool,
        stage: &str,
        err: crate::error::AppError,
    ) -> AppResult<ProvenanceRunOutcome> {
        match mode {
            ProvenanceMode::Required => {
                tracing::warn!(
                    artifact_id = %artifact.id,
                    stage,
                    error = %err,
                    "provenance: fetch exhausted under Required — fail-closed (RekorNotFound)",
                );
                // `RekorNotFound` is the backend-AGNOSTIC fail-closed-fetch reason
                // here ("no verifiable attestation material was obtained"). The keyed
                // `cosign-key` backend has no Rekor, but reuses this marker rather than
                // growing the enum — the audit event's `backend` label disambiguates
                // which backend's fetch failed.
                let verdict = ProvenanceVerdict::rejected(ProvenanceRejectReason::RekorNotFound);
                self.apply_verdict(artifact, backend, verdict, mode, window_open)
                    .await
            }
            ProvenanceMode::VerifyIfPresent | ProvenanceMode::Off => {
                tracing::warn!(
                    artifact_id = %artifact.id,
                    stage,
                    error = %err,
                    "provenance: fetch exhausted under VerifyIfPresent — \
                     degrade to NoAttestation (allow)",
                );
                let verdict = ProvenanceVerdict::no_attestation();
                self.apply_verdict(artifact, backend, verdict, mode, window_open)
                    .await
            }
        }
    }
}

/// Parse an OCI `sha256:<hex>` digest string into a CAS [`ContentHash`].
/// Only `sha256` maps to the CAS keyspace; any other algorithm or malformed
/// hex yields `None` (the caller skips that referrer). Mirrors the private
/// helper in `hort_domain::oci`; kept local because the orchestrator parses a
/// *referrer descriptor* digest string (not a manifest layer) and the domain
/// helper is intentionally not exported.
fn parse_sha256_digest(digest: &str) -> Option<ContentHash> {
    digest.strip_prefix("sha256:")?.parse().ok()
}

/// Decode a base64 `dev.cosignproject.cosign/signature` annotation into raw
/// signature bytes (ADR 0039 §8). cosign emits standard-alphabet base64. A
/// malformed annotation yields `None` — the carriage skips it; it can never be
/// a valid signature, and under `Required` the absence of any valid bundle
/// folds to `Rejected{Unsigned}`.
fn decode_simplesigning_signature(annotation: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(annotation.trim())
        .ok()
}

/// Wrap a Sigstore v0.3 bundle blob as the right [`AttestationBundle`] shape so
/// the two verifiers self-select (ADR 0039 §6/§8):
///
/// - a **cosign v3 keyed** bundle (a v0.3 bundle whose `verificationMaterial`
///   is a bare `publicKey`, no Fulcio cert) → `new_signed(bytes, raw DSSE sig)`,
///   so the keyed `cosign-key` verifier claims it (its loop requires
///   `signature.is_some()`) and the Sigstore verifier skips it. The keyed
///   verifier re-derives the DSSE PAE + subject digest from `bytes`; the
///   `signature` half both flips the routing gate and carries the raw sig it
///   verifies.
/// - a **keyless** bundle (Fulcio cert chain), or any bundle the keyed
///   extractor does not claim / cannot parse → `new(bytes)` (`signature =
///   None`), routed to the Sigstore verifier unchanged (byte-for-byte the prior
///   behaviour).
fn build_bundle(bytes: Vec<u8>) -> AttestationBundle {
    match hort_domain::provenance_bundle::extract_keyed_dsse_signature(&bytes) {
        Ok(Some(material)) => AttestationBundle::new_signed(bytes, material.signature),
        // Keyless, or not a keyed DSSE bundle, or unparseable-as-keyed: the
        // Sigstore verifier's (a truly malformed bundle folds to
        // BundleMalformed there). Never route a non-keyed bundle to the keyed
        // verifier.
        Ok(None) | Err(_) => AttestationBundle::new(bytes),
    }
}

/// Fold two verdicts to one (the multi-verifier fold rule). `Rejected`
/// dominates `Verified` dominates `NoAttestation`. Pure helper — testable
/// without the use case.
fn fold_two(a: ProvenanceVerdict, b: ProvenanceVerdict) -> ProvenanceVerdict {
    use hort_domain::ports::provenance::ProvenanceOutcome::{NoAttestation, Rejected, Verified};
    match (&a.outcome, &b.outcome) {
        (Rejected(_), _) => a,
        (_, Rejected(_)) => b,
        (Verified { .. }, _) => a,
        (_, Verified { .. }) => b,
        (NoAttestation, NoAttestation) => a,
    }
}

/// Fold two `(verdict, backend)` candidates — [`fold_two`] plus backend
/// attribution. The returned backend names the verifier whose verdict won, so
/// the metric labels the deciding backend rather than `applicable[0]`
/// (ADR 0039 §6). Pure helper — testable without the use case.
fn fold_two_backend(
    a: (ProvenanceVerdict, String),
    b: (ProvenanceVerdict, String),
) -> (ProvenanceVerdict, String) {
    if fold_two(a.0.clone(), b.0.clone()) == a.0 {
        a
    } else {
        b
    }
}

#[cfg(test)]
#[path = "provenance_orchestration_tests.rs"]
mod tests;
