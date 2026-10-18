//! Provenance-orchestration use case (ADR 0027).
//!
//! The worker-side flow for the `provenance-verify` job: load the
//! artifact + its resolved `ScanPolicy`, fetch the attestation bundles
//! (OCI: the Referrers / content-reference surface — possibly empty),
//! stream the artifact preimage from CAS, dispatch each applicable
//! [`ProvenancePort`], fold the per-verifier verdicts to one, and apply
//! [`Artifact::complete_provenance`] — persisting the returned events (if
//! any) via the artifact lifecycle port.
//!
//! # An unsigned artifact is held, never rejected
//!
//! A `NoAttestation` verdict under [`ProvenanceMode::Required`] HOLDS the
//! artifact (`Quarantined`, `Pending` at the release gate, 503 to a pull)
//! indefinitely — it is a statement about a point in time, not about the
//! artifact, and with cosign the signature necessarily follows the subject
//! it signs. Only a positive disproof (a signature that is present and
//! invalid) is terminal. See ADR 0039's 2026-09-12 amendment, D1–D4.
//!
//! Mirrors [`ScanOrchestrationUseCase`](super::scan_orchestration::ScanOrchestrationUseCase):
//! port-only `Arc<dyn _Port>` dependencies, no concrete use-case handles.
//!
//! # Fail-closed semantics
//!
//! - A bundle-fetch / CAS-read failure that retries cannot resolve is
//!   `Indeterminate{AttestationFetchFailed}` in every mode — the material
//!   was never seen, so nothing about the artifact was established.
//!   Under [`ProvenanceMode::Required`] the artifact HOLDS: no event, so
//!   a **never-verified** `Required` artifact still never timer-releases
//!   (it stays `Pending` in the release sweep's clearance computation).
//!   Fail-closed, and not terminal — terminality needs a positive
//!   disproof (ADR 0039 D2/D4).
//! - A dispatched verifier that returns `Err` — an adapter fault, a
//!   trust root that cannot build a verifier, a subject-payload
//!   mismatch — is `Indeterminate{VerifierUnavailable}`, again in every
//!   mode: it returned no verdict, so nothing about the artifact was
//!   established. The consequence is the fetch failure's, for the same
//!   reason. It contributes a verdict rather than nothing, so that an
//!   all-verifiers-errored run does not fold to `NoAttestation` and
//!   report an unsigned artifact for a fault of ours.
//! - Under [`ProvenanceMode::VerifyIfPresent`], the same unresolved
//!   infra/fetch/verifier failure is allowed through — it must NEVER make
//!   the proxy fail-closed on flakiness — and reports
//!   `allowed_indeterminate` rather than the allowed-unsigned value, so
//!   an unreachable upstream does not read as an unsigned artifact.
//!   `VerifyIfPresent` only ever *adds* a rejection on a forged/untrusted
//!   signature.
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

use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::entities::scan_policy::ProvenanceMode;
use hort_domain::events::{system_actor, ArtifactIngested, DomainEvent, IngestSource};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::{
    ContentReference, ContentReferenceClaim, ContentReferenceIndex,
};
use hort_domain::ports::event_store::{AppendEvents, EventToAppend, ExpectedVersion};
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::provenance::{
    AttestationBundle, IndeterminateReason, ProvenancePort, ProvenanceRejectReason,
    ProvenanceRequirements, ProvenanceSubject, ProvenanceVerdict,
};
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping;
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::upstream_proxy::{IdentityProjector, UpstreamProxy};
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_domain::types::ContentHash;

use tokio_util::io::StreamReader;

use crate::error::AppResult;
use crate::event_store_publisher::EventStorePublisher;
use crate::use_cases::policy_resolution::resolve_active_policy_for_repo;
use crate::use_cases::provenance_cascade::ProvenanceCascade;
use crate::use_cases::{
    read_unpaired_append_version, ArtifactAtVersion, OverCapStream, UnpairedAppend,
};

/// The `kind` filter used to read cosign attestation bundles off the
/// content-reference / OCI Referrers surface. A cosign signature manifest
/// is recorded as an `"oci_subject"` row pointing AT the signed artifact's
/// content hash (the OCI Referrers projection).
const OCI_SUBJECT_KIND: &str = "oci_subject";

/// Number of attempts (1 initial + N-1 retries) the orchestrator makes to
/// fetch the bundle set / read the CAS preimage before giving up. On
/// exhaustion the verdict is `Indeterminate{AttestationFetchFailed}`
/// whatever the mode; the mode decides only the consequence (`Required` →
/// a hold, `VerifyIfPresent` / `Off` → allowed through). See
/// `apply_fetch_failure`.
const FETCH_ATTEMPTS: u32 = 3;

/// Bounded grace window (issue #90 defense-in-depth) — see `apply_verdict`.
/// A `NoAttestation`×`Required` verdict on a `None`-status, anchor-less
/// artifact requeues instead of terminally rejecting only while the
/// artifact is younger than this. `IngestUseCase::ingest_inner` now commits
/// `ArtifactIngested` + `ArtifactQuarantined` atomically, so a job it
/// enqueues can never observe this shape from THAT race anymore — this
/// grace window exists purely as a backstop against any other/future
/// dual-commit path exhibiting the same symptom, and against clock/replica
/// skew. A steady-state PERMISSIVE artifact (`quarantine_duration_secs ==
/// 0`) shows the identical shape forever, so the window must stay short:
/// generous enough for at least one of the dispatcher's own retries to
/// land inside it, short enough that a permissive artifact still resolves
/// to its correct terminal decision within a few minutes, not
/// indefinitely.
///
/// The gate is the artifact's *age*, not a retry count, so the shared
/// retry curve (`crate::retry_backoff::compute_backoff`) decides only
/// how much of the attempt budget the window costs. At its 1/5/30/60-min
/// shape a requeued verify re-runs at ~60 s — inside the window — and
/// again at ~360 s, by which point the artifact is past it and the
/// verdict is applied: two of five attempts spent, leaving budget for a
/// genuine infrastructure failure afterwards.
const PROVENANCE_ANCHOR_GRACE_SECS: i64 = 300;

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
    /// A typed rejection (`ProvenanceRejected` + its `ArtifactRejected`
    /// companion emitted), carrying the typed reason. Only ever a
    /// verifier's **positive disproof** about material it could read: a
    /// fetch that never landed holds instead (ADR 0039 D4).
    Rejected(ProvenanceRejectReason),
    /// No bundle was found / passed and the mode allowed it
    /// (`VerifyIfPresent`/`Off` no-op, no event) — a previously-silent
    /// case, made observable here.
    NoAttestation,
    /// A `Required`-mode **subject** was found unsigned: no event, status
    /// stays `Quarantined` (HELD, read as `Pending` by the release gate).
    /// Distinct from `NoAttestation` so the task handler's `result_summary`
    /// separates "waiting to be signed" from "allowed unsigned".
    HeldPendingSignature,
    /// A `Required`-mode **constituent** (an OCI config/layer blob) was
    /// found unsigned: no event, status stays `Quarantined` (HELD).
    /// Distinct from [`Self::HeldPendingSignature`] because nothing is
    /// waiting for *this* row to be signed — it can never carry its own
    /// attestation. It is waiting for its **subject** to arrive and clear
    /// it via the cascade or the late-joiner self-clear, which is a
    /// different operator action (push/sign the parent, not this row).
    HeldPendingSubject,
    /// A `Required`-mode artifact whose verification **could not be
    /// carried out**: no event, status stays `Quarantined` (HELD).
    /// Distinct from the two above because the thing to fix is on *our*
    /// side — a trust root with no usable key, attestation material that
    /// could never be fetched, a verifier that returned no verdict — and
    /// nothing about the artifact was established, so nothing was
    /// disproved (ADR 0039 D4).
    HeldIndeterminate,
    /// The same could-not-check verdict under `VerifyIfPresent` / `Off`:
    /// no event, status unchanged, and the artifact runs its normal
    /// quarantine window and releases. **Not** a hold.
    ///
    /// Distinct from [`Self::NoAttestation`] for the reason that value
    /// could not carry: `no_attestation` says the artifact has no
    /// signature, and here the artifact's signature is not what failed —
    /// our trust root had no usable key, the material never arrived, or
    /// our verifier returned no verdict. An operator reading "allowed
    /// unsigned" off a permissive scope whose upstream is unreachable
    /// goes looking at the publisher's signing pipeline, the one place
    /// the fault is not.
    AllowedIndeterminate,
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
    /// cleared artifact is wasted work at best: a cascade-cleared
    /// constituent has no referrer surface of its own (cosign signs only
    /// the top-level digest), so re-running the pipeline would resolve
    /// `NoAttestation` and re-hold an already-cleared artifact's job for
    /// no outcome. `Required` mode only.
    SkippedAlreadyCleared,
    /// A verdict was produced and applied. `event_appended` is `true` when
    /// `complete_provenance` emitted events (Verified / Rejected) and
    /// `false` for the `NoAttestation` hold / allowed-unsigned no-op.
    /// `verdict` carries the coarse outcome bucket the task handler maps to
    /// `result_summary`.
    Applied {
        event_appended: bool,
        verdict: ProvenanceVerdictSummary,
        /// How many candidates the verifier(s) skipped as unreadable
        /// while reaching this verdict — the sum across every verifier
        /// that ran (see
        /// [`ProvenanceVerdict::unreadable_skipped`](hort_domain::ports::provenance::ProvenanceVerdict::unreadable_skipped)).
        /// Carried so the job's `result_summary` can name it: the
        /// material was not *considered*, which must not become not
        /// *noticed*. Reporting only — it gates nothing.
        unreadable_skipped: u32,
    },
    /// The artifact is the **signature material of a subject the
    /// verifier accepts** (ADR 0039 D8): the folded verdict was
    /// `NoAttestation` under `Required`, and a signature manifest that
    /// binds this artifact's digest had its bundle verified against the
    /// subject it names. A cascaded `ProvenanceVerified` was committed —
    /// so no hold was applied and no `NoAttestation` verdict reached
    /// `complete_provenance`. Distinct from
    /// [`Self::Applied`]`{verdict: Verified}` because this artifact holds
    /// no direct verification of its own: the authority is another
    /// artifact's signature, recorded in the event's `cascaded_from`.
    ClearedAsSignatureMaterial {
        /// The skip count from the folded verdict, carried for the same
        /// reason [`Self::Applied`] carries it: this path returns before
        /// `apply_verdict`, and a candidate someone attached to a
        /// signature payload must still be reported.
        unreadable_skipped: u32,
    },
    /// Defense-in-depth bounded requeue (issue #90): a `NoAttestation`
    /// verdict under `Required` on a `None`-status, anchor-less,
    /// recently-ingested artifact. No verdict was applied — no event, no
    /// state transition — the task handler maps this to a retryable
    /// `TaskOutcome::Failed` so the dispatcher re-runs the verify with its
    /// normal backoff once the (expected, imminent) quarantine commit
    /// lands. See [`PROVENANCE_ANCHOR_GRACE_SECS`].
    RequeuedNoAnchor,
}

/// What a HOLD under `Required` is waiting for.
///
/// **Reporting only — never a gate.** Both held verdicts hold
/// unconditionally — `NoAttestation` under ADR 0039's 2026-09-12 amendment
/// (D1/D3), `Indeterminate` under D4 — so this type decides nothing about
/// the outcome; it only says *what the operator is waiting for*, which
/// under D4's indefinite hold is the one thing the observability has to
/// answer: `PendingSignature` means "this artifact may still be signed"
/// (sign it); `PendingSubject` means "this artifact will never be signed
/// on its own — its subject must arrive and clear it" (push/sign the
/// parent); `Indeterminate` means "we could not check" (fix the trust
/// root or the verifier, or the fetch will be retried) — the only one of
/// the three whose action is on *our* side rather than the publisher's.
/// Keeping the mapping to the log line, the metric label and the job's
/// `result_summary` on one type is what stops the three from drifting
/// apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HoldReason {
    /// A subject — a row that could carry an attestation of its own.
    PendingSignature,
    /// A constituent that can never carry its own attestation.
    PendingSubject,
    /// The check could not be carried out at all — nothing about the
    /// artifact was established, so nothing was disproved. Carries no
    /// [`hort_domain::ports::provenance::IndeterminateReason`]: the
    /// operator answer is the same for all of them ("we could not
    /// check"), and the specific reason rides the verdict's own audit
    /// trail rather than splitting a reporting label three ways.
    Indeterminate,
}

impl HoldReason {
    fn metric_result(self) -> crate::metrics::ProvenanceVerifyResult {
        match self {
            Self::PendingSignature => crate::metrics::ProvenanceVerifyResult::HeldPendingSignature,
            Self::PendingSubject => crate::metrics::ProvenanceVerifyResult::HeldPendingSubject,
            Self::Indeterminate => crate::metrics::ProvenanceVerifyResult::HeldIndeterminate,
        }
    }

    fn verdict_summary(self) -> ProvenanceVerdictSummary {
        match self {
            Self::PendingSignature => ProvenanceVerdictSummary::HeldPendingSignature,
            Self::PendingSubject => ProvenanceVerdictSummary::HeldPendingSubject,
            Self::Indeterminate => ProvenanceVerdictSummary::HeldIndeterminate,
        }
    }

    fn log_message(self) -> &'static str {
        match self {
            Self::PendingSignature => {
                "provenance held pending signature (Required; no attestation has reached \
                 Hort yet — the hold is indefinite and lifts when one does)"
            }
            Self::PendingSubject => {
                "provenance held pending subject (Required; a constituent carries no \
                 attestation of its own and is cleared by its subject's cascade or the \
                 late-joiner self-clear)"
            }
            Self::Indeterminate => {
                "provenance held — the check could not be carried out (Required; no usable \
                 trust-root key, attestation material that could not be fetched, or a \
                 verifier that returned no verdict. Nothing about the artifact was \
                 established, so nothing is terminal: fix the trust root or the verifier, \
                 or the fetch is retried)"
            }
        }
    }
}

/// What an **empty event batch** from [`Artifact::complete_provenance`]
/// has to report — the one question the batch cannot answer about itself.
///
/// The domain emits the identical (absent) transition for an unsigned
/// artifact and for a check that could not be carried out, under every
/// mode: `Required` holds, `VerifyIfPresent` / `Off` allow. Four readings,
/// one shape. By the time the batch comes back the verdict has been moved
/// into the domain, so the outcome × mode reading is taken *before* the
/// call and carried here.
///
/// It exists rather than a bare `Option<HoldReason>` because the
/// permissive half needs the same separation the held half got. A
/// `VerifyIfPresent` scope whose trust root is unusable, or whose
/// attestation material never arrived, must not report the
/// allowed-unsigned value: that names the **artifact's** state when the
/// fault is on *our* side, and sends an operator to the publisher's
/// signer instead of to their own provisioning. Both reportings live on
/// one type for the reason [`HoldReason`]'s three do — a reading that
/// reached the metric and not the job row, or the reverse, would show up
/// in a dashboard and not in the forensic trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoEventReport {
    /// A `Required`-mode HOLD — [`HoldReason`] says which, and owns the
    /// operator-facing wording.
    Held(HoldReason),
    /// `VerifyIfPresent` / `Off` let an unsigned artifact through: the
    /// allowed-unsigned no-op.
    AllowedUnsigned,
    /// `VerifyIfPresent` / `Off` let through an artifact whose check
    /// could not be carried out at all. The artifact proceeds exactly as
    /// the unsigned case does — normal quarantine window, normal release
    /// — and the reporting is the only thing that differs, which is the
    /// whole point of the value.
    AllowedIndeterminate,
}

impl NoEventReport {
    fn metric_result(self) -> crate::metrics::ProvenanceVerifyResult {
        match self {
            Self::Held(reason) => reason.metric_result(),
            Self::AllowedUnsigned => crate::metrics::ProvenanceVerifyResult::NoAttestation,
            Self::AllowedIndeterminate => {
                crate::metrics::ProvenanceVerifyResult::AllowedIndeterminate
            }
        }
    }

    fn verdict_summary(self) -> ProvenanceVerdictSummary {
        match self {
            Self::Held(reason) => reason.verdict_summary(),
            Self::AllowedUnsigned => ProvenanceVerdictSummary::NoAttestation,
            Self::AllowedIndeterminate => ProvenanceVerdictSummary::AllowedIndeterminate,
        }
    }

    /// The `info!` line, present **only** for a hold.
    ///
    /// `None` is a decision, not an omission: a hold is an operator audit
    /// signal (an image that is not yet clearable), while the allowed
    /// paths run at proxy scale on every unsigned pull-through and would
    /// be a firehose. Their rate signal is the counter and their
    /// per-artifact trail is the job's `result_summary`; the one allowed
    /// reading with something specific to say — a fetch that failed —
    /// already carries its own `warn!` naming the stage and the error,
    /// which no line here could reproduce.
    fn log_message(self) -> Option<&'static str> {
        match self {
            Self::Held(reason) => Some(reason.log_message()),
            Self::AllowedUnsigned | Self::AllowedIndeterminate => None,
        }
    }
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
    /// Shared clearance-cascade machinery (ADR 0039 §11), built from the
    /// same port handles this use case already holds. The verify-time
    /// cascade is one of its two trigger ends; the ingest-time
    /// late-joiner self-clear is the other. One implementation so the
    /// two ends can never drift on what a signature covers.
    cascade: ProvenanceCascade,
    /// Compiled-in format handlers, keyed by format string — the same
    /// `HashMap<String, Arc<dyn FormatHandler>>` shape the scan
    /// orchestrator and `PrefetchTickHandler` take from composition.
    /// Consulted for exactly one question:
    /// [`FormatHandler::is_provenance_constituent`], the pure
    /// classification of "can this row ever carry an attestation of its
    /// own?".
    format_handlers: HashMap<String, Arc<dyn FormatHandler>>,
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
        format_handlers: HashMap<String, Arc<dyn FormatHandler>>,
    ) -> Self {
        let cascade = ProvenanceCascade::new(
            Arc::clone(&artifacts),
            Arc::clone(&storage),
            Arc::clone(&lifecycle),
            Arc::clone(&events),
            Arc::clone(&content_references),
        );
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
            cascade,
            format_handlers,
        }
    }

    /// Verify the provenance of `artifact_id` and apply the verdict.
    ///
    /// Pure orchestration: loads the artifact + policy + bundles, dispatches
    /// the verifier(s), and threads the folded verdict through
    /// [`Artifact::complete_provenance`], persisting the event (if any).
    pub async fn verify_artifact(&self, artifact_id: Uuid) -> AppResult<ProvenanceRunOutcome> {
        // Pair the artifact load with the version this verify's append
        // will carry, BEFORE the bundle-fetch / CAS-preimage / verifier
        // round trip below. See `ArtifactAtVersion`'s contract: read the
        // version at commit time instead, and a scan verdict that
        // committed `ArtifactRejected` during that round trip is ALREADY
        // in the version read — so the provenance append does not
        // conflict, and `complete_provenance(Verified)`, working from the
        // stale-loaded `Quarantined`, writes that status back over
        // `Rejected`, resurrecting a rejected artifact into a
        // timer-releasable state.
        //
        // Nothing between here and the commit appends to THIS stream:
        // the referrer-landing path (`commit_referrer_manifest`) mints a
        // NEW artifact id and appends to its own stream, and the cascade
        // runs only after this artifact's own verdict has committed.
        //
        // `Err` PROPAGATES instead of skipping: this is a
        // single-artifact job, so failing it makes the dispatcher retry
        // rather than silently report a verify that never happened (the
        // bulk re-evaluation pass, where one artifact is skippable, logs
        // and continues instead).
        let paired = ArtifactAtVersion::load(
            &*self.artifacts,
            &*self.events,
            artifact_id,
            OverCapStream::Tolerate,
        )
        .await
        .inspect_err(|e| {
            tracing::warn!(
                artifact_id = %artifact_id,
                error = %e,
                "provenance verify: artifact/expected-version pairing failed; aborting this \
                 artifact (job retries)",
            );
        })?;
        let expected_version = paired.expected_version();
        let artifact = paired.into_artifact();

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

        // Constituent classification — REPORTING ONLY, never a gate. A
        // `NoAttestation` verdict under `Required` holds unconditionally
        // (ADR 0039's 2026-09-12 amendment, D1/D3), so nothing here decides
        // whether the artifact is held; it decides what the hold is waiting
        // FOR, which is what an indefinite hold's observability has to
        // answer. The format handler is asked the durable question — can
        // this row ever carry an attestation of its own? For OCI, blob rows
        // cannot (cosign signs the manifest/index digest); manifests and
        // indexes are subjects. The classification is pure and derived from
        // the artifact's own identity, so there is no I/O here and no error
        // direction to get wrong.
        //
        // An unregistered format resolves `false` — subject semantics, the
        // conservative label ("waiting for its own signature"). That is a
        // composition-root mis-registration, not a transient failure:
        // nothing would be gained by failing the job, since a retry re-reads
        // the same empty map. `warn!` so the mis-wiring is visible rather
        // than silent.
        let is_constituent = match self.format_handlers.get(&format) {
            Some(handler) => handler.is_provenance_constituent(&artifact),
            None => {
                tracing::warn!(
                    artifact_id = %artifact.id,
                    format = %format,
                    "provenance verify: no FormatHandler registered for the repo's format — \
                     treating the artifact as a provenance subject",
                );
                false
            }
        };

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
        // the whole pipeline only to resolve `NoAttestation` and report a
        // hold for an artifact that is already cleared. Skip instead.
        // `VerifyIfPresent`/`Off` never consult the clearance, so their
        // re-verify behaviour is unchanged.
        if mode == ProvenanceMode::Required {
            let (cleared, _) = self.cascade.read_clearance_state(artifact.id).await?;
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
                    match self.cascade.read_bounded(&artifact.sha256_checksum).await {
                        Ok(payload) => {
                            self.cascade
                                .cascade_clearance(
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
        // retries. A fetch failure that retries cannot resolve folds to
        // one verdict in every mode — `Indeterminate`, "we could not
        // look" — and the mode decides only whether that holds.
        // The backend label for the metrics. Tier-1 is a single verifier
        // (cosign); for a future multi-verifier set the first applicable
        // port names the metric series — the representative backend that
        // ran for this format. Captured before any fetch-failure
        // early-return so the indeterminate verdict carries the same
        // label.
        let backend = applicable[0].name().to_string();

        let mut bundles = match self
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
                        "bundle fetch",
                        e,
                        expected_version,
                    )
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
        // fetch error follows the SAME `apply_fetch_failure` path as a local
        // bundle-fetch failure: the material was never seen either way.
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
                                        "post-proxy bundle re-read",
                                        e,
                                        expected_version,
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
                                "upstream referrer fetch",
                                e,
                                expected_version,
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
                        "CAS preimage read",
                        e,
                        expected_version,
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
            .dispatch_and_fold(&applicable, &subject, &bundles, &requirements)
            .await;

        // Label every emission below with the backend that DECIDED the
        // folded verdict (ADR 0039 §6), not `applicable[0]`. The
        // dead-defensive empty case (no verifier ran — impossible since
        // `applicable` is non-empty) falls back to the representative
        // `backend`. Resolved here, directly after the fold, so the
        // unreadable-skip report and the verdict's own metric carry the
        // same label rather than two different ones.
        let metric_backend = if verdict_backend.is_empty() {
            backend
        } else {
            verdict_backend
        };

        // Material a verifier could not read contributed nothing to the
        // verdict above — not a rejection, not a hold, not evidence of any
        // kind. *Not considered* must not become *not noticed*, so the
        // count is reported here, at the one point where it is complete
        // (every verifier has run) and ahead of every early return below,
        // so no downstream path can drop it. Two real cases depend on it
        // being visible: a publisher whose own signature material is
        // broken would otherwise see only "unsigned", and an operator
        // would never learn that someone attached garbage to an artifact.
        //
        // `warn!`, not `info!` — unreadable attestation material is
        // either a broken publisher pipeline or someone writing junk to
        // the referrer surface, and neither should need a log level
        // raised to be seen. Emitted only when something was actually
        // skipped, so the ordinary path stays silent.
        let unreadable_skipped = verdict.unreadable_skipped;
        if unreadable_skipped > 0 {
            tracing::warn!(
                artifact_id = %artifact.id,
                backend = %metric_backend,
                unreadable_skipped,
                "provenance: skipped unreadable attestation candidate(s) — they could not be \
                 read, so they were not considered: no rejection, no hold, no evidence. Check \
                 what is attached to this artifact's referrer surface",
            );
            crate::metrics::emit_provenance_unreadable_skipped(&metric_backend, unreadable_skipped);
        }

        // ADR 0039 D8 — signature material is not on the provenance axis,
        // and that includes its bytes. Nothing signs a signature, so the
        // `{}` config blob and the payload layer of a cosign signature
        // manifest can never acquire an attestation of their own and
        // neither end of the §11 cascade can ever fire for them: under
        // `Required` D1 holds them and D4 holds them indefinitely, which
        // is the terminality D4 reserves for positive disproof reached by
        // another route. Resolved HERE, in the window between the folded
        // verdict and the hold, because the question is one of
        // applicability and everything it needs — the applicable
        // verifiers, the CAS, the content-reference index, the resolved
        // signer patterns — is already in scope. This is NOT a fourth
        // shape predicate on the `NoAttestation` × `Required` arm (D3
        // deleted those): the verdict stays shape-independent, and what
        // decides the clearance is another artifact's VERIFIED signature,
        // not this artifact's shape.
        if mode == ProvenanceMode::Required
            && matches!(
                verdict.outcome,
                hort_domain::ports::provenance::ProvenanceOutcome::NoAttestation
            )
        {
            if let Some(cleared) = self
                .cascade
                .resolve_signature_material_clearance(&artifact, &applicable, &requirements)
                .await
            {
                // The constituent now carries a real cascaded
                // `ProvenanceVerified` whose `cascaded_from` names the
                // signature manifest, so the release gate's provenance
                // leg (`provenance_clearance_from`: any
                // `ProvenanceVerified` on the stream) reads `Cleared`
                // without a second code path. Labelled with the verifier
                // that accepted the signature manifest's bundle.
                crate::metrics::emit_provenance_verify(
                    &cleared.backend,
                    mode,
                    crate::metrics::ProvenanceVerifyResult::ClearedSignatureMaterial,
                );
                return Ok(ProvenanceRunOutcome::ClearedAsSignatureMaterial { unreadable_skipped });
            }
        }

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
            .apply_verdict(
                artifact,
                &metric_backend,
                verdict,
                mode,
                is_constituent,
                expected_version,
            )
            .await?;

        // The cascade fires only after the subject's own clearance
        // committed (`apply_verdict` returning `Ok` on a Verified verdict
        // means the `ProvenanceVerified` event is persisted — an append
        // failure propagates above). Best-effort by construction: nothing
        // in the cascade can retract or block the already-committed
        // subject clearance.
        if let Some((signer, predicate_type)) = cascade_seed {
            self.cascade
                .cascade_clearance(
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
            let manifest_bytes = self.cascade.read_bounded(&source.sha256_checksum).await?;

            // Both carriage shapes — keyless Sigstore v0.3 bundle layers and
            // keyed cosign `simplesigning` layers — come from the one
            // extraction in `ProvenanceCascade::referrer_bundles`, which the
            // D8 signature-material walk also uses. A referrer that carries
            // neither (a non-cosign referrer — SBOM, an attestation of
            // another predicate, an ordinary manifest) contributes nothing:
            // skipped, not errored. A bundle blob the manifest references but
            // CAS does not hold surfaces as an `Err` → the existing
            // fetch-failure path (indeterminate), never a panic.
            bundles.extend(self.cascade.referrer_bundles(&manifest_bytes).await?);
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
    /// operation; a failure is reported by the caller's
    /// `apply_fetch_failure` path). `info!` on a fetch that yielded ≥1 bundle;
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
        //    `apply_fetch_failure` path.
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
    /// mismatch). An upstream / CAS error propagates (indeterminate).
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

        // e. Narrow create — the referrer-manifest `artifacts` row plus the
        //    content-reference edges it claims, in ONE transaction. Built
        //    with the already-held `lifecycle` port (NOT `IngestUseCase`):
        //    `quarantine_status = None` (an internal provenance-bookkeeping
        //    artifact, outside the scan/quarantine/provenance lifecycle) and
        //    NO `jobs.enqueue_*` — the whole point of the narrow create.
        //
        //    The `oci_subject` claim — source the referrer manifest, target
        //    the proxied image's content hash, mirroring the push-path row
        //    shape in `manifests_write.rs` — rides that transaction rather
        //    than following it. A `content_references` row is the claim that
        //    keeps bytes alive: the storage GC deletes a CAS blob exactly
        //    when no row targets its hash, and this row claims the IMAGE's
        //    bytes, not the referrer's. Written afterwards it left a window
        //    in which the referrer was live and the image it attests had one
        //    fewer claim, with nothing to repair it — the refcount-reconcile
        //    sweep converges `primary_content` / `metadata_blob` from the
        //    artifact row, and no relational row records what a manifest
        //    references. Upsert on the full PK, so a re-run is idempotent.
        let _manifest_artifact = self
            .commit_referrer_manifest(
                artifact,
                manifest_put.hash,
                manifest_put.size_bytes,
                &[ContentReferenceClaim {
                    target_content_hash: artifact.sha256_checksum.clone(),
                    kind: OCI_SUBJECT_KIND.to_string(),
                    metadata: serde_json::json!({
                        "artifact_type": hort_domain::oci::SIGSTORE_BUNDLE_MEDIA_TYPE,
                        "media_type": "application/vnd.oci.image.manifest.v1+json",
                    }),
                }],
            )
            .await?;

        Ok(true)
    }

    /// Commit the status-`None` referrer-manifest artifact, a single
    /// `ArtifactIngested` event and the manifest's content-reference edges
    /// via `commit_transition_with_enqueues` — the same create primitive
    /// `IngestUseCase::ingest_signature_manifest` uses, inlined here against
    /// the already-held ports. NO scan / provenance enqueue. Returns the
    /// created `Artifact`.
    ///
    /// The edge set is the manifest's own `primary_content` plus whatever the
    /// caller claims. Both are claims on bytes against the storage GC, which
    /// deletes a CAS blob exactly when no `content_references` row targets
    /// its hash, so they belong in the transaction that makes the claiming
    /// artifact live. `primary_content` matters here in particular because
    /// this artifact commits at `quarantine_status = None` — outside the
    /// scan/quarantine lifecycle, and therefore outside the GC's
    /// protected-evidence rule — so with no row claiming its own content it
    /// counted zero against itself until the next reconcile sweep converged
    /// it.
    async fn commit_referrer_manifest(
        &self,
        image: &Artifact,
        manifest_hash: ContentHash,
        size_bytes: u64,
        claimed_edges: &[ContentReferenceClaim],
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
            provenance_hold_indefinite: false,
            deleted_at: None,
            upstream_published_at: None,
            uploaded_by: None,
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
        let expected_version = read_unpaired_append_version(
            &*self.events,
            &stream_id,
            true,
            UnpairedAppend::GenesisAppend,
        )
        .await?;

        let mut edges = vec![ContentReference {
            source_artifact_id: artifact_id,
            target_content_hash: artifact.sha256_checksum.clone(),
            kind: "primary_content".to_string(),
            metadata: serde_json::Value::Object(serde_json::Map::new()),
            repository_id: artifact.repository_id,
            recorded_at: now,
        }];
        edges.extend(
            claimed_edges
                .iter()
                .map(|c| c.resolve(artifact_id, artifact.repository_id, now)),
        );

        self.lifecycle
            .commit_transition_with_enqueues(
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
                // No ingest-time jobs — see this method's docstring.
                &[],
                &edges,
            )
            .await?;

        Ok(artifact)
    }

    /// Read the artifact preimage from CAS (bounded). Returns the bytes
    /// `ProvenanceSubject.payload` is built over.
    async fn read_preimage(&self, content_hash: &ContentHash) -> AppResult<Vec<u8>> {
        let mut last_err = None;
        for _ in 0..FETCH_ATTEMPTS {
            match self.cascade.read_bounded(content_hash).await {
                Ok(bytes) => return Ok(bytes),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.expect("FETCH_ATTEMPTS >= 1 so at least one error was recorded"))
    }

    // -----------------------------------------------------------------
    // Verdict dispatch / fold / apply
    // -----------------------------------------------------------------

    /// Dispatch each applicable verifier and fold the verdicts to one. In
    /// the Tier-1 single-verifier deployment this is a single call; the
    /// fold rule keeps the orchestrator total for a future multi-verifier
    /// set, and is [`fold_two`]'s ladder:
    ///
    /// - any `Rejected` verdict wins (most restrictive — a forged/untrusted
    ///   signature from any verifier rejects the artifact);
    /// - else any `Verified` verdict wins (a trusted signature from any
    ///   verifier clears it);
    /// - else any `Indeterminate` verdict wins (both remaining rungs
    ///   hold, and this is the more informative hold — it names an
    ///   operator action the other does not);
    /// - else `NoAttestation` (no verifier found a bundle).
    ///
    /// A verifier that itself errors (an adapter bug, a trust root that
    /// cannot build a verifier, a subject-payload/content-hash mismatch)
    /// returned no verdict at all, so it proved nothing about the
    /// artifact: it contributes
    /// `Indeterminate{VerifierUnavailable}` — **one value, in every
    /// mode**, because the epistemic state does not depend on policy. The
    /// mode decides the consequence downstream and once, exactly as it
    /// does for a fetch that never landed (see `apply_fetch_failure`):
    /// `Required` holds, `VerifyIfPresent` / `Off` allow through and
    /// report `allowed_indeterminate`.
    ///
    /// It does **not** contribute nothing: a run in which every verifier
    /// errored would then fold to `NoAttestation` and report
    /// `held_pending_signature`, sending the operator to the publisher's
    /// signer for a fault of ours.
    async fn dispatch_and_fold(
        &self,
        applicable: &[&Arc<dyn ProvenancePort>],
        subject: &ProvenanceSubject<'_>,
        bundles: &[AttestationBundle],
        requirements: &ProvenanceRequirements<'_>,
    ) -> (ProvenanceVerdict, String) {
        use hort_domain::ports::provenance::ProvenanceOutcome;

        let mut folded: Option<(ProvenanceVerdict, String)> = None;
        for port in applicable {
            let verdict = match port.verify(subject, bundles, requirements).await {
                Ok(v) => v,
                Err(e) => {
                    // The verifier returned no verdict, so nothing about
                    // the artifact was established and nothing was
                    // disproved — the check is what failed, not the
                    // material. One value in every mode: the mode decides
                    // the consequence downstream (a hold under `Required`,
                    // allowed through otherwise), and the epistemic state
                    // does not depend on policy.
                    //
                    // The `warn!` keeps `backend` and `error` — the only
                    // record of WHICH verifier failed and why, which the
                    // verdict itself does not carry.
                    tracing::warn!(
                        backend = port.name(),
                        error = %e,
                        "provenance verifier returned no verdict — the check could not be \
                         carried out (indeterminate: held under Required, allowed under \
                         VerifyIfPresent/Off; never terminal, because nothing about the \
                         artifact was established)",
                    );
                    ProvenanceVerdict::indeterminate(IndeterminateReason::VerifierUnavailable)
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
                    unreadable_skipped: 0,
                },
                String::new(),
            )
        })
    }

    /// Apply a folded verdict via [`Artifact::complete_provenance`] and
    /// persist the returned events (if any). Mirrors how scan orchestration
    /// persists `ScanCompleted` through the lifecycle port.
    ///
    /// `is_constituent` is threaded for the **hold label only** (see
    /// [`HoldReason`]); it is not a gate and does not reach the domain.
    async fn apply_verdict(
        &self,
        mut artifact: Artifact,
        backend: &str,
        verdict: ProvenanceVerdict,
        mode: ProvenanceMode,
        is_constituent: bool,
        expected_version: ExpectedVersion,
    ) -> AppResult<ProvenanceRunOutcome> {
        // Defense-in-depth bounded requeue (issue #90). A `NoAttestation`
        // verdict under `Required` with a `None` `quarantine_window_start`
        // on an artifact whose status is STILL `None` is the exact
        // symptom of the ingest TOCTOU this issue fixed: the artifact may
        // be mid-transition to `Quarantined` by a commit that just hasn't
        // landed yet (or a residual race in some other/future dual-commit
        // path — `IngestUseCase::ingest_inner` itself now commits
        // `ArtifactIngested` + `ArtifactQuarantined` atomically, so a job
        // IT enqueues can no longer observe this shape). Requeueing runs
        // the verify again once the (expected, imminent) quarantine commit
        // has landed, so the verdict is applied against the artifact's real
        // state rather than a half-committed one — bounded to artifacts
        // younger than `PROVENANCE_ANCHOR_GRACE_SECS`, because a
        // steady-state PERMISSIVE artifact (`quarantine_duration_secs ==
        // 0`) shows this exact shape too, but FOREVER (it is never
        // quarantined), and must not requeue indefinitely.
        if mode == ProvenanceMode::Required
            && artifact.quarantine_status == QuarantineStatus::None
            && artifact.quarantine_window_start.is_none()
            && matches!(
                verdict.outcome,
                hort_domain::ports::provenance::ProvenanceOutcome::NoAttestation
            )
            && chrono::Utc::now() - artifact.created_at
                < chrono::Duration::seconds(PROVENANCE_ANCHOR_GRACE_SECS)
        {
            tracing::info!(
                artifact_id = %artifact.id,
                backend = %backend,
                "provenance: NoAttestation×Required on a None-status, anchor-less, \
                 recently-ingested artifact — requeueing instead of terminal reject \
                 (bounded defense-in-depth, issue #90)",
            );
            crate::metrics::emit_provenance_verify(
                backend,
                mode,
                crate::metrics::ProvenanceVerifyResult::RequeuedNoAnchor,
            );
            return Ok(ProvenanceRunOutcome::RequeuedNoAnchor);
        }

        // What an empty event batch will mean, captured before the verdict
        // is moved into `complete_provenance` (see [`NoEventReport`]). Two
        // outcomes emit nothing — an unsigned artifact and a check that
        // could not be carried out — and the domain produces the SAME
        // (absent) transition for both under every mode, so neither the
        // outcome nor the mode is recoverable from the batch that comes
        // back. Both have to be read here or not at all.
        //
        // Under `Required` both are HELD: `complete_provenance` emits
        // nothing and leaves the status `Quarantined` → the release gate
        // reads it as `Pending` (fail-closed / held), not an
        // allowed-unsigned no-op. A hold reported as the allowed-unsigned
        // no-op would mislabel a fail-closed hold as a pass in both the
        // summary and the metric.
        //
        // Which hold is a LABEL, not a gate (see `HoldReason`): a
        // constituent can never carry an attestation of its own, so it is
        // waiting for its subject's cascade, not for its own signature —
        // a different operator action, and the hold is indefinite, so the
        // distinction is the useful half of the observability.
        //
        // An `Indeterminate` verdict is the second held outcome and takes
        // the third label. It is NOT split by `is_constituent`: the thing
        // to fix is our trust root, our fetch or our verifier, which is
        // the same answer whatever shape the artifact has.
        //
        // Under `VerifyIfPresent` / `Off` both are allowed through, and
        // they are still two different readings: an artifact nobody
        // signed, and an artifact we could not check. Reporting the second
        // as the first names the artifact's state when the fault is ours.
        //
        // Wildcard-free over the outcome so a future one has to state what
        // an empty batch would report before it compiles — the whole point
        // of the held/terminal line being a type rather than a convention.
        let no_event_report = {
            use hort_domain::ports::provenance::ProvenanceOutcome as O;
            match (&verdict.outcome, mode) {
                (O::NoAttestation, ProvenanceMode::Required) => {
                    NoEventReport::Held(if is_constituent {
                        HoldReason::PendingSubject
                    } else {
                        HoldReason::PendingSignature
                    })
                }
                (O::Indeterminate(_), ProvenanceMode::Required) => {
                    NoEventReport::Held(HoldReason::Indeterminate)
                }
                (O::NoAttestation, ProvenanceMode::VerifyIfPresent | ProvenanceMode::Off) => {
                    NoEventReport::AllowedUnsigned
                }
                (O::Indeterminate(_), ProvenanceMode::VerifyIfPresent | ProvenanceMode::Off) => {
                    NoEventReport::AllowedIndeterminate
                }
                // `Verified` / `Rejected` each append their own axis event,
                // so they never reach the empty-batch branch and this
                // reading is never read. They take the no-op value because
                // that is what an empty batch would have meant for them:
                // nothing was recorded at all. A total value rather than an
                // `unreachable!`, for the same reason the axis-event fold
                // further down keeps a defensive default — a value cannot
                // become a panic when the domain changes under it.
                (O::Verified { .. } | O::Rejected(_), _) => NoEventReport::AllowedUnsigned,
            }
        };
        // The status as LOADED, captured before `complete_provenance`
        // mutates it — the guard the conditional projection write keys on
        // (issue #108 H2b; see `ArtifactLifecyclePort`'s doc). A
        // `Verified` verdict leaves the artifact `Quarantined`, i.e.
        // EQUAL to this, so the adapter skips the status write entirely.
        let prior_status = artifact.quarantine_status;
        // Captured before the verdict is consumed. The count is reported
        // (log + counter) by the caller, which is the only place it is
        // complete; it is carried onto the outcome here so the job row's
        // `result_summary` — the per-artifact forensic trail — names it
        // too.
        let unreadable_skipped = verdict.unreadable_skipped;
        let events = artifact.complete_provenance(verdict, backend)?;

        if events.is_empty() {
            // No event, status unchanged — held under `Required`, allowed
            // under `VerifyIfPresent` / `Off`. Each of the four readings
            // ticks its own result value, so a hold is never reported as a
            // pass and a check we could not run is never reported as an
            // artifact nobody signed. Single emission layer — the
            // orchestration use case.
            //
            // The `info!` (no `err`) is the operator audit signal that an
            // image is not yet clearable, and is therefore scoped to the
            // holds; see `NoEventReport::log_message`.
            if let Some(message) = no_event_report.log_message() {
                tracing::info!(
                    artifact_id = %artifact.id,
                    backend = %backend,
                    is_constituent,
                    unreadable_skipped,
                    "{}",
                    message,
                );
            }
            crate::metrics::emit_provenance_verify(backend, mode, no_event_report.metric_result());
            return Ok(ProvenanceRunOutcome::Applied {
                event_appended: false,
                verdict: no_event_report.verdict_summary(),
                unreadable_skipped,
            });
        }

        // Tracing: info! on the supply-chain decision — audit signal, not
        // `err`. Domain stays tracing-free. Metrics fire alongside, once
        // per applied verdict, at this single layer:
        // `hort_provenance_verify_total{backend, mode, result}` always, +
        // `hort_provenance_reject_total{backend, reason}` on a rejection.
        // The coarse verdict bucket surfaced to the task handler's
        // `result_summary`. Derived from the batch's AXIS event — the
        // `Verified` / `Rejected` arm; the `ArtifactRejected` companion the
        // rejection arm appends alongside carries no provenance-specific
        // information, so it is skipped here rather than matched. A batch
        // with no axis event is unreachable (a non-empty batch always leads
        // with one), so the defensive default keeps the fold total.
        let verdict_summary = events.iter().fold(
            ProvenanceVerdictSummary::NoAttestation,
            |acc, event| match event {
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
                _ => acc,
            },
        );

        let stream_id = hort_domain::events::StreamId::artifact(artifact.id);
        let correlation_id = Uuid::new_v4();

        // Column-scoped, prior-status-guarded verdict commit.
        // `artifact` was loaded at the top of `verify_artifact`, before
        // the bundle fetch / CAS preimage read / verifier dispatch round
        // trip — by now its snapshot of every column can be stale. Three
        // things keep that from clobbering a concurrent verdict:
        //
        // 1. `expected_version` came from the `ArtifactAtVersion` pairing
        //    at that same load, so an intervening append fails this one
        //    `Conflict` before any projection write happens.
        // 2. `commit_provenance_verdict` writes only `quarantine_status`,
        //    so a concurrent transition's `quarantine_window_start` (the
        //    quarantine anchor) survives regardless.
        // 3. `prior_status` makes even that one column's write
        //    skip-if-unchanged and conditional-if-changed.
        self.lifecycle
            .commit_provenance_verdict(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: events.into_iter().map(EventToAppend::new).collect(),
                    correlation_id,
                    causation_id: None,
                    actor: system_actor(),
                },
                prior_status,
            )
            .await?;

        Ok(ProvenanceRunOutcome::Applied {
            event_appended: true,
            verdict: verdict_summary,
            unreadable_skipped,
        })
    }

    /// Handle a bundle-fetch / CAS-read failure: the attestation material
    /// could not be obtained at all, so nothing about the artifact was
    /// established and nothing was disproved. The verdict is
    /// `Indeterminate{AttestationFetchFailed}` — **one value, in every
    /// mode**, because the epistemic state does not depend on policy. The
    /// mode already decides the consequence, downstream and once:
    ///
    /// - `Required` → the artifact HOLDS (`Quarantined`, `Pending` at the
    ///   release gate, 503 to a pull), under the indeterminate hold
    ///   reason so the operator sees that the fault is on our side. A
    ///   never-verified `Required` artifact still cannot timer-release:
    ///   the hold IS the fail-closed reading, and fail-closed is not the
    ///   same as terminal (ADR 0039 D2).
    /// - `VerifyIfPresent` / `Off` → no event, no status change: the
    ///   artifact runs its normal quarantine window and releases, exactly
    ///   as it does for an unsigned one. The run reports
    ///   `allowed_indeterminate`, not the allowed-unsigned value, so an
    ///   unreachable upstream does not read as an artifact nobody signed.
    ///
    /// A fetch that never happened is the weakest state the pipeline can
    /// be in: not "the signature is wrong", not even "no signature has
    /// arrived" — *we could not look*. Terminality follows only from a
    /// positive disproof about readable material (ADR 0039 D4), which is
    /// why this path states no [`ProvenanceRejectReason`] at all: a
    /// network error is nobody's material being at fault.
    ///
    /// The hold-label input (`is_constituent`) is not threaded: the
    /// indeterminate hold is not split by the artifact's shape, because
    /// the thing to fix is our fetch either way.
    ///
    /// The `warn!` keeps `stage` and `error` — the only record of WHICH
    /// fetch failed, which the verdict itself does not carry.
    async fn apply_fetch_failure(
        &self,
        artifact: Artifact,
        backend: &str,
        mode: ProvenanceMode,
        stage: &str,
        err: crate::error::AppError,
        expected_version: ExpectedVersion,
    ) -> AppResult<ProvenanceRunOutcome> {
        tracing::warn!(
            artifact_id = %artifact.id,
            mode = %mode,
            stage,
            error = %err,
            "provenance: attestation fetch exhausted — the check could not be carried out \
             (indeterminate: held under Required, allowed under VerifyIfPresent/Off; never \
             terminal, because nothing about the artifact was established)",
        );
        let verdict = ProvenanceVerdict::indeterminate(IndeterminateReason::AttestationFetchFailed);
        self.apply_verdict(artifact, backend, verdict, mode, false, expected_version)
            .await
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

/// Fold two verdicts to one (the multi-verifier fold rule):
/// `Rejected` ⊳ `Verified` ⊳ `Indeterminate` ⊳ `NoAttestation`.
///
/// `Rejected` ⊳ `Verified` is the standing decision and is unchanged: a
/// finding about pushed material dominates a second verifier's acceptance
/// of it.
///
/// `Verified` ⊳ `Indeterminate` is the position the could-not-check state
/// takes, and the direction matters: a real signature is **not** overridden
/// because the *other* verifier had no usable trust-root key or never
/// fetched its material. Our provisioning fault cannot invalidate a
/// signature we did verify.
///
/// `Indeterminate` ⊳ `NoAttestation` keeps the more informative hold. Both
/// hold, so no verdict changes — but "we could not check" names an operator
/// action (fix the trust root; the fetch retries) that "nothing was signed"
/// does not, and folding the other way would lose it.
///
/// The final arm is deliberately the concrete `(NoAttestation,
/// NoAttestation)` pair rather than a wildcard: a future outcome makes this
/// match non-exhaustive and must be given a rung on the ladder before it
/// compiles. Pure helper — testable without the use case.
///
/// The ladder decides the **outcome** only. A verdict also carries
/// `unreadable_skipped`, which is not on any rung — it is a record of what
/// each verifier could not read, so the two verifiers' counts have to be
/// *added*, not ranked. [`fold_two_backend`] does that; this function
/// returns one of its two arguments whole, so calling it directly discards
/// the loser's count.
fn fold_two(a: ProvenanceVerdict, b: ProvenanceVerdict) -> ProvenanceVerdict {
    use hort_domain::ports::provenance::ProvenanceOutcome::{
        Indeterminate, NoAttestation, Rejected, Verified,
    };
    match (&a.outcome, &b.outcome) {
        (Rejected(_), _) => a,
        (_, Rejected(_)) => b,
        (Verified { .. }, _) => a,
        (_, Verified { .. }) => b,
        (Indeterminate(_), _) => a,
        (_, Indeterminate(_)) => b,
        (NoAttestation, NoAttestation) => a,
    }
}

/// Fold two `(verdict, backend)` candidates — [`fold_two`] plus backend
/// attribution, plus the **sum** of the two candidates' unreadable-skip
/// counts. The returned backend names the verifier whose verdict won, so
/// the metric labels the deciding backend rather than `applicable[0]`
/// (ADR 0039 §6). Pure helper — testable without the use case.
///
/// The count is summed rather than inherited from the winner because the
/// two verifiers partition the candidate set by shape: each one can only
/// report on the candidates that were its own, and the losing verdict's
/// count is exactly the part the winner never saw. Inheriting the winner's
/// count is the shape of this unit's whole failure mode — a keyed bundle
/// that verifies next to unparseable bytes declared as a keyless bundle
/// yields `Verified` from the keyed verifier and the skip from the
/// keyless one, so the winner's count is 0 and the record would be lost
/// precisely in the case it exists for.
///
/// Associative over the running fold (the intermediate carries the running
/// total), so a three-verifier set sums all three.
fn fold_two_backend(
    a: (ProvenanceVerdict, String),
    b: (ProvenanceVerdict, String),
) -> (ProvenanceVerdict, String) {
    let total =
        a.0.unreadable_skipped
            .saturating_add(b.0.unreadable_skipped);
    let (verdict, backend) = if fold_two(a.0.clone(), b.0.clone()) == a.0 {
        a
    } else {
        b
    };
    (verdict.with_unreadable_skipped(total), backend)
}

#[cfg(test)]
#[path = "provenance_orchestration_tests.rs"]
mod tests;
