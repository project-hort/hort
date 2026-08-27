use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::quarantine_transitions::{self, QuarantineEvent};
use crate::entities::repository::RepositoryFormat;
use crate::entities::scan_policy::ProvenanceMode;
use crate::error::{DomainError, DomainResult};
use crate::events::{
    ArtifactCorrupted, ArtifactDeleted, ArtifactQuarantined, ArtifactRejected, ArtifactReleased,
    DomainEvent, ProvenanceRejected, ProvenanceVerified, RejectionReason, ReleaseReason,
    ScanIndeterminate,
};
use crate::policy::ScanOutcome;
use crate::ports::provenance::{
    ProvenanceOutcome, ProvenanceRejectReason, ProvenanceVerdict, SignerIdentity,
};
use crate::types::ContentHash;

// ---------------------------------------------------------------------------
// QuarantineStatus
// ---------------------------------------------------------------------------

/// Quarantine lifecycle state for an artifact.
///
/// Models a hold-and-release workflow:
/// - [`None`](Self::None) — not quarantined (no quarantine configured or not applicable)
/// - [`Quarantined`](Self::Quarantined) — held for review, downloads blocked
/// - [`Released`](Self::Released) — review complete, scan clean, downloads allowed
/// - [`Rejected`](Self::Rejected) — scan found blocking findings, permanently blocked
/// - [`ScanIndeterminate`](Self::ScanIndeterminate) — terminal scan failure
///   (every backend errored and the job exhausted its retry budget); the
///   scanner could not decide. Fail-closed (ADR 0007): non-downloadable
///   and non-promotable, releasable only by admin override or a later
///   successful re-scan.
///
/// This is distinct from scan state — scan results *feed into* quarantine
/// decisions but are tracked separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineStatus {
    None,
    Quarantined,
    Released,
    Rejected,
    /// Terminal scan failure: the scanner could not
    /// decide. Fail-closed (ADR 0007); recovery is admin override or a
    /// later successful re-scan. Distinct from
    /// [`Rejected`](Self::Rejected) (provably bad content).
    ScanIndeterminate,
}

impl fmt::Display for QuarantineStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Quarantined => f.write_str("quarantined"),
            Self::Released => f.write_str("released"),
            Self::Rejected => f.write_str("rejected"),
            Self::ScanIndeterminate => f.write_str("scan_indeterminate"),
        }
    }
}

impl FromStr for QuarantineStatus {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "quarantined" => Ok(Self::Quarantined),
            "released" => Ok(Self::Released),
            "rejected" => Ok(Self::Rejected),
            "scan_indeterminate" => Ok(Self::ScanIndeterminate),
            _ => Err(DomainError::Validation(format!(
                "unknown quarantine status: {s}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Artifact
// ---------------------------------------------------------------------------

/// An uploaded artifact (package, image, file) within a repository.
///
/// The `sha256_checksum` field uses [`ContentHash`] for validated SHA-256.
/// Legacy checksums (`sha1`, `md5`) remain as plain strings — they exist for
/// compatibility but are not the CAS identity.
///
/// `name` stores the normalised form (output of
/// `FormatHandler::normalize_name`) — the lookup key for index paths.
/// `name_as_published` stores the **exact** client-supplied name before
/// any normalisation; it is the drift-resilience safety net. See
/// `docs/architecture/explanation/format-handlers.md`
/// §"Normalisation stability".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub name: String,
    pub name_as_published: String,
    pub version: Option<String>,
    pub path: String,
    pub size_bytes: i64,
    pub sha256_checksum: ContentHash,
    pub sha1_checksum: Option<String>,
    pub md5_checksum: Option<String>,
    pub content_type: String,
    pub quarantine_status: QuarantineStatus,
    /// Why this artifact is in [`QuarantineStatus::Rejected`] — the
    /// structured rejection reason last applied by an `ArtifactRejected`
    /// event (`Scanner`, `CurationRetroactive`, `Curator`, `Admin`).
    /// `None` when the artifact is not rejected (or when the rejection
    /// reason is unknown — e.g. a legacy row, or a rejection from a code
    /// path that predates reason carriage).
    ///
    /// **Cross-axis release eligibility (ADR 0041, invariant #6).** The
    /// scan re-evaluation release path ([`Self::re_evaluate`]) is
    /// scan-clearable only for `Some(RejectionReason::Scanner)`: a
    /// provenance- / curation- / admin-rejected artifact is **ineligible**
    /// for a scan re-judgement and stays held. A reject reason added later
    /// is ineligible by default (`None` is not `Scanner`). The field is set
    /// on the entity reject methods (`reject_from_scan`,
    /// `reject_from_retroactive_curation`, `block_by_curator`) and is
    /// re-hydrated by the application layer from the artifact's stored
    /// `ArtifactRejected` event before [`Self::re_evaluate`] is called
    /// (the projection row does not persist it — same transient-hydration
    /// contract as [`Self::quarantine_deadline`]).
    ///
    /// `#[serde(default)]` so any persisted/replayed `Artifact`
    /// representation that predates the field deserialises as `None`
    /// (defence-in-depth — `Artifact` is materialised from a projection
    /// row, not the event stream, but the field participates in the
    /// derived `Serialize`/`Deserialize`).
    #[serde(default)]
    pub rejection_reason: Option<RejectionReason>,
    /// Immutable observation-window **anchor** (ADR 0007). The resolved
    /// window start: the earliest defensible evidence of the content's
    /// age, computed by
    /// [`derive_quarantine_anchor`](crate::policy::derive_quarantine_anchor)
    /// as the minimum over the applicable sources — the mint instant, the
    /// earliest moment hort observed this content in any of its
    /// repositories, a trusted upstream publish time from this
    /// repository's own mapping, and the referenced-tree-descendant
    /// carve-out (ADR 0054). `None` ⇒ not quarantined.
    ///
    /// The window *deadline* is **not stored** — it is computed live as
    /// `quarantine_window_start + duration` (the duration resolved from
    /// the matched `ScanPolicy`), because the duration is config that
    /// can change after the artifact is quarantined. See
    /// [`crate::policy::effective_quarantine_deadline`].
    pub quarantine_window_start: Option<DateTime<Utc>>,
    /// **Transient, non-persisted** computed quarantine deadline.
    /// The adapter never reads or writes this field —
    /// it is hydrated by the application/use-case layer on the artifact
    /// representation returned to format-crate read paths so the
    /// proxy-`503` `Retry-After` sites can read a deadline without
    /// resolving a `ScanPolicy` themselves (the adapter-free
    /// `hort-http-<format>` crates cannot). `#[serde(skip)]` so it never
    /// enters any wire/event form; always `None` on a fresh load from
    /// the store.
    #[serde(skip)]
    pub quarantine_deadline: Option<DateTime<Utc>>,
    /// Upstream-asserted publish timestamp —
    /// **untrusted, audit only**. Populated best-effort at ingest from
    /// per-format upstream metadata (npm packument `time[<version>]`,
    /// PyPI `upload_time_iso_8601`, Cargo / OCI `Last-Modified` header).
    /// `None` when the upstream did not supply a parseable value, or
    /// when the artifact was directly uploaded (no upstream at all).
    ///
    /// **Recorded unconditionally** — recording an untrusted,
    /// clearly-labelled value is not trusting it. The window-anchor
    /// *computation* that consumes it is what is
    /// gated on the per-upstream
    /// `RepositoryUpstreamMapping.trust_upstream_publish_time`
    /// opt-in (interaction constraints: ADR 0016).
    pub upstream_published_at: Option<DateTime<Utc>>,
    pub uploaded_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Soft-delete marker. `None` ⇒ the artifact is **live**; `Some(ts)`
    /// ⇒ it was deleted at `ts` and is no longer part of the repository's
    /// served catalog.
    ///
    /// Deliberately a dedicated field rather than a
    /// [`QuarantineStatus`] variant: deletion is **orthogonal** to scan
    /// state (a `Released` artifact and a `Rejected` one are both
    /// deletable), so folding it into the status enum would conflate two
    /// axes and destroy the pre-deletion state the audit trail needs.
    ///
    /// Every live read filters `deleted_at IS NULL`, so an artifact
    /// materialised by a normal lookup always carries `None` here; the
    /// non-`None` case is observable only on the deletion path itself.
    /// The projection column is what a fresh ingest at the same path
    /// consults — the `(repository_id, path)` unique index is predicated
    /// on `deleted_at IS NULL`, so a deleted row no longer reserves its
    /// path.
    ///
    /// `#[serde(default)]` so any persisted/replayed `Artifact`
    /// representation that predates the field deserialises as live —
    /// which is exactly what those rows were.
    #[serde(default)]
    pub deleted_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// ArtifactMetadata
// ---------------------------------------------------------------------------

/// Format-specific metadata attached to an artifact — 1:1 projection of
/// format payload captured at ingest time.
///
/// `artifact_id` is the only identifier: the projection is 1:1 with
/// [`Artifact`], and the `artifact_metadata` table's primary key is the
/// same UUID. No separate `id` column exists.
///
/// `format` uses [`RepositoryFormat`] — the same vocabulary as
/// [`Repository.format`](super::repository::Repository).
///
/// `metadata` is the opaque JSON blob produced by the format handler at
/// ingest (e.g., PyPI METADATA fields; npm packument entry). Under the
/// [`HashReference`](crate::ports::format_handler::MetadataStrategy::HashReference)
/// strategy it carries the handler-extracted summary (what index/listing
/// rendering needs); under `Inline` it carries the full payload.
///
/// `metadata_blob` is `Some(hash)` iff the handler's
/// [`MetadataStrategy`](crate::ports::format_handler::MetadataStrategy) is
/// `HashReference` and the serialised payload exceeded the inline
/// threshold — in which case the full payload lives at `hash` in CAS.
/// `None` otherwise (all `Inline`-strategy rows, and `HashReference` rows
/// whose payload fit under the threshold).
///
/// `properties` is reserved for user-assigned key/values; v2 never writes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub artifact_id: Uuid,
    pub format: RepositoryFormat,
    pub metadata: serde_json::Value,
    pub metadata_blob: Option<ContentHash>,
    pub properties: serde_json::Value,
}

// ---------------------------------------------------------------------------
// ReleaseAuthorization (fail-closed release predicate, ADR 0007)
// ---------------------------------------------------------------------------

/// Why a release is authorized. Constructed only by the application
/// layer from verified facts; the entity trusts it as the predicate
/// input (it owns the event store and the policy projection — the
/// entity stays pure). Each variant is a distinct, audited release
/// authority (ADR 0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseAuthorization {
    /// A successful `ScanCompleted` exists for this artifact (the app
    /// layer proved it by reading the artifact stream). The normal
    /// timer-sweep release path: window expired AND scan succeeded.
    ScanSucceeded,
    /// The artifact's resolved `ScanPolicy` has `scan_backends: []`
    /// (scanning explicitly waived by operator policy). Timer-sweep
    /// release is permitted without a scan because the operator
    /// declared this repo/scope un-scanned by design.
    ScanWaived,
    /// The artifact was scanned, the scan produced findings, and the
    /// artifact's resolved `ScanPolicy` declares
    /// `enforcement: record` — the operator has said the scan verdict is
    /// recorded, not gating ("publish proceeds with findings; blocking at
    /// retrieval is the consuming policy's job").
    ///
    /// **Deliberately NOT folded into [`Self::ScanSucceeded`].** That
    /// authority means the artifact's latest `ScanCompleted` carries
    /// `finding_count == 0`; widening it to cover a dirty scan would make
    /// the ADR 0007 "latest verdict, not mere presence" clause
    /// conditional on a policy field, and would make the release audit
    /// (`authority = scan_succeeded`) claim a pass that never happened.
    /// It is not [`Self::ScanWaived`] either — that authority asserts the
    /// operator declared the scope un-scanned; here the scan ran and its
    /// evidence exists. A distinct token keeps "released with recorded,
    /// over-threshold findings" queryable in the audit trail and on the
    /// release metric.
    ///
    /// Constructible only by the application layer, from two verified
    /// facts: a `ScanCompleted` exists on the artifact's own stream with
    /// no later `ArtifactRejected`, AND the resolved policy's
    /// `enforcement` is `record`. Pairs only with
    /// [`ReleaseReason::Timer`] and carries the same provenance
    /// AND-precondition as the other two timer authorities — `record`
    /// un-gates the scan axis, never the provenance or curation ones.
    ScanRecorded,
    /// Admin explicitly released despite indeterminate/rejected/no-scan
    /// state. Attribution is populated at the call site
    /// (`released_by_user_id` + `justification` on the event).
    AdminOverride,
    /// Post-exclusion policy re-evaluation removed the block (the
    /// existing `re_evaluate()` path; kept distinct so the predicate
    /// does not have to special-case `Rejected`).
    PolicyReEvaluation,
    /// A curator (`Permission::Curate`) issued an
    /// early release ("waive") of a quarantined artifact. Pairs ONLY
    /// with [`ReleaseReason::Curator`] in the deny-by-default predicate;
    /// the source-state guard is **narrower** than admin
    /// (`Quarantined` only — `ScanIndeterminate` stays admin-only).
    /// Attribution lives on the event (released-by user + justification),
    /// not on the authorization tag, so the variant carries no inline
    /// data.
    CuratorWaiver,
}

// ---------------------------------------------------------------------------
// ProvenanceClearance (ADR 0027)
// ---------------------------------------------------------------------------

/// The provenance side of the fail-closed release gate (ADR 0027 +
/// ADR 0007). Computed by the release sweep per release candidate and
/// threaded into [`Artifact::release`] as an **AND-precondition** on the
/// *timer* release arm — never a new [`ReleaseAuthorization`], never a
/// blocker for an explicit Admin/Curator/PolicyReEval release.
///
/// - [`NotRequired`](Self::NotRequired) — `provenance_mode ∈ {Off,
///   VerifyIfPresent}`. Provenance never gates release in these modes
///   (`VerifyIfPresent`'s protection is `complete_provenance(Rejected) ->
///   rejected`, which removes a bad artifact from candidacy, not a
///   release-gate).
/// - [`Cleared`](Self::Cleared) — `Required` mode AND a
///   `ProvenanceVerified` event exists for this artifact.
/// - [`Pending`](Self::Pending) — `Required` mode with no
///   `ProvenanceVerified` yet (the transient pre-verify window).
///   **Fail-closed**: a `Pending` artifact does not timer-release before
///   verification completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceClearance {
    /// Provenance does not gate release (mode `Off` / `VerifyIfPresent`).
    NotRequired,
    /// `Required` mode and a `ProvenanceVerified` event exists.
    Cleared,
    /// `Required` mode, not yet verified — fail-closed, denies the timer arm.
    Pending,
}

// ---------------------------------------------------------------------------
// CurationClearance (ADR 0041, invariant #6 conjunct (c))
// ---------------------------------------------------------------------------

/// The curation side of the cross-axis re-evaluation release gate
/// (ADR 0041, invariant #6). Computed by the application layer per
/// re-evaluation candidate from the live curation rule set
/// (`CurationRuleRepository::list_for_repo` → `evaluate_curation`) and
/// threaded into [`Artifact::re_evaluate`] as an **AND-precondition** on
/// the `Rejected → Released` arm — mirroring the
/// [`ProvenanceClearance`] param on [`Artifact::release`].
///
/// This conjunct is **not** subsumed by the rejection-reason eligibility
/// guard: a *scan*-rejected artifact (eligible) that a curation rule
/// added *after* the scan rejection would now block is **not** re-marked
/// by the retroactive curation pass (`reject_from_retroactive_curation`
/// transitions only `Quarantined` / `Released`, never an already-
/// `Rejected` artifact). Without this active re-check, a scan loosen
/// would release it past the live curation block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurationClearance {
    /// No currently-active curation rule blocks the artifact — the
    /// curation conjunct of the release gate is satisfied.
    Cleared,
    /// A currently-active curation rule (`evaluate_curation` →
    /// `CurationOutcome::Block`) matches the artifact — the
    /// `Rejected → Released` arm is denied (fail-closed). A `Warn` /
    /// `Allow` curation outcome resolves to [`Self::Cleared`]; only a
    /// `Block` resolves to `Blocked`.
    Blocked,
}

// ---------------------------------------------------------------------------
// Artifact state machine
// ---------------------------------------------------------------------------

impl Artifact {
    /// Transition to quarantined state. Only valid from `None`.
    ///
    /// `window_start` is the immutable observation-window **anchor**
    /// (ADR 0007) — `ingested_at` by default. The window *deadline*
    /// is never stored; it is computed live from the anchor + the
    /// resolved policy duration via
    /// [`crate::policy::effective_quarantine_deadline`].
    pub fn quarantine(&mut self, window_start: DateTime<Utc>) -> DomainResult<ArtifactQuarantined> {
        if quarantine_transitions::allowed_targets(
            QuarantineEvent::Quarantine,
            self.quarantine_status,
        )
        .is_none()
        {
            return Err(DomainError::Invariant(format!(
                "cannot quarantine artifact in state {}",
                self.quarantine_status
            )));
        }
        self.quarantine_status = QuarantineStatus::Quarantined;
        self.quarantine_window_start = Some(window_start);
        Ok(ArtifactQuarantined {
            artifact_id: self.id,
            quarantine_window_start: window_start,
        })
    }

    /// Record a clean scan result. Does NOT release — the quarantine
    /// observation window still applies when the artifact is in
    /// `Quarantined`.
    ///
    /// Accepts `Quarantined` (strict mode: artifact is being held; clean
    /// scan validates the hold but does not shorten it) and `None`
    /// (permissive mode under `ScanPolicy.quarantineDuration = 0`: the
    /// artifact ingests downloadable and the scan runs alongside; a
    /// clean result is a no-op confirming nothing to block). Rejects
    /// `Released` and `Rejected` — both are terminal-for-this-purpose:
    /// a Released artifact has already passed review and re-running a
    /// "clean scan" against it is meaningless; a Rejected artifact has
    /// been blocked and a contradictory clean signal would mask the
    /// rejection. (This is the `quarantineDuration: 0` permissive-mode
    /// contract — see `docs/architecture/explanation/scanning-pipeline.md`.)
    ///
    /// **This is the state guard for every scan observation that does not
    /// transition the artifact**, not only a literally-clean one: a
    /// blocking verdict under `enforcement: record`
    /// ([`ScanOutcome::FindingsRecorded`]) records its findings through
    /// the same guard, because the artifact's status is likewise
    /// untouched by that verdict. The method reads no findings and
    /// mutates nothing — it answers only "is this artifact in a state
    /// where recording a scan observation is meaningful?".
    pub fn record_clean_scan(&self) -> DomainResult<()> {
        match quarantine_transitions::allowed_targets(
            QuarantineEvent::RecordCleanScan,
            self.quarantine_status,
        ) {
            Some(_) => Ok(()),
            None => {
                let other = self.quarantine_status;
                Err(DomainError::Invariant(format!(
                    "cannot record clean scan for artifact in state {other}"
                )))
            }
        }
    }

    /// Record scan with findings. Transitions to `Rejected`.
    ///
    /// Accepts source states `Quarantined` (strict mode: the artifact
    /// was being held pending scan; bad findings convert the hold into
    /// a permanent block) and `None` (permissive mode under
    /// `ScanPolicy.quarantineDuration = 0`: the artifact was
    /// downloadable; bad findings retroactively block downloads).
    /// Rejects `Released` (the operator already completed review;
    /// re-rejecting must go through retroactive curation or admin
    /// release-then-re-evaluation) and `Rejected` (terminal — the
    /// artifact is already blocked). (The `quarantineDuration: 0`
    /// permissive-mode contract — see
    /// `docs/architecture/explanation/scanning-pipeline.md`.)
    pub fn reject_from_scan(&mut self, reason: String) -> DomainResult<ArtifactRejected> {
        if quarantine_transitions::allowed_targets(
            QuarantineEvent::RejectFromScan,
            self.quarantine_status,
        )
        .is_none()
        {
            let other = self.quarantine_status;
            return Err(DomainError::Invariant(format!(
                "cannot reject artifact in state {other}"
            )));
        }
        self.quarantine_status = QuarantineStatus::Rejected;
        self.rejection_reason = Some(RejectionReason::Scanner);
        Ok(ArtifactRejected {
            artifact_id: self.id,
            rejected_by: RejectionReason::Scanner,
            reason,
        })
    }

    /// Reject an artifact because a retroactive curation evaluation hit.
    ///
    /// Valid only from `Quarantined` or `Released` — these are the
    /// "active" states `ArtifactRepository::list_active_for_repo` returns
    /// (already-rejected artifacts are excluded; retro-block on a rejected
    /// artifact is a no-op handled at the call-site by simply not invoking
    /// this method). Both transitions go to `Rejected`.
    pub fn reject_from_retroactive_curation(
        &mut self,
        rule_id: Uuid,
        reason: String,
    ) -> DomainResult<ArtifactRejected> {
        if quarantine_transitions::allowed_targets(
            QuarantineEvent::RejectFromRetroactiveCuration,
            self.quarantine_status,
        )
        .is_none()
        {
            let other = self.quarantine_status;
            return Err(DomainError::Invariant(format!(
                "cannot retroactively-reject artifact in state {other}"
            )));
        }
        self.quarantine_status = QuarantineStatus::Rejected;
        self.rejection_reason = Some(RejectionReason::CurationRetroactive { rule_id });
        Ok(ArtifactRejected {
            artifact_id: self.id,
            rejected_by: RejectionReason::CurationRetroactive { rule_id },
            reason,
        })
    }

    /// Retroactive **scan-policy** re-hold (ADR 0041, the tighten
    /// direction of continuous enforcement). A gate-affecting `ScanPolicy`
    /// change re-derived this artifact's verdict from its **stored**
    /// findings under the new policy; this method applies that verdict.
    ///
    /// The verdict is the single source of truth — the caller (the
    /// re-evaluation pass) computes it via
    /// [`crate::policy::evaluate_scan_result`] over the artifact's stored
    /// findings and threads the [`ScanOutcome`] in; the domain stays pure
    /// (no I/O, no re-scan). Both the loosen direction
    /// ([`Self::re_evaluate`]) and this tighten direction read the same
    /// `evaluate_scan_result` outcome, so the two cannot diverge
    /// (invariant #2).
    ///
    /// - [`ScanOutcome::Reject`] (now-failing) → transition to
    ///   [`QuarantineStatus::Rejected`], emit [`ArtifactRejected`] with
    ///   [`RejectionReason::ScanPolicyRetroactive`]. Mirrors
    ///   [`Self::reject_from_retroactive_curation`]: valid only from the
    ///   "active" states [`QuarantineStatus::Quarantined`] /
    ///   [`QuarantineStatus::Released`] (the set
    ///   `ArtifactRepository::list_active_for_policy` returns).
    /// - [`ScanOutcome::Clean`] (still-passing) → `Ok(None)`, no
    ///   transition, no event (invariant #2's "unchanged verdict → no-op").
    /// - [`ScanOutcome::FindingsRecorded`] (now-failing, but the policy
    ///   declares `enforcement: record`) → `Ok(None)`. The verdict blocks
    ///   nothing, so a tighten pass leaves the artifact where it is; only
    ///   a policy that enforces can re-hold a population.
    ///
    /// **No evidence ⇒ no re-rejection (invariant #4).** This method does
    /// not manufacture a verdict — it applies the one the caller computed.
    /// An artifact with no stored findings evaluates
    /// [`ScanOutcome::Clean`], so the caller threads `Clean` and this is a
    /// no-op: a scan tighten can never re-reject an artifact that has no
    /// evidence it violates.
    ///
    /// **The timer window is NOT re-opened.** A re-rejection does not reset
    /// [`Self::quarantine_window_start`] (or the transient
    /// [`Self::quarantine_deadline`]) — the artifact's original observation
    /// anchor is preserved, exactly as
    /// [`Self::reject_from_retroactive_curation`] leaves it. Re-rejecting a
    /// `Released` artifact blocks **future** downloads (the status gate);
    /// already-served bytes cannot be recalled.
    ///
    /// **Terminal source states reject as `Invariant` *without* mutating**
    /// (mirroring the sibling reject primitives), so the caller skips the
    /// event append:
    /// - [`QuarantineStatus::None`] — a never-held artifact is not in the
    ///   active scanned population this pass walks.
    /// - [`QuarantineStatus::Rejected`] — already blocked (idempotent skip;
    ///   a re-evaluation that finds it still-failing is a no-op).
    /// - [`QuarantineStatus::ScanIndeterminate`] — terminal scan-failure
    ///   state (ADR 0007); admin-only exit, never re-held by a policy pass.
    pub fn reject_from_scan_policy_retroactive(
        &mut self,
        outcome: &ScanOutcome,
        reason: String,
    ) -> DomainResult<Option<ArtifactRejected>> {
        if quarantine_transitions::allowed_targets(
            QuarantineEvent::RejectFromScanPolicyRetroactive,
            self.quarantine_status,
        )
        .is_none()
        {
            let other = self.quarantine_status;
            return Err(DomainError::Invariant(format!(
                "cannot retroactively scan-re-hold artifact in state {other}"
            )));
        }
        match outcome {
            // Still-passing under the new policy — unchanged verdict, no-op
            // (invariant #2). The window is untouched; no event appended.
            ScanOutcome::Clean => Ok(None),
            // The bumped policy computes a blocking verdict but declares
            // `enforcement: record` — the verdict is recorded, never
            // enforced, so a tighten pass must NOT re-hold. Same no-op
            // shape as Clean: no transition, no event. (The recorded
            // violations were already persisted by the scan that produced
            // the findings; a re-evaluation pass appends no new audit for
            // an unchanged download status.)
            ScanOutcome::FindingsRecorded(_) => Ok(None),
            // Now-failing — re-hold. The window anchor is preserved (not
            // re-opened); only the status + reason move.
            ScanOutcome::Reject(_) => {
                self.quarantine_status = QuarantineStatus::Rejected;
                self.rejection_reason = Some(RejectionReason::ScanPolicyRetroactive);
                Ok(Some(ArtifactRejected {
                    artifact_id: self.id,
                    rejected_by: RejectionReason::ScanPolicyRetroactive,
                    reason,
                }))
            }
        }
    }

    /// Block an artifact via a manual curator decision (see
    /// `docs/architecture/how-to/curator-workflow.md`). The
    /// use-case-level entry point is
    /// `CurationUseCase::block`; this method is the entity-
    /// level primitive.
    ///
    /// **Source-state guard:** accepts any **non-terminal** state — `None`
    /// (artifact ingested under `quarantineDuration:0`), `Quarantined`
    /// (currently held), or `Released` (the shadow-IT case: a long-
    /// released artifact is pulled from the catalog after an operator
    /// is paged by external advisory intelligence). All three transition
    /// to `Rejected`. Mirrors `reject_from_retroactive_curation`'s state-
    /// guard SHAPE but widens it to include `None` (manual blocking can
    /// apply to a never-quarantined artifact in permissive-scan mode,
    /// whereas retroactive curation only fires against artifacts the
    /// gitops-apply pass considers "active").
    ///
    /// **Terminal states reject as `Invariant`:**
    /// - `Rejected` — already blocked. The use-case layer
    ///   short-circuits this as an idempotent no-op:
    ///   `BlockOutcome.already_rejected_ids` records the id, no event
    ///   is appended. The entity must return `Err(Invariant)` **without
    ///   mutating** so the caller's commit path skips the append (the
    ///   same convention `tombstone_from_corruption` and
    ///   `fail_scan_indeterminate` use for their idempotent-skip
    ///   branches).
    /// - `ScanIndeterminate` — terminal scan-failure state (ADR 0007);
    ///   admin-only exit. Only `None | Quarantined | Released` are
    ///   accepted source states. Mirrors the
    ///   curator-waive narrowing: curator authority is
    ///   intentionally narrower than admin (clearing a stuck scanner
    ///   stays admin-only on both the release and the block side).
    ///
    /// Emits `ArtifactRejected { rejected_by: Curator { curator_id },
    /// reason }`. The `reason` is the curator-supplied justification
    /// (≤ 512 bytes at the HTTP boundary; the entity does not enforce
    /// that cap — `ArtifactRejected::validate` caps `reason` at
    /// `MAX_REASON_LEN = 4096`).
    pub fn block_by_curator(
        &mut self,
        curator_id: Uuid,
        reason: String,
    ) -> DomainResult<ArtifactRejected> {
        if quarantine_transitions::allowed_targets(
            QuarantineEvent::BlockByCurator,
            self.quarantine_status,
        )
        .is_none()
        {
            let other = self.quarantine_status;
            return Err(DomainError::Invariant(format!(
                "cannot curator-block artifact in state {other}"
            )));
        }
        self.quarantine_status = QuarantineStatus::Rejected;
        self.rejection_reason = Some(RejectionReason::Curator { curator_id });
        Ok(ArtifactRejected {
            artifact_id: self.id,
            rejected_by: RejectionReason::Curator { curator_id },
            reason,
        })
    }

    /// Tombstone an artifact whose CAS content failed re-verification.
    /// Transitions to
    /// [`QuarantineStatus::Rejected`] from any non-Rejected state.
    ///
    /// Distinct from [`Self::reject_from_scan`] (which requires
    /// `Quarantined`) and [`Self::reject_from_retroactive_curation`]
    /// (which requires `Quarantined` or `Released`): corruption can
    /// surface against any artifact the scrubber walks past, including
    /// long-released artifacts whose bytes were tampered with later.
    /// Reusing `Rejected` rather than introducing a new state is
    /// deliberate: corruption is
    /// structurally identical to a disqualifying scan finding —
    /// permanently bad content, time does not reverse it.
    ///
    /// Already-rejected artifacts (e.g. a previous scrub run already
    /// tombstoned this blob) are an idempotent no-op: the state stays
    /// `Rejected` and this method returns `Err(Invariant)` so the
    /// caller skips the event append rather than emit a duplicate
    /// `ArtifactCorrupted` for a state-noop transition. The scrub
    /// path treats this as a recoverable "already tombstoned" branch.
    ///
    /// `now` is the wall-clock timestamp the scrubber detected the
    /// mismatch — flows through to `ArtifactCorrupted.detected_at` so
    /// the event carries a server-time fact independent of when the
    /// event store appended.
    pub fn tombstone_from_corruption(
        &mut self,
        computed_hash: ContentHash,
        now: DateTime<Utc>,
    ) -> DomainResult<ArtifactCorrupted> {
        if quarantine_transitions::allowed_targets(
            QuarantineEvent::TombstoneFromCorruption,
            self.quarantine_status,
        )
        .is_none()
        {
            return Err(DomainError::Invariant(format!(
                "cannot tombstone artifact in state {} (already rejected)",
                self.quarantine_status
            )));
        }
        let expected_hash = self.sha256_checksum.clone();
        self.quarantine_status = QuarantineStatus::Rejected;
        // Corruption is not scan-clearable: there is no `RejectionReason`
        // variant for it (it emits `ArtifactCorrupted`, not
        // `ArtifactRejected`). Leaving the reason `None` keeps a
        // corruption-tombstoned artifact ineligible for a scan
        // re-judgement (ADR 0041 invariant #6 — `None` is not `Scanner`).
        self.rejection_reason = None;
        Ok(ArtifactCorrupted {
            artifact_id: self.id,
            computed_hash,
            expected_hash,
            detected_at: now,
        })
    }

    /// Release after quarantine period expires or by admin override.
    /// Valid from `Quarantined` or `ScanIndeterminate` (the wide guard
    /// lets an admin clear a
    /// stuck-scanner artifact without a state dance).
    ///
    /// **Fail-closed predicate (ADR 0007).** The release is
    /// authorized only by an explicit, typed [`ReleaseAuthorization`]
    /// the application layer constructs from verified facts. The boolean
    /// is **deny-by-default**: every `(reason, authz)` pair that is not
    /// an explicit allow is refused. The quarantine window is **never
    /// read here** — the computed deadline is the sweep's *candidacy*
    /// filter (which rows to consider), not its *authorization*. A
    /// timer-driven
    /// release requires a successful scan, an explicit
    /// `scan_backends:[]` waiver, or a recorded verdict under
    /// `enforcement: record`; expiry alone can never release.
    ///
    /// The entity emits
    /// the event with `released_by_user_id = None` and
    /// `justification = None`. The
    /// [`crate::events::ArtifactReleased::validate`] invariant requires
    /// `Admin` / `Curator` to carry both fields — the application
    /// layer (`QuarantineUseCase::admin_release` /
    /// `CurationUseCase::waive`) is responsible for populating them
    /// from the verified `ApiActor` and the HTTP-supplied justification
    /// before the event is appended. `release_expired` (timer sweep)
    /// emits `Timer` and leaves both fields `None`, satisfying the
    /// system-driven invariant.
    pub fn release(
        &mut self,
        reason: ReleaseReason,
        authz: ReleaseAuthorization,
        provenance: ProvenanceClearance,
    ) -> DomainResult<ArtifactReleased> {
        // Source-state guard: releasable only from Quarantined or
        // ScanIndeterminate. (Rejected exits via re_evaluate(); None/
        // Released are not releasable.) The curator
        // surface is **narrower**: a `(Curator, CuratorWaiver)`
        // release accepts `Quarantined` ONLY. `ScanIndeterminate`
        // stays admin-only — clearing a stuck scanner requires the
        // broader admin authority.
        let release_event = match (&reason, authz) {
            (ReleaseReason::Curator, ReleaseAuthorization::CuratorWaiver) => {
                QuarantineEvent::ReleaseCuratorWaiver
            }
            _ => QuarantineEvent::ReleaseGeneral,
        };
        let source_state_ok =
            quarantine_transitions::allowed_targets(release_event, self.quarantine_status)
                .is_some();
        if !source_state_ok {
            // Caller-reachable state precondition (an operator can POST
            // release/waive against an artifact in any state) → InvalidState
            // (HTTP 409), NOT Invariant (HTTP 500). ADR 0025.
            return Err(DomainError::InvalidState(format!(
                "cannot release artifact in state {}",
                self.quarantine_status
            )));
        }

        // FAIL-CLOSED PREDICATE (ADR 0007). A timer-driven release
        // (ReleaseReason::Timer) is authorized ONLY by ScanSucceeded,
        // ScanWaived or ScanRecorded (the three scan-axis authorities:
        // the scan passed / the operator waived scanning / the operator
        // declared the verdict non-gating).
        // AdminOverride / PolicyReEvaluation / CuratorWaiver
        // are operator / system / curator authorities and pair with
        // their own ReleaseReason.
        // A computed deadline `<= now()` alone is NOT a release
        // authority — the window is never read here; expiry is the
        // sweep's *candidacy* signal, not its *authorization*.
        // The `(Curator, CuratorWaiver)` pair is
        // the single allow row for the curator-waive surface; every
        // other cross pair involving either variant is denied
        // (deny-by-default preserved).
        // ADR 0027: the timer arm carries a provenance
        // AND-precondition. A `(Timer, ScanSucceeded|ScanWaived|ScanRecorded)` release
        // is authorized only when `provenance ∈ {NotRequired, Cleared}` —
        // a `Pending` (Required mode, not yet a `ProvenanceVerified`)
        // candidate stays quarantined (fail-closed). The Admin / Curator /
        // PolicyReEval arms IGNORE the provenance param — explicit
        // overrides are never blocked by provenance (the AND-precondition
        // is on the timer arm only, never a new `ReleaseAuthorization`).
        let provenance_clears_timer = matches!(
            provenance,
            ProvenanceClearance::NotRequired | ProvenanceClearance::Cleared
        );
        let authorized = match (&reason, authz) {
            (ReleaseReason::Timer, ReleaseAuthorization::ScanSucceeded) => provenance_clears_timer,
            (ReleaseReason::Timer, ReleaseAuthorization::ScanWaived) => provenance_clears_timer,
            // `enforcement: record` — the scan ran and its verdict is
            // recorded rather than gating. Same AND-precondition as the
            // two arms above: recording a scan verdict says nothing about
            // provenance, so a `Pending` (Required, unverified) candidate
            // still stays quarantined.
            (ReleaseReason::Timer, ReleaseAuthorization::ScanRecorded) => provenance_clears_timer,
            (ReleaseReason::Timer, _) => false,
            (ReleaseReason::Admin, ReleaseAuthorization::AdminOverride) => true,
            (ReleaseReason::Admin, _) => false,
            (ReleaseReason::PolicyReEvaluation, ReleaseAuthorization::PolicyReEvaluation) => true,
            (ReleaseReason::PolicyReEvaluation, _) => false,
            (ReleaseReason::Curator, ReleaseAuthorization::CuratorWaiver) => true,
            (ReleaseReason::Curator, _) => false,
        };
        if !authorized {
            return Err(DomainError::Invariant(
                "release not authorized: timer-only release requires a \
                 successful scan, an explicit scan_backends:[] waiver or a \
                 recorded verdict under enforcement:record, \
                 and a cleared/not-required provenance gate \
                 (fail-closed release predicate, ADR 0007)"
                    .into(),
            ));
        }

        self.quarantine_status = QuarantineStatus::Released;
        Ok(ArtifactReleased {
            artifact_id: self.id,
            released_by: reason,
            released_by_user_id: None,
            justification: None,
        })
    }

    /// Apply a provenance verdict to artifact state (ADR 0027).
    /// Returns the domain event to append (if any) or
    /// `Ok(None)` for the no-op case.
    ///
    /// **Not source-state-gated** — unlike every other method in this
    /// state machine, there is no `match self.quarantine_status` guard
    /// here; the caller (the provenance orchestrator) only ever invokes
    /// this against a held artifact, but the method itself is total over
    /// every [`QuarantineStatus`]. [`crate::entities::quarantine_transitions`]
    /// represents it as `QuarantineEvent::CompleteProvenance`, unrestricted
    /// (`Allowed` from every state) — there is no guard here for the table
    /// to replace.
    ///
    /// - [`ProvenanceOutcome::Verified`] → emit [`ProvenanceVerified`];
    ///   **status unchanged** (like `ScanCompleted(clean)`, a verified
    ///   attestation is a success record that does NOT release the
    ///   artifact early — the release gate reads its *existence* later).
    /// - [`ProvenanceOutcome::Rejected`] → emit [`ProvenanceRejected`];
    ///   status → [`QuarantineStatus::Rejected`].
    /// - [`ProvenanceOutcome::NoAttestation`] (the unsigned case):
    ///   - under [`ProvenanceMode::VerifyIfPresent`] → `Ok(None)` (no
    ///     event, status unchanged — unsigned is allowed);
    ///   - under [`ProvenanceMode::Required`] → **window-aware** (issue #13,
    ///     the push-then-sign round-trip): a missing signature is
    ///     *time-dependent* (the artifact may yet be signed), so it is
    ///     **held** over the same observation window quarantine already
    ///     provides rather than being collapsed into a terminal rejection at
    ///     the first verify:
    ///     - `window_open == true` **OR** `is_referenced_descendant == true`
    ///       → `Ok(None)` (no event, status stays `Quarantined` → the
    ///       release gate reads it as [`ProvenanceClearance::Pending`],
    ///       fail-closed / held);
    ///     - both `false` → emit [`ProvenanceRejected`] with reason
    ///       [`ProvenanceRejectReason::Unsigned`]; status → `Rejected`
    ///       (unsigned-at-expiry IS a terminal rejection there).
    ///   - under [`ProvenanceMode::Off`] → `Ok(None)` (provenance is
    ///     inert; the orchestrator does not run a verifier in `Off`, but
    ///     the method is total over the mode for safety).
    ///
    /// `window_open` and `is_referenced_descendant` gate **only** the
    /// `NoAttestation × Required` arm. A *bad* signature is
    /// *time-independent* (already wrong) and equally
    /// *position-independent* (a forged signature on a layer blob is still
    /// forged), so the [`ProvenanceOutcome::Verified`] and
    /// [`ProvenanceOutcome::Rejected`] arms never consult either flag — a
    /// valid or a forged/untrusted/digest-mismatch signature is decided
    /// immediately, even mid-window and even on a descendant. The domain
    /// stays I/O-free: the application layer computes `window_open`
    /// (`effective_quarantine_deadline(window_start, duration) > now`) and
    /// resolves `is_referenced_descendant`, then threads both in.
    ///
    /// # `is_referenced_descendant` — why a descendant NEVER
    /// terminally-rejects as `Unsigned` (issue #115 defect (b))
    ///
    /// A **referenced-tree descendant** is an artifact that is already a
    /// `content_references` target of some other, already-ingested
    /// artifact: an index's child manifest, a manifest's config/layer
    /// blob, a referrer's subject. Such artifacts get a **zero-length**
    /// observation window by design (#46: anchor = `ingested_at −
    /// duration`), so `window_open` is `false` for them from the instant
    /// they are ingested.
    ///
    /// That interacts fatally with `Required`. cosign signs only the
    /// top-level digest, so a layer blob has **no attestation of its own
    /// and never will** — its provenance authority is its parent's
    /// signature, delivered later by
    /// [`Self::cascade_provenance_clearance`]. Before this carve-out, the
    /// ingest-enqueued verify of a layer resolved
    /// `NoAttestation × Required × window_open == false` → terminal
    /// `Rejected{Unsigned}` *before* the subject's cascade could clear it,
    /// and the cascade refuses a rejected constituent ("terminal is
    /// terminal") — permanently bricking a correctly-signed image.
    ///
    /// Holding instead is the fail-closed outcome, not a relaxation: the
    /// artifact stays `Quarantined` (503, not downloadable) until either
    /// the cascade clears it or an admin releases it per ADR 0025. An
    /// unsigned parent leaves its constituents held forever — correct,
    /// and recoverable by signing the parent, unlike the terminal
    /// rejection it replaces. See ADR 0007 (zero-window section) and
    /// ADR 0039 (cascade section).
    ///
    /// `backend` is the id of the verifier that produced the verdict
    /// (`port.name()`, e.g. `"cosign"`) — recorded on the event for audit
    /// attribution and kept consistent with the `hort_provenance_*{backend}`
    /// metric the orchestrator emits from the same value. (Hardcoding
    /// `"cosign"` here would mislabel a future Tier-2 verifier's events while
    /// its metric reported the real backend.) The `Required`-mode unsigned
    /// mapping instead records the synthetic `"(policy)"` backend — no
    /// verifier verdict produced it, it is a policy decision — so the passed
    /// `backend` is intentionally unused on that one arm.
    pub fn complete_provenance(
        &mut self,
        verdict: ProvenanceVerdict,
        mode: ProvenanceMode,
        backend: &str,
        window_open: bool,
        is_referenced_descendant: bool,
    ) -> DomainResult<Option<DomainEvent>> {
        match verdict.outcome {
            ProvenanceOutcome::Verified {
                signer,
                predicate_type,
            } => {
                // Success record only — status is deliberately unchanged
                // (must NOT release early; the release sweep reads the
                // event's existence under `Required`).
                Ok(Some(DomainEvent::ProvenanceVerified(ProvenanceVerified {
                    artifact_id: self.id,
                    content_hash: self.sha256_checksum.clone(),
                    backend: backend.into(),
                    signer,
                    predicate_type,
                    // A direct verification of this artifact's own
                    // attestation — never a cascade (see
                    // `cascade_provenance_clearance`).
                    cascaded_from: None,
                })))
            }
            ProvenanceOutcome::Rejected(reason) => {
                self.quarantine_status = QuarantineStatus::Rejected;
                // A provenance rejection is not scan-clearable. There is
                // no `RejectionReason` variant for provenance (it emits
                // `ProvenanceRejected`); leaving the reason `None` keeps
                // the artifact ineligible for a scan re-judgement
                // (ADR 0041 invariant #6 — `None` is not `Scanner`).
                self.rejection_reason = None;
                Ok(Some(DomainEvent::ProvenanceRejected(ProvenanceRejected {
                    artifact_id: self.id,
                    content_hash: self.sha256_checksum.clone(),
                    backend: backend.into(),
                    reason,
                })))
            }
            ProvenanceOutcome::NoAttestation => match mode {
                // Window-aware hold under Required (issue #13). A missing
                // signature is time-dependent: while the observation window
                // is still open the artifact is HELD (no event, status stays
                // Quarantined → Pending), exactly like an incomplete scan.
                //
                // A referenced-tree descendant is held REGARDLESS of the
                // window (issue #115 defect (b)): its window is zero-length
                // by construction (#46) and it can never carry its own
                // attestation — cosign signs only the top-level digest — so
                // its provenance authority is its parent's signature,
                // arriving later via `cascade_provenance_clearance`.
                // Terminally rejecting it here would race ahead of that
                // cascade and permanently brick a correctly-signed image.
                // See the method doc for the full rationale.
                ProvenanceMode::Required if window_open || is_referenced_descendant => Ok(None),
                ProvenanceMode::Required => {
                    // Window closed on a non-descendant → unsigned-at-expiry
                    // IS a terminal rejection under Required (ADR 0027).
                    self.quarantine_status = QuarantineStatus::Rejected;
                    // Not scan-clearable — see the `Rejected` arm above.
                    self.rejection_reason = None;
                    Ok(Some(DomainEvent::ProvenanceRejected(ProvenanceRejected {
                        artifact_id: self.id,
                        content_hash: self.sha256_checksum.clone(),
                        backend: "(policy)".into(),
                        reason: ProvenanceRejectReason::Unsigned,
                    })))
                }
                // VerifyIfPresent / Off: unsigned-but-allowed → no event,
                // status unchanged.
                ProvenanceMode::VerifyIfPresent | ProvenanceMode::Off => Ok(None),
            },
        }
    }

    /// Record a **cascaded** provenance clearance: this artifact is a
    /// constituent of a verified subject whose signed bytes bind this
    /// artifact's digest (ADR 0039 provenance-clearance cascade). cosign
    /// signs only the top-level digest, but that digest cryptographically
    /// covers the whole tree — an index's `manifests[]` digests are inside
    /// the signed index bytes and a manifest's config/layer digests are
    /// inside its bytes — so the signature over `cascaded_from` attests
    /// exactly this artifact's content too.
    ///
    /// Returns the [`ProvenanceVerified`] event to append, carrying the
    /// verified subject's hash in `cascaded_from` (the audit attribution:
    /// "cleared via signature over `cascaded_from`") and the subject's
    /// verified `signer`. Like the Verified arm of
    /// [`Self::complete_provenance`], this is a **success record only** —
    /// status is unchanged (`&self`, no mutation); the release sweep reads
    /// the event's existence under `Required` and every other gate (scan,
    /// observation window) stays per-artifact.
    ///
    /// Valid **only** from [`QuarantineStatus::Quarantined`] — the held,
    /// pending-provenance state. Every other state refuses
    /// (`Err(Invariant)`), fail-closed:
    /// - `Rejected` / `ScanIndeterminate` — terminal is terminal; a
    ///   cascade never resurrects a rejected constituent (the operator
    ///   re-pushes instead);
    /// - `Released` / `None` — outside the hold, nothing to clear.
    pub fn cascade_provenance_clearance(
        &self,
        cascaded_from: ContentHash,
        signer: SignerIdentity,
        predicate_type: Option<String>,
        backend: &str,
    ) -> DomainResult<ProvenanceVerified> {
        if quarantine_transitions::allowed_targets(
            QuarantineEvent::CascadeProvenanceClearance,
            self.quarantine_status,
        )
        .is_none()
        {
            return Err(DomainError::Invariant(format!(
                "cannot cascade provenance clearance to artifact in state {}",
                self.quarantine_status
            )));
        }
        Ok(ProvenanceVerified {
            artifact_id: self.id,
            content_hash: self.sha256_checksum.clone(),
            backend: backend.into(),
            signer,
            predicate_type,
            cascaded_from: Some(cascaded_from),
        })
    }

    /// Terminal scan failure: the scanner could not decide. Fail-closed
    /// (ADR 0007). Valid from `Quarantined` (strict: the
    /// hold becomes indeterminate) and `None` (permissive
    /// `quarantineDuration:0`: an undecided scan retroactively blocks
    /// downloads, mirroring [`Self::reject_from_scan`]'s `None` source
    /// state).
    ///
    /// Rejects `Released` (already passed review — a later infra failure
    /// does not un-review it; that retroactive path is the
    /// rescan-amplification concern, deliberately not
    /// widened), `Rejected` (strictly-stronger terminal block — never
    /// downgrade "proven bad" to "unknown"), and `ScanIndeterminate`
    /// (idempotent no-op: returns `Err(Invariant)` *before* mutating so
    /// the orchestrator skips a duplicate event append, mirroring
    /// [`Self::tombstone_from_corruption`]'s already-rejected branch).
    pub fn fail_scan_indeterminate(
        &mut self,
        scanner: String,
        reason: String,
        attempts: u32,
    ) -> DomainResult<ScanIndeterminate> {
        if quarantine_transitions::allowed_targets(
            QuarantineEvent::FailScanIndeterminate,
            self.quarantine_status,
        )
        .is_none()
        {
            let other = self.quarantine_status;
            return Err(DomainError::Invariant(format!(
                "cannot mark scan-indeterminate for artifact in state {other}"
            )));
        }
        self.quarantine_status = QuarantineStatus::ScanIndeterminate;
        Ok(ScanIndeterminate {
            artifact_id: self.id,
            scanner,
            reason,
            attempts,
        })
    }

    /// Re-evaluate after a scan-policy change cleared the scan block.
    /// Only valid from `Rejected`.
    ///
    /// If the quarantine observation window is still in the future,
    /// transitions back to `Quarantined` — the remaining window still
    /// applies. Otherwise transitions directly to `Released`.
    ///
    /// # Cross-axis release conjunction (ADR 0041, invariant #6)
    ///
    /// A `Rejected → Released` transition fires only on the full
    /// conjunction `scan ∧ curation ∧ provenance` — each conjunct
    /// *mechanized*, none merely proxied:
    ///
    /// - **(a) Rejection-reason eligibility.** Only a scan-clearable
    ///   rejection (`rejection_reason == Some(RejectionReason::Scanner)`)
    ///   is a candidate for a scan re-judgement. A provenance- /
    ///   curation- / admin- / corruption-rejected artifact (any other
    ///   reason, including `None`) is **ineligible** and returns
    ///   `Err(Invariant)` without mutating, so the application pass skips
    ///   it (the artifact stays `Rejected`). The caller has already
    ///   re-hydrated `rejection_reason` from the stored `ArtifactRejected`
    ///   event (the projection row does not persist it).
    /// - **(b) Active provenance precondition.** The `Released` arm fires
    ///   only when `provenance ∈ {NotRequired, Cleared}` — a scan-cleared
    ///   artifact with `Pending` (Required mode, not yet a
    ///   `ProvenanceVerified`) provenance stays `Rejected` (fail-closed).
    /// - **(c) Active curation precondition.** The `Released` arm fires
    ///   only when `curation == Cleared` — a `Blocked` (a currently-active
    ///   curation rule matches) artifact stays `Rejected`. Symmetric to
    ///   (b); not covered by (a) (see [`CurationClearance`]).
    ///
    /// `provenance` and `curation` are verified facts the application
    /// layer computes from the live provenance state / curation rules and
    /// passes in (mirroring the [`ProvenanceClearance`] param on
    /// [`Self::release`]); the domain stays pure (no I/O).
    ///
    /// The **re-quarantine** arm (`Rejected → Quarantined`, window still
    /// active) is **not** gated by (b)/(c): the artifact remains held
    /// (downloads blocked), so deferring the curation/provenance gate to
    /// the eventual timer release is fail-closed-safe. The reason guard
    /// (a) gates the whole method.
    ///
    /// **The window check reads the transient
    /// [`Self::quarantine_deadline`]** — the computed deadline, NOT the
    /// stored anchor [`Self::quarantine_window_start`]
    /// (the anchor is always in the past, so comparing it to `now` would
    /// always read "elapsed" and release a re-evaluated `Rejected`
    /// artifact ~`duration` early). The application caller
    /// (`PolicyUseCase`) hydrates `quarantine_deadline` from
    /// [`crate::policy::effective_quarantine_deadline`] before calling
    /// this method; an un-hydrated `None` is treated as "elapsed",
    /// matching the historic no-quarantine-hold semantics.
    pub fn re_evaluate(
        &mut self,
        now: DateTime<Utc>,
        provenance: ProvenanceClearance,
        curation: CurationClearance,
    ) -> DomainResult<DomainEvent> {
        if quarantine_transitions::allowed_targets(
            QuarantineEvent::ReEvaluate,
            self.quarantine_status,
        )
        .is_none()
        {
            return Err(DomainError::Invariant(format!(
                "cannot re-evaluate artifact in state {}",
                self.quarantine_status
            )));
        }

        // (a) Eligibility guard: only a scan-clearable rejection is a
        // candidate for a scan re-judgement. Every other reason (and an
        // unknown `None`) is ineligible — return without mutating so the
        // application pass leaves the artifact `Rejected`.
        if !is_scan_clearable(self.rejection_reason.as_ref()) {
            return Err(DomainError::Invariant(format!(
                "cannot scan-re-evaluate artifact rejected by {:?}: only a \
                 scan-axis rejection (Scanner or ScanPolicyRetroactive) is \
                 scan-clearable (ADR 0041 invariant #6)",
                self.rejection_reason
            )));
        }

        let still_in_window = self
            .quarantine_deadline
            .is_some_and(|deadline| deadline > now);

        if still_in_window {
            self.quarantine_status = QuarantineStatus::Quarantined;
            // The artifact stays held; clearing the scan reason here keeps
            // a subsequent re-evaluation from treating a now-re-quarantined
            // artifact as a stale scan rejection. The eventual timer
            // release applies the provenance gate via `release()`.
            self.rejection_reason = None;
            Ok(DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id: self.id,
                // The re-quarantine preserves the original anchor — the
                // observation window is unchanged, not restarted.
                quarantine_window_start: self.quarantine_window_start.unwrap_or(now),
            }))
        } else {
            // (b)+(c) the release arm requires both cross-axis conjuncts
            // to currently clear. A pending/failed provenance or an active
            // curation block keeps the artifact `Rejected` (fail-closed) —
            // return without mutating so the pass skips it.
            let provenance_clears = matches!(
                provenance,
                ProvenanceClearance::NotRequired | ProvenanceClearance::Cleared
            );
            let curation_clears = matches!(curation, CurationClearance::Cleared);
            if !provenance_clears || !curation_clears {
                return Err(DomainError::Invariant(format!(
                    "cannot release re-evaluated artifact: cross-axis release \
                     conjunction not satisfied (provenance={provenance:?}, \
                     curation={curation:?}) — ADR 0041 invariant #6"
                )));
            }

            self.quarantine_status = QuarantineStatus::Released;
            self.rejection_reason = None;
            // PolicyReEvaluation is system-driven
            // (no operator attribution); the variant invariant requires
            // both fields `None`.
            Ok(DomainEvent::ArtifactReleased(ArtifactReleased {
                artifact_id: self.id,
                released_by: ReleaseReason::PolicyReEvaluation,
                released_by_user_id: None,
                justification: None,
            }))
        }
    }

    /// Record the **deletion** of this artifact — the terminal
    /// artifact-lifecycle transition on the operator/registry-API axis.
    ///
    /// Deletion is a **soft delete**: the projection row survives with
    /// `deleted_at` set and the CAS blob is untouched (blob lifetime is
    /// refcount-gated GC, never a per-artifact delete — another
    /// repository's artifact may reference the same bytes). What changes
    /// is that the artifact leaves the live catalog: every live read
    /// filters `deleted_at IS NULL`, and the `(repository_id, path)`
    /// unique index is predicated on the same, so the freed path admits a
    /// fresh ingest as a NEW artifact (new id, new row, new stream).
    ///
    /// Deliberately **orthogonal to [`QuarantineStatus`]**: this method
    /// does not touch `quarantine_status`, and there is no `Deleted`
    /// status variant. A `Released` artifact and a `Rejected` one are
    /// both deletable, and the pre-deletion status is exactly what an
    /// auditor needs preserved. For the same reason deletion does not go
    /// through the [`quarantine_transitions`] table — that table models
    /// the scan-verdict axis only.
    ///
    /// Idempotency guard: deleting an already-deleted artifact is an
    /// invariant violation, not a second deletion — the terminal event
    /// must appear at most once on the stream. Callers that treat a
    /// re-delete as a benign no-op resolve it before reaching here (the
    /// adapter's conditional `WHERE deleted_at IS NULL` write matches no
    /// row and surfaces `NotFound`).
    ///
    /// `deleted_at` is caller-supplied rather than read from a clock so
    /// the entity stays pure and the persisted column and the entity
    /// agree on one timestamp.
    pub fn delete(&mut self, deleted_at: DateTime<Utc>) -> DomainResult<ArtifactDeleted> {
        if let Some(at) = self.deleted_at {
            return Err(DomainError::Invariant(format!(
                "artifact {} was already deleted at {at}",
                self.id
            )));
        }
        self.deleted_at = Some(deleted_at);
        Ok(ArtifactDeleted {
            artifact_id: self.id,
            repository_id: self.repository_id,
            path: self.path.clone(),
            content_hash: self.sha256_checksum.clone(),
        })
    }

    /// Check if downloads are allowed.
    ///
    /// A deleted artifact is never downloadable, whatever its quarantine
    /// status was when it was deleted. In practice every live read
    /// already filters deleted rows out, so this conjunct is
    /// defence-in-depth against a caller that materialised an artifact
    /// through the deletion path itself.
    pub fn is_downloadable(&self) -> bool {
        self.deleted_at.is_none()
            && matches!(
                self.quarantine_status,
                QuarantineStatus::None | QuarantineStatus::Released
            )
    }

    /// Check if promotion is allowed. Deleted artifacts are not
    /// promotable — same reasoning as [`Self::is_downloadable`].
    pub fn is_promotable(&self) -> bool {
        self.deleted_at.is_none()
            && matches!(
                self.quarantine_status,
                QuarantineStatus::None | QuarantineStatus::Released
            )
    }
}

/// Is a rejection **scan-clearable** — i.e. on the scan axis, so a later
/// scan-policy loosen can re-release it (ADR 0041 invariant #6 (a))?
///
/// The scan-axis reasons are [`RejectionReason::Scanner`] (a fresh-scan
/// rejection) and [`RejectionReason::ScanPolicyRetroactive`] (a retroactive
/// scan-policy tighten re-hold — see
/// [`Artifact::reject_from_scan_policy_retroactive`]). Both are cleared by
/// re-deriving the verdict over the artifact's stored findings, so a
/// subsequent loosen must be able to re-release an artifact re-held by an
/// earlier tighten — otherwise a tighten→loosen sequence would strand it
/// `Rejected` forever.
///
/// Every other reason is **not** scan-clearable and stays held:
/// `Admin`, `Curator` (manual decisions), `CurationRetroactive` (curation
/// axis), and an unknown `None` (a legacy / reason-less rejection, or a
/// provenance / corruption rejection that deliberately leaves the reason
/// `None`). Exhaustive `match` (no wildcard) so a future `RejectionReason`
/// variant forces a deliberate scan-clearable / not decision here rather
/// than silently defaulting to eligible.
pub fn is_scan_clearable(reason: Option<&RejectionReason>) -> bool {
    match reason {
        Some(RejectionReason::Scanner) | Some(RejectionReason::ScanPolicyRetroactive) => true,
        Some(RejectionReason::Admin)
        | Some(RejectionReason::Curator { .. })
        | Some(RejectionReason::CurationRetroactive { .. })
        | None => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- QuarantineStatus ---------------------------------------------------

    #[test]
    fn quarantine_display() {
        assert_eq!(QuarantineStatus::None.to_string(), "none");
        assert_eq!(QuarantineStatus::Quarantined.to_string(), "quarantined");
        assert_eq!(QuarantineStatus::Released.to_string(), "released");
        assert_eq!(QuarantineStatus::Rejected.to_string(), "rejected");
        // The terminal scan-failure state's wire form (ADR 0007).
        assert_eq!(
            QuarantineStatus::ScanIndeterminate.to_string(),
            "scan_indeterminate"
        );
    }

    #[test]
    fn quarantine_from_str_roundtrip() {
        for name in &[
            "none",
            "quarantined",
            "released",
            "rejected",
            "scan_indeterminate",
        ] {
            let parsed: QuarantineStatus = name.parse().unwrap();
            assert_eq!(parsed.to_string(), *name);
        }
    }

    #[test]
    fn quarantine_from_str_scan_indeterminate_case_insensitive() {
        let parsed: QuarantineStatus = "SCAN_INDETERMINATE".parse().unwrap();
        assert_eq!(parsed, QuarantineStatus::ScanIndeterminate);
    }

    #[test]
    fn quarantine_from_str_case_insensitive() {
        let parsed: QuarantineStatus = "QUARANTINED".parse().unwrap();
        assert_eq!(parsed, QuarantineStatus::Quarantined);
    }

    #[test]
    fn quarantine_from_str_invalid() {
        let result: Result<QuarantineStatus, _> = "pending".parse();
        assert!(result.is_err());
    }

    #[test]
    fn quarantine_copy() {
        let a = QuarantineStatus::Released;
        let b = a;
        assert_eq!(a, b);
    }

    // -- Artifact -----------------------------------------------------------

    const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn sample_artifact() -> Artifact {
        Artifact {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            name: "my-package".into(),
            name_as_published: "My_Package".into(),
            version: Some("1.0.0".into()),
            path: "my-package/1.0.0/my-package-1.0.0.tar.gz".into(),
            size_bytes: 1024,
            sha256_checksum: VALID_SHA256.parse().unwrap(),
            sha1_checksum: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".into()),
            md5_checksum: None,
            content_type: "application/gzip".into(),
            quarantine_status: QuarantineStatus::None,
            rejection_reason: None,
            quarantine_window_start: None,
            quarantine_deadline: None,
            deleted_at: None,
            upstream_published_at: None,
            uploaded_by: Some(Uuid::nil()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn artifact_clone_eq() {
        let a = sample_artifact();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn artifact_sha256_is_content_hash() {
        let a = sample_artifact();
        assert_eq!(a.sha256_checksum.as_ref(), VALID_SHA256);
    }

    #[test]
    fn artifact_quarantined_state() {
        let mut a = sample_artifact();
        a.quarantine_status = QuarantineStatus::Quarantined;
        a.quarantine_window_start = Some(Utc::now());
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
        assert!(a.quarantine_window_start.is_some());
    }

    /// The `upstream_published_at` audit field
    /// defaults to `None` in the sample fixture, mirroring the
    /// constructor default. Writers without parseable upstream metadata
    /// stamp `None`; the ingest path populates the field from
    /// per-format upstream metadata; the prefetch use case is the consumer.
    #[test]
    fn artifact_sample_defaults_upstream_published_at_to_none() {
        let a = sample_artifact();
        assert_eq!(a.upstream_published_at, None);
    }

    /// The field round-trips a value when populated.
    /// The field is a plain `Option<DateTime<Utc>>`; this test pins
    /// the type and clone-equality so a future change cannot silently
    /// drop the field from `PartialEq`/`Clone`.
    #[test]
    fn artifact_upstream_published_at_roundtrips_on_clone() {
        let mut a = sample_artifact();
        let ts = Utc::now();
        a.upstream_published_at = Some(ts);
        let b = a.clone();
        assert_eq!(a.upstream_published_at, Some(ts));
        assert_eq!(b.upstream_published_at, Some(ts));
        assert_eq!(a, b);
    }

    // -- ArtifactMetadata ---------------------------------------------------

    #[test]
    fn artifact_metadata_clone_eq() {
        let meta = ArtifactMetadata {
            artifact_id: Uuid::nil(),
            format: RepositoryFormat::Npm,
            metadata: serde_json::json!({"name": "@scope/pkg"}),
            metadata_blob: None,
            properties: serde_json::json!({}),
        };
        let cloned = meta.clone();
        assert_eq!(meta, cloned);
    }

    #[test]
    fn artifact_metadata_with_other_format() {
        let meta = ArtifactMetadata {
            artifact_id: Uuid::nil(),
            format: RepositoryFormat::Other("custom-wasm".into()),
            metadata: serde_json::json!({}),
            metadata_blob: None,
            properties: serde_json::json!({}),
        };
        assert_eq!(meta.format.to_string(), "custom-wasm");
    }

    // -- State machine: quarantine ------------------------------------------

    fn quarantined_artifact() -> Artifact {
        let mut a = sample_artifact();
        a.quarantine_status = QuarantineStatus::Quarantined;
        // The stored anchor is the window *start* (ingest-time);
        // populated so `release()` tests can prove it is never read.
        a.quarantine_window_start = Some(Utc::now());
        a
    }

    fn rejected_artifact() -> Artifact {
        let mut a = quarantined_artifact();
        a.quarantine_status = QuarantineStatus::Rejected;
        // The default rejected fixture is a *scanner*-rejected artifact —
        // the scan-clearable reason, so `re_evaluate`'s eligibility guard
        // (ADR 0041 invariant #6 (a)) admits it. Non-scanner reasons are
        // exercised by dedicated tests.
        a.rejection_reason = Some(RejectionReason::Scanner);
        a
    }

    fn released_artifact() -> Artifact {
        let mut a = sample_artifact();
        a.quarantine_status = QuarantineStatus::Released;
        a
    }

    /// An artifact already in the terminal
    /// `ScanIndeterminate` state. Built from a quarantined artifact so
    /// `quarantine_window_start` is populated (used to prove `release()`
    /// never reads it).
    fn scan_indeterminate_artifact() -> Artifact {
        let mut a = quarantined_artifact();
        a.quarantine_status = QuarantineStatus::ScanIndeterminate;
        a
    }

    #[test]
    fn quarantine_from_none_succeeds() {
        let mut a = sample_artifact();
        let window_start = Utc::now();
        let event = a.quarantine(window_start).unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
        // `quarantine` stores the anchor, not a deadline.
        assert_eq!(a.quarantine_window_start, Some(window_start));
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(event.quarantine_window_start, window_start);
    }

    #[test]
    fn quarantine_from_quarantined_fails() {
        let mut a = quarantined_artifact();
        let result = a.quarantine(Utc::now());
        assert!(matches!(result, Err(DomainError::Invariant(_))));
    }

    #[test]
    fn quarantine_from_released_fails() {
        let mut a = released_artifact();
        let result = a.quarantine(Utc::now());
        assert!(matches!(result, Err(DomainError::Invariant(_))));
    }

    #[test]
    fn quarantine_from_rejected_fails() {
        let mut a = rejected_artifact();
        let result = a.quarantine(Utc::now());
        assert!(matches!(result, Err(DomainError::Invariant(_))));
    }

    // -- State machine: record_clean_scan -----------------------------------

    #[test]
    fn record_clean_scan_from_quarantined_ok() {
        let a = quarantined_artifact();
        let original_status = a.quarantine_status;
        let original_window_start = a.quarantine_window_start;
        assert!(a.record_clean_scan().is_ok());
        // Status and the window anchor must NOT change.
        assert_eq!(a.quarantine_status, original_status);
        assert_eq!(a.quarantine_window_start, original_window_start);
    }

    /// State-machine extension for `quarantineDuration = 0` (permissive
    /// scan mode): a clean scan against an artifact that was never
    /// quarantined is the normal happy path, NOT an invariant violation.
    /// The artifact stays in `None` and remains downloadable (the
    /// `quarantineDuration: 0` permissive-mode contract).
    #[test]
    fn record_clean_scan_from_none_succeeds_in_permissive_mode() {
        let a = sample_artifact();
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
        a.record_clean_scan()
            .expect("clean scan from None is a no-op in permissive mode");
        // State remains None — no transition on clean.
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
    }

    #[test]
    fn record_clean_scan_from_released_fails() {
        let a = released_artifact();
        assert!(matches!(
            a.record_clean_scan(),
            Err(DomainError::Invariant(_))
        ));
    }

    #[test]
    fn record_clean_scan_from_rejected_fails() {
        let a = rejected_artifact();
        assert!(matches!(
            a.record_clean_scan(),
            Err(DomainError::Invariant(_))
        ));
    }

    // -- State machine: reject_from_scan ------------------------------------

    #[test]
    fn reject_from_scan_from_quarantined_succeeds() {
        let mut a = quarantined_artifact();
        let event = a.reject_from_scan("CVE-2024-0001".into()).unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(event.rejected_by, RejectionReason::Scanner);
        assert_eq!(event.reason, "CVE-2024-0001");
        // ADR 0041: the scan-clearable reason is carried on the aggregate.
        assert_eq!(a.rejection_reason, Some(RejectionReason::Scanner));
    }

    /// State-machine extension for `quarantineDuration = 0` (permissive
    /// scan mode): the artifact ingests at `None` and is downloadable;
    /// the scan runs in the background; bad findings retroactively
    /// block the artifact via `None → Rejected`. Pre-extension this
    /// transition was rejected as an invariant violation — preserving
    /// that behaviour would force every scan-policy workflow through
    /// `Quarantined`, which the smoke's `quarantineDuration: 0s`
    /// configuration explicitly opts out of.
    #[test]
    fn reject_from_scan_from_none_succeeds_in_permissive_mode() {
        let mut a = sample_artifact();
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
        let event = a
            .reject_from_scan("CVE-2021-23337".into())
            .expect("reject_from_scan must accept None in permissive mode");
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(event.rejected_by, RejectionReason::Scanner);
        assert_eq!(event.reason, "CVE-2021-23337");
    }

    #[test]
    fn reject_from_scan_from_released_fails() {
        let mut a = released_artifact();
        assert!(matches!(
            a.reject_from_scan("reason".into()),
            Err(DomainError::Invariant(_))
        ));
    }

    #[test]
    fn reject_from_scan_from_rejected_fails() {
        let mut a = rejected_artifact();
        assert!(matches!(
            a.reject_from_scan("reason".into()),
            Err(DomainError::Invariant(_))
        ));
    }

    // -- State machine: reject_from_retroactive_curation --------------------

    #[test]
    fn reject_from_retroactive_curation_from_quarantined_succeeds() {
        let mut a = quarantined_artifact();
        let rule_id = Uuid::new_v4();
        let event = a
            .reject_from_retroactive_curation(rule_id, "policy block".into())
            .unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(
            event.rejected_by,
            RejectionReason::CurationRetroactive { rule_id }
        );
        assert_eq!(event.reason, "policy block");
        // ADR 0041: a curation rejection is NOT scan-clearable; the
        // aggregate carries the curation reason (ineligible for
        // `re_evaluate`'s scan re-judgement).
        assert_eq!(
            a.rejection_reason,
            Some(RejectionReason::CurationRetroactive { rule_id })
        );
    }

    #[test]
    fn reject_from_retroactive_curation_from_released_succeeds() {
        let mut a = released_artifact();
        let rule_id = Uuid::new_v4();
        let event = a
            .reject_from_retroactive_curation(rule_id, "policy block".into())
            .unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(
            event.rejected_by,
            RejectionReason::CurationRetroactive { rule_id }
        );
    }

    #[test]
    fn reject_from_retroactive_curation_from_none_fails() {
        let mut a = sample_artifact();
        let result = a.reject_from_retroactive_curation(Uuid::new_v4(), "reason".into());
        assert!(matches!(result, Err(DomainError::Invariant(_))));
    }

    #[test]
    fn reject_from_retroactive_curation_from_rejected_fails() {
        let mut a = rejected_artifact();
        let result = a.reject_from_retroactive_curation(Uuid::new_v4(), "reason".into());
        assert!(matches!(result, Err(DomainError::Invariant(_))));
    }

    // -- State machine: block_by_curator ------------------------------------
    //
    // Mirrors `reject_from_retroactive_curation`'s state-guard SHAPE
    // but emits the `RejectionReason::Curator { curator_id }`
    // variant. Source-state guard:
    //   None | Quarantined | Released → Rejected (any non-terminal state).
    //   Rejected → DomainError::Invariant (the use-case layer treats
    //   this as an idempotent no-op short-circuit).
    // ScanIndeterminate is a TERMINAL scan-failure state (ADR 0007;
    // admin-only exit — curator authority is narrower) and is
    // therefore NOT a valid block_by_curator source state: only the
    // three non-terminal states are accepted.

    #[test]
    fn block_by_curator_from_none_succeeds() {
        let mut a = sample_artifact();
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
        let curator_id = Uuid::new_v4();
        let event = a
            .block_by_curator(curator_id, "shadow IT block".into())
            .unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(event.rejected_by, RejectionReason::Curator { curator_id });
        assert_eq!(event.reason, "shadow IT block");
        // ADR 0041: a curator block is NOT scan-clearable.
        assert_eq!(
            a.rejection_reason,
            Some(RejectionReason::Curator { curator_id })
        );
    }

    #[test]
    fn block_by_curator_from_quarantined_succeeds() {
        let mut a = quarantined_artifact();
        let curator_id = Uuid::new_v4();
        let event = a
            .block_by_curator(curator_id, "blocked while held".into())
            .unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(event.rejected_by, RejectionReason::Curator { curator_id });
        assert_eq!(event.reason, "blocked while held");
    }

    #[test]
    fn block_by_curator_from_released_succeeds() {
        // The shadow-IT case: an already-released artifact is pulled from
        // the catalog after the operator is paged by external advisory
        // intelligence. Mirrors reject_from_retroactive_curation's
        // Released → Rejected transition (same shape as reject_from_retroactive_curation).
        let mut a = released_artifact();
        let curator_id = Uuid::new_v4();
        let event = a
            .block_by_curator(curator_id, "advisory paged".into())
            .unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(event.rejected_by, RejectionReason::Curator { curator_id });
        assert_eq!(event.reason, "advisory paged");
    }

    #[test]
    fn block_by_curator_from_rejected_fails() {
        // The use-case layer treats this Err as the idempotent no-op
        // short-circuit (BlockOutcome.already_rejected_ids; no event
        // appended). The entity contract is: do NOT mutate state, do NOT
        // emit an event — return Invariant so the caller skips append.
        let mut a = rejected_artifact();
        let result = a.block_by_curator(Uuid::new_v4(), "redundant".into());
        assert!(matches!(result, Err(DomainError::Invariant(_))));
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
    }

    #[test]
    fn block_by_curator_from_scan_indeterminate_fails() {
        // ScanIndeterminate is a terminal scan-failure state
        // (ADR 0007; admin-only exit); only
        // None | Quarantined | Released are accepted source states.
        // Mirrors the curator-waive surface: curator authority is
        // **narrower** than admin — clearing a stuck scanner stays
        // admin-only on the release side; symmetrically here the block
        // side does not widen to ScanIndeterminate either.
        let mut a = scan_indeterminate_artifact();
        let result = a.block_by_curator(Uuid::new_v4(), "should not block".into());
        assert!(matches!(result, Err(DomainError::Invariant(_))));
        assert_eq!(a.quarantine_status, QuarantineStatus::ScanIndeterminate);
    }

    #[test]
    fn block_by_curator_event_payload_carries_curator_id() {
        // Explicit payload pin: a freshly-generated curator_id must
        // round-trip onto the `Curator { curator_id }` variant. Defends
        // against a future refactor swapping curator_id for, e.g., the
        // artifact's `uploaded_by` (which would compile but be wrong).
        let mut a = quarantined_artifact();
        let curator_id = Uuid::new_v4();
        let event = a
            .block_by_curator(curator_id, "payload pin".into())
            .unwrap();
        match event.rejected_by {
            RejectionReason::Curator { curator_id: cid } => assert_eq!(cid, curator_id),
            other => panic!("expected RejectionReason::Curator, got {other:?}"),
        }
    }

    // -- State machine: tombstone_from_corruption ----------------------------

    fn computed_hash() -> ContentHash {
        // Distinct from the artifact's `sha256_checksum` so the
        // computed-vs-expected pair on the event is observably non-equal.
        "aa".repeat(32).parse().unwrap()
    }

    #[test]
    fn tombstone_from_corruption_from_none_succeeds() {
        let mut a = sample_artifact();
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
        let now = Utc::now();
        let event = a
            .tombstone_from_corruption(computed_hash(), now)
            .expect("tombstone from None must succeed");
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(event.computed_hash, computed_hash());
        assert_eq!(event.expected_hash, a.sha256_checksum);
        assert_eq!(event.detected_at, now);
        // ADR 0041: corruption is not scan-clearable — reason stays None
        // (ineligible for `re_evaluate`'s scan re-judgement).
        assert_eq!(a.rejection_reason, None);
    }

    #[test]
    fn tombstone_from_corruption_from_quarantined_succeeds() {
        let mut a = quarantined_artifact();
        let event = a
            .tombstone_from_corruption(computed_hash(), Utc::now())
            .expect("tombstone from Quarantined must succeed");
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(event.expected_hash, a.sha256_checksum);
    }

    #[test]
    fn tombstone_from_corruption_from_released_succeeds() {
        // Released artifacts are the most-likely target — quarantine
        // window expired, downloads have been served, scrubber catches
        // a later at-rest corruption.
        let mut a = released_artifact();
        let event = a
            .tombstone_from_corruption(computed_hash(), Utc::now())
            .expect("tombstone from Released must succeed");
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(event.expected_hash, a.sha256_checksum);
    }

    #[test]
    fn tombstone_from_corruption_from_rejected_is_idempotent_skip() {
        // Already-rejected: returning Err signals the use case to skip
        // emitting a duplicate event. State stays Rejected (caller does
        // not mutate on Err — we still flip the field internally?
        // No — we return Err BEFORE mutating, so the entity is
        // unchanged for the caller's downstream commit_transition.)
        let mut a = rejected_artifact();
        let result = a.tombstone_from_corruption(computed_hash(), Utc::now());
        assert!(matches!(result, Err(DomainError::Invariant(_))));
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
    }

    // -- State machine: release (fail-closed predicate, ADR 0007) -----------

    // --- Source-state guard (widened to Quarantined | ScanIndeterminate) ---

    #[test]
    fn release_from_quarantined_with_scan_succeeded_succeeds() {
        let mut a = quarantined_artifact();
        let event = a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanSucceeded,
                ProvenanceClearance::NotRequired,
            )
            .unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(event.released_by, ReleaseReason::Timer);
        assert_eq!(event.released_by_user_id, None);
        assert_eq!(event.justification, None);
    }

    #[test]
    fn release_from_scan_indeterminate_admin_override_succeeds() {
        // The widened source-state guard: an admin can clear a
        // stuck-scanner artifact directly from ScanIndeterminate.
        let mut a = scan_indeterminate_artifact();
        let event = a
            .release(
                ReleaseReason::Admin,
                ReleaseAuthorization::AdminOverride,
                ProvenanceClearance::NotRequired,
            )
            .unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
        assert_eq!(event.released_by, ReleaseReason::Admin);
    }

    #[test]
    fn release_from_none_fails_source_state_guard() {
        let mut a = sample_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanSucceeded,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::InvalidState(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
    }

    #[test]
    fn release_from_released_fails_source_state_guard() {
        let mut a = released_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Admin,
                ReleaseAuthorization::AdminOverride,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::InvalidState(_))
        ));
    }

    #[test]
    fn release_from_rejected_fails_source_state_guard() {
        // Rejected exits via re_evaluate(), never release().
        let mut a = rejected_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::PolicyReEvaluation,
                ReleaseAuthorization::PolicyReEvaluation,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::InvalidState(_))
        ));
    }

    // --- Deny-by-default authorization predicate (every (reason,authz)) ---

    #[test]
    fn release_timer_scan_succeeded_authorized() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanSucceeded,
                ProvenanceClearance::NotRequired
            )
            .is_ok());
    }

    #[test]
    fn release_timer_scan_waived_authorized() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanWaived,
                ProvenanceClearance::NotRequired
            )
            .is_ok());
    }

    #[test]
    fn release_timer_admin_override_denied() {
        // The fail-closed centerpiece: a timer must NEVER release on
        // anything other than ScanSucceeded / ScanWaived. AdminOverride
        // paired with a Timer reason is denied.
        let mut a = quarantined_artifact();
        let err = a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::AdminOverride,
                ProvenanceClearance::NotRequired,
            )
            .unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        // State unchanged — the timer did NOT release it.
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    #[test]
    fn release_timer_policy_re_evaluation_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Timer,
                ReleaseAuthorization::PolicyReEvaluation,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    #[test]
    fn release_admin_admin_override_authorized() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::Admin,
                ReleaseAuthorization::AdminOverride,
                ProvenanceClearance::NotRequired
            )
            .is_ok());
    }

    #[test]
    fn release_admin_scan_succeeded_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Admin,
                ReleaseAuthorization::ScanSucceeded,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    #[test]
    fn release_admin_scan_waived_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Admin,
                ReleaseAuthorization::ScanWaived,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
    }

    #[test]
    fn release_admin_policy_re_evaluation_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Admin,
                ReleaseAuthorization::PolicyReEvaluation,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
    }

    #[test]
    fn release_policy_re_evaluation_policy_re_evaluation_authorized() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::PolicyReEvaluation,
                ReleaseAuthorization::PolicyReEvaluation,
                ProvenanceClearance::NotRequired
            )
            .is_ok());
    }

    #[test]
    fn release_policy_re_evaluation_scan_succeeded_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::PolicyReEvaluation,
                ReleaseAuthorization::ScanSucceeded,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
    }

    #[test]
    fn release_policy_re_evaluation_scan_waived_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::PolicyReEvaluation,
                ReleaseAuthorization::ScanWaived,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
    }

    #[test]
    fn release_policy_re_evaluation_admin_override_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::PolicyReEvaluation,
                ReleaseAuthorization::AdminOverride,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
    }

    /// The quarantine window is NEVER read in `release()` — expiry is
    /// the sweep's *candidacy* signal, not its *authorization*. Proven
    /// by: an expired-window artifact with no scan authority is NOT
    /// released (it would be under a timer-only guard).
    /// Sets both the stored anchor and the transient computed deadline
    /// to an elapsed window so neither is read.
    #[test]
    fn release_does_not_read_quarantine_window_expired_window_still_denied() {
        let mut a = quarantined_artifact();
        a.quarantine_window_start = Some(Utc::now() - chrono::Duration::hours(72));
        a.quarantine_deadline = Some(Utc::now() - chrono::Duration::hours(48));
        let err = a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::AdminOverride,
                ProvenanceClearance::NotRequired,
            )
            .unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// Symmetric proof: a *future*-window artifact WITH a scan authority
    /// IS released — `release()` decides on the authz token alone, never
    /// on the timestamp.
    #[test]
    fn release_does_not_read_quarantine_window_future_window_still_released() {
        let mut a = quarantined_artifact();
        a.quarantine_window_start = Some(Utc::now());
        a.quarantine_deadline = Some(Utc::now() + chrono::Duration::hours(48));
        assert!(a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanSucceeded,
                ProvenanceClearance::NotRequired
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    // -- ProvenanceClearance gate on the timer arm (ADR 0027) ---------------
    //
    // The timer arm carries a provenance AND-precondition:
    //   (Timer, ScanSucceeded|ScanWaived) && provenance in {NotRequired,Cleared} => release
    //   (Timer, ScanSucceeded|ScanWaived) && Pending => deny (stay quarantined)
    // The Admin / Curator / PolicyReEval arms IGNORE the provenance param
    // (explicit overrides are unaffected — no new ReleaseAuthorization).

    /// `(Timer, ScanSucceeded, Pending)` is denied — a `Required`-mode
    /// artifact with no `ProvenanceVerified` yet stays quarantined
    /// (fail-closed), even though the scan/time gate would otherwise
    /// release it.
    #[test]
    fn release_timer_scan_succeeded_provenance_pending_denied() {
        let mut a = quarantined_artifact();
        let err = a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanSucceeded,
                ProvenanceClearance::Pending,
            )
            .unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// `(Timer, ScanWaived, Pending)` is denied for the same reason — the
    /// provenance AND-precondition holds regardless of which scan
    /// authority drives the timer arm.
    #[test]
    fn release_timer_scan_waived_provenance_pending_denied() {
        let mut a = quarantined_artifact();
        let err = a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanWaived,
                ProvenanceClearance::Pending,
            )
            .unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// `(Timer, ScanSucceeded, Cleared)` releases — `Required` mode with a
    /// `ProvenanceVerified` event present clears the gate.
    #[test]
    fn release_timer_scan_succeeded_provenance_cleared_released() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanSucceeded,
                ProvenanceClearance::Cleared,
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    /// `(Timer, ScanWaived, Cleared)` releases.
    #[test]
    fn release_timer_scan_waived_provenance_cleared_released() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanWaived,
                ProvenanceClearance::Cleared,
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    /// `(Timer, ScanSucceeded, NotRequired)` releases — the
    /// `Off`/`VerifyIfPresent` mode never gates the timer arm.
    #[test]
    fn release_timer_scan_succeeded_provenance_not_required_released() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanSucceeded,
                ProvenanceClearance::NotRequired,
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    /// `(Timer, ScanWaived, NotRequired)` releases.
    #[test]
    fn release_timer_scan_waived_provenance_not_required_released() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanWaived,
                ProvenanceClearance::NotRequired,
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    /// Admin override releases regardless of the provenance param — pass
    /// `Pending` and confirm it still releases (the override arm ignores
    /// provenance; explicit Admin/Curator/PolicyReEval releases are never
    /// blocked by the provenance gate).
    #[test]
    fn release_admin_override_ignores_provenance_pending() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::Admin,
                ReleaseAuthorization::AdminOverride,
                ProvenanceClearance::Pending,
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    /// Curator waiver releases regardless of the provenance param.
    #[test]
    fn release_curator_waiver_ignores_provenance_pending() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::Curator,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::Pending,
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    /// Policy re-evaluation releases regardless of the provenance param.
    #[test]
    fn release_policy_re_evaluation_ignores_provenance_pending() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::PolicyReEvaluation,
                ReleaseAuthorization::PolicyReEvaluation,
                ProvenanceClearance::Pending,
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    /// Fail-closed property re-asserted across the provenance dimension:
    /// a never-scanned artifact (no `ScanSucceeded`/`ScanWaived` authority
    /// constructible) does NOT timer-release under ANY `ProvenanceClearance`
    /// — provenance never *adds* release authority, only ever an
    /// AND-precondition that can subtract it.
    #[test]
    fn f6_fail_closed_unscanned_never_timer_releases_under_any_clearance() {
        for clearance in [
            ProvenanceClearance::NotRequired,
            ProvenanceClearance::Cleared,
            ProvenanceClearance::Pending,
        ] {
            for authz in [
                ReleaseAuthorization::AdminOverride,
                ReleaseAuthorization::PolicyReEvaluation,
            ] {
                let mut a = quarantined_artifact();
                assert!(
                    matches!(
                        a.release(ReleaseReason::Timer, authz, clearance),
                        Err(DomainError::Invariant(_))
                    ),
                    "timer release with non-scan authority {authz:?} and clearance \
                     {clearance:?} must be denied (fail-closed predicate)"
                );
                assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
            }
        }
    }

    // -- ScanRecorded (enforcement: record) --------------------------------
    //
    // The sixth authority behaves exactly like the other two scan-axis
    // timer authorities: it releases on the timer arm, carries the same
    // provenance AND-precondition, and pairs with NO other reason.

    /// `(Timer, ScanRecorded, NotRequired)` releases — the operator
    /// declared the scan verdict recorded rather than gating, so the
    /// artifact's own dirty `ScanCompleted` no longer holds it.
    #[test]
    fn release_timer_scan_recorded_provenance_not_required_released() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanRecorded,
                ProvenanceClearance::NotRequired,
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    /// `(Timer, ScanRecorded, Cleared)` releases.
    #[test]
    fn release_timer_scan_recorded_provenance_cleared_released() {
        let mut a = quarantined_artifact();
        assert!(a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanRecorded,
                ProvenanceClearance::Cleared,
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    /// `(Timer, ScanRecorded, Pending)` is DENIED — `enforcement: record`
    /// un-gates the scan axis only. A `Required`-mode artifact with no
    /// `ProvenanceVerified` yet stays quarantined, exactly as it does
    /// under `ScanSucceeded` / `ScanWaived`. This is the load-bearing
    /// cross-axis pin: the new authority must not become a way to release
    /// past the provenance gate.
    #[test]
    fn release_timer_scan_recorded_provenance_pending_denied() {
        let mut a = quarantined_artifact();
        let err = a
            .release(
                ReleaseReason::Timer,
                ReleaseAuthorization::ScanRecorded,
                ProvenanceClearance::Pending,
            )
            .unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// `ScanRecorded` pairs ONLY with `Timer` — deny-by-default is
    /// preserved for every other reason (an Admin/Curator/PolicyReEval
    /// release carries its own authority token).
    #[test]
    fn release_scan_recorded_denied_for_every_non_timer_reason() {
        for reason in [
            ReleaseReason::Admin,
            ReleaseReason::Curator,
            ReleaseReason::PolicyReEvaluation,
        ] {
            let mut a = quarantined_artifact();
            assert!(
                matches!(
                    a.release(
                        reason.clone(),
                        ReleaseAuthorization::ScanRecorded,
                        ProvenanceClearance::NotRequired,
                    ),
                    Err(DomainError::Invariant(_))
                ),
                "({reason:?}, ScanRecorded) must be denied (deny-by-default)"
            );
            assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
        }
    }

    /// `Cleared`/`NotRequired` cannot rescue a non-scan timer authority —
    /// provenance clearing the gate does NOT substitute for the scan gate.
    #[test]
    fn provenance_cleared_does_not_substitute_for_scan_authority() {
        for clearance in [
            ProvenanceClearance::Cleared,
            ProvenanceClearance::NotRequired,
        ] {
            let mut a = quarantined_artifact();
            assert!(matches!(
                a.release(
                    ReleaseReason::Timer,
                    ReleaseAuthorization::AdminOverride,
                    clearance,
                ),
                Err(DomainError::Invariant(_))
            ));
            assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
        }
    }

    // -- complete_provenance verdict -> state (ADR 0027) --------------------

    #[test]
    fn complete_provenance_verified_emits_event_and_leaves_status_unchanged() {
        // A Verified verdict must NOT release early (like
        // ScanCompleted(clean)) — status stays Quarantined and a
        // ProvenanceVerified event is emitted for the audit trail / the
        // release-sweep `Cleared` computation.
        for (mode, is_descendant) in [
            (ProvenanceMode::VerifyIfPresent, false),
            (ProvenanceMode::VerifyIfPresent, true),
            (ProvenanceMode::Required, false),
            (ProvenanceMode::Required, true),
        ] {
            let mut a = quarantined_artifact();
            let signer = SignerIdentity {
                issuer: "https://token.actions.githubusercontent.com".into(),
                san: "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
                    .into(),
            };
            let verdict = ProvenanceVerdict::verified(
                signer.clone(),
                Some("https://slsa.dev/provenance/v1".into()),
            );
            let ev = a
                // A deliberately non-"cosign" backend proves the id is
                // threaded from the running verifier, not hardcoded
                // (Tier-2 readiness). `window_open = true` proves a Verified
                // verdict is decided immediately even mid-window (it never
                // consults the window flag); `is_referenced_descendant`
                // varies across the loop below for the same reason (#115 —
                // the flag is inert on this arm).
                .complete_provenance(verdict, mode, "pgp", true, is_descendant)
                .expect("Ok")
                .expect("Verified emits an event");
            assert_eq!(
                a.quarantine_status,
                QuarantineStatus::Quarantined,
                "Verified must NOT release early (status unchanged)"
            );
            match ev {
                DomainEvent::ProvenanceVerified(e) => {
                    assert_eq!(e.artifact_id, a.id);
                    assert_eq!(e.content_hash, a.sha256_checksum);
                    assert_eq!(
                        e.backend, "pgp",
                        "backend is threaded from the verifier, not hardcoded"
                    );
                    assert_eq!(e.signer, signer);
                    assert_eq!(
                        e.predicate_type.as_deref(),
                        Some("https://slsa.dev/provenance/v1")
                    );
                }
                other => panic!("expected ProvenanceVerified, got {other:?}"),
            }
        }
    }

    #[test]
    fn complete_provenance_rejected_drives_status_to_rejected() {
        // Every reject reason drives Quarantined -> Rejected and emits a
        // ProvenanceRejected carrying the typed reason. Independent of mode.
        // `window_open = true` proves a bad signature is time-independent:
        // the Rejected arm decides terminally IMMEDIATELY, even mid-window
        // (it never consults `window_open`, unlike the NoAttestation×Required
        // hold).
        let reasons = [
            ProvenanceRejectReason::Unsigned,
            ProvenanceRejectReason::UntrustedIdentity,
            ProvenanceRejectReason::RekorNotFound,
            ProvenanceRejectReason::CertChainInvalid,
            ProvenanceRejectReason::BundleMalformed,
        ];
        for reason in reasons {
            for (mode, is_descendant) in [
                (ProvenanceMode::VerifyIfPresent, false),
                (ProvenanceMode::VerifyIfPresent, true),
                (ProvenanceMode::Required, false),
                (ProvenanceMode::Required, true),
            ] {
                let mut a = quarantined_artifact();
                let ev = a
                    .complete_provenance(
                        ProvenanceVerdict::rejected(reason),
                        mode,
                        "cosign",
                        true,
                        is_descendant,
                    )
                    .expect("Ok")
                    .expect("Rejected emits an event");
                assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
                // ADR 0041: a provenance rejection is not scan-clearable.
                assert_eq!(a.rejection_reason, None);
                match ev {
                    DomainEvent::ProvenanceRejected(e) => {
                        assert_eq!(e.artifact_id, a.id);
                        assert_eq!(e.content_hash, a.sha256_checksum);
                        assert_eq!(e.backend, "cosign");
                        assert_eq!(e.reason, reason);
                    }
                    other => panic!("expected ProvenanceRejected, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn complete_provenance_no_attestation_under_verify_if_present_is_noop() {
        // Unsigned-but-allowed: no event, status unchanged.
        let mut a = quarantined_artifact();
        let out = a
            .complete_provenance(
                ProvenanceVerdict::no_attestation(),
                ProvenanceMode::VerifyIfPresent,
                "cosign",
                // Neither flag is relevant to VerifyIfPresent (both gate only
                // NoAttestation×Required); pass false for both to prove they
                // never leak into this arm.
                false,
                false,
            )
            .expect("Ok");
        assert!(
            out.is_none(),
            "VerifyIfPresent NoAttestation must be a no-op"
        );
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    #[test]
    fn complete_provenance_no_attestation_under_off_is_noop() {
        // Off mode is inert — the method is total over the mode and treats
        // NoAttestation as a no-op (the orchestrator never runs a verifier
        // in Off, but the entity stays safe regardless).
        let mut a = quarantined_artifact();
        let out = a
            .complete_provenance(
                ProvenanceVerdict::no_attestation(),
                ProvenanceMode::Off,
                "cosign",
                // Neither flag is relevant to Off (inert mode); pass false for
                // both to prove they never leak into this arm.
                false,
                false,
            )
            .expect("Ok");
        assert!(out.is_none());
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    #[test]
    fn complete_provenance_no_attestation_under_required_window_open_holds() {
        // Issue #13 — the push-then-sign round-trip. A missing signature is
        // time-dependent: while the observation window is still open, an
        // unsigned Required artifact is HELD (no event, status stays
        // Quarantined → the release gate reads it as `Pending`), NOT rejected.
        let mut a = quarantined_artifact();
        let out = a
            .complete_provenance(
                ProvenanceVerdict::no_attestation(),
                ProvenanceMode::Required,
                "cosign",
                true,  // window still open → hold
                false, // not a descendant — the window alone holds it
            )
            .expect("Ok");
        assert!(
            out.is_none(),
            "Required NoAttestation mid-window must hold (no event)"
        );
        assert_eq!(
            a.quarantine_status,
            QuarantineStatus::Quarantined,
            "held artifact stays Quarantined (Pending), not Rejected"
        );
        // The hold must not touch rejection_reason (it is not a rejection).
        assert_eq!(a.rejection_reason, None);
    }

    #[test]
    fn complete_provenance_no_attestation_under_required_window_closed_rejects_unsigned() {
        // Window closed (issue #13): unsigned-at-expiry IS a terminal
        // rejection under Required — emit ProvenanceRejected{Unsigned},
        // status -> Rejected. Byte-for-byte the pre-#13 mapping, incl. the
        // "(policy)" synthetic backend.
        let mut a = quarantined_artifact();
        let ev = a
            .complete_provenance(
                ProvenanceVerdict::no_attestation(),
                ProvenanceMode::Required,
                // Passed backend is intentionally ignored on the synthesized
                // unsigned arm — the event records the "(policy)" sentinel.
                "cosign",
                false, // window closed
                false, // and NOT a descendant → terminal rejection
            )
            .expect("Ok")
            .expect("Required NoAttestation at expiry emits a rejection");
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        // ADR 0041: a provenance rejection is not scan-clearable.
        assert_eq!(a.rejection_reason, None);
        match ev {
            DomainEvent::ProvenanceRejected(e) => {
                assert_eq!(e.artifact_id, a.id);
                assert_eq!(e.content_hash, a.sha256_checksum);
                assert_eq!(e.reason, ProvenanceRejectReason::Unsigned);
                // The synthetic backend label for the policy-derived
                // unsigned mapping (no backend verdict produced it).
                assert_eq!(e.backend, "(policy)");
            }
            other => panic!("expected ProvenanceRejected, got {other:?}"),
        }
    }

    // -- is_referenced_descendant carve-out (issue #115 defect (b)) ----------

    /// **The defect this carve-out closes.** A referenced-tree descendant
    /// (an index's child manifest, a manifest's config/layer blob) has a
    /// ZERO-length observation window by construction (#46), so
    /// `window_open` is `false` from the instant it is ingested. cosign
    /// signs only the top-level digest, so the descendant has no
    /// attestation of its own and never will — its provenance authority is
    /// its parent's signature, arriving later via
    /// `cascade_provenance_clearance`. Before this carve-out the pair
    /// (`NoAttestation × Required × window_open == false`) resolved to a
    /// terminal `Rejected{Unsigned}` BEFORE the cascade could clear it,
    /// and the cascade refuses a rejected constituent — permanently
    /// bricking a correctly-signed image. It must HOLD instead.
    #[test]
    fn complete_provenance_descendant_no_attestation_required_window_closed_holds() {
        let mut a = quarantined_artifact();
        let out = a
            .complete_provenance(
                ProvenanceVerdict::no_attestation(),
                ProvenanceMode::Required,
                "cosign",
                false, // window CLOSED (zero-window descendant, by construction)
                true,  // …but it IS a referenced-tree descendant → HOLD
            )
            .expect("Ok");
        assert!(
            out.is_none(),
            "a zero-window descendant must HOLD, not emit a terminal rejection"
        );
        assert_eq!(
            a.quarantine_status,
            QuarantineStatus::Quarantined,
            "held descendant stays Quarantined (Pending) so the parent's \
             cascade can still clear it — terminal is terminal, and a \
             rejected constituent is unrecoverable"
        );
        // The hold must not touch rejection_reason (it is not a rejection).
        assert_eq!(a.rejection_reason, None);
    }

    /// Truth table for the two hold flags on the `NoAttestation × Required`
    /// arm: it holds iff `window_open || is_referenced_descendant`. Pins
    /// the OR explicitly so a future refactor cannot silently narrow it to
    /// an AND (which would re-open the defect) or widen it to
    /// unconditional (which would remove the unsigned-at-expiry rejection).
    #[test]
    fn complete_provenance_required_no_attestation_holds_iff_window_open_or_descendant() {
        for (window_open, is_descendant) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            let mut a = quarantined_artifact();
            let out = a
                .complete_provenance(
                    ProvenanceVerdict::no_attestation(),
                    ProvenanceMode::Required,
                    "cosign",
                    window_open,
                    is_descendant,
                )
                .expect("Ok");
            let should_hold = window_open || is_descendant;
            assert_eq!(
                out.is_none(),
                should_hold,
                "window_open={window_open}, is_descendant={is_descendant}: \
                 expected hold={should_hold}"
            );
            assert_eq!(
                a.quarantine_status,
                if should_hold {
                    QuarantineStatus::Quarantined
                } else {
                    QuarantineStatus::Rejected
                },
                "window_open={window_open}, is_descendant={is_descendant}",
            );
        }
    }

    /// The flag is scoped to the unsigned arm ONLY: a forged / untrusted /
    /// digest-mismatch signature on a descendant is *position-independent*
    /// (it is already wrong, exactly like it is *time*-independent w.r.t.
    /// `window_open`) and must still reject terminally. Without this, the
    /// carve-out would become a blanket "descendants are never rejected",
    /// which would let a tampered layer through.
    #[test]
    fn complete_provenance_descendant_still_rejects_a_bad_signature() {
        for reason in [
            ProvenanceRejectReason::Unsigned,
            ProvenanceRejectReason::UntrustedIdentity,
            ProvenanceRejectReason::RekorNotFound,
            ProvenanceRejectReason::CertChainInvalid,
            ProvenanceRejectReason::BundleMalformed,
        ] {
            let mut a = quarantined_artifact();
            let ev = a
                .complete_provenance(
                    ProvenanceVerdict::rejected(reason),
                    ProvenanceMode::Required,
                    "cosign",
                    false, // window closed
                    true,  // descendant — must NOT rescue a bad signature
                )
                .expect("Ok")
                .expect("a Rejected verdict always emits, descendant or not");
            assert_eq!(
                a.quarantine_status,
                QuarantineStatus::Rejected,
                "reason {reason:?}: a bad signature on a descendant is still terminal"
            );
            match ev {
                DomainEvent::ProvenanceRejected(e) => assert_eq!(e.reason, reason),
                other => panic!("expected ProvenanceRejected, got {other:?}"),
            }
        }
    }

    /// The flag is inert outside `Required`: `VerifyIfPresent` / `Off`
    /// treat `NoAttestation` as an allowed no-op whether or not the
    /// artifact is a descendant (they have no hold semantics to gate).
    #[test]
    fn complete_provenance_descendant_flag_is_inert_outside_required() {
        for mode in [ProvenanceMode::VerifyIfPresent, ProvenanceMode::Off] {
            for is_descendant in [true, false] {
                let mut a = quarantined_artifact();
                let out = a
                    .complete_provenance(
                        ProvenanceVerdict::no_attestation(),
                        mode,
                        "cosign",
                        false,
                        is_descendant,
                    )
                    .expect("Ok");
                assert!(
                    out.is_none(),
                    "{mode:?} / descendant={is_descendant} must stay an allowed no-op"
                );
                assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
            }
        }
    }

    // -- cascade_provenance_clearance (ADR 0039 cascade) ---------------------

    #[test]
    fn cascade_provenance_clearance_from_quarantined_emits_attributed_event() {
        // A held constituent takes the cascaded clearance: the returned
        // ProvenanceVerified carries THIS artifact's identity/hash, the
        // subject's verified signer, and the subject hash in
        // `cascaded_from` (the "cleared via signature over <root>" audit
        // attribution). `&self` — status untouched (success record only;
        // the scan/window gates stay per-artifact).
        let a = quarantined_artifact();
        let subject: ContentHash =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap();
        let signer = SignerIdentity {
            issuer: "operator-pinned-key".into(),
            san: "cosign-key".into(),
        };
        let ev = a
            .cascade_provenance_clearance(
                subject.clone(),
                signer.clone(),
                Some("https://sigstore.dev/cosign/sign/v1".into()),
                "cosign-key",
            )
            .expect("Quarantined constituent takes the cascade");
        assert_eq!(ev.artifact_id, a.id);
        assert_eq!(ev.content_hash, a.sha256_checksum);
        assert_eq!(ev.backend, "cosign-key");
        assert_eq!(ev.signer, signer);
        assert_eq!(
            ev.predicate_type.as_deref(),
            Some("https://sigstore.dev/cosign/sign/v1")
        );
        assert_eq!(
            ev.cascaded_from,
            Some(subject),
            "the cascaded event must attribute the clearance to the verified subject digest"
        );
        assert_eq!(
            a.quarantine_status,
            QuarantineStatus::Quarantined,
            "a cascaded clearance is a success record only — status unchanged"
        );
    }

    #[test]
    fn cascade_provenance_clearance_refuses_every_non_quarantined_state() {
        // Fail-closed edges: terminal states stay terminal (Rejected /
        // ScanIndeterminate are never resurrected by a cascade) and
        // Released / None are outside the hold — all four refuse.
        let subject: ContentHash =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap();
        let signer = SignerIdentity {
            issuer: "iss".into(),
            san: "san".into(),
        };
        for status in [
            QuarantineStatus::None,
            QuarantineStatus::Released,
            QuarantineStatus::Rejected,
            QuarantineStatus::ScanIndeterminate,
        ] {
            let mut a = sample_artifact();
            a.quarantine_status = status;
            let err = a
                .cascade_provenance_clearance(subject.clone(), signer.clone(), None, "cosign-key")
                .expect_err("only a held (Quarantined) constituent takes a cascaded clearance");
            assert!(
                matches!(err, DomainError::Invariant(_)),
                "expected Invariant for {status}, got {err:?}"
            );
            assert_eq!(
                a.quarantine_status, status,
                "the refusal must not mutate state"
            );
        }
    }

    #[test]
    fn complete_provenance_verified_from_none_permissive_mode_status_unchanged() {
        // Permissive (quarantineDuration:0) ingest sits at None; a Verified
        // verdict is a success record that does not move state.
        let mut a = sample_artifact();
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
        let signer = SignerIdentity {
            issuer: "iss".into(),
            san: "san".into(),
        };
        let ev = a
            .complete_provenance(
                ProvenanceVerdict::verified(signer, None),
                ProvenanceMode::Required,
                "cosign",
                // Verified never consults either flag; false for both proves
                // the arm decides regardless.
                false,
                false,
            )
            .expect("Ok")
            .expect("emits event");
        assert!(matches!(ev, DomainEvent::ProvenanceVerified(_)));
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
    }

    // -- Curator + CuratorWaiver release pair -------------------------------

    /// The curator-waive pair is the single allow row
    /// for the curator variants. Mirrors the `(Admin, AdminOverride)` shape:
    /// a curator-issued release transitions a `Quarantined` artifact to
    /// `Released` via the explicit typed authorization token.
    #[test]
    fn release_curator_curator_waiver_authorized() {
        let mut a = quarantined_artifact();
        let event = a
            .release(
                ReleaseReason::Curator,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired,
            )
            .unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(event.released_by, ReleaseReason::Curator);
        // Attribution is populated by the application layer (the same
        // pattern as admin_release). The entity
        // emits the event with attribution fields `None`; the use case
        // is responsible for the released_by_user_id +
        // justification before the event is appended.
        assert_eq!(event.released_by_user_id, None);
        assert_eq!(event.justification, None);
    }

    // --- Deny-by-default: every cross pair involving the new variants ---

    /// `(Timer, CuratorWaiver)` is denied: a timer must never
    /// release on a curator authority (the timer authority is scan-bound).
    #[test]
    fn release_timer_curator_waiver_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Timer,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// `(Admin, CuratorWaiver)` is denied: admin pairs ONLY
    /// with `AdminOverride`. A curator waiver under the admin reason tag
    /// is a mis-construction the deny-by-default predicate rejects.
    #[test]
    fn release_admin_curator_waiver_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Admin,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// `(PolicyReEvaluation, CuratorWaiver)` is denied.
    #[test]
    fn release_policy_re_evaluation_curator_waiver_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::PolicyReEvaluation,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired,
            ),
            Err(DomainError::Invariant(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// `(Curator, ScanSucceeded)` is denied: a curator
    /// authority pairs ONLY with `CuratorWaiver`.
    #[test]
    fn release_curator_scan_succeeded_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Curator,
                ReleaseAuthorization::ScanSucceeded,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// `(Curator, ScanWaived)` is denied.
    #[test]
    fn release_curator_scan_waived_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Curator,
                ReleaseAuthorization::ScanWaived,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// `(Curator, AdminOverride)` is denied: admin override is
    /// the admin authority's token; a curator-reason event must carry
    /// `CuratorWaiver`, never `AdminOverride`.
    #[test]
    fn release_curator_admin_override_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Curator,
                ReleaseAuthorization::AdminOverride,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// `(Curator, PolicyReEvaluation)` is denied.
    #[test]
    fn release_curator_policy_re_evaluation_denied() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Curator,
                ReleaseAuthorization::PolicyReEvaluation,
                ProvenanceClearance::NotRequired,
            ),
            Err(DomainError::Invariant(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    // --- Source-state guard for the curator pair ---

    /// The curator surface is **narrower** than admin:
    /// `CuratorWaiver` accepts source state `Quarantined` only.
    /// `ScanIndeterminate` stays admin-only (clearing a stuck scanner
    /// requires the broader admin authority).
    #[test]
    fn release_curator_curator_waiver_from_scan_indeterminate_denied() {
        let mut a = scan_indeterminate_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Curator,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::InvalidState(_))
        ));
        // State unchanged — the curator did NOT clear the stuck scanner.
        assert_eq!(a.quarantine_status, QuarantineStatus::ScanIndeterminate);
    }

    /// Curator cannot un-reject. `Rejected` is terminal:
    /// neither curator-waive NOR `admin_release` exits it (both go through
    /// this source-state guard). Only the finding-exclusion re-evaluation
    /// path (`re_evaluate`) exits `Rejected`. See ADR 0025 / 0007.
    #[test]
    fn release_curator_curator_waiver_from_rejected_denied() {
        let mut a = rejected_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Curator,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::InvalidState(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
    }

    /// `None` is not a curator-waive source state (nothing
    /// to release).
    #[test]
    fn release_curator_curator_waiver_from_none_denied() {
        let mut a = sample_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Curator,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::InvalidState(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
    }

    /// `Released` is not a curator-waive source state
    /// (already released).
    #[test]
    fn release_curator_curator_waiver_from_released_denied() {
        let mut a = released_artifact();
        assert!(matches!(
            a.release(
                ReleaseReason::Curator,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::InvalidState(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    // --- ADR 0007 invariant: predicate never reads quarantine_window_start ---

    /// ADR 0007 invariant: the release
    /// predicate must NOT read `quarantine_window_start`. Proof: two
    /// artifacts identical except for the stored anchor + computed
    /// deadline produce the same predicate verdict for the same
    /// `(reason, authz)` input. Pairs an *elapsed* window against the
    /// new curator allow pair — if the predicate were reading the
    /// timestamp, the verdict could differ between artifacts; it must
    /// not.
    #[test]
    fn release_curator_predicate_does_not_read_quarantine_window() {
        // Artifact A — window in the far past (would read "elapsed").
        let mut a = quarantined_artifact();
        a.quarantine_window_start = Some(Utc::now() - chrono::Duration::hours(72));
        a.quarantine_deadline = Some(Utc::now() - chrono::Duration::hours(48));

        // Artifact B — window in the far future (would read "not yet").
        let mut b = quarantined_artifact();
        b.quarantine_window_start = Some(Utc::now());
        b.quarantine_deadline = Some(Utc::now() + chrono::Duration::hours(48));

        // Same `(reason, authz)` input → same verdict (Ok) on both,
        // independent of the window.
        assert!(a
            .release(
                ReleaseReason::Curator,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired
            )
            .is_ok());
        assert!(b
            .release(
                ReleaseReason::Curator,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired
            )
            .is_ok());

        // And: a deny pair stays denied on both, independent of the
        // window — the predicate decides on the authz token alone.
        let mut c = quarantined_artifact();
        c.quarantine_window_start = Some(Utc::now() - chrono::Duration::hours(72));
        c.quarantine_deadline = Some(Utc::now() - chrono::Duration::hours(48));
        let mut d = quarantined_artifact();
        d.quarantine_window_start = Some(Utc::now());
        d.quarantine_deadline = Some(Utc::now() + chrono::Duration::hours(48));
        assert!(matches!(
            c.release(
                ReleaseReason::Timer,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
        assert!(matches!(
            d.release(
                ReleaseReason::Timer,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired
            ),
            Err(DomainError::Invariant(_))
        ));
    }

    /// ADR 0007 invariant: the window-not-read
    /// guarantee also holds when `quarantine_window_start = None`. A
    /// `Quarantined` artifact with `None` anchor (defensive — should
    /// not happen in practice, but the predicate must not crash or read
    /// the field) still produces the correct verdict on `(Curator,
    /// CuratorWaiver)`.
    #[test]
    fn release_curator_predicate_none_anchor_still_authorized() {
        let mut a = quarantined_artifact();
        a.quarantine_window_start = None;
        a.quarantine_deadline = None;
        assert!(a
            .release(
                ReleaseReason::Curator,
                ReleaseAuthorization::CuratorWaiver,
                ProvenanceClearance::NotRequired
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    // -- State machine: fail_scan_indeterminate (ADR 0007) ------------------

    #[test]
    fn fail_scan_indeterminate_from_quarantined_succeeds() {
        // Strict mode: the hold becomes indeterminate.
        let mut a = quarantined_artifact();
        let event = a
            .fail_scan_indeterminate("trivy,osv".into(), "all backends down".into(), 5)
            .unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::ScanIndeterminate);
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(event.scanner, "trivy,osv");
        assert_eq!(event.reason, "all backends down");
        assert_eq!(event.attempts, 5);
    }

    #[test]
    fn fail_scan_indeterminate_from_none_succeeds_in_permissive_mode() {
        // Permissive mode (quarantineDuration:0): the artifact ingested
        // downloadable; an undecided scan retroactively blocks it.
        // Mirrors reject_from_scan's None source state.
        let mut a = sample_artifact();
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
        assert!(a.is_downloadable());
        let event = a
            .fail_scan_indeterminate("trivy".into(), "scanner crashed".into(), 5)
            .expect("fail_scan_indeterminate must accept None in permissive mode");
        assert_eq!(a.quarantine_status, QuarantineStatus::ScanIndeterminate);
        // The fail-open-today half is closed: no longer downloadable.
        assert!(!a.is_downloadable());
        assert_eq!(event.artifact_id, a.id);
    }

    #[test]
    fn fail_scan_indeterminate_from_released_fails() {
        // A released artifact passed review; a later infra failure does
        // not retroactively un-review it (the rescan-amplification concern).
        let mut a = released_artifact();
        let result = a.fail_scan_indeterminate("trivy".into(), "down".into(), 5);
        assert!(matches!(result, Err(DomainError::Invariant(_))));
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    #[test]
    fn fail_scan_indeterminate_from_rejected_fails() {
        // Rejected is strictly stronger than ScanIndeterminate — never
        // downgrade "proven bad" to "unknown".
        let mut a = rejected_artifact();
        let result = a.fail_scan_indeterminate("trivy".into(), "down".into(), 5);
        assert!(matches!(result, Err(DomainError::Invariant(_))));
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
    }

    #[test]
    fn fail_scan_indeterminate_from_scan_indeterminate_is_idempotent_skip() {
        // Already terminal: return Err(Invariant) so the orchestrator
        // skips a duplicate event append (mirrors
        // tombstone_from_corruption's already-rejected branch).
        let mut a = scan_indeterminate_artifact();
        let result = a.fail_scan_indeterminate("trivy".into(), "down".into(), 5);
        assert!(matches!(result, Err(DomainError::Invariant(_))));
        assert_eq!(a.quarantine_status, QuarantineStatus::ScanIndeterminate);
    }

    // -- Quarantine-Invariant interaction arms ------------------------------

    /// Inv #1 — downloads blocked: ScanIndeterminate is outside the
    /// `is_downloadable` whitelist, so the gate blocks it by construction.
    #[test]
    fn invariant_1_scan_indeterminate_is_not_downloadable() {
        assert!(!scan_indeterminate_artifact().is_downloadable());
    }

    /// Inv #2 — a missing scan does NOT release on a timer alone.
    #[test]
    fn invariant_2_timer_alone_never_releases_unscanned_artifact() {
        let mut a = quarantined_artifact();
        // No ScanSucceeded / ScanWaived authority is constructible.
        for authz in [
            ReleaseAuthorization::AdminOverride,
            ReleaseAuthorization::PolicyReEvaluation,
        ] {
            assert!(matches!(
                a.release(
                    ReleaseReason::Timer,
                    authz,
                    ProvenanceClearance::NotRequired
                ),
                Err(DomainError::Invariant(_))
            ));
        }
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    /// Inv #3 — admin override is a valid `ScanIndeterminate` exit
    /// (the findings path `reject_from_scan` is disjoint and unchanged).
    #[test]
    fn invariant_3_scan_indeterminate_releases_via_admin_override() {
        let mut a = scan_indeterminate_artifact();
        assert!(a
            .release(
                ReleaseReason::Admin,
                ReleaseAuthorization::AdminOverride,
                ProvenanceClearance::NotRequired
            )
            .is_ok());
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
    }

    /// Inv #2/#3 fail-closed: the realistic sweep scenario for a
    /// never-successfully-scanned `ScanIndeterminate` artifact — the app
    /// layer cannot mint `ScanSucceeded`/`ScanWaived` (no successful
    /// `ScanCompleted`, scanning not waived), so a timer release with
    /// any non-scan authority is denied. The entity stays pure: it
    /// trusts the typed token; the app layer guarantees no `ScanSucceeded`
    /// token is ever constructed for an unscanned artifact.
    #[test]
    fn invariant_3_scan_indeterminate_timer_without_scan_authority_denied() {
        for authz in [
            ReleaseAuthorization::AdminOverride,
            ReleaseAuthorization::PolicyReEvaluation,
        ] {
            let mut b = scan_indeterminate_artifact();
            assert!(matches!(
                b.release(
                    ReleaseReason::Timer,
                    authz,
                    ProvenanceClearance::NotRequired
                ),
                Err(DomainError::Invariant(_))
            ));
            assert_eq!(b.quarantine_status, QuarantineStatus::ScanIndeterminate);
        }
    }

    /// Inv #3 — re_evaluate() is NOT widened to ScanIndeterminate (spec
    /// re_evaluate is not widened to ScanIndeterminate: a finding-exclusion
    /// is a no-op for an artifact with no finding. re_evaluate from
    /// ScanIndeterminate is an Invariant error.
    #[test]
    fn invariant_3_re_evaluate_not_widened_to_scan_indeterminate() {
        let mut a = scan_indeterminate_artifact();
        assert!(matches!(
            a.re_evaluate(
                Utc::now(),
                ProvenanceClearance::NotRequired,
                CurationClearance::Cleared
            ),
            Err(DomainError::Invariant(_))
        ));
        assert_eq!(a.quarantine_status, QuarantineStatus::ScanIndeterminate);
    }

    /// Inv #4 — promotion blocked: ScanIndeterminate is outside the
    /// `is_promotable` whitelist.
    #[test]
    fn invariant_4_scan_indeterminate_is_not_promotable() {
        assert!(!scan_indeterminate_artifact().is_promotable());
    }

    // -- State machine: re_evaluate -----------------------------------------
    //
    // ADR 0041 invariant #6 — the `Rejected → Released` arm fires only on
    // the cross-axis conjunction `scan ∧ curation ∧ provenance`. The
    // happy-path tests pass `(NotRequired, Cleared)` (both conjuncts
    // satisfied); dedicated tests below exercise each non-satisfied
    // conjunct and the reason-eligibility guard.

    /// Convenience: the "both cross-axis conjuncts clear" inputs — the
    /// default that mirrors the pre-ADR-0041 `re_evaluate(now)` happy
    /// path.
    fn clears() -> (ProvenanceClearance, CurationClearance) {
        (ProvenanceClearance::NotRequired, CurationClearance::Cleared)
    }

    #[test]
    fn re_evaluate_rejected_future_quarantine_goes_quarantined() {
        let mut a = rejected_artifact();
        // `re_evaluate` reads the transient computed deadline, not the
        // stored anchor.
        a.quarantine_deadline = Some(Utc::now() + chrono::Duration::hours(12));
        let now = Utc::now();
        let (prov, cur) = clears();
        let event = a.re_evaluate(now, prov, cur).unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
        assert!(matches!(event, DomainEvent::ArtifactQuarantined(_)));
        // The re-quarantine clears the scan reason — the artifact is now
        // held under the window, no longer a scan rejection.
        assert_eq!(a.rejection_reason, None);
    }

    #[test]
    fn re_evaluate_rejected_past_quarantine_goes_released() {
        let mut a = rejected_artifact();
        a.quarantine_deadline = Some(Utc::now() - chrono::Duration::hours(1));
        let now = Utc::now();
        let (prov, cur) = clears();
        let event = a.re_evaluate(now, prov, cur).unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
        assert_eq!(a.rejection_reason, None);
        match event {
            DomainEvent::ArtifactReleased(e) => {
                assert_eq!(e.released_by, ReleaseReason::PolicyReEvaluation);
            }
            _ => panic!("expected ArtifactReleased"),
        }
    }

    #[test]
    fn re_evaluate_rejected_quarantine_at_now_goes_released() {
        let mut a = rejected_artifact();
        let now = Utc::now();
        a.quarantine_deadline = Some(now);
        let (prov, cur) = clears();
        let event = a.re_evaluate(now, prov, cur).unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
        assert!(matches!(event, DomainEvent::ArtifactReleased(_)));
    }

    #[test]
    fn re_evaluate_rejected_no_quarantine_deadline_goes_released() {
        let mut a = rejected_artifact();
        a.quarantine_deadline = None;
        let (prov, cur) = clears();
        let event = a.re_evaluate(Utc::now(), prov, cur).unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
        assert!(matches!(event, DomainEvent::ArtifactReleased(_)));
    }

    /// Correctness landmine: `re_evaluate` must read the
    /// computed `quarantine_deadline`, NEVER the stored anchor
    /// `quarantine_window_start`. The anchor is always in the past, so
    /// branching on it would always read "elapsed" and release a
    /// re-evaluated `Rejected` artifact ~`duration` early. Here the
    /// anchor is far in the past but the computed deadline is still in
    /// the future — the artifact must return to `Quarantined`, not
    /// `Released`.
    #[test]
    fn re_evaluate_reads_computed_deadline_not_stored_anchor() {
        let mut a = rejected_artifact();
        // Anchor is in the past (an artifact ingested hours ago)...
        a.quarantine_window_start = Some(Utc::now() - chrono::Duration::hours(6));
        // ...but the computed deadline is still in the future.
        a.quarantine_deadline = Some(Utc::now() + chrono::Duration::hours(18));
        let (prov, cur) = clears();
        let event = a.re_evaluate(Utc::now(), prov, cur).unwrap();
        assert_eq!(
            a.quarantine_status,
            QuarantineStatus::Quarantined,
            "must re-quarantine: the computed deadline is still in the future"
        );
        match event {
            DomainEvent::ArtifactQuarantined(e) => {
                // The re-quarantine preserves the original anchor.
                assert_eq!(Some(e.quarantine_window_start), a.quarantine_window_start);
            }
            _ => panic!("expected ArtifactQuarantined"),
        }
    }

    #[test]
    fn re_evaluate_from_none_fails() {
        let mut a = sample_artifact();
        let (prov, cur) = clears();
        assert!(matches!(
            a.re_evaluate(Utc::now(), prov, cur),
            Err(DomainError::Invariant(_))
        ));
    }

    #[test]
    fn re_evaluate_from_quarantined_fails() {
        let mut a = quarantined_artifact();
        let (prov, cur) = clears();
        assert!(matches!(
            a.re_evaluate(Utc::now(), prov, cur),
            Err(DomainError::Invariant(_))
        ));
    }

    #[test]
    fn re_evaluate_from_released_fails() {
        let mut a = released_artifact();
        let (prov, cur) = clears();
        assert!(matches!(
            a.re_evaluate(Utc::now(), prov, cur),
            Err(DomainError::Invariant(_))
        ));
    }

    // -- ADR 0041 invariant #6 — cross-axis release conjunction -------------

    /// (a) Eligibility guard: a non-`Scanner` rejection reason is
    /// ineligible for a scan re-judgement. Each non-scan reason (and the
    /// unknown `None` case) must keep the artifact `Rejected` and return
    /// `Err(Invariant)` *without mutating* — the application pass skips it.
    #[test]
    fn re_evaluate_non_scanner_reason_is_ineligible_stays_rejected() {
        let non_scanner = [
            None,
            Some(RejectionReason::Admin),
            Some(RejectionReason::CurationRetroactive {
                rule_id: Uuid::new_v4(),
            }),
            Some(RejectionReason::Curator {
                curator_id: Uuid::new_v4(),
            }),
        ];
        for reason in non_scanner {
            let mut a = rejected_artifact();
            a.rejection_reason = reason.clone();
            // Elapsed window — would release under the old reason-blind path.
            a.quarantine_deadline = Some(Utc::now() - chrono::Duration::hours(1));
            let (prov, cur) = clears();
            let err = a.re_evaluate(Utc::now(), prov, cur).unwrap_err();
            assert!(
                matches!(err, DomainError::Invariant(_)),
                "reason {reason:?} must be ineligible"
            );
            assert_eq!(
                a.quarantine_status,
                QuarantineStatus::Rejected,
                "reason {reason:?} must stay Rejected (no mutation)"
            );
            // Reason is left untouched (not cleared) on the ineligible path.
            assert_eq!(a.rejection_reason, reason);
        }
    }

    /// (b) Active provenance precondition: a scan-cleared artifact with
    /// `Pending` provenance (Required mode, not yet verified) must NOT be
    /// released — stays `Rejected` (fail-closed).
    #[test]
    fn re_evaluate_provenance_pending_blocks_release() {
        let mut a = rejected_artifact();
        a.quarantine_deadline = Some(Utc::now() - chrono::Duration::hours(1));
        let err = a
            .re_evaluate(
                Utc::now(),
                ProvenanceClearance::Pending,
                CurationClearance::Cleared,
            )
            .unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        // The scan reason is preserved — a later verify can clear it.
        assert_eq!(a.rejection_reason, Some(RejectionReason::Scanner));
    }

    /// (c) Active curation precondition: a scan-rejected artifact that a
    /// curation rule now blocks (`Blocked`) must NOT be released — the
    /// case the reason guard alone misses (a scan-rejected artifact is
    /// *eligible* under (a), so only the active curation re-check stops
    /// it). Stays `Rejected`.
    #[test]
    fn re_evaluate_curation_blocked_blocks_release() {
        let mut a = rejected_artifact();
        a.quarantine_deadline = Some(Utc::now() - chrono::Duration::hours(1));
        let err = a
            .re_evaluate(
                Utc::now(),
                ProvenanceClearance::NotRequired,
                CurationClearance::Blocked,
            )
            .unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(a.rejection_reason, Some(RejectionReason::Scanner));
    }

    /// The conjunction is an AND: `Cleared` provenance still cannot
    /// release past a curation `Blocked`, and vice versa. Exhaustive over
    /// the "exactly one conjunct fails" cross product.
    #[test]
    fn re_evaluate_release_requires_both_conjuncts() {
        let blocking = [
            (ProvenanceClearance::Pending, CurationClearance::Cleared),
            (ProvenanceClearance::Pending, CurationClearance::Blocked),
            (ProvenanceClearance::NotRequired, CurationClearance::Blocked),
            (ProvenanceClearance::Cleared, CurationClearance::Blocked),
        ];
        for (prov, cur) in blocking {
            let mut a = rejected_artifact();
            a.quarantine_deadline = Some(Utc::now() - chrono::Duration::hours(1));
            let err = a.re_evaluate(Utc::now(), prov, cur).unwrap_err();
            assert!(
                matches!(err, DomainError::Invariant(_)),
                "({prov:?}, {cur:?}) must block release"
            );
            assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        }
        // Both clear → released (the only allow combination on the elapsed
        // window). `Cleared` provenance is also an allow.
        for prov in [
            ProvenanceClearance::NotRequired,
            ProvenanceClearance::Cleared,
        ] {
            let mut a = rejected_artifact();
            a.quarantine_deadline = Some(Utc::now() - chrono::Duration::hours(1));
            assert!(a
                .re_evaluate(Utc::now(), prov, CurationClearance::Cleared)
                .is_ok());
            assert_eq!(a.quarantine_status, QuarantineStatus::Released);
        }
    }

    /// The re-quarantine arm (future window) is NOT gated by the
    /// provenance / curation conjuncts — the artifact stays held
    /// (downloads blocked), so deferring those gates to the eventual timer
    /// release is fail-closed-safe. Even a `Blocked` curation + `Pending`
    /// provenance re-quarantines rather than erroring.
    #[test]
    fn re_evaluate_future_window_requarantines_regardless_of_conjuncts() {
        let mut a = rejected_artifact();
        a.quarantine_deadline = Some(Utc::now() + chrono::Duration::hours(12));
        let event = a
            .re_evaluate(
                Utc::now(),
                ProvenanceClearance::Pending,
                CurationClearance::Blocked,
            )
            .unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
        assert!(matches!(event, DomainEvent::ArtifactQuarantined(_)));
    }

    /// `CurationClearance` derives (Debug/Clone/Copy/Eq) coverage.
    #[test]
    fn curation_clearance_derives() {
        let a = CurationClearance::Cleared;
        let b = a;
        #[allow(clippy::clone_on_copy)]
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, CurationClearance::Blocked);
        assert!(!format!("{:?}", CurationClearance::Blocked).is_empty());
    }

    // -- is_scan_clearable (ADR 0041 invariant #6 (a)) ----------------------
    //
    // The eligibility predicate that `re_evaluate` consults. The scan-axis
    // reasons (Scanner + ScanPolicyRetroactive) are clearable; every other
    // reason (and None) is not.

    #[test]
    fn is_scan_clearable_scan_axis_reasons_are_clearable() {
        assert!(is_scan_clearable(Some(&RejectionReason::Scanner)));
        assert!(is_scan_clearable(Some(
            &RejectionReason::ScanPolicyRetroactive
        )));
    }

    #[test]
    fn is_scan_clearable_non_scan_reasons_and_none_are_not_clearable() {
        assert!(!is_scan_clearable(None));
        assert!(!is_scan_clearable(Some(&RejectionReason::Admin)));
        assert!(!is_scan_clearable(Some(&RejectionReason::Curator {
            curator_id: Uuid::new_v4(),
        })));
        assert!(!is_scan_clearable(Some(
            &RejectionReason::CurationRetroactive {
                rule_id: Uuid::new_v4(),
            }
        )));
    }

    // -- State machine: reject_from_scan_policy_retroactive (ADR 0041) ------
    //
    // The tighten direction of continuous enforcement. The caller computes
    // the verdict via `evaluate_scan_result` over the artifact's STORED
    // findings and threads the `ScanOutcome` in; this method applies it.
    //   Reject           → Rejected (ScanPolicyRetroactive), window NOT re-opened.
    //   Clean            → no-op (Ok(None)), no mutation, no event.
    //   FindingsRecorded → no-op (Ok(None)) — the bumped policy computes a
    //                      blocking verdict but declares enforcement:record,
    //                      so it holds nothing.
    // Valid only from the "active" states Quarantined / Released; terminal
    // source states return Err(Invariant) WITHOUT mutating.

    fn reject_outcome() -> ScanOutcome {
        // The violation list is immaterial to the transition — the verdict
        // (Reject vs Clean) is the only thing the method reads.
        ScanOutcome::Reject(vec![])
    }

    #[test]
    fn reject_from_scan_policy_retroactive_released_now_failing_re_holds() {
        // The headline tighten case: a long-released artifact whose stored
        // findings now cross the tightened gate is re-held to Rejected.
        let mut a = released_artifact();
        // A released artifact has no live quarantine window; set an anchor
        // to prove it is NOT re-opened by the re-hold.
        a.quarantine_window_start = Some(Utc::now() - chrono::Duration::hours(6));
        let anchor = a.quarantine_window_start;
        let event = a
            .reject_from_scan_policy_retroactive(&reject_outcome(), "now exceeds threshold".into())
            .expect("Ok")
            .expect("a now-failing verdict re-holds (emits ArtifactRejected)");
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(event.artifact_id, a.id);
        assert_eq!(event.rejected_by, RejectionReason::ScanPolicyRetroactive);
        assert_eq!(event.reason, "now exceeds threshold");
        // The scan-axis reason is carried on the aggregate so a later
        // loosen can re-release it (invariant #6 (a)).
        assert_eq!(
            a.rejection_reason,
            Some(RejectionReason::ScanPolicyRetroactive)
        );
        // The timer window is NOT re-opened — the original anchor is intact.
        assert_eq!(a.quarantine_window_start, anchor);
    }

    #[test]
    fn reject_from_scan_policy_retroactive_quarantined_now_failing_re_holds() {
        // A still-held artifact whose stored findings now fail is re-held
        // to Rejected (the other accepted active source state).
        let mut a = quarantined_artifact();
        let anchor = a.quarantine_window_start;
        let event = a
            .reject_from_scan_policy_retroactive(&reject_outcome(), "tighten".into())
            .expect("Ok")
            .expect("now-failing re-holds");
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(event.rejected_by, RejectionReason::ScanPolicyRetroactive);
        // Window anchor preserved, not re-opened.
        assert_eq!(a.quarantine_window_start, anchor);
    }

    #[test]
    fn reject_from_scan_policy_retroactive_clean_verdict_is_noop() {
        // Unchanged verdict (still-passing under the new policy) → no-op:
        // no transition, no event, no mutation (invariant #2).
        for mut a in [released_artifact(), quarantined_artifact()] {
            let before = a.clone();
            let out = a
                .reject_from_scan_policy_retroactive(&ScanOutcome::Clean, "irrelevant".into())
                .expect("Clean is Ok(None), never an error");
            assert!(out.is_none(), "Clean must emit no event");
            // Status, reason, and window all unchanged.
            assert_eq!(a, before);
        }
    }

    /// Invariant #4 — no evidence ⇒ no re-rejection. An artifact with no
    /// stored findings evaluates `ScanOutcome::Clean`, so threading `Clean`
    /// here is a no-op: a scan tighten can NEVER re-reject an artifact that
    /// has no evidence it violates. This pins the contract that the method
    /// applies the caller's verdict and never manufactures one.
    #[test]
    fn reject_from_scan_policy_retroactive_no_evidence_clean_never_re_rejects() {
        let mut a = released_artifact();
        let out = a
            .reject_from_scan_policy_retroactive(
                // The verdict a findings-less artifact produces.
                &ScanOutcome::Clean,
                "no findings".into(),
            )
            .expect("Ok");
        assert!(out.is_none());
        assert_eq!(
            a.quarantine_status,
            QuarantineStatus::Released,
            "an artifact with no evidence is never re-rejected on a tighten"
        );
    }

    #[test]
    fn reject_from_scan_policy_retroactive_findings_recorded_is_noop() {
        // A bumped policy whose verdict BLOCKS but whose enforcement is
        // `record`: the tighten pass must leave the artifact exactly where
        // it is. Without this arm a record-mode policy change would
        // re-hold the population it explicitly declared non-gating.
        for mut a in [released_artifact(), quarantined_artifact()] {
            let before = a.clone();
            let out = a
                .reject_from_scan_policy_retroactive(
                    &ScanOutcome::FindingsRecorded(vec![crate::events::PolicyViolation {
                        rule: "cve-severity-threshold".into(),
                        severity: crate::entities::scan_policy::SeverityThreshold::Critical,
                        message: "critical finding".into(),
                        details: serde_json::Value::Null,
                    }]),
                    "irrelevant".into(),
                )
                .expect("FindingsRecorded is Ok(None), never an error");
            assert!(out.is_none(), "a recorded verdict must emit no event");
            assert_eq!(a, before, "a recorded verdict must not mutate the artifact");
        }
    }

    #[test]
    fn reject_from_scan_policy_retroactive_from_none_fails_without_mutating() {
        // A never-held artifact is not in the active scanned population the
        // pass walks; Err(Invariant) without mutating.
        let mut a = sample_artifact();
        let result = a.reject_from_scan_policy_retroactive(&reject_outcome(), "x".into());
        assert!(matches!(result, Err(DomainError::Invariant(_))));
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
        assert_eq!(a.rejection_reason, None);
    }

    #[test]
    fn reject_from_scan_policy_retroactive_from_rejected_fails_without_mutating() {
        // Already blocked — idempotent skip. The fixture is Scanner-rejected;
        // the source-state guard rejects before reading the reason.
        let mut a = rejected_artifact();
        let result = a.reject_from_scan_policy_retroactive(&reject_outcome(), "x".into());
        assert!(matches!(result, Err(DomainError::Invariant(_))));
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        // Reason untouched.
        assert_eq!(a.rejection_reason, Some(RejectionReason::Scanner));
    }

    #[test]
    fn reject_from_scan_policy_retroactive_from_scan_indeterminate_fails_without_mutating() {
        // Terminal scan-failure state (ADR 0007); admin-only exit, never
        // re-held by a policy pass.
        let mut a = scan_indeterminate_artifact();
        let result = a.reject_from_scan_policy_retroactive(&reject_outcome(), "x".into());
        assert!(matches!(result, Err(DomainError::Invariant(_))));
        assert_eq!(a.quarantine_status, QuarantineStatus::ScanIndeterminate);
    }

    /// The guard-widening case (ADR 0041 Item 1): an artifact re-held by a
    /// tighten (`ScanPolicyRetroactive`) whose stored findings a LATER
    /// loosen passes must be re-releasable by `re_evaluate` — otherwise a
    /// tighten→loosen sequence would strand it `Rejected` forever. The
    /// eligibility guard admits `ScanPolicyRetroactive` alongside `Scanner`.
    #[test]
    fn re_evaluate_scan_policy_retroactive_reason_is_re_releasable() {
        let mut a = rejected_artifact();
        a.rejection_reason = Some(RejectionReason::ScanPolicyRetroactive);
        // Elapsed window → the release arm (not re-quarantine).
        a.quarantine_deadline = Some(Utc::now() - chrono::Duration::hours(1));
        let (prov, cur) = clears();
        let event = a
            .re_evaluate(Utc::now(), prov, cur)
            .expect("a ScanPolicyRetroactive rejection is scan-clearable");
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
        assert_eq!(a.rejection_reason, None);
        match event {
            DomainEvent::ArtifactReleased(e) => {
                assert_eq!(e.released_by, ReleaseReason::PolicyReEvaluation);
            }
            other => panic!("expected ArtifactReleased, got {other:?}"),
        }
    }

    /// Companion to the guard-widening test: a `ScanPolicyRetroactive`
    /// rejection with a still-active window re-quarantines (not releases),
    /// proving the widened eligibility admits it on the re-quarantine arm too.
    #[test]
    fn re_evaluate_scan_policy_retroactive_future_window_requarantines() {
        let mut a = rejected_artifact();
        a.rejection_reason = Some(RejectionReason::ScanPolicyRetroactive);
        a.quarantine_deadline = Some(Utc::now() + chrono::Duration::hours(12));
        let (prov, cur) = clears();
        let event = a.re_evaluate(Utc::now(), prov, cur).unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
        assert!(matches!(event, DomainEvent::ArtifactQuarantined(_)));
        assert_eq!(a.rejection_reason, None);
    }

    // -- is_downloadable / is_promotable ------------------------------------

    #[test]
    fn is_downloadable_none() {
        assert!(sample_artifact().is_downloadable());
    }

    #[test]
    fn is_downloadable_quarantined() {
        assert!(!quarantined_artifact().is_downloadable());
    }

    #[test]
    fn is_downloadable_released() {
        assert!(released_artifact().is_downloadable());
    }

    #[test]
    fn is_downloadable_rejected() {
        assert!(!rejected_artifact().is_downloadable());
    }

    #[test]
    fn is_downloadable_scan_indeterminate() {
        assert!(!scan_indeterminate_artifact().is_downloadable());
    }

    #[test]
    fn is_promotable_none() {
        assert!(sample_artifact().is_promotable());
    }

    #[test]
    fn is_promotable_quarantined() {
        assert!(!quarantined_artifact().is_promotable());
    }

    #[test]
    fn is_promotable_released() {
        assert!(released_artifact().is_promotable());
    }

    #[test]
    fn is_promotable_rejected() {
        assert!(!rejected_artifact().is_promotable());
    }

    #[test]
    fn is_promotable_scan_indeterminate() {
        assert!(!scan_indeterminate_artifact().is_promotable());
    }

    // -- delete (soft delete, terminal) -------------------------------------

    fn deletion_ts() -> DateTime<Utc> {
        "2026-03-04T05:06:07Z".parse().unwrap()
    }

    #[test]
    fn delete_marks_deleted_and_returns_event_with_denormalised_coordinates() {
        let mut a = sample_artifact();
        let repo = Uuid::new_v4();
        let id = Uuid::new_v4();
        a.id = id;
        a.repository_id = repo;

        let event = a.delete(deletion_ts()).expect("live artifact is deletable");

        assert_eq!(a.deleted_at, Some(deletion_ts()));
        assert_eq!(event.artifact_id, id);
        assert_eq!(event.repository_id, repo);
        assert_eq!(event.path, a.path);
        assert_eq!(event.content_hash, a.sha256_checksum);
    }

    #[test]
    fn delete_does_not_touch_quarantine_status_or_rejection_reason() {
        // Deletion is orthogonal to the scan axis: the pre-deletion state
        // is exactly what an auditor needs preserved.
        for mut a in [
            sample_artifact(),
            quarantined_artifact(),
            released_artifact(),
            rejected_artifact(),
            scan_indeterminate_artifact(),
        ] {
            let before = a.quarantine_status;
            let reason_before = a.rejection_reason.clone();
            a.delete(deletion_ts()).expect("deletable in any state");
            assert_eq!(a.quarantine_status, before, "status must be preserved");
            assert_eq!(a.rejection_reason, reason_before);
        }
    }

    #[test]
    fn delete_is_terminal_second_delete_is_an_invariant_violation() {
        let mut a = sample_artifact();
        a.delete(deletion_ts()).expect("first delete succeeds");
        let err = a
            .delete(deletion_ts())
            .expect_err("a deleted artifact cannot be deleted again");
        assert!(matches!(err, DomainError::Invariant(_)), "got {err:?}");
        assert!(err.to_string().contains("already deleted"));
        // The rejected second attempt must not move the recorded instant.
        assert_eq!(a.deleted_at, Some(deletion_ts()));
    }

    #[test]
    fn deleted_artifact_is_neither_downloadable_nor_promotable() {
        // Even from `Released`, the state that otherwise permits both.
        let mut a = released_artifact();
        assert!(a.is_downloadable() && a.is_promotable());
        a.delete(deletion_ts()).unwrap();
        assert!(!a.is_downloadable());
        assert!(!a.is_promotable());
    }

    #[test]
    fn delete_event_validates_and_rejects_an_oversize_path() {
        let mut a = sample_artifact();
        let event = a.delete(deletion_ts()).unwrap();
        event.validate().expect("well-formed payload validates");

        let mut oversize = event.clone();
        oversize.path = "x".repeat(2049);
        let err = oversize.validate().expect_err("path is length-capped");
        assert!(err.to_string().contains("path"));
    }

    #[test]
    fn delete_event_rejects_an_empty_path() {
        let mut a = sample_artifact();
        let mut event = a.delete(deletion_ts()).unwrap();
        event.path = String::new();
        let err = event.validate().expect_err("empty path is not a location");
        assert!(err.to_string().contains("path"));
    }
}
