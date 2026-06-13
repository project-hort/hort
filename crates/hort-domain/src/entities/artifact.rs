use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::repository::RepositoryFormat;
use crate::entities::scan_policy::ProvenanceMode;
use crate::error::{DomainError, DomainResult};
use crate::events::{
    ArtifactCorrupted, ArtifactQuarantined, ArtifactRejected, ArtifactReleased, DomainEvent,
    ProvenanceRejected, ProvenanceVerified, RejectionReason, ReleaseReason, ScanIndeterminate,
};
use crate::ports::provenance::{ProvenanceOutcome, ProvenanceRejectReason, ProvenanceVerdict};
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
    /// Immutable observation-window **anchor** (ADR 0007). The
    /// resolved window start — `ingested_at` by default, or
    /// `min(upstream_published_at, ingested_at)` under the per-upstream
    /// publish-anchoring opt-in. `None` ⇒ not quarantined.
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
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
        if self.quarantine_status != QuarantineStatus::None {
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
    pub fn record_clean_scan(&self) -> DomainResult<()> {
        match self.quarantine_status {
            QuarantineStatus::Quarantined | QuarantineStatus::None => Ok(()),
            other => Err(DomainError::Invariant(format!(
                "cannot record clean scan for artifact in state {other}"
            ))),
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
        match self.quarantine_status {
            QuarantineStatus::Quarantined | QuarantineStatus::None => {}
            other => {
                return Err(DomainError::Invariant(format!(
                    "cannot reject artifact in state {other}"
                )));
            }
        }
        self.quarantine_status = QuarantineStatus::Rejected;
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
        match self.quarantine_status {
            QuarantineStatus::Quarantined | QuarantineStatus::Released => {}
            other => {
                return Err(DomainError::Invariant(format!(
                    "cannot retroactively-reject artifact in state {other}"
                )));
            }
        }
        self.quarantine_status = QuarantineStatus::Rejected;
        Ok(ArtifactRejected {
            artifact_id: self.id,
            rejected_by: RejectionReason::CurationRetroactive { rule_id },
            reason,
        })
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
        match self.quarantine_status {
            QuarantineStatus::None | QuarantineStatus::Quarantined | QuarantineStatus::Released => {
            }
            other => {
                return Err(DomainError::Invariant(format!(
                    "cannot curator-block artifact in state {other}"
                )));
            }
        }
        self.quarantine_status = QuarantineStatus::Rejected;
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
        if self.quarantine_status == QuarantineStatus::Rejected {
            return Err(DomainError::Invariant(format!(
                "cannot tombstone artifact in state {} (already rejected)",
                self.quarantine_status
            )));
        }
        let expected_hash = self.sha256_checksum.clone();
        self.quarantine_status = QuarantineStatus::Rejected;
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
    /// release requires a successful scan or an explicit
    /// `scan_backends:[]` waiver; expiry alone can never release.
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
        let source_state_ok = match (&reason, authz) {
            (ReleaseReason::Curator, ReleaseAuthorization::CuratorWaiver) => {
                matches!(self.quarantine_status, QuarantineStatus::Quarantined)
            }
            _ => matches!(
                self.quarantine_status,
                QuarantineStatus::Quarantined | QuarantineStatus::ScanIndeterminate
            ),
        };
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
        // (ReleaseReason::Timer) is authorized ONLY by ScanSucceeded or
        // ScanWaived. AdminOverride / PolicyReEvaluation / CuratorWaiver
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
        // AND-precondition. A `(Timer, ScanSucceeded|ScanWaived)` release
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
                 successful scan or an explicit scan_backends:[] waiver, \
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
    /// - [`ProvenanceOutcome::Verified`] → emit [`ProvenanceVerified`];
    ///   **status unchanged** (like `ScanCompleted(clean)`, a verified
    ///   attestation is a success record that does NOT release the
    ///   artifact early — the release gate reads its *existence* later).
    /// - [`ProvenanceOutcome::Rejected`] → emit [`ProvenanceRejected`];
    ///   status → [`QuarantineStatus::Rejected`].
    /// - [`ProvenanceOutcome::NoAttestation`] (the unsigned case):
    ///   - under [`ProvenanceMode::VerifyIfPresent`] → `Ok(None)` (no
    ///     event, status unchanged — unsigned is allowed);
    ///   - under [`ProvenanceMode::Required`] → emit
    ///     [`ProvenanceRejected`] with reason
    ///     [`ProvenanceRejectReason::Unsigned`]; status → `Rejected`
    ///     (unsigned IS a rejection there).
    ///   - under [`ProvenanceMode::Off`] → `Ok(None)` (provenance is
    ///     inert; the orchestrator does not run a verifier in `Off`, but
    ///     the method is total over the mode for safety).
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
                })))
            }
            ProvenanceOutcome::Rejected(reason) => {
                self.quarantine_status = QuarantineStatus::Rejected;
                Ok(Some(DomainEvent::ProvenanceRejected(ProvenanceRejected {
                    artifact_id: self.id,
                    content_hash: self.sha256_checksum.clone(),
                    backend: backend.into(),
                    reason,
                })))
            }
            ProvenanceOutcome::NoAttestation => match mode {
                ProvenanceMode::Required => {
                    // Unsigned IS a rejection under Required (ADR 0027).
                    self.quarantine_status = QuarantineStatus::Rejected;
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
        match self.quarantine_status {
            QuarantineStatus::Quarantined | QuarantineStatus::None => {}
            other => {
                return Err(DomainError::Invariant(format!(
                    "cannot mark scan-indeterminate for artifact in state {other}"
                )));
            }
        }
        self.quarantine_status = QuarantineStatus::ScanIndeterminate;
        Ok(ScanIndeterminate {
            artifact_id: self.id,
            scanner,
            reason,
            attempts,
        })
    }

    /// Re-evaluate after a policy exclusion removes the scan block.
    /// Only valid from `Rejected`.
    ///
    /// If the quarantine observation window is still in the future,
    /// transitions back to `Quarantined` — the remaining window still
    /// applies. Otherwise transitions directly to `Released`.
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
    pub fn re_evaluate(&mut self, now: DateTime<Utc>) -> DomainResult<DomainEvent> {
        if self.quarantine_status != QuarantineStatus::Rejected {
            return Err(DomainError::Invariant(format!(
                "cannot re-evaluate artifact in state {}",
                self.quarantine_status
            )));
        }
        let still_in_window = self
            .quarantine_deadline
            .is_some_and(|deadline| deadline > now);

        if still_in_window {
            self.quarantine_status = QuarantineStatus::Quarantined;
            Ok(DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
                artifact_id: self.id,
                // The re-quarantine preserves the original anchor — the
                // observation window is unchanged, not restarted.
                quarantine_window_start: self.quarantine_window_start.unwrap_or(now),
            }))
        } else {
            self.quarantine_status = QuarantineStatus::Released;
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

    /// Check if downloads are allowed.
    pub fn is_downloadable(&self) -> bool {
        matches!(
            self.quarantine_status,
            QuarantineStatus::None | QuarantineStatus::Released
        )
    }

    /// Check if promotion is allowed.
    pub fn is_promotable(&self) -> bool {
        matches!(
            self.quarantine_status,
            QuarantineStatus::None | QuarantineStatus::Released
        )
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
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: Some(Uuid::nil()),
            is_deleted: false,
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
    /// per-format upstream metadata; Item 6 is the consumer.
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
        // Released → Rejected transition (design doc §2.3 line 99).
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
        // Use-case layer (Item 5) treats this Err as the idempotent no-op
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
    /// released (it would be under the pre-F-6 timer-only guard).
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
    // The timer arm gains a provenance AND-precondition:
    //   (Timer, ScanSucceeded|ScanWaived) && matches!(provenance,
    //     NotRequired|Cleared)  => release
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
    /// provenance; the F-6 §2.3 invariant "never blocks an explicit
    /// Admin/Curator/PolicyReEval release").
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

    /// F-6 fail-closed property re-asserted across the provenance
    /// dimension: a never-scanned artifact (no `ScanSucceeded`/`ScanWaived`
    /// authority constructible) does NOT timer-release under ANY
    /// `ProvenanceClearance` — provenance never *adds* release authority,
    /// only ever an AND-precondition that can subtract it.
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
                     {clearance:?} must be denied (F-6 fail-closed)"
                );
                assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
            }
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
        // release-sweep `Cleared` computation (Item 4).
        for mode in [ProvenanceMode::VerifyIfPresent, ProvenanceMode::Required] {
            let mut a = quarantined_artifact();
            let signer = crate::ports::provenance::SignerIdentity {
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
                // (Tier-2 readiness).
                .complete_provenance(verdict, mode, "pgp")
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
        let reasons = [
            ProvenanceRejectReason::Unsigned,
            ProvenanceRejectReason::UntrustedIdentity,
            ProvenanceRejectReason::RekorNotFound,
            ProvenanceRejectReason::CertChainInvalid,
            ProvenanceRejectReason::BundleMalformed,
        ];
        for reason in reasons {
            for mode in [ProvenanceMode::VerifyIfPresent, ProvenanceMode::Required] {
                let mut a = quarantined_artifact();
                let ev = a
                    .complete_provenance(ProvenanceVerdict::rejected(reason), mode, "cosign")
                    .expect("Ok")
                    .expect("Rejected emits an event");
                assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
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
            )
            .expect("Ok");
        assert!(out.is_none());
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
    }

    #[test]
    fn complete_provenance_no_attestation_under_required_rejects_unsigned() {
        // Unsigned IS a rejection under Required: emit
        // ProvenanceRejected{Unsigned}, status -> Rejected.
        let mut a = quarantined_artifact();
        let ev = a
            .complete_provenance(
                ProvenanceVerdict::no_attestation(),
                ProvenanceMode::Required,
                // Passed backend is intentionally ignored on the synthesized
                // unsigned arm — the event records the "(policy)" sentinel.
                "cosign",
            )
            .expect("Ok")
            .expect("Required NoAttestation emits a rejection");
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
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

    #[test]
    fn complete_provenance_verified_from_none_permissive_mode_status_unchanged() {
        // Permissive (quarantineDuration:0) ingest sits at None; a Verified
        // verdict is a success record that does not move state.
        let mut a = sample_artifact();
        assert_eq!(a.quarantine_status, QuarantineStatus::None);
        let signer = crate::ports::provenance::SignerIdentity {
            issuer: "iss".into(),
            san: "san".into(),
        };
        let ev = a
            .complete_provenance(
                ProvenanceVerdict::verified(signer, None),
                ProvenanceMode::Required,
                "cosign",
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

    // -- Quarantine-Invariant interaction arms (spec §5) --------------------

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
    /// trusts the typed token; the app layer (spec §6) guarantees no
    /// `ScanSucceeded` token is ever constructed for an unscanned
    /// artifact.
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
    /// §13 R3): a finding-exclusion is a no-op for an artifact with no
    /// finding. re_evaluate from ScanIndeterminate is an Invariant error.
    #[test]
    fn invariant_3_re_evaluate_not_widened_to_scan_indeterminate() {
        let mut a = scan_indeterminate_artifact();
        assert!(matches!(
            a.re_evaluate(Utc::now()),
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

    #[test]
    fn re_evaluate_rejected_future_quarantine_goes_quarantined() {
        let mut a = rejected_artifact();
        // `re_evaluate` reads the transient computed deadline, not the
        // stored anchor.
        a.quarantine_deadline = Some(Utc::now() + chrono::Duration::hours(12));
        let now = Utc::now();
        let event = a.re_evaluate(now).unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
        assert!(matches!(event, DomainEvent::ArtifactQuarantined(_)));
    }

    #[test]
    fn re_evaluate_rejected_past_quarantine_goes_released() {
        let mut a = rejected_artifact();
        a.quarantine_deadline = Some(Utc::now() - chrono::Duration::hours(1));
        let now = Utc::now();
        let event = a.re_evaluate(now).unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
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
        let event = a.re_evaluate(now).unwrap();
        assert_eq!(a.quarantine_status, QuarantineStatus::Released);
        assert!(matches!(event, DomainEvent::ArtifactReleased(_)));
    }

    #[test]
    fn re_evaluate_rejected_no_quarantine_deadline_goes_released() {
        let mut a = rejected_artifact();
        a.quarantine_deadline = None;
        let event = a.re_evaluate(Utc::now()).unwrap();
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
        let event = a.re_evaluate(Utc::now()).unwrap();
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
        assert!(matches!(
            a.re_evaluate(Utc::now()),
            Err(DomainError::Invariant(_))
        ));
    }

    #[test]
    fn re_evaluate_from_quarantined_fails() {
        let mut a = quarantined_artifact();
        assert!(matches!(
            a.re_evaluate(Utc::now()),
            Err(DomainError::Invariant(_))
        ));
    }

    #[test]
    fn re_evaluate_from_released_fails() {
        let mut a = released_artifact();
        assert!(matches!(
            a.re_evaluate(Utc::now()),
            Err(DomainError::Invariant(_))
        ));
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
}
