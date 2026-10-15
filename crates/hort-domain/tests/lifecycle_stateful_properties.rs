//! Stateful property-based suite for the artifact quarantine lifecycle
//! (backlog 091, #135 item 3) — DB-free, network-free, pure `hort-domain`.
//!
//! Random interleavings of ingest / verify (scan, provenance) / sweep-tick
//! (window elapse, release, re-evaluate) actions are replayed against a
//! real [`Artifact`], cross-checked against the declared
//! [`quarantine_transitions::QUARANTINE_TRANSITIONS`] table (backlog 090)
//! as the reference model for transition *legality*, and against five
//! invariants the table alone cannot express (it only encodes per-event
//! source-state legality, not the release-authorization matrix, the
//! re-evaluation eligibility formula, the scan-re-block partition, or
//! any liveness/idempotency property):
//!
//! (a) **Anti-stranding liveness** — every artifact that reaches a
//!     terminal-or-resolvable condition (a clean-scan-equivalent release
//!     authority becomes available, or a `Rejected` artifact's rejection
//!     is scan-clearable) is proven, by actually driving the remaining
//!     preconditions and re-attempting the transition, to reach
//!     `Released` — never permanently stuck `Quarantined`/`ScanIndeterminate`/
//!     `Rejected` when a legitimate path out exists. A `Rejected` artifact
//!     whose reason is *not* scan-clearable (`Admin`, `Curator`,
//!     `CurationRetroactive`, or an unknown `None`) is asserted to
//!     PERMANENTLY fail `re_evaluate` — that is correct fail-closed
//!     behaviour (ADR 0041 invariant #6(a)), not a stranding bug. The
//!     *attended* half is checked beside it, because "the unattended path
//!     correctly refuses" is only half an answer about stranding: a
//!     `Rejected` artifact on an axis `is_curator_overridable` admits is
//!     proven to resolve through the curator's waive, and one on an axis it
//!     refuses (`Corruption`, `Admin`, a reason-less rejection) is proven
//!     to stay `Rejected` through BOTH paths — permanently held by design
//!     (ADR 0007's axis boundary), which is what makes the corruption
//!     tombstone's refusal a property rather than a convention.
//! (b) **The release predicate's allow-row set (ADR 0007)** — see
//!     `release_predicate_exhaustive_authority_matrix` below: an exhaustive
//!     (not sampled) sweep of every `(ReleaseReason, ReleaseAuthorization,
//!     ProvenanceClearance, QuarantineStatus, RejectionReason)` tuple
//!     against the real
//!     `Artifact::release`, asserting `Ok` iff the tuple is one of the
//!     six documented allow-rows with the provenance AND-precondition
//!     satisfied on the `Timer` arm (four scan-axis timer authorities plus
//!     the PolicyReEvaluation / Curator rows — `ReleaseReason::Admin`
//!     pairs with nothing since one authority came to own the manual
//!     release, ADR 0007), **or** the manual `(Curator, CuratorWaiver)`
//!     pairing from `Rejected` on an axis `is_curator_overridable`
//!     admits. The rejection-reason axis is swept from every source
//!     state, not only `Rejected`, which is what proves the predicate
//!     reads the reason nowhere else. Exhaustive
//!     enumeration is used here (not
//!     `proptest` sampling) because the input space is small
//!     (4×6×3×5×8=2880) and finite — exhaustive coverage is strictly
//!     stronger than a random
//!     sample of it; the *stateful*, unbounded-length-sequence invariants
//!     (a), (c), (d) are where `proptest`'s random search earns its keep.
//!
//!     The sweep is only exhaustive over the authority axis if
//!     `ALL_RELEASE_AUTHORIZATIONS` lists every variant, and that array is
//!     hand-written — `ScanRecorded` was missing from it from the day that
//!     authority shipped, which is why its `(Timer, ScanRecorded)` allow-row
//!     went unswept and the oracle's wildcard `_ => false` never had to
//!     answer for it. `authority_ordinal` now pins the array against the
//!     enum at compile time (see `all_release_authorizations_lists_every_variant`),
//!     and nothing in that check is a written-down count: the census size
//!     is the array's own length, so retiring an authority is a deletion
//!     and not a deletion plus a number to remember.
//! (c) **`Rejected -> Released` only through the ADR 0041 `re_evaluate`
//!     exception or the curator's manual override, each with its EXACT
//!     eligibility** — checked live at every step of the random walk
//!     (never a blanket "no Rejected->Released" ban, which would be wrong:
//!     both paths are real) via `re_evaluate_exhaustive_adr_0041_matrix`
//!     (exhaustive, same rationale as (b)) plus a per-step assertion in the
//!     stateful walk that any observed `Rejected -> Released` transition
//!     names `Action::ReEvaluate` and satisfies invariant #6(a)(b)(c) at
//!     the moment it fired, **or** names
//!     `Action::ReleaseCuratorWaiver` and satisfies ADR 0007's axis
//!     boundary (`is_curator_overridable` of the reason in effect when the
//!     call fired). Any third path panics. The two are separate arms
//!     because neither's preconditions may be read off the other's: the
//!     re-judgement is unattended and carries the window and the cross-axis
//!     conjunction, the override is attended and carries only the axis.
//! (d) **Idempotency under event replay** — after every domain-call action,
//!     the SAME action is replayed against a clone of the just-produced
//!     state. A guarded method's documented idempotent-skip contract
//!     ("returns `Err` *without mutating*" — see `Artifact::block_by_curator`,
//!     `tombstone_from_corruption`, `fail_scan_indeterminate` doc comments)
//!     means a replay must either error with the status unchanged, or
//!     succeed as a harmless self-loop (`RecordCleanScan`, a `Clean`-outcome
//!     `RejectFromScanPolicyRetroactive`, `CascadeProvenanceClearance`, a
//!     `Verified`/held `CompleteProvenance` arm) — it must never progress
//!     the state machine a second time.
//! (e) **`reject_from_scan`'s `Released` behaviour IS
//!     `ReleaseOrigin::permits_scan_reblock`, with no second copy of the
//!     rule** — checked live at every `RejectScan` step from a
//!     `Released` source state, as an IFF in both directions. This is a
//!     DRIFT guard, not a statement of the partition: it compares the
//!     method against the predicate, so it stays green if the predicate
//!     itself is rewritten (which is correct — the partition's *content*
//!     is pinned by `release_origin_partitions_automatic_from_explicit`
//!     and the per-reason acceptance tests in `hort-domain` /
//!     `hort-app`). What it catches is the method growing its own,
//!     divergent notion of which releases are protected — the conjunct
//!     the declared table documents as `RejectFromScan`'s
//!     `required_triggers` and does not itself execute.
//!
//! ## Determinism (no wall-clock, no random-seed flake)
//!
//! All timestamps are fixed constants (`base_time()` +/- a `Duration`) —
//! never `Utc::now()`. The stateful-walk property runs its own
//! [`TestRunner`] seeded with a fixed 32-byte `ChaCha` seed
//! ([`TestRng::from_seed`]) instead of the `proptest!` macro's default
//! (process-random-seeded) runner, so the exact same input sequence is
//! explored on every run, on every machine — a failure is reproducible
//! from the printed minimal case alone, with no dependency on `proptest`'s
//! failure-persistence regression file. Case counts (`STATEFUL_CASES`,
//! sequence length `1..=24`) and the two exhaustive matrices (2880 + 96
//! tuples) keep the whole module well under the ~60s local budget (measured
//! well under 1s for the matrices: these are pure in-memory `hort-domain`
//! calls, no I/O). Neither count is written down anywhere the sweep reads
//! — both assertions derive the expected case count from the vocabularies'
//! own lengths, so widening one is not also a number to remember.
//!
//! ## Failure minimization
//!
//! `proptest` shrinks a failing stateful-walk case automatically —
//! toward the shortest action sequence (and the simplest per-action
//! parameters) that still reproduces the violation — before printing it;
//! the printed `Vec<Action>` is that minimized case, not the original
//! random draw. No extra configuration is required to get this: it is
//! `proptest`'s default `Strategy::value_tree`/shrink behaviour for
//! `proptest::collection::vec` and the `prop_oneof!`-built `Action`
//! strategy used here.
//!
//! ## Hard constraint
//!
//! This suite is tests-only. If a run surfaces a genuine invariant
//! violation, that is a STOP-and-report finding (a real domain bug) —
//! never a test weakened to pass.

#![allow(clippy::too_many_lines)]

use chrono::{DateTime, Duration, TimeZone, Utc};
use hort_domain::entities::artifact::{
    is_curator_overridable, is_scan_clearable, Artifact, CurationClearance, ProvenanceClearance,
    QuarantineStatus, ReleaseAuthorization, ReleaseOrigin,
};
use hort_domain::entities::quarantine_transitions::{self, QuarantineEvent};
use hort_domain::entities::scan_policy::{ProvenanceMode, SeverityThreshold};
use hort_domain::events::{PolicyViolation, RejectionReason, ReleaseReason};
use hort_domain::policy::ScanOutcome;
use hort_domain::ports::provenance::{
    IndeterminateReason, ProvenanceRejectReason, ProvenanceVerdict, SignerIdentity,
};
use hort_domain::types::ContentHash;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixed fixtures — no wall-clock, no OS randomness in anything that affects
// control flow.
// ---------------------------------------------------------------------------

const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// A fixed 32-byte seed for the stateful walk's own [`TestRunner`] — see
/// the module header's Determinism section.
const FIXED_SEED: [u8; 32] = [0x4f; 32];
const STATEFUL_CASES: u32 = 8192;

fn base_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

fn future_deadline() -> DateTime<Utc> {
    base_time() + Duration::hours(1)
}

fn past_deadline() -> DateTime<Utc> {
    base_time() - Duration::hours(1)
}

fn fixed_hash() -> ContentHash {
    VALID_SHA256.parse().expect("fixture sha256 must parse")
}

fn fixed_signer() -> SignerIdentity {
    SignerIdentity {
        issuer: "https://issuer.example".into(),
        san: "workload@example".into(),
    }
}

fn curator_id() -> Uuid {
    Uuid::from_u128(0xC0)
}

fn rule_id() -> Uuid {
    Uuid::from_u128(0xEE)
}

fn fresh_artifact() -> Artifact {
    Artifact {
        id: Uuid::from_u128(1),
        repository_id: Uuid::from_u128(2),
        name: "pkg".into(),
        name_as_published: "pkg".into(),
        version: Some("1.0.0".into()),
        path: "pkg/1.0.0/pkg-1.0.0.tar.gz".into(),
        size_bytes: 1024,
        sha256_checksum: fixed_hash(),
        sha1_checksum: None,
        md5_checksum: None,
        content_type: "application/octet-stream".into(),
        quarantine_status: QuarantineStatus::None,
        rejection_reason: None,
        quarantine_window_start: None,
        quarantine_deadline: None,
        provenance_hold_indefinite: false,
        deleted_at: None,
        upstream_published_at: None,
        uploaded_by: None,
        created_at: base_time(),
        updated_at: base_time(),
    }
}

fn reject_violation() -> ScanOutcome {
    ScanOutcome::Reject(vec![PolicyViolation {
        rule: "cve-severity-threshold".into(),
        severity: SeverityThreshold::Critical,
        message: "fixture violation".into(),
        details: serde_json::Value::Null,
    }])
}

// ---------------------------------------------------------------------------
// Aux — the application-layer-computed facts `Artifact`'s pure methods
// trust as input (ADR 0007 / ADR 0027 / ADR 0041). Never mutated by
// `perform` — only by the main walk loop, so a replay call always sees
// exactly the conditions in effect when the original call fired.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Aux {
    provenance_mode: ProvenanceMode,
    window_open: bool,
    curation_blocked: bool,
    provenance_verified: bool,
    /// Who last released the artifact — the fact the application layer
    /// resolves from the stream's latest `ArtifactReleased` and
    /// `Artifact::reject_from_scan` applies to a `Released` source
    /// state. Updated by the walk loop from the REAL outcome of each
    /// release action, so a `RejectScan` that follows an admin release
    /// sees `Released(Admin)` exactly as the orchestration would.
    release_origin: ReleaseOrigin,
}

impl Aux {
    fn initial() -> Self {
        Aux {
            provenance_mode: ProvenanceMode::Off,
            window_open: false,
            curation_blocked: false,
            provenance_verified: false,
            release_origin: ReleaseOrigin::NeverReleased,
        }
    }

    fn provenance_clearance(&self) -> ProvenanceClearance {
        match self.provenance_mode {
            ProvenanceMode::Off | ProvenanceMode::VerifyIfPresent => {
                ProvenanceClearance::NotRequired
            }
            ProvenanceMode::Required => {
                if self.provenance_verified {
                    ProvenanceClearance::Cleared
                } else {
                    ProvenanceClearance::Pending
                }
            }
        }
    }

    fn curation_clearance(&self) -> CurationClearance {
        if self.curation_blocked {
            CurationClearance::Blocked
        } else {
            CurationClearance::Cleared
        }
    }
}

// ---------------------------------------------------------------------------
// Action — one step of a random interleaving.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Action {
    Ingest,
    CleanScan,
    RejectScan,
    RejectRetroCuration,
    ScanPolicyRetro { reject: bool },
    BlockByCurator,
    TombstoneCorruption,
    FailScanIndeterminate,
    ProvenanceVerify,
    ProvenanceReject,
    ProvenanceNoAttestation,
    // The verdict that could not be reached (no usable trust-root key,
    // material we never fetched). A held arm like
    // `ProvenanceNoAttestation`, and in the model for the same reason: a
    // hold must never progress the lifecycle, whatever is interleaved
    // around it.
    ProvenanceIndeterminate,
    CascadeClearance,
    ElapseWindow,
    SetCurationBlocked(bool),
    SetProvenanceMode(ProvenanceMode),
    ReleaseCuratorWaiver,
    ReleasePolicyReEval,
    ReleaseTimer { waived: bool },
    ReEvaluate,
}

fn provenance_mode_strategy() -> impl Strategy<Value = ProvenanceMode> {
    prop_oneof![
        Just(ProvenanceMode::Off),
        Just(ProvenanceMode::VerifyIfPresent),
        Just(ProvenanceMode::Required),
    ]
}

fn action_strategy() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::Ingest),
        Just(Action::CleanScan),
        Just(Action::RejectScan),
        Just(Action::RejectRetroCuration),
        any::<bool>().prop_map(|reject| Action::ScanPolicyRetro { reject }),
        Just(Action::BlockByCurator),
        Just(Action::TombstoneCorruption),
        Just(Action::FailScanIndeterminate),
        Just(Action::ProvenanceVerify),
        Just(Action::ProvenanceReject),
        Just(Action::ProvenanceNoAttestation),
        Just(Action::ProvenanceIndeterminate),
        Just(Action::CascadeClearance),
        Just(Action::ElapseWindow),
        any::<bool>().prop_map(Action::SetCurationBlocked),
        provenance_mode_strategy().prop_map(Action::SetProvenanceMode),
        Just(Action::ReleaseCuratorWaiver),
        Just(Action::ReleasePolicyReEval),
        any::<bool>().prop_map(|waived| Action::ReleaseTimer { waived }),
        Just(Action::ReEvaluate),
    ]
}

fn actions_strategy() -> impl Strategy<Value = Vec<Action>> {
    proptest::collection::vec(action_strategy(), 1..=24)
}

/// The [`QuarantineEvent`] a domain-call action represents, for the
/// declared-table cross-check — `None` for the pure environment-toggle
/// actions (`ElapseWindow`, `SetDescendant`, `SetConstituent`, `SetCurationBlocked`,
/// `SetProvenanceMode`), which are not domain calls at all.
fn event_for(action: Action) -> Option<QuarantineEvent> {
    match action {
        Action::Ingest => Some(QuarantineEvent::Quarantine),
        Action::CleanScan => Some(QuarantineEvent::RecordCleanScan),
        Action::RejectScan => Some(QuarantineEvent::RejectFromScan),
        Action::RejectRetroCuration => Some(QuarantineEvent::RejectFromRetroactiveCuration),
        Action::ScanPolicyRetro { .. } => Some(QuarantineEvent::RejectFromScanPolicyRetroactive),
        Action::BlockByCurator => Some(QuarantineEvent::BlockByCurator),
        Action::TombstoneCorruption => Some(QuarantineEvent::TombstoneFromCorruption),
        Action::FailScanIndeterminate => Some(QuarantineEvent::FailScanIndeterminate),
        Action::ProvenanceVerify
        | Action::ProvenanceReject
        | Action::ProvenanceNoAttestation
        | Action::ProvenanceIndeterminate => Some(QuarantineEvent::CompleteProvenance),
        Action::CascadeClearance => Some(QuarantineEvent::CascadeProvenanceClearance),
        Action::ReleaseCuratorWaiver
        | Action::ReleasePolicyReEval
        | Action::ReleaseTimer { .. } => Some(QuarantineEvent::Release),
        Action::ReEvaluate => Some(QuarantineEvent::ReEvaluate),
        Action::ElapseWindow | Action::SetCurationBlocked(_) | Action::SetProvenanceMode(_) => None,
    }
}

/// Perform the domain call `action` represents against `artifact`, trusting
/// `aux` as the verified-facts input (mirroring the application layer).
/// Returns whether the call returned `Ok`. Never touches `aux` — callers
/// update it afterward based on the *real* outcome, and a replay call
/// passes the SAME `aux` snapshot the original call saw.
fn perform(artifact: &mut Artifact, aux: &Aux, action: Action) -> bool {
    match action {
        Action::Ingest => artifact.quarantine(base_time()).is_ok(),
        Action::CleanScan => artifact.record_clean_scan().is_ok(),
        Action::RejectScan => artifact
            .reject_from_scan("scan finding".into(), aux.release_origin)
            .is_ok(),
        Action::RejectRetroCuration => artifact
            .reject_from_retroactive_curation(rule_id(), "curation hit".into())
            .is_ok(),
        Action::ScanPolicyRetro { reject } => {
            let outcome = if reject {
                reject_violation()
            } else {
                ScanOutcome::Clean
            };
            artifact
                .reject_from_scan_policy_retroactive(&outcome, "policy re-derive".into())
                .is_ok()
        }
        Action::BlockByCurator => artifact
            .block_by_curator(curator_id(), "curator block".into())
            .is_ok(),
        Action::TombstoneCorruption => artifact
            .tombstone_from_corruption(fixed_hash(), base_time())
            .is_ok(),
        Action::FailScanIndeterminate => artifact
            .fail_scan_indeterminate("trivy".into(), "exhausted".into(), 3)
            .is_ok(),
        Action::ProvenanceVerify => artifact
            .complete_provenance(ProvenanceVerdict::verified(fixed_signer(), None), "cosign")
            .is_ok(),
        Action::ProvenanceReject => artifact
            .complete_provenance(
                ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity),
                "cosign",
            )
            .is_ok(),
        Action::ProvenanceNoAttestation => artifact
            .complete_provenance(ProvenanceVerdict::no_attestation(), "cosign")
            .is_ok(),
        Action::ProvenanceIndeterminate => artifact
            .complete_provenance(
                ProvenanceVerdict::indeterminate(IndeterminateReason::TrustRootUnusable),
                "cosign",
            )
            .is_ok(),
        Action::CascadeClearance => artifact
            .cascade_provenance_clearance(fixed_hash(), fixed_signer(), None, "cosign")
            .is_ok(),
        Action::ReleaseCuratorWaiver => artifact
            .release(
                ReleaseReason::Curator,
                ReleaseAuthorization::CuratorWaiver,
                aux.provenance_clearance(),
            )
            .is_ok(),
        Action::ReleasePolicyReEval => artifact
            .release(
                ReleaseReason::PolicyReEvaluation,
                ReleaseAuthorization::PolicyReEvaluation,
                aux.provenance_clearance(),
            )
            .is_ok(),
        Action::ReleaseTimer { waived } => {
            let authz = if waived {
                ReleaseAuthorization::ScanWaived
            } else {
                ReleaseAuthorization::ScanSucceeded
            };
            artifact
                .release(ReleaseReason::Timer, authz, aux.provenance_clearance())
                .is_ok()
        }
        Action::ReEvaluate => artifact
            .re_evaluate(
                base_time(),
                aux.provenance_clearance(),
                aux.curation_clearance(),
            )
            .is_ok(),
        Action::ElapseWindow | Action::SetCurationBlocked(_) | Action::SetProvenanceMode(_) => {
            unreachable!("pure aux actions never call perform")
        }
    }
}

// ---------------------------------------------------------------------------
// The stateful walk: interpret a random `Vec<Action>`, checking invariants
// (a) liveness, (c) the ADR 0041 exception, and (d) idempotency at every
// step, using the declared table as the transition-legality oracle
// throughout (backlog 090's stated purpose: "using item 090's declared
// tables as the reference model where they fit").
// ---------------------------------------------------------------------------

fn run_walk(actions: &[Action]) {
    let mut artifact = fresh_artifact();
    let mut aux = Aux::initial();

    for &action in actions {
        if matches!(
            action,
            Action::ElapseWindow | Action::SetCurationBlocked(_) | Action::SetProvenanceMode(_)
        ) {
            match action {
                Action::ElapseWindow => {
                    aux.window_open = false;
                    if artifact.quarantine_deadline.is_some() {
                        artifact.quarantine_deadline = Some(past_deadline());
                    }
                }
                Action::SetCurationBlocked(b) => aux.curation_blocked = b,
                Action::SetProvenanceMode(m) => aux.provenance_mode = m,
                _ => unreachable!(),
            }
            continue;
        }

        let before_status = artifact.quarantine_status;
        let before_reason = artifact.rejection_reason.clone();
        let before_aux = aux;
        let event = event_for(action).expect("domain-call action must map to a QuarantineEvent");

        let ok = perform(&mut artifact, &aux, action);
        let after_status = artifact.quarantine_status;

        // --- declared-table cross-check (backlog 090 reference model) ---
        let table_allowed = quarantine_transitions::allowed_targets(event, before_status);
        if ok {
            let allowed = table_allowed.unwrap_or_else(|| {
                panic!(
                    "{action:?} succeeded from {before_status:?} but \
                     QUARANTINE_TRANSITIONS classifies this cell Forbidden"
                )
            });
            assert!(
                allowed.contains(&after_status),
                "{action:?} from {before_status:?} reached {after_status:?}, not in the \
                 table-declared reachable set {allowed:?}"
            );
        } else {
            assert_eq!(
                after_status, before_status,
                "{action:?} returned Err but mutated quarantine_status \
                 ({before_status:?} -> {after_status:?}) — a guarded method must not \
                 mutate on its error path"
            );
        }

        // --- invariant (c): Rejected -> Released only via the ADR 0041
        //     exception or the curator's override, each with its EXACT
        //     precondition ---
        // Two paths, deliberately not one: the unattended re-judgement
        // (`re_evaluate`, ADR 0041 invariant #6) and the attended human
        // override (ADR 0007's axis boundary). Nothing else, ever — and
        // neither path's preconditions may be read off the other's, which
        // is why the predicates are separate and so are these arms.
        if before_status == QuarantineStatus::Rejected && after_status == QuarantineStatus::Released
        {
            match action {
                Action::ReEvaluate => {
                    assert!(
                        is_scan_clearable(before_reason.as_ref()),
                        "re_evaluate released a Rejected artifact whose reason \
                         {before_reason:?} is not scan-clearable (invariant #6(a))"
                    );
                    assert!(
                        !before_aux.window_open,
                        "re_evaluate released a Rejected artifact while its observation \
                         window was still open (should have re-quarantined instead)"
                    );
                    assert!(
                        matches!(
                            before_aux.provenance_clearance(),
                            ProvenanceClearance::NotRequired | ProvenanceClearance::Cleared
                        ),
                        "re_evaluate released a Rejected artifact with provenance \
                         {:?} — invariant #6(b) requires NotRequired or Cleared",
                        before_aux.provenance_clearance()
                    );
                    assert!(
                        !before_aux.curation_blocked,
                        "re_evaluate released a Rejected artifact under an active \
                         curation block — invariant #6(c) violated"
                    );
                }
                Action::ReleaseCuratorWaiver => {
                    assert!(
                        is_curator_overridable(before_reason.as_ref()),
                        "a curator waive released a Rejected artifact whose reason \
                         {before_reason:?} is on an axis the override does not reach \
                         (ADR 0007's axis boundary — corruption, admin and a \
                         reason-less rejection are refused)"
                    );
                }
                other => panic!(
                    "artifact moved Rejected -> Released via {other:?} — the only two \
                     paths are re_evaluate's ADR 0041 exception and the curator's \
                     manual override; an unattended authority must never acquire one"
                ),
            }
            assert_eq!(
                artifact.rejection_reason, None,
                "a Rejected -> Released transition via {action:?} left the rejection \
                 reason {:?} behind — a Released artifact carrying one is an illegal \
                 state and the next policy pass would read it",
                artifact.rejection_reason
            );
        }

        // --- invariant (e): reject_from_scan's Released behaviour IS
        //     ReleaseOrigin::permits_scan_reblock ---
        // An IFF in both directions, so the method cannot grow its own
        // notion of which releases are protected — neither a narrower
        // one (an automatic release left permanently un-blockable) nor a
        // wider one (an operator release undone by a scan verdict).
        // A drift guard against the predicate, not a statement of the
        // partition: see the module header's (e). Asked of the origin in
        // effect when the call fired, which is what `before_aux` holds.
        if matches!(action, Action::RejectScan) && before_status == QuarantineStatus::Released {
            assert_eq!(
                after_status == QuarantineStatus::Rejected,
                before_aux.release_origin.permits_scan_reblock(),
                "reject_from_scan on a Released artifact with origin {} left it \
                 {after_status:?}; the origin's partition says \
                 permits_scan_reblock={}",
                before_aux.release_origin,
                before_aux.release_origin.permits_scan_reblock()
            );
        }

        // --- update aux from the REAL outcome ---
        if ok {
            match action {
                Action::Ingest => {
                    aux.window_open = true;
                    artifact.quarantine_deadline = Some(future_deadline());
                }
                Action::ProvenanceVerify => aux.provenance_verified = true,
                Action::ProvenanceReject => aux.provenance_verified = false,
                Action::CascadeClearance => aux.provenance_verified = true,
                // Every path that appends an `ArtifactReleased` records
                // the reason it carried, so the next `RejectScan` reads
                // the same origin the orchestration would resolve from
                // the stream.
                Action::ReleaseCuratorWaiver => {
                    aux.release_origin = ReleaseOrigin::Released(ReleaseReason::Curator);
                }
                Action::ReleasePolicyReEval => {
                    aux.release_origin = ReleaseOrigin::Released(ReleaseReason::PolicyReEvaluation);
                }
                Action::ReleaseTimer { .. } => {
                    aux.release_origin = ReleaseOrigin::Released(ReleaseReason::Timer);
                }
                Action::ReEvaluate if after_status == QuarantineStatus::Released => {
                    // The ADR 0041 exception's release arm appends an
                    // `ArtifactReleased{PolicyReEvaluation}`.
                    aux.release_origin = ReleaseOrigin::Released(ReleaseReason::PolicyReEvaluation);
                }
                Action::ReEvaluate if after_status == QuarantineStatus::Quarantined => {
                    // Re-quarantine preserves the original (still-open) window.
                }
                _ => {}
            }
        }

        // --- invariant (d): idempotency under event replay ---
        // Redeliver the SAME action, under the SAME conditions the original
        // call saw, against a clone of the just-produced state. It must
        // never progress the state machine a second time.
        let mut replay = artifact.clone();
        let replay_before = replay.quarantine_status;
        let replay_ok = perform(&mut replay, &aux, action);
        assert_eq!(
            replay.quarantine_status, replay_before,
            "replaying {action:?} (idempotency under event replay) moved the \
             artifact from {replay_before:?} to {:?} (replay Ok={replay_ok}) — a \
             redelivered event must be a no-op, not a second state transition",
            replay.quarantine_status
        );
    }

    // --- invariant (a): anti-stranding liveness closer ---
    // Drive whatever additional preconditions a real sweep/orchestrator
    // would eventually supply, then prove the artifact is NOT permanently
    // stuck — unless it is being held for a documented, intentional
    // fail-closed reason (a non-scan-clearable Rejected reason).
    match artifact.quarantine_status {
        QuarantineStatus::Quarantined | QuarantineStatus::ScanIndeterminate => {
            // Eventually the signature arrives, if one was pending.
            if aux.provenance_mode == ProvenanceMode::Required && !aux.provenance_verified {
                let ok = artifact
                    .complete_provenance(
                        ProvenanceVerdict::verified(fixed_signer(), None),
                        "cosign",
                    )
                    .is_ok();
                assert!(ok, "a pending provenance verify must always be acceptable");
                aux.provenance_verified = true;
            }
            let status_before_release = artifact.quarantine_status;
            let released = artifact
                .release(
                    ReleaseReason::Timer,
                    ReleaseAuthorization::ScanSucceeded,
                    aux.provenance_clearance(),
                )
                .is_ok();
            assert!(
                released,
                "artifact stranded in {status_before_release:?}: a scan-succeeded timer \
                 release with clearance {:?} was refused (anti-stranding liveness \
                 violated, invariant (a))",
                aux.provenance_clearance()
            );
            assert_eq!(artifact.quarantine_status, QuarantineStatus::Released);
        }
        QuarantineStatus::Rejected => {
            let reason_snapshot = artifact.rejection_reason.clone();

            // The ATTENDED half, checked on a clone so the unattended
            // assertions below still see the untouched artifact. A curator
            // waive needs no window, no provenance clearance and no
            // curation clearance — only the axis — so this is a complete
            // statement of the override's liveness, and of its permanence
            // on the axes it refuses.
            {
                let mut attended = artifact.clone();
                let overridden = attended
                    .release(
                        ReleaseReason::Curator,
                        ReleaseAuthorization::CuratorWaiver,
                        // Deliberately the worst case: an explicit
                        // override is never blocked by the provenance gate.
                        ProvenanceClearance::Pending,
                    )
                    .is_ok();
                assert_eq!(
                    overridden,
                    is_curator_overridable(reason_snapshot.as_ref()),
                    "a curator waive against a Rejected artifact (reason \
                     {reason_snapshot:?}) returned Ok={overridden}, but ADR 0007's axis \
                     boundary says the override reaches it = {}. A false negative strands \
                     an artifact the curator is the authority over; a false positive \
                     overrides an axis the curator's instrument cannot reach",
                    is_curator_overridable(reason_snapshot.as_ref())
                );
                if overridden {
                    assert_eq!(attended.quarantine_status, QuarantineStatus::Released);
                    assert_eq!(
                        attended.rejection_reason, None,
                        "the override must clear the rejection reason"
                    );
                } else {
                    assert_eq!(attended.quarantine_status, QuarantineStatus::Rejected);
                }
            }

            if is_scan_clearable(reason_snapshot.as_ref()) {
                // Eligible for the ADR 0041 exception: drive window-elapsed +
                // clear provenance/curation and prove it actually resolves.
                aux.window_open = false;
                if artifact.quarantine_deadline.is_some() {
                    artifact.quarantine_deadline = Some(past_deadline());
                } else {
                    // Never explicitly quarantined (e.g. reached Rejected from
                    // `None` via `RejectFromScan`) — an un-hydrated deadline
                    // reads as elapsed per `re_evaluate`'s own documented
                    // contract, so no deadline needs to be set here.
                }
                aux.curation_blocked = false;
                if aux.provenance_mode == ProvenanceMode::Required && !aux.provenance_verified {
                    let ok = artifact
                        .complete_provenance(
                            ProvenanceVerdict::verified(fixed_signer(), None),
                            "cosign",
                        )
                        .is_ok();
                    assert!(ok);
                    aux.provenance_verified = true;
                }
                let resolved = artifact
                    .re_evaluate(
                        base_time(),
                        aux.provenance_clearance(),
                        aux.curation_clearance(),
                    )
                    .is_ok();
                assert!(
                    resolved,
                    "scan-clearable Rejected artifact (reason {reason_snapshot:?}) failed \
                     to resolve via re_evaluate once window/provenance/curation all \
                     cleared — anti-stranding liveness violated for the ADR 0041 exception"
                );
                assert_eq!(artifact.quarantine_status, QuarantineStatus::Released);
            } else {
                // NOT scan-clearable: permanently held is the correct,
                // intentional outcome (ADR 0041 invariant #6(a)) — prove it
                // is genuinely permanent, i.e. re_evaluate never resolves it
                // no matter how favourable the other conditions are.
                aux.window_open = false;
                aux.curation_blocked = false;
                let resolved = artifact
                    .re_evaluate(
                        base_time(),
                        ProvenanceClearance::NotRequired,
                        aux.curation_clearance(),
                    )
                    .is_ok();
                assert!(
                    !resolved,
                    "a non-scan-clearable Rejected artifact (reason {reason_snapshot:?}) \
                     unexpectedly resolved via re_evaluate — invariant #6(a) breached"
                );
                assert_eq!(artifact.quarantine_status, QuarantineStatus::Rejected);
            }
        }
        QuarantineStatus::None | QuarantineStatus::Released => {
            // Never quarantined, or already resolved — nothing to strand.
        }
    }
}

#[test]
fn stateful_lifecycle_walk_invariants() {
    let config = Config {
        cases: STATEFUL_CASES,
        // No regression-file persistence: the fixed `FIXED_SEED` below
        // already makes every run fully reproducible without depending on
        // a `proptest-regressions/` file (and this manual `TestRunner`, not
        // the `proptest!` macro, cannot resolve a source path for one
        // anyway — leaving the default `Some(..)` here only prints a
        // spurious `FileFailurePersistence::SourceParallel set, but no
        // source file known` warning on every run).
        failure_persistence: None,
        ..Config::default()
    };
    let mut runner = TestRunner::new_with_rng(
        config,
        TestRng::from_seed(RngAlgorithm::ChaCha, &FIXED_SEED),
    );
    runner
        .run(&actions_strategy(), |actions| {
            run_walk(&actions);
            Ok(())
        })
        .unwrap();
}

// ---------------------------------------------------------------------------
// Invariant (b): the release predicate's allow-row set (ADR 0007) —
// exhaustive over the full finite argument space of `Artifact::release`.
// ---------------------------------------------------------------------------

const ALL_RELEASE_REASONS: &[ReleaseReason] = &[
    ReleaseReason::Timer,
    ReleaseReason::Admin,
    ReleaseReason::PolicyReEvaluation,
    ReleaseReason::Curator,
];

const ALL_RELEASE_AUTHORIZATIONS: &[ReleaseAuthorization] = &[
    ReleaseAuthorization::ScanSucceeded,
    ReleaseAuthorization::ScanCleared,
    ReleaseAuthorization::ScanWaived,
    ReleaseAuthorization::ScanRecorded,
    ReleaseAuthorization::PolicyReEvaluation,
    ReleaseAuthorization::CuratorWaiver,
];

/// A distinct index per authority, via a match with **no wildcard arm**:
/// a new `ReleaseAuthorization` does not compile until it is given one.
///
/// This exists because the sweep's exhaustiveness over the authority axis
/// rests on a hand-written array, and an array cannot be checked by the
/// compiler. `ScanRecorded` was absent from it for the whole life of that
/// authority — the sweep silently never exercised `(Timer, ScanRecorded)`,
/// and because the oracle below denies by default, adding it later would
/// have been a *failing* test rather than a quietly widened one.
/// `all_release_authorizations_lists_every_variant` closes that: the
/// compiler forces a row here, and the test forces the array to carry it.
fn authority_ordinal(authz: ReleaseAuthorization) -> usize {
    match authz {
        ReleaseAuthorization::ScanSucceeded => 0,
        ReleaseAuthorization::ScanCleared => 1,
        ReleaseAuthorization::ScanWaived => 2,
        ReleaseAuthorization::ScanRecorded => 3,
        ReleaseAuthorization::PolicyReEvaluation => 4,
        ReleaseAuthorization::CuratorWaiver => 5,
    }
}

/// `ALL_RELEASE_AUTHORIZATIONS` carries every authority exactly once, so
/// the matrix sweep below is genuinely exhaustive over that axis.
///
/// **No written-down count.** The census size is the array's own length:
/// the assertion is that mapping the array through the wildcard-free
/// `authority_ordinal` yields exactly the ordinals `0..len`, each once.
/// A hand-maintained `COUNT` beside the array stated the same fact a
/// third time and was the copy a vocabulary change forgot — retiring
/// the admin-override authority had to be a deletion from the enum, the
/// array and the ordinal match, not those three plus a number.
#[test]
fn all_release_authorizations_lists_every_variant() {
    let mut ordinals: Vec<usize> = ALL_RELEASE_AUTHORIZATIONS
        .iter()
        .copied()
        .map(authority_ordinal)
        .collect();
    ordinals.sort_unstable();
    assert_eq!(
        ordinals,
        (0..ALL_RELEASE_AUTHORIZATIONS.len()).collect::<Vec<_>>(),
        "the sweep's authority axis must list every ReleaseAuthorization \
         exactly once, with no gap and no duplicate; `authority_ordinal` \
         is the compiler-checked census (it has no wildcard arm, so a new \
         variant does not compile until it is given an ordinal — and the \
         ordinals have to stay dense from zero, which is what forces the \
         array to carry it)"
    );
}

const ALL_PROVENANCE_CLEARANCES: &[ProvenanceClearance] = &[
    ProvenanceClearance::NotRequired,
    ProvenanceClearance::Cleared,
    ProvenanceClearance::Pending,
];

const ALL_QUARANTINE_STATUSES: &[QuarantineStatus] = &[
    QuarantineStatus::None,
    QuarantineStatus::Quarantined,
    QuarantineStatus::Released,
    QuarantineStatus::Rejected,
    QuarantineStatus::ScanIndeterminate,
];

/// The exact six-row allow predicate documented in ADR 0007 / this
/// module's header, independent of `Artifact::release`'s implementation —
/// the oracle the exhaustive sweep checks the real method against.
///
/// The trailing `_ => false` is the deny-by-default statement itself, not
/// a gap: it is what makes a *new* authority denied here until someone
/// writes its row, so the sweep fails loudly rather than widening.
///
/// `rejection_reason` is the reason the artifact carries, consulted only
/// for a `Rejected` source state (where the sweep varies it) and ignored
/// everywhere else — the release predicate reads it nowhere else.
fn expected_release_ok(
    reason: &ReleaseReason,
    authz: ReleaseAuthorization,
    provenance: ProvenanceClearance,
    from: QuarantineStatus,
    rejection_reason: Option<&RejectionReason>,
) -> bool {
    // Two source-state rules, not one. `Quarantined` /
    // `ScanIndeterminate` are reached by every pairing — one authority
    // owns the manual release and what it requires there is the source
    // state, not a second permission tier (ADR 0007, "One authority owns
    // the manual release"). `Rejected` is reached by the MANUAL pairing
    // alone, and only on an axis the curator's instrument reaches (ADR
    // 0007, "The axis boundary for a `Rejected` artifact"): an override of
    // a recorded verdict is a human decision taken with that verdict in
    // view, and the timer sweep and the policy pass run unattended.
    match from {
        QuarantineStatus::Quarantined | QuarantineStatus::ScanIndeterminate => {}
        QuarantineStatus::Rejected => {
            let manual = matches!(
                (reason, authz),
                (ReleaseReason::Curator, ReleaseAuthorization::CuratorWaiver)
            );
            return manual && is_curator_overridable(rejection_reason);
        }
        QuarantineStatus::None | QuarantineStatus::Released => return false,
    }
    let provenance_clears_timer = matches!(
        provenance,
        ProvenanceClearance::NotRequired | ProvenanceClearance::Cleared
    );
    match (reason, authz) {
        // The four scan-axis timer authorities, all carrying the same
        // provenance AND-precondition: the scan found nothing /
        // the verdict permitted what it found / the operator waived
        // scanning / the operator declared the verdict non-gating.
        (ReleaseReason::Timer, ReleaseAuthorization::ScanSucceeded)
        | (ReleaseReason::Timer, ReleaseAuthorization::ScanCleared)
        | (ReleaseReason::Timer, ReleaseAuthorization::ScanWaived)
        | (ReleaseReason::Timer, ReleaseAuthorization::ScanRecorded) => provenance_clears_timer,
        // `ReleaseReason::Admin` has no allow row: one authority owns the
        // manual release and it is the curator's. The reason stays
        // readable on historical streams (the stream is append-only,
        // ADR 0002) — it is just never minted again, so the wildcard
        // below denies every pairing it appears in.
        (ReleaseReason::PolicyReEvaluation, ReleaseAuthorization::PolicyReEvaluation) => true,
        (ReleaseReason::Curator, ReleaseAuthorization::CuratorWaiver) => true,
        _ => false,
    }
}

#[test]
fn release_predicate_exhaustive_authority_matrix() {
    let mut cases = 0usize;
    let reasons = all_rejection_reasons();
    for reason in ALL_RELEASE_REASONS {
        for &authz in ALL_RELEASE_AUTHORIZATIONS {
            for &provenance in ALL_PROVENANCE_CLEARANCES {
                for &from in ALL_QUARANTINE_STATUSES {
                    // The rejection-reason axis is the whole
                    // `RejectionReason` vocabulary plus `None`. It is
                    // material only from `Rejected`; sweeping it from
                    // every state is what proves that — the predicate
                    // must answer identically for all eight from the
                    // other four states.
                    for rejection_reason in &reasons {
                        cases += 1;
                        let mut artifact = fresh_artifact();
                        artifact.quarantine_status = from;
                        artifact.rejection_reason = rejection_reason.clone();
                        let expected = expected_release_ok(
                            reason,
                            authz,
                            provenance,
                            from,
                            rejection_reason.as_ref(),
                        );
                        let actual = artifact.release(*reason, authz, provenance).is_ok();
                        assert_eq!(
                            actual, expected,
                            "Artifact::release({reason:?}, {authz:?}, {provenance:?}) from \
                             {from:?} with rejection_reason {rejection_reason:?}: expected \
                             Ok={expected} (ADR 0007 fail-closed release predicate), got \
                             Ok={actual}"
                        );
                        if expected {
                            assert_eq!(artifact.quarantine_status, QuarantineStatus::Released);
                            assert_eq!(
                                artifact.rejection_reason, None,
                                "a successful release must clear the rejection reason — a \
                                 Released artifact carrying one is an illegal state"
                            );
                        } else {
                            assert_eq!(
                                artifact.quarantine_status, from,
                                "denied release mutated status"
                            );
                            assert_eq!(
                                &artifact.rejection_reason, rejection_reason,
                                "denied release mutated the rejection reason"
                            );
                        }
                    }
                }
            }
        }
    }
    assert_eq!(
        cases,
        ALL_RELEASE_REASONS.len()
            * ALL_RELEASE_AUTHORIZATIONS.len()
            * ALL_PROVENANCE_CLEARANCES.len()
            * ALL_QUARANTINE_STATUSES.len()
            * reasons.len(),
        "the sweep must visit the whole finite argument space"
    );
}

// ---------------------------------------------------------------------------
// Invariant (c), direct form: the ADR 0041 `re_evaluate` exception's EXACT
// eligibility — exhaustive over rejection reason x provenance x curation x
// window-open.
// ---------------------------------------------------------------------------

/// Every rejection reason the vocabulary holds, plus `None`.
///
/// **Derived from the domain's own `ALL_KIND_SAMPLES`, not hand-written.**
/// The hand-written list this replaces was missing `Provenance` and
/// `Corruption` — the two reasons that most needed sweeping, since one is
/// the axis the curator's override reaches and the other is the axis it
/// permanently does not. A copy of a vocabulary is the copy a vocabulary
/// change forgets; `ALL_KIND_SAMPLES` is the single source both the
/// curation-queue discriminator and the `?reason=` filter already derive
/// from, and it carries a nil-id payload for the two payload-carrying
/// variants, which is all these matrices read.
fn all_rejection_reasons() -> Vec<Option<RejectionReason>> {
    std::iter::once(None)
        .chain(RejectionReason::ALL_KIND_SAMPLES.iter().cloned().map(Some))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReEvalOutcome {
    Denied,
    ReQuarantined,
    Released,
}

/// The exact ADR 0041 invariant #6 formula, independent of
/// `Artifact::re_evaluate`'s implementation.
fn expected_re_evaluate(
    reason: Option<&RejectionReason>,
    window_open: bool,
    provenance: ProvenanceClearance,
    curation: CurationClearance,
) -> ReEvalOutcome {
    if !is_scan_clearable(reason) {
        return ReEvalOutcome::Denied;
    }
    if window_open {
        return ReEvalOutcome::ReQuarantined;
    }
    let provenance_clears = matches!(
        provenance,
        ProvenanceClearance::NotRequired | ProvenanceClearance::Cleared
    );
    let curation_clears = matches!(curation, CurationClearance::Cleared);
    if provenance_clears && curation_clears {
        ReEvalOutcome::Released
    } else {
        ReEvalOutcome::Denied
    }
}

#[test]
fn re_evaluate_exhaustive_adr_0041_matrix() {
    let mut cases = 0usize;
    let reasons = all_rejection_reasons();
    for reason in &reasons {
        for &provenance in ALL_PROVENANCE_CLEARANCES {
            for &curation in &[CurationClearance::Cleared, CurationClearance::Blocked] {
                for &window_open in &[true, false] {
                    cases += 1;
                    let mut artifact = fresh_artifact();
                    artifact.quarantine_status = QuarantineStatus::Rejected;
                    artifact.rejection_reason = reason.clone();
                    artifact.quarantine_deadline = Some(if window_open {
                        future_deadline()
                    } else {
                        past_deadline()
                    });

                    let expected =
                        expected_re_evaluate(reason.as_ref(), window_open, provenance, curation);
                    let result = artifact.re_evaluate(base_time(), provenance, curation);

                    match expected {
                        ReEvalOutcome::Denied => {
                            assert!(
                                result.is_err(),
                                "re_evaluate(reason={reason:?}, window_open={window_open}, \
                                 provenance={provenance:?}, curation={curation:?}) expected \
                                 Denied (ADR 0041 invariant #6), got Ok"
                            );
                            assert_eq!(
                                artifact.quarantine_status,
                                QuarantineStatus::Rejected,
                                "denied re_evaluate mutated status"
                            );
                        }
                        ReEvalOutcome::ReQuarantined => {
                            assert!(result.is_ok());
                            assert_eq!(artifact.quarantine_status, QuarantineStatus::Quarantined);
                        }
                        ReEvalOutcome::Released => {
                            assert!(
                                result.is_ok(),
                                "re_evaluate(reason={reason:?}, window_open={window_open}, \
                                 provenance={provenance:?}, curation={curation:?}) expected \
                                 Released (the ADR 0041 exception), got Err"
                            );
                            assert_eq!(artifact.quarantine_status, QuarantineStatus::Released);
                        }
                    }
                }
            }
        }
    }
    // No written-down count: the census size is the vocabulary's own
    // length, so adding a `RejectionReason` widens this sweep without a
    // number to remember (the same rule
    // `all_release_authorizations_lists_every_variant` states).
    assert_eq!(
        cases,
        reasons.len() * ALL_PROVENANCE_CLEARANCES.len() * 2 * 2
    );
}

// ---------------------------------------------------------------------------
// Only the MANUAL pairing reaches a `Rejected` artifact through
// `release()` — pinned as a standalone regression so the exhaustive
// matrix's intent is legible on its own even if someone only reads this
// one test.
// ---------------------------------------------------------------------------

/// Every unattended `(reason, authz)` pairing is refused from `Rejected`,
/// on an axis the curator's override **does** reach.
///
/// The axis matters: a reason-less fixture would pass this sweep for the
/// wrong reason — refused by the axis conjunct rather than by the pairing
/// one — so a leak of the widening to the timer sweep or the policy pass
/// would go unnoticed. Driving it from an overridable axis is what makes
/// the pairing conjunct the only thing standing in the way.
#[test]
fn release_from_rejected_admits_the_manual_pairing_alone() {
    let overridable: Vec<RejectionReason> = RejectionReason::ALL_KIND_SAMPLES
        .iter()
        .filter(|r| is_curator_overridable(Some(r)))
        .cloned()
        .collect();
    assert!(
        !overridable.is_empty(),
        "fixture guard: the override must reach at least one axis, or this sweep is \
         vacuous"
    );
    for rejection_reason in &overridable {
        for reason in ALL_RELEASE_REASONS {
            for &authz in ALL_RELEASE_AUTHORIZATIONS {
                for &provenance in ALL_PROVENANCE_CLEARANCES {
                    let manual = matches!(
                        (reason, authz),
                        (ReleaseReason::Curator, ReleaseAuthorization::CuratorWaiver)
                    );
                    let mut artifact = fresh_artifact();
                    artifact.quarantine_status = QuarantineStatus::Rejected;
                    artifact.rejection_reason = Some(rejection_reason.clone());
                    let ok = artifact.release(*reason, authz, provenance).is_ok();
                    assert_eq!(
                        ok, manual,
                        "release({reason:?}, {authz:?}, {provenance:?}) from \
                         Rejected({rejection_reason:?}) returned Ok={ok}; only the manual \
                         (Curator, CuratorWaiver) pairing may override a recorded \
                         rejection — the timer sweep and the policy pass run unattended, \
                         and their exit from a rejection is re_evaluate's ADR 0041 \
                         exception"
                    );
                    assert_eq!(
                        artifact.quarantine_status,
                        if manual {
                            QuarantineStatus::Released
                        } else {
                            QuarantineStatus::Rejected
                        }
                    );
                }
            }
        }
    }
}

/// And the corruption tombstone is refused even for the manual pairing,
/// whatever else is favourable — the one axis the override never reaches.
#[test]
fn release_from_rejected_never_reaches_a_corruption_tombstone() {
    for &provenance in ALL_PROVENANCE_CLEARANCES {
        let mut artifact = fresh_artifact();
        artifact.quarantine_status = QuarantineStatus::Rejected;
        artifact.rejection_reason = Some(RejectionReason::Corruption);
        let result = artifact.release(
            ReleaseReason::Curator,
            ReleaseAuthorization::CuratorWaiver,
            provenance,
        );
        assert!(
            result.is_err(),
            "a curator waive with provenance {provenance:?} overrode a corruption \
             tombstone — the bytes hort holds are not the bytes their hash names, so \
             the curator's comparison confirms nothing and the read fails verification \
             regardless (ADR 0003)"
        );
        assert_eq!(artifact.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(
            artifact.rejection_reason,
            Some(RejectionReason::Corruption),
            "a refused override must leave the tombstone's reason in place"
        );
    }
}
