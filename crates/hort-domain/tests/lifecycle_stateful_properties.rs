//! Stateful property-based suite for the artifact quarantine lifecycle
//! (backlog 091, #135 item 3) — DB-free, network-free, pure `hort-domain`.
//!
//! Random interleavings of ingest / verify (scan, provenance) / sweep-tick
//! (window elapse, release, re-evaluate) actions are replayed against a
//! real [`Artifact`], cross-checked against the declared
//! [`quarantine_transitions::QUARANTINE_TRANSITIONS`] table (backlog 090)
//! as the reference model for transition *legality*, and against four
//! invariants the table alone cannot express (it only encodes per-event
//! source-state legality, not the release-authorization matrix, the
//! re-evaluation eligibility formula, or any liveness/idempotency
//! property):
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
//!     behaviour (ADR 0041 invariant #6(a)), not a stranding bug.
//! (b) **Five-authority release predicate (ADR 0007)** — see
//!     `release_predicate_exhaustive_authority_matrix` below: an exhaustive
//!     (not sampled) sweep of every `(ReleaseReason, ReleaseAuthorization,
//!     ProvenanceClearance, QuarantineStatus)` tuple against the real
//!     `Artifact::release`, asserting `Ok` iff the tuple is one of the five
//!     documented allow-rows with the provenance AND-precondition satisfied
//!     on the `Timer` arm. Exhaustive enumeration is used here (not
//!     `proptest` sampling) because the input space is small (4×5×3×5=300)
//!     and finite — exhaustive coverage is strictly stronger than a random
//!     sample of it; the *stateful*, unbounded-length-sequence invariants
//!     (a), (c), (d) are where `proptest`'s random search earns its keep.
//! (c) **`Rejected -> Released` only through the ADR 0041 `re_evaluate`
//!     exception, with its EXACT eligibility** — checked live at every step
//!     of the random walk (never a blanket "no Rejected->Released" ban,
//!     which would be wrong: the exception is real) via
//!     `re_evaluate_exhaustive_adr_0041_matrix` (exhaustive, same rationale
//!     as (b)) plus a per-step assertion in the stateful walk that any
//!     observed `Rejected -> Released` transition names `Action::ReEvaluate`
//!     and satisfies invariant #6(a)(b)(c) at the moment it fired.
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
//! sequence length `1..=24`) and the two exhaustive matrices (300 + 72
//! tuples) keep the whole module well under the ~60s local budget (measured
//! well under 1s: these are pure in-memory `hort-domain` calls, no I/O).
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
    is_scan_clearable, Artifact, CurationClearance, ProvenanceClearance, QuarantineStatus,
    ReleaseAuthorization,
};
use hort_domain::entities::quarantine_transitions::{self, QuarantineEvent};
use hort_domain::entities::scan_policy::{ProvenanceMode, SeverityThreshold};
use hort_domain::events::{PolicyViolation, RejectionReason, ReleaseReason};
use hort_domain::policy::ScanOutcome;
use hort_domain::ports::provenance::{ProvenanceRejectReason, ProvenanceVerdict, SignerIdentity};
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
    is_referenced_descendant: bool,
    curation_blocked: bool,
    provenance_verified: bool,
}

impl Aux {
    fn initial() -> Self {
        Aux {
            provenance_mode: ProvenanceMode::Off,
            window_open: false,
            is_referenced_descendant: false,
            curation_blocked: false,
            provenance_verified: false,
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
    CascadeClearance,
    ElapseWindow,
    SetDescendant(bool),
    SetCurationBlocked(bool),
    SetProvenanceMode(ProvenanceMode),
    ReleaseAdmin,
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
        Just(Action::CascadeClearance),
        Just(Action::ElapseWindow),
        any::<bool>().prop_map(Action::SetDescendant),
        any::<bool>().prop_map(Action::SetCurationBlocked),
        provenance_mode_strategy().prop_map(Action::SetProvenanceMode),
        Just(Action::ReleaseAdmin),
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
/// actions (`ElapseWindow`, `SetDescendant`, `SetCurationBlocked`,
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
        Action::ProvenanceVerify | Action::ProvenanceReject | Action::ProvenanceNoAttestation => {
            Some(QuarantineEvent::CompleteProvenance)
        }
        Action::CascadeClearance => Some(QuarantineEvent::CascadeProvenanceClearance),
        Action::ReleaseAdmin | Action::ReleasePolicyReEval | Action::ReleaseTimer { .. } => {
            Some(QuarantineEvent::ReleaseGeneral)
        }
        Action::ReleaseCuratorWaiver => Some(QuarantineEvent::ReleaseCuratorWaiver),
        Action::ReEvaluate => Some(QuarantineEvent::ReEvaluate),
        Action::ElapseWindow
        | Action::SetDescendant(_)
        | Action::SetCurationBlocked(_)
        | Action::SetProvenanceMode(_) => None,
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
        Action::RejectScan => artifact.reject_from_scan("scan finding".into()).is_ok(),
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
            .complete_provenance(
                ProvenanceVerdict::verified(fixed_signer(), None),
                aux.provenance_mode,
                "cosign",
                aux.window_open,
                aux.is_referenced_descendant,
            )
            .is_ok(),
        Action::ProvenanceReject => artifact
            .complete_provenance(
                ProvenanceVerdict::rejected(ProvenanceRejectReason::UntrustedIdentity),
                aux.provenance_mode,
                "cosign",
                aux.window_open,
                aux.is_referenced_descendant,
            )
            .is_ok(),
        Action::ProvenanceNoAttestation => artifact
            .complete_provenance(
                ProvenanceVerdict::no_attestation(),
                aux.provenance_mode,
                "cosign",
                aux.window_open,
                aux.is_referenced_descendant,
            )
            .is_ok(),
        Action::CascadeClearance => artifact
            .cascade_provenance_clearance(fixed_hash(), fixed_signer(), None, "cosign")
            .is_ok(),
        Action::ReleaseAdmin => artifact
            .release(
                ReleaseReason::Admin,
                ReleaseAuthorization::AdminOverride,
                aux.provenance_clearance(),
            )
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
        Action::ElapseWindow
        | Action::SetDescendant(_)
        | Action::SetCurationBlocked(_)
        | Action::SetProvenanceMode(_) => unreachable!("pure aux actions never call perform"),
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
            Action::ElapseWindow
                | Action::SetDescendant(_)
                | Action::SetCurationBlocked(_)
                | Action::SetProvenanceMode(_)
        ) {
            match action {
                Action::ElapseWindow => {
                    aux.window_open = false;
                    if artifact.quarantine_deadline.is_some() {
                        artifact.quarantine_deadline = Some(past_deadline());
                    }
                }
                Action::SetDescendant(b) => aux.is_referenced_descendant = b,
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

        // --- invariant (c): Rejected -> Released only via the exact ADR 0041 exception ---
        if before_status == QuarantineStatus::Rejected && after_status == QuarantineStatus::Released
        {
            assert!(
                matches!(action, Action::ReEvaluate),
                "artifact moved Rejected -> Released via {action:?}, not re_evaluate \
                 (ADR 0041 invariant #6 violated: no other path may ever do this)"
            );
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

        // --- update aux from the REAL outcome ---
        if ok {
            match action {
                Action::Ingest => {
                    aux.window_open = true;
                    artifact.quarantine_deadline = Some(future_deadline());
                }
                Action::ProvenanceVerify => aux.provenance_verified = true,
                Action::ProvenanceReject => aux.provenance_verified = false,
                Action::ProvenanceNoAttestation if after_status == QuarantineStatus::Rejected => {
                    aux.provenance_verified = false;
                }
                Action::CascadeClearance => aux.provenance_verified = true,
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
                        aux.provenance_mode,
                        "cosign",
                        aux.window_open,
                        aux.is_referenced_descendant,
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
                            aux.provenance_mode,
                            "cosign",
                            aux.window_open,
                            aux.is_referenced_descendant,
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
// Invariant (b): the five-authority release predicate (ADR 0007) —
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
    ReleaseAuthorization::ScanWaived,
    ReleaseAuthorization::AdminOverride,
    ReleaseAuthorization::PolicyReEvaluation,
    ReleaseAuthorization::CuratorWaiver,
];

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

/// The exact five-row allow predicate documented in ADR 0007 / this
/// module's header, independent of `Artifact::release`'s implementation —
/// the oracle the exhaustive sweep checks the real method against.
fn expected_release_ok(
    reason: &ReleaseReason,
    authz: ReleaseAuthorization,
    provenance: ProvenanceClearance,
    from: QuarantineStatus,
) -> bool {
    let source_state_ok = match (reason, authz) {
        (ReleaseReason::Curator, ReleaseAuthorization::CuratorWaiver) => {
            from == QuarantineStatus::Quarantined
        }
        _ => matches!(
            from,
            QuarantineStatus::Quarantined | QuarantineStatus::ScanIndeterminate
        ),
    };
    if !source_state_ok {
        return false;
    }
    let provenance_clears_timer = matches!(
        provenance,
        ProvenanceClearance::NotRequired | ProvenanceClearance::Cleared
    );
    match (reason.clone(), authz) {
        (ReleaseReason::Timer, ReleaseAuthorization::ScanSucceeded)
        | (ReleaseReason::Timer, ReleaseAuthorization::ScanWaived) => provenance_clears_timer,
        (ReleaseReason::Admin, ReleaseAuthorization::AdminOverride) => true,
        (ReleaseReason::PolicyReEvaluation, ReleaseAuthorization::PolicyReEvaluation) => true,
        (ReleaseReason::Curator, ReleaseAuthorization::CuratorWaiver) => true,
        _ => false,
    }
}

#[test]
fn release_predicate_exhaustive_authority_matrix() {
    let mut cases = 0usize;
    for reason in ALL_RELEASE_REASONS {
        for &authz in ALL_RELEASE_AUTHORIZATIONS {
            for &provenance in ALL_PROVENANCE_CLEARANCES {
                for &from in ALL_QUARANTINE_STATUSES {
                    cases += 1;
                    let mut artifact = fresh_artifact();
                    artifact.quarantine_status = from;
                    let expected = expected_release_ok(reason, authz, provenance, from);
                    let actual = artifact.release(reason.clone(), authz, provenance).is_ok();
                    assert_eq!(
                        actual, expected,
                        "Artifact::release({reason:?}, {authz:?}, {provenance:?}) from \
                         {from:?}: expected Ok={expected} (ADR 0007 five-authority \
                         predicate), got Ok={actual}"
                    );
                    if expected {
                        assert_eq!(artifact.quarantine_status, QuarantineStatus::Released);
                    } else {
                        assert_eq!(
                            artifact.quarantine_status, from,
                            "denied release mutated status"
                        );
                    }
                }
            }
        }
    }
    assert_eq!(cases, 4 * 5 * 3 * 5);
}

// ---------------------------------------------------------------------------
// Invariant (c), direct form: the ADR 0041 `re_evaluate` exception's EXACT
// eligibility — exhaustive over rejection reason x provenance x curation x
// window-open.
// ---------------------------------------------------------------------------

fn all_rejection_reasons() -> Vec<Option<RejectionReason>> {
    vec![
        None,
        Some(RejectionReason::Scanner),
        Some(RejectionReason::Admin),
        Some(RejectionReason::CurationRetroactive { rule_id: rule_id() }),
        Some(RejectionReason::ScanPolicyRetroactive),
        Some(RejectionReason::Curator {
            curator_id: curator_id(),
        }),
    ]
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
    for reason in all_rejection_reasons() {
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
    assert_eq!(cases, 6 * 3 * 2 * 2);
}

// ---------------------------------------------------------------------------
// A never-Rejected-to-Released path exists in `release()` — pinned as a
// standalone regression so the exhaustive matrix's intent is legible on
// its own even if someone only reads this one test.
// ---------------------------------------------------------------------------

#[test]
fn release_never_accepts_rejected_source_state() {
    for reason in ALL_RELEASE_REASONS {
        for &authz in ALL_RELEASE_AUTHORIZATIONS {
            for &provenance in ALL_PROVENANCE_CLEARANCES {
                let mut artifact = fresh_artifact();
                artifact.quarantine_status = QuarantineStatus::Rejected;
                let result = artifact.release(reason.clone(), authz, provenance);
                assert!(
                    result.is_err(),
                    "release({reason:?}, {authz:?}, {provenance:?}) accepted a Rejected \
                     source state — the ONLY sanctioned Rejected -> Released path is \
                     re_evaluate's ADR 0041 exception"
                );
                assert_eq!(artifact.quarantine_status, QuarantineStatus::Rejected);
            }
        }
    }
}
