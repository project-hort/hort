//! Declared transition table for the [`QuarantineStatus`] lifecycle
//! (backlog 090, #135 item 2).
//!
//! Representation change only. The guard methods on [`Artifact`](super::artifact::Artifact)
//! already enforce every one of these transitions by hand-written `match`
//! statements; this module lifts the *state-guard* portion of that logic
//! (which source states a given event accepts) into one declared `const`
//! table so the accept/reject set has a single, greppable source of truth
//! instead of living only inside eleven separate method bodies. The guard
//! methods still own everything a state check cannot express — the extra
//! predicates a transition also requires (an outcome enum, a window
//! comparison, a rejection-reason eligibility check, …) — documented per
//! row as `required_triggers`, enforced exactly as before.
//!
//! [`classify`] is the compile-enforced source of truth: an exhaustive
//! `match` (no wildcard arm) over every `(QuarantineEvent, QuarantineStatus)`
//! cell. Adding a variant to either enum fails to compile here until the
//! new cells are consciously classified — the same pattern
//! `retention_permitted` uses in `crates/hort-app/tests/retention_registration_guard.rs`.
//! [`QUARANTINE_TRANSITIONS`] is hand-authored data cross-checked against
//! [`classify`] by a test, so the two cannot silently drift.
//!
//! [`render_lifecycle_dot`] renders the same table as a Graphviz DOT graph
//! (deterministic — the table's declaration order — so the emitted artifact
//! at `docs/architecture/artifact-lifecycle.dot` is diff-stable). Self-loop
//! cells (a `to` set containing only the `from` state — e.g. a clean scan
//! recorded while `Quarantined`) carry no lifecycle-visible transition and
//! are omitted from the graph; only edges where `to != from` are drawn.

use super::artifact::QuarantineStatus;

// ---------------------------------------------------------------------------
// QuarantineEvent
// ---------------------------------------------------------------------------

/// One entry point into the [`QuarantineStatus`] state machine — one
/// variant per guard method on [`Artifact`](super::artifact::Artifact),
/// except [`Self::ReleaseCuratorWaiver`] / [`Self::ReleaseGeneral`], which
/// split `Artifact::release`'s single method into its two source-state
/// guards (the curator-waiver pairing is narrower than every other
/// `(reason, authz)` pairing — see `Artifact::release`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuarantineEvent {
    /// `Artifact::quarantine`.
    Quarantine,
    /// `Artifact::record_clean_scan`.
    RecordCleanScan,
    /// `Artifact::reject_from_scan`.
    RejectFromScan,
    /// `Artifact::reject_from_retroactive_curation`.
    RejectFromRetroactiveCuration,
    /// `Artifact::reject_from_scan_policy_retroactive`.
    RejectFromScanPolicyRetroactive,
    /// `Artifact::block_by_curator`.
    BlockByCurator,
    /// `Artifact::tombstone_from_corruption`.
    TombstoneFromCorruption,
    /// `Artifact::release`, the `(ReleaseReason::Curator, ReleaseAuthorization::CuratorWaiver)` pairing.
    ReleaseCuratorWaiver,
    /// `Artifact::release`, every other `(reason, authz)` pairing.
    ReleaseGeneral,
    /// `Artifact::cascade_provenance_clearance`.
    CascadeProvenanceClearance,
    /// `Artifact::fail_scan_indeterminate`.
    FailScanIndeterminate,
    /// `Artifact::re_evaluate`.
    ReEvaluate,
    /// `Artifact::complete_provenance`. **Not source-state-gated** — the
    /// method carries no `match self.quarantine_status` guard at all (its
    /// caller, the provenance orchestrator, only ever invokes it against a
    /// held artifact, but the domain method itself is total over every
    /// state). Included here so the DOT artifact and the dependency
    /// registry can represent its real `Rejected` edges; `classify` marks
    /// every state `Allowed` for it, and no guard method consults this
    /// table for it — there is no state check to replace.
    CompleteProvenance,
}

impl QuarantineEvent {
    /// All variants, in declaration order — the order [`QUARANTINE_TRANSITIONS`]
    /// follows and [`render_lifecycle_dot`] iterates, so the emitted
    /// artifact stays diff-stable across runs.
    pub const ALL: &'static [QuarantineEvent] = &[
        QuarantineEvent::Quarantine,
        QuarantineEvent::RecordCleanScan,
        QuarantineEvent::RejectFromScan,
        QuarantineEvent::RejectFromRetroactiveCuration,
        QuarantineEvent::RejectFromScanPolicyRetroactive,
        QuarantineEvent::BlockByCurator,
        QuarantineEvent::TombstoneFromCorruption,
        QuarantineEvent::ReleaseCuratorWaiver,
        QuarantineEvent::ReleaseGeneral,
        QuarantineEvent::CascadeProvenanceClearance,
        QuarantineEvent::FailScanIndeterminate,
        QuarantineEvent::ReEvaluate,
        QuarantineEvent::CompleteProvenance,
    ];

    /// Stable, human-readable label — the DOT edge label and the name used
    /// in guard failure messages. Mirrors the method name it represents.
    pub fn label(self) -> &'static str {
        match self {
            Self::Quarantine => "quarantine",
            Self::RecordCleanScan => "record_clean_scan",
            Self::RejectFromScan => "reject_from_scan",
            Self::RejectFromRetroactiveCuration => "reject_from_retroactive_curation",
            Self::RejectFromScanPolicyRetroactive => "reject_from_scan_policy_retroactive",
            Self::BlockByCurator => "block_by_curator",
            Self::TombstoneFromCorruption => "tombstone_from_corruption",
            Self::ReleaseCuratorWaiver => "release (curator waiver)",
            Self::ReleaseGeneral => "release (general)",
            Self::CascadeProvenanceClearance => "cascade_provenance_clearance",
            Self::FailScanIndeterminate => "fail_scan_indeterminate",
            Self::ReEvaluate => "re_evaluate",
            Self::CompleteProvenance => "complete_provenance",
        }
    }
}

// ---------------------------------------------------------------------------
// Cell classification — the compile-enforced source of truth
// ---------------------------------------------------------------------------

/// The classification of one `(event, state)` cell: either the event
/// refuses `state` outright, or it accepts it and reaches one or more of
/// the listed target states (more than one when an additional runtime
/// predicate — documented as the row's `required_triggers` — decides
/// between them; e.g. `ReEvaluate` from `Rejected` reaches `Quarantined`
/// **or** `Released` depending on whether the observation window has
/// elapsed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cell {
    Forbidden,
    Allowed(&'static [QuarantineStatus]),
}

/// Classify every `(event, state)` cell. **Exhaustive, no wildcard arm** —
/// `QuarantineStatus` and `QuarantineEvent` are both plain (non-`#[non_exhaustive]`)
/// enums, so adding a variant to either fails this function to COMPILE
/// until every new cell is consciously classified. This is the structural
/// guard: a state × event combination cannot silently default to
/// "forbidden" (a fail-open representation bug) or "allowed" (a fail-closed
/// invariant violation) — it must be written down here.
///
/// [`QUARANTINE_TRANSITIONS`] is cross-checked against this function by
/// `quarantine_transitions_table_matches_classification` (below) so the
/// hand-authored data table and this compile-enforced match cannot drift.
#[allow(clippy::match_same_arms)]
pub fn classify(event: QuarantineEvent, state: QuarantineStatus) -> Cell {
    use Cell::{Allowed, Forbidden};
    use QuarantineStatus::{None as NoneSt, Quarantined, Rejected, Released, ScanIndeterminate};

    match event {
        QuarantineEvent::Quarantine => match state {
            NoneSt => Allowed(&[Quarantined]),
            Quarantined | Released | Rejected | ScanIndeterminate => Forbidden,
        },
        QuarantineEvent::RecordCleanScan => match state {
            NoneSt => Allowed(&[NoneSt]),
            Quarantined => Allowed(&[Quarantined]),
            Released | Rejected | ScanIndeterminate => Forbidden,
        },
        QuarantineEvent::RejectFromScan => match state {
            NoneSt => Allowed(&[Rejected]),
            Quarantined => Allowed(&[Rejected]),
            Released | Rejected | ScanIndeterminate => Forbidden,
        },
        QuarantineEvent::RejectFromRetroactiveCuration => match state {
            Quarantined => Allowed(&[Rejected]),
            Released => Allowed(&[Rejected]),
            NoneSt | Rejected | ScanIndeterminate => Forbidden,
        },
        QuarantineEvent::RejectFromScanPolicyRetroactive => match state {
            Quarantined => Allowed(&[Quarantined, Rejected]),
            Released => Allowed(&[Released, Rejected]),
            NoneSt | Rejected | ScanIndeterminate => Forbidden,
        },
        QuarantineEvent::BlockByCurator => match state {
            NoneSt => Allowed(&[Rejected]),
            Quarantined => Allowed(&[Rejected]),
            Released => Allowed(&[Rejected]),
            Rejected | ScanIndeterminate => Forbidden,
        },
        QuarantineEvent::TombstoneFromCorruption => match state {
            NoneSt => Allowed(&[Rejected]),
            Quarantined => Allowed(&[Rejected]),
            Released => Allowed(&[Rejected]),
            ScanIndeterminate => Allowed(&[Rejected]),
            Rejected => Forbidden,
        },
        QuarantineEvent::ReleaseCuratorWaiver => match state {
            Quarantined => Allowed(&[Released]),
            NoneSt | Released | Rejected | ScanIndeterminate => Forbidden,
        },
        QuarantineEvent::ReleaseGeneral => match state {
            Quarantined => Allowed(&[Released]),
            ScanIndeterminate => Allowed(&[Released]),
            NoneSt | Released | Rejected => Forbidden,
        },
        QuarantineEvent::CascadeProvenanceClearance => match state {
            Quarantined => Allowed(&[Quarantined]),
            NoneSt | Released | Rejected | ScanIndeterminate => Forbidden,
        },
        QuarantineEvent::FailScanIndeterminate => match state {
            NoneSt => Allowed(&[ScanIndeterminate]),
            Quarantined => Allowed(&[ScanIndeterminate]),
            Released | Rejected | ScanIndeterminate => Forbidden,
        },
        QuarantineEvent::ReEvaluate => match state {
            Rejected => Allowed(&[Quarantined, Released]),
            NoneSt | Quarantined | Released | ScanIndeterminate => Forbidden,
        },
        // Unguarded: every state is a valid entry point (see the variant
        // doc). Verified / VerifyIfPresent / Off / window-open / descendant
        // arms self-loop; the Rejected outcome and the unsigned-at-expiry
        // arm transition to Rejected — both reachable from any state.
        QuarantineEvent::CompleteProvenance => match state {
            NoneSt => Allowed(&[NoneSt, Rejected]),
            Quarantined => Allowed(&[Quarantined, Rejected]),
            Released => Allowed(&[Released, Rejected]),
            Rejected => Allowed(&[Rejected]),
            ScanIndeterminate => Allowed(&[ScanIndeterminate, Rejected]),
        },
    }
}

// ---------------------------------------------------------------------------
// QUARANTINE_TRANSITIONS — the declared data table
// ---------------------------------------------------------------------------

/// One row of the declared transition table: `state × event → next +
/// required triggers`.
#[derive(Debug, Clone, Copy)]
pub struct QuarantineTransitionRow {
    pub event: QuarantineEvent,
    pub from: QuarantineStatus,
    /// Reachable target state(s). More than one entry means an additional
    /// runtime predicate — see `required_triggers` — decides which; never
    /// empty (an unreachable-but-present row is not represented — see
    /// [`classify`]'s `Forbidden` cells for that).
    pub to: &'static [QuarantineStatus],
    /// The predicates, beyond the source-state check, that the guard
    /// method still enforces in code — documentation only; the table does
    /// not execute these, the method bodies do (unchanged).
    pub required_triggers: &'static [&'static str],
}

/// The declared table. One row per `Allowed` cell in [`classify`] — see
/// `quarantine_transitions_table_matches_classification` for the
/// cross-check that keeps the two from drifting.
pub const QUARANTINE_TRANSITIONS: &[QuarantineTransitionRow] = &[
    QuarantineTransitionRow {
        event: QuarantineEvent::Quarantine,
        from: QuarantineStatus::None,
        to: &[QuarantineStatus::Quarantined],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::RecordCleanScan,
        from: QuarantineStatus::None,
        to: &[QuarantineStatus::None],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::RecordCleanScan,
        from: QuarantineStatus::Quarantined,
        to: &[QuarantineStatus::Quarantined],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::RejectFromScan,
        from: QuarantineStatus::None,
        to: &[QuarantineStatus::Rejected],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::RejectFromScan,
        from: QuarantineStatus::Quarantined,
        to: &[QuarantineStatus::Rejected],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::RejectFromRetroactiveCuration,
        from: QuarantineStatus::Quarantined,
        to: &[QuarantineStatus::Rejected],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::RejectFromRetroactiveCuration,
        from: QuarantineStatus::Released,
        to: &[QuarantineStatus::Rejected],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::RejectFromScanPolicyRetroactive,
        from: QuarantineStatus::Quarantined,
        to: &[QuarantineStatus::Quarantined, QuarantineStatus::Rejected],
        required_triggers: &[
            "ScanOutcome::Clean | ScanOutcome::FindingsRecorded(_) -> no-op \
             (stays Quarantined, no event)",
            "ScanOutcome::Reject(_) -> Rejected",
        ],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::RejectFromScanPolicyRetroactive,
        from: QuarantineStatus::Released,
        to: &[QuarantineStatus::Released, QuarantineStatus::Rejected],
        required_triggers: &[
            "ScanOutcome::Clean | ScanOutcome::FindingsRecorded(_) -> no-op \
             (stays Released, no event)",
            "ScanOutcome::Reject(_) -> Rejected",
        ],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::BlockByCurator,
        from: QuarantineStatus::None,
        to: &[QuarantineStatus::Rejected],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::BlockByCurator,
        from: QuarantineStatus::Quarantined,
        to: &[QuarantineStatus::Rejected],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::BlockByCurator,
        from: QuarantineStatus::Released,
        to: &[QuarantineStatus::Rejected],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::TombstoneFromCorruption,
        from: QuarantineStatus::None,
        to: &[QuarantineStatus::Rejected],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::TombstoneFromCorruption,
        from: QuarantineStatus::Quarantined,
        to: &[QuarantineStatus::Rejected],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::TombstoneFromCorruption,
        from: QuarantineStatus::Released,
        to: &[QuarantineStatus::Rejected],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::TombstoneFromCorruption,
        from: QuarantineStatus::ScanIndeterminate,
        to: &[QuarantineStatus::Rejected],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::ReleaseCuratorWaiver,
        from: QuarantineStatus::Quarantined,
        to: &[QuarantineStatus::Released],
        required_triggers: &["reason == Curator && authz == CuratorWaiver"],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::ReleaseGeneral,
        from: QuarantineStatus::Quarantined,
        to: &[QuarantineStatus::Released],
        required_triggers: &[
            "authorized only for (Timer, ScanSucceeded|ScanWaived|ScanRecorded) with \
             provenance cleared/not-required, (Admin, AdminOverride), or \
             (PolicyReEvaluation, PolicyReEvaluation) — every other (reason, authz) \
             pair is denied at the authorization step, independent of source state",
        ],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::ReleaseGeneral,
        from: QuarantineStatus::ScanIndeterminate,
        to: &[QuarantineStatus::Released],
        required_triggers: &[
            "authorized only for (Timer, ScanSucceeded|ScanWaived|ScanRecorded) with \
             provenance cleared/not-required, (Admin, AdminOverride), or \
             (PolicyReEvaluation, PolicyReEvaluation) — every other (reason, authz) \
             pair is denied at the authorization step, independent of source state",
        ],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::CascadeProvenanceClearance,
        from: QuarantineStatus::Quarantined,
        to: &[QuarantineStatus::Quarantined],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::FailScanIndeterminate,
        from: QuarantineStatus::None,
        to: &[QuarantineStatus::ScanIndeterminate],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::FailScanIndeterminate,
        from: QuarantineStatus::Quarantined,
        to: &[QuarantineStatus::ScanIndeterminate],
        required_triggers: &[],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::ReEvaluate,
        from: QuarantineStatus::Rejected,
        to: &[QuarantineStatus::Quarantined, QuarantineStatus::Released],
        required_triggers: &[
            "rejection_reason must be scan-clearable (Scanner | ScanPolicyRetroactive) \
             — ADR 0041 invariant #6(a), else Err without mutating",
            "quarantine_deadline > now -> re-quarantine (Quarantined), window preserved",
            "quarantine_deadline <= now -> Released only if provenance in \
             {NotRequired, Cleared} AND curation == Cleared (ADR 0041 invariant #6(b)(c))",
        ],
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::CompleteProvenance,
        from: QuarantineStatus::None,
        to: &[QuarantineStatus::None, QuarantineStatus::Rejected],
        required_triggers: COMPLETE_PROVENANCE_TRIGGERS,
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::CompleteProvenance,
        from: QuarantineStatus::Quarantined,
        to: &[QuarantineStatus::Quarantined, QuarantineStatus::Rejected],
        required_triggers: COMPLETE_PROVENANCE_TRIGGERS,
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::CompleteProvenance,
        from: QuarantineStatus::Released,
        to: &[QuarantineStatus::Released, QuarantineStatus::Rejected],
        required_triggers: COMPLETE_PROVENANCE_TRIGGERS,
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::CompleteProvenance,
        from: QuarantineStatus::Rejected,
        to: &[QuarantineStatus::Rejected],
        required_triggers: COMPLETE_PROVENANCE_TRIGGERS,
    },
    QuarantineTransitionRow {
        event: QuarantineEvent::CompleteProvenance,
        from: QuarantineStatus::ScanIndeterminate,
        to: &[
            QuarantineStatus::ScanIndeterminate,
            QuarantineStatus::Rejected,
        ],
        required_triggers: COMPLETE_PROVENANCE_TRIGGERS,
    },
];

const COMPLETE_PROVENANCE_TRIGGERS: &[&str] = &[
    "ProvenanceOutcome::Verified -> no-op (status unchanged, success record only)",
    "ProvenanceOutcome::Rejected -> Rejected",
    "ProvenanceOutcome::NoAttestation, mode=Required, window_open||is_referenced_descendant -> no-op (held)",
    "ProvenanceOutcome::NoAttestation, mode=Required, !window_open && !is_referenced_descendant -> Rejected (Unsigned)",
    "ProvenanceOutcome::NoAttestation, mode=VerifyIfPresent|Off -> no-op",
];

// ---------------------------------------------------------------------------
// Lookup — what the refactored guard methods consult
// ---------------------------------------------------------------------------

/// Look up the reachable target state set for `(event, from)`. `None` means
/// the event refuses `from` outright — the guard method's existing
/// `Err(...)` branch. `Some(targets)` means the state check passes; the
/// method's own logic (unchanged) still decides which member of `targets`
/// is reached and appends the matching event, if any.
pub fn allowed_targets(
    event: QuarantineEvent,
    from: QuarantineStatus,
) -> Option<&'static [QuarantineStatus]> {
    QUARANTINE_TRANSITIONS
        .iter()
        .find(|row| row.event == event && row.from == from)
        .map(|row| row.to)
}

// ---------------------------------------------------------------------------
// DOT rendering (backlog 090 item 4)
// ---------------------------------------------------------------------------

/// Render the table as a Graphviz DOT digraph. Deterministic: iterates
/// [`QuarantineEvent::ALL`] then [`QuarantineStatus`] in a fixed order, so
/// two runs over the same table produce byte-identical output — the
/// generated-artifact drift guard (`crates/hort-domain/tests/lifecycle_dot_artifact.rs`)
/// depends on this.
///
/// Self-loop-only edges (`to == [from]`, no lifecycle-visible transition —
/// e.g. a clean scan recorded while `Quarantined`) are omitted: the graph
/// shows state CHANGES, not every guard method that can be called without
/// effect. An event with both a self-loop and a real transition in its
/// `to` set (e.g. `RejectFromScanPolicyRetroactive`) draws only the real
/// edge.
pub fn render_lifecycle_dot() -> String {
    let mut out = String::new();
    out.push_str(
        "// AUTO-GENERATED — do not hand-edit.\n\
         //\n\
         // Rendered by `hort_domain::entities::quarantine_transitions::render_lifecycle_dot`\n\
         // from the declared `QUARANTINE_TRANSITIONS` table (backlog 090, #135 item 2).\n\
         // Regenerate after any table change; the drift guard\n\
         // `crates/hort-domain/tests/lifecycle_dot_artifact.rs` fails CI if this file\n\
         // and the table disagree. Self-loop-only transitions (a guard method that\n\
         // accepts a state but leaves it unchanged) are omitted — see the render\n\
         // function's doc comment.\n",
    );
    out.push_str("digraph ArtifactQuarantineLifecycle {\n");
    out.push_str("    rankdir=LR;\n");
    out.push_str("    node [shape=box];\n");
    for state in ALL_STATUSES {
        out.push_str(&format!("    \"{}\";\n", state));
    }
    for &event in QuarantineEvent::ALL {
        for &from in ALL_STATUSES {
            let Cell::Allowed(targets) = classify(event, from) else {
                continue;
            };
            for &to in targets {
                if to == from {
                    continue;
                }
                out.push_str(&format!(
                    "    \"{from}\" -> \"{to}\" [label=\"{}\"];\n",
                    event.label()
                ));
            }
        }
    }
    out.push_str("}\n");
    out
}

const ALL_STATUSES: &[QuarantineStatus] = &[
    QuarantineStatus::None,
    QuarantineStatus::Quarantined,
    QuarantineStatus::Released,
    QuarantineStatus::Rejected,
    QuarantineStatus::ScanIndeterminate,
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-check: [`QUARANTINE_TRANSITIONS`] and the compile-enforced
    /// [`classify`] match must agree on every `(event, state)` cell. A
    /// drift here means the hand-authored table and the exhaustive match
    /// disagree — exactly the STOP-and-report condition the directive
    /// names (a table found to diverge from the guard it represents).
    #[test]
    fn table_matches_classification_exhaustively() {
        for &event in QuarantineEvent::ALL {
            for &state in ALL_STATUSES {
                let classified = classify(event, state);
                let from_table = allowed_targets(event, state);
                match classified {
                    Cell::Forbidden => assert_eq!(
                        from_table, None,
                        "classify({event:?}, {state:?}) says Forbidden but \
                         QUARANTINE_TRANSITIONS has a row for it"
                    ),
                    Cell::Allowed(targets) => assert_eq!(
                        from_table,
                        Some(targets),
                        "classify({event:?}, {state:?}) says Allowed({targets:?}) but \
                         QUARANTINE_TRANSITIONS disagrees ({from_table:?})"
                    ),
                }
            }
        }
    }

    /// Every table row's `to` set is non-empty (a present-but-unreachable
    /// row is not a valid representation — see `classify`'s `Forbidden`
    /// for that) and every row's `(event, from)` pair is unique (no
    /// duplicate cells).
    #[test]
    fn every_row_nonempty_and_unique() {
        let mut seen: Vec<(QuarantineEvent, QuarantineStatus)> = Vec::new();
        for row in QUARANTINE_TRANSITIONS {
            assert!(
                !row.to.is_empty(),
                "row {:?}/{:?} has an empty `to` set",
                row.event,
                row.from
            );
            let key = (row.event, row.from);
            assert!(
                !seen.contains(&key),
                "duplicate row for {:?}/{:?}",
                row.event,
                row.from
            );
            seen.push(key);
        }
    }

    #[test]
    fn allowed_targets_none_for_forbidden_cell() {
        assert_eq!(
            allowed_targets(QuarantineEvent::Quarantine, QuarantineStatus::Quarantined),
            None
        );
    }

    #[test]
    fn allowed_targets_some_for_allowed_cell() {
        assert_eq!(
            allowed_targets(QuarantineEvent::Quarantine, QuarantineStatus::None),
            Some(&[QuarantineStatus::Quarantined][..])
        );
    }

    #[test]
    fn event_label_is_stable_and_non_empty() {
        for &event in QuarantineEvent::ALL {
            assert!(!event.label().is_empty());
        }
    }

    #[test]
    fn render_lifecycle_dot_is_deterministic() {
        assert_eq!(render_lifecycle_dot(), render_lifecycle_dot());
    }

    #[test]
    fn render_lifecycle_dot_contains_every_state_node_and_omits_self_loops() {
        let dot = render_lifecycle_dot();
        assert!(dot.starts_with("// AUTO-GENERATED"));
        assert!(dot.contains("digraph ArtifactQuarantineLifecycle {\n"));
        for state in ALL_STATUSES {
            assert!(dot.contains(&format!("\"{state}\";")));
        }
        // record_clean_scan is a pure self-loop event — it must never
        // appear as an edge label.
        assert!(!dot.contains("record_clean_scan"));
        // reject_from_scan is a real Quarantined -> Rejected edge.
        assert!(dot.contains("\"quarantined\" -> \"rejected\" [label=\"reject_from_scan\"]"));
        assert!(dot.ends_with("}\n"));
    }
}
