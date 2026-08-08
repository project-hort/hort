//! Dependency-edge registry (backlog 090, #135 item 2).
//!
//! A standing **cross-artifact** lifecycle dependency — "artifact A's
//! state change decides artifact B's state" — is a different shape from
//! the per-lifecycle transition table in
//! `hort_domain::entities::quarantine_transitions` (which is about ONE
//! artifact's own state machine). This registry is the both-ends-trigger
//! ledger ADR 0039 §12 requires: every such dependency names the code site
//! that fires when the *subject* changes AND the code site that fires when
//! the *constituent* arrives/changes, so a reviewer (or the structural
//! guard below) can see at a glance whether a dependency was ever
//! implemented single-ended.
//!
//! **Why this lives in `hort-app`, not `hort-domain`.** The registry's
//! entries name concrete code sites (`ProvenanceCascade::cascade_clearance`,
//! `ProvenanceCascade::resolve_late_joiner_clearance`) that live in this
//! crate's `use_cases::provenance_cascade` module. `hort-domain` must stay
//! zero-I/O and must not name application-layer symbols; a domain-level
//! registry could only describe the STATE shape (already covered by
//! `quarantine_transitions`), not the trigger *sites* the both-ends
//! principle is actually about.
//!
//! ADR 0039 §12 (the both-ends-trigger principle): "A standing
//! cross-artifact lifecycle dependency … MUST name a trigger at both
//! ends: one fired by A's change, one fired by B's arrival/change. A
//! single-ended trigger is correct only for the arrival order its author
//! had in mind, and silently strands the other order."

// ---------------------------------------------------------------------------
// TriggerSite / DependencyEdge
// ---------------------------------------------------------------------------

/// One end of a cross-artifact lifecycle dependency: the code site that
/// fires it, and a one-line description of when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TriggerSite {
    /// `crate::module::path::Type::method` — a real, greppable symbol
    /// path, not free text. The structural guard below only checks
    /// non-emptiness (this crate has no doc-symbol resolver), but a
    /// reviewer can `grep` it directly.
    pub code_site: &'static str,
    /// When this trigger fires — the arrival/change event, in one line.
    pub fires_on: &'static str,
}

/// A standing cross-artifact lifecycle dependency, both trigger ends
/// named. See the module doc and ADR 0039 §12.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyEdge {
    /// Short, stable, greppable identifier for this dependency.
    pub name: &'static str,
    /// One-line description of the dependency itself (what decides what).
    pub description: &'static str,
    /// The end fired by the SUBJECT's own state change.
    pub subject_trigger: TriggerSite,
    /// The end fired by the CONSTITUENT's arrival/change.
    pub constituent_trigger: TriggerSite,
}

// ---------------------------------------------------------------------------
// DEPENDENCY_EDGES — the registry
// ---------------------------------------------------------------------------

/// The registry. First entry = the subject⇄constituent provenance
/// clearance dependency (#135 item 089): a verified subject's signed
/// bytes decide whether an already-ingested OR a later-arriving
/// constituent holds a `ProvenanceVerified` clearance. Both ends are
/// implemented by the shared `ProvenanceCascade` machinery in
/// `provenance_cascade.rs` so the two can never disagree about what the
/// subject's signature covers (see that module's doc comment).
///
/// A future standing cross-artifact dependency (parent⇄child,
/// policy⇄artifact, or a new subject⇄constituent shape) registers itself
/// here with both trigger ends filled in at the same time it lands — see
/// the structural guard below and the architect-doc anti-pattern entry
/// ("Single-ended cross-artifact lifecycle trigger").
pub const DEPENDENCY_EDGES: &[DependencyEdge] = &[DependencyEdge {
    name: "provenance_subject_constituent_clearance",
    description: "A verified subject's signed CAS bytes decide whether each \
                   constituent digest they bind holds a cascaded \
                   ProvenanceVerified clearance — regardless of which of the \
                   two artifacts is ingested/verified first.",
    subject_trigger: TriggerSite {
        code_site: "hort_app::use_cases::provenance_cascade::ProvenanceCascade::cascade_clearance",
        fires_on: "the subject's own verify-time cascade — a Verified verdict on a \
                   signed subject under Required walks its signed bytes and clears \
                   every constituent already ingested and held",
    },
    constituent_trigger: TriggerSite {
        code_site: "hort_app::use_cases::provenance_cascade::ProvenanceCascade::resolve_late_joiner_clearance",
        fires_on: "the constituent's own quarantine-commit time (ingest) — a \
                   late-joining constituent looks up an already-verified subject \
                   and self-clears from the same signed-bytes authority",
    },
}];

// ---------------------------------------------------------------------------
// Structural guard helpers (backlog 090 item 3)
// ---------------------------------------------------------------------------

/// A registry entry with an empty trigger-site code path on either end —
/// the "one-ended registry entry" the structural guard test rejects.
/// Returns the names of BOTH code sites (even the non-empty one) so the
/// guard failure message always identifies both ends, per the directive.
pub fn one_ended_entries(
    edges: &[DependencyEdge],
) -> Vec<(&'static str, &'static str, &'static str)> {
    edges
        .iter()
        .filter(|e| {
            e.subject_trigger.code_site.is_empty() || e.constituent_trigger.code_site.is_empty()
        })
        .map(|e| {
            (
                e.name,
                e.subject_trigger.code_site,
                e.constituent_trigger.code_site,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_non_empty() {
        assert!(
            !DEPENDENCY_EDGES.is_empty(),
            "the dependency-edge registry must seed at least the provenance \
             subject/constituent edge (#135 item 089)"
        );
    }

    #[test]
    fn first_entry_is_the_provenance_cascade_edge() {
        let first = &DEPENDENCY_EDGES[0];
        assert_eq!(first.name, "provenance_subject_constituent_clearance");
        assert!(first
            .subject_trigger
            .code_site
            .contains("cascade_clearance"));
        assert!(first
            .constituent_trigger
            .code_site
            .contains("resolve_late_joiner_clearance"));
    }

    #[test]
    fn every_registered_edge_is_two_ended() {
        let bad = one_ended_entries(DEPENDENCY_EDGES);
        assert!(
            bad.is_empty(),
            "one-ended dependency-edge registry entries found (name, subject_trigger, \
             constituent_trigger): {bad:?} — every standing cross-artifact lifecycle \
             dependency must name a trigger at BOTH ends (ADR 0039 §12)"
        );
    }

    #[test]
    fn one_ended_entries_reports_both_code_sites_on_a_synthetic_violation() {
        let synthetic = [DependencyEdge {
            name: "synthetic_one_ended",
            description: "test fixture",
            subject_trigger: TriggerSite {
                code_site: "some::real::Site",
                fires_on: "x",
            },
            constituent_trigger: TriggerSite {
                code_site: "",
                fires_on: "y",
            },
        }];
        let bad = one_ended_entries(&synthetic);
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0], ("synthetic_one_ended", "some::real::Site", ""));
    }

    #[test]
    fn one_ended_entries_empty_for_the_real_registry() {
        assert!(one_ended_entries(DEPENDENCY_EDGES).is_empty());
    }
}
