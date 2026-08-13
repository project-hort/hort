//! Dependency-edge registry structural guard (ADR 0039 §12, backlog 090
//! item 3, #135). DB-free, network-free, sub-second — same family as
//! `retention_registration_guard` / `no_bcrypt` / `no_sensitive_drops`.
//!
//! `hort_app::lifecycle_dependency_registry::DEPENDENCY_EDGES` is the
//! both-ends-trigger ledger every standing cross-artifact lifecycle
//! dependency must register in. This guard fails whenever:
//!
//! 1. **A registry entry is one-ended** — either trigger's `code_site` is
//!    empty. The failure message names BOTH code sites (even the
//!    populated one) so a reviewer sees the whole entry, not just the gap.
//! 2. **The registry is empty** — it must seed at least the #135 item 089
//!    subject/constituent provenance-clearance edge.
//!
//! Unlike `retention_registration_guard`'s fixed `StreamCategory`
//! enumeration, the dependency-edge registry has no closed universe to
//! exhaustively match over (a new dependency is a new *entry*, not a new
//! enum variant) — so there is no compile-forcing match here. The
//! structural close is instead the `DependencyEdge` struct shape itself
//! (both trigger fields are required, non-`Option`, at construction) plus
//! this content guard against an empty-string sidestep.

#![allow(clippy::expect_used)]

use hort_app::lifecycle_dependency_registry::{one_ended_entries, DEPENDENCY_EDGES};

#[test]
fn registry_seeds_at_least_the_provenance_cascade_edge() {
    assert!(
        !DEPENDENCY_EDGES.is_empty(),
        "hort_app::lifecycle_dependency_registry::DEPENDENCY_EDGES is empty — it must \
         register at least the #135 item 089 subject/constituent provenance-clearance \
         edge (subject_trigger: ProvenanceCascade::cascade_clearance, \
         constituent_trigger: ProvenanceCascade::resolve_late_joiner_clearance)."
    );
}

#[test]
fn no_registry_entry_is_one_ended() {
    let bad = one_ended_entries(DEPENDENCY_EDGES);
    assert!(
        bad.is_empty(),
        "one-ended dependency-edge registry entries found — every standing \
         cross-artifact lifecycle dependency must name a trigger at BOTH ends \
         (ADR 0039 §12: 'a single-ended trigger is correct only for the arrival \
         order its author had in mind, and silently strands the other order'). \
         Offending entries as (name, subject_trigger.code_site, \
         constituent_trigger.code_site): {bad:?}"
    );
}

#[test]
fn every_entry_has_a_non_empty_name_and_description() {
    for edge in DEPENDENCY_EDGES {
        assert!(
            !edge.name.is_empty(),
            "a DEPENDENCY_EDGES entry has an empty name"
        );
        assert!(
            !edge.description.is_empty(),
            "dependency edge {:?} has an empty description",
            edge.name
        );
        assert!(
            !edge.subject_trigger.fires_on.is_empty(),
            "dependency edge {:?} has an empty subject_trigger.fires_on",
            edge.name
        );
        assert!(
            !edge.constituent_trigger.fires_on.is_empty(),
            "dependency edge {:?} has an empty constituent_trigger.fires_on",
            edge.name
        );
    }
}
