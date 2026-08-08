//! Generated-artifact drift guard (backlog 090, #135 item 2) —
//! DB-free, network-free, sub-second, in the spirit of
//! `ephemeral_keyspace_exhaustive` / `no_bcrypt` / `alpha_fixtures` /
//! `streaming_metadata_port` / `no_sensitive_drops` /
//! `retention_registration_guard`.
//!
//! `docs/architecture/artifact-lifecycle.dot` is a checked-in,
//! test-emitted artifact rendered from the declared
//! `QUARANTINE_TRANSITIONS` table
//! (`hort_domain::entities::quarantine_transitions::render_lifecycle_dot`).
//! This guard fails whenever the checked-in file and the live render
//! disagree — a table edit that lands without regenerating the artifact,
//! or a hand-edit of the `.dot` file itself. `include_str!` pulls the file
//! in at COMPILE time (no runtime filesystem I/O), so the crate stays
//! within the DB-free / network-free guard family.

#![allow(clippy::expect_used)]

use hort_domain::entities::quarantine_transitions::render_lifecycle_dot;

#[test]
fn artifact_lifecycle_dot_matches_the_declared_table() {
    let checked_in = include_str!("../../../docs/architecture/artifact-lifecycle.dot");
    let rendered = render_lifecycle_dot();
    assert_eq!(
        checked_in, rendered,
        "docs/architecture/artifact-lifecycle.dot is stale relative to \
         QUARANTINE_TRANSITIONS. Regenerate it from \
         hort_domain::entities::quarantine_transitions::render_lifecycle_dot() \
         and commit the result in the same change."
    );
}
