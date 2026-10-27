//! Shared "what does this artifact's own format handler say its bytes
//! are?" resolver — the single definition of that lookup in the
//! application layer.
//!
//! [`ArtifactKind`] is the role half of ADR 0064 D2's line: it is what
//! decides whether a finding's filesystem claim is about the filesystem
//! the artifact *is* or about one it is a constituent of
//! ([`Finding::may_condemn_artifact`](hort_domain::types::Finding::may_condemn_artifact)),
//! and whether an *absent* assessment of that surface holds the row
//! ([`NotAnalysable::gates_release`](hort_domain::ports::scanner::NotAnalysable::gates_release)).
//! Four call sites need it — the scan run, the tighten and loosen
//! directions of the policy re-evaluation pass, and the curator's
//! single-artifact re-evaluation — and all four must get the same answer
//! for one row, or a verdict re-taken over stored findings answers a
//! different question from the one the fresh scan answered.
//!
//! **The handler decides; this function only asks it.** Re-deriving the
//! kind from a path prefix would be a second copy of
//! [`FormatHandler::scan_kind`], and the kind is the one input ADR 0064
//! D2's loosening is scoped by — a second copy that drifted would hand a
//! format a decision nobody took, silently, with the findings still
//! recorded and simply no longer gating. This is the shape
//! `crates/hort-app/tests/https_rule_is_single_sourced.rs` exists to
//! prevent one axis over.
//!
//! The registry key is the repository's format rendered with
//! `RepositoryFormat::to_string()` — the same string the ingest-time
//! scan enqueue writes onto `jobs.format`, so the scan run and a later
//! re-evaluation of the same row look the handler up under one key.

use std::collections::HashMap;
use std::sync::Arc;

use hort_domain::entities::artifact::Artifact;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::types::ArtifactKind;

/// What `format`'s registered [`FormatHandler`] says `artifact`'s bytes
/// are.
///
/// [`ArtifactKind::Other`] when no handler claims `format`. That is not a
/// fallback standing in for an answer nobody could give — it is the
/// handler registry's honest answer ("no materialisation applies to
/// these bytes"), and it is a **non**-constituent, so every finding on
/// such a row keeps the authority it has today and every gating
/// abstention keeps holding. A kind invented in the other direction
/// would move an obligation off a row no operator had promoted.
pub(crate) fn scan_kind_of(
    handlers: &HashMap<String, Arc<dyn FormatHandler>>,
    format: &str,
    artifact: &Artifact,
) -> ArtifactKind {
    handlers
        .get(format)
        .map_or(ArtifactKind::Other, |h| h.scan_kind(artifact))
}
