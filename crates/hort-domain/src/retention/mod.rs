//! Retention-policy domain aggregate.
//!
//! This module ships the **pure-domain** half of retention:
//!
//! - [`RetentionPolicyEvent`] — the event-sourced lifecycle vocabulary
//!   (`Created` / `Updated` / `Archived` / `Evaluated`), shaped to match
//!   the scan-policy aggregate lifecycle so the operational model
//!   stays uniform.
//! - [`PolicyPredicate`] + [`BooleanOp`] — the retention predicate
//!   algebra, including the four security-driven variants that consume
//!   scan projections (`HasFindingAboveSeverity`, `HasFindingAboveCvss`,
//!   `HasFixAvailable`, `HasFindingDetectedFor`) and the
//!   [`PolicyPredicate::Composite`] boolean combinator.
//! - [`RetentionScope`] — the retention-specific policy scope. **This is
//!   a deliberately distinct type from
//!   [`crate::events::PolicyScope`]** (the scan-policy `{ Global,
//!   Repository(Uuid) }`): the retention model needs the richer
//!   `{ AllRepos, Repos, Format, PackageNamePattern, IngestSource }`
//!   taxonomy. Reusing the scan-policy enum would either corrupt its
//!   shipped wire form or force every existing policy consumer to handle
//!   variants that make no sense for them. Divergence is intentional.
//! - [`ExpirationReason`] — the discriminated reason carried by the
//!   `ArtifactExpired` event. The event type itself lands on the
//!   *artifact* stream; this module only owns the
//!   `RetentionPolicy` aggregate and the reason value object it
//!   produces.
//! - [`RetentionPolicy`] — the replayed aggregate state, reconstructed
//!   by the pure fold [`RetentionPolicy::project`] /
//!   [`RetentionPolicy::apply`]. Pure replay is a pure function over
//!   events and is exhaustively tested in-domain.
//!
//! ## Evaluation additions
//!
//! - [`evaluate`] / [`matches_bool`] / [`EvaluationInputs`] /
//!   [`EvaluationOutcome`] — the **pure** retention-predicate evaluator.
//!   The security boundary: deciding match +
//!   producing the [`ExpirationReason`] snapshot. Zero I/O — the
//!   `hort-app` `RetentionUseCase` owns the projection reads, the
//!   scan-freshness gate, the `(policy_id, artifact_id)` idempotency check,
//!   the quarantine/rejected filter, and event append + metrics.
//! - [`resolve_held_state_entry`] / [`HeldState`] / [`HeldStateEntry`] —
//!   the pure **state-entry anchor**: when the artifact entered the held
//!   state it is in now, read off its own event stream. The counterpart
//!   to the content anchor
//!   [`Artifact::quarantine_window_start`](crate::entities::artifact::Artifact::quarantine_window_start),
//!   and deliberately named so the two cannot be confused — a span over
//!   a held artifact measures time in the state, never the age of the
//!   content. No entry event means **no span**, never a fallback.
//!
//!   The entry carries the entry event's **stream position** as well as
//!   its instant, because all three held states are re-enterable: it is
//!   the identity of *this* occupancy, and it is what an
//!   [`ArtifactExpired`](crate::events::ArtifactExpired) snapshots as
//!   its `held_state_authority` so a decision recorded about one
//!   occupancy cannot purge a later one.
//! - [`resolve_finding_age_anchor`] / [`FindingAgeAnchor`] /
//!   [`FindingAgeAnchorSource`] — the pure `HasFindingDetectedFor`
//!   anchor: how long the *vulnerability* has been known, from the
//!   advisory's publication date where a backend reported one and our own
//!   first observation of it otherwise. No anchor means the predicate
//!   does not match. The app layer supplies the two reads it folds.
//!
//! ## The held-state exception
//!
//! A held artifact is refused by five independent gates on the way to
//! collection, and [`RetentionPolicy::held_states`] is the only thing
//! that opens them — per policy and per state, empty by default. Its
//! paired invariant is
//! [`PolicyPredicate::every_branch_has_positive_age_bound`]: an opt-in
//! requires a predicate whose every successful branch carries a
//! positive `AgeExceeds`, and for such an evaluation `AgeExceeds` is
//! re-anchored to the state entry
//! ([`EvaluationInputs::held_state_entry`]). Both halves are needed —
//! an unbounded branch expires evidence the instant it is judged, and
//! an unanchored bound expires a two-year-old artifact the afternoon it
//! is first rejected.
//!
//! ## Domain-only scope
//!
//! The domain layer is zero-I/O, zero-`tracing`, zero-metrics.
//! The `serde` round-trip tests in this module prove the payloads are
//! *wire-stable*; persisting them through the real Postgres event store
//! is the adapter layer's job.

mod anchor;
mod evaluate;
mod held_state_entry;
mod mode;
mod policy;
mod predicate;
mod reason;
mod scope;

pub use anchor::{
    distinct_vulnerability_ids, resolve_finding_age_anchor, FindingAgeAnchor,
    FindingAgeAnchorSource,
};
pub use evaluate::{
    evaluate, matches_bool, severity_at_or_above, EvaluationInputs, EvaluationOutcome,
};
pub use held_state_entry::{resolve_held_state_entry, HeldState, HeldStateEntry};
pub use mode::RetentionEvaluationMode;
pub use policy::{RetentionPolicy, RetentionPolicyEvent};
pub use predicate::{BooleanOp, PolicyPredicate};
pub use reason::ExpirationReason;
pub use scope::{RetentionScope, MAX_REPOS_IN_SCOPE};
