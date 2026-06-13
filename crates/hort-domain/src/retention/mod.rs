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
//!   `ArtifactExpired` event (§4). The event type itself lands on the
//!   *artifact* stream and is wired in Item B2; B1 only owns the
//!   `RetentionPolicy` aggregate and the reason value object it
//!   produces.
//! - [`RetentionPolicy`] — the replayed aggregate state, reconstructed
//!   by the pure fold [`RetentionPolicy::project`] /
//!   [`RetentionPolicy::apply`]. Pure replay is a pure function over
//!   events (§4 / §1) and is exhaustively tested in-domain.
//!
//! ## Item B3 additions
//!
//! - [`evaluate`] / [`matches_bool`] / [`EvaluationInputs`] /
//!   [`EvaluationOutcome`] — the **pure** retention-predicate evaluator.
//!   The security boundary: deciding match +
//!   producing the [`ExpirationReason`] snapshot. Zero I/O — the
//!   `hort-app` `RetentionUseCase` owns the projection reads, the
//!   scan-freshness gate, the `(policy_id, artifact_id)` idempotency check,
//!   the quarantine/rejected filter, the `HasFindingDetectedFor`
//!   stream anchor, and event append + metrics.
//!
//! ## Carved to a follow-on (NOT in B1)
//!
//! The B1 backlog acceptance bullets about *adapter persistence + replay
//! round-trips through the event-store adapter* and the *apply-pipeline
//! `info!`-level §6-invariant-8 warning* are explicitly **out of scope
//! for B1** (domain-only). They are carried to the B1-adapter / B3
//! apply-path follow-on. The domain layer is zero-I/O, zero-`tracing`,
//! zero-metrics — an `info!` warning cannot live here by construction.
//! The `serde` round-trip tests in this module prove the payloads are
//! *wire-stable*; persisting them through the real Postgres event store
//! is the adapter item's job.

mod evaluate;
mod policy;
mod predicate;
mod reason;
mod scope;

pub use evaluate::{
    evaluate, matches_bool, severity_at_or_above, EvaluationInputs, EvaluationOutcome,
};
pub use policy::{RetentionPolicy, RetentionPolicyEvent};
pub use predicate::{BooleanOp, PolicyPredicate};
pub use reason::ExpirationReason;
pub use scope::RetentionScope;
