//! Application-layer projectors.
//!
//! A *projector* in this codebase is a small, stateless helper that
//! computes a row-level delta for a denormalised projection table and
//! threads that delta through the lifecycle port so the projection
//! upsert lands in the same Postgres transaction as the originating
//! event append. Projectors live in `hort-app` (not `hort-domain`) because
//! they observe domain entities + events but do not own any pure
//! invariant — they are just delta calculators.
//!
//! The first projector is
//! [`RepoSecurityScoreProjector`], which maintains the per-repo
//! `repo_security_scores` aggregate.

pub mod repo_security_score;
