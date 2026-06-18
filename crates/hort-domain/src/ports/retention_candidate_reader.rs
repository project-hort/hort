//! Outbound port for the retention candidate-enumeration query.
//!
//! `RetentionEvaluateHandler` (in
//! `hort-app::task_handlers::retention_evaluate`) delegates the SQL-side
//! candidate enumeration — selecting non-protected artifacts and
//! resolving each one's repo-scoped rescan interval (the
//! freshness-window input) via the scan-policy chain — to this
//! port, exactly mirroring the
//! [`RescanCandidatesRepository`](super::rescan_candidates::RescanCandidatesRepository)
//! precedent (the architect-blessed candidate-builder /
//! keyset-pagination pattern of the structurally-identical
//! cron-rescan handler).
//!
//! ## Enumeration scope
//!
//! All artifacts whose `quarantine_status NOT IN ('quarantined',
//! 'rejected', 'scan_indeterminate')` — i.e. `none` / `released`, the
//! retention-eligible set (the eligibility filter, pushed SQL-side).
//! Keyset-paginated by `artifact.id`. Per-policy-scope SQL
//! pre-filtering is **deliberately not** done here: the evaluator
//! does scope matching via the pure
//! [`RetentionScope::matches`](crate::retention::RetentionScope::matches),
//! invoked in `RetentionUseCase::evaluate_one` **before** the
//! predicate `evaluate()` call (scope matching is *not* part of
//! `evaluate()` — that function only evaluates the predicate). The
//! eligibility + idempotency + scan-freshness gates bound the work
//! (query-on-demand, no premature materialization). The reader still
//! does no scope SQL pre-filter — it only joins `repositories` to
//! supply the per-artifact `format` input `RetentionScope::matches`
//! needs (a single query, no extra round-trip).
//!
//! ## `resolved_rescan_interval_hours`
//!
//! Resolved per the artifact's repo via the scan-policy chain
//! (repo-scoped scan policy shadows the global default; archived rows
//! excluded), reading `policy_projections.rescan_interval_hours` — the
//! identical `JOIN LATERAL` the `rescan_candidates` adapter uses. A
//! **LEFT** join (not the rescan adapter's INNER join): an artifact
//! with no resolved scan policy yields `None` (→ the default 24 h)
//! rather than being dropped — age-based retention applies even
//! without a scan policy.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::entities::artifact::Artifact;
use crate::entities::repository::RepositoryFormat;
use crate::error::DomainResult;

use super::BoxFuture;

/// One retention candidate: the artifact plus the resolved rescan
/// interval for its repository (the freshness-window input).
///
/// An `hort-domain`-defined row DTO (NOT `hort-app`'s
/// `RetentionUseCase::RetentionCandidate` — an `hort-domain` port cannot
/// depend on an `hort-app` type). `RetentionEvaluateHandler` maps this
/// to `RetentionCandidate` with a trivial field copy. Every field is
/// already an `hort-domain` type ([`Artifact`] is `hort-domain`).
#[derive(Debug, Clone, PartialEq)]
pub struct RetentionCandidateRow {
    /// The artifact under evaluation.
    pub artifact: Artifact,
    /// The artifact's repository [`RepositoryFormat`] — the
    /// `RetentionScope::Format` input. Read by the adapter from the
    /// joined `repositories.format` column (the existing
    /// `repositories.format text` → `RepositoryFormat` mapping; same
    /// query, no extra round-trip). `Artifact` itself has no `format`
    /// field, so this is carried alongside it for B3's scope gate.
    pub format: RepositoryFormat,
    /// The resolved `rescan_interval_hours` for the artifact's
    /// repository. `Some(0)` is meaningful (rescanning disabled — a
    /// security-driven predicate is then always-stale → fail-safe
    /// never-expire); `None` means no scan policy resolved → the
    /// default 24 h. Mirrors `RetentionCandidate
    /// .resolved_rescan_interval_hours` semantics exactly.
    pub resolved_rescan_interval_hours: Option<i64>,
}

/// Outbound port for the retention candidate-enumeration query.
///
/// The Postgres adapter implements this against the canonical SQL
/// (the non-protected-artifact filter + the LEFT-JOIN-LATERAL
/// repo→policy rescan-interval resolution + keyset pagination). The
/// handler (`hort-app`) loops this until a short page, accumulating the
/// per-batch evaluate summary.
pub trait RetentionCandidateReader: Send + Sync {
    /// Return up to `batch_size` non-protected artifacts whose
    /// `artifact.id` is strictly greater than `after` (keyset
    /// pagination cursor; `None` = from the start), ordered by
    /// `artifact.id`.
    ///
    /// `now` is the wall-clock timestamp the handler captured at the
    /// start of the sweep — passed in (rather than read inside the
    /// adapter) so per-sweep semantics stay coherent across retries
    /// and tests can pin the comparison time (the established
    /// sweep-handler convention).
    fn list_candidates<'a>(
        &'a self,
        batch_size: u32,
        after: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<Vec<RetentionCandidateRow>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_dyn_compatible(_: Box<dyn RetentionCandidateReader>) {}

    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn RetentionCandidateReader>();
    }

    #[tokio::test]
    async fn list_candidates_dispatches_through_trait_object() {
        struct Stub;
        impl RetentionCandidateReader for Stub {
            fn list_candidates<'a>(
                &'a self,
                _batch_size: u32,
                _after: Option<Uuid>,
                _now: DateTime<Utc>,
            ) -> BoxFuture<'a, DomainResult<Vec<RetentionCandidateRow>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
        }
        let port: Box<dyn RetentionCandidateReader> = Box::new(Stub);
        let out = port
            .list_candidates(1000, None, Utc::now())
            .await
            .expect("Ok");
        assert!(out.is_empty());
    }
}
