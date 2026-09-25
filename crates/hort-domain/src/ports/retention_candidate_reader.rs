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
//! All live artifacts whose status is retention-eligible: SQL `NULL`,
//! `none`, the legacy non-terminal scan spellings (`unscanned`, `clean`,
//! `flagged`), and `released`. The protected states `quarantined`,
//! `rejected`, and `scan_indeterminate` and all soft-deleted rows are
//! excluded SQL-side. The result is keyset-paginated by `artifact.id`.
//! Per-policy-scope SQL
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
//! needs, plus the `key` the operator-facing preview names the
//! repository by (a single query, no extra round-trip).
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
//!
//! ## `keep_rank` — the `KeepLastN` input
//!
//! This artifact's 1-based rank among its siblings plus the sibling
//! total, resolved in the **same** enumeration statement (a window
//! function — no second port, no extra round-trip, no second data
//! source).
//!
//! **Sibling group.** `(repository_id, artifact name)`.
//!
//! **Ordering (contract, not an implementation detail).** Newest first
//! by `created_at`, ties broken by artifact id descending. Which `n`
//! versions survive `KeepLastN(n)` is decided entirely by this
//! ordering, and the tiebreak is what makes it reproducible: two
//! artifacts stored in the same instant must not be free to swap ranks
//! between two sweeps and expire alternately.
//!
//! **Live set.** The rank is computed over the artifacts that are live
//! by the same definition this reader's own enumeration uses —
//! `deleted_at IS NULL`. A retired artifact must occupy no rank slot:
//! it would otherwise shield itself and push one extra live artifact
//! over the edge. GC-protected siblings (`quarantined` / `rejected` /
//! `scan_indeterminate`) are *not* enumerable as candidates but they
//! **do** occupy rank slots — they are live bytes on disk, and
//! "keep the last n" means n live artifacts.
//!
//! **Pagination.** The rank is a property of the whole sibling group,
//! never of the page. An implementation that lets the keyset cursor
//! reach the window partition computes a rank relative to the current
//! page and expires the wrong artifacts; the sibling group can be far
//! larger than one page.
//!
//! ## `tag_targeted` — the tag exemption
//!
//! A tag target survives `KeepLastN` regardless of rank, and nothing
//! in a rank knows about tags. The flag answers "does a mutable ref in
//! **this** repository resolve to this artifact?" and it has three
//! ways to look right and be wrong:
//!
//! - **Repository-scoped.** Content hashes are shared across
//!   repositories by construction — that is what CAS is. A
//!   hash-global lookup would exempt an untagged artifact because
//!   identical bytes happen to be tagged in another repository, and
//!   under a name-pattern-scoped policy it would protect nothing when
//!   the tag lives in a repository the policy does not cover.
//! - **Both target kinds.** `target_kind = 'hash'` is the OCI tag
//!   (a pointer at a content hash); `target_kind = 'version'` is how
//!   an npm dist-tag or any other non-OCI mutable pointer resolves.
//!   A hash-only exemption silently protects nothing outside OCI.
//! - **Evaluation is not the last word.** Evaluation and purge are
//!   separate sweeps, so a tag added between them finds the artifact
//!   already carrying `ArtifactExpired`. The window is closed on the
//!   purge side — see
//!   [`PendingPurge::tag_targeted`](super::purge_gc::PendingPurge::tag_targeted).

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
    /// field, so this is carried alongside it for the scope gate.
    pub format: RepositoryFormat,
    /// The artifact's repository **key** — `repositories.key`, the
    /// unique operator-facing identifier a policy's `metadata.name`
    /// resolves against (`RepositoryRepository::find_by_key`).
    ///
    /// Carried on the same `JOIN repositories` that already supplies
    /// `format`, so it costs no extra round-trip and no N+1 lookup.
    /// It exists so an operator-facing retention preview can name the
    /// repository the operator would actually type; `repository_id` is
    /// a UUID and nobody writes a UUID into a policy. Both travel
    /// together — the id stays for machine consumers.
    pub repository_key: String,
    /// The resolved `rescan_interval_hours` for the artifact's
    /// repository. `Some(0)` is meaningful (rescanning disabled — a
    /// security-driven predicate is then always-stale → fail-safe
    /// never-expire); `None` means no scan policy resolved → the
    /// default 24 h. Mirrors `RetentionCandidate
    /// .resolved_rescan_interval_hours` semantics exactly.
    pub resolved_rescan_interval_hours: Option<i64>,
    /// The `KeepLastN` input: this artifact's 1-based rank among its
    /// live siblings (newest = 1) and the size of that sibling group.
    /// `None` when no ranking could be resolved — the pure evaluator
    /// then fails `KeepLastN` safe and never expires the artifact.
    ///
    /// See the module docs for the ordering contract, the sibling-group
    /// definition, and why the rank cannot be computed per page.
    pub keep_rank: Option<(u32, u32)>,
    /// `true` iff a mutable ref **in this artifact's own repository**
    /// currently resolves to this artifact — an OCI tag
    /// (`target_kind = 'hash'`) pointing at its content hash, or a
    /// version pointer (`target_kind = 'version'`, the npm dist-tag
    /// shape) naming its `(name, version)`. See the module docs for
    /// why both kinds and the repository scope are load-bearing.
    pub tag_targeted: bool,
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
