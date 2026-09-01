//! `prefetch-tick` `TaskHandler`
//! (see `docs/architecture/explanation/prefetch-pipeline.md`).
//!
//! The per-tick walk resolves the
//! upstream mapping for each Scheduled-eligible repo, fetches upstream
//! metadata via [`UpstreamProxy::fetch_metadata`], extracts the
//! published version set via the
//! [`FormatHandler::extract_upstream_versions`] trait method, and calls
//! the [`PrefetchUseCase::plan`] planner with the REAL
//! divergence. The metric pipeline fires
//! `hort_prefetch_enqueued_total{trigger="scheduled"}` from the same
//! code path a production tick uses.
//!
//! # Scheduled prefetch trigger
//!
//! Periodically walks every repository whose `prefetch_policy.enabled =
//! true` AND whose `prefetch_policy.triggers` contains
//! `PrefetchTrigger::Scheduled`, and for each *tracked package* invokes
//! the [`PrefetchUseCase::plan`] planner with `trigger =
//! PrefetchTrigger::Scheduled`. The handler is the scheduled-tick
//! counterpart of the hot-path trigger (`OnDistTagMove` —
//! the serve-site hook; there is deliberately no `OnIndexFetch`
//! trigger).
//!
//! # Tracked-package definition
//!
//! A *tracked package* is any package name that has at least one row in
//! the `artifacts` projection for the repository — i.e., a package
//! hort-server has been asked to serve at least once. The handler reads
//! distinct names via [`ArtifactRepository::list_distinct_names`].
//! Hort has no separate "watched packages" concept; the projection row
//! is the proof of having been touched.
//!
//! # Authority + the fail-closed release property (ADR 0007)
//!
//! The scheduled tick has **no authority of its own**. It only invokes
//! the planner. The planner is a pure planner + metric
//! emitter: it returns a list of versions the *format crate* could pull,
//! but the spawn / ingest itself lives downstream. The tick reports per-
//! tick counters in `result_summary` (mirrors
//! `QuarantineReleaseSweepHandler`):
//!
//! ```json
//! {
//!   "repos_walked":          u64,
//!   "packages_walked":       u64,
//!   "prefetches_planned":    u64,
//!   "prefetches_enqueued":   u64,
//!   "prefetches_deduped":    u64,
//!   "budget_exhausted":      bool,
//!   "skipped_disabled":      u64,
//!   "skipped_no_trigger":    u64,
//!   "upstream_fetch_errors": u64,
//!   "upstream_parse_errors": u64,
//!   "no_mapping":            u64,
//!   "cursor":                { "position": "after_repo" | "within_repo", … } | null
//! }
//! ```
//!
//! `cursor` is the rotation's own progress marker — see "Cross-tick
//! rotation" below.
//!
//! # Upstream discovery
//!
//! The handler resolves the catch-all upstream mapping (empty
//! `path_prefix`) for each candidate repo via
//! [`RepositoryUpstreamMappingRepository::list_for_repository`], fetches
//! the upstream catalog body via [`UpstreamProxy::fetch_metadata`], and
//! decodes it via [`FormatHandler::extract_upstream_versions`]. Per-
//! format upstream paths mirror the hot-path triggers verbatim:
//!
//! - **npm** — `/<url-encoded-name>` (packument)
//! - **cargo** — `/<index-path>` (sparse-index NDJSON)
//! - **pypi** — `/simple/<normalised-name>/` (PEP 503 HTML)
//!
//! Failure modes (no mapping, fetch error, parse error, unknown
//! format) are non-fatal — a `warn!` is emitted and the walk moves on.
//! One bad repo cannot starve the rest of the walk.
//!
//! # Cross-tick rotation
//!
//! No repo or tracked package is page-1-locked out. The walk is a
//! **single flattened total order** — repos in stable `ORDER BY id`,
//! packages within a repo in [`ArtifactRepository::list_distinct_names`]'s
//! byte-stable `ORDER BY name` — and the tick persists a keyset cursor
//! (`(repository_id, package_name)`, [`TickCursor`]) marking the last
//! position fully processed. The NEXT tick's fresh job row (every
//! recurring tick is a brand-new `jobs` INSERT — see
//! `enqueue-prefetch-tick`) reads that cursor back via
//! [`JobsRepository::last_result_summary_by_kind`] and resumes strictly
//! after it — no new table, no column on `repositories`; the cursor
//! rides the tick's own `result_summary`, which is already durable
//! per-row state. A cursor naming a since-deleted repo or package
//! degrades gracefully: the keyset `>` comparison simply resumes at the
//! next existing entry. Reaching the true end of the repo table wraps
//! the walk back to the beginning for free — the same "fetch after the
//! cursor; if short, fetch the remainder from the start" keyset step
//! that resumes a mid-table cutover also closes a completed cycle,
//! without a separate "did we finish everything" check.
//!
//! [`MAX_REPOS_PER_TICK`] and [`MAX_PACKAGES_PER_REPO`] are **per-tick
//! page sizes of the rotation, not hard visibility ceilings**: a
//! repository count or a single repo's tracked-package count beyond
//! either cap no longer stops that repo (or those packages) from ever
//! being visited — it only stops the CURRENT tick there, and the
//! persisted cursor picks the walk back up on the next one. Concretely,
//! hitting [`MAX_PACKAGES_PER_REPO`] mid-repo — its per-tick package
//! page comes back full — halts the *entire* tick at that point (not
//! just that repo): the flattened total order has exactly one active
//! cursor position, so continuing on to other repos in the same tick
//! would either advance past this repo's remaining names with nothing
//! recording where to resume, or require tracking more than one
//! in-flight cursor. Concretely too: with the per-tick enqueue budget
//! [`MAX_PREFETCHES_PER_TICK`] = B and total plannable work (the
//! repo×package space actually walked before a fresh divergence stops
//! appearing) W, a full traversal completes in `⌈W / B⌉` ticks in the
//! common case where the enqueue budget binds before either page-size
//! cap does; a deployment with more than [`MAX_REPOS_PER_TICK`] repos
//! or a repo with more than [`MAX_PACKAGES_PER_REPO`] tracked names
//! simply takes the page-size cap as its per-tick stride instead, still
//! monotonically covering everything — never a permanent visibility
//! ceiling.
//!
//! # Batch discipline
//!
//! The handler bounds per-tick work two ways:
//!
//! 1. Repository walk uses [`MAX_REPOS_PER_TICK`] as the per-tick page
//!    size (field `max_repos_per_tick`, unit-testable independent of
//!    the const).
//! 2. Per-repo package walk uses [`MAX_PACKAGES_PER_REPO`] as the
//!    per-tick page size (field `max_packages_per_repo`).
//!
//! Both caps mirror `QuarantineReleaseSweepHandler::BATCH_SIZE`'s
//! shape; neither bounds *total* visibility any more (see "Cross-tick
//! rotation" above) — only how much of the rotation a single tick
//! advances.
//!
//! # Composition + delivery
//!
//! Registered in `crates/hort-worker/src/composition.rs` alongside
//! [`super::quarantine_release_sweep::QuarantineReleaseSweepHandler`] —
//! same single-active (`max_concurrency = 1`) discipline.
//!
//! The Helm CronJob (`deploy/helm/hort-server/templates/cronjob-prefetch-
//! tick.yaml`, default `enabled: false`) runs `hort-server enqueue-
//! prefetch-tick`, which inserts one `kind = 'prefetch-tick'` row via
//! the runtime DSN — same delivery contract as the
//! quarantine-release sweep.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::{PrefetchTrigger, Repository, RepositoryFormat};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::jobs_repository::{JobsRepository, PrefetchEnqueueRow};
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::upstream_proxy::UpstreamProxy;
use hort_domain::ports::BoxFuture;

use crate::use_cases::index_serve_filter::{
    CargoSemverOrdering, NpmSemverOrdering, Pep440Ordering, VersionOrdering,
};
use crate::use_cases::prefetch_use_case::PrefetchUseCase;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default per-tick page size for the repository rotation. Mirrors the
/// `BATCH_SIZE = 1000` discipline in
/// [`super::quarantine_release_sweep::QuarantineReleaseSweepHandler`].
/// A single tick visits at most this many repos (default value for
/// [`PrefetchTickHandler::max_repos_per_tick`]); the persisted
/// [`TickCursor`] resumes the rotation on the next tick, so this is a
/// per-tick stride, not a hard visibility ceiling — see "Cross-tick
/// rotation" in the module docs. Pinning as a `u64` constant (rather
/// than wiring through env) follows the v1 sweep precedent — ENV-tuning
/// is out of scope here.
const MAX_REPOS_PER_TICK: u64 = 1000;

/// Default per-tick page size for a single repository's tracked-package
/// walk (default value for
/// [`PrefetchTickHandler::max_packages_per_repo`]).
/// [`ArtifactRepository::list_distinct_names_after`] is keyset-paginated;
/// the handler reads one page of this size, resuming after the
/// persisted cursor. A repo with more packages than this page size
/// halts the ENTIRE tick at the page boundary (not just this repo — see
/// "Cross-tick rotation" in the module docs) and resumes the same repo,
/// same position, on the next tick; the planner is idempotent so
/// re-walking is always harmless, it simply never happens for a
/// completed name.
const MAX_PACKAGES_PER_REPO: u64 = 1000;

/// Per-tick enqueue budget. The walk is bulk
/// (`repos × tracked-packages × depth`), so the row-fan-out is bounded
/// here even though the L3 `target_key` single-flight (`ON CONFLICT DO
/// NOTHING`) collapses cross-tick duplicates. Checked **between
/// packages**: once cumulative `prefetches_enqueued` reaches this, the
/// walk stops (`budget_exhausted`) and the remaining packages resume on
/// the next tick (the walk is already idempotent + partitioned). Sized in
/// the same spirit as `MAX_REPOS_PER_TICK` / `MAX_PACKAGES_PER_REPO`.
const MAX_PREFETCHES_PER_TICK: usize = 5000;

/// `kind` for the leaf-ingest rows the tick enqueues. Dispatched to
/// `PrefetchIngestHandler` (the same kind the cascade + self-service use).
const PREFETCH_INGEST_KIND: &str = "prefetch";

/// `trigger_source` for scheduled enqueues. Deliberately NOT `"prefetch"`
/// (the cascade-internal marker): a `"scheduled"` leaf is a SEED, so its
/// ingest re-fires the transitive cascade (`is_cascade_internal_leaf` is
/// `trigger_source == "prefetch"`). Must be present in the
/// `jobs.trigger_source` CHECK (migration 009).
const SCHEDULED_TRIGGER_SOURCE: &str = "scheduled";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// [`TaskHandler`] for the periodic prefetch scheduled tick. Constructed
/// at composition time with the ports + the format-handler lookup map.
pub struct PrefetchTickHandler {
    repositories: Arc<dyn RepositoryRepository>,
    artifacts: Arc<dyn ArtifactRepository>,
    prefetch: Arc<PrefetchUseCase>,
    /// The jobs port the tick enqueues `prefetch` leaf-ingests through
    /// (via `enqueue_prefetch_batch`, the cascade's `target_key`-deduped
    /// path). Mirrors `PrefetchDependenciesHandler`'s port-only shape.
    jobs: Arc<dyn JobsRepository>,
    upstream_proxy: Arc<dyn UpstreamProxy>,
    upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
    /// Format-handler lookup keyed by `RepositoryFormat`'s `Display`
    /// output (the same string `format_key()` returns for the
    /// compiled-in handlers in `hort-formats`). Mirrors the worker
    /// composition's `HashMap<String, Arc<dyn FormatHandler>>` shape —
    /// the worker already owns this map and clones it into the
    /// handler at registration time.
    format_handlers: HashMap<String, Arc<dyn FormatHandler>>,
    /// Per-tick enqueue budget. Defaults to [`MAX_PREFETCHES_PER_TICK`]; a
    /// field (not a bare const read) so the budget boundary is
    /// unit-testable without a 5000-row fixture.
    max_prefetches_per_tick: usize,
    /// Per-tick repository-rotation page size. Defaults to
    /// [`MAX_REPOS_PER_TICK`]; a field so the > cap rotation/wrap
    /// behaviour is unit-testable without a 1000+-repo fixture.
    max_repos_per_tick: u64,
    /// Per-tick per-repository package-rotation page size. Defaults to
    /// [`MAX_PACKAGES_PER_REPO`]; a field so the > cap resume behaviour
    /// is unit-testable without a 1000+-name fixture.
    max_packages_per_repo: u64,
}

impl PrefetchTickHandler {
    /// Construct the handler from its port dependencies + the planner.
    /// `prefetch` is `Arc<PrefetchUseCase>` for shape consistency with the
    /// rest of the use-case surface — `PrefetchUseCase` is a zero-cost unit
    /// struct so the `Arc` is a trivial wrapper.
    pub fn new(
        repositories: Arc<dyn RepositoryRepository>,
        artifacts: Arc<dyn ArtifactRepository>,
        prefetch: Arc<PrefetchUseCase>,
        jobs: Arc<dyn JobsRepository>,
        upstream_proxy: Arc<dyn UpstreamProxy>,
        upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
        format_handlers: HashMap<String, Arc<dyn FormatHandler>>,
    ) -> Self {
        Self {
            repositories,
            artifacts,
            prefetch,
            jobs,
            upstream_proxy,
            upstream_mappings,
            format_handlers,
            max_prefetches_per_tick: MAX_PREFETCHES_PER_TICK,
            max_repos_per_tick: MAX_REPOS_PER_TICK,
            max_packages_per_repo: MAX_PACKAGES_PER_REPO,
        }
    }

    /// Read the rotation cursor persisted by the most recently completed
    /// `prefetch-tick` run's `result_summary.cursor`. Every failure mode
    /// — the kind has never completed, the port read failed, the prior
    /// summary carries no `cursor` key, or the value fails to
    /// deserialise — collapses to `None` (walk from the beginning): a
    /// missing or malformed cursor is a resumability optimisation lost,
    /// never a reason to fail the tick.
    async fn read_cursor(&self) -> Option<TickCursor> {
        let summary = match self.jobs.last_result_summary_by_kind(self.kind()).await {
            Ok(s) => s?,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "prefetch-tick: last_result_summary_by_kind failed; walking from the beginning",
                );
                return None;
            }
        };
        let cursor = summary.get("cursor")?.clone();
        if cursor.is_null() {
            return None;
        }
        match serde_json::from_value::<TickCursor>(cursor.clone()) {
            Ok(c) => Some(c),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    %cursor,
                    "prefetch-tick: malformed cursor in prior result_summary; \
                     walking from the beginning",
                );
                None
            }
        }
    }
}

/// Cross-tick keyset cursor for the repo × package rotation.
/// Persisted as the tick's own `result_summary.cursor` — see the module
/// docs' "Cross-tick rotation" section for why the state lives there
/// rather than a new table or a column on `repositories`.
///
/// `AfterRepo` means "this repo's rotation slot is fully spent — resume
/// at the next repo in id order, packages from the top." `WithinRepo`
/// means "this repo's per-tick package page was not fully drained —
/// resume the SAME repo, at the next name after `package_name`."
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "position", rename_all = "snake_case")]
enum TickCursor {
    AfterRepo {
        repository_id: Uuid,
    },
    WithinRepo {
        repository_id: Uuid,
        package_name: String,
    },
}

impl TickCursor {
    /// The repository-id keyset bound for the rotation's NEXT-repo
    /// query. Both variants resume subsequent repos strictly after this
    /// id — a `WithinRepo` cursor's own repo is re-fetched separately
    /// (by id, not through this keyset bound) so its package walk can
    /// resume mid-repo.
    fn repository_id(&self) -> Uuid {
        match self {
            TickCursor::AfterRepo { repository_id }
            | TickCursor::WithinRepo { repository_id, .. } => *repository_id,
        }
    }
}

/// Per-tick counters threaded through the walk. Lives outside `run` so
/// the per-repo and per-package mutation sites read the same struct
/// without an inline tuple-of-bindings shuffle.
#[derive(Default, Debug)]
struct TickSummary {
    repos_walked: u64,
    packages_walked: u64,
    prefetches_planned: u64,
    /// `prefetch` leaf rows actually inserted by `enqueue_prefetch_batch`
    /// (the ids it returned). Mirrors the cascade's
    /// `WalkSummary::prefetch_rows_enqueued`.
    prefetches_enqueued: u64,
    /// Planned rows collapsed by the L3 `target_key` `ON CONFLICT DO
    /// NOTHING` (`attempted − inserted`). Mirrors the cascade's
    /// `WalkSummary::prefetch_rows_deduped`.
    prefetches_deduped: u64,
    /// `true` when the per-tick enqueue budget stopped the walk early
    /// (remaining packages resume next tick).
    budget_exhausted: bool,
    skipped_disabled: u64,
    skipped_no_trigger: u64,
    upstream_fetch_errors: u64,
    upstream_parse_errors: u64,
    no_mapping: u64,
    /// Rotation progress: the last `(repository_id, package_name)`
    /// position fully processed this tick, or `None` when nothing was
    /// walked (e.g. an empty repository table). Read back by the next
    /// tick via `JobsRepository::last_result_summary_by_kind`.
    cursor: Option<TickCursor>,
}

impl TickSummary {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "repos_walked":          self.repos_walked,
            "packages_walked":       self.packages_walked,
            "prefetches_planned":    self.prefetches_planned,
            "prefetches_enqueued":   self.prefetches_enqueued,
            "prefetches_deduped":    self.prefetches_deduped,
            "budget_exhausted":      self.budget_exhausted,
            "skipped_disabled":      self.skipped_disabled,
            "skipped_no_trigger":    self.skipped_no_trigger,
            "upstream_fetch_errors": self.upstream_fetch_errors,
            "upstream_parse_errors": self.upstream_parse_errors,
            "no_mapping":            self.no_mapping,
            "cursor":                self.cursor,
        })
    }
}

impl TaskHandler for PrefetchTickHandler {
    fn kind(&self) -> &'static str {
        "prefetch-tick"
    }

    #[tracing::instrument(skip(self))]
    fn run<'a>(
        &'a self,
        _params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            let cursor = self.read_cursor().await;

            // ----- Step 1: resolve this tick's repo rotation page -----
            //
            // A `WithinRepo` cursor's own repo is re-fetched by id (its
            // package walk resumes mid-repo, below); every other repo
            // comes from the keyset page, strictly after the cursor's
            // repo id. Reaching the true end of the repo table (a short
            // page) wraps by fetching the remainder from the start,
            // deduped against what this tick already selected — a repo
            // count at or below the page size is never double-visited
            // in one tick, and a repo count above it wraps for free on
            // whichever tick's cursor first reaches the tail.
            let mut repos_to_walk: Vec<(Repository, Option<String>)> = Vec::new();
            let mut repo_budget = self.max_repos_per_tick;

            if let Some(TickCursor::WithinRepo {
                repository_id,
                package_name,
            }) = &cursor
            {
                match self.repositories.find_by_id(*repository_id).await {
                    Ok(repo) => {
                        repos_to_walk.push((repo, Some(package_name.clone())));
                        repo_budget = repo_budget.saturating_sub(1);
                    }
                    Err(DomainError::NotFound { .. }) => {
                        tracing::debug!(
                            repository_id = %repository_id,
                            "prefetch-tick: cursor's repo was deleted; resuming past it",
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            repository_id = %repository_id,
                            "prefetch-tick: find_by_id failed resolving the cursor's repo; \
                             resuming past it",
                        );
                    }
                }
            }

            if repo_budget > 0 {
                let after_id = cursor.as_ref().map(TickCursor::repository_id);
                let page = match self.repositories.list_after(after_id, repo_budget).await {
                    Ok(p) => p,
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "prefetch-tick: repositories.list_after failed; will retry on next tick",
                        );
                        return Ok(TaskOutcome::fail(
                            format!("repositories.list_after failed: {err}"),
                            true,
                        ));
                    }
                };
                let short_by = repo_budget.saturating_sub(page.len() as u64);
                let mut page = page;
                if short_by > 0 && after_id.is_some() {
                    let wrap = match self.repositories.list_after(None, short_by).await {
                        Ok(w) => w,
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "prefetch-tick: repositories.list_after (wrap) failed; \
                                 continuing with the partial page",
                            );
                            Vec::new()
                        }
                    };
                    let seen: HashSet<Uuid> = repos_to_walk
                        .iter()
                        .map(|(r, _)| r.id)
                        .chain(page.iter().map(|r| r.id))
                        .collect();
                    page.extend(wrap.into_iter().filter(|r| !seen.contains(&r.id)));
                }
                repos_to_walk.extend(page.into_iter().map(|r| (r, None)));
            }

            let mut summary = TickSummary::default();

            'walk: for (repo, resume_after) in repos_to_walk.iter() {
                // ----- Per-repo candidacy filter -----------------------
                let policy = &repo.prefetch_policy;
                if !policy.enabled {
                    summary.skipped_disabled += 1;
                    summary.cursor = Some(TickCursor::AfterRepo {
                        repository_id: repo.id,
                    });
                    continue;
                }
                if !policy.triggers.contains(&PrefetchTrigger::Scheduled) {
                    summary.skipped_no_trigger += 1;
                    summary.cursor = Some(TickCursor::AfterRepo {
                        repository_id: repo.id,
                    });
                    continue;
                }
                let Some(handler) = self.format_handlers.get(&repo.format.to_string()) else {
                    tracing::warn!(
                        repository = %repo.key,
                        format = ?repo.format,
                        "prefetch-tick: no FormatHandler registered for repo's format — \
                         skipping repo (Phase-1 ships npm/cargo/pypi/oci handlers; \
                         a Phase-2 format with an ordering but no handler is a \
                         composition oversight)",
                    );
                    summary.cursor = Some(TickCursor::AfterRepo {
                        repository_id: repo.id,
                    });
                    continue;
                };
                // Pre-flight: the format must participate in the
                // VersionDiscovery capability group (issue #58) — the
                // structural replacement for the old
                // `ordering_for_format(&repo.format).is_none()` boolean
                // pre-check. `vd` (`&dyn VersionDiscovery`) is `Send +
                // Sync` (a supertrait bound on the trait itself), so —
                // unlike `&dyn VersionOrdering` below — holding it across
                // this iteration's `.await` points does not taint the
                // enclosing `Pin<Box<dyn Future + Send>>`.
                let Some(vd) = handler.version_discovery() else {
                    tracing::debug!(
                        repository = %repo.key,
                        format = ?repo.format,
                        "prefetch-tick: format does not implement VersionDiscovery — \
                         skipping repo",
                    );
                    summary.cursor = Some(TickCursor::AfterRepo {
                        repository_id: repo.id,
                    });
                    continue;
                };

                // ----- Step 2: resolve the catch-all upstream mapping --
                //
                // npm / cargo / pypi are single-upstream formats — the
                // mapping the prefetch trigger uses is the one with
                // `path_prefix = ""` (the catch-all). The handler does
                // NOT use the production `UpstreamResolver` cache (which
                // lives in `hort-http-oci`); hort-app holds the
                // `RepositoryUpstreamMappingRepository` port directly
                // because the cron tier tolerates the per-tick DB round-
                // trip and avoids a worker-side dep on the OCI inbound
                // crate.
                let mappings = match self.upstream_mappings.list_for_repository(repo.id).await {
                    Ok(m) => m,
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            repository = %repo.key,
                            "prefetch-tick: list_for_repository failed; continuing",
                        );
                        summary.cursor = Some(TickCursor::AfterRepo {
                            repository_id: repo.id,
                        });
                        continue;
                    }
                };
                let Some(mapping) = mappings.into_iter().find(|m| m.path_prefix.is_empty()) else {
                    tracing::warn!(
                        repository = %repo.key,
                        "prefetch-tick: no catch-all upstream mapping (path_prefix=\"\") \
                         for repo — skipping (a proxy repo with prefetch enabled but no \
                         upstream mapping is a config gap)",
                    );
                    summary.no_mapping += 1;
                    summary.cursor = Some(TickCursor::AfterRepo {
                        repository_id: repo.id,
                    });
                    continue;
                };

                summary.repos_walked += 1;

                // ----- Step 3: keyset page of tracked package names ----
                let names_page = match self
                    .artifacts
                    .list_distinct_names_after(
                        repo.id,
                        resume_after.as_deref(),
                        self.max_packages_per_repo,
                    )
                    .await
                {
                    Ok(p) => p,
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            repository = %repo.key,
                            "prefetch-tick: list_distinct_names_after failed for repo; continuing",
                        );
                        summary.cursor = Some(TickCursor::AfterRepo {
                            repository_id: repo.id,
                        });
                        continue;
                    }
                };
                let names_page_full = names_page.len() as u64 == self.max_packages_per_repo;

                // ----- Step 4: per-package upstream-fetch + plan --------
                for package in names_page.iter() {
                    // The port returns a 3-tuple
                    // `(version, status, quarantine_until)`. The pure
                    // planner ignores `quarantine_until`; strip the
                    // third element here so the planner-side type stays
                    // `&[(String, QuarantineStatus)]` (one-tuple-arm
                    // contraction at the consumer boundary).
                    let held_status: Vec<(String, QuarantineStatus)> = match self
                        .artifacts
                        .package_version_status(repo.id, package)
                        .await
                    {
                        Ok(rows) => rows.into_iter().map(|(v, s, _)| (v, s)).collect(),
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                repository = %repo.key,
                                package = %package,
                                "prefetch-tick: package_version_status failed; continuing",
                            );
                            summary.packages_walked += 1;
                            continue;
                        }
                    };

                    // Per-format URL conventions live on the
                    // VersionDiscovery trait. `None` here is a
                    // participating format that (like pypi's peers)
                    // simply has no metadata-index document; the
                    // structural pre-flight above already guarantees
                    // `vd` participates in the group at all.
                    let Some(upstream_path) = vd.upstream_metadata_path(package) else {
                        tracing::debug!(
                            repository = %repo.key,
                            package = %package,
                            format = ?repo.format,
                            "prefetch-tick: handler has no upstream_metadata_path; skipping package",
                        );
                        summary.packages_walked += 1;
                        continue;
                    };
                    let accept = vd.upstream_metadata_accept();
                    let outcome = match self
                        .upstream_proxy
                        .fetch_metadata(mapping.clone(), upstream_path.clone(), accept)
                        .await
                    {
                        Ok(b) => b,
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                repository = %repo.key,
                                package = %package,
                                path = %upstream_path,
                                "prefetch-tick: fetch_metadata failed; continuing",
                            );
                            summary.upstream_fetch_errors += 1;
                            summary.packages_walked += 1;
                            continue;
                        }
                    };
                    // Stream the cached metadata tempfile
                    // through `extract_upstream_versions` on a blocking
                    // thread (no full-body buffering). Prefetch-tick does
                    // not serve, so no mirror write; the tempfile is removed
                    // once the version list has been projected.
                    let Some(cache_handle) = outcome.cache_handle.as_ref() else {
                        tracing::warn!(
                            repository = %repo.key,
                            package = %package,
                            path = %upstream_path,
                            "prefetch-tick: metadata fetch produced no cache handle; continuing",
                        );
                        summary.upstream_fetch_errors += 1;
                        summary.packages_walked += 1;
                        continue;
                    };
                    let versions_result = {
                        let handler = Arc::clone(handler);
                        crate::project::run_handler_body(cache_handle, move |reader| {
                            // Re-derive `vd` from the cloned, owned `Arc`
                            // — the closure must be `'static`, so it
                            // cannot capture the outer borrowed `vd`.
                            // `version_discovery()` is a pure dispatch
                            // on `handler`'s concrete type, so re-deriving
                            // it is exactly as safe as the pre-flight
                            // check above (same handler, same answer).
                            let vd = handler.version_discovery().expect(
                                "handler participates in VersionDiscovery — checked at the \
                                 top of this repo's iteration",
                            );
                            vd.extract_upstream_versions(reader)
                        })
                        .await
                    };
                    crate::project::remove_cached_body(cache_handle).await;
                    let upstream_versions = match versions_result {
                        Ok(v) => v,
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                repository = %repo.key,
                                package = %package,
                                "prefetch-tick: extract_upstream_versions failed; continuing",
                            );
                            summary.upstream_parse_errors += 1;
                            summary.packages_walked += 1;
                            continue;
                        }
                    };

                    // Resolve the ordering + run the pure planner inside a
                    // block — strictly after every `.await` in this
                    // iteration AND before the `enqueue_prefetch_batch` await
                    // below — so the `!Send` trait object never crosses an
                    // await boundary. Today npm/cargo/pypi are exactly both
                    // the VersionDiscovery participants (the pre-flight
                    // `vd` check above) and the only Phase-1-ordering
                    // formats, so that check already guarantees this
                    // resolves; we still pattern-match for defence-in-depth
                    // against the two capabilities ever diverging.
                    let planned: Vec<String> = {
                        let Some(ordering) = ordering_for_format(&repo.format) else {
                            continue;
                        };
                        run_planner_sync(
                            self.prefetch.as_ref(),
                            repo,
                            package,
                            &upstream_versions,
                            &held_status,
                            ordering,
                        )
                    };
                    summary.packages_walked += 1;
                    summary.prefetches_planned += planned.len() as u64;
                    if planned.is_empty() {
                        continue;
                    }

                    // ----- Step 5: enqueue the cohort -------------------------
                    // One `prefetch` leaf row per planned version, batched
                    // through the cascade's `target_key`-deduped path
                    // (`enqueue_prefetch_batch` → `ON CONFLICT (target_key)
                    // DO NOTHING`). `target_key` is computed with the SAME
                    // `format_key` + `normalize_name` the cascade uses, so a
                    // scheduled row dedups against an in-flight cascade /
                    // scheduled row for the same coordinate.
                    let format_key = repo.format.to_string();
                    let normalised = handler.normalize_name(package);
                    let rows: Vec<PrefetchEnqueueRow> = planned
                        .iter()
                        .map(|version| PrefetchEnqueueRow {
                            kind: PREFETCH_INGEST_KIND.to_string(),
                            params: json!({
                                "repository_id": repo.id,
                                "package": normalised,
                                "version": version,
                            }),
                            priority: 0,
                            trigger_source: SCHEDULED_TRIGGER_SOURCE.to_string(),
                            target_key: super::prefetch_target_key(
                                repo.id,
                                &format_key,
                                &normalised,
                                version,
                            ),
                        })
                        .collect();
                    match self.jobs.enqueue_prefetch_batch(&rows).await {
                        Ok(ids) => {
                            // Inserted ids = non-deduped rows; the rest were
                            // collapsed by `ON CONFLICT DO NOTHING`.
                            summary.prefetches_enqueued += ids.len() as u64;
                            summary.prefetches_deduped += (rows.len() - ids.len()) as u64;
                        }
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                repository = %repo.key,
                                package = %package,
                                "prefetch-tick: enqueue_prefetch_batch failed; continuing \
                                 (best-effort — versions re-plan next tick)",
                            );
                        }
                    }

                    // Per-tick budget, checked BETWEEN packages so each
                    // walked package's cohort enqueues whole (keeps the
                    // plan-time metric aligned per package). The cursor
                    // saves the EXACT stopping point — the next tick
                    // resumes at this package, not at page 1.
                    if summary.prefetches_enqueued >= self.max_prefetches_per_tick as u64 {
                        summary.budget_exhausted = true;
                        summary.cursor = Some(TickCursor::WithinRepo {
                            repository_id: repo.id,
                            package_name: package.clone(),
                        });
                        tracing::warn!(
                            enqueued = summary.prefetches_enqueued,
                            budget = self.max_prefetches_per_tick,
                            "prefetch-tick: per-tick enqueue budget reached; remaining \
                             packages resume next tick",
                        );
                        break 'walk;
                    }
                }

                if names_page_full {
                    // This repo's per-tick package page came back full —
                    // there may be more names beyond it. Stop the ENTIRE
                    // tick here (not just this repo) so the single
                    // cursor resumes this repo's remaining names next
                    // tick: the flattened (repo, package) total order
                    // has exactly one active position, so continuing on
                    // to other repos this tick would either strand this
                    // repo's remainder unrecorded or require tracking
                    // more than one in-flight cursor.
                    summary.cursor = Some(TickCursor::WithinRepo {
                        repository_id: repo.id,
                        package_name: names_page
                            .last()
                            .cloned()
                            .expect("names_page_full implies max_packages_per_repo > 0 names"),
                    });
                    break 'walk;
                }

                summary.cursor = Some(TickCursor::AfterRepo {
                    repository_id: repo.id,
                });
            }

            tracing::info!(
                repos_walked = summary.repos_walked,
                packages_walked = summary.packages_walked,
                prefetches_planned = summary.prefetches_planned,
                prefetches_enqueued = summary.prefetches_enqueued,
                prefetches_deduped = summary.prefetches_deduped,
                budget_exhausted = summary.budget_exhausted,
                skipped_disabled = summary.skipped_disabled,
                skipped_no_trigger = summary.skipped_no_trigger,
                upstream_fetch_errors = summary.upstream_fetch_errors,
                upstream_parse_errors = summary.upstream_parse_errors,
                no_mapping = summary.no_mapping,
                cursor = ?summary.cursor,
                "prefetch-tick complete",
            );

            Ok(TaskOutcome::Completed {
                result_summary: summary.to_json(),
            })
        })
    }
}

/// Synchronous planner invocation. Called inside the `for package`
/// loop after the held-status `await` has completed, so the `&dyn
/// VersionOrdering` it instantiates here never crosses an `await`
/// boundary and the enclosing async block stays `Send`.
fn run_planner_sync(
    prefetch: &PrefetchUseCase,
    repo: &Repository,
    package: &str,
    upstream_versions: &[String],
    held_status: &[(String, QuarantineStatus)],
    ordering: &'static dyn VersionOrdering,
) -> Vec<String> {
    let upstream_refs: Vec<&str> = upstream_versions.iter().map(String::as_str).collect();
    let plan = prefetch.plan(
        repo,
        package,
        PrefetchTrigger::Scheduled,
        &upstream_refs,
        held_status,
        ordering,
    );
    plan.versions
}

/// Map a [`RepositoryFormat`] reference to a Phase-1 [`VersionOrdering`]
/// reference. Returns `None` for formats without a Phase-1 reference
/// ordering (Maven, OCI, generic, etc.). Mirrors the per-format pick at
/// the format-crate serve sites.
fn ordering_for_format(format: &RepositoryFormat) -> Option<&'static dyn VersionOrdering> {
    static NPM: NpmSemverOrdering = NpmSemverOrdering;
    static CARGO: CargoSemverOrdering = NpmSemverOrdering;
    static PEP440: Pep440Ordering = Pep440Ordering;
    match format {
        RepositoryFormat::Npm => Some(&NPM as &dyn VersionOrdering),
        RepositoryFormat::Cargo => Some(&CARGO as &dyn VersionOrdering),
        RepositoryFormat::Pypi => Some(&PEP440 as &dyn VersionOrdering),
        // Maven, OCI, Helm, RPM, Debian, … — Phase-1 has no reference
        // ordering. Phase-2 extends this match.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use hort_domain::types::PageRequest;
    use std::sync::Mutex;

    use chrono::{DateTime, Utc};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::MetricKind;
    use uuid::Uuid;

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{
        IndexMode, PrefetchPolicy, ReplicationPriority, RepositoryType,
    };
    use hort_domain::error::DomainError;
    use hort_domain::events::system_actor;
    use hort_domain::ports::format_handler::{DependencySpec, VersionDiscovery};
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, RepositoryUpstreamMappingArgs, UpstreamAuth,
    };
    use hort_domain::types::Page;

    use crate::use_cases::test_support::{
        MockJobsRepository, MockRepositoryUpstreamMappingRepository, MockUpstreamProxy,
    };

    // ---------- helpers ---------------------------------------------------

    fn test_job_row() -> JobRow {
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        JobRow {
            id: Uuid::nil(),
            kind: "prefetch-tick".to_string(),
            status: JobStatus::Running,
            params: Some(serde_json::Value::Null),
            actor_id: None,
            priority: 0,
            trigger_source: "test".to_string(),
            attempts: 1,
            created_at: now,
            updated_at: now,
            completed_at: None,
            last_error: None,
            result_summary: None,
            kind_fields: KindFields::Other,
        }
    }

    fn make_context() -> TaskContext {
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: test_job_row(),
        }
    }

    fn enabled_scheduled_policy() -> PrefetchPolicy {
        PrefetchPolicy {
            enabled: true,
            triggers: vec![PrefetchTrigger::Scheduled],
            depth: 3,
            transitive_depth: 5,
            max_age_days: None,
            // Production default.
            max_descendants: PrefetchPolicy::default().max_descendants,
        }
    }

    fn repo_with(key: &str, format: RepositoryFormat, policy: PrefetchPolicy) -> Repository {
        Repository {
            id: Uuid::new_v4(),
            key: key.into(),
            name: "Test".into(),
            description: None,
            format,
            repo_type: RepositoryType::Proxy,
            storage_backend: "filesystem".into(),
            storage_path: "/data/repos/test".into(),
            upstream_url: Some("https://example.test".into()),
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode: IndexMode::ReleasedOnly,
            prefetch_policy: policy,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    fn catchall_mapping(repo_id: Uuid) -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping::new(RepositoryUpstreamMappingArgs {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            path_prefix: String::new(),
            upstream_url: "https://registry.example.com".to_string(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        })
        .expect("constructor")
    }

    fn npm_packument_with_versions(versions: &[&str]) -> Vec<u8> {
        let mut s = String::from("{\"name\":\"express\",\"versions\":{");
        let pieces: Vec<String> = versions
            .iter()
            .map(|v| format!("\"{v}\":{{\"dist\":{{\"integrity\":\"sha512-x\"}}}}"))
            .collect();
        s.push_str(&pieces.join(","));
        s.push_str("}}");
        s.into_bytes()
    }

    fn handlers_for_npm() -> HashMap<String, Arc<dyn FormatHandler>> {
        let mut m: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
        m.insert(
            "npm".to_string(),
            Arc::new(NpmHandlerForTests) as Arc<dyn FormatHandler>,
        );
        m
    }

    // ---------- minimal in-crate FormatHandler doubles -------------------
    //
    // hort-app must not import hort-formats (it would create a cycle). For
    // tests we build the smallest format-handler shape that the
    // `extract_upstream_versions` + path-composition code paths consume:
    // `format_key()` + `normalize_name()` + `upstream_checksum_metadata_path()`
    // + `extract_upstream_versions()`. All other trait methods are
    // unused by the handler and inherit the default impl.

    struct NpmHandlerForTests;
    impl FormatHandler for NpmHandlerForTests {
        fn format_key(&self) -> &str {
            "npm"
        }
        fn parse_download_path(
            &self,
            _path: &str,
        ) -> DomainResult<hort_domain::types::ArtifactCoords> {
            unimplemented!()
        }
        fn normalize_name(&self, name: &str) -> String {
            name.to_string()
        }
        fn version_discovery(&self) -> Option<&dyn VersionDiscovery> {
            Some(self)
        }
    }
    impl VersionDiscovery for NpmHandlerForTests {
        fn upstream_metadata_path(&self, package: &str) -> Option<String> {
            Some(format!("/{package}"))
        }
        fn upstream_metadata_accept(&self) -> Vec<String> {
            Vec::new()
        }
        fn extract_upstream_versions(
            &self,
            body: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<String>> {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(body, &mut buf)
                .map_err(|e| DomainError::Validation(e.to_string()))?;
            let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&buf) else {
                return Ok(Vec::new());
            };
            let Some(versions) = doc.get("versions").and_then(|v| v.as_object()) else {
                return Ok(Vec::new());
            };
            Ok(versions.keys().cloned().collect())
        }
        fn extract_dependency_specs(
            &self,
            _content: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<DependencySpec>> {
            Ok(Vec::new())
        }
        fn resolve_range_max(
            &self,
            _range: &str,
            _available: &[&str],
        ) -> DomainResult<Option<String>> {
            Ok(None)
        }
        fn download_config_path(&self) -> Option<String> {
            None
        }
        fn compose_download_url_from_config(
            &self,
            _body: &mut dyn std::io::Read,
            _package: &str,
            _version: &str,
            _cksum_hex: Option<&str>,
        ) -> DomainResult<String> {
            Err(DomainError::Validation(
                "not supported by test double".into(),
            ))
        }
        fn resolve_download_url_from_metadata(
            &self,
            _body: &mut dyn std::io::Read,
            _coords: &hort_domain::types::ArtifactCoords,
        ) -> DomainResult<String> {
            Err(DomainError::Validation(
                "not supported by test double".into(),
            ))
        }
    }

    struct PypiHandlerForTests;
    impl FormatHandler for PypiHandlerForTests {
        fn format_key(&self) -> &str {
            "pypi"
        }
        fn parse_download_path(
            &self,
            _path: &str,
        ) -> DomainResult<hort_domain::types::ArtifactCoords> {
            unimplemented!()
        }
        fn normalize_name(&self, name: &str) -> String {
            name.to_lowercase()
        }
        fn version_discovery(&self) -> Option<&dyn VersionDiscovery> {
            Some(self)
        }
    }
    impl VersionDiscovery for PypiHandlerForTests {
        fn upstream_metadata_path(&self, package: &str) -> Option<String> {
            Some(format!("/simple/{}/", self.normalize_name(package)))
        }
        fn upstream_metadata_accept(&self) -> Vec<String> {
            vec![
                "application/vnd.pypi.simple.v1+json".to_string(),
                "text/html;q=0.5".to_string(),
            ]
        }
        fn extract_upstream_versions(
            &self,
            body: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<String>> {
            // Only the JSON `versions[]` arm is needed for the existing
            // tests below.
            let mut buf = Vec::new();
            std::io::Read::read_to_end(body, &mut buf)
                .map_err(|e| DomainError::Validation(e.to_string()))?;
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&buf) else {
                return Ok(Vec::new());
            };
            let Some(arr) = value.get("versions").and_then(|v| v.as_array()) else {
                return Ok(Vec::new());
            };
            Ok(arr
                .iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect())
        }
        fn extract_dependency_specs(
            &self,
            _content: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<DependencySpec>> {
            Ok(Vec::new())
        }
        fn resolve_range_max(
            &self,
            _range: &str,
            _available: &[&str],
        ) -> DomainResult<Option<String>> {
            Ok(None)
        }
        fn download_config_path(&self) -> Option<String> {
            None
        }
        fn compose_download_url_from_config(
            &self,
            _body: &mut dyn std::io::Read,
            _package: &str,
            _version: &str,
            _cksum_hex: Option<&str>,
        ) -> DomainResult<String> {
            Err(DomainError::Validation(
                "not supported by test double".into(),
            ))
        }
        fn resolve_download_url_from_metadata(
            &self,
            _body: &mut dyn std::io::Read,
            _coords: &hort_domain::types::ArtifactCoords,
        ) -> DomainResult<String> {
            Err(DomainError::Validation(
                "not supported by test double".into(),
            ))
        }
    }

    /// `FormatHandler` whose `extract_upstream_versions` always returns
    /// a Validation error — used to exercise the
    /// `upstream_parse_errors` partition.
    struct AlwaysFailingParserHandler;
    impl FormatHandler for AlwaysFailingParserHandler {
        fn format_key(&self) -> &str {
            "npm"
        }
        fn parse_download_path(
            &self,
            _path: &str,
        ) -> DomainResult<hort_domain::types::ArtifactCoords> {
            unimplemented!()
        }
        fn normalize_name(&self, name: &str) -> String {
            name.to_string()
        }
        fn version_discovery(&self) -> Option<&dyn VersionDiscovery> {
            Some(self)
        }
    }
    impl VersionDiscovery for AlwaysFailingParserHandler {
        fn upstream_metadata_path(&self, package: &str) -> Option<String> {
            Some(format!("/{package}"))
        }
        fn upstream_metadata_accept(&self) -> Vec<String> {
            Vec::new()
        }
        fn extract_upstream_versions(
            &self,
            _body: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<String>> {
            Err(DomainError::Validation("injected parse failure".into()))
        }
        fn extract_dependency_specs(
            &self,
            _content: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<DependencySpec>> {
            Ok(Vec::new())
        }
        fn resolve_range_max(
            &self,
            _range: &str,
            _available: &[&str],
        ) -> DomainResult<Option<String>> {
            Ok(None)
        }
        fn download_config_path(&self) -> Option<String> {
            None
        }
        fn compose_download_url_from_config(
            &self,
            _body: &mut dyn std::io::Read,
            _package: &str,
            _version: &str,
            _cksum_hex: Option<&str>,
        ) -> DomainResult<String> {
            Err(DomainError::Validation(
                "not supported by test double".into(),
            ))
        }
        fn resolve_download_url_from_metadata(
            &self,
            _body: &mut dyn std::io::Read,
            _coords: &hort_domain::types::ArtifactCoords,
        ) -> DomainResult<String> {
            Err(DomainError::Validation(
                "not supported by test double".into(),
            ))
        }
    }

    /// A registered `FormatHandler` that does NOT implement
    /// `VersionDiscovery` (inherits the accessor's `None` default) —
    /// distinct from "no handler registered for the format" (see
    /// `unsupported_format_silently_skips`, which is the `format_handlers`
    /// map lookup missing entirely). This double exercises the newer,
    /// narrower gate: a handler IS registered, but it does not participate
    /// in the capability group, so the per-repo walk must still skip it
    /// rather than reach a method that no longer exists on `FormatHandler`
    /// for a non-participant (issue #58).
    struct NoVersionDiscoveryHandler;
    impl FormatHandler for NoVersionDiscoveryHandler {
        fn format_key(&self) -> &str {
            "maven"
        }
        fn parse_download_path(
            &self,
            _path: &str,
        ) -> DomainResult<hort_domain::types::ArtifactCoords> {
            unimplemented!()
        }
        fn normalize_name(&self, name: &str) -> String {
            name.to_string()
        }
        // `version_discovery` is NOT overridden — inherits `None`.
    }

    // ---------- mock RepositoryRepository --------------------------------
    //
    // `find_by_id` and `list_after` are exercised (the rotation's two
    // read paths); every other method is a `panic!`. Backed by a plain
    // `Vec` (not a one-shot result) so a test can drive the handler
    // across multiple simulated ticks against a stable repo set.

    struct MockRepoRepo {
        repos: Mutex<Vec<Repository>>,
        /// When `Some`, the NEXT `list_after` call returns this error
        /// instead of querying `repos` (one-shot).
        list_after_err: Mutex<Option<DomainError>>,
        /// Recorded `(after, limit)` argument pairs from every
        /// `list_after` call, in call order.
        list_after_calls: Mutex<Vec<(Option<Uuid>, u64)>>,
    }

    impl MockRepoRepo {
        fn returning(rows: Vec<Repository>) -> Self {
            Self {
                repos: Mutex::new(rows),
                list_after_err: Mutex::new(None),
                list_after_calls: Mutex::new(Vec::new()),
            }
        }

        fn failing(err: DomainError) -> Self {
            Self {
                repos: Mutex::new(Vec::new()),
                list_after_err: Mutex::new(Some(err)),
                list_after_calls: Mutex::new(Vec::new()),
            }
        }

        fn list_after_calls(&self) -> Vec<(Option<Uuid>, u64)> {
            self.list_after_calls.lock().unwrap().clone()
        }
    }

    impl RepositoryRepository for MockRepoRepo {
        fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Repository>> {
            let found = self
                .repos
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.id == id)
                .cloned();
            Box::pin(async move {
                found.ok_or_else(|| DomainError::NotFound {
                    entity: "Repository",
                    id: id.to_string(),
                })
            })
        }
        fn find_by_key(&self, _key: &str) -> BoxFuture<'_, DomainResult<Repository>> {
            panic!("find_by_key should not be called by the prefetch-tick handler")
        }
        fn list(
            &self,
            _page: PageRequest,
            _search: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<Page<Repository>>> {
            panic!("list should not be called by the prefetch-tick handler — it rotates via list_after")
        }
        fn list_after(
            &self,
            after: Option<Uuid>,
            limit: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<Repository>>> {
            self.list_after_calls.lock().unwrap().push((after, limit));
            if let Some(err) = self.list_after_err.lock().unwrap().take() {
                return Box::pin(async move { Err(err) });
            }
            let mut sorted: Vec<Repository> = self.repos.lock().unwrap().clone();
            sorted.sort_by_key(|r| r.id);
            let items: Vec<Repository> = sorted
                .into_iter()
                .filter(|r| after.is_none_or(|a| r.id > a))
                .take(limit as usize)
                .collect();
            Box::pin(async move { Ok(items) })
        }
        fn save(&self, _repository: &Repository) -> BoxFuture<'_, DomainResult<()>> {
            panic!("save should not be called by the prefetch-tick handler")
        }
        fn delete(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            panic!("delete should not be called by the prefetch-tick handler")
        }
        fn get_virtual_members(&self, _vid: Uuid) -> BoxFuture<'_, DomainResult<Vec<Repository>>> {
            panic!("get_virtual_members should not be called by the prefetch-tick handler")
        }
        fn add_virtual_member(&self, _v: Uuid, _m: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            panic!("add_virtual_member should not be called by the prefetch-tick handler")
        }
        fn remove_virtual_member(&self, _v: Uuid, _m: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            panic!("remove_virtual_member should not be called by the prefetch-tick handler")
        }
        fn replace_virtual_members(
            &self,
            _v: Uuid,
            _ordered: &[Uuid],
        ) -> BoxFuture<'_, DomainResult<()>> {
            panic!("replace_virtual_members should not be called by the prefetch-tick handler")
        }
        fn get_storage_usage(&self, _r: Uuid) -> BoxFuture<'_, DomainResult<u64>> {
            panic!("get_storage_usage should not be called by the prefetch-tick handler")
        }
        fn save_managed(&self, _r: &Repository, _d: &[u8; 32]) -> BoxFuture<'_, DomainResult<()>> {
            panic!("save_managed should not be called by the prefetch-tick handler")
        }
        fn delete_managed(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
            panic!("delete_managed should not be called by the prefetch-tick handler")
        }
    }

    // ---------- mock ArtifactRepository ----------------------------------

    type PackageStatusMap =
        HashMap<(Uuid, String), Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>>;

    struct MockArtRepo {
        distinct_names: Mutex<HashMap<Uuid, Vec<String>>>,
        per_package_status: Mutex<PackageStatusMap>,
        list_names_err: Mutex<Option<DomainError>>,
        package_status_err: Mutex<Option<DomainError>>,
        /// Every `repository_id` passed to `list_distinct_names_after`,
        /// in call order — a rotation test's window into exactly which
        /// (and how many times each) repo was visited across simulated
        /// ticks, independent of the opaque per-tick summary counters.
        list_distinct_names_after_calls: Mutex<Vec<Uuid>>,
    }

    impl MockArtRepo {
        fn new() -> Self {
            Self {
                distinct_names: Mutex::new(HashMap::new()),
                per_package_status: Mutex::new(HashMap::new()),
                list_names_err: Mutex::new(None),
                package_status_err: Mutex::new(None),
                list_distinct_names_after_calls: Mutex::new(Vec::new()),
            }
        }

        fn list_distinct_names_after_calls(&self) -> Vec<Uuid> {
            self.list_distinct_names_after_calls.lock().unwrap().clone()
        }

        fn with_names(self, repo_id: Uuid, names: Vec<&str>) -> Self {
            self.distinct_names
                .lock()
                .unwrap()
                .insert(repo_id, names.into_iter().map(str::to_string).collect());
            self
        }

        fn with_held(
            self,
            repo_id: Uuid,
            package: &str,
            rows: Vec<(&str, QuarantineStatus)>,
        ) -> Self {
            // The port returns
            // `(version, status, quarantine_until)` triples. The
            // prefetch-tick handler ignores the third element (it strips
            // before passing to the planner — see the handler body), so
            // the mock seeds `None` for `quarantine_until` uniformly.
            self.per_package_status.lock().unwrap().insert(
                (repo_id, package.to_string()),
                rows.into_iter()
                    .map(|(v, s)| (v.to_string(), s, None))
                    .collect(),
            );
            self
        }
    }

    impl ArtifactRepository for MockArtRepo {
        fn find_by_id(
            &self,
            _id: Uuid,
        ) -> BoxFuture<'_, DomainResult<hort_domain::entities::artifact::Artifact>> {
            panic!("find_by_id should not be called by the prefetch-tick handler")
        }
        fn find_by_checksum(
            &self,
            _h: &hort_domain::types::ContentHash,
        ) -> BoxFuture<'_, DomainResult<Option<hort_domain::entities::artifact::Artifact>>>
        {
            panic!("find_by_checksum should not be called by the prefetch-tick handler")
        }
        fn find_by_repo_and_checksum(
            &self,
            _r: Uuid,
            _h: &hort_domain::types::ContentHash,
        ) -> BoxFuture<'_, DomainResult<Option<hort_domain::entities::artifact::Artifact>>>
        {
            panic!("find_by_repo_and_checksum should not be called by the prefetch-tick handler")
        }
        fn list_by_repository(
            &self,
            _r: Uuid,
            _p: PageRequest,
        ) -> BoxFuture<'_, DomainResult<Page<hort_domain::entities::artifact::Artifact>>> {
            panic!("list_by_repository should not be called by the prefetch-tick handler")
        }
        fn delete(
            &self,
            _id: Uuid,
            _actor: hort_domain::events::Actor,
        ) -> BoxFuture<'_, DomainResult<()>> {
            panic!("delete should not be called by the prefetch-tick handler")
        }
        fn find_by_path(
            &self,
            _r: Uuid,
            _p: &str,
        ) -> BoxFuture<'_, DomainResult<Option<hort_domain::entities::artifact::Artifact>>>
        {
            panic!("find_by_path should not be called by the prefetch-tick handler")
        }
        fn list_distinct_names(
            &self,
            _repository_id: Uuid,
            _page: PageRequest,
        ) -> BoxFuture<'_, DomainResult<Page<String>>> {
            panic!(
                "list_distinct_names should not be called by the prefetch-tick handler — \
                 it rotates via list_distinct_names_after"
            )
        }
        fn list_distinct_names_after(
            &self,
            repository_id: Uuid,
            after: Option<&str>,
            limit: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<String>>> {
            self.list_distinct_names_after_calls
                .lock()
                .unwrap()
                .push(repository_id);
            let maybe_err = self.list_names_err.lock().unwrap().take();
            if let Some(err) = maybe_err {
                return Box::pin(async move { Err(err) });
            }
            let mut names: Vec<String> = self
                .distinct_names
                .lock()
                .unwrap()
                .get(&repository_id)
                .cloned()
                .unwrap_or_default();
            names.sort();
            let after = after.map(str::to_string);
            let items: Vec<String> = names
                .into_iter()
                .filter(|n| after.as_deref().is_none_or(|a| n.as_str() > a))
                .take(limit as usize)
                .collect();
            Box::pin(async move { Ok(items) })
        }
        fn find_by_name_in_repo(
            &self,
            _r: Uuid,
            _n: &str,
            _p: PageRequest,
        ) -> BoxFuture<'_, DomainResult<Page<hort_domain::entities::artifact::Artifact>>> {
            panic!("find_by_name_in_repo should not be called by the prefetch-tick handler")
        }
        fn find_by_name_as_published(
            &self,
            _r: Uuid,
            _n: &str,
            _p: PageRequest,
        ) -> BoxFuture<'_, DomainResult<Page<hort_domain::entities::artifact::Artifact>>> {
            panic!("find_by_name_as_published should not be called by the prefetch-tick handler")
        }
        fn list_active_for_repo(
            &self,
            _r: Uuid,
        ) -> BoxFuture<
            '_,
            DomainResult<
                hort_domain::types::LimitedList<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            panic!("list_active_for_repo should not be called by the prefetch-tick handler")
        }
        fn list_rejected_for_policy(
            &self,
            _p: Uuid,
        ) -> BoxFuture<
            '_,
            DomainResult<
                hort_domain::types::LimitedList<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            panic!("list_rejected_for_policy should not be called by the prefetch-tick handler")
        }
        fn list_active_for_policy(
            &self,
            _p: Uuid,
            _page: PageRequest,
        ) -> BoxFuture<'_, DomainResult<Page<hort_domain::entities::artifact::Artifact>>> {
            panic!("list_active_for_policy should not be called by the prefetch-tick handler")
        }
        fn package_version_status(
            &self,
            repository_id: Uuid,
            package: &str,
        ) -> BoxFuture<'_, DomainResult<Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>>>
        {
            let maybe_err = self.package_status_err.lock().unwrap().take();
            if let Some(err) = maybe_err {
                return Box::pin(async move { Err(err) });
            }
            let rows = self
                .per_package_status
                .lock()
                .unwrap()
                .get(&(repository_id, package.to_string()))
                .cloned()
                .unwrap_or_default();
            Box::pin(async move { Ok(rows) })
        }
        fn find_pypi_wheels_without_kind(
            &self,
            _kind: &str,
            _limit: u32,
            _after: Option<Uuid>,
            _skip_marker_kind: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::entities::artifact::Artifact>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn find_oci_image_manifests_without_kind(
            &self,
            _kind: &str,
            _limit: u32,
            _after: Option<Uuid>,
            _skip_marker_kind: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::entities::artifact::Artifact>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn make_handler(
        repos: Arc<MockRepoRepo>,
        arts: Arc<MockArtRepo>,
        proxy: Arc<MockUpstreamProxy>,
        mappings: Arc<MockRepositoryUpstreamMappingRepository>,
        handlers: HashMap<String, Arc<dyn FormatHandler>>,
    ) -> PrefetchTickHandler {
        // Default jobs mock for tests that do not inspect the enqueue path.
        make_handler_with_jobs(
            repos,
            arts,
            proxy,
            mappings,
            handlers,
            Arc::new(MockJobsRepository::default()),
        )
    }

    /// Variant that threads a caller-supplied `MockJobsRepository` so a test
    /// can assert the `enqueue_prefetch_batch` rows / dedup.
    fn make_handler_with_jobs(
        repos: Arc<MockRepoRepo>,
        arts: Arc<MockArtRepo>,
        proxy: Arc<MockUpstreamProxy>,
        mappings: Arc<MockRepositoryUpstreamMappingRepository>,
        handlers: HashMap<String, Arc<dyn FormatHandler>>,
        jobs: Arc<MockJobsRepository>,
    ) -> PrefetchTickHandler {
        PrefetchTickHandler::new(
            repos as Arc<dyn RepositoryRepository>,
            arts as Arc<dyn ArtifactRepository>,
            Arc::new(PrefetchUseCase::new()),
            jobs as Arc<dyn JobsRepository>,
            proxy as Arc<dyn UpstreamProxy>,
            mappings as Arc<dyn RepositoryUpstreamMappingRepository>,
            handlers,
        )
    }

    // =====================================================================
    // kind() returns "prefetch-tick"
    // =====================================================================

    #[test]
    fn kind_returns_prefetch_tick() {
        let repos = Arc::new(MockRepoRepo::returning(Vec::new()));
        let arts = Arc::new(MockArtRepo::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let handler = make_handler(repos, arts, proxy, mappings, HashMap::new());
        assert_eq!(handler.kind(), "prefetch-tick");
    }

    // =====================================================================
    // Empty + disabled-everywhere config yields zero counters.
    // =====================================================================

    #[tokio::test]
    async fn empty_repo_list_yields_all_zero_summary() {
        let repos = Arc::new(MockRepoRepo::returning(Vec::new()));
        let arts = Arc::new(MockArtRepo::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let handler = make_handler(repos, arts, proxy, mappings, HashMap::new());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["repos_walked"], 0);
                assert_eq!(result_summary["packages_walked"], 0);
                assert_eq!(result_summary["prefetches_planned"], 0);
                assert_eq!(result_summary["skipped_disabled"], 0);
                assert_eq!(result_summary["skipped_no_trigger"], 0);
                assert_eq!(result_summary["upstream_fetch_errors"], 0);
                assert_eq!(result_summary["upstream_parse_errors"], 0);
                assert_eq!(result_summary["no_mapping"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn disabled_repo_increments_skipped_disabled_and_does_not_walk_packages() {
        let r1 = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            PrefetchPolicy::default(),
        );
        let r2 = repo_with(
            "npm-mirror-2",
            RepositoryFormat::Npm,
            PrefetchPolicy::default(),
        );
        let repos = Arc::new(MockRepoRepo::returning(vec![r1, r2]));
        let arts = Arc::new(MockArtRepo::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let handler = make_handler(repos, arts, proxy, mappings, handlers_for_npm());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["repos_walked"], 0);
                assert_eq!(result_summary["packages_walked"], 0);
                assert_eq!(result_summary["prefetches_planned"], 0);
                assert_eq!(result_summary["skipped_disabled"], 2);
                assert_eq!(result_summary["skipped_no_trigger"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn enabled_repo_without_scheduled_trigger_skipped_no_trigger() {
        let policy = PrefetchPolicy {
            enabled: true,
            triggers: vec![PrefetchTrigger::OnDistTagMove],
            depth: 3,
            transitive_depth: 5,
            max_age_days: None,
            // Production default.
            max_descendants: PrefetchPolicy::default().max_descendants,
        };
        let r1 = repo_with("npm-mirror", RepositoryFormat::Npm, policy);
        let repos = Arc::new(MockRepoRepo::returning(vec![r1]));
        let arts = Arc::new(MockArtRepo::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let handler = make_handler(repos, arts, proxy, mappings, handlers_for_npm());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["repos_walked"], 0);
                assert_eq!(result_summary["packages_walked"], 0);
                assert_eq!(result_summary["skipped_disabled"], 0);
                assert_eq!(result_summary["skipped_no_trigger"], 1);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unsupported_format_silently_skips() {
        let r = repo_with(
            "maven-mirror",
            RepositoryFormat::Maven,
            enabled_scheduled_policy(),
        );
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(MockArtRepo::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let handler = make_handler(repos, arts, proxy, mappings, handlers_for_npm());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(
                    result_summary["repos_walked"], 0,
                    "Maven is not Phase-1; repo is silently dropped"
                );
                assert_eq!(result_summary["packages_walked"], 0);
                assert_eq!(result_summary["skipped_disabled"], 0);
                assert_eq!(result_summary["skipped_no_trigger"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// Issue #58: distinct from `unsupported_format_silently_skips` (no
    /// `FormatHandler` registered at all) — here a `FormatHandler` IS
    /// registered for the repo's format, but it does not implement
    /// `VersionDiscovery`. The per-repo walk must skip it via the
    /// `handler.version_discovery()` early-return, not reach a method
    /// that no longer exists on `FormatHandler` for a non-participant.
    #[tokio::test]
    async fn registered_handler_without_version_discovery_is_skipped() {
        let r = repo_with(
            "maven-mirror",
            RepositoryFormat::Maven,
            enabled_scheduled_policy(),
        );
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(MockArtRepo::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
        handlers.insert(
            "maven".to_string(),
            Arc::new(NoVersionDiscoveryHandler) as Arc<dyn FormatHandler>,
        );
        let handler = make_handler(repos, arts, proxy, mappings, handlers);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(
                    result_summary["repos_walked"], 0,
                    "a registered handler with no VersionDiscovery participation must be \
                     skipped exactly like a missing handler"
                );
                assert_eq!(result_summary["packages_walked"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn repositories_list_after_failure_returns_failed_retry() {
        let repos = Arc::new(MockRepoRepo::failing(DomainError::Invariant(
            "simulated repositories.list_after failure".into(),
        )));
        let arts = Arc::new(MockArtRepo::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let handler = make_handler(repos, arts, proxy, mappings, HashMap::new());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok — repositories.list_after errors surface via TaskOutcome::Failed");

        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(retry, "list_after failure must retry");
                assert!(
                    reason.contains("repositories.list_after"),
                    "reason should name the failing call: {reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_distinct_names_per_repo_failure_continues_other_repos() {
        let r1 = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repo_id = r1.id;
        let repos = Arc::new(MockRepoRepo::returning(vec![r1]));
        let arts = Arc::new(MockArtRepo::new().with_names(repo_id, vec!["unused"]));
        *arts.list_names_err.lock().unwrap() = Some(DomainError::Invariant(
            "simulated list_distinct_names failure".into(),
        ));
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        mappings
            .upsert(catchall_mapping(repo_id))
            .await
            .expect("upsert");
        let handler = make_handler(repos, arts, proxy, mappings, handlers_for_npm());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["repos_walked"], 1);
                assert_eq!(result_summary["packages_walked"], 0);
                assert_eq!(result_summary["prefetches_planned"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // A real upstream-vs-held divergence walks the planner and ticks
    // `hort_prefetch_enqueued_total{trigger="scheduled"}`.
    //
    // **No fixture-injected divergence at the planner tier** — the test
    // wires the full handler (UpstreamProxy + FormatHandler-by-key +
    // mapping repo) and lets the production code path drive the emission.
    // =====================================================================

    #[test]
    fn handler_emits_enqueued_with_trigger_scheduled_on_real_divergence() {
        // Uses a per-test Runtime + `metrics::with_local_recorder` so
        // the recorder is the active one for every counter tick the
        // handler emits. A `#[tokio::test]` would not let
        // `with_local_recorder` (sync closure) wrap the `run` future
        // — the recorder would be inactive by the time the metric
        // tick fires inside the planner.
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let r = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repo_id = r.id;
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        // Held: only 1.0.0. Upstream: 1.0.0 + 1.1.0 + 1.2.0.
        let arts = Arc::new(
            MockArtRepo::new()
                .with_names(repo_id, vec!["express"])
                .with_held(
                    repo_id,
                    "express",
                    vec![("1.0.0", QuarantineStatus::Released)],
                ),
        );
        let proxy = Arc::new(MockUpstreamProxy::new());
        // npm packument path is `/express` (per
        // `upstream_metadata_path_for`'s npm arm).
        proxy.insert_metadata(
            "",
            "/express",
            npm_packument_with_versions(&["1.0.0", "1.1.0", "1.2.0"]),
        );
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(mappings.upsert(catchall_mapping(repo_id)))
            .expect("upsert");

        let handler = make_handler(repos, arts, proxy, mappings, handlers_for_npm());

        let outcome = metrics::with_local_recorder(&recorder, || {
            rt.block_on(handler.run(&serde_json::Value::Null, make_context()))
        })
        .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["repos_walked"], 1);
                assert_eq!(result_summary["packages_walked"], 1);
                // Two new versions (1.1.0, 1.2.0) clear the depth=3 cap.
                assert_eq!(
                    result_summary["prefetches_planned"], 2,
                    "scheduled tick sees upstream 1.0.0/1.1.0/1.2.0 vs held 1.0.0 — \
                     two new versions planned"
                );
                assert_eq!(result_summary["upstream_fetch_errors"], 0);
                assert_eq!(result_summary["upstream_parse_errors"], 0);
                assert_eq!(result_summary["no_mapping"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }

        let snapshot = snapshotter.snapshot().into_vec();
        let enqueued = snapshot
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_enqueued_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "trigger" && l.value() == "scheduled")
            })
            .expect(
                "hort_prefetch_enqueued_total must fire with trigger=scheduled \
                 from the prefetch-tick handler walking real upstream-vs-held \
                 divergence",
            );
        match &enqueued.3 {
            DebugValue::Counter(c) => {
                assert_eq!(*c, 2, "two new versions emitted = counter = 2");
            }
            other => panic!("expected counter, got {other:?}"),
        }
    }

    // =====================================================================
    // The scheduled tick ENQUEUES `prefetch` leaf rows
    // (`enqueue_prefetch_batch`), it does not merely plan + count.
    // =====================================================================

    /// Acceptance #1: a not-held upstream version on a `[scheduled]` repo
    /// produces a `kind="prefetch"`, `trigger_source="scheduled"` leaf row
    /// (a SEED so the cascade can fire) with a populated `target_key` and
    /// `{repository_id, package, version}` params.
    #[tokio::test]
    async fn scheduled_tick_enqueues_prefetch_leaf_rows_for_not_held_versions() {
        let r = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repo_id = r.id;
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(
            MockArtRepo::new()
                .with_names(repo_id, vec!["express"])
                .with_held(
                    repo_id,
                    "express",
                    vec![("1.0.0", QuarantineStatus::Released)],
                ),
        );
        let proxy = Arc::new(MockUpstreamProxy::new());
        proxy.insert_metadata(
            "",
            "/express",
            npm_packument_with_versions(&["1.0.0", "1.1.0", "1.2.0"]),
        );
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        mappings
            .upsert(catchall_mapping(repo_id))
            .await
            .expect("upsert");
        let jobs = Arc::new(MockJobsRepository::default());
        let handler = make_handler_with_jobs(
            repos,
            arts,
            proxy,
            mappings,
            handlers_for_npm(),
            jobs.clone(),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        let batches = jobs.prefetch_batch_calls();
        assert_eq!(batches.len(), 1, "one cohort batch for the single package");
        let rows = &batches[0];
        assert_eq!(
            rows.len(),
            2,
            "two not-held versions (1.1.0, 1.2.0) enqueued"
        );
        for row in rows {
            assert_eq!(row.kind, "prefetch");
            assert_eq!(
                row.trigger_source, "scheduled",
                "SEED trigger source (not \"prefetch\") so the on-ingest cascade fires"
            );
            assert_eq!(row.priority, 0);
            assert!(!row.target_key.is_empty(), "L3 dedup key must be populated");
            assert_eq!(row.params["repository_id"], serde_json::json!(repo_id));
            assert_eq!(row.params["package"], "express");
        }
        let versions: Vec<&str> = rows
            .iter()
            .map(|r| r.params["version"].as_str().unwrap())
            .collect();
        assert!(
            versions.contains(&"1.1.0") && versions.contains(&"1.2.0"),
            "both new versions present: {versions:?}"
        );

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["prefetches_enqueued"], 2);
                assert_eq!(result_summary["prefetches_deduped"], 0);
                assert_eq!(result_summary["budget_exhausted"], false);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// Acceptance #4/#7: a version already in-flight under `kind='prefetch'`
    /// (same `target_key` the handler computes) is collapsed by the L3
    /// `ON CONFLICT DO NOTHING` — counted `deduped`, not a second row. This
    /// is the cross-tick / cross-cascade dedup the self-service mirror would
    /// NOT have provided.
    #[tokio::test]
    async fn scheduled_tick_dedups_already_inflight_target_key() {
        let r = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repo_id = r.id;
        let format = r.format.to_string();
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(
            MockArtRepo::new()
                .with_names(repo_id, vec!["express"])
                .with_held(
                    repo_id,
                    "express",
                    vec![("1.0.0", QuarantineStatus::Released)],
                ),
        );
        let proxy = Arc::new(MockUpstreamProxy::new());
        proxy.insert_metadata(
            "",
            "/express",
            npm_packument_with_versions(&["1.0.0", "1.1.0", "1.2.0"]),
        );
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        mappings
            .upsert(catchall_mapping(repo_id))
            .await
            .expect("upsert");
        let jobs = Arc::new(MockJobsRepository::default());
        // 1.1.0 already in-flight under the SAME (kind, target_key) the
        // handler will compute → the mock's ON CONFLICT simulation drops it.
        jobs.seed_prefetch_inflight_target_key(
            "prefetch",
            crate::task_handlers::prefetch_target_key(repo_id, &format, "express", "1.1.0"),
        );
        let handler = make_handler_with_jobs(
            repos,
            arts,
            proxy,
            mappings,
            handlers_for_npm(),
            jobs.clone(),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["prefetches_planned"], 2, "both planned");
                assert_eq!(
                    result_summary["prefetches_enqueued"], 1,
                    "1.2.0 inserted; 1.1.0 deduped"
                );
                assert_eq!(
                    result_summary["prefetches_deduped"], 1,
                    "1.1.0 collapsed by ON CONFLICT DO NOTHING"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// Acceptance #6: the per-tick enqueue budget stops the walk between
    /// packages and reports `budget_exhausted`.
    #[tokio::test]
    async fn scheduled_tick_stops_at_per_tick_budget_between_packages() {
        let r = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repo_id = r.id;
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(
            MockArtRepo::new()
                .with_names(repo_id, vec!["alpha", "beta"])
                .with_held(
                    repo_id,
                    "alpha",
                    vec![("1.0.0", QuarantineStatus::Released)],
                )
                .with_held(repo_id, "beta", vec![("1.0.0", QuarantineStatus::Released)]),
        );
        let proxy = Arc::new(MockUpstreamProxy::new());
        proxy.insert_metadata(
            "",
            "/alpha",
            npm_packument_with_versions(&["1.0.0", "1.1.0"]),
        );
        proxy.insert_metadata(
            "",
            "/beta",
            npm_packument_with_versions(&["1.0.0", "1.1.0"]),
        );
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        mappings
            .upsert(catchall_mapping(repo_id))
            .await
            .expect("upsert");
        let jobs = Arc::new(MockJobsRepository::default());
        let mut handler = make_handler_with_jobs(
            repos,
            arts,
            proxy,
            mappings,
            handlers_for_npm(),
            jobs.clone(),
        );
        handler.max_prefetches_per_tick = 1; // stop after the first package's cohort

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        assert_eq!(
            jobs.prefetch_batch_calls().len(),
            1,
            "second package must not be walked once the budget is hit"
        );
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["prefetches_enqueued"], 1);
                assert_eq!(result_summary["budget_exhausted"], true);
                assert_eq!(
                    result_summary["packages_walked"], 1,
                    "walk stopped before the 2nd package"
                );
                // The cursor saves the EXACT stopping point — "alpha"
                // (the package whose enqueue tripped the budget), not a
                // page-1 restart.
                assert_eq!(
                    result_summary["cursor"],
                    serde_json::json!({
                        "position": "within_repo",
                        "repository_id": repo_id,
                        "package_name": "alpha",
                    }),
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// A `enqueue_prefetch_batch` failure is best-effort: logged and the
    /// walk continues to completion (the versions re-plan next tick),
    /// nothing counted as enqueued/deduped.
    #[tokio::test]
    async fn scheduled_tick_continues_on_batch_enqueue_error() {
        let r = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repo_id = r.id;
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(
            MockArtRepo::new()
                .with_names(repo_id, vec!["express"])
                .with_held(
                    repo_id,
                    "express",
                    vec![("1.0.0", QuarantineStatus::Released)],
                ),
        );
        let proxy = Arc::new(MockUpstreamProxy::new());
        proxy.insert_metadata(
            "",
            "/express",
            npm_packument_with_versions(&["1.0.0", "1.1.0"]),
        );
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        mappings
            .upsert(catchall_mapping(repo_id))
            .await
            .expect("upsert");
        let jobs = Arc::new(MockJobsRepository::default());
        jobs.fail_next_prefetch_batch(DomainError::Invariant("jobs down".into()));
        let handler = make_handler_with_jobs(
            repos,
            arts,
            proxy,
            mappings,
            handlers_for_npm(),
            jobs.clone(),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("tick completes despite the enqueue error");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["packages_walked"], 1, "package was walked");
                assert_eq!(result_summary["prefetches_planned"], 1, "1.1.0 planned");
                assert_eq!(
                    result_summary["prefetches_enqueued"], 0,
                    "batch failed → nothing inserted"
                );
                assert_eq!(result_summary["prefetches_deduped"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// When the planner returns no new versions (upstream == held), the
    /// package is walked but no batch is enqueued.
    #[tokio::test]
    async fn scheduled_tick_skips_enqueue_when_nothing_planned() {
        let r = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repo_id = r.id;
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(
            MockArtRepo::new()
                .with_names(repo_id, vec!["express"])
                .with_held(
                    repo_id,
                    "express",
                    vec![("1.0.0", QuarantineStatus::Released)],
                ),
        );
        let proxy = Arc::new(MockUpstreamProxy::new());
        // Upstream offers only the already-held version → nothing newer.
        proxy.insert_metadata("", "/express", npm_packument_with_versions(&["1.0.0"]));
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        mappings
            .upsert(catchall_mapping(repo_id))
            .await
            .expect("upsert");
        let jobs = Arc::new(MockJobsRepository::default());
        let handler = make_handler_with_jobs(
            repos,
            arts,
            proxy,
            mappings,
            handlers_for_npm(),
            jobs.clone(),
        );

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        assert!(
            jobs.prefetch_batch_calls().is_empty(),
            "no batch when nothing is planned"
        );
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["packages_walked"], 1);
                assert_eq!(result_summary["prefetches_planned"], 0);
                assert_eq!(result_summary["prefetches_enqueued"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // Failure-mode partitions: no mapping / fetch error / parse error /
    // package-status error each route into the matching summary counter
    // and the walk continues.
    // =====================================================================

    #[tokio::test]
    async fn no_catchall_mapping_increments_no_mapping_and_skips_repo() {
        let r = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(MockArtRepo::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        // mappings repo returns an empty list — no mapping at all.
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let handler = make_handler(repos, arts, proxy, mappings, handlers_for_npm());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["repos_walked"], 0);
                assert_eq!(result_summary["packages_walked"], 0);
                assert_eq!(result_summary["no_mapping"], 1);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_metadata_failure_increments_upstream_fetch_errors() {
        let r = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repo_id = r.id;
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(MockArtRepo::new().with_names(repo_id, vec!["express"]));
        // proxy has no seeded entry for /express — fetch returns Err.
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        mappings
            .upsert(catchall_mapping(repo_id))
            .await
            .expect("upsert");
        let handler = make_handler(repos, arts, proxy, mappings, handlers_for_npm());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["repos_walked"], 1);
                assert_eq!(result_summary["packages_walked"], 1);
                assert_eq!(result_summary["prefetches_planned"], 0);
                assert_eq!(result_summary["upstream_fetch_errors"], 1);
                assert_eq!(result_summary["upstream_parse_errors"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn extract_upstream_versions_failure_increments_parse_errors() {
        let r = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repo_id = r.id;
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(MockArtRepo::new().with_names(repo_id, vec!["express"]));
        let proxy = Arc::new(MockUpstreamProxy::new());
        proxy.insert_metadata("", "/express", b"any bytes".to_vec());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        mappings
            .upsert(catchall_mapping(repo_id))
            .await
            .expect("upsert");
        let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
        handlers.insert(
            "npm".to_string(),
            Arc::new(AlwaysFailingParserHandler) as Arc<dyn FormatHandler>,
        );

        let handler = make_handler(repos, arts, proxy, mappings, handlers);

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["repos_walked"], 1);
                assert_eq!(result_summary["packages_walked"], 1);
                assert_eq!(result_summary["upstream_parse_errors"], 1);
                assert_eq!(result_summary["upstream_fetch_errors"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn package_status_failure_continues_to_next_package() {
        let r = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repo_id = r.id;
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(MockArtRepo::new().with_names(repo_id, vec!["express"]));
        *arts.package_status_err.lock().unwrap() = Some(DomainError::Invariant(
            "simulated package_version_status failure".into(),
        ));
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        mappings
            .upsert(catchall_mapping(repo_id))
            .await
            .expect("upsert");
        let handler = make_handler(repos, arts, proxy, mappings, handlers_for_npm());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        // package_status failure → packages_walked incremented, no
        // upstream fetch attempted (early-continue in the loop).
        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(result_summary["repos_walked"], 1);
                assert_eq!(result_summary["packages_walked"], 1);
                assert_eq!(result_summary["prefetches_planned"], 0);
                assert_eq!(result_summary["upstream_fetch_errors"], 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    // =====================================================================
    // ordering_for_format pin: npm/cargo/pypi resolve, Maven/OCI don't.
    // =====================================================================

    #[test]
    fn ordering_for_format_supports_npm_cargo_pypi() {
        assert!(ordering_for_format(&RepositoryFormat::Npm).is_some());
        assert!(ordering_for_format(&RepositoryFormat::Cargo).is_some());
        assert!(ordering_for_format(&RepositoryFormat::Pypi).is_some());
    }

    #[test]
    fn ordering_for_format_does_not_support_maven_oci_helm() {
        assert!(ordering_for_format(&RepositoryFormat::Maven).is_none());
        assert!(ordering_for_format(&RepositoryFormat::Oci).is_none());
        assert!(ordering_for_format(&RepositoryFormat::Helm).is_none());
    }

    // =====================================================================
    // FormatHandler::upstream_metadata_path — per-format hot-path
    // equivalence. The handler trait owns the per-format URL
    // convention; these tests pin the
    // PyPI/npm/AlwaysFailing overrides used by the prefetch-tick path.
    // The real hort-formats impls have their own unit tests in
    // crates/hort-formats/src/{npm,cargo,pypi}.rs.
    // =====================================================================

    #[test]
    fn upstream_metadata_path_pypi_uses_simple_index() {
        let handler = PypiHandlerForTests;
        // PypiHandlerForTests.normalize_name lowercases — mirroring
        // PEP 503.
        assert_eq!(
            handler.upstream_metadata_path("Requests"),
            Some("/simple/requests/".to_string()),
        );
    }

    #[test]
    fn upstream_metadata_path_npm_uses_packument() {
        let handler = NpmHandlerForTests;
        assert_eq!(
            handler.upstream_metadata_path("express"),
            Some("/express".to_string()),
        );
    }

    #[test]
    fn upstream_metadata_accept_pypi_negotiates_pep691_json() {
        let accept = PypiHandlerForTests.upstream_metadata_accept();
        assert!(accept
            .iter()
            .any(|a| a.contains("application/vnd.pypi.simple")));
    }

    #[test]
    fn upstream_metadata_accept_npm_empty_deferring_to_upstream_default() {
        assert!(NpmHandlerForTests.upstream_metadata_accept().is_empty());
    }

    // =====================================================================
    // MAX_REPOS_PER_TICK — handler asks list_after for exactly 1000, with
    // no cursor on the very first tick.
    // =====================================================================

    #[tokio::test]
    async fn run_asks_list_after_for_exactly_max_repos_per_tick() {
        let repos = Arc::new(MockRepoRepo::returning(Vec::new()));
        let arts = Arc::new(MockArtRepo::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repos_for_assert = repos.clone();
        let handler = make_handler(repos, arts, proxy, mappings, HashMap::new());

        let _ = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        let calls = repos_for_assert.list_after_calls();
        assert_eq!(calls.len(), 1, "list_after called exactly once");
        assert_eq!(
            calls[0],
            (None, MAX_REPOS_PER_TICK),
            "no cursor yet, full page size"
        );
        assert_eq!(
            MAX_REPOS_PER_TICK, 1000,
            "design pin: MAX_REPOS_PER_TICK = 1000"
        );
        assert_eq!(
            MAX_PACKAGES_PER_REPO, 1000,
            "design pin: MAX_PACKAGES_PER_REPO = 1000"
        );
    }

    // =====================================================================
    // Cross-tick rotation. These fixtures drive the handler across
    // multiple simulated ticks, wiring each tick's `result_summary`
    // into the next tick's `last_result_summary_by_kind` read — exactly
    // what the real dispatcher + a fresh job row do.
    // =====================================================================

    /// Fixture with > `max_repos_per_tick` fully-eligible repos: every
    /// repo is visited within a bounded number of simulated ticks, and
    /// reaching the end of the repo table wraps the walk back to the
    /// beginning instead of starving the tail forever. Each repo is
    /// fully eligible (enabled, `Scheduled` trigger, npm handler, a
    /// catch-all mapping) but carries zero tracked package names, so
    /// `list_distinct_names_after` is reached — and its `repository_id`
    /// argument recorded — for every repo the walk visits, without any
    /// upstream I/O.
    #[tokio::test]
    async fn cross_tick_rotation_covers_every_repo_beyond_the_per_tick_cap() {
        const TOTAL_REPOS: usize = 5;
        let repo_rows: Vec<Repository> = (0..TOTAL_REPOS)
            .map(|i| {
                repo_with(
                    &format!("repo-{i}"),
                    RepositoryFormat::Npm,
                    enabled_scheduled_policy(),
                )
            })
            .collect();
        let all_ids: HashSet<Uuid> = repo_rows.iter().map(|r| r.id).collect();

        let repos = Arc::new(MockRepoRepo::returning(repo_rows.clone()));
        let arts = Arc::new(MockArtRepo::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        for repo in &repo_rows {
            mappings
                .upsert(catchall_mapping(repo.id))
                .await
                .expect("upsert");
        }
        let jobs = Arc::new(MockJobsRepository::default());
        let mut handler = make_handler_with_jobs(
            repos,
            arts.clone(),
            proxy,
            mappings,
            handlers_for_npm(),
            jobs.clone(),
        );
        handler.max_repos_per_tick = 2; // cap well below TOTAL_REPOS

        // ceil(TOTAL_REPOS / cap) ticks already reaches full coverage;
        // a couple of extra ticks are slack against the greedy
        // wrap-fetch (a short post-cursor page immediately spends
        // leftover per-tick budget on the next cycle rather than idling
        // it, so a cycle can finish a tick "early").
        for _ in 0..5 {
            let outcome = handler
                .run(&serde_json::Value::Null, make_context())
                .await
                .expect("Ok");
            let TaskOutcome::Completed { result_summary } = outcome else {
                panic!("expected Completed");
            };
            assert!(
                result_summary["repos_walked"].as_u64().unwrap() > 0,
                "every tick with repos remaining must make progress",
            );
            jobs.set_last_result_summary_by_kind("prefetch-tick", result_summary);
        }

        let visited: HashSet<Uuid> = arts.list_distinct_names_after_calls().into_iter().collect();
        assert_eq!(
            visited, all_ids,
            "every repo must be visited at least once across the rotation"
        );
    }

    /// Fixture with one repo carrying > `max_packages_per_repo` tracked
    /// names: every name is visited across ticks, and the tick after a
    /// full per-tick page resumes at the saved cursor — not at page 1.
    #[tokio::test]
    async fn cross_tick_package_rotation_resumes_at_saved_cursor_not_page_one() {
        let r = repo_with(
            "npm-mirror",
            RepositoryFormat::Npm,
            enabled_scheduled_policy(),
        );
        let repo_id = r.id;
        let names: Vec<String> = (0..7).map(|i| format!("pkg-{i}")).collect();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let repos = Arc::new(MockRepoRepo::returning(vec![r]));
        let arts = Arc::new(MockArtRepo::new().with_names(repo_id, name_refs));
        // No upstream metadata is seeded for any package — each walked
        // package fails `fetch_metadata` and is counted
        // `upstream_fetch_errors`, isolating this test to the
        // package-rotation cursor (cap 2) rather than the planner path.
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        mappings
            .upsert(catchall_mapping(repo_id))
            .await
            .expect("upsert");
        let jobs = Arc::new(MockJobsRepository::default());
        let mut handler = make_handler_with_jobs(
            repos,
            arts,
            proxy,
            mappings,
            handlers_for_npm(),
            jobs.clone(),
        );
        handler.max_packages_per_repo = 3; // cap well below the 7 seeded names

        let expected_cursors = [
            serde_json::json!({
                "position": "within_repo", "repository_id": repo_id, "package_name": "pkg-2",
            }),
            serde_json::json!({
                "position": "within_repo", "repository_id": repo_id, "package_name": "pkg-5",
            }),
            serde_json::json!({
                "position": "after_repo", "repository_id": repo_id,
            }),
        ];
        let mut total_packages_walked = 0u64;
        for expected_cursor in expected_cursors {
            let outcome = handler
                .run(&serde_json::Value::Null, make_context())
                .await
                .expect("Ok");
            let TaskOutcome::Completed { result_summary } = outcome else {
                panic!("expected Completed");
            };
            assert_eq!(result_summary["cursor"], expected_cursor);
            total_packages_walked += result_summary["packages_walked"].as_u64().unwrap();
            jobs.set_last_result_summary_by_kind("prefetch-tick", result_summary);
        }
        assert_eq!(
            total_packages_walked,
            names.len() as u64,
            "every name is visited exactly once across the three ticks"
        );
    }

    /// A cursor naming a since-deleted repo degrades gracefully: the
    /// keyset `>` comparison simply resumes at the next existing repo,
    /// rather than erroring or stalling the rotation.
    #[tokio::test]
    async fn deleted_repo_under_cursor_degrades_gracefully() {
        let mut deleted = repo_with("gone", RepositoryFormat::Npm, PrefetchPolicy::default());
        deleted.id = Uuid::from_u128(1);
        let mut next = repo_with("next", RepositoryFormat::Npm, PrefetchPolicy::default());
        next.id = Uuid::from_u128(2);
        let next_id = next.id;

        // `deleted` is NOT in the backing store — simulating it was
        // removed after the cursor was saved pointing at it.
        let repos = Arc::new(MockRepoRepo::returning(vec![next]));
        let arts = Arc::new(MockArtRepo::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let jobs = Arc::new(MockJobsRepository::default());
        jobs.set_last_result_summary_by_kind(
            "prefetch-tick",
            serde_json::json!({
                "cursor": {
                    "position": "within_repo",
                    "repository_id": deleted.id,
                    "package_name": "whatever",
                }
            }),
        );
        let handler =
            make_handler_with_jobs(repos, arts, proxy, mappings, HashMap::new(), jobs.clone());

        let outcome = handler
            .run(&serde_json::Value::Null, make_context())
            .await
            .expect("Ok");

        match outcome {
            TaskOutcome::Completed { result_summary } => {
                assert_eq!(
                    result_summary["skipped_disabled"], 1,
                    "the next existing repo (past the deleted cursor) is still reached"
                );
                assert_eq!(
                    result_summary["cursor"],
                    serde_json::json!({ "position": "after_repo", "repository_id": next_id }),
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }
}
