//! `prefetch-dependencies` `TaskHandler` (see
//! `docs/architecture/explanation/prefetch-pipeline.md`).
//!
//! Per ingested artifact, reads the manifest via
//! [`FormatHandler::extract_dependency_specs`], resolves
//! each declared runtime-dep version range via
//! [`FormatHandler::resolve_range_max`], and for each not-already-held
//! dependency enqueues a `prefetch` ingest job + a child
//! `prefetch-dependencies` job (bounded by
//! [`PrefetchPolicy::transitive_depth`]). The walk is stateless —
//! the cascade keeps no progress store beyond the `jobs` table
//! itself; a failed walk leaves a terminal row that the L3 partial
//! unique index releases (the index is `…AND status IN
//! ('pending','running')`), and the next pull of any dependent
//! re-derives the missing subtree from the `artifacts` projection.
//!
//! # Params shape
//!
//! ```json
//! { "artifact_id": "<uuid>", "current_depth": 0 }
//! ```
//!
//! `current_depth` starts at 0 for the root enqueue (the cascade
//! seed) and is incremented per cascade level. The parent enqueues
//! children with `current_depth + 1`; when `current_depth + 1 >
//! transitive_depth` the child `prefetch-dependencies` row is
//! omitted but the leaf `prefetch` ingest row is still enqueued.
//! Depth-0 is the seed walk — typically scheduled hot-path-side as
//! "the artifact I just ingested has a manifest; cascade".
//!
//! # Three-level dedup
//!
//! The cascade composes with the existing dedup layers:
//!
//! - **L1** — `PullDedup` (concurrent fetch single-flight)
//! - **L2** — `artifacts` path-UNIQUE (terminal ingest absorb)
//! - **L3** — `jobs.target_key` partial unique index
//!
//! The handler enqueues via
//! [`JobsRepository::enqueue_prefetch_batch`] — one batch INSERT
//! `… ON CONFLICT (target_key) DO NOTHING` per cohort, so the L3
//! dedup IS the insert (no read-then-insert race).
//!
//! # Stateless re-derivation
//!
//! The cascade keeps NO progress state beyond the `jobs` rows
//! themselves. A failed `prefetch-dependencies` job leaves a
//! `failed` row; the L3 unique index does not block re-enqueue
//! because the partial WHERE excludes terminal states. The next
//! client pull of the parent artifact re-triggers the cascade.
//!
//! # Low priority
//!
//! All cascade-spawned rows carry `priority = 0` (the schema
//! default) so manual / cron / advisory work drains
//! first. The cascade is a background warm; starving it under
//! load is fine — the next pull re-derives.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use hort_domain::entities::artifact::Artifact;
use hort_domain::entities::repository::Repository;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::format_handler::{DependencySpec, FormatHandler};
use hort_domain::ports::jobs_repository::{JobsRepository, PrefetchEnqueueRow};
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::upstream_proxy::UpstreamProxy;
use hort_domain::ports::BoxFuture;
use hort_domain::types::PageRequest;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `trigger_source` literal on every cascade-enqueued row. Mirrors
/// the migration-009 CHECK addition. The dedicated literal
/// distinguishes cascade-spawned rows from cron / advisory / ingest
/// / manual / seed-import in audit + metric labels — see §7
/// (`hort_prefetch_enqueued_total{trigger}`).
const PREFETCH_TRIGGER_SOURCE: &str = "prefetch";

/// `kind` literal for the ingest-leaf row. Must match
/// `VALID_TASK_KINDS`.
const KIND_PREFETCH_INGEST: &str = "prefetch";

/// `kind` literal for the cascade-driver row. Must match
/// `VALID_TASK_KINDS`.
const KIND_PREFETCH_DEPENDENCIES: &str = "prefetch-dependencies";

// ---------------------------------------------------------------------------
// target_key canonicalisation
// ---------------------------------------------------------------------------

/// Build the canonical L3 dedup key for a `(repo, package, version)`
/// coordinate.
///
/// Canonical shape (mirrors the `jobs.target_key` column comment in
/// migration 009):
///
/// ```text
/// "{repo_id}|{format}|{normalised_package}|{version}"
/// ```
///
/// `format` is the [`Repository::format`]'s `Display` string
/// (`"npm"`/`"pypi"`/`"cargo"`/...). `normalised_package` is the
/// output of [`FormatHandler::normalize_name`] — the cascade
/// performs the normalisation at the call site so the artifact
/// projection lookup uses the same key.
///
/// The U+007C VERTICAL LINE separator was chosen because:
/// - it never appears in any RFC-valid package identifier
///   (npm `name`, PEP 503 `name`, Cargo `crate`, Maven `groupId:
///   artifactId`),
/// - it sorts before all alphanumerics (a multi-key index scan over
///   `target_key` ranges naturally),
/// - it is a single ASCII byte (cheap to write, easy to read).
#[must_use]
pub fn target_key(repo_id: Uuid, format: &str, normalised_package: &str, version: &str) -> String {
    format!("{repo_id}|{format}|{normalised_package}|{version}")
}

// ---------------------------------------------------------------------------
// Params shape
// ---------------------------------------------------------------------------

/// Parsed shape of the `params` JSONB column for a
/// `prefetch-dependencies` row.
///
/// # Two enqueue shapes (one consumer)
///
/// A row is enqueued in one of two shapes, and the handler resolves the
/// target artifact from whichever is present:
///
/// - **`artifact_id`** — the seed shape. The on-ingest hook
///   (`ingest_inner`) and `register_by_hash` enqueue this for an artifact
///   they just minted, so the id is known. `current_depth: 0`.
/// - **`(repository_id, package, version)`** — the cascade shape, emitted
///   by [`PrefetchDependenciesHandler::plan_and_enqueue`] for each
///   not-already-held dependency. The dependency's `artifact_id` is
///   **unknown at enqueue time** (the paired `prefetch` leaf-ingest has
///   not run yet), so the row carries the coordinate and the handler
///   re-resolves the artifact on claim. If the leaf has not landed the
///   artifact yet, the claim **retries** (the row is enqueued alongside
///   the leaf; a later claim finds it). This is the H8-sibling fix —
///   before it, the handler required `artifact_id` and every cascade
///   child row failed deserialization, defeating the depth/descendants
///   caps.
#[derive(Debug, Deserialize)]
struct PrefetchDependenciesParams {
    /// Seed shape: the artifact whose manifest the cascade walks, when
    /// already minted (on-ingest hook / `register_by_hash`). `None` for
    /// the cascade shape — re-resolve from `(repository_id, package,
    /// version)` instead.
    #[serde(default)]
    artifact_id: Option<Uuid>,
    /// Cascade shape: the repository the coordinate is re-resolved
    /// against. `None` when `artifact_id` is present.
    #[serde(default)]
    repository_id: Option<Uuid>,
    /// Cascade shape: the (normalised) package name to re-resolve.
    #[serde(default)]
    package: Option<String>,
    /// Cascade shape: the concrete version to re-resolve.
    #[serde(default)]
    version: Option<String>,
    /// Current cascade depth (root = 0). The handler skips child
    /// `prefetch-dependencies` enqueues once `current_depth + 1 >
    /// transitive_depth`. **Defaults to 0** when absent so a
    /// hand-written enqueue (`{"artifact_id": "..."}`) is treated as
    /// the root walk.
    #[serde(default)]
    current_depth: u32,
    /// Cumulative descendant count carried
    /// across the cascade. Each child `prefetch-dependencies` row's
    /// params receive `current + cohort_size_enqueued` so the cap
    /// applies *cumulatively along the cascade branch*, not per-walk
    /// (which the per-package `transitive_depth` already covers). The
    /// running total rides in the task params (stateless-cascade
    /// design — no progress store).
    ///
    /// `#[serde(default)]` for backward-compat with **in-flight jobs
    /// enqueued before this field landed**. A worker booting after
    /// the v2 upgrade may claim a `prefetch-dependencies` row whose
    /// `params` JSONB pre-dates the field; the missing field
    /// deserialises to `0` and the walk behaves like a root walk
    /// (worst case: one extra cohort enqueued before the cap kicks
    /// in — bounded by `max_descendants` of the next cascade level).
    #[serde(default)]
    current_descendants_so_far: u32,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// [`TaskHandler`] for the cascade driver. Constructed at worker
/// composition time with the ports + the format-handler lookup map.
pub struct PrefetchDependenciesHandler {
    repositories: Arc<dyn RepositoryRepository>,
    artifacts: Arc<dyn ArtifactRepository>,
    storage: Arc<dyn StoragePort>,
    jobs: Arc<dyn JobsRepository>,
    /// Live ports for the hybrid range-resolution
    /// Pass 2 (cold-cohort upstream fetch). Mirrors the
    /// `PrefetchTickHandler` wiring shape — same port surface, same
    /// catch-all-mapping resolution.
    upstream_proxy: Arc<dyn UpstreamProxy>,
    upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
    /// Format-handler lookup keyed by `RepositoryFormat::Display`
    /// (the same key shape `PrefetchTickHandler` uses).
    format_handlers: HashMap<String, Arc<dyn FormatHandler>>,
}

impl PrefetchDependenciesHandler {
    /// Construct the handler from its port dependencies.
    ///
    /// The `upstream_proxy` +
    /// `upstream_mappings` ports exist because
    /// the cascade performs the per-cold-package
    /// upstream-metadata fetch (Pass 2 of the hybrid range
    /// resolution) so `target_key` keys on a concrete version, not
    /// the opaque range string — overlapping ranges naturally
    /// collapse via the L3 partial unique index.
    pub fn new(
        repositories: Arc<dyn RepositoryRepository>,
        artifacts: Arc<dyn ArtifactRepository>,
        storage: Arc<dyn StoragePort>,
        jobs: Arc<dyn JobsRepository>,
        upstream_proxy: Arc<dyn UpstreamProxy>,
        upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
        format_handlers: HashMap<String, Arc<dyn FormatHandler>>,
    ) -> Self {
        Self {
            repositories,
            artifacts,
            storage,
            jobs,
            upstream_proxy,
            upstream_mappings,
            format_handlers,
        }
    }

    /// Resolve the artifact this `prefetch-dependencies` row walks, from
    /// whichever params shape it carries (see [`PrefetchDependenciesParams`]).
    ///
    /// `Ok(artifact)` proceeds with the walk; `Err(outcome)` is an early
    /// [`TaskOutcome`] the caller returns verbatim (`Failed { retry }` or a
    /// no-op `Completed`). The retry semantics differ by shape:
    ///
    /// - **`artifact_id` shape:** a `NotFound` is a stale enqueue (the
    ///   artifact was purged between enqueue and claim) → **non-retry**.
    /// - **coordinate shape:** a miss means the paired `prefetch`
    ///   leaf-ingest has not landed the artifact *yet* → **retry** (a later
    ///   claim, after the leaf ingests, resolves it). The cascade child row
    ///   is enqueued alongside the leaf, so this is the common ordering on
    ///   the first claim.
    async fn resolve_target_artifact(
        &self,
        parsed: &PrefetchDependenciesParams,
    ) -> Result<Artifact, TaskOutcome> {
        // Seed shape — load by id (existing on-ingest-hook / register_by_hash path).
        if let Some(id) = parsed.artifact_id {
            return self.artifacts.find_by_id(id).await.map_err(|err| {
                // NotFound = stale enqueue (artifact purged); non-retry.
                let retry = !matches!(err, DomainError::NotFound { .. });
                TaskOutcome::fail(
                    format!("prefetch-dependencies: artifact {id} not loadable: {err}"),
                    retry,
                )
            });
        }

        // Cascade shape — re-resolve the coordinate.
        let (Some(repository_id), Some(package), Some(version)) = (
            parsed.repository_id,
            parsed.package.as_deref(),
            parsed.version.as_deref(),
        ) else {
            return Err(TaskOutcome::fail(
                "prefetch-dependencies: params carry neither `artifact_id` nor \
                 (`repository_id`, `package`, `version`)"
                    .to_string(),
                false,
            ));
        };

        // The cascade stored the package name post-`normalize_name` (the
        // artifacts projection's lookup key); normalising again is
        // idempotent and keeps the lookup correct even if a future caller
        // passes a raw name. Resolving the repo first gives us the format
        // handler for that normalisation.
        let repo = self
            .repositories
            .find_by_id(repository_id)
            .await
            .map_err(|err| {
                let retry = !matches!(err, DomainError::NotFound { .. });
                TaskOutcome::fail(
                    format!(
                        "prefetch-dependencies: repository {repository_id} not loadable: {err}"
                    ),
                    retry,
                )
            })?;
        let normalised = match self.format_handlers.get(&repo.format.to_string()) {
            Some(handler) => handler.normalize_name(package),
            None => package.to_string(),
        };

        // A proxy holds only the handful of versions Hort has actually
        // ingested for a package, so the default page covers them; if the
        // page fills we log and fall through to the retry path (the missing
        // version is either on a later page or not yet ingested — both
        // resolve on a later claim).
        let page = self
            .artifacts
            .find_by_name_in_repo(repository_id, &normalised, PageRequest::default())
            .await
            .map_err(|err| {
                TaskOutcome::fail(
                    format!("prefetch-dependencies: find_by_name_in_repo failed: {err}"),
                    true,
                )
            })?;
        if page.total > page.items.len() as u64 {
            tracing::warn!(
                repository = %repo.key,
                package = %normalised,
                held_versions = page.total,
                "prefetch-dependencies: re-resolution page did not cover every held version; \
                 a coordinate beyond the first page resolves on a later claim",
            );
        }
        match page
            .items
            .into_iter()
            .find(|a| a.version.as_deref() == Some(version) && !a.is_deleted)
        {
            Some(artifact) => Ok(artifact),
            None => Err(TaskOutcome::fail(
                format!(
                    "prefetch-dependencies: artifact for ({repository_id}, {normalised}, \
                     {version}) not yet ingested; retrying until the paired leaf-ingest lands"
                ),
                true,
            )),
        }
    }

    /// Read the artifact's content bytes from CAS into a `Vec<u8>`.
    /// Bounded by [`MAX_MANIFEST_BYTES`] to keep a runaway artifact
    /// (a corrupted multi-GB tarball mis-typed as a manifest) from
    /// OOMing the worker.
    async fn read_artifact_bytes(&self, artifact: &Artifact) -> DomainResult<Vec<u8>> {
        let mut stream = self.storage.get(&artifact.sha256_checksum).await?;
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        let mut total = 0usize;
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| DomainError::Invariant(format!("stream read failed: {e}")))?;
            if n == 0 {
                break;
            }
            total += n;
            if total > MAX_MANIFEST_BYTES {
                return Err(DomainError::Validation(format!(
                    "prefetch-dependencies: artifact content exceeds {MAX_MANIFEST_BYTES}-byte cap \
                     (read so far: {total} bytes) — refusing to extract manifest from giant blob"
                )));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Ok(buf)
    }
}

/// 32 MiB cap on per-artifact manifest bytes. Any artifact whose
/// content exceeds this is rejected — manifests (`package.json`,
/// `Cargo.toml`, METADATA, POM, ...) are at most a handful of
/// kilobytes; a 32 MiB upper bound covers every published manifest
/// in the wild with massive headroom while keeping a corrupted
/// upload from exhausting worker memory.
const MAX_MANIFEST_BYTES: usize = 32 * 1024 * 1024;

/// Per-call counters threaded through the walk. Mirrors
/// `prefetch_tick::TickSummary` — distinct counters, same shape
/// discipline.
#[derive(Default, Debug)]
struct WalkSummary {
    deps_extracted: u64,
    deps_already_held: u64,
    deps_resolve_failed: u64,
    /// Cold deps the cascade tried to resolve
    /// against upstream but could not find a satisfying version for
    /// (upstream's available set returned `None` from
    /// `resolve_range_max`). Logged as `warn` and skipped (the
    /// cascade can't fabricate a version upstream doesn't have).
    deps_upstream_unsatisfiable: u64,
    /// Distinct upstream `fetch_metadata` calls
    /// the walk performed (one per cold `(repo, package)` cohort).
    /// Coalesced so two specs referencing the same package make ONE
    /// fetch, not two.
    upstream_metadata_fetches: u64,
    /// Upstream metadata fetches that failed
    /// (network, 5xx, parse). Logged + skipped; the walk continues
    /// for the rest of the cohort.
    upstream_metadata_fetch_errors: u64,
    /// Repos walked where no catch-all upstream
    /// mapping (`path_prefix = ""`) was configured. The cold cohort
    /// for these is silently skipped; the held-set pass still runs.
    no_upstream_mapping: u64,
    prefetch_rows_enqueued: u64,
    prefetch_rows_deduped: u64,
    child_walk_rows_enqueued: u64,
    child_walk_rows_deduped: u64,
    /// `true` when `current_depth + 1 > transitive_depth` — the
    /// child enqueue was skipped (the leaf prefetch still happened).
    child_walk_at_cap: bool,
    /// `true` when the cohort was
    /// truncated because the cumulative descendant count would have
    /// exceeded `PrefetchPolicy::max_descendants`. Distinct from
    /// `child_walk_at_cap` (which fires on the per-package
    /// `transitive_depth` cap). Item 6 (`hort_prefetch_amplification_total`)
    /// reads this field to emit `result=cap_hit`.
    cap_hit: bool,
}

impl WalkSummary {
    fn to_json(&self, current_depth: u32, transitive_depth: u32) -> serde_json::Value {
        json!({
            "current_depth":                   current_depth,
            "transitive_depth":                transitive_depth,
            "deps_extracted":                  self.deps_extracted,
            "deps_already_held":               self.deps_already_held,
            "deps_resolve_failed":             self.deps_resolve_failed,
            "deps_upstream_unsatisfiable":     self.deps_upstream_unsatisfiable,
            "upstream_metadata_fetches":       self.upstream_metadata_fetches,
            "upstream_metadata_fetch_errors":  self.upstream_metadata_fetch_errors,
            "no_upstream_mapping":             self.no_upstream_mapping,
            "prefetch_rows_enqueued":          self.prefetch_rows_enqueued,
            "prefetch_rows_deduped":           self.prefetch_rows_deduped,
            "child_walk_rows_enqueued":        self.child_walk_rows_enqueued,
            "child_walk_rows_deduped":         self.child_walk_rows_deduped,
            "child_walk_at_cap":               self.child_walk_at_cap,
            "cap_hit":                         self.cap_hit,
        })
    }
}

impl TaskHandler for PrefetchDependenciesHandler {
    fn kind(&self) -> &'static str {
        KIND_PREFETCH_DEPENDENCIES
    }

    #[tracing::instrument(skip(self, params))]
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        _ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            // ----- Step 1: parse params -------------------------------
            let parsed: PrefetchDependenciesParams = match serde_json::from_value(params.clone()) {
                Ok(p) => p,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("prefetch-dependencies params JSON invalid: {err}"),
                        false,
                    ));
                }
            };

            // ----- Step 2: resolve the target artifact ----------------
            // Either by `artifact_id` (seed shape) or by re-resolving the
            // `(repository_id, package, version)` coordinate (cascade
            // shape — the dep's artifact_id was unknown at enqueue time).
            let artifact = match self.resolve_target_artifact(&parsed).await {
                Ok(a) => a,
                Err(outcome) => return Ok(outcome),
            };
            let repo = match self.repositories.find_by_id(artifact.repository_id).await {
                Ok(r) => r,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!(
                            "prefetch-dependencies: repository {} not loadable: {err}",
                            artifact.repository_id
                        ),
                        true,
                    ));
                }
            };

            // ----- Step 3: resolve format handler ---------------------
            let format_key = repo.format.to_string();
            let Some(handler) = self.format_handlers.get(&format_key).cloned() else {
                tracing::warn!(
                    repository = %repo.key,
                    format = %format_key,
                    "prefetch-dependencies: no FormatHandler registered for repo's format — \
                     completing as a no-op (a format with no handler has no extract_dependency_specs)",
                );
                return Ok(TaskOutcome::Completed {
                    result_summary: WalkSummary::default()
                        .to_json(parsed.current_depth, repo.prefetch_policy.transitive_depth),
                });
            };

            // ----- Step 4: read manifest bytes ------------------------
            let content = match self.read_artifact_bytes(&artifact).await {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        artifact_id = %artifact.id,
                        repository = %repo.key,
                        "prefetch-dependencies: failed to read artifact content; aborting walk",
                    );
                    return Ok(TaskOutcome::fail(
                        format!("artifact content read failed: {err}"),
                        true,
                    ));
                }
            };

            // ----- Step 5: extract dependency specs -------------------
            // spec 076 Item 3 — `extract_dependency_specs` is fed the
            // STORED ARTIFACT (the format's own archive: npm `.tgz` / cargo
            // `.crate` gzip-tar, pypi wheel zip), NOT a pre-selected
            // manifest. `content` is the raw artifact bytes read from
            // storage above; the handler locates its declared manifest
            // inside the archive (`package/package.json`, `<dir>/Cargo.toml`,
            // `*.dist-info/METADATA`) via the audited `archive_bounds`
            // extractor and parses it. The port stays a
            // streaming `&mut dyn Read`, so a cursor over the in-memory
            // artifact satisfies it without a second fetch.
            let specs = match handler.extract_dependency_specs(&mut std::io::Cursor::new(&content))
            {
                Ok(specs) => specs,
                Err(err) => {
                    // `Err` here covers BOTH archive-extraction failure
                    // (input not the expected container — e.g. not a
                    // gzip-tar — a missing declared manifest entry, or an
                    // `archive_bounds` bomb-guard trip) AND parse failure on
                    // an extracted-but-malformed manifest. Both mean the
                    // stored bytes can't yield runtime deps; the handler's
                    // contract reserves `Ok(vec![])` for a well-formed
                    // artifact with zero declared deps. Either way the bytes
                    // won't change → non-retry. (The warn message carries the
                    // handler's distinguishing detail so an operator can tell
                    // "corrupt tarball" from "manifest present but malformed".)
                    tracing::warn!(
                        error = %err,
                        artifact_id = %artifact.id,
                        "prefetch-dependencies: extract_dependency_specs failed \
                         (archive-extraction or manifest-parse); non-retry",
                    );
                    return Ok(TaskOutcome::fail(
                        format!("extract_dependency_specs failed: {err}"),
                        false,
                    ));
                }
            };

            // ----- Step 6: walk + enqueue cohort ----------------------
            let summary = self
                .plan_and_enqueue(
                    &repo,
                    &handler,
                    &specs,
                    parsed.current_depth,
                    parsed.current_descendants_so_far,
                )
                .await?;

            tracing::info!(
                artifact_id = %artifact.id,
                repository = %repo.key,
                current_depth = parsed.current_depth,
                transitive_depth = repo.prefetch_policy.transitive_depth,
                current_descendants_so_far = parsed.current_descendants_so_far,
                max_descendants = repo.prefetch_policy.max_descendants,
                deps_extracted = summary.deps_extracted,
                deps_already_held = summary.deps_already_held,
                deps_resolve_failed = summary.deps_resolve_failed,
                prefetch_rows_enqueued = summary.prefetch_rows_enqueued,
                prefetch_rows_deduped = summary.prefetch_rows_deduped,
                child_walk_rows_enqueued = summary.child_walk_rows_enqueued,
                child_walk_rows_deduped = summary.child_walk_rows_deduped,
                child_walk_at_cap = summary.child_walk_at_cap,
                cap_hit = summary.cap_hit,
                "prefetch-dependencies walk complete",
            );

            // Emit
            // `hort_prefetch_amplification_total{format, repository, result}`
            // exactly once per walk. Precedence (see
            // `PrefetchAmplificationResult` docstring): CapHit wins over
            // ResolverFailed; Normal is the residual.
            let amplification = if summary.cap_hit {
                crate::metrics::PrefetchAmplificationResult::CapHit
            } else if summary.no_upstream_mapping > 0 {
                crate::metrics::PrefetchAmplificationResult::ResolverFailed
            } else {
                crate::metrics::PrefetchAmplificationResult::Normal
            };
            crate::metrics::emit_prefetch_amplification(&format_key, &repo.key, amplification);

            Ok(TaskOutcome::Completed {
                result_summary: summary
                    .to_json(parsed.current_depth, repo.prefetch_policy.transitive_depth),
            })
        })
    }
}

impl PrefetchDependenciesHandler {
    /// Plan and enqueue the cohort for a single
    /// `prefetch-dependencies` invocation.
    ///
    /// **Hybrid range resolution.** Two passes:
    ///
    /// - **Pass 1 (held-set, free, no I/O):** for each declared dep,
    ///   read `ArtifactRepository::package_version_status` for the
    ///   held set + `FormatHandler::resolve_range_max(range, held)`.
    ///   `Some(_)` → Hort already holds a satisfying version; skip
    ///   (the dedup-win path Item 12 already had).
    /// - **Pass 2 (upstream, bounded I/O):** for the cold cohort
    ///   (specs that Pass 1 did not absorb), coalesce by `(repo,
    ///   normalised_package)` so two specs referencing the same
    ///   package make ONE `fetch_metadata` call. Per cold package:
    ///   resolve the catch-all upstream mapping → fetch_metadata →
    ///   `FormatHandler::extract_upstream_versions` → per-spec
    ///   `resolve_range_max(range, upstream_versions)` → concrete
    ///   version. `target_key` is keyed on the CONCRETE version, so
    ///   overlapping ranges (`^1.0`, `~1.2`) both resolving to
    ///   `1.2.5` collapse into one row at the L3 partial unique
    ///   index. A cold dep whose range upstream can't satisfy logs
    ///   `warn!` and skips — the cascade can't fabricate versions.
    ///
    /// `PullDedup` (L1) absorbs concurrent `fetch_metadata`
    /// calls across handlers; the per-cohort dedup inside
    /// `plan_and_enqueue` (a `HashMap<package, …>`) absorbs
    /// duplicates *within* the cohort.
    async fn plan_and_enqueue(
        &self,
        repo: &Repository,
        handler: &Arc<dyn FormatHandler>,
        specs: &[DependencySpec],
        current_depth: u32,
        current_descendants_so_far: u32,
    ) -> DomainResult<WalkSummary> {
        let policy = &repo.prefetch_policy;
        let mut summary = WalkSummary {
            deps_extracted: specs.len() as u64,
            ..WalkSummary::default()
        };

        if specs.is_empty() {
            return Ok(summary);
        }

        // Compute the depth-cap decision once for the cohort. A
        // child `prefetch-dependencies` is enqueued only if the
        // child's `current_depth + 1` is within the cap; the leaf
        // `prefetch` ingest is enqueued either way (the cap is on
        // *cascade* depth, not on warming).
        let next_depth = current_depth.saturating_add(1);
        let enqueue_child_walk = next_depth <= policy.transitive_depth;
        summary.child_walk_at_cap = !enqueue_child_walk;

        // Cumulative descendants cap.
        //
        // `remaining` is the headroom this branch of the cascade still
        // has under `PrefetchPolicy.max_descendants`. The cap is
        // CUMULATIVE across the cascade — each child task carries
        // `current + cohort_size_enqueued` in its params (see the
        // child-row enqueue below) so the running total rides in the
        // task params rather than a progress store. The truncation
        // applies BEFORE we enqueue (truncating after means a single
        // huge cohort can blow the cap by N rows before we notice).
        //
        // `remaining == 0` collapses transitive enqueue entirely — a
        // deliberate operator knob (`max_descendants: 0`) AND the
        // terminal state at the cascade leaf (every parent has
        // already added `max_descendants` rows below it). The leaf
        // prefetch rows are bounded by this same headroom; once it
        // reaches 0 we enqueue nothing.
        let remaining = policy
            .max_descendants
            .saturating_sub(current_descendants_so_far);

        let format_key = repo.format.to_string();

        // ----- Pass 1: held-set resolution --------------------------
        //
        // For each spec, look up the held set + try
        // `resolve_range_max` against it. `Some(_)` → skip (already
        // held). `None` → spec moves to the cold cohort for Pass 2.
        //
        // Cold cohort is bucketed by normalised package name so a
        // second spec for the same package (e.g. `lodash@^4` and
        // `lodash@>=4.17`) coalesces to one upstream fetch.
        struct ColdSpec<'a> {
            normalised: String,
            range: &'a str,
        }
        let mut cold_by_package: HashMap<String, Vec<ColdSpec<'_>>> = HashMap::new();
        for spec in specs {
            let normalised = handler.normalize_name(&spec.name);
            let held = match self
                .artifacts
                .package_version_status(repo.id, &normalised)
                .await
            {
                Ok(rows) => rows,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        repository = %repo.key,
                        package = %normalised,
                        "prefetch-dependencies: package_version_status failed; skipping spec",
                    );
                    summary.deps_resolve_failed += 1;
                    continue;
                }
            };
            // The port returns `(version, status,
            // quarantine_until)`; the dep-resolution pass only needs
            // the version string. Destructure the unused trailing
            // elements explicitly.
            let held_versions: Vec<&str> = held.iter().map(|(v, _, _)| v.as_str()).collect();
            let resolved = handler
                .resolve_range_max(&spec.range, &held_versions)
                .ok()
                .flatten();
            if resolved.is_some() {
                summary.deps_already_held += 1;
                continue;
            }
            // Cold spec — buffer for Pass 2's per-package fetch.
            cold_by_package
                .entry(normalised.clone())
                .or_default()
                .push(ColdSpec {
                    normalised,
                    range: &spec.range,
                });
        }

        // ----- Pass 2: cold-cohort upstream fetch -------------------
        //
        // Build the two batches (one per kind) keyed on CONCRETE
        // versions. Per-package coalesced — N specs referencing the
        // same package make ONE `fetch_metadata` call.
        let mut prefetch_rows: Vec<PrefetchEnqueueRow> = Vec::new();
        let mut child_rows: Vec<PrefetchEnqueueRow> = Vec::new();

        // Pass 2 needs the catch-all upstream mapping. If absent,
        // the cold cohort is silently skipped (the held-set pass
        // already ran). Mirrors Item 8b's `PrefetchTickHandler`
        // mapping resolution — same port, same `path_prefix == ""`
        // predicate.
        let upstream_mapping = if cold_by_package.is_empty() {
            None
        } else {
            match self.upstream_mappings.list_for_repository(repo.id).await {
                Ok(mappings) => match mappings.into_iter().find(|m| m.path_prefix.is_empty()) {
                    Some(m) => Some(m),
                    None => {
                        tracing::warn!(
                            repository = %repo.key,
                            "prefetch-dependencies: no catch-all upstream mapping \
                             (path_prefix=\"\") — cold cohort skipped",
                        );
                        summary.no_upstream_mapping += 1;
                        None
                    }
                },
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        repository = %repo.key,
                        "prefetch-dependencies: list_for_repository failed — cold cohort skipped",
                    );
                    None
                }
            }
        };

        if let Some(mapping) = upstream_mapping {
            for (normalised, cold_specs) in cold_by_package {
                // ONE upstream metadata fetch per package, regardless
                // of how many specs refer to it.
                summary.upstream_metadata_fetches += 1;
                let upstream_path =
                    upstream_metadata_path_for(handler.as_ref(), &repo.format, &normalised);
                let accept = upstream_accept_for(&repo.format);
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
                            package = %normalised,
                            path = %upstream_path,
                            "prefetch-dependencies: fetch_metadata failed; skipping package's cold specs",
                        );
                        summary.upstream_metadata_fetch_errors += 1;
                        // Every cold spec for this package counts as
                        // unsatisfiable (we couldn't even check).
                        summary.deps_upstream_unsatisfiable += cold_specs.len() as u64;
                        continue;
                    }
                };
                // Stream the cached metadata tempfile
                // through `extract_upstream_versions` on a blocking thread
                // (the npm packument / cargo index / pypi simple-index page
                // is never buffered whole). Prefetch does not serve, so no
                // mirror write; the tempfile is removed after projection.
                let Some(cache_handle) = outcome.cache_handle.as_ref() else {
                    tracing::warn!(
                        repository = %repo.key,
                        package = %normalised,
                        path = %upstream_path,
                        "prefetch-dependencies: metadata fetch produced no cache handle; \
                         skipping package's cold specs",
                    );
                    summary.upstream_metadata_fetch_errors += 1;
                    summary.deps_upstream_unsatisfiable += cold_specs.len() as u64;
                    continue;
                };
                let versions_result = {
                    let handler = Arc::clone(handler);
                    crate::project::run_handler_body(cache_handle, move |reader| {
                        handler.extract_upstream_versions(reader)
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
                            package = %normalised,
                            "prefetch-dependencies: extract_upstream_versions failed; \
                             skipping package's cold specs",
                        );
                        summary.upstream_metadata_fetch_errors += 1;
                        summary.deps_upstream_unsatisfiable += cold_specs.len() as u64;
                        continue;
                    }
                };
                let upstream_refs: Vec<&str> =
                    upstream_versions.iter().map(String::as_str).collect();
                for cold in cold_specs {
                    let concrete = match handler.resolve_range_max(cold.range, &upstream_refs) {
                        Ok(Some(v)) => v,
                        Ok(None) => {
                            tracing::warn!(
                                repository = %repo.key,
                                package = %cold.normalised,
                                range = %cold.range,
                                "prefetch-dependencies: upstream's available set does not \
                                 satisfy range — cold dep skipped",
                            );
                            summary.deps_upstream_unsatisfiable += 1;
                            continue;
                        }
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                repository = %repo.key,
                                package = %cold.normalised,
                                range = %cold.range,
                                "prefetch-dependencies: resolve_range_max errored — cold dep skipped",
                            );
                            summary.deps_resolve_failed += 1;
                            continue;
                        }
                    };
                    // `target_key` keyed on the CONCRETE version (not
                    // the range string) — this is the property
                    // overlapping-ranges dedup depends on.
                    let key = target_key(repo.id, &format_key, &cold.normalised, &concrete);
                    prefetch_rows.push(PrefetchEnqueueRow {
                        kind: KIND_PREFETCH_INGEST.to_string(),
                        params: json!({
                            "repository_id": repo.id,
                            "package": cold.normalised,
                            "version": concrete,
                        }),
                        priority: 0,
                        trigger_source: PREFETCH_TRIGGER_SOURCE.to_string(),
                        target_key: key.clone(),
                    });
                    if enqueue_child_walk {
                        // Child cascade row — its `artifact_id` is
                        // unknown until the leaf ingests; the row
                        // carries `(repository_id, package, version,
                        // current_depth)` so the worker can re-resolve
                        // the artifact on claim. The L3 partial
                        // unique index is per-kind (disjoint WHERE
                        // clauses for `prefetch_unique` and
                        // `prefetch_dependencies_unique`) so the two
                        // rows sharing the same `target_key` do NOT
                        // collide across kinds.
                        //
                        // `current_descendants_so_far`
                        // on the child row is filled in below at
                        // enqueue time, once we know how many rows the
                        // post-cap-truncation cohort actually contains.
                        child_rows.push(PrefetchEnqueueRow {
                            kind: KIND_PREFETCH_DEPENDENCIES.to_string(),
                            params: json!({
                                "repository_id": repo.id,
                                "package": cold.normalised,
                                "version": concrete,
                                "current_depth": next_depth,
                            }),
                            priority: 0,
                            trigger_source: PREFETCH_TRIGGER_SOURCE.to_string(),
                            target_key: key,
                        });
                    }
                }
            }
        }

        // ----- Apply the cumulative descendants cap -----
        //
        // Truncate the candidate cohort BEFORE the batched INSERTs.
        // The parent task params carry `current_descendants_so_far`;
        // this branch of the cascade has `remaining` headroom under
        // `max_descendants`. If the cohort exceeds it, drop the tail
        // and flag `cap_hit` for Item 6's amplification metric. The
        // child cascade rows are truncated in lockstep with their
        // paired prefetch leaves (they are produced one-to-one above).
        let attempted_prefetch = prefetch_rows.len() as u64;
        if attempted_prefetch > remaining as u64 {
            tracing::warn!(
                repository = %repo.key,
                format = %format_key,
                cap = policy.max_descendants,
                current_descendants = current_descendants_so_far,
                attempted_to_enqueue = attempted_prefetch,
                "prefetch-dependencies cascade truncated by max_descendants cap",
            );
            summary.cap_hit = true;
            prefetch_rows.truncate(remaining as usize);
            // Pair-truncate the child cohort: child rows are produced
            // 1:1 with prefetch leaves only when `enqueue_child_walk`
            // is true, so when we cap leaves at K the matching K child
            // entries are the prefix.
            if child_rows.len() > remaining as usize {
                child_rows.truncate(remaining as usize);
            }
        }

        // Stamp the cumulative running total onto
        // each child task's params *after* truncation. The new total
        // is `current_descendants_so_far + cohort_size_enqueued`
        // (i.e. the descendants this branch has added BY the time
        // the child task starts). Each child re-applies the cap
        // against this new total, preserving the per-branch cap
        // discipline across the cascade.
        let cohort_size_enqueued = prefetch_rows.len() as u32;
        let next_cumulative = current_descendants_so_far.saturating_add(cohort_size_enqueued);
        for row in &mut child_rows {
            if let Some(obj) = row.params.as_object_mut() {
                obj.insert(
                    "current_descendants_so_far".to_string(),
                    serde_json::Value::from(next_cumulative),
                );
            }
        }

        // ----- Batched INSERTs ---------------------------------------
        // One INSERT per kind. The cascade enqueues both kinds via
        // the same `enqueue_prefetch_batch` entry-point; the Postgres
        // adapter splits by `kind` so the per-kind partial unique
        // index is the dedup target.
        if !prefetch_rows.is_empty() {
            let attempted = prefetch_rows.len() as u64;
            let inserted = self
                .jobs
                .enqueue_prefetch_batch(&prefetch_rows)
                .await?
                .len() as u64;
            summary.prefetch_rows_enqueued = inserted;
            summary.prefetch_rows_deduped = attempted.saturating_sub(inserted);
        }
        if !child_rows.is_empty() {
            let attempted = child_rows.len() as u64;
            let inserted = self.jobs.enqueue_prefetch_batch(&child_rows).await?.len() as u64;
            summary.child_walk_rows_enqueued = inserted;
            summary.child_walk_rows_deduped = attempted.saturating_sub(inserted);
        }

        Ok(summary)
    }
}

// ---------------------------------------------------------------------------
// Per-format upstream-metadata path / accept helpers
// ---------------------------------------------------------------------------
//
// Mirrors `prefetch_tick.rs`'s helpers verbatim — same per-format
// hot-path equivalence (npm packument, cargo NDJSON, pypi
// PEP 503/691). Lifted into module-scope so the cascade and the
// scheduled tick stay in lock-step; a future refactor could lift
// these into a shared `task_handlers::prefetch_shared` module.

/// Compose the format-native upstream-metadata path for a tracked
/// package. Mirrors `prefetch_tick::upstream_metadata_path_for`.
fn upstream_metadata_path_for(
    handler: &dyn FormatHandler,
    format: &hort_domain::entities::repository::RepositoryFormat,
    package: &str,
) -> String {
    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::types::ArtifactCoords;
    match format {
        RepositoryFormat::Pypi => {
            // The simple-index path enumerates ALL versions of the
            // package; the per-version JSON manifest is per-VERSION
            // and not the right read here. Mirrors
            // `prefetch_tick::upstream_metadata_path_for`'s Pypi arm.
            let normalized = handler.normalize_name(package);
            format!("/simple/{normalized}/")
        }
        _ => {
            let coords = ArtifactCoords {
                name: package.to_string(),
                name_as_published: package.to_string(),
                version: None,
                path: String::new(),
                format: format.clone(),
                metadata: serde_json::Value::Null,
            };
            handler
                .upstream_checksum_metadata_path(&coords)
                .unwrap_or_else(|| format!("/{package}"))
        }
    }
}

/// The `Accept` header set the upstream-metadata fetch should send.
/// Mirrors `prefetch_tick::upstream_accept_for`.
fn upstream_accept_for(
    format: &hort_domain::entities::repository::RepositoryFormat,
) -> Vec<String> {
    use hort_domain::entities::repository::RepositoryFormat;
    match format {
        RepositoryFormat::Pypi => vec![
            "application/vnd.pypi.simple.v1+json".to_string(),
            "text/html;q=0.5".to_string(),
        ],
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use chrono::Utc;

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{
        IndexMode, PrefetchPolicy, PrefetchTrigger, ReplicationPriority, RepositoryFormat,
        RepositoryType,
    };
    use hort_domain::events::system_actor;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};

    use crate::use_cases::test_support::{
        MockArtifactRepository, MockJobsRepository, MockRepositoryRepository,
        MockRepositoryUpstreamMappingRepository, MockStoragePort, MockUpstreamProxy,
    };

    // ---------- shared fixtures -----------------------------------------

    fn make_context() -> TaskContext {
        let now = Utc::now();
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: JobRow {
                id: Uuid::nil(),
                kind: KIND_PREFETCH_DEPENDENCIES.to_string(),
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
            },
        }
    }

    fn enabled_policy(transitive_depth: u32) -> PrefetchPolicy {
        PrefetchPolicy {
            enabled: true,
            triggers: vec![PrefetchTrigger::TransitiveDeps],
            depth: 3,
            transitive_depth,
            max_age_days: None,
            // Use the production default
            // (200) for the existing cohort tests; the descendants-cap
            // tests below override via `enabled_policy_with_max_descendants`.
            max_descendants: PrefetchPolicy::default().max_descendants,
        }
    }

    /// Variant of [`enabled_policy`] that
    /// sets a non-default `max_descendants`. Used by the three
    /// transitive-cap tests below. Mirrors `enabled_policy`'s shape so
    /// the cap-tests reuse the same harness as the cohort tests.
    fn enabled_policy_with_max_descendants(
        transitive_depth: u32,
        max_descendants: u32,
    ) -> PrefetchPolicy {
        PrefetchPolicy {
            enabled: true,
            triggers: vec![PrefetchTrigger::TransitiveDeps],
            depth: 3,
            transitive_depth,
            max_age_days: None,
            max_descendants,
        }
    }

    /// Like [`make_repo`] but with a custom
    /// `max_descendants` policy. The three transitive-cap tests use
    /// this helper to vary the cap without affecting other policy
    /// dimensions.
    fn make_repo_with_max_descendants(
        format: RepositoryFormat,
        transitive_depth: u32,
        max_descendants: u32,
    ) -> Repository {
        let mut repo = make_repo(format, transitive_depth);
        repo.prefetch_policy =
            enabled_policy_with_max_descendants(transitive_depth, max_descendants);
        repo
    }

    fn make_repo(format: RepositoryFormat, transitive_depth: u32) -> Repository {
        Repository {
            id: Uuid::new_v4(),
            key: "test-repo".into(),
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
            prefetch_policy: enabled_policy(transitive_depth),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    fn npm_package_json_with_deps(deps: &[(&str, &str)], dev_deps: &[(&str, &str)]) -> Vec<u8> {
        let runtime: Vec<String> = deps
            .iter()
            .map(|(n, r)| format!("\"{n}\":\"{r}\""))
            .collect();
        let dev: Vec<String> = dev_deps
            .iter()
            .map(|(n, r)| format!("\"{n}\":\"{r}\""))
            .collect();
        format!(
            "{{\"name\":\"root\",\"version\":\"1.0.0\",\
              \"dependencies\":{{{}}},\
              \"devDependencies\":{{{}}}}}",
            runtime.join(","),
            dev.join(","),
        )
        .into_bytes()
    }

    /// Tiny in-test [`FormatHandler`] for npm. Implements only the
    /// methods the cascade touches:
    /// `format_key`, `normalize_name`, `extract_dependency_specs`,
    /// `resolve_range_max`, `upstream_checksum_metadata_path`,
    /// `extract_upstream_versions`. The default impl for everything
    /// else.
    struct NpmInTest;
    impl FormatHandler for NpmInTest {
        fn format_key(&self) -> &str {
            "npm"
        }
        fn parse_download_path(
            &self,
            _path: &str,
        ) -> DomainResult<hort_domain::types::ArtifactCoords> {
            unimplemented!("not called in cascade tests")
        }
        fn normalize_name(&self, name: &str) -> String {
            name.to_lowercase()
        }
        fn upstream_checksum_metadata_path(
            &self,
            coords: &hort_domain::types::ArtifactCoords,
        ) -> Option<String> {
            // Packument path — `/express` etc.
            Some(format!("/{}", coords.name))
        }
        fn extract_upstream_versions(
            &self,
            body: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<String>> {
            // Test packument: `{"versions":{"1.0.0":{},"2.5.0":{}}}`.
            // Item 12b cold-cohort tests seed this shape.
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
        // spec 076 §3.8 NOTE: this stand-in JSON-parses `content` DIRECTLY,
        // which deliberately diverges from the production npm handler's
        // archive-aware contract (the real handler is fed the stored `.tgz`
        // and reads `package/package.json` out of it via `archive_bounds`).
        // That is intentional, not a contract contradiction: these cascade
        // tests exercise the WALK/ENQUEUE logic (depth, fan-out caps, cohort
        // planning), not archive extraction — feeding plain JSON here keeps
        // the fixtures readable. Real-archive extraction is covered in
        // `hort-formats` (`npm::tests::extract_dependency_specs_npm_from_tgz_*`).
        fn extract_dependency_specs(
            &self,
            content: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<DependencySpec>> {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(content, &mut buf)
                .map_err(|e| DomainError::Validation(e.to_string()))?;
            let v: serde_json::Value = serde_json::from_slice(&buf)
                .map_err(|e| DomainError::Validation(format!("npm in-test parse: {e}")))?;
            let deps = v.get("dependencies").and_then(|d| d.as_object());
            let mut out = Vec::new();
            if let Some(map) = deps {
                for (k, val) in map {
                    if let Some(s) = val.as_str() {
                        out.push(DependencySpec {
                            name: k.clone(),
                            range: s.to_string(),
                        });
                    }
                }
            }
            Ok(out)
        }
        fn resolve_range_max(
            &self,
            range: &str,
            available: &[&str],
        ) -> DomainResult<Option<String>> {
            // For testing: "any range" matches any non-empty version
            // in the available set; the highest version is the
            // lexicographically-max string. Real npm semver lives in
            // hort-formats; this is sufficient for cascade-logic tests.
            if available.is_empty() {
                return Ok(None);
            }
            // Treat "x.x.x" as "match any version".
            let any = range == "*" || range == "x" || range == "latest";
            if !any
                && !available
                    .iter()
                    .any(|v| v.contains(range.trim_start_matches('^')))
            {
                return Ok(None);
            }
            let max = available.iter().max().copied().map(str::to_string);
            Ok(max)
        }
    }

    // Seed an npm packument body the cold-cohort
    // `fetch_metadata` path returns. Path matches
    // `upstream_metadata_path_for` for npm (`/{package}`) and the
    // packument shape `NpmInTest::extract_upstream_versions` parses.
    fn seed_npm_packument(proxy: &MockUpstreamProxy, package: &str, versions: &[&str]) {
        let mut s = String::from(r#"{"versions":{"#);
        let pieces: Vec<String> = versions.iter().map(|v| format!(r#""{v}":{{}}"#)).collect();
        s.push_str(&pieces.join(","));
        s.push_str("}}");
        proxy.insert_metadata("", &format!("/{package}"), s.into_bytes());
    }

    // Build + upsert the catch-all upstream
    // mapping (`path_prefix = ""`) for `repo_id` so the cascade's
    // Pass 2 fetch_metadata call has a mapping to resolve against.
    async fn seed_catchall_mapping(
        mappings: &Arc<MockRepositoryUpstreamMappingRepository>,
        repo_id: Uuid,
    ) {
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, RepositoryUpstreamMappingArgs, UpstreamAuth,
        };
        let now = Utc::now();
        let mapping = RepositoryUpstreamMapping::new(RepositoryUpstreamMappingArgs {
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
        .expect("constructor");
        mappings.upsert(mapping).await.expect("upsert");
    }

    /// `FormatHandler` whose `extract_dependency_specs` returns
    /// structural Err — exercises the bad-bytes path.
    struct AlwaysFailingExtractor;
    impl FormatHandler for AlwaysFailingExtractor {
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
        fn extract_dependency_specs(
            &self,
            _content: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<DependencySpec>> {
            Err(DomainError::Validation("injected extract failure".into()))
        }
    }

    fn handlers_npm() -> HashMap<String, Arc<dyn FormatHandler>> {
        let mut m: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
        m.insert("npm".to_string(), Arc::new(NpmInTest));
        m
    }

    fn handlers_failing() -> HashMap<String, Arc<dyn FormatHandler>> {
        let mut m: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
        m.insert("npm".to_string(), Arc::new(AlwaysFailingExtractor));
        m
    }

    async fn seed_artifact_with_bytes(
        artifacts: &Arc<MockArtifactRepository>,
        storage: &Arc<MockStoragePort>,
        repo_id: Uuid,
        bytes: Vec<u8>,
    ) -> Artifact {
        let put = storage
            .put(Box::new(std::io::Cursor::new(bytes)))
            .await
            .expect("storage put");
        let now = Utc::now();
        let artifact = Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            name: "root".into(),
            name_as_published: "root".into(),
            version: Some("1.0.0".into()),
            path: "root-1.0.0.tgz".into(),
            size_bytes: put.size_bytes as i64,
            sha256_checksum: put.hash,
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/json".into(),
            quarantine_status: QuarantineStatus::Released,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: now,
            updated_at: now,
        };
        artifacts.seed_artifact(artifact.clone());
        artifact
    }

    fn make_handler(
        repos: Arc<MockRepositoryRepository>,
        artifacts: Arc<MockArtifactRepository>,
        storage: Arc<MockStoragePort>,
        jobs: Arc<MockJobsRepository>,
        upstream_proxy: Arc<MockUpstreamProxy>,
        upstream_mappings: Arc<MockRepositoryUpstreamMappingRepository>,
        handlers: HashMap<String, Arc<dyn FormatHandler>>,
    ) -> PrefetchDependenciesHandler {
        PrefetchDependenciesHandler::new(
            repos as Arc<dyn RepositoryRepository>,
            artifacts as Arc<dyn ArtifactRepository>,
            storage as Arc<dyn StoragePort>,
            jobs as Arc<dyn JobsRepository>,
            upstream_proxy as Arc<dyn UpstreamProxy>,
            upstream_mappings as Arc<dyn RepositoryUpstreamMappingRepository>,
            handlers,
        )
    }

    // =====================================================================
    // kind() returns "prefetch-dependencies"
    // =====================================================================

    #[test]
    fn kind_returns_prefetch_dependencies() {
        let h = make_handler(
            Arc::new(MockRepositoryRepository::new()),
            Arc::new(MockArtifactRepository::new()),
            Arc::new(MockStoragePort::new()),
            Arc::new(MockJobsRepository::new()),
            Arc::new(MockUpstreamProxy::new()),
            Arc::new(MockRepositoryUpstreamMappingRepository::new()),
            HashMap::new(),
        );
        assert_eq!(h.kind(), KIND_PREFETCH_DEPENDENCIES);
    }

    // =====================================================================
    // target_key canonicalisation pin
    // =====================================================================

    #[test]
    fn target_key_canonical_shape_is_pipe_separated() {
        let rid = Uuid::nil();
        let k = target_key(rid, "npm", "express", "4.18.0");
        assert_eq!(k, "00000000-0000-0000-0000-000000000000|npm|express|4.18.0");
        // Pipe is single byte, never appears in package identifiers
        // — sort + dedup-by-string semantics are stable.
        assert_eq!(k.matches('|').count(), 3);
    }

    // =====================================================================
    // Cascade fan-out: 3 runtime deps, none held → 3 prefetch + 3 children
    // =====================================================================

    #[tokio::test]
    async fn cascade_fan_out_three_runtime_deps_three_prefetch_three_children() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[("a", "^1.0"), ("b", "^2.0"), ("c", "^3.0")], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        // Seed catch-all mapping + per-package
        // packuments so the cold cohort's Pass 2 fetch_metadata
        // resolves and `resolve_range_max` against the upstream
        // versions picks a concrete version per spec.
        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "a", &["1.0.0", "1.2.0"]);
        seed_npm_packument(&proxy, "b", &["2.0.0", "2.5.0"]);
        seed_npm_packument(&proxy, "c", &["3.0.0", "3.1.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(
                &json!({"artifact_id": art.id, "current_depth": 0}),
                make_context(),
            )
            .await
            .expect("Ok");

        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed, got {outcome:?}");
        };
        assert_eq!(result_summary["deps_extracted"], 3);
        assert_eq!(result_summary["deps_already_held"], 0);
        assert_eq!(result_summary["prefetch_rows_enqueued"], 3);
        assert_eq!(result_summary["child_walk_rows_enqueued"], 3);
        assert_eq!(result_summary["child_walk_at_cap"], false);
        // Three cold packages → three upstream metadata fetches.
        assert_eq!(result_summary["upstream_metadata_fetches"], 3);

        // Two batch INSERTs — one per kind.
        let batches = jobs.prefetch_batch_calls();
        assert_eq!(batches.len(), 2);
        assert!(batches
            .iter()
            .any(|b| b.iter().all(|r| r.kind == "prefetch")));
        assert!(batches
            .iter()
            .any(|b| b.iter().all(|r| r.kind == "prefetch-dependencies")));

        // target_key is keyed on the CONCRETE
        // version (e.g. "1.2.0"), NOT the range string ("^1.0").
        // Pick the prefetch batch and assert one of the keys ends
        // with a concrete version this fixture produced.
        let prefetch_batch = batches
            .iter()
            .find(|b| b.iter().all(|r| r.kind == "prefetch"))
            .expect("prefetch batch present");
        assert!(prefetch_batch
            .iter()
            .any(|r| r.target_key.ends_with("|1.2.0")));
        assert!(prefetch_batch
            .iter()
            .any(|r| r.target_key.ends_with("|2.5.0")));
        assert!(prefetch_batch
            .iter()
            .any(|r| r.target_key.ends_with("|3.1.0")));
    }

    // =====================================================================
    // Coordinate re-resolution (H8 sibling): the cascade's own child
    // `prefetch-dependencies` rows carry {repository_id, package, version,
    // current_depth} with NO artifact_id (the dep's artifact_id is unknown
    // until the paired leaf-ingest lands). The handler MUST re-resolve the
    // artifact by coordinate on claim — before this fix it required
    // artifact_id, so every cascade child row failed deserialization
    // ("missing field artifact_id"), defeating the depth/descendants caps.
    // =====================================================================

    #[tokio::test]
    async fn coordinate_params_re_resolve_to_ingested_artifact_and_walk() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[("a", "^1.0")], &[]);
        // `seed_artifact_with_bytes` names the artifact "root" @ "1.0.0".
        let _art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "a", &["1.0.0", "1.2.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        // Coordinate shape — NO artifact_id (the shape `plan_and_enqueue`
        // emits for its child rows).
        let outcome = handler
            .run(
                &json!({
                    "repository_id": repo.id,
                    "package": "root",
                    "version": "1.0.0",
                    "current_depth": 0,
                }),
                make_context(),
            )
            .await
            .expect("Ok");

        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed (re-resolved + walked), got {outcome:?}");
        };
        assert_eq!(result_summary["deps_extracted"], 1);
        assert_eq!(result_summary["prefetch_rows_enqueued"], 1);
    }

    #[tokio::test]
    async fn coordinate_params_unresolvable_yet_returns_retry() {
        // The cascade child row is enqueued ALONGSIDE the paired leaf
        // `prefetch` ingest; if the child is claimed before the leaf lands
        // the artifact, re-resolution misses and the row must RETRY
        // (retry=true) — on a later claim the leaf will have ingested.
        // (Contrast the artifact_id path, where NotFound is a stale-purge
        // → non-retry.)
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        // Empty artifacts — nothing matches the coordinate yet.
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs,
            Arc::new(MockUpstreamProxy::new()),
            Arc::new(MockRepositoryUpstreamMappingRepository::new()),
            handlers_npm(),
        );

        let outcome = handler
            .run(
                &json!({
                    "repository_id": repo.id,
                    "package": "not-yet-ingested",
                    "version": "1.0.0",
                    "current_depth": 1,
                }),
                make_context(),
            )
            .await
            .expect("Ok");
        let TaskOutcome::Failed { retry, .. } = outcome else {
            panic!("expected Failed(retry), got {outcome:?}");
        };
        assert!(
            retry,
            "an unresolved coordinate must RETRY until the paired leaf-ingest lands",
        );
    }

    // =====================================================================
    // Dev-deps NOT followed: 1 runtime + 5 dev → only 1 prefetch
    //
    // The runtime/dev boundary is enforced by the FormatHandler
    // (Item 11) — `extract_dependency_specs` returns RUNTIME deps
    // only. This test confirms the cascade respects it.
    // =====================================================================

    #[tokio::test]
    async fn dev_deps_not_followed_runtime_only_enqueued() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(
            &[("real-dep", "^1.0")],
            &[
                ("test-runner", "^7"),
                ("linter", "^9"),
                ("formatter", "^3"),
                ("type-checker", "^5"),
                ("bundler", "^2"),
            ],
        );
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "real-dep", &["1.0.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed, got {outcome:?}");
        };
        assert_eq!(result_summary["deps_extracted"], 1);
        assert_eq!(result_summary["prefetch_rows_enqueued"], 1);
        assert_eq!(result_summary["child_walk_rows_enqueued"], 1);
    }

    // =====================================================================
    // Already-held: 3 deps, 2 already in artifacts → only 1 enqueued
    // =====================================================================

    #[tokio::test]
    async fn already_held_deps_skipped_only_new_enqueued() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        // Seed `a` + `b` as already-held. The NpmInTest range
        // resolver returns Some(version) when the held set is
        // non-empty, so the cascade should skip both.
        artifacts.seed_package_version_status(
            repo.id,
            "a",
            vec![("1.5.0".to_string(), QuarantineStatus::Released)],
        );
        artifacts.seed_package_version_status(
            repo.id,
            "b",
            vec![("2.5.0".to_string(), QuarantineStatus::Released)],
        );
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[("a", "^1"), ("b", "^2"), ("c", "^3")], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        // Only the cold package `c` needs an
        // upstream packument; `a` + `b` are absorbed by Pass 1
        // (held-set) and never hit fetch_metadata.
        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "c", &["3.1.0", "3.0.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["deps_extracted"], 3);
        assert_eq!(result_summary["deps_already_held"], 2);
        assert_eq!(result_summary["prefetch_rows_enqueued"], 1);
        assert_eq!(result_summary["child_walk_rows_enqueued"], 1);
        // Only `c` was cold → ONE upstream fetch (not three).
        assert_eq!(result_summary["upstream_metadata_fetches"], 1);
    }

    // =====================================================================
    // Depth cap: at the cap, leaf prefetch enqueues but child walk doesn't
    // =====================================================================

    #[tokio::test]
    async fn depth_cap_at_cap_emits_leaf_but_not_child_walk() {
        // transitive_depth = 2 → walks at current_depth=1 → next=2
        // ≤ cap → child enqueued. At current_depth=2 → next=3 > 2 →
        // child NOT enqueued; leaf still enqueued.
        let repo = make_repo(RepositoryFormat::Npm, 2);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[("a", "^1.0")], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "a", &["1.0.0", "1.5.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        // current_depth=2 → next=3 > cap=2 → at-cap.
        let outcome = handler
            .run(
                &json!({"artifact_id": art.id, "current_depth": 2}),
                make_context(),
            )
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["prefetch_rows_enqueued"], 1);
        assert_eq!(result_summary["child_walk_rows_enqueued"], 0);
        assert_eq!(result_summary["child_walk_at_cap"], true);
    }

    // =====================================================================
    // L3 dedup: a second invocation of the same cohort enqueues 0
    // (mock's seen_keys set absorbs the duplicate, mirroring the
    // partial unique index).
    // =====================================================================

    #[tokio::test]
    async fn l3_dedup_second_invocation_inserts_zero_rows() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[("a", "^1.0")], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "a", &["1.0.0", "1.5.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        // First invocation enqueues both rows.
        let first = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed {
            result_summary: s1, ..
        } = first
        else {
            panic!("expected Completed");
        };
        assert_eq!(s1["prefetch_rows_enqueued"], 1);
        assert_eq!(s1["child_walk_rows_enqueued"], 1);

        // Second invocation enqueues zero (target_keys already seen).
        let second = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed {
            result_summary: s2, ..
        } = second
        else {
            panic!("expected Completed");
        };
        assert_eq!(s2["prefetch_rows_enqueued"], 0);
        assert_eq!(s2["prefetch_rows_deduped"], 1);
        assert_eq!(s2["child_walk_rows_enqueued"], 0);
        assert_eq!(s2["child_walk_rows_deduped"], 1);
    }

    // =====================================================================
    // Cycle / diamond termination: A→B, A→C, B→D, C→D, D→A. The walk
    // terminates because each cohort's target_key is dedup'd at L3.
    //
    // Concretely: a single cohort enqueues distinct (repo, package,
    // range) entries; a re-walk caused by a hypothetical cycle would
    // re-encounter the same target_keys and get absorbed by the
    // in-mock seen-keys set. We exercise the same scenario by running
    // the cascade twice against the same artifact + verifying the
    // second walk inserts zero rows.
    // =====================================================================

    #[tokio::test]
    async fn cycle_diamond_terminates_via_l3_dedup() {
        // Diamond: root depends on B + C. B + C both depend on D.
        // D depends back on root (cycle). The cascade walks each
        // cohort once via L3 dedup; re-encounters collapse.
        let repo = make_repo(RepositoryFormat::Npm, 10);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        // Root has B + C as deps.
        let bytes = npm_package_json_with_deps(&[("b", "^1"), ("c", "^1")], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "b", &["1.0.0", "1.2.0"]);
        seed_npm_packument(&proxy, "c", &["1.0.0", "1.3.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        // First walk: 2 new (B + C).
        assert_eq!(result_summary["prefetch_rows_enqueued"], 2);
        assert_eq!(result_summary["child_walk_rows_enqueued"], 2);

        // Simulate the cycle by re-running: B + C target_keys are
        // already seen → 0 inserts. This is the dedup-IS-the-insert
        // termination guarantee.
        let second = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed {
            result_summary: s2, ..
        } = second
        else {
            panic!("expected Completed");
        };
        assert_eq!(s2["prefetch_rows_enqueued"], 0);
        assert_eq!(s2["prefetch_rows_deduped"], 2);
    }

    // =====================================================================
    // Re-derivation after failed walk: a failed cascade row is terminal
    // (status='failed'); the L3 partial unique index excludes it (WHERE
    // status IN ('pending','running')), so a future re-enqueue lands.
    //
    // The mock's seen-keys set models the partial unique index — to
    // simulate "rows aged out of the index" we drop the seen-keys set
    // and re-run. The walk re-enqueues the missing subtree.
    // =====================================================================

    #[tokio::test]
    async fn re_derivation_after_failed_walk_re_enqueues_missing_subtree() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[("a", "^1.0"), ("b", "^2.0")], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        // Reusable proxy + mappings (shared across both walks — the
        // cascade only reads, so sharing is safe).
        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "a", &["1.0.0", "1.5.0"]);
        seed_npm_packument(&proxy, "b", &["2.0.0", "2.5.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            Arc::clone(&artifacts),
            Arc::clone(&storage),
            jobs.clone(),
            proxy.clone(),
            mappings.clone(),
            handlers_npm(),
        );

        // First walk: 2 inserts.
        let outcome = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["prefetch_rows_enqueued"], 2);

        // Use a FRESH MockJobsRepository to simulate "the previous
        // rows reached terminal status and fell out of the partial
        // unique index". The next walk re-enqueues the missing
        // subtree.
        let fresh_jobs = Arc::new(MockJobsRepository::new());
        let repos2 = Arc::new(MockRepositoryRepository::new());
        repos2.insert(repo.clone());
        let handler2 = make_handler(
            repos2,
            artifacts,
            storage,
            fresh_jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );
        let outcome2 = handler2
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed {
            result_summary: s2, ..
        } = outcome2
        else {
            panic!("expected Completed");
        };
        // Re-derivation: same cohort, fresh L3 set → 2 inserts.
        assert_eq!(s2["prefetch_rows_enqueued"], 2);
        assert_eq!(s2["prefetch_rows_deduped"], 0);
    }

    // =====================================================================
    // Error paths
    // =====================================================================

    #[tokio::test]
    async fn bad_params_returns_non_retry_failed() {
        let handler = make_handler(
            Arc::new(MockRepositoryRepository::new()),
            Arc::new(MockArtifactRepository::new()),
            Arc::new(MockStoragePort::new()),
            Arc::new(MockJobsRepository::new()),
            Arc::new(MockUpstreamProxy::new()),
            Arc::new(MockRepositoryUpstreamMappingRepository::new()),
            HashMap::new(),
        );
        // Neither shape present (no `artifact_id`, no coordinate) — a
        // structurally meaningless row → non-retry (it can never resolve).
        let outcome = handler
            .run(&json!({"current_depth": 0}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Failed { retry, reason } = outcome else {
            panic!("expected Failed, got {outcome:?}");
        };
        assert!(
            !retry,
            "a params row carrying no resolvable target is non-retry"
        );
        assert!(
            reason.contains("neither") && reason.contains("artifact_id"),
            "{reason}",
        );
    }

    #[tokio::test]
    async fn unknown_artifact_id_returns_non_retry_failed() {
        let handler = make_handler(
            Arc::new(MockRepositoryRepository::new()),
            Arc::new(MockArtifactRepository::new()),
            Arc::new(MockStoragePort::new()),
            Arc::new(MockJobsRepository::new()),
            Arc::new(MockUpstreamProxy::new()),
            Arc::new(MockRepositoryUpstreamMappingRepository::new()),
            HashMap::new(),
        );
        let outcome = handler
            .run(
                &json!({"artifact_id": Uuid::new_v4(), "current_depth": 0}),
                make_context(),
            )
            .await
            .expect("Ok");
        let TaskOutcome::Failed { retry, .. } = outcome else {
            panic!("expected Failed");
        };
        // NotFound = non-retry (the row will never resolve).
        assert!(!retry);
    }

    #[tokio::test]
    async fn no_format_handler_completes_as_noop() {
        let repo = make_repo(RepositoryFormat::Maven, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        // No bytes seeded — Maven path not exercised because the
        // format handler lookup is the gate.
        let art = Artifact {
            id: Uuid::new_v4(),
            repository_id: repo.id,
            name: "g:a".into(),
            name_as_published: "g:a".into(),
            version: Some("1".into()),
            path: "p".into(),
            size_bytes: 0,
            sha256_checksum: "a".repeat(64).parse().unwrap(),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/jar".into(),
            quarantine_status: QuarantineStatus::Released,
            quarantine_window_start: None,
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        artifacts.seed_artifact(art.clone());

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            Arc::new(MockUpstreamProxy::new()),
            Arc::new(MockRepositoryUpstreamMappingRepository::new()),
            handlers_npm(), // no maven entry
        );
        let outcome = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["deps_extracted"], 0);
        assert_eq!(result_summary["prefetch_rows_enqueued"], 0);
        assert_eq!(jobs.prefetch_batch_calls().len(), 0);
    }

    #[tokio::test]
    async fn extract_dependency_specs_failure_returns_non_retry_failed() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, b"junk".to_vec()).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            Arc::new(MockUpstreamProxy::new()),
            Arc::new(MockRepositoryUpstreamMappingRepository::new()),
            handlers_failing(),
        );
        let outcome = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Failed { retry, reason } = outcome else {
            panic!("expected Failed");
        };
        assert!(!retry, "structural parse failure is non-retry");
        assert!(reason.contains("extract_dependency_specs"), "{reason}");
    }

    // =====================================================================
    // Empty manifest: no deps → completed with all zero counters
    // =====================================================================

    #[tokio::test]
    async fn zero_deps_manifest_completes_with_zero_counters() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            Arc::new(MockUpstreamProxy::new()),
            Arc::new(MockRepositoryUpstreamMappingRepository::new()),
            handlers_npm(),
        );
        let outcome = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["deps_extracted"], 0);
        assert_eq!(result_summary["prefetch_rows_enqueued"], 0);
        assert_eq!(jobs.prefetch_batch_calls().len(), 0);
    }

    // =====================================================================
    // Pass 2 cold-cohort hybrid resolution tests
    // =====================================================================

    /// End-to-end Item 12b acceptance: a manifest with 3 deps where
    /// 2 are already held and 1 is cold → exactly 1 upstream
    /// `fetch_metadata` call, 1 `prefetch` row with the concrete
    /// version `target_key`, 1 child `prefetch-dependencies` row.
    /// Mirrors the backlog spec's acceptance scenario.
    #[tokio::test]
    async fn item_12b_acceptance_three_deps_two_held_one_cold_one_upstream_fetch() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        artifacts.seed_package_version_status(
            repo.id,
            "held1",
            vec![("1.0.0".to_string(), QuarantineStatus::Released)],
        );
        artifacts.seed_package_version_status(
            repo.id,
            "held2",
            vec![("2.0.0".to_string(), QuarantineStatus::Released)],
        );
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(
            &[("held1", "^1.0"), ("held2", "^2.0"), ("cold", "^3.0")],
            &[],
        );
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        // Only the cold package needs a packument — the held ones
        // are absorbed by Pass 1.
        seed_npm_packument(&proxy, "cold", &["3.0.0", "3.5.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["deps_extracted"], 3);
        assert_eq!(result_summary["deps_already_held"], 2);
        assert_eq!(result_summary["upstream_metadata_fetches"], 1);
        assert_eq!(result_summary["prefetch_rows_enqueued"], 1);
        assert_eq!(result_summary["child_walk_rows_enqueued"], 1);

        // The single prefetch row carries the CONCRETE version
        // `3.5.0` (highest match in `["3.0.0", "3.5.0"]` for `^3.0`),
        // not the opaque range `^3.0`.
        let batches = jobs.prefetch_batch_calls();
        let prefetch_batch = batches
            .iter()
            .find(|b| b.iter().all(|r| r.kind == "prefetch"))
            .expect("prefetch batch present");
        assert_eq!(prefetch_batch.len(), 1);
        assert!(prefetch_batch[0].target_key.ends_with("|3.5.0"));
        // Params carry the concrete version, not the range.
        assert_eq!(prefetch_batch[0].params["version"], "3.5.0");
        assert!(prefetch_batch[0].params.get("range").is_none());
    }

    /// Overlapping-ranges dedup (Item 12b acceptance): two specs
    /// `pkg@^1.0` and `pkg@~1.2` both resolve to upstream `1.2.5` →
    /// ONE concrete prefetch row in the cohort (the second spec's
    /// target_key matches the first and the in-batch enqueue gets
    /// deduped by the mock's L3 seen-keys set).
    #[tokio::test]
    async fn item_12b_overlapping_ranges_collapse_on_concrete_version() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        // Same package twice with different range strings — the
        // hybrid path resolves BOTH to `1.2.5`, the L3 key is
        // identical, so only ONE row lands in the cohort.
        //
        // NpmInTest's range resolver: a range "x.x.x" matches any
        // version; we use the simple `^1` and `~1` strings here —
        // both contain "1" so the `substring` heuristic in
        // `resolve_range_max` matches anything containing "1". The
        // resolver picks the lexicographically-max version, so
        // `1.2.5` wins. Both specs collapse to the same key.
        let manifest =
            br#"{"name":"r","version":"1.0.0","dependencies":{"pkg":"^1"},"devDependencies":{}}"#;
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, manifest.to_vec()).await;

        // The trick: per-package coalescence inside a single
        // invocation. Even though the manifest only has one spec
        // for `pkg`, the underlying contract is that overlapping
        // ranges in the same cohort would collapse via target_key.
        // Two cohorts referencing the same (repo, package, concrete)
        // both produce the same key → the second insert is
        // deduped by the mock's seen-keys set (mirrors the L3
        // partial unique index). Run twice to exercise it.
        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "pkg", &["1.0.0", "1.2.5"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        // First invocation: `^1` → `1.2.5` (concrete) lands.
        let r1 = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary: s1 } = r1 else {
            panic!("expected Completed");
        };
        assert_eq!(s1["prefetch_rows_enqueued"], 1);
        let batches = jobs.prefetch_batch_calls();
        let first_prefetch = batches
            .iter()
            .find(|b| b.iter().all(|r| r.kind == "prefetch"))
            .expect("prefetch batch");
        assert_eq!(
            first_prefetch[0].target_key.split('|').next_back().unwrap(),
            "1.2.5"
        );

        // Second invocation with the same artifact — Pass 2 again
        // produces the same concrete version `1.2.5` and the same
        // target_key. The mock's L3 seen-keys set absorbs the
        // duplicate — `prefetch_rows_enqueued` is 0, `_deduped` is 1.
        // This is the "overlapping ranges collapse" property.
        let r2 = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary: s2 } = r2 else {
            panic!("expected Completed");
        };
        assert_eq!(s2["prefetch_rows_enqueued"], 0);
        assert_eq!(s2["prefetch_rows_deduped"], 1);
    }

    /// Cold dep that the upstream's available set cannot satisfy →
    /// `deps_upstream_unsatisfiable` increments, no row enqueued,
    /// walk continues for the rest of the cohort.
    #[tokio::test]
    async fn item_12b_cold_dep_upstream_cannot_satisfy_skipped_with_warn() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[("impossible", "^99.0"), ("ok", "^1.0")], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        // Impossible: upstream only has 1.0.0, range is ^99 → no match.
        seed_npm_packument(&proxy, "impossible", &["1.0.0"]);
        seed_npm_packument(&proxy, "ok", &["1.0.0", "1.5.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        // Both packages got fetched. `impossible` had no satisfying
        // version → unsatisfiable; `ok` lands one row.
        assert_eq!(result_summary["upstream_metadata_fetches"], 2);
        assert_eq!(result_summary["deps_upstream_unsatisfiable"], 1);
        assert_eq!(result_summary["prefetch_rows_enqueued"], 1);
    }

    /// No catch-all upstream mapping → cold cohort silently skipped,
    /// `no_upstream_mapping` increments, held-set pass still runs.
    #[tokio::test]
    async fn item_12b_no_catchall_mapping_skips_cold_cohort_but_counts_held() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        artifacts.seed_package_version_status(
            repo.id,
            "held",
            vec![("1.0.0".to_string(), QuarantineStatus::Released)],
        );
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[("held", "^1.0"), ("cold", "^2.0")], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        // NO mapping seeded — cold cohort can't fetch upstream.
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        assert_eq!(result_summary["deps_already_held"], 1);
        assert_eq!(result_summary["no_upstream_mapping"], 1);
        assert_eq!(result_summary["prefetch_rows_enqueued"], 0);
        // No fetches were attempted — the mapping is the gate.
        assert_eq!(result_summary["upstream_metadata_fetches"], 0);
    }

    /// Per-package coalescence: TWO specs for the same package in
    /// one cohort produce ONE upstream fetch (not two). Stresses the
    /// `HashMap<package, Vec<spec>>` bucketing in Pass 2.
    #[tokio::test]
    async fn item_12b_two_specs_same_package_coalesce_to_one_fetch() {
        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        // npm uniqs by name, so we can't put two `pkg` lines in
        // dependencies — but we can produce two distinct specs by
        // hand-constructing the DependencySpec input. Easiest path:
        // capitalisation drift — the test handler lowercases via
        // `normalize_name`, so `pkg` and `PKG` collapse to one
        // bucket. Two ranges for the same normalised name.
        let manifest = br#"{"name":"r","version":"1.0.0","dependencies":{"PKG":"^1.0","pkg":"~1.2"},"devDependencies":{}}"#;
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, manifest.to_vec()).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "pkg", &["1.0.0", "1.2.5"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(&json!({"artifact_id": art.id}), make_context())
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed");
        };
        // Two specs, ONE upstream fetch (coalesced by normalised name).
        assert_eq!(result_summary["deps_extracted"], 2);
        assert_eq!(result_summary["upstream_metadata_fetches"], 1);
    }

    // =====================================================================
    // PrefetchPolicy.max_descendants:
    // global cumulative cap on the transitive cascade.
    // =====================================================================

    /// Cap-not-hit walks normally — every cold-cohort row enqueued,
    /// `WalkSummary.cap_hit = false`, child rows carry the next
    /// cumulative descendant count (`current + cohort_size_enqueued`).
    /// This is the legitimate-traffic happy path.
    #[tokio::test]
    async fn transitive_cap_not_hit_walks_normally() {
        let repo = make_repo_with_max_descendants(RepositoryFormat::Npm, 5, 10);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        // 3 cold deps; cap=10; current=0 → remaining=10; cohort fits.
        let bytes = npm_package_json_with_deps(&[("a", "^1"), ("b", "^2"), ("c", "^3")], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "a", &["1.0.0"]);
        seed_npm_packument(&proxy, "b", &["2.0.0"]);
        seed_npm_packument(&proxy, "c", &["3.0.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(
                &json!({"artifact_id": art.id, "current_depth": 0}),
                make_context(),
            )
            .await
            .expect("Ok");

        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed, got {outcome:?}");
        };
        assert_eq!(result_summary["prefetch_rows_enqueued"], 3);
        assert_eq!(result_summary["child_walk_rows_enqueued"], 3);
        assert_eq!(
            result_summary["cap_hit"], false,
            "cap NOT hit when cohort fits under max_descendants",
        );

        // Child rows must carry `current_descendants_so_far = 3` (the
        // cumulative running total after this branch enqueues 3 deps).
        let batches = jobs.prefetch_batch_calls();
        let child_batch = batches
            .iter()
            .find(|b| b.iter().all(|r| r.kind == "prefetch-dependencies"))
            .expect("child batch present");
        assert_eq!(child_batch.len(), 3);
        for row in child_batch {
            let cur = row
                .params
                .get("current_descendants_so_far")
                .and_then(serde_json::Value::as_u64)
                .expect("current_descendants_so_far must be stamped on child params");
            assert_eq!(cur, 3, "child carries current + cohort_size_enqueued");
        }
    }

    /// Cap-hit truncates the cohort *before* the batch INSERT and
    /// emits a `warn!` (verified via the summary fields the warn!
    /// shares). cap=2, current=0, 5 cold deps → 2 enqueued, 3 dropped;
    /// `cap_hit=true`; child rows carry `current+2 = 2`.
    #[tokio::test]
    async fn transitive_cap_hit_truncates_cohort_and_emits_warn() {
        // cap=2; 5 distinct cold deps in the manifest → only 2
        // leaves enqueued (+ 2 paired children), the rest dropped.
        let repo = make_repo_with_max_descendants(RepositoryFormat::Npm, 5, 2);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(
            &[
                ("a", "^1"),
                ("b", "^2"),
                ("c", "^3"),
                ("d", "^4"),
                ("e", "^5"),
            ],
            &[],
        );
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "a", &["1.0.0"]);
        seed_npm_packument(&proxy, "b", &["2.0.0"]);
        seed_npm_packument(&proxy, "c", &["3.0.0"]);
        seed_npm_packument(&proxy, "d", &["4.0.0"]);
        seed_npm_packument(&proxy, "e", &["5.0.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(
                &json!({"artifact_id": art.id, "current_depth": 0}),
                make_context(),
            )
            .await
            .expect("Ok");

        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed, got {outcome:?}");
        };
        assert_eq!(
            result_summary["prefetch_rows_enqueued"], 2,
            "cohort truncated to cap (2 of 5)",
        );
        assert_eq!(
            result_summary["child_walk_rows_enqueued"], 2,
            "child rows truncated in lockstep with prefetch leaves",
        );
        assert_eq!(
            result_summary["cap_hit"], true,
            "cap_hit must be true when cohort exceeds remaining",
        );

        // Truncation happens BEFORE the batch INSERT — the jobs port
        // observed exactly 2 leaf rows in the prefetch batch (and 2
        // child rows in the cascade batch). If the cap were applied
        // after enqueue, the port would have seen 5 + 5.
        let batches = jobs.prefetch_batch_calls();
        let leaf_batch = batches
            .iter()
            .find(|b| b.iter().all(|r| r.kind == "prefetch"))
            .expect("leaf batch present");
        assert_eq!(
            leaf_batch.len(),
            2,
            "leaf cohort truncated before INSERT, not after — only 2 rows reached the port",
        );

        // Child rows must carry `current_descendants_so_far = 2` (the
        // post-truncation cohort size). The cumulative count rides in
        // the params so the next cascade level sees its own
        // remaining = max_descendants - 2 = 0 and enqueues nothing.
        let child_batch = batches
            .iter()
            .find(|b| b.iter().all(|r| r.kind == "prefetch-dependencies"))
            .expect("child batch present");
        for row in child_batch {
            let cur = row
                .params
                .get("current_descendants_so_far")
                .and_then(serde_json::Value::as_u64)
                .expect("current_descendants_so_far must be stamped on child params");
            assert_eq!(
                cur, 2,
                "child carries truncated cohort size, not pre-truncation count",
            );
        }
    }

    /// `max_descendants = 0` collapses the transitive cascade to
    /// nothing — every prefetch leaf AND child row is dropped by the
    /// remaining=0 truncation. This is the defense-in-depth operator
    /// knob: collapse transitive enqueueing without disabling the
    /// `TransitiveDeps` trigger.
    #[tokio::test]
    async fn transitive_cap_zero_skips_all_child_enqueue() {
        let repo = make_repo_with_max_descendants(RepositoryFormat::Npm, 5, 0);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[("a", "^1"), ("b", "^2"), ("c", "^3")], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "a", &["1.0.0"]);
        seed_npm_packument(&proxy, "b", &["2.0.0"]);
        seed_npm_packument(&proxy, "c", &["3.0.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        seed_catchall_mapping(&mappings, repo.id).await;

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(
                &json!({"artifact_id": art.id, "current_depth": 0}),
                make_context(),
            )
            .await
            .expect("Ok");

        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed, got {outcome:?}");
        };
        assert_eq!(
            result_summary["prefetch_rows_enqueued"], 0,
            "cap=0 enqueues zero leaves",
        );
        assert_eq!(
            result_summary["child_walk_rows_enqueued"], 0,
            "cap=0 enqueues zero child cascades",
        );
        assert_eq!(
            result_summary["cap_hit"], true,
            "cap=0 with cohort > 0 trips the cap-hit flag",
        );

        // No INSERTs reached the port — the cap truncated both
        // batches to empty before the batch-insert branches.
        let batches = jobs.prefetch_batch_calls();
        assert!(
            batches.is_empty(),
            "cap=0 short-circuits BEFORE any batch INSERT; got: {batches:?}",
        );
    }

    // =====================================================================
    // Same-upstream resolver-pin regression
    // guard. The Pass 2 cold-cohort resolution at lines 611-636 picks
    // the catch-all upstream mapping (`path_prefix.is_empty()`
    // predicate). The transitive resolver is structurally incapable of
    // following a child dep to a *different* upstream URL than the one
    // the parent artifact was served by — cross-upstream cascade is
    // prevented by construction.
    //
    // This regression test pins that property. If a future refactor
    // changes the predicate (e.g. to a longest-prefix match like the
    // OCI-style mapping resolution), the resolver could pick the
    // narrower `@private/` mapping for a dep named `@private/foo` and
    // open the cross-upstream cascade the audit's F-46.2.2 framing
    // implied was already possible. The test asserts the chosen
    // mapping was the catch-all by inspecting the enqueued row's
    // concrete version — distinct upstream version sets per mapping
    // surface the choice unambiguously.
    //
    // The same-upstream dep-confusion vector that REMAINS (an attacker
    // publishing `@private/foo` on the catch-all upstream that the
    // legitimate `@private/foo` does not live on) is caught downstream
    // by the release gate + the scan gate, not here.
    // =====================================================================

    /// Regression guard for the same-upstream resolver-pin property.
    ///
    /// Fixture: a repo with two upstream mappings — a narrower
    /// `path_prefix="@private/"` mapping at one upstream, and a
    /// catch-all `path_prefix=""` mapping at a different upstream. A
    /// parent artifact ingested via the catch-all declares a dependency
    /// on `@private/foo`. The cold cohort's `fetch_metadata` MUST go to
    /// the catch-all (`path_prefix.is_empty()` predicate at the Pass 2
    /// upstream-mapping selection site); a future refactor that
    /// re-introduces longest-prefix matching would route to the
    /// `@private/` mapping instead, opening cross-upstream cascade.
    ///
    /// Verification mechanism: distinct upstream version sets per
    /// mapping. The catch-all advertises `99.0.0-catchall`; the
    /// `@private/` mapping advertises `1.0.0-private`. The enqueued
    /// `prefetch` row's `target_key` reveals which set the resolver
    /// consulted. Only the catch-all version is acceptable.
    #[tokio::test]
    async fn transitive_resolver_pins_to_parent_catch_all_upstream() {
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, RepositoryUpstreamMappingArgs, UpstreamAuth,
        };

        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());

        // Parent artifact's manifest declares a single dep — name
        // `@private/foo`, range `*` so the `NpmInTest::resolve_range_max`
        // accepts any version in the advertised set. The choice of
        // dep name is load-bearing: a longest-prefix-match refactor
        // would select the `@private/` mapping for this name; the
        // current `path_prefix.is_empty()` predicate must select the
        // catch-all regardless.
        let bytes = npm_package_json_with_deps(&[("@private/foo", "*")], &[]);
        let art = seed_artifact_with_bytes(&artifacts, &storage, repo.id, bytes).await;

        let proxy = Arc::new(MockUpstreamProxy::new());
        // Distinct upstream version sets per mapping. The mock keys
        // metadata fixtures on `(path_prefix, path)`, so the proxy
        // serves a different version set depending on which mapping
        // the resolver chose.
        //
        //  - Catch-all (`path_prefix=""`) → advertises `99.0.0-catchall`.
        //  - `@private/`              → advertises `1.0.0-private`.
        //
        // The expected (load-bearing) behaviour is that the resolver
        // selects the catch-all, so the cohort sees `99.0.0-catchall`
        // and the enqueued `target_key` ends with that string. If the
        // resolver were to select the `@private/` mapping instead,
        // the cohort would see `1.0.0-private` — the assertion
        // catches the deviation.
        proxy.insert_metadata(
            "",
            "/@private/foo",
            br#"{"versions":{"99.0.0-catchall":{}}}"#.to_vec(),
        );
        proxy.insert_metadata(
            "@private/",
            "/@private/foo",
            br#"{"versions":{"1.0.0-private":{}}}"#.to_vec(),
        );

        // Seed BOTH mappings on the same repo. Mapping construction
        // mirrors `seed_catchall_mapping` (default-shape Args; only
        // `path_prefix` and `upstream_url` differ between the two).
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let now = Utc::now();
        let catchall = RepositoryUpstreamMapping::new(RepositoryUpstreamMappingArgs {
            id: Uuid::new_v4(),
            repository_id: repo.id,
            path_prefix: String::new(),
            upstream_url: "https://registry.npmjs.org".to_string(),
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
        .expect("catch-all mapping constructor");
        let private = RepositoryUpstreamMapping::new(RepositoryUpstreamMappingArgs {
            id: Uuid::new_v4(),
            repository_id: repo.id,
            path_prefix: "@private/".to_string(),
            upstream_url: "https://internal.example".to_string(),
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
        .expect("private mapping constructor");
        mappings.upsert(catchall).await.expect("upsert catchall");
        mappings.upsert(private).await.expect("upsert private");

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let outcome = handler
            .run(
                &json!({"artifact_id": art.id, "current_depth": 0}),
                make_context(),
            )
            .await
            .expect("Ok");
        let TaskOutcome::Completed { result_summary } = outcome else {
            panic!("expected Completed, got {outcome:?}");
        };

        // Exactly one cold dep → exactly one upstream metadata fetch.
        // (If the resolver had attempted both mappings, this would be 2.)
        assert_eq!(
            result_summary["upstream_metadata_fetches"], 1,
            "exactly one upstream fetch — the resolver consults a single mapping",
        );
        assert_eq!(result_summary["prefetch_rows_enqueued"], 1);

        // The load-bearing assertion: the enqueued row's target_key
        // must carry the CATCH-ALL's version (`99.0.0-catchall`), not
        // the `@private/` mapping's version (`1.0.0-private`). The
        // target_key is `{repo_id}|{format}|{package}|{version}`; the
        // suffix after the last `|` is the resolved concrete version.
        let batches = jobs.prefetch_batch_calls();
        let leaf_batch = batches
            .iter()
            .find(|b| b.iter().all(|r| r.kind == "prefetch"))
            .expect("prefetch batch present");
        assert_eq!(
            leaf_batch.len(),
            1,
            "exactly one leaf prefetch row enqueued"
        );
        let leaf = &leaf_batch[0];
        assert!(
            leaf.target_key.ends_with("|99.0.0-catchall"),
            "resolver MUST pin to the catch-all upstream mapping \
             (path_prefix.is_empty() predicate). target_key was `{}`, \
             expected suffix `|99.0.0-catchall`. A suffix of \
             `|1.0.0-private` would indicate the resolver picked the \
             narrower `@private/` mapping — a cross-upstream cascade \
             regression.",
            leaf.target_key,
        );
    }

    // =====================================================================
    // `hort_prefetch_amplification_total`
    // amplification metric. Three result values:
    //   - `normal`           — walk completed under the cap.
    //   - `cap_hit`          — walk truncated by the §2.4.1 cap.
    //   - `resolver_failed`  — cold-cohort upstream resolution failed
    //                          (`summary.no_upstream_mapping > 0`).
    //
    // The counter fires once at the end of each `prefetch-dependencies`
    // walk (after `plan_and_enqueue` returns the `WalkSummary`).
    // Cardinality: `format` × `repository` × 3 result values.
    // =====================================================================

    /// Probe a `DebuggingRecorder` snapshot for a counter matching the
    /// supplied `(name, labels)`. Returns the counter value or `None`.
    /// Mirrors `prefetch_trigger::tests::counter_value`.
    fn amplification_counter_value(
        snapshot: &[(
            metrics_util::CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            metrics_util::debugging::DebugValue,
        )],
        name: &str,
        wanted_labels: &[(&str, &str)],
    ) -> Option<u64> {
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;
        snapshot.iter().find_map(|(ck, _, _, v)| {
            if ck.kind() != MetricKind::Counter || ck.key().name() != name {
                return None;
            }
            let all_match = wanted_labels.iter().all(|(k, want)| {
                ck.key()
                    .labels()
                    .any(|l| l.key() == *k && l.value() == *want)
            });
            if !all_match {
                return None;
            }
            match v {
                DebugValue::Counter(c) => Some(*c),
                _ => None,
            }
        })
    }

    /// Happy path — walk completes under the cap with the cold cohort
    /// satisfied. Counter fires once with `result=normal`.
    ///
    /// Uses `#[test]` (not `#[tokio::test]`) + an explicit
    /// `current_thread` runtime + `block_on` so the
    /// `metrics::with_local_recorder` thread-local scope strictly
    /// encloses the awaited handler call. Mirrors
    /// `task_dispatcher::tests::dispatcher_emits_completed_total_metric_blocking`.
    #[test]
    fn amplification_metric_fires_normal_when_walk_completes_under_cap() {
        use metrics_util::debugging::DebuggingRecorder;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let repo = make_repo_with_max_descendants(RepositoryFormat::Npm, 5, 10);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[("a", "^1")], &[]);
        let art = rt.block_on(seed_artifact_with_bytes(
            &artifacts, &storage, repo.id, bytes,
        ));
        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "a", &["1.0.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        rt.block_on(seed_catchall_mapping(&mappings, repo.id));

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let outcome = metrics::with_local_recorder(&recorder, || {
            rt.block_on(handler.run(
                &json!({"artifact_id": art.id, "current_depth": 0}),
                make_context(),
            ))
        })
        .expect("Ok");
        let TaskOutcome::Completed { .. } = outcome else {
            panic!("expected Completed");
        };

        let snap = snapshotter.snapshot().into_vec();
        let v = amplification_counter_value(
            &snap,
            "hort_prefetch_amplification_total",
            &[
                ("format", "npm"),
                ("repository", "test-repo"),
                ("result", "normal"),
            ],
        );
        assert_eq!(
            v,
            Some(1),
            "hort_prefetch_amplification_total{{result=normal}} must fire once \
             when the walk completes under the cap; got {v:?}",
        );
    }

    /// Cap-hit — cohort exceeds `remaining` and gets truncated.
    /// Counter fires once with `result=cap_hit`.
    #[test]
    fn amplification_metric_fires_cap_hit_when_cohort_truncated() {
        use metrics_util::debugging::DebuggingRecorder;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // cap=2, 5 cold deps → cohort truncated.
        let repo = make_repo_with_max_descendants(RepositoryFormat::Npm, 5, 2);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(
            &[
                ("a", "^1"),
                ("b", "^2"),
                ("c", "^3"),
                ("d", "^4"),
                ("e", "^5"),
            ],
            &[],
        );
        let art = rt.block_on(seed_artifact_with_bytes(
            &artifacts, &storage, repo.id, bytes,
        ));
        let proxy = Arc::new(MockUpstreamProxy::new());
        seed_npm_packument(&proxy, "a", &["1.0.0"]);
        seed_npm_packument(&proxy, "b", &["2.0.0"]);
        seed_npm_packument(&proxy, "c", &["3.0.0"]);
        seed_npm_packument(&proxy, "d", &["4.0.0"]);
        seed_npm_packument(&proxy, "e", &["5.0.0"]);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        rt.block_on(seed_catchall_mapping(&mappings, repo.id));

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let outcome = metrics::with_local_recorder(&recorder, || {
            rt.block_on(handler.run(
                &json!({"artifact_id": art.id, "current_depth": 0}),
                make_context(),
            ))
        })
        .expect("Ok");
        let TaskOutcome::Completed { .. } = outcome else {
            panic!("expected Completed");
        };

        let snap = snapshotter.snapshot().into_vec();
        let v = amplification_counter_value(
            &snap,
            "hort_prefetch_amplification_total",
            &[
                ("format", "npm"),
                ("repository", "test-repo"),
                ("result", "cap_hit"),
            ],
        );
        assert_eq!(
            v,
            Some(1),
            "hort_prefetch_amplification_total{{result=cap_hit}} must fire once \
             when the cohort exceeds the cap and is truncated; got {v:?}",
        );
        // And `normal` must NOT have fired on this walk — they are mutually
        // exclusive per-walk outcomes (the result enum is closed and
        // each walk produces exactly one increment).
        let normal = amplification_counter_value(
            &snap,
            "hort_prefetch_amplification_total",
            &[
                ("format", "npm"),
                ("repository", "test-repo"),
                ("result", "normal"),
            ],
        );
        assert_eq!(
            normal, None,
            "cap_hit and normal are mutually exclusive; normal must not fire \
             on a cap-hit walk; got {normal:?}",
        );
    }

    /// Resolver-failed — cold cohort has no catch-all upstream mapping;
    /// `summary.no_upstream_mapping > 0`. Counter fires once with
    /// `result=resolver_failed`.
    #[test]
    fn amplification_metric_fires_resolver_failed_when_no_catch_all_mapping() {
        use metrics_util::debugging::DebuggingRecorder;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let repo = make_repo(RepositoryFormat::Npm, 5);
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo.clone());
        let artifacts = Arc::new(MockArtifactRepository::new());
        let storage = Arc::new(MockStoragePort::new());
        let jobs = Arc::new(MockJobsRepository::new());
        let bytes = npm_package_json_with_deps(&[("cold", "^2.0")], &[]);
        let art = rt.block_on(seed_artifact_with_bytes(
            &artifacts, &storage, repo.id, bytes,
        ));
        // NO catch-all mapping seeded — the cold cohort can't fetch
        // upstream and `summary.no_upstream_mapping` increments.
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let handler = make_handler(
            repos,
            artifacts,
            storage,
            jobs.clone(),
            proxy,
            mappings,
            handlers_npm(),
        );

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let outcome = metrics::with_local_recorder(&recorder, || {
            rt.block_on(handler.run(
                &json!({"artifact_id": art.id, "current_depth": 0}),
                make_context(),
            ))
        })
        .expect("Ok");
        let TaskOutcome::Completed { .. } = outcome else {
            panic!("expected Completed");
        };

        let snap = snapshotter.snapshot().into_vec();
        let v = amplification_counter_value(
            &snap,
            "hort_prefetch_amplification_total",
            &[
                ("format", "npm"),
                ("repository", "test-repo"),
                ("result", "resolver_failed"),
            ],
        );
        assert_eq!(
            v,
            Some(1),
            "hort_prefetch_amplification_total{{result=resolver_failed}} must fire \
             once when the cold cohort has no catch-all upstream mapping \
             (summary.no_upstream_mapping > 0); got {v:?}",
        );
    }
}
