//! Prefetch trigger `on_dist_tag_move` (see
//! `docs/architecture/explanation/prefetch-pipeline.md`).
//!
//! Phase-1, non-transitive: given a `(repo, package)` plus the upstream
//! version set the format crate just observed at index/metadata serve
//! time and the hort-held per-version quarantine status (via
//! [`ArtifactRepository::package_version_status`](hort_domain::ports::artifact_repository::ArtifactRepository::package_version_status)),
//! decide which upstream versions to pull-through-prefetch so the
//! quarantine window elapses *off* the next build's critical path.
//!
//! # What this use case does
//!
//! [`PrefetchUseCase::plan`] is a **pure planner + metrics emitter**:
//!
//! 1. Reads [`PrefetchPolicy`] off the supplied `Repository`. If
//!    `enabled == false`, emits
//!    `hort_prefetch_skipped_total{reason="disabled"}` once and returns
//!    an empty plan.
//! 2. If the requested `trigger` is not in `policy.triggers`, emits
//!    `hort_prefetch_skipped_total{reason="trigger_not_enabled"}` once
//!    and returns an empty plan.
//! 3. Computes Hort's newest **held** (any [`QuarantineStatus`]) version
//!    per the supplied [`VersionOrdering`].
//! 4. Walks the upstream version set:
//!    - already in Hort's catalog → emits
//!      `hort_prefetch_skipped_total{reason="already_held"}` per version.
//!    - older than Hort's newest held → emits
//!      `hort_prefetch_skipped_total{reason="not_newer"}` per version.
//!    - otherwise: a candidate.
//! 5. Sorts candidates descending by ordering, takes the top
//!    `policy.depth`, and emits
//!    `hort_prefetch_enqueued_total{trigger}` once per planned version.
//! 6. Returns [`PrefetchPlan`] with the version list — newest first.
//!
//! # What this use case does NOT do
//!
//! - **No I/O.** No upstream call, no DB read, no spawn. The planner
//!   shape keeps `hort-app` tests pure / millisecond-fast and the
//!   composition root free of new ports.
//! - **No ingest.** The format crate iterates `plan.versions` and
//!   spawns the format-specific pull-through (e.g. npm's
//!   `try_upstream_tarball_pull`, cargo's `try_upstream_crate_pull`).
//!   The format crate owns the spawn because these are
//!   high-frequency hot-path triggers: a DB-backed job row
//!   per serve would be exactly the churn that must be avoided. The
//!   `scheduled` trigger IS DB-backed — that path is the job
//!   queue.
//! - **No range satisfaction.** Phase-1 picks "newest N" by per-format
//!   *ordering only*. `resolve_range_max` (range
//!   satisfaction) is Phase-2 and is intentionally NOT a dependency
//!   here.
//!
//! # `max_age_days`
//!
//! `policy.max_age_days` is rejected at apply by `ApplyConfigUseCase`
//! until the per-version timestamp surface lands;
//! the field stays in the schema for forward-compat. The
//! Phase-1 planner has no published-at metadata at the planner
//! boundary — the upstream version set passed in is a list of version
//! *strings*, not a list of `(version, published_at)` pairs — so any
//! value the planner *might* receive would silently fail to gate
//! versions. The architect anti-pattern *"Policy field accepted at
//! apply, inert at runtime"* (ADR 0015) closes that footgun at the
//! gitops boundary: see `validate_prefetch_max_age_days_not_implemented`
//! in `hort-config::desired` + the reject path in
//! `ApplyConfigUseCase::apply`. When the per-version timestamp surface
//! ships, both the linter and this comment
//! go away in the same commit.
//!
//! # Dedup
//!
//! [`PullDedup`](crate::pull_dedup::PullDedup) sits inside the
//! format crate's per-version pull. A prefetch racing a client pull
//! for the same artifact single-flights through that. The planner
//! never double-fetches because:
//!
//! - **`already_held`** removes versions already in `artifacts`;
//! - **`PullDedup` (single-flight)** absorbs concurrent in-flight
//!   pulls inside the spawn (downstream of this planner);
//! - **`artifacts` path-UNIQUE** terminally absorbs a redundant ingest
//!   if both the planner *and* the dedup miss (degenerate).
//!
//! # `OnDistTagMove`
//!
//! Detected at the index/metadata serve site. The format crate (npm's
//! packument; OCI registries) compares upstream's
//! `latest`/`:latest`-style pointer against Hort's held set; when it
//! points at a version Hort does not hold, that IS a tag move to an
//! unknown version. The plan API is trigger-agnostic: the caller passes
//! the trigger kind and the use case emits the right metric label.
//! (`OnDistTagMove` is the only hot-path trigger; there is deliberately
//! no index-fetch trigger.)

use std::cmp::Ordering;
use std::collections::HashMap;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::{PrefetchTrigger, Repository};

use crate::use_cases::index_serve_filter::VersionOrdering;

/// Outcome of [`PrefetchUseCase::plan`].
///
/// `versions` is the list of upstream versions the use case decided to
/// enqueue, newest-first per the supplied [`VersionOrdering`]. The
/// format crate iterates this list and spawns its per-version pull.
/// An empty list means "nothing to prefetch" — every early-exit path
/// (disabled policy, trigger not enabled, no upstream versions newer
/// than Hort's catalog) yields `versions: Vec::new()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchPlan {
    /// Versions to prefetch, newest-first per [`VersionOrdering`].
    /// Capped at `PrefetchPolicy::depth` entries.
    pub versions: Vec<String>,
}

impl PrefetchPlan {
    /// Empty plan — convenience constructor for the early-exit paths.
    fn empty() -> Self {
        Self {
            versions: Vec::new(),
        }
    }

    /// `true` iff the plan has at least one version to enqueue.
    /// Callers use this to short-circuit a no-op spawn loop.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }
}

/// Reasons emitted on the `reason` label of
/// `hort_prefetch_skipped_total`. The catalog (`docs/metrics-catalog.md`)
/// pins this enumeration.
///
/// Every variant is dispatched by the use case from a distinct
/// branch — the enum exists so the metric label values are unique
/// constants and a label-string typo is a compile error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkipReason {
    /// `prefetch_policy.enabled = false` — repository has not opted in.
    /// Emitted once per call (not per version).
    Disabled,
    /// `trigger` not present in `prefetch_policy.triggers` — repository
    /// opted in but did not subscribe this trigger. Emitted once per
    /// call (not per version).
    TriggerNotEnabled,
    /// Hort already holds this upstream version — `package_version_status`
    /// has a row for it (any status, including non-servable). Emitted
    /// once per skipped version. Counts toward "we won't double-pull".
    AlreadyHeld,
    /// Upstream version is older than or equal to Hort's newest held
    /// version per the per-format [`VersionOrdering`]. Emitted once
    /// per skipped version. Skipping these is what bounds the planner
    /// to "warm the newest depth" rather than "back-fill every old
    /// version upstream advertises".
    NotNewer,
}

impl SkipReason {
    /// String literal emitted on the `reason` label. Catalog-pinned.
    fn as_label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::TriggerNotEnabled => "trigger_not_enabled",
            Self::AlreadyHeld => "already_held",
            Self::NotNewer => "not_newer",
        }
    }
}

/// Stateless prefetch planner. Lives on `AppContext` as
/// `Arc<PrefetchUseCase>`; format crates call
/// [`Self::plan`] from their index/metadata serve sites.
///
/// The use case has no constructor dependencies — every input is
/// passed to [`Self::plan`]. The struct exists so the call site reads
/// `ctx.prefetch_use_case.plan(...)` (consistent with the rest of the
/// use-case surface) rather than a free function in the crate root.
#[derive(Debug, Default, Clone, Copy)]
pub struct PrefetchUseCase;

impl PrefetchUseCase {
    /// Construct the planner. Zero-cost; the type is a unit struct.
    pub fn new() -> Self {
        Self
    }

    /// Plan a prefetch for `(repo, package)` triggered by `trigger`.
    ///
    /// See module docs for full semantics. The caller supplies:
    ///
    /// - `repo` — for `repository_id` (logging) + the
    ///   `prefetch_policy` + the `key` (metric label).
    /// - `package` — the per-format package name, for the
    ///   `tracing::info!` event only. **Never** appears in a metric
    ///   label (cardinality).
    /// - `trigger` — the kind that fired this call. Used for the
    ///   `triggers`-membership check AND as the `trigger` metric
    ///   label on `hort_prefetch_enqueued_total`.
    /// - `upstream_versions` — the version set the format crate just
    ///   observed in the index/metadata document.
    /// - `held_status` — the result of
    ///   [`ArtifactRepository::package_version_status`](hort_domain::ports::artifact_repository::ArtifactRepository::package_version_status)
    ///   for this `(repo, package)`. The use case does NOT call the
    ///   port itself — keeping the planner pure makes
    ///   format-crate tests cheap (a mock that returns the seeded
    ///   list) and `hort-app` tests cheap (call `plan` directly with
    ///   inline data).
    /// - `ordering` — per-format version ordering
    ///   ([`crate::use_cases::index_serve_filter::NpmSemverOrdering`] /
    ///   `CargoSemverOrdering` / `Pep440Ordering`).
    ///
    /// Returns a [`PrefetchPlan`] — empty on every early-exit path so
    /// the caller's iterate-and-spawn loop is a no-op.
    #[tracing::instrument(
        skip(self, repo, upstream_versions, held_status, ordering),
        fields(
            repository_id = %repo.id,
            repository_key = %repo.key,
            package = %package,
            trigger = %trigger,
        ),
    )]
    pub fn plan(
        &self,
        repo: &Repository,
        package: &str,
        trigger: PrefetchTrigger,
        upstream_versions: &[&str],
        held_status: &[(String, QuarantineStatus)],
        ordering: &dyn VersionOrdering,
    ) -> PrefetchPlan {
        let policy = &repo.prefetch_policy;

        // ----- Early-exit 1: policy disabled --------------------------
        // `debug!` not `info!` per the architect tracing-rules
        // ("routine non-state-changing skips are `debug!`"). This
        // branch is unreachable from production today — every caller
        // pre-checks `policy.enabled` — so the log line is a
        // defense-in-depth signal only; promoting it to `info!` would
        // flood logs from any future caller that wires the planner
        // directly without the pre-check.
        if !policy.enabled {
            emit_skipped(&repo.key, SkipReason::Disabled, 1);
            tracing::debug!(
                reason = SkipReason::Disabled.as_label(),
                "prefetch skipped: policy disabled for repository"
            );
            return PrefetchPlan::empty();
        }

        // ----- Early-exit 2: trigger not subscribed -------------------
        // Same `debug!` rationale as Early-exit 1.
        if !policy.triggers.contains(&trigger) {
            emit_skipped(&repo.key, SkipReason::TriggerNotEnabled, 1);
            tracing::debug!(
                reason = SkipReason::TriggerNotEnabled.as_label(),
                "prefetch skipped: trigger not enabled for repository"
            );
            return PrefetchPlan::empty();
        }

        // Degenerate but valid: depth = 0 means "no prefetch even if
        // enabled". The planner short-circuits before the per-version
        // walk so no spurious `already_held` / `not_newer` ticks fire.
        // `debug!` per the architect rule (routine non-state-changing
        // skip).
        if policy.depth == 0 {
            tracing::debug!(
                depth = 0,
                "prefetch planner short-circuit: depth=0 (degenerate but valid)"
            );
            return PrefetchPlan::empty();
        }

        // ----- Build Hort's catalog set + Hort's newest held version ------
        // `held_set` for O(1) membership lookup; `held_newest` for the
        // "not_newer" filter. Both use the supplied per-format
        // VersionOrdering — comparing held versions to upstream
        // versions with the same comparator is the only correctness
        // requirement.
        let held_set: HashMap<&str, QuarantineStatus> =
            held_status.iter().map(|(v, s)| (v.as_str(), *s)).collect();
        let held_newest: Option<&str> = held_status
            .iter()
            .map(|(v, _)| v.as_str())
            .max_by(|a, b| ordering.compare(a, b));

        // ----- Walk upstream versions ---------------------------------
        // Dedup upstream first: a malformed upstream that repeats a
        // version key must not double-count `already_held` skips.
        let mut seen_upstream: HashMap<&str, ()> = HashMap::new();
        let mut already_held = 0u64;
        let mut not_newer = 0u64;
        let mut candidates: Vec<&str> = Vec::new();
        for &v in upstream_versions {
            if seen_upstream.insert(v, ()).is_some() {
                continue;
            }
            if held_set.contains_key(v) {
                already_held += 1;
                continue;
            }
            // Older or equal to Hort's newest held → not_newer. Strictly:
            // we want "strictly newer than newest held". `Ordering::Equal`
            // falls through the held_set check above (equal-version
            // would have been already_held), so this branch only
            // triggers for `Less`.
            if let Some(newest) = held_newest {
                if matches!(
                    ordering.compare(v, newest),
                    Ordering::Less | Ordering::Equal
                ) {
                    not_newer += 1;
                    continue;
                }
            }
            candidates.push(v);
        }

        if already_held > 0 {
            emit_skipped(&repo.key, SkipReason::AlreadyHeld, already_held);
        }
        if not_newer > 0 {
            emit_skipped(&repo.key, SkipReason::NotNewer, not_newer);
        }

        // ----- Sort + cap to `depth` ----------------------------------
        // Descending by ordering — the newest `depth` win.
        candidates.sort_by(|a, b| ordering.compare(b, a));
        candidates.truncate(policy.depth as usize);

        if candidates.is_empty() {
            tracing::info!(
                upstream_seen = upstream_versions.len(),
                already_held,
                not_newer,
                "prefetch planner: no candidate versions after filter"
            );
            return PrefetchPlan::empty();
        }

        // ----- Emit enqueued metrics + log ----------------------------
        emit_enqueued(&repo.key, trigger, candidates.len() as u64);
        tracing::info!(
            upstream_seen = upstream_versions.len(),
            already_held,
            not_newer,
            planned = candidates.len(),
            depth = policy.depth,
            "prefetch planned: enqueueing versions"
        );

        PrefetchPlan {
            versions: candidates.into_iter().map(str::to_string).collect(),
        }
    }
}

/// Emit `hort_prefetch_skipped_total{repository, reason}`. Sentinel
/// `_all` is applied by the catalog-side `include_repository_label`
/// flag at the format-crate emission site for `enqueued`; the
/// `skipped` counter ALWAYS carries the real repo key because
/// `repo.key` is supplied verbatim. Operator visibility of the
/// per-repo skip distribution matters here — collapsing it to `_all`
/// would defeat the diagnostic.
fn emit_skipped(repo_key: &str, reason: SkipReason, by: u64) {
    if by == 0 {
        return;
    }
    metrics::counter!(
        "hort_prefetch_skipped_total",
        "repository" => repo_key.to_string(),
        "reason" => reason.as_label(),
    )
    .increment(by);
}

/// Emit `hort_prefetch_enqueued_total{repository, trigger}`. Same
/// `repository` label semantics as [`emit_skipped`].
fn emit_enqueued(repo_key: &str, trigger: PrefetchTrigger, by: u64) {
    if by == 0 {
        return;
    }
    metrics::counter!(
        "hort_prefetch_enqueued_total",
        "repository" => repo_key.to_string(),
        "trigger" => trigger.to_string(),
    )
    .increment(by);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{
        IndexMode, PrefetchPolicy, ReplicationPriority, Repository, RepositoryFormat,
        RepositoryType,
    };
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::MetricKind;
    use uuid::Uuid;

    use crate::use_cases::index_serve_filter::NpmSemverOrdering;

    fn repo_with_policy(key: &str, policy: PrefetchPolicy) -> Repository {
        Repository {
            id: Uuid::new_v4(),
            key: key.into(),
            name: "Test".into(),
            description: None,
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Proxy,
            storage_backend: "filesystem".into(),
            storage_path: "/data/repos/test".into(),
            upstream_url: Some("https://registry.npmjs.org".into()),
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

    fn enabled_policy(triggers: Vec<PrefetchTrigger>, depth: u32) -> PrefetchPolicy {
        PrefetchPolicy {
            enabled: true,
            triggers,
            depth,
            transitive_depth: 5,
            max_age_days: None,
            // Production default.
            max_descendants: PrefetchPolicy::default().max_descendants,
        }
    }

    // ---------- early exits ----------

    /// Disabled policy → empty plan + `skipped{reason=disabled}` fires
    /// once, never twice and never per-version.
    #[test]
    fn disabled_policy_emits_skipped_disabled_once_and_returns_empty_plan() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let plan = metrics::with_local_recorder(&recorder, || {
            let repo = repo_with_policy("npm-mirror", PrefetchPolicy::default());
            PrefetchUseCase::new().plan(
                &repo,
                "express",
                PrefetchTrigger::OnDistTagMove,
                &["1.0.0", "1.1.0"],
                &[],
                &NpmSemverOrdering,
            )
        });

        assert_eq!(plan, PrefetchPlan::empty());

        let snapshot = snapshotter.snapshot().into_vec();
        let skipped = snapshot
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_skipped_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "reason" && l.value() == "disabled")
            })
            .expect("hort_prefetch_skipped_total{reason=disabled} must fire");
        match &skipped.3 {
            DebugValue::Counter(c) => assert_eq!(*c, 1, "fires exactly once for the call"),
            other => panic!("expected counter, got {other:?}"),
        }
        // No `enqueued` must have fired.
        assert!(snapshot
            .iter()
            .all(|(ck, _, _, _)| { ck.key().name() != "hort_prefetch_enqueued_total" }));
    }

    /// Trigger not in `policy.triggers` → empty plan +
    /// `skipped{reason=trigger_not_enabled}` fires once.
    #[test]
    fn trigger_not_enabled_emits_skipped_trigger_not_enabled_once() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        // Enabled, but ONLY `Scheduled` is subscribed; the caller fires
        // `OnDistTagMove` → must not enqueue.
        let plan = metrics::with_local_recorder(&recorder, || {
            let repo = repo_with_policy(
                "npm-mirror",
                enabled_policy(vec![PrefetchTrigger::Scheduled], 3),
            );
            PrefetchUseCase::new().plan(
                &repo,
                "express",
                PrefetchTrigger::OnDistTagMove,
                &["1.0.0", "1.1.0"],
                &[],
                &NpmSemverOrdering,
            )
        });
        assert!(plan.is_empty());

        let snapshot = snapshotter.snapshot().into_vec();
        let skipped = snapshot
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_skipped_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "reason" && l.value() == "trigger_not_enabled")
            })
            .expect("hort_prefetch_skipped_total{reason=trigger_not_enabled} must fire");
        match &skipped.3 {
            DebugValue::Counter(c) => assert_eq!(*c, 1),
            other => panic!("expected counter, got {other:?}"),
        }
    }

    /// `depth = 0` with otherwise-valid policy → empty plan, NO
    /// per-version `already_held` / `not_newer` ticks (planner short-
    /// circuits before the walk). `depth = 0` is the no-op end of the
    /// dial: a degenerate but valid configuration.
    #[test]
    fn depth_zero_short_circuits_without_per_version_ticks() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let plan = metrics::with_local_recorder(&recorder, || {
            let repo = repo_with_policy(
                "npm-mirror",
                enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 0),
            );
            PrefetchUseCase::new().plan(
                &repo,
                "express",
                PrefetchTrigger::OnDistTagMove,
                &["1.0.0", "1.1.0", "2.0.0"],
                &[("1.0.0".to_string(), QuarantineStatus::Released)],
                &NpmSemverOrdering,
            )
        });
        assert!(plan.is_empty());

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(snapshot.iter().all(|(ck, _, _, _)| {
            ck.key().name() != "hort_prefetch_skipped_total"
                && ck.key().name() != "hort_prefetch_enqueued_total"
        }));
    }

    // ---------- the steady-state path ----------

    /// Steady-state: Hort holds `1.0.0`; upstream advertises
    /// `[1.0.0, 1.1.0, 1.2.0]`. Plan is `[1.2.0, 1.1.0]` newest-first;
    /// `already_held` fires for `1.0.0`; `enqueued{on_dist_tag_move}`
    /// fires by 2.
    #[test]
    fn plans_newest_depth_emits_enqueued_and_already_held() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let plan = metrics::with_local_recorder(&recorder, || {
            let repo = repo_with_policy(
                "npm-mirror",
                enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
            );
            PrefetchUseCase::new().plan(
                &repo,
                "express",
                PrefetchTrigger::OnDistTagMove,
                &["1.0.0", "1.1.0", "1.2.0"],
                &[("1.0.0".to_string(), QuarantineStatus::Released)],
                &NpmSemverOrdering,
            )
        });
        assert_eq!(
            plan.versions,
            vec!["1.2.0".to_string(), "1.1.0".to_string()],
            "newest-first per semver ordering"
        );

        let snapshot = snapshotter.snapshot().into_vec();

        let enqueued = snapshot
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_enqueued_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "trigger" && l.value() == "on_dist_tag_move")
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "repository" && l.value() == "npm-mirror")
            })
            .expect("hort_prefetch_enqueued_total must fire with trigger=on_dist_tag_move");
        match &enqueued.3 {
            DebugValue::Counter(c) => assert_eq!(*c, 2, "two new versions planned"),
            other => panic!("expected counter, got {other:?}"),
        }

        let already_held = snapshot
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_skipped_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "reason" && l.value() == "already_held")
            })
            .expect("already_held must fire for the 1.0.0 row");
        match &already_held.3 {
            DebugValue::Counter(c) => assert_eq!(*c, 1),
            other => panic!("expected counter, got {other:?}"),
        }
    }

    /// `policy.depth = 1` clamps the plan to a single newest version.
    /// Anything older than the chosen newest still in the upstream
    /// remainder is silently dropped by the truncate — NOT counted as
    /// `not_newer` (the reason exists only for "older than Hort's newest
    /// held", not "older than the planned newest").
    #[test]
    fn depth_truncates_to_newest_versions_only() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let plan = metrics::with_local_recorder(&recorder, || {
            let repo = repo_with_policy(
                "npm-mirror",
                enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 1),
            );
            PrefetchUseCase::new().plan(
                &repo,
                "express",
                PrefetchTrigger::OnDistTagMove,
                // Upstream advertises five new versions; Hort has none.
                &["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"],
                &[],
                &NpmSemverOrdering,
            )
        });
        assert_eq!(
            plan.versions,
            vec!["1.4.0".to_string()],
            "depth=1 keeps only the single newest version"
        );

        let snapshot = snapshotter.snapshot().into_vec();
        let enqueued = snapshot
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_enqueued_total"
            })
            .expect("enqueued must fire");
        match &enqueued.3 {
            DebugValue::Counter(c) => assert_eq!(*c, 1, "depth=1 → one enqueue"),
            other => panic!("expected counter, got {other:?}"),
        }
        // No `not_newer` — versions older than the planned 1.4.0 but
        // newer than Hort's empty held set are NOT counted as not_newer.
        assert!(snapshot.iter().all(|(ck, _, _, _)| {
            !(ck.key().name() == "hort_prefetch_skipped_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "reason" && l.value() == "not_newer"))
        }));
    }

    /// Upstream version older than Hort's newest held → `not_newer`
    /// fires. The newest-held filter is what bounds the planner to
    /// "warm forward, not back-fill".
    #[test]
    fn upstream_older_than_newest_held_is_not_newer() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let plan = metrics::with_local_recorder(&recorder, || {
            let repo = repo_with_policy(
                "npm-mirror",
                enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
            );
            PrefetchUseCase::new().plan(
                &repo,
                "express",
                PrefetchTrigger::OnDistTagMove,
                // 0.9.0 < newest held (1.0.0); 1.1.0 > newest held.
                &["0.9.0", "1.1.0"],
                &[("1.0.0".to_string(), QuarantineStatus::Released)],
                &NpmSemverOrdering,
            )
        });
        assert_eq!(plan.versions, vec!["1.1.0".to_string()]);

        let snapshot = snapshotter.snapshot().into_vec();
        let not_newer = snapshot
            .iter()
            .find(|(ck, _, _, _)| {
                ck.kind() == MetricKind::Counter
                    && ck.key().name() == "hort_prefetch_skipped_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "reason" && l.value() == "not_newer")
            })
            .expect("not_newer must fire for the 0.9.0 row");
        match &not_newer.3 {
            DebugValue::Counter(c) => assert_eq!(*c, 1),
            other => panic!("expected counter, got {other:?}"),
        }
    }

    /// Upstream version `==` Hort's newest held → `not_newer` (NOT
    /// `already_held` — equal-version would hit `already_held` first
    /// because the held_set contains it. This test confirms that
    /// path; the strict "<" inside the not_newer arm therefore
    /// excludes equal-version cases from being double-counted.).
    #[test]
    fn upstream_equal_to_newest_held_is_already_held_not_not_newer() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let plan = metrics::with_local_recorder(&recorder, || {
            let repo = repo_with_policy(
                "npm-mirror",
                enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
            );
            PrefetchUseCase::new().plan(
                &repo,
                "express",
                PrefetchTrigger::OnDistTagMove,
                &["1.0.0"],
                &[("1.0.0".to_string(), QuarantineStatus::Released)],
                &NpmSemverOrdering,
            )
        });
        assert!(plan.is_empty(), "no new versions → empty plan");

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(snapshot.iter().any(|(ck, _, _, _)| {
            ck.key().name() == "hort_prefetch_skipped_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "reason" && l.value() == "already_held")
        }));
        assert!(snapshot.iter().all(|(ck, _, _, _)| {
            !(ck.key().name() == "hort_prefetch_skipped_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "reason" && l.value() == "not_newer"))
        }));
    }

    /// Quarantined / Rejected / ScanIndeterminate versions all count
    /// as "held" — prefetching them again is a double-pull. Pins the
    /// "any status counts" semantic: the planner's catalog awareness
    /// extends to non-servable rows, not just `Released`.
    #[test]
    fn already_held_covers_all_quarantine_statuses() {
        for status in [
            QuarantineStatus::Released,
            QuarantineStatus::None,
            QuarantineStatus::Quarantined,
            QuarantineStatus::Rejected,
            QuarantineStatus::ScanIndeterminate,
        ] {
            let recorder = DebuggingRecorder::new();
            let snapshotter = recorder.snapshotter();
            metrics::with_local_recorder(&recorder, || {
                let repo = repo_with_policy(
                    "npm-mirror",
                    enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
                );
                PrefetchUseCase::new().plan(
                    &repo,
                    "express",
                    PrefetchTrigger::OnDistTagMove,
                    &["1.0.0"],
                    &[("1.0.0".to_string(), status)],
                    &NpmSemverOrdering,
                );
            });
            let snapshot = snapshotter.snapshot().into_vec();
            assert!(
                snapshot.iter().any(|(ck, _, _, _)| {
                    ck.key().name() == "hort_prefetch_skipped_total"
                        && ck
                            .key()
                            .labels()
                            .any(|l| l.key() == "reason" && l.value() == "already_held")
                }),
                "status {status:?} must count as already_held"
            );
        }
    }

    /// Duplicate upstream version keys (malformed upstream packument)
    /// collapse — `already_held` fires ONCE for two identical entries.
    /// Guards against a malformed-upstream double-count.
    #[test]
    fn duplicate_upstream_versions_collapse_in_skip_count() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            let repo = repo_with_policy(
                "npm-mirror",
                enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
            );
            PrefetchUseCase::new().plan(
                &repo,
                "express",
                PrefetchTrigger::OnDistTagMove,
                &["1.0.0", "1.0.0", "1.0.0"],
                &[("1.0.0".to_string(), QuarantineStatus::Released)],
                &NpmSemverOrdering,
            );
        });

        let snapshot = snapshotter.snapshot().into_vec();
        let already_held = snapshot
            .iter()
            .find(|(ck, _, _, _)| {
                ck.key().name() == "hort_prefetch_skipped_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "reason" && l.value() == "already_held")
            })
            .expect("already_held must fire");
        match &already_held.3 {
            DebugValue::Counter(c) => assert_eq!(*c, 1, "three duplicates collapse to one tick"),
            other => panic!("expected counter, got {other:?}"),
        }
    }

    /// `OnDistTagMove` is a first-class trigger on the same surface.
    /// The label value `on_dist_tag_move` lands on the metric.
    #[test]
    fn on_dist_tag_move_trigger_emits_correct_label() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let plan = metrics::with_local_recorder(&recorder, || {
            let repo = repo_with_policy(
                "npm-mirror",
                enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
            );
            PrefetchUseCase::new().plan(
                &repo,
                "express",
                PrefetchTrigger::OnDistTagMove,
                &["2.0.0"],
                &[],
                &NpmSemverOrdering,
            )
        });
        assert_eq!(plan.versions, vec!["2.0.0".to_string()]);

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(
            snapshot.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_prefetch_enqueued_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "trigger" && l.value() == "on_dist_tag_move")
            }),
            "trigger=on_dist_tag_move must appear on the enqueued counter"
        );
    }

    /// Empty upstream version list → empty plan, no skipped emissions
    /// (no versions to consider).
    #[test]
    fn empty_upstream_yields_empty_plan_and_no_per_version_emissions() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let plan = metrics::with_local_recorder(&recorder, || {
            let repo = repo_with_policy(
                "npm-mirror",
                enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
            );
            PrefetchUseCase::new().plan(
                &repo,
                "express",
                PrefetchTrigger::OnDistTagMove,
                &[],
                &[],
                &NpmSemverOrdering,
            )
        });
        assert!(plan.is_empty());

        let snapshot = snapshotter.snapshot().into_vec();
        // No skipped reasons, no enqueued.
        assert!(snapshot.iter().all(|(ck, _, _, _)| {
            ck.key().name() != "hort_prefetch_skipped_total"
                && ck.key().name() != "hort_prefetch_enqueued_total"
        }));
    }

    /// `PrefetchPlan::is_empty` agrees with the field.
    #[test]
    fn plan_is_empty_helper() {
        assert!(PrefetchPlan::empty().is_empty());
        let p = PrefetchPlan {
            versions: vec!["1.0.0".into()],
        };
        assert!(!p.is_empty());
    }

    /// `PrefetchUseCase::new` constructs a unit struct — Default/Clone/Copy.
    #[test]
    fn use_case_is_zero_sized_default_clone_copy() {
        let a = PrefetchUseCase::new();
        let b = PrefetchUseCase;
        let _c: PrefetchUseCase = a; // Copy
        let _d = b;
        // No assertions needed — the type-system properties are pinned
        // by the trait bounds + the `let _` rebinds; if any of these
        // bounds dropped this test would fail to compile.
    }
}
