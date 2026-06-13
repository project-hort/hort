//! Shared per-format hot-path prefetch-trigger helper (see
//! `docs/architecture/explanation/prefetch-pipeline.md`).
//!
//! This module exposes a single public function,
//! [`fire_hot_path_trigger`], that captures the **canonical four-step
//! sequence** the three per-format hot-path trigger functions
//! (`fire_prefetch_trigger_npm`, `fire_prefetch_trigger_pypi`,
//! `fire_prefetch_trigger` in `hort-http-cargo/src/index_cache.rs`) all
//! copy verbatim today:
//!
//! 1. Early-exit if [`Repository::prefetch_policy`] is `enabled = false`.
//! 2. Parse the format-native body into
//!    `(upstream_versions, optional_explicit_latest)` via the
//!    caller-supplied `parser` closure.
//! 3. Compute "latest":
//!    - `optional_explicit_latest = Some(s)` — protocol carries a real
//!      mutable-tag pointer (npm's `dist-tags.latest`); use `s` verbatim.
//!    - `optional_explicit_latest = None` — protocol has no native
//!      `latest`; synthesise one by `max_by(ordering)` over
//!      `upstream_versions` (pypi / cargo shape).
//! 4. If `latest` is *not* in the hort-held `pkg_status` set, call
//!    [`PrefetchUseCase::plan`] for [`PrefetchTrigger::OnDistTagMove`]
//!    and invoke `spawner` again. Else skip — Hort already holds the
//!    upstream-current version, no tag-move signal to act on.
//!
//! There is deliberately no `plan + spawn OnIndexFetch` step; the
//! helper anchors on
//! `OnDistTagMove` divergence-detection. The convenience workflow such
//! a step would serve (warm newer versions of a touched package on
//! anonymous index reads) is covered by the explicit, JWT-only
//! `hort-cli prefetch`.
//!
//! # Why a helper
//!
//! The four-step pattern is a perfect cross-format duplication: the
//! only per-format variation is the *parser* (npm packument JSON →
//! `versions{}` keys + `dist-tags.latest`; PEP 503 HTML / PEP 691 JSON
//! → filename-derived version list + `None`; cargo sparse-index NDJSON
//! → `vers` field list + `None`) and the *spawner* (each format spawns
//! its own per-version `try_upstream_*_pull`). Everything else — the
//! enabled-check, the planner invocations, the `OnDistTagMove`
//! divergence test — is identical across the three formats.
//!
//! **OCI is deliberately excluded.** `fire_prefetch_trigger_oci` lives
//! in the manifest-fetch path (`hort-http-oci/src/prefetch.rs`); its
//! shape — *digest-divergence detection* between Hort's prior held tag-
//! digest and the upstream's freshly-resolved digest — does not match
//! this helper's "parse body for version set, pick newest, spawn per-
//! version pulls" contract. OCI continues to call
//! [`PrefetchUseCase::plan`] directly.
//!
//! # Generic over `Ctx` — dep-graph note
//!
//! The helper cannot take the
//! per-format crate's `&Arc<AppContext>` literal as the first
//! parameter: that type is defined in `hort-http-core`, which depends on
//! `hort-app` — so an `hort-app`-resident helper cannot name it without
//! introducing a circular dependency the dep-graph
//! contract (ADR 0008) structurally forbids (and the workspace would
//! reject as an unresolved-import compile error).
//!
//! The resolution — same shape, no circular dep —
//! is to make the helper **generic over the context type**
//! (`Ctx: ?Sized`). The per-format caller passes `&Arc<AppContext>`
//! exactly as before; the spawner closure receives the same `&Ctx`
//! reference back. The helper itself never touches `ctx` — it only
//! threads it through to the spawner — so being context-agnostic is
//! the natural shape. The `IndexBuilder` skeleton resolved an
//! identical dep-direction conflict the same way; see
//! [`crate::use_cases::index_serve`] for the precedent.
//!
//! # Metrics and tracing
//!
//! - **No new metric names or label values.** This helper invokes
//!   [`PrefetchUseCase::plan`] (which emits the existing
//!   `hort_prefetch_enqueued_total` / `hort_prefetch_skipped_total`
//!   counters per `docs/metrics-catalog.md`) and the spawner closure
//!   (whose pull-through emissions are unchanged). The catalog is
//!   untouched.
//! - **One `info!` line per call** carrying `format`, `repository`
//!   (the repo key, not the UUID — per the per-repo cardinality
//!   contract in the metrics catalog), `package`, and the per-trigger
//!   outcome (`on_dist_tag_move_planned`, `on_dist_tag_move_skipped`
//!   — the prior `on_index_fetch_*` fields are gone with the trigger).
//! - `#[tracing::instrument(skip(ctx, body, pkg_status, parser,
//!   spawner))]` without `err` — the architect tracing-rules forbid
//!   `err` on application-layer instrumentation because the
//!   policy-disabled / trigger-not-subscribed branches are operator
//!   policy states, not errors.

use std::sync::Arc;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::{PrefetchTrigger, Repository};

use crate::use_cases::index_serve_filter::VersionOrdering;
use crate::use_cases::prefetch_use_case::{PrefetchPlan, PrefetchUseCase};

/// Fire the shared per-format hot-path prefetch trigger sequence —
/// the four steps (enabled-check, parse, latest-divergence check,
/// plan(`OnDistTagMove`) + spawn) the three SimpleIndex format hot-path
/// trigger functions (npm / pypi / cargo) duplicated verbatim before
/// this helper landed. The steps anchor on the
/// `OnDistTagMove` divergence-detection; there is deliberately no
/// `plan + spawn OnIndexFetch` step.
///
/// # Parameters
///
/// - `ctx` — the per-format caller's app context (typically
///   `&Arc<AppContext>`). Generic so the helper lives in `hort-app`
///   without depending on `hort-http-core`; the spawner closure
///   receives the same reference back.
/// - `planner` — the [`PrefetchUseCase`] (typically
///   `&ctx.prefetch_use_case`). Passed explicitly so this helper does
///   not need to know how the caller stores the planner.
/// - `repo` — the repository whose `prefetch_policy` gates the
///   sequence and whose `key` is the per-repo metric label
///   downstream-emitters consume.
/// - `package` — the per-format package name (npm package, PyPI
///   project, cargo crate). Threaded through the planner and the
///   spawner verbatim; never appears in a metric label
///   (cardinality).
/// - `body` — the format-native index document the serve site is
///   about to return. Passed to `parser` once; otherwise opaque.
/// - `pkg_status` — `ArtifactRepository::package_version_status`
///   result for `(repo, package)`. Used both by the planner (to
///   classify `already_held` / `not_newer`) and by the helper itself
///   for the `OnDistTagMove`-gate divergence check.
/// - `ordering` — the per-format [`VersionOrdering`] (`NpmSemverOrdering`,
///   `Pep440Ordering`, or `CargoSemverOrdering` which is the npm
///   alias). Trait-object reference so the helper can be invoked
///   with each per-format ordering without monomorphisation.
/// - `parser` — extracts `(upstream_versions, optional_explicit_latest)`
///   from the format-native body. Contract:
///   - `optional_explicit_latest = Some(s)` — the protocol carries a
///     real mutable-tag pointer (npm's `dist-tags.latest`); the helper
///     uses `s` verbatim for the `OnDistTagMove` gate.
///   - `optional_explicit_latest = None` — the protocol has no native
///     `latest`; the helper synthesises one by `max_by(ordering)` over
///     `upstream_versions` (pypi / cargo shape). When
///     `upstream_versions` is also empty, the `OnDistTagMove` branch
///     is skipped entirely (there is no candidate to gate against).
/// - `spawner` — runs the format-specific per-version pull-spawn loop.
///   Called at most once per invocation (only when the `OnDistTagMove`
///   gate fires — i.e. Hort does not already hold the resolved latest;
///   there is no unconditional `OnIndexFetch` call).
///   Each call receives the planner's [`PrefetchPlan`] and the
///   [`PrefetchTrigger`] discriminator. The spawner is responsible for
///   short-circuiting on `PrefetchPlan::is_empty` (the existing
///   per-format spawners already do).
///
/// # Behaviour
///
/// See the module-level doc for the canonical four-step sequence.
/// The function never returns an error: the planner's only failure
/// modes are early exits (disabled policy / trigger not subscribed)
/// which are operator policy states, not errors; the spawner spawns
/// background tasks via `tokio::spawn` and never blocks the caller.
///
/// # Tracing
///
/// `#[tracing::instrument(skip(ctx, body, pkg_status, ordering,
/// parser, spawner))]` — `ctx` and `body` are typically large;
/// `pkg_status`, `parser`, and `spawner` are not `Display`/`Debug`
/// shapes worth rendering; `ordering` is `dyn VersionOrdering`
/// (no `Debug` bound on the trait). One `info!` line is emitted on
/// each call with the per-trigger outcome counts; no `err`
/// annotation per the architect tracing rules (operator-policy
/// skips are not errors).
// The argument list is deliberate: the
// callable shape every per-format consumer adopts is the same eight
// values plus two closures. Wrapping any of them in a record type
// would introduce a per-call construction burden every per-format
// consumer has to pay at every serve site.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    skip(ctx, body, pkg_status, ordering, parser, spawner),
    fields(
        format = %format,
        repository = %repo.key,
        package = %package,
    ),
)]
pub fn fire_hot_path_trigger<Ctx, P, S>(
    ctx: &Arc<Ctx>,
    planner: &PrefetchUseCase,
    repo: &Repository,
    package: &str,
    body: &[u8],
    pkg_status: &[(String, QuarantineStatus)],
    ordering: &dyn VersionOrdering,
    format: &'static str,
    parser: P,
    spawner: S,
) where
    Ctx: ?Sized,
    P: FnOnce(&[u8]) -> (Vec<String>, Option<String>),
    S: Fn(&Arc<Ctx>, &Repository, &str, PrefetchPlan, PrefetchTrigger),
{
    // ---- Step 1: enabled-escape -------------------------------------
    // Cheap short-circuit. The planner would emit
    // `skipped{reason=disabled}` itself, but skipping the parse + the
    // planner call entirely is the steady-state-cost optimisation
    // every existing per-format trigger pays.
    if !repo.prefetch_policy.enabled {
        return;
    }

    // ---- Step 2: parse upstream version set --------------------------
    let (upstream_versions, explicit_latest) = parser(body);
    let upstream_refs: Vec<&str> = upstream_versions.iter().map(String::as_str).collect();

    // ---- Step 3: compute "latest" ------------------------------------
    // (There is deliberately no `plan + spawn OnIndexFetch` step;
    // the helper anchors on `OnDistTagMove` divergence-detection
    // only. The convenience workflow such a step would serve — warm
    // newer versions of a touched package on anonymous reads — is
    // covered by the explicit, JWT-only `hort-cli prefetch` endpoint.)
    //
    // Explicit-from-parser wins when present (npm's
    // `dist-tags.latest`); otherwise synthesise via
    // `max_by(ordering)` over the parsed version set (pypi / cargo).
    // An empty `upstream_versions` combined with a `None` explicit
    // latest yields `None` — the `OnDistTagMove` branch then
    // short-circuits below, which is the right behaviour: there is no
    // candidate to gate against.
    let latest: Option<String> = match explicit_latest {
        Some(s) => Some(s),
        None => upstream_refs
            .iter()
            .copied()
            .max_by(|a, b| ordering.compare(a, b))
            .map(str::to_string),
    };

    // ---- Step 4: OnDistTagMove gate ---------------------------------
    // Fire only when the resolved latest is NOT in Hort's held set —
    // that IS the detection event (a tag pointing at a version Hort
    // has never seen). When Hort already holds the latest, there is no
    // tag-move signal to act on.
    let (on_dist_tag_move_planned, on_dist_tag_move_skipped) = if let Some(latest_str) = latest {
        let hort_holds = pkg_status.iter().any(|(held, _)| held == &latest_str);
        if hort_holds {
            (0usize, true)
        } else {
            let plan_tag = planner.plan(
                repo,
                package,
                PrefetchTrigger::OnDistTagMove,
                &upstream_refs,
                pkg_status,
                ordering,
            );
            let planned = plan_tag.versions.len();
            spawner(ctx, repo, package, plan_tag, PrefetchTrigger::OnDistTagMove);
            (planned, false)
        }
    } else {
        // No latest to gate against — empty upstream set with no
        // explicit-latest. Neither plan nor spawn fires; the field
        // still reports the per-trigger outcome for parity with the
        // hort_holds-skipped arm.
        (0usize, true)
    };

    tracing::info!(
        on_dist_tag_move_planned,
        on_dist_tag_move_skipped,
        "prefetch hot-path trigger fired",
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use chrono::Utc;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{
        IndexMode, PrefetchPolicy, ReplicationPriority, Repository, RepositoryFormat,
        RepositoryType,
    };
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::MetricKind;
    use uuid::Uuid;

    use crate::use_cases::index_serve_filter::{NpmSemverOrdering, Pep440Ordering};

    // ------------------------------------------------------------------
    // Test fixtures
    // ------------------------------------------------------------------

    /// Per-format spawner closure inputs the test wants to inspect.
    /// Captured by the spawner closure so each test can assert on
    /// (a) how many times the spawner was invoked and (b) which
    /// trigger discriminator each invocation carried.
    #[derive(Debug, Clone)]
    struct SpawnerCall {
        package: String,
        repo_key: String,
        plan: PrefetchPlan,
        trigger: PrefetchTrigger,
    }

    /// `Ctx` is generic in the helper signature so any monomorphisation
    /// works. The test mostly uses a unit struct to confirm a non-
    /// `AppContext` type also satisfies the bounds, exercising the
    /// generic-over-Ctx deviation.
    struct TestCtx;

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

    /// Construct a recording spawner closure. The returned `Arc<Mutex<…>>`
    /// is shared with the closure and consumed by the test after the
    /// helper returns.
    ///
    /// The pair-of-(`Arc<Mutex<_>>` + `impl Fn(…)`) shape is wider than
    /// clippy's `type_complexity` default. Factoring the spawner type
    /// out (it varies by `Ctx` and embeds two reference parameters)
    /// would not reduce the cognitive load — the return type IS the
    /// test fixture's contract.
    #[allow(clippy::type_complexity)]
    fn recording_spawner() -> (
        Arc<Mutex<Vec<SpawnerCall>>>,
        impl Fn(&Arc<TestCtx>, &Repository, &str, PrefetchPlan, PrefetchTrigger),
    ) {
        let calls: Arc<Mutex<Vec<SpawnerCall>>> = Arc::new(Mutex::new(Vec::new()));
        let calls_for_closure = Arc::clone(&calls);
        let closure = move |_ctx: &Arc<TestCtx>,
                            repo: &Repository,
                            package: &str,
                            plan: PrefetchPlan,
                            trigger: PrefetchTrigger| {
            calls_for_closure.lock().unwrap().push(SpawnerCall {
                package: package.to_string(),
                repo_key: repo.key.clone(),
                plan,
                trigger,
            });
        };
        (calls, closure)
    }

    /// Probe a metric snapshot for a single counter matching all the
    /// supplied (key, value) label predicates. Returns the counter's
    /// integer value, or `None` if no matching counter exists.
    fn counter_value(
        snapshot: &[(
            metrics_util::CompositeKey,
            Option<metrics::Unit>,
            Option<metrics::SharedString>,
            DebugValue,
        )],
        name: &str,
        wanted_labels: &[(&str, &str)],
    ) -> Option<u64> {
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

    // ------------------------------------------------------------------
    // 1. prefetch disabled — helper returns immediately, no plan/spawn,
    //    no metric ticks.
    // ------------------------------------------------------------------

    #[test]
    fn disabled_policy_returns_immediately_without_calling_parser_or_spawner() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let ctx = Arc::new(TestCtx);
        let planner = PrefetchUseCase::new();
        let repo = repo_with_policy("npm-mirror", PrefetchPolicy::default());
        let parser_called = Arc::new(Mutex::new(false));
        let parser_called_for_closure = Arc::clone(&parser_called);
        let (spawner_calls, spawner) = recording_spawner();

        metrics::with_local_recorder(&recorder, || {
            fire_hot_path_trigger(
                &ctx,
                &planner,
                &repo,
                "express",
                b"body bytes",
                &[],
                &NpmSemverOrdering,
                "npm",
                |_body| {
                    *parser_called_for_closure.lock().unwrap() = true;
                    (vec!["1.0.0".into()], Some("1.0.0".into()))
                },
                spawner,
            );
        });

        // Parser is NOT called — the disabled-policy escape happens
        // before parsing. This is the steady-state-cost optimisation
        // the existing per-format triggers pay.
        assert!(
            !*parser_called.lock().unwrap(),
            "parser must not run when policy.enabled = false"
        );
        // Spawner is NOT called either.
        assert!(
            spawner_calls.lock().unwrap().is_empty(),
            "spawner must not run when policy.enabled = false"
        );
        // The catalog: the helper itself does not invoke the planner
        // in this branch (the early-exit happens before it), so
        // `hort_prefetch_enqueued_total` must not fire. The planner
        // would have fired `hort_prefetch_skipped_total{reason=disabled}`
        // if we had reached it; we did NOT, so that counter is also
        // absent. This pins the optimisation contract: skip the parse
        // AND the planner call when the operator hasn't opted in.
        let snapshot = snapshotter.snapshot().into_vec();
        assert!(
            counter_value(&snapshot, "hort_prefetch_enqueued_total", &[]).is_none(),
            "hort_prefetch_enqueued_total must not fire when disabled",
        );
        assert!(
            counter_value(
                &snapshot,
                "hort_prefetch_skipped_total",
                &[("reason", "disabled")]
            )
            .is_none(),
            "the helper short-circuits before the planner; no skipped{{disabled}} tick from this call",
        );
    }

    // ------------------------------------------------------------------
    // 2. trigger not subscribed — `OnDistTagMove` is NOT in
    //    policy.triggers; the planner emits
    //    skipped{reason=trigger_not_enabled}, returns empty plan, and
    //    the spawner gets that empty plan for `OnDistTagMove`.
    //    There is no `OnIndexFetch` call, so the
    //    helper invokes the planner at most once per call.
    // ------------------------------------------------------------------

    #[test]
    fn trigger_not_subscribed_emits_skipped_label_and_spawner_gets_empty_plan() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let ctx = Arc::new(TestCtx);
        let planner = PrefetchUseCase::new();
        // Enabled, but only `Scheduled` subscribed — `OnDistTagMove`
        // is NOT in the list. The helper will still call the planner
        // when the divergence gate fires (because policy.enabled is
        // true), but the planner returns empty for the un-subscribed
        // trigger.
        let repo = repo_with_policy(
            "npm-mirror",
            enabled_policy(vec![PrefetchTrigger::Scheduled], 3),
        );
        let (spawner_calls, spawner) = recording_spawner();

        metrics::with_local_recorder(&recorder, || {
            fire_hot_path_trigger(
                &ctx,
                &planner,
                &repo,
                "express",
                b"body",
                &[],
                &NpmSemverOrdering,
                "npm",
                |_body| (vec!["1.0.0".into(), "2.0.0".into()], None),
                spawner,
            );
        });

        // Spawner was called once for `OnDistTagMove` (the resolved
        // latest `2.0.0` is not in the empty `pkg_status`); the planner
        // short-circuits with an empty plan because `OnDistTagMove`
        // is not subscribed.
        let calls = spawner_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "only `OnDistTagMove` fires");
        assert_eq!(calls[0].trigger, PrefetchTrigger::OnDistTagMove);
        assert_eq!(calls[0].package, "express");
        assert_eq!(calls[0].repo_key, "npm-mirror");
        assert!(calls[0].plan.is_empty(), "un-subscribed trigger → empty");

        // The planner emitted skipped{trigger_not_enabled} once.
        let snapshot = snapshotter.snapshot().into_vec();
        let skipped = counter_value(
            &snapshot,
            "hort_prefetch_skipped_total",
            &[("reason", "trigger_not_enabled")],
        )
        .expect("skipped{trigger_not_enabled} must fire");
        assert_eq!(
            skipped, 1,
            "fires once for the surviving `OnDistTagMove` planner call"
        );
        assert!(
            counter_value(&snapshot, "hort_prefetch_enqueued_total", &[]).is_none(),
            "no enqueued counter when the trigger is not subscribed",
        );
    }

    // ------------------------------------------------------------------
    // 3. divergent latest, never held — explicit-latest = Some("2.0.0"),
    //    absent from pkg_status → OnDistTagMove plan call fires,
    //    spawner invoked once.
    // ------------------------------------------------------------------

    #[test]
    fn divergent_explicit_latest_never_held_fires_on_dist_tag_move() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let ctx = Arc::new(TestCtx);
        let planner = PrefetchUseCase::new();
        let repo = repo_with_policy(
            "npm-mirror",
            enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
        );
        // Hort holds 1.0.0 only. Upstream's explicit latest is 2.0.0,
        // not held.
        let pkg_status = vec![("1.0.0".to_string(), QuarantineStatus::Released)];
        let (spawner_calls, spawner) = recording_spawner();

        metrics::with_local_recorder(&recorder, || {
            fire_hot_path_trigger(
                &ctx,
                &planner,
                &repo,
                "express",
                b"body",
                &pkg_status,
                &NpmSemverOrdering,
                "npm",
                |_body| {
                    (
                        vec!["1.0.0".into(), "1.5.0".into(), "2.0.0".into()],
                        Some("2.0.0".into()),
                    )
                },
                spawner,
            );
        });

        let calls = spawner_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "spawner runs once: OnDistTagMove only");
        assert_eq!(calls[0].trigger, PrefetchTrigger::OnDistTagMove);
        assert!(
            !calls[0].plan.is_empty(),
            "OnDistTagMove should plan candidates"
        );

        let snapshot = snapshotter.snapshot().into_vec();
        let on_dist_tag_move = counter_value(
            &snapshot,
            "hort_prefetch_enqueued_total",
            &[("trigger", "on_dist_tag_move")],
        )
        .expect("enqueued{trigger=on_dist_tag_move} must fire");
        assert!(on_dist_tag_move >= 1);
    }

    // ------------------------------------------------------------------
    // 4. divergent latest, already held — same parser output as case
    //    3 but pkg_status includes "2.0.0"; the `OnDistTagMove` plan
    //    call MUST NOT fire; spawner is never invoked.
    // ------------------------------------------------------------------

    #[test]
    fn divergent_explicit_latest_already_held_skips_on_dist_tag_move() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let ctx = Arc::new(TestCtx);
        let planner = PrefetchUseCase::new();
        let repo = repo_with_policy(
            "npm-mirror",
            enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
        );
        let pkg_status = vec![
            ("1.0.0".to_string(), QuarantineStatus::Released),
            ("2.0.0".to_string(), QuarantineStatus::Released),
        ];
        let (spawner_calls, spawner) = recording_spawner();

        metrics::with_local_recorder(&recorder, || {
            fire_hot_path_trigger(
                &ctx,
                &planner,
                &repo,
                "express",
                b"body",
                &pkg_status,
                &NpmSemverOrdering,
                "npm",
                |_body| (vec!["1.0.0".into(), "2.0.0".into()], Some("2.0.0".into())),
                spawner,
            );
        });

        let calls = spawner_calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            0,
            "spawner never fires — OnDistTagMove gated by held latest, and there is no unconditional OnIndexFetch spawn"
        );

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(
            counter_value(
                &snapshot,
                "hort_prefetch_enqueued_total",
                &[("trigger", "on_dist_tag_move")],
            )
            .is_none(),
            "no enqueued{{on_dist_tag_move}} tick when hort already holds the latest",
        );
    }

    // ------------------------------------------------------------------
    // 5. no-prior-held — empty pkg_status, fresh package; planner
    //    output non-empty; spawner invoked once for `OnDistTagMove`
    //    (the explicit latest is not held).
    // ------------------------------------------------------------------

    #[test]
    fn no_prior_held_fires_on_dist_tag_move() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let ctx = Arc::new(TestCtx);
        let planner = PrefetchUseCase::new();
        let repo = repo_with_policy(
            "npm-mirror",
            enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
        );
        let (spawner_calls, spawner) = recording_spawner();

        metrics::with_local_recorder(&recorder, || {
            fire_hot_path_trigger(
                &ctx,
                &planner,
                &repo,
                "express",
                b"body",
                &[],
                &NpmSemverOrdering,
                "npm",
                |_body| (vec!["1.0.0".into()], Some("1.0.0".into())),
                spawner,
            );
        });

        let calls = spawner_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "fresh package fires OnDistTagMove only");
        assert_eq!(calls[0].trigger, PrefetchTrigger::OnDistTagMove);
        assert_eq!(calls[0].plan.versions, vec!["1.0.0".to_string()]);

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(counter_value(
            &snapshot,
            "hort_prefetch_enqueued_total",
            &[("trigger", "on_dist_tag_move")]
        )
        .is_some());
    }

    // ------------------------------------------------------------------
    // 6. explicit-latest verbatim — Some("2.0.0") wins even if a
    //    higher version exists in the parsed set. Pins the npm
    //    `dist-tags.latest` contract: an upstream `latest` pointing
    //    at a non-max version (back-pinned tag) is honoured verbatim.
    // ------------------------------------------------------------------

    #[test]
    fn explicit_latest_used_verbatim_over_max_by_ordering() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let ctx = Arc::new(TestCtx);
        let planner = PrefetchUseCase::new();
        let repo = repo_with_policy(
            "npm-mirror",
            enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
        );
        // Hort holds 1.0.0 (the upstream-asserted latest). The parsed
        // set contains 3.0.0 — semantically newer — but the explicit
        // latest must dominate, so the OnDistTagMove gate sees
        // "Hort holds latest" and short-circuits. With no unconditional
        // OnIndexFetch spawn, the
        // spawner fires zero times in this scenario.
        let pkg_status = vec![("1.0.0".to_string(), QuarantineStatus::Released)];
        let (spawner_calls, spawner) = recording_spawner();

        metrics::with_local_recorder(&recorder, || {
            fire_hot_path_trigger(
                &ctx,
                &planner,
                &repo,
                "express",
                b"body",
                &pkg_status,
                &NpmSemverOrdering,
                "npm",
                |_body| {
                    (
                        vec!["1.0.0".into(), "2.0.0".into(), "3.0.0".into()],
                        Some("1.0.0".into()),
                    )
                },
                spawner,
            );
        });

        let calls = spawner_calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            0,
            "explicit-latest = 1.0.0 (held) → OnDistTagMove skipped; there is no OnIndexFetch spawn"
        );

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(
            counter_value(
                &snapshot,
                "hort_prefetch_enqueued_total",
                &[("trigger", "on_dist_tag_move")],
            )
            .is_none(),
            "explicit-latest dominates max_by; tag-move gate sees held",
        );
    }

    // ------------------------------------------------------------------
    // 7. max_by(ordering) — None explicit-latest synthesises via the
    //    per-format ordering. Famous case: 1.10.0 must beat 1.9.0
    //    under semver, not lex. Pins the synthesis branch.
    // ------------------------------------------------------------------

    #[test]
    fn computed_latest_via_npm_semver_ordering_picks_semantic_max() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let ctx = Arc::new(TestCtx);
        let planner = PrefetchUseCase::new();
        let repo = repo_with_policy(
            "npm-mirror",
            enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
        );
        // Hort holds 1.9.0 (lex-max, semver-not-max). Upstream
        // advertises 1.9.0 and 1.10.0; the parser returns
        // explicit-latest = None, so the helper must synthesise
        // 1.10.0 as the latest and fire OnDistTagMove (not held).
        let pkg_status = vec![("1.9.0".to_string(), QuarantineStatus::Released)];
        let (spawner_calls, spawner) = recording_spawner();

        metrics::with_local_recorder(&recorder, || {
            fire_hot_path_trigger(
                &ctx,
                &planner,
                &repo,
                "express",
                b"body",
                &pkg_status,
                &NpmSemverOrdering,
                "npm",
                |_body| (vec!["1.9.0".into(), "1.10.0".into()], None),
                spawner,
            );
        });

        let calls = spawner_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].trigger, PrefetchTrigger::OnDistTagMove);
        // The OnDistTagMove plan must include 1.10.0 (the synthesised
        // latest), proving the synthesis used semver ordering not lex.
        assert!(
            calls[0].plan.versions.iter().any(|v| v == "1.10.0"),
            "OnDistTagMove plan must include the semver-max 1.10.0, not lex-max 1.9.0",
        );

        let snapshot = snapshotter.snapshot().into_vec();
        assert!(counter_value(
            &snapshot,
            "hort_prefetch_enqueued_total",
            &[("trigger", "on_dist_tag_move")]
        )
        .is_some());
    }

    // ------------------------------------------------------------------
    // 7b. max_by(ordering) for PyPI / PEP 440 — proves the trait-
    //     object boundary works for the second concrete ordering.
    //     PEP 440 `1.0a1` < `1.0` (pre-release ordering); helper
    //     must pick `1.0` as latest.
    // ------------------------------------------------------------------

    #[test]
    fn computed_latest_via_pep440_ordering_picks_release_over_pre_release() {
        let ctx = Arc::new(TestCtx);
        let planner = PrefetchUseCase::new();
        let repo = repo_with_policy(
            "pypi-mirror",
            enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
        );
        // Hort holds the pre-release. Upstream offers the final
        // release; computed latest under PEP 440 ordering picks the
        // release.
        let pkg_status = vec![("1.0a1".to_string(), QuarantineStatus::Released)];
        let (spawner_calls, spawner) = recording_spawner();

        let recorder = DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            fire_hot_path_trigger(
                &ctx,
                &planner,
                &repo,
                "requests",
                b"body",
                &pkg_status,
                &Pep440Ordering,
                "pypi",
                |_body| (vec!["1.0a1".into(), "1.0".into()], None),
                spawner,
            );
        });

        let calls = spawner_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "tag-move detected → OnDistTagMove spawn");
        assert_eq!(calls[0].trigger, PrefetchTrigger::OnDistTagMove);
        assert!(
            calls[0].plan.versions.iter().any(|v| v == "1.0"),
            "OnDistTagMove plan must include the PEP 440-max release 1.0"
        );
    }

    // ------------------------------------------------------------------
    // 8. empty upstream + None explicit-latest — neither trigger
    //    fires: the `OnDistTagMove` gate has no latest candidate to
    //    compare against. The helper
    //    short-circuits without invoking the spawner at all (no
    //    OnIndexFetch fallback). Pins the
    //    `upstream_versions = []` corner.
    // ------------------------------------------------------------------

    #[test]
    fn empty_upstream_and_no_explicit_latest_fires_nothing() {
        let ctx = Arc::new(TestCtx);
        let planner = PrefetchUseCase::new();
        let repo = repo_with_policy(
            "npm-mirror",
            enabled_policy(vec![PrefetchTrigger::OnDistTagMove], 5),
        );
        let (spawner_calls, spawner) = recording_spawner();

        let recorder = DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            fire_hot_path_trigger(
                &ctx,
                &planner,
                &repo,
                "express",
                b"body",
                &[],
                &NpmSemverOrdering,
                "npm",
                |_body| (Vec::new(), None),
                spawner,
            );
        });

        let calls = spawner_calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            0,
            "no latest candidate → OnDistTagMove gate short-circuits; there is no unconditional OnIndexFetch spawn"
        );
    }
}
