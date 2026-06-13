//! `PatchCandidateUseCase`.
//!
//! Admin-only read of the patch-candidate quarantine surface. See
//! `docs/architecture/how-to/quarantine-patch-release.md`.

use std::sync::Arc;

use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::ports::patch_candidate_repository::{
    PatchCandidate, PatchCandidateFilter, PatchCandidateRepository,
};

use crate::error::{AppError, AppResult};
use crate::metrics::{emit_patch_candidates_listed, values, PatchCandidateListResult};
use crate::use_cases::CallerPrivileges;

/// Hard cap on `filter.limit`. Anything above this returns
/// `AppError::Domain(DomainError::Validation(..))` *before* the repo
/// is called, so a malicious caller cannot DoS the adapter via
/// `limit = u32::MAX`.
pub const MAX_LIMIT: u32 = 500;

/// Application use case for `GET /admin/quarantine/patch-candidates`.
pub struct PatchCandidateUseCase {
    repo: Arc<dyn PatchCandidateRepository>,
}

impl PatchCandidateUseCase {
    /// Construct from the outbound port. The Postgres adapter
    /// provides the production impl; the inline
    /// test mock in this module's `tests` block provides the unit
    /// test impl.
    pub fn new(repo: Arc<dyn PatchCandidateRepository>) -> Self {
        Self { repo }
    }

    /// List patch candidates visible to an admin.
    #[tracing::instrument(skip(self, privileges))]
    pub async fn list(
        &self,
        actor: ApiActor,
        privileges: CallerPrivileges,
        filter: PatchCandidateFilter,
    ) -> AppResult<Vec<PatchCandidate>> {
        // Repository label value for `hort_patch_candidates_listed_total`.
        // Resolved once up-front from the handler-supplied hint
        // (`filter.repository_key_for_metric`) so every emission below
        // (denied / invalid / error / ok) carries the same label.
        // `None` → `_all` sentinel for admin-wide scope; `Some(key)` →
        // the resolved key emitted verbatim.
        // `"unknown"` is not reachable from the HTTP handler because
        // `find_by_key` failures surface as 404 before the use case
        // runs — the sentinel stays reserved for future non-HTTP paths.
        let repo_label: String = filter
            .repository_key_for_metric
            .clone()
            .unwrap_or_else(|| values::REPOSITORY_ALL.to_string());

        // 1. Authz first — denials never reach validation, never reach the repo.
        //    Inline-log-then-return mirrors `QuarantineUseCase::admin_release`
        //    at crates/hort-app/src/use_cases/quarantine_use_case.rs:815-818.
        //    Carry the filter shape so the audit trail captures the attempt.
        if let Err(e) = privileges.require_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                filter_repository_id = ?filter.repository_id,
                filter_limit = filter.limit,
                "patch-candidate list denied: not admin",
            );
            emit_patch_candidates_listed(&repo_label, PatchCandidateListResult::Denied);
            return Err(e);
        }

        // 2. Validate the limit BEFORE calling the repo. `limit > MAX_LIMIT`
        //    is a caller-input issue (`result=invalid`), not a
        //    system error — Validation, not External.
        if filter.limit > MAX_LIMIT {
            tracing::info!(
                actor_id = %actor.user_id,
                filter_limit = filter.limit,
                max_limit = MAX_LIMIT,
                "patch-candidate list rejected: limit exceeds maximum",
            );
            emit_patch_candidates_listed(&repo_label, PatchCandidateListResult::Invalid);
            return Err(AppError::Domain(DomainError::Validation(format!(
                "limit {n} exceeds maximum {MAX_LIMIT}",
                n = filter.limit
            ))));
        }

        // 3. Repo call. Error path emits `result=error` and propagates;
        //    no other path emits `error`.
        let candidates = match self.repo.list_candidates(filter).await {
            Ok(c) => c,
            Err(e) => {
                emit_patch_candidates_listed(&repo_label, PatchCandidateListResult::Error);
                return Err(e.into());
            }
        };

        // 4. Success-side audit log — security-relevant read of the
        //    patch-fix surface. Deliberately
        //    at info! (not debug!) because the surface enumerates
        //    artifacts an operator is about to act on.
        tracing::info!(
            actor_id = %actor.user_id,
            candidate_count = candidates.len(),
            "admin queried patch-candidate quarantine surface",
        );
        emit_patch_candidates_listed(&repo_label, PatchCandidateListResult::Ok);

        Ok(candidates)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use hort_domain::error::DomainResult;
    use hort_domain::ports::BoxFuture;
    use uuid::Uuid;

    use super::*;
    use crate::use_cases::test_support::{
        admin_privileges, api_actor, reviewer_privileges, unprivileged,
    };

    /// Inline mock — records every `list_candidates(filter)` call and
    /// returns a seeded `Vec<PatchCandidate>`. `std::sync::Mutex` per
    /// the project's existing in-test recorder convention (e.g.
    /// `MockJobsRepository` in `test_support.rs`).
    ///
    /// Failure-injection: `fail_next(err)` seeds a one-shot error
    /// returned by the next `list_candidates` call. Mirrors the
    /// `MockJobsRepository::fail_next_enqueue_scan` pattern in
    /// `test_support.rs` — used by the `result=error`
    /// metric-emission test.
    struct MockRepo {
        calls: Mutex<Vec<PatchCandidateFilter>>,
        rows: Mutex<Vec<PatchCandidate>>,
        fail_next: Mutex<Option<DomainError>>,
    }

    impl MockRepo {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                rows: Mutex::new(Vec::new()),
                fail_next: Mutex::new(None),
            }
        }

        fn seed(&self, rows: Vec<PatchCandidate>) {
            *self.rows.lock().unwrap() = rows;
        }

        fn calls(&self) -> Vec<PatchCandidateFilter> {
            self.calls.lock().unwrap().clone()
        }

        /// Configure `list_candidates` to return an error on the next
        /// call (one-shot). Mirrors
        /// `MockJobsRepository::fail_next_enqueue_scan`.
        fn fail_next(&self, err: DomainError) {
            *self.fail_next.lock().unwrap() = Some(err);
        }
    }

    impl PatchCandidateRepository for MockRepo {
        fn list_candidates<'a>(
            &'a self,
            filter: PatchCandidateFilter,
        ) -> BoxFuture<'a, DomainResult<Vec<PatchCandidate>>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(filter);
                if let Some(e) = self.fail_next.lock().unwrap().take() {
                    return Err(e);
                }
                Ok(self.rows.lock().unwrap().clone())
            })
        }
    }

    fn sample_candidate() -> PatchCandidate {
        use chrono::{DateTime, Utc};
        use hort_domain::entities::artifact::QuarantineStatus;
        use hort_domain::entities::repository::RepositoryFormat;
        use hort_domain::entities::scan_policy::SeverityThreshold;

        PatchCandidate {
            quarantined_artifact_id: Uuid::new_v4(),
            quarantined_version: Some("4.17.21".into()),
            quarantined_status: QuarantineStatus::Quarantined,
            quarantined_until: Some(DateTime::<Utc>::from_timestamp(0, 0).unwrap()),
            repository_id: Uuid::new_v4(),
            repository_key: "npm-main".into(),
            format: RepositoryFormat::Npm,
            package_name: "lodash".into(),
            vulnerable_artifact_id: Uuid::new_v4(),
            vulnerable_version: Some("4.17.20".into()),
            vulnerable_finding_count: 3,
            vulnerable_max_severity: Some(SeverityThreshold::High),
        }
    }

    // ---------- happy paths ----------------------------------------------

    /// Admin happy path with an empty result. Pins that the success path
    /// executed (repo called exactly once) — the unconditional info-log
    /// emission therefore fired by code-path coverage, even though we
    /// don't install a tracing subscriber to capture it.
    #[tokio::test]
    async fn list_admin_happy_path_empty_vec() {
        let repo = Arc::new(MockRepo::new());
        let uc = PatchCandidateUseCase::new(repo.clone());

        let out = uc
            .list(
                api_actor(),
                admin_privileges(),
                PatchCandidateFilter::default(),
            )
            .await
            .expect("admin happy path");

        assert!(out.is_empty());
        assert_eq!(repo.calls().len(), 1, "repo must be called exactly once");
    }

    /// Admin + default filter + seeded non-empty rows → Ok(rows passthrough).
    #[tokio::test]
    async fn list_admin_happy_path_non_empty_vec() {
        let repo = Arc::new(MockRepo::new());
        let c1 = sample_candidate();
        let c2 = sample_candidate();
        repo.seed(vec![c1.clone(), c2.clone()]);

        let uc = PatchCandidateUseCase::new(repo.clone());
        let out = uc
            .list(
                api_actor(),
                admin_privileges(),
                PatchCandidateFilter::default(),
            )
            .await
            .expect("admin happy path");

        assert_eq!(out.len(), 2, "use case returns repo rows verbatim");
        assert_eq!(out[0], c1);
        assert_eq!(out[1], c2);
    }

    // ---------- 403: non-admin denial ------------------------------------

    /// Reviewer-only callers (not admin) are rejected with Forbidden BEFORE
    /// the repo is called — admin parity with the
    /// release endpoint.
    #[tokio::test]
    async fn list_non_admin_reviewer_returns_forbidden_and_does_not_call_repo() {
        let repo = Arc::new(MockRepo::new());
        let uc = PatchCandidateUseCase::new(repo.clone());

        let err = uc
            .list(
                api_actor(),
                reviewer_privileges(),
                PatchCandidateFilter::default(),
            )
            .await
            .expect_err("reviewer must be forbidden");
        assert!(
            matches!(err, AppError::Domain(DomainError::Forbidden(_))),
            "expected Forbidden, got {err:?}"
        );
        assert!(
            repo.calls().is_empty(),
            "Forbidden path must not invoke the repo",
        );
    }

    /// Fully unprivileged caller is also rejected. Same code path as
    /// reviewer-only, but pins the explicit `is_reviewer = false` arm
    /// of `require_admin()` for branch coverage.
    #[tokio::test]
    async fn list_unprivileged_returns_forbidden_and_does_not_call_repo() {
        let repo = Arc::new(MockRepo::new());
        let uc = PatchCandidateUseCase::new(repo.clone());

        let err = uc
            .list(api_actor(), unprivileged(), PatchCandidateFilter::default())
            .await
            .expect_err("non-admin must be forbidden");
        assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
        assert!(repo.calls().is_empty());
    }

    // ---------- 400: oversize limit --------------------------------------

    /// `filter.limit > MAX_LIMIT` (501) → Validation, repo never called.
    #[tokio::test]
    async fn list_limit_just_over_max_returns_validation_and_does_not_call_repo() {
        let repo = Arc::new(MockRepo::new());
        let uc = PatchCandidateUseCase::new(repo.clone());

        let filter = PatchCandidateFilter {
            repository_id: None,
            limit: MAX_LIMIT + 1,
            repository_key_for_metric: None,
        };
        let err = uc
            .list(api_actor(), admin_privileges(), filter)
            .await
            .expect_err("501 must reject");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("501") && msg.contains("500"),
                    "validation msg must name actual and max: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        assert!(
            repo.calls().is_empty(),
            "Validation path must not call repo"
        );
    }

    /// `filter.limit = u32::MAX` → Validation. Catches the "huge value
    /// underflows the comparison" class of bug if `> MAX_LIMIT` were
    /// ever replaced with arithmetic.
    #[tokio::test]
    async fn list_limit_u32_max_returns_validation_and_does_not_call_repo() {
        let repo = Arc::new(MockRepo::new());
        let uc = PatchCandidateUseCase::new(repo.clone());

        let filter = PatchCandidateFilter {
            repository_id: None,
            limit: u32::MAX,
            repository_key_for_metric: None,
        };
        let err = uc
            .list(api_actor(), admin_privileges(), filter)
            .await
            .expect_err("u32::MAX must reject");
        assert!(matches!(err, AppError::Domain(DomainError::Validation(_))));
        assert!(repo.calls().is_empty());
    }

    // ---------- boundary: limit = MAX_LIMIT exactly ----------------------

    /// `filter.limit = MAX_LIMIT` (500) is allowed — the check is `>`,
    /// not `>=`. Pins the inclusive-of-500 contract.
    #[tokio::test]
    async fn list_limit_exact_max_is_allowed_and_repo_is_called() {
        let repo = Arc::new(MockRepo::new());
        let uc = PatchCandidateUseCase::new(repo.clone());

        let filter = PatchCandidateFilter {
            repository_id: None,
            limit: MAX_LIMIT,
            repository_key_for_metric: None,
        };
        let out = uc
            .list(api_actor(), admin_privileges(), filter.clone())
            .await
            .expect("limit=500 is admissible");
        assert!(out.is_empty());

        let calls = repo.calls();
        assert_eq!(calls.len(), 1, "repo must be called at the boundary");
        assert_eq!(calls[0].limit, MAX_LIMIT);
    }

    // ---------- filter passthrough ---------------------------------------

    /// The filter values (`repository_id` + `limit`) reach the repo
    /// verbatim — no rewriting / clamping inside the use case.
    #[tokio::test]
    async fn list_filter_passthrough_to_repo() {
        let repo = Arc::new(MockRepo::new());
        let uc = PatchCandidateUseCase::new(repo.clone());

        let repo_id = Uuid::new_v4();
        let filter = PatchCandidateFilter {
            repository_id: Some(repo_id),
            limit: 42,
            repository_key_for_metric: None,
        };
        uc.list(api_actor(), admin_privileges(), filter.clone())
            .await
            .expect("admin happy path");

        let calls = repo.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].repository_id, Some(repo_id));
        assert_eq!(calls[0].limit, 42);
    }

    // ---------- `hort_patch_candidates_listed_total` -----------------------

    /// Helper: assert exactly-one increment of
    /// `hort_patch_candidates_listed_total{repository=<repo>, result=<r>}`
    /// in `snap`, and no forbidden high-cardinality labels.
    fn assert_patch_candidates_listed_emitted_once(
        snap: metrics_util::debugging::Snapshot,
        expected_repository: &str,
        expected_result: &str,
    ) {
        use metrics_util::debugging::DebugValue;
        use metrics_util::MetricKind;

        let entries = snap.into_vec();
        let mut hits = entries.iter().filter(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_patch_candidates_listed_total"
        });
        let (key, _, _, value) = hits
            .next()
            .expect("hort_patch_candidates_listed_total must fire exactly once");
        assert!(
            hits.next().is_none(),
            "hort_patch_candidates_listed_total must fire only once per use-case call"
        );

        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(
            labels.get("repository"),
            Some(&expected_repository),
            "repository label must match the documented semantics \
             (_all sentinel when admin-wide, resolved key when scoped)"
        );
        assert_eq!(
            labels.get("result"),
            Some(&expected_result),
            "result label must match the use-case path"
        );

        // High-cardinality labels must NOT appear on
        // any `hort_app::metrics` counter.
        for forbidden in &[
            "artifact_id",
            "actor_id",
            "user_id",
            "content_hash",
            "purl",
            "package_name",
            "version",
        ] {
            assert!(
                !labels.contains_key(*forbidden),
                "forbidden label `{forbidden}` must not appear on \
                 hort_patch_candidates_listed_total",
            );
        }

        match value {
            DebugValue::Counter(n) => assert_eq!(
                *n, 1,
                "exactly one increment per use-case call (result={expected_result})"
            ),
            other => panic!("expected Counter, got {other:?}"),
        }
    }

    /// Admin happy path emits `result=ok` with `repository="_all"`.
    #[test]
    fn list_emits_metric_with_result_ok_on_happy_path() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(MockRepo::new());
        repo.seed(vec![sample_candidate()]);
        let uc = PatchCandidateUseCase::new(repo);

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.list(
                    api_actor(),
                    admin_privileges(),
                    PatchCandidateFilter::default(),
                ))
                .expect("admin happy path");
        });

        assert_patch_candidates_listed_emitted_once(snapshotter.snapshot(), "_all", "ok");
    }

    /// Non-admin caller emits `result=denied` *before* the early return.
    #[test]
    fn list_emits_metric_with_result_denied_on_non_admin() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(MockRepo::new());
        let uc = PatchCandidateUseCase::new(repo.clone());

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.list(
                    api_actor(),
                    reviewer_privileges(),
                    PatchCandidateFilter::default(),
                ))
                .expect_err("non-admin must be forbidden");
        });

        assert_patch_candidates_listed_emitted_once(snapshotter.snapshot(), "_all", "denied");
        // Denied path must NOT call the repo — pinned alongside the
        // metric assertion so a refactor that swaps the order surfaces.
        assert!(repo.calls().is_empty(), "denied path must not call repo");
    }

    /// `filter.limit > MAX_LIMIT` emits `result=invalid`; repo never
    /// called.
    #[test]
    fn list_emits_metric_with_result_invalid_on_oversize_limit() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(MockRepo::new());
        let uc = PatchCandidateUseCase::new(repo.clone());

        let filter = PatchCandidateFilter {
            repository_id: None,
            limit: MAX_LIMIT + 1,
            repository_key_for_metric: None,
        };

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.list(api_actor(), admin_privileges(), filter))
                .expect_err("limit > MAX_LIMIT must reject");
        });

        assert_patch_candidates_listed_emitted_once(snapshotter.snapshot(), "_all", "invalid");
        assert!(
            repo.calls().is_empty(),
            "invalid path must not call repo (validation runs before repo)"
        );
    }

    /// Repo `Err` emits `result=error` and propagates the error.
    #[test]
    fn list_emits_metric_with_result_error_on_repo_failure() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(MockRepo::new());
        // The adapter surfaces I/O failures as `DomainError::Invariant`
        // (see `hort-adapters-postgres/src/patch_candidate_repo.rs`).
        repo.fail_next(DomainError::Invariant("simulated adapter failure".into()));
        let uc = PatchCandidateUseCase::new(repo.clone());

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.list(
                    api_actor(),
                    admin_privileges(),
                    PatchCandidateFilter::default(),
                ))
                .expect_err("repo error must propagate");
        });

        assert_patch_candidates_listed_emitted_once(snapshotter.snapshot(), "_all", "error");
        // Error path called the repo exactly once before failing.
        assert_eq!(
            repo.calls().len(),
            1,
            "error path calls the repo exactly once before emitting + returning",
        );
    }

    /// `filter.repository_key_for_metric = Some("npm-proxy")` → the
    /// metric carries `repository="npm-proxy"` instead of the `_all`
    /// sentinel. Pins the key-pass-through contract:
    /// the handler resolves `?repository=<key>` to a UUID + key,
    /// threads the key through the filter, and the use case emits it
    /// verbatim on `ok`.
    #[test]
    fn list_emits_metric_with_resolved_key_when_filter_carries_one() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(MockRepo::new());
        let uc = PatchCandidateUseCase::new(repo);

        let filter = PatchCandidateFilter {
            repository_id: Some(Uuid::new_v4()),
            limit: 100,
            repository_key_for_metric: Some("npm-proxy".into()),
        };

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.list(api_actor(), admin_privileges(), filter))
                .expect("admin happy path");
        });

        assert_patch_candidates_listed_emitted_once(snapshotter.snapshot(), "npm-proxy", "ok");
    }

    /// Same key-pass-through contract on the `denied` path — even on
    /// authz failure the emission carries the resolved key (the
    /// handler resolved the repo *before* invoking the use case, so
    /// the key is known regardless of the authz outcome). Pins the
    /// "label resolved up-front, every emission below uses it"
    /// invariant.
    #[test]
    fn list_emits_metric_with_resolved_key_on_denied_path() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let repo = Arc::new(MockRepo::new());
        let uc = PatchCandidateUseCase::new(repo);

        let filter = PatchCandidateFilter {
            repository_id: Some(Uuid::new_v4()),
            limit: 100,
            repository_key_for_metric: Some("npm-proxy".into()),
        };

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(uc.list(api_actor(), reviewer_privileges(), filter))
                .expect_err("non-admin must be forbidden");
        });

        assert_patch_candidates_listed_emitted_once(snapshotter.snapshot(), "npm-proxy", "denied");
    }
}
