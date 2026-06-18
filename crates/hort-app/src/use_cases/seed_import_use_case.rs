//! Seed-import cutover path.
//!
//! A quarantining proxy deployed against a live build farm has an empty
//! released set on day one → a window-long outage for *every* dependency.
//! Seed-import is a **one-shot admin path** that bulk-registers an
//! operator-supplied dependency set so the *time* gate is already
//! elapsed on import: each artifact is created `Quarantined` with
//! `quarantine_window_start` backdated far enough that the computed
//! deadline (`anchor + effective_duration`) is already
//! at or before `now()`. The next sweep / scan-complete fast-path
//! releases the artifact as soon as a clean scan lands — typically
//! within minutes, not the full window.
//!
//! **Critical invariant — the scan still gates.** Seed-import stamps
//! the time anchor only. A dirty scan still transitions the artifact
//! to `Rejected` via `Artifact::reject_from_scan` (fail-closed
//! release authority is unchanged). This is **NOT** `ScanWaived` and
//! **NOT** permissive mode (`quarantineDuration: 0`); both of those
//! retire the scan as a gate. Seed-import only retires the *observation
//! window* — the operator is asserting that a deployment's
//! already-in-production dependency closure does not benefit from the
//! observation half of strict mode, but still needs the scan half.
//!
//! ## Architecture
//!
//! Wraps [`IngestUseCase::register_existing_cas_blob`] with the
//! `RegisterExistingCasBlobRequest.seed_import_quarantine_anchor` field.
//! That field, when `Some(anchor)`, drives the
//! `register_by_hash_inner` path to emit `ArtifactQuarantined` on the
//! same stream as the preceding `ArtifactIngested` (two transitions,
//! mirroring `ingest_inner`'s strict-mode quarantine step).
//!
//! Idempotency is structural: `register_by_hash`'s same-path-same-hash
//! dedup (`artifacts.find_by_path` + post-put SHA compare) returns the
//! existing artifact unchanged on a re-run; the use case counts these
//! as `already_imported`. A re-run with the same input set is a no-op.
//!
//! ## Why the bytes must be in CAS
//!
//! The use case calls `register_existing_cas_blob`, whose `None`-branch
//! verifies the bytes are CAS-present via `storage.exists` and resolves
//! `size_bytes` via `storage.size_of`. Seed-import does **not** fetch
//! bytes from upstream — that would be a regular pull-through. The
//! deployment scenario this addresses is "operator restored CAS from
//! backup and now wants to register the metadata rows"; if the bytes
//! aren't present, the per-item ingest fails with `NotFound` and the
//! summary counts it as an error.
//!
//! ## Backdated anchor — policy resolution
//!
//! Per item, the use case:
//!
//! 1. Resolves the repository (for `policy_scope` lookup).
//! 2. Resolves the active `ScanPolicy` for the repo — repo-scoped
//!    takes precedence over global; mirrors
//!    `IngestUseCase::resolve_active_policy_for_repo` and
//!    `QuarantineUseCase::record_scan_result`.
//! 3. Reads `policy.quarantine_duration_secs`; falls back to
//!    [`DEFAULT_QUARANTINE_DURATION_SECS`] when no policy applies (no
//!    `DefaultPolicy::quarantine_duration_secs` exists in
//!    `hort-domain` today; the constant here is the concrete
//!    fallback).
//! 4. Computes `anchor = now - effective_duration -
//!    BACKDATE_MARGIN_SECS` so the *computed* deadline is already
//!    elapsed by at least `BACKDATE_MARGIN_SECS`.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::entities::scan_policy::ScanPolicyProjection;
use hort_domain::events::{ApiActor, PolicyScope};
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::types::{ArtifactCoords, ContentHash};

use crate::error::{AppError, AppResult};
use crate::use_cases::ingest_use_case::{IngestUseCase, RegisterExistingCasBlobRequest};

/// Fallback `quarantine_duration_secs` when no `ScanPolicy` matches the
/// repository. 24 hours.
///
/// There is no `DefaultPolicy::quarantine_duration_secs` helper in
/// `hort-domain` today. Seed-import is the first concrete caller that
/// needs the fallback, so the constant lives here; if the domain-level
/// helper is ever added, this `const` becomes its mirror.
///
/// 24h matches the strict-mode policy YAML examples (`quarantineDuration:
/// 24h`) shipped in `examples/scan-policy/`.
pub const DEFAULT_QUARANTINE_DURATION_SECS: i64 = 24 * 3600;

/// Additional seconds subtracted from the backdated anchor so the
/// computed deadline is past — not at — `now()`. A small fixed margin;
/// 60 seconds is more than enough to absorb any clock skew between the
/// subcommand's `Utc::now()` and the worker's release sweep query.
///
/// Without the margin, `anchor + effective_duration == now()` would
/// sit on the boundary the candidacy SQL compares with `<=`; including
/// it makes the seed-imported set unambiguously expired-by-construction.
pub const BACKDATE_MARGIN_SECS: i64 = 60;

/// One row of an operator-supplied seed-import set.
///
/// Five required fields — minimal contract, no optional hash:
///
/// - `repository_id` — target repo. The use case looks up the repo +
///   the format match check inside `register_by_hash` enforces that
///   `coords.format` (set from `format`) equals `repo.format`.
/// - `format` — `RepositoryFormat` string (e.g. `"pypi"`, `"npm"`).
/// - `name` — normalized artifact name.
/// - `version` — artifact version (semver / PEP 440 / Maven format).
/// - `content_hash` — SHA-256 of the CAS-present bytes.
///
/// `path` is derived as `<name>/<version>` for v1. A future revision
/// could carry the path explicitly when the operator's source-of-
/// truth (lockfile) has it. For v1 the derived shape is the smallest
/// honest contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedImportItem {
    pub repository_id: Uuid,
    pub format: RepositoryFormat,
    pub name: String,
    pub version: String,
    pub content_hash: ContentHash,
}

/// Run summary returned by [`SeedImportUseCase::run`].
///
/// `total` is the input count; `registered + already_imported +
/// errors.len()` must equal `total` — the per-item arms partition the
/// input set. Surfaced verbatim by the `SeedImportHandler` task
/// handler's `result_summary` JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedImportSummary {
    /// Input row count.
    pub total: usize,
    /// Rows that minted a fresh `ArtifactIngested` + `ArtifactQuarantined`
    /// (backdated anchor) commit pair.
    pub registered: usize,
    /// Rows that hit `register_by_hash`'s same-path-same-hash dedup —
    /// the artifact already exists at the target `(repo, path, hash)`
    /// and the re-run is a no-op (idempotency property of the cutover
    /// path).
    pub already_imported: usize,
    /// Per-row error strings — one per failed item. Order matches the
    /// input order. Keeping the failed rows visible in the summary lets
    /// operators decide whether to retry the whole set or just the
    /// failed subset; aborting the whole batch on the first error
    /// would be operator-hostile for an N-thousand-item cutover.
    pub errors: Vec<String>,
}

/// Orchestrates a one-shot seed-import run.
///
/// Holds the three dependencies the run needs:
///
/// - `ingest` — the wrapped [`IngestUseCase`] (the actual ingest /
///   register / quarantine commit happens inside this).
/// - `policies` — the active-policy lookup for the backdated-anchor
///   computation.
/// - `repositories` — repo metadata (`policy_scope` → repo id).
///
/// `handlers` is a per-format `FormatHandler` registry. The use case
/// looks up the handler for each item's `format` via
/// `FormatHandler::format_key()`. Constructed at composition time
/// with one entry per supported format.
pub struct SeedImportUseCase {
    ingest: Arc<IngestUseCase>,
    policies: Arc<dyn PolicyProjectionRepository>,
    repositories: Arc<dyn RepositoryRepository>,
    artifacts: Arc<dyn ArtifactRepository>,
    handlers: HashMap<String, Arc<dyn FormatHandler>>,
}

impl SeedImportUseCase {
    /// Construct the use case.
    ///
    /// `handlers` is the per-format-key registry the run loop consults
    /// per item; missing handlers fail that item with a
    /// `format-handler-unavailable` error (not a panic — the operator
    /// might have submitted a row for a format the deployment doesn't
    /// host yet).
    pub fn new(
        ingest: Arc<IngestUseCase>,
        policies: Arc<dyn PolicyProjectionRepository>,
        repositories: Arc<dyn RepositoryRepository>,
        artifacts: Arc<dyn ArtifactRepository>,
        handlers: HashMap<String, Arc<dyn FormatHandler>>,
    ) -> Self {
        Self {
            ingest,
            policies,
            repositories,
            artifacts,
            handlers,
        }
    }

    /// Resolve the active `ScanPolicy` for the given repo — repo-scoped
    /// takes precedence over `Global`. Mirrors
    /// `IngestUseCase::resolve_active_policy_for_repo` exactly (the
    /// logic is duplicated rather than shared because that helper is
    /// `pub(crate)` to `ingest_use_case`).
    async fn resolve_active_policy_for_repo(
        &self,
        repo_id: Uuid,
    ) -> AppResult<Option<ScanPolicyProjection>> {
        let active = self.policies.list_active().await?;
        let mut repo_scoped: Option<ScanPolicyProjection> = None;
        let mut global: Option<ScanPolicyProjection> = None;
        for projection in active {
            match &projection.scope {
                PolicyScope::Repository(id) if *id == repo_id => {
                    repo_scoped = Some(projection);
                }
                PolicyScope::Global if global.is_none() => {
                    global = Some(projection);
                }
                _ => {}
            }
        }
        Ok(repo_scoped.or(global))
    }

    /// Compute the backdated `quarantine_window_start` anchor for a
    /// given repo's effective duration.
    ///
    /// `anchor = now - effective_duration - BACKDATE_MARGIN_SECS`
    ///
    /// `effective_duration` is the matched policy's
    /// `quarantine_duration_secs` when one applies, else
    /// [`DEFAULT_QUARANTINE_DURATION_SECS`]. A permissive-mode policy
    /// (`quarantine_duration_secs == 0`) collapses to `now -
    /// BACKDATE_MARGIN_SECS` — the anchor is still in the past, which
    /// is what we want even when the policy itself would not have
    /// quarantined (seed-import always quarantines for the
    /// already-elapsed observation property; release-authority is the
    /// scan, not the window).
    fn compute_backdated_anchor(
        &self,
        now: DateTime<Utc>,
        policy: Option<&ScanPolicyProjection>,
    ) -> DateTime<Utc> {
        let duration_secs = policy
            .map(|p| p.quarantine_duration_secs)
            .unwrap_or(DEFAULT_QUARANTINE_DURATION_SECS);
        now - chrono::Duration::seconds(duration_secs)
            - chrono::Duration::seconds(BACKDATE_MARGIN_SECS)
    }

    /// Bulk-register the supplied items with backdated quarantine
    /// anchors. Returns the per-arm partition counts.
    ///
    /// Per-item failures are accumulated into `summary.errors`; the
    /// loop never aborts early. This matches the cutover use case —
    /// an operator running a 10k-item set wants the run summary and
    /// the failed-rows list, not a partial result that stopped at row
    /// 47.
    ///
    /// `actor` is propagated as the `ApiActor` recorded on each
    /// `ArtifactIngested` (`uploaded_by` column when the actor is a
    /// real user; `None` for the system nil-uuid sentinel).
    #[tracing::instrument(skip(self, items))]
    pub async fn run(
        &self,
        items: Vec<SeedImportItem>,
        actor: ApiActor,
    ) -> AppResult<SeedImportSummary> {
        let total = items.len();
        let mut summary = SeedImportSummary {
            total,
            ..Default::default()
        };

        // One `now` per run — the entire batch backdates against the
        // same wall-clock. This keeps the per-item anchors comparable
        // (they all elapsed at the same observation-window boundary)
        // and avoids the case where the first item's anchor is older
        // than the last item's by the run's wall-clock duration.
        let now = Utc::now();

        for (idx, item) in items.into_iter().enumerate() {
            match self.run_one(&item, now, &actor).await {
                Ok(RunOneOutcome::Registered) => {
                    summary.registered += 1;
                }
                Ok(RunOneOutcome::AlreadyImported) => {
                    summary.already_imported += 1;
                }
                Err(err) => {
                    summary.errors.push(format!(
                        "item {idx} ({}/{}@{}): {err}",
                        item.format, item.name, item.version,
                    ));
                }
            }
        }

        tracing::info!(
            total = summary.total,
            registered = summary.registered,
            already_imported = summary.already_imported,
            errors = summary.errors.len(),
            "seed-import run complete"
        );

        Ok(summary)
    }

    /// Process one item. Returns the per-row outcome arm.
    ///
    /// Factored out of [`Self::run`] so the loop body is a single
    /// arm-bucket assignment per row.
    async fn run_one(
        &self,
        item: &SeedImportItem,
        now: DateTime<Utc>,
        actor: &ApiActor,
    ) -> AppResult<RunOneOutcome> {
        // 1. Repo exists + active policy lookup.
        let repo = self.repositories.find_by_id(item.repository_id).await?;
        let policy = self.resolve_active_policy_for_repo(repo.id).await?;
        let anchor = self.compute_backdated_anchor(now, policy.as_ref());

        // 2. Format handler dispatch by format_key.
        let key = item.format.to_string();
        let handler = self.handlers.get(&key).ok_or_else(|| {
            AppError::Domain(hort_domain::error::DomainError::Validation(format!(
                "no FormatHandler registered for format {key}"
            )))
        })?;

        // 3. Build coords. v1 path shape is `<name>/<version>` —
        // deterministic per (name, version), so a re-run hits the
        // same path-UNIQUE dedup row.
        let path = format!("{}/{}", item.name, item.version);
        let coords = ArtifactCoords {
            name: item.name.clone(),
            name_as_published: item.name.clone(),
            version: Some(item.version.clone()),
            path,
            format: item.format.clone(),
            metadata: serde_json::Value::Null,
        };

        // 4. Pre-existence check so the per-item outcome arm can
        // distinguish a fresh registration from a same-path-same-hash
        // dedup hit. `register_by_hash` itself dedups internally —
        // this read is only here to disambiguate the *outcome* for
        // the run summary (the call below stays the source of truth
        // for actual state changes).
        let pre_existing = self
            .artifacts
            .find_by_path(item.repository_id, &coords.path)
            .await
            .map_err(AppError::Domain)?;

        let outcome = self
            .ingest
            .register_existing_cas_blob(
                RegisterExistingCasBlobRequest {
                    repository_id: item.repository_id,
                    coords,
                    content_type: "application/octet-stream".to_string(),
                    actor: actor.clone(),
                    payload_metadata: serde_json::json!({
                        "source": "seed-import",
                    }),
                    content_hash: item.content_hash.clone(),
                    seed_import_quarantine_anchor: Some(anchor),
                },
                handler.as_ref(),
            )
            .await?;

        // Same-path-same-hash dedup: the artifact already existed at
        // this `(repo, path)` with the same SHA-256. `register_by_hash`
        // returned the pre-existing row unchanged (no event emitted).
        // For the summary's purposes this is the idempotent "already
        // imported" arm — the operator can re-run the same input set
        // and the second pass costs only the read-side work.
        if pre_existing
            .as_ref()
            .map(|a| a.sha256_checksum == outcome.artifact.sha256_checksum)
            .unwrap_or(false)
        {
            Ok(RunOneOutcome::AlreadyImported)
        } else {
            Ok(RunOneOutcome::Registered)
        }
    }
}

/// Internal per-item outcome — one of the three partition arms.
enum RunOneOutcome {
    Registered,
    AlreadyImported,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use chrono::Duration;
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::repository::Repository;
    use hort_domain::entities::scan_policy::{ProvenanceMode, SeverityThreshold};
    use hort_domain::events::DomainEvent;

    use crate::use_cases::artifact_group_use_case::ArtifactGroupUseCase;
    use crate::use_cases::ingest_use_case::IngestUseCase;
    use crate::use_cases::test_support::{
        api_actor, sample_repository, MockArtifactGroupLifecyclePort, MockArtifactGroupRepository,
        MockArtifactLifecycle, MockArtifactRepository, MockContentReferenceIndex,
        MockCurationRuleRepository, MockEventStore, MockJobsRepository,
        MockPolicyProjectionRepository, MockRepositoryRepository, MockStoragePort,
        StubFormatHandler,
    };

    /// Build a sample `ScanPolicyProjection` for backdated-anchor tests.
    /// Local helper (not shared via `test_support`) so this module's
    /// tests do not have to depend on the policy-use-case test module.
    fn sample_projection() -> ScanPolicyProjection {
        let now = Utc::now();
        ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: "seed-import-test".into(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs: 24 * 3600,
            require_approval: false,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".into()],
            rescan_interval_hours: 24,
            stream_version: 0,
            created_at: now,
            updated_at: now,
        }
    }

    // -----------------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------------

    /// Make a wired SeedImportUseCase with default-empty mocks +
    /// a single pypi handler. Returns the use case + the underlying
    /// mocks so tests can pre-populate CAS, set up policies, and
    /// inspect the per-commit lifecycle log.
    #[allow(clippy::type_complexity)]
    fn make_use_case() -> (
        SeedImportUseCase,
        Arc<MockArtifactRepository>,
        Arc<MockArtifactLifecycle>,
        Arc<MockStoragePort>,
        Arc<MockRepositoryRepository>,
        Arc<MockPolicyProjectionRepository>,
    ) {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let storage = Arc::new(MockStoragePort::new());
        let repos = Arc::new(MockRepositoryRepository::new());
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let group_use_case = Arc::new(ArtifactGroupUseCase::new(groups, group_lifecycle, true));
        let curation_rules = Arc::new(MockCurationRuleRepository::new());
        let content_references = Arc::new(MockContentReferenceIndex::new());
        let policies = Arc::new(MockPolicyProjectionRepository::new());
        let jobs = Arc::new(MockJobsRepository::default());

        let ingest = Arc::new(IngestUseCase::new(
            storage.clone(),
            lifecycle.clone(),
            artifacts.clone(),
            repos.clone(),
            crate::event_store_publisher::wrap_for_test(events.clone()),
            curation_rules,
            group_use_case,
            true,
            HashMap::new(),
            0,
            content_references,
            policies.clone(),
            jobs,
        ));

        let mut handlers: HashMap<String, Arc<dyn FormatHandler>> = HashMap::new();
        handlers.insert(
            "pypi".to_string(),
            Arc::new(StubFormatHandler::new("pypi").with_max_bytes(10 * 1024 * 1024)),
        );

        let uc = SeedImportUseCase::new(
            ingest,
            policies.clone(),
            repos.clone(),
            artifacts.clone(),
            handlers,
        );
        (uc, artifacts, lifecycle, storage, repos, policies)
    }

    fn pypi_repository() -> Repository {
        let mut repo = sample_repository();
        repo.format = RepositoryFormat::Pypi;
        repo
    }

    fn sample_hash(byte: u8) -> ContentHash {
        let hex = format!("{byte:02x}").repeat(32);
        hex.parse().expect("hex parses as ContentHash")
    }

    /// Pre-populate storage with a known CAS-present blob so
    /// `register_existing_cas_blob`'s `storage.exists`/`size_of` gate
    /// passes. Returns the hash for use in test items.
    fn put_blob(storage: &MockStoragePort, byte: u8, len: usize) -> ContentHash {
        let bytes = vec![byte; len];
        // Use the storage mock's deterministic SHA computation by
        // staging the bytes at a hash matching the bytes' SHA. The
        // simplest path: just store under a synthetic hash and
        // confirm the test only relies on `exists`/`size_of`.
        let hash = sample_hash(byte);
        storage.insert_content(hash.clone(), bytes);
        hash
    }

    // -----------------------------------------------------------------------
    // Backdated-anchor (compute_backdated_anchor) — pure
    // -----------------------------------------------------------------------

    #[test]
    fn compute_backdated_anchor_with_policy_subtracts_policy_duration_and_margin() {
        let (uc, _a, _l, _s, _r, _p) = make_use_case();
        let now = Utc::now();
        let mut policy = sample_projection();
        policy.quarantine_duration_secs = 3600; // 1h

        let anchor = uc.compute_backdated_anchor(now, Some(&policy));

        let expected = now - Duration::seconds(3600) - Duration::seconds(BACKDATE_MARGIN_SECS);
        assert_eq!(anchor, expected);
    }

    #[test]
    fn compute_backdated_anchor_without_policy_uses_default_duration_constant() {
        let (uc, _a, _l, _s, _r, _p) = make_use_case();
        let now = Utc::now();

        let anchor = uc.compute_backdated_anchor(now, None);

        let expected = now
            - Duration::seconds(DEFAULT_QUARANTINE_DURATION_SECS)
            - Duration::seconds(BACKDATE_MARGIN_SECS);
        assert_eq!(anchor, expected);
    }

    #[test]
    fn compute_backdated_anchor_with_permissive_policy_collapses_to_margin_only() {
        let (uc, _a, _l, _s, _r, _p) = make_use_case();
        let now = Utc::now();
        let mut policy = sample_projection();
        policy.quarantine_duration_secs = 0; // permissive

        let anchor = uc.compute_backdated_anchor(now, Some(&policy));

        // Anchor is still in the past — by BACKDATE_MARGIN_SECS.
        let expected = now - Duration::seconds(BACKDATE_MARGIN_SECS);
        assert_eq!(anchor, expected);
    }

    // -----------------------------------------------------------------------
    // Backdated-anchor stamping — INTEGRATION through IngestUseCase
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn run_one_item_stamps_backdated_anchor_and_emits_quarantine_event() {
        let (uc, _artifacts, lifecycle, storage, repos, _policies) = make_use_case();
        let repo = pypi_repository();
        let repo_id = repo.id;
        repos.insert(repo);

        let hash = put_blob(&storage, 0x42, 1024);

        let item = SeedImportItem {
            repository_id: repo_id,
            format: RepositoryFormat::Pypi,
            name: "my-package".into(),
            version: "1.0.0".into(),
            content_hash: hash,
        };

        let before = Utc::now();
        let summary = uc.run(vec![item], api_actor()).await.unwrap();

        assert_eq!(summary.total, 1);
        assert_eq!(summary.registered, 1);
        assert_eq!(summary.already_imported, 0);
        assert!(summary.errors.is_empty(), "{:?}", summary.errors);

        // Two commits — ArtifactIngested + ArtifactQuarantined.
        let transitions = lifecycle.committed_transitions();
        assert_eq!(
            transitions.len(),
            2,
            "expected ArtifactIngested + ArtifactQuarantined transitions; got {transitions:?}"
        );
        assert!(matches!(
            &transitions[0].1.events[0].event,
            DomainEvent::ArtifactIngested(_)
        ));
        let q_event = match &transitions[1].1.events[0].event {
            DomainEvent::ArtifactQuarantined(q) => q,
            other => panic!("expected ArtifactQuarantined, got {other:?}"),
        };

        // Anchor must be backdated by at least the default duration +
        // margin (no policy was seeded → DEFAULT_QUARANTINE_DURATION_SECS
        // applies).
        let max_expected_anchor = before
            - Duration::seconds(DEFAULT_QUARANTINE_DURATION_SECS)
            - Duration::seconds(BACKDATE_MARGIN_SECS - 1);
        assert!(
            q_event.quarantine_window_start <= max_expected_anchor,
            "anchor {} should be at or before {max_expected_anchor}",
            q_event.quarantine_window_start
        );
    }

    #[tokio::test]
    async fn run_one_item_artifact_lands_quarantined_with_backdated_anchor_status() {
        // Acceptance: backdated-anchor.
        let (uc, artifacts, _l, storage, repos, _p) = make_use_case();
        let repo = pypi_repository();
        let repo_id = repo.id;
        repos.insert(repo);
        let hash = put_blob(&storage, 0x77, 512);

        let item = SeedImportItem {
            repository_id: repo_id,
            format: RepositoryFormat::Pypi,
            name: "pkg".into(),
            version: "2.3.4".into(),
            content_hash: hash,
        };
        let _ = uc.run(vec![item], api_actor()).await.unwrap();

        // Single artifact, status Quarantined, anchor set.
        let stored: Vec<_> = artifacts.snapshot_all();
        assert_eq!(stored.len(), 1);
        let a = &stored[0];
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);
        assert!(
            a.quarantine_window_start.is_some(),
            "quarantine_window_start must be set after seed-import"
        );
        // Anchor must be in the past (by at least the default duration).
        let anchor = a.quarantine_window_start.unwrap();
        assert!(
            anchor < Utc::now() - Duration::seconds(DEFAULT_QUARANTINE_DURATION_SECS / 2),
            "anchor {anchor} must be backdated well into the past"
        );
    }

    // -----------------------------------------------------------------------
    // Acceptance: a dirty scan still rejects (use case does NOT bypass scan)
    // -----------------------------------------------------------------------

    /// Acceptance: dirty-scan-still-rejects.
    ///
    /// Seed-import produces an artifact in `Quarantined` status (NOT
    /// `Released`, NOT `ScanWaived`). The scan gate still applies —
    /// asserted here by calling the post-seed-import state machine
    /// directly: `Artifact::reject_from_scan` accepts `Quarantined` →
    /// `Rejected` and produces a domain event. If seed-import had
    /// landed the artifact as `Released` (the rejected `ScanWaived`
    /// alternative), `reject_from_scan` would fail with an invariant
    /// error (which the test would catch).
    #[tokio::test]
    async fn dirty_scan_still_rejects_a_seed_imported_artifact() {
        let (uc, artifacts, _l, storage, repos, _p) = make_use_case();
        let repo = pypi_repository();
        let repo_id = repo.id;
        repos.insert(repo);
        let hash = put_blob(&storage, 0xAB, 256);

        let item = SeedImportItem {
            repository_id: repo_id,
            format: RepositoryFormat::Pypi,
            name: "vuln-pkg".into(),
            version: "0.1.0".into(),
            content_hash: hash,
        };
        let _ = uc.run(vec![item], api_actor()).await.unwrap();

        let stored = artifacts.snapshot_all();
        let mut a = stored[0].clone();
        assert_eq!(a.quarantine_status, QuarantineStatus::Quarantined);

        // The domain transition `Quarantined → Rejected` MUST succeed
        // (scan still gates). If seed-import had landed `Released`, the
        // transition would fail.
        let rejected = a
            .reject_from_scan("simulated dirty scan finding".to_string())
            .expect("reject_from_scan must accept a seed-imported Quarantined artifact");
        assert_eq!(a.quarantine_status, QuarantineStatus::Rejected);
        assert_eq!(rejected.artifact_id, a.id);
        assert!(rejected.reason.contains("simulated dirty scan finding"));
    }

    // -----------------------------------------------------------------------
    // Acceptance: run summary counts
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn run_summary_counts_partition_input_into_registered_and_errors() {
        let (uc, _a, _l, storage, repos, _p) = make_use_case();
        let repo = pypi_repository();
        let repo_id = repo.id;
        repos.insert(repo);
        let hash_ok = put_blob(&storage, 0x10, 128);
        // Second item references a NOT-CAS-present hash → ingest fails
        // with NotFound; counted as error.
        let hash_missing = sample_hash(0xFF);

        let items = vec![
            SeedImportItem {
                repository_id: repo_id,
                format: RepositoryFormat::Pypi,
                name: "good-pkg".into(),
                version: "1.0.0".into(),
                content_hash: hash_ok,
            },
            SeedImportItem {
                repository_id: repo_id,
                format: RepositoryFormat::Pypi,
                name: "missing-pkg".into(),
                version: "1.0.0".into(),
                content_hash: hash_missing,
            },
        ];

        let summary = uc.run(items, api_actor()).await.unwrap();

        assert_eq!(summary.total, 2);
        assert_eq!(summary.registered, 1);
        assert_eq!(summary.already_imported, 0);
        assert_eq!(summary.errors.len(), 1);
        assert!(
            summary.errors[0].contains("missing-pkg"),
            "error row should mention the failing item: {:?}",
            summary.errors
        );
    }

    // -----------------------------------------------------------------------
    // Acceptance: idempotency — same input set re-run is a no-op
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn idempotent_rerun_counts_as_already_imported() {
        let (uc, _a, _l, storage, repos, _p) = make_use_case();
        let repo = pypi_repository();
        let repo_id = repo.id;
        repos.insert(repo);
        let hash = put_blob(&storage, 0x55, 64);

        let item = SeedImportItem {
            repository_id: repo_id,
            format: RepositoryFormat::Pypi,
            name: "pkg".into(),
            version: "9.9.9".into(),
            content_hash: hash,
        };

        // First run — registered.
        let summary_1 = uc.run(vec![item.clone()], api_actor()).await.unwrap();
        assert_eq!(summary_1.registered, 1);
        assert_eq!(summary_1.already_imported, 0);

        // Second run — same item; same-path-same-hash dedup fires.
        let summary_2 = uc.run(vec![item], api_actor()).await.unwrap();
        assert_eq!(summary_2.registered, 0);
        assert_eq!(summary_2.already_imported, 1);
        assert!(summary_2.errors.is_empty());
    }

    // -----------------------------------------------------------------------
    // Negative: missing format handler is reported, not panicked
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn run_with_unsupported_format_lands_in_errors_arm_without_panic() {
        let (uc, _a, _l, storage, repos, _p) = make_use_case();
        // Only "pypi" handler is registered (see `make_use_case`).
        // Submit a Cargo-format item — handler lookup misses → per-row
        // error.
        let mut repo = sample_repository();
        repo.format = RepositoryFormat::Cargo;
        let repo_id = repo.id;
        repos.insert(repo);
        let _ = put_blob(&storage, 0x33, 32);

        let item = SeedImportItem {
            repository_id: repo_id,
            format: RepositoryFormat::Cargo,
            name: "cargo-pkg".into(),
            version: "0.1.0".into(),
            content_hash: sample_hash(0x33),
        };

        let summary = uc.run(vec![item], api_actor()).await.unwrap();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.registered, 0);
        assert_eq!(summary.errors.len(), 1);
        assert!(
            summary.errors[0].contains("no FormatHandler registered for format"),
            "{:?}",
            summary.errors
        );
    }

    // -----------------------------------------------------------------------
    // Empty input — zero-length run is valid (no commits, all zeros)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn run_empty_input_returns_zeroed_summary_and_no_commits() {
        let (uc, _a, lifecycle, _s, _r, _p) = make_use_case();
        let summary = uc.run(Vec::new(), api_actor()).await.unwrap();
        assert_eq!(
            summary,
            SeedImportSummary {
                total: 0,
                registered: 0,
                already_imported: 0,
                errors: Vec::new(),
            }
        );
        assert!(lifecycle.committed_transitions().is_empty());
    }

    // -----------------------------------------------------------------------
    // resolve_active_policy_for_repo — repo-scoped takes precedence
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn resolve_policy_returns_repo_scoped_over_global() {
        let (uc, _a, _l, _s, _r, policies) = make_use_case();
        let repo_id = Uuid::new_v4();

        // Both a Global and a Repository-scoped policy active.
        let mut global = sample_projection();
        global.scope = PolicyScope::Global;
        global.quarantine_duration_secs = 7200;
        let mut scoped = sample_projection();
        scoped.scope = PolicyScope::Repository(repo_id);
        scoped.quarantine_duration_secs = 600;
        policies.insert(global);
        policies.insert(scoped);

        let resolved = uc
            .resolve_active_policy_for_repo(repo_id)
            .await
            .unwrap()
            .expect("a policy resolves");
        assert!(matches!(resolved.scope, PolicyScope::Repository(_)));
        assert_eq!(resolved.quarantine_duration_secs, 600);
    }

    #[tokio::test]
    async fn resolve_policy_returns_global_when_no_repo_scoped() {
        let (uc, _a, _l, _s, _r, policies) = make_use_case();
        let mut global = sample_projection();
        global.scope = PolicyScope::Global;
        global.quarantine_duration_secs = 3600;
        policies.insert(global);

        let resolved = uc
            .resolve_active_policy_for_repo(Uuid::new_v4())
            .await
            .unwrap()
            .expect("a policy resolves");
        assert!(matches!(resolved.scope, PolicyScope::Global));
    }

    #[tokio::test]
    async fn resolve_policy_returns_none_when_nothing_matches() {
        let (uc, _a, _l, _s, _r, _p) = make_use_case();
        let resolved = uc
            .resolve_active_policy_for_repo(Uuid::new_v4())
            .await
            .unwrap();
        assert!(resolved.is_none());
    }
}
