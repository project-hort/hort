//! [`DiscoveryUseCase`].
//!
//! The repo-keyed, JWT-only discovery endpoint backing
//! `GET /api/v1/repositories/{repo_key}/discovery/versions/{package_name}`.
//! Composes locally-held versions (via the extended
//! [`ArtifactRepository::package_version_status`]) with upstream-advertised
//! versions (via [`UpstreamMetadataPort::list_versions`]) and overlays
//! per-version statuses.
//!
//! # Why this lives outside the unified index pipeline
//!
//! The all-statuses invariant is load-bearing: discovery returns *every*
//! status
//! (`Released`, `Quarantined`, `QuarantinedAwaitingRelease`, `Rejected`,
//! `ScanIndeterminate`, `Unknown`) because the operator-UX axis is "show
//! me what's there and why I can or cannot use it." Composing the
//! unified-index filters (the non-servable-status filter and the
//! index-mode filter — see
//! `docs/architecture/explanation/index-construction.md`) or the
//! index-builder spine would silently strip the
//! quarantined / rejected / scan-indeterminate rows the operator
//! explicitly wants to see. The unified pipeline continues to gate the
//! package-manager-client serve path; these are different consumers with
//! deliberately divergent shapes.
//!
//! # Gate order (§2.6, §7)
//!
//! 1. **Token-kind gate** — `caller.token_kind == Some(TokenKind::CliSession)`
//!    is required. PATs and service-account tokens are rejected with
//!    `Forbidden`. This fires first (cheapest — no repo resolution
//!    required) and emits `result="token_kind_denied"`.
//! 2. **RBAC gate** — `Permission::Read` on the resolved repo. Denial
//!    emits `result="permission_denied"`.
//! 3. **OCI rejection** — if the upstream call returns
//!    [`UpstreamFetchError::UnsupportedFormat`], the use case maps to
//!    `result="oci_unsupported"` and returns the §8 exact wording wrapped
//!    in [`DomainError::Validation`].
//!
//! All ticks emit from this layer (per the architect-doc *"Emission by
//! layer"* rule). The inbound `hort-http-discovery` handler is a thin
//! wrapper that maps `AppError` → `ApiError` and emits no business
//! metric.
//!
//! # Status overlay (§6.8)
//!
//! Per AK-held version `(version, status, quarantine_until)`:
//!
//! | HORT status              | `quarantine_until`     | Surfaced as                              |
//! |------------------------|------------------------|------------------------------------------|
//! | `Released`             | any                    | [`DiscoveryVersionStatus::Released`]     |
//! | `Quarantined`          | `Some(d)` where `d > now()` | [`DiscoveryVersionStatus::Quarantined { quarantine_until: d }`] |
//! | `Quarantined`          | `Some(d)` where `d <= now()` | [`DiscoveryVersionStatus::QuarantinedAwaitingRelease`] |
//! | `Quarantined`          | `None`                 | [`DiscoveryVersionStatus::QuarantinedAwaitingRelease`] (conservative) |
//! | `Rejected`             | any                    | [`DiscoveryVersionStatus::Rejected`]     |
//! | `ScanIndeterminate`    | any                    | [`DiscoveryVersionStatus::ScanIndeterminate`] |
//! | `None`                 | any                    | [`DiscoveryVersionStatus::Released`] (un-quarantined hosted upload) |
//!
//! Upstream versions that are not in HORT's held set surface as
//! [`DiscoveryVersionStatus::Unknown`]. AK-held versions that are not in
//! the upstream set still surface — discovery is the union view.
//!
//! ## `quarantine_until = None` edge case
//!
//! When HORT reports a row with `quarantine_status = Quarantined` but
//! `quarantine_deadline = None`, the use case picks the conservative
//! sub-state: [`DiscoveryVersionStatus::QuarantinedAwaitingRelease`]. The
//! conservative choice is correct because:
//!
//! - "deadline not set" is structurally equivalent to "deadline already
//!   elapsed" — the operator cannot rely on the timer firing.
//! - Operators dashboarding "stuck quarantines" should see this row in
//!   the awaiting-release bucket, not the active-window bucket.
//! - The §3.1 [`DiscoveryVersionStatus::Quarantined`] arm carries a
//!   `DateTime<Utc>` payload; synthesising `Utc::now()` for a missing
//!   deadline would be a lie about the policy state.
//!
//! # Observability
//!
//! - `#[tracing::instrument(skip(self))]` on the public method.
//!   **No `err`** per the architect-doc Observability rule
//!   ("`err` conflates privilege denials with infrastructure errors").
//! - Token-kind denial / permission denial → `tracing::info!` (audit
//!   trail).
//! - Success → `tracing::debug!` with `format` + `repo_key` + version
//!   count. **Package name is intentionally not logged at debug** — it
//!   would inflate index cardinality on busy deployments.
//! - One `hort_discovery_list_versions_total{format, repository, result}`
//!   tick per call (single-package shape — no per-item ticks).

use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Utc;
use tracing::instrument;

use hort_domain::entities::api_token::TokenKind;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::discovery::{
    DiscoveryListing, DiscoveryVersionEntry, DiscoveryVersionStatus,
};
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::scan_policy::ScanPolicyProjection;
use hort_domain::error::DomainError;
use hort_domain::events::PolicyScope;
use hort_domain::policy::{effective_quarantine_deadline, DefaultPolicy};
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;

use crate::error::{AppError, AppResult};
use crate::metrics::{emit_discovery_list_versions, values, DiscoveryResult, UpstreamFetchError};
use crate::ports::upstream_metadata::UpstreamMetadataPort;
use crate::rbac::RbacEvaluator;

// Exact wording propagated verbatim to the client through
// `AppError::Domain(DomainError::Validation(_))`. The inbound layer maps
// to 400 Bad Request via the existing `ApiError` envelope.
const OCI_UNSUPPORTED_MESSAGE: &str =
    "discovery + prefetch are not supported for OCI; use registry-protocol-native \
     catalog/tags endpoints, or warm via crane pull";

const TOKEN_KIND_DENIED_MESSAGE: &str = "this endpoint requires a CLI session token";

/// Application use case for the repo-keyed discovery endpoint.
///
/// Concrete `pub struct`, NOT a trait — mirrors every other use case in
/// `crates/hort-app/src/use_cases/` (`CurationUseCase`, `QuarantineUseCase`,
/// `PatchCandidateUseCase`, …). Use cases are not dyn-dispatched in this
/// codebase; introducing a `pub trait DiscoveryUseCase` would be a one-off
/// pattern with no justification.
pub struct DiscoveryUseCase {
    repositories: Arc<dyn RepositoryRepository>,
    artifacts: Arc<dyn ArtifactRepository>,
    upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
    upstream_metadata: Arc<dyn UpstreamMetadataPort>,
    rbac: Arc<ArcSwap<RbacEvaluator>>,
    policies: Arc<dyn PolicyProjectionRepository>,
}

impl DiscoveryUseCase {
    /// Construct a new `DiscoveryUseCase` from its five outbound ports.
    pub fn new(
        repositories: Arc<dyn RepositoryRepository>,
        artifacts: Arc<dyn ArtifactRepository>,
        upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
        upstream_metadata: Arc<dyn UpstreamMetadataPort>,
        rbac: Arc<ArcSwap<RbacEvaluator>>,
        policies: Arc<dyn PolicyProjectionRepository>,
    ) -> Self {
        Self {
            repositories,
            artifacts,
            upstream_mappings,
            upstream_metadata,
            rbac,
            policies,
        }
    }

    /// List versions for `(repo_key, package_name)` with per-version
    /// status overlay. See module-level doc for the full contract.
    #[instrument(skip(self), fields(repo_key = %repo_key))]
    pub async fn list_versions(
        &self,
        repo_key: &str,
        package_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> AppResult<DiscoveryListing> {
        // -------- Gate 0: anonymous (F-25 read-endpoint pattern) ------
        //
        // The discovery GET routes through `extract_optional_principal`
        // (`hort-http-core::router.rs:313-318` — GET/HEAD/OPTIONS), so the
        // caller arrives as `Option`. A `None` here means no token, or a
        // token the read-path middleware could not validate. Reject with
        // 401 (`AppError::Unauthorized`). This returns BEFORE any metric
        // tick, so §8.7's "anonymous → 401 + NO tick" invariant holds: an
        // unauthenticated request never reaches the emission sites below.
        let caller = caller
            .ok_or_else(|| AppError::Unauthorized("discovery requires authentication".into()))?;

        // -------- Gate 1: token-kind (cheapest first per §2.6) --------
        //
        // Pre-repo-resolution — fires before any port I/O. The `format`
        // label is unknown here because we have not resolved the repo
        // yet; emit `FORMAT_UNKNOWN` per the catalog's missing-format
        // sentinel rule. Per §7 the `repository` label collapses to
        // `REPOSITORY_ALL` for pre-resolution gate ticks.
        if caller.token_kind != Some(TokenKind::CliSession) {
            tracing::info!(
                caller_user_id = %caller.user_id,
                caller_token_kind = ?caller.token_kind,
                outcome = "denied",
                "discovery list_versions denied: token kind is not CliSession",
            );
            emit_discovery_list_versions(
                values::FORMAT_UNKNOWN,
                values::REPOSITORY_ALL,
                DiscoveryResult::TokenKindDenied,
            );
            return Err(AppError::Domain(DomainError::Forbidden(
                TOKEN_KIND_DENIED_MESSAGE.into(),
            )));
        }

        // -------- Resolve repository (anti-enumeration via NotFound) --
        //
        // Pre-RBAC: a missing repo collapses to `NotFound` for callers
        // who hold neither Read nor admin — the existing
        // `RepositoryAccessUseCase` pattern. Discovery does NOT use
        // `RepositoryAccessUseCase` because that helper is shaped around
        // the `AccessLevel::{Read, Write}` enum and discovery's
        // gate-order (token-kind before RBAC) lives more cleanly here.
        // The two helpers are equivalent in the visible-Read case;
        // discovery's response shape (`AppError::Domain(NotFound)`) is
        // identical.
        let repository = match self.repositories.find_by_key(repo_key).await {
            Ok(r) => r,
            Err(DomainError::NotFound { .. }) => {
                // Anti-enumeration: do NOT tick a metric here — the
                // architect-doc ceiling on `result` cardinality (12)
                // does not include a "repo not found" bucket, and adding
                // one would push past the ceiling without operator-
                // actionable benefit. Callers see a 404 envelope from
                // the inbound layer; that is the signal.
                return Err(AppError::Domain(DomainError::NotFound {
                    entity: "Repository",
                    id: repo_key.to_string(),
                }));
            }
            Err(other) => return Err(AppError::Domain(other)),
        };
        let format_label = repository.format.to_string();
        let repository_label = repository.key.clone();

        // -------- Gate 2: RBAC `Permission::Read` ---------------------
        if !self
            .rbac
            .load()
            .authorize(caller, Permission::Read, Some(repository.id))
        {
            tracing::info!(
                caller_user_id = %caller.user_id,
                repository = %repository.key,
                outcome = "denied",
                "discovery list_versions denied: missing Permission::Read on repository",
            );
            emit_discovery_list_versions(
                &format_label,
                &repository_label,
                DiscoveryResult::PermissionDenied,
            );
            return Err(AppError::Domain(DomainError::Forbidden(format!(
                "Permission::Read required on repository {}",
                repository.key,
            ))));
        }

        // -------- Fetch AK-held versions + quarantine anchors ---------
        //
        // F27: discovery reads the immutable `quarantine_window_start`
        // anchor via the dedicated `package_version_anchors` query — NOT
        // the hot `package_version_status` serve path (which returns no
        // deadline and stays an index-only scan). The live deadline is
        // computed below from the resolved policy duration.
        let held_anchors = self
            .artifacts
            .package_version_anchors(repository.id, package_name)
            .await
            .map_err(AppError::Domain)?;

        // Resolve the active quarantine-window duration for this repo so
        // each quarantined row's anchor becomes its live deadline
        // (`anchor + duration`). Absent policy → the quarantine-by-default
        // duration (ADR 0007).
        let policy = self.resolve_active_policy_for_repo(repository.id).await?;
        let quarantine_duration = chrono::Duration::seconds(
            policy
                .as_ref()
                .map(|p| p.quarantine_duration_secs)
                .unwrap_or_else(DefaultPolicy::quarantine_duration_secs),
        );
        let held: Vec<(
            String,
            hort_domain::entities::artifact::QuarantineStatus,
            Option<chrono::DateTime<Utc>>,
        )> = held_anchors
            .into_iter()
            .map(|(version, status, anchor)| {
                let deadline =
                    anchor.map(|a| effective_quarantine_deadline(a, quarantine_duration));
                (version, status, deadline)
            })
            .collect();

        // -------- Fetch upstream-advertised versions ------------------
        //
        // §6.2: a repo with no upstream mapping (hosted-only) yields an
        // empty `unknown` set. The mapping resolver here mirrors every
        // other prefetch / proxy call site (longest-prefix not relevant
        // — discovery is repo-scoped, not path-scoped): pick the
        // catch-all (`path_prefix == ""`) mapping if present.
        let mapping_opt = self
            .upstream_mappings
            .list_for_repository(repository.id)
            .await
            .map_err(AppError::Domain)?
            .into_iter()
            .find(|m| m.path_prefix.is_empty());

        let upstream_versions: Vec<String> = if let Some(mapping) = mapping_opt {
            match self
                .upstream_metadata
                .list_versions(&format_label, &mapping, package_name)
                .await
            {
                Ok(v) => v,
                Err(UpstreamFetchError::UnsupportedFormat) => {
                    // §8 — OCI / unknown format. Emit
                    // `oci_unsupported` and return Validation.
                    tracing::info!(
                        repository = %repository.key,
                        format = %format_label,
                        "discovery list_versions rejected: format does not support discovery",
                    );
                    emit_discovery_list_versions(
                        &format_label,
                        &repository_label,
                        DiscoveryResult::OciUnsupported,
                    );
                    return Err(AppError::Domain(DomainError::Validation(
                        OCI_UNSUPPORTED_MESSAGE.into(),
                    )));
                }
                Err(other) => {
                    // Map the typed fetch error to its discovery result
                    // label via the `UpstreamErrorKind` taxonomy (no
                    // free-form re-parsing — the adapter classified once
                    // at the boundary; the use case translates once
                    // here). All non-OCI errors collapse the listing to
                    // "AK-held only" + the tick on the failure bucket;
                    // the response is still a `Success` shape at the
                    // *envelope* level (200 OK with `unknown = []`), the
                    // metric records that the upstream half of the call
                    // did not complete cleanly.
                    let kind = other
                        .as_upstream_error_kind()
                        // The `UnsupportedFormat` arm is handled above;
                        // every other variant returns `Some(_)`.
                        .expect("non-UnsupportedFormat variants always classify");
                    let result = DiscoveryResult::from_upstream_error_kind(kind);
                    tracing::info!(
                        repository = %repository.key,
                        format = %format_label,
                        upstream_error = ?other,
                        "discovery list_versions: upstream-fetch failed, returning AK-held set only",
                    );
                    emit_discovery_list_versions(&format_label, &repository_label, result);
                    // §7 catalog row — the upstream-fetch outcome is the
                    // single point of taxonomic alignment with
                    // `UpstreamErrorKind`; the response still serializes
                    // with an empty unknown-set (per §7 the *metric*
                    // distinguishes upstream-call cleanliness, not
                    // listing emptiness).
                    return Ok(build_listing(
                        package_name,
                        &format_label,
                        held,
                        Vec::new(),
                        Utc::now(),
                    ));
                }
            }
        } else {
            // §6.2: no upstream mapping → empty unknown set; we still
            // tick `Success` (the call assembled a listing cleanly).
            Vec::new()
        };

        // -------- Assemble + emit success ----------------------------
        let now = Utc::now();
        let listing = build_listing(package_name, &format_label, held, upstream_versions, now);
        let version_count = listing.versions.len();
        tracing::debug!(
            format = %format_label,
            repo_key = %repository.key,
            version_count,
            "discovery list_versions succeeded",
        );
        emit_discovery_list_versions(&format_label, &repository_label, DiscoveryResult::Success);
        Ok(listing)
    }

    /// Resolve the active `ScanPolicy` for `repo_id` — repo-scoped wins
    /// over `Global`. Mirrors `IngestUseCase::resolve_active_policy_for_repo`
    /// (the logic is duplicated per use case because that helper is
    /// `pub(crate)` to `ingest_use_case`; see also
    /// `SeedImportUseCase::resolve_active_policy_for_repo`).
    async fn resolve_active_policy_for_repo(
        &self,
        repo_id: uuid::Uuid,
    ) -> AppResult<Option<ScanPolicyProjection>> {
        let active = self
            .policies
            .list_active()
            .await
            .map_err(AppError::Domain)?;
        let mut repo_scoped: Option<ScanPolicyProjection> = None;
        let mut global: Option<ScanPolicyProjection> = None;
        for projection in active {
            match &projection.scope {
                PolicyScope::Repository(id) if *id == repo_id => repo_scoped = Some(projection),
                PolicyScope::Global if global.is_none() => global = Some(projection),
                _ => {}
            }
        }
        Ok(repo_scoped.or(global))
    }
}

/// Pure status-overlay assembly — separate function so unit tests can
/// exercise every §6.8 arm without wiring the full use case.
///
/// `held` is the AK-side projection (`version, status, quarantine_until`);
/// `upstream` is the upstream-advertised set. HORT rows win when both sets
/// list the same version. `now` is the comparison anchor used to
/// discriminate `Quarantined` from `QuarantinedAwaitingRelease`; passing
/// it explicitly makes the boundary test deterministic.
fn build_listing(
    package: &str,
    format: &str,
    held: Vec<(
        String,
        hort_domain::entities::artifact::QuarantineStatus,
        Option<chrono::DateTime<Utc>>,
    )>,
    upstream: Vec<String>,
    now: chrono::DateTime<Utc>,
) -> DiscoveryListing {
    use hort_domain::entities::artifact::QuarantineStatus;
    use std::collections::HashSet;

    let mut versions: Vec<DiscoveryVersionEntry> = Vec::new();
    let mut held_set: HashSet<String> = HashSet::with_capacity(held.len());

    for (version, status, quarantine_until) in held.into_iter() {
        held_set.insert(version.clone());
        let status = match status {
            // `None` is the "un-quarantined hosted upload" shape; the
            // operator-facing UX of discovery is *"what versions does
            // HORT hold and what's their status?"* — no-quarantine and
            // released are observationally equivalent here.
            QuarantineStatus::None | QuarantineStatus::Released => DiscoveryVersionStatus::Released,
            QuarantineStatus::Quarantined => match quarantine_until {
                Some(deadline) if deadline > now => DiscoveryVersionStatus::Quarantined {
                    quarantine_until: deadline,
                },
                // deadline elapsed OR `None` (conservative — see
                // module-level "edge case" note).
                _ => DiscoveryVersionStatus::QuarantinedAwaitingRelease,
            },
            QuarantineStatus::Rejected => DiscoveryVersionStatus::Rejected,
            QuarantineStatus::ScanIndeterminate => DiscoveryVersionStatus::ScanIndeterminate,
        };
        versions.push(DiscoveryVersionEntry { version, status });
    }

    for version in upstream.into_iter() {
        if held_set.contains(&version) {
            // HORT already lists this version with a real status — the
            // overlay never demotes a known status to `Unknown`.
            continue;
        }
        versions.push(DiscoveryVersionEntry {
            version,
            status: DiscoveryVersionStatus::Unknown,
        });
    }

    DiscoveryListing {
        package: package.to_string(),
        format: format.to_string(),
        versions,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use arc_swap::ArcSwap;
    use chrono::{DateTime, Duration, Utc};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::repository::Repository;
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    use uuid::Uuid;

    use crate::use_cases::test_support::{
        sample_repository, MockArtifactRepository, MockPolicyProjectionRepository,
        MockRepositoryRepository, MockRepositoryUpstreamMappingRepository,
        MockUpstreamMetadataPort,
    };

    // --- fixtures --------------------------------------------------------

    fn caller_cli_session(claims: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: claims.iter().map(|s| (*s).to_string()).collect(),
            token_kind: Some(TokenKind::CliSession),
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    fn caller_with_token_kind(claims: &[&str], kind: Option<TokenKind>) -> CallerPrincipal {
        let mut c = caller_cli_session(claims);
        c.token_kind = kind;
        c
    }

    fn npm_repo() -> Repository {
        let mut r = sample_repository();
        r.format = hort_domain::entities::repository::RepositoryFormat::Npm;
        r.is_public = false;
        r
    }

    fn oci_repo() -> Repository {
        let mut r = sample_repository();
        r.format = hort_domain::entities::repository::RepositoryFormat::Oci;
        r.is_public = false;
        r
    }

    fn evaluator_with_read_grant(claim: &str, repo_id: Uuid) -> RbacEvaluator {
        RbacEvaluator::new(vec![PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec![claim.to_string()]),
            repository_id: Some(repo_id),
            permission: Permission::Read,
            created_at: Utc::now(),
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        }])
    }

    fn empty_evaluator() -> RbacEvaluator {
        RbacEvaluator::new(Vec::new())
    }

    fn mapping(repo_id: Uuid) -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            path_prefix: String::new(),
            upstream_url: "https://registry.example/".into(),
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
        }
    }

    struct Harness {
        uc: DiscoveryUseCase,
        repos: Arc<MockRepositoryRepository>,
        artifacts: Arc<MockArtifactRepository>,
        mappings: Arc<MockRepositoryUpstreamMappingRepository>,
        upstream: Arc<MockUpstreamMetadataPort>,
        policies: Arc<MockPolicyProjectionRepository>,
    }

    fn wire(repo: Repository, evaluator: RbacEvaluator) -> Harness {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo);
        let artifacts = Arc::new(MockArtifactRepository::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let upstream = Arc::new(MockUpstreamMetadataPort::new());
        let rbac = Arc::new(ArcSwap::from_pointee(evaluator));
        let policies = Arc::new(MockPolicyProjectionRepository::new());
        let uc = DiscoveryUseCase::new(
            repos.clone(),
            artifacts.clone(),
            mappings.clone(),
            upstream.clone(),
            rbac,
            policies.clone(),
        );
        Harness {
            uc,
            repos,
            artifacts,
            mappings,
            upstream,
            policies,
        }
    }

    /// Capture metrics + run a future, then return the snapshot. Mirrors
    /// the `capture` helper in `purge_use_case_tests.rs`.
    fn capture<F>(f: F) -> Vec<(metrics_util::CompositeKey, DebugValue)>
    where
        F: FnOnce() -> futures::future::BoxFuture<'static, ()> + Send + 'static,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter: Snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(f());
        });
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(k, _u, _d, v)| (k, v))
            .collect()
    }

    fn counter_value(
        snap: &[(metrics_util::CompositeKey, DebugValue)],
        name: &str,
        result_label: &str,
    ) -> Option<u64> {
        for (key, value) in snap {
            if key.key().name() != name {
                continue;
            }
            let labels: HashMap<&str, &str> =
                key.key().labels().map(|l| (l.key(), l.value())).collect();
            if labels.get("result") != Some(&result_label) {
                continue;
            }
            if let DebugValue::Counter(v) = value {
                return Some(*v);
            }
        }
        None
    }

    // --- Gate 0: anonymous -----------------------------------------------

    #[test]
    fn anonymous_caller_returns_unauthorized_and_no_tick() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                // Wire a fully-granted evaluator so the ONLY thing that can
                // deny is the anonymous gate — proves Gate 0 fires first,
                // before token-kind / RBAC / any port I/O.
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                let err =
                    h.uc.list_versions("any-key", "left-pad", None)
                        .await
                        .expect_err("anonymous caller must be rejected");
                assert!(
                    matches!(err, AppError::Unauthorized(_)),
                    "anonymous → AppError::Unauthorized (maps to 401); got {err:?}",
                );
            })
        });
        // §8.7: anonymous → 401 + NO metric tick. The Gate 0 guard returns
        // before any `emit_discovery_list_versions` call, so the counter
        // must be entirely absent (no result label of any kind).
        assert_eq!(
            snap.iter()
                .filter(|(k, _)| k.key().name() == "hort_discovery_list_versions_total")
                .count(),
            0,
            "anonymous deny must not tick any result label",
        );
    }

    // --- Gate 1: token-kind ----------------------------------------------

    #[test]
    fn token_kind_denied_for_pat_caller() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                let actor = caller_with_token_kind(&["dev"], Some(TokenKind::Pat));
                let err =
                    h.uc.list_versions("any-key", "left-pad", Some(&actor))
                        .await
                        .expect_err("PAT must be rejected");
                assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
                if let AppError::Domain(DomainError::Forbidden(msg)) = err {
                    assert!(msg.contains("CLI session"), "msg: {msg}");
                }
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_discovery_list_versions_total",
                "token_kind_denied"
            ),
            Some(1)
        );
    }

    #[test]
    fn token_kind_denied_for_service_account() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                let actor = caller_with_token_kind(&["dev"], Some(TokenKind::ServiceAccount));
                let err =
                    h.uc.list_versions("any-key", "left-pad", Some(&actor))
                        .await
                        .expect_err("service account token must be rejected");
                assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_discovery_list_versions_total",
                "token_kind_denied"
            ),
            Some(1)
        );
    }

    #[test]
    fn token_kind_denied_for_no_token_kind() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                let actor = caller_with_token_kind(&["dev"], None);
                let err =
                    h.uc.list_versions("any-key", "left-pad", Some(&actor))
                        .await
                        .expect_err("None token-kind must be rejected");
                assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_discovery_list_versions_total",
                "token_kind_denied"
            ),
            Some(1)
        );
    }

    // --- Gate 2: RBAC ----------------------------------------------------

    #[test]
    fn permission_denied_when_caller_lacks_read_on_repo() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let key = repo.key.clone();
                let h = wire(repo, empty_evaluator()); // no grants
                let actor = caller_cli_session(&[]); // CliSession but no claims
                let err =
                    h.uc.list_versions(&key, "left-pad", Some(&actor))
                        .await
                        .expect_err("missing Permission::Read must deny");
                assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_discovery_list_versions_total",
                "permission_denied"
            ),
            Some(1)
        );
    }

    // --- repository not found --------------------------------------------

    #[tokio::test]
    async fn unknown_repository_key_returns_notfound() {
        let repo = npm_repo();
        let repo_id = repo.id;
        let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
        let actor = caller_cli_session(&["dev"]);
        let err =
            h.uc.list_versions("does-not-exist", "left-pad", Some(&actor))
                .await
                .expect_err("unknown repo must NotFound");
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "Repository",
                ..
            })
        ));
    }

    // --- §6.2: no upstream mapping ---------------------------------------

    #[test]
    fn no_upstream_mapping_yields_hort_held_only_and_ticks_success() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let repo_key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                // Seed two AK-held versions; no upstream mapping seeded
                // ⇒ §6.2 unknown set is empty.
                h.artifacts.seed_package_version_status(
                    repo_id,
                    "left-pad",
                    vec![
                        ("1.0.0".into(), QuarantineStatus::Released),
                        ("1.1.0".into(), QuarantineStatus::Released),
                    ],
                );
                let actor = caller_cli_session(&["dev"]);
                let listing =
                    h.uc.list_versions(&repo_key, "left-pad", Some(&actor))
                        .await
                        .expect("ok");
                assert_eq!(listing.versions.len(), 2);
                assert!(listing
                    .versions
                    .iter()
                    .all(|v| matches!(v.status, DiscoveryVersionStatus::Released)));
                assert!(
                    h.upstream.calls().is_empty(),
                    "no mapping ⇒ port must not be called"
                );
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_discovery_list_versions_total", "success"),
            Some(1)
        );
    }

    // --- F27: deadline computed from anchor + resolved policy duration ---

    /// A `Quarantined` artifact carrying a `quarantine_window_start`
    /// anchor — exercises the `package_version_anchors` → deadline path.
    fn quarantined_artifact(
        repo_id: Uuid,
        pkg: &str,
        version: &str,
        anchor: DateTime<Utc>,
    ) -> hort_domain::entities::artifact::Artifact {
        let now = Utc::now();
        hort_domain::entities::artifact::Artifact {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            name: pkg.to_string(),
            name_as_published: pkg.to_string(),
            version: Some(version.to_string()),
            path: format!("seeded-{pkg}-{version}"),
            size_bytes: 0,
            sha256_checksum: "a".repeat(64).parse().expect("sha"),
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/octet-stream".to_string(),
            quarantine_status: QuarantineStatus::Quarantined,
            quarantine_window_start: Some(anchor),
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: now,
            updated_at: now,
        }
    }

    /// Minimal `ScanPolicyProjection` for the duration-resolution tests.
    fn scan_policy(scope: PolicyScope, quarantine_duration_secs: i64) -> ScanPolicyProjection {
        let now = Utc::now();
        ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: format!("policy-{}", Uuid::new_v4()),
            scope,
            severity_threshold: hort_domain::entities::scan_policy::SeverityThreshold::Critical,
            quarantine_duration_secs,
            require_approval: false,
            provenance_mode: hort_domain::entities::scan_policy::ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            stream_version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn quarantined_anchor_no_policy_uses_default_duration() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let repo_key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                let anchor = Utc::now();
                h.artifacts
                    .seed_artifact(quarantined_artifact(repo_id, "left-pad", "1.0.0", anchor));
                let actor = caller_cli_session(&["dev"]);
                let listing =
                    h.uc.list_versions(&repo_key, "left-pad", Some(&actor))
                        .await
                        .expect("ok");
                assert_eq!(listing.versions.len(), 1);
                match listing.versions[0].status {
                    DiscoveryVersionStatus::Quarantined { quarantine_until } => {
                        // No policy ⇒ quarantine-by-default duration.
                        let expected =
                            anchor + Duration::seconds(DefaultPolicy::quarantine_duration_secs());
                        assert_eq!(quarantine_until, expected);
                    }
                    ref other => panic!("expected Quarantined, got {other:?}"),
                }
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_discovery_list_versions_total", "success"),
            Some(1)
        );
    }

    #[test]
    fn quarantined_anchor_with_repo_scoped_policy_uses_policy_duration() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let repo_key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                let anchor = Utc::now();
                h.artifacts
                    .seed_artifact(quarantined_artifact(repo_id, "left-pad", "1.0.0", anchor));
                // Repo-scoped policy wins → 1-hour window.
                h.policies
                    .insert(scan_policy(PolicyScope::Repository(repo_id), 3600));
                let actor = caller_cli_session(&["dev"]);
                let listing =
                    h.uc.list_versions(&repo_key, "left-pad", Some(&actor))
                        .await
                        .expect("ok");
                match listing.versions[0].status {
                    DiscoveryVersionStatus::Quarantined { quarantine_until } => {
                        assert_eq!(quarantine_until, anchor + Duration::seconds(3600));
                    }
                    ref other => panic!("expected Quarantined, got {other:?}"),
                }
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_discovery_list_versions_total", "success"),
            Some(1)
        );
    }

    #[test]
    fn quarantined_anchor_with_global_policy_when_no_repo_scope() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let repo_key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                let anchor = Utc::now();
                h.artifacts
                    .seed_artifact(quarantined_artifact(repo_id, "left-pad", "1.0.0", anchor));
                // A repo-scoped policy for a DIFFERENT repo must be ignored;
                // two Global rows (same duration) exercise the
                // `Global if global.is_none()` true + false arms
                // deterministically; the Global window (2h) applies.
                h.policies
                    .insert(scan_policy(PolicyScope::Repository(Uuid::new_v4()), 999));
                h.policies.insert(scan_policy(PolicyScope::Global, 7200));
                h.policies.insert(scan_policy(PolicyScope::Global, 7200));
                let actor = caller_cli_session(&["dev"]);
                let listing =
                    h.uc.list_versions(&repo_key, "left-pad", Some(&actor))
                        .await
                        .expect("ok");
                match listing.versions[0].status {
                    DiscoveryVersionStatus::Quarantined { quarantine_until } => {
                        assert_eq!(quarantine_until, anchor + Duration::seconds(7200));
                    }
                    ref other => panic!("expected Quarantined, got {other:?}"),
                }
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_discovery_list_versions_total", "success"),
            Some(1)
        );
    }

    #[tokio::test]
    async fn policy_list_active_error_propagates() {
        let repo = npm_repo();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();
        let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
        h.policies
            .fail_next_list_active(DomainError::Invariant("policy DB exploded".into()));
        let actor = caller_cli_session(&["dev"]);
        let err =
            h.uc.list_versions(&repo_key, "left-pad", Some(&actor))
                .await
                .expect_err("policy list_active error must propagate");
        assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
    }

    // --- §6.8 status overlay arms ----------------------------------------

    #[test]
    fn overlay_released_arm() {
        let now = Utc::now();
        let listing = build_listing(
            "p",
            "npm",
            vec![("1.0.0".into(), QuarantineStatus::Released, None)],
            Vec::new(),
            now,
        );
        assert_eq!(listing.versions[0].status, DiscoveryVersionStatus::Released);
    }

    #[test]
    fn overlay_none_arm_collapses_to_released() {
        // A `QuarantineStatus::None` row is an un-quarantined direct
        // upload; surfacing it as `Released` is the operator-faithful
        // shape (the artifact is installable; the policy state is
        // "never had a quarantine window").
        let now = Utc::now();
        let listing = build_listing(
            "p",
            "npm",
            vec![("1.0.0".into(), QuarantineStatus::None, None)],
            Vec::new(),
            now,
        );
        assert_eq!(listing.versions[0].status, DiscoveryVersionStatus::Released);
    }

    #[test]
    fn overlay_quarantined_with_future_deadline_carries_payload() {
        let now = Utc::now();
        let deadline = now + Duration::hours(1);
        let listing = build_listing(
            "p",
            "npm",
            vec![(
                "1.0.0".into(),
                QuarantineStatus::Quarantined,
                Some(deadline),
            )],
            Vec::new(),
            now,
        );
        match listing.versions[0].status {
            DiscoveryVersionStatus::Quarantined { quarantine_until } => {
                assert_eq!(quarantine_until, deadline);
            }
            ref other => panic!("expected Quarantined {{ ... }}, got {other:?}"),
        }
    }

    #[test]
    fn overlay_quarantined_with_elapsed_deadline_becomes_awaiting_release() {
        let now = Utc::now();
        let elapsed = now - Duration::hours(1);
        let listing = build_listing(
            "p",
            "npm",
            vec![("1.0.0".into(), QuarantineStatus::Quarantined, Some(elapsed))],
            Vec::new(),
            now,
        );
        assert_eq!(
            listing.versions[0].status,
            DiscoveryVersionStatus::QuarantinedAwaitingRelease
        );
    }

    #[test]
    fn overlay_quarantined_with_deadline_exactly_now_becomes_awaiting_release() {
        // Boundary: `deadline > now` is the active-window predicate;
        // `deadline == now` falls into the awaiting-release bucket
        // (conservative — the window IS over).
        let now = Utc::now();
        let listing = build_listing(
            "p",
            "npm",
            vec![("1.0.0".into(), QuarantineStatus::Quarantined, Some(now))],
            Vec::new(),
            now,
        );
        assert_eq!(
            listing.versions[0].status,
            DiscoveryVersionStatus::QuarantinedAwaitingRelease
        );
    }

    #[test]
    fn overlay_quarantined_with_none_deadline_becomes_awaiting_release_conservative() {
        // Edge case (acceptance #11): `quarantine_until = None` paired
        // with `Quarantined` is unusual but possible (admin-override
        // workflows, gitops resets). Surface the conservative status —
        // operator dashboarding "stuck quarantines" sees it.
        let now = Utc::now();
        let listing = build_listing(
            "p",
            "npm",
            vec![("1.0.0".into(), QuarantineStatus::Quarantined, None)],
            Vec::new(),
            now,
        );
        assert_eq!(
            listing.versions[0].status,
            DiscoveryVersionStatus::QuarantinedAwaitingRelease
        );
    }

    #[test]
    fn overlay_rejected_arm() {
        let now = Utc::now();
        let listing = build_listing(
            "p",
            "npm",
            vec![("1.0.0".into(), QuarantineStatus::Rejected, None)],
            Vec::new(),
            now,
        );
        assert_eq!(listing.versions[0].status, DiscoveryVersionStatus::Rejected);
    }

    #[test]
    fn overlay_scan_indeterminate_arm() {
        let now = Utc::now();
        let listing = build_listing(
            "p",
            "npm",
            vec![("1.0.0".into(), QuarantineStatus::ScanIndeterminate, None)],
            Vec::new(),
            now,
        );
        assert_eq!(
            listing.versions[0].status,
            DiscoveryVersionStatus::ScanIndeterminate
        );
    }

    #[test]
    fn overlay_unknown_for_upstream_only_versions() {
        let now = Utc::now();
        let listing = build_listing(
            "p",
            "npm",
            Vec::new(),
            vec!["2.0.0".to_string(), "3.0.0".to_string()],
            now,
        );
        assert_eq!(listing.versions.len(), 2);
        assert!(listing
            .versions
            .iter()
            .all(|v| matches!(v.status, DiscoveryVersionStatus::Unknown)));
    }

    #[test]
    fn overlay_hort_held_wins_over_upstream() {
        // §6.8 contract: HORT rows are not demoted to `Unknown` just
        // because upstream also lists them.
        let now = Utc::now();
        let listing = build_listing(
            "p",
            "npm",
            vec![("1.0.0".into(), QuarantineStatus::Released, None)],
            vec!["1.0.0".to_string()],
            now,
        );
        assert_eq!(listing.versions.len(), 1);
        assert_eq!(listing.versions[0].status, DiscoveryVersionStatus::Released);
    }

    #[test]
    fn overlay_union_with_mixed_sets() {
        let now = Utc::now();
        let deadline = now + Duration::hours(1);
        let listing = build_listing(
            "p",
            "npm",
            vec![
                ("1.0.0".into(), QuarantineStatus::Released, None),
                (
                    "1.1.0".into(),
                    QuarantineStatus::Quarantined,
                    Some(deadline),
                ),
                ("0.9.0".into(), QuarantineStatus::Rejected, None),
            ],
            vec!["2.0.0".to_string(), "1.0.0".to_string()],
            now,
        );
        // 3 HORT + 1 upstream-only = 4 entries (1.0.0 is held; not
        // duplicated as `Unknown`).
        assert_eq!(listing.versions.len(), 4);
        // Find each by version + assert status.
        let by_version: HashMap<&str, &DiscoveryVersionStatus> = listing
            .versions
            .iter()
            .map(|v| (v.version.as_str(), &v.status))
            .collect();
        assert!(matches!(
            by_version["1.0.0"],
            DiscoveryVersionStatus::Released
        ));
        assert!(matches!(
            by_version["1.1.0"],
            DiscoveryVersionStatus::Quarantined { .. }
        ));
        assert!(matches!(
            by_version["0.9.0"],
            DiscoveryVersionStatus::Rejected
        ));
        assert!(matches!(
            by_version["2.0.0"],
            DiscoveryVersionStatus::Unknown
        ));
    }

    // --- §8 OCI rejection -------------------------------------------------

    #[test]
    fn oci_format_returns_validation_with_exact_message_and_ticks_oci_unsupported() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = oci_repo();
                let repo_id = repo.id;
                let repo_key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                // Seed a catch-all mapping (so the port IS called) — the
                // OCI port returns `UnsupportedFormat` by default policy.
                h.mappings
                    .upsert(mapping(repo_id))
                    .await
                    .expect("seed mapping");
                let actor = caller_cli_session(&["dev"]);
                let err =
                    h.uc.list_versions(&repo_key, "library/alpine", Some(&actor))
                        .await
                        .expect_err("OCI must be rejected");
                match err {
                    AppError::Domain(DomainError::Validation(msg)) => {
                        assert_eq!(msg, OCI_UNSUPPORTED_MESSAGE);
                    }
                    other => panic!("expected Validation, got {other:?}"),
                }
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_discovery_list_versions_total",
                "oci_unsupported"
            ),
            Some(1)
        );
    }

    // --- happy path: success across full overlay -------------------------

    #[test]
    fn happy_path_returns_full_listing_and_ticks_success_once() {
        let snap = capture(|| {
            Box::pin(async {
                let repo = npm_repo();
                let repo_id = repo.id;
                let repo_key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.upstream.insert_versions(
                    "npm",
                    "left-pad",
                    Ok(vec!["1.0.0".into(), "1.1.0".into(), "2.0.0".into()]),
                );
                h.artifacts.seed_package_version_status(
                    repo_id,
                    "left-pad",
                    vec![
                        ("1.0.0".into(), QuarantineStatus::Released),
                        ("1.1.0".into(), QuarantineStatus::Released),
                    ],
                );
                let actor = caller_cli_session(&["dev"]);
                let listing =
                    h.uc.list_versions(&repo_key, "left-pad", Some(&actor))
                        .await
                        .expect("ok");
                assert_eq!(listing.package, "left-pad");
                assert_eq!(listing.format, "npm");
                assert_eq!(listing.versions.len(), 3);
                // dispatch went through the port exactly once with
                // (format, package).
                assert_eq!(
                    h.upstream.calls(),
                    vec![("npm".to_string(), "left-pad".to_string())]
                );
            })
        });
        assert_eq!(
            counter_value(&snap, "hort_discovery_list_versions_total", "success"),
            Some(1)
        );
    }

    // --- upstream-fetch error variants ------------------------------------

    fn assert_upstream_fetch_error_maps_to_result(
        seed: UpstreamFetchError,
        expected_result_label: &str,
    ) {
        let snap = capture(move || {
            let seed = seed;
            Box::pin(async move {
                let repo = npm_repo();
                let repo_id = repo.id;
                let repo_key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.upstream.insert_versions("npm", "p", Err(seed));
                let actor = caller_cli_session(&["dev"]);
                let listing =
                    h.uc.list_versions(&repo_key, "p", Some(&actor))
                        .await
                        .expect("upstream error returns Ok envelope (per §7)");
                // Empty unknown set when the upstream call failed.
                assert!(listing
                    .versions
                    .iter()
                    .all(|v| !matches!(v.status, DiscoveryVersionStatus::Unknown)));
            })
        });
        assert_eq!(
            counter_value(
                &snap,
                "hort_discovery_list_versions_total",
                expected_result_label,
            ),
            Some(1),
            "expected {} tick",
            expected_result_label,
        );
    }

    #[test]
    fn upstream_not_found_ticks_not_found_label() {
        assert_upstream_fetch_error_maps_to_result(UpstreamFetchError::NotFound, "not_found");
    }

    #[test]
    fn upstream_unauthorized_ticks_unauthorized_label() {
        assert_upstream_fetch_error_maps_to_result(
            UpstreamFetchError::Unauthorized,
            "unauthorized",
        );
    }

    #[test]
    fn upstream_rate_limited_ticks_rate_limited_label() {
        assert_upstream_fetch_error_maps_to_result(UpstreamFetchError::RateLimited, "rate_limited");
    }

    #[test]
    fn upstream_4xx_ticks_upstream_4xx_label() {
        assert_upstream_fetch_error_maps_to_result(
            UpstreamFetchError::Upstream4xx { status: 418 },
            "upstream_4xx",
        );
    }

    #[test]
    fn upstream_5xx_ticks_upstream_5xx_label() {
        assert_upstream_fetch_error_maps_to_result(
            UpstreamFetchError::Upstream5xx { status: 503 },
            "upstream_5xx",
        );
    }

    #[test]
    fn upstream_network_error_ticks_network_error_label() {
        assert_upstream_fetch_error_maps_to_result(
            UpstreamFetchError::NetworkError("dns".into()),
            "network_error",
        );
    }

    #[test]
    fn upstream_timeout_ticks_timeout_label() {
        assert_upstream_fetch_error_maps_to_result(UpstreamFetchError::Timeout, "timeout");
    }

    #[test]
    fn upstream_parse_error_ticks_parse_error_label() {
        assert_upstream_fetch_error_maps_to_result(
            UpstreamFetchError::ParseError("packument".into()),
            "parse_error",
        );
    }

    // --- DiscoveryResult helper coverage ---------------------------------

    #[test]
    fn discovery_result_as_str_covers_every_arm() {
        // Pin every label string against the catalog wording.
        let pairs = [
            (DiscoveryResult::Success, "success"),
            (DiscoveryResult::NotFound, "not_found"),
            (DiscoveryResult::Unauthorized, "unauthorized"),
            (DiscoveryResult::RateLimited, "rate_limited"),
            (DiscoveryResult::Upstream4xx, "upstream_4xx"),
            (DiscoveryResult::Upstream5xx, "upstream_5xx"),
            (DiscoveryResult::NetworkError, "network_error"),
            (DiscoveryResult::Timeout, "timeout"),
            (DiscoveryResult::ParseError, "parse_error"),
            (DiscoveryResult::PermissionDenied, "permission_denied"),
            (DiscoveryResult::TokenKindDenied, "token_kind_denied"),
            (DiscoveryResult::OciUnsupported, "oci_unsupported"),
        ];
        for (variant, expected) in pairs {
            assert_eq!(variant.as_str(), expected);
        }
    }

    #[test]
    fn discovery_result_from_upstream_error_kind_covers_taxonomy() {
        use crate::metrics::UpstreamErrorKind;
        assert_eq!(
            DiscoveryResult::from_upstream_error_kind(UpstreamErrorKind::Success),
            DiscoveryResult::Success
        );
        assert_eq!(
            DiscoveryResult::from_upstream_error_kind(UpstreamErrorKind::NotFound),
            DiscoveryResult::NotFound
        );
        assert_eq!(
            DiscoveryResult::from_upstream_error_kind(UpstreamErrorKind::Unauthorized),
            DiscoveryResult::Unauthorized
        );
        assert_eq!(
            DiscoveryResult::from_upstream_error_kind(UpstreamErrorKind::RateLimited),
            DiscoveryResult::RateLimited
        );
        assert_eq!(
            DiscoveryResult::from_upstream_error_kind(UpstreamErrorKind::Upstream4xx),
            DiscoveryResult::Upstream4xx
        );
        assert_eq!(
            DiscoveryResult::from_upstream_error_kind(UpstreamErrorKind::Upstream5xx),
            DiscoveryResult::Upstream5xx
        );
        assert_eq!(
            DiscoveryResult::from_upstream_error_kind(UpstreamErrorKind::NetworkError),
            DiscoveryResult::NetworkError
        );
        assert_eq!(
            DiscoveryResult::from_upstream_error_kind(UpstreamErrorKind::Timeout),
            DiscoveryResult::Timeout
        );
        assert_eq!(
            DiscoveryResult::from_upstream_error_kind(UpstreamErrorKind::ParseError),
            DiscoveryResult::ParseError
        );
        // Defensive fold for the four out-of-band variants — all
        // collapse to `NetworkError` (documented in the helper).
        for kind in [
            UpstreamErrorKind::ChecksumMismatch,
            UpstreamErrorKind::BodyTooLarge,
            UpstreamErrorKind::PinMismatch,
            UpstreamErrorKind::CaUnknown,
        ] {
            assert_eq!(
                DiscoveryResult::from_upstream_error_kind(kind),
                DiscoveryResult::NetworkError
            );
        }
    }

    // --- §6.9 invariant guard --------------------------------------------

    /// Smoke-pin the §6.9 invariant at the source level. The pre-merge
    /// verification gate runs `git grep` on the same set of identifiers;
    /// this in-source assertion catches an early stray import or a
    /// future refactor that wires in the unified index pipeline.
    ///
    /// The forbidden identifiers are assembled at runtime from string
    /// fragments — the assertion message itself must NOT spell the
    /// identifier verbatim, otherwise the in-source string scan would
    /// trip on its own panic literal.
    #[test]
    fn discovery_use_case_does_not_import_init49_filter_or_builder() {
        let src = include_str!("discovery_use_case.rs");
        // Build the identifier strings from disjoint fragments so the
        // test source itself contains neither the joined form. Format
        // them per-arm into the panic message via positional args; the
        // formatting expression also avoids the joined form.
        let non_servable = format!("{}{}{}", "NonServ", "ableStatu", "sFilter");
        let index_mode = format!("{}{}", "IndexMod", "eFilter");
        let index_builder = format!("{}{}", "IndexBu", "ilder");
        for forbidden in [non_servable, index_mode, index_builder] {
            assert!(
                !src.contains(&forbidden),
                "index-pipeline isolation invariant violated: {} present in discovery_use_case.rs",
                forbidden,
            );
        }
    }

    // --- defensive: repo-port infrastructure error propagates ------------

    #[tokio::test]
    async fn repo_port_non_notfound_error_propagates() {
        let repo = npm_repo();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();
        let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
        h.repos
            .fail_next_find_by_key(DomainError::Invariant("DB exploded".into()));
        let actor = caller_cli_session(&["dev"]);
        let err =
            h.uc.list_versions(&repo_key, "p", Some(&actor))
                .await
                .expect_err("invariant must propagate");
        assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
    }

    // --- defensive: structural — port impl is invoked with format key ----

    #[test]
    fn dispatch_passes_format_key_to_port() {
        let _snap = capture(|| {
            Box::pin(async {
                let repo = {
                    let mut r = sample_repository();
                    r.format = hort_domain::entities::repository::RepositoryFormat::Pypi;
                    r.is_public = false;
                    r
                };
                let repo_id = repo.id;
                let repo_key = repo.key.clone();
                let h = wire(repo, evaluator_with_read_grant("dev", repo_id));
                h.mappings.upsert(mapping(repo_id)).await.unwrap();
                h.upstream
                    .insert_versions("pypi", "requests", Ok(vec!["2.31.0".into()]));
                let actor = caller_cli_session(&["dev"]);
                let _listing =
                    h.uc.list_versions(&repo_key, "requests", Some(&actor))
                        .await
                        .expect("ok");
                assert_eq!(
                    h.upstream.calls(),
                    vec![("pypi".to_string(), "requests".to_string())]
                );
            })
        });
    }

    // --- defensive: success across status arms (mixed payload) -----------

    #[test]
    fn success_path_serializes_mixed_arms() {
        // Smoke check that the listing's outer envelope is shaped per
        // §2.2's JSON example — `package`, `format`, `versions` —
        // through Serialize. The arm-level coverage lives upstream in
        // `entities/discovery.rs` Serialize tests; this is the
        // use-case-level check.
        let now = Utc::now();
        let deadline = now + Duration::hours(2);
        let listing = build_listing(
            "p",
            "npm",
            vec![
                ("1.0.0".into(), QuarantineStatus::Released, None),
                (
                    "1.1.0".into(),
                    QuarantineStatus::Quarantined,
                    Some(deadline),
                ),
            ],
            vec!["2.0.0".to_string()],
            now,
        );
        let json = serde_json::to_value(&listing).expect("serialize");
        assert_eq!(json["package"], "p");
        assert_eq!(json["format"], "npm");
        assert_eq!(json["versions"].as_array().unwrap().len(), 3);
    }

    // --- defensive: mapping-port infrastructure error propagates ---------

    /// One-shot failing mapping mock: returns an `Invariant` error on
    /// the next `list_for_repository` call. Pinned-local; not added to
    /// `test_support` (one use, one purpose).
    struct FailingMappingRepo {
        next: std::sync::Mutex<Option<DomainError>>,
    }

    impl FailingMappingRepo {
        fn new(err: DomainError) -> Self {
            Self {
                next: std::sync::Mutex::new(Some(err)),
            }
        }
    }

    impl RepositoryUpstreamMappingRepository for FailingMappingRepo {
        fn list_for_repository(
            &self,
            _repository_id: Uuid,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Vec<RepositoryUpstreamMapping>>,
        > {
            let next = self.next.lock().unwrap().take();
            Box::pin(async move {
                match next {
                    Some(e) => Err(e),
                    None => Ok(Vec::new()),
                }
            })
        }
        fn list_all(
            &self,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Vec<RepositoryUpstreamMapping>>,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn upsert(
            &self,
            _m: RepositoryUpstreamMapping,
        ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn delete(
            &self,
            _r: Uuid,
            _p: &str,
        ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn list_managed_by_gitops(
            &self,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Vec<RepositoryUpstreamMapping>>,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn save_managed(
            &self,
            _m: &RepositoryUpstreamMapping,
        ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn delete_managed_by_id(
            &self,
            _id: Uuid,
        ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn mapping_port_invariant_error_propagates() {
        let repo = npm_repo();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo);
        let artifacts = Arc::new(MockArtifactRepository::new());
        let mappings = Arc::new(FailingMappingRepo::new(DomainError::Invariant(
            "mapping DB exploded".into(),
        )));
        let upstream = Arc::new(MockUpstreamMetadataPort::new());
        let rbac = Arc::new(ArcSwap::from_pointee(evaluator_with_read_grant(
            "dev", repo_id,
        )));
        let policies = Arc::new(MockPolicyProjectionRepository::new());
        let uc = DiscoveryUseCase::new(repos, artifacts, mappings, upstream, rbac, policies);
        let actor = caller_cli_session(&["dev"]);
        let err = uc
            .list_versions(&repo_key, "p", Some(&actor))
            .await
            .expect_err("mapping invariant must propagate");
        assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
    }

    // --- defensive: artifacts-port infrastructure error propagates -------

    /// Failing artifact mock that errors on `package_version_status`.
    struct FailingArtifactsRepo;

    impl ArtifactRepository for FailingArtifactsRepo {
        fn find_by_id(
            &self,
            _id: Uuid,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<hort_domain::entities::artifact::Artifact>,
        > {
            unimplemented!("not used by discovery test")
        }
        fn find_by_checksum(
            &self,
            _h: &hort_domain::types::ContentHash,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Option<hort_domain::entities::artifact::Artifact>>,
        > {
            Box::pin(async { Ok(None) })
        }
        fn find_by_repo_and_checksum(
            &self,
            _r: Uuid,
            _h: &hort_domain::types::ContentHash,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Option<hort_domain::entities::artifact::Artifact>>,
        > {
            Box::pin(async { Ok(None) })
        }
        fn list_by_repository(
            &self,
            _r: Uuid,
            _p: hort_domain::types::PageRequest,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::types::Page<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn delete(
            &self,
            _id: Uuid,
        ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_path(
            &self,
            _r: Uuid,
            _p: &str,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Option<hort_domain::entities::artifact::Artifact>>,
        > {
            Box::pin(async { Ok(None) })
        }
        fn list_distinct_names(
            &self,
            _r: Uuid,
            _p: hort_domain::types::PageRequest,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<hort_domain::types::Page<String>>,
        > {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn find_by_name_in_repo(
            &self,
            _r: Uuid,
            _n: &str,
            _p: hort_domain::types::PageRequest,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::types::Page<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn find_by_name_as_published(
            &self,
            _r: Uuid,
            _n: &str,
            _p: hort_domain::types::PageRequest,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::types::Page<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::Page::empty()) })
        }
        fn list_active_for_repo(
            &self,
            _r: Uuid,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::types::LimitedList<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::LimitedList::empty()) })
        }
        fn list_rejected_for_policy(
            &self,
            _p: Uuid,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                hort_domain::types::LimitedList<hort_domain::entities::artifact::Artifact>,
            >,
        > {
            Box::pin(async { Ok(hort_domain::types::LimitedList::empty()) })
        }
        fn package_version_status(
            &self,
            _r: Uuid,
            _p: &str,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>,
            >,
        > {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "package_version_status exploded".into(),
                ))
            })
        }
        fn package_version_anchors(
            &self,
            _r: Uuid,
            _p: &str,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<
                Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>,
            >,
        > {
            Box::pin(async {
                Err(DomainError::Invariant(
                    "package_version_anchors exploded".into(),
                ))
            })
        }
        fn find_pypi_wheels_without_kind(
            &self,
            _k: &str,
            _l: u32,
        ) -> hort_domain::ports::BoxFuture<
            '_,
            hort_domain::error::DomainResult<Vec<hort_domain::entities::artifact::Artifact>>,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn artifacts_port_invariant_error_propagates() {
        let repo = npm_repo();
        let repo_id = repo.id;
        let repo_key = repo.key.clone();
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(repo);
        let artifacts: Arc<dyn ArtifactRepository> = Arc::new(FailingArtifactsRepo);
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
        let upstream = Arc::new(MockUpstreamMetadataPort::new());
        let rbac = Arc::new(ArcSwap::from_pointee(evaluator_with_read_grant(
            "dev", repo_id,
        )));
        let policies = Arc::new(MockPolicyProjectionRepository::new());
        let uc = DiscoveryUseCase::new(repos, artifacts, mappings, upstream, rbac, policies);
        let actor = caller_cli_session(&["dev"]);
        let err = uc
            .list_versions(&repo_key, "p", Some(&actor))
            .await
            .expect_err("artifacts invariant must propagate");
        assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
    }
}
