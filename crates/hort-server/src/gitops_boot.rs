//! Boot-time gitops apply (see
//! `docs/architecture/how-to/declare-gitops-config.md`).
//!
//! Walks `$HORT_CONFIG_DIR` recursively, parses every `*.yaml` /
//! `*.yml` envelope into a `DesiredState`, validates against the
//! current snapshot + env, and runs `ApplyConfigUseCase::apply`.
//! Runs **before** `build_app_context` so the `Vec<ClaimMapping>`
//! consumed by `AuthenticateUseCase::new` reflects the post-apply
//! state — there is no mid-boot `AppContext` mutation, no live-
//! refresh path. Restart-to-apply is the contract.
//!
//! Failure semantics are blunt by design: any parse / validate /
//! apply error returns `Err(GitopsBootError)`; the caller (`cli::serve`)
//! maps that to a non-zero exit. Half-applied state is acceptable
//! — the operator's recovery action is identical (correct the
//! config and restart), so rollback would be ceremony for no
//! benefit.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use hort_app::error::AppError;
use hort_app::event_store_publisher::EventStorePublisher;
use hort_app::use_cases::apply_config_use_case::{
    ApplyConfigUseCase, ApplyReport, UpstreamHostAllowlist,
};
use hort_app::use_cases::PolicyUseCase;
use hort_config::desired::EnvSnapshot;
use hort_config::{DesiredState, EnvAuthProvider};
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::claim_mapping_repository::ClaimMappingRepository;
use hort_domain::ports::content_reference_index::ContentReferenceIndex;
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::oidc_issuer_repository::OidcIssuerRepository;
use hort_domain::ports::permission_grant_repository::PermissionGrantRepository;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;
use hort_domain::ports::service_account_repository::ServiceAccountRepository;
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::user_repository::UserRepository;
use sqlx::PgPool;
use walkdir::WalkDir;

use crate::config::AuthConfig;

/// Outcome from a boot-time apply. Boot wires this into
/// `tracing::info!`/`error!` and a non-zero process exit on `Err`.
#[derive(Debug, thiserror::Error)]
pub enum GitopsBootError {
    /// Parse failures rendered into one human-readable string.
    /// Multiple per-file errors are collapsed into one block by the
    /// `ParseErrors` `Display` impl (one error per line).
    #[error("gitops parse failed:\n{0}")]
    Parse(String),

    /// Provably **pre-write** validation/lint failure, surfaced by
    /// `ApplyConfigUseCase::preflight_validate` BEFORE `apply()` runs.
    /// No DB write has occurred, so the caller PARKS not-ready instead of
    /// crashlooping — distinct from [`Self::Validate`] (the in-stage,
    /// mid-write-capable validation that must still crash).
    #[error("gitops preflight validation failed:\n{0}")]
    PreflightValidate(String),

    /// Cross-spec validation failed **inside `apply()`'s write stages**
    /// (e.g. a Stage-2/3 RetentionPolicy predicate/scope resolve, an
    /// upstream-mapping construction). This is mid-write-capable — a
    /// Stage-1 `save_managed` may already have run — so it MUST crash, not
    /// park. Pre-write cross-spec validation (duplicate names, dangling
    /// virtual members, HORT_AUTH_PROVIDER conflict, managed-vs-Local
    /// conflict) is caught earlier by the preflight pass and surfaces as
    /// [`Self::PreflightValidate`] instead.
    #[error("gitops validation failed:\n{0}")]
    Validate(String),

    /// `ApplyConfigUseCase::apply` returned `Err` mid-flight. `v1`
    /// is strict-atomic with no rollback — half-applied state is
    /// observable but the operator's recovery is identical (fix
    /// YAML + restart).
    #[error("gitops apply failed: {0}")]
    Apply(String),

    /// Filesystem I/O failure during the directory walk.
    #[error("gitops filesystem walk failed: {0}")]
    Walk(#[from] walkdir::Error),

    /// Reading a file's bytes failed (file appeared in the walk but
    /// can't be opened — permissions, race, etc).
    #[error("gitops read failed for {path:?}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Read every `*.yaml` / `*.yml` under `dir` and apply it.
///
/// Constructs only the adapters needed for apply (`PgRepositoryRepository`,
/// `PgClaimMappingRepository`); does NOT call `build_app_context`.
/// The full `AppContext` is built later by the caller, after this
/// function returns successfully.
///
/// `auth_for_env_snapshot` is the parsed `Config::auth` value. Mapped
/// down to `EnvAuthProvider` so `hort-config`'s validate doesn't have to
/// know about `AuthConfig`'s OIDC-specific shape.
pub async fn apply_config_from_dir(
    pool: &PgPool,
    config_dir: &Path,
    auth_for_env_snapshot: &AuthConfig,
    upstream_allowlist: UpstreamHostAllowlist,
    extra_trust_anchors: Option<&hort_config::ExtraTrustAnchors>,
    storage: Arc<dyn StoragePort>,
    // The
    // deployment's effective global storage backend, mapped by the
    // caller from its already-in-scope `StorageConfig`. Threaded so
    // `ApplyConfigUseCase` can reject a per-repo `storage.backend`
    // mismatch at apply. This is an **internal `hort-server` fn
    // signature** only — NOT a port trait, NOT `ApplyConfigUseCase::new`,
    // NOT a cross-crate edge (`EffectiveStorageBackend` is `hort-app`,
    // which `hort-server` already depends on).
    effective_storage_backend: hort_app::storage_backend::EffectiveStorageBackend,
) -> Result<ApplyReport, GitopsBootError> {
    let started = Instant::now();
    let result = apply_inner(
        pool,
        config_dir,
        auth_for_env_snapshot,
        upstream_allowlist,
        extra_trust_anchors,
        storage,
        effective_storage_backend,
    )
    .await;
    record_duration_metric(started.elapsed().as_secs_f64());
    classify_and_emit_apply_metric(&result);
    result
}

async fn apply_inner(
    pool: &PgPool,
    config_dir: &Path,
    auth: &AuthConfig,
    upstream_allowlist: UpstreamHostAllowlist,
    extra_trust_anchors: Option<&hort_config::ExtraTrustAnchors>,
    storage: Arc<dyn StoragePort>,
    effective_storage_backend: hort_app::storage_backend::EffectiveStorageBackend,
) -> Result<ApplyReport, GitopsBootError> {
    // ---- 1. walk the directory, collect (path, bytes) pairs ----
    let files = collect_yaml_files(config_dir)?;
    tracing::info!(
        config_dir = %config_dir.display(),
        files_loaded = files.len(),
        "gitops boot: directory walk complete"
    );

    // ---- 2. parse ----
    let desired = match DesiredState::parse_files(files) {
        Ok(d) => d,
        Err(errs) => {
            let rendered = errs.to_string();
            tracing::error!(error = %rendered, "gitops boot: parse failed");
            return Err(GitopsBootError::Parse(rendered));
        }
    };
    tracing::info!(
        repositories_desired = desired.repositories.len(),
        claim_mappings_desired = desired.claim_mappings.len(),
        permission_grants_desired = desired.permission_grants.len(),
        "gitops boot: parse complete"
    );

    // ---- 3. construct apply-only adapters ----
    //
    // The apply
    // pipeline needs the per-kind managed-write ports plus a
    // `PolicyUseCase` for the event-sourced (`ScanPolicy` / `Exclusion`)
    // applies. Each adapter takes the same shared `PgPool`. The
    // `PgEventStore` constructor verifies the immutability trigger at
    // startup — if it returns `Err`, the apply path is unsafe and we
    // surface it as a typed apply failure (operators see "gitops apply
    // failed: <err>" before any rows are written).
    let repos: Arc<dyn RepositoryRepository> = Arc::new(
        hort_adapters_postgres::repository_repo::PgRepositoryRepository::new(pool.clone()),
    );
    // The apply pipeline handles the additive-claims
    // config kinds (ADR 0012): `ClaimMapping` and the
    // subject-typed `PermissionGrant`. There is no
    // `Role`/`role_id` model and no `RoleRepository` /
    // `GroupMappingRepository` adapter.
    let claim_mappings: Arc<dyn ClaimMappingRepository> = Arc::new(
        hort_adapters_postgres::claim_mapping_repo::PgClaimMappingRepository::new(pool.clone()),
    );
    let permission_grants: Arc<dyn PermissionGrantRepository> = Arc::new(
        hort_adapters_postgres::permission_grant_repo::PgPermissionGrantRepository::new(
            pool.clone(),
        ),
    );
    let curation_rule_repo: Arc<dyn CurationRuleRepository> = Arc::new(
        hort_adapters_postgres::curation_rule_repo::PgCurationRuleRepository::new(pool.clone()),
    );
    let policy_projections: Arc<dyn PolicyProjectionRepository> = Arc::new(
        hort_adapters_postgres::policy_projection_repo::PgPolicyProjectionRepository::new(
            pool.clone(),
        ),
    );
    let pg_event_store = Arc::new(
        hort_adapters_postgres::event_store::PgEventStore::new(pool.clone())
            .await
            .map_err(|e| GitopsBootError::Apply(format!("event store init: {e}")))?,
    );
    let event_store: Arc<dyn EventStore> = pg_event_store.clone();
    // Gitops boot runs the apply pipeline before
    // `AppContext` is constructed; no dispatcher is running, so wrap in
    // a no-broadcast publisher. The apply path appends `PolicyCreated`,
    // `RepositoryConfigChanged`, etc. via the use cases; with no
    // subscribers attached, those events are not broadcast — same
    // production semantics as a fresh boot before any `Subscription`
    // row exists. Tested catches up via `read_category` on next start.
    let event_publisher = Arc::new(EventStorePublisher::without_broadcast(event_store.clone()));
    // The apply pipeline drives a
    // retroactive curation evaluation pass which needs read access to
    // active artifacts plus an atomic state-plus-events writer for
    // `RetroBlock` outcomes. Mirrors `composition.rs`'s wiring; cheap
    // pool clones, the pool itself owns the connection lifecycle.
    let pg_artifact_repo =
        Arc::new(hort_adapters_postgres::artifact_repo::PgArtifactRepository::new(pool.clone()));
    let artifacts: Arc<dyn ArtifactRepository> = pg_artifact_repo.clone();
    let pg_artifact_metadata_repo = Arc::new(
        hort_adapters_postgres::artifact_metadata_repo::PgArtifactMetadataRepository::new(
            pool.clone(),
        ),
    );
    let artifact_lifecycle: Arc<dyn ArtifactLifecyclePort> = Arc::new(
        hort_adapters_postgres::artifact_lifecycle::PgArtifactLifecycle::new(
            pg_event_store,
            pg_artifact_repo,
            pg_artifact_metadata_repo,
        ),
    );
    // The gitops boot path drives `add_exclusion` /
    // `remove_exclusion` via `Actor::Gitops` (not the curator HTTP
    // edge), but the use case is permission-neutral; both call sites
    // share the same emission code. Wire a `RepositoryAccessUseCase`
    // pinned to `RbacAccess::Disabled` (gitops apply is not user-
    // authority) with the cardinality knob enabled. The repo metric
    // label resolves via the existing `RepositoryRepository`; failures
    // fall to the `unknown` sentinel.
    let repository_access_for_policy = Arc::new(
        hort_app::use_cases::repository_access::RepositoryAccessUseCase::new(
            repos.clone(),
            hort_app::use_cases::repository_access::RbacAccess::Disabled,
            true,
        ),
    );
    let policies = Arc::new(PolicyUseCase::new(
        event_publisher.clone(),
        policy_projections.clone(),
        artifacts.clone(),
        artifact_lifecycle.clone(),
        storage,
        repository_access_for_policy,
    ));
    // Gitops writer for the
    // `repository_upstream_mappings` table (there is no admin
    // REST writer; gitops is the only write path).
    let upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository> = Arc::new(
        hort_adapters_postgres::repository_upstream_mapping_repo::PgRepositoryUpstreamMappingRepo::new(
            pool.clone(),
        ),
    );
    // The apply pipeline's
    // retroactive curation `RetroBlock` arm sweeps
    // `content_references` rows for the rejected source. Cheap pool
    // clone; cheaper than re-routing the apply through the full
    // `AppContext` composition.
    let content_references: Arc<dyn ContentReferenceIndex> = Arc::new(
        hort_adapters_postgres::pg_content_reference_repo::PgContentReferenceRepo::new(
            pool.clone(),
        ),
    );
    // Apply-pipeline ports for the machine-identity gitops
    // kinds (OidcIssuer + ServiceAccount — ADR 0018). The user repo is
    // reused
    // from the human-user pipeline; the apply path uses it to ensure
    // backing-user rows for declared SAs.
    let oidc_issuers: Arc<dyn OidcIssuerRepository> = Arc::new(
        hort_adapters_postgres::oidc_issuer_repo::PgOidcIssuerRepository::new(pool.clone()),
    );
    let service_accounts: Arc<dyn ServiceAccountRepository> = Arc::new(
        hort_adapters_postgres::service_account_repo::PgServiceAccountRepository::new(pool.clone()),
    );
    let users: Arc<dyn UserRepository> = Arc::new(
        hort_adapters_postgres::user_repo::PgUserRepository::new(pool.clone()),
    );
    // Apply-time
    // JWKS warm-up (ADR 0018). Construct the same `MultiIssuerJwksValidator` shape
    // the runtime composition wires (`composition.rs`), against the
    // same `OidcIssuerRepository`, threading the operator's extra-CA
    // bundle through. Constructor failure (extra-CA parse / TLS
    // builder) maps to `GitopsBootError::Apply` — boot refuses to
    // start against a partially-trusted state. On a fully disabled
    // auth deployment (`AuthConfig::Disabled`) we skip the validator
    // entirely; federation cannot fire so warm-up is moot.
    let federated_jwt_validator: Option<
        Arc<dyn hort_domain::ports::federated_jwt_validator::FederatedJwtValidator>,
    > = match auth {
        AuthConfig::Disabled => None,
        AuthConfig::Oidc(_) => {
            let issuers_for_validator: Arc<dyn OidcIssuerRepository> = oidc_issuers.clone();
            let v = hort_adapters_oidc::MultiIssuerJwksValidator::new(
                issuers_for_validator,
                extra_trust_anchors,
            )
            .map_err(|e| {
                GitopsBootError::Apply(format!("MultiIssuerJwksValidator construction failed: {e}"))
            })?;
            tracing::info!(
                "gitops boot: federation JWT validator wired for apply-time JWKS warm-up"
            );
            Some(Arc::new(v))
        }
    };

    let apply_uc = ApplyConfigUseCase::new(
        repos,
        claim_mappings,
        permission_grants,
        curation_rule_repo,
        policy_projections,
        policies,
        artifacts,
        artifact_lifecycle,
        event_publisher,
        upstream_mappings,
        upstream_allowlist,
        content_references,
        oidc_issuers,
        service_accounts,
        users,
    );
    let apply_uc = match federated_jwt_validator {
        Some(v) => apply_uc.with_federated_jwt_validator(v),
        None => apply_uc,
    };
    // Wire the
    // deployment's effective global storage backend so a per-repo
    // `storage.backend` differing from it is rejected at apply
    // (fail-closed, loud). Mirrors the
    // `with_federated_jwt_validator` builder shape; the constructor
    // signature is byte-unchanged.
    let apply_uc = apply_uc.with_effective_storage_backend(effective_storage_backend);
    // Activate the apply-time fail-closed
    // provenance linter (ADR 0027). The set is the **static** backend→format
    // capability map (Tier-1: cosign → OCI), passed as plain data so
    // hort-server never depends on hort-adapters-provenance-sigstore (it
    // mirrors the worker's registered cosign port, Tier-1: cosign → oci).
    // A `provenance_mode: Required` policy on a scope whose format is
    // absent from this set is apply-rejected (no verifier could ever
    // satisfy the gate → artifacts stuck Pending forever). The check is
    // necessarily static: apply runs server-side while a verifier's live
    // enablement (`worker.provenance.cosign.enabled`) is a worker deploy
    // concern apply cannot see — the how-to warns operators that
    // `Required` also needs the matching verifier enabled on the worker.
    let apply_uc = apply_uc.with_provenance_capable_formats(
        hort_app::provenance::TIER1_PROVENANCE_CAPABLE_FORMATS
            .iter()
            .copied()
            .map(String::from),
    );

    // ---- 4. apply ----
    let env_snapshot = EnvSnapshot {
        auth_provider: match auth {
            AuthConfig::Disabled => EnvAuthProvider::Disabled,
            AuthConfig::Oidc(_) => EnvAuthProvider::Oidc,
        },
    };

    // Provably pre-write validation/lint pass FIRST, so a config error that
    // cannot have written anything PARKS not-ready (`PreflightValidate`)
    // instead of crashlooping. `apply()` re-runs the same checks (emitting
    // the advisories) on the write path; reaching `apply()` at all means
    // preflight passed, so any `Validation` it then returns is in-stage
    // (mid-write-capable) and correctly crashes.
    if let Err(e) = apply_uc.preflight_validate(&desired, &env_snapshot).await {
        return match e {
            AppError::Domain(hort_domain::error::DomainError::Validation(msg)) => {
                tracing::error!(
                    error = %msg,
                    "gitops boot: preflight validation failed (pre-write — parking not-ready)"
                );
                Err(GitopsBootError::PreflightValidate(msg))
            }
            // A non-validation error from preflight is infrastructure (snapshot
            // build read) — NOT provably benign, so crash.
            other => {
                let rendered = other.to_string();
                tracing::error!(error = %rendered, "gitops boot: preflight failed (infrastructure)");
                Err(GitopsBootError::Apply(rendered))
            }
        };
    }

    let report = match apply_uc.apply(desired, env_snapshot).await {
        Ok(r) => r,
        Err(AppError::Domain(hort_domain::error::DomainError::Validation(msg))) => {
            tracing::error!(
                error = %msg,
                "gitops boot: in-stage validation failed (mid-write — crashing)"
            );
            return Err(GitopsBootError::Validate(msg));
        }
        Err(e) => {
            let rendered = e.to_string();
            tracing::error!(error = %rendered, "gitops boot: apply failed");
            return Err(GitopsBootError::Apply(rendered));
        }
    };

    tracing::info!(
        created = report.created,
        updated = report.updated,
        deleted = report.deleted,
        unchanged = report.unchanged,
        "gitops boot: apply succeeded"
    );

    Ok(report)
}

/// Recursively collect every `*.yaml` / `*.yml` file under `dir`.
///
/// Symlinks ARE followed — this is required for the canonical
/// production deployment shape, a Kubernetes ConfigMap volume
/// mount. K8s projects ConfigMap keys with subdirectory paths as:
///
/// ```text
/// /etc/hort-server/config/
/// ├── ..2026_05_03_…/auth/admins.yaml         ← real file
/// ├── ..data → ..2026_05_03_…/                ← hidden, filtered
/// ├── auth → ..data/auth/                     ← symlink to dir
/// └── repositories → ..data/repositories/     ← symlink to dir
/// ```
///
/// With `follow_links(false)` the walker would skip every visible
/// top-level entry as a non-file non-dir symlink and silently
/// report `files_loaded: 0` against a correctly-projected mount.
///
/// `walkdir`'s built-in cycle detection bounds the loop / surprise-
/// inclusion concern: a symlink loop emits `Error::Loop` rather
/// than infinite-looping; the error propagates as
/// `GitopsBootError::Walk` and the boot apply fails loud.
///
/// Hidden files and hidden directories (anything whose name starts
/// with `.`) are skipped — `.git/`, `.DS_Store`, `.flux-sync`,
/// AND the K8s `..data` / `..<timestamp>` projection-internal
/// entries shouldn't poison the apply. `filter_entry` prunes
/// hidden dirs BEFORE WalkDir descends into them, so an enormous
/// `.git/` doesn't slow the walk and the K8s projection's
/// timestamped real directory is not double-walked (the visible
/// `auth` / `repositories` symlinks are the operator's intended
/// entry points).
///
/// The match is case-insensitive so `Foo.YAML` also lands.
///
/// The root directory itself is never treated as hidden even if
/// the operator chose a hidden-style path like `/etc/.hort-config`.
///
/// `pub(crate)` so the offline
/// [`crate::cli::validate_config`] command reuses the exact same walker
/// the boot path runs ("reuse, don't fork").
/// Kept crate-scoped: the only
/// consumer is the sibling CLI module in this same crate, so there is no
/// need to widen the published surface.
pub(crate) fn collect_yaml_files(dir: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>, GitopsBootError> {
    let root_depth = 0;
    let mut out = Vec::new();
    let walker = WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_entry(move |e| {
            // Don't filter the root entry itself — operator may have
            // chosen a hidden-style root path.
            if e.depth() == root_depth {
                return true;
            }
            !e.file_name().to_string_lossy().starts_with('.')
        });
    for entry in walker {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        let lower = name.to_ascii_lowercase();
        if !(lower.ends_with(".yaml") || lower.ends_with(".yml")) {
            continue;
        }
        let bytes = std::fs::read(entry.path()).map_err(|source| GitopsBootError::Read {
            path: entry.path().to_path_buf(),
            source,
        })?;
        out.push((entry.path().to_path_buf(), bytes));
    }
    Ok(out)
}

fn record_duration_metric(seconds: f64) {
    metrics::histogram!("hort_gitops_apply_duration_seconds").record(seconds);
}

/// Is this boot-time gitops failure **provably pre-write** — i.e. did it
/// fire before `apply_uc.apply()` (the first DB write, `apply_inner`
/// stage 4)?
///
/// Only the provably-pre-write classes are park-eligible:
///
/// - `Parse` — fails in the `DesiredState::parse_files` branch of
///   `apply_inner`, before any apply-only adapter is even constructed, so
///   zero rows are written.
/// - `Read` / `Walk` — fail during `collect_yaml_files`'s directory walk,
///   before parse and therefore before any write.
/// - `PreflightValidate` — fails in `apply_uc.preflight_validate()`, which
///   `apply_inner` runs BEFORE `apply()`. That pass performs only the
///   snapshot read and the in-memory validation/lint checks — zero writes —
///   so a failure here is provably pre-write and parks. This is the
///   validation/lint that operators most commonly trip (a typo'd
///   `scanBackends`, a bad lint/provenance config, a duplicate name, a
///   dangling FK); it no longer crashloops. (A *correct* `scanBackends`
///   entry no longer trips it on a fresh boot: backends are validated
///   against the compiled-in set, not the live worker registry — H20.)
///
/// `Validate` and `Apply` originate from `apply_uc.apply()` (or the
/// adapter / event-store-probe construction that immediately precedes it),
/// which is mid-write-capable. By the time `apply()` runs, preflight has
/// already passed, so a `Validate` here is an *in-stage* check (e.g. a
/// Stage-2/3 RetentionPolicy predicate/scope resolve) that can fire after a
/// Stage-1 `save_managed`. `ApplyConfigUseCase` ships **no rollback** on
/// purpose; its safety rests on "boot exits non-zero on a possibly-half-
/// applied state". So these classes MUST still crash — parking them would
/// silently erode that invariant. The `is_park_eligible_*` unit tests pin
/// it per-variant.
pub fn is_park_eligible(err: &GitopsBootError) -> bool {
    match err {
        GitopsBootError::Parse(_)
        | GitopsBootError::Read { .. }
        | GitopsBootError::Walk(_)
        | GitopsBootError::PreflightValidate(_) => true,
        GitopsBootError::Validate(_) | GitopsBootError::Apply(_) => false,
    }
}

fn classify_and_emit_apply_metric(result: &Result<ApplyReport, GitopsBootError>) {
    let label = match result {
        Ok(_) => "ok",
        Err(GitopsBootError::Parse(_)) => "parse_error",
        // Pre-write preflight + in-stage validation share the existing
        // `validation_error` label (no new metric-catalog label value).
        Err(GitopsBootError::PreflightValidate(_)) | Err(GitopsBootError::Validate(_)) => {
            "validation_error"
        }
        Err(_) => "apply_error",
    };
    metrics::counter!("hort_gitops_apply_total", "result" => label).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(dir: &Path, rel: &str, body: &str) {
        let full = dir.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, body).unwrap();
    }

    #[test]
    fn collect_yaml_files_picks_up_both_extensions_recursively() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "repositories/a.yaml", "x: 1");
        write(dir.path(), "auth/b.yml", "x: 2");
        write(dir.path(), "notes.txt", "ignored");
        write(dir.path(), ".hidden.yaml", "ignored");
        write(dir.path(), ".git/config", "ignored");

        let files = collect_yaml_files(dir.path()).unwrap();
        let names: Vec<&str> = files
            .iter()
            .filter_map(|(p, _)| p.file_name())
            .map(|n| n.to_str().unwrap())
            .collect();
        assert!(names.contains(&"a.yaml"), "got: {names:?}");
        assert!(names.contains(&"b.yml"), "got: {names:?}");
        assert!(!names.contains(&"notes.txt"));
        assert!(!names.contains(&".hidden.yaml"));
    }

    #[test]
    fn collect_yaml_files_skips_hidden_directories() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".secret/leaked.yaml", "x: 1");
        write(dir.path(), "ok.yaml", "x: 2");

        let files = collect_yaml_files(dir.path()).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].0.ends_with("ok.yaml"));
    }

    #[test]
    fn collect_yaml_files_case_insensitive_extension() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "Foo.YAML", "x: 1");
        write(dir.path(), "Bar.YML", "x: 2");
        let files = collect_yaml_files(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn collect_yaml_files_empty_directory_is_ok() {
        let dir = TempDir::new().unwrap();
        let files = collect_yaml_files(dir.path()).unwrap();
        assert!(files.is_empty());
    }

    /// Regression for a K8s-ConfigMap-mount bug seen in a test
    /// deployment of the Helm chart: the production layout
    /// projects every visible top-level entry as a symlink into a
    /// timestamped real directory. With `follow_links(false)` the
    /// walker skips them all and reports `files_loaded: 0` against
    /// a correctly-projected mount. This test simulates the K8s
    /// layout exactly so a future regression on `follow_links`
    /// fails loud here.
    #[cfg(unix)]
    #[test]
    fn collect_yaml_files_follows_kubernetes_configmap_projection_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let root = dir.path();

        // Real directory, dot-dot prefix mirrors K8s atomic-update
        // pattern; the timestamp is arbitrary but the prefix is the
        // load-bearing detail (filtered as hidden).
        let timestamped = root.join("..2026_05_03_12_34_56.123456789");
        fs::create_dir_all(timestamped.join("auth")).unwrap();
        fs::create_dir_all(timestamped.join("repositories")).unwrap();
        fs::write(timestamped.join("auth/admins.yaml"), "x: 1").unwrap();
        fs::write(timestamped.join("repositories/npm.yaml"), "x: 2").unwrap();

        // K8s creates `..data` as a symlink to the timestamped dir,
        // then atomically swings it on update. Both names start
        // with `.` so the hidden-prefix filter prunes them.
        symlink(&timestamped, root.join("..data")).unwrap();

        // The operator-visible top-level entries are symlinks into
        // `..data/`. These are what `follow_links(true)` must
        // traverse; `follow_links(false)` skips them as
        // non-file-non-dir.
        symlink(root.join("..data/auth"), root.join("auth")).unwrap();
        symlink(root.join("..data/repositories"), root.join("repositories")).unwrap();

        let files = collect_yaml_files(root).unwrap();
        let names: Vec<&str> = files
            .iter()
            .filter_map(|(p, _)| p.file_name())
            .map(|n| n.to_str().unwrap())
            .collect();
        // Both files reachable through the visible symlinks; the
        // hidden ..data / ..<timestamp> traversal is suppressed by
        // the filter so files are not collected twice.
        assert_eq!(
            files.len(),
            2,
            "expected 2 files (one via each visible symlink), got {names:?}"
        );
        assert!(names.contains(&"admins.yaml"), "got: {names:?}");
        assert!(names.contains(&"npm.yaml"), "got: {names:?}");

        // The collected paths reflect the operator's mental model
        // (path-via-symlink, not the resolved `..data/` path) — this
        // is what `entry.path()` returns under `follow_links(true)`,
        // and what surfaces in tracing / error messages.
        for (path, _) in &files {
            let s = path.to_string_lossy();
            assert!(
                !s.contains("..data"),
                "file path leaked the K8s projection-internal name: {s}"
            );
            assert!(
                !s.contains("..2026_05_03"),
                "file path leaked the K8s timestamped-dir name: {s}"
            );
        }
    }

    /// Boot-path wiring: a production
    /// bundle directory containing a `kind: PermissionGrantLintConfig`
    /// file is carried, by the **exact two steps `apply_inner` runs
    /// before `ApplyConfigUseCase::apply`** (`collect_yaml_files` then
    /// `DesiredState::parse_files`), into `desired.lint_config` — the
    /// input `ApplyConfigUseCase::resolve_effective_lint_config`
    /// consumes. This proves the operator's gitops kind reaches the
    /// resolver seam end-to-end on the real boot path; the resolver's
    /// own behaviour (same-bundle ordering, absent-kind default,
    /// downgrade-applied, the >1/invalid + info paths) is covered by
    /// the `hort-app` `apply_config_use_case` tests. Together they
    /// guard against a "documented opt-out is unreachable" defect, with
    /// no DB
    /// dependency. A full apply against a live DB additionally lands in
    /// the E2E smoke (test-gitops.sh).
    #[test]
    fn boot_parse_path_carries_permission_grant_lint_config_into_desired() {
        let dir = TempDir::new().unwrap();
        let lint_yaml = "\
apiVersion: project-hort.de/v1beta1
kind: PermissionGrantLintConfig
metadata:
  name: rbac-lint
spec:
  singleClaimAllowlist: [team-alpha]
";
        write(dir.path(), "auth/lint.yaml", lint_yaml);
        // The two steps `apply_inner` runs before `apply` — verbatim.
        let files = collect_yaml_files(dir.path()).unwrap();
        let desired = DesiredState::parse_files(files).expect("bundle must parse");

        let env = desired
            .lint_config
            .as_ref()
            .expect("the PermissionGrantLintConfig kind must be absorbed by the boot parse path");
        assert_eq!(env.metadata.name, "rbac-lint");
        assert_eq!(env.spec.single_claim_allowlist, vec!["team-alpha"]);
        // Singleton bookkeeping the resolver's >1 guard reads.
        assert_eq!(desired.lint_config_sources.len(), 1);
    }

    /// Composition note: `composition.rs` does NOT
    /// construct or run `ApplyConfigUseCase::apply` (only this
    /// `gitops_boot` path does), so no `composition.rs` wiring is
    /// required — the boot path's `apply_uc.apply(desired, …)` already
    /// threads `desired.lint_config` into the resolver. A bundle with
    /// NO lint-config kind parses to `lint_config: None`, which the
    /// resolver maps to the secure composition-root default
    /// (a missing kind is not a downgrade).
    #[test]
    fn boot_parse_path_absent_lint_config_kind_is_none() {
        let dir = TempDir::new().unwrap();
        let repo_yaml = "\
apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: npm-public
spec:
  name: npm-public
  format: npm
  type: hosted
  isPublic: true
  replicationPriority: immediate
  storage:
    backend: filesystem
    path: /data/npm
";
        write(dir.path(), "repositories/npm.yaml", repo_yaml);
        let files = collect_yaml_files(dir.path()).unwrap();
        let desired = DesiredState::parse_files(files).expect("bundle must parse");
        assert!(
            desired.lint_config.is_none(),
            "no PermissionGrantLintConfig kind ⇒ None ⇒ resolver yields the secure default"
        );
        assert!(desired.lint_config_sources.is_empty());
    }

    // The `apply_config_from_dir` integration test path requires a
    // real PgPool, which lives behind the existing `postgres-tests`
    // gating in adapter integration suites. The unit-level coverage
    // above pins the directory-walk + parse-into-`desired` semantics
    // (the boot-path wiring this item introduces); full apply against
    // a live DB lands in the E2E smoke (test-gitops.sh).

    // ---- `is_park_eligible` per-variant ---------------------------------
    //
    // The park boundary is THE safety-critical invariant: park ONLY on
    // provably-pre-write failures (`Parse | Read | Walk |
    // PreflightValidate`); `Validate | Apply` MUST still crash because
    // `ApplyConfigUseCase` has no rollback and its safety rests on "boot
    // exits non-zero on a half-applied state". `PreflightValidate` is the
    // pre-write validation/lint pass that `apply_inner` runs (via
    // `preflight_validate`) before the first write, so it parks; `Validate`
    // is the in-stage (mid-write) validation that survives into `apply()`'s
    // stages, so it still crashes.

    /// Construct a representative `Walk` variant. `walkdir::Error` has no
    /// public constructor, so we provoke a real one by walking a path
    /// that does not exist (the iterator yields an `Err` for the missing
    /// root). `#[from] walkdir::Error` makes `collect_yaml_files` surface
    /// it as `GitopsBootError::Walk`.
    fn walk_error() -> GitopsBootError {
        let missing = Path::new("/nonexistent/hort-gitops-test-path-xyz");
        collect_yaml_files(missing).expect_err("walking a missing path must error")
    }

    #[test]
    fn is_park_eligible_parses_read_walk_are_pre_write() {
        assert!(
            is_park_eligible(&GitopsBootError::Parse("bad yaml".into())),
            "Parse fails before any DB write — must park"
        );
        assert!(
            is_park_eligible(&GitopsBootError::Read {
                path: PathBuf::from("/etc/hort/x.yaml"),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            }),
            "Read fails during the directory walk, before any DB write — must park"
        );
        let walk = walk_error();
        assert!(
            matches!(walk, GitopsBootError::Walk(_)),
            "expected a Walk variant, got {walk:?}"
        );
        assert!(
            is_park_eligible(&walk),
            "Walk fails during the directory walk, before any DB write — must park"
        );
    }

    #[test]
    fn is_park_eligible_preflight_validate_parks() {
        // A pre-write validation/lint failure surfaced by `preflight_validate`
        // (before `apply()`/the first `save_managed`) is provably pre-write,
        // so it parks not-ready rather than crashlooping.
        assert!(
            is_park_eligible(&GitopsBootError::PreflightValidate(
                "scanBackends `bogus` not registered".into()
            )),
            "PreflightValidate fires before any DB write — must park"
        );
    }

    #[test]
    fn is_park_eligible_validate_and_apply_must_crash() {
        assert!(
            !is_park_eligible(&GitopsBootError::Validate(
                "in-stage predicate resolve".into()
            )),
            "in-stage Validate can fire after a stage-1 write — must crash (no rollback)"
        );
        assert!(
            !is_park_eligible(&GitopsBootError::Apply("mid-flight".into())),
            "Apply is mid-write-capable — must crash (no rollback)"
        );
    }
}
