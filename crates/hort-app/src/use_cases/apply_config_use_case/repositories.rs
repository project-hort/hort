use super::*;

impl ApplyConfigUseCase {
    pub(super) async fn apply_repository_rows(
        &self,
        plan: &KindPlan<RepositorySpec, Uuid>,
        desired: &DesiredState,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        for env in plan.create.iter().chain(plan.update.iter()) {
            let digest = spec_digest_repository(&env.spec);
            let id = self.resolve_repo_id(&env.metadata.name).await?;
            let repo = build_repository_from_spec(env, id, self.effective_storage_backend)?;
            self.repositories.save_managed(&repo, &digest).await?;
        }
        for _ in &plan.create {
            emit_gitops_object(gitops_kind::REPOSITORY, GitopsObjectResult::Created);
            report.created += 1;
        }
        for _ in &plan.update {
            emit_gitops_object(gitops_kind::REPOSITORY, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        for id in &plan.delete {
            self.repositories.delete_managed(*id).await?;
            emit_gitops_object(gitops_kind::REPOSITORY, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        // Junction-edge writes for every
        // declared repository whose spec carries `curation_rules`.
        // Always-write rather than digest-tracked-edges: the per-edge
        // spec digest doesn't include the resolved-rule ids (it's a
        // list of rule names), and `set_curation_rules_for_repository`
        // is idempotent. Cleared (empty Vec) reaches us identically to
        // a populated Vec — the operator removed every name and the
        // junction now empties.
        for env in &desired.repositories {
            let rule_names = env.spec.curation_rules.as_deref().unwrap_or(&[]);
            // Resolve repo id from the post-stage-1+repo-row state.
            let repo = self.repositories.find_by_key(&env.metadata.name).await?;
            // Resolve rule names → ids via find_by_name on the freshly-
            // applied rules. Validation in `validate_against` already
            // confirmed every name is a declared CurationRule, so the
            // `None` branch here would only fire on a port-layer
            // inconsistency — surface as Invariant.
            let mut rule_ids = Vec::with_capacity(rule_names.len());
            for name in rule_names {
                let rule = self
                    .curation_rules
                    .find_by_name(name)
                    .await?
                    .ok_or_else(|| {
                        DomainError::Invariant(format!(
                            "repository '{}' references curation rule '{name}' that vanished \
                             between stage 1 apply and stage 2 junction write",
                            env.metadata.name
                        ))
                    })?;
                rule_ids.push(rule.id);
            }
            self.curation_rules
                .set_curation_rules_for_repository(repo.id, &rule_ids)
                .await?;
        }
        Ok(())
    }
}

/// Build a `Repository` from a `RepositorySpec` envelope. Inlines the
/// validator from `RepositoryUseCase::create` (the upstream-url
/// requirement on `Proxy` repos): the public use case rejects every
/// gitops-managed write, so the apply pipeline must NOT route through
/// it. Five lines of duplication beats a shared validator module that
/// exists for one extra caller.
fn build_repository_from_spec(
    env: &Envelope<RepositorySpec>,
    id: Uuid,
    effective_backend: Option<crate::storage_backend::EffectiveStorageBackend>,
) -> AppResult<Repository> {
    debug_assert!(matches!(env.kind, Kind::ArtifactRepository));
    let spec = &env.spec;

    // RepositoryFormat::FromStr::Err is Infallible — unknown names map
    // to RepositoryFormat::Other(_), they don't fail. Unwrap is exact;
    // unwrap_or would express uncertainty that doesn't exist. The
    // unknown-format guard runs in `validate_repository` before apply.
    let format: RepositoryFormat = spec.format.parse().unwrap();
    let repo_type = RepositoryType::from_str(&spec.repo_type)?;
    let replication_priority = ReplicationPriority::from_str(&spec.replication_priority)?;
    let upstream_url = spec.proxy.as_ref().map(|p| p.upstream_url.clone());
    // Typed `index_upstream_url` override for split-
    // host registries (currently consulted only by the Cargo handler).
    // Cross-spec validation in `hort-config::validate_repository` rejects
    // `Some(_)` when format != cargo or repo_type != proxy, so by the
    // time the apply pipeline reaches this converter the surface is
    // narrow.
    let index_upstream_url = spec
        .proxy
        .as_ref()
        .and_then(|p| p.index_upstream_url.clone());

    if matches!(repo_type, RepositoryType::Proxy) && upstream_url.is_none() {
        return Err(
            DomainError::Validation("proxy repository must have an upstream URL".into()).into(),
        );
    }

    // `spec.storage` is optional. Omitting
    // it is the documented honest path — inherit the deployment's
    // effective global backend (per-repo storage is not
    // routing-effective in v2; see the `StorageSpec` honesty note). The
    // `storage_*` columns are NOT NULL with no usable default, so the
    // omitted case is resolved to concrete, internally-consistent
    // values here (never NULL, never a magic free-string sentinel —
    // that was the original footgun): the effective global backend if the
    // composition wired one, else `"filesystem"` (the DB column default
    // and the domain default — the least-surprising fallback when the
    // cross-check is unwired); the placement-inert `storage_path`
    // becomes the repo key (stable across re-apply, NOT NULL, honest —
    // no fabricated filesystem prefix). When the operator *did* supply
    // a block, it is used verbatim (the apply-time mismatch reject runs
    // separately in `reject_repo_storage_backend_mismatch`).
    let (storage_backend, storage_path) = match spec.storage.as_ref() {
        Some(s) => (s.backend.clone(), s.path.clone()),
        None => {
            let backend = effective_backend
                .map(|e| e.as_spec_str().to_string())
                .unwrap_or_else(|| "filesystem".to_string());
            (backend, env.metadata.name.clone())
        }
    };

    let now = Utc::now();
    Ok(Repository {
        id,
        key: env.metadata.name.clone(),
        name: spec.name.clone(),
        description: spec.description.clone(),
        format,
        repo_type,
        storage_backend,
        storage_path,
        upstream_url,
        index_upstream_url,
        is_public: spec.is_public,
        // Opt-in per-repo download auditing.
        // Mirrors the `is_public` spec→domain plumbing exactly;
        // `#[serde(default)]` on the spec field makes absence == false
        // (non-breaking for existing gitops configs).
        download_audit_enabled: spec.download_audit_enabled,
        quota_bytes: spec.quota_bytes,
        replication_priority,
        promotion: spec.promotion.clone(),
        // The spec carries a list of `CurationRule`
        // names (from `spec.curationRules`). The apply pipeline writes
        // them through `set_curation_rules_for_repository` after the
        // repository row itself; this in-memory carrier just preserves
        // the list for downstream callers that may inspect the
        // `Repository` value.
        curation_rule_names: spec.curation_rules.clone().unwrap_or_default(),
        // The optional `indexMode` gitops field
        // (`#[serde(default)]`) lands here verbatim. Absent ⇒
        // `IndexMode::ReleasedOnly` via the enum's `Default` impl —
        // the build-safe posture, matching the migration column
        // default and the mapper's defensive fallback.
        index_mode: spec.index_mode,
        // The optional `prefetchPolicy` gitops field
        // (`#[serde(default)]`) lands here verbatim. Absent ⇒
        // `PrefetchPolicy::default()` (disabled, no triggers, default
        // depths) — matches the migration column defaults
        // (`prefetch_enabled = false`, `prefetch_triggers = NULL`) and
        // the mapper's defensive fallback. The prefetch pipeline is the
        // consumer; this converter only threads the typed value.
        prefetch_policy: spec.prefetch_policy.clone(),
        created_at: now,
        updated_at: now,
        managed_by: ManagedBy::GitOps,
        managed_by_digest: None, // save_managed sets this
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::apply_config_use_case::tests::*;
    use hort_domain::entities::repository::IndexMode;

    /// Gitops YAML carrying
    /// `proxy.indexUpstreamUrl` lands the override on the persisted
    /// `Repository` row. Exercises the converter at
    /// `build_repository_from_spec`: the field is read off
    /// `spec.proxy.index_upstream_url` and copied onto
    /// `Repository.index_upstream_url`. End-to-end through the apply
    /// pipeline so any future refactor of the converter that drops
    /// the field gets caught.
    #[tokio::test]
    async fn apply_propagates_proxy_index_upstream_url_onto_repository() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let mut env = repo_env("cargo-proxy", "proxy");
        env.spec.format = "cargo".into();
        let proxy = env.spec.proxy.as_mut().expect("proxy block");
        proxy.upstream_url = "https://crates.io".into();
        proxy.index_upstream_url = Some("https://internal-index.example.com".into());

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        // Reach the persisted repo through the trait surface — the
        // mock stores the row inside `save_managed`, so `find_by_key`
        // must surface the propagated field.
        let stored = h.repos.find_by_key("cargo-proxy").await.unwrap();
        assert_eq!(
            stored.index_upstream_url.as_deref(),
            Some("https://internal-index.example.com"),
            "apply pipeline must propagate proxy.indexUpstreamUrl onto Repository.index_upstream_url"
        );
    }

    // -- gitops apply propagates `indexMode` ---------------------------------

    /// A gitops `ArtifactRepository` envelope carrying
    /// `indexMode: include_pending` lands the typed `IndexMode` on
    /// the persisted `Repository` row. Mirror of the
    /// `index_upstream_url` propagation test: exercises the converter
    /// at `build_repository_from_spec` end-to-end through the apply
    /// pipeline so any future refactor that drops the field gets caught.
    #[tokio::test]
    async fn apply_propagates_index_mode_include_pending_onto_repository() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let mut env = repo_env("npm-filter", "proxy");
        env.spec.index_mode = IndexMode::IncludePending;

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let stored = h.repos.find_by_key("npm-filter").await.unwrap();
        assert_eq!(
            stored.index_mode,
            IndexMode::IncludePending,
            "apply pipeline must propagate spec.indexMode onto Repository.index_mode"
        );
    }

    // -- gitops apply propagates `prefetchPolicy` ----------------------------

    /// A gitops `ArtifactRepository` envelope
    /// carrying a populated `prefetchPolicy` block lands the typed
    /// `PrefetchPolicy` on the persisted `Repository` row. Mirror of
    /// the `index_mode` propagation test: exercises the converter at
    /// `build_repository_from_spec` end-to-end through the apply
    /// pipeline so any future refactor that drops the field gets
    /// caught.
    #[tokio::test]
    async fn apply_propagates_populated_prefetch_policy_onto_repository() {
        use hort_domain::entities::repository::{PrefetchPolicy, PrefetchTrigger};
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let mut env = repo_env("npm-prefetch", "proxy");
        let policy = PrefetchPolicy {
            enabled: true,
            triggers: vec![PrefetchTrigger::OnDistTagMove, PrefetchTrigger::Scheduled],
            depth: 11,
            transitive_depth: 6,
            // `max_age_days` is rejected at
            // apply by `validate_prefetch_max_age_days_not_implemented`
            // until the per-version timestamp surface lands
            // (ADR 0015). Set to `None` here so the
            // round-trip-other-fields coverage stays meaningful; the
            // reject path is exercised by
            // `apply_rejects_prefetch_policy_with_max_age_days_set`.
            max_age_days: None,
            // Non-default sentinel so the
            // apply-pipeline round-trip of the knob is pinned.
            max_descendants: 500,
        };
        env.spec.prefetch_policy = policy.clone();

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let stored = h.repos.find_by_key("npm-prefetch").await.unwrap();
        assert_eq!(
            stored.prefetch_policy, policy,
            "apply pipeline must propagate spec.prefetchPolicy onto Repository.prefetch_policy"
        );
    }

    /// Negative half: a repo declared YAML-side with
    /// no `prefetchPolicy` field lands `PrefetchPolicy::default()` (the
    /// `#[serde(default)]`). Locks down the disabled-by-default posture
    /// so a future refactor that wires a stray override cannot silently
    /// turn every existing repo into a mirror.
    #[tokio::test]
    async fn apply_defaults_prefetch_policy_to_disabled_when_absent() {
        use hort_domain::entities::repository::PrefetchPolicy;
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        // `repo_env` builds the spec with `PrefetchPolicy::default()` —
        // the same shape as an omitted-field gitops YAML after serde's
        // default.
        let env = repo_env("npm-prefetch-default", "proxy");

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let stored = h.repos.find_by_key("npm-prefetch-default").await.unwrap();
        assert_eq!(stored.prefetch_policy, PrefetchPolicy::default());
        assert!(!stored.prefetch_policy.enabled);
        assert!(stored.prefetch_policy.triggers.is_empty());
    }

    /// Negative half: a repo declared YAML-side with
    /// no `indexMode` field lands `IndexMode::ReleasedOnly` (the
    /// `#[serde(default)]`). Locks down the default so a future
    /// refactor that wires a stray override does not silently flip the
    /// build-safe posture for every existing repo.
    #[tokio::test]
    async fn apply_defaults_index_mode_to_released_only_when_absent() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        // `repo_env` builds the spec with `IndexMode::default()` (i.e.
        // `ReleasedOnly`) — the same shape as an omitted-field gitops
        // YAML after serde's default.
        let env = repo_env("npm-default", "proxy");

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let stored = h.repos.find_by_key("npm-default").await.unwrap();
        assert_eq!(stored.index_mode, IndexMode::ReleasedOnly);
    }

    /// Negative half of the propagation test: a cargo proxy with no
    /// override declared YAML-side stores `None`. Locks down the
    /// default so a future refactor that wires a stray default doesn't
    /// silently turn the override on for every cargo proxy.
    #[tokio::test]
    async fn apply_leaves_index_upstream_url_none_when_unset() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let mut env = repo_env("cargo-proxy-default", "proxy");
        env.spec.format = "cargo".into();
        let proxy = env.spec.proxy.as_mut().expect("proxy block");
        proxy.upstream_url = "https://crates.io".into();
        // index_upstream_url left at its serde default (None).

        let mut desired = DesiredState::default();
        desired.repositories.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let stored = h.repos.find_by_key("cargo-proxy-default").await.unwrap();
        assert!(stored.index_upstream_url.is_none());
    }

    // ===================================================================
    // Apply-time per-repo-vs-effective-global storage-backend reject.
    //
    // `EffectiveStorageBackend` is the *true* `{filesystem, s3}`
    // deployment fact (never the coarse `StoragePort::backend_label()`
    // `{filesystem, object_store}` — that would fail-*wrong*). The
    // builder seam mirrors `with_lint_config` / `with_retention`:
    // `new()` is byte-unchanged, the field defaults to `None`, and
    // `None` ⇒ the cross-check is skipped (so every pre-existing test
    // harness — which never calls the builder — keeps passing
    // unchanged; `build_harness()` is the witness).
    // ===================================================================

    /// `Some(eff)` + a per-repo `storage.backend` differing from the
    /// effective global backend ⇒ the whole apply is rejected with the
    /// canonical operator wording, extended to name the effective
    /// global backend. Fail-closed and loud.
    ///
    /// New-branch coverage: `Some(eff)` taken + `repo.storage.backend
    /// != eff.as_spec_str()` true ⇒ reject (the `s3`-spec-on-
    /// `Filesystem`-deployment direction; exercises
    /// `EffectiveStorageBackend::Filesystem.as_spec_str()`).
    #[tokio::test]
    async fn apply_rejects_per_repo_backend_mismatching_effective_global() {
        let h = build_harness();
        let mut env = repo_env("s3-on-fs-deploy", "hosted");
        // The deployment is filesystem; the operator wrote s3.
        env.spec.storage.as_mut().unwrap().backend = "s3".into();

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        let uc = h.uc.with_effective_storage_backend(
            crate::storage_backend::EffectiveStorageBackend::Filesystem,
        );
        let err = uc.apply(desired, env_oidc()).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("per-repository storage")
                && msg.contains("s3")
                && msg.contains("filesystem"),
            "reject must reuse the canonical wording and name BOTH \
             the offending per-repo value and the effective global \
             backend; got: {msg}"
        );
    }

    /// The other enum arm / spec-string direction: an `s3` deployment
    /// with a per-repo `backend: filesystem` is equally rejected.
    /// Exercises `EffectiveStorageBackend::S3.as_spec_str()` in the
    /// reject path.
    #[tokio::test]
    async fn apply_rejects_filesystem_repo_on_s3_deployment() {
        let h = build_harness();
        let env = repo_env("fs-on-s3-deploy", "hosted"); // repo_env defaults backend=filesystem

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        let uc = h
            .uc
            .with_effective_storage_backend(crate::storage_backend::EffectiveStorageBackend::S3);
        let err = uc.apply(desired, env_oidc()).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("per-repository storage")
                && msg.contains("filesystem")
                && msg.contains("s3"),
            "s3-deployment + per-repo filesystem must reject and name \
             both; got: {msg}"
        );
    }

    /// `Some(eff)` + a per-repo `storage.backend` *matching* the
    /// effective global backend ⇒ the cross-check passes; the apply
    /// proceeds normally and the row lands. New-branch coverage:
    /// `Some(eff)` taken + the `!=` guard false ⇒ no reject.
    #[tokio::test]
    async fn apply_accepts_per_repo_backend_matching_effective_global() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let env = repo_env("fs-on-fs-deploy", "hosted"); // backend=filesystem

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        let uc = h.uc.with_effective_storage_backend(
            crate::storage_backend::EffectiveStorageBackend::Filesystem,
        );
        uc.apply(desired, env_oidc())
            .await
            .expect("matching backend must apply cleanly");

        let stored = h.repos.find_by_key("fs-on-fs-deploy").await.unwrap();
        assert_eq!(stored.storage_backend, "filesystem");
    }

    /// `None` (the default — the builder never called) ⇒ the
    /// cross-check is skipped entirely; an `s3`-backed repo applies on
    /// a harness that wired no effective backend. This is the witness
    /// that every pre-existing harness (none of which call the
    /// builder) keeps compiling and passing unchanged. New-branch
    /// coverage: `self.effective_storage_backend` is `None` ⇒ the
    /// `if let Some(..)` is not taken.
    #[tokio::test]
    async fn apply_skips_backend_cross_check_when_effective_unset() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness(); // never calls with_effective_storage_backend
        let mut env = repo_env("s3-repo-unchecked", "hosted");
        env.spec.storage.as_mut().unwrap().backend = "s3".into();

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        h.uc.apply(desired, env_oidc())
            .await
            .expect("None effective backend must skip the cross-check");

        let stored = h.repos.find_by_key("s3-repo-unchecked").await.unwrap();
        assert_eq!(stored.storage_backend, "s3");
    }

    // ---- storage-omitted is the honest path -------------------------------

    /// The rc.19 regression, at the apply layer. A repo whose
    /// `storage:` block is omitted applies cleanly **and** the
    /// persisted row inherits the deployment's effective global
    /// backend — the documented honest path the storage validator's
    /// own remedy points at. This config previously could not even parse
    /// (`missing field 'storage'`), so the remedy was unimplementable.
    #[tokio::test]
    async fn storage_omitted_inherits_effective_global_s3() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness();
        let mut env = repo_env("omitted-on-s3", "hosted");
        env.spec.storage = None; // operator omitted the block

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        let uc = h
            .uc
            .with_effective_storage_backend(crate::storage_backend::EffectiveStorageBackend::S3);
        uc.apply(desired, env_oidc())
            .await
            .expect("a storage-omitted repo must apply — not reject, not crash");

        let stored = h.repos.find_by_key("omitted-on-s3").await.unwrap();
        assert_eq!(
            stored.storage_backend, "s3",
            "omitted storage must inherit the effective global backend"
        );
        assert_eq!(
            stored.storage_path, "omitted-on-s3",
            "omitted storage_path resolves to the repo key (NOT NULL, stable, inert)"
        );
    }

    /// Omitted storage with **no** effective backend wired (the
    /// pre-existing-harness shape) falls back to `filesystem` — the DB
    /// column default and domain default — never NULL, never a magic
    /// sentinel.
    #[tokio::test]
    async fn storage_omitted_no_effective_defaults_filesystem() {
        use hort_domain::ports::repository_repository::RepositoryRepository;

        let h = build_harness(); // no with_effective_storage_backend
        let mut env = repo_env("omitted-no-eff", "hosted");
        env.spec.storage = None;

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        h.uc.apply(desired, env_oidc())
            .await
            .expect("omitted storage + no effective backend must apply");

        let stored = h.repos.find_by_key("omitted-no-eff").await.unwrap();
        assert_eq!(stored.storage_backend, "filesystem");
        assert_eq!(stored.storage_path, "omitted-no-eff");
    }

    /// The self-contradiction, pinned closed: omitted storage is the
    /// validator's own suggested remedy, so it must **not** be
    /// rejected by the per-repo-vs-global mismatch check even when an
    /// effective backend is wired (omission inherits by construction —
    /// there is nothing to mismatch).
    #[tokio::test]
    async fn storage_omitted_not_rejected_by_mismatch_check() {
        let h = build_harness();
        let mut env = repo_env("omitted-not-rejected", "hosted");
        env.spec.storage = None;

        let mut desired = DesiredState::default();
        desired.repositories.push(env);

        let uc = h
            .uc
            .with_effective_storage_backend(crate::storage_backend::EffectiveStorageBackend::S3);
        uc.apply(desired, env_oidc()).await.expect(
            "omitted storage is the validator's own remedy — it must inherit, \
             never trip reject_repo_storage_backend_mismatch",
        );
    }

    // ===================================================================
    // Stage 2: Repository + curation-rule junction
    // ===================================================================

    #[tokio::test]
    async fn repository_with_curation_rule_writes_junction_with_resolved_id() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("allow-rust", "allow", "rust*", "trusted"));
        let mut repo = repo_env("rust-public", "hosted");
        repo.spec.curation_rules = Some(vec!["allow-rust".into()]);
        desired.repositories.push(repo);

        h.uc.apply(desired, env_oidc()).await.unwrap();

        let calls = h.rule_repo.junction_calls();
        assert_eq!(
            calls.len(),
            1,
            "expect one set_curation_rules_for_repository call"
        );
        let (_repo_id, rule_ids) = &calls[0];
        assert_eq!(rule_ids.len(), 1);
    }

    #[tokio::test]
    async fn repository_curation_rules_cleared_writes_empty_junction() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("allow-rust", "allow", "rust*", "trusted"));
        let mut repo = repo_env("rust-public", "hosted");
        repo.spec.curation_rules = Some(vec!["allow-rust".into()]);
        desired.repositories.push(repo);
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();

        let junction_count_before = h.rule_repo.junction_calls().len();
        desired.repositories[0].spec.curation_rules = Some(vec![]);
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let after = h.rule_repo.junction_calls();
        assert!(after.len() > junction_count_before);
        let last = after.last().unwrap();
        assert!(
            last.1.is_empty(),
            "expected empty rule_ids, got {:?}",
            last.1
        );
    }
}
