use super::*;

impl ApplyConfigUseCase {
    /// Apply `OidcIssuer` create / update / delete from the gitops
    /// plan. Per-row event emission lands on the
    /// [`StreamCategory::Authorization`] stream alongside the other
    /// apply-time authz mutations.
    pub(super) async fn apply_oidc_issuers(
        &self,
        plan: &KindPlan<OidcIssuerSpec, String>,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let mut events: Vec<EventToAppend> = Vec::new();
        let now = Utc::now();

        for env in &plan.create {
            let id = self
                .oidc_issuers
                .get_by_name(&env.metadata.name)
                .await?
                .map(|i| i.id)
                .unwrap_or_else(Uuid::new_v4);
            let issuer = build_oidc_issuer_from_spec(env, id)?;
            self.oidc_issuers.upsert(&issuer).await?;
            // Best-effort
            // JWKS warm-up. MUST NOT fail the apply on error; federation
            // works lazily via the cache-miss path on first request.
            self.warm_up_oidc_jwks(&issuer).await;
            events.push(EventToAppend::new(DomainEvent::OidcIssuerCreated(
                OidcIssuerCreated {
                    issuer_id: id,
                    name: env.metadata.name.clone(),
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::OIDC_ISSUER, GitopsObjectResult::Created);
            report.created += 1;
        }
        for env in &plan.update {
            let existing = self
                .oidc_issuers
                .get_by_name(&env.metadata.name)
                .await?
                .ok_or_else(|| {
                    DomainError::Invariant(format!(
                        "OidcIssuer `{}` scheduled for update but not present in snapshot",
                        env.metadata.name
                    ))
                })?;
            let issuer = build_oidc_issuer_from_spec(env, existing.id)?;
            self.oidc_issuers.upsert(&issuer).await?;
            // Best-effort
            // JWKS warm-up on update too (jwks_uri or audiences may have
            // shifted; populate the cache so the next federation
            // request sees the post-update key set without an inline
            // fetch tax). MUST NOT fail the apply on error.
            self.warm_up_oidc_jwks(&issuer).await;
            events.push(EventToAppend::new(DomainEvent::OidcIssuerUpdated(
                OidcIssuerUpdated {
                    issuer_id: existing.id,
                    name: env.metadata.name.clone(),
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::OIDC_ISSUER, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        for name in &plan.delete {
            // Resolve the row's id for the audit-event payload BEFORE
            // the DELETE — once the row is gone we can't recover it.
            let prior_id = self
                .oidc_issuers
                .get_by_name(name)
                .await?
                .map(|i| i.id)
                .unwrap_or_else(Uuid::new_v4);
            self.oidc_issuers.delete_by_name(name).await?;
            events.push(EventToAppend::new(DomainEvent::OidcIssuerDeleted(
                OidcIssuerDeleted {
                    issuer_id: prior_id,
                    name: name.clone(),
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::OIDC_ISSUER, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        if !events.is_empty() {
            tracing::info!(
                kind = gitops_kind::OIDC_ISSUER,
                events = events.len(),
                "oidc_issuer audit events committed"
            );
            let actor = gitops_actor_for_kind(Kind::OidcIssuer);
            self.events
                .append(AppendEvents {
                    stream_id: StreamId::authorization(),
                    expected_version: ExpectedVersion::Any,
                    events,
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor,
                })
                .await?;
        }
        Ok(())
    }

    /// Apply-time
    /// JWKS warm-up. Best-effort: on any error, emit `tracing::warn!`
    /// and let the apply proceed. The adapter (`MultiIssuerJwksValidator::
    /// refresh_issuer_impl`) emits `hort_jwks_refresh_total{result=
    /// apply_warmup_failed}` itself via the `RefreshContext::ApplyWarmup`
    /// switch, so this helper only handles the tracing side.
    ///
    /// Federation works lazily even when warm-up fails: the first
    /// `validate()` call against a freshly-applied issuer pays the
    /// discovery + JWKS round-trip cost on demand. The warm-up exists
    /// to surface "the gitops apply pushed a config that the IdP
    /// can't serve" as an operator-visible signal without a real
    /// federation request having to arrive first.
    ///
    /// `None` validator slot (`new()`-only composition, no
    /// `with_federated_jwt_validator`) skips warm-up entirely.
    async fn warm_up_oidc_jwks(&self, issuer: &OidcIssuer) {
        let Some(validator) = self.federated_jwt_validator.as_ref() else {
            return;
        };
        match validator.refresh_issuer(issuer).await {
            Ok(()) => {
                tracing::debug!(
                    issuer_name = %issuer.name,
                    "OidcIssuer JWKS apply-time warm-up populated cache"
                );
            }
            Err(reason) => {
                // Operator-feedback-only: the apply is NOT failed.
                // Federation will fetch lazily on first request. The
                // metric is emitted by the adapter's
                // `RefreshContext::ApplyWarmup` failure paths
                // (`hort_jwks_refresh_total{result=apply_warmup_failed}`).
                tracing::warn!(
                    issuer_name = %issuer.name,
                    reason = reason.as_str(),
                    "OidcIssuer JWKS apply-time warm-up failed — \
                     federation will fetch lazily on first use"
                );
            }
        }
    }
}

/// Build an `OidcIssuer` from a validated spec envelope.
/// The `validate_oidc_issuer` pass has already gated the
/// algorithm strings, so every `JwtAlg::from_str` is expected to
/// succeed — a failure here is an `Invariant` because it means the
/// validator was bypassed.
fn build_oidc_issuer_from_spec(env: &Envelope<OidcIssuerSpec>, id: Uuid) -> AppResult<OidcIssuer> {
    debug_assert!(matches!(env.kind, Kind::OidcIssuer));
    let spec = &env.spec;
    let jwks_refresh_interval =
        humantime::parse_duration(&spec.jwks_refresh_interval).map_err(|e| {
            DomainError::Invariant(format!(
                "OidcIssuer `{}`: jwksRefreshInterval validation passed but parse failed: {e}",
                env.metadata.name
            ))
        })?;
    let allowed_algorithms: Vec<JwtAlg> = spec
        .allowed_algorithms
        .iter()
        .map(|s| {
            JwtAlg::from_str(s).map_err(|e| {
                DomainError::Invariant(format!(
                    "OidcIssuer `{}`: allowedAlgorithms `{s}` validation passed but parse failed: {e}",
                    env.metadata.name
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(OidcIssuer {
        id,
        name: env.metadata.name.clone(),
        issuer_url: spec.issuer_url.clone(),
        audiences: spec.audiences.clone(),
        jwks_refresh_interval,
        allowed_algorithms,
        // Threaded verbatim from the
        // spec. `#[serde(default)]` already resolved a missing
        // `requireJti:` to `true` (the silent-apply tightening).
        require_jti: spec.require_jti,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::apply_config_use_case::tests::*;

    // -- OidcIssuer apply --------------------------------------------------

    #[tokio::test]
    async fn apply_oidc_issuer_creates_new_row_and_emits_event() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 1, "exactly one row created");
        let stored = h.oidc_issuers.snapshot();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].name, "github-actions");
        assert_eq!(stored[0].issuer_url, "https://github-actions.example.com");
    }

    #[tokio::test]
    async fn apply_oidc_issuer_is_idempotent_on_reapply() {
        let h = build_harness();
        let env = oidc_issuer_env_for_apply("github-actions");
        let mut desired_a = DesiredState::default();
        desired_a.oidc_issuers.push(env.clone());
        h.uc.apply(desired_a, env_oidc()).await.unwrap();
        // First apply created the issuer. Snapshot's digest is `None`,
        // so the diff currently classifies the second apply as
        // `update` rather than `unchanged` — but the post-apply row
        // count must still be exactly 1.
        let mut desired_b = DesiredState::default();
        desired_b.oidc_issuers.push(env);
        h.uc.apply(desired_b, env_oidc()).await.unwrap();
        assert_eq!(h.oidc_issuers.snapshot().len(), 1);
    }

    #[tokio::test]
    async fn apply_oidc_issuer_delete_removes_row() {
        let h = build_harness();
        let env = oidc_issuer_env_for_apply("github-actions");
        let mut desired = DesiredState::default();
        desired.oidc_issuers.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(h.oidc_issuers.snapshot().len(), 1);
        // Re-apply with no issuers — the row is scheduled for delete.
        let empty = DesiredState::default();
        let report = h.uc.apply(empty, env_oidc()).await.unwrap();
        assert_eq!(report.deleted, 1);
        assert!(h.oidc_issuers.snapshot().is_empty());
    }

    // -- apply-time JWKS warm-up tests ---------------------------------------

    /// Helper: rebuild the apply use case from a base harness with a
    /// `MockFederatedJwtValidator` attached. Returns the
    /// already-shared mock so tests can seed `register_refresh_outcome`
    /// and assert on `refresh_calls`.
    fn install_validator(
        h: &Harness,
    ) -> (
        ApplyConfigUseCase,
        Arc<crate::use_cases::test_support::MockFederatedJwtValidator>,
    ) {
        let validator = Arc::new(crate::use_cases::test_support::MockFederatedJwtValidator::new());
        let policies = Arc::new(PolicyUseCase::new(
            crate::event_store_publisher::wrap_for_test(h.events.clone()),
            h.proj.clone(),
            h.artifacts.clone(),
            h.lifecycle.clone(),
            Arc::new(crate::use_cases::test_support::MockStoragePort::new()),
            default_repository_access_for_policy(),
            Arc::new(crate::use_cases::test_support::MockCurationRuleRepository::new()),
            Arc::new(crate::use_cases::test_support::MockJobsRepository::default()),
        ));
        let uc = ApplyConfigUseCase::new(
            h.repos.clone(),
            h.claim_mappings.clone(),
            h.grant_repo.clone(),
            h.rule_repo.clone(),
            h.proj.clone(),
            policies,
            h.artifacts.clone(),
            h.lifecycle.clone(),
            crate::event_store_publisher::wrap_for_test(h.events.clone()),
            h.upstream.clone(),
            UpstreamHostAllowlist::Disabled,
            h.content_refs.clone(),
            h.oidc_issuers.clone(),
            h.service_accounts.clone(),
            h.users.clone(),
        )
        // Permissive linter (see `build_harness`) —
        // the OIDC warm-up tests apply only `oidc_issuers` envelopes,
        // but pinning permissive keeps parity with `build_harness`
        // (the harness this is derived from) so a future grant added
        // to one of these tests is not silently rejected.
        .with_lint_config(crate::lint::LintConfig::permissive_for_tests())
        .with_federated_jwt_validator(validator.clone() as Arc<dyn FederatedJwtValidator>);
        (uc, validator)
    }

    /// M2 invariant 1 — when warm-up succeeds, the apply succeeds and
    /// the row is created. Validator was invoked exactly once with the
    /// expected issuer name.
    #[tokio::test]
    async fn apply_oidc_issuer_warm_up_success_does_not_fail_apply() {
        let h = build_harness();
        let (uc, validator) = install_validator(&h);
        validator.register_refresh_outcome("github-actions", Ok(()));

        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));

        let report = uc
            .apply(desired, env_oidc())
            .await
            .expect("apply must succeed on warm-up success");
        assert_eq!(report.created, 1, "row was created");
        assert_eq!(h.oidc_issuers.snapshot().len(), 1, "row persists");
        // Warm-up fired exactly once with the right name.
        assert_eq!(
            validator.refresh_calls(),
            vec!["github-actions".to_string()],
            "refresh_issuer must be invoked once with the persisted issuer's name"
        );
    }

    /// M2 invariant 2 (load-bearing) — when warm-up FAILS, the apply
    /// STILL SUCCEEDS. Federation works lazily on first request; warm-up
    /// is operator-feedback-only.
    #[tokio::test]
    async fn apply_oidc_issuer_warm_up_failure_does_not_fail_apply() {
        let h = build_harness();
        let (uc, validator) = install_validator(&h);
        validator.register_refresh_outcome(
            "github-actions",
            Err(hort_domain::ports::federated_jwt_validator::FederationDenyReason::UnknownKid),
        );

        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));

        // CRITICAL: apply must succeed even though warm-up failed.
        let report = uc
            .apply(desired, env_oidc())
            .await
            .expect("warm-up failure MUST NOT fail the apply (M2 invariant)");
        assert_eq!(report.created, 1, "row was created despite warm-up failure");
        assert_eq!(
            h.oidc_issuers.snapshot().len(),
            1,
            "row persists in repo despite warm-up failure"
        );
        // Warm-up was attempted (the failure is visible via `tracing::warn!`,
        // not via apply failure).
        assert_eq!(
            validator.refresh_calls(),
            vec!["github-actions".to_string()],
            "refresh_issuer must still be invoked even when failing"
        );
    }

    /// M2 — warm-up is invoked on the update path too (jwks_uri or
    /// audiences may have shifted; populate the cache so the next
    /// federation request sees the post-update key set without an
    /// inline fetch tax).
    #[tokio::test]
    async fn apply_oidc_issuer_warm_up_fires_on_update() {
        let h = build_harness();
        // First apply creates the row (use the harness's
        // no-validator path, since we want to test the second apply's
        // update arm).
        let mut desired_a = DesiredState::default();
        desired_a
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));
        h.uc.apply(desired_a, env_oidc()).await.unwrap();
        assert_eq!(h.oidc_issuers.snapshot().len(), 1);

        // Second apply uses a new harness-shaped UC with the validator
        // installed. The diff classifies as `update` (snapshot digest
        // is `None` so even an identical envelope goes through update).
        let (uc, validator) = install_validator(&h);
        validator.register_refresh_outcome("github-actions", Ok(()));
        let mut desired_b = DesiredState::default();
        desired_b
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));
        uc.apply(desired_b, env_oidc())
            .await
            .expect("update apply must succeed");

        assert_eq!(
            validator.refresh_calls(),
            vec!["github-actions".to_string()],
            "refresh_issuer must fire on the update path too"
        );
    }

    /// When no validator is wired (None slot), warm-up is skipped
    /// silently and the apply still succeeds. This is the default
    /// posture for every validator-less test harness; this test guards
    /// the slot.
    #[tokio::test]
    async fn apply_oidc_issuer_without_validator_skips_warm_up_silently() {
        let h = build_harness();
        // `build_harness` uses `ApplyConfigUseCase::new` only — no
        // `with_federated_jwt_validator` call.
        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));

        let report =
            h.uc.apply(desired, env_oidc())
                .await
                .expect("apply must succeed with no validator wired");
        assert_eq!(report.created, 1);
    }
}
