use super::*;

impl ApplyConfigUseCase {
    /// Apply `OidcIssuer` create / update / delete from the gitops
    /// plan. Per-row event emission lands on the
    /// [`StreamCategory::Authorization`] stream alongside the other
    /// apply-time authz mutations.
    ///
    /// **Rows and events commit together.** The branch builds the whole
    /// [`OidcIssuerChange`] plus its audit batch from the plan, then
    /// hands both to
    /// [`AuthorityLifecyclePort::commit_oidc_issuers`], which writes
    /// them in one transaction. An issuer row is a trust anchor
    /// (ADR 0018) — a serving validator reads the repository at
    /// validation time, so a surviving replica acts on the new trust
    /// state the moment the row commits. Before the port, each
    /// `upsert` / `delete_by_name` was an independently committed
    /// statement and the audit batch was appended at the very end, so
    /// a failure in between left issuers live with nothing in the
    /// authorization stream about them — and a reapply could not
    /// restore the original `Created` / `Deleted`.
    ///
    /// **The JWKS warm-up runs after the commit.** It has to: the
    /// transaction lives inside the adapter, so there is no "between
    /// the upsert and the next upsert" for it to sit in any more. That
    /// is also the better order — a cache warmed for an issuer whose
    /// row then rolled back would be a trust state nothing persisted.
    /// Warm-up failure still does NOT fail the apply (ADR 0018's
    /// deliberate lazy-federation posture).
    ///
    /// **Report / metric counters are emitted while the plan is walked,
    /// i.e. before the commit** — the same point the claim-mapping and
    /// permission-grant branches have always emitted theirs. They used
    /// to be emitted per successfully-written row, so a mid-way failure
    /// counted only what had landed. The counters are now
    /// "what this apply intended"; a failed apply aborts the boot and
    /// nothing reads the report, and the per-kind
    /// `hort_gitops_objects_total` series is the signal that an apply
    /// was attempted, not that it committed.
    pub(super) async fn apply_oidc_issuers(
        &self,
        plan: &KindPlan<OidcIssuerSpec, String>,
        report: &mut ApplyReport,
        token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        let mut events: Vec<EventToAppend> = Vec::new();
        let mut change = OidcIssuerChange::default();
        let now = Utc::now();

        for env in &plan.create {
            let id = self
                .oidc_issuers
                .get_by_name(&env.metadata.name)
                .await?
                .map(|i| i.id)
                .unwrap_or_else(Uuid::new_v4);
            let issuer = build_oidc_issuer_from_spec(env, id)?;
            change.upserts.push(issuer);
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
            change.upserts.push(issuer);
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
            change.deletes.push(name.clone());
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

        if change.upserts.is_empty() && change.deletes.is_empty() {
            // Nothing in the plan: no row write, no event, no
            // transaction. Same observable behaviour as before the
            // port, without a pointless round-trip on every boot.
            return Ok(());
        }

        let event_count = events.len();
        let batches = Self::authorization_batches(events, Kind::OidcIssuer, token);
        self.authority.commit_oidc_issuers(&change, batches).await?;

        // Emitted AFTER the commit returned `Ok` — the first point at
        // which "committed" is true. The same line used to run *before*
        // the append, so an operator reading the log saw the claim on a
        // path that had not yet done the thing it claimed.
        //
        // Unguarded, unlike the pre-port `if !events.is_empty()`: the
        // early return above already established that the change set is
        // non-empty, and every row operation pushed into it pushed an
        // event beside it, so `event_count >= 1` here by construction.
        // A guard would be an unreachable branch.
        tracing::info!(
            kind = gitops_kind::OIDC_ISSUER,
            events = event_count,
            "oidc_issuer audit events committed"
        );

        // Best-effort JWKS warm-up for every issuer whose row is now
        // durable. MUST NOT fail the apply on error; federation works
        // lazily via the cache-miss path on first request. Fires on the
        // update path too (jwks_uri or audiences may have shifted;
        // populate the cache so the next federation request sees the
        // post-update key set without an inline fetch tax).
        for issuer in &change.upserts {
            self.warm_up_oidc_jwks(issuer).await;
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

    // -- rows commit with their audit events ---------------------------------

    /// An audit-append failure during the issuer apply leaves **no**
    /// issuer row behind. Issuer rows are trust anchors (ADR 0018): a
    /// serving validator reads the repository at validation time, so a
    /// row that commits without its attesting event is a live trust
    /// change the authorization stream is silent about — and a reapply
    /// cannot restore the original `Created` / `Deleted`.
    #[tokio::test]
    async fn apply_oidc_issuer_commit_failure_leaves_no_row() {
        let h = build_harness();
        h.authority.fail_next(
            AuthoritySite::OidcIssuers,
            DomainError::Invariant("event store unavailable".into()),
        );
        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));

        let err =
            h.uc.apply(desired, env_oidc())
                .await
                .expect_err("an audit-append failure must fail the apply");
        assert!(
            err.to_string().contains("event store unavailable"),
            "the event-store failure must surface, got: {err}"
        );
        assert!(
            h.oidc_issuers.snapshot().is_empty(),
            "the issuer row must not be in effect after a failed commit"
        );
        assert!(
            !authz_events(&h)
                .await
                .iter()
                .any(|e| matches!(e, DomainEvent::OidcIssuerCreated(_))),
            "no OidcIssuerCreated may have landed either"
        );
    }

    /// The JWKS warm-up runs **after** the commit, so a rolled-back
    /// issuer never gets its keys cached. A warmed cache for a row
    /// nothing persisted would be a trust state with no record.
    #[tokio::test]
    async fn apply_oidc_issuer_commit_failure_skips_jwks_warm_up() {
        let h = build_harness();
        let (uc, validator) = install_validator(&h);
        validator.register_refresh_outcome("github-actions", Ok(()));
        h.authority.fail_next(
            AuthoritySite::OidcIssuers,
            DomainError::Invariant("event store unavailable".into()),
        );
        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));

        uc.apply(desired, env_oidc())
            .await
            .expect_err("an audit-append failure must fail the apply");
        assert!(
            validator.refresh_calls().is_empty(),
            "warm-up must not run for an issuer whose row did not commit"
        );
    }

    /// An apply with no issuer envelopes opens no transaction at all —
    /// the early return before the commit. Same observable behaviour as
    /// before the port (no row write, no event), without a round-trip
    /// on every boot.
    #[tokio::test]
    async fn apply_oidc_issuer_empty_plan_does_not_commit() {
        let h = build_harness();
        h.uc.apply(DesiredState::default(), env_oidc())
            .await
            .unwrap();
        assert!(
            !h.authority
                .commits()
                .iter()
                .any(|(site, _)| *site == AuthoritySite::OidcIssuers),
            "an empty issuer plan must not reach the authority port"
        );
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
            // Same atomic authority writer the base harness holds, so
            // an armed failure seeded via `h.authority` is observed by
            // this rebuilt use case too.
            h.authority.clone(),
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
            // See `build_harness_with_lint_config` — same default posture.
            Arc::new(["npm".to_string()].into_iter().collect()),
            // No retention projection in this harness. Explicit,
            // not inherited: the slot is a required argument so a
            // composition that skips retention says so, and the
            // apply warns on every envelope it then drops.
            None,
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
