use super::*;

impl ApplyConfigUseCase {
    /// Apply `ServiceAccount` create / update / delete from the gitops
    /// plan. Each create / update step:
    ///
    /// 1. Ensures a backing `users` row exists (`username = "sa:" || name`,
    ///    `is_service_account = true`). The user row is shared
    ///    infrastructure — created on first apply, never deleted by
    ///    the apply path.
    /// 2. Composes the full SA aggregate (SA row +
    ///    federated_identities + fallback_rotation) and calls
    ///    `service_accounts.upsert`, which runs the whole shape in a
    ///    single transaction.
    /// 3. Manages the role/repo grants — one `permission_grants` row
    ///    per `(role, repo)` pair (Permission::Write is the read+write
    ///    surface for developer SAs; reader SAs get Permission::Read).
    ///    Idempotent: re-applying the same SA does not produce
    ///    duplicate grant rows because each grant is upserted by
    ///    `(role_id, repository_id, permission)` triple.
    ///
    /// Delete path: removes the SA aggregate (CASCADE drops sub-rows)
    /// and the permission grants. The backing `users` row stays.
    pub(super) async fn apply_service_accounts(
        &self,
        plan: &KindPlan<ServiceAccountSpec, String>,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let mut events: Vec<EventToAppend> = Vec::new();
        let now = Utc::now();

        for env in &plan.create {
            let (backing_user_id, sa_id) = self.upsert_service_account_aggregate(env, true).await?;
            events.push(EventToAppend::new(DomainEvent::ServiceAccountCreated(
                ServiceAccountCreated {
                    service_account_id: sa_id,
                    service_account_name: env.metadata.name.clone(),
                    backing_user_id,
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::SERVICE_ACCOUNT, GitopsObjectResult::Created);
            report.created += 1;
        }
        for env in &plan.update {
            let (_, sa_id) = self.upsert_service_account_aggregate(env, false).await?;
            events.push(EventToAppend::new(DomainEvent::ServiceAccountUpdated(
                ServiceAccountUpdated {
                    service_account_id: sa_id,
                    service_account_name: env.metadata.name.clone(),
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::SERVICE_ACCOUNT, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        for name in &plan.delete {
            let existing = self.service_accounts.get_by_name(name).await?;
            let Some(sa) = existing else {
                // Row already gone (out-of-band delete or no-op
                // re-apply) — fall through silently. Idempotent.
                continue;
            };
            // The SA's `User`-subject permission grants
            // are NOT deleted here. A deleted SA is absent from
            // `desired.service_accounts`, so the consolidated
            // PermissionGrant reconcile (`apply_permission_grants`,
            // which runs after this pass) does not include its grants
            // in the desired set; `save_managed`'s whole-partition
            // delete-absent removes them atomically. Deleting them here
            // would be a no-op-with-extra-round-trips at best and a
            // double-delete race at worst.
            self.service_accounts.delete_by_name(name).await?;
            events.push(EventToAppend::new(DomainEvent::ServiceAccountDeleted(
                ServiceAccountDeleted {
                    service_account_id: sa.id,
                    service_account_name: name.clone(),
                    backing_user_id: sa.backing_user_id,
                    at: now,
                },
            )));
            emit_gitops_object(gitops_kind::SERVICE_ACCOUNT, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        if !events.is_empty() {
            tracing::info!(
                kind = gitops_kind::SERVICE_ACCOUNT,
                events = events.len(),
                "service_account audit events committed"
            );
            let actor = gitops_actor_for_kind(Kind::ServiceAccount);
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

    /// Combined SA-create-or-update workhorse: ensure backing user,
    /// upsert SA aggregate. Returns `(backing_user_id,
    /// service_account_id)`.
    ///
    /// This does not reconcile the SA's permission
    /// grants. SA authority is materialised as
    /// `GrantSubject::User(backing_user_id)` rows by the consolidated
    /// `apply_permission_grants` pass, which runs after every SA's
    /// aggregate + backing user exists (one whole-partition
    /// `save_managed` covering envelope grants ∪ SA-owned grants).
    ///
    /// `is_create` is informational — the row UPSERT handles both
    /// cases atomically. We thread it for future-friendly logging
    /// only.
    async fn upsert_service_account_aggregate(
        &self,
        env: &Envelope<ServiceAccountSpec>,
        _is_create: bool,
    ) -> AppResult<(Uuid, Uuid)> {
        // 1. Backing user.
        let backing_user_id = self.ensure_backing_user(&env.metadata.name).await?;

        // 2. SA aggregate. Resolve a stable id when the row exists.
        let existing_id = self
            .service_accounts
            .get_by_name(&env.metadata.name)
            .await?
            .map(|s| s.id);
        let sa_id = existing_id.unwrap_or_else(Uuid::new_v4);
        let sa = build_service_account_from_spec(env, sa_id, backing_user_id)?;
        self.service_accounts.upsert(&sa).await?;

        Ok((backing_user_id, sa_id))
    }

    /// Look up the backing user by `username = "sa:" || sa_name` and
    /// return its id, creating the row if it doesn't exist.
    ///
    /// The user row is shared infrastructure — we never
    /// delete it from the apply path. Other code (API
    /// token issuance, audit attribution) may grant or revoke tokens
    /// scoped to this user independent of the SA aggregate lifecycle.
    async fn ensure_backing_user(&self, sa_name: &str) -> AppResult<Uuid> {
        let username = backing_username(sa_name);
        if let Some(user) = self.users.find_by_username(&username).await? {
            return Ok(user.id);
        }
        let user = User {
            id: Uuid::new_v4(),
            username: username.clone(),
            // Synthesised email — not used for delivery, but the
            // `users.email` column is NOT NULL in the existing schema.
            email: format!("{username}@service-accounts.local"),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: Some(format!("Service account: {sa_name}")),
            is_active: true,
            is_admin: false,
            is_service_account: true,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.users.save(&user).await?;
        tracing::info!(
            entity = "service_account_backing_user",
            username = %username,
            "created backing users row for service account"
        );
        Ok(user.id)
    }
}

/// Build a `ServiceAccount` aggregate (SA row + federated identities
/// + optional fallback rotation) from a validated spec envelope.
///
/// The `validate_service_account` pass has already gated every value;
/// fall through to `Invariant` for any parse-after-validate failure.
fn build_service_account_from_spec(
    env: &Envelope<ServiceAccountSpec>,
    id: Uuid,
    backing_user_id: Uuid,
) -> AppResult<ServiceAccount> {
    debug_assert!(matches!(env.kind, Kind::ServiceAccount));
    let spec = &env.spec;
    let federated_identities: Vec<FederatedIdentity> = spec
        .federated_identities
        .iter()
        .map(|fi| FederatedIdentity {
            issuer_name: fi.issuer.clone(),
            claims: fi.claims.clone(),
        })
        .collect();
    let fallback_rotation = match &spec.fallback_rotation {
        None => None,
        Some(r) => {
            let rotation_interval = humantime::parse_duration(&r.rotation_interval).map_err(
                |e| {
                    DomainError::Invariant(format!(
                        "ServiceAccount `{}`: rotationInterval validation passed but parse failed: {e}",
                        env.metadata.name
                    ))
                },
            )?;
            let validity = humantime::parse_duration(&r.validity).map_err(|e| {
                DomainError::Invariant(format!(
                    "ServiceAccount `{}`: validity validation passed but parse failed: {e}",
                    env.metadata.name
                ))
            })?;
            let format = match r.target_secret.format.as_str() {
                "dockerconfigjson" => SecretFormat::Dockerconfigjson,
                "opaque" => SecretFormat::Opaque,
                other => {
                    return Err(DomainError::Invariant(format!(
                        "ServiceAccount `{}`: targetSecret.format `{other}` validation \
                         passed but enum mapping failed",
                        env.metadata.name
                    ))
                    .into());
                }
            };
            Some(FallbackRotation {
                target_secret_name: r.target_secret.name.clone(),
                target_secret_namespace: r.target_secret.namespace.clone(),
                format,
                rotation_interval,
                validity,
            })
        }
    };
    Ok(ServiceAccount {
        id,
        name: env.metadata.name.clone(),
        backing_user_id,
        role: spec.role.clone(),
        repositories: spec.repositories.clone(),
        federated_identities,
        fallback_rotation,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::apply_config_use_case::tests::*;
    use hort_config::envelope::{ApiVersion, Metadata};
    use hort_config::service_account::FederatedIdentitySpec;
    use hort_domain::types::PageRequest;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    // -- ServiceAccount apply ----------------------------------------------

    #[tokio::test]
    async fn apply_service_account_creates_backing_user_and_sa_row() {
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "ci-pypi-pusher",
            &["pypi-internal"],
            None,
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 1, "exactly one SA created");
        // Backing user exists.
        let user = h
            .users
            .find_by_username("sa:ci-pypi-pusher")
            .await
            .unwrap()
            .expect("backing user must exist after SA apply");
        assert!(user.is_service_account);
        // SA row exists, points at the backing user.
        let sas = h.service_accounts.snapshot();
        assert_eq!(sas.len(), 1);
        assert_eq!(sas[0].backing_user_id, user.id);
    }

    #[tokio::test]
    async fn apply_service_account_reapply_is_idempotent_no_duplicate_user_or_grants() {
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });

        let env = service_account_env_for_apply("ci-pypi-pusher", &["pypi-internal"], None);
        let mut desired_a = DesiredState::default();
        desired_a.service_accounts.push(env.clone());
        h.uc.apply(desired_a, env_oidc()).await.unwrap();

        let mut desired_b = DesiredState::default();
        desired_b.service_accounts.push(env);
        h.uc.apply(desired_b, env_oidc()).await.unwrap();

        // Exactly one backing user, exactly one SA row, exactly one
        // permission grant — re-applying must not duplicate any of them.
        let users_page = h.users.list(PageRequest::new(0, 100)).await.unwrap();
        let sa_users: Vec<_> = users_page
            .items
            .iter()
            .filter(|u| u.is_service_account)
            .collect();
        assert_eq!(sa_users.len(), 1, "exactly one SA backing user");
        assert_eq!(h.service_accounts.snapshot().len(), 1, "exactly one SA row");
        // SA authority is a `GrantSubject::User(backing
        // _user_id)` grant materialised through the consolidated
        // whole-partition `permission_grants.save_managed` reconcile.
        // Re-applying the identical SA env must not duplicate the
        // grant — the User-subject diff key
        // `(user_id, repository_id, permission)` makes the replay a
        // no-op, so exactly one managed grant survives.
        let managed = h.grant_repo.managed_snapshot();
        assert_eq!(managed.len(), 1, "exactly one SA-owned grant after reapply");
        assert_eq!(managed[0].subject, GrantSubject::User(sa_users[0].id));
    }

    /// Closure proof — replay the operator's rc.20 bundle
    /// (`glci-supply-chain-security` SA + `developer` claim grants
    /// covered by a `singleClaimAllowlist: [developer]` lint config +
    /// `gitlab-kdp` OidcIssuer) and assert the SA-derived User-subject
    /// grant lands in the managed partition. The operator's "no
    /// User-subject grant persisted" observation must be reproducible
    /// here if it is a code bug; a green test rules code out and pins
    /// the contract that future changes must preserve.
    #[tokio::test]
    async fn apply_operator_f9_bundle_persists_sa_owned_user_subject_grant() {
        use hort_config::lint_config::RuleOverridesSpec;
        let h = build_harness();
        // Operator's bundle declares the ArtifactRepository as well; let
        // the apply path create it (no harness pre-seed — that would
        // collide with the managed_by=gitops upsert).
        let mut desired = DesiredState::default();
        desired
            .repositories
            .push(repo_env("supply-chain-security", "hosted"));
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("gitlab-kdp"));
        desired
            .claim_mappings
            .push(cm_env("admins", "platform-admins", "admin"));
        desired
            .claim_mappings
            .push(cm_env("developers", "developers", "developer"));
        desired.permission_grants.push(grant_env(
            "developer-write-supply-chain-security",
            &["developer"],
            "write",
            Some("supply-chain-security"),
        ));
        desired.permission_grants.push(grant_env(
            "developer-read-supply-chain-security",
            &["developer"],
            "read",
            Some("supply-chain-security"),
        ));
        put_lint_config(
            &mut desired,
            "rbac-lint",
            &["developer"],
            RuleOverridesSpec::default(),
        );
        desired.service_accounts.push(service_account_env_for_apply(
            "glci-supply-chain-security",
            &["supply-chain-security"],
            Some("gitlab-kdp"),
        ));

        h.uc.apply(desired, env_oidc())
            .await
            .expect("operator bundle must apply cleanly");

        let sa_user = h
            .users
            .find_by_username("sa:glci-supply-chain-security")
            .await
            .unwrap()
            .expect("SA backing user must exist after apply");
        let managed = h.grant_repo.managed_snapshot();
        // Operator's "no User-subject grant persisted" assertion fails
        // if the harness disagrees — this is the load-bearing assert.
        let sa_grant = managed
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::User(uid) if *uid == sa_user.id))
            .expect(
                "SA-derived `GrantSubject::User(backing_user_id)` grant for \
                 supply-chain-security must be in the managed partition",
            );
        assert_eq!(sa_grant.permission, Permission::Write);
        assert!(
            sa_grant.repository_id.is_some(),
            "SA-derived grant must be repo-scoped, not global"
        );
    }

    // -- ServiceAccount-subject standalone grants (ADR 0037 / spec §9) -----

    #[tokio::test]
    async fn apply_global_service_account_grant_resolves_to_backing_user() {
        // A declared SA + a standalone GLOBAL serviceAccount Read grant.
        // The grant must materialise as `GrantSubject::User(backing_user_id)`
        // with `repository_id: None` — the global authority an SA envelope
        // (always repo-scoped) cannot express.
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "npm-public".into(),
            ..sample_repository_for_test("npm-public")
        });
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "maintainer-dev",
            &["npm-public"],
            None,
        ));
        desired.permission_grants.push(sa_grant_env(
            "maintainer-dev-global-read",
            "maintainer-dev",
            "read",
            None, // global
        ));

        h.uc.apply(desired, env_oidc())
            .await
            .expect("global serviceAccount grant must apply");

        let sa_user = h
            .users
            .find_by_username("sa:maintainer-dev")
            .await
            .unwrap()
            .expect("SA backing user must exist");
        let managed = h.grant_repo.managed_snapshot();
        // The standalone GLOBAL grant resolves to User(backing) / None.
        let global = managed
            .iter()
            .find(|g| {
                matches!(&g.subject, GrantSubject::User(uid) if *uid == sa_user.id)
                    && g.repository_id.is_none()
                    && g.permission == Permission::Read
            })
            .expect("global User(backing_user_id) Read grant must be present");
        assert!(global.repository_id.is_none());
    }

    #[tokio::test]
    async fn apply_service_account_grant_reapply_is_idempotent_no_churn() {
        // THE diff-idempotence assertion. Apply the SAME config (SA +
        // standalone global serviceAccount Read grant) twice; the second
        // apply must produce ZERO add/remove churn in the managed grant
        // partition — the SA-name resolves to the same backing_user_id and
        // the resolved User(uuid) row diffs identically across applies.
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "npm-public".into(),
            ..sample_repository_for_test("npm-public")
        });
        let build = || {
            let mut d = DesiredState::default();
            d.service_accounts.push(service_account_env_for_apply(
                "maintainer-dev",
                &["npm-public"],
                None,
            ));
            d.permission_grants.push(sa_grant_env(
                "maintainer-dev-global-read",
                "maintainer-dev",
                "read",
                None,
            ));
            d
        };

        h.uc.apply(build(), env_oidc()).await.unwrap();
        // Managed set after first apply: the SA-role-derived repo-scoped
        // grant + the standalone global grant = 2.
        let first = h.grant_repo.managed_snapshot();
        let first_count = first.len();
        assert_eq!(
            first_count, 2,
            "SA role-derived repo grant + standalone global grant = 2"
        );
        // Capture surrogate ids so we can prove they carry through.
        let mut first_ids: Vec<Uuid> = first.iter().map(|g| g.id).collect();
        first_ids.sort();

        h.uc.apply(build(), env_oidc()).await.unwrap();
        let second = h.grant_repo.managed_snapshot();
        assert_eq!(
            second.len(),
            first_count,
            "re-applying the identical config must not change the managed grant count"
        );
        let mut second_ids: Vec<Uuid> = second.iter().map(|g| g.id).collect();
        second_ids.sort();
        assert_eq!(
            first_ids, second_ids,
            "surrogate grant ids must carry through a no-op re-apply (no delete+recreate churn)"
        );
        // Exactly one save_managed call per apply (two total).
        assert_eq!(h.grant_repo.save_managed_call_count(), 2);
    }

    #[tokio::test]
    async fn apply_repo_scoped_service_account_curate_grant_resolves() {
        // Repo-scoped `curate` — non-read/write authority an SA role
        // bundle cannot grant. Resolves to User(backing) scoped to the repo.
        let h = build_harness();
        seed_developer_role(&h);
        // Declare the repo in the bundle (let the apply create it) so the
        // grant's `spec.repository` cross-spec reference resolves; a
        // pre-seeded harness row would collide with the managed upsert.
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("oci-prod", "hosted"));
        desired.service_accounts.push(service_account_env_for_apply(
            "maintainer-curator",
            &["oci-prod"],
            None,
        ));
        desired.permission_grants.push(sa_grant_env(
            "curator-grant",
            "maintainer-curator",
            "curate",
            Some("oci-prod"),
        ));

        h.uc.apply(desired, env_oidc())
            .await
            .expect("repo-scoped serviceAccount curate grant must apply");

        let sa_user = h
            .users
            .find_by_username("sa:maintainer-curator")
            .await
            .unwrap()
            .expect("SA backing user must exist");
        let managed = h.grant_repo.managed_snapshot();
        let curate = managed
            .iter()
            .find(|g| {
                matches!(&g.subject, GrantSubject::User(uid) if *uid == sa_user.id)
                    && g.permission == Permission::Curate
            })
            .expect("User(backing_user_id) Curate grant must be present");
        assert!(
            curate.repository_id.is_some(),
            "curate grant is repo-scoped"
        );
    }

    #[tokio::test]
    async fn apply_global_service_account_grant_passes_secure_default_linter() {
        // The audited operator path: a GLOBAL serviceAccount grant under
        // the SECURE-BY-DEFAULT linter (no downgrade). It must NOT trip
        // the `direct-user-grant-without-justification` reject arm — the
        // resolved backing user is SA-owned (provenance-justified), so the
        // linter exempts it exactly like an SA role-derived grant.
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        h.repos.insert(Repository {
            key: "npm-public".into(),
            ..sample_repository_for_test("npm-public")
        });
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "maintainer-dev",
            &["npm-public"],
            None,
        ));
        desired.permission_grants.push(sa_grant_env(
            "maintainer-dev-global-read",
            "maintainer-dev",
            "read",
            None,
        ));

        h.uc.apply(desired, env_oidc())
            .await
            .expect("a global serviceAccount grant must clear the SECURE-DEFAULT linter");
    }

    #[tokio::test]
    async fn apply_service_account_grant_naming_missing_sa_fails_validation() {
        // A serviceAccount-subject grant naming an undeclared SA is a
        // cross-spec DanglingReference — apply must fail before any write.
        let h = build_harness();
        h.repos.insert(Repository {
            key: "npm-public".into(),
            ..sample_repository_for_test("npm-public")
        });
        let mut desired = DesiredState::default();
        desired
            .permission_grants
            .push(sa_grant_env("dangling", "ghost-sa", "read", None));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("ghost-sa"),
            "validation error must name the missing ServiceAccount: {rendered}"
        );
        // No grant was written.
        assert_eq!(h.grant_repo.save_managed_call_count(), 0);
    }

    #[tokio::test]
    async fn apply_service_account_with_unknown_issuer_fails_validation() {
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "ci-pypi-pusher",
            &["pypi-internal"],
            Some("ghost-issuer"), // not declared!
        ));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("ghost-issuer"),
            "FK error must name the missing issuer: {rendered}"
        );
        assert!(
            rendered.contains("OidcIssuer") || rendered.contains("oidc"),
            "FK error must mention OidcIssuer: {rendered}"
        );
    }

    #[tokio::test]
    async fn apply_service_account_with_declared_issuer_in_same_pass_succeeds() {
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });
        // OidcIssuer declared in the same apply — the FK check accepts
        // either snapshot or desired, with desired winning.
        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));
        desired.service_accounts.push(service_account_env_for_apply(
            "ci-pypi-pusher",
            &["pypi-internal"],
            Some("github-actions"),
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 2, "issuer + SA both created");
    }

    // -- apply-time under-constrained-FI
    //    warning is WIRED into the production apply path ------------------
    //
    // Historically `detect_under_constrained_federated_identities`
    // was dead code (only `#[test]` callers in `hort-config`); commit
    // `37ece7da` falsely claimed a boot caller emitted the `warn!`. These
    // tests prove `ApplyConfigUseCase::apply` now actually emits one
    // structured `warn!` per under-constrained FI — and does NOT for a
    // well-constrained one — using the established `set_default` tracing-
    // capture pattern (mirrors `quarantine_use_case.rs`'s audit-log
    // assertions and the dependency-rule note on `hort-config`: the pure
    // detector returns findings, this caller logs them).

    #[derive(Clone, Default)]
    struct F7CapturingLayer {
        records: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for F7CapturingLayer
    where
        S: tracing::Subscriber,
    {
        fn register_callsite(
            &self,
            _meta: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }
        fn enabled(
            &self,
            _meta: &tracing::Metadata<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) -> bool {
            true
        }
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = F7MessageVisitor::default();
            event.record(&mut visitor);
            self.records
                .lock()
                .unwrap()
                .push((*event.metadata().level(), visitor.combined));
        }
    }

    #[derive(Default)]
    struct F7MessageVisitor {
        combined: String,
    }
    impl tracing::field::Visit for F7MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.combined
                .push_str(&format!("{}={:?} ", field.name(), value));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.combined
                .push_str(&format!("{}={} ", field.name(), value));
        }
    }

    static F7_TRACING_TEST_MUTEX: Mutex<()> = Mutex::new(());

    /// A well-constrained FI: repository + a discriminating
    /// `environment` claim ⇒ the detector must stay silent.
    fn service_account_env_well_constrained(
        sa_name: &str,
        repos: &[&str],
        issuer: &str,
    ) -> Envelope<ServiceAccountSpec> {
        let mut claims = BTreeMap::new();
        claims.insert("repository".into(), "my-org/my-repo".into());
        claims.insert("environment".into(), "production".into());
        Envelope {
            api_version: ApiVersion::V1Beta1,
            kind: Kind::ServiceAccount,
            metadata: Metadata {
                name: sa_name.into(),
            },
            spec: ServiceAccountSpec {
                role: "developer".into(),
                repositories: repos.iter().map(|s| (*s).into()).collect(),
                federated_identities: vec![FederatedIdentitySpec {
                    issuer: issuer.into(),
                    claims,
                }],
                fallback_rotation: None,
            },
        }
    }

    // Synchronous `#[test]` driving the async `apply` via a
    // current-thread runtime's `block_on` — mirrors
    // `quarantine_use_case.rs`'s `admin_release_success_log_carries_user_id`
    // shape. A `#[tokio::test]` would hold the serialization
    // `MutexGuard` across the `.await` (clippy `await_holding_lock`);
    // `block_on` keeps the guard on the synchronous stack so it is
    // never held *across* a suspension point.

    #[test]
    fn apply_emits_warn_for_under_constrained_federated_identity() {
        use tracing_subscriber::layer::SubscriberExt;

        let _serial = F7_TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let layer = F7CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let h = build_harness();
            seed_developer_role(&h);
            h.repos.insert(Repository {
                key: "pypi-internal".into(),
                ..sample_repository_for_test("pypi-internal")
            });
            let mut desired = DesiredState::default();
            desired
                .oidc_issuers
                .push(oidc_issuer_env_for_apply("github-actions"));
            // `service_account_env_for_apply(..., Some(_))` builds an FI
            // with ONLY a `repository` claim — the under-constrained shape
            // (no ref/environment/workflow/aud discriminator).
            desired.service_accounts.push(service_account_env_for_apply(
                "ci-loose",
                &["pypi-internal"],
                Some("github-actions"),
            ));

            // Apply MUST still succeed — warning, not ValidationError.
            let report = h.uc.apply(desired, env_oidc()).await.unwrap();
            assert_eq!(
                report.created, 2,
                "issuer + SA both created; apply succeeds"
            );
        });

        let records = captured.lock().unwrap();
        let warn = records
            .iter()
            .find(|(lvl, msg)| {
                *lvl == tracing::Level::WARN
                    && msg.contains("under-constrained federatedIdentities")
            })
            .expect(
                "ApplyConfigUseCase::apply must emit a WARN for an under-constrained FI \
                 (detector was previously dead code before this wiring)",
            );
        let msg = &warn.1;
        assert!(
            msg.contains("ci-loose"),
            "warn must carry the SA name (operator-authored identifier): {msg}"
        );
        assert!(
            msg.contains("github-actions"),
            "warn must carry the issuer reference: {msg}"
        );
        assert!(
            msg.contains("discriminating"),
            "warn must forward the detector's remediation message: {msg}"
        );
    }

    #[test]
    fn apply_does_not_warn_for_well_constrained_federated_identity() {
        use tracing_subscriber::layer::SubscriberExt;

        let _serial = F7_TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let layer = F7CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let h = build_harness();
            seed_developer_role(&h);
            h.repos.insert(Repository {
                key: "pypi-internal".into(),
                ..sample_repository_for_test("pypi-internal")
            });
            let mut desired = DesiredState::default();
            desired
                .oidc_issuers
                .push(oidc_issuer_env_for_apply("github-actions"));
            desired
                .service_accounts
                .push(service_account_env_well_constrained(
                    "ci-tight",
                    &["pypi-internal"],
                    "github-actions",
                ));

            let report = h.uc.apply(desired, env_oidc()).await.unwrap();
            assert_eq!(report.created, 2, "issuer + SA both created");
        });

        let records = captured.lock().unwrap();
        assert!(
            !records
                .iter()
                .any(|(_, msg)| msg.contains("under-constrained federatedIdentities")),
            "a repository+environment FI is well-constrained — no under-constrained warning expected"
        );
    }

    #[tokio::test]
    async fn apply_service_account_referencing_about_to_be_deleted_issuer_fails_validation() {
        // Regression guard. The FK validator
        // must consider only the *post-apply* set of OidcIssuers, which is
        // exactly `desired.oidc_issuers`. Issuers present in the snapshot
        // but absent from desired are being deleted by omission and must
        // NOT satisfy the FK for any ServiceAccount that still references
        // them — otherwise the apply would leave a dangling logical FK
        // (the `service_account_federated_identities` row points at an
        // issuer name that no longer exists, and every later federation
        // exchange against that SA returns `UnknownIssuer`).
        //
        // Test shape:
        //   snapshot: OidcIssuer `legacy-idp`, ServiceAccount `legacy-sa`
        //             federated to `legacy-idp` (seeded directly).
        //   desired:  ServiceAccount `legacy-sa` federated to `legacy-idp`
        //             (no OidcIssuer envelopes — `legacy-idp` is being
        //             deleted by omission).
        // Expected: apply fails with a validation error naming both the
        //           SA and the missing issuer.
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });
        // Seed the snapshot: an OidcIssuer that the desired state will
        // delete by omission.
        let snapshot_issuer = OidcIssuer {
            id: Uuid::new_v4(),
            name: "legacy-idp".into(),
            issuer_url: "https://legacy-idp.example.com".into(),
            audiences: vec!["hort-server".into()],
            jwks_refresh_interval: std::time::Duration::from_secs(3600),
            allowed_algorithms: vec![JwtAlg::Rs256],
            require_jti: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        h.oidc_issuers.upsert(&snapshot_issuer).await.unwrap();
        // Build a desired with the SA still referencing `legacy-idp` but
        // NO OidcIssuer envelopes — the issuer is being deleted by
        // omission.
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "legacy-sa",
            &["pypi-internal"],
            Some("legacy-idp"),
        ));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("legacy-sa"),
            "FK error must name the offending ServiceAccount: {rendered}"
        );
        assert!(
            rendered.contains("legacy-idp"),
            "FK error must name the missing OidcIssuer: {rendered}"
        );
    }

    #[tokio::test]
    async fn apply_service_account_delete_preserves_backing_user_row() {
        // Invariant: the backing user is shared infrastructure
        // — deleting the SA must NOT delete the user.
        let h = build_harness();
        seed_developer_role(&h);
        h.repos.insert(Repository {
            key: "pypi-internal".into(),
            ..sample_repository_for_test("pypi-internal")
        });
        let env = service_account_env_for_apply("ci-pypi-pusher", &["pypi-internal"], None);
        let mut desired = DesiredState::default();
        desired.service_accounts.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();
        assert!(h
            .users
            .find_by_username("sa:ci-pypi-pusher")
            .await
            .unwrap()
            .is_some());

        // Re-apply with no SA — delete sweep runs.
        // The PG sweep skips SA-owned grants (their digests are computed
        // from the snapshot SAs and excluded from the PG delete plan), so
        // `report.deleted` is exactly the SA row count. The SA-owned
        // permission grant is removed by `delete_service_account_grants`
        // and is NOT counted in `report.deleted` (the SA-sweep bumps
        // `report.deleted` once per SA, not once per grant).
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(
            report.deleted, 1,
            "SA-owned grants are deleted by \
             delete_service_account_grants, not by the PG sweep; \
             only the SA row contributes to report.deleted"
        );
        assert!(h.service_accounts.snapshot().is_empty());
        // The backing user row stays.
        assert!(
            h.users
                .find_by_username("sa:ci-pypi-pusher")
                .await
                .unwrap()
                .is_some(),
            "backing user row must persist across SA delete (shared infrastructure)"
        );
    }
}
