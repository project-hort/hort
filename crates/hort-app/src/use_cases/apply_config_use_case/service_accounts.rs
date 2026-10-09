use super::*;

impl ApplyConfigUseCase {
    /// Apply `ServiceAccount` create / update / delete from the gitops
    /// plan.
    ///
    /// The aggregate is identity + federation binding only — this pass
    /// materialises no permission grants. SA authority is declared as
    /// explicit `serviceAccount`-subject `PermissionGrant` envelopes
    /// and reconciled by `apply_permission_grants` (ADR 0037).
    ///
    /// **Rows and events commit together.** The branch builds the whole
    /// [`ServiceAccountCommit`] — one aggregate per `create` / `update`
    /// envelope, one name per `plan.delete` — plus the audit batch, and
    /// hands both to
    /// [`AuthorityLifecyclePort::commit_service_accounts`], which
    /// writes them in one transaction. A service account is a
    /// **federated-identity trust anchor** (ADR 0018): its
    /// `federated_identities[].claims` decide which JWTs from a trusted
    /// issuer may assume it, and the federation handler reads the
    /// aggregate at assume time — so a surviving replica acts on the
    /// new trust state the moment the row commits. Before the port each
    /// `upsert` / `delete_by_name` committed on its own and the whole
    /// audit batch was appended at the very end, so a failure in
    /// between left service accounts live with nothing in the
    /// authorization stream about them, in a state the retry could not
    /// repair (the next apply diffs against the already-written rows).
    ///
    /// **The backing `users` row is written outside the transaction,
    /// and has to be.** Each create / update step ensures a
    /// `username = "sa:" || name`, `is_service_account = true` row
    /// exists via `UserRepository`; the FK from
    /// `service_accounts.backing_user_id` means it must be durable
    /// before the SA row can reference it. That is safe because an
    /// orphan backing user confers nothing: `apply_permission_grants`
    /// materialises `GrantSubject::User(backing_user_id)` rows only for
    /// service accounts in the desired set, resolved from the persisted
    /// SA aggregate, so a users row whose SA commit rolled back carries
    /// no grant and no token. The next apply finds it by username,
    /// reuses its id, and re-emits the same `ServiceAccountCreated`.
    /// The row is shared infrastructure and is never deleted by this
    /// path (other code may hold tokens scoped to it).
    ///
    /// Delete path: removes the SA aggregate (CASCADE drops the
    /// sub-rows). The SA's `User`-subject permission grants are NOT
    /// deleted here. A deleted SA is absent from
    /// `desired.service_accounts`, so the consolidated PermissionGrant
    /// reconcile (`apply_permission_grants`, which runs after this
    /// pass) does not include its grants in the desired set and its
    /// whole-partition delete-absent removes them atomically. Deleting
    /// them here would be a no-op-with-extra-round-trips at best and a
    /// double-delete race at worst.
    pub(super) async fn apply_service_accounts(
        &self,
        plan: &KindPlan<ServiceAccountSpec, String>,
        report: &mut ApplyReport,
        token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        let mut events: Vec<EventToAppend> = Vec::new();
        let mut change = ServiceAccountCommit::default();
        let now = Utc::now();

        for env in &plan.create {
            let (backing_user_id, sa) = self.build_service_account_aggregate(env).await?;
            events.push(EventToAppend::new(DomainEvent::ServiceAccountCreated(
                ServiceAccountCreated {
                    service_account_id: sa.id,
                    service_account_name: env.metadata.name.clone(),
                    backing_user_id,
                    at: now,
                },
            )));
            change.upserts.push(sa);
            emit_gitops_object(gitops_kind::SERVICE_ACCOUNT, GitopsObjectResult::Created);
            report.created += 1;
        }
        for env in &plan.update {
            let (_, sa) = self.build_service_account_aggregate(env).await?;
            events.push(EventToAppend::new(DomainEvent::ServiceAccountUpdated(
                ServiceAccountUpdated {
                    service_account_id: sa.id,
                    service_account_name: env.metadata.name.clone(),
                    at: now,
                },
            )));
            change.upserts.push(sa);
            emit_gitops_object(gitops_kind::SERVICE_ACCOUNT, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        for name in &plan.delete {
            let existing = self.service_accounts.get_by_name(name).await?;
            let Some(sa) = existing else {
                // Row already gone (out-of-band delete or no-op
                // re-apply) — fall through silently. Idempotent, and
                // there is no prior state to attest.
                continue;
            };
            change.deletes.push(name.clone());
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

        if change.upserts.is_empty() && change.deletes.is_empty() {
            // Nothing in the plan: no row write, no event, no
            // transaction. Same observable behaviour as before the
            // port, without a pointless round-trip on every boot.
            return Ok(());
        }

        let event_count = events.len();
        let batches = Self::authorization_batches(events, Kind::ServiceAccount, token);
        self.authority
            .commit_service_accounts(&change, batches)
            .await?;

        // Emitted AFTER the commit returned `Ok` — the first point at
        // which "committed" is true. The same line used to run before
        // the append, so an operator reading the log saw the claim on a
        // path that had not yet done the thing it claimed.
        //
        // Unguarded, unlike the pre-port `if !events.is_empty()`: the
        // early return above already established that the change set is
        // non-empty, and every row operation pushed into it pushed an
        // event beside it, so `event_count >= 1` here by construction.
        // A guard would be an unreachable branch.
        tracing::info!(
            kind = gitops_kind::SERVICE_ACCOUNT,
            events = event_count,
            "service_account audit events committed"
        );
        Ok(())
    }

    /// Ensure the backing `users` row exists and compose the SA
    /// aggregate the commit will write. Returns `(backing_user_id,
    /// aggregate)`.
    ///
    /// Writes the backing user (see
    /// [`Self::apply_service_accounts`] for why that write is outside
    /// the authority transaction) and nothing else — the SA rows are
    /// written by the one `commit_service_accounts` call.
    ///
    /// This does not reconcile the SA's permission grants. SA authority
    /// is materialised as `GrantSubject::User(backing_user_id)` rows by
    /// the consolidated `apply_permission_grants` pass, which runs
    /// after every SA's aggregate + backing user exists (one
    /// whole-partition reconcile covering envelope grants ∪ SA-owned
    /// grants).
    async fn build_service_account_aggregate(
        &self,
        env: &Envelope<ServiceAccountSpec>,
    ) -> AppResult<(Uuid, ServiceAccount)> {
        // 1. Backing user.
        let backing_user_id = self.ensure_backing_user(&env.metadata.name).await?;

        // 2. SA aggregate. Resolve a stable id when the row exists, so
        // the audit `service_account_id` names the row the adapter's
        // `ON CONFLICT (name) DO UPDATE` keeps.
        let existing_id = self
            .service_accounts
            .get_by_name(&env.metadata.name)
            .await?
            .map(|s| s.id);
        let sa_id = existing_id.unwrap_or_else(Uuid::new_v4);
        let sa = build_service_account_from_spec(env, sa_id, backing_user_id)?;
        Ok((backing_user_id, sa))
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

    // -- SA rows commit with their audit events (one transaction) ----------

    fn sa_event_count(evts: &[DomainEvent]) -> usize {
        use DomainEvent::{
            ServiceAccountCreated as Created, ServiceAccountDeleted as Deleted,
            ServiceAccountUpdated as Updated,
        };
        evts.iter()
            .filter(|e| matches!(e, Created(_) | Updated(_) | Deleted(_)))
            .count()
    }

    /// An audit-append failure during the SA apply leaves **no SA row**
    /// — the apply fails closed rather than half-done. This is the
    /// federated-identity trust-anchor case (ADR 0018): the
    /// `federated_identities[].claims` decide which JWTs may assume the
    /// account, so an SA that commits without its event is a live trust
    /// grant the authorization stream is silent about, in a state the
    /// retry cannot repair.
    #[tokio::test]
    async fn apply_service_account_commit_failure_leaves_no_sa_row() {
        let h = build_harness();
        h.authority.fail_next(
            AuthoritySite::ServiceAccounts,
            DomainError::Invariant("event store unavailable".into()),
        );
        let mut desired = DesiredState::default();
        desired
            .service_accounts
            .push(service_account_env_for_apply("ci-pypi-pusher", None));

        let err =
            h.uc.apply(desired, env_oidc())
                .await
                .expect_err("an audit-append failure must fail the apply");
        assert!(
            err.to_string().contains("event store unavailable"),
            "the event-store failure must surface, got: {err}"
        );

        assert!(
            h.service_accounts.snapshot().is_empty(),
            "no service account may be assumable without an attesting event"
        );
        assert_eq!(
            sa_event_count(&authz_events(&h).await),
            0,
            "and no audit event may have landed"
        );
    }

    /// The deliberate exception, pinned rather than left to prose: the
    /// backing `users` row IS durable after the rolled-back commit. It
    /// has to be written first (the `service_accounts.backing_user_id`
    /// FK), and it confers nothing on its own — `apply_permission_grants`
    /// materialises `GrantSubject::User(backing_user_id)` rows only for
    /// service accounts resolved from the persisted SA aggregate, so
    /// this orphan carries no grant. The next apply finds it by
    /// username and reuses its id.
    #[tokio::test]
    async fn apply_service_account_commit_failure_leaves_an_unprivileged_backing_user() {
        let h = build_harness();
        h.authority.fail_next(
            AuthoritySite::ServiceAccounts,
            DomainError::Invariant("event store unavailable".into()),
        );
        let mut desired = DesiredState::default();
        desired
            .service_accounts
            .push(service_account_env_for_apply("ci-pypi-pusher", None));
        h.uc.apply(desired, env_oidc())
            .await
            .expect_err("the apply must fail");

        let orphan = h
            .users
            .find_by_username("sa:ci-pypi-pusher")
            .await
            .unwrap()
            .expect("the backing user is written before the SA commit");
        assert!(orphan.is_service_account);
        assert!(
            !orphan.is_admin,
            "the backing user must carry no standing authority of its own"
        );
        assert_eq!(
            h.grant_repo.managed_count(),
            0,
            "and no permission grant may target it — the grant reconcile \
             resolves subjects from the persisted SA aggregate, which rolled back"
        );
    }

    /// Every SA row operation in one apply goes through **one** commit
    /// call carrying one audit batch: creates, updates and deletes are
    /// collected into a single `ServiceAccountCommit`. Before the port
    /// each `upsert` / `delete_by_name` was independently committed and
    /// the batch was appended at the very end.
    #[tokio::test]
    async fn apply_service_account_commits_every_row_operation_once() {
        let h = build_harness();
        // Seed two SAs.
        let mut seeded = DesiredState::default();
        seeded
            .service_accounts
            .push(service_account_env_for_apply("keeper", None));
        seeded
            .service_accounts
            .push(service_account_env_for_apply("doomed", None));
        h.uc.apply(seeded, env_oidc()).await.unwrap();

        // Re-apply with `doomed` omitted. `keeper` is re-classified as
        // an update on every apply — the `service_accounts` table
        // carries no `managed_by_digest` column, so the diff's
        // `digest: None` means "force update" (the conservative
        // re-stamp the snapshot builder documents).
        let mut next = DesiredState::default();
        next.service_accounts
            .push(service_account_env_for_apply("keeper", None));
        h.uc.apply(next, env_oidc()).await.unwrap();

        let commits: Vec<usize> = h
            .authority
            .commits()
            .into_iter()
            .filter(|(site, _)| *site == AuthoritySite::ServiceAccounts)
            .map(|(_, batches)| batches)
            .collect();
        assert_eq!(
            commits,
            vec![1, 1],
            "one commit call per apply, each carrying one batch — the \
             second covers the update AND the delete"
        );
        assert_eq!(
            h.service_accounts
                .snapshot()
                .iter()
                .map(|sa| sa.name.clone())
                .collect::<Vec<_>>(),
            vec!["keeper".to_string()],
            "`doomed` is gone, `keeper` survives"
        );
        assert_eq!(
            sa_event_count(&authz_events(&h).await),
            4,
            "two Created from the first apply, one Updated and one Deleted \
             from the second — every row operation attested"
        );
    }

    /// An apply with no SA plan reaches the port **not at all** — no
    /// row to write, no event to append, so no transaction.
    #[tokio::test]
    async fn apply_service_account_empty_plan_opens_no_commit() {
        let h = build_harness();
        h.uc.apply(DesiredState::default(), env_oidc())
            .await
            .unwrap();
        assert!(
            h.authority
                .commits()
                .into_iter()
                .all(|(site, _)| site != AuthoritySite::ServiceAccounts),
            "an empty SA plan must not open a transaction"
        );
    }

    // -- ServiceAccount apply ----------------------------------------------

    #[tokio::test]
    async fn apply_service_account_creates_backing_user_and_sa_row() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .service_accounts
            .push(service_account_env_for_apply("ci-pypi-pusher", None));
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
    async fn apply_service_account_reapply_is_idempotent_and_materialises_no_grants() {
        let h = build_harness();

        let env = service_account_env_for_apply("ci-pypi-pusher", None);
        let mut desired_a = DesiredState::default();
        desired_a.service_accounts.push(env.clone());
        h.uc.apply(desired_a, env_oidc()).await.unwrap();

        let mut desired_b = DesiredState::default();
        desired_b.service_accounts.push(env);
        h.uc.apply(desired_b, env_oidc()).await.unwrap();

        // Exactly one backing user and one SA row — re-applying must
        // not duplicate either.
        let users_page = h.users.list(PageRequest::new(0, 100)).await.unwrap();
        let sa_users: Vec<_> = users_page
            .items
            .iter()
            .filter(|u| u.is_service_account)
            .collect();
        assert_eq!(sa_users.len(), 1, "exactly one SA backing user");
        assert_eq!(h.service_accounts.snapshot().len(), 1, "exactly one SA row");
        // The envelope is identity + federation binding only: with no
        // `PermissionGrant` envelopes in the desired set, the managed
        // grant partition stays empty — no authority is materialised
        // from the SA declaration itself.
        let managed = h.grant_repo.managed_snapshot();
        assert!(
            managed.is_empty(),
            "an SA envelope must materialise no grants: {managed:?}"
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
        let mut desired = DesiredState::default();
        desired
            .service_accounts
            .push(service_account_env_for_apply("maintainer-dev", None));
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
        let build = || {
            let mut d = DesiredState::default();
            d.service_accounts
                .push(service_account_env_for_apply("maintainer-dev", None));
            d.permission_grants.push(sa_grant_env(
                "maintainer-dev-global-read",
                "maintainer-dev",
                "read",
                None,
            ));
            d
        };

        h.uc.apply(build(), env_oidc()).await.unwrap();
        // Managed set after first apply: exactly the standalone global
        // grant — the SA envelope itself materialises nothing.
        let first = h.grant_repo.managed_snapshot();
        let first_count = first.len();
        assert_eq!(first_count, 1, "exactly the standalone global grant");
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
        // Exactly one grant reconcile per apply (two total).
        assert_eq!(h.grant_repo.reconcile_call_count(), 2);
    }

    #[tokio::test]
    async fn apply_repo_scoped_service_account_curate_grant_resolves() {
        // Repo-scoped `curate` resolves to User(backing) scoped to the
        // repo.
        let h = build_harness();
        // Declare the repo in the bundle (let the apply create it) so the
        // grant's `spec.repository` cross-spec reference resolves; a
        // pre-seeded harness row would collide with the managed upsert.
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("oci-prod", "hosted"));
        desired
            .service_accounts
            .push(service_account_env_for_apply("maintainer-curator", None));
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
        // resolved backing user is SA-owned (provenance-justified), so
        // the linter exempts it.
        let h = build_harness_with_lint_config(crate::lint::LintConfig::default());
        let mut desired = DesiredState::default();
        desired
            .service_accounts
            .push(service_account_env_for_apply("maintainer-dev", None));
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
        assert_eq!(h.grant_repo.reconcile_call_count(), 0);
    }

    #[tokio::test]
    async fn apply_service_account_with_unknown_issuer_fails_validation() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "ci-pypi-pusher",
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
        // OidcIssuer declared in the same apply — the FK check accepts
        // either snapshot or desired, with desired winning.
        let mut desired = DesiredState::default();
        desired
            .oidc_issuers
            .push(oidc_issuer_env_for_apply("github-actions"));
        desired.service_accounts.push(service_account_env_for_apply(
            "ci-pypi-pusher",
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
        issuer: &str,
    ) -> Envelope<ServiceAccountSpec> {
        let mut claims = BTreeMap::new();
        claims.insert("repository".into(), "my-org/my-repo".into());
        claims.insert("environment".into(), "production".into());
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::ServiceAccount,
            metadata: Metadata {
                name: sa_name.into(),
            },
            spec: ServiceAccountSpec {
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
            let mut desired = DesiredState::default();
            desired
                .oidc_issuers
                .push(oidc_issuer_env_for_apply("github-actions"));
            // `service_account_env_for_apply(..., Some(_))` builds an FI
            // with ONLY a `repository` claim — the under-constrained shape
            // (no ref/environment/workflow/aud discriminator).
            desired.service_accounts.push(service_account_env_for_apply(
                "ci-loose",
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
            let mut desired = DesiredState::default();
            desired
                .oidc_issuers
                .push(oidc_issuer_env_for_apply("github-actions"));
            desired
                .service_accounts
                .push(service_account_env_well_constrained(
                    "ci-tight",
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
        h.oidc_issuers.upsert_row(&snapshot_issuer);
        // Build a desired with the SA still referencing `legacy-idp` but
        // NO OidcIssuer envelopes — the issuer is being deleted by
        // omission.
        let mut desired = DesiredState::default();
        desired.service_accounts.push(service_account_env_for_apply(
            "legacy-sa",
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
        let env = service_account_env_for_apply("ci-pypi-pusher", None);
        let mut desired = DesiredState::default();
        desired.service_accounts.push(env);
        h.uc.apply(desired, env_oidc()).await.unwrap();
        assert!(h
            .users
            .find_by_username("sa:ci-pypi-pusher")
            .await
            .unwrap()
            .is_some());

        // Re-apply with no SA — the delete sweep removes exactly the
        // SA row.
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(
            report.deleted, 1,
            "only the SA row contributes to report.deleted"
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
