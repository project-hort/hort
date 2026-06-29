use super::*;

impl ApplyConfigUseCase {
    /// Consolidated PermissionGrant reconcile (ADR 0012).
    ///
    /// `PermissionGrantRepository::save_managed` reconciles the **entire**
    /// `managed_by = gitops` partition (atomic delete-absent +
    /// upsert-present, keyed on the subject-dependent identity —
    /// `(sorted required_claims, repository_id, permission)` for
    /// `Claims`; `(user_id, repository_id, permission)` for `User`). The
    /// envelope-declared grants AND the ServiceAccount-owned
    /// `User`-subject grants therefore MUST be unioned into one
    /// call — two independent writers would delete each other's rows.
    ///
    /// Steps:
    ///
    /// 1. build the complete desired set: every `desired.permission_grants`
    ///    envelope mapped to a domain `PermissionGrant` (with the
    ///    sum-typed [`GrantSubject`]), plus one
    ///    `GrantSubject::User(backing_user_id)` row per
    ///    `(ServiceAccount, repo)` pair (the role
    ///    bundle is code-expanded by `service_account_permission_for_role`,
    ///    NOT a `claim_mappings` consultation, NOT a `Claims` subject);
    /// 2. diff the prior managed set (`list_managed_by_gitops`) against
    ///    the desired set by subject-dependent identity to emit one
    ///    `PermissionGrantApplied` per added-or-changed row and one
    ///    `PermissionGrantRevoked` per removed row, routed to
    ///    `StreamCategory::Repository(r)` for a repo-scoped grant or
    ///    `StreamCategory::Authorization` for a global grant
    ///    (audit-event-per-mutation invariant — there is no `role_id`;
    ///    the subject is the `GrantSubjectRecord` payload);
    /// 3. `save_managed(&complete_set)` once.
    ///
    /// Diff-then-emit failure-mode contract preserved:
    /// a `save_managed` failure aborts the apply before any audit event
    /// lands; an append failure after a successful save surfaces the
    /// apply error and the next apply re-runs the (now no-op) diff.
    pub(super) async fn apply_permission_grants(
        &self,
        plan: &KindPlan<PermissionGrantSpec, Uuid>,
        desired: &DesiredState,
        // The effective `LintConfig` resolved by
        // `resolve_effective_lint_config` BEFORE this call (so a
        // same-bundle allowlist-then-use commits). Passed in rather
        // than read off `&self.lint_config` so the bundle's
        // lint-config partition is honored in the same apply; a private
        // helper parameter, NOT a port-contract change (the public
        // `ApplyConfigUseCase::new` signature is unchanged).
        lint_config: &crate::lint::LintConfig,
        report: &mut ApplyReport,
        token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        // Prior gitops-managed grant set, keyed by subject-dependent
        // identity (the same key `save_managed` upserts on). The
        // surrogate id + digest carry through so re-applies are stable
        // and the audit `grant_id` matches the existing row.
        let prior = self.permission_grants.list_managed_by_gitops().await?;
        let prior_by_identity: HashMap<GrantIdentityKey, PermissionGrant> = prior
            .into_iter()
            .map(|g| {
                (
                    grant_identity_key(&g.subject, g.repository_id, g.permission),
                    g,
                )
            })
            .collect();

        // ---- complete desired set ----
        let mut desired_set: Vec<PermissionGrant> = Vec::new();
        let mut desired_identities: HashSet<GrantIdentityKey> = HashSet::new();
        // Backing-user ids of SA-owned
        // `User`-subject grants (the legitimate auto-synthesised
        // direct-user path). The linter's
        // `direct-user-grant-without-justification` rule exempts these
        // (justified by provenance); a bare operator-hand-declared
        // `User` grant whose uid is NOT here is the shape that rule
        // rejects.
        let mut sa_owned_user_ids: HashSet<Uuid> = HashSet::new();

        // (a) envelope-declared grants.
        for env in &desired.permission_grants {
            let digest = spec_digest_permission_grant(&env.spec);
            let permission = Permission::from_str(&env.spec.permission).map_err(|_| {
                // Unreachable in practice: `validate_permission_grant`
                // gated the permission string before the apply stage.
                DomainError::Invariant(format!(
                    "PermissionGrant `{}` carries permission `{}` that should have been \
                     rejected by validate_permission_grant",
                    env.metadata.name, env.spec.permission
                ))
            })?;
            let repository_id = match env.spec.repository.as_deref() {
                Some(name) => Some(self.repositories.find_by_key(name).await?.id),
                None => None,
            };
            let subject = match &env.spec.subject {
                GrantSubjectSpec::Claims { required } => {
                    let mut sorted = required.clone();
                    sorted.sort();
                    GrantSubject::Claims(sorted)
                }
                GrantSubjectSpec::User { user_id } => {
                    let uid = Uuid::parse_str(user_id.trim()).map_err(|_| {
                        DomainError::Validation(format!(
                            "PermissionGrant `{}` subject.userId `{}` is not a valid UUID",
                            env.metadata.name, user_id
                        ))
                    })?;
                    GrantSubject::User(uid)
                }
                GrantSubjectSpec::ServiceAccount { name } => {
                    // Gitops-spec sugar: resolve the named ServiceAccount
                    // to its backing-user UUID and materialise the grant
                    // as `GrantSubject::User(backing_user_id)` — the
                    // domain taxonomy stays two-variant (ADR 0012/0037).
                    // `apply_service_accounts` ran earlier in this apply
                    // (Stage above), so the SA aggregate + backing user
                    // exist and resolve here. A dangling name is rejected
                    // cross-spec at validate-time (`DanglingReference`).
                    let sa = self
                        .service_accounts
                        .get_by_name(name)
                        .await?
                        .ok_or_else(|| {
                            DomainError::Validation(format!(
                                "PermissionGrant `{}` subject.serviceAccount `{name}` names no \
                                 declared ServiceAccount — define the ServiceAccount in gitops \
                                 and apply first",
                                env.metadata.name
                            ))
                        })?;
                    let backing_user_id = sa.backing_user_id;
                    // This backing user-id is an SA-owned
                    // (provenance-justified) direct-user subject — exempt
                    // it from the `direct-user-grant-without-justification`
                    // linter rule, exactly like the SA-role-derived grants
                    // in step (b). Without this a global serviceAccount
                    // grant (the audited operator path for global / curate
                    // / admin_task_invoke authority) would trip the
                    // high-privilege reject arm.
                    sa_owned_user_ids.insert(backing_user_id);
                    GrantSubject::User(backing_user_id)
                }
            };
            self.push_desired_grant(
                subject,
                repository_id,
                permission,
                digest,
                &prior_by_identity,
                &mut desired_set,
                &mut desired_identities,
            );
        }

        // (b) ServiceAccount-owned `User`-subject grants.
        // The role bundle is code-expanded over the fixed
        // {developer, reader} enum — never a `claim_mappings`
        // consultation, never a `Claims` subject.
        // `apply_service_accounts` (the pass before this consolidated
        // reconcile) has already upserted the SA aggregate + backing
        // user, so both resolve here.
        for env in &desired.service_accounts {
            let permission = service_account_permission_for_role(&env.spec.role)?;
            let sa = self
                .service_accounts
                .get_by_name(&env.metadata.name)
                .await?
                .ok_or_else(|| {
                    DomainError::Invariant(format!(
                        "ServiceAccount `{}` not found after apply_service_accounts — \
                         the SA aggregate pass must run before the grant reconcile",
                        env.metadata.name
                    ))
                })?;
            let backing_user_id = sa.backing_user_id;
            // This backing user-id is an SA-owned
            // (provenance-justified) direct-user subject — exempt from
            // the `direct-user-grant-without-justification` linter rule.
            sa_owned_user_ids.insert(backing_user_id);
            // SA-owned digest: keyed on `sa.id` and stable across YAML
            // repo re-orderings — byte-identical to the snapshot's
            // `sa_owned_grant_digests` canonical form
            // (`sha256("sa-grant|{sa.id}|{role}|{permission}|{sorted_repos}")`,
            // computed in `build_snapshot`), so the diff layer's
            // SA-exclusion keeps these rows out of
            // the per-envelope PG plan while this consolidated reconcile
            // owns their lifecycle.
            let mut sorted_repos: Vec<&str> =
                env.spec.repositories.iter().map(String::as_str).collect();
            sorted_repos.sort_unstable();
            let canonical = format!(
                "sa-grant|{}|{}|{}|{}",
                sa.id,
                env.spec.role,
                permission,
                sorted_repos.join(",")
            );
            let digest = sha256_of(&canonical);
            for repo_name in &env.spec.repositories {
                let repository_id = Some(self.repositories.find_by_key(repo_name).await?.id);
                self.push_desired_grant(
                    GrantSubject::User(backing_user_id),
                    repository_id,
                    permission,
                    digest,
                    &prior_by_identity,
                    &mut desired_set,
                    &mut desired_identities,
                );
            }
        }

        // ---- permission-grant linter (ADR 0015) ----
        //
        // This linter is the load-bearing mitigation for
        // additive-claims' deliberate loss of *server-enforced*
        // "every grant has both legs". It runs over the fully-built
        // desired set (envelope grants ∪ SA-owned
        // `User`-subject grants) AND the desired `claim_mappings`,
        // BEFORE the whole-partition `save_managed` commit and BEFORE
        // any audit event is constructed — a `Reject` aborts the
        // apply strict-atomic so no row and no `PermissionGrantApplied`
        // / `ClaimMappingApplied` event lands. The metric
        // (`hort_apply_config_linter_total{rule,result}`) is emitted
        // per (grant|row, rule) evaluation inside the linter.
        let desired_claim_mappings: Vec<ClaimMapping> = desired
            .claim_mappings
            .iter()
            .map(|env| ClaimMapping {
                // The `claim-name-collision` rule reads only `claim`;
                // id / managed_by / digest are irrelevant to it, so a
                // minimal projection keeps the linter pure over its
                // inputs without a prior-set lookup or digest work.
                id: Uuid::new_v4(),
                idp_group: env.spec.idp_group.clone(),
                claim: env.spec.claim.clone(),
                managed_by: ManagedBy::GitOps,
                managed_by_digest: None,
            })
            .collect();
        let lint_outcome = crate::lint::lint_permission_grants(
            &desired_set,
            &desired_claim_mappings,
            &sa_owned_user_ids,
            lint_config,
        );
        if lint_outcome.rejected() {
            let reject_rules: Vec<&str> = lint_outcome
                .violations
                .iter()
                .filter(|v| v.action == crate::lint::RuleAction::Reject)
                .map(|v| v.rule)
                .collect();
            tracing::error!(
                rejected_rules = ?reject_rules,
                "gitops apply: permission-grant linter rejected the desired set \
                 (secure-by-default — operator allowlist/downgrade \
                 is the only escape hatch)"
            );
            return Err(AppError::Domain(DomainError::Validation(format!(
                "apply-config linter rejected {} grant/claim-mapping rule \
                 violation(s): [{}]. The secure-by-default posture rejects \
                 single-claim, wildcard-repo-non-admin, unjustified \
                 high-privilege direct-user grants, and reserved-claim-name \
                 collisions; relax via an explicit, audited operator \
                 LintConfig downgrade.",
                reject_rules.len(),
                reject_rules.join(", ")
            ))));
        }

        // ---- audit diff: applied (added/changed) + revoked (removed) ----
        let mut authz_events_by_stream: HashMap<StreamId, Vec<EventToAppend>> = HashMap::new();
        for grant in &desired_set {
            let identity =
                grant_identity_key(&grant.subject, grant.repository_id, grant.permission);
            let changed = match prior_by_identity.get(&identity) {
                None => true,
                Some(prev) => prev.managed_by_digest != grant.managed_by_digest,
            };
            if changed {
                let stream_id = match grant.repository_id {
                    Some(r) => StreamId::repository(r),
                    None => StreamId::authorization(),
                };
                authz_events_by_stream
                    .entry(stream_id)
                    .or_default()
                    .push(EventToAppend::new(DomainEvent::PermissionGrantApplied(
                        PermissionGrantApplied {
                            grant_id: grant.id,
                            subject: GrantSubjectRecord::from_subject(&grant.subject),
                            permission: grant.permission,
                            repository_id: grant.repository_id,
                        },
                    )));
            }
        }
        for (identity, prev) in &prior_by_identity {
            if !desired_identities.contains(identity) {
                let stream_id = match prev.repository_id {
                    Some(r) => StreamId::repository(r),
                    None => StreamId::authorization(),
                };
                authz_events_by_stream
                    .entry(stream_id)
                    .or_default()
                    .push(EventToAppend::new(DomainEvent::PermissionGrantRevoked(
                        PermissionGrantRevoked {
                            grant_id: prev.id,
                            subject: GrantSubjectRecord::from_subject(&prev.subject),
                            permission: prev.permission,
                            repository_id: prev.repository_id,
                        },
                    )));
            }
        }

        // Per-envelope report + metric counters from the diff plan. The
        // diff layer already excludes SA-owned digests from the PG plan
        // (`sa_owned_grant_digests`), so the
        // SA-owned rows do not double-count here; their lifecycle is
        // attested by the audit diff above.
        for _ in &plan.create {
            emit_gitops_object(gitops_kind::PERMISSION_GRANT, GitopsObjectResult::Created);
            report.created += 1;
        }
        for _ in &plan.update {
            emit_gitops_object(gitops_kind::PERMISSION_GRANT, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        for _ in &plan.delete {
            emit_gitops_object(gitops_kind::PERMISSION_GRANT, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        let total_pg_events: usize = authz_events_by_stream.values().map(Vec::len).sum();
        if total_pg_events > 0 {
            tracing::info!(
                kind = "permission_grant",
                events = total_pg_events,
                streams = authz_events_by_stream.len(),
                "permission_grant audit events committed"
            );
        }

        // Whole-partition atomic delete-absent + upsert-present (covers
        // envelope grants AND SA-owned grants in one transaction).
        self.permission_grants.save_managed(&desired_set).await?;

        self.append_grouped_authorization_events(
            authz_events_by_stream,
            Kind::PermissionGrant,
            token,
        )
        .await?;
        Ok(())
    }

    /// Push one desired grant into the reconcile set, reusing the prior
    /// row's surrogate id when an identity-equal managed row exists
    /// (stable `grant_id` across re-applies; fresh UUID otherwise).
    #[allow(clippy::too_many_arguments)]
    fn push_desired_grant(
        &self,
        subject: GrantSubject,
        repository_id: Option<Uuid>,
        permission: Permission,
        digest: [u8; 32],
        prior_by_identity: &HashMap<GrantIdentityKey, PermissionGrant>,
        desired_set: &mut Vec<PermissionGrant>,
        desired_identities: &mut HashSet<GrantIdentityKey>,
    ) {
        let identity = grant_identity_key(&subject, repository_id, permission);
        let id = prior_by_identity
            .get(&identity)
            .map(|p| p.id)
            .unwrap_or_else(Uuid::new_v4);
        let created_at = prior_by_identity
            .get(&identity)
            .map(|p| p.created_at)
            .unwrap_or_else(Utc::now);
        desired_identities.insert(identity);
        desired_set.push(PermissionGrant {
            id,
            subject,
            repository_id,
            permission,
            created_at,
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some(digest),
        });
    }
}

/// Map a service-account role name to the matching `Permission`. The
/// apply-time validator gates `role ∈ {developer, reader}`, so any
/// other value reaching this helper is an `Invariant`.
///
/// - `developer` → `Permission::Write` (by convention
///   developer = read+write+delete, with `Write` standing in
///   for the bundled grant because the `Permission` enum is flat).
/// - `reader` → `Permission::Read`.
///
/// `pub` so cross-crate callers (notably the `hort-http-core` federation
/// `/api/v1/token/exchange` handler, which mints SA tokens from
/// validated JWTs) can stamp the federation token's
/// `declared_permissions` from the same role-mapping table the apply
/// pipeline uses; otherwise the federation cap leg of
/// `RbacEvaluator::authorize` denies every check (empty cap permissions
/// never `contains(&requested)` — see `cap_allows_optional_repo`).
pub fn service_account_permission_for_role(role: &str) -> Result<Permission, DomainError> {
    match role {
        "developer" => Ok(Permission::Write),
        "reader" => Ok(Permission::Read),
        other => Err(DomainError::Invariant(format!(
            "service-account role `{other}` is not in {{developer, reader}}"
        ))),
    }
}
