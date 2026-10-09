use super::*;

impl ApplyConfigUseCase {
    /// Consolidated PermissionGrant reconcile (ADR 0012).
    ///
    /// [`AuthorityLifecyclePort::commit_permission_grants`] reconciles
    /// the **entire** `managed_by = gitops` partition (delete-absent +
    /// upsert-present, keyed on the subject-dependent identity —
    /// `(sorted required_claims, repository_id, permission)` for
    /// `Claims`; `(user_id, repository_id, permission)` for `User`)
    /// **and** appends the audit batches, in one transaction.
    /// The `PermissionGrant` envelopes are the single authority source
    /// — a `ServiceAccount` envelope materialises no grants (identity +
    /// federation binding only; SA authority is declared as explicit
    /// `serviceAccount`-subject grant envelopes, ADR 0037).
    ///
    /// Steps:
    ///
    /// 1. build the complete desired set: every `desired.permission_grants`
    ///    envelope mapped to a domain `PermissionGrant` (with the
    ///    sum-typed [`GrantSubject`]; a `serviceAccount` subject
    ///    resolves to `GrantSubject::User(backing_user_id)`);
    /// 2. diff the prior managed set (`list_managed_by_gitops`) against
    ///    the desired set by subject-dependent identity to emit one
    ///    `PermissionGrantApplied` per added-or-changed row and one
    ///    `PermissionGrantRevoked` per removed row, routed to
    ///    `StreamCategory::Repository(r)` for a repo-scoped grant or
    ///    `StreamCategory::Authorization` for a global grant
    ///    (audit-event-per-mutation invariant — there is no `role_id`;
    ///    the subject is the `GrantSubjectRecord` payload);
    /// 3. commit the complete set + every per-stream batch once.
    ///
    /// **Failure mode (changed).** A failure on either side leaves the
    /// partition **unchanged** — the apply aborts fail-closed instead
    /// of half-done, and the multi-stream batch list commits as one
    /// unit (no "some repository streams audited, others not"). Before
    /// the port, an append failure after a committed row write left
    /// the grant live with nothing attesting it, and the retry
    /// could not repair that: the next apply diffs against the
    /// already-changed rows and emits nothing.
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
        // identity (the same key the reconcile upserts on). The
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
                    // linter rule. Without this a serviceAccount grant
                    // (the audited operator path for read / write / curate
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

        // ---- permission-grant linter (ADR 0015) ----
        //
        // This linter is the load-bearing mitigation for
        // additive-claims' deliberate loss of *server-enforced*
        // "every grant has both legs". It runs over the fully-built
        // desired set AND the desired `claim_mappings`,
        // BEFORE the whole-partition commit and BEFORE any audit event
        // is constructed. The metric
        // (`hort_apply_config_linter_total{rule,result}`) is emitted
        // per (grant|row, rule) evaluation inside the linter, and this is
        // its only emission site: the port-built desired set is the real
        // one, so it is the one the series describes.
        //
        // The REJECTION, however, is not this stage's to raise first. This
        // stage runs after the repository, policy and mapping writes, and
        // the apply ships no rollback — so a grant refused here used to
        // leave a loosening from the same bundle committed. The pre-write
        // pass therefore rejects on the same rules (its row 8), over an
        // expansion with placeholder ids whose verdict is provably the same
        // because no rule reads an id value. What survives here is the
        // gate over the real set: reaching a `Reject` at this point would
        // mean the two expansions disagreed, which is a contract violation
        // rather than operator error — and the strict-atomic abort below
        // still holds the line if it ever happens.
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

        // Per-envelope report + metric counters from the diff plan.
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

        // Whole-partition delete-absent + upsert-present (covers
        // envelope grants AND SA-owned grants) AND every per-stream
        // audit batch, in one transaction.
        let batches = Self::grouped_authorization_batches(
            authz_events_by_stream,
            Kind::PermissionGrant,
            token,
        );
        let total_pg_events: usize = batches.iter().map(|b| b.events.len()).sum();
        let streams = batches.len();
        self.authority
            .commit_permission_grants(&desired_set, batches)
            .await?;

        // Emitted AFTER the commit returned `Ok`, because that is the
        // first point at which "committed" is true. The same line used
        // to run before the row write and the append, so an apply that
        // died in between left an operator-visible claim that the audit
        // events had landed when none had.
        if total_pg_events > 0 {
            tracing::info!(
                kind = "permission_grant",
                events = total_pg_events,
                streams,
                "permission_grant audit events committed"
            );
        }
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
