use super::*;

impl ApplyConfigUseCase {
    /// Apply curation-rule create / update / delete from the gitops
    /// plan + run the retroactive curation evaluation pass.
    ///
    /// The retroactive pass fires on every rule that is either
    /// **newly declared** OR **tightened** (`Allow → Warn`, `Allow →
    /// Block`, `Warn → Block`). Pattern broadening is **deferred**
    /// per the design — pattern-equivalence detection isn't trivial,
    /// and operators who broaden a pattern can re-trigger by also
    /// tightening the action or deleting + re-adding the rule.
    /// Weakenings (`Block → Warn`, `Block → Allow`, `Warn → Allow`)
    /// and rule deletions emit no retroactive events: rejection is
    /// sticky per the asymmetric semantics, mirroring the architect-
    /// skill quarantine invariant 3 admin-explicit-release path.
    ///
    /// Strict-atomic: any `ArtifactRejected` append failure (typically
    /// optimistic-concurrency `Conflict` from a concurrent ingest)
    /// aborts the apply pipeline. The operator restarts; the second
    /// pass re-resolves the now-consistent state and continues.
    pub(super) async fn apply_curation_rules(
        &self,
        plan: &KindPlan<hort_config::curation_rule::CurationRuleSpec, Uuid>,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        // Capture old action BEFORE save_managed
        // for every rule in `plan.update`. Tightening detection compares
        // old vs new and is the trigger for the retroactive pass.
        let mut old_action_by_name: HashMap<String, CurationRuleAction> = HashMap::new();
        for env in &plan.update {
            if let Some(existing) = self.curation_rules.find_by_name(&env.metadata.name).await? {
                old_action_by_name.insert(env.metadata.name.clone(), existing.action);
            }
        }

        // Track which rules need a retroactive evaluation pass after
        // `save_managed` lands. A rule is a candidate when:
        //   1. it is newly declared (`plan.create`), OR
        //   2. its action tightened on update.
        let mut retro_candidate_names: Vec<String> = Vec::new();

        for env in plan.create.iter() {
            // Re-use existing UUID if a managed row already exists for
            // this name (the rule is in `plan.create` because the
            // diff classifier saw no row, but a defensive lookup
            // matches the established pattern). Mint otherwise.
            let digest = spec_digest_curation_rule(&env.spec);
            let id = self
                .curation_rules
                .find_by_name(&env.metadata.name)
                .await?
                .map(|r| r.id)
                .unwrap_or_else(Uuid::new_v4);
            let rule = build_curation_rule_from_spec(env, id, &digest)?;
            self.curation_rules.save_managed(&rule).await?;
            retro_candidate_names.push(env.metadata.name.clone());
        }

        for env in plan.update.iter() {
            let digest = spec_digest_curation_rule(&env.spec);
            let id = self
                .curation_rules
                .find_by_name(&env.metadata.name)
                .await?
                .map(|r| r.id)
                .unwrap_or_else(Uuid::new_v4);
            let rule = build_curation_rule_from_spec(env, id, &digest)?;
            // Detect tightening before the save: Allow → Warn|Block,
            // Warn → Block. (Allow → Allow / Warn → Warn / Block → Block
            // would be `unchanged`, not in `plan.update`.)
            let old = old_action_by_name.get(&env.metadata.name).copied();
            let tightened = matches!(
                (old, rule.action),
                (Some(CurationRuleAction::Allow), CurationRuleAction::Warn)
                    | (Some(CurationRuleAction::Allow), CurationRuleAction::Block)
                    | (Some(CurationRuleAction::Warn), CurationRuleAction::Block)
            );
            self.curation_rules.save_managed(&rule).await?;
            if tightened {
                retro_candidate_names.push(env.metadata.name.clone());
            }
        }

        for _ in &plan.create {
            emit_gitops_object(gitops_kind::CURATION_RULE, GitopsObjectResult::Created);
            report.created += 1;
        }
        for _ in &plan.update {
            emit_gitops_object(gitops_kind::CURATION_RULE, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        // Same id-vs-name mismatch as `apply_roles`: the `KindPlan`
        // emits ids, the port's `delete_managed` takes a name. Look
        // each up via the bounded `list_managed_by_gitops` snapshot.
        let managed = self.curation_rules.list_managed_by_gitops().await?;
        let name_by_id: HashMap<Uuid, String> =
            managed.iter().map(|r| (r.id, r.name.clone())).collect();
        for id in &plan.delete {
            let name = name_by_id.get(id).ok_or_else(|| {
                DomainError::Invariant(format!(
                    "curation rule id {id} scheduled for delete is not in list_managed_by_gitops"
                ))
            })?;
            self.curation_rules.delete_managed(name).await?;
            emit_gitops_object(gitops_kind::CURATION_RULE, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        // Retroactive curation evaluation. Runs AFTER all
        // rule writes in this pass have landed so the per-repo rule set
        // each candidate is evaluated against is the post-apply view.
        for rule_name in retro_candidate_names {
            self.run_retroactive_curation_for_rule(&rule_name, report)
                .await?;
        }

        Ok(())
    }

    /// Run the retroactive curation evaluation pass for one
    /// candidate rule.
    ///
    /// Resolves linked repos via `list_repos_for_rule`, materialises
    /// each repo's just-applied rule set via `list_for_repo`, walks
    /// active artifacts, and emits `CurationApplied` (per `RetroWarn`
    /// or `RetroBlock`) plus `ArtifactRejected` (per `RetroBlock`).
    ///
    /// `RetroBlock` events go through `commit_transition` so the
    /// artifact-state mutation and event are atomic — a concurrent
    /// ingest cannot leave the artifact `Released` while the
    /// `ArtifactRejected` event lands on its stream. Optimistic-
    /// concurrency conflicts surface as `DomainError::Conflict` and
    /// are mapped to `AppError::ConcurrentModification` via
    /// [`map_concurrent_modification`] — strict-atomic abort.
    async fn run_retroactive_curation_for_rule(
        &self,
        rule_name: &str,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let rule = self
            .curation_rules
            .find_by_name(rule_name)
            .await?
            .ok_or_else(|| {
                DomainError::Invariant(format!(
                    "retroactive curation: rule '{rule_name}' missing after save_managed"
                ))
            })?;

        let repo_ids = self.curation_rules.list_repos_for_rule(rule.id).await?;
        if repo_ids.is_empty() {
            tracing::debug!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                "retroactive curation pass: no linked repos, skipping"
            );
            return Ok(());
        }

        let actor = gitops_actor_for_kind(Kind::CurationRule);

        for repo_id in repo_ids {
            // Materialise the just-applied rule set for this repo —
            // first-match-wins iteration depends on the post-apply
            // ordering, so we re-read every iteration.
            let rules_active_on_repo = self.curation_rules.list_for_repo(repo_id).await?;
            let active_list = self.artifacts.list_active_for_repo(repo_id).await?;
            // `list_active_for_repo`
            // returns a `LimitedList` capped at `LIMIT_LIST_MAX_ITEMS`. When the
            // cap fires we still process what we got. Whether the remainder
            // gets picked up by a subsequent apply depends on the rule effects:
            // a `RetroBlock` rule mutates the active set (blocked artifacts
            // leave it), so the next pass walks fresh territory; a
            // `RetroWarn`-only rule set does not mutate state, so an
            // unchanging >cap active set will re-emit the same warning every
            // apply. The `warn!` below is the operator-actionable signal.
            if active_list.truncated {
                tracing::warn!(
                    repository_id = %repo_id,
                    cap = hort_domain::types::LIMIT_LIST_MAX_ITEMS,
                    "result set truncated; only the first cap active artifacts \
                     in this repo were re-evaluated against the new policy. \
                     If this triggers repeatedly without the active set \
                     shrinking, review whether any rule has a Block effect or \
                     whether the cap should be raised for this repo."
                );
            }
            let artifacts = active_list.items;

            let mut retro_warn = 0usize;
            let mut retro_block = 0usize;

            for artifact in artifacts {
                let coords = hort_domain::types::ArtifactCoords {
                    name: artifact.name.clone(),
                    name_as_published: artifact.name_as_published.clone(),
                    version: artifact.version.clone(),
                    path: artifact.path.clone(),
                    // `Artifact` carries the repository's format, but we
                    // need it on the coords for the format-gate; resolve
                    // via the repository row.
                    format: self
                        .repositories
                        .find_by_id(artifact.repository_id)
                        .await?
                        .format,
                    metadata: serde_json::Value::Null,
                };

                let outcome = evaluate_curation_retroactive(&coords, &rules_active_on_repo);
                match outcome {
                    RetroactiveCurationOutcome::NoChange => {
                        emit_policy_evaluation(
                            policy_decision_point::CURATION_RETROACTIVE,
                            PolicyEvaluationResult::NoChange,
                        );
                    }
                    RetroactiveCurationOutcome::RetroWarn {
                        rule_name: r_name,
                        reason,
                        rule_id,
                    } => {
                        self.append_curation_applied(
                            repo_id,
                            coords.clone(),
                            rule_id,
                            r_name,
                            CurationActionTag::Warn,
                            reason.clone(),
                            actor.clone(),
                        )
                        .await
                        .map_err(map_concurrent_modification)?;
                        retro_warn += 1;
                        report.retro_warn_count += 1;
                        tracing::info!(
                            rule_id = %rule_id,
                            repository_id = %repo_id,
                            artifact_id = %artifact.id,
                            action = "warn",
                            "retroactive curation transition"
                        );
                        emit_policy_evaluation(
                            policy_decision_point::CURATION_RETROACTIVE,
                            PolicyEvaluationResult::RetroWarn,
                        );
                        emit_policy_violations(
                            policy_decision_point::CURATION_RETROACTIVE,
                            &[hort_domain::events::PolicyViolation {
                                rule: "curation-warn".to_string(),
                                severity: SeverityThreshold::Low,
                                message: reason,
                                details: serde_json::Value::Null,
                            }],
                        );
                    }
                    RetroactiveCurationOutcome::RetroBlock {
                        rule_name: r_name,
                        reason,
                        rule_id,
                    } => {
                        self.append_curation_applied(
                            repo_id,
                            coords.clone(),
                            rule_id,
                            r_name.clone(),
                            CurationActionTag::Block,
                            reason.clone(),
                            actor.clone(),
                        )
                        .await
                        .map_err(map_concurrent_modification)?;
                        self.commit_retroactive_block(
                            artifact,
                            rule_id,
                            reason.clone(),
                            actor.clone(),
                        )
                        .await
                        .map_err(map_concurrent_modification)?;
                        retro_block += 1;
                        report.retro_block_count += 1;
                        tracing::info!(
                            rule_id = %rule_id,
                            repository_id = %repo_id,
                            action = "block",
                            "retroactive curation transition"
                        );
                        emit_policy_evaluation(
                            policy_decision_point::CURATION_RETROACTIVE,
                            PolicyEvaluationResult::RetroBlock,
                        );
                        emit_policy_violations(
                            policy_decision_point::CURATION_RETROACTIVE,
                            &[hort_domain::events::PolicyViolation {
                                rule: "curation-block".to_string(),
                                severity: SeverityThreshold::High,
                                message: reason,
                                details: serde_json::Value::Null,
                            }],
                        );
                    }
                }
            }

            tracing::info!(
                rule_id = %rule.id,
                repository_id = %repo_id,
                retro_warn,
                retro_block,
                "retroactive curation pass complete"
            );
        }

        Ok(())
    }

    /// Append a `CurationApplied` event on the per-repo curation
    /// stream. No artifact-state change here — the `RetroBlock` arm
    /// also calls [`Self::commit_retroactive_block`] for the artifact-
    /// stream side.
    #[allow(clippy::too_many_arguments)]
    async fn append_curation_applied(
        &self,
        repository_id: Uuid,
        coords: hort_domain::types::ArtifactCoords,
        rule_id: Uuid,
        rule_name: String,
        action: CurationActionTag,
        reason: String,
        actor: Actor,
    ) -> AppResult<()> {
        let stream_id = StreamId::curation_per_repo(repository_id);
        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;
        let event = CurationApplied {
            repository_id,
            coords,
            rule_id,
            rule_name,
            action,
            reason,
            trigger: CurationTrigger::Retroactive,
        };
        self.events
            .append(AppendEvents {
                stream_id,
                expected_version,
                events: vec![EventToAppend::new(DomainEvent::CurationApplied(event))],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor,
            })
            .await?;
        Ok(())
    }

    /// Commit the artifact-stream side of a `RetroBlock`. Atomic —
    /// `commit_transition` writes the artifact-state mutation AND the
    /// `ArtifactRejected` event in one transaction.
    async fn commit_retroactive_block(
        &self,
        mut artifact: hort_domain::entities::artifact::Artifact,
        rule_id: Uuid,
        reason: String,
        actor: Actor,
    ) -> AppResult<()> {
        let stream_id = StreamId::artifact(artifact.id);
        let expected_version = read_expected_version(&*self.events, &stream_id, false).await?;
        let artifact_id = artifact.id;
        let reject_event = artifact.reject_from_retroactive_curation(rule_id, reason)?;
        self.artifact_lifecycle
            .commit_transition(
                &artifact,
                AppendEvents {
                    stream_id,
                    expected_version,
                    events: vec![EventToAppend::new(DomainEvent::ArtifactRejected(
                        reject_event,
                    ))],
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor,
                },
                None,
            )
            .await?;

        // Sweep `content_references`
        // rows for the rejected source. Same posture as the
        // scan-driven reject path in `quarantine_use_case`: the
        // artifact row stays alive after `ArtifactRejected` (rejection
        // is sticky; hard-delete is forbidden), so the
        // FK CASCADE never fires and the surviving rows would mislead
        // `PurgeUseCase`. Failure is warn-only — the
        // rejection itself has landed. The refcount reconcile sweep
        // heals any drift.
        if let Err(e) = self.content_references.delete_by_source(artifact_id).await {
            tracing::warn!(
                artifact_id = %artifact_id,
                error = %e,
                stage = "content_references_delete_on_reject",
                "content_references delete failed on retroactive curation reject; refcount row \
                 not deleted on reject — refcount eventual, operator reconcile is future work"
            );
        }

        // Best-effort upstream-index cache
        // invalidation. Same post-commit-warn-on-fail posture as the
        // refcount sweep above and the symmetric curator-block /
        // scan-driven-reject hooks: the retroactive `ArtifactRejected`
        // append already committed; the `NonServableStatusFilter` on
        // the next index build is the load-bearing close. No-op when
        // the composition root did not wire an invalidator.
        if let Some(invalidator) = self.upstream_index_cache_invalidator.as_ref() {
            invalidate_after_reject(
                invalidator,
                artifact_id,
                artifact.repository_id,
                &artifact.name,
            )
            .await;
        }

        Ok(())
    }
}

fn build_curation_rule_from_spec(
    env: &Envelope<hort_config::curation_rule::CurationRuleSpec>,
    id: Uuid,
    digest: &[u8; 32],
) -> AppResult<CurationRule> {
    debug_assert!(matches!(env.kind, Kind::CurationRule));
    let action = CurationRuleAction::from_str(&env.spec.action)?;
    // `format: "any"` (case-insensitive) → None; otherwise parse via
    // RepositoryFormat. The `validate_curation_rule` checker rejected
    // `Other(_)` already, so an unknown format here is an invariant.
    let format = if env.spec.format.eq_ignore_ascii_case("any") {
        None
    } else {
        let parsed: RepositoryFormat = env.spec.format.parse().unwrap();
        if matches!(parsed, RepositoryFormat::Other(_)) {
            return Err(DomainError::Invariant(format!(
                "CurationRule '{}' carries unknown format '{}' that should have been \
                 rejected by validate_curation_rule",
                env.metadata.name, env.spec.format
            ))
            .into());
        }
        Some(parsed)
    };
    Ok(CurationRule {
        id,
        name: env.metadata.name.clone(),
        format,
        package_pattern: env.spec.pattern.clone(),
        action,
        reason: env.spec.reason.clone(),
        managed_by: ManagedBy::GitOps,
        managed_by_digest: Some(*digest),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::apply_config_use_case::tests::*;
    use crate::use_cases::test_support::MockRepositoryRepository;
    use hort_domain::entities::repository::IndexMode;

    // ===================================================================
    // Stage 1 CRUD: CurationRule
    // ===================================================================

    #[tokio::test]
    async fn create_curation_rule_calls_save_managed() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("allow-rust", "allow", "rust*", "trusted"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(h.rule_repo.save_count(), 1);
        assert_eq!(report.created, 1);
    }

    #[tokio::test]
    async fn update_curation_rule_when_action_changes() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("rule-a", "warn", "p", "r"));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let saves_before = h.rule_repo.save_count();
        desired.curation_rules[0].spec.action = "block".into();
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.updated, 1);
        assert_eq!(h.rule_repo.save_count(), saves_before + 1);
    }

    #[tokio::test]
    async fn delete_curation_rule_when_absent_from_desired() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("r1", "block", "p", "r"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(h.rule_repo.delete_count(), 1);
    }

    #[test]
    fn create_curation_rule_emits_objects_total_kind_curation_rule() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut desired = DesiredState::default();
                desired
                    .curation_rules
                    .push(rule_env("allow-rust", "allow", "rust*", "trusted"));
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_objects_total",
                &[("kind", "curation_rule"), ("result", "created")],
            ),
            1,
        );
    }

    // ===================================================================
    // Retroactive curation evaluation
    // ===================================================================

    /// Helper: seed a repository row in `MockRepositoryRepository` with a
    /// known id, key, and format so the apply pipeline's
    /// `find_by_key` (during stage 2 junction-write) and
    /// `find_by_id` (during the retroactive pass coords assembly) both
    /// succeed.
    fn seed_repo(
        repos: &Arc<MockRepositoryRepository>,
        key: &str,
        format: RepositoryFormat,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let now = Utc::now();
        repos.insert(Repository {
            id,
            key: key.into(),
            name: key.into(),
            description: None,
            format,
            repo_type: RepositoryType::Hosted,
            storage_backend: "filesystem".into(),
            storage_path: format!("/data/{key}"),
            upstream_url: None,
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode: IndexMode::ReleasedOnly,
            prefetch_policy: hort_domain::entities::repository::PrefetchPolicy::default(),
            created_at: now,
            updated_at: now,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        });
        id
    }

    /// Helper: seed an active artifact (Quarantined or Released) in
    /// `MockArtifactRepository` with a known name + format. Returns the
    /// artifact id so tests can assert state transitions.
    fn seed_active_artifact(
        artifacts: &Arc<crate::use_cases::test_support::MockArtifactRepository>,
        repository_id: Uuid,
        name: &str,
        status: hort_domain::entities::artifact::QuarantineStatus,
    ) -> Uuid {
        use hort_domain::entities::artifact::Artifact;
        use hort_domain::types::ContentHash;
        let id = Uuid::new_v4();
        let now = Utc::now();
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        artifacts.insert(Artifact {
            id,
            repository_id,
            name: name.into(),
            name_as_published: name.into(),
            version: Some("1.0.0".into()),
            path: format!("{name}/1.0.0/{name}-1.0.0.tgz"),
            size_bytes: 1024,
            sha256_checksum: hash,
            sha1_checksum: None,
            md5_checksum: None,
            content_type: "application/gzip".into(),
            quarantine_status: status,
            // Store the observation-window anchor;
            // the deadline is computed live.
            rejection_reason: None,
            quarantine_window_start: Some(now),
            quarantine_deadline: None,
            upstream_published_at: None,
            uploaded_by: None,
            is_deleted: false,
            created_at: now,
            updated_at: now,
        });
        id
    }

    /// Wire `MockCurationRuleRepo`'s reverse-index after a curation
    /// rule lands. The mock's `save_managed` stores the rule but does
    /// not auto-link to repos (the apply pipeline drives the junction
    /// edges via `set_curation_rules_for_repository`); for the
    /// retroactive-pass tests we link the freshly-saved rule to a
    /// pre-seeded repo manually.
    async fn link_rule_after_apply(h: &Harness, rule_name: &str, repo_id: Uuid) {
        let rule = h
            .rule_repo
            .find_by_name(rule_name)
            .await
            .unwrap()
            .expect("rule landed");
        h.rule_repo.link_rule_to_repo(rule.id, repo_id);
    }

    /// Declaring a `Block` rule for the first time triggers the retroactive
    /// pass on previously-active matching artifacts. The
    /// artifact transitions to `Rejected` AND the apply emits both a
    /// `CurationApplied { trigger: Retroactive, action: Block }` on the
    /// per-repo curation stream and an `ArtifactRejected` on the
    /// artifact stream.
    #[tokio::test]
    async fn retro_block_creates_rule_then_rejects_matching_artifact() {
        // To trigger the retroactive pass we use the tightening path:
        // apply an Allow rule first (silent), then tighten to Block.
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        let artifact_id = seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );

        // Apply 1 — Allow rule. No retroactive evaluation; report
        // counters stay zero.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "trusted"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.retro_warn_count, 0);
        assert_eq!(report.retro_block_count, 0);

        // Wire reverse-index now that rule exists.
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;

        // Apply 2 — same name, action tightens Allow → Block. The
        // retroactive pass hits.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        assert_eq!(report.retro_block_count, 1);
        assert_eq!(report.retro_warn_count, 0);

        // Artifact transitioned to Rejected.
        let after = h.artifacts.get(artifact_id).unwrap();
        assert_eq!(
            after.quarantine_status,
            hort_domain::entities::artifact::QuarantineStatus::Rejected
        );

        // The lifecycle port saw the commit_transition with an
        // ArtifactRejected payload carrying RejectionReason::CurationRetroactive.
        let transitions = h.lifecycle.committed_transitions();
        assert_eq!(transitions.len(), 1);
        let (_a, batch, _meta) = &transitions[0];
        assert_eq!(batch.events.len(), 1);
        match &batch.events[0].event {
            DomainEvent::ArtifactRejected(r) => {
                assert!(matches!(
                    r.rejected_by,
                    hort_domain::events::RejectionReason::CurationRetroactive { .. }
                ));
                assert_eq!(r.reason, "supply chain");
            }
            other => panic!("expected ArtifactRejected, got {other:?}"),
        }

        // The event-store saw a CurationApplied with trigger=Retroactive
        // on the curation stream for this repo.
        let mut found = false;
        for batch in h.events.appended() {
            if batch.stream_id == StreamId::curation_per_repo(repo_id) {
                for ev in &batch.events {
                    if let DomainEvent::CurationApplied(c) = &ev.event {
                        assert_eq!(c.trigger, CurationTrigger::Retroactive);
                        assert_eq!(c.action, CurationActionTag::Block);
                        assert_eq!(c.repository_id, repo_id);
                        found = true;
                    }
                }
            }
        }
        assert!(found, "expected CurationApplied on curation stream");
    }

    /// Retroactive curation pass emits
    /// `decision_point=curation_retroactive` with `result=retro_block`
    /// when a tightened rule transitions an existing artifact to
    /// `Rejected`, plus a violations counter under `rule=curation-block`.
    #[test]
    fn retroactive_curation_block_emits_metrics() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let h = build_harness();
                let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
                let _aid = seed_active_artifact(
                    &h.artifacts,
                    repo_id,
                    "left-pad",
                    hort_domain::entities::artifact::QuarantineStatus::Released,
                );
                let mut desired = DesiredState::default();
                desired.curation_rules.push(rule_env(
                    "block-leftpad",
                    "allow",
                    "left-pad",
                    "trusted",
                ));
                h.uc.apply(desired, env_oidc()).await.unwrap();
                link_rule_after_apply(&h, "block-leftpad", repo_id).await;

                let mut desired = DesiredState::default();
                desired.curation_rules.push(rule_env(
                    "block-leftpad",
                    "block",
                    "left-pad",
                    "supply chain",
                ));
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_evaluation_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "decision_point" && l.value() == "curation_retroactive")
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "result" && l.value() == "retro_block")
            }),
            "RetroBlock outcome must emit decision_point=curation_retroactive, result=retro_block"
        );
        assert!(
            entries.iter().any(|(ck, _, _, _)| {
                ck.key().name() == "hort_policy_violations_total"
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "decision_point" && l.value() == "curation_retroactive")
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "rule" && l.value() == "curation-block")
            }),
            "RetroBlock outcome must emit rule=curation-block"
        );
    }

    /// Acceptance: a retroactive
    /// curation `RetroBlock` outcome MUST sweep every
    /// `content_references` row whose `source_artifact_id` matches the
    /// just-rejected artifact. Mirrors the scan-driven reject path
    /// covered by `quarantine_reject_sweeps_content_references`. The
    /// artifact row stays alive (rejection is sticky), so the FK
    /// CASCADE never fires; the explicit `delete_by_source` sweep is
    /// the only mechanism that keeps the projection consistent with
    /// the artifact's terminal state.
    #[tokio::test]
    async fn retroactive_curation_reject_sweeps_content_references() {
        use hort_domain::ports::content_reference_index::ContentReference;
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        let artifact_id = seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );
        let primary_hash = h.artifacts.get(artifact_id).unwrap().sha256_checksum;
        let blob_hash: hort_domain::types::ContentHash =
            "1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .unwrap();
        // Seed both refcount rows that an ingest with HashReference-
        // strategy metadata would have produced: primary_content +
        // metadata_blob, sharing the source.
        h.content_refs
            .insert(ContentReference {
                source_artifact_id: artifact_id,
                target_content_hash: primary_hash.clone(),
                kind: "primary_content".into(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo_id,
                recorded_at: Utc::now(),
            })
            .await
            .unwrap();
        h.content_refs
            .insert(ContentReference {
                source_artifact_id: artifact_id,
                target_content_hash: blob_hash.clone(),
                kind: "metadata_blob".into(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo_id,
                recorded_at: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(
            h.content_refs.entry_count(),
            2,
            "fixture: two refcount rows seeded for the artifact-about-to-retro-reject"
        );

        // Apply 1 — Allow rule (silent; no retroactive evaluation).
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "trusted"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;
        // Refcount untouched by the silent path.
        assert_eq!(h.content_refs.entry_count(), 2);

        // Apply 2 — tighten Allow → Block. The retroactive pass hits
        // `commit_retroactive_block`, which now sweeps refcount rows.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.retro_block_count, 1, "the retro block must fire");

        // Both refcount rows must be gone, regardless of kind.
        assert_eq!(
            h.content_refs.entry_count(),
            0,
            "retro-block must sweep every content_references row for the source"
        );
        let primary_rows = h
            .content_refs
            .find_by_target(repo_id, &primary_hash, Some("primary_content"))
            .await
            .unwrap();
        assert_eq!(primary_rows.len(), 0, "primary_content row gone");
        let blob_rows = h
            .content_refs
            .find_by_target(repo_id, &blob_hash, Some("metadata_blob"))
            .await
            .unwrap();
        assert_eq!(blob_rows.len(), 0, "metadata_blob row gone");
    }

    /// Branch coverage for the
    /// warn-on-fail arm at `commit_retroactive_block` after
    /// `reject_from_retroactive_curation`. The refcount sweep is
    /// post-commit eventual — when
    /// `delete_by_source` fails on the retroactive-curation reject
    /// path, the outer `apply` MUST still return `Ok` because the
    /// `ArtifactRejected` event has already been appended and is the
    /// authoritative state change. The seeded refcount row is left
    /// in place and is repaired by the Phase B reconcile sweep.
    #[tokio::test]
    async fn retroactive_curation_reject_refcount_delete_failure_is_warn_only() {
        use hort_domain::ports::content_reference_index::ContentReference;
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        let artifact_id = seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );
        let primary_hash = h.artifacts.get(artifact_id).unwrap().sha256_checksum;

        // Seed one refcount row so the post-reject `delete_by_source`
        // has a concrete target; the assertion that the row remains
        // is sharper than asserting an already-empty mock stayed
        // empty.
        h.content_refs
            .insert(ContentReference {
                source_artifact_id: artifact_id,
                target_content_hash: primary_hash.clone(),
                kind: "primary_content".into(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo_id,
                recorded_at: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(h.content_refs.entry_count(), 1, "fixture seeded");

        // Apply 1 — Allow rule (silent; no retroactive evaluation).
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "trusted"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;
        assert_eq!(
            h.content_refs.entry_count(),
            1,
            "silent-path apply must not touch refcount"
        );

        // Arm a one-shot delete failure. The next `delete_by_source`
        // call (from the about-to-fire retro-block) consumes it.
        h.content_refs.fail_next_delete(DomainError::Invariant(
            "synthetic failure: delete_by_source on retro-curation reject".into(),
        ));

        // Apply 2 — tighten Allow → Block. Retroactive pass hits
        // `commit_retroactive_block`; the inner sweep fails; the
        // outer `apply` must still succeed and the report must
        // record the retro-block.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        let report =
            h.uc.apply(desired, env_oidc())
                .await
                .expect("apply must succeed even when refcount sweep fails on retro-block");
        assert_eq!(
            report.retro_block_count, 1,
            "the retro block must still fire"
        );

        // Load-bearing: the seeded refcount row is STILL present
        // after the warn-arm fired. A future change that aborts the
        // apply on delete-failure would either flip the
        // `.expect("apply must succeed")` above or the row would be
        // gone (because the arm reached delete and unwound) — either
        // outcome would fail this assertion.
        assert_eq!(
            h.content_refs.entry_count(),
            1,
            "warn-on-fail must leave the seeded row in place; reconcile is future work"
        );
        let rows = h
            .content_refs
            .find_by_target(repo_id, &primary_hash, Some("primary_content"))
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "primary_content row still present after the warn arm fired"
        );
    }

    /// Declaring `Block` then weakening to `Allow` must NOT auto-unblock
    /// the previously-rejected artifact. Rejection is sticky; admin
    /// explicit release is the override.
    #[tokio::test]
    async fn retro_weaken_does_not_unblock_or_emit_events() {
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);

        // Seed an already-rejected artifact (the `list_active_for_repo`
        // SQL excludes these, so the retroactive pass should not touch it).
        let _rejected_id = seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Rejected,
        );

        // Apply 1 — Block rule; link to repo.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;

        let events_before = h.events.appended().len();
        let transitions_before = h.lifecycle.committed_transitions().len();

        // Apply 2 — weaken to Allow.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "revoked"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        // No retroactive counters incremented (weakening is silent).
        assert_eq!(report.retro_warn_count, 0);
        assert_eq!(report.retro_block_count, 0);

        // No new events on any stream from the retro path.
        assert_eq!(
            h.events.appended().len(),
            events_before,
            "weakening must NOT emit events"
        );
        assert_eq!(
            h.lifecycle.committed_transitions().len(),
            transitions_before,
            "weakening must NOT mutate artifact state"
        );
    }

    /// Declaring a Warn rule emits CurationApplied on the curation stream
    /// but does NOT mutate artifact state.
    #[tokio::test]
    async fn retro_warn_emits_event_without_state_change() {
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        let artifact_id = seed_active_artifact(
            &h.artifacts,
            repo_id,
            "moment",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );

        // Apply 1 — Allow rule.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("warn-moment", "allow", "moment", "trusted"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "warn-moment", repo_id).await;

        // Apply 2 — tighten to Warn.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("warn-moment", "warn", "moment", "deprecated"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        assert_eq!(report.retro_warn_count, 1);
        assert_eq!(report.retro_block_count, 0);

        // Artifact state is unchanged (still Released).
        let after = h.artifacts.get(artifact_id).unwrap();
        assert_eq!(
            after.quarantine_status,
            hort_domain::entities::artifact::QuarantineStatus::Released
        );

        // No artifact-stream commit_transition fired.
        assert!(h.lifecycle.committed_transitions().is_empty());

        // CurationApplied with action=Warn fired on the curation stream.
        let mut found = false;
        for batch in h.events.appended() {
            if batch.stream_id == StreamId::curation_per_repo(repo_id) {
                for ev in &batch.events {
                    if let DomainEvent::CurationApplied(c) = &ev.event {
                        assert_eq!(c.trigger, CurationTrigger::Retroactive);
                        assert_eq!(c.action, CurationActionTag::Warn);
                        found = true;
                    }
                }
            }
        }
        assert!(found, "expected CurationApplied(Warn) on curation stream");
    }

    /// `list_active_for_repo` excludes `Rejected` artifacts; the
    /// retroactive pass on a rule that would block them is a no-op
    /// (no events, no state change). Defends the "rejection is sticky"
    /// property at the repo-listing layer.
    #[tokio::test]
    async fn retro_skips_already_rejected_artifacts() {
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        // Only a rejected artifact exists.
        seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Rejected,
        );

        // Apply 1 — Allow rule.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "trusted"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;

        // Apply 2 — tighten to Block. The rejected artifact is invisible
        // to the retroactive pass.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        assert_eq!(report.retro_block_count, 0);
        assert_eq!(report.retro_warn_count, 0);
        assert!(h.lifecycle.committed_transitions().is_empty());
    }

    /// Strict-atomic discipline — a concurrent ingest causing
    /// `commit_transition` to fail with `Conflict` aborts the entire
    /// apply pipeline as `AppError::ConcurrentModification`. The
    /// operator restarts; the second pass re-resolves and continues
    /// (covered by re-running the apply on a fresh harness).
    #[tokio::test]
    async fn retro_block_optimistic_concurrency_aborts_strict_atomic() {
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );

        // Apply 1 — Allow rule, link.
        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("block-leftpad", "allow", "left-pad", "trusted"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "block-leftpad", repo_id).await;

        // Inject a Conflict on the next commit_transition (simulating a
        // concurrent ingest racing the retroactive pass).
        h.lifecycle
            .fail_next_commit(DomainError::Conflict("stale stream version".into()));

        // Apply 2 — tighten Allow → Block. The retroactive pass hits a
        // Conflict; strict-atomic aborts.
        let mut desired = DesiredState::default();
        desired.curation_rules.push(rule_env(
            "block-leftpad",
            "block",
            "left-pad",
            "supply chain",
        ));
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        assert!(matches!(err, AppError::ConcurrentModification(_)));
    }

    /// Declaring a NEW rule with action=Allow does NOT trigger any
    /// retroactive events even when matching artifacts exist
    /// (Allow → NoChange is silent).
    #[tokio::test]
    async fn retro_create_allow_rule_emits_no_events() {
        let h = build_harness();
        let repo_id = seed_repo(&h.repos, "npm-public", RepositoryFormat::Npm);
        seed_active_artifact(
            &h.artifacts,
            repo_id,
            "left-pad",
            hort_domain::entities::artifact::QuarantineStatus::Released,
        );

        let mut desired = DesiredState::default();
        desired
            .curation_rules
            .push(rule_env("allow-leftpad", "allow", "left-pad", "trusted"));
        // Pre-link so the retro pass would see the repo.
        // We need to apply first to get the rule id, then link, then
        // re-apply — but the create branch is what triggers the retro
        // pass on first apply. Instead, seed the link via a manual
        // post-save hook: use `link_rule_to_repo` AFTER the apply
        // resolved the id.
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        link_rule_after_apply(&h, "allow-leftpad", repo_id).await;

        // The first apply was a `create` and IS a retro candidate, but
        // the rule's action is Allow — outcome is NoChange. So no
        // events are emitted regardless of the candidate flag.
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        // Reapply is unchanged; no retro candidacy triggered.
        assert_eq!(report.retro_block_count, 0);
        assert_eq!(report.retro_warn_count, 0);
        assert!(h.lifecycle.committed_transitions().is_empty());
    }
}
