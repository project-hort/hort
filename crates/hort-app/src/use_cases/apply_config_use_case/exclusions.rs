use super::*;

impl ApplyConfigUseCase {
    /// Apply event-sourced `Exclusion` envelopes.
    ///
    /// Per parent `ScanPolicy`:
    /// 1. Build the desired `Vec<ExclusionSpec>` for THIS policy by
    ///    filtering `DesiredState.exclusions` on `spec.policy ==
    ///    policy_name`.
    /// 2. Read the current `Vec<ExclusionProjection>` via
    ///    `list_exclusions_for_policy`.
    /// 3. Run `ExclusionsApplier::diff` to produce the event set.
    /// 4. Translate each `ExclusionAdded` / `ExclusionRemoved` into
    ///    the matching `PolicyUseCase` call. The use case mints fresh
    ///    `exclusion_id`s on add — the applier-minted id is discarded
    ///    for the same reason as `PolicyCreated` (single source of
    ///    truth for id minting).
    pub(super) async fn apply_exclusions(
        &self,
        desired: &DesiredState,
        repo_id_by_name: &HashMap<String, Uuid>,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let actor = gitops_actor_for_kind(Kind::Exclusion);

        // Group desired exclusions by their parent policy name. Empty
        // policies (declared with no exclusions) still need to flow
        // through the diff so any current projection rows get removed.
        let mut by_policy: HashMap<&str, Vec<&Envelope<ExclusionSpec>>> = HashMap::new();
        for ex in &desired.exclusions {
            by_policy
                .entry(ex.spec.policy.as_str())
                .or_default()
                .push(ex);
        }
        for env in &desired.scan_policies {
            by_policy.entry(env.metadata.name.as_str()).or_default();
        }

        for (policy_name, ex_envs) in by_policy {
            // Re-read the parent projection. For policies just created
            // in stage 2, this returns the freshly-upserted row.
            let Some(parent) = self.policy_projections.find_by_name(policy_name).await? else {
                // The parent policy reference passed validation (it's
                // either a desired policy or — if dangling — was
                // already rejected by `validate_against`). Reaching
                // this branch means the projection didn't materialise
                // after a stage-2 create; surface as Invariant.
                return Err(DomainError::Invariant(format!(
                    "exclusions reference policy '{policy_name}' but its projection \
                     is missing after stage 2 — projection upsert may have failed silently"
                ))
                .into());
            };

            let applier = ExclusionsApplier::new(parent.policy_id, repo_id_by_name.clone());
            let current = self
                .policy_projections
                .list_exclusions_for_policy(parent.policy_id)
                .await?;

            let desired_specs: Vec<ExclusionSpec> =
                ex_envs.iter().map(|e| e.spec.clone()).collect();
            let synthetic = Envelope {
                api_version: hort_config::envelope::ApiVersion::default(),
                kind: Kind::Exclusion,
                metadata: hort_config::envelope::Metadata {
                    name: format!("__bundle__{policy_name}"),
                },
                spec: desired_specs,
            };
            let events = applier.diff(&synthetic, Some(&current));

            for event in events {
                // Capture the discriminant before
                // the match arm moves the inner payload — `event_type()`
                // borrows `&self`, which is fine here, and yields the
                // catalog-bounded `&'static str` we want as the metric
                // label. Emission happens AFTER the use-case call
                // succeeds (one branch below), so a strict-atomic
                // abort never tick this counter.
                let event_type = event.event_type();
                match event {
                    DomainEvent::ExclusionAdded(payload) => {
                        let cmd = AddExclusionCommand {
                            policy_id: parent.policy_id,
                            cve_id: payload.cve_id,
                            package_pattern: payload.package_pattern,
                            scope: payload.scope,
                            reason: payload.reason,
                            expires_at: payload.expires_at,
                        };
                        self.policies
                            .add_exclusion(cmd, actor.clone())
                            .await
                            .map_err(map_concurrent_modification)?;
                        emit_gitops_object(gitops_kind::EXCLUSION, GitopsObjectResult::Created);
                        emit_gitops_event(gitops_kind::EXCLUSION, event_type);
                        report.created += 1;
                    }
                    DomainEvent::ExclusionRemoved(payload) => {
                        let cmd = RemoveExclusionCommand {
                            policy_id: parent.policy_id,
                            exclusion_id: payload.exclusion_id,
                            reason: payload.reason,
                        };
                        self.policies
                            .remove_exclusion(cmd, actor.clone())
                            .await
                            .map_err(map_concurrent_modification)?;
                        emit_gitops_object(gitops_kind::EXCLUSION, GitopsObjectResult::Deleted);
                        emit_gitops_event(gitops_kind::EXCLUSION, event_type);
                        report.deleted += 1;
                    }
                    other => {
                        // ExclusionsApplier::diff only emits Added/Removed.
                        return Err(DomainError::Invariant(format!(
                            "ExclusionsApplier emitted unexpected event type: {}",
                            other.event_type()
                        ))
                        .into());
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::apply_config_use_case::tests::*;
    use hort_domain::entities::scan_policy::{
        ExclusionProjection, NegligibleAction, ProvenanceMode, ScanEnforcement,
        ScanPolicyProjection,
    };

    // ===================================================================
    // Stage 3: Exclusion event-sourced apply
    // ===================================================================

    #[tokio::test]
    async fn add_exclusion_routes_through_policy_use_case() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("p1"));
        desired
            .exclusions
            .push(exclusion_env("ex-cve-1", "p1", "CVE-2024-0001"));

        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        // 1 policy + 1 exclusion = 2 created.
        assert_eq!(report.created, 2);
        // Two appends: PolicyCreated then ExclusionAdded.
        let appends = h.events.appended();
        assert!(appends
            .iter()
            .any(|b| { matches!(b.events[0].event, DomainEvent::ExclusionAdded(_)) }));
    }

    #[tokio::test]
    async fn remove_exclusion_when_absent_from_desired() {
        // Seed a current projection with one exclusion, then re-apply
        // with the parent policy still declared but the exclusion
        // dropped. The applier should produce one ExclusionRemoved.
        let h = build_harness();
        // Stage 1: seed a projection so the ScanPolicy diff reads
        // existing projection (rather than create-from-scratch).
        let policy_id = Uuid::new_v4();
        let now = Utc::now();
        h.proj.insert_active(ScanPolicyProjection {
            policy_id,
            name: "p1".into(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::High,
            quarantine_duration_secs: 24 * 3600,
            require_approval: true,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: Some(90 * 24 * 3600),
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            stream_version: 0,
            created_at: now,
            updated_at: now,
        });
        let exclusion_id = Uuid::new_v4();
        h.proj.insert_exclusion(ExclusionProjection {
            exclusion_id,
            policy_id,
            cve_id: "CVE-2024-0001".into(),
            package_pattern: None,
            scope: PolicyScope::Global,
            reason: "old".into(),
            added_by_actor_id: None,
            expires_at: None,
        });

        // Desired has the policy but NO exclusion.
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("p1"));

        h.uc.apply(desired, env_oidc()).await.unwrap();

        // Look for an ExclusionRemoved append.
        let appends = h.events.appended();
        let removed_count = appends
            .iter()
            .filter(|b| {
                b.events
                    .iter()
                    .any(|e| matches!(e.event, DomainEvent::ExclusionRemoved(_)))
            })
            .count();
        assert_eq!(removed_count, 1);
    }

    /// Any mutable-field edit is a remove-then-add: the events crate has
    /// no `ExclusionUpdated`. This exercises `reason`; the scope is not
    /// among the editable fields any more, since every repository scope
    /// is refused before the first write.
    #[tokio::test]
    async fn change_exclusion_field_emits_remove_then_add() {
        let h = build_harness();
        let policy_id = Uuid::new_v4();
        let now = Utc::now();
        h.proj.insert_active(ScanPolicyProjection {
            policy_id,
            name: "p1".into(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::High,
            quarantine_duration_secs: 24 * 3600,
            require_approval: true,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: Some(90 * 24 * 3600),
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            stream_version: 0,
            created_at: now,
            updated_at: now,
        });
        let old_id = Uuid::new_v4();
        h.proj.insert_exclusion(ExclusionProjection {
            exclusion_id: old_id,
            policy_id,
            cve_id: "CVE-2024-0001".into(),
            package_pattern: None,
            scope: PolicyScope::Global,
            reason: "rev1".into(),
            added_by_actor_id: None,
            expires_at: None,
        });

        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("p1"));
        let mut ex = exclusion_env("ex-cve-1", "p1", "CVE-2024-0001");
        ex.spec.reason = "rev2".into();
        desired.exclusions.push(ex);

        h.uc.apply(desired, env_oidc()).await.unwrap();

        let appends = h.events.appended();
        let removed = appends
            .iter()
            .filter(|b| {
                b.events
                    .iter()
                    .any(|e| matches!(e.event, DomainEvent::ExclusionRemoved(_)))
            })
            .count();
        let added = appends
            .iter()
            .filter(|b| {
                b.events
                    .iter()
                    .any(|e| matches!(e.event, DomainEvent::ExclusionAdded(_)))
            })
            .count();
        assert_eq!(removed, 1, "scope/reason change must emit a Removed");
        assert_eq!(added, 1, "scope/reason change must emit an Added");
    }

    #[test]
    fn add_exclusion_emits_one_exclusion_added_event_metric() {
        use crate::metrics::capture_metrics;
        let snap = capture_metrics(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let h = build_harness();
                let mut desired = DesiredState::default();
                desired.scan_policies.push(scan_policy_env("p1"));
                desired
                    .exclusions
                    .push(exclusion_env("ex1", "p1", "CVE-2024-0001"));
                h.uc.apply(desired, env_oidc()).await.unwrap();
            });
        });
        let entries = snap.into_vec();
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_events_emitted_total",
                &[("kind", "exclusion"), ("event_type", "ExclusionAdded")],
            ),
            1,
        );
        assert_eq!(
            counter_value_for(
                &entries,
                "hort_gitops_objects_total",
                &[("kind", "exclusion"), ("result", "created")],
            ),
            1,
        );
    }

    // ===================================================================
    // Repository scope: refused before the first write
    // ===================================================================

    /// A `ScanPolicyProjection` fixture for a global policy named
    /// `name`, carrying no stored licence rules.
    fn active_global_policy(policy_id: Uuid, name: &str) -> ScanPolicyProjection {
        let now = Utc::now();
        ScanPolicyProjection {
            policy_id,
            name: name.into(),
            scope: PolicyScope::Global,
            severity_threshold: SeverityThreshold::High,
            quarantine_duration_secs: 24 * 3600,
            require_approval: true,
            provenance_mode: ProvenanceMode::VerifyIfPresent,
            provenance_backends: vec!["cosign".to_string()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: Some(90 * 24 * 3600),
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".to_string()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            stream_version: 0,
            created_at: now,
            updated_at: now,
        }
    }

    /// The acceptance shape: a repository-scoped `Exclusion` in the same
    /// bundle as a loosening global policy. Nothing is written, and the
    /// boot preflight reaches the same verdict so the pod parks
    /// not-ready instead of crashlooping on a half-applied tree.
    #[tokio::test]
    async fn an_exclusion_scoped_to_a_repository_writes_nothing() {
        // Loosened on all three axes an operator would notice: findings
        // are recorded instead of blocking, approval is no longer
        // required, and only `critical` counts.
        let mut loosened = scan_policy_env("relaxed");
        loosened.spec.enforcement = "record".into();
        loosened.spec.require_approval = false;
        loosened.spec.severity_threshold = "critical".into();

        // Positive control: on its own the loosening policy DOES land, so
        // the "nothing written" assertions below cannot pass vacuously.
        let control = build_harness();
        control
            .uc
            .apply(
                DesiredState {
                    scan_policies: vec![loosened.clone()],
                    ..Default::default()
                },
                env_oidc(),
            )
            .await
            .expect("the loosening policy alone must apply cleanly");
        assert!(
            !control.events.appended().is_empty(),
            "positive control: applying the loosening policy must append the \
             ScanPolicy event that creates its projection"
        );

        // The repository IS declared, so the refusal is the scope itself
        // and not a dangling reference.
        let mut scoped = exclusion_env("cve-on-one-repo", "relaxed", "CVE-2026-0101");
        scoped.spec.scope = ScopeSpec::Repository(hort_config::scope::RepositoryScope {
            repository: "npm-internal".into(),
        });
        let desired = DesiredState {
            repositories: vec![repo_env("npm-internal", "hosted")],
            scan_policies: vec![loosened],
            exclusions: vec![scoped],
            ..Default::default()
        };

        let h = build_harness();
        let err =
            h.uc.apply(desired.clone(), env_oidc())
                .await
                .expect_err("a repository-scoped exclusion must fail the apply");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => assert!(
                msg.contains("cve-on-one-repo")
                    && msg.contains("npm-internal")
                    && msg.contains("not enforced"),
                "the abort must name the exclusion, the repository and why the scope \
                 cannot be honoured, got: {msg}"
            ),
            other => panic!("expected a park-eligible Validation error, got {other:?}"),
        }
        assert!(
            h.events.appended().is_empty(),
            "the loosening scan policy must NOT have been written — {} event \
             batch(es) landed",
            h.events.appended().len()
        );
        assert!(
            h.repos.calls().is_empty(),
            "no repository row may be written either: {:?}",
            h.repos.calls()
        );

        h.uc.preflight_validate(&desired, &env_oidc())
            .await
            .expect_err("the boot preflight must refuse the same bundle");
    }

    /// `ExclusionsApplier::resolve_scope` panics on a repository name it
    /// cannot resolve — a Stage-3 abort that is not a `GitopsBootError`,
    /// so `is_park_eligible` never sees it and the pod crashloops with
    /// Stages 1 and 2 already written, on a one-character typo in a
    /// scope name. **This test says that panic is unreachable from
    /// operator config**: the pre-write row refuses every repository
    /// scope, so neither an undeclared name (which would panic) nor a
    /// declared one (which would resolve, and then be refused by
    /// `PolicyUseCase::add_exclusion` from inside the write-capable
    /// stage) reaches the resolver.
    ///
    /// Both halves matter and the test would notice either going away:
    /// delete the pre-write row and the undeclared case turns this
    /// `apply` call into the `INVARIANT:` panic rather than the
    /// `Validation` error asserted below.
    #[tokio::test]
    async fn the_exclusion_scope_resolver_panic_is_unreachable_from_operator_config() {
        for (what, repository, declared) in [
            ("a name the bundle never declares", "not-declared", false),
            ("a name the bundle does declare", "npm-internal", true),
        ] {
            let mut scoped = exclusion_env("scoped", "p-parent", "CVE-2026-0102");
            scoped.spec.scope = ScopeSpec::Repository(hort_config::scope::RepositoryScope {
                repository: repository.into(),
            });
            let desired = DesiredState {
                repositories: if declared {
                    vec![repo_env("npm-internal", "hosted")]
                } else {
                    Vec::new()
                },
                scan_policies: vec![scan_policy_env("p-parent")],
                exclusions: vec![scoped],
                ..Default::default()
            };

            let h = build_harness();
            let Err(err) = h.uc.apply(desired.clone(), env_oidc()).await else {
                panic!("{what}: the apply must refuse a repository-scoped exclusion")
            };
            assert!(
                matches!(err, AppError::Domain(DomainError::Validation(_))),
                "{what}: must surface as a park-eligible Validation error — a panic \
                 is not a GitopsBootError and cannot park the pod — got {err:?}"
            );
            assert!(
                h.events.appended().is_empty() && h.repos.calls().is_empty(),
                "{what}: the refusal must land before the first write; events {}, \
                 repo calls {:?}",
                h.events.appended().len(),
                h.repos.calls(),
            );

            // And the boot preflight agrees, which is what makes the
            // refusal park-eligible rather than crashloop-shaped.
            h.uc.preflight_validate(&desired, &env_oidc())
                .await
                .unwrap_err();
        }
    }

    /// An exclusion stored with a repository scope before the refusal
    /// shipped is still removable through gitops: drop its envelope and
    /// the applier emits the `ExclusionRemoved`.
    ///
    /// Nothing refuses a removal — not here, not
    /// `PolicyUseCase::remove_exclusion`, not the HTTP `DELETE`.
    /// Removing such a row withdraws an assurance the finding filter
    /// never honoured, which is the safe direction; and refusing it in
    /// this method specifically would turn dropping the envelope into a
    /// post-write apply failure, because the applier emits removals
    /// from a write-capable stage — the partial-apply defect the
    /// pre-write validation pass exists to prevent.
    #[tokio::test]
    async fn a_stored_repository_scoped_exclusion_is_still_removable_by_gitops() {
        let h = build_harness();
        let policy_id = Uuid::new_v4();
        h.proj.insert_active(active_global_policy(policy_id, "p1"));
        h.proj.insert_exclusion(ExclusionProjection {
            exclusion_id: Uuid::new_v4(),
            policy_id,
            cve_id: "CVE-2024-0001".into(),
            package_pattern: None,
            // The shape no writer accepts any more.
            scope: PolicyScope::Repository(Uuid::new_v4()),
            reason: "stored before the scope was refused".into(),
            added_by_actor_id: None,
            expires_at: None,
        });

        // Parent policy still declared; the exclusion envelope dropped.
        let desired = DesiredState {
            scan_policies: vec![scan_policy_env("p1")],
            ..Default::default()
        };
        let report = h.uc.apply(desired, env_oidc()).await.expect(
            "dropping the envelope of a stored repository-scoped exclusion must still apply",
        );
        assert_eq!(report.deleted, 1, "the stored row must be removed");
        assert!(
            h.events.appended().iter().any(|b| b
                .events
                .iter()
                .any(|e| matches!(e.event, DomainEvent::ExclusionRemoved(_)))),
            "the removal must reach the event store: {:?}",
            h.events.appended()
        );
    }
}
