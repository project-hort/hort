use super::*;

impl ApplyConfigUseCase {
    /// Apply event-sourced `ScanPolicy` envelopes.
    ///
    /// For each desired envelope:
    /// - Read the projection by name. `None` → mint a new policy via
    ///   `PolicyUseCase::create_policy`.
    /// - `Some(_)` → consult `ScanPolicyApplier::diff` to compute the
    ///   minimal update event set. Extract each `PolicyUpdated.field`
    ///   into the corresponding `FieldChange<_>` on `UpdatePolicyCommand`
    ///   and dispatch through `PolicyUseCase::update_policy`.
    ///
    /// For every active projection whose name is absent from desired,
    /// archive it via `PolicyUseCase::archive_policy`.
    pub(super) async fn apply_scan_policies(
        &self,
        desired: &DesiredState,
        repo_id_by_name: &HashMap<String, Uuid>,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let actor = gitops_actor_for_kind(Kind::ScanPolicy);
        let applier = ScanPolicyApplier::new(repo_id_by_name.clone());

        let desired_names: HashSet<&str> = desired
            .scan_policies
            .iter()
            .map(|e| e.metadata.name.as_str())
            .collect();

        // Apply each desired policy.
        for env in &desired.scan_policies {
            // First, look only at active rows (`find_by_name` filters
            // archived). If found, take the unchanged / update branch.
            // Otherwise probe `find_by_name_including_archived` so we
            // can distinguish "never existed" from "archived row of the
            // same name exists" — the latter requires reactivation
            // before any spec diff is applied
            // (gitops re-declaring an archived YAML must
            // preserve `policy_id` + event-stream history rather than
            // colliding with the existing UNIQUE-name row).
            let active = self
                .policy_projections
                .find_by_name(&env.metadata.name)
                .await?;
            match active {
                Some(proj) => {
                    let projection_opt = Some(proj.clone());
                    let events = applier.diff(env, projection_opt.as_ref());
                    if events.is_empty() {
                        emit_gitops_object(gitops_kind::SCAN_POLICY, GitopsObjectResult::Unchanged);
                        report.unchanged += 1;
                    } else {
                        let cmd = update_command_from_diff(proj.policy_id, env, repo_id_by_name);
                        self.policies
                            .update_policy(cmd, actor.clone())
                            .await
                            .map_err(map_concurrent_modification)?;
                        emit_gitops_object(gitops_kind::SCAN_POLICY, GitopsObjectResult::Updated);
                        // Emit one
                        // `hort_gitops_events_emitted_total` per event the
                        // applier produced. `update_policy` appends one
                        // `PolicyUpdated` per actually-changed field —
                        // the applier's diff and the use case's diff
                        // both visit the same field set in the same
                        // order, so `events.len()` is the canonical
                        // event count for this update. Label value
                        // comes from `DomainEvent::event_type()` — a
                        // `&'static str` from a static table.
                        for event in &events {
                            emit_gitops_event(gitops_kind::SCAN_POLICY, event.event_type());
                        }
                        report.updated += 1;
                    }
                }
                None => {
                    // No active row. Probe for an archived row of the
                    // same name before falling through to create.
                    let archived = self
                        .policy_projections
                        .find_by_name_including_archived(&env.metadata.name)
                        .await?;
                    match archived {
                        Some(proj) if proj.archived => {
                            // Reactivate first, then diff against the
                            // post-reactivation projection so any spec
                            // deltas land as a follow-on PolicyUpdated
                            // batch in the same apply pass.
                            self.policies
                                .reactivate_policy(proj.policy_id, actor.clone())
                                .await
                                .map_err(map_concurrent_modification)?;
                            emit_gitops_object(
                                gitops_kind::SCAN_POLICY,
                                GitopsObjectResult::Updated,
                            );
                            emit_gitops_event(gitops_kind::SCAN_POLICY, "PolicyReactivated");

                            // Re-read to pick up the bumped
                            // stream_version + flipped `archived` flag
                            // before computing the spec diff. The
                            // applier's `diff` ignores the archived
                            // field, so any spec deltas surface as
                            // ordinary PolicyUpdated events.
                            let post = self
                                .policy_projections
                                .find_by_name(&env.metadata.name)
                                .await?;
                            let events = applier.diff(env, post.as_ref());
                            if !events.is_empty() {
                                let cmd =
                                    update_command_from_diff(proj.policy_id, env, repo_id_by_name);
                                self.policies
                                    .update_policy(cmd, actor.clone())
                                    .await
                                    .map_err(map_concurrent_modification)?;
                                for event in &events {
                                    emit_gitops_event(gitops_kind::SCAN_POLICY, event.event_type());
                                }
                            }
                            report.updated += 1;
                        }
                        // No row in any state — clean create.
                        _ => {
                            // Pipeline mints id (the design-doc choice —
                            // avoids the applier's mint-and-discard).
                            // Build the command directly from the spec.
                            let cmd = create_command_from_spec(env, repo_id_by_name);
                            self.policies
                                .create_policy(cmd, actor.clone())
                                .await
                                .map_err(map_concurrent_modification)?;
                            emit_gitops_object(
                                gitops_kind::SCAN_POLICY,
                                GitopsObjectResult::Created,
                            );
                            // Emit the per-event
                            // counter. `event_type` is the `DomainEvent`
                            // discriminant (catalog-bounded), not a
                            // free-form caller string.
                            // `PolicyUseCase::create_policy` appends
                            // exactly one `PolicyCreated`; emit one
                            // increment after the append succeeds.
                            emit_gitops_event(gitops_kind::SCAN_POLICY, "PolicyCreated");
                            report.created += 1;
                        }
                    }
                }
            }
        }

        // Archive every active projection that disappeared from desired.
        let active = self.policy_projections.list_active().await?;
        for proj in active {
            if !desired_names.contains(proj.name.as_str()) {
                self.policies
                    .archive_policy(proj.policy_id, actor.clone())
                    .await
                    .map_err(map_concurrent_modification)?;
                emit_gitops_object(gitops_kind::SCAN_POLICY, GitopsObjectResult::Deleted);
                // `archive_policy` appends exactly
                // one `PolicyArchived` event.
                emit_gitops_event(gitops_kind::SCAN_POLICY, "PolicyArchived");
                report.deleted += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::apply_config_use_case::tests::*;

    // ===================================================================
    // Stage 2: ScanPolicy event-sourced apply
    // ===================================================================

    #[tokio::test]
    async fn create_scan_policy_routes_through_policy_use_case() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("prod-default"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 1);
        // PolicyUseCase::create_policy appended a PolicyCreated event.
        let appends = h.events.appended();
        assert_eq!(appends.len(), 1);
        assert!(matches!(
            appends[0].events[0].event,
            DomainEvent::PolicyCreated(_)
        ));
        // Actor must be GitOps.
        assert!(matches!(appends[0].actor, Actor::GitOps(_)));
    }

    #[tokio::test]
    async fn idempotent_scan_policy_reapply_emits_zero_events() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("prod-default"));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let appends_before = h.events.appended().len();
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.unchanged, 1);
        assert_eq!(h.events.appended().len(), appends_before);
    }

    #[tokio::test]
    async fn update_scan_policy_single_field_routes_through_update_policy() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("prod-default"));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let appends_before = h.events.appended().len();

        // Mutate one field — severity_threshold high → critical.
        desired.scan_policies[0].spec.severity_threshold = "critical".into();
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.updated, 1);
        // Exactly one new append (the PolicyUpdated batch).
        let new_appends = &h.events.appended()[appends_before..];
        assert_eq!(new_appends.len(), 1);
        // The single event in the batch is a PolicyUpdated for SeverityThreshold.
        assert_eq!(new_appends[0].events.len(), 1);
        assert!(matches!(
            new_appends[0].events[0].event,
            DomainEvent::PolicyUpdated(_)
        ));
    }

    #[tokio::test]
    async fn missing_scan_policy_archives_via_policy_use_case() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("prod-default"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        let appends_before = h.events.appended().len();

        // Drop the desired scan policy.
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(report.deleted, 1);
        let new_appends = &h.events.appended()[appends_before..];
        assert_eq!(new_appends.len(), 1);
        assert!(matches!(
            new_appends[0].events[0].event,
            DomainEvent::PolicyArchived(_)
        ));
    }

    #[tokio::test]
    async fn concurrent_modification_aborts_strict_atomic() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.scan_policies.push(scan_policy_env("p1"));
        desired.scan_policies.push(scan_policy_env("p2"));
        // Inject a Conflict on the very first append (the create of p1).
        h.events.schedule_conflict_on_next_append();

        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        assert!(matches!(err, AppError::ConcurrentModification(_)));
        // After the conflict, the apply MUST abort: only the conflict-
        // injected append is in the log; p2 is never attempted.
        let appends = h.events.appended();
        assert_eq!(
            appends.len(),
            1,
            "stage 2 must not continue past concurrent-modification abort: got {} appends",
            appends.len()
        );
    }
}
