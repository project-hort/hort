use super::*;

impl ApplyConfigUseCase {
    /// Apply `ClaimMapping` create / update / delete (ADR 0012;
    /// `ClaimMappingRepository`, `claim_mappings` table —
    /// there is no `roles` table in the additive-claims model).
    ///
    /// **Whole-partition reconcile.**
    /// `ClaimMappingRepository::save_managed` atomically deletes every
    /// gitops-managed row absent from `items` and upserts every row in
    /// `items` (keyed on the `(idp_group, claim)` UNIQUE identity). The
    /// branch therefore:
    ///
    /// 1. builds the **complete** desired gitops-managed mapping set
    ///    from every declared envelope (`desired.claim_mappings`, not
    ///    just the changed subset — `save_managed` is whole-partition);
    /// 2. reads the prior managed set (`list_managed_by_gitops`) and
    ///    diffs it against the desired set by `(idp_group, claim)` to
    ///    emit one `ClaimMappingApplied` per added-or-changed row and
    ///    one `ClaimMappingRevoked` per removed row
    ///    (audit-event-per-mutation invariant);
    /// 3. calls `save_managed(&complete_desired_set)` once.
    ///
    /// Diff-then-emit failure-mode contract is preserved:
    /// a `save_managed` failure aborts the apply (strict-atomic) before
    /// any audit event lands; a save that succeeds followed by an
    /// event-store append failure surfaces the apply error and the next
    /// apply re-runs the diff against the now-saved state (idempotent —
    /// no events to re-emit). The `plan` argument drives the
    /// per-envelope `created` / `updated` / `deleted` report + metric
    /// counters; the audit events are derived from the live
    /// prior-vs-desired diff so they stay correct even if the plan's
    /// coarse classification and the row state diverge.
    pub(super) async fn apply_claim_mappings(
        &self,
        plan: &KindPlan<ClaimMappingSpec, String>,
        desired: &DesiredState,
        report: &mut ApplyReport,
        token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        // Prior gitops-managed set, keyed by the natural identity
        // `(idp_group, claim)` — the same key `save_managed` upserts on
        // and the table's UNIQUE constraint enforces.
        let prior = self.claim_mappings.list_managed_by_gitops().await?;
        let prior_by_identity: HashMap<(String, String), ClaimMapping> = prior
            .into_iter()
            .map(|m| ((m.idp_group.clone(), m.claim.clone()), m))
            .collect();

        // Complete desired gitops-managed set — every declared envelope,
        // not just the plan's changed subset (`save_managed` reconciles
        // the whole partition). The digest is the canonicalised spec
        // hash; the adapter writes `managed_by = gitops` unconditionally.
        let mut desired_set: Vec<ClaimMapping> = Vec::with_capacity(desired.claim_mappings.len());
        let mut desired_identities: HashSet<(String, String)> = HashSet::new();
        let mut authz_events: Vec<EventToAppend> = Vec::new();
        for env in &desired.claim_mappings {
            let digest = spec_digest_claim_mapping(&env.spec);
            let idp_group = env.spec.idp_group.clone();
            let claim = env.spec.claim.clone();
            let identity = (idp_group.clone(), claim.clone());
            desired_identities.insert(identity.clone());

            // Reuse the prior row's surrogate id when the identity
            // already exists so the audit `mapping_id` stays stable
            // across re-applies; mint a fresh one for a brand-new
            // mapping.
            let existing = prior_by_identity.get(&identity);
            let mapping_id = existing.map(|m| m.id).unwrap_or_else(Uuid::new_v4);

            // Emit `ClaimMappingApplied` for create OR digest change.
            // An unchanged digest is a no-op (no audit event, no churn).
            let changed = match existing {
                None => true,
                Some(prev) => prev.managed_by_digest != Some(digest),
            };
            if changed {
                authz_events.push(EventToAppend::new(DomainEvent::ClaimMappingApplied(
                    ClaimMappingApplied {
                        mapping_id,
                        idp_group: idp_group.clone(),
                        claim: claim.clone(),
                    },
                )));
            }

            desired_set.push(ClaimMapping {
                id: mapping_id,
                idp_group,
                claim,
                managed_by: ManagedBy::GitOps,
                managed_by_digest: Some(digest),
            });
        }

        // Revocations: every prior gitops-managed identity absent from
        // the desired set. `save_managed` deletes these rows; the audit
        // event attests the removal.
        for ((idp_group, claim), prev) in &prior_by_identity {
            if !desired_identities.contains(&(idp_group.clone(), claim.clone())) {
                authz_events.push(EventToAppend::new(DomainEvent::ClaimMappingRevoked(
                    ClaimMappingRevoked {
                        mapping_id: prev.id,
                        idp_group: idp_group.clone(),
                        claim: claim.clone(),
                    },
                )));
            }
        }

        // Per-envelope report + metric counters from the diff plan,
        // `kind="claim_mapping"`.
        for _ in &plan.create {
            emit_gitops_object(gitops_kind::CLAIM_MAPPING, GitopsObjectResult::Created);
            report.created += 1;
        }
        for _ in &plan.update {
            emit_gitops_object(gitops_kind::CLAIM_MAPPING, GitopsObjectResult::Updated);
            report.updated += 1;
        }
        for _ in &plan.delete {
            emit_gitops_object(gitops_kind::CLAIM_MAPPING, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        // Whole-partition atomic delete-absent + upsert-present.
        self.claim_mappings.save_managed(&desired_set).await?;

        self.append_authorization_events(authz_events, Kind::ClaimMapping, token)
            .await?;
        Ok(())
    }

    /// Append a batch of authorization audit events to the global
    /// authorization stream.
    ///
    /// `expected_version: Any` — gitops apply runs in
    /// a single boot-time process and concurrent apply is prevented
    /// at a higher layer (boot lock). No-op when `events` is empty
    /// (avoids an unnecessary append round-trip).
    ///
    /// **Compile-time gate.** The
    /// `_token: &GitOpsApplyToken` argument refuses to compile any
    /// caller outside the gitops apply pipeline. The token is
    /// constructible only from inside `hort-app` (via the `pub(crate)`
    /// constructor), and a non-gitops caller has nothing to pass. See
    /// [`GitOpsApplyToken`] for the architectural rationale.
    async fn append_authorization_events(
        &self,
        events: Vec<EventToAppend>,
        kind: Kind,
        _token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        let actor = gitops_actor_for_kind(kind);
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
        Ok(())
    }

    /// Append a per-stream batch of authorization audit events.
    ///
    /// Used by the repo-scoped emitters (`apply_permission_grants`,
    /// `apply_upstream_mappings`) that route events to either
    /// `StreamCategory::Repository(r)` or `StreamCategory::Authorization`
    /// depending on the per-row `repository_id`. One append round-trip
    /// per stream — empty buckets are skipped. `expected_version: Any`
    /// (gitops apply is single-process per boot lock).
    ///
    /// **Compile-time gate.** Same
    /// `_token: &GitOpsApplyToken` argument as
    /// [`append_authorization_events`](Self::append_authorization_events) — see that
    /// docstring for the full architectural rationale.
    pub(super) async fn append_grouped_authorization_events(
        &self,
        events_by_stream: HashMap<StreamId, Vec<EventToAppend>>,
        kind: Kind,
        _token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        if events_by_stream.is_empty() {
            return Ok(());
        }
        let actor = gitops_actor_for_kind(kind);
        // Sort by stream_id for deterministic test assertions; the
        // event store contract does not require ordering across
        // streams (each stream's `stream_position` is independent),
        // but iteration order on a HashMap is non-deterministic and a
        // future test that asserts append ordering would be flaky
        // otherwise. Sort key is the stream's Display form.
        let mut sorted: Vec<(StreamId, Vec<EventToAppend>)> =
            events_by_stream.into_iter().collect();
        sorted.sort_by_key(|(s, _)| s.to_string());
        for (stream_id, events) in sorted {
            if events.is_empty() {
                continue;
            }
            self.events
                .append(AppendEvents {
                    stream_id,
                    expected_version: ExpectedVersion::Any,
                    events,
                    correlation_id: Uuid::new_v4(),
                    causation_id: None,
                    actor: actor.clone(),
                })
                .await?;
        }
        Ok(())
    }
}

/// The `claim_mappings` diff identity is the natural
/// `(idp_group, claim)` pair (the table's UNIQUE key). The
/// `CurrentClaimMapping` snapshot view keys off a single `name`
/// string, so the snapshot builder synthesises a stable composite
/// name from the pair. The separator (`\u{1f}`, ASCII Unit Separator)
/// cannot appear in an `idp_group` / `claim` value (both are
/// non-blank operator strings), so the encoding is injective —
/// distinct pairs never collide on the synthesised name.
pub(super) fn claim_mapping_identity_name(idp_group: &str, claim: &str) -> String {
    format!("{idp_group}\u{1f}{claim}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::apply_config_use_case::tests::*;

    fn count_cm_applied(evts: &[DomainEvent]) -> usize {
        evts.iter()
            .filter(|e| matches!(e, DomainEvent::ClaimMappingApplied(_)))
            .count()
    }

    fn count_cm_revoked(evts: &[DomainEvent]) -> usize {
        evts.iter()
            .filter(|e| matches!(e, DomainEvent::ClaimMappingRevoked(_)))
            .count()
    }

    #[tokio::test]
    async fn apply_claim_mappings_create_emits_applied_and_reconciles() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .claim_mappings
            .push(cm_env("devs", "g-dev", "developer"));
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 1);
        // Whole-partition reconcile fires exactly once.
        assert_eq!(h.claim_mappings.save_managed_call_count(), 1);
        assert_eq!(h.claim_mappings.managed_count(), 1);
        let evts = authz_events(&h).await;
        assert_eq!(
            count_cm_applied(&evts),
            1,
            "create must emit exactly one ClaimMappingApplied"
        );
        if let Some(DomainEvent::ClaimMappingApplied(a)) = evts
            .iter()
            .find(|e| matches!(e, DomainEvent::ClaimMappingApplied(_)))
        {
            assert_eq!(a.idp_group, "g-dev");
            assert_eq!(a.claim, "developer");
        } else {
            panic!("no ClaimMappingApplied event");
        }
    }

    /// Retargeting a claim mapping. The design keys both the reconcile
    /// (`apply_claim_mappings`, on the `(idp_group, claim)` pair) and
    /// the diff identity (`diff_claim_mappings`, on `metadata.name` =
    /// the identity-encoded name) off the `(idp_group, claim)` pair, and
    /// `spec_digest_claim_mapping` is a pure function of that same pair.
    /// Consequently a *same-identity digest change is unreachable by
    /// construction* — changing the claim is a NEW identity: the old
    /// `(g-dev, developer)` is revoked and the new `(g-dev, admin)` is
    /// applied. This pins that shipped reconcile semantics.
    #[tokio::test]
    async fn apply_claim_mappings_retarget_revokes_old_and_applies_new() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .claim_mappings
            .push(cm_env("devs", "g-dev", "developer"));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let applied_before = count_cm_applied(&authz_events(&h).await);
        let revoked_before = count_cm_revoked(&authz_events(&h).await);
        assert_eq!(applied_before, 1);
        assert_eq!(revoked_before, 0);
        // Retarget `g-dev` from `developer` → `admin`. New identity:
        // the old mapping is absent from desired (revoked), the new one
        // is created (applied). The reconciled set still holds one row.
        desired.claim_mappings[0] = cm_env("devs", "g-dev", "admin");
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.created, 1);
        assert_eq!(report.deleted, 1);
        let evts = authz_events(&h).await;
        assert_eq!(
            count_cm_applied(&evts),
            applied_before + 1,
            "the new identity must emit a ClaimMappingApplied"
        );
        assert_eq!(
            count_cm_revoked(&evts),
            revoked_before + 1,
            "the old identity must emit a ClaimMappingRevoked"
        );
        assert_eq!(h.claim_mappings.managed_count(), 1);
        let row = &h.claim_mappings.managed.lock().unwrap();
        assert!(row.contains_key(&("g-dev".to_string(), "admin".to_string())));
    }

    #[tokio::test]
    async fn apply_claim_mappings_unchanged_is_silent() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .claim_mappings
            .push(cm_env("devs", "g-dev", "developer"));
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let applied_before = count_cm_applied(&authz_events(&h).await);
        // Replay the identical desired set → unchanged digest → no new
        // ClaimMappingApplied (silent no-op — unchanged digest).
        let report = h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.created, 0);
        assert_eq!(report.updated, 0);
        assert_eq!(
            count_cm_applied(&authz_events(&h).await),
            applied_before,
            "an unchanged-digest replay must emit no ClaimMappingApplied"
        );
    }

    #[tokio::test]
    async fn apply_claim_mappings_absent_is_revoked() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired
            .claim_mappings
            .push(cm_env("devs", "g-dev", "developer"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(h.claim_mappings.managed_count(), 1);
        // Re-apply with the mapping gone → prior gitops-managed row
        // absent from desired → ClaimMappingRevoked + the
        // whole-partition reconcile drops it.
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(h.claim_mappings.managed_count(), 0);
        assert_eq!(
            count_cm_revoked(&authz_events(&h).await),
            1,
            "a now-absent managed mapping must emit one ClaimMappingRevoked"
        );
    }

    #[tokio::test]
    async fn apply_claim_mappings_empty_desired_revokes_all() {
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.claim_mappings.push(cm_env("a", "g-a", "ca"));
        desired.claim_mappings.push(cm_env("b", "g-b", "cb"));
        h.uc.apply(desired, env_oidc()).await.unwrap();
        assert_eq!(h.claim_mappings.managed_count(), 2);
        // Empty `claim_mappings` slice in desired → save_managed(&[])
        // revokes the entire gitops-managed partition.
        let report =
            h.uc.apply(DesiredState::default(), env_oidc())
                .await
                .unwrap();
        assert_eq!(report.deleted, 2);
        assert_eq!(h.claim_mappings.managed_count(), 0);
        assert_eq!(count_cm_revoked(&authz_events(&h).await), 2);
    }
}
