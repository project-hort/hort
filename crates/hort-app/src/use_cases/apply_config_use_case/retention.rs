use super::*;

impl ApplyConfigUseCase {
    /// Apply event-sourced `RetentionPolicy` envelopes.
    ///
    /// Mirrors [`Self::apply_scan_policies`]: per desired envelope,
    /// `find_by_name` → create (no row) / update (active row, predicate
    /// or scope changed; `RetentionPolicyUseCase::update_policy`
    /// short-circuits an unchanged spec to a no-op) / unchanged. Every
    /// active projection absent from desired is archived.
    ///
    /// **Terminal-archive divergence from the ScanPolicy reactivation
    /// path:** RetentionPolicy has no `Reactivated` event. A re-declared *archived*
    /// name is treated as a **new policy** (fresh `policy_id`) — the
    /// partial-unique-on-active-name index does not collide because it
    /// only covers `archived = false`, and the old archived stream
    /// stays as audit history. So there is no
    /// `find_by_name_including_archived` reactivate branch here; the
    /// `find_by_name` (active-only) miss falls straight to create.
    ///
    /// **Apply-time security-scope warning:**
    /// after resolving the predicate + scope, if the predicate is
    /// security-driven AND the scope does not exclude
    /// `IngestSource(Direct)`, emit an `info!` (NOT an error — the
    /// policy still applies; this is operator-intent advisory). The
    /// runtime retention evaluator deliberately does NOT block; this
    /// is the single home of that warning.
    ///
    /// No-op (logged) when the retention apply slot is unwired
    /// (`with_retention` not called) — a `RetentionPolicy` YAML present
    /// with the slot unwired is operator-visible, never a silent drop.
    ///
    /// Open item — retention-apply slot unwired:
    /// `with_retention()` stays builder-optional until the
    /// consumer ships. Sweep this slot's `Option` shape when
    /// artifact retention goes live.
    pub(super) async fn apply_retention_policies(
        &self,
        desired: &DesiredState,
        report: &mut ApplyReport,
    ) -> AppResult<()> {
        let Some(retention) = self.retention.as_ref() else {
            if !desired.retention_policies.is_empty() {
                tracing::warn!(
                    count = desired.retention_policies.len(),
                    "RetentionPolicy envelopes present but the retention apply \
                     slot is unwired (ApplyConfigUseCase::with_retention not \
                     called) — skipping; these policies will NOT be applied \
                     until the composition root wires retention"
                );
            }
            return Ok(());
        };

        let actor = gitops_actor_for_kind(Kind::RetentionPolicy);
        let desired_names: HashSet<&str> = desired
            .retention_policies
            .iter()
            .map(|e| e.metadata.name.as_str())
            .collect();

        for env in &desired.retention_policies {
            let name = &env.metadata.name;
            // Resolve the JSON-shaped machine-envelope predicate +
            // scope into domain enums (the `hort-config` layer
            // holds them as `serde_json::Value`; per-spec validation
            // already ran in `DesiredState::validate`, so a parse
            // failure here is a contract violation surfaced as a
            // domain Validation error).
            let predicate = hort_config::retention_policy::predicate_from_value(
                &env.spec.predicate,
            )
            .map_err(|e| {
                AppError::Domain(DomainError::Validation(format!(
                    "RetentionPolicy '{name}': predicate resolve: {e}"
                )))
            })?;
            let scope =
                hort_config::retention_policy::scope_from_value(&env.spec.scope).map_err(|e| {
                    AppError::Domain(DomainError::Validation(format!(
                        "RetentionPolicy '{name}': scope resolve: {e}"
                    )))
                })?;

            // A security-driven predicate must exclude
            // direct uploads, or the operator is told (advisory, NOT
            // a reject — the policy applies).
            if predicate.is_security_driven() && !scope.excludes_direct_uploads() {
                tracing::info!(
                    policy = %name,
                    "retention policy: a security-driven predicate's resolved \
                     scope does not exclude IngestSource(Direct) — directly \
                     uploaded artifacts (which may be the only build of a \
                     version in production) are deletable by this policy. \
                     Confirm intent in YAML review."
                );
            }

            match retention.projections.find_by_name(name).await? {
                Some(existing) => {
                    // Active row: update path. `update_policy`
                    // short-circuits an unchanged predicate+scope to
                    // a no-op (Ok, zero events) — mirror the
                    // ScanPolicy unchanged/updated accounting.
                    if existing.predicate == predicate && existing.scope == scope {
                        emit_gitops_object(
                            gitops_kind::RETENTION_POLICY,
                            GitopsObjectResult::Unchanged,
                        );
                        report.unchanged += 1;
                    } else {
                        retention
                            .policies
                            .update_policy(
                                crate::use_cases::retention_policy_use_case::UpdateRetentionPolicyCommand {
                                    policy_id: existing.policy_id,
                                    predicate,
                                    scope,
                                },
                                actor.clone(),
                            )
                            .await
                            .map_err(map_concurrent_modification)?;
                        emit_gitops_object(
                            gitops_kind::RETENTION_POLICY,
                            GitopsObjectResult::Updated,
                        );
                        emit_gitops_event(gitops_kind::RETENTION_POLICY, "RetentionPolicyUpdated");
                        report.updated += 1;
                    }
                }
                None => {
                    // No active row of this name. Per the
                    // terminal-archive model a re-declared archived
                    // name mints a FRESH policy_id (no reactivation),
                    // so create unconditionally — the
                    // partial-unique-on-active-name index does not
                    // collide with an archived same-name row.
                    retention
                        .policies
                        .create_policy(
                            crate::use_cases::retention_policy_use_case::CreateRetentionPolicyCommand {
                                name: name.clone(),
                                predicate,
                                scope,
                            },
                            actor.clone(),
                        )
                        .await
                        .map_err(map_concurrent_modification)?;
                    emit_gitops_object(gitops_kind::RETENTION_POLICY, GitopsObjectResult::Created);
                    emit_gitops_event(gitops_kind::RETENTION_POLICY, "RetentionPolicyCreated");
                    report.created += 1;
                }
            }
        }

        // Archive every active projection absent from desired.
        for proj in retention.projections.list_active_rows().await? {
            if !desired_names.contains(proj.name.as_str()) {
                retention
                    .policies
                    .archive_policy(
                        proj.policy_id,
                        // Archived-by: the gitops actor's identity is
                        // carried on the event's `actor` column; the
                        // RetentionPolicyEvent::Archived.by is the
                        // domain-level "who" — use the nil sentinel
                        // (gitops-system), consistent with how the
                        // ScanPolicy archive path attributes via the
                        // actor, not a payload user id.
                        Uuid::nil(),
                        actor.clone(),
                    )
                    .await
                    .map_err(map_concurrent_modification)?;
                emit_gitops_object(gitops_kind::RETENTION_POLICY, GitopsObjectResult::Deleted);
                emit_gitops_event(gitops_kind::RETENTION_POLICY, "RetentionPolicyArchived");
                report.deleted += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // =======================================================================
    // apply_retention_policies (create / update / archive /
    // unchanged accounting + the security-scope apply-time warning + the
    // unwired-slot no-op).
    // =======================================================================
    mod retention_apply {
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        use hort_config::desired::DesiredState;
        use hort_config::envelope::{ApiVersion, Envelope, Kind, Metadata};
        use hort_config::retention_policy::RetentionPolicySpec;
        use hort_domain::error::DomainResult;
        use hort_domain::events::{Actor, ApiActor, PersistedEvent, StreamCategory, StreamId};
        use hort_domain::ports::event_store::{
            AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
        };
        use hort_domain::ports::retention_policy_projection_repository::{
            RetentionPolicyProjectionRepository, RetentionPolicyRow,
        };
        use hort_domain::ports::BoxFuture;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::Registry;
        use uuid::Uuid;

        use crate::use_cases::apply_config_use_case::tests::{build_harness, env_oidc};
        use crate::use_cases::apply_config_use_case::{ApplyConfigUseCase, RetentionApply};
        use crate::use_cases::retention_policy_use_case::RetentionPolicyUseCase;

        // -- tracing capture (the established repository_access pattern) --
        #[derive(Clone, Default)]
        struct CapLayer {
            records: Arc<Mutex<Vec<(tracing::Level, String)>>>,
        }
        impl<S> tracing_subscriber::Layer<S> for CapLayer
        where
            S: tracing::Subscriber,
        {
            fn register_callsite(
                &self,
                _m: &'static tracing::Metadata<'static>,
            ) -> tracing::subscriber::Interest {
                tracing::subscriber::Interest::sometimes()
            }
            fn enabled(
                &self,
                _m: &tracing::Metadata<'_>,
                _c: tracing_subscriber::layer::Context<'_, S>,
            ) -> bool {
                true
            }
            fn on_event(
                &self,
                e: &tracing::Event<'_>,
                _c: tracing_subscriber::layer::Context<'_, S>,
            ) {
                let mut v = MsgVisitor::default();
                e.record(&mut v);
                self.records
                    .lock()
                    .unwrap()
                    .push((*e.metadata().level(), v.s));
            }
        }
        #[derive(Default)]
        struct MsgVisitor {
            s: String,
        }
        impl tracing::field::Visit for MsgVisitor {
            fn record_debug(&mut self, f: &tracing::field::Field, val: &dyn std::fmt::Debug) {
                self.s.push_str(&format!("{}={:?} ", f.name(), val));
            }
            fn record_str(&mut self, f: &tracing::field::Field, val: &str) {
                self.s.push_str(&format!("{}={} ", f.name(), val));
            }
        }
        static TRACING_MUTEX: Mutex<()> = Mutex::new(());
        fn install_global() {
            use std::sync::OnceLock;
            static I: OnceLock<()> = OnceLock::new();
            I.get_or_init(|| {
                let _ = tracing::subscriber::set_global_default(
                    Registry::default().with(CapLayer::default()),
                );
            });
        }

        // -- minimal mocks (same shape as retention_policy_use_case_tests) --
        struct MockEvents;
        impl EventStore for MockEvents {
            fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
                let n = batch.events.len() as u64;
                Box::pin(async move {
                    Ok(AppendResult {
                        stream_position: n.saturating_sub(1),
                        global_positions: (0..n).collect(),
                    })
                })
            }
            fn read_stream(
                &self,
                _s: &StreamId,
                _f: ReadFrom,
                _m: u64,
            ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn read_category(
                &self,
                _c: StreamCategory,
                _f: SubscribeFrom,
                _m: u64,
            ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn delete_stream(&self, _s: StreamId) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unimplemented!() })
            }
            fn archive_stream(&self, _s: StreamId, _t: &str) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unimplemented!() })
            }
        }

        #[derive(Default)]
        struct MockProj {
            rows: Mutex<HashMap<Uuid, RetentionPolicyRow>>,
        }
        impl MockProj {
            fn active_count(&self) -> usize {
                self.rows
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|r| !r.archived)
                    .count()
            }
        }
        impl RetentionPolicyProjectionRepository for MockProj {
            fn list_active(
                &self,
            ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::retention::RetentionPolicy>>>
            {
                let v: Vec<_> = self
                    .rows
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|r| !r.archived)
                    .cloned()
                    .map(RetentionPolicyRow::into_policy)
                    .collect();
                Box::pin(async move { Ok(v) })
            }
            fn find_by_name(
                &self,
                name: &str,
            ) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>> {
                let f = self
                    .rows
                    .lock()
                    .unwrap()
                    .values()
                    .find(|r| r.name == name && !r.archived)
                    .cloned();
                Box::pin(async move { Ok(f) })
            }
            fn find_by_name_including_archived(
                &self,
                name: &str,
            ) -> BoxFuture<'_, DomainResult<Option<RetentionPolicyRow>>> {
                let f = self
                    .rows
                    .lock()
                    .unwrap()
                    .values()
                    .find(|r| r.name == name)
                    .cloned();
                Box::pin(async move { Ok(f) })
            }
            fn list_active_rows(&self) -> BoxFuture<'_, DomainResult<Vec<RetentionPolicyRow>>> {
                let v: Vec<_> = self
                    .rows
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|r| !r.archived)
                    .cloned()
                    .collect();
                Box::pin(async move { Ok(v) })
            }
            fn upsert(&self, row: &RetentionPolicyRow) -> BoxFuture<'_, DomainResult<()>> {
                self.rows.lock().unwrap().insert(row.policy_id, row.clone());
                Box::pin(async { Ok(()) })
            }
        }

        fn rp_env(
            name: &str,
            predicate: serde_json::Value,
            scope: serde_json::Value,
        ) -> Envelope<RetentionPolicySpec> {
            Envelope {
                api_version: ApiVersion::V1Beta1,
                kind: Kind::RetentionPolicy,
                metadata: Metadata { name: name.into() },
                spec: RetentionPolicySpec { predicate, scope },
            }
        }

        fn make_uc(proj: Arc<MockProj>) -> ApplyConfigUseCase {
            let events = crate::event_store_publisher::wrap_for_test(Arc::new(MockEvents));
            let rp_uc = Arc::new(RetentionPolicyUseCase::new(events, proj.clone()));
            // Reuse the apply harness's full constructor via the
            // module-level `build_harness`, then override retention.
            build_harness()
                .uc
                .with_retention(RetentionApply::new(proj, rp_uc))
        }

        fn nil_actor() -> Actor {
            Actor::Api(ApiActor {
                user_id: Uuid::nil(),
            })
        }

        #[tokio::test]
        async fn create_then_unchanged_then_update_then_archive_accounting() {
            let proj = Arc::new(MockProj::default());
            let uc = make_uc(proj.clone());

            // 1. create
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "retain-30d",
                serde_json::json!({ "AgeExceeds": 2_592_000 }),
                serde_json::json!("AllRepos"),
            ));
            let r = uc.apply(d, env_oidc()).await.expect("apply create");
            assert_eq!(r.created, 1, "first apply creates");
            assert_eq!(proj.active_count(), 1);

            // 2. same spec → unchanged (no event)
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "retain-30d",
                serde_json::json!({ "AgeExceeds": 2_592_000 }),
                serde_json::json!("AllRepos"),
            ));
            let r = uc.apply(d, env_oidc()).await.expect("apply unchanged");
            assert_eq!(r.unchanged, 1, "same spec is unchanged");
            assert_eq!(r.created, 0);

            // 3. changed predicate → update
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "retain-30d",
                serde_json::json!({ "AgeExceeds": 5_184_000 }),
                serde_json::json!("AllRepos"),
            ));
            let r = uc.apply(d, env_oidc()).await.expect("apply update");
            assert_eq!(r.updated, 1, "changed predicate updates");

            // 4. absent from desired → archive
            let r = uc
                .apply(DesiredState::default(), env_oidc())
                .await
                .expect("apply archive");
            assert_eq!(r.deleted, 1, "absent policy archived");
            assert_eq!(proj.active_count(), 0);
        }

        /// A security-driven predicate whose scope does NOT exclude
        /// IngestSource(Direct) fires an apply-time `info!` (NOT an error —
        /// the policy still applies). A proxied-scoped security predicate
        /// does NOT warn.
        #[test]
        fn inv8_security_predicate_non_direct_excluding_scope_warns_but_applies() {
            install_global();
            let _g = TRACING_MUTEX
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let layer = CapLayer::default();
            let captured = layer.records.clone();
            let _sub = tracing::subscriber::set_default(Registry::default().with(layer));
            tracing::callsite::rebuild_interest_cache();

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            // Security predicate (HasFixAvailable) + AllRepos scope
            // (does NOT exclude Direct) → must warn AND still create.
            let proj = Arc::new(MockProj::default());
            let uc = make_uc(proj.clone());
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "vuln-allrepos",
                serde_json::json!("HasFixAvailable"),
                serde_json::json!("AllRepos"),
            ));
            let r = rt.block_on(uc.apply(d, env_oidc())).expect("apply");
            assert_eq!(
                r.created, 1,
                "the policy still applies (advisory, not reject)"
            );

            let recs = captured.lock().unwrap();
            assert!(
                recs.iter().any(|(lvl, msg)| *lvl == tracing::Level::INFO
                    && msg.contains("does not exclude IngestSource(Direct)")
                    && msg.contains("vuln-allrepos")),
                "info! must fire for a security predicate with a \
                 non-direct-excluding scope; captured: {recs:?}"
            );
            drop(recs);

            // Proxied scope EXCLUDES direct → must NOT warn.
            let proj2 = Arc::new(MockProj::default());
            let uc2 = make_uc(proj2);
            captured.lock().unwrap().clear();
            let mut d2 = DesiredState::default();
            d2.retention_policies.push(rp_env(
                "vuln-proxied",
                serde_json::json!("HasFixAvailable"),
                serde_json::json!({ "IngestSource": "Proxied" }),
            ));
            rt.block_on(uc2.apply(d2, env_oidc())).expect("apply");
            let recs2 = captured.lock().unwrap();
            assert!(
                !recs2
                    .iter()
                    .any(|(_, msg)| msg.contains("does not exclude IngestSource(Direct)")),
                "a proxied-scoped (direct-excluding) security predicate must \
                 NOT fire the warning; captured: {recs2:?}"
            );
        }

        /// Unwired retention slot: a `RetentionPolicy` envelope present
        /// but `with_retention` not called → logged no-op, NOT a silent
        /// drop and NOT an apply failure.
        #[tokio::test]
        async fn unwired_slot_is_logged_noop_not_failure() {
            // build_harness() does NOT call with_retention.
            let h = build_harness();
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "orphan",
                serde_json::json!({ "AgeExceeds": 60 }),
                serde_json::json!("AllRepos"),
            ));
            let r =
                h.uc.apply(d, env_oidc())
                    .await
                    .expect("apply must NOT fail when retention slot is unwired");
            assert_eq!(r.created, 0, "unwired slot creates nothing");
        }

        /// The actor threaded into the retention lifecycle append is
        /// the gitops actor (apply is gitops-authored, exactly like
        /// ScanPolicy) — NOT the RetentionScheduler actor (that is the
        /// runtime Evaluated breadcrumb's actor).
        #[tokio::test]
        async fn create_uses_gitops_actor_not_retention_scheduler() {
            // Captured by routing through a spy event store.
            struct SpyEvents {
                seen: Mutex<Vec<Actor>>,
            }
            impl EventStore for SpyEvents {
                fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
                    self.seen.lock().unwrap().push(batch.actor.clone());
                    let n = batch.events.len() as u64;
                    Box::pin(async move {
                        Ok(AppendResult {
                            stream_position: n.saturating_sub(1),
                            global_positions: (0..n).collect(),
                        })
                    })
                }
                fn read_stream(
                    &self,
                    _s: &StreamId,
                    _f: ReadFrom,
                    _m: u64,
                ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                    Box::pin(async { Ok(Vec::new()) })
                }
                fn read_category(
                    &self,
                    _c: StreamCategory,
                    _f: SubscribeFrom,
                    _m: u64,
                ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
                    Box::pin(async { Ok(Vec::new()) })
                }
                fn delete_stream(&self, _s: StreamId) -> BoxFuture<'_, DomainResult<()>> {
                    Box::pin(async { unimplemented!() })
                }
                fn archive_stream(
                    &self,
                    _s: StreamId,
                    _t: &str,
                ) -> BoxFuture<'_, DomainResult<()>> {
                    Box::pin(async { unimplemented!() })
                }
            }
            let spy = Arc::new(SpyEvents {
                seen: Mutex::new(Vec::new()),
            });
            let proj = Arc::new(MockProj::default());
            let rp_uc = Arc::new(RetentionPolicyUseCase::new(
                crate::event_store_publisher::wrap_for_test(spy.clone()),
                proj.clone(),
            ));
            let uc = build_harness()
                .uc
                .with_retention(RetentionApply::new(proj, rp_uc));
            let mut d = DesiredState::default();
            d.retention_policies.push(rp_env(
                "g",
                serde_json::json!({ "AgeExceeds": 60 }),
                serde_json::json!("AllRepos"),
            ));
            let _ = nil_actor(); // keep helper referenced
            uc.apply(d, env_oidc()).await.expect("apply");
            let seen = spy.seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert!(
                matches!(seen[0], Actor::GitOps(_)),
                "retention lifecycle append must use the gitops actor, got {:?}",
                seen[0]
            );
        }
    }
}
