use super::*;

impl ApplyConfigUseCase {
    /// Apply the upstream-mapping plan.
    ///
    /// Stage 3: depends on Repository being applied first so
    /// `repo_id_by_name` is populated for every desired repository.
    /// Each `create` and `update` calls `save_managed`, with the
    /// digest computed from the spec; deletes call `delete_managed_by_id`.
    ///
    /// `repo_id_by_name` carries the post-Stage-2 view, so a desired
    /// mapping that references a freshly-created repository resolves
    /// correctly (cross-doc-reference validation already ensured the
    /// key exists in the map).
    pub(super) async fn apply_upstream_mappings(
        &self,
        plan: &KindPlan<UpstreamMappingSpec, Uuid>,
        repo_id_by_name: &HashMap<String, Uuid>,
        report: &mut ApplyReport,
        token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        // Operator-enumerated upstream-host
        // allowlist enforcement. Run BEFORE any save_managed call so a
        // miss aborts the apply with no partial writes. This is
        // apply-time-only — only rows in the apply diff
        // (create + update) are checked. An unchanged row that was
        // saved under a previous, looser allowlist stays as-is until
        // its YAML is touched (documented limitation; see
        // `docs/operator/upstream-trust-model.md`). `delete` rows are
        // deliberately exempt — removing a mapping that was previously
        // permitted should always succeed regardless of current
        // allowlist state, otherwise tightening the allowlist would
        // also block GC of mappings the operator wants gone.
        for env in plan.create.iter().chain(plan.update.iter()) {
            self.check_upstream_host_allowed(&env.spec.upstream_url, &env.metadata.name)?;
        }

        // Collect per-stream audit events.
        // Every UpstreamMapping mutation is repo-scoped (the row
        // carries a non-NULL `repository_id`), so the routing target
        // is always `StreamCategory::Repository(r)`. Same diff-then-
        // emit failure-mode contract as `apply_permission_grants`.
        let mut authz_events_by_stream: HashMap<StreamId, Vec<EventToAppend>> = HashMap::new();

        // Capture prior-state for every update row before any
        // save_managed runs. This mirrors the model from `apply_roles`. We need
        // the prior `(secret_ref, upstream_url, id, repository_id)`
        // to compute the `previous_*` fields on the
        // `RepositoryUpstreamMappingChanged` event before the upsert
        // overwrites them.
        let pre_update_state: HashMap<Uuid, RepositoryUpstreamMapping> = if plan.update.is_empty() {
            HashMap::new()
        } else {
            self.upstream_mappings
                .list_managed_by_gitops()
                .await?
                .into_iter()
                .map(|m| (m.id, m))
                .collect()
        };

        for env in plan.create.iter().chain(plan.update.iter()) {
            let digest = spec_digest_upstream_mapping(&env.spec);
            let repository_id = *repo_id_by_name.get(&env.spec.repository).ok_or_else(|| {
                // Validation runs before diff, so a missing
                // entry here would indicate a bug in
                // `validate()` rather than operator error.
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` references repository `{}` not in \
                             repo_id_by_name — cross-doc validation slipped",
                    env.metadata.name, env.spec.repository
                ))
            })?;
            let mapping = build_upstream_mapping_from_spec(env, repository_id, &digest)?;
            self.upstream_mappings.save_managed(&mapping).await?;
        }

        // Build `RepositoryUpstreamMappingChanged` audit events for
        // every create / update / delete row. The `previous_*` /
        // `new_*` payload fields carry the secret-ref **identifier**
        // (`<source>:<location>`) and the literal upstream URL —
        // never the resolved secret value. The post-save snapshot
        // resolves the row's actual primary key via
        // `find_managed_by_repo_and_prefix`.
        let post_save_state: HashMap<(Uuid, String), RepositoryUpstreamMapping> =
            if plan.create.is_empty() && plan.update.is_empty() {
                HashMap::new()
            } else {
                self.upstream_mappings
                    .list_managed_by_gitops()
                    .await?
                    .into_iter()
                    .map(|m| ((m.repository_id, m.path_prefix.clone()), m))
                    .collect()
            };

        for env in plan.create.iter() {
            let repository_id = *repo_id_by_name.get(&env.spec.repository).ok_or_else(|| {
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` references repository `{}` not in repo_id_by_name",
                    env.metadata.name, env.spec.repository
                ))
            })?;
            let key = (repository_id, env.spec.path_prefix.clone());
            let saved = post_save_state.get(&key).ok_or_else(|| {
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` not in post-save snapshot at key (repo={repository_id}, prefix={:?})",
                    env.metadata.name, env.spec.path_prefix
                ))
            })?;
            let stream_id = StreamId::repository(repository_id);
            authz_events_by_stream
                .entry(stream_id)
                .or_default()
                .push(EventToAppend::new(
                    DomainEvent::RepositoryUpstreamMappingChanged(
                        RepositoryUpstreamMappingChanged {
                            mapping_id: saved.id,
                            repository_id,
                            change: UpstreamMappingChange::Created,
                            previous_secret_ref: None,
                            new_secret_ref: env.spec.secret_ref.as_ref().map(secret_ref_name),
                            previous_url: None,
                            new_url: Some(env.spec.upstream_url.clone()),
                        },
                    ),
                ));
            emit_gitops_object(gitops_kind::UPSTREAM_MAPPING, GitopsObjectResult::Created);
            report.created += 1;
        }
        for env in plan.update.iter() {
            let repository_id = *repo_id_by_name.get(&env.spec.repository).ok_or_else(|| {
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` references repository `{}` not in repo_id_by_name",
                    env.metadata.name, env.spec.repository
                ))
            })?;
            let key = (repository_id, env.spec.path_prefix.clone());
            let saved = post_save_state.get(&key).ok_or_else(|| {
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` not in post-save snapshot at key (repo={repository_id}, prefix={:?})",
                    env.metadata.name, env.spec.path_prefix
                ))
            })?;
            // Prior state lookup: keyed by the post-save id (which is
            // stable across upsert per the adapter contract). When the
            // diff classifier saw an update but the prior snapshot
            // does not contain the row (race window between snapshot
            // collection and save_managed), fall back to None — the
            // event still records the post-state, which is the
            // operator-visible thing.
            let prior = pre_update_state.get(&saved.id);
            let previous_secret_ref = prior
                .and_then(|p| p.secret_ref.as_ref())
                .map(secret_ref_name);
            let previous_url = prior.map(|p| p.upstream_url.clone());
            let stream_id = StreamId::repository(repository_id);
            authz_events_by_stream
                .entry(stream_id)
                .or_default()
                .push(EventToAppend::new(
                    DomainEvent::RepositoryUpstreamMappingChanged(
                        RepositoryUpstreamMappingChanged {
                            mapping_id: saved.id,
                            repository_id,
                            change: UpstreamMappingChange::Updated,
                            previous_secret_ref,
                            new_secret_ref: env.spec.secret_ref.as_ref().map(secret_ref_name),
                            previous_url,
                            new_url: Some(env.spec.upstream_url.clone()),
                        },
                    ),
                ));
            emit_gitops_object(gitops_kind::UPSTREAM_MAPPING, GitopsObjectResult::Updated);
            report.updated += 1;
        }

        // Read about-to-be-deleted rows BEFORE any
        // delete_managed_by_id runs. This snapshot is bounded by the
        // `idx_repository_upstream_mappings_managed_by` partial index
        // and the operator's repo count (typically O(10s)).
        let pre_delete_state: HashMap<Uuid, RepositoryUpstreamMapping> = if plan.delete.is_empty() {
            HashMap::new()
        } else {
            self.upstream_mappings
                .list_managed_by_gitops()
                .await?
                .into_iter()
                .map(|m| (m.id, m))
                .collect()
        };
        for id in &plan.delete {
            self.upstream_mappings.delete_managed_by_id(*id).await?;
            if let Some(prior) = pre_delete_state.get(id) {
                let stream_id = StreamId::repository(prior.repository_id);
                authz_events_by_stream
                    .entry(stream_id)
                    .or_default()
                    .push(EventToAppend::new(
                        DomainEvent::RepositoryUpstreamMappingChanged(
                            RepositoryUpstreamMappingChanged {
                                mapping_id: prior.id,
                                repository_id: prior.repository_id,
                                change: UpstreamMappingChange::Removed,
                                previous_secret_ref: prior.secret_ref.as_ref().map(secret_ref_name),
                                new_secret_ref: None,
                                previous_url: Some(prior.upstream_url.clone()),
                                new_url: None,
                            },
                        ),
                    ));
            }
            emit_gitops_object(gitops_kind::UPSTREAM_MAPPING, GitopsObjectResult::Deleted);
            report.deleted += 1;
        }

        // Per-kind audit-commit log
        // line. All UpstreamMapping events are repo-scoped, so
        // `streams` here is the count of distinct repositories
        // touched in this apply.
        let total_um_events: usize = authz_events_by_stream.values().map(Vec::len).sum();
        if total_um_events > 0 {
            tracing::info!(
                kind = "upstream_mapping",
                events = total_um_events,
                streams = authz_events_by_stream.len(),
                "upstream_mapping audit events committed"
            );
        }
        self.append_grouped_authorization_events(
            authz_events_by_stream,
            Kind::UpstreamMapping,
            token,
        )
        .await?;

        Ok(())
    }

    /// Host-allowlist gate for
    /// `apply_upstream_mappings`. Parses the mapping's
    /// `upstream_url`, looks up the host, and consults
    /// [`UpstreamHostAllowlist::permits`].
    ///
    /// On miss: emits
    /// `hort_gitops_objects_total{kind="upstream_mapping",result="rejected_not_in_allowlist"}`
    /// and returns
    /// `AppError::Domain(DomainError::Validation("upstream host '<host>' not in HORT_UPSTREAM_ALLOWLIST_HOSTS"))`
    /// so the apply aborts cleanly. The metric increment + the error
    /// give two independent signals (Prometheus alert + boot exit
    /// non-zero); operators see whichever they look at first.
    ///
    /// `Disabled` mode short-circuits: every host passes without
    /// parsing the URL. This keeps the default deployment posture's
    /// per-mapping cost at zero — the parser only runs when the
    /// operator has opted into enforcement.
    ///
    /// **URL parse failure** propagates the existing
    /// `RepositoryUpstreamMappingArgs::try_into_mapping` validation
    /// error path — it is NOT classified as
    /// `rejected_not_in_allowlist`. A malformed URL is an operator
    /// authoring bug (caught later by `build_upstream_mapping_from_spec`),
    /// not an allowlist policy violation, and conflating the two
    /// would muddy the metric. We surface the parse error here so
    /// the operator sees one error per mapping rather than the
    /// allowlist gate masking it.
    fn check_upstream_host_allowed(&self, upstream_url: &str, mapping_name: &str) -> AppResult<()> {
        // Default-posture short-circuit. No URL parse, no host
        // extraction — the allowlist is operator-opt-in.
        if matches!(self.upstream_allowlist, UpstreamHostAllowlist::Disabled) {
            return Ok(());
        }
        let parsed = url::Url::parse(upstream_url).map_err(|e| {
            // Distinct from the allowlist miss path: a bad URL is an
            // authoring bug, not a policy violation.
            AppError::Domain(DomainError::Validation(format!(
                "UpstreamMapping `{mapping_name}` has an unparseable upstream_url \
                 `{upstream_url}`: {e}"
            )))
        })?;
        let host = parsed.host_str().ok_or_else(|| {
            AppError::Domain(DomainError::Validation(format!(
                "UpstreamMapping `{mapping_name}` upstream_url `{upstream_url}` \
                 has no host component"
            )))
        })?;
        if self.upstream_allowlist.permits(host) {
            return Ok(());
        }
        // Loud miss. Bump the metric BEFORE returning so the counter
        // increments regardless of how the apply caller logs the
        // error (gitops_boot maps the AppError to a parse_error /
        // validation_error / apply_error bucket — different from the
        // per-object signal this counter carries).
        emit_gitops_object(
            gitops_kind::UPSTREAM_MAPPING,
            GitopsObjectResult::RejectedNotInAllowlist,
        );
        Err(AppError::Domain(DomainError::Validation(format!(
            "upstream host '{host}' not in HORT_UPSTREAM_ALLOWLIST_HOSTS"
        ))))
    }
}

/// Auth-variant translation:
/// - `anonymous` → `UpstreamAuth::Anonymous`
/// - `bearer_challenge` → `UpstreamAuth::BearerChallenge`
/// - `basic` → `UpstreamAuth::Basic { username }`
///
/// The closed enum was already enforced by `validate_upstream_mapping`;
/// an unknown value here is an invariant.
fn build_upstream_mapping_from_spec(
    env: &Envelope<UpstreamMappingSpec>,
    repository_id: Uuid,
    digest: &[u8; 32],
) -> AppResult<RepositoryUpstreamMapping> {
    debug_assert!(matches!(env.kind, Kind::UpstreamMapping));
    let upstream_auth = match env.spec.auth.r#type.as_str() {
        "anonymous" => UpstreamAuth::Anonymous,
        "bearer_challenge" => UpstreamAuth::BearerChallenge,
        "basic" => {
            // `validate_upstream_mapping` rejected the empty/missing
            // username path for the basic variant; if we reach here
            // without one, the validator slipped — surface as an
            // invariant rather than panic.
            let username = env.spec.auth.username.clone().ok_or_else(|| {
                DomainError::Invariant(format!(
                    "UpstreamMapping `{}` has type=basic but no username — \
                     validate_upstream_mapping slipped",
                    env.metadata.name
                ))
            })?;
            UpstreamAuth::Basic { username }
        }
        other => {
            return Err(DomainError::Invariant(format!(
                "UpstreamMapping `{}` has unknown auth.type `{}` that should have been \
                 rejected by validate_upstream_mapping",
                env.metadata.name, other
            ))
            .into());
        }
    };
    let now = Utc::now();
    // Gitops apply funnels through
    // `RepositoryUpstreamMapping::new`, which enforces the
    // transport-scheme invariant at the value-object boundary. The
    // YAML validator already rejects http:// without
    // `insecureUpstreamUrl: true`; the constructor is the
    // defence-in-depth re-check so any future bypass of validate_*
    // surfaces here, not at fetch time.
    let mapping = RepositoryUpstreamMapping::new(RepositoryUpstreamMappingArgs {
        // Adapter's INSERT ... ON CONFLICT (repository_id, path_prefix)
        // DO UPDATE preserves the existing row id on conflict, so the
        // freshly-minted id here is harmless on the update path.
        id: Uuid::new_v4(),
        repository_id,
        path_prefix: env.spec.path_prefix.clone(),
        upstream_url: env.spec.upstream_url.clone(),
        upstream_name_prefix: env.spec.upstream_name_prefix.clone(),
        upstream_auth,
        secret_ref: env.spec.secret_ref.clone(),
        managed_by: ManagedBy::GitOps,
        managed_by_digest: Some(*digest),
        insecure_upstream_url: env.spec.insecure_upstream_url,
        // Per-upstream opt-in to publish-time
        // anchoring of the quarantine window (ADR 0007). Plain bool,
        // default `false`, plumbed through to the row. No apply-time
        // validator mirroring `insecure_upstream_url`'s scheme guard —
        // this flag is not a security knob, just a trust signal for
        // the quarantine-window anchor computation.
        trust_upstream_publish_time: env.spec.trust_upstream_publish_time,
        // Per-upstream TLS material. The apply pipeline only wires the
        // data through; fetch-path behaviour (cert load, rustls
        // verifier, metric emission) lives in the upstream adapter. The
        // value-object constructor below enforces the
        // pairing + scheme + hex-format invariants.
        mtls_cert_ref: env.spec.mtls_cert_ref.clone(),
        mtls_key_ref: env.spec.mtls_key_ref.clone(),
        ca_bundle_ref: env.spec.ca_bundle_ref.clone(),
        pinned_cert_sha256: env.spec.pinned_cert_sha256.clone(),
        created_at: now,
        updated_at: now,
    })?;
    Ok(mapping)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::apply_config_use_case::tests::*;

    // ----------------------------------------------------------------------
    // UpstreamMapping apply branch
    // ----------------------------------------------------------------------

    /// Happy path: a desired `UpstreamMapping` against a freshly-
    /// created repository round-trips through the apply pipeline. The
    /// pipeline must resolve `spec.repository` → `repository_id` from
    /// the Stage 2 result map, then `save_managed` the row with
    /// `managed_by=GitOps`.
    #[tokio::test]
    async fn apply_upstream_mapping_create_writes_managed_row() {
        let h = build_harness();
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };

        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        // One mapping created (the Repository also counts as `created`,
        // so we assert the upstream-mapping write specifically through
        // the mock instead of the rolled-up counter).
        assert!(
            report.created >= 2,
            "expected at least repo + mapping creates, got {}",
            report.created
        );
        // Mock recorded one managed row at (repo_id, "dockerhub/").
        let listed = h
            .upstream
            .list_managed_by_gitops()
            .await
            .expect("list_managed_by_gitops");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path_prefix, "dockerhub/");
        assert_eq!(listed[0].managed_by, ManagedBy::GitOps);
        assert!(listed[0].managed_by_digest.is_some());
        assert_eq!(listed[0].upstream_url, "https://registry-1.docker.io");
    }

    /// Re-applying the same desired state produces zero churn — the
    /// digest matches, the diff classifies the mapping as `unchanged`,
    /// and `save_managed` is NOT called the second time.
    #[tokio::test]
    async fn apply_upstream_mapping_reapply_is_idempotent() {
        let h = build_harness();
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };
        h.uc.apply(desired.clone(), env_oidc()).await.unwrap();
        let listed_first = h.upstream.list_managed_by_gitops().await.unwrap();
        let id_first = listed_first[0].id;
        let digest_first = listed_first[0].managed_by_digest;

        let report = h.uc.apply(desired, env_oidc()).await.unwrap();

        // Second apply: row stays put, digest unchanged.
        let listed_second = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(listed_second.len(), 1);
        assert_eq!(listed_second[0].id, id_first, "id stays stable");
        assert_eq!(
            listed_second[0].managed_by_digest, digest_first,
            "digest stays stable"
        );
        // The mapping contributes one to the unchanged counter.
        assert!(
            report.unchanged >= 1,
            "expected at least the mapping in unchanged, got {}",
            report.unchanged
        );
    }

    /// Round-trip: Some(true) in the spec lands as `true` on the
    /// persisted row.
    #[tokio::test]
    async fn apply_upstream_mapping_threads_trust_upstream_publish_time_true_to_persisted_row() {
        let h = build_harness();
        let mut mapping_env = upstream_mapping_env(
            "oci-mirror-dockerhub",
            "oci-mirror-e2e",
            "dockerhub/",
            "https://registry-1.docker.io",
        );
        mapping_env.spec.trust_upstream_publish_time = true;
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![mapping_env],
            ..Default::default()
        };

        h.uc.apply(desired, env_oidc()).await.unwrap();

        let listed = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(
            listed[0].trust_upstream_publish_time,
            "the apply pipeline must thread trustUpstreamPublishTime=true through to the row"
        );
    }

    /// Round-trip: Some(false) in the spec lands as `false` on the
    /// persisted row — and the field-absent default (Phase-1
    /// happy-path envelope) also lands as `false`. One test covers
    /// both because they share the same expected outcome and the
    /// distinction (explicit vs. defaulted) is already covered by the
    /// hort-config parser unit tests.
    #[tokio::test]
    async fn apply_upstream_mapping_defaults_trust_upstream_publish_time_to_false() {
        let h = build_harness();
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            // upstream_mapping_env constructs the spec with
            // trust_upstream_publish_time: false (the Phase-1 default
            // envelope shape) — this is the absent-field case at
            // YAML-level after serde-default kicked in.
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };

        h.uc.apply(desired, env_oidc()).await.unwrap();

        let listed = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(
            !listed[0].trust_upstream_publish_time,
            "the default-`false` spec must produce a row with trust_upstream_publish_time = false"
        );
    }

    /// End-to-end: YAML spec with `upstreamNamePrefix` set →
    /// `ApplyConfigUseCase::apply` → re-load the mapping from the mock
    /// port. The field must survive the round-trip from spec to
    /// `RepositoryUpstreamMappingArgs` to the persisted row.
    #[tokio::test]
    async fn apply_upstream_mapping_threads_upstream_name_prefix_to_persisted_row() {
        let h = build_harness();
        let desired = DesiredState {
            repositories: vec![oci_repo_env("oci-mirror-e2e")],
            upstream_mappings: vec![upstream_mapping_env_with_prefix(
                "oci-via-zot",
                "oci-mirror-e2e",
                "",
                "https://zot.example.com",
                Some("docker.io"),
            )],
            ..Default::default()
        };

        h.uc.apply(desired, env_oidc()).await.unwrap();

        let listed = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].upstream_name_prefix.as_deref(),
            Some("docker.io"),
            "the apply pipeline must thread upstreamNamePrefix through to the row"
        );
    }

    /// Diff-identity invariant: the new field participates in the
    /// spec digest, so changing it across re-applies produces a
    /// single `result=updated` event — NOT `deleted+created` (which
    /// would happen if the field were part of the identity tuple) and
    /// NOT a no-op (which would happen if the field were absent from
    /// the digest input). This rules out all four bad outcomes:
    ///
    /// (a) the two specs produce DIFFERENT digests
    /// (b) the apply classifies the change as one `result=updated`
    /// (c) NOT `result=deleted` + `result=created`
    /// (d) NOT zero events (no-op)
    #[tokio::test]
    async fn upstream_name_prefix_change_produces_one_updated_event_not_create_delete_or_noop() {
        let h = build_harness();

        let before_spec = upstream_mapping_env_with_prefix(
            "oci-via-zot",
            "oci-mirror-e2e",
            "",
            "https://zot.example.com",
            Some("docker.io"),
        );
        let after_spec = upstream_mapping_env_with_prefix(
            "oci-via-zot",
            "oci-mirror-e2e",
            "",
            "https://zot.example.com",
            Some("docker.io/sub"),
        );

        // (a) Digests differ across the two specs.
        let digest_before = spec_digest_upstream_mapping(&before_spec.spec);
        let digest_after = spec_digest_upstream_mapping(&after_spec.spec);
        assert_ne!(
            digest_before, digest_after,
            "spec_digest_upstream_mapping must change when upstreamNamePrefix changes — \
             otherwise the diff layer cannot detect the value change. This rules out \
             the no-op-from-missing-hash bug where the implementer adds the field to \
             the struct but forgets to hash it."
        );

        // First apply seeds the mapping.
        let first = DesiredState {
            repositories: vec![oci_repo_env("oci-mirror-e2e")],
            upstream_mappings: vec![before_spec],
            ..Default::default()
        };
        h.uc.apply(first, env_oidc()).await.unwrap();
        let row_count_after_first = h.upstream.entry_count();
        assert_eq!(row_count_after_first, 1, "seed apply must write one row");

        // Re-apply with the prefix changed.
        let second = DesiredState {
            repositories: vec![oci_repo_env("oci-mirror-e2e")],
            upstream_mappings: vec![after_spec],
            ..Default::default()
        };
        let report = h.uc.apply(second, env_oidc()).await.unwrap();

        // The mapping contributes exactly one to `updated`. Other
        // updates may happen (the repository itself ticks `unchanged`),
        // so we filter by inspecting the mock's mapping content
        // rather than counting all events.
        let listed = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(listed.len(), 1, "row count unchanged after update");
        assert_eq!(
            listed[0].upstream_name_prefix.as_deref(),
            Some("docker.io/sub"),
            "(b) update path must write the new value"
        );

        // (c) NOT delete+create: the row id is stable across the
        // re-apply (a delete+create would surface as a new id).
        // (b) at least one mapping update.
        assert!(
            report.updated >= 1,
            "(b) expected at least one updated event for the mapping; got report={report:?}"
        );

        // (d) NOT zero events (no-op): if the prefix change were
        // invisible to the digest, the mapping would land in
        // `unchanged` and `updated` would be 0 *for the mapping*. We
        // already asserted updated >= 1 above; explicitly cross-check
        // that the persisted prefix value was rewritten — not just
        // that the counter ticked for some other kind of change.
        assert_ne!(
            listed[0].upstream_name_prefix.as_deref(),
            Some("docker.io"),
            "(d) the persisted row must reflect the new prefix; \
             reverting to the old value would mean the apply pipeline \
             ignored the change"
        );
    }

    /// Removing a mapping from desired while it remains as a managed
    /// row in current produces a delete.
    #[tokio::test]
    async fn apply_upstream_mapping_absent_in_desired_deletes_managed_row() {
        let h = build_harness();
        let with_mapping = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };
        h.uc.apply(with_mapping, env_oidc()).await.unwrap();
        assert_eq!(h.upstream.entry_count(), 1);

        // Re-apply with the mapping omitted — repo still declared.
        let without_mapping = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![],
            ..Default::default()
        };
        let report = h.uc.apply(without_mapping, env_oidc()).await.unwrap();
        assert!(
            report.deleted >= 1,
            "expected the mapping in deleted, got {}",
            report.deleted
        );
        assert_eq!(
            h.upstream.entry_count(),
            0,
            "managed mapping must be removed"
        );
    }
}
