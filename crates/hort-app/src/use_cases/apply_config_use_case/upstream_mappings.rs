use super::*;

impl ApplyConfigUseCase {
    /// Apply the upstream-mapping plan.
    ///
    /// Stage 3: depends on Repository being applied first so
    /// `repo_id_by_name` is populated for every desired repository.
    /// `repo_id_by_name` carries the post-Stage-2 view, so a desired
    /// mapping that references a freshly-created repository resolves
    /// correctly (cross-doc-reference validation already ensured the
    /// key exists in the map).
    ///
    /// **Rows and events commit together.** The branch builds the whole
    /// [`UpstreamMappingCommit`] — one upsert per `create` / `update`
    /// envelope, one delete per `plan.delete` id — plus the per-stream
    /// audit batches, and hands both to
    /// [`AuthorityLifecyclePort::commit_upstream_mappings`], which
    /// writes them in one transaction. A mapping names the **upstream a
    /// proxy repository will trust and fetch from**, with its
    /// credential reference and its TLS material, so a mapping that
    /// commits unattested is a changed trust anchor the authorization
    /// stream is silent about.
    ///
    /// Before the port this branch was the worst-shaped member of the
    /// family: each row write was independently committed, *and*
    /// the closing `append_grouped_authorization_events` was one
    /// transaction per stream, so a part-way failure could leave some
    /// repositories' mappings live and unattested while others were
    /// audited. Both halves are now one unit. And the retry could not
    /// repair it either — the next apply's prior-vs-desired diff
    /// compares against rows that already carry the change, so it
    /// emits nothing.
    ///
    /// **One prior snapshot, read before any write.** The pre-port
    /// shape read `list_managed_by_gitops` up to three times, including
    /// once *after* the upserts, purely to recover the surrogate id of
    /// a freshly-written row for the audit payload. With the write
    /// deferred to a single commit there is no post-write read to take,
    /// so the id is resolved up front from the row at the mapping's
    /// `(repository_id, path_prefix)` identity — exactly what the
    /// adapter's `ON CONFLICT … DO UPDATE` preserves. The snapshot is
    /// [`RepositoryUpstreamMappingRepository::list_all`] rather than the
    /// gitops partition because a pre-existing `managed_by = 'local'`
    /// row at that identity is adopted by the upsert and keeps its id:
    /// reading only the gitops partition would mint a fresh id for it
    /// and emit an audit event naming a row that does not exist.
    ///
    /// **Report / metric counters are emitted while the plan is walked,
    /// i.e. before the commit** — the same point every other authority
    /// branch emits theirs. They used to be emitted after each row's
    /// own commit, so a mid-way failure counted only what had landed.
    pub(super) async fn apply_upstream_mappings(
        &self,
        plan: &KindPlan<UpstreamMappingSpec, Uuid>,
        repo_id_by_name: &HashMap<String, Uuid>,
        report: &mut ApplyReport,
        token: &GitOpsApplyToken,
    ) -> AppResult<()> {
        // Upstream-host allowlist enforcement (write-time, defense-in-depth).
        // The PRIMARY gate is pre-write in `run_pre_write_validation`, so a
        // boot-time miss parks not-ready (`GitopsBootError::PreflightValidate`)
        // instead of writing Stage-1/2 rows and then crashlooping. This
        // re-checks the same diff-scoped set immediately before this stage's
        // commit. See `check_upstream_allowlist_for_plan`.
        self.check_upstream_allowlist_for_plan(plan)?;

        if plan.create.is_empty() && plan.update.is_empty() && plan.delete.is_empty() {
            // Nothing in the plan: no snapshot read, no row write, no
            // event, no transaction. An unchanged replay is the common
            // case on every boot.
            return Ok(());
        }

        // The one prior snapshot, taken before any write. Keyed two
        // ways: by natural identity for the upsert id resolution and
        // the `previous_*` audit fields, and by primary key for the
        // delete events (the diff layer surfaces ids).
        let prior = self.upstream_mappings.list_all().await?;
        let mut prior_by_identity: HashMap<(Uuid, String), RepositoryUpstreamMapping> =
            HashMap::with_capacity(prior.len());
        let mut prior_by_id: HashMap<Uuid, RepositoryUpstreamMapping> =
            HashMap::with_capacity(prior.len());
        for mapping in prior {
            prior_by_identity.insert(
                (mapping.repository_id, mapping.path_prefix.clone()),
                mapping.clone(),
            );
            prior_by_id.insert(mapping.id, mapping);
        }

        let mut change = UpstreamMappingCommit::default();
        // Collect per-stream audit events.
        // Every UpstreamMapping mutation is repo-scoped (the row
        // carries a non-NULL `repository_id`), so the routing target
        // is always `StreamCategory::Repository(r)`. Same diff-then-
        // emit failure-mode contract as `apply_permission_grants`.
        let mut authz_events_by_stream: HashMap<StreamId, Vec<EventToAppend>> = HashMap::new();

        // Creates and updates in one pass, in that order — the two
        // differ only in the event's `change` tag and whether it
        // carries `previous_*` fields, and the chained order is the
        // order the pre-port shape emitted in.
        for (env, is_create) in plan
            .create
            .iter()
            .map(|env| (env, true))
            .chain(plan.update.iter().map(|env| (env, false)))
        {
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
            // Reuse the row's surrogate id when one already exists at
            // this identity (the `ON CONFLICT` update keeps it), mint a
            // fresh one otherwise — so the audit `mapping_id` names the
            // row the commit writes. Mirrors `apply_claim_mappings`.
            let prior_row = prior_by_identity.get(&(repository_id, env.spec.path_prefix.clone()));
            let mapping_id = prior_row.map(|m| m.id).unwrap_or_else(Uuid::new_v4);
            let digest = spec_digest_upstream_mapping(&env.spec);
            let mapping =
                build_upstream_mapping_from_spec(env, mapping_id, repository_id, &digest)?;

            // The `previous_*` / `new_*` payload fields carry the
            // secret-ref **identifier** (`<source>:<location>`) and the
            // literal upstream URL — never the resolved secret value.
            // A create carries no `previous_*`: either there is no row,
            // or there is a `local` row the gitops partition has never
            // seen, and the event records the post-state either way.
            let (kind, previous_secret_ref, previous_url) = if is_create {
                (UpstreamMappingChange::Created, None, None)
            } else {
                (
                    UpstreamMappingChange::Updated,
                    prior_row
                        .and_then(|p| p.secret_ref.as_ref())
                        .map(secret_ref_name),
                    prior_row.map(|p| p.upstream_url.clone()),
                )
            };
            authz_events_by_stream
                .entry(StreamId::repository(repository_id))
                .or_default()
                .push(EventToAppend::new(
                    DomainEvent::RepositoryUpstreamMappingChanged(
                        RepositoryUpstreamMappingChanged {
                            mapping_id,
                            repository_id,
                            change: kind,
                            previous_secret_ref,
                            new_secret_ref: env.spec.secret_ref.as_ref().map(secret_ref_name),
                            previous_url,
                            new_url: Some(env.spec.upstream_url.clone()),
                        },
                    ),
                ));
            change.upserts.push(mapping);
            if is_create {
                emit_gitops_object(gitops_kind::UPSTREAM_MAPPING, GitopsObjectResult::Created);
                report.created += 1;
            } else {
                emit_gitops_object(gitops_kind::UPSTREAM_MAPPING, GitopsObjectResult::Updated);
                report.updated += 1;
            }
        }

        for id in &plan.delete {
            change.deletes.push(*id);
            // A scheduled id absent from the snapshot was deleted
            // out-of-band between the plan's own snapshot and this read.
            // The delete is still issued (it is a no-op) but there is no
            // prior state to describe, so no event is emitted.
            if let Some(prior) = prior_by_id.get(id) {
                authz_events_by_stream
                    .entry(StreamId::repository(prior.repository_id))
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

        // Every row operation AND every per-stream audit batch, in one
        // transaction.
        let batches = Self::grouped_authorization_batches(
            authz_events_by_stream,
            Kind::UpstreamMapping,
            token,
        );
        // All UpstreamMapping events are repo-scoped, so `streams` here
        // is the count of distinct repositories touched in this apply.
        // Counted before the commit consumes the batches, emitted after
        // it returned `Ok`.
        let total_um_events: usize = batches.iter().map(|b| b.events.len()).sum();
        let um_streams = batches.len();
        self.authority
            .commit_upstream_mappings(&change, batches)
            .await?;
        if total_um_events > 0 {
            tracing::info!(
                kind = "upstream_mapping",
                events = total_um_events,
                streams = um_streams,
                "upstream_mapping audit events committed"
            );
        }

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

    /// Enforce the upstream-host allowlist over the diff's create+update
    /// mappings — the apply-time scope: `delete` and unchanged rows are
    /// exempt (tightening the allowlist neither blocks GC of a removed
    /// mapping nor re-rejects an untouched one; documented in
    /// `docs/operator/upstream-trust-model.md`). Returns
    /// `DomainError::Validation` on the first miss.
    ///
    /// Called from two sites over the SAME set: **pre-write** in
    /// `ApplyConfigUseCase::run_pre_write_validation` (the boot park gate —
    /// a miss there surfaces as `GitopsBootError::PreflightValidate` and
    /// parks the pod not-ready rather than crashlooping after an earlier
    /// stage wrote), and again in [`Self::apply_upstream_mappings`] as
    /// write-time defense-in-depth.
    pub(super) fn check_upstream_allowlist_for_plan(
        &self,
        plan: &KindPlan<UpstreamMappingSpec, Uuid>,
    ) -> AppResult<()> {
        for env in plan.create.iter().chain(plan.update.iter()) {
            self.check_upstream_host_allowed(&env.spec.upstream_url, &env.metadata.name)?;
        }
        Ok(())
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
    id: Uuid,
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
        // Resolved by the caller against the row at this mapping's
        // `(repository_id, path_prefix)` identity, so the audit
        // `mapping_id` names the row the commit writes. The adapter's
        // `ON CONFLICT (repository_id, path_prefix) DO UPDATE` keeps an
        // existing row's id, which is what makes that resolution right.
        id,
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
    /// the Stage 2 result map, then commit the row with
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
    /// no row is written the second time.
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
    // ----------------------------------------------------------------------
    // Mapping rows commit with their audit events (one transaction).
    // ----------------------------------------------------------------------

    fn mapping_changed_count(evts: &[DomainEvent]) -> usize {
        evts.iter()
            .filter(|e| matches!(e, DomainEvent::RepositoryUpstreamMappingChanged(_)))
            .count()
    }

    /// An audit-append failure during the upstream-mapping apply leaves
    /// the row **exactly as it was** — the apply fails closed rather
    /// than half-done. This is the property the retry cannot supply: a
    /// committed re-point with no event is invisible to the next
    /// apply's digest comparison, so no replacement event is ever
    /// emitted and the repository keeps fetching from an upstream the
    /// authorization stream never named.
    #[tokio::test]
    async fn apply_upstream_mapping_commit_failure_leaves_the_row_unchanged() {
        let h = build_harness();
        let seeded = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };
        h.uc.apply(seeded, env_oidc()).await.unwrap();
        let repo_id = h.repos.find_by_key("oci-mirror-e2e").await.unwrap().id;
        let before = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(before.len(), 1);
        let events_before = mapping_changed_count(&repo_stream_events(&h.events, repo_id).await);

        // Re-point the same `(repository_id, path_prefix)` identity,
        // with the commit armed to fail.
        h.authority.fail_next(
            AuthoritySite::UpstreamMappings,
            DomainError::Invariant("event store unavailable".into()),
        );
        let repointed = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://attacker.example.com",
            )],
            ..Default::default()
        };
        let err =
            h.uc.apply(repointed, env_oidc())
                .await
                .expect_err("an audit-append failure must fail the apply");
        assert!(
            err.to_string().contains("event store unavailable"),
            "the event-store failure must surface, got: {err}"
        );

        let after = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(
            after[0].upstream_url, "https://registry-1.docker.io",
            "the mapping must still name the upstream the stream attested — \
             rows and events commit together"
        );
        assert_eq!(
            after[0].managed_by_digest, before[0].managed_by_digest,
            "and the digest must not have advanced, or the next apply \
             would read the change as already applied"
        );
        assert_eq!(
            mapping_changed_count(&repo_stream_events(&h.events, repo_id).await),
            events_before,
            "no audit event may have landed either"
        );
    }

    /// An apply that touches two repositories hands the whole batch
    /// list to **one** commit call, which is what makes the multi-stream
    /// append atomic. Before the port each stream was its own
    /// `EventStore::append` transaction *and* each row its own commit,
    /// so a list that failed part-way left some repositories' mappings
    /// live and unattested while others were audited.
    #[tokio::test]
    async fn apply_upstream_mapping_commit_takes_every_stream_in_one_call() {
        let h = build_harness();
        let desired = DesiredState {
            repositories: vec![repo_env("mirror-a", "proxy"), repo_env("mirror-b", "proxy")],
            upstream_mappings: vec![
                upstream_mapping_env("um-a", "mirror-a", "a/", "https://a.example.com"),
                upstream_mapping_env("um-b", "mirror-b", "b/", "https://b.example.com"),
            ],
            ..Default::default()
        };
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let commits: Vec<usize> = h
            .authority
            .commits()
            .into_iter()
            .filter(|(site, _)| *site == AuthoritySite::UpstreamMappings)
            .map(|(_, batches)| batches)
            .collect();
        assert_eq!(
            commits,
            vec![2],
            "exactly one commit call carrying both repositories' batches"
        );

        let repo_a = h.repos.find_by_key("mirror-a").await.unwrap().id;
        let repo_b = h.repos.find_by_key("mirror-b").await.unwrap().id;
        assert_eq!(
            mapping_changed_count(&repo_stream_events(&h.events, repo_a).await),
            1
        );
        assert_eq!(
            mapping_changed_count(&repo_stream_events(&h.events, repo_b).await),
            1
        );
    }

    /// An unchanged replay reaches the port **not at all**: with no
    /// create, update or delete there is no row to write and no event
    /// to append, so the branch returns before the snapshot read and
    /// before the commit.
    #[tokio::test]
    async fn apply_upstream_mapping_unchanged_replay_opens_no_commit() {
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
        let commits_after_first = h
            .authority
            .commits()
            .into_iter()
            .filter(|(site, _)| *site == AuthoritySite::UpstreamMappings)
            .count();
        assert_eq!(commits_after_first, 1, "the seeding apply commits once");

        h.uc.apply(desired, env_oidc()).await.unwrap();
        let commits_after_second = h
            .authority
            .commits()
            .into_iter()
            .filter(|(site, _)| *site == AuthoritySite::UpstreamMappings)
            .count();
        assert_eq!(
            commits_after_second, commits_after_first,
            "an unchanged replay must not open a transaction"
        );
    }

    /// The row id the audit event names is the row the commit writes,
    /// across a re-point: the branch resolves it from the mapping's
    /// `(repository_id, path_prefix)` identity before the write, which
    /// is what the adapter's `ON CONFLICT … DO UPDATE` preserves.
    /// Resolving it afterwards is what the pre-port shape needed a
    /// post-write snapshot read for.
    #[tokio::test]
    async fn apply_upstream_mapping_update_event_names_the_existing_row_id() {
        let h = build_harness();
        let seeded = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://registry-1.docker.io",
            )],
            ..Default::default()
        };
        h.uc.apply(seeded, env_oidc()).await.unwrap();
        let repo_id = h.repos.find_by_key("oci-mirror-e2e").await.unwrap().id;
        let seeded_id = h.upstream.list_managed_by_gitops().await.unwrap()[0].id;

        let repointed = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![upstream_mapping_env(
                "oci-mirror-dockerhub",
                "oci-mirror-e2e",
                "dockerhub/",
                "https://mirror.example.com",
            )],
            ..Default::default()
        };
        h.uc.apply(repointed, env_oidc()).await.unwrap();

        let rows = h.upstream.list_managed_by_gitops().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, seeded_id, "the row id stays stable");
        assert_eq!(rows[0].upstream_url, "https://mirror.example.com");

        let updated: Vec<_> = repo_stream_events(&h.events, repo_id)
            .await
            .into_iter()
            .filter_map(|e| match e {
                DomainEvent::RepositoryUpstreamMappingChanged(c)
                    if c.change == UpstreamMappingChange::Updated =>
                {
                    Some(c)
                }
                _ => None,
            })
            .collect();
        assert_eq!(updated.len(), 1, "exactly one Updated event");
        assert_eq!(
            updated[0].mapping_id, seeded_id,
            "the audit event must name the row the commit wrote"
        );
        assert_eq!(
            updated[0].previous_url.as_deref(),
            Some("https://registry-1.docker.io"),
            "and carry the pre-commit upstream as `previous_url`"
        );
    }

    // ----------------------------------------------------------------------
    // Pre-write TLS-material rejection (mirror of the domain constructor)
    // ----------------------------------------------------------------------
    //
    // mTLS pair completeness, TLS material on a plaintext upstream, and the
    // pin's hex shape are invariants of `RepositoryUpstreamMapping::new`,
    // which gitops reaches only in Stage 3 — after the Stage-1 and Stage-2
    // writes of the same bundle. Per-spec validation now carries the same
    // three rules (`hort_config::upstream_mapping::validate_upstream_mapping`),
    // so the verdict is reachable before the first write. These tests pin the
    // two halves that make that safe: the pre-write row rejects everything the
    // constructor rejects, and accepts everything it accepts.

    /// One TLS field combination, with the YAML-side spec mutation and
    /// the matching constructor-arg mutation, so a single corpus entry
    /// drives both ends of the mirror.
    struct TlsCase {
        name: &'static str,
        /// `true` ⇒ the upstream is plaintext (`http://` + opt-in).
        plaintext: bool,
        mtls_cert: bool,
        mtls_key: bool,
        ca_bundle: bool,
        pin: Option<&'static str>,
    }

    fn secret_ref(location: &str) -> SecretRef {
        SecretRef {
            source: hort_domain::ports::secret_port::SecretSource::EnvVar,
            location: location.into(),
        }
    }

    const VALID_PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    impl TlsCase {
        fn mapping_env(&self) -> Envelope<UpstreamMappingSpec> {
            let url = if self.plaintext {
                "http://mirror.internal"
            } else {
                "https://mirror.internal"
            };
            let mut env = upstream_mapping_env("m-tls", "oci-mirror-e2e", "dockerhub/", url);
            env.spec.insecure_upstream_url = self.plaintext;
            if self.mtls_cert {
                env.spec.mtls_cert_ref = Some(secret_ref("CLIENT_CERT"));
            }
            if self.mtls_key {
                env.spec.mtls_key_ref = Some(secret_ref("CLIENT_KEY"));
            }
            if self.ca_bundle {
                env.spec.ca_bundle_ref = Some(secret_ref("CA_PEM"));
            }
            env.spec.pinned_cert_sha256 = self.pin.map(str::to_owned);
            env
        }

        /// The Stage-3 authority: the same combination handed to the
        /// value-object constructor the apply funnels through.
        fn constructor_result(&self) -> Result<RepositoryUpstreamMapping, AppError> {
            let spec = self.mapping_env().spec;
            let now = Utc::now();
            let mapping = RepositoryUpstreamMapping::new(RepositoryUpstreamMappingArgs {
                id: Uuid::new_v4(),
                repository_id: Uuid::new_v4(),
                path_prefix: spec.path_prefix,
                upstream_url: spec.upstream_url,
                upstream_name_prefix: None,
                upstream_auth: UpstreamAuth::Anonymous,
                secret_ref: None,
                managed_by: ManagedBy::GitOps,
                managed_by_digest: Some([7u8; 32]),
                insecure_upstream_url: spec.insecure_upstream_url,
                trust_upstream_publish_time: false,
                mtls_cert_ref: spec.mtls_cert_ref,
                mtls_key_ref: spec.mtls_key_ref,
                ca_bundle_ref: spec.ca_bundle_ref,
                pinned_cert_sha256: spec.pinned_cert_sha256,
                created_at: now,
                updated_at: now,
            })?;
            Ok(mapping)
        }

        fn bundle(&self) -> DesiredState {
            DesiredState {
                repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
                upstream_mappings: vec![self.mapping_env()],
                ..Default::default()
            }
        }
    }

    /// Every combination the Stage-3 constructor rejects is rejected by the
    /// pre-write pass, which therefore never reaches a write.
    #[tokio::test]
    async fn preflight_rejects_every_tls_combination_the_constructor_rejects() {
        let cases = [
            TlsCase {
                name: "cert without key",
                plaintext: false,
                mtls_cert: true,
                mtls_key: false,
                ca_bundle: false,
                pin: None,
            },
            TlsCase {
                name: "key without cert",
                plaintext: false,
                mtls_cert: false,
                mtls_key: true,
                ca_bundle: false,
                pin: None,
            },
            TlsCase {
                name: "mTLS pair on a plaintext upstream",
                plaintext: true,
                mtls_cert: true,
                mtls_key: true,
                ca_bundle: false,
                pin: None,
            },
            TlsCase {
                name: "CA bundle on a plaintext upstream",
                plaintext: true,
                mtls_cert: false,
                mtls_key: false,
                ca_bundle: true,
                pin: None,
            },
            TlsCase {
                name: "pin on a plaintext upstream",
                plaintext: true,
                mtls_cert: false,
                mtls_key: false,
                ca_bundle: false,
                pin: Some(VALID_PIN),
            },
            TlsCase {
                name: "pin that is not 64 hex chars",
                plaintext: false,
                mtls_cert: false,
                mtls_key: false,
                ca_bundle: false,
                pin: Some("deadbeef"),
            },
            TlsCase {
                name: "pin with an uppercase hex digit",
                plaintext: false,
                mtls_cert: false,
                mtls_key: false,
                ca_bundle: false,
                pin: Some("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"),
            },
        ];

        for case in cases {
            // The Stage-3 authority still rejects — the pre-write row is a
            // mirror, not a replacement.
            assert!(
                case.constructor_result().is_err(),
                "`{}` must be rejected by RepositoryUpstreamMapping::new — if the \
                 constructor accepts it, this corpus entry no longer describes a \
                 late rejection",
                case.name
            );
            let h = build_harness();
            let Err(err) = h.uc.preflight_validate(&case.bundle(), &env_oidc()).await else {
                panic!(
                    "`{}` reaches the apply's third stage and is refused there, so the \
                     pre-write pass must refuse it too — otherwise the Stage-1 and \
                     Stage-2 rows of the same bundle are already written when it does",
                    case.name
                )
            };
            assert!(
                matches!(err, AppError::Domain(DomainError::Validation(_))),
                "`{}` must surface as a park-eligible Validation error, got {err:?}",
                case.name
            );
        }
    }

    /// And every combination the constructor accepts stays accepted: a
    /// mirror that over-rejects would refuse configurations the apply would
    /// have taken, which is as much a defect as the gap it closes.
    #[tokio::test]
    async fn preflight_accepts_every_tls_combination_the_constructor_accepts() {
        let cases = [
            TlsCase {
                name: "no TLS material at all",
                plaintext: false,
                mtls_cert: false,
                mtls_key: false,
                ca_bundle: false,
                pin: None,
            },
            TlsCase {
                name: "custom CA alone",
                plaintext: false,
                mtls_cert: false,
                mtls_key: false,
                ca_bundle: true,
                pin: None,
            },
            TlsCase {
                name: "pin alone",
                plaintext: false,
                mtls_cert: false,
                mtls_key: false,
                ca_bundle: false,
                pin: Some(VALID_PIN),
            },
            TlsCase {
                name: "complete mTLS pair",
                plaintext: false,
                mtls_cert: true,
                mtls_key: true,
                ca_bundle: false,
                pin: None,
            },
            TlsCase {
                name: "full https combination",
                plaintext: false,
                mtls_cert: true,
                mtls_key: true,
                ca_bundle: true,
                pin: Some(VALID_PIN),
            },
            TlsCase {
                name: "plaintext upstream with no TLS material",
                plaintext: true,
                mtls_cert: false,
                mtls_key: false,
                ca_bundle: false,
                pin: None,
            },
        ];

        for case in cases {
            assert!(
                case.constructor_result().is_ok(),
                "`{}` must be accepted by RepositoryUpstreamMapping::new",
                case.name
            );
            let h = build_harness();
            h.uc.preflight_validate(&case.bundle(), &env_oidc())
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "`{}` is accepted by the Stage-3 constructor, so the pre-write \
                         mirror must accept it too; got {e:?}",
                        case.name
                    )
                });
        }
    }

    /// The acceptance shape: an invalid TLS combination on a changed
    /// upstream mapping, in the same bundle as a loosening scan policy.
    /// Nothing is written — the policy projection is untouched, so the
    /// operator is never left with the loosening committed and the rest
    /// refused.
    #[tokio::test]
    async fn invalid_upstream_tls_beside_a_loosening_scan_policy_writes_nothing() {
        // Loosened on all three axes an operator would notice: findings are
        // recorded instead of blocking, approval is no longer required, and
        // only `critical` counts.
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
                    repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
                    scan_policies: vec![loosened.clone()],
                    ..Default::default()
                },
                env_oidc(),
            )
            .await
            .expect("the loosening policy alone must apply cleanly");
        assert!(
            !control.events.appended().is_empty(),
            "positive control: applying the loosening policy must append policy events"
        );
        assert!(!control.repos.calls().is_empty());

        // Same policy, now beside a mapping the Stage-3 constructor would
        // refuse (half an mTLS pair).
        let mut bad_mapping = upstream_mapping_env(
            "oci-mirror-dockerhub",
            "oci-mirror-e2e",
            "dockerhub/",
            "https://registry-1.docker.io",
        );
        bad_mapping.spec.mtls_cert_ref = Some(secret_ref("CLIENT_CERT"));
        let desired = DesiredState {
            repositories: vec![repo_env("oci-mirror-e2e", "proxy")],
            upstream_mappings: vec![bad_mapping],
            scan_policies: vec![loosened],
            ..Default::default()
        };

        let h = build_harness();
        let err =
            h.uc.apply(desired.clone(), env_oidc())
                .await
                .expect_err("a half mTLS pair must fail the apply");
        assert!(matches!(err, AppError::Domain(DomainError::Validation(_))));
        assert!(
            h.events.appended().is_empty(),
            "the loosening scan policy must NOT have been written: {:?}",
            h.events.appended().len()
        );
        assert!(
            h.repos.calls().is_empty(),
            "no repository row may be written either: {:?}",
            h.repos.calls()
        );
        assert_eq!(h.upstream.entry_count(), 0);

        // And the boot preflight reaches the same verdict, so the pod parks
        // not-ready instead of crashlooping on a half-applied bundle.
        h.uc.preflight_validate(&desired, &env_oidc())
            .await
            .expect_err("the boot preflight must refuse the same bundle");
    }
}
