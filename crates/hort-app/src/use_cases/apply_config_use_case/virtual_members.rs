use super::*;

impl ApplyConfigUseCase {
    /// Pass 3 — for every desired `type: virtual` repo, reconcile
    /// the membership edge set against current state. Idempotent:
    /// when the declared and current edge sets match, no port
    /// mutation happens.
    ///
    /// Doesn't take the pre-apply `CurrentSnapshot` because it would
    /// be stale for any virtual repo stage 2 just created. Current
    /// edges are read fresh per virtual repo via `get_virtual_members`.
    pub(super) async fn apply_virtual_members(&self, desired: &DesiredState) -> AppResult<()> {
        for env in &desired.repositories {
            let Some(declared_members) = env.spec.virtual_members.as_ref() else {
                continue;
            };
            let virtual_repo = match self.repositories.find_by_key(&env.metadata.name).await {
                Ok(r) => r,
                Err(e) => return Err(e.into()),
            };

            // Resolve declared member keys to ids, **preserving the
            // `virtualMembers` list order** — that order is the resolution
            // priority (ADR 0031 rule 3). `replace_virtual_members` assigns
            // `priority` = list index, so the declared order is the priority.
            let mut declared_ordered: Vec<Uuid> = Vec::with_capacity(declared_members.len());
            for member_key in declared_members {
                let m = self.repositories.find_by_key(member_key).await?;
                declared_ordered.push(m.id);
            }

            // `get_virtual_members` returns members already ordered by
            // priority, so this is the current ordered edge list.
            let current_ordered: Vec<Uuid> = self
                .repositories
                .get_virtual_members(virtual_repo.id)
                .await?
                .into_iter()
                .map(|r| r.id)
                .collect();

            // Idempotent: when the declared list matches the current
            // priority-ordered edges exactly (same members, same order), make
            // no port mutation. Otherwise reconcile via the **atomic**
            // `replace_virtual_members` so persisted `priority` always tracks
            // the `virtualMembers` index AND a concurrent reader (another
            // replica on the shared DB during a rolling deploy) never observes
            // a partial member set. A pure reorder (no set change) still
            // re-pins priority. The prior remove-loop-then-add-loop was
            // non-transactional: its mid-reconcile window could transiently
            // drop the owner edge, making an owned name look unowned and
            // momentarily un-suppressing proxies (ADR 0031 rule 2b / S-2).
            if declared_ordered == current_ordered {
                continue;
            }
            self.repositories
                .replace_virtual_members(virtual_repo.id, &declared_ordered)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn collect_repo_id_by_name(
        &self,
        desired: &DesiredState,
    ) -> AppResult<HashMap<String, Uuid>> {
        let mut out = HashMap::with_capacity(desired.repositories.len());
        for env in &desired.repositories {
            // Each declared repo just had `save_managed` run in stage 2
            // → it exists. `find_by_key` resolves the id.
            let repo = self.repositories.find_by_key(&env.metadata.name).await?;
            out.insert(env.metadata.name.clone(), repo.id);
        }
        Ok(out)
    }

    /// Re-use existing UUID if a managed row already exists for this
    /// key (UPDATE path); mint a new one otherwise (CREATE path).
    /// `save_managed` does an INSERT-or-UPDATE on the supplied id.
    pub(super) async fn resolve_repo_id(&self, key: &str) -> AppResult<Uuid> {
        match self.repositories.find_by_key(key).await {
            Ok(r) => Ok(r.id),
            Err(DomainError::NotFound { .. }) => Ok(Uuid::new_v4()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::apply_config_use_case::tests::*;
    use crate::use_cases::test_support::MockCall;

    fn virtual_env(name: &str, members: &[&str]) -> Envelope<RepositorySpec> {
        let mut env = repo_env(name, "virtual");
        env.spec.virtual_members = Some(members.iter().map(|s| (*s).into()).collect());
        env
    }

    #[tokio::test]
    async fn apply_rejects_virtual_repo_until_serve_supported() {
        // ADR 0015 inert-field stopgap (spec §9 part A): applying a
        // `type: virtual` repo fails pre-write validation when the format is
        // absent from `VIRTUAL_SERVE_SUPPORTED_FORMATS`. npm/pypi/cargo/maven/
        // gradle are lifted; `oci` is a known, still-unsupported format — the
        // correct steady state — so this exercises the stopgap through the real
        // apply path (`run_pre_write_validation` → `validate_against` → `validate`).
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("a", "hosted"));
        let mut vroot = virtual_env("vroot", &["a"]);
        vroot.spec.format = "oci".into();
        desired.repositories.push(vroot);
        let err = h.uc.apply(desired, env_oidc()).await.unwrap_err();
        assert!(
            err.to_string().contains("not yet serve-supported"),
            "expected serve-support rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn apply_npm_virtual_passes_validation_and_reconciles_members() {
        // npm/pypi/cargo/maven/gradle are lifted into
        // `VIRTUAL_SERVE_SUPPORTED_FORMATS`, so a `type: virtual` npm repo
        // passes apply validation and the member reconcile runs end-to-end
        // through `apply()` (no longer orphaned by the stopgap). A
        // still-unsupported format (e.g. oci) trips the stopgap — see
        // `apply_rejects_virtual_repo_until_serve_supported`.
        let h = build_harness();
        let mut desired = DesiredState::default();
        desired.repositories.push(repo_env("a", "hosted"));
        desired.repositories.push(virtual_env("vroot", &["a"]));
        h.uc.apply(desired, env_oidc()).await.unwrap();

        let vroot = h.repos.find_by_key("vroot").await.unwrap();
        let members: Vec<String> = h
            .repos
            .get_virtual_members(vroot.id)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.key)
            .collect();
        assert_eq!(
            members,
            vec!["a".to_string()],
            "npm virtual member edge reconciled via apply()"
        );
    }

    // The three tests below drive `apply_virtual_members` **directly** — they
    // keep the order-aware reconcile and its edge cases (idempotent re-apply,
    // atomic replace on a list edit) covered without a full `apply()`
    // round-trip. The end-to-end npm path is covered by
    // `apply_npm_virtual_passes_validation_and_reconciles_members` above; the
    // pypi/cargo formats are still stopgapped at validation, so the direct
    // drive is the only way to exercise the reconcile for them until they lift.

    /// Collect the ordered id lists of every `ReplaceMembers` call for `vroot`.
    fn replace_calls_for(h: &Harness, vroot_id: Uuid) -> Vec<Vec<Uuid>> {
        h.repos
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                MockCall::ReplaceMembers(v, ids) if v == vroot_id => Some(ids),
                _ => None,
            })
            .collect()
    }

    /// Assert no per-edge (non-atomic) member mutation ever happened.
    fn assert_no_per_edge_mutations(h: &Harness) {
        assert!(
            h.repos
                .calls()
                .iter()
                .all(|c| !matches!(c, MockCall::AddMember(..) | MockCall::RemoveMember(..))),
            "member reconcile must be atomic (ADR 0031 / S-2) — never per-edge add/remove"
        );
    }

    #[tokio::test]
    async fn apply_virtual_members_replaces_edges_in_declared_order() {
        // Reconcile from an empty edge set: members are written in
        // `virtualMembers` order via one ATOMIC replace, so persisted priority
        // == list index.
        let h = build_harness();
        for key in ["vroot", "a", "b"] {
            h.repos.insert(sample_repository_for_test(key));
        }
        let mut desired = DesiredState::default();
        desired.repositories.push(virtual_env("vroot", &["a", "b"]));

        h.uc.apply_virtual_members(&desired).await.unwrap();

        let vroot = h.repos.find_by_key("vroot").await.unwrap();
        let a = h.repos.find_by_key("a").await.unwrap();
        let b = h.repos.find_by_key("b").await.unwrap();
        let members: Vec<String> = h
            .repos
            .get_virtual_members(vroot.id)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.key)
            .collect();
        assert_eq!(members, vec!["a".to_string(), "b".to_string()]);
        assert_no_per_edge_mutations(&h);
        assert_eq!(
            replace_calls_for(&h, vroot.id),
            vec![vec![a.id, b.id]],
            "one atomic replace in declared order"
        );
    }

    #[tokio::test]
    async fn apply_virtual_members_idempotent_when_order_matches() {
        // Declared list already matches the current priority-ordered edges:
        // no port mutation (no churn).
        let h = build_harness();
        for key in ["vroot", "a", "b"] {
            h.repos.insert(sample_repository_for_test(key));
        }
        let vroot = h.repos.find_by_key("vroot").await.unwrap();
        let a = h.repos.find_by_key("a").await.unwrap();
        let b = h.repos.find_by_key("b").await.unwrap();
        h.repos.seed_virtual_member(vroot.id, a.id);
        h.repos.seed_virtual_member(vroot.id, b.id);

        let mut desired = DesiredState::default();
        desired.repositories.push(virtual_env("vroot", &["a", "b"]));
        h.uc.apply_virtual_members(&desired).await.unwrap();

        let mutations = h
            .repos
            .calls()
            .into_iter()
            .filter(|c| {
                matches!(
                    c,
                    MockCall::AddMember(..)
                        | MockCall::RemoveMember(..)
                        | MockCall::ReplaceMembers(..)
                )
            })
            .count();
        assert_eq!(mutations, 0, "matching declared order must not churn edges");
    }

    #[tokio::test]
    async fn apply_virtual_members_reorders_atomically() {
        // A pure reorder (same set, different order) re-pins priority via one
        // ATOMIC replace — a concurrent reader never sees a partial set with
        // the owner edge transiently removed (ADR 0031 rule 2b / S-2).
        let h = build_harness();
        for key in ["vroot", "a", "b", "c"] {
            h.repos.insert(sample_repository_for_test(key));
        }
        let vroot = h.repos.find_by_key("vroot").await.unwrap();
        let a = h.repos.find_by_key("a").await.unwrap();
        let b = h.repos.find_by_key("b").await.unwrap();
        let c = h.repos.find_by_key("c").await.unwrap();
        h.repos.seed_virtual_member(vroot.id, a.id);
        h.repos.seed_virtual_member(vroot.id, b.id);
        h.repos.seed_virtual_member(vroot.id, c.id);

        let mut desired = DesiredState::default();
        desired
            .repositories
            .push(virtual_env("vroot", &["c", "a", "b"]));
        h.uc.apply_virtual_members(&desired).await.unwrap();

        let members: Vec<String> = h
            .repos
            .get_virtual_members(vroot.id)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.key)
            .collect();
        assert_eq!(
            members,
            vec!["c".to_string(), "a".to_string(), "b".to_string()]
        );
        assert_no_per_edge_mutations(&h);
        assert_eq!(
            replace_calls_for(&h, vroot.id),
            vec![vec![c.id, a.id, b.id]],
            "one atomic replace re-pinning the declared order"
        );
    }
}
