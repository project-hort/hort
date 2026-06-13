//! Outbound port for the `curation_rules` table and its junction with
//! `repositories`.
//!
//! Read paths:
//! - `find_by_name` / `find_by_id` — operator-facing diagnostic lookups.
//! - `list_for_repo` — the curation evaluator calls this at
//!   ingest time to materialise the rule set linked to the repository
//!   that's receiving the artifact.
//! - `list_managed_by_gitops` — the gitops apply pipeline's diff query: every
//!   gitops-managed rule plus its digest, bounded by the partial index
//!   `idx_curation_rules_managed_by` (`006_curation.sql`).
//!
//! Write paths are exclusively for the gitops apply pipeline. The public
//! CRUD surface for `CurationRule` is YAML — same gitops-managed model as
//! `GroupMapping` and `Repository`
//! (see `docs/architecture/how-to/declare-gitops-config.md`).
//!
//! `set_curation_rules_for_repository` is an idempotent set-replace on the
//! `repository_curation_rules` junction: delete every existing edge for
//! the repo, then insert the new set, in one transaction. Re-applying the
//! same spec produces no row churn beyond the wholesale delete + insert.

use uuid::Uuid;

use crate::entities::curation_rule::CurationRule;
use crate::error::DomainResult;

use super::BoxFuture;

/// Outbound port for the `curation_rules` table.
pub trait CurationRuleRepository: Send + Sync {
    /// Lookup by `metadata.name`. `None` when no rule with that name exists.
    fn find_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<Option<CurationRule>>>;

    /// Lookup by primary key. `None` when the row is absent.
    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Option<CurationRule>>>;

    /// Every rule attached to a given repository via the
    /// `repository_curation_rules` junction. The curation evaluator
    /// hits this on the ingest hot path; the join order is junction →
    /// `curation_rules` (rule rows are far less numerous than artifacts).
    fn list_for_repo(&self, repository_id: Uuid) -> BoxFuture<'_, DomainResult<Vec<CurationRule>>>;

    /// Every gitops-managed rule. Bounded by the partial index
    /// `idx_curation_rules_managed_by` (`006_curation.sql`) — this is the
    /// diff query the gitops apply pipeline runs on every boot.
    fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<CurationRule>>>;

    /// INSERT-or-UPDATE a `managed_by = 'gitops'` row. Sets the digest in
    /// the same statement so a partial write can't leave `managed_by =
    /// 'gitops'` with `managed_by_digest = NULL` (a CHECK constraint
    /// also enforces this on the DB side). The gitops apply pipeline is
    /// the only caller.
    fn save_managed(&self, rule: &CurationRule) -> BoxFuture<'_, DomainResult<()>>;

    /// DELETE a `managed_by = 'gitops'` row by name. Refuses non-gitops
    /// rows defensively (the diff layer never schedules a delete on a
    /// `managed_by = 'local'` row, but the port enforces the invariant
    /// in case of out-of-band SQL).
    fn delete_managed(&self, name: &str) -> BoxFuture<'_, DomainResult<()>>;

    /// Replace the rule set linked to `repository_id` with `rule_ids`.
    ///
    /// Idempotent: every call yields the same final junction state for
    /// the supplied inputs. The delete-then-insert is one transaction;
    /// a partial failure leaves the previous set intact.
    fn set_curation_rules_for_repository(
        &self,
        repository_id: Uuid,
        rule_ids: &[Uuid],
    ) -> BoxFuture<'_, DomainResult<()>>;

    /// Reverse-index lookup: every repository linked to a rule via the
    /// `repository_curation_rules` junction. Used by the retroactive
    /// curation pass in `ApplyConfigUseCase`
    /// — when a rule is newly-declared or tightened, the apply
    /// pipeline lists the linked repositories then enumerates each
    /// repo's active artifacts to re-evaluate.
    ///
    /// SQL semantics: `SELECT repository_id FROM
    /// repository_curation_rules WHERE curation_rule_id = $1`. Empty
    /// when the rule is unattached.
    fn list_repos_for_rule(&self, rule_id: Uuid) -> BoxFuture<'_, DomainResult<Vec<Uuid>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `CurationRuleRepository` is dyn-compatible.
    /// A non-object-safe signature would break the composition root, which
    /// holds this trait behind an `Arc<dyn CurationRuleRepository>`.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn CurationRuleRepository>();
    }
}
