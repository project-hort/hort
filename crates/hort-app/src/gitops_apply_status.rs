//! What **this running process** applied from gitops at boot.
//!
//! Pure value types (zero-I/O, sibling of [`crate::storage_backend`]).
//! The boot path fills one of these from the apply outcome and the
//! composition root parks it on the `AppContext` for the admin
//! inspection endpoint to read.
//!
//! ## Why the shape is "this process", not "the cluster"
//!
//! Gitops apply is a boot step: it runs once, before the listener binds,
//! and there is no live-refresh path (restart-to-apply is the contract).
//! So the honest question an operator can ask a *running server* is "what
//! did **you** apply when you started?", and the honest answer is
//! in-memory, scoped to this process. Persisting it would answer a
//! different and less useful question — "what did the last process to
//! write this row apply?" — which during a rolling upgrade is routinely
//! some *other* pod's boot, mid-rollout, with no way for the reader to
//! tell. A pod reporting its own apply is a fact; a shared row is a race.
//!
//! Absent apply ⇒ no status. A DSN-only boot (no `HORT_CONFIG_DIR`)
//! records nothing, and the endpoint says so explicitly rather than
//! reporting a zeroed apply that never happened.

use chrono::{DateTime, Utc};

use crate::use_cases::apply_config_use_case::ApplyReport;

/// Create/update/delete/unchanged object counts for one gitops kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KindCounts {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    pub unchanged: usize,
}

impl KindCounts {
    /// Project one kind's plan into its counts.
    ///
    /// The plan is the same source the aggregate counters increment
    /// from — every CRUD kind's apply walks `plan.create` / `plan.update`
    /// / `plan.delete` and bumps the rolled-up counter once per entry —
    /// so this is a projection of numbers that already exist, never a
    /// second computation that could disagree with them. Apply is
    /// strict-atomic (the first port failure aborts the whole apply), so
    /// on a successful apply the planned counts are the applied counts.
    fn from_plan<Spec: Clone, K: Clone>(plan: &hort_config::diff::KindPlan<Spec, K>) -> Self {
        Self {
            created: plan.create.len(),
            updated: plan.update.len(),
            deleted: plan.delete.len(),
            unchanged: plan.unchanged,
        }
    }
}

/// Per-kind object deltas for one apply.
///
/// Covers the five CRUD kinds an operator inspects for config drift.
/// The aggregate counters on [`ApplyReport`] additionally span the
/// event-sourced kinds (scan policies, retention policies, exclusions)
/// and the machine-identity kinds (OIDC issuers, service accounts), so
/// **the per-kind counts here do not sum to the aggregate** — the
/// breakdown is a per-kind detail view, not a partition of the total.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyKindCounts {
    pub repositories: KindCounts,
    pub upstream_mappings: KindCounts,
    pub claim_mappings: KindCounts,
    pub permission_grants: KindCounts,
    pub curation_rules: KindCounts,
}

impl ApplyKindCounts {
    /// Project the apply plan's per-kind counts. Called once, inside
    /// the apply, so the numbers ride out on the report instead of
    /// being discarded with the plan.
    #[must_use]
    pub fn from_plan(plan: &hort_config::diff::ApplyPlan) -> Self {
        Self {
            repositories: KindCounts::from_plan(&plan.repositories),
            upstream_mappings: KindCounts::from_plan(&plan.upstream_mappings),
            claim_mappings: KindCounts::from_plan(&plan.claim_mappings),
            permission_grants: KindCounts::from_plan(&plan.permission_grants),
            curation_rules: KindCounts::from_plan(&plan.curation_rules),
        }
    }
}

/// The gitops apply this process performed at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitopsApplyStatus {
    /// When this process finished its boot apply.
    pub applied_at: DateTime<Utc>,
    /// Hex SHA-256 fingerprint of the applied desired state
    /// ([`hort_config::diff::desired_state_digest`]).
    ///
    /// The same generation across two boots means the two boots applied
    /// the same configuration; a different generation means the config
    /// changed. It is a fingerprint of *what was applied*, not a
    /// monotonic counter — nothing orders two generations.
    pub generation: String,
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    pub unchanged: usize,
    /// Retroactive-curation `RetroWarn` outcomes (one `CurationApplied`
    /// event each, no artifact-state change).
    pub retro_warn_count: usize,
    /// Retroactive-curation `RetroBlock` outcomes (one `CurationApplied`
    /// **and** one `ArtifactRejected` event each, atomic per artifact).
    pub retro_block_count: usize,
    /// Per-kind breakdown — see [`ApplyKindCounts`] for why it does not
    /// sum to the aggregate above.
    pub per_kind: ApplyKindCounts,
}

impl GitopsApplyStatus {
    /// Build the status from a successful apply.
    ///
    /// `generation` is the raw digest of the desired state that was
    /// applied; it is hex-encoded here so the one rendering lives in one
    /// place.
    #[must_use]
    pub fn from_report(
        report: ApplyReport,
        generation: [u8; 32],
        applied_at: DateTime<Utc>,
    ) -> Self {
        Self {
            applied_at,
            generation: hex_lower(&generation),
            created: report.created,
            updated: report.updated,
            deleted: report.deleted,
            unchanged: report.unchanged,
            retro_warn_count: report.retro_warn_count,
            retro_block_count: report.retro_block_count,
            per_kind: report.per_kind,
        }
    }
}

/// Lowercase hex of a 32-byte digest. Hand-rolled rather than pulling a
/// hex crate into this layer for one call site.
fn hex_lower(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing into a `String` is infallible.
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_config::diff::{ApplyPlan, KindPlan};
    use hort_config::envelope::{ApiVersion, Envelope, Kind, Metadata};
    use hort_config::repository::RepositorySpec;

    fn repo_env(name: &str) -> Envelope<RepositorySpec> {
        Envelope {
            api_version: ApiVersion::V1,
            kind: Kind::ArtifactRepository,
            metadata: Metadata { name: name.into() },
            spec: RepositorySpec {
                name: name.into(),
                description: None,
                format: "npm".into(),
                repo_type: "hosted".into(),
                storage: None,
                proxy: None,
                virtual_members: None,
                is_public: true,
                download_audit_enabled: false,
                index_mode: Default::default(),
                prefetch_policy: Default::default(),
                quota_bytes: None,
                replication_priority: "immediate".into(),
                promotion: None,
                curation_rules: None,
            },
        }
    }

    #[test]
    fn hex_renders_lowercase_and_full_width() {
        let mut d = [0u8; 32];
        d[0] = 0x0a;
        d[31] = 0xff;
        let s = hex_lower(&d);
        assert_eq!(s.len(), 64);
        assert!(s.starts_with("0a"));
        assert!(s.ends_with("ff"));
        assert_eq!(s, s.to_lowercase());
    }

    #[test]
    fn kind_counts_project_the_plan() {
        let plan = ApplyPlan {
            repositories: KindPlan {
                create: vec![repo_env("a"), repo_env("b")],
                update: vec![repo_env("c")],
                delete: vec![uuid::Uuid::new_v4()],
                unchanged: 7,
            },
            ..ApplyPlan::default()
        };
        let counts = ApplyKindCounts::from_plan(&plan);
        assert_eq!(
            counts.repositories,
            KindCounts {
                created: 2,
                updated: 1,
                deleted: 1,
                unchanged: 7,
            }
        );
        // Untouched kinds project to zeros, not to the repository counts.
        assert_eq!(counts.claim_mappings, KindCounts::default());
        assert_eq!(counts.upstream_mappings, KindCounts::default());
        assert_eq!(counts.permission_grants, KindCounts::default());
        assert_eq!(counts.curation_rules, KindCounts::default());
    }

    #[test]
    fn empty_plan_projects_to_all_zeros() {
        assert_eq!(
            ApplyKindCounts::from_plan(&ApplyPlan::default()),
            ApplyKindCounts::default()
        );
    }

    #[test]
    fn status_carries_every_report_field() {
        let report = ApplyReport {
            created: 1,
            updated: 2,
            deleted: 3,
            unchanged: 4,
            retro_warn_count: 5,
            retro_block_count: 6,
            per_kind: ApplyKindCounts {
                repositories: KindCounts {
                    created: 1,
                    ..KindCounts::default()
                },
                ..ApplyKindCounts::default()
            },
        };
        let at = Utc::now();
        let status = GitopsApplyStatus::from_report(report, [0xab; 32], at);

        assert_eq!(status.applied_at, at);
        assert_eq!(status.generation, "ab".repeat(32));
        assert_eq!(status.created, 1);
        assert_eq!(status.updated, 2);
        assert_eq!(status.deleted, 3);
        assert_eq!(status.unchanged, 4);
        assert_eq!(status.retro_warn_count, 5);
        assert_eq!(status.retro_block_count, 6);
        assert_eq!(status.per_kind.repositories.created, 1);
    }

    #[test]
    fn a_no_op_apply_is_a_recorded_status_not_an_absent_one() {
        // Every counter zero is still an apply that happened — the
        // "no apply recorded" case is `Option::None`, never a zeroed
        // status. The generation is what distinguishes them at a glance.
        let status = GitopsApplyStatus::from_report(ApplyReport::default(), [0u8; 32], Utc::now());
        assert_eq!(status.created, 0);
        assert_eq!(status.per_kind, ApplyKindCounts::default());
        assert_eq!(status.generation.len(), 64);
    }
}
