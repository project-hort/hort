//! `PatchCandidateRepository` port.
//!
//! Outbound port behind the patch-candidate quarantine surface (read-side).
//!
//! The surface answers: for every artifact currently in
//! `quarantine_status = 'quarantined'`, is there an earlier *released*
//! version of the same package (same `repository_id`, `name`) that the
//! operator could promote in its place? When such a fallback exists the
//! quarantined row is a *patch candidate* — the human reviewer can choose
//! between releasing it (if the scan is acceptable) or rejecting it and
//! letting consumers stay on the released predecessor.
//!
//! See `docs/architecture/how-to/quarantine-patch-release.md`
//! for the operator-facing workflow this serves.
//!
//! # Authority
//!
//! The use case in `hort-app` gates this port behind
//! `CallerPrivileges::require_admin` — same authz as the existing
//! `POST /admin/quarantine/:artifact_id/release` endpoint.
//!
//! # Domain DTO discipline
//!
//! [`PatchCandidate`] and [`PatchCandidateFilter`] do **NOT** derive
//! `Serialize` or `Deserialize`. The HTTP DTO is a
//! separate type in the inbound-HTTP layer; mixing serde onto the domain
//! struct would let request input or outbound HTTP rounds drag wire
//! semantics into the domain layer.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::entities::artifact::QuarantineStatus;
use crate::entities::repository::RepositoryFormat;
use crate::entities::scan_policy::SeverityThreshold;
use crate::error::DomainResult;

use super::BoxFuture;

/// A quarantined artifact that has an earlier released version available
/// in the same repository — a candidate for the "patch-fix" workflow.
///
/// All identifiers are bare [`Uuid`]s (the codebase does not use typed
/// `ArtifactId` / `RepositoryId` newtypes).
///
/// `repository_key` is resolved by the adapter so the
/// HTTP DTO can render a human-readable key without a second round
/// trip. The use case treats it as an opaque pass-through string.
///
/// `vulnerable_max_severity` is `Option<SeverityThreshold>` — the
/// adapter's `severity_from_rank(i16) -> Option<SeverityThreshold>`
/// helper folds the SQL `MAX(CASE ...)` rank (0–4) onto the four-variant
/// enum. `None` means "no scan findings" (should never appear when the
/// LATERAL `finding_count > 0` filter has matched, but the type-level
/// possibility is preserved for adapter-level resilience).
#[derive(Debug, Clone, PartialEq)]
pub struct PatchCandidate {
    /// `artifacts.id` of the row currently in quarantine.
    pub quarantined_artifact_id: Uuid,
    /// `artifacts.version` of the quarantined row (nullable per schema).
    pub quarantined_version: Option<String>,
    /// Always [`QuarantineStatus::Quarantined`] when surfaced by this
    /// port (the SQL filters on `q.quarantine_status = 'quarantined'`),
    /// carried for symmetry with the artifact entity and so the HTTP
    /// DTO can render the value without an enum-introduction.
    pub quarantined_status: QuarantineStatus,
    /// `artifacts.quarantine_window_start` of the quarantined row — the
    /// observation-window anchor (ADR 0007).
    pub quarantined_until: Option<DateTime<Utc>>,
    /// `artifacts.repository_id` shared by both the quarantined and
    /// the vulnerable (= released predecessor) rows.
    pub repository_id: Uuid,
    /// `repositories.key` resolved by the adapter.
    /// The use case never inspects this; it is carried through to the
    /// HTTP DTO so the response is human-readable.
    pub repository_key: String,
    /// `repositories.format` of the shared repository.
    pub format: RepositoryFormat,
    /// `artifacts.name` shared by both rows.
    pub package_name: String,
    /// `artifacts.id` of the earlier *released* row.
    pub vulnerable_artifact_id: Uuid,
    /// `artifacts.version` of the earlier released row.
    pub vulnerable_version: Option<String>,
    /// `COUNT(*)` over `scan_findings` for the released row. The
    /// LATERAL filter `finding_count > 0` guarantees this is >= 1
    /// when the row surfaces.
    pub vulnerable_finding_count: u32,
    /// Highest severity in the released row's `scan_findings`. `None`
    /// is the type-level possibility for "no findings"; in practice
    /// the LATERAL filter prevents that.
    pub vulnerable_max_severity: Option<SeverityThreshold>,
}

/// Query filter for [`PatchCandidateRepository::list_candidates`].
///
/// [`Self::limit`] defaults to 100; the use case caps at 500 and
/// surfaces over-cap requests as
/// `AppError::Domain(DomainError::Validation(..))`.
#[derive(Debug, Clone, PartialEq)]
pub struct PatchCandidateFilter {
    /// Optional repository scope. `None` returns candidates across
    /// every visible repository (admin-only — see use case authz).
    pub repository_id: Option<Uuid>,
    /// Maximum rows to return. Use-case validates `<= 500`.
    pub limit: u32,
    /// Resolved repository key threaded through for the
    /// `hort_patch_candidates_listed_total{repository}` metric label
    /// `None` → use case emits the `_all` sentinel;
    /// `Some(key)` → emits the key verbatim. The use case never reads
    /// this for query logic — it is metric-only metadata supplied by
    /// the handler after `RepositoryRepository::find_by_key` resolved
    /// the `?repository=<key>` query parameter.
    ///
    /// `"unknown"` is **not** reachable from the HTTP handler today:
    /// `find_by_key` returning `NotFound` surfaces as 404 to the caller
    /// before the use case is invoked. The sentinel is reserved for
    /// non-HTTP / dispatcher paths that may exist in future.
    pub repository_key_for_metric: Option<String>,
}

impl Default for PatchCandidateFilter {
    fn default() -> Self {
        Self {
            repository_id: None,
            limit: 100,
            repository_key_for_metric: None,
        }
    }
}

/// Outbound port for the patch-candidate surface.
///
/// One method: [`Self::list_candidates`]. The Postgres adapter
/// (`hort-adapters-postgres::patch_candidate_repository`) executes the
/// candidacy query; the in-test mock in
/// `patch_candidate_use_case::tests` is a Mutex-backed recorder.
pub trait PatchCandidateRepository: Send + Sync {
    /// List quarantined artifacts that have an earlier released
    /// predecessor in the same repository. Bounded by
    /// `filter.limit`; the use case is responsible for capping the
    /// value before it reaches the adapter.
    fn list_candidates<'a>(
        &'a self,
        filter: PatchCandidateFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<PatchCandidate>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that the port is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn PatchCandidateRepository>();
    }

    #[test]
    fn filter_default_returns_limit_100_and_no_repository() {
        let f = PatchCandidateFilter::default();
        assert_eq!(f.limit, 100);
        assert!(f.repository_id.is_none());
    }

    /// Trivial construction test — pins the field set so future
    /// additions break loudly (`PatchCandidate { ... }` is a
    /// structural type; adding a field forces every constructor to
    /// be updated, this one included).
    #[test]
    fn patch_candidate_construction_compiles_with_full_field_set() {
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let c = PatchCandidate {
            quarantined_artifact_id: Uuid::nil(),
            quarantined_version: Some("4.17.21".into()),
            quarantined_status: QuarantineStatus::Quarantined,
            quarantined_until: Some(now),
            repository_id: Uuid::nil(),
            repository_key: "npm-main".into(),
            format: RepositoryFormat::Npm,
            package_name: "lodash".into(),
            vulnerable_artifact_id: Uuid::nil(),
            vulnerable_version: Some("4.17.20".into()),
            vulnerable_finding_count: 3,
            vulnerable_max_severity: Some(SeverityThreshold::High),
        };
        // Exercise Clone + PartialEq + Debug.
        assert_eq!(c.clone(), c);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("PatchCandidate"));
        assert!(dbg.contains("lodash"));
    }

    #[test]
    fn filter_clone_and_eq_round_trip() {
        let f = PatchCandidateFilter {
            repository_id: Some(Uuid::nil()),
            limit: 250,
            repository_key_for_metric: Some("npm-main".into()),
        };
        assert_eq!(f.clone(), f);
        let dbg = format!("{f:?}");
        assert!(dbg.contains("PatchCandidateFilter"));
        assert!(dbg.contains("250"));
        assert!(dbg.contains("npm-main"));
    }

    /// Default filter has the metric-label hint cleared — the use
    /// case will emit the `_all` sentinel for the admin-wide scope.
    /// Pins the contract so a regression that introduces a stale
    /// default (e.g. `Some("".to_string())`) trips here rather than
    /// silently emitting an empty-string Prometheus label.
    #[test]
    fn filter_default_has_no_repository_key_for_metric() {
        let f = PatchCandidateFilter::default();
        assert!(f.repository_key_for_metric.is_none());
    }
}
