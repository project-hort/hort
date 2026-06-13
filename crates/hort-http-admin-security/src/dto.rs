//! Wire-shape DTOs for the security-score REST surface.
//!
//! Distinct from the domain [`hort_domain::ports::repo_security_score_repository::RepoSecurityScore`]:
//! the wire shape carries the repository's **name** (string key) rather
//! than its UUID, matching the §7 design-doc envelope. The domain row
//! is keyed by `repository_id`, so the handler resolves the id → name
//! through [`hort_app::use_cases::security_score_use_case::SecurityScoreUseCase::resolve_repo_name`]
//! before serialisation.

use chrono::{DateTime, Utc};
use serde::Serialize;

use hort_domain::ports::repo_security_score_repository::RepoSecurityScore;

/// JSON envelope for `GET /api/v1/repositories/:name/security-score`.
///
/// Mirrors the §7 example payload — the `severity_histogram` field
/// carries the four cumulative severity-tier counts (`critical`, `high`,
/// `medium`, `low`). The `negligible` count from the §7 example is not
/// tracked by the v1 projection (aligned with Trivy/OSV's four canonical
/// tiers); future scanners that emit a fifth tier will extend both the
/// projection and this DTO together.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecurityScoreDto {
    /// Repository name (key), NOT the UUID. Resolved by the handler
    /// from `repository_id` so the wire response is operator-friendly.
    pub repository: String,
    pub quarantined: u32,
    pub rejected: u32,
    pub released: u32,
    pub severity_histogram: SeverityHistogramDto,
    /// Most-recent scan time across the repository. `None` when no
    /// scan has completed for any artifact in this repository yet.
    /// Serialises as JSON `null`.
    pub last_scan_at: Option<DateTime<Utc>>,
}

/// Severity histogram envelope for [`SecurityScoreDto::severity_histogram`].
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SeverityHistogramDto {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

impl SecurityScoreDto {
    /// Build a wire-shape DTO from a domain row + the resolved
    /// repository name. Mirrors the §7 example envelope.
    pub fn from_domain(repository: String, score: &RepoSecurityScore) -> Self {
        Self {
            repository,
            quarantined: score.quarantined_count,
            rejected: score.rejected_count,
            released: score.released_count,
            severity_histogram: SeverityHistogramDto {
                critical: score.critical_count,
                high: score.high_count,
                medium: score.medium_count,
                low: score.low_count,
            },
            last_scan_at: score.last_scan_at,
        }
    }
}

/// JSON envelope for `GET /api/v1/security-score`.
///
/// `next_cursor` mirrors the use-case shape: `Some(_)` when more rows
/// follow past the slice; `null` on the final page.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecurityScoreListDto {
    pub scores: Vec<SecurityScoreDto>,
    pub next_cursor: Option<String>,
}

/// JSON envelope for `POST /api/v1/artifacts/:id/rescan`.
///
/// Mirrors the admin-task surface (`/api/v1/admin/tasks/{kind}`) shape
/// so downstream tooling that polls `/api/v1/admin/tasks/<id>` for
/// status sees the same `task_job_id` field name on both surfaces.
/// The wrapped value is the **new `jobs.id`** (NOT the artifact id) —
/// the caller correlates the manual rescan invocation with the worker's
/// lifecycle updates by polling the admin-tasks read surface using
/// this id.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RescanResponse {
    /// Newly-inserted `jobs.id` for the manual rescan request.
    pub task_job_id: uuid::Uuid,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use uuid::Uuid;

    use super::*;

    fn sample_score() -> RepoSecurityScore {
        RepoSecurityScore {
            repository_id: Uuid::nil(),
            quarantined_count: 12,
            rejected_count: 3,
            released_count: 4521,
            critical_count: 1,
            high_count: 8,
            medium_count: 47,
            low_count: 123,
            last_scan_at: Some(Utc.with_ymd_and_hms(2026, 5, 8, 14, 23, 11).unwrap()),
            updated_at: Utc.with_ymd_and_hms(2026, 5, 8, 14, 23, 11).unwrap(),
        }
    }

    #[test]
    fn from_domain_carries_repository_and_counts() {
        let dto = SecurityScoreDto::from_domain("internal-pypi".into(), &sample_score());
        assert_eq!(dto.repository, "internal-pypi");
        assert_eq!(dto.quarantined, 12);
        assert_eq!(dto.rejected, 3);
        assert_eq!(dto.released, 4521);
        assert_eq!(dto.severity_histogram.critical, 1);
        assert_eq!(dto.severity_histogram.high, 8);
        assert_eq!(dto.severity_histogram.medium, 47);
        assert_eq!(dto.severity_histogram.low, 123);
        assert!(dto.last_scan_at.is_some());
    }

    #[test]
    fn serialised_envelope_matches_design_doc_shape() {
        // Sanity-check the §7 wire shape. Field names matter — these
        // are part of the public API contract.
        let dto = SecurityScoreDto::from_domain("internal-pypi".into(), &sample_score());
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(v["repository"], "internal-pypi");
        assert_eq!(v["quarantined"], 12);
        assert_eq!(v["rejected"], 3);
        assert_eq!(v["released"], 4521);
        assert!(v["severity_histogram"].is_object());
        assert_eq!(v["severity_histogram"]["critical"], 1);
        assert!(v["last_scan_at"].is_string());
    }

    #[test]
    fn last_scan_at_none_serialises_as_null() {
        let mut score = sample_score();
        score.last_scan_at = None;
        let dto = SecurityScoreDto::from_domain("fresh-repo".into(), &score);
        let v = serde_json::to_value(&dto).unwrap();
        assert!(v["last_scan_at"].is_null());
    }

    #[test]
    fn list_dto_round_trips() {
        let dto = SecurityScoreListDto {
            scores: vec![SecurityScoreDto::from_domain(
                "alpha".into(),
                &sample_score(),
            )],
            next_cursor: Some("abc".into()),
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert!(v["scores"].is_array());
        assert_eq!(v["next_cursor"], "abc");
    }

    #[test]
    fn list_dto_with_no_cursor_serialises_null() {
        let dto = SecurityScoreListDto {
            scores: vec![],
            next_cursor: None,
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert!(v["next_cursor"].is_null());
    }
}
