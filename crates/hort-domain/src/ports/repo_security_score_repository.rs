//! Outbound port for the per-repository `repo_security_scores`
//! projection.
//!
//! The `repo_security_scores` table is a denormalised projection
//! maintained by `RepoSecurityScoreProjector` (in `hort-app`) on every
//! `ScanCompleted`, `ArtifactReleased`, `ArtifactRejected` and
//! `ArtifactQuarantined` event. The row carries:
//!
//! - `quarantined_count` / `rejected_count` / `released_count` — the
//!   per-status artifact counts in the repository.
//! - `critical_count` / `high_count` / `medium_count` / `low_count` —
//!   the cumulative finding-tier counts across every `ScanCompleted`
//!   event.
//! - `last_scan_at` — the most recent `ScanCompleted` event in the
//!   repository (per-repo aggregate, NOT per-artifact — see §3.6a for
//!   the per-artifact denorm column).
//!
//! Atomicity contract: the row is updated **inside the same Postgres
//! transaction** as the originating event append. This is enforced by
//! threading a [`ScoreDelta`] through
//! [`crate::ports::artifact_lifecycle::ArtifactLifecyclePort`]'s
//! `commit_transition_with_score` / `commit_scan_result_with_score`
//! methods. Direct calls to [`RepoSecurityScoreRepository::upsert`]
//! exist for code paths that don't go through the lifecycle port (e.g.
//! out-of-band reconciliation), but the lifecycle path is the v1
//! production caller.
//!
//! Underflow guard: counts never go negative. The Postgres adapter
//! clamps with `GREATEST(0, current + delta)`. Subtracting more than
//! the current value stays at zero rather than wrapping or erroring.
//! See §3.6 invariant in the design doc.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainResult;

use super::BoxFuture;

/// The materialised `repo_security_scores` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSecurityScore {
    pub repository_id: Uuid,
    pub quarantined_count: u32,
    pub rejected_count: u32,
    pub released_count: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// Signed delta applied to a `repo_security_scores` row.
///
/// Counts are signed (`i32`) so transitions can decrement
/// (e.g. quarantined → released bumps `released_delta = +1` and
/// `quarantined_delta = -1`). Severity counts are cumulative — they
/// only increase as scans complete; a scan-result transition supplies
/// non-negative deltas for the four tiers. The Postgres adapter
/// clamps the post-add result at zero so a buggy delta producer can
/// never store a negative count.
///
/// `last_scan_at` is `Some` when the transition is a scan result;
/// `None` for pure status transitions (admin release, quarantine, etc.)
/// which do not advance the per-repo "most recent scan" timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScoreDelta {
    pub quarantined_delta: i32,
    pub rejected_delta: i32,
    pub released_delta: i32,
    pub critical_delta: i32,
    pub high_delta: i32,
    pub medium_delta: i32,
    pub low_delta: i32,
    pub last_scan_at: Option<DateTime<Utc>>,
}

impl ScoreDelta {
    /// `true` when every numeric delta is zero AND `last_scan_at` is
    /// `None`. The lifecycle adapter uses this to skip the SQL upsert
    /// entirely on no-op deltas (defensive — the projector should
    /// already short-circuit, but the adapter checks too).
    pub fn is_noop(&self) -> bool {
        self.quarantined_delta == 0
            && self.rejected_delta == 0
            && self.released_delta == 0
            && self.critical_delta == 0
            && self.high_delta == 0
            && self.medium_delta == 0
            && self.low_delta == 0
            && self.last_scan_at.is_none()
    }
}

/// Outbound port for the `repo_security_scores` projection.
///
/// The port exposes a row-level upsert and a single-row find. The
/// in-tx path (used by the lifecycle adapter) does NOT go through this
/// trait — it uses an internal helper that operates on the open
/// transaction. This trait covers standalone (single-tx) calls.
pub trait RepoSecurityScoreRepository: Send + Sync {
    /// Upsert the supplied row. The full row replaces whatever was
    /// stored under `repository_id`. Used by direct callers (e.g.
    /// reconciliation tasks); the lifecycle dual-write path uses an
    /// adapter-internal helper that applies a delta inside its own
    /// transaction.
    fn upsert<'a>(&'a self, score: &'a RepoSecurityScore) -> BoxFuture<'a, DomainResult<()>>;

    /// Look up a single row by repository id. Returns `None` for a
    /// repository that has no projection row yet.
    fn find(&self, repo_id: Uuid) -> BoxFuture<'_, DomainResult<Option<RepoSecurityScore>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that the port is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn RepoSecurityScoreRepository>();
    }

    #[test]
    fn score_delta_default_is_noop() {
        let d = ScoreDelta::default();
        assert!(d.is_noop());
    }

    #[test]
    fn score_delta_with_status_change_is_not_noop() {
        let d = ScoreDelta {
            quarantined_delta: 1,
            ..ScoreDelta::default()
        };
        assert!(!d.is_noop());
    }

    #[test]
    fn score_delta_with_severity_change_is_not_noop() {
        let d = ScoreDelta {
            critical_delta: 1,
            ..ScoreDelta::default()
        };
        assert!(!d.is_noop());
    }

    #[test]
    fn score_delta_with_last_scan_at_only_is_not_noop() {
        let d = ScoreDelta {
            last_scan_at: Some(Utc::now()),
            ..ScoreDelta::default()
        };
        assert!(!d.is_noop());
    }

    #[test]
    fn repo_security_score_clone_eq_debug() {
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let r = RepoSecurityScore {
            repository_id: Uuid::nil(),
            quarantined_count: 1,
            rejected_count: 2,
            released_count: 3,
            critical_count: 4,
            high_count: 5,
            medium_count: 6,
            low_count: 7,
            last_scan_at: Some(now),
            updated_at: now,
        };
        assert_eq!(r.clone(), r);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("RepoSecurityScore"));
    }
}
