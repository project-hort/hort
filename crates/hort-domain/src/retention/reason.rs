//! [`ExpirationReason`] — the discriminated reason an artifact became
//! eligible for purge.
//!
//! This value object is carried by the `ArtifactExpired` event. That
//! event lands on the **artifact** stream. The `metric_label` strings
//! are the exact `hort_retention_expired_total{reason}` label set
//! (`age_exceeded`, `unused_ttl`, `keep_last_n`, `manual`,
//! `security_finding`) — one authoritative source for the label
//! vocabulary.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::scan_policy::SeverityThreshold;
use crate::error::{DomainError, DomainResult};

/// Upper bound on a free-text manual-expiry reason. Mirrors the
/// scan-policy `MAX_REASON_LEN` so the two operator-reason surfaces
/// share one
/// structural guard.
const MAX_REASON_LEN: usize = 4096;

/// Why a retention policy marked an artifact eligible for purge.
/// Each variant snapshots the inputs that drove the
/// decision so an audit query never has to re-resolve projection rows
/// that may have shifted since the decision was recorded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExpirationReason {
    /// `AgeExceeds` predicate fired.
    AgeExceeded {
        published_at: DateTime<Utc>,
        /// The configured TTL, in seconds (domain duration wire form).
        ttl_secs: u64,
    },
    /// `UnusedFor` predicate fired. `last_downloaded_at` is `None` when
    /// the artifact was never downloaded.
    UnusedTtl {
        last_downloaded_at: Option<DateTime<Utc>>,
        ttl_secs: u64,
    },
    /// `KeepLastN` predicate fired. `rank` is this artifact's position
    /// (1-based, newest = 1) among `total` versions; it expired because
    /// `rank > keep`.
    KeepLastN { keep: u32, total: u32, rank: u32 },
    /// An operator manually expired the artifact.
    Manual { actor: Uuid, reason: String },
    /// One of the security-driven predicates
    /// (`HasFindingAboveSeverity` / `HasFindingAboveCvss` /
    /// `HasFixAvailable` / `HasFindingDetectedFor`) fired. Carries the
    /// severity-and-fix snapshot that drove the decision so audit
    /// queries don't need to re-resolve `scan_findings` rows that may
    /// have shifted since.
    SecurityFinding {
        max_severity: SeverityThreshold,
        /// `None` when the matched findings carry no CVSS score.
        max_cvss: Option<f32>,
        finding_count: u32,
        fix_available: bool,
        first_detected_at: DateTime<Utc>,
        latest_scan_at: DateTime<Utc>,
    },
}

impl ExpirationReason {
    /// The exact `hort_retention_expired_total{reason}` Prometheus label
    /// for this variant. Pure — the metric *emission* is the
    /// app-layer use case's job; the domain only owns the canonical
    /// label vocabulary so it cannot drift between the emitter and the
    /// metrics catalog.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::AgeExceeded { .. } => "age_exceeded",
            Self::UnusedTtl { .. } => "unused_ttl",
            Self::KeepLastN { .. } => "keep_last_n",
            Self::Manual { .. } => "manual",
            Self::SecurityFinding { .. } => "security_finding",
        }
    }

    /// Structural validation. Pure — no I/O.
    ///
    /// - `Manual.reason` must be non-empty and bounded (it is the audit
    ///   record of an operator's stated intent).
    /// - `KeepLastN` must be self-consistent: `rank >= 1`,
    ///   `rank <= total`, and `rank > keep` (the artifact only expired
    ///   *because* it fell outside the keep window — recording a
    ///   `KeepLastN` reason for an artifact inside the window is a bug).
    /// - `SecurityFinding.finding_count` must be `>= 1` — a
    ///   security-finding expiry with zero findings is a contradiction.
    /// - `SecurityFinding.max_cvss`, when present, must be a finite
    ///   in-range `[0.0, 10.0]` score.
    /// - `SecurityFinding.latest_scan_at` must be at-or-after
    ///   `first_detected_at` (the finding cannot be detected after the
    ///   most recent scan that observed it).
    pub fn validate(&self) -> DomainResult<()> {
        match self {
            Self::Manual { reason, .. } => {
                if reason.is_empty() {
                    return Err(DomainError::Validation(
                        "ExpirationReason::Manual reason must not be empty".into(),
                    ));
                }
                if reason.len() > MAX_REASON_LEN {
                    return Err(DomainError::Validation(format!(
                        "ExpirationReason::Manual reason exceeds the maximum length of \
                         {MAX_REASON_LEN} (got {})",
                        reason.len()
                    )));
                }
                Ok(())
            }
            Self::KeepLastN { keep, total, rank } => {
                if *rank == 0 {
                    return Err(DomainError::Validation(
                        "ExpirationReason::KeepLastN rank is 1-based and must be >= 1".into(),
                    ));
                }
                if rank > total {
                    return Err(DomainError::Validation(format!(
                        "ExpirationReason::KeepLastN rank ({rank}) cannot exceed total ({total})"
                    )));
                }
                if rank <= keep {
                    return Err(DomainError::Validation(format!(
                        "ExpirationReason::KeepLastN records an expiry but rank ({rank}) is \
                         within the keep window ({keep}) — not an expiry"
                    )));
                }
                Ok(())
            }
            Self::SecurityFinding {
                max_cvss,
                finding_count,
                first_detected_at,
                latest_scan_at,
                ..
            } => {
                if *finding_count == 0 {
                    return Err(DomainError::Validation(
                        "ExpirationReason::SecurityFinding must carry at least one finding".into(),
                    ));
                }
                if let Some(c) = max_cvss {
                    if !c.is_finite() || *c < 0.0 || *c > 10.0 {
                        return Err(DomainError::Validation(format!(
                            "ExpirationReason::SecurityFinding max_cvss must be a finite score \
                             within [0.0, 10.0] (got {c})"
                        )));
                    }
                }
                if latest_scan_at < first_detected_at {
                    return Err(DomainError::Validation(
                        "ExpirationReason::SecurityFinding latest_scan_at precedes \
                         first_detected_at"
                            .into(),
                    ));
                }
                Ok(())
            }
            Self::AgeExceeded { .. } | Self::UnusedTtl { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    // -- metric_label (§7 label vocabulary) ---------------------------------

    #[test]
    fn metric_label_age_exceeded() {
        let r = ExpirationReason::AgeExceeded {
            published_at: ts(0),
            ttl_secs: 86_400,
        };
        assert_eq!(r.metric_label(), "age_exceeded");
    }

    #[test]
    fn metric_label_unused_ttl() {
        let r = ExpirationReason::UnusedTtl {
            last_downloaded_at: None,
            ttl_secs: 3600,
        };
        assert_eq!(r.metric_label(), "unused_ttl");
    }

    #[test]
    fn metric_label_keep_last_n() {
        let r = ExpirationReason::KeepLastN {
            keep: 3,
            total: 5,
            rank: 4,
        };
        assert_eq!(r.metric_label(), "keep_last_n");
    }

    #[test]
    fn metric_label_manual() {
        let r = ExpirationReason::Manual {
            actor: Uuid::nil(),
            reason: "ops cleanup".into(),
        };
        assert_eq!(r.metric_label(), "manual");
    }

    #[test]
    fn metric_label_security_finding() {
        let r = ExpirationReason::SecurityFinding {
            max_severity: SeverityThreshold::High,
            max_cvss: Some(9.0),
            finding_count: 1,
            fix_available: true,
            first_detected_at: ts(0),
            latest_scan_at: ts(10),
        };
        assert_eq!(r.metric_label(), "security_finding");
    }

    // -- validate: AgeExceeded / UnusedTtl (always ok) ----------------------

    #[test]
    fn validate_age_exceeded_ok() {
        ExpirationReason::AgeExceeded {
            published_at: ts(0),
            ttl_secs: 1,
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn validate_unused_ttl_ok_with_and_without_download() {
        ExpirationReason::UnusedTtl {
            last_downloaded_at: Some(ts(5)),
            ttl_secs: 10,
        }
        .validate()
        .unwrap();
        ExpirationReason::UnusedTtl {
            last_downloaded_at: None,
            ttl_secs: 10,
        }
        .validate()
        .unwrap();
    }

    // -- validate: Manual ---------------------------------------------------

    #[test]
    fn validate_manual_ok() {
        ExpirationReason::Manual {
            actor: Uuid::nil(),
            reason: "decommission".into(),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn validate_manual_empty_reason_rejected() {
        let err = ExpirationReason::Manual {
            actor: Uuid::nil(),
            reason: String::new(),
        }
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_manual_oversize_reason_rejected() {
        let err = ExpirationReason::Manual {
            actor: Uuid::nil(),
            reason: "x".repeat(MAX_REASON_LEN + 1),
        }
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("maximum length"));
    }

    #[test]
    fn validate_manual_reason_at_limit_ok() {
        ExpirationReason::Manual {
            actor: Uuid::nil(),
            reason: "x".repeat(MAX_REASON_LEN),
        }
        .validate()
        .unwrap();
    }

    // -- validate: KeepLastN ------------------------------------------------

    #[test]
    fn validate_keep_last_n_ok() {
        ExpirationReason::KeepLastN {
            keep: 3,
            total: 10,
            rank: 4,
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn validate_keep_last_n_rank_zero_rejected() {
        let err = ExpirationReason::KeepLastN {
            keep: 3,
            total: 10,
            rank: 0,
        }
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("1-based"));
    }

    #[test]
    fn validate_keep_last_n_rank_exceeds_total_rejected() {
        let err = ExpirationReason::KeepLastN {
            keep: 3,
            total: 5,
            rank: 6,
        }
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("cannot exceed total"));
    }

    #[test]
    fn validate_keep_last_n_rank_within_keep_window_rejected() {
        // rank == keep is still inside the window (we keep ranks
        // 1..=keep), so recording an expiry here is a contradiction.
        let err = ExpirationReason::KeepLastN {
            keep: 3,
            total: 5,
            rank: 3,
        }
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("within the keep window"));
    }

    #[test]
    fn validate_keep_last_n_rank_just_outside_window_ok() {
        ExpirationReason::KeepLastN {
            keep: 3,
            total: 5,
            rank: 4,
        }
        .validate()
        .unwrap();
    }

    // -- validate: SecurityFinding ------------------------------------------

    #[test]
    fn validate_security_finding_ok_with_cvss() {
        ExpirationReason::SecurityFinding {
            max_severity: SeverityThreshold::Critical,
            max_cvss: Some(9.8),
            finding_count: 2,
            fix_available: true,
            first_detected_at: ts(0),
            latest_scan_at: ts(100),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn validate_security_finding_ok_without_cvss() {
        ExpirationReason::SecurityFinding {
            max_severity: SeverityThreshold::Medium,
            max_cvss: None,
            finding_count: 1,
            fix_available: false,
            first_detected_at: ts(0),
            latest_scan_at: ts(0),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn validate_security_finding_zero_findings_rejected() {
        let err = ExpirationReason::SecurityFinding {
            max_severity: SeverityThreshold::Low,
            max_cvss: None,
            finding_count: 0,
            fix_available: false,
            first_detected_at: ts(0),
            latest_scan_at: ts(0),
        }
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("at least one finding"));
    }

    #[test]
    fn validate_security_finding_nan_cvss_rejected() {
        let err = ExpirationReason::SecurityFinding {
            max_severity: SeverityThreshold::High,
            max_cvss: Some(f32::NAN),
            finding_count: 1,
            fix_available: true,
            first_detected_at: ts(0),
            latest_scan_at: ts(0),
        }
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("finite score"));
    }

    #[test]
    fn validate_security_finding_negative_cvss_rejected() {
        let err = ExpirationReason::SecurityFinding {
            max_severity: SeverityThreshold::High,
            max_cvss: Some(-1.0),
            finding_count: 1,
            fix_available: true,
            first_detected_at: ts(0),
            latest_scan_at: ts(0),
        }
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("[0.0, 10.0]"));
    }

    #[test]
    fn validate_security_finding_over_ten_cvss_rejected() {
        let err = ExpirationReason::SecurityFinding {
            max_severity: SeverityThreshold::High,
            max_cvss: Some(10.5),
            finding_count: 1,
            fix_available: true,
            first_detected_at: ts(0),
            latest_scan_at: ts(0),
        }
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("[0.0, 10.0]"));
    }

    #[test]
    fn validate_security_finding_scan_before_detection_rejected() {
        let err = ExpirationReason::SecurityFinding {
            max_severity: SeverityThreshold::High,
            max_cvss: Some(9.0),
            finding_count: 1,
            fix_available: true,
            first_detected_at: ts(100),
            latest_scan_at: ts(50),
        }
        .validate()
        .unwrap_err();
        assert!(err.to_string().contains("precedes"));
    }

    #[test]
    fn validate_security_finding_equal_timestamps_ok() {
        ExpirationReason::SecurityFinding {
            max_severity: SeverityThreshold::High,
            max_cvss: Some(0.0),
            finding_count: 1,
            fix_available: true,
            first_detected_at: ts(42),
            latest_scan_at: ts(42),
        }
        .validate()
        .unwrap();
    }

    // -- serde round-trip (wire stability) ----------------------------------

    #[test]
    fn serde_round_trip_every_variant() {
        let variants = vec![
            ExpirationReason::AgeExceeded {
                published_at: ts(1),
                ttl_secs: 86_400,
            },
            ExpirationReason::UnusedTtl {
                last_downloaded_at: Some(ts(2)),
                ttl_secs: 3600,
            },
            ExpirationReason::UnusedTtl {
                last_downloaded_at: None,
                ttl_secs: 3600,
            },
            ExpirationReason::KeepLastN {
                keep: 3,
                total: 9,
                rank: 7,
            },
            ExpirationReason::Manual {
                actor: Uuid::nil(),
                reason: "manual purge".into(),
            },
            ExpirationReason::SecurityFinding {
                max_severity: SeverityThreshold::Critical,
                max_cvss: Some(9.8),
                finding_count: 4,
                fix_available: true,
                first_detected_at: ts(0),
                latest_scan_at: ts(1000),
            },
            ExpirationReason::SecurityFinding {
                max_severity: SeverityThreshold::Low,
                max_cvss: None,
                finding_count: 1,
                fix_available: false,
                first_detected_at: ts(0),
                latest_scan_at: ts(0),
            },
        ];
        for v in variants {
            let json = serde_json::to_value(&v).unwrap();
            let back: ExpirationReason = serde_json::from_value(json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn clone_debug_eq_cover() {
        let a = ExpirationReason::Manual {
            actor: Uuid::nil(),
            reason: "r".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(
            a,
            ExpirationReason::AgeExceeded {
                published_at: ts(0),
                ttl_secs: 1,
            }
        );
        assert!(format!("{a:?}").contains("Manual"));
    }
}
