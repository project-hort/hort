//! The [`RetentionPolicy`] event-sourced aggregate.
//!
//! Lifecycle shape mirrors the scan-policy aggregate
//! (`PolicyCreated` / `PolicyUpdated` / `PolicyArchived`) so the
//! operational model stays uniform. The aggregate is
//! identified by a `PolicyId` (`Uuid` — every policy id in the event
//! vocabulary is a `Uuid`).
//!
//! ## Pure replay
//!
//! [`RetentionPolicy::project`] is a **pure function over events** — no
//! I/O, no clock, no projection access. It folds a stream into the
//! current aggregate state and enforces the replay invariants:
//!
//! - the first event of a stream is `Created` (a stream that opens with
//!   `Updated` / `Archived` / `Evaluated` is `Broken`);
//! - every event's `id` matches the stream's `Created.id`;
//! - no mutating event (`Updated` / `Archived` / `Evaluated`) is
//!   accepted after an `Archived` (an archived policy is terminal — the
//!   scan-policy model reactivates via a *new* event, which the retention
//!   aggregate does not yet model: it is create/update/archive/evaluate
//!   only, reactivation is a follow-on if ever needed);
//! - the embedded `predicate` / `scope` re-validate on `Created` /
//!   `Updated` so a malformed payload cannot enter replayed state.
//!
//! `project` is exercised by replay tests over fixture streams that
//! include composite security-driven predicates. Persisting these events
//! through the real Postgres event-store adapter and round-tripping
//! there is the adapter layer's job.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{DomainError, DomainResult};

use super::predicate::PolicyPredicate;
use super::scope::RetentionScope;

/// Upper bound on a retention-policy name. Mirrors the
/// scan-policy `MAX_POLICY_NAME_LEN` so the two policy-name surfaces
/// share one
/// structural guard.
const MAX_POLICY_NAME_LEN: usize = 256;

/// The event-sourced lifecycle of a retention policy.
///
/// `Created` opens the stream; `Updated` re-states the (whole)
/// predicate — retention has a single predicate tree per policy, so an
/// update replaces it rather than field-patching, matching the
/// `Updated { id, predicate, .. }` shape; `Archived` terminates it;
/// `Evaluated` is an audit breadcrumb of one sweep pass (it does not
/// change the policy's configuration, only its observed-counts
/// projection). The enum is `#[non_exhaustive]` so a future
/// `Reactivated` (the scan-policy model has one; retention does not
/// need it yet) is an additive change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RetentionPolicyEvent {
    /// The policy was created. Opens the stream.
    Created {
        id: Uuid,
        name: String,
        predicate: PolicyPredicate,
        scope: RetentionScope,
        created_at: DateTime<Utc>,
    },
    /// The policy's predicate and/or scope was replaced wholesale.
    Updated {
        id: Uuid,
        predicate: PolicyPredicate,
        scope: RetentionScope,
        updated_at: DateTime<Utc>,
    },
    /// The policy was archived (terminal — no further mutation).
    Archived {
        id: Uuid,
        by: Uuid,
        archived_at: DateTime<Utc>,
    },
    /// One evaluation sweep completed. Audit breadcrumb; updates only
    /// the observed-count projection fields, not the configuration.
    Evaluated {
        id: Uuid,
        evaluated_at: DateTime<Utc>,
        matched_count: u32,
        expired_count: u32,
    },
}

impl RetentionPolicyEvent {
    /// The aggregate id this event belongs to. Pure accessor used by
    /// the replay fold to enforce single-aggregate-per-stream.
    pub fn aggregate_id(&self) -> Uuid {
        match self {
            Self::Created { id, .. }
            | Self::Updated { id, .. }
            | Self::Archived { id, .. }
            | Self::Evaluated { id, .. } => *id,
        }
    }

    /// Per-event structural validation. Pure — no I/O. Delegates to the
    /// embedded `predicate` / `scope` validators on the config-bearing
    /// variants so a malformed payload is rejected at replay time.
    pub fn validate(&self) -> DomainResult<()> {
        match self {
            Self::Created {
                name,
                predicate,
                scope,
                ..
            } => {
                validate_name(name)?;
                predicate.validate()?;
                scope.validate()?;
                Ok(())
            }
            Self::Updated {
                predicate, scope, ..
            } => {
                predicate.validate()?;
                scope.validate()?;
                Ok(())
            }
            Self::Archived { .. } | Self::Evaluated { .. } => Ok(()),
        }
    }
}

fn validate_name(name: &str) -> DomainResult<()> {
    if name.is_empty() {
        return Err(DomainError::Validation(
            "RetentionPolicy name must not be empty".into(),
        ));
    }
    if name.len() > MAX_POLICY_NAME_LEN {
        return Err(DomainError::Validation(format!(
            "RetentionPolicy name exceeds the maximum length of {MAX_POLICY_NAME_LEN} (got {})",
            name.len()
        )));
    }
    Ok(())
}

/// The replayed current state of one retention policy.
///
/// Reconstructed purely from the event stream by
/// [`RetentionPolicy::project`]. The observed-count fields
/// (`last_evaluated_at` / `last_matched_count` / `last_expired_count`)
/// reflect the most recent `Evaluated` event, or `None` / `0` if the
/// policy has never been swept.
#[derive(Debug, Clone, PartialEq)]
pub struct RetentionPolicy {
    pub id: Uuid,
    pub name: String,
    pub predicate: PolicyPredicate,
    pub scope: RetentionScope,
    pub archived: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_evaluated_at: Option<DateTime<Utc>>,
    pub last_matched_count: u32,
    pub last_expired_count: u32,
    /// 0-based position of the last applied event — the same
    /// optimistic-concurrency anchor the `ScanPolicyProjection`
    /// carries (`stream_version`). A single-event (`Created`-only)
    /// stream is at version 0.
    pub stream_version: u64,
}

impl RetentionPolicy {
    /// Fold an event stream into the current aggregate state. Pure —
    /// no I/O, no clock. Errors are replay-integrity failures
    /// ([`DomainError::Invariant`]) or malformed payloads
    /// ([`DomainError::Validation`]).
    pub fn project(events: &[RetentionPolicyEvent]) -> DomainResult<Self> {
        let mut iter = events.iter();
        let first = iter
            .next()
            .ok_or_else(|| DomainError::Invariant("RetentionPolicy stream is empty".into()))?;

        let mut state = match first {
            RetentionPolicyEvent::Created {
                id,
                name,
                predicate,
                scope,
                created_at,
            } => {
                first.validate()?;
                Self {
                    id: *id,
                    name: name.clone(),
                    predicate: predicate.clone(),
                    scope: scope.clone(),
                    archived: false,
                    created_at: *created_at,
                    updated_at: *created_at,
                    last_evaluated_at: None,
                    last_matched_count: 0,
                    last_expired_count: 0,
                    stream_version: 0,
                }
            }
            other => {
                return Err(DomainError::Invariant(format!(
                    "RetentionPolicy stream must open with Created, got {}",
                    variant_name(other)
                )));
            }
        };

        for event in iter {
            state.apply(event)?;
        }
        Ok(state)
    }

    /// Apply a single subsequent event to the replayed state. Pure.
    /// Not the stream-opening path — `Created` is only valid as the
    /// first event and is handled by [`Self::project`]; a second
    /// `Created` (or any event after `Archived`) is a replay-integrity
    /// failure.
    fn apply(&mut self, event: &RetentionPolicyEvent) -> DomainResult<()> {
        if event.aggregate_id() != self.id {
            return Err(DomainError::Invariant(format!(
                "RetentionPolicy stream mixes aggregate ids: stream is {}, event is {}",
                self.id,
                event.aggregate_id()
            )));
        }
        if self.archived {
            return Err(DomainError::Invariant(format!(
                "RetentionPolicy {} is archived; no further events are valid (got {})",
                self.id,
                variant_name(event)
            )));
        }
        match event {
            RetentionPolicyEvent::Created { .. } => {
                return Err(DomainError::Invariant(
                    "RetentionPolicy stream has a second Created event".into(),
                ));
            }
            RetentionPolicyEvent::Updated {
                predicate,
                scope,
                updated_at,
                ..
            } => {
                event.validate()?;
                self.predicate = predicate.clone();
                self.scope = scope.clone();
                self.updated_at = *updated_at;
            }
            RetentionPolicyEvent::Archived { archived_at, .. } => {
                self.archived = true;
                self.updated_at = *archived_at;
            }
            RetentionPolicyEvent::Evaluated {
                evaluated_at,
                matched_count,
                expired_count,
                ..
            } => {
                self.last_evaluated_at = Some(*evaluated_at);
                self.last_matched_count = *matched_count;
                self.last_expired_count = *expired_count;
            }
        }
        self.stream_version += 1;
        Ok(())
    }
}

fn variant_name(e: &RetentionPolicyEvent) -> &'static str {
    match e {
        RetentionPolicyEvent::Created { .. } => "Created",
        RetentionPolicyEvent::Updated { .. } => "Updated",
        RetentionPolicyEvent::Archived { .. } => "Archived",
        RetentionPolicyEvent::Evaluated { .. } => "Evaluated",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::scan_policy::SeverityThreshold;
    use crate::events::IngestSource;
    use crate::retention::BooleanOp;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn created(id: Uuid) -> RetentionPolicyEvent {
        RetentionPolicyEvent::Created {
            id,
            name: "expire-old".into(),
            predicate: PolicyPredicate::AgeExceeds(86_400),
            scope: RetentionScope::IngestSource(IngestSource::Proxied),
            created_at: ts(1_000),
        }
    }

    // -- aggregate_id --------------------------------------------------------

    #[test]
    fn aggregate_id_covers_every_variant() {
        let id = Uuid::from_u128(7);
        assert_eq!(created(id).aggregate_id(), id);
        assert_eq!(
            RetentionPolicyEvent::Updated {
                id,
                predicate: PolicyPredicate::HasFixAvailable,
                scope: RetentionScope::AllRepos,
                updated_at: ts(2),
            }
            .aggregate_id(),
            id
        );
        assert_eq!(
            RetentionPolicyEvent::Archived {
                id,
                by: Uuid::nil(),
                archived_at: ts(3),
            }
            .aggregate_id(),
            id
        );
        assert_eq!(
            RetentionPolicyEvent::Evaluated {
                id,
                evaluated_at: ts(4),
                matched_count: 1,
                expired_count: 1,
            }
            .aggregate_id(),
            id
        );
    }

    // -- event validate ------------------------------------------------------

    #[test]
    fn created_validate_ok() {
        created(Uuid::nil()).validate().unwrap();
    }

    #[test]
    fn created_validate_empty_name_rejected() {
        let e = RetentionPolicyEvent::Created {
            id: Uuid::nil(),
            name: String::new(),
            predicate: PolicyPredicate::HasFixAvailable,
            scope: RetentionScope::AllRepos,
            created_at: ts(0),
        };
        assert!(e
            .validate()
            .unwrap_err()
            .to_string()
            .contains("not be empty"));
    }

    #[test]
    fn created_validate_oversize_name_rejected() {
        let e = RetentionPolicyEvent::Created {
            id: Uuid::nil(),
            name: "x".repeat(MAX_POLICY_NAME_LEN + 1),
            predicate: PolicyPredicate::HasFixAvailable,
            scope: RetentionScope::AllRepos,
            created_at: ts(0),
        };
        assert!(e
            .validate()
            .unwrap_err()
            .to_string()
            .contains("maximum length"));
    }

    #[test]
    fn created_validate_name_at_limit_ok() {
        let e = RetentionPolicyEvent::Created {
            id: Uuid::nil(),
            name: "x".repeat(MAX_POLICY_NAME_LEN),
            predicate: PolicyPredicate::HasFixAvailable,
            scope: RetentionScope::AllRepos,
            created_at: ts(0),
        };
        e.validate().unwrap();
    }

    #[test]
    fn created_validate_bad_predicate_rejected() {
        let e = RetentionPolicyEvent::Created {
            id: Uuid::nil(),
            name: "p".into(),
            predicate: PolicyPredicate::AgeExceeds(0),
            scope: RetentionScope::AllRepos,
            created_at: ts(0),
        };
        assert!(e
            .validate()
            .unwrap_err()
            .to_string()
            .contains("> 0 seconds"));
    }

    #[test]
    fn created_validate_bad_scope_rejected() {
        let e = RetentionPolicyEvent::Created {
            id: Uuid::nil(),
            name: "p".into(),
            predicate: PolicyPredicate::HasFixAvailable,
            scope: RetentionScope::Repos(vec![]),
            created_at: ts(0),
        };
        assert!(e
            .validate()
            .unwrap_err()
            .to_string()
            .contains("at least one repository"));
    }

    #[test]
    fn updated_validate_bad_predicate_rejected() {
        let e = RetentionPolicyEvent::Updated {
            id: Uuid::nil(),
            predicate: PolicyPredicate::KeepLastN(0),
            scope: RetentionScope::AllRepos,
            updated_at: ts(0),
        };
        assert!(e
            .validate()
            .unwrap_err()
            .to_string()
            .contains("every artifact"));
    }

    #[test]
    fn updated_validate_bad_scope_rejected() {
        let e = RetentionPolicyEvent::Updated {
            id: Uuid::nil(),
            predicate: PolicyPredicate::HasFixAvailable,
            scope: RetentionScope::PackageNamePattern(String::new()),
            updated_at: ts(0),
        };
        assert!(e
            .validate()
            .unwrap_err()
            .to_string()
            .contains("not be empty"));
    }

    #[test]
    fn updated_validate_ok() {
        RetentionPolicyEvent::Updated {
            id: Uuid::nil(),
            predicate: PolicyPredicate::HasFixAvailable,
            scope: RetentionScope::AllRepos,
            updated_at: ts(0),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn archived_and_evaluated_validate_ok() {
        RetentionPolicyEvent::Archived {
            id: Uuid::nil(),
            by: Uuid::nil(),
            archived_at: ts(0),
        }
        .validate()
        .unwrap();
        RetentionPolicyEvent::Evaluated {
            id: Uuid::nil(),
            evaluated_at: ts(0),
            matched_count: 0,
            expired_count: 0,
        }
        .validate()
        .unwrap();
    }

    // -- project: happy paths -----------------------------------------------

    #[test]
    fn project_created_only() {
        let id = Uuid::from_u128(1);
        let p = RetentionPolicy::project(&[created(id)]).unwrap();
        assert_eq!(p.id, id);
        assert_eq!(p.name, "expire-old");
        assert!(!p.archived);
        assert_eq!(p.created_at, ts(1_000));
        assert_eq!(p.updated_at, ts(1_000));
        assert_eq!(p.last_evaluated_at, None);
        assert_eq!(p.last_matched_count, 0);
        assert_eq!(p.last_expired_count, 0);
        assert_eq!(p.stream_version, 0);
    }

    #[test]
    fn project_created_then_updated() {
        let id = Uuid::from_u128(2);
        let p = RetentionPolicy::project(&[
            created(id),
            RetentionPolicyEvent::Updated {
                id,
                predicate: PolicyPredicate::KeepLastN(5),
                scope: RetentionScope::AllRepos,
                updated_at: ts(2_000),
            },
        ])
        .unwrap();
        assert_eq!(p.predicate, PolicyPredicate::KeepLastN(5));
        assert_eq!(p.scope, RetentionScope::AllRepos);
        assert_eq!(p.updated_at, ts(2_000));
        assert_eq!(p.created_at, ts(1_000));
        assert_eq!(p.stream_version, 1);
    }

    #[test]
    fn project_created_then_evaluated_updates_counts() {
        let id = Uuid::from_u128(3);
        let p = RetentionPolicy::project(&[
            created(id),
            RetentionPolicyEvent::Evaluated {
                id,
                evaluated_at: ts(5_000),
                matched_count: 42,
                expired_count: 7,
            },
        ])
        .unwrap();
        assert_eq!(p.last_evaluated_at, Some(ts(5_000)));
        assert_eq!(p.last_matched_count, 42);
        assert_eq!(p.last_expired_count, 7);
        // Evaluation does not change configuration timestamps.
        assert_eq!(p.updated_at, ts(1_000));
        assert_eq!(p.stream_version, 1);
    }

    #[test]
    fn project_created_then_archived_is_terminal_state() {
        let id = Uuid::from_u128(4);
        let p = RetentionPolicy::project(&[
            created(id),
            RetentionPolicyEvent::Archived {
                id,
                by: Uuid::from_u128(99),
                archived_at: ts(9_000),
            },
        ])
        .unwrap();
        assert!(p.archived);
        assert_eq!(p.updated_at, ts(9_000));
        assert_eq!(p.stream_version, 1);
    }

    /// The canonical operator pattern fixture: a
    /// `Composite(And, [HasFindingAboveSeverity(High),
    /// HasFixAvailable, HasFindingDetectedFor(7d)])` policy replayed
    /// over a Created → Evaluated → Updated stream.
    #[test]
    fn project_canonical_composite_operator_pattern_stream() {
        let id = Uuid::from_u128(0xC0FFEE);
        let seven_days = 7 * 24 * 3600;
        let canonical = PolicyPredicate::Composite(
            BooleanOp::And,
            vec![
                PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
                PolicyPredicate::HasFixAvailable,
                PolicyPredicate::HasFindingDetectedFor(seven_days),
            ],
        );
        let stream = vec![
            RetentionPolicyEvent::Created {
                id,
                name: "high-with-fix-7d".into(),
                predicate: canonical.clone(),
                // Default scope for security-driven retention.
                scope: RetentionScope::IngestSource(IngestSource::Proxied),
                created_at: ts(100),
            },
            RetentionPolicyEvent::Evaluated {
                id,
                evaluated_at: ts(200),
                matched_count: 12,
                expired_count: 3,
            },
            RetentionPolicyEvent::Updated {
                id,
                predicate: canonical.clone(),
                scope: RetentionScope::AllRepos,
                updated_at: ts(300),
            },
        ];
        let p = RetentionPolicy::project(&stream).unwrap();
        assert_eq!(p.predicate, canonical);
        assert!(p.predicate.is_security_driven());
        assert_eq!(p.scope, RetentionScope::AllRepos);
        assert!(!p.scope.excludes_direct_uploads());
        assert_eq!(p.last_matched_count, 12);
        assert_eq!(p.last_expired_count, 3);
        assert_eq!(p.last_evaluated_at, Some(ts(200)));
        assert_eq!(p.updated_at, ts(300));
        assert_eq!(p.stream_version, 2);
    }

    // -- project: replay-integrity failures ---------------------------------

    #[test]
    fn project_empty_stream_rejected() {
        let err = RetentionPolicy::project(&[]).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn project_stream_not_opening_with_created_rejected() {
        let id = Uuid::nil();
        for opener in [
            RetentionPolicyEvent::Updated {
                id,
                predicate: PolicyPredicate::HasFixAvailable,
                scope: RetentionScope::AllRepos,
                updated_at: ts(0),
            },
            RetentionPolicyEvent::Archived {
                id,
                by: Uuid::nil(),
                archived_at: ts(0),
            },
            RetentionPolicyEvent::Evaluated {
                id,
                evaluated_at: ts(0),
                matched_count: 0,
                expired_count: 0,
            },
        ] {
            let err = RetentionPolicy::project(&[opener]).unwrap_err();
            assert!(matches!(err, DomainError::Invariant(_)));
            assert!(err.to_string().contains("must open with Created"));
        }
    }

    #[test]
    fn project_second_created_rejected() {
        let id = Uuid::from_u128(5);
        let err = RetentionPolicy::project(&[created(id), created(id)]).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("second Created"));
    }

    #[test]
    fn project_mixed_aggregate_ids_rejected() {
        let id = Uuid::from_u128(6);
        let other = Uuid::from_u128(7);
        let err = RetentionPolicy::project(&[
            created(id),
            RetentionPolicyEvent::Evaluated {
                id: other,
                evaluated_at: ts(0),
                matched_count: 0,
                expired_count: 0,
            },
        ])
        .unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("mixes aggregate ids"));
    }

    #[test]
    fn project_event_after_archived_rejected() {
        let id = Uuid::from_u128(8);
        for trailing in [
            RetentionPolicyEvent::Updated {
                id,
                predicate: PolicyPredicate::HasFixAvailable,
                scope: RetentionScope::AllRepos,
                updated_at: ts(0),
            },
            RetentionPolicyEvent::Evaluated {
                id,
                evaluated_at: ts(0),
                matched_count: 0,
                expired_count: 0,
            },
            RetentionPolicyEvent::Archived {
                id,
                by: Uuid::nil(),
                archived_at: ts(0),
            },
        ] {
            let err = RetentionPolicy::project(&[
                created(id),
                RetentionPolicyEvent::Archived {
                    id,
                    by: Uuid::nil(),
                    archived_at: ts(50),
                },
                trailing,
            ])
            .unwrap_err();
            assert!(matches!(err, DomainError::Invariant(_)));
            assert!(err.to_string().contains("is archived"));
        }
    }

    #[test]
    fn project_malformed_updated_predicate_rejected_at_replay() {
        let id = Uuid::from_u128(9);
        let err = RetentionPolicy::project(&[
            created(id),
            RetentionPolicyEvent::Updated {
                id,
                predicate: PolicyPredicate::AgeExceeds(0),
                scope: RetentionScope::AllRepos,
                updated_at: ts(0),
            },
        ])
        .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("> 0 seconds"));
    }

    #[test]
    fn project_malformed_created_rejected_at_replay() {
        let err = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
            id: Uuid::nil(),
            name: String::new(),
            predicate: PolicyPredicate::HasFixAvailable,
            scope: RetentionScope::AllRepos,
            created_at: ts(0),
        }])
        .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- variant_name (error-message helper) --------------------------------

    #[test]
    fn variant_name_covers_every_variant() {
        let id = Uuid::nil();
        assert_eq!(variant_name(&created(id)), "Created");
        assert_eq!(
            variant_name(&RetentionPolicyEvent::Updated {
                id,
                predicate: PolicyPredicate::HasFixAvailable,
                scope: RetentionScope::AllRepos,
                updated_at: ts(0),
            }),
            "Updated"
        );
        assert_eq!(
            variant_name(&RetentionPolicyEvent::Archived {
                id,
                by: id,
                archived_at: ts(0),
            }),
            "Archived"
        );
        assert_eq!(
            variant_name(&RetentionPolicyEvent::Evaluated {
                id,
                evaluated_at: ts(0),
                matched_count: 0,
                expired_count: 0,
            }),
            "Evaluated"
        );
    }

    // -- serde round-trip (wire stability) ----------------------------------

    #[test]
    fn serde_round_trip_every_event_variant() {
        let id = Uuid::from_u128(123);
        let events = vec![
            created(id),
            RetentionPolicyEvent::Updated {
                id,
                predicate: PolicyPredicate::Composite(
                    BooleanOp::And,
                    vec![
                        PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
                        PolicyPredicate::HasFixAvailable,
                        PolicyPredicate::HasFindingDetectedFor(604_800),
                    ],
                ),
                scope: RetentionScope::Repos(vec![Uuid::nil()]),
                updated_at: ts(2),
            },
            RetentionPolicyEvent::Archived {
                id,
                by: Uuid::from_u128(9),
                archived_at: ts(3),
            },
            RetentionPolicyEvent::Evaluated {
                id,
                evaluated_at: ts(4),
                matched_count: 9,
                expired_count: 2,
            },
        ];
        for e in events {
            let json = serde_json::to_value(&e).unwrap();
            let back: RetentionPolicyEvent = serde_json::from_value(json).unwrap();
            assert_eq!(e, back);
        }
    }

    #[test]
    fn replay_state_clone_debug_eq_cover() {
        let id = Uuid::from_u128(55);
        let p = RetentionPolicy::project(&[created(id)]).unwrap();
        let q = p.clone();
        assert_eq!(p, q);
        let mut r = p.clone();
        r.archived = true;
        assert_ne!(p, r);
        assert!(format!("{p:?}").contains("RetentionPolicy"));
    }

    #[test]
    fn event_clone_debug_eq_cover() {
        let e = created(Uuid::nil());
        let f = e.clone();
        assert_eq!(e, f);
        assert_ne!(
            e,
            RetentionPolicyEvent::Archived {
                id: Uuid::nil(),
                by: Uuid::nil(),
                archived_at: ts(0),
            }
        );
        assert!(format!("{e:?}").contains("Created"));
    }
}
