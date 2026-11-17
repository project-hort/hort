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

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{DomainError, DomainResult};

use super::held_state_entry::HeldState;
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
        /// The held states this policy may expire — see
        /// [`RetentionPolicy::held_states`]. Additive and
        /// `#[serde(default)]`: a stream written before the held-state
        /// exception existed decodes as the empty set, which is the
        /// behaviour it had.
        #[serde(default)]
        held_states: BTreeSet<HeldState>,
        created_at: DateTime<Utc>,
    },
    /// The policy's predicate and/or scope was replaced wholesale.
    Updated {
        id: Uuid,
        predicate: PolicyPredicate,
        scope: RetentionScope,
        /// The replacement held-state opt-in. Re-stated wholesale with
        /// the predicate and the scope, for the same reason they are:
        /// retention has one configuration per policy and an update
        /// replaces it. An update that omits it therefore **clears**
        /// the opt-in, which is the direction that cannot surprise an
        /// operator into a wider exception than the YAML states.
        #[serde(default)]
        held_states: BTreeSet<HeldState>,
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
                held_states,
                ..
            } => {
                validate_name(name)?;
                predicate.validate()?;
                scope.validate()?;
                validate_held_states(predicate, held_states)?;
                Ok(())
            }
            Self::Updated {
                predicate,
                scope,
                held_states,
                ..
            } => {
                predicate.validate()?;
                scope.validate()?;
                validate_held_states(predicate, held_states)?;
                Ok(())
            }
            Self::Archived { .. } | Self::Evaluated { .. } => Ok(()),
        }
    }
}

/// The held-state opt-in's own invariant: an opt-in that is not empty
/// requires a predicate whose **every** successful branch carries a
/// positive age bound
/// ([`PolicyPredicate::every_branch_has_positive_age_bound`]).
///
/// Enforced at replay as well as at apply, and that is the point of it
/// being here. The apply pipeline rejects such an envelope with an
/// operator-facing message, but the aggregate is event-sourced: a
/// stream is also written by a future code path, replayed by a future
/// binary, and seeded by a fixture. An opt-in without a bound is a
/// policy that expires retained evidence the instant it is first
/// judged, so the aggregate refuses to replay into that state at all.
///
/// An empty opt-in is unconditionally valid: it is the state every
/// existing policy is in and it changes no decision.
fn validate_held_states(
    predicate: &PolicyPredicate,
    held_states: &BTreeSet<HeldState>,
) -> DomainResult<()> {
    if held_states.is_empty() {
        return Ok(());
    }
    if !predicate.every_branch_has_positive_age_bound() {
        return Err(DomainError::Validation(format!(
            "RetentionPolicy opts in to held states {held_states:?} but its predicate \
             has a branch that can match with no positive AgeExceeds bound; a held-state \
             expiry must be bounded by time spent in the state on every branch that can \
             fire"
        )));
    }
    Ok(())
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
    /// The **held** quarantine states this policy may expire an
    /// artifact out of — empty for every policy that does not say
    /// otherwise, which is every policy that predates the exception.
    ///
    /// A held artifact (`quarantined` / `rejected` /
    /// `scan_indeterminate`) is retained evidence or an artifact
    /// awaiting a decision, and is refused by five independent gates
    /// on the way to collection. This set is the only thing that opens
    /// them, per policy and per state: a policy that does not name a
    /// state cannot expire an artifact in it, and an empty set leaves
    /// every gate exactly as shut as it was.
    ///
    /// Paired invariant, enforced by
    /// [`RetentionPolicyEvent::validate`]: a non-empty opt-in requires
    /// a predicate whose every successful branch carries a positive
    /// `AgeExceeds`
    /// ([`PolicyPredicate::every_branch_has_positive_age_bound`]), and
    /// for such an evaluation `AgeExceeds` is re-anchored to the
    /// artifact's held-state **entry** rather than to its content
    /// anchor. Without both halves the opt-in would expire an artifact
    /// the moment it was judged — a two-year-old artifact rejected five
    /// minutes ago is already past any span measured from its content.
    pub held_states: BTreeSet<HeldState>,
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
                held_states,
                created_at,
            } => {
                first.validate()?;
                Self {
                    id: *id,
                    name: name.clone(),
                    predicate: predicate.clone(),
                    scope: scope.clone(),
                    held_states: held_states.clone(),
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
            state.apply_appended(event)?;
        }
        Ok(state)
    }

    /// Apply a single subsequent event to the replayed state. Pure.
    /// Not the stream-opening path — `Created` is only valid as the
    /// first event and is handled by [`Self::project`]; a second
    /// `Created` (or any event after `Archived`) is a replay-integrity
    /// failure.
    ///
    /// Public because the **write** path uses it too: a mutation builds
    /// its event and then applies it, instead of maintaining the event and
    /// the projection edit side by side. That makes the forward and the
    /// replay directions one mapping, so a row written by a command and a
    /// row re-derived from the same stream cannot disagree. The caller
    /// then overwrites `stream_version` with the append's
    /// `AppendResult.stream_position` — this bumps it by one, which is
    /// right for a contiguous replay but is not the authority on where an
    /// append actually landed.
    pub fn apply_appended(&mut self, event: &RetentionPolicyEvent) -> DomainResult<()> {
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
                held_states,
                updated_at,
                ..
            } => {
                event.validate()?;
                self.predicate = predicate.clone();
                self.scope = scope.clone();
                self.held_states = held_states.clone();
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
            held_states: Default::default(),
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
                held_states: Default::default(),
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
            held_states: Default::default(),
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
            held_states: Default::default(),
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
            held_states: Default::default(),
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
            held_states: Default::default(),
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
            held_states: Default::default(),
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
            held_states: Default::default(),
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
            held_states: Default::default(),
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
            held_states: Default::default(),
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
                held_states: Default::default(),
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
                held_states: Default::default(),
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
                held_states: Default::default(),
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
                held_states: Default::default(),
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
                held_states: Default::default(),
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
                held_states: Default::default(),
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
            held_states: Default::default(),
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
                held_states: Default::default(),
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
                held_states: Default::default(),
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

    // -- the held-state opt-in -----------------------------------------------

    fn opt_in(states: &[HeldState]) -> BTreeSet<HeldState> {
        states.iter().copied().collect()
    }

    /// An opt-in with a positive age bound on the only branch replays.
    #[test]
    fn an_age_bounded_opt_in_replays() {
        let id = Uuid::from_u128(11);
        let policy = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
            id,
            name: "collect-rejected-after-90d".into(),
            predicate: PolicyPredicate::AgeExceeds(90 * 86_400),
            scope: RetentionScope::AllRepos,
            held_states: opt_in(&[HeldState::Rejected]),
            created_at: ts(1_000),
        }])
        .expect("an age-bounded opt-in is valid");
        assert_eq!(policy.held_states, opt_in(&[HeldState::Rejected]));
    }

    /// The default is no opt-in, so every policy that does not say
    /// otherwise — including every policy already deployed — leaves
    /// every gate shut.
    #[test]
    fn the_default_opt_in_is_empty() {
        let id = Uuid::from_u128(12);
        let policy = RetentionPolicy::project(&[created(id)]).expect("valid");
        assert!(policy.held_states.is_empty());
    }

    /// An opt-in whose predicate has an unbounded successful branch is
    /// refused **at replay**, not only at apply. The decisive shape is
    /// the `Or` whose other arm matches immediately.
    #[test]
    fn an_unbounded_opt_in_is_refused_at_replay() {
        let id = Uuid::from_u128(13);
        let err = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
            id,
            name: "collect-rejected".into(),
            predicate: PolicyPredicate::Composite(
                BooleanOp::Or,
                vec![
                    PolicyPredicate::AgeExceeds(90 * 86_400),
                    PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
                ],
            ),
            scope: RetentionScope::AllRepos,
            held_states: opt_in(&[HeldState::Rejected]),
            created_at: ts(1_000),
        }])
        .expect_err("an unbounded opt-in must not replay");
        match err {
            DomainError::Validation(msg) => {
                assert!(msg.contains("held states"), "msg = {msg}");
                assert!(msg.contains("AgeExceeds"), "msg = {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    /// The same predicate is fine with **no** opt-in: the invariant is
    /// the opt-in's, not the predicate's. A policy expiring released
    /// artifacts on a severity match is an existing, supported shape and
    /// this change must not have outlawed it.
    #[test]
    fn an_unbounded_predicate_without_an_opt_in_still_replays() {
        let id = Uuid::from_u128(14);
        RetentionPolicy::project(&[RetentionPolicyEvent::Created {
            id,
            name: "expire-severe".into(),
            predicate: PolicyPredicate::Composite(
                BooleanOp::Or,
                vec![
                    PolicyPredicate::AgeExceeds(90 * 86_400),
                    PolicyPredicate::HasFindingAboveSeverity(SeverityThreshold::High),
                ],
            ),
            scope: RetentionScope::AllRepos,
            held_states: BTreeSet::new(),
            created_at: ts(1_000),
        }])
        .expect("no opt-in, no held-state invariant");
    }

    /// An `Updated` re-states the opt-in wholesale, and an update that
    /// names no state **clears** it — the direction that cannot widen
    /// an exception past what the YAML says.
    #[test]
    fn an_update_restates_the_opt_in_and_an_omission_clears_it() {
        let id = Uuid::from_u128(15);
        let mut policy = RetentionPolicy::project(&[RetentionPolicyEvent::Created {
            id,
            name: "collect-held".into(),
            predicate: PolicyPredicate::AgeExceeds(90 * 86_400),
            scope: RetentionScope::AllRepos,
            held_states: opt_in(&[HeldState::Rejected, HeldState::ScanIndeterminate]),
            created_at: ts(1_000),
        }])
        .expect("valid");
        assert_eq!(policy.held_states.len(), 2);

        policy
            .apply_appended(&RetentionPolicyEvent::Updated {
                id,
                predicate: PolicyPredicate::AgeExceeds(90 * 86_400),
                scope: RetentionScope::AllRepos,
                held_states: BTreeSet::new(),
                updated_at: ts(2_000),
            })
            .expect("clearing the opt-in is valid");
        assert!(policy.held_states.is_empty());
    }

    /// An `Updated` that opts in while replacing the predicate with an
    /// unbounded one is refused — the invariant is re-checked on the
    /// pair, not only when the policy is created.
    #[test]
    fn an_update_to_an_unbounded_opt_in_is_refused() {
        let id = Uuid::from_u128(16);
        let mut policy = RetentionPolicy::project(&[created(id)]).expect("valid");
        let err = policy
            .apply_appended(&RetentionPolicyEvent::Updated {
                id,
                predicate: PolicyPredicate::HasFixAvailable,
                scope: RetentionScope::AllRepos,
                held_states: opt_in(&[HeldState::Quarantined]),
                updated_at: ts(2_000),
            })
            .expect_err("an unbounded opt-in must not apply");
        assert!(matches!(err, DomainError::Validation(_)));
    }

    /// A pre-change stream decodes as carrying no opt-in: the event's
    /// `held_states` is `#[serde(default)]`, and that is what lets this
    /// field ship without a rewrite of the existing policy streams.
    #[test]
    fn a_legacy_created_payload_decodes_with_no_opt_in() {
        let legacy = serde_json::json!({
            "Created": {
                "id": "00000000-0000-4000-8000-000000000001",
                "name": "retain-30d",
                "predicate": { "AgeExceeds": 2_592_000 },
                "scope": "AllRepos",
                "created_at": "2026-01-01T00:00:00Z"
            }
        });
        let event: RetentionPolicyEvent =
            serde_json::from_value(legacy).expect("a pre-change payload decodes");
        match event {
            RetentionPolicyEvent::Created { held_states, .. } => assert!(held_states.is_empty()),
            other => panic!("expected Created, got {}", variant_name(&other)),
        }
    }

    /// The opt-in survives the round trip the projection and the event
    /// store both depend on, as a JSON array of state names.
    #[test]
    fn the_opt_in_round_trips_through_serde() {
        let states = opt_in(&[HeldState::Rejected, HeldState::Quarantined]);
        let json = serde_json::to_value(&states).expect("serialises");
        // `BTreeSet` orders by the enum's declaration order, so
        // `Quarantined` precedes `Rejected` — deterministic, which is
        // what a JSONB column written on every apply needs.
        assert_eq!(json, serde_json::json!(["Quarantined", "Rejected"]));
        assert_eq!(
            serde_json::from_value::<BTreeSet<HeldState>>(json).expect("deserialises"),
            states
        );
    }
}
