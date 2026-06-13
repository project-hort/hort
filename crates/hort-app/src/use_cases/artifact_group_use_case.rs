//! Artifact-group write-path use case.
//!
//! Orchestrates [`ArtifactGroupRepository`] (read) +
//! [`ArtifactGroupLifecyclePort`] (atomic write). See
//! `docs/architecture/explanation/domain-model.md` for the refs/groups
//! model.
//!
//! # Concurrency model — three decisions the use case owns
//!
//! 1. **Read-then-emit with adapter-authoritative race surface.** The
//!    use case reads `find_by_coords` to decide whether to build a
//!    first-placement batch (with `ArtifactGroupInitiated`) or an
//!    append-to-existing batch. The adapter validates that decision
//!    under a transaction: on a concurrent-create race it rolls back
//!    entirely and returns `Ok(GroupAlreadyExists { existing_id })`.
//!    The use case's lookup is an optimisation; correctness lives in
//!    the adapter.
//!
//! 2. **Bounded single retry.** On a first-attempt `GroupAlreadyExists`
//!    the use case re-fetches via `find_by_coords` to pick up the
//!    winner's `primary_role`, rebuilds a fresh event batch scoped to
//!    the observed `existing_id`, and calls the port again. A second
//!    `GroupAlreadyExists` means the adapter lied (returned
//!    `AlreadyExists` after reporting `Committed` for the same
//!    group) — it is a [`DomainError::Invariant`], not another retry.
//!    This bound is non-negotiable: an unbounded retry masks adapter
//!    bugs.
//!
//! 3. **Primary-role race is an unrecoverable conflict.** When two
//!    callers race to fix the same group's `primary_role`, the
//!    adapter's conditional `UPDATE ... WHERE primary_role = ''`
//!    lets exactly one win; the loser's whole transaction (member
//!    INSERT included) rolls back and surfaces as
//!    `DomainError::Conflict`. The use case does NOT retry with
//!    `is_primary = false` automatically — the caller chose a
//!    privileged role and needs to know the assignment didn't stick.
//!
//! # Event payload integrity
//!
//! The use case is the SOLE constructor of `DomainEvent` payloads on
//! this path. The adapter is forbidden from mutating payloads
//! (§2.6a). On retry the use case builds new events against the
//! observed `existing_id`; it never patches the prior batch.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use hort_domain::entities::artifact_group::{ArtifactGroup, ArtifactGroupMember};
use hort_domain::error::DomainError;
use hort_domain::events::{
    Actor, ArtifactGroupInitiated, ArtifactGroupMemberAdded, ArtifactGroupMemberRemoved,
    ArtifactGroupPrimaryRoleAssigned, DomainEvent, StreamId,
};
use hort_domain::ports::artifact_group_lifecycle::{
    ArtifactGroupLifecyclePort, GroupCommitOutcome, GroupMemberCommit,
};
use hort_domain::ports::artifact_group_repository::ArtifactGroupRepository;
use hort_domain::ports::event_store::{AppendEvents, EventToAppend, ExpectedVersion};
use hort_domain::types::{ArtifactCoords, StringPage};

use crate::error::AppResult;
use crate::metrics::{
    emit_artifact_group_created, emit_artifact_group_member_added, values, GroupMemberRole,
};

/// Default `n` substituted when the caller passes `0` (unspecified
/// `?n=` on OCI `_catalog` / `tags/list`). Matches OCI client defaults.
const DEFAULT_CATALOG_LIMIT: u32 = 100;
/// Hard ceiling mirroring `PageRequest::MAX_LIMIT`. Keeps a single
/// `_catalog` request from running an unbounded DISTINCT scan.
const MAX_CATALOG_LIMIT: u32 = 1000;

fn effective_catalog_limit(n: u32) -> u32 {
    let base = if n == 0 { DEFAULT_CATALOG_LIMIT } else { n };
    base.clamp(1, MAX_CATALOG_LIMIT)
}

/// Application-layer use case for the `ArtifactGroup` write path.
///
/// Two write methods and three read-throughs:
/// - [`add_member`](Self::add_member) — create group (if missing) +
///   attach member; handles the concurrent-create retry loop.
/// - [`remove_member`](Self::remove_member) — detach a member from a
///   group. Propagates `NotFound` without a retry.
/// - [`find_by_coords`](Self::find_by_coords),
///   [`find_by_member`](Self::find_by_member),
///   [`list_distinct_names`](Self::list_distinct_names) — read-through
///   delegates to the registry port.
pub struct ArtifactGroupUseCase {
    groups: Arc<dyn ArtifactGroupRepository>,
    lifecycle: Arc<dyn ArtifactGroupLifecyclePort>,
    include_repository_label: bool,
}

impl ArtifactGroupUseCase {
    pub fn new(
        groups: Arc<dyn ArtifactGroupRepository>,
        lifecycle: Arc<dyn ArtifactGroupLifecyclePort>,
        include_repository_label: bool,
    ) -> Self {
        Self {
            groups,
            lifecycle,
            include_repository_label,
        }
    }

    /// Resolve the `repository` metric label, honouring the
    /// cardinality safety valve. Mirrors `RefUseCase::repo_label`.
    fn repo_label(&self, repo_key: Option<&str>) -> String {
        if !self.include_repository_label {
            values::REPOSITORY_ALL.to_string()
        } else {
            repo_key.unwrap_or(values::REPOSITORY_UNKNOWN).to_string()
        }
    }

    // -----------------------------------------------------------------
    // Write path
    // -----------------------------------------------------------------

    /// Attach an artifact to a group, creating the group if this is
    /// the first member.
    ///
    /// The caller passes:
    /// - `repo` — the repository the group belongs to.
    /// - `group_coords` — canonical coords (identity fields only;
    ///   `path` empty, `metadata` null). The adapter canonicalises
    ///   again as a defence-in-depth, but the use case expects
    ///   well-formed input.
    /// - `role` — the format-defined role for this member (`"pom"`,
    ///   `"jar"`, `"layer"`, etc.). Used for both event payloads and
    ///   the `role` metric label.
    /// - `artifact_id` — foreign key into the `artifacts` table.
    /// - `is_primary` — whether this member should be the group's
    ///   `primary_role`. On a freshly-created group this short-circuits
    ///   into `ArtifactGroupInitiated.primary_role`; on a later join
    ///   it emits `ArtifactGroupPrimaryRoleAssigned` if the slot was
    ///   previously empty, and returns `Conflict` if the existing
    ///   primary is a different role.
    /// - `actor` — the caller's identity (carried into every event).
    /// - `correlation_id` / `causation_id` — event-envelope plumbing.
    /// - `repo_key` / `format_label` — resolved strings for the two
    ///   cardinality-safe metric labels. `format_label` is the
    ///   format's short key (`"maven"`, `"oci"`, etc.); the use case
    ///   does not classify.
    ///
    /// Returns `Ok(())` on success, `DomainError::Conflict` on a
    /// different-role-same-artifact add, on a primary-role mismatch,
    /// or on a primary-assign race, and `DomainError::Invariant` if
    /// the adapter contract is broken (second-attempt
    /// `GroupAlreadyExists`).
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip(self, actor))]
    pub async fn add_member(
        &self,
        repo: Uuid,
        group_coords: ArtifactCoords,
        role: String,
        artifact_id: Uuid,
        is_primary: bool,
        actor: Actor,
        correlation_id: Uuid,
        causation_id: Option<Uuid>,
        repo_key: Option<&str>,
        format_label: &str,
    ) -> AppResult<()> {
        // First attempt — adapter decides first-placement vs append.
        match self
            .try_add_member_first(
                repo,
                &group_coords,
                &role,
                artifact_id,
                is_primary,
                &actor,
                correlation_id,
                causation_id,
                repo_key,
                format_label,
            )
            .await?
        {
            GroupCommitOutcome::Committed => Ok(()),
            GroupCommitOutcome::GroupAlreadyExists { existing_id } => {
                tracing::debug!(
                    existing_id = %existing_id,
                    retry = 1,
                    "concurrent-create observed; retrying against winner's id"
                );
                // Second attempt — rebuild events against the winner's id.
                match self
                    .try_add_member_to_existing(
                        existing_id,
                        repo,
                        &group_coords,
                        &role,
                        artifact_id,
                        is_primary,
                        &actor,
                        correlation_id,
                        causation_id,
                        repo_key,
                        format_label,
                    )
                    .await?
                {
                    GroupCommitOutcome::Committed => Ok(()),
                    GroupCommitOutcome::GroupAlreadyExists { .. } => Err(DomainError::Invariant(
                        "adapter contract broken: second attempt returned GroupAlreadyExists"
                            .into(),
                    )
                    .into()),
                }
            }
        }
    }

    /// Build + dispatch the first-attempt commit. Returns the raw
    /// [`GroupCommitOutcome`] so the caller can decide whether to
    /// retry.
    #[allow(clippy::too_many_arguments)]
    async fn try_add_member_first(
        &self,
        repo: Uuid,
        group_coords: &ArtifactCoords,
        role: &str,
        artifact_id: Uuid,
        is_primary: bool,
        actor: &Actor,
        correlation_id: Uuid,
        causation_id: Option<Uuid>,
        repo_key: Option<&str>,
        format_label: &str,
    ) -> AppResult<GroupCommitOutcome> {
        let existing = self.groups.find_by_coords(repo, group_coords).await?;
        match existing {
            Some(existing_group) => {
                // Group already exists — we will not emit Initiated.
                let primary_role_assigned =
                    Self::decide_primary_role(&existing_group.primary_role, role, is_primary)?;
                let change = GroupMemberCommit {
                    new_group: None,
                    member: ArtifactGroupMember {
                        role: role.to_string(),
                        artifact_id,
                        added_at: Utc::now(),
                    },
                    primary_role_assigned: primary_role_assigned.clone(),
                };
                let batch = Self::build_batch(
                    existing_group.id,
                    repo,
                    None, // no Initiated event — group already exists
                    role,
                    artifact_id,
                    primary_role_assigned,
                    actor.clone(),
                    correlation_id,
                    causation_id,
                );
                let outcome = self.lifecycle.commit_member_added(change, batch).await?;
                // Only emit member-added on Committed — the race-lost
                // path will retry and emit then.
                if matches!(outcome, GroupCommitOutcome::Committed) {
                    Self::emit_member_added_metric(self, repo_key, format_label, role);
                    tracing::debug!(
                        group_id = %existing_group.id,
                        role,
                        "member attached to existing group"
                    );
                }
                Ok(outcome)
            }
            None => {
                // First-placement branch. Mint a fresh group id; the
                // adapter may still observe that a concurrent writer
                // won under the unique index, in which case it returns
                // GroupAlreadyExists.
                let group_id = Uuid::new_v4();
                let now = Utc::now();
                let primary_role = if is_primary {
                    role.to_string()
                } else {
                    String::new()
                };
                let new_group = ArtifactGroup {
                    id: group_id,
                    repository_id: repo,
                    coords: group_coords.clone(),
                    primary_role: primary_role.clone(),
                    members: vec![],
                    created_at: now,
                    updated_at: now,
                };
                let change = GroupMemberCommit {
                    new_group: Some(new_group),
                    member: ArtifactGroupMember {
                        role: role.to_string(),
                        artifact_id,
                        added_at: now,
                    },
                    // First placement carries the primary role in
                    // ArtifactGroupInitiated; NO separate Assigned event.
                    primary_role_assigned: None,
                };
                let batch = Self::build_batch(
                    group_id,
                    repo,
                    Some((group_coords.clone(), primary_role)),
                    role,
                    artifact_id,
                    None, // no PrimaryRoleAssigned — rolled into Initiated
                    actor.clone(),
                    correlation_id,
                    causation_id,
                );
                let outcome = self.lifecycle.commit_member_added(change, batch).await?;
                // On Committed + first-placement emit BOTH counters.
                // The race-lost path emits nothing (the retry does).
                if matches!(outcome, GroupCommitOutcome::Committed) {
                    let repo_label = self.repo_label(repo_key);
                    emit_artifact_group_created(&repo_label, format_label);
                    Self::emit_member_added_metric(self, repo_key, format_label, role);
                    tracing::info!(
                        group_id = %group_id,
                        name = %group_coords.name,
                        version = ?group_coords.version,
                        format = format_label,
                        "artifact group created"
                    );
                }
                Ok(outcome)
            }
        }
    }

    /// Retry path — the first attempt observed a concurrent winner.
    /// Re-fetches `find_by_coords` (to pick up the winner's current
    /// `primary_role`) and rebuilds a fresh batch against the winner's
    /// `existing_id`. The use case never patches the original events;
    /// the adapter MUST NEVER touch them either.
    ///
    /// The caller (`add_member`) threads `group_coords` through so
    /// the re-read hits the same row the adapter observed.
    #[allow(clippy::too_many_arguments)]
    async fn try_add_member_to_existing(
        &self,
        existing_id: Uuid,
        repo: Uuid,
        group_coords: &ArtifactCoords,
        role: &str,
        artifact_id: Uuid,
        is_primary: bool,
        actor: &Actor,
        correlation_id: Uuid,
        causation_id: Option<Uuid>,
        repo_key: Option<&str>,
        format_label: &str,
    ) -> AppResult<GroupCommitOutcome> {
        // Re-read to pick up the winner's `primary_role`. A stale
        // read (winner committed after our adapter call but before
        // our re-read) is not a correctness problem — the adapter's
        // primary-role UPDATE is gated on `primary_role = ''` and
        // will surface `Conflict` if the slot was filled in the
        // meantime. The re-read is an optimisation that keeps the
        // common case (no primary yet) fast.
        let observed = self.groups.find_by_coords(repo, group_coords).await?;
        let existing_primary = observed
            .as_ref()
            .map(|g| g.primary_role.as_str())
            .unwrap_or("");
        let primary_role_assigned = Self::decide_primary_role(existing_primary, role, is_primary)?;

        let change = GroupMemberCommit {
            new_group: None,
            member: ArtifactGroupMember {
                role: role.to_string(),
                artifact_id,
                added_at: Utc::now(),
            },
            primary_role_assigned: primary_role_assigned.clone(),
        };
        let batch = Self::build_batch(
            existing_id,
            repo,
            None,
            role,
            artifact_id,
            primary_role_assigned,
            actor.clone(),
            correlation_id,
            causation_id,
        );
        let outcome = self.lifecycle.commit_member_added(change, batch).await?;
        if matches!(outcome, GroupCommitOutcome::Committed) {
            Self::emit_member_added_metric(self, repo_key, format_label, role);
            tracing::debug!(
                group_id = %existing_id,
                role,
                retry = 1,
                "member attached to existing group (retry)"
            );
        }
        Ok(outcome)
    }

    /// Classify `role` into a bounded-cardinality label value and
    /// emit the `hort_artifact_group_members_added_total` counter.
    fn emit_member_added_metric(&self, repo_key: Option<&str>, format_label: &str, role: &str) {
        let repo_label = self.repo_label(repo_key);
        let role_label = GroupMemberRole::classify(role);
        emit_artifact_group_member_added(&repo_label, format_label, role_label);
    }

    /// Decide what to do about `is_primary` given the existing
    /// group's `primary_role`. Returns the role to pass into
    /// `primary_role_assigned`, or surfaces `Conflict` when the
    /// existing primary is a different role. Called for the
    /// `new_group.is_none()` branches (both first-attempt append and
    /// retry).
    fn decide_primary_role(
        existing_primary: &str,
        role: &str,
        is_primary: bool,
    ) -> AppResult<Option<String>> {
        if !is_primary {
            return Ok(None);
        }
        if existing_primary.is_empty() {
            // §2.10 case 2 — claim the empty slot.
            return Ok(Some(role.to_string()));
        }
        if existing_primary == role {
            // Already the primary for this role — nothing to assign.
            // The member add itself may still be a no-op at the
            // adapter (same artifact + same role) or a new member
            // (different artifact same role — OCI layer style).
            return Ok(None);
        }
        // Existing primary is a different role — this call cannot
        // succeed as a primary. The caller is responsible for
        // retrying with is_primary = false.
        Err(DomainError::Conflict(format!(
            "primary role mismatch: existing `{existing_primary}`, requested `{role}`"
        ))
        .into())
    }

    /// Build the `AppendEvents` batch. `initiated` carries the
    /// `(coords, primary_role)` pair when this call creates the group
    /// (first-placement path); `None` otherwise.
    #[allow(clippy::too_many_arguments)]
    fn build_batch(
        group_id: Uuid,
        repo: Uuid,
        initiated: Option<(ArtifactCoords, String)>,
        role: &str,
        artifact_id: Uuid,
        primary_role_assigned: Option<String>,
        actor: Actor,
        correlation_id: Uuid,
        causation_id: Option<Uuid>,
    ) -> AppendEvents {
        let mut events: Vec<EventToAppend> = Vec::with_capacity(3);
        let expected_version = if initiated.is_some() {
            ExpectedVersion::NoStream
        } else {
            ExpectedVersion::Any
        };
        if let Some((coords, primary_role)) = initiated {
            events.push(EventToAppend::new(DomainEvent::ArtifactGroupInitiated(
                ArtifactGroupInitiated {
                    group_id,
                    repository_id: repo,
                    coords,
                    primary_role,
                },
            )));
        }
        events.push(EventToAppend::new(DomainEvent::ArtifactGroupMemberAdded(
            ArtifactGroupMemberAdded {
                group_id,
                role: role.to_string(),
                artifact_id,
            },
        )));
        if let Some(primary_role) = primary_role_assigned {
            events.push(EventToAppend::new(
                DomainEvent::ArtifactGroupPrimaryRoleAssigned(ArtifactGroupPrimaryRoleAssigned {
                    group_id,
                    primary_role,
                }),
            ));
        }
        AppendEvents {
            stream_id: StreamId::artifact_group(group_id),
            expected_version,
            events,
            correlation_id,
            causation_id,
            actor,
        }
    }

    /// Detach an artifact from a group.
    ///
    /// The caller resolves `group_id` via [`find_by_member`](Self::find_by_member)
    /// before invocation. Missing member → `DomainError::NotFound`.
    #[tracing::instrument(skip(self, actor))]
    pub async fn remove_member(
        &self,
        group_id: Uuid,
        artifact_id: Uuid,
        reason: Option<String>,
        actor: Actor,
        correlation_id: Uuid,
        causation_id: Option<Uuid>,
    ) -> AppResult<()> {
        let batch = AppendEvents {
            stream_id: StreamId::artifact_group(group_id),
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(DomainEvent::ArtifactGroupMemberRemoved(
                ArtifactGroupMemberRemoved {
                    group_id,
                    artifact_id,
                    reason,
                },
            ))],
            correlation_id,
            causation_id,
            actor,
        };
        self.lifecycle
            .commit_member_removed(group_id, artifact_id, batch)
            .await?;
        tracing::info!(%group_id, %artifact_id, "group member removed");
        Ok(())
    }

    // -----------------------------------------------------------------
    // Read path
    // -----------------------------------------------------------------

    /// Find a group by canonical coordinates. Thin delegate to the
    /// registry port; kept here so call sites depend on the use case
    /// rather than the port directly.
    #[tracing::instrument(skip(self))]
    pub async fn find_by_coords(
        &self,
        repo: Uuid,
        coords: &ArtifactCoords,
    ) -> AppResult<Option<ArtifactGroup>> {
        Ok(self.groups.find_by_coords(repo, coords).await?)
    }

    /// Reverse lookup: what group contains this artifact?
    #[tracing::instrument(skip(self))]
    pub async fn find_by_member(&self, artifact_id: Uuid) -> AppResult<Option<ArtifactGroup>> {
        Ok(self.groups.find_by_member(artifact_id).await?)
    }

    /// Paginated distinct enumeration of group names by primary role.
    /// Thin wrapper retained for callers that want the raw port list
    /// without `StringPage` saturation detection (projections, tests).
    #[tracing::instrument(skip(self))]
    pub async fn list_distinct_names(
        &self,
        repo: Uuid,
        primary_role: &str,
        after: Option<&str>,
        limit: u32,
    ) -> AppResult<Vec<String>> {
        Ok(self
            .groups
            .list_distinct_names(repo, primary_role, after, limit)
            .await?)
    }

    /// Per-repo catalog of distinct group names — the modern-default
    /// OCI `_catalog` surface (`GET /v2/<repo_key>/_catalog`).
    ///
    /// Wraps [`ArtifactGroupRepository::list_distinct_names`] with the
    /// `StringPage` over-fetch / saturation contract: requests
    /// `limit + 1` rows, truncates to `limit`, flips `saturated` when
    /// a next page exists.
    ///
    /// `n` is clamped to `[1, 1000]`; `n = 0` substitutes
    /// [`DEFAULT_CATALOG_LIMIT`] (100). Return type is a
    /// `StringPage<String>` of unqualified names (`library/nginx`) —
    /// the global-catalog variant qualifies them with the repo key.
    #[tracing::instrument(skip(self))]
    pub async fn list_repo_catalog(
        &self,
        repo: Uuid,
        primary_role: &str,
        after: Option<&str>,
        n: u32,
    ) -> AppResult<StringPage<String>> {
        let limit = effective_catalog_limit(n);
        let over = self
            .groups
            .list_distinct_names(repo, primary_role, after, limit + 1)
            .await?;
        Ok(StringPage::from_overfetch(over, limit as usize))
    }

    /// Global catalog — the Docker-legacy
    /// `GET /v2/_catalog` surface. Produces `<repo_key>/<group_name>`
    /// qualified names across a caller-supplied set of visible repos.
    ///
    /// **Visibility is the caller's responsibility.** The handler
    /// layer decides which repos the current principal can read
    /// (`RbacEvaluator::authorize` + public-repo predicate) and hands
    /// the `(repo_id, repo_key)` list down to this method. The use
    /// case does not touch auth — it stays format-agnostic and
    /// principal-agnostic.
    ///
    /// **Cursor semantics.** The cursor is applied to the qualified
    /// name (`<repo_key>/<group_name>`), since that's what the client
    /// sees and walks. Across N visible repos the use case queries
    /// each repo with `after = None` (the per-repo cursor doesn't
    /// translate cleanly to qualified-name cursors), collects all
    /// results, filters by `> after` on the qualified name, sorts
    /// byte-stably, and over-fetches `limit + 1`. This is O(total
    /// distinct names across visible repos) per request — acceptable
    /// for Phase 1 scale; a later phase that needs better scaling
    /// adds a cross-repo `list_distinct_names_paginated` port variant.
    #[tracing::instrument(skip(self, visible_repos))]
    pub async fn list_global_catalog(
        &self,
        visible_repos: &[(Uuid, String)],
        primary_role: &str,
        after: Option<&str>,
        n: u32,
    ) -> AppResult<StringPage<String>> {
        let limit = effective_catalog_limit(n) as usize;
        let mut qualified: Vec<String> = Vec::new();
        for (repo_id, repo_key) in visible_repos {
            let names = self
                .groups
                .list_distinct_names(*repo_id, primary_role, None, MAX_CATALOG_LIMIT)
                .await?;
            for name in names {
                qualified.push(format!("{repo_key}/{name}"));
            }
        }
        qualified.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let filtered: Vec<String> = match after {
            Some(cursor) => qualified
                .into_iter()
                .filter(|q| q.as_bytes() > cursor.as_bytes())
                .take(limit + 1)
                .collect(),
            None => qualified.into_iter().take(limit + 1).collect(),
        };
        Ok(StringPage::from_overfetch(filtered, limit))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use hort_domain::entities::repository::RepositoryFormat;
    use hort_domain::events::{Actor, ApiActor};

    use crate::metrics::capture_metrics;
    use crate::use_cases::test_support::{
        GroupCommitInjection, MockArtifactGroupLifecyclePort, MockArtifactGroupRepository,
    };

    fn actor() -> Actor {
        Actor::Api(ApiActor {
            user_id: Uuid::new_v4(),
        })
    }

    fn maven_coords(name: &str, version: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: name.into(),
            name_as_published: name.into(),
            version: Some(version.into()),
            path: String::new(),
            format: RepositoryFormat::Maven,
            metadata: serde_json::Value::Null,
        }
    }

    fn build() -> (
        Arc<MockArtifactGroupRepository>,
        Arc<MockArtifactGroupLifecyclePort>,
        ArtifactGroupUseCase,
    ) {
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let uc = ArtifactGroupUseCase::new(groups.clone(), lifecycle.clone(), true);
        (groups, lifecycle, uc)
    }

    // ----- decide_primary_role covers every branch -----------------------

    #[test]
    fn decide_primary_role_non_primary_is_none() {
        let got = ArtifactGroupUseCase::decide_primary_role("pom", "jar", false).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn decide_primary_role_empty_slot_claims() {
        let got = ArtifactGroupUseCase::decide_primary_role("", "jar", true).unwrap();
        assert_eq!(got, Some("jar".into()));
    }

    #[test]
    fn decide_primary_role_same_role_is_none() {
        let got = ArtifactGroupUseCase::decide_primary_role("pom", "pom", true).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn decide_primary_role_mismatch_is_conflict() {
        let err = ArtifactGroupUseCase::decide_primary_role("pom", "jar", true).unwrap_err();
        match err {
            crate::error::AppError::Domain(DomainError::Conflict(msg)) => {
                assert!(msg.contains("primary role mismatch"), "got: {msg}");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    // ----- add_member happy paths ---------------------------------------

    #[tokio::test]
    async fn add_member_creates_group_on_first_call() {
        let (_groups, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let coords = maven_coords("com.example:widget", "1.2.3");
        let artifact_id = Uuid::new_v4();

        uc.add_member(
            repo,
            coords.clone(),
            "jar".into(),
            artifact_id,
            true,
            actor(),
            Uuid::new_v4(),
            None,
            Some("my-repo"),
            "maven",
        )
        .await
        .unwrap();

        assert_eq!(lifecycle.commit_call_count(), 1);
        let commits = lifecycle.recorded_commits();
        assert_eq!(commits.len(), 1);
        let c = &commits[0];
        assert!(c.new_group_id.is_some(), "first call must create group");
        assert_eq!(c.member_role, "jar");
        assert_eq!(c.member_artifact_id, artifact_id);
        assert!(c.primary_role_assigned.is_none());
        // Batch: expected_version NoStream, two events (Initiated + MemberAdded).
        assert_eq!(c.batch.expected_version, ExpectedVersion::NoStream);
        assert_eq!(c.batch.events.len(), 2);
        assert!(matches!(
            c.batch.events[0].event,
            DomainEvent::ArtifactGroupInitiated(_)
        ));
        assert!(matches!(
            c.batch.events[1].event,
            DomainEvent::ArtifactGroupMemberAdded(_)
        ));
    }

    #[tokio::test]
    async fn add_member_first_placement_non_primary_leaves_primary_role_empty() {
        // When the first member is NOT primary, the group is created
        // with `primary_role = ""` (§2.10 case 2 seed). A later
        // member with `is_primary = true` claims the slot via
        // `ArtifactGroupPrimaryRoleAssigned`.
        let (_groups, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let coords = maven_coords("com.example:widget", "1.2.3");
        uc.add_member(
            repo,
            coords,
            "sources".into(),
            Uuid::new_v4(),
            false, // non-primary first member
            actor(),
            Uuid::new_v4(),
            None,
            Some("my-repo"),
            "maven",
        )
        .await
        .unwrap();

        let c = &lifecycle.recorded_commits()[0];
        let init_payload = c
            .batch
            .events
            .iter()
            .find_map(|e| match &e.event {
                DomainEvent::ArtifactGroupInitiated(i) => Some(i),
                _ => None,
            })
            .expect("Initiated fired");
        assert_eq!(
            init_payload.primary_role, "",
            "non-primary first member leaves slot empty"
        );
    }

    #[tokio::test]
    async fn add_member_to_existing_group_emits_member_added_only() {
        let (groups, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let coords = maven_coords("com.example:widget", "1.2.3");
        let existing_id = Uuid::new_v4();
        groups.insert(ArtifactGroup {
            id: existing_id,
            repository_id: repo,
            coords: coords.clone(),
            primary_role: "jar".into(),
            members: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        uc.add_member(
            repo,
            coords,
            "pom".into(),
            Uuid::new_v4(),
            false,
            actor(),
            Uuid::new_v4(),
            None,
            None,
            "maven",
        )
        .await
        .unwrap();

        assert_eq!(lifecycle.commit_call_count(), 1);
        let c = &lifecycle.recorded_commits()[0];
        assert!(c.new_group_id.is_none(), "existing group = no Initiated");
        assert_eq!(c.batch.expected_version, ExpectedVersion::Any);
        assert_eq!(c.batch.events.len(), 1);
        assert!(matches!(
            c.batch.events[0].event,
            DomainEvent::ArtifactGroupMemberAdded(_)
        ));
    }

    #[tokio::test]
    async fn add_member_primary_role_assigned_on_empty_slot() {
        // §2.10 case 2: group created non-primary, later member
        // claims the primary slot.
        let (groups, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let coords = maven_coords("com.example:widget", "1.2.3");
        let existing_id = Uuid::new_v4();
        groups.insert(ArtifactGroup {
            id: existing_id,
            repository_id: repo,
            coords: coords.clone(),
            primary_role: String::new(),
            members: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        uc.add_member(
            repo,
            coords,
            "jar".into(),
            Uuid::new_v4(),
            true,
            actor(),
            Uuid::new_v4(),
            None,
            None,
            "maven",
        )
        .await
        .unwrap();

        let c = &lifecycle.recorded_commits()[0];
        assert_eq!(c.primary_role_assigned.as_deref(), Some("jar"));
        assert_eq!(c.batch.events.len(), 2);
        assert!(matches!(
            c.batch.events[1].event,
            DomainEvent::ArtifactGroupPrimaryRoleAssigned(_)
        ));
    }

    #[tokio::test]
    async fn add_member_primary_role_mismatch_is_conflict_without_port_call() {
        let (groups, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let coords = maven_coords("com.example:widget", "1.2.3");
        groups.insert(ArtifactGroup {
            id: Uuid::new_v4(),
            repository_id: repo,
            coords: coords.clone(),
            primary_role: "pom".into(),
            members: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        let err = uc
            .add_member(
                repo,
                coords,
                "jar".into(),
                Uuid::new_v4(),
                true,
                actor(),
                Uuid::new_v4(),
                None,
                None,
                "maven",
            )
            .await
            .unwrap_err();
        match err {
            crate::error::AppError::Domain(DomainError::Conflict(_)) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }
        // Absolutely NO port call — mismatch is detected at the
        // read-side. A bug here (e.g. emitting a Conflict after the
        // port fired) would show up as commit_call_count > 0.
        assert_eq!(lifecycle.commit_call_count(), 0);
    }

    // ----- Concurrent-create retry: one GroupAlreadyExists then Committed ---

    #[tokio::test]
    async fn add_member_retries_on_group_already_exists() {
        let (groups, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let coords = maven_coords("com.example:widget", "1.2.3");
        // First call: adapter observes concurrent winner with id = winner_id.
        let winner_id = Uuid::new_v4();
        // Simulate the winner having already seeded the group in the
        // registry (real adapter would have committed the winner's
        // transaction).
        groups.insert(ArtifactGroup {
            id: winner_id,
            repository_id: repo,
            coords: coords.clone(),
            primary_role: "jar".into(),
            members: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        lifecycle.inject(GroupCommitInjection::AlreadyExists {
            existing_id: winner_id,
        });

        uc.add_member(
            repo,
            coords.clone(),
            "pom".into(),
            Uuid::new_v4(),
            false,
            actor(),
            Uuid::new_v4(),
            None,
            None,
            "maven",
        )
        .await
        .unwrap();

        // Exactly TWO lifecycle calls — the injected AlreadyExists
        // and the retry Committed.
        assert_eq!(lifecycle.commit_call_count(), 2);
        // The second call targets `winner_id` with fresh events (no
        // Initiated; just MemberAdded).
        let commits = lifecycle.recorded_commits();
        assert_eq!(
            commits.len(),
            1,
            "injected call did NOT record (injection short-circuits)"
        );
        let c = &commits[0];
        assert_eq!(c.batch.stream_id.entity_id, winner_id);
        assert_eq!(c.batch.expected_version, ExpectedVersion::Any);
        assert_eq!(c.batch.events.len(), 1);
        assert!(matches!(
            c.batch.events[0].event,
            DomainEvent::ArtifactGroupMemberAdded(_)
        ));
    }

    #[tokio::test]
    async fn add_member_second_already_exists_is_invariant() {
        let (groups, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let coords = maven_coords("com.example:widget", "1.2.3");
        let winner_id = Uuid::new_v4();
        groups.insert(ArtifactGroup {
            id: winner_id,
            repository_id: repo,
            coords: coords.clone(),
            primary_role: "jar".into(),
            members: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        // Both injected calls return AlreadyExists — simulates an
        // adapter that lies.
        lifecycle.inject(GroupCommitInjection::AlreadyExists {
            existing_id: winner_id,
        });
        lifecycle.inject(GroupCommitInjection::AlreadyExists {
            existing_id: winner_id,
        });

        let err = uc
            .add_member(
                repo,
                coords,
                "pom".into(),
                Uuid::new_v4(),
                false,
                actor(),
                Uuid::new_v4(),
                None,
                None,
                "maven",
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::AppError::Domain(DomainError::Invariant(_))
            ),
            "got: {err}"
        );
        assert_eq!(lifecycle.commit_call_count(), 2);
    }

    // ----- Idempotent same-role add — adapter is responsible; the use
    // case's job here is to ensure it builds the right batch. The
    // adapter's "same role = no events" short-circuit is covered in
    // the adapter's integration tests.
    //
    // Here we just assert: when find_by_coords shows an existing
    // group and we call add_member with a previously-seen member, the
    // use case DOES still invoke the port (the adapter decides what
    // to do). That's the correct division of responsibility.
    #[tokio::test]
    async fn add_member_same_role_still_calls_port_for_adapter_to_decide() {
        let (groups, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let coords = maven_coords("com.example:widget", "1.2.3");
        let artifact_id = Uuid::new_v4();
        let existing_id = Uuid::new_v4();
        groups.insert(ArtifactGroup {
            id: existing_id,
            repository_id: repo,
            coords: coords.clone(),
            primary_role: "jar".into(),
            members: vec![ArtifactGroupMember {
                role: "jar".into(),
                artifact_id,
                added_at: Utc::now(),
            }],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        uc.add_member(
            repo,
            coords,
            "jar".into(),
            artifact_id,
            false,
            actor(),
            Uuid::new_v4(),
            None,
            None,
            "maven",
        )
        .await
        .unwrap();
        assert_eq!(
            lifecycle.commit_call_count(),
            1,
            "use case always delegates; adapter decides no-op"
        );
    }

    // ----- Metrics ------------------------------------------------------

    #[test]
    fn add_member_first_placement_emits_both_metrics() {
        let (_groups, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let coords = maven_coords("com.example:widget", "1.2.3");

        let snap = capture_metrics(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                uc.add_member(
                    repo,
                    coords,
                    "jar".into(),
                    Uuid::new_v4(),
                    true,
                    actor(),
                    Uuid::new_v4(),
                    None,
                    Some("my-repo"),
                    "maven",
                )
                .await
                .unwrap();
            });
        });
        let entries = snap.into_vec();
        // Created counter.
        let (key_c, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_artifact_groups_created_total")
            .expect("groups_created must fire");
        let labels_c: std::collections::HashMap<&str, &str> =
            key_c.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels_c.get("repository"), Some(&"my-repo"));
        assert_eq!(labels_c.get("format"), Some(&"maven"));
        // Member-added counter.
        let (key_m, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_artifact_group_members_added_total")
            .expect("members_added must fire");
        let labels_m: std::collections::HashMap<&str, &str> =
            key_m.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels_m.get("role"), Some(&"jar"));
    }

    #[test]
    fn add_member_to_existing_emits_only_member_added() {
        let (groups, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let coords = maven_coords("com.example:widget", "1.2.3");
        groups.insert(ArtifactGroup {
            id: Uuid::new_v4(),
            repository_id: repo,
            coords: coords.clone(),
            primary_role: "jar".into(),
            members: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        let snap = capture_metrics(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                uc.add_member(
                    repo,
                    coords,
                    "pom".into(),
                    Uuid::new_v4(),
                    false,
                    actor(),
                    Uuid::new_v4(),
                    None,
                    Some("my-repo"),
                    "maven",
                )
                .await
                .unwrap();
            });
        });
        let entries = snap.into_vec();
        let found_created = entries
            .iter()
            .any(|(k, _, _, _)| k.key().name() == "hort_artifact_groups_created_total");
        assert!(
            !found_created,
            "no ArtifactGroupInitiated = no groups_created metric"
        );
        let found_member = entries
            .iter()
            .any(|(k, _, _, _)| k.key().name() == "hort_artifact_group_members_added_total");
        assert!(found_member, "member add metric must fire");
    }

    // ----- remove_member ------------------------------------------------

    #[tokio::test]
    async fn remove_member_calls_port_with_event_batch() {
        let (_groups, lifecycle, uc) = build();
        let group_id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();

        uc.remove_member(
            group_id,
            artifact_id,
            Some("admin correction".into()),
            actor(),
            Uuid::new_v4(),
            None,
        )
        .await
        .unwrap();

        assert_eq!(lifecycle.remove_call_count(), 1);
        let removes = lifecycle.recorded_removes();
        assert_eq!(removes.len(), 1);
        let (r_gid, r_aid, batch) = &removes[0];
        assert_eq!(*r_gid, group_id);
        assert_eq!(*r_aid, artifact_id);
        assert_eq!(batch.stream_id.entity_id, group_id);
        assert_eq!(batch.events.len(), 1);
        match &batch.events[0].event {
            DomainEvent::ArtifactGroupMemberRemoved(e) => {
                assert_eq!(e.group_id, group_id);
                assert_eq!(e.artifact_id, artifact_id);
                assert_eq!(e.reason.as_deref(), Some("admin correction"));
            }
            other => panic!("expected MemberRemoved, got {other:?}"),
        }
    }

    // ----- Read-throughs -----------------------------------------------

    #[tokio::test]
    async fn find_by_coords_delegates_to_port() {
        let (groups, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let coords = maven_coords("com.example:widget", "1.2.3");
        let gid = Uuid::new_v4();
        groups.insert(ArtifactGroup {
            id: gid,
            repository_id: repo,
            coords: coords.clone(),
            primary_role: "jar".into(),
            members: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        let got = uc.find_by_coords(repo, &coords).await.unwrap();
        assert_eq!(got.unwrap().id, gid);
    }

    #[tokio::test]
    async fn find_by_member_delegates_to_port() {
        let (groups, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let gid = Uuid::new_v4();
        let aid = Uuid::new_v4();
        groups.insert(ArtifactGroup {
            id: gid,
            repository_id: repo,
            coords: maven_coords("n", "v"),
            primary_role: "jar".into(),
            members: vec![ArtifactGroupMember {
                role: "jar".into(),
                artifact_id: aid,
                added_at: Utc::now(),
            }],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        let got = uc.find_by_member(aid).await.unwrap();
        assert_eq!(got.unwrap().id, gid);
    }

    #[tokio::test]
    async fn list_distinct_names_delegates_to_port() {
        let (groups, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        for (n, role) in [
            ("alpha", "manifest"),
            ("Beta", "manifest"),
            ("gamma", "jar"),
        ] {
            groups.insert(ArtifactGroup {
                id: Uuid::new_v4(),
                repository_id: repo,
                coords: maven_coords(n, "1"),
                primary_role: role.into(),
                members: vec![],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
        }
        let got = uc
            .list_distinct_names(repo, "manifest", None, 10)
            .await
            .unwrap();
        assert_eq!(got, vec!["Beta".to_string(), "alpha".to_string()]);
    }

    // ----- Repository-label sentinel -----------------------------------

    #[tokio::test]
    async fn repo_label_disabled_emits_all_sentinel() {
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let uc = ArtifactGroupUseCase::new(groups, lifecycle, false);
        assert_eq!(uc.repo_label(Some("ignored")), "_all");
    }

    #[tokio::test]
    async fn repo_label_unknown_when_none() {
        let (_groups, _lifecycle, uc) = build();
        assert_eq!(uc.repo_label(None), "unknown");
    }

    // -----------------------------------------------------------------
    // list_repo_catalog + list_global_catalog (OCI `_catalog` surfaces)
    // -----------------------------------------------------------------

    /// Seed a group so its `coords.name` shows up in
    /// `list_distinct_names(repo, primary_role, ...)`.
    fn seed_group(
        groups: &MockArtifactGroupRepository,
        repo_id: Uuid,
        name: &str,
        primary_role: &str,
    ) {
        let coords = ArtifactCoords {
            name: name.into(),
            name_as_published: name.into(),
            version: Some("sha256:abc".into()),
            path: String::new(),
            format: RepositoryFormat::Oci,
            metadata: serde_json::Value::Null,
        };
        let g = ArtifactGroup {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            coords,
            primary_role: primary_role.into(),
            members: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        groups.insert(g);
    }

    #[tokio::test]
    async fn list_repo_catalog_returns_distinct_names_non_saturated() {
        let (groups, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        seed_group(&groups, repo, "a", "manifest");
        seed_group(&groups, repo, "b", "manifest");
        seed_group(&groups, repo, "c", "manifest");

        let page = uc
            .list_repo_catalog(repo, "manifest", None, 10)
            .await
            .unwrap();
        assert_eq!(page.items, vec!["a".to_string(), "b".into(), "c".into()]);
        assert!(!page.saturated, "3 items with limit 10 not saturated");
    }

    #[tokio::test]
    async fn list_repo_catalog_saturates_on_over_fetch() {
        let (groups, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        for name in ["a", "b", "c", "d"] {
            seed_group(&groups, repo, name, "manifest");
        }

        // limit=2 → returns [a, b], saturated=true (c exists).
        let page = uc
            .list_repo_catalog(repo, "manifest", None, 2)
            .await
            .unwrap();
        assert_eq!(page.items, vec!["a".to_string(), "b".into()]);
        assert!(page.saturated);
    }

    #[tokio::test]
    async fn list_repo_catalog_filters_by_primary_role() {
        let (groups, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        seed_group(&groups, repo, "a", "manifest");
        seed_group(&groups, repo, "b", "config");
        seed_group(&groups, repo, "c", "manifest");

        let page = uc
            .list_repo_catalog(repo, "manifest", None, 10)
            .await
            .unwrap();
        assert_eq!(page.items, vec!["a".to_string(), "c".into()]);
    }

    #[tokio::test]
    async fn list_global_catalog_qualifies_names_with_repo_key() {
        let (groups, _lifecycle, uc) = build();
        let r1 = Uuid::new_v4();
        let r2 = Uuid::new_v4();
        seed_group(&groups, r1, "nginx", "manifest");
        seed_group(&groups, r2, "alpine", "manifest");

        let visible = vec![(r1, "myrepo".to_string()), (r2, "mirror".to_string())];
        let page = uc
            .list_global_catalog(&visible, "manifest", None, 10)
            .await
            .unwrap();

        // Qualified, byte-sorted.
        assert_eq!(
            page.items,
            vec!["mirror/alpine".to_string(), "myrepo/nginx".into()]
        );
        assert!(!page.saturated);
    }

    #[tokio::test]
    async fn list_global_catalog_honours_visibility_exclusion() {
        // Groups exist in BOTH repos; handler only marks r1 as visible.
        // r2's contents MUST NOT appear in the page.
        let (groups, _lifecycle, uc) = build();
        let r1 = Uuid::new_v4();
        let r2 = Uuid::new_v4();
        seed_group(&groups, r1, "nginx", "manifest");
        seed_group(&groups, r2, "private-image", "manifest");

        let visible = vec![(r1, "myrepo".to_string())]; // r2 excluded
        let page = uc
            .list_global_catalog(&visible, "manifest", None, 10)
            .await
            .unwrap();

        assert_eq!(page.items, vec!["myrepo/nginx".to_string()]);
        // Load-bearing: a private-image in r2 stays invisible even
        // though the adapter could return it. Visibility is the
        // handler's concern; the use case trusts the caller's list.
        assert!(
            !page.items.iter().any(|n| n.contains("private-image")),
            "visibility-excluded repo leaked into global catalog"
        );
    }

    #[tokio::test]
    async fn list_global_catalog_cursor_applies_to_qualified_name() {
        // Cursor is `myrepo/n` — the qualified form, not the raw
        // group name. Must exclude `mirror/alpine` (less) and include
        // everything strictly greater.
        let (groups, _lifecycle, uc) = build();
        let r1 = Uuid::new_v4();
        let r2 = Uuid::new_v4();
        seed_group(&groups, r1, "nginx", "manifest");
        seed_group(&groups, r2, "alpine", "manifest");

        let visible = vec![(r1, "myrepo".into()), (r2, "mirror".into())];
        let page = uc
            .list_global_catalog(&visible, "manifest", Some("mirror/alpine"), 10)
            .await
            .unwrap();

        assert_eq!(page.items, vec!["myrepo/nginx".to_string()]);
    }

    #[tokio::test]
    async fn list_global_catalog_empty_visible_set_returns_empty() {
        let (_groups, _lifecycle, uc) = build();
        let page = uc
            .list_global_catalog(&[], "manifest", None, 10)
            .await
            .unwrap();
        assert!(page.is_empty());
        assert!(!page.saturated);
    }

    #[tokio::test]
    async fn list_repo_catalog_limit_zero_substitutes_default() {
        // `n = 0` must not return an empty page — the effective limit
        // falls through to DEFAULT_CATALOG_LIMIT (100).
        let (groups, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        seed_group(&groups, repo, "only", "manifest");

        let page = uc
            .list_repo_catalog(repo, "manifest", None, 0)
            .await
            .unwrap();
        assert_eq!(page.items, vec!["only".to_string()]);
    }
}
