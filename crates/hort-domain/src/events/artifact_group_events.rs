//! Artifact-group lifecycle events (see
//! `docs/architecture/explanation/domain-model.md`).
//!
//! Emitted by the `ArtifactGroupLifecyclePort` write adapter.
//! Streams live in category
//! [`StreamCategory::ArtifactGroup`](super::StreamCategory::ArtifactGroup);
//! each group has one stream keyed by `group_id`, so the full history of
//! a group — its initial creation, every member add / remove, and any
//! later primary-role assignment — is ordered within that single stream.
//!
//! # Design notes
//!
//! - `ArtifactGroupInitiated` carries the full [`ArtifactCoords`] because
//!   a replayer reconstructing the `artifact_groups` projection needs the
//!   canonical coords without consulting the projection itself. The
//!   adapter canonicalises coords on write (drops per-file `path` and
//!   `metadata`), but the event payload preserves whatever the use case
//!   chose to emit — the adapter is responsible for not rewriting event
//!   payloads.
//! - `ArtifactGroupMemberRemoved::reason` is `Option<String>`. Admin
//!   corrections carry a reason; GC-driven removals do not. An empty
//!   string in `Some(_)` is a caller bug — use `None` instead — and is
//!   rejected by `validate()`.
//! - `ArtifactGroupPrimaryRoleAssigned` exists only for the case where
//!   when the group was created with `primary_role = ""` (first member
//!   was not primary) and a later member arrives with `is_primary =
//!   true`. It is NOT emitted on the common happy path where the first
//!   member is itself primary — that path captures the role inside
//!   `ArtifactGroupInitiated` directly.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::ArtifactCoords;

use super::validation::{validate_optional_string, validate_string};

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

/// Maximum allowed length of `role` / `primary_role` in a group event
/// payload.
///
/// 128 characters is generous — real-world roles are short identifiers
/// (`pom`, `jar`, `sources`, `javadoc`, `config`, `layer`, `manifest`,
/// etc. — all well under 32 bytes). The bound exists as a
/// defence-in-depth cap so a misbehaving WASM format module cannot push
/// an unbounded blob into an event payload.
const MAX_ROLE_LEN: usize = 128;

/// Maximum allowed length of `ArtifactGroupMemberRemoved.reason`.
///
/// 512 characters matches the bound used by
/// [`crate::events::RefRetired`] / [`crate::events::RefMoved`] for free-text
/// fields — keeps admin-supplied context readable in audit trails without
/// letting a single event blow past sane storage bounds.
const MAX_REASON_LEN: usize = 512;

// ---------------------------------------------------------------------------
// ArtifactGroupInitiated
// ---------------------------------------------------------------------------

/// Emitted when an artifact group is first created.
///
/// The event carries the full canonical coords so that a replayer can
/// rebuild the `artifact_groups` projection row from the event stream
/// alone. `primary_role` may be the empty string when the first member
/// was not primary — see [`ArtifactGroupPrimaryRoleAssigned`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactGroupInitiated {
    pub group_id: Uuid,
    pub repository_id: Uuid,
    pub coords: ArtifactCoords,
    /// Role of the first primary member, or `""` when the first member
    /// was not primary. The sentinel is explicitly valid.
    pub primary_role: String,
}

impl ArtifactGroupInitiated {
    pub fn validate(&self) -> DomainResult<()> {
        // `primary_role` may be `""` (case-2 sentinel) — only cap the
        // upper bound. Length-only validation that tolerates empty input
        // isn't a common helper today; a direct bound check here keeps
        // the rule visible.
        if self.primary_role.len() > MAX_ROLE_LEN {
            return Err(crate::error::DomainError::Validation(format!(
                "primary_role exceeds maximum length of {MAX_ROLE_LEN} (got {})",
                self.primary_role.len()
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ArtifactGroupMemberAdded
// ---------------------------------------------------------------------------

/// Emitted when an artifact is attached to a group as a member with a
/// given `role` (e.g. Maven's `pom`, `jar`, `sources`, `javadoc`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactGroupMemberAdded {
    pub group_id: Uuid,
    pub role: String,
    pub artifact_id: Uuid,
}

impl ArtifactGroupMemberAdded {
    pub fn validate(&self) -> DomainResult<()> {
        validate_string("role", &self.role, MAX_ROLE_LEN)
    }
}

// ---------------------------------------------------------------------------
// ArtifactGroupMemberRemoved
// ---------------------------------------------------------------------------

/// Emitted when an artifact is detached from a group.
///
/// Admin-driven corrections carry a `reason`; GC-driven removals leave
/// it `None`. An empty `Some(_)` is a caller bug — use `None`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactGroupMemberRemoved {
    pub group_id: Uuid,
    pub artifact_id: Uuid,
    pub reason: Option<String>,
}

impl ArtifactGroupMemberRemoved {
    pub fn validate(&self) -> DomainResult<()> {
        validate_optional_string("reason", &self.reason, MAX_REASON_LEN)
    }
}

// ---------------------------------------------------------------------------
// ArtifactGroupPrimaryRoleAssigned
// ---------------------------------------------------------------------------

/// Emitted when a group created with `primary_role = ""` later receives a
/// member with `is_primary = true`. The adapter gates the assignment with a
/// race-safe `UPDATE ... WHERE primary_role = ''`; the event lands only
/// when the update succeeded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactGroupPrimaryRoleAssigned {
    pub group_id: Uuid,
    pub primary_role: String,
}

impl ArtifactGroupPrimaryRoleAssigned {
    pub fn validate(&self) -> DomainResult<()> {
        // Empty `primary_role` here would be meaningless — the event's
        // purpose is to record an assignment, not a clearing.
        validate_string("primary_role", &self.primary_role, MAX_ROLE_LEN)
    }
}
