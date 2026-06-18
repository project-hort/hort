//! A set of files that together form one logical artifact.
//!
//! See `docs/architecture/explanation/domain-model.md` (refs and groups).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::types::ArtifactCoords;

// ---------------------------------------------------------------------------
// ArtifactGroupMember
// ---------------------------------------------------------------------------

/// One file in an [`ArtifactGroup`].
///
/// An artifact belongs to at most one group. Multiple members within the
/// same group may share a role (OCI layers — `role = "layer"` × N; Debian
/// source packages can carry multiple orig tarballs). The repository is a
/// set, not a map — ordered by `added_at` for consumers that care about
/// original arrival order.
///
/// Format-scoped conventions for `role`:
///
/// | Format  | Roles                                                       |
/// |---------|-------------------------------------------------------------|
/// | Maven   | `"pom"`, `"jar"`, `"sources"`, `"javadoc"`, `"signature"`, `"sha256"`, `"md5"` |
/// | Go      | `"mod"`, `"zip"`, `"info"`                                  |
/// | OCI     | `"manifest"`, `"config"`, `"layer"` (multiple layers OK)    |
/// | Debian  | `"deb"`, `"dsc"`, `"changes"`, `"orig"`                     |
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactGroupMember {
    /// Role within the group.
    pub role: String,
    /// Foreign key into the `artifacts` table. The blob itself lives in
    /// CAS at that artifact's content hash.
    pub artifact_id: Uuid,
    pub added_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// ArtifactGroup
// ---------------------------------------------------------------------------

/// A set of files that together form one logical artifact.
///
/// Groups exist for formats where a single "version" is composed of
/// multiple physical files (Maven POM+JAR+sources, Go .zip+.mod+.info,
/// OCI manifest+config+layers, Debian .deb+.dsc+.changes). Each member is
/// a separate row in the `artifacts` table; the group is the relationship.
///
/// **Late joins allowed.** Maven signatures frequently arrive days after
/// the JAR. There is no mandatory `finalize` step; a group grows as members
/// arrive.
///
/// # Canonicalization contract — load-bearing
///
/// `coords_json` is the unique key on `artifact_groups`. The handler that
/// produces a `GroupMembership { group_coords, … }` MUST populate
/// `group_coords` with ONLY the identity-forming fields of [`ArtifactCoords`] —
/// `name`, `name_as_published`, `version`, `format`. The per-file fields
/// (`path`, `metadata`) MUST be their type-default values
/// (`path: String::new()`, `metadata: serde_json::Value::Null`). Any handler
/// that diverges creates duplicate groups — Postgres compares JSONB values
/// logically (key-order-independent), but differing payloads are different
/// keys.
///
/// The [`ArtifactGroupRepository`](crate::ports::artifact_group_repository::ArtifactGroupRepository)
/// adapter MUST serialise a queried [`ArtifactCoords`] with the same
/// canonicalisation so that `find_by_coords` hits the same row regardless
/// of where the lookup originates.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactGroup {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub coords: ArtifactCoords,
    /// Format-declared role of the group's canonical file. Used when a
    /// consumer needs "the main file" without disambiguation (e.g.
    /// `HEAD /<group>/<artifact>/<version>/` with no file-name).
    /// Advisory, not enforced. The empty-string sentinel (`""`) is
    /// allowed and represents "no primary role assigned yet".
    pub primary_role: String,
    pub members: Vec<ArtifactGroupMember>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::repository::RepositoryFormat;

    fn sample_coords() -> ArtifactCoords {
        ArtifactCoords {
            name: "com.example:widget".into(),
            name_as_published: "com.example:widget".into(),
            version: Some("1.2.3".into()),
            path: String::new(),
            format: RepositoryFormat::Maven,
            metadata: serde_json::Value::Null,
        }
    }

    fn sample_member() -> ArtifactGroupMember {
        ArtifactGroupMember {
            role: "jar".into(),
            artifact_id: Uuid::nil(),
            added_at: Utc::now(),
        }
    }

    fn sample_group() -> ArtifactGroup {
        ArtifactGroup {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            coords: sample_coords(),
            primary_role: "jar".into(),
            members: vec![sample_member()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn artifact_group_member_clone_eq() {
        let a = sample_member();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn artifact_group_member_distinct_by_role() {
        let a = sample_member();
        let b = ArtifactGroupMember {
            role: "pom".into(),
            ..a.clone()
        };
        assert_ne!(a, b);
    }

    #[test]
    fn artifact_group_member_distinct_by_artifact_id() {
        let a = sample_member();
        let b = ArtifactGroupMember {
            artifact_id: Uuid::new_v4(),
            ..a.clone()
        };
        assert_ne!(a, b);
    }

    #[test]
    fn artifact_group_clone_eq() {
        let a = sample_group();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn artifact_group_allows_empty_primary_role() {
        // First member is not primary; group created with empty-string
        // sentinel so a later primary can claim the slot.
        let g = ArtifactGroup {
            primary_role: String::new(),
            ..sample_group()
        };
        assert!(g.primary_role.is_empty());
    }

    #[test]
    fn artifact_group_multiple_members_same_role() {
        // OCI images ship N layers, each with role = "layer".
        let layer_a = ArtifactGroupMember {
            role: "layer".into(),
            artifact_id: Uuid::new_v4(),
            added_at: Utc::now(),
        };
        let layer_b = ArtifactGroupMember {
            role: "layer".into(),
            artifact_id: Uuid::new_v4(),
            added_at: Utc::now(),
        };
        let g = ArtifactGroup {
            primary_role: "manifest".into(),
            members: vec![layer_a.clone(), layer_b.clone()],
            ..sample_group()
        };
        assert_eq!(g.members.len(), 2);
        assert_eq!(g.members[0].role, "layer");
        assert_eq!(g.members[1].role, "layer");
        assert_ne!(g.members[0].artifact_id, g.members[1].artifact_id);
    }

    #[test]
    fn artifact_group_distinct_by_id() {
        let a = sample_group();
        let b = ArtifactGroup {
            id: Uuid::new_v4(),
            ..a.clone()
        };
        assert_ne!(a, b);
    }

    #[test]
    fn artifact_group_distinct_by_coords() {
        let a = sample_group();
        let different_coords = ArtifactCoords {
            version: Some("9.9.9".into()),
            ..sample_coords()
        };
        let b = ArtifactGroup {
            coords: different_coords,
            ..a.clone()
        };
        assert_ne!(a, b);
    }
}
