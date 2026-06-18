//! Moveable, named pointers from an operator-visible string to content or
//! a version.
//!
//! See `docs/architecture/explanation/domain-model.md` (refs and groups).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::ContentHash;

// ---------------------------------------------------------------------------
// RefTarget
// ---------------------------------------------------------------------------

/// What a [`MutableRef`] points at.
///
/// **Closed enum.** The two variants cover every supported format's ref
/// shape. Adding a third (e.g. `CommitSha`, `PullRequest`) is a design
/// change — the adapter's `find_by_target` query planning depends on the
/// fixed two-column target split (`target_hash` CHAR(64), `target_version`
/// TEXT) and a new variant requires a cross-format review. See
/// `docs/architecture/explanation/domain-model.md`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RefTarget {
    /// Content-addressable target. Example: OCI tag pointing at a manifest
    /// digest.
    ContentHash(ContentHash),
    /// Version-string target. Example: npm dist-tag pointing at `"1.2.3"`.
    Version(String),
}

// ---------------------------------------------------------------------------
// MutableRef
// ---------------------------------------------------------------------------

/// A named, moveable pointer from an operator-visible string to a piece of
/// content or a version.
///
/// Uniqueness is `(repository_id, namespace, ref_name)`. A repository can
/// have many namespaces; each namespace can have many refs. A ref exists in
/// exactly one namespace.
///
/// The row in `mutable_refs` is a projection off the `RefMoved` /
/// `RefRetired` event stream. Rebuilding the projection from scratch is
/// always possible.
///
/// Format-scoped conventions for `namespace` and `ref_name`:
///
/// | Format | namespace                 | ref_name                           |
/// |--------|---------------------------|------------------------------------|
/// | OCI    | image-name (`library/nginx`) | tag (`latest`, `v1.2.3`)        |
/// | npm    | package-name (`express`)  | dist-tag (`latest`, `next`, `beta`) |
/// | Maven  | `<group>:<artifact>`      | `release`, `latest`                |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutableRef {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub namespace: String,
    pub ref_name: String,
    pub target: RefTarget,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn sample_hash() -> ContentHash {
        VALID_HASH.parse().unwrap()
    }

    // -- RefTarget ----------------------------------------------------------

    #[test]
    fn ref_target_content_hash_clone_eq() {
        let a = RefTarget::ContentHash(sample_hash());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn ref_target_version_clone_eq() {
        let a = RefTarget::Version("1.2.3".into());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn ref_target_content_hash_ne_version() {
        let a = RefTarget::ContentHash(sample_hash());
        let b = RefTarget::Version(VALID_HASH.into());
        assert_ne!(a, b);
    }

    #[test]
    fn ref_target_version_ne_other_version() {
        let a = RefTarget::Version("1.0.0".into());
        let b = RefTarget::Version("2.0.0".into());
        assert_ne!(a, b);
    }

    #[test]
    fn ref_target_content_hash_serde_roundtrip() {
        let original = RefTarget::ContentHash(sample_hash());
        let json = serde_json::to_string(&original).unwrap();
        let parsed: RefTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn ref_target_version_serde_roundtrip() {
        let original = RefTarget::Version("dev-main".into());
        let json = serde_json::to_string(&original).unwrap();
        let parsed: RefTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn ref_target_exhaustive_match_compiles() {
        // Compile-time proof that matching is exhaustive against the two
        // variants. If someone adds a third variant without a cross-format
        // review, this match fails compilation (desired behaviour per
        // "RefTarget is a closed enum".
        fn describe(t: &RefTarget) -> &'static str {
            match t {
                RefTarget::ContentHash(_) => "hash",
                RefTarget::Version(_) => "version",
            }
        }
        assert_eq!(describe(&RefTarget::ContentHash(sample_hash())), "hash");
        assert_eq!(describe(&RefTarget::Version("v".into())), "version");
    }

    #[test]
    fn ref_target_hash_impl_content_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RefTarget::ContentHash(sample_hash()));
        assert!(set.contains(&RefTarget::ContentHash(sample_hash())));
    }

    #[test]
    fn ref_target_hash_impl_version() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RefTarget::Version("1.0.0".into()));
        assert!(set.contains(&RefTarget::Version("1.0.0".into())));
        assert!(!set.contains(&RefTarget::Version("2.0.0".into())));
    }

    // -- MutableRef ---------------------------------------------------------

    fn sample_ref() -> MutableRef {
        MutableRef {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            namespace: "library/nginx".into(),
            ref_name: "latest".into(),
            target: RefTarget::ContentHash(sample_hash()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn mutable_ref_clone_eq() {
        let a = sample_ref();
        let b = a.clone();
        assert_eq!(a, b);
    }

    /// Helper that exercises both arms of the closed [`RefTarget`] enum
    /// on the `MutableRef.target` field. Used below to cover both match
    /// paths without generating a `matches!` macro's synthetic NoMatch
    /// arm.
    fn describe_target(r: &MutableRef) -> String {
        match &r.target {
            RefTarget::Version(v) => format!("version:{v}"),
            RefTarget::ContentHash(h) => format!("hash:{h}"),
        }
    }

    #[test]
    fn mutable_ref_with_version_target() {
        let r = MutableRef {
            target: RefTarget::Version("1.2.3".into()),
            ..sample_ref()
        };
        assert_eq!(describe_target(&r), "version:1.2.3");
    }

    #[test]
    fn mutable_ref_with_hash_target() {
        // Pair with `mutable_ref_with_version_target` — together they
        // cover both arms of `describe_target`'s match on `RefTarget`.
        let r = sample_ref();
        assert_eq!(describe_target(&r), format!("hash:{VALID_HASH}"));
    }

    #[test]
    fn mutable_ref_serde_roundtrip() {
        let original = sample_ref();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: MutableRef = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn mutable_ref_distinct_by_ref_name() {
        let a = sample_ref();
        let b = MutableRef {
            ref_name: "next".into(),
            ..a.clone()
        };
        assert_ne!(a, b);
    }

    #[test]
    fn mutable_ref_distinct_by_namespace() {
        let a = sample_ref();
        let b = MutableRef {
            namespace: "library/redis".into(),
            ..a.clone()
        };
        assert_ne!(a, b);
    }
}
