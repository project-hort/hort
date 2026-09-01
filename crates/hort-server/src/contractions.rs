//! Runtime reader for `migrations/CONTRACTIONS.toml` — the manifest the
//! `hort-server migrate` fleet fence reads to decide whether a pending
//! migration set contains a contraction (ADR 0030 amendment (c)).
//!
//! This is a deliberately separate, minimal reader from
//! `crates/hort-app/tests/expand_contract_guard.rs`'s manifest parser:
//! that parser lives under `tests/`, which the production binary must
//! not depend on, and the fence needs only the migration file names —
//! not the `identifiers` / `reference_removed_in` / `note` fields the
//! guard validates in CI. Both readers parse the same TOML shape; this
//! one simply ignores fields it does not need (no `deny_unknown_fields`
//! here), so a manifest field the guard requires but the fence has no
//! use for cannot break this reader.

use std::collections::BTreeSet;

use serde::Deserialize;

/// Embedded at compile time. Relative to this file, matching
/// `crate::migrate::MIGRATOR`'s `sqlx::migrate!("../../migrations")`
/// convention (that path is relative to `Cargo.toml`, one directory up
/// from `src/`, hence the extra `..` here).
const MANIFEST_TOML: &str = include_str!("../../../migrations/CONTRACTIONS.toml");

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(default)]
    contraction: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    migration: String,
}

/// The sqlx migration `version` (the leading integer in the file name —
/// e.g. `20` for `020_drop_artifacts_is_deleted.sql`) of every migration
/// `CONTRACTIONS.toml` declares destructive.
pub fn contraction_versions() -> BTreeSet<i64> {
    parse_contraction_versions(MANIFEST_TOML)
}

fn parse_contraction_versions(raw: &str) -> BTreeSet<i64> {
    let manifest: Manifest = toml::from_str(raw)
        .expect("migrations/CONTRACTIONS.toml must parse — guarded by expand_contract_guard");
    manifest
        .contraction
        .into_iter()
        .filter_map(|entry| migration_version(&entry.migration))
        .collect()
}

/// The leading integer version prefix of a migration file name
/// (`sqlx`'s own `<VERSION>_<DESCRIPTION>.sql` convention).
fn migration_version(file_name: &str) -> Option<i64> {
    file_name.split('_').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the migrations this workspace's checked-in manifest
    /// currently declares destructive. If a future manifest edit
    /// changes this set, the intent is deliberate — update the
    /// assertion alongside the manifest edit.
    #[test]
    fn reads_the_checked_in_manifest_versions() {
        let versions = contraction_versions();
        assert_eq!(
            versions,
            BTreeSet::from([9, 14, 20]),
            "migrations/CONTRACTIONS.toml contraction set changed — update this pin"
        );
    }

    #[test]
    fn migration_version_parses_the_leading_integer() {
        assert_eq!(
            migration_version("020_drop_artifacts_is_deleted.sql"),
            Some(20)
        );
        assert_eq!(migration_version("009_scan_jobs_and_findings.sql"), Some(9));
    }

    #[test]
    fn migration_version_rejects_a_non_numeric_prefix() {
        assert_eq!(migration_version("not_a_version.sql"), None);
        assert_eq!(migration_version(""), None);
    }

    #[test]
    fn empty_manifest_yields_no_contractions() {
        assert!(parse_contraction_versions("").is_empty());
    }

    #[test]
    fn unknown_fields_are_ignored_not_rejected() {
        let raw = r#"
            [[contraction]]
            migration = "020_drop_artifacts_is_deleted.sql"
            identifiers = ["artifacts.is_deleted"]
            reference_removed_in = "0.12.0"
            note = "the guard validates these fields; the fence does not need to"
        "#;
        assert_eq!(parse_contraction_versions(raw), BTreeSet::from([20]));
    }
}
