//! Runtime reader for `migrations/CONTRACTIONS.toml` — the manifest
//! behind two `hort-server migrate` behaviours: the fleet fence, which
//! decides whether a pending migration set contains a contraction
//! (ADR 0030 amendment (c)), and the schema compatibility register, which
//! records each applied migration's `reference_removed_in` so a later
//! binary can read back the oldest version that migration tolerates.
//!
//! This is a deliberately separate, minimal reader from
//! `crates/hort-app/tests/expand_contract_guard.rs`'s manifest parser:
//! that parser lives under `tests/`, which the production binary must
//! not depend on, and neither consumer here needs the `identifiers` /
//! `note` fields the guard validates in CI. Both readers parse the same
//! TOML shape; this one simply ignores fields it does not need (no
//! `deny_unknown_fields` here), so a manifest field the guard requires
//! but these consumers have no use for cannot break this reader.
//!
//! Only this binary's *embedded* migrations are covered — that is the
//! whole reason the register exists. A binary holds the manifest entry
//! for every migration it ships and for none that it does not, so the
//! migrations a rollback actually cares about are unreachable from here
//! and have to come out of the database instead
//! (`hort_config::schema_compat`).

use std::collections::{BTreeMap, BTreeSet};

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
    reference_removed_in: String,
}

/// The sqlx migration `version` (the leading integer in the file name —
/// e.g. `20` for `020_drop_artifacts_is_deleted.sql`) of every migration
/// `CONTRACTIONS.toml` declares destructive.
pub fn contraction_versions() -> BTreeSet<i64> {
    contraction_minimum_binary_versions().into_keys().collect()
}

/// Every declared contraction's `reference_removed_in`, keyed by sqlx
/// migration version.
///
/// `reference_removed_in` is "the release whose code no longer references
/// the identifiers this migration removes", which is exactly the oldest
/// binary version the migration tolerates: the release before it is the
/// last one that named them. A migration absent from this map removed
/// nothing and every binary tolerates it.
pub fn contraction_minimum_binary_versions() -> BTreeMap<i64, String> {
    parse_manifest(MANIFEST_TOML)
}

fn parse_manifest(raw: &str) -> BTreeMap<i64, String> {
    let manifest: Manifest = toml::from_str(raw)
        .expect("migrations/CONTRACTIONS.toml must parse — guarded by expand_contract_guard");
    manifest
        .contraction
        .into_iter()
        .filter_map(|entry| {
            migration_version(&entry.migration).map(|v| (v, entry.reference_removed_in))
        })
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
        assert!(parse_manifest("").is_empty());
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
        assert_eq!(
            parse_manifest(raw),
            BTreeMap::from([(20, "0.12.0".to_string())])
        );
    }

    /// The minimum-binary map is what the register write draws on, so the
    /// checked-in manifest's `reference_removed_in` values are pinned the
    /// same way the version set is.
    #[test]
    fn reads_the_checked_in_minimum_binary_versions() {
        assert_eq!(
            contraction_minimum_binary_versions(),
            BTreeMap::from([
                (9, "0.9.2".to_string()),
                (14, "0.9.8".to_string()),
                (20, "0.12.0".to_string()),
            ]),
            "migrations/CONTRACTIONS.toml reference_removed_in set changed — update this pin"
        );
    }

    /// The two accessors cannot drift: the version set is the key set.
    #[test]
    fn the_version_set_is_the_minimum_map_key_set() {
        assert_eq!(
            contraction_versions(),
            contraction_minimum_binary_versions()
                .into_keys()
                .collect::<BTreeSet<_>>()
        );
    }
}
