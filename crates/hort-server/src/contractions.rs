//! Runtime reader for `migrations/CONTRACTIONS.toml` — the manifest
//! behind two `hort-server migrate` behaviours: the fleet fence, which
//! compares connected clients with the strictest floor among pending
//! declared contractions (ADR 0030 amendment (c)), and the schema
//! compatibility register, which records each applied migration's
//! `reference_removed_in` so a later binary can read back the oldest
//! version that migration tolerates.
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
/// `reference_removed_in` is "the release whose code no longer produces
/// what this migration takes away", which is exactly the oldest binary
/// version the migration tolerates: the release before it is the last one
/// that did. For a removal that is the release whose code stopped naming
/// the identifier; for a narrowing — a type change, a `SET NOT NULL`, a
/// new `CHECK` — the identifier stays and it is the release whose writers
/// can no longer emit a value the migration refuses. A migration absent
/// from this map took nothing away and every binary tolerates it; so does
/// one whose entry names the oldest release, which is what a narrowing
/// that only widened an admitted set honestly carries.
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
    ///
    /// Beyond the three drop/rename migrations the set carries three `CHECK`
    /// additions on a pre-existing column, which narrow that column's write
    /// contract: 39 and 44, real narrowings, and 31, which the guard reports
    /// because it cannot read the statement as a replacement and fails
    /// closed. 17 and 2 are those same two categories one constraint class
    /// over: 17 a real narrowing (a partial unique index replacing no
    /// predecessor at all), 2 a fail-closed declaration (the deferred
    /// `permission_grants` foreign key, declared in a later migration file
    /// than the column it constrains, which a per-file scan cannot see is
    /// part of the same baseline release). A replacement whose reach only GREW — a
    /// `CHECK` whose admitted set gained a literal, a wider primary key, a
    /// full unique constraint becoming partial — is not a narrowing and is
    /// deliberately absent: declaring one would fence a rolling upgrade
    /// ADR 0030 exempts. See the manifest's own section comments.
    #[test]
    fn reads_the_checked_in_manifest_versions() {
        let versions = contraction_versions();
        assert_eq!(
            versions,
            BTreeSet::from([2, 9, 14, 17, 20, 31, 39, 44]),
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
    ///
    /// 31's and 2's `0.9.2` is not a placeholder: neither migration takes
    /// anything away from any writer (their own notes carry why), so the
    /// oldest binary each tolerates is the oldest binary there has ever
    /// been. Dating either to the release it shipped in would make this map
    /// — and so the register's recorded rollback floor — claim a floor the
    /// schema does not impose, which is a false "you cannot roll back" in
    /// an incident.
    ///
    /// The maximum over this map is what the fleet fence and the register
    /// actually report, and it is 39's `0.17.3`: every entry added since is
    /// strictly below it, so neither operator-facing number moved.
    #[test]
    fn reads_the_checked_in_minimum_binary_versions() {
        assert_eq!(
            contraction_minimum_binary_versions(),
            BTreeMap::from([
                (2, "0.9.2".to_string()),
                (9, "0.9.2".to_string()),
                (14, "0.9.8".to_string()),
                (17, "0.10.0".to_string()),
                (20, "0.12.0".to_string()),
                (31, "0.9.2".to_string()),
                (39, "0.17.3".to_string()),
                (44, "0.14.1".to_string()),
            ]),
            "migrations/CONTRACTIONS.toml reference_removed_in set changed — update this pin"
        );
    }

    /// The strictest declared floor — the number the fleet fence refuses
    /// clients against and the register records as the rollback floor —
    /// pinned on its own, because every entry added to the manifest has to
    /// be checked against it and a set-equality assertion does not say
    /// which entry is the maximum.
    #[test]
    fn the_strictest_declared_floor_is_migration_39s() {
        let strictest = contraction_minimum_binary_versions()
            .into_iter()
            .max_by(|(_, a), (_, b)| {
                let core = |raw: &str| {
                    raw.split('.')
                        .map(|part| part.parse::<u64>().unwrap_or_default())
                        .collect::<Vec<_>>()
                };
                core(a).cmp(&core(b))
            })
            .expect("the manifest declares at least one contraction");
        assert_eq!(strictest, (39, "0.17.3".to_string()));
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
