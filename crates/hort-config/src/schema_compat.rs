//! Which (binary, schema) pairs may boot — the one definition, shared by
//! every gate that asks.
//!
//! Two independent gates decide whether a binary may come up against a
//! given database: the `migrate` runner (which refuses to proceed when the
//! database records a migration the binary does not embed) and the
//! serve-path schema assertion (which refuses to serve on a version skew).
//! Answering the question differently in the two places is what makes a
//! binary rollback impossible: one gate passes and the other still refuses.
//! Hence a single predicate, consumed by both.
//!
//! The answer comes from the expand/contract discipline (ADR 0030): a
//! contraction ships only in a release strictly *after* the last release
//! whose code referenced the identifier, so the immediately preceding
//! release's binary never references anything a contraction removed. A
//! schema **newer** than the binary is therefore a supported serving state
//! by construction. A schema **older** than the binary is not — those are
//! pending migrations.
//!
//! The shared prefix of the two sets is immutable (ADR 0022). That is what
//! makes a discrepancy *below* the newest version a genuinely broken
//! history rather than a version skew, and why it stays a refusal.
//!
//! "Newer schema" alone is a structural answer, and a lossy one in the
//! other direction: it accepts *any* number of releases of skew when what
//! actually matters is whether one of the migrations in that gap was a
//! contraction. The [schema compatibility register] closes that: the
//! binary that applies a migration records the oldest binary version that
//! migration tolerates, taken from `migrations/CONTRACTIONS.toml`, and a
//! later gate reads those rows back for exactly the migrations it does not
//! embed. Five releases of expansions are then as bootable as one, and a
//! single contraction refuses with the version it needs named.
//!
//! Zero I/O: the caller reads the applied set out of the bookkeeping table,
//! the register rows out of `schema_compat_register`, and the embedded set
//! off its compiled-in migrator, then asks here.
//!
//! [schema compatibility register]: SchemaCompatRegister

use std::collections::{BTreeMap, BTreeSet};

use crate::pg_identity::parse_version_core;

/// What the schema compatibility register records for one applied
/// migration version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationTolerance {
    /// An expansion: the migration removed nothing, so every binary
    /// tolerates it however far back it is.
    Expansion,
    /// A contraction: the oldest binary version that tolerates this
    /// migration — the `reference_removed_in` its
    /// `migrations/CONTRACTIONS.toml` entry records, which is the release
    /// whose code stopped referencing the identifiers it removes.
    MinimumBinary(String),
}

/// The register rows, keyed by migration version.
///
/// A version **absent** from the map is unregistered, which is not the
/// same as [`MigrationTolerance::Expansion`]: silence is not evidence that
/// nothing was removed, so [`SchemaCompatibility::evaluate`] fails closed
/// on it. A binary carrying the register writes a row for every migration
/// it embeds on every `migrate` run, so a database it has migrated carries
/// rows for its whole history — including the part applied before the
/// register existed. See [`register_from_rows`] for why bootstrapping
/// self-resolves.
pub type SchemaCompatRegister = BTreeMap<i64, MigrationTolerance>;

/// Build a [`SchemaCompatRegister`] from raw `(version,
/// min_binary_version)` rows as they sit in `schema_compat_register`,
/// where a `NULL` minimum means the migration was an expansion.
///
/// The mapping lives here rather than at each read site so both boot gates
/// interpret a `NULL` identically. A missing *table* is not represented at
/// all: the reader hands back no rows, every unembedded applied migration
/// is then unregistered, and the fail-closed rule refuses.
///
/// **Bootstrapping is self-resolving.** A rollback target from before the
/// register existed has no register logic at all and is governed by the
/// structural gate alone — correct, and needing no special case. Every
/// binary that *does* have the logic embeds every migration up to and
/// including the one that created the table and records a row for each of
/// them on every `migrate` run, so the migrations it does not embed are
/// exactly the ones a register-aware binary applied and recorded. The only
/// route to an applied-but-unembedded migration with no row is a downgrade
/// followed by a migrate, which the fail-closed rule already covers.
pub fn register_from_rows(
    rows: impl IntoIterator<Item = (i64, Option<String>)>,
) -> SchemaCompatRegister {
    rows.into_iter()
        .map(|(version, minimum)| {
            let tolerance = match minimum {
                Some(min) => MigrationTolerance::MinimumBinary(min),
                None => MigrationTolerance::Expansion,
            };
            (version, tolerance)
        })
        .collect()
}

/// The verdict on one (applied set, embedded set) pair.
///
/// Exactly one variant applies to any pair; the three are mutually
/// exclusive and jointly exhaustive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaCompatibility {
    /// Every embedded migration is applied, and every applied migration
    /// the binary does not embed is strictly newer than the newest
    /// migration it does embed. Nothing to apply; the binary serves this
    /// schema correctly per ADR 0030.
    Supported {
        /// Applied versions this binary does not embed, ascending. All
        /// strictly newer than the newest embedded version. Empty when
        /// the two sets match exactly — the steady state.
        newer_applied: Vec<i64>,
    },
    /// Every applied migration is embedded and at least one embedded
    /// migration is not applied yet: the normal upgrade path.
    Pending {
        /// Embedded versions not yet applied, ascending.
        pending: Vec<i64>,
        /// The newest applied version, `0` when nothing is applied. The
        /// operator-facing message reports this as `applied=`.
        newest_applied: i64,
        /// The newest embedded version, reported as `binary expects=`.
        newest_embedded: i64,
    },
    /// A discrepancy below the newest version on either side. Refuse.
    Divergent(SchemaDivergence),
    /// Structurally a rollback — every applied migration this binary does
    /// not embed is newer than everything it does — but at least one of
    /// those migrations removed something a binary of this version may
    /// still reference, or records nothing at all. Refuse.
    Intolerable(SchemaRollbackBound),
}

/// One applied-but-unembedded migration that a binary is too old to
/// tolerate, behind a [`SchemaCompatibility::Intolerable`] verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockingMigration {
    /// The migration version, as recorded in the bookkeeping table.
    pub version: i64,
    /// The oldest binary version that tolerates it, when the register
    /// records one. `None` when the register has no row for this
    /// migration: silence is not evidence of an expansion, so it counts
    /// as a contraction whose minimum this binary cannot meet.
    pub minimum_binary: Option<String>,
}

/// Why a structurally-supported rollback is refused anyway, kept so the
/// refusal can name the migration that blocks it and the version it would
/// work from. An operator reads this message mid-incident and it is their
/// whole recovery path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaRollbackBound {
    /// The applied-but-unembedded migrations this binary does not
    /// tolerate, ascending. Never empty.
    pub blocking: Vec<BlockingMigration>,
    /// This binary's own version, verbatim as it was supplied — the
    /// message reports it so an operator can see which binary refused
    /// without correlating against the image tag.
    pub binary_version: String,
}

impl SchemaRollbackBound {
    /// The oldest binary version that clears **every** blocking
    /// migration, or `None` when at least one of them is unregistered and
    /// the answer is therefore unknown. Unknown is not "no bound": it is a
    /// bound this binary cannot prove it meets.
    pub fn required_binary_version(&self) -> Option<&str> {
        let mut highest: Option<(&str, _)> = None;
        for blocker in &self.blocking {
            let recorded = blocker.minimum_binary.as_deref()?;
            // An unparseable recorded minimum is a manifest defect the
            // build-time expand/contract guard prevents; treating it as
            // unknown here keeps the message honest rather than silently
            // dropping a bound.
            let core = parse_version_core(recorded)?;
            if highest.is_none_or(|(_, best)| core > best) {
                highest = Some((recorded, core));
            }
        }
        highest.map(|(version, _)| version)
    }

    /// The refusal text, naming every blocking migration and — when every
    /// one of them is registered — the version this binary would have to
    /// be for the same schema to boot.
    pub fn refusal(&self) -> String {
        let clauses: Vec<String> = self
            .blocking
            .iter()
            .map(|blocker| match blocker.minimum_binary.as_deref() {
                Some(minimum) => format!(
                    "migration {} requires a binary of version {minimum} or newer",
                    blocker.version
                ),
                None => format!(
                    "migration {} is absent from the schema compatibility register, so it must be \
                     assumed to have removed something this binary still references",
                    blocker.version
                ),
            })
            .collect();
        let remedy = match self.required_binary_version() {
            Some(required) => format!(
                "Run a binary of version {required} or newer against this database, or restore a \
                 backup taken before those migrations were applied"
            ),
            None => "Run the release that applied those migrations (or newer) against this \
                     database, or restore a backup taken before they were applied"
                .to_string(),
        };
        format!(
            "schema is newer than this binary ({}) tolerates: {}. {remedy} — migrations are \
             forward-only, so the schema itself cannot be rolled back. Each migration's own \
             record is its migrations/CONTRACTIONS.toml entry in the release that shipped it.",
            self.binary_version,
            clauses.join("; "),
        )
    }
}

/// How far back the applied schema tolerates a binary, as far as the
/// register records it — the operator-facing answer reported alongside the
/// applied and expected schema versions at boot.
///
/// Three outcomes, mutually exclusive: each states its own meaning in full,
/// and none of them states another's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaRollbackFloor {
    /// Every applied migration is registered, and every registered row is
    /// an expansion. Nothing in the register constrains how old a binary
    /// may serve this schema — any binary carrying the boot gates will.
    /// This is the common case: contractions are rare and batched, so most
    /// databases' whole applied history is expansions.
    Unconstrained,
    /// At least one applied migration has no register row at all: the
    /// register was never asked about it, so it cannot state a floor. The
    /// boot gates fail closed on exactly that migration when a binary does
    /// not embed it. A database migrated at least once by a binary
    /// carrying the register backfills a row for everything it embeds on
    /// every run, so this outcome means this database has never been
    /// migrated by such a binary — migrating once with the current release
    /// resolves it.
    Indeterminate,
    /// The strongest minimum recorded across the applied set: the oldest
    /// binary version every registered applied migration tolerates.
    Version(String),
}

impl std::fmt::Display for SchemaRollbackFloor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unconstrained => f.write_str("unconstrained"),
            Self::Indeterminate => f.write_str("indeterminate"),
            Self::Version(version) => f.write_str(version),
        }
    }
}

/// The oldest binary version the applied schema tolerates, over the
/// register rows that cover it. See [`SchemaRollbackFloor`] for the three
/// outcomes and what each does and does not promise.
///
/// Deliberately mirrors [`SchemaRollbackBound::required_binary_version`]'s
/// unknown-dominates rule: one unregistered applied migration makes the
/// whole answer [`SchemaRollbackFloor::Indeterminate`], even alongside a
/// recorded minimum from another. A report that disagrees with the gate it
/// predicts is worse than silence — an operator who reads a version here and
/// rolls back to it would be refused anyway, by a message calling the
/// requirement unknown.
pub fn schema_rollback_floor(
    applied: &BTreeSet<i64>,
    register: &SchemaCompatRegister,
) -> SchemaRollbackFloor {
    let mut highest: Option<(&str, _)> = None;
    for version in applied {
        match register.get(version) {
            Some(MigrationTolerance::MinimumBinary(minimum)) => {
                // Skip rather than fail: this is an inspection answer, and
                // a recorded value that does not parse is a manifest
                // defect the build-time guard prevents. The boot gates
                // fail closed on the same value; they are the safety
                // property, this is the report.
                let Some(core) = parse_version_core(minimum) else {
                    continue;
                };
                if highest.is_none_or(|(_, best)| core > best) {
                    highest = Some((minimum.as_str(), core));
                }
            }
            Some(MigrationTolerance::Expansion) => {}
            None => return SchemaRollbackFloor::Indeterminate,
        }
    }
    match highest {
        Some((version, _)) => SchemaRollbackFloor::Version(version.to_string()),
        None => SchemaRollbackFloor::Unconstrained,
    }
}

/// The offending versions behind a [`SchemaCompatibility::Divergent`]
/// verdict, kept so the refusal can name them: an operator hits this
/// message mid-incident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDivergence {
    /// Applied versions the binary does not embed that sit *below* its
    /// newest embedded version — the database skipped forward past
    /// something this binary would still have applied.
    pub applied_below_waterline: Vec<i64>,
    /// Embedded versions the database has not applied that sit *below*
    /// its newest applied version — the database applied out of order, or
    /// a row was removed from the bookkeeping table.
    pub unapplied_below_waterline: Vec<i64>,
    /// The newest applied version, `0` when nothing is applied.
    pub newest_applied: i64,
    /// The newest embedded version, `0` when the binary embeds none.
    pub newest_embedded: i64,
}

impl SchemaDivergence {
    /// The refusal text, naming every offending version.
    pub fn refusal(&self) -> String {
        let mut clauses = Vec::new();
        if !self.applied_below_waterline.is_empty() {
            clauses.push(format!(
                "the database records migration(s) {} that this binary does not embed, below its \
                 newest embedded version {}",
                join_versions(&self.applied_below_waterline),
                self.newest_embedded
            ));
        }
        if !self.unapplied_below_waterline.is_empty() {
            clauses.push(format!(
                "this binary embeds migration(s) {} that the database has not applied, below its \
                 newest applied version {}",
                join_versions(&self.unapplied_below_waterline),
                self.newest_applied
            ));
        }
        format!(
            "divergent migration history: {}. The shared prefix of the applied and embedded \
             migration sets is immutable, so this is a broken history rather than a version skew \
             — a newer schema alone would be accepted. Confirm this binary was built from a \
             release on the same migration line as the database, and inspect _sqlx_migrations.",
            clauses.join("; ")
        )
    }
}

impl SchemaCompatibility {
    /// The whole predicate: the structural comparison of the two version
    /// sets, refined by the schema compatibility register.
    ///
    /// This is the only entry point a boot gate may use. [`Self::structural`]
    /// is deliberately private so no consumer can take the structural
    /// verdict and skip the register — a gate that did would accept a
    /// rollback past a contraction, which is the failure this whole
    /// mechanism exists to prevent.
    ///
    /// `binary_version` is the calling binary's own version
    /// (`CARGO_PKG_VERSION`); it is compared with
    /// [`crate::pg_identity::parse_version_core`], the same comparison the
    /// runtime fleet fence uses, so a `-dev`/`-rc` suffix sorts as the
    /// release it is working towards. A version that does not parse is
    /// treated as meeting no minimum at all — fail closed.
    pub fn evaluate(
        applied: &BTreeSet<i64>,
        embedded: &BTreeSet<i64>,
        register: &SchemaCompatRegister,
        binary_version: &str,
    ) -> Self {
        Self::structural(applied, embedded).refine_with_register(register, binary_version)
    }

    /// Downgrade a [`Self::Supported`] verdict to [`Self::Intolerable`]
    /// when the register says one of the migrations the binary does not
    /// embed removed something a binary of this version may still
    /// reference.
    ///
    /// Only `Supported` carries applied-but-unembedded migrations, so
    /// every other verdict passes through untouched.
    fn refine_with_register(self, register: &SchemaCompatRegister, binary_version: &str) -> Self {
        let Self::Supported { newer_applied } = &self else {
            return self;
        };
        let binary_core = parse_version_core(binary_version);
        let blocking: Vec<BlockingMigration> = newer_applied
            .iter()
            .filter_map(|version| match register.get(version) {
                // Recorded as removing nothing: tolerated by any binary.
                Some(MigrationTolerance::Expansion) => None,
                Some(MigrationTolerance::MinimumBinary(minimum)) => {
                    let tolerated = parse_version_core(minimum)
                        .zip(binary_core)
                        .is_some_and(|(required, binary)| binary >= required);
                    (!tolerated).then(|| BlockingMigration {
                        version: *version,
                        minimum_binary: Some(minimum.clone()),
                    })
                }
                // No row: silence is not evidence of an expansion.
                None => Some(BlockingMigration {
                    version: *version,
                    minimum_binary: None,
                }),
            })
            .collect();

        if blocking.is_empty() {
            self
        } else {
            Self::Intolerable(SchemaRollbackBound {
                blocking,
                binary_version: binary_version.to_string(),
            })
        }
    }

    /// Compare the versions recorded in the bookkeeping table against the
    /// versions compiled into this binary.
    ///
    /// Total: either set may be empty. An empty applied set is a database
    /// with nothing migrated yet ([`Self::Pending`]); an empty embedded set
    /// is a binary carrying no migrations, which is trivially older than
    /// any schema ([`Self::Supported`]).
    fn structural(applied: &BTreeSet<i64>, embedded: &BTreeSet<i64>) -> Self {
        let newest_applied = applied.iter().next_back().copied();
        let newest_embedded = embedded.iter().next_back().copied();

        let applied_not_embedded: Vec<i64> = applied.difference(embedded).copied().collect();
        let embedded_not_applied: Vec<i64> = embedded.difference(applied).copied().collect();

        // "Below the waterline" — under the other side's newest version.
        // An absent maximum means that side is empty, so there is no
        // waterline and nothing can sit below it.
        let applied_below_waterline: Vec<i64> = applied_not_embedded
            .iter()
            .copied()
            .filter(|v| newest_embedded.is_some_and(|newest| *v < newest))
            .collect();
        let unapplied_below_waterline: Vec<i64> = embedded_not_applied
            .iter()
            .copied()
            .filter(|v| newest_applied.is_some_and(|newest| *v < newest))
            .collect();

        if !applied_below_waterline.is_empty() || !unapplied_below_waterline.is_empty() {
            return Self::Divergent(SchemaDivergence {
                applied_below_waterline,
                unapplied_below_waterline,
                newest_applied: newest_applied.unwrap_or(0),
                newest_embedded: newest_embedded.unwrap_or(0),
            });
        }

        // Past the divergence check the two difference sets can never both
        // be non-empty: an extra applied version is above the newest
        // embedded one and an unapplied embedded version is above the
        // newest applied one, which cannot hold simultaneously.
        if embedded_not_applied.is_empty() {
            Self::Supported {
                newer_applied: applied_not_embedded,
            }
        } else {
            Self::Pending {
                pending: embedded_not_applied,
                newest_applied: newest_applied.unwrap_or(0),
                newest_embedded: newest_embedded.unwrap_or(0),
            }
        }
    }

    /// The refusal text for a verdict a *serving* binary must not boot on,
    /// or `None` for [`Self::Supported`] — the only bootable verdict.
    ///
    /// [`Self::Pending`] keeps the long-standing operator-actionable
    /// wording: the corrective action is to run the migration step, or to
    /// roll the binary back to the release the schema belongs to.
    /// [`Self::Intolerable`] names the migration that blocks the rollback
    /// and the version it would work from — see
    /// [`SchemaRollbackBound::refusal`].
    pub fn boot_refusal(&self) -> Option<String> {
        match self {
            Self::Supported { .. } => None,
            Self::Pending {
                newest_applied,
                newest_embedded,
                ..
            } => Some(format!(
                "schema version mismatch: applied={newest_applied}, binary expects=\
                 {newest_embedded}. Run `hort-server migrate` to advance, or roll the binary back \
                 to match the schema."
            )),
            Self::Divergent(divergence) => Some(divergence.refusal()),
            Self::Intolerable(bound) => Some(bound.refusal()),
        }
    }
}

fn join_versions(versions: &[i64]) -> String {
    versions
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    //! Exhaustive, database-free coverage of the predicate: every verdict,
    //! every boundary between them, both empty-set edges, and every way
    //! the register can refine (or refuse to refine) a structural
    //! `Supported`.

    use super::*;

    fn set(versions: &[i64]) -> BTreeSet<i64> {
        versions.iter().copied().collect()
    }

    /// The structural half on its own. The register layer is exercised by
    /// [`evaluate_with`] below; splitting the two keeps each block of
    /// assertions about one thing.
    fn evaluate(applied: &[i64], embedded: &[i64]) -> SchemaCompatibility {
        SchemaCompatibility::structural(&set(applied), &set(embedded))
    }

    /// The whole predicate, over a register spelled as `(version,
    /// Some("X.Y.Z") | None)` rows exactly as they sit in the table.
    fn evaluate_with(
        applied: &[i64],
        embedded: &[i64],
        rows: &[(i64, Option<&str>)],
        binary_version: &str,
    ) -> SchemaCompatibility {
        let register = register_from_rows(
            rows.iter()
                .map(|(version, minimum)| (*version, minimum.map(str::to_string))),
        );
        SchemaCompatibility::evaluate(&set(applied), &set(embedded), &register, binary_version)
    }

    // -- supported -----------------------------------------------------

    #[test]
    fn exact_match_is_supported_with_no_extras() {
        assert_eq!(
            evaluate(&[1, 2, 3], &[1, 2, 3]),
            SchemaCompatibility::Supported {
                newer_applied: vec![]
            }
        );
    }

    #[test]
    fn one_newer_applied_migration_is_supported() {
        assert_eq!(
            evaluate(&[1, 2, 3, 4], &[1, 2, 3]),
            SchemaCompatibility::Supported {
                newer_applied: vec![4]
            }
        );
    }

    #[test]
    fn several_newer_applied_migrations_are_supported() {
        assert_eq!(
            evaluate(&[1, 2, 3, 7, 9], &[1, 2, 3]),
            SchemaCompatibility::Supported {
                newer_applied: vec![7, 9]
            }
        );
    }

    /// A non-contiguous embedded sequence is normal (the migration
    /// numbering on disk has gaps). The extras only need to be newer than
    /// the newest embedded version, not adjacent to it.
    #[test]
    fn gaps_inside_the_shared_prefix_do_not_matter() {
        assert_eq!(
            evaluate(&[1, 5, 9, 12], &[1, 5, 9]),
            SchemaCompatibility::Supported {
                newer_applied: vec![12]
            }
        );
    }

    /// A binary that embeds no migrations at all is older than any schema.
    #[test]
    fn empty_embedded_set_against_a_migrated_database_is_supported() {
        assert_eq!(
            evaluate(&[1, 2], &[]),
            SchemaCompatibility::Supported {
                newer_applied: vec![1, 2]
            }
        );
    }

    #[test]
    fn both_sets_empty_is_supported() {
        assert_eq!(
            evaluate(&[], &[]),
            SchemaCompatibility::Supported {
                newer_applied: vec![]
            }
        );
    }

    #[test]
    fn supported_has_no_boot_refusal() {
        assert_eq!(evaluate(&[1, 2, 3], &[1, 2]).boot_refusal(), None);
    }

    // -- pending -------------------------------------------------------

    #[test]
    fn one_unapplied_newest_migration_is_pending() {
        assert_eq!(
            evaluate(&[1, 2], &[1, 2, 3]),
            SchemaCompatibility::Pending {
                pending: vec![3],
                newest_applied: 2,
                newest_embedded: 3,
            }
        );
    }

    #[test]
    fn several_unapplied_newest_migrations_are_pending() {
        assert_eq!(
            evaluate(&[1], &[1, 2, 3]),
            SchemaCompatibility::Pending {
                pending: vec![2, 3],
                newest_applied: 1,
                newest_embedded: 3,
            }
        );
    }

    /// A fresh database: the bookkeeping table exists but records nothing.
    /// `newest_applied` is `0`, which is the value the operator-facing
    /// message has always reported for this state.
    #[test]
    fn empty_applied_set_is_pending_with_zero_as_newest_applied() {
        assert_eq!(
            evaluate(&[], &[1, 2]),
            SchemaCompatibility::Pending {
                pending: vec![1, 2],
                newest_applied: 0,
                newest_embedded: 2,
            }
        );
    }

    #[test]
    fn pending_refusal_names_both_versions_and_the_corrective_action() {
        let refusal = evaluate(&[1, 2], &[1, 2, 3])
            .boot_refusal()
            .expect("pending must refuse");
        assert!(refusal.contains("schema version mismatch"), "{refusal}");
        assert!(refusal.contains("applied=2"), "{refusal}");
        assert!(refusal.contains("binary expects=3"), "{refusal}");
        assert!(refusal.contains("hort-server migrate"), "{refusal}");
    }

    // -- divergent -----------------------------------------------------

    /// An applied version the binary does not embed, sitting below the
    /// newest embedded version.
    #[test]
    fn applied_version_below_the_embedded_waterline_is_divergent() {
        assert_eq!(
            evaluate(&[1, 2, 3], &[1, 3]),
            SchemaCompatibility::Divergent(SchemaDivergence {
                applied_below_waterline: vec![2],
                unapplied_below_waterline: vec![],
                newest_applied: 3,
                newest_embedded: 3,
            })
        );
    }

    /// An embedded version the database never applied, sitting below the
    /// newest applied version.
    #[test]
    fn unapplied_version_below_the_applied_waterline_is_divergent() {
        assert_eq!(
            evaluate(&[1, 3], &[1, 2, 3]),
            SchemaCompatibility::Divergent(SchemaDivergence {
                applied_below_waterline: vec![],
                unapplied_below_waterline: vec![2],
                newest_applied: 3,
                newest_embedded: 3,
            })
        );
    }

    /// Both directions at once — the refusal names every offender.
    #[test]
    fn discrepancies_in_both_directions_are_divergent() {
        let verdict = evaluate(&[1, 2, 5], &[1, 3, 5]);
        assert_eq!(
            verdict,
            SchemaCompatibility::Divergent(SchemaDivergence {
                applied_below_waterline: vec![2],
                unapplied_below_waterline: vec![3],
                newest_applied: 5,
                newest_embedded: 5,
            })
        );
        let refusal = verdict.boot_refusal().expect("divergent must refuse");
        assert!(refusal.contains("divergent migration history"), "{refusal}");
        assert!(refusal.contains("migration(s) 2"), "{refusal}");
        assert!(refusal.contains("migration(s) 3"), "{refusal}");
    }

    /// The rollback shape with one extra defect in it: a newer schema is
    /// fine on its own, but a missing shared-prefix version is not.
    #[test]
    fn newer_schema_plus_a_gap_below_the_waterline_is_divergent() {
        assert_eq!(
            evaluate(&[1, 3, 4, 5], &[1, 2, 3]),
            SchemaCompatibility::Divergent(SchemaDivergence {
                applied_below_waterline: vec![],
                unapplied_below_waterline: vec![2],
                newest_applied: 5,
                newest_embedded: 3,
            })
        );
    }

    #[test]
    fn divergence_refusal_lists_every_offending_version() {
        let divergence = SchemaDivergence {
            applied_below_waterline: vec![4, 6],
            unapplied_below_waterline: vec![2],
            newest_applied: 9,
            newest_embedded: 8,
        };
        let refusal = divergence.refusal();
        assert!(refusal.contains("migration(s) 4, 6"), "{refusal}");
        assert!(refusal.contains("newest embedded version 8"), "{refusal}");
        assert!(refusal.contains("migration(s) 2"), "{refusal}");
        assert!(refusal.contains("newest applied version 9"), "{refusal}");
    }

    /// Only the direction that actually diverged is described — the
    /// message must not invent an empty clause.
    #[test]
    fn divergence_refusal_omits_the_clause_for_the_clean_direction() {
        let refusal = SchemaDivergence {
            applied_below_waterline: vec![2],
            unapplied_below_waterline: vec![],
            newest_applied: 3,
            newest_embedded: 3,
        }
        .refusal();
        assert!(refusal.contains("does not embed"), "{refusal}");
        assert!(!refusal.contains("has not applied"), "{refusal}");
    }

    // -- boundaries ----------------------------------------------------

    /// The exact boundary between `supported` and `divergent`: an extra
    /// applied version one step *above* the newest embedded one is
    /// supported; the same version one step *below* it is divergent.
    #[test]
    fn extra_applied_version_flips_verdict_at_the_embedded_waterline() {
        assert_eq!(
            evaluate(&[1, 2, 3], &[1, 2]),
            SchemaCompatibility::Supported {
                newer_applied: vec![3]
            }
        );
        assert!(matches!(
            evaluate(&[1, 2, 3], &[1, 3]),
            SchemaCompatibility::Divergent(_)
        ));
    }

    /// The mirror boundary: an unapplied embedded version above the newest
    /// applied one is pending; below it, divergent.
    #[test]
    fn unapplied_embedded_version_flips_verdict_at_the_applied_waterline() {
        assert!(matches!(
            evaluate(&[1, 2], &[1, 2, 3]),
            SchemaCompatibility::Pending { .. }
        ));
        assert!(matches!(
            evaluate(&[1, 3], &[1, 2, 3]),
            SchemaCompatibility::Divergent(_)
        ));
    }

    /// Single-element sets on both sides, the smallest possible skew in
    /// each direction.
    #[test]
    fn singleton_sets_cover_each_verdict() {
        assert_eq!(
            evaluate(&[7], &[7]),
            SchemaCompatibility::Supported {
                newer_applied: vec![]
            }
        );
        assert_eq!(
            evaluate(&[7, 8], &[7]),
            SchemaCompatibility::Supported {
                newer_applied: vec![8]
            }
        );
        assert_eq!(
            evaluate(&[7], &[7, 8]),
            SchemaCompatibility::Pending {
                pending: vec![8],
                newest_applied: 7,
                newest_embedded: 8,
            }
        );
        assert!(matches!(
            evaluate(&[8], &[7]),
            SchemaCompatibility::Divergent(_)
        ));
    }

    /// Disjoint sets where the applied side is entirely older: every
    /// embedded version sits above the newest applied one, so there is no
    /// below-the-waterline offender in the embedded direction, but the
    /// applied side has no embedded counterpart at all.
    #[test]
    fn disjoint_sets_with_older_applied_side_are_divergent() {
        assert_eq!(
            evaluate(&[1, 2], &[3, 4]),
            SchemaCompatibility::Divergent(SchemaDivergence {
                applied_below_waterline: vec![1, 2],
                unapplied_below_waterline: vec![],
                newest_applied: 2,
                newest_embedded: 4,
            })
        );
    }

    /// Disjoint the other way: every applied version is newer than
    /// everything embedded, so the embedded side is entirely unapplied and
    /// below the applied waterline.
    #[test]
    fn disjoint_sets_with_newer_applied_side_are_divergent() {
        assert_eq!(
            evaluate(&[3, 4], &[1, 2]),
            SchemaCompatibility::Divergent(SchemaDivergence {
                applied_below_waterline: vec![],
                unapplied_below_waterline: vec![1, 2],
                newest_applied: 4,
                newest_embedded: 2,
            })
        );
    }

    // -- register: row interpretation ----------------------------------

    #[test]
    fn a_null_minimum_reads_back_as_an_expansion() {
        let register = register_from_rows([(4, None), (5, Some("0.13.0".to_string()))]);
        assert_eq!(register.get(&4), Some(&MigrationTolerance::Expansion));
        assert_eq!(
            register.get(&5),
            Some(&MigrationTolerance::MinimumBinary("0.13.0".to_string()))
        );
        assert_eq!(register.get(&6), None, "an unwritten version stays absent");
    }

    // -- register: the refined verdict ---------------------------------

    /// The whole point: however many releases of expansions separate the
    /// binary from the schema, it boots.
    #[test]
    fn many_expansions_ahead_stay_supported() {
        let rows = [(4, None), (5, None), (6, None), (7, None), (8, None)];
        assert_eq!(
            evaluate_with(&[1, 2, 3, 4, 5, 6, 7, 8], &[1, 2, 3], &rows, "0.12.0"),
            SchemaCompatibility::Supported {
                newer_applied: vec![4, 5, 6, 7, 8]
            }
        );
    }

    /// An exactly-matching binary version clears the bound: the recorded
    /// minimum is the oldest version that *tolerates* the migration, not
    /// the oldest that fails it.
    #[test]
    fn binary_exactly_at_the_recorded_minimum_is_supported() {
        assert_eq!(
            evaluate_with(&[1, 4], &[1], &[(4, Some("0.13.0"))], "0.13.0"),
            SchemaCompatibility::Supported {
                newer_applied: vec![4]
            }
        );
    }

    /// A pre-release of the release the minimum names sorts as that
    /// release — the same `parse_version_core` rule the fleet fence uses.
    #[test]
    fn prerelease_of_the_required_version_clears_the_bound() {
        assert!(matches!(
            evaluate_with(&[1, 4], &[1], &[(4, Some("0.13.0"))], "0.13.0-dev"),
            SchemaCompatibility::Supported { .. }
        ));
    }

    #[test]
    fn binary_below_the_recorded_minimum_is_intolerable() {
        assert_eq!(
            evaluate_with(&[1, 4], &[1], &[(4, Some("0.13.0"))], "0.12.4"),
            SchemaCompatibility::Intolerable(SchemaRollbackBound {
                blocking: vec![BlockingMigration {
                    version: 4,
                    minimum_binary: Some("0.13.0".to_string()),
                }],
                binary_version: "0.12.4".to_string(),
            })
        );
    }

    /// Fail closed: an applied migration the binary does not embed and the
    /// register does not cover is assumed to be a contraction.
    #[test]
    fn an_unregistered_newer_migration_is_intolerable() {
        assert_eq!(
            evaluate_with(&[1, 4], &[1], &[], "9.9.9"),
            SchemaCompatibility::Intolerable(SchemaRollbackBound {
                blocking: vec![BlockingMigration {
                    version: 4,
                    minimum_binary: None,
                }],
                binary_version: "9.9.9".to_string(),
            })
        );
    }

    /// Fail closed on this binary's own version too: a version string that
    /// does not parse meets no recorded minimum.
    #[test]
    fn an_unparseable_binary_version_meets_no_minimum() {
        assert!(matches!(
            evaluate_with(&[1, 4], &[1], &[(4, Some("0.1.0"))], "not-a-version"),
            SchemaCompatibility::Intolerable(_)
        ));
    }

    /// Fail closed on the recorded value as well — a minimum that does not
    /// parse cannot be shown to be met.
    #[test]
    fn an_unparseable_recorded_minimum_blocks() {
        assert!(matches!(
            evaluate_with(&[1, 4], &[1], &[(4, Some("thirteen"))], "9.9.9"),
            SchemaCompatibility::Intolerable(_)
        ));
    }

    /// Only the migrations that actually block appear in the bound; the
    /// expansions around them are not named.
    #[test]
    fn only_the_blocking_migrations_are_collected() {
        let rows = [
            (4, None),
            (5, Some("0.13.0")),
            (6, None),
            (7, Some("0.14.0")),
        ];
        let verdict = evaluate_with(&[1, 4, 5, 6, 7], &[1], &rows, "0.12.0");
        let SchemaCompatibility::Intolerable(bound) = verdict else {
            panic!("expected an intolerable verdict, got {verdict:?}");
        };
        assert_eq!(
            bound.blocking.iter().map(|b| b.version).collect::<Vec<_>>(),
            vec![5, 7]
        );
    }

    /// The register never affects a verdict that carries no
    /// applied-but-unembedded migration — an exact match, a pending
    /// upgrade, and a divergent history all pass through untouched.
    #[test]
    fn the_register_does_not_touch_the_other_verdicts() {
        assert_eq!(
            evaluate_with(&[1, 2], &[1, 2], &[], "0.1.0"),
            SchemaCompatibility::Supported {
                newer_applied: vec![]
            }
        );
        assert!(matches!(
            evaluate_with(&[1], &[1, 2], &[], "0.1.0"),
            SchemaCompatibility::Pending { .. }
        ));
        assert!(matches!(
            evaluate_with(&[1, 3], &[1, 2, 3], &[], "0.1.0"),
            SchemaCompatibility::Divergent(_)
        ));
    }

    /// A register row for a migration the binary *does* embed is ignored:
    /// the binary carries that migration, so it cannot be broken by it.
    #[test]
    fn rows_for_embedded_migrations_do_not_block() {
        assert_eq!(
            evaluate_with(&[1, 2], &[1, 2], &[(2, Some("99.0.0"))], "0.1.0"),
            SchemaCompatibility::Supported {
                newer_applied: vec![]
            }
        );
    }

    // -- register: the refusal message ---------------------------------

    #[test]
    fn intolerable_refusal_names_the_migration_and_the_required_version() {
        let refusal = evaluate_with(&[1, 4], &[1], &[(4, Some("0.13.0"))], "0.12.4")
            .boot_refusal()
            .expect("intolerable must refuse");
        assert!(refusal.contains("migration 4"), "{refusal}");
        assert!(refusal.contains("0.13.0 or newer"), "{refusal}");
        assert!(refusal.contains("(0.12.4)"), "{refusal}");
        assert!(
            refusal.contains("forward-only"),
            "the message must close off the schema-rollback non-option: {refusal}"
        );
    }

    /// The refusal is read mid-incident and is the operator's whole
    /// recovery path, so both wordings are pinned verbatim rather than by
    /// substring — a refactor that drops the migration number, the
    /// required version, or the "no schema rollback" clause fails here.
    #[test]
    fn the_two_refusal_wordings_are_pinned_verbatim() {
        assert_eq!(
            evaluate_with(&[1, 4], &[1], &[(4, Some("0.13.0"))], "0.12.4")
                .boot_refusal()
                .expect("intolerable must refuse"),
            "schema is newer than this binary (0.12.4) tolerates: migration 4 requires a binary \
             of version 0.13.0 or newer. Run a binary of version 0.13.0 or newer against this \
             database, or restore a backup taken before those migrations were applied — \
             migrations are forward-only, so the schema itself cannot be rolled back. Each \
             migration's own record is its migrations/CONTRACTIONS.toml entry in the release \
             that shipped it."
        );
        assert_eq!(
            evaluate_with(&[1, 4], &[1], &[], "0.12.4")
                .boot_refusal()
                .expect("intolerable must refuse"),
            "schema is newer than this binary (0.12.4) tolerates: migration 4 is absent from the \
             schema compatibility register, so it must be assumed to have removed something this \
             binary still references. Run the release that applied those migrations (or newer) \
             against this database, or restore a backup taken before they were applied — \
             migrations are forward-only, so the schema itself cannot be rolled back. Each \
             migration's own record is its migrations/CONTRACTIONS.toml entry in the release \
             that shipped it."
        );
    }

    #[test]
    fn unregistered_refusal_says_so_and_offers_no_version() {
        let refusal = evaluate_with(&[1, 4], &[1], &[], "0.12.4")
            .boot_refusal()
            .expect("intolerable must refuse");
        assert!(refusal.contains("migration 4"), "{refusal}");
        assert!(
            refusal.contains("absent from the schema compatibility register"),
            "{refusal}"
        );
        assert!(
            refusal.contains("the release that applied those migrations"),
            "an unknown minimum must still leave the operator a next step: {refusal}"
        );
    }

    /// The governing bound is the strongest one, and it is what the remedy
    /// clause names.
    #[test]
    fn required_version_is_the_maximum_over_the_blocking_set() {
        let bound = SchemaRollbackBound {
            blocking: vec![
                BlockingMigration {
                    version: 5,
                    minimum_binary: Some("0.13.0".to_string()),
                },
                BlockingMigration {
                    version: 7,
                    minimum_binary: Some("0.14.2".to_string()),
                },
                BlockingMigration {
                    version: 9,
                    minimum_binary: Some("0.13.9".to_string()),
                },
            ],
            binary_version: "0.12.0".to_string(),
        };
        assert_eq!(bound.required_binary_version(), Some("0.14.2"));
        let refusal = bound.refusal();
        assert!(refusal.contains("migration 5"), "{refusal}");
        assert!(refusal.contains("migration 7"), "{refusal}");
        assert!(refusal.contains("migration 9"), "{refusal}");
        assert!(refusal.contains("version 0.14.2 or newer"), "{refusal}");
    }

    /// One unregistered blocker makes the whole requirement unknown, even
    /// alongside registered ones — the unknown one could require more.
    #[test]
    fn one_unregistered_blocker_makes_the_requirement_unknown() {
        let bound = SchemaRollbackBound {
            blocking: vec![
                BlockingMigration {
                    version: 5,
                    minimum_binary: Some("0.13.0".to_string()),
                },
                BlockingMigration {
                    version: 7,
                    minimum_binary: None,
                },
            ],
            binary_version: "0.12.0".to_string(),
        };
        assert_eq!(bound.required_binary_version(), None);
    }

    #[test]
    fn an_unparseable_recorded_minimum_makes_the_requirement_unknown() {
        let bound = SchemaRollbackBound {
            blocking: vec![BlockingMigration {
                version: 5,
                minimum_binary: Some("thirteen".to_string()),
            }],
            binary_version: "0.12.0".to_string(),
        };
        assert_eq!(bound.required_binary_version(), None);
    }

    // -- the inspection answer -----------------------------------------

    #[test]
    fn rollback_floor_is_the_strongest_recorded_minimum() {
        let register = register_from_rows([
            (1, None),
            (2, Some("0.12.0".to_string())),
            (3, Some("0.11.4".to_string())),
            (4, None),
        ]);
        assert_eq!(
            schema_rollback_floor(&set(&[1, 2, 3, 4]), &register),
            SchemaRollbackFloor::Version("0.12.0".to_string())
        );
    }

    /// An unregistered sibling dominates a recorded minimum, exactly as
    /// `required_binary_version` treats it: the unregistered one could
    /// require more, so the answer is unknown regardless of what the
    /// registered one records.
    #[test]
    fn rollback_floor_lets_an_unregistered_sibling_override_a_recorded_minimum() {
        let register = register_from_rows([(2, Some("0.12.0".to_string()))]);
        assert_eq!(
            schema_rollback_floor(&set(&[1, 2]), &register),
            SchemaRollbackFloor::Indeterminate
        );
    }

    /// Only the applied set counts — a row for a migration this database
    /// has not applied says nothing about what it tolerates. Here neither
    /// applied version has a row of its own, so the register cannot answer.
    #[test]
    fn rollback_floor_ignores_rows_outside_the_applied_set() {
        let register = register_from_rows([(9, Some("99.0.0".to_string()))]);
        assert_eq!(
            schema_rollback_floor(&set(&[1, 2]), &register),
            SchemaRollbackFloor::Indeterminate
        );
    }

    #[test]
    fn rollback_floor_is_unconstrained_when_every_row_is_an_expansion() {
        let register = register_from_rows([(1, None), (2, None)]);
        assert_eq!(
            schema_rollback_floor(&set(&[1, 2]), &register),
            SchemaRollbackFloor::Unconstrained
        );
    }

    #[test]
    fn rollback_floor_skips_an_unparseable_recorded_minimum() {
        let register = register_from_rows([
            (1, Some("thirteen".to_string())),
            (2, Some("0.12.0".to_string())),
        ]);
        assert_eq!(
            schema_rollback_floor(&set(&[1, 2]), &register),
            SchemaRollbackFloor::Version("0.12.0".to_string())
        );
        let only_garbage = register_from_rows([(1, Some("thirteen".to_string()))]);
        assert_eq!(
            schema_rollback_floor(&set(&[1]), &only_garbage),
            SchemaRollbackFloor::Unconstrained
        );
    }

    /// The report and the refusal are two views of the same register rows
    /// over the same applied set, and they must agree: an operator who
    /// reads the report's version and rolls back to it must not then hit a
    /// refusal that calls the requirement unknown. `blocking` here mirrors
    /// exactly what `refine_with_register` builds from an applied set that
    /// is entirely "newer than embedded" — an `Expansion` row is tolerated
    /// by any binary and excluded, a recorded minimum is carried through,
    /// and a missing row carries no minimum at all.
    #[test]
    fn rollback_floor_agrees_with_the_refusal_over_the_same_applied_set() {
        fn required_binary_version_for(
            register: &SchemaCompatRegister,
            applied: &[i64],
        ) -> Option<String> {
            let blocking: Vec<BlockingMigration> = applied
                .iter()
                .filter_map(|version| match register.get(version) {
                    Some(MigrationTolerance::Expansion) => None,
                    Some(MigrationTolerance::MinimumBinary(minimum)) => Some(BlockingMigration {
                        version: *version,
                        minimum_binary: Some(minimum.clone()),
                    }),
                    None => Some(BlockingMigration {
                        version: *version,
                        minimum_binary: None,
                    }),
                })
                .collect();
            if blocking.is_empty() {
                return None;
            }
            SchemaRollbackBound {
                blocking,
                binary_version: "0.0.0".to_string(),
            }
            .required_binary_version()
            .map(str::to_string)
        }

        // A recorded minimum alongside an unregistered sibling: the report
        // must say Indeterminate, matching the refusal's unknown.
        let mixed = register_from_rows([(2, Some("0.12.0".to_string()))]);
        assert_eq!(
            schema_rollback_floor(&set(&[1, 2]), &mixed),
            SchemaRollbackFloor::Indeterminate
        );
        assert_eq!(required_binary_version_for(&mixed, &[1, 2]), None);

        // Every applied migration registered: the report's version must be
        // the same version the refusal would require.
        let all_registered = register_from_rows([
            (1, None),
            (2, Some("0.12.0".to_string())),
            (3, Some("0.11.4".to_string())),
            (4, None),
        ]);
        assert_eq!(
            schema_rollback_floor(&set(&[1, 2, 3, 4]), &all_registered),
            SchemaRollbackFloor::Version("0.12.0".to_string())
        );
        assert_eq!(
            required_binary_version_for(&all_registered, &[1, 2, 3, 4]),
            Some("0.12.0".to_string())
        );
    }

    #[test]
    fn rollback_floor_renders_for_the_boot_log() {
        assert_eq!(
            SchemaRollbackFloor::Unconstrained.to_string(),
            "unconstrained"
        );
        assert_eq!(
            SchemaRollbackFloor::Indeterminate.to_string(),
            "indeterminate"
        );
        assert_eq!(
            SchemaRollbackFloor::Version("0.12.0".to_string()).to_string(),
            "0.12.0"
        );
    }
}
