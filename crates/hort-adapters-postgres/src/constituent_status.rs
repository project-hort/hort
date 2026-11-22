//! PostgreSQL implementation of the constituent-deliverability read: one
//! statement that turns a document's closure into the strongest terminal
//! verdict inside it, and one that answers the same question per
//! constituent for the side that has to record each one (see *Two
//! statements, one derivation* below).
//!
//! # Why the hash set is a CTE and not `= ANY($2)`
//!
//! The membership test reads naturally as
//! `WHERE checksum_sha256 = ANY($2::text[])`, and that form is a latency
//! trap under a prepared statement. Postgres folds bound parameters into
//! constants only while it is building **custom** plans; once the
//! statement flips to a **generic** plan — which it does from the sixth
//! execution on a pooled connection, and a server pool keeps connections
//! open for days — `$2` stays a `Param`, the array can no longer be
//! hashed, and the filter degrades to a linear scan of the whole array
//! for every candidate row, with nothing in the query, the data or the
//! configuration having changed. The project has measured the cliff on
//! its own corpus at 1.7 s as a join against 64.2 s as an array filter
//! (see [`crate::retention_preview`] and
//! [`crate::event_repository_resolver`], the same rewrite for the same
//! reason). Unnesting the array into a CTE expresses the identical set
//! and plans as a join under both plan types. Do not "simplify" it back
//! to `= ANY`.
//!
//! # Why the statement spells out no status
//!
//! The terminal vocabulary is bound, not written: the array comes from
//! [`terminal_status_binding`], which filters `QuarantineStatus::ALL`
//! through `QuarantineStatus::is_terminal` and encodes each survivor
//! through `quarantine_status_to_sql` — the one author of this column's
//! stored vocabulary, and the one derivation of this array. A literal
//! `IN ('rejected','scan_indeterminate')` here would be a second
//! definition of `is_terminal`, and a sixth `QuarantineStatus` variant
//! would leave it narrower than the predicate with nothing failing. The
//! array also carries the **order**: `WITH ORDINALITY` turns the
//! Rust-side refusal precedence into the `ORDER BY` key, so the
//! strongest verdict is picked in SQL without SQL knowing which one that
//! is. `crates/hort-adapters-postgres/tests/terminal_status_set_is_derived.rs`
//! is the DB-free guard over both halves.
//!
//! # Determinism
//!
//! `HEAD` and `GET` resolve the same closure and must name the same
//! constituent, so the tie inside one status class is broken by the
//! caller's own ordering — the closure order the second `WITH ORDINALITY`
//! preserves (config before layers, a parent before its children), which
//! is also the most useful one to report.
//!
//! # Liveness, not identity
//!
//! The row filter is `deleted_at IS NULL`, matching every live
//! `ArtifactRepository` read. Deliverability is exactly the question
//! those reads answer, so a soft-deleted row is as absent here as it is
//! there — and absence is not a hold.
//!
//! # Two statements, one derivation
//!
//! [`ConstituentStatusReader::terminal_constituents`] answers the same
//! question **per hash**, for the admission side: its refusal names one
//! constituent, so its per-reference log is the record of the others and
//! has to come from this derivation rather than from a lookup with a
//! selection of its own. It is a second statement rather than a filter
//! over the first because the two have different budgets — a manifest
//! read wants one row off the registry's hottest path and can stop at
//! it, where the per-hash form has to rank the whole matched set first.
//!
//! What must not become two is the **derivation**: both statements bind
//! [`terminal_status_binding`] for the vocabulary *and* the order, both
//! unnest it with `WITH ORDINALITY`, and both rank by
//! `(t.precedence, w.position)`. Their agreement is pinned at runtime —
//! `the_two_statements_agree_on_the_strongest_constituent` drives a mixed
//! corpus through both and asserts the per-hash answer's first entry is
//! the single-answer one — and structurally by
//! `crates/hort-adapters-postgres/tests/terminal_status_set_is_derived.rs`,
//! which asserts every statement in this file, not a named one.

use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::constituent_status::{ConstituentStatusReader, TerminalConstituent};
use hort_domain::types::ContentHash;

use crate::quarantine_status_sql::{quarantine_status_from_sql, terminal_status_binding};
use crate::{map_sqlx_error, BoxFuture};

/// The single-answer statement, for
/// [`ConstituentStatusReader::strongest_terminal_constituent`]. Hoisted to
/// a `const` so the DB-free guard can read it without lexing the method
/// body around it.
const STRONGEST_TERMINAL_CONSTITUENT_SQL: &str = r#"
    WITH wanted AS (
        SELECT content_hash, position
          FROM unnest($2::text[]) WITH ORDINALITY AS w(content_hash, position)
    ),
    terminal AS (
        SELECT status, precedence
          FROM unnest($3::text[]) WITH ORDINALITY AS t(status, precedence)
    )
    SELECT a.checksum_sha256 AS content_hash,
           a.quarantine_status AS quarantine_status
      FROM artifacts a
      JOIN wanted w ON w.content_hash = a.checksum_sha256
      JOIN terminal t ON t.status = a.quarantine_status
     WHERE a.repository_id = $1
       AND a.deleted_at IS NULL
     ORDER BY t.precedence, w.position
     LIMIT 1
"#;

/// The per-hash statement, for
/// [`ConstituentStatusReader::terminal_constituents`]. Same CTEs, same
/// binding, and the ranking key written in the same spelling as
/// [`STRONGEST_TERMINAL_CONSTITUENT_SQL`]'s — what differs is only how
/// much of the ranking survives: `rank = 1` keeps the strongest row
/// **per hash** where the sibling's `LIMIT 1` keeps the strongest row
/// overall, and the outer `ORDER BY` then re-imposes the same order over
/// those survivors, so the first entry is what the sibling answers.
///
/// `row_number()` over the partition rather than `DISTINCT ON`, because
/// `DISTINCT ON` would force the hash into the leading `ORDER BY`
/// position and the key would no longer be the one literal the DB-free
/// guard holds both statements to — a formulation in which two orders
/// cannot look identical is a formulation in which they can drift.
///
/// Hoisted beside its sibling so the DB-free guard reads both out of
/// this file without lexing a method body.
const TERMINAL_CONSTITUENTS_SQL: &str = r#"
    WITH wanted AS (
        SELECT content_hash, position
          FROM unnest($2::text[]) WITH ORDINALITY AS w(content_hash, position)
    ),
    terminal AS (
        SELECT status, precedence
          FROM unnest($3::text[]) WITH ORDINALITY AS t(status, precedence)
    ),
    ranked AS (
        SELECT a.checksum_sha256 AS content_hash,
               a.quarantine_status AS quarantine_status,
               t.precedence AS precedence,
               w.position AS position,
               row_number() OVER (
                   PARTITION BY w.content_hash
                       ORDER BY t.precedence, w.position
               ) AS rank
          FROM artifacts a
          JOIN wanted w ON w.content_hash = a.checksum_sha256
          JOIN terminal t ON t.status = a.quarantine_status
         WHERE a.repository_id = $1
           AND a.deleted_at IS NULL
    )
    SELECT content_hash, quarantine_status
      FROM ranked
     WHERE rank = 1
     ORDER BY precedence, position
"#;

/// Read-only Postgres reader for the constituent-deliverability question.
pub struct PgConstituentStatusReader {
    pool: PgPool,
}

impl PgConstituentStatusReader {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The terminal statuses in their stored spelling, strongest first —
    /// the `$3` binding.
    ///
    /// `pub` so the DB-free guard
    /// (`tests/terminal_status_set_is_derived.rs`) can assert the binding
    /// against the domain predicate directly rather than inferring it
    /// from the statement text. Nothing in production calls it except
    /// the two queries below, which bind it identically — that identity
    /// is the whole of why there is one derivation and not one per
    /// statement.
    ///
    /// The derivation itself lives in
    /// [`crate::quarantine_status_sql`] — beside the encoder it uses —
    /// because a second query now binds the same array (the list
    /// surfaces' census), and the crate holds one derivation of it
    /// rather than one per consumer.
    #[must_use]
    pub fn terminal_status_binding() -> Vec<String> {
        terminal_status_binding()
    }
}

impl ConstituentStatusReader for PgConstituentStatusReader {
    fn strongest_terminal_constituent<'a>(
        &'a self,
        repository_id: Uuid,
        constituents: &'a [ContentHash],
    ) -> BoxFuture<'a, DomainResult<Option<TerminalConstituent>>> {
        let hashes: Vec<String> = constituents
            .iter()
            .map(|hash| hash.as_ref().to_string())
            .collect();
        Box::pin(async move {
            // A document that binds nothing asks about nothing; do not
            // spend a round trip proving it.
            if hashes.is_empty() {
                return Ok(None);
            }
            tracing::debug!(
                %repository_id,
                constituent_count = hashes.len(),
                "strongest_terminal_constituent"
            );
            let row = sqlx::query(STRONGEST_TERMINAL_CONSTITUENT_SQL)
                .bind(repository_id)
                .bind(&hashes)
                .bind(Self::terminal_status_binding())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "constituent_status", "strongest_terminal"))?;
            let Some(row) = row else {
                return Ok(None);
            };
            decode_constituent(&row, repository_id).map(Some)
        })
    }

    fn terminal_constituents<'a>(
        &'a self,
        repository_id: Uuid,
        constituents: &'a [ContentHash],
    ) -> BoxFuture<'a, DomainResult<Vec<TerminalConstituent>>> {
        let hashes: Vec<String> = constituents
            .iter()
            .map(|hash| hash.as_ref().to_string())
            .collect();
        Box::pin(async move {
            // Same short-circuit as the sibling above, for the same
            // reason: a document that binds nothing asks about nothing.
            if hashes.is_empty() {
                return Ok(Vec::new());
            }
            tracing::debug!(
                %repository_id,
                constituent_count = hashes.len(),
                "terminal_constituents"
            );
            let rows = sqlx::query(TERMINAL_CONSTITUENTS_SQL)
                .bind(repository_id)
                .bind(&hashes)
                .bind(Self::terminal_status_binding())
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "constituent_status", "terminal_constituents"))?;
            rows.iter()
                .map(|row| decode_constituent(row, repository_id))
                .collect()
        })
    }
}

/// The two columns both statements project, decoded once.
///
/// Shared rather than written per method: the status goes through
/// [`quarantine_status_from_sql`], the one reader of this column's stored
/// vocabulary, and a second hand-written decode is a second place for a
/// legacy spelling to be tolerated differently.
fn decode_constituent(
    row: &sqlx::postgres::PgRow,
    repository_id: Uuid,
) -> DomainResult<TerminalConstituent> {
    let raw_hash: String = row
        .try_get("content_hash")
        .map_err(|e| decode_error("content_hash", &e))?;
    let raw_status: Option<String> = row
        .try_get("quarantine_status")
        .map_err(|e| decode_error("quarantine_status", &e))?;
    let content_hash: ContentHash = raw_hash.parse()?;
    let status = quarantine_status_from_sql(raw_status.as_deref(), || {
        format!("constituent {content_hash} of a document in repository {repository_id}")
    })?;
    Ok(TerminalConstituent {
        content_hash,
        status,
    })
}

fn decode_error(column: &str, e: &sqlx::Error) -> DomainError {
    DomainError::Invariant(format!("constituent_status row decode ({column}): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use hort_domain::entities::artifact::QuarantineStatus;
    use serial_test::serial;

    use crate::quarantine_status_sql::quarantine_status_to_sql;

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;
        Some(pool)
    }

    async fn seed_repo(pool: &PgPool) -> Uuid {
        let key = format!("repo-{}", Uuid::new_v4());
        sqlx::query_scalar(
            r#"INSERT INTO repositories (
                   key, name, format, repo_type, storage_backend, storage_path,
                   replication_priority
               ) VALUES (
                   $1, $1, 'oci', 'hosted', 'filesystem', $2, 'local_only'
               ) RETURNING id"#,
        )
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .fetch_one(pool)
        .await
        .expect("seed repository")
    }

    /// Seed one artifact row carrying `status` (and optionally retired)
    /// at a synthetic content hash.
    async fn seed_artifact(
        pool: &PgPool,
        repo: Uuid,
        hex_seed: char,
        status: QuarantineStatus,
        deleted: bool,
    ) -> ContentHash {
        let hash: ContentHash = std::iter::repeat_n(hex_seed, 64)
            .collect::<String>()
            .parse()
            .expect("synthetic sha256");
        let name = format!("pkg-{}", Uuid::new_v4());
        sqlx::query(
            r#"INSERT INTO artifacts (
                   repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   quarantine_status, deleted_at
               ) VALUES (
                   $1, $2, $2, '1.0.0', $3,
                   1, $4, 'application/octet-stream', $3,
                   $5, CASE WHEN $6 THEN now() ELSE NULL END
               )"#,
        )
        .bind(repo)
        .bind(&name)
        .bind(format!("{name}/{hash}"))
        .bind(hash.as_ref())
        .bind(quarantine_status_to_sql(status))
        .bind(deleted)
        .execute(pool)
        .await
        .expect("seed artifact");
        hash
    }

    /// Every non-terminal status answers "nothing terminal here", and
    /// every terminal one answers with itself. Driven off
    /// `QuarantineStatus::ALL` rather than a hand-written list, so the
    /// live behaviour is pinned against the predicate over the whole
    /// vocabulary — the same property the DB-free guard asserts about the
    /// binding.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn every_status_answers_according_to_the_terminal_predicate() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let reader = PgConstituentStatusReader::new(pool.clone());
        for (index, status) in QuarantineStatus::ALL.into_iter().enumerate() {
            let repo = seed_repo(&pool).await;
            let hex = char::from_digit(index as u32, 16).expect("index fits a hex digit");
            let hash = seed_artifact(&pool, repo, hex, status, false).await;
            let answer = reader
                .strongest_terminal_constituent(repo, std::slice::from_ref(&hash))
                .await
                .expect("the read succeeds");
            // Both statements, every status: the per-hash one asks the
            // same question of the same column and must not come out
            // narrower or wider for any member of the vocabulary.
            let per_hash = reader
                .terminal_constituents(repo, std::slice::from_ref(&hash))
                .await
                .expect("the read succeeds");
            if status.is_terminal() {
                assert_eq!(
                    answer,
                    Some(TerminalConstituent {
                        content_hash: hash.clone(),
                        status
                    }),
                    "{status} is terminal and must be reported"
                );
                assert_eq!(
                    per_hash,
                    vec![TerminalConstituent {
                        content_hash: hash,
                        status
                    }],
                    "{status} is terminal and must be reported per hash too"
                );
            } else {
                assert_eq!(answer, None, "{status} is not terminal and must not hold");
                assert_eq!(
                    per_hash,
                    Vec::new(),
                    "{status} is not terminal and must not hold per hash either"
                );
            }
        }
    }

    /// Absence is not a hold: a hash with no row at all answers `None`.
    /// This is the cold-pull-through arm — inverting it refuses every
    /// manifest whose blobs have not arrived yet.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_hash_with_no_row_is_not_a_hold() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let absent: ContentHash = "f".repeat(64).parse().expect("synthetic sha256");
        let reader = PgConstituentStatusReader::new(pool);
        assert_eq!(
            reader
                .strongest_terminal_constituent(repo, std::slice::from_ref(&absent))
                .await
                .expect("the read succeeds"),
            None
        );
        assert_eq!(
            reader
                .terminal_constituents(repo, &[absent])
                .await
                .expect("the read succeeds"),
            Vec::new(),
            "a hash with no row has no entry — absence is not a hold on either statement"
        );
    }

    /// A retired row is absent too — the live `ArtifactRepository` reads
    /// filter `deleted_at IS NULL`, and deliverability is their question.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_soft_deleted_terminal_row_is_not_a_hold() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let hash = seed_artifact(&pool, repo, 'a', QuarantineStatus::Rejected, true).await;
        let reader = PgConstituentStatusReader::new(pool);
        assert_eq!(
            reader
                .strongest_terminal_constituent(repo, std::slice::from_ref(&hash))
                .await
                .expect("the read succeeds"),
            None
        );
        assert_eq!(
            reader
                .terminal_constituents(repo, &[hash])
                .await
                .expect("the read succeeds"),
            Vec::new(),
            "a retired row is absent on both statements"
        );
    }

    /// The same bytes rejected in **another** repository do not hold this
    /// one's manifest back: the question is per repository, as every
    /// other artifact read is.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_terminal_row_in_another_repository_is_not_a_hold() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let theirs = seed_repo(&pool).await;
        let mine = seed_repo(&pool).await;
        let hash = seed_artifact(&pool, theirs, 'b', QuarantineStatus::Rejected, false).await;
        let reader = PgConstituentStatusReader::new(pool);
        assert_eq!(
            reader
                .strongest_terminal_constituent(mine, std::slice::from_ref(&hash))
                .await
                .expect("the read succeeds"),
            None
        );
        assert_eq!(
            reader
                .terminal_constituents(mine, &[hash])
                .await
                .expect("the read succeeds"),
            Vec::new(),
            "the question is per repository on both statements"
        );
    }

    /// With both terminal classes present the refusal reports the
    /// stronger one, whatever order the caller listed them in.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn rejected_wins_over_scan_indeterminate_in_either_listing_order() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let rejected = seed_artifact(&pool, repo, 'c', QuarantineStatus::Rejected, false).await;
        let indeterminate =
            seed_artifact(&pool, repo, 'd', QuarantineStatus::ScanIndeterminate, false).await;
        let reader = PgConstituentStatusReader::new(pool);
        for order in [
            vec![rejected.clone(), indeterminate.clone()],
            vec![indeterminate.clone(), rejected.clone()],
        ] {
            assert_eq!(
                reader
                    .strongest_terminal_constituent(repo, &order)
                    .await
                    .expect("the read succeeds"),
                Some(TerminalConstituent {
                    content_hash: rejected.clone(),
                    status: QuarantineStatus::Rejected
                })
            );
        }
    }

    /// Inside one status class the caller's ordering decides, so `HEAD`
    /// and `GET` over the same closure name the same constituent. The
    /// closure order is config first, which is the population this issue
    /// is about.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn ties_inside_a_class_follow_the_callers_closure_order() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let first = seed_artifact(&pool, repo, 'e', QuarantineStatus::Rejected, false).await;
        let second = seed_artifact(&pool, repo, '1', QuarantineStatus::Rejected, false).await;
        let reader = PgConstituentStatusReader::new(pool);
        for leading in [&first, &second] {
            let other = if leading == &first { &second } else { &first };
            let answer = reader
                .strongest_terminal_constituent(repo, &[leading.clone(), other.clone()])
                .await
                .expect("the read succeeds")
                .expect("a rejected constituent is reported");
            assert_eq!(
                &answer.content_hash, leading,
                "the first constituent in closure order is the one reported"
            );
        }
    }

    /// How many live rows the repository holds for `hash` — the premise
    /// of every twin test below, asserted rather than assumed: a fixture
    /// that made one row proves nothing about a selection between two.
    async fn live_row_count(pool: &PgPool, repo: Uuid, hash: &ContentHash) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts \
             WHERE repository_id = $1 AND checksum_sha256 = $2 AND deleted_at IS NULL",
        )
        .bind(repo)
        .bind(hash.as_ref())
        .fetch_one(pool)
        .await
        .expect("count the rows for the hash")
    }

    /// **One hash, two live rows, independent statuses: the strongest
    /// verdict answers.** `artifacts` is unique on
    /// `(repository_id, path)` and not on the checksum, so a repository
    /// legitimately holds a blob row and a manifest row for one set of
    /// bytes. An identity lookup over them is a `LIMIT 1` with no
    /// `ORDER BY` and answers with either; this statement joins both and
    /// ranks them, so the answer is the verdict and not the plan's
    /// choice.
    ///
    /// Seeded in both orders because a statement that happened to return
    /// rows in insertion order would pass one of them by luck.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_strongest_row_answers_when_one_hash_is_held_by_two_rows() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        for (first, second) in [
            (QuarantineStatus::Rejected, QuarantineStatus::Released),
            (QuarantineStatus::Released, QuarantineStatus::Rejected),
        ] {
            let repo = seed_repo(&pool).await;
            let hash = seed_artifact(&pool, repo, 'a', first, false).await;
            let twin = seed_artifact(&pool, repo, 'a', second, false).await;
            assert_eq!(twin, hash, "the two rows must carry the same hash");
            assert_eq!(
                live_row_count(&pool, repo, &hash).await,
                2,
                "the premise is two live rows for one hash"
            );
            let reader = PgConstituentStatusReader::new(pool.clone());
            let expected = TerminalConstituent {
                content_hash: hash.clone(),
                status: QuarantineStatus::Rejected,
            };
            assert_eq!(
                reader
                    .strongest_terminal_constituent(repo, std::slice::from_ref(&hash))
                    .await
                    .expect("the read succeeds"),
                Some(expected.clone()),
                "seeded {first} then {second}: the terminal row decides"
            );
            assert_eq!(
                reader
                    .terminal_constituents(repo, std::slice::from_ref(&hash))
                    .await
                    .expect("the read succeeds"),
                vec![expected],
                "seeded {first} then {second}: and the per-hash answer is the same one"
            );
        }
    }

    /// The per-hash answer: **one entry per hash** that carries a
    /// terminal verdict, strongest first, with nothing for a hash that is
    /// absent or deliverable — and its first entry is what the `LIMIT 1`
    /// statement answers, which is the agreement the two statements owe
    /// each other.
    ///
    /// Driven over a corpus holding every case at once (a twinned pair, a
    /// lone indeterminate row, a deliverable row, an absent hash, and the
    /// same hash listed twice) and in two listing orders, because the
    /// order the answer comes back in is the refusal precedence and not
    /// the caller's.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_two_statements_agree_on_the_strongest_constituent() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let twinned = seed_artifact(&pool, repo, 'a', QuarantineStatus::Rejected, false).await;
        let released_twin =
            seed_artifact(&pool, repo, 'a', QuarantineStatus::Released, false).await;
        assert_eq!(released_twin, twinned, "the twin shares the hash");
        let held =
            seed_artifact(&pool, repo, 'b', QuarantineStatus::ScanIndeterminate, false).await;
        let deliverable = seed_artifact(&pool, repo, 'c', QuarantineStatus::Released, false).await;
        let absent: ContentHash = "d".repeat(64).parse().expect("synthetic sha256");
        let reader = PgConstituentStatusReader::new(pool.clone());
        let expected = vec![
            TerminalConstituent {
                content_hash: twinned.clone(),
                status: QuarantineStatus::Rejected,
            },
            TerminalConstituent {
                content_hash: held.clone(),
                status: QuarantineStatus::ScanIndeterminate,
            },
        ];
        for order in [
            vec![
                deliverable.clone(),
                absent.clone(),
                held.clone(),
                twinned.clone(),
                twinned.clone(),
            ],
            vec![
                twinned.clone(),
                held.clone(),
                absent.clone(),
                deliverable.clone(),
            ],
        ] {
            let per_hash = reader
                .terminal_constituents(repo, &order)
                .await
                .expect("the read succeeds");
            assert_eq!(
                per_hash, expected,
                "one entry per terminal hash, strongest first, nothing for the absent or the \
                 deliverable one, and a repeated hash counted once"
            );
            assert_eq!(
                per_hash.first().cloned(),
                reader
                    .strongest_terminal_constituent(repo, &order)
                    .await
                    .expect("the read succeeds"),
                "the two statements must answer the same constituent: one question, two budgets"
            );
        }
    }

    /// An empty ask must not reach the database: a manifest that binds
    /// nothing is the common degenerate case and owes no round trip.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn an_empty_ask_is_answered_without_a_round_trip() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        // Close the pool first: a statement issued against it would
        // error, so an `Ok` here proves no statement was issued.
        pool.close().await;
        let reader = PgConstituentStatusReader::new(pool);
        assert_eq!(
            reader
                .strongest_terminal_constituent(Uuid::new_v4(), &[])
                .await
                .expect("an empty ask must short-circuit before touching the pool"),
            None
        );
        assert_eq!(
            reader
                .terminal_constituents(Uuid::new_v4(), &[])
                .await
                .expect("an empty ask must short-circuit before touching the pool"),
            Vec::new(),
            "the per-hash statement owes an empty ask no round trip either"
        );
    }
}
