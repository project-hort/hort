//! PostgreSQL adapter for [`RepositoryInventoryReader`] — the
//! per-repository live-catalog readout.
//!
//! # One set-based aggregate, not a per-repository loop
//!
//! [`INVENTORY_SQL`] is one statement for the whole installation. A loop
//! over repository keys would answer the question N instants apart and
//! pay N round-trips for a readout whose whole value is that its numbers
//! describe one moment. If a bound ever turns out to be needed, the
//! thing to page is the **repository keys** before their artifacts are
//! aggregated — paginating an already-global aggregate does not bound
//! the work it did. Existing precedents cap repository pages at 1 000
//! and the security-score list at 500, so the shape is there when a
//! measurement calls for it.
//!
//! # Distinctness is on the hash, and that is the computation
//!
//! The byte figure is the sum over **distinct contents**: group the live
//! rows by `(repository_id, checksum_sha256)`, take one `size_bytes` per
//! group, sum the groups. `SUM(DISTINCT size_bytes)` is the spelling
//! that looks right and is a different, wrong statement — two different
//! contents can be exactly the same length, so deduplicating the
//! *number* silently drops one of them. The distinctness has to be a
//! property of the hash, which is why the grouping key carries it and
//! the sum does not.
//!
//! # What the byte figure is not
//!
//! A **catalog weight**, and the port's docs carry the full reading.
//! Non-additive across repositories (one CAS entry can carry rows in
//! several of them, ADR 0054), not disk usage (it omits CAS-resident
//! metadata and every other content-reference target kind), not
//! reclaimable space (a soft-deleted row's bytes stay resident until
//! refcount-gated GC).
//!
//! [`RepositoryRepository::get_storage_usage`](hort_domain::ports::repository_repository::RepositoryRepository::get_storage_usage)
//! already wrote that warning down: its sum "was never the figure that
//! answers 'how much disk does the repository hold'". **Its warning is
//! taken and its value is not** — it sums over live *rows*, so two
//! artifacts in one repository sharing one blob are counted twice, which
//! is exactly the double count the hash grouping here removes. Nothing
//! in this file calls it and nothing should start.
//!
//! # A new read path, not a widened old one
//!
//! `held_set_reader`'s statements are about the held-pending-signature
//! slice: a resolved policy, an expired window, a quarantine status, a
//! bucket rule. This one reads every live row with no policy resolution
//! and no status predicate at all. Sharing a query between them would
//! mean the first change that wanted one silently got the other. The two
//! field names `artifact_count` / `distinct_content_count` are shared
//! deliberately — a second vocabulary for one pair of numbers is a
//! defect — and nothing else is.

use sqlx::PgPool;
use uuid::Uuid;

use hort_domain::error::DomainResult;
use hort_domain::ports::repository_inventory_reader::{
    RepositoryInventory, RepositoryInventoryReader,
};

use crate::{map_sqlx_error, BoxFuture};

/// Every repository's three numbers, in one statement.
///
/// Reads bottom-up:
///
/// 1. `live_repository_contents` collapses the live rows to one row per
///    `(repository, distinct content)`, carrying how many artifacts name
///    that content and the content's own size **once**.
/// 2. `per_repository` folds those groups: the row count is their sum,
///    the distinct-content count is how many groups there are, and the
///    byte figure is the sum of the one-size-per-group column.
/// 3. The outer `SELECT` drives from `repositories` with a `LEFT JOIN`,
///    so a repository holding nothing is reported as zeros rather than
///    omitted. An absent row cannot be told apart from a repository the
///    readout never saw, and "this repository is now empty" is the
///    result a retention before/after is looking for.
///
/// `::bigint` on each `SUM` is load-bearing rather than tidiness:
/// Postgres widens `SUM(bigint)` to `numeric` to keep the aggregate from
/// overflowing, so the bare expression does not decode into `i64`. The
/// cast can itself overflow — on a catalog past 8 EiB — which Postgres
/// raises rather than wrapping, so that failure is loud.
const INVENTORY_SQL: &str = r#"
    WITH live_repository_contents AS (
        -- One row per (repository, distinct content). Grouping by the
        -- HASH is the whole computation: the sum below counts each
        -- content once however many artifacts name it, which
        -- `SUM(DISTINCT size_bytes)` would not do — two different
        -- contents can be exactly the same length, and deduplicating
        -- the number would drop one of them.
        --
        -- `MIN(size_bytes)` picks the group's one size. A row records
        -- its hash and its size together from one CAS result, so two
        -- rows sharing a hash and disagreeing about its size is an
        -- already-broken invariant that this readout is not the
        -- instrument for; the aggregate is chosen so the answer does not
        -- depend on row order, and so that it cannot overstate the
        -- weight.
        --
        -- A live read. A soft-deleted artifact is not in the
        -- repository's served catalog, so it is not part of what that
        -- catalog weighs — its bytes may well still be resident, which
        -- is the refcount-gated purge GC's question and not this one's.
        SELECT a.repository_id           AS repository_id,
               COUNT(*)::bigint          AS artifact_count,
               MIN(a.size_bytes)::bigint AS content_size_bytes
        FROM artifacts a
        WHERE a.deleted_at IS NULL
        GROUP BY a.repository_id, a.checksum_sha256
    ),
    per_repository AS (
        SELECT repository_id                   AS repository_id,
               SUM(artifact_count)::bigint     AS artifact_count,
               COUNT(*)::bigint                AS distinct_content_count,
               SUM(content_size_bytes)::bigint AS live_primary_content_bytes
        FROM live_repository_contents
        GROUP BY repository_id
    )
    SELECT r.id                                           AS repository_id,
           r.key                                          AS repository_key,
           COALESCE(p.artifact_count, 0)::bigint           AS artifact_count,
           COALESCE(p.distinct_content_count, 0)::bigint   AS distinct_content_count,
           COALESCE(p.live_primary_content_bytes, 0)::bigint
                                                          AS live_primary_content_bytes
    FROM repositories r
    LEFT JOIN per_repository p ON p.repository_id = r.id
    ORDER BY r.key
"#;

/// PostgreSQL adapter for the per-repository inventory readout.
pub struct PgRepositoryInventoryReader {
    pool: PgPool,
}

impl PgRepositoryInventoryReader {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// sqlx `FromRow` shape for the projection.
///
/// A derived row shape rather than per-column `try_get` calls, matching
/// `held_set_reader`'s `BucketRow`: the `SELECT` list and this struct are
/// the one pairing, and the decode-failure path is sqlx's rather than
/// hand-written closures no test can reach.
#[derive(sqlx::FromRow)]
struct InventoryRow {
    repository_id: Uuid,
    repository_key: String,
    artifact_count: i64,
    distinct_content_count: i64,
    live_primary_content_bytes: i64,
}

impl InventoryRow {
    fn into_domain(self) -> RepositoryInventory {
        RepositoryInventory {
            repository_id: self.repository_id,
            repository_key: self.repository_key,
            artifact_count: nonneg(self.artifact_count),
            distinct_content_count: nonneg(self.distinct_content_count),
            live_primary_content_bytes: nonneg(self.live_primary_content_bytes),
        }
    }
}

impl RepositoryInventoryReader for PgRepositoryInventoryReader {
    fn inventory(&self) -> BoxFuture<'_, DomainResult<Vec<RepositoryInventory>>> {
        Box::pin(async move {
            tracing::debug!(entity = "repository_inventory", "inventory");
            let rows = sqlx::query_as::<_, InventoryRow>(INVENTORY_SQL)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "repository_inventory", "aggregate"))?;

            Ok(rows.into_iter().map(InventoryRow::into_domain).collect())
        })
    }
}

/// A `COUNT`/`SUM` over non-negative column values is never negative;
/// fold the signed SQL type onto the unsigned domain one without an
/// unwrap. Mirrors `held_set_reader::nonneg`.
fn nonneg(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    use serial_test::serial;

    use crate::test_support::isolated_db_from;

    // -- DB-free pins: the statement says what the computation is ----------

    /// The statement's **code**, with its `--` comments removed.
    ///
    /// Load-bearing rather than fastidious, and the sibling guard
    /// `live_reads_exclude_deleted` makes the same distinction for the
    /// same reason: the comments below deliberately *name* the wrong
    /// spelling in order to warn against it, so a pin that searched the
    /// raw literal would find the warning and read it as the defect. A
    /// line-based strip is exact here because the statement contains no
    /// string literals at all — [`the_comment_strip_leaves_real_sql`] is
    /// the counter-assertion that it has not stripped everything.
    fn sql_code() -> String {
        INVENTORY_SQL
            .lines()
            .map(|line| match line.find("--") {
                Some(at) => &line[..at],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The strip leaves the statement, not an empty string. Without
    /// this, every pin below would pass vacuously on a helper that had
    /// started removing too much.
    #[test]
    fn the_comment_strip_leaves_real_sql() {
        let code = sql_code();
        for fragment in [
            "FROM artifacts a",
            "FROM repositories r",
            "GROUP BY a.repository_id, a.checksum_sha256",
        ] {
            assert!(code.contains(fragment), "{fragment} was stripped: {code}");
        }
        assert!(
            !code.contains("--"),
            "the strip left a comment behind: {code}"
        );
        // And the strip really is removing something — the raw literal
        // carries the warning the pins must not mistake for the defect.
        assert!(INVENTORY_SQL.to_lowercase().contains("sum(distinct"));
    }

    /// **The distinctness is on the hash, not on the size.**
    ///
    /// `SUM(DISTINCT size_bytes)` is the spelling that looks right and
    /// is a different, wrong statement: two different contents can be
    /// exactly the same length. The DB-backed
    /// [`tests::two_different_contents_of_equal_size_are_both_counted`]
    /// proves the behaviour; this pins the shape, so a future edit that
    /// reaches for the wrong aggregate fails without a database.
    #[test]
    fn the_statement_never_deduplicates_the_size() {
        let lower = sql_code().to_lowercase();
        // Token-wise, not substring-wise: the statement's own
        // `distinct_content_count` alias carries the word, and a
        // substring match would read the column name this readout
        // reports as the aggregate it must not use.
        let keyword_used = lower
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|token| token == "distinct");
        assert!(
            !keyword_used,
            "distinctness belongs on the grouping key, so no DISTINCT \
             aggregate belongs in this statement at all: {lower}"
        );
        assert!(
            lower.contains("group by a.repository_id, a.checksum_sha256"),
            "the grouping key is what makes each content count once: {lower}"
        );
    }

    /// The statement is a live read and carries the predicate in its own
    /// SQL — the property `live_reads_exclude_deleted` asserts across
    /// the workspace, stated here beside the query so an edit to this
    /// file fails in this file.
    #[test]
    fn the_statement_excludes_soft_deleted_rows() {
        let code = sql_code();
        assert!(
            code.contains("a.deleted_at IS NULL"),
            "a soft-deleted artifact is not in the served catalog, and the \
             predicate has to be in the SQL rather than in a comment \
             discussing it: {code}"
        );
    }

    /// **`quota_bytes` is nowhere near this statement.** The column
    /// outlives its code references by one release under ADR 0030's
    /// expand/contract, and nothing ever enforced it — the operator
    /// surface is retired and refused at apply — so a figure drawn from
    /// it beside a usage figure would make the readout look like quota
    /// monitoring over a limit nothing can declare. The field is not
    /// selected, not joined and not named.
    #[test]
    fn the_statement_reads_no_quota() {
        // The raw literal, comments included: a comment mentioning the
        // column would be a reader's first hint that the readout is
        // about quotas, which is the impression the omission exists to
        // avoid.
        assert!(
            !INVENTORY_SQL.to_lowercase().contains("quota"),
            "no quota figure belongs in a readout nothing enforces: {INVENTORY_SQL}"
        );
    }

    /// The readout drives from `repositories`, so a repository holding
    /// nothing has a row. Driving from `artifacts` instead would make an
    /// emptied repository vanish, and "this repository is now empty" is
    /// the result a retention before/after is looking for.
    #[test]
    fn the_statement_drives_from_repositories_so_an_empty_one_survives() {
        let code = sql_code();
        assert!(code.contains("FROM repositories r"));
        assert!(code.contains("LEFT JOIN per_repository p"));
        for column in [
            "COALESCE(p.artifact_count, 0)",
            "COALESCE(p.distinct_content_count, 0)",
            "COALESCE(p.live_primary_content_bytes, 0)",
        ] {
            assert!(
                code.contains(column),
                "{column} must fold the LEFT JOIN's NULL to zero: {code}"
            );
        }
    }

    /// Every `SUM` carries the `::bigint` cast. Postgres widens
    /// `SUM(bigint)` to `numeric`, so a missing cast is a decode error
    /// for every caller rather than a wrong number — loud, but only
    /// reachable with a database, which is why the shape is pinned here.
    #[test]
    fn every_sum_is_cast_back_to_bigint() {
        let code = sql_code();
        let sums = code.matches("SUM(").count();
        assert_eq!(sums, 2, "the statement has exactly two SUMs: {code}");
        for cast in [
            "SUM(artifact_count)::bigint",
            "SUM(content_size_bytes)::bigint",
        ] {
            assert!(
                code.contains(cast),
                "{cast} must carry the cast — without it the aggregate comes \
                 back as `numeric` and fails to decode: {code}"
            );
        }
    }

    /// This readout resolves no policy and no quarantine status. Those
    /// belong to the held-set slice, and a predicate from that question
    /// appearing here would mean the two populations had been merged.
    #[test]
    fn the_statement_is_not_the_held_set_query() {
        let lower = sql_code().to_lowercase();
        for foreign in [
            "policy_projections",
            "quarantine_status",
            "quarantine_window_start",
            "provenance_mode",
            "content_references",
        ] {
            assert!(
                !lower.contains(foreign),
                "{foreign} belongs to the held-set question, not the inventory: {lower}"
            );
        }
    }

    // -- DB-backed: the three numbers, against seeded rows -----------------

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;
        Some(pool)
    }

    async fn seed_repository(pool: &PgPool, key_prefix: &str) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("{key_prefix}-{}", id.simple());
        sqlx::query(
            r#"INSERT INTO public.repositories (
                   id, key, name, format, repo_type, storage_backend,
                   storage_path, replication_priority
               ) VALUES (
                   $1, $2, $2, 'oci'::repository_format,
                   'hosted'::repository_type, 'filesystem', $3,
                   'local_only'::replication_priority
               )"#,
        )
        .bind(id)
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .execute(pool)
        .await
        .expect("seed repository");
        id
    }

    /// Seed one artifact with an explicit content hash and size, so a
    /// test can make two rows share their bytes on purpose, or give two
    /// different contents exactly equal sizes.
    async fn seed_artifact(
        pool: &PgPool,
        repo: Uuid,
        name: &str,
        hash: &str,
        size_bytes: i64,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO public.artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   created_at, updated_at
               ) VALUES (
                   $1, $2, $3, $3, '1.0.0', $4,
                   $5, $6, 'application/octet-stream', $6,
                   now(), now()
               )"#,
        )
        .bind(id)
        .bind(repo)
        .bind(name)
        .bind(format!("{name}/1.0.0/{}.tgz", id.simple()))
        .bind(size_bytes)
        .bind(hash)
        .execute(pool)
        .await
        .expect("seed artifact");
        id
    }

    /// A 64-hex content hash that is stable per `seed`, so two artifacts
    /// can be made to share their bytes on purpose.
    fn hash(seed: u8) -> String {
        std::iter::repeat_n(format!("{seed:02x}"), 32).collect()
    }

    async fn inventory_of(pool: &PgPool, repo: Uuid) -> RepositoryInventory {
        PgRepositoryInventoryReader::new(pool.clone())
            .inventory()
            .await
            .expect("inventory")
            .into_iter()
            .find(|r| r.repository_id == repo)
            .expect("the seeded repository is in the readout")
    }

    /// **One content shared by two artifacts in one repository.**
    ///
    /// Rows ≠ contents, and the byte figure counts the shared content
    /// **once**. This is the fixture that separates a correct
    /// distinct-content sum from a row sum: `get_storage_usage` would
    /// report 1 400 here, and the honest catalog weight is 700.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn one_content_shared_by_two_artifacts_is_weighed_once() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repository(&pool, "oci-shared-within").await;
        let shared = hash(0xa1);
        seed_artifact(&pool, repo, "manifest-a", &shared, 700).await;
        seed_artifact(&pool, repo, "manifest-b", &shared, 700).await;

        let got = inventory_of(&pool, repo).await;

        assert_eq!(got.artifact_count, 2, "two live rows name the content");
        assert_eq!(
            got.distinct_content_count, 1,
            "they name ONE content — rows are not contents"
        );
        assert_eq!(
            got.live_primary_content_bytes, 700,
            "the shared content is weighed once; a row sum would say 1400"
        );
    }

    /// **One content referenced from two different repositories.**
    ///
    /// Each repository reports the full weight of the content it holds,
    /// so the two figures **cannot be added** — the sum would count one
    /// physical blob twice. The assertion states the non-additivity
    /// directly: `a + b` exceeds the distinct bytes the two repositories
    /// actually stand on.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn one_content_in_two_repositories_makes_the_figure_non_additive() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let left = seed_repository(&pool, "oci-left").await;
        let right = seed_repository(&pool, "oci-right").await;
        let shared = hash(0xb2);
        seed_artifact(&pool, left, "shared", &shared, 900).await;
        seed_artifact(&pool, right, "shared", &shared, 900).await;

        let l = inventory_of(&pool, left).await;
        let r = inventory_of(&pool, right).await;

        assert_eq!(l.live_primary_content_bytes, 900);
        assert_eq!(r.live_primary_content_bytes, 900);
        // One blob, 900 bytes of it in CAS. The per-repository figures
        // sum to 1 800, which is why adding them is wrong and why the
        // response documentation says so.
        assert_eq!(
            l.live_primary_content_bytes + r.live_primary_content_bytes,
            1_800,
            "the figures add to twice the one blob — they are not additive"
        );
        assert_eq!(l.distinct_content_count, 1);
        assert_eq!(r.distinct_content_count, 1);
    }

    /// **Two different contents of exactly equal size are both counted.**
    ///
    /// The test the whole naming discipline turns on: with
    /// `SUM(DISTINCT size_bytes)` this reports 500 and one content. The
    /// distinctness is on the hash, so it reports 1 000 and two.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn two_different_contents_of_equal_size_are_both_counted() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repository(&pool, "oci-equal-sizes").await;
        let (first, second) = (hash(0xc3), hash(0xd4));
        assert_ne!(first, second, "the fixture needs two different contents");
        seed_artifact(&pool, repo, "equal-a", &first, 500).await;
        seed_artifact(&pool, repo, "equal-b", &second, 500).await;

        let got = inventory_of(&pool, repo).await;

        assert_eq!(got.artifact_count, 2);
        assert_eq!(
            got.distinct_content_count, 2,
            "two hashes are two contents however equal their sizes"
        );
        assert_eq!(
            got.live_primary_content_bytes, 1_000,
            "`SUM(DISTINCT size_bytes)` would report 500 — distinctness is on the hash"
        );
    }

    /// **A soft-deleted artifact is excluded**, proven against a seeded
    /// row rather than by reading the SQL: all three numbers drop when
    /// the row is marked deleted, and the live sibling's are untouched.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_soft_deleted_artifact_leaves_the_readout() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repository(&pool, "oci-soft-delete").await;
        seed_artifact(&pool, repo, "live", &hash(0xe5), 300).await;
        let doomed = seed_artifact(&pool, repo, "doomed", &hash(0xf6), 4_000).await;

        let before = inventory_of(&pool, repo).await;
        assert_eq!(before.artifact_count, 2);
        assert_eq!(before.distinct_content_count, 2);
        assert_eq!(before.live_primary_content_bytes, 4_300);

        crate::test_support::soft_delete_artifact(&pool, doomed).await;

        let after = inventory_of(&pool, repo).await;
        assert_eq!(after.artifact_count, 1, "the deleted row left the count");
        assert_eq!(after.distinct_content_count, 1);
        assert_eq!(
            after.live_primary_content_bytes, 300,
            "the deleted row's bytes left the catalog weight — they may well \
             still be resident, which is the purge GC's question"
        );
    }

    /// A repository holding nothing is reported as zeros. Omitting it
    /// would make "retention emptied this repository" indistinguishable
    /// from "the readout does not know about this repository".
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_repository_holding_nothing_is_reported_as_zeros() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let empty = seed_repository(&pool, "oci-empty").await;

        let got = inventory_of(&pool, empty).await;

        assert_eq!(got.artifact_count, 0);
        assert_eq!(got.distinct_content_count, 0);
        assert_eq!(got.live_primary_content_bytes, 0);
    }

    /// Every repository the installation declares appears exactly once,
    /// ordered by key — one set-based aggregate over the whole catalog,
    /// not a per-repository lookup the caller has to drive.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_readout_carries_every_repository_once_ordered_by_key() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let a = seed_repository(&pool, "aaa-inventory").await;
        let b = seed_repository(&pool, "zzz-inventory").await;
        seed_artifact(&pool, a, "one", &hash(0x11), 10).await;

        let rows = PgRepositoryInventoryReader::new(pool.clone())
            .inventory()
            .await
            .expect("inventory");

        let seeded: Vec<&RepositoryInventory> = rows
            .iter()
            .filter(|r| r.repository_id == a || r.repository_id == b)
            .collect();
        assert_eq!(seeded.len(), 2, "each repository appears exactly once");
        assert!(
            seeded[0].repository_key < seeded[1].repository_key,
            "ordered by key: {:?}",
            seeded.iter().map(|r| &r.repository_key).collect::<Vec<_>>()
        );
        // The key is resolved by the statement's own join — a
        // pass-through the HTTP DTO renders, so the caller never has to
        // resolve a UUID to show the operator which repository a row is.
        assert!(seeded
            .iter()
            .all(|r| !r.repository_key.is_empty() && r.repository_key.contains("-inventory-")));
    }

    /// The three numbers against a mixed repository: shared content,
    /// equal-size distinct contents and a soft-deleted row together, so
    /// the interactions are asserted once rather than only in isolation.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_three_numbers_hold_together_on_a_mixed_catalog() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repository(&pool, "oci-mixed").await;
        let shared = hash(0x21);
        // Two rows on one 100-byte content.
        seed_artifact(&pool, repo, "shared-a", &shared, 100).await;
        seed_artifact(&pool, repo, "shared-b", &shared, 100).await;
        // A second, different content of exactly the same size.
        seed_artifact(&pool, repo, "twin-size", &hash(0x22), 100).await;
        // And a soft-deleted row carrying a content nothing else names.
        let gone = seed_artifact(&pool, repo, "gone", &hash(0x23), 5_000).await;
        crate::test_support::soft_delete_artifact(&pool, gone).await;

        let got = inventory_of(&pool, repo).await;

        assert_eq!(got.artifact_count, 3, "three live rows");
        assert_eq!(got.distinct_content_count, 2, "two distinct live contents");
        assert_eq!(
            got.live_primary_content_bytes, 200,
            "100 (shared, counted once) + 100 (its equal-size twin); the \
             deleted row's 5000 is not in the served catalog"
        );
    }
}
