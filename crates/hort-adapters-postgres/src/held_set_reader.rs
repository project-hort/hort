//! PostgreSQL adapter for [`HeldSetReader`] — the held-pending-signature
//! overview and its drill-down.
//!
//! # This is a new read path, not a widened old one
//!
//! The GC protection of ADR 0007's invariant 1 is single-sourced in
//! [`crate::gc_protected_quarantine_status_names`] and bound into
//! `retention_candidate_reader`'s own query. **Nothing here touches
//! it.** Widening that query to also answer "what is held?" would put
//! the GC protection and the operator overview on one code path, and the
//! first change that wanted one would silently get the other. So the
//! enumeration gets its own port and its own statements, and
//! [`tests::no_gc_protected_artifact_reaches_the_retention_candidates`]
//! asserts — against the constant, not a restated list — that the old
//! path still protects what it protected.
//!
//! # Two statements, one membership definition
//!
//! The aggregate and the page statements share a `held` CTE whose `WHERE`
//! clause **is** the category: `quarantined`, live, an expired window
//! under the resolved policy's duration, and that same policy's
//! `provenance_mode = 'required'`. Three of the four conditions; the
//! fourth — no `ProvenanceVerified` on the artifact stream — is the
//! release conjunct's provenance leg and is deliberately **not**
//! computed here. `hort_app::use_cases::release_clearance` owns it
//! because two independent computations of it drifted once, and an SQL
//! copy would be that second computation however faithful. That is
//! exactly what makes the aggregate a declared **superset** rather than
//! the gate's answer, and why the drill-down's caller re-decides every
//! row it is handed.
//!
//! # The resolved policy is one row, not two columns
//!
//! The `JOIN LATERAL` picks **one** `policy_projections` row per
//! artifact — the repository's own non-archived policy if there is one,
//! else the non-archived global — and projects both halves the category
//! needs from it. Two independent `COALESCE`d sub-selects would let a
//! repository policy supply the duration and the global policy supply
//! the provenance mode, which is a deadline from one operator decision
//! judged against a gate from another. It is an INNER join, so a
//! repository with no resolvable policy contributes no rows at all:
//! **no policy means no deadline, so the row is not in the category** —
//! enforced by the join rather than by a predicate anyone can forget.
//!
//! # The bucket boolean, and whose rule it is
//!
//! `is_constituent` splits each repository's held set into the
//! parent-gated blob constituents (held because a parent manifest is
//! unsigned — a blob can never carry its own attestation, ADR 0039) and
//! the artifacts held in their own right, because the operator action
//! differs. The **rule** is
//! `hort_app::use_cases::referenced_descendant::is_parent_gated_blob_constituent_kinds`
//! and lives only there: its two kind lists arrive as `text[]`
//! parameters and the SQL forms only the boolean
//!
//! ```text
//! bool_or(kind = ANY($blob)) AND bool_and(kind = ANY($blob) OR kind = ANY($self))
//! ```
//!
//! which is that function transcribed into aggregates, with
//! `COALESCE(…, false)` for the reference-less artifact whose `LEFT
//! JOIN` yields one all-`NULL` row. `held_set_bucket_parity` (this
//! crate's `tests/`) drives the Rust predicate and this SQL over the
//! same kind sets, so neither side can be edited alone.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use hort_app::use_cases::held_set_use_case::MAX_HELD_PAGE_LIMIT;
use hort_domain::error::DomainResult;
use hort_domain::ports::held_set_reader::{
    ConstituentKindSets, HeldBucket, HeldCandidateBucket, HeldCandidateQuery, HeldCandidateRow,
    HeldSetReader,
};

use crate::{map_sqlx_error, BoxFuture};

/// The persisted `quarantine_status` spelling the category is defined
/// over.
///
/// Pinned to the crate's one status encoder by
/// [`tests::the_statements_name_the_status_the_writers_store`], so a
/// renamed `Display` spelling fails there rather than by silently
/// matching no row.
const QUARANTINED: &str = "quarantined";

/// The `provenance_mode` spelling the category is defined over. Pinned
/// to the domain enum's `Display` by
/// [`tests::the_statements_name_the_provenance_mode_the_writers_store`].
const REQUIRED_MODE: &str = "required";

/// The name the population wears **in the SQL**, not only on the wire.
///
/// An aggregate named as if it were the gate's decision is the failure
/// this guards: the query resolves the policy and the window expiry and
/// stops short of the clearance verdict, so what it yields is
/// *candidates*. A CTE called `held` would read as "artifacts the gate
/// is holding" to whoever next opens an `EXPLAIN` or a slow-query log,
/// which is the one thing this population is not. Pinned by
/// [`tests::the_sql_names_the_population_candidates`].
const CANDIDATES: &str = "held_pending_signature_candidates";

/// The per-artifact membership CTE, shared verbatim by both statements.
///
/// `{extra}` is where the drill-down adds its keyset / repository
/// narrowing; the aggregate passes an empty string. Everything that
/// decides *membership* is here, so the two statements cannot drift
/// about what "held" means.
///
/// `$1` = `now`, `$2` = blob kinds `text[]`, `$3` = self-referential
/// kinds `text[]`.
const CANDIDATES_CTE: &str = r#"
    SELECT a.id                       AS artifact_id,
           a.repository_id            AS repository_id,
           r.key                      AS repository_key,
           a.name                     AS name,
           a.version                  AS version,
           a.path                     AS path,
           a.checksum_sha256          AS content_hash,
           -- The hold anchor, which is what the age is measured from,
           -- and deliberately WITHOUT a `created_at` fallback.
           --
           -- The membership predicate below requires a window anchor,
           -- so this column cannot be NULL as the statement stands. The
           -- question a fallback answers is what happens if someone
           -- later relaxes that predicate, and the two answers are not
           -- equally safe: `COALESCE(…, a.created_at)` would substitute
           -- the row's creation date for "the system never anchored a
           -- window to this row" and hand an operator a plausible age
           -- that measures nothing, while the bare column decodes into a
           -- non-optional timestamp and so fails loudly instead.
           --
           -- The age is the number the indefinite hold's justification
           -- rests on (ADR 0039 D4 declines a deadline by pointing at an
           -- operator who can see the held set *and its age*), so a
           -- fabricated one is worse than an error. Absent facts are not
           -- substituted here.
           a.quarantine_window_start  AS held_since,
           -- `is_parent_gated_blob_constituent_kinds`, transcribed.
           -- The kind lists are parameters; this forms only the
           -- boolean. A reference-less artifact's LEFT JOIN yields one
           -- all-NULL row, both aggregates return NULL, and the
           -- COALESCE makes that `false` — as the Rust predicate's
           -- empty-iterator case is.
           COALESCE(
               bool_or(cr.kind = ANY($2::text[]))
               AND bool_and(cr.kind = ANY($2::text[])
                            OR cr.kind = ANY($3::text[])),
               false
           )                          AS is_constituent
    FROM artifacts a
    JOIN repositories r ON r.id = a.repository_id
    -- ONE resolved policy row, both halves projected from it: the
    -- repository's own non-archived policy beats the non-archived
    -- global. INNER, so no resolvable policy => no deadline => the row
    -- is not in the category.
    JOIN LATERAL (
        SELECT pp.quarantine_duration_secs AS duration_secs,
               pp.provenance_mode          AS provenance_mode
        FROM policy_projections pp
        WHERE pp.archived = false
          AND (
                (pp.scope ? 'Repository'
                  AND (pp.scope->>'Repository')::uuid = a.repository_id)
             OR (pp.scope ? 'Global'
                  AND NOT EXISTS (
                        SELECT 1 FROM policy_projections pp2
                        WHERE pp2.archived = false
                          AND pp2.scope ? 'Repository'
                          AND (pp2.scope->>'Repository')::uuid = a.repository_id
                  ))
              )
        ORDER BY (pp.scope ? 'Repository') DESC
        LIMIT 1
    ) p ON TRUE
    -- The artifact's inbound reference set, scoped exactly as
    -- `ContentReferenceIndex::find_by_target(repo, hash, None)` scopes
    -- it: one repository, one target hash, every kind. LEFT so a
    -- reference-less artifact survives to be bucketed as
    -- in-own-right.
    LEFT JOIN content_references cr
           ON cr.repository_id = a.repository_id
          AND cr.target_content_hash = a.checksum_sha256
    WHERE a.quarantine_status = $4
      -- A soft-deleted artifact is not in the repository's served
      -- catalog and must not appear in a curator's worklist — the exact
      -- defect `live_reads_exclude_deleted` was written after. This is
      -- a live read.
      AND a.deleted_at IS NULL
      AND p.provenance_mode = $5
      AND a.quarantine_window_start IS NOT NULL
      AND a.quarantine_window_start
            + (p.duration_secs * INTERVAL '1 second') < $1
      {extra}
    GROUP BY a.id, a.repository_id, r.key, a.name, a.version, a.path,
             a.checksum_sha256, a.quarantine_window_start, a.created_at
"#;

/// Build a statement around [`CANDIDATES_CTE`].
fn held_statement(extra: &str, tail: &str) -> String {
    format!(
        "WITH {CANDIDATES} AS ({cte})\n{tail}",
        cte = CANDIDATES_CTE.replace("{extra}", extra),
        tail = tail.replace("{CANDIDATES}", CANDIDATES),
    )
}

/// `(repository, bucket)` cells: row count, distinct-content count and
/// the oldest hold anchor.
///
/// `COUNT(*)` and `COUNT(DISTINCT content_hash)` are both reported
/// because CAS shares bytes across artifacts (ADR 0054) — an artifact
/// count is not a byte count and must not be read as reclaimable
/// storage.
const AGGREGATE_TAIL: &str = r#"
    SELECT repository_id,
           repository_key,
           is_constituent,
           COUNT(*)::bigint                     AS artifact_count,
           COUNT(DISTINCT content_hash)::bigint AS distinct_content_count,
           MIN(held_since)                      AS oldest_held_since
    FROM {CANDIDATES}
    GROUP BY repository_id, repository_key, is_constituent
    ORDER BY repository_key, is_constituent
"#;

/// One keyset page of one bucket.
///
/// `$6` = `is_constituent`, `$7` = optional repository filter, `$8` =
/// optional keyset cursor, `$9` = limit. The repository and cursor
/// predicates sit inside the CTE (see [`PAGE_EXTRA`]) so the scan is
/// narrowed before the per-artifact aggregation; `is_constituent` cannot,
/// because it *is* that aggregation.
const PAGE_TAIL: &str = r#"
    SELECT artifact_id, repository_id, repository_key, name, version,
           path, content_hash, is_constituent, held_since
    FROM {CANDIDATES}
    WHERE is_constituent = $6
    ORDER BY artifact_id
    LIMIT $9
"#;

/// The drill-down's narrowing, spliced into [`CANDIDATES_CTE`].
const PAGE_EXTRA: &str = r#"
      AND ($7::uuid IS NULL OR a.repository_id = $7)
      AND ($8::uuid IS NULL OR a.id > $8)"#;

/// PostgreSQL adapter for the held-set overview.
pub struct PgHeldSetReader {
    pool: PgPool,
}

impl PgHeldSetReader {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Own the caller's kind lists so the bound values outlive the borrow.
fn owned(kinds: ConstituentKindSets<'_>) -> (Vec<String>, Vec<String>) {
    (
        kinds.blob_kinds.iter().map(|k| (*k).to_string()).collect(),
        kinds
            .self_referential_kinds
            .iter()
            .map(|k| (*k).to_string())
            .collect(),
    )
}

/// sqlx `FromRow` shape for the aggregate projection.
///
/// A derived row shape rather than per-column `try_get` calls, matching
/// `curation_queue_repository`'s `CurationQueueRow`: the SELECT list and
/// this struct are the one pairing, and the decode-failure path is
/// sqlx's rather than forty hand-written closures no test can reach.
#[derive(sqlx::FromRow)]
struct BucketRow {
    repository_id: Uuid,
    repository_key: String,
    is_constituent: bool,
    artifact_count: i64,
    distinct_content_count: i64,
    oldest_held_since: DateTime<Utc>,
}

impl BucketRow {
    fn into_domain(self) -> HeldCandidateBucket {
        HeldCandidateBucket {
            repository_id: self.repository_id,
            repository_key: self.repository_key,
            bucket: HeldBucket::from_is_constituent(self.is_constituent),
            artifact_count: nonneg(self.artifact_count),
            distinct_content_count: nonneg(self.distinct_content_count),
            oldest_held_since: self.oldest_held_since,
        }
    }
}

/// sqlx `FromRow` shape for the drill-down projection.
#[derive(sqlx::FromRow)]
struct CandidateRow {
    artifact_id: Uuid,
    repository_id: Uuid,
    repository_key: String,
    name: String,
    version: Option<String>,
    path: String,
    content_hash: String,
    is_constituent: bool,
    held_since: DateTime<Utc>,
}

impl CandidateRow {
    fn into_domain(self) -> HeldCandidateRow {
        HeldCandidateRow {
            artifact_id: self.artifact_id,
            repository_id: self.repository_id,
            repository_key: self.repository_key,
            name: self.name,
            version: self.version,
            path: self.path,
            content_hash: self.content_hash,
            bucket: HeldBucket::from_is_constituent(self.is_constituent),
            held_since: self.held_since,
        }
    }
}

impl HeldSetReader for PgHeldSetReader {
    fn aggregate_candidates<'a>(
        &'a self,
        now: DateTime<Utc>,
        kinds: ConstituentKindSets<'a>,
    ) -> BoxFuture<'a, DomainResult<Vec<HeldCandidateBucket>>> {
        let (blob_kinds, self_kinds) = owned(kinds);
        Box::pin(async move {
            tracing::debug!(
                entity = "held_pending_signature_candidate",
                %now,
                "aggregate_candidates"
            );
            let sql = held_statement("", AGGREGATE_TAIL);
            let rows = sqlx::query_as::<_, BucketRow>(sqlx::AssertSqlSafe(sql))
                .bind(now)
                .bind(&blob_kinds)
                .bind(&self_kinds)
                .bind(QUARANTINED)
                .bind(REQUIRED_MODE)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "held_pending_signature_candidate", "aggregate"))?;

            Ok(rows.into_iter().map(BucketRow::into_domain).collect())
        })
    }

    fn list_candidates<'a>(
        &'a self,
        query: HeldCandidateQuery<'a>,
    ) -> BoxFuture<'a, DomainResult<Vec<HeldCandidateRow>>> {
        let (blob_kinds, self_kinds) = owned(query.kinds);
        Box::pin(async move {
            // The use case REFUSES an oversize limit; this clamp is a
            // defence-in-depth bound on the work a non-use-case caller
            // can ask for, against the same single-sourced constant.
            let limit = i64::from(query.limit.min(MAX_HELD_PAGE_LIMIT));
            tracing::debug!(
                entity = "held_pending_signature_candidate",
                now = %query.now,
                bucket = %query.bucket,
                has_repository_filter = query.repository_id.is_some(),
                has_cursor = query.after.is_some(),
                limit,
                "list_candidates"
            );
            let sql = held_statement(PAGE_EXTRA, PAGE_TAIL);
            let rows = sqlx::query_as::<_, CandidateRow>(sqlx::AssertSqlSafe(sql))
                .bind(query.now)
                .bind(&blob_kinds)
                .bind(&self_kinds)
                .bind(QUARANTINED)
                .bind(REQUIRED_MODE)
                .bind(query.bucket.is_constituent())
                .bind(query.repository_id)
                .bind(query.after)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "held_pending_signature_candidate", "page"))?;

            Ok(rows.into_iter().map(CandidateRow::into_domain).collect())
        })
    }
}

/// A `COUNT(*)` is never negative; fold the signed SQL type onto the
/// unsigned domain one without an unwrap.
fn nonneg(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    use hort_app::use_cases::referenced_descendant::{
        PARENT_GATE_BLOB_KINDS, SELF_REFERENTIAL_KINDS,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::scan_policy::ProvenanceMode;
    use hort_domain::ports::retention_candidate_reader::RetentionCandidateReader;
    use serial_test::serial;

    use crate::quarantine_status_sql::quarantine_status_to_sql;
    use crate::retention_candidate_reader::PgRetentionCandidateReader;
    use crate::test_support::isolated_db_from;

    // -- DB-free pins: the statements' literals are the writers' ------------

    /// The status literal both statements are defined over is the one
    /// the writers actually store. A renamed `Display` spelling would
    /// otherwise silently match no row — an empty held set that looks
    /// like good news.
    #[test]
    fn the_statements_name_the_status_the_writers_store() {
        assert_eq!(
            quarantine_status_to_sql(QuarantineStatus::Quarantined).as_deref(),
            Some(QUARANTINED),
        );
    }

    /// Same pin for the provenance mode: the category is "the effective
    /// mode is `Required`", and `$5` has to be the token the projection
    /// writer stores for that variant.
    #[test]
    fn the_statements_name_the_provenance_mode_the_writers_store() {
        assert_eq!(ProvenanceMode::Required.to_string(), REQUIRED_MODE);
    }

    /// Both statements really are built from one membership CTE, and the
    /// splice point is still there. Without this, a future edit could
    /// give each statement its own `WHERE` and the two could disagree
    /// about what "held" means while every other test stayed green.
    #[test]
    fn both_statements_share_one_membership_definition() {
        assert!(
            CANDIDATES_CTE.contains("{extra}"),
            "the splice point the drill-down narrows through is gone"
        );
        let aggregate = held_statement("", AGGREGATE_TAIL);
        let page = held_statement(PAGE_EXTRA, PAGE_TAIL);
        for statement in [&aggregate, &page] {
            assert!(statement.contains("a.quarantine_status = $4"));
            assert!(statement.contains("a.deleted_at IS NULL"));
            assert!(statement.contains("p.provenance_mode = $5"));
            assert!(statement.contains("a.quarantine_window_start IS NOT NULL"));
            assert!(statement.contains("bool_or(cr.kind = ANY($2::text[]))"));
        }
        assert!(!aggregate.contains("$7::uuid"), "aggregate takes no cursor");
        assert!(page.contains("$8::uuid IS NULL OR a.id > $8"));
    }

    /// The SQL names the population after what it measures.
    ///
    /// The response field says `held_pending_signature_candidates`; so
    /// must the query, because a reader meeting this statement in an
    /// `EXPLAIN` or a slow-query log has only the SQL in front of them.
    /// An aggregate named as if it were the gate's decision is the
    /// failure mode, and "held" on its own is that name.
    #[test]
    fn the_sql_names_the_population_candidates() {
        assert_eq!(CANDIDATES, "held_pending_signature_candidates");
        for statement in [
            held_statement("", AGGREGATE_TAIL),
            held_statement(PAGE_EXTRA, PAGE_TAIL),
        ] {
            assert!(
                statement.contains(&format!("WITH {CANDIDATES} AS (")),
                "the CTE must carry the measured name: {statement}"
            );
            assert!(
                statement.contains(&format!("FROM {CANDIDATES}")),
                "the tail must read FROM the named CTE, not a re-typed alias: {statement}"
            );
            // No unsubstituted placeholder reached the database.
            assert!(!statement.contains("{CANDIDATES}"), "{statement}");
            assert!(!statement.contains("{extra}"), "{statement}");
        }
    }

    /// Neither statement evaluates the provenance clearance verdict.
    /// That is what makes the aggregate a declared superset rather than
    /// a second computation of the release conjunct — the thing
    /// `release_clearance.rs` exists to prevent. A `ProvenanceVerified`
    /// appearing in this SQL is the regression.
    #[test]
    fn neither_statement_reads_the_event_stream() {
        for statement in [
            held_statement("", AGGREGATE_TAIL),
            held_statement(PAGE_EXTRA, PAGE_TAIL),
        ] {
            let lower = statement.to_lowercase();
            assert!(
                !lower.contains("provenanceverified"),
                "the clearance verdict has one computation, and it is not here"
            );
            assert!(
                !lower.contains("from events"),
                "the aggregate must take no per-row event read"
            );
        }
    }

    /// The SQL carries no kind list of its own: every
    /// `content_references.kind` comparison is against a bound
    /// parameter. A literal `'oci_config'` here would be a second
    /// bucket rule.
    #[test]
    fn the_sql_carries_no_kind_list_of_its_own() {
        let statements = [
            held_statement("", AGGREGATE_TAIL),
            held_statement(PAGE_EXTRA, PAGE_TAIL),
        ];
        for kind in PARENT_GATE_BLOB_KINDS
            .iter()
            .chain(SELF_REFERENTIAL_KINDS.iter())
        {
            for statement in &statements {
                // Only the SQL code matters; the module docs quote the
                // shape of the predicate, not a kind.
                assert!(
                    !statement.contains(&format!("'{kind}'")),
                    "{kind} is spelled in the SQL — the kind lists are parameters"
                );
            }
        }
    }

    // -- invariant 1 is untouched -------------------------------------------

    /// **The old read path still protects what it protected.**
    ///
    /// Seeds one artifact per GC-protected status and asserts none of
    /// them reaches `RetentionCandidateReader::list_candidates`. It
    /// iterates [`crate::GC_PROTECTED_QUARANTINE_STATUSES`] rather than
    /// a list restated here, so the assertion cannot drift from the
    /// constant it protects: a status added to that array is a status
    /// this test immediately demands protection for.
    ///
    /// It lives beside the *new* read path on purpose. The claim this
    /// item rests on is "the enumeration gets its own query and
    /// invariant 1 is unchanged", and the place a future reader will be
    /// tempted to widen the candidate query is here, while adding a
    /// column to the overview.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn no_gc_protected_artifact_reaches_the_retention_candidates() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        let repo_id = seed_repository(&pool, "oci-inv1").await;
        let mut protected: Vec<(Uuid, &str)> = Vec::new();
        for (name, status) in crate::GC_PROTECTED_QUARANTINE_STATUSES {
            let id = seed_artifact(&pool, repo_id, &format!("inv1-{name}"), name, Some(0)).await;
            assert_eq!(
                quarantine_status_to_sql(status).as_deref(),
                Some(name),
                "the constant's literal and its variant must agree"
            );
            protected.push((id, name));
        }
        // A control row in a non-protected state, so the test can tell
        // "the query protected every status" from "the query returned
        // nothing at all".
        let released = seed_artifact(&pool, repo_id, "inv1-released", "released", Some(0)).await;

        let reader = PgRetentionCandidateReader::new(pool.clone());
        let candidates = reader
            .list_candidates(500, None, Utc::now())
            .await
            .expect("candidate listing");
        let ids: Vec<Uuid> = candidates.iter().map(|c| c.artifact.id).collect();

        for (id, name) in &protected {
            assert!(
                !ids.contains(id),
                "a `{name}` artifact reached the retention candidates — \
                 invariant 1 protects it as evidence, not GC fodder"
            );
        }
        assert!(
            ids.contains(&released),
            "the control row did not reach the candidates either, so this \
             test proves nothing about the protected statuses"
        );
    }

    // -- the two queries answer over real rows ------------------------------

    /// The category end to end: an expired window under a `Required`
    /// policy is held; a live window, a non-`Required` mode, a
    /// soft-deleted row and a repository with no policy at all are not.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_category_is_exactly_the_sql_conditions() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        let gated = seed_repository(&pool, "oci-gated").await;
        let lenient = seed_repository(&pool, "oci-lenient").await;
        let unpolicied = seed_repository(&pool, "oci-unpolicied").await;
        seed_repo_policy(&pool, gated, 60, "required").await;
        seed_repo_policy(&pool, lenient, 60, "verify_if_present").await;

        // Window opened 3600 s ago against a 60 s duration: expired.
        let held = seed_artifact(&pool, gated, "held", QUARANTINED, Some(3600)).await;
        // Opened 10 s ago: still inside the window, so not yet held
        // *past* its deadline.
        let inside = seed_artifact(&pool, gated, "inside", QUARANTINED, Some(10)).await;
        // No window anchor at all: no deadline, so not in the category.
        let anchorless = seed_artifact(&pool, gated, "anchorless", QUARANTINED, None).await;
        // Expired, but the gate does not require provenance.
        let lenient_row = seed_artifact(&pool, lenient, "lenient", QUARANTINED, Some(3600)).await;
        // Expired and `Required`, but soft-deleted.
        let deleted = seed_artifact(&pool, gated, "deleted", QUARANTINED, Some(3600)).await;
        sqlx::query("UPDATE artifacts SET deleted_at = now() WHERE id = $1")
            .bind(deleted)
            .execute(&pool)
            .await
            .expect("soft delete");
        // Expired, but the repository resolves no policy.
        let no_policy = seed_artifact(&pool, unpolicied, "nopol", QUARANTINED, Some(3600)).await;
        // Expired and `Required`, but already released.
        let released = seed_artifact(&pool, gated, "released", "released", Some(3600)).await;

        let reader = PgHeldSetReader::new(pool.clone());
        let ids = page_ids(&reader, HeldBucket::InOwnRight, None).await;

        assert_eq!(ids, vec![held], "only the expired Required row is held");
        for (id, why) in [
            (inside, "its window has not expired"),
            (anchorless, "it has no window anchor, so no deadline"),
            (lenient_row, "its policy does not require provenance"),
            (deleted, "it is soft-deleted"),
            (no_policy, "its repository resolves no policy"),
            (released, "it is not quarantined"),
        ] {
            assert!(!ids.contains(&id), "excluded because {why}");
        }

        // The aggregate agrees with the drill-down's superset.
        let buckets = reader
            .aggregate_candidates(Utc::now(), kind_sets())
            .await
            .expect("aggregate");
        assert_eq!(buckets.len(), 1);
        assert!(buckets[0].repository_key.starts_with("oci-gated"));
        assert_eq!(buckets[0].bucket, HeldBucket::InOwnRight);
        assert_eq!(buckets[0].artifact_count, 1);
        assert_eq!(buckets[0].distinct_content_count, 1);
    }

    /// The repository's own non-archived policy beats the global one,
    /// and **both halves come from that one row**: the repo policy here
    /// carries a long duration and `verify_if_present`, the global a
    /// short duration and `required`. If the two halves could come from
    /// different rows the artifact would be reported as held (global
    /// duration expired × global mode required); from one row it is not.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn duration_and_mode_come_from_one_resolved_policy_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        let repo = seed_repository(&pool, "oci-precedence").await;
        seed_global_policy(&pool, 60, "required").await;
        seed_repo_policy(&pool, repo, 86_400, "verify_if_present").await;
        let artifact = seed_artifact(&pool, repo, "mixed", QUARANTINED, Some(3600)).await;

        let reader = PgHeldSetReader::new(pool.clone());
        let ids = page_ids(&reader, HeldBucket::InOwnRight, None).await;
        assert!(
            !ids.contains(&artifact),
            "the repo policy supplies BOTH halves: its window has not \
             expired and it does not require provenance"
        );

        // Archive the repo-scoped policy and the global one takes over —
        // again both halves together.
        sqlx::query("UPDATE policy_projections SET archived = true WHERE scope ? 'Repository'")
            .execute(&pool)
            .await
            .expect("archive repo policy");
        let ids = page_ids(&reader, HeldBucket::InOwnRight, None).await;
        assert_eq!(ids, vec![artifact], "the global policy now governs");
    }

    /// Rows are not bytes (ADR 0054): three artifacts sharing two
    /// content hashes report `artifact_count = 3` and
    /// `distinct_content_count = 2`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_aggregate_reports_rows_and_distinct_contents() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        let repo = seed_repository(&pool, "oci-cas").await;
        seed_repo_policy(&pool, repo, 60, "required").await;
        let shared = hex_hash(7);
        for name in ["a", "b"] {
            seed_artifact_with_hash(&pool, repo, name, QUARANTINED, Some(3600), &shared).await;
        }
        seed_artifact(&pool, repo, "c", QUARANTINED, Some(3600)).await;

        let reader = PgHeldSetReader::new(pool.clone());
        let buckets = reader
            .aggregate_candidates(Utc::now(), kind_sets())
            .await
            .expect("aggregate");
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].artifact_count, 3);
        assert_eq!(
            buckets[0].distinct_content_count, 2,
            "two of the three rows share their bytes"
        );
    }

    /// The oldest anchor in the cell is the age the operator reads.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_aggregate_reports_the_oldest_anchor_in_the_cell() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        let repo = seed_repository(&pool, "oci-age").await;
        seed_repo_policy(&pool, repo, 60, "required").await;
        seed_artifact(&pool, repo, "young", QUARANTINED, Some(600)).await;
        seed_artifact(&pool, repo, "old", QUARANTINED, Some(90_000)).await;

        let reader = PgHeldSetReader::new(pool.clone());
        let now = Utc::now();
        let buckets = reader
            .aggregate_candidates(now, kind_sets())
            .await
            .expect("aggregate");
        let age = buckets[0].oldest_age_secs(now);
        assert!(
            (89_000..92_000).contains(&age),
            "expected the OLDER row's age, got {age}"
        );
    }

    /// Keyset paging, the repository filter and the defensive clamp.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_page_is_keyset_ordered_and_filterable() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        let repo = seed_repository(&pool, "oci-page").await;
        let other = seed_repository(&pool, "oci-other").await;
        seed_repo_policy(&pool, repo, 60, "required").await;
        seed_repo_policy(&pool, other, 60, "required").await;
        for n in 0..3 {
            seed_artifact(&pool, repo, &format!("p{n}"), QUARANTINED, Some(3600)).await;
        }
        let elsewhere = seed_artifact(&pool, other, "x", QUARANTINED, Some(3600)).await;

        let reader = PgHeldSetReader::new(pool.clone());
        let all = page_ids(&reader, HeldBucket::InOwnRight, None).await;
        assert_eq!(all.len(), 4);
        let mut sorted = all.clone();
        sorted.sort();
        assert_eq!(all, sorted, "rows come back in artifact_id order");

        // One row at a time, resuming from the cursor.
        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let rows = reader
                .list_candidates(query(HeldBucket::InOwnRight, None, cursor, 1))
                .await
                .expect("page");
            let Some(row) = rows.first() else { break };
            seen.push(row.artifact_id);
            cursor = Some(row.artifact_id);
        }
        assert_eq!(seen, all, "paging one row at a time visits every row once");

        // The repository filter narrows, and the clamp holds an
        // oversize limit to the bound without erroring.
        let only_other = page_ids(&reader, HeldBucket::InOwnRight, Some(other)).await;
        assert_eq!(only_other, vec![elsewhere]);
        let clamped = reader
            .list_candidates(query(HeldBucket::InOwnRight, None, None, u32::MAX))
            .await
            .expect("an oversize limit is clamped, not refused, at the adapter");
        assert_eq!(clamped.len(), 4);
    }

    // -- fixtures -----------------------------------------------------------

    /// Per-test isolated database. `None` when `DATABASE_URL` is unset —
    /// the one skip condition; from there every failure is a hard
    /// failure (`migrate_or_panic`).
    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;
        Some(pool)
    }

    fn kind_sets() -> ConstituentKindSets<'static> {
        ConstituentKindSets {
            blob_kinds: &PARENT_GATE_BLOB_KINDS,
            self_referential_kinds: &SELF_REFERENTIAL_KINDS,
        }
    }

    fn query(
        bucket: HeldBucket,
        repository_id: Option<Uuid>,
        after: Option<Uuid>,
        limit: u32,
    ) -> HeldCandidateQuery<'static> {
        HeldCandidateQuery {
            now: Utc::now(),
            kinds: kind_sets(),
            bucket,
            repository_id,
            after,
            limit,
        }
    }

    async fn page_ids(
        reader: &PgHeldSetReader,
        bucket: HeldBucket,
        repository_id: Option<Uuid>,
    ) -> Vec<Uuid> {
        reader
            .list_candidates(query(bucket, repository_id, None, 500))
            .await
            .expect("page")
            .into_iter()
            .map(|r| r.artifact_id)
            .collect()
    }

    /// A 64-hex content hash that is stable per `seed`, so two artifacts
    /// can be made to share their bytes on purpose.
    fn hex_hash(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
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

    async fn seed_repo_policy(pool: &PgPool, repo: Uuid, duration_secs: i64, mode: &str) {
        seed_policy(
            pool,
            serde_json::json!({ "Repository": repo }),
            duration_secs,
            mode,
        )
        .await;
    }

    async fn seed_global_policy(pool: &PgPool, duration_secs: i64, mode: &str) {
        seed_policy(pool, serde_json::json!("Global"), duration_secs, mode).await;
    }

    async fn seed_policy(pool: &PgPool, scope: serde_json::Value, duration_secs: i64, mode: &str) {
        sqlx::query(
            r#"INSERT INTO public.policy_projections (
                   policy_id, name, scope, severity_threshold,
                   rescan_interval_hours, quarantine_duration_secs,
                   require_approval, provenance_mode, archived, stream_version
               ) VALUES ($1, $2, $3, 'high', 24, $4, false, $5, false, 1)"#,
        )
        .bind(Uuid::new_v4())
        .bind(format!("held-set-policy-{}", Uuid::new_v4().simple()))
        .bind(&scope)
        .bind(duration_secs)
        .bind(mode)
        .execute(pool)
        .await
        .expect("seed policy");
    }

    /// Seed one artifact. `window_age_secs` is how long ago its
    /// quarantine window opened; `None` leaves the anchor unset, which
    /// is the "no deadline" row.
    async fn seed_artifact(
        pool: &PgPool,
        repo: Uuid,
        name: &str,
        status: &str,
        window_age_secs: Option<i64>,
    ) -> Uuid {
        let hash = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        seed_artifact_with_hash(pool, repo, name, status, window_age_secs, &hash).await
    }

    async fn seed_artifact_with_hash(
        pool: &PgPool,
        repo: Uuid,
        name: &str,
        status: &str,
        window_age_secs: Option<i64>,
        hash: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let window_start = window_age_secs.map(|secs| Utc::now() - chrono::Duration::seconds(secs));
        sqlx::query(
            r#"INSERT INTO public.artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   quarantine_status, created_at, updated_at,
                   quarantine_window_start
               ) VALUES (
                   $1, $2, $3, $3, '1.0.0', $4,
                   10, $5, 'application/octet-stream', $5,
                   $6, now(), now(), $7
               )"#,
        )
        .bind(id)
        .bind(repo)
        .bind(name)
        .bind(format!("{name}/1.0.0/{}.tgz", id.simple()))
        .bind(hash)
        .bind(status)
        .bind(window_start)
        .execute(pool)
        .await
        .expect("seed artifact");
        id
    }
}
