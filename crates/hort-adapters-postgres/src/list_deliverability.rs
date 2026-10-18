//! PostgreSQL implementation of the list-surface census: one recursive
//! statement that turns a set of candidate manifest hashes into the
//! subset a hort-built document must omit.
//!
//! # What the statement walks, and what it is allowed to get wrong
//!
//! The closure comes from `content_references`, the membership
//! projection, and never from CAS. A candidate's descent is
//! `member hash → artifacts.checksum_sha256 → artifacts.id →
//! content_references.source_artifact_id → target_content_hash`,
//! repeated, restricted to the OCI membership kinds
//! (`hort_domain::ports::list_deliverability::CLOSURE_EDGE_KINDS`). The
//! verdict is then one semi-join: a candidate is withheld when **any**
//! member of its closure — itself included, since the seed is the
//! candidate's own hash — has a live row in a terminal status.
//!
//! The semi-join is an `EXISTS` rather than a plain join, which is a
//! measured choice and not a style one: the join form carries the
//! closure's whole row set into a merge join against the repository's
//! artifacts, and cost 10–11 ms where this costs 2.3–3.0 ms on the same
//! corpus (see the measurement below). A variant that instead resolved
//! each member's row inside the recursion and carried the status through
//! it was worse still, at 76–93 ms.
//!
//! **The projection is allowed to be incomplete, and the direction of
//! that incompleteness is why this is safe.** A manifest row minted
//! before the OCI membership edges began committing with their claiming
//! artifact — the ADR 0043 amendment dated 2026-10-07 — can carry no
//! `oci_config` / `oci_layer` / `oci_index_member` rows at all, and the
//! `oci-membership-edge-backfill` task exists to repair exactly those.
//! A missing edge makes this census **under**-report: the entry stays in
//! the list and the subsequent pull refuses it, which is precisely the
//! behaviour that preceded this census — no regression, and it fails
//! **open** rather than hiding something the registry would have served.
//!
//! The converse cannot happen. An edge is written only from a *complete*
//! resolution of what a document declares, inside the claiming
//! artifact's own transaction, so the projection cannot nominate a
//! constituent a document does not bind. There is therefore no path by
//! which a stale edge removes a deliverable entry from a client's list.
//!
//! The by-the-bytes sibling, `crate::constituent_status`, makes the
//! opposite authority choice for the same question, and deliberately:
//! its caller already holds the document's bytes, so reading them costs
//! nothing, while a list surface holds no bytes and would pay N CAS-read
//! trees for the same answer.
//!
//! # Why every membership test is a join and not `= ANY`
//!
//! Three sets are bound here — the candidate hashes, the closure edge
//! kinds and the terminal statuses — and all three are unnested into
//! CTEs and joined. `= ANY($n::text[])` reads more naturally and is a
//! latency trap under a prepared statement: Postgres folds bound
//! parameters into constants only while it builds **custom** plans, and
//! from the sixth execution on a pooled connection the statement flips
//! to a **generic** plan, where the array stays a `Param`, can no longer
//! be hashed, and the filter degrades to a linear scan of the whole
//! array per candidate row — with nothing in the query, the data or the
//! configuration having changed. Measured on this project's corpus at
//! 1.7 s as a join against 64.2 s as an array filter (see
//! [`crate::retention_preview`], [`crate::event_repository_resolver`]
//! and [`crate::constituent_status`], the same rewrite for the same
//! reason). Do not "simplify" any of them back.
//!
//! # Why the statement spells out no status
//!
//! The terminal vocabulary is bound from
//! [`terminal_status_binding`](crate::quarantine_status_sql), the crate's
//! one derivation of "the statuses `QuarantineStatus::is_terminal` calls
//! terminal, in the column's stored spelling". A literal
//! `IN ('rejected','scan_indeterminate')` would be a second definition
//! of the predicate, and a sixth terminal `QuarantineStatus` variant
//! would leave the list surfaces advertising what the pull refuses with
//! nothing in the build failing.
//! `crates/hort-adapters-postgres/tests/census_status_set_is_derived.rs`
//! is the DB-free guard.
//!
//! # Termination
//!
//! The recursive term is a `UNION` — distinct, not `UNION ALL` — so the
//! walk stops when it produces no `(candidate, member)` pair it has not
//! already produced. The pair set is finite inside one repository, which
//! makes a cyclic or self-referential edge set terminate rather than
//! spin: content addressing cannot express a cycle, but the projection
//! is relational and nothing in the schema forbids one. There is
//! therefore no arbitrary depth or expansion cap here, unlike the
//! by-the-bytes sibling: that walk spends a CAS read per node and has to
//! bound what it will fetch, while this one is a single statement whose
//! work is bounded by the repository's own edge count.
//!
//! # Measured cost, and the one spike in it
//!
//! Measured 2026-10-14 against a seeded 22,001-artifact / 22,000-edge
//! repository (2,000 image manifests, each one config blob plus ten
//! layers, the config shared across all of them — the production shape):
//! **2.3–3.0 ms** per call, flat across candidate pages of 1, 10, 100,
//! 1,000 and 2,000, and 45 ms in the pathological case where all 2,000
//! candidates are withheld. The cost is flat in the page because the
//! dominant term is the repository's edge set, not the candidate count.
//!
//! The **first five executions on a fresh pooled connection cost
//! 166–197 ms**, and the reason is worth knowing before someone chases
//! it: a recursive CTE's row estimate is structurally pessimistic
//! (22,002,000 estimated against 24,000 actual on that corpus), which
//! lifts the custom plan's cost over `jit_above_cost` and buys ~160 ms
//! of LLVM compilation per execution. From the sixth execution the
//! statement flips to a generic plan whose estimate sits below the
//! threshold, JIT stops firing, and the steady state above is what a
//! long-lived pool sees. Note the direction: here the custom→generic
//! flip is a 50× **improvement**, the opposite of the `= ANY` cliff
//! above — which is why the two must not be confused when reading a
//! latency graph after a restart.
//!
//! # Liveness, not identity
//!
//! Both the descent and the verdict filter `deleted_at IS NULL`, the
//! same posture as `crate::constituent_status` and as every live
//! `ArtifactRepository` read: deliverability is their question, so a
//! retired row is as absent here as it is there. Absence is not a
//! verdict — a candidate nobody has ingested yet stays in the list,
//! because a cold pull-through is the ordinary way an OCI tag or a
//! referrer descriptor names a digest this registry does not hold.

use std::collections::HashSet;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::list_deliverability::{ListDeliverabilityCensus, CLOSURE_EDGE_KINDS};
use hort_domain::types::ContentHash;

use crate::quarantine_status_sql::terminal_status_binding;
use crate::{map_sqlx_error, BoxFuture};

/// The one statement. Hoisted to a `const` so the DB-free guard can read
/// it without lexing the method body around it.
const NON_DELIVERABLE_IN_SQL: &str = r#"
    WITH RECURSIVE candidates AS (
        SELECT content_hash
          FROM unnest($2::text[]) AS c(content_hash)
    ),
    closure_kinds AS (
        SELECT kind
          FROM unnest($3::text[]) AS k(kind)
    ),
    terminal AS (
        SELECT status
          FROM unnest($4::text[]) AS t(status)
    ),
    closure AS (
        SELECT c.content_hash AS candidate, c.content_hash AS member
          FROM candidates c
        UNION
        SELECT cl.candidate, e.target_content_hash AS member
          FROM closure cl
          JOIN artifacts parent
            ON parent.checksum_sha256 = cl.member
           AND parent.repository_id = $1
           AND parent.deleted_at IS NULL
          JOIN content_references e
            ON e.source_artifact_id = parent.id
           AND e.repository_id = $1
          JOIN closure_kinds k ON k.kind = e.kind
    )
    SELECT DISTINCT cl.candidate AS candidate
      FROM closure cl
     WHERE EXISTS (
         SELECT 1
           FROM artifacts a
           JOIN terminal t ON t.status = a.quarantine_status
          WHERE a.checksum_sha256 = cl.member
            AND a.repository_id = $1
            AND a.deleted_at IS NULL
     )
"#;

/// Read-only Postgres census for the list surfaces' omission decision.
pub struct PgListDeliverabilityCensus {
    pool: PgPool,
}

impl PgListDeliverabilityCensus {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The closure edge kinds in their stored spelling — the `$3`
    /// binding.
    ///
    /// `pub` so the DB-free guard can assert the binding against the
    /// domain constant directly rather than inferring it from the
    /// statement text. Nothing in production calls it except the one
    /// query below.
    #[must_use]
    pub fn closure_kind_binding() -> Vec<String> {
        CLOSURE_EDGE_KINDS
            .iter()
            .map(|kind| (*kind).to_string())
            .collect()
    }

    /// The terminal statuses in their stored spelling — the `$4`
    /// binding. Delegates to the crate's one derivation; see
    /// [`crate::quarantine_status_sql::terminal_status_binding`].
    ///
    /// `pub` for the same reason as [`Self::closure_kind_binding`].
    #[must_use]
    pub fn terminal_status_binding() -> Vec<String> {
        terminal_status_binding()
    }
}

impl ListDeliverabilityCensus for PgListDeliverabilityCensus {
    fn non_deliverable_in<'a>(
        &'a self,
        repository_id: Uuid,
        candidates: &'a [ContentHash],
    ) -> BoxFuture<'a, DomainResult<HashSet<ContentHash>>> {
        let hashes: Vec<String> = candidates
            .iter()
            .map(|hash| hash.as_ref().to_string())
            .collect();
        Box::pin(async move {
            // A document that names nothing asks about nothing; do not
            // spend a round trip proving it.
            if hashes.is_empty() {
                return Ok(HashSet::new());
            }
            tracing::debug!(
                %repository_id,
                candidate_count = hashes.len(),
                "non_deliverable_in"
            );
            let rows = sqlx::query(NON_DELIVERABLE_IN_SQL)
                .bind(repository_id)
                .bind(&hashes)
                .bind(Self::closure_kind_binding())
                .bind(Self::terminal_status_binding())
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "list_deliverability", "non_deliverable_in"))?;
            let mut withheld = HashSet::with_capacity(rows.len());
            for row in rows {
                let raw: String = row
                    .try_get("candidate")
                    .map_err(|e| decode_error("candidate", &e))?;
                withheld.insert(raw.parse::<ContentHash>()?);
            }
            Ok(withheld)
        })
    }
}

fn decode_error(column: &str, e: &sqlx::Error) -> DomainError {
    DomainError::Invariant(format!("list_deliverability row decode ({column}): {e}"))
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

    /// A distinct synthetic sha256 per `seed` byte.
    fn hash_of(seed: u8) -> ContentHash {
        format!("{seed:02x}")
            .repeat(32)
            .parse()
            .expect("synthetic sha256")
    }

    /// Seed one artifact row at `hash_of(seed)` carrying `status`, and
    /// return its id so an edge can be hung off it.
    async fn seed_artifact(
        pool: &PgPool,
        repo: Uuid,
        seed: u8,
        status: QuarantineStatus,
        deleted: bool,
    ) -> Uuid {
        let hash = hash_of(seed);
        let name = format!("pkg-{}", Uuid::new_v4());
        sqlx::query_scalar(
            r#"INSERT INTO artifacts (
                   repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   quarantine_status, deleted_at
               ) VALUES (
                   $1, $2, $2, '1.0.0', $3,
                   1, $4, 'application/octet-stream', $3,
                   $5, CASE WHEN $6 THEN now() ELSE NULL END
               ) RETURNING id"#,
        )
        .bind(repo)
        .bind(&name)
        .bind(format!("{name}/{hash}"))
        .bind(hash.as_ref())
        .bind(quarantine_status_to_sql(status))
        .bind(deleted)
        .fetch_one(pool)
        .await
        .expect("seed artifact")
    }

    async fn seed_edge(pool: &PgPool, repo: Uuid, source: Uuid, kind: &str, target: &ContentHash) {
        sqlx::query(
            r#"INSERT INTO content_references (
                   repository_id, source_artifact_id, target_content_hash, kind,
                   metadata, recorded_at
               ) VALUES ($1, $2, $3, $4, '{}'::jsonb, now())"#,
        )
        .bind(repo)
        .bind(source)
        .bind(target.as_ref())
        .bind(kind)
        .execute(pool)
        .await
        .expect("seed content_reference");
    }

    /// Every status answers according to the predicate when it is the
    /// candidate's **own**. Driven off `QuarantineStatus::ALL` so the
    /// live behaviour is pinned against the predicate over the whole
    /// vocabulary rather than against a hand-written list.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn every_own_status_answers_according_to_the_terminal_predicate() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let census = PgListDeliverabilityCensus::new(pool.clone());
        for (index, status) in QuarantineStatus::ALL.into_iter().enumerate() {
            let repo = seed_repo(&pool).await;
            let seed = u8::try_from(index).expect("five variants fit a byte");
            seed_artifact(&pool, repo, seed, status, false).await;
            let candidate = hash_of(seed);
            let withheld = census
                .non_deliverable_in(repo, std::slice::from_ref(&candidate))
                .await
                .expect("the census read succeeds");
            assert_eq!(
                withheld.contains(&candidate),
                status.is_terminal(),
                "{status} withholds the candidate iff is_terminal() holds for it"
            );
        }
    }

    /// The closure half: the candidate's own row is clean, and a config
    /// blob one hop below it is terminal. This is the case an
    /// own-status-only filter misses, and the real population behind the
    /// rule — a manifest sharing a rejected base layer.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_terminal_constituent_one_hop_down_withholds_the_candidate() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let manifest = seed_artifact(&pool, repo, 0x11, QuarantineStatus::Released, false).await;
        seed_artifact(&pool, repo, 0x22, QuarantineStatus::Rejected, false).await;
        seed_edge(&pool, repo, manifest, "oci_config", &hash_of(0x22)).await;

        let candidate = hash_of(0x11);
        let withheld = PgListDeliverabilityCensus::new(pool)
            .non_deliverable_in(repo, std::slice::from_ref(&candidate))
            .await
            .expect("the census read succeeds");
        assert!(
            withheld.contains(&candidate),
            "a rejected config blob withholds the manifest that binds it"
        );
    }

    /// Two hops: an index whose child manifest's layer is terminal. One
    /// hop would be an arbitrary cut — the index would be listed and the
    /// pull would then fail at the grandchild.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_terminal_grandchild_withholds_the_index() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let index = seed_artifact(&pool, repo, 0x31, QuarantineStatus::Released, false).await;
        let child = seed_artifact(&pool, repo, 0x32, QuarantineStatus::Released, false).await;
        seed_artifact(
            &pool,
            repo,
            0x33,
            QuarantineStatus::ScanIndeterminate,
            false,
        )
        .await;
        seed_edge(&pool, repo, index, "oci_index_member", &hash_of(0x32)).await;
        seed_edge(&pool, repo, child, "oci_layer", &hash_of(0x33)).await;

        let candidate = hash_of(0x31);
        let withheld = PgListDeliverabilityCensus::new(pool)
            .non_deliverable_in(repo, std::slice::from_ref(&candidate))
            .await
            .expect("the census read succeeds");
        assert!(
            withheld.contains(&candidate),
            "the walk is transitive: a terminal layer under a child manifest withholds the \
             index above it"
        );
    }

    /// `oci_subject` is not a closure edge. An attestation that points
    /// at a withdrawn image is a document in its own right and must stay
    /// listed — descending the subject relation would run it backwards
    /// against the one surface that exists to report it.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_terminal_subject_does_not_withhold_its_referrer() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let referrer = seed_artifact(&pool, repo, 0x41, QuarantineStatus::Released, false).await;
        seed_artifact(&pool, repo, 0x42, QuarantineStatus::Rejected, false).await;
        seed_edge(&pool, repo, referrer, "oci_subject", &hash_of(0x42)).await;

        let candidate = hash_of(0x41);
        assert!(
            !PgListDeliverabilityCensus::new(pool)
                .non_deliverable_in(repo, std::slice::from_ref(&candidate))
                .await
                .expect("the census read succeeds")
                .contains(&candidate),
            "a rejected subject must not withhold the referrer that describes it"
        );
    }

    /// Absence is not a verdict: a candidate with no catalog row at all
    /// is the ordinary cold-pull-through state and stays listed.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_candidate_with_no_row_is_not_withheld() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let absent = hash_of(0xfe);
        assert!(PgListDeliverabilityCensus::new(pool)
            .non_deliverable_in(repo, std::slice::from_ref(&absent))
            .await
            .expect("the census read succeeds")
            .is_empty());
    }

    /// A retired row is absent too, on both halves of the question: as a
    /// candidate and as a constituent.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_soft_deleted_row_is_absent_as_candidate_and_as_constituent() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        // Retired candidate, terminal in its own right.
        seed_artifact(&pool, repo, 0x51, QuarantineStatus::Rejected, true).await;
        // Live candidate over a retired terminal constituent.
        let live = seed_artifact(&pool, repo, 0x52, QuarantineStatus::Released, false).await;
        seed_artifact(&pool, repo, 0x53, QuarantineStatus::Rejected, true).await;
        seed_edge(&pool, repo, live, "oci_layer", &hash_of(0x53)).await;

        let withheld = PgListDeliverabilityCensus::new(pool)
            .non_deliverable_in(repo, &[hash_of(0x51), hash_of(0x52)])
            .await
            .expect("the census read succeeds");
        assert!(
            withheld.is_empty(),
            "a soft-deleted row no live read can see must not withhold anything; got {withheld:?}"
        );
    }

    /// The same bytes rejected in **another** repository withhold
    /// nothing here: the question is per repository, as every other
    /// artifact read is. Asserted on both halves — the candidate's own
    /// row and the edge's descent.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn another_repositorys_terminal_row_withholds_nothing() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let theirs = seed_repo(&pool).await;
        let mine = seed_repo(&pool).await;
        seed_artifact(&pool, theirs, 0x61, QuarantineStatus::Rejected, false).await;
        let mine_manifest =
            seed_artifact(&pool, mine, 0x62, QuarantineStatus::Released, false).await;
        // The constituent is terminal, but only in the other repository.
        seed_artifact(&pool, theirs, 0x63, QuarantineStatus::Rejected, false).await;
        seed_edge(&pool, mine, mine_manifest, "oci_config", &hash_of(0x63)).await;

        let withheld = PgListDeliverabilityCensus::new(pool)
            .non_deliverable_in(mine, &[hash_of(0x61), hash_of(0x62)])
            .await
            .expect("the census read succeeds");
        assert!(
            withheld.is_empty(),
            "repository scope holds on both halves of the question; got {withheld:?}"
        );
    }

    /// A batch answers per candidate: the clean one survives and the
    /// withheld one does not, in one call. This is the shape both list
    /// surfaces depend on — the census is a filter over the caller's own
    /// list, so it must never answer about a hash the caller did not
    /// supply.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_batch_withholds_only_the_candidates_that_earn_it() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let clean = seed_artifact(&pool, repo, 0x71, QuarantineStatus::Released, false).await;
        seed_artifact(&pool, repo, 0x72, QuarantineStatus::Quarantined, false).await;
        seed_edge(&pool, repo, clean, "oci_layer", &hash_of(0x72)).await;
        let dirty = seed_artifact(&pool, repo, 0x73, QuarantineStatus::Released, false).await;
        seed_artifact(&pool, repo, 0x74, QuarantineStatus::Rejected, false).await;
        seed_edge(&pool, repo, dirty, "oci_layer", &hash_of(0x74)).await;

        let withheld = PgListDeliverabilityCensus::new(pool)
            .non_deliverable_in(repo, &[hash_of(0x71), hash_of(0x73)])
            .await
            .expect("the census read succeeds");
        assert_eq!(
            withheld,
            HashSet::from([hash_of(0x73)]),
            "a held constituent is a 'not yet' and leaves its parent listed; a rejected one \
             withholds it — and the answer names only candidates the caller supplied"
        );
    }

    /// A cyclic edge set terminates. Content addressing cannot express a
    /// cycle, but the projection is relational and nothing in the schema
    /// forbids one — the `UNION`'s distinctness is what stops the walk,
    /// and this test is what proves the statement is not `UNION ALL`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_cyclic_edge_set_terminates() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let a = seed_artifact(&pool, repo, 0x81, QuarantineStatus::Released, false).await;
        let b = seed_artifact(&pool, repo, 0x82, QuarantineStatus::Released, false).await;
        seed_edge(&pool, repo, a, "oci_index_member", &hash_of(0x82)).await;
        seed_edge(&pool, repo, b, "oci_index_member", &hash_of(0x81)).await;
        // A self-edge too, the degenerate case of the same hazard.
        seed_edge(&pool, repo, a, "oci_layer", &hash_of(0x81)).await;

        let candidate = hash_of(0x81);
        assert!(PgListDeliverabilityCensus::new(pool)
            .non_deliverable_in(repo, std::slice::from_ref(&candidate))
            .await
            .expect("the census read terminates and succeeds")
            .is_empty());
    }

    /// An empty ask must not reach the database: a page with no
    /// hash-targeted entry is the common degenerate case on both list
    /// surfaces and owes no round trip.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn an_empty_ask_is_answered_without_a_round_trip() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        // Close the pool first: a statement issued against it would
        // error, so an `Ok` here proves no statement was issued.
        pool.close().await;
        assert!(PgListDeliverabilityCensus::new(pool)
            .non_deliverable_in(Uuid::new_v4(), &[])
            .await
            .expect("an empty ask must short-circuit before touching the pool")
            .is_empty());
    }
}
