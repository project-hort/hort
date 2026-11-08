//! `jobs.trigger_source` — real-adapter write **and** read proofs for the
//! two literals a `kind='scan'` row can carry beyond the four the domain
//! type used to know.
//!
//! The set `jobs.trigger_source` may hold was written down three times
//! and no two copies agreed: the SQL CHECK admitted eight literals, the
//! domain type named four while claiming to mirror the CHECK, and the
//! writers produced a ninth (`'register-by-hash'`) that was in neither.
//! That left two independent defects on the same column, one on each
//! side of it, and this file pins both against a real database.
//!
//! **The write side.** `IngestUseCase::register_by_hash` stamps
//! `'register-by-hash'` on the scan it enqueues for a mount or a
//! pull-dedup follower, and the CHECK refused it — aborting the ingest
//! transition the enqueue rides inside, which the OCI cross-repository
//! blob mount surfaced as `500`.
//! `036_jobs_trigger_source_register_by_hash.sql` redefines the
//! constraint; the enqueue test below is the proof that the redefinition
//! applies cleanly on top of 009's inline CHECK and that the literal
//! lands. (The end-to-end mount proof is
//! `crates/hort-server/tests/oci_cross_mount_scan_enqueue_real_db.rs`.)
//!
//! **The read side.** `'seed-import'` was *already* accepted by the CHECK
//! and *already* written onto `kind='scan'` rows by the seed import's own
//! `register_by_hash` enqueues — but `TriggerSource::FromStr` rejected
//! it, and both scan-row readers parse through that `FromStr` and turn a
//! miss into `DomainError::Invariant`. So a seed-imported artifact's
//! first scan could not be reconstructed from its row at all. Widening
//! the type to the whole set fixes that; `claim_scan_jobs` is where this
//! file proves it, against a row written by the production enqueue path
//! rather than a hand-built `ScanJob`.
//!
//! **The read side's reach, which is a decision.** Widening the type
//! means a scan row carrying ANY member of the set is now claimed, where
//! a narrower type refused the ones it did not know. That reach was
//! chosen rather than inherited;
//! `every_globally_valid_trigger_source_is_accepted_on_a_scan_row`
//! states it and says why rejection was not chosen, and the rationale
//! also sits next to the acceptance in `row_to_scan_job`.
//!
//! Sibling of `jobs_kind_check_oci_edge_backfill.rs`, which does the same
//! job for the `jobs.kind` constraint. The DB-free lock-step guard
//! `jobs_trigger_source_check_lockstep_guard.rs` cannot reach either
//! surface: it proves the newest defining migration's list agrees with
//! `TriggerSource::ALL`, but only a real migrate-then-INSERT-then-SELECT
//! proves the migration applies to a database that already carries 009's
//! constraint, that the redefined constraint admits the literal, and that
//! the row reads back.
//!
//! ## Isolation contract
//!
//! Every test acquires a real connection via [`maybe_pool`] and
//! therefore carries `#[serial(hort_pg_db)]` per CLAUDE.md → Test
//! Coverage Tiers → DB-backed test isolation.
//!
//! ## Self-skip without `DATABASE_URL`
//!
//! Like every DB-gated test in this crate, each early-returns silently
//! when `DATABASE_URL` is unset (the local `cargo test --workspace`
//! gate), and runs in CI's Tier-2 integration job which sets the DSN.

#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::env;
use std::time::Duration;

use serial_test::serial;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_adapters_postgres::jobs_repository::PgJobsRepository;
use hort_domain::ports::jobs_repository::{JobsRepository, TriggerSource};
use hort_domain::types::task_tier::scan_queue_priority;
use hort_domain::types::ContentHash;

async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

/// A unique, valid 64-lowercase-hex SHA-256. Two 32-hex uuid halves —
/// `format!("{:0<64}", id.simple())` does NOT work, because
/// `uuid::Simple`'s `Display` ignores width/fill flags.
fn unique_hash() -> ContentHash {
    Uuid::new_v4()
        .simple()
        .to_string()
        .repeat(2)
        .parse()
        .expect("valid sha256")
}

/// Enqueue a `kind='scan'` row through the production entry point, with
/// `trigger_source` as given, and return its id.
///
/// `enqueue_scan` rather than a raw INSERT on purpose: the row has to be
/// written by the code path a mount or a seed import actually uses, so
/// the CHECK is being asked about the binding `enqueue_scan_in_tx`'s
/// sibling performs and the priority is the one `scan_queue_priority`
/// answers.
async fn enqueue_scan_with(jobs: &PgJobsRepository, trigger_source: &str) -> Uuid {
    let hash = unique_hash();
    jobs.enqueue_scan(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &hash,
        "oci",
        scan_queue_priority(trigger_source),
        trigger_source,
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "enqueue_scan with trigger_source={trigger_source:?} must succeed — a 23514 \
             check_violation here means the effective jobs.trigger_source CHECK (the newest \
             migration that redefines it) is missing the literal: {e}"
        )
    })
}

/// Claim every pending `kind='scan'` row in this isolated database and
/// return each row's id with the `trigger_source` the row mapper decoded
/// for it.
///
/// One helper for all three read-side proofs below: they differ in which
/// literals they put in and what they expect back, not in how the claim
/// is made. `claim_scan_jobs` rather than a SELECT, because the row
/// mapper's `FromStr` is the thing under test and the claim path is where
/// production reaches it — a refusal there fails the WHOLE batch, which
/// is why a single unparseable literal used to take the scan pipeline
/// down rather than just its own row.
async fn claim_decoded_scan_rows(
    jobs: &PgJobsRepository,
    worker_id: &str,
) -> HashMap<Uuid, TriggerSource> {
    jobs.claim_scan_jobs(worker_id, 64, Duration::from_secs(60))
        .await
        .expect(
            "claiming the enqueued scan rows must succeed — an Invariant here is the row \
             mapper's FromStr refusing a literal the column accepts and a producer writes, \
             and it fails every row in the batch, not only the offending one",
        )
        .into_iter()
        .map(|job| (job.id, job.trigger_source))
        .collect()
}

/// **Write side.** Every member of the set enqueues through the real
/// adapter path and lands — so the effective CHECK admits the whole of
/// `TriggerSource::ALL`, not merely the literal this change added.
///
/// Iterating the set rather than naming `'register-by-hash'` alone is
/// what makes the test survive the next widening: a literal added to the
/// type and to a migration that was never applied to this database fails
/// here.
#[tokio::test]
#[serial(hort_pg_db)]
async fn every_trigger_source_literal_survives_the_jobs_check() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jobs = PgJobsRepository::new(pool.clone());

    for source in TriggerSource::ALL {
        let id = enqueue_scan_with(&jobs, source.as_str()).await;
        let stored: String = sqlx::query("SELECT trigger_source FROM public.jobs WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read back the enqueued row")
            .get("trigger_source");
        assert_eq!(
            stored,
            source.as_str(),
            "the column must store the literal verbatim"
        );
    }
}

/// **Read side.** A `kind='scan'` row carrying `'seed-import'` claims,
/// and its `trigger_source` reads back as the typed variant.
///
/// This is the second consequence of the four-literal type, and it was
/// reachable without any widening of the CHECK: the seed import's
/// `register_by_hash` enqueues have always written `'seed-import'`, the
/// CHECK has always accepted it, and `claim_scan_jobs`' row mapper
/// parsed it through a `FromStr` that did not know it — returning
/// `DomainError::Invariant` for the whole claim batch. The dispatcher's
/// own reconstruction (`ScanTaskHandler::run`) parses through the same
/// `FromStr`, so the row could not be executed either.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_seed_import_scan_row_claims_and_decodes() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jobs = PgJobsRepository::new(pool.clone());
    let id = enqueue_scan_with(&jobs, TriggerSource::SeedImport.as_str()).await;

    let decoded = claim_decoded_scan_rows(&jobs, "it-seed-import-worker").await;
    assert_eq!(
        decoded.get(&id),
        Some(&TriggerSource::SeedImport),
        "a seed-imported artifact's first scan must be claimable and decode to its own variant"
    );
}

/// The same read proof for `'register-by-hash'` — the literal this
/// change admits. A mount's scan row is claimable and decodes to its own
/// variant rather than being folded into `Ingest`, which is what keeps
/// the caller-class distinction readable downstream.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_register_by_hash_scan_row_claims_and_decodes() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jobs = PgJobsRepository::new(pool.clone());
    let id = enqueue_scan_with(&jobs, TriggerSource::RegisterByHash.as_str()).await;

    let decoded = claim_decoded_scan_rows(&jobs, "it-register-by-hash-worker").await;
    assert_eq!(
        decoded.get(&id),
        Some(&TriggerSource::RegisterByHash),
        "a mount's scan row must decode to its own variant rather than being folded into \
         Ingest, which is what keeps the caller-class distinction readable downstream"
    );
}

/// **The recorded read-side decision: every globally valid trigger
/// source is accepted on a `kind='scan'` row.**
///
/// This test exists to state that decision, not to observe that nothing
/// currently rejects. The decision was live — the alternative was to keep
/// a scan-specific subset and refuse the rest — and it was made this way:
///
/// The schema already admits the combination. `jobs_trigger_source_check`
/// is not conditioned on `kind`, and `JobsRepository::enqueue_scan` takes
/// an unrestricted `&str`, so a scan row carrying `'prefetch'`,
/// `'self_service'` or `'scheduled'` is constructible today — this test
/// constructs nine of them through the production enqueue — even though
/// no current producer writes one. "No producer does" is a census of the
/// tree, not an invariant of the port.
///
/// Rejection was not chosen because it reintroduces a narrower copy of
/// the defect this file was written for: a row the column accepts, a
/// producer can write, and the claim path refuses — a scan row that
/// cannot be claimed. The two failures are not symmetric. A mislabelled
/// scan that RUNS leaves an audit inaccuracy; a scan that does not run
/// leaves an artifact ungated, and the `jobs` row is the system's only
/// record that the artifact is still owed a verdict. For a scanning
/// system the second is worse, so the read side accepts what the schema
/// accepts.
///
/// What is NOT accepted is a literal outside the set entirely — that is
/// schema drift rather than a mislabel, and
/// `a_literal_outside_the_set_is_still_refused` below is the half of the
/// decision that stays closed.
#[tokio::test]
#[serial(hort_pg_db)]
async fn every_globally_valid_trigger_source_is_accepted_on_a_scan_row() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jobs = PgJobsRepository::new(pool.clone());

    let mut enqueued: Vec<(Uuid, TriggerSource)> = Vec::new();
    for source in TriggerSource::ALL {
        enqueued.push((enqueue_scan_with(&jobs, source.as_str()).await, source));
    }

    let decoded = claim_decoded_scan_rows(&jobs, "it-whole-set-worker").await;
    assert_eq!(
        decoded.len(),
        TriggerSource::ALL.len(),
        "all {} scan rows must be in the claim batch; the claim filters on kind and status \
         only, so a missing row means the trigger source changed whether the row is \
         claimable at all",
        TriggerSource::ALL.len()
    );
    for (id, source) in enqueued {
        assert_eq!(
            decoded.get(&id),
            Some(&source),
            "a kind='scan' row carrying {:?} must be claimed and decode to its own variant — \
             the decision recorded on `row_to_scan_job` is that the read side accepts the \
             whole set, because a scan that cannot be claimed leaves an artifact ungated",
            source.as_str()
        );
    }
}

/// Counter-assertion: the CHECK is still a CHECK.
///
/// Without this, a migration that dropped the constraint and forgot to
/// re-add it would make every test above pass — the enqueues would land
/// and the rows would read back — while the column silently accepted
/// anything. `'api'` is the literal that caused the original
/// rotation-smoke 500 spiral and has never been a member of the set.
#[tokio::test]
#[serial(hort_pg_db)]
async fn a_literal_outside_the_set_is_still_refused() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jobs = PgJobsRepository::new(pool.clone());
    let hash = unique_hash();

    let err = jobs
        .enqueue_scan(Uuid::new_v4(), Uuid::new_v4(), &hash, "oci", 0, "api")
        .await
        .expect_err("'api' is not a trigger-source literal and the CHECK must refuse it");
    let text = err.to_string();
    assert!(
        text.contains("jobs_trigger_source_check"),
        "the refusal must come from the CHECK constraint, not from something else: {text}"
    );
}

/// The constraint a migrated database carries is the **explicitly
/// named** `jobs_trigger_source_check` the redefining migration adds —
/// not an anonymous re-add under a Postgres-generated name. Future
/// redefinitions drop it by that name, so the name itself is part of the
/// contract. Mirrors `jobs_kind_check_carries_its_explicit_name`.
#[tokio::test]
#[serial(hort_pg_db)]
async fn jobs_trigger_source_check_carries_its_explicit_name() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    let named: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint \
         WHERE conrelid = 'public.jobs'::regclass AND contype = 'c' \
           AND conname = 'jobs_trigger_source_check')",
    )
    .fetch_one(&pool)
    .await
    .expect("probe pg_constraint for jobs_trigger_source_check");
    assert!(
        named,
        "public.jobs must carry a CHECK constraint named `jobs_trigger_source_check` after \
         the migration chain — a future widening drops it by that name",
    );
}
