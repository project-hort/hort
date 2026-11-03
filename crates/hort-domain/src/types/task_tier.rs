//! `TaskTier` — the one definition of *who is waiting* on a queued
//! `jobs` row, and the one place the row's `priority` ordinal is decided.
//!
//! See ADR 0066 (background work never outranks the path a client is
//! waiting on), decisions D1, D2, D3, D6, D7 and D8.
//!
//! # Why this module exists
//!
//! The ordinal was retyped at every producer of work — twelve named
//! constants in eleven files plus twelve bare literals, with no shared
//! type and no shared module — so nothing existed for a reviewer to check
//! an assignment against. That is how "maintenance outranks publishing"
//! came to be written down in several places without ever reading as
//! wrong: an ingest scan sat at `0`, the lowest rank in the system, while
//! the cron rescans nobody waits on sat at `10`.
//!
//! # The two faces, and why they are separate functions
//!
//! [`TaskTier::classify`] is the **read** face: given the `(kind,
//! trigger_source)` a row already carries, which class is it? It is
//! derived rather than stored (ADR 0066 D7), so there is no column, no
//! migration and no backfill (D8), and a row an older binary wrote
//! classifies exactly like one a current binary wrote.
//!
//! [`queue_priority`] is the **write** face: the `jobs.priority` a fresh
//! row carries.
//!
//! **The write face is deliberately not derived from the tier.** Tier
//! order and today's numeric order disagree — an ingest scan is
//! [`TaskTier::Interactive`] and carries `0`; a cron rescan is
//! [`TaskTier::Bulk`] and carries `10` — and that disagreement is the
//! defect ADR 0066 names. Reconciling the two is the behaviour change,
//! and it ships as its own change so that rolling the fix back does not
//! roll back the vocabulary (ADR 0066 D8). Until then this function
//! reproduces, exactly, the number each producer wrote before the
//! vocabulary existed: `SELECT kind, trigger_source, priority FROM jobs`
//! for a freshly enqueued row is byte-identical across that boundary.
//!
//! The two faces are pinned against each other by
//! `tier_and_ordinal_disagree_today`, which asserts the disagreement
//! rather than apologising for it — so the change that removes it has to
//! delete an assertion.
//!
//! # The trigger-source vocabulary is not this module's
//!
//! Both faces key on `jobs.trigger_source`, and the set that column may
//! hold is defined once, in
//! [`ports::jobs_repository::TriggerSource`](crate::ports::jobs_repository::TriggerSource).
//! This module held its own private copy of the set for one release,
//! because the public type then named four of the CHECK's eight literals
//! and widening it would have changed what two scan-row read paths
//! accept — a behaviour change, and not that release's business. The
//! copy is gone: a copy is how the set came to be written down three
//! times with no two agreeing. Both matches below are wildcard-free over
//! the one type, so a new literal has to be given a tier and an ordinal
//! here before the build passes.
//!
//! # Scope of the vocabulary
//!
//! A tier is a property of work the dispatcher schedules. `kind =
//! 'verify-event-chain'` is therefore outside it rather than unassigned
//! within it: there is no `TaskHandler` for that kind and no worker
//! registration, its row is a liveness breadcrumb inserted `status =
//! 'completed'` by the `hort-server verify-event-chain` subcommand, and
//! nothing ever claims it. It gets no branch here for that reason.

use crate::ports::jobs_repository::TriggerSource;

// ---------------------------------------------------------------------------
// Kind literals this module's tables key on
// ---------------------------------------------------------------------------

/// `jobs.kind` of an artifact scan. The only kind whose `'manual'`
/// trigger outranks everything else today ([`MANUAL_RESCAN_PRIORITY`]).
const KIND_SCAN: &str = "scan";

/// `jobs.kind` of the operator one-shot quarantine seed. Distinct from
/// the `'seed-import'` *trigger source*, which the same subcommand also
/// writes — the pair `(kind, trigger_source) = ('seed-import',
/// 'seed-import')` is what makes that producer's ordinal reachable
/// without colliding with the scans the same import enqueues.
const KIND_SEED_IMPORT: &str = "seed-import";

/// `jobs.kind` of the quarantine-window release sweep — the path that
/// makes an ingested artifact available.
///
/// This is the one kind whose tier is *not* read off its trigger source,
/// and the carve-out is ADR 0066 D3: that a piece of work runs on a timer
/// says how it is triggered, never that nobody is waiting for its effect.
/// The sweep is enqueued by a CronJob and so carries `trigger_source =
/// 'cron'`, and ranking it with the scheduled rescans is precisely the
/// misassignment that left a pushed, window-elapsed artifact unreleased.
const KIND_QUARANTINE_RELEASE_SWEEP: &str = "quarantine-release-sweep";

// ---------------------------------------------------------------------------
// Ordinals
// ---------------------------------------------------------------------------

/// The `jobs.priority` schema default (migration 009), and what a row
/// whose `trigger_source` this module does not recognise is given.
///
/// Recognising nothing is the safe answer here: the column's `CHECK
/// (priority BETWEEN 0 AND 100)` and the claim query's `ORDER BY priority
/// DESC` make `0` the *last* row claimed, so an unparseable trigger
/// source cannot displace anything.
///
/// No producer in the tree writes a trigger source this module cannot
/// parse — [`TriggerSource`] is the set and the writers' constants are
/// defined from it — so the fallback is reached only by a row written by
/// a binary whose set was wider, or edited by hand. It was reachable from
/// production until `'register-by-hash'` joined the set, and that
/// producer wrote this same number, which is why
/// [`TriggerSource::RegisterByHash`] maps here explicitly: the ordinal a
/// mount's enqueue carries is unchanged by it becoming parseable.
const SCHEMA_DEFAULT_PRIORITY: i16 = 0;

/// Ordinal for an advisory-driven rescan. Below cron deliberately: the
/// cron rescan is the safety-net path that catches whatever the advisory
/// feed missed, so it is claimed first.
const ADVISORY_PRIORITY: i16 = 5;

/// Ordinal for every cron-triggered row — the scheduled rescan tick and
/// each of the six `hort-server enqueue-*` CronJob subcommands.
const CRON_PRIORITY: i16 = 10;

/// Ordinal for an operator-triggered rescan (`POST
/// /api/v1/artifacts/:id/rescan`) and for the `hort-server seed-import`
/// subcommand's own row.
const MANUAL_RESCAN_PRIORITY: i16 = 20;

/// `jobs.priority` for the **clearance-gating** `provenance-verify`
/// enqueue — the signature-arrival hook and the expiry backstop.
///
/// Not reachable from [`queue_priority`], and that is a property of the
/// row rather than of this module: the clearance-gating verify and the
/// ingest-time verify are both `kind = 'provenance-verify'` with
/// `trigger_source = 'ingest'`, they are both
/// [`TaskTier::Interactive`], and they write **different** ordinals (`10`
/// here, `0` at ingest). Nothing the row carries separates them, so no
/// derivation keyed on what the row carries can reproduce both. It is
/// kept verbatim rather than collapsed into `queue_priority`'s table
/// because collapsing it would change a number a producer writes today,
/// which is exactly what the vocabulary change must not do.
pub const CLEARANCE_GATING_VERIFY_PRIORITY: i16 = 10;

// ---------------------------------------------------------------------------
// TaskTier
// ---------------------------------------------------------------------------

/// Who is waiting on a queued work item (ADR 0066 D1).
///
/// Three variants because the question has three answers. A fourth would
/// have to name a fourth answer, and the evidence is that the producers
/// of work could not agree on three distinct values, so they will not
/// agree on seven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskTier {
    /// A client is waiting on this right now. The ingest-time gates —
    /// the first scan, the provenance verify — and the sweep that makes a
    /// quarantined artifact available are all in this class, the last of
    /// them even though a timer enqueues it (D3).
    Interactive,
    /// An operator is waiting for an answer: an admin task invoke, a
    /// manual rescan, a `hort-cli prefetch`, a seed import.
    Normal,
    /// Nobody is waiting. Scheduled rescans, the advisory sweep, the
    /// retention and row-retention sweeps, the prefetch cascade.
    Bulk,
}

impl TaskTier {
    /// Stable label, for a log field or a metric.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Normal => "normal",
            Self::Bulk => "bulk",
        }
    }

    /// Classify a `jobs` row from `(kind, trigger_source)`.
    ///
    /// Both arguments are columns the row already has, which is what
    /// makes this compatible with a mixed-version fleet (ADR 0066 D7):
    /// an older binary writes the ordinal it always wrote and this reads
    /// the same two columns off the same row. Nothing here requires a
    /// value only a newer writer would produce.
    ///
    /// `None` means "this row does not classify" — its `trigger_source`
    /// is not one of [`TriggerSource::ALL`]. A row like that does not
    /// acquire a tier by default, which is why the match below has no
    /// wildcard arm: a new literal has to be added to [`TriggerSource`]
    /// to be parsed at all, and adding it there fails the build here
    /// until somebody decides which class it belongs to.
    pub fn classify(kind: &str, trigger_source: &str) -> Option<Self> {
        // D3: the path that makes an artifact available is client-waited
        // even when it is scheduled. Read before the trigger source, so
        // the `'cron'` the CronJob stamps cannot file it with the
        // scheduled rescans it is supposed to outrank.
        if kind == KIND_QUARANTINE_RELEASE_SWEEP {
            return Some(Self::Interactive);
        }
        Some(match trigger_source.parse::<TriggerSource>().ok()? {
            // A client pushed, or pulled through, and the gates this
            // enqueues are what stand between those bytes and being
            // served. `RegisterByHash` is the same claim through a
            // different door: a cross-repository mount or a pull-dedup
            // follower is a client request waiting on its 201.
            TriggerSource::Ingest | TriggerSource::RegisterByHash => Self::Interactive,
            // An operator asked and is reading the answer.
            TriggerSource::Manual | TriggerSource::SeedImport | TriggerSource::SelfService => {
                Self::Normal
            }
            // Nobody is waiting: a timer, a feed, or a cascade the
            // server spawned for itself.
            TriggerSource::Cron
            | TriggerSource::Advisory
            | TriggerSource::Prefetch
            | TriggerSource::Scheduled => Self::Bulk,
        })
    }
}

// ---------------------------------------------------------------------------
// queue_priority
// ---------------------------------------------------------------------------

/// The `jobs.priority` a freshly enqueued row carries — **the** place the
/// ordinal is decided.
///
/// Keyed on `(kind, trigger_source)` rather than on
/// [`TaskTier::classify`]'s answer, because today's numbers and the tier
/// order disagree; see this module's header for why that disagreement is
/// preserved here rather than fixed.
///
/// The match over the trigger source has no wildcard arm for the same
/// reason [`TaskTier::classify`]'s does not: a new CHECK literal must
/// make a decision here, not inherit one.
pub fn queue_priority(kind: &str, trigger_source: &str) -> i16 {
    let Ok(source) = trigger_source.parse::<TriggerSource>() else {
        return SCHEMA_DEFAULT_PRIORITY;
    };
    match source {
        // Every ingest-time enqueue: the first scan, the ingest-time
        // provenance verify, the prefetch-dependencies cascade root, the
        // OCI index child rows.
        TriggerSource::Ingest => SCHEMA_DEFAULT_PRIORITY,
        TriggerSource::Advisory => ADVISORY_PRIORITY,
        TriggerSource::Cron => CRON_PRIORITY,
        // `ManualRescanUseCase` is the only producer that outranks cron.
        // Every other `'manual'` row is an admin task invoke or a
        // gitops-driven policy re-evaluation, both of which the admin
        // enqueue path writes at the schema default.
        TriggerSource::Manual => {
            if kind == KIND_SCAN {
                MANUAL_RESCAN_PRIORITY
            } else {
                SCHEMA_DEFAULT_PRIORITY
            }
        }
        // The `hort-server seed-import` subcommand's own row outranks
        // cron; the scans and verifies that import then enqueues ride
        // the same trigger source at the schema default.
        TriggerSource::SeedImport => {
            if kind == KIND_SEED_IMPORT {
                MANUAL_RESCAN_PRIORITY
            } else {
                SCHEMA_DEFAULT_PRIORITY
            }
        }
        // The cascade, the operator's `hort-cli prefetch` root, and the
        // prefetch tick's leaf rows all drain behind manual, cron and
        // advisory work.
        TriggerSource::Prefetch | TriggerSource::SelfService | TriggerSource::Scheduled => {
            SCHEMA_DEFAULT_PRIORITY
        }
        // The mount / pull-dedup-follower registration. The schema
        // default is the number this path already wrote: before the
        // literal joined the CHECK it did not parse, so it fell to the
        // `else` above and took this value.
        TriggerSource::RegisterByHash => SCHEMA_DEFAULT_PRIORITY,
    }
}

/// [`queue_priority`] for the kind
/// [`JobsRepository::enqueue_scan`](crate::ports::jobs_repository::JobsRepository::enqueue_scan)
/// fixes.
///
/// `enqueue_scan` is the only enqueue entry point whose `kind` is not a
/// parameter — it is the only writer of the four scan-typed columns, so
/// `'scan'` is baked into its INSERT. Without this its three producers
/// would each re-type that literal purely to ask this module a question
/// the entry point has already answered.
pub fn scan_queue_priority(trigger_source: &str) -> i16 {
    queue_priority(KIND_SCAN, trigger_source)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every literal `jobs.trigger_source` may hold, read off the one
    /// definition rather than re-typed.
    ///
    /// It used to be re-typed here, on the argument that the CHECK is SQL
    /// and the test owed the reader its own statement of the column's
    /// contents. That argument is spent: the set is now
    /// [`TriggerSource`], the SQL CHECK is checked against it by
    /// `jobs_trigger_source_check_lockstep_guard`, and a local copy would
    /// only let this module's tests keep passing over a set the column no
    /// longer has.
    fn check_trigger_sources() -> Vec<&'static str> {
        TriggerSource::ALL.iter().map(|v| v.as_str()).collect()
    }

    /// Every literal in the `jobs.kind` CHECK as migration 027 leaves it.
    const CHECK_KINDS: &[&str] = &[
        "scan",
        "cron-rescan-tick",
        "advisory-watch-tick",
        "retention-evaluate",
        "retention-purge",
        "eventstore-archive",
        "staging-sweep",
        "noop",
        "service-account-rotation",
        "eventstore-checkpoint",
        "replay-seen-prune",
        "quarantine-release-sweep",
        "seed-import",
        "prefetch-tick",
        "prefetch",
        "prefetch-dependencies",
        "prefetch-row-retention-sweep",
        "wheel-metadata-backfill",
        "provenance-verify",
        "scanner-registry-prune",
        "verify-event-chain",
        "policy-reevaluation",
        "oci-membership-edge-backfill",
        "scan-row-retention-sweep",
        "oci-index-child-ingest",
        "jobs-row-retention-sweep",
    ];

    // -----------------------------------------------------------------
    // The per-producer ordinal pin
    // -----------------------------------------------------------------

    /// **The acceptance assertion for the compatibility step**: per
    /// producer, the number [`queue_priority`] answers is the number that
    /// producer wrote before this module existed.
    ///
    /// Each row names the producer and the constant or literal it used,
    /// so the change that re-ranks a path has to delete an assertion
    /// here rather than move a number quietly. Twelve named constants
    /// plus twelve bare literals, all twenty-four of them:
    #[test]
    fn every_producer_keeps_the_ordinal_it_writes_today() {
        // --- the twelve named constants ---
        // ADVISORY_PRIORITY = 5, task_handlers/advisory_watch_tick.rs
        assert_eq!(queue_priority("scan", "advisory"), 5);
        // CRON_RESCAN_PRIORITY = 10, task_handlers/cron_rescan_tick.rs
        assert_eq!(queue_priority("scan", "cron"), 10);
        // CLEARANCE_VERIFY_PRIORITY = 10, use_cases/ingest_use_case.rs —
        // the signature-arrival hook, and use_cases/quarantine_use_case.rs
        // reusing it for the expiry backstop. Unreachable from
        // `queue_priority`; see CLEARANCE_GATING_VERIFY_PRIORITY.
        assert_eq!(CLEARANCE_GATING_VERIFY_PRIORITY, 10);
        // CRON_PRIORITY = 10, the six `hort-server enqueue-*` subcommands
        assert_eq!(queue_priority("jobs-row-retention-sweep", "cron"), 10);
        assert_eq!(queue_priority("prefetch-row-retention-sweep", "cron"), 10);
        assert_eq!(queue_priority("prefetch-tick", "cron"), 10);
        assert_eq!(queue_priority("quarantine-release-sweep", "cron"), 10);
        assert_eq!(queue_priority("scan-row-retention-sweep", "cron"), 10);
        assert_eq!(queue_priority("wheel-metadata-backfill", "cron"), 10);
        // MANUAL_RESCAN_PRIORITY = 20, use_cases/manual_rescan_use_case.rs
        assert_eq!(queue_priority("scan", "manual"), 20);
        // MANUAL_PRIORITY = 20, cli/seed_import.rs
        assert_eq!(queue_priority("seed-import", "seed-import"), 20);
        // CHILD_INGEST_ENQUEUE_PRIORITY = 0,
        // task_handlers/oci_index_child_ingest.rs (the grandchild
        // recursion) and use_cases/oci_index_child_enqueue.rs (the
        // pull-through leg)
        assert_eq!(queue_priority("oci-index-child-ingest", "ingest"), 0);

        // --- the twelve bare literals ---
        // use_cases/ingest_use_case.rs: IngestEnqueue::Scan and
        // ::ProvenanceVerify at ingest, and the same pair on the
        // register-by-hash path when the caller backdates an anchor
        assert_eq!(queue_priority("scan", "ingest"), 0);
        assert_eq!(queue_priority("provenance-verify", "ingest"), 0);
        assert_eq!(queue_priority("scan", "seed-import"), 0);
        assert_eq!(queue_priority("provenance-verify", "seed-import"), 0);
        // use_cases/ingest_use_case.rs: the prefetch-dependencies
        // cascade root, from `ingest` and from `register_by_hash`
        assert_eq!(queue_priority("prefetch-dependencies", "ingest"), 0);
        // use_cases/task_use_case.rs: every admin task invoke
        for kind in CHECK_KINDS {
            // `scan` is deliberately absent from
            // ADMIN_INVOKABLE_TASK_KINDS, and it is the one kind whose
            // `manual` row outranks cron.
            if *kind == "scan" {
                continue;
            }
            assert_eq!(
                queue_priority(kind, "manual"),
                0,
                "admin task invoke of {kind} must stay at the schema default"
            );
        }
        // use_cases/policy_use_case.rs: the scan-policy re-evaluation pass
        assert_eq!(queue_priority("policy-reevaluation", "manual"), 0);
        // use_cases/self_service_prefetch_use_case.rs: the `hort-cli
        // prefetch` root
        assert_eq!(queue_priority("prefetch", "self_service"), 0);
        // task_handlers/prefetch_tick.rs: the scheduled leaf rows
        assert_eq!(queue_priority("prefetch", "scheduled"), 0);
        // task_handlers/prefetch_dependencies.rs: the cascade's own leaf
        // and child rows
        assert_eq!(queue_priority("prefetch", "prefetch"), 0);
        assert_eq!(queue_priority("prefetch-dependencies", "prefetch"), 0);
    }

    /// Counter-assertion for the pin above: the table can still answer
    /// something other than the schema default, so a `queue_priority`
    /// that had been reduced to `0` everywhere would fail rather than
    /// make twenty-four assertions vacuously true.
    #[test]
    fn the_ordinal_table_is_not_uniformly_the_schema_default() {
        let answers: Vec<i16> = check_trigger_sources()
            .iter()
            .map(|s| queue_priority("scan", s))
            .collect();
        assert!(
            answers.iter().any(|p| *p != SCHEMA_DEFAULT_PRIORITY),
            "every trigger source answered the schema default: {answers:?}"
        );
        assert_eq!(
            queue_priority("scan", "manual"),
            MANUAL_RESCAN_PRIORITY,
            "the two-axis arm collapsed"
        );
        assert_eq!(
            queue_priority("provenance-verify", "manual"),
            SCHEMA_DEFAULT_PRIORITY,
            "the two-axis arm stopped discriminating on kind"
        );
    }

    /// The `enqueue_scan` convenience answers exactly what
    /// [`queue_priority`] answers for `kind = 'scan'`, for every CHECK
    /// literal — so a producer using it is not on a second table.
    #[test]
    fn scan_queue_priority_agrees_with_the_general_table() {
        for source in check_trigger_sources() {
            assert_eq!(
                scan_queue_priority(source),
                queue_priority("scan", source),
                "the scan convenience diverged on {source}"
            );
        }
        // Counter-assertion: it really is scan-keyed, not kind-blind.
        assert_eq!(scan_queue_priority("manual"), 20);
        assert_eq!(queue_priority("noop", "manual"), 0);
    }

    // -----------------------------------------------------------------
    // The derivation
    // -----------------------------------------------------------------

    /// Every CHECK literal classifies, which is what makes a row written
    /// by a binary predating this module readable: the derivation needs
    /// nothing a newer writer would have had to put there.
    #[test]
    fn every_check_trigger_source_classifies() {
        for source in check_trigger_sources() {
            for kind in CHECK_KINDS {
                assert!(
                    TaskTier::classify(kind, source).is_some(),
                    "({kind}, {source}) does not classify"
                );
            }
        }
    }

    /// A `trigger_source` outside the set does not acquire a tier, and
    /// takes the schema default ordinal.
    ///
    /// No producer in the tree writes one any more —
    /// `"register-by-hash"` used to be the live exemplar here and is now
    /// in the set — so the inputs below are the shapes a hand-edited row
    /// or a wider future writer could present: a retired literal
    /// (`"api"`), the empty string, a wrong case, and the underscored
    /// near-miss of a real literal.
    #[test]
    fn an_unknown_trigger_source_acquires_no_tier() {
        for source in ["api", "", "Cron", "advisory_watch", "self-service"] {
            assert_eq!(
                TaskTier::classify("scan", source),
                None,
                "{source:?} acquired a tier"
            );
            assert_eq!(
                queue_priority("scan", source),
                SCHEMA_DEFAULT_PRIORITY,
                "{source:?} got an ordinal other than the schema default"
            );
        }
    }

    /// `'register-by-hash'` — the literal admitted into the set when the
    /// OCI cross-repository mount's `500` was fixed.
    ///
    /// Two separate claims, and only the first is a change:
    ///
    /// - it now **classifies**, as [`TaskTier::Interactive`]. A mount is
    ///   a client request waiting on its `201`, so it belongs with the
    ///   ingest-time gates rather than with the background sweeps. Before
    ///   the literal joined the set it did not parse and `classify`
    ///   answered `None`.
    /// - its **ordinal is unchanged**: the schema default, which is
    ///   exactly what the unparseable literal already fell through to.
    ///   `SELECT priority FROM jobs` for a mount's freshly enqueued scan
    ///   is byte-identical across this change.
    #[test]
    fn register_by_hash_is_interactive_and_keeps_the_schema_default_ordinal() {
        assert_eq!(
            TaskTier::classify("scan", "register-by-hash"),
            Some(TaskTier::Interactive)
        );
        assert_eq!(
            TaskTier::classify("provenance-verify", "register-by-hash"),
            Some(TaskTier::Interactive)
        );
        assert_eq!(
            queue_priority("scan", "register-by-hash"),
            SCHEMA_DEFAULT_PRIORITY
        );
        assert_eq!(
            queue_priority("provenance-verify", "register-by-hash"),
            SCHEMA_DEFAULT_PRIORITY
        );
        assert_eq!(
            scan_queue_priority("register-by-hash"),
            SCHEMA_DEFAULT_PRIORITY
        );
    }

    /// The trigger axis, per CHECK literal.
    #[test]
    fn the_trigger_axis_assigns_one_tier_per_check_literal() {
        // A client pushed or pulled; the gates stand between those bytes
        // and being served.
        assert_eq!(
            TaskTier::classify("scan", "ingest"),
            Some(TaskTier::Interactive)
        );
        assert_eq!(
            TaskTier::classify("provenance-verify", "ingest"),
            Some(TaskTier::Interactive)
        );
        assert_eq!(
            TaskTier::classify("oci-index-child-ingest", "ingest"),
            Some(TaskTier::Interactive)
        );
        // An operator is reading the answer.
        assert_eq!(TaskTier::classify("scan", "manual"), Some(TaskTier::Normal));
        assert_eq!(
            TaskTier::classify("seed-import", "seed-import"),
            Some(TaskTier::Normal)
        );
        assert_eq!(
            TaskTier::classify("prefetch", "self_service"),
            Some(TaskTier::Normal)
        );
        // Nobody is waiting.
        assert_eq!(TaskTier::classify("scan", "cron"), Some(TaskTier::Bulk));
        assert_eq!(TaskTier::classify("scan", "advisory"), Some(TaskTier::Bulk));
        assert_eq!(
            TaskTier::classify("prefetch", "prefetch"),
            Some(TaskTier::Bulk)
        );
        assert_eq!(
            TaskTier::classify("prefetch", "scheduled"),
            Some(TaskTier::Bulk)
        );
    }

    /// The three kinds the governing decision settles by measurement
    /// rather than by trigger source land where it says.
    #[test]
    fn the_settled_kinds_land_where_the_decision_says() {
        for kind in [
            "policy-reevaluation",
            "replay-seen-prune",
            "scanner-registry-prune",
        ] {
            assert_eq!(
                TaskTier::classify(kind, "manual"),
                Some(TaskTier::Normal),
                "{kind} must be Normal"
            );
        }
        assert_eq!(TaskTier::classify("scan", "advisory"), Some(TaskTier::Bulk));
    }

    /// ADR 0066 D3, as an assertion: the release sweep is client-waited
    /// on every trigger source it can be enqueued under, including the
    /// `'cron'` its CronJob actually stamps.
    ///
    /// This is the misassignment that produced the second instance — a
    /// push completed, its quarantine window elapsed, and nothing
    /// released it, because "it is a scheduled task, so it ranks with
    /// scheduled tasks".
    #[test]
    fn the_release_sweep_is_client_waited_even_when_scheduled() {
        for source in check_trigger_sources() {
            assert_eq!(
                TaskTier::classify("quarantine-release-sweep", source),
                Some(TaskTier::Interactive),
                "the release sweep under {source} is not Interactive"
            );
        }
        // Counter-assertion: the carve-out is the kind's, not every
        // kind's. A sibling sweep on the same trigger source is Bulk.
        assert_eq!(
            TaskTier::classify("jobs-row-retention-sweep", "cron"),
            Some(TaskTier::Bulk)
        );
    }

    // -----------------------------------------------------------------
    // The two faces against each other
    // -----------------------------------------------------------------

    /// The disagreement this step preserves, stated as an assertion.
    ///
    /// Tier order is `Interactive > Normal > Bulk`; the claim query's is
    /// `priority DESC`. The two do not agree today, and that is the
    /// defect the vocabulary exists to let the next change fix. When
    /// the ordinal is finally derived from the tier, this test fails and
    /// is deleted — which is the point of writing it down.
    #[test]
    fn tier_and_ordinal_disagree_today() {
        // An ingest scan is the most waited-on work in the system and
        // carries the lowest rank.
        assert_eq!(
            TaskTier::classify("scan", "ingest"),
            Some(TaskTier::Interactive)
        );
        assert_eq!(queue_priority("scan", "ingest"), SCHEMA_DEFAULT_PRIORITY);
        // A cron rescan is waited on by nobody and outranks it.
        assert_eq!(TaskTier::classify("scan", "cron"), Some(TaskTier::Bulk));
        assert!(queue_priority("scan", "cron") > queue_priority("scan", "ingest"));
        // So does the release sweep's own flood-mate, at the identical
        // ordinal — which is how `created_at ASC` came to resolve the tie
        // against the sweep.
        assert_eq!(
            queue_priority("quarantine-release-sweep", "cron"),
            queue_priority("scan", "cron"),
        );
    }

    // -----------------------------------------------------------------
    // Value-type surface
    // -----------------------------------------------------------------

    #[test]
    fn tier_labels_are_stable_and_distinct() {
        let labels = [
            TaskTier::Interactive.as_str(),
            TaskTier::Normal.as_str(),
            TaskTier::Bulk.as_str(),
        ];
        assert_eq!(labels, ["interactive", "normal", "bulk"]);
        assert_eq!(
            labels
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
    }

    #[test]
    fn tier_is_a_copyable_value_with_a_debug() {
        let t = TaskTier::Interactive;
        let copied = t;
        assert_eq!(t, copied);
        assert_ne!(t, TaskTier::Bulk);
        assert_eq!(format!("{t:?}"), "Interactive");
        let mut set = std::collections::HashSet::new();
        assert!(set.insert(TaskTier::Normal));
        assert!(!set.insert(TaskTier::Normal));
    }

    /// This module reads the trigger source through the one definition's
    /// [`FromStr`](std::str::FromStr), not through a local parse of its
    /// own — so the set it keys on cannot be a release behind the
    /// column's.
    ///
    /// Kept after the private mirror was deleted because it is the pin
    /// on *which* parse the two tables use: a reintroduced local
    /// `fn parse` would keep every other test in this file green.
    #[test]
    fn trigger_source_parses_every_check_literal_and_nothing_else() {
        for source in check_trigger_sources() {
            assert!(
                source.parse::<TriggerSource>().is_ok(),
                "{source} does not parse"
            );
        }
        assert!("seedimport".parse::<TriggerSource>().is_err());
        assert!("self-service".parse::<TriggerSource>().is_err());
        // Copy + Debug + Eq, so the two tables can match on it by value.
        let s = TriggerSource::Cron;
        assert_eq!(s, s);
        assert_ne!(s, TriggerSource::Ingest);
        assert_eq!(format!("{:?}", TriggerSource::SeedImport), "SeedImport");
    }
}
