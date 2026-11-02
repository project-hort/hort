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
//! # Scope of the vocabulary
//!
//! A tier is a property of work the dispatcher schedules. `kind =
//! 'verify-event-chain'` is therefore outside it rather than unassigned
//! within it: there is no `TaskHandler` for that kind and no worker
//! registration, its row is a liveness breadcrumb inserted `status =
//! 'completed'` by the `hort-server verify-event-chain` subcommand, and
//! nothing ever claims it. It gets no branch here for that reason.

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
/// source cannot displace anything. It is also the value such a row
/// already carries today, because the only producer writing a
/// trigger source outside the CHECK writes this number too.
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
    /// is not one of the migration-009 CHECK literals. A row like that
    /// does not acquire a tier by default, which is why the match below
    /// has no wildcard arm: a ninth CHECK literal has to be added to
    /// [`TriggerSource`] to be parsed at all, and adding it there fails
    /// the build here until somebody decides which class it belongs to.
    pub fn classify(kind: &str, trigger_source: &str) -> Option<Self> {
        // D3: the path that makes an artifact available is client-waited
        // even when it is scheduled. Read before the trigger source, so
        // the `'cron'` the CronJob stamps cannot file it with the
        // scheduled rescans it is supposed to outrank.
        if kind == KIND_QUARANTINE_RELEASE_SWEEP {
            return Some(Self::Interactive);
        }
        Some(match TriggerSource::parse(trigger_source)? {
            // A client pushed, or pulled through, and the gates this
            // enqueues are what stand between those bytes and being
            // served.
            TriggerSource::Ingest => Self::Interactive,
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
    let Some(source) = TriggerSource::parse(trigger_source) else {
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

// ---------------------------------------------------------------------------
// TriggerSource
// ---------------------------------------------------------------------------

/// Closed mirror of the `jobs.trigger_source` CHECK (migration 009), so
/// that both tables above can match over it exhaustively.
///
/// Deliberately **not**
/// [`ports::jobs_repository::TriggerSource`](crate::ports::jobs_repository::TriggerSource),
/// which covers four of the eight CHECK literals — its `FromStr` rejects
/// `'seed-import'`, `'prefetch'`, `'self_service'` and `'scheduled'` —
/// and is parsed only off a `kind = 'scan'` row. Widening that type would
/// change what two scan-row read paths accept, which is a behaviour
/// change and not this module's business; narrowing the tier derivation
/// to its four literals would leave half the queue unclassifiable.
///
/// Private on purpose: it exists to give the two public functions an
/// exhaustive match, not to become a second trigger-source vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TriggerSource {
    /// `'ingest'` — an ingest, a pull-through, or a hook on one.
    Ingest,
    /// `'cron'` — the rescan tick and the `enqueue-*` CronJobs.
    Cron,
    /// `'advisory'` — the advisory-watch sweep.
    Advisory,
    /// `'manual'` — an admin task invoke, a manual rescan, a
    /// gitops-driven policy re-evaluation.
    Manual,
    /// `'seed-import'` — the `hort-server seed-import` subcommand.
    SeedImport,
    /// `'prefetch'` — a row the transitive prefetch cascade spawned for
    /// itself.
    Prefetch,
    /// `'self_service'` — the operator-initiated `hort-cli prefetch`
    /// root.
    SelfService,
    /// `'scheduled'` — the prefetch tick's root enqueues.
    Scheduled,
}

impl TriggerSource {
    /// Parse a `jobs.trigger_source` cell. `None` for anything outside
    /// the CHECK.
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "ingest" => Self::Ingest,
            "cron" => Self::Cron,
            "advisory" => Self::Advisory,
            "manual" => Self::Manual,
            "seed-import" => Self::SeedImport,
            "prefetch" => Self::Prefetch,
            "self_service" => Self::SelfService,
            "scheduled" => Self::Scheduled,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every literal in the migration-009 `jobs.trigger_source` CHECK, in
    /// the order the migration lists them.
    ///
    /// Re-typed here rather than imported because the CHECK is SQL: this
    /// list is the test's own statement of what the column may hold, and
    /// it is what makes "every CHECK literal classifies" checkable.
    const CHECK_TRIGGER_SOURCES: &[&str] = &[
        "manual",
        "cron",
        "advisory",
        "ingest",
        "seed-import",
        "prefetch",
        "self_service",
        "scheduled",
    ];

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
        let answers: Vec<i16> = CHECK_TRIGGER_SOURCES
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
        for source in CHECK_TRIGGER_SOURCES {
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
        for source in CHECK_TRIGGER_SOURCES {
            for kind in CHECK_KINDS {
                assert!(
                    TaskTier::classify(kind, source).is_some(),
                    "({kind}, {source}) does not classify"
                );
            }
        }
    }

    /// A `trigger_source` outside the CHECK does not acquire a tier, and
    /// takes the schema default ordinal.
    ///
    /// `"register-by-hash"` is not hypothetical: `register_by_hash`
    /// stamps it on the enqueues of a mount or follower registration,
    /// and it is absent from the CHECK.
    #[test]
    fn an_unknown_trigger_source_acquires_no_tier() {
        for source in ["register-by-hash", "api", "", "Cron", "advisory_watch"] {
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
        for source in CHECK_TRIGGER_SOURCES {
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

    #[test]
    fn trigger_source_parses_every_check_literal_and_nothing_else() {
        for source in CHECK_TRIGGER_SOURCES {
            assert!(
                TriggerSource::parse(source).is_some(),
                "{source} does not parse"
            );
        }
        assert_eq!(TriggerSource::parse("seedimport"), None);
        assert_eq!(TriggerSource::parse("self-service"), None);
        // Copy + Debug + Eq, so the two tables can match on it by value.
        let s = TriggerSource::Cron;
        assert_eq!(s, s);
        assert_ne!(s, TriggerSource::Ingest);
        assert_eq!(format!("{:?}", TriggerSource::SeedImport), "SeedImport");
    }
}
