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
//! # The two faces, and why the write face is derived from the read face
//!
//! [`TaskTier::classify`] is the **read** face: given the `(kind,
//! trigger_source)` a row already carries, which class is it? It is
//! derived rather than stored (ADR 0066 D7), so there is no column, no
//! migration and no backfill, and a row an older binary wrote classifies
//! exactly like one a current binary wrote.
//!
//! [`queue_priority`] is the **write** face: the `jobs.priority` a fresh
//! row carries. It is **computed from the read face**, which is what
//! makes the two unable to disagree:
//!
//! ```text
//! ordinal = classify(kind, trigger_source).band()
//!           + low_volume_offset(kind, trigger_source)
//! ```
//!
//! The class decides the band; one step inside the band expresses volume,
//! and nothing else does. Tier order and numeric order therefore agree by
//! construction, which `the_ordinal_order_agrees_with_the_tier_order`
//! asserts exhaustively over every pair the two tables can be asked
//! about. That test is the counterpart of the
//! `tier_and_ordinal_disagree_today` this change deleted: the module used
//! to assert the disagreement rather than apologise for it, so that the
//! change removing it had to delete an assertion.
//!
//! # The bands, and why these numbers
//!
//! Three bands, [`BAND_WIDTH`] apart, the lowest at the column's own
//! default:
//!
//! | class | band floor | with the volume offset |
//! |---|---|---|
//! | [`TaskTier::Bulk`] | `0` | — |
//! | [`TaskTier::Normal`] | `30` | `31` |
//! | [`TaskTier::Interactive`] | `60` | `61` |
//!
//! The gap is thirty against an offset of one because the asymmetry *is*
//! the statement: the class dominates the rank and the volume offset only
//! nudges inside it. Nothing in the tree can reach the next band by
//! accumulating offsets. The top of the layout stays well inside the
//! column's `CHECK (priority BETWEEN 0 AND 100)` (migration 009) — a
//! `const` assertion below holds that, because a band that overflowed the
//! CHECK would turn every enqueue into a `23514`, at runtime, at every
//! producer at once. The headroom above `61` is left deliberately: the
//! CHECK's upper bound is the operator-misuse boundary migration 009
//! describes, and an operator hand-lifting one row above everything the
//! system itself writes is the escape hatch that bound exists for.
//!
//! # Rows an older binary already queued
//!
//! The *classification* needs no backfill because it is derived (D7). The
//! *ordinal* is on the row and the claim query orders by it, so the
//! re-ranking has to be safe against rows written under the previous
//! scheme without touching them. That scheme wrote exactly four numbers —
//! `0`, `5`, `10` and `20` — and the bands above are chosen against that
//! set:
//!
//! - every new `Normal` and `Interactive` ordinal is **above `20`**, the
//!   highest the previous scheme ever wrote, so no already-queued row of
//!   any class can outrank a fresh client- or operator-waited row;
//! - every new `Bulk` ordinal **is `0`**, the lowest it ever wrote, so no
//!   fresh background row can outrank an already-queued row of any class
//!   either; where the two meet at `0` the claim's `created_at ASC`
//!   tiebreak takes the already-queued one first.
//!
//! So the queued rows drain, in an order no worse than the one they were
//! enqueued under, and there is nothing to migrate.
//! `a_row_at_the_previous_schemes_ordinal_does_not_outrank_a_fresh_waited_on_row`
//! is that property over the previous scheme's whole set of numbers, and
//! those numbers are written down in the test rather than imported —
//! the constants that held them do not exist any more, and a test reading
//! a constant that moved would go vacuous instead of failing.
//!
//! What no change of this shape can repair is the order *among* the
//! already-queued rows: an old cron row at `10` still outranks an old
//! ingest row at `0` until both drain. Leaving them alone is D7's
//! decision, and the window is the drain, not the deployment.
//!
//! # The within-band offset is volume, and only volume
//!
//! Three rows in the tree are the single low-volume member of a class
//! whose other members arrive as a flood, and each would wait behind that
//! flood at the band floor:
//!
//! - the operator's rescan (`('scan', 'manual')`), against the admin task
//!   invokes and the gitops policy re-evaluations that share `'manual'`
//!   and are bookkeeping;
//! - the `hort-server seed-import` subcommand's own row
//!   (`('seed-import', 'seed-import')`), against the per-artifact scans
//!   and verifies that import then enqueues under the same trigger
//!   source;
//! - the clearance-gating verify (`('provenance-verify', 'clearance')`),
//!   against the one-per-ingest ingest-time verify backlog — a held
//!   artifact queued behind that backlog waits for the backlog rather
//!   than for its own verify, which is release latency.
//!
//! Each is asserted by name below, so a later simplification that
//! flattens the offset away fails here rather than in production.
//!
//! All three are **rows** — `(kind, trigger_source)` pairs — and
//! [`low_volume_offset`] reads both halves for each. A trigger source is
//! not by itself a volume fact: the clearance arm keyed on `'clearance'`
//! alone would lift the whole `Bulk` band one step for any kind that
//! literal ever reached, and the `Bulk` floor being the column default
//! is what the compatibility property above rests on.
//!
//! The offset expresses nothing else. A *preference* between two floods
//! of the same class is not a volume fact and does not get a number: the
//! previous scheme's `advisory = 5` below `cron = 10` was such a
//! preference ("the cron rescan is the safety net, so claim it first"),
//! both are scheduled rescan floods nobody waits on, and both now sit at
//! the `Bulk` floor where the claim's age tiebreak orders them. Keeping
//! that one step would also have cost the compatibility property above:
//! a `Bulk` band two steps tall cannot have its top at `0`, and a fresh
//! cron row one step up would outrank an already-queued ingest row.
//!
//! # The two kinds whose class is not read off their trigger source
//!
//! The trigger source is the *cause*; the class is *who waits*. D2 keys
//! the class on the cause because the cause usually determines who
//! waits — and two kinds are the cases where it does not. Both are
//! carve-outs in [`TaskTier::classify`], read **before** the trigger
//! source and keyed on the kind alone, and both are D3 read in opposite
//! directions:
//!
//! - **[`KIND_QUARANTINE_RELEASE_SWEEP`] is [`TaskTier::Interactive`]**
//!   though a CronJob stamps it `'cron'`. That a piece of work runs on a
//!   timer says how it was triggered, never that nobody is waiting for
//!   its effect, and what waits on the sweep is a pushed,
//!   window-elapsed artifact becoming servable.
//! - **[`KIND_PREFETCH_DEPENDENCIES`] is [`TaskTier::Bulk`]** though a
//!   client's push spawns the cascade root and stamps it `'ingest'`. The
//!   converse: that a client's push caused the row says how it was
//!   triggered, never that a client is waiting for its effect. The push
//!   has already answered `201`, the walk only makes *later* pulls warm,
//!   and a walk that never runs costs nothing — the next pull of any
//!   dependent fetches that dependency on its own path. So the root
//!   ranks *with* the cascade's own child rows, which carry `'prefetch'`
//!   and were already `Bulk`, rather than two bands above them where a
//!   bulk push's one-root-per-artifact flood would preempt the operator
//!   work the cascade used to drain behind.
//!
//! Both live in `classify` and not in [`queue_priority`]: a kind-keyed
//! exception in the write face that the read face does not share is the
//! two-lists-disagreeing defect this module exists to end, and the write
//! face is derived from the read face precisely so that it cannot be
//! written. Which class a kind belongs to is a `classify` question (D2),
//! never an ordinal one.
//!
//! `the_kind_carve_outs_are_exactly_two_and_each_is_that_kinds_alone`
//! holds the census: a third carve-out is a decision, taken here with
//! the reasoning written down, rather than a line added quietly.
//!
//! ## The test for a third one: whose artifact does the work complete?
//!
//! `oci-index-child-ingest` was considered and **stays**
//! [`TaskTier::Interactive`], though it matches the cascade root on
//! every surface feature — an `'ingest'` trigger source, one row per
//! child the manifest declares, and a handler whose own header says it
//! does "up front, exactly the ingest a later lazy client pull would
//! have performed".
//!
//! What separates them is not how speculative the work looks but
//! **whose artifact it completes.** The cascade warms a *different*
//! artifact: the dependencies a pushed manifest declares, which nobody
//! has asked for and may never ask for. An index's children are
//! *constituents of the artifact in hand* — a multi-arch image is not
//! servable from its index alone, so a client that asked for that image
//! needs them, and ingesting them eagerly is what keeps their
//! observation windows from running after the index's instead of
//! alongside it. Skipping it does not cost a hypothetical later client
//! a warm cache; it costs the client who asked a second full window.
//!
//! The fan-out is bounded by what the client actually pushed or pulled,
//! which is the shape ADR 0066 ascribes to interactive work — unlike a
//! bulk ingest run, where the cascade's one-root-per-artifact flood is
//! bounded by nothing.
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
//! the one type, so a new literal has to be given a tier and a volume
//! answer here before the build passes.
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
/// trigger carries the within-band volume offset — the operator's rescan
/// against the admin invokes that share the trigger source.
const KIND_SCAN: &str = "scan";

/// `jobs.kind` of the operator one-shot quarantine seed. Distinct from
/// the `'seed-import'` *trigger source*, which the same subcommand also
/// writes — the pair `(kind, trigger_source) = ('seed-import',
/// 'seed-import')` is what separates that producer's own row from the
/// scans the same import enqueues.
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

/// `jobs.kind` of the transitive dependency-prefetch cascade — both the
/// root a push spawns and the child rows the walk spawns for itself.
///
/// The second kind whose tier is *not* read off its trigger source, and
/// the carve-out is ADR 0066 D3 read in the other direction: that a
/// client's push caused the row says how it was triggered, never that a
/// client is waiting for its effect. Nobody waits on the cascade — the
/// push has already answered `201`, the walk only makes *later* pulls
/// warm, and a walk that never runs costs nothing because the next pull
/// of any dependent fetches that dependency on its own path.
///
/// Keyed on the kind alone rather than on `(kind, trigger_source)`:
/// there is no `('prefetch-dependencies', _)` row anyone waits on, and
/// the cascade's own child rows already carry `'prefetch'` and are
/// [`TaskTier::Bulk`] — so the carve-out makes the root rank *with* its
/// children instead of two whole bands above them.
const KIND_PREFETCH_DEPENDENCIES: &str = "prefetch-dependencies";

/// `jobs.kind` of a provenance verify. The kind half of the
/// clearance-gating verify's within-band volume offset — see
/// [`low_volume_offset`], whose three arms each name a *row*, not a
/// trigger source.
const KIND_PROVENANCE_VERIFY: &str = "provenance-verify";

// ---------------------------------------------------------------------------
// The bands
// ---------------------------------------------------------------------------

/// The `jobs.priority` schema default (migration 009), the floor of the
/// [`TaskTier::Bulk`] band, and what a row that does not classify is
/// given.
///
/// All three being the same number is deliberate and is what makes the
/// column default safe. A producer that sets nothing, and a row whose
/// trigger source does not parse, land in the lowest band — so neither
/// can displace a client-waited row — and neither is thereby starved:
/// the lowest band is [`TaskTier::Bulk`]'s, whose guarantee of service
/// is the age-ordered allocation that runs beneath the per-class
/// reservation at each capacity point (see [`waited_on_bands`]), not a
/// reserved share of its own.
///
/// "Does not classify" is narrower than "has an unreadable trigger
/// source": the two carve-out kinds —
/// [`KIND_QUARANTINE_RELEASE_SWEEP`] and
/// [`KIND_PREFETCH_DEPENDENCIES`] — are classified off the kind before
/// the trigger source is read at all (ADR 0066 D3, in both directions),
/// so such a row keeps its band whatever its trigger source says.
///
/// No producer in the tree writes a trigger source this module cannot
/// parse — [`TriggerSource`] is the set and the writers' constants are
/// defined from it — so the unparseable path is reached only by a row
/// written by a binary whose set was wider, or edited by hand.
const SCHEMA_DEFAULT_PRIORITY: i16 = 0;

/// Distance from one band's floor to the next.
///
/// Thirty against a [`LOW_VOLUME_OFFSET`] of one: no accumulation of
/// within-band offsets can reach the next class, and a reader comparing
/// two ordinals can tell a class difference from a volume difference by
/// magnitude alone.
const BAND_WIDTH: i16 = 30;

/// Floor of the [`TaskTier::Bulk`] band — the bottom of the layout, and
/// the column default (see [`SCHEMA_DEFAULT_PRIORITY`]).
///
/// At the bottom rather than merely below the others, because that is
/// what keeps a freshly enqueued background row from outranking anything
/// an older binary already queued: the previous scheme's lowest number
/// was also `0`.
const BULK_BAND: i16 = SCHEMA_DEFAULT_PRIORITY;

/// Floor of the [`TaskTier::Normal`] band — an operator is waiting for
/// an answer.
///
/// Above `20`, the highest ordinal the previous scheme wrote, so an
/// already-queued row cannot outrank a fresh operator-waited one.
const NORMAL_BAND: i16 = BULK_BAND + BAND_WIDTH;

/// Floor of the [`TaskTier::Interactive`] band — a client is waiting on
/// this right now.
const INTERACTIVE_BAND: i16 = NORMAL_BAND + BAND_WIDTH;

/// Added to the one row of a class whose other members arrive as a flood.
///
/// One step, because its only job is to put a single low-volume row in
/// front of the flood it shares a class with; the three rows that carry
/// it are named in this module's header and asserted individually below.
const LOW_VOLUME_OFFSET: i16 = 1;

/// Upper bound of the `jobs.priority` CHECK (migration 009).
const COLUMN_CHECK_MAX: i16 = 100;

// The whole layout has to fit the column, or every enqueue becomes a
// `23514` at runtime rather than a failure here.
const _: () = assert!(BULK_BAND >= 0);
const _: () = assert!(INTERACTIVE_BAND + LOW_VOLUME_OFFSET <= COLUMN_CHECK_MAX);

// ---------------------------------------------------------------------------
// TaskTier
// ---------------------------------------------------------------------------

/// An inclusive `jobs.priority` range — the ordinal footprint of one
/// [`TaskTier`], as [`TaskTier::priority_band`] answers it.
///
/// Exists so a reader that cannot classify a row can still tell which
/// class an ordinal belongs to. The one such reader is the claim query,
/// which is handed these bounds as bind parameters: expressing the
/// per-class reservation on `priority` is what keeps the
/// `(kind, trigger_source)` table out of SQL (ADR 0066 D6, and the
/// `task_class_is_single_sourced` guard).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorityBand {
    /// Lowest `jobs.priority` in the band, inclusive.
    pub lowest: i16,
    /// Highest `jobs.priority` in the band, inclusive.
    pub highest: i16,
}

impl PriorityBand {
    /// Does `priority` fall in this band?
    pub const fn contains(self, priority: i16) -> bool {
        priority >= self.lowest && priority <= self.highest
    }
}

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
    /// retention and row-retention sweeps, and the whole prefetch
    /// cascade — the root a push spawns included, even though a push
    /// spawns it (D3 in the other direction; see the module header).
    Bulk,
}

impl TaskTier {
    /// Every class, **highest first** — the order a capacity allocation
    /// honours reservations in when there is not enough capacity to
    /// satisfy all of them.
    ///
    /// Ordered rather than merely complete: at
    /// `HORT_SCANNER_BATCH_SIZE = 1` the claim has one slot and two
    /// waited-on classes may both be waiting, so the sequence here is
    /// what decides. `the_order_of_all_is_the_tier_order` holds it
    /// against the same `tier_rank` the ordinal order is checked with,
    /// so the list cannot be reordered into disagreeing with the
    /// ranking it projects.
    pub const ALL: [Self; 3] = [Self::Interactive, Self::Normal, Self::Bulk];

    /// Stable label, for a log field or a metric.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Normal => "normal",
            Self::Bulk => "bulk",
        }
    }

    /// The floor of the `jobs.priority` band this class occupies.
    ///
    /// Private: the ordinal is decided in exactly one place
    /// ([`queue_priority`]) and the per-class reservation keys on the
    /// class itself, so nothing outside this module has a use for a band
    /// floor that is not already served by asking the table.
    const fn band(self) -> i16 {
        match self {
            Self::Interactive => INTERACTIVE_BAND,
            Self::Normal => NORMAL_BAND,
            Self::Bulk => BULK_BAND,
        }
    }

    /// Is somebody waiting on work of this class?
    ///
    /// The one definition of *which* classes a capacity allocation
    /// reserves a share for (ADR 0066 D4). Wildcard-free, so a fourth
    /// variant cannot acquire an answer by default — a class nobody has
    /// decided about would otherwise silently join, or silently miss,
    /// every reservation in the system.
    pub const fn is_waited_on(self) -> bool {
        match self {
            Self::Interactive | Self::Normal => true,
            Self::Bulk => false,
        }
    }

    /// The inclusive `jobs.priority` range this class occupies — the
    /// band membership a *reader* of the column tests, as opposed to
    /// [`Self::band`], which is the floor a *writer* starts from.
    ///
    /// The three ranges **partition the whole `i16` space**, which is
    /// what makes them usable as a classification by a reader that
    /// cannot call [`Self::classify`] — the claim SQL, which is handed
    /// these bounds as bind parameters and never learns what a class
    /// is. `the_bands_partition_the_ordinal_space` holds the partition.
    /// Open at both ends rather than clamped to the column's
    /// `CHECK (priority BETWEEN 0 AND 100)` so that no value a row
    /// could carry — including one a future CHECK widening admits —
    /// belongs to no band at all: a row outside every band would be
    /// invisible to a per-class reservation while still competing for
    /// the batch.
    ///
    /// **The projection is of the ordinal, not of the row.** A row an
    /// older binary queued carries an ordinal from the previous scheme
    /// (`0`, `5`, `10`, `20` — all below [`NORMAL_BAND`]), so it reads
    /// as [`Self::Bulk`] here whatever [`Self::classify`] would say
    /// about its columns. That is ADR 0066 D7's accepted window — the
    /// classification needs no backfill, the ordinal is not backfilled,
    /// and the disagreement drains with those rows. It is safe in the
    /// direction that matters: such a row can never *consume* a
    /// waited-on class's reserved slot, only miss one.
    pub const fn priority_band(self) -> PriorityBand {
        match self {
            Self::Interactive => PriorityBand {
                lowest: INTERACTIVE_BAND,
                highest: i16::MAX,
            },
            Self::Normal => PriorityBand {
                lowest: NORMAL_BAND,
                highest: INTERACTIVE_BAND - 1,
            },
            Self::Bulk => PriorityBand {
                lowest: i16::MIN,
                highest: NORMAL_BAND - 1,
            },
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
        // D3 in the other direction: that a client's push caused the
        // cascade root says how it was triggered, never that a client is
        // waiting for its effect. The push has already answered `201`,
        // the walk only makes later pulls warm, and the next pull of any
        // dependent fetches that dependency itself — so a walk that never
        // runs leaves nobody waiting. Read before the trigger source, so
        // the `'ingest'` the producers stamp cannot file a push-spawned
        // flood above the operator work it drains behind.
        if kind == KIND_PREFETCH_DEPENDENCIES {
            return Some(Self::Bulk);
        }
        Some(match trigger_source.parse::<TriggerSource>().ok()? {
            // A client pushed, or pulled through, and the gates this
            // enqueues are what stand between those bytes and being
            // served. `RegisterByHash` is the same claim through a
            // different door: a cross-repository mount or a pull-dedup
            // follower is a client request waiting on its 201.
            TriggerSource::Ingest | TriggerSource::RegisterByHash => Self::Interactive,
            // The last thing between an artifact already held and a
            // release decision. Who waits is a release decision rather
            // than a push, but it is still somebody — so this is the
            // same class as the ingest-time verify it was previously
            // indistinguishable from, and the class boundary does not
            // move when the row finally says which of the two it is.
            // The separation the literal buys is *within* the class, by
            // volume, which is what the ordinal is for (ADR 0066 D1
            // rules out a fourth class, and this is not one).
            TriggerSource::Clearance => Self::Interactive,
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

/// `LOW_VOLUME_OFFSET` for a row that is the single low-volume member of
/// its class, `0` for everything else.
///
/// The three rows that carry it, and why each needs to sit in front of
/// its own class's flood, are in this module's header. The match over the
/// trigger source has no wildcard arm for the same reason
/// [`TaskTier::classify`]'s does not: a new CHECK literal has to say
/// whether it is a flood or the one row waiting behind one.
fn low_volume_offset(kind: &str, trigger_source: &str) -> i16 {
    let Ok(source) = trigger_source.parse::<TriggerSource>() else {
        return 0;
    };
    match source {
        // `ManualRescanUseCase`'s row, against the admin task invokes
        // and the gitops-driven policy re-evaluations that share
        // `'manual'`.
        TriggerSource::Manual => {
            if kind == KIND_SCAN {
                LOW_VOLUME_OFFSET
            } else {
                0
            }
        }
        // The `hort-server seed-import` subcommand's own row, against
        // the per-artifact scans and verifies that import then enqueues
        // under the same trigger source.
        TriggerSource::SeedImport => {
            if kind == KIND_SEED_IMPORT {
                LOW_VOLUME_OFFSET
            } else {
                0
            }
        }
        // The clearance-gating verify, against the one-per-ingest
        // ingest-time verify backlog. Keyed on the kind like the two
        // arms above: a trigger source is not by itself a volume fact,
        // and `'clearance'` read alone would put the `Bulk` floor one
        // step above the column default for any kind a carve-out files
        // there — which is the compatibility property this module's
        // header rests on.
        TriggerSource::Clearance => {
            if kind == KIND_PROVENANCE_VERIFY {
                LOW_VOLUME_OFFSET
            } else {
                0
            }
        }
        // Every other row is either a flood of its class or alone in it,
        // and in neither case does a step up mean anything.
        TriggerSource::Ingest
        | TriggerSource::RegisterByHash
        | TriggerSource::SelfService
        | TriggerSource::Cron
        | TriggerSource::Advisory
        | TriggerSource::Prefetch
        | TriggerSource::Scheduled => 0,
    }
}

/// The `jobs.priority` a freshly enqueued row carries — **the** place the
/// ordinal is decided.
///
/// Derived from [`TaskTier::classify`]'s answer: the class picks the
/// band, [`low_volume_offset`] picks the step inside it. The two faces of
/// this module therefore cannot disagree, which is ADR 0066 D8's
/// outcome; see the header for the arithmetic and for what happens to
/// rows an older binary already queued.
///
/// A row this module cannot classify takes [`SCHEMA_DEFAULT_PRIORITY`] —
/// the bottom of the layout, so an unparseable trigger source cannot
/// displace anything.
pub fn queue_priority(kind: &str, trigger_source: &str) -> i16 {
    match TaskTier::classify(kind, trigger_source) {
        Some(tier) => tier.band() + low_volume_offset(kind, trigger_source),
        None => SCHEMA_DEFAULT_PRIORITY,
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
// The reservation the two capacity allocations are built from
// ---------------------------------------------------------------------------

/// The `jobs.priority` bands a capacity allocation reserves a share for
/// — one per **waited-on** class, highest class first (ADR 0066 D4).
///
/// The one place "which classes get a reserved share, and what ordinals
/// they occupy" is answered, for both points at which the system
/// allocates capacity: the claim (`claim_pending_by_kinds`, which takes
/// these bounds as bind parameters) and the permit
/// (`hort_app::class_fair_permits`, which reserves per class directly
/// because it holds the row and can [`TaskTier::classify`] it).
///
/// Derived from [`TaskTier::ALL`] filtered by
/// [`TaskTier::is_waited_on`], so there is no second list to disagree
/// with the first.
///
/// **[`TaskTier::Bulk`] deliberately has no reserved share.** Nobody is
/// waiting on it, so reserving it a slot would be capacity taken from
/// the paths someone *is* waiting on — the opposite of the decision.
/// Its guarantee of service (ADR 0066 D5) is the allocation that runs
/// *beneath* the reservation at each point: the claim's one
/// priority-blind oldest slot, and the permit's arrival-ordered
/// remainder. Both are age-ordered, which is where ADR 0066 puts aging
/// — "worth having as a safety net beneath (4), not as a substitute for
/// it".
/// Slots a capacity allocation holds for each non-empty waited-on class
/// when the operator has not said otherwise — ADR 0066 D4's default.
///
/// **One, and derived from the domain rather than measured.**
/// Interactive work is bounded by what clients actually do and bulk work
/// is unbounded by construction, so a share that can go to zero for a
/// class someone is waiting on is the defect itself; one slot is the
/// smallest share that cannot. Nothing about the number needs a
/// deployment's throughput to justify it, which is why it is a default
/// and not a tuning exercise.
///
/// ADR 0066 states explicitly that the decision does **not** fix the
/// shares — with a single worker replica the share is the whole control
/// surface — so this is the default of a per-deployment knob
/// (`HORT_SCANNER_RESERVED_SLOTS_PER_CLASS`), not a constant the system
/// relies on.
pub const DEFAULT_RESERVED_SLOTS_PER_CLASS: u16 = 1;

pub fn waited_on_bands() -> Vec<PriorityBand> {
    TaskTier::ALL
        .iter()
        .filter(|tier| tier.is_waited_on())
        .map(|tier| tier.priority_band())
        .collect()
}

/// Every class paired with its band, **highest class first** — the
/// bands a *service observation* reads (ADR 0066 D5).
///
/// The counterpart of [`waited_on_bands`], and deliberately a different
/// list. That one answers "which classes get a reserved share", and
/// [`TaskTier::Bulk`] is absent from it because nobody is waiting on
/// bulk work. D5 is the decision's other half — *every* class is
/// guaranteed service, and the guarantee is observable — so an
/// observation built from the reservation's list would be blind to the
/// one class whose service has no reservation behind it, which is the
/// class most able to go unserved.
///
/// Pairs each band with its class because the reader of a sample has to
/// label it: the bounds travel to SQL as bind parameters and the result
/// comes back positionally (ADR 0066 D6 — the adapter never learns what
/// a class is), so this is the one place a position becomes a class
/// again. Derived from [`TaskTier::ALL`], so a fourth class joins every
/// observation by existing rather than by being added to a second list.
pub fn class_bands() -> Vec<(TaskTier, PriorityBand)> {
    TaskTier::ALL
        .iter()
        .map(|tier| (*tier, tier.priority_band()))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    use crate::events::EVENT_TASK_KINDS;

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

    /// Every literal the `jobs.kind` CHECK may hold, read off the one
    /// definition rather than re-typed.
    ///
    /// It used to be a hand-typed copy, on the same argument
    /// [`check_trigger_sources`] above once carried — that the CHECK is
    /// SQL and the test owed the reader its own statement of the column's
    /// contents. That argument is spent here for the same reason: the SQL
    /// CHECK is held against [`EVENT_TASK_KINDS`] by
    /// `task_kind_check_lockstep_guard`, so the constant *is* the
    /// column's contents, while nothing held the copy against either — a
    /// kind added to the column could leave this module's exhaustive
    /// loops running over a set the column no longer had, which is the
    /// one way an "exhaustive over the CHECK" assertion goes quietly
    /// vacuous.
    ///
    /// What this does **not** do is make a new kind declare itself below.
    /// [`TaskTier::classify`] answers from the *trigger source*, so an
    /// unrecognised kind classifies rather than failing — that is ADR
    /// 0066's design (the tier is a property of who waits, and the
    /// trigger source is what expresses it), not a gap. The loops here
    /// therefore guarantee that every pair the column admits gets a
    /// legal, class-consistent ordinal; they do not guarantee that a new
    /// kind appears in [`PRODUCER_CENSUS`], whose own reconciliation is
    /// its count assertion.
    fn check_kinds() -> &'static [&'static str] {
        EVENT_TASK_KINDS
    }

    /// Tier order as a number, so two tiers can be compared.
    ///
    /// Wildcard-free, so the fourth variant ADR 0066 D1 rules out cannot
    /// arrive without a rank — which would silently exempt it from
    /// `the_ordinal_order_agrees_with_the_tier_order` below.
    fn tier_rank(tier: TaskTier) -> u8 {
        match tier {
            TaskTier::Interactive => 2,
            TaskTier::Normal => 1,
            TaskTier::Bulk => 0,
        }
    }

    /// The per-producer census: `(kind, trigger_source, the ordinal the
    /// previous scheme wrote, the ordinal the table answers now)`.
    ///
    /// Each row names a producer and the constant or bare literal it used
    /// before the ordinal was decided in one place — thirteen named
    /// constants plus twelve bare literals, all twenty-five of them. Both
    /// numbers are written down here, so the change that re-ranks a path
    /// again has to edit a row rather than move a number quietly.
    ///
    /// The third column is deliberately **local history** rather than a
    /// read of the production constants: those constants no longer exist,
    /// and a test that imported one would answer `0 > 0` and pass once
    /// somebody deleted it.
    const PRODUCER_CENSUS: &[(&str, &str, i16, i16)] = &[
        // --- the twelve named constants ---
        // ADVISORY_PRIORITY = 5, task_handlers/advisory_watch_tick.rs
        ("scan", "advisory", 5, BULK_BAND),
        // CRON_RESCAN_PRIORITY = 10, task_handlers/cron_rescan_tick.rs
        ("scan", "cron", 10, BULK_BAND),
        // CLEARANCE_VERIFY_PRIORITY = 10, use_cases/ingest_use_case.rs —
        // the signature-arrival hook, and use_cases/quarantine_use_case.rs
        // reusing it for the expiry backstop.
        (
            "provenance-verify",
            "clearance",
            10,
            INTERACTIVE_BAND + LOW_VOLUME_OFFSET,
        ),
        // CRON_PRIORITY = 10, the seven `hort-server enqueue-*`
        // subcommands. Six of them are Bulk; the seventh enqueues the
        // release sweep, which D3 keeps client-waited whatever triggers
        // it.
        ("api-token-retention-sweep", "cron", 10, BULK_BAND),
        ("jobs-row-retention-sweep", "cron", 10, BULK_BAND),
        ("prefetch-row-retention-sweep", "cron", 10, BULK_BAND),
        ("prefetch-tick", "cron", 10, BULK_BAND),
        ("quarantine-release-sweep", "cron", 10, INTERACTIVE_BAND),
        ("scan-row-retention-sweep", "cron", 10, BULK_BAND),
        ("wheel-metadata-backfill", "cron", 10, BULK_BAND),
        // MANUAL_RESCAN_PRIORITY = 20, use_cases/manual_rescan_use_case.rs
        ("scan", "manual", 20, NORMAL_BAND + LOW_VOLUME_OFFSET),
        // MANUAL_PRIORITY = 20, cli/seed_import.rs
        (
            "seed-import",
            "seed-import",
            20,
            NORMAL_BAND + LOW_VOLUME_OFFSET,
        ),
        // CHILD_INGEST_ENQUEUE_PRIORITY = 0,
        // task_handlers/oci_index_child_ingest.rs (the grandchild
        // recursion) and use_cases/oci_index_child_enqueue.rs (the
        // pull-through leg)
        ("oci-index-child-ingest", "ingest", 0, INTERACTIVE_BAND),
        // --- the twelve bare literals ---
        // use_cases/ingest_use_case.rs: IngestEnqueue::Scan and
        // ::ProvenanceVerify at ingest, and the same pair on the
        // register-by-hash path when the caller backdates an anchor
        ("scan", "ingest", 0, INTERACTIVE_BAND),
        ("provenance-verify", "ingest", 0, INTERACTIVE_BAND),
        ("scan", "seed-import", 0, NORMAL_BAND),
        ("provenance-verify", "seed-import", 0, NORMAL_BAND),
        // The mount / pull-dedup-follower registration, which took the
        // schema default by falling through an unparseable literal.
        ("scan", "register-by-hash", 0, INTERACTIVE_BAND),
        ("provenance-verify", "register-by-hash", 0, INTERACTIVE_BAND),
        // use_cases/ingest_use_case.rs: the prefetch-dependencies
        // cascade root, from `ingest` and from `register_by_hash`. Its
        // kind carve-out answers before the trigger source, so it ranks
        // with the cascade's own child rows two entries below rather
        // than with the gates its `'ingest'` would otherwise file it
        // beside; see the module header.
        ("prefetch-dependencies", "ingest", 0, BULK_BAND),
        // use_cases/policy_use_case.rs: the scan-policy re-evaluation pass
        ("policy-reevaluation", "manual", 0, NORMAL_BAND),
        // use_cases/self_service_prefetch_use_case.rs: the `hort-cli
        // prefetch` root
        ("prefetch", "self_service", 0, NORMAL_BAND),
        // task_handlers/prefetch_tick.rs: the scheduled leaf rows
        ("prefetch", "scheduled", 0, BULK_BAND),
        // task_handlers/prefetch_dependencies.rs: the cascade's own leaf
        // and child rows
        ("prefetch", "prefetch", 0, BULK_BAND),
        ("prefetch-dependencies", "prefetch", 0, BULK_BAND),
    ];

    // -----------------------------------------------------------------
    // The per-producer census
    // -----------------------------------------------------------------

    /// **The acceptance assertion for the re-assignment**: per producer,
    /// the ordinal the table answers is the band its class names, at the
    /// floor or one volume step above it.
    #[test]
    fn every_producer_lands_in_the_band_its_class_names() {
        for (kind, source, previous, expected) in PRODUCER_CENSUS {
            let answered = queue_priority(kind, source);
            assert_eq!(
                answered, *expected,
                "({kind}, {source}) was {previous} under the previous scheme and must now \
                 answer {expected}; the table answered {answered}"
            );
            let tier = TaskTier::classify(kind, source)
                .unwrap_or_else(|| panic!("({kind}, {source}) does not classify"));
            assert!(
                answered == tier.band() || answered == tier.band() + LOW_VOLUME_OFFSET,
                "({kind}, {source}) is {} and must sit at that class's floor ({}) or one \
                 volume step above it; it answered {answered}",
                tier.as_str(),
                tier.band(),
            );
        }
        assert_eq!(
            PRODUCER_CENSUS.len(),
            25,
            "the census is the named constants plus the twelve bare literals the producers \
             wrote before the ordinal was decided in one place — thirteen of the former \
             since `enqueue-api-token-retention-sweep` joined the `CRON_PRIORITY` group; a \
             producer added or removed changes this number deliberately"
        );
    }

    /// Every admin task invoke lands at the `Normal` floor — it is
    /// bookkeeping an operator reads, and there is one row per invoke.
    ///
    /// Three kinds are deliberately outside the loop and asserted on
    /// their own, because none is reachable as a plain invoke of a
    /// `Normal` row:
    ///
    /// - `'scan'` is absent from `ADMIN_INVOKABLE_TASK_KINDS` (only
    ///   `enqueue_scan` writes the four scan-typed columns), and it is
    ///   the kind whose `'manual'` row carries the volume offset;
    /// - `'quarantine-release-sweep'` is invokable, and D3 keeps it
    ///   client-waited however it is triggered — including by hand;
    /// - `'prefetch-dependencies'` is invokable, and its carve-out keeps
    ///   it `Bulk` however it is triggered — including by hand, because
    ///   the thing that makes nobody wait on a cascade walk is what the
    ///   walk *does*, not who asked for it. An operator who hand-invokes
    ///   one is asking for a warm-up, and the next pull of any dependent
    ///   fetches that dependency whether or not the walk ever ran.
    #[test]
    fn an_admin_task_invoke_lands_at_the_normal_band_floor() {
        for kind in check_kinds() {
            if *kind == KIND_SCAN
                || *kind == KIND_QUARANTINE_RELEASE_SWEEP
                || *kind == KIND_PREFETCH_DEPENDENCIES
            {
                continue;
            }
            assert_eq!(
                queue_priority(kind, "manual"),
                NORMAL_BAND,
                "admin task invoke of {kind} must land at the Normal band floor"
            );
        }
        assert_eq!(
            queue_priority(KIND_SCAN, "manual"),
            NORMAL_BAND + LOW_VOLUME_OFFSET,
            "the operator's rescan carries the volume offset"
        );
        assert_eq!(
            queue_priority(KIND_QUARANTINE_RELEASE_SWEEP, "manual"),
            INTERACTIVE_BAND,
            "a hand-invoked release sweep is still the path a client is waiting on (D3)"
        );
        assert_eq!(
            queue_priority(KIND_PREFETCH_DEPENDENCIES, "manual"),
            BULK_BAND,
            "a hand-invoked cascade walk is still work nobody waits on; the carve-out is \
             keyed on the kind alone"
        );
    }

    /// Counter-assertion for the census above: the table can still answer
    /// something other than the schema default, so a `queue_priority`
    /// reduced to `0` everywhere would fail rather than make the census
    /// vacuously true.
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
            NORMAL_BAND + LOW_VOLUME_OFFSET,
            "the two-axis volume offset collapsed"
        );
        assert_eq!(
            queue_priority("provenance-verify", "manual"),
            NORMAL_BAND,
            "the two-axis volume offset stopped discriminating on kind"
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
        assert_eq!(
            scan_queue_priority("manual"),
            NORMAL_BAND + LOW_VOLUME_OFFSET
        );
        assert_eq!(queue_priority("noop", "manual"), NORMAL_BAND);
    }

    // -----------------------------------------------------------------
    // The two faces against each other
    // -----------------------------------------------------------------

    /// ADR 0066 D8's outcome, as an assertion, and the replacement for
    /// the `tier_and_ordinal_disagree_today` this change deleted: for
    /// every pair the two tables can be asked about, a higher class
    /// carries a strictly higher ordinal.
    ///
    /// Exhaustive over `TriggerSource::ALL` × the `jobs.kind` CHECK
    /// rather than a list of examples, and compared pairwise — so a
    /// future literal cannot be given a number that contradicts its
    /// class, whichever pair it would have contradicted.
    ///
    /// Equal classes are deliberately unconstrained here: inside a class
    /// the ordinal expresses volume, and the three rows that use it are
    /// each asserted by name below.
    #[test]
    fn the_ordinal_order_agrees_with_the_tier_order() {
        let mut pairs: Vec<(&str, &str, TaskTier, i16)> = Vec::new();
        for kind in check_kinds() {
            for source in check_trigger_sources() {
                let tier = TaskTier::classify(kind, source)
                    .unwrap_or_else(|| panic!("({kind}, {source}) does not classify"));
                pairs.push((kind, source, tier, queue_priority(kind, source)));
            }
        }

        for (hi_kind, hi_source, hi_tier, hi) in &pairs {
            for (lo_kind, lo_source, lo_tier, lo) in &pairs {
                if tier_rank(*hi_tier) <= tier_rank(*lo_tier) {
                    continue;
                }
                assert!(
                    hi > lo,
                    "({hi_kind}, {hi_source}) is {} and ({lo_kind}, {lo_source}) is {}, so \
                     {hi} must be above {lo}",
                    hi_tier.as_str(),
                    lo_tier.as_str(),
                );
            }
        }

        // Counter-assertions: the corpus is real. All three classes are
        // present (otherwise the cross product compares one class with
        // itself and asserts nothing), and every band floor and volume
        // step is reached (otherwise a flattened layout would pass).
        let classes: BTreeSet<&str> = pairs.iter().map(|(_, _, t, _)| t.as_str()).collect();
        assert_eq!(
            classes.len(),
            3,
            "the corpus must exercise all three classes: {classes:?}"
        );
        let ordinals: BTreeSet<i16> = pairs.iter().map(|(_, _, _, p)| *p).collect();
        assert_eq!(
            ordinals,
            [
                BULK_BAND,
                NORMAL_BAND,
                NORMAL_BAND + LOW_VOLUME_OFFSET,
                INTERACTIVE_BAND,
                INTERACTIVE_BAND + LOW_VOLUME_OFFSET,
            ]
            .into_iter()
            .collect::<BTreeSet<_>>(),
            "the corpus must reach every band floor and every volume step"
        );
    }

    /// The upgrade property, over the previous scheme's whole set of
    /// numbers: nothing already queued when the re-ranking ships can
    /// outrank a fresh waited-on row, and nothing freshly enqueued as
    /// background work can outrank something already queued.
    ///
    /// Together those two are why there is no migration and no backfill
    /// (ADR 0066 D7): the queued rows drain in an order no worse than the
    /// one they were enqueued under.
    #[test]
    fn a_row_at_the_previous_schemes_ordinal_does_not_outrank_a_fresh_waited_on_row() {
        let previous: BTreeSet<i16> = PRODUCER_CENSUS.iter().map(|(_, _, old, _)| *old).collect();
        assert_eq!(
            previous,
            [0, 5, 10, 20].into_iter().collect::<BTreeSet<_>>(),
            "the previous scheme wrote exactly these four numbers — the census above is the \
             record of which producer wrote which, and this property is stated against the \
             set rather than against one example"
        );
        let highest_queued = *previous
            .iter()
            .max()
            .expect("the previous scheme wrote at least one number");
        let lowest_queued = *previous
            .iter()
            .min()
            .expect("the previous scheme wrote at least one number");

        for (kind, source, _, _) in PRODUCER_CENSUS {
            let tier = TaskTier::classify(kind, source)
                .unwrap_or_else(|| panic!("({kind}, {source}) does not classify"));
            let fresh = queue_priority(kind, source);
            match tier {
                TaskTier::Interactive | TaskTier::Normal => assert!(
                    fresh > highest_queued,
                    "a fresh ({kind}, {source}) row is {} at {fresh}, which does not clear \
                     {highest_queued} — the highest ordinal an older binary can already have \
                     queued, so such a row would outrank this one",
                    tier.as_str(),
                ),
                TaskTier::Bulk => assert!(
                    fresh <= lowest_queued,
                    "a fresh ({kind}, {source}) row is Bulk at {fresh}, above \
                     {lowest_queued} — the lowest ordinal an older binary can already have \
                     queued, so fresh background work would outrank an already-queued \
                     client-waited row",
                ),
            }
        }
    }

    /// The whole layout fits the column's `CHECK (priority BETWEEN 0 AND
    /// 100)`, for every pair the tables know.
    ///
    /// A band that overflowed it would not fail here or in review — it
    /// would fail as a `23514` check_violation at every producer at once,
    /// in production. The `const` assertion beside the bands covers the
    /// arithmetic; this covers the answers.
    #[test]
    fn every_ordinal_the_table_answers_fits_the_columns_check() {
        let mut answers: Vec<i16> = Vec::new();
        for kind in check_kinds() {
            for source in check_trigger_sources() {
                let p = queue_priority(kind, source);
                assert!(
                    (0..=COLUMN_CHECK_MAX).contains(&p),
                    "({kind}, {source}) answers {p}, outside the jobs.priority CHECK"
                );
                answers.push(p);
            }
        }
        // Counter-assertion: the bound is not vacuous. The top of the
        // layout is the Interactive floor plus one volume step, and the
        // bottom is the column default — so the range the loop above
        // cleared is the whole layout, and a band moved past the CHECK
        // would be a failure here rather than a `23514` in production.
        assert_eq!(
            answers.iter().copied().max(),
            Some(INTERACTIVE_BAND + LOW_VOLUME_OFFSET),
            "the highest ordinal the table answers must be the top of the layout"
        );
        assert_eq!(
            answers.iter().copied().min(),
            Some(SCHEMA_DEFAULT_PRIORITY),
            "the lowest ordinal the table answers must be the column default"
        );
    }

    // -----------------------------------------------------------------
    // The three within-class separations, each by name
    // -----------------------------------------------------------------

    /// The operator's rescan outranks the other `'manual'` rows.
    ///
    /// An operator is reading that answer; the admin task invoke and the
    /// gitops-driven policy re-evaluation that share the trigger source
    /// are bookkeeping. Asserted as a *within-class* separation — same
    /// tier, one volume step — so flattening it fails here and promoting
    /// it to a class of its own (which D1 rules out) fails here too.
    #[test]
    fn the_manual_rescan_outranks_the_other_manual_rows() {
        for other in ["policy-reevaluation", "noop", "retention-purge"] {
            assert_eq!(
                TaskTier::classify(KIND_SCAN, "manual"),
                TaskTier::classify(other, "manual"),
                "the rescan and {other} must stay in one class — the separation is by volume"
            );
            assert!(
                queue_priority(KIND_SCAN, "manual") > queue_priority(other, "manual"),
                "the operator's rescan must outrank {other}, which is bookkeeping"
            );
        }
        assert_eq!(
            queue_priority(KIND_SCAN, "manual") - queue_priority("noop", "manual"),
            LOW_VOLUME_OFFSET,
            "the separation is one volume step inside the band, not a band of its own"
        );
    }

    /// The `hort-server seed-import` subcommand's own row outranks the
    /// scans and verifies that import then enqueues.
    ///
    /// One row drives the import; the scans are one per artifact in it.
    /// Same trigger source, so the ordinal is the only thing that can
    /// separate them.
    #[test]
    fn the_seed_imports_own_row_outranks_the_scans_it_enqueues() {
        for enqueued in [KIND_SCAN, "provenance-verify"] {
            assert_eq!(
                TaskTier::classify(KIND_SEED_IMPORT, "seed-import"),
                TaskTier::classify(enqueued, "seed-import"),
                "the import's own row and its {enqueued} rows must stay in one class"
            );
            assert!(
                queue_priority(KIND_SEED_IMPORT, "seed-import")
                    > queue_priority(enqueued, "seed-import"),
                "the import's own row must outrank the {enqueued} rows it enqueues"
            );
        }
        assert_eq!(
            queue_priority(KIND_SEED_IMPORT, "seed-import")
                - queue_priority(KIND_SCAN, "seed-import"),
            LOW_VOLUME_OFFSET,
            "the separation is one volume step inside the band, not a band of its own"
        );
    }

    /// The clearance-gating verify outranks the ingest-time verify
    /// backlog.
    ///
    /// Three claims, and the class one is the reason the other two are a
    /// within-band offset rather than a band:
    ///
    /// - the **class is the same** as the ingest-time verify it was once
    ///   indistinguishable from: who waits does not change (D1 — not a
    ///   fourth class);
    /// - the **ordinal is strictly above** it, because that backlog is
    ///   one row per ingest and a held artifact queued behind it waits
    ///   for the backlog rather than for its own verify;
    /// - the step is exactly [`LOW_VOLUME_OFFSET`], so this cannot
    ///   quietly become a band.
    #[test]
    fn the_clearance_verify_outranks_the_ingest_time_verify_backlog() {
        assert_eq!(
            TaskTier::classify("provenance-verify", "clearance"),
            Some(TaskTier::Interactive)
        );
        assert_eq!(
            TaskTier::classify("provenance-verify", "ingest"),
            Some(TaskTier::Interactive),
            "the class boundary must be visibly unchanged"
        );
        assert!(
            queue_priority("provenance-verify", "clearance")
                > queue_priority("provenance-verify", "ingest"),
            "a clearance verify that does not outrank the ingest-time verify backlog makes a \
             held artifact wait for the backlog rather than for its own verify"
        );
        assert_eq!(
            queue_priority("provenance-verify", "clearance")
                - queue_priority("provenance-verify", "ingest"),
            LOW_VOLUME_OFFSET,
            "the separation is one volume step inside the band, not a band of its own"
        );
        // The offset belongs to the *row*, not to the trigger source:
        // `'clearance'` is the clearance verify's volume fact and says
        // nothing about any other kind. Read on the source alone it
        // would lift whatever band the kind landed in — including the
        // `Bulk` floor, which the compatibility property needs to be the
        // column default exactly.
        assert_eq!(
            queue_priority("noop", "clearance"),
            INTERACTIVE_BAND,
            "the clearance offset stopped discriminating on kind"
        );
        assert_eq!(
            queue_priority(KIND_PREFETCH_DEPENDENCIES, "clearance"),
            BULK_BAND,
            "a carve-out kind under `'clearance'` must sit at its own band's floor, not \
             one step above it"
        );
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
            for kind in check_kinds() {
                assert!(
                    TaskTier::classify(kind, source).is_some(),
                    "({kind}, {source}) does not classify"
                );
            }
        }
    }

    /// A `trigger_source` outside the set does not acquire a tier, and
    /// takes the schema default ordinal — which is the bottom of the
    /// layout, so it cannot displace anything.
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

    /// The release sweep's kind carve-out is read **before** the trigger
    /// source (D3), so a sweep row whose trigger source does not parse
    /// still classifies — and still carries its class's band.
    ///
    /// A carve-out kind is one of the two inputs for which
    /// [`TaskTier::classify`] answers `Some` while the trigger source is
    /// unreadable, so it is one of the two that reach
    /// [`low_volume_offset`] without a parseable source. The band floor
    /// is the right answer there: nothing about an unreadable trigger
    /// source makes a row the low-volume member of its class, and
    /// dropping such a row to the bottom of the layout would be exactly
    /// the "it is a scheduled task, so it ranks with scheduled tasks"
    /// misfiling D3 exists to forbid. The sibling carve-out's half of
    /// the same property is in
    /// `the_kind_carve_outs_are_exactly_two_and_each_is_that_kinds_alone`.
    #[test]
    fn the_release_sweep_keeps_its_band_when_its_trigger_source_does_not_parse() {
        for source in ["api", "", "Cron", "advisory_watch"] {
            assert_eq!(
                TaskTier::classify(KIND_QUARANTINE_RELEASE_SWEEP, source),
                Some(TaskTier::Interactive),
                "the kind carve-out must be read before the trigger source"
            );
            assert_eq!(
                queue_priority(KIND_QUARANTINE_RELEASE_SWEEP, source),
                INTERACTIVE_BAND,
                "{source:?} must not cost the sweep its band"
            );
        }
        // Counter-assertion: the carve-out is this kind's, not every
        // kind's. Any other kind with an unreadable trigger source does
        // not classify and takes the bottom of the layout.
        assert_eq!(TaskTier::classify("scan", "api"), None);
        assert_eq!(queue_priority("scan", "api"), SCHEMA_DEFAULT_PRIORITY);
    }

    /// ADR 0066 D3 read in the other direction: the dependency-cascade
    /// root is work nobody is waiting on, whatever caused it.
    ///
    /// Asserted over [`TriggerSource::ALL`] rather than for the
    /// `'ingest'` the two producers actually stamp, because the
    /// carve-out is read **before** the parse — the claim is about the
    /// kind, so the test has to be too. The push has already answered
    /// `201`; the walk makes *later* pulls warm; and the next pull of
    /// any dependent fetches that dependency on its own path, so a walk
    /// that never ran leaves nobody waiting.
    #[test]
    fn the_cascade_root_is_bulk_on_every_trigger_source() {
        for source in check_trigger_sources() {
            assert_eq!(
                TaskTier::classify(KIND_PREFETCH_DEPENDENCIES, source),
                Some(TaskTier::Bulk),
                "the cascade under {source} is not Bulk"
            );
            assert_eq!(
                queue_priority(KIND_PREFETCH_DEPENDENCIES, source),
                BULK_BAND,
                "{source} must not lift the cascade off the Bulk floor"
            );
        }
        // And the carve-out is read before the parse, so an unreadable
        // trigger source does not cost it its class either — the half of
        // `the_release_sweep_keeps_its_band_when_its_trigger_source_does_not_parse`
        // that belongs to this kind.
        for source in ["api", "", "Cron", "advisory_watch"] {
            assert_eq!(
                TaskTier::classify(KIND_PREFETCH_DEPENDENCIES, source),
                Some(TaskTier::Bulk),
                "the kind carve-out must be read before the trigger source"
            );
            assert_eq!(
                queue_priority(KIND_PREFETCH_DEPENDENCIES, source),
                BULK_BAND,
                "{source:?} must not cost the cascade its band"
            );
        }
    }

    /// The relation this carve-out exists for: the cascade root does not
    /// outrank the work it used to drain behind.
    ///
    /// With prefetch-on-ingest enabled a bulk push produces one root per
    /// artifact. Read off its `'ingest'` trigger source that flood sat
    /// at the `Interactive` floor — above the operator's manual rescan,
    /// above an admin task invoke, and level with the ingest-time gates
    /// that stand between a client's bytes and being served. Stated as
    /// strict inequalities against each of those plus the band itself,
    /// so neither a band change nor a re-classification can satisfy this
    /// test while putting the flood back on top.
    #[test]
    fn the_cascade_root_does_not_outrank_the_work_it_drains_behind() {
        let root = queue_priority(KIND_PREFETCH_DEPENDENCIES, "ingest");
        assert_eq!(root, BULK_BAND, "the cascade root sits at the Bulk floor");
        for (what, other) in [
            (
                "the operator's manual rescan",
                queue_priority(KIND_SCAN, "manual"),
            ),
            ("an admin task invoke", queue_priority("noop", "manual")),
            (
                "the ingest-time scan gate",
                queue_priority(KIND_SCAN, "ingest"),
            ),
            (
                "the ingest-time provenance verify",
                queue_priority(KIND_PROVENANCE_VERIFY, "ingest"),
            ),
        ] {
            assert!(
                root < other,
                "the cascade root at {root} must not outrank {what} at {other} — one root \
                 per artifact is a flood, and nobody is waiting on any of them"
            );
        }
    }

    /// The root ranks **with** its own children, as an equality.
    ///
    /// The cascade's leaf-ingest and child-walk rows carry
    /// `trigger_source = 'prefetch'` and were already `Bulk`, so before
    /// the carve-out the root outranked its own descendants by two whole
    /// bands. Pinned as an equality rather than as a number so a later
    /// band change cannot separate them again without failing here.
    #[test]
    fn the_cascade_root_ranks_with_its_own_children() {
        let root = queue_priority(KIND_PREFETCH_DEPENDENCIES, "ingest");
        assert_eq!(
            root,
            queue_priority("prefetch", "prefetch"),
            "the root must rank with the leaf-ingest rows its walk enqueues"
        );
        assert_eq!(
            root,
            queue_priority(KIND_PREFETCH_DEPENDENCIES, "prefetch"),
            "the root must rank with the child-walk rows its walk enqueues"
        );
        assert_eq!(
            TaskTier::classify(KIND_PREFETCH_DEPENDENCIES, "ingest"),
            TaskTier::classify("prefetch", "prefetch"),
            "and in the same class, so the equality is not a coincidence of two bands"
        );
    }

    /// The census of kind carve-outs: there are exactly two, and each
    /// answers for its own kind only.
    ///
    /// A carve-out's observable signature is that
    /// [`TaskTier::classify`] answers `Some` for a trigger source it
    /// cannot parse — that is what "read before the trigger source"
    /// means. So the census is exhaustive over the `jobs.kind` CHECK
    /// with an unparseable source, with **no allow-list**: a third
    /// carve-out fails here, where the module header's reasoning for the
    /// two sits, rather than arriving as a line somebody added quietly.
    ///
    /// The per-kind halves are the counter-assertions: a sibling sweep
    /// kind on the sweep's own trigger source is `Bulk`, and a sibling
    /// prefetch kind on the cascade root's own trigger source is
    /// `Interactive` — so neither carve-out is a prefix match or a
    /// whole-family rule.
    #[test]
    fn the_kind_carve_outs_are_exactly_two_and_each_is_that_kinds_alone() {
        let unparseable = "api";
        assert!(
            unparseable.parse::<TriggerSource>().is_err(),
            "the probe has to be a source the parse rejects, or this census is vacuous"
        );

        let carved: BTreeSet<(&str, &str)> = check_kinds()
            .iter()
            .filter_map(|kind| {
                TaskTier::classify(kind, unparseable).map(|tier| (*kind, tier.as_str()))
            })
            .collect();
        assert_eq!(
            carved,
            [
                (KIND_QUARANTINE_RELEASE_SWEEP, "interactive"),
                (KIND_PREFETCH_DEPENDENCIES, "bulk"),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>(),
            "exactly two kinds are classified off the kind before the trigger source, and \
             these are the classes the module header reasons about: {carved:?}"
        );

        // Each is that kind's alone, not its family's.
        assert_eq!(
            TaskTier::classify("jobs-row-retention-sweep", "cron"),
            Some(TaskTier::Bulk),
            "a sibling sweep on the release sweep's own trigger source must stay Bulk"
        );
        assert_eq!(
            TaskTier::classify("prefetch", "ingest"),
            Some(TaskTier::Interactive),
            "a sibling prefetch kind on the cascade root's own trigger source must read \
             its trigger source — the carve-out is one kind, not a prefix"
        );
        assert_eq!(
            TaskTier::classify("prefetch-row-retention-sweep", "ingest"),
            Some(TaskTier::Interactive),
            "and the match is the whole kind, not a prefix of it either"
        );
    }

    /// The column default is the lowest band and not the top one.
    ///
    /// Both halves matter. It must not be the top band, or a producer
    /// that sets nothing — and a hand-written row — could displace a
    /// client-waited one. It is allowed to be the lowest, because the
    /// per-class reservation keys on [`TaskTier::classify`]'s answer and
    /// not on the ordinal, so a row at the default is still protected by
    /// its class.
    #[test]
    fn the_schema_default_is_the_lowest_band_and_not_the_top() {
        assert_eq!(SCHEMA_DEFAULT_PRIORITY, TaskTier::Bulk.band());
        assert!(SCHEMA_DEFAULT_PRIORITY < TaskTier::Normal.band());
        assert!(SCHEMA_DEFAULT_PRIORITY < TaskTier::Interactive.band());
        for kind in check_kinds() {
            for source in check_trigger_sources() {
                assert!(
                    queue_priority(kind, source) >= SCHEMA_DEFAULT_PRIORITY,
                    "({kind}, {source}) answers below the column default"
                );
            }
        }
    }

    /// `'register-by-hash'` — the literal admitted into the set when the
    /// OCI cross-repository mount's `500` was fixed.
    ///
    /// A mount is a client request waiting on its `201`, so it belongs
    /// with the ingest-time gates rather than with the background
    /// sweeps — and now that the ordinal follows the class, it ranks
    /// with them too. Pinned as an equality with the ingest-time pair
    /// rather than as a number: the claim is "the same rank as the gates
    /// it is one of", which survives the bands moving.
    #[test]
    fn register_by_hash_is_interactive_and_ranks_with_the_ingest_time_gates() {
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
            queue_priority("scan", "ingest")
        );
        assert_eq!(
            queue_priority("provenance-verify", "register-by-hash"),
            queue_priority("provenance-verify", "ingest")
        );
        assert_eq!(
            scan_queue_priority("register-by-hash"),
            scan_queue_priority("ingest")
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
    /// `'cron'` its CronJob actually stamps — and, now that the ordinal
    /// follows the class, it **outranks** the scheduled rescan flood it
    /// used to tie with.
    ///
    /// The tie is the second instance: a push completed, its quarantine
    /// window elapsed, and nothing released it, because the sweep sat at
    /// the cron ordinal and `created_at ASC` resolved the tie against it
    /// — a backlog is always older than the next scheduled run.
    #[test]
    fn the_release_sweep_is_client_waited_even_when_scheduled() {
        for source in check_trigger_sources() {
            assert_eq!(
                TaskTier::classify(KIND_QUARANTINE_RELEASE_SWEEP, source),
                Some(TaskTier::Interactive),
                "the release sweep under {source} is not Interactive"
            );
        }
        assert!(
            queue_priority(KIND_QUARANTINE_RELEASE_SWEEP, "cron") > queue_priority("scan", "cron"),
            "the sweep must outrank the scheduled rescan flood; at an equal ordinal the \
             claim's age tiebreak resolves against the sweep, which is the stall"
        );
        assert!(
            queue_priority(KIND_QUARANTINE_RELEASE_SWEEP, "cron")
                > queue_priority("jobs-row-retention-sweep", "cron"),
            "the sweep must outrank the other cron-triggered CronJob rows too"
        );
        // Counter-assertion: the carve-out is the kind's, not every
        // kind's. A sibling sweep on the same trigger source is Bulk.
        assert_eq!(
            TaskTier::classify("jobs-row-retention-sweep", "cron"),
            Some(TaskTier::Bulk)
        );
    }

    // -----------------------------------------------------------------
    // The bands a reservation is expressed on (ADR 0066 D4)
    // -----------------------------------------------------------------

    /// The three bands **partition** the `i16` space: every value
    /// belongs to exactly one.
    ///
    /// This is what makes `priority_band` usable as a classification by
    /// a reader that cannot call `classify` — the claim SQL. A gap would
    /// make a row invisible to the per-class reservation while it still
    /// competed for the batch; an overlap would let one row satisfy two
    /// classes' reservations at once. Checked over the whole space at
    /// the boundaries plus every ordinal the table can answer, rather
    /// than only at the three floors, because an off-by-one at a band
    /// edge is exactly the shape that survives a floors-only check.
    #[test]
    fn the_bands_partition_the_ordinal_space() {
        let mut edges: Vec<i16> = vec![i16::MIN, i16::MAX, 0, COLUMN_CHECK_MAX];
        for tier in TaskTier::ALL {
            let band = tier.priority_band();
            for at in [band.lowest, band.highest] {
                edges.push(at);
                edges.push(at.saturating_sub(1));
                edges.push(at.saturating_add(1));
            }
        }
        for (kind, source, _, ordinal) in PRODUCER_CENSUS {
            let _ = (kind, source);
            edges.push(*ordinal);
        }
        for at in edges {
            let owners: Vec<TaskTier> = TaskTier::ALL
                .into_iter()
                .filter(|tier| tier.priority_band().contains(at))
                .collect();
            assert_eq!(
                owners.len(),
                1,
                "priority {at} belongs to {} bands, not exactly one: {owners:?}",
                owners.len()
            );
        }
    }

    /// A freshly written ordinal lands in its own class's band — the
    /// projection the claim's reservation rests on.
    ///
    /// `every_producer_lands_in_the_band_its_class_names` already holds
    /// the *write* direction (the ordinal equals the class's floor plus
    /// the volume offset); this is the *read* direction over the same
    /// census, which is the one the SQL performs. Both are needed: a
    /// band whose `highest` was set one short of the volume offset would
    /// pass the write check and fail here.
    #[test]
    fn a_fresh_ordinal_reads_back_as_its_own_class() {
        for &(kind, source, _, _) in PRODUCER_CENSUS {
            let tier = TaskTier::classify(kind, source).expect("census row classifies");
            let ordinal = queue_priority(kind, source);
            assert!(
                tier.priority_band().contains(ordinal),
                "({kind}, {source}) is {tier:?} and writes {ordinal}, which is outside \
                 {:?}",
                tier.priority_band()
            );
        }
    }

    /// `waited_on_bands` is `ALL` filtered by `is_waited_on`, in that
    /// order — not a second list.
    ///
    /// The thing a copy would get wrong is the *order*: the bands are
    /// consumed highest-first, and at a batch size of one the order is
    /// the whole decision. So this asserts the sequence, not the set.
    #[test]
    fn the_reserved_bands_are_the_waited_on_classes_highest_first() {
        let bands = waited_on_bands();
        assert_eq!(
            bands,
            vec![
                TaskTier::Interactive.priority_band(),
                TaskTier::Normal.priority_band()
            ],
            "the reserved bands must be Interactive then Normal"
        );
        // Counter-assertion: the filter is real — Bulk is a class, has a
        // band, and is deliberately absent.
        assert!(!TaskTier::Bulk.is_waited_on());
        assert!(!bands.contains(&TaskTier::Bulk.priority_band()));
        assert_eq!(
            bands.len(),
            TaskTier::ALL.iter().filter(|t| t.is_waited_on()).count(),
            "every waited-on class must contribute exactly one band"
        );
    }

    /// `class_bands` is every class, highest first — the observation
    /// list, which is NOT the reservation list.
    ///
    /// The thing that would collapse the two is a `class_bands` written
    /// as `waited_on_bands` plus a label: the per-class service
    /// observation would then never report `Bulk`, the one class with
    /// no reserved share and therefore the one whose service nothing
    /// else holds. So this asserts that the list includes it, and that
    /// the two functions disagree exactly there.
    #[test]
    fn the_observed_bands_are_every_class_including_the_unreserved_one() {
        let observed = class_bands();
        assert_eq!(
            observed,
            vec![
                (TaskTier::Interactive, TaskTier::Interactive.priority_band()),
                (TaskTier::Normal, TaskTier::Normal.priority_band()),
                (TaskTier::Bulk, TaskTier::Bulk.priority_band()),
            ],
            "the observed bands must be every class, highest first, each with its own band"
        );
        assert_eq!(
            observed.len(),
            TaskTier::ALL.len(),
            "every class must contribute exactly one observed band"
        );
        // The counter-assertion: the reservation list is strictly
        // smaller, and the difference is exactly the class nobody waits
        // on.
        let reserved = waited_on_bands();
        let observed_bands: Vec<PriorityBand> = observed.iter().map(|(_, b)| *b).collect();
        assert!(
            observed_bands.len() > reserved.len(),
            "an observation that matched the reservation would be blind to Bulk"
        );
        let only_observed: Vec<PriorityBand> = observed_bands
            .iter()
            .copied()
            .filter(|b| !reserved.contains(b))
            .collect();
        assert_eq!(only_observed, vec![TaskTier::Bulk.priority_band()]);
    }

    /// `TaskTier::ALL` is ordered highest class first, and is complete.
    ///
    /// The order is load-bearing (it decides which reservation is
    /// honoured when capacity runs out), and completeness is what makes
    /// `waited_on_bands`'s filter total — a class missing from `ALL`
    /// would silently lose its reserved share at both allocation
    /// points.
    #[test]
    fn the_order_of_all_is_the_tier_order() {
        let ranks: Vec<u8> = TaskTier::ALL.into_iter().map(tier_rank).collect();
        let mut descending = ranks.clone();
        descending.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(ranks, descending, "ALL must be ordered highest class first");
        let distinct: BTreeSet<u8> = ranks.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            TaskTier::ALL.len(),
            "ALL must list each class once"
        );
        // Every pair the ordinal table can answer about classifies into
        // a class ALL lists — the completeness half.
        for &(kind, source, _, _) in PRODUCER_CENSUS {
            let tier = TaskTier::classify(kind, source).expect("census row classifies");
            assert!(
                TaskTier::ALL.contains(&tier),
                "({kind}, {source}) classifies as {tier:?}, which ALL does not list"
            );
        }
    }

    /// An ordinal an older binary wrote reads as `Bulk` — the known,
    /// bounded disagreement between the row's class and its band.
    ///
    /// Asserted rather than left implied, because it is the one place
    /// the band projection is *not* the classification: the previous
    /// scheme's whole set of numbers is below the `Normal` floor, so
    /// such a row misses a waited-on reservation until it drains (ADR
    /// 0066 D7, no backfill). Safe in the direction that matters — it
    /// can miss a reserved slot, never consume one — and that is the
    /// half this pins.
    #[test]
    fn an_ordinal_from_the_previous_scheme_reads_as_bulk() {
        // The previous scheme's whole set, written down here as local
        // history: the constants that held them no longer exist, and a
        // test reading one that moved would go vacuous instead of
        // failing.
        for previous in [0i16, 5, 10, 20] {
            assert!(
                TaskTier::Bulk.priority_band().contains(previous),
                "an ordinal of {previous} from the previous scheme must read as Bulk"
            );
            for tier in TaskTier::ALL.into_iter().filter(|t| t.is_waited_on()) {
                assert!(
                    !tier.priority_band().contains(previous),
                    "{previous} must not fall in {tier:?}'s band — a row an older binary \
                     queued would then consume a waited-on class's reserved slot"
                );
            }
        }
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
        assert_eq!(labels.iter().collect::<BTreeSet<_>>().len(), 3);
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
    fn tier_rank_orders_the_three_classes() {
        assert!(tier_rank(TaskTier::Interactive) > tier_rank(TaskTier::Normal));
        assert!(tier_rank(TaskTier::Normal) > tier_rank(TaskTier::Bulk));
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
