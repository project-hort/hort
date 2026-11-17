//! PostgreSQL adapter for [`CurationQueueRepository`].
//!
//! Executes the queue listing query against the live
//! `artifacts`, `repositories`, `scan_findings`, `policy_projections`,
//! and `events` tables.
//!
//! ## Per-row deadline resolution (load-bearing)
//!
//! The queue can span repositories whose
//! `ScanPolicy.quarantine_duration_secs` differ; the deadline must
//! therefore be resolved **per row, in SQL**. The adapter joins to the
//! `policy_projections` view with the same precedence
//! `quarantine_release_candidates` uses (repo-scoped non-archived >
//! global non-archived; no operator policy ⇒ no deadline). The deadline
//! expression `window_start + duration * INTERVAL '1 second'` mirrors
//! [`effective_quarantine_deadline`](hort_domain::policy::effective_quarantine_deadline).
//! The use case does NOT pre-resolve a duration parameter (single query
//! preserves both the `limit` cap and the cross-repo result set).
//!
//! ## Rejection-reason via LATERAL JOIN
//!
//! For `quarantine_status = 'rejected'` rows the adapter resolves the
//! latest `ArtifactRejected` event's `rejected_by` discriminator via:
//!
//! ```sql
//! LEFT JOIN LATERAL (
//!   SELECT event_data
//!   FROM events
//!   WHERE stream_id = 'artifact-' || a.id::text
//!     AND event_type = 'ArtifactRejected'
//!   ORDER BY stream_position DESC
//!   LIMIT 1
//! ) e ON true
//! ```
//!
//! The persisted `event_data` shape is
//! `{"type": "ArtifactRejected", "data": { "rejected_by": <reason>, ... }}`
//! (see `mappers::serialize_event_data`). `rejected_by` is serialized by
//! serde's default externally-tagged convention:
//!
//! | Variant                                        | JSON shape                                   | Wire kind                 |
//! |------------------------------------------------|----------------------------------------------|---------------------------|
//! | `RejectionReason::Scanner`                     | `"Scanner"` (string)                         | `scanner`                 |
//! | `RejectionReason::Admin`                       | `"Admin"` (string)                           | `admin`                   |
//! | `RejectionReason::CurationRetroactive { .. }`  | `{"CurationRetroactive": {"rule_id": ".."}}` | `curation_retroactive`    |
//! | `RejectionReason::ScanPolicyRetroactive`       | `"ScanPolicyRetroactive"` (string)           | `scan_policy_retroactive` |
//! | `RejectionReason::Curator { .. }`              | `{"Curator": {"curator_id": ".."}}`          | `curator`                 |
//! | `RejectionReason::Provenance`                  | `"Provenance"` (string)                      | `provenance`              |
//! | `RejectionReason::Corruption`                  | `"Corruption"` (string)                      | `corruption`              |
//!
//! **The wire column is not a mechanical lowering** —
//! `ScanPolicyRetroactive` must become `scan_policy_retroactive`, not
//! `scanpolicyretroactive` — so every variant needs its own `CASE` arm;
//! the `ELSE lower(...)` fallthrough is a defensive backstop, not a
//! substitute. `RejectionReason::wire_kind()` is the single source, the
//! Rust-side `normalise_rejection_reason_kind` derives from it, and the
//! DB-free guard `sql_case_covers_every_rejection_reason_variant` pins
//! the SQL `CASE` to the same set.
//!
//! The CASE expression handles BOTH the bare-string form (unit variants)
//! and the single-key object form (tuple variants).
//!
//! `corruption` is here because the CAS-integrity tombstone now appends an
//! `ArtifactRejected{Corruption}` alongside its `ArtifactCorrupted` (ADR
//! 0039's 2026-09-12 amendment, D6) — the LATERAL reads the companion, not
//! the axis event. Before that companion existed this column resolved to
//! NULL for a corruption-tombstoned artifact, so a curator saw a `rejected`
//! row with no reason at all; a **historical** tombstone (a stream written
//! before the companion) still resolves to NULL, because the event store is
//! append-only and this change cannot reach backwards.
//!
//! The lowercasing of the PascalCase JSONB key happens **inside SQL**
//! (case-symmetry fix on commit ce043c05): both the output column and
//! the WHERE-clause filter share the same lowercased discriminator, so
//! a caller passing the wire format
//! (`filter.rejection_reason_kind = Some("curator")`) matches a
//! `{"Curator": …}` JSONB key. Before this fix the filter binding was
//! compared against the raw PascalCase key (`"Curator"`), which
//! contradicted the lowercase output produced by the same query — a
//! caller using the documented wire format hit zero rows.
//!
//! The `events` table has a unique index on `(stream_id,
//! stream_position)`; LATERAL is one indexed lookup per artifact row
//! and is bounded by `filter.limit`.
//!
//! ## `finding_count` / `max_severity` answer about the LAST scan
//!
//! `scan_findings` is per-scan history: every run writes its rows under a
//! fresh `scan_id` and nothing removes the previous run's, so a reader
//! that only filters on `artifact_id` summarises every scan the artifact
//! ever had and its numbers grow with the rescan count. The findings
//! LATERAL therefore carries `sf.detected_at = a.last_scan_at`, which
//! selects exactly one scan's rows: every row of one scan shares the one
//! `detected_at` the run was committed with.
//!
//! **The anchor is `artifacts.last_scan_at`, not anything inside
//! `scan_findings`.** `PgArtifactLifecycle::commit_scan_result_with_score`
//! writes `artifacts.last_scan_at` and inserts the per-finding rows in the
//! SAME transaction, from the same `DateTime<Utc>` the rows' `detected_at`
//! is bound from — so the anchor and the rows it selects can only ever
//! agree. The newest `scan_id` *present in the table* would not work: a
//! scan that found nothing writes no row at all, so a table-internal
//! anchor hands back the previous, dirty run for an artifact that has
//! since come clean. `last_scan_at` advances on that clean run, matches no
//! row, and the artifact reads as clean — which is the point.
//!
//! A `last_scan_at` of NULL (never scanned) matches nothing. The outer
//! projection uses that anchor to leave the finding summary absent;
//! a completed clean scan still reports zero findings.
//!
//! ## `tags` aggregates INSIDE its LATERAL
//!
//! The tag annotation reads `mutable_refs` for every ref pointing at the
//! driving row's bytes — `(repository_id, target_hash) =
//! (a.repository_id, a.checksum_sha256)`, which is exactly the shape of
//! the partial index `idx_mutable_refs_target_hash` (the equality is
//! strict in `target_hash`, so it implies the index's
//! `WHERE target_hash IS NOT NULL` predicate).
//!
//! **The aggregate is inside the subquery, and that is the load-bearing
//! part.** A plain `LEFT JOIN mutable_refs` returns one row *per ref*, so
//! an artifact with three tags would appear three times and `LIMIT $4`
//! would stop counting artifacts — a queue page would silently hold fewer
//! pieces of curator work than it claims, and the one row the curator acts
//! on would be indistinguishable from its duplicates. An aggregate with no
//! `GROUP BY` returns exactly one row over any input including none, so
//! `LEFT JOIN LATERAL (…) ON true` is one row in, one row out, tags or no
//! tags. `COALESCE(…, ARRAY[]::text[])` keeps the column non-NULL for the
//! no-tags case so the `Vec<String>` decode never meets a SQL NULL
//! (same shape as `repository_repo`'s `curation_rule_names`).
//!
//! `DISTINCT` because the uniqueness in the schema is
//! `(repository_id, namespace, ref_name)`: one repository can carry the
//! same ref name under two namespaces, both pointing at these bytes, and
//! this column is a display annotation that cannot show the namespace
//! it came from — a doubled name would read as a defect while telling the
//! curator nothing they could act on. `ORDER BY` so the rendered order is
//! the same on every read.
//!
//! The join does **not** reach `artifacts` a second time: the digest it
//! matches on is projected from the driving row, which the outer
//! `WHERE` has already restricted to live rows. A soft-deleted artifact
//! therefore stays out of the listing however many refs point at it.
//!
//! **Tags are never an addressing key here.** `CurationQueueFilter`
//! carries no tag field and the query has no tag predicate — a ref is a
//! mutable pointer, so a decision binds to the digest and the tag is for
//! a human to read.
//!
//! See `docs/architecture/how-to/curator-workflow.md` for operator guidance.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::entities::scan_policy::SeverityThreshold;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::RejectionReason;
use hort_domain::ports::curation_queue_repository::{
    CurationQueueEntry, CurationQueueFilter, CurationQueueRepository,
};

use crate::quarantine_status_sql::quarantine_status_from_sql;
use crate::BoxFuture;

/// `limit` hard cap — capped at 500 defensively. The use case is
/// responsible for surfacing `> 500` as a validation error; the
/// adapter still clamps so a bypass cannot drag the DB through a
/// 10k-row scan.
const MAX_LIMIT: u32 = 500;

/// PostgreSQL adapter for the curation queue listing.
pub struct PgCurationQueueRepository {
    pool: PgPool,
}

impl PgCurationQueueRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// The queue listing query.
///
/// Hoisted to a `const` (rather than inlined at the call site) so the
/// DB-free guard `sql_case_covers_every_rejection_reason_variant` can
/// read it: the PascalCase -> wire-format `CASE` below is the one place
/// the discriminator mapping is expressed in SQL, and nothing else in
/// the build can see whether it still covers every `RejectionReason`
/// variant.
///
/// - The `effective_policy_duration` CTE resolves
///   `quarantine_duration_secs` per repo using the same precedence
///   `quarantine_release_candidates` uses (repo-scoped > global; no
///   policy => NULL => no deadline).
/// - The LATERAL `events` lookup pulls the latest `ArtifactRejected`
///   event for the artifact's stream and extracts the `rejected_by`
///   discriminator via a `CASE` expression that handles BOTH the
///   bare-string form (unit variants) and the single-key object form
///   (tuple variants).
/// - `f.finding_count` and `f.max_severity_rank` are the same
///   scan_findings projection as `patch_candidate_repo` — values 0–4
///   inline mapping — scoped to the artifact's last scan by
///   `sf.detected_at = a.last_scan_at` (see the module docs).
/// - `LEFT JOIN` for findings + LATERAL so a row with no findings and no
///   rejection event still surfaces (e.g. `scan_indeterminate` rows).
/// - `t.tags` is the `mutable_refs` annotation, aggregated **inside** its
///   own LATERAL so the join yields exactly one row per artifact — tags
///   or no tags (see the module docs).
/// - `$1` = optional repository_id, `$2` = optional status text,
///   `$3` = optional rejection_reason_kind, `$4` = limit i64,
///   `$5` = optional artifact_id.
/// - `$1` and `$5` are a conjunction, not alternatives: a mismatched
///   pair (an artifact that is not in the named repository) returns
///   empty. There is no precedence rule and no silent widening.
const QUEUE_SQL: &str = r#"
                WITH effective_policy_duration AS (
                    -- Per-repo effective quarantine duration. Repo-scoped
                    -- non-archived policy beats global non-archived; an
                    -- unmatched repo gets NULL (no deadline computed).
                    SELECT
                        a.repository_id AS repository_id,
                        COALESCE(
                            (SELECT pp.quarantine_duration_secs
                             FROM policy_projections pp
                             WHERE pp.archived = false
                               AND pp.scope ? 'Repository'
                               AND (pp.scope->>'Repository')::uuid = a.repository_id
                             LIMIT 1),
                            (SELECT pp.quarantine_duration_secs
                             FROM policy_projections pp
                             WHERE pp.archived = false
                               AND pp.scope ? 'Global'
                             LIMIT 1)
                        ) AS duration_secs
                    FROM (SELECT DISTINCT repository_id FROM artifacts
                          WHERE quarantine_status IN ('quarantined','rejected','scan_indeterminate')
                            AND deleted_at IS NULL) a
                )
                SELECT
                    a.id                        AS artifact_id,
                    a.repository_id             AS repository_id,
                    r.key                       AS repository_key,
                    r.format::text              AS format,
                    a.name                      AS package_name,
                    a.version                   AS version,
                    a.path                      AS path,
                    -- The bytes the curator is deciding about, whole:
                    -- `character(64) NOT NULL`, projected unshortened
                    -- because this is the key a decision is addressed by.
                    a.checksum_sha256           AS checksum_sha256,
                    t.tags                      AS tags,
                    a.last_scan_at              AS last_scan_at,
                    a.quarantine_status         AS quarantine_status,
                    a.quarantine_window_start   AS quarantine_window_start,
                    CASE
                        WHEN a.quarantine_window_start IS NOT NULL
                             AND epd.duration_secs IS NOT NULL
                        THEN a.quarantine_window_start
                             + (epd.duration_secs * INTERVAL '1 second')
                        ELSE NULL
                    END                         AS quarantine_deadline,
                    COALESCE(f.finding_count, 0)::bigint AS finding_count,
                    f.max_severity_rank         AS max_severity_rank,
                    -- The LATERAL subquery `e` already projects the
                    -- lowercased discriminator (`scanner`, `admin`,
                    -- `curator`, `curation_retroactive`, …) so this
                    -- output column and the WHERE-clause filter share
                    -- the same lowercased value — case-symmetric with
                    -- the documented wire format.
                    e.rejection_reason_kind     AS rejection_reason_kind_raw
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
                LEFT JOIN effective_policy_duration epd
                       ON epd.repository_id = a.repository_id
                LEFT JOIN LATERAL (
                    SELECT
                        COUNT(*)::bigint AS finding_count,
                        MAX(CASE sf.severity
                                WHEN 'critical' THEN 4
                                WHEN 'high'     THEN 3
                                WHEN 'medium'   THEN 2
                                WHEN 'low'      THEN 1
                                ELSE 0
                            END)::int2 AS max_severity_rank
                    FROM scan_findings sf
                    WHERE sf.artifact_id = a.id
                      -- The last scan's rows and nothing else. See the
                      -- module docs: `artifacts.last_scan_at` is written in
                      -- the same transaction as these rows, from the same
                      -- value their `detected_at` carries.
                      AND sf.detected_at = a.last_scan_at
                ) f ON true
                LEFT JOIN LATERAL (
                    -- Single-source extraction: pull the latest
                    -- ArtifactRejected event for the stream, then map
                    -- the PascalCase JSONB discriminator
                    -- (`"Scanner"`/`"Admin"` bare-string for unit
                    -- variants; `"Curator"`/`"CurationRetroactive"`
                    -- single-key object for tuple variants) to the
                    -- wire format (lowercase / snake_case) via an
                    -- enumerated CASE that mirrors
                    -- `RejectionReason::wire_kind()`. One arm per
                    -- variant; `sql_case_covers_every_rejection_reason_variant`
                    -- is the DB-free guard that keeps the two in step.
                    -- Unknown variants lowercase through (defensive —
                    -- a future RejectionReason arm must still surface,
                    -- not vanish — but the lowering is NOT the wire
                    -- format for a multi-word variant, which is why
                    -- every variant needs its own arm rather than
                    -- relying on the ELSE).
                    SELECT
                        CASE
                            WHEN jsonb_typeof(ev.event_data->'data'->'rejected_by') = 'string'
                                THEN CASE ev.event_data->'data'->>'rejected_by'
                                    WHEN 'Scanner'              THEN 'scanner'
                                    WHEN 'Admin'                THEN 'admin'
                                    WHEN 'Curator'              THEN 'curator'
                                    WHEN 'CurationRetroactive'  THEN 'curation_retroactive'
                                    WHEN 'ScanPolicyRetroactive' THEN 'scan_policy_retroactive'
                                    WHEN 'Provenance'           THEN 'provenance'
                                    WHEN 'Corruption'           THEN 'corruption'
                                    ELSE lower(ev.event_data->'data'->>'rejected_by')
                                END
                            WHEN jsonb_typeof(ev.event_data->'data'->'rejected_by') = 'object'
                                THEN CASE (SELECT k FROM jsonb_object_keys(ev.event_data->'data'->'rejected_by') k LIMIT 1)
                                    WHEN 'Scanner'              THEN 'scanner'
                                    WHEN 'Admin'                THEN 'admin'
                                    WHEN 'Curator'              THEN 'curator'
                                    WHEN 'CurationRetroactive'  THEN 'curation_retroactive'
                                    WHEN 'ScanPolicyRetroactive' THEN 'scan_policy_retroactive'
                                    WHEN 'Provenance'           THEN 'provenance'
                                    WHEN 'Corruption'           THEN 'corruption'
                                    ELSE lower((SELECT k FROM jsonb_object_keys(ev.event_data->'data'->'rejected_by') k LIMIT 1))
                                END
                            ELSE NULL
                        END AS rejection_reason_kind
                    FROM events ev
                    WHERE ev.stream_id = 'artifact-' || a.id::text
                      AND ev.event_type = 'ArtifactRejected'
                    ORDER BY ev.stream_position DESC
                    LIMIT 1
                ) e ON true
                LEFT JOIN LATERAL (
                    -- Display-only tag annotation: every mutable ref that
                    -- points at THESE bytes in THIS repository. The
                    -- aggregate lives inside the subquery, which is what
                    -- makes the join one-row-in-one-row-out: an aggregate
                    -- with no GROUP BY returns a single row over any
                    -- input, empty included, so an artifact with three
                    -- tags still occupies one slot of `LIMIT $4` and an
                    -- artifact with none still appears. A plain
                    -- `LEFT JOIN mutable_refs` would return one row per
                    -- ref and the limit would stop counting artifacts.
                    --
                    -- `(repository_id, target_hash)` is the partial index
                    -- `idx_mutable_refs_target_hash`; the equality is
                    -- strict in `target_hash` and so implies that index's
                    -- `target_hash IS NOT NULL` predicate. No second read
                    -- of `artifacts`: the digest comes from the driving
                    -- row, which the outer WHERE has already restricted
                    -- to live rows.
                    --
                    -- DISTINCT because `(repository_id, namespace,
                    -- ref_name)` is the unique key — one repository can
                    -- carry the same ref name under two namespaces, and a
                    -- column that cannot show the namespace would render
                    -- the name twice for no reader's benefit. ORDER BY so
                    -- the rendering is stable across reads.
                    SELECT COALESCE(
                               ARRAY_AGG(DISTINCT mr.ref_name ORDER BY mr.ref_name),
                               ARRAY[]::text[]
                           ) AS tags
                    FROM mutable_refs mr
                    WHERE mr.repository_id = a.repository_id
                      AND mr.target_hash = a.checksum_sha256
                ) t ON true
                WHERE a.quarantine_status IN ('quarantined','rejected','scan_indeterminate')
                  AND a.deleted_at IS NULL
                  AND ($1::uuid IS NULL OR a.repository_id = $1)
                  AND ($5::uuid IS NULL OR a.id = $5)
                  AND ($2::text IS NULL OR a.quarantine_status = $2)
                  AND ($3::text IS NULL OR e.rejection_reason_kind = $3)
                ORDER BY a.created_at DESC
                LIMIT $4
"#;

impl CurationQueueRepository for PgCurationQueueRepository {
    fn list_queue<'a>(
        &'a self,
        filter: CurationQueueFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<CurationQueueEntry>>> {
        Box::pin(async move {
            // Clamp limit to MAX_LIMIT defensively (use case should
            // already validate; the adapter still enforces).
            let limit = filter.limit.min(MAX_LIMIT);

            // Status filter as Option<&str> — bound to a NULL when the
            // caller did not supply one. The outer set is
            // `IN ('quarantined','rejected','scan_indeterminate')`.
            let status_text: Option<String> = filter.status.map(|s| s.to_string());

            // See [`QUEUE_SQL`] for the query and its parameter map.
            let rows = sqlx::query_as::<_, CurationQueueRow>(QUEUE_SQL)
                .bind(filter.repository_id)
                .bind(status_text.as_deref())
                .bind(filter.rejection_reason_kind.as_deref())
                .bind(i64::from(limit))
                .bind(filter.artifact_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| DomainError::Invariant(format!("curation_queue_repo list: {e}")))?;

            rows.into_iter()
                .map(CurationQueueRow::into_domain)
                .collect()
        })
    }
}

/// sqlx FromRow shape for the queue listing projection.
#[derive(sqlx::FromRow)]
struct CurationQueueRow {
    artifact_id: Uuid,
    repository_id: Uuid,
    repository_key: String,
    format: String,
    package_name: String,
    version: Option<String>,
    path: String,
    /// `artifacts.checksum_sha256` — `character(64) NOT NULL`, so no
    /// `Option`: a row without a digest is a row the schema refuses.
    checksum_sha256: String,
    /// `COALESCE(ARRAY_AGG(…), ARRAY[]::text[])` from the tags LATERAL,
    /// and `mutable_refs.ref_name` is itself `NOT NULL` — so neither the
    /// column nor an element is ever SQL NULL and the decode needs no
    /// `Option` either. The empty vector is the no-tags answer.
    tags: Vec<String>,
    last_scan_at: Option<DateTime<Utc>>,
    quarantine_status: Option<String>,
    quarantine_window_start: Option<DateTime<Utc>>,
    quarantine_deadline: Option<DateTime<Utc>>,
    finding_count: i64,
    max_severity_rank: Option<i16>,
    rejection_reason_kind_raw: Option<String>,
}

impl CurationQueueRow {
    fn into_domain(self) -> DomainResult<CurationQueueEntry> {
        // Decoded through the crate's one codec
        // (`quarantine_status_sql`), so this reader cannot drift from
        // the column's stored vocabulary: an unclassifiable value is a
        // `DomainError::Invariant` there.
        //
        // The `None` arm on top of it is defence-in-depth (mirrors
        // `patch_candidate_repo`'s strict mapping). The codec maps SQL
        // NULL to `QuarantineStatus::None`, which is correct for the
        // column in general — but this query's outer filter pins the
        // rows to a non-NULL set, so a `None` here is drift in the
        // WHERE clause rather than a state. It is also the only way to
        // reach `None`: a literal `'none'` is not a stored spelling and
        // the codec refuses it.
        let quarantine_status =
            match quarantine_status_from_sql(self.quarantine_status.as_deref(), || {
                format!("curation_queue_repo row {}", self.artifact_id)
            })? {
                QuarantineStatus::None => {
                    return Err(DomainError::Invariant(format!(
                        "curation_queue_repo row {} has NULL quarantine_status",
                        self.artifact_id
                    )));
                }
                other => other,
            };

        // `RepositoryFormat::from_str` is infallible — unknown literals
        // round-trip as `Other(s)`. Mirrors `mappers.rs:67` /
        // `patch_candidate_repo`.
        let format: RepositoryFormat = self.format.parse().unwrap_or(RepositoryFormat::Generic);

        // SQL already projects the lowercase / snake_case wire format
        // (`"scanner" | "admin" | "curator" |
        // "curation_retroactive"`) from the LATERAL subquery — both
        // halves of the case-symmetric filter (output projection +
        // WHERE clause) read it from the same expression. The
        // Rust-side `normalise_rejection_reason_kind` is retained as
        // belt-and-braces (a SQL fork landing on a future
        // `RejectionReason` variant before the SQL CASE catches up
        // would otherwise surface PascalCase to callers); the inline
        // unit tests double as the canonical variant→wire-format
        // mapping documentation.
        let rejection_reason_kind = self
            .rejection_reason_kind_raw
            .map(|raw| normalise_rejection_reason_kind(&raw));
        let finding_count = self
            .last_scan_at
            .map(|_| i64_finding_count_to_u32(self.finding_count));
        let max_severity = self
            .last_scan_at
            .and_then(|_| self.max_severity_rank.and_then(severity_from_rank));

        Ok(CurationQueueEntry {
            artifact_id: self.artifact_id,
            repository_id: self.repository_id,
            repository_key: self.repository_key,
            format,
            package_name: self.package_name,
            version: self.version,
            path: self.path,
            checksum_sha256: self.checksum_sha256,
            tags: self.tags,
            quarantine_status,
            quarantine_window_start: self.quarantine_window_start,
            quarantine_deadline: self.quarantine_deadline,
            finding_count,
            max_severity,
            rejection_reason_kind,
        })
    }
}

/// Inverse mapping of the SQL `CASE sf.severity WHEN ...` ranks.
/// `0` (the LATERAL `ELSE 0` branch when no findings exist) and any
/// value outside `1..=4` map to `None`. Mirrors
/// `patch_candidate_repo::severity_from_rank`.
fn severity_from_rank(r: i16) -> Option<SeverityThreshold> {
    match r {
        4 => Some(SeverityThreshold::Critical),
        3 => Some(SeverityThreshold::High),
        2 => Some(SeverityThreshold::Medium),
        1 => Some(SeverityThreshold::Low),
        _ => None,
    }
}

/// Clamp a SQL `bigint COUNT(*)` to `u32`. Mirrors
/// `patch_candidate_repo::i64_finding_count_to_u32`.
fn i64_finding_count_to_u32(v: i64) -> u32 {
    if v < 0 {
        0
    } else {
        u32::try_from(v).unwrap_or(u32::MAX)
    }
}

/// Normalise the raw `rejected_by` discriminator to its wire format.
///
/// **Derived from the domain, not restated.** The mapping is
/// `RejectionReason::variant_name() → RejectionReason::wire_kind()` over
/// [`RejectionReason::ALL_KIND_SAMPLES`], the same single source the
/// admin queue's `?reason=` accepted set is built from — so a new variant
/// cannot appear in one place and be missing from the other.
///
/// **Note (case-symmetry fix on ce043c05):** the SQL LATERAL subquery
/// lowercases the discriminator before binding it to the output
/// column AND before comparing it against the `$3` filter parameter.
/// In the steady state this function therefore receives values that
/// are already lowercase and round-trips them unchanged. It is kept
/// as defence-in-depth: a future `RejectionReason` variant landing in
/// the domain ahead of the SQL CASE update would otherwise leak
/// PascalCase to HTTP callers.
///
/// Adapter-private — the wire format the HTTP DTO renders is the
/// normalised form. Pinning the case-conversion here makes the
/// filter parameter (`filter.rejection_reason_kind = Some("curator")`)
/// the same string the operator sees in the response.
///
/// Unknown discriminators round-trip lowercased (defensive: a future
/// `RejectionReason` variant should still surface, not vanish).
fn normalise_rejection_reason_kind(raw: &str) -> String {
    RejectionReason::ALL_KIND_SAMPLES
        .iter()
        .find(|r| r.variant_name() == raw)
        .map_or_else(|| raw.to_lowercase(), |r| r.wire_kind().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that the adapter implements the port.
    /// Mirrors `patch_candidate_repo::tests::pg_adapter_implements_port`.
    #[test]
    fn pg_adapter_implements_port() {
        fn assert_impl<T: CurationQueueRepository>() {}
        assert_impl::<PgCurationQueueRepository>();
    }

    // -- normalise_rejection_reason_kind ------------------------------------

    #[test]
    fn normalise_scanner_to_lowercase() {
        assert_eq!(normalise_rejection_reason_kind("Scanner"), "scanner");
    }

    #[test]
    fn normalise_admin_to_lowercase() {
        assert_eq!(normalise_rejection_reason_kind("Admin"), "admin");
    }

    #[test]
    fn normalise_curator_to_lowercase() {
        assert_eq!(normalise_rejection_reason_kind("Curator"), "curator");
    }

    #[test]
    fn normalise_curation_retroactive_to_snake_case() {
        assert_eq!(
            normalise_rejection_reason_kind("CurationRetroactive"),
            "curation_retroactive"
        );
    }

    /// `ScanPolicyRetroactive` (ADR 0041 tighten direction) gets a proper
    /// explicit snake_case arm rather than the degraded wildcard
    /// `to_lowercase` fallthrough (which would yield the run-together
    /// `scanpolicyretroactive`).
    #[test]
    fn normalise_scan_policy_retroactive_to_snake_case() {
        assert_eq!(
            normalise_rejection_reason_kind("ScanPolicyRetroactive"),
            "scan_policy_retroactive"
        );
    }

    /// The Rust-side normaliser is derived from the domain, so it covers
    /// **every** variant by construction — asserted here over the same
    /// single source rather than by re-listing the variants.
    #[test]
    fn normalise_covers_every_rejection_reason_variant() {
        for sample in RejectionReason::ALL_KIND_SAMPLES {
            assert_eq!(
                normalise_rejection_reason_kind(sample.variant_name()),
                sample.wire_kind(),
                "normaliser must map {} to its wire kind",
                sample.variant_name()
            );
        }
    }

    /// **DB-free drift guard for the SQL half of the mapping.**
    ///
    /// The PascalCase→wire `CASE` inside [`QUEUE_SQL`] is the one place
    /// the discriminator mapping is written in SQL, and the compiler
    /// cannot see it. Its `ELSE lower(...)` fallthrough makes an omission
    /// silent *and wrong* for any multi-word variant —
    /// `ScanPolicyRetroactive` lowers to `scanpolicyretroactive`, which
    /// matches neither the documented wire format nor the `$3` filter
    /// value an operator would send. That is exactly how
    /// `?reason=scan_policy_retroactive` came to match nothing.
    ///
    /// This is a source scan, unlike the sibling structural guards that
    /// deliberately avoid one — but here the SQL string *is* the artifact
    /// being checked, not a proxy for it.
    #[test]
    fn sql_case_covers_every_rejection_reason_variant() {
        for sample in RejectionReason::ALL_KIND_SAMPLES {
            let arm = format!("WHEN '{}'", sample.variant_name());
            assert!(
                QUEUE_SQL.contains(&arm),
                "QUEUE_SQL has no `{arm}` arm — a {} rejection would fall through the \
                 ELSE lower(...) branch and surface as `{}` instead of `{}`, which the \
                 ?reason= filter will never match",
                sample.variant_name(),
                sample.variant_name().to_lowercase(),
                sample.wire_kind()
            );
            let target = format!("THEN '{}'", sample.wire_kind());
            assert!(
                QUEUE_SQL.contains(&target),
                "QUEUE_SQL never produces `{}` — the {} arm maps to something else",
                sample.wire_kind(),
                sample.variant_name()
            );
        }
        // Both shapes of the discriminator need the arms: unit variants
        // serialise as a bare string, payload-carrying ones as a
        // single-key object, and the query branches on `jsonb_typeof`.
        for sample in RejectionReason::ALL_KIND_SAMPLES {
            let arm = format!("WHEN '{}'", sample.variant_name());
            assert_eq!(
                QUEUE_SQL.matches(&arm).count(),
                2,
                "`{arm}` must appear in BOTH the string-form and object-form CASE \
                 branches — a variant covered in only one is a latent gap the day its \
                 payload shape changes"
            );
        }
    }

    /// An unknown variant tag (introduced by a future
    /// `RejectionReason` arm) lower-cases through rather than
    /// vanishing.
    #[test]
    fn normalise_unknown_round_trips_lowercased() {
        assert_eq!(
            normalise_rejection_reason_kind("FutureVariant"),
            "futurevariant"
        );
    }

    // -- the tags LATERAL's shape -------------------------------------------

    /// **The aggregate is inside the LATERAL.** The DB-backed
    /// `list_queue_lateral_does_not_widen_the_row_set` proves the
    /// behaviour; this pins the shape that produces it, because moving
    /// the aggregate out to the outer query — or turning the subquery
    /// into a plain `LEFT JOIN mutable_refs` — still compiles, still
    /// returns the right tag *names*, and only breaks the row count.
    #[test]
    fn tags_are_aggregated_inside_their_lateral() {
        let (before, after) = QUEUE_SQL
            .split_once("FROM mutable_refs")
            .expect("the tags annotation reads `mutable_refs`");
        let lateral_open = before
            .rfind("LEFT JOIN LATERAL (")
            .expect("the `mutable_refs` scan sits inside a LEFT JOIN LATERAL");
        assert!(
            before[lateral_open..].contains("ARRAY_AGG(DISTINCT mr.ref_name ORDER BY mr.ref_name)"),
            "the aggregate must be INSIDE the lateral: a plain join over \
             `mutable_refs` returns one row per ref, so an artifact with \
             three tags would take three of `LIMIT $4`'s slots and appear \
             three times in the curator's worklist"
        );
        assert!(
            after.contains(") t ON true"),
            "the lateral joins `ON true`, which is what keeps the row of an \
             artifact that nothing points at"
        );
        // And no GROUP BY in the outer query, which is where one would
        // have to sit: the aggregation is the lateral's alone, and an
        // outer one would be the same widening repaired after the fact.
        // Asked of the text AFTER the lateral closes, not of the whole
        // query — the comment inside the lateral explains why there is no
        // outer GROUP BY, and a scan that could not tell a clause from a
        // sentence about one would read that explanation as the thing it
        // forbids.
        let outer_tail = after
            .rsplit_once(") t ON true")
            .expect("the lateral closes before the outer query's tail")
            .1;
        assert!(
            !outer_tail.contains("GROUP BY"),
            "the outer query must have no GROUP BY — found one in {outer_tail}"
        );
    }

    /// The no-tags case comes out of SQL as an empty array, not NULL —
    /// which is what lets the row decode into a plain `Vec<String>`
    /// instead of an `Option` nothing could reach.
    #[test]
    fn the_tags_column_is_never_null() {
        assert!(
            QUEUE_SQL.contains("ARRAY[]::text[]"),
            "the tags aggregate needs its COALESCE fallback: ARRAY_AGG over \
             zero rows is NULL, and a NULL column would fail the \
             `Vec<String>` decode for every artifact nothing points at"
        );
    }

    /// The tag is an annotation, never a selector.
    ///
    /// A ref is a mutable pointer: it can be moved to other bytes
    /// immediately after a curator reviewed these, so a listing that could
    /// be *narrowed* by tag would be offering an addressing mode whose
    /// answer changes under it. The digest is the addressing key, and the
    /// five bound parameters are the whole filterable surface.
    #[test]
    fn the_queue_cannot_be_filtered_by_tag() {
        let predicate_surface = QUEUE_SQL
            .rsplit_once(") t ON true")
            .expect("the tags lateral closes before the WHERE clause")
            .1;
        for tag_column in ["ref_name", "tags", "mutable_refs"] {
            assert!(
                !predicate_surface.contains(tag_column),
                "`{tag_column}` appears in the WHERE/ORDER/LIMIT surface — a \
                 tag is a mutable pointer and must not select which rows a \
                 curator sees"
            );
        }
    }

    /// The digest reaches the caller whole.
    ///
    /// The CLI table shortens it to 12 hex for alignment; a digest
    /// shortened in SQL would be shortened for the HTTP JSON too, where it
    /// is the key a curation decision is addressed by — and the truncation
    /// would be invisible to whoever tried to use it.
    #[test]
    fn the_digest_is_projected_whole() {
        assert!(
            QUEUE_SQL.contains("AS checksum_sha256"),
            "the projection must carry the digest column"
        );
        for shortener in ["left(", "LEFT(", "substr", "SUBSTR", "starts_with"] {
            assert!(
                !QUEUE_SQL.contains(shortener),
                "`{shortener}` in the query would shorten a projected value; \
                 the digest is an addressing key and is projected whole"
            );
        }
    }

    // -- severity_from_rank --------------------------------------------------

    #[test]
    fn severity_from_rank_zero_is_none() {
        assert_eq!(severity_from_rank(0), None);
    }

    #[test]
    fn severity_from_rank_one_through_four_map_correctly() {
        assert_eq!(severity_from_rank(1), Some(SeverityThreshold::Low));
        assert_eq!(severity_from_rank(2), Some(SeverityThreshold::Medium));
        assert_eq!(severity_from_rank(3), Some(SeverityThreshold::High));
        assert_eq!(severity_from_rank(4), Some(SeverityThreshold::Critical));
    }

    #[test]
    fn severity_from_rank_out_of_range_is_none() {
        assert_eq!(severity_from_rank(-1), None);
        assert_eq!(severity_from_rank(5), None);
        assert_eq!(severity_from_rank(i16::MAX), None);
        assert_eq!(severity_from_rank(i16::MIN), None);
    }

    // -- i64_finding_count_to_u32 -------------------------------------------

    #[test]
    fn finding_count_zero_round_trips() {
        assert_eq!(i64_finding_count_to_u32(0), 0);
    }

    #[test]
    fn finding_count_negative_clamps_to_zero() {
        assert_eq!(i64_finding_count_to_u32(-1), 0);
        assert_eq!(i64_finding_count_to_u32(i64::MIN), 0);
    }

    #[test]
    fn finding_count_above_u32_max_saturates() {
        assert_eq!(i64_finding_count_to_u32(i64::from(u32::MAX) + 1), u32::MAX);
        assert_eq!(i64_finding_count_to_u32(i64::MAX), u32::MAX);
    }

    #[test]
    fn finding_count_positive_round_trips() {
        assert_eq!(i64_finding_count_to_u32(42), 42);
        assert_eq!(i64_finding_count_to_u32(i64::from(u32::MAX)), u32::MAX);
    }
}
