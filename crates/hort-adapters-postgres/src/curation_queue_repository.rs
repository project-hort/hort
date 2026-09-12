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
//! `corruption` is deliberately absent: it rides the separate
//! `ArtifactCorrupted` event, whose tag is not `ArtifactRejected`, so the
//! LATERAL never sees it. Only `RejectionReason` discriminators appear
//! here; a corruption discriminator would need a separate source.
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
///   inline mapping.
/// - `LEFT JOIN` for findings + LATERAL so a row with no findings and no
///   rejection event still surfaces (e.g. `scan_indeterminate` rows).
/// - `$1` = optional repository_id, `$2` = optional status text,
///   `$3` = optional rejection_reason_kind, `$4` = limit i64.
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
                          WHERE quarantine_status IN ('quarantined','rejected','scan_indeterminate')) a
                )
                SELECT
                    a.id                        AS artifact_id,
                    a.repository_id             AS repository_id,
                    r.key                       AS repository_key,
                    r.format::text              AS format,
                    a.name                      AS package_name,
                    a.version                   AS version,
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
                WHERE a.quarantine_status IN ('quarantined','rejected','scan_indeterminate')
                  AND ($1::uuid IS NULL OR a.repository_id = $1)
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
    quarantine_status: Option<String>,
    quarantine_window_start: Option<DateTime<Utc>>,
    quarantine_deadline: Option<DateTime<Utc>>,
    finding_count: i64,
    max_severity_rank: Option<i16>,
    rejection_reason_kind_raw: Option<String>,
}

impl CurationQueueRow {
    fn into_domain(self) -> DomainResult<CurationQueueEntry> {
        // The outer status filter pins this to a non-NULL set, but the
        // schema permits NULL — so the `None` arm exists as
        // defence-in-depth (mirrors `patch_candidate_repo` strict
        // mapping). Drift in the SQL WHERE clause surfaces as
        // `DomainError::Invariant`.
        let quarantine_status = match self.quarantine_status.as_deref() {
            Some(s) => s.parse::<QuarantineStatus>().map_err(|_| {
                DomainError::Invariant(format!(
                    "unknown quarantine_status in curation_queue_repo row: {s}"
                ))
            })?,
            None => {
                return Err(DomainError::Invariant(format!(
                    "curation_queue_repo row {} has NULL quarantine_status",
                    self.artifact_id
                )));
            }
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

        Ok(CurationQueueEntry {
            artifact_id: self.artifact_id,
            repository_id: self.repository_id,
            repository_key: self.repository_key,
            format,
            package_name: self.package_name,
            version: self.version,
            quarantine_status,
            quarantine_window_start: self.quarantine_window_start,
            quarantine_deadline: self.quarantine_deadline,
            finding_count: i64_finding_count_to_u32(self.finding_count),
            max_severity: self.max_severity_rank.and_then(severity_from_rank),
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
