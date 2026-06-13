//! PostgreSQL adapter for [`CurationDecisionsRepository`].
//!
//! Executes the §2.9 + §3 event-log scan against the live `events`
//! table (and joins to `artifacts` for the `--repository` / `--package`
//! filters that apply to waive/block rows only).
//!
//! ## Per-event-type curator-actor discrimination (load-bearing)
//!
//! The four event types use different discriminator surfaces (design
//! §2.9 + §3):
//!
//! | Event type        | Discriminator surface | JSONB path / column                                  |
//! |-------------------|-----------------------|------------------------------------------------------|
//! | `ArtifactReleased`| Payload-side          | `event_data->'data'->>'released_by' = 'Curator'`     |
//! | `ArtifactRejected`| Payload-side          | `rejected_by` lowercased to `'curator'` (case-symm)  |
//! | `ExclusionAdded`  | Envelope-side         | `actor_type = 'api' AND actor_id IS NOT NULL`        |
//! | `ExclusionRemoved`| Envelope-side         | `actor_type = 'api' AND actor_id IS NOT NULL`        |
//!
//! **Why the split.** `ArtifactReleased.released_by: ReleaseReason`
//! and `ArtifactRejected.rejected_by: RejectionReason` carry the
//! authority distinction in the payload (the variant tag IS the
//! curator/scanner/admin discriminator). `ExclusionAdded` /
//! `ExclusionRemoved` payloads carry NO actor field (see
//! `policy_events.rs`) — actor attribution rides the envelope columns
//! (`actor_type`, `actor_id`) populated on every append. `actor_type
//! = 'api'` excludes `system` / `timer` / `gitops` /
//! `retention_scheduler` internal actors (`004_events.sql`
//! `chk_actor_id`), leaving only API-authenticated callers — the
//! curator/admin surface.
//!
//! **Why not `--actor-kind = 'user'`.** The events table uses
//! `actor_type` (not `actor_kind`); the API-authenticated literal is
//! `'api'` (not `'user'`). Confirmed by reading
//! `migrations/004_events.sql` `chk_actor_id`.
//!
//! ## ArtifactReleased payload-side discriminator
//!
//! The design doc §2.9 references `payload->>'authority' =
//! 'CuratorWaiver'` but the actual `ArtifactReleased` payload has no
//! `authority` field (see `artifact_events.rs:404-418`). The variant
//! tag rides on `released_by: ReleaseReason`, where
//! `ReleaseReason::Curator` is a unit variant → JSONB bare string
//! `"Curator"`. The adapter therefore filters on
//! `event_data->'data'->>'released_by' = 'Curator'` — the actual
//! shape `serialize_event_data` writes (verified against the
//! event_store append path, `mappers.rs:533`).
//!
//! ## ArtifactRejected payload-side discriminator (case-symmetric SQL)
//!
//! Mirrors Item 6's `curation_queue_repository`: the `rejected_by`
//! JSONB key is PascalCase (`{"Curator": {"curator_id": ...}}` for
//! the tuple variant) but the design doc spells the discriminator in
//! lowercase. The adapter applies the same lowercase mapping inline
//! and filters on the mapped value (`= 'curator'`), making the
//! WHERE-clause filter symmetric with the wire format the operator
//! supplies.
//!
//! ## --since / --limit
//!
//! Applied at the SQL level (`stored_at >= $since`, `LIMIT $limit`).
//! `--limit` is clamped to 500 defensively (the use case already
//! validates; the adapter belt-and-braces clamp).
//!
//! ## --repository / --package filters (waive/block only)
//!
//! Per design §2.9 + the task spec, these filters join through to
//! `artifacts` for `ArtifactReleased` / `ArtifactRejected` rows and
//! are no-ops for `ExclusionAdded` / `ExclusionRemoved` rows (those
//! are policy-keyed, not artifact-keyed). The SQL gates the join via
//! event_type so exclude/unexclude rows still surface when a
//! repo/package filter is set.
//!
//! ## --by-correlation
//!
//! NOT a SQL flag. The port always returns one row per event; the
//! HTTP/CLI rendering layer (Items 10 / 13) may collapse by
//! `correlation_id` if asked.
//!
//! See `docs/architecture/how-to/curator-workflow.md` for operator guidance.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::curation_decisions_repository::{
    CurationDecisionEntry, CurationDecisionFilter, CurationDecisionKind,
    CurationDecisionsRepository,
};

use crate::BoxFuture;

/// `limit` hard cap — capped at 500 defensively. The use case validates
/// `> 500` as `AppError::Validation`; the adapter still clamps so a
/// bypass cannot drag the DB through a 10k-row scan.
const MAX_LIMIT: u32 = 500;

/// PostgreSQL adapter for the curation decisions listing.
pub struct PgCurationDecisionsRepository {
    pool: PgPool,
}

impl PgCurationDecisionsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl CurationDecisionsRepository for PgCurationDecisionsRepository {
    fn list_decisions<'a>(
        &'a self,
        filter: CurationDecisionFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<CurationDecisionEntry>>> {
        Box::pin(async move {
            // Clamp limit defensively (use case validates; adapter
            // enforces — same pattern as Item 6).
            let limit = filter.limit.min(MAX_LIMIT);

            // Translate the kind filter to its on-disk discriminator
            // (lowercase wire format, mirroring Item 6's
            // case-symmetric approach). When `None`, the kind filter is
            // bypassed — all four curator event types surface.
            let kind_text: Option<&'static str> = filter.kind.map(kind_to_wire);

            // The §2.9 event-log query.
            //
            // The `decisions` CTE filters the events table to the four
            // curator decision event types AND applies the per-event-
            // type curator-actor discriminator inline. Each row also
            // emits its `kind` discriminator (lowercase wire format)
            // so the optional `--kind` filter can be applied uniformly
            // post-CTE.
            //
            // The artifact join is a `LEFT JOIN` against `artifacts`,
            // resolved via the `stream_id = 'artifact-' || a.id::text`
            // shape (matches Item 6's LATERAL extraction shape). The
            // join is meaningful for ArtifactReleased / ArtifactRejected
            // rows and produces NULL for ExclusionAdded /
            // ExclusionRemoved (those streams are policy-keyed).
            //
            // The exclusion projection LEFT JOIN resolves `cve_id` for
            // ExclusionRemoved rows (whose payload carries only
            // `policy_id` + `exclusion_id`); ExclusionAdded rows read
            // it directly from the payload. The join is best-effort —
            // a removed exclusion may have had its projection dropped
            // (`cve_id` falls back to NULL in that case).
            //
            // Parameters:
            //   $1 = Option<&str>  kind filter (lowercase)
            //   $2 = Option<Uuid>  actor_id filter (envelope)
            //   $3 = Option<Uuid>  repository_id filter (artifact-keyed events only)
            //   $4 = Option<&str>  package filter (artifact-keyed events only)
            //   $5 = Option<DateTime<Utc>>  since (stored_at >= $5)
            //   $6 = i64           limit
            let rows = sqlx::query_as::<_, CurationDecisionRow>(
                r#"
                WITH decisions AS (
                    SELECT
                        e.event_id,
                        e.event_type,
                        e.event_data,
                        e.actor_id,
                        e.correlation_id,
                        e.stored_at,
                        CASE e.event_type
                            WHEN 'ArtifactReleased' THEN 'waive'
                            WHEN 'ArtifactRejected' THEN 'block'
                            WHEN 'ExclusionAdded'   THEN 'exclude_finding'
                            WHEN 'ExclusionRemoved' THEN 'unexclude_finding'
                        END AS kind,
                        -- artifact stream resolver (for the
                        -- LEFT JOIN below). NULL for non-artifact
                        -- streams (policy events).
                        CASE
                            WHEN e.stream_category = 'artifact'
                                THEN substr(e.stream_id, length('artifact-') + 1)::uuid
                            ELSE NULL
                        END AS payload_artifact_id
                    FROM events e
                    WHERE e.event_type IN (
                            'ArtifactReleased',
                            'ArtifactRejected',
                            'ExclusionAdded',
                            'ExclusionRemoved'
                          )
                      AND (
                            -- ArtifactReleased: curator variant tag
                            -- carried in the payload's `released_by`
                            -- field (ReleaseReason::Curator is a unit
                            -- variant → bare-string `"Curator"`).
                            (e.event_type = 'ArtifactReleased'
                             AND e.event_data->'data'->>'released_by' = 'Curator')
                            OR
                            -- ArtifactRejected: curator variant tag
                            -- carried in the payload's `rejected_by`
                            -- field (RejectionReason::Curator is a
                            -- tuple variant → `{"Curator": {...}}`).
                            -- Case-symmetric: lowercase the JSONB key
                            -- inside SQL to match the wire format
                            -- (mirrors Item 6).
                            (e.event_type = 'ArtifactRejected'
                             AND CASE
                                    WHEN jsonb_typeof(e.event_data->'data'->'rejected_by') = 'string'
                                        THEN lower(e.event_data->'data'->>'rejected_by') = 'curator'
                                    WHEN jsonb_typeof(e.event_data->'data'->'rejected_by') = 'object'
                                        THEN lower(
                                            (SELECT k
                                             FROM jsonb_object_keys(e.event_data->'data'->'rejected_by') k
                                             LIMIT 1)
                                        ) = 'curator'
                                    ELSE FALSE
                                 END)
                            OR
                            -- ExclusionAdded / ExclusionRemoved: payloads
                            -- carry NO actor field; attribution rides the
                            -- events envelope. Curator/admin → actor_type
                            -- = 'api' AND actor_id IS NOT NULL.
                            (e.event_type IN ('ExclusionAdded', 'ExclusionRemoved')
                             AND e.actor_type = 'api'
                             AND e.actor_id IS NOT NULL)
                          )
                )
                SELECT
                    d.event_id                          AS event_id,
                    d.kind                              AS kind,
                    d.actor_id                          AS actor_id,
                    -- artifact_id: payload-derived for waive/block,
                    -- NULL for exclude/unexclude.
                    CASE
                        WHEN d.event_type IN ('ArtifactReleased', 'ArtifactRejected')
                            THEN d.payload_artifact_id
                        ELSE NULL
                    END                                 AS artifact_id,
                    -- policy_id: payload-derived for exclude/unexclude,
                    -- NULL for waive/block.
                    CASE
                        WHEN d.event_type IN ('ExclusionAdded', 'ExclusionRemoved')
                            THEN (d.event_data->'data'->>'policy_id')::uuid
                        ELSE NULL
                    END                                 AS policy_id,
                    -- cve_id: ExclusionAdded reads from payload;
                    -- ExclusionRemoved resolves via exclusion_projections
                    -- (best-effort — falls back to NULL if the projection
                    -- has been dropped); NULL for waive/block.
                    CASE
                        WHEN d.event_type = 'ExclusionAdded'
                            THEN d.event_data->'data'->>'cve_id'
                        WHEN d.event_type = 'ExclusionRemoved'
                            THEN ep.cve_id
                        ELSE NULL
                    END                                 AS cve_id,
                    -- justification: per-event-type payload field
                    -- (Released/Rejected use 'justification'/'reason';
                    -- ExclusionAdded/Removed use 'reason'). Falls back
                    -- to the empty string defensively — every curator
                    -- decision has a non-empty justification by
                    -- use-case-level enforcement, but a defensive
                    -- COALESCE prevents NULL surfacing.
                    COALESCE(
                        d.event_data->'data'->>'justification',
                        d.event_data->'data'->>'reason',
                        ''
                    )                                   AS justification,
                    d.correlation_id                    AS correlation_id,
                    d.stored_at                         AS occurred_at
                FROM decisions d
                LEFT JOIN artifacts a
                       ON d.event_type IN ('ArtifactReleased', 'ArtifactRejected')
                      AND d.payload_artifact_id IS NOT NULL
                      AND a.id = d.payload_artifact_id
                LEFT JOIN exclusion_projections ep
                       ON d.event_type = 'ExclusionRemoved'
                      AND ep.exclusion_id = (d.event_data->'data'->>'exclusion_id')::uuid
                WHERE ($1::text IS NULL OR d.kind = $1)
                  AND ($2::uuid IS NULL OR d.actor_id = $2)
                  -- Repository filter: applies ONLY to artifact-keyed
                  -- rows (Waive/Block). Exclude/Unexclude rows surface
                  -- regardless when the filter is set (policy-keyed,
                  -- not artifact-keyed — design §2.9).
                  AND ($3::uuid IS NULL
                       OR d.event_type IN ('ExclusionAdded', 'ExclusionRemoved')
                       OR a.repository_id = $3)
                  -- Package filter: same shape as repository — no-op
                  -- for exclude/unexclude rows.
                  AND ($4::text IS NULL
                       OR d.event_type IN ('ExclusionAdded', 'ExclusionRemoved')
                       OR a.name = $4)
                  AND ($5::timestamptz IS NULL OR d.stored_at >= $5)
                ORDER BY d.stored_at DESC
                LIMIT $6
                "#,
            )
            .bind(kind_text)
            .bind(filter.actor_id)
            .bind(filter.repository_id)
            .bind(filter.package.as_deref())
            .bind(filter.since)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DomainError::Invariant(format!("curation_decisions_repo list: {e}")))?;

            rows.into_iter()
                .map(CurationDecisionRow::into_domain)
                .collect()
        })
    }
}

/// Mapping from [`CurationDecisionKind`] to the lowercase wire-format
/// discriminator the SQL `kind` column emits. Mirrors Item 6's
/// case-symmetric approach.
fn kind_to_wire(kind: CurationDecisionKind) -> &'static str {
    match kind {
        CurationDecisionKind::Waive => "waive",
        CurationDecisionKind::Block => "block",
        CurationDecisionKind::ExcludeFinding => "exclude_finding",
        CurationDecisionKind::UnexcludeFinding => "unexclude_finding",
    }
}

/// Inverse of [`kind_to_wire`]. Returns `Err(DomainError::Invariant)`
/// on an unknown discriminator — defensive, mirrors Item 6 strict
/// row-mapping.
fn kind_from_wire(raw: &str) -> DomainResult<CurationDecisionKind> {
    match raw {
        "waive" => Ok(CurationDecisionKind::Waive),
        "block" => Ok(CurationDecisionKind::Block),
        "exclude_finding" => Ok(CurationDecisionKind::ExcludeFinding),
        "unexclude_finding" => Ok(CurationDecisionKind::UnexcludeFinding),
        other => Err(DomainError::Invariant(format!(
            "unknown curation decision kind in row: {other}"
        ))),
    }
}

/// sqlx FromRow shape mirroring the §2.9 projection.
#[derive(sqlx::FromRow)]
struct CurationDecisionRow {
    event_id: Uuid,
    kind: String,
    actor_id: Option<Uuid>,
    artifact_id: Option<Uuid>,
    policy_id: Option<Uuid>,
    cve_id: Option<String>,
    justification: String,
    correlation_id: Uuid,
    occurred_at: DateTime<Utc>,
}

impl CurationDecisionRow {
    fn into_domain(self) -> DomainResult<CurationDecisionEntry> {
        let kind = kind_from_wire(&self.kind)?;

        // The CTE's per-event-type discriminator pins actor_id to
        // non-NULL for ExclusionAdded/Removed (actor_type='api' AND
        // actor_id IS NOT NULL), and ArtifactReleased/Rejected events
        // are always emitted via the API actor path (CurationUseCase
        // wraps Actor::Api on every commit_transition_with_score
        // call — see curation_use_case.rs::waive / ::block_one). A
        // NULL actor_id surfacing here would indicate either a
        // gitops/system-driven exclusion (filtered out by the CTE) or
        // a future code path that bypasses the standard envelope —
        // either way, an invariant violation on the curator-decisions
        // surface. Strict mapping mirrors Item 6.
        let actor_id = self.actor_id.ok_or_else(|| {
            DomainError::Invariant(format!(
                "curation_decisions_repo row {} has NULL actor_id (CTE invariant violated)",
                self.event_id
            ))
        })?;

        Ok(CurationDecisionEntry {
            event_id: self.event_id,
            kind,
            actor_id,
            artifact_id: self.artifact_id,
            policy_id: self.policy_id,
            cve_id: self.cve_id,
            justification: self.justification,
            correlation_id: self.correlation_id,
            occurred_at: self.occurred_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that the adapter implements the port.
    /// Mirrors `patch_candidate_repo::tests::pg_adapter_implements_port`.
    #[test]
    fn pg_adapter_implements_port() {
        fn assert_impl<T: CurationDecisionsRepository>() {}
        assert_impl::<PgCurationDecisionsRepository>();
    }

    // -- kind_to_wire / kind_from_wire round-trip ----------------------------

    #[test]
    fn kind_to_wire_round_trips_for_all_variants() {
        for k in [
            CurationDecisionKind::Waive,
            CurationDecisionKind::Block,
            CurationDecisionKind::ExcludeFinding,
            CurationDecisionKind::UnexcludeFinding,
        ] {
            let wire = kind_to_wire(k);
            assert_eq!(kind_from_wire(wire).expect("round trip"), k);
        }
    }

    #[test]
    fn kind_to_wire_spelling_is_lowercase_snake_case() {
        // Pin the wire format (the same strings the HTTP query param
        // `?type=...` and the `hort-cli --type ...` flag accept per
        // design §2.7).
        assert_eq!(kind_to_wire(CurationDecisionKind::Waive), "waive");
        assert_eq!(kind_to_wire(CurationDecisionKind::Block), "block");
        assert_eq!(
            kind_to_wire(CurationDecisionKind::ExcludeFinding),
            "exclude_finding"
        );
        assert_eq!(
            kind_to_wire(CurationDecisionKind::UnexcludeFinding),
            "unexclude_finding"
        );
    }

    #[test]
    fn kind_from_wire_unknown_is_invariant_error() {
        let err = kind_from_wire("future_decision").expect_err("unknown kind must error");
        match err {
            DomainError::Invariant(msg) => assert!(msg.contains("future_decision")),
            other => panic!("expected Invariant, got: {other:?}"),
        }
    }
}
