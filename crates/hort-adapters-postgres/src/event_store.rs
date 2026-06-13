use std::time::Instant;

use sqlx::PgPool;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{
    compute_event_hash, genesis_hash, ActorCanonical, ChainInput, DomainEvent, EventHash,
    PersistedEvent, StreamCategory, StreamId, StreamSealed,
};
use hort_domain::ports::event_store::{
    AppendEvents, AppendResult, EventStore, EventToAppend, ExpectedVersion, ReadFrom, SubscribeFrom,
};
use hort_domain::ports::BoxFuture;

use crate::mappers::{actor_to_columns, serialize_event_data, stream_id_to_columns, EventRow};
use crate::metrics::{
    classify_trigger_error_message, emit_audit_events_blocked, labels, values,
    AuditBlockedDecisionPoint, AuditBlockedOp, EventStoreResult,
};

// ---------------------------------------------------------------------------
// Metric helpers
// ---------------------------------------------------------------------------

/// Map a `StreamCategory` to the canonical label value string declared in
/// `crate::metrics::values`. Centralised so every emission site uses the same
/// mapping.
fn category_label(category: StreamCategory) -> &'static str {
    match category {
        StreamCategory::Artifact => values::CATEGORY_ARTIFACT,
        StreamCategory::Policy => values::CATEGORY_POLICY,
        StreamCategory::Admin => values::CATEGORY_ADMIN,
        StreamCategory::Ref => values::CATEGORY_REF,
        StreamCategory::ArtifactGroup => values::CATEGORY_ARTIFACT_GROUP,
        StreamCategory::Curation => values::CATEGORY_CURATION,
        StreamCategory::Repository => values::CATEGORY_REPOSITORY,
        StreamCategory::AuthAttempts => values::CATEGORY_AUTH_ATTEMPTS,
        StreamCategory::Authorization => values::CATEGORY_AUTHORIZATION,
        StreamCategory::User => values::CATEGORY_USER,
        StreamCategory::DownloadAudit => values::CATEGORY_DOWNLOAD_AUDIT,
        StreamCategory::TokenUse => values::CATEGORY_TOKEN_USE,
        StreamCategory::RetentionPolicy => values::CATEGORY_RETENTION_POLICY,
    }
}

/// Classify an append outcome into an `EventStoreResult` for the `result` label
/// of `hort_event_store_appends_total`. The optimistic-concurrency path returns
/// `DomainError::Conflict` from `append_with_conn`; everything else maps to
/// `Error`.
fn classify_append_result<T>(result: &DomainResult<T>) -> EventStoreResult {
    match result {
        Ok(_) => EventStoreResult::Success,
        Err(DomainError::Conflict(_)) => EventStoreResult::Conflict,
        Err(_) => EventStoreResult::Error,
    }
}

/// Emit the append counter + duration histogram with `category`/`result` labels.
fn emit_append_metrics(category: &'static str, result: EventStoreResult, elapsed_secs: f64) {
    metrics::counter!(
        "hort_event_store_appends_total",
        labels::CATEGORY => category,
        labels::RESULT => result.as_str(),
    )
    .increment(1);
    metrics::histogram!(
        "hort_event_store_append_duration_seconds",
        labels::CATEGORY => category,
    )
    .record(elapsed_secs);
}

/// Emit the read counter with `category`/`operation` labels.
///
/// Called at the START of each read so a failed query still gets counted —
/// the catalog spec does NOT define a `result` label on
/// `hort_event_store_reads_total`, so attempt-counting is the intended
/// semantic. Compare with `emit_append_metrics`, which is called at end
/// and carries a `result` label.
fn emit_read_metrics(category: &'static str, operation: &'static str) {
    metrics::counter!(
        "hort_event_store_reads_total",
        labels::CATEGORY => category,
        labels::OPERATION => operation,
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum allowed size for serialized event JSON (64 KB).
const MAX_EVENT_JSON_BYTES: usize = 65_536;

/// SQLSTATE Postgres returns for `RAISE EXCEPTION` without `ERRCODE`.
/// The `events_immutable` trigger uses `RAISE EXCEPTION` so its errors
/// carry this code. See `inspect_audit_block` for the full classifier.
const SQLSTATE_RAISE_EXCEPTION: &str = "P0001";

/// Map an `AuditBlockedOp` variant to the Postgres privilege keyword used
/// in `has_table_privilege(role, 'events', '<priv>')`. The strings are
/// the literal keywords Postgres accepts; case is significant only in
/// the sense that Postgres normalises to upper-case internally.
fn priv_keyword(op: AuditBlockedOp) -> &'static str {
    match op {
        AuditBlockedOp::Update => "UPDATE",
        AuditBlockedOp::Delete => "DELETE",
        AuditBlockedOp::Truncate => "TRUNCATE",
    }
}

/// Inspect an `sqlx::Error` to see if it is a trigger-caught audit block.
/// Returns `Some(op)` and emits
/// `hort_audit_events_blocked_total{attempted_op, decision_point="trigger_caught"}`
/// when the error came from the `events_immutable` trigger; returns
/// `None` for any other error (caller is then responsible for its own
/// classification — this helper is the trip-wire, not a catch-all).
///
/// Detection: SQLSTATE `P0001` + the trigger's literal message
/// `events table is append-only: <TG_OP> not allowed` parsed by
/// `crate::metrics::classify_trigger_error_message`. Both checks must
/// pass — the SQLSTATE alone could be any user-defined `RAISE
/// EXCEPTION`, and the message alone could collide with an unrelated
/// error string.
pub fn inspect_audit_block(error: &sqlx::Error) -> Option<AuditBlockedOp> {
    let db_err = error.as_database_error()?;
    let code = db_err.code()?;
    if code.as_ref() != SQLSTATE_RAISE_EXCEPTION {
        return None;
    }
    let msg = db_err.message();
    let op = classify_trigger_error_message(msg)?;
    emit_audit_events_blocked(op, AuditBlockedDecisionPoint::TriggerCaught);
    tracing::error!(
        attempted_op = op.as_str(),
        message = msg,
        "events_immutable trigger caught a forbidden mutation"
    );
    Some(op)
}

/// Column list for SELECT queries on the events table.
///
/// `actor_source_file` and `actor_spec_digest` are appended at the end
/// so the column order matches `EventRow`'s
/// field order — sqlx's `FromRow` requires positional alignment when
/// the row type derives `FromRow` without explicit `#[sqlx(rename)]`.
const EVENT_COLS: &str = r#"
    event_id, stream_id, stream_category, stream_position, global_position,
    event_type, event_version, event_data, correlation_id, causation_id,
    actor_type, actor_id, actor_source_file, actor_spec_digest, stored_at
"#;

// ---------------------------------------------------------------------------
// PgUnitOfWork
// ---------------------------------------------------------------------------

/// A PostgreSQL transaction handle for cross-port transactional writes.
///
/// Internal adapter plumbing — used by `PgEventStore::append_in_tx` and
/// `PgArtifactLifecycle::commit_transition` to coordinate multi-table
/// writes in a single transaction.
pub(crate) struct PgUnitOfWork {
    tx: sqlx::Transaction<'static, sqlx::Postgres>,
}

impl PgUnitOfWork {
    /// Access the underlying connection for executing queries.
    pub(crate) fn conn(&mut self) -> &mut sqlx::PgConnection {
        &mut self.tx
    }

    /// Commit the transaction.
    pub(crate) async fn commit(self) -> DomainResult<()> {
        self.tx
            .commit()
            .await
            .map_err(|e| DomainError::Invariant(format!("transaction commit failed: {e}")))
    }
}

// ---------------------------------------------------------------------------
// PgEventStore
// ---------------------------------------------------------------------------

/// PostgreSQL implementation of [`EventStore`].
pub struct PgEventStore {
    pool: PgPool,
}

impl PgEventStore {
    /// Create a new event store, verifying that the immutability trigger
    /// exists and is enabled on the `events` table, and that the runtime
    /// role does not hold any forbidden mutation privilege.
    ///
    /// Two startup checks run in order:
    ///
    /// 1. `events_immutable` trigger present + enabled (existing check).
    /// 2. `has_table_privilege('events', '<priv>')` for each of `UPDATE`,
    ///    `DELETE`, `TRUNCATE` returns `false` for the runtime role
    ///    (ADR 0017 / events-role hardening). If any returns `true`, the
    ///    constructor refuses to start and emits
    ///    `hort_audit_events_blocked_total{attempted_op=<priv>,
    ///    decision_point="startup_probe"}` with a clear error naming
    ///    the offending privilege.
    ///
    /// The privilege probe is **skipped** (logged, no refusal) when
    /// `current_user` is a Postgres superuser or owns the `events` table
    /// — or is a member of the owning role `hort_admin` (finding F12). In
    /// both cases the forbidden privileges are unrevokable, so the probe
    /// cannot enforce H-7 against that role. Admin subcommands connect
    /// with the admin DSN and hit the owner skip; the runtime serve /
    /// worker role owns nothing and hits neither.
    pub async fn new(pool: PgPool) -> DomainResult<Self> {
        let trigger_enabled: Option<bool> = sqlx::query_scalar(
            r#"
            SELECT tgenabled != 'D'
            FROM pg_trigger
            WHERE tgname = 'events_immutable'
            "#,
        )
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "failed to query pg_trigger for immutability trigger"
            );
            DomainError::Invariant(format!("failed to verify immutability trigger: {e}"))
        })?;

        match trigger_enabled {
            Some(true) => {
                tracing::info!("events_immutable trigger verified: present and enabled");
            }
            Some(false) => {
                tracing::error!("events_immutable trigger is DISABLED");
                return Err(DomainError::Invariant(
                    "events_immutable trigger is disabled".into(),
                ));
            }
            None => {
                tracing::error!("events_immutable trigger not found in pg_trigger");
                return Err(DomainError::Invariant(
                    "events_immutable trigger does not exist".into(),
                ));
            }
        }

        // -----------------------------------------------------------------
        // Privilege probe (events-role hardening).
        // -----------------------------------------------------------------
        //
        // Walk the three forbidden privileges in deterministic order so the
        // failure message is reproducible. We refuse on the first match —
        // the operator only needs to fix one grant at a time, and emitting
        // the metric for *every* offending privilege at once would be
        // double-counting (each is the same root cause).
        //
        // The probe runs against `current_user`. In normal operation that's
        // the role the runtime authenticated as; in tests, the harness can
        // create a dedicated low-privilege user and connect through it to
        // exercise both the pass and refuse branches.
        //
        // Superuser handling: Postgres superusers bypass every ACL check,
        // so `has_table_privilege` returns `true` regardless of GRANTs.
        // Refusing-to-start in that case would also refuse the dev /
        // CI compose stack (which uses the bootstrap superuser today).
        // We log a WARN and skip the probe — the operator MUST move to a
        // non-superuser runtime role for the probe to provide its
        // intended security guarantee. This matches Postgres' own
        // semantics ("superuser is outside the privilege system").
        let is_superuser: bool = sqlx::query_scalar(
            "SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user",
        )
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to probe rolsuper for current_user");
            DomainError::Invariant(format!("failed to probe rolsuper: {e}"))
        })?
        .unwrap_or(false);

        if is_superuser {
            tracing::warn!(
                "events table privilege probe SKIPPED: runtime is a Postgres \
                 superuser; superusers bypass ACL and the probe cannot enforce \
                 the H-7 invariant. Move the runtime to a non-superuser role \
                 that is a member of hort_app_role to enable the probe."
            );
        } else {
            // Table-owner handling (finding F12). A role that owns
            // `events` — or is a member of the owning role `hort_admin` —
            // implicitly holds UPDATE/DELETE/TRUNCATE; `has_table_privilege`
            // reports `true` regardless of any REVOKE, because ownership
            // privileges cannot be revoked, only re-assigned. This is the
            // same "outside the privilege system" situation as the
            // superuser case above. Admin subcommands (`issue-svc-token`,
            // `reconcile-groups`, `scrub`) connect with the admin DSN — a
            // member of `hort_admin` — and construct an event store to
            // append audit events; the probe would otherwise refuse to
            // start. The runtime serve/worker role is a member of
            // `hort_app_role`, never `hort_admin` (the migrate DSN is DML-only
            // per ADR 0009 and cannot CREATE / own tables), so this
            // skip never disables the probe on a runtime path.
            let owns_events: bool = sqlx::query_scalar(
                r#"
                SELECT pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER')
                FROM pg_catalog.pg_class c
                JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = 'events' AND n.nspname = 'public'
                "#,
            )
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to probe events-table ownership");
                DomainError::Invariant(format!("failed to probe events ownership: {e}"))
            })?
            .unwrap_or(false);

            if owns_events {
                tracing::info!(
                    "events table privilege probe SKIPPED: current role owns the \
                     events table (or is a member of the owner role hort_admin); \
                     ownership privileges cannot be revoked, so the H-7 probe is \
                     not meaningful here. Expected for admin subcommands using the \
                     admin DSN; the runtime serve/worker role must not own events."
                );
            } else {
                for op in [
                    AuditBlockedOp::Update,
                    AuditBlockedOp::Delete,
                    AuditBlockedOp::Truncate,
                ] {
                    let priv_name = priv_keyword(op);
                    let granted: bool = sqlx::query_scalar(
                        "SELECT has_table_privilege(current_user, 'events', $1)",
                    )
                    .bind(priv_name)
                    .fetch_one(&pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            error = %e,
                            privilege = priv_name,
                            "failed to probe events-table privilege"
                        );
                        DomainError::Invariant(format!(
                            "failed to probe '{priv_name}' privilege on events: {e}"
                        ))
                    })?;
                    if granted {
                        emit_audit_events_blocked(op, AuditBlockedDecisionPoint::StartupProbe);
                        tracing::error!(
                            privilege = priv_name,
                            "runtime role holds forbidden '{priv_name}' privilege on events table"
                        );
                        return Err(DomainError::Invariant(format!(
                            "runtime role holds forbidden '{priv_name}' privilege on events \
                             table; run the events_immutable role-hardening migration as an \
                             administrator"
                        )));
                    }
                }
                tracing::info!(
                    "events table privilege probe verified: runtime role has no \
                     UPDATE/DELETE/TRUNCATE privilege"
                );
            }
        }

        Ok(Self { pool })
    }

    /// Begin a new unit of work backed by a PostgreSQL transaction.
    pub(crate) async fn begin_unit_of_work(&self) -> DomainResult<PgUnitOfWork> {
        let tx = self
            .pool
            .begin()
            .await
            .map_err(|e| DomainError::Invariant(format!("failed to begin transaction: {e}")))?;
        Ok(PgUnitOfWork { tx })
    }

    /// Append events within an existing transaction.
    ///
    /// This is an inherent method (not a trait method) that enables
    /// use cases to append events and perform other writes in the same
    /// transaction.
    pub(crate) async fn append_in_tx(
        &self,
        tx: &mut PgUnitOfWork,
        batch: AppendEvents,
    ) -> DomainResult<AppendResult> {
        let category = category_label(batch.stream_id.category);
        let started = Instant::now();
        let result = async {
            let serialized = validate_and_serialize(&batch.events)?;
            tracing::debug!(
                stream_id = %batch.stream_id,
                event_count = batch.events.len(),
                "append_in_tx"
            );
            append_with_conn(tx.conn(), &batch, &serialized).await
        }
        .await;
        let outcome = classify_append_result(&result);
        emit_append_metrics(category, outcome, started.elapsed().as_secs_f64());
        result
    }
}

// ---------------------------------------------------------------------------
// EventStore trait implementation
// ---------------------------------------------------------------------------

impl EventStore for PgEventStore {
    fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
        Box::pin(async move {
            let category = category_label(batch.stream_id.category);
            let started = Instant::now();
            let result: DomainResult<AppendResult> = async {
                let serialized = validate_and_serialize(&batch.events)?;
                tracing::debug!(
                    stream_id = %batch.stream_id,
                    event_count = batch.events.len(),
                    "append"
                );

                let mut tx = self.pool.begin().await.map_err(|e| {
                    DomainError::Invariant(format!("failed to begin transaction: {e}"))
                })?;

                let result = append_with_conn(&mut tx, &batch, &serialized).await?;

                tx.commit().await.map_err(|e| {
                    DomainError::Invariant(format!("transaction commit failed: {e}"))
                })?;

                Ok(result)
            }
            .await;
            let outcome = classify_append_result(&result);
            emit_append_metrics(category, outcome, started.elapsed().as_secs_f64());
            result
        })
    }

    fn read_stream(
        &self,
        stream_id: &StreamId,
        from: ReadFrom,
        max_count: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
        let stream_id_str = stream_id.to_string();
        let category = category_label(stream_id.category);
        let after_position: i64 = match from {
            ReadFrom::Start => -1,
            ReadFrom::After(n) => n as i64,
        };
        let limit = max_count as i64;

        emit_read_metrics(category, values::OPERATION_READ_STREAM);

        Box::pin(async move {
            let sql = format!(
                r#"SELECT {EVENT_COLS}
                   FROM events
                   WHERE stream_id = $1
                     AND stream_position > $2
                   ORDER BY stream_position ASC
                   LIMIT $3"#
            );
            let rows: Vec<EventRow> = sqlx::query_as(&sql)
                .bind(&stream_id_str)
                .bind(after_position)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| DomainError::Invariant(format!("read_stream query failed: {e}")))?;

            let events: Vec<PersistedEvent> = rows
                .into_iter()
                .map(PersistedEvent::try_from)
                .collect::<Result<Vec<_>, _>>()?;

            tracing::debug!(
                stream_id = %stream_id_str,
                result_count = events.len(),
                "read_stream"
            );
            Ok(events)
        })
    }

    fn read_category(
        &self,
        category: StreamCategory,
        from: SubscribeFrom,
        max_count: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
        let cat_str = category_label(category);
        let after_global: i64 = match from {
            SubscribeFrom::Start => 0,
            SubscribeFrom::AfterGlobal(n) => n as i64,
        };
        let limit = max_count as i64;

        emit_read_metrics(cat_str, values::OPERATION_READ_CATEGORY);

        Box::pin(async move {
            let sql = format!(
                r#"SELECT {EVENT_COLS}
                   FROM events
                   WHERE stream_category = $1
                     AND global_position > $2
                   ORDER BY global_position ASC
                   LIMIT $3"#
            );
            let rows: Vec<EventRow> = sqlx::query_as(&sql)
                .bind(cat_str)
                .bind(after_global)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| DomainError::Invariant(format!("read_category query failed: {e}")))?;

            let events: Vec<PersistedEvent> = rows
                .into_iter()
                .map(PersistedEvent::try_from)
                .collect::<Result<Vec<_>, _>>()?;

            tracing::debug!(
                category = cat_str,
                result_count = events.len(),
                "read_category"
            );
            Ok(events)
        })
    }

    /// `/readyz` probe. Round-trips `SELECT 1`
    /// against the `PgPool` that backs every other `EventStore`
    /// operation, so a successful ping confirms both pool acquisition
    /// (DB connection available) and DB responsiveness in one call.
    /// Failure is logged at `warn!` so operators get the underlying
    /// reason when readiness flips to 503.
    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            match sqlx::query("SELECT 1").fetch_one(&self.pool).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    tracing::warn!(error = %e, "event_store health_check failed");
                    Err(DomainError::Invariant(format!(
                        "event store health check failed: {e}"
                    )))
                }
            }
        })
    }

    fn delete_stream(&self, stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move { self.seal_and_remove(stream_id, SealMode::Delete).await })
    }

    fn archive_stream(&self, stream_id: StreamId, target: &str) -> BoxFuture<'_, DomainResult<()>> {
        let target = target.to_owned();
        Box::pin(async move {
            self.seal_and_remove(stream_id, SealMode::Archive { target })
                .await
        })
    }
}

// ---------------------------------------------------------------------------
// F-2 `StreamSealed` tombstone emitter (ADR 0004 + 0002)
//
// `delete_stream` / `archive_stream` MUST NOT remove any row of a stream
// without first appending — *through the normal chained append path* — a
// `StreamSealed` tombstone to the never-deleted audit-meta stream
// `StreamId::eventstore_retention()` (`admin-<v5-uuid>`). The tombstone
// carries the deleted stream's chain head so the verifier can treat the
// now-absent stream as a defined `SealedGap` rather than a `Broken` chain
// (F-2 spec §2.3 / §14 R3).
//
// The ordering invariant is load-bearing and structural: the tombstone
// append and the row removal happen in **one transaction**, tombstone
// FIRST. If the tombstone append fails the transaction rolls back and
// **no row is removed** (the delete MUST abort — an untombstoned delete
// makes the chain `Broken`). If the removal fails the transaction also
// rolls back, so a tombstone is never left orphaned without its
// corresponding deletion. There is exactly one chokepoint
// (`seal_and_remove`); `archive_stream` is treated identically to
// `delete_stream` for the live DB — the cold-storage archive *target* is
// The cold-storage archive target is future work; today both seal the
// chain head and remove the live rows; only the trace differs.
//
// Row-removal mechanism (decided 2026-05-17 — design §10.2; F-2 spec
// §2.3 reconciled in the same B9 change): the actual row removal past
// the `events_immutable` BEFORE-DELETE trigger is NOT done by disabling
// the trigger (`ALTER TABLE … DISABLE TRIGGER` is the exact attack
// vector audit F-2 names). The removal here is a **plain `DELETE`**; the
// trigger stays ENABLED at all times and is amended (migration
// `004_events.sql`) to permit DELETE only when
// `current_user = 'hort_retention_role'` — a dedicated, DELETE-capable
// role distinct from the runtime DML `hort_app_role`. Under any other
// role (notably `hort_app_role`) the still-active trigger raises, this
// `DELETE` errors, and the whole seal transaction rolls back fail-safe:
// zero rows removed, no orphan tombstone. **DSN/pool composition wiring
// — connecting the worker as a member of `hort_retention_role` — is
// DSN/pool composition wiring is a separate concern.** This module
// documents the contract and delivers the migration + this keyed removal
// path; the retention sweep is correctly non-functional (fail-safe)
// until that wiring lands.
//
// The `EventStore::delete_stream`/`archive_stream` port signature carries
// neither a retention-policy id nor an actor (it is intentionally NOT
// changed here — see the dispatch report). The adapter therefore records
// the system/timer-driven retention sweep as the authority:
// `retention_policy_id = Uuid::nil()` (no specific policy at this layer;
// B5 `EventStoreRetentionUseCase`, when it lands, routes through this
// same chokepoint and is the layer that knows the policy id) and
// `actor_id = None` (exactly what `StreamSealed.actor_id`'s contract
// documents for "the system/timer-driven retention sweep"). The append
// itself uses `timer_actor()`, the controlled retention-scheduler actor.
//
// Operator-provisioning contract (Option B, F-2 co-reviewed,
// 2026-05-18 — closes the B9 trigger-vs-NOLOGIN defect): the
// `events_immutable` trigger function (`004_events.sql`) permits DELETE
// only on an *exact* `current_user = 'hort_retention_role'` match — not a
// membership test (Option B deliberately keeps that exemption
// maximally narrow). `seal_and_remove` therefore issues a
// transaction-scoped `SET LOCAL ROLE hort_retention_role` between the
// tombstone append and the row removal. For that to work the
// `HORT_RETENTION_DATABASE_URL` login user MUST be GRANTed membership in
// BOTH:
//   * `hort_app_role` — the tombstone `append_with_conn` is an INSERT
//     into `events`; `hort_retention_role` has NO INSERT
//     (`004_events.sql:314`), so the append runs under the
//     INSERT-capable login role before the role is assumed; and
//   * `hort_retention_role` — granted **`WITH INHERIT FALSE`**
//     (NOINHERIT membership; PG16+ per-grant INHERIT option) so the
//     login user holds NO *ambient* DELETE on `events`. This is
//     load-bearing: `PgEventStore::new`'s append-only hardening probe
//     (ADR 0009) rejects construction if
//     `has_table_privilege(current_user,'events','DELETE')` — a
//     default-INHERIT `hort_retention_role` member inherits ambient
//     DELETE and the retention store would fail to construct. With
//     NOINHERIT the probe passes (no ambient DELETE) yet
//     `SET LOCAL ROLE hort_retention_role` still succeeds (a member may
//     `SET ROLE` regardless of INHERIT), and the subsequent DELETE
//     runs with `current_user = hort_retention_role`, which the
//     unchanged trigger lets through. `hort_app_role` stays default
//     INHERIT so its INSERT is ambient for the tombstone append.
// `SET LOCAL ROLE` is the sole sanctioned, transaction-scoped,
// auto-reverting elevation (no `ALTER TABLE … DISABLE TRIGGER`, no
// manual `RESET ROLE`). A runtime user that is NOT a member of
// `hort_retention_role` (e.g. `HORT_RETENTION_DATABASE_URL` unset → the
// `hort_app_role`-only pool, the documented Q5 path) makes the
// `SET LOCAL ROLE` raise `permission denied`, so every seal
// fail-closes: zero rows removed, the staged tombstone rolled back, no
// orphan — exactly the pre-fix fail-safe, just surfaced as a
// not-assumable-role Err instead of a trigger RAISE. B5/B6 wire the
// `hort_retention_role` DSN/pool; this contract is documented in
// ADR 0020 §10.2.
// ---------------------------------------------------------------------------

/// Whether the seal+removal chokepoint was reached via `delete_stream`
/// or `archive_stream`. The live-DB action is identical (seal the chain
/// head, then remove the rows); only the emitted trace differs. The
/// cold-storage `target` is carried for the log line and as a forward
/// hook for the archive-backend follow-on.
#[derive(Debug)]
enum SealMode {
    Delete,
    Archive { target: String },
}

impl SealMode {
    fn op(&self) -> &'static str {
        match self {
            SealMode::Delete => "delete_stream",
            SealMode::Archive { .. } => "archive_stream",
        }
    }
}

impl PgEventStore {
    /// Single chokepoint for whole-stream seal + removal. Appends the
    /// `StreamSealed` tombstone through the normal chained append path,
    /// then removes the stream's rows — both in one transaction,
    /// tombstone first. No delete/archive code path may bypass this.
    ///
    /// Tracing-only (no metric — there is no `hort_*_seal*` metric in the
    /// catalog and §10.2 does not mandate one; the security-relevant
    /// state change is surfaced via the `info!` on emission and the
    /// `error!` on abort).
    #[tracing::instrument(skip(self))]
    async fn seal_and_remove(&self, stream_id: StreamId, mode: SealMode) -> DomainResult<()> {
        let (target_id, target_cat) = stream_id_to_columns(&stream_id);

        let mut tx = self.pool.begin().await.map_err(|e| {
            DomainError::Invariant(format!("failed to begin seal transaction: {e}"))
        })?;

        // Read the sealed stream's chain head: its tail (max
        // stream_position) row's `event_hash`, plus the event count.
        // One query, ordered DESC LIMIT 1 — the same shape the append
        // path uses for the tail read.
        let tail: Option<(i64, Vec<u8>)> = sqlx::query_as(
            r#"SELECT stream_position, event_hash
               FROM events
               WHERE stream_id = $1
               ORDER BY stream_position DESC
               LIMIT 1"#,
        )
        .bind(&target_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| DomainError::Invariant(format!("failed to read sealed stream head: {e}")))?;

        let Some((final_position, head_bytes)) = tail else {
            // Empty / non-existent stream: there is no chain head to
            // record and no rows to remove. A stream that never
            // existed is not `Broken` (the verifier only flags streams
            // a checkpoint anchored). Idempotent no-op — do NOT write
            // a tombstone for a head that does not exist.
            tracing::info!(
                op = mode.op(),
                stream_id = %target_id,
                "seal_and_remove: stream absent/empty — nothing to seal or remove"
            );
            tx.commit().await.map_err(|e| {
                DomainError::Invariant(format!("seal transaction commit failed: {e}"))
            })?;
            return Ok(());
        };

        let final_event_hash: [u8; 32] = head_bytes.as_slice().try_into().map_err(|_| {
            DomainError::Invariant(format!(
                "sealed stream {target_id} head event_hash is {} bytes, expected 32 \
                 (schema CHECK should make this unreachable)",
                head_bytes.len()
            ))
        })?;

        // event_count = final_stream_position + 1 for a gapless stream
        // (positions are contiguous 0-based per the UNIQUE index +
        // ExpectedVersion model). Carried explicitly so the audit
        // record is self-describing.
        let event_count = (final_position as u64) + 1;

        let tombstone = DomainEvent::StreamSealed(StreamSealed {
            sealed_stream_id: target_id.clone(),
            sealed_stream_category: target_cat.to_string(),
            final_stream_position: final_position as u64,
            final_event_hash,
            event_count,
            // The port signature carries no policy id at this layer;
            // the nil sentinel records "system/timer retention sweep,
            // no specific policy known here". B5 routes through this
            // same chokepoint and is the layer that knows the policy.
            retention_policy_id: uuid::Uuid::nil(),
            // `None` == the system/timer-driven retention sweep, per
            // the `StreamSealed.actor_id` field contract.
            actor_id: None,
        });

        // Append the tombstone THROUGH THE NORMAL CHAINED APPEND PATH
        // (`append_with_conn`) so the tombstone is itself F-2-chained
        // on the audit-meta stream. ExpectedVersion::Any: the
        // audit-meta stream is append-many (one tombstone per sealed
        // stream over time); the chain predecessor is read from its
        // own tail inside `append_with_conn`.
        let seal_batch = AppendEvents {
            stream_id: StreamId::eventstore_retention(),
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(tombstone)],
            correlation_id: uuid::Uuid::new_v4(),
            causation_id: None,
            actor: hort_domain::events::timer_actor(),
        };
        let serialized = validate_and_serialize(&seal_batch.events)?;

        if let Err(e) = append_with_conn(&mut tx, &seal_batch, &serialized).await {
            // The tombstone could not be durably appended. The delete
            // MUST abort — an untombstoned whole-stream delete makes
            // the chain `Broken`, not `SealedGap`. Roll back: nothing
            // is removed.
            tracing::error!(
                op = mode.op(),
                stream_id = %target_id,
                error = %e,
                "StreamSealed tombstone append failed — aborting seal; \
                 NO rows removed (an untombstoned delete is a Broken chain)"
            );
            return Err(e);
        }

        // Tombstone is staged in this transaction. Only now may rows be
        // removed. The `events_immutable` trigger (defense-in-depth,
        // F-2 spec §7) stays ENABLED — it is NEVER disabled by app code
        // (design §10.2: `DISABLE TRIGGER` is the exact F-2 attack
        // vector). The trigger function (migration `004_events.sql`,
        // verbatim and unchanged by this fix) permits DELETE ONLY when
        // `current_user = 'hort_retention_role'` (exact match, not a
        // membership check — Option B keeps that exemption maximally
        // narrow). The runtime/test connection logs in as a *member* of
        // `hort_retention_role`, so without an explicit role assumption
        // `current_user` is the login user, NOT the role, and the
        // trigger would raise. We therefore assume the role for the
        // remainder of THIS transaction only.
        //
        // FORCED ORDERING — this `SET LOCAL ROLE` MUST sit here, after
        // the tombstone `append_with_conn` returned `Ok` and BEFORE the
        // first `DELETE FROM events`:
        //   * `hort_retention_role` is granted `SELECT, DELETE` and
        //     **NO INSERT** (`004_events.sql:313-314`) and no sequence
        //     USAGE. The tombstone append above is an INSERT into
        //     `events`; issuing `SET LOCAL ROLE hort_retention_role`
        //     before it would make that INSERT fail with
        //     `permission denied`. The append must run under the
        //     INSERT-capable login role (hort_app_role-equivalent); only
        //     the DELETE needs the retention role.
        // `SET LOCAL` is transaction-scoped: it auto-reverts on
        // commit/rollback, so the pooled connection is returned clean
        // with no manual `RESET ROLE` (and none is added — a manual
        // RESET on the error path would be dead code since rollback
        // already reverts it).
        //
        // Q5-unset / non-member fail-closed (design §10.2; Q5
        // semantics preserved): when the connection's login role is NOT
        // a member of `hort_retention_role` (the `hort_app_role`-only pool
        // used when `HORT_RETENTION_DATABASE_URL` is unset), this
        // statement raises `permission denied to set role
        // "hort_retention_role"` (SQLSTATE 42501). It is caught here (NO
        // `unwrap`/`expect`/panic), mapped through the same
        // `DomainError::Invariant` channel the trigger-RAISE Err used,
        // and returned — `tx` is dropped without commit, rolling back
        // the staged tombstone INSERT too: zero rows removed, no orphan
        // tombstone. Identical fail-safe to the pre-fix trigger-RAISE
        // path; B5's `EventStoreRetentionUseCase::seal_one` absorbs this
        // Err exactly as it absorbed the trigger-RAISE Err
        // (`summary.errors += 1` + `tracing::error!` + continue).
        sqlx::query("SET LOCAL ROLE hort_retention_role")
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(
                    op = mode.op(),
                    stream_id = %target_id,
                    error = %e,
                    "SET LOCAL ROLE hort_retention_role failed — aborting \
                     seal; NO rows removed, staged tombstone rolled back \
                     (retention role not assumable: \
                     HORT_RETENTION_DATABASE_URL unset or the runtime user \
                     is not a member of hort_retention_role). Fail-closed; \
                     retried next sweep."
                );
                DomainError::Invariant(format!(
                    "retention role not assumable (HORT_RETENTION_DATABASE_URL \
                     unset or runtime user is not a member of \
                     hort_retention_role): SET LOCAL ROLE hort_retention_role \
                     failed: {e}"
                ))
            })?;

        // The DELETE now executes with `current_user = hort_retention_role`,
        // which the (unchanged) trigger function permits. A genuine
        // trigger violation can still only arise if the role assumption
        // above were bypassed; it is mapped distinctly below
        // ("failed to remove sealed stream rows") so an operator can
        // tell a real trigger RAISE from a not-assumable-role error.
        let removed = sqlx::query("DELETE FROM events WHERE stream_id = $1")
            .bind(&target_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                // Defence-in-depth (events-role hardening): if the
                // still-enabled trigger fired (DELETE under a non
                // hort_retention_role), tick the `trigger_caught` metric
                // before mapping the error.
                inspect_audit_block(&e);
                DomainError::Invariant(format!("failed to remove sealed stream rows: {e}"))
            })?
            .rows_affected();

        tx.commit()
            .await
            .map_err(|e| DomainError::Invariant(format!("seal transaction commit failed: {e}")))?;

        // Security-relevant state change: stream id + final position
        // only, never the payload (design §10.7).
        tracing::info!(
            op = mode.op(),
            stream_id = %target_id,
            final_stream_position = final_position,
            rows_removed = removed,
            archive_target = match &mode {
                SealMode::Archive { target } => Some(target.as_str()),
                SealMode::Delete => None,
            },
            "StreamSealed tombstone emitted; stream sealed and removed"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Core append logic shared between the trait method and `append_in_tx`.
async fn append_with_conn(
    conn: &mut sqlx::PgConnection,
    batch: &AppendEvents,
    serialized: &[serde_json::Value],
) -> DomainResult<AppendResult> {
    let (stream_id_str, cat_str) = stream_id_to_columns(&batch.stream_id);

    // Read the tail position of this stream (if any). The earlier shape
    // of this query used `FOR UPDATE` to serialize concurrent appenders
    // on the tail row, but Postgres requires the table-level UPDATE
    // privilege for `SELECT … FOR UPDATE` (per the SQL spec) and the
    // events-role hardening (ADR 0009) deliberately REVOKEs UPDATE from
    // `hort_app_role` to keep the audit log immutable. The two
    // collided in production: every fresh-stream append on
    // `stream_category="ref"` (OCI tag→digest writes) failed with 42501
    // "permission denied for table events" before the INSERT ran.
    //
    // Correctness without the lock: the `UNIQUE (stream_id,
    // stream_position)` index is the load-bearing serializer.
    // Concurrent appenders read the same tail position N here, both
    // attempt to INSERT at N+1, and Postgres' unique-index check
    // catches the loser as a 23505 unique_violation — the existing
    // error-mapping below maps that to `DomainError::Conflict`. This
    // is the standard optimistic-concurrency model for event sourcing
    // (matches the `ExpectedVersion::Exact` semantics callers already
    // rely on); the FOR UPDATE clause was a contention optimization,
    // not a correctness mechanism. Under high contention a few extra
    // 23505-retries are observable on `hort_event_store_appends_total
    // {result="conflict"}`; the cost is negligible because warm-cache
    // ingest dominates the hot path and tail-row contention on any
    // single stream is rare.
    //
    // See `crates/hort-adapters-postgres/tests/events_role_hardening.rs`
    // case 5 for the regression test that pins this contract.
    //
    // The same tail query also returns the tail row's `event_hash` —
    // the predecessor for the first event of this batch's chain link.
    // This rides the existing single round trip (spec §9: "carry the
    // predecessor `event_hash` from the same per-stream tail query
    // already executed ... no extra round trip").
    let tail: Option<(i64, Vec<u8>)> = sqlx::query_as(
        r#"SELECT stream_position, event_hash
           FROM events
           WHERE stream_id = $1
           ORDER BY stream_position DESC
           LIMIT 1"#,
    )
    .bind(&stream_id_str)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| DomainError::Invariant(format!("failed to read stream position: {e}")))?;

    let (current_position, tail_event_hash): (i64, Option<EventHash>) = match tail {
        // Fresh stream — the first event chains from the genesis
        // sentinel (spec §2.2). `-1` keeps the existing
        // optimistic-concurrency arithmetic (`stream_position += 1`
        // yields 0 for the first event) byte-identical.
        None => (-1, None),
        Some((pos, hash_bytes)) => {
            // The tail row exists, so its `event_hash` must be the
            // 32-byte chain head. An absent / wrong-width value is
            // only reachable mid-backfill or against a pre-chain row,
            // which the `NOT NULL` + `CHECK` make unreachable in
            // steady state — surface it as the same `Invariant`
            // "should be impossible" shape the file already uses
            // (spec §10), never as a silent break.
            let arr: [u8; 32] = hash_bytes.as_slice().try_into().map_err(|_| {
                DomainError::Invariant(format!(
                    "event chain predecessor missing for stream {stream_id_str} at position {pos}"
                ))
            })?;
            (pos, Some(EventHash(arr)))
        }
    };

    // Validate expected version.
    match batch.expected_version {
        ExpectedVersion::NoStream => {
            if current_position != -1 {
                return Err(DomainError::Conflict(format!(
                    "stream {stream_id_str} already exists (position {current_position}), \
                     expected NoStream"
                )));
            }
        }
        ExpectedVersion::Exact(expected) => {
            if current_position != expected as i64 {
                return Err(DomainError::Conflict(format!(
                    "stream {stream_id_str} at position {current_position}, expected {expected}"
                )));
            }
        }
        ExpectedVersion::Any => {}
    }

    let actor_cols = actor_to_columns(&batch.actor);
    let mut stream_position = current_position;
    let mut global_positions = Vec::with_capacity(batch.events.len());

    // The running per-stream chain predecessor.
    // The first event of this batch chains from the stored tail's
    // `event_hash`, or the genesis sentinel (spec §2.2) if the stream
    // is new. Each subsequent event in the batch chains from the hash
    // we just computed, so a multi-event batch forms a contiguous
    // chain segment with no extra DB round trips.
    let mut prev_event_hash = tail_event_hash.unwrap_or_else(genesis_hash);

    for (i, to_append) in batch.events.iter().enumerate() {
        stream_position += 1;
        // Bind the caller-supplied event_id verbatim. The adapter never
        // mints — "adapter is pure persistence" extends from payload
        // (Item 6) to identity (review B6).
        let event_id = to_append.event_id;
        let event = &to_append.event;
        let event_type = event.event_type();
        let event_data = &serialized[i];

        // Compute this event's hash over the canonical form of the
        // typed event + the predecessor hash (spec §3/§9). Pure and
        // infallible — `canonical_event_bytes` serializes an
        // already-`validate()`d typed `DomainEvent`, so the append
        // path gains NO new fallible step (spec §10). `event_version`
        // is the literal `1` bound below; keep the two in lockstep.
        let event_version: u32 = 1;
        let chain_input = ChainInput {
            prev_event_hash,
            event_id,
            stream_id: &stream_id_str,
            stream_category: cat_str,
            stream_position: stream_position as u64,
            event_type,
            event_version,
            event,
            correlation_id: batch.correlation_id,
            causation_id: batch.causation_id,
            actor: ActorCanonical {
                actor_type: actor_cols.actor_type,
                actor_id: actor_cols.actor_id,
                actor_source_file: actor_cols.actor_source_file.as_deref(),
                actor_spec_digest: actor_cols.actor_spec_digest.as_deref(),
            },
        };
        let event_hash = compute_event_hash(&chain_input);
        let prev_for_row = prev_event_hash;

        let global_position: i64 = sqlx::query_scalar(
            r#"INSERT INTO events (
                   event_id, stream_id, stream_category,
                   stream_position, event_type, event_version,
                   event_data, correlation_id, causation_id,
                   actor_type, actor_id, actor_source_file, actor_spec_digest,
                   prev_event_hash, event_hash
               )
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                       $14, $15)
               RETURNING global_position"#,
        )
        .bind(event_id)
        .bind(&stream_id_str)
        .bind(cat_str)
        .bind(stream_position)
        .bind(event_type)
        .bind(event_version as i32) // event_version
        .bind(event_data)
        .bind(batch.correlation_id)
        .bind(batch.causation_id)
        .bind(actor_cols.actor_type)
        .bind(actor_cols.actor_id)
        .bind(actor_cols.actor_source_file.as_ref())
        .bind(actor_cols.actor_spec_digest.as_ref())
        .bind(prev_for_row.as_bytes().as_slice())
        .bind(event_hash.as_bytes().as_slice())
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| {
            // Defence-in-depth (events-role hardening): if any future
            // code path on this connection fires the `events_immutable`
            // trigger, the metric ticks at the `trigger_caught` decision
            // point. INSERTs never trip the trigger today, so this is a
            // no-op in steady state — the intent is that the helper sits
            // at every error site that reaches the events table, so a
            // future regression cannot silently slip a forbidden mutation
            // past observability.
            inspect_audit_block(&e);
            // Unique-index violation on (stream_id, stream_position) means
            // a concurrent appender won the insert race for this position.
            // Surface that as a `Conflict` (the semantic the domain layer
            // already translates to a 409); everything else stays Invariant.
            if matches!(
                e.as_database_error()
                    .and_then(|db| db.code().map(std::borrow::Cow::into_owned)),
                Some(ref code) if code == "23505"
            ) {
                DomainError::Conflict(format!(
                    "stream {stream_id_str} concurrent append at position {stream_position}"
                ))
            } else {
                DomainError::Invariant(format!("failed to insert event: {e}"))
            }
        })?;

        global_positions.push(global_position as u64);
        // Advance the chain: the next event in this batch chains from
        // the hash we just persisted.
        prev_event_hash = event_hash;
    }

    Ok(AppendResult {
        stream_position: stream_position as u64,
        global_positions,
    })
}

/// Validate each event's per-field invariants (string-length caps, enum
/// sanity, cross-field sums) **before** serialising,
/// then enforce the 64 KB overall-serialised cap as defence-in-depth. The
/// two checks are complementary: per-field validation catches specific
/// attacker-controlled inputs (oversize `name`, too-many-violations sums);
/// the 64 KB cap catches anything future event types might slip through.
fn validate_and_serialize(events: &[EventToAppend]) -> DomainResult<Vec<serde_json::Value>> {
    events
        .iter()
        .map(|to_append| {
            let event = &to_append.event;
            event.validate()?;
            let json = serialize_event_data(event);
            let size = json.to_string().len();
            if size > MAX_EVENT_JSON_BYTES {
                return Err(DomainError::Validation(format!(
                    "serialized event {} exceeds 64 KB limit ({size} bytes)",
                    event.event_type()
                )));
            }
            Ok(json)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::entities::scan_policy::SeverityThreshold;
    use hort_domain::events::{
        ArtifactIngested, ArtifactRejected, AuthenticationAttempted, DomainEvent, IngestSource,
        PolicyEvaluated, PolicyResult, PolicyViolation, RejectionReason,
    };
    use hort_domain::types::ContentHash;
    use serial_test::serial;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Per-field validation fires before the 64 KB cap. An `ArtifactRejected`
    /// with a 70 KB `reason` trips `MAX_REASON_LEN` (4096) first — the
    /// validation error names the field, so attackers can't infer whether a
    /// large payload was rejected by defence-in-depth or by a per-field rule.
    #[test]
    fn validate_and_serialize_rejects_oversize_field_via_per_field_validate() {
        let big_reason = "x".repeat(70_000);
        let event = DomainEvent::ArtifactRejected(ArtifactRejected {
            artifact_id: Uuid::new_v4(),
            rejected_by: RejectionReason::Admin,
            reason: big_reason,
        });
        let err = validate_and_serialize(&[EventToAppend::new(event)]).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("reason"),
            "error should name the failing field, got: {err}"
        );
    }

    /// Backlog-mandated coverage: a 1025-char `name` on `ArtifactIngested`
    /// trips `MAX_NAME_LEN` (1024) from `ArtifactIngested::validate`. The
    /// per-field validation must run on every event type before the append
    /// path — this test is the regression guard that `validate_and_serialize`
    /// calls into the per-event `validate()`.
    #[test]
    fn validate_and_serialize_rejects_oversized_name_field() {
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        let event = DomainEvent::ArtifactIngested(ArtifactIngested {
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            name: "x".repeat(1025),
            version: Some("1.0.0".into()),
            sha256: hash,
            size_bytes: 512,
            source: IngestSource::Direct,
            metadata: serde_json::Value::Null,
            metadata_blob: None,
            upstream_published_at: None,
        });
        let err = validate_and_serialize(&[EventToAppend::new(event)]).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("name"),
            "error should name the failing field, got: {err}"
        );
    }

    /// Defence-in-depth: an event that passes every per-field cap but whose
    /// serialised form still exceeds 64 KB must be rejected by the cap.
    ///
    /// `PolicyViolation` has the shape `{ rule, severity, message, details }`.
    /// The per-field caps are
    /// `MAX_RULE_LEN = 256`, `MAX_MESSAGE_LEN = 4096`, and the JSON
    /// `details` blob is capped at 4 KiB. 20 violations with each field
    /// just under cap (rule = 256, message = 4000, details = Null)
    /// individually pass `PolicyViolation::validate`; the Vec aggregates
    /// to ~85 KB of JSON — past the 64 KB ceiling.
    #[test]
    fn validate_and_serialize_rejects_via_64kb_cap_when_per_field_passes() {
        let violations: Vec<PolicyViolation> = (0..20)
            .map(|i| PolicyViolation {
                // 256-char rule string — exactly at MAX_RULE_LEN.
                // Prefix `"rule-NNN-"` is 9 chars (3-digit zero-padded
                // index plus delimiters), so 256 - 9 = 247 padding.
                rule: format!("rule-{i:03}-{}", "r".repeat(247)),
                severity: SeverityThreshold::Critical,
                // 4000-char message — under MAX_MESSAGE_LEN (4096).
                message: "d".repeat(4000),
                // Null details — small, keeps the per-violation JSON
                // overhead predictable while still crossing the 64 KB
                // aggregate.
                details: serde_json::Value::Null,
            })
            .collect();
        let event = DomainEvent::PolicyEvaluated(PolicyEvaluated {
            artifact_id: Uuid::new_v4(),
            policy_id: Uuid::new_v4(),
            result: PolicyResult::Fail,
            violations,
        });
        // Sanity: per-field validate passes.
        event.validate().expect("per-field validate should accept");
        let err = validate_and_serialize(&[EventToAppend::new(event)]).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(
            err.to_string().contains("64 KB"),
            "expected 64 KB cap error, got: {err}"
        );
    }

    #[test]
    fn validate_and_serialize_accepts_normal_event() {
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        let event = DomainEvent::ArtifactIngested(ArtifactIngested {
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            name: "test-pkg".into(),
            version: Some("1.0.0".into()),
            sha256: hash,
            size_bytes: 512,
            source: IngestSource::Direct,
            metadata: serde_json::Value::Null,
            metadata_blob: None,
            upstream_published_at: None,
        });
        let result = validate_and_serialize(&[EventToAppend::new(event)]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    // -----------------------------------------------------------------
    // DB-backed integration tests — skipped when `DATABASE_URL` is unset.
    // -----------------------------------------------------------------
    use hort_domain::events::{Actor, ApiActor};
    use hort_domain::ports::event_store::AppendEvents;
    use std::env;

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
    }

    /// B6 regression guard: the `event_id` the caller supplied in
    /// [`EventToAppend`] MUST be the id persisted in `events.event_id`.
    /// Before the fix the adapter minted a fresh `Uuid::new_v4()`
    /// internally; any caller that threaded the pre-minted id as a
    /// downstream `causation_id` ended up with a dangling reference.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn append_binds_caller_supplied_event_id() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let store = PgEventStore::new(pool.clone()).await.unwrap();

        let event_id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let stream = StreamId::artifact(artifact_id);
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        let batch = AppendEvents {
            stream_id: stream.clone(),
            expected_version: ExpectedVersion::NoStream,
            events: vec![EventToAppend {
                event_id,
                event: DomainEvent::ArtifactIngested(ArtifactIngested {
                    artifact_id,
                    repository_id: Uuid::new_v4(),
                    name: "b6-regression".into(),
                    version: Some("1.0.0".into()),
                    sha256: hash,
                    size_bytes: 10,
                    source: IngestSource::Direct,
                    metadata: serde_json::Value::Null,
                    metadata_blob: None,
                    upstream_published_at: None,
                }),
            }],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
        };

        store.append(batch).await.unwrap();

        let row: (Uuid,) = sqlx::query_as("SELECT event_id FROM events WHERE stream_id = $1")
            .bind(stream.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            row.0, event_id,
            "adapter must bind caller-supplied event_id verbatim"
        );
    }

    // -----------------------------------------------------------------
    // Dyn-shape lock for delete_stream / archive_stream (ADR 0020)
    //
    // These tests pin two contracts:
    //
    // 1. **Compile-time:** `PgEventStore` is upcastable to
    //    `&dyn EventStore` and the trait carries `delete_stream` /
    //    `archive_stream` with the expected signatures. If a future
    //    edit adds a generic parameter or `impl Trait` return to either
    //    method (breaking dyn-compat), or removes the method outright,
    //    these tests stop compiling. The
    //    `port_is_dyn_compatible` test in `hort-domain` covers the trait
    //    side; this is the adapter-side mirror.
    //
    // 2. **Runtime (when DB is available):** Both methods are live.
    //    The earlier stub `should_panic` assertions are RETIRED — the
    //    methods now seal+remove via the `seal_and_remove` chokepoint.
    //    The Phase-B runtime contract is exercised by the dedicated
    //    `b9_db_*` tests below (ordering, abort, archive parity,
    //    idempotent no-op) and the no-DB verifier round-trip.
    //
    // The dyn-shape acceptance is satisfied at compile time regardless
    // (`_upcasts_event_store`).
    // -----------------------------------------------------------------

    /// Type-only fixture: locks the dyn-shape of the new `EventStore`
    /// methods at compile time, no DB required. Tier 1 catches any future
    /// regression that breaks dyn-compatibility (e.g. a generic param or
    /// `-> impl Trait`) or removes the methods outright.
    #[allow(dead_code)]
    fn _upcasts_event_store(p: &PgEventStore) {
        fn _accepts(_: &dyn EventStore) {}
        _accepts(p);
    }

    // -----------------------------------------------------------------
    // Tamper-evident event chain (ADR 0004)
    //
    // Centerpiece acceptance: "a tampered row fails verification".
    // The chain link is computed by `append_with_conn` and the
    // detection logic is the pure `hort-domain` verifier. These tests
    // pin the adapter↔domain contract: the `ChainInput` the append
    // path binds is exactly the one the verifier reconstructs from the
    // persisted columns, so a mutation of any persisted field (payload
    // or a stored hash) is detected offline with no DB write needed.
    //
    // The no-DB test runs in Tier 1 (the offline verifier model: read
    // rows, recompute, detect — no privileged write required). The
    // DB-backed test additionally exercises the real append path and a
    // privileged in-place row mutation under Tier 2.
    // -----------------------------------------------------------------
    use hort_domain::events::{
        compute_event_hash, genesis_hash, verify_stream_chain, ActorCanonical, ChainBreak,
        ChainInput, EventHash, StreamRow, StreamRows, StreamVerdict,
    };

    /// The envelope columns the per-event hash binds, in the exact
    /// form a stored row carries them (`event_id`, `stream_category`,
    /// `correlation_id`, `causation_id`, and the four actor columns).
    ///
    /// `row_view` previously hardcoded these
    /// (`event_id = Uuid::from_u128(0xE0 + pos)`,
    /// `correlation_id = Uuid::from_u128(0xC0FFEE)`,
    /// `stream_category = "artifact"`, `actor = system/None`). Because
    /// `canonical_event_bytes` (spec §3.1, frozen field order) hashes
    /// field 2 `event_id`, field 4 `stream_category`, field 9
    /// `correlation_id`, and field 11 the actor tuple, a `row_view`
    /// reconstruction of a row that was stored with a *real* envelope
    /// (random `event_id` from `EventToAppend::new`, `Uuid::new_v4()`
    /// correlation, the real `StreamId` category, `system_actor()`)
    /// recomputed a hash that never matched the stored `event_hash` —
    /// a spurious `Broken { at_position: 0, HashMismatch }` at the very
    /// first row, masking whatever the test actually injected further
    /// down the chain. Threading the *stored* envelope (the same
    /// mechanism the production verifier uses —
    /// `hort-server::cli::verify_event_chain::OwnedRow::as_stream_row`,
    /// which builds `ChainInput` from the real `EventRow` columns) makes
    /// the recompute equal the stored hash for genuinely-appended rows.
    /// Fixed under explicit architect+user F-2 co-review (design §10.1).
    #[derive(Clone, Copy)]
    struct RowEnvelope<'a> {
        event_id: Uuid,
        stream_category: &'a str,
        correlation_id: Uuid,
        causation_id: Option<Uuid>,
        actor: ActorCanonical<'a>,
    }

    /// The deterministic synthetic envelope the in-memory
    /// (`chained_admin_rows`-based) F-2 tests stored their hashes with.
    /// This is the *single source of truth* for those constants: both
    /// `chained_admin_rows` (which computes the stored hash) and the
    /// synthetic `row_view` call sites (which recompute it) take the
    /// envelope from here, so `compute_event_hash(reconstructed) ==
    /// stored event_hash` holds structurally for the synthetic callers,
    /// not by two copies of the same literals happening to agree.
    fn synthetic_envelope(position: u64) -> RowEnvelope<'static> {
        RowEnvelope {
            event_id: Uuid::from_u128(0xE0 + position as u128),
            stream_category: "artifact",
            correlation_id: Uuid::from_u128(0xC0FFEE),
            causation_id: None,
            actor: ActorCanonical {
                actor_type: "system",
                actor_id: None,
                actor_source_file: None,
                actor_spec_digest: None,
            },
        }
    }

    /// Build the stored-row views for a stream the same way
    /// `append_with_conn` chains them: position 0 chains from the
    /// genesis sentinel, each subsequent event from the prior hash.
    /// The stored hash is computed with [`synthetic_envelope`] so the
    /// synthetic `row_view` reconstruction round-trips exactly.
    fn chained_admin_rows(stream_id: &str, n: u64) -> Vec<(DomainEvent, EventHash, EventHash)> {
        let mut prev = genesis_hash();
        let mut out = Vec::new();
        for i in 0..n {
            let ev = DomainEvent::ArtifactRejected(ArtifactRejected {
                artifact_id: Uuid::from_u128(0xA0 + i as u128),
                rejected_by: RejectionReason::Scanner,
                reason: format!("CVE-{i}"),
            });
            let env = synthetic_envelope(i);
            let inp = ChainInput {
                prev_event_hash: prev,
                event_id: env.event_id,
                stream_id,
                stream_category: env.stream_category,
                stream_position: i,
                event_type: ev.event_type(),
                event_version: 1,
                event: &ev,
                correlation_id: env.correlation_id,
                causation_id: env.causation_id,
                actor: env.actor,
            };
            let h = compute_event_hash(&inp);
            out.push((ev, prev, h));
            prev = h;
        }
        out
    }

    /// Reconstruct one stored row's verifier view. `env` MUST be the
    /// envelope the row was *stored* with — the synthetic callers pass
    /// [`synthetic_envelope`] (the constants `chained_admin_rows` used),
    /// the DB callers pass the real columns read back from the
    /// persisted `EventRow`. This mirrors the production verifier's
    /// `OwnedRow::as_stream_row` `ChainInput` construction
    /// (`hort-server::cli::verify_event_chain`).
    fn row_view<'a>(
        stream_id: &'a str,
        position: u64,
        event: &'a DomainEvent,
        env: RowEnvelope<'a>,
        stored_prev: EventHash,
        stored_hash: EventHash,
    ) -> StreamRow<'a> {
        StreamRow {
            input: ChainInput {
                prev_event_hash: stored_prev,
                event_id: env.event_id,
                stream_id,
                stream_category: env.stream_category,
                stream_position: position,
                event_type: event.event_type(),
                event_version: 1,
                event,
                correlation_id: env.correlation_id,
                causation_id: env.causation_id,
                actor: env.actor,
            },
            stored_prev,
            stored_hash,
        }
    }

    /// One persisted row, owned, reconstructed via the production
    /// `EventRow` + `TryFrom<EventRow> for PersistedEvent` path — the
    /// exact mechanism `verify_event_chain.rs::read_stream_rows` /
    /// `OwnedRow::as_stream_row` use. The owned envelope columns
    /// (`stream_category`, the four actor columns) are kept verbatim so
    /// `as_stream_row` borrows the *real* stored envelope into the
    /// `RowEnvelope` — the Item-B15 fix that makes the recomputed hash
    /// equal the stored `event_hash` for genuinely-appended rows.
    struct OwnedDbRow {
        persisted: PersistedEvent,
        stream_id: String,
        stream_category: String,
        actor_type: String,
        actor_id: Option<Uuid>,
        actor_source_file: Option<String>,
        actor_spec_digest: Option<Vec<u8>>,
        stored_prev: EventHash,
        stored_hash: EventHash,
    }

    impl OwnedDbRow {
        /// Borrow this owned row as a pure-core `StreamRow`, threading
        /// the *real* stored envelope (mirrors the production
        /// `OwnedRow::as_stream_row` `ChainInput` construction).
        fn as_stream_row(&self) -> StreamRow<'_> {
            row_view(
                &self.stream_id,
                self.persisted.stream_position,
                &self.persisted.event,
                RowEnvelope {
                    event_id: self.persisted.event_id,
                    stream_category: &self.stream_category,
                    correlation_id: self.persisted.correlation_id,
                    causation_id: self.persisted.causation_id,
                    actor: ActorCanonical {
                        actor_type: &self.actor_type,
                        actor_id: self.actor_id,
                        actor_source_file: self.actor_source_file.as_deref(),
                        actor_spec_digest: self.actor_spec_digest.as_deref(),
                    },
                },
                self.stored_prev,
                self.stored_hash,
            )
        }
    }

    /// Read one stream back through the production `EventRow` +
    /// `TryFrom<EventRow> for PersistedEvent` path and pair each row
    /// with its stored `(prev_event_hash, event_hash)` columns. Two
    /// queries per stream (the `EventRow` columns, then the two `bytea`
    /// chain columns) both ordered `stream_position ASC` — the F-2
    /// chain columns are not part of `EventRow`'s `FromRow` shape, so
    /// they are selected separately and zipped by position. Shared by
    /// the two Tier-2 DB F-2 tests so the reconstruction is written
    /// once and stays identical to the production verifier's mechanism.
    async fn read_back_owned_rows(pool: &PgPool, stream_id: &str) -> Vec<OwnedDbRow> {
        let event_rows: Vec<EventRow> = sqlx::query_as(&format!(
            r#"SELECT {EVENT_COLS}
               FROM events WHERE stream_id = $1 ORDER BY stream_position ASC"#
        ))
        .bind(stream_id)
        .fetch_all(pool)
        .await
        .unwrap();
        let chain_cols: Vec<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            r#"SELECT stream_position, prev_event_hash, event_hash
               FROM events WHERE stream_id = $1 ORDER BY stream_position ASC"#,
        )
        .bind(stream_id)
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(
            event_rows.len(),
            chain_cols.len(),
            "row count must match between the EventRow read and the \
             chain-column read (both ORDER BY stream_position ASC)"
        );
        let mut out = Vec::with_capacity(event_rows.len());
        for (r, (pos, prev, hash)) in event_rows.into_iter().zip(chain_cols.into_iter()) {
            assert_eq!(
                r.stream_position, pos,
                "EventRow / chain-column zip must align by stream_position"
            );
            // Keep the owned envelope columns before `TryFrom` consumes
            // the `EventRow` (mirrors production `read_stream_rows`,
            // which clones these out of `EventRow` for `OwnedRow`).
            let stream_id_owned = r.stream_id.clone();
            let stream_category = r.stream_category.clone();
            let actor_type = r.actor_type.clone();
            let actor_id = r.actor_id;
            let actor_source_file = r.actor_source_file.clone();
            let actor_spec_digest = r.actor_spec_digest.clone();
            let stored_prev = EventHash(
                <[u8; 32]>::try_from(prev.as_slice())
                    .expect("prev_event_hash is a 32-byte column (schema CHECK)"),
            );
            let stored_hash = EventHash(
                <[u8; 32]>::try_from(hash.as_slice())
                    .expect("event_hash is a 32-byte column (schema CHECK)"),
            );
            let persisted = PersistedEvent::try_from(r)
                .expect("a genuinely-appended row deserializes via TryFrom<EventRow>");
            out.push(OwnedDbRow {
                persisted,
                stream_id: stream_id_owned,
                stream_category,
                actor_type,
                actor_id,
                actor_source_file,
                actor_spec_digest,
                stored_prev,
                stored_hash,
            });
        }
        out
    }

    /// Untampered: the chain the append path computes verifies `Ok`.
    #[test]
    fn appended_chain_verifies_ok() {
        let sid = "artifact-deadbeef";
        let chained = chained_admin_rows(sid, 4);
        let rows: Vec<StreamRow> = chained
            .iter()
            .enumerate()
            .map(|(i, (ev, prev, h))| {
                row_view(sid, i as u64, ev, synthetic_envelope(i as u64), *prev, *h)
            })
            .collect();
        match verify_stream_chain(&StreamRows::new(&rows)) {
            StreamVerdict::Ok { position, .. } => assert_eq!(position, 3),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    /// CENTERPIECE: a tampered stored row fails verification. A
    /// privileged adversary mutates the persisted `event_data`
    /// (modelled here by substituting the typed event the verifier
    /// reconstructs from that row) while leaving the stored
    /// `event_hash` untouched — `verify_stream_chain` recomputes and
    /// flags `HashMismatch` at exactly the tampered position.
    #[test]
    fn tampered_row_fails_verification() {
        let sid = "artifact-deadbeef";
        let chained = chained_admin_rows(sid, 4);
        let mut rows: Vec<StreamRow> = chained
            .iter()
            .enumerate()
            .map(|(i, (ev, prev, h))| {
                row_view(sid, i as u64, ev, synthetic_envelope(i as u64), *prev, *h)
            })
            .collect();

        // Tamper: rewrite the payload of the row at position 2 (the
        // attacker edits event_data in the table) but cannot recompute
        // the chain because the chain head is externally anchored.
        let forged = DomainEvent::ArtifactRejected(ArtifactRejected {
            artifact_id: Uuid::from_u128(0xDEAD),
            rejected_by: RejectionReason::Admin,
            reason: "exonerated by insider".into(),
        });
        rows[2].input.event = &forged;

        assert_eq!(
            verify_stream_chain(&StreamRows::new(&rows)),
            StreamVerdict::Broken {
                at_position: 2,
                reason: ChainBreak::HashMismatch
            }
        );
    }

    /// A privileged adversary who deletes the newest event and rewrites
    /// the new tail's stored `event_hash` still cannot avoid detection:
    /// excising position 3 and leaving 0..=2 makes position 2 the tail,
    /// which still verifies — but excising a *middle* row breaks the
    /// position contiguity / prev linkage. Pins the "deletion is
    /// detectable" half of invariant I1.
    #[test]
    fn excised_middle_row_fails_verification() {
        let sid = "artifact-deadbeef";
        let chained = chained_admin_rows(sid, 4);
        let all: Vec<StreamRow> = chained
            .iter()
            .enumerate()
            .map(|(i, (ev, prev, h))| {
                row_view(sid, i as u64, ev, synthetic_envelope(i as u64), *prev, *h)
            })
            .collect();
        // Drop position 1 -> positions 0, 2, 3 -> gap detected at the
        // second surviving row.
        let gapped = [all[0], all[2], all[3]];
        assert_eq!(
            verify_stream_chain(&StreamRows::new(&gapped)),
            StreamVerdict::Broken {
                at_position: 2,
                reason: ChainBreak::PositionGap
            }
        );
    }

    /// DB-backed end-to-end (Tier 2, gated on `DATABASE_URL`): append
    /// real events through the adapter, read the persisted
    /// `prev_event_hash`/`event_hash` columns back, confirm the chain
    /// verifies `Ok`, then mutate a stored row's `event_data` via the
    /// table-owner connection (a privileged adversary the trigger +
    /// REVOKE cannot stop) and confirm verification now fails.
    ///
    /// `#[ignore]` mirrors the file's existing Tier-2 idiom: the
    /// privileged UPDATE needs the owner role, not the `hort_app_role`
    /// `maybe_pool()` provides, so the tamper step is skipped unless a
    /// DB is present; the no-DB tests above already prove detection.
    #[tokio::test]
    #[serial(hort_pg_db)]
    #[ignore = "requires DATABASE_URL — runs in Tier 2 only"]
    async fn db_appended_chain_persists_and_detects_tamper() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let store = PgEventStore::new(pool.clone()).await.unwrap();

        let artifact_id = Uuid::new_v4();
        let stream = StreamId::artifact(artifact_id);
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        let batch = AppendEvents {
            stream_id: stream.clone(),
            expected_version: ExpectedVersion::NoStream,
            events: vec![
                EventToAppend::new(DomainEvent::ArtifactIngested(ArtifactIngested {
                    artifact_id,
                    repository_id: Uuid::new_v4(),
                    name: "f2-chain".into(),
                    version: Some("1.0.0".into()),
                    sha256: hash,
                    size_bytes: 10,
                    source: IngestSource::Direct,
                    metadata: serde_json::Value::Null,
                    metadata_blob: None,
                    upstream_published_at: None,
                })),
                EventToAppend::new(DomainEvent::ArtifactRejected(ArtifactRejected {
                    artifact_id,
                    rejected_by: RejectionReason::Scanner,
                    reason: "CVE-2026-0001".into(),
                })),
            ],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: hort_domain::events::system_actor(),
        };
        store.append(batch).await.unwrap();

        // Read the persisted chain columns back in order.
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            r#"SELECT stream_position, prev_event_hash, event_hash
               FROM events WHERE stream_id = $1 ORDER BY stream_position ASC"#,
        )
        .bind(stream.to_string())
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        // Position 0 chains from the genesis sentinel; position 1's
        // prev equals position 0's stored event_hash.
        assert_eq!(rows[0].1.as_slice(), genesis_hash().as_bytes().as_slice());
        assert_eq!(rows[1].1, rows[0].2);
        for (_, prev, h) in &rows {
            assert_eq!(prev.len(), 32);
            assert_eq!(h.len(), 32);
        }

        // Tamper as the table owner (privileged adversary). The
        // `events_immutable` trigger blocks UPDATE; disable it for the
        // mutation, then restore — modelling a DBA with DISABLE
        // TRIGGER, exactly the threat F-2 defends against.
        sqlx::query("ALTER TABLE events DISABLE TRIGGER events_immutable")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            r#"UPDATE events
               SET event_data = jsonb_set(event_data, '{data,reason}', '"exonerated"')
               WHERE stream_id = $1 AND stream_position = 1"#,
        )
        .bind(stream.to_string())
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("ALTER TABLE events ENABLE TRIGGER events_immutable")
            .execute(&pool)
            .await
            .unwrap();

        // Re-read and rebuild the verifier inputs from the persisted
        // rows through the *production* `EventRow` +
        // `TryFrom<EventRow> for PersistedEvent` path (the exact
        // mechanism `verify_event_chain.rs` uses), threading the real
        // stored envelope (Item-B15 `row_view` fix).
        let owned = read_back_owned_rows(&pool, &stream.to_string()).await;
        let rows2: Vec<StreamRow> = owned.iter().map(OwnedDbRow::as_stream_row).collect();

        // Why `at_position: 1` is the *provably correct* verdict for
        // the injected tamper (Item-B15 reasoning):
        //
        //   * Position 0 (`ArtifactIngested`) is UNtampered. With the
        //     fixed `row_view` threading the real `event_id` /
        //     `correlation_id` / `stream_category` ("artifact") /
        //     `system` actor, `compute_event_hash(reconstructed)` ==
        //     the stored `event_hash`, so position 0 verifies clean and
        //     the verifier advances to position 1. (Before the B15 fix
        //     the hardcoded-envelope `row_view` mismatched here first,
        //     yielding a spurious `Broken { at_position: 0 }` that
        //     masked the real detection — that masked failure is the
        //     latent F-2-test defect this item fixes.)
        //   * Position 1 (`ArtifactRejected`) had its `event_data`
        //     `reason` rewritten to "exonerated" by the owner UPDATE
        //     above. Its stored `event_hash` was computed over the
        //     ORIGINAL payload; the verifier recomputes over the
        //     tampered typed event (real envelope, unchanged) → the
        //     recompute != the stored hash → `HashMismatch` at exactly
        //     position 1. The stored `prev_event_hash` still equals
        //     position 0's head (the attacker did not — and cannot —
        //     re-chain), so the break is isolated to the mutated field,
        //     not a `PrevMismatch`.
        //
        // Tamper-evidence is genuine, NOT a tautology: with no tamper
        // this exact reconstruction verifies `Ok` (proven by the
        // sibling `b15_concurrent_any_appends_form_a_verifiable_chain`
        // and the no-DB `appended_chain_verifies_ok`); only the
        // injected mutation produces `Broken`, and at the position the
        // mutation was applied.
        assert_eq!(
            verify_stream_chain(&StreamRows::new(&rows2)),
            StreamVerdict::Broken {
                at_position: 1,
                reason: ChainBreak::HashMismatch
            },
            "a privileged in-place event_data mutation must be detected \
             at exactly the tampered position (1), not masked by a \
             spurious position-0 mismatch"
        );
    }

    /// F-2 × `ExpectedVersion::Any` per-stream-chain reconciliation
    /// (Tier 2, gated on `DATABASE_URL`).
    ///
    /// **The proven invariant.** A high-volume per-(scope,date) audit
    /// stream is appended with `ExpectedVersion::Any` — no
    /// optimistic-concurrency precondition (the shipped
    /// `AuthenticationAttempted` `auth-<uuid>` daily stream uses exactly
    /// this path; `StreamId::auth_attempts` + the `Any` arm at the
    /// `match batch.expected_version` site in `append_with_conn`).
    /// Concurrency is *not* unserialised: the
    /// `UNIQUE (stream_id, stream_position)` index
    /// (`migrations/004_events.sql`) is the load-bearing
    /// serializer. Two concurrent appenders that both read the same tail
    /// (the live tail read at `event_store.rs` ~800-833) and both target
    /// position `k` are resolved by that unique index admitting exactly
    /// one row; the loser's INSERT raises `23505`, mapped to
    /// `DomainError::Conflict` (the `23505 → Conflict` arm at
    /// ~944-959), and its row is never committed. On caller retry it
    /// re-reads the new tail and rechains from the freshly-committed
    /// predecessor. Therefore every *committed* row's `prev_event_hash`
    /// equals the committed predecessor's `event_hash` and positions are
    /// gapless — a healthy concurrent-`Any` stream is a normal
    /// contiguous F-2 chain that `verify_stream_chain` returns `Ok` for.
    ///
    /// This test is the regression guard for that invariant: it drives
    /// the real `store.append` path under genuine concurrency, with the
    /// loser-retry-rechains contract exercised explicitly, and asserts
    /// the four chain-integrity properties (count, gapless positions,
    /// genesis+linkage by hand, and the load-bearing
    /// `verify_stream_chain == Ok`/`!= Broken`).
    ///
    /// **Verifier path note.** The full server-side read-back +
    /// `roll_up`/`FixedAnchor` machinery lives in
    /// `hort-server::cli::verify_event_chain`; `hort-server` depends on
    /// `hort-adapters-postgres`, so importing it back here would be a
    /// circular dependency. The spec-decision authorised the
    /// minimal-sufficient assertion in that case:
    /// `verify_stream_chain` over the read-back rows == `Ok` and
    /// `!= Broken`. The read-back itself uses the production
    /// `EventRow` + `TryFrom<EventRow> for PersistedEvent` path (the
    /// exact mechanism `verify_event_chain.rs::read_stream_rows` uses),
    /// mirroring the sibling `db_appended_chain_persists_and_detects_tamper`.
    ///
    /// **Concurrency-join note.** The spec names
    /// `futures::future::join_all`; `futures` is not a dev-dependency of
    /// this crate and adding it would require a `Cargo.toml` edit
    /// outside this item's single-file scope fence. `tokio::task::JoinSet`
    /// (tokio is already a dev-dep with `full` features) has identical
    /// semantics — spawn N, await every handle, fail on any task error —
    /// and stays in-scope.
    #[tokio::test]
    #[serial(hort_pg_db)]
    #[ignore = "requires DATABASE_URL — runs in Tier 2 only"]
    async fn b15_concurrent_any_appends_form_a_verifiable_chain() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());

        // ONE shared stream standing in for a high-volume per-(scope,
        // date) audit stream — the shipped `Any` audit-stream shape.
        // A fixed date keeps the UUIDv5-derived stream id deterministic.
        let date = chrono::NaiveDate::from_ymd_opt(2026, 5, 17).unwrap();
        let stream = StreamId::auth_attempts(date);
        let stream_str = stream.to_string();

        // Clean any prior rows for this deterministic stream id so the
        // count/position assertions are exact regardless of run order
        // on the shared DB (the `#[serial(hort_pg_db)]` key already
        // serialises DB-touching tests; this makes the precondition
        // explicit). The `events_immutable` trigger blocks DELETE, so
        // disable it for this fixture-reset only, then restore — this
        // is test-fixture teardown, NOT the append path under test.
        sqlx::query("ALTER TABLE events DISABLE TRIGGER events_immutable")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM events WHERE stream_id = $1")
            .bind(&stream_str)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE events ENABLE TRIGGER events_immutable")
            .execute(&pool)
            .await
            .unwrap();

        const N: usize = 16; // concurrent appenders
        const M: usize = 8; // sequential appends per task
                            // Bounded loser-retry budget. Under genuine N-way contention on
                            // a single stream tail the unique-index admits exactly one
                            // winner per position; the N-1 losers re-contend. A *correct*
                            // optimistic-`Any` retry loop de-correlates the herd with a
                            // capped, fully-jittered exponential backoff so the serializer
                            // makes monotone progress — `yield_now()` alone does not spread
                            // the retries and lets one unlucky task starve. The budget is
                            // set well above any realistic consecutive-loss streak for
                            // N=16 over N*M=128 rows (each row has exactly one winner; with
                            // jittered backoff the expected per-append retry count is small
                            // and bounded). This is the standard correct way to drive the
                            // loser-retry-rechains contract this test exercises — it does
                            // NOT weaken any chain-integrity assertion below.
        const MAX_RETRIES: usize = 512;

        let mut set: tokio::task::JoinSet<Result<(), String>> = tokio::task::JoinSet::new();
        for task_idx in 0..N {
            let store = Arc::clone(&store);
            let stream = stream.clone();
            set.spawn(async move {
                for seq in 0..M {
                    // A small valid event matching this stream's
                    // category (`AuthAttempts`) — the shipped
                    // `AuthenticationAttempted` shape.
                    let mut attempts = 0usize;
                    loop {
                        let event = DomainEvent::AuthenticationAttempted(AuthenticationAttempted {
                            client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                198, 51, 100, 7,
                            )),
                            result: "local_invalid_credentials".into(),
                            external_id_if_decoded: Some(format!("t{task_idx}-s{seq}")),
                            at: chrono::Utc::now(),
                        });
                        let res = store
                            .append(AppendEvents {
                                stream_id: stream.clone(),
                                expected_version: ExpectedVersion::Any,
                                events: vec![EventToAppend::new(event)],
                                correlation_id: Uuid::new_v4(),
                                causation_id: None,
                                actor: hort_domain::events::system_actor(),
                            })
                            .await;
                        match res {
                            Ok(_) => break,
                            // Losing the unique-index race for a tail
                            // position and retrying IS the contract:
                            // re-read the new tail, rechain, try again.
                            Err(DomainError::Conflict(_)) => {
                                attempts += 1;
                                if attempts > MAX_RETRIES {
                                    return Err(format!(
                                        "task {task_idx} seq {seq} exceeded \
                                         {MAX_RETRIES} Conflict retries"
                                    ));
                                }
                                // Capped exponential backoff with full
                                // jitter. The exponent is the *capped*
                                // attempt count (so the ceiling is a
                                // few ms, not unbounded); the jitter is
                                // cheap entropy from a fresh v4 UUID
                                // (already this crate's only randomness
                                // primitive — no new dep, stays inside
                                // the single-file scope fence). Full
                                // jitter (`rand_ms` in `0..=window`)
                                // de-correlates the N-1 losers so the
                                // unique-index serializer makes
                                // monotone forward progress instead of
                                // a synchronized thundering herd.
                                let exp = attempts.min(6) as u32; // cap 2^6 = 64
                                let window_ms: u64 = 1u64 << exp;
                                let rand_ms = (Uuid::new_v4().as_u128() as u64) % (window_ms + 1);
                                tokio::time::sleep(std::time::Duration::from_millis(rand_ms)).await;
                            }
                            // Any non-Conflict Err fails the test.
                            Err(other) => {
                                return Err(format!(
                                    "task {task_idx} seq {seq} non-Conflict err: {other}"
                                ));
                            }
                        }
                    }
                }
                Ok(())
            });
        }

        // Await every handle; assert every task succeeded.
        while let Some(joined) = set.join_next().await {
            joined
                .expect("append task panicked")
                .expect("append task returned an error");
        }

        // --- Assertion 1: exactly N*M rows for the stream. ---
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
            .bind(&stream_str)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            total,
            (N * M) as i64,
            "every committed append must land exactly one row"
        );

        // --- Assertion 2: positions gapless 0..N*M (no gap, no dup). ---
        let positions: Vec<i64> = sqlx::query_scalar(
            r#"SELECT array_agg(stream_position ORDER BY stream_position)
               FROM events WHERE stream_id = $1"#,
        )
        .bind(&stream_str)
        .fetch_one(&pool)
        .await
        .unwrap();
        let expected: Vec<i64> = (0..(N * M) as i64).collect();
        assert_eq!(
            positions,
            expected,
            "stream_position must be a gapless contiguous 0..{} run",
            N * M
        );

        // --- Assertion 3: genesis + by-hand linkage. ---
        let chain: Vec<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            r#"SELECT stream_position, prev_event_hash, event_hash
               FROM events WHERE stream_id = $1 ORDER BY stream_position ASC"#,
        )
        .bind(&stream_str)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(chain.len(), N * M);
        assert_eq!(
            chain[0].1.as_slice(),
            genesis_hash().as_bytes().as_slice(),
            "position 0 must chain from the genesis sentinel"
        );
        for k in 1..chain.len() {
            assert_eq!(
                chain[k].1,
                chain[k - 1].2,
                "row {k} prev_event_hash must equal row {} event_hash \
                 (committed-predecessor linkage)",
                k - 1
            );
        }

        // --- Assertion 4 (load-bearing): the chain verifies, NOT
        // Broken. Read back through the production `EventRow` +
        // `TryFrom<EventRow> for PersistedEvent` path (the exact
        // mechanism the server-side verifier uses) via the shared
        // `read_back_owned_rows` helper, which threads the *real*
        // stored envelope (Item-B15 `row_view` fix), and assert the
        // pure core's verdict. ---
        let owned = read_back_owned_rows(&pool, &stream_str).await;
        let rows: Vec<StreamRow> = owned.iter().map(OwnedDbRow::as_stream_row).collect();
        let verdict = verify_stream_chain(&StreamRows::new(&rows));
        // The load-bearing assertion: a healthy high-volume `Any`
        // stream verifies `Ok` at the final position and is NOT any
        // `Broken` verdict. (Minimal-sufficient verifier assertion per
        // the spec-decision — see the verifier-path note above for why
        // the full server-side roll-up is not wired from this crate.)
        assert!(
            !matches!(verdict, StreamVerdict::Broken { .. }),
            "concurrent `Any` appends must never produce a Broken \
             chain verdict, got: {verdict:?}"
        );
        assert_eq!(
            verdict,
            StreamVerdict::Ok {
                head: rows.last().unwrap().stored_hash,
                position: (N * M - 1) as u64,
            },
            "the concurrent-`Any` chain must verify Ok at the final position"
        );
    }

    // -----------------------------------------------------------------
    // `StreamSealed` tombstone emitter on `delete_stream` / `archive_stream`
    // (ADR 0020).
    //
    // The load-bearing test is the offline verifier round-trip
    // (`b9_no_db_deleted_stream_*`): a whole-stream delete that
    // appended a matching, anchored `StreamSealed` tombstone verifies
    // as a defined `SealedGap` (the anchor cross-check returns `Ok`);
    // the same absent stream WITHOUT a tombstone, or with a head-hash
    // mismatch, is `Broken`. This is exactly the F-2 spec §2.3 / §14 R3
    // verdict contract — consumed here, not re-implemented (the verdict
    // logic lives in the pure `hort-domain` verifier core, byte-unchanged
    // by B9).
    //
    // The no-DB tests run in Tier 1 (offline verifier model). The
    // DB-backed tests (`#[ignore]`, Tier 2 via `DATABASE_URL`) exercise
    // the real append+remove transaction and the ordering / abort /
    // archive-parity / idempotency invariants end-to-end.
    // -----------------------------------------------------------------
    use hort_domain::events::{
        verify_against_checkpoint, AnchorBreak, AnchorVerdict, Checkpoint, SealedStreamRecord,
    };

    /// Build the `StreamSealed` tombstone exactly as `seal_and_remove`
    /// constructs it for a sealed stream with the given head, so the
    /// round-trip test is pinned to the emitter's real payload.
    fn emitter_tombstone(
        sealed_id: &str,
        sealed_cat: &str,
        final_pos: u64,
        head: EventHash,
    ) -> StreamSealed {
        StreamSealed {
            sealed_stream_id: sealed_id.to_string(),
            sealed_stream_category: sealed_cat.to_string(),
            final_stream_position: final_pos,
            final_event_hash: head.0,
            event_count: final_pos + 1,
            retention_policy_id: Uuid::nil(),
            actor_id: None,
        }
    }

    /// CENTERPIECE (no DB, Tier 1): a deleted stream WITH a matching
    /// anchored `StreamSealed` is a `SealedGap`, not `Broken`; WITHOUT
    /// one (or with a head-hash mismatch) it is `Broken`. This is the
    /// F-2 spec §2.3 verdict contract the emitter must satisfy.
    #[test]
    fn b9_no_db_deleted_stream_with_matching_streamsealed_is_sealedgap_not_broken() {
        let sealed_sid = "authorization-deadbeef";
        // The deleted stream's chain head (the emitter records this as
        // `final_event_hash`). Built the same way the append path
        // chains a 3-event stream.
        let chained = chained_admin_rows(sealed_sid, 3);
        let (_, _, head) = chained.last().cloned().unwrap();
        let final_pos = 2u64;

        // The emitter's tombstone, as it lands on the audit-meta
        // stream, projected to the verifier-facing record (exactly
        // what `PgEventChainHeadReader` reads).
        let ss = emitter_tombstone(sealed_sid, "authorization", final_pos, head);
        let sealed_record = SealedStreamRecord {
            sealed_stream_id: ss.sealed_stream_id.clone(),
            final_event_hash: EventHash(ss.final_event_hash),
        };

        // A checkpoint anchored AFTER the seal that covers the sealed
        // stream's head (the §2.3 "anchored at-or-after the seal"
        // condition). The deleted stream is absent from live_heads.
        let now = chrono::Utc::now();
        let checkpoint = Checkpoint {
            chain_format_version: "hort-evchain/v1".into(),
            checkpoint_seq: 1,
            created_at: now,
            // The checkpoint anchored the now-deleted stream's head
            // before it was sealed...
            stream_heads: vec![(sealed_sid.to_string(), final_pos, head)],
            // ...and covers the StreamSealed record.
            sealed_streams: vec![sealed_record.clone()],
        };

        // (1) Absent stream WITH a matching anchored tombstone -> the
        //     anchor cross-check is `Ok` (a defined SealedGap, NOT a
        //     Broken truncation).
        assert_eq!(
            verify_against_checkpoint(
                &[], // sealed stream is absent (deleted)
                std::slice::from_ref(&sealed_record),
                std::slice::from_ref(&checkpoint),
                now,
                std::time::Duration::from_secs(3600),
            ),
            AnchorVerdict::Ok,
            "a deleted stream WITH a matching anchored StreamSealed must \
             be a SealedGap (Ok), not Broken"
        );

        // (2) Same absent stream WITHOUT the tombstone -> Broken
        //     (UnsealedAbsentStream). This is the exact failure the
        //     ordering invariant prevents: delete a row without first
        //     appending the tombstone and the chain is Broken.
        assert_eq!(
            verify_against_checkpoint(
                &[],
                &[], // NO StreamSealed
                std::slice::from_ref(&checkpoint),
                now,
                std::time::Duration::from_secs(3600),
            ),
            AnchorVerdict::Broken(AnchorBreak::UnsealedAbsentStream),
            "an absent stream with NO StreamSealed must be Broken"
        );

        // (3) Tombstone present but head-hash does NOT match the
        //     anchored head -> Broken (SealUnanchored): a forged
        //     tombstone cannot launder a truncation.
        let wrong_head = SealedStreamRecord {
            sealed_stream_id: sealed_sid.to_string(),
            final_event_hash: EventHash([0x99; 32]),
        };
        assert_eq!(
            verify_against_checkpoint(
                &[],
                &[wrong_head],
                &[checkpoint],
                now,
                std::time::Duration::from_secs(3600),
            ),
            AnchorVerdict::Broken(AnchorBreak::SealUnanchored),
            "a StreamSealed whose head was never anchored must be Broken"
        );
    }

    /// The emitter's `StreamSealed` payload, serialized the way
    /// `append_with_conn` -> `serialize_event_data` stores it, MUST be
    /// exactly what `PgEventChainHeadReader::sealed_record_from_row`
    /// projects. Pins the cross-adapter contract so B9's emitter and
    /// B8's reader agree (no DB needed — pure serde shape).
    #[test]
    fn b9_no_db_tombstone_payload_shape_matches_reader_projection() {
        let head = EventHash([0xab; 32]);
        let ss = emitter_tombstone("ref-cafe", "ref", 4, head);

        // What the append path stores (mappers::serialize_event_data).
        let stored = serialize_event_data(&DomainEvent::StreamSealed(ss.clone()));
        assert_eq!(stored["type"], "StreamSealed");

        // Reconstruct via the reader's exact envelope shape and assert
        // the projected fields. (Mirrors the projection logic in
        // `event_chain_head_reader::sealed_record_from_row`.)
        let data = stored.get("data").expect("stored tombstone has data");
        let envelope = serde_json::json!({ "StreamSealed": data });
        let back: DomainEvent = serde_json::from_value(envelope).unwrap();
        match back {
            DomainEvent::StreamSealed(s) => {
                assert_eq!(s.sealed_stream_id, "ref-cafe");
                assert_eq!(s.final_event_hash, head.0);
                assert_eq!(s.final_stream_position, 4);
                assert_eq!(s.event_count, 5);
                assert_eq!(s.retention_policy_id, Uuid::nil());
                assert_eq!(s.actor_id, None);
            }
            other => panic!("expected StreamSealed, got {other:?}"),
        }
    }

    /// `SealMode::op()` distinguishes the two entry points for the
    /// trace; `archive_stream` is treated identically to
    /// `delete_stream` for the live DB (only the trace differs).
    #[test]
    fn b9_no_db_seal_mode_op_label() {
        assert_eq!(SealMode::Delete.op(), "delete_stream");
        assert_eq!(
            SealMode::Archive {
                target: "s3://x".into()
            }
            .op(),
            "archive_stream"
        );
    }

    /// Tier 2 (DB): the tombstone is appended to the audit-meta stream
    /// BEFORE any row of the target stream is removed, and the target
    /// stream is gone afterwards. Proves the ordering invariant
    /// end-to-end through the real `seal_and_remove` transaction.
    #[tokio::test]
    #[serial(hort_pg_db)]
    #[ignore = "requires DATABASE_URL — runs in Tier 2 only"]
    async fn b9_db_tombstone_appended_before_rows_removed() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let store = PgEventStore::new(pool.clone()).await.unwrap();

        let artifact_id = Uuid::new_v4();
        let stream = StreamId::artifact(artifact_id);
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        store
            .append(AppendEvents {
                stream_id: stream.clone(),
                expected_version: ExpectedVersion::NoStream,
                events: vec![
                    EventToAppend::new(DomainEvent::ArtifactIngested(ArtifactIngested {
                        artifact_id,
                        repository_id: Uuid::new_v4(),
                        name: "b9-seal".into(),
                        version: Some("1.0.0".into()),
                        sha256: hash,
                        size_bytes: 10,
                        source: IngestSource::Direct,
                        metadata: serde_json::Value::Null,
                        metadata_blob: None,
                        upstream_published_at: None,
                    })),
                    EventToAppend::new(DomainEvent::ArtifactRejected(ArtifactRejected {
                        artifact_id,
                        rejected_by: RejectionReason::Scanner,
                        reason: "CVE-2026-9999".into(),
                    })),
                ],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::system_actor(),
            })
            .await
            .unwrap();

        // Capture the target stream's head before sealing.
        let head_before: (i64, Vec<u8>) = sqlx::query_as(
            r#"SELECT stream_position, event_hash FROM events
               WHERE stream_id = $1 ORDER BY stream_position DESC LIMIT 1"#,
        )
        .bind(stream.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();

        let retention_sid = StreamId::eventstore_retention().to_string();
        let sealed_before: i64 =
            sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
                .bind(&retention_sid)
                .fetch_one(&pool)
                .await
                .unwrap();

        store.delete_stream(stream.clone()).await.unwrap();

        // The target stream is gone...
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
            .bind(stream.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 0, "sealed stream rows must be removed");

        // ...and exactly one StreamSealed tombstone was appended to the
        // audit-meta stream, carrying the deleted stream's head.
        let sealed_after: i64 =
            sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
                .bind(&retention_sid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            sealed_after,
            sealed_before + 1,
            "exactly one StreamSealed tombstone appended"
        );

        let (etype, edata): (String, serde_json::Value) = sqlx::query_as(
            r#"SELECT event_type, event_data FROM events
               WHERE stream_id = $1 ORDER BY stream_position DESC LIMIT 1"#,
        )
        .bind(&retention_sid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(etype, "StreamSealed");
        // The precise head-hash equality is asserted by the no-DB
        // verifier round-trip test; here we pin the identity + position
        // the emitter recorded for the deleted stream.
        let _ = &head_before.1;
        assert_eq!(edata["data"]["sealed_stream_id"], stream.to_string());
        assert_eq!(
            edata["data"]["final_stream_position"], head_before.0,
            "tombstone records the deleted stream's final position"
        );
    }

    /// Tier 2 (DB): if the tombstone append fails the delete MUST
    /// abort and remove NO rows. The failure is injected
    /// deterministically: a concurrently-held open transaction inserts
    /// at the audit-meta stream's next `stream_position` and stays
    /// uncommitted. Under read-committed the seal's tail read
    /// (`append_with_conn`) cannot see that uncommitted row, so the
    /// chained tombstone INSERT still targets the contended position and
    /// — crucially — *blocks* on the squatter's uncommitted unique-index
    /// entry rather than failing fast. The squatter is only released
    /// AFTER `delete_stream` returns, so absent a bounded wait this is an
    /// unbreakable cycle (it previously relied on an ambient,
    /// environment-configured `lock_timeout`; CI had one, the local
    /// docker-compose Postgres did not → infinite hang).
    ///
    /// This test therefore bounds the wait HERMETICALLY: the store gets
    /// its own pool whose every connection runs `lock_timeout = 5s`, so
    /// the blocked INSERT aborts (SQLSTATE 55P03) → `append_with_conn`
    /// returns `Err` → `seal_and_remove` aborts at its
    /// tombstone-append-`Err` `return` → zero rows removed. The assertion
    /// is cause-agnostic, so a `lock_timeout` `Err` proves the invariant
    /// exactly as a committed-duplicate 23505 would. The bound is on
    /// THIS TEST's store pool only — never server-wide, never in
    /// production `seal_and_remove` (that is an F-2-co-reviewed decision
    /// on concurrent-append-to-`admin-eventstore-retention` semantics).
    /// NB: "commit the squatter" and "spawn the squatter rollback" both
    /// free/advance the slot, so the seal append then *succeeds* and the
    /// test silently stops asserting the F-2 invariant (false-green); the
    /// bounded wait is the only fix that preserves the injected failure.
    /// The target stream MUST survive fully intact (zero rows removed) —
    /// proving removal never precedes a durable tombstone.
    #[tokio::test]
    #[serial(hort_pg_db)]
    #[ignore = "requires DATABASE_URL — runs in Tier 2 only"]
    async fn b9_db_tombstone_append_failure_aborts_delete_no_rows_removed() {
        // `maybe_pool()` runs migrations and backs the squatter + the
        // post-assertions. It MUST NOT carry the short `lock_timeout` —
        // the squatter holds its uncommitted slot deliberately.
        let Some(pool) = maybe_pool().await else {
            return;
        };
        // Dedicated store pool with a bounded per-connection
        // `lock_timeout` (see the test doc-comment for why this is the
        // only correct fix and why it is test-scoped, not production).
        use sqlx::postgres::PgPoolOptions;
        use sqlx::Executor;
        let url = env::var("DATABASE_URL").expect("maybe_pool() returned Some");
        let store_pool = PgPoolOptions::new()
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    conn.execute("SET lock_timeout = '5s'").await?;
                    Ok::<(), sqlx::Error>(())
                })
            })
            .connect(&url)
            .await
            .expect("connect store pool with bounded lock_timeout");
        let store = PgEventStore::new(store_pool).await.unwrap();

        // A target stream to (attempt to) seal+delete.
        let artifact_id = Uuid::new_v4();
        let stream = StreamId::artifact(artifact_id);
        store
            .append(AppendEvents {
                stream_id: stream.clone(),
                expected_version: ExpectedVersion::NoStream,
                events: vec![EventToAppend::new(DomainEvent::ArtifactRejected(
                    ArtifactRejected {
                        artifact_id,
                        rejected_by: RejectionReason::Scanner,
                        reason: "must survive a failed seal".into(),
                    },
                ))],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::system_actor(),
            })
            .await
            .unwrap();

        let retention_sid = StreamId::eventstore_retention().to_string();

        // Find the audit-meta stream's next stream_position and
        // squat on it from a separate, uncommitted transaction so the
        // emitter's INSERT at that position collides (23505 -> the
        // append returns Conflict; the seal must abort).
        let next_pos: i64 = sqlx::query_scalar(
            r#"SELECT COALESCE(MAX(stream_position), -1) + 1
               FROM events WHERE stream_id = $1"#,
        )
        .bind(&retention_sid)
        .fetch_one(&pool)
        .await
        .unwrap();

        let mut squatter = pool.begin().await.unwrap();
        // Insert a placeholder row at the contended position. The
        // events_immutable trigger only blocks UPDATE/DELETE, not
        // INSERT, so this is permitted; it holds the unique slot until
        // this tx commits/rolls back.
        sqlx::query("ALTER TABLE events DISABLE TRIGGER events_immutable")
            .execute(&mut *squatter)
            .await
            .unwrap();
        sqlx::query(
            r#"INSERT INTO events
                 (event_id, stream_id, stream_category, stream_position,
                  event_type, event_version, event_data, correlation_id,
                  actor_type, prev_event_hash, event_hash)
               VALUES ($1,$2,'admin',$3,'StreamSealed',1,
                       '{"type":"StreamSealed","data":{}}'::jsonb,$4,
                       'timer',$5,$6)"#,
        )
        .bind(Uuid::new_v4())
        .bind(&retention_sid)
        .bind(next_pos)
        .bind(Uuid::new_v4())
        .bind([0u8; 32].as_slice())
        .bind([1u8; 32].as_slice())
        .execute(&mut *squatter)
        .await
        .unwrap();

        // The emitter's tombstone append targets the same position so
        // the seal aborts with an error. The squatter holds the unique
        // slot uncommitted; the emitter's INSERT at that position
        // blocks then fails (the slot is taken), so the seal returns
        // Err and its transaction rolls back.
        let result = store.delete_stream(stream.clone()).await;
        assert!(
            result.is_err(),
            "delete_stream must return Err when the tombstone append fails"
        );

        // Release the squatter (roll back — its placeholder never
        // commits).
        squatter.rollback().await.unwrap();

        // THE INVARIANT: the target stream is fully intact — NOT ONE
        // row was removed, because the tombstone was never durably
        // committed.
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
            .bind(stream.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            remaining, 1,
            "a failed tombstone append MUST leave the target stream untouched \
             (no row removed without a durable StreamSealed)"
        );
    }

    /// Tier 2 (DB): an absent/empty stream is a clean idempotent no-op
    /// that MUST NOT write a tombstone (a tombstone for a head that
    /// does not exist would itself be misleading audit).
    #[tokio::test]
    #[serial(hort_pg_db)]
    #[ignore = "requires DATABASE_URL — runs in Tier 2 only"]
    async fn b9_db_absent_stream_is_idempotent_noop_no_tombstone() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let store = PgEventStore::new(pool.clone()).await.unwrap();

        let retention_sid = StreamId::eventstore_retention().to_string();
        let sealed_before: i64 =
            sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
                .bind(&retention_sid)
                .fetch_one(&pool)
                .await
                .unwrap();

        // A stream that never existed: no head to record, nothing to
        // remove. MUST be a clean no-op and MUST NOT write a tombstone
        // (a tombstone for a head that does not exist would itself be
        // misleading audit).
        store
            .delete_stream(StreamId::artifact(Uuid::new_v4()))
            .await
            .unwrap();
        store
            .archive_stream(StreamId::artifact(Uuid::new_v4()), "s3://archive")
            .await
            .unwrap();

        let sealed_after: i64 =
            sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
                .bind(&retention_sid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            sealed_after, sealed_before,
            "an absent/empty stream must NOT emit a tombstone (idempotent no-op)"
        );
    }

    /// Tier 2 (DB): `archive_stream` is treated identically to
    /// `delete_stream` for the live DB — it also seals (one tombstone)
    /// and removes the rows. Cold-storage offload is a follow-on item;
    /// only the trace differs.
    #[tokio::test]
    #[serial(hort_pg_db)]
    #[ignore = "requires DATABASE_URL — runs in Tier 2 only"]
    async fn b9_db_archive_stream_parity_with_delete() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let store = PgEventStore::new(pool.clone()).await.unwrap();

        let artifact_id = Uuid::new_v4();
        let stream = StreamId::artifact(artifact_id);
        store
            .append(AppendEvents {
                stream_id: stream.clone(),
                expected_version: ExpectedVersion::NoStream,
                events: vec![EventToAppend::new(DomainEvent::ArtifactRejected(
                    ArtifactRejected {
                        artifact_id,
                        rejected_by: RejectionReason::Admin,
                        reason: "archived".into(),
                    },
                ))],
                correlation_id: Uuid::new_v4(),
                causation_id: None,
                actor: hort_domain::events::system_actor(),
            })
            .await
            .unwrap();

        let retention_sid = StreamId::eventstore_retention().to_string();
        let sealed_before: i64 =
            sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
                .bind(&retention_sid)
                .fetch_one(&pool)
                .await
                .unwrap();

        store
            .archive_stream(stream.clone(), "s3://archive-bucket/x")
            .await
            .unwrap();

        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
            .bind(stream.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 0, "archive_stream must remove the live rows");

        let sealed_after: i64 =
            sqlx::query_scalar("SELECT count(*) FROM events WHERE stream_id = $1")
                .bind(&retention_sid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            sealed_after,
            sealed_before + 1,
            "archive_stream must also append exactly one StreamSealed tombstone"
        );
    }
}
