//! Authorization-model audit events (NIS2 Art. 21(2)(h); claim-based
//! RBAC — ADR 0012).
//!
//! These events are appended whenever the gitops apply pipeline
//! mutates an authorization-model row. The state itself stays in
//! CRUD (`claim_mappings`, `permission_grants`,
//! `repository_upstream_mappings`); this module's events exist
//! purely as an audit-attribution trail. They do not drive a
//! projection — re-reading them is the audit consumer's job.
//!
//! **Claim-based-RBAC vocabulary (ADR 0012).** The earlier
//! role-and-group-mapping audit surface (`RoleDefined` / `RoleUpdated`
//! / `RoleArchived` / `GroupMappingAdded` / `GroupMappingRemoved` /
//! `GroupMappingUpdated`) is **retired** along with the `roles` /
//! `group_mappings` tables. The additive-claims model replaces it with:
//! - [`ClaimMappingApplied`] / [`ClaimMappingRevoked`] — the
//!   IdP-group → registry-claim mapping audit surface (replaces the
//!   six retired `Role*` / `GroupMapping*` events).
//! - [`PermissionGrantApplied`] / [`PermissionGrantRevoked`] — the
//!   per-grant audit surface, now carrying a sum-typed
//!   [`GrantSubjectRecord`] (`claims` XOR `user`) instead of the
//!   dropped `role_id`. (`PermissionGrantApplied` is the rename of the
//!   earlier `PermissionGrantAdded`.)
//!
//! **Pre-v1.0 — no event-upcasting / compat shim.** The cutover is
//! hard: dev DBs drop the affected tables and re-migrate.
//! There is deliberately no backward-compat
//! deserialiser for the retired payload shapes — a stored
//! `RoleDefined` / `role_id`-shaped `PermissionGrantAdded` JSONB
//! envelope simply fails to deserialise (the variant no longer exists),
//! which is the intended pre-v1.0 behaviour.
//!
//! **Routing — global vs repo-scoped.**
//! - `ClaimMappingApplied` / `ClaimMappingRevoked` are *global*
//!   authorization mutations and land on the single
//!   [`StreamCategory::Authorization`](super::StreamCategory::Authorization)
//!   stream constructed via [`StreamId::authorization`](super::StreamId::authorization).
//! - `PermissionGrantApplied` / `PermissionGrantRevoked` route on the
//!   grant's `repository_id`: `Some(r)` lands on
//!   `StreamCategory::Repository(r)`, `None` lands on the global
//!   `StreamCategory::Authorization` stream.
//! - `RepositoryUpstreamMappingChanged` is always repo-scoped and
//!   lands on `StreamCategory::Repository(repository_id)`.
//!
//! **No actor in payload.** Per the architect-skill anti-patterns
//! checklist, event payloads carry no actor / principal data; the
//! actor is on `EventToAppend.actor` (a [`super::Actor::GitOps`]
//! variant for these events). The `validate()` methods here trivially
//! return `Ok(())` for empty bodies — the diffing layer in
//! `hort-app::ApplyConfigUseCase` enforces the diff invariants.
//!
//! **Secret-ref handling for `RepositoryUpstreamMappingChanged`.** The
//! `previous_secret_ref` / `new_secret_ref` fields carry the
//! [`super::super::ports::secret_port::SecretRef`] **identifier** —
//! `"<source>:<location>"` (e.g. `"env_var:DOCKERHUB_TOKEN"`,
//! `"file:/run/secrets/ghcr-token"`) — never the resolved secret
//! value. This is a load-bearing security invariant:
//! a rotated `secret_ref` is a privilege-changing operation
//! that must land in the audit trail without leaking the credential
//! material. The literal identifier is recorded as-is (operator-
//! disclosed, not hashed) to preserve forensic correlation against
//! the secret-store audit log.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::rbac::{GrantSubject, Permission};
use crate::error::{DomainError, DomainResult};

// ---------------------------------------------------------------------------
// GrantSubjectRecord — serializable audit mirror of GrantSubject
// ---------------------------------------------------------------------------

/// Serializable audit-trail mirror of
/// [`GrantSubject`](crate::entities::rbac::GrantSubject).
///
/// `GrantSubject` itself is deliberately **not** `Serialize` /
/// `Deserialize` (it is server-constructed from validated gitops config
/// or the postgres adapter, never deserialised from request input — see
/// its rustdoc + the architect-skill anti-pattern on domain-type
/// deserialisation in the API layer). The authorization audit events,
/// however, *are* serialised to and from the event store JSONB column,
/// so they carry this thin serialisable mirror instead of the domain
/// type. The wire shape matches the effective-permissions response
/// (`{ "kind": "claims", "required": [..] }` /
/// `{ "kind": "user", "user_id": "…" }`) so the audit log and the admin
/// endpoint speak one subject vocabulary.
///
/// `required_claims` is recorded verbatim (sorted by the apply layer
/// before emission so re-applies are stable) — the claim strings are
/// operator-authored and audit-relevant (an auditor reading the log
/// needs to know which claim set was granted what).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantSubjectRecord {
    /// Subset-match subject — the grant required every claim in
    /// `required`. Non-empty by construction (DB CHECK + apply-time
    /// linter enforce `len() >= 1`).
    Claims { required: Vec<String> },
    /// Identity-match subject — the grant bound directly to a user id
    /// (service accounts and one-off escalations).
    User { user_id: Uuid },
}

impl GrantSubjectRecord {
    /// Project a domain [`GrantSubject`] into its serialisable audit
    /// mirror. The only direction the event layer needs — events are
    /// written from server-constructed grants, never reconstructed back
    /// into a domain `GrantSubject` (the audit trail is read-only).
    pub fn from_subject(subject: &GrantSubject) -> Self {
        match subject {
            GrantSubject::Claims(required) => Self::Claims {
                required: required.clone(),
            },
            GrantSubject::User(user_id) => Self::User { user_id: *user_id },
        }
    }
}

// ---------------------------------------------------------------------------
// ClaimMappingApplied (replaces GroupMapping*/Role*)
// ---------------------------------------------------------------------------

/// An IdP-group → registry-claim mapping was created or updated by
/// gitops apply.
///
/// Replaces the retired `GroupMappingAdded` / `GroupMappingUpdated`
/// (and, transitively, the `Role*` events — there is no `roles` table
/// in the additive-claims model). `idp_group` is the external IdP group
/// claim value; `claim` is the registry claim name it now resolves to.
/// Both are bare strings because an operator reading the audit log needs
/// to know precisely which group now grants which claim. A create and
/// an in-place retarget both emit `ClaimMappingApplied` — the audit
/// consumer correlates by `(idp_group, claim)`, not by a surrogate id,
/// so a single applied/revoked pair is sufficient (no separate
/// `*Updated`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimMappingApplied {
    pub mapping_id: Uuid,
    pub idp_group: String,
    pub claim: String,
}

impl ClaimMappingApplied {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ClaimMappingRevoked
// ---------------------------------------------------------------------------

/// A gitops-managed IdP-group → registry-claim mapping was removed
/// because the desired state no longer declares it.
/// Replaces the retired `GroupMappingRemoved`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimMappingRevoked {
    pub mapping_id: Uuid,
    pub idp_group: String,
    pub claim: String,
}

impl ClaimMappingRevoked {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PermissionGrantApplied (renamed from PermissionGrantAdded;
// payload role_id → subject)
// ---------------------------------------------------------------------------

/// A permission-grant row was created or updated by gitops apply
/// (the rename of the earlier `PermissionGrantAdded`).
///
/// The dropped `role_id` is replaced by a sum-typed [`subject`]
/// ([`GrantSubjectRecord::Claims`] for a claim-set grant,
/// [`GrantSubjectRecord::User`] for a direct-user / service-account
/// grant).
///
/// `repository_id == Some(r)` indicates a repo-scoped grant; the event
/// routes to `StreamCategory::Repository(r)`. `repository_id == None`
/// indicates a global grant; the event routes to the single
/// `StreamCategory::Authorization` stream. Both forms appear in the
/// audit trail under the same payload type so a forensic query that
/// wants every grant change does one `read_category(Authorization)`
/// plus a per-repo `read_stream(Repository(r))` per affected repo.
///
/// [`subject`]: PermissionGrantApplied::subject
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionGrantApplied {
    pub grant_id: Uuid,
    pub subject: GrantSubjectRecord,
    pub permission: Permission,
    /// `None` for a global grant; `Some(_)` for a repo-scoped grant.
    pub repository_id: Option<Uuid>,
}

impl PermissionGrantApplied {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PermissionGrantRevoked (payload role_id → subject)
// ---------------------------------------------------------------------------

/// An existing permission-grant row was removed by gitops apply (the
/// desired state no longer declares the grant). The payload carries the
/// same sum-typed [`GrantSubjectRecord`] as
/// [`PermissionGrantApplied`] (`role_id` dropped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionGrantRevoked {
    pub grant_id: Uuid,
    pub subject: GrantSubjectRecord,
    pub permission: Permission,
    /// `None` for a global grant; `Some(_)` for a repo-scoped grant.
    pub repository_id: Option<Uuid>,
}

impl PermissionGrantRevoked {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RepositoryUpstreamMappingChanged
// ---------------------------------------------------------------------------

/// Discriminator for a [`RepositoryUpstreamMappingChanged`] event.
///
/// Created / Updated / Removed maps directly to the gitops apply
/// plan's create / update / delete buckets. A change with
/// `change == Updated` and identical `previous_*` / `new_*` pairs is
/// possible (the spec digest changed but no observable field did);
/// the audit trail still records the touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpstreamMappingChange {
    Created,
    Updated,
    Removed,
}

/// A `repository_upstream_mappings` row was created, updated, or
/// removed by gitops apply.
///
/// **Why this event matters.** A rotated `secret_ref` is a
/// privilege-changing operation: the upstream pull is now authorised
/// against a different credential. Without this event the rotation
/// lands silently — only the
/// gitops counter ticks; no audit trail records "credential X was
/// swapped for credential Y on date Z".
///
/// **Secret handling — identifier only, never the value.** Both
/// `previous_secret_ref` and `new_secret_ref` carry the
/// [`super::super::ports::secret_port::SecretRef`] **identifier**
/// shaped as `"<source>:<location>"`. The resolved bytes never appear
/// in the payload — that boundary is enforced by a regression test
/// in this module that constructs a ref whose identifier is a known
/// string and asserts the JSONB roundtrip never contains the resolved
/// secret value. `None` indicates the mapping was previously / is now
/// anonymous (no `secret_ref` set).
///
/// **URL fields.** `previous_url` / `new_url` carry the literal
/// `upstream_url` strings. Auditors prefer the full URL over a hash
/// for forensic correlation (cross-checking against an upstream-side
/// access log). `None` is reserved for the Created arm's `previous_url`
/// and the Removed arm's `new_url`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryUpstreamMappingChanged {
    pub mapping_id: Uuid,
    pub repository_id: Uuid,
    pub change: UpstreamMappingChange,
    /// SecretRef identifier (`"<source>:<location>"`) before the
    /// change. `None` when previously anonymous, when the change is
    /// `Created` (no prior state), or when the previous row has no
    /// `secret_ref` set.
    pub previous_secret_ref: Option<String>,
    /// SecretRef identifier (`"<source>:<location>"`) after the
    /// change. `None` when now anonymous or when the change is
    /// `Removed` (no post-state).
    pub new_secret_ref: Option<String>,
    pub previous_url: Option<String>,
    pub new_url: Option<String>,
}

impl RepositoryUpstreamMappingChanged {
    pub fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Task kind allowlist
// ---------------------------------------------------------------------------

/// The v1 task-kind literals — mirrors the SQL CHECK constraint on
/// `jobs.kind` (migration 009; all kinds defined in place there per
/// `feedback_pre_release_migrations`. The prior 012/014/015/016
/// forward-ALTER chain was collapsed back into 009 once it stopped
/// earning its keep — DB-wipe-per-alpha makes the in-place edit free
/// and a single defining migration is easier to read than a chain).
/// `TaskInvoked::validate` and `TaskFailed::validate` reject any kind not
/// in this set.
pub const VALID_TASK_KINDS: &[&str] = &[
    "scan",
    "cron-rescan-tick",
    "advisory-watch-tick",
    "retention-evaluate",
    "retention-purge",
    "eventstore-archive",
    "staging-sweep",
    "noop",
    // Consumed by `ServiceAccountRotationHandler` in the worker.
    "service-account-rotation",
    // Audit-checkpoint emission — consumed by
    // `EventstoreCheckpointHandler` in the worker (assembles +
    // Ed25519-signs + S3-Object-Lock-anchors the signed
    // checkpoint — the external tamper-evidence anchor for the
    // event log).
    "eventstore-checkpoint",
    // Replay-guard seen-set TTL cleanup — consumed
    // by `ReplaySeenPruneHandler` in the worker (`DELETE FROM
    // jwt_replay_seen WHERE expires_at < now()` — the periodic
    // delete-expired sweep, shipped **default-ENABLED**).
    "replay-seen-prune",
    // Quarantine-by-default release sweep — consumed
    // by `QuarantineReleaseSweepHandler` in the worker. Hands a
    // batch-limited candidate list (artifacts whose computed
    // `quarantine_window_start + effective_duration <= now()`)
    // to `QuarantineUseCase::release_expired`,
    // which enforces the fail-closed release predicate (ADR 0007)
    // per artifact. Non-destructive — the kind carries no
    // authority of its own.
    "quarantine-release-sweep",
    // Seed-import cutover path — consumed by
    // `SeedImportHandler` in the worker. The `hort-server seed-import`
    // subcommand parses an operator-supplied TSV input and enqueues
    // one row of this kind carrying the dependency set in
    // `params.items`. The handler delegates to `SeedImportUseCase` to
    // bulk-register each item with a backdated
    // `quarantine_window_start` anchor (the *time* gate
    // is already elapsed at import; the scan gate still applies). The
    // run summary lands in `result_summary` as
    // `{ total, registered, already_imported, errors }`.
    "seed-import",
    // Prefetch scheduled trigger (see
    // `docs/architecture/explanation/prefetch-pipeline.md`) — consumed by
    // `PrefetchTickHandler` in the worker. The Helm CronJob (default
    // disabled, since prefetch is opt-in per-repo) runs `hort-server
    // enqueue-prefetch-tick` to insert one row of this kind via the
    // runtime DSN; the worker picks it up and dispatches to the
    // handler. The handler walks every repository whose
    // `prefetch_policy.enabled = true` AND
    // `prefetch_policy.triggers.contains(Scheduled)`, and for each
    // *tracked package* (any package with at least one row in the
    // `artifacts` projection for that repo) invokes the
    // `PrefetchUseCase::plan` planner with `trigger = Scheduled`. The
    // kind is **non-destructive** — the planner emits at most an
    // intent (per-version metric ticks); the actual pull-through is
    // the format crate's job and rides the same authorities as a
    // client-driven pull. The run summary lands in `result_summary`
    // as `{ repos_walked, packages_walked, prefetches_planned,
    // skipped_disabled, skipped_no_trigger }`.
    "prefetch-tick",
    // Transitive prefetch cascade — per-version
    // ingest unit — consumed by `PrefetchIngestHandler` in the
    // worker. Enqueued by `PrefetchDependenciesHandler` for each
    // not-already-held `(repo, package, version)` discovered in the
    // walk. The kind exists as a dedicated reservation so the L3
    // dedup partial unique index on `jobs.target_key` (migration 009
    // — `jobs_prefetch_unique`) can scope itself to "an in-flight
    // ingest for THIS coordinate" without conflating with the
    // cascade-driver `prefetch-dependencies` rows. Non-destructive
    // — drives the same pull-through path as a client-driven pull
    // (same PullDedup gate, same scan policy, same
    // quarantine window). Carries low `priority` (= 0 default)
    // so manual/cron tasks drain first.
    "prefetch",
    // Transitive prefetch cascade — driver —
    // consumed by `PrefetchDependenciesHandler` in the worker. Per
    // ingested artifact, reads the manifest via
    // `FormatHandler::extract_dependency_specs`, resolves
    // each declared runtime-dep range via
    // `FormatHandler::resolve_range_max`, and for each
    // not-already-held dependency enqueues a `prefetch` ingest row +
    // a child `prefetch-dependencies` row (bounded by
    // `prefetch_policy.transitive_depth`). The cascade is stateless
    // — a failed walk leaves a terminal row; the next pull of any
    // dependent re-derives the missing subtree from the `artifacts`
    // projection. Dedup is the L3 partial unique on `target_key`
    // (`jobs_prefetch_dependencies_unique`) — concurrent re-walks
    // collapse via `ON CONFLICT (target_key) DO NOTHING`. Low
    // priority for the same reason as `prefetch`.
    "prefetch-dependencies",
    // Terminal `prefetch%` row retention sweep.
    // Consumed by `PrefetchRowRetentionSweepHandler` in
    // the worker. Periodically deletes `kind LIKE 'prefetch%'` rows
    // whose `status IN ('completed', 'failed')` and whose
    // `updated_at < now() - $horizon` (default 7 days). The sweep
    // bounds `jobs`-table growth under cascade load (a closure-warm
    // enqueues thousands of rows; without the sweep the table grows
    // unbounded). Non-destructive at the artifact level — only
    // garbage-collects historical job rows; no artifact / event /
    // scan data is touched. Pairs with the per-table autovacuum
    // tuning on `public.jobs` (migration 009) — the sweep deletes
    // the rows, autovacuum reclaims the page space.
    "prefetch-row-retention-sweep",
    // PEP 658 wheel-metadata backfill — consumed by
    // `WheelMetadataBackfillHandler` in the worker. The ingest
    // hook extracts wheel METADATA into CAS + a
    // `kind = "wheel_metadata"` ContentReference row for newly-ingested
    // wheels; wheels ingested before the hook existed have no such
    // row, so the simple-index
    // emits no PEP 658 advertisement for them and pip falls
    // back to whole-wheel download. This task is the operator-opt-in
    // retrofit: it walks PyPI wheel artifacts whose `content_references`
    // row of kind `wheel_metadata` is absent (the inverse of the ingest
    // hook's output), streams each wheel from CAS, invokes
    // `FormatHandler::extract_wheel_metadata_bytes`, and on `Some(bytes)`
    // persists the bytes to CAS + inserts the ContentReference row. Non-
    // destructive — no artifact / event mutation; only derived-projection
    // rows are added. Operators run it once per deployment after upgrade;
    // the Helm CronJob ships default-disabled (no urgency to retrofit —
    // pip's fallback is correct, just slower). Params:
    // `{"batch_size": <int>}` (default 100, capped at 1000 per
    // invocation). Run summary in `result_summary`:
    // `{ artifacts_walked, metadata_extracted, skipped_no_metadata,
    // errors }`.
    "wheel-metadata-backfill",
    // Sigstore/cosign provenance verification (ADR 0027) — consumed
    // by `ProvenanceVerifyHandler` in the worker. Enqueued by the ingest
    // path (`IngestUseCase`) carrying `params.artifact_id`, **only when**
    // the resolved `ScanPolicy.provenance_mode != Off` AND some registered
    // `ProvenancePort` `applies_to(format)` (non-OCI ingests
    // under the Tier-1 cosign-only set are zero-overhead; no row for a
    // format no verifier can act on). The handler delegates to
    // `ProvenanceOrchestrationUseCase`, which fetches the attestation
    // bundles off the OCI Referrers surface, streams the CAS preimage,
    // dispatches the cosign verifier, and threads the folded verdict
    // through `Artifact::complete_provenance`. **Non-destructive** — it
    // only records a `ProvenanceVerified` / `ProvenanceRejected` verdict
    // (each subject to the fail-closed release gate — ADR 0007); it never
    // deletes or releases
    // an artifact on its own. Run summary in `result_summary`:
    // `{ "result": "verified" | "rejected:<reason>" |
    // "no_attestation" | "skipped:off" | "skipped:no_verifier" }`.
    "provenance-verify",
    // Scanner-worker registry housekeeping — consumed by
    // `ScannerRegistryPruneHandler` in the worker. Periodically deletes
    // `scanner_registry` rows whose `last_heartbeat < now() - $horizon`
    // (default 7 days): pod churn (rollouts, HPA scaling) leaves a row per
    // retired `worker_id` that never heartbeats again, so without this the
    // worker-coordination table grows without bound. **Non-destructive** —
    // a live worker heartbeats every 60 s so it is never deleted; only
    // long-dead rows are GC'd, and a worker that comes back simply
    // re-registers. Mirrors `prefetch-row-retention-sweep` (the other
    // table-growth sweep). Run summary: `{ "deleted_rows": <n> }`.
    "scanner-registry-prune",
];

// ---------------------------------------------------------------------------
// Destructive task-kind tier (ADR 0028)
// ---------------------------------------------------------------------------

/// The task kinds whose invocation is **irreversible** and therefore
/// requires strictly more authority than an ordinary kind.
///
/// **Rationale-reversal breadcrumb (recorded, not silent).** The
/// admin-task framework's original rationale — "task kinds are not
/// security-tier-distinct; one coarse `Permission::AdminTaskInvoke`
/// gates every kind" — was written before `retention-purge` (permanent
/// artifact deletion), `eventstore-archive` (audit-stream
/// truncation/archive), and `retention-evaluate` (drives the two above)
/// existed. A subsequent security audit reversed that rationale: the
/// destructive trio is security-tier-distinct from `noop`/`scan`/etc.
/// The reversal is recorded here (the place the next deferred-items
/// sweep finds it) as a decision, not silence. The set is **closed at
/// exactly these three**; adding a fourth is a scope-creep regression
/// and must be treated as re-opening the audit finding. The same kinds
/// also carry the durable idempotency layer (ADR 0028).
pub const DESTRUCTIVE_TASK_KINDS: &[&str] = &[
    "retention-evaluate",
    "retention-purge",
    "eventstore-archive",
];

/// The single registry **claim** a caller must additionally carry to
/// invoke a [`DESTRUCTIVE_TASK_KINDS`] kind (expressed via the
/// additive-claims model — ADR 0012).
///
/// **Why a claim, not a new `Permission` enum variant.** The
/// claim-based-RBAC model (ADR 0012) keeps the `Permission` /
/// `GrantSubject` taxonomies closed — a third `GrantSubject`
/// variant is forbidden. A single well-named claim
/// (`task:destructive`) is the simplest expression that lets operators
/// grant destructive-task authority **distinctly** from ordinary
/// admin-task authority (`Permission::AdminTaskInvoke`) without touching
/// the closed `Permission`/`GrantSubject` taxonomies: an operator maps an
/// IdP group → the `task:destructive` claim (or binds it on a
/// `User`-subject service-account grant) exactly as any other claim. The
/// gate is `AdminTaskInvoke` **AND** this claim — the destructive caller
/// needs strictly more authority than a `noop` caller, by construction.
pub const DESTRUCTIVE_TASK_CLAIM: &str = "task:destructive";

/// Classify a task `kind` string as destructive (irreversible — requires
/// the [`DESTRUCTIVE_TASK_CLAIM`] in addition to
/// `Permission::AdminTaskInvoke`) versus ordinary (the existing
/// `AdminTaskInvoke`-only gate, zero behaviour change).
///
/// Pure, zero-I/O, total: an unknown / empty `kind` is **not**
/// destructive (it is rejected upstream by the `VALID_TASK_KINDS`
/// allowlist; the classifier must never over-claim authority for an
/// input it does not recognise — fail-safe-by-construction).
#[must_use]
pub fn task_kind_is_destructive(kind: &str) -> bool {
    DESTRUCTIVE_TASK_KINDS.contains(&kind)
}

// ---------------------------------------------------------------------------
// TaskInvoked (admin-endpoint audit)
// ---------------------------------------------------------------------------

/// An admin-task enqueue was accepted by `TaskUseCase::enqueue`.
///
/// Emitted on [`StreamCategory::Authorization`](super::super::events::StreamCategory::Authorization)
/// as part of the admin-endpoint audit-coverage rule —
/// every admin action that mutates system state must produce an immutable
/// audit-trail event.
///
/// **`params_digest`** is the lowercase-hex BLAKE3-256 hash of the
/// canonical JSON serialisation of the task's `params` object. The full
/// params are NOT stored in the event (they may contain operator-sensitive
/// values); the digest is sufficient for forensic correlation against the
/// `jobs` row. The 64-hex-char invariant mirrors BLAKE3-256's 32-byte
/// output.
///
/// **No actor in payload.** The actor is carried on `EventToAppend.actor`
/// per the existing authz-events convention.
///
/// **`duplicate_of`** (ADR 0028):
/// `Some(existing_job_id)` when this `TaskInvoked` was emitted on the
/// `EnqueueOutcome::Duplicate` branch (the DB partial-unique-index dedup
/// hit fired). `None` on the common `Enqueued` branch. The wire form
/// carries `#[serde(default)]` so the event-store JSONB deserialise path
/// reads `None` for events appended **before** the field existed —
/// dropping the default would break replay/read of every older
/// `TaskInvoked` row. `task_job_id` continues to identify the row that
/// was *logically* enqueued (the existing one on the Duplicate branch);
/// `duplicate_of` is the flag reviewers grep for when reconstructing
/// dedup decisions from the audit stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskInvoked {
    /// `jobs.id` of the newly-inserted row.
    pub task_job_id: Uuid,
    /// One of a v1 kind literal (see `VALID_TASK_KINDS`).
    pub kind: String,
    /// Lowercase-hex BLAKE3-256 hash of `serde_json::to_vec(&params)`.
    /// 64 hex chars (32 bytes).
    pub params_digest: String,
    /// `Some(existing_job_id)` if this enqueue was deduped against an
    /// existing row by the `jobs_idempotency_key_uq` partial-unique
    /// index (the DB-layer dedup hit — ADR 0028).
    /// `None` for a fresh enqueue.
    ///
    /// Carries `#[serde(default)]` so older audit rows that
    /// lack the field deserialise cleanly
    /// (load-bearing for event-store JSONB replay).
    #[serde(default)]
    pub duplicate_of: Option<Uuid>,
}

impl TaskInvoked {
    /// Compute the BLAKE3-256 digest of `params` in the canonical form
    /// expected by the `params_digest` field. Callers use this helper
    /// to populate the field rather than re-implementing the hash.
    pub fn compute_params_digest(params: &serde_json::Value) -> String {
        let bytes = serde_json::to_vec(params).unwrap_or_default();
        let hash = blake3::hash(&bytes);
        hash.to_hex().to_string()
    }

    /// Validate the payload.
    ///
    /// - `kind` must be one of a v1 literal.
    /// - `params_digest` must be a 64-character lowercase hex string.
    pub fn validate(&self) -> DomainResult<()> {
        if !VALID_TASK_KINDS.contains(&self.kind.as_str()) {
            return Err(DomainError::Validation(format!(
                "TaskInvoked: unknown task kind {:?}; expected one of {:?}",
                self.kind, VALID_TASK_KINDS
            )));
        }
        validate_params_digest(&self.params_digest)
    }
}

// ---------------------------------------------------------------------------
// TaskFailed (admin-endpoint audit)
// ---------------------------------------------------------------------------

/// An admin-task failed. Emitted on
/// [`StreamCategory::Authorization`](super::super::events::StreamCategory::Authorization).
///
/// **Emission sources:**
///
/// 1. *Compensating-delete path in `TaskUseCase::enqueue`* — if the
///    `jobs` INSERT succeeds but the `TaskInvoked` event-store append
///    fails, and the compensating `delete_job` also fails, the system is
///    in a temporarily inconsistent state. No
///    `TaskFailed` is actually emitted on this path (the event store is
///    unavailable); `tracing::error!` is written instead and the caller
///    returns an error. Operators can identify orphaned rows by looking
///    for `status='pending'` jobs with no corresponding `TaskInvoked`
///    event on the authorization stream.
///
/// 2. *Worker terminal-failure path* — the
///    worker dispatcher emits `TaskFailed` when a `TaskHandler` returns
///    a terminal error. `final_attempt = true` distinguishes "we will
///    not retry" from `final_attempt = false` ("we will retry on next
///    claim").
///
/// Only infrastructure failures after the RBAC check produce this event —
/// RBAC denial is logged at `info!` and returns `AppError::Forbidden`
/// without appending any event (the denial itself IS the audit fact, visible
/// in the RBAC evaluator metrics).
///
/// **`reason`** is capped at 4,096 bytes to mirror the
/// `jobs.last_error` column cap and prevent unbounded payloads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskFailed {
    /// `jobs.id` of the failed row.
    pub task_job_id: Uuid,
    /// One of a v1 kind literal (see `VALID_TASK_KINDS`).
    pub kind: String,
    /// Human-readable failure description. ≤ 4,096 bytes.
    pub reason: String,
    /// `true` when the worker will not attempt this job again (terminal
    /// failure); `false` when the job will be retried on the next claim
    /// cycle. Always `false` for failures emitted before the worker
    /// terminal-failure path shipped.
    pub final_attempt: bool,
}

impl TaskFailed {
    /// Validate the payload.
    ///
    /// - `kind` must be one of a v1 literal.
    /// - `reason` must be ≤ 4,096 bytes.
    /// - `final_attempt` is a boolean — no range validation required.
    pub fn validate(&self) -> DomainResult<()> {
        if !VALID_TASK_KINDS.contains(&self.kind.as_str()) {
            return Err(DomainError::Validation(format!(
                "TaskFailed: unknown task kind {:?}; expected one of {:?}",
                self.kind, VALID_TASK_KINDS
            )));
        }
        const MAX_REASON_BYTES: usize = 4096;
        if self.reason.len() > MAX_REASON_BYTES {
            return Err(DomainError::Validation(format!(
                "TaskFailed: reason exceeds {MAX_REASON_BYTES}-byte cap ({} bytes)",
                self.reason.len()
            )));
        }
        Ok(())
    }
}

/// Validate that `s` is a 64-character lowercase hex string (BLAKE3-256 output).
fn validate_params_digest(s: &str) -> DomainResult<()> {
    if s.len() != 64 {
        return Err(DomainError::Validation(format!(
            "params_digest must be 64 hex chars (BLAKE3-256), got {} chars",
            s.len()
        )));
    }
    if !s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return Err(DomainError::Validation(
            "params_digest must be lowercase hex (0-9, a-f only)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Uuid {
        Uuid::new_v4()
    }

    // GrantSubjectRecord -----------------------------------------------------

    #[test]
    fn grant_subject_record_from_claims_subject() {
        let s = GrantSubject::Claims(vec!["developer".into(), "team-alpha".into()]);
        let r = GrantSubjectRecord::from_subject(&s);
        assert_eq!(
            r,
            GrantSubjectRecord::Claims {
                required: vec!["developer".into(), "team-alpha".into()],
            }
        );
    }

    #[test]
    fn grant_subject_record_from_user_subject() {
        let uid = id();
        let s = GrantSubject::User(uid);
        let r = GrantSubjectRecord::from_subject(&s);
        assert_eq!(r, GrantSubjectRecord::User { user_id: uid });
    }

    #[test]
    fn grant_subject_record_claims_wire_shape_is_tagged() {
        // Wire contract: `{ "kind": "claims", "required": [..] }`.
        // The audit log + the effective-permissions endpoint speak one
        // subject vocabulary; a tag rename here breaks both consumers.
        let r = GrantSubjectRecord::Claims {
            required: vec!["admin".into()],
        };
        let json = serde_json::to_string(&r).expect("serialise");
        assert!(json.contains("\"kind\":\"claims\""), "got: {json}");
        assert!(json.contains("\"required\":[\"admin\"]"), "got: {json}");
        let back: GrantSubjectRecord = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, r);
    }

    #[test]
    fn grant_subject_record_user_wire_shape_is_tagged() {
        let uid = Uuid::nil();
        let r = GrantSubjectRecord::User { user_id: uid };
        let json = serde_json::to_string(&r).expect("serialise");
        assert!(json.contains("\"kind\":\"user\""), "got: {json}");
        assert!(json.contains("\"user_id\""), "got: {json}");
        let back: GrantSubjectRecord = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, r);
    }

    // ClaimMappingApplied ----------------------------------------------------

    #[test]
    fn claim_mapping_applied_validate_ok() {
        let e = ClaimMappingApplied {
            mapping_id: id(),
            idp_group: "ops-team".into(),
            claim: "admin".into(),
        };
        assert!(e.validate().is_ok());
    }

    #[test]
    fn claim_mapping_applied_round_trip() {
        let e = ClaimMappingApplied {
            mapping_id: id(),
            idp_group: "engineering".into(),
            claim: "developer".into(),
        };
        let json = serde_json::to_string(&e).expect("serialise");
        let back: ClaimMappingApplied = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, e);
    }

    // ClaimMappingRevoked ----------------------------------------------------

    #[test]
    fn claim_mapping_revoked_validate_ok() {
        let e = ClaimMappingRevoked {
            mapping_id: id(),
            idp_group: "ops-team".into(),
            claim: "admin".into(),
        };
        assert!(e.validate().is_ok());
    }

    #[test]
    fn claim_mapping_revoked_round_trip() {
        let e = ClaimMappingRevoked {
            mapping_id: id(),
            idp_group: "engineering".into(),
            claim: "developer".into(),
        };
        let json = serde_json::to_string(&e).expect("serialise");
        let back: ClaimMappingRevoked = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, e);
    }

    // PermissionGrantApplied -------------------------------------------------

    #[test]
    fn permission_grant_applied_validate_ok_claims_global() {
        let e = PermissionGrantApplied {
            grant_id: id(),
            subject: GrantSubjectRecord::Claims {
                required: vec!["admin".into()],
            },
            permission: Permission::Read,
            repository_id: None,
        };
        assert!(e.validate().is_ok());
    }

    #[test]
    fn permission_grant_applied_validate_ok_user_repo_scoped() {
        let e = PermissionGrantApplied {
            grant_id: id(),
            subject: GrantSubjectRecord::User { user_id: id() },
            permission: Permission::Write,
            repository_id: Some(id()),
        };
        assert!(e.validate().is_ok());
    }

    #[test]
    fn permission_grant_applied_round_trip_carries_subject() {
        // JSONB roundtrip pinning — same path the Postgres event-store
        // adapter uses (`serde_json::to_value` / `from_value`). A serde
        // drift on the new `subject` field surfaces here before the
        // adapter mapper round-trip test.
        let e = PermissionGrantApplied {
            grant_id: id(),
            subject: GrantSubjectRecord::Claims {
                required: vec!["developer".into(), "team-alpha".into()],
            },
            permission: Permission::Write,
            repository_id: Some(id()),
        };
        let json = serde_json::to_string(&e).expect("serialise");
        assert!(!json.contains("role_id"), "role_id retired: {json}");
        let back: PermissionGrantApplied = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, e);
    }

    // PermissionGrantRevoked -------------------------------------------------

    #[test]
    fn permission_grant_revoked_validate_ok_claims_global() {
        let e = PermissionGrantRevoked {
            grant_id: id(),
            subject: GrantSubjectRecord::Claims {
                required: vec!["admin".into()],
            },
            permission: Permission::Admin,
            repository_id: None,
        };
        assert!(e.validate().is_ok());
    }

    #[test]
    fn permission_grant_revoked_round_trip_user_subject() {
        let e = PermissionGrantRevoked {
            grant_id: id(),
            subject: GrantSubjectRecord::User { user_id: id() },
            permission: Permission::Read,
            repository_id: Some(id()),
        };
        let json = serde_json::to_string(&e).expect("serialise");
        let back: PermissionGrantRevoked = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, e);
    }

    // UpstreamMappingChange --------------------------------------------------

    #[test]
    fn upstream_mapping_change_round_trips_each_variant() {
        // Pin the wire form of each variant — the audit consumer
        // pattern-matches on these strings; a future rename here is a
        // breaking change to the audit contract.
        for (variant, expected) in [
            (UpstreamMappingChange::Created, "\"Created\""),
            (UpstreamMappingChange::Updated, "\"Updated\""),
            (UpstreamMappingChange::Removed, "\"Removed\""),
        ] {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, expected, "wire form drift for {variant:?}");
            let back: UpstreamMappingChange = serde_json::from_str(&s).unwrap();
            assert_eq!(back, variant);
        }
    }

    // RepositoryUpstreamMappingChanged ---------------------------------------

    #[test]
    fn upstream_mapping_changed_validate_ok_created() {
        let e = RepositoryUpstreamMappingChanged {
            mapping_id: id(),
            repository_id: id(),
            change: UpstreamMappingChange::Created,
            previous_secret_ref: None,
            new_secret_ref: Some("env_var:DOCKERHUB_TOKEN".into()),
            previous_url: None,
            new_url: Some("https://registry-1.docker.io".into()),
        };
        assert!(e.validate().is_ok());
    }

    #[test]
    fn upstream_mapping_changed_validate_ok_updated_rotation() {
        let e = RepositoryUpstreamMappingChanged {
            mapping_id: id(),
            repository_id: id(),
            change: UpstreamMappingChange::Updated,
            previous_secret_ref: Some("env_var:DOCKERHUB_TOKEN_V1".into()),
            new_secret_ref: Some("env_var:DOCKERHUB_TOKEN_V2".into()),
            previous_url: Some("https://registry-1.docker.io".into()),
            new_url: Some("https://registry-1.docker.io".into()),
        };
        assert!(e.validate().is_ok());
    }

    #[test]
    fn upstream_mapping_changed_validate_ok_removed() {
        let e = RepositoryUpstreamMappingChanged {
            mapping_id: id(),
            repository_id: id(),
            change: UpstreamMappingChange::Removed,
            previous_secret_ref: Some("file:/run/secrets/ghcr".into()),
            new_secret_ref: None,
            previous_url: Some("https://ghcr.io".into()),
            new_url: None,
        };
        assert!(e.validate().is_ok());
    }

    // -- LOAD-BEARING SECURITY GATE -------------------------------------------
    //
    // `RepositoryUpstreamMappingChanged` payloads MUST carry the secret-ref
    // *identifier*, never the resolved secret value. A regression that lets
    // the resolved bytes leak into the JSONB payload would silently put
    // credentials into the audit log. This test pins that invariant by
    // serialising a payload whose identifier is a known sentinel
    // (`"redacted-name"`) and asserting:
    //
    //   - the identifier IS present in the wire form (positive case — the
    //     audit trail must surface "which credential ref was rotated to
    //     which"),
    //   - the resolved value sentinel `"S3CRET-DO-NOT-LEAK"` is NOT
    //     present in the wire form (negative case — the resolved bytes
    //     must never appear in the event).
    //
    // The author of any future change to this struct or its serialisation
    // path is on notice: deliberately leaking the value (e.g. by switching
    // the field type from `Option<String>` to a struct that carries the
    // resolved bytes) trips this test before review can.

    /// Red-phase demonstration test — the security gate's assertion
    /// shape MUST catch a deliberate leak. This test simulates the
    /// regression by serialising a payload whose `new_secret_ref`
    /// field carries the resolved value rather than the identifier.
    /// The negation expectation is that this test FAILS — proving the
    /// real `upstream_mapping_changed_payload_records_identifier_not_value`
    /// test would also fail under the same leak. We invert via
    /// `should_panic` so the test passes when the leak is present.
    ///
    /// Run-time behaviour: the inner `assert!` MUST panic. If the
    /// gate ever stops detecting leaks, this test stops panicking and
    /// fails — surfacing the regression that the regression test went
    /// silent. (Pairs with the live security gate below.)
    #[test]
    #[should_panic(expected = "SECURITY REGRESSION")]
    fn red_phase_demo_regression_test_catches_a_deliberate_leak() {
        const RESOLVED_VALUE: &str = "S3CRET-DO-NOT-LEAK";
        // Deliberate leak: stuff the resolved value into the
        // identifier slot. Real code never does this — the apply
        // pipeline writes `<source>:<location>`. The gate's assertion
        // shape is what we exercise here.
        let event = RepositoryUpstreamMappingChanged {
            mapping_id: id(),
            repository_id: id(),
            change: UpstreamMappingChange::Updated,
            previous_secret_ref: Some(RESOLVED_VALUE.into()),
            new_secret_ref: Some(RESOLVED_VALUE.into()),
            previous_url: Some("https://example.com".into()),
            new_url: Some("https://example.com".into()),
        };
        let json = serde_json::to_string(&event).expect("serialise");
        // Mirror the assertion in the live gate verbatim — the panic
        // message starts with "SECURITY REGRESSION:" which is what
        // `should_panic(expected = ...)` matches against.
        assert!(
            !json.contains(RESOLVED_VALUE),
            "SECURITY REGRESSION: payload contains resolved secret value \
             `{RESOLVED_VALUE}`; identifier-only invariant violated. \
             Full payload: {json}",
        );
    }

    #[test]
    fn upstream_mapping_changed_payload_records_identifier_not_value() {
        // Identifier — the operator-visible reference name. The literal
        // colon-separated `<source>:<location>` form is what the apply
        // pipeline writes into the payload.
        const IDENTIFIER: &str = "redacted-name";
        // Resolved value — what `SecretPort::resolve` would return. The
        // payload MUST NOT contain this byte sequence.
        const RESOLVED_VALUE: &str = "S3CRET-DO-NOT-LEAK";
        // Sanity: the seeded value is non-trivially distinct from the
        // identifier, so a substring check is meaningful.
        assert_ne!(IDENTIFIER, RESOLVED_VALUE);

        let event = RepositoryUpstreamMappingChanged {
            mapping_id: id(),
            repository_id: id(),
            change: UpstreamMappingChange::Updated,
            previous_secret_ref: Some(IDENTIFIER.into()),
            new_secret_ref: Some(IDENTIFIER.into()),
            previous_url: Some("https://example.com".into()),
            new_url: Some("https://example.com".into()),
        };
        // JSONB roundtrip via serde_json — same path the Postgres event
        // store adapter uses (`serde_json::to_value(&event)?` →
        // `sqlx::types::Json(payload)`). Asserting on the string form
        // directly catches both `to_value` and `to_string` drift.
        let json = serde_json::to_string(&event).expect("serialise");
        assert!(
            json.contains(IDENTIFIER),
            "expected payload to carry the SecretRef identifier `{IDENTIFIER}`; \
             got: {json}",
        );
        assert!(
            !json.contains(RESOLVED_VALUE),
            "SECURITY REGRESSION: payload contains resolved secret value \
             `{RESOLVED_VALUE}`; identifier-only invariant violated. \
             Full payload: {json}",
        );

        // Defence-in-depth: round-trip through a serde_json::Value too,
        // since the Postgres adapter uses `to_value` rather than
        // `to_string`. A leak in the value form would be missed by the
        // string check above on a hypothetical custom Serialize impl.
        let value = serde_json::to_value(&event).expect("to_value");
        let value_str = value.to_string();
        assert!(value_str.contains(IDENTIFIER));
        assert!(
            !value_str.contains(RESOLVED_VALUE),
            "SECURITY REGRESSION (Value path): {value_str}",
        );
    }

    #[test]
    fn upstream_mapping_changed_anonymous_round_trip() {
        // `None` on every secret_ref / url field round-trips correctly —
        // covers the boundary where a mapping had no credential and one
        // is now added (or vice versa).
        let event = RepositoryUpstreamMappingChanged {
            mapping_id: id(),
            repository_id: id(),
            change: UpstreamMappingChange::Created,
            previous_secret_ref: None,
            new_secret_ref: None,
            previous_url: None,
            new_url: Some("https://example.com".into()),
        };
        let json = serde_json::to_string(&event).expect("serialise");
        let back: RepositoryUpstreamMappingChanged =
            serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, event);
    }

    // -- TaskInvoked ---------------------------------------------------------

    fn sample_digest() -> String {
        // A valid 64-char lowercase hex string (all zeros).
        "0".repeat(64)
    }

    #[test]
    fn task_invoked_validate_ok_each_valid_kind() {
        for kind in VALID_TASK_KINDS {
            let e = TaskInvoked {
                task_job_id: id(),
                kind: kind.to_string(),
                params_digest: sample_digest(),
                duplicate_of: None,
            };
            assert!(
                e.validate().is_ok(),
                "validate failed for valid kind {kind:?}"
            );
        }
    }

    #[test]
    fn task_invoked_validate_rejects_unknown_kind() {
        let e = TaskInvoked {
            task_job_id: id(),
            kind: "bogus-kind".into(),
            params_digest: sample_digest(),
            duplicate_of: None,
        };
        match e.validate() {
            Err(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("bogus-kind"),
                    "expected kind in message: {msg}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn task_invoked_validate_rejects_wrong_length_digest() {
        let e = TaskInvoked {
            task_job_id: id(),
            kind: "noop".into(),
            params_digest: "abc123".into(), // too short
            duplicate_of: None,
        };
        match e.validate() {
            Err(DomainError::Validation(msg)) => {
                assert!(msg.contains("64"), "expected 64 in message: {msg}");
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn task_invoked_validate_rejects_uppercase_digest() {
        // 64-char but contains uppercase — not valid lowercase hex.
        let e = TaskInvoked {
            task_job_id: id(),
            kind: "noop".into(),
            params_digest: "A".repeat(64),
            duplicate_of: None,
        };
        match e.validate() {
            Err(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("lowercase"),
                    "expected lowercase in message: {msg}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn task_invoked_compute_params_digest_returns_64_lowercase_hex() {
        let params = serde_json::json!({"key": "value"});
        let digest = TaskInvoked::compute_params_digest(&params);
        assert_eq!(digest.len(), 64, "digest should be 64 chars");
        assert!(
            digest.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "digest should be lowercase hex: {digest}"
        );
        // Validate passes with the computed digest.
        let e = TaskInvoked {
            task_job_id: id(),
            kind: "noop".into(),
            params_digest: digest,
            duplicate_of: None,
        };
        assert!(e.validate().is_ok());
    }

    #[test]
    fn task_invoked_round_trip() {
        let e = TaskInvoked {
            task_job_id: id(),
            kind: "scan".into(),
            params_digest: sample_digest(),
            duplicate_of: None,
        };
        let json = serde_json::to_string(&e).expect("serialise");
        let back: TaskInvoked = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, e);
    }

    /// Load-bearing (ADR 0028): events appended before the
    /// `duplicate_of` field existed lack it in the event-store JSONB
    /// column. Without `#[serde(default)]` on that field,
    /// every read/replay of those rows would error. This test pins the
    /// default — a dropped `#[serde(default)]` reintroduces the
    /// replay break.
    #[test]
    fn task_invoked_deserialises_pre_amendment_payload_without_duplicate_of() {
        // The exact wire shape a pre-amendment TaskInvoked appended into
        // the audit stream — no `duplicate_of` key.
        let pre_amendment = serde_json::json!({
            "task_job_id": Uuid::nil(),
            "kind": "noop",
            "params_digest": "0".repeat(64),
        });
        let parsed: TaskInvoked =
            serde_json::from_value(pre_amendment).expect("pre-amendment payload must replay");
        assert_eq!(
            parsed.duplicate_of, None,
            "absent duplicate_of must deserialise as None",
        );
        assert_eq!(parsed.kind, "noop");
    }

    /// Round-trip with `duplicate_of = Some(_)`
    /// preserves the field value through the JSONB hop.
    #[test]
    fn task_invoked_round_trip_with_duplicate_of_some() {
        let existing = Uuid::new_v4();
        let e = TaskInvoked {
            task_job_id: existing,
            kind: "retention-purge".into(),
            params_digest: sample_digest(),
            duplicate_of: Some(existing),
        };
        let json = serde_json::to_string(&e).expect("serialise");
        let back: TaskInvoked = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, e);
        assert_eq!(back.duplicate_of, Some(existing));
    }

    // -- TaskFailed ----------------------------------------------------------

    #[test]
    fn task_failed_validate_ok_each_valid_kind() {
        for kind in VALID_TASK_KINDS {
            let e = TaskFailed {
                task_job_id: id(),
                kind: kind.to_string(),
                reason: "db connection lost".into(),
                final_attempt: false,
            };
            assert!(e.validate().is_ok(), "validate failed for kind {kind:?}");
        }
    }

    #[test]
    fn task_failed_validate_rejects_unknown_kind() {
        let e = TaskFailed {
            task_job_id: id(),
            kind: "unknown-kind".into(),
            reason: "some reason".into(),
            final_attempt: true,
        };
        match e.validate() {
            Err(DomainError::Validation(msg)) => {
                assert!(
                    msg.contains("unknown-kind"),
                    "expected kind in message: {msg}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn task_failed_validate_rejects_oversized_reason() {
        let e = TaskFailed {
            task_job_id: id(),
            kind: "noop".into(),
            reason: "x".repeat(4097), // 4097 bytes > 4096 cap
            final_attempt: true,
        };
        match e.validate() {
            Err(DomainError::Validation(msg)) => {
                assert!(msg.contains("4096"), "expected cap in message: {msg}");
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn task_failed_validate_accepts_boundary_4096_bytes() {
        let e = TaskFailed {
            task_job_id: id(),
            kind: "noop".into(),
            reason: "x".repeat(4096), // exactly at cap
            final_attempt: false,
        };
        assert!(e.validate().is_ok());
    }

    #[test]
    fn task_failed_round_trip() {
        let e = TaskFailed {
            task_job_id: id(),
            kind: "advisory-watch-tick".into(),
            reason: "upstream timeout".into(),
            final_attempt: true,
        };
        let json = serde_json::to_string(&e).expect("serialise");
        let back: TaskFailed = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, e);
    }

    // -- Wire-format contract tests (LOAD-BEARING) ----------------------------
    //
    // These tests pin the JSON wire names for `task_job_id` on both events.
    // Every downstream consumer (admin HTTP handlers, hort-cli table renderer,
    // audit log forensic queries) reads `"task_job_id"` — not `"job_id"`.
    // A rename on the Rust identifier without a matching serde attribute
    // would change the wire form silently; this test catches it before
    // it reaches the Postgres event-store adapter.

    #[test]
    fn task_invoked_wire_format_uses_task_job_id_not_job_id() {
        let jid = Uuid::nil();
        let e = TaskInvoked {
            task_job_id: jid,
            kind: "noop".into(),
            params_digest: "0".repeat(64),
            duplicate_of: None,
        };
        let json = serde_json::to_string(&e).expect("serialise");
        assert!(
            json.contains("\"task_job_id\""),
            "wire format must use key \"task_job_id\"; got: {json}"
        );
        assert!(
            !json.contains("\"job_id\""),
            "wire format must NOT contain bare \"job_id\" key; got: {json}"
        );
        // Round-trip confirms the key is stable both ways.
        let back: TaskInvoked = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back.task_job_id, jid);
    }

    #[test]
    fn task_failed_wire_format_uses_task_job_id_not_job_id() {
        let jid = Uuid::nil();
        let e = TaskFailed {
            task_job_id: jid,
            kind: "noop".into(),
            reason: "something went wrong".into(),
            final_attempt: true,
        };
        let json = serde_json::to_string(&e).expect("serialise");
        assert!(
            json.contains("\"task_job_id\""),
            "wire format must use key \"task_job_id\"; got: {json}"
        );
        assert!(
            !json.contains("\"job_id\""),
            "wire format must NOT contain bare \"job_id\" key; got: {json}"
        );
        assert!(
            json.contains("\"final_attempt\""),
            "wire format must include \"final_attempt\"; got: {json}"
        );
        // Round-trip confirms all three new-spec fields survive serde.
        let back: TaskFailed = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back.task_job_id, jid);
        assert!(back.final_attempt);
    }

    // -- quarantine-release-sweep kind registration --------------------------

    /// The periodic release-sweep handler kind must be
    /// registered in [`VALID_TASK_KINDS`] so the kind literal:
    /// 1. validates on `TaskInvoked` / `TaskFailed` events,
    /// 2. is accepted by the `jobs.kind` CHECK constraint (defined in
    ///    migration 009 — all kinds live in place there per
    ///    `feedback_pre_release_migrations`; see the constant's doc),
    /// 3. enqueues without error through `enqueue_task` (covered by the
    ///    `task_use_case_enqueue_real_db.rs` walk over every kind).
    ///
    /// The kind is **non-destructive**: it carries no authority of its
    /// own; `QuarantineUseCase::release_expired` re-evaluates the
    /// fail-closed release predicate (ADR 0007) per artifact, so
    /// invoking the sweep arbitrarily
    /// can release only what is already releasable.
    #[test]
    fn valid_task_kinds_contains_quarantine_release_sweep() {
        assert!(
            VALID_TASK_KINDS.contains(&"quarantine-release-sweep"),
            "`quarantine-release-sweep` MUST be in VALID_TASK_KINDS so the \
             handler dispatches and the CHECK constraint (migration 009) lines up; if this fails \
             the keyspace registry and the SQL CHECK have drifted apart"
        );
    }

    /// The release-sweep kind is **not** destructive (no extra
    /// `task:destructive` claim required). The release sweep delegates
    /// release authority to `QuarantineUseCase::release_expired`, which
    /// enforces the fail-closed release predicate (ADR 0007) per
    /// artifact (`ScanSucceeded`/`ScanWaived`
    /// only) — the kind itself carries no privilege.
    #[test]
    fn quarantine_release_sweep_is_not_destructive() {
        assert!(
            !task_kind_is_destructive("quarantine-release-sweep"),
            "`quarantine-release-sweep` MUST NOT be destructive; \
             release authority is enforced per-artifact in release_expired (ADR 0007)"
        );
    }

    /// The prefetch scheduled-tick handler kind must be
    /// registered in [`VALID_TASK_KINDS`] so the kind literal:
    /// 1. validates on `TaskInvoked` / `TaskFailed` events,
    /// 2. is accepted by the `jobs.kind` CHECK constraint (migration 009 —
    ///    in place per `feedback_pre_release_migrations`),
    /// 3. enqueues without error through `enqueue_task` (the DB-backed
    ///    walk over every kind in `task_use_case_enqueue_real_db.rs`).
    #[test]
    fn valid_task_kinds_contains_prefetch_tick() {
        assert!(
            VALID_TASK_KINDS.contains(&"prefetch-tick"),
            "`prefetch-tick` MUST be in VALID_TASK_KINDS so the \
             handler dispatches and the migration-009 CHECK constraint lines up; if this \
             fails the keyspace registry and the SQL CHECK have drifted apart"
        );
    }

    /// `prefetch-tick` is **not** destructive (the
    /// scheduled tick is a planner invocation, not a release-of-authority
    /// path; the planner only emits intent counters and may schedule
    /// pull-through prefetches, which themselves ride the same authority
    /// gates as a client-driven pull).
    #[test]
    fn prefetch_tick_is_not_destructive() {
        assert!(
            !task_kind_is_destructive("prefetch-tick"),
            "`prefetch-tick` MUST NOT be destructive; the \
             scheduled tick only invokes the prefetch planner and never elevates authority"
        );
    }

    /// The three prefetch-cascade kinds MUST be registered
    /// in [`VALID_TASK_KINDS`] so:
    /// 1. `TaskInvoked` / `TaskFailed` validate on these kinds (events fire
    ///    through the `TaskDispatcher` for terminal failures + audit),
    /// 2. the `jobs.kind` SQL CHECK accepts them (migration 009 — added in
    ///    lock-step with this allowlist per `feedback_pre_release_migrations`
    ///    and the CLAUDE.md "VALID_TASK_KINDS + CHECK lock-step" mandate),
    /// 3. they enqueue through `enqueue_task` (DB-backed walk over every
    ///    kind in `task_use_case_enqueue_real_db.rs`).
    #[test]
    fn valid_task_kinds_contains_prefetch_cascade_kinds() {
        for kind in [
            "prefetch",
            "prefetch-dependencies",
            "prefetch-row-retention-sweep",
        ] {
            assert!(
                VALID_TASK_KINDS.contains(&kind),
                "`{kind}` MUST be in VALID_TASK_KINDS so the \
                 cascade handler dispatches and the migration-009 CHECK constraint \
                 lines up; if this fails the keyspace registry and the SQL CHECK \
                 have drifted apart"
            );
        }
    }

    /// None of the three cascade kinds are
    /// destructive. They:
    /// - `prefetch` — drives the format's pull-through path (same authority
    ///   as a client-driven pull; the scan / quarantine / policy gates
    ///   apply identically).
    /// - `prefetch-dependencies` — calls the planner + enqueues child rows;
    ///   enqueues no events of its own.
    /// - `prefetch-row-retention-sweep` — deletes only historical `jobs`
    ///   rows (no artifact / event-stream / scan data). The job-row
    ///   delete is GC of operational state, not a release of authority.
    #[test]
    fn prefetch_cascade_kinds_are_not_destructive() {
        for kind in [
            "prefetch",
            "prefetch-dependencies",
            "prefetch-row-retention-sweep",
        ] {
            assert!(
                !task_kind_is_destructive(kind),
                "`{kind}` MUST NOT be destructive; the cascade \
                 kinds invoke pull-through / planner / job-row GC paths and never \
                 elevate authority"
            );
        }
    }

    /// The wheel-metadata-backfill task kind MUST be in
    /// [`VALID_TASK_KINDS`] so the kind literal:
    /// 1. validates on `TaskInvoked` / `TaskFailed` events,
    /// 2. is accepted by the `jobs.kind` CHECK constraint (migration 009
    ///    — added in lock-step with this allowlist per
    ///    `feedback_pre_release_migrations`),
    /// 3. enqueues without error through `enqueue_task` (the DB-backed
    ///    walk over every kind in `task_use_case_enqueue_real_db.rs`),
    /// 4. is dispatched by `WheelMetadataBackfillHandler` in the worker.
    #[test]
    fn valid_task_kinds_contains_wheel_metadata_backfill() {
        assert!(
            VALID_TASK_KINDS.contains(&"wheel-metadata-backfill"),
            "`wheel-metadata-backfill` MUST be in VALID_TASK_KINDS so \
             the handler dispatches and the migration-009 CHECK constraint lines up; if \
             this fails the keyspace registry and the SQL CHECK have drifted apart"
        );
    }

    /// The backfill kind is **non-destructive**. It
    /// only walks read-only artifact rows, extracts the wheel's existing
    /// METADATA from CAS, and writes a derived-projection row
    /// (`content_references kind=wheel_metadata`). No artifact / event /
    /// scan-state mutation; no release-of-authority. The kind itself
    /// carries no privilege beyond `Permission::AdminTaskInvoke`.
    #[test]
    fn wheel_metadata_backfill_is_not_destructive() {
        assert!(
            !task_kind_is_destructive("wheel-metadata-backfill"),
            "`wheel-metadata-backfill` MUST NOT be destructive; it \
             only writes derived-projection ContentReference rows and never elevates \
             authority"
        );
    }

    // -- Destructive-kind classification (ADR 0028) --------------------------

    #[test]
    fn destructive_task_kinds_is_exactly_the_audited_three() {
        // The destructive set is closed at the three audited kinds;
        // scope-creep into other kinds is a regression.
        let mut got: Vec<&str> = DESTRUCTIVE_TASK_KINDS.to_vec();
        got.sort_unstable();
        let mut want = [
            "retention-purge",
            "eventstore-archive",
            "retention-evaluate",
        ];
        want.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn destructive_task_kinds_are_a_subset_of_valid_task_kinds() {
        for k in DESTRUCTIVE_TASK_KINDS {
            assert!(
                VALID_TASK_KINDS.contains(k),
                "destructive kind {k:?} must also be a valid kind"
            );
        }
    }

    #[test]
    fn task_kind_is_destructive_classifies_every_valid_kind() {
        // Exhaustive over VALID_TASK_KINDS: each known kind is destructive
        // iff it is one of the audited three. No other kind reclassifies.
        for kind in VALID_TASK_KINDS {
            let expected = matches!(
                *kind,
                "retention-purge" | "eventstore-archive" | "retention-evaluate"
            );
            assert_eq!(
                task_kind_is_destructive(kind),
                expected,
                "kind {kind:?} destructive-classification mismatch"
            );
        }
    }

    #[test]
    fn task_kind_is_destructive_each_destructive_kind_true() {
        assert!(task_kind_is_destructive("retention-purge"));
        assert!(task_kind_is_destructive("eventstore-archive"));
        assert!(task_kind_is_destructive("retention-evaluate"));
    }

    #[test]
    fn task_kind_is_destructive_ordinary_kinds_false() {
        assert!(!task_kind_is_destructive("noop"));
        assert!(!task_kind_is_destructive("scan"));
        assert!(!task_kind_is_destructive("staging-sweep"));
    }

    #[test]
    fn task_kind_is_destructive_unknown_kind_is_not_destructive() {
        // Unknown kinds are rejected upstream by the kind allowlist; the
        // classifier must not over-claim them as destructive.
        assert!(!task_kind_is_destructive("bogus-kind"));
        assert!(!task_kind_is_destructive(""));
    }

    #[test]
    fn destructive_task_claim_is_the_documented_literal() {
        assert_eq!(DESTRUCTIVE_TASK_CLAIM, "task:destructive");
    }
}
