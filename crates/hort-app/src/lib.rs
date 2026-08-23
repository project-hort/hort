//! # hort-app — Application Layer
//!
//! Orchestrates domain entities and outbound port traits to implement use cases.
//! No SQL, no HTTP framework imports, no storage driver imports.
//!
//! Depends on: hort-domain (domain entities + port traits)
//! Used by:    hort-http-core + every hort-http-<format> crate (inbound
//!             adapters) and hort-server (composition root)
//!
//! Contains:
//! - Use-case services (ArtifactUseCase, QuarantineUseCase, PromotionUseCase, …)
//! - Application-level error types
//! - Command and query types that inbound adapters construct from requests
//!
//! The application layer calls port traits from hort-domain. It never imports
//! concrete adapter types (sqlx, S3, wasmtime). Those are wired at startup
//! in the composition root in `hort-server`.

// Single Argon2id facade used by both the PAT validator and the
// user-password / admin-bootstrap paths (Argon2id, not bcrypt — the
// invariant is pinned by the `no_bcrypt` guard test).
pub mod argon2_hash;
// CliSession access-token JWT signer/verifier (ADR 0013). Reuses the
// `oci_token_signing` Ed25519 primitive; the two token families are
// separated by `aud` + `token_kind`.
pub mod cli_session_signing;
// NotificationDispatcher: per-subscription tokio tasks consuming the
// broadcast channel from `event_store_publisher`, with catch-up loop,
// failure budget, and a `SubscriptionChangeListener` port for
// near-real-time cache invalidation. See
// `docs/architecture/explanation/event-notifications.md`.
pub mod dispatcher;
pub mod ephemeral_keyspace;
pub mod error;
// The one shared predicate deciding whether an event-chain checkpoint
// anchor exists in this deployment. Consulted by BOTH the checkpoint
// writer (worker) and the checkpoint reader (`verify-event-chain`) so
// the two sides cannot drift apart (ADR 0002, ADR 0057).
pub mod event_chain_anchoring;
// Broadcasts persisted events on a `tokio::sync::broadcast` channel
// after a successful append. The `dispatcher` module subscribes to the
// sender; with no consumers the broadcast is a transparent best-effort
// no-op.
pub mod event_store_publisher;
pub mod gitops;
// What THIS running process applied from gitops at boot — pure value
// types (zero-I/O), filled by the boot path and parked on `AppContext`
// for the admin apply-status inspection endpoint. In-memory by design:
// gitops apply is a boot step with no live-refresh path, so the only
// honest answer a running server can give is its own (ADR 0058).
pub mod gitops_apply_status;
// Apply-config linter — secure-by-default reject rules over the
// desired permission-grant + claim-mapping set, run inside
// `ApplyConfigUseCase::apply_permission_grants` before commit
// (ADR 0015).
pub mod lint;
pub mod metrics;
// Application-layer outbound ports.
//
// Most port traits live in `hort-domain::ports`. This module hosts
// ports whose contract composes domain primitives with async / I/O
// concerns that don't belong in `hort-domain` — currently the
// `UpstreamMetadataPort`. See module doc for the layering rationale.
pub mod ports;
// Two-layer pull-through request coalescing. Concrete service (no new
// outbound port); consumes `Arc<dyn EphemeralStore>` and exposes
// `coalesce_metadata` / `coalesce_blob` for format-handler call sites.
pub mod pull_dedup;
// OCI Distribution-Spec `/v2/auth` JWT signing + verification
// primitives. See module-level doc for the rationale of a dedicated
// key (separate from the OIDC validation keys, which are remote
// IdP-owned).
pub mod oci_token_signing;
// `repo_security_scores` projector + future projectors that maintain
// denormalised projection tables off the event log. Pure delta
// calculators; no SQL, no I/O of their own.
pub mod projectors;
// Consumer-side projection over a cached upstream body (ADR 0026).
// `project_cached` is the single sync/async bridge every per-format
// projector and the `IdentityProjector` flow through. Lives in
// `hort-app` (not `hort-formats`) because `hort-formats → hort-app` is
// already in the dep graph — putting it in `hort-formats` would block
// `hort-app`'s own task handlers from using it.
pub mod project;
// Provenance-subsystem shared facts (ADR 0027): the Tier-1
// capable-format set (single source for every wiring site) + the
// ScanPolicy wire->domain mappers.
pub mod provenance;
// Dependency-edge registry (backlog 090, #135 item 2, ADR 0039 §12):
// every standing cross-artifact lifecycle dependency, both trigger ends
// named. Pure data + the structural guard's cross-check helper; no I/O.
pub mod lifecycle_dependency_registry;
pub mod rbac;
// The vulnerability-scanner backends compiled into this build — the single
// source of truth the apply-time `scanBackends` validator checks against
// (sibling of `crate::provenance`). Static, not the live worker registry:
// see the module docs (regression H20).
pub mod scanning;
// The deployment's effective global storage backend as a pure value
// type (zero-I/O, sibling of `crate::lint::LintConfig`). Threaded into
// `ApplyConfigUseCase` via the additive `with_effective_storage_backend`
// builder seam so a per-repo `storage.backend` that differs from the
// global backend is rejected at apply.
pub mod storage_backend;
// TaskHandler implementations for the worker dispatcher. Each handler
// is registered by kind() and invoked with per-job params.
pub mod task_handlers;
// Generalised multi-kind TaskDispatcher driving the worker poll loop.
pub mod task_dispatcher;
pub mod use_cases;
