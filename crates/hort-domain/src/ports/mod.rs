use std::future::Future;
use std::pin::Pin;

/// Boxed future alias for dyn-compatible async trait methods.
/// Used by all port traits in this module.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub mod advisory;
pub mod advisory_sync_state;
pub mod api_token_cache_invalidator;
pub mod api_token_repository;
pub mod artifact_group_lifecycle;
pub mod artifact_group_repository;
pub mod artifact_lifecycle;
pub mod artifact_metadata_repository;
pub mod artifact_repository;
pub mod checkpoint_anchor;
pub mod checkpoint_emitter;
pub mod claim_mapping_repository;
pub mod content_reference_index;
// Three curation read-surface ports that `CurationUseCase` holds as
// `Arc<dyn _>` from construction; the Postgres adapter implements the
// bodies and the use case exposes the `list_*` delegations.
pub mod curation_decisions_repository;
pub mod curation_exclusions_repository;
pub mod curation_queue_repository;
pub mod curation_rule_repository;
pub mod ephemeral_store;
pub mod event_chain_head_reader;
pub mod event_chain_reader;
pub mod event_notifier;
pub mod event_store;
pub mod federated_jwt_validator;
pub mod format_handler;
// `group_mapping_repository` / `role_repository` are retired
// (replaced by `claim_mapping_repository` / `permission_grant_repository`,
// registered above / below — ADR 0012).
pub mod identity_provider;
pub mod jobs_repository;
pub mod kubernetes_secret_writer;
pub mod metadata_mirror_store;
pub mod oidc_issuer_repository;
pub mod patch_candidate_repository;
pub mod permission_grant_repository;
pub mod policy_projection_repository;
// Outbound provenance-verification port (ADR 0027). A per-backend
// Sigstore/cosign verifier adapter
// (`hort-adapters-provenance-sigstore`) implements it; the
// `ProvenanceOrchestrationUseCase` dispatches by format.
pub mod provenance;
pub mod purge_gc;
// Outbound ports for the quarantine release-sweep handler (ADR 0007):
//   - `quarantine_release`: the per-tick release entry-point
//     (`QuarantineUseCase::release_expired` impl in `hort-app`).
//   - `quarantine_release_candidates`: candidacy query implemented in
//     `hort-adapters-postgres`. Mirrors the `rescan_candidates` shape.
pub mod quarantine_release;
pub mod quarantine_release_candidates;
pub mod ref_lifecycle;
pub mod ref_registry;
pub mod refcount_reconcile;
pub mod replay_guard;
pub mod replay_seen_prune;
pub mod repo_security_score_repository;
pub mod repository_repository;
pub mod repository_upstream_mapping_repository;
pub mod rescan_candidates;
pub mod retention_candidate_reader;
pub mod retention_policy_projection_repository;
pub mod retention_scan_reader;
pub mod sbom_component_repository;
pub mod scan_findings_repository;
pub mod scanner;
pub mod scanner_registry_repository;
pub mod secret_port;
pub mod service_account_repository;
pub mod stateful_upload_staging;
pub mod storage;
pub mod subscription_change_listener;
pub mod subscription_repository;
pub mod task_handler;
pub mod terminal_stream_reader;
// Invalidate cached upstream
// packument / simple-index / sparse-index entries on
// `ArtifactRejected`. Best-effort defense-in-depth cache hygiene
// that shortens the freshness-of-revocation-signal window; the
// `NonServableStatusFilter` on the next index build is
// the load-bearing close (see
// `docs/architecture/explanation/index-construction.md`).
pub mod upstream_index_cache_invalidator;
pub mod upstream_proxy;
pub mod upstream_resolver;
pub mod user_repository;
pub mod webhook_target_guard;
