//! # hort-adapters-postgres — PostgreSQL Outbound Adapters
//!
//! Implements the outbound port traits defined in hort-domain using PostgreSQL
//! via sqlx. This is the only crate that may import sqlx.
//!
//! Depends on: hort-domain, hort-app
//! Used by:    hort-server (composition root wires these adapters at startup)
//!
//! Contains:
//! - PostgresArtifactRepository — implements ArtifactRepository
//! - PostgresRepositoryRepository — implements RepositoryRepository
//! - PostgresUserRepository — implements UserRepository
//! - PostgresEventStore — implements EventPort (append-only artifact lifecycle events)
//!
//! Migrations live under `migrations/` and are applied at startup
//! by `hort-server::migrate::run` against the pool that
//! `hort-server::composition::build_app_context` receives.

use std::future::Future;
use std::pin::Pin;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::error::DomainError;

pub mod advisory_sync_state;
pub mod api_token_repo;
pub mod api_token_revocation_listener;
pub mod artifact_group_lifecycle;
pub mod artifact_group_repo;
pub mod artifact_lifecycle;
pub mod artifact_metadata_repo;
pub mod artifact_repo;
pub(crate) mod blob_lock;
pub mod claim_mapping_repo;
// Transient write-contention (serialization failure / deadlock): the
// sqlstate classifier and the bounded whole-transaction retry over it.
// Crate-internal by design — the Postgres vocabulary it speaks must not
// cross the port boundary (ADR 0008); what leaves is
// `DomainError::Contended`.
pub(crate) mod contention;
// PostgreSQL adapter for the curation decisions listing
// (`CurationDecisionsRepository`). Event-log scan over the `events`
// table with per-event-type curator-actor discrimination
// (payload-side for ArtifactReleased/Rejected; envelope-side for
// ExclusionAdded/Removed). Consumed by `CurationUseCase::list_decisions`.
pub mod curation_decisions_repository;
// PostgreSQL adapter for the active-exclusions listing
// (`CurationExclusionsRepository`). Reads `exclusion_projections` (the
// existing read model used by `QuarantineUseCase::record_scan_result`).
// The projection carries `added_by_actor_id` + `added_at` columns — see
// `005_policy.sql` + the projector update in
// `policy_projection_repo::upsert_exclusion`. Consumed by
// `CurationUseCase::list_exclusions`.
pub mod curation_exclusions_repository;
// PostgreSQL adapter for the curation queue listing
// (`CurationQueueRepository`). Joins `artifacts` + `repositories` +
// `scan_findings` + `policy_projections` with a per-row deadline
// computation and a LATERAL `events` lookup for the rejection-reason
// discriminator. Consumed by `CurationUseCase::list_queue`.
pub mod curation_queue_repository;
pub mod curation_rule_repo;
pub mod event_chain_head_reader;
pub mod event_chain_reader;
pub mod event_store;
pub mod jobs_repository;
pub mod mappers;
pub(crate) mod merged_category_read;
pub mod metrics;
pub mod oidc_issuer_repo;
pub mod patch_candidate_repo;
pub mod permission_grant_repo;
pub mod pg_content_reference_repo;
pub mod policy_projection_repo;
pub mod purge_gc;
// PostgreSQL implementation of the release-sweep candidacy query
// (`QuarantineReleaseCandidatesRepository`). Mirrors
// `rescan_candidates`'s file layout; consumed by
// `QuarantineReleaseSweepHandler`.
pub mod quarantine_release_candidates;
pub mod ref_lifecycle;
pub mod ref_registry_repo;
pub mod refcount_reconcile;
pub mod replay_guard_repo;
pub mod replay_seen_prune;
pub mod repo_security_score_repository;
pub mod repository_repo;
pub mod repository_upstream_mapping_repo;
pub mod rescan_candidates;
pub mod retention_candidate_reader;
pub mod retention_policy_projection_repo;
pub mod retention_preview;
pub mod retention_scan_reader;
pub mod sbom_components;
pub mod scan_findings_repository;
pub mod scanner_registry_repository;
pub mod service_account_repo;
pub mod subscription_change_listener;
pub mod subscription_repo;
pub mod terminal_stream_reader;
#[doc(hidden)]
pub mod test_support;
pub mod user_repo;

/// Boxed future alias for dyn-compatible async trait methods.
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Persisted quarantine statuses that must never be offered to garbage
/// collection or refcount repair paths.
const GC_PROTECTED_QUARANTINE_STATUSES: [(&str, QuarantineStatus); 3] = [
    ("quarantined", QuarantineStatus::Quarantined),
    ("rejected", QuarantineStatus::Rejected),
    ("scan_indeterminate", QuarantineStatus::ScanIndeterminate),
];

/// Names for binding the shared GC-protected set as a PostgreSQL text array.
pub(crate) fn gc_protected_quarantine_status_names() -> Vec<&'static str> {
    GC_PROTECTED_QUARANTINE_STATUSES
        .iter()
        .map(|(name, _)| *name)
        .collect()
}

/// SQL predicate body deciding whether a mutable ref in an artifact's
/// **own** repository currently resolves to it — the `KeepLastN` tag
/// exemption. Expects the artifacts row to be in scope as `a`; binds
/// nothing.
///
/// Both retention sweeps read it: the evaluator, so a tag target never
/// acquires an `ArtifactExpired` under `KeepLastN`, and the purge, so a
/// tag set in the hour between the two sweeps still saves the artifact.
/// The two readings must be the same reading, not two that happen to
/// agree today — hence one string.
///
/// Three things are load-bearing:
///
/// - **`mr.repository_id = a.repository_id`.** Content hashes are
///   shared across repositories by construction; a hash-global lookup
///   would exempt an untagged artifact because identical bytes are
///   tagged next door, and under a name-pattern-scoped policy it would
///   protect nothing when the tag lives outside the policy's scope.
/// - **Both target kinds.** `'hash'` is the OCI tag, resolving to a
///   content hash; `'version'` is the npm dist-tag and every other
///   non-OCI mutable pointer. A hash-only reading silently protects
///   nothing outside OCI.
/// - **`mr.namespace = a.name` on the version arm.** A version pointer
///   names `(namespace, version)`; without the namespace one package's
///   `latest` would exempt every same-versioned package beside it.
///
/// Both arms are served by the repository-scoped partial indexes on
/// `mutable_refs`: `(repository_id, target_hash)` and
/// `(repository_id, target_version)`.
pub(crate) const ARTIFACT_IS_TAG_TARGETED_SQL: &str = r#"
    EXISTS (
        SELECT 1 FROM mutable_refs mr
         WHERE mr.repository_id = a.repository_id
           AND (
                 (mr.target_kind = 'hash'
                   AND mr.target_hash = a.checksum_sha256)
              OR (mr.target_kind = 'version'
                   AND mr.namespace = a.name
                   AND mr.target_version = a.version)
               )
    )
"#;

/// Map a persisted status when it belongs to the shared GC-protected set.
pub(crate) fn gc_protected_quarantine_status(raw: &str) -> Option<QuarantineStatus> {
    GC_PROTECTED_QUARANTINE_STATUSES
        .iter()
        .find_map(|(name, status)| (*name == raw).then_some(*status))
}

/// Map sqlx errors to domain errors.
///
/// Order matters. The contention arm sits ahead of the catch-all because a
/// serialization failure or a deadlock is a *transient* abort — the write was
/// rolled back whole and running it again is expected to succeed — and
/// letting it fall through to `Invariant` is what turns two clients writing
/// the same row into an intermittent 500 on a request that was never wrong.
/// It sits below the duplicate-key arm only for readability; the two classes
/// are disjoint sqlstates and cannot both match (see `contention`).
pub(crate) fn map_sqlx_error(e: &sqlx::Error, entity: &'static str, id: &str) -> DomainError {
    match e {
        sqlx::Error::RowNotFound => DomainError::NotFound {
            entity,
            id: id.to_string(),
        },
        _ if e.to_string().contains("duplicate key") => {
            DomainError::Conflict(format!("{entity} already exists"))
        }
        _ if contention::is_contention(e) => {
            // `debug`, not `warn`: the adapter's bounded retry absorbs this
            // in the ordinary case, so logging every occurrence at warn would
            // make a self-healing condition look like an incident. The
            // exhausted-budget case warns once, in `with_contention_retry`.
            tracing::debug!(entity, id, error = %e, "write contention");
            contention::contention_error(e, entity)
                .unwrap_or_else(|| DomainError::Invariant(format!("database error: {e}")))
        }
        _ => {
            tracing::warn!(entity, id, error = %e, "unexpected database error");
            DomainError::Invariant(format!("database error: {e}"))
        }
    }
}

/// Escape SQL LIKE metacharacters in user-supplied search input.
///
/// Escapes `\` → `\\`, `%` → `\%`, `_` → `\_` (in that order — backslash
/// first to avoid double-escaping). Use with `ESCAPE '\'` in the SQL query.
pub(crate) fn escape_like_pattern(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_protected_status_definition_supplies_names_and_domain_values() {
        assert_eq!(
            gc_protected_quarantine_status_names(),
            ["quarantined", "rejected", "scan_indeterminate"]
        );
        assert_eq!(
            gc_protected_quarantine_status("quarantined"),
            Some(QuarantineStatus::Quarantined)
        );
        assert_eq!(
            gc_protected_quarantine_status("rejected"),
            Some(QuarantineStatus::Rejected)
        );
        assert_eq!(
            gc_protected_quarantine_status("scan_indeterminate"),
            Some(QuarantineStatus::ScanIndeterminate)
        );
        assert_eq!(gc_protected_quarantine_status("released"), None);
    }

    #[test]
    fn escape_like_plain_text() {
        assert_eq!(escape_like_pattern("hello world"), "hello world");
    }

    #[test]
    fn escape_like_percent() {
        assert_eq!(escape_like_pattern("100%"), "100\\%");
    }

    #[test]
    fn escape_like_underscore() {
        assert_eq!(escape_like_pattern("my_repo"), "my\\_repo");
    }

    #[test]
    fn escape_like_backslash() {
        assert_eq!(escape_like_pattern("path\\to"), "path\\\\to");
    }

    #[test]
    fn escape_like_combined() {
        assert_eq!(escape_like_pattern("100%_\\test"), "100\\%\\_\\\\test");
    }

    #[test]
    fn escape_like_empty() {
        assert_eq!(escape_like_pattern(""), "");
    }
}
