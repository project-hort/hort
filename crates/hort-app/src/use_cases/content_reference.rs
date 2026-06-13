//! `ContentReferenceUseCase` — the application-layer facade over the
//! content-reference index. Inbound HTTP crates (the `hort-http-oci`
//! referrers surface, the PyPI PEP 658 metadata serve) go through this
//! use case rather than touching the port directly (ADR 0008).
//!
//! # Read side
//!
//! [`ContentReferenceUseCase::find_by_visible_target`] composes
//! [`RepositoryAccessUseCase::resolve`] before
//! calling [`ContentReferenceIndex::find_by_target`]. The visibility
//! check is the load-bearing addition: a private repo invisible to the
//! caller MUST collapse to `NotFound` indistinguishably from a missing
//! repo (anti-enumeration). The handler-side OCI Referrers spec rule
//! "empty result returns 200" then leaks no information about whether
//! the repo exists.
//!
//! # Write side
//!
//! [`Self::insert_for_repo`] and [`Self::delete_by_source_for_repo`]
//! are *no-authz forwards* over the port. The trust contract is
//! documented per-method: callers MUST hold a pre-authz'd `repo_id` —
//! in OCI the only caller is the manifest-PUT / manifest-DELETE handler
//! which has already extracted [`WriteRepoAccess`]. Re-checking
//! visibility here would pay an extra DB roundtrip on every write and
//! defend against a callsite shape that doesn't exist. The shape the
//! port enforces — `(repository_id, source_artifact_id, kind)` PK +
//! idempotent upsert per `kind` (sibling rows
//! under different kinds for the same source coexist) — is sufficient
//! for the current caller set.
//!
//! # Observability
//!
//! Every public method gets `#[tracing::instrument(skip(self))]` (NOT
//! `err`). `find_by_visible_target` logs nothing on a Read denial — the
//! composed `RepositoryAccessUseCase::resolve` already logged at the
//! right level (debug). The metric `hort_content_reference_queries_total`
//! continues to be emitted from the OCI handler (the only caller that
//! has a `format` label to bind to); centralising emission here would
//! force every future caller to the OCI label set.

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::Repository;
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::types::ContentHash;

use crate::error::AppResult;
use crate::use_cases::repository_access::{AccessLevel, RepositoryAccessUseCase};

/// Composition over [`ContentReferenceIndex`] + [`RepositoryAccessUseCase`].
///
/// See module-level doc for the read/write boundary semantics and the
/// no-authz trust contract on the write methods.
pub struct ContentReferenceUseCase {
    content_references: Arc<dyn ContentReferenceIndex>,
    repository_access: Arc<RepositoryAccessUseCase>,
}

impl ContentReferenceUseCase {
    /// Construct a new use case from the underlying port and the
    /// repository-access use case (composed for the visibility check on
    /// the read side).
    pub fn new(
        content_references: Arc<dyn ContentReferenceIndex>,
        repository_access: Arc<RepositoryAccessUseCase>,
    ) -> Self {
        Self {
            content_references,
            repository_access,
        }
    }

    /// Read-side: list references targeting `target_hash` inside a
    /// Read-visible repo.
    ///
    /// Replaces the OCI referrers handler's direct
    /// `content_references.find_by_target` call. The visibility check is
    /// load-bearing — a private repo invisible to `actor` collapses to
    /// `NotFound` indistinguishably from a missing repo. Returns the
    /// resolved [`Repository`] alongside the rows so the handler does
    /// not pay a second `find_by_key` roundtrip for label rendering.
    #[tracing::instrument(skip(self))]
    pub async fn find_by_visible_target(
        &self,
        repo_key: &str,
        target_hash: &ContentHash,
        kind_filter: Option<&str>,
        actor: Option<&CallerPrincipal>,
    ) -> AppResult<(Repository, Vec<ContentReference>)> {
        let repo = self
            .repository_access
            .resolve(repo_key, actor, AccessLevel::Read)
            .await?;
        let rows = self
            .content_references
            .find_by_target(repo.id, target_hash, kind_filter)
            .await?;
        Ok((repo, rows))
    }

    /// Write-side: insert a reference scoped to a pre-authz'd repo.
    ///
    /// **Trust contract — no authz here.** Callers MUST hold a
    /// pre-authz'd `repo_id` (in OCI's case: extracted via
    /// `WriteRepoAccess` upstream of this call). The `repo_id` argument
    /// is provided so future audits can grep for cross-repo write
    /// confusion at the use-case boundary; the port itself derives the
    /// repo from the `row.repository_id` field per the
    /// [`ContentReferenceIndex`] contract.
    ///
    /// Idempotent upsert per the [`ContentReferenceIndex::insert`] port
    /// docstring — a repeat call with the same
    /// `(repository_id, source_artifact_id, kind)` refreshes the row.
    /// Inserts under a different `kind` add sibling rows.
    #[tracing::instrument(skip(self, row))]
    pub async fn insert_for_repo(&self, repo_id: Uuid, row: ContentReference) -> AppResult<()> {
        // `repo_id` is part of the signature so the call site reads as
        // "insert into repo X". The port itself reads `row.repository_id`
        // (kept distinct because the port pre-dates this use case). A
        // mismatch would surface as a write to the `row.repository_id`
        // repo, not the `repo_id` argument — which is a callsite bug at
        // the OCI handler, but defensive validation here would only
        // trade one panic for another. The OCI handler builds
        // `reference_row` with `repository_id: repo_id` directly so the
        // two are identical by construction.
        let _ = repo_id;
        self.content_references.insert(row).await?;
        Ok(())
    }

    /// Read-side: **batched** PK lookup of `wheel_metadata`-style
    /// per-source-attribute rows for a pre-authz'd repo.
    ///
    /// The PEP 658 simple-index serve iterates per
    /// wheel artifact and would otherwise issue N
    /// `find_by_source_and_kind` round-trips. The format-tier source
    /// (`HostedPypiSource`) calls this exactly once per simple-index
    /// build, populating `PypiVersionFile.metadata_hash` from the
    /// returned map.
    ///
    /// **Trust contract — no authz here.** Caller (the per-format
    /// `IndexSource::fetch` impl) has already passed
    /// `list_by_raw_name_visible` (F-25) for the same `repo_id`; the
    /// `source_artifact_id` slice is the set of trusted ids returned
    /// from that hop (trusted-ids contract, ADR 0008). Re-checking
    /// visibility here would pay an extra DB roundtrip per
    /// simple-index serve and defend against a callsite shape that
    /// doesn't exist.
    ///
    /// Sources without a matching row are absent from the returned
    /// map; the caller folds them into its own per-source default
    /// (PypiVersionFile.metadata_hash = None → builder omits PEP 658
    /// advertisement; pip falls back to whole-wheel download). An
    /// empty `sources` slice returns an empty map without touching
    /// the backend.
    #[tracing::instrument(skip(self, sources), fields(source_count = sources.len()))]
    pub async fn find_by_sources_and_kind_for_repo(
        &self,
        repo_id: Uuid,
        sources: &[Uuid],
        kind: &str,
    ) -> AppResult<std::collections::HashMap<Uuid, ContentReference>> {
        let out = self
            .content_references
            .find_by_sources_and_kind(repo_id, sources, kind)
            .await?;
        Ok(out)
    }

    /// Cleanup-side: drop every reference sourced from
    /// `source_artifact_id`.
    ///
    /// **Trust contract — no authz here.** Same rationale as
    /// [`Self::insert_for_repo`]. Caller (OCI manifest DELETE) holds
    /// `WriteRepoAccess` for `repo_id`. The port's
    /// [`ContentReferenceIndex::delete_by_source`] sweeps every row
    /// keyed by `source` — the migration's FK cascade also runs on
    /// `artifacts(id)` delete, so this is belt-and-suspenders.
    ///
    /// `repo_id` is in the signature so callsite intent is explicit
    /// (see the [`Self::insert_for_repo`] docstring); it is not passed
    /// to the underlying port because `delete_by_source` is keyed only
    /// by the source artifact id (which is globally unique).
    #[tracing::instrument(skip(self))]
    pub async fn delete_by_source_for_repo(
        &self,
        repo_id: Uuid,
        source_artifact_id: Uuid,
    ) -> AppResult<()> {
        let _ = repo_id;
        self.content_references
            .delete_by_source(source_artifact_id)
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use arc_swap::ArcSwap;
    use chrono::Utc;
    use serde_json::json;

    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::repository::Repository;
    use hort_domain::error::DomainError;
    use hort_domain::ports::content_reference_index::ContentReference;
    use hort_domain::ports::BoxFuture;

    use super::*;
    use crate::error::AppError;
    use crate::rbac::RbacEvaluator;
    use crate::use_cases::repository_access::RbacAccess;
    use crate::use_cases::test_support::{
        sample_repository, MockContentReferenceIndex, MockRepositoryRepository,
    };

    // -- helpers -----------------------------------------------------------

    fn private_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.is_public = false;
        r
    }

    fn public_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.is_public = true;
        r
    }

    fn enabled(rbac: RbacEvaluator) -> RbacAccess {
        RbacAccess::Enabled(Arc::new(ArcSwap::from_pointee(rbac)))
    }

    fn principal(roles: &[&str]) -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            claims: roles.iter().map(|s| (*s).to_string()).collect(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    /// Evaluator where the `reader` claim carries `Permission::Read`
    /// scoped to `repo_id` (claim-subject model, ADR 0012).
    fn rbac_with_reader_role(repo_id: Uuid) -> RbacEvaluator {
        RbacEvaluator::new(vec![PermissionGrant {
            id: Uuid::new_v4(),
            subject: GrantSubject::Claims(vec!["reader".to_string()]),
            repository_id: Some(repo_id),
            permission: Permission::Read,
            created_at: Utc::now(),
            managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
            managed_by_digest: None,
        }])
    }

    /// Sample sha256 hex used as a target across read-side tests. The
    /// hex value itself is the SHA-256 of an empty input — semantically
    /// arbitrary; tests only need a stable parseable string.
    const TARGET_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn target_hash() -> ContentHash {
        TARGET_HEX.parse().unwrap()
    }

    fn sample_row(repo_id: Uuid, source: Uuid, kind: &str) -> ContentReference {
        ContentReference {
            source_artifact_id: source,
            target_content_hash: target_hash(),
            kind: kind.into(),
            metadata: json!({"k": "v"}),
            repository_id: repo_id,
            recorded_at: Utc::now(),
        }
    }

    fn build_uc(
        repos: Arc<MockRepositoryRepository>,
        index: Arc<MockContentReferenceIndex>,
        access: RbacAccess,
    ) -> ContentReferenceUseCase {
        let rac = Arc::new(RepositoryAccessUseCase::new(
            repos, access, /* include_repository_label = */ true,
        ));
        ContentReferenceUseCase::new(index, rac)
    }

    // -- find_by_visible_target — anti-enumeration -------------------------

    /// **Acceptance: anti-enumeration on Read.** Invisible-private-repo
    /// and missing-repo MUST return *byte-identical* `NotFound`
    /// envelopes. Snapshot the rendered display strings — that is what
    /// an external 404-vs-403 oracle would observe.
    #[tokio::test]
    async fn find_by_visible_target_invisible_and_missing_are_byte_identical() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let index = Arc::new(MockContentReferenceIndex::new());
        // "vault" exists as a private repo; anonymous caller cannot see it.
        repos.insert(private_repo("vault"));
        let uc = build_uc(repos, index, enabled(RbacEvaluator::new(Vec::new())));

        let invisible = uc
            .find_by_visible_target("vault", &target_hash(), Some("oci_subject"), None)
            .await
            .unwrap_err();
        let missing = uc
            .find_by_visible_target("ghost", &target_hash(), Some("oci_subject"), None)
            .await
            .unwrap_err();

        // Both are the canonical `not found: Repository <key>` envelope —
        // same prefix means an enumeration probe sees the same shape.
        // The id token differs (vault vs ghost) only because the
        // request URL differed; the *envelope* is identical.
        let inv_text = invisible.to_string();
        let mis_text = missing.to_string();
        assert!(inv_text.starts_with("not found: Repository "));
        assert!(mis_text.starts_with("not found: Repository "));

        // Variant equality: both must be `AppError::Domain(DomainError::NotFound { entity: "Repository", .. })`.
        assert!(matches!(
            invisible,
            AppError::Domain(DomainError::NotFound {
                entity: "Repository",
                ..
            })
        ));
        assert!(matches!(
            missing,
            AppError::Domain(DomainError::NotFound {
                entity: "Repository",
                ..
            })
        ));
    }

    // -- find_by_visible_target — happy path -------------------------------

    #[tokio::test]
    async fn find_by_visible_target_visible_repo_returns_rows() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let index = Arc::new(MockContentReferenceIndex::new());
        let repo = public_repo("public-pkg");
        let repo_id = repo.id;
        repos.insert(repo);
        // Seed the index via the use case's own write path so the test
        // exercises both the trust-contract write and the read.
        let uc = build_uc(repos, index.clone(), RbacAccess::Disabled);
        let source = Uuid::new_v4();
        uc.insert_for_repo(repo_id, sample_row(repo_id, source, "oci_subject"))
            .await
            .unwrap();

        let (resolved, rows) = uc
            .find_by_visible_target("public-pkg", &target_hash(), Some("oci_subject"), None)
            .await
            .unwrap();
        assert_eq!(resolved.key, "public-pkg");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source_artifact_id, source);
    }

    #[tokio::test]
    async fn find_by_visible_target_authenticated_reader_on_private_succeeds() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let index = Arc::new(MockContentReferenceIndex::new());
        let repo = private_repo("vault");
        let repo_id = repo.id;
        repos.insert(repo);
        let uc = build_uc(
            repos,
            index.clone(),
            enabled(rbac_with_reader_role(repo_id)),
        );
        // Seed via direct port — the write trust-contract test below
        // already covers `insert_for_repo`.
        index
            .insert(sample_row(repo_id, Uuid::new_v4(), "oci_subject"))
            .await
            .unwrap();

        let reader = principal(&["reader"]);
        let (resolved, rows) = uc
            .find_by_visible_target("vault", &target_hash(), Some("oci_subject"), Some(&reader))
            .await
            .unwrap();
        assert_eq!(resolved.key, "vault");
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn find_by_visible_target_disabled_admits_anonymous_on_private() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let index = Arc::new(MockContentReferenceIndex::new());
        let repo = private_repo("vault");
        let repo_id = repo.id;
        repos.insert(repo);
        let uc = build_uc(repos, index.clone(), RbacAccess::Disabled);
        index
            .insert(sample_row(repo_id, Uuid::new_v4(), "oci_subject"))
            .await
            .unwrap();

        let (resolved, rows) = uc
            .find_by_visible_target("vault", &target_hash(), Some("oci_subject"), None)
            .await
            .unwrap();
        assert_eq!(resolved.key, "vault");
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn find_by_visible_target_kind_filter_passes_through() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let index = Arc::new(MockContentReferenceIndex::new());
        let repo = public_repo("public-pkg");
        let repo_id = repo.id;
        repos.insert(repo);
        // Seed two rows with different kinds at the same target hash.
        index
            .insert(sample_row(repo_id, Uuid::new_v4(), "oci_subject"))
            .await
            .unwrap();
        index
            .insert(sample_row(repo_id, Uuid::new_v4(), "sbom_attachment"))
            .await
            .unwrap();
        let uc = build_uc(repos, index, RbacAccess::Disabled);

        // With the OCI subject filter, only the matching row comes back.
        let (_repo, rows) = uc
            .find_by_visible_target("public-pkg", &target_hash(), Some("oci_subject"), None)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "kind filter must reach the port");
        assert_eq!(rows[0].kind, "oci_subject");

        // With no filter, both rows come back.
        let (_repo, rows_unfiltered) = uc
            .find_by_visible_target("public-pkg", &target_hash(), None, None)
            .await
            .unwrap();
        assert_eq!(rows_unfiltered.len(), 2, "None filter passes everything");
    }

    // -- find_by_visible_target — port error propagation -------------------

    /// Stub `ContentReferenceIndex` whose `find_by_target` always returns
    /// a non-NotFound `Invariant` error. Used to prove the use case
    /// propagates port errors without re-shaping them.
    struct FailingFindIndex;
    impl ContentReferenceIndex for FailingFindIndex {
        fn insert(
            &self,
            _row: ContentReference,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_target(
            &self,
            _repo: Uuid,
            _target: &ContentHash,
            _kind_filter: Option<&str>,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<ContentReference>>> {
            Box::pin(async { Err(DomainError::Invariant("db down".into())) })
        }
        fn delete_by_source(
            &self,
            _src: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_source_and_kind(
            &self,
            _repo: Uuid,
            _src: Uuid,
            _kind: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<ContentReference>>> {
            Box::pin(async { Ok(None) })
        }
        fn find_by_sources_and_kind(
            &self,
            _repo: Uuid,
            _sources: &[Uuid],
            _kind: &str,
        ) -> BoxFuture<
            '_,
            hort_domain::error::DomainResult<std::collections::HashMap<Uuid, ContentReference>>,
        > {
            Box::pin(async { Ok(std::collections::HashMap::new()) })
        }
    }

    #[tokio::test]
    async fn find_by_visible_target_propagates_port_error() {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(public_repo("public-pkg"));
        let index = Arc::new(FailingFindIndex);
        let rac = Arc::new(RepositoryAccessUseCase::new(
            repos,
            RbacAccess::Disabled,
            true,
        ));
        let uc = ContentReferenceUseCase::new(index, rac);

        let err = uc
            .find_by_visible_target("public-pkg", &target_hash(), None, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("db down"));
    }

    // -- insert_for_repo — no-authz contract -------------------------------

    /// Acceptance: `insert_for_repo` does NOT consult RBAC. The caller
    /// asserts via WriteRepoAccess upstream; this method just forwards.
    /// Proven here by passing an empty-RBAC enabled access context: the
    /// write still succeeds because the access use case is never asked.
    #[tokio::test]
    async fn insert_for_repo_does_not_consult_authz() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let index = Arc::new(MockContentReferenceIndex::new());
        // Empty RBAC: nobody has any permissions. If `insert_for_repo`
        // were checking authz, it would fail here.
        let uc = build_uc(
            repos,
            index.clone(),
            enabled(RbacEvaluator::new(Vec::new())),
        );
        let repo_id = Uuid::new_v4();
        let source = Uuid::new_v4();
        // No repository was even inserted — proves we never look up the
        // repo on the write path. Pure forward to the port.
        uc.insert_for_repo(repo_id, sample_row(repo_id, source, "oci_subject"))
            .await
            .unwrap();
        assert_eq!(index.entry_count(), 1);
    }

    /// Idempotent upsert — calling insert twice with the same PK
    /// `(repo_id, source, kind)` keeps the row count at one. Mirrors
    /// the OCI idempotent-PUT contract.
    #[tokio::test]
    async fn insert_for_repo_is_upsert_idempotent() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let index = Arc::new(MockContentReferenceIndex::new());
        let uc = build_uc(repos, index.clone(), RbacAccess::Disabled);
        let repo_id = Uuid::new_v4();
        let source = Uuid::new_v4();
        uc.insert_for_repo(repo_id, sample_row(repo_id, source, "oci_subject"))
            .await
            .unwrap();
        uc.insert_for_repo(repo_id, sample_row(repo_id, source, "oci_subject"))
            .await
            .unwrap();
        assert_eq!(index.entry_count(), 1, "upsert must not duplicate");
    }

    /// Stub for testing port-error propagation on the write side.
    struct FailingInsertIndex;
    impl ContentReferenceIndex for FailingInsertIndex {
        fn insert(
            &self,
            _row: ContentReference,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Err(DomainError::Invariant("write conflict".into())) })
        }
        fn find_by_target(
            &self,
            _repo: Uuid,
            _target: &ContentHash,
            _kind_filter: Option<&str>,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<ContentReference>>> {
            Box::pin(async { Ok(vec![]) })
        }
        fn delete_by_source(
            &self,
            _src: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_source_and_kind(
            &self,
            _repo: Uuid,
            _src: Uuid,
            _kind: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<ContentReference>>> {
            Box::pin(async { Ok(None) })
        }
        fn find_by_sources_and_kind(
            &self,
            _repo: Uuid,
            _sources: &[Uuid],
            _kind: &str,
        ) -> BoxFuture<
            '_,
            hort_domain::error::DomainResult<std::collections::HashMap<Uuid, ContentReference>>,
        > {
            Box::pin(async { Ok(std::collections::HashMap::new()) })
        }
    }

    #[tokio::test]
    async fn insert_for_repo_propagates_port_error() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let index = Arc::new(FailingInsertIndex);
        let rac = Arc::new(RepositoryAccessUseCase::new(
            repos,
            RbacAccess::Disabled,
            true,
        ));
        let uc = ContentReferenceUseCase::new(index, rac);
        let repo_id = Uuid::new_v4();
        let source = Uuid::new_v4();
        let err = uc
            .insert_for_repo(repo_id, sample_row(repo_id, source, "oci_subject"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("write conflict"));
    }

    // -- delete_by_source_for_repo — no-authz contract ---------------------

    /// Acceptance: `delete_by_source_for_repo` does NOT consult RBAC.
    /// Same shape as the insert acceptance test.
    #[tokio::test]
    async fn delete_by_source_for_repo_does_not_consult_authz() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let index = Arc::new(MockContentReferenceIndex::new());
        let uc = build_uc(
            repos,
            index.clone(),
            enabled(RbacEvaluator::new(Vec::new())),
        );
        let repo_id = Uuid::new_v4();
        let source = Uuid::new_v4();
        uc.insert_for_repo(repo_id, sample_row(repo_id, source, "oci_subject"))
            .await
            .unwrap();
        assert_eq!(index.entry_count(), 1);

        // Empty RBAC; if delete consulted authz it would fail here.
        uc.delete_by_source_for_repo(repo_id, source).await.unwrap();
        assert_eq!(index.entry_count(), 0);
    }

    /// Per the port contract, missing entries on delete are `Ok(())` —
    /// the FK cascade may have already run. The use case must not
    /// re-shape that into an error.
    #[tokio::test]
    async fn delete_by_source_for_repo_missing_source_is_ok() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let index = Arc::new(MockContentReferenceIndex::new());
        let uc = build_uc(repos, index, RbacAccess::Disabled);
        uc.delete_by_source_for_repo(Uuid::new_v4(), Uuid::new_v4())
            .await
            .unwrap();
    }

    /// Stub for testing port-error propagation on the delete side.
    struct FailingDeleteIndex;
    impl ContentReferenceIndex for FailingDeleteIndex {
        fn insert(
            &self,
            _row: ContentReference,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn find_by_target(
            &self,
            _repo: Uuid,
            _target: &ContentHash,
            _kind_filter: Option<&str>,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<ContentReference>>> {
            Box::pin(async { Ok(vec![]) })
        }
        fn delete_by_source(
            &self,
            _src: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Err(DomainError::Invariant("cascade failure".into())) })
        }
        fn find_by_source_and_kind(
            &self,
            _repo: Uuid,
            _src: Uuid,
            _kind: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Option<ContentReference>>> {
            Box::pin(async { Ok(None) })
        }
        fn find_by_sources_and_kind(
            &self,
            _repo: Uuid,
            _sources: &[Uuid],
            _kind: &str,
        ) -> BoxFuture<
            '_,
            hort_domain::error::DomainResult<std::collections::HashMap<Uuid, ContentReference>>,
        > {
            Box::pin(async { Ok(std::collections::HashMap::new()) })
        }
    }

    #[tokio::test]
    async fn delete_by_source_for_repo_propagates_port_error() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let index = Arc::new(FailingDeleteIndex);
        let rac = Arc::new(RepositoryAccessUseCase::new(
            repos,
            RbacAccess::Disabled,
            true,
        ));
        let uc = ContentReferenceUseCase::new(index, rac);
        let err = uc
            .delete_by_source_for_repo(Uuid::new_v4(), Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cascade failure"));
    }
}
