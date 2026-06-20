use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use hort_domain::entities::managed_by::ManagedBy;
use hort_domain::entities::repository::{
    IndexMode, PrefetchPolicy, PromotionConfig, ReplicationPriority, Repository, RepositoryFormat,
    RepositoryType,
};
use hort_domain::error::DomainError;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::types::{Page, PageRequest};

use crate::error::AppResult;

// ---------------------------------------------------------------------------
// Command structs
// ---------------------------------------------------------------------------

/// Command to create a new repository.
#[derive(Debug)]
pub struct CreateRepository {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: RepositoryFormat,
    pub repo_type: RepositoryType,
    pub storage_backend: String,
    pub storage_path: String,
    pub upstream_url: Option<String>,
    pub is_public: bool,
    pub quota_bytes: Option<i64>,
    pub replication_priority: ReplicationPriority,
    pub promotion: Option<PromotionConfig>,
    /// Names of `CurationRule` objects attached to this repository.
    /// Empty by default; the apply pipeline resolves names → ids and
    /// writes them via the curation-rule junction setter.
    pub curation_rule_names: Vec<String>,
}

/// Command to partially update a repository.
///
/// `None` = don't change, `Some(None)` = clear, `Some(Some(v))` = set.
#[derive(Debug)]
pub struct UpdateRepository {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub is_public: Option<bool>,
    pub quota_bytes: Option<Option<i64>>,
    pub upstream_url: Option<Option<String>>,
}

// ---------------------------------------------------------------------------
// RepositoryUseCase
// ---------------------------------------------------------------------------

/// Application use case for repository CRUD.
pub struct RepositoryUseCase {
    repos: Arc<dyn RepositoryRepository>,
}

impl RepositoryUseCase {
    pub fn new(repos: Arc<dyn RepositoryRepository>) -> Self {
        Self { repos }
    }

    /// Create a new repository.
    ///
    /// Validates that proxy repositories have an upstream URL, rejects
    /// keys colliding with a `managed_by = GitOps` row, then builds the
    /// full entity (with generated ID and timestamps) and persists it.
    #[tracing::instrument(skip(self, cmd))]
    pub async fn create(&self, cmd: CreateRepository) -> AppResult<Repository> {
        if cmd.repo_type == RepositoryType::Proxy && cmd.upstream_url.is_none() {
            return Err(DomainError::Validation(
                "proxy repository must have an upstream URL".into(),
            )
            .into());
        }

        // Reject creating a `Local` row whose `key` collides with an
        // already-declared `GitOps` row. Without this check the unique
        // index on `key` would surface as a generic 409 with no
        // operator-actionable message; routing through
        // `ManagedByConfiguration` produces the same problem+json
        // shape as update/delete and points at the YAML.
        match self.repos.find_by_key(&cmd.key).await {
            Ok(existing) if existing.managed_by == ManagedBy::GitOps => {
                tracing::info!(
                    kind = "repository",
                    name = %existing.key,
                    decision = "rejected_managed_by_gitops",
                    op = "create",
                    "create blocked — key collides with a gitops-managed repository"
                );
                return Err(DomainError::ManagedByConfiguration {
                    kind: "repository",
                    name: existing.key,
                }
                .into());
            }
            // `Local` row with the same key falls through to `save()`,
            // which surfaces the unique-index violation as the existing
            // 409 — keeps the legacy contract for non-managed
            // collisions intact.
            Ok(_) | Err(DomainError::NotFound { .. }) => {}
            Err(e) => return Err(e.into()),
        }

        let now = Utc::now();
        let repo = Repository {
            id: Uuid::new_v4(),
            key: cmd.key,
            name: cmd.name,
            description: cmd.description,
            format: cmd.format,
            repo_type: cmd.repo_type,
            storage_backend: cmd.storage_backend,
            storage_path: cmd.storage_path,
            upstream_url: cmd.upstream_url,
            // The public CRUD command struct does
            // not (yet) carry `index_upstream_url`. Operators who need
            // the override declare the repository via gitops, where the
            // typed `proxy.indexUpstreamUrl` field is plumbed through
            // ApplyConfigUseCase. A future Item may extend the public
            // CRUD surface; for now it stays `None`.
            index_upstream_url: None,
            is_public: cmd.is_public,
            // The opt-in download-audit flag
            // is gitops-managed (operators enable it via
            // the `downloadAuditEnabled` spec field, plumbed through
            // ApplyConfigUseCase). The public CRUD command does not
            // (yet) carry it; the same posture as `index_upstream_url`
            // above. CRUD-created repos default to `false`.
            download_audit_enabled: false,
            quota_bytes: cmd.quota_bytes,
            replication_priority: cmd.replication_priority,
            promotion: cmd.promotion,
            curation_rule_names: cmd.curation_rule_names,
            index_mode: IndexMode::ReleasedOnly,
            // The public CRUD command struct does not
            // (yet) carry a prefetch policy. Operators who want prefetch
            // declare the repository via gitops, where the typed
            // `prefetchPolicy` field is plumbed through ApplyConfigUseCase.
            // Mirrors the `index_mode` /
            // `download_audit_enabled` posture — CRUD-created repos
            // default to disabled.
            prefetch_policy: PrefetchPolicy::default(),
            created_at: now,
            updated_at: now,
            // Public CRUD path always writes Local. The gitops apply
            // path bypasses this use case entirely and uses a managed-write
            // port method that sets GitOps + digest in one statement.
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
        };

        self.repos.save(&repo).await?;
        Ok(repo)
    }

    /// Get a repository by ID.
    #[tracing::instrument(skip(self))]
    pub async fn get_by_id(&self, id: Uuid) -> AppResult<Repository> {
        Ok(self.repos.find_by_id(id).await?)
    }

    /// Get a repository by key.
    #[tracing::instrument(skip(self))]
    pub async fn get_by_key(&self, key: &str) -> AppResult<Repository> {
        Ok(self.repos.find_by_key(key).await?)
    }

    /// List repositories with optional search.
    #[tracing::instrument(skip(self))]
    pub async fn list(
        &self,
        page: PageRequest,
        search: Option<&str>,
    ) -> AppResult<Page<Repository>> {
        Ok(self.repos.list(page, search).await?)
    }

    /// Partially update a repository.
    ///
    /// Fetches the existing entity, rejects writes on rows that the
    /// gitops apply pipeline owns, applies the changes, and saves.
    /// The check lives here (not in the HTTP handler) so gRPC, CLI,
    /// and any future inbound surface inherit the rejection without
    /// duplicating the logic.
    #[tracing::instrument(skip(self, cmd))]
    pub async fn update(&self, id: Uuid, cmd: UpdateRepository) -> AppResult<Repository> {
        let mut repo = self.repos.find_by_id(id).await?;

        if repo.managed_by == ManagedBy::GitOps {
            tracing::info!(
                kind = "repository",
                name = %repo.key,
                decision = "rejected_managed_by_gitops",
                op = "update",
                "update blocked — repository is declared in $HORT_CONFIG_DIR"
            );
            return Err(DomainError::ManagedByConfiguration {
                kind: "repository",
                name: repo.key,
            }
            .into());
        }

        if let Some(name) = cmd.name {
            repo.name = name;
        }
        if let Some(description) = cmd.description {
            repo.description = description;
        }
        if let Some(is_public) = cmd.is_public {
            repo.is_public = is_public;
        }
        if let Some(quota_bytes) = cmd.quota_bytes {
            repo.quota_bytes = quota_bytes;
        }
        if let Some(upstream_url) = cmd.upstream_url {
            repo.upstream_url = upstream_url;
        }

        repo.updated_at = Utc::now();
        self.repos.save(&repo).await?;
        Ok(repo)
    }

    /// Delete a repository by ID.
    ///
    /// Same `ManagedByConfiguration` check as `update`. The gitops apply
    /// path uses `RepositoryRepository::delete_managed` — a separate port
    /// method that does NOT route through this use case and therefore is
    /// unaffected.
    #[tracing::instrument(skip(self))]
    pub async fn delete(&self, id: Uuid) -> AppResult<()> {
        let repo = self.repos.find_by_id(id).await?;
        if repo.managed_by == ManagedBy::GitOps {
            tracing::info!(
                kind = "repository",
                name = %repo.key,
                decision = "rejected_managed_by_gitops",
                op = "delete",
                "delete blocked — repository is declared in $HORT_CONFIG_DIR"
            );
            return Err(DomainError::ManagedByConfiguration {
                kind: "repository",
                name: repo.key,
            }
            .into());
        }
        Ok(self.repos.delete(id).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    // -- MockRepositoryRepository -------------------------------------------

    struct MockRepositoryRepository {
        repos: Mutex<HashMap<Uuid, Repository>>,
        // The reject-branch tests assert "save() must NOT be called on the
        // reject branch". A counter is the cleanest way to pin that —
        // checking for absence of state change leaves room for false positives
        // (e.g. if save was called but happened to write the same data).
        save_calls: std::sync::atomic::AtomicUsize,
        delete_calls: std::sync::atomic::AtomicUsize,
    }

    impl MockRepositoryRepository {
        fn new() -> Self {
            Self {
                repos: Mutex::new(HashMap::new()),
                save_calls: std::sync::atomic::AtomicUsize::new(0),
                delete_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn save_call_count(&self) -> usize {
            self.save_calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn delete_call_count(&self) -> usize {
            self.delete_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    use std::pin::Pin;
    type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

    impl RepositoryRepository for MockRepositoryRepository {
        fn find_by_id(
            &self,
            id: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Repository>> {
            let result =
                self.repos
                    .lock()
                    .unwrap()
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| DomainError::NotFound {
                        entity: "Repository",
                        id: id.to_string(),
                    });
            Box::pin(async move { result })
        }

        fn find_by_key(
            &self,
            key: &str,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Repository>> {
            let result = self
                .repos
                .lock()
                .unwrap()
                .values()
                .find(|r| r.key == key)
                .cloned()
                .ok_or_else(|| DomainError::NotFound {
                    entity: "Repository",
                    id: key.to_string(),
                });
            Box::pin(async move { result })
        }

        fn list(
            &self,
            page: PageRequest,
            search: Option<&str>,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Page<Repository>>> {
            let repos = self.repos.lock().unwrap();
            let mut items: Vec<Repository> = if let Some(q) = search {
                let q = q.to_lowercase();
                repos
                    .values()
                    .filter(|r| {
                        r.key.to_lowercase().contains(&q) || r.name.to_lowercase().contains(&q)
                    })
                    .cloned()
                    .collect()
            } else {
                repos.values().cloned().collect()
            };
            items.sort_by(|a, b| a.name.cmp(&b.name));
            let total = items.len() as u64;
            let offset = page.offset as usize;
            let limit = page.limit as usize;
            let items = items.into_iter().skip(offset).take(limit).collect();
            Box::pin(async move { Ok(Page { items, total }) })
        }

        fn save(
            &self,
            repository: &Repository,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            self.save_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.repos
                .lock()
                .unwrap()
                .insert(repository.id, repository.clone());
            Box::pin(async { Ok(()) })
        }

        fn delete(&self, id: Uuid) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            self.delete_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let existed = self.repos.lock().unwrap().remove(&id).is_some();
            Box::pin(async move {
                if existed {
                    Ok(())
                } else {
                    Err(DomainError::NotFound {
                        entity: "Repository",
                        id: id.to_string(),
                    })
                }
            })
        }

        fn get_virtual_members(
            &self,
            _virtual_repo_id: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<Vec<Repository>>> {
            Box::pin(async { Ok(vec![]) })
        }

        fn add_virtual_member(
            &self,
            _virtual_repo_id: Uuid,
            _member_repo_id: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn remove_virtual_member(
            &self,
            _virtual_repo_id: Uuid,
            _member_repo_id: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn replace_virtual_members(
            &self,
            _virtual_repo_id: Uuid,
            _ordered_member_ids: &[Uuid],
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn get_storage_usage(
            &self,
            _repo_id: Uuid,
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<u64>> {
            Box::pin(async { Ok(0) })
        }

        // These mock-local impls aren't exercised by the RepositoryUseCase
        // tests (which only touch the public CRUD path), but the trait
        // requires them.
        fn save_managed(
            &self,
            _repository: &Repository,
            _digest: &[u8; 32],
        ) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn delete_managed(&self, _id: Uuid) -> BoxFuture<'_, hort_domain::error::DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // -- Helpers -------------------------------------------------------------

    fn make_use_case() -> RepositoryUseCase {
        RepositoryUseCase::new(Arc::new(MockRepositoryRepository::new()))
    }

    /// Test variant that returns both the use case and a handle on the
    /// shared mock so reject-branch tests can assert `save_call_count() == 0`.
    fn make_use_case_with_mock() -> (RepositoryUseCase, Arc<MockRepositoryRepository>) {
        let mock = Arc::new(MockRepositoryRepository::new());
        let uc = RepositoryUseCase::new(mock.clone());
        (uc, mock)
    }

    /// Insert a managed-by-gitops fixture row directly into the mock,
    /// bypassing `RepositoryUseCase::create` (which would always write
    /// `Local`). Returns the row's id so tests can hit it via update /
    /// delete.
    fn insert_managed_repo(mock: &MockRepositoryRepository, key: &str) -> Uuid {
        use std::time::SystemTime;
        let id = Uuid::new_v4();
        let now = chrono::DateTime::from(SystemTime::now());
        mock.repos.lock().unwrap().insert(
            id,
            Repository {
                id,
                key: key.into(),
                name: key.into(),
                description: None,
                format: RepositoryFormat::Pypi,
                repo_type: RepositoryType::Hosted,
                storage_backend: "filesystem".into(),
                storage_path: format!("/data/{key}"),
                upstream_url: None,
                index_upstream_url: None,
                is_public: true,
                download_audit_enabled: false,
                quota_bytes: None,
                replication_priority: ReplicationPriority::LocalOnly,
                promotion: None,
                curation_rule_names: Vec::new(),
                index_mode: IndexMode::ReleasedOnly,
                prefetch_policy: PrefetchPolicy::default(),
                created_at: now,
                updated_at: now,
                managed_by: ManagedBy::GitOps,
                managed_by_digest: Some([0xab; 32]),
            },
        );
        id
    }

    fn hosted_repo_cmd() -> CreateRepository {
        CreateRepository {
            key: "maven-hosted".into(),
            name: "Maven Hosted".into(),
            description: Some("Hosted Maven repo".into()),
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Hosted,
            storage_backend: "filesystem".into(),
            storage_path: "/data/repos/maven-hosted".into(),
            upstream_url: None,
            is_public: true,
            quota_bytes: None,
            replication_priority: ReplicationPriority::LocalOnly,
            promotion: None,
            curation_rule_names: Vec::new(),
        }
    }

    // -- Create tests -------------------------------------------------------

    #[tokio::test]
    async fn create_hosted_repo() {
        let uc = make_use_case();
        let repo = uc.create(hosted_repo_cmd()).await.unwrap();

        assert_eq!(repo.key, "maven-hosted");
        assert_eq!(repo.name, "Maven Hosted");
        assert_eq!(repo.format, RepositoryFormat::Maven);
        assert_eq!(repo.repo_type, RepositoryType::Hosted);
        assert!(!repo.id.is_nil());
    }

    #[tokio::test]
    async fn create_proxy_repo_with_upstream() {
        let uc = make_use_case();
        let cmd = CreateRepository {
            key: "npm-proxy".into(),
            name: "NPM Proxy".into(),
            description: None,
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Proxy,
            storage_backend: "filesystem".into(),
            storage_path: "/data/repos/npm-proxy".into(),
            upstream_url: Some("https://registry.npmjs.org".into()),
            is_public: true,
            quota_bytes: None,
            replication_priority: ReplicationPriority::Scheduled,
            promotion: None,
            curation_rule_names: Vec::new(),
        };
        let repo = uc.create(cmd).await.unwrap();
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://registry.npmjs.org")
        );
    }

    #[tokio::test]
    async fn create_proxy_repo_without_upstream_fails() {
        let uc = make_use_case();
        let cmd = CreateRepository {
            repo_type: RepositoryType::Proxy,
            upstream_url: None,
            ..hosted_repo_cmd()
        };
        let err = uc.create(cmd).await.unwrap_err();
        assert!(err.to_string().contains("upstream URL"));
    }

    // -- Get tests ----------------------------------------------------------

    #[tokio::test]
    async fn get_by_id_found() {
        let uc = make_use_case();
        let repo = uc.create(hosted_repo_cmd()).await.unwrap();
        let found = uc.get_by_id(repo.id).await.unwrap();
        assert_eq!(found.id, repo.id);
    }

    #[tokio::test]
    async fn get_by_id_not_found() {
        let uc = make_use_case();
        let err = uc.get_by_id(Uuid::new_v4()).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn get_by_key_found() {
        let uc = make_use_case();
        uc.create(hosted_repo_cmd()).await.unwrap();
        let found = uc.get_by_key("maven-hosted").await.unwrap();
        assert_eq!(found.key, "maven-hosted");
    }

    #[tokio::test]
    async fn get_by_key_not_found() {
        let uc = make_use_case();
        let err = uc.get_by_key("nonexistent").await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    // -- List tests ---------------------------------------------------------

    #[tokio::test]
    async fn list_empty() {
        let uc = make_use_case();
        let page = uc.list(PageRequest::default(), None).await.unwrap();
        assert!(page.is_empty());
        assert_eq!(page.total, 0);
    }

    #[tokio::test]
    async fn list_with_results() {
        let uc = make_use_case();
        uc.create(hosted_repo_cmd()).await.unwrap();
        let page = uc.list(PageRequest::default(), None).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.total, 1);
    }

    #[tokio::test]
    async fn list_with_search() {
        let uc = make_use_case();
        uc.create(hosted_repo_cmd()).await.unwrap();
        uc.create(CreateRepository {
            key: "npm-hosted".into(),
            name: "NPM Hosted".into(),
            format: RepositoryFormat::Npm,
            ..hosted_repo_cmd()
        })
        .await
        .unwrap();

        let page = uc
            .list(PageRequest::default(), Some("maven"))
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].key, "maven-hosted");
    }

    #[tokio::test]
    async fn list_with_pagination() {
        let uc = make_use_case();
        for i in 0..5 {
            uc.create(CreateRepository {
                key: format!("repo-{i}"),
                name: format!("Repo {i}"),
                ..hosted_repo_cmd()
            })
            .await
            .unwrap();
        }

        let page = uc.list(PageRequest::new(0, 2), None).await.unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.total, 5);

        let page = uc.list(PageRequest::new(4, 2), None).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.total, 5);
    }

    // -- Update tests -------------------------------------------------------

    #[tokio::test]
    async fn update_partial_fields() {
        let uc = make_use_case();
        let repo = uc.create(hosted_repo_cmd()).await.unwrap();

        let updated = uc
            .update(
                repo.id,
                UpdateRepository {
                    name: Some("Renamed Repo".into()),
                    description: Some(None), // clear description
                    is_public: Some(false),
                    quota_bytes: Some(Some(1_000_000)),
                    upstream_url: None, // don't change
                },
            )
            .await
            .unwrap();

        assert_eq!(updated.name, "Renamed Repo");
        assert!(updated.description.is_none());
        assert!(!updated.is_public);
        assert_eq!(updated.quota_bytes, Some(1_000_000));
        assert!(updated.updated_at > repo.updated_at);
    }

    #[tokio::test]
    async fn update_not_found() {
        let uc = make_use_case();
        let err = uc
            .update(
                Uuid::new_v4(),
                UpdateRepository {
                    name: Some("x".into()),
                    description: None,
                    is_public: None,
                    quota_bytes: None,
                    upstream_url: None,
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    // -- Delete tests -------------------------------------------------------

    #[tokio::test]
    async fn delete_existing() {
        let uc = make_use_case();
        let repo = uc.create(hosted_repo_cmd()).await.unwrap();
        uc.delete(repo.id).await.unwrap();
        let err = uc.get_by_id(repo.id).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn delete_not_found() {
        let uc = make_use_case();
        let err = uc.delete(Uuid::new_v4()).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    // -- managed_by rejection -----------------------------------------------

    #[tokio::test]
    async fn update_on_managed_repo_returns_managed_by_configuration() {
        let (uc, mock) = make_use_case_with_mock();
        let id = insert_managed_repo(&mock, "npm-public");
        let saves_before = mock.save_call_count();

        let err = uc
            .update(
                id,
                UpdateRepository {
                    name: Some("renamed".into()),
                    description: None,
                    is_public: None,
                    quota_bytes: None,
                    upstream_url: None,
                },
            )
            .await
            .unwrap_err();

        // Right error variant + message identifies kind/name.
        match err {
            crate::error::AppError::Domain(DomainError::ManagedByConfiguration { kind, name }) => {
                assert_eq!(kind, "repository");
                assert_eq!(name, "npm-public");
            }
            other => panic!("expected ManagedByConfiguration, got {other:?}"),
        }

        // Save was NOT called on the reject branch — the load is
        // diagnostic, not write-coupled.
        assert_eq!(
            mock.save_call_count(),
            saves_before,
            "rejected update must not call save()"
        );
    }

    #[tokio::test]
    async fn delete_on_managed_repo_returns_managed_by_configuration() {
        let (uc, mock) = make_use_case_with_mock();
        let id = insert_managed_repo(&mock, "all-pypi");
        let deletes_before = mock.delete_call_count();

        let err = uc.delete(id).await.unwrap_err();
        match err {
            crate::error::AppError::Domain(DomainError::ManagedByConfiguration { kind, name }) => {
                assert_eq!(kind, "repository");
                assert_eq!(name, "all-pypi");
            }
            other => panic!("expected ManagedByConfiguration, got {other:?}"),
        }
        assert_eq!(
            mock.delete_call_count(),
            deletes_before,
            "rejected delete must not call port delete()"
        );
    }

    #[tokio::test]
    async fn create_with_key_colliding_managed_row_is_rejected() {
        let (uc, mock) = make_use_case_with_mock();
        insert_managed_repo(&mock, "maven-hosted");
        let saves_before = mock.save_call_count();

        // Default fixture uses key="maven-hosted" — same as the
        // managed row above.
        let err = uc.create(hosted_repo_cmd()).await.unwrap_err();
        match err {
            crate::error::AppError::Domain(DomainError::ManagedByConfiguration { kind, name }) => {
                assert_eq!(kind, "repository");
                assert_eq!(name, "maven-hosted");
            }
            other => panic!("expected ManagedByConfiguration, got {other:?}"),
        }
        assert_eq!(
            mock.save_call_count(),
            saves_before,
            "rejected create must not call save()"
        );
    }

    #[tokio::test]
    async fn update_on_local_repo_still_succeeds() {
        // Control: the managed-row check must not trip on the common
        // case. Without this we wouldn't know whether the rejection
        // tests above were passing for the wrong reason.
        let uc = make_use_case();
        let repo = uc.create(hosted_repo_cmd()).await.unwrap();
        let updated = uc
            .update(
                repo.id,
                UpdateRepository {
                    name: Some("renamed".into()),
                    description: None,
                    is_public: None,
                    quota_bytes: None,
                    upstream_url: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "renamed");
    }
}
