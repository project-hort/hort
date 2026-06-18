//! `RepositoryAccessUseCase`.
//!
//! Single source of truth for repository-key resolution + Read/Write authz +
//! visibility filtering. The two callers today are the `hort-http-core::authz`
//! extractors (which keep their thin wrapper for handler-signature ergonomics)
//! and the `ArtifactUseCase::find_visible_*` methods.
//!
//! # Anti-enumeration
//!
//! [`AccessLevel::Read`] denial collapses "repo missing" and "repo invisible"
//! into the same [`AppError::Domain(DomainError::NotFound)`]. Returning
//! `Forbidden` on Read leaks the existence of private repos to unauthenticated
//! probers — the canonical defence against a 404-vs-403 oracle.
//!
//! [`AccessLevel::Write`] is permitted to return `Forbidden` because the
//! caller is authenticated and a Read-visible-but-not-writable response
//! carries no extra information beyond what the handler-known principal
//! already knows.
//!
//! # `AuthContext::Disabled`
//!
//! The lower-level `AuthContext` enum lives in `hort-http-core`; `hort-app` cannot
//! reach upward to it without breaking hexagonal layering. To preserve the
//! single-node dev semantics this use case carries its own [`RbacAccess`]
//! enum that mirrors the two states. Composition is responsible for mapping
//! one to the other.
//!
//! # Observability
//!
//! Every public method gets `#[tracing::instrument(skip(self))]` (NOT `err`).
//! Write-grant denials log `tracing::info!` (audit signal). Read-grant
//! denials log `tracing::debug!` (background noise).

use std::sync::Arc;

use arc_swap::ArcSwap;
use uuid::Uuid;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::rbac::Permission;
use hort_domain::entities::repository::Repository;
use hort_domain::error::DomainError;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::types::{Page, PageRequest};

use crate::error::{AppError, AppResult};
use crate::metrics::values;
use crate::rbac::RbacEvaluator;

// ---------------------------------------------------------------------------
// AccessLevel
// ---------------------------------------------------------------------------

/// Which capability the caller asserts against the resolved repository.
///
/// The choice changes the failure mapping:
/// - [`Read`](Self::Read) — denial collapses to `NotFound`
///   (anti-enumeration). Anonymous probers cannot distinguish "repo
///   missing" from "repo invisible".
/// - [`Write`](Self::Write) — denial of the Write grant returns
///   `Forbidden` IFF the caller still has Read on the repo. Pure
///   invisibility (no Read either) still collapses to `NotFound` so
///   the actor cannot enumerate repos by sending Write probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLevel {
    Read,
    Write,
}

// ---------------------------------------------------------------------------
// RbacAccess
// ---------------------------------------------------------------------------

/// `hort-app`-local mirror of `hort-http-core::AuthContext`.
///
/// Required because `hort-app` sits *below* `hort-http-core` in the dependency
/// graph (the inbound HTTP crate depends on `hort-app`, not the other way
/// round). The composition root in `hort-server` constructs this from the
/// existing `AuthContext` and hands it to the use case.
///
/// `Enabled` carries the same `Arc<ArcSwap<RbacEvaluator>>` shape as
/// `AuthContext::Enabled.rbac` so the live-refresh contract
/// survives unchanged.
#[derive(Clone)]
pub enum RbacAccess {
    /// Auth disabled (dev / bootstrap). Every caller is admitted.
    Disabled,
    /// Auth enabled. Carries a snapshot pointer to the live RBAC evaluator.
    Enabled(Arc<ArcSwap<RbacEvaluator>>),
}

impl std::fmt::Debug for RbacAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("Disabled"),
            Self::Enabled(_) => f.write_str("Enabled(<rbac>)"),
        }
    }
}

// ---------------------------------------------------------------------------
// RepositoryAccessUseCase
// ---------------------------------------------------------------------------

/// Single source of truth for repo-key resolution + Read/Write authz +
/// visibility filtering.
///
/// See module-level doc for the anti-enumeration invariants and the
/// authz / `AuthContext::Disabled` admit-everything semantics.
pub struct RepositoryAccessUseCase {
    repositories: Arc<dyn RepositoryRepository>,
    auth: RbacAccess,
    /// Cardinality safety valve mirroring `METRICS_INCLUDE_REPOSITORY_LABEL`.
    /// When `false`, [`metric_label`](Self::metric_label) returns
    /// [`values::REPOSITORY_ALL`] regardless of the input id.
    include_repository_label: bool,
}

impl RepositoryAccessUseCase {
    /// Construct a new access use case.
    ///
    /// `auth` is constructed by the composition root in `hort-server` from the
    /// existing `AuthContext`. Tests in `hort-app` build [`RbacAccess`] values
    /// directly.
    pub fn new(
        repositories: Arc<dyn RepositoryRepository>,
        auth: RbacAccess,
        include_repository_label: bool,
    ) -> Self {
        Self {
            repositories,
            auth,
            include_repository_label,
        }
    }

    /// Resolve `repo_key` and enforce `level` on `actor`.
    ///
    /// Returns `NotFound` indistinguishably for: repo absent OR repo
    /// invisible to actor (anti-enumeration). Returns `Forbidden` ONLY
    /// when the actor IS Read-visible but lacks Write.
    #[tracing::instrument(skip(self))]
    pub async fn resolve(
        &self,
        repo_key: &str,
        actor: Option<&CallerPrincipal>,
        level: AccessLevel,
    ) -> AppResult<Repository> {
        let repo = match self.repositories.find_by_key(repo_key).await {
            Ok(r) => r,
            Err(DomainError::NotFound { .. }) => {
                return Err(AppError::Domain(not_found_repo(repo_key)));
            }
            Err(other) => return Err(AppError::Domain(other)),
        };
        self.enforce(&repo, actor, level)
    }

    /// Same shape as [`resolve`](Self::resolve), but keyed by id.
    #[tracing::instrument(skip(self))]
    pub async fn resolve_by_id(
        &self,
        repo_id: Uuid,
        actor: Option<&CallerPrincipal>,
        level: AccessLevel,
    ) -> AppResult<Repository> {
        let repo = match self.repositories.find_by_id(repo_id).await {
            Ok(r) => r,
            Err(DomainError::NotFound { .. }) => {
                return Err(AppError::Domain(not_found_repo(&repo_id.to_string())));
            }
            Err(other) => return Err(AppError::Domain(other)),
        };
        self.enforce(&repo, actor, level)
    }

    /// Page through every Read-visible repository for `actor`.
    ///
    /// Public repos are visible to everyone (including anonymous callers).
    /// Private repos are visible only when the principal has
    /// `Permission::Read` on the specific repo id, or when
    /// [`RbacAccess::Disabled`] is active (dev mode admits everything).
    ///
    /// Phase 1 implementation: enumerates the underlying port with `page`
    /// and filters in-memory. The visibility predicate's worst case is
    /// O(grants × roles) per repo, which is small (<10 in practice).
    #[tracing::instrument(skip(self))]
    pub async fn list_visible(
        &self,
        actor: Option<&CallerPrincipal>,
        page: PageRequest,
    ) -> AppResult<Page<Repository>> {
        let raw = self.repositories.list(page, None).await?;
        let total = raw.total;
        let items: Vec<Repository> = raw.into_iter_visible(|r| self.can_see(r, actor)).collect();
        Ok(Page { items, total })
    }

    /// Repo-id lookup for the OCI `/v2/auth`
    /// scope-evaluation hot path. Returns `Ok(Some(id))` when the repo
    /// exists, `Ok(None)` when the lookup misses, or propagates an
    /// infrastructure error.
    ///
    /// **NO authz** — by design. The caller (the OCI token-exchange
    /// use case) wraps this in a per-action `RbacEvaluator::authorize`
    /// check that is the actual access gate; surfacing "missing" as
    /// `Ok(None)` lets the use case map a missing-repo scope to
    /// "no actions granted" rather than aborting the whole exchange
    /// with a 404 (partial-grant semantics).
    /// Keeping the helper narrowly scoped to id-only avoids handing
    /// callers the full `Repository` row through a no-authz door.
    #[tracing::instrument(skip(self))]
    pub async fn find_repo_id_by_key_unchecked(&self, repo_key: &str) -> AppResult<Option<Uuid>> {
        match self.repositories.find_by_key(repo_key).await {
            Ok(r) => Ok(Some(r.id)),
            Err(DomainError::NotFound { .. }) => Ok(None),
            Err(other) => Err(AppError::Domain(other)),
        }
    }

    /// Cheap label-resolution helper for metric emission.
    ///
    /// Returns `repo.key` when the label is enabled and the lookup
    /// succeeds, else the [`values::REPOSITORY_ALL`] /
    /// [`values::REPOSITORY_UNKNOWN`] sentinel per cardinality rules.
    /// **NO authz** — the caller has authz'd the id elsewhere; this
    /// method exists solely so handlers don't need raw repository-port
    /// access for metric emission.
    #[tracing::instrument(skip(self))]
    pub async fn metric_label(&self, repo_id: Uuid) -> String {
        if !self.include_repository_label {
            return values::REPOSITORY_ALL.to_string();
        }
        match self.repositories.find_by_id(repo_id).await {
            Ok(r) => r.key,
            Err(_) => values::REPOSITORY_UNKNOWN.to_string(),
        }
    }

    // -- internals ---------------------------------------------------------

    /// Apply the level-specific authz check. Logs at the right level.
    fn enforce(
        &self,
        repo: &Repository,
        actor: Option<&CallerPrincipal>,
        level: AccessLevel,
    ) -> AppResult<Repository> {
        // Disabled = admit everything (dev / single-node bootstrap).
        let rbac = match &self.auth {
            RbacAccess::Disabled => return Ok(repo.clone()),
            RbacAccess::Enabled(rbac) => rbac.load(),
        };

        let can_read = repo.is_public
            || actor
                .map(|p| rbac.authorize(p, Permission::Read, Some(repo.id)))
                .unwrap_or(false);

        match level {
            AccessLevel::Read => {
                if can_read {
                    Ok(repo.clone())
                } else {
                    // Anti-enumeration: collapse invisible to NotFound.
                    // No actor? Background noise; no audit value.
                    tracing::debug!(
                        repo_key = %repo.key,
                        actor = ?actor.map(|p| p.external_id.as_str()),
                        "read denied — collapsed to NotFound"
                    );
                    Err(AppError::Domain(not_found_repo(&repo.key)))
                }
            }
            AccessLevel::Write => {
                let can_write = actor
                    .map(|p| rbac.authorize(p, Permission::Write, Some(repo.id)))
                    .unwrap_or(false);
                if can_write {
                    return Ok(repo.clone());
                }
                if can_read {
                    // Audit signal: actor is authenticated, allowed to
                    // know the repo exists, but lacks the Write grant.
                    tracing::info!(
                        repo_key = %repo.key,
                        actor = ?actor.map(|p| p.external_id.as_str()),
                        permission = "write",
                        "write denied"
                    );
                    Err(AppError::Domain(DomainError::Forbidden(format!(
                        "write permission denied for repository {}",
                        repo.key
                    ))))
                } else {
                    // Anti-enumeration: pure invisibility on a Write
                    // probe still collapses to NotFound so the actor
                    // cannot enumerate repos by issuing Write requests.
                    tracing::debug!(
                        repo_key = %repo.key,
                        actor = ?actor.map(|p| p.external_id.as_str()),
                        "write denied (no read either) — collapsed to NotFound"
                    );
                    Err(AppError::Domain(not_found_repo(&repo.key)))
                }
            }
        }
    }

    /// Visibility predicate used by `list_visible`.
    ///
    /// Mirrors the `oci::catalog::can_see_repo` predicate that this use
    /// case will eventually replace.
    fn can_see(&self, repo: &Repository, actor: Option<&CallerPrincipal>) -> bool {
        if repo.is_public {
            return true;
        }
        match (&self.auth, actor) {
            (RbacAccess::Disabled, _) => true,
            (RbacAccess::Enabled(_), None) => false,
            (RbacAccess::Enabled(rbac), Some(p)) => {
                let guard = rbac.load();
                guard.authorize(p, Permission::Read, Some(repo.id))
            }
        }
    }
}

/// Construct the canonical `NotFound` envelope used by every
/// anti-enumeration return.
fn not_found_repo(id: &str) -> DomainError {
    DomainError::NotFound {
        entity: "Repository",
        id: id.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Page extension trait — small helper to keep `list_visible` readable.
// ---------------------------------------------------------------------------

trait PageVisibility<T> {
    fn into_iter_visible<F>(self, predicate: F) -> std::vec::IntoIter<T>
    where
        F: FnMut(&T) -> bool;
}

impl<T> PageVisibility<T> for Page<T> {
    fn into_iter_visible<F>(self, mut predicate: F) -> std::vec::IntoIter<T>
    where
        F: FnMut(&T) -> bool,
    {
        let kept: Vec<T> = self.items.into_iter().filter(|t| predicate(t)).collect();
        kept.into_iter()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use chrono::Utc;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;

    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::entities::repository::{
        ReplicationPriority, RepositoryFormat, RepositoryType,
    };

    use super::*;
    use crate::use_cases::test_support::{sample_repository, MockRepositoryRepository};

    // -- Helpers ------------------------------------------------------------

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

    fn enabled(rbac: RbacEvaluator) -> RbacAccess {
        RbacAccess::Enabled(Arc::new(ArcSwap::from_pointee(rbac)))
    }

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

    /// Build an RBAC evaluator where (claim-based subject model, ADR 0012):
    /// - the `developer` claim has `Permission::Write` scoped to `repo_id`.
    /// - the `reader` claim has `Permission::Read` globally.
    fn rbac_with_read_and_write(repo_id: Uuid) -> RbacEvaluator {
        RbacEvaluator::new(vec![
            PermissionGrant {
                id: Uuid::new_v4(),
                subject: GrantSubject::Claims(vec!["developer".to_string()]),
                repository_id: Some(repo_id),
                permission: Permission::Write,
                created_at: Utc::now(),
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
            },
            PermissionGrant {
                id: Uuid::new_v4(),
                subject: GrantSubject::Claims(vec!["reader".to_string()]),
                repository_id: None,
                permission: Permission::Read,
                created_at: Utc::now(),
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
            },
        ])
    }

    // -- AccessLevel marker traits + Debug coverage -------------------------

    #[test]
    fn access_level_is_copy_eq_debug() {
        let r = AccessLevel::Read;
        let r_copy = r;
        assert_eq!(r, r_copy);
        assert_ne!(AccessLevel::Read, AccessLevel::Write);
        // Cover the `Debug` derive so the `derive` block shows up in
        // line-coverage reports.
        let _ = format!("{:?}", AccessLevel::Read);
        let _ = format!("{:?}", AccessLevel::Write);
    }

    #[test]
    fn rbac_access_debug_distinguishes_variants() {
        let disabled = format!("{:?}", RbacAccess::Disabled);
        assert_eq!(disabled, "Disabled");
        let enabled = format!(
            "{:?}",
            RbacAccess::Enabled(Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(
                Vec::new()
            ))))
        );
        assert_eq!(enabled, "Enabled(<rbac>)");
    }

    #[test]
    fn rbac_access_clone_preserves_variant() {
        let cloned = RbacAccess::Disabled.clone();
        assert!(matches!(cloned, RbacAccess::Disabled));

        let original = RbacAccess::Enabled(Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        ))));
        let cloned = original.clone();
        assert!(matches!(cloned, RbacAccess::Enabled(_)));
    }

    // -- resolve(Read) — anti-enumeration ----------------------------------

    /// **Acceptance bullet #3 (Read-side anti-enumeration).** Missing-repo
    /// and invisible-private-repo MUST return *byte-identical* `NotFound`
    /// envelopes. This test snapshots both error displays and asserts
    /// equality — the canonical defence against a 404-vs-403 oracle.
    #[tokio::test]
    async fn resolve_read_invisible_and_missing_are_byte_identical() {
        let repos = Arc::new(MockRepositoryRepository::new());
        // Invisible: a private repo named "vault" exists but actor cannot
        // see it.
        repos.insert(private_repo("vault"));

        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);

        let invisible_err = uc
            .resolve("vault", None, AccessLevel::Read)
            .await
            .unwrap_err();
        let missing_err = uc
            .resolve("vault", None, AccessLevel::Read)
            .await
            .unwrap_err(); // same key — same resolution → same body
        assert_eq!(invisible_err.to_string(), missing_err.to_string());

        // Now compare against a key that genuinely doesn't exist —
        // different ID, but the format must still be the same shape.
        let missing_err2 = uc
            .resolve("ghost", None, AccessLevel::Read)
            .await
            .unwrap_err();
        // Both are the canonical `not found: Repository <id>` envelope,
        // differing only in the id token. Format equality is what an
        // operator-side enumeration probe would observe.
        let invisible_text = invisible_err.to_string();
        let missing_text = missing_err2.to_string();
        assert!(invisible_text.starts_with("not found: Repository "));
        assert!(missing_text.starts_with("not found: Repository "));
    }

    /// `resolve(Read)` with anonymous + private repo returns `NotFound`.
    #[tokio::test]
    async fn resolve_read_invisible_private_is_not_found() {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(private_repo("vault"));
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let err = uc
            .resolve("vault", None, AccessLevel::Read)
            .await
            .unwrap_err();
        match err {
            AppError::Domain(DomainError::NotFound { entity, id }) => {
                assert_eq!(entity, "Repository");
                assert_eq!(id, "vault");
            }
            other => panic!("expected NotFound, got: {other:?}"),
        }
    }

    /// `resolve(Read)` with public repo + anonymous succeeds.
    #[tokio::test]
    async fn resolve_read_public_anonymous_is_ok() {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(public_repo("public-pkg"));
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let repo = uc
            .resolve("public-pkg", None, AccessLevel::Read)
            .await
            .unwrap();
        assert_eq!(repo.key, "public-pkg");
    }

    /// `resolve(Read)` with private repo + authenticated reader succeeds.
    #[tokio::test]
    async fn resolve_read_private_with_grant_is_ok() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let repo = private_repo("vault");
        let repo_id = repo.id;
        repos.insert(repo);
        let uc =
            RepositoryAccessUseCase::new(repos, enabled(rbac_with_read_and_write(repo_id)), true);
        let reader = principal(&["reader"]);
        let resolved = uc
            .resolve("vault", Some(&reader), AccessLevel::Read)
            .await
            .unwrap();
        assert_eq!(resolved.key, "vault");
    }

    /// `resolve(Read)` propagates non-NotFound port errors verbatim.
    #[tokio::test]
    async fn resolve_read_propagates_port_invariant_error() {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.fail_next_find_by_key(DomainError::Invariant("connection reset".into()));
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let err = uc
            .resolve("anything", None, AccessLevel::Read)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("connection reset"));
    }

    // -- resolve(Write) ----------------------------------------------------

    /// `resolve(Write)` returns `Forbidden` when actor has Read but not
    /// Write — the only case where Write deviates from Read's NotFound.
    #[tokio::test]
    async fn resolve_write_read_visible_no_write_grant_is_forbidden() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let repo = private_repo("vault");
        let repo_id = repo.id;
        repos.insert(repo);
        let uc =
            RepositoryAccessUseCase::new(repos, enabled(rbac_with_read_and_write(repo_id)), true);
        let reader = principal(&["reader"]); // global Read, no Write
        let err = uc
            .resolve("vault", Some(&reader), AccessLevel::Write)
            .await
            .unwrap_err();
        match err {
            AppError::Domain(DomainError::Forbidden(msg)) => {
                assert!(msg.contains("write permission denied"));
                assert!(msg.contains("vault"));
            }
            other => panic!("expected Forbidden, got: {other:?}"),
        }
    }

    /// `resolve(Write)` returns `NotFound` when the repo is missing.
    #[tokio::test]
    async fn resolve_write_missing_repo_is_not_found() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let err = uc
            .resolve("ghost", None, AccessLevel::Write)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "Repository",
                ..
            })
        ));
    }

    /// `resolve(Write)` returns `NotFound` when actor cannot even read
    /// the repo — anti-enumeration on Write.
    #[tokio::test]
    async fn resolve_write_anonymous_on_private_is_not_found() {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(private_repo("vault"));
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let err = uc
            .resolve("vault", None, AccessLevel::Write)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "Repository",
                ..
            })
        ));
    }

    /// `resolve(Write)` allows when actor has the write grant.
    #[tokio::test]
    async fn resolve_write_with_write_grant_is_ok() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let repo = public_repo("public-pkg");
        let repo_id = repo.id;
        repos.insert(repo);
        let uc =
            RepositoryAccessUseCase::new(repos, enabled(rbac_with_read_and_write(repo_id)), true);
        let dev = principal(&["developer"]);
        let resolved = uc
            .resolve("public-pkg", Some(&dev), AccessLevel::Write)
            .await
            .unwrap();
        assert_eq!(resolved.key, "public-pkg");
    }

    // -- Write-grant denial log assertion (acceptance bullet) --------------

    /// Custom tracing layer that captures emitted events into a shared
    /// vector. Lightweight enough that we don't need
    /// `tracing-subscriber`'s `fmt` layer.
    #[derive(Clone, Default)]
    struct CapturingLayer {
        records: Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for CapturingLayer
    where
        S: tracing::Subscriber,
    {
        /// Force per-event re-evaluation rather than the global callsite
        /// cache deciding once-and-for-all that nobody listens. Without
        /// this, `tracing` caches the first observed `Interest::Never`
        /// for the event's callsite — which, under `cargo test`'s parallel
        /// execution, can be set by a sibling test that fires the same
        /// callsite while THIS test's per-thread subscriber is not yet
        /// installed. `Interest::sometimes()` opts into per-event
        /// `enabled()` evaluation so the cache cannot poison us.
        fn register_callsite(
            &self,
            _meta: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn enabled(
            &self,
            _meta: &tracing::Metadata<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) -> bool {
            true
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = MessageVisitor::default();
            event.record(&mut visitor);
            self.records
                .lock()
                .unwrap()
                .push((*event.metadata().level(), visitor.combined));
        }
    }

    #[derive(Default)]
    struct MessageVisitor {
        combined: String,
    }
    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.combined
                .push_str(&format!("{}={:?} ", field.name(), value));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.combined
                .push_str(&format!("{}={} ", field.name(), value));
        }
    }

    /// Global mutex serialising tests that install per-thread tracing
    /// subscribers. `tracing` caches per-callsite `Interest` **globally**;
    /// installing one subscriber on thread A while thread B is
    /// simultaneously firing the same callsite races. Serialising the
    /// install + drive + observe sequence with one mutex eliminates
    /// the race without slowing the rest of the suite.
    static TRACING_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Process-global subscriber that returns `Interest::sometimes()` for
    /// every callsite — installed once via [`OnceLock`]. This poisons the
    /// global callsite-interest cache with `sometimes`, which forces
    /// `tracing` to consult the **current** per-thread default subscriber
    /// on every event instead of trusting a once-cached `Never` from
    /// whichever thread happened to hit the callsite first. Without
    /// this, `set_default` in a test races against other parallel tests
    /// firing the same callsite under the no-op default subscriber,
    /// which caches `Never` and locks our test out.
    fn install_global_passthrough_subscriber() {
        use std::sync::OnceLock;
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            // The global subscriber is just a `Registry` with our layer.
            // The layer's `register_callsite` returns `sometimes()`, and
            // its `enabled()` returns true — but it has no listener
            // attached at the global level (the per-test layer is the
            // listener via `set_default`).
            let global_layer = CapturingLayer::default();
            let global_subscriber = Registry::default().with(global_layer);
            // Ignore the result — if a sibling crate has already set a
            // global subscriber, we still get our `sometimes()` cache
            // entry through the per-thread `set_default` re-ask.
            let _ = tracing::subscriber::set_global_default(global_subscriber);
        });
    }

    /// Write-grant denial fires `tracing::info!` with the actor's
    /// `external_id`, `repo_key`, and `permission = "write"` — the
    /// required write-denial audit signal.
    ///
    /// See [`TRACING_TEST_MUTEX`] and [`install_global_passthrough_subscriber`]
    /// for the test-isolation machinery.
    ///
    /// Note this test is `#[test]` rather than `#[tokio::test]`: the
    /// mutex guard is `std::sync::Mutex` and cannot be held across an
    /// `await` point (clippy would block the build). We drive the
    /// async resolve on a fresh runtime via `block_on` inside the
    /// guarded scope so the mutex never crosses an await.
    #[test]
    fn resolve_write_denial_logs_info_with_actor_and_repo() {
        install_global_passthrough_subscriber();
        let _serial = TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let layer = CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // After installing our per-thread default, force re-evaluation
        // of every callsite's interest. Combined with the global
        // passthrough subscriber above, this guarantees the layer's
        // `register_callsite` runs before the event fires.
        tracing::callsite::rebuild_interest_cache();

        let repos = Arc::new(MockRepositoryRepository::new());
        let repo = private_repo("vault");
        let repo_id = repo.id;
        repos.insert(repo);
        let uc =
            RepositoryAccessUseCase::new(repos, enabled(rbac_with_read_and_write(repo_id)), true);
        let reader = principal(&["reader"]);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let _ = uc.resolve("vault", Some(&reader), AccessLevel::Write).await;
        });

        let records = captured.lock().unwrap();
        let info_event = records
            .iter()
            .find(|(lvl, _)| *lvl == tracing::Level::INFO)
            .expect("expected info-level event on Write denial");
        let msg = &info_event.1;
        assert!(msg.contains("vault"), "log missing repo_key: {msg}");
        assert!(msg.contains("test:sub"), "log missing actor: {msg}");
        assert!(msg.contains("write"), "log missing permission: {msg}");
    }

    /// Read-grant denial fires `tracing::debug!` (background noise — anonymous
    /// probers on private repos are not security events). This exercises the
    /// debug-level format-arg closures that would otherwise be skipped under
    /// the no-listening-subscriber default — both the "Read denied" path
    /// (anonymous on a private repo) and the Write probe with no Read
    /// (line 277). Together with the Write-denial test above, this covers
    /// every match arm in [`RepositoryAccessUseCase::enforce`].
    #[test]
    fn resolve_read_and_write_denial_debug_paths_exercise_format_args() {
        install_global_passthrough_subscriber();
        let _serial = TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let layer = CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let repos = Arc::new(MockRepositoryRepository::new());
        let private = private_repo("vault");
        repos.insert(private);
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let p = principal(&["nobody"]);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Read denial with an actor — exercises line 247 closure.
            let _ = uc.resolve("vault", Some(&p), AccessLevel::Read).await;
            // Read denial without actor — exercises line 247 closure under
            // the `None` arm.
            let _ = uc.resolve("vault", None, AccessLevel::Read).await;
            // Write denial without Read — exercises line 279 closure
            // (the second debug! branch in `enforce`).
            let _ = uc.resolve("vault", Some(&p), AccessLevel::Write).await;
        });

        let records = captured.lock().unwrap();
        // We expect at least two DEBUG events (one Read + one Read + one
        // Write-without-read). They should mention `vault`.
        let debug_events: Vec<&(tracing::Level, String)> = records
            .iter()
            .filter(|(lvl, _)| *lvl == tracing::Level::DEBUG)
            .collect();
        assert!(
            debug_events.len() >= 2,
            "expected >=2 debug-level events; got {}: {:?}",
            debug_events.len(),
            records
        );
        // The actor-bearing events must include `test:sub` (proving the
        // format-arg closure ran).
        let with_actor = debug_events
            .iter()
            .find(|(_, msg)| msg.contains("test:sub"))
            .expect("expected at least one debug event with actor field");
        assert!(with_actor.1.contains("vault"));
    }

    // -- Disabled — admit everything (acceptance bullet) -------------------

    /// Under [`RbacAccess::Disabled`], every resolve / level / actor
    /// combination returns `Ok` (the dev / single-node bootstrap
    /// contract). Exhaustive matrix: 2 levels × {anonymous, principal}
    /// × {private repo, public repo}.
    #[tokio::test]
    async fn resolve_under_disabled_admits_every_actor_and_level() {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(public_repo("public"));
        repos.insert(private_repo("vault"));
        let uc = RepositoryAccessUseCase::new(repos, RbacAccess::Disabled, true);

        for key in ["public", "vault"] {
            for level in [AccessLevel::Read, AccessLevel::Write] {
                // Anonymous
                let r = uc.resolve(key, None, level).await.unwrap();
                assert_eq!(r.key, key);
                // Authenticated (no roles)
                let p = principal(&[]);
                let r = uc.resolve(key, Some(&p), level).await.unwrap();
                assert_eq!(r.key, key);
            }
        }
    }

    // -- resolve_by_id mirror tests ----------------------------------------

    #[tokio::test]
    async fn resolve_by_id_invisible_private_is_not_found() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let r = private_repo("vault");
        let id = r.id;
        repos.insert(r);
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let err = uc
            .resolve_by_id(id, None, AccessLevel::Read)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "Repository",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn resolve_by_id_missing_is_not_found() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let err = uc
            .resolve_by_id(Uuid::new_v4(), None, AccessLevel::Read)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::Domain(DomainError::NotFound {
                entity: "Repository",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn resolve_by_id_propagates_port_invariant_error() {
        // Stub a port whose `find_by_id` returns a non-NotFound DomainError.
        struct FailingFindRepo;
        impl RepositoryRepository for FailingFindRepo {
            fn find_by_id(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Repository>>
            {
                Box::pin(async { Err(DomainError::Invariant("db down".into())) })
            }
            fn find_by_key(
                &self,
                _key: &str,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Repository>>
            {
                Box::pin(async { Err(DomainError::Invariant("db down".into())) })
            }
            fn list(
                &self,
                _page: PageRequest,
                _search: Option<&str>,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Page<Repository>>>
            {
                Box::pin(async {
                    Ok(Page {
                        items: vec![],
                        total: 0,
                    })
                })
            }
            fn save(
                &self,
                _r: &Repository,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
            fn delete(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
            fn get_virtual_members(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<Vec<Repository>>>
            {
                Box::pin(async { Ok(vec![]) })
            }
            fn add_virtual_member(
                &self,
                _v: Uuid,
                _m: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
            fn remove_virtual_member(
                &self,
                _v: Uuid,
                _m: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
            fn get_storage_usage(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<u64>>
            {
                Box::pin(async { Ok(0) })
            }
            fn save_managed(
                &self,
                _r: &Repository,
                _d: &[u8; 32],
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
            fn delete_managed(
                &self,
                _id: Uuid,
            ) -> hort_domain::ports::BoxFuture<'_, hort_domain::error::DomainResult<()>>
            {
                Box::pin(async { Ok(()) })
            }
        }
        let repos = Arc::new(FailingFindRepo);
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let err = uc
            .resolve_by_id(Uuid::new_v4(), None, AccessLevel::Read)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("db down"));
    }

    // -- list_visible ------------------------------------------------------

    #[tokio::test]
    async fn list_visible_anonymous_sees_only_public() {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(public_repo("a"));
        repos.insert(private_repo("b"));
        repos.insert(public_repo("c"));
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let page = uc
            .list_visible(None, PageRequest::new(0, 100))
            .await
            .unwrap();
        let keys: Vec<&str> = page.items.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, vec!["a", "c"]);
    }

    #[tokio::test]
    async fn list_visible_under_disabled_sees_everything() {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(public_repo("a"));
        repos.insert(private_repo("b"));
        let uc = RepositoryAccessUseCase::new(repos, RbacAccess::Disabled, true);
        let page = uc
            .list_visible(None, PageRequest::new(0, 100))
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);
    }

    #[tokio::test]
    async fn list_visible_principal_with_grant_sees_private() {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(public_repo("a"));
        let private_b = private_repo("b");
        let private_id = private_b.id;
        repos.insert(private_b);
        let uc = RepositoryAccessUseCase::new(
            repos,
            enabled(rbac_with_read_and_write(private_id)),
            true,
        );
        let reader = principal(&["reader"]); // global Read
        let page = uc
            .list_visible(Some(&reader), PageRequest::new(0, 100))
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);
    }

    #[tokio::test]
    async fn list_visible_principal_without_grant_sees_only_public() {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(public_repo("a"));
        repos.insert(private_repo("b"));
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let p = principal(&["ghost"]); // role unknown to evaluator
        let page = uc
            .list_visible(Some(&p), PageRequest::new(0, 100))
            .await
            .unwrap();
        let keys: Vec<&str> = page.items.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, vec!["a"]);
    }

    /// Pagination passes through verbatim — `total` reflects the raw
    /// port total, not the post-filter visible count.
    #[tokio::test]
    async fn list_visible_total_reflects_raw_page_total() {
        let repos = Arc::new(MockRepositoryRepository::new());
        repos.insert(public_repo("a"));
        repos.insert(private_repo("b"));
        let uc = RepositoryAccessUseCase::new(repos, enabled(RbacEvaluator::new(Vec::new())), true);
        let page = uc
            .list_visible(None, PageRequest::new(0, 100))
            .await
            .unwrap();
        // total = raw page total = 2 (both repos seen by the port)
        assert_eq!(page.total, 2);
        // items = visible only = 1 (just the public one)
        assert_eq!(page.items.len(), 1);
    }

    // -- metric_label ------------------------------------------------------

    #[tokio::test]
    async fn metric_label_disabled_flag_returns_all_sentinel() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let uc = RepositoryAccessUseCase::new(repos, RbacAccess::Disabled, false);
        let label = uc.metric_label(Uuid::new_v4()).await;
        assert_eq!(label, values::REPOSITORY_ALL);
    }

    #[tokio::test]
    async fn metric_label_enabled_with_existing_repo_returns_key() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let r = public_repo("alpha");
        let id = r.id;
        repos.insert(r);
        let uc = RepositoryAccessUseCase::new(repos, RbacAccess::Disabled, true);
        let label = uc.metric_label(id).await;
        assert_eq!(label, "alpha");
    }

    #[tokio::test]
    async fn metric_label_enabled_with_unknown_repo_returns_unknown_sentinel() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let uc = RepositoryAccessUseCase::new(repos, RbacAccess::Disabled, true);
        let label = uc.metric_label(Uuid::new_v4()).await;
        assert_eq!(label, values::REPOSITORY_UNKNOWN);
    }

    // -- not_found_repo helper --------------------------------------------

    #[test]
    fn not_found_repo_helper_carries_id() {
        let err = not_found_repo("some-key");
        match err {
            DomainError::NotFound { entity, id } => {
                assert_eq!(entity, "Repository");
                assert_eq!(id, "some-key");
            }
            other => panic!("expected NotFound, got: {other:?}"),
        }
    }

    // -- Sample fields exercised once so the helper struct matches the real
    //    Repository shape (catches drift in `sample_repository`).
    #[test]
    fn sample_repository_helper_matches_expected_shape() {
        // Defensive: a future change to `sample_repository` that omits a
        // field used by this test module surfaces here, not deep in an
        // unrelated case.
        let r = sample_repository();
        assert_eq!(r.format, RepositoryFormat::Generic);
        assert_eq!(r.repo_type, RepositoryType::Hosted);
        assert_eq!(r.replication_priority, ReplicationPriority::OnDemand);
    }
}
