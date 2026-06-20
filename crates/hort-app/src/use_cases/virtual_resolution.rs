//! `VirtualResolutionUseCase` — resolves a virtual repository's members for
//! serve-time aggregation (ADR 0031).
//!
//! A `type: virtual` repository aggregates several member repositories behind a
//! single URL. This use case turns a virtual repo into the ordered, access-
//! filtered list of members the per-format serve path then queries:
//!
//! - **Priority order.** Members come back highest-priority-first (the
//!   `virtualMembers` list order, persisted as `virtual_repo_members.priority`).
//!   The downstream pinning + authoritative-member merge
//!   (`crate::use_cases::index_serve`) depend on that order.
//! - **Anti-enumeration (ADR 0021).** Each member is resolved with the *same*
//!   caller; a member the caller cannot Read is **skipped**, not errored — a
//!   public virtual must not leak a private member's existence. Read denial
//!   collapses to `NotFound` in [`RepositoryAccessUseCase::resolve_by_id`], so
//!   "skip" is "treat as absent".
//! - **No nested virtuals (ADR 0031 rule 5).** A member that is itself
//!   `Virtual` is skipped defensively; apply-time validation already rejects
//!   nested virtuals, so this only guards against a stale edge.
//!
//! This is a read path: it threads `Option<&CallerPrincipal>` and enforces
//! per-member visibility itself (there is no middleware defence-in-depth for
//! reads — ADR 0021).

use std::future::Future;
use std::sync::Arc;

use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::{Repository, RepositoryType};
use hort_domain::error::DomainError;
use hort_domain::ports::repository_repository::RepositoryRepository;

use crate::error::{AppError, AppResult};
use crate::use_cases::index_serve::{aggregate_index_members, MemberFetch, VersionEntry};
use crate::use_cases::repository_access::{AccessLevel, RepositoryAccessUseCase};

/// One member's name-presence outcome for the download pinning decision
/// ([`VirtualResolutionUseCase::resolve_download`]).
///
/// This is the download path's projection of the index path's ownership
/// signal ([`MemberFetch`](crate::use_cases::index_serve::MemberFetch)) to
/// the single bit pinning needs:
///
/// - `Present` — the member has ≥1 version of the requested name.
/// - `Absent` — the member definitively does not have the name.
/// - `Unavailable` — the name probe errored (infrastructure). Ownership is
///   indeterminate, so a *non-proxy* member that errors is treated
///   **fail-closed** as a potential owner (proxies stay suppressed for the
///   name) — a transient outage of the trusted owner must not re-open the
///   dependency-confusion window by making the name look unowned
///   (ADR 0031 rule 2b).
///
/// The per-format closure maps its name lookup into this: a "name absent
/// here" miss → `Absent`, an infrastructure error → `Unavailable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberNamePresence {
    Present,
    Absent,
    Unavailable,
}

/// Resolves a virtual repository's members for serving. See the module docs.
pub struct VirtualResolutionUseCase {
    repositories: Arc<dyn RepositoryRepository>,
    access: Arc<RepositoryAccessUseCase>,
}

impl VirtualResolutionUseCase {
    /// Construct the use case from the repository port (member listing) and the
    /// access use case (per-member Read visibility).
    pub fn new(
        repositories: Arc<dyn RepositoryRepository>,
        access: Arc<RepositoryAccessUseCase>,
    ) -> Self {
        Self {
            repositories,
            access,
        }
    }

    /// Members of `virtual_repo`, in priority order (highest first), filtered to
    /// those `caller` may Read. Members the caller cannot see — and any member
    /// that is itself `Virtual` — are skipped (not errored). Infrastructure
    /// errors propagate.
    #[tracing::instrument(skip(self, caller), fields(virtual_repo = %virtual_repo.key))]
    pub async fn resolve_members(
        &self,
        virtual_repo: &Repository,
        caller: Option<&CallerPrincipal>,
    ) -> AppResult<Vec<Repository>> {
        let members = self
            .repositories
            .get_virtual_members(virtual_repo.id)
            .await
            .map_err(AppError::Domain)?;

        let mut visible = Vec::with_capacity(members.len());
        let mut skipped = 0usize;
        for member in members {
            // Defensive: apply-time rejects nested virtuals, so a `Virtual`
            // member would be a stale edge. Skip rather than recurse.
            if matches!(member.repo_type, RepositoryType::Virtual) {
                skipped += 1;
                continue;
            }
            // Re-resolve with the caller: Read denial collapses to `NotFound`
            // (anti-enumeration), which we treat as "member absent". A genuine
            // infrastructure error propagates.
            match self
                .access
                .resolve_by_id(member.id, caller, AccessLevel::Read)
                .await
            {
                Ok(resolved) => visible.push(resolved),
                Err(AppError::Domain(DomainError::NotFound { .. })) => skipped += 1,
                Err(other) => return Err(other),
            }
        }

        tracing::debug!(
            member_count = visible.len(),
            skipped_count = skipped,
            "resolved virtual members"
        );
        Ok(visible)
    }

    /// First-authoritative download resolution for a virtual repo
    /// (ADR 0031 §4.2). Two phases over the priority-ordered, access-
    /// filtered members ([`resolve_members`](Self::resolve_members)):
    ///
    /// 1. **Name-level pinning (rule 2b), fail-closed.** A name is *owned*
    ///    if any **non-proxy** member is [`MemberNamePresence::Present`] or
    ///    [`MemberNamePresence::Unavailable`] (the fail-closed case: a
    ///    non-proxy owner that errored is a potential owner). When the name
    ///    is owned, every `Proxy` member is excluded from the walk — a
    ///    coordinate present only in a proxy is never served for an owned
    ///    name (closes the new-version dependency-confusion variant).
    /// 2. **First-authoritative walk (rule 2a).** Among the surviving
    ///    members in priority order, the first whose `fetch_coord` returns
    ///    `Ok(Some(_))` is authoritative — the walk stops and returns it. A
    ///    member returning `Ok(None)` definitively lacks the coordinate and
    ///    the walk continues; an `Err` is an infrastructure failure and is
    ///    propagated — the walk does **not** fall through to a lower-priority
    ///    member (availability-first fall-through re-opens substitution and
    ///    is rejected, ADR 0031).
    ///
    /// `name_present` is invoked only for non-proxy members (proxies never
    /// own); the first owner short-circuits the rest. Returns `Ok(None)`
    /// when no eligible member has the coordinate (the caller renders the
    /// format's 404 — never a proxy fall-through for an owned name). `T` is
    /// the format crate's resolved-download payload — opaque here, so the
    /// quarantine-gate / HTTP rendering stays in the format crate.
    #[tracing::instrument(
        skip(self, caller, name_present, fetch_coord),
        fields(virtual_repo = %virtual_repo.key)
    )]
    pub async fn resolve_download<T, NP, NPF, FC, FCF>(
        &self,
        virtual_repo: &Repository,
        caller: Option<&CallerPrincipal>,
        mut name_present: NP,
        mut fetch_coord: FC,
    ) -> AppResult<Option<T>>
    where
        NP: FnMut(Repository) -> NPF,
        NPF: Future<Output = MemberNamePresence>,
        FC: FnMut(Repository) -> FCF,
        FCF: Future<Output = AppResult<Option<T>>>,
    {
        let members = self.resolve_members(virtual_repo, caller).await?;

        // Phase 1 — name ownership (fail-closed) over non-proxy members.
        // One owner is enough to pin, so short-circuit on the first.
        let mut name_is_owned = false;
        for member in &members {
            if matches!(member.repo_type, RepositoryType::Proxy) {
                continue;
            }
            match name_present(member.clone()).await {
                MemberNamePresence::Present | MemberNamePresence::Unavailable => {
                    name_is_owned = true;
                    break;
                }
                MemberNamePresence::Absent => {}
            }
        }
        tracing::debug!(name_is_owned, "virtual download name-ownership resolved");

        // Phase 2 — pinning-filtered first-authoritative walk. Proxies are
        // excluded once the name is owned; the first member that has the
        // coordinate wins and the walk stops (no fall-through).
        for member in &members {
            if name_is_owned && matches!(member.repo_type, RepositoryType::Proxy) {
                continue;
            }
            if let Some(found) = fetch_coord(member.clone()).await? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// Index aggregation for a virtual repo (ADR 0031 §4.1) — the index
    /// twin of [`resolve_download`](Self::resolve_download). Resolves the
    /// priority-ordered, access-filtered members, runs each through the
    /// per-format `fetch_member` closure, classifies the outcome into a
    /// [`MemberFetch`], and folds the lot through [`aggregate_index_members`]
    /// (name-level pinning + the authoritative-member merge + the
    /// fail-closed member rule).
    ///
    /// **The classification IS the dependency-confusion security boundary**
    /// (ADR 0031 rule 2b): a member that responds with rows is `Present`; a
    /// definitive "absent here" (a `NotFound`) is `Present(empty)` — it does
    /// not own the name; **any other error is `Unavailable`** — a non-proxy
    /// member that errors is a fail-closed *potential owner*, so proxies stay
    /// suppressed and a transient outage cannot re-open the confusion window.
    /// It lives here, once, behind `hort-app`'s 100%-coverage requirement —
    /// the per-format `Virtual*Source` shims supply only the `fetch_member`
    /// closure and never re-implement this match (a transcription slip in one
    /// format would otherwise silently re-open the window for that format).
    ///
    /// `fetch_member` is the member's own format source (hosted DB read /
    /// proxy upstream fetch); it returns that member's RAW `Vec<VersionEntry>`
    /// (status hydrated, pre-filter — the merge must see `Quarantined` status
    /// to apply the authoritative-member rule). The caller runs the standard
    /// `NonServableStatusFilter` + `IndexModeFilter` pipeline on the result.
    #[tracing::instrument(skip(self, caller, fetch_member), fields(virtual_repo = %virtual_repo.key))]
    pub async fn aggregate_virtual_index<FC, Fut>(
        &self,
        virtual_repo: &Repository,
        caller: Option<&CallerPrincipal>,
        mut fetch_member: FC,
    ) -> AppResult<Vec<VersionEntry>>
    where
        FC: FnMut(Repository) -> Fut,
        Fut: Future<Output = Result<Vec<VersionEntry>, AppError>>,
    {
        let members = self.resolve_members(virtual_repo, caller).await?;

        // Phase 1 — fetch only the NON-PROXY members and compute name
        // ownership. **Ownership-first**, mirroring [`resolve_download`]: a
        // proxy member is fetched in phase 2 ONLY when the name is unowned, so
        // an owned/internal name is never driven to a public proxy upstream
        // just to be discarded by pinning. The fetch-then-pin shape would
        // leak the owned name (a reconnaissance signal — the very thing the
        // aggregator exists to prevent) on every cache-cold index request.
        // The dedup key is name+version, so this is semantics-preserving.
        let mut slots: Vec<Option<MemberFetch>> = Vec::with_capacity(members.len());
        let mut name_is_owned = false;
        for member in &members {
            if matches!(member.repo_type, RepositoryType::Proxy) {
                slots.push(None); // deferred — fetched in phase 2 iff unowned
                continue;
            }
            let fetch = classify_member_fetch(fetch_member(member.clone()).await);
            let owns = match &fetch {
                MemberFetch::Present(entries) => !entries.is_empty(),
                MemberFetch::Unavailable => true,
            };
            name_is_owned = name_is_owned || owns;
            slots.push(Some(fetch));
        }
        tracing::debug!(name_is_owned, "virtual index name-ownership resolved");

        // Phase 2 — assemble per-member outcomes in priority order. A proxy
        // member is fetched here only when the name is unowned; when owned it
        // is dropped WITHOUT a fetch (no upstream GET, no leak). The result is
        // identical to fetch-then-pin — pinning is name-level — but no owned
        // name reaches a proxy upstream.
        let mut per_member: Vec<(RepositoryType, MemberFetch)> = Vec::with_capacity(members.len());
        for (member, slot) in members.iter().zip(slots) {
            let fetch = match slot {
                Some(f) => f,                      // non-proxy, already fetched in phase 1
                None if name_is_owned => continue, // owned → proxy excluded, never fetched
                None => classify_member_fetch(fetch_member(member.clone()).await),
            };
            per_member.push((member.repo_type, fetch));
        }
        Ok(aggregate_index_members(per_member))
    }
}

/// Classify a per-member index fetch outcome into a [`MemberFetch`] — the
/// fail-closed dependency-confusion classification (ADR 0031 rule 2b):
///
/// - `Ok(entries)` → `Present(entries)` (the member responded; empty = absent
///   there, does not own the name).
/// - a definitive `NotFound` → `Present(empty)` (definitively absent — does
///   not own the name).
/// - **any other error → `Unavailable`** (an infrastructure failure: a
///   non-proxy member that errors is a fail-closed *potential owner*, so the
///   aggregation keeps proxies suppressed).
///
/// Shared by both phases of [`VirtualResolutionUseCase::aggregate_virtual_index`]
/// so the security-critical classification is written exactly once.
fn classify_member_fetch(result: Result<Vec<VersionEntry>, AppError>) -> MemberFetch {
    match result {
        Ok(entries) => MemberFetch::Present(entries),
        Err(AppError::Domain(DomainError::NotFound { .. })) => MemberFetch::Present(Vec::new()),
        Err(_) => MemberFetch::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use arc_swap::ArcSwap;

    use super::*;
    use crate::rbac::RbacEvaluator;
    use crate::use_cases::repository_access::RbacAccess;
    use crate::use_cases::test_support::{sample_repository, MockRepositoryRepository};

    fn repo(key: &str, repo_type: RepositoryType, is_public: bool) -> Repository {
        Repository {
            key: key.into(),
            repo_type,
            is_public,
            ..sample_repository()
        }
    }

    /// Auth enabled with no grants: public repos visible to everyone, private
    /// repos invisible to an anonymous caller.
    fn enabled_empty() -> RbacAccess {
        RbacAccess::Enabled(Arc::new(ArcSwap::from_pointee(RbacEvaluator::new(
            Vec::new(),
        ))))
    }

    fn use_case(
        repos: Arc<MockRepositoryRepository>,
        auth: RbacAccess,
    ) -> VirtualResolutionUseCase {
        let access = Arc::new(RepositoryAccessUseCase::new(repos.clone(), auth, true));
        VirtualResolutionUseCase::new(repos, access)
    }

    #[tokio::test]
    async fn resolve_members_returns_visible_members_in_priority_order() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let vroot = repo("vroot", RepositoryType::Virtual, true);
        let a = repo("a", RepositoryType::Hosted, true);
        let b = repo("b", RepositoryType::Proxy, true);
        repos.insert(vroot.clone());
        repos.insert(a.clone());
        repos.insert(b.clone());
        repos.seed_virtual_member(vroot.id, a.id);
        repos.seed_virtual_member(vroot.id, b.id);

        let uc = use_case(repos, RbacAccess::Disabled);
        let resolved = uc.resolve_members(&vroot, None).await.unwrap();

        let keys: Vec<&str> = resolved.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, vec!["a", "b"], "members preserved in priority order");
    }

    #[tokio::test]
    async fn resolve_members_skips_member_caller_cannot_read() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let vroot = repo("vroot", RepositoryType::Virtual, true);
        let public = repo("pub", RepositoryType::Hosted, true);
        let private = repo("priv", RepositoryType::Hosted, false);
        repos.insert(vroot.clone());
        repos.insert(public.clone());
        repos.insert(private.clone());
        repos.seed_virtual_member(vroot.id, public.id);
        repos.seed_virtual_member(vroot.id, private.id);

        // Anonymous caller (None) + auth enabled → the private member is
        // invisible and must be skipped, not leaked or errored.
        let uc = use_case(repos, enabled_empty());
        let resolved = uc.resolve_members(&vroot, None).await.unwrap();

        let keys: Vec<&str> = resolved.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(
            keys,
            vec!["pub"],
            "private member skipped (anti-enumeration)"
        );
    }

    #[tokio::test]
    async fn resolve_members_skips_nested_virtual_member() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let vroot = repo("vroot", RepositoryType::Virtual, true);
        let a = repo("a", RepositoryType::Hosted, true);
        let nested = repo("nested", RepositoryType::Virtual, true);
        repos.insert(vroot.clone());
        repos.insert(a.clone());
        repos.insert(nested.clone());
        repos.seed_virtual_member(vroot.id, a.id);
        repos.seed_virtual_member(vroot.id, nested.id);

        let uc = use_case(repos, RbacAccess::Disabled);
        let resolved = uc.resolve_members(&vroot, None).await.unwrap();

        let keys: Vec<&str> = resolved.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, vec!["a"], "nested virtual member skipped");
    }

    #[tokio::test]
    async fn resolve_members_empty_when_no_members() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let vroot = repo("vroot", RepositoryType::Virtual, true);
        repos.insert(vroot.clone());

        let uc = use_case(repos, RbacAccess::Disabled);
        let resolved = uc.resolve_members(&vroot, None).await.unwrap();
        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn resolve_members_propagates_get_virtual_members_error() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let vroot = repo("vroot", RepositoryType::Virtual, true);
        repos.insert(vroot.clone());
        repos.fail_next_get_virtual_members(DomainError::Invariant("db down".into()));

        let uc = use_case(repos, RbacAccess::Disabled);
        let err = uc.resolve_members(&vroot, None).await.unwrap_err();
        assert!(err.to_string().contains("db down"));
    }

    #[tokio::test]
    async fn resolve_members_propagates_resolve_by_id_infra_error() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let vroot = repo("vroot", RepositoryType::Virtual, true);
        let a = repo("a", RepositoryType::Hosted, true);
        repos.insert(vroot.clone());
        repos.insert(a.clone());
        repos.seed_virtual_member(vroot.id, a.id);
        // The member's `resolve_by_id` → `find_by_id` fails with a non-NotFound
        // infrastructure error, which must propagate (not be swallowed as a
        // skip).
        repos.fail_next_find_by_id(DomainError::Invariant("pool exhausted".into()));

        let uc = use_case(repos, RbacAccess::Disabled);
        let err = uc.resolve_members(&vroot, None).await.unwrap_err();
        assert!(err.to_string().contains("pool exhausted"));
    }

    // ---------------------------------------------------------------------
    // resolve_download (ADR 0031 §4.2) — name-level pinning (fail-closed) +
    // first-authoritative walk. The closures are canned so these pin the
    // pure decision logic; the per-format crate tests exercise the real
    // `find_visible_by_path` / proxy-pull closures end-to-end.
    // ---------------------------------------------------------------------

    use std::sync::Mutex;

    /// Build a virtual repo seeded with `members` (priority order, first =
    /// highest) and a use case over a disabled-RBAC access layer (every
    /// member resolves).
    fn vroot_with_members(
        members: &[(&str, RepositoryType)],
    ) -> (VirtualResolutionUseCase, Repository) {
        let repos = Arc::new(MockRepositoryRepository::new());
        let vroot = repo("vroot", RepositoryType::Virtual, true);
        repos.insert(vroot.clone());
        for (key, ty) in members {
            let m = repo(key, *ty, true);
            repos.insert(m.clone());
            repos.seed_virtual_member(vroot.id, m.id);
        }
        (use_case(repos, RbacAccess::Disabled), vroot)
    }

    #[tokio::test]
    async fn resolve_download_first_authoritative_stops_at_first_holder() {
        // Not owned (both proxy). The walk hits the higher-priority proxy
        // first and stops — the lower-priority proxy is never probed (so no
        // wasteful second upstream pull).
        let (uc, vroot) =
            vroot_with_members(&[("p1", RepositoryType::Proxy), ("p2", RepositoryType::Proxy)]);
        let probed = Arc::new(Mutex::new(Vec::<String>::new()));
        let p = probed.clone();
        let out: Option<String> = uc
            .resolve_download(
                &vroot,
                None,
                |_m| async { MemberNamePresence::Absent },
                move |m| {
                    let p = p.clone();
                    async move {
                        p.lock().unwrap().push(m.key.clone());
                        Ok(Some(m.key.clone()))
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(out.as_deref(), Some("p1"));
        assert_eq!(
            *probed.lock().unwrap(),
            vec!["p1".to_string()],
            "walk stops at the first authoritative member"
        );
    }

    #[tokio::test]
    async fn resolve_download_name_owned_excludes_proxy_even_when_proxy_has_coord() {
        // New-version dependency-confusion regression: a hosted member owns
        // the name; the coordinate exists ONLY in the proxy. Pinning drops
        // the proxy → 404, NEVER the proxy's copy.
        let (uc, vroot) =
            vroot_with_members(&[("h", RepositoryType::Hosted), ("p", RepositoryType::Proxy)]);
        let coord_probed = Arc::new(Mutex::new(Vec::<String>::new()));
        let cp = coord_probed.clone();
        let out: Option<String> = uc
            .resolve_download(
                &vroot,
                None,
                |m| async move {
                    if matches!(m.repo_type, RepositoryType::Hosted) {
                        MemberNamePresence::Present
                    } else {
                        MemberNamePresence::Absent
                    }
                },
                move |m| {
                    let cp = cp.clone();
                    async move {
                        cp.lock().unwrap().push(m.key.clone());
                        // hosted has the NAME but not this version; the proxy
                        // WOULD have it — but it must be excluded.
                        if matches!(m.repo_type, RepositoryType::Proxy) {
                            Ok(Some(m.key.clone()))
                        } else {
                            Ok(None)
                        }
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(
            out, None,
            "owned name with the version only in a proxy → 404, never a proxy fall-through"
        );
        assert_eq!(
            *coord_probed.lock().unwrap(),
            vec!["h".to_string()],
            "the proxy is excluded from the walk; only the hosted owner is probed"
        );
    }

    #[tokio::test]
    async fn resolve_download_authoritative_is_highest_priority_holder() {
        // Same-version: both hosted members hold the coordinate; the
        // higher-priority one is authoritative and the lower is never probed
        // (its copy never silently substitutes the authoritative one).
        let (uc, vroot) = vroot_with_members(&[
            ("primary", RepositoryType::Hosted),
            ("secondary", RepositoryType::Hosted),
        ]);
        let probed = Arc::new(Mutex::new(Vec::<String>::new()));
        let p = probed.clone();
        let out: Option<String> = uc
            .resolve_download(
                &vroot,
                None,
                |_m| async { MemberNamePresence::Present },
                move |m| {
                    let p = p.clone();
                    async move {
                        p.lock().unwrap().push(m.key.clone());
                        Ok(Some(m.key.clone()))
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(out.as_deref(), Some("primary"));
        assert_eq!(
            *probed.lock().unwrap(),
            vec!["primary".to_string()],
            "the lower-priority holder is not probed"
        );
    }

    #[tokio::test]
    async fn resolve_download_non_proxy_unavailable_pins_fail_closed() {
        // The hosted member's name probe ERRORS → Unavailable → owned
        // (fail-closed) → the proxy is excluded, so a transient outage of
        // the trusted owner cannot re-open the confusion window.
        let (uc, vroot) =
            vroot_with_members(&[("h", RepositoryType::Hosted), ("p", RepositoryType::Proxy)]);
        let probed = Arc::new(Mutex::new(Vec::<String>::new()));
        let p = probed.clone();
        let out: Option<String> = uc
            .resolve_download(
                &vroot,
                None,
                |m| async move {
                    if matches!(m.repo_type, RepositoryType::Hosted) {
                        MemberNamePresence::Unavailable
                    } else {
                        MemberNamePresence::Absent
                    }
                },
                move |m| {
                    let p = p.clone();
                    async move {
                        p.lock().unwrap().push(m.key.clone());
                        Ok::<Option<String>, AppError>(None)
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(out, None);
        assert_eq!(
            *probed.lock().unwrap(),
            vec!["h".to_string()],
            "fail-closed: the proxy is suppressed by the Unavailable non-proxy owner"
        );
    }

    #[tokio::test]
    async fn resolve_download_unowned_name_served_from_proxy() {
        // Public-package path: the hosted member does NOT own the name, so
        // the proxy participates and serves it.
        let (uc, vroot) =
            vroot_with_members(&[("h", RepositoryType::Hosted), ("p", RepositoryType::Proxy)]);
        let out: Option<String> = uc
            .resolve_download(
                &vroot,
                None,
                |_m| async { MemberNamePresence::Absent },
                |m| async move {
                    if matches!(m.repo_type, RepositoryType::Proxy) {
                        Ok(Some(m.key.clone()))
                    } else {
                        Ok(None)
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(out.as_deref(), Some("p"));
    }

    #[tokio::test]
    async fn resolve_download_owner_found_after_absent_non_proxy() {
        // First non-proxy is Absent, second is Present → owned via the
        // second (covers the phase-1 Absent-continue then Present-break).
        let (uc, vroot) = vroot_with_members(&[
            ("h1", RepositoryType::Hosted),
            ("h2", RepositoryType::Hosted),
        ]);
        let np_probed = Arc::new(Mutex::new(Vec::<String>::new()));
        let np = np_probed.clone();
        let out: Option<String> = uc
            .resolve_download(
                &vroot,
                None,
                move |m| {
                    let np = np.clone();
                    async move {
                        np.lock().unwrap().push(m.key.clone());
                        if m.key == "h2" {
                            MemberNamePresence::Present
                        } else {
                            MemberNamePresence::Absent
                        }
                    }
                },
                |m| async move {
                    if m.key == "h2" {
                        Ok(Some(m.key.clone()))
                    } else {
                        Ok(None)
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(out.as_deref(), Some("h2"));
        assert_eq!(
            *np_probed.lock().unwrap(),
            vec!["h1".to_string(), "h2".to_string()],
            "phase-1 checks h1 (Absent) then h2 (Present)"
        );
    }

    #[tokio::test]
    async fn resolve_download_none_when_no_member_has_coordinate() {
        let (uc, vroot) = vroot_with_members(&[("h", RepositoryType::Hosted)]);
        let out: Option<String> = uc
            .resolve_download(
                &vroot,
                None,
                |_m| async { MemberNamePresence::Absent },
                |_m| async { Ok(None) },
            )
            .await
            .unwrap();
        assert_eq!(out, None);
    }

    #[tokio::test]
    async fn resolve_download_propagates_coord_fetch_infra_error() {
        // An infrastructure error in the coordinate walk propagates — the
        // walk does NOT fall through to a lower-priority member.
        let (uc, vroot) = vroot_with_members(&[("h", RepositoryType::Hosted)]);
        let err = uc
            .resolve_download::<String, _, _, _, _>(
                &vroot,
                None,
                |_m| async { MemberNamePresence::Absent },
                |_m| async { Err(AppError::Domain(DomainError::Invariant("pool down".into()))) },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("pool down"));
    }

    #[tokio::test]
    async fn resolve_download_propagates_resolve_members_error() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let vroot = repo("vroot", RepositoryType::Virtual, true);
        repos.insert(vroot.clone());
        repos.fail_next_get_virtual_members(DomainError::Invariant("db down".into()));
        let uc = use_case(repos, RbacAccess::Disabled);
        let err = uc
            .resolve_download::<String, _, _, _, _>(
                &vroot,
                None,
                |_m| async { MemberNamePresence::Absent },
                |_m| async { Ok(None) },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("db down"));
    }

    // ---------------------------------------------------------------------
    // aggregate_virtual_index (ADR 0031 §4.1) — the index twin of
    // resolve_download. The per-member `MemberFetch` classification (the
    // dependency-confusion security boundary) lives here, so these pin all
    // three arms + the merge + the resolve_members error path.
    // ---------------------------------------------------------------------

    fn ve(version: &str) -> VersionEntry {
        use crate::use_cases::index_serve::{NpmVersionPayload, PerVersionPayload};
        VersionEntry {
            version: version.into(),
            status: None,
            payload: PerVersionPayload::Npm(NpmVersionPayload {
                name_as_published: "x".into(),
                tarball_basename: "x".into(),
                integrity: None,
                shasum: String::new(),
            }),
        }
    }

    #[tokio::test]
    async fn aggregate_virtual_index_merges_present_members() {
        // Two hosted members each return a distinct version → merged union.
        let (uc, vroot) =
            vroot_with_members(&[("a", RepositoryType::Hosted), ("b", RepositoryType::Hosted)]);
        let merged = uc
            .aggregate_virtual_index(&vroot, None, |m| async move {
                if m.key == "a" {
                    Ok(vec![ve("1.0.0")])
                } else {
                    Ok(vec![ve("2.0.0")])
                }
            })
            .await
            .unwrap();
        let versions: Vec<&str> = merged.iter().map(|e| e.version.as_str()).collect();
        assert_eq!(versions, vec!["1.0.0", "2.0.0"]);
    }

    #[tokio::test]
    async fn aggregate_virtual_index_notfound_member_contributes_nothing() {
        // A member whose fetch returns `NotFound` is `Present(empty)` — it
        // does not own the name and contributes no entries.
        let (uc, vroot) =
            vroot_with_members(&[("a", RepositoryType::Hosted), ("b", RepositoryType::Hosted)]);
        let merged = uc
            .aggregate_virtual_index(&vroot, None, |m| async move {
                if m.key == "a" {
                    Ok(vec![ve("1.0.0")])
                } else {
                    Err(AppError::Domain(DomainError::NotFound {
                        entity: "Artifact",
                        id: "x".into(),
                    }))
                }
            })
            .await
            .unwrap();
        let versions: Vec<&str> = merged.iter().map(|e| e.version.as_str()).collect();
        assert_eq!(
            versions,
            vec!["1.0.0"],
            "NotFound member dropped, not Unavailable"
        );
    }

    #[tokio::test]
    async fn aggregate_virtual_index_non_proxy_error_pins_fail_closed() {
        // A non-proxy member whose fetch errors with a non-NotFound error is
        // `Unavailable` → the name is owned (fail-closed) → the proxy member
        // is dropped, so its version is NOT merged in.
        let (uc, vroot) =
            vroot_with_members(&[("h", RepositoryType::Hosted), ("p", RepositoryType::Proxy)]);
        let merged = uc
            .aggregate_virtual_index(&vroot, None, |m| async move {
                if matches!(m.repo_type, RepositoryType::Proxy) {
                    Ok(vec![ve("9.9.9")])
                } else {
                    Err(AppError::Domain(DomainError::Invariant("pool down".into())))
                }
            })
            .await
            .unwrap();
        assert!(
            merged.is_empty(),
            "fail-closed: erroring non-proxy owner suppresses the proxy's entry: {:?}",
            merged.iter().map(|e| e.version.clone()).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn aggregate_virtual_index_propagates_resolve_members_error() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let vroot = repo("vroot", RepositoryType::Virtual, true);
        repos.insert(vroot.clone());
        repos.fail_next_get_virtual_members(DomainError::Invariant("db down".into()));
        let uc = use_case(repos, RbacAccess::Disabled);
        let err = uc
            .aggregate_virtual_index(&vroot, None, |_m| async { Ok(vec![ve("1.0.0")]) })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("db down"));
    }

    #[tokio::test]
    async fn aggregate_virtual_index_owned_name_does_not_fetch_proxy_members() {
        // S-1: an owned name must NOT drive a proxy upstream fetch. The index
        // path is ownership-first, so an internal/owned name is never leaked
        // to a public registry just to be discarded during pinning. The proxy
        // member's `fetch_member` closure must never be invoked.
        let (uc, vroot) =
            vroot_with_members(&[("h", RepositoryType::Hosted), ("p", RepositoryType::Proxy)]);
        let fetched = Arc::new(Mutex::new(Vec::<String>::new()));
        let f = fetched.clone();
        let merged = uc
            .aggregate_virtual_index(&vroot, None, move |m| {
                let f = f.clone();
                async move {
                    f.lock().unwrap().push(m.key.clone());
                    if matches!(m.repo_type, RepositoryType::Proxy) {
                        Ok(vec![ve("9.9.9")]) // the attacker's public version
                    } else {
                        Ok(vec![ve("1.0.0")]) // the private owner
                    }
                }
            })
            .await
            .unwrap();
        let versions: Vec<&str> = merged.iter().map(|e| e.version.as_str()).collect();
        assert_eq!(
            versions,
            vec!["1.0.0"],
            "only the owner's version is served"
        );
        assert_eq!(
            *fetched.lock().unwrap(),
            vec!["h".to_string()],
            "the proxy member is NEVER fetched for an owned name (no upstream leak)"
        );
    }

    #[tokio::test]
    async fn aggregate_virtual_index_unowned_name_fetches_proxy_members() {
        // The complement of S-1: when no non-proxy member owns the name, the
        // proxy IS fetched and contributes (ordinary pull-through).
        let (uc, vroot) =
            vroot_with_members(&[("h", RepositoryType::Hosted), ("p", RepositoryType::Proxy)]);
        let fetched = Arc::new(Mutex::new(Vec::<String>::new()));
        let f = fetched.clone();
        let merged = uc
            .aggregate_virtual_index(&vroot, None, move |m| {
                let f = f.clone();
                async move {
                    f.lock().unwrap().push(m.key.clone());
                    if matches!(m.repo_type, RepositoryType::Proxy) {
                        Ok(vec![ve("1.0.0")])
                    } else {
                        Ok(Vec::new()) // hosted does NOT own the name
                    }
                }
            })
            .await
            .unwrap();
        let versions: Vec<&str> = merged.iter().map(|e| e.version.as_str()).collect();
        assert_eq!(versions, vec!["1.0.0"], "the proxy serves the unowned name");
        let probed = fetched.lock().unwrap();
        assert!(
            probed.contains(&"h".to_string()) && probed.contains(&"p".to_string()),
            "both members fetched when the name is unowned: {probed:?}"
        );
    }
}
