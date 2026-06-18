use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::entities::artifact::{Artifact, QuarantineStatus};
use crate::error::DomainResult;
use crate::types::{ContentHash, LimitedList, Page, PageRequest};

use super::BoxFuture;

/// Per-`(repository, package)` projection row: `(version,
/// quarantine_status, third)`.
///
/// The third element's meaning depends on the producing method:
/// - [`ArtifactRepository::package_version_status`] (the hot, index-only
///   serve path) always sets it to `None` — that path does not read a
///   deadline.
/// - [`ArtifactRepository::package_version_anchors`] (the discovery-only
///   read) sets it to the immutable quarantine anchor
///   `artifacts.quarantine_window_start`; [`DiscoveryUseCase`] turns that
///   anchor into a live deadline via
///   [`effective_quarantine_deadline`](crate::policy::effective_quarantine_deadline)
///   to discriminate `Quarantined` from `QuarantinedAwaitingRelease`
///   (ADR 0007).
///
/// There is no stored `quarantine_deadline` column — the schema persists
/// only the anchor (migration `003_artifacts_cas.sql`).
pub type PackageVersionStatusRow = (String, QuarantineStatus, Option<DateTime<Utc>>);

/// Outbound port for artifact persistence (read-only + delete).
///
/// Artifact writes go through [`ArtifactLifecyclePort::commit_transition`],
/// which atomically persists the artifact state and its domain events in a
/// single transaction. There is no `save()` method here — this prevents
/// agents and developers from accidentally writing a dual-write (separate
/// event append + artifact save) instead of using the atomic path.
pub trait ArtifactRepository: Send + Sync {
    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Artifact>>;
    fn find_by_checksum(
        &self,
        sha256: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Option<Artifact>>>;

    /// Repo-scoped checksum lookup — `SELECT … WHERE repository_id = $1
    /// AND checksum_sha256 = $2 LIMIT 1`.
    ///
    /// Separate from [`Self::find_by_checksum`] because a single SHA-256
    /// can legitimately appear on multiple artifact rows across
    /// repositories (cross-mounted blobs, organic uploads of identical
    /// bytes to different repos). The unscoped method returns an
    /// arbitrary row; callers that need to assert repo ownership — most
    /// notably [`IngestUseCase::register_by_hash`]'s OCI cross-mount
    /// authorisation — MUST use this
    /// method so the repo-scope invariant is enforced at the adapter
    /// boundary, not re-implemented in every caller.
    fn find_by_repo_and_checksum(
        &self,
        repository_id: Uuid,
        sha256: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Option<Artifact>>>;
    fn list_by_repository(
        &self,
        repository_id: Uuid,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<Artifact>>>;
    fn delete(&self, id: Uuid) -> BoxFuture<'_, DomainResult<()>>;

    /// Find an artifact by its logical path within a repository.
    ///
    /// Returns `None` if no artifact exists at that path. At most one row —
    /// `(repository_id, path)` has a UNIQUE constraint.
    fn find_by_path(
        &self,
        repository_id: Uuid,
        path: &str,
    ) -> BoxFuture<'_, DomainResult<Option<Artifact>>>;

    /// List distinct artifact names in a repository, paginated.
    ///
    /// Takes a `PageRequest`
    /// to bound the unbounded `fetch_all` that previously loaded every
    /// distinct name into memory. Use case layer iterates pages until
    /// exhaustion or the
    /// [`LIMIT_LIST_MAX_ITEMS`](crate::types::LIMIT_LIST_MAX_ITEMS)
    /// truncation cap, whichever fires first.
    fn list_distinct_names(
        &self,
        repository_id: Uuid,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<String>>>;

    /// Find artifacts with a given normalized name in a repository,
    /// paginated.
    ///
    /// Names are pre-normalized at ingest time via `FormatHandler::normalize_name()`,
    /// so this uses an exact match on the `name` column.
    ///
    /// Takes a `PageRequest`
    /// to bound result-set growth driven by repeated pull-through ingest.
    fn find_by_name_in_repo(
        &self,
        repository_id: Uuid,
        normalized_name: &str,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<Artifact>>>;

    /// Find artifacts whose **`name_as_published`** (the raw client-
    /// supplied name, pre-normalisation) matches in a repository,
    /// paginated. Used as the drift-resilience fallback by
    /// `ArtifactUseCase::list_by_raw_name` when the primary normalised
    /// lookup misses — it lets drift-era artifacts remain reachable when
    /// a `FormatHandler::normalize_name` implementation has changed output
    /// for the same input across plugin versions.
    ///
    /// Handlers MUST NOT call this method directly; use
    /// `list_by_raw_name` on the use case so the fallback logs the drift
    /// signal consistently.
    ///
    /// Takes a `PageRequest`
    /// to bound result-set growth driven by repeated pull-through ingest.
    fn find_by_name_as_published(
        &self,
        repository_id: Uuid,
        raw_name: &str,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<Artifact>>>;

    /// Find the canonical (stored `name`) of any existing artifact in the
    /// repository whose **registration-collision key** equals
    /// `collision_key`, or `None` if no such artifact exists.
    ///
    /// The collision key is the case- and separator-folded form of the
    /// stored name (`replace(lower(name), '_', '-')` — matching
    /// `FormatHandler::collision_key`'s `lower + _→-` fold; the `lower()` is
    /// defensive since cargo already stores lowercase). Used by
    /// `IngestUseCase::ingest_direct` to apply
    /// the crates.io registration-collision rule on the cargo publish path
    /// (spec 075): a `Some(existing)` whose value differs from the new
    /// crate's canonical name is a collision (`foo_bar` vs an existing
    /// `foo-bar`). `repository_id` scopes the probe — a repo is single-
    /// format, so no `format` filter is needed (the `artifacts` table has
    /// no `format` column; format lives on the repository).
    ///
    /// **Default impl returns `Ok(None)`** (no collision) so the many test
    /// mocks compile unchanged — only the publish path, against the real
    /// adapter, exercises it. The folded comparison and the soft-delete
    /// filter live in the Postgres adapter.
    fn find_canonical_name_by_collision_key<'a>(
        &'a self,
        repository_id: Uuid,
        collision_key: &'a str,
    ) -> BoxFuture<'a, DomainResult<Option<String>>> {
        let _ = (repository_id, collision_key);
        Box::pin(async { Ok(None) })
    }

    /// List artifacts in a repository that are still "active" — i.e.
    /// `quarantine_status IN ('quarantined', 'released')`. Used by
    /// the retroactive curation pass to
    /// drive the artifacts that need re-evaluation when a curation rule
    /// is created or tightened. Already-rejected artifacts are excluded
    /// because retro-block on a rejected artifact is a no-op (the
    /// rejection is sticky per the asymmetric semantics).
    ///
    /// SQL semantics: `WHERE repository_id = $1 AND quarantine_status
    /// IN ('quarantined', 'released')`. The list is unordered — callers
    /// iterate it without dependency on order.
    ///
    /// Wrapped in
    /// [`LimitedList`] with a hard `LIMIT_LIST_MAX_ITEMS` cap. When the
    /// cap fires, callers MUST log a `tracing::warn!` so operators see
    /// the defence-in-depth bound (the cap is intended to stop runaway
    /// table growth from collapsing this query, not to be a normal
    /// operating mode).
    fn list_active_for_repo(
        &self,
        repository_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<LimitedList<Artifact>>>;

    /// List rejected artifacts whose active scan-policy resolves to
    /// `policy_id`. Used by the post-exclusion-add re-evaluation pass
    /// to find the artifacts a newly-
    /// added exclusion may unblock.
    ///
    /// "Active scan-policy" is a runtime resolution rather than a
    /// denormalized column on `artifacts` — repo-scoped policies win
    /// over global, mirroring
    /// `QuarantineUseCase::resolve_active_policy_for_repo`. The v1
    /// adapter implements this by fetching rejected rows and
    /// filtering in-memory (the rejected set is expected ≪ 1k); a
    /// future per-policy denormalised column can replace the
    /// in-memory filter without changing this signature.
    ///
    /// `is_deleted = false` for symmetry with the rest of the read
    /// path. Already-released or quarantined artifacts are excluded —
    /// only `Rejected` rows can be unblocked by a new exclusion.
    ///
    /// Wrapped in
    /// [`LimitedList`] with a hard `LIMIT_LIST_MAX_ITEMS` cap; truncation
    /// is logged at `warn!` for the same reason as `list_active_for_repo`.
    fn list_rejected_for_policy(
        &self,
        policy_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<LimitedList<Artifact>>>;

    /// Per-`(package, version)` servability query — the hot serve-path
    /// read used by the quarantine-aware index-serve filter (the
    /// highest-QPS new query).
    ///
    /// Returns `(version, quarantine_status)` for every artifact whose
    /// `(repository_id, name)` matches and that is not soft-deleted.
    /// The serve path uses this to decide which versions to advertise:
    /// `ReleasedOnly` keeps only `Released` (or `None` under permissive
    /// mode); `IncludePending` keeps everything except `Quarantined`
    /// / `Rejected` / `ScanIndeterminate`. The decision belongs to the
    /// caller — this port returns the raw pairs.
    ///
    /// Answered from the `artifacts` projection — **not** the event
    /// store. The serve path fires this on every packument / simple-
    /// index / sparse-index / `maven-metadata.xml` resolution (a single
    /// `npm install` does dozens to hundreds), so an event-store replay
    /// is not viable. The adapter relies on the covering index
    /// `artifacts (repository_id, name) INCLUDE (version, quarantine_status)
    ///  WHERE NOT is_deleted` for an index-only scan
    /// with no heap fetch.
    ///
    /// Artifact rows with a NULL `version` column (the format does not
    /// version the file — rare; structural metadata, signature files,
    /// etc.) are filtered out: the index-serve filter operates on a
    /// versioned advertisement, and a null-version row has nothing to
    /// advertise. Callers that need the un-versioned rows use
    /// `find_by_name_in_repo` instead.
    ///
    /// The third tuple element is always `None` on this path — it is the
    /// hot, high-QPS serve-path read (index-only scan over the covering
    /// index, no heap fetch), and its consumers (the index-serve filter,
    /// `PrefetchUseCase::plan`, the prefetch task handlers) only need
    /// `(version, status)`. Discovery, which needs the quarantine
    /// deadline, uses [`Self::package_version_anchors`] instead.
    ///
    /// Note: this query must not select any `quarantine_deadline` column
    /// (none exists); the schema stores only the anchor
    /// (`quarantine_window_start`), never a precomputed deadline.
    fn package_version_status(
        &self,
        repository_id: Uuid,
        package: &str,
    ) -> BoxFuture<'_, DomainResult<Vec<PackageVersionStatusRow>>>;

    /// Discovery-only read: per-version `(version, status, anchor)` where
    /// the third element is the immutable quarantine anchor
    /// `artifacts.quarantine_window_start` (NOT a deadline — the deadline
    /// is computed at the use-case layer via
    /// [`effective_quarantine_deadline`](crate::policy::effective_quarantine_deadline)
    /// from the anchor plus the resolved `ScanPolicy.quarantineDuration`).
    ///
    /// Separate from [`Self::package_version_status`] precisely so the hot
    /// serve path keeps its index-only scan: this method reads
    /// `quarantine_window_start` (a heap fetch) and is called only by
    /// [`DiscoveryUseCase`], which is low-QPS. The default impl returns
    /// empty so the test doubles that never exercise discovery need not
    /// override it.
    fn package_version_anchors(
        &self,
        _repository_id: Uuid,
        _package: &str,
    ) -> BoxFuture<'_, DomainResult<Vec<PackageVersionStatusRow>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    /// Find PyPI **wheel** artifacts (path ends `.whl`)
    /// that have no `content_references` row of the given `kind` (in
    /// practice `"wheel_metadata"`), bounded by `limit`.
    ///
    /// The candidacy predicate is the inverse of the ingest-hook
    /// output: wheels whose hook fired and inserted a `wheel_metadata`
    /// row are excluded; everything else (wheels ingested before the
    /// hook existed, hook-skipped wheels with no METADATA member,
    /// oversized-METADATA wheels) stays in the candidate set. Used by
    /// the `wheel-metadata-backfill` admin task
    /// (`WheelMetadataBackfillHandler`)
    /// to retroactively extract metadata for those wheels.
    ///
    /// SQL contract: a single `SELECT … FROM artifacts WHERE path LIKE
    /// '%.whl' AND NOT EXISTS (SELECT 1 FROM content_references WHERE
    /// source_artifact_id = artifacts.id AND kind = $1) LIMIT $2`. The
    /// task handler bounds `limit` at 1000 (its own cap); the adapter
    /// MUST NOT silently cap below the request — a future raise of the
    /// handler cap must surface through unchanged.
    ///
    /// **Resumable by construction** — the candidacy query is stateless
    /// (no cursor, no "claimed" marker). A failed batch leaves the
    /// candidate set unchanged; the next invocation re-derives the same
    /// work minus whatever the previous run completed. Two concurrent
    /// runs would re-walk the same set; the per-CAS `StoragePort::put`
    /// idempotency on identical content + the upsert semantics of
    /// `ContentReferenceIndex::insert` absorb the duplicate work.
    ///
    /// `is_deleted = false` for symmetry with the rest of the read
    /// path; a soft-deleted wheel is not a backfill candidate.
    fn find_pypi_wheels_without_kind(
        &self,
        kind: &str,
        limit: u32,
    ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `ArtifactRepository` is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: size_of call executes in the test body for coverage.
        let _ = size_of::<&dyn ArtifactRepository>();
    }

    /// The `package_version_status` method exists on
    /// the trait. The return tuple includes
    /// `quarantine_until: Option<DateTime<Utc>>` as the third element
    /// (powering Discovery's sub-state computation); the planner
    /// and index-serve filter ignore the third element.
    ///
    /// This is a *shape* assertion: it compiles only if the method signature
    /// matches the current contract verbatim. A future rename/retype is
    /// caught here. The trait is dyn-compatible (proven above), so we
    /// exercise the method through a `&dyn ArtifactRepository` to also pin
    /// the dyn-compatibility of *this specific method* (a generic method or
    /// `impl Future` return would silently regress dyn-compat).
    #[test]
    fn package_version_status_has_documented_shape() {
        use std::sync::Arc;
        struct Stub;
        impl ArtifactRepository for Stub {
            fn find_by_id(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<Artifact>> {
                Box::pin(async {
                    Err(crate::error::DomainError::NotFound {
                        entity: "Artifact",
                        id: String::new(),
                    })
                })
            }
            fn find_by_checksum(
                &self,
                _sha256: &ContentHash,
            ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
                Box::pin(async { Ok(None) })
            }
            fn find_by_repo_and_checksum(
                &self,
                _repository_id: Uuid,
                _sha256: &ContentHash,
            ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
                Box::pin(async { Ok(None) })
            }
            fn list_by_repository(
                &self,
                _repository_id: Uuid,
                _page: PageRequest,
            ) -> BoxFuture<'_, DomainResult<Page<Artifact>>> {
                Box::pin(async { Ok(Page::empty()) })
            }
            fn delete(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn find_by_path(
                &self,
                _repository_id: Uuid,
                _path: &str,
            ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
                Box::pin(async { Ok(None) })
            }
            fn list_distinct_names(
                &self,
                _repository_id: Uuid,
                _page: PageRequest,
            ) -> BoxFuture<'_, DomainResult<Page<String>>> {
                Box::pin(async { Ok(Page::empty()) })
            }
            fn find_by_name_in_repo(
                &self,
                _repository_id: Uuid,
                _normalized_name: &str,
                _page: PageRequest,
            ) -> BoxFuture<'_, DomainResult<Page<Artifact>>> {
                Box::pin(async { Ok(Page::empty()) })
            }
            fn find_by_name_as_published(
                &self,
                _repository_id: Uuid,
                _raw_name: &str,
                _page: PageRequest,
            ) -> BoxFuture<'_, DomainResult<Page<Artifact>>> {
                Box::pin(async { Ok(Page::empty()) })
            }
            fn list_active_for_repo(
                &self,
                _repository_id: Uuid,
            ) -> BoxFuture<'_, DomainResult<LimitedList<Artifact>>> {
                Box::pin(async { Ok(LimitedList::empty()) })
            }
            fn list_rejected_for_policy(
                &self,
                _policy_id: Uuid,
            ) -> BoxFuture<'_, DomainResult<LimitedList<Artifact>>> {
                Box::pin(async { Ok(LimitedList::empty()) })
            }
            fn package_version_status(
                &self,
                _repository_id: Uuid,
                _package: &str,
            ) -> BoxFuture<'_, DomainResult<Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>>>
            {
                Box::pin(async {
                    let deadline = DateTime::<Utc>::from_timestamp(1_700_000_000, 0);
                    Ok(vec![
                        ("1.0.0".to_string(), QuarantineStatus::Released, None),
                        ("1.1.0".to_string(), QuarantineStatus::Quarantined, deadline),
                    ])
                })
            }
            fn find_pypi_wheels_without_kind(
                &self,
                _kind: &str,
                _limit: u32,
            ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
        }
        let stub: Arc<dyn ArtifactRepository> = Arc::new(Stub);
        let fut = stub.package_version_status(Uuid::nil(), "left-pad");
        let result = futures::executor::block_on(fut).expect("stub returns Ok");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "1.0.0");
        assert_eq!(result[0].1, QuarantineStatus::Released);
        assert_eq!(result[0].2, None);
        assert_eq!(result[1].0, "1.1.0");
        assert_eq!(result[1].1, QuarantineStatus::Quarantined);
        assert_eq!(
            result[1].2,
            DateTime::<Utc>::from_timestamp(1_700_000_000, 0),
        );
    }

    /// The `find_pypi_wheels_without_kind` method exists
    /// on the trait with the documented shape: `(kind: &str, limit: u32)
    /// -> BoxFuture<DomainResult<Vec<Artifact>>>`. Shape-pin guards
    /// against a rename / retype that would silently break the
    /// `wheel-metadata-backfill` task handler.
    #[test]
    fn find_pypi_wheels_without_kind_has_documented_shape() {
        use std::sync::Arc;
        struct Stub;
        impl ArtifactRepository for Stub {
            fn find_by_id(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<Artifact>> {
                unimplemented!()
            }
            fn find_by_checksum(
                &self,
                _sha256: &ContentHash,
            ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
                Box::pin(async { Ok(None) })
            }
            fn find_by_repo_and_checksum(
                &self,
                _r: Uuid,
                _s: &ContentHash,
            ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
                Box::pin(async { Ok(None) })
            }
            fn list_by_repository(
                &self,
                _r: Uuid,
                _p: PageRequest,
            ) -> BoxFuture<'_, DomainResult<Page<Artifact>>> {
                Box::pin(async { Ok(Page::empty()) })
            }
            fn delete(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn find_by_path(
                &self,
                _r: Uuid,
                _p: &str,
            ) -> BoxFuture<'_, DomainResult<Option<Artifact>>> {
                Box::pin(async { Ok(None) })
            }
            fn list_distinct_names(
                &self,
                _r: Uuid,
                _p: PageRequest,
            ) -> BoxFuture<'_, DomainResult<Page<String>>> {
                Box::pin(async { Ok(Page::empty()) })
            }
            fn find_by_name_in_repo(
                &self,
                _r: Uuid,
                _n: &str,
                _p: PageRequest,
            ) -> BoxFuture<'_, DomainResult<Page<Artifact>>> {
                Box::pin(async { Ok(Page::empty()) })
            }
            fn find_by_name_as_published(
                &self,
                _r: Uuid,
                _n: &str,
                _p: PageRequest,
            ) -> BoxFuture<'_, DomainResult<Page<Artifact>>> {
                Box::pin(async { Ok(Page::empty()) })
            }
            fn list_active_for_repo(
                &self,
                _r: Uuid,
            ) -> BoxFuture<'_, DomainResult<LimitedList<Artifact>>> {
                Box::pin(async { Ok(LimitedList::empty()) })
            }
            fn list_rejected_for_policy(
                &self,
                _p: Uuid,
            ) -> BoxFuture<'_, DomainResult<LimitedList<Artifact>>> {
                Box::pin(async { Ok(LimitedList::empty()) })
            }
            fn package_version_status(
                &self,
                _r: Uuid,
                _p: &str,
            ) -> BoxFuture<'_, DomainResult<Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>>>
            {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn find_pypi_wheels_without_kind(
                &self,
                kind: &str,
                limit: u32,
            ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>> {
                // Pin the input shape: the stub returns nothing but
                // accepts the documented kinds/limits without panicking.
                assert_eq!(kind, "wheel_metadata");
                assert!(limit <= 1_000, "handler-side cap is 1000");
                Box::pin(async { Ok(Vec::new()) })
            }
        }
        let stub: Arc<dyn ArtifactRepository> = Arc::new(Stub);
        let fut = stub.find_pypi_wheels_without_kind("wheel_metadata", 100);
        let result = futures::executor::block_on(fut).expect("stub returns Ok");
        assert!(result.is_empty());
    }
}
