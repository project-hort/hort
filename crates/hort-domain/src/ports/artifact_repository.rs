use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::entities::artifact::{Artifact, QuarantineStatus};
use crate::error::{DomainError, DomainResult};
use crate::events::Actor;
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

/// Per-`(repository, package)` publish-timestamp row: `(version,
/// created_at, upstream_published_at)`.
///
/// Row presence carries the same meaning documented on
/// [`ArtifactRepository::package_version_status`]: a returned row
/// asserts locally-ingested content. A queried version with no row is
/// "never locally ingested", not "timestamp unknown" — callers computing
/// a served publish time must read absence as "omit the field", never
/// as a zero or invented timestamp.
///
/// Deliberately its own port method rather than a widening of
/// [`PackageVersionStatusRow`] / [`ArtifactRepository::package_version_status`]:
/// that method is the hot, index-only-scan serve path shared by every
/// format's quarantine-aware filtering, and folding two more timestamp
/// columns into it would (a) force a heap fetch onto that highest-QPS
/// read for every format, not just cargo, and (b) leak a cargo-only
/// concern into a cross-format row shape. This method is a separate,
/// lower-QPS read exercised only by the cargo sparse-index proxy source.
pub type PackageVersionPublishTimeRow = (String, DateTime<Utc>, Option<DateTime<Utc>>);

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
    /// Delete an artifact — an **event-sourced soft delete**.
    ///
    /// The implementation must, atomically:
    ///
    /// 1. mark the artifact deleted (`artifacts.deleted_at`), retaining
    ///    the row, and
    /// 2. append
    ///    [`ArtifactDeleted`](crate::events::ArtifactDeleted) to the
    ///    artifact's own stream ([`StreamId::artifact`](crate::events::StreamId::artifact)),
    ///    attributed to `actor`.
    ///
    /// Neither may be observable without the other: a projection marked
    /// deleted with no event is an unrecorded terminal transition, and an
    /// event with no projection change is a lie about the catalog.
    ///
    /// The CAS blob is **not** touched. Blob lifetime is refcount-gated
    /// GC (`content_references` → the purge path), because another
    /// artifact may reference the same bytes.
    ///
    /// `actor` is the caller identity the event is attributed to; it
    /// rides the persisted-event envelope, never the payload.
    ///
    /// **Idempotent.** Deleting an absent — or already-deleted — artifact
    /// returns [`DomainError::NotFound`](crate::error::DomainError::NotFound)
    /// and appends nothing, so a retried delete cannot put two terminal
    /// events on one stream.
    fn delete(&self, id: Uuid, actor: Actor) -> BoxFuture<'_, DomainResult<()>>;

    /// Find an artifact by its logical path within a repository.
    ///
    /// Returns `None` if no **live** artifact exists at that path — the
    /// lookup filters `deleted_at IS NULL`, like every other read on this
    /// port except the content-age anchor
    /// ([`Self::first_seen_for_checksum`], which counts deleted rows as
    /// evidence on purpose). At most one row: `(repository_id, path)` is
    /// unique among live rows.
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

    /// Keyset-paginated distinct-name listing ordered by `name`
    /// ascending — the same byte-stable order [`Self::list_distinct_names`]
    /// already produces, since names are unique per repository. `after`
    /// excludes names lexicographically `<= after`; `None` starts at the
    /// beginning. Powers `PrefetchTickHandler`'s cross-tick rotation:
    /// resuming a repo's package walk `after` a saved cursor degrades
    /// gracefully if that exact name was since deleted (the `>`
    /// comparison simply lands on the next existing name). Returns a
    /// plain `Vec` — no `total` needed by a cursor walker.
    ///
    /// **Default implementation:** returns
    /// `Err(DomainError::Invariant("list_distinct_names_after not
    /// implemented"))` so existing mocks compile without modification.
    /// The Postgres adapter overrides with the real keyset query.
    fn list_distinct_names_after(
        &self,
        repository_id: Uuid,
        after: Option<&str>,
        limit: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<String>>> {
        let _ = (repository_id, after, limit);
        Box::pin(async {
            Err(DomainError::Invariant(
                "list_distinct_names_after not implemented".into(),
            ))
        })
    }

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
    /// Already-released or quarantined artifacts are excluded —
    /// only `Rejected` rows can be unblocked by a new exclusion.
    ///
    /// Wrapped in
    /// [`LimitedList`] with a hard `LIMIT_LIST_MAX_ITEMS` cap; truncation
    /// is logged at `warn!` for the same reason as `list_active_for_repo`.
    fn list_rejected_for_policy(
        &self,
        policy_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<LimitedList<Artifact>>>;

    /// List **active scanned** artifacts whose active scan-policy resolves
    /// to `policy_id`, **paginated** — the `Released` / `Quarantined` set a
    /// policy *tighten* may have to re-hold (ADR 0041, the tighten
    /// direction of continuous enforcement). The complement of
    /// [`Self::list_rejected_for_policy`]: that lists the `Rejected`
    /// population a *loosen* may re-release; this lists the active
    /// population a tighten may re-reject.
    ///
    /// "Active scan-policy" is the same runtime resolution
    /// [`Self::list_rejected_for_policy`] encodes — repo-scoped policies win
    /// over global, mirroring
    /// `QuarantineUseCase::resolve_active_policy_for_repo`. Only
    /// `Quarantined` / `Released` rows are returned (`Rejected` /
    /// `ScanIndeterminate` / `None` are excluded — a tighten never re-holds
    /// a never-held, already-blocked, or terminal-failure artifact).
    ///
    /// **Returns a [`Page`], NOT a [`LimitedList`] — and the caller pages
    /// through the *whole* population with no fixed cap.** Unlike the
    /// loosen direction (where a `LimitedList` truncation merely defers a
    /// few would-be releases — fail-safe, the artifact stays `Rejected`), a
    /// `LimitedList` cap on the tighten direction is **fail-open**: a
    /// now-failing artifact past the cap would silently keep serving. The
    /// re-evaluation pass therefore iterates pages until exhaustion (ADR
    /// 0041 invariant: a tighten covers the entire in-scope population).
    ///
    /// `page.total` reflects the full in-scope row count so the pass can
    /// surface a completeness signal; callers detect the last page by
    /// `items.len() < page.limit`.
    fn list_active_for_policy(
        &self,
        policy_id: Uuid,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<Artifact>>>;

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
    /// `artifacts (repository_id, name) INCLUDE (version, quarantine_status)`
    /// for an index-only scan with no heap fetch.
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
    ///
    /// Contract any adapter implementing this method must honour: a
    /// returned row always asserts locally-ingested content, regardless
    /// of its `quarantine_status` — including `None`. This holds because
    /// the row is sourced from `artifacts`, whose `checksum_sha256` and
    /// `storage_key` columns are NOT NULL; there is no representable
    /// "known upstream, not ingested" row. Callers that need to
    /// distinguish "ingested, no quarantine lifecycle" (status `None`)
    /// from "never ingested" must do so by row PRESENCE, not by status
    /// value — the absence of a `(version, _, _)` entry for a queried
    /// version is the only "not locally ingested" signal.
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

    /// Per-version `(version, created_at, upstream_published_at)` for
    /// every locally-ingested artifact row in `(repository_id,
    /// package)` — the timestamp source for the cargo sparse-index
    /// `pubtime` field. `created_at` is the row's own NOT NULL column
    /// (hort's first-seen-here observation); `upstream_published_at` is
    /// the untrusted, best-effort upstream-asserted timestamp captured
    /// at ingest (see `Artifact.upstream_published_at`). A version
    /// hort has never ingested for this `(repository_id, package)`
    /// produces no row at all.
    ///
    /// Default impl returns empty so existing test doubles that never
    /// exercise cargo pubtime need not override it (mirrors
    /// [`Self::package_version_anchors`]).
    fn package_version_publish_times(
        &self,
        _repository_id: Uuid,
        _package: &str,
    ) -> BoxFuture<'_, DomainResult<Vec<PackageVersionPublishTimeRow>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    /// The earliest ingest observation hort holds for this content hash —
    /// `MIN(created_at)` over every `artifacts` row carrying
    /// `checksum_sha256 = $1`, across **all** repositories of this
    /// instance. `None` when no row carries the hash.
    ///
    /// This is the primary age evidence behind the quarantine-window
    /// anchor (ADR 0054): the moment hort itself first held these bytes.
    /// It is an *observation*, not a third-party assertion, which is why
    /// it needs no operator opt-in — an upstream claim can be backdated,
    /// an observation cannot.
    ///
    /// **Derived, never materialised.** There is no content-level table
    /// and no projection to keep in step; the aggregate is read live on
    /// the index that already exists (`idx_artifacts_checksum`, migration
    /// `003_artifacts_cas.sql`). A live aggregate is also race-free by
    /// construction — concurrent observers cannot disagree about a `MIN`
    /// the way they could about a stored value they each try to lower.
    /// The accepted cost: the evidence does not outlive the rows, so
    /// content whose last row is purged and which is later re-fetched
    /// re-anchors at that later ingest. That direction is conservative —
    /// a lost observation can only lengthen a window, never shorten one.
    ///
    /// **Soft-deleted rows count**, unlike the rest of this port's read
    /// path. A soft-delete withdraws a row from *service*; it does not
    /// un-observe the bytes, and hort's observation of them is exactly
    /// what this method reports. Only a hard purge — which removes the
    /// row — retires the evidence.
    ///
    /// **Default impl returns `Ok(None)`** so the many test doubles
    /// compile unchanged. `None` is the fail-safe answer: the caller
    /// treats absent evidence as "no evidence", falling back on the mint
    /// instant and holding the content for a full window.
    fn first_seen_for_checksum(
        &self,
        sha256: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Option<DateTime<Utc>>>> {
        let _ = sha256;
        Box::pin(async { Ok(None) })
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
    /// `after`: keyset cursor — when `Some(id)`, only rows with
    /// `id > after` are considered. `None` starts from the beginning.
    /// Lets a single task run walk multiple pages without re-reading a
    /// page it already visited (the in-run advance): a 100%-skipped
    /// page no longer stalls the run at the same rows forever.
    ///
    /// `skip_marker_kind`: when `Some(marker_kind)`, rows carrying a
    /// `content_references` row of `marker_kind` are ALSO excluded (a
    /// second `NOT EXISTS`, alongside the `kind` one) — the durable
    /// structural-skip marker. `None` (the operator's
    /// `ignore_skip_markers: true`) lifts that exclusion and re-surfaces
    /// previously-marked rows, e.g. after a parser fix.
    ///
    /// SQL contract: a single `SELECT … FROM artifacts WHERE path LIKE
    /// '%.whl' AND ($3::uuid IS NULL OR id > $3) AND NOT EXISTS (SELECT 1
    /// FROM content_references WHERE source_artifact_id = artifacts.id AND
    /// kind = $1) AND ($4::text IS NULL OR NOT EXISTS (SELECT 1 FROM
    /// content_references WHERE source_artifact_id = artifacts.id AND kind
    /// = $4)) ORDER BY id LIMIT $2`. The task handler bounds `limit` at
    /// 1000 (its own cap); the adapter MUST NOT silently cap below the
    /// request — a future raise of the handler cap must surface through
    /// unchanged.
    ///
    /// **Resumable across invocations by construction** — a fresh
    /// invocation starts with `after = None`; the candidacy predicate
    /// (`kind` NOT EXISTS, plus `skip_marker_kind` NOT EXISTS when
    /// exclusion is active) is otherwise stateless. A failed page leaves
    /// the candidate set unchanged; the next invocation re-derives the
    /// same work minus whatever a prior successful invocation completed
    /// (extracted, or — for structural skips — marked). Two concurrent
    /// runs would re-walk overlapping sets; the per-CAS `StoragePort::put`
    /// idempotency on identical content + the upsert semantics of
    /// `ContentReferenceIndex::insert` absorb the duplicate work.
    fn find_pypi_wheels_without_kind(
        &self,
        kind: &str,
        limit: u32,
        after: Option<Uuid>,
        skip_marker_kind: Option<&str>,
    ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>>;

    /// Find OCI **single-image manifest** artifacts (`path LIKE
    /// 'manifests/sha256:%'`) that have no `content_references` row of the
    /// given `kind` (in practice `"oci_config"`), bounded by `limit`.
    /// Mirrors [`Self::find_pypi_wheels_without_kind`]'s shape and posture
    /// one-for-one — same candidacy-query contract (including the `after`
    /// keyset cursor and the `skip_marker_kind` durable-exclusion toggle),
    /// same resumability, same consumer (an admin-task backfill:
    /// `oci-membership-edge-backfill` here vs. `wheel-metadata-backfill`
    /// there).
    ///
    /// **Image manifests only — an index must never be returned.** An OCI
    /// image index legitimately carries no `config`/`layers` (it carries
    /// `oci_index_member` children instead), so it would always match the
    /// NOT-EXISTS-`oci_config` predicate despite having nothing to repair.
    /// The adapter discriminates on the manifest's stored media type
    /// (`artifact_metadata.metadata->>'oci_media_type'`, the same field the
    /// OCI read path resolves via `resolve_media_type` —
    /// `hort-http-oci::manifests::resolve_media_type`): a row whose stored
    /// media type is one of the two index types
    /// ([`crate::oci::OCI_IMAGE_INDEX_MEDIA_TYPE`] /
    /// [`crate::oci::DOCKER_MANIFEST_LIST_MEDIA_TYPE`]) is excluded. A row
    /// with **no** `artifact_metadata` row, or one whose `oci_media_type`
    /// field is absent, is treated as an image manifest — this mirrors
    /// `resolve_media_type`'s own fallback (`DEFAULT_MEDIA_TYPE`, the
    /// single-image type) for exactly the pre-metadata-migration rows this
    /// backfill exists to repair.
    ///
    /// SQL contract: `SELECT … FROM artifacts WHERE path LIKE
    /// 'manifests/sha256:%' AND ($5::uuid IS NULL OR id > $5) AND NOT
    /// EXISTS (SELECT 1 FROM content_references WHERE source_artifact_id =
    /// artifacts.id AND kind = $1) AND ($6::text IS NULL OR NOT EXISTS
    /// (SELECT 1 FROM content_references WHERE source_artifact_id =
    /// artifacts.id AND kind = $6)) AND NOT EXISTS (SELECT 1 FROM
    /// artifact_metadata WHERE artifact_id = artifacts.id AND
    /// metadata->>'oci_media_type' IN (<index media types>)) ORDER BY id
    /// LIMIT $2`.
    ///
    /// **Resumable across invocations by construction** — same posture as
    /// [`Self::find_pypi_wheels_without_kind`]: a fresh invocation starts
    /// with `after = None`, a failed page leaves the candidate set
    /// unchanged, and the upsert-on-PK semantics of
    /// `ContentReferenceIndex::insert` absorb duplicate work from
    /// overlapping runs.
    fn find_oci_image_manifests_without_kind(
        &self,
        kind: &str,
        limit: u32,
        after: Option<Uuid>,
        skip_marker_kind: Option<&str>,
    ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// One trait implementation shared by every shape test below.
    ///
    /// The three per-method shape tests each used to carry their own
    /// near-identical 15-method stub; they are collapsed here because the
    /// boilerplate is what the tests are least about, and a fourth copy
    /// (for `first_seen_for_checksum`) would have made the file mostly
    /// stub. Methods that a test asserts on carry their fixture data — and
    /// their input assertions — directly in this impl.
    ///
    /// Deliberately does NOT override the trait's defaulted methods: their
    /// fail-safe defaults are themselves part of the contract and are
    /// exercised through this stub.
    struct Stub;

    impl ArtifactRepository for Stub {
        fn find_by_id(&self, _id: Uuid) -> BoxFuture<'_, DomainResult<Artifact>> {
            Box::pin(async {
                Err(DomainError::NotFound {
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
        fn delete(&self, _id: Uuid, _actor: Actor) -> BoxFuture<'_, DomainResult<()>> {
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
        fn list_active_for_policy(
            &self,
            _policy_id: Uuid,
            _page: PageRequest,
        ) -> BoxFuture<'_, DomainResult<Page<Artifact>>> {
            Box::pin(async { Ok(Page::empty()) })
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
            kind: &str,
            limit: u32,
            _after: Option<Uuid>,
            _skip_marker_kind: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>> {
            // Pin the input shape: the stub returns nothing but
            // accepts the documented kinds/limits without panicking.
            assert_eq!(kind, "wheel_metadata");
            assert!(limit <= 1_000, "handler-side cap is 1000");
            Box::pin(async { Ok(Vec::new()) })
        }
        fn find_oci_image_manifests_without_kind(
            &self,
            kind: &str,
            limit: u32,
            _after: Option<Uuid>,
            _skip_marker_kind: Option<&str>,
        ) -> BoxFuture<'_, DomainResult<Vec<Artifact>>> {
            // Pin the input shape: the stub accepts the documented
            // kind/limit without panicking.
            assert_eq!(kind, "oci_config");
            assert!(limit <= 1_000, "handler-side cap is 1000");
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    /// The trait is dyn-compatible, and so is every method exercised
    /// below — the shape tests all go through `&dyn ArtifactRepository`,
    /// so a generic method or an `impl Future` return would fail to
    /// compile here rather than silently regressing dyn-compat at some
    /// distant call site.
    fn stub() -> Arc<dyn ArtifactRepository> {
        Arc::new(Stub)
    }

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
    /// caught here.
    #[test]
    fn package_version_status_has_documented_shape() {
        let repo = stub();
        let fut = repo.package_version_status(Uuid::nil(), "left-pad");
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
    /// on the trait with the documented shape: `(kind: &str, limit: u32,
    /// after: Option<Uuid>, skip_marker_kind: Option<&str>) ->
    /// BoxFuture<DomainResult<Vec<Artifact>>>`. Shape-pin guards
    /// against a rename / retype that would silently break the
    /// `wheel-metadata-backfill` task handler.
    #[test]
    fn find_pypi_wheels_without_kind_has_documented_shape() {
        let repo = stub();
        let fut = repo.find_pypi_wheels_without_kind(
            "wheel_metadata",
            100,
            Some(Uuid::new_v4()),
            Some("wheel_metadata_skipped"),
        );
        let result = futures::executor::block_on(fut).expect("stub returns Ok");
        assert!(result.is_empty());
    }

    /// The `find_oci_image_manifests_without_kind` method exists on the
    /// trait with the documented shape: `(kind: &str, limit: u32, after:
    /// Option<Uuid>, skip_marker_kind: Option<&str>) ->
    /// BoxFuture<DomainResult<Vec<Artifact>>>`. Shape-pin guards against a
    /// rename/retype that would silently break the
    /// `oci-membership-edge-backfill` task handler — mirrors
    /// `find_pypi_wheels_without_kind_has_documented_shape` above.
    #[test]
    fn find_oci_image_manifests_without_kind_has_documented_shape() {
        let repo = stub();
        let fut = repo.find_oci_image_manifests_without_kind(
            "oci_config",
            100,
            Some(Uuid::new_v4()),
            Some("oci_membership_skipped"),
        );
        let result = futures::executor::block_on(fut).expect("stub returns Ok");
        assert!(result.is_empty());
    }

    /// `first_seen_for_checksum` exists with the documented shape —
    /// `(&ContentHash) -> BoxFuture<DomainResult<Option<DateTime<Utc>>>>`
    /// — and its default impl answers `None`.
    ///
    /// `None` is the load-bearing half: it is what an adapter that has not
    /// implemented the method reports, and the quarantine-anchor
    /// derivation must read that as "no age evidence" and fall back on the
    /// mint instant (a full window), never as "evidence of an earlier
    /// instant". A default that guessed would shorten a security window on
    /// no evidence.
    #[test]
    fn first_seen_for_checksum_defaults_to_no_evidence() {
        let hash: ContentHash = "a".repeat(64).parse().expect("valid sha256 hex");
        let repo = stub();
        let fut = repo.first_seen_for_checksum(&hash);
        let result = futures::executor::block_on(fut).expect("default impl returns Ok");
        assert_eq!(result, None, "absent evidence, not an invented instant");
    }

    /// The other two defaulted reads answer conservatively too:
    /// `package_version_anchors` yields no rows (a test double that never
    /// exercises discovery advertises nothing) and
    /// `find_canonical_name_by_collision_key` yields "no collision".
    #[test]
    fn the_defaulted_reads_answer_conservatively() {
        let repo = stub();

        let anchors =
            futures::executor::block_on(repo.package_version_anchors(Uuid::nil(), "left-pad"))
                .expect("default impl returns Ok");
        assert!(anchors.is_empty());

        let canonical = futures::executor::block_on(
            repo.find_canonical_name_by_collision_key(Uuid::nil(), "foo-bar"),
        )
        .expect("default impl returns Ok");
        assert_eq!(canonical, None);
    }
}
