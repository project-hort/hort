//! Maven `maven-metadata.xml` serve — the Maven side of the unified
//! Source → Filter → Builder pipeline (design §6 A-level; §7 V-level).
//!
//! `maven-metadata.xml` is **server-generated** on every GET, never served
//! from a client-PUT copy: the client copy could advertise quarantined
//! versions, which the [`NonServableStatusFilter`] step deliberately drops.
//! The pipeline is:
//!
//! 1. **Source.** [`HostedMavenSource`] materialises one [`VersionEntry`]
//!    per servable version (A-level) or per stored timestamped build
//!    (V-level) from the hosted artifact projection, via the
//!    drift-resilient [`ArtifactUseCase::list_by_raw_name_visible`]
//!    (which threads the caller for anti-enumeration — a Read denial /
//!    missing repo collapses to `NotFound { entity: "Repository" }`).
//! 2. **Filter pipeline.** `NonServableStatusFilter` then
//!    `IndexModeFilter::new(repo.index_mode)` — identical to the
//!    npm/pypi/cargo pipeline.
//! 3. **Builder.** [`MavenMetadataXmlBuilder`] emits the A-level or
//!    V-level document, dispatching on the entry payload case, with
//!    `MavenVersionOrdering` wired into `BuildContext.ordering`.
//!
//! # A-level vs V-level
//!
//! A request's path-shape marker (`maven_path_kind`, tagged by
//! `MavenFormatHandler::parse_download_path`) decides which document the
//! source materialises:
//!
//! - **A-level** (`g/a/maven-metadata.xml`, no version): the distinct
//!   Maven versions for the `group:artifact` name. The source emits one
//!   [`MavenVersionPayload::Artifact`] entry per distinct version; the
//!   per-version `last_updated` comes from the newest artifact row of that
//!   version (max `created_at`). An unknown artifact (zero rows) → 404.
//! - **V-level** (`g/a/X-SNAPSHOT/maven-metadata.xml`): the timestamped
//!   snapshot builds for the base `-SNAPSHOT` version. The source loads the
//!   stored group members for that base version, decomposes each
//!   timestamped filename into a `(classifier, extension, timestamp,
//!   build_number)` build, and emits one `MavenVersionPayload::Snapshot`
//!   per build (the builder keeps the most-recent build per
//!   `(classifier, extension)` and derives the `<snapshot>` block from the
//!   single highest build). An unknown snapshot artifact (zero stored rows
//!   for the base version) → 404.
//!
//! # Observability
//!
//! No per-handler request spans (tower-http covers it). The filter
//! pipeline reuses the existing
//! `hort_index_versions_filtered_total{format, repository}` counter,
//! emitted once per call across the dropped-version count (mirrors the
//! cargo serve handler).

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{DateTime, Utc};

use hort_app::error::AppError;
use hort_app::use_cases::index_filters::{IndexModeFilter, NonServableStatusFilter};
use hort_app::use_cases::index_serve::{
    BuildContext, IndexFilter, MavenVersionPayload, PerVersionPayload, VersionEntry,
};
use hort_app::use_cases::index_serve_filter::MavenVersionOrdering;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::Repository;
use hort_formats::index_serve::IndexBuilder;
use hort_formats::maven::coords::split_ga;
use hort_formats::maven::metadata::MavenMetadataXmlBuilder;
use hort_formats::maven::snapshot::decompose_snapshot_filename;
use hort_formats::maven::MavenFormatHandler;
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;

/// Which `maven-metadata.xml` document a request addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataLevel {
    /// A-level (`g/a/maven-metadata.xml`) — the artifact version list.
    Artifact,
    /// V-level (`g/a/X-SNAPSHOT/maven-metadata.xml`) — the snapshot build
    /// list for one base `-SNAPSHOT` version.
    Snapshot,
}

/// Output of one [`MavenIndexSource::fetch`] call: the per-version /
/// per-build entries plus the document `<lastUpdated>` fallback the
/// builder uses when no entry carries a derivable timestamp (the newest
/// artifact row's commit time — data-derived, never a live clock; design
/// §6 / §12).
pub(crate) struct MavenSourceOutput {
    pub entries: Vec<VersionEntry>,
    pub last_updated_fallback: String,
}

/// Per-format Maven metadata source. Stays `pub(crate)` — sources are an
/// implementation detail of the format HTTP crate (mirrors the cargo
/// `IndexSource` shape). Dispatched on the requested [`MetadataLevel`].
#[async_trait]
pub(crate) trait MavenIndexSource: Send + Sync {
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        name: &str,
        level: MetadataLevel,
        version: Option<&str>,
        caller: Option<&CallerPrincipal>,
    ) -> Result<MavenSourceOutput, AppError>;
}

// ---------------------------------------------------------------------------
// Hosted
// ---------------------------------------------------------------------------

/// `MavenIndexSource` for hosted (and Staging) repos.
///
/// Reads the local artifact projection via the drift-resilient
/// [`ArtifactUseCase::list_by_raw_name_visible`] (the
/// per-resource-visibility-enforcing anti-enumeration entry point — a
/// Read denial / missing repo collapses to `NotFound`).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct HostedMavenSource;

#[async_trait]
impl MavenIndexSource for HostedMavenSource {
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        name: &str,
        level: MetadataLevel,
        version: Option<&str>,
        caller: Option<&CallerPrincipal>,
    ) -> Result<MavenSourceOutput, AppError> {
        let handler = MavenFormatHandler;
        // `list_by_raw_name_visible` re-resolves the repo (Read) before
        // reading rows: invisible / missing repo collapses to
        // `NotFound { entity: "Repository" }` (anti-enumeration). The
        // raw-name fallback recovers rows under normalisation drift.
        let (resolved_repo, artifact_list) = ctx
            .artifact_use_case
            .list_by_raw_name_visible(&repo.key, &handler, name, caller)
            .await?;
        debug_assert_eq!(resolved_repo.id, repo.id);
        let artifacts = artifact_list.items;

        match level {
            MetadataLevel::Artifact => Ok(materialise_a_level(&artifacts)),
            // V-level (snapshot) materialisation from the stored group's
            // timestamped members for the base `-SNAPSHOT` version.
            MetadataLevel::Snapshot => Ok(materialise_v_level(name, &artifacts, version)),
        }
    }
}

/// Materialise A-level entries: one [`MavenVersionPayload::Artifact`] per
/// distinct version, with `last_updated` derived from the newest artifact
/// row of that version (max `created_at`, in Maven's `yyyyMMddHHmmss`
/// form). `status` is the **worst** (most-restrictive) status across the
/// version's files so the `NonServableStatusFilter` drops a version when
/// any of its files is non-servable (a quarantined `.jar` hides the
/// version even if its `.pom` is released).
fn materialise_a_level(
    artifacts: &[hort_domain::entities::artifact::Artifact],
) -> MavenSourceOutput {
    // Per-version aggregation: keep the worst status + the newest commit
    // time. `BTreeMap` keeps a deterministic key order (the builder sorts
    // by `MavenVersionOrdering` anyway, but determinism here keeps the
    // `last_updated_max` derivation stable).
    let mut per_version: BTreeMap<
        String,
        (
            hort_domain::entities::artifact::QuarantineStatus,
            DateTime<Utc>,
        ),
    > = BTreeMap::new();
    let mut newest_overall: Option<DateTime<Utc>> = None;

    for artifact in artifacts {
        let Some(version) = artifact.version.clone() else {
            continue;
        };
        if newest_overall.is_none_or(|cur| artifact.created_at > cur) {
            newest_overall = Some(artifact.created_at);
        }
        per_version
            .entry(version)
            .and_modify(|(status, created)| {
                *status = worst_status(*status, artifact.quarantine_status);
                if artifact.created_at > *created {
                    *created = artifact.created_at;
                }
            })
            .or_insert((artifact.quarantine_status, artifact.created_at));
    }

    let entries: Vec<VersionEntry> = per_version
        .into_iter()
        .map(|(version, (status, created))| VersionEntry {
            version,
            status: Some(status),
            payload: PerVersionPayload::Maven(MavenVersionPayload::Artifact {
                last_updated: Some(fmt_last_updated(created)),
            }),
        })
        .collect();

    let last_updated_fallback = newest_overall.map(fmt_last_updated).unwrap_or_default();
    MavenSourceOutput {
        entries,
        last_updated_fallback,
    }
}

/// Materialise V-level (snapshot) entries from the stored group's
/// timestamped members for the base `-SNAPSHOT` `version` (design §7).
///
/// For each stored artifact row whose `version` matches the requested base
/// `X-SNAPSHOT`, the row's `path` filename is decomposed into
/// `(classifier, extension, timestamp, build_number)` via the Item-4
/// snapshot parser, and one [`MavenVersionPayload::Snapshot`] entry is
/// emitted carrying:
/// - `value` = the resolved timestamped version string
///   (`{base}-{yyyyMMdd.HHmmss}-{N}`) Maven clients request the concrete
///   file by;
/// - `timestamp` = the dotted `yyyyMMdd.HHmmss` form (the
///   `<snapshot><timestamp>` value for the highest build);
/// - `updated` = the NON-dotted `yyyyMMddHHmmss` form (the
///   `<snapshotVersion><updated>` / `<lastUpdated>` value);
/// - `classifier` / `extension` / `build_number` from the filename.
///
/// The builder then keeps the most-recent build per
/// `(classifier, extension)` key and derives the document `<snapshot>`
/// block from the single highest `(timestamp, build_number)` across all
/// keys. (We emit one entry per stored build and let the builder
/// deduplicate — the most-recent-per-key reduction is its job, not the
/// source's, and it keeps the `value` strings carried verbatim.)
///
/// The `<lastUpdated>` fallback is the newest matching row's commit time —
/// data-derived, never a live clock. When no rows match the base version
/// the entry set is empty; the builder renders a valid (empty) V-level
/// document and the handler 404s on the unknown snapshot artifact.
fn materialise_v_level(
    name: &str,
    artifacts: &[hort_domain::entities::artifact::Artifact],
    version: Option<&str>,
) -> MavenSourceOutput {
    // The `(group, artifact)` split drives the filename decomposition. A
    // mis-constructed GA name (no `:`) yields no entries — the handler then
    // 404s, the same as an unknown artifact.
    let artifact_id = split_ga(name).map(|(_g, a)| a.to_string()).ok();
    // The requested base is the V-level path's version segment (always a
    // `X-SNAPSHOT` — the parser only tags `metadata_v` for snapshot
    // versions). Strip the `-SNAPSHOT` suffix to get the base `X`.
    let snapshot_base = version.and_then(|v| v.strip_suffix("-SNAPSHOT"));

    let mut entries: Vec<VersionEntry> = Vec::new();
    for artifact in artifacts {
        // Only rows of the requested base version contribute.
        if artifact.version.as_deref() != version {
            continue;
        }
        let (Some(artifact_id), Some(base), Some(base_version)) =
            (artifact_id.as_deref(), snapshot_base, version)
        else {
            continue;
        };
        let filename = artifact
            .path
            .rsplit('/')
            .next()
            .unwrap_or(artifact.path.as_str());
        let Some(snap) = decompose_snapshot_filename(filename, artifact_id, base) else {
            // A literal `foo-X-SNAPSHOT.jar` (non-timestamped) stored row,
            // or any filename that is not a timestamped build, contributes
            // no `<snapshotVersion>` entry. (Maven 3 always deploys unique
            // timestamped snapshots; a non-timestamped row is not part of
            // the snapshot build list.)
            continue;
        };
        entries.push(VersionEntry {
            version: base_version.to_string(),
            status: Some(artifact.quarantine_status),
            payload: PerVersionPayload::Maven(MavenVersionPayload::Snapshot(snap)),
        });
    }

    let last_updated_fallback = artifacts
        .iter()
        .filter(|a| a.version.as_deref() == version)
        .map(|a| a.created_at)
        .max()
        .map(fmt_last_updated)
        .unwrap_or_default();
    MavenSourceOutput {
        entries,
        last_updated_fallback,
    }
}

/// The most-restrictive of two quarantine statuses, so an A-level version
/// is dropped by `NonServableStatusFilter` when ANY of its files is
/// non-servable. Ordering (most → least restrictive):
/// `Rejected` > `Quarantined` > `ScanIndeterminate` > `Released` > `None`.
fn worst_status(
    a: hort_domain::entities::artifact::QuarantineStatus,
    b: hort_domain::entities::artifact::QuarantineStatus,
) -> hort_domain::entities::artifact::QuarantineStatus {
    use hort_domain::entities::artifact::QuarantineStatus as Q;
    fn rank(s: Q) -> u8 {
        match s {
            Q::Rejected => 4,
            Q::Quarantined => 3,
            Q::ScanIndeterminate => 2,
            Q::Released => 1,
            Q::None => 0,
        }
    }
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

/// Format a `DateTime<Utc>` as Maven's `yyyyMMddHHmmss` (14-digit,
/// no-separator) `<lastUpdated>` form. Pure data derivation — the time is
/// an artifact row's commit timestamp, never a live clock read inside the
/// pure builder (design §12).
fn fmt_last_updated(t: DateTime<Utc>) -> String {
    t.format("%Y%m%d%H%M%S").to_string()
}

/// Pick the [`MavenIndexSource`] for `repo`. Hosted is the only v1 source
/// (pull-through metadata is Item 9). Mirrors the cargo `select_source`
/// dispatch seam so a future proxy source slots in here.
fn select_source(_repo: &Repository) -> Box<dyn MavenIndexSource> {
    Box::new(HostedMavenSource)
}

/// Build the server-generated `maven-metadata.xml` (A-level or V-level)
/// wire bytes through the Source → Filter → Builder pipeline.
///
/// This is the shared producer for both the metadata GET
/// ([`serve_metadata`]) and the metadata-sidecar GET
/// ([`crate::download`] → digest over these bytes): a
/// `maven-metadata.xml.sha1` GET hashes exactly the bytes a
/// `maven-metadata.xml` GET would serve, so the sidecar is always
/// consistent with the served document (design §6).
///
/// `caller` is threaded for anti-enumeration: the hosted source's
/// `list_by_raw_name_visible` hop performs the Read access check, so a
/// denied / invisible / missing repo collapses to a 404 `NotFound`
/// envelope before any version data is surfaced.
///
/// An unknown artifact → 404: A-level with no servable rows, or V-level
/// (`X-SNAPSHOT`) with no stored rows for the base version.
pub(crate) async fn build_metadata_bytes(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    name: &str,
    level: MetadataLevel,
    version: Option<&str>,
    caller: Option<&CallerPrincipal>,
) -> Result<Vec<u8>, ApiError> {
    let output = select_source(repo)
        .fetch(ctx, repo, name, level, version, caller)
        .await
        .map_err(ApiError::from)?;

    // Unknown artifact → 404 (design §17: maven-metadata.xml GET for an
    // unknown artifact).
    // - A-level with zero source entries means no version of
    //   `group:artifact` exists in this repo.
    // - V-level (`X-SNAPSHOT`) with NO stored rows of the base version is an
    //   unknown snapshot artifact. The source's empty `last_updated_fallback`
    //   (derived from rows matching the base version) is the
    //   zero-matching-rows signal — distinct from "rows exist but none are
    //   timestamped builds", which renders a valid (empty) V-level document.
    let unknown = match level {
        MetadataLevel::Artifact => output.entries.is_empty(),
        MetadataLevel::Snapshot => output.last_updated_fallback.is_empty(),
    };
    if unknown {
        return Err(ApiError::from(AppError::Domain(
            hort_domain::error::DomainError::NotFound {
                entity: "Artifact",
                id: name.to_string(),
            },
        )));
    }

    // ---- Filter pipeline (identical to the npm/pypi/cargo pipeline) ----
    let upstream_count = output.entries.len();
    let filters: Vec<Arc<dyn IndexFilter>> = vec![
        Arc::new(NonServableStatusFilter),
        Arc::new(IndexModeFilter::new(repo.index_mode)),
    ];
    let filtered: Vec<VersionEntry> = filters.iter().fold(output.entries, |acc, f| f.apply(acc));
    let served_count = filtered.len();
    let filtered_count = upstream_count.saturating_sub(served_count);

    if filtered_count > 0 {
        metrics::counter!(
            "hort_index_versions_filtered_total",
            "format" => "maven",
            "repository" => repo.key.clone(),
        )
        .increment(filtered_count as u64);
    }

    // ---- Build the wire bytes ----
    let builder = MavenMetadataXmlBuilder::new(output.last_updated_fallback);
    let body_bytes = builder.build(
        BuildContext {
            package_name: name,
            base_url: "", // unused — maven-metadata carries no per-version URLs
            index_mode: repo.index_mode,
            ordering: &MavenVersionOrdering,
        },
        filtered,
    );
    Ok(body_bytes.to_vec())
}

/// Serve a server-generated `maven-metadata.xml` (A-level or V-level)
/// through the Source → Filter → Builder pipeline.
///
/// `caller` is threaded for anti-enumeration: the hosted source's
/// `list_by_raw_name_visible` hop performs the Read access check, so a
/// denied / invisible / missing repo collapses to a 404 `NotFound`
/// envelope before any version data is surfaced.
///
/// An unknown artifact → 404: A-level with no servable rows, or V-level
/// (`X-SNAPSHOT`) with no stored rows for the base version.
pub(crate) async fn serve_metadata(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    name: &str,
    level: MetadataLevel,
    version: Option<&str>,
    caller: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    let body_bytes = build_metadata_bytes(ctx, repo, name, level, version, caller).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        // Real Maven Central serves `text/xml`; Maven Resolver tolerates
        // either `text/xml` or `application/xml` (it parses
        // namespace-agnostically). `text/xml` matches Central.
        .header(CONTENT_TYPE, "text/xml")
        .body(Body::from(body_bytes))
        .unwrap())
}
