//! Cargo `IndexSource` impls for the unified sparse-index pipeline
//! (see `docs/architecture/explanation/index-construction.md`).
//!
//! Mirrors the npm and PyPI shapes. The per-format-internal
//! [`IndexSource`] trait is `pub(crate)` (sources stay in the format
//! HTTP crate because hosted needs `ArtifactUseCase` access and proxy
//! needs the upstream-fetch ports) and has two Cargo implementations:
//!
//! - [`HostedCargoSource`] — reads the local artifact projection via
//!   [`ArtifactUseCase::list_by_raw_name_visible`] (threading the
//!   caller principal so anti-enumeration applies — denied / no-
//!   rows / missing-repo all collapse to `NotFound` at the unified
//!   handler).
//! - [`ProxyCargoSource`] — drives the upstream-fetch + cache +
//!   dedup + stale-while-error pipeline via
//!   [`crate::index_cache::fetch_raw_with_cache`] (which streams the
//!   body through the projector and returns the small
//!   `Vec<CargoVersionLine>` projection — the raw NDJSON body goes to
//!   the mirror, the projection to Redis; see ADR 0026), then maps
//!   each [`CargoVersionLine`] into one [`VersionEntry`] for the
//!   unified Source → Filter → Builder pipeline. The prefetch trigger
//!   (see `docs/architecture/explanation/prefetch-pipeline.md`) fires
//!   from this source after the fetch, consuming the projection
//!   directly.
//!
//! # Why drive the existing `fetch_raw_with_cache` rather than dial
//! # upstream directly
//!
//! `fetch_raw_with_cache` already implements all the cache-layer
//! invariants the unified handler must preserve byte-for-byte:
//!
//! - cache key format / mapping-id invalidation axis;
//! - `PullDedup` single-flight coalescing;
//! - stale-while-error fallback.
//!
//! The quarantine-aware serve filter previously lived inside the cache
//! helper (`apply_quarantine_filter`); the unified pipeline moved it
//! into `NonServableStatusFilter` + `IndexModeFilter`, applied
//! post-source. The prefetch trigger fires from this source after the
//! raw fetch (`fire_prefetch_trigger_cargo`).
//!
//! # Output of the proxy source
//!
//! [`ProxyCargoSource::fetch`] parses the raw upstream NDJSON line-by-
//! line and produces one [`VersionEntry`] per **servable** line, with
//! `status` hydrated from [`ArtifactUseCase::package_version_status`]
//! (`None` when the registry has never seen the version). Each entry's
//! `payload.Cargo` carries the NDJSON-line fields the builder needs.
//!
//! A line whose upstream `cksum` the pull-through could not verify a
//! download against is withheld here rather than advertised — hort
//! advertises nothing it will not serve (ADR 0062), and the upstream
//! checksum is the precondition for serving a proxied version at all
//! (ADR 0006). The decision is per version and the projection itself
//! stays verbatim; see [`projection_to_entries`] for why it sits at
//! this mapping and nowhere earlier.
//!
//! # `truncated` channel
//!
//! [`IndexSourceOutput::truncated`] lets the hosted source propagate
//! the `LimitedList::truncated` flag into a `Warning: 299` header.
//! Cargo mirrors the npm/PyPI shape: hosted sources can be truncated
//! (the paginated read caps at `LIMIT_LIST_MAX_ITEMS`); proxy sources
//! cannot (upstream cargo sparse-index NDJSON is not paginated on the
//! wire). Re-declared here (sources are crate-private;
//! the support type is also crate-private and per-crate-local) —
//! mirrors `IndexSourceOutput` in `hort-http-npm/src/index_source.rs`
//! and `hort-http-pypi/src/index_source.rs`.

use std::sync::Arc;

use async_trait::async_trait;

use hort_app::error::AppError;
use hort_app::use_cases::index_serve::{CargoVersionPayload, PerVersionPayload, VersionEntry};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::{Repository, RepositoryType};
use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::cargo::projection::CargoVersionLine;
use hort_formats::cargo::{parse_index_cksum, CargoFormatHandler};
use hort_http_core::context::AppContext;

use crate::index_cache::IndexFetchError;
use crate::publish_metadata::StoredIndexFields;

/// Output of one [`IndexSource::fetch`] call.
///
/// `truncated` is the channel the hosted source uses to propagate the
/// [`LimitedList::truncated`] flag from
/// [`ArtifactUseCase::list_by_raw_name_visible`]; the unified handler
/// converts it into the `Warning: 299` response header. The proxy
/// source always sets it to `false` (Cargo sparse-index NDJSON is not
/// paginated at the wire layer).
#[derive(Debug)]
pub(crate) struct IndexSourceOutput {
    /// Per-version entries the source produced — fed verbatim into
    /// the [`crate::serve`] handler's filter pipeline.
    pub entries: Vec<VersionEntry>,
    /// True iff the underlying paginated read hit
    /// [`LIMIT_LIST_MAX_ITEMS`](hort_domain::types::LIMIT_LIST_MAX_ITEMS).
    /// The unified handler emits a `Warning: 299` header when this is
    /// true; only the hosted source is paginated.
    pub truncated: bool,
}

/// Per-format index source. Stays `pub(crate)` —
/// sources are an implementation detail of the format HTTP crate.
#[async_trait]
pub(crate) trait IndexSource: Send + Sync {
    /// Produce per-version entries for `crate_name` on `repo`.
    /// `caller` is threaded for anti-enumeration (the hosted
    /// source's use-case call requires it).
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        crate_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> Result<IndexSourceOutput, AppError>;
}

// ---------------------------------------------------------------------------
// Hosted
// ---------------------------------------------------------------------------

/// `IndexSource` impl for `RepositoryType::Hosted` (and `Staging` /
/// `Virtual`, which the dispatch site treats as "anything not Proxy").
///
/// Reads the local artifact projection via
/// [`ArtifactUseCase::list_by_raw_name_visible`] (the
/// per-resource-visibility-enforcing anti-enumeration entry point).
/// Each Artifact row becomes one [`VersionEntry`] whose
/// `payload.Cargo` carries the hosted-emission NDJSON-line fields.
///
/// The artifact row is authoritative for identity and integrity:
/// `name` from `Artifact.name` (drift-resilience pin), `vers` from
/// `Artifact.version`, `cksum` from `Artifact.sha256_checksum` (the
/// CAS hash — never a publisher-supplied digest), `yanked = false`.
/// The dependency-graph fields — `deps`, `features`, `features2`,
/// `v`, `links`, `rust_version` — come from the metadata the publish
/// handler persisted, joined in via
/// [`ArtifactUseCase::batch_metadata`]. A version with no stored
/// metadata (ingested before publish captured it, or written by a
/// non-publish path such as a seed import) keeps serving the entry it
/// always served: empty `deps` / `features`, no `v` / `features2`.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct HostedCargoSource;

#[async_trait]
impl IndexSource for HostedCargoSource {
    #[tracing::instrument(skip(self, ctx, caller), fields(repo_key = %repo.key))]
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        crate_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> Result<IndexSourceOutput, AppError> {
        // `list_by_raw_name_visible` performs the
        // `RepositoryAccessUseCase::resolve(_, actor, Read)` hop
        // before reading rows: invisible / missing repo collapses to
        // `NotFound { entity: "Repository" }` (anti-enumeration); the
        // unified handler maps both arms back into the same 404
        // envelope the hosted serve emitted.
        let handler = CargoFormatHandler;
        let (resolved_repo, artifact_list) = ctx
            .artifact_use_case
            .list_by_raw_name_visible(&repo.key, &handler, crate_name, caller)
            .await?;
        // Defence-in-depth: the use case re-resolved the repo (its
        // visibility predicate is authoritative); the `repo` the
        // unified handler held cannot be a different one in practice,
        // but the assertion documents the invariant.
        debug_assert_eq!(resolved_repo.id, repo.id);
        let truncated = artifact_list.truncated;
        let artifacts = artifact_list.items;

        // One batched read for the whole version set — never a
        // per-version round-trip. Every id was authz'd by
        // `list_by_raw_name_visible` above, which is the precondition
        // `batch_metadata` documents. Goes through the use case
        // because `ctx.artifact_metadata` is off-limits to format
        // crates (ADR 0008).
        let ids: Vec<uuid::Uuid> = artifacts.iter().map(|a| a.id).collect();
        let metadata_rows = ctx.artifact_use_case.batch_metadata(&ids).await?;

        let mut entries = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            // Versionless rows are not part of the sparse-index; skip.
            let Some(version) = artifact.version.clone() else {
                continue;
            };
            // `load_full_metadata` is the strategy-agnostic read: the
            // cargo handler stores inline, so this resolves to the
            // row's own JSON with no CAS round-trip, and it stays
            // correct if the format ever adopts the blob-spilling
            // strategy.
            let stored = match metadata_rows.get(&artifact.id) {
                Some(row) => ctx.artifact_use_case.load_full_metadata(row).await?,
                None => serde_json::Value::Null,
            };
            let index_fields = StoredIndexFields::from_stored(&stored);
            let payload = CargoVersionPayload {
                // Drift-resilience: use the STORED name, not the
                // re-normalised request parameter. Under drift this
                // keeps each entry's `name` consistent with the path
                // where `find_by_path` will actually find it. Mirrors
                // the hosted local-NDJSON path.
                name_as_published: artifact.name.clone(),
                vers: version.clone(),
                cksum: artifact.sha256_checksum.to_string(),
                deps: index_fields.deps,
                features: index_fields.features,
                yanked: false,
                links: index_fields.links,
                rust_version: index_fields.rust_version,
                v: index_fields.v,
                features2: index_fields.features2,
                // Hosted: the artifact's own `created_at` — publish
                // time at THIS registry, authoritative (always `Some`;
                // every hosted artifact row has one).
                pubtime: Some(artifact.created_at),
            };
            entries.push(VersionEntry {
                version,
                status: Some(artifact.quarantine_status),
                payload: PerVersionPayload::Cargo(payload),
            });
        }

        Ok(IndexSourceOutput { entries, truncated })
    }
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

/// `IndexSource` impl for `RepositoryType::Proxy`.
///
/// Calls the existing [`crate::index_cache::fetch_with_cache`] (which
/// drives the `UpstreamProxy::fetch_metadata` port through the
/// established cache + dedup + stale-while-error + quarantine-filter
/// pipeline, preserving every cache-invariant byte-for-byte), then
/// re-parses the served body into per-version [`VersionEntry`] rows
/// with status hydrated via
/// [`ArtifactUseCase::package_version_status`].
///
/// **No new port shape introduced.** Source adapters reuse the
/// existing surface. The proxy source's only new behaviour is the
/// re-parse step; the upstream-IO path is the existing serve path.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ProxyCargoSource;

#[async_trait]
impl IndexSource for ProxyCargoSource {
    #[tracing::instrument(skip(self, ctx, caller), fields(repo_key = %repo.key))]
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        crate_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> Result<IndexSourceOutput, AppError> {
        // Anti-enumeration defensive re-resolve. The unified
        // handler performs `RepositoryAccessUseCase::resolve(_, actor,
        // Read)` before invoking the source; we re-resolve here
        // defensively so the anti-enumeration invariant holds even if a future
        // caller bypasses the dispatch hop. Mirrors `ProxyNpmSource`'s
        // same defensive re-resolve.
        let _ = ctx
            .repository_access_use_case
            .resolve(
                &repo.key,
                caller,
                hort_app::use_cases::repository_access::AccessLevel::Read,
            )
            .await?;

        // Drive the existing cache + dedup + stale-while-error pipeline.
        // The helper streams the body through the projector and returns
        // the PROJECTION (`Vec<CargoVersionLine>`); the raw NDJSON went
        // to the mirror (see ADR 0026). Serve maps the projection
        // directly into entries; no `Cursor::project` re-parse here.
        // The helper takes explicit deps to keep
        // `hort-formats-upstream` from needing `Arc<AppContext>` (a
        // construction cycle). In-crate callers pass the corresponding
        // ctx fields by ref (+ `Some(ctx.metadata_mirror.as_ref())`).
        let projection = match crate::index_cache::fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy
                .for_format(&crate::UPSTREAM_PROXY_FORMAT)
                .as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            repo,
            crate_name,
        )
        .await
        {
            Ok(p) => p,
            Err(IndexFetchError::NoUpstream) => {
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::NotFound {
                        entity: "Artifact",
                        id: crate_name.to_string(),
                    },
                ));
            }
            Err(IndexFetchError::UpstreamUnavailable) => {
                return Err(AppError::External(
                    "cargo upstream unavailable; no cached fallback".to_string(),
                ));
            }
            Err(IndexFetchError::MetadataMalformed { cause: _ }) => {
                // A malformed upstream NDJSON body surfaces as
                // `result=parse_error` (502 via the typed
                // `UpstreamMetadataInvalid` mapping — mirrors the
                // established `upstream_pull::map_upstream_pull_error`
                // `ParseError` wire shape), NEVER the network /
                // `upstream_unavailable` bucket, and NEVER the raw
                // upstream-derived `cause` (already logged server-side at
                // the construction site in `index_cache.rs`). Fail-closed:
                // nothing was cached or mirrored.
                let repo_label = if ctx.include_repository_label {
                    repo.key.as_str()
                } else {
                    hort_app::metrics::values::REPOSITORY_ALL
                };
                hort_app::metrics::emit_upstream_parse_error("cargo", repo_label);
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::UpstreamMetadataInvalid,
                ));
            }
            Err(IndexFetchError::Internal(msg)) => {
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::Invariant(msg),
                ));
            }
        };

        // Per-version status hydration, propagated and never degraded
        // — see the npm proxy source for the full reasoning: an empty
        // status map is the claim "hort holds nothing non-servable
        // here", which under `IncludePending` re-advertises every
        // version hort is holding back.
        let handler = CargoFormatHandler;
        let normalized = handler.normalize_name(crate_name);
        let pkg_status = ctx
            .artifact_use_case
            .package_version_status(repo.id, &normalized)
            .await?;

        // Fire the prefetch trigger on every successful fetch. The
        // trigger consumes the already-computed projection directly (no
        // second parse of a raw body, which no longer exists at this
        // layer; see `docs/architecture/explanation/prefetch-pipeline.md`).
        crate::index_cache::fire_prefetch_trigger_cargo(
            ctx,
            repo,
            &normalized,
            &projection,
            &pkg_status,
        );
        let status_map: std::collections::HashMap<
            String,
            hort_domain::entities::artifact::QuarantineStatus,
        > = pkg_status.into_iter().collect();

        // `pubtime` timestamp source. Row presence (like `pkg_status`
        // above) means "locally ingested"; a version with no row here
        // is never-ingested and must serve no `pubtime` at all — never
        // an invented value. A read failure degrades to "no timestamps
        // known" (every entry omits `pubtime`), matching the
        // `pkg_status` degradation above: this field is a served
        // convenience, never load-bearing for gate/policy decisions.
        let publish_times = ctx
            .artifact_use_case
            .package_version_publish_times(repo.id, &normalized)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "cargo proxy source: package_version_publish_times failed; degrading to no pubtime");
                Vec::new()
            });
        let pubtime_map: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>> =
            publish_times
                .into_iter()
                .map(|(version, created_at, upstream_published_at)| {
                    // Precedence: upstream-asserted → first-seen-here.
                    // Row presence already guarantees "locally
                    // ingested"; `created_at` is NOT NULL, so this is
                    // always `Some`.
                    (version, upstream_published_at.unwrap_or(created_at))
                })
                .collect();

        let entries = projection_to_entries(projection, &normalized, &status_map, &pubtime_map);

        Ok(IndexSourceOutput {
            entries,
            truncated: false,
        })
    }
}

/// Map an already-projected cargo sparse-index
/// `Vec<CargoVersionLine>` into `Vec<VersionEntry>`. Each **servable**
/// line becomes one entry with `payload.Cargo` carrying the line's
/// fields. The `status_map` hydrates the entry's `status` field via
/// `(version, status)` lookup; absent → `None` (unknown tier).
/// `pubtime_map` hydrates `payload.pubtime` the same way; absent → the
/// version is never-ingested, so `pubtime` stays `None` — never a
/// `line.pubtime` fallback (that field is upstream-sourced forward-compat
/// scaffolding, unrelated to the precedence this backlog defines; see
/// `CargoVersionLine::pubtime`'s doc-comment).
///
/// The projection is already computed (the helper
/// `crate::index_cache::fetch_raw_with_cache` streamed the body through
/// `CargoSparseIndexProjector` on the fetch path; serve maps the cached
/// projection with no re-parse). A malformed NDJSON line fails closed
/// *inside* `fetch_and_project` (reject-on-invalid,
/// validate-before-commit) and surfaces as
/// `IndexFetchError::MetadataMalformed` above — it never reaches here
/// as a partially-projected body.
///
/// # A version with no verifiable upstream checksum is withheld
///
/// Hort advertises nothing it will not serve (ADR 0062), and for a
/// proxied version the upstream-published checksum is the precondition
/// for serving it at all (ADR 0006): the pull-through verifies the
/// streamed bytes against the index `cksum` and refuses the download
/// when that value is absent or malformed. Advertising such a version
/// resolves a client onto bytes that can never arrive, so this mapping
/// withholds it.
///
/// # Why the withholding sits here and nowhere earlier
///
/// The projection stays **verbatim**. Both legs read it: the download
/// leg recovers the upstream `cksum` from the very same
/// `CargoVersionLine` set, so a line dropped while projecting would turn
/// the download's refusal from "this entry has no cksum" into "upstream
/// has no entry for this version" — a different answer to the client,
/// and the diagnosis lost. Nor can the withholding be a filter in the
/// shared serve pipeline: those filters carry the *universal* reasons
/// (quarantine status, index mode) and operate on the `VersionEntry`
/// spine with the per-format payload opaque to them, which is the
/// property that keeps them format-agnostic. A format's own wire-level
/// verdict about the document it just parsed therefore belongs to the
/// format's source, which is the one layer that holds both the upstream
/// value and the knowledge of what it means.
fn projection_to_entries(
    lines: Vec<CargoVersionLine>,
    crate_name: &str,
    status_map: &std::collections::HashMap<
        String,
        hort_domain::entities::artifact::QuarantineStatus,
    >,
    pubtime_map: &std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
) -> Vec<VersionEntry> {
    let mut entries: Vec<VersionEntry> = Vec::new();
    let mut withheld = 0usize;
    for line in lines {
        // The verdict is the download leg's own rule, called rather than
        // restated: `parse_index_cksum` is what the cargo handler applies
        // to this same field when it verifies a pull-through. A local
        // blankness-or-shape test beside it is how the advertised set and
        // the servable set come to disagree — silently, and in the
        // direction that breaks a build.
        //
        // The refusal reaches exactly one version: every other version of
        // the crate stays advertised, and a crate whose every version is
        // unusable serves an index with no versions rather than an error.
        // One unusable upstream line must not deny the crate.
        if parse_index_cksum(&line.cksum).is_err() {
            withheld += 1;
            continue;
        }
        let status = status_map.get(&line.vers).copied();
        let pubtime = pubtime_map.get(&line.vers).copied();
        entries.push(VersionEntry {
            version: line.vers.clone(),
            status,
            payload: PerVersionPayload::Cargo(CargoVersionPayload {
                name_as_published: line.name,
                vers: line.vers,
                cksum: line.cksum,
                deps: line.deps,
                features: line.features,
                yanked: line.yanked,
                links: line.links,
                rust_version: line.rust_version,
                v: line.v,
                features2: line.features2,
                pubtime,
            }),
        });
    }
    // One aggregated line per request, never one per version: a large
    // crate behind an upstream that publishes no usable checksums would
    // otherwise emit thousands. The enclosing instrumented span carries
    // `repo_key`, so the operator can see which upstream is advertising
    // versions hort will not serve.
    if withheld > 0 {
        tracing::warn!(
            crate_name,
            withheld_versions = withheld,
            "cargo proxy index: upstream advertises versions with no verifiable checksum; withheld from the served index"
        );
    }
    entries
}

// ---------------------------------------------------------------------------
// Virtual (aggregating)
// ---------------------------------------------------------------------------

/// `IndexSource` impl for `RepositoryType::Virtual` (ADR 0031).
///
/// A thin shim over the shared
/// [`VirtualResolutionUseCase::aggregate_virtual_index`](hort_app::use_cases::virtual_resolution::VirtualResolutionUseCase::aggregate_virtual_index):
/// it supplies only the per-member fetch closure (each member's OWN source
/// via [`select_source`], so the member's hosted/proxy gate + parsing apply
/// unchanged). The name-level pinning, authoritative-member merge, and the
/// fail-closed member-failure classification all live once in `hort-app`
/// (the dependency-confusion security boundary) — this crate cannot diverge
/// it. The serve handler runs the unchanged filter pipeline + builder on the
/// result; it never special-cases `Virtual`.
///
/// `resolve_members` yields only non-virtual members, so the
/// `select_source(member)` recursion bottoms out at hosted/proxy.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct VirtualCargoSource;

#[async_trait]
impl IndexSource for VirtualCargoSource {
    #[tracing::instrument(skip(self, ctx, caller), fields(repo_key = %repo.key))]
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        crate_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> Result<IndexSourceOutput, AppError> {
        let entries = ctx
            .virtual_resolution_use_case
            .aggregate_virtual_index(repo, caller, move |member| async move {
                Ok(select_source(&member)
                    .fetch(ctx, &member, crate_name, caller)
                    .await?
                    .entries)
            })
            .await?;

        Ok(IndexSourceOutput {
            entries,
            truncated: false,
        })
    }
}

/// Pick the [`IndexSource`] for `repo` by type — the single dispatch point
/// the serve handler uses (so it stays virtual-agnostic) and that
/// [`VirtualCargoSource`] reuses per member.
pub(crate) fn select_source(repo: &Repository) -> Box<dyn IndexSource> {
    match repo.repo_type {
        RepositoryType::Proxy => Box::new(ProxyCargoSource),
        RepositoryType::Virtual => Box::new(VirtualCargoSource),
        RepositoryType::Hosted | RepositoryType::Staging => Box::new(HostedCargoSource),
    }
}

// ---------------------------------------------------------------------------
// Tests — `projection_to_entries`'s `pubtime` precedence and its withholding
// of versions with no verifiable upstream checksum. Both are pinned directly
// against this pure mapping function rather than through the full HTTP serve
// stack, since neither needs I/O and both tables are exactly this function's
// contract. What the *client* then sees for a withheld-only crate is the
// unified serve handler's own behaviour: a proxy repository with an empty
// entry set serves a 200 with an empty NDJSON body (the empty-set → 404 arm
// in `crate::serve` is hosted/staging/virtual only).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{DateTime, Utc};
    use hort_domain::entities::artifact::QuarantineStatus;

    use super::*;

    /// The entry's cargo payload, or a panic — every entry this module
    /// builds comes out of the cargo mapping.
    fn cargo_payload(entry: &VersionEntry) -> &CargoVersionPayload {
        match &entry.payload {
            PerVersionPayload::Cargo(p) => p,
            _ => panic!("expected Cargo payload"),
        }
    }

    fn line(vers: &str) -> CargoVersionLine {
        CargoVersionLine {
            name: "serde".to_string(),
            vers: vers.to_string(),
            cksum: "a".repeat(64),
            deps: serde_json::json!([]),
            features: serde_json::json!({}),
            yanked: false,
            links: None,
            rust_version: None,
            v: None,
            features2: None,
            pubtime: None,
        }
    }

    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn pubtime_present_in_map_is_used_verbatim() {
        let lines = vec![line("1.0.0")];
        let status_map = HashMap::new();
        let mut pubtime_map = HashMap::new();
        pubtime_map.insert("1.0.0".to_string(), ts("2020-01-01T00:00:00Z"));

        let entries = projection_to_entries(lines, "serde", &status_map, &pubtime_map);
        let PerVersionPayload::Cargo(payload) = &entries[0].payload else {
            panic!("expected Cargo payload");
        };
        assert_eq!(payload.pubtime, Some(ts("2020-01-01T00:00:00Z")));
    }

    #[test]
    fn pubtime_absent_from_map_omits_never_ingested_version() {
        // A version present in the upstream projection but with no row
        // in `pubtime_map` (never locally ingested) MUST serve no
        // `pubtime` — hort has no knowledge and must not invent one.
        let lines = vec![line("9.9.9")];
        let status_map = HashMap::new();
        let pubtime_map = HashMap::new();

        let entries = projection_to_entries(lines, "serde", &status_map, &pubtime_map);
        let PerVersionPayload::Cargo(payload) = &entries[0].payload else {
            panic!("expected Cargo payload");
        };
        assert!(payload.pubtime.is_none());
    }

    #[test]
    fn line_own_pubtime_field_is_never_consulted() {
        // `CargoVersionLine::pubtime` is upstream-sourced forward-compat
        // scaffolding (no real cargo upstream serves it today); the
        // proxy source's served `pubtime` comes exclusively from
        // `pubtime_map` (hort's own artifact record), even when the
        // line itself carries a value.
        let mut l = line("1.0.0");
        l.pubtime = Some(ts("1999-01-01T00:00:00Z"));
        let status_map = HashMap::new();
        let pubtime_map = HashMap::new();

        let entries = projection_to_entries(vec![l], "serde", &status_map, &pubtime_map);
        let PerVersionPayload::Cargo(payload) = &entries[0].payload else {
            panic!("expected Cargo payload");
        };
        assert!(
            payload.pubtime.is_none(),
            "the line's own pubtime must never leak through when the version \
             is absent from pubtime_map (never-ingested)"
        );
    }

    #[test]
    fn multiple_versions_each_resolve_independently() {
        let lines = vec![line("1.0.0"), line("1.1.0"), line("1.2.0")];
        let status_map = HashMap::new();
        let mut pubtime_map = HashMap::new();
        pubtime_map.insert("1.0.0".to_string(), ts("2020-01-01T00:00:00Z"));
        // "1.1.0" deliberately absent — never-ingested.
        pubtime_map.insert("1.2.0".to_string(), ts("2022-06-15T00:00:00Z"));

        let entries = projection_to_entries(lines, "serde", &status_map, &pubtime_map);
        let pubtimes: Vec<Option<DateTime<Utc>>> = entries
            .iter()
            .map(|e| match &e.payload {
                PerVersionPayload::Cargo(p) => p.pubtime,
                _ => panic!("expected Cargo payload"),
            })
            .collect();
        assert_eq!(
            pubtimes,
            vec![
                Some(ts("2020-01-01T00:00:00Z")),
                None,
                Some(ts("2022-06-15T00:00:00Z")),
            ]
        );
    }

    /// A cksum with the right charset and the wrong length.
    fn short_cksum() -> String {
        "a".repeat(63)
    }

    /// A cksum with the right length and a byte outside lowercase hex.
    fn non_hex_cksum() -> String {
        "g".repeat(64)
    }

    #[test]
    fn only_the_version_with_a_verifiable_cksum_is_advertised() {
        // The three shapes the shared rule separates: a valid digest, the
        // empty string an upstream that omitted the field projects to, and
        // two malformed values. An `is_empty()` test would admit the last
        // two, which the download leg refuses.
        let valid = line("1.0.0");
        let mut omitted = line("1.1.0");
        omitted.cksum = String::new();
        let mut short = line("1.2.0");
        short.cksum = short_cksum();
        let mut non_hex = line("1.3.0");
        non_hex.cksum = non_hex_cksum();

        let entries = projection_to_entries(
            vec![valid, omitted, short, non_hex],
            "serde",
            &HashMap::new(),
            &HashMap::new(),
        );

        let served: Vec<&str> = entries.iter().map(|e| e.version.as_str()).collect();
        assert_eq!(
            served,
            vec!["1.0.0"],
            "exactly the version whose cksum the download leg would accept"
        );
    }

    #[test]
    fn every_version_unusable_serves_an_empty_set_and_not_an_error() {
        // The honest outcome of a per-version refusal, deliberately not
        // special-cased: the crate's index comes out with no versions.
        let mut a = line("1.0.0");
        a.cksum = String::new();
        let mut b = line("2.0.0");
        b.cksum = short_cksum();

        let entries = projection_to_entries(vec![a, b], "serde", &HashMap::new(), &HashMap::new());

        assert!(entries.is_empty(), "no versions, and no error");
    }

    #[test]
    fn an_upper_case_cksum_stays_advertised_because_the_download_leg_accepts_it() {
        // The shared rule lower-cases before judging shape, so the pull
        // path verifies this version's bytes — and an index that withheld
        // it would under-advertise something hort will serve. Inclusion is
        // the only decision made here: the advertised value stays the
        // verbatim upstream one.
        let mut l = line("1.0.0");
        l.cksum = "A".repeat(64);

        let entries = projection_to_entries(vec![l], "serde", &HashMap::new(), &HashMap::new());

        assert_eq!(entries.len(), 1);
        let PerVersionPayload::Cargo(payload) = &entries[0].payload else {
            panic!("expected Cargo payload");
        };
        assert_eq!(payload.cksum, "A".repeat(64));
    }

    #[test]
    fn withholding_a_version_does_not_shift_what_its_siblings_carry() {
        // Each surviving entry keeps its OWN status and pubtime: the
        // hydration is a per-version lookup, never a positional walk that
        // a withheld line could slide.
        let valid_low = line("1.0.0");
        let mut unusable = line("1.1.0");
        unusable.cksum = String::new();
        let valid_high = line("1.2.0");

        let mut status_map = HashMap::new();
        status_map.insert("1.2.0".to_string(), QuarantineStatus::Quarantined);
        let mut pubtime_map = HashMap::new();
        pubtime_map.insert("1.0.0".to_string(), ts("2020-01-01T00:00:00Z"));
        // The withheld version's own row, which no surviving entry may pick up.
        pubtime_map.insert("1.1.0".to_string(), ts("2021-01-01T00:00:00Z"));
        pubtime_map.insert("1.2.0".to_string(), ts("2022-06-15T00:00:00Z"));

        let entries = projection_to_entries(
            vec![valid_low, unusable, valid_high],
            "serde",
            &status_map,
            &pubtime_map,
        );

        let served: Vec<&str> = entries.iter().map(|e| e.version.as_str()).collect();
        assert_eq!(served, vec!["1.0.0", "1.2.0"]);
        assert_eq!(entries[0].status, None);
        assert_eq!(entries[1].status, Some(QuarantineStatus::Quarantined));
        assert_eq!(
            cargo_payload(&entries[0]).pubtime,
            Some(ts("2020-01-01T00:00:00Z"))
        );
        assert_eq!(
            cargo_payload(&entries[1]).pubtime,
            Some(ts("2022-06-15T00:00:00Z"))
        );
    }

    #[test]
    fn the_projection_keeps_the_line_the_serve_mapping_withholds() {
        // The placement property the withholding rests on. The download
        // leg recovers the upstream cksum from this same projection, so
        // the projector must keep the entry: its refusal is then "this
        // entry has no cksum" rather than "upstream has no entry for this
        // version", which is a different answer to the client.
        use hort_domain::ports::upstream_proxy::MetadataProjector as _;
        use hort_formats::cargo::projection::CargoSparseIndexProjector;

        let body = br#"{"name":"serde","vers":"1.0.0","deps":[],"features":{},"yanked":false}"#;
        let projection = CargoSparseIndexProjector::new()
            .project(std::io::Cursor::new(body))
            .expect("a line without cksum still projects");

        assert_eq!(projection.len(), 1, "the projection stays verbatim");
        assert_eq!(
            projection[0].cksum, "",
            "an omitted cksum projects to the empty default"
        );

        let entries = projection_to_entries(projection, "serde", &HashMap::new(), &HashMap::new());
        assert!(entries.is_empty(), "the serve mapping withholds it");
    }
}
