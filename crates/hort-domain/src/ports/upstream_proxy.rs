//! Upstream proxy port.
//!
//! Streams blob/manifest content from a configured upstream registry
//! into the local CAS. Format-agnostic at the trait level — OCI is
//! the first consumer (multi-upstream pull-through), but any format
//! with proxy semantics shares the same shape.
//!
//! # Why a port
//!
//! Same rationale as Item 9's [`crate::ports::upstream_resolver`]:
//! the implementation lives in a dedicated adapter crate
//! (`hort-adapters-upstream-http`) so `reqwest` stays off the
//! `hort-http-oci` dependency edge. The trait is in `hort-domain` so
//! `AppContext` can hold it as `Arc<dyn UpstreamProxy>` without
//! pinning either side to a concrete impl.
//!
//! # Streaming
//!
//! [`UpstreamProxy::fetch_blob`] returns an async byte stream — OCI
//! blobs can be gigabytes, so the implementation MUST stream to the
//! local CAS rather than buffer. Manifest payloads are small (KB)
//! and returned as `Vec<u8>` for simplicity.
//!
//! See `docs/architecture/how-to/oci-pull-through.md` and
//! ADR 0006 (mandatory upstream verification).

use std::path::PathBuf;
use std::pin::Pin;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::Stream;

use crate::error::{DomainError, DomainResult};
use crate::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping;

use super::BoxFuture;

/// Async byte stream returned by [`UpstreamProxy::fetch_blob`].
///
/// Concrete adapters typically use a `reqwest::Response::bytes_stream`
/// wrapped to map errors. The lifetime is `'static` because the
/// stream may outlive the call (held by the consumer for the
/// duration of a multi-GB CAS write).
pub type BlobStream = Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static>>;

/// Manifest fetch result: `(bytes, media_type)`.
///
/// `media_type` is the upstream-declared `Content-Type` (e.g.
/// `application/vnd.oci.image.manifest.v1+json`). Callers verify it
/// matches what they expect; the proxy itself does no validation
/// beyond returning what the upstream sent.
#[derive(Debug, Clone)]
pub struct ManifestFetch {
    pub bytes: Vec<u8>,
    pub media_type: String,
    /// Upstream-declared content digest header (`Docker-Content-Digest`),
    /// when present. The pull handler uses this to verify
    /// the manifest hash matches before populating the local CAS.
    pub declared_digest: Option<String>,
    /// Parsed `Last-Modified` response header (RFC 7231 §7.1.1.2),
    /// surfaced as an `Option<DateTime<Utc>>` so format crates stay
    /// adapter-free — the raw header lives in the HTTP adapter; the
    /// format crate sees only the parsed value. Absent / unparseable
    /// header → `None`.
    ///
    /// **Why on the manifest envelope too:** `Last-Modified` was
    /// originally surfaced only on the [`BlobFetch`] /
    /// [`ArtifactFetch`] envelopes (commit `51d03d56`). The OCI manifest
    /// path was left at `None`, which left a real operator-visible gap:
    /// under `trust_upstream_publish_time = true`,
    /// blobs would release on their upstream age while manifests stayed
    /// anchored on `ingested_at` — `docker pull` would 503 on the
    /// manifest while every layer/config blob is already released.
    /// Surfacing it here closes the gap symmetrically. Best-effort by
    /// the same contract as the other envelopes.
    pub last_modified: Option<DateTime<Utc>>,
}

/// Artifact fetch result: a streamed body plus optional response
/// metadata. Returned from [`UpstreamProxy::fetch_artifact`].
///
/// `last_modified` is the parsed `Last-Modified` response header
/// (RFC 7231 §7.1.1.2), surfaced as an `Option<DateTime<Utc>>` so
/// format crates stay adapter-free — the raw header lives in the
/// HTTP adapter; the format crate sees only the parsed value.
/// Absent / unparseable header → `None`. The publish-anchored
/// quarantine window (cargo `.crate` tarball) consumes this for
/// `VerifiedIngestRequest.upstream_published_at`.
pub struct ArtifactFetch {
    pub stream: BlobStream,
    pub last_modified: Option<DateTime<Utc>>,
}

/// Blob fetch result: a streamed body plus optional response
/// metadata. Returned from [`UpstreamProxy::fetch_blob`].
///
/// `declared_digest` is the upstream-declared `Docker-Content-Digest`
/// header (when present) — the pull handler cross-checks against
/// what it expected. `last_modified` is the parsed `Last-Modified`
/// response header (RFC 7231 §7.1.1.2). Absent / unparseable header
/// → `None`. The publish-anchored quarantine window (OCI config +
/// layer blobs) consumes this for
/// `VerifiedIngestRequest.upstream_published_at`.
pub struct BlobFetch {
    pub stream: BlobStream,
    pub declared_digest: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
}

/// A single OCI referrer descriptor (ADR 0027).
///
/// Returned by [`UpstreamProxy::fetch_referrers`] — one entry per
/// `manifests[]` descriptor in the upstream OCI image index served by
/// the Referrers API (`GET /v2/<name>/referrers/<digest>`), or the
/// single descriptor synthesised from the cosign `.sig` tag-scheme
/// fallback. The caller selects descriptors whose `artifact_type` (or
/// `media_type`) is the Sigstore bundle media type, then fetches the
/// referrer manifest + its bundle blob via
/// [`UpstreamProxy::fetch_manifest`] / [`UpstreamProxy::fetch_blob`].
///
/// No `ReferrersIndex` wrapper: the design (§3.3) deliberately returns
/// `Vec<ReferrerDescriptor>` directly — a single-`Vec` newtype carries
/// no behaviour and back-compat is not required pre-v1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferrerDescriptor {
    /// The referrer manifest's content digest (`sha256:<hex>`), used as
    /// the `reference` argument to [`UpstreamProxy::fetch_manifest`].
    pub digest: String,
    /// The descriptor's `mediaType` (the manifest media type — e.g.
    /// `application/vnd.oci.image.manifest.v1+json`).
    pub media_type: String,
    /// The descriptor's `artifactType` when present — for a Sigstore
    /// bundle referrer this carries the bundle media type the caller
    /// filters on. `None` when the upstream omits it (some registries
    /// do, in which case the caller falls back to inspecting the
    /// fetched manifest).
    pub artifact_type: Option<String>,
}

/// Outbound port: fetch artifact content from an upstream registry.
///
/// Method signatures are deliberately format-agnostic. OCI blobs
/// reach upstream as `<base>/v2/<name>/blobs/<digest>`; manifests as
/// `<base>/v2/<name>/manifests/<reference>`. Adapter implementations
/// own URL composition + auth strategy resolution.
pub trait UpstreamProxy: Send + Sync {
    /// Stream a blob's bytes from `upstream_name@digest` on the
    /// upstream registry described by `mapping`. Returns a
    /// [`BlobFetch`] envelope: the byte stream, the upstream-declared
    /// `Docker-Content-Digest` (when present) so callers can cross-check
    /// before committing to local CAS, and the parsed `Last-Modified`
    /// response header (OCI config + layer
    /// blob `upstream_published_at` hint).
    fn fetch_blob(
        &self,
        mapping: RepositoryUpstreamMapping,
        upstream_name: String,
        digest: String,
    ) -> BoxFuture<'_, DomainResult<BlobFetch>>;

    /// Fetch a manifest by reference (tag or digest) from
    /// `upstream_name` on the upstream registry.
    ///
    /// `accept` carries the media types the caller is willing to
    /// accept (RFC 7231 §5.3.2 — comma-joined into the upstream
    /// request's `Accept` header). Empty list → adapter falls back
    /// to its default of OCI manifest + Docker v2 manifest.
    ///
    /// Returns a [`ManifestFetchOutcome`] carrying a
    /// [`CachedBodyHandle`] (the body lives on disk; consumers run
    /// per-format projection via the `project_cached` helper in
    /// `hort-formats`) plus the response-header surface
    /// (`media_type`, `declared_digest`, `last_modified`). Method
    /// stays non-generic so the trait remains dyn-compatible.
    fn fetch_manifest(
        &self,
        mapping: RepositoryUpstreamMapping,
        upstream_name: String,
        reference: String,
        accept: Vec<String>,
    ) -> BoxFuture<'_, DomainResult<ManifestFetchOutcome>>;

    /// Stream a generic artifact body — PyPI wheel/sdist, Cargo
    /// `.crate`, npm tarball. Format-agnostic; the format crate
    /// composes the path (ADR 0006).
    ///
    /// `path` accepts EITHER a mapping-relative path (composed onto
    /// `mapping.upstream_url`) OR an absolute URL — used as-is when it
    /// starts with `https://` or `http://`. The dual mode is required
    /// because PyPI publishes file URLs on a different host
    /// (`files.pythonhosted.org`) than the index (`pypi.org`) and
    /// Cargo splits index/download hosts via `<index>/config.json`.
    ///
    /// **SSRF defence (mandatory):** the adapter resolves an absolute
    /// URL's host and refuses to fetch when it resolves to loopback
    /// (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`,
    /// `fe80::/10`), or RFC 1918 private ranges. Refusal returns
    /// [`crate::error::DomainError::Validation`]. Format handlers
    /// validate their expected host patterns at the inbound-HTTP
    /// boundary; the adapter is defence-in-depth.
    ///
    /// No body cap — artifacts are large by design.
    ///
    /// Returns an [`ArtifactFetch`] envelope: the byte stream and the
    /// parsed `Last-Modified` response header (cargo `.crate`
    /// tarball `upstream_published_at` hint).
    fn fetch_artifact(
        &self,
        mapping: RepositoryUpstreamMapping,
        path: String,
    ) -> BoxFuture<'_, DomainResult<ArtifactFetch>>;

    /// Fetch a small upstream metadata payload.
    /// Used by every non-OCI format to retrieve the body that the
    /// format handler's `parse_upstream_checksum` decodes (npm
    /// packument, PyPI JSON, Cargo sparse-index NDJSON, Maven
    /// `.sha256` sidecar). See ADR 0006.
    ///
    /// `accept` mirrors [`fetch_manifest`](Self::fetch_manifest):
    /// empty → no `Accept` header (defer to upstream default);
    /// non-empty → comma-joined per RFC 7231 §5.3.2. Landing the
    /// parameter on the first definition avoids a second port-shape
    /// PR for PyPI's PEP 691 negotiation in 17.2.
    ///
    /// Returns a [`MetadataFetchOutcome`] carrying a
    /// [`CachedBodyHandle`]; consumers run per-format projection via
    /// the `project_cached` helper in `hort-formats`. Method stays
    /// non-generic so the trait remains dyn-compatible (ADR 0026).
    fn fetch_metadata(
        &self,
        mapping: RepositoryUpstreamMapping,
        path: String,
        accept: Vec<String>,
    ) -> BoxFuture<'_, DomainResult<MetadataFetchOutcome>>;

    /// Fetch the OCI referrers of `digest` on `upstream_name`
    /// (ADR 0027).
    ///
    /// OCI Distribution Spec v1.1 §referrers-api:
    /// `GET /v2/<name>/referrers/<digest>` returns an OCI image index
    /// whose `manifests[]` are the referrer descriptors. The adapter
    /// falls back to the cosign tag scheme
    /// `GET /v2/<name>/manifests/sha256-<digest>.sig` (the `sha256:`
    /// separator replaced with `sha256-`) when the upstream returns
    /// 404 / unsupported for the Referrers API (e.g. Docker Hub legacy),
    /// synthesising a single descriptor from the `.sig` manifest. When
    /// neither the Referrers API nor the tag scheme yields a referrer,
    /// the result is `Ok(Vec::new())`.
    ///
    /// Returns the descriptors only; the caller fetches the chosen
    /// referrer manifests + bundle blobs via
    /// [`fetch_manifest`](Self::fetch_manifest) /
    /// [`fetch_blob`](Self::fetch_blob).
    ///
    /// **Default impl returns `Ok(Vec::new())`** — "no referrers", the
    /// safe default. Only the real `hort-adapters-upstream-http` adapter
    /// and seedable test mocks override it; every other mock inherits
    /// this default unchanged so the additive method needs no edit to
    /// existing impls.
    fn fetch_referrers(
        &self,
        mapping: RepositoryUpstreamMapping,
        upstream_name: String,
        digest: String,
    ) -> BoxFuture<'_, DomainResult<Vec<ReferrerDescriptor>>> {
        let _ = (mapping, upstream_name, digest);
        Box::pin(async { Ok(Vec::new()) })
    }
}

// ---------------------------------------------------------------------------
// Streaming metadata projection (ADR 0026): types + projector trait
// ---------------------------------------------------------------------------

/// Handle to a cached upstream-body file. Returned by `fetch_metadata`
/// / `fetch_manifest` on either outcome; consumers open `path` (via the
/// `project_cached` helper in `hort-formats`) and stream-parse the body
/// without re-fetching upstream.
///
/// `key` is a format-local identifier (the cache layer keys on it
/// for TTL eviction). `path` is the
/// concrete filesystem path to the committed body. `byte_length` and
/// `fetched_at` are recorded for cache-freshness checks and observability.
#[derive(Debug, Clone)]
pub struct CachedBodyHandle {
    pub key: String,
    pub path: PathBuf,
    pub fetched_at: DateTime<Utc>,
    pub byte_length: u64,
}

/// Outcome of [`UpstreamProxy::fetch_metadata`]. No projection — the
/// body lives on disk at `cache_handle.path`; consumers project from
/// it via `project_cached` in `hort-formats`. `last_modified` is the
/// parsed `Last-Modified` response header
/// (`upstream_published_at` hint for npm / PyPI / Cargo).
#[derive(Debug, Clone)]
pub struct MetadataFetchOutcome {
    pub cache_handle: Option<CachedBodyHandle>,
    pub bytes_read: u64,
    pub last_modified: Option<DateTime<Utc>>,
}

/// Outcome of [`UpstreamProxy::fetch_manifest`]. Mirrors the legacy
/// `ManifestFetch` envelope's header surface — `media_type`,
/// `declared_digest`, and `last_modified` are all consumed downstream
/// (OCI digest verification, content-type dispatch,
/// `trust_upstream_publish_time`). No projection — same shape pattern
/// as [`MetadataFetchOutcome`].
#[derive(Debug, Clone)]
pub struct ManifestFetchOutcome {
    pub cache_handle: Option<CachedBodyHandle>,
    pub bytes_read: u64,
    pub media_type: Option<String>,
    pub declared_digest: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
}

/// Format-supplied streaming projector. Sync `Read` because the
/// `project_cached` helper opens the cache file synchronously and the
/// projector runs under `tokio::task::spawn_blocking`. Per-format
/// impls (Items 3–6) declare DTOs that omit unwanted fields; serde's
/// `deserialize_ignored_any` consumes skipped JSON tokens without
/// allocating, bounding memory by the projected shape regardless of
/// upstream body size.
///
/// Name kept generic ("Metadata") even though OCI manifests use it —
/// the shape (typed streaming JSON projection from a `Read` source)
/// is identical, and inventing a separate `ManifestProjector` trait
/// for the same shape just doubles the surface.
pub trait MetadataProjector: Send + 'static {
    type Projection: Send + 'static;
    fn project<R: std::io::Read>(self, reader: R) -> DomainResult<Self::Projection>;
}

/// Compile-through projector: reads the cached body into a `Vec<u8>`.
/// Used by Item 1's caller-side migration before per-format projectors
/// (Items 3–6) land. Lives in `hort-domain` because every consumer
/// needs it during the transition and it has no I/O dependency (it
/// just calls `Read::read_to_end` on whatever reader the helper hands
/// it).
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityProjector;

impl MetadataProjector for IdentityProjector {
    type Projection = Vec<u8>;
    fn project<R: std::io::Read>(self, mut reader: R) -> DomainResult<Self::Projection> {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| DomainError::Validation(format!("failed to read cached body: {e}")))?;
        Ok(buf)
    }
}

/// `std::io::Read` wrapper that tracks
/// cumulative bytes consumed. Used by per-format streaming projectors
/// to sample `bytes_consumed()` inside `Visitor::visit_map`'s
/// loop and trip `DomainError::Validation` when a single version-object
/// (npm `versions{}` value, PyPI `releases{}` value, etc.) exceeds the
/// configured per-value cap (default 2 MiB). See ADR 0026.
///
/// Pure Rust, no I/O: `CountingReader` consumes whatever reader the
/// `project_cached` helper hands it. Lives in `hort-domain` because
/// the trait + helpers do and the counter is purely structural — no
/// dependency direction is forced by its location.
///
/// The actual sampling happens inside the
/// per-format projectors for npm and PyPI. The Cargo (NDJSON)
/// and OCI-manifest projectors don't enforce the cap — Cargo
/// is line-bounded by the sparse-index shape, OCI manifests are
/// spec-bounded and never grow per-value-object large.
pub struct CountingReader<R> {
    inner: R,
    bytes_consumed: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl<R> CountingReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_consumed: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Cumulative bytes the wrapped reader has produced. Per-format
    /// projectors sample this before/after `next_value::<…>()` to
    /// measure a single map-entry's value-size.
    pub fn bytes_consumed(&self) -> u64 {
        self.bytes_consumed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Shared handle to the byte counter — used by per-format
    /// projectors that consume the reader (handing ownership to
    /// `serde_json::Deserializer::from_reader`) but still need to
    /// sample the count from inside a `Visitor::visit_map` loop.
    pub fn counter(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        std::sync::Arc::clone(&self.bytes_consumed)
    }
}

impl<R: std::io::Read> std::io::Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_consumed
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::repository_upstream_mapping_repository::UpstreamAuth;
    use chrono::Utc;
    use uuid::Uuid;

    /// Compile-time assertion that the port is dyn-compatible —
    /// held as `Arc<dyn UpstreamProxy>` on `AppContext`.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn UpstreamProxy>();
    }

    fn dummy_mapping() -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path_prefix: "docker".into(),
            upstream_url: "https://registry.example".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: crate::entities::managed_by::ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// An impl that only relies on the default `fetch_referrers` impl —
    /// all other methods are unimplemented (never called by the test).
    struct DefaultReferrersProxy;

    impl UpstreamProxy for DefaultReferrersProxy {
        fn fetch_blob(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _upstream_name: String,
            _digest: String,
        ) -> BoxFuture<'_, DomainResult<BlobFetch>> {
            unreachable!("not exercised")
        }
        fn fetch_manifest(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _upstream_name: String,
            _reference: String,
            _accept: Vec<String>,
        ) -> BoxFuture<'_, DomainResult<ManifestFetchOutcome>> {
            unreachable!("not exercised")
        }
        fn fetch_artifact(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _path: String,
        ) -> BoxFuture<'_, DomainResult<ArtifactFetch>> {
            unreachable!("not exercised")
        }
        fn fetch_metadata(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _path: String,
            _accept: Vec<String>,
        ) -> BoxFuture<'_, DomainResult<MetadataFetchOutcome>> {
            unreachable!("not exercised")
        }
        // deliberately does NOT override fetch_referrers — inherits the default.
    }

    /// An impl that overrides `fetch_referrers` with a seeded value.
    struct OverridingReferrersProxy(Vec<ReferrerDescriptor>);

    impl UpstreamProxy for OverridingReferrersProxy {
        fn fetch_blob(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _upstream_name: String,
            _digest: String,
        ) -> BoxFuture<'_, DomainResult<BlobFetch>> {
            unreachable!("not exercised")
        }
        fn fetch_manifest(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _upstream_name: String,
            _reference: String,
            _accept: Vec<String>,
        ) -> BoxFuture<'_, DomainResult<ManifestFetchOutcome>> {
            unreachable!("not exercised")
        }
        fn fetch_artifact(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _path: String,
        ) -> BoxFuture<'_, DomainResult<ArtifactFetch>> {
            unreachable!("not exercised")
        }
        fn fetch_metadata(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _path: String,
            _accept: Vec<String>,
        ) -> BoxFuture<'_, DomainResult<MetadataFetchOutcome>> {
            unreachable!("not exercised")
        }
        fn fetch_referrers(
            &self,
            _mapping: RepositoryUpstreamMapping,
            _upstream_name: String,
            _digest: String,
        ) -> BoxFuture<'_, DomainResult<Vec<ReferrerDescriptor>>> {
            let seeded = self.0.clone();
            Box::pin(async move { Ok(seeded) })
        }
    }

    /// The default `fetch_referrers` impl returns an empty vec — the
    /// "no referrers" safe default — under dyn dispatch.
    #[tokio::test]
    async fn fetch_referrers_default_returns_empty_under_dyn_dispatch() {
        let proxy: &dyn UpstreamProxy = &DefaultReferrersProxy;
        let out = proxy
            .fetch_referrers(dummy_mapping(), "library/nginx".into(), "sha256:abc".into())
            .await
            .expect("default fetch_referrers");
        assert!(out.is_empty());
    }

    /// An overriding impl returns the seeded descriptors under dyn
    /// dispatch — proving the method is a real override point.
    #[tokio::test]
    async fn fetch_referrers_override_returns_seeded_descriptors_under_dyn_dispatch() {
        let seeded = vec![ReferrerDescriptor {
            digest: "sha256:sig".into(),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            artifact_type: Some("application/vnd.dev.sigstore.bundle.v0.3+json".into()),
        }];
        let proxy: &dyn UpstreamProxy = &OverridingReferrersProxy(seeded.clone());
        let out = proxy
            .fetch_referrers(dummy_mapping(), "library/nginx".into(), "sha256:abc".into())
            .await
            .expect("override fetch_referrers");
        assert_eq!(out, seeded);
    }
}
