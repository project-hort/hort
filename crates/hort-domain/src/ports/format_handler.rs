use bytes::Bytes;

use crate::error::{DomainError, DomainResult};
use crate::types::checksum::UpstreamPublishedChecksum;
use crate::types::{ArtifactCoords, PayloadAccess, Sbom};

/// How a format handler wants ingest to persist its payload metadata.
///
/// Declared by [`FormatHandler::metadata_strategy`] (default `Inline`).
/// This enum is the wire between the handler's declaration and the
/// ingest-path's routing logic; the split-payload design is described
/// in `docs/architecture/explanation/format-handlers.md`.
///
/// - [`Inline`](Self::Inline) — the full payload rides in the event
///   and the 1:1 projection row. Appropriate for formats whose p99
///   metadata fits comfortably inside the 1 MB event-payload ceiling.
/// - [`HashReference`](Self::HashReference) — if the serialised payload
///   exceeds `inline_threshold_bytes`, the full payload is written to
///   CAS and the event + projection row carry the handler-extracted
///   summary plus a `ContentHash` pointing at the blob. Below the
///   threshold, behaviour is identical to `Inline` — no point paying
///   a CAS round-trip for a small packument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataStrategy {
    Inline,
    HashReference { inline_threshold_bytes: usize },
}

/// Outbound port for format-specific artifact parsing.
///
/// Synchronous and stateless — a pure strategy pattern, not an I/O port.
/// Each format (PyPI, npm, Maven, etc.) provides one implementation.
///
/// Upload parsing is NOT in this trait — it is tightly coupled to HTTP
/// mechanics (multipart, content negotiation, path patterns) and belongs
/// in the axum handler layer.
pub trait FormatHandler: Send + Sync {
    /// Format key (e.g., `"pypi"`, `"npm"`, `"maven"`).
    fn format_key(&self) -> &str;

    /// Parse a download request path into artifact coordinates.
    fn parse_download_path(&self, path: &str) -> DomainResult<ArtifactCoords>;

    /// Normalize a package name for matching.
    ///
    /// Format-specific (e.g., PyPI: `[-_.]+` → `-`, lowercase per PEP 503).
    /// The normalized form is stored in `Artifact.name` at ingest time.
    ///
    /// **`normalize_name`'s output for a given input is part of the
    /// format's wire contract.** Changing it across plugin versions —
    /// deliberately, by "bug fix", or via WASM hot-swap — without a
    /// declared migration path is a breaking change on par with a schema
    /// migration: artifacts ingested under the old algorithm become
    /// unreachable via primary lookups, even though their bytes, rows,
    /// and event history remain intact.
    ///
    /// A query-side safety net (`Artifact.name_as_published` +
    /// `ArtifactUseCase::list_by_raw_name` fallback) recovers drift-era
    /// artifacts on lookup. A planned loader-side contract refuses a
    /// plugin swap whose `normalize_name` output differs from the
    /// currently-active algorithm without operator opt-in. See
    /// `docs/architecture/explanation/format-handlers.md`
    /// §"Normalisation stability".
    fn normalize_name(&self, name: &str) -> String;

    /// THE single logical-projection-path constructor — the inverse of the
    /// (name, version, filename) extraction
    /// [`parse_download_path`](Self::parse_download_path) performs.
    ///
    /// Embeds `self.normalize_name(name)` as the protocol-canonical name
    /// segment, then assembles the format's path shape. Both
    /// `parse_download_path` (read) and every write-site (publish,
    /// on-demand pull, prefetch leaf) call it so read and write can never
    /// diverge — the projection is keyed on `(repository_id, coords.path)`,
    /// so a write that produces a different string than the read-side
    /// lookup yields an unreachable row.
    ///
    /// `filename` is REQUIRED for multi-distribution formats (pypi: one
    /// `(name, version)` maps to many distribution files) and IGNORED by
    /// single-artifact formats (npm/cargo derive the filename from
    /// name+version). The filename is embedded VERBATIM — it is the real
    /// upstream artifact filename, not an identity segment.
    ///
    /// Default impl returns `Err(DomainError::Validation(...))` so a format
    /// without a logical-path projection (OCI is digest/descriptor-based)
    /// fails LOUDLY rather than writing a wrong path — fail-safe.
    fn build_artifact_logical_path(
        &self,
        name: &str,
        version: &str,
        filename: Option<&str>,
    ) -> DomainResult<String> {
        let _ = (name, version, filename);
        Err(DomainError::Validation(
            "build_artifact_logical_path not supported for this format".into(),
        ))
    }

    /// The registry's **registration-uniqueness key** for `name`, if the
    /// registry enforces uniqueness under a fold the *lookup* path does NOT
    /// apply. `None` (the default) = the format permits any names its
    /// `normalize_name` keeps distinct, so no extra publish-time check is
    /// needed; `Some(key)` = a second artifact whose `collision_key` equals
    /// `key` but whose `normalize_name` differs is a registration collision
    /// the publish path must reject.
    ///
    /// This is DISTINCT from `normalize_name` (the lookup/storage/path key)
    /// and must not be conflated with it. cargo is the only v1 format that
    /// needs it: crates.io forbids publishing `foo_bar` when `foo-bar`
    /// exists (case- AND `-`/`_`-folded uniqueness), yet the cargo index
    /// *lookup* path preserves separators (`normalize_name` lowercases
    /// only). npm (case-sensitive) and pypi (PEP 503 already collapses
    /// `[-_.]` at the identity layer) return `None`. See the
    /// `collision_key` section of
    /// `docs/architecture/how-to/add-a-format-handler.md`.
    fn collision_key(&self, name: &str) -> Option<String> {
        let _ = name;
        None
    }

    /// Format-declared expected maximum serialized length (in bytes) of
    /// upload-payload metadata (`IngestRequest.payload_metadata`).
    ///
    /// The middle layer of the three-layer size model:
    ///
    /// 1. DB absolute ceiling — 1 MB `CHECK` on the event-payload column.
    /// 2. **Format-declared expected max** — this method. The envelope the
    ///    format itself considers reasonable for compliant metadata.
    /// 3. Operator override — per-tenant tightening via
    ///    `METADATA_CAP_BYTES_<FORMAT>`, checked against this value as the
    ///    fallback when the operator did not configure an override.
    ///
    /// Invariant: `operator_override ≤ format_declared ≤ db_ceiling`.
    /// The cap is enforced in the outer `IngestUseCase::ingest` method
    /// before any I/O — a violation emits `hort_ingest_total` with
    /// `result="metadata_too_large"` and returns an `AppError` without
    /// invoking `classify_ingest_error`.
    ///
    /// The default (64 KB) is a conservative fallback for format handlers
    /// that have not yet declared a specific envelope. The compiled-in
    /// handlers override with envelopes calibrated against real-world
    /// corpus measurements (raised for HashReference formats so the
    /// pre-dispatch cap does not pre-empt the split decision):
    ///
    /// | Format | Override | Source |
    /// |---|---|---|
    /// | PyPI  | 128 KB | corpus measurement (max 109.9 KB) |
    /// | Cargo | 64 KB  | corpus measurement (max 53.8 KB)  |
    /// | npm   | 5 MB   | HashReference ceiling, NOT the inline storage size. npm's inline split threshold lives on `metadata_strategy` (256 KB); this value is the pathological-input cap, sized above the measured 1.37 MB max and below the 10 MB `HORT_METADATA_BLOB_MAX_SIZE` safety net. |
    fn metadata_expected_max_bytes(&self) -> usize {
        64 * 1024
    }

    /// Declares how ingest persists this format's payload metadata.
    ///
    /// Default is [`MetadataStrategy::Inline`] — the full payload rides
    /// in the event and the `artifact_metadata` row. Formats whose p99
    /// payload occasionally exceeds the 1 MB event-payload ceiling
    /// (notably npm) override to
    /// [`MetadataStrategy::HashReference`] with a per-format threshold
    /// measured against real-world corpora.
    fn metadata_strategy(&self) -> MetadataStrategy {
        MetadataStrategy::Inline
    }

    /// When [`metadata_strategy`](Self::metadata_strategy) is
    /// `HashReference`, extract the subset of `full` that must remain
    /// inline for index/listing rendering (e.g. PyPI
    /// `pkg_info.requires_python`, npm `dist-tags` and a minimal
    /// per-version record). Handler-defined — drive from the real
    /// consumers of the format's index/listing responses.
    ///
    /// Default is the identity function, which matches `Inline`
    /// handlers — the ingest path never invokes this method for them.
    /// `HashReference` handlers must override.
    fn extract_metadata_summary(&self, full: &serde_json::Value) -> serde_json::Value {
        full.clone()
    }

    /// Classify an uploaded file as a member of an artifact group.
    ///
    /// Returns `Some(GroupMembership)` when the file belongs to a group;
    /// returns `None` when the format has no group structure or the
    /// uploaded file is a single-file artifact (PyPI sdist, Cargo
    /// `.crate`). The ingest path consults this method AFTER storage
    /// commit to either create the group (if new) or attach the file to
    /// an existing group. See the refs/groups section of
    /// `docs/architecture/explanation/domain-model.md`.
    ///
    /// Default implementation returns `None` — formats that do not use
    /// groups need not override. Formats WITH groups override and return
    /// the canonical group coords plus the role of the uploaded file.
    ///
    /// **Canonicalisation contract:** [`GroupMembership::group_coords`]
    /// MUST carry ONLY the identity fields of [`ArtifactCoords`] —
    /// `name`, `name_as_published`, `version`, `format`. Per-file fields
    /// (`path`, `metadata`) MUST be their type-default values.
    /// Divergence creates duplicate groups — see the `ArtifactGroup`
    /// entity docstring.
    fn classify_group_member(
        &self,
        coords: &ArtifactCoords,
        path: &str,
    ) -> Option<GroupMembership> {
        let _ = (coords, path);
        None
    }

    /// Whether this format's protocol embeds the content digest in the
    /// request itself — making a separate metadata fetch redundant.
    ///
    /// `true` for OCI (`/v2/{name}/blobs/sha256:<digest>`); the
    /// `IngestUseCase` reads the digest from the
    /// [`crate::types::checksum::UpstreamPublishedChecksum`]-equivalent
    /// position in the request URL via the `VerifiedIngestRequest::ProtocolNative`
    /// variant rather than calling
    /// [`upstream_checksum_metadata_path`](Self::upstream_checksum_metadata_path).
    ///
    /// Default `false`. See ADR 0006 (mandatory upstream verification).
    fn protocol_native_integrity(&self) -> bool {
        false
    }

    /// Format-specific path for fetching the upstream-published
    /// checksum metadata body. The upstream-proxy adapter composes this
    /// onto the mapping's `upstream_url` base (or treats it as an
    /// absolute URL when prefixed `https://` / `http://`).
    ///
    /// Returns `None` when the format publishes no per-artifact
    /// checksum, or when [`protocol_native_integrity`](Self::protocol_native_integrity)
    /// is `true`. Returning `Some(_)` mandates also overriding
    /// [`parse_upstream_checksum`](Self::parse_upstream_checksum) — the
    /// default parser produces an `Invariant` error if those two
    /// methods get out of sync.
    ///
    /// Default `None`. See ADR 0006 (mandatory upstream verification).
    fn upstream_checksum_metadata_path(&self, coords: &ArtifactCoords) -> Option<String> {
        let _ = coords;
        None
    }

    /// Parse the body returned from
    /// [`upstream_checksum_metadata_path`](Self::upstream_checksum_metadata_path)
    /// and recover the published checksum for `coords`.
    ///
    /// - `Ok(checksum)` — checksum was successfully extracted.
    /// - `Err(DomainError::Validation)` — body is malformed OR is
    ///   well-formed but contains no usable checksum for these coords
    ///   (legacy package without `dist.integrity`, PyPI release with
    ///   only md5 in `digests`, etc.). Surfaces as
    ///   `UpstreamErrorKind::ParseError` and `502 Bad Gateway` from the
    ///   handler. There is no soft-fail path — the design rejects the
    ///   "skip verification when upstream omits the checksum" case
    ///   (ADR 0006).
    ///
    /// The default returns
    /// [`DomainError::Invariant`] — every format that overrides
    /// [`upstream_checksum_metadata_path`](Self::upstream_checksum_metadata_path)
    /// to return `Some(_)` MUST override this method too. The default
    /// is unreachable for OCI (which uses `protocol_native_integrity =
    /// true`) and for any handler that has not yet implemented
    /// pull-through (its handler never calls this method).
    ///
    /// **Streaming contract (ADR 0026).** `body` is a streaming
    /// reader over the just-fetched upstream metadata body, NOT a
    /// buffered byte slice — the whole-body-never-buffered guarantee is
    /// structural at the port boundary. Overriding implementations
    /// stream the reader (via the per-format projectors in
    /// `hort-formats`) and never materialise the full body. The default
    /// ignores the reader entirely.
    fn parse_upstream_checksum(
        &self,
        body: &mut dyn std::io::Read,
        coords: &ArtifactCoords,
    ) -> DomainResult<UpstreamPublishedChecksum> {
        let _ = (body, coords);
        Err(DomainError::Invariant(format!(
            "format handler {} declared an upstream_checksum_metadata_path \
             but did not implement parse_upstream_checksum",
            self.format_key()
        )))
    }

    /// Extract the set of upstream-published version identifiers from a
    /// just-fetched upstream metadata body.
    ///
    /// **Streaming contract (ADR 0026).** `body` is a streaming
    /// reader over the upstream metadata body — overriding implementations
    /// project the reader (via the per-format `hort-formats` projectors)
    /// without buffering the whole body; the default ignores the reader.
    ///
    /// The caller already obtained `body` via
    /// [`crate::ports::upstream_proxy::UpstreamProxy::fetch_metadata`]
    /// (or any other byte source); this method only parses bytes into
    /// the format's published version-string set. Used by the
    /// `PrefetchTickHandler` to compute the divergence between
    /// upstream and the registry's held set on the cron path — the
    /// handler-tier equivalent of the per-format hot-path triggers
    /// (`fire_prefetch_trigger_npm` / `fire_prefetch_trigger_cargo` /
    /// `fire_prefetch_trigger_pypi`).
    ///
    /// Returns the version-string set in the order they appear in the
    /// upstream document (no sort, no dedup at this layer — the planner
    /// handles both via [`crate::entities::repository::PrefetchPolicy`]
    /// and its `VersionOrdering` arg).
    ///
    /// **Phase-1 scope cap.** Reference implementations exist for
    /// `npm` (packument `versions{}` keys), `cargo` (sparse-index
    /// NDJSON `vers` field per line), and `pypi` (PEP 503 HTML anchor
    /// list parsed via the filename → version extractor).
    /// Every other format — maven, oci, helm, rpm, debian, generic —
    /// returns `Ok(Vec::new())` from the default impl, which the
    /// scheduled tick reads as "format has no Phase-1 upstream-version
    /// discovery" and silently skips (alongside the unsupported-
    /// `VersionOrdering` early-exit). When a Phase-2 implementation
    /// lands (e.g. OCI prefetch-on-tag-move), the override
    /// SHOULD be added in the same commit that wires the hot-path
    /// counterpart — keeping the trait method default the
    /// signal that the format is not yet wired prevents a stray
    /// override from "discovering versions" via an inert path while
    /// the hot-path serve-site is still a no-op.
    fn extract_upstream_versions(&self, body: &mut dyn std::io::Read) -> DomainResult<Vec<String>> {
        let _ = body;
        Ok(Vec::new())
    }

    /// Return the format-native
    /// path for fetching the version-AGNOSTIC metadata-index document
    /// (npm packument, cargo sparse-index entry, PyPI PEP 503 simple
    /// index). Composed onto an upstream-mapping's base URL.
    ///
    /// Distinct from [`upstream_checksum_metadata_path`](Self::upstream_checksum_metadata_path)
    /// — that one returns the per-VERSION checksum-metadata path
    /// (which for PyPI is `/pypi/<name>/<version>/json`). For npm and
    /// cargo the two paths happen to coincide (their packument /
    /// sparse-index documents carry both the version-set and the
    /// checksum metadata); for PyPI they differ structurally.
    ///
    /// Consumed by [`super::super::ports`]-adjacent task handlers that
    /// need to discover the upstream version-set divergence without
    /// already having the body in hand from a serve-path fetch
    /// (the scheduled `prefetch-tick` handler is the current consumer).
    ///
    /// Default `None` — formats without a metadata-index concept
    /// (oci, generic, raw) inherit the inert default. Returns `None`
    /// rather than `Err` because absence is a normal state, not an
    /// error; the caller skips the format and continues. The
    /// `prefetch-tick` handler's pre-flight `ordering_for_format`
    /// check ensures only formats with a Phase-1 ordering reach
    /// this method, so in practice the `None` arm is unreachable on
    /// the cron path — but the trait default keeps the contract
    /// open for new formats opting in by override.
    fn upstream_metadata_path(&self, package: &str) -> Option<String> {
        let _ = package;
        None
    }

    /// Return the `Accept` header values the upstream-metadata fetch
    /// should send for this format. Empty `Vec` = no Accept header
    /// (the upstream's default representation is fine).
    ///
    /// Currently only PyPI uses this — it negotiates PEP 691 JSON via
    /// `Accept: application/vnd.pypi.simple.v1+json` falling back to
    /// `text/html`. npm / cargo / others accept the upstream default
    /// representation and need no Accept header. Future formats with
    /// content negotiation (RubyGems JSON/marshal, Conda repodata
    /// variants) override here.
    ///
    /// Default `Vec::new()` — same inert-default pattern as
    /// [`upstream_metadata_path`](Self::upstream_metadata_path).
    fn upstream_metadata_accept(&self) -> Vec<String> {
        Vec::new()
    }

    /// Extract a deterministic SBOM from the ingested payload.
    ///
    /// `format_metadata` is the JSON the handler already extracted at
    /// ingest time (`ArtifactIngested.metadata`). Most formats produce
    /// the SBOM from this without re-reading the payload, which keeps
    /// the worker's IO bill low. Handlers that need raw bytes (Maven JAR
    /// inspection, OCI layer walking) request them via `payload`.
    ///
    /// Default returns `Ok(None)` — opaque formats (raw binary uploads,
    /// Helm charts, Conda packages, Hex, Pub) have no machine-readable
    /// dependency manifest. Formats with extractable manifests override;
    /// today npm, PyPI, and Cargo do.
    ///
    /// Pure function over its inputs. No I/O beyond reading from
    /// `payload` — `PayloadAccess` is a per-call argument rather than a
    /// stored handle so the handler stays a stateless strategy and the
    /// caller controls when (and whether) payload I/O is opened. See
    /// `docs/architecture/explanation/scanning-pipeline.md`.
    fn extract_sbom(
        &self,
        coords: &ArtifactCoords,
        format_metadata: &serde_json::Value,
        payload: PayloadAccess<'_>,
    ) -> DomainResult<Option<Sbom>> {
        let _ = (coords, format_metadata, payload);
        Ok(None)
    }

    /// Extract the wheel's `<dist-info>/METADATA` file bytes
    /// from an ingested wheel artifact's content, for the PEP 658
    /// metadata-files endpoint.
    ///
    /// **Wheels only.** Returns `Ok(None)` for sdists, non-PyPI
    /// artifacts, and any artifact whose content is not a recognisable
    /// wheel ZIP. Per PEP 658 sdists do not serve PEP 658 metadata —
    /// the caller treats `None` as "no PEP 658 advertisement; the
    /// `.metadata` endpoint returns 404 for this artifact."
    ///
    /// Bounded by an internal cap (default 1 MiB — a wheel METADATA
    /// file above 100 KiB is already pathological; 1 MiB is a generous
    /// safety net). Bodies above the cap are rejected as
    /// [`DomainError::Validation`] rather than silently truncated;
    /// implementations enforce the cap on the entry's reported
    /// uncompressed size BEFORE reading bytes (so a maliciously-crafted
    /// ZIP that claims 1 KB but expands to 1 GB is rejected on the
    /// header, not after the OOM).
    ///
    /// Pure (I/O-free at the trait level — the handler receives the
    /// already-opened payload stream via [`PayloadAccess`]). Same
    /// sibling pattern as [`extract_sbom`](Self::extract_sbom)
    /// and [`extract_dependency_specs`](Self::extract_dependency_specs):
    /// same trait, same input shape, different return shape.
    ///
    /// Default returns `Ok(None)` — opaque formats (npm, cargo, OCI,
    /// generic, raw uploads, helm, conda, …) have no wheel concept and
    /// inherit the inert default. Only PyPI overrides today; the
    /// trait's other implementers are expected to keep the default
    /// indefinitely (PEP 658 is a PyPI-only feature).
    fn extract_wheel_metadata_bytes(
        &self,
        coords: &ArtifactCoords,
        payload: PayloadAccess<'_>,
    ) -> DomainResult<Option<Bytes>> {
        let _ = (coords, payload);
        Ok(None)
    }

    /// Extract the *declared runtime*
    /// dependency specs from the **stored artifact stream** (the format's
    /// own archive).
    ///
    /// **Input contract.** `content` is the raw stored
    /// artifact the transitive prefetch cascade read from CAS — for the
    /// archive formats this is the format's OWN container, NOT a
    /// pre-selected manifest body:
    ///
    /// - **npm** — the `.tgz` gzip tarball; the declared `dependencies` live
    ///   in `package/package.json` INSIDE it.
    /// - **cargo** — the `.crate` gzip tarball; `[dependencies]` live in the
    ///   top-level `<dir>/Cargo.toml` inside it.
    /// - **pypi** — the wheel (zip) / sdist (gzip-tar); `Requires-Dist` lives
    ///   in `*.dist-info/METADATA` inside the wheel.
    ///
    /// Each overriding handler is **archive-aware**: it locates its declared
    /// runtime manifest inside the artifact (via the audited
    /// `hort-formats::archive_bounds` extractor) and parses it. (An earlier
    /// contract — "a just-ingested artifact's pre-selected manifest body" —
    /// was a bug: the cascade never pre-selects a manifest, so an impl
    /// that JSON/TOML-parsed `content` directly tripped on the archive's
    /// magic byte and the cascade was inert for every archive format.)
    ///
    /// Runtime classes ONLY — never `devDependencies` / `peerDependencies`
    /// / `optionalDependencies` / `bundleDependencies` (npm), never
    /// `Requires-Dist` lines carrying a test/dev `extra` marker (PyPI),
    /// never `[dev-dependencies]` / `[build-dependencies]` entries (cargo
    /// `Cargo.toml`), never `scope = test`/`provided`/`system` (Maven).
    /// The runtime-vs-dev class boundary is load-bearing for the
    /// transitive prefetch cascade: a TypeScript devDependency
    /// closure can be 1000+ packages that none of the production code
    /// needs. Getting the class boundary wrong inflates the prefetch
    /// fan-out by 10–100×.
    ///
    /// The `range` field stays opaque (a [`String`] in the format's
    /// native range syntax — `"^1.2"` for npm, `">=2,<3"` for PyPI,
    /// `"2.x"` for cargo, `"[1.0,2.0)"` for Maven). Parsing the range
    /// is the per-format
    /// [`resolve_range_max`](Self::resolve_range_max) implementation's
    /// concern, not the caller's; different formats have different
    /// range grammars, and the call-site does not need to know which.
    ///
    /// **Streaming contract (ADR 0026).** `content` stays a
    /// `&mut dyn std::io::Read` (the `streaming_metadata_port`
    /// guard test pins the signature). Overriding implementations read the
    /// stored artifact via the per-format `hort-formats` archive helpers;
    /// the default ignores the reader.
    ///
    /// Default returns `Ok(Vec::new())` — formats
    /// without a machine-readable runtime-dep concept (oci, generic,
    /// raw uploads, helm, Maven) inherit the empty-vec contract, which the
    /// cascade reads as "no transitive deps to enqueue". Returning
    /// `Err` is reserved for a *structurally* invalid artifact — input that
    /// is not the expected container (e.g. npm input that is not a gzip-tar),
    /// a missing declared manifest entry, an unparseable manifest, or an
    /// `archive_bounds` guard trip; a well-formed artifact whose manifest
    /// declares zero runtime deps must return `Ok(vec![])`, not `Err`.
    ///
    /// Same shape contract as
    /// [`extract_upstream_versions`](Self::extract_upstream_versions):
    /// keeping the default an inert empty Vec
    /// lets new formats opt in by overriding without a cascade-of-
    /// `unimplemented!()` panics elsewhere in the call graph.
    fn extract_dependency_specs(
        &self,
        content: &mut dyn std::io::Read,
    ) -> DomainResult<Vec<DependencySpec>> {
        let _ = content;
        Ok(Vec::new())
    }

    /// Resolve a declared `range` against an
    /// `available` set of concrete versions, returning the highest
    /// version that satisfies the range.
    ///
    /// **Range-max only — NOT a SAT solver.** This is one range against
    /// one set, picking the highest match. Resolving a whole dependency
    /// graph (multi-dep co-satisfaction across a closure) is out of
    /// scope and never gets implemented at this layer — the transitive
    /// cascade just calls `resolve_range_max` per declared
    /// dep and accepts that the registry's pick may differ from a strict
    /// resolver's. This is a deliberately "plausible closure"; the
    /// deterministic exact closure is the job of
    /// seed-import / lockfile prewarm. See
    /// `docs/architecture/explanation/prefetch-pipeline.md`.
    ///
    /// Returns `Option<String>` — the matching version string in the
    /// format's native form (suitable to feed back into
    /// [`ArtifactCoords::version`](crate::types::ArtifactCoords::version)):
    ///
    /// - `None` — no version in `available` satisfies `range`, OR
    ///   `range`/`available` are unparseable (best-effort; an
    ///   unparseable user-supplied range silently no-ops rather than
    ///   surfacing a `DomainError`). The cascade reads `None` as
    ///   "skip this dep" — a transient or malformed range must not
    ///   abort the rest of the walk.
    /// - `Some(version_string)` — the highest version in `available`
    ///   satisfying `range`, in the format's native string form.
    ///
    /// Default returns `Ok(None)` — formats without a range concept
    /// (oci tags are exact pointers, not ranges) never resolve. The
    /// signature returns [`DomainResult`] for parity with
    /// [`extract_dependency_specs`](Self::extract_dependency_specs);
    /// the `Err` arm is reserved for genuinely structural errors,
    /// not "unparseable input" (which is the silent-`None` path).
    fn resolve_range_max(&self, range: &str, available: &[&str]) -> DomainResult<Option<String>> {
        let _ = (range, available);
        Ok(None)
    }

    /// Compose the upstream pull URL(s) for a
    /// `(upstream_url, package, version)` coordinate.
    ///
    /// Returns the URL(s) the leaf prefetch ingest (
    /// [`crate::ports::task_handler::TaskHandler`] `kind = "prefetch"`)
    /// should `fetch_artifact` against. The trait method stays
    /// **I/O-free** — the caller has already resolved a concrete
    /// version, so URL composition
    /// is a pure string operation per format:
    ///
    /// - **npm** — single URL: the conventional npm tarball path
    ///   `{upstream_url}/{name}/-/{name}-{version}.tgz` (scoped packages
    ///   use the *unscoped* basename in the filename per the npm
    ///   convention: `@scope/pkg → /@scope/pkg/-/pkg-{version}.tgz`).
    ///   `vec![url]`.
    /// - **cargo** — single URL: the spec-default sparse-index download
    ///   suffix `{upstream_url}/{name}/{version}/download` (the
    ///   crates.io shape; private registries with custom `dl` templates
    ///   that diverge from this need to expose the conventional path
    ///   too — the leaf handler does not fetch `config.json`). `vec![url]`.
    /// - **pypi** — returns `Ok(Vec::new())`. PyPI's per-version
    ///   manifest enumerates a variable number of distributions
    ///   (sdist + N wheels) with per-file checksums; the leaf handler
    ///   resolves them by re-fetching the per-version JSON manifest
    ///   (which the upstream-checksum-parse path already fetches via
    ///   [`upstream_checksum_metadata_path`](Self::upstream_checksum_metadata_path)),
    ///   not via this trait method. Keeping the trait method pure
    ///   forbids encoding the fan-out here.
    /// - **oci / maven / helm / rpm / debian / generic** — default
    ///   `Ok(Vec::new())`. The leaf prefetch handler reads an empty
    ///   vec as "format has no compose-style URL" and skips.
    ///
    /// `upstream_url` is the mapping's `upstream_url` field (a non-
    /// `/`-terminated absolute URL like `https://registry.npmjs.org`);
    /// composition trims a trailing `/` on `upstream_url` if present.
    ///
    /// Returning `Err` is reserved for genuinely structural errors
    /// (e.g. an empty package name) — an unsupported format must
    /// return `Ok(vec![])`, not `Err`, so the cascade silently moves
    /// on instead of failing the whole walk.
    ///
    /// Same shape contract as
    /// [`extract_dependency_specs`](Self::extract_dependency_specs) +
    /// [`resolve_range_max`](Self::resolve_range_max)
    /// and [`extract_upstream_versions`](Self::extract_upstream_versions):
    /// the same pattern (opaque default + per-format override) so new
    /// formats opt in without touching the cascade.
    fn build_pull_url(
        &self,
        upstream_url: &str,
        package: &str,
        version: &str,
    ) -> DomainResult<Vec<String>> {
        let _ = (upstream_url, package, version);
        Ok(Vec::new())
    }
}

/// One declared runtime dependency from an
/// ingested artifact's manifest.
///
/// Carries the package name as the manifest declares it and the
/// version-range string in the format's native syntax. The struct
/// stays format-neutral — `range` is opaque; parsing it is the
/// per-format
/// [`FormatHandler::resolve_range_max`] implementation's concern.
///
/// Produced by [`FormatHandler::extract_dependency_specs`]; consumed
/// by the transitive prefetch cascade
/// (`docs/architecture/explanation/prefetch-pipeline.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencySpec {
    /// Package name as the manifest declares it. The cascade re-applies
    /// per-format
    /// [`normalize_name`](FormatHandler::normalize_name) before
    /// any lookup; the unnormalised form is preserved here so the
    /// origin can be reproduced verbatim in diagnostic events.
    pub name: String,
    /// Version range in the format's native syntax — `"^1.2"` for
    /// npm-style caret, `">=2,<3"` for PEP 440 specifier, `"2.x"`
    /// for cargo-style wildcard, `"[1.0,2.0)"` for Maven bracketed
    /// range. Opaque to the caller; only
    /// [`FormatHandler::resolve_range_max`] knows the grammar.
    pub range: String,
}

/// Return value of [`FormatHandler::classify_group_member`].
///
/// Produced by format handlers that group multiple uploaded files
/// under a single logical identity (Maven GAV, OCI image, etc.). See
/// the trait method docstring for the canonicalisation contract on
/// [`GroupMembership::group_coords`].
#[derive(Debug, Clone, PartialEq)]
pub struct GroupMembership {
    /// Canonical coordinates identifying the group. Carries ONLY
    /// identity fields — `name`, `name_as_published`, `version`,
    /// `format`. Per-file fields (`path`, `metadata`) MUST be their
    /// type defaults (empty string / `Value::Null`).
    pub group_coords: ArtifactCoords,
    /// Role of the uploaded file within the group (format-defined —
    /// `"pom"`, `"jar"`, `"layer"`, etc.).
    pub role: String,
    /// `true` if the handler treats this role as the group's primary
    /// file. The first member added with `is_primary = true` fixes
    /// the group's `primary_role`. Subsequent members with
    /// `is_primary = true` that disagree surface as
    /// [`crate::error::DomainError::Conflict`].
    pub is_primary: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::repository::RepositoryFormat;
    use crate::types::ArtifactCoords;

    /// Compile-time assertion that `FormatHandler` is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: size_of call executes in the test body for coverage.
        let _ = size_of::<&dyn FormatHandler>();
    }

    /// A handler that does not override `metadata_expected_max_bytes`
    /// inherits the conservative 64 KB default. Regression guard:
    /// shrinking or growing the default without updating the docstring
    /// and its override table must fail this test.
    struct DefaultsOnlyHandler;

    impl FormatHandler for DefaultsOnlyHandler {
        fn format_key(&self) -> &str {
            "defaults"
        }
        fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
            Ok(ArtifactCoords {
                name: "x".into(),
                name_as_published: "x".into(),
                version: None,
                path: "x".into(),
                format: RepositoryFormat::Generic,
                metadata: serde_json::Value::Null,
            })
        }
        fn normalize_name(&self, name: &str) -> String {
            name.to_string()
        }
    }

    #[test]
    fn default_metadata_expected_max_bytes_is_64_kb() {
        assert_eq!(DefaultsOnlyHandler.metadata_expected_max_bytes(), 64 * 1024);
    }

    #[test]
    fn default_build_artifact_logical_path_returns_validation_error() {
        // A format without a logical-path projection
        // (OCI is digest/descriptor-based) inherits the fail-safe default:
        // a `Validation` error rather than a silently-wrong path. Regression
        // guard: changing the default to a `Ok` would let any non-overriding
        // format write a bogus projection path and re-open the
        // unreachable-row bug class.
        let err = DefaultsOnlyHandler
            .build_artifact_logical_path("pkg", "1.0", None)
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn default_build_artifact_logical_path_ignores_all_inputs() {
        // The default does not inspect name/version/filename — every input
        // shape (with or without a filename) yields the same `Validation`
        // error. Pins the no-inspection contract for reviewers.
        for filename in [None, Some("x-1.0.tar.gz")] {
            let r = DefaultsOnlyHandler.build_artifact_logical_path("anything", "9.9", filename);
            assert!(matches!(r, Err(DomainError::Validation(_))));
        }
    }

    #[test]
    fn default_collision_key_is_none() {
        // The default opts OUT of the registration-collision
        // check; only a format whose registry folds beyond its lookup key
        // (cargo) overrides this. A format inheriting the default never
        // engages the publish-time gate.
        assert_eq!(DefaultsOnlyHandler.collision_key("anything"), None);
    }

    #[test]
    fn default_metadata_strategy_is_inline() {
        assert_eq!(
            DefaultsOnlyHandler.metadata_strategy(),
            MetadataStrategy::Inline
        );
    }

    #[test]
    fn default_extract_metadata_summary_is_identity() {
        // Default never runs on the Inline path (the dispatch short-circuits
        // before calling it), but the identity contract must hold for any
        // handler that overrides `metadata_strategy` to HashReference without
        // also overriding this method. Regression guard.
        let full = serde_json::json!({ "a": 1, "nested": { "b": 2 } });
        assert_eq!(DefaultsOnlyHandler.extract_metadata_summary(&full), full);
    }

    // -------------------------------------------------------------------
    // Upstream-verification trait extensions (ADR 0006)
    // -------------------------------------------------------------------

    #[test]
    fn default_protocol_native_integrity_is_false() {
        // Every format except OCI inherits the false default; OCI alone
        // overrides to `true`. Regression guard.
        assert!(!DefaultsOnlyHandler.protocol_native_integrity());
    }

    #[test]
    fn default_upstream_checksum_metadata_path_returns_none() {
        // The default communicates "this format does not publish a
        // per-artifact checksum at a separate metadata path" — used by
        // OCI (uses protocol_native_integrity) and by handlers that have
        // not yet implemented pull-through.
        let coords = ArtifactCoords {
            name: "pkg".into(),
            name_as_published: "pkg".into(),
            version: Some("1.0".into()),
            path: "pkg/1.0/pkg-1.0.tar.gz".into(),
            format: RepositoryFormat::Generic,
            metadata: serde_json::Value::Null,
        };
        assert_eq!(
            DefaultsOnlyHandler.upstream_checksum_metadata_path(&coords),
            None
        );
    }

    #[test]
    fn default_parse_upstream_checksum_returns_invariant_error() {
        // The "soft-fail" path is deliberately rejected (ADR 0006):
        // a handler that overrides `upstream_checksum_metadata_path` to
        // `Some(_)` MUST also override the parser. The default produces
        // a clear runtime failure, not silently-skipped verification.
        let coords = ArtifactCoords {
            name: "pkg".into(),
            name_as_published: "pkg".into(),
            version: Some("1.0".into()),
            path: "pkg/1.0/pkg-1.0.tar.gz".into(),
            format: RepositoryFormat::Generic,
            metadata: serde_json::Value::Null,
        };
        let err = DefaultsOnlyHandler
            .parse_upstream_checksum(&mut std::io::Cursor::new(&[]), &coords)
            .unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    #[test]
    fn default_classify_group_member_returns_none() {
        // Default for every format without an explicit override — preserves
        // single-file artifact behaviour bit-for-bit. Regression guard:
        // changing the default to return `Some` would silently start
        // creating groups for every upload across all handlers that rely
        // on the default.
        let coords = ArtifactCoords {
            name: "x".into(),
            name_as_published: "x".into(),
            version: Some("1.0".into()),
            path: "x/1.0/x-1.0.tar.gz".into(),
            format: RepositoryFormat::Generic,
            metadata: serde_json::Value::Null,
        };
        assert!(DefaultsOnlyHandler
            .classify_group_member(&coords, &coords.path)
            .is_none());
    }

    // -------------------------------------------------------------------
    // `extract_sbom` default impl
    // -------------------------------------------------------------------

    fn sbom_test_coords() -> ArtifactCoords {
        ArtifactCoords {
            name: "pkg".into(),
            name_as_published: "pkg".into(),
            version: Some("1.0".into()),
            path: "pkg/1.0/pkg-1.0.tar.gz".into(),
            format: RepositoryFormat::Generic,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn default_extract_sbom_returns_none_for_bytes_payload() {
        // Opaque-format default: a handler that does not override
        // `extract_sbom` returns `Ok(None)` regardless of payload shape.
        // Most opaque formats (raw uploads, Helm, Conda, Hex, Pub) keep
        // this default; npm/PyPI/Cargo override per format.
        let coords = sbom_test_coords();
        let metadata = serde_json::Value::Null;
        let payload = PayloadAccess::Bytes(b"");
        let result = DefaultsOnlyHandler.extract_sbom(&coords, &metadata, payload);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn default_extract_sbom_returns_none_for_read_stream_payload() {
        // Same default contract over the streaming variant. The handler
        // must not consume the stream — verified indirectly by the
        // `does_not_consume_payload_bytes` test below.
        let coords = sbom_test_coords();
        let metadata = serde_json::Value::Null;
        let stream: Box<dyn std::io::Read + Send + '_> = Box::new(&b""[..]);
        let payload = PayloadAccess::ReadStream(stream);
        let result = DefaultsOnlyHandler.extract_sbom(&coords, &metadata, payload);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn default_extract_sbom_does_not_consume_payload_bytes() {
        // Documents the contract: the default impl does not read `payload`.
        // We can't directly observe "didn't read" without instrumenting
        // the byte source; passing a sentinel slice and asserting the
        // call returns `Ok(None)` without panicking is the structural
        // guard. If a future change made the default eagerly consume
        // bytes, the rest of the suite would still pass — this test
        // pins the no-consume contract for reviewers.
        let coords = sbom_test_coords();
        let metadata = serde_json::Value::Null;
        let payload = PayloadAccess::Bytes(b"sentinel");
        let result = DefaultsOnlyHandler.extract_sbom(&coords, &metadata, payload);
        assert!(matches!(result, Ok(None)));
    }

    // -------------------------------------------------------------------
    // `extract_wheel_metadata_bytes` default impl
    // -------------------------------------------------------------------

    #[test]
    fn default_extract_wheel_metadata_bytes_returns_none_for_bytes_payload() {
        // Opaque-format default: a handler that does not override
        // `extract_wheel_metadata_bytes` returns `Ok(None)` regardless
        // of payload shape. Only PyPI overrides; every
        // other handler keeps the inert default. Regression guard:
        // changing the default to a non-None value would silently
        // start producing PEP 658 ContentReference rows for every
        // format that inherits it (which is every format except PyPI).
        let coords = sbom_test_coords();
        let payload = PayloadAccess::Bytes(b"");
        let result = DefaultsOnlyHandler.extract_wheel_metadata_bytes(&coords, payload);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn default_extract_wheel_metadata_bytes_returns_none_for_read_stream_payload() {
        // Same default contract over the streaming variant. The handler
        // must not consume the stream — mirrors the
        // `extract_sbom` no-consume contract documented above.
        let coords = sbom_test_coords();
        let stream: Box<dyn std::io::Read + Send + '_> = Box::new(&b""[..]);
        let payload = PayloadAccess::ReadStream(stream);
        let result = DefaultsOnlyHandler.extract_wheel_metadata_bytes(&coords, payload);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn default_extract_wheel_metadata_bytes_ignores_payload_bytes() {
        // The default does not inspect `payload` — passing
        // wheel-shaped sentinel bytes (the PK ZIP magic) still yields
        // `Ok(None)`. Pins the no-inspection contract for reviewers.
        let coords = sbom_test_coords();
        // ZIP magic prefix `PK\x03\x04` followed by sentinel bytes —
        // the default impl must not interpret it.
        let payload = PayloadAccess::Bytes(b"PK\x03\x04sentinel");
        let result = DefaultsOnlyHandler.extract_wheel_metadata_bytes(&coords, payload);
        assert!(matches!(result, Ok(None)));
    }

    // -------------------------------------------------------------------
    // `extract_upstream_versions` default impl
    // -------------------------------------------------------------------

    #[test]
    fn default_extract_upstream_versions_returns_empty_vec() {
        // Opaque-format default: a handler that does not override
        // returns `Ok(Vec::new())` regardless of body. The
        // PrefetchTickHandler reads this as "no Phase-1 upstream
        // discovery" and silently skips. Regression guard: changing
        // the default to a non-empty Vec would silently enable
        // scheduled prefetch for every handler that inherits it,
        // including formats whose hot-path serve-site has no
        // matching trigger.
        let result = DefaultsOnlyHandler
            .extract_upstream_versions(&mut std::io::Cursor::new(b"any bytes here"));
        assert_eq!(result.expect("Ok"), Vec::<String>::new());
    }

    #[test]
    fn default_extract_upstream_versions_does_not_inspect_bytes() {
        // The default does not parse — well-formed JSON, malformed
        // bytes, and empty input all yield the same empty Vec. Pins
        // the no-inspection contract for reviewers.
        for body in [
            &b""[..],
            &b"{\"versions\":{\"1.0.0\":{}}}"[..],
            &b"<<not even close to valid>>"[..],
        ] {
            let r = DefaultsOnlyHandler.extract_upstream_versions(&mut std::io::Cursor::new(body));
            assert_eq!(r.expect("Ok"), Vec::<String>::new());
        }
    }

    #[test]
    fn default_upstream_metadata_path_returns_none() {
        // Opaque-format default: a handler that does not override
        // returns `None`. The PrefetchTickHandler reads this
        // as "no metadata-index document for this format" and skips
        // the repo. Regression guard: changing the default to a
        // non-empty Option would silently activate scheduled prefetch
        // for every handler that inherits it, including OCI / generic /
        // raw which have no metadata-index concept at all.
        assert_eq!(DefaultsOnlyHandler.upstream_metadata_path("anything"), None);
    }

    #[test]
    fn default_upstream_metadata_path_ignores_package_name() {
        // The default does not inspect its input — any package name
        // produces the same `None`. Pins the no-inspection contract
        // for reviewers; mirrors the same shape as
        // `default_extract_upstream_versions_does_not_inspect_bytes`.
        let long = "x".repeat(10_000);
        for pkg in ["", "lodash", long.as_str()] {
            assert_eq!(DefaultsOnlyHandler.upstream_metadata_path(pkg), None);
        }
    }

    #[test]
    fn default_upstream_metadata_accept_returns_empty() {
        // Opaque-format default: no content negotiation. Most formats
        // (npm, cargo, oci, generic, raw, …) accept the upstream's
        // default representation and need no `Accept` header. Only
        // PyPI overrides today (PEP 691 JSON negotiation); future
        // formats with content negotiation (RubyGems, Conda) add
        // their own override.
        assert_eq!(
            DefaultsOnlyHandler.upstream_metadata_accept(),
            Vec::<String>::new(),
        );
    }

    #[test]
    fn default_extract_sbom_ignores_format_metadata_shape() {
        // The default returns `None` regardless of the metadata JSON
        // shape — opaque formats have no manifest, so even a non-null
        // value should be ignored. Regression guard: the per-format
        // overrides (npm/PyPI/Cargo) parse this argument; the default
        // must not start interpreting it.
        let coords = sbom_test_coords();
        let metadata = serde_json::json!({ "name": "lodash", "version": "4.17.21" });
        let payload = PayloadAccess::Bytes(b"");
        let result = DefaultsOnlyHandler.extract_sbom(&coords, &metadata, payload);
        assert!(matches!(result, Ok(None)));
    }

    // -------------------------------------------------------------------
    // `extract_dependency_specs` / `resolve_range_max` default impls
    // -------------------------------------------------------------------

    #[test]
    fn default_extract_dependency_specs_returns_empty_vec() {
        // Opaque-format default: a handler that does not override
        // returns `Ok(Vec::new())` regardless of body. The
        // transitive-prefetch cascade reads this as "no
        // declared runtime deps" and enqueues nothing. Regression
        // guard: changing the default to a non-empty Vec would
        // silently start cascading prefetch jobs for every handler
        // that inherits it, including OCI / generic / raw uploads
        // that have no runtime-dep concept at all.
        let result = DefaultsOnlyHandler
            .extract_dependency_specs(&mut std::io::Cursor::new(b"any bytes here"));
        assert_eq!(result.expect("Ok"), Vec::<DependencySpec>::new());
    }

    #[test]
    fn default_extract_dependency_specs_does_not_inspect_bytes() {
        // The default does not parse — well-formed JSON, malformed
        // bytes, and empty input all yield the same empty Vec. Same
        // no-inspection contract as `extract_upstream_versions`.
        for body in [
            &b""[..],
            &b"{\"dependencies\":{\"lodash\":\"^4\"}}"[..],
            &b"<<not even close to valid>>"[..],
        ] {
            let r = DefaultsOnlyHandler.extract_dependency_specs(&mut std::io::Cursor::new(body));
            assert_eq!(r.expect("Ok"), Vec::<DependencySpec>::new());
        }
    }

    #[test]
    fn default_resolve_range_max_returns_none() {
        // Opaque-format default: a handler that does not override
        // returns `Ok(None)` regardless of range/available. The
        // cascade reads `None` as "skip this dep" so a handler
        // without a range concept (oci tags, generic uploads)
        // contributes nothing to the prefetch walk.
        let result = DefaultsOnlyHandler.resolve_range_max("^1.0", &["1.0.0", "2.0.0"]);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn default_resolve_range_max_ignores_available_set_shape() {
        // The default does not parse — an empty available set, a
        // populated one, and one with garbage all yield `Ok(None)`.
        // Pins the no-inspection contract for reviewers.
        for available in [
            &[][..],
            &["1.0.0", "1.2.3", "2.0.0"][..],
            &["definitely-not-a-version"][..],
        ] {
            let r = DefaultsOnlyHandler.resolve_range_max("anything", available);
            assert!(matches!(r, Ok(None)));
        }
    }

    // -------------------------------------------------------------------
    // `build_pull_url` default impl
    // -------------------------------------------------------------------

    #[test]
    fn default_build_pull_url_returns_empty_vec() {
        // Opaque-format default: a handler that does not override
        // returns `Ok(Vec::new())` regardless of inputs. The
        // PrefetchIngestHandler reads this as "format has no pull-URL
        // concept" and skips. Regression guard: changing the default
        // to a non-empty Vec would silently start enqueuing pull URLs
        // for every handler that inherits it, including OCI / generic
        // / raw uploads.
        let result =
            DefaultsOnlyHandler.build_pull_url("https://registry.example.com", "lodash", "4.17.21");
        assert_eq!(result.expect("Ok"), Vec::<String>::new());
    }

    #[test]
    fn default_build_pull_url_does_not_inspect_inputs() {
        // The default does not parse — well-formed inputs, empty
        // inputs, and garbage all yield the same empty Vec. Pins the
        // no-inspection contract for reviewers.
        for (url, pkg, ver) in [
            ("https://r.example.com", "name", "1.0.0"),
            ("", "", ""),
            ("not-a-url", "<<weird>>", "neither-this"),
        ] {
            let r = DefaultsOnlyHandler.build_pull_url(url, pkg, ver);
            assert_eq!(r.expect("Ok"), Vec::<String>::new());
        }
    }

    #[test]
    fn dependency_spec_carries_opaque_range_string() {
        // The struct is format-neutral: `range` is a plain `String`
        // and `DependencySpec` is constructible without any range
        // grammar dependency. Regression guard: adding a typed
        // `Range` enum to the struct would force every caller to
        // bind the type at the trait boundary, defeating the
        // deliberately-chosen format-neutrality.
        let spec = DependencySpec {
            name: "lodash".into(),
            range: "^4.17.0".into(),
        };
        assert_eq!(spec.name, "lodash");
        assert_eq!(spec.range, "^4.17.0");
        // Equality on the struct is value-equality.
        assert_eq!(
            spec,
            DependencySpec {
                name: "lodash".into(),
                range: "^4.17.0".into(),
            }
        );
    }
}
