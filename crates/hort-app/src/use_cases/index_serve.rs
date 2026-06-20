//! Format-agnostic index-construction trait skeleton (see
//! `docs/architecture/explanation/index-construction.md`).
//!
//! This module defines the **Source → Filter → Builder** pipeline's
//! traits and the spine [`VersionEntry`] all three operate on. Each
//! per-format crate (npm, pypi, cargo) supplies its own
//! [`IndexBuilder`] implementation; `hort-app` supplies the shared
//! [`IndexFilter`] implementations (see
//! [`crate::use_cases::index_filters`]); the per-format HTTP crate
//! supplies the `IndexSource` that produces `Vec<VersionEntry>` from
//! either the local DB (hosted) or an upstream fetch (proxy).
//!
//! [`PerVersionPayload`] is a single closed-sum
//! type whose set of variants grows exactly once per per-format
//! migration.
//!
//! # Dep direction
//!
//! `hort-formats` depends on `hort-app` (see
//! `crates/hort-formats/Cargo.toml`), not the other way around — the
//! `IndexFilter` impls could not reference traits defined in a crate
//! `hort-app` does not depend on. So the traits + spine types are
//! **defined here in `hort-app`**, and `hort-formats::index_serve`
//! re-exports them. This:
//!
//! - keeps the filter implementations on the same side of the
//!   dep-graph as the trait they implement (no circular dep);
//! - mirrors the existing [`VersionOrdering`] re-export shape from
//!   [`crate::use_cases::index_serve_filter`] (defined in `hort-app`,
//!   re-exported from `hort-formats::index_serve`);
//! - gives format-crate consumers a single import path
//!   (`use hort_formats::index_serve::{…}`);
//! - matches the existing precedent —
//!   [`crate::use_cases::index_serve_filter::filter_served_versions`]
//!   already lives in `hort-app` despite being consumed by format
//!   crates through the same re-export pattern.

use std::collections::HashSet;

use bytes::Bytes;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::{IndexMode, RepositoryType};
use hort_domain::types::ContentHash;

pub use crate::use_cases::index_serve_filter::VersionOrdering;

/// One version's worth of data feeding the index-construction
/// pipeline.
///
/// The spine — `version` + `status` — is what every filter operates
/// on; the per-format `payload` is opaque to filters and consumed
/// only by the matching [`IndexBuilder`].
///
/// `status` is `Option<QuarantineStatus>` rather than
/// `QuarantineStatus`: a `None` entry represents a version that Hort
/// has no projection row for. This is exactly the "unknown" tier
/// [`IndexMode::IncludePending`] needs (proxy sources advertise
/// upstream versions Hort has never ingested; the filter keeps them).
/// Hosted sources never produce `None` entries because every entry
/// comes from `artifacts` rows that have an explicit
/// [`QuarantineStatus`].
#[derive(Debug, Clone)]
pub struct VersionEntry {
    /// The version string in the format's resolver shape — npm/cargo
    /// semver, PyPI PEP 440, Cargo NDJSON `vers`. Sources construct
    /// it from the local row's `version` column or by parsing the
    /// upstream document; the filter pipeline treats it as an opaque
    /// string; the builder emits it verbatim into the wire shape.
    pub version: String,
    /// Hort's known quarantine status for `(repository, name, version)`,
    /// or `None` when Hort has no projection row for this version.
    pub status: Option<QuarantineStatus>,
    /// Per-format payload — the builder uses this to emit the
    /// format-specific wire shape (npm `dist.tarball` / SRI /
    /// shasum, PyPI `files[]` row, Cargo NDJSON line, …).
    ///
    /// Deliberately a closed sum type; variants are added alongside each
    /// per-format builder. See [`PerVersionPayload`].
    pub payload: PerVersionPayload,
}

/// Per-format payload.
///
/// A closed sum type was chosen over `Box<dyn Payload>`: each builder
/// needs concrete access to *its* variant's fields, and type-erasure
/// would force every builder to downcast, defeating the type-system
/// guarantee that a `NpmIndexBuilder` only ever sees
/// `PerVersionPayload::Npm`. "PerVersionPayload is a deliberately closed
/// sum type."
///
/// # Dep-graph note
///
/// Per-format payload structs live **here** (in `hort-app`) rather than
/// in `hort-formats::<format>::index`. Reason: `hort-app` does not depend
/// on `hort-formats` (the dep edge runs `hort-formats → hort-app`);
/// defining a variant whose data type lives in `hort-formats` would
/// require the impossible reverse edge. `hort-formats::npm::index`
/// re-exports [`NpmVersionPayload`] so format-crate consumers see the
/// expected import path (`use hort_formats::npm::index::NpmVersionPayload;`)
/// and the data type stays in the dep-graph layer that actually compiles.
#[derive(Debug, Clone)]
pub enum PerVersionPayload {
    /// npm packument per-version data. Carried by
    /// [`VersionEntry`]s the `HostedNpmSource` / `ProxyNpmSource`
    /// produce; consumed by `NpmIndexBuilder` in
    /// `hort-formats::npm::index` to emit each `versions[v]` entry of
    /// the packument JSON. See [`NpmVersionPayload`].
    Npm(NpmVersionPayload),
    /// PyPI simple-index per-version data. Carried
    /// by [`VersionEntry`]s the `HostedPypiSource` / `ProxyPypiSource`
    /// produce; consumed by `PypiHtmlIndexBuilder` (PEP 503) and
    /// `PypiJsonIndexBuilder` (PEP 691) in `hort-formats::pypi::index`
    /// to emit each `files[]` row / `<a>` anchor. Unlike npm where
    /// one version maps to a single tarball, a PyPI version carries
    /// a *list* of files (sdist + N wheels) — see [`PypiVersionPayload`].
    Pypi(PypiVersionPayload),
    /// Cargo sparse-index per-version data. Carried
    /// by [`VersionEntry`]s the `HostedCargoSource` / `ProxyCargoSource`
    /// produce; consumed by `CargoIndexBuilder` in
    /// `hort-formats::cargo::index` to emit one NDJSON line per version
    /// of the sparse-index document. Unlike npm and PyPI where a single
    /// version maps to one tarball or a file-list, cargo's per-version
    /// record is itself a flat JSON object with a fixed key set —
    /// see [`CargoVersionPayload`].
    Cargo(CargoVersionPayload),
}

/// npm packument per-version data.
///
/// Carries exactly the fields the `NpmIndexBuilder` reads when
/// emitting one entry of the packument's `versions{}` object. Kept
/// minimal by contract: anything the builder
/// does *not* read stays out (no upstream `time`, no `maintainers`,
/// no `bugs`, no README — the unified packument is the wire-shape
/// minimum every npm client tolerates; carrying upstream extras
/// would expand the surface the proxy source has to faithfully
/// parse for no observable client win).
///
/// # Field reference
///
/// - `name_as_published` — the per-version `"name"` field. npm
///   permits a published `name` different from the request route
///   (drift-resilience on hosted; arbitrary upstream-declared names
///   on proxy). Preserved verbatim; the builder embeds it as the
///   per-version `name` field of the emitted packument **and** uses
///   it to construct the per-version `dist.tarball` URL segment
///   (mirrors the existing local-CAS handler in
///   `hort-http-npm/src/lib.rs::serve_packument`).
/// - `tarball_basename` — the upstream tarball URL's *basename*
///   (everything after `/-/`). The builder composes the full
///   `dist.tarball` URL as
///   `{base_url}/npm/{repo_key}/{name_as_published}/-/{tarball_basename}`.
///   The hosted source derives it from `Artifact.path`
///   (`{name}/-/{filename}` → `filename`); the proxy source derives
///   it from the upstream `dist.tarball` URL.
/// - `integrity` — `dist.integrity` (the SRI string,
///   `sha512-<base64>`). `Some(...)` on proxy when the upstream
///   published one; `None` on hosted unless future ingest captures
///   it (a quarantine/scanning-adjacent extension — out of scope
///   for the index pipeline). The
///   builder emits the key only when `Some`, preserving the npm
///   convention of omitting absent fields rather than emitting
///   `null`.
/// - `shasum` — `dist.shasum` (the SHA-1 hex digest). npm clients
///   pre-`integrity` verified against this; modern clients still
///   honour it as a fallback. Always emitted by the builder (empty
///   string when neither hosted nor proxy supplied one — matches
///   the existing local-CAS handler's `unwrap_or_default` shape).
#[derive(Debug, Clone)]
pub struct NpmVersionPayload {
    /// Per-version `name` field — the npm-published name. Preserved
    /// verbatim from the source (hosted: `Artifact.name`; proxy:
    /// upstream `versions[v].name`).
    pub name_as_published: String,
    /// Tarball URL basename — everything after the npm-conventional
    /// `/-/` separator. The builder composes the absolute URL by
    /// prepending `{base_url}/npm/{repo_key}/{name_as_published}/-/`.
    pub tarball_basename: String,
    /// `dist.integrity` — the npm SRI string (`sha512-<base64>`).
    /// `None` when the source could not supply one (hosted has no
    /// SRI capture path in v2 today; proxy honours upstream omission).
    pub integrity: Option<String>,
    /// `dist.shasum` — the SHA-1 hex digest. Always present (the
    /// empty string when neither source supplied one — mirrors the
    /// earlier local-CAS handler's `unwrap_or_default` semantics).
    pub shasum: String,
}

/// PyPI simple-index per-version data.
///
/// A PyPI "version" in the simple index is not one distribution but
/// a **list of files** (the sdist + per-platform wheels). The builder
/// emits one `<a>` anchor (PEP 503 HTML) or one `files[]` row (PEP
/// 691 JSON) per file. This is the structural difference vs npm where
/// one version → one tarball.
///
/// The set of files is materialised by the source adapter
/// (`HostedPypiSource` reads one row per `Artifact`; `ProxyPypiSource`
/// pulls them from the upstream simple-index body's per-anchor /
/// per-`files[]` entries) and consumed by the builder verbatim. The
/// payload carries exactly what the builder reads — no upstream
/// extras (no `yanked`, no `upload_time`, no `core-metadata-hash`
/// beyond `sha256`); the same minimal-surface contract npm's payload
/// follows. Extras can be added when a builder actually reads them.
///
/// # Field reference
///
/// - `files` — the per-version file list. Each [`PypiVersionFile`] is
///   one `<a>` / `files[]` entry. Ordered as the source produced it
///   (the builder does not re-sort; PyPI clients tolerate any order).
#[derive(Debug, Clone)]
pub struct PypiVersionPayload {
    /// The per-version file list (sdist + N wheels). One entry maps
    /// to one `<a>` anchor (PEP 503) or one `files[]` row (PEP 691).
    /// Order is preserved by the builder (the source picks the order;
    /// the order is not load-bearing on the wire because PyPI clients
    /// pick by filename + metadata).
    pub files: Vec<PypiVersionFile>,
}

/// One file within a [`PypiVersionPayload`] — a single sdist or wheel.
///
/// Builders emit one wire entry per file. The fields are exactly what
/// PEP 503 / PEP 691 require to make a downloadable link:
///
/// - `filename` — the distribution filename (e.g.
///   `requests-2.31.0-py3-none-any.whl` or `requests-2.31.0.tar.gz`).
///   Builder embeds it verbatim as the link text (HTML) / `filename`
///   field (JSON) and uses it as the URL's last segment.
/// - `hash_sha256` — the SHA-256 hex digest. Emitted as the
///   `#sha256=...` URL fragment in HTML and as `hashes.sha256` in
///   JSON. `None` is rare but legitimate (an upstream that doesn't
///   publish hashes; Hort hosted-without-checksum is possible too) —
///   the builder omits the attribute in that case rather than
///   emitting empty bytes.
/// - `requires_python` — PEP 503 `data-requires-python` attribute /
///   PEP 691 `requires-python` field. Carried verbatim from the
///   stored metadata or upstream entry; absent when the publisher
///   didn't declare it.
#[derive(Debug, Clone)]
pub struct PypiVersionFile {
    /// Distribution filename — the `<a>` link text / `files[].filename`.
    /// The builder uses this as the URL basename when composing the
    /// per-file simple-index download link.
    pub filename: String,
    /// SHA-256 hex digest. `None` when the source could not supply
    /// one; builders omit the corresponding hash field in that case
    /// (no empty-string / `null` emission).
    pub hash_sha256: Option<String>,
    /// PEP 503 `data-requires-python` / PEP 691 `requires-python`.
    /// `None` when absent; builders omit the attribute / field in
    /// that case.
    pub requires_python: Option<String>,
    /// PEP 658 metadata hash for the wheel's
    /// `<dist-info>/METADATA` blob (the bytes the `.metadata`
    /// endpoint serves). `None` for sdists (PEP 658 is wheels-only),
    /// for wheels ingested before metadata extraction existed (until
    /// the `wheel-metadata-backfill` task runs), and for any wheel whose
    /// `wheel_metadata` ContentReference lookup failed. The HTML
    /// builder emits `data-dist-info-metadata="sha256=<hex>"` only
    /// when `Some`; the JSON builder emits
    /// `"dist-info-metadata": {"sha256": "<hex>"}` when `Some` and
    /// `"dist-info-metadata": false` (PEP 691 — "no integrity
    /// available") when `None`. Sources populate this field from
    /// either a batched `content_references` lookup (hosted) or a
    /// parse of the upstream's `data-dist-info-metadata` attribute
    /// (proxy).
    pub metadata_hash: Option<ContentHash>,
}

/// Cargo sparse-index per-version data.
///
/// Carries exactly the fields the [`CargoIndexBuilder`] reads when
/// emitting one NDJSON line of the sparse-index document. The cargo
/// sparse-index wire shape per the registry spec is a flat JSON
/// object per line with this key set:
///
/// ```text
/// {"name":"<name>","vers":"<vers>","deps":[...],"cksum":"<sha256>",
///  "features":{...},"yanked":<bool>,"links":<string|null>,
///  "rust_version":<string|null>,"v":<int|null>,"features2":{...}}
/// ```
///
/// The fields the existing emission / parse code reads are a
/// strict subset; this payload carries exactly that subset ("carry
/// only what the builder reads; anything not read on emission stays
/// out").
///
/// The hosted source (`HostedCargoSource`) populates this from the
/// stored [`Artifact`] row — the earlier local-NDJSON path
/// emitted `{name, vers, deps: [], cksum, features: {}, yanked:
/// false, rust_version: null}`. The proxy source (`ProxyCargoSource`)
/// parses the upstream NDJSON body and preserves whatever the
/// upstream supplied for `deps` / `features` / `features2` / `links`
/// / `v` / `rust_version` (the upstream-fidelity contract — cargo
/// clients perform version-resolution against this body, so
/// stripping fields would break legitimate resolves).
///
/// # Field reference
///
/// - `name_as_published` — the per-version `"name"` field. Cargo
///   normalises crate names to lowercase + `_`-vs-`-` equivalence at
///   the URL layer, but the index entry carries the *stored* form
///   (drift-resilience under non-idempotent normaliser changes —
///   mirrors the earlier local-NDJSON `artifact.name` shape).
/// - `vers` — the version string (semver). Preserved verbatim from
///   the source — the builder embeds it as the per-version `vers`
///   field and the filter pipeline keys on it for status lookup.
/// - `cksum` — the SHA-256 hex digest of the `.crate` file. Mandatory
///   per the cargo wire spec; populated from the stored sha256 on
///   hosted, and from the upstream NDJSON `cksum` field on proxy.
/// - `deps` — the per-version dependency list. Hosted emits `[]`:
///   cargo dep extraction from the publish `.crate` (a
///   publish-`.crate` parser path) is not implemented yet.
///   Proxy preserves the upstream-supplied array verbatim.
/// - `features` — the named-features map. Hosted emits `{}`; proxy
///   preserves the upstream-supplied object verbatim.
/// - `yanked` — the version's yanked status. **Yanked is orthogonal
///   to quarantine**: cargo's clients treat yanked separately from
///   missing-from-index (yanked is allowed in version ranges that
///   already pin it, missing is not). The index filter pipeline
///   does NOT filter yanked versions — they appear in the served
///   set with `yanked: true`. This is the cargo per-protocol
///   contract.
/// - `links` — the native-library linkage hint
///   (`Cargo.toml` `[package].links`). `Some(...)` when the upstream
///   supplied a non-null value; `None` for the local hosted path
///   (the earlier local-NDJSON path never carried this field).
///   The builder emits `null` when `None`, matching the wire shape
///   cargo clients tolerate.
/// - `rust_version` — the MSRV pin. `Some(...)` when the upstream
///   supplied one; `None` for hosted (emitted as `null`).
/// - `v` — the schema version. `Some(2)` when the upstream entry
///   uses `features2` for namespaced/weak deps; `None` for legacy
///   v1 entries. Hosted emits `None`.
/// - `features2` — the v2-extra features map (namespaced /
///   weak-dep features). Preserved verbatim from upstream when
///   present. Hosted emits `None`.
#[derive(Debug, Clone)]
pub struct CargoVersionPayload {
    /// Per-version `name` field — the cargo-published crate name.
    /// Preserved verbatim from the source (hosted: `Artifact.name`;
    /// proxy: upstream NDJSON `name`).
    pub name_as_published: String,
    /// Per-version `vers` field — the semver version string. Same
    /// value as the spine `VersionEntry.version`; carried in the
    /// payload as well so the builder can emit it without reaching
    /// back through `VersionEntry`.
    pub vers: String,
    /// `cksum` — the SHA-256 hex digest of the `.crate` file.
    /// Mandatory per cargo's sparse-index spec; the empty string is
    /// emitted only when neither source supplied one (mirrors the
    /// earlier local-NDJSON `unwrap_or("")` semantics).
    pub cksum: String,
    /// `deps` — per-version dependency list. Hosted carries `[]`;
    /// proxy preserves the upstream-supplied array verbatim. Builder
    /// embeds the value as-is into the NDJSON line.
    pub deps: serde_json::Value,
    /// `features` — named-features map. Hosted carries `{}`; proxy
    /// preserves the upstream-supplied object verbatim.
    pub features: serde_json::Value,
    /// `yanked` — the version's yanked status. Cargo clients honour
    /// this orthogonally to quarantine — yanked versions are kept
    /// in the served set with `yanked: true`.
    pub yanked: bool,
    /// `links` — native-library linkage hint. `None` → emitted as
    /// JSON `null`.
    pub links: Option<String>,
    /// `rust_version` — MSRV pin. `None` → emitted as JSON `null`.
    pub rust_version: Option<String>,
    /// `v` — schema version (2 when `features2` is in use). `None`
    /// → omitted from the line.
    pub v: Option<u32>,
    /// `features2` — v2-extra features map. `None` → omitted from
    /// the line.
    pub features2: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Virtual-repository aggregation primitives (ADR 0031)
// ---------------------------------------------------------------------------
//
// Format-agnostic — both operate on the `VersionEntry` spine, so npm / PyPI /
// Cargo reuse them. They run BEFORE the `IndexFilter` pipeline, on RAW entries:
// the dependency-confusion defences require an entry's `Quarantined`/`Rejected`
// status to survive into the merge, which a per-member `NonServableStatusFilter`
// pass would already have dropped (ADR 0031 §Decision; spec §4 / §7).

/// One member's index-fetch outcome, as the aggregation helper sees it.
///
/// `Present(entries)` — the member responded; an empty vec means the package is
/// genuinely absent *there*. `Unavailable` — the member's fetch errored (an
/// infrastructure failure), so whether it owns the name is **indeterminate**.
/// The per-format `IndexSource` maps its `Result` into this (a "package absent"
/// miss → `Present(vec![])`; an infra error → `Unavailable`).
#[derive(Debug, Clone)]
pub enum MemberFetch {
    Present(Vec<VersionEntry>),
    Unavailable,
}

/// Index aggregation for a virtual repo (ADR 0031) — the single home of the two
/// substitution defences plus the fail-closed member-failure rule.
///
/// Members are supplied highest-priority-first. On RAW entries:
///
/// 1. **Name-level pinning (rule 2b).** The name is *owned* if any non-proxy
///    member (`Hosted`/`Staging`) is `Present(non-empty)` **or** `Unavailable`.
///    The `Unavailable` case is the fail-closed rule: a non-proxy owner that
///    errored is treated as a *potential* owner, so proxies stay suppressed —
///    a transient outage of the trusted owner cannot re-open the confusion
///    window by making the name look unowned. When the name is owned, every
///    `Proxy` member is dropped.
/// 2. **Authoritative merge (rule 2a).** [`merge_members_authoritative`] over
///    the surviving members: dedup by version, higher-priority wins (status
///    included). An `Unavailable` member contributes no entries.
///
/// Runs BEFORE the `NonServableStatusFilter` / `IndexModeFilter` pipeline. Pure
/// transform, no I/O.
pub fn aggregate_index_members(
    per_member_in_priority_order: Vec<(RepositoryType, MemberFetch)>,
) -> Vec<VersionEntry> {
    let name_is_owned = per_member_in_priority_order
        .iter()
        .any(|(repo_type, fetch)| {
            !matches!(repo_type, RepositoryType::Proxy)
                && match fetch {
                    MemberFetch::Present(entries) => !entries.is_empty(),
                    MemberFetch::Unavailable => true,
                }
        });
    let surviving: Vec<Vec<VersionEntry>> = per_member_in_priority_order
        .into_iter()
        .filter_map(|(repo_type, fetch)| {
            if name_is_owned && matches!(repo_type, RepositoryType::Proxy) {
                return None;
            }
            Some(match fetch {
                MemberFetch::Present(entries) => entries,
                MemberFetch::Unavailable => Vec::new(),
            })
        })
        .collect();
    merge_members_authoritative(surviving)
}

/// Merge per-member version entries under the authoritative-member rule — the
/// same-version dependency-confusion defence (ADR 0031 rule 2a).
///
/// Members are supplied highest-priority-first. The first member to carry a
/// given `version` wins it, **including that entry's `status`**; a lower-priority
/// member's copy of the same version is dropped, not merged. So a coordinate
/// held (`Quarantined`/`Rejected`) in a higher-priority member is never silently
/// replaced by a lower-priority member's released copy. Runs on RAW entries,
/// BEFORE the `NonServableStatusFilter` / `IndexModeFilter` pipeline. The dedup
/// key is the `version` string within the single requested name. Pure transform,
/// no I/O.
pub fn merge_members_authoritative(
    per_member_in_priority_order: Vec<Vec<VersionEntry>>,
) -> Vec<VersionEntry> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut merged: Vec<VersionEntry> = Vec::new();
    for member_entries in per_member_in_priority_order {
        for entry in member_entries {
            if seen.insert(entry.version.clone()) {
                merged.push(entry);
            }
        }
    }
    merged
}

/// Format-agnostic filter.
///
/// Operates on the [`VersionEntry`] spine only. Implementations live
/// in [`crate::use_cases::index_filters`] (`NonServableStatusFilter`
/// drops [`QuarantineStatus::Quarantined`] / `Rejected` /
/// `ScanIndeterminate` universally; `IndexModeFilter` wraps the
/// `filter_served_versions` semantics on the spine fields).
/// Future operator-exclusion / curation filters extend this trait.
///
/// `apply` is owned (`Vec<VersionEntry>` in, `Vec<VersionEntry>`
/// out) so the pipeline composes by piping the previous filter's
/// output into the next filter's input without intermediate cloning.
/// A pure transform — no I/O.
pub trait IndexFilter: Send + Sync {
    /// Apply the filter to a list of entries, returning the filtered
    /// list. The relative order of retained entries is preserved
    /// (the universal source-of-truth order is whatever the source
    /// produced; filters only drop, they don't reorder).
    fn apply(&self, entries: Vec<VersionEntry>) -> Vec<VersionEntry>;
}

/// Per-call context passed to [`IndexBuilder::build`].
///
/// Carries the inputs the builder needs that are *not* part of the
/// per-version entries: the package's display name (for wire-shape
/// fields the builder embeds — npm `name`, PyPI page title), the
/// base URL the builder uses to compose tarball / download links,
/// the repository's [`IndexMode`] (some builders embed the mode in
/// served-document metadata), and the
/// per-format [`VersionOrdering`] (used by builders that need to
/// pick "the newest served version" for `dist-tags.latest`-shaped
/// fields).
///
/// `'a` is the lifetime of the borrowed references; the builder
/// must not store `BuildContext` past the call.
pub struct BuildContext<'a> {
    /// Package display name (e.g. npm `name`, PyPI distribution
    /// name). Builders embed this in their wire shape as-is.
    pub package_name: &'a str,
    /// Base URL the builder uses to compose tarball / download URLs.
    /// Already URL-encoded by the calling handler; the builder
    /// concatenates per-format path suffixes onto it.
    pub base_url: &'a str,
    /// The repository's [`IndexMode`]. Most builders ignore this —
    /// the filter pipeline has already applied the mode by the time
    /// the builder sees the entries; the field is here so a future
    /// builder that needs to reflect the mode in its emitted
    /// document can do so without a trait change.
    pub index_mode: IndexMode,
    /// Per-format version ordering — used by builders that need to
    /// pick the newest served version (npm `dist-tags.latest`, PyPI
    /// most-recent-link, …). Not consumed by the filter pipeline.
    pub ordering: &'a dyn VersionOrdering,
}

/// Per-format wire-shape emitter.
///
/// Stateless; one impl per emitted document shape. PyPI's HTML
/// (PEP 503) vs JSON (PEP 691) split uses two distinct [`IndexBuilder`]
/// implementations (`PypiHtmlIndexBuilder` / `PypiJsonIndexBuilder`)
/// selected by the handler based on the request's `Accept` header —
/// the trait stays content-type-agnostic.
///
/// Returns `bytes::Bytes` so the caller can hand the buffer
/// directly to `axum::body::Body::from`; the workspace already pins
/// `bytes 1.x` (see workspace `Cargo.toml`).
pub trait IndexBuilder: Send + Sync {
    /// Emit the wire bytes for `entries` under `ctx`. The entries
    /// are post-filter — the builder does not re-filter; it formats.
    fn build(&self, ctx: BuildContext<'_>, entries: Vec<VersionEntry>) -> Bytes;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::*;

    /// A no-op filter used to exercise the [`IndexFilter`] trait
    /// shape (the real impls live in
    /// [`crate::use_cases::index_filters`] and are tested there).
    struct IdentityFilter;

    impl IndexFilter for IdentityFilter {
        fn apply(&self, entries: Vec<VersionEntry>) -> Vec<VersionEntry> {
            entries
        }
    }

    /// A trivial [`VersionOrdering`] for `BuildContext` tests.
    struct LexOrdering;

    impl VersionOrdering for LexOrdering {
        fn compare(&self, a: &str, b: &str) -> Ordering {
            a.cmp(b)
        }
    }

    #[test]
    fn version_entry_vec_threads_payload() {
        // Smoke: a `Vec<VersionEntry>` materialises empty and threads
        // through generic containers. Real value construction is
        // exercised in the per-format builder tests (`hort-formats::npm::index`
        // and counterpart builders) where the source-shaped fixtures
        // actually carry an `NpmVersionPayload`.
        let entries: Vec<VersionEntry> = Vec::new();
        assert!(entries.is_empty());
    }

    #[test]
    fn index_filter_apply_passes_through_empty_input() {
        let f = IdentityFilter;
        let out = f.apply(Vec::new());
        assert!(out.is_empty());
    }

    #[test]
    fn build_context_holds_borrowed_inputs() {
        let pkg = String::from("example");
        let base = String::from("https://repo.example/v2/");
        let ordering = LexOrdering;
        let ctx = BuildContext {
            package_name: &pkg,
            base_url: &base,
            index_mode: IndexMode::ReleasedOnly,
            ordering: &ordering,
        };
        assert_eq!(ctx.package_name, "example");
        assert_eq!(ctx.base_url, "https://repo.example/v2/");
        assert_eq!(ctx.index_mode, IndexMode::ReleasedOnly);
        assert_eq!(ctx.ordering.compare("a", "b"), Ordering::Less);
    }

    /// Verifies the `PerVersionPayload::Npm`
    /// variant carries an [`NpmVersionPayload`] with the four fields
    /// `NpmIndexBuilder` consumes. The structural shape is part of
    /// the closed-sum contract; the existence test here is the
    /// lightweight compile-and-shape pin (the builder-emission
    /// semantics live in `hort-formats::npm::index`'s test module).
    #[test]
    fn npm_per_version_payload_has_required_fields() {
        let payload = NpmVersionPayload {
            name_as_published: "express".into(),
            tarball_basename: "express-1.0.0.tgz".into(),
            integrity: Some("sha512-aGVsbG8=".into()),
            shasum: "da39a3ee5e6b4b0d3255bfef95601890afd80709".into(),
        };
        let wrapped = PerVersionPayload::Npm(payload.clone());
        match wrapped {
            PerVersionPayload::Npm(p) => {
                assert_eq!(p.name_as_published, "express");
                assert_eq!(p.tarball_basename, "express-1.0.0.tgz");
                assert_eq!(p.integrity.as_deref(), Some("sha512-aGVsbG8="));
                assert_eq!(p.shasum, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
            }
            // The `Pypi` and `Cargo` variants have their own sister
            // tests; the npm test explicitly only exercises the `Npm`
            // arm. A mis-construction would be a test-side bug.
            PerVersionPayload::Pypi(_) => {
                unreachable!("npm fixture must produce an Npm payload")
            }
            PerVersionPayload::Cargo(_) => {
                unreachable!("npm fixture must produce an Npm payload")
            }
        }
        // Smoke: `Clone` is on the struct (consumed by source
        // adapters that materialise an entry per row / per upstream
        // version).
        let _ = payload.clone();
    }

    // --- Virtual-repository aggregation primitives (ADR 0031) -----------

    /// Minimal `VersionEntry` for the pinning/merge tests — both primitives
    /// key on `version` + `status` only; the payload is opaque to them.
    fn ve(version: &str, status: Option<QuarantineStatus>) -> VersionEntry {
        VersionEntry {
            version: version.into(),
            status,
            payload: PerVersionPayload::Npm(NpmVersionPayload {
                name_as_published: "p".into(),
                tarball_basename: format!("p-{version}.tgz"),
                integrity: None,
                shasum: "x".into(),
            }),
        }
    }

    /// Version strings of a merged entry list, in order.
    fn vers(entries: Vec<VersionEntry>) -> Vec<String> {
        entries.into_iter().map(|e| e.version).collect()
    }

    use MemberFetch::{Present, Unavailable};

    #[test]
    fn aggregate_owned_name_drops_all_proxy_members() {
        // A non-proxy member owns the name → the proxy's (attacker-published)
        // version is excluded entirely.
        let merged = aggregate_index_members(vec![
            (RepositoryType::Proxy, Present(vec![ve("9.9.9", None)])),
            (
                RepositoryType::Hosted,
                Present(vec![ve("1.0.0", Some(QuarantineStatus::Released))]),
            ),
        ]);
        assert_eq!(vers(merged), vec!["1.0.0".to_string()]);
    }

    #[test]
    fn aggregate_unowned_name_keeps_proxy_members() {
        // No non-proxy member has the name → proxy participates normally.
        let merged = aggregate_index_members(vec![(
            RepositoryType::Proxy,
            Present(vec![ve("1.0.0", None)]),
        )]);
        assert_eq!(vers(merged), vec!["1.0.0".to_string()]);
    }

    #[test]
    fn aggregate_empty_non_proxy_member_does_not_own() {
        // A non-proxy member that responded with NO entries does not own the
        // name, so the proxy is kept.
        let merged = aggregate_index_members(vec![
            (RepositoryType::Hosted, Present(vec![])),
            (RepositoryType::Proxy, Present(vec![ve("1.0.0", None)])),
        ]);
        assert_eq!(vers(merged), vec!["1.0.0".to_string()]);
    }

    #[test]
    fn aggregate_staging_counts_as_owner_and_drops_proxy() {
        let merged = aggregate_index_members(vec![
            (RepositoryType::Proxy, Present(vec![ve("9", None)])),
            (
                RepositoryType::Staging,
                Present(vec![ve("1", Some(QuarantineStatus::Quarantined))]),
            ),
        ]);
        assert_eq!(vers(merged), vec!["1".to_string()]);
    }

    #[test]
    fn aggregate_unavailable_non_proxy_is_failclosed_owner() {
        // The trusted owner errored — ownership indeterminate → proxies stay
        // suppressed (no confusion window during the outage). The errored
        // member contributes nothing, so the package looks absent rather than
        // being served from the proxy.
        let merged = aggregate_index_members(vec![
            (RepositoryType::Hosted, Unavailable),
            (RepositoryType::Proxy, Present(vec![ve("9.9.9", None)])),
        ]);
        assert!(
            vers(merged).is_empty(),
            "proxy must not serve a name a failed non-proxy member might own"
        );
    }

    #[test]
    fn aggregate_unavailable_proxy_is_skipped_when_unowned() {
        // No non-proxy owner; one proxy errored (contributes nothing), another
        // proxy serves normally.
        let merged = aggregate_index_members(vec![
            (RepositoryType::Proxy, Unavailable),
            (RepositoryType::Proxy, Present(vec![ve("2.0.0", None)])),
        ]);
        assert_eq!(vers(merged), vec!["2.0.0".to_string()]);
    }

    #[test]
    fn aggregate_empty_input_is_empty() {
        assert!(aggregate_index_members(Vec::new()).is_empty());
    }

    #[test]
    fn merge_collision_higher_priority_wins_including_status() {
        // Higher-priority member holds 1.0.0 Quarantined; lower-priority has it
        // Released. The held entry wins — no substitution.
        let merged = merge_members_authoritative(vec![
            vec![ve("1.0.0", Some(QuarantineStatus::Quarantined))],
            vec![ve("1.0.0", Some(QuarantineStatus::Released))],
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].version, "1.0.0");
        assert!(matches!(
            merged[0].status,
            Some(QuarantineStatus::Quarantined)
        ));
    }

    #[test]
    fn merge_disjoint_versions_union_in_priority_order() {
        let merged = merge_members_authoritative(vec![vec![ve("1", None)], vec![ve("2", None)]]);
        let got: Vec<String> = merged.into_iter().map(|e| e.version).collect();
        assert_eq!(got, vec!["1".to_string(), "2".to_string()]);
    }

    #[test]
    fn merge_single_member_passthrough() {
        let merged = merge_members_authoritative(vec![vec![ve("1", None), ve("2", None)]]);
        let got: Vec<String> = merged.into_iter().map(|e| e.version).collect();
        assert_eq!(got, vec!["1".to_string(), "2".to_string()]);
    }

    #[test]
    fn merge_empty_inputs_are_empty() {
        assert!(merge_members_authoritative(Vec::new()).is_empty());
        assert!(merge_members_authoritative(vec![vec![], vec![]]).is_empty());
    }

    /// Sister test to
    /// [`tests::npm_per_version_payload_has_required_fields`]. Pins the
    /// `Pypi` variant carries a [`PypiVersionPayload`] whose `files`
    /// vector and per-file fields match the closed-sum contract the
    /// builders consume.
    #[test]
    fn pypi_per_version_payload_has_required_fields() {
        let file = PypiVersionFile {
            filename: "requests-2.31.0.tar.gz".into(),
            hash_sha256: Some("abc123".into()),
            requires_python: Some(">=3.7".into()),
            metadata_hash: None,
        };
        let payload = PypiVersionPayload {
            files: vec![file.clone()],
        };
        let wrapped = PerVersionPayload::Pypi(payload.clone());
        match wrapped {
            PerVersionPayload::Pypi(p) => {
                assert_eq!(p.files.len(), 1);
                assert_eq!(p.files[0].filename, "requests-2.31.0.tar.gz");
                assert_eq!(p.files[0].hash_sha256.as_deref(), Some("abc123"));
                assert_eq!(p.files[0].requires_python.as_deref(), Some(">=3.7"));
            }
            PerVersionPayload::Npm(_) => {
                unreachable!("pypi fixture must produce a Pypi payload")
            }
            PerVersionPayload::Cargo(_) => {
                unreachable!("pypi fixture must produce a Pypi payload")
            }
        }
        let _ = payload.clone();
        let _ = file.clone();
    }

    /// Sister test to
    /// [`tests::npm_per_version_payload_has_required_fields`] and
    /// [`tests::pypi_per_version_payload_has_required_fields`]. Pins
    /// the `Cargo` variant carries a [`CargoVersionPayload`] whose
    /// fields match the NDJSON-line contract the builder consumes.
    #[test]
    fn cargo_per_version_payload_has_required_fields() {
        let payload = CargoVersionPayload {
            name_as_published: "serde".into(),
            vers: "1.0.0".into(),
            cksum: "a".repeat(64),
            deps: serde_json::json!([]),
            features: serde_json::json!({}),
            yanked: false,
            links: None,
            rust_version: Some("1.70".into()),
            v: None,
            features2: None,
        };
        let wrapped = PerVersionPayload::Cargo(payload.clone());
        match wrapped {
            PerVersionPayload::Cargo(p) => {
                assert_eq!(p.name_as_published, "serde");
                assert_eq!(p.vers, "1.0.0");
                assert_eq!(p.cksum.len(), 64);
                assert!(p.deps.is_array());
                assert!(p.features.is_object());
                assert!(!p.yanked);
                assert!(p.links.is_none());
                assert_eq!(p.rust_version.as_deref(), Some("1.70"));
                assert!(p.v.is_none());
                assert!(p.features2.is_none());
            }
            PerVersionPayload::Npm(_) | PerVersionPayload::Pypi(_) => {
                unreachable!("cargo fixture must produce a Cargo payload")
            }
        }
        let _ = payload.clone();
    }
}
