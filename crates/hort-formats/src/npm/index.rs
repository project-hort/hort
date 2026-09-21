//! npm `IndexBuilder` — the reference implementation for the Source →
//! Filter → Builder pipeline (see explanation/index-construction.md).
//!
//! This module ships the npm-side of the pipeline:
//!
//! - [`NpmVersionPayload`] (re-exported from
//!   [`hort_app::use_cases::index_serve`] — defined there for dep-graph
//!   reasons, see that module's "Dep direction" note) — the per-version
//!   data the builder consumes.
//! - [`NpmIndexBuilder`] — the [`IndexBuilder`] impl that emits the
//!   packument JSON from a `Vec<VersionEntry>` whose entries' payload
//!   is `PerVersionPayload::Npm(NpmVersionPayload)`.
//!
//! # What the builder emits
//!
//! Given `entries` post-filter, the builder produces the npm packument
//! wire shape:
//!
//! ```json
//! {
//!   "name": "<package_name>",
//!   "versions": {
//!     "<v>": {
//!       "name": "<NpmVersionPayload.name_as_published>",
//!       "version": "<v>",
//!       "dist": {
//!         "tarball": "<base_url>/npm/<repo_key derived from base_url+pkg>/<name>/-/<basename>",
//!         "shasum":  "<sha1-hex>",
//!         "integrity": "<sri>"   // present iff payload.integrity.is_some()
//!       },
//!       // …plus each install-v1 whitelist key the payload's `manifest`
//!       // carries (`dependencies`, `engines`, `deprecated`, …), verbatim.
//!       // A key the source did not publish is simply absent.
//!     },
//!     ...
//!   },
//!   // The served tag map (stored map ∩ served set) plus the derived
//!   // `latest` fallback. Omitted entirely when `entries` is empty.
//!   "dist-tags": { "latest": "1.2.3", "next": "2.0.0-rc.1" },
//!   // Diagnostic only — outside the resolution surface. Omitted
//!   // entirely when nothing is held. See the section below.
//!   "hort": { "held": [ { "version": "7.29.7", "status": "quarantined",
//!                         "available_after": "2026-08-26T08:18:00Z" } ] }
//! }
//! ```
//!
//! # The `hort.held` block
//!
//! `versions{}` and `dist-tags` carry only what hort will serve, so a
//! version the filter pipeline withheld is absent from both. Absent from
//! the catalog reads as "this version does not exist" — while the same
//! registry's content route answers that exact version with `503` and a
//! `Retry-After`. The two surfaces contradicting each other is a
//! diagnosis trap: a pinned install fails, the catalog is consulted, and
//! the version looks like it was never published.
//!
//! The block closes that without touching the resolution surface.
//! `versions{}` and `dist-tags` are byte-identical to what the same input
//! produced before it existed — a range, a bare install or `latest` still
//! cannot resolve to something that would `503`, which is the whole
//! reason the filter drops those versions. What changes is only that the
//! catalog now says *why* a version is missing instead of being silent
//! about it.
//!
//! Three rules carry the honesty of the block:
//!
//! - **Omitted when nothing is held.** The common packument must not grow
//!   a key.
//! - **`status` distinguishes a timed hold from a verdict**
//!   ([`HeldReason`]). Describing a `rejected` version as held-until-`T`
//!   would be a lie in the opposite direction from the one this fixes, so
//!   [`HeldVersion::new`] drops an `available_after` offered for one.
//! - **`available_after` is absent when unknown**, never a guess. It
//!   comes from the same anchor + resolved policy duration the content
//!   route's `Retry-After` is computed from
//!   (`ArtifactUseCase::package_hold_deadlines` and
//!   `ArtifactUseCase::hydrate_quarantine_deadline` share one window
//!   resolver), so the two surfaces cannot name different instants.
//!
//! # `dist-tags` invariant
//!
//! The map the builder emits is the **stored** tag map — upstream's for
//! a proxy repo, the maintainer's `mutable_refs` rows for a hosted one —
//! already intersected with the served set by [`intersect_dist_tags`].
//! A tag whose target version is not served is dropped, never rewritten.
//! Tags are otherwise emitted verbatim: hort is not their author.
//!
//! `latest` is the one tag the builder will synthesise, and only when
//! the served map has none (the stored `latest` was dropped by the
//! intersection, or was never set). Then it points at the
//! **resolved-latest of the served set, excluding pre-releases** —
//! i.e. the max over `entries` per [`BuildContext::ordering`] whose
//! [`VersionOrdering::is_prerelease`](hort_app::use_cases::index_serve_filter::VersionOrdering::is_prerelease)
//! is `false`, computed *after* the filter pipeline. This mirrors the
//! npm ecosystem contract: a pre-release is never `latest` while any
//! release is served, so a bare `npm i`/`pnpm add` never installs a
//! canary. If every served entry is a pre-release, `latest` falls back
//! to the pre-release max (a pre-release-only package still gets a
//! usable tag) — the builder sees only post-filter entries, so this
//! fallback IS the served-max in that case. An empty served set
//! produces a packument with empty `versions{}` and **no `dist-tags`
//! block at all** — a client following an absent `latest` falls back to
//! its lockfile or fails the same way as "nothing servable".
//!
//! # URL construction
//!
//! The full `dist.tarball` URL is
//! `{base_url}/<name_as_published>/-/<tarball_basename>` where
//! `base_url` is the per-call [`BuildContext::base_url`] (already
//! includes `/npm/{repo_key}` — the per-format serve handler composes
//! it before invoking the builder). The builder is content-type-
//! agnostic about `base_url`; it just concatenates with `/`.
//!
//! Per-version `name` is the [`NpmVersionPayload::name_as_published`]
//! field — npm permits a published `name` different from the route
//! (drift-resilience on hosted; arbitrary upstream-declared names on
//! proxy), so this is preserved verbatim. The hosted source uses
//! `Artifact.name` (the stored normalised form); the proxy source
//! uses upstream's per-version `name` after the canonical
//! [`validate_npm_name`](crate::npm::validate_npm_name) check.
//!
//! # Why the per-version field set is a whitelist
//!
//! The unified packument carries exactly what [`NpmVersionPayload`]
//! declares: the `name`/`version`/`dist` triple plus
//! [`NPM_INSTALL_V1_MANIFEST_KEYS`](crate::npm::NPM_INSTALL_V1_MANIFEST_KEYS)
//! — the npm registry API's abbreviated-metadata (install-v1) field set,
//! which is what an installer needs to resolve a dependency tree. Full
//! packument equality is deliberately not the target: no `time`, no
//! `maintainers`, no `bugs`, no README, no `scripts`, no
//! `devDependencies`. Carrying arbitrary upstream extras would need a
//! passthrough-blob escape hatch on the closed payload sum that is the
//! spine of the format-agnostic pipeline; a fixed whitelist keeps the
//! served surface a contract both sources can satisfy verbatim.
//!
//! # Tests
//!
//! Builder tests (this module) cover every branch on `entries`:
//! empty set (no `versions{}` keys, no `dist-tags`), single-version
//! set (all four `NpmVersionPayload` fields rendered), multi-version
//! set (semver-correct `dist-tags.latest`), and the URL-construction
//! check (`dist.tarball` is built from `base_url + payload.tarball_basename`,
//! NOT from any copied upstream URL — the rewriter cannot leak a raw
//! upstream URL through the builder).
//!
//! Source-adapter tests live in `hort-http-npm/src/index_source.rs`
//! (they need `AppContext` + mocks and so cannot live in `hort-formats`).
//! Anti-enumeration tests live in `hort-http-npm/src/serve.rs`
//! (the unified handler is the anti-enumeration assertion site).

use std::collections::BTreeMap;

use bytes::Bytes;
use chrono::{DateTime, SecondsFormat, Utc};
use hort_app::use_cases::index_serve::{
    BuildContext, IndexBuilder, PerVersionPayload, VersionEntry, VersionOrdering,
};
use hort_domain::entities::artifact::QuarantineStatus;

pub use hort_app::use_cases::index_serve::NpmVersionPayload;

/// Why the served index withholds a version — the value the packument's
/// `hort.held[].status` carries.
///
/// One variant per non-servable [`QuarantineStatus`], so the wire cannot
/// blur a timed hold into a verdict or the other way round. The
/// distinction is the point: a client told a version is *waiting* will
/// retry, and telling it that about a version that was **rejected** is a
/// lie in the opposite direction from the one this block exists to fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldReason {
    /// A timed hold pending a verdict — the observation window has not
    /// elapsed. Resolves on its own; the only reason that carries an
    /// `available_after`.
    Quarantined,
    /// A verdict was reached and it was negative. Terminal: no deadline,
    /// nothing to wait for.
    Rejected,
    /// The scanner could not decide. Terminal and fail-closed, with no
    /// self-resolving deadline (ADR 0007).
    ScanIndeterminate,
}

impl HeldReason {
    /// Classify a status the served index withholds, or `None` for one it
    /// serves.
    ///
    /// Exhaustive over [`QuarantineStatus`] with no wildcard arm: a future
    /// variant is a compile error here rather than silently becoming
    /// either "served" or "held". This mirrors
    /// `hort_app::use_cases::index_filters::HeldVisibility::admits`, whose
    /// `Hidden` row decides which versions reach this block in the first
    /// place — the two must keep agreeing about which statuses are
    /// non-servable.
    pub fn from_status(status: QuarantineStatus) -> Option<Self> {
        match status {
            QuarantineStatus::Released | QuarantineStatus::None => None,
            QuarantineStatus::Quarantined => Some(Self::Quarantined),
            QuarantineStatus::Rejected => Some(Self::Rejected),
            QuarantineStatus::ScanIndeterminate => Some(Self::ScanIndeterminate),
        }
    }

    /// The wire token. Snake-case, matching the status vocabulary the
    /// rest of hort's JSON surfaces use.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
            Self::ScanIndeterminate => "scan_indeterminate",
        }
    }
}

/// One withheld version, as the packument's `hort.held[]` array carries
/// it.
///
/// Constructed through [`HeldVersion::new`], which drops a deadline
/// supplied for anything but [`HeldReason::Quarantined`]: the
/// "a verdict is never presented as pending" rule is enforced by the
/// type, not by each caller remembering it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldVersion {
    /// The withheld version string, exactly as the source produced it —
    /// the same spelling a client would have pinned in its lockfile.
    pub version: String,
    /// Why it is withheld.
    pub reason: HeldReason,
    /// When the hold elapses, for a timed hold whose deadline is known.
    /// `None` is emitted as an **absent** field, never `null` or a zero
    /// instant: an absent field is honest about not knowing, a guessed
    /// timestamp is not.
    pub available_after: Option<DateTime<Utc>>,
}

impl HeldVersion {
    /// Build an entry, keeping `available_after` only where it can be
    /// true. A terminal verdict has no deadline by definition, so one
    /// offered for a `Rejected` / `ScanIndeterminate` version is dropped
    /// rather than emitted.
    pub fn new(
        version: String,
        reason: HeldReason,
        available_after: Option<DateTime<Utc>>,
    ) -> Self {
        let available_after = match reason {
            HeldReason::Quarantined => available_after,
            HeldReason::Rejected | HeldReason::ScanIndeterminate => None,
        };
        Self {
            version,
            reason,
            available_after,
        }
    }

    /// The `hort.held[]` element: `{version, status, available_after?}`.
    fn to_json(&self) -> serde_json::Value {
        let mut out = serde_json::Map::with_capacity(3);
        out.insert(
            "version".to_string(),
            serde_json::Value::String(self.version.clone()),
        );
        out.insert(
            "status".to_string(),
            serde_json::Value::String(self.reason.wire().to_string()),
        );
        if let Some(deadline) = self.available_after {
            out.insert(
                "available_after".to_string(),
                serde_json::Value::String(deadline.to_rfc3339_opts(SecondsFormat::Secs, true)),
            );
        }
        serde_json::Value::Object(out)
    }
}

/// Intersect a stored `dist-tags` map with the **post-filter served
/// set**: a tag whose target version is not served is DROPPED, never
/// rewritten to something that is.
///
/// This is the whole of the pass-through contract's safety property. The
/// stored map is authored elsewhere — upstream for a proxy repo, the
/// maintainer's `mutable_refs` rows for a hosted one — and neither
/// author knows what hort will serve. Rewriting a dropped tag to a
/// nearby served version would silently hand a client a different
/// artifact than the tag names; dropping it makes the tag absent, which
/// every npm client already handles.
///
/// `latest` is NOT special here: this function is pure intersection.
/// The "dropped or absent `latest` falls back to
/// [`resolve_served_latest`]" half of the contract lives at the two
/// emission sites ([`NpmIndexBuilder::build`] and the abbreviated
/// per-version/tag route), so the derivation keeps exactly one
/// definition.
pub fn intersect_dist_tags(
    stored: &BTreeMap<String, String>,
    entries: &[VersionEntry],
) -> BTreeMap<String, String> {
    if stored.is_empty() {
        return BTreeMap::new();
    }
    let served: std::collections::HashSet<&str> =
        entries.iter().map(|e| e.version.as_str()).collect();
    stored
        .iter()
        .filter(|(_, version)| served.contains(version.as_str()))
        .map(|(tag, version)| (tag.clone(), version.clone()))
        .collect()
}

/// Resolve `dist-tags.latest` over a **post-filter served** set: the
/// max non-prerelease version per `ordering`, falling back to the
/// unfiltered max only when every served entry is a prerelease.
/// `None` for an empty served set — the wire-equivalent of "nothing
/// servable" (no `dist-tags` block in the packument, 404 on the
/// abbreviated per-version `latest` route).
///
/// This is the single definition of the npm ecosystem's "a pre-release
/// never wins `latest` while a release is served" contract
/// (see the module docs above); [`NpmIndexBuilder::build`] and the
/// abbreviated per-version/tag route (`hort-http-npm::serve`) both
/// call it so the invariant cannot drift between the two callers.
pub fn resolve_served_latest<'a>(
    entries: &'a [VersionEntry],
    ordering: &dyn VersionOrdering,
) -> Option<&'a str> {
    entries
        .iter()
        .map(|e| e.version.as_str())
        .filter(|v| !ordering.is_prerelease(v))
        .max_by(|a, b| ordering.compare(a, b))
        .or_else(|| {
            entries
                .iter()
                .map(|e| e.version.as_str())
                .max_by(|a, b| ordering.compare(a, b))
        })
}

/// Compose the per-version JSON object shared by the full packument
/// builder and the abbreviated per-version route: `name`, `version`,
/// `dist`, then the install-v1 manifest whitelist the payload carries,
/// merged in verbatim. A whitelist key is never `name`/`version`/`dist`,
/// so the merge cannot displace the triple.
/// `None` for a non-`Npm` payload (cross-format mis-tag — see
/// [`NpmIndexBuilder::build`]'s panics section).
pub fn version_entry_json(base_url: &str, entry: &VersionEntry) -> Option<serde_json::Value> {
    let PerVersionPayload::Npm(payload) = &entry.payload else {
        return None;
    };

    let tarball_url = format!(
        "{base_url}/{name}/-/{basename}",
        name = payload.name_as_published,
        basename = payload.tarball_basename,
    );
    let mut dist = serde_json::Map::new();
    dist.insert(
        "tarball".to_string(),
        serde_json::Value::String(tarball_url),
    );
    dist.insert(
        "shasum".to_string(),
        serde_json::Value::String(payload.shasum.clone()),
    );
    if let Some(sri) = payload.integrity.as_ref() {
        dist.insert(
            "integrity".to_string(),
            serde_json::Value::String(sri.clone()),
        );
    }

    let mut out = serde_json::Map::with_capacity(3 + payload.manifest.len());
    out.insert(
        "name".to_string(),
        serde_json::Value::String(payload.name_as_published.clone()),
    );
    out.insert(
        "version".to_string(),
        serde_json::Value::String(entry.version.clone()),
    );
    out.insert("dist".to_string(), serde_json::Value::Object(dist));
    for (key, value) in &payload.manifest {
        out.insert(key.clone(), value.clone());
    }
    Some(serde_json::Value::Object(out))
}

/// npm `IndexBuilder` — emits the packument JSON from a post-filter
/// `Vec<VersionEntry>`.
///
/// Carries the request's **served** `dist-tags` map — the stored map
/// already intersected with the served set by [`intersect_dist_tags`].
/// The per-format serve handler constructs one instance per request, so
/// the builder holds no state across requests; the map is per-call input
/// that is not per-version, exactly like [`BuildContext`]'s fields. It
/// lives on the builder rather than on `BuildContext` because
/// `BuildContext` is the format-agnostic seam every builder shares
/// (PyPI, Cargo, Maven), and a tag map is npm's own entity — putting it
/// there would make three other formats carry a field they can only pass
/// empty.
///
/// [`Self::default()`] builds with no stored tags, which is the
/// pre-pass-through behaviour: `dist-tags.latest` is derived from the
/// served set alone.
///
/// # Panics
///
/// Never panics on a well-formed input. A `VersionEntry` carrying a
/// non-`Npm` `PerVersionPayload` variant is the only ill-formed
/// shape; the builder skips such entries with a structured `warn!`
/// and emits a degraded packument (the entry is simply absent from
/// `versions{}`). This is a defence-in-depth posture against a
/// hypothetical future source adapter that mis-tags its payloads;
/// today the only constructible variant is `Npm`, so the warn arm
/// is unreachable on the production hot path. Pinning it behind a
/// warn rather than a `panic!` keeps the serve-time error mode the
/// same as `rewrite_packument`'s parse-failure passthrough.
#[derive(Debug, Default, Clone)]
pub struct NpmIndexBuilder {
    /// Served `dist-tags` — the stored map ∩ the served set. Emitted
    /// verbatim; the only value this builder ever synthesises is the
    /// `latest` fallback below.
    dist_tags: BTreeMap<String, String>,
    /// The versions the filter pipeline withheld, for the diagnostic
    /// `hort.held` block. Empty — the default — emits no `hort` key at
    /// all, so a packument with nothing held keeps exactly the shape it
    /// had before this block existed.
    held: Vec<HeldVersion>,
}

impl NpmIndexBuilder {
    /// Build with an already-intersected tag map (see
    /// [`intersect_dist_tags`]). Entries are emitted verbatim.
    pub fn new(dist_tags: BTreeMap<String, String>) -> Self {
        Self {
            dist_tags,
            held: Vec::new(),
        }
    }

    /// Attach the withheld-version list the `hort.held` block reports.
    ///
    /// Separate from [`Self::new`] because it is optional in the strong
    /// sense: an empty list is not merely a degenerate case but the
    /// common one, and it must leave the emitted packument byte-identical
    /// to a build that never called this.
    #[must_use]
    pub fn with_held(mut self, held: Vec<HeldVersion>) -> Self {
        self.held = held;
        self
    }
}

impl IndexBuilder for NpmIndexBuilder {
    fn build(&self, ctx: BuildContext<'_>, entries: Vec<VersionEntry>) -> Bytes {
        // `latest` fallback: the served tag map wins verbatim when it
        // carries one (the maintainer's / upstream's choice survived the
        // intersection). Only a dropped or absent `latest` is derived —
        // the max over non-prerelease entries, falling back to the
        // unfiltered max when the served set is all-prerelease. An empty
        // served set produces no `dist-tags` block at all (the
        // wire-equivalent of "no servable latest").
        let mut dist_tags = if entries.is_empty() {
            // Nothing servable → no tags at all, whatever was stored. In
            // production the intersection has already emptied the map;
            // the guard is here so the "no dist-tags block for an empty
            // served set" invariant holds at the emission site itself.
            BTreeMap::new()
        } else {
            self.dist_tags.clone()
        };
        if !entries.is_empty() && !dist_tags.contains_key("latest") {
            if let Some(derived) = resolve_served_latest(&entries, ctx.ordering) {
                dist_tags.insert("latest".to_string(), derived.to_string());
            }
        }

        let mut versions = serde_json::Map::new();
        for entry in &entries {
            // Cross-format mis-tag defence: a Pypi/Cargo payload
            // should never reach the npm builder, but the closed-sum is
            // enforced at the use-case layer not at the builder layer,
            // so the match arm is reachable in principle. Skip with a
            // structured warn (degraded packument, never a panic).
            match version_entry_json(ctx.base_url, entry) {
                Some(v) => {
                    versions.insert(entry.version.clone(), v);
                }
                None => {
                    tracing::warn!(
                        version = %entry.version,
                        "npm packument builder: skipping VersionEntry with non-Npm payload \
                         (cross-format mis-tag — should be unreachable)",
                    );
                }
            }
        }

        let mut packument = serde_json::Map::new();
        packument.insert(
            "name".to_string(),
            serde_json::Value::String(ctx.package_name.to_string()),
        );
        packument.insert("versions".to_string(), serde_json::Value::Object(versions));
        // Empty served set → empty tag map → no `dist-tags` block at
        // all. Wire-shape for "nothing servable"; the client falls back
        // to lockfile-or-error.
        if !dist_tags.is_empty() {
            let wire: serde_json::Map<String, serde_json::Value> = dist_tags
                .into_iter()
                .map(|(tag, version)| (tag, serde_json::Value::String(version)))
                .collect();
            packument.insert("dist-tags".to_string(), serde_json::Value::Object(wire));
        }

        // The held block is additive and lives OUTSIDE the resolution
        // surface: it is not `versions{}` and not `dist-tags`, so no
        // resolver can reach a withheld version through it. It exists
        // because a version dropped from both of those is otherwise
        // indistinguishable from one that never existed — which is what
        // the content route already contradicts by answering a held
        // version with `503` rather than `404`.
        //
        // Omitted entirely when nothing is held, so the common packument
        // does not grow a key.
        if !self.held.is_empty() {
            let held: Vec<serde_json::Value> = self.held.iter().map(HeldVersion::to_json).collect();
            let mut hort = serde_json::Map::with_capacity(1);
            hort.insert("held".to_string(), serde_json::Value::Array(held));
            packument.insert("hort".to_string(), serde_json::Value::Object(hort));
        }

        // `serde_json::to_vec` on a `serde_json::Map` is infallible
        // (no non-string keys, no `f64::NAN` floats — the input is
        // built entirely from `Value::String` and `Value::Object`).
        // `expect` documents the invariant.
        let bytes = serde_json::to_vec(&serde_json::Value::Object(packument))
            .expect("NpmIndexBuilder serialises owned String / Object values only");
        Bytes::from(bytes)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use hort_app::use_cases::index_serve_filter::NpmSemverOrdering;
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::repository::IndexMode;

    use super::*;

    fn entry(version: &str, payload: NpmVersionPayload) -> VersionEntry {
        VersionEntry {
            version: version.to_string(),
            status: Some(QuarantineStatus::Released),
            payload: PerVersionPayload::Npm(payload),
        }
    }

    fn payload(
        name: &str,
        basename: &str,
        integrity: Option<&str>,
        shasum: &str,
    ) -> NpmVersionPayload {
        NpmVersionPayload {
            name_as_published: name.to_string(),
            tarball_basename: basename.to_string(),
            integrity: integrity.map(str::to_string),
            shasum: shasum.to_string(),
            manifest: serde_json::Map::new(),
        }
    }

    fn build(entries: Vec<VersionEntry>, package: &str, base: &str) -> serde_json::Value {
        build_with_tags(entries, package, base, BTreeMap::new())
    }

    fn build_with_tags(
        entries: Vec<VersionEntry>,
        package: &str,
        base: &str,
        dist_tags: BTreeMap<String, String>,
    ) -> serde_json::Value {
        let bytes = NpmIndexBuilder::new(dist_tags).build(
            BuildContext {
                package_name: package,
                base_url: base,
                index_mode: IndexMode::ReleasedOnly,
                ordering: &NpmSemverOrdering,
            },
            entries,
        );
        serde_json::from_slice(&bytes).expect("builder emits valid JSON")
    }

    // -----------------------------------------------------------------
    // 1. Empty served set → packument with empty `versions{}` and NO
    //    `dist-tags` block.
    // -----------------------------------------------------------------

    #[test]
    fn empty_entries_produces_packument_with_empty_versions_and_no_dist_tags() {
        let json = build(Vec::new(), "express", "https://r.example/npm/m");
        assert_eq!(json["name"].as_str().unwrap(), "express");
        assert!(
            json["versions"].as_object().unwrap().is_empty(),
            "empty entries must produce an empty versions{{}} object"
        );
        assert!(
            json.get("dist-tags").is_none(),
            "empty entries must NOT emit a dist-tags block (dist-tags.latest regression guard)"
        );
    }

    // -----------------------------------------------------------------
    // 2. Single-version set — all four NpmVersionPayload fields render
    //    correctly. Pins the per-field emission contract.
    // -----------------------------------------------------------------

    #[test]
    fn single_version_emits_full_dist_block_with_all_fields() {
        let p = payload(
            "express",
            "express-1.0.0.tgz",
            Some("sha512-aGVsbG8="),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        );
        let json = build(
            vec![entry("1.0.0", p)],
            "express",
            "https://r.example/npm/m",
        );
        let v = &json["versions"]["1.0.0"];
        assert_eq!(v["name"].as_str().unwrap(), "express");
        assert_eq!(v["version"].as_str().unwrap(), "1.0.0");
        assert_eq!(
            v["dist"]["tarball"].as_str().unwrap(),
            "https://r.example/npm/m/express/-/express-1.0.0.tgz",
            "dist.tarball must be built from base_url + name_as_published + tarball_basename"
        );
        assert_eq!(
            v["dist"]["shasum"].as_str().unwrap(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(v["dist"]["integrity"].as_str().unwrap(), "sha512-aGVsbG8=");
        assert_eq!(json["dist-tags"]["latest"].as_str().unwrap(), "1.0.0");
    }

    #[test]
    fn manifest_whitelist_merges_alongside_the_name_version_dist_triple() {
        let mut p = payload("express", "express-1.0.0.tgz", None, "abc123");
        p.manifest = crate::npm::extract_install_v1_manifest(&serde_json::json!({
            "name": "express",
            "dependencies": {"body-parser": "^1.20.0"},
            "engines": {"node": ">=18"},
            "deprecated": "moved to @express/core",
            "scripts": {"test": "mocha"},
        }));
        let json = build(
            vec![entry("1.0.0", p)],
            "express",
            "https://r.example/npm/m",
        );
        let v = &json["versions"]["1.0.0"];
        // The triple survives the merge.
        assert_eq!(v["name"].as_str().unwrap(), "express");
        assert_eq!(v["version"].as_str().unwrap(), "1.0.0");
        assert_eq!(
            v["dist"]["tarball"].as_str().unwrap(),
            "https://r.example/npm/m/express/-/express-1.0.0.tgz"
        );
        // Whitelist keys ride alongside it, verbatim.
        assert_eq!(
            v["dependencies"],
            serde_json::json!({"body-parser": "^1.20.0"})
        );
        assert_eq!(v["engines"], serde_json::json!({"node": ">=18"}));
        assert_eq!(v["deprecated"].as_str().unwrap(), "moved to @express/core");
        // Out-of-contract keys never reach the wire.
        assert!(v.get("scripts").is_none());
        // Absent whitelist keys are absent, not null.
        assert!(v.get("os").is_none());
        assert!(v.get("optionalDependencies").is_none());
    }

    #[test]
    fn empty_manifest_emits_exactly_the_name_version_dist_triple() {
        let p = payload("express", "express-1.0.0.tgz", None, "abc123");
        let json = build(
            vec![entry("1.0.0", p)],
            "express",
            "https://r.example/npm/m",
        );
        let mut keys: Vec<&str> = json["versions"]["1.0.0"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["dist", "name", "version"]);
    }

    // -----------------------------------------------------------------
    // 3. `integrity = None` — the key is OMITTED, not emitted as null.
    //    Mirrors the npm convention (`dist.integrity` absent on legacy
    //    sources rather than `null`).
    // -----------------------------------------------------------------

    #[test]
    fn absent_integrity_omits_the_key_rather_than_emitting_null() {
        let p = payload("hosted-pkg", "hosted-pkg-1.0.0.tgz", None, "abc123");
        let json = build(
            vec![entry("1.0.0", p)],
            "hosted-pkg",
            "https://r.example/npm/m",
        );
        let dist = &json["versions"]["1.0.0"]["dist"];
        assert!(
            dist.get("integrity").is_none(),
            "absent integrity must be omitted, NOT emitted as null"
        );
        assert_eq!(dist["shasum"].as_str().unwrap(), "abc123");
        assert!(
            dist["tarball"].as_str().is_some(),
            "tarball must still emit when integrity is absent"
        );
    }

    // -----------------------------------------------------------------
    // 4. Multi-version semver — `dist-tags.latest` is the semver-max,
    //    not the lex-max. Pins NpmSemverOrdering hooked correctly.
    // -----------------------------------------------------------------

    #[test]
    fn dist_tags_latest_is_semver_max_not_lex_max() {
        let entries = vec![
            entry("1.9.0", payload("p", "p-1.9.0.tgz", None, "a")),
            entry("1.10.0", payload("p", "p-1.10.0.tgz", None, "b")),
            entry("1.2.0", payload("p", "p-1.2.0.tgz", None, "c")),
        ];
        let json = build(entries, "p", "https://r.example/npm/m");
        // Lex-max would pick "1.9.0" (> "1.10.0" in lex order); semver
        // picks "1.10.0". The builder must take the ordering from
        // BuildContext, so this proves NpmSemverOrdering reaches the
        // builder correctly.
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "1.10.0",
            "dist-tags.latest must use NpmSemverOrdering, not lex"
        );
        // All three versions must appear in versions{}.
        let versions = json["versions"].as_object().unwrap();
        assert_eq!(versions.len(), 3);
        assert!(versions.contains_key("1.2.0"));
        assert!(versions.contains_key("1.9.0"));
        assert!(versions.contains_key("1.10.0"));
    }

    // -----------------------------------------------------------------
    // 4b. dist-tags.latest excludes a semver-greater prerelease while a
    //     release is served — the npm ecosystem contract that a bare
    //     `npm i`/`pnpm add` never installs a canary.
    // -----------------------------------------------------------------

    #[test]
    fn dist_tags_latest_excludes_prerelease_when_release_is_served() {
        let entries = vec![
            entry("1.2.8", payload("p", "p-1.2.8.tgz", None, "a")),
            entry(
                "1.3.0-canary.0",
                payload("p", "p-1.3.0-canary.0.tgz", None, "b"),
            ),
        ];
        let json = build(entries, "p", "https://r.example/npm/m");
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "1.2.8",
            "a prerelease must never win latest while a release is served, \
             even though it is semver-greater"
        );
        let versions = json["versions"].as_object().unwrap();
        assert!(
            versions.contains_key("1.3.0-canary.0"),
            "the prerelease is still SERVED, only excluded from dist-tags.latest"
        );
    }

    #[test]
    fn dist_tags_latest_falls_back_to_prerelease_max_when_all_prerelease() {
        let entries = vec![
            entry("1.0.0-alpha.1", payload("p", "p-a1.tgz", None, "a")),
            entry("1.0.0-alpha.2", payload("p", "p-a2.tgz", None, "b")),
        ];
        let json = build(entries, "p", "https://r.example/npm/m");
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "1.0.0-alpha.2",
            "an all-prerelease served set still gets a usable latest tag"
        );
    }

    #[test]
    fn dist_tags_latest_build_metadata_only_version_treated_as_release() {
        let entries = vec![
            entry("1.0.0+build.5", payload("p", "p-b5.tgz", None, "a")),
            entry("1.0.0-rc.1", payload("p", "p-rc1.tgz", None, "b")),
        ];
        let json = build(entries, "p", "https://r.example/npm/m");
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "1.0.0+build.5",
            "build metadata alone is not a prerelease; it must beat an actual \
             prerelease for latest"
        );
    }

    // -----------------------------------------------------------------
    // 5. Scoped package — name_as_published carries the `@scope/pkg`
    //    form and the URL embeds it verbatim. Matches the npm
    //    public-registry convention and the existing local-CAS
    //    handler's emission shape.
    // -----------------------------------------------------------------

    #[test]
    fn scoped_package_emits_unencoded_scope_in_tarball_url() {
        let p = payload("@types/node", "node-20.0.0.tgz", Some("sha512-yyy"), "def");
        let json = build(
            vec![entry("20.0.0", p)],
            "@types/node",
            "https://r.example/npm/m",
        );
        let v = &json["versions"]["20.0.0"];
        assert_eq!(v["name"].as_str().unwrap(), "@types/node");
        assert_eq!(
            v["dist"]["tarball"].as_str().unwrap(),
            "https://r.example/npm/m/@types/node/-/node-20.0.0.tgz",
            "scoped tarball URL must carry the `@scope/pkg` segment unencoded"
        );
    }

    // -----------------------------------------------------------------
    // 6. URL construction comes ONLY from base_url + payload, NEVER
    //    leaks a raw upstream URL through. Pins the architectural
    //    contract: the builder is the URL-construction site, not the
    //    rewriter. (If a future regression had the source adapter
    //    stash an upstream URL in some payload field and the builder
    //    emitted it, this test catches it — no upstream-shape value
    //    survives the builder.)
    // -----------------------------------------------------------------

    #[test]
    fn url_construction_uses_base_url_and_basename_never_raw_upstream() {
        // basename is just `pkg-1.0.0.tgz`; the test pins that the
        // emitted URL is base_url + name + "/-/" + basename, with NO
        // upstream host like "registry.npmjs.org" leaking through.
        let p = payload("p", "p-1.0.0.tgz", None, "x");
        let json = build(vec![entry("1.0.0", p)], "p", "http://localhost/npm/m");
        let url = json["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert_eq!(url, "http://localhost/npm/m/p/-/p-1.0.0.tgz");
        assert!(
            !url.contains("registry.npmjs.org"),
            "URL must NOT carry any upstream-host bytes: {url}"
        );
    }

    // -----------------------------------------------------------------
    // 7. Top-level `name` always reflects BuildContext.package_name
    //    verbatim, even when the per-version `name_as_published`
    //    diverges (drift-era hosted artifact case).
    // -----------------------------------------------------------------

    #[test]
    fn top_level_name_reflects_build_context_not_per_version_name() {
        // The drift case: request was for "drift-pkg" but the stored
        // artifact's name is "legacy-name". The hosted source supplies
        // BuildContext.package_name = stored canonical name
        // ("legacy-name"); the top-level `name` reflects that.
        let p = payload("legacy-name", "legacy-name-1.0.0.tgz", None, "x");
        let json = build(
            vec![entry("1.0.0", p)],
            "legacy-name",
            "https://r.example/npm/m",
        );
        assert_eq!(json["name"].as_str().unwrap(), "legacy-name");
        assert_eq!(
            json["versions"]["1.0.0"]["name"].as_str().unwrap(),
            "legacy-name"
        );
        assert_eq!(
            json["versions"]["1.0.0"]["dist"]["tarball"]
                .as_str()
                .unwrap(),
            "https://r.example/npm/m/legacy-name/-/legacy-name-1.0.0.tgz"
        );
    }

    // -----------------------------------------------------------------
    // `resolve_served_latest` — direct unit tests for the extracted
    // helper (the builder's `dist-tags.latest` derivation, and the
    // abbreviated per-version route's `latest` resolution, both call
    // this one definition).
    // -----------------------------------------------------------------

    #[test]
    fn resolve_served_latest_release_mix_excludes_prerelease() {
        let entries = vec![
            entry("1.2.8", payload("p", "p-1.2.8.tgz", None, "a")),
            entry(
                "1.3.0-canary.0",
                payload("p", "p-1.3.0-canary.0.tgz", None, "b"),
            ),
        ];
        assert_eq!(
            resolve_served_latest(&entries, &NpmSemverOrdering),
            Some("1.2.8"),
            "a prerelease must never win latest while a release is served"
        );
    }

    #[test]
    fn resolve_served_latest_all_prerelease_falls_back_to_prerelease_max() {
        let entries = vec![
            entry("1.0.0-alpha.1", payload("p", "p-a1.tgz", None, "a")),
            entry("1.0.0-alpha.2", payload("p", "p-a2.tgz", None, "b")),
        ];
        assert_eq!(
            resolve_served_latest(&entries, &NpmSemverOrdering),
            Some("1.0.0-alpha.2"),
            "an all-prerelease served set still resolves a usable latest"
        );
    }

    #[test]
    fn resolve_served_latest_empty_set_is_none() {
        assert_eq!(resolve_served_latest(&[], &NpmSemverOrdering), None);
    }

    // -----------------------------------------------------------------
    // dist-tags pass-through: the served map is emitted verbatim, and
    // `latest` is the only tag the builder will ever synthesise.
    // -----------------------------------------------------------------

    fn tags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(t, v)| (t.to_string(), v.to_string()))
            .collect()
    }

    fn three_version_entries() -> Vec<VersionEntry> {
        vec![
            entry("1.2.3", payload("p", "p-1.2.3.tgz", None, "a")),
            entry("2.0.0-rc.1", payload("p", "p-2.0.0-rc.1.tgz", None, "b")),
            entry(
                "2.0.0-beta.4",
                payload("p", "p-2.0.0-beta.4.tgz", None, "c"),
            ),
        ]
    }

    #[test]
    fn served_tag_map_is_emitted_verbatim() {
        let json = build_with_tags(
            three_version_entries(),
            "p",
            "https://r.example/npm/m",
            tags(&[
                ("latest", "1.2.3"),
                ("next", "2.0.0-rc.1"),
                ("beta", "2.0.0-beta.4"),
            ]),
        );
        assert_eq!(
            json["dist-tags"],
            serde_json::json!({
                "latest": "1.2.3",
                "next": "2.0.0-rc.1",
                "beta": "2.0.0-beta.4",
            }),
            "every served tag reaches the wire unaltered"
        );
    }

    #[test]
    fn stored_latest_beats_the_derivation() {
        // The maintainer / upstream pinned `latest` at an older release.
        // That is a deliberate choice, not something to second-guess:
        // the derivation is a fallback, never an override.
        let json = build_with_tags(
            vec![
                entry("1.0.0", payload("p", "p-1.0.0.tgz", None, "a")),
                entry("2.0.0", payload("p", "p-2.0.0.tgz", None, "b")),
            ],
            "p",
            "https://r.example/npm/m",
            tags(&[("latest", "1.0.0")]),
        );
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "1.0.0",
            "a served `latest` is verbatim; the semver-max derivation must not override it"
        );
    }

    #[test]
    fn absent_latest_is_derived_while_other_tags_stay_verbatim() {
        // The intersection dropped `latest` (or the maintainer never set
        // one). `latest` derives; `next` still passes through.
        let json = build_with_tags(
            three_version_entries(),
            "p",
            "https://r.example/npm/m",
            tags(&[("next", "2.0.0-rc.1")]),
        );
        assert_eq!(
            json["dist-tags"]["latest"].as_str().unwrap(),
            "1.2.3",
            "absent latest falls back to the served-set derivation"
        );
        assert_eq!(json["dist-tags"]["next"].as_str().unwrap(), "2.0.0-rc.1");
    }

    #[test]
    fn empty_served_set_emits_no_dist_tags_even_with_stored_tags() {
        // Nothing servable → no `dist-tags` block, whatever the stored
        // map said. (In production the intersection has already emptied
        // it; this pins the builder's own guard.)
        let json = build_with_tags(
            Vec::new(),
            "p",
            "https://r.example/npm/m",
            tags(&[("latest", "1.0.0")]),
        );
        assert!(
            json.get("dist-tags").is_none(),
            "an empty served set must never emit a dist-tags block"
        );
    }

    // -----------------------------------------------------------------
    // The `hort.held` block.
    //
    // Read the first test first: it is the one that protects the property
    // the filter pipeline exists for. Everything else here is about the
    // block's own honesty.
    // -----------------------------------------------------------------

    /// Emit the packument bytes for a given `(entries, tags, held)`
    /// triple — the raw builder output, not a re-serialised `Value`, so
    /// the byte-identity test below compares what actually goes on the
    /// wire.
    fn build_bytes(
        entries: Vec<VersionEntry>,
        base: &str,
        dist_tags: BTreeMap<String, String>,
        held: Vec<HeldVersion>,
    ) -> Bytes {
        NpmIndexBuilder::new(dist_tags).with_held(held).build(
            BuildContext {
                package_name: "p",
                base_url: base,
                index_mode: IndexMode::ReleasedOnly,
                ordering: &NpmSemverOrdering,
            },
            entries,
        )
    }

    fn held_fixture() -> Vec<HeldVersion> {
        vec![
            HeldVersion::new(
                "7.29.7".to_string(),
                HeldReason::Quarantined,
                DateTime::parse_from_rfc3339("2026-08-26T08:18:00Z")
                    .map(|d| d.with_timezone(&Utc))
                    .ok(),
            ),
            HeldVersion::new("6.0.0".to_string(), HeldReason::Rejected, None),
        ]
    }

    #[test]
    fn the_held_block_leaves_the_resolution_surface_byte_identical() {
        // THE regression guard for this whole feature. For one and the
        // same input, the packument with a held block must differ from
        // the packument without it by the added `hort` key and by
        // NOTHING else — so `versions{}` and `dist-tags`, the two
        // members any resolver reads, come out byte for byte as they did
        // before the block existed. A range, a bare install or `latest`
        // therefore still cannot resolve to a version hort would refuse
        // to serve.
        let base = "https://r.example/npm/m";
        let stored = tags(&[("latest", "1.2.3"), ("next", "2.0.0-rc.1")]);

        let baseline = build_bytes(three_version_entries(), base, stored.clone(), Vec::new());
        let with_held = build_bytes(three_version_entries(), base, stored, held_fixture());

        assert_ne!(baseline, with_held, "the block must actually be emitted");

        let mut stripped: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&with_held).expect("builder emits a JSON object");
        stripped
            .remove("hort")
            .expect("the held block is the key that was added");
        assert_eq!(
            serde_json::to_vec(&serde_json::Value::Object(stripped)).unwrap(),
            baseline.to_vec(),
            "the held block must add a key and change nothing else — `versions{{}}` and \
             `dist-tags` are byte-identical to the same input's output without it"
        );
    }

    #[test]
    fn no_hort_key_at_all_when_nothing_is_held() {
        // The common case. A packument for a package with nothing held
        // must not grow a key.
        let json = build(three_version_entries(), "p", "https://r.example/npm/m");
        assert!(
            json.get("hort").is_none(),
            "an empty held list emits no `hort` key: {json}"
        );
    }

    #[test]
    fn held_entry_carries_version_status_and_available_after() {
        let bytes = build_bytes(
            three_version_entries(),
            "https://r.example/npm/m",
            BTreeMap::new(),
            held_fixture(),
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["hort"]["held"][0],
            serde_json::json!({
                "version": "7.29.7",
                "status": "quarantined",
                "available_after": "2026-08-26T08:18:00Z",
            }),
            "a timed hold names itself, says it is a hold, and says when it lifts"
        );
    }

    #[test]
    fn a_rejected_version_is_never_presented_as_pending() {
        // The one way this block can make things worse rather than
        // better: telling a client to wait for a version that was
        // rejected. `HeldVersion::new` drops a deadline offered for a
        // terminal verdict, so the lie is not constructible.
        let deadline = DateTime::parse_from_rfc3339("2026-08-26T08:18:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let held = vec![HeldVersion::new(
            "6.0.0".to_string(),
            HeldReason::Rejected,
            Some(deadline),
        )];
        let bytes = build_bytes(
            three_version_entries(),
            "https://r.example/npm/m",
            BTreeMap::new(),
            held,
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let entry = &json["hort"]["held"][0];
        assert_eq!(entry["status"].as_str().unwrap(), "rejected");
        assert!(
            entry.get("available_after").is_none(),
            "a verdict is not waiting for anything — it must carry no deadline: {entry}"
        );
    }

    #[test]
    fn an_unknown_deadline_is_an_absent_field_not_a_null() {
        let held = vec![HeldVersion::new(
            "7.29.7".to_string(),
            HeldReason::Quarantined,
            None,
        )];
        let bytes = build_bytes(
            three_version_entries(),
            "https://r.example/npm/m",
            BTreeMap::new(),
            held,
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let entry = &json["hort"]["held"][0];
        assert_eq!(entry["status"].as_str().unwrap(), "quarantined");
        assert!(
            entry.get("available_after").is_none(),
            "an unknown deadline is omitted — never null, never a zero instant: {entry}"
        );
    }

    #[test]
    fn held_reason_classifies_exactly_the_non_servable_statuses() {
        // Must agree with `HeldVisibility::Hidden::admits` — the filter
        // decides which versions reach this block, this decides how they
        // are described, and a disagreement would either drop a withheld
        // version from the report or report a served one.
        assert_eq!(HeldReason::from_status(QuarantineStatus::Released), None);
        assert_eq!(HeldReason::from_status(QuarantineStatus::None), None);
        assert_eq!(
            HeldReason::from_status(QuarantineStatus::Quarantined),
            Some(HeldReason::Quarantined)
        );
        assert_eq!(
            HeldReason::from_status(QuarantineStatus::Rejected),
            Some(HeldReason::Rejected)
        );
        assert_eq!(
            HeldReason::from_status(QuarantineStatus::ScanIndeterminate),
            Some(HeldReason::ScanIndeterminate)
        );
    }

    #[test]
    fn held_reason_wire_tokens_are_distinct_and_snake_case() {
        assert_eq!(HeldReason::Quarantined.wire(), "quarantined");
        assert_eq!(HeldReason::Rejected.wire(), "rejected");
        assert_eq!(HeldReason::ScanIndeterminate.wire(), "scan_indeterminate");
    }

    #[test]
    fn scan_indeterminate_is_reported_as_terminal_too() {
        let held = vec![HeldVersion::new(
            "6.0.0".to_string(),
            HeldReason::ScanIndeterminate,
            Some(Utc::now()),
        )];
        let bytes = build_bytes(
            three_version_entries(),
            "https://r.example/npm/m",
            BTreeMap::new(),
            held,
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let entry = &json["hort"]["held"][0];
        assert_eq!(entry["status"].as_str().unwrap(), "scan_indeterminate");
        assert!(
            entry.get("available_after").is_none(),
            "a fail-closed block has no self-resolving deadline: {entry}"
        );
    }

    #[test]
    fn available_after_is_second_precision_utc_with_a_z_suffix() {
        // Sub-second precision is noise in an hours-long observation
        // window, and an offset other than `Z` would make two hort
        // instances render the same instant differently.
        let deadline = DateTime::parse_from_rfc3339("2026-08-26T08:18:00.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        let held = vec![HeldVersion::new(
            "7.29.7".to_string(),
            HeldReason::Quarantined,
            Some(deadline),
        )];
        let bytes = build_bytes(
            three_version_entries(),
            "https://r.example/npm/m",
            BTreeMap::new(),
            held,
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["hort"]["held"][0]["available_after"].as_str().unwrap(),
            "2026-08-26T08:18:00Z"
        );
    }

    #[test]
    fn held_entries_keep_the_order_the_source_produced() {
        let bytes = build_bytes(
            three_version_entries(),
            "https://r.example/npm/m",
            BTreeMap::new(),
            held_fixture(),
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let versions: Vec<&str> = json["hort"]["held"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["version"].as_str().unwrap())
            .collect();
        assert_eq!(
            versions,
            vec!["7.29.7", "6.0.0"],
            "the array preserves input order; it is not re-sorted"
        );
    }

    #[test]
    fn an_empty_served_set_still_reports_what_is_held() {
        // Every version of a package is held: `versions{}` is empty and
        // there is no `dist-tags` block — the exact shape that used to
        // read as "this package does not exist here". The held block is
        // the only thing that distinguishes it from one that really
        // doesn't.
        let bytes = build_bytes(
            Vec::new(),
            "https://r.example/npm/m",
            BTreeMap::new(),
            held_fixture(),
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["versions"].as_object().unwrap().is_empty());
        assert!(json.get("dist-tags").is_none());
        assert_eq!(json["hort"]["held"].as_array().unwrap().len(), 2);
    }

    // -----------------------------------------------------------------
    // `intersect_dist_tags` — the drop-never-rewrite contract.
    // -----------------------------------------------------------------

    #[test]
    fn intersect_keeps_only_tags_whose_target_is_served() {
        let entries = vec![
            entry("1.2.3", payload("p", "p-1.2.3.tgz", None, "a")),
            entry("2.0.0-rc.1", payload("p", "p-2.0.0-rc.1.tgz", None, "b")),
        ];
        let out = intersect_dist_tags(
            &tags(&[
                ("latest", "1.2.3"),
                ("next", "2.0.0-rc.1"),
                // 9.9.9 is quarantined / never ingested → not served.
                ("canary", "9.9.9"),
            ]),
            &entries,
        );
        assert_eq!(out, tags(&[("latest", "1.2.3"), ("next", "2.0.0-rc.1")]));
        assert!(
            !out.contains_key("canary"),
            "a tag pointing at a non-served version is dropped, never rewritten"
        );
    }

    #[test]
    fn intersect_drops_latest_when_its_target_is_not_served() {
        let entries = vec![entry("1.0.0", payload("p", "p-1.0.0.tgz", None, "a"))];
        let out = intersect_dist_tags(&tags(&[("latest", "9.9.9")]), &entries);
        assert!(
            out.is_empty(),
            "latest gets no special treatment in the intersection itself"
        );
    }

    #[test]
    fn intersect_of_empty_inputs_is_empty() {
        let entries = vec![entry("1.0.0", payload("p", "p-1.0.0.tgz", None, "a"))];
        assert!(intersect_dist_tags(&BTreeMap::new(), &entries).is_empty());
        assert!(intersect_dist_tags(&tags(&[("latest", "1.0.0")]), &[]).is_empty());
    }

    #[test]
    fn intersect_is_identity_under_a_null_gate() {
        // The transparency property: when nothing is filtered out, the
        // intersection degrades to identity and hort serves upstream's
        // map verbatim.
        let entries = three_version_entries();
        let upstream = tags(&[
            ("latest", "1.2.3"),
            ("next", "2.0.0-rc.1"),
            ("beta", "2.0.0-beta.4"),
        ]);
        assert_eq!(intersect_dist_tags(&upstream, &entries), upstream);
    }
}
