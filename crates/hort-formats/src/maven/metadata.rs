//! Maven `maven-metadata.xml` `IndexBuilder` — the Nth concrete
//! [`IndexBuilder`] impl in the unified Source → Filter → Builder pipeline
//! (see explanation/index-construction.md; design §6 + §7).
//!
//! - [`MavenVersionPayload`] / [`MavenSnapshotArtifact`] (re-exported from
//!   [`hort_app::use_cases::index_serve`] — defined there for the same
//!   dep-graph reason that `NpmVersionPayload` / `CargoVersionPayload`
//!   live in `hort-app`) — the per-version data the builder consumes.
//! - [`MavenMetadataXmlBuilder`] — the [`IndexBuilder`] impl that emits
//!   **either** the A-level or the V-level `maven-metadata.xml` document.
//!
//! # One builder, dispatched on the payload case
//!
//! Maven serves two structurally different `maven-metadata.xml`
//! documents:
//!
//! - **A-level** (`g/a/maven-metadata.xml`): the artifact-level version
//!   list — `<versioning><latest><release><versions/><lastUpdated/>`.
//! - **V-level** (`g/a/X-SNAPSHOT/maven-metadata.xml`): the per-snapshot
//!   build list — `<versioning><snapshot/><lastUpdated/><snapshotVersions/>`.
//!
//! **Factoring choice: one builder that dispatches on the
//! [`PerVersionPayload::Maven`] case** ([`MavenVersionPayload::Artifact`]
//! → A-level, [`MavenVersionPayload::Snapshot`] → V-level), rather than
//! two separate builder types or a mode flag on [`BuildContext`]. Reasons:
//!
//! 1. The payload variant *already* encodes which document the entries are
//!    for — the source materialises `Artifact` entries for an A-level
//!    request and `Snapshot` entries for a V-level request (keyed off the
//!    `maven_path_kind` path-shape marker the `MavenFormatHandler`
//!    tags). Dispatching on the case is reading information the pipeline
//!    already carries; a `BuildContext` mode flag would duplicate it and
//!    risk the two disagreeing.
//! 2. It avoids adding a Maven-only field to the shared [`BuildContext`]
//!    (which every other format's builder would then have to ignore) —
//!    keeping the §18 WIT-containment promise that Maven adds no generic
//!    surface beyond the Nth `IndexBuilder`/`PerVersionPayload` instance.
//! 3. The two emission routines stay small and share the XML helpers, so a
//!    single type with two private methods is less code than two unit
//!    structs each re-importing the helpers (mirrors how the cargo builder
//!    keeps its whole emission in one `impl`; contrast PyPI's HTML/JSON
//!    split, which is driven by the *request's `Accept` header* — a
//!    genuine handler-tier choice — not by the entry data).
//!
//! A mixed entry set (some `Artifact`, some `Snapshot`) cannot legitimately
//! occur — the source produces one case per request. The builder dispatches
//! on the **first** entry's case; any entries of the other case are skipped
//! with the same cross-format mis-tag defence the cargo builder uses (drop,
//! never panic). An empty entry set produces an empty A-level document
//! (the conservative default — an A-level metadata with no versions).
//!
//! # `<lastUpdated>` without a clock
//!
//! The builder is **pure**: no I/O, no tracing, and crucially **no system
//! clock** (the workspace forbids `Date::now`-style calls; design §12 pins
//! the builder pure). `<lastUpdated>` is therefore *derived from the
//! inputs*:
//!
//! - **A-level**: the max of the per-version
//!   [`MavenVersionPayload::Artifact::last_updated`] values present. When
//!   no entry carries one, the builder falls back to the caller-supplied
//!   [`MavenMetadataXmlBuilder::last_updated_fallback`] — a value the serve
//!   handler materialises from data (e.g. the group's newest artifact
//!   row's commit time), NOT from a live clock.
//! - **V-level**: the max of the per-build
//!   [`MavenSnapshotArtifact::updated`] values; the fallback is used only
//!   when the set is empty.
//!
//! Threading the fallback through the builder struct (rather than
//! [`BuildContext`]) keeps it Maven-local.
//!
//! # Two distinct timestamp formats
//!
//! V-level emits two timestamp formats that **must not be unified**:
//! - `<snapshot><timestamp>` = `yyyyMMdd.HHmmss` (WITH the dot).
//! - `<snapshotVersion><updated>` and `<lastUpdated>` = `yyyyMMddHHmmss`
//!   (NO separators).
//!
//! The builder emits each verbatim from the payload — the source supplies
//! both forms (the dotted from the parsed snapshot filename, the
//! non-dotted as the row's `updated`); the builder never converts between
//! them, so there is no single canonical-format helper to accidentally
//! collapse the two.
//!
//! # No `xmlns`
//!
//! Real Maven Central `maven-metadata.xml` files emit **no** `xmlns`
//! attribute on `<metadata>`; the builder matches that. (Maven Resolver
//! parses the document namespace-agnostically — a fact the source/parse
//! side must honour too; this builder only emits.)

use bytes::Bytes;
use hort_app::use_cases::index_serve::{
    BuildContext, IndexBuilder, PerVersionPayload, VersionEntry,
};

pub use hort_app::use_cases::index_serve::{MavenSnapshotArtifact, MavenVersionPayload};

use crate::maven::snapshot::is_snapshot_version;

/// Maven `maven-metadata.xml` `IndexBuilder`.
///
/// Constructed per request by the serve handler. Carries the
/// [`Self::last_updated_fallback`] used when no per-entry timestamp is
/// derivable (see the module-level "`<lastUpdated>` without a clock"
/// note). Stateless otherwise — the dispatch is purely a function of the
/// entry data.
///
/// # Panics
///
/// Never panics on a well-formed input. An entry carrying a non-`Maven`
/// `PerVersionPayload`, or a case-mismatched Maven entry (a `Snapshot`
/// entry in an A-level set, or vice versa), is skipped — the builder
/// emits a degraded document rather than panicking, mirroring the cargo
/// builder's cross-format mis-tag defence.
#[derive(Debug, Clone)]
pub struct MavenMetadataXmlBuilder {
    /// The `<lastUpdated>` value (`yyyyMMddHHmmss`, 14 digits, no
    /// separators) used as a fallback when no entry carries a derivable
    /// timestamp. Supplied by the caller from artifact data — NEVER from
    /// a system clock. The empty string is permitted (the builder then
    /// emits `<lastUpdated></lastUpdated>`), but callers should supply a
    /// data-derived value.
    pub last_updated_fallback: String,
}

impl MavenMetadataXmlBuilder {
    /// Construct with the caller-supplied `<lastUpdated>` fallback.
    #[must_use]
    pub fn new(last_updated_fallback: impl Into<String>) -> Self {
        Self {
            last_updated_fallback: last_updated_fallback.into(),
        }
    }
}

impl IndexBuilder for MavenMetadataXmlBuilder {
    fn build(&self, ctx: BuildContext<'_>, entries: Vec<VersionEntry>) -> Bytes {
        // Decide which document to emit from the FIRST Maven entry's case.
        // An empty set, or a set whose only Maven entries are `Artifact`,
        // is A-level; a set led by a `Snapshot` entry is V-level. (The
        // source produces a single case per request — see module rustdoc.)
        let mode = entries.iter().find_map(|e| match &e.payload {
            PerVersionPayload::Maven(MavenVersionPayload::Snapshot(_)) => Some(Mode::Snapshot),
            PerVersionPayload::Maven(MavenVersionPayload::Artifact { .. }) => Some(Mode::Artifact),
            // Non-Maven payloads do not decide the mode; if the whole set
            // is non-Maven the builder defaults to an empty A-level doc.
            _ => None,
        });

        match mode {
            Some(Mode::Snapshot) => self.build_v_level(&ctx, &entries),
            // None (empty / all-non-Maven) → an empty A-level document.
            Some(Mode::Artifact) | None => self.build_a_level(&ctx, &entries),
        }
    }
}

/// Which `maven-metadata.xml` document the entry set calls for.
enum Mode {
    /// A-level (`g/a/maven-metadata.xml`).
    Artifact,
    /// V-level (`g/a/X-SNAPSHOT/maven-metadata.xml`).
    Snapshot,
}

impl MavenMetadataXmlBuilder {
    /// Emit the A-level `g/a/maven-metadata.xml` document.
    ///
    /// `<versions>` = the post-filter entries sorted by `ctx.ordering`
    /// (the caller wires `MavenVersionOrdering`); `<latest>` = the highest
    /// overall version; `<release>` = the highest non-`-SNAPSHOT` version
    /// (the element is omitted when every version is a snapshot).
    /// `<lastUpdated>` is derived from the entries' `last_updated` values
    /// (max), falling back to [`Self::last_updated_fallback`].
    fn build_a_level(&self, ctx: &BuildContext<'_>, entries: &[VersionEntry]) -> Bytes {
        // Collect the (version, last_updated) pairs for the Maven A-level
        // entries; skip case-mismatched / non-Maven entries (mis-tag
        // defence — drop, never panic).
        let mut versions: Vec<String> = Vec::with_capacity(entries.len());
        let mut last_updated_max: Option<String> = None;
        for entry in entries {
            let last_updated = match &entry.payload {
                PerVersionPayload::Maven(MavenVersionPayload::Artifact { last_updated }) => {
                    last_updated.clone()
                }
                // A `Snapshot` entry in an A-level set, or a non-Maven
                // payload, is a mis-tag — skip it.
                _ => continue,
            };
            versions.push(entry.version.clone());
            if let Some(lu) = last_updated {
                // `yyyyMMddHHmmss` is fixed-width, so lexicographic max is
                // chronological max.
                if last_updated_max
                    .as_deref()
                    .is_none_or(|cur| lu.as_str() > cur)
                {
                    last_updated_max = Some(lu);
                }
            }
        }

        // Sort `<versions>` by the per-call ordering (MavenVersionOrdering).
        versions.sort_by(|a, b| ctx.ordering.compare(a, b));

        // `<latest>` = highest overall (last after sort). `<release>` =
        // highest non-snapshot (last non-snapshot after sort).
        let latest = versions.last().cloned();
        let release = versions
            .iter()
            .rev()
            .find(|v| !is_snapshot_version(v))
            .cloned();

        // Split the GA name into groupId / artifactId for the header.
        let (group_id, artifact_id) = split_ga(ctx.package_name);
        let last_updated = last_updated_max.unwrap_or_else(|| self.last_updated_fallback.clone());

        let mut out = String::new();
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str("<metadata>\n");
        push_text_element(&mut out, "  ", "groupId", group_id);
        push_text_element(&mut out, "  ", "artifactId", artifact_id);
        out.push_str("  <versioning>\n");
        if let Some(latest) = &latest {
            push_text_element(&mut out, "    ", "latest", latest);
        }
        if let Some(release) = &release {
            push_text_element(&mut out, "    ", "release", release);
        }
        out.push_str("    <versions>\n");
        for v in &versions {
            push_text_element(&mut out, "      ", "version", v);
        }
        out.push_str("    </versions>\n");
        push_text_element(&mut out, "    ", "lastUpdated", &last_updated);
        out.push_str("  </versioning>\n");
        out.push_str("</metadata>\n");

        Bytes::from(out.into_bytes())
    }

    /// Emit the V-level `g/a/X-SNAPSHOT/maven-metadata.xml` document.
    ///
    /// `<snapshot>` = the highest `(timestamp, build_number)` build across
    /// all keys (`<timestamp>` dotted, `<buildNumber>` from that build).
    /// `<snapshotVersions>` = the most-recent build per
    /// `(classifier, extension)` key. `<lastUpdated>` = the max `updated`
    /// across all builds (no dot), falling back to
    /// [`Self::last_updated_fallback`] when the set is empty.
    fn build_v_level(&self, ctx: &BuildContext<'_>, entries: &[VersionEntry]) -> Bytes {
        // The base `X-SNAPSHOT` version — the package_name carries the GA
        // and the entries' version carries the base. Use the first
        // Snapshot entry's spine version for the `<version>` element.
        let base_version = entries
            .iter()
            .find_map(|e| match &e.payload {
                PerVersionPayload::Maven(MavenVersionPayload::Snapshot(_)) => {
                    Some(e.version.clone())
                }
                _ => None,
            })
            .unwrap_or_default();

        // Keep the most-recent build per (classifier, extension) key.
        // Order is insertion order of first-seen keys, made deterministic
        // by a final sort on (classifier, extension).
        let mut per_key: Vec<((Option<String>, String), MavenSnapshotArtifact)> = Vec::new();
        // The highest build overall (for the document `<snapshot>` block)
        // and the max `updated` (for `<lastUpdated>`).
        let mut highest: Option<MavenSnapshotArtifact> = None;
        let mut last_updated_max: Option<String> = None;

        for entry in entries {
            // An `Artifact` entry in a V-level set, or a non-Maven payload,
            // is a mis-tag — skip it (drop, never panic).
            let PerVersionPayload::Maven(MavenVersionPayload::Snapshot(snap)) = &entry.payload
            else {
                continue;
            };

            // Track the document-level highest build and max updated.
            if highest
                .as_ref()
                .is_none_or(|h| build_key(snap) > build_key(h))
            {
                highest = Some(snap.clone());
            }
            if last_updated_max
                .as_deref()
                .is_none_or(|cur| snap.updated.as_str() > cur)
            {
                last_updated_max = Some(snap.updated.clone());
            }

            // Keep most-recent per (classifier, extension).
            let key = (snap.classifier.clone(), snap.extension.clone());
            match per_key.iter_mut().find(|(k, _)| *k == key) {
                Some((_, existing)) => {
                    if build_key(snap) > build_key(existing) {
                        *existing = snap.clone();
                    }
                }
                None => per_key.push((key, snap.clone())),
            }
        }

        // Deterministic `<snapshotVersions>` order: by (classifier, ext).
        // `None` classifier (the main artifact) sorts before any named one.
        per_key.sort_by(|((ca, ea), _), ((cb, eb), _)| ca.cmp(cb).then_with(|| ea.cmp(eb)));

        let (group_id, artifact_id) = split_ga(ctx.package_name);
        let last_updated = last_updated_max.unwrap_or_else(|| self.last_updated_fallback.clone());

        let mut out = String::new();
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str("<metadata>\n");
        push_text_element(&mut out, "  ", "groupId", group_id);
        push_text_element(&mut out, "  ", "artifactId", artifact_id);
        push_text_element(&mut out, "  ", "version", &base_version);
        out.push_str("  <versioning>\n");
        // `<snapshot>` block — from the highest build (dotted timestamp).
        if let Some(h) = &highest {
            out.push_str("    <snapshot>\n");
            push_text_element(&mut out, "      ", "timestamp", &h.timestamp);
            // buildNumber is numeric; format directly (no escaping needed).
            out.push_str("      <buildNumber>");
            out.push_str(&h.build_number.to_string());
            out.push_str("</buildNumber>\n");
            out.push_str("    </snapshot>\n");
        }
        push_text_element(&mut out, "    ", "lastUpdated", &last_updated);
        out.push_str("    <snapshotVersions>\n");
        for (_, snap) in &per_key {
            out.push_str("      <snapshotVersion>\n");
            if let Some(classifier) = &snap.classifier {
                push_text_element(&mut out, "        ", "classifier", classifier);
            }
            push_text_element(&mut out, "        ", "extension", &snap.extension);
            push_text_element(&mut out, "        ", "value", &snap.value);
            // `<updated>` is the NON-dotted form — distinct from
            // `<snapshot><timestamp>`. Emitted verbatim from the payload.
            push_text_element(&mut out, "        ", "updated", &snap.updated);
            out.push_str("      </snapshotVersion>\n");
        }
        out.push_str("    </snapshotVersions>\n");
        out.push_str("  </versioning>\n");
        out.push_str("</metadata>\n");

        Bytes::from(out.into_bytes())
    }
}

/// Total ordering key for a snapshot build: `(timestamp, build_number)`.
/// The timestamp is the fixed-width dotted `yyyyMMdd.HHmmss` form, so its
/// lexicographic order is chronological; the build number breaks
/// same-second ties.
fn build_key(s: &MavenSnapshotArtifact) -> (&str, u32) {
    (s.timestamp.as_str(), s.build_number)
}

/// Split a `groupId:artifactId` GA name into its two halves. A name with
/// no `:` is treated as all-groupId with an empty artifactId — the
/// degraded shape a mis-constructed `package_name` would produce; the
/// builder emits it rather than panicking (the upstream serve handler is
/// responsible for supplying a well-formed GA name).
fn split_ga(name: &str) -> (&str, &str) {
    match name.split_once(':') {
        Some((g, a)) => (g, a),
        None => (name, ""),
    }
}

/// Append `{indent}<{tag}>{escaped text}</{tag}>\n` to `out`.
///
/// The text content is XML-escaped (`&`, `<`, `>`); attribute-only
/// escapes (`"`, `'`) are unnecessary for element text content but
/// escaping `>` is harmless and matches conservative emitters.
fn push_text_element(out: &mut String, indent: &str, tag: &str, text: &str) {
    out.push_str(indent);
    out.push('<');
    out.push_str(tag);
    out.push('>');
    out.push_str(&xml_escape_text(text));
    out.push_str("</");
    out.push_str(tag);
    out.push_str(">\n");
}

/// Escape a string for use as XML element text content.
///
/// Escapes the three characters that are significant in element text:
/// `&` (entity start), `<` (tag start), and `>` (defensive — only
/// significant as part of `]]>`, but conservative emitters escape it).
/// Quotes are NOT escaped (they are only significant inside attribute
/// values, which this builder never emits).
fn xml_escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use hort_app::use_cases::index_serve_filter::MavenVersionOrdering;
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::repository::IndexMode;

    use super::*;

    // -- helpers --------------------------------------------------------------

    /// Build an A-level entry for `version` with an optional last_updated.
    fn a_entry(version: &str, last_updated: Option<&str>) -> VersionEntry {
        VersionEntry {
            version: version.to_string(),
            status: Some(QuarantineStatus::Released),
            payload: PerVersionPayload::Maven(MavenVersionPayload::Artifact {
                last_updated: last_updated.map(str::to_string),
            }),
        }
    }

    /// Build a V-level (snapshot) entry.
    fn v_entry(
        base_version: &str,
        classifier: Option<&str>,
        extension: &str,
        value: &str,
        updated: &str,
        timestamp: &str,
        build_number: u32,
    ) -> VersionEntry {
        VersionEntry {
            version: base_version.to_string(),
            status: Some(QuarantineStatus::Released),
            payload: PerVersionPayload::Maven(MavenVersionPayload::Snapshot(
                MavenSnapshotArtifact {
                    classifier: classifier.map(str::to_string),
                    extension: extension.to_string(),
                    value: value.to_string(),
                    updated: updated.to_string(),
                    timestamp: timestamp.to_string(),
                    build_number,
                },
            )),
        }
    }

    fn build(name: &str, fallback: &str, entries: Vec<VersionEntry>) -> String {
        let bytes = MavenMetadataXmlBuilder::new(fallback).build(
            BuildContext {
                package_name: name,
                base_url: "https://example.test/maven/m",
                index_mode: IndexMode::ReleasedOnly,
                ordering: &MavenVersionOrdering,
            },
            entries,
        );
        String::from_utf8(bytes.to_vec()).expect("maven-metadata.xml is UTF-8")
    }

    /// Extract the text of every `<{tag}>…</{tag}>` occurrence, in order.
    fn extract_all<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let mut out = Vec::new();
        let mut rest = xml;
        while let Some(start) = rest.find(&open) {
            let after = &rest[start + open.len()..];
            let Some(end) = after.find(&close) else {
                break;
            };
            out.push(&after[..end]);
            rest = &after[end + close.len()..];
        }
        out
    }

    fn extract_one<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
        extract_all(xml, tag).into_iter().next()
    }

    // -- A-level: versions ordering, latest, release --------------------------

    #[test]
    fn a_level_mixed_release_and_snapshot_orders_via_maven_ordering() {
        // A deliberately un-ordered, mixed release+snapshot set. The
        // `<versions>` must come out in MavenVersionOrdering order, NOT
        // input or lexical order.
        let entries = vec![
            a_entry("1.0", None),
            a_entry("1.0-SNAPSHOT", None),
            a_entry("1.10", None),
            a_entry("1.2", None),
            a_entry("2.0-alpha-1", None),
        ];
        let xml = build("com.example:foo", "20231201000000", entries);

        let versions = extract_all(&xml, "version");
        // Maven order: 1.0-SNAPSHOT < 1.0 < 1.2 < 1.10 < 2.0-alpha-1.
        // (1.0-SNAPSHOT sorts before 1.0; 1.10 > 1.2 numerically;
        // 2.0-alpha-1 is the highest base.)
        assert_eq!(
            versions,
            vec!["1.0-SNAPSHOT", "1.0", "1.2", "1.10", "2.0-alpha-1"],
            "versions must be sorted by MavenVersionOrdering"
        );

        // `<latest>` = highest overall (incl. snapshot) = 2.0-alpha-1.
        assert_eq!(extract_one(&xml, "latest"), Some("2.0-alpha-1"));
        // `<release>` = highest NON-snapshot. 2.0-alpha-1 is not a
        // `-SNAPSHOT`, so it IS the release too (alpha is a release).
        assert_eq!(extract_one(&xml, "release"), Some("2.0-alpha-1"));
    }

    #[test]
    fn a_level_release_is_highest_non_snapshot() {
        // Highest version is a snapshot; release must skip it.
        let entries = vec![
            a_entry("1.0", None),
            a_entry("1.1", None),
            a_entry("2.0-SNAPSHOT", None),
        ];
        let xml = build("com.example:foo", "20231201000000", entries);
        assert_eq!(extract_one(&xml, "latest"), Some("2.0-SNAPSHOT"));
        assert_eq!(
            extract_one(&xml, "release"),
            Some("1.1"),
            "release must be the highest NON-snapshot"
        );
    }

    #[test]
    fn a_level_release_omitted_when_all_snapshots() {
        let entries = vec![a_entry("1.0-SNAPSHOT", None), a_entry("2.0-SNAPSHOT", None)];
        let xml = build("com.example:foo", "20231201000000", entries);
        assert_eq!(extract_one(&xml, "latest"), Some("2.0-SNAPSHOT"));
        assert!(
            !xml.contains("<release>"),
            "<release> must be omitted when every version is a snapshot: {xml}"
        );
    }

    #[test]
    fn a_level_single_version() {
        let entries = vec![a_entry("1.0", None)];
        let xml = build("com.example:foo", "20231201000000", entries);
        assert_eq!(extract_all(&xml, "version"), vec!["1.0"]);
        assert_eq!(extract_one(&xml, "latest"), Some("1.0"));
        assert_eq!(extract_one(&xml, "release"), Some("1.0"));
    }

    #[test]
    fn a_level_empty_set_produces_empty_versions_no_latest_no_release() {
        let xml = build("com.example:foo", "20231201000000", Vec::new());
        assert!(extract_all(&xml, "version").is_empty());
        assert!(!xml.contains("<latest>"), "no latest on empty set: {xml}");
        assert!(!xml.contains("<release>"), "no release on empty set: {xml}");
        // The fallback lastUpdated is used.
        assert_eq!(extract_one(&xml, "lastUpdated"), Some("20231201000000"));
        // Structure is still a valid empty A-level doc.
        assert!(xml.contains("<versions>"));
        assert!(xml.contains("</versions>"));
    }

    #[test]
    fn a_level_header_carries_split_group_and_artifact() {
        let xml = build(
            "com.example.sub:my-artifact",
            "20231201000000",
            vec![a_entry("1.0", None)],
        );
        assert_eq!(extract_one(&xml, "groupId"), Some("com.example.sub"));
        assert_eq!(extract_one(&xml, "artifactId"), Some("my-artifact"));
    }

    #[test]
    fn a_level_last_updated_is_max_of_entries_when_present() {
        let entries = vec![
            a_entry("1.0", Some("20230101000000")),
            a_entry("1.1", Some("20230615120000")),
            a_entry("1.2", Some("20230301000000")),
        ];
        let xml = build("com.example:foo", "19990101000000", entries);
        assert_eq!(
            extract_one(&xml, "lastUpdated"),
            Some("20230615120000"),
            "lastUpdated must be the max per-version timestamp, not the fallback"
        );
    }

    #[test]
    fn a_level_last_updated_falls_back_when_no_entry_carries_one() {
        let entries = vec![a_entry("1.0", None), a_entry("1.1", None)];
        let xml = build("com.example:foo", "20240101000000", entries);
        assert_eq!(
            extract_one(&xml, "lastUpdated"),
            Some("20240101000000"),
            "lastUpdated falls back to the caller-supplied value when no entry has one"
        );
    }

    // -- V-level: snapshot block, snapshotVersions, formats -------------------

    #[test]
    fn v_level_keeps_most_recent_per_classifier_extension() {
        // Two builds of the main jar (keep the higher), one sources jar.
        let entries = vec![
            v_entry(
                "1.0-SNAPSHOT",
                None,
                "jar",
                "1.0-20231201.120000-1",
                "20231201120000",
                "20231201.120000",
                1,
            ),
            v_entry(
                "1.0-SNAPSHOT",
                None,
                "jar",
                "1.0-20231205.080000-3",
                "20231205080000",
                "20231205.080000",
                3,
            ),
            v_entry(
                "1.0-SNAPSHOT",
                Some("sources"),
                "jar",
                "1.0-20231202.090000-2",
                "20231202090000",
                "20231202.090000",
                2,
            ),
        ];
        let xml = build("com.example:foo", "20231201000000", entries);

        // Exactly two <snapshotVersion> blocks (one per key).
        let extensions = extract_all(&xml, "extension");
        assert_eq!(extensions.len(), 2, "one snapshotVersion per key: {xml}");

        // The main jar's value must be the HIGHER build (build 3).
        let values = extract_all(&xml, "value");
        assert!(
            values.contains(&"1.0-20231205.080000-3"),
            "most-recent main-jar build wins: {values:?}"
        );
        assert!(
            !values.contains(&"1.0-20231201.120000-1"),
            "older main-jar build must be dropped: {values:?}"
        );
        assert!(values.contains(&"1.0-20231202.090000-2"));

        // The sources classifier is present.
        assert_eq!(extract_all(&xml, "classifier"), vec!["sources"]);
    }

    #[test]
    fn v_level_snapshot_block_picks_highest_build_with_dotted_timestamp() {
        let entries = vec![
            v_entry(
                "1.0-SNAPSHOT",
                None,
                "jar",
                "1.0-20231201.120000-1",
                "20231201120000",
                "20231201.120000",
                1,
            ),
            v_entry(
                "1.0-SNAPSHOT",
                Some("sources"),
                "jar",
                "1.0-20231205.080000-7",
                "20231205080000",
                "20231205.080000",
                7,
            ),
        ];
        let xml = build("com.example:foo", "20231201000000", entries);

        // <snapshot><timestamp> = the HIGHEST build's dotted timestamp.
        assert_eq!(
            extract_one(&xml, "timestamp"),
            Some("20231205.080000"),
            "snapshot/timestamp = highest build, DOTTED form"
        );
        // <snapshot><buildNumber> = the highest build's number.
        assert_eq!(extract_one(&xml, "buildNumber"), Some("7"));
        // The dotted timestamp must NOT appear as an <updated> value.
        let updated = extract_all(&xml, "updated");
        assert!(
            updated.iter().all(|u| !u.contains('.')),
            "<updated>/<lastUpdated> must be NON-dotted: {updated:?}"
        );
    }

    #[test]
    fn v_level_timestamp_and_updated_formats_are_distinct() {
        let entries = vec![v_entry(
            "1.0-SNAPSHOT",
            None,
            "jar",
            "1.0-20231201.120000-1",
            "20231201120000",
            "20231201.120000",
            1,
        )];
        let xml = build("com.example:foo", "20231201000000", entries);
        // snapshot/timestamp is dotted (15 chars incl. the dot).
        assert_eq!(extract_one(&xml, "timestamp"), Some("20231201.120000"));
        // snapshotVersion/updated is NON-dotted (14 digits).
        assert_eq!(extract_one(&xml, "updated"), Some("20231201120000"));
        // lastUpdated is NON-dotted too.
        assert_eq!(extract_one(&xml, "lastUpdated"), Some("20231201120000"));
    }

    #[test]
    fn v_level_last_updated_is_max_updated_across_builds() {
        let entries = vec![
            v_entry(
                "1.0-SNAPSHOT",
                None,
                "jar",
                "1.0-20231201.120000-1",
                "20231201120000",
                "20231201.120000",
                1,
            ),
            v_entry(
                "1.0-SNAPSHOT",
                Some("sources"),
                "jar",
                "1.0-20231210.090000-2",
                "20231210090000",
                "20231210.090000",
                2,
            ),
        ];
        let xml = build("com.example:foo", "19990101000000", entries);
        assert_eq!(
            extract_one(&xml, "lastUpdated"),
            Some("20231210090000"),
            "lastUpdated = max updated across builds (non-dotted)"
        );
    }

    #[test]
    fn v_level_main_artifact_omits_classifier_element() {
        let entries = vec![v_entry(
            "1.0-SNAPSHOT",
            None,
            "jar",
            "1.0-20231201.120000-1",
            "20231201120000",
            "20231201.120000",
            1,
        )];
        let xml = build("com.example:foo", "20231201000000", entries);
        assert!(
            !xml.contains("<classifier>"),
            "the main artifact (no classifier) must omit <classifier>: {xml}"
        );
        assert_eq!(extract_one(&xml, "extension"), Some("jar"));
        assert_eq!(extract_one(&xml, "value"), Some("1.0-20231201.120000-1"));
    }

    #[test]
    fn v_level_carries_base_version_and_ga_header() {
        let entries = vec![v_entry(
            "1.0-SNAPSHOT",
            None,
            "jar",
            "1.0-20231201.120000-1",
            "20231201120000",
            "20231201.120000",
            1,
        )];
        let xml = build("com.example:foo", "20231201000000", entries);
        assert_eq!(extract_one(&xml, "groupId"), Some("com.example"));
        assert_eq!(extract_one(&xml, "artifactId"), Some("foo"));
        assert_eq!(extract_one(&xml, "version"), Some("1.0-SNAPSHOT"));
    }

    // -- XML escaping + no xmlns ----------------------------------------------

    #[test]
    fn no_xmlns_attribute_is_emitted() {
        let xml = build(
            "com.example:foo",
            "20231201000000",
            vec![a_entry("1.0", None)],
        );
        assert!(
            !xml.contains("xmlns"),
            "real Central files omit xmlns; the builder must too: {xml}"
        );
        // The root element is bare `<metadata>` with no attributes.
        assert!(xml.contains("<metadata>\n"), "bare <metadata> root: {xml}");
    }

    #[test]
    fn xml_text_content_is_escaped() {
        // A pathological GA / version with XML metacharacters. (These are
        // rejected by validate_maven_coordinate upstream, but the builder
        // must still escape defensively — it does not trust its inputs to
        // be metachar-free.)
        let entries = vec![a_entry("1.0<&>", None)];
        let xml = build("a&b:c<d>", "20231201000000", entries);
        // The raw metacharacters must not appear in text positions.
        assert!(xml.contains("a&amp;b"), "groupId & escaped: {xml}");
        assert!(xml.contains("c&lt;d&gt;"), "artifactId <> escaped: {xml}");
        assert!(
            xml.contains("<version>1.0&lt;&amp;&gt;</version>"),
            "version metachars escaped: {xml}"
        );
        // Sanity: the escaped doc still parses each escaped sequence back.
        assert_eq!(extract_one(&xml, "groupId"), Some("a&amp;b"));
    }

    // -- mis-tag defence ------------------------------------------------------

    #[test]
    fn non_maven_payload_entries_are_skipped_not_panicked() {
        use hort_app::use_cases::index_serve::NpmVersionPayload;

        // A mis-tagged Npm payload riding the Maven builder: it must be
        // skipped (the version is dropped), not panic. One good A-level
        // entry verifies the survivor still emits.
        let good = a_entry("1.0", None);
        let bad = VersionEntry {
            version: "9.9.9".to_string(),
            status: Some(QuarantineStatus::Released),
            payload: PerVersionPayload::Npm(NpmVersionPayload {
                name_as_published: "wrong".into(),
                tarball_basename: "x.tgz".into(),
                integrity: None,
                shasum: String::new(),
            }),
        };
        let xml = build("com.example:foo", "20231201000000", vec![good, bad]);
        assert_eq!(
            extract_all(&xml, "version"),
            vec!["1.0"],
            "non-Maven entry must be skipped, only the good version remains"
        );
    }

    #[test]
    fn a_level_skips_snapshot_case_entries_mixed_in() {
        // A `Snapshot` entry mixed into an A-level (Artifact-led) set is a
        // mis-tag — it must be dropped from `<versions>`.
        let entries = vec![
            a_entry("1.0", None),
            v_entry(
                "1.0-SNAPSHOT",
                None,
                "jar",
                "1.0-20231201.120000-1",
                "20231201120000",
                "20231201.120000",
                1,
            ),
        ];
        let xml = build("com.example:foo", "20231201000000", entries);
        assert_eq!(
            extract_all(&xml, "version"),
            vec!["1.0"],
            "the Snapshot-case entry must be dropped from an A-level doc"
        );
    }

    // -- round-trip sanity ----------------------------------------------------

    #[test]
    fn a_level_round_trips_through_a_lightweight_xml_check() {
        // Emit, then re-read each element with the same lightweight
        // extractor a parser would use — proves the document is
        // structurally coherent (open/close tags balanced for the fields
        // we emit).
        let entries = vec![
            a_entry("1.0", Some("20230101000000")),
            a_entry("2.0", Some("20230601000000")),
        ];
        let xml = build("com.example:foo", "19990101000000", entries);
        assert_eq!(extract_one(&xml, "groupId"), Some("com.example"));
        assert_eq!(extract_one(&xml, "artifactId"), Some("foo"));
        assert_eq!(extract_one(&xml, "latest"), Some("2.0"));
        assert_eq!(extract_one(&xml, "release"), Some("2.0"));
        assert_eq!(extract_all(&xml, "version"), vec!["1.0", "2.0"]);
        assert_eq!(extract_one(&xml, "lastUpdated"), Some("20230601000000"));
        // Declares the XML prolog.
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    }

    #[test]
    fn v_level_round_trips_through_a_lightweight_xml_check() {
        let entries = vec![
            v_entry(
                "2.5-SNAPSHOT",
                None,
                "jar",
                "2.5-20231201.120000-4",
                "20231201120000",
                "20231201.120000",
                4,
            ),
            v_entry(
                "2.5-SNAPSHOT",
                None,
                "pom",
                "2.5-20231201.120000-4",
                "20231201120000",
                "20231201.120000",
                4,
            ),
        ];
        let xml = build("com.example:foo", "20231201000000", entries);
        assert_eq!(extract_one(&xml, "version"), Some("2.5-SNAPSHOT"));
        assert_eq!(extract_one(&xml, "timestamp"), Some("20231201.120000"));
        assert_eq!(extract_one(&xml, "buildNumber"), Some("4"));
        // Two snapshotVersion blocks: jar + pom (deterministic order).
        assert_eq!(extract_all(&xml, "extension"), vec!["jar", "pom"]);
        assert!(xml.contains("<snapshotVersions>"));
        assert!(xml.contains("</snapshotVersions>"));
    }

    #[test]
    fn v_level_snapshot_versions_order_is_deterministic_by_classifier_then_extension() {
        // Insert in a scrambled order; output must be sorted by
        // (classifier, extension): None classifier first, then sources.
        let entries = vec![
            v_entry(
                "1.0-SNAPSHOT",
                Some("sources"),
                "jar",
                "1.0-20231201.120000-1",
                "20231201120000",
                "20231201.120000",
                1,
            ),
            v_entry(
                "1.0-SNAPSHOT",
                None,
                "pom",
                "1.0-20231201.120000-1",
                "20231201120000",
                "20231201.120000",
                1,
            ),
            v_entry(
                "1.0-SNAPSHOT",
                None,
                "jar",
                "1.0-20231201.120000-1",
                "20231201120000",
                "20231201.120000",
                1,
            ),
        ];
        let xml = build("com.example:foo", "20231201000000", entries);
        // Order: (None,"jar"), (None,"pom"), (Some("sources"),"jar").
        // Extensions in that order: jar, pom, jar.
        assert_eq!(extract_all(&xml, "extension"), vec!["jar", "pom", "jar"]);
        // Only the sources block has a <classifier>.
        assert_eq!(extract_all(&xml, "classifier"), vec!["sources"]);
    }

    #[test]
    fn builder_is_pure_same_inputs_same_bytes() {
        // Deterministic output: two builds with identical inputs are
        // byte-identical (no clock, no map-iteration nondeterminism).
        let mk = || {
            build(
                "com.example:foo",
                "20231201000000",
                vec![
                    a_entry("1.10", None),
                    a_entry("1.2", None),
                    a_entry("1.0", None),
                ],
            )
        };
        assert_eq!(mk(), mk(), "builder must be deterministic");
    }
}
