//! Maven SNAPSHOT timestamped-filename parsing + mutable-version
//! resolution (design §7).
//!
//! A `-SNAPSHOT` deploy uploads unique, timestamped files of the form
//! `{artifactId}-{base}-{yyyyMMdd.HHmmss}-{N}[-{classifier}].{ext}` (Maven 3
//! always deploys unique snapshots). A request for the unresolved base form
//! `{artifactId}-{base}-SNAPSHOT[-{classifier}].{ext}` resolves to the
//! highest `(timestamp, buildNumber)` stored build matching the requested
//! `(classifier, extension)`.
//!
//! Pure domain code — zero I/O, no tracing.

use hort_app::use_cases::index_serve::MavenSnapshotArtifact;

/// Whether a version string is a SNAPSHOT (base, unresolved) version —
/// i.e. ends with the literal `-SNAPSHOT` suffix.
#[must_use]
pub fn is_snapshot_version(version: &str) -> bool {
    version.ends_with("-SNAPSHOT")
}

/// A parsed Maven snapshot timestamp + build number: the
/// `yyyyMMdd.HHmmss-N` token Maven appends to a unique snapshot filename.
///
/// Ordering is `(timestamp_string, build_number)` — the timestamp is a
/// fixed-width `yyyyMMdd.HHmmss` form, so lexicographic ordering of the
/// string is chronological, and ties (same second) break on the build
/// number. Stored as the raw string + parsed build number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotTimestamp {
    /// The dotted timestamp `yyyyMMdd.HHmmss` (15 chars, fixed width).
    pub timestamp: String,
    /// The build number `N` (monotonic per snapshot deploy).
    pub build_number: u32,
}

impl SnapshotTimestamp {
    /// Total ordering key. The timestamp is fixed-width so its
    /// lexicographic order is chronological; the build number breaks
    /// same-second ties.
    fn order_key(&self) -> (&str, u32) {
        (self.timestamp.as_str(), self.build_number)
    }
}

impl PartialOrd for SnapshotTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SnapshotTimestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.order_key().cmp(&other.order_key())
    }
}

/// Parse a leading `yyyyMMdd.HHmmss-N` token from `s`, returning the parsed
/// timestamp + the byte offset just past the `-N` (so the caller can read a
/// trailing `-{classifier}.{ext}`), or `None` if `s` does not begin with a
/// well-formed timestamp token.
///
/// Shape: 8 digits, `.`, 6 digits, `-`, 1+ digits. The timestamp portion
/// (`yyyyMMdd.HHmmss`) is exactly 15 chars.
#[must_use]
fn parse_leading_timestamp(s: &str) -> Option<(SnapshotTimestamp, usize)> {
    // `yyyyMMdd.HHmmss` = 8 + 1 + 6 = 15 bytes (ASCII).
    if s.len() < 15 + 2 {
        // need at least the 15-char ts + `-` + one build digit
        return None;
    }
    let bytes = s.as_bytes();
    let digit = |b: u8| b.is_ascii_digit();
    // 8 digits
    if !bytes[..8].iter().all(|&b| digit(b)) {
        return None;
    }
    // dot
    if bytes[8] != b'.' {
        return None;
    }
    // 6 digits
    if !bytes[9..15].iter().all(|&b| digit(b)) {
        return None;
    }
    // dash separating timestamp from build number
    if bytes[15] != b'-' {
        return None;
    }
    // build number: 1+ digits, terminated by EOS or `-` (classifier) or
    // `.` (extension).
    let mut end = 16;
    while end < bytes.len() && digit(bytes[end]) {
        end += 1;
    }
    if end == 16 {
        // no build digits
        return None;
    }
    let build_number: u32 = s[16..end].parse().ok()?;
    let timestamp = s[..15].to_string();
    Some((
        SnapshotTimestamp {
            timestamp,
            build_number,
        },
        end,
    ))
}

/// Parse a timestamped-snapshot SUFFIX `yyyyMMdd.HHmmss-N` (used by the
/// coords filename matcher to confirm a remainder is a timestamped build).
///
/// Returns the parsed timestamp if `s` BEGINS with a well-formed token;
/// the trailing bytes (classifier/extension) are ignored.
#[must_use]
pub fn parse_snapshot_timestamp(s: &str) -> Option<SnapshotTimestamp> {
    parse_leading_timestamp(s).map(|(ts, _)| ts)
}

/// A decomposed timestamped-snapshot filename.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TimestampedFile {
    /// The parsed `(timestamp, buildNumber)`.
    ts: SnapshotTimestamp,
    /// The classifier (`sources`, `javadoc`, …) or empty for the main file.
    classifier: String,
    /// The file extension (`jar`, `pom`, `module`, …) — the final
    /// dot-suffix, lowercased for comparison.
    extension: String,
}

/// Decompose a timestamped-snapshot filename into `(timestamp, classifier,
/// extension)` for `(artifactId, snapshotBase)`.
///
/// Expects `filename` of the form
/// `{artifactId}-{base}-{yyyyMMdd.HHmmss}-{N}[-{classifier}].{ext}`.
/// Returns `None` if `filename` is not a timestamped build for these
/// coords (wrong artifact/base prefix, no parseable timestamp, no
/// extension).
fn parse_timestamped_file(
    filename: &str,
    artifact_id: &str,
    snapshot_base: &str,
) -> Option<TimestampedFile> {
    // Strip the `{artifactId}-{base}-` prefix.
    let prefix = format!("{artifact_id}-{snapshot_base}-");
    let rest = filename.strip_prefix(&prefix)?;
    // `rest` = `{yyyyMMdd.HHmmss}-{N}[-{classifier}].{ext}`.
    let (ts, past_build) = parse_leading_timestamp(rest)?;
    let tail = &rest[past_build..]; // `[-{classifier}].{ext}`
                                    // Split off the extension on the LAST dot.
    let (stem, ext) = tail.rsplit_once('.')?;
    if ext.is_empty() {
        return None;
    }
    // `stem` is `` (no classifier) or `-{classifier}`.
    let classifier = stem.strip_prefix('-').unwrap_or(stem).to_string();
    Some(TimestampedFile {
        ts,
        classifier,
        extension: ext.to_ascii_lowercase(),
    })
}

/// Decompose a stored timestamped-snapshot filename
/// (`{artifactId}-{base}-{yyyyMMdd.HHmmss}-{N}[-{classifier}].{ext}`) into a
/// [`MavenSnapshotArtifact`], or `None` when `filename` is not a timestamped
/// build for `(artifact_id, base)`.
///
/// This is the format-layer home for Maven snapshot-filename grammar (§18):
/// the V-level `maven-metadata.xml` source in `hort-http-maven` calls this
/// instead of carrying its own parser. It reuses [`parse_timestamped_file`]
/// for the `(timestamp, classifier, extension, build_number)` decomposition
/// and maps the result into the `hort_app` payload type the metadata builder
/// consumes.
///
/// Field derivation (byte-for-byte identical to the prior inbound-HTTP copy):
/// - `value` = `{base}-{timestamp}-{N}` (dotted timestamp) — the resolved
///   timestamped version string Maven clients request the concrete file by;
/// - `updated` = the dotted timestamp with the `.` removed (the NON-dotted
///   `yyyyMMddHHmmss` `<updated>` / `<lastUpdated>` form);
/// - `timestamp` = the dotted `yyyyMMdd.HHmmss` form, carried verbatim
///   (the `<snapshot><timestamp>` value);
/// - `extension` = the file extension, lowercased;
/// - `classifier` = `None` when absent (the main artifact), `Some(c)` otherwise.
#[must_use]
pub fn decompose_snapshot_filename(
    filename: &str,
    artifact_id: &str,
    base: &str,
) -> Option<MavenSnapshotArtifact> {
    let tf = parse_timestamped_file(filename, artifact_id, base)?;
    let value_tail = format!("{}-{}", tf.ts.timestamp, tf.ts.build_number);
    Some(MavenSnapshotArtifact {
        // No classifier (the main artifact) — `parse_timestamped_file`
        // yields an empty `classifier` string for that case.
        classifier: if tf.classifier.is_empty() {
            None
        } else {
            Some(tf.classifier)
        },
        extension: tf.extension,
        // `value` is the full resolved timestamped version string Maven
        // requests the concrete file by: `{base}-{timestamp}-{N}`.
        value: format!("{base}-{value_tail}"),
        // `<updated>` / `<lastUpdated>` is the NON-dotted form (drop the dot
        // from the dotted `yyyyMMdd.HHmmss` timestamp).
        updated: tf.ts.timestamp.replace('.', ""),
        // `<snapshot><timestamp>` is the dotted form, carried verbatim.
        timestamp: tf.ts.timestamp,
        build_number: tf.ts.build_number,
    })
}

/// Extract `(classifier, extension)` from an UNRESOLVED snapshot request
/// filename `{artifactId}-{base}-SNAPSHOT[-{classifier}].{ext}`.
///
/// Returns `None` if `filename` is not an unresolved snapshot request for
/// these coords.
fn parse_unresolved_request(
    filename: &str,
    artifact_id: &str,
    snapshot_base: &str,
) -> Option<(String, String)> {
    let prefix = format!("{artifact_id}-{snapshot_base}-SNAPSHOT");
    let rest = filename.strip_prefix(&prefix)?;
    // `rest` = `[-{classifier}].{ext}`.
    let (stem, ext) = rest.rsplit_once('.')?;
    if ext.is_empty() {
        return None;
    }
    let classifier = stem.strip_prefix('-').unwrap_or(stem).to_string();
    Some((classifier, ext.to_ascii_lowercase()))
}

/// Resolve a mutable (SNAPSHOT) version request path to the concrete,
/// immutable stored path among `available_paths` (design §7;
/// `FormatHandler::resolve_mutable_version`).
///
/// `requested_path` is a full repo-relative path. The last segment is the
/// requested filename; the 2nd-to-last is the version (which must be a base
/// `X-SNAPSHOT`); the 3rd-to-last is the artifactId. The request is matched
/// against the timestamped builds in `available_paths` (each a full path
/// sharing the same directory), and the highest `(timestamp, buildNumber)`
/// build matching the requested `(classifier, extension)` wins.
///
/// Returns `Some(concrete_path)` on a match, or `None` when:
/// - the request is not an unresolved SNAPSHOT (already concrete /
///   non-snapshot version) — the caller treats the path as concrete;
/// - no available path matches the requested `(classifier, extension)`.
#[must_use]
pub fn resolve_mutable_version(requested_path: &str, available_paths: &[&str]) -> Option<String> {
    let req = requested_path.strip_prefix('/').unwrap_or(requested_path);
    let parts: Vec<&str> = req.split('/').collect();
    if parts.len() < 4 {
        return None;
    }
    let req_filename = parts[parts.len() - 1];
    let version = parts[parts.len() - 2];
    let artifact_id = parts[parts.len() - 3];

    // Only base `X-SNAPSHOT` versions are mutable. A timestamped (already
    // concrete) or non-snapshot version is not resolvable.
    let snapshot_base = version.strip_suffix("-SNAPSHOT")?;

    // The request must itself be the unresolved base-SNAPSHOT filename.
    let (req_classifier, req_ext) =
        parse_unresolved_request(req_filename, artifact_id, snapshot_base)?;

    let mut best: Option<(SnapshotTimestamp, &str)> = None;
    for candidate in available_paths {
        let cand = candidate.strip_prefix('/').unwrap_or(candidate);
        let cand_filename = cand.rsplit('/').next().unwrap_or(cand);
        let Some(tf) = parse_timestamped_file(cand_filename, artifact_id, snapshot_base) else {
            continue;
        };
        if tf.classifier != req_classifier || tf.extension != req_ext {
            continue;
        }
        let is_better = match &best {
            None => true,
            Some((best_ts, _)) => tf.ts > *best_ts,
        };
        if is_better {
            best = Some((tf.ts, candidate));
        }
    }
    best.map(|(_, path)| (*path).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- is_snapshot_version --------------------------------------------------

    #[test]
    fn snapshot_detection() {
        assert!(is_snapshot_version("1.0-SNAPSHOT"));
        assert!(is_snapshot_version("2.3.4-SNAPSHOT"));
        assert!(!is_snapshot_version("1.0"));
        assert!(!is_snapshot_version("1.0-rc1"));
        // Lowercase `snapshot` is NOT the Maven base-snapshot marker.
        assert!(!is_snapshot_version("1.0-snapshot"));
    }

    // -- parse_snapshot_timestamp ---------------------------------------------

    #[test]
    fn parse_timestamp_basic() {
        let ts = parse_snapshot_timestamp("20231201.120000-3.jar").unwrap();
        assert_eq!(ts.timestamp, "20231201.120000");
        assert_eq!(ts.build_number, 3);
    }

    #[test]
    fn parse_timestamp_multi_digit_build() {
        let ts = parse_snapshot_timestamp("20231201.120000-42").unwrap();
        assert_eq!(ts.build_number, 42);
    }

    #[test]
    fn parse_timestamp_rejects_malformed() {
        assert!(parse_snapshot_timestamp("not-a-timestamp").is_none());
        assert!(parse_snapshot_timestamp("2023.120000-3").is_none()); // wrong digit count
        assert!(parse_snapshot_timestamp("20231201-120000-3").is_none()); // no dot
        assert!(parse_snapshot_timestamp("20231201.120000-").is_none()); // no build digits
        assert!(parse_snapshot_timestamp("").is_none());
    }

    // -- SnapshotTimestamp ordering ------------------------------------------

    #[test]
    fn timestamp_ordering_by_time_then_build() {
        let a = SnapshotTimestamp {
            timestamp: "20231201.120000".into(),
            build_number: 1,
        };
        let b = SnapshotTimestamp {
            timestamp: "20231201.120000".into(),
            build_number: 2,
        };
        let c = SnapshotTimestamp {
            timestamp: "20231202.000000".into(),
            build_number: 1,
        };
        assert!(a < b); // same second, higher build wins
        assert!(b < c); // later day wins regardless of build
        assert!(a < c);
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
        // PartialOrd path is exercised too.
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Less));
    }

    // -- resolve_mutable_version ---------------------------------------------

    const DIR: &str = "com/example/foo/1.0-SNAPSHOT";

    fn req(filename: &str) -> String {
        format!("{DIR}/{filename}")
    }

    #[test]
    fn resolves_highest_build_number() {
        let avail = [
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-1.jar",
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.jar",
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-2.jar",
        ];
        let avail_refs: Vec<&str> = avail.to_vec();
        let got = resolve_mutable_version(&req("foo-1.0-SNAPSHOT.jar"), &avail_refs).unwrap();
        assert_eq!(
            got,
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.jar"
        );
    }

    #[test]
    fn resolves_highest_timestamp_over_build() {
        let avail = [
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-9.jar",
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231205.080000-1.jar",
        ];
        let avail_refs: Vec<&str> = avail.to_vec();
        let got = resolve_mutable_version(&req("foo-1.0-SNAPSHOT.jar"), &avail_refs).unwrap();
        // Later timestamp wins even though its build number is lower.
        assert_eq!(
            got,
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231205.080000-1.jar"
        );
    }

    #[test]
    fn resolves_per_classifier_extension() {
        // Different classifiers carry DIFFERENT timestamps — each resolves
        // to its own latest build independently (design §7 / §11).
        let avail = [
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.jar",
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3-sources.jar",
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231205.080000-5-sources.jar",
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.pom",
        ];
        let avail_refs: Vec<&str> = avail.to_vec();

        let main = resolve_mutable_version(&req("foo-1.0-SNAPSHOT.jar"), &avail_refs).unwrap();
        assert_eq!(
            main,
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.jar"
        );

        let sources =
            resolve_mutable_version(&req("foo-1.0-SNAPSHOT-sources.jar"), &avail_refs).unwrap();
        // The sources classifier has a later build than the main jar.
        assert_eq!(
            sources,
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231205.080000-5-sources.jar"
        );

        let pom = resolve_mutable_version(&req("foo-1.0-SNAPSHOT.pom"), &avail_refs).unwrap();
        assert_eq!(
            pom,
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.pom"
        );
    }

    #[test]
    fn returns_none_for_empty_available() {
        assert!(resolve_mutable_version(&req("foo-1.0-SNAPSHOT.jar"), &[]).is_none());
    }

    #[test]
    fn returns_none_for_no_matching_classifier_extension() {
        let avail = ["com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.jar"];
        let avail_refs: Vec<&str> = avail.to_vec();
        // Request a `.pom` — no pom build available.
        assert!(resolve_mutable_version(&req("foo-1.0-SNAPSHOT.pom"), &avail_refs).is_none());
        // Request a classifier with no matching build.
        assert!(
            resolve_mutable_version(&req("foo-1.0-SNAPSHOT-javadoc.jar"), &avail_refs).is_none()
        );
    }

    #[test]
    fn returns_none_for_non_snapshot_request() {
        let avail = ["com/example/foo/1.0/foo-1.0.jar"];
        let avail_refs: Vec<&str> = avail.to_vec();
        let got = resolve_mutable_version("com/example/foo/1.0/foo-1.0.jar", &avail_refs);
        assert!(got.is_none());
    }

    #[test]
    fn returns_none_for_short_path() {
        // Fewer than 4 segments cannot carry group/artifact/version/filename.
        assert!(resolve_mutable_version("foo-1.0-SNAPSHOT.jar", &[]).is_none());
        assert!(resolve_mutable_version("a/b/c", &["a/b/c"]).is_none());
    }

    #[test]
    fn ignores_other_artifacts_and_bases_in_available() {
        // available set may contain unrelated files; they must not match.
        let avail = [
            "com/example/foo/1.0-SNAPSHOT/bar-1.0-20231201.120000-3.jar", // wrong artifact
            "com/example/foo/1.0-SNAPSHOT/foo-2.0-20231201.120000-3.jar", // wrong base
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.jar", // the match
        ];
        let avail_refs: Vec<&str> = avail.to_vec();
        let got = resolve_mutable_version(&req("foo-1.0-SNAPSHOT.jar"), &avail_refs).unwrap();
        assert_eq!(
            got,
            "com/example/foo/1.0-SNAPSHOT/foo-1.0-20231201.120000-3.jar"
        );
    }

    #[test]
    fn parse_timestamped_file_decomposes_classifier_and_ext() {
        let tf =
            parse_timestamped_file("foo-1.0-20231201.120000-3-sources.jar", "foo", "1.0").unwrap();
        assert_eq!(tf.classifier, "sources");
        assert_eq!(tf.extension, "jar");
        assert_eq!(tf.ts.build_number, 3);

        let main = parse_timestamped_file("foo-1.0-20231201.120000-3.jar", "foo", "1.0").unwrap();
        assert_eq!(main.classifier, "");
        assert_eq!(main.extension, "jar");

        // Wrong prefix → None.
        assert!(parse_timestamped_file("bar-1.0-20231201.120000-3.jar", "foo", "1.0").is_none());
        // No extension → None.
        assert!(parse_timestamped_file("foo-1.0-20231201.120000-3", "foo", "1.0").is_none());
    }

    // -- decompose_snapshot_filename ------------------------------------------

    #[test]
    fn decompose_snapshot_filename_main_artifact() {
        let snap =
            decompose_snapshot_filename("foo-1.0-20231201.120000-3.jar", "foo", "1.0").unwrap();
        assert_eq!(snap.classifier, None);
        assert_eq!(snap.extension, "jar");
        assert_eq!(snap.value, "1.0-20231201.120000-3");
        assert_eq!(snap.timestamp, "20231201.120000"); // dotted, verbatim
        assert_eq!(snap.updated, "20231201120000"); // NON-dotted
        assert_eq!(snap.build_number, 3);
    }

    #[test]
    fn decompose_snapshot_filename_with_classifier() {
        let snap =
            decompose_snapshot_filename("foo-1.0-20231205.080000-5-sources.jar", "foo", "1.0")
                .unwrap();
        assert_eq!(snap.classifier, Some("sources".to_string()));
        assert_eq!(snap.extension, "jar");
        assert_eq!(snap.value, "1.0-20231205.080000-5");
        assert_eq!(snap.timestamp, "20231205.080000");
        assert_eq!(snap.updated, "20231205080000");
        assert_eq!(snap.build_number, 5);
    }

    #[test]
    fn decompose_snapshot_filename_lowercases_extension() {
        // The extension is folded to lowercase (matches the resolver matcher).
        let snap =
            decompose_snapshot_filename("foo-1.0-20231201.120000-3.POM", "foo", "1.0").unwrap();
        assert_eq!(snap.extension, "pom");
    }

    #[test]
    fn decompose_snapshot_filename_rejects_non_builds() {
        // Wrong artifact prefix.
        assert!(
            decompose_snapshot_filename("bar-1.0-20231201.120000-3.jar", "foo", "1.0").is_none()
        );
        // Wrong base.
        assert!(
            decompose_snapshot_filename("foo-2.0-20231201.120000-3.jar", "foo", "1.0").is_none()
        );
        // No parseable timestamp (literal base-SNAPSHOT, non-timestamped).
        assert!(decompose_snapshot_filename("foo-1.0-SNAPSHOT.jar", "foo", "1.0").is_none());
        // No extension.
        assert!(decompose_snapshot_filename("foo-1.0-20231201.120000-3", "foo", "1.0").is_none());
    }

    #[test]
    fn parse_unresolved_request_decomposes() {
        let (c, e) = parse_unresolved_request("foo-1.0-SNAPSHOT.jar", "foo", "1.0").unwrap();
        assert_eq!(c, "");
        assert_eq!(e, "jar");
        let (c, e) =
            parse_unresolved_request("foo-1.0-SNAPSHOT-javadoc.jar", "foo", "1.0").unwrap();
        assert_eq!(c, "javadoc");
        assert_eq!(e, "jar");
        assert!(parse_unresolved_request("foo-1.0-SNAPSHOT", "foo", "1.0").is_none());
        assert!(parse_unresolved_request("bar-1.0-SNAPSHOT.jar", "foo", "1.0").is_none());
    }
}
