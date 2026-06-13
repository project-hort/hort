//! `hort_advisory_ingest_count` — per-ecosystem advisory ingest counter.
//!
//! NIS2 Art. 21(2)(f) efficacy metric.
//!
//! Emitted by [`OsvAdvisoryAdapter::pull_diff_since`] once per successful
//! per-ecosystem ingest, counting the number of advisory entries ingested in
//! that tick.  The `category` label maps each OSV ecosystem to a bounded fixed
//! set so the metric has predictable cardinality (≤ 12 series total).
//!
//! **Alert spec:** operators SHOULD alert when
//! `increase(hort_advisory_ingest_count[7d]) == 0` for any `category` that has
//! historically produced advisories — a zero 7-day increase signals the bulk
//! feed may be broken or the OSV dataset for that category is stale (silent
//! detection failure).  The threshold for "expected floor" is ecosystem-specific
//! and should be tuned per deployment; a conservative starting point is
//! `increase[7d] < 1` (any advisory is better than zero).

/// Label key for the `hort_advisory_ingest_count` metric.
///
/// `category` here is this metric's **own per-metric bounded value set**
/// (advisory ecosystem class — 11 named values + `"other"`), catalogued in
/// `docs/metrics-catalog.md §"Advisory ingest efficacy"`.  It is distinct from
/// the event-stream `category` taxonomy (`artifact`, `policy`, `admin`, …) used
/// by other metrics such as `hort_events_published_total`.  The two value sets
/// share the label key name because `category` is on the architect's allowed-
/// label list; they do NOT share values and must not be queried interchangeably.
///
/// Using this label (rather than a raw `ecosystem` label) avoids per-ecosystem
/// cardinality inflation — the raw OSV ecosystem strings (`npm`, `PyPI`,
/// `crates.io`, …) would be 11 distinct label values today and could grow
/// unboundedly if new ecosystems are added.  Mapping to the fixed logical
/// category taxonomy keeps the metric self-stable at ≤ 12 series.
pub const LABEL_CATEGORY: &str = "category";

// ---------------------------------------------------------------------------
// Fixed category values — closed taxonomy, 11 values
// ---------------------------------------------------------------------------

/// JavaScript / Node.js ecosystem (OSV: `npm`).
pub const CATEGORY_JAVASCRIPT: &str = "javascript";
/// Python ecosystem (OSV: `PyPI`).
pub const CATEGORY_PYTHON: &str = "python";
/// Rust ecosystem (OSV: `crates.io`).
pub const CATEGORY_RUST: &str = "rust";
/// JVM ecosystem (OSV: `Maven`).
pub const CATEGORY_JVM: &str = "jvm";
/// Go ecosystem (OSV: `Go`).
pub const CATEGORY_GO: &str = "go";
/// Ruby ecosystem (OSV: `RubyGems`).
pub const CATEGORY_RUBY: &str = "ruby";
/// .NET ecosystem (OSV: `NuGet`).
pub const CATEGORY_DOTNET: &str = "dotnet";
/// PHP ecosystem (OSV: `Packagist`).
pub const CATEGORY_PHP: &str = "php";
/// BEAM / Erlang / Elixir ecosystem (OSV: `Hex`).
pub const CATEGORY_BEAM: &str = "beam";
/// Dart / Flutter ecosystem (OSV: `Pub`).
pub const CATEGORY_DART: &str = "dart";
/// Conda / data-science ecosystem (OSV: `Conda`).
pub const CATEGORY_CONDA: &str = "conda";
/// Catch-all for OSV ecosystem strings not in the fixed mapping.
/// Should never appear in practice — if it does, add a new constant.
pub const CATEGORY_OTHER: &str = "other";

// ---------------------------------------------------------------------------
// Mapping function
// ---------------------------------------------------------------------------

/// Map an OSV ecosystem label (the literal from the URL path or from
/// `affected[].package.ecosystem`) to the bounded `category` label value used
/// in `hort_advisory_ingest_count`.
///
/// The mapping is a closed set. Any unrecognised label maps to `"other"` and
/// emits a `tracing::warn!` at the call site so operators can see when OSV has
/// added a new ecosystem that needs a category entry here.
///
/// Must stay in sync with `bulk::osv_label_to_ecosystem` — when a new OSV
/// ecosystem label is supported there, add a corresponding entry here.
pub fn osv_label_to_category(label: &str) -> &'static str {
    match label {
        "npm" => CATEGORY_JAVASCRIPT,
        "PyPI" => CATEGORY_PYTHON,
        "crates.io" => CATEGORY_RUST,
        "Maven" => CATEGORY_JVM,
        "Go" => CATEGORY_GO,
        "RubyGems" => CATEGORY_RUBY,
        "NuGet" => CATEGORY_DOTNET,
        "Packagist" => CATEGORY_PHP,
        "Hex" => CATEGORY_BEAM,
        "Pub" => CATEGORY_DART,
        "Conda" => CATEGORY_CONDA,
        _ => CATEGORY_OTHER,
    }
}

// ---------------------------------------------------------------------------
// Emission helper
// ---------------------------------------------------------------------------

/// Increment `hort_advisory_ingest_count{category}` by `count`.
///
/// Called once per successful per-ecosystem ingest inside
/// `OsvAdvisoryAdapter::pull_diff_since` with the count of
/// `AdvisoryEntry` values returned by `pull_one_ecosystem`.  Emitted
/// at the adapter layer — NOT at `hort-app` — because this crate is the
/// only layer that knows the per-ecosystem ingest count.
///
/// `osv_label` is the OSV bulk-archive path label (e.g. `"npm"`,
/// `"PyPI"`, `"crates.io"`). It is converted to a bounded category
/// string internally so the metric label cardinality is fixed (≤ 12
/// series: 11 named categories + `"other"`).
pub fn emit_advisory_ingest_count(osv_label: &str, count: u64) {
    let category = osv_label_to_category(osv_label);
    metrics::counter!(
        "hort_advisory_ingest_count",
        LABEL_CATEGORY => category,
    )
    .increment(count);
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // osv_label_to_category — closed mapping coverage
    // -----------------------------------------------------------------------

    #[test]
    fn every_supported_osv_label_maps_to_a_non_other_category() {
        // These are the labels from bulk::osv_label_to_ecosystem — they must
        // all resolve to a named (non-"other") category.
        let expected = [
            ("npm", CATEGORY_JAVASCRIPT),
            ("PyPI", CATEGORY_PYTHON),
            ("crates.io", CATEGORY_RUST),
            ("Maven", CATEGORY_JVM),
            ("Go", CATEGORY_GO),
            ("RubyGems", CATEGORY_RUBY),
            ("NuGet", CATEGORY_DOTNET),
            ("Packagist", CATEGORY_PHP),
            ("Hex", CATEGORY_BEAM),
            ("Pub", CATEGORY_DART),
            ("Conda", CATEGORY_CONDA),
        ];
        for (label, expected_cat) in expected {
            let got = osv_label_to_category(label);
            assert_eq!(
                got, expected_cat,
                "label '{label}' expected category '{expected_cat}', got '{got}'"
            );
            assert_ne!(
                got, CATEGORY_OTHER,
                "label '{label}' must not map to 'other'"
            );
        }
    }

    #[test]
    fn unknown_label_maps_to_other() {
        assert_eq!(osv_label_to_category("Helm"), CATEGORY_OTHER);
        assert_eq!(osv_label_to_category(""), CATEGORY_OTHER);
        assert_eq!(osv_label_to_category("notreal"), CATEGORY_OTHER);
        // Case-sensitive: "NPM" is not "npm".
        assert_eq!(osv_label_to_category("NPM"), CATEGORY_OTHER);
    }

    #[test]
    fn emit_advisory_ingest_count_uses_category_label_not_raw_ecosystem() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::MetricKind;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            emit_advisory_ingest_count("npm", 42);
        });

        let snap = snapshotter.snapshot().into_vec();

        let counter = snap.iter().find(|(ck, _, _, _)| {
            ck.kind() == MetricKind::Counter && ck.key().name() == "hort_advisory_ingest_count"
        });
        let (key, _, _, value) = counter.expect("hort_advisory_ingest_count must fire");

        // Label must be `category=javascript`, NOT `ecosystem=npm`.
        let cat_label = key
            .key()
            .labels()
            .find(|l| l.key() == LABEL_CATEGORY)
            .expect("category label present");
        assert_eq!(cat_label.value(), CATEGORY_JAVASCRIPT);
        // No raw ecosystem label.
        assert!(
            !key.key().labels().any(|l| l.key() == "ecosystem"),
            "raw ecosystem label must NOT appear on hort_advisory_ingest_count"
        );

        match value {
            DebugValue::Counter(n) => assert_eq!(*n, 42),
            other => panic!("expected Counter(42), got {other:?}"),
        }
    }
}
