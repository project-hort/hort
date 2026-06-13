//! Shared [`IndexFilter`] implementations for the unified index
//! pipeline (see `docs/architecture/explanation/index-construction.md`).
//!
//! Two filters, both operating on the
//! [`VersionEntry`] spine (the per-format `payload` is opaque to them):
//!
//! - [`NonServableStatusFilter`] — universal. Drops every entry whose
//!   `status` is [`QuarantineStatus::Quarantined`] /
//!   [`QuarantineStatus::Rejected`] / [`QuarantineStatus::ScanIndeterminate`].
//!   This is the **rescan-rejection visibility close**: a hosted
//!   artifact transitioned to
//!   [`QuarantineStatus::Rejected`] by the rescan path
//!   disappears from the index, fixing the asymmetry where the
//!   download path correctly 503s but the index kept advertising
//!   the version.
//!
//! - [`IndexModeFilter`] — wraps the `filter_served_versions`
//!   semantics on the [`VersionEntry`] spine. The original helper
//!   takes two parallel inputs (`upstream_versions: &[&str]` +
//!   `status: &[(String, QuarantineStatus)]`); the unified pipeline
//!   merges these into one `Vec<VersionEntry>` where each entry
//!   carries both `version` and `status` (and `status == None`
//!   represents a "never-ingested upstream version" — the same
//!   "unknown" tier the original helper handled by absence-from-the-
//!   `status`-map). The two `IndexMode` arms therefore reduce to a
//!   single predicate per entry:
//!
//!     | `IndexMode`            | `status == None`  | `status == Some(Released/None-variant)` | `status == Some(Q/R/SI)` |
//!     |------------------------|-------------------|-----------------------------------------|--------------------------|
//!     | `ReleasedOnly`         | drop              | keep                                    | drop                     |
//!     | `IncludePending`       | keep              | keep                                    | drop                     |
//!
//!   The columns reproduce `filter_served_versions`' load-bearing
//!   behaviour:
//!   `ReleasedOnly` is build-safe (no never-ingested versions surface
//!   in the served set, so no `503`-on-resolve); `IncludePending`
//!   exposes upstream's full catalog minus known-bad versions.
//!   (`FilterQuarantined` was renamed to `IncludePending` in place,
//!   pre-v1.0 — ADR 0015.)
//!
//! # Composition
//!
//! The per-format serve handler composes the pipeline as
//! `[NonServableStatusFilter, IndexModeFilter::new(repo.index_mode)]`.
//! `NonServableStatusFilter` runs first; `IndexModeFilter` then makes
//! the mode-specific decision about never-ingested entries. (Running
//! `IndexModeFilter` second is purely organisational — the two filters
//! commute on the matrix above because both agree that
//! `Some(Q/R/SI)` is dropped; only the never-ingested column differs
//! between modes, and `NonServableStatusFilter` never touches it.)
//!
//! # Tracing
//!
//! `IndexFilter::apply` is intentionally **not** `#[instrument]`ed.
//! These are pure-function filters with no I/O, called once per
//! index-serve request on every format. The architect rule's spirit is
//! that *application-layer security-relevant decisions get traced* —
//! the filter pipeline is structural; the per-format serve handler
//! is where the overall security-relevant decision is
//! traced. Instrumenting `apply` would spam logs without adding
//! diagnostic value beyond the per-version filter counter
//! (`hort_index_versions_filtered_total`) that already exists.

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::IndexMode;

use crate::use_cases::index_serve::{IndexFilter, VersionEntry};

/// Universal non-servable-status filter — drops entries whose
/// `status` is [`QuarantineStatus::Quarantined`] /
/// [`QuarantineStatus::Rejected`] / [`QuarantineStatus::ScanIndeterminate`].
///
/// Entries with `status == None` (never-ingested-by-Hort — the "unknown"
/// tier the proxy source produces) and `status == Some(Released)` /
/// `Some(None-variant)` are kept. The downstream [`IndexModeFilter`]
/// decides what to do with the "unknown" tier.
///
/// This is the **rescan-rejection visibility close**: a hosted
/// artifact transitioned to [`QuarantineStatus::Rejected`] by the
/// rescan path is dropped here, regardless of `IndexMode`.
/// Per-format integration tests pin this invariant.
#[derive(Debug, Default, Clone, Copy)]
pub struct NonServableStatusFilter;

impl IndexFilter for NonServableStatusFilter {
    fn apply(&self, entries: Vec<VersionEntry>) -> Vec<VersionEntry> {
        entries
            .into_iter()
            .filter(|e| match e.status {
                None => true,
                Some(s) => is_servable_status(s),
            })
            .collect()
    }
}

/// [`IndexMode`]-aware filter — preserves the
/// `filter_served_versions` semantics on the [`VersionEntry`] spine.
///
/// See the module-level rustdoc for the per-entry truth table. The
/// filter is constructed with the repository's [`IndexMode`]; the
/// per-format serve handler (Items 2/3/4) reads
/// `repository.index_mode` and passes it to [`IndexModeFilter::new`].
///
/// The `filter_served_versions` semantics are load-bearing — the
/// existing per-format
/// helper tests (`filter_served_versions` arm coverage in
/// [`crate::use_cases::index_serve_filter`]) remain the canonical
/// reference for the predicate's behaviour. This filter is a
/// per-entry restatement of the same predicate; it does **not** call
/// `filter_served_versions` because the helper's input shape
/// (separate `upstream_versions` + `status` arrays) is the
/// pre-pipeline shape the unified [`VersionEntry`] supersedes.
#[derive(Debug, Clone, Copy)]
pub struct IndexModeFilter {
    /// The repository's index-serve mode. Drives the
    /// "drop never-ingested" decision (`ReleasedOnly` drops them;
    /// `IncludePending` keeps them).
    pub mode: IndexMode,
}

impl IndexModeFilter {
    /// Construct a filter for the given mode.
    pub fn new(mode: IndexMode) -> Self {
        Self { mode }
    }
}

impl IndexFilter for IndexModeFilter {
    fn apply(&self, entries: Vec<VersionEntry>) -> Vec<VersionEntry> {
        entries
            .into_iter()
            .filter(|e| match (self.mode, e.status) {
                // Never-ingested (no Hort row): mode decides.
                // ReleasedOnly is build-safe — drop.
                (IndexMode::ReleasedOnly, None) => false,
                // IncludePending exposes upstream's full catalog —
                // keep never-ingested.
                (IndexMode::IncludePending, None) => true,
                // Known status: keep iff servable. Identical between
                // modes — the only mode-dependent column is None.
                (_, Some(s)) => is_servable_status(s),
            })
            .collect()
    }
}

/// True iff a version with this [`QuarantineStatus`] may be served to
/// clients. Mirrors the predicate of the same name in
/// [`crate::use_cases::index_serve_filter::is_servable_status`] — the
/// two are duplicated deliberately because the helper module's
/// version is `pub(super)`-shaped (file-local), and re-exposing it
/// across the use-case module boundary just to share three lines
/// would couple two modules whose only common ground is the
/// underlying domain rule. The rule itself ("Released and None are
/// servable; Quarantined / Rejected / ScanIndeterminate are not") is
/// a [`QuarantineStatus`] invariant that lives in `hort-domain` (see
/// `QuarantineStatus`'s rustdoc); both filter implementations encode
/// it identically.
fn is_servable_status(status: QuarantineStatus) -> bool {
    matches!(status, QuarantineStatus::Released | QuarantineStatus::None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Note on test approach: `PerVersionPayload` is uninhabited in
    // Item 1 (no variants until Items 2/3/4), so we cannot construct
    // a `VersionEntry` directly — the `payload` field has no
    // constructible value. Each filter's `apply` is exercised on the
    // empty input (which pins the trait shape + the empty-input
    // behaviour) and the per-arm predicate is tested directly via a
    // mirror function that reproduces the closure body. The two
    // matrix tests below cover every cell of the truth tables in
    // both filter implementations.
    //
    // Once Items 2/3/4 add the first `PerVersionPayload` variant,
    // this test module gains real `VersionEntry`-shaped fixtures and
    // the matrix tests become end-to-end through `apply`.

    // -----------------------------------------------------------------
    // NonServableStatusFilter
    // -----------------------------------------------------------------

    #[test]
    fn non_servable_status_filter_apply_passes_empty_input_through() {
        let f = NonServableStatusFilter;
        let out = f.apply(Vec::new());
        assert!(out.is_empty());
    }

    #[test]
    fn non_servable_status_filter_predicate_matrix() {
        // The predicate the filter encodes — see the `match` in
        // `NonServableStatusFilter::apply`. We exercise each arm
        // directly because constructing a `VersionEntry` requires a
        // `PerVersionPayload` value, which is uninhabited until
        // Items 2/3/4.
        //
        // Keeps: None, Some(Released), Some(None-variant).
        // Drops: Some(Quarantined), Some(Rejected), Some(ScanIndeterminate).
        assert!(non_servable_filter_keeps(None));
        assert!(non_servable_filter_keeps(Some(QuarantineStatus::Released)));
        assert!(non_servable_filter_keeps(Some(QuarantineStatus::None)));
        assert!(!non_servable_filter_keeps(Some(
            QuarantineStatus::Quarantined
        )));
        assert!(!non_servable_filter_keeps(Some(QuarantineStatus::Rejected)));
        assert!(!non_servable_filter_keeps(Some(
            QuarantineStatus::ScanIndeterminate
        )));
    }

    /// Mirror of the closure inside `NonServableStatusFilter::apply` —
    /// kept in lockstep with the impl. The matrix test above checks
    /// every input column.
    fn non_servable_filter_keeps(status: Option<QuarantineStatus>) -> bool {
        match status {
            None => true,
            Some(s) => is_servable_status(s),
        }
    }

    // -----------------------------------------------------------------
    // IndexModeFilter
    // -----------------------------------------------------------------

    #[test]
    fn index_mode_filter_new_stores_mode() {
        let f = IndexModeFilter::new(IndexMode::IncludePending);
        assert_eq!(f.mode, IndexMode::IncludePending);
        let f = IndexModeFilter::new(IndexMode::ReleasedOnly);
        assert_eq!(f.mode, IndexMode::ReleasedOnly);
    }

    #[test]
    fn index_mode_filter_apply_passes_empty_input_through_under_both_modes() {
        for mode in [IndexMode::ReleasedOnly, IndexMode::IncludePending] {
            let f = IndexModeFilter::new(mode);
            let out = f.apply(Vec::new());
            assert!(out.is_empty(), "{mode:?}: empty input must pass through");
        }
    }

    #[test]
    fn index_mode_filter_predicate_matrix_released_only() {
        // ReleasedOnly: drops never-ingested (None) and known non-servable;
        // keeps Released and None-variant.
        assert!(!index_mode_keeps(IndexMode::ReleasedOnly, None));
        assert!(index_mode_keeps(
            IndexMode::ReleasedOnly,
            Some(QuarantineStatus::Released)
        ));
        assert!(index_mode_keeps(
            IndexMode::ReleasedOnly,
            Some(QuarantineStatus::None)
        ));
        assert!(!index_mode_keeps(
            IndexMode::ReleasedOnly,
            Some(QuarantineStatus::Quarantined)
        ));
        assert!(!index_mode_keeps(
            IndexMode::ReleasedOnly,
            Some(QuarantineStatus::Rejected)
        ));
        assert!(!index_mode_keeps(
            IndexMode::ReleasedOnly,
            Some(QuarantineStatus::ScanIndeterminate)
        ));
    }

    #[test]
    fn index_mode_filter_predicate_matrix_include_pending() {
        // IncludePending: keeps never-ingested (None) and Released
        // and None-variant; drops known non-servable.
        assert!(index_mode_keeps(IndexMode::IncludePending, None));
        assert!(index_mode_keeps(
            IndexMode::IncludePending,
            Some(QuarantineStatus::Released)
        ));
        assert!(index_mode_keeps(
            IndexMode::IncludePending,
            Some(QuarantineStatus::None)
        ));
        assert!(!index_mode_keeps(
            IndexMode::IncludePending,
            Some(QuarantineStatus::Quarantined)
        ));
        assert!(!index_mode_keeps(
            IndexMode::IncludePending,
            Some(QuarantineStatus::Rejected)
        ));
        assert!(!index_mode_keeps(
            IndexMode::IncludePending,
            Some(QuarantineStatus::ScanIndeterminate)
        ));
    }

    /// Mirror of the closure inside `IndexModeFilter::apply` — kept
    /// in lockstep with the impl. The two matrix tests above cover
    /// every `(IndexMode, status)` cell.
    fn index_mode_keeps(mode: IndexMode, status: Option<QuarantineStatus>) -> bool {
        match (mode, status) {
            (IndexMode::ReleasedOnly, None) => false,
            (IndexMode::IncludePending, None) => true,
            (_, Some(s)) => is_servable_status(s),
        }
    }

    // -----------------------------------------------------------------
    // is_servable_status — explicit branch coverage
    // -----------------------------------------------------------------

    #[test]
    fn is_servable_status_branches() {
        assert!(is_servable_status(QuarantineStatus::Released));
        assert!(is_servable_status(QuarantineStatus::None));
        assert!(!is_servable_status(QuarantineStatus::Quarantined));
        assert!(!is_servable_status(QuarantineStatus::Rejected));
        assert!(!is_servable_status(QuarantineStatus::ScanIndeterminate));
    }
}
