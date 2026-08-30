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
//! # Held metadata and the write-authorized hold-read
//!
//! Both filters take a [`HeldVisibility`], and both default to
//! [`HeldVisibility::Hidden`] — the ordinary reader's view, where a
//! [`QuarantineStatus::Quarantined`] version is absent from the index.
//! [`HeldVisibility::WriteAuthorized`] is the hold-read exemption
//! (ADR 0055, generalising ADR 0039 §10): a principal holding *granted*
//! write authority on the repository may resolve held **metadata**
//! there, because a publisher has to resolve what it just uploaded
//! before the hold clears. It is the caller's job to establish that
//! authority — the filters only carry the decision.
//!
//! The exemption is `Quarantined`-only and metadata-only.
//! `Rejected` and `ScanIndeterminate` are terminal verdicts and stay
//! filtered for every caller; held **bytes** stay unserved to everyone
//! (the download paths do not consult this type at all).
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

/// Whether the status filters admit a **held** (`Quarantined`) version.
///
/// See the module-level rustdoc for the boundary this encodes. The
/// variants are not interchangeable authority levels: `Hidden` is the
/// invariant every reader gets, and `WriteAuthorized` is the narrow
/// exemption a caller must have positively established before it may
/// construct one.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum HeldVisibility {
    /// A `Quarantined` version is absent from the served index. Every
    /// anonymous, read-only and pull-through caller.
    #[default]
    Hidden,
    /// A `Quarantined` version survives the status filters — the
    /// write-authorized hold-read (ADR 0055). Only `Quarantined`;
    /// terminal verdicts are unaffected.
    WriteAuthorized,
}

impl HeldVisibility {
    /// Whether a version with this known status reaches the served set.
    ///
    /// Exhaustive over [`QuarantineStatus`] with no wildcard arm, so a
    /// future variant is a compile error here rather than silently
    /// inheriting either answer.
    ///
    /// The `Hidden` row restates
    /// [`crate::use_cases::index_serve_filter::is_servable_status`],
    /// deliberately rather than by delegation: that helper is
    /// file-local, and re-exposing it across the use-case module
    /// boundary would couple two modules whose only common ground is
    /// the underlying rule. The rule ("Released and None are servable;
    /// Quarantined / Rejected / ScanIndeterminate are not") is a
    /// [`QuarantineStatus`] invariant that lives in `hort-domain`; both
    /// encode it identically.
    fn admits(self, status: QuarantineStatus) -> bool {
        match status {
            QuarantineStatus::Released | QuarantineStatus::None => true,
            QuarantineStatus::Quarantined => matches!(self, Self::WriteAuthorized),
            QuarantineStatus::Rejected | QuarantineStatus::ScanIndeterminate => false,
        }
    }
}

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
///
/// [`Default`] is [`HeldVisibility::Hidden`] — the ordinary reader's
/// filter.
#[derive(Debug, Default, Clone, Copy)]
pub struct NonServableStatusFilter {
    held: HeldVisibility,
}

impl NonServableStatusFilter {
    /// Construct the filter for a caller with the given held-metadata
    /// visibility.
    pub fn new(held: HeldVisibility) -> Self {
        Self { held }
    }
}

impl IndexFilter for NonServableStatusFilter {
    fn apply(&self, entries: Vec<VersionEntry>) -> Vec<VersionEntry> {
        entries
            .into_iter()
            .filter(|e| match e.status {
                None => true,
                Some(s) => self.held.admits(s),
            })
            .collect()
    }
}

/// [`IndexMode`]-aware filter — preserves the
/// `filter_served_versions` semantics on the [`VersionEntry`] spine.
///
/// See the module-level rustdoc for the per-entry truth table. The
/// filter is constructed with the repository's [`IndexMode`]; the
/// per-format serve handler reads `repository.index_mode` and passes it
/// to [`IndexModeFilter::new`].
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
    /// Held-metadata visibility for this caller. The mode arms are
    /// unaffected by it — it only decides the `Some(Quarantined)`
    /// column, identically in both modes.
    held: HeldVisibility,
}

impl IndexModeFilter {
    /// Construct a filter for the given mode, with held versions
    /// hidden — the ordinary reader's filter.
    pub fn new(mode: IndexMode) -> Self {
        Self {
            mode,
            held: HeldVisibility::Hidden,
        }
    }

    /// Construct a filter for the given mode and held-metadata
    /// visibility.
    pub fn with_held_visibility(mode: IndexMode, held: HeldVisibility) -> Self {
        Self { mode, held }
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
                // Known status: keep iff servable for this caller.
                // Identical between modes — the only mode-dependent
                // column is None.
                (_, Some(s)) => self.held.admits(s),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::use_cases::index_serve::{CargoVersionPayload, PerVersionPayload};

    // Note on test approach: each filter is covered twice over.
    //
    // End-to-end through `apply`, on a fixture carrying every status
    // column at once (`every_status_entry_set`) — this is what actually
    // exercises the closure bodies, so the filters' real behaviour and
    // not just their predicates is pinned. The payload variant is
    // irrelevant to both filters (they read `status` alone), so the
    // cargo one stands in for all four.
    //
    // And per-arm, through a mirror function that reproduces the
    // closure body. Those matrix tests enumerate every cell of the
    // truth tables in one place and fail with the offending column
    // named, which the end-to-end assertions cannot do as precisely.
    // They must be kept in lockstep with the impl.

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    /// One entry, versioned so the surviving set reads as an ordered
    /// list of status columns.
    fn entry(version: &str, status: Option<QuarantineStatus>) -> VersionEntry {
        VersionEntry {
            version: version.to_string(),
            status,
            payload: PerVersionPayload::Cargo(CargoVersionPayload {
                name_as_published: "hort-domain".to_string(),
                vers: version.to_string(),
                cksum: "0".repeat(64),
                deps: serde_json::Value::Array(Vec::new()),
                features: serde_json::Value::Object(serde_json::Map::new()),
                yanked: false,
                links: None,
                rust_version: None,
                v: None,
                features2: None,
                pubtime: None,
            }),
        }
    }

    /// Every status column in one input set, in a fixed order:
    ///
    /// | version | status |
    /// |---|---|
    /// | 1.0.0 | never ingested (no Hort row) |
    /// | 1.0.1 | `Released` |
    /// | 1.0.2 | `None` |
    /// | 1.0.3 | `Quarantined` — the only column the exemption moves |
    /// | 1.0.4 | `Rejected` |
    /// | 1.0.5 | `ScanIndeterminate` |
    fn every_status_entry_set() -> Vec<VersionEntry> {
        vec![
            entry("1.0.0", None),
            entry("1.0.1", Some(QuarantineStatus::Released)),
            entry("1.0.2", Some(QuarantineStatus::None)),
            entry("1.0.3", Some(QuarantineStatus::Quarantined)),
            entry("1.0.4", Some(QuarantineStatus::Rejected)),
            entry("1.0.5", Some(QuarantineStatus::ScanIndeterminate)),
        ]
    }

    /// The versions that survive `filter`, in input order.
    fn survivors(filter: &dyn IndexFilter, entries: Vec<VersionEntry>) -> Vec<String> {
        filter
            .apply(entries)
            .into_iter()
            .map(|e| e.version)
            .collect()
    }

    // -----------------------------------------------------------------
    // NonServableStatusFilter
    // -----------------------------------------------------------------

    #[test]
    fn non_servable_status_filter_apply_drops_held_and_verdicts_for_an_ordinary_reader() {
        assert_eq!(
            survivors(
                &NonServableStatusFilter::default(),
                every_status_entry_set()
            ),
            ["1.0.0", "1.0.1", "1.0.2"],
            "the ordinary reader sees neither the held version nor either verdict"
        );
    }

    #[test]
    fn non_servable_status_filter_apply_admits_the_held_version_for_a_write_authorized_caller() {
        assert_eq!(
            survivors(
                &NonServableStatusFilter::new(HeldVisibility::WriteAuthorized),
                every_status_entry_set()
            ),
            ["1.0.0", "1.0.1", "1.0.2", "1.0.3"],
            "the exemption admits the Quarantined column and moves no other — the two \
             verdicts stay dropped for a write-authorized caller too"
        );
    }

    #[test]
    fn non_servable_status_filter_apply_passes_empty_input_through() {
        for held in [HeldVisibility::Hidden, HeldVisibility::WriteAuthorized] {
            let f = NonServableStatusFilter::new(held);
            let out = f.apply(Vec::new());
            assert!(out.is_empty(), "{held:?}: empty input must pass through");
        }
    }

    #[test]
    fn non_servable_status_filter_default_hides_held_versions() {
        assert_eq!(
            NonServableStatusFilter::default().held,
            HeldVisibility::Hidden,
            "the default filter is the ordinary reader's — a caller that wants the \
             hold-read exemption has to ask for it explicitly"
        );
    }

    #[test]
    fn non_servable_status_filter_predicate_matrix() {
        // The predicate the filter encodes — see the `match` in
        // `NonServableStatusFilter::apply`. We exercise each arm
        // directly because constructing a `VersionEntry` requires a
        // `PerVersionPayload` value, which is currently uninhabited.
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
        non_servable_filter_keeps_for(HeldVisibility::Hidden, status)
    }

    /// The same mirror, parameterised by the caller's held-metadata
    /// visibility.
    fn non_servable_filter_keeps_for(
        held: HeldVisibility,
        status: Option<QuarantineStatus>,
    ) -> bool {
        match status {
            None => true,
            Some(s) => held.admits(s),
        }
    }

    #[test]
    fn non_servable_status_filter_predicate_matrix_write_authorized() {
        // The exemption's whole effect on this filter: the Quarantined
        // column flips, nothing else moves.
        let held = HeldVisibility::WriteAuthorized;
        assert!(non_servable_filter_keeps_for(held, None));
        assert!(non_servable_filter_keeps_for(
            held,
            Some(QuarantineStatus::Released)
        ));
        assert!(non_servable_filter_keeps_for(
            held,
            Some(QuarantineStatus::None)
        ));
        assert!(non_servable_filter_keeps_for(
            held,
            Some(QuarantineStatus::Quarantined)
        ));
        assert!(!non_servable_filter_keeps_for(
            held,
            Some(QuarantineStatus::Rejected)
        ));
        assert!(!non_servable_filter_keeps_for(
            held,
            Some(QuarantineStatus::ScanIndeterminate)
        ));
    }

    // -----------------------------------------------------------------
    // HeldVisibility — the hold-read exemption's whole truth table
    // -----------------------------------------------------------------

    #[test]
    fn held_visibility_hidden_admits_only_servable_statuses() {
        let v = HeldVisibility::Hidden;
        assert!(v.admits(QuarantineStatus::Released));
        assert!(v.admits(QuarantineStatus::None));
        assert!(!v.admits(QuarantineStatus::Quarantined));
        assert!(!v.admits(QuarantineStatus::Rejected));
        assert!(!v.admits(QuarantineStatus::ScanIndeterminate));
    }

    #[test]
    fn held_visibility_write_authorized_widens_quarantined_and_nothing_else() {
        let v = HeldVisibility::WriteAuthorized;
        assert!(v.admits(QuarantineStatus::Released));
        assert!(v.admits(QuarantineStatus::None));
        assert!(
            v.admits(QuarantineStatus::Quarantined),
            "the exemption exists so a publisher can resolve what it just uploaded"
        );
        assert!(
            !v.admits(QuarantineStatus::Rejected),
            "Rejected is a terminal verdict — the exemption covers a hold pending a \
             verdict, never a verdict already reached"
        );
        assert!(
            !v.admits(QuarantineStatus::ScanIndeterminate),
            "ScanIndeterminate is a terminal fail-closed block with no self-resolving \
             deadline — no caller sees it"
        );
    }

    #[test]
    fn held_visibility_default_is_hidden() {
        assert_eq!(HeldVisibility::default(), HeldVisibility::Hidden);
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
    fn index_mode_filter_new_hides_held_versions() {
        assert_eq!(
            IndexModeFilter::new(IndexMode::ReleasedOnly).held,
            HeldVisibility::Hidden
        );
    }

    #[test]
    fn index_mode_filter_with_held_visibility_stores_both() {
        let f = IndexModeFilter::with_held_visibility(
            IndexMode::IncludePending,
            HeldVisibility::WriteAuthorized,
        );
        assert_eq!(f.mode, IndexMode::IncludePending);
        assert_eq!(f.held, HeldVisibility::WriteAuthorized);
    }

    #[test]
    fn index_mode_filter_held_column_is_mode_independent() {
        // The exemption widens the `Some(Quarantined)` column only, and
        // does so identically in both modes — the never-ingested column
        // stays the mode's own decision.
        for mode in [IndexMode::ReleasedOnly, IndexMode::IncludePending] {
            let f = IndexModeFilter::with_held_visibility(mode, HeldVisibility::WriteAuthorized);
            assert!(f.held.admits(QuarantineStatus::Quarantined), "{mode:?}");
            assert!(!f.held.admits(QuarantineStatus::Rejected), "{mode:?}");
            assert_eq!(f.mode, mode);
        }
    }

    #[test]
    fn index_mode_filter_apply_over_every_status_column_in_both_modes() {
        // The mode decides the never-ingested column (1.0.0) and the
        // held visibility decides the Quarantined one (1.0.3); the two
        // are independent, and no other column moves.
        let cases = [
            (
                IndexMode::ReleasedOnly,
                HeldVisibility::Hidden,
                vec!["1.0.1", "1.0.2"],
            ),
            (
                IndexMode::ReleasedOnly,
                HeldVisibility::WriteAuthorized,
                vec!["1.0.1", "1.0.2", "1.0.3"],
            ),
            (
                IndexMode::IncludePending,
                HeldVisibility::Hidden,
                vec!["1.0.0", "1.0.1", "1.0.2"],
            ),
            (
                IndexMode::IncludePending,
                HeldVisibility::WriteAuthorized,
                vec!["1.0.0", "1.0.1", "1.0.2", "1.0.3"],
            ),
        ];
        for (mode, held, expected) in cases {
            let f = IndexModeFilter::with_held_visibility(mode, held);
            assert_eq!(
                survivors(&f, every_status_entry_set()),
                expected,
                "{mode:?} / {held:?}"
            );
        }
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
            (_, Some(s)) => HeldVisibility::Hidden.admits(s),
        }
    }
}
