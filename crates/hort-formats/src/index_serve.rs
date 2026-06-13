//! Re-export façade for the format-agnostic index-construction pipeline.
//! See explanation/index-construction.md.
//!
//! The traits, spine [`VersionEntry`], [`PerVersionPayload`] empty
//! enum, [`BuildContext`], and the [`VersionOrdering`] re-export all
//! live in [`hort_app::use_cases::index_serve`] — `hort-app` is the lower
//! layer in the dep graph (`hort-formats → hort-app`), so the trait
//! definitions live there to let the in-`hort-app` filter
//! implementations (`NonServableStatusFilter` / `IndexModeFilter` in
//! [`hort_app::use_cases::index_filters`]) reference them without a
//! circular edge.
//!
//! This module re-exports the public surface under the
//! `hort_formats::index_serve` path the design doc §2.6 names so
//! format-crate consumers — the per-format `IndexBuilder`
//! implementations that land in
//! `hort_formats::<format>::index` in Items 2/3/4 — have a single
//! import location: `use hort_formats::index_serve::{VersionEntry,
//! IndexBuilder, BuildContext, …};`.
//!
//! See the [`hort_app::use_cases::index_serve`] module docs for the
//! full rustdoc of each type.

pub use hort_app::use_cases::index_serve::{
    BuildContext, IndexBuilder, IndexFilter, PerVersionPayload, VersionEntry, VersionOrdering,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke-test the re-export — the items must be reachable via
    /// `hort_formats::index_serve::…` so the per-format `IndexBuilder`
    /// modules (Items 2/3/4) can pull them from a single path.
    #[test]
    fn reexports_are_reachable() {
        // VersionEntry is a struct shape — pin that the three fields
        // are visible at the re-export path. An empty `Vec` exercises
        // the type at the type level without requiring a constructed
        // `PerVersionPayload` value (the npm variant lands via Item 2
        // and is exercised in `hort-formats::npm::index`'s test module).
        let entries: Vec<VersionEntry> = Vec::new();
        assert!(entries.is_empty());

        // IndexBuilder + IndexFilter + BuildContext + VersionOrdering
        // are traits / structs that compile here only if the
        // re-export brought them in.
        fn _accept_filter(_f: &dyn IndexFilter) {}
        fn _accept_builder(_b: &dyn IndexBuilder) {}
        fn _accept_ordering(_o: &dyn VersionOrdering) {}
        fn _accept_ctx(_c: &BuildContext<'_>) {}
        // PerVersionPayload has an `Npm` variant; the type-level
        // reachability check is the same shape — a `fn` parameter that
        // compiles iff the re-export resolved.
        fn _accept_payload(_p: &PerVersionPayload) {}
    }
}
