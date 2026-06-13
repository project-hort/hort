//! Application-layer outbound port traits.
//!
//! Most port traits in this workspace live in [`hort_domain::ports`] —
//! they are pure-Rust contracts the application layer calls into and
//! the adapter crates implement. This module is for ports whose
//! contract intentionally lives *above* the domain layer because they
//! compose domain primitives with async / I/O concerns that do not
//! belong in `hort-domain`.
//!
//! Today the only resident is [`upstream_metadata::UpstreamMetadataPort`]:
//! it composes the synchronous parsing-side
//! [`hort_domain::ports::format_handler::FormatHandler`] methods
//! (`extract_upstream_versions` + `upstream_metadata_path`) with the
//! async per-format fetch helpers in the `hort-http-<format>` crates.
//! Async + `reqwest` are anti-pattern hard blocks in `hort-domain` (see
//! `CLAUDE.md` → architectural direction), so the composing port has
//! to live here. The concrete implementation lives in the dedicated
//! `hort-formats-upstream` crate; this module is the trait + the typed
//! error only.

pub mod upstream_metadata;
