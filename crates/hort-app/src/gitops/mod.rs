//! Gitops apply-pipeline support modules consumed by
//! [`ApplyConfigUseCase`](crate::use_cases::apply_config_use_case).
//!
//! [`event_sourced::ApplyEventSourcedKind`] is
//! the trait that lets the apply pipeline diff a desired YAML
//! envelope against the current projection and emit the matching
//! domain events. The trait stays pure logic (no I/O); resolution of
//! cross-spec references (e.g. repository name → UUID) happens in the
//! pipeline before it constructs the applier.

pub mod event_sourced;
