//! Scanning-subsystem shared facts.
//!
//! Single source of truth for the set of vulnerability-scanner backends that
//! are **compiled into this build** — the scanning-subsystem analogue of
//! [`crate::provenance::TIER1_PROVENANCE_CAPABLE_FORMATS`].
//!
//! Apply-time `ScanPolicy.scanBackends` validation
//! ([`hort_config::desired::validate_scan_policy_backends`]) checks every
//! declared backend name against THIS set — **not** against the live
//! `scanner_registry` worker table.
//!
//! ## Why a static set, not the live registry
//!
//! Validating `scanBackends` against the *live* worker registry was a
//! boot-ordering hazard. On a fresh deployment the gitops boot applies the
//! desired config before any `hort-worker` has registered its first
//! heartbeat, so the live set is **transiently empty**. A perfectly correct
//! `scanBackends: [trivy]` policy was therefore rejected fail-closed at
//! preflight, parking the server not-ready with no retry (it serves
//! `/healthz` 200 so the kubelet never restarts it) until an operator
//! manually bounced the pod — regression **H20**, hit in production.
//!
//! Whether a backend *name* is valid is a **permanent** property of the
//! build, knowable offline and independent of worker-registration timing: a
//! name is either a real, compiled-in scanner adapter or it is not.
//! Validating that property here removes the race entirely while still
//! catching the operator typo the live check was meant to catch.
//!
//! Whether a worker advertising a given backend is actually *running* is a
//! runtime-liveness concern, surfaced by metrics/health — never a
//! gitops-apply validity error.
//!
//! When a new scanner adapter is wired (e.g. `grype`), add its `name()` here
//! in lock-step so the apply-time validator accepts it.

/// The vulnerability-scanner backend names compiled into this build.
///
/// Each entry is the `name()` returned by a wired `ScannerPort` adapter:
/// `trivy` (`hort-adapters-scanner-trivy`) and `osv`
/// (`hort-adapters-scanner-osv`).
pub const KNOWN_SCAN_BACKENDS: &[&str] = &["trivy", "osv"];

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the compiled-in scanner set. Adding (or removing) a scanner
    /// adapter is a deliberate capability change that this const and the
    /// apply-time validator pick up together; the pin documents that intent
    /// and fails loudly if the set drifts silently.
    #[test]
    fn known_backends_are_trivy_and_osv() {
        assert_eq!(KNOWN_SCAN_BACKENDS, &["trivy", "osv"]);
    }
}
