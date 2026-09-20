//! Scanning-subsystem shared facts.
//!
//! Single source of truth for two compiled-in properties of this build —
//! the scanning-subsystem analogue of
//! [`crate::provenance::TIER1_PROVENANCE_CAPABLE_FORMATS`]:
//!
//! 1. [`KNOWN_SCAN_BACKENDS`] — which vulnerability-scanner backends
//!    exist at all.
//! 2. The **scanner capability map**
//!    ([`scan_backend_applies_to`], [`any_scan_backend_applies_to`]) —
//!    which of them can produce a verdict for which repository format.
//!    The backends own that truth (`ScannerPort::applies_to`); this is
//!    the mirror the apply path reads, and the `hort-worker` parity
//!    guard is what keeps the two from disagreeing.
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

/// The formats `trivy` can produce a verdict for.
///
/// Mirrors `TrivyAdapter::applies_to`, which derives it from the
/// adapter's own materialisation table. Trivy reads the payload, so its
/// coverage is the set of formats whose artifact kinds it can put on
/// disk in a shape its analyzers claim.
const TRIVY_FORMATS: &[&str] = &["oci", "maven", "pypi", "npm", "cargo"];

/// The formats `osv` can produce a verdict for.
///
/// Mirrors `OsvScannerAdapter::applies_to`. This backend reads only the
/// SBOM, so its coverage is exactly the set of formats whose compiled-in
/// handler exposes one — `oci` has no SBOM source and is therefore
/// absent.
const OSV_FORMATS: &[&str] = &["npm", "pypi", "cargo", "maven"];

/// Whether `backend` can produce a verdict for at least one artifact
/// kind of `format` — the **scanner capability map**.
///
/// Returns `false` for a backend name this build does not compile in,
/// and for any format no compiled-in handler serves: neither can yield a
/// verdict, and the map's job is to say so before a policy claims
/// otherwise.
///
/// ## The rule behind a cell
///
/// A cell is "yes" only where a test exists in which a known-vulnerable
/// fixture of that format, materialised by that backend, yields at least
/// one finding. No test means "no". Materialisation alone is not
/// evidence — bytes reaching a scanner that no analyzer claims produce
/// the *absence* of a verdict, which is precisely the inert pairing this
/// map exists to name. The evidence per cell lives with the adapter that
/// owns the truth (`hort-adapters-scanner-trivy`'s
/// `tests/materialisation_evidence.rs`, the OSV adapter's SBOM tests).
///
/// The map is binary. What a "yes" covers varies — Trivy on an npm
/// tarball sees the package's own identity but not its declared
/// dependency ranges, on a `.crate` only a shipped `Cargo.lock` — but a
/// third "partial" state would attach a warning to nearly every non-OCI
/// cell, which is noise rather than signal. The per-cell detail belongs
/// in the documentation, not in the type.
///
/// ## Why the record is static
///
/// The same reason [`KNOWN_SCAN_BACKENDS`] is: the apply path runs in
/// the **server**, which constructs no scanner adapters and so has
/// nobody to ask. Validating against the live `scanner_registry` instead
/// was the boot-ordering hazard H20 — on a fresh deployment the gitops
/// boot applies before any worker has registered, so the live answer is
/// transiently empty and a correct policy is rejected fail-closed with
/// no retry. Whether a backend *can* analyse a format is a permanent
/// property of the build, knowable offline; whether a worker advertising
/// it is running is a liveness concern, never an apply-time validity
/// error.
///
/// Keeping the record here rather than in the adapters means it can
/// drift from them, so it does not get to: the `hort-worker` parity
/// guard — the one crate that constructs the real adapters *and* the
/// handler registry — asserts this function agrees with every adapter's
/// own answer for every registered handler key.
#[must_use]
pub fn scan_backend_applies_to(backend: &str, format: &str) -> bool {
    match backend {
        "trivy" => TRIVY_FORMATS.contains(&format),
        "osv" => OSV_FORMATS.contains(&format),
        _ => false,
    }
}

/// Whether **any** compiled-in backend can produce a verdict for
/// `format`.
///
/// The distinction that matters to an operator: a format no backend
/// covers cannot be fixed by choosing a different backend, so it is a
/// different problem from a backend pointed at the wrong format.
#[must_use]
pub fn any_scan_backend_applies_to(format: &str) -> bool {
    !scan_backends_covering(format).is_empty()
}

/// The compiled-in backends that can produce a verdict for `format`, in
/// [`KNOWN_SCAN_BACKENDS`] order (deterministic, so a rendered message
/// is stable across runs).
///
/// The operator-facing half of the map. A rejection that only says
/// "this backend cannot analyse this format" leaves the operator to go
/// find the table; naming the backends that *do* cover the format turns
/// the rejection into the fix. Empty exactly when
/// [`any_scan_backend_applies_to`] is `false`.
#[must_use]
pub fn scan_backends_covering(format: &str) -> Vec<&'static str> {
    KNOWN_SCAN_BACKENDS
        .iter()
        .copied()
        .filter(|backend| scan_backend_applies_to(backend, format))
        .collect()
}

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

    /// The map's rows **are** [`KNOWN_SCAN_BACKENDS`]: a compiled-in
    /// backend that covers no format at all is either a wiring mistake
    /// or a backend that should not be offered to operators.
    #[test]
    fn every_known_backend_covers_at_least_one_format() {
        for backend in KNOWN_SCAN_BACKENDS {
            assert!(
                ["oci", "maven", "pypi", "npm", "cargo"]
                    .iter()
                    .any(|f| scan_backend_applies_to(backend, f)),
                "{backend} covers no format"
            );
        }
    }

    /// A backend this build does not compile in has no capability at
    /// all — not even for a format every real backend covers.
    #[test]
    fn an_unknown_backend_is_false_for_every_format() {
        for format in ["oci", "maven", "pypi", "npm", "cargo", "gradle"] {
            assert!(!scan_backend_applies_to("grype", format));
            assert!(!scan_backend_applies_to("", format));
            assert!(!scan_backend_applies_to("TRIVY", format));
        }
    }

    /// The cell the map exists for: `osv` on an OCI repository. OCI has
    /// no SBOM source, so the pairing produces no verdict — while
    /// reading, in a policy, as a second scan authority.
    #[test]
    fn osv_does_not_cover_oci_but_trivy_does() {
        assert!(!scan_backend_applies_to("osv", "oci"));
        assert!(scan_backend_applies_to("trivy", "oci"));
    }

    #[test]
    fn trivy_covers_every_compiled_in_handler_format() {
        for format in ["oci", "maven", "pypi", "npm", "cargo"] {
            assert!(scan_backend_applies_to("trivy", format), "{format}");
        }
    }

    #[test]
    fn osv_covers_the_sbom_capable_formats_only() {
        for format in ["maven", "pypi", "npm", "cargo"] {
            assert!(scan_backend_applies_to("osv", format), "{format}");
        }
        assert!(!scan_backend_applies_to("osv", "oci"));
    }

    /// A format no compiled-in handler serves is kind `Other` for every
    /// artifact under it, so no backend has anything to materialise or
    /// any SBOM to read.
    #[test]
    fn a_format_no_handler_serves_is_covered_by_nobody() {
        for format in ["gradle", "generic", "nuget", "", "OCI"] {
            assert!(!any_scan_backend_applies_to(format), "{format}");
            for backend in KNOWN_SCAN_BACKENDS {
                assert!(!scan_backend_applies_to(backend, format));
            }
        }
    }

    #[test]
    fn any_backend_covers_every_compiled_in_handler_format() {
        for format in ["oci", "maven", "pypi", "npm", "cargo"] {
            assert!(any_scan_backend_applies_to(format), "{format}");
        }
    }

    /// The alternatives an operator is offered are exactly the map's
    /// "yes" cells for that format, in the backend set's own order — so
    /// the rendered list is stable and never suggests a backend that
    /// would be rejected in turn.
    #[test]
    fn covering_backends_are_the_yes_cells_in_known_backend_order() {
        assert_eq!(scan_backends_covering("oci"), vec!["trivy"]);
        for format in ["maven", "pypi", "npm", "cargo"] {
            assert_eq!(
                scan_backends_covering(format),
                vec!["trivy", "osv"],
                "{format}"
            );
        }
    }

    /// The empty list and `any_ == false` are the same fact: a format
    /// nobody covers has no alternative to offer, which is why it is a
    /// different operator problem from a mis-paired backend.
    #[test]
    fn a_format_nobody_covers_offers_no_alternatives() {
        for format in ["gradle", "generic", "nuget", "", "OCI"] {
            assert!(scan_backends_covering(format).is_empty(), "{format}");
            assert!(!any_scan_backend_applies_to(format), "{format}");
        }
    }

    /// `any_` is the disjunction of the rows, including the row that
    /// carries a format alone: OCI is covered only because `trivy`
    /// covers it.
    #[test]
    fn any_backend_is_the_disjunction_of_the_rows() {
        for format in ["oci", "maven", "pypi", "npm", "cargo", "gradle"] {
            assert_eq!(
                any_scan_backend_applies_to(format),
                scan_backend_applies_to("trivy", format) || scan_backend_applies_to("osv", format),
                "{format}"
            );
        }
    }
}
