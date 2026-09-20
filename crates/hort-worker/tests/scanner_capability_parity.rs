//! Scanner capability map parity guard.
//!
//! The capability map has two readers that must never disagree:
//!
//! - The **apply-time linter** runs in `hort-server`, which constructs
//!   no scanner adapters, so it reads the static record in
//!   `hort_app::scanning`.
//! - The **worker** dispatches on the adapter's own
//!   `ScannerPort::applies_to`.
//!
//! A policy accepted because the static record said "yes" while the
//! adapter answers "no" is an inert pairing that passed the very gate
//! built to reject it — and the reverse rejects a pairing that would
//! have worked. Neither is visible from either side alone.
//!
//! This crate is the one place that constructs the real adapters **and**
//! the real format-handler registry, so it is the one place the two
//! halves can be compared. The comparison is exhaustive: every
//! registered handler key × every name in `KNOWN_SCAN_BACKENDS`.
//!
//! No database, no binary, no network: `applies_to` is a pure function
//! of the format string, and both adapters are constructible without
//! touching storage or probing for their CLI. That keeps this guard in
//! the plain `cargo test --workspace` gate.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use hort_adapters_scanner_osv::{OsvScannerAdapter, OsvScannerConfig};
use hort_adapters_scanner_trivy::{TrivyAdapter, TrivyConfig};
use hort_app::scanning::{
    any_scan_backend_applies_to, scan_backend_applies_to, KNOWN_SCAN_BACKENDS,
};
use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::DomainResult;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::scanner::ScannerPort;
use hort_domain::ports::storage::{PutResult, StoragePort};
use hort_domain::ports::BoxFuture;
use hort_domain::types::{ArtifactCoords, ByteRange, ContentHash, PayloadAccess};
use hort_worker::composition::compiled_in_format_handlers;
use tokio::io::AsyncRead;

/// A `StoragePort` that refuses every call.
///
/// The Trivy adapter needs one to be constructed, and `applies_to`
/// must not reach it — a capability answer that depended on a CAS read
/// could not be given by the apply path at all. Panicking rather than
/// stubbing makes that a test failure instead of a silent dependency.
struct NoStorage;

impl StoragePort for NoStorage {
    fn put(&self, _s: Box<dyn AsyncRead + Send + Unpin>) -> BoxFuture<'_, DomainResult<PutResult>> {
        Box::pin(async { unreachable!("the capability map reads no bytes") })
    }
    fn get(
        &self,
        _h: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        Box::pin(async { unreachable!("the capability map reads no bytes") })
    }
    fn get_range(
        &self,
        _h: &ContentHash,
        _r: ByteRange,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        Box::pin(async { unreachable!("the capability map reads no bytes") })
    }
    fn exists(&self, _h: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
        Box::pin(async { unreachable!("the capability map reads no bytes") })
    }
    fn size_of(&self, _h: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
        Box::pin(async { unreachable!("the capability map reads no bytes") })
    }
}

/// The real adapters, constructed the way the worker constructs them
/// minus the operator-tunable knobs — no health check, no binary, no
/// storage round-trip.
fn adapters() -> Vec<Arc<dyn ScannerPort>> {
    vec![
        Arc::new(TrivyAdapter::new(
            TrivyConfig::default(),
            Arc::new(NoStorage),
        )),
        Arc::new(OsvScannerAdapter::new(OsvScannerConfig::default())),
    ]
}

/// Whether `handler` exposes an SBOM the scan orchestrator can hand to a
/// backend, asked exactly the way
/// `ScanOrchestrationUseCase::try_extract_sbom` asks it: the payload
/// capability first, then the metadata path.
///
/// The metadata call is made with a representative coordinate set and a
/// null metadata document — the shape a proxied pull that never landed
/// a parsed manifest produces. A handler that yields an SBOM even there
/// is SBOM-capable; one that yields `None` has no SBOM source at all,
/// which is the fact the `osv` row of the map is made of.
fn handler_is_sbom_capable(handler: &dyn FormatHandler, coords: &ArtifactCoords) -> bool {
    if handler.payload_sbom().is_some() {
        return true;
    }
    matches!(
        handler.extract_sbom(coords, &serde_json::Value::Null, PayloadAccess::Bytes(&[])),
        Ok(Some(_))
    )
}

fn sample_coords() -> ArtifactCoords {
    ArtifactCoords {
        name: "evidence".to_string(),
        name_as_published: "evidence".to_string(),
        version: Some("1.0.0".to_string()),
        path: "evidence/1.0.0/evidence-1.0.0".to_string(),
        format: RepositoryFormat::Npm,
        metadata: serde_json::Value::Null,
    }
}

/// The guard itself: for every registered handler key × every known
/// backend, the adapter's answer and the static record must agree.
#[test]
fn the_static_record_matches_every_adapters_own_answer() {
    let handlers = compiled_in_format_handlers();
    let adapters = adapters();
    assert_eq!(
        adapters.len(),
        KNOWN_SCAN_BACKENDS.len(),
        "every compiled-in backend must be represented in this guard"
    );

    let mut checked = 0usize;
    for adapter in &adapters {
        let backend = adapter.name();
        assert!(
            KNOWN_SCAN_BACKENDS.contains(&backend),
            "adapter `{backend}` is not in the static backend set"
        );
        for key in handlers.keys() {
            assert_eq!(
                adapter.applies_to(key),
                scan_backend_applies_to(backend, key),
                "capability map disagreement on {backend} × {key}: the apply-time linter \
                 reads the static record, the worker dispatches on the adapter's answer, \
                 and they must never disagree"
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked,
        handlers.len() * KNOWN_SCAN_BACKENDS.len(),
        "every cell must be compared"
    );
}

/// The `osv` row is not a list someone maintains — it *is* the set of
/// formats whose handler exposes an SBOM, because that is the only
/// input this backend has. A handler gaining or losing an SBOM source
/// must move the row with it.
#[test]
fn the_osv_row_is_exactly_the_sbom_capable_handlers() {
    let handlers = compiled_in_format_handlers();
    let osv = OsvScannerAdapter::new(OsvScannerConfig::default());
    let coords = sample_coords();

    let mut sbom_capable: Vec<&str> = Vec::new();
    for (key, handler) in &handlers {
        let capable = handler_is_sbom_capable(handler.as_ref(), &coords);
        assert_eq!(
            osv.applies_to(key),
            capable,
            "osv × {key}: this backend reads only the SBOM, so its coverage is exactly \
             the formats whose handler exposes one"
        );
        assert_eq!(scan_backend_applies_to("osv", key), capable);
        if capable {
            sbom_capable.push(key);
        }
    }
    sbom_capable.sort_unstable();
    assert_eq!(
        sbom_capable,
        ["cargo", "maven", "npm", "pypi"],
        "the SBOM-capable set moved; the osv row and the static record must move with it"
    );
}

/// OCI is the cell the map exists to close: it has no SBOM source, so
/// `osv` on an OCI repository analyses nothing while reading, in a
/// policy, as a second scan authority. Trivy does cover it, so the
/// format is not uncovered — it is the *pairing* that is inert.
#[test]
fn oci_is_covered_by_trivy_alone_and_the_handler_confirms_it_has_no_sbom() {
    let handlers = compiled_in_format_handlers();
    let oci = handlers.get("oci").expect("oci handler is registered");
    let coords = sample_coords();

    assert!(
        !handler_is_sbom_capable(oci.as_ref(), &coords),
        "the OCI handler must expose no SBOM — the osv × oci cell rests on it"
    );
    assert!(!scan_backend_applies_to("osv", "oci"));
    assert!(scan_backend_applies_to("trivy", "oci"));
    assert!(any_scan_backend_applies_to("oci"));
}

/// The static record must not claim coverage for a format no handler
/// serves: such an artifact is kind `Other`, which no backend
/// materialises and no handler gives an SBOM for.
#[test]
fn no_backend_claims_a_format_outside_the_handler_registry() {
    let handlers = compiled_in_format_handlers();
    for format in ["gradle", "generic", "nuget", "debian", ""] {
        assert!(
            !handlers.contains_key(format),
            "{format} unexpectedly has a handler; this guard's premise is stale"
        );
        assert!(!any_scan_backend_applies_to(format), "{format}");
        for adapter in &adapters() {
            assert!(
                !adapter.applies_to(format),
                "{} must not claim {format}",
                adapter.name()
            );
        }
    }
}

/// Every registered handler key is covered by at least one backend.
///
/// Not a tautology: a format whose handler ships without an SBOM source
/// and whose kinds Trivy cannot materialise would be a format Hort
/// ingests and can never scan — worth failing the build over, because
/// the honest fix is either a scanner that covers it or an explicit
/// scanning waiver, not silence.
#[test]
fn every_registered_handler_format_has_at_least_one_backend() {
    for key in compiled_in_format_handlers().keys() {
        assert!(
            any_scan_backend_applies_to(key),
            "{key} is served by a handler but by no scanner backend"
        );
    }
}
