//! Outbound port for the per-tick quarantine-release entry point used
//! by [`QuarantineReleaseSweepHandler`](crate) (ADR 0007).
//! The implementation lives in `hort-app`
//! (`QuarantineUseCase::release_expired`); this trait is the seam the
//! handler depends on so its tests do not have to wire a full
//! application-layer aggregate.
//!
//! Keeping the handler trait-only — rather than holding a concrete
//! `Arc<QuarantineUseCase>` — preserves the
//! `crates/hort-app/src/task_handlers/cron_rescan_tick.rs` shape, where
//! every task handler depends only on ports.
//!
//! **Authority discipline.** The implementer re-evaluates the fail-closed
//! release predicate (`ScanSucceeded` / `ScanWaived` only) per artifact,
//! so a window-expired candidate without a clean scan stays quarantined
//! and falls out of [`ReleaseExpiredSummary::released`]. The window
//! deadline is **never** evidence of release authority — the candidacy
//! filter is the *caller's* concern, the authority check is this port's.

use uuid::Uuid;

use crate::error::DomainResult;

use super::BoxFuture;

/// Per-tick outcome of [`QuarantineReleasePort::release_expired`]:
/// what was released, and *why* the rest was not.
///
/// The two skip counters exist because "candidates − released" is not a
/// diagnosis. A candidate can be held back by two independent gates —
/// the ADR 0007 scan-authority gate and the ADR 0027 provenance
/// clearance — and an operator staring at a non-draining backlog needs
/// to know which one is holding it: a scan-authority backlog drains
/// once scanners catch up, whereas a provenance-pending backlog of
/// parent-gated blobs never self-clears and is a different remediation
/// entirely. Collapsing both into one number hides that distinction.
///
/// The counters are **mutually exclusive and order-stable**: a candidate
/// whose provenance is `Pending` counts as `skipped_provenance_pending`
/// whatever the scan side says (provenance alone already denies the
/// timer arm), and only a provenance-cleared candidate that then fails
/// the authority check counts as `skipped_no_scan_authority`. Candidates
/// refused by the domain source-state guard (already released, not in a
/// releasable state) count towards neither — they are not held, they are
/// simply no longer releasable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReleaseExpiredSummary {
    /// Ids that were actually released — a subset of the input.
    pub released: Vec<Uuid>,
    /// Candidates whose provenance cleared but for which no release
    /// authority (`ScanSucceeded` / `ScanWaived`) was constructible.
    pub skipped_no_scan_authority: u32,
    /// Candidates whose provenance clearance is still `Pending` — the
    /// provenance gate denies the timer arm on its own.
    pub skipped_provenance_pending: u32,
}

/// Outbound port: release a batch of artifact ids whose quarantine
/// observation window has elapsed (candidacy-only — every release goes
/// through the fail-closed authority check inside the implementation).
///
/// Returns a [`ReleaseExpiredSummary`] whose `released` is a strict
/// subset of the input on the fail-closed path. A candidate with no
/// `ScanCompleted` on its stream AND no `scan_backends: []` waiver is
/// skipped (no authority is constructible); the sweep loop continues.
pub trait QuarantineReleasePort: Send + Sync {
    /// Drive the per-artifact release-authority check over `artifact_ids`
    /// and append `ArtifactReleased` for each candidate whose authority
    /// resolves. Returns the released ids plus the per-cause skip counts.
    ///
    /// `release_expired` itself is unchanged — the candidacy filter
    /// (`quarantine_window_start + effective_duration <= now()`) is the
    /// *caller's* concern; this port re-evaluates authority per artifact
    /// and is where a defective candidacy filter is caught (it falls
    /// through to "no authority ⇒ skip", never to "released without
    /// authority").
    fn release_expired<'a>(
        &'a self,
        artifact_ids: Vec<Uuid>,
    ) -> BoxFuture<'a, DomainResult<ReleaseExpiredSummary>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time dyn-compatibility assertion.
    fn _assert_dyn_compatible(_: Box<dyn QuarantineReleasePort>) {}

    #[test]
    fn quarantine_release_port_is_dyn_compatible() {
        let _ = size_of::<&dyn QuarantineReleasePort>();
    }

    /// Trait-object dispatch + `BoxFuture` shape smoke test.
    #[tokio::test]
    async fn release_expired_dispatches_through_trait_object() {
        struct Stub;
        impl QuarantineReleasePort for Stub {
            fn release_expired<'a>(
                &'a self,
                ids: Vec<Uuid>,
            ) -> BoxFuture<'a, DomainResult<ReleaseExpiredSummary>> {
                Box::pin(async move {
                    Ok(ReleaseExpiredSummary {
                        released: ids,
                        skipped_no_scan_authority: 0,
                        skipped_provenance_pending: 0,
                    })
                })
            }
        }
        let port: Box<dyn QuarantineReleasePort> = Box::new(Stub);
        let out = port.release_expired(vec![Uuid::nil()]).await.expect("Ok");
        assert_eq!(out.released, vec![Uuid::nil()]);
    }

    /// The summary's `Default` is the empty tick — no releases, no skips.
    /// Handlers rely on this to build a zero outcome without naming every
    /// field.
    #[test]
    fn release_expired_summary_default_is_all_zero() {
        let s = ReleaseExpiredSummary::default();
        assert!(s.released.is_empty());
        assert_eq!(s.skipped_no_scan_authority, 0);
        assert_eq!(s.skipped_provenance_pending, 0);
    }

    /// The two skip counters are distinct fields, not aliases: a summary
    /// carrying only a provenance hold must not read as a scan-authority
    /// skip (that conflation is exactly what the per-cause split fixes).
    #[test]
    fn release_expired_summary_counters_are_independent() {
        let provenance_only = ReleaseExpiredSummary {
            released: Vec::new(),
            skipped_no_scan_authority: 0,
            skipped_provenance_pending: 7,
        };
        let authority_only = ReleaseExpiredSummary {
            released: Vec::new(),
            skipped_no_scan_authority: 7,
            skipped_provenance_pending: 0,
        };
        assert_ne!(provenance_only, authority_only);
        assert_eq!(provenance_only.clone(), provenance_only);
    }
}
