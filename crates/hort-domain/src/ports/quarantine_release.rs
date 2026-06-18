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
//! and falls out of the returned `Vec`. The window deadline is **never**
//! evidence of release authority — the candidacy filter is the *caller's*
//! concern, the authority check is this port's.

use uuid::Uuid;

use crate::error::DomainResult;

use super::BoxFuture;

/// Outbound port: release a batch of artifact ids whose quarantine
/// observation window has elapsed (candidacy-only — every release goes
/// through the fail-closed authority check inside the implementation).
///
/// Returns the ids that were *actually* released — a strict subset of the
/// input on the fail-closed path. A candidate with no `ScanCompleted` on
/// its stream AND no `scan_backends: []` waiver is skipped (no authority
/// is constructible); the sweep loop continues.
pub trait QuarantineReleasePort: Send + Sync {
    /// Drive the per-artifact release-authority check over `artifact_ids`
    /// and append `ArtifactReleased` for each candidate whose authority
    /// resolves. Returns the ids that were released.
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
    ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>>;
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
            ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>> {
                Box::pin(async move { Ok(ids) })
            }
        }
        let port: Box<dyn QuarantineReleasePort> = Box::new(Stub);
        let out = port.release_expired(vec![Uuid::nil()]).await.expect("Ok");
        assert_eq!(out, vec![Uuid::nil()]);
    }
}
