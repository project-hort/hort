//! Outbound port: periodic cleanup of expired rows from the durable
//! anti-replay seen-set.
//!
//! # Why this is a separate port from [`ReplayGuardPort`]
//!
//! [`ReplayGuardPort`](super::replay_guard::ReplayGuardPort) is the
//! **hot-path** atomic claim used inside the federation token-exchange
//! mint use case. The seen-set's TTL cleanup is an entirely separate,
//! **cold-path** concern: a periodic
//! `DELETE FROM jwt_replay_seen WHERE expires_at < now()` driven by the
//! worker `TaskHandler` + external-CronJob model — exactly the
//! pattern the sibling cleanup/maintenance tasks
//! (`staging-sweep`, `cron-rescan-tick`, `eventstore-checkpoint`) use.
//!
//! Splitting it into its own narrow port keeps the claim trait's
//! contract (one atomic method) intact — adding a `prune` method to
//! `ReplayGuardPort` would be an unrequested signature change to a
//! shipped trait. The Postgres adapter implements **both** ports on the
//! same `PgReplayGuardRepository` (the prune `DELETE` and the claim
//! `INSERT … ON CONFLICT` are the only two statements that touch
//! `jwt_replay_seen`), so there is exactly one place the table's DML
//! lives.
//!
//! # Cleanup degrades safe
//!
//! If the prune never runs the table only grows; the seen-set never
//! *forgets* a `jti` within its TTL window, so a stale-but-present row
//! still correctly reports `Replayed`. A cleanup outage costs storage,
//! **not** security — it degrades toward conservatism, never open. The
//! `TaskHandler` therefore treats a prune failure as a retry-on-next-
//! tick condition (`warn!`), never a hard worker failure.
//!
//! # Layering
//!
//! - Port trait lives in `hort-domain` (zero I/O, zero `tracing`).
//! - Adapter implementation lives in `hort-adapters-postgres`
//!   (`replay_seen_prune.rs`) and delegates to the existing public
//!   `PgReplayGuardRepository::prune_expired()` — the claim adapter's
//!   prune statement is reused byte-unchanged.
//! - The error type is the **shared** [`ReplayGuardError`] from
//!   [`super::replay_guard`] — a prune-store outage is the same
//!   infrastructure-failure class as a claim-store outage; introducing
//!   a second error enum would split one concept for no benefit and is
//!   an unrequested new error type.

use super::replay_guard::ReplayGuardError;
use super::BoxFuture;

/// Outbound port for the periodic seen-set TTL cleanup.
///
/// The single operation deletes every `jwt_replay_seen` row whose
/// `expires_at` is in the past and returns the number of rows removed
/// so the `TaskHandler` can report it in the job's `result_summary`.
///
/// Dyn-compatible: registered as `Arc<dyn ReplaySeenPrunePort>` and
/// injected into the `replay-seen-prune` `TaskHandler` at composition
/// time.
pub trait ReplaySeenPrunePort: Send + Sync {
    /// Delete all rows whose TTL horizon (`expires_at`) has passed.
    ///
    /// Returns the number of rows deleted on success, or
    /// [`ReplayGuardError::Unavailable`] if the backing store could not
    /// be reached. The caller (the `replay-seen-prune` `TaskHandler`)
    /// maps `Unavailable` to a retry-on-next-tick outcome — cleanup
    /// degrades **safe**: a missed prune only grows the table, it never
    /// forgets a recorded replay.
    fn prune_expired(&self) -> BoxFuture<'_, Result<u64, ReplayGuardError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time invariant: the port must remain dyn-compatible
    /// (registered as `Arc<dyn ReplaySeenPrunePort>` in the worker
    /// dispatch wiring, mirroring every other `TaskHandler` port dep).
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn ReplaySeenPrunePort>();
    }

    /// A hand-rolled in-memory fake proves the trait is implementable
    /// and the `BoxFuture` return shape resolves both arms (the
    /// `hort-app` handler tests reuse this exact shape via their own
    /// mock).
    struct FakePrune {
        result: Result<u64, ReplayGuardError>,
    }

    impl ReplaySeenPrunePort for FakePrune {
        fn prune_expired(&self) -> BoxFuture<'_, Result<u64, ReplayGuardError>> {
            let r = self.result.clone();
            Box::pin(async move { r })
        }
    }

    #[tokio::test]
    async fn fake_prune_ok_yields_row_count() {
        let f = FakePrune { result: Ok(42) };
        let got = f.prune_expired().await;
        assert_eq!(got, Ok(42));
    }

    #[tokio::test]
    async fn fake_prune_unavailable_propagates() {
        let f = FakePrune {
            result: Err(ReplayGuardError::Unavailable("db down".into())),
        };
        let got = f.prune_expired().await;
        assert_eq!(got, Err(ReplayGuardError::Unavailable("db down".into())));
    }
}
