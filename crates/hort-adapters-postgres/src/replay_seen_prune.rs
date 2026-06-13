//! [`ReplaySeenPrunePort`] implementation for [`PgReplayGuardRepository`].
//!
//! This module adds **only** the `ReplaySeenPrunePort` impl block — it
//! does not touch `replay_guard_repo.rs`. The actual
//! `DELETE FROM jwt_replay_seen WHERE expires_at < now()` lives in the
//! shipped, byte-unchanged public
//! [`PgReplayGuardRepository::prune_expired`] (the claim adapter owns
//! the only two statements that touch the table — the hot-path
//! `INSERT … ON CONFLICT` and this cold-path `DELETE` — so the table's
//! DML stays in one place). This impl is the thin port-boundary
//! wrapper the `hort-app` `replay-seen-prune` `TaskHandler` calls.
//!
//! DDL (the table, index, CHECK) is owned by the `migrate` role only —
//! this path issues DML exclusively (`DELETE`). Migration 011 pins the
//! runtime DSN's grants on `jwt_replay_seen` to `INSERT, SELECT,
//! DELETE` (ADR 0009 — least-privilege runtime role).

use hort_domain::ports::replay_guard::ReplayGuardError;
use hort_domain::ports::replay_seen_prune::ReplaySeenPrunePort;

use crate::replay_guard_repo::PgReplayGuardRepository;
use crate::BoxFuture;

impl ReplaySeenPrunePort for PgReplayGuardRepository {
    fn prune_expired(&self) -> BoxFuture<'_, Result<u64, ReplayGuardError>> {
        // Delegate to the shipped inherent method (unchanged). Keeping
        // the SQL in `replay_guard_repo.rs` means the claim `INSERT`
        // and the prune `DELETE` — the only two statements that touch
        // `jwt_replay_seen` — stay co-located.
        Box::pin(async move { PgReplayGuardRepository::prune_expired(self).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The adapter must be usable as the `Arc<dyn ReplaySeenPrunePort>`
    /// the worker injects into the `replay-seen-prune` `TaskHandler`.
    /// Pure compile-time wiring check (no DB).
    #[test]
    fn pg_repo_is_a_replay_seen_prune_port() {
        fn assert_impl<T: ReplaySeenPrunePort + 'static>() {}
        assert_impl::<PgReplayGuardRepository>();
        // The `dyn` coercion the composition root performs.
        fn _coerce(r: Arc<PgReplayGuardRepository>) -> Arc<dyn ReplaySeenPrunePort> {
            r
        }
    }
}
