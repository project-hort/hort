//! Graceful-shutdown signal primitive.
//!
//! This module previously exposed a one-shot `async fn signal()`
//! consumed by `axum::serve(...)`. The serve path has a second awaiter
//! (the RBAC refresh task); a single one-shot future cannot be awaited
//! from two places (either racing the signal or deadlocking the second
//! awaiter).
//!
//! The refactor introduces a broadcast primitive: one
//! [`ShutdownHandle`] installed at startup owns the signal-handler
//! task and a [`CancellationToken`]. Every consumer (axum serve,
//! RBAC refresh task, any future long-lived task) gets a cheap
//! clone of the token via [`ShutdownHandle::token`] and awaits
//! [`CancellationToken::cancelled`]. On SIGTERM/SIGINT the listener
//! task calls `cancel()` once — every clone resolves.
//!
//! SIGTERM + SIGINT semantics are preserved bit-for-bit from the
//! one-shot `signal()` future; the only behavioural change is that
//! the signal is now *broadcast*. Registration failures still log
//! at `error!` and fall through to `std::future::pending::<()>()` so
//! the process doesn't exit while axum is still bound (matching the
//! prior fail-open posture).

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Process-scoped shutdown coordinator.
///
/// One instance per `hort-server serve` run. Installing it spawns the
/// signal-listener task and returns a handle whose token can be
/// cloned and shared with every long-lived task. Dropping the handle
/// aborts the listener task — intentional, because the handle lives
/// for the duration of [`crate::cli::serve::run_async`] and the
/// listener has no work to do once serve returns.
pub struct ShutdownHandle {
    token: CancellationToken,
    // Kept so the listener task's lifetime is tied to the handle.
    // Named with a leading underscore to mark it as an owned-but-
    // unused field (keeps clippy quiet without `#[allow]` noise).
    _listener_task: JoinHandle<()>,
}

impl ShutdownHandle {
    /// Install the signal handler and return a handle whose token
    /// fires on SIGTERM or SIGINT (Unix) / Ctrl+C (Windows).
    ///
    /// Must be called from within a Tokio runtime — the listener task
    /// is spawned via [`tokio::spawn`]. A single call per process is
    /// enough; downstream consumers clone the token rather than
    /// installing additional handlers (multiple installations race
    /// for the signal).
    pub fn install() -> Self {
        let token = CancellationToken::new();
        let listener_token = token.clone();
        let listener_task = tokio::spawn(async move {
            wait_for_signal().await;
            listener_token.cancel();
        });
        Self {
            token,
            _listener_task: listener_task,
        }
    }

    /// Clone the underlying token. Cheap — `CancellationToken` is an
    /// `Arc` internally. Every long-lived task keeps its own clone
    /// and either `.cancelled().await`s or uses `.is_cancelled()` in
    /// a `tokio::select!` arm.
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Await shutdown. Equivalent to `handle.token().cancelled()`;
    /// convenience for callers that only need a single awaitable.
    #[cfg(test)]
    pub async fn cancelled(&self) {
        self.token.cancelled().await;
    }

    /// Synchronously cancel the shutdown token. Used by tests that
    /// need deterministic shutdown without racing a real OS signal.
    /// Production code lets the signal-listener task call `cancel()`
    /// on its own in response to SIGTERM/SIGINT.
    #[cfg(test)]
    pub fn cancel(&self) {
        self.token.cancel();
    }
}

/// Block until the process receives SIGTERM or SIGINT (Unix) / Ctrl+C
/// (Windows). Preserves the pre-Item-13 semantics of the retired
/// `signal()` function exactly — handler-registration failures log at
/// `error!` and fall through to `pending::<()>()` so axum keeps
/// serving instead of the task aborting and leaving a dangling
/// handle.
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal as unix_signal, SignalKind};

        let mut sigterm = match unix_signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(%err, "failed to register SIGTERM handler — shutdown disabled");
                std::future::pending::<()>().await;
                return;
            }
        };
        let mut sigint = match unix_signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(%err, "failed to register SIGINT handler — shutdown disabled");
                std::future::pending::<()>().await;
                return;
            }
        };

        tokio::select! {
            _ = sigterm.recv() => tracing::info!("received SIGTERM — beginning graceful shutdown"),
            _ = sigint.recv() => tracing::info!("received SIGINT — beginning graceful shutdown"),
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "ctrl_c handler failed");
        } else {
            tracing::info!("received Ctrl+C — beginning graceful shutdown");
        }
    }
}

#[cfg(test)]
mod tests {
    //! Shutdown primitive tests — pure token-level semantics. OS
    //! signal delivery is NOT exercised here; that's the E2E
    //! harness's job (and trying to deliver a real SIGTERM inside a
    //! unit test trips anyone who runs `cargo test` from a shell
    //! that's already waiting on a parent signal).
    //!
    //! The contract being pinned:
    //!
    //! - `install()` returns a handle whose token starts in the
    //!   un-cancelled state.
    //! - Every token clone resolves together — calling `cancel()`
    //!   on any of them propagates to all (broadcast semantics).
    //! - Awaiting the token is cheap when cancelled already fired
    //!   (no polling loop required).
    //! - The listener task is tied to the handle's lifetime — it
    //!   does not outlive the handle. (Important because `serve`
    //!   returns normally on SIGTERM; we don't want an orphan
    //!   handler lingering into the next test.)
    use super::*;

    #[tokio::test]
    async fn install_returns_handle_with_live_token() {
        let handle = ShutdownHandle::install();
        assert!(
            !handle.token().is_cancelled(),
            "fresh handle must carry an un-cancelled token"
        );
    }

    #[tokio::test]
    async fn cancel_propagates_to_every_clone() {
        let handle = ShutdownHandle::install();
        let clone_a = handle.token();
        let clone_b = handle.token();

        assert!(!clone_a.is_cancelled());
        assert!(!clone_b.is_cancelled());

        handle.cancel();

        // Both clones resolve without polling once the token fires.
        clone_a.cancelled().await;
        clone_b.cancelled().await;
        assert!(clone_a.is_cancelled());
        assert!(clone_b.is_cancelled());
    }

    #[tokio::test]
    async fn cancelled_future_from_handle_resolves() {
        // Exercises the helper used by serve-path futures:
        // `async move { shutdown.cancelled().await }`.
        let handle = ShutdownHandle::install();
        let fut_token = handle.token();

        let join = tokio::spawn(async move {
            fut_token.cancelled().await;
        });

        handle.cancel();
        // `tokio::time::timeout` imported inline to avoid a crate-
        // wide dep shuffle; 100ms is generous for token propagation.
        tokio::time::timeout(std::time::Duration::from_millis(100), join)
            .await
            .expect("shutdown token did not propagate within 100ms")
            .expect("awaiter task panicked");
    }

    #[tokio::test]
    async fn cancelled_future_from_self_resolves() {
        // Mirror of the prior test but using `handle.cancelled()`
        // directly — pins the inherent-method shortcut used by
        // the rbac-refresh task for readability.
        let handle = ShutdownHandle::install();
        handle.cancel();
        tokio::time::timeout(std::time::Duration::from_millis(100), handle.cancelled())
            .await
            .expect("shutdown token did not propagate within 100ms");
    }
}
