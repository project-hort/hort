//! `NotificationDispatcher`.
//!
//! Top-level orchestrator that maintains one tokio task per active
//! subscription. The dispatcher itself subscribes once to the
//! [`EventStorePublisher`](crate::event_store_publisher::EventStorePublisher)
//! broadcast channel; each per-subscription task subscribes to its own
//! receiver (cloned from the same sender) so a slow task only impacts
//! its own delivery (best-effort, never block the use-case append
//! path).
//!
//! # Module layout
//!
//! - [`failure_budget`] — sliding-window failure tracker per subscription.
//! - [`subscription_task`] — per-subscription task body (catch-up + live
//!   loop + filter + dispatch + budget bookkeeping).
//! - [`dispatcher`] — the top-level reconcile loop spawning / cancelling
//!   per-subscription tasks.
//!
//! See `docs/architecture/explanation/event-notifications.md`.

// Per the project's convention, the top-level orchestrator lives in
// `dispatcher.rs` and the public name re-exports through this `mod.rs`.
// Clippy's `module_inception` lint flags the parent/child name match,
// but the alternative (renaming to `dispatcher_core.rs` /
// `top_level.rs`) trades clarity for lint silence — the file's
// purpose is "the dispatcher module's dispatcher". Allow locally.
#[allow(clippy::module_inception)]
pub mod dispatcher;
pub mod failure_budget;
pub mod subscription_task;

pub use dispatcher::NotificationDispatcher;
pub use failure_budget::FailureBudget;
pub use subscription_task::SubscriptionTaskDeps;
