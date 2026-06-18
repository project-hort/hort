//! Outbound port the **audit-retention stream sweep**
//! (`EventStoreRetentionUseCase::archive_terminal_streams`)
//! uses to enumerate the candidate streams the retention model may
//! seal. The per-category seal rule (terminal-gated vs age-gated) and
//! the audit-retention floor live in the `hort-app` use case;
//! this port performs **enumeration only**.
//!
//! # Why this exists
//!
//! `EventStoreRetentionUseCase::archive_terminal_streams` seals whole
//! **terminal** streams once their audit-retention floor has elapsed —
//! `delete_stream` for the global `StreamRetentionMode::Delete`,
//! `archive_stream` for `StreamRetentionMode::Archive`. Both route
//! through the `seal_and_remove` chokepoint, which auto-emits the
//! `StreamSealed` tombstone.
//!
//! The use case needs, per candidate stream: the rendered stream id,
//! its [`StreamCategory`], the oldest event's `stored_at` (the floor
//! anchor — every later event is at-or-after it), the newest
//! event's `stored_at`, and the tail event's
//! [`DomainEvent::event_type`](crate::events::DomainEvent::event_type)
//! (the terminal-gate input). That is exactly
//! [`TerminalStreamCandidate`].
//!
//! # Why a *new, separate* additive port (not extra methods on
//! [`EventStore`](super::event_store::EventStore))
//!
//! `EventStore` is frozen (an EventStoreDB adapter must remain
//! implementable against it unchanged). Adding a stream-enumeration
//! surface to `EventStore` would mutate that signature. So the
//! enumeration surface is a **distinct, purely-additive** trait — zero
//! existing impls touched. It reuses the shipped
//! [`StreamCategory`](crate::events::StreamCategory) type so nothing is
//! redefined.
//!
//! # Why the port returns *candidates* (data), not a "seal" verb
//!
//! Keeping enumeration and the per-category seal decision as separate
//! concerns that exchange typed candidate data lets the `hort-app`
//! `EventStoreRetentionUseCase` stay pure orchestration (100%
//! mock-testable — the two seal modes, the meta-stream guard, the
//! floor proof, the `info!`/`warn!`/`debug!`/`error!` policy, the
//! summary) while the SQL (the set-based per-stream aggregate over
//! `events`) stays in the Postgres adapter (≥85% integration-tested).
//! The use case never embeds SQL; the adapter never embeds the
//! seal-policy / floor / tracing / summary orchestration.

use crate::error::DomainResult;
use crate::events::StreamCategory;

use super::BoxFuture;

/// One enumerated candidate stream the audit-retention sweep may
/// seal. The port performs **enumeration only** — the per-category
/// seal rule (terminal-gated vs age-gated) and the retention floor
/// live in the `hort-app` use case, never here (policy in the use case,
/// enumeration in the adapter — the established retention-port split).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalStreamCandidate {
    /// Wire form `"{category}-{uuid}"` (`StreamId::Display`). The use
    /// case parses it back via `StreamId::from_str` to call the seal
    /// chokepoint; carried as the already-rendered string so the
    /// the adapter's set-based enumeration query does not re-stringify and
    /// the use case's meta-stream guard is a cheap string compare
    /// against `StreamId::eventstore_retention().to_string()`.
    pub stream_id: String,
    /// The aggregate category of the stream — selects the per-category
    /// retention rule (floor + seal mode) in the use case.
    pub category: StreamCategory,
    /// Min `events.stored_at` over the stream — the retention-floor anchor.
    /// Every later event is at-or-after this, so proving
    /// `now - first_event_at >= floor` proves the floor for the whole
    /// stream. Never a payload timestamp, never the chain head.
    pub first_event_at: chrono::DateTime<chrono::Utc>,
    /// Max `events.stored_at` over the stream. Carried for the trace
    /// and future age-window diagnostics; NOT the floor anchor.
    pub last_event_at: chrono::DateTime<chrono::Utc>,
    /// [`DomainEvent::event_type`](crate::events::DomainEvent::event_type)
    /// of the tail (max `stream_position`) event — the terminal-gate
    /// input for `TerminalGated` categories. Ignored for `AgeGated`
    /// categories (rotated audit streams have no terminal).
    pub last_event_type: String,
}

/// Read-only stream-enumeration outbound port for the
/// audit-retention sweep. Purely additive — introduces no change to
/// any existing port. The Postgres adapter implements the enumeration
/// as one set-based aggregate query over `events`; unit tests use an
/// in-memory mock.
pub trait TerminalStreamReader: Send + Sync {
    /// Every stream the retention model may consider, with the
    /// per-candidate facts the use case needs to apply the
    /// per-category seal rule + the retention floor.
    ///
    /// The adapter MUST exclude the meta-stream
    /// `StreamId::eventstore_retention()` (double defence-in-depth —
    /// the use case re-asserts the guard regardless: sealing the
    /// never-deleted audit-meta stream would truncate the very audit
    /// trail of every seal). The adapter MAY pre-filter to the
    /// categories B5 registers a rule for; the use case skips any
    /// unregistered category it is handed anyway. A converged / empty
    /// store returns an empty vec (the sweep is then a no-op).
    fn list_terminal_candidates(&self)
        -> BoxFuture<'_, DomainResult<Vec<TerminalStreamCandidate>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(secs, 0).unwrap()
    }

    /// Compile-time dyn-compatibility assertion (mirrors the pattern in
    /// [`crate::ports::purge_gc`] / [`crate::ports::refcount_reconcile`]).
    #[test]
    fn terminal_stream_reader_port_is_dyn_compatible() {
        let _ = size_of::<&dyn TerminalStreamReader>();
    }

    /// A no-op impl proves the trait can be `dyn`-cast and stands in
    /// for adapter impls in cross-crate tests.
    struct EmptyPort;
    impl TerminalStreamReader for EmptyPort {
        fn list_terminal_candidates(
            &self,
        ) -> BoxFuture<'_, DomainResult<Vec<TerminalStreamCandidate>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn empty_port_returns_no_candidates() {
        let p = EmptyPort;
        assert!(p.list_terminal_candidates().await.unwrap().is_empty());
    }

    /// `DomainError` round-trips through the return signature — the
    /// adapter surfaces SQL failures this way and the use case maps
    /// them to `AppError::Domain` (a `list_*` failure aborts the whole
    /// sweep, vs per-stream chokepoint failures which continue).
    #[tokio::test]
    async fn errors_round_trip_through_port_signature() {
        use crate::error::DomainError;
        struct ErrPort;
        impl TerminalStreamReader for ErrPort {
            fn list_terminal_candidates(
                &self,
            ) -> BoxFuture<'_, DomainResult<Vec<TerminalStreamCandidate>>> {
                Box::pin(async { Err(DomainError::Invariant("candidate list failed".into())) })
            }
        }
        let p = ErrPort;
        assert!(matches!(
            p.list_terminal_candidates().await.unwrap_err(),
            DomainError::Invariant(_)
        ));
    }

    /// The candidate is a plain value struct — round-trip equality +
    /// every field carries through (the use case reads all five).
    #[test]
    fn candidate_round_trips() {
        let c = TerminalStreamCandidate {
            stream_id: "artifact-00000000-0000-0000-0000-000000000001".to_owned(),
            category: StreamCategory::Artifact,
            first_event_at: ts(1000),
            last_event_at: ts(2000),
            last_event_type: "ArtifactPurged".to_owned(),
        };
        assert_eq!(c.clone(), c);
        assert_eq!(c.category, StreamCategory::Artifact);
        assert_eq!(c.first_event_at, ts(1000));
        assert_eq!(c.last_event_at, ts(2000));
        assert_eq!(c.last_event_type, "ArtifactPurged");
        assert!(c.stream_id.starts_with("artifact-"));

        let other = TerminalStreamCandidate {
            last_event_type: "ArtifactIngested".to_owned(),
            ..c.clone()
        };
        assert_ne!(other, c);
    }
}
