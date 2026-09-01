//! Bounded read-decide-append combinator for the append-conflict reaction
//! contract (ADR 0060).
//!
//! On `DomainError::Conflict` from an expected-version event-store append,
//! a writer must re-read the stream, re-check its intent against the
//! refreshed state, and either accept an already-satisfied intent as
//! idempotent success or rebuild the event batch against the refreshed
//! version and re-append — bounded, never unbounded. This module gives
//! that shape one reusable combinator so a call site cannot answer the
//! reaction ad hoc.
//!
//! The combinator does **no I/O of its own**. It is driven by a closure
//! that owns the full read + intent-recheck + rebuild + append cycle for
//! one attempt; the combinator's only job is to invoke that closure up to
//! a bound and interpret its outcome. This keeps the primitive
//! backend-agnostic — it has no `EventStore` dependency, only the shape of
//! one attempt.

use std::future::Future;

use hort_domain::error::DomainError;

use crate::error::{AppError, AppResult};

/// Outcome of one read-decide-append attempt, as returned by the closure
/// passed to [`append_with_conflict_retry`].
pub enum ConflictCycleOutcome<T> {
    /// The caller's intent is achieved — either this attempt's append
    /// committed, or a re-read found the target state already reflects it
    /// (idempotent success, ADR 0060 step (b)). Terminal: the combinator
    /// returns `T` to its caller.
    Satisfied(T),
    /// This attempt's append lost to `DomainError::Conflict`; the closure
    /// re-reads and rebuilds against the refreshed version on its next
    /// invocation (ADR 0060 step (c)).
    Retry,
}

/// Bounded read-decide-append combinator (ADR 0060).
///
/// Invokes `cycle` up to `attempts` times, passing the 1-based attempt
/// number. Each invocation owns one full cycle: it must re-read the
/// current state, re-check the caller's intent against it (returning
/// `Ok(ConflictCycleOutcome::Satisfied(_))` when already true), and
/// otherwise rebuild the event batch against the refreshed version and
/// attempt the append. A losing `DomainError::Conflict` on that append
/// maps to `Ok(ConflictCycleOutcome::Retry)`.
///
/// The combinator never inspects or classifies errors itself: any `Err`
/// the closure returns propagates immediately, unretried. This is what
/// makes the non-Conflict-passthrough half of the contract structural
/// rather than a match arm here — the closure is the only place that
/// knows a `DomainError::Conflict` from anything else, because it is the
/// only place that calls `append`.
///
/// On exhaustion (every attempt reported `Retry`), returns
/// `DomainError::Contended` — the retryable-busy outcome ADR 0060
/// mandates, already mappable to the existing 503 + `Retry-After`
/// contention vocabulary at HTTP edges without new HTTP surface.
pub async fn append_with_conflict_retry<T, Fut>(
    attempts: u8,
    mut cycle: impl FnMut(u8) -> Fut,
) -> AppResult<T>
where
    Fut: Future<Output = AppResult<ConflictCycleOutcome<T>>>,
{
    for attempt in 1..=attempts {
        match cycle(attempt).await? {
            ConflictCycleOutcome::Satisfied(value) => return Ok(value),
            ConflictCycleOutcome::Retry => continue,
        }
    }
    Err(AppError::Domain(DomainError::Contended(format!(
        "append-conflict retry budget exhausted after {attempts} attempt(s)"
    ))))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[tokio::test]
    async fn immediate_success() {
        let calls = Cell::new(0u8);
        let result = append_with_conflict_retry(3, |attempt| {
            calls.set(calls.get() + 1);
            assert_eq!(attempt, 1);
            async { Ok(ConflictCycleOutcome::Satisfied(42)) }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test]
    async fn satisfied_on_recheck_after_one_conflict() {
        let calls = Cell::new(0u8);
        let result = append_with_conflict_retry(3, |attempt| {
            calls.set(calls.get() + 1);
            async move {
                if attempt == 1 {
                    Ok(ConflictCycleOutcome::Retry)
                } else {
                    Ok(ConflictCycleOutcome::Satisfied("already-there"))
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), "already-there");
        assert_eq!(calls.get(), 2);
    }

    #[tokio::test]
    async fn retry_then_success() {
        let calls = Cell::new(0u8);
        let result = append_with_conflict_retry(3, |attempt| {
            calls.set(calls.get() + 1);
            async move {
                if attempt < 3 {
                    Ok(ConflictCycleOutcome::Retry)
                } else {
                    Ok(ConflictCycleOutcome::Satisfied(attempt))
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 3);
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test]
    async fn exhaustion_at_the_bound() {
        let calls = Cell::new(0u8);
        let result: AppResult<()> = append_with_conflict_retry(4, |_attempt| {
            calls.set(calls.get() + 1);
            async { Ok(ConflictCycleOutcome::Retry) }
        })
        .await;

        assert_eq!(
            calls.get(),
            4,
            "must call the closure exactly `attempts` times"
        );
        match result {
            Err(AppError::Domain(DomainError::Contended(msg))) => {
                assert!(
                    msg.contains('4'),
                    "exhaustion message should name the bound: {msg}"
                );
            }
            other => panic!("expected exhaustion as DomainError::Contended, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_conflict_error_passthrough() {
        let calls = Cell::new(0u8);
        let result: AppResult<()> = append_with_conflict_retry(5, |_attempt| {
            calls.set(calls.get() + 1);
            async {
                Err(AppError::Domain(DomainError::Validation(
                    "bad input".into(),
                )))
            }
        })
        .await;

        assert_eq!(calls.get(), 1, "a non-Conflict error must not be retried");
        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }

    #[tokio::test]
    async fn bound_of_one() {
        let calls = Cell::new(0u8);
        let result: AppResult<()> = append_with_conflict_retry(1, |attempt| {
            calls.set(calls.get() + 1);
            assert_eq!(attempt, 1);
            async { Ok(ConflictCycleOutcome::Retry) }
        })
        .await;

        assert_eq!(calls.get(), 1);
        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Contended(_)))
        ));
    }
}
