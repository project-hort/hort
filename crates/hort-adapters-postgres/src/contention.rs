//! Transient write-contention: detecting it, and the bounded retry over it.
//!
//! Postgres aborts a transaction outright when letting it continue would
//! break isolation — a serialization failure, or a deadlock it had to break
//! by choosing a victim. Both are reported as an ordinary statement error,
//! and both mean something quite specific: **the transaction was rolled back
//! whole, nothing was applied, and running it again is expected to work.**
//!
//! Without a classifier that distinction is invisible. Every such abort lands
//! in [`map_sqlx_error`](crate::map_sqlx_error)'s catch-all as
//! [`DomainError::Invariant`], which the HTTP layers read as "the server is
//! broken" and render as a 500 — so two clients writing the same row at the
//! same time produce an intermittent, unreproducible internal error on a
//! request that was entirely valid and would have succeeded a millisecond
//! later. The OCI manifest-PUT path is where this bites hardest: a
//! multi-architecture push issues several manifest writes concurrently, and
//! sibling manifests routinely share a `content_references` target (the
//! empty-config blob is shared by every attestation manifest in a buildkit
//! index), so their upserts contend on one row by construction.
//!
//! ## Why the sqlstate stays here
//!
//! `40001` / `40P01` are Postgres vocabulary. Nothing above the adapter may
//! learn them (ADR 0008): the classification happens at the seam where the
//! `sqlx::Error` is still in hand, and what crosses the port boundary is
//! [`DomainError::Contended`] — a statement about the write, not about the
//! engine that refused it. A future non-Postgres adapter classifies its own
//! equivalent and callers are unaffected.
//!
//! ## Why the retry cannot widen
//!
//! [`with_contention_retry`] retries **only** `Contended`. A
//! [`DomainError::Conflict`] — a genuine duplicate, or an event-store
//! position clash — is a decided answer that re-running reproduces exactly,
//! and retrying it would burn the budget to arrive at the same place while
//! turning a crisp 409/400 into a slow one. Everything else returns on the
//! first attempt, spending none of the budget.
//!
//! On exhaustion the final attempt's error is returned verbatim, so a caller
//! can distinguish "contended past the budget" (`Contended`) from every other
//! failure — and the inbound adapter can answer 503 + `Retry-After` instead
//! of a 500 that misdescribes a healthy, merely busy, system.

use std::future::Future;
use std::time::Duration;

use hort_domain::error::{DomainError, DomainResult};

/// Attempts (not retries): one initial try plus three retries.
///
/// Sized against what it is absorbing. A contention abort resolves as soon as
/// the winning writer commits, which is sub-millisecond for the single-row
/// upserts this covers, so the first retry succeeds in the overwhelming
/// majority of cases and the later ones exist for a pile-up. Going higher
/// trades a vanishing extra success rate against holding a request open
/// longer under exactly the load that produced the contention.
pub(crate) const CONTENTION_RETRY_ATTEMPTS: u32 = 4;

/// Postgres error classes meaning "your transaction was aborted so another
/// could proceed; nothing was applied; run it again":
///
/// - `40001` `serialization_failure`
/// - `40P01` `deadlock_detected`
///
/// Deliberately NOT `23505` (`unique_violation`): that is a real duplicate,
/// and re-running it produces the same violation.
fn contention_sqlstate(code: &str) -> bool {
    matches!(code, "40001" | "40P01")
}

/// The sqlstate of `e`, if it carries one.
fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|db| db.code().map(std::borrow::Cow::into_owned))
}

/// `true` when `e` is a transient contention abort (see
/// [`contention_sqlstate`]).
pub(crate) fn is_contention(e: &sqlx::Error) -> bool {
    sqlstate(e).is_some_and(|code| contention_sqlstate(&code))
}

/// [`DomainError::Contended`] for `e` when it is a contention abort, else
/// `None` so the caller falls through to its own mapping.
///
/// `op` names the write for the operator reading the log — the sqlstate goes
/// into the message because it is the one detail that makes a contention
/// report actionable (a deadlock wants a lock-order look, a serialization
/// failure wants a transaction-shape look), and this string never leaves the
/// server: the HTTP layers render a fixed envelope for this variant.
pub(crate) fn contention_error(e: &sqlx::Error, op: &str) -> Option<DomainError> {
    let code = sqlstate(e)?;
    contention_sqlstate(&code).then(|| {
        DomainError::Contended(format!(
            "{op} aborted by concurrent write contention (SQLSTATE {code})"
        ))
    })
}

/// `5ms * 4^(attempt-1)` (5/20/80ms across the three gaps between four
/// attempts) plus 0–5ms of jitter, so a pile-up of losers does not re-collide
/// in lockstep. Worst-case added latency is ~105ms + jitter.
///
/// Deliberately an order of magnitude tighter than the event-append CAS
/// backoff in the application layer: that one waits out a co-writer's whole
/// append round trip, whereas a contention abort is already resolved — the
/// winner committed before Postgres raised the error — so the delay only has
/// to break the lockstep, not wait for anything.
pub(crate) fn contention_backoff(attempt: u32) -> Duration {
    let base_ms = 5u64.saturating_mul(4u64.saturating_pow(attempt.saturating_sub(1)));
    let jitter_ms = u64::from(rand::random::<u8>() % 6); // 0..=5ms
    Duration::from_millis(base_ms + jitter_ms)
}

/// Run `op`, retrying it while it fails with [`DomainError::Contended`], up
/// to `attempts` total tries.
///
/// `op` must be **whole-transaction re-runnable**: a contention abort rolls
/// its transaction back completely, so a caller wrapping anything less than a
/// full transaction boundary would re-run a fragment of work whose earlier
/// half is gone. Every call site here wraps exactly one transaction or one
/// self-contained statement.
///
/// Returns the final attempt's error verbatim on exhaustion — the same value
/// a single unretried attempt would have produced — so `Err(Contended(_))`
/// reaching a caller unambiguously means the budget was spent, and any other
/// `Err` means the first attempt failed for a reason that was never retried.
pub(crate) async fn with_contention_retry<T, F, Fut>(
    op: &'static str,
    attempts: u32,
    backoff: impl Fn(u32) -> Duration,
    mut f: F,
) -> DomainResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = DomainResult<T>>,
{
    let mut attempt: u32 = 1;
    loop {
        match f().await {
            Ok(value) => return Ok(value),
            Err(DomainError::Contended(detail)) if attempt < attempts => {
                let delay = backoff(attempt);
                tracing::debug!(
                    op,
                    attempt,
                    attempts,
                    delay_ms = delay.as_millis() as u64,
                    detail = %detail,
                    "write contention — retrying the whole transaction",
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(DomainError::Contended(detail)) => {
                // Budget spent. `warn`, not `error`: the system is busy, not
                // broken, and the caller is about to be told to come back.
                tracing::warn!(
                    op,
                    attempts,
                    detail = %detail,
                    "write contention persisted across the whole retry budget",
                );
                return Err(DomainError::Contended(detail));
            }
            Err(other) => return Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn contended() -> DomainError {
        DomainError::Contended("test".into())
    }

    /// Zero backoff so the retry tests do not pay real wall-clock time.
    fn no_backoff(_attempt: u32) -> Duration {
        Duration::ZERO
    }

    #[test]
    fn contention_sqlstates_are_exactly_the_two_abort_classes() {
        assert!(contention_sqlstate("40001"), "serialization_failure");
        assert!(contention_sqlstate("40P01"), "deadlock_detected");
    }

    /// The negative half is the load-bearing one: `23505` is a real
    /// duplicate, and classifying it as contention would make the retry
    /// re-run a write that is going to violate the same constraint every
    /// time — and, worse, would convert a `Conflict` (which the OCI manifest
    /// path answers with a crisp 400, and the event store with a 409) into a
    /// retryable `Contended`, breaking idempotency for every caller that
    /// pattern-matches on it.
    #[test]
    fn a_unique_violation_is_never_contention() {
        for code in ["23505", "23503", "23514", "22001", "40002", "4001", "40P02"] {
            assert!(
                !contention_sqlstate(code),
                "{code} must not be classified as transient contention"
            );
        }
    }

    #[tokio::test]
    async fn a_first_attempt_success_costs_no_retries() {
        let calls = Cell::new(0u32);
        let out: DomainResult<u32> =
            with_contention_retry("test", CONTENTION_RETRY_ATTEMPTS, no_backoff, || {
                calls.set(calls.get() + 1);
                async { Ok(7) }
            })
            .await;
        assert_eq!(out.unwrap(), 7);
        assert_eq!(calls.get(), 1, "no retry on success");
    }

    #[tokio::test]
    async fn contention_is_retried_until_it_clears() {
        let calls = Cell::new(0u32);
        let out: DomainResult<u32> =
            with_contention_retry("test", CONTENTION_RETRY_ATTEMPTS, no_backoff, || {
                calls.set(calls.get() + 1);
                let n = calls.get();
                async move {
                    if n < 3 {
                        Err(contended())
                    } else {
                        Ok(n)
                    }
                }
            })
            .await;
        assert_eq!(out.unwrap(), 3, "the third attempt's value is returned");
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test]
    async fn exhaustion_returns_contended_verbatim_and_stops_at_the_budget() {
        let calls = Cell::new(0u32);
        let out: DomainResult<u32> =
            with_contention_retry("test", CONTENTION_RETRY_ATTEMPTS, no_backoff, || {
                calls.set(calls.get() + 1);
                async { Err(contended()) }
            })
            .await;
        assert!(
            matches!(out, Err(DomainError::Contended(_))),
            "exhaustion must stay Contended so the edge can answer 503, not 500"
        );
        assert_eq!(
            calls.get(),
            CONTENTION_RETRY_ATTEMPTS,
            "the budget is a hard bound"
        );
    }

    /// The invariant that keeps idempotent re-writes idempotent: a decided
    /// `Conflict` is returned on the first attempt, untouched and unretried.
    #[tokio::test]
    async fn a_conflict_is_never_retried() {
        let calls = Cell::new(0u32);
        let out: DomainResult<u32> =
            with_contention_retry("test", CONTENTION_RETRY_ATTEMPTS, no_backoff, || {
                calls.set(calls.get() + 1);
                async { Err(DomainError::Conflict("duplicate".into())) }
            })
            .await;
        assert!(matches!(out, Err(DomainError::Conflict(msg)) if msg == "duplicate"));
        assert_eq!(calls.get(), 1, "a decided conflict spends no budget");
    }

    #[tokio::test]
    async fn other_errors_return_on_the_first_attempt() {
        for seed in [
            DomainError::Invariant("boom".into()),
            DomainError::NotFound {
                entity: "Artifact",
                id: "x".into(),
            },
            DomainError::Validation("bad".into()),
        ] {
            let calls = Cell::new(0u32);
            let expected = seed.clone();
            let out: DomainResult<u32> =
                with_contention_retry("test", CONTENTION_RETRY_ATTEMPTS, no_backoff, || {
                    calls.set(calls.get() + 1);
                    let e = expected.clone();
                    async move { Err(e) }
                })
                .await;
            assert!(out.is_err());
            assert_eq!(calls.get(), 1, "{seed:?} must not be retried");
        }
    }

    #[test]
    fn backoff_grows_and_stays_bounded() {
        let mut previous = Duration::ZERO;
        for attempt in 1..CONTENTION_RETRY_ATTEMPTS {
            let delay = contention_backoff(attempt);
            assert!(
                delay > previous || attempt == 1,
                "attempt {attempt} must not shrink the delay"
            );
            assert!(
                delay <= Duration::from_millis(85),
                "attempt {attempt} delay {delay:?} exceeds the documented worst case"
            );
            previous = Duration::from_millis(5u64 * 4u64.pow(attempt - 1));
        }
    }
}
