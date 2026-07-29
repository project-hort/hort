//! Bounded startup retry with backoff for one-shot, fallible
//! composition-root initialization calls (issue #86).
//!
//! At boot there is no state yet to corrupt, so every failure mode of a
//! call like [`crate::composition::build_app_context`] is either
//! transient infra (a retry helps) or persistent misconfig (a retry
//! costs the backoff budget, then fails with the same message). This
//! helper therefore retries ALL errors from `f` uniformly — it never
//! inspects or classifies the error to decide whether to retry.

use std::future::Future;
use std::time::Duration;

/// Call `f` up to `attempts` times (`attempts >= 1`), sleeping
/// `backoff(n)` between the n-th failed attempt and the next
/// (1-indexed: `backoff(1)` follows the first failure, ...,
/// `backoff(attempts - 1)` follows the second-to-last failure). Returns
/// the first `Ok`, or — on exhaustion — the LAST attempt's error
/// verbatim, unwrapped: the caller's own `.context(...)` layers on top
/// exactly as it would around a single unretried call.
pub async fn retry_with_backoff<T, E, F, Fut>(
    attempts: u32,
    backoff: impl Fn(u32) -> Duration,
    mut f: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    debug_assert!(attempts >= 1, "retry_with_backoff requires attempts >= 1");
    let mut attempt: u32 = 1;
    loop {
        match f().await {
            Ok(value) => return Ok(value),
            Err(err) if attempt < attempts => {
                let delay = backoff(attempt);
                tracing::warn!(
                    attempt,
                    attempts,
                    error = %err,
                    delay_secs = delay.as_secs_f64(),
                    "startup attempt failed — retrying after backoff",
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    /// A backoff schedule with zero real delay — the tests still pause
    /// the Tokio clock and assert on elapsed *virtual* time, but a
    /// zero-length sleep keeps `tokio::time::advance` calls trivial to
    /// reason about.
    fn zero_backoff(_attempt: u32) -> Duration {
        Duration::ZERO
    }

    fn secs_backoff(attempt: u32) -> Duration {
        Duration::from_secs(u64::from(attempt))
    }

    #[tokio::test]
    async fn succeeds_after_n_failures() {
        let calls = AtomicU32::new(0);
        let result: Result<&'static str, &'static str> =
            retry_with_backoff(5, zero_backoff, || {
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    if n < 3 {
                        Err("transient")
                    } else {
                        Ok("booted")
                    }
                }
            })
            .await;

        assert_eq!(result, Ok("booted"));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "must stop retrying on success"
        );
    }

    #[tokio::test]
    async fn exhaustion_propagates_the_last_error() {
        let calls = AtomicU32::new(0);
        let result: Result<&'static str, String> = retry_with_backoff(4, zero_backoff, || {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            async move { Err(format!("failure #{n}")) }
        })
        .await;

        assert_eq!(
            result,
            Err("failure #4".to_string()),
            "exhaustion must surface the LAST attempt's error, not the first"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "attempt count must be respected"
        );
    }

    #[tokio::test]
    async fn single_attempt_bound_never_retries() {
        let calls = AtomicU32::new(0);
        let result: Result<&'static str, &'static str> =
            retry_with_backoff(1, zero_backoff, || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err("boom") }
            })
            .await;

        assert_eq!(result, Err("boom"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn first_attempt_success_never_sleeps() {
        // A real (unpaused) clock: if this incorrectly slept, the test
        // would still pass but slowly. Combined with the paused-clock
        // test below (which asserts on elapsed virtual time), the pair
        // covers both "does it try to sleep" and "does it sleep the
        // right amount when it does."
        let result: Result<&'static str, &'static str> =
            retry_with_backoff(5, secs_backoff, || async { Ok("booted") }).await;
        assert_eq!(result, Ok("booted"));
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_delays_are_honoured_between_attempts() {
        let calls = AtomicU32::new(0);
        let start = tokio::time::Instant::now();
        let result: Result<&'static str, &'static str> =
            retry_with_backoff(3, secs_backoff, || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err("transient") }
            })
            .await;

        assert_eq!(result, Err("transient"));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        // backoff(1) + backoff(2) = 1s + 2s = 3s of paused-clock time
        // elapsed between the three attempts, with no real-time sleep.
        assert_eq!(start.elapsed(), Duration::from_secs(3));
    }
}
