//! "Which of the entries this document is about to name would the
//! registry refuse?" — resolved once, here, for every surface hort
//! **builds** out of manifest digests.
//!
//! ADR 0062 splits enforcement by the kind of document. Where the
//! document is immutable content-addressed bytes hort cannot rewrite, it
//! is **refused** — that is
//! [`ManifestDeliverabilityUseCase`](crate::use_cases::manifest_deliverability::ManifestDeliverabilityUseCase),
//! which resolves one manifest's closure out of the bytes its caller
//! already holds. Where hort **constructs** the document, it chooses the
//! entries, so the non-servable one is **omitted** — and this use case
//! is the question behind that omission for the two OCI surfaces that
//! name manifests by digest: the referrers index and `tags/list`.
//!
//! # The two authorities are deliberate, not an inconsistency
//!
//! Both answer "is this manifest's closure still deliverable?". They
//! read the closure from different places because their callers hold
//! different things:
//!
//! - a manifest `GET` is already holding the bytes it is about to serve.
//!   Deriving the closure from them costs nothing, and consulting the
//!   edge projection there would buy a second source of truth for free.
//! - a **list** is holding no bytes. The same derivation would be one
//!   CAS-read tree per entry — N round trips to answer a document that
//!   names N manifests — and a list has no acceptable fail-closed answer
//!   when a per-entry budget blows: refusing one manifest is
//!   proportionate, refusing a whole `tags/list` is not.
//!
//! So this use case resolves the closure from the membership projection,
//! through `ListDeliverabilityCensus`, and the manifest route does not.
//! Routing either through the other is the one change to make
//! deliberately rather than tidily.
//!
//! # What it does not decide
//!
//! - **How many halves a caller needs.** Non-deliverable means the
//!   candidate's own status is terminal *or* something in its closure
//!   is, and the census answers both. A caller that already holds an
//!   entry's hydrated artifact row — the referrers loop does — answers
//!   the own-status half with one match and hands the census only the
//!   survivors. That is an optimisation in the caller, not a different
//!   question: the census's answer for a survivor is its closure half,
//!   because its own status is already known non-terminal.
//! - **Which entries are candidates at all.** A `tags/list` entry
//!   pointing at a version string rather than a content hash is not an
//!   OCI manifest pointer; the caller does not supply it, and this use
//!   case does not guess at what it might mean.
//! - **What a caller does with a failure.** The census propagates its
//!   error. Not knowing what a list would refuse is not the same as
//!   knowing it would refuse nothing (ADR 0007), so a caller serves
//!   nothing — but choosing the wire shape for that is the caller's.
//! - **Caching.** Deliverability is not a property of an entry's own
//!   row: it changes in both directions when a constituent is
//!   re-judged, with the entry's bytes and status untouched.

use std::collections::HashSet;
use std::sync::Arc;

use uuid::Uuid;

use hort_domain::ports::list_deliverability::ListDeliverabilityCensus;
use hort_domain::types::ContentHash;

use crate::error::AppResult;

/// Resolves the omission set for a hort-built list of manifest digests.
pub struct ListDeliverabilityUseCase {
    census: Arc<dyn ListDeliverabilityCensus>,
}

impl ListDeliverabilityUseCase {
    #[must_use]
    pub fn new(census: Arc<dyn ListDeliverabilityCensus>) -> Self {
        Self { census }
    }

    /// The subset of `candidates` the document must leave out.
    ///
    /// **One call for the whole page**, never one per entry: the cost
    /// model this surface was shaped around is a single round trip per
    /// list, and a per-entry fan-out would put one on every name a
    /// client resolves against.
    ///
    /// The log line on a non-empty answer is here rather than at the
    /// call site because this is the one place the omission is decided,
    /// so a second surface cannot omit silently. The omission is
    /// invisible to the client by design (ADR 0062 — the list omits, the
    /// direct ask explains), which is exactly why an operator needs to
    /// be able to tell a withheld entry from a missing one.
    pub async fn non_deliverable_in(
        &self,
        repository_id: Uuid,
        candidates: &[ContentHash],
    ) -> AppResult<HashSet<ContentHash>> {
        let withheld = self
            .census
            .non_deliverable_in(repository_id, candidates)
            .await?;
        if !withheld.is_empty() {
            tracing::info!(
                %repository_id,
                candidates = candidates.len(),
                withheld = withheld.len(),
                "list surface omitting entries: a terminal status in each one's closure makes \
                 it non-deliverable, and a document hort builds omits what it will not serve"
            );
        }
        Ok(withheld)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::BoxFuture;

    use crate::error::AppError;

    fn hash(seed: u8) -> ContentHash {
        format!("{seed:02x}")
            .repeat(32)
            .parse()
            .expect("synthetic sha256")
    }

    /// Records what it was asked and answers a fixed set, so the use
    /// case's own two properties — it batches, and it does not reshape
    /// the answer — are observable without a database.
    struct RecordingCensus {
        withheld: HashSet<ContentHash>,
        error: Option<DomainError>,
        calls: std::sync::Mutex<Vec<(Uuid, Vec<ContentHash>)>>,
    }

    impl RecordingCensus {
        fn answering(withheld: HashSet<ContentHash>) -> Self {
            Self {
                withheld,
                error: None,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn failing(error: DomainError) -> Self {
            Self {
                withheld: HashSet::new(),
                error: Some(error),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl ListDeliverabilityCensus for RecordingCensus {
        fn non_deliverable_in<'a>(
            &'a self,
            repository_id: Uuid,
            candidates: &'a [ContentHash],
        ) -> BoxFuture<'a, DomainResult<HashSet<ContentHash>>> {
            self.calls
                .lock()
                .unwrap()
                .push((repository_id, candidates.to_vec()));
            let answer = self
                .error
                .clone()
                .map_or_else(|| Ok(self.withheld.clone()), Err);
            Box::pin(async move { answer })
        }
    }

    #[tokio::test]
    async fn the_whole_page_is_asked_in_one_call() {
        let census = Arc::new(RecordingCensus::answering(HashSet::from([hash(2)])));
        let repo = Uuid::new_v4();
        let page = [hash(1), hash(2), hash(3)];

        let withheld = ListDeliverabilityUseCase::new(census.clone())
            .non_deliverable_in(repo, &page)
            .await
            .expect("the census answers");

        assert_eq!(withheld, HashSet::from([hash(2)]));
        let calls = census.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![(repo, page.to_vec())],
            "one call carrying the whole page, not one per entry"
        );
    }

    /// The answer is passed through unreshaped. A use case that
    /// "helpfully" intersected, sorted or re-derived it would be a
    /// second decision between the census and the document.
    #[tokio::test]
    async fn an_empty_answer_omits_nothing() {
        let census = Arc::new(RecordingCensus::answering(HashSet::new()));
        assert!(ListDeliverabilityUseCase::new(census)
            .non_deliverable_in(Uuid::new_v4(), &[hash(9)])
            .await
            .expect("the census answers")
            .is_empty());
    }

    /// A census failure propagates rather than degrading to "omit
    /// nothing": that degradation is a list advertising on an
    /// unanswered question, which is the posture ADR 0062 replaced.
    #[tokio::test]
    async fn a_census_failure_propagates() {
        let census = Arc::new(RecordingCensus::failing(DomainError::Invariant(
            "census exploded".into(),
        )));
        let err = ListDeliverabilityUseCase::new(census)
            .non_deliverable_in(Uuid::new_v4(), &[hash(9)])
            .await
            .expect_err("the failure must not be absorbed");
        assert!(
            matches!(err, AppError::Domain(DomainError::Invariant(ref m)) if m == "census exploded"),
            "unexpected error: {err:?}"
        );
    }
}
