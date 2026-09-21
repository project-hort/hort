//! `OciIndexChildEnqueueUseCase` — the application-layer facade the OCI
//! inbound-HTTP crate calls to queue eager ingest of an image index's
//! declared children.
//!
//! # Why a use case and not a direct port call
//!
//! `AppContext::jobs` is `pub(crate)` to `hort-http-core` (ADR 0008): an
//! inbound format crate must not touch the queue directly. The OCI
//! pull-through legs therefore reach the `jobs` table through this facade,
//! exactly as they reach the content-reference index through
//! [`crate::use_cases::content_reference::ContentReferenceUseCase`]. Keeping
//! the row shape here also keeps the producer and the consumer
//! ([`crate::task_handlers::oci_index_child_ingest`]) in one crate, so the
//! params and the dedupe key have a single definition that the compiler
//! checks rather than two that can drift.
//!
//! # What it does
//!
//! Given the bytes of a manifest that was just ingested, enqueue one
//! `oci-index-child-ingest` row per child the manifest declares. A
//! single-image manifest declares none, so it is a no-op — the domain's
//! [`index_child_digests`] yields an empty set for a body with no
//! `manifests[]`, which is the "not an index, no enqueue" rule expressed as
//! data rather than as a second media-type branch. The **body** decides,
//! never the upstream's declared `Content-Type`: those are the bytes that
//! were hashed and stored.
//!
//! # Every failure is non-fatal
//!
//! The caller is a live pull-through that has already committed the index
//! artifact and is about to answer the client. A malformed body, an
//! over-cap index and a jobs-table error are each logged and skipped; the
//! response is unaffected and the children still reach the repository
//! through the lazy pull path a client GET triggers. Degrading to that lazy
//! behaviour is the correct fallback — eager child ingest is a latency
//! optimisation, so the only cost of not enqueueing is the optimisation
//! itself. The jobs-table failure is all-or-nothing rather than per child:
//! one statement enqueues the cohort, so a failed statement leaves every
//! declared child on the lazy path, which is the same fallback in bulk.
//!
//! Every row this facade mints is at the **root** recursion depth: a
//! pull-through leg observes the index a client asked for, which is the top of
//! any nested chain by definition. The handler's depth cap counts from there,
//! and the depth is carried by [`child_ingest_params`] rather than being a
//! parameter of this call — there is no leg that could legitimately pass
//! anything else.
//!
//! # Idempotency
//!
//! Each row carries the `(repository_id, child_digest)` dedupe key from
//! [`child_ingest_idempotency_key`], on the `jobs.idempotency_key` partial
//! unique index. Concurrent pulls of the same index, a re-pull after the
//! index releases, and the leader and coalesced-follower legs firing for
//! the same repository therefore all collapse onto one row. The requested
//! name is deliberately NOT part of the key: the same content in the same
//! repository is one unit of work however it was reached.
//!
//! # One statement, not one per child
//!
//! The whole cohort goes through
//! [`JobsRepository::enqueue_idempotent_batch`] — a single
//! `INSERT … ON CONFLICT (idempotency_key) DO NOTHING` — never a per-child
//! loop over [`JobsRepository::enqueue_task`]. This call runs on the
//! request path, inside a pull-through's dedup coalescing window, before
//! the client's manifest response is produced and with other clients
//! pulling the same index waiting behind it; an index may declare up to
//! the domain's per-index child cap, so a per-row entry point would mean
//! that many round-trips of latency and lock churn in exactly the case
//! this feature exists for — a fresh multi-arch index, where every child
//! is a real write rather than a conflict. ADR 0053 reached the same
//! conclusion for the prefetch cascade.
//!
//! Batching is also why the enqueue does not need to move off the request
//! path: one statement is affordable there, and it stays synchronous and
//! durable rather than being spawned, because a spawned enqueue can be
//! lost and a lost enqueue is the failure this feature's design rejected.
//!
//! Dedup counts come from the statement's result — one returned id per row
//! that actually inserted — rather than from per-row outcomes, so a
//! conflict is absorbed by the index rather than raised and swallowed.

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::oci::index_child_digests;
use hort_domain::ports::jobs_repository::{IdempotentEnqueueRow, JobsRepository};

use crate::task_handlers::oci_index_child_ingest::{
    child_ingest_idempotency_key, child_ingest_params, CHILD_INGEST_ENQUEUE_PRIORITY,
    CHILD_INGEST_TRIGGER_SOURCE, OCI_INDEX_CHILD_INGEST_KIND,
};

/// Facade over [`JobsRepository`] for the eager index-child enqueue.
pub struct OciIndexChildEnqueueUseCase {
    jobs: Arc<dyn JobsRepository>,
}

impl OciIndexChildEnqueueUseCase {
    /// Construct the facade over the `jobs` port.
    pub fn new(jobs: Arc<dyn JobsRepository>) -> Self {
        Self { jobs }
    }

    /// Enqueue one `oci-index-child-ingest` row per child `manifest_body`
    /// declares, targeting `repository_id`.
    ///
    /// `requested_name` is the **client-facing** name the pull resolved
    /// this manifest from (`dockerhub/library/nginx`, not the stripped
    /// `library/nginx`). The consumer re-resolves it through
    /// `UpstreamResolver`, reproducing exactly what a lazy client pull for
    /// the same child would do — which is the semantics eager child ingest
    /// is defined by. Passing the stripped name instead would send every
    /// child to whichever mapping happens to be the catch-all, which on a
    /// prefix-scoped multi-upstream proxy is either the wrong upstream or
    /// no upstream at all.
    ///
    /// Returns nothing and never fails: see the module doc's non-fatal
    /// contract. The outcome counts are emitted here as a log record
    /// rather than handed back — every call site is a live pull-through
    /// that has nothing to decide on them, and this frame is the only one
    /// that can also distinguish "no children declared" from "body
    /// refused or over-cap", each of which logs its own line at the point
    /// the distinction is known.
    #[tracing::instrument(skip(self, manifest_body))]
    pub async fn enqueue_declared_children(
        &self,
        repository_id: Uuid,
        requested_name: &str,
        manifest_body: &[u8],
    ) {
        let children = match index_child_digests(manifest_body) {
            Ok(c) => c,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    %repository_id,
                    requested_name,
                    "OCI eager child ingest: index children not enumerable; no child rows \
                     enqueued (non-fatal, the children stay on the lazy pull path)",
                );
                return;
            }
        };
        if children.is_empty() {
            return;
        }

        let rows: Vec<IdempotentEnqueueRow> = children
            .iter()
            .map(|child| IdempotentEnqueueRow {
                kind: OCI_INDEX_CHILD_INGEST_KIND.to_string(),
                params: child_ingest_params(repository_id, requested_name, child),
                priority: CHILD_INGEST_ENQUEUE_PRIORITY,
                trigger_source: CHILD_INGEST_TRIGGER_SOURCE.to_string(),
                idempotency_key: child_ingest_idempotency_key(repository_id, child),
            })
            .collect();

        match self.jobs.enqueue_idempotent_batch(&rows).await {
            Ok(inserted) => tracing::info!(
                %repository_id,
                requested_name,
                declared_children = children.len(),
                enqueued = inserted.len(),
                deduped = rows.len() - inserted.len(),
                "OCI eager child ingest: index children queued",
            ),
            // The statement is all-or-nothing, so a failure leaves every
            // declared child un-enqueued — all of them fall back to the
            // lazy pull path, and the client's response is unaffected.
            Err(err) => tracing::warn!(
                error = %err,
                %repository_id,
                requested_name,
                declared_children = children.len(),
                "OCI eager child ingest: child row enqueue failed; those children stay \
                 on the lazy pull path (non-fatal)",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hort_domain::error::DomainError;
    use hort_domain::types::ContentHash;
    use serde_json::json;

    use crate::task_handlers::oci_index_child_ingest::CHILD_INGEST_ROOT_DEPTH;
    use crate::use_cases::test_support::MockJobsRepository;

    fn deterministic_sha(seed: u32) -> ContentHash {
        format!("{seed:064x}").parse().expect("64-hex sha")
    }

    fn index_body(children: &[ContentHash]) -> Vec<u8> {
        let manifests: Vec<serde_json::Value> = children
            .iter()
            .map(|c| {
                json!({
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{}", c.as_ref()),
                    "size": 7,
                })
            })
            .collect();
        json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": manifests,
        })
        .to_string()
        .into_bytes()
    }

    fn image_manifest_body() -> Vec<u8> {
        json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "digest": format!("sha256:{}", deterministic_sha(1).as_ref()) },
            "layers": [ { "digest": format!("sha256:{}", deterministic_sha(2).as_ref()) } ],
        })
        .to_string()
        .into_bytes()
    }

    fn fixture() -> (OciIndexChildEnqueueUseCase, Arc<MockJobsRepository>) {
        let jobs = Arc::new(MockJobsRepository::default());
        (OciIndexChildEnqueueUseCase::new(jobs.clone()), jobs)
    }

    /// The rows of the one and only cohort the facade enqueued. Asserting
    /// the statement count here means every caller of this helper also
    /// pins "one statement", not just the test that says so by name.
    fn single_cohort(jobs: &MockJobsRepository) -> Vec<IdempotentEnqueueRow> {
        let calls = jobs.idempotent_batch_calls();
        assert_eq!(
            calls.len(),
            1,
            "the facade must issue exactly one enqueue statement per index",
        );
        calls.into_iter().next().expect("one cohort")
    }

    #[tokio::test]
    async fn enqueues_one_row_per_declared_child() {
        let (uc, jobs) = fixture();
        let repo_id = Uuid::new_v4();
        let children = [deterministic_sha(1), deterministic_sha(2)];
        uc.enqueue_declared_children(repo_id, "dockerhub/library/nginx", &index_body(&children))
            .await;

        let cohort = single_cohort(&jobs);
        assert_eq!(cohort.len(), 2);
        for (row, child) in cohort.iter().zip(children.iter()) {
            assert_eq!(row.kind, OCI_INDEX_CHILD_INGEST_KIND);
            assert_eq!(row.priority, CHILD_INGEST_ENQUEUE_PRIORITY);
            assert_eq!(row.trigger_source, CHILD_INGEST_TRIGGER_SOURCE);
            assert_eq!(row.params["repository_id"], json!(repo_id));
            assert_eq!(
                row.params["requested_name"], "dockerhub/library/nginx",
                "the CLIENT-FACING name travels, so the consumer re-resolves the \
                 same mapping a lazy pull would have used",
            );
            assert_eq!(
                row.params["child_digest"],
                format!("sha256:{}", child.as_ref())
            );
            assert_eq!(
                row.idempotency_key,
                child_ingest_idempotency_key(repo_id, child),
                "every child row carries the (repository, child digest) dedupe key",
            );
        }
    }

    /// An index declaring N children costs ONE statement, not N. This is
    /// the whole point of the batched entry point: the call runs inside a
    /// live pull-through's coalescing window, so a refactor back to a
    /// per-child loop must fail a test rather than pass quietly.
    #[tokio::test]
    async fn a_many_child_index_issues_exactly_one_statement() {
        let (uc, jobs) = fixture();
        let children: Vec<ContentHash> = (0..64u32).map(deterministic_sha).collect();
        uc.enqueue_declared_children(
            Uuid::new_v4(),
            "dockerhub/library/nginx",
            &index_body(&children),
        )
        .await;

        assert_eq!(
            jobs.idempotent_batch_calls().len(),
            1,
            "64 declared children must cost ONE enqueue statement",
        );
        assert!(
            jobs.enqueue_calls().is_empty(),
            "the per-row entry point must not be used for a cohort",
        );
        assert_eq!(single_cohort(&jobs).len(), 64);
    }

    /// A pull-through leg observes the index a client asked for, which is the
    /// root of any nested chain — so every row it mints is at the root depth
    /// and the handler's depth cap counts from here.
    #[tokio::test]
    async fn a_pull_through_leg_mints_rows_at_the_root_depth() {
        let (uc, jobs) = fixture();
        uc.enqueue_declared_children(
            Uuid::new_v4(),
            "dockerhub/library/nginx",
            &index_body(&[deterministic_sha(7)]),
        )
        .await;
        assert_eq!(
            single_cohort(&jobs)[0].params["depth"],
            json!(CHILD_INGEST_ROOT_DEPTH)
        );
    }

    /// The dedupe key ignores the requested name: the same content in the
    /// same repository is one unit of work however it was reached, so a
    /// second leg enqueueing the same child collapses onto the first row.
    #[tokio::test]
    async fn the_dedupe_key_is_stable_across_names_and_legs() {
        let (uc, jobs) = fixture();
        let repo_id = Uuid::new_v4();
        let child = deterministic_sha(9);
        let body = index_body(std::slice::from_ref(&child));

        uc.enqueue_declared_children(repo_id, "dockerhub/library/nginx", &body)
            .await;
        uc.enqueue_declared_children(repo_id, "ghcr/library/nginx", &body)
            .await;

        let calls = jobs.idempotent_batch_calls();
        assert_eq!(calls.len(), 2, "one statement per leg");
        assert_eq!(
            calls[0][0].idempotency_key, calls[1][0].idempotency_key,
            "two legs reaching the same child in the same repository must present the \
             SAME key, so the jobs unique index absorbs the second row",
        );
    }

    /// A repeat pull adds no rows and raises no error: the dedupe key
    /// collides inside the unique index, which returns fewer ids rather
    /// than a per-row conflict the facade would have to swallow.
    #[tokio::test]
    async fn a_repeat_pull_adds_no_rows_by_index_conflict() {
        let (uc, jobs) = fixture();
        let repo_id = Uuid::new_v4();
        let child = deterministic_sha(3);
        let body = index_body(std::slice::from_ref(&child));
        jobs.seed_idempotent_key_present(
            child_ingest_idempotency_key(repo_id, &child)
                .as_str()
                .to_string(),
        );

        uc.enqueue_declared_children(repo_id, "dockerhub/library/nginx", &body)
            .await;

        let cohort = single_cohort(&jobs);
        assert_eq!(
            cohort.len(),
            1,
            "the statement is still issued — the index, not the caller, decides the row \
             is redundant",
        );
    }

    /// A batch-statement failure is logged and skipped: the pull is not
    /// affected and the children fall back to the lazy path. All-or-
    /// nothing is the trade the single statement buys — there is no
    /// partial cohort to reason about.
    #[tokio::test]
    async fn a_jobs_table_error_is_swallowed_and_never_surfaced() {
        let (uc, jobs) = fixture();
        jobs.fail_next_idempotent_batch(DomainError::Invariant("simulated jobs outage".into()));
        uc.enqueue_declared_children(
            Uuid::new_v4(),
            "dockerhub/library/nginx",
            &index_body(&[deterministic_sha(4), deterministic_sha(5)]),
        )
        .await;
        assert_eq!(
            single_cohort(&jobs).len(),
            2,
            "the failing call still issued exactly one statement for the whole cohort",
        );
    }

    #[tokio::test]
    async fn a_single_image_manifest_enqueues_nothing() {
        let (uc, jobs) = fixture();
        uc.enqueue_declared_children(
            Uuid::new_v4(),
            "dockerhub/library/nginx",
            &image_manifest_body(),
        )
        .await;
        assert!(jobs.idempotent_batch_calls().is_empty());
    }

    #[tokio::test]
    async fn an_empty_manifests_array_enqueues_nothing() {
        let (uc, jobs) = fixture();
        uc.enqueue_declared_children(Uuid::new_v4(), "dockerhub/library/nginx", &index_body(&[]))
            .await;
        assert!(jobs.idempotent_batch_calls().is_empty());
    }

    #[tokio::test]
    async fn an_unparseable_body_enqueues_nothing_and_does_not_panic() {
        let (uc, jobs) = fixture();
        uc.enqueue_declared_children(Uuid::new_v4(), "dockerhub/library/nginx", b"not json")
            .await;
        assert!(jobs.idempotent_batch_calls().is_empty());
    }

    /// An index declaring more children than the domain's per-index cap is
    /// REFUSED by `index_child_digests`, never truncated — so it enqueues
    /// nothing rather than a partial child set.
    #[tokio::test]
    async fn an_over_cap_index_enqueues_nothing() {
        let (uc, jobs) = fixture();
        // One past the domain's per-index child cap, which is private to
        // `hort_domain::oci` — the same literal the handler's own over-cap
        // test uses.
        let over_cap: Vec<ContentHash> = (0..1_025u32).map(deterministic_sha).collect();
        uc.enqueue_declared_children(
            Uuid::new_v4(),
            "dockerhub/library/nginx",
            &index_body(&over_cap),
        )
        .await;
        assert!(jobs.idempotent_batch_calls().is_empty());
    }
}
