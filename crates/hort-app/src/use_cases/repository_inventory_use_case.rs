//! `RepositoryInventoryUseCase` — the admin readout of what each
//! repository's live catalog holds.
//!
//! A retention concept without a before/after measurement is not
//! verifiable, and until this surface existed nothing in the product
//! answered "how many artifacts and how many bytes does this repository
//! hold?" — the first inventory had to be taken by hand, with read-only
//! SQL against a production database. This use case is the product's
//! answer: per repository, the live row count, the distinct-content
//! count, and the weight of those distinct contents.
//!
//! # A readout, not a gauge
//!
//! It emits **no metric**. The surface is the answer to an interactive
//! operator question, and the precedent for that shape is the removal of
//! the two provenance-hold gauges: *"no replacement metric; the
//! operator's view of the held set is the admin curation queue."* That
//! decision was about the held set rather than about an inventory, so it
//! does not bar an inventory gauge on its own terms — whether such a
//! gauge is worth having is a separate decision on freshness, scrape
//! cost and whether anyone needs to alert on it. This use case neither
//! builds nor forecloses it.
//!
//! # What the three numbers are, and which one can be misread
//!
//! [`RepositoryInventory`] carries them, and
//! [`RepositoryInventoryReader`]'s docs are where the full reading of
//! the third one lives. The short form, because every consumer has to
//! repeat it: `live_primary_content_bytes` is a **catalog weight** — it
//! is **non-additive across repositories** (one CAS entry can carry rows
//! in several of them, ADR 0054), it is **not disk usage** (it omits
//! CAS-resident metadata and every other content-reference target kind)
//! and it is **not reclaimable space** (a soft-deleted row's bytes stay
//! resident until refcount-gated GC, and what a disposal frees depends
//! on every surviving claim).
//!
//! # No quota figure
//!
//! `repositories.quota_bytes` is deliberately **absent** from this
//! readout, and the question of what to do about that field has since
//! been settled: the operator surface is **retired**. A gitops apply
//! declaring `quotaBytes` is refused
//! ([`hort_config::desired::validate_repository_quota_bytes_retired`]),
//! nothing ever compared the value to a usage figure, and no surface
//! reports the column. Reporting a stored leftover beside a usage figure
//! would make this readout look like quota monitoring while no quota
//! exists to monitor, which is the more dangerous of the two available
//! mistakes.
//!
//! # Its own port, deliberately not the held set's
//!
//! [`HeldSetUseCase`](crate::use_cases::held_set_use_case::HeldSetUseCase)
//! asks a different question over a different population — the slice the
//! release gate holds pending a signature, with a resolved policy and a
//! quarantine predicate behind it. This one reads every live row with no
//! policy resolution at all. The two field names
//! `artifact_count` / `distinct_content_count` are shared, because a
//! second vocabulary for one pair of numbers is a defect; the port and
//! the query are not.
//!
//! # Read-only
//!
//! No event, no state transition, no delete. Nothing here decides
//! anything about an artifact.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use hort_domain::events::ApiActor;
use hort_domain::ports::repository_inventory_reader::{
    RepositoryInventory, RepositoryInventoryReader,
};

use crate::error::{AppError, AppResult};
use crate::use_cases::CallerPrivileges;

/// The readout, with the instant it was measured at.
///
/// `measured_at` is carried rather than left to the renderer because the
/// whole point of this surface is comparing two readings: an operator
/// holding a before and an after has to know which instants they are
/// comparing, and a timestamp the caller pins is the one thing the
/// response cannot reconstruct later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogInventory {
    pub measured_at: DateTime<Utc>,
    /// One entry per repository, including the ones holding nothing.
    ///
    /// A repository with an empty catalog is reported with zeros rather
    /// than omitted: "this repository is now empty" is the *result* a
    /// retention before/after is looking for, and an absent entry cannot
    /// be told apart from a repository the readout never saw. This is
    /// the opposite choice from the held-set overview, which omits an
    /// empty `(repository, bucket)` cell — there the population is a
    /// slice that is normally empty and the cross-product would be
    /// mostly noise, here it is the catalog itself and every
    /// operator-declared repository has a place in it.
    pub repositories: Vec<RepositoryInventory>,
}

/// Application use case behind `GET /api/v1/admin/inventory`.
pub struct RepositoryInventoryUseCase {
    reader: Arc<dyn RepositoryInventoryReader>,
}

impl RepositoryInventoryUseCase {
    pub fn new(reader: Arc<dyn RepositoryInventoryReader>) -> Self {
        Self { reader }
    }

    /// Every repository's three numbers, measured at `now`.
    ///
    /// Admin-only — the existing admin gate, no new `Permission`. The
    /// readout spans every repository in the installation, so a
    /// per-repository authority would have to answer a different
    /// question (the caller's repositories) and this one is the
    /// installation-wide inventory. Non-admin callers are denied before
    /// the port is read; the HTTP edge has already gated through the
    /// `AdminPrincipal` extractor, so this is defence in depth and the
    /// canonical denial-log site for non-HTTP callers.
    ///
    /// `now` is supplied by the caller so the instant in the response is
    /// the instant the caller is attributing the reading to.
    #[tracing::instrument(skip(self, privileges))]
    pub async fn inventory(
        &self,
        actor: ApiActor,
        privileges: CallerPrivileges,
        now: DateTime<Utc>,
    ) -> AppResult<CatalogInventory> {
        // 1) Privilege gate. A denial is an audit fact rather than an
        //    error — `info!` then propagate (Observability rule), and
        //    the port is never reached.
        if let Err(e) = privileges.require_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                outcome = "denied",
                "repository inventory denied: not admin"
            );
            return Err(e);
        }

        // 2) One set-based aggregate. Not a per-repository loop: the
        //    question is global, and N round-trips would answer it N
        //    instants apart.
        let repositories = self.reader.inventory().await.map_err(AppError::Domain)?;

        // 3) A routine aggregate read that changes nothing and
        //    enumerates no artifact — `debug!`, not `info!`
        //    (Observability rule: reserve `info!` for state changes and
        //    security-relevant decisions; the denial above is the
        //    audited one).
        tracing::debug!(
            repository_count = repositories.len(),
            "admin read the repository inventory"
        );

        Ok(CatalogInventory {
            measured_at: now,
            repositories,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::BoxFuture;
    use uuid::Uuid;

    /// Recording double for the one port. Serves what it is seeded with
    /// and counts the calls, which is what the denial assertions stand
    /// on. It round-trips nothing — there is no stream here — so the
    /// validity rule for round-tripping doubles does not apply.
    struct MockInventoryReader {
        result: Mutex<DomainResult<Vec<RepositoryInventory>>>,
        calls: Mutex<usize>,
    }

    impl MockInventoryReader {
        fn new(result: DomainResult<Vec<RepositoryInventory>>) -> Self {
            Self {
                result: Mutex::new(result),
                calls: Mutex::new(0),
            }
        }

        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl RepositoryInventoryReader for MockInventoryReader {
        fn inventory(&self) -> BoxFuture<'_, DomainResult<Vec<RepositoryInventory>>> {
            *self.calls.lock().unwrap() += 1;
            let result = match &*self.result.lock().unwrap() {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(e.clone()),
            };
            Box::pin(async move { result })
        }
    }

    fn admin() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: true,
            is_reviewer: false,
            is_curator: false,
            writable_repository_ids: Vec::new(),
        }
    }

    fn not_admin() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: false,
            // A curator is the authority over the held set, and
            // deliberately not over this installation-wide readout.
            is_curator: true,
            is_reviewer: true,
            writable_repository_ids: Vec::new(),
        }
    }

    fn actor() -> ApiActor {
        ApiActor {
            user_id: Uuid::new_v4(),
        }
    }

    fn row(key: &str, rows: u64, contents: u64, bytes: u64) -> RepositoryInventory {
        RepositoryInventory {
            repository_id: Uuid::new_v4(),
            repository_key: key.into(),
            artifact_count: rows,
            distinct_content_count: contents,
            live_primary_content_bytes: bytes,
        }
    }

    fn use_case(
        result: DomainResult<Vec<RepositoryInventory>>,
    ) -> (RepositoryInventoryUseCase, Arc<MockInventoryReader>) {
        let reader = Arc::new(MockInventoryReader::new(result));
        let uc =
            RepositoryInventoryUseCase::new(reader.clone() as Arc<dyn RepositoryInventoryReader>);
        (uc, reader)
    }

    /// The happy path hands back exactly what the port served, with the
    /// caller's instant stamped on it.
    #[tokio::test]
    async fn inventory_returns_every_repository_at_the_callers_instant() {
        let now = Utc::now();
        let (uc, reader) = use_case(Ok(vec![
            row("oci-main", 3_647, 3_608, 142_000),
            row("npm-proxy", 12, 12, 400),
        ]));

        let out = uc
            .inventory(actor(), admin(), now)
            .await
            .expect("inventory");

        assert_eq!(
            out.measured_at, now,
            "the response stamps the caller's instant"
        );
        assert_eq!(out.repositories.len(), 2);
        assert_eq!(out.repositories[0].repository_key, "oci-main");
        assert_eq!(out.repositories[0].artifact_count, 3_647);
        assert_eq!(out.repositories[0].distinct_content_count, 3_608);
        assert_eq!(out.repositories[0].live_primary_content_bytes, 142_000);
        assert_eq!(reader.calls(), 1, "one set-based aggregate, not a loop");
    }

    /// A repository holding nothing survives as zeros. Dropping it would
    /// make "retention emptied this repository" indistinguishable from
    /// "the readout does not know about this repository".
    #[tokio::test]
    async fn an_empty_repository_is_reported_as_zeros_not_omitted() {
        let (uc, _) = use_case(Ok(vec![row("drained", 0, 0, 0)]));

        let out = uc
            .inventory(actor(), admin(), Utc::now())
            .await
            .expect("inventory");

        assert_eq!(out.repositories.len(), 1);
        assert_eq!(out.repositories[0].artifact_count, 0);
        assert_eq!(out.repositories[0].distinct_content_count, 0);
        assert_eq!(out.repositories[0].live_primary_content_bytes, 0);
    }

    /// An installation with no repositories at all is an empty list and
    /// not an error.
    #[tokio::test]
    async fn an_installation_with_no_repositories_is_an_empty_list() {
        let (uc, _) = use_case(Ok(Vec::new()));

        let out = uc
            .inventory(actor(), admin(), Utc::now())
            .await
            .expect("inventory");

        assert!(out.repositories.is_empty());
    }

    /// A non-admin is refused, and the port is never reached — the
    /// denial happens before any database work.
    #[tokio::test]
    async fn a_non_admin_is_forbidden_and_the_port_is_not_read() {
        let (uc, reader) = use_case(Ok(vec![row("oci-main", 1, 1, 1)]));

        let err = uc
            .inventory(actor(), not_admin(), Utc::now())
            .await
            .expect_err("denied");

        match err {
            AppError::Domain(DomainError::Forbidden(msg)) => {
                assert!(msg.contains("admin"), "{msg}");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
        assert_eq!(reader.calls(), 0, "a denial must not reach the port");
    }

    /// An infrastructure failure propagates. An inventory that answers
    /// "every repository is empty" because the database is down is the
    /// worst available answer for a before/after measurement.
    #[tokio::test]
    async fn a_port_failure_propagates_rather_than_reading_as_an_empty_catalog() {
        let (uc, _) = use_case(Err(DomainError::Invariant("db down".into())));

        let err = uc
            .inventory(actor(), admin(), Utc::now())
            .await
            .expect_err("propagated");

        match err {
            AppError::Domain(DomainError::Invariant(msg)) => assert_eq!(msg, "db down"),
            other => panic!("expected the port's own error, got {other:?}"),
        }
    }
}
