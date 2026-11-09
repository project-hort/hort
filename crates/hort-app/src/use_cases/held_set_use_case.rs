//! `HeldSetUseCase` — the operator-facing surface over the set the
//! release gate holds pending a signature.
//!
//! ADR 0039 D4 declines to put a deadline on an unsigned hold. It argues
//! that on one ground: an operator can see the held set *and its age*,
//! on the admin curation queue and on "retention's overview, where
//! disposal is operator-confirmed and never decided automatically".
//! This use case is that overview. An indefinite hold nobody can see is
//! the thing that argument is not allowed to rest on.
//!
//! # The category
//!
//! An artifact is a held-pending-signature candidate when all four hold:
//!
//! 1. `quarantine_status = 'quarantined'`;
//! 2. the quarantine window has **expired** — `quarantine_window_start +
//!    effective duration < now`, the duration resolved with the same
//!    precedence the curation queue uses (the repository's own
//!    non-archived policy before the global one). **No resolvable policy
//!    means no deadline, so the row is not in the category**;
//! 3. the effective `provenance_mode` is `Required`;
//! 4. there is **no** `ProvenanceVerified` on `artifact-<id>`.
//!
//! # Two precisions, and each wears its own name
//!
//! [`release_clearance`](crate::use_cases::release_clearance) exists
//! because two independent provenance computations drifted, and the
//! drift was found as a HIGH finding. An SQL re-implementation of the
//! release conjunct would be that second computation. So the two reads
//! here are deliberately different kinds of answer:
//!
//! - [`HeldSetUseCase::overview`] is a **declared superset**: the
//!   adapter resolves conditions 1–3 in SQL and stops. Condition 4 is
//!   the clearance verdict, and the aggregate does not evaluate it — one
//!   query, no per-row event read. So the count is named
//!   `held_pending_signature_candidates` everywhere it appears, and
//!   never "artifacts the gate is holding".
//! - [`HeldSetUseCase::list_held`] is exact per row: every row the
//!   adapter returns is re-decided here through
//!   [`provenance_clearance_from`] — the one source — over the
//!   artifact's own stream and the mode resolved by the one shared
//!   policy resolver. A row the authority clears is dropped from the
//!   page.
//!
//! One authority per artifact stays true; the count is an honestly named
//! approximation of it.
//!
//! # What this use case does not do
//!
//! It is **read-only over the artifact set**. No `DELETE`, no state
//! transition, no event. Disposal of a held artifact is
//! operator-confirmed (propose → confirm → execute) and is not part of
//! this surface. It also emits no metric: the overview is the surface,
//! not the gauge (ADR 0039 D4 — a gauge, if one ever follows, is a
//! trigger and not an authority).
//!
//! The GC protection of invariant 1 (ADR 0007) is untouched. This is a
//! new read path with its own port and its own query, deliberately not a
//! widening of the retention candidate query: one code path for the
//! GC protection and the overview means the first change that wants one
//! silently gets the other.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::ProvenanceClearance;
use hort_domain::entities::scan_policy::ProvenanceMode;
use hort_domain::error::DomainError;
use hort_domain::events::{ApiActor, StreamId};
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::held_set_reader::{
    ConstituentKindSets, HeldBucket, HeldCandidateBucket, HeldCandidateQuery, HeldCandidateRow,
    HeldSetReader,
};
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;

use crate::error::{AppError, AppResult};
use crate::use_cases::policy_resolution::resolve_active_policy_for_repo;
use crate::use_cases::referenced_descendant::{PARENT_GATE_BLOB_KINDS, SELF_REFERENTIAL_KINDS};
use crate::use_cases::release_clearance::provenance_clearance_from;
use crate::use_cases::{read_artifact_stream, CallerPrivileges};

/// Maximum `limit` accepted by [`HeldSetUseCase::list_held`].
///
/// **This view's own named bound.** Deliberately not a constant called
/// `MAX_LIST_LIMIT`: the workspace has two of that name with different
/// values (1000 in `ref_use_case`, 500 in `security_score_use_case`) and
/// a third in the curation handlers, so the name says nothing about
/// which bound a reader is looking at.
///
/// One definition, three consumers, each doing its own job: this use
/// case **refuses** an oversize value, the HTTP handler refuses it at the
/// boundary before any database work, and the Postgres adapter clamps to
/// it defensively so a use-case bypass cannot drag the database through
/// a 10k-row scan. A refusal rather than a silent clamp, matching the
/// curation queue: a clamp returns fewer rows than the caller asked for
/// and tells them nothing.
pub const MAX_HELD_PAGE_LIMIT: u32 = 500;

/// Default page size when the caller names none.
pub const DEFAULT_HELD_PAGE_LIMIT: u32 = 100;

/// The bucket rule's kind lists, as the one Rust definition spells them.
///
/// The adapter binds these as `text[]` query parameters and forms only
/// the boolean from them, so the rule is not re-implemented in SQL.
fn bucket_kind_sets() -> ConstituentKindSets<'static> {
    ConstituentKindSets {
        blob_kinds: &PARENT_GATE_BLOB_KINDS,
        self_referential_kinds: &SELF_REFERENTIAL_KINDS,
    }
}

/// The aggregate, with the instant it was measured at.
///
/// `measured_at` is what every age in `buckets` is relative to, and it is
/// carried rather than left to the renderer so the whole response
/// describes one instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldSetOverview {
    pub measured_at: DateTime<Utc>,
    /// One cell per `(repository, bucket)`. A cell with no rows is
    /// absent rather than zero-valued — the aggregate reports what is
    /// held, not the cross-product of every repository and bucket.
    pub buckets: Vec<HeldCandidateBucket>,
}

/// One drill-down request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldListRequest {
    /// Which half of the held set. Required — the two halves are
    /// different operator tasks.
    pub bucket: HeldBucket,
    pub repository_id: Option<Uuid>,
    /// Keyset cursor: the `next_cursor` of the previous page.
    pub after: Option<Uuid>,
    pub limit: u32,
}

impl Default for HeldListRequest {
    fn default() -> Self {
        Self {
            bucket: HeldBucket::InOwnRight,
            repository_id: None,
            after: None,
            limit: DEFAULT_HELD_PAGE_LIMIT,
        }
    }
}

/// One page of the drill-down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldSetPage {
    pub measured_at: DateTime<Utc>,
    /// The rows that survived the per-row authority. May be shorter than
    /// the page the adapter returned, and may be **empty** while
    /// `next_cursor` is `Some` — a whole page can be dropped.
    pub rows: Vec<HeldCandidateRow>,
    /// Where to resume. `Some` iff the adapter filled the page, so there
    /// may be more; derived from the last row **scanned**, never the last
    /// row kept — resuming from a kept row would re-read every dropped
    /// row behind it forever.
    pub next_cursor: Option<Uuid>,
}

/// Application use case behind `GET /api/v1/admin/retention/overview`
/// and `GET /api/v1/admin/retention/held`.
pub struct HeldSetUseCase {
    reader: Arc<dyn HeldSetReader>,
    events: Arc<dyn EventStore>,
    policy_projections: Arc<dyn PolicyProjectionRepository>,
}

impl HeldSetUseCase {
    pub fn new(
        reader: Arc<dyn HeldSetReader>,
        events: Arc<dyn EventStore>,
        policy_projections: Arc<dyn PolicyProjectionRepository>,
    ) -> Self {
        Self {
            reader,
            events,
            policy_projections,
        }
    }

    /// The aggregate: row count, distinct-content count and oldest age
    /// per `(repository, bucket)`.
    ///
    /// A declared superset — see the module docs. `now` is supplied by
    /// the caller so the window-expiry comparison and every age in the
    /// response describe one instant.
    ///
    /// The gate is `Curate` **or** `Admin`
    /// ([`CallerPrivileges::require_curate_or_admin`]). `Curate` is
    /// already the decision authority over quarantined and rejected
    /// artifacts, which is exactly this set; a separate permission would
    /// cost a DB enum migration, grant upkeep and a token rotation (the
    /// cap is frozen at issuance, ADR 0012) without separating an
    /// authority that should be separate.
    #[tracing::instrument(skip(self, privileges))]
    pub async fn overview(
        &self,
        actor: ApiActor,
        privileges: CallerPrivileges,
        now: DateTime<Utc>,
    ) -> AppResult<HeldSetOverview> {
        // 1) Privilege gate. A denial is an audit fact, not an error —
        //    `info!` then propagate (architect Observability rule).
        if let Err(e) = privileges.require_curate_or_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                outcome = "denied",
                "held-set overview denied: missing curate/admin"
            );
            return Err(e);
        }

        // 2) One query. No per-row event read, which is what keeps this
        //    an aggregate rather than a second computation of the
        //    release conjunct.
        let buckets = self
            .reader
            .aggregate_candidates(now, bucket_kind_sets())
            .await
            .map_err(AppError::Domain)?;

        // 3) Success-side audit log: the surface enumerates artifacts an
        //    operator is about to make a disposal decision about.
        tracing::info!(
            actor_id = %actor.user_id,
            bucket_count = buckets.len(),
            candidate_total = buckets.iter().map(|b| b.artifact_count).sum::<u64>(),
            "curator or admin read the held-pending-signature overview"
        );

        Ok(HeldSetOverview {
            measured_at: now,
            buckets,
        })
    }

    /// The drill-down: one keyset page of held artifacts, each row
    /// re-decided through the one provenance authority.
    ///
    /// A `limit` above [`MAX_HELD_PAGE_LIMIT`] is **refused**
    /// (`DomainError::Validation`), and `limit = 0` with it: a page that
    /// can hold nothing is a request that cannot be answered, and
    /// answering it with an empty page would look like an exhausted set.
    #[tracing::instrument(skip(self, privileges))]
    pub async fn list_held(
        &self,
        actor: ApiActor,
        privileges: CallerPrivileges,
        request: HeldListRequest,
        now: DateTime<Utc>,
    ) -> AppResult<HeldSetPage> {
        // 1) Privilege gate — same authority as the aggregate.
        if let Err(e) = privileges.require_curate_or_admin() {
            tracing::info!(
                actor_id = %actor.user_id,
                bucket = %request.bucket,
                outcome = "denied",
                "held-set drill-down denied: missing curate/admin"
            );
            return Err(e);
        }

        // 2) Validate the limit BEFORE the port call. Refuse, never
        //    clamp — see `MAX_HELD_PAGE_LIMIT`.
        if request.limit == 0 {
            tracing::info!(
                actor_id = %actor.user_id,
                outcome = "invalid",
                "held-set drill-down rejected: limit must be >= 1"
            );
            return Err(AppError::Domain(DomainError::Validation(
                "limit must be >= 1".into(),
            )));
        }
        if request.limit > MAX_HELD_PAGE_LIMIT {
            tracing::info!(
                actor_id = %actor.user_id,
                requested_limit = request.limit,
                max_limit = MAX_HELD_PAGE_LIMIT,
                outcome = "invalid",
                "held-set drill-down rejected: limit exceeds maximum"
            );
            return Err(AppError::Domain(DomainError::Validation(format!(
                "limit {n} exceeds maximum {MAX_HELD_PAGE_LIMIT}",
                n = request.limit
            ))));
        }

        // 3) The superset page.
        let scanned = self
            .reader
            .list_candidates(HeldCandidateQuery {
                now,
                kinds: bucket_kind_sets(),
                bucket: request.bucket,
                repository_id: request.repository_id,
                after: request.after,
                limit: request.limit,
            })
            .await
            .map_err(AppError::Domain)?;

        // The cursor is the last row SCANNED, taken before any row is
        // dropped. A cursor derived from the last row KEPT would make a
        // fully-dropped page non-advancing: the next request would hand
        // back the same cursor and re-read the same rows.
        let page_was_full = scanned.len() as u64 >= u64::from(request.limit);
        let next_cursor = page_was_full
            .then(|| scanned.last().map(|r| r.artifact_id))
            .flatten();

        // 4) Per row: the one authority. The provenance mode comes from
        //    the one shared policy resolver (an absent policy resolves
        //    to the default `VerifyIfPresent`, which is `NotRequired`
        //    and so drops the row), and the verdict from
        //    `provenance_clearance_from` over the artifact's own stream.
        //    Only `Pending` — a `Required` artifact with no
        //    `ProvenanceVerified` — is actually held.
        //
        //    Modes are memoised per repository: the resolver lists the
        //    active projections once per call, and a page can carry many
        //    rows from one repository.
        let mut modes: HashMap<Uuid, ProvenanceMode> = HashMap::new();
        let mut rows = Vec::with_capacity(scanned.len());
        let mut cleared = 0usize;
        for row in scanned {
            let mode = match modes.get(&row.repository_id) {
                Some(mode) => *mode,
                None => {
                    let mode = resolve_active_policy_for_repo(
                        &*self.policy_projections,
                        row.repository_id,
                    )
                    .await?
                    .map_or_else(ProvenanceMode::default, |p| p.provenance_mode);
                    modes.insert(row.repository_id, mode);
                    mode
                }
            };

            // `read_artifact_stream` refuses an over-cap stream rather
            // than answering from a truncated prefix, so a stream this
            // read cannot see in full surfaces as an error instead of as
            // a `Pending` that only means "the verification is outside
            // the read window".
            let stream =
                read_artifact_stream(&*self.events, &StreamId::artifact(row.artifact_id)).await?;

            match provenance_clearance_from(&stream, mode) {
                ProvenanceClearance::Pending => rows.push(row),
                ProvenanceClearance::Cleared | ProvenanceClearance::NotRequired => {
                    cleared += 1;
                }
            }
        }

        // 5) Success-side audit log. `dropped` is the aggregate's
        //    overcount made visible at the one place that can measure
        //    it: these are rows the superset counted and the authority
        //    cleared.
        tracing::info!(
            actor_id = %actor.user_id,
            bucket = %request.bucket,
            held = rows.len(),
            dropped = cleared,
            has_more = next_cursor.is_some(),
            "curator or admin read the held-pending-signature drill-down"
        );

        Ok(HeldSetPage {
            measured_at: now,
            rows,
            next_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use chrono::TimeZone;
    use hort_domain::entities::scan_policy::{
        CompositeVerdictMode, NegligibleAction, ScanEnforcement, ScanPolicyProjection,
        SeverityThreshold,
    };
    use hort_domain::error::DomainResult;
    use hort_domain::events::{DomainEvent, PersistedEvent, PolicyScope, ProvenanceVerified};
    use hort_domain::ports::provenance::SignerIdentity;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ContentHash;

    use crate::use_cases::test_support::{MockEventStore, MockPolicyProjectionRepository};

    const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0)
            .single()
            .expect("valid timestamp")
    }

    // -- the reader mock ----------------------------------------------------

    /// Recording mock for [`HeldSetReader`].
    ///
    /// Records the kind sets it was handed, so the tests can assert the
    /// use case passes the one Rust definition down rather than letting
    /// the adapter invent one.
    struct MockHeldSetReader {
        aggregate_result: Mutex<DomainResult<Vec<HeldCandidateBucket>>>,
        page_result: Mutex<DomainResult<Vec<HeldCandidateRow>>>,
        recorded_kinds: Mutex<Vec<(Vec<String>, Vec<String>)>>,
        recorded_queries: Mutex<Vec<RecordedQuery>>,
    }

    /// What one `list_candidates` call asked for. A named record rather
    /// than a tuple so an assertion says which field it checks.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedQuery {
        bucket: HeldBucket,
        repository_id: Option<Uuid>,
        after: Option<Uuid>,
        limit: u32,
    }

    impl MockHeldSetReader {
        fn new() -> Self {
            Self {
                aggregate_result: Mutex::new(Ok(Vec::new())),
                page_result: Mutex::new(Ok(Vec::new())),
                recorded_kinds: Mutex::new(Vec::new()),
                recorded_queries: Mutex::new(Vec::new()),
            }
        }

        fn set_aggregate(&self, r: DomainResult<Vec<HeldCandidateBucket>>) {
            *self.aggregate_result.lock().expect("lock") = r;
        }

        fn set_page(&self, r: DomainResult<Vec<HeldCandidateRow>>) {
            *self.page_result.lock().expect("lock") = r;
        }

        fn recorded_kinds(&self) -> Vec<(Vec<String>, Vec<String>)> {
            self.recorded_kinds.lock().expect("lock").clone()
        }

        fn recorded_queries(&self) -> Vec<RecordedQuery> {
            self.recorded_queries.lock().expect("lock").clone()
        }

        fn record_kinds(&self, kinds: ConstituentKindSets<'_>) {
            self.recorded_kinds.lock().expect("lock").push((
                kinds.blob_kinds.iter().map(|k| (*k).to_string()).collect(),
                kinds
                    .self_referential_kinds
                    .iter()
                    .map(|k| (*k).to_string())
                    .collect(),
            ));
        }
    }

    impl HeldSetReader for MockHeldSetReader {
        fn aggregate_candidates<'a>(
            &'a self,
            _now: DateTime<Utc>,
            kinds: ConstituentKindSets<'a>,
        ) -> BoxFuture<'a, DomainResult<Vec<HeldCandidateBucket>>> {
            self.record_kinds(kinds);
            let out = match &*self.aggregate_result.lock().expect("lock") {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(e.clone()),
            };
            Box::pin(async move { out })
        }

        fn list_candidates<'a>(
            &'a self,
            query: HeldCandidateQuery<'a>,
        ) -> BoxFuture<'a, DomainResult<Vec<HeldCandidateRow>>> {
            self.record_kinds(query.kinds);
            self.recorded_queries
                .lock()
                .expect("lock")
                .push(RecordedQuery {
                    bucket: query.bucket,
                    repository_id: query.repository_id,
                    after: query.after,
                    limit: query.limit,
                });
            let out = match &*self.page_result.lock().expect("lock") {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(e.clone()),
            };
            Box::pin(async move { out })
        }
    }

    // -- fixtures -----------------------------------------------------------

    fn curator() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: false,
            is_reviewer: false,
            is_curator: true,
            writable_repository_ids: Vec::new(),
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

    fn nobody() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: false,
            is_reviewer: false,
            is_curator: false,
            writable_repository_ids: Vec::new(),
        }
    }

    fn actor() -> ApiActor {
        ApiActor {
            user_id: Uuid::new_v4(),
        }
    }

    fn bucket(repo: Uuid) -> HeldCandidateBucket {
        HeldCandidateBucket {
            repository_id: repo,
            repository_key: "oci-main".into(),
            bucket: HeldBucket::Constituent,
            artifact_count: 3_647,
            distinct_content_count: 3_608,
            oldest_held_since: at(0),
        }
    }

    fn row(repo: Uuid, artifact_id: Uuid) -> HeldCandidateRow {
        HeldCandidateRow {
            artifact_id,
            repository_id: repo,
            repository_key: "oci-main".into(),
            name: "library/nginx".into(),
            version: None,
            path: "library/nginx/blobs/sha256:dead".into(),
            content_hash: VALID_SHA256.into(),
            bucket: HeldBucket::InOwnRight,
            held_since: at(0),
        }
    }

    fn policy(scope: PolicyScope, mode: ProvenanceMode) -> ScanPolicyProjection {
        ScanPolicyProjection {
            policy_id: Uuid::new_v4(),
            name: format!("p-{}", Uuid::new_v4()),
            scope,
            severity_threshold: SeverityThreshold::Critical,
            quarantine_duration_secs: 3600,
            require_approval: false,
            provenance_mode: mode,
            provenance_backends: vec!["cosign".into()],
            provenance_identities: Vec::new(),
            max_artifact_age_secs: None,
            license_policy: serde_json::Value::Null,
            archived: false,
            scan_backends: vec!["trivy".into()],
            rescan_interval_hours: 24,
            negligible_action: NegligibleAction::Ignore,
            enforcement: ScanEnforcement::Reject,
            composite_verdict_mode: CompositeVerdictMode::Observed,
            stream_version: 0,
            created_at: at(0),
            updated_at: at(0),
        }
    }

    fn verified_event(artifact_id: Uuid) -> PersistedEvent {
        let hash: ContentHash = VALID_SHA256.parse().expect("valid sha256");
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId::artifact(artifact_id),
            stream_position: 1,
            global_position: 1,
            event: DomainEvent::ProvenanceVerified(ProvenanceVerified {
                artifact_id,
                content_hash: hash,
                backend: "cosign".into(),
                signer: SignerIdentity {
                    issuer: "https://token.actions.githubusercontent.com".into(),
                    san: "https://github.com/acme/repo/.github/workflows/release.yml".into(),
                },
                predicate_type: None,
                cascaded_from: None,
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: hort_domain::events::system_actor(),
            event_version: 1,
            stored_at: at(0),
        }
    }

    struct Harness {
        uc: HeldSetUseCase,
        reader: Arc<MockHeldSetReader>,
        events: Arc<MockEventStore>,
        policies: Arc<MockPolicyProjectionRepository>,
    }

    fn harness() -> Harness {
        let reader = Arc::new(MockHeldSetReader::new());
        let events = Arc::new(MockEventStore::new());
        let policies = Arc::new(MockPolicyProjectionRepository::new());
        let uc = HeldSetUseCase::new(
            reader.clone() as Arc<dyn HeldSetReader>,
            events.clone() as Arc<dyn EventStore>,
            policies.clone() as Arc<dyn PolicyProjectionRepository>,
        );
        Harness {
            uc,
            reader,
            events,
            policies,
        }
    }

    // -- the aggregate ------------------------------------------------------

    #[tokio::test]
    async fn overview_denies_a_caller_with_neither_permission() {
        let h = harness();
        let err =
            h.uc.overview(actor(), nobody(), at(10))
                .await
                .expect_err("denied");
        assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
        assert!(
            h.reader.recorded_kinds().is_empty(),
            "a denied caller must not reach the port"
        );
    }

    #[tokio::test]
    async fn overview_admits_a_curator_and_an_admin() {
        for privileges in [curator(), admin()] {
            let h = harness();
            h.reader.set_aggregate(Ok(vec![bucket(Uuid::new_v4())]));
            let out =
                h.uc.overview(actor(), privileges, at(10))
                    .await
                    .expect("allowed");
            assert_eq!(out.buckets.len(), 1);
        }
    }

    /// Rows are not bytes (ADR 0054): the aggregate carries both counts,
    /// and the pair really can differ — these are the numbers the first
    /// real retention dry run produced.
    #[tokio::test]
    async fn overview_reports_rows_and_distinct_contents_separately() {
        let h = harness();
        h.reader.set_aggregate(Ok(vec![bucket(Uuid::new_v4())]));
        let out =
            h.uc.overview(actor(), curator(), at(10))
                .await
                .expect("allowed");
        assert_eq!(out.buckets[0].artifact_count, 3_647);
        assert_eq!(out.buckets[0].distinct_content_count, 3_608);
        assert!(out.buckets[0].distinct_content_count < out.buckets[0].artifact_count);
    }

    /// `measured_at` is the caller's instant, and the ages in the
    /// response are relative to it.
    #[tokio::test]
    async fn overview_carries_the_measurement_instant_for_the_ages() {
        let h = harness();
        h.reader.set_aggregate(Ok(vec![bucket(Uuid::new_v4())]));
        let out =
            h.uc.overview(actor(), curator(), at(600))
                .await
                .expect("allowed");
        assert_eq!(out.measured_at, at(600));
        assert_eq!(out.buckets[0].oldest_age_secs(out.measured_at), 600);
    }

    /// An empty held set is an empty bucket list, not a row of zeroes.
    #[tokio::test]
    async fn overview_of_an_empty_held_set_is_empty() {
        let h = harness();
        let out =
            h.uc.overview(actor(), curator(), at(10))
                .await
                .expect("allowed");
        assert!(out.buckets.is_empty());
    }

    /// The use case hands the port the ONE Rust definition of the bucket
    /// rule's kind lists. If this ever stops being true the adapter is
    /// deciding the split from a list of its own.
    #[tokio::test]
    async fn overview_passes_the_single_sourced_kind_lists_to_the_port() {
        let h = harness();
        h.uc.overview(actor(), curator(), at(10))
            .await
            .expect("allowed");
        let recorded = h.reader.recorded_kinds();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, PARENT_GATE_BLOB_KINDS.to_vec());
        assert_eq!(recorded[0].1, SELF_REFERENTIAL_KINDS.to_vec());
    }

    #[tokio::test]
    async fn overview_propagates_a_port_error() {
        let h = harness();
        h.reader
            .set_aggregate(Err(DomainError::Invariant("db down".into())));
        let err =
            h.uc.overview(actor(), curator(), at(10))
                .await
                .expect_err("propagated");
        assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
    }

    // -- the drill-down -----------------------------------------------------

    #[tokio::test]
    async fn list_denies_a_caller_with_neither_permission() {
        let h = harness();
        let err =
            h.uc.list_held(actor(), nobody(), HeldListRequest::default(), at(10))
                .await
                .expect_err("denied");
        assert!(matches!(err, AppError::Domain(DomainError::Forbidden(_))));
        assert!(h.reader.recorded_queries().is_empty());
    }

    /// Refused, not clamped — and the message names the bound so the
    /// caller learns what to ask for.
    #[tokio::test]
    async fn list_refuses_an_oversize_limit_rather_than_clamping() {
        let h = harness();
        let request = HeldListRequest {
            limit: MAX_HELD_PAGE_LIMIT + 1,
            ..HeldListRequest::default()
        };
        let err =
            h.uc.list_held(actor(), curator(), request, at(10))
                .await
                .expect_err("refused");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(msg.contains(&MAX_HELD_PAGE_LIMIT.to_string()), "{msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        assert!(
            h.reader.recorded_queries().is_empty(),
            "the refusal must land before the port call"
        );
    }

    /// The boundary itself is accepted — the bound is inclusive.
    #[tokio::test]
    async fn list_accepts_the_maximum_limit_exactly() {
        let h = harness();
        let request = HeldListRequest {
            limit: MAX_HELD_PAGE_LIMIT,
            ..HeldListRequest::default()
        };
        h.uc.list_held(actor(), curator(), request, at(10))
            .await
            .expect("accepted");
        assert_eq!(h.reader.recorded_queries()[0].limit, MAX_HELD_PAGE_LIMIT);
    }

    /// `limit = 0` is refused rather than answered: an empty page from a
    /// zero-capacity request is indistinguishable from an exhausted set.
    #[tokio::test]
    async fn list_refuses_a_zero_limit() {
        let h = harness();
        let request = HeldListRequest {
            limit: 0,
            ..HeldListRequest::default()
        };
        let err =
            h.uc.list_held(actor(), curator(), request, at(10))
                .await
                .expect_err("refused");
        match err {
            AppError::Domain(DomainError::Validation(msg)) => {
                assert!(msg.contains(">= 1"), "{msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        assert!(h.reader.recorded_queries().is_empty());
    }

    #[tokio::test]
    async fn list_forwards_the_bucket_repository_and_cursor() {
        let h = harness();
        let repo = Uuid::new_v4();
        let cursor = Uuid::new_v4();
        let request = HeldListRequest {
            bucket: HeldBucket::Constituent,
            repository_id: Some(repo),
            after: Some(cursor),
            limit: 7,
        };
        h.uc.list_held(actor(), curator(), request, at(10))
            .await
            .expect("allowed");
        assert_eq!(
            h.reader.recorded_queries(),
            vec![RecordedQuery {
                bucket: HeldBucket::Constituent,
                repository_id: Some(repo),
                after: Some(cursor),
                limit: 7,
            }]
        );
    }

    /// A `Required` artifact with no `ProvenanceVerified` is genuinely
    /// held, so it survives the per-row authority.
    #[tokio::test]
    async fn list_keeps_a_row_the_authority_finds_pending() {
        let h = harness();
        let repo = Uuid::new_v4();
        let artifact = Uuid::new_v4();
        h.policies.insert(policy(
            PolicyScope::Repository(repo),
            ProvenanceMode::Required,
        ));
        h.reader.set_page(Ok(vec![row(repo, artifact)]));

        let page =
            h.uc.list_held(actor(), curator(), HeldListRequest::default(), at(10))
                .await
                .expect("allowed");
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].artifact_id, artifact);
        assert_eq!(page.rows[0].age_secs(page.measured_at), 10);
    }

    /// **The drop path.** The aggregate is a superset: a row whose
    /// stream already carries a `ProvenanceVerified` is cleared by the
    /// one authority and does not reach the operator's list.
    #[tokio::test]
    async fn list_drops_a_row_whose_stream_carries_provenance_verified() {
        let h = harness();
        let repo = Uuid::new_v4();
        let artifact = Uuid::new_v4();
        h.policies.insert(policy(
            PolicyScope::Repository(repo),
            ProvenanceMode::Required,
        ));
        h.events.set_stream(
            &StreamId::artifact(artifact),
            vec![verified_event(artifact)],
        );
        h.reader.set_page(Ok(vec![row(repo, artifact)]));

        let page =
            h.uc.list_held(actor(), curator(), HeldListRequest::default(), at(10))
                .await
                .expect("allowed");
        assert!(
            page.rows.is_empty(),
            "a cleared artifact is not held: {:?}",
            page.rows
        );
    }

    /// The other half of the conjunct, re-decided here rather than
    /// trusted from SQL: a repository whose effective mode is not
    /// `Required` has no provenance gate, so its rows are not held.
    #[tokio::test]
    async fn list_drops_a_row_whose_effective_mode_is_not_required() {
        for mode in [ProvenanceMode::Off, ProvenanceMode::VerifyIfPresent] {
            let h = harness();
            let repo = Uuid::new_v4();
            h.policies
                .insert(policy(PolicyScope::Repository(repo), mode));
            h.reader.set_page(Ok(vec![row(repo, Uuid::new_v4())]));

            let page =
                h.uc.list_held(actor(), curator(), HeldListRequest::default(), at(10))
                    .await
                    .expect("allowed");
            assert!(page.rows.is_empty(), "mode {mode} does not gate release");
        }
    }

    /// No resolvable policy resolves to the default `VerifyIfPresent`,
    /// which never gates release — so the row is dropped rather than
    /// reported as held on a deadline nothing supplied.
    #[tokio::test]
    async fn list_drops_a_row_with_no_resolvable_policy() {
        let h = harness();
        h.reader
            .set_page(Ok(vec![row(Uuid::new_v4(), Uuid::new_v4())]));
        let page =
            h.uc.list_held(actor(), curator(), HeldListRequest::default(), at(10))
                .await
                .expect("allowed");
        assert!(page.rows.is_empty());
    }

    /// The global policy is the fallback, with the same precedence the
    /// curation queue uses: a repository with no policy of its own is
    /// governed by it.
    #[tokio::test]
    async fn list_falls_back_to_the_global_policy() {
        let h = harness();
        let repo = Uuid::new_v4();
        h.policies
            .insert(policy(PolicyScope::Global, ProvenanceMode::Required));
        h.reader.set_page(Ok(vec![row(repo, Uuid::new_v4())]));
        let page =
            h.uc.list_held(actor(), curator(), HeldListRequest::default(), at(10))
                .await
                .expect("allowed");
        assert_eq!(page.rows.len(), 1);
    }

    /// The repository's own non-archived policy beats the global one —
    /// here a repo-scoped `Off` over a global `Required`, so the row is
    /// not held.
    #[tokio::test]
    async fn list_prefers_the_repository_policy_over_the_global_one() {
        let h = harness();
        let repo = Uuid::new_v4();
        h.policies
            .insert(policy(PolicyScope::Global, ProvenanceMode::Required));
        h.policies
            .insert(policy(PolicyScope::Repository(repo), ProvenanceMode::Off));
        h.reader.set_page(Ok(vec![row(repo, Uuid::new_v4())]));
        let page =
            h.uc.list_held(actor(), curator(), HeldListRequest::default(), at(10))
                .await
                .expect("allowed");
        assert!(page.rows.is_empty());
    }

    /// **The empty page.** A page the adapter filled, every row of which
    /// the authority cleared, is empty AND advancing: the cursor comes
    /// from the last row scanned, so the next request makes progress
    /// instead of re-reading the same rows forever.
    #[tokio::test]
    async fn a_fully_dropped_page_is_empty_and_still_advances() {
        let h = harness();
        let repo = Uuid::new_v4();
        let first = Uuid::from_u128(1);
        let last = Uuid::from_u128(2);
        h.policies.insert(policy(
            PolicyScope::Repository(repo),
            ProvenanceMode::Required,
        ));
        for id in [first, last] {
            h.events
                .set_stream(&StreamId::artifact(id), vec![verified_event(id)]);
        }
        h.reader
            .set_page(Ok(vec![row(repo, first), row(repo, last)]));

        let request = HeldListRequest {
            limit: 2,
            ..HeldListRequest::default()
        };
        let page =
            h.uc.list_held(actor(), curator(), request, at(10))
                .await
                .expect("allowed");
        assert!(page.rows.is_empty());
        assert_eq!(
            page.next_cursor,
            Some(last),
            "the cursor must come from the last row SCANNED, not kept"
        );
    }

    /// A short page means the bucket is exhausted — no cursor, so a
    /// caller does not poll a finished scan.
    #[tokio::test]
    async fn a_short_page_reports_no_cursor() {
        let h = harness();
        let repo = Uuid::new_v4();
        h.policies.insert(policy(
            PolicyScope::Repository(repo),
            ProvenanceMode::Required,
        ));
        h.reader.set_page(Ok(vec![row(repo, Uuid::new_v4())]));
        let request = HeldListRequest {
            limit: 10,
            ..HeldListRequest::default()
        };
        let page =
            h.uc.list_held(actor(), curator(), request, at(10))
                .await
                .expect("allowed");
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.next_cursor, None);
    }

    /// An empty page from an empty scan carries no cursor either.
    #[tokio::test]
    async fn an_empty_scan_reports_no_cursor() {
        let h = harness();
        let page =
            h.uc.list_held(actor(), curator(), HeldListRequest::default(), at(10))
                .await
                .expect("allowed");
        assert!(page.rows.is_empty());
        assert_eq!(page.next_cursor, None);
    }

    #[tokio::test]
    async fn list_propagates_a_port_error() {
        let h = harness();
        h.reader
            .set_page(Err(DomainError::Invariant("db down".into())));
        let err =
            h.uc.list_held(actor(), curator(), HeldListRequest::default(), at(10))
                .await
                .expect_err("propagated");
        assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
    }

    /// The per-row stream read resolves one mode per repository, not one
    /// per row: the resolver lists every active projection on each call,
    /// so a page from one repository must not pay for it `limit` times.
    #[tokio::test]
    async fn the_provenance_mode_is_resolved_once_per_repository() {
        let h = harness();
        let repo = Uuid::new_v4();
        h.policies.insert(policy(
            PolicyScope::Repository(repo),
            ProvenanceMode::Required,
        ));
        h.reader.set_page(Ok(vec![
            row(repo, Uuid::from_u128(1)),
            row(repo, Uuid::from_u128(2)),
            row(repo, Uuid::from_u128(3)),
        ]));

        let before = h.policies.list_active_call_count();
        h.uc.list_held(actor(), curator(), HeldListRequest::default(), at(10))
            .await
            .expect("allowed");
        assert_eq!(
            h.policies.list_active_call_count() - before,
            1,
            "three rows from one repository must resolve one policy"
        );
    }
}
