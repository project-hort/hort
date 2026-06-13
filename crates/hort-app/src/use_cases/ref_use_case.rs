//! Mutable-ref write path use case.
//!
//! Orchestrates [`RefRegistryPort`] (read) + [`RefLifecyclePort`] (atomic
//! write). The adapter owns the authoritative idempotence check; the use
//! case's read-then-compare is an optimisation that keeps the fast path
//! free of a transaction round-trip. See
//! `docs/architecture/explanation/domain-model.md` (refs and groups).

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use hort_domain::entities::mutable_ref::{MutableRef, RefTarget};
use hort_domain::error::DomainError;
use hort_domain::events::{Actor, ApiActor, DomainEvent, RefMoved, RefRetired, StreamId};
use hort_domain::ports::event_store::{AppendEvents, EventToAppend, ExpectedVersion};
use hort_domain::ports::ref_lifecycle::{RefCommitOutcome, RefLifecyclePort};
use hort_domain::ports::ref_registry::RefRegistryPort;
use hort_domain::types::StringPage;

use crate::error::AppResult;
use crate::metrics::{emit_ref_moved, values, RefMetricResult};

/// Default `n` when the caller passes `0` (e.g. a client that elides
/// `?n=` entirely). Matches Docker Registry V2 / OCI client defaults.
const DEFAULT_LIST_LIMIT: u32 = 100;
/// Hard ceiling on the per-page limit — mirrors the workspace
/// `PageRequest::MAX_LIMIT`. Exists so a client passing `?n=99999`
/// can't stall the server with an unbounded scan.
const MAX_LIST_LIMIT: u32 = 1000;

/// Application-layer use case for the `MutableRef` write path.
///
/// Three public methods, one per lifecycle transition:
/// - [`set`](Self::set) — create or re-point a ref. No-op on same target.
/// - [`retire`](Self::retire) — delete an existing ref. `NotFound` if missing.
/// - [`get`](Self::get) — read-through lookup. Returns `NotFound` on miss.
///
/// **Idempotence layering.** The use case reads the current target and
/// short-circuits when the new target matches, avoiding the transaction
/// entirely in the common case. The adapter independently re-reads the
/// current target inside the transaction (`SELECT ... FOR UPDATE`) and
/// short-circuits there too — the adapter's check is the authoritative
/// race defence; the use case's check is an optimisation.
pub struct RefUseCase {
    refs: Arc<dyn RefRegistryPort>,
    ref_lifecycle: Arc<dyn RefLifecyclePort>,
    /// Cardinality safety valve mirroring `METRICS_INCLUDE_REPOSITORY_LABEL`.
    /// When false every metric emission sets `repository = "_all"`
    /// ([`values::REPOSITORY_ALL`]). See `docs/metrics-catalog.md` §Sentinel.
    include_repository_label: bool,
}

impl RefUseCase {
    /// Construct the use case.
    ///
    /// `include_repository_label` gates the `repository` label on
    /// `hort_ref_moved_total`. Use cases never resolve repository keys
    /// themselves — the caller (inbound adapter) supplies the pre-
    /// resolved key string to the public methods.
    pub fn new(
        refs: Arc<dyn RefRegistryPort>,
        ref_lifecycle: Arc<dyn RefLifecyclePort>,
        include_repository_label: bool,
    ) -> Self {
        Self {
            refs,
            ref_lifecycle,
            include_repository_label,
        }
    }

    /// Resolve the `repository` metric label.
    ///
    /// Mirrors the sentinel contract in `docs/metrics-catalog.md`:
    /// `_all` when the label is globally disabled, the supplied key
    /// otherwise, falling through to `unknown` when the caller could not
    /// resolve one.
    fn repo_label(&self, repo_key: Option<&str>) -> String {
        if !self.include_repository_label {
            values::REPOSITORY_ALL.to_string()
        } else {
            repo_key.unwrap_or(values::REPOSITORY_UNKNOWN).to_string()
        }
    }

    /// Create or re-point a ref to `target`.
    ///
    /// On a brand-new ref: generates a fresh `ref_id`, appends
    /// `RefMoved { from: None, to: target }` on a new `ref-<id>`
    /// stream, and writes the projection row. Emits
    /// `hort_ref_moved_total{result="created"}`.
    ///
    /// On an existing ref with a different target: appends
    /// `RefMoved { from: Some(prior), to: target }` on the existing
    /// stream and updates the projection. Emits
    /// `hort_ref_moved_total{result="moved"}`.
    ///
    /// On an existing ref with the same target: returns `Ok(())`
    /// WITHOUT invoking the lifecycle port. Emits
    /// `hort_ref_moved_total{result="no_op"}`.
    ///
    /// **Concurrent first-placement retry.** If the first-attempt
    /// lifecycle call returns
    /// [`RefCommitOutcome::RefAlreadyExists`] — another writer
    /// created this ref between our read and our adapter call — we
    /// retry ONCE. The second attempt sees the winner's row and
    /// dispatches as a move, so it cannot hit the same race again.
    /// A second `RefAlreadyExists` is an adapter contract violation
    /// and surfaces as [`DomainError::Invariant`].
    ///
    /// The adapter's in-transaction `FOR UPDATE` re-read is the
    /// authoritative same-target idempotence guard — the use-case
    /// check is an optimisation that avoids a transaction round-trip
    /// on the happy path.
    ///
    /// `repo_key` is used only for the metric label; pass `None` if the
    /// caller has not resolved the key (the metric emits
    /// `repository="unknown"`).
    #[tracing::instrument(skip(self, repo_key))]
    pub async fn set(
        &self,
        repo: Uuid,
        namespace: &str,
        ref_name: &str,
        target: RefTarget,
        actor: ApiActor,
        repo_key: Option<&str>,
    ) -> AppResult<()> {
        // Attempt 1 — may observe a concurrent create race.
        match self
            .try_set(
                repo,
                namespace,
                ref_name,
                target.clone(),
                actor.clone(),
                repo_key,
            )
            .await?
        {
            RefCommitOutcome::Committed => Ok(()),
            RefCommitOutcome::RefAlreadyExists { existing_id } => {
                tracing::debug!(
                    %existing_id,
                    reason = "ref_already_exists",
                    retry = 1,
                    "retrying ref set after concurrent create"
                );
                // Attempt 2 — re-reads the winner's row and dispatches
                // as a move. Second RefAlreadyExists would mean the
                // adapter contract is broken.
                match self
                    .try_set(repo, namespace, ref_name, target, actor, repo_key)
                    .await?
                {
                    RefCommitOutcome::Committed => Ok(()),
                    RefCommitOutcome::RefAlreadyExists { .. } => Err(DomainError::Invariant(
                        "adapter contract broken: second attempt returned RefAlreadyExists".into(),
                    )
                    .into()),
                }
            }
        }
    }

    /// Single-attempt implementation of [`set`](Self::set): read the
    /// current ref (if any), decide create vs move vs no-op, dispatch
    /// once. Returns the raw [`RefCommitOutcome`] so [`set`] can
    /// decide whether to retry.
    async fn try_set(
        &self,
        repo: Uuid,
        namespace: &str,
        ref_name: &str,
        target: RefTarget,
        actor: ApiActor,
        repo_key: Option<&str>,
    ) -> AppResult<RefCommitOutcome> {
        // Read-side lookup. A NotFound on `find` means the ref doesn't
        // exist yet (first-placement path); any other error surfaces.
        let current = match self.refs.find(repo, namespace, ref_name).await {
            Ok(r) => Some(r),
            Err(DomainError::NotFound { .. }) => None,
            Err(e) => return Err(e.into()),
        };

        let repo_label = self.repo_label(repo_key);

        // No-op short-circuit — use case-level optimisation. Adapter's
        // FOR UPDATE re-read is the authoritative race defence; missing
        // this short-circuit is a perf regression, not a correctness bug.
        if let Some(ref c) = current {
            if c.target == target {
                tracing::debug!(
                    ref_id = %c.id,
                    namespace = %namespace,
                    ref_name = %ref_name,
                    reason = "same_target",
                    "set: no-op short-circuit"
                );
                emit_ref_moved(&repo_label, RefMetricResult::NoOp);
                return Ok(RefCommitOutcome::Committed);
            }
        }

        // Choose `ref_id`: reuse the existing row's id (ensures the
        // same stream carries the whole history) or mint a fresh one on
        // first placement.
        let (ref_id, from, expected_version, result_label, created_at) = match &current {
            Some(c) => (
                c.id,
                Some(c.target.clone()),
                // The adapter's `FOR UPDATE` serialises concurrent moves
                // on the same row, so `Any` at the event-store layer is
                // safe — same-ref concurrent appenders are forced to wait
                // for the row lock and the loser sees the winner's new
                // target on re-read.
                ExpectedVersion::Any,
                RefMetricResult::Moved,
                c.created_at,
            ),
            None => (
                Uuid::new_v4(),
                None,
                ExpectedVersion::NoStream,
                RefMetricResult::Created,
                Utc::now(),
            ),
        };

        let now = Utc::now();
        let new_ref = MutableRef {
            id: ref_id,
            repository_id: repo,
            namespace: namespace.to_string(),
            ref_name: ref_name.to_string(),
            target: target.clone(),
            created_at,
            updated_at: now,
        };

        let moved = RefMoved {
            ref_id,
            repository_id: repo,
            namespace: namespace.to_string(),
            ref_name: ref_name.to_string(),
            from,
            to: target,
        };

        let batch = AppendEvents {
            stream_id: StreamId::ref_(ref_id),
            expected_version,
            events: vec![EventToAppend::new(DomainEvent::RefMoved(moved))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(actor),
        };

        let outcome = self.ref_lifecycle.move_ref(new_ref, batch).await?;

        // Only emit the success metric on Committed. On the race-lost
        // path the caller (`set`) retries and the retry fires the
        // metric with the terminal result.
        if matches!(outcome, RefCommitOutcome::Committed) {
            emit_ref_moved(&repo_label, result_label);
            tracing::info!(
                %ref_id,
                namespace,
                ref_name,
                "ref set"
            );
        }
        Ok(outcome)
    }

    /// Retire (delete) an existing ref.
    ///
    /// Reads the current target, builds `RefRetired { last_target }`,
    /// and delegates to the adapter. The adapter deletes the projection
    /// row and appends the event in a single transaction; if no row
    /// exists it returns [`DomainError::NotFound`] without touching the
    /// event log. Emits `hort_ref_moved_total{result="retired"}`.
    ///
    /// When no row exists, this method propagates the `NotFound` from
    /// the read-side `find` and never reaches the lifecycle port —
    /// caller sees a single domain error without the adapter having to
    /// abort a transaction for every misdirected retire.
    #[tracing::instrument(skip(self, repo_key))]
    pub async fn retire(
        &self,
        repo: Uuid,
        namespace: &str,
        ref_name: &str,
        actor: ApiActor,
        repo_key: Option<&str>,
    ) -> AppResult<()> {
        // Read-through: propagate NotFound without reaching the adapter.
        let current = self.refs.find(repo, namespace, ref_name).await?;

        let retired = RefRetired {
            ref_id: current.id,
            repository_id: repo,
            namespace: namespace.to_string(),
            ref_name: ref_name.to_string(),
            last_target: current.target,
        };

        let batch = AppendEvents {
            stream_id: StreamId::ref_(current.id),
            expected_version: ExpectedVersion::Any,
            events: vec![EventToAppend::new(DomainEvent::RefRetired(retired))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(actor),
        };

        self.ref_lifecycle
            .retire_ref(repo, namespace, ref_name, batch)
            .await?;

        let repo_label = self.repo_label(repo_key);
        emit_ref_moved(&repo_label, RefMetricResult::Retired);
        tracing::info!(
            ref_id = %current.id,
            namespace = %namespace,
            ref_name = %ref_name,
            "ref retired"
        );
        Ok(())
    }

    /// Read-through lookup. Returns
    /// [`DomainError::NotFound`](hort_domain::error::DomainError::NotFound)
    /// with `entity = "MutableRef"` when no row exists for the triple.
    #[tracing::instrument(skip(self))]
    pub async fn get(&self, repo: Uuid, namespace: &str, ref_name: &str) -> AppResult<MutableRef> {
        let r = self.refs.find(repo, namespace, ref_name).await?;
        Ok(r)
    }

    /// Paginated enumeration of refs in `(repo, namespace)` for cursor
    /// walks (OCI `/v2/<name>/tags/list`, npm dist-tag enumeration,
    /// Maven `release` / `latest` pointer listings).
    ///
    /// `after` is a `ref_name` cursor — returned rows have
    /// `ref_name > after` under byte ordering. `None` means "from the
    /// start". `n` is clamped to `[1, 1000]`; `0` substitutes the
    /// [`DEFAULT_LIST_LIMIT`] (100) so URL shapes like `?n=` with an
    /// empty value fall through to the default.
    ///
    /// Ordering is byte-stable (`COLLATE "C"` in the Postgres adapter)
    /// so the cursor walk is commutative with concurrent inserts: a
    /// ref added during pagination either sorts before `after` (it
    /// was skipped — fine, it was already unreachable via this cursor
    /// walk) or after (it shows up on a later page). Locale-aware
    /// sort would invalidate both invariants.
    ///
    /// **Port contract.** `RefRegistryPort::list` returns every ref
    /// in `(repo, namespace)` — the port does NOT paginate
    /// (the set is bounded by spec in practice: dozens of tags per
    /// image is typical). If a
    /// format breaks the bound, add a paginated variant to the port;
    /// do not work around it here. Today the use case sorts +
    /// filters + over-fetches `n + 1` client-side.
    #[tracing::instrument(skip(self))]
    pub async fn list(
        &self,
        repo: Uuid,
        namespace: &str,
        after: Option<&str>,
        n: u32,
    ) -> AppResult<StringPage<MutableRef>> {
        let limit = effective_limit(n);
        let mut all = self.refs.list(repo, namespace).await?;
        all.sort_by(|a, b| a.ref_name.as_bytes().cmp(b.ref_name.as_bytes()));

        let filtered: Vec<MutableRef> = match after {
            Some(cursor) => all
                .into_iter()
                .filter(|r| r.ref_name.as_bytes() > cursor.as_bytes())
                .take(limit + 1)
                .collect(),
            None => all.into_iter().take(limit + 1).collect(),
        };

        Ok(StringPage::from_overfetch(filtered, limit))
    }
}

/// Resolve the effective per-page limit: clamp to `[1, MAX_LIST_LIMIT]`,
/// substitute `DEFAULT_LIST_LIMIT` when the caller passed `0`.
fn effective_limit(n: u32) -> usize {
    let base = if n == 0 { DEFAULT_LIST_LIMIT } else { n };
    base.clamp(1, MAX_LIST_LIMIT) as usize
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use hort_domain::entities::mutable_ref::{MutableRef, RefTarget};
    use hort_domain::error::DomainError;
    use hort_domain::events::{DomainEvent, StreamCategory};
    use hort_domain::types::ContentHash;

    use crate::metrics::capture_metrics;
    use crate::use_cases::test_support::{
        api_actor, MockRefLifecyclePort, MockRefRegistryPort, VALID_SHA256,
    };

    fn sample_hash() -> ContentHash {
        VALID_SHA256.parse().unwrap()
    }

    fn other_hash() -> ContentHash {
        "a".repeat(64).parse().unwrap()
    }

    fn build() -> (
        Arc<MockRefRegistryPort>,
        Arc<MockRefLifecyclePort>,
        RefUseCase,
    ) {
        let refs = Arc::new(MockRefRegistryPort::new());
        let lifecycle = Arc::new(MockRefLifecyclePort::new(refs.clone()));
        let uc = RefUseCase::new(refs.clone(), lifecycle.clone(), true);
        (refs, lifecycle, uc)
    }

    /// First `set` on a non-existent ref emits `result="created"` and
    /// calls `move_ref` once.
    #[test]
    fn set_first_time_is_created() {
        let (_refs, lifecycle, uc) = build();
        let repo = Uuid::new_v4();

        let snap = capture_metrics(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                uc.set(
                    repo,
                    "library/nginx",
                    "latest",
                    RefTarget::ContentHash(sample_hash()),
                    api_actor(),
                    Some("my-repo"),
                )
                .await
                .unwrap();
            });
        });

        assert_eq!(lifecycle.move_call_count(), 1);
        // Inspect the recorded batch — RefMoved.from is None, to is the
        // content-hash target.
        let moves = lifecycle.recorded_moves();
        assert_eq!(moves.len(), 1);
        let (recorded_ref, batch) = &moves[0];
        assert_eq!(recorded_ref.repository_id, repo);
        assert_eq!(recorded_ref.namespace, "library/nginx");
        assert_eq!(recorded_ref.ref_name, "latest");
        assert_eq!(batch.stream_id.category, StreamCategory::Ref);
        assert_eq!(batch.stream_id.entity_id, recorded_ref.id);
        assert_eq!(batch.expected_version, ExpectedVersion::NoStream);
        assert_eq!(batch.events.len(), 1);
        match &batch.events[0].event {
            DomainEvent::RefMoved(m) => {
                assert!(m.from.is_none());
                assert_eq!(m.to, RefTarget::ContentHash(sample_hash()));
                assert_eq!(m.ref_id, recorded_ref.id);
            }
            other => panic!("expected RefMoved, got {other:?}"),
        }

        // Metric fired with result="created".
        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_ref_moved_total")
            .expect("counter fires");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("result"), Some(&"created"));
        assert_eq!(labels.get("repository"), Some(&"my-repo"));
    }

    /// Second `set` with a different target emits `result="moved"` and
    /// reuses the existing `ref_id` (same stream).
    #[test]
    fn set_with_different_target_is_moved() {
        let (refs, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let existing_id = Uuid::new_v4();
        refs.insert(MutableRef {
            id: existing_id,
            repository_id: repo,
            namespace: "express".into(),
            ref_name: "latest".into(),
            target: RefTarget::Version("1.0.0".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        let snap = capture_metrics(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                uc.set(
                    repo,
                    "express",
                    "latest",
                    RefTarget::Version("2.0.0".into()),
                    api_actor(),
                    Some("npm-mirror"),
                )
                .await
                .unwrap();
            });
        });

        assert_eq!(lifecycle.move_call_count(), 1);
        let moves = lifecycle.recorded_moves();
        let (recorded_ref, batch) = &moves[0];
        // Reuses the existing id (keeps the stream history linear).
        assert_eq!(recorded_ref.id, existing_id);
        assert_eq!(batch.stream_id.entity_id, existing_id);
        assert_eq!(batch.expected_version, ExpectedVersion::Any);
        match &batch.events[0].event {
            DomainEvent::RefMoved(m) => {
                assert_eq!(m.from, Some(RefTarget::Version("1.0.0".into())));
                assert_eq!(m.to, RefTarget::Version("2.0.0".into()));
            }
            other => panic!("expected RefMoved, got {other:?}"),
        }

        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_ref_moved_total")
            .expect("counter fires");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("result"), Some(&"moved"));
    }

    /// Third `set` with the same target short-circuits — no lifecycle
    /// call, metric labelled `no_op`.
    #[test]
    fn set_with_same_target_is_no_op() {
        let (refs, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let target = RefTarget::ContentHash(sample_hash());
        refs.insert(MutableRef {
            id: Uuid::new_v4(),
            repository_id: repo,
            namespace: "library/nginx".into(),
            ref_name: "latest".into(),
            target: target.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        let snap = capture_metrics(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                uc.set(
                    repo,
                    "library/nginx",
                    "latest",
                    target.clone(),
                    api_actor(),
                    Some("my-repo"),
                )
                .await
                .unwrap();
            });
        });

        // No lifecycle call for the no-op path.
        assert_eq!(lifecycle.move_call_count(), 0);

        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_ref_moved_total")
            .expect("counter fires");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("result"), Some(&"no_op"));
    }

    /// `retire` on an existing ref emits `result="retired"` and calls
    /// `retire_ref` once with a `RefRetired` event.
    #[test]
    fn retire_existing_ref() {
        let (refs, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let existing_id = Uuid::new_v4();
        let target = RefTarget::ContentHash(sample_hash());
        refs.insert(MutableRef {
            id: existing_id,
            repository_id: repo,
            namespace: "library/nginx".into(),
            ref_name: "latest".into(),
            target: target.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        let snap = capture_metrics(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                uc.retire(
                    repo,
                    "library/nginx",
                    "latest",
                    api_actor(),
                    Some("my-repo"),
                )
                .await
                .unwrap();
            });
        });

        assert_eq!(lifecycle.retire_call_count(), 1);
        let retires = lifecycle.recorded_retires();
        let (r_repo, r_ns, r_name, batch) = &retires[0];
        assert_eq!(*r_repo, repo);
        assert_eq!(r_ns, "library/nginx");
        assert_eq!(r_name, "latest");
        assert_eq!(batch.stream_id.entity_id, existing_id);
        match &batch.events[0].event {
            DomainEvent::RefRetired(r) => {
                assert_eq!(r.ref_id, existing_id);
                assert_eq!(r.last_target, target);
            }
            other => panic!("expected RefRetired, got {other:?}"),
        }

        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_ref_moved_total")
            .expect("counter fires");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("result"), Some(&"retired"));
    }

    /// `retire` on a nonexistent ref returns NotFound and does NOT
    /// invoke the lifecycle port.
    #[tokio::test]
    async fn retire_missing_returns_not_found() {
        let (_refs, lifecycle, uc) = build();
        let repo = Uuid::new_v4();

        let err = uc
            .retire(repo, "ghost", "latest", api_actor(), Some("my-repo"))
            .await
            .expect_err("expected NotFound on missing ref");
        match err {
            crate::error::AppError::Domain(DomainError::NotFound { entity, .. }) => {
                assert_eq!(entity, "MutableRef");
            }
            other => panic!("expected Domain(NotFound), got {other:?}"),
        }
        assert_eq!(lifecycle.retire_call_count(), 0);
    }

    /// `get` propagates the find result; missing ref surfaces NotFound.
    #[tokio::test]
    async fn get_returns_find_result() {
        let (refs, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let existing = MutableRef {
            id: Uuid::new_v4(),
            repository_id: repo,
            namespace: "express".into(),
            ref_name: "latest".into(),
            target: RefTarget::Version("1.0.0".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        refs.insert(existing.clone());

        let got = uc.get(repo, "express", "latest").await.unwrap();
        assert_eq!(got.id, existing.id);

        let err = uc
            .get(repo, "express", "next")
            .await
            .expect_err("missing ref");
        assert!(matches!(
            err,
            crate::error::AppError::Domain(DomainError::NotFound { entity, .. }) if entity == "MutableRef"
        ));
    }

    /// When `include_repository_label = false` the metric carries the
    /// `_all` sentinel regardless of what the caller supplied.
    #[test]
    fn repo_label_disabled_emits_all_sentinel() {
        let refs = Arc::new(MockRefRegistryPort::new());
        let lifecycle = Arc::new(MockRefLifecyclePort::new(refs.clone()));
        let uc = RefUseCase::new(refs.clone(), lifecycle.clone(), false);
        let repo = Uuid::new_v4();

        let snap = capture_metrics(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                uc.set(
                    repo,
                    "library/redis",
                    "latest",
                    RefTarget::ContentHash(other_hash()),
                    api_actor(),
                    Some("my-repo"), // Caller-supplied, but flag disables emission.
                )
                .await
                .unwrap();
            });
        });

        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_ref_moved_total")
            .expect("counter fires");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("repository"), Some(&"_all"));
    }

    /// When `repo_key=None` with the label enabled, the sentinel is
    /// `unknown` per the catalog convention.
    #[test]
    fn repo_label_none_emits_unknown_sentinel() {
        let (_refs, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();

        let snap = capture_metrics(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                uc.set(
                    repo,
                    "library/redis",
                    "latest",
                    RefTarget::ContentHash(other_hash()),
                    api_actor(),
                    None,
                )
                .await
                .unwrap();
            });
        });

        let entries = snap.into_vec();
        let (key, _, _, _) = entries
            .iter()
            .find(|(k, _, _, _)| k.key().name() == "hort_ref_moved_total")
            .expect("counter fires");
        let labels: std::collections::HashMap<&str, &str> =
            key.key().labels().map(|l| (l.key(), l.value())).collect();
        assert_eq!(labels.get("repository"), Some(&"unknown"));
    }

    /// B5 retry path: the first attempt observes `RefAlreadyExists`
    /// (concurrent create race), the use case re-reads the winner's
    /// row and retries as a move. Exactly two lifecycle calls; the
    /// second records (the first is injected and short-circuited).
    #[test]
    fn set_retries_on_ref_already_exists() {
        let (refs, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let winner_id = Uuid::new_v4();
        // Inject a RefAlreadyExists for the FIRST call. Seed the
        // registry with the winner's row so the retry's `find` sees
        // it.
        lifecycle.inject_move_outcome(RefCommitOutcome::RefAlreadyExists {
            existing_id: winner_id,
        });
        refs.insert(MutableRef {
            id: winner_id,
            repository_id: repo,
            namespace: "library/nginx".into(),
            ref_name: "latest".into(),
            target: RefTarget::Version("1.0.0".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        let snap = capture_metrics(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                uc.set(
                    repo,
                    "library/nginx",
                    "latest",
                    // Different target so the retry dispatches as a move.
                    RefTarget::ContentHash(sample_hash()),
                    api_actor(),
                    Some("my-repo"),
                )
                .await
                .unwrap();
            });
        });

        // Two lifecycle calls — the injected one and the retry.
        assert_eq!(lifecycle.move_call_count(), 2);
        // Only the retry recorded (injection short-circuits before
        // recording).
        let moves = lifecycle.recorded_moves();
        assert_eq!(moves.len(), 1, "injected call did NOT record");
        let (retry_ref, retry_batch) = &moves[0];
        assert_eq!(
            retry_ref.id, winner_id,
            "retry targets the winner's id, not a fresh mint"
        );
        // Retry is a move (from -> to), not a first-placement.
        assert_eq!(retry_batch.expected_version, ExpectedVersion::Any);
        match &retry_batch.events[0].event {
            DomainEvent::RefMoved(m) => {
                assert_eq!(m.from, Some(RefTarget::Version("1.0.0".into())));
                assert_eq!(m.to, RefTarget::ContentHash(sample_hash()));
            }
            other => panic!("expected RefMoved, got {other:?}"),
        }

        // Metric fired exactly once, with `result="moved"` (the retry
        // dispatched as a move since the winner's row was already
        // present).
        let entries = snap.into_vec();
        let moved_entries: Vec<_> = entries
            .iter()
            .filter(|(k, _, _, _)| k.key().name() == "hort_ref_moved_total")
            .collect();
        assert_eq!(
            moved_entries.len(),
            1,
            "metric fires exactly once (no double-count from race-lost attempt)"
        );
        let labels: std::collections::HashMap<&str, &str> = moved_entries[0]
            .0
            .key()
            .labels()
            .map(|l| (l.key(), l.value()))
            .collect();
        assert_eq!(labels.get("result"), Some(&"moved"));
    }

    /// A second `RefAlreadyExists` after retry is an adapter contract
    /// violation and surfaces as `DomainError::Invariant`. The retry
    /// loop is bounded: we never loop forever.
    #[tokio::test]
    async fn set_second_already_exists_is_invariant() {
        let (refs, lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        let winner_id = Uuid::new_v4();
        refs.insert(MutableRef {
            id: winner_id,
            repository_id: repo,
            namespace: "library/nginx".into(),
            ref_name: "latest".into(),
            target: RefTarget::Version("1.0.0".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        // BOTH calls return RefAlreadyExists — simulates an adapter
        // bug where the mock insists it observed a race even though
        // the row is visible.
        lifecycle.inject_move_outcome(RefCommitOutcome::RefAlreadyExists {
            existing_id: winner_id,
        });
        lifecycle.inject_move_outcome(RefCommitOutcome::RefAlreadyExists {
            existing_id: winner_id,
        });

        let err = uc
            .set(
                repo,
                "library/nginx",
                "latest",
                RefTarget::ContentHash(sample_hash()),
                api_actor(),
                Some("my-repo"),
            )
            .await
            .expect_err("second RefAlreadyExists is Invariant");
        match err {
            crate::error::AppError::Domain(DomainError::Invariant(msg)) => {
                assert!(
                    msg.contains("adapter contract"),
                    "message should name the contract violation, got: {msg}"
                );
            }
            other => panic!("expected Domain(Invariant), got {other:?}"),
        }
        // Exactly two attempts — no unbounded retry loop.
        assert_eq!(lifecycle.move_call_count(), 2);
    }

    // -----------------------------------------------------------------
    // RefUseCase::list
    // -----------------------------------------------------------------

    /// Seed five refs in `(repo, namespace)` with ref_names chosen so
    /// their byte-ordered sort is obvious: ascending `a`..`e`.
    fn seed_five_refs(refs: &MockRefRegistryPort, repo: Uuid, namespace: &str) {
        for name in ["d", "b", "e", "a", "c"] {
            refs.insert(MutableRef {
                id: Uuid::new_v4(),
                repository_id: repo,
                namespace: namespace.to_string(),
                ref_name: name.to_string(),
                target: RefTarget::ContentHash(sample_hash()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
        }
    }

    #[test]
    fn list_returns_byte_stable_sorted_refs() {
        let (refs, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        seed_five_refs(&refs, repo, "library/nginx");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let page = rt
            .block_on(uc.list(repo, "library/nginx", None, 10))
            .unwrap();

        let names: Vec<&str> = page.items.iter().map(|r| r.ref_name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c", "d", "e"]);
        assert!(!page.saturated, "five items with limit 10 not saturated");
    }

    #[test]
    fn list_cursor_walks_three_pages() {
        // limit=2 across 5 refs → pages [a,b], [c,d], [e]; the last
        // page is non-saturated (no sixth ref behind it).
        let (refs, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        seed_five_refs(&refs, repo, "library/nginx");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let p1 = rt
            .block_on(uc.list(repo, "library/nginx", None, 2))
            .unwrap();
        assert_eq!(
            p1.items
                .iter()
                .map(|r| r.ref_name.clone())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert!(p1.saturated, "page 1 must be saturated with 5 total / n=2");

        let p2 = rt
            .block_on(uc.list(repo, "library/nginx", Some("b"), 2))
            .unwrap();
        assert_eq!(
            p2.items
                .iter()
                .map(|r| r.ref_name.clone())
                .collect::<Vec<_>>(),
            vec!["c", "d"]
        );
        assert!(p2.saturated);

        let p3 = rt
            .block_on(uc.list(repo, "library/nginx", Some("d"), 2))
            .unwrap();
        assert_eq!(
            p3.items
                .iter()
                .map(|r| r.ref_name.clone())
                .collect::<Vec<_>>(),
            vec!["e"]
        );
        assert!(!p3.saturated, "terminal page must not be saturated");
    }

    #[test]
    fn list_cursor_strictly_greater_than_after() {
        // Regression guard: the cursor predicate must be `> after`,
        // not `>= after`. Passing `Some("c")` must skip `"c"` itself.
        let (refs, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        seed_five_refs(&refs, repo, "lib/n");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let page = rt.block_on(uc.list(repo, "lib/n", Some("c"), 10)).unwrap();

        let names: Vec<&str> = page.items.iter().map(|r| r.ref_name.as_str()).collect();
        assert_eq!(names, vec!["d", "e"], "cursor c must exclude c itself");
    }

    #[test]
    fn list_empty_namespace_returns_empty_page() {
        let (_refs, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let page = rt
            .block_on(uc.list(repo, "nonexistent/ns", None, 10))
            .unwrap();

        assert!(page.is_empty());
        assert!(!page.saturated);
    }

    #[test]
    fn list_limit_zero_substitutes_default() {
        // `n = 0` is the "unspecified" URL shape. The use case
        // substitutes DEFAULT_LIST_LIMIT (100), NOT a zero-sized page
        // — otherwise `GET /v2/<name>/tags/list` (no `?n=`) would
        // always return empty.
        let (refs, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        // Seed 3 refs — fewer than DEFAULT_LIST_LIMIT so the default
        // doesn't over-trim.
        for name in ["x", "y", "z"] {
            refs.insert(MutableRef {
                id: Uuid::new_v4(),
                repository_id: repo,
                namespace: "ns".to_string(),
                ref_name: name.to_string(),
                target: RefTarget::ContentHash(sample_hash()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let page = rt.block_on(uc.list(repo, "ns", None, 0)).unwrap();
        assert_eq!(page.items.len(), 3, "n=0 must fall through to default");
    }

    #[test]
    fn list_cross_namespace_isolation() {
        // Refs seeded in `ns-a` must not surface under `ns-b` — the
        // port query is `(repo, namespace)`-scoped; the use case must
        // not widen it.
        let (refs, _lifecycle, uc) = build();
        let repo = Uuid::new_v4();
        refs.insert(MutableRef {
            id: Uuid::new_v4(),
            repository_id: repo,
            namespace: "ns-a".into(),
            ref_name: "tag".into(),
            target: RefTarget::ContentHash(sample_hash()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let page = rt.block_on(uc.list(repo, "ns-b", None, 10)).unwrap();
        assert!(page.is_empty());
    }
}
