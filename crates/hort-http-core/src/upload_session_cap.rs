//! Generic per-`(repo, principal)` live upload-session cap primitive.
//!
//! Every `StatefulUpload` format (OCI blob upload, Git LFS batch
//! transfer, future chunked-PUT formats) bounds the number of
//! concurrently-open upload sessions a single principal may hold in a
//! single repository. This module is the shared, format-parameterized
//! implementation of that cap: an **authoritative, self-pruning live
//! session SET**, stored as one serialized value per
//! `(format, repo, principal)` and reconciled on every admit.
//!
//! The set is authoritative for the cap: it age-prunes abandoned members
//! on every [`admit`], and a cap rejection performs NO write, so it never
//! refreshes the set TTL. Those two properties keep an abandoned-upload
//! retry storm from pinning the cap — an unfinalized, un-released session
//! ages out of the set and a rejection cannot extend its lifetime.
//!
//! # Format parameterization
//!
//! Every entry point takes a `format: &str` (`"oci"`, `"lfs"`, …). The
//! key builder ([`session_set_key`]) inlines it, so each format's cap is
//! a disjoint keyspace: an `"oci"` admit never counts against an `"lfs"`
//! cap on the same `(repo, principal)`. The two metrics carry the same
//! `format` label so operators can attribute prune / rejection pressure
//! per format.
//!
//! # Relationship to the per-session record
//!
//! This module tracks ONLY the cap-accounting set. The individual
//! upload-session records (bytes-received, CAS version, staging cursor)
//! live in the format crate under its own `stateful_upload:{format}:…`
//! keyspace. The cap set is a separate `upload_sessions:{format}:…`
//! keyspace — individual session rows and the aggregate set never
//! collide.
//!
//! # Wire-format invariant
//!
//! `postcard` encodes struct fields in declaration order with no field
//! tags. Reordering / adding / removing fields on [`SessionSet`] or
//! [`SessionMember`] is a breaking wire-format change. The set is under
//! the `upload_sessions:` prefix; a future schema break bumps the prefix
//! (`upload_sessions_v2:`) and lets in-flight sets expire via their
//! max-age TTL — the drain-via-TTL migration.

use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use uuid::Uuid;

use hort_app::error::{AppError, AppResult};
use hort_domain::error::DomainError;

use crate::context::AppContext;

// ---------------------------------------------------------------------------
// Key
// ---------------------------------------------------------------------------

/// Build the `EphemeralStore` key for the per-`(format, repo, principal)`
/// live upload-session set.
///
/// Key shape is `upload_sessions:{format}:{repo_id}:{principal_id}`.
/// Stable across process restarts (every component is a UUID's `Display`
/// form or a static format token), so a set reseats naturally when a
/// Redis-backed deployment recycles the registry binary while an
/// attacker's session pool is still in flight. The `upload_sessions:`
/// prefix keeps this set out of the per-format `stateful_upload:`
/// namespace consumed by the individual session rows — the aggregate set
/// and individual session rows never collide.
///
/// The `format` segment makes each format's cap a disjoint keyspace: an
/// `"oci"` admit never counts against an `"lfs"` cap on the same
/// `(repo, principal)`.
pub fn session_set_key(format: &str, repo_id: Uuid, principal_id: Uuid) -> String {
    format!("upload_sessions:{format}:{repo_id}:{principal_id}")
}

// ---------------------------------------------------------------------------
// Set + member
// ---------------------------------------------------------------------------

/// One live upload session, tracked in the per-`(format, repo, principal)`
/// [`SessionSet`] for cap accounting.
///
/// `id` is the session UUID as a `u128` (postcard encodes `u128`
/// compactly and it avoids pulling `Uuid`'s serde feature into this
/// module's wire format). `created_at_ms` is the epoch-millis timestamp
/// the member was admitted; the admit reconcile prunes any member older
/// than the configured session max-age, so the set self-heals as
/// abandoned sessions age out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SessionMember {
    pub id: u128,
    pub created_at_ms: i64,
}

/// The per-`(format, repo, principal)` set of live upload sessions — the
/// authoritative cap accounting.
///
/// Stored as ONE serialized value under [`session_set_key`]. `version`
/// tracks the [`EphemeralStore`](hort_domain::ports::ephemeral_store::EphemeralStore)
/// CAS counter so the admit / release loops can compare-and-swap without
/// a `get_with_version` port method. `members` holds the live sessions;
/// the cap check counts `members.len()` AFTER age-pruning, so an
/// abandoned session can never pin the cap past the session max-age.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SessionSet {
    pub version: u64,
    pub members: Vec<SessionMember>,
}

/// Serialise a [`SessionSet`] to `Bytes` for `EphemeralStore`.
/// `DomainError::Invariant` on encode failure — postcard's allocating
/// writer can only fail on OOM or a serializer error, neither a
/// validation concern.
pub(crate) fn encode_session_set(set: &SessionSet) -> Result<Bytes, DomainError> {
    let bytes = postcard::to_allocvec(set).map_err(|e| {
        DomainError::Invariant(format!("upload-session-set postcard-encode failed: {e}"))
    })?;
    Ok(Bytes::from(bytes))
}

/// Deserialise a [`SessionSet`] from `EphemeralStore`-retrieved bytes.
/// `DomainError::Invariant` on a malformed payload — only possible if an
/// adapter stored bytes not produced by [`encode_session_set`]
/// (corruption or manual operator poke).
pub(crate) fn decode_session_set(bytes: &[u8]) -> Result<SessionSet, DomainError> {
    postcard::from_bytes(bytes).map_err(|e| {
        DomainError::Invariant(format!("upload-session-set postcard-decode failed: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Admit / release
// ---------------------------------------------------------------------------

/// Upper bound on the reconcile-admit / release CAS retry loop. The set
/// is per-`(format, repo, principal)`, so realistic write contention is a
/// single principal opening / closing a handful of sessions concurrently
/// — 32 iterations is generous headroom. Exhausting it means pathological
/// contention (or a broken adapter); the admit path surfaces that as
/// [`AdmitOutcome::Contended`] (a transient `503`) rather than fail-open
/// (the cap is a DoS guard).
const RECONCILE_MAX_ITERS: usize = 32;

/// Outcome of [`admit`].
#[derive(Debug)]
pub enum AdmitOutcome {
    /// The session was added to the live set — proceed with the create.
    Admitted,
    /// The set is already at the cap after pruning aged-out members —
    /// reject with `429`. No write was performed.
    OverCap,
    /// The bounded reconcile CAS loop exhausted its retry budget under
    /// pathological write contention — a **transient** condition, not a
    /// cap breach and not an infra failure. No write was performed.
    /// Consumers map this to `503 Service Unavailable` + a short
    /// `Retry-After` so the client retries soon; the cap stays a
    /// fail-closed DoS guard (never fail-open) without turning transient
    /// contention into a `500`. Genuine infra failures (a `get` / `put` /
    /// CAS `Err` from the store) still propagate as `Err` → `500`.
    Contended,
}

/// Reconcile the per-`(format, repo, principal)` live session set and
/// admit `session_id` if the (post-prune) member count is below `cap`.
///
/// Bounded `get → age-prune → check-cap → CAS` loop:
///
/// 1. `get(set_key)`.
/// 2. **Absent** → first slot: `put_if_absent(set_key, {version:1,
///    members:[new]}, max_age)`. Won → admitted; lost the create race →
///    retry (now the CAS branch).
/// 3. **Present** → deserialize → prune members older than `max_age` →
///    if `pruned.len() < cap`: push the new member →
///    `compare_and_swap(version, {version+1, pruned+new}, max_age)`.
///    `Ok(Some)` → admitted; `Ok(None)` (version raced) → retry. If
///    `pruned.len() >= cap` → **reject** with NO write.
/// 4. Loop exhausted → [`AdmitOutcome::Contended`] (transient; NO write,
///    never a `500`-panic, never fail-open — the cap is a DoS guard).
///    Genuine infra failures on the `get` / `put` / CAS calls propagate
///    as `Err` → `500`; only retry-budget exhaustion is `Contended`.
///
/// Because a rejected admit performs no write, it never refreshes the
/// set TTL — a rejection cannot extend an abandoned session's lifetime,
/// so the cap can never be pinned past the age-prune window. The prune
/// emits `hort_upload_session_reconcile_pruned_total{format,repo,result}`
/// on every admit (`result=pruned` when any member aged out, `none`
/// otherwise) and a `debug!` (count only — never a principal / session
/// id) when pruning. The caller passes a pre-resolved `repo_label` (the
/// `repo` metric-label value) so a single initiate performs ONE
/// repository lookup, not one here plus one for its own `created`
/// counter — the primitive never re-resolves the label.
///
/// Consumers map [`AdmitOutcome::OverCap`] to a `429` and emit
/// `hort_upload_session_cap_rejections_total{format,repo,result=over_cap}`
/// themselves — the primitive returns the outcome so the caller controls
/// the HTTP envelope. [`AdmitOutcome::Contended`] maps to a `503` +
/// short `Retry-After`; it is a transient status, NOT a cap rejection,
/// so consumers do NOT emit the cap-rejection metric for it (keeping the
/// `over_cap` counter a clean signal of real cap pressure).
///
/// The argument list is intentionally wide: every parameter is a
/// distinct axis of the cap-accounting key or policy (`format` / `repo`
/// / `principal` / `session` / `cap` / `max_age`) plus the pre-resolved
/// `repo_label` the caller threads in to avoid a duplicate repository
/// lookup — bundling them into a struct would not remove any and would
/// add ceremony at every call site.
#[allow(clippy::too_many_arguments)]
pub async fn admit(
    ctx: &AppContext,
    format: &str,
    repo_id: Uuid,
    repo_label: &str,
    principal_id: Uuid,
    session_id: Uuid,
    cap: u32,
    max_age: Duration,
) -> AppResult<AdmitOutcome> {
    let key = session_set_key(format, repo_id, principal_id);
    let cap = cap as usize;
    let now_ms = Utc::now().timestamp_millis();
    let max_age_ms = max_age.as_millis() as i64;
    let new_member = SessionMember {
        id: session_id.as_u128(),
        created_at_ms: now_ms,
    };

    for _ in 0..RECONCILE_MAX_ITERS {
        let stored = ctx
            .ephemeral_durable
            .get(&key)
            .await
            .map_err(AppError::from)?;
        match stored {
            None => {
                // No live set — a zero cap rejects unconditionally
                // (no first slot to grant).
                if cap == 0 {
                    return Ok(AdmitOutcome::OverCap);
                }
                let set = SessionSet {
                    version: 1,
                    members: vec![new_member],
                };
                let bytes = encode_session_set(&set).map_err(AppError::from)?;
                let created = ctx
                    .ephemeral_durable
                    .put_if_absent(&key, bytes, max_age)
                    .await
                    .map_err(AppError::from)?;
                if created {
                    emit_reconcile_metric(format, repo_id, repo_label, 0);
                    return Ok(AdmitOutcome::Admitted);
                }
                // Lost the create race — retry into the CAS branch.
                continue;
            }
            Some(value) => {
                let set = decode_session_set(&value).map_err(AppError::from)?;
                // Age-prune: drop members older than the max-age. The
                // set-value's own `created_at_ms` is the prune signal —
                // no per-record GET, and it catches BOTH `POST`-only and
                // `PATCH`ed abandons.
                let before = set.members.len();
                let mut pruned: Vec<SessionMember> = set
                    .members
                    .into_iter()
                    .filter(|m| now_ms - m.created_at_ms <= max_age_ms)
                    .collect();
                let pruned_count = before - pruned.len();

                if pruned.len() >= cap {
                    // At cap after pruning — reject with NO write. The
                    // set is unchanged; its TTL is not refreshed.
                    return Ok(AdmitOutcome::OverCap);
                }

                // Dedup a re-`POST` of the same id (cosmically unlikely
                // under v4 UUIDs, but keeps the set a true set).
                if !pruned.iter().any(|m| m.id == new_member.id) {
                    pruned.push(new_member);
                }
                let next = SessionSet {
                    version: set.version + 1,
                    members: pruned,
                };
                let bytes = encode_session_set(&next).map_err(AppError::from)?;
                let cas = ctx
                    .ephemeral_durable
                    .compare_and_swap(&key, set.version, bytes, max_age)
                    .await
                    .map_err(AppError::from)?;
                match cas {
                    Some(_) => {
                        emit_reconcile_metric(format, repo_id, repo_label, pruned_count);
                        return Ok(AdmitOutcome::Admitted);
                    }
                    // Version raced — another admit/release won. Retry.
                    None => continue,
                }
            }
        }
    }
    // Pathological contention. Never fail-open (the cap is a DoS guard)
    // and never panic — surface a transient `Contended` outcome the
    // handler maps to a `503` + short `Retry-After`. Genuine infra
    // failures already returned `Err` above; only retry-budget
    // exhaustion reaches here.
    Ok(AdmitOutcome::Contended)
}

/// Emit `hort_upload_session_reconcile_pruned_total{format,repo,result}`
/// for one admit and, when any member aged out, a `debug!` carrying the
/// count only (never a principal / session id — cardinality + PII rule).
///
/// `repo_label` is the caller's pre-resolved `repo` label value: the
/// admit path takes exactly one repository lookup per initiate (the
/// caller resolves it once and threads it here AND into its own
/// `created` counter), rather than re-resolving inside the primitive.
fn emit_reconcile_metric(format: &str, repo_id: Uuid, repo_label: &str, pruned_count: usize) {
    let result = if pruned_count > 0 { "pruned" } else { "none" };
    if pruned_count > 0 {
        tracing::debug!(
            target: "hort::upload_session_cap",
            format = format,
            repository_id = %repo_id,
            pruned = pruned_count,
            "upload session-set reconcile pruned aged-out members",
        );
    }
    metrics::counter!(
        "hort_upload_session_reconcile_pruned_total",
        "format" => format.to_owned(),
        "repo" => repo_label.to_owned(),
        "result" => result,
    )
    .increment(1);
}

/// Release a session from the per-`(format, repo, principal)` live set on
/// finalize success / declared-hash conflict / infra error /
/// DELETE-cancel.
///
/// `get → remove-by-id → compare_and_swap` (retry on a version race).
/// The member already being absent (aged out by a prior admit's prune,
/// or the whole set TTL-expired) is a no-op — never an underflow. When
/// the removal empties the set the key is dropped so the next admit
/// takes the clean absent-key branch.
///
/// Best-effort: an infrastructure error is logged at `warn!` and does
/// NOT propagate. The set is max-age-bounded, so a leaked slot
/// self-heals on the next admit's age-prune (or the set's own TTL).
pub async fn release(
    ctx: &AppContext,
    format: &str,
    repo_id: Uuid,
    principal_id: Uuid,
    session_id: Uuid,
    max_age: Duration,
) {
    let key = session_set_key(format, repo_id, principal_id);
    let target = session_id.as_u128();

    for _ in 0..RECONCILE_MAX_ITERS {
        let stored = match ctx.ephemeral_durable.get(&key).await {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(
                    target: "hort::upload_session_cap",
                    format = format,
                    repository_id = %repo_id,
                    error = %err,
                    "upload session-set release: ephemeral get failed; set will age-prune / TTL out",
                );
                return;
            }
        };
        // Set already gone (TTL elapsed / never created). Nothing to
        // release; the cap state is consistent already.
        let Some(value) = stored else {
            return;
        };
        let set = match decode_session_set(&value) {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(
                    target: "hort::upload_session_cap",
                    format = format,
                    repository_id = %repo_id,
                    error = %err,
                    "upload session-set release: decode failed; leaving set (age-prune / TTL will reap)",
                );
                return;
            }
        };
        // Member absent (pruned already, or a double-release) → no-op.
        if !set.members.iter().any(|m| m.id == target) {
            return;
        }
        let remaining: Vec<SessionMember> =
            set.members.into_iter().filter(|m| m.id != target).collect();

        if remaining.is_empty() {
            // Cleanest representation of "no live sessions" is to drop
            // the key; the next admit recreates it via the absent-key
            // branch. `delete` is idempotent so a TTL race is harmless.
            // A concurrent admit that CAS-created a NEW version between
            // our `get` and this `delete` would be clobbered — but the
            // set is per-`(format, repo, principal)`, single-user
            // contention is low, and the next admit's age-prune repairs
            // any lost slot.
            if let Err(err) = ctx.ephemeral_durable.delete(&key).await {
                tracing::warn!(
                    target: "hort::upload_session_cap",
                    format = format,
                    repository_id = %repo_id,
                    error = %err,
                    "upload session-set release: delete failed; set will age-prune / TTL out",
                );
            }
            return;
        }

        let next = SessionSet {
            version: set.version + 1,
            members: remaining,
        };
        let bytes = match encode_session_set(&next) {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(
                    target: "hort::upload_session_cap",
                    format = format,
                    repository_id = %repo_id,
                    error = %err,
                    "upload session-set release: encode failed; leaving set (age-prune / TTL will reap)",
                );
                return;
            }
        };
        match ctx
            .ephemeral_durable
            .compare_and_swap(&key, set.version, bytes, max_age)
            .await
        {
            Ok(Some(_)) => return,
            // Version raced (concurrent admit/release) — retry.
            Ok(None) => continue,
            Err(err) => {
                tracing::warn!(
                    target: "hort::upload_session_cap",
                    format = format,
                    repository_id = %repo_id,
                    error = %err,
                    "upload session-set release: CAS failed; set will age-prune / TTL out",
                );
                return;
            }
        }
    }
    // Retry budget exhausted — best-effort release gives up. The set's
    // age-prune (or TTL) reclaims the leaked slot on the next admit.
    tracing::warn!(
        target: "hort::upload_session_cap",
        format = format,
        repository_id = %repo_id,
        "upload session-set release: retry budget exhausted; set will age-prune / TTL out",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use hort_app::use_cases::test_support::sample_repository;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};

    use crate::test_support::build_mock_ctx;

    // -------------------- Harness --------------------

    /// Default session max-age used across the tests that don't
    /// exercise age-pruning. One hour matches the OCI production
    /// default; the age-prune tests pass a short value explicitly.
    const TEST_MAX_AGE: Duration = Duration::from_secs(3600);

    fn run<F, T>(f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn capture<T, F>(f: F) -> (Snapshot, T)
    where
        F: FnOnce() -> T,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let out = metrics::with_local_recorder(&recorder, f);
        (snapshotter.snapshot(), out)
    }

    fn find_counter<'a>(
        entries: &'a [MetricEntry],
        name: &str,
        expected: &[(&str, &str)],
    ) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != MetricKind::Counter || ck.key().name() != name {
                return None;
            }
            let ok = expected
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            ok.then_some(dv)
        })
    }

    /// Count the live members currently in the per-`(format, repo,
    /// principal)` session set (0 when the set is absent). Test-only
    /// observability into the authoritative cap accounting.
    async fn live_member_count(
        ctx: &AppContext,
        format: &str,
        repo_id: Uuid,
        principal_id: Uuid,
    ) -> usize {
        let key = session_set_key(format, repo_id, principal_id);
        match ctx.ephemeral_durable.get(&key).await.unwrap() {
            None => 0,
            Some(bytes) => decode_session_set(&bytes).unwrap().members.len(),
        }
    }

    /// Test wrapper: resolve the `repo` label the way the production
    /// caller does (one lookup), then call [`admit`]. Keeps the many
    /// test call sites free of the extra `repo_label` argument and
    /// exercises the same label the OCI adapter would thread through.
    #[allow(clippy::too_many_arguments)]
    async fn admit_t(
        ctx: &AppContext,
        format: &str,
        repo_id: Uuid,
        principal_id: Uuid,
        session_id: Uuid,
        cap: u32,
        max_age: Duration,
    ) -> AppResult<AdmitOutcome> {
        let label = ctx.repository_access_use_case.metric_label(repo_id).await;
        admit(
            ctx,
            format,
            repo_id,
            &label,
            principal_id,
            session_id,
            cap,
            max_age,
        )
        .await
    }

    /// Drive `admit` repeatedly and count admitted vs over-cap.
    async fn admit_n(
        ctx: &AppContext,
        format: &str,
        repo_id: Uuid,
        principal_id: Uuid,
        cap: u32,
        n: usize,
    ) -> (usize, usize) {
        let mut admitted = 0usize;
        let mut over = 0usize;
        for _ in 0..n {
            match admit_t(
                ctx,
                format,
                repo_id,
                principal_id,
                Uuid::new_v4(),
                cap,
                TEST_MAX_AGE,
            )
            .await
            .unwrap()
            {
                AdmitOutcome::Admitted => admitted += 1,
                AdmitOutcome::OverCap => over += 1,
                AdmitOutcome::Contended => {
                    panic!("admit_n saw Contended — the harness never induces contention")
                }
            }
        }
        (admitted, over)
    }

    // -------------------- key --------------------

    #[test]
    fn session_set_key_has_format_segment() {
        let repo = Uuid::new_v4();
        let principal = Uuid::new_v4();
        let key = session_set_key("oci", repo, principal);
        assert!(key.starts_with("upload_sessions:oci:"));
        assert!(key.contains(&repo.to_string()));
        assert!(key.ends_with(&principal.to_string()));
    }

    #[test]
    fn session_set_key_differs_per_format() {
        let repo = Uuid::new_v4();
        let principal = Uuid::new_v4();
        let oci = session_set_key("oci", repo, principal);
        let lfs = session_set_key("lfs", repo, principal);
        assert_ne!(oci, lfs);
        assert!(lfs.starts_with("upload_sessions:lfs:"));
    }

    // -------------------- encode/decode round-trip --------------------

    #[test]
    fn session_set_round_trips_via_postcard() {
        let set = SessionSet {
            version: 7,
            members: vec![
                SessionMember {
                    id: u128::MAX,
                    created_at_ms: i64::MIN,
                },
                SessionMember {
                    id: 0,
                    created_at_ms: 1_700_000_000_000,
                },
            ],
        };
        let bytes = encode_session_set(&set).unwrap();
        let decoded = decode_session_set(&bytes).unwrap();
        assert_eq!(decoded, set);
    }

    #[test]
    fn decode_garbage_bytes_returns_invariant() {
        // A single 0xff varint byte claims a continuation that never
        // arrives — postcard detects the truncation.
        let err = decode_session_set(&[0xff]).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }

    // -------------------- admit — cap behaviour --------------------

    #[test]
    fn admit_admits_up_to_cap_then_rejects() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let principal = Uuid::new_v4();
            let cap: u32 = 3;
            let (admitted, over) =
                admit_n(&ctx, "oci", repo_id, principal, cap, cap as usize).await;
            assert_eq!(admitted, cap as usize);
            assert_eq!(over, 0);

            // The next admit is over-cap.
            let next = admit_t(
                &ctx,
                "oci",
                repo_id,
                principal,
                Uuid::new_v4(),
                cap,
                TEST_MAX_AGE,
            )
            .await
            .unwrap();
            assert!(matches!(next, AdmitOutcome::OverCap));
            assert_eq!(
                live_member_count(&ctx, "oci", repo_id, principal).await,
                cap as usize
            );
        });
    }

    #[test]
    fn admit_zero_cap_rejects_unconditionally() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle);
            let repo_id = Uuid::new_v4();
            let principal = Uuid::new_v4();
            let out = admit_t(
                &ctx,
                "oci",
                repo_id,
                principal,
                Uuid::new_v4(),
                0,
                TEST_MAX_AGE,
            )
            .await
            .unwrap();
            assert!(matches!(out, AdmitOutcome::OverCap));
            assert_eq!(live_member_count(&ctx, "oci", repo_id, principal).await, 0);
        });
    }

    // -------------------- per-format keyspace isolation (reuse proof) ----

    #[test]
    fn oci_admit_does_not_count_against_lfs_cap_on_same_repo_principal() {
        // The reuse invariant: a second format (`"lfs"`) sharing the
        // primitive must NOT collide with `"oci"` on the same
        // `(repo, principal)`. Fill the OCI cap; the LFS cap is still
        // fully available.
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let principal = Uuid::new_v4();
            let cap: u32 = 2;

            // Fill the OCI cap.
            let _ = admit_n(&ctx, "oci", repo_id, principal, cap, cap as usize).await;
            assert!(matches!(
                admit_t(
                    &ctx,
                    "oci",
                    repo_id,
                    principal,
                    Uuid::new_v4(),
                    cap,
                    TEST_MAX_AGE
                )
                .await
                .unwrap(),
                AdmitOutcome::OverCap
            ));

            // The LFS cap for the SAME (repo, principal) is untouched.
            assert_eq!(live_member_count(&ctx, "lfs", repo_id, principal).await, 0);
            let lfs = admit_t(
                &ctx,
                "lfs",
                repo_id,
                principal,
                Uuid::new_v4(),
                cap,
                TEST_MAX_AGE,
            )
            .await
            .unwrap();
            assert!(
                matches!(lfs, AdmitOutcome::Admitted),
                "an oci admit must not count against an lfs cap on the same (repo, principal)"
            );
            assert_eq!(live_member_count(&ctx, "lfs", repo_id, principal).await, 1);
            // OCI set is unchanged by the LFS admit.
            assert_eq!(
                live_member_count(&ctx, "oci", repo_id, principal).await,
                cap as usize
            );
        });
    }

    #[test]
    fn cap_is_isolated_per_principal_and_per_repo() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo_x = sample_repository();
            repo_x.key = "x".into();
            let repo_x_id = repo_x.id;
            let mut repo_y = sample_repository();
            repo_y.key = "y".into();
            let repo_y_id = repo_y.id;
            mocks.repositories.insert(repo_x);
            mocks.repositories.insert(repo_y);

            let principal_a = Uuid::new_v4();
            let principal_b = Uuid::new_v4();
            let cap: u32 = 2;

            // A fills repo_x.
            let _ = admit_n(&ctx, "oci", repo_x_id, principal_a, cap, cap as usize).await;
            assert!(matches!(
                admit_t(
                    &ctx,
                    "oci",
                    repo_x_id,
                    principal_a,
                    Uuid::new_v4(),
                    cap,
                    TEST_MAX_AGE
                )
                .await
                .unwrap(),
                AdmitOutcome::OverCap
            ));
            // Different principal, same repo — unaffected.
            assert!(matches!(
                admit_t(
                    &ctx,
                    "oci",
                    repo_x_id,
                    principal_b,
                    Uuid::new_v4(),
                    cap,
                    TEST_MAX_AGE
                )
                .await
                .unwrap(),
                AdmitOutcome::Admitted
            ));
            // Same principal, different repo — unaffected.
            assert!(matches!(
                admit_t(
                    &ctx,
                    "oci",
                    repo_y_id,
                    principal_a,
                    Uuid::new_v4(),
                    cap,
                    TEST_MAX_AGE
                )
                .await
                .unwrap(),
                AdmitOutcome::Admitted
            ));
        });
    }

    // -------------------- release --------------------

    #[test]
    fn release_frees_a_slot_and_double_release_is_noop() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle);
            let repo_id = Uuid::new_v4();
            let principal = Uuid::new_v4();
            let session = Uuid::new_v4();
            let key = session_set_key("oci", repo_id, principal);

            // Release with no prior admit — absent set, no-op.
            release(&ctx, "oci", repo_id, principal, session, TEST_MAX_AGE).await;
            assert!(ctx.ephemeral_durable.get(&key).await.unwrap().is_none());

            // Admit one, release twice.
            assert!(matches!(
                admit_t(&ctx, "oci", repo_id, principal, session, 2, TEST_MAX_AGE)
                    .await
                    .unwrap(),
                AdmitOutcome::Admitted
            ));
            release(&ctx, "oci", repo_id, principal, session, TEST_MAX_AGE).await; // empties → key dropped
            release(&ctx, "oci", repo_id, principal, session, TEST_MAX_AGE).await; // double-release
            assert!(ctx.ephemeral_durable.get(&key).await.unwrap().is_none());
            assert_eq!(live_member_count(&ctx, "oci", repo_id, principal).await, 0);
        });
    }

    #[test]
    fn release_leaves_other_members_intact() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, _mocks) = build_mock_ctx(handle);
            let repo_id = Uuid::new_v4();
            let principal = Uuid::new_v4();
            let s1 = Uuid::new_v4();
            let s2 = Uuid::new_v4();
            let cap: u32 = 3;

            admit_t(&ctx, "oci", repo_id, principal, s1, cap, TEST_MAX_AGE)
                .await
                .unwrap();
            admit_t(&ctx, "oci", repo_id, principal, s2, cap, TEST_MAX_AGE)
                .await
                .unwrap();
            assert_eq!(live_member_count(&ctx, "oci", repo_id, principal).await, 2);

            release(&ctx, "oci", repo_id, principal, s1, TEST_MAX_AGE).await;
            assert_eq!(
                live_member_count(&ctx, "oci", repo_id, principal).await,
                1,
                "releasing s1 must leave s2 live"
            );
        });
    }

    // -------------------- age-prune --------------------

    #[test]
    fn aged_out_members_are_pruned_on_next_admit() {
        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = sample_repository();
            let repo_id = repo.id;
            repo.key = "myrepo".into();
            mocks.repositories.insert(repo);

            let principal = Uuid::new_v4();
            let cap: u32 = 3;
            let short = Duration::from_millis(40);

            // Fill the cap with abandoned members (admit-only).
            for _ in 0..cap {
                admit_t(&ctx, "oci", repo_id, principal, Uuid::new_v4(), cap, short)
                    .await
                    .unwrap();
            }
            assert_eq!(
                live_member_count(&ctx, "oci", repo_id, principal).await,
                cap as usize
            );
            // Cap full — a fresh admit is over-cap now.
            assert!(matches!(
                admit_t(&ctx, "oci", repo_id, principal, Uuid::new_v4(), cap, short)
                    .await
                    .unwrap(),
                AdmitOutcome::OverCap
            ));

            // Let the members age past the max-age.
            tokio::time::sleep(Duration::from_millis(80)).await;

            // The next admit prunes them all and succeeds.
            let next = admit_t(&ctx, "oci", repo_id, principal, Uuid::new_v4(), cap, short)
                .await
                .unwrap();
            assert!(matches!(next, AdmitOutcome::Admitted));
            assert_eq!(
                live_member_count(&ctx, "oci", repo_id, principal).await,
                1,
                "after aging, only the fresh admit remains"
            );
        });
    }

    // -------------------- CAS race safety --------------------

    #[test]
    fn concurrent_admits_never_over_admit_past_cap() {
        // Multi-thread runtime so the spawned tasks genuinely race the
        // single per-(format, repo, principal) set key.
        let (admitted, over, transient, live) = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                let repo_id = repo.id;
                repo.key = "myrepo".into();
                mocks.repositories.insert(repo);
                let principal = Uuid::new_v4();
                let cap: u32 = 8;
                let contenders = 12u32;
                let mut handles = Vec::with_capacity(contenders as usize);
                for _ in 0..contenders {
                    let ctx_ref = ctx.clone();
                    handles.push(tokio::spawn(async move {
                        admit_t(
                            &ctx_ref,
                            "oci",
                            repo_id,
                            principal,
                            Uuid::new_v4(),
                            cap,
                            TEST_MAX_AGE,
                        )
                        .await
                    }));
                }
                let mut admitted = 0usize;
                let mut over = 0usize;
                // Transient non-admits: an infra `Err` OR an
                // `AdmitOutcome::Contended` (retry-budget exhaustion).
                // The in-memory mock does not realistically induce
                // either at this contention level, but bucketing them
                // together keeps the "every attempt resolves" invariant
                // exhaustive without asserting they never happen.
                let mut transient = 0usize;
                for h in handles {
                    match h.await.unwrap() {
                        Ok(AdmitOutcome::Admitted) => admitted += 1,
                        Ok(AdmitOutcome::OverCap) => over += 1,
                        Ok(AdmitOutcome::Contended) | Err(_) => transient += 1,
                    }
                }
                let live = live_member_count(&ctx, "oci", repo_id, principal).await;
                (admitted, over, transient, live)
            });
        assert!(
            admitted <= 8,
            "must never admit past the cap, got {admitted}"
        );
        assert_eq!(
            admitted + over + transient,
            12,
            "every attempt must resolve"
        );
        assert_eq!(
            admitted, 8,
            "cap-many admits must succeed under moderate contention"
        );
        assert_eq!(live, admitted, "live set must equal the admitted count");
    }

    // -------------------- reconcile-prune metric --------------------

    #[test]
    fn reconcile_metric_carries_format_label_on_prune() {
        // Seed a set whose sole member is already past the max-age, then
        // admit — the stale member is pruned and the metric fires with
        // result=pruned and the format label.
        let (snap, _) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                let repo_id = repo.id;
                repo.key = "myrepo".into();
                mocks.repositories.insert(repo);

                let principal = Uuid::new_v4();
                let stale = SessionSet {
                    version: 1,
                    members: vec![SessionMember {
                        id: Uuid::new_v4().as_u128(),
                        created_at_ms: Utc::now().timestamp_millis() - 2 * 3600 * 1000,
                    }],
                };
                let key = session_set_key("oci", repo_id, principal);
                ctx.ephemeral_durable
                    .put(&key, encode_session_set(&stale).unwrap(), TEST_MAX_AGE)
                    .await
                    .unwrap();

                admit_t(
                    &ctx,
                    "oci",
                    repo_id,
                    principal,
                    Uuid::new_v4(),
                    4,
                    TEST_MAX_AGE,
                )
                .await
                .unwrap();
            })
        });
        let entries = snap.into_vec();
        let v = find_counter(
            &entries,
            "hort_upload_session_reconcile_pruned_total",
            &[("format", "oci"), ("repo", "myrepo"), ("result", "pruned")],
        )
        .expect("prune metric absent with {format=oci,repo=myrepo,result=pruned}");
        assert!(matches!(v, DebugValue::Counter(n) if *n >= 1));

        // Cardinality guard: no principal/session-id label.
        for (ck, _, _, _) in &entries {
            if ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_upload_session_reconcile_pruned_total"
            {
                for label in ck.key().labels() {
                    assert!(
                        !matches!(
                            label.key(),
                            "principal_id" | "user_id" | "actor_id" | "session_id"
                        ),
                        "prune metric MUST NOT carry a high-cardinality label: {}",
                        label.key(),
                    );
                }
            }
        }
    }

    #[test]
    fn reconcile_metric_emits_none_when_nothing_pruned() {
        let (snap, _) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let mut repo = sample_repository();
                let repo_id = repo.id;
                repo.key = "myrepo".into();
                mocks.repositories.insert(repo);
                admit_t(
                    &ctx,
                    "oci",
                    repo_id,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    4,
                    TEST_MAX_AGE,
                )
                .await
                .unwrap();
            })
        });
        let entries = snap.into_vec();
        assert!(
            find_counter(
                &entries,
                "hort_upload_session_reconcile_pruned_total",
                &[("format", "oci"), ("repo", "myrepo"), ("result", "none")],
            )
            .is_some(),
            "a clean admit must emit result=none with the format label"
        );
    }

    // -------------------- error propagation --------------------

    #[test]
    fn admit_propagates_ephemeral_failure() {
        use hort_domain::error::DomainResult;
        use hort_domain::ports::ephemeral_store::EphemeralStore;
        use hort_domain::ports::BoxFuture;

        struct FailingEphemeral;
        impl EphemeralStore for FailingEphemeral {
            fn get(&self, _key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
            fn put(&self, _k: &str, _v: Bytes, _t: Duration) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
            fn put_if_absent(
                &self,
                _k: &str,
                _v: Bytes,
                _t: Duration,
            ) -> BoxFuture<'_, DomainResult<bool>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
            fn compare_and_swap(
                &self,
                _k: &str,
                _e: u64,
                _v: Bytes,
                _t: Duration,
            ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
            fn delete(&self, _k: &str) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
            fn extend_ttl(&self, _k: &str, _t: Duration) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
        }

        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, _mocks) = build_mock_ctx(handle);
            let mut base = Arc::try_unwrap(base)
                .unwrap_or_else(|_| panic!("build_mock_ctx must return a sole Arc owner"));
            base.ephemeral_durable = Arc::new(FailingEphemeral);
            let ctx = Arc::new(base);

            let err = admit(
                &ctx,
                "oci",
                Uuid::new_v4(),
                "myrepo",
                Uuid::new_v4(),
                Uuid::new_v4(),
                4,
                TEST_MAX_AGE,
            )
            .await
            .expect_err("failing ephemeral must surface an error");
            assert!(matches!(err, AppError::Domain(DomainError::Invariant(_))));
        });
    }

    // -------------------- contention → Contended --------------------

    #[test]
    fn admit_returns_contended_on_retry_budget_exhaustion() {
        use hort_domain::error::DomainResult;
        use hort_domain::ports::ephemeral_store::EphemeralStore;
        use hort_domain::ports::BoxFuture;

        // A store that always presents a below-cap set on `get` but whose
        // `compare_and_swap` *never* wins (perpetual version race). Every
        // reconcile iteration re-reads, re-CASes, loses, retries — until
        // the bounded loop exhausts. That is the pathological-contention
        // path, and it must surface as `AdmitOutcome::Contended` (a
        // transient `503`), NOT an `Err` (a `500`).
        struct AlwaysRacingEphemeral;
        impl EphemeralStore for AlwaysRacingEphemeral {
            fn get(&self, _key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
                // One live member, cap will be > 1 in the test, so the
                // admit reaches the CAS branch (not the OverCap branch).
                let set = SessionSet {
                    version: 1,
                    members: vec![SessionMember {
                        id: 1,
                        created_at_ms: Utc::now().timestamp_millis(),
                    }],
                };
                let bytes = encode_session_set(&set).unwrap();
                Box::pin(async move { Ok(Some(bytes)) })
            }
            fn put(&self, _k: &str, _v: Bytes, _t: Duration) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn put_if_absent(
                &self,
                _k: &str,
                _v: Bytes,
                _t: Duration,
            ) -> BoxFuture<'_, DomainResult<bool>> {
                Box::pin(async { Ok(true) })
            }
            fn compare_and_swap(
                &self,
                _k: &str,
                _e: u64,
                _v: Bytes,
                _t: Duration,
            ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
                // Perpetual version race — the CAS never succeeds.
                Box::pin(async { Ok(None) })
            }
            fn delete(&self, _k: &str) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
            fn extend_ttl(&self, _k: &str, _t: Duration) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (base, _mocks) = build_mock_ctx(handle);
            let mut base = Arc::try_unwrap(base)
                .unwrap_or_else(|_| panic!("build_mock_ctx must return a sole Arc owner"));
            base.ephemeral_durable = Arc::new(AlwaysRacingEphemeral);
            let ctx = Arc::new(base);

            let out = admit(
                &ctx,
                "oci",
                Uuid::new_v4(),
                "myrepo",
                Uuid::new_v4(),
                Uuid::new_v4(),
                4,
                TEST_MAX_AGE,
            )
            .await
            .expect("retry-budget exhaustion is a transient outcome, never an Err");
            assert!(
                matches!(out, AdmitOutcome::Contended),
                "perpetual CAS contention must surface as Contended, got {out:?}"
            );
        });
    }
}
