//! # Authorization extractors
//!
//! `FromRequestParts` extractors that enforce RBAC at the handler signature
//! boundary rather than via inline `rbac.authorize(...)` calls. Handlers
//! declare one of the four extractors as a parameter; forgetting the
//! extractor leaves the handler with only the raw `CallerPrincipal` (or
//! nothing), which has no admin-typed or repo-scoped operations in scope —
//! so the compiler stops the code from compiling before it stops the
//! request from being served.
//!
//! `DeleteRepoAccess` covers endpoints that destroy landed content
//! (currently only OCI manifest delete). The delete-vs-write boundary is
//! "is the operator destroying landed content visible to other readers" —
//! cancel/finalize of an in-flight upload stays on `WriteRepoAccess`.
//!
//! The RBAC/claims model the extractors enforce is ADR 0012.
//!
//! ## Failure shapes
//!
//! - Principal missing under `AuthContext::Enabled` → `500` (router-wiring
//!   bug; `require_principal` layer didn't run). Matches the existing
//!   behaviour in `handlers/pypi.rs::resolve_actor_user_id`.
//! - RBAC deny → `403 {"error":"insufficient permissions"}`. Body is
//!   load-bearing — native clients match on it.
//! - Repo-scoped extractor, `repo_key` does not resolve → `404 {"error":"repository not found"}`.
//!   Distinct from `403` to keep the 403 signal pure; distinct from
//!   `403` specifically to avoid the enumeration-oracle where "forbidden"
//!   confirms existence. Emits `hort_http_404_repo_lookups_total{format}`
//!   (separate from `hort_authz_decisions_total` so brute-force
//!   dashboards watching `deny` spikes stay decoupled from enumeration
//!   dashboards watching 404 spikes).
//!
//! ## Emission sites
//!
//! `hort_authz_decisions_total{permission, result}` fires from exactly one
//! spot per extractor (the shared [`emit_authz_decision`] helper). No
//! per-handler duplication. The existing `handlers/pypi.rs:696`
//! `emit_authz_metric` helper stays in place until Sprint 3 migrates its
//! call sites to these extractors — this change ships the primitive only.

pub mod extractors;
pub mod write;

pub use extractors::{
    AdminPrincipal, CurateOrAdminPrincipal, DeleteRepoAccess, MetricsReaderPrincipal,
    ReadRepoAccess, WriteRepoAccess,
};

// ---------------------------------------------------------------------------
// Metric emission — shared by every extractor
// ---------------------------------------------------------------------------

/// Catalog: `docs/metrics-catalog.md` — `hort_authz_decisions_total`.
///
/// `permission` ∈ `{admin, read, write, delete, curate, read_metrics}`;
/// `result` ∈ `{allow, deny}`. Any other value is a programming error and
/// must be caught in review. (`delete` lights up via `DeleteRepoAccess`'s
/// live emission site; `curate` via the `CurateOrAdminPrincipal`
/// extractor — each successful or denied curate-or-admin decision
/// lights up `permission="curate"` so dashboards can watch the curator
/// surface independently of the global admin gate; `read_metrics` via
/// `MetricsReaderPrincipal`, issue #113.)
///
/// The metric carries NO `repository` label — deliberate
/// cardinality-control decision. Per-repo
/// drill-down lives in tracing spans (deny logs carry `user_id` +
/// `permission` as structured fields).
pub(crate) fn emit_authz_decision(permission: &'static str, result: &'static str) {
    metrics::counter!(
        "hort_authz_decisions_total",
        "permission" => permission,
        "result" => result,
    )
    .increment(1);
}

/// Catalog: `docs/metrics-catalog.md` — `hort_authz_denials_total`.
///
/// Deny-only sibling of [`emit_authz_decision`], carrying WHICH leg of the
/// two-leg authorization AND produced the deny. `reason` comes from
/// [`hort_app::rbac::AuthzDecision::denial_reason`] — `{grants, cap, both}`
/// — so the label spelling cannot drift from the variant set.
///
/// **Why a sibling series and not a `reason` label on
/// `hort_authz_decisions_total`.** That counter is also emitted from
/// composite gates ([`CurateOrAdminPrincipal`]) which evaluate two
/// permissions and deny on the pair: neither decision describes the deny on
/// its own, so a `reason` label there would have to carry an `unknown`
/// value — forcing a meaningless value into a catalogued series at exactly
/// the sites where the answer is hardest to read. A separate series is
/// simply absent at those sites instead, and `hort_authz_decisions_total`
/// stays the complete decision count.
///
/// [`CurateOrAdminPrincipal`] is also the ONLY emitter of
/// `permission="curate"`, so no `curate` series exists on this counter at
/// all — every value it does carry comes from the shared `authorize` helper,
/// which has exactly one decision per request.
///
/// Cardinality is bounded by permissions × three reasons, deny paths only,
/// and carries **no** `repository` label — the same cardinality-control
/// decision [`emit_authz_decision`] documents. Per-repo drill-down lives in
/// the deny log's structured fields.
pub(crate) fn emit_authz_denial(permission: &'static str, reason: &'static str) {
    metrics::counter!(
        "hort_authz_denials_total",
        "permission" => permission,
        "reason" => reason,
    )
    .increment(1);
}

/// Catalog: `docs/metrics-catalog.md` — `hort_http_404_repo_lookups_total`.
///
/// `format` is the resolved [`hort_domain::entities::repository::RepositoryFormat`]'s
/// `Display` string when known, or the sentinel `"unknown"` when the
/// request hit a 404 *before* a repository aggregate could be resolved
/// (which is precisely the case this metric exists to track). Do NOT
/// feed UUIDs or raw `repo_key` values — cardinality control.
pub(crate) fn emit_repo_not_found(format: &'static str) {
    metrics::counter!(
        "hort_http_404_repo_lookups_total",
        "format" => format,
    )
    .increment(1);
}
