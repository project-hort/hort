//! # hort-adapters-oidc::metrics — JWKS refresh outcome taxonomy
//!
//! Owns the `hort_jwks_refresh_total{result}` metric. Contains label-name
//! constants, the `JwksRefreshResult` enum, and a small emission helper.
//! The canonical catalog entry lives at `docs/metrics-catalog.md`.
//!
//! Layering (architect rules): the result enum lives in the
//! adapter that emits the metric, NOT in `hort-domain` (zero-I/O) or any
//! inbound-HTTP crate. Every new label value requires a catalog update in
//! the same PR.

/// Label-name constants. Using constants (rather than string literals at call
/// sites) prevents a typo from silently producing a different time series.
pub(crate) mod labels {
    /// Outcome classification for a JWKS refresh attempt or evict decision.
    pub(crate) const RESULT: &str = "result";
    /// Issuer-name label on `hort_jwks_refresh_total`. The single-issuer
    /// call site emits the sentinel [`super::USER_LOGIN_ISSUER`]; the
    /// multi-issuer federation validator emits the trusted issuer's
    /// `OidcIssuer.name`. Cardinality is bounded by the operator's
    /// `OidcIssuer` CRD count + 1.
    pub(crate) const ISSUER: &str = "issuer";
}

/// Sentinel value emitted on the `issuer` label by the single-issuer
/// user-login validation path (`OidcProvider`). The single-issuer path
/// has no per-issuer name to thread through; the sentinel keeps the
/// multi-issuer dashboard interpretable when both code paths share
/// `hort_jwks_refresh_total`. The leading `<` / trailing `>` mark this
/// as not a user-supplied issuer name and cannot collide with one (CRD
/// `metadata.name` validates against the k8s DNS-1123 subdomain regex —
/// `<` and `>` are forbidden).
pub(crate) const USER_LOGIN_ISSUER: &str = "<user-login>";

/// Outcome of a JWKS refresh cycle, emitted as the `result` label of
/// `hort_jwks_refresh_total`.
///
/// String values are normative — they are part of the public metrics
/// contract declared in `docs/metrics-catalog.md`. Add a variant only
/// alongside a catalog update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JwksRefreshResult {
    /// Discovery + JWKS fetched, parsed, and the cache was replaced.
    Success,
    /// Signature-mismatch eviction suppressed by the per-kid backoff
    /// window. No network I/O; the cache entry stays as-is. This fires
    /// on the DoS-mitigation path.
    Throttled,
    /// Discovery or JWKS HTTP request failed (timeout, DNS, non-2xx).
    /// The cache stays stale; the triggering request 401s.
    FetchFailed,
    /// Upstream response exceeded `HORT_JWKS_RESP_BODY_MAX_SIZE`. The
    /// response is discarded un-parsed; the cache stays stale.
    BodyTooLarge,
    /// Bytes were received within the cap but failed JSON parsing.
    ParseError,
    /// Apply-time best-effort JWKS warm-up failed. Emitted by
    /// `ApplyConfigUseCase::apply_oidc_issuers` after a create/update
    /// persist when the validator's `refresh_issuer` returns an error.
    /// Distinct from `fetch_failed` (per-request runtime failure) so
    /// operator dashboards separate "the IdP was unreachable during a
    /// config push" from "the IdP went down during normal serving". The
    /// apply itself proceeds; federation will fetch lazily on first
    /// request.
    ApplyWarmupFailed,
}

impl JwksRefreshResult {
    /// Label value string. Must match the catalog exactly.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Throttled => "throttled",
            Self::FetchFailed => "fetch_failed",
            Self::BodyTooLarge => "body_too_large",
            Self::ParseError => "parse_error",
            Self::ApplyWarmupFailed => "apply_warmup_failed",
        }
    }
}

/// Emit one `hort_jwks_refresh_total{issuer, result}` increment. Centralised
/// so the emission sites in `lib.rs` (single-issuer) and
/// `multi_issuer.rs` (federation) cannot drift on metric name or label
/// name. The single-issuer call site passes [`USER_LOGIN_ISSUER`] as the
/// sentinel — see the constant's doc comment for the rationale.
pub(crate) fn emit_jwks_refresh(issuer: &str, result: JwksRefreshResult) {
    metrics::counter!(
        "hort_jwks_refresh_total",
        labels::ISSUER => issuer.to_string(),
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Outcome of a JWKS rotation **observation** — fired only when
/// `JwksCache::replace` actually changes the cached kid set, not on
/// every refresh. Supplements `hort_jwks_refresh_total` (which fires on
/// every refresh attempt regardless of whether the key set changed) so a
/// SIEM can answer "how often did the IdP actually rotate" without
/// having to compare consecutive `success` counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OidcKeyRotationResult {
    /// JWKS refresh succeeded, the kid set changed, and the
    /// `OidcKeyRotated` event was successfully appended.
    Success,
    /// JWKS refresh succeeded and the kid set changed, but appending
    /// the `OidcKeyRotated` event to the audit stream failed (event
    /// store down, optimistic-concurrency conflict, etc.). The
    /// rotation observation itself is NOT lost — the metric fires —
    /// but the durable audit record did not land. Operators should
    /// correlate this against `hort_event_store_*` failure counters.
    Failure,
}

impl OidcKeyRotationResult {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Emit one `hort_oidc_key_rotation_total{result}` increment.
/// Catalog: `docs/metrics-catalog.md`.
pub(crate) fn emit_oidc_key_rotation(result: OidcKeyRotationResult) {
    metrics::counter!(
        "hort_oidc_key_rotation_total",
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::{labels, JwksRefreshResult};
    use std::collections::HashSet;

    #[test]
    fn label_result_is_result() {
        assert_eq!(labels::RESULT, "result");
    }

    #[test]
    fn label_issuer_is_issuer() {
        assert_eq!(labels::ISSUER, "issuer");
    }

    #[test]
    fn user_login_sentinel_is_angle_bracketed() {
        // Cannot collide with a CRD `metadata.name` (DNS-1123 subdomain
        // regex forbids `<` and `>`).
        assert_eq!(super::USER_LOGIN_ISSUER, "<user-login>");
    }

    #[test]
    fn jwks_refresh_result_success_as_str() {
        assert_eq!(JwksRefreshResult::Success.as_str(), "success");
    }

    #[test]
    fn jwks_refresh_result_throttled_as_str() {
        assert_eq!(JwksRefreshResult::Throttled.as_str(), "throttled");
    }

    #[test]
    fn jwks_refresh_result_fetch_failed_as_str() {
        assert_eq!(JwksRefreshResult::FetchFailed.as_str(), "fetch_failed");
    }

    #[test]
    fn jwks_refresh_result_body_too_large_as_str() {
        assert_eq!(JwksRefreshResult::BodyTooLarge.as_str(), "body_too_large");
    }

    #[test]
    fn jwks_refresh_result_parse_error_as_str() {
        assert_eq!(JwksRefreshResult::ParseError.as_str(), "parse_error");
    }

    #[test]
    fn jwks_refresh_result_values_are_unique() {
        let variants = [
            JwksRefreshResult::Success,
            JwksRefreshResult::Throttled,
            JwksRefreshResult::FetchFailed,
            JwksRefreshResult::BodyTooLarge,
            JwksRefreshResult::ParseError,
        ];
        let set: HashSet<&'static str> = variants.iter().map(JwksRefreshResult::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn oidc_key_rotation_result_success_as_str() {
        assert_eq!(super::OidcKeyRotationResult::Success.as_str(), "success");
    }

    #[test]
    fn oidc_key_rotation_result_failure_as_str() {
        assert_eq!(super::OidcKeyRotationResult::Failure.as_str(), "failure");
    }

    #[test]
    fn oidc_key_rotation_result_values_are_unique() {
        let variants = [
            super::OidcKeyRotationResult::Success,
            super::OidcKeyRotationResult::Failure,
        ];
        let set: HashSet<&'static str> = variants
            .iter()
            .map(super::OidcKeyRotationResult::as_str)
            .collect();
        assert_eq!(set.len(), variants.len());
    }
}
