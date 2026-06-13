//! # hort-adapters-secrets::metrics — label names, value constants, result enum
//!
//! Owns the metric label names and the `SecretResolveResult` taxonomy emitted
//! by the secret-resolution adapters, plus the adapter-side boundary mapping
//! from [`SecretError`] to [`DomainError`]. Together these three concerns
//! describe the full classification + emission boundary used by the
//! adapters: the `result` label (which `SecretResolveResult` variant fired),
//! the metric-emission helper, and the wire-format translation returned to
//! callers of [`SecretPort`].
//!
//! The canonical metric catalog lives at `docs/metrics-catalog.md`. Every
//! string in this module corresponds to a row in that catalog. A new label
//! value or result variant requires a catalog update first.
//!
//! [`SecretError`]: hort_domain::ports::secret_port::SecretError
//! [`DomainError`]: hort_domain::error::DomainError
//! [`SecretPort`]: hort_domain::ports::secret_port::SecretPort

use hort_domain::error::DomainError;
use hort_domain::ports::secret_port::SecretError;

/// Label-name constants used as keys when emitting secret-resolution metrics.
/// Using constants (rather than string literals at call sites) prevents
/// typos from silently producing a different time series.
pub mod labels {
    /// Source identifier — matches `SecretRef::source` of the input.
    pub const SOURCE: &str = "source";
    /// Outcome classification for a resolve call.
    pub const RESULT: &str = "result";
}

/// Enumerable label-value constants the adapters emit for `source`.
pub mod values {
    /// Source label value for the env-var adapter.
    pub const SOURCE_ENV_VAR: &str = "env_var";
    /// Source label value for the mounted-file adapter.
    pub const SOURCE_FILE: &str = "file";
}

/// Outcome of a `SecretPort::resolve` call, used as the `result` label of
/// `hort_secret_resolve_total`.
///
/// String values are normative. They are part of the public metrics contract
/// declared in `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretResolveResult {
    /// Secret read; bytes returned to the caller.
    Success,
    /// Env var not set, or file does not exist.
    NotFound,
    /// File existed but could not be read (permission denied, mid-rotation
    /// race, generic I/O error). Always operator-actionable.
    ReadFailure,
    /// Env var contains non-UTF-8 bytes, or the dispatcher mis-routed a
    /// `SecretRef` to the wrong adapter (defensive — `DispatchSecretPort`
    /// is the trust boundary).
    DecodeError,
}

impl SecretResolveResult {
    /// Label value string. Must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NotFound => "not_found",
            Self::ReadFailure => "read_failure",
            Self::DecodeError => "decode_error",
        }
    }
}

/// Canonical metric name for the resolve counter.
pub const METRIC_RESOLVE_TOTAL: &str = "hort_secret_resolve_total";

/// Emit one increment of `hort_secret_resolve_total{source, result}`.
/// Centralised so all adapter call sites cannot drift on metric name or
/// label-key spelling.
pub(crate) fn emit_resolve(source: &'static str, result: SecretResolveResult) {
    metrics::counter!(
        METRIC_RESOLVE_TOTAL,
        labels::SOURCE => source,
        labels::RESULT => result.as_str(),
    )
    .increment(1);
}

/// Adapter-side boundary mapping from [`SecretError`] (used internally to
/// classify which metric `result` label to fire) to [`DomainError::Invariant`]
/// (the format the [`SecretPort`] trait returns to callers).
///
/// Single source of truth: every adapter routes its terminal `Err` arm
/// through this function so the wire format stays consistent. Adding a
/// new error classification means updating this and the metric enum
/// together.
///
/// [`SecretError`]: hort_domain::ports::secret_port::SecretError
/// [`SecretPort`]: hort_domain::ports::secret_port::SecretPort
pub(crate) fn classify_to_domain_error(err: &SecretError) -> DomainError {
    DomainError::Invariant(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        classify_to_domain_error, labels, values, SecretResolveResult, METRIC_RESOLVE_TOTAL,
    };
    use hort_domain::error::DomainError;
    use hort_domain::ports::secret_port::SecretError;
    use std::collections::HashSet;

    #[test]
    fn label_source_is_source() {
        assert_eq!(labels::SOURCE, "source");
    }

    #[test]
    fn label_result_is_result() {
        assert_eq!(labels::RESULT, "result");
    }

    #[test]
    fn source_env_var_value() {
        assert_eq!(values::SOURCE_ENV_VAR, "env_var");
    }

    #[test]
    fn source_file_value() {
        assert_eq!(values::SOURCE_FILE, "file");
    }

    #[test]
    fn metric_name_is_pinned() {
        assert_eq!(METRIC_RESOLVE_TOTAL, "hort_secret_resolve_total");
    }

    #[test]
    fn result_strings() {
        assert_eq!(SecretResolveResult::Success.as_str(), "success");
        assert_eq!(SecretResolveResult::NotFound.as_str(), "not_found");
        assert_eq!(SecretResolveResult::ReadFailure.as_str(), "read_failure");
        assert_eq!(SecretResolveResult::DecodeError.as_str(), "decode_error");
    }

    #[test]
    fn result_strings_are_unique() {
        let variants = [
            SecretResolveResult::Success,
            SecretResolveResult::NotFound,
            SecretResolveResult::ReadFailure,
            SecretResolveResult::DecodeError,
        ];
        let set: HashSet<&'static str> = variants.iter().map(SecretResolveResult::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn source_values_are_unique() {
        let set: HashSet<&'static str> = [values::SOURCE_ENV_VAR, values::SOURCE_FILE]
            .into_iter()
            .collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn classify_wraps_as_invariant() {
        let de = classify_to_domain_error(&SecretError::ReadFailure("io".into()));
        match de {
            DomainError::Invariant(msg) => assert!(msg.contains("io"), "got: {msg}"),
            other => panic!("expected Invariant, got {other:?}"),
        }
    }
}
