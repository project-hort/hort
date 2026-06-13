//! `TaskParams` trait and v1 parameter structs for the admin-task
//! HTTP surface. See `how-to/using-hort-cli-with-admin-ops.md` and ADR 0028.
//!
//! # Extension model
//!
//! Each task `kind` maps to a concrete `TaskParams` impl:
//!
//! - `NoopParams` and `StagingSweepParams` ship in this crate (v1).
//! - The six other v1 kinds (`scan`, `cron-rescan-tick`,
//!   `advisory-watch-tick`, `retention-evaluate`, `retention-purge`,
//!   `eventstore-archive`) are handled by a permissive
//!   [`RawTaskParams`] wrapper that forwards the request body as-is.
//!   Each consumer crate supersedes the raw handler with a typed
//!   `TaskParams` impl when its handler lands.
//!
//! # Dep-graph invariant
//!
//! This crate MUST NOT depend on any `hort-adapters-*` crate, `sqlx`, or
//! `reqwest`. The dep graph is load-bearing (ADR 0008). Run
//! `cargo tree -p hort-http-admin-tasks --edges normal --prefix none` to
//! verify; absence of `hort-adapters-*`, `sqlx`, and `reqwest` in the
//! output is the acceptance criterion.

use serde::{Deserialize, Serialize};

/// Error returned by [`TaskParams::validate`] when the params are
/// semantically invalid. Maps to HTTP 422 Unprocessable Content in
/// the handler via [`hort_http_core::error::ApiError`].
#[derive(Debug, Clone)]
pub struct ValidationError(pub String);

impl ValidationError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Implemented by every task-kind parameter struct.
///
/// The generic `invoke<P: TaskParams>` handler uses the associated
/// constant to determine the task `kind` literal, and calls `validate`
/// before forwarding the params to `TaskUseCase::enqueue`.
pub trait TaskParams: serde::de::DeserializeOwned + Serialize + Send + Sync + 'static {
    /// The `jobs.kind` literal for this parameter struct.
    /// Must be one of the values in `VALID_TASK_KINDS`.
    const KIND: &'static str;

    /// Validate the params. Returns `Err(ValidationError)` for any
    /// semantically invalid value (e.g. a string that exceeds a
    /// documented byte cap). HTTP 422 is emitted on failure.
    fn validate(&self) -> Result<(), ValidationError>;
}

// ---------------------------------------------------------------------------
// NoopParams
// ---------------------------------------------------------------------------

/// Parameters for the `noop` task kind.
///
/// The noop handler records a `TaskInvoked` event and does nothing else.
/// An optional `label` is hashed into `result_summary` by the worker so
/// CronJob operators can distinguish runs in the audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NoopParams {
    /// Optional opaque label hashed into `result_summary`.
    ///
    /// Capped at 256 bytes to prevent pathological CronJob misconfiguration
    /// (e.g. an accidental entire-config JSON dump as the label).
    #[serde(default)]
    pub label: Option<String>,
}

impl TaskParams for NoopParams {
    const KIND: &'static str = "noop";

    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(ref l) = self.label {
            if l.len() > 256 {
                return Err(ValidationError::new(
                    "label exceeds 256-byte cap (pathological CronJob config guard)",
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// StagingSweepParams
// ---------------------------------------------------------------------------

/// Parameters for the `staging-sweep` task kind.
///
/// The sweep handler scans the stateful-upload staging directory for
/// orphaned sessions and removes them. No parameters are required;
/// the empty body is accepted for forward-compatibility with future
/// filter knobs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StagingSweepParams {}

impl TaskParams for StagingSweepParams {
    const KIND: &'static str = "staging-sweep";

    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RawTaskParams — permissive fallback for untyped kinds
// ---------------------------------------------------------------------------

/// Permissive parameter wrapper used for the six task kinds whose
/// typed `TaskParams` impls have not landed yet.
///
/// The request body is deserialised into an opaque `serde_json::Value`
/// and forwarded verbatim to `TaskUseCase::enqueue`. The owning consumer
/// crate replaces this with a typed struct when its handler lands.
///
/// `KIND` is deliberately set to `""` — the `invoke` handler reads the
/// kind from a fixed associated constant on the *concrete* type at each
/// `Router::route` call site (e.g. `.route(".../scan", post(invoke::<ScanRawParams>))`).
/// `RawTaskParams` itself must never be instantiated directly at a route
/// that requires a specific kind; each of the six untyped routes uses a
/// distinct newtype below.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawTaskParams {
    #[serde(flatten)]
    pub inner: serde_json::Value,
}

impl Default for RawTaskParams {
    fn default() -> Self {
        Self {
            inner: serde_json::Value::Object(Default::default()),
        }
    }
}

/// Macro to produce a minimal newtype around `RawTaskParams` that
/// carries a specific `KIND` constant. Avoids repeating the same
/// Serialize/Deserialize + TaskParams boilerplate six times.
macro_rules! raw_kind {
    ($name:ident, $kind:literal) => {
        /// Raw (untyped) task params for the `$kind` kind.
        ///
        /// Superseded by a typed `TaskParams` impl when the owning
        /// consumer crate lands its handler.
        #[derive(Debug, Clone, Default, Serialize, Deserialize)]
        pub struct $name {
            #[serde(flatten)]
            pub inner: serde_json::Value,
        }

        impl $name {
            /// Construct from an arbitrary JSON value.
            pub fn from_value(v: serde_json::Value) -> Self {
                Self { inner: v }
            }
        }

        impl TaskParams for $name {
            const KIND: &'static str = $kind;
            fn validate(&self) -> Result<(), ValidationError> {
                Ok(())
            }
        }
    };
}

raw_kind!(ScanRawParams, "scan");
raw_kind!(CronRescanTickRawParams, "cron-rescan-tick");
raw_kind!(AdvisoryWatchTickRawParams, "advisory-watch-tick");
raw_kind!(RetentionEvaluateRawParams, "retention-evaluate");
raw_kind!(RetentionPurgeRawParams, "retention-purge");
raw_kind!(EventstoreArchiveRawParams, "eventstore-archive");
// The worker's `ServiceAccountRotationHandler` (registered in
// `hort-worker::composition`) consumes the row this route enqueues.
// Body is empty; the handler reads the target SA set from the database
// + ConfigPort and walks it itself.
raw_kind!(ServiceAccountRotationRawParams, "service-account-rotation");
// The worker's `EventstoreCheckpointHandler` consumes the row this
// route enqueues. Body is empty; the handler snapshots the live chain,
// builds the checkpoint, Ed25519-signs it, and WORM-anchors it.
raw_kind!(EventstoreCheckpointRawParams, "eventstore-checkpoint");
// The worker's `ReplaySeenPruneHandler` consumes the row this route
// enqueues. Body is empty; the handler runs one
// `DELETE FROM jwt_replay_seen WHERE expires_at < now()` tick. The
// CronJob driving this route is **default-ENABLED** — a deliberate
// divergence from the admin-task default-disabled convention.
raw_kind!(ReplaySeenPruneRawParams, "replay-seen-prune");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_params_validate_accepts_empty() {
        let p = NoopParams { label: None };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn noop_params_validate_accepts_short_label() {
        let p = NoopParams {
            label: Some("hello".to_string()),
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn noop_params_validate_rejects_long_label() {
        let p = NoopParams {
            label: Some("x".repeat(257)),
        };
        let err = p.validate().unwrap_err();
        assert!(err.0.contains("256-byte cap"));
    }

    #[test]
    fn noop_params_validate_accepts_exactly_256_bytes() {
        let p = NoopParams {
            label: Some("x".repeat(256)),
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn staging_sweep_params_validate_always_ok() {
        let p = StagingSweepParams {};
        assert!(p.validate().is_ok());
    }

    #[test]
    fn noop_kind_constant() {
        assert_eq!(NoopParams::KIND, "noop");
    }

    #[test]
    fn staging_sweep_kind_constant() {
        assert_eq!(StagingSweepParams::KIND, "staging-sweep");
    }

    #[test]
    fn raw_kind_constants() {
        assert_eq!(ScanRawParams::KIND, "scan");
        assert_eq!(CronRescanTickRawParams::KIND, "cron-rescan-tick");
        assert_eq!(AdvisoryWatchTickRawParams::KIND, "advisory-watch-tick");
        assert_eq!(RetentionEvaluateRawParams::KIND, "retention-evaluate");
        assert_eq!(RetentionPurgeRawParams::KIND, "retention-purge");
        assert_eq!(EventstoreArchiveRawParams::KIND, "eventstore-archive");
        assert_eq!(
            ServiceAccountRotationRawParams::KIND,
            "service-account-rotation"
        );
        assert_eq!(EventstoreCheckpointRawParams::KIND, "eventstore-checkpoint");
        assert_eq!(ReplaySeenPruneRawParams::KIND, "replay-seen-prune");
    }

    #[test]
    fn raw_params_validate_always_ok() {
        let p = ScanRawParams::default();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn validation_error_display() {
        let e = ValidationError::new("bad");
        assert_eq!(e.to_string(), "bad");
    }

    #[test]
    fn noop_params_roundtrip_json() {
        let p = NoopParams {
            label: Some("my-label".to_string()),
        };
        let json = serde_json::to_string(&p).unwrap();
        let p2: NoopParams = serde_json::from_str(&json).unwrap();
        assert_eq!(p2.label.as_deref(), Some("my-label"));
    }
}
