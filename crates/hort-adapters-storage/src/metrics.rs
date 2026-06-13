//! # hort-adapters-storage::metrics -- label names, value constants, result enum
//!
//! Owns the metric label names and the `StorageResult` taxonomy emitted by
//! the storage adapters. Contains no emission code at the module boundary
//! -- only canonical string constants, the result enum, and small internal
//! helpers used by the backends to keep emission uniform.
//!
//! The canonical metric catalog lives at `docs/metrics-catalog.md`. Every
//! string in this module corresponds to a row in that catalog. A new metric
//! name or label value requires a catalog update first.
//!
//! Layering (design doc section 1): each adapter owns its own result taxonomy.
//! The storage adapter does NOT depend on `hort-app::metrics`, and the domain
//! layer has no knowledge of metrics at all. 5-10 variants of duplication is
//! cheaper than a shared dependency that pulls metric concerns into the
//! domain layer.

/// Label-name constants used as keys when emitting storage metrics with the
/// `metrics` crate macros. Using constants (rather than string literals at
/// call sites) prevents typos from silently producing a different time series.
pub mod labels {
    /// Storage backend identifier (`filesystem`, `s3`, `memory`, ...).
    pub const BACKEND: &str = "backend";
    /// Low-level operation identifier (`put`, `get`, `exists`).
    pub const OPERATION: &str = "operation";
    /// Outcome classification for a storage operation.
    pub const RESULT: &str = "result";
}

/// Enumerable label-value constants that storage adapters emit.
///
/// Only values that are enumerable and re-used at multiple emission sites
/// live here. Free-form values (hashes, paths) never appear in labels.
pub mod values {
    /// Backend label value for the local filesystem adapter.
    pub const BACKEND_FILESYSTEM: &str = "filesystem";
    /// Backend label value for an AWS/MinIO/Garage S3-compatible backend.
    pub const BACKEND_S3: &str = "s3";
    /// Backend label value for Google Cloud Storage.
    pub const BACKEND_GCS: &str = "gcs";
    /// Backend label value for Azure Blob Storage.
    pub const BACKEND_AZURE: &str = "azure";
    /// Backend label value for the in-memory backend (used by tests only).
    pub const BACKEND_MEMORY: &str = "memory";

    /// Operation label value for `StoragePort::put`.
    pub const OPERATION_PUT: &str = "put";
    /// Operation label value for `StoragePort::get`.
    pub const OPERATION_GET: &str = "get";
    /// Operation label value for `StoragePort::exists`.
    pub const OPERATION_EXISTS: &str = "exists";
    /// Operation label value for `StoragePort::delete`.
    ///
    /// Emitted by the ingest declared-hash mismatch rollback path —
    /// request-serving handlers do not call `delete`. Observed frequency
    /// is bounded by declared-hash violation rate.
    pub const OPERATION_DELETE: &str = "delete";
}

/// Outcome of a storage operation, used as the `result` label of
/// `hort_storage_operations_total`.
///
/// String values are normative. They are part of the public metrics contract
/// declared in `docs/metrics-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageResult {
    /// Operation completed successfully.
    Success,
    /// The requested content hash was not found in the backend.
    NotFound,
    /// Backend I/O or protocol failure.
    Error,
}

impl StorageResult {
    /// Label value string. Must match the catalog exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NotFound => "not_found",
            Self::Error => "error",
        }
    }
}

/// Emit the standard pair of storage metrics (counter + duration histogram)
/// for a single operation. Centralised so the three operations in each
/// backend cannot drift on metric name, label name, or emission order.
///
/// - `hort_storage_operations_total{backend, operation, result}` is incremented.
/// - `hort_storage_operation_duration_seconds{backend, operation}` records the
///   elapsed time in seconds (as `f64`).
pub(crate) fn emit_operation(
    backend: &'static str,
    operation: &'static str,
    result: StorageResult,
    elapsed: std::time::Duration,
) {
    metrics::counter!(
        "hort_storage_operations_total",
        labels::BACKEND => backend,
        labels::OPERATION => operation,
        labels::RESULT => result.as_str(),
    )
    .increment(1);
    metrics::histogram!(
        "hort_storage_operation_duration_seconds",
        labels::BACKEND => backend,
        labels::OPERATION => operation,
    )
    .record(elapsed.as_secs_f64());
}

/// Emit the `hort_storage_dedup_total{backend}` counter. Called from the `put`
/// short-circuit branch when the content hash already exists in the backend.
pub(crate) fn emit_dedup(backend: &'static str) {
    metrics::counter!(
        "hort_storage_dedup_total",
        labels::BACKEND => backend,
    )
    .increment(1);
}

/// Emit the `hort_storage_blobs_deleted_bytes_total{backend}` counter,
/// incremented by the size in bytes of a CAS blob that was just
/// successfully deleted (ADR 0020 — storage-reclamation metric).
///
/// **Emission contract.** Called from `StoragePort::delete`'s
/// successful-delete branch only, with `bytes` = the object size
/// stat'd *before* the delete. An already-absent blob (the
/// `DomainError::NotFound` / idempotent re-purge path, §6 invariant 4)
/// does NOT call this — re-running a purge on a gone blob reclaims
/// nothing, so double-counting on retry is impossible by construction.
/// `backend` is the only label (bounded — `filesystem` / `s3` / `gcs`
/// / `azure` / `memory`); no `content_hash` / `artifact_id` (the
/// architect high-cardinality hard-block — those stay in `tracing`).
pub(crate) fn emit_blob_deleted_bytes(backend: &'static str, bytes: u64) {
    metrics::counter!(
        "hort_storage_blobs_deleted_bytes_total",
        labels::BACKEND => backend,
    )
    .increment(bytes);
}

/// Emit the `hort_storage_integrity_failures_total{backend}` counter. Called
/// from the `VerifyingReader::on_mismatch` callback wired by each adapter's
/// `get` path (ADR 0003). Fires exactly once per mismatched read —
/// `VerifyingReader` takes the callback via `Option::take` so a single reader
/// that is polled to EOF multiple times (hypothetical misuse) cannot
/// double-count.
pub(crate) fn emit_integrity_failure(backend: &'static str) {
    metrics::counter!(
        "hort_storage_integrity_failures_total",
        labels::BACKEND => backend,
    )
    .increment(1);
}

/// RAII guard that emits the standard pair of storage metrics when dropped.
/// Created at the top of each `StoragePort` method; callers flip the
/// terminal state to the expected outcome via `finish_success()` or
/// `finish_not_found()`. The default result is `Error`, so a panic or
/// early `?` return still produces a metric with `result="error"` — no
/// explicit `finish_error` helper needed.
///
/// `mark_dedup()` is additive and only meaningful for `put`.
pub(crate) struct MetricGuard {
    backend: &'static str,
    operation: &'static str,
    started: std::time::Instant,
    result: StorageResult,
    dedup: bool,
}

impl MetricGuard {
    pub(crate) fn new(backend: &'static str, operation: &'static str) -> Self {
        Self {
            backend,
            operation,
            started: std::time::Instant::now(),
            // Default to Error so an early return or panic records a failure
            // rather than silently losing the emission.
            result: StorageResult::Error,
            dedup: false,
        }
    }

    pub(crate) fn finish_success(&mut self) {
        self.result = StorageResult::Success;
    }

    pub(crate) fn finish_not_found(&mut self) {
        self.result = StorageResult::NotFound;
    }

    pub(crate) fn mark_dedup(&mut self) {
        self.dedup = true;
    }
}

impl Drop for MetricGuard {
    fn drop(&mut self) {
        emit_operation(
            self.backend,
            self.operation,
            self.result,
            self.started.elapsed(),
        );
        if self.dedup {
            emit_dedup(self.backend);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{labels, values, StorageResult};
    use std::collections::HashSet;

    #[test]
    fn label_backend_is_backend() {
        assert_eq!(labels::BACKEND, "backend");
    }

    #[test]
    fn label_operation_is_operation() {
        assert_eq!(labels::OPERATION, "operation");
    }

    #[test]
    fn label_result_is_result() {
        assert_eq!(labels::RESULT, "result");
    }

    #[test]
    fn backend_filesystem_is_filesystem() {
        assert_eq!(values::BACKEND_FILESYSTEM, "filesystem");
    }

    #[test]
    fn backend_s3_is_s3() {
        assert_eq!(values::BACKEND_S3, "s3");
    }

    #[test]
    fn backend_gcs_is_gcs() {
        assert_eq!(values::BACKEND_GCS, "gcs");
    }

    #[test]
    fn backend_azure_is_azure() {
        assert_eq!(values::BACKEND_AZURE, "azure");
    }

    #[test]
    fn backend_memory_is_memory() {
        assert_eq!(values::BACKEND_MEMORY, "memory");
    }

    #[test]
    fn operation_put_is_put() {
        assert_eq!(values::OPERATION_PUT, "put");
    }

    #[test]
    fn operation_get_is_get() {
        assert_eq!(values::OPERATION_GET, "get");
    }

    #[test]
    fn operation_exists_is_exists() {
        assert_eq!(values::OPERATION_EXISTS, "exists");
    }

    #[test]
    fn operation_delete_is_delete() {
        assert_eq!(values::OPERATION_DELETE, "delete");
    }

    #[test]
    fn backend_values_are_unique() {
        let set: HashSet<&'static str> = [
            values::BACKEND_FILESYSTEM,
            values::BACKEND_S3,
            values::BACKEND_GCS,
            values::BACKEND_AZURE,
            values::BACKEND_MEMORY,
        ]
        .into_iter()
        .collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn operation_values_are_unique() {
        let set: HashSet<&'static str> = [
            values::OPERATION_PUT,
            values::OPERATION_GET,
            values::OPERATION_EXISTS,
            values::OPERATION_DELETE,
        ]
        .into_iter()
        .collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn storage_result_success_as_str() {
        assert_eq!(StorageResult::Success.as_str(), "success");
    }

    #[test]
    fn storage_result_not_found_as_str() {
        assert_eq!(StorageResult::NotFound.as_str(), "not_found");
    }

    #[test]
    fn storage_result_error_as_str() {
        assert_eq!(StorageResult::Error.as_str(), "error");
    }

    #[test]
    fn storage_result_values_are_unique() {
        let variants = [
            StorageResult::Success,
            StorageResult::NotFound,
            StorageResult::Error,
        ];
        let set: HashSet<&'static str> = variants.iter().map(StorageResult::as_str).collect();
        assert_eq!(set.len(), variants.len());
    }

    /// `emit_blob_deleted_bytes` increments
    /// `hort_storage_blobs_deleted_bytes_total{backend}` by the exact byte
    /// count, with `backend` the only label (ADR 0020).
    #[test]
    fn emit_blob_deleted_bytes_increments_by_byte_count_with_backend_label() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::MetricKind;

        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            super::emit_blob_deleted_bytes(values::BACKEND_FILESYSTEM, 4096);
            super::emit_blob_deleted_bytes(values::BACKEND_FILESYSTEM, 11);
        });
        let entries = snap.snapshot().into_vec();
        let mut found = None;
        for (ck, _, _, dv) in &entries {
            if ck.kind() == MetricKind::Counter
                && ck.key().name() == "hort_storage_blobs_deleted_bytes_total"
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == labels::BACKEND && l.value() == values::BACKEND_FILESYSTEM)
            {
                if let DebugValue::Counter(n) = dv {
                    found = Some(*n);
                }
            }
        }
        // 4096 + 11 = 4107 — sum of bytes reclaimed (it is a counter).
        assert_eq!(found, Some(4107));
    }
}
