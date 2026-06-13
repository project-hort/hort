//! Storage adapter dispatch.
//!
//! Given a [`StorageConfig`], return an `Arc<dyn StoragePort>` the
//! composition root can hand to `build_app_context`. This module is the
//! only place the binary depends on the concrete storage adapters — the
//! rest of the binary is generic over `StoragePort`.

use std::sync::Arc;

use hort_adapters_storage::builders::{build_s3_object_store, build_s3_storage, S3StorageOpts};
use hort_adapters_storage::metrics::values;
use hort_adapters_storage::{
    FilesystemMetadataMirror, FilesystemStorage, ObjectStoreMetadataMirror, ObjectStoreStorage,
};
use hort_config::ExtraTrustAnchors;
use hort_domain::ports::metadata_mirror_store::MetadataMirrorStore;
use hort_domain::ports::storage::StoragePort;

use crate::config::{S3SseMode, StorageConfig};

/// Build the configured storage adapter.
///
/// `extra_trust_anchors` is threaded in from the composition root
/// (ADR 0010). When `Some`, the extra CA bundle is applied to
/// the S3 client's root certificate store via
/// [`hort_adapters_storage::builders::S3StorageOpts`]. The filesystem backend
/// is unaffected (no TLS). Composition owns the parse; this function never
/// reads `HORT_EXTRA_CA_BUNDLE` itself.
pub fn build(
    cfg: &StorageConfig,
    extra_trust_anchors: Option<&ExtraTrustAnchors>,
) -> anyhow::Result<Arc<dyn StoragePort>> {
    match cfg {
        StorageConfig::Filesystem { root } => Ok(Arc::new(FilesystemStorage::new(root.clone()))),
        StorageConfig::S3 {
            bucket,
            region,
            endpoint,
            force_path_style,
            allow_http,
            access_key_id,
            secret_access_key,
            sse_mode,
        } => {
            let opts = S3StorageOpts {
                bucket,
                region,
                endpoint: endpoint.as_deref(),
                force_path_style: *force_path_style,
                allow_http: *allow_http,
                access_key: access_key_id,
                secret_key: secret_access_key,
                extra_trust_anchors,
                sse_mode: sse_mode.as_ref().map(S3SseMode::to_adapter),
            };
            let adapter = build_s3_storage(&opts)?;
            Ok(Arc::new(adapter))
        }
    }
}

/// Build BOTH the CAS [`StoragePort`] and the raw upstream-metadata mirror
/// [`MetadataMirrorStore`] from one `StorageConfig`, sharing a SINGLE backend.
///
/// This is the composition-root entry point for the `serve` path, which needs
/// both adapters. It exists so the S3 branch constructs its
/// `Arc<dyn ObjectStore>` ONCE (one reqwest client, one connection pool, one
/// trust-anchor parse) and hands the same `Arc` to the CAS
/// [`ObjectStoreStorage`] and the [`ObjectStoreMetadataMirror`] (ADR 0026).
/// An earlier wiring called [`build`] and a separate
/// `build_metadata_mirror`, which built the S3 object store twice (a duplicate
/// client + pool); this combined builder replaces that pair on the serve path.
/// [`build`] remains for callers that need only the CAS half (e.g. `scrub`,
/// which never touches the mirror).
///
/// - **Filesystem**: the two wrappers are cheap `PathBuf` holders, so there is
///   no shared-handle concern; both are rooted at the same path.
/// - **S3 / object store**: the single [`build_s3_object_store`] result is
///   `clone`d into both wrappers (`Arc::clone`, not a second backend build).
pub fn build_with_mirror(
    cfg: &StorageConfig,
    extra_trust_anchors: Option<&ExtraTrustAnchors>,
) -> anyhow::Result<(Arc<dyn StoragePort>, Arc<dyn MetadataMirrorStore>)> {
    match cfg {
        StorageConfig::Filesystem { root } => Ok((
            Arc::new(FilesystemStorage::new(root.clone())),
            Arc::new(FilesystemMetadataMirror::new(root.clone())),
        )),
        StorageConfig::S3 {
            bucket,
            region,
            endpoint,
            force_path_style,
            allow_http,
            access_key_id,
            secret_access_key,
            sse_mode,
        } => {
            let opts = S3StorageOpts {
                bucket,
                region,
                endpoint: endpoint.as_deref(),
                force_path_style: *force_path_style,
                allow_http: *allow_http,
                access_key: access_key_id,
                secret_key: secret_access_key,
                extra_trust_anchors,
                sse_mode: sse_mode.as_ref().map(S3SseMode::to_adapter),
            };
            // Build the object store exactly once and share it.
            let store = build_s3_object_store(&opts)?;
            let cas: Arc<dyn StoragePort> =
                Arc::new(ObjectStoreStorage::new(store.clone(), values::BACKEND_S3));
            let mirror: Arc<dyn MetadataMirrorStore> =
                Arc::new(ObjectStoreMetadataMirror::new(store));
            Ok((cas, mirror))
        }
    }
}
