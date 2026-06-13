//! # hort-adapters-storage — Storage Backend Implementations
//!
//! Implements `StoragePort` with enforced content-addressable storage (CAS).
//! The interface is streaming: `put(Box<dyn AsyncRead>) -> ContentHash` —
//! callers never supply storage keys and SHA-256 is computed incrementally
//! so memory usage is bounded regardless of artifact size.
//!
//! Depends on: hort-domain (StoragePort trait, ContentHash type)
//! Used by:    hort-server (composition root), hort-formats (WASM host)
//!
//! Backends:
//! - FilesystemStorage — local filesystem, sharded by content hash
//! - ObjectStoreStorage — S3/GCS/Azure via the `object_store` crate

pub mod builders;
mod cas;
pub(crate) mod extra_ca;
pub mod filesystem;
pub mod filesystem_stateful_upload_staging;
pub(crate) mod integrity;
pub mod metadata_mirror;
pub mod metrics;
pub mod object_store_backend;
#[cfg(test)]
pub(crate) mod range_contract;

pub use filesystem::FilesystemStorage;
pub use metadata_mirror::{FilesystemMetadataMirror, ObjectStoreMetadataMirror};
pub use object_store_backend::ObjectStoreStorage;
