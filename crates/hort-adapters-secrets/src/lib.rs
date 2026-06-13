//! # hort-adapters-secrets — Secret-Resolution Adapters
//!
//! Implements `SecretPort` for the two operator-wiring sinks HORT supports
//! out of the box: process environment variables and mounted files. Both
//! adapters are always wired; the `DispatchSecretPort` selects one per
//! resolve based on `SecretRef::source`.
//!
//! See `docs/how-to/wire-secrets.md` for the operator guide and ADR 0010
//! for the TLS / secret-handling posture.
//!
//! Depends on: hort-domain (`SecretPort` trait, `SecretRef`, `SecretValue`)
//! Used by:    hort-server (composition root wires `DispatchSecretPort`)

pub mod dispatch;
pub mod env_var;
pub mod metrics;
pub mod mounted_file;

#[cfg(test)]
pub(crate) mod test_util;

pub use dispatch::DispatchSecretPort;
pub use env_var::EnvVarSecretAdapter;
pub use mounted_file::MountedFileSecretAdapter;
