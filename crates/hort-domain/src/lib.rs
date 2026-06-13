//! # hort-domain — Domain Layer
//!
//! Pure Rust. Zero I/O. No axum, no sqlx, no reqwest, no tokio (except in tests).
//!
//! Contains:
//! - Domain entities and aggregates (Artifact, Repository, User, Policy, …)
//! - Domain events (ArtifactIngested, ArtifactQuarantined, ScanCompleted, …)
//! - Outbound port traits (ArtifactRepository, StoragePort, EventPort, …)
//! - Domain invariants and state transition rules
//!
//! Nothing in this crate may perform I/O. All I/O occurs in adapters that
//! implement the port traits defined here.

pub mod entities;
pub mod error;
pub mod events;
pub mod oci;
pub mod policy;
pub mod ports;
pub mod retention;
pub mod types;
