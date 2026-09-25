//! Read-only simulation seam for retention preview byte accounting.
//!
//! The port mirrors the target-set decision made by purge: remove every
//! `content_references` source edge for the supplied artifacts, then retain
//! only target hashes whose cross-kind reference count would be zero after
//! the whole set is removed. It never mutates the projection.

use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// Result of the bounded target-set simulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionContentSimulation {
    /// The complete set of CAS targets that would lose their final reference.
    Exact(Vec<ContentHash>),
    /// The configured bound was exceeded, so no potentially misleading
    /// partial target set is returned.
    Omitted,
}

/// Outbound port for the read-only half of purge's refcount decision.
pub trait RetentionPreview: Send + Sync {
    /// Simulate removing all source edges belonging to `artifact_ids`.
    ///
    /// Implementations return [`RetentionContentSimulation::Omitted`] when
    /// either input or result cardinality exceeds the supplied bounds.
    fn reclaimable_content<'a>(
        &'a self,
        artifact_ids: &'a [Uuid],
        max_artifacts: usize,
        max_targets: u32,
    ) -> BoxFuture<'a, DomainResult<RetentionContentSimulation>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Empty;

    impl RetentionPreview for Empty {
        fn reclaimable_content<'a>(
            &'a self,
            _artifact_ids: &'a [Uuid],
            _max_artifacts: usize,
            _max_targets: u32,
        ) -> BoxFuture<'a, DomainResult<RetentionContentSimulation>> {
            Box::pin(async { Ok(RetentionContentSimulation::Exact(Vec::new())) })
        }
    }

    #[tokio::test]
    async fn port_is_dyn_compatible() {
        let port: &dyn RetentionPreview = &Empty;
        assert_eq!(
            port.reclaimable_content(&[], 1, 1).await.unwrap(),
            RetentionContentSimulation::Exact(Vec::new())
        );
    }

    #[test]
    fn simulation_values_are_plain_data() {
        assert_eq!(
            RetentionContentSimulation::Omitted.clone(),
            RetentionContentSimulation::Omitted
        );
    }
}
