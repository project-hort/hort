//! Read-only simulation seam for retention preview byte accounting.
//!
//! The port mirrors the target-set decision made by purge: remove every
//! `content_references` source edge for the supplied artifacts, then retain
//! only target hashes whose cross-kind reference count would be zero after
//! the whole set is removed. It never mutates the projection.
//!
//! # Two bounds, two different costs
//!
//! The simulation carries two ceilings, and they are not interchangeable.
//! `max_artifacts` is checked **before** the walk runs, so it is the one that
//! keeps an oversized input away from the database. `max_targets` is checked
//! **after** it, against the walk's own output, so it bounds what the caller
//! then does per target — for the retention preview, one
//! `StoragePort::size_of` round trip each. A caller that raises one has not
//! raised the other.

use std::fmt;

use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// Which of the simulation's two ceilings stopped an exact accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationBound {
    /// The number of artifacts handed to the simulation.
    Artifacts,
    /// The number of CAS targets the simulation would return.
    Targets,
}

impl SimulationBound {
    /// The noun to use when naming this bound to an operator. Plural, so it
    /// reads correctly after a count.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Artifacts => "artifacts",
            Self::Targets => "reclaimable content targets",
        }
    }
}

/// How well the observed cardinality behind a bound rejection is known.
///
/// The distinction is load-bearing rather than pedantic: the artifact count is
/// the caller's own input and is therefore exact, while the target count is
/// deliberately never fully computed — the statement stops reading at
/// `limit + 1` rows precisely so that an oversized run does not pay for the
/// count that proves it is oversized. Reporting the second as if it were the
/// first would be an invented number, which is the one thing this whole
/// accounting path refuses to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedCardinality {
    /// Counted in full.
    Exact(u64),
    /// Known only to be at least this large.
    AtLeast(u64),
}

impl fmt::Display for ObservedCardinality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(n) => write!(f, "{n}"),
            Self::AtLeast(n) => write!(f, "at least {n}"),
        }
    }
}

/// Why an exact accounting was declined, in the terms an operator needs in
/// order to decide whether a narrower scope brings the figure back: which
/// ceiling, what it is set to, and how far over it the run stood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimulationBoundExceeded {
    pub bound: SimulationBound,
    /// The ceiling as configured by the caller.
    pub limit: u64,
    /// What the run actually presented to that ceiling.
    pub observed: ObservedCardinality,
}

/// Result of the bounded target-set simulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionContentSimulation {
    /// The complete set of CAS targets that would lose their final reference.
    Exact(Vec<ContentHash>),
    /// A configured bound was exceeded, so no potentially misleading partial
    /// target set is returned. The payload names the bound that stopped it.
    Omitted(SimulationBoundExceeded),
}

/// Outbound port for the read-only half of purge's refcount decision.
pub trait RetentionPreview: Send + Sync {
    /// Simulate removing all source edges belonging to `artifact_ids`.
    ///
    /// Implementations return [`RetentionContentSimulation::Omitted`] when
    /// either input or result cardinality exceeds the supplied bounds, naming
    /// the bound that was exceeded.
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

    fn exceeded(bound: SimulationBound, observed: ObservedCardinality) -> SimulationBoundExceeded {
        SimulationBoundExceeded {
            bound,
            limit: 10,
            observed,
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
        let omitted = RetentionContentSimulation::Omitted(exceeded(
            SimulationBound::Targets,
            ObservedCardinality::AtLeast(11),
        ));
        assert_eq!(omitted.clone(), omitted);
        assert_ne!(omitted, RetentionContentSimulation::Exact(Vec::new()));
    }

    #[test]
    fn each_bound_names_itself_for_the_operator() {
        assert_eq!(SimulationBound::Artifacts.as_str(), "artifacts");
        assert_eq!(
            SimulationBound::Targets.as_str(),
            "reclaimable content targets"
        );
    }

    #[test]
    fn an_exact_observation_reads_as_a_bare_count() {
        assert_eq!(ObservedCardinality::Exact(36_894).to_string(), "36894");
    }

    #[test]
    fn a_partial_observation_never_reads_as_a_bare_count() {
        assert_eq!(
            ObservedCardinality::AtLeast(200_001).to_string(),
            "at least 200001"
        );
    }

    #[test]
    fn a_bound_rejection_carries_bound_limit_and_observation() {
        let e = exceeded(SimulationBound::Artifacts, ObservedCardinality::Exact(11));
        assert_eq!(e.bound, SimulationBound::Artifacts);
        assert_eq!(e.limit, 10);
        assert_eq!(e.observed, ObservedCardinality::Exact(11));
        // Copy, so a caller reporting it does not have to clone the enum.
        let copied = e;
        assert_eq!(copied, e);
        assert!(format!("{e:?}").contains("Artifacts"));
    }
}
