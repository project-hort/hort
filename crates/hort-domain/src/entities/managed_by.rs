//! `ManagedBy` — provenance flag for entities that can be declared
//! either via the public CRUD API or the gitops apply pipeline.
//!
//! See `docs/architecture/how-to/declare-gitops-config.md`. Only
//! gitops-declarable kinds (`Repository`, `GroupMapping`, …) carry the
//! field; auxiliary CRUD (users, API tokens, etc.) stays `Local` by
//! definition.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// Whether an entity originated from the public CRUD API or from
/// the gitops apply pipeline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedBy {
    /// Created/modified via the public REST/gRPC API. Default for any
    /// row inserted by `RepositoryUseCase::create` etc. —
    /// `ApplyConfigUseCase` does NOT call those use cases; it uses
    /// dedicated managed-write port methods that set `GitOps`.
    #[default]
    Local,
    /// Created/modified by a gitops apply. The public CRUD path on this
    /// row returns `409 Managed by configuration`.
    GitOps,
}

impl fmt::Display for ManagedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => f.write_str("local"),
            Self::GitOps => f.write_str("gitops"),
        }
    }
}

impl FromStr for ManagedBy {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "gitops" => Ok(Self::GitOps),
            _ => Err(DomainError::Validation(format!("unknown managed_by: {s}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_lowercase() {
        assert_eq!(ManagedBy::Local.to_string(), "local");
        assert_eq!(ManagedBy::GitOps.to_string(), "gitops");
    }

    #[test]
    fn from_str_round_trip() {
        for v in [ManagedBy::Local, ManagedBy::GitOps] {
            let parsed: ManagedBy = v.to_string().parse().unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!("LOCAL".parse::<ManagedBy>().unwrap(), ManagedBy::Local);
        assert_eq!("GitOps".parse::<ManagedBy>().unwrap(), ManagedBy::GitOps);
    }

    #[test]
    fn from_str_unknown_is_validation_err() {
        let err = "managed".parse::<ManagedBy>().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("managed"));
    }

    #[test]
    fn default_is_local() {
        // The migration-side default is `'local'` — the Rust default
        // mirrors that so adapter row mappers and test fixtures can
        // call `ManagedBy::default()` without surprises. The gitops
        // apply path explicitly writes `GitOps`; nothing else does.
        assert_eq!(ManagedBy::default(), ManagedBy::Local);
    }
}
