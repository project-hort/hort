/// Domain-layer errors.
///
/// These represent business-rule violations and lookup failures — never
/// infrastructure problems (database down, network timeout). Adapters catch
/// infrastructure errors and map them to [`AppError`](../hort_app) variants;
/// only domain-meaningful failures surface here.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DomainError {
    #[error("not found: {entity} {id}")]
    NotFound { entity: &'static str, id: String },

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("validation: {0}")]
    Validation(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("{0}")]
    Invariant(String),

    /// Caller-reachable state-machine precondition violation: the request
    /// is well-formed and understood, but the target resource is in a
    /// state incompatible with the requested transition (e.g. releasing a
    /// `rejected` artifact, promoting a `quarantined` one). Maps to
    /// **409 Conflict** at the HTTP boundary — the operator can act on it.
    ///
    /// Distinct from [`Self::Conflict`], which this codebase reserves for
    /// event-store optimistic-concurrency version conflicts, and from
    /// [`Self::Invariant`], which is a should-never-happen-via-a-correct-
    /// caller internal breach (→ 500). Use this for guards a client can
    /// legitimately reach by choosing a target in the wrong state. See
    /// ADR 0025.
    #[error("{0}")]
    InvalidState(String),

    /// Write attempted on a row whose
    /// provenance is the gitops apply pipeline. Returned by
    /// `RepositoryUseCase::update`/`delete` (and equivalents on
    /// future kinds the apply pipeline manages). Maps to a
    /// `409 Conflict` `application/problem+json` response at the
    /// HTTP boundary; the operator-facing message tells them to
    /// modify the YAML and restart, since gitops is restart-to-apply.
    #[error("{kind} '{name}' is managed by configuration")]
    ManagedByConfiguration { kind: &'static str, name: String },

    /// Ingest blocked by a curation rule
    /// (`policy::curation::evaluate_curation` returned
    /// [`crate::policy::curation::CurationOutcome::Block`]). The
    /// default HTTP mapping is 403 Forbidden (client-upload paths);
    /// per-format pull-through fetch handlers (npm/pypi/cargo/oci
    /// proxy) override to 404 Not Found at the handler level so the
    /// client sees the same "package does not exist" UX as a
    /// genuine upstream miss. Carries `rule_id` for audit and
    /// event emission (`CurationApplied` reuses it).
    #[error("curation rule '{rule_name}' blocked this package: {reason}")]
    CurationBlocked {
        rule_name: String,
        rule_id: uuid::Uuid,
        reason: String,
    },

    /// Upstream metadata or manifest body exceeded the
    /// configured storage backstop during fetch (ADR 0026). Distinct
    /// from the retired buffer-cap classification (`body_too_large`):
    /// this surfaces at the wire layer as a structured 502 with explicit
    /// `bytes_read` + `cap`, not folded into the generic
    /// "upstream unavailable" sanitisation.
    #[error("upstream {fetch_class} body too large: read {bytes_read} bytes, cap {cap}")]
    UpstreamBodyTooLarge {
        fetch_class: FetchClass,
        bytes_read: u64,
        cap: u64,
    },
}

/// Fetch-class discriminator for
/// [`DomainError::UpstreamBodyTooLarge`] and the matching
/// `hort_upstream_fetch_total{result}` metric labels
/// (`metadata_too_large` / `manifest_too_large`).
///
/// Two variants because the storage backstop has two distinct
/// classes (`fetch_metadata` and `fetch_manifest`) with separately
/// configurable byte caps; folding them into one error variant +
/// `FetchClass` discriminator keeps the surface bounded while letting
/// the wire-error path emit the honest classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchClass {
    Metadata,
    Manifest,
}

impl std::fmt::Display for FetchClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Metadata => f.write_str("metadata"),
            Self::Manifest => f.write_str("manifest"),
        }
    }
}

/// Convenience alias used throughout the domain and port traits.
pub type DomainResult<T> = Result<T, DomainError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_display() {
        let err = DomainError::NotFound {
            entity: "Artifact",
            id: "abc-123".into(),
        };
        assert_eq!(err.to_string(), "not found: Artifact abc-123");
    }

    #[test]
    fn conflict_display() {
        let err = DomainError::Conflict("duplicate key".into());
        assert_eq!(err.to_string(), "conflict: duplicate key");
    }

    #[test]
    fn validation_display() {
        let err = DomainError::Validation("name is required".into());
        assert_eq!(err.to_string(), "validation: name is required");
    }

    #[test]
    fn forbidden_display() {
        let err = DomainError::Forbidden("insufficient permissions".into());
        assert_eq!(err.to_string(), "forbidden: insufficient permissions");
    }

    #[test]
    fn invariant_display() {
        let err = DomainError::Invariant("quarantined artifact cannot be promoted".into());
        assert_eq!(err.to_string(), "quarantined artifact cannot be promoted");
    }

    #[test]
    fn clone_preserves_variant() {
        let err = DomainError::NotFound {
            entity: "Repository",
            id: "repo-key".into(),
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn domain_result_ok() {
        fn returns_ok() -> DomainResult<u32> {
            Ok(42)
        }
        assert_eq!(returns_ok().unwrap(), 42);
    }

    #[test]
    fn domain_result_err() {
        let result: DomainResult<u32> = Err(DomainError::Validation("bad".into()));
        assert!(result.is_err());
    }

    #[test]
    fn managed_by_configuration_display_includes_kind_and_name() {
        let err = DomainError::ManagedByConfiguration {
            kind: "repository",
            name: "npm-public".into(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("repository"));
        assert!(rendered.contains("npm-public"));
    }

    #[test]
    fn curation_blocked_display_carries_rule_name_and_reason() {
        let err = DomainError::CurationBlocked {
            rule_name: "block-event-stream".into(),
            rule_id: uuid::Uuid::nil(),
            reason: "compromised maintainer".into(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("block-event-stream"));
        assert!(rendered.contains("compromised maintainer"));
    }

    #[test]
    fn curation_blocked_clone_preserves_fields() {
        let err = DomainError::CurationBlocked {
            rule_name: "block-xz".into(),
            rule_id: uuid::Uuid::new_v4(),
            reason: "CVE-2024-3094".into(),
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }
}
