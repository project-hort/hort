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

    /// The write lost a **concurrency race inside the storage engine** and
    /// was rolled back whole: nothing was applied, and re-running the
    /// identical request is expected to succeed once the contending writer
    /// finishes. Two near-simultaneous writers touching the same row is the
    /// canonical producer.
    ///
    /// Kept separate from its two neighbours because the correct caller
    /// response differs in each case:
    ///
    /// - [`Self::Conflict`] is a *decided* outcome — a real duplicate, or an
    ///   optimistic-concurrency clash against a position someone else took.
    ///   Re-running it returns the same answer, so a caller must not treat it
    ///   as retryable, and a retry layer must never widen onto it. That
    ///   separation is what keeps idempotent re-writes idempotent.
    /// - [`Self::Invariant`] is a breach that re-running cannot fix.
    ///
    /// The storage adapter retries this class itself, bounded, so the variant
    /// only reaches a caller once that budget is spent. At that point it
    /// still means "the system is contended right now", not "the server is
    /// broken" — so the HTTP boundary owes the client a 503 with a retry
    /// hint, never a 500.
    #[error("contended: {0}")]
    Contended(String),

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

    /// An upstream index/metadata body failed to parse or project (a
    /// content fault, not a network failure). Carries no upstream-
    /// derived text — the parse cause is attacker-influenced (it comes
    /// straight out of the upstream response body) and is logged
    /// server-side by the caller instead. Mirrors the sanitisation
    /// discipline `UpstreamBodyTooLarge` established: the wire layer
    /// renders a fixed message, never the inner cause.
    #[error("upstream metadata invalid")]
    UpstreamMetadataInvalid,

    /// Several exclusions on one scan policy carry the CVE the caller
    /// named, and the request did not say which of them to act on.
    ///
    /// An exclusion's identity is its `exclusion_id`; a CVE identifies a
    /// *set* of them, because a policy may hold one row per
    /// `package_pattern` for the same CVE. Choosing a row out of that set
    /// by anything other than its identity lets the read model's ordering
    /// decide which suppression ends, and leaves the rest unreachable
    /// through the same route — so the ambiguity is reported to the only
    /// party that can resolve it rather than guessed.
    ///
    /// Carries the `candidates` so the caller can repeat the request
    /// naming one: the wire layer renders them as structured members, and
    /// a caller must never have to recover an identifier by parsing an
    /// error sentence. Maps to **409 Conflict** at the HTTP boundary (the
    /// resource's state is incompatible with the transition as
    /// requested) — distinct from [`Self::Conflict`], which this codebase
    /// reserves for event-store optimistic-concurrency version
    /// conflicts, and from [`Self::Invariant`], which is a server fault.
    /// See ADR 0025.
    #[error("{} exclusions match {cve_id}; name one by exclusion_id", candidates.len())]
    AmbiguousExclusion {
        cve_id: String,
        candidates: Vec<ExclusionCandidate>,
    },
}

/// One candidate row in a [`DomainError::AmbiguousExclusion`]: the
/// identity the caller must name for the request to succeed, plus the
/// only field that tells two exclusions for the same CVE apart.
///
/// Deliberately not the whole exclusion row — a caller resolving the
/// ambiguity needs the identity and the discriminator, and nothing else
/// on the row (its reason, its scope, its author) helps them choose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExclusionCandidate {
    pub exclusion_id: uuid::Uuid,
    pub package_pattern: Option<String>,
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
    fn upstream_metadata_invalid_display_carries_no_cause() {
        let err = DomainError::UpstreamMetadataInvalid;
        assert_eq!(err.to_string(), "upstream metadata invalid");
    }

    #[test]
    fn ambiguous_exclusion_display_counts_the_candidates_and_names_the_cve() {
        let err = DomainError::AmbiguousExclusion {
            cve_id: "CVE-2026-0001".into(),
            candidates: vec![
                ExclusionCandidate {
                    exclusion_id: uuid::Uuid::nil(),
                    package_pattern: None,
                },
                ExclusionCandidate {
                    exclusion_id: uuid::Uuid::nil(),
                    package_pattern: Some("pkg:npm/left-pad@*".into()),
                },
            ],
        };
        assert_eq!(
            err.to_string(),
            "2 exclusions match CVE-2026-0001; name one by exclusion_id"
        );
    }

    #[test]
    fn ambiguous_exclusion_clone_preserves_its_candidates() {
        // The candidates are the actionable part of this variant — a
        // caller repeats the request naming one of them — so a clone
        // that dropped or reordered them would hand the wire layer a
        // body that cannot resolve the ambiguity it reports.
        let pattern_id = uuid::Uuid::new_v4();
        let err = DomainError::AmbiguousExclusion {
            cve_id: "CVE-2026-0002".into(),
            candidates: vec![ExclusionCandidate {
                exclusion_id: pattern_id,
                package_pattern: Some("pkg:pypi/requests@*".into()),
            }],
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
        match cloned {
            DomainError::AmbiguousExclusion { cve_id, candidates } => {
                assert_eq!(cve_id, "CVE-2026-0002");
                assert_eq!(
                    candidates,
                    vec![ExclusionCandidate {
                        exclusion_id: pattern_id,
                        package_pattern: Some("pkg:pypi/requests@*".into()),
                    }]
                );
            }
            other => panic!("clone must preserve the variant, got {other:?}"),
        }
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
