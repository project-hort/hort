//! Retention-policy scope.
//!
//! Distinct from [`crate::events::PolicyScope`] (the scan-policy
//! `{ Global, Repository(Uuid) }`) — see the [module docstring][m] for
//! why the divergence is intentional.
//!
//! [m]: super

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainResult;
use crate::events::IngestSource;

/// Upper bound on a `PackageNamePattern` glob string. Mirrors the
/// scan-policy `MAX_PACKAGE_PATTERN_LEN` (`policy_events.rs`) so the two
/// pattern surfaces share one structural guard.
const MAX_PACKAGE_PATTERN_LEN: usize = 512;

/// Upper bound on the number of explicit repository ids in a
/// [`RetentionScope::Repos`] list. A retention policy that names
/// thousands of repos individually is a misconfiguration; the
/// supported way to cover "everything" is [`RetentionScope::AllRepos`].
/// Bounded so a malformed envelope cannot smuggle an unbounded list
/// into a persisted event.
const MAX_REPOS_IN_SCOPE: usize = 1024;

/// Which artifacts a retention policy applies to.
///
/// `IngestSource` reuses the **existing**
/// [`crate::events::IngestSource`] enum (shipped on
/// `ArtifactIngested.source`) rather than minting a duplicate —
/// the §4 default for security-driven retention is
/// `IngestSource(Proxied)` (see [`Self::excludes_direct_uploads`] and
/// §6 invariant 8).
///
/// `Format` reuses the existing
/// [`crate::entities::repository::RepositoryFormat`] enum — the domain
/// already has the canonical 19-variant format taxonomy.
/// `PackageNamePattern` is a
/// validated glob string (the domain has no `Glob` newtype; the
/// exclusion model also carries package patterns as a bounded
/// `String`). `Repos` carries repository ids as `Uuid` — consistent
/// with `PolicyScope::Repository(Uuid)` and every `repository_id: Uuid`
/// in the event vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionScope {
    /// Every repository in the deployment.
    AllRepos,
    /// An explicit list of repository ids.
    Repos(Vec<Uuid>),
    /// Every repository of a given package format.
    Format(crate::entities::repository::RepositoryFormat),
    /// Artifacts whose package name matches a glob.
    PackageNamePattern(String),
    /// Restrict to artifacts whose `ArtifactIngested.source` matches.
    ///
    /// The recommended default scope for security-driven retention.
    /// `IngestSource(Proxied)` is safe to auto-delete (re-pull restores
    /// it); `IngestSource(Direct)` is not — the artifact may be the only
    /// build of that version in production.
    IngestSource(IngestSource),
}

impl RetentionScope {
    /// `true` iff this scope is provably safe for **security-driven**
    /// retention without an operator confirming the direct-upload
    /// blast radius — i.e. it cannot match a directly-uploaded
    /// artifact.
    ///
    /// Only `IngestSource(Proxied)` is provably direct-excluding:
    /// every pulled-through artifact is restorable by re-pull. Every
    /// other scope (`AllRepos`, `Repos`, `Format`, `PackageNamePattern`,
    /// and `IngestSource(Direct)` itself) *can* match a direct upload,
    /// so the apply pipeline surfaces a warning for them (that warning
    /// lives in the app/apply layer, not here — the domain layer is
    /// zero-`tracing`). This predicate is the pure decision the warning
    /// is keyed off.
    pub fn excludes_direct_uploads(&self) -> bool {
        matches!(self, Self::IngestSource(IngestSource::Proxied))
    }

    /// `true` iff this scope applies to the given artifact.
    /// Pure — zero I/O; the caller resolves
    /// the inputs (`repository_id`, the repo's [`RepositoryFormat`], the
    /// artifact `name`, and the `ArtifactIngested.source`) and this
    /// function is the total decision.
    ///
    /// This is the gate B3's `RetentionUseCase::evaluate_one` applies
    /// **before** the pure `evaluate(&predicate, …)` call: a scoped
    /// policy that does not match an artifact must never expire it. It
    /// is *not* invoked inside `evaluate()` itself — `evaluate()` only
    /// evaluates the predicate; scope is a separate, earlier gate (see
    /// the `RetentionCandidateReader` port docstring, which the
    /// candidate-reader honours by doing **no** scope SQL pre-filter).
    ///
    /// Semantics per §4 + the variant docs above:
    /// - [`AllRepos`](Self::AllRepos) → always `true`.
    /// - [`Repos`](Self::Repos) → the artifact's `repository_id` is in
    ///   the list.
    /// - [`Format`](Self::Format) → the repo's format equals the scoped
    ///   format (`RepositoryFormat` derives `PartialEq`; the
    ///   `Other(String)` arm compares by inner string).
    /// - [`PackageNamePattern`](Self::PackageNamePattern) → the artifact
    ///   `name` matches the `*`-only glob, using the **same** matcher
    ///   the exclusion model uses
    ///   ([`crate::policy::exclusion::pattern_matches`]) — one pattern
    ///   surface, one engine; `*` matches any (possibly empty)
    ///   substring, every other byte is literal.
    /// - [`IngestSource`](Self::IngestSource) → the artifact's
    ///   `ArtifactIngested.source` equals the scoped source.
    pub fn matches(
        &self,
        repository_id: Uuid,
        format: &crate::entities::repository::RepositoryFormat,
        name: &str,
        ingest_source: IngestSource,
    ) -> bool {
        match self {
            Self::AllRepos => true,
            Self::Repos(ids) => ids.contains(&repository_id),
            Self::Format(f) => f == format,
            Self::PackageNamePattern(p) => crate::policy::exclusion::pattern_matches(p, name),
            Self::IngestSource(s) => *s == ingest_source,
        }
    }

    /// Validate the scope's structural bounds. Pure — no I/O. Used by
    /// the aggregate's `Created` / `Updated` apply arms so a malformed
    /// scope cannot enter the replayed state.
    pub fn validate(&self) -> DomainResult<()> {
        match self {
            Self::Repos(ids) => {
                if ids.is_empty() {
                    return Err(crate::error::DomainError::Validation(
                        "RetentionScope::Repos must name at least one repository".into(),
                    ));
                }
                if ids.len() > MAX_REPOS_IN_SCOPE {
                    return Err(crate::error::DomainError::Validation(format!(
                        "RetentionScope::Repos exceeds the maximum of {MAX_REPOS_IN_SCOPE} \
                         repositories (got {})",
                        ids.len()
                    )));
                }
                Ok(())
            }
            Self::PackageNamePattern(p) => {
                if p.is_empty() {
                    return Err(crate::error::DomainError::Validation(
                        "RetentionScope::PackageNamePattern must not be empty".into(),
                    ));
                }
                if p.len() > MAX_PACKAGE_PATTERN_LEN {
                    return Err(crate::error::DomainError::Validation(format!(
                        "RetentionScope::PackageNamePattern exceeds the maximum length of \
                         {MAX_PACKAGE_PATTERN_LEN} (got {})",
                        p.len()
                    )));
                }
                Ok(())
            }
            Self::AllRepos | Self::Format(_) | Self::IngestSource(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::repository::RepositoryFormat;
    use crate::error::DomainError;

    // -- excludes_direct_uploads (§6 invariant 8) ----------------------------

    #[test]
    fn proxied_ingest_source_excludes_direct_uploads() {
        assert!(RetentionScope::IngestSource(IngestSource::Proxied).excludes_direct_uploads());
    }

    #[test]
    fn direct_ingest_source_does_not_exclude_direct_uploads() {
        assert!(!RetentionScope::IngestSource(IngestSource::Direct).excludes_direct_uploads());
    }

    #[test]
    fn all_repos_does_not_exclude_direct_uploads() {
        assert!(!RetentionScope::AllRepos.excludes_direct_uploads());
    }

    #[test]
    fn repos_does_not_exclude_direct_uploads() {
        assert!(!RetentionScope::Repos(vec![Uuid::nil()]).excludes_direct_uploads());
    }

    #[test]
    fn format_does_not_exclude_direct_uploads() {
        assert!(!RetentionScope::Format(RepositoryFormat::Npm).excludes_direct_uploads());
    }

    #[test]
    fn package_name_pattern_does_not_exclude_direct_uploads() {
        assert!(!RetentionScope::PackageNamePattern("xz-*".into()).excludes_direct_uploads());
    }

    // -- validate: AllRepos / Format / IngestSource (always ok) --------------

    #[test]
    fn validate_all_repos_ok() {
        RetentionScope::AllRepos.validate().unwrap();
    }

    #[test]
    fn validate_format_ok() {
        RetentionScope::Format(RepositoryFormat::Cargo)
            .validate()
            .unwrap();
    }

    #[test]
    fn validate_ingest_source_both_variants_ok() {
        RetentionScope::IngestSource(IngestSource::Proxied)
            .validate()
            .unwrap();
        RetentionScope::IngestSource(IngestSource::Direct)
            .validate()
            .unwrap();
    }

    // -- validate: Repos -----------------------------------------------------

    #[test]
    fn validate_repos_non_empty_ok() {
        RetentionScope::Repos(vec![Uuid::nil(), Uuid::nil()])
            .validate()
            .unwrap();
    }

    #[test]
    fn validate_repos_empty_rejected() {
        let err = RetentionScope::Repos(vec![]).validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("at least one repository"));
    }

    #[test]
    fn validate_repos_at_limit_ok() {
        let ids = vec![Uuid::nil(); MAX_REPOS_IN_SCOPE];
        RetentionScope::Repos(ids).validate().unwrap();
    }

    #[test]
    fn validate_repos_over_limit_rejected() {
        let ids = vec![Uuid::nil(); MAX_REPOS_IN_SCOPE + 1];
        let err = RetentionScope::Repos(ids).validate().unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("maximum"));
    }

    // -- validate: PackageNamePattern ---------------------------------------

    #[test]
    fn validate_pattern_non_empty_ok() {
        RetentionScope::PackageNamePattern("org.example.*".into())
            .validate()
            .unwrap();
    }

    #[test]
    fn validate_pattern_empty_rejected() {
        let err = RetentionScope::PackageNamePattern(String::new())
            .validate()
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_pattern_at_limit_ok() {
        RetentionScope::PackageNamePattern("x".repeat(MAX_PACKAGE_PATTERN_LEN))
            .validate()
            .unwrap();
    }

    #[test]
    fn validate_pattern_over_limit_rejected() {
        let err = RetentionScope::PackageNamePattern("x".repeat(MAX_PACKAGE_PATTERN_LEN + 1))
            .validate()
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
        assert!(err.to_string().contains("maximum length"));
    }

    // -- serde round-trip (wire stability) ----------------------------------

    #[test]
    fn serde_round_trip_every_variant() {
        let variants = vec![
            RetentionScope::AllRepos,
            RetentionScope::Repos(vec![Uuid::nil()]),
            RetentionScope::Format(RepositoryFormat::Oci),
            RetentionScope::PackageNamePattern("a/*".into()),
            RetentionScope::IngestSource(IngestSource::Proxied),
            RetentionScope::IngestSource(IngestSource::Direct),
        ];
        for v in variants {
            let json = serde_json::to_value(&v).unwrap();
            let back: RetentionScope = serde_json::from_value(json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn clone_debug_eq_cover() {
        let a = RetentionScope::Repos(vec![Uuid::nil()]);
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, RetentionScope::AllRepos);
        assert!(format!("{a:?}").contains("Repos"));
    }

    // -- matches (scope evaluation) ------------------------------------------
    //
    // Every variant gets an inclusion AND an exclusion case; `hort-domain`
    // is the 100%-coverage tier so every match arm + boundary is pinned.

    fn rid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    // `RepositoryFormat` is not `Copy`; `matches` takes it by ref, so
    // the tests pin a couple of named values rather than rebuilding the
    // enum at every call site.
    fn npm() -> RepositoryFormat {
        RepositoryFormat::Npm
    }

    #[test]
    fn matches_all_repos_is_unconditionally_true() {
        let s = RetentionScope::AllRepos;
        assert!(s.matches(rid(1), &npm(), "anything", IngestSource::Direct));
        assert!(s.matches(rid(2), &RepositoryFormat::Oci, "", IngestSource::Proxied));
    }

    #[test]
    fn matches_repos_hit() {
        let s = RetentionScope::Repos(vec![rid(1), rid(2), rid(3)]);
        assert!(s.matches(rid(2), &npm(), "pkg", IngestSource::Direct));
    }

    #[test]
    fn matches_repos_miss() {
        let s = RetentionScope::Repos(vec![rid(1), rid(2)]);
        assert!(!s.matches(rid(9), &npm(), "pkg", IngestSource::Direct));
    }

    #[test]
    fn matches_format_hit() {
        let s = RetentionScope::Format(RepositoryFormat::Cargo);
        assert!(s.matches(
            rid(1),
            &RepositoryFormat::Cargo,
            "pkg",
            IngestSource::Proxied
        ));
    }

    #[test]
    fn matches_format_miss() {
        let s = RetentionScope::Format(RepositoryFormat::Cargo);
        assert!(!s.matches(rid(1), &npm(), "pkg", IngestSource::Proxied));
    }

    #[test]
    fn matches_format_other_variant_hit_and_miss() {
        let s = RetentionScope::Format(RepositoryFormat::Other("flatpak".into()));
        assert!(s.matches(
            rid(1),
            &RepositoryFormat::Other("flatpak".into()),
            "pkg",
            IngestSource::Direct
        ));
        assert!(!s.matches(
            rid(1),
            &RepositoryFormat::Other("snap".into()),
            "pkg",
            IngestSource::Direct
        ));
    }

    #[test]
    fn matches_ingest_source_proxied_hit_and_miss() {
        let s = RetentionScope::IngestSource(IngestSource::Proxied);
        assert!(s.matches(rid(1), &npm(), "pkg", IngestSource::Proxied));
        assert!(!s.matches(rid(1), &npm(), "pkg", IngestSource::Direct));
    }

    #[test]
    fn matches_ingest_source_direct_hit_and_miss() {
        let s = RetentionScope::IngestSource(IngestSource::Direct);
        assert!(s.matches(rid(1), &npm(), "pkg", IngestSource::Direct));
        assert!(!s.matches(rid(1), &npm(), "pkg", IngestSource::Proxied));
    }

    #[test]
    fn matches_package_name_pattern_exact_hit_and_miss() {
        let s = RetentionScope::PackageNamePattern("lodash".into());
        assert!(s.matches(rid(1), &npm(), "lodash", IngestSource::Direct));
        assert!(!s.matches(rid(1), &npm(), "lodashx", IngestSource::Direct));
    }

    #[test]
    fn matches_package_name_pattern_star_suffix() {
        let s = RetentionScope::PackageNamePattern("xz-*".into());
        assert!(s.matches(rid(1), &npm(), "xz-utils", IngestSource::Direct));
        // `*` matches the empty string — the prefix alone still matches.
        assert!(s.matches(rid(1), &npm(), "xz-", IngestSource::Direct));
        assert!(!s.matches(rid(1), &npm(), "lz-utils", IngestSource::Direct));
    }

    #[test]
    fn matches_package_name_pattern_star_prefix() {
        let s = RetentionScope::PackageNamePattern("*-beta".into());
        assert!(s.matches(rid(1), &npm(), "app-beta", IngestSource::Direct));
        assert!(!s.matches(rid(1), &npm(), "app-alpha", IngestSource::Direct));
    }

    #[test]
    fn matches_package_name_pattern_lone_star_matches_any_name() {
        let s = RetentionScope::PackageNamePattern("*".into());
        assert!(s.matches(rid(1), &npm(), "anything", IngestSource::Direct));
        // `*` matches the empty string (boundary).
        assert!(s.matches(rid(1), &npm(), "", IngestSource::Direct));
    }

    #[test]
    fn matches_package_name_pattern_empty_name_boundary() {
        // A literal (no `*`) pattern only matches an identical name; an
        // empty artifact name matches only an empty pattern (which
        // `validate` already forbids, but `matches` itself is pure and
        // must still be well-defined on the boundary).
        let s = RetentionScope::PackageNamePattern("pkg".into());
        assert!(!s.matches(rid(1), &npm(), "", IngestSource::Direct));
    }
}
