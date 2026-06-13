//! Provenance-subsystem shared facts (ADR 0027).
//!
//! Single source of truth for (a) the Tier-1 set of artifact formats that have
//! a registered provenance verifier, and (b) the `ScanPolicy` wire→domain
//! mappers. Centralising them here makes the offline
//! `hort-server validate-config` gate's row-7 verdict **version-correct by
//! construction** rather than by convention, and avoids apply/validator
//! mapper duplication.

use std::str::FromStr;

use hort_config::scan_policy::SignerIdentitySpec;
use hort_domain::entities::scan_policy::{ProvenanceMode, SignerIdentityPattern};

/// The Tier-1 set of formats with a registered `ProvenancePort` verifier.
///
/// **THE single source** every wiring site derives from:
/// [`ApplyConfigUseCase::with_provenance_capable_formats`](crate::use_cases::apply_config_use_case::ApplyConfigUseCase::with_provenance_capable_formats)
/// at boot (`gitops_boot`) and in the server composition, **and** the offline
/// `hort-server validate-config` CLI. Tier 1 ships `oci` (cosign); when
/// Tier 2 adds npm/PyPI/cargo/Maven verifiers, update this ONE const
/// and all wiring sites stay in lock-step — so the offline gate can never
/// report a `provenanceMode: required` verdict the live server would not
/// enforce, nor miss one it would. The set's *content* is
/// the deployment fact; the validator's row-7 *logic* is single-sourced
/// separately in `hort_app::lint::static_validate`.
pub const TIER1_PROVENANCE_CAPABLE_FORMATS: &[&str] = &["oci"];

/// Map the validated `provenanceMode` wire string to the
/// domain enum. `hort_config::scan_policy::validate_scan_policy` ran first, so
/// a parse failure is a bypassed-validator programming error.
pub(crate) fn provenance_mode_from_spec(s: &str) -> ProvenanceMode {
    ProvenanceMode::from_str(s).expect("INVARIANT: provenanceMode validated by hort-config")
}

/// Map the validated `provenanceIdentities` wire specs to the
/// domain pattern type. Each entry already passed the per-element constructor
/// validator in `validate_scan_policy`.
pub(crate) fn provenance_identities_from_spec(
    specs: &[SignerIdentitySpec],
) -> Vec<SignerIdentityPattern> {
    specs
        .iter()
        .map(|s| {
            SignerIdentityPattern::new(s.issuer.clone(), s.san.clone())
                .expect("INVARIANT: provenanceIdentities validated by hort-config")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the Tier-1 set. A change here is a deliberate capability change
    /// (Tier-2 verifier rollout) that every wiring site picks up by construction — the
    /// pin documents that intent and fails loudly if the set drifts silently.
    #[test]
    fn tier1_set_is_oci_only() {
        assert_eq!(TIER1_PROVENANCE_CAPABLE_FORMATS, &["oci"]);
    }

    #[test]
    fn provenance_mode_maps_each_validated_string() {
        assert_eq!(provenance_mode_from_spec("off"), ProvenanceMode::Off);
        assert_eq!(
            provenance_mode_from_spec("verify_if_present"),
            ProvenanceMode::VerifyIfPresent
        );
        assert_eq!(
            provenance_mode_from_spec("required"),
            ProvenanceMode::Required
        );
    }

    #[test]
    fn provenance_identities_map_to_patterns() {
        let specs = vec![
            SignerIdentitySpec {
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                san: "https://github.com/acme/.+".to_string(),
            },
            SignerIdentitySpec {
                issuer: "https://accounts.google.com".to_string(),
                san: "ci@acme.iam.gserviceaccount.com".to_string(),
            },
        ];
        let patterns = provenance_identities_from_spec(&specs);
        assert_eq!(patterns.len(), 2);
    }

    #[test]
    fn provenance_identities_empty_is_empty() {
        assert!(provenance_identities_from_spec(&[]).is_empty());
    }
}
