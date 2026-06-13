//! The deployment's **effective global storage backend**, as a pure
//! `hort-app` value type (zero-I/O — a sibling of
//! [`crate::lint::LintConfig`]).
//!
//! ## Why this exists
//!
//! `ArtifactRepository.spec.storage.backend` is enum-validated at
//! parse to `{filesystem, s3}`, persisted, and
//! mapper-round-tripped — but blob placement is the **single
//! global** storage adapter (ADR 0003). A per-repo `backend` differing
//! from the deployment's effective global backend is therefore inert,
//! so such a mismatch is **rejected at apply** (fail-closed and loud;
//! ADR 0015's no-inert-fields rule).
//!
//! The cross-check needs to *know* the effective global backend, not
//! a per-repo *routing* model. The value cannot come from
//! [`hort_domain::ports::storage::StoragePort::backend_label`] — that is
//! the coarse `{filesystem, object_store}` label, so an `s3`-on-S3
//! deployment would report `object_store` and a naive cross-check
//! would **falsely reject** a legitimate config (fail-*wrong*, the
//! opposite of fail-closed). Instead this enum carries the *true* `{filesystem, s3}`
//! deployment fact: the composition root (`hort-server`) maps its
//! already-in-scope `StorageConfig` onto it and threads it through the
//! existing builder seam ([`ApplyConfigUseCase::with_effective_storage_backend`]),
//! mirroring `with_lint_config` / `with_retention` — **no
//! port-contract change, no `ApplyConfigUseCase::new` change, no new
//! crate-dependency edge** (`hort-server` already depends on `hort-app`).
//!
//! [`ApplyConfigUseCase::with_effective_storage_backend`]: crate::use_cases::apply_config_use_case::ApplyConfigUseCase::with_effective_storage_backend

/// The deployment's effective global storage backend.
///
/// Pure value type — zero-I/O, `Copy`. Maps 1:1 onto the operator's
/// `ArtifactRepository.spec.storage.backend` value-domain (the
/// `VALID_STORAGE_BACKENDS` set: `filesystem` | `s3`); the
/// [`storage_backend_matches_valid_set`](mod@self) test pins that
/// correspondence so the two sets cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveStorageBackend {
    Filesystem,
    S3,
}

impl EffectiveStorageBackend {
    /// The exact string an operator writes in
    /// `ArtifactRepository.spec.storage.backend`.
    ///
    /// Returns precisely the
    /// `hort_config::repository::VALID_STORAGE_BACKENDS` strings
    /// (`"filesystem"` / `"s3"`) so the apply-time cross-check
    /// (`spec.storage.backend != eff.as_spec_str()`) compares like
    /// for like.
    pub fn as_spec_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::S3 => "s3",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both enum arms map to their spec string. Pins the exact wire
    /// form an operator writes — a refactor that swaps the arms is a
    /// silent fail-*wrong* of the cross-check, so this is asserted
    /// explicitly per arm.
    #[test]
    fn as_spec_str_covers_both_arms() {
        assert_eq!(
            EffectiveStorageBackend::Filesystem.as_spec_str(),
            "filesystem"
        );
        assert_eq!(EffectiveStorageBackend::S3.as_spec_str(), "s3");
    }

    /// `as_spec_str()` over every arm equals the
    /// `VALID_STORAGE_BACKENDS` set 1:1 — same cardinality, same
    /// members, no extras on either side. This is the anti-drift pin:
    /// if the parse-time value-domain ever changes, this test fails
    /// until the enum is reconciled (and vice-versa).
    #[test]
    fn storage_backend_matches_valid_set() {
        use std::collections::BTreeSet;

        // The full set of strings this enum can emit.
        let enum_strings: BTreeSet<&'static str> = [
            EffectiveStorageBackend::Filesystem.as_spec_str(),
            EffectiveStorageBackend::S3.as_spec_str(),
        ]
        .into_iter()
        .collect();

        // The parse-time value-domain (re-exported for
        // exactly this cross-crate pin).
        let valid_set: BTreeSet<&'static str> = hort_config::repository::VALID_STORAGE_BACKENDS
            .iter()
            .copied()
            .collect();

        assert_eq!(
            enum_strings, valid_set,
            "EffectiveStorageBackend::as_spec_str() must match \
             hort_config::repository::VALID_STORAGE_BACKENDS 1:1 \
             (anti-drift pin)"
        );
    }

    /// `Copy` + `Eq` are part of the contract (the cross-check does
    /// `repo.storage.backend != eff.as_spec_str()` after a by-value
    /// `Some(eff)` match without moving the use-case field).
    #[test]
    fn is_copy_and_eq() {
        let a = EffectiveStorageBackend::S3;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(
            EffectiveStorageBackend::S3,
            EffectiveStorageBackend::Filesystem
        );
    }
}
