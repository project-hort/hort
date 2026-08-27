//! The **one** predicate that decides whether an event-chain checkpoint
//! anchor exists in this deployment — shared by the checkpoint *writer*
//! (the worker's `EventstoreCheckpointHandler` registration) and the
//! checkpoint *reader* (`hort-server verify-event-chain`).
//!
//! ## Why one predicate
//!
//! Anchoring is a two-sided mechanism: the worker signs and WORM-anchors
//! checkpoints, the verifier reads them back and cross-checks the live
//! chain heads against them (ADR 0002). Both sides need to answer "is
//! anchoring configured here?" and they must never answer it
//! differently — a writer that anchors while the reader believes no
//! anchor is expected silently stops attesting; a reader that expects an
//! anchor the writer never emits fails every run.
//!
//! So the condition is stated **once**, here, as a pure value-level
//! predicate over the two facts *both* sides can observe:
//!
//! ```text
//! anchoring_configured  ==  (storage backend is S3) && (anchor public key present)
//! ```
//!
//! Extending or renaming the condition therefore moves both sides
//! together — that is the whole point of this module. Neither side may
//! restate the condition locally.
//!
//! ## Why the signing key is not part of the shared predicate
//!
//! The base predicate is deliberately **verifier-observable**: it names
//! only facts a reader can see. Checkpoint *verification* is a
//! public-key operation, so the verify job is never given the private
//! signing key — least privilege on the integrity system's key material.
//! The writer's extra requirement (it also needs the private key,
//! because it *writes* anchors) is layered on top by
//! [`checkpoint_emission_status`], never folded into the base.
//!
//! A consequence, and it is the correct one: a half-configured
//! deployment (S3 + anchor public key present, signing key absent) reads
//! as anchor-**expected** on the verifier side and will flag. An
//! operator who provisioned an anchor public key and an S3 backend but
//! no signing key has a broken anchor setup worth alarming about.
//!
//! ## Storage backend
//!
//! S3 is required because the anchor's tamper-resistance comes from S3
//! Object-Lock WORM retention (ADR 0002); a filesystem backend has
//! nowhere to put an anchor that an attacker with write access could not
//! also rewrite. An unanchored deployment is a **supported posture, not
//! a degraded one** — the per-stream hash chain is still verified and a
//! real break still fails; only "anchor absent when none was expected"
//! is a non-failure.

use crate::storage_backend::EffectiveStorageBackend;

/// Environment variable naming the operator-provisioned anchor
/// **public** key file (Ed25519 SPKI PEM).
///
/// Read by **both** sides — the writer needs it to derive the next
/// monotonic `checkpoint_seq`, the reader needs it to verify checkpoint
/// signatures. Named here, once, so a rename cannot move one side
/// without the other.
pub const ANCHOR_PUBLIC_KEY_FILE_ENV: &str = "HORT_EVENT_CHAIN_ANCHOR_PUBKEY_FILE";

/// Environment variable naming the operator-provisioned anchor
/// **private** signing key file (Ed25519 PKCS#8 PEM).
///
/// Read by the **writer only**. The verify job is never given this file:
/// verification is a public-key operation, and the integrity system's
/// private key has no business in a read-only auditor.
pub const ANCHOR_SIGNING_KEY_FILE_ENV: &str = "HORT_EVENT_CHAIN_ANCHOR_SIGNING_KEY_FILE";

/// Why anchoring is not configured. Each variant is a distinct operator
/// action, so each carries its own explanation for the log line the
/// caller emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchoringGap {
    /// The deployment's effective storage backend is not S3, so there is
    /// no Object-Lock WORM prefix to anchor into.
    StorageNotS3,
    /// No operator-provisioned anchor public key (Ed25519 SPKI PEM).
    AnchorPublicKeyAbsent,
}

impl AnchoringGap {
    /// One-line operator-facing explanation.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::StorageNotS3 => {
                "storage backend is not S3 — S3 Object-Lock WORM is required to anchor \
                 checkpoints"
            }
            Self::AnchorPublicKeyAbsent => {
                "no anchor public key is provisioned (the Ed25519 SPKI PEM that the \
                 checkpoint signature is verified against)"
            }
        }
    }
}

/// The shared, verifier-observable anchoring verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchoringStatus {
    /// An external checkpoint anchor exists in this deployment: the
    /// verifier expects checkpoints, and a missing/stale one is a real
    /// coverage gap.
    Configured,
    /// No anchor is configured. The chain is still verified; a missing
    /// checkpoint is not a failure.
    NotConfigured(AnchoringGap),
}

impl AnchoringStatus {
    /// **Reader side, in full.** Whether `verify-event-chain` should
    /// expect an anchored checkpoint to exist — and therefore treat a
    /// missing, stale or gapped one as a real coverage gap (exit 3)
    /// rather than the benign unanchored case (exit 0).
    ///
    /// There is deliberately no separate reader-side predicate to keep
    /// in step with this one: the reader's answer *is* the shared
    /// verdict, structurally, and it observes no private key.
    #[must_use]
    pub fn is_configured(self) -> bool {
        matches!(self, Self::Configured)
    }
}

/// Whether key material was actually provisioned. Whitespace-only
/// content counts as absent: an empty mounted Secret is a
/// half-provisioned deployment, not a configured one, and treating it as
/// "present" would make the verifier expect an anchor whose key can
/// never verify anything.
fn provisioned(pem: Option<&str>) -> bool {
    pem.is_some_and(|p| !p.trim().is_empty())
}

/// **The** anchoring predicate. Both the writer and the reader derive
/// their gate from this function; neither restates the condition.
///
/// `anchor_public_key` is the operator-provisioned Ed25519 SPKI PEM
/// (`None` when unset or unreadable).
#[must_use]
pub fn anchoring_status(
    backend: EffectiveStorageBackend,
    anchor_public_key: Option<&str>,
) -> AnchoringStatus {
    if backend != EffectiveStorageBackend::S3 {
        return AnchoringStatus::NotConfigured(AnchoringGap::StorageNotS3);
    }
    if !provisioned(anchor_public_key) {
        return AnchoringStatus::NotConfigured(AnchoringGap::AnchorPublicKeyAbsent);
    }
    AnchoringStatus::Configured
}

/// Boolean form of [`anchoring_status`].
#[must_use]
pub fn anchoring_configured(
    backend: EffectiveStorageBackend,
    anchor_public_key: Option<&str>,
) -> bool {
    anchoring_status(backend, anchor_public_key).is_configured()
}

/// Why checkpoint emission is not enabled on the writer side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointEmissionGap {
    /// The shared anchoring predicate is already unsatisfied.
    Anchoring(AnchoringGap),
    /// Anchoring is configured, but the private signing key the writer
    /// needs in order to sign checkpoints is absent.
    SigningKeyAbsent,
}

impl CheckpointEmissionGap {
    /// One-line operator-facing explanation.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Anchoring(gap) => gap.reason(),
            Self::SigningKeyAbsent => {
                "no anchor signing key is provisioned (the Ed25519 PKCS#8 private \
                 counterpart of the anchor public key); checkpoint emission cannot sign"
            }
        }
    }
}

/// Whether the writer should register the checkpoint-emission handler.
///
/// The `Enabled` arm hands back the key material it validated, so the
/// caller builds its adapters from the values the gate approved rather
/// than re-deriving them from the `Option`s it passed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointEmissionStatus<'a> {
    Enabled {
        anchor_public_key: &'a str,
        anchor_signing_key: &'a str,
    },
    Disabled(CheckpointEmissionGap),
}

impl CheckpointEmissionStatus<'_> {
    #[must_use]
    pub fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled { .. })
    }
}

/// **Writer side.** The shared anchoring predicate **plus** the private
/// signing key the writer needs because it *writes* anchors. The extra
/// check is layered on top of [`anchoring_status`] — it is never a
/// second statement of the base condition.
#[must_use]
pub fn checkpoint_emission_status<'a>(
    backend: EffectiveStorageBackend,
    anchor_public_key: Option<&'a str>,
    anchor_signing_key: Option<&'a str>,
) -> CheckpointEmissionStatus<'a> {
    match anchoring_status(backend, anchor_public_key) {
        AnchoringStatus::NotConfigured(gap) => {
            CheckpointEmissionStatus::Disabled(CheckpointEmissionGap::Anchoring(gap))
        }
        AnchoringStatus::Configured => match (anchor_public_key, anchor_signing_key) {
            (Some(public), Some(signing)) if provisioned(Some(signing)) => {
                CheckpointEmissionStatus::Enabled {
                    anchor_public_key: public,
                    anchor_signing_key: signing,
                }
            }
            _ => CheckpointEmissionStatus::Disabled(CheckpointEmissionGap::SigningKeyAbsent),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FS: EffectiveStorageBackend = EffectiveStorageBackend::Filesystem;
    const S3: EffectiveStorageBackend = EffectiveStorageBackend::S3;
    const PEM: Option<&str> = Some("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----");
    const KEY: Option<&str> = Some("-----BEGIN PRIVATE KEY-----\nBBB\n-----END PRIVATE KEY-----");

    /// Every (backend, public key, signing key) combination, so the
    /// drift guard below is exhaustive rather than sampled.
    fn matrix() -> Vec<(
        EffectiveStorageBackend,
        Option<&'static str>,
        Option<&'static str>,
    )> {
        let mut out = Vec::new();
        for backend in [FS, S3] {
            for pubkey in [None, Some(""), Some("   \n"), PEM] {
                for signing in [None, Some(""), KEY] {
                    out.push((backend, pubkey, signing));
                }
            }
        }
        out
    }

    // -- The base predicate ------------------------------------------------

    #[test]
    fn s3_with_public_key_is_configured() {
        assert_eq!(anchoring_status(S3, PEM), AnchoringStatus::Configured);
        assert!(anchoring_configured(S3, PEM));
    }

    #[test]
    fn filesystem_backend_is_never_configured() {
        assert_eq!(
            anchoring_status(FS, PEM),
            AnchoringStatus::NotConfigured(AnchoringGap::StorageNotS3)
        );
        assert!(!anchoring_configured(FS, PEM));
        // Backend dominates: a filesystem install reports the backend
        // gap even when no key is provisioned either.
        assert_eq!(
            anchoring_status(FS, None),
            AnchoringStatus::NotConfigured(AnchoringGap::StorageNotS3)
        );
    }

    #[test]
    fn s3_without_public_key_is_not_configured() {
        assert_eq!(
            anchoring_status(S3, None),
            AnchoringStatus::NotConfigured(AnchoringGap::AnchorPublicKeyAbsent)
        );
    }

    #[test]
    fn empty_or_whitespace_key_material_counts_as_absent() {
        for empty in [Some(""), Some("   "), Some("\n\t ")] {
            assert_eq!(
                anchoring_status(S3, empty),
                AnchoringStatus::NotConfigured(AnchoringGap::AnchorPublicKeyAbsent),
                "an empty mounted Secret is half-provisioned, not configured"
            );
        }
    }

    // -- Writer side -------------------------------------------------------

    #[test]
    fn writer_needs_the_signing_key_on_top() {
        assert_eq!(
            checkpoint_emission_status(S3, PEM, KEY),
            CheckpointEmissionStatus::Enabled {
                anchor_public_key: PEM.unwrap(),
                anchor_signing_key: KEY.unwrap(),
            },
            "the enabled arm hands back exactly the material it validated"
        );
        assert_eq!(
            checkpoint_emission_status(S3, PEM, None),
            CheckpointEmissionStatus::Disabled(CheckpointEmissionGap::SigningKeyAbsent)
        );
        assert_eq!(
            checkpoint_emission_status(S3, PEM, Some("  ")),
            CheckpointEmissionStatus::Disabled(CheckpointEmissionGap::SigningKeyAbsent)
        );
    }

    #[test]
    fn writer_reports_the_anchoring_gap_when_the_base_predicate_fails() {
        assert_eq!(
            checkpoint_emission_status(FS, PEM, KEY),
            CheckpointEmissionStatus::Disabled(CheckpointEmissionGap::Anchoring(
                AnchoringGap::StorageNotS3
            ))
        );
        assert_eq!(
            checkpoint_emission_status(S3, None, KEY),
            CheckpointEmissionStatus::Disabled(CheckpointEmissionGap::Anchoring(
                AnchoringGap::AnchorPublicKeyAbsent
            ))
        );
    }

    // -- The drift guard ---------------------------------------------------

    /// The two sides must derive from the same base predicate: the
    /// reader's anchor-expectedness IS the base verdict, and the
    /// writer's gate is the base AND a provisioned signing key. If
    /// either side ever grows a locally-restated condition, this
    /// exhaustive matrix goes red.
    #[test]
    fn reader_and_writer_derive_from_one_shared_predicate() {
        for (backend, pubkey, signing) in matrix() {
            let base = anchoring_configured(backend, pubkey);

            assert_eq!(
                anchoring_status(backend, pubkey).is_configured(),
                base,
                "reader side must be exactly the shared predicate \
                 ({backend:?}, pubkey={pubkey:?})"
            );

            assert_eq!(
                checkpoint_emission_status(backend, pubkey, signing).is_enabled(),
                base && provisioned(signing),
                "writer side must be the shared predicate AND a provisioned \
                 signing key ({backend:?}, pubkey={pubkey:?}, signing={signing:?})"
            );
        }
    }

    /// The half-configured deployment the decision deliberately keeps
    /// alarming: S3 + anchor public key, no signing key. The writer emits
    /// nothing, but the reader still expects an anchor — so the verify
    /// run flags instead of silently going green.
    #[test]
    fn half_configured_anchor_setup_reads_as_expected_and_flags() {
        assert!(
            anchoring_configured(S3, PEM),
            "an operator with S3 + an anchor public key but no signing key has a \
             broken anchor setup; the verifier must keep expecting an anchor"
        );
        assert!(!checkpoint_emission_status(S3, PEM, None).is_enabled());
    }

    // -- Reasons -----------------------------------------------------------

    #[test]
    fn the_env_var_names_are_stated_once() {
        // Both sides read the public key from the same variable; only
        // the writer ever reads the signing key.
        assert_eq!(
            ANCHOR_PUBLIC_KEY_FILE_ENV,
            "HORT_EVENT_CHAIN_ANCHOR_PUBKEY_FILE"
        );
        assert_eq!(
            ANCHOR_SIGNING_KEY_FILE_ENV,
            "HORT_EVENT_CHAIN_ANCHOR_SIGNING_KEY_FILE"
        );
        assert_ne!(ANCHOR_PUBLIC_KEY_FILE_ENV, ANCHOR_SIGNING_KEY_FILE_ENV);
    }

    #[test]
    fn every_gap_has_a_distinct_reason() {
        let reasons = [
            AnchoringGap::StorageNotS3.reason(),
            AnchoringGap::AnchorPublicKeyAbsent.reason(),
            CheckpointEmissionGap::SigningKeyAbsent.reason(),
        ];
        for r in reasons {
            assert!(!r.is_empty());
        }
        assert_ne!(reasons[0], reasons[1]);
        assert_ne!(reasons[1], reasons[2]);
        assert_ne!(reasons[0], reasons[2]);
        // The writer's wrapper delegates to the base gap's reason.
        assert_eq!(
            CheckpointEmissionGap::Anchoring(AnchoringGap::StorageNotS3).reason(),
            AnchoringGap::StorageNotS3.reason()
        );
        assert_eq!(
            CheckpointEmissionGap::Anchoring(AnchoringGap::AnchorPublicKeyAbsent).reason(),
            AnchoringGap::AnchorPublicKeyAbsent.reason()
        );
    }

    #[test]
    fn status_helpers_report_both_arms() {
        assert!(AnchoringStatus::Configured.is_configured());
        assert!(!AnchoringStatus::NotConfigured(AnchoringGap::StorageNotS3).is_configured());
        assert!(CheckpointEmissionStatus::Enabled {
            anchor_public_key: "pub",
            anchor_signing_key: "priv",
        }
        .is_enabled());
        assert!(
            !CheckpointEmissionStatus::Disabled(CheckpointEmissionGap::SigningKeyAbsent)
                .is_enabled()
        );
    }
}
