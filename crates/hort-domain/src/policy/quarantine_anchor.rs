//! Quarantine-window **anchor** derivation (ADR 0054).
//!
//! The quarantine window is a proxy for elapsed *ecosystem exposure*, not
//! a scan queue: the assumption is that content available in the world for
//! the window's duration has had the ecosystem's scanners, advisories and
//! researchers looking at it. This module answers the one question that
//! proxy needs — **from which instant has the world been able to look at
//! these bytes?** — and answers it as the *earliest defensible evidence*
//! available, i.e. the minimum over the applicable sources.
//!
//! Release **authority** is not this module's business and is untouched by
//! it: [`Artifact::release`](crate::entities::artifact::Artifact::release)
//! still requires the artifact's own `ScanSucceeded` / `ScanWaived`
//! (ADR 0007). The anchor governs the *timer*, never the authority.
//!
//! # Why a minimum, and why these sources
//!
//! Every source here is a "the world has already had this long to look"
//! argument, so the honest composition is the earliest deadline any
//! applicable rule would set on its own. `min` is also order-insensitive,
//! which makes the result race-independent by construction: whichever
//! concurrent minting path observes the content first, the derived anchor
//! is the same.
//!
//! - **The mint instant** — unconditional, and therefore the answer when
//!   nothing else applies. hort can always vouch for "the bytes existed no
//!   later than the moment I held them".
//! - **The content-level age evidence** ([`AnchorEvidence::first_seen_at`])
//!   — the earliest moment hort itself observed these bytes in any of its
//!   own repositories. An *observation*, not a third-party assertion: it
//!   cannot be backdated, because making hort see the bytes earlier
//!   requires the bytes to genuinely have existed earlier, during which the
//!   ecosystem had exactly the exposure the window is a proxy for.
//! - **A trusted upstream publish time**
//!   ([`AnchorEvidence::trusted_upstream_published_at`]) — attacker-
//!   assertable, hence per-mapping opt-in and future-skew-clamped here
//!   before it may compete.
//! - **The referenced-tree descendant carve-out** — content that is already
//!   a `content_references` target of another ingested artifact contributes
//!   `minted_at - window`, i.e. a window that is already over.
//!
//! # The second source never transits repositories
//!
//! `trusted_upstream_published_at` is the *caller's* trust statement about
//! **this** repository's own upstream mapping. This function takes no
//! repository identity and holds no mapping table, so it structurally
//! cannot reach for another repository's opt-in: a value observed through a
//! different mapping can only arrive here if a caller puts it here, and no
//! caller does. That scoping is what keeps the two-source model out of the
//! ADR 0016 cross-opt-in collapse pattern — an unfiltered minimum over
//! every repository's upstream claims would let a repository proxying an
//! untrusted mirror shorten the window of a repository proxying the genuine
//! upstream.
//!
//! # Missing evidence is not earlier evidence
//!
//! Absent age evidence — no prior observation, or a failed read of it —
//! resolves to the mint instant, which falls out structurally from the mint
//! instant being an unconditional candidate. Inventing an earlier instant
//! for content whose age hort cannot vouch for would shorten a security
//! window on no evidence; standing on the mint instant can only hold
//! content *longer* than the truth justifies.

use chrono::{DateTime, Duration, Utc};

/// The applicable age sources for one minting of one artifact row.
///
/// Assembled by the application layer, which owns the I/O (the age-evidence
/// read, the upstream-mapping opt-in, the `content_references` topology
/// probe); the derivation itself is pure so every arm is exhaustively
/// testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorEvidence {
    /// The instant this artifact row is being minted — `ingested_at` on
    /// the ingest path, the registration instant on the register-by-hash
    /// path. Always a candidate, so the derivation is total.
    pub minted_at: DateTime<Utc>,
    /// The resolved observation-window length (the matched
    /// `ScanPolicy.quarantineDuration`, or the built-in default). Consumed
    /// only by the descendant carve-out, which expresses "a window that is
    /// already over" as `minted_at - window`.
    pub window: Duration,
    /// A caller-supplied anchor that wins **absolutely** — the seed-import
    /// cutover's backdated anchor. `Some(_)` short-circuits the whole
    /// minimum: an explicit operator-supplied anchor is never overridden by
    /// a derived one, in either direction.
    pub explicit_override: Option<DateTime<Utc>>,
    /// The earliest ingest observation hort holds for this content hash
    /// across all of its own repositories — `MIN(created_at)` over the
    /// artifact rows sharing the hash
    /// ([`ArtifactRepository::first_seen_for_checksum`](crate::ports::artifact_repository::ArtifactRepository::first_seen_for_checksum)).
    ///
    /// `None` means "hort holds no such observation" **or** "the read
    /// failed" — deliberately indistinguishable, because both resolve the
    /// same conservative way (see the module docs).
    pub first_seen_at: Option<DateTime<Utc>>,
    /// An upstream-asserted publish time the caller is willing to trust,
    /// i.e. one observed through **this** repository's own mapping with
    /// `trust_upstream_publish_time` enabled. Callers pass `None` whenever
    /// the opt-in is off, the format extracted no hint, or the value
    /// reached them through a different repository's mapping.
    ///
    /// Future-skew-clamped to [`Self::minted_at`] before it competes. An
    /// *ancient* claim is deliberately left unclamped: bounding it would
    /// require an age fact hort does not have, and the opt-in exists
    /// precisely so an operator can state that this upstream's claims are
    /// worth believing.
    pub trusted_upstream_published_at: Option<DateTime<Utc>>,
    /// Whether this content is already a `content_references` target of
    /// some other, already-ingested artifact in this repository (a child
    /// manifest, a referrer's subject, a config/layer blob). A topology
    /// fact, hence caller-independent: one artifact in one repository gets
    /// one window whichever path minted its row.
    pub is_referenced_descendant: bool,
}

/// Which source the derived anchor came from — observability only; the
/// release predicate never reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorSource {
    /// [`AnchorEvidence::explicit_override`] — absolute precedence.
    Override,
    /// [`AnchorEvidence::minted_at`]. Also the answer when another source
    /// merely *equals* the mint instant: a source that moved nothing did
    /// not decide anything.
    Mint,
    /// [`AnchorEvidence::first_seen_at`].
    FirstSeen,
    /// [`AnchorEvidence::trusted_upstream_published_at`], post-clamp.
    TrustedUpstreamPublish,
    /// The [`AnchorEvidence::is_referenced_descendant`] carve-out's
    /// `minted_at - window`.
    ReferencedDescendant,
}

/// The derived anchor plus what an operator needs to explain it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedAnchor {
    /// The instant to stamp as `quarantine_window_start`. The deadline is
    /// never stored — consumers compute it live via
    /// [`effective_quarantine_deadline`](super::effective_quarantine_deadline).
    pub anchor: DateTime<Utc>,
    /// The winning source.
    pub source: AnchorSource,
    /// Whether the future-skew clamp fired on
    /// [`AnchorEvidence::trusted_upstream_published_at`] — i.e. the
    /// upstream claimed a publish time *after* the mint instant, which is
    /// physically impossible. Reported whether or not the clamped value
    /// went on to win, because the claim itself is the operator signal.
    pub upstream_clamp_fired: bool,
}

/// Derive the quarantine-window anchor from the applicable age sources.
///
/// An explicit override short-circuits; otherwise the result is the
/// minimum over the mint instant, the content-level age evidence, the
/// future-skew-clamped trusted upstream publish time, and the descendant
/// carve-out's `minted_at - window`.
///
/// Ties resolve to the source considered first, in the order
/// mint → first-seen → trusted-upstream → descendant. That order only
/// affects [`DerivedAnchor::source`], never [`DerivedAnchor::anchor`]: the
/// mint instant leads so a source that merely equals it is not credited
/// with a decision it did not make.
pub fn derive_quarantine_anchor(evidence: &AnchorEvidence) -> DerivedAnchor {
    // Seed-import precedence is absolute. Checked before the clamp so an
    // override is never reported alongside a clamp verdict it did not
    // participate in.
    if let Some(explicit) = evidence.explicit_override {
        return DerivedAnchor {
            anchor: explicit,
            source: AnchorSource::Override,
            upstream_clamp_fired: false,
        };
    }

    // Future-skew clamp, applied BEFORE the value competes: a claimed
    // publish time after the mint instant is physically impossible, so a
    // buggy or malicious upstream cannot push its own window into the
    // future. An ancient claim is left alone — see the field docs.
    let upstream_clamp_fired = evidence
        .trusted_upstream_published_at
        .is_some_and(|ts| ts > evidence.minted_at);
    let clamped_upstream = evidence
        .trusted_upstream_published_at
        .map(|ts| ts.min(evidence.minted_at));

    // The descendant carve-out composes by `min` like everything else
    // rather than overriding: both it and an earlier age source are
    // "shorten the window" arguments, so the honest composition is the
    // earliest deadline any applicable rule would set on its own.
    // Overriding is only distinguishable when another source is *even
    // earlier*, where it would silently lengthen a window relative to a
    // rule that already applied.
    let descendant = evidence
        .is_referenced_descendant
        .then(|| evidence.minted_at - evidence.window);

    let mut anchor = evidence.minted_at;
    let mut source = AnchorSource::Mint;
    for (candidate, candidate_source) in [
        (evidence.first_seen_at, AnchorSource::FirstSeen),
        (clamped_upstream, AnchorSource::TrustedUpstreamPublish),
        (descendant, AnchorSource::ReferencedDescendant),
    ] {
        match candidate {
            Some(ts) if ts < anchor => {
                anchor = ts;
                source = candidate_source;
            }
            _ => {}
        }
    }

    DerivedAnchor {
        anchor,
        source,
        upstream_clamp_fired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("in-range timestamp")
    }

    const MINT: i64 = 1_000_000;
    const WINDOW_SECS: i64 = 86_400;

    /// Baseline evidence: mint instant only, nothing else applicable.
    fn bare() -> AnchorEvidence {
        AnchorEvidence {
            minted_at: ts(MINT),
            window: Duration::seconds(WINDOW_SECS),
            explicit_override: None,
            first_seen_at: None,
            trusted_upstream_published_at: None,
            is_referenced_descendant: false,
        }
    }

    #[test]
    fn no_evidence_resolves_to_the_mint_instant() {
        let derived = derive_quarantine_anchor(&bare());
        assert_eq!(derived.anchor, ts(MINT));
        assert_eq!(derived.source, AnchorSource::Mint);
        assert!(!derived.upstream_clamp_fired);
    }

    #[test]
    fn earlier_first_seen_moves_the_anchor_back() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            first_seen_at: Some(ts(MINT - 5_000)),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT - 5_000));
        assert_eq!(derived.source, AnchorSource::FirstSeen);
    }

    /// Clock skew between the DB's `now()` (which stamps `created_at`) and
    /// the application clock can put the evidence marginally *after* the
    /// mint instant. The minimum absorbs it — no clamp needed.
    #[test]
    fn first_seen_after_the_mint_instant_loses_to_it() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            first_seen_at: Some(ts(MINT + 5)),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT));
        assert_eq!(derived.source, AnchorSource::Mint);
    }

    /// A source that merely equals the mint instant decided nothing, so
    /// the mint instant keeps the attribution.
    #[test]
    fn first_seen_equal_to_the_mint_instant_is_attributed_to_the_mint() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            first_seen_at: Some(ts(MINT)),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT));
        assert_eq!(derived.source, AnchorSource::Mint);
    }

    /// ADR 0054's rationale: only *future*-dated values are clamped. An
    /// ancient claim from an opted-in mapping is honoured verbatim — the
    /// opt-in is exactly the operator saying this upstream's claims are
    /// worth believing.
    #[test]
    fn an_ancient_trusted_upstream_value_stays_unclamped() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            trusted_upstream_published_at: Some(ts(1)),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(1));
        assert_eq!(derived.source, AnchorSource::TrustedUpstreamPublish);
        assert!(!derived.upstream_clamp_fired);
    }

    #[test]
    fn a_future_dated_trusted_upstream_value_is_clamped_to_the_mint_instant() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            trusted_upstream_published_at: Some(ts(MINT + 100_000)),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT));
        assert!(derived.upstream_clamp_fired);
        // The clamped value ties with the mint instant, so the mint keeps
        // the attribution — the upstream claim moved nothing.
        assert_eq!(derived.source, AnchorSource::Mint);
    }

    #[test]
    fn a_trusted_upstream_value_equal_to_the_mint_instant_does_not_fire_the_clamp() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            trusted_upstream_published_at: Some(ts(MINT)),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT));
        assert!(!derived.upstream_clamp_fired);
        assert_eq!(derived.source, AnchorSource::Mint);
    }

    #[test]
    fn the_earlier_of_first_seen_and_trusted_upstream_wins_either_way() {
        let upstream_earlier = derive_quarantine_anchor(&AnchorEvidence {
            first_seen_at: Some(ts(MINT - 1_000)),
            trusted_upstream_published_at: Some(ts(MINT - 9_000)),
            ..bare()
        });
        assert_eq!(upstream_earlier.anchor, ts(MINT - 9_000));
        assert_eq!(
            upstream_earlier.source,
            AnchorSource::TrustedUpstreamPublish
        );

        let first_seen_earlier = derive_quarantine_anchor(&AnchorEvidence {
            first_seen_at: Some(ts(MINT - 9_000)),
            trusted_upstream_published_at: Some(ts(MINT - 1_000)),
            ..bare()
        });
        assert_eq!(first_seen_earlier.anchor, ts(MINT - 9_000));
        assert_eq!(first_seen_earlier.source, AnchorSource::FirstSeen);
    }

    /// The opt-in is the caller's gate: with it off the caller passes
    /// `None`, and the claim — however ancient — never reaches the
    /// minimum. This is the structural form of "the second source never
    /// transits repositories": there is no other channel into the
    /// derivation for an upstream assertion.
    #[test]
    fn an_untrusted_upstream_value_has_no_channel_into_the_minimum() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            trusted_upstream_published_at: None,
            first_seen_at: Some(ts(MINT - 10)),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT - 10));
        assert_eq!(derived.source, AnchorSource::FirstSeen);
    }

    #[test]
    fn the_descendant_carve_out_backdates_by_a_full_window() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            is_referenced_descendant: true,
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT - WINDOW_SECS));
        assert_eq!(derived.source, AnchorSource::ReferencedDescendant);
    }

    /// Composition, not override: an age source that is *even earlier*
    /// than the carve-out keeps its earlier deadline.
    #[test]
    fn an_even_earlier_source_beats_the_descendant_carve_out() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            is_referenced_descendant: true,
            first_seen_at: Some(ts(MINT - WINDOW_SECS - 1)),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT - WINDOW_SECS - 1));
        assert_eq!(derived.source, AnchorSource::FirstSeen);
    }

    /// …and the carve-out still wins when it is the earliest applicable
    /// rule, which is the case an "override" model would have been
    /// indistinguishable from.
    #[test]
    fn the_descendant_carve_out_beats_a_later_age_source() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            is_referenced_descendant: true,
            first_seen_at: Some(ts(MINT - 10)),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT - WINDOW_SECS));
        assert_eq!(derived.source, AnchorSource::ReferencedDescendant);
    }

    #[test]
    fn an_ancient_trusted_upstream_value_beats_the_descendant_carve_out() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            is_referenced_descendant: true,
            trusted_upstream_published_at: Some(ts(1)),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(1));
        assert_eq!(derived.source, AnchorSource::TrustedUpstreamPublish);
    }

    /// A zero-length window makes the carve-out's contribution equal the
    /// mint instant; the tie-break keeps the attribution on the mint. (The
    /// application layer only derives an anchor when the resolved duration
    /// is `> 0`, so this pins totality rather than a live path.)
    #[test]
    fn a_zero_window_descendant_ties_with_the_mint_instant() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            is_referenced_descendant: true,
            window: Duration::zero(),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT));
        assert_eq!(derived.source, AnchorSource::Mint);
    }

    /// Seed-import precedence is absolute in BOTH directions: the explicit
    /// anchor stands even though every other source is earlier.
    #[test]
    fn an_explicit_override_beats_every_earlier_derived_source() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            explicit_override: Some(ts(MINT - 7)),
            first_seen_at: Some(ts(1)),
            trusted_upstream_published_at: Some(ts(2)),
            is_referenced_descendant: true,
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT - 7));
        assert_eq!(derived.source, AnchorSource::Override);
    }

    /// …and stands even when it is *later* than what the minimum would
    /// have produced on its own.
    #[test]
    fn an_explicit_override_is_never_replaced_by_a_derived_value() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            explicit_override: Some(ts(MINT)),
            first_seen_at: Some(ts(MINT - 500_000)),
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT));
        assert_eq!(derived.source, AnchorSource::Override);
    }

    /// An override suppresses the clamp verdict too — the upstream claim
    /// never entered the derivation, so reporting a clamp on it would
    /// describe a decision that did not happen.
    #[test]
    fn an_explicit_override_reports_no_clamp_verdict() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            explicit_override: Some(ts(MINT)),
            trusted_upstream_published_at: Some(ts(MINT + 999)),
            ..bare()
        });
        assert!(!derived.upstream_clamp_fired);
        assert_eq!(derived.source, AnchorSource::Override);
    }

    /// With every source applicable, the result is their minimum — and it
    /// is the same minimum regardless of which one happens to be earliest.
    #[test]
    fn every_source_applicable_resolves_to_their_minimum() {
        let derived = derive_quarantine_anchor(&AnchorEvidence {
            first_seen_at: Some(ts(MINT - 100)),
            trusted_upstream_published_at: Some(ts(MINT - 200)),
            is_referenced_descendant: true,
            ..bare()
        });
        assert_eq!(derived.anchor, ts(MINT - WINDOW_SECS));
        assert_eq!(derived.source, AnchorSource::ReferencedDescendant);
    }

    /// `min` is order-insensitive, so two concurrent minting paths that
    /// observe the same evidence in different orders derive the same
    /// anchor — the race-independence ADR 0054 relies on.
    #[test]
    fn the_derivation_is_insensitive_to_which_source_arrives_first() {
        let a = derive_quarantine_anchor(&AnchorEvidence {
            first_seen_at: Some(ts(MINT - 3)),
            trusted_upstream_published_at: Some(ts(MINT - 4)),
            ..bare()
        });
        let b = derive_quarantine_anchor(&AnchorEvidence {
            first_seen_at: Some(ts(MINT - 4)),
            trusted_upstream_published_at: Some(ts(MINT - 3)),
            ..bare()
        });
        assert_eq!(a.anchor, b.anchor);
        assert_eq!(a.anchor, ts(MINT - 4));
    }

    /// The derived anchor never lands after the mint instant, whatever the
    /// evidence — the window can only ever be shortened, never extended,
    /// by this derivation.
    #[test]
    fn the_derived_anchor_never_exceeds_the_mint_instant() {
        for evidence in [
            AnchorEvidence {
                first_seen_at: Some(ts(MINT + 10_000)),
                trusted_upstream_published_at: Some(ts(MINT + 10_000)),
                ..bare()
            },
            AnchorEvidence {
                first_seen_at: Some(ts(MINT + 1)),
                is_referenced_descendant: true,
                ..bare()
            },
            bare(),
        ] {
            assert!(derive_quarantine_anchor(&evidence).anchor <= ts(MINT));
        }
    }
}
