//! Outbound port: durable anti-replay seen-set for federated-JWT
//! token exchange.
//!
//! The federation branch of `/auth/token-exchange`
//! mints a fresh `≤1h` `ServiceAccount` bearer for every accepted
//! foreign JWT. Without a seen-set a captured-but-still-valid JWT
//! (leaked CI/k8s projected token, mTLS-terminating-proxy log) can be
//! replayed to mint a fresh bearer on *every* call for the JWT's full
//! validity window. The token-mint surface is **public by requirement**
//! (audit T6 tier ii) — there is no network tier to fall back on, so
//! the seen-set is a hard ship gate, not defense-in-depth.
//!
//! This port is the standard RFC 8693 / OIDC token-exchange anti-replay
//! control: before any token is minted, the token-exchange use case
//! atomically *claims* the presented JWT's identity. First presentation
//! → claimed → mint proceeds. Any subsequent presentation of the same
//! `jti`/composite within its TTL window → deny, no mint.
//!
//! # Layering
//!
//! - Port trait lives in `hort-domain` (zero I/O, zero `tracing`). The
//!   trait method returns [`Result<ReplayClaim, ReplayGuardError>`] —
//!   typed both ways; no string error inspection at the call site
//!   (mirrors [`FederationDenyReason`](super::federated_jwt_validator::FederationDenyReason)).
//! - Adapter implementation lives in `hort-adapters-postgres`
//!   (`replay_guard_repo.rs`) as a single
//!   `INSERT … ON CONFLICT DO NOTHING RETURNING` against the durable
//!   `jwt_replay_seen` table so the database arbitrates concurrent
//!   replays — no application-level lock, no read-then-write window.
//!
//! # Not `Deserialize`/`Serialize`
//!
//! [`ReplayKey`], [`ReplayClaim`], and [`ReplayGuardError`] intentionally
//! do **not** implement `Deserialize`/`Serialize`. They are internal-only
//! and never cross an HTTP boundary as a deserialised value (architect
//! anti-pattern: no-`Deserialize` lock — same rule as
//! [`ValidatedClaims`](super::federated_jwt_validator::ValidatedClaims)).

use chrono::{DateTime, Utc};

use super::BoxFuture;

// ---------------------------------------------------------------------------
// ReplayKey
// ---------------------------------------------------------------------------

/// The replay-claim key. The federation use case constructs exactly one
/// of these per exchange attempt; the variant is chosen by the resolved
/// `OidcIssuer.require_jti` flag + JWT `jti` presence (§5 behaviour
/// matrix):
///
/// | `jti` present? | `require_jti` | key |
/// |---|---|---|
/// | yes | (either) | [`ReplayKey::Jti`] |
/// | no | `false` | [`ReplayKey::Composite`] |
/// | no | `true` | (no key — denied `jti_required` before any claim) |
///
/// NOT `Deserialize`/`Serialize` — internal-only, never crosses an
/// HTTP boundary (mirrors the `ValidatedClaims` / `OidcIssuer`
/// no-`Deserialize` lock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayKey {
    /// JWT carried a `jti`. Key = (issuer_name, jti).
    Jti { issuer_name: String, jti: String },
    /// Issuer config allows missing `jti` (`require_jti = false`) and
    /// the JWT had none. Key = (issuer_name, iss, sub, iat, exp).
    ///
    /// `iat`/`exp` are `i64` NumericDate seconds in the JWT wire form
    /// (RFC 7519 §2) — the composite key must be byte-stable across
    /// presentations of the *same* token, so it uses the raw claim
    /// values, not a re-derived `DateTime`.
    Composite {
        issuer_name: String,
        iss: String,
        sub: String,
        iat: i64,
        exp: i64,
    },
}

/// Unit separator (`US`, 0x1F) delimiting the composite digest's
/// pre-image fields. A control character that cannot appear in a JSON
/// string claim makes the concatenation injective — two distinct
/// `(iss, sub, iat, exp)` tuples can never collide on the joined
/// pre-image.
const US: char = '\u{1f}';

impl ReplayKey {
    /// The `key_kind` discriminator written to / matched against the
    /// `jwt_replay_seen.key_kind` column. One value per variant; the
    /// PK includes it so a `jti` value can never collide with a
    /// composite digest (§3 PK semantics).
    pub fn key_kind(&self) -> &'static str {
        match self {
            Self::Jti { .. } => "jti",
            Self::Composite { .. } => "composite",
        }
    }

    /// The resolved `OidcIssuer.name` this key is scoped to (the
    /// `ValidatedClaims.issuer_name`, NOT the raw `iss` URL). Both
    /// variants carry it; it is the first PK column so the seen-set is
    /// namespaced per trusted issuer exactly as §2.3 keys it.
    pub fn issuer_name(&self) -> &str {
        match self {
            Self::Jti { issuer_name, .. } | Self::Composite { issuer_name, .. } => issuer_name,
        }
    }

    /// Stable single-column identity used by the PK
    /// `(issuer_name, key_kind, key_id)`.
    ///
    /// - `Jti` → the `jti` itself (already opaque; no digest needed).
    /// - `Composite` → `lower(hex(sha256(iss US sub US iat US exp)))`,
    ///   unit-separator-delimited so the pre-image is injective. The
    ///   component columns are also stored verbatim for audit/forensics
    ///   and to satisfy the row CHECK; the PK uses this digest so the
    ///   row is a single comparable key.
    ///
    /// This is the only place the composite digest is computed; the
    /// adapter binds the returned string directly into the PK column.
    pub fn key_id(&self) -> String {
        match self {
            Self::Jti { jti, .. } => jti.clone(),
            Self::Composite {
                iss, sub, iat, exp, ..
            } => {
                use sha2::{Digest, Sha256};
                let pre_image = format!("{iss}{US}{sub}{US}{iat}{US}{exp}");
                let digest = Sha256::digest(pre_image.as_bytes());
                // lowercase hex, matches the §3 schema note.
                let mut out = String::with_capacity(64);
                for byte in digest {
                    use std::fmt::Write as _;
                    let _ = write!(out, "{byte:02x}");
                }
                out
            }
        }
    }

    /// Metric-label value for the `result` label of
    /// `hort_jwt_replay_rejected_total` (§8) when [`ReplayClaim::Replayed`]
    /// is returned for this key. `Jti` → `replayed_jti`, `Composite` →
    /// `replayed_composite`. The string is part of the public metrics +
    /// deny-log contract (§7) — normative.
    pub fn replay_result_label(&self) -> &'static str {
        match self {
            Self::Jti { .. } => "replayed_jti",
            Self::Composite { .. } => "replayed_composite",
        }
    }
}

// ---------------------------------------------------------------------------
// ReplayClaim
// ---------------------------------------------------------------------------

/// Outcome of an atomic claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayClaim {
    /// First sighting — the row was inserted; mint may proceed.
    FirstSeen,
    /// This key is already in the seen-set within its TTL window — a
    /// replay. The use case denies; no token is minted.
    Replayed,
}

// ---------------------------------------------------------------------------
// ReplayGuardError
// ---------------------------------------------------------------------------

/// Why a claim could not be evaluated (infrastructure failure).
///
/// Distinct from [`ReplayClaim::Replayed`] — `Replayed` is an
/// authorization fact, `Unavailable` is an outage. The use case maps
/// `Unavailable` to a **fail-CLOSED** deny (§4): a replay guard that
/// cannot answer must not let a possibly-replayed token mint. There is
/// deliberately no `Ok`-with-unknown variant — the type forces the
/// caller to handle the outage explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayGuardError {
    /// The seen-set backing store (Postgres) was unreachable or the
    /// atomic claim statement failed for an infrastructure reason. The
    /// adapter logs the underlying cause at `error!`; this string is a
    /// short, non-sensitive summary for the deny path.
    Unavailable(String),
}

// ---------------------------------------------------------------------------
// Port trait
// ---------------------------------------------------------------------------

/// Outbound port for the durable anti-replay seen-set.
///
/// The single operation is an **atomic claim-or-report-replay**, never
/// a separate check-then-insert (a TOCTOU between two concurrent
/// replays would let both through). Implemented adapter-side as one
/// `INSERT … ON CONFLICT DO NOTHING RETURNING` so the database
/// arbitrates the race.
pub trait ReplayGuardPort: Send + Sync {
    /// Atomically claim `key` with the given `expires_at` (the row's
    /// TTL horizon, already computed = `min(jwt_remaining, fed_max)`,
    /// §3/§4).
    ///
    /// Returns [`ReplayClaim::FirstSeen`] iff this exact key was not
    /// present (and is now recorded), [`ReplayClaim::Replayed`] iff it
    /// already was, and [`ReplayGuardError::Unavailable`] iff the claim
    /// could not be evaluated (infrastructure failure → the caller
    /// fails closed).
    ///
    /// Callers MUST invoke this exactly once per exchange attempt,
    /// immediately before mint: a second call with the same key is by
    /// definition a replay.
    fn claim<'a>(
        &'a self,
        key: &'a ReplayKey,
        expires_at: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<ReplayClaim, ReplayGuardError>>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn jti_key() -> ReplayKey {
        ReplayKey::Jti {
            issuer_name: "github-actions".into(),
            jti: "jti-abc-123".into(),
        }
    }

    fn composite_key() -> ReplayKey {
        ReplayKey::Composite {
            issuer_name: "gitlab".into(),
            iss: "https://gitlab.com".into(),
            sub: "project_path:acme/app:ref:refs/heads/main".into(),
            iat: 1_700_000_000,
            exp: 1_700_003_600,
        }
    }

    // -- key_kind ------------------------------------------------------------

    #[test]
    fn key_kind_jti() {
        assert_eq!(jti_key().key_kind(), "jti");
    }

    #[test]
    fn key_kind_composite() {
        assert_eq!(composite_key().key_kind(), "composite");
    }

    // -- issuer_name ---------------------------------------------------------

    #[test]
    fn issuer_name_jti_variant() {
        assert_eq!(jti_key().issuer_name(), "github-actions");
    }

    #[test]
    fn issuer_name_composite_variant() {
        assert_eq!(composite_key().issuer_name(), "gitlab");
    }

    // -- key_id --------------------------------------------------------------

    #[test]
    fn key_id_jti_is_the_jti_verbatim() {
        // §3: for jti rows key_id is the jti itself (already opaque).
        assert_eq!(jti_key().key_id(), "jti-abc-123");
    }

    #[test]
    fn key_id_composite_is_lowercase_hex_sha256_64_chars() {
        let id = composite_key().key_id();
        assert_eq!(id.len(), 64, "sha256 hex is 64 chars");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "digest must be lowercase hex, got {id}"
        );
    }

    #[test]
    fn key_id_composite_is_stable_across_calls() {
        // A replayed (byte-identical) JWT must produce the SAME
        // composite key, hence the same digest — that is the whole
        // point of the composite fallback.
        assert_eq!(composite_key().key_id(), composite_key().key_id());
    }

    #[test]
    fn key_id_composite_matches_known_sha256_vector() {
        // Pin the exact pre-image construction (unit-separator-joined,
        // iat/exp rendered as decimal) so a future refactor cannot
        // silently change the digest and re-open every recorded replay.
        use sha2::{Digest, Sha256};
        let expected_pre_image =
            "https://gitlab.com\u{1f}project_path:acme/app:ref:refs/heads/main\u{1f}1700000000\u{1f}1700003600";
        let want = {
            let d = Sha256::digest(expected_pre_image.as_bytes());
            let mut s = String::new();
            for b in d {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
            }
            s
        };
        assert_eq!(composite_key().key_id(), want);
    }

    #[test]
    fn key_id_composite_injective_across_field_shifts() {
        // The unit separator makes the concatenation injective: moving
        // a character across the iss/sub boundary must change the
        // digest (no "ab|c" vs "a|bc" collision).
        let a = ReplayKey::Composite {
            issuer_name: "i".into(),
            iss: "ab".into(),
            sub: "c".into(),
            iat: 1,
            exp: 2,
        };
        let b = ReplayKey::Composite {
            issuer_name: "i".into(),
            iss: "a".into(),
            sub: "bc".into(),
            iat: 1,
            exp: 2,
        };
        assert_ne!(a.key_id(), b.key_id());
    }

    #[test]
    fn key_id_composite_differs_when_iat_differs() {
        // Two genuinely-distinct JWTs from the same subject differ in
        // `iat` (minted at different instants) → different keys → both
        // mint. Only a byte-identical replay collides.
        let mut later = composite_key();
        if let ReplayKey::Composite { iat, .. } = &mut later {
            *iat += 1;
        }
        assert_ne!(composite_key().key_id(), later.key_id());
    }

    // -- replay_result_label -------------------------------------------------

    #[test]
    fn replay_result_label_jti() {
        assert_eq!(jti_key().replay_result_label(), "replayed_jti");
    }

    #[test]
    fn replay_result_label_composite() {
        assert_eq!(composite_key().replay_result_label(), "replayed_composite");
    }

    #[test]
    fn replay_result_labels_are_distinct() {
        assert_ne!(
            jti_key().replay_result_label(),
            composite_key().replay_result_label()
        );
    }

    // -- ReplayClaim / ReplayGuardError shape --------------------------------

    #[test]
    fn replay_claim_variants_distinct_clone_debug() {
        let a = ReplayClaim::FirstSeen;
        let b = ReplayClaim::Replayed;
        assert_ne!(a, b);
        assert_eq!(a.clone(), ReplayClaim::FirstSeen);
        assert!(!format!("{b:?}").is_empty());
    }

    #[test]
    fn replay_guard_error_unavailable_carries_cause_and_eq() {
        let e = ReplayGuardError::Unavailable("db down".into());
        assert_eq!(e.clone(), ReplayGuardError::Unavailable("db down".into()));
        assert_ne!(
            e,
            ReplayGuardError::Unavailable("other".into()),
            "the cause string participates in equality"
        );
        assert!(format!("{e:?}").contains("db down"));
    }

    #[test]
    fn replay_key_clone_eq_debug() {
        let k = jti_key();
        assert_eq!(k.clone(), jti_key());
        assert_ne!(jti_key(), composite_key());
        assert!(!format!("{k:?}").is_empty());
    }

    /// Compile-time invariant: the port trait must remain
    /// dyn-compatible (registered as `Arc<dyn ReplayGuardPort>`).
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn ReplayGuardPort>();
    }

    // Architect anti-pattern lock (no `Deserialize`): the replay-key and
    // outcome types carry trust-decision data and must never be
    // reconstructable from untrusted input. `static_assertions` is a
    // dev-dep of `hort-domain` already.
    static_assertions::assert_not_impl_any!(ReplayKey: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(ReplayKey: serde::Serialize);
    static_assertions::assert_not_impl_any!(ReplayClaim: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(ReplayClaim: serde::Serialize);
    static_assertions::assert_not_impl_any!(ReplayGuardError: serde::de::DeserializeOwned);
    static_assertions::assert_not_impl_any!(ReplayGuardError: serde::Serialize);
}
