//! # Argon2id hashing helper
//!
//! The workspace's single Argon2id facade for
//! **token hashing** (PAT validation + issuance). Same OWASP-2024
//! parameter set across every caller.
//!
//! ## Public surface
//!
//! - [`hash_token`] / [`verify_token`] — token-plaintext side; the input
//!   is high-entropy (160-bit base32 body) so the cost
//!   parameter is chosen for *forced verification time*, not entropy
//!   amplification.
//!
//! There is deliberately no `hash_password` / `verify_password` façade —
//! there is no local-admin-row identity path; users authenticate via
//! the IdP (see `docs/auth-catalog.md`).
//!
//! ## Constant-time guarantee
//!
//! Both `verify_*` functions ALWAYS run the full Argon2id verify cost,
//! even on malformed or empty `hash` input. When the supplied hash
//! cannot be parsed as a PHC string, the verifier runs against a
//! pre-computed sentinel hash so the path length matches the
//! valid-hash branch — validation stays constant-time even on
//! prefix-not-found.
//!
//! Tests assert this with a **call-counter spy**, NOT wall-clock
//! measurement (CI noise; the architectural invariant is "verifier
//! invoked exactly once per call regardless of input shape"). The
//! spy harness sits behind a `pub` trait so
//! [`crate::use_cases::pat_validation_use_case`] (and any future
//! cross-use-case caller) can reuse it without a parallel harness —
//! `pub(crate)` was sufficient when only this module's tests consumed
//! the trait, but the validator orchestrates Argon2 verify from
//! outside this module and needs to inject the same counter spy on
//! the same trait surface.
//!
//! ## OWASP 2024 parameters
//!
//! - `m_cost = 19_456` (KiB; ~19 MiB)
//! - `t_cost = 2`
//! - `p_cost = 1`
//!
//! Source: OWASP Password Storage Cheat Sheet, "Argon2id" §
//! (cheatsheetseries.owasp.org).

use std::sync::OnceLock;

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use password_hash::{rand_core::OsRng, SaltString};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Argon2id parameter set (OWASP 2024)
// ---------------------------------------------------------------------------

/// Memory cost in KiB. OWASP 2024 recommends a minimum of 19 MiB; we use
/// exactly that. Higher values trade login-latency for attack cost; the
/// 19 MiB floor is the accepted compromise for interactive auth paths.
const M_COST_KIB: u32 = 19_456;

/// Time cost (iterations). OWASP 2024 minimum.
const T_COST: u32 = 2;

/// Parallelism (lanes). OWASP 2024 minimum. Single-lane keeps the
/// verify path single-threaded and predictable on shared cores.
const P_COST: u32 = 1;

/// Build the canonical [`Argon2`] context. Used by every hash and
/// verify call. Centralising the construction means a future
/// parameter rotation touches one site.
fn argon2_context() -> Argon2<'static> {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, None)
        .expect("OWASP 2024 Argon2id parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

// ---------------------------------------------------------------------------
// Internal verifier trait — pub(crate) so B5 can reuse the spy harness
// ---------------------------------------------------------------------------

/// Verifier strategy. The default ([`DefaultArgon2Verifier`]) calls into
/// the real `argon2` crate. Tests inject a counter spy to assert the
/// "verify exactly once" invariant on every code path.
///
/// `pub` because
/// [`crate::use_cases::pat_validation_use_case::PatValidationUseCase`]
/// orchestrates Argon2 verify from outside this module and needs to
/// inject the same counter spy on the same trait surface so both
/// layers' constant-time tests use one harness rather than two
/// parallel ones.
pub trait Argon2Verifier: Send + Sync {
    /// Verify `plaintext` against the PHC-encoded `hash` string.
    /// Returns `true` iff the verification succeeds. Returns `false`
    /// for malformed PHC strings, parameter mismatches, and genuine
    /// password mismatches alike — callers must NOT distinguish.
    fn verify(&self, plaintext: &[u8], hash: &str) -> bool;
}

/// Production verifier. Delegates to `argon2::Argon2::verify_password`.
pub struct DefaultArgon2Verifier;

impl Argon2Verifier for DefaultArgon2Verifier {
    fn verify(&self, plaintext: &[u8], hash: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        argon2_context().verify_password(plaintext, &parsed).is_ok()
    }
}

// ---------------------------------------------------------------------------
// Sentinel hash for malformed-input branch
// ---------------------------------------------------------------------------

/// Pre-computed Argon2id PHC string used as the sentinel input on the
/// malformed-hash branch. Lazy-initialised on first call so unit tests
/// that never touch `verify_*` don't pay the construction cost. The
/// sentinel is hashed against a never-matching plaintext, so a real
/// caller plaintext can never accidentally satisfy it.
///
/// `pub` so [`PatValidationUseCase`] can run the
/// sentinel-verify branch on prefix-not-found while keeping the
/// architectural invariant "exactly one Argon2 verify per call shape"
/// — the validator's prefix-found and prefix-not-found arms must hit
/// the same verifier (one is the looked-up hash, the other is this
/// sentinel) so a counter spy observes parity across both paths.
///
/// [`PatValidationUseCase`]: crate::use_cases::pat_validation_use_case::PatValidationUseCase
pub fn sentinel_hash() -> &'static str {
    static SENTINEL: OnceLock<String> = OnceLock::new();
    SENTINEL.get_or_init(|| {
        // The plaintext content of the sentinel is irrelevant — the
        // verify call against it MUST always fail (we hand it a
        // different `plaintext` argument at the call site). We pick a
        // fixed string so the sentinel is deterministic; any value
        // works. The salt is freshly generated to keep the encoded
        // PHC well-formed.
        let salt = SaltString::generate(&mut OsRng);
        argon2_context()
            .hash_password(b"argon2-hash-helper-sentinel", &salt)
            .expect("Argon2id hash of sentinel input cannot fail with valid params")
            .to_string()
    })
}

// ---------------------------------------------------------------------------
// Shared verify implementation — every public verify_* delegates here
// ---------------------------------------------------------------------------

/// Shared verify path. The verifier is **always** invoked exactly once,
/// even when `hash` is empty or unparseable — the malformed branch
/// runs the verify against a sentinel so the work is unconditional.
///
/// Returns `true` iff the supplied `hash` parses as a PHC string AND
/// the verifier accepts `plaintext` against it.
fn verify_inner(verifier: &dyn Argon2Verifier, plaintext: &[u8], hash: &str) -> bool {
    // We need to differentiate "valid hash, run real verify" from
    // "malformed hash, run sentinel verify" while keeping the verify
    // call unconditional. The `parse_ok` flag captures the parse
    // outcome; we run the verifier against the real input on the
    // valid path and against the sentinel on the malformed path —
    // both branches do EXACTLY ONE verify call. The malformed branch
    // discards the verify result and returns `false` regardless.
    let parse_ok = PasswordHash::new(hash).is_ok();
    if parse_ok {
        verifier.verify(plaintext, hash)
    } else {
        // Run the sentinel verify so the path length matches; ignore
        // the result. The sentinel's plaintext is fixed and not
        // equal to any caller `plaintext`, so even an attacker who
        // somehow guessed the sentinel's encoded hash gets `false`
        // back — the unconditional `false` return below is
        // belt-and-braces.
        let _ = verifier.verify(plaintext, sentinel_hash());
        false
    }
}

// ---------------------------------------------------------------------------
// Public token-hash surface
// ---------------------------------------------------------------------------

/// Errors returned by [`hash_token`].
///
/// Distinct from `hort_app::error::AppError` because the PAT issuance
/// path maps this directly to a user-facing error before the
/// application use case runs.
#[derive(Debug, Error)]
pub enum TokenHashError {
    /// The Argon2id context failed to hash. With OWASP-2024 parameters
    /// this only fires on a memory-allocation failure for the 19 MiB
    /// scratch buffer — vanishingly rare in the runtime this binary
    /// targets, but we surface it rather than panic.
    #[error("Argon2id hashing failed: {0}")]
    HashFailed(String),
}

/// Hash `plaintext` with Argon2id at the workspace's standard
/// parameter set. Returns the PHC-encoded hash (`$argon2id$v=19$m=…`).
///
/// Used by:
/// - PAT issuance — full token plaintext as input.
pub fn hash_token(plaintext: &str) -> Result<String, TokenHashError> {
    let salt = SaltString::generate(&mut OsRng);
    argon2_context()
        .hash_password(plaintext.as_bytes(), &salt)
        .map(|ph| ph.to_string())
        .map_err(|e| TokenHashError::HashFailed(e.to_string()))
}

/// Verify `plaintext` against the supplied PHC-encoded `hash`.
///
/// Always runs exactly one Argon2 verify regardless of `hash` shape —
/// malformed/empty input takes the sentinel branch (also one verify),
/// preserving the constant-time contract.
///
/// Returns `false` on any non-success outcome (including parse
/// failure, verification mismatch, parameter mismatch). Callers MUST
/// NOT distinguish.
pub fn verify_token(plaintext: &str, hash: &str) -> bool {
    verify_inner(&DefaultArgon2Verifier, plaintext.as_bytes(), hash)
}

// ---------------------------------------------------------------------------
// pub(crate) test helpers — exposed for the auth-middleware reuse
// ---------------------------------------------------------------------------

/// Internal entry point that lets a caller inject a custom
/// [`Argon2Verifier`] (a counter spy in tests). Used by the
/// auth-middleware tests as well as this module's own tests.
///
/// `#[allow(dead_code)]` — the function is consumed only from
/// `cfg(test)` blocks; the build sees no callers outside test cfg.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn verify_token_with(
    verifier: &dyn Argon2Verifier,
    plaintext: &str,
    hash: &str,
) -> bool {
    verify_inner(verifier, plaintext.as_bytes(), hash)
}

/// PHC-prefix substring used inside this module's sentinel-construction
/// and tests to assert a well-formed Argon2id hash. A genuine encoded
/// hash from this module always starts with `$argon2id$v=19$`.
/// Centralising the literal here means a future parameter rotation
/// that bumps the version touches one site.
///
/// Private (not `pub(crate)`) — there is no out-of-module consumer;
/// the password-hash newtype that once checked this prefix is gone.
#[allow(dead_code)]
const ARGON2ID_PHC_PREFIX: &str = "$argon2id$v=19$";

// ---------------------------------------------------------------------------
// Tests — counter-spy harness covers every input shape
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counter-spy verifier. Wraps the real verifier and counts how
    /// many times `verify` is called — this is the architectural
    /// invariant from design doc §8 invariant 1: every input shape
    /// (valid hash, wrong hash, malformed hash, empty hash) hits the
    /// verify path EXACTLY ONCE.
    struct CountingVerifier {
        calls: AtomicUsize,
    }

    impl CountingVerifier {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Argon2Verifier for CountingVerifier {
        fn verify(&self, plaintext: &[u8], hash: &str) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            DefaultArgon2Verifier.verify(plaintext, hash)
        }
    }

    /// A spy that records calls but always returns `false`. Used to
    /// confirm a `false` return is not the result of a verifier
    /// short-circuit but of an actual verify call.
    struct AlwaysFalseSpy {
        calls: AtomicUsize,
    }
    impl AlwaysFalseSpy {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    impl Argon2Verifier for AlwaysFalseSpy {
        fn verify(&self, _plaintext: &[u8], _hash: &str) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            false
        }
    }

    // --- hash_token + verify_token ----------------------------------------

    #[test]
    fn hash_token_round_trips() {
        let hash = hash_token("hunter2-token").expect("hash succeeds");
        assert!(
            hash.starts_with(ARGON2ID_PHC_PREFIX),
            "PHC string should start with `$argon2id$v=19$`, got: {hash}"
        );
        assert!(verify_token("hunter2-token", &hash));
    }

    #[test]
    fn hash_token_unique_salt_per_call() {
        // Two calls with identical plaintext MUST produce distinct
        // PHC strings (random salt per call).
        let h1 = hash_token("same").unwrap();
        let h2 = hash_token("same").unwrap();
        assert_ne!(h1, h2, "salt must be random per call");
        // Both verify against the same plaintext.
        assert!(verify_token("same", &h1));
        assert!(verify_token("same", &h2));
    }

    #[test]
    fn verify_token_rejects_wrong_plaintext() {
        let hash = hash_token("right").unwrap();
        assert!(!verify_token("wrong", &hash));
    }

    // --- Counter-spy: every input shape calls verify exactly once ---------

    #[test]
    fn verify_token_calls_verifier_once_on_valid_hash() {
        let hash = hash_token("plain").unwrap();
        let spy = CountingVerifier::new();
        let ok = verify_token_with(&spy, "plain", &hash);
        assert!(ok);
        assert_eq!(
            spy.calls(),
            1,
            "valid-hash branch must invoke verifier exactly once"
        );
    }

    #[test]
    fn verify_token_calls_verifier_once_on_wrong_plaintext() {
        let hash = hash_token("right").unwrap();
        let spy = CountingVerifier::new();
        let ok = verify_token_with(&spy, "wrong", &hash);
        assert!(!ok);
        assert_eq!(
            spy.calls(),
            1,
            "wrong-plaintext branch must invoke verifier exactly once"
        );
    }

    #[test]
    fn verify_token_calls_verifier_once_on_malformed_hash() {
        let spy = CountingVerifier::new();
        let ok = verify_token_with(&spy, "anything", "not-a-phc-string");
        assert!(!ok, "malformed hash MUST NOT verify");
        assert_eq!(
            spy.calls(),
            1,
            "malformed-hash branch must invoke verifier exactly once (sentinel path)"
        );
    }

    #[test]
    fn verify_token_calls_verifier_once_on_empty_hash() {
        let spy = CountingVerifier::new();
        let ok = verify_token_with(&spy, "anything", "");
        assert!(!ok, "empty hash MUST NOT verify");
        assert_eq!(
            spy.calls(),
            1,
            "empty-hash branch must invoke verifier exactly once (sentinel path)"
        );
    }

    #[test]
    fn verify_token_calls_verifier_once_on_truncated_phc() {
        // A PHC-shaped but incomplete string. The parser rejects;
        // sentinel branch runs.
        let spy = CountingVerifier::new();
        let ok = verify_token_with(&spy, "anything", "$argon2id$v=19$broken");
        assert!(!ok);
        assert_eq!(spy.calls(), 1);
    }

    #[test]
    fn verify_token_returns_false_when_verifier_always_false() {
        // A pathological verifier that always says false — even on a
        // structurally valid hash. We assert (a) one call still
        // happens and (b) the result is `false`. This pins the
        // contract that a verifier `false` return is honoured;
        // there's no hidden short-circuit that bypasses the verifier.
        let hash = hash_token("plain").unwrap();
        let spy = AlwaysFalseSpy::new();
        let ok = verify_token_with(&spy, "plain", &hash);
        assert!(!ok);
        assert_eq!(spy.calls(), 1);
    }

    // --- Sentinel correctness --------------------------------------------

    #[test]
    fn sentinel_hash_is_well_formed_phc() {
        // The sentinel must be a parseable PHC string itself —
        // otherwise the malformed branch's verify call would fail
        // for the wrong reason.
        let s = sentinel_hash();
        assert!(s.starts_with(ARGON2ID_PHC_PREFIX));
        assert!(PasswordHash::new(s).is_ok());
    }

    #[test]
    fn sentinel_hash_does_not_match_any_realistic_caller_plaintext() {
        // The sentinel was hashed against the fixed plaintext
        // `argon2-hash-helper-sentinel`. Real callers (PATs, user
        // passwords) will never paste that exact string, so the
        // unconditional `false` return on the malformed branch is
        // belt-and-braces — defensive but never load-bearing.
        let s = sentinel_hash();
        // Just make sure the sentinel can be verified ONLY against
        // its known plaintext — confirms the OnceLock didn't get a
        // garbage value.
        assert!(verify_token("argon2-hash-helper-sentinel", s));
        assert!(!verify_token("definitely-not-the-sentinel", s));
    }

    // --- Error variant ---------------------------------------------------

    #[test]
    fn token_hash_error_display_includes_cause() {
        // Construct the error directly — the production path doesn't
        // hit `HashFailed` under normal memory conditions, but the
        // type's Display contract is part of the public surface.
        let err = TokenHashError::HashFailed("memory exhausted".into());
        assert!(err.to_string().contains("Argon2id"));
        assert!(err.to_string().contains("memory exhausted"));
    }

    #[test]
    fn argon2_context_uses_owasp_2024_params() {
        // Pin the parameter constants — a perf-panic PR that drops
        // them silently would be caught here. The catalog +
        // design doc §7 and §8 invariant 1 depend on these values.
        assert_eq!(M_COST_KIB, 19_456);
        assert_eq!(T_COST, 2);
        assert_eq!(P_COST, 1);
    }
}
