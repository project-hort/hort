//! `IdempotencyKey` — validated newtype used by
//! [`JobsRepository::enqueue_task`](crate::ports::jobs_repository::JobsRepository::enqueue_task)
//! to gate the destructive-cron per-UTC-day single-flight invariant.
//!
//! See ADR 0028 (destructive-task idempotency).
//!
//! # Invariants
//!
//! - **Charset:** `[A-Za-z0-9-_/:.]` only. ASCII-restricted; multi-byte UTF-8
//!   is rejected.
//! - **Length:** 1..=256 bytes (the empty string and anything over 256 bytes
//!   are rejected).
//!
//! The validator is mirrored 1:1 by the SQL CHECK constraint
//! `jobs_idempotency_key_charset_chk` on `public.jobs.idempotency_key`
//! (migration 009). Defence in depth — the schema rejects raw-SQL writes
//! that bypass the domain layer.
//!
//! # Anti-pattern: no `Deserialize`
//!
//! Per the architect doc, domain newtypes do NOT derive `Deserialize`.
//! HTTP / event-store adapters convert from `String` at the boundary via
//! [`IdempotencyKey::try_from`] — this keeps the validator the single
//! source of truth and prevents accidental construction from untrusted
//! JSON.

use crate::error::{DomainError, DomainResult};

/// A validated idempotency key, suitable for the `jobs.idempotency_key`
/// column.
///
/// Construct via [`IdempotencyKey::try_from`]. See module docs for the
/// charset and length invariants.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Validate and wrap `raw` as an `IdempotencyKey`.
    ///
    /// Returns [`DomainError::Validation`] when `raw` is empty, exceeds
    /// 256 bytes, or contains any byte outside `[A-Za-z0-9-_/:.]`. The
    /// allowed-byte test is byte-wise: any multi-byte UTF-8 codepoint
    /// (e.g. `é` = `0xc3 0xa9`) fails on the first non-ASCII byte.
    pub fn try_from(raw: impl Into<String>) -> DomainResult<Self> {
        let s = raw.into();
        if s.is_empty() {
            return Err(DomainError::Validation(
                "idempotency_key must not be empty".into(),
            ));
        }
        if s.len() > 256 {
            return Err(DomainError::Validation(format!(
                "idempotency_key length {} exceeds 256",
                s.len()
            )));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'/' | b':' | b'.'))
        {
            return Err(DomainError::Validation(
                "idempotency_key must match [A-Za-z0-9-_/:.]+".into(),
            ));
        }
        Ok(Self(s))
    }

    /// Borrow the inner string slice (for adapter binds and tracing
    /// fields).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- accept paths --------------------------------------------------------

    #[test]
    fn accepts_alphanumeric() {
        for raw in ["a", "Z", "0", "9", "AbCdEf123"] {
            let k = IdempotencyKey::try_from(raw).expect("alphanumeric must accept");
            assert_eq!(k.as_str(), raw);
        }
    }

    #[test]
    fn accepts_each_allowed_special_byte() {
        for raw in ["-", "_", "/", ":", "."] {
            let k = IdempotencyKey::try_from(raw).expect("allowed special bytes must accept");
            assert_eq!(k.as_str(), raw);
        }
    }

    #[test]
    fn accepts_mixed_destructive_cron_shape() {
        // The shape the HTTP handler derives.
        let raw = "cron:eventstore-archive:2026-06-03";
        let k = IdempotencyKey::try_from(raw).expect("destructive-cron shape must accept");
        assert_eq!(k.as_str(), raw);
    }

    #[test]
    fn accepts_length_one() {
        let k = IdempotencyKey::try_from("x").expect("len=1 must accept");
        assert_eq!(k.as_str(), "x");
    }

    #[test]
    fn accepts_length_256() {
        let raw = "a".repeat(256);
        let k = IdempotencyKey::try_from(raw.clone()).expect("len=256 must accept");
        assert_eq!(k.as_str(), raw.as_str());
    }

    // -- reject paths --------------------------------------------------------

    #[test]
    fn rejects_empty_string() {
        let err = IdempotencyKey::try_from("").expect_err("empty must reject");
        assert!(
            matches!(err, DomainError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn rejects_length_257() {
        let raw = "a".repeat(257);
        let err = IdempotencyKey::try_from(raw).expect_err("len=257 must reject");
        assert!(
            matches!(err, DomainError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn rejects_space() {
        let err = IdempotencyKey::try_from("a b").expect_err("space must reject");
        assert!(
            matches!(err, DomainError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn rejects_each_disallowed_special_byte() {
        // One per disallowed printable-ASCII byte-class commonly
        // encountered in URL/JSON payloads. Each must reject so an HTTP
        // boundary cannot silently smuggle a malformed key into the DB.
        for raw in [
            "a*b", "a@b", "a#b", "a+b", "a=b", "a,b", "a;b", "a(b", "a)b", "a[b", "a]b", "a{b",
            "a}b", "a!b", "a?b", "a$b", "a&b", "a~b", "a^b", "a%b", "a|b", "a\\b", "a\"b", "a'b",
            "a`b", "a<b", "a>b",
        ] {
            let err = IdempotencyKey::try_from(raw)
                .expect_err(&format!("disallowed-byte input {raw:?} must reject"));
            assert!(
                matches!(err, DomainError::Validation(_)),
                "expected Validation for {raw:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_multibyte_utf8() {
        // `é` = 0xc3 0xa9 — both bytes are outside the allowed set.
        // The byte-wise validator must reject before any UTF-8 decode.
        let err = IdempotencyKey::try_from("café").expect_err("multibyte UTF-8 must reject");
        assert!(
            matches!(err, DomainError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn rejects_control_bytes() {
        // \n, \t, \0 — non-printable ASCII outside the allowed set.
        for raw in ["a\nb", "a\tb", "a\0b"] {
            let err = IdempotencyKey::try_from(raw)
                .expect_err(&format!("control byte {raw:?} must reject"));
            assert!(
                matches!(err, DomainError::Validation(_)),
                "expected Validation for {raw:?}, got {err:?}"
            );
        }
    }

    // -- shape pins ----------------------------------------------------------

    #[test]
    fn clone_and_eq_round_trip() {
        let a = IdempotencyKey::try_from("cron:retention-purge:2026-06-03").expect("accept");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_compare_unequal() {
        let a = IdempotencyKey::try_from("cron:retention-purge:2026-06-03").expect("accept");
        let b = IdempotencyKey::try_from("cron:retention-purge:2026-06-04").expect("accept");
        assert_ne!(a, b);
    }
}
