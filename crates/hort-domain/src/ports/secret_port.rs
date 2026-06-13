use serde::{Deserialize, Serialize};

use crate::error::DomainResult;

use super::BoxFuture;

/// Outbound port: resolves a [`SecretRef`] to its underlying bytes.
///
/// The port carries the contract; concrete adapters
/// (env-var, file, future Vault / KMS / SOPS backends) live in a
/// dedicated `hort-adapters-secret` crate.
///
/// `Err(_)` from this port is mapped to
/// [`crate::error::DomainError::Invariant`] at the consumption site
/// (e.g. `hort-adapters-upstream-http::fetch_bearer_token`); the
/// adapter side keeps formatting concerns out of the domain.
pub trait SecretPort: Send + Sync {
    fn resolve<'a>(&'a self, reference: &'a SecretRef) -> BoxFuture<'a, DomainResult<SecretValue>>;
}

/// Reference to a secret. Carries enough information for the
/// [`SecretPort`] adapter to fetch the underlying bytes without ever
/// embedding the secret material itself.
///
/// The hashable shape lets callers cache resolution results keyed on
/// the reference (e.g. an in-memory upstream-token cache that avoids
/// re-reading `/etc/secrets/foo` on every request).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretRef {
    pub source: SecretSource,
    /// Source-specific locator. For [`SecretSource::EnvVar`], an
    /// environment-variable name. For [`SecretSource::File`], an
    /// absolute filesystem path.
    pub location: String,
}

/// Where a secret's bytes are read from.
///
/// Closed enum — adapters that need a new source kind extend this set
/// in coordination with the port contract; the design doc §2 is the
/// canonical list. Serialised lower-snake-case so YAML config files
/// can spell `source: env_var` / `source: file`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretSource {
    EnvVar,
    File,
}

/// A resolved secret. Drop zeroes the inner bytes; missing
/// `Debug` / `Display` / `Serialize` / `Clone` impls make accidental
/// log emission, JSON serialisation, or unexpected duplication a
/// compile error.
///
/// The zeroize-on-drop guarantee comes from the `Zeroizing<Vec<u8>>`
/// wrapper. The compile-time invariants below are equally
/// load-bearing: a future change that derives `Debug` (etc.) breaks
/// the security contract and these doctests stand guard.
///
/// ```compile_fail
/// use hort_domain::ports::secret_port::SecretValue;
/// let v = SecretValue::from_bytes(vec![1, 2, 3]);
/// let _ = format!("{:?}", v);
/// ```
///
/// ```compile_fail
/// use hort_domain::ports::secret_port::SecretValue;
/// let v = SecretValue::from_bytes(vec![1, 2, 3]);
/// let _ = v.clone();
/// ```
pub struct SecretValue(zeroize::Zeroizing<Vec<u8>>);

impl SecretValue {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Failure modes from a [`SecretPort::resolve`] call.
///
/// Adapters return `DomainResult<SecretValue>` where the `Err` arm is
/// constructed by stringifying one of these variants into
/// `DomainError::Invariant`. Keeping `SecretError` separate
/// from `DomainError` and intentionally NOT implementing
/// `From<SecretError> for DomainError` keeps the domain layer free of
/// adapter formatting choices: the boundary mapping lives in the
/// adapter crate that consumes the port.
#[derive(Debug)]
pub enum SecretError {
    NotFound {
        source: SecretSource,
        location: String,
    },
    ReadFailure(String),
    Decode(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The field is named `source` for symmetry with `SecretRef`,
            // not for `std::error::Error::source()` chaining — `Display`
            // is implemented manually to keep that shape without
            // thiserror auto-deriving an error-chain link.
            Self::NotFound { source, location } => {
                write!(f, "secret not found: {source:?}:{location}")
            }
            Self::ReadFailure(msg) => write!(f, "secret read failure: {msg}"),
            Self::Decode(msg) => write!(f, "secret content invalid: {msg}"),
        }
    }
}

impl std::error::Error for SecretError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_value_round_trip() {
        let v = SecretValue::from_bytes(vec![1, 2, 3]);
        assert_eq!(v.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn secret_value_round_trip_empty() {
        // Boundary: zero-byte secrets must round-trip without panicking
        // (e.g. an empty file resolved as a SecretRef File source).
        let v = SecretValue::from_bytes(vec![]);
        assert!(v.as_bytes().is_empty());
    }

    #[test]
    fn secret_value_drop_does_not_panic() {
        // The Zeroizing<Vec<u8>> Drop impl is upstream-tested; this
        // case asserts our wrapper does not introduce a panic in Drop.
        // Construct in a scope and let it fall out — no assertion is
        // needed beyond the test surviving the destructor.
        {
            let _v = SecretValue::from_bytes(vec![0x42; 32]);
        }
    }

    #[test]
    fn secret_value_preserves_every_byte() {
        // Round-trip over a full 0..=255 window — guards against the
        // accidental introduction of any encoding/transformation
        // step inside `from_bytes` / `as_bytes`.
        let bytes: Vec<u8> = (0u8..=255).collect();
        let v = SecretValue::from_bytes(bytes.clone());
        assert_eq!(v.as_bytes(), bytes.as_slice());
        assert_eq!(v.as_bytes().len(), 256);
    }

    #[test]
    fn secret_ref_serializes_envvar_as_snake_case() {
        let r = SecretRef {
            source: SecretSource::EnvVar,
            location: "HORT_UPSTREAM_TOKEN".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains("\"source\":\"env_var\""),
            "expected env_var, got {json}"
        );
        assert!(json.contains("\"location\":\"HORT_UPSTREAM_TOKEN\""));
    }

    #[test]
    fn secret_ref_round_trip_envvar() {
        let r = SecretRef {
            source: SecretSource::EnvVar,
            location: "FOO".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: SecretRef = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn secret_ref_round_trip_file() {
        let r = SecretRef {
            source: SecretSource::File,
            location: "/etc/secrets/foo".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains("\"source\":\"file\""),
            "expected file, got {json}"
        );
        let back: SecretRef = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn secret_source_rejects_unknown_variant() {
        // `vault` is not a SecretSource variant — this must fail rather than
        // silently default. The test exists so a future variant addition is
        // a deliberate decision (touch the enum, touch this test).
        let json = r#"{"source":"vault","location":"path/to/token"}"#;
        let result: Result<SecretRef, _> = serde_json::from_str(json);
        assert!(result.is_err(), "expected unknown variant to be rejected");
    }

    #[test]
    fn secret_ref_hash_eq_for_identical_fields() {
        use std::collections::HashSet;
        let a = SecretRef {
            source: SecretSource::EnvVar,
            location: "FOO".into(),
        };
        let b = SecretRef {
            source: SecretSource::EnvVar,
            location: "FOO".into(),
        };
        let mut set = HashSet::new();
        set.insert(a);
        // Equivalent value must hash to the same bucket and report present.
        assert!(set.contains(&b));
    }

    #[test]
    fn secret_ref_hash_neq_for_different_fields() {
        use std::collections::HashSet;
        let a = SecretRef {
            source: SecretSource::EnvVar,
            location: "FOO".into(),
        };
        let b = SecretRef {
            source: SecretSource::File,
            location: "FOO".into(),
        };
        let c = SecretRef {
            source: SecretSource::EnvVar,
            location: "BAR".into(),
        };
        let mut set = HashSet::new();
        set.insert(a);
        assert!(!set.contains(&b), "different source must not collide");
        assert!(!set.contains(&c), "different location must not collide");
    }

    #[test]
    fn secret_error_display_not_found() {
        let err = SecretError::NotFound {
            source: SecretSource::EnvVar,
            location: "MISSING".into(),
        };
        assert_eq!(err.to_string(), "secret not found: EnvVar:MISSING");
    }

    #[test]
    fn secret_error_display_not_found_file_variant() {
        let err = SecretError::NotFound {
            source: SecretSource::File,
            location: "/etc/secrets/missing".into(),
        };
        assert_eq!(
            err.to_string(),
            "secret not found: File:/etc/secrets/missing"
        );
    }

    #[test]
    fn secret_error_is_std_error() {
        // Box<dyn Error> compatibility — adapters wrap secret-port
        // failures into DomainError::Invariant via the Display impl,
        // but tooling that wants a `&dyn Error` (test logging,
        // anyhow::Error::msg, …) needs the std::error::Error impl too.
        fn assert_is_error<E: std::error::Error>(_: &E) {}
        assert_is_error(&SecretError::ReadFailure("x".into()));
    }

    #[test]
    fn secret_error_display_read_failure() {
        let err = SecretError::ReadFailure("permission denied".into());
        assert_eq!(err.to_string(), "secret read failure: permission denied");
    }

    #[test]
    fn secret_error_display_decode() {
        let err = SecretError::Decode("not valid utf-8".into());
        assert_eq!(err.to_string(), "secret content invalid: not valid utf-8");
    }

    #[test]
    fn secret_port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: size_of call executes in the test body for coverage.
        let _ = size_of::<&dyn SecretPort>();
    }
}
