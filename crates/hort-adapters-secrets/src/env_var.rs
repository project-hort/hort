//! `EnvVarSecretAdapter` — resolves `SecretRef { source: EnvVar, location }`
//! by reading `std::env::var(location)`.
//!
//! No I/O beyond the syscall, no cache. Process env is immutable for the
//! lifetime of the process; rotation requires the file source.

use std::env::VarError;

use hort_domain::error::DomainResult;
use hort_domain::ports::secret_port::{
    SecretError, SecretPort, SecretRef, SecretSource, SecretValue,
};
use hort_domain::ports::BoxFuture;

use crate::metrics::{classify_to_domain_error, emit_resolve, values, SecretResolveResult};

/// Reads secrets from process environment variables.
///
/// Stateless and zero-sized — the same instance can be shared via
/// `Arc<dyn SecretPort>` across the whole process.
pub struct EnvVarSecretAdapter;

impl SecretPort for EnvVarSecretAdapter {
    fn resolve<'a>(&'a self, reference: &'a SecretRef) -> BoxFuture<'a, DomainResult<SecretValue>> {
        Box::pin(async move {
            // Defensive: if the dispatcher mis-routes a non-env_var
            // reference here, surface it as a Decode error. The
            // dispatcher is the trust boundary; this branch is the
            // last line of defence.
            if reference.source != SecretSource::EnvVar {
                emit_resolve(values::SOURCE_ENV_VAR, SecretResolveResult::DecodeError);
                tracing::error!(
                    source = "env_var",
                    location = %reference.location,
                    "EnvVarSecretAdapter received non-env_var SecretRef",
                );
                let err = SecretError::Decode(
                    "EnvVarSecretAdapter received non-env_var SecretRef".into(),
                );
                return Err(classify_to_domain_error(&err));
            }
            match std::env::var(&reference.location) {
                Ok(s) => {
                    emit_resolve(values::SOURCE_ENV_VAR, SecretResolveResult::Success);
                    // Demoted from `info!` per the observability rule:
                    // `info!` is reserved for state-changing or
                    // security-impact events; routine secret resolves
                    // are neither. Failure arms (NotFound /
                    // NotUnicode) keep WARN/ERROR.
                    tracing::debug!(
                        source = "env_var",
                        location = %reference.location,
                        "secret resolved",
                    );
                    Ok(SecretValue::from_bytes(s.into_bytes()))
                }
                Err(VarError::NotPresent) => {
                    emit_resolve(values::SOURCE_ENV_VAR, SecretResolveResult::NotFound);
                    tracing::warn!(
                        source = "env_var",
                        location = %reference.location,
                        "secret not found",
                    );
                    let err = SecretError::NotFound {
                        source: SecretSource::EnvVar,
                        location: reference.location.clone(),
                    };
                    Err(classify_to_domain_error(&err))
                }
                Err(VarError::NotUnicode(_)) => {
                    emit_resolve(values::SOURCE_ENV_VAR, SecretResolveResult::DecodeError);
                    tracing::error!(
                        source = "env_var",
                        location = %reference.location,
                        "env var contains invalid UTF-8",
                    );
                    let err = SecretError::Decode("env var contains invalid UTF-8".into());
                    Err(classify_to_domain_error(&err))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::block_on;
    use hort_domain::error::DomainError;

    #[test]
    fn happy_path_returns_value() {
        // `temp_env::with_var` guarantees set→test→unset, even on panic.
        // Without it, parallel test runs would race on global env state.
        temp_env::with_var("HORT_TEST_HAPPY", Some("hunter2"), || {
            let adapter = EnvVarSecretAdapter;
            let r = SecretRef {
                source: SecretSource::EnvVar,
                location: "HORT_TEST_HAPPY".into(),
            };
            let v = block_on(adapter.resolve(&r)).expect("resolve");
            assert_eq!(v.as_bytes(), b"hunter2");
        });
    }

    /// Helper: assert the result is `Err(DomainError::Invariant(msg))` and
    /// return the message. `SecretValue` has no `Debug` so we cannot
    /// use `unwrap_err()` directly — match by hand.
    fn expect_invariant_err(result: DomainResult<SecretValue>) -> String {
        match result {
            Err(DomainError::Invariant(msg)) => msg,
            Err(other) => panic!("expected Invariant, got {other:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn not_present_returns_invariant_error() {
        // Ensure the var is unset for the duration of this test.
        temp_env::with_var_unset("HORT_TEST_NOT_PRESENT_VAR", || {
            let adapter = EnvVarSecretAdapter;
            let r = SecretRef {
                source: SecretSource::EnvVar,
                location: "HORT_TEST_NOT_PRESENT_VAR".into(),
            };
            let msg = expect_invariant_err(block_on(adapter.resolve(&r)));
            assert!(msg.contains("not found"), "got: {msg}");
            assert!(msg.contains("HORT_TEST_NOT_PRESENT_VAR"), "got: {msg}");
        });
    }

    #[test]
    fn mismatched_source_returns_decode_error() {
        let adapter = EnvVarSecretAdapter;
        let r = SecretRef {
            source: SecretSource::File,
            location: "/etc/secrets/wrong".into(),
        };
        let msg = expect_invariant_err(block_on(adapter.resolve(&r)));
        assert!(msg.contains("non-env_var"), "got: {msg}");
    }

    // ----------------------------------------------------------------------
    // Demoted log level — success resolves emit debug!, not info!
    // ----------------------------------------------------------------------

    #[tracing_test::traced_test]
    #[test]
    fn success_resolve_does_not_emit_info_line() {
        // The success arm was demoted from `info!` to `debug!`; this
        // test pins the new contract by asserting no INFO-level
        // "secret resolved" line is captured.
        temp_env::with_var("HORT_TEST_DEMOTED_LEVEL", Some("v"), || {
            let adapter = EnvVarSecretAdapter;
            let r = SecretRef {
                source: SecretSource::EnvVar,
                location: "HORT_TEST_DEMOTED_LEVEL".into(),
            };
            let _ = block_on(adapter.resolve(&r)).expect("resolve");
        });

        logs_assert(|lines: &[&str]| {
            // Use ` INFO ` (with whitespace boundaries) to match the
            // tracing-subscriber level field, not arbitrary substrings
            // inside test names or env-var names.
            let info_resolved = lines
                .iter()
                .filter(|l| l.contains(" INFO ") && l.contains("secret resolved"))
                .count();
            if info_resolved == 0 {
                Ok(())
            } else {
                Err(format!(
                    "successful env-var resolve must not emit INFO-level \
                     'secret resolved' (found {info_resolved} in: {lines:?})"
                ))
            }
        });
    }

    #[tracing_test::traced_test]
    #[test]
    fn not_present_still_emits_warn() {
        // Failure paths keep their level — the demotion only affects
        // the success arm.
        temp_env::with_var_unset("HORT_TEST_NEVER_SET_FOR_DEMOTION_TEST", || {
            let adapter = EnvVarSecretAdapter;
            let r = SecretRef {
                source: SecretSource::EnvVar,
                location: "HORT_TEST_NEVER_SET_FOR_DEMOTION_TEST".into(),
            };
            let _ = block_on(adapter.resolve(&r));
        });

        logs_assert(|lines: &[&str]| {
            let warn_lines = lines
                .iter()
                .filter(|l| l.contains(" WARN ") && l.contains("secret not found"))
                .count();
            if warn_lines >= 1 {
                Ok(())
            } else {
                Err(format!(
                    "expected at least one WARN 'secret not found' line; got: {lines:?}"
                ))
            }
        });
    }

    /// Non-UTF-8 env var. Building a non-UTF-8 `OsString` is portable on
    /// Unix via `OsStringExt::from_vec`; gated to `#[cfg(unix)]` so the
    /// test compiles on Windows but is skipped (the `Err(NotUnicode)`
    /// arm is still type-checked).
    #[cfg(unix)]
    #[test]
    fn not_unicode_returns_decode_error() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        // 0xFF is invalid as the first byte of a UTF-8 sequence.
        let bad = OsString::from_vec(vec![0xFFu8, 0xFE, 0xFD]);

        temp_env::with_var("HORT_TEST_NOT_UNICODE", Some(&bad), || {
            let adapter = EnvVarSecretAdapter;
            let r = SecretRef {
                source: SecretSource::EnvVar,
                location: "HORT_TEST_NOT_UNICODE".into(),
            };
            let msg = expect_invariant_err(block_on(adapter.resolve(&r)));
            assert!(msg.contains("invalid UTF-8"), "got: {msg}");
        });
    }
}
