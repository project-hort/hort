//! `DispatchSecretPort` — selects the underlying adapter by
//! `SecretRef::source`. Per design doc §5.3 — three lines of routing,
//! no env vars, no config knobs.

use std::sync::Arc;

use hort_domain::error::DomainResult;
use hort_domain::ports::secret_port::{SecretPort, SecretRef, SecretSource, SecretValue};
use hort_domain::ports::BoxFuture;

/// Routes a `SecretPort::resolve` call to the env-var or file adapter
/// based on `SecretRef::source`.
///
/// Public field access is the documented composition shape (design
/// doc §5.3); there is no constructor function — direct struct init
/// keeps the wiring obvious in `hort-server::composition`.
pub struct DispatchSecretPort {
    pub env: Arc<dyn SecretPort>,
    pub file: Arc<dyn SecretPort>,
}

impl SecretPort for DispatchSecretPort {
    fn resolve<'a>(&'a self, reference: &'a SecretRef) -> BoxFuture<'a, DomainResult<SecretValue>> {
        Box::pin(async move {
            match reference.source {
                SecretSource::EnvVar => self.env.resolve(reference).await,
                SecretSource::File => self.file.resolve(reference).await,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::block_on;
    use hort_domain::error::DomainError;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Stub `SecretPort` that records the number of calls it received.
    /// Returns a fixed `Err(Invariant("called: <name>"))` so the test
    /// can verify *which* stub was reached without decoding bytes.
    struct CountingStub {
        name: &'static str,
        calls: AtomicU32,
    }

    impl CountingStub {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                calls: AtomicU32::new(0),
            }
        }
        fn count(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl SecretPort for CountingStub {
        fn resolve<'a>(
            &'a self,
            _reference: &'a SecretRef,
        ) -> BoxFuture<'a, DomainResult<SecretValue>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let name = self.name;
            Box::pin(async move {
                Err::<SecretValue, _>(DomainError::Invariant(format!("called: {name}")))
            })
        }
    }

    fn expect_invariant_err(result: DomainResult<SecretValue>) -> String {
        match result {
            Err(DomainError::Invariant(msg)) => msg,
            Err(other) => panic!("expected Invariant, got {other:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn env_var_routes_to_env_adapter() {
        let env_stub = Arc::new(CountingStub::new("env"));
        let file_stub = Arc::new(CountingStub::new("file"));
        let dispatch = DispatchSecretPort {
            env: env_stub.clone(),
            file: file_stub.clone(),
        };
        let r = SecretRef {
            source: SecretSource::EnvVar,
            location: "FOO".into(),
        };
        let msg = expect_invariant_err(block_on(dispatch.resolve(&r)));
        assert_eq!(msg, "called: env");
        assert_eq!(env_stub.count(), 1, "env adapter should have been called");
        assert_eq!(file_stub.count(), 0, "file adapter must not be called");
    }

    #[test]
    fn file_routes_to_file_adapter() {
        let env_stub = Arc::new(CountingStub::new("env"));
        let file_stub = Arc::new(CountingStub::new("file"));
        let dispatch = DispatchSecretPort {
            env: env_stub.clone(),
            file: file_stub.clone(),
        };
        let r = SecretRef {
            source: SecretSource::File,
            location: "/etc/secrets/x".into(),
        };
        let msg = expect_invariant_err(block_on(dispatch.resolve(&r)));
        assert_eq!(msg, "called: file");
        assert_eq!(env_stub.count(), 0, "env adapter must not be called");
        assert_eq!(file_stub.count(), 1, "file adapter should have been called");
    }
}
