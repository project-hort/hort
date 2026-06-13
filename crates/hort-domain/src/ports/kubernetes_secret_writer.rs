//! Outbound port for the fallback PAT-rotation reconciler's k8s Secret
//! writes (ADR 0018; see
//! `docs/architecture/how-to/rotating-service-account-tokens.md`).
//!
//! The `ServiceAccountRotationHandler` drives this
//! port. Per tick it reads the existing Secret at
//! `(target_secret_namespace, target_secret_name)`, decides freshness
//! against the `project-hort.de/last-rotated` annotation (annotation rather than
//! label because RFC 3339 timestamps contain `:`, which the apiserver
//! rejects in label values), mints a new PAT when stale, and writes
//! the new bytes via [`KubernetesSecretWriter::upsert_managed`].
//!
//! The port is intentionally narrow — it surfaces only the
//! reconciler-managed metadata the reconciler reads + the upsert
//! payload the reconciler writes.
//! Implementations live in `hort-adapters-kubernetes` and run against
//! either an in-cluster ServiceAccount token (`kube::Client::try_default`
//! prefers `/var/run/secrets/kubernetes.io/serviceaccount/token`) or, in
//! development, a kubeconfig the operator has on disk — that fallback
//! lives in `kube-rs` itself and is not surfaced as a separate env-var
//! knob (in-cluster only for v1; the dev-laptop case is
//! the implicit `hort-cli` developer experience).
//!
//! # Layering
//!
//! - Trait lives in `hort-domain` (zero I/O). `BoxFuture` keeps it
//!   dyn-compatible without `async-trait`.
//! - DTOs ([`ManagedSecret`], [`ManagedSecretSpec`]) are
//!   intentionally not `Serialize`/`Deserialize` — the secret payload
//!   ([`ManagedSecretSpec::token_value`]) is plaintext PAT bytes that
//!   must never reach an HTTP request DTO.
//! - The plaintext PAT is wrapped in [`zeroize::Zeroizing<String>`] so
//!   it is zeroed when the spec is dropped. Same precedent as
//!   `hort-domain::ports::secret_port::SecretValue`.

use chrono::{DateTime, Utc};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::entities::service_account::SecretFormat;
use crate::error::DomainResult;

use super::BoxFuture;

// ---------------------------------------------------------------------------
// ManagedSecret — read-side projection
// ---------------------------------------------------------------------------

/// Projection of the reconciler-managed metadata on an existing
/// `Secret` (three labels — `project-hort.de/managed-by`,
/// `project-hort.de/service-account`, `project-hort.de/token-id` — plus one annotation
/// — `project-hort.de/last-rotated`, which carries an RFC 3339 timestamp and
/// therefore cannot be a label). Every field is optional because a
/// Secret may exist with the `project-hort.de/managed-by` label absent
/// (operator-created and not yet adopted by the reconciler) or with
/// a malformed `project-hort.de/last-rotated` / `project-hort.de/token-id` value
/// (out-of-band edit; the adapter parses and surfaces `None` rather
/// than failing the read).
///
/// The reconciler decides:
/// - `managed_by != Some("hort-worker")` → collision, refuse to manage.
/// - `last_rotated` older than `rotation_interval` → mint + upsert.
/// - `last_rotated` absent → mint + upsert (stale by definition).
/// - `token_id` is informational; carried for audit only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSecret {
    /// `project-hort.de/managed-by` label value. `None` when the label is
    /// absent on the existing Secret.
    pub managed_by: Option<String>,
    /// `project-hort.de/service-account` label value.
    pub service_account: Option<String>,
    /// `project-hort.de/last-rotated` annotation parsed as an RFC 3339
    /// timestamp. `None` when the annotation is absent OR parsing
    /// failed (in which case the adapter logged a `warn!`). Stored
    /// as an annotation rather than a label because k8s rejects
    /// `:` in label values, and every RFC 3339 timestamp carries
    /// at least two of them.
    pub last_rotated: Option<DateTime<Utc>>,
    /// `project-hort.de/token-id` label parsed as a UUID. Same parse-failure
    /// semantics as [`Self::last_rotated`].
    pub token_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// ManagedSecretSpec — write-side payload
// ---------------------------------------------------------------------------

/// Upsert payload for [`KubernetesSecretWriter::upsert_managed`].
///
/// Constructed once per rotation tick. Carries the freshly-minted PAT
/// value in plaintext (the only point in the system where the secret
/// is plaintext outside of the `ApiTokenUseCase::issue` return value);
/// [`Zeroizing<String>`] ensures the buffer is zeroed when the spec
/// is dropped, matching the
/// [`SecretValue`](crate::ports::secret_port::SecretValue) precedent.
///
/// Intentionally **not** `Clone` / `Serialize` / `Deserialize` —
/// duplicating a plaintext-PAT-carrying struct must require an
/// explicit zeroizing buffer dance at the call site, not an
/// accidental `.clone()`.
pub struct ManagedSecretSpec {
    /// Wire format the Secret is written as
    /// (`kubernetes.io/dockerconfigjson` vs `Opaque`).
    pub format: SecretFormat,
    /// Plaintext PAT value to embed in the Secret payload. The buffer
    /// is zeroed when the spec is dropped — see the
    /// [`Zeroizing<T>`](zeroize::Zeroizing) docs.
    pub token_value: Zeroizing<String>,
    /// The `ApiToken.id` that owns the plaintext above. Written
    /// verbatim into the `project-hort.de/token-id` label so a future tick (or
    /// an operator running `kubectl describe`) can correlate the
    /// Secret to the row in `api_tokens`.
    pub token_id: Uuid,
    /// The CRD `metadata.name` of the [`ServiceAccount`](crate::entities::service_account::ServiceAccount)
    /// whose rotation produced this spec. Written into the
    /// `project-hort.de/service-account` label AND used as the
    /// `dockerconfigjson` username (`format!("sa:{name}")` — matches
    /// the service-account backing-user prefix).
    pub service_account_name: String,
    /// Timestamp written into the `project-hort.de/last-rotated` annotation
    /// (annotation rather than label because RFC 3339 timestamps
    /// contain `:`, forbidden in label values). The reconciler
    /// always passes "now" but threading it through the spec keeps
    /// the adapter deterministic under test.
    pub last_rotated: DateTime<Utc>,
    /// Registry host used in the `dockerconfigjson` `auths` map key.
    /// Required when `format == Dockerconfigjson`; ignored for
    /// `Opaque`. The reconciler derives this from the operator's
    /// `HORT_PUBLIC_BASE_URL` host component.
    pub registry_host: String,
}

// ---------------------------------------------------------------------------
// Port trait
// ---------------------------------------------------------------------------

/// Outbound port for the reconciler's read + upsert against k8s
/// Secrets.
///
/// Implementations:
/// - `hort-adapters-kubernetes::KubernetesSecretWriterImpl` — real
///   `kube-rs`-backed writer. Server-side apply for idempotency.
/// - `hort-app::use_cases::test_support::MockKubernetesSecretWriter` —
///   in-memory mock the reconciler tests drive.
pub trait KubernetesSecretWriter: Send + Sync {
    /// Read the existing Secret at `(namespace, name)` and project
    /// only the four reconciler-managed labels (see
    /// [`ManagedSecret`]). Returns `Ok(None)` when no Secret exists
    /// at that coordinate (the standard "not found" path — the
    /// reconciler treats it as "fresh upsert needed").
    fn read_managed<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, DomainResult<Option<ManagedSecret>>>;

    /// Upsert the Secret with the supplied spec. Idempotent — the
    /// production adapter uses Kubernetes server-side apply, so
    /// repeated calls with identical specs do not bump the
    /// `metadata.resourceVersion`.
    fn upsert_managed<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
        spec: ManagedSecretSpec,
    ) -> BoxFuture<'a, DomainResult<()>>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time invariant: the port trait must remain dyn-compatible
    /// (no generics on methods, no `Self: Sized` bounds, no async fn).
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn KubernetesSecretWriter>();
    }

    #[test]
    fn managed_secret_clone_eq() {
        let now = Utc::now();
        let id = Uuid::nil();
        let a = ManagedSecret {
            managed_by: Some("hort-worker".into()),
            service_account: Some("ci".into()),
            last_rotated: Some(now),
            token_id: Some(id),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn managed_secret_all_none_is_legal() {
        // A Secret created out-of-band that lacks every reconciler label
        // surfaces as a fully-`None` projection — the reconciler maps
        // this to the "collision" path because `managed_by != Some(hort-worker)`.
        let projection = ManagedSecret {
            managed_by: None,
            service_account: None,
            last_rotated: None,
            token_id: None,
        };
        assert_eq!(projection.managed_by, None);
        assert_eq!(projection.last_rotated, None);
    }

    #[test]
    fn managed_secret_spec_zeroizes_token_value_on_drop() {
        // Smoke test the Zeroizing<String> wrapper is in play — we
        // can't assert on freed memory but we can confirm the wrapper
        // type is `Zeroizing`, which is the contract.
        let spec = ManagedSecretSpec {
            format: SecretFormat::Opaque,
            token_value: Zeroizing::new("hort_svc_secret_xyz".into()),
            token_id: Uuid::nil(),
            service_account_name: "ci".into(),
            last_rotated: Utc::now(),
            registry_host: "registry.example".into(),
        };
        assert_eq!(spec.token_value.as_str(), "hort_svc_secret_xyz");
        // Drop happens here; the buffer is zeroed by Zeroizing's Drop impl.
    }

    /// `ManagedSecretSpec` must not be `Clone` — duplicating a plaintext-
    /// PAT-carrying struct must be a deliberate Zeroizing dance, not a
    /// `.clone()`. Same discipline as `ApiToken` plaintext bytes.
    #[test]
    fn managed_secret_spec_is_not_clone() {
        // Compile-time check via static_assertions in entities/
        // service_account.rs precedent — here we assert structurally
        // by attempting (in a hypothetical) and observing the lack of
        // a `Clone` impl. The `static_assertions` crate is already in
        // dev-deps for hort-domain.
        static_assertions::assert_not_impl_any!(ManagedSecretSpec: Clone);
    }

    /// Neither DTO carries serde — both are internal-only.
    #[test]
    fn dtos_are_not_deserialize() {
        static_assertions::assert_not_impl_any!(ManagedSecret: serde::de::DeserializeOwned);
        static_assertions::assert_not_impl_any!(ManagedSecretSpec: serde::de::DeserializeOwned);
    }
}
