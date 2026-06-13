//! Real `kube-rs`-backed implementation of
//! [`KubernetesSecretWriter`](hort_domain::ports::kubernetes_secret_writer::KubernetesSecretWriter).
//!
//! Constructor: [`KubernetesSecretWriterImpl::try_in_cluster`] — uses
//! `kube::Client::try_default()`, which prefers in-cluster auth and
//! falls back to a kubeconfig for the dev-laptop case.
//!
//! Per-call wire:
//! - `read_managed` → `Api::<Secret>::namespaced(...).get_opt(name)`
//!   → [`payload::project_managed`].
//! - `upsert_managed` → [`payload::build_secret`] →
//!   `Api::<Secret>::patch(name, &PatchParams::apply(FIELD_MANAGER),
//!   &Patch::Apply(&secret))` (server-side apply).
//!
//! Errors from `kube` are mapped to
//! [`DomainError::Invariant`](hort_domain::error::DomainError::Invariant)
//! — matches the convention used elsewhere in the adapter layer (see
//! `hort-adapters-secrets::mounted_file`) where the domain has no
//! dedicated `Infrastructure` variant. The string carries the kube
//! error's display form for operator-actionable diagnostics.

use std::sync::Arc;

use futures::future::BoxFuture;
use futures::FutureExt;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::kubernetes_secret_writer::{
    KubernetesSecretWriter, ManagedSecret, ManagedSecretSpec,
};

use crate::payload::{build_secret, project_managed, FIELD_MANAGER_RE_EXPORT};

/// `kube-rs`-backed [`KubernetesSecretWriter`].
///
/// Cheap to clone — the underlying [`kube::Client`] is an
/// `Arc`-wrapped HTTP client. Held inside an `Arc<dyn …>` slot on
/// [`AppContext`](hort_http_core::context::AppContext) once construction
/// succeeds.
pub struct KubernetesSecretWriterImpl {
    client: Arc<Client>,
}

impl KubernetesSecretWriterImpl {
    /// Construct from a shared [`kube::Client`]. Test entry point.
    /// Production callers use [`Self::try_in_cluster`].
    pub fn from_client(client: Client) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    /// Build a writer using `kube::Client::try_default()`.
    ///
    /// Resolution order (delegated to kube-rs — the library default is
    /// inherited rather than exposing a separate env-var override):
    ///
    /// 1. In-cluster: reads `/var/run/secrets/kubernetes.io/
    ///    serviceaccount/token` + `ca.crt`. This is the path the
    ///    `hort-worker` Pod takes in production.
    /// 2. `$KUBECONFIG` or `~/.kube/config` for the developer-laptop
    ///    `hort-cli` case.
    ///
    /// Both paths produce a working `Client`; the failure mode is
    /// "neither file tree is present", which surfaces as a
    /// `kube::Error` carrying a config-load diagnostic.
    pub async fn try_in_cluster() -> Result<Self, kube::Error> {
        // kube ⇒ hyper-rustls ⇒ rustls 0.23+ requires the process-level
        // CryptoProvider to be installed before the first TLS handshake;
        // otherwise the kube `try_default` call panics in worker startup
        // with "Could not automatically determine the process-level
        // CryptoProvider". The same idempotent pattern lives in
        // hort-adapters-oidc and hort-adapters-upstream-http — calling it
        // here too is safe (Err on the second install is harmless) and
        // covers worker startup where the kubernetes adapter is the
        // first to hit rustls.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = Client::try_default().await?;
        tracing::info!("KubernetesSecretWriter wired (kube::Client::try_default)");
        Ok(Self::from_client(client))
    }
}

impl KubernetesSecretWriter for KubernetesSecretWriterImpl {
    fn read_managed<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, DomainResult<Option<ManagedSecret>>> {
        async move {
            let api: Api<Secret> = Api::namespaced((*self.client).clone(), namespace);
            let opt = api.get_opt(name).await.map_err(|err| {
                tracing::error!(
                    namespace,
                    name,
                    error = %err,
                    "k8s Secret read failed",
                );
                DomainError::Invariant(format!(
                    "kubernetes Secret read failed (ns={namespace}, name={name}): {err}"
                ))
            })?;

            match opt {
                Some(secret) => {
                    let projected = project_managed(&secret, namespace, name);
                    tracing::debug!(
                        namespace,
                        name,
                        managed_by = ?projected.managed_by,
                        last_rotated = ?projected.last_rotated,
                        "k8s Secret read",
                    );
                    Ok(Some(projected))
                }
                None => {
                    tracing::debug!(
                        namespace,
                        name,
                        "k8s Secret absent — reconciler will treat as fresh upsert",
                    );
                    Ok(None)
                }
            }
        }
        .boxed()
    }

    fn upsert_managed<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
        spec: ManagedSecretSpec,
    ) -> BoxFuture<'a, DomainResult<()>> {
        async move {
            let api: Api<Secret> = Api::namespaced((*self.client).clone(), namespace);
            // SSA: idempotent + apiserver-mediated conflict resolution.
            // The previous approach (read → conditional create-or-replace)
            // races against parallel ticks; SSA is the documented
            // controller-runtime pattern for owned-resource reconciliation.
            let manifest = build_secret(name, &spec);
            let params = PatchParams::apply(FIELD_MANAGER_RE_EXPORT);

            // Capture format + sa name BEFORE the spec moves so we can
            // log without holding the plaintext alive in the closure.
            let format_str = spec.format.as_str();
            let sa_name = spec.service_account_name.clone();
            let last_rotated = spec.last_rotated;
            drop(spec); // zero the plaintext eagerly

            api.patch(name, &params, &Patch::Apply(&manifest))
                .await
                .map_err(|err| {
                    tracing::error!(
                        namespace,
                        name,
                        service_account = %sa_name,
                        format = format_str,
                        error = %err,
                        "k8s Secret upsert failed",
                    );
                    DomainError::Invariant(format!(
                        "kubernetes Secret upsert failed (ns={namespace}, \
                         name={name}, sa={sa_name}): {err}"
                    ))
                })?;

            // Per-upsert success logged at `debug!` only. Per-tick
            // aggregate observability lives in the handler's SUMMARY
            // line (still `info!`); per-Secret success is too chatty
            // for INFO at high SA counts.
            tracing::debug!(
                namespace,
                name,
                service_account = %sa_name,
                format = format_str,
                last_rotated = %last_rotated.to_rfc3339(),
                "k8s Secret rotated",
            );
            Ok(())
        }
        .boxed()
    }
}

// ---------------------------------------------------------------------------
// Type assertions — keep the public surface honest
//
// An empty `#[ignore]` `kind_cluster_tests` mod once lived between this
// header and the type-tests below as a structural placeholder; it was
// removed because the kind-cluster smoke runner under
// `scripts/native-tests/` is the runner, not an in-crate harness.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod type_tests {
    use super::*;

    /// Compile-time assertion that the impl satisfies the trait. The
    /// production callers go through `Arc<dyn KubernetesSecretWriter>`
    /// so any signature drift on the port shows up here as a build
    /// error before composition catches it.
    #[test]
    fn impl_is_dyn_compatible_secret_writer() {
        fn assert_impl<T: KubernetesSecretWriter + 'static>() {}
        assert_impl::<KubernetesSecretWriterImpl>();
    }
}
