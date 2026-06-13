//! # hort-adapters-kubernetes — Outbound Kubernetes adapters
//!
//! Implements [`KubernetesSecretWriter`](hort_domain::ports::kubernetes_secret_writer::KubernetesSecretWriter)
//! against the in-cluster Kubernetes API via `kube-rs`.
//!
//! Only consumer is the `ServiceAccountRotationHandler` TaskHandler
//! running inside `hort-worker`. The composition root in `hort-server`
//! (and the hort-worker binary's own composition) build the impl only
//! when the operator opts in via `HORT_K8S_SECRET_WRITER_ENABLED=true`;
//! non-k8s deployments leave the
//! [`AppContext`](`hort_http_core::context::AppContext`)`.k8s_secret_writer`
//! slot as `None` and the rotation handler refuses to register.
//!
//! See `docs/how-to/rotating-service-account-tokens.md` for the operator
//! guide and ADR 0018 for the machine-identity design.
//!
//! # Design highlights
//!
//! - **rustls only.** `kube` is pinned with
//!   `default-features = false, features = ["client", "rustls-tls"]`
//!   — matches the workspace-wide `*_INSECURE_TLS` anti-pattern rule
//!   and the no-openssl-in-adapter-HTTP-clients rule (ADR 0010).
//! - **Server-side apply.** Upserts use `Patch::Apply` with
//!   `field_manager = "hort-worker"`, so concurrent rotation ticks (or
//!   a parallel operator `kubectl apply`) merge cleanly and the
//!   apiserver owns conflict resolution. The alternative imperative
//!   create-or-replace path requires the adapter to read +
//!   conditional-write, which is racier and re-implements logic the
//!   apiserver already does.
//! - **In-cluster auth by default.** `kube::Client::try_default()`
//!   prefers the mounted ServiceAccount token at
//!   `/var/run/secrets/kubernetes.io/serviceaccount/token` and falls
//!   back to `$KUBECONFIG` / `~/.kube/config` for the dev-laptop case.
//!   The fallback is the implicit `hort-cli` developer-experience path;
//!   no separate env-var knob is exposed.
//! - **Plaintext PAT lives in [`Zeroizing<String>`](zeroize::Zeroizing).**
//!   The buffer is zeroed when the [`ManagedSecretSpec`](hort_domain::ports::kubernetes_secret_writer::ManagedSecretSpec)
//!   drops, matching the `SecretValue` precedent.

mod metrics;
mod payload;
mod secret_writer;

pub use secret_writer::KubernetesSecretWriterImpl;
