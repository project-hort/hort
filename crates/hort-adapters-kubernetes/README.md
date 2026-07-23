# hort-adapters-kubernetes — Kubernetes Secret Writer Adapter

## Layer

Outbound adapter — no `hort-app` dependency (leaf adapter over
`hort-domain`). Requires >= 85% coverage.

## Responsibility

Manages Kubernetes `Secret` resources for fallback PAT (personal-access-token)
rotation of service-account machine identities, via `kube-rs` against the
in-cluster API. Its only consumer is `hort-worker`'s
`ServiceAccountRotationHandler` task, wired only when
`HORT_K8S_SECRET_WRITER_ENABLED=true`.

## Ports

- **Implements:** `KubernetesSecretWriter` (`KubernetesSecretWriterImpl`).
- **Consumes:** none — leaf adapter.

## Key types

- `KubernetesSecretWriterImpl`.

## Rules

- **rustls only:** `kube` is pinned `default-features = false, features =
  ["client", "rustls-tls"]` — matches the workspace-wide no-insecure-TLS
  posture (ADR 0010).
- `rustls::crypto::aws_lc_rs::default_provider().install_default()` is
  called at adapter-construction time to satisfy `kube`'s rustls-0.23
  process-level crypto-provider requirement before the first TLS
  handshake — the same idempotent-install pattern used in
  `hort-adapters-oidc` and `hort-adapters-upstream-http`.
- The plaintext PAT is held in `Zeroizing<String>`.
