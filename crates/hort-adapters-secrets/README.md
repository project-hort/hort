# hort-adapters-secrets — Secret Resolution Adapters

## Layer

Outbound adapter — no `hort-app` dependency (leaf adapter over
`hort-domain`). Requires >= 85% coverage.

## Responsibility

Resolves `SecretRef`s from the two operator-wiring sinks Hort ships by
default — process environment variables and mounted files — plus a
dispatcher that routes by `SecretRef::source`.

## Ports

- **Implements:** `SecretPort`, by `DispatchSecretPort` (routes to the
  `env`/`file` adapters below), `EnvVarSecretAdapter`,
  `MountedFileSecretAdapter`.
- **Consumes:** none — leaf adapter.

## Key types

- `DispatchSecretPort` (holds `env`/`file: Arc<dyn SecretPort>`).
- `EnvVarSecretAdapter`.
- `MountedFileSecretAdapter`.

## Rules

- Secret material is wrapped so it zeroes on drop (`zeroize` is a direct
  dependency) — no plaintext secret buffer may outlive its use.
- `MountedFileSecretAdapter` enforces a path-containment check when
  `HORT_SECRETS_FILE_ROOT`/`secrets_root` is configured, rejecting symlink
  escapes out of the configured secrets root.
