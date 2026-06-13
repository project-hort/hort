# Wire secrets for `proxy.secretRef:`

This guide is for operators who need to give `hort` an
upstream-registry credential (a GHCR PAT, a private PyPI token, a
Maven Central deploy key, …) without committing it to the gitops
repository.

The model is **operator-wired**: hort-server has no Vault client, no
ESO controller, no cloud-KMS SDK. It reads either an environment
variable or a file from its own filesystem. **You** wire whatever
secret-sync mechanism you prefer — ESO, the secrets-store CSI
driver, Vault Agent, plain Kubernetes Secrets, Compose secrets,
systemd `LoadCredential=` — to land the bytes in one of those two
places. Hort's `SecretPort` reads them from there at
resolve time.

> **Status note.** The credentialed pull-
> through path is live in production — the gitops apply pipeline
> writes `repository_upstream_mappings` rows from declared envelopes
> and the proxy resolver picks them up. Both wiring shapes are
> supported:
>
> - **`spec.proxy.secretRef:` inline on `kind: ArtifactRepository`** —
>   single-upstream proxy repositories. The shape documented in §1
>   below.
> - **`spec.secretRef:` on a standalone `kind: UpstreamMapping`
>   envelope** — multi-upstream OCI mirrors fronting several
>   registries under different `pathPrefix` values. Identical
>   `SecretRef` shape, same wiring patterns (§2), same resolver. The
>   YAML body shape is documented in
>   `crates/hort-config/src/upstream_mapping.rs` and at a glance in
>   declare-gitops-config.md §6.
>
> Pick the shape that matches the repository topology; the wiring
> patterns in §2 are agnostic to which envelope the `secretRef:`
> sits on.

---

## 1. The `secretRef:` shape

Every pattern below ends in the same Hort-side YAML inside a
`type: proxy` repository envelope:

```yaml
apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: ghcr-mirror
spec:
  name: "GHCR Mirror"
  format: oci
  type: proxy
  storage:
    backend: filesystem
    path: /var/lib/hort-server/cas/ghcr-mirror
  proxy:
    upstreamUrl: "https://ghcr.io"
    secretRef:
      source: file                       # `file` or `env_var`
      location: "/run/secrets/ghcr-token"
  isPublic: true
  replicationPriority: on_demand
```

Validation rules:

- `source: file` — `location` MUST be an absolute path.
- `source: env_var` — `location` MUST match `^[A-Z_][A-Z0-9_]*$`.
- Reference existence is **not** checked at parse time. The first
  `resolve()` call at upstream-fetch time produces the error if the
  file or env var is missing.

For the field shape in code see
`crates/hort-config/src/repository.rs` (`ProxySpec`).

---

## 2. Wiring patterns

The twelve patterns below are ordered roughly from "most managed,
most production-like" (External Secrets Operator) down to "raw shell
export for local dev." Pick whichever fits your platform.

Where an operator-side YAML is shown, the API versions are pinned to
values current at the time of writing — verified against vendor
documentation, not against a live deployment in this repository's
test rig. Re-emit if your cluster's CRDs have moved.

### 2.1 External Secrets Operator (ESO) → mounted file

Operator side — sync a Vault-resident PAT into a Kubernetes `Secret`:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: ghcr-pat
  namespace: hort
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: ghcr-pat-secret
  data:
    - secretKey: token
      remoteRef:
        key: secret/data/ghcr/pat
        property: token
```

Mount the synced `Secret` as a file on the Hort pod:

```yaml
# Hort Deployment fragment
spec:
  template:
    spec:
      containers:
        - name: hort-server
          volumeMounts:
            - name: ghcr-pat
              mountPath: /run/secrets/ghcr
              readOnly: true
      volumes:
        - name: ghcr-pat
          secret:
            secretName: ghcr-pat-secret
            defaultMode: 0440
            items:
              - key: token
                path: ghcr-token
```

Hort side:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: file
    location: "/run/secrets/ghcr/ghcr-token"
```

### 2.2 External Secrets Operator (ESO) → env var

Same `ExternalSecret` as 2.1. Consume the synced `Secret` via
`envFrom.secretRef`:

```yaml
spec:
  template:
    spec:
      containers:
        - name: hort-server
          envFrom:
            - secretRef:
                name: ghcr-pat-secret
```

The `Secret`'s `data:` keys land as env vars verbatim — so the key
must already match the POSIX env-var name regex
(`^[A-Z_][A-Z0-9_]*$`). If the key in Vault is `token`, remap it to
`GHCR_TOKEN` via `ExternalSecret.spec.data[].secretKey: GHCR_TOKEN`
on the operator side.

Hort side:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: env_var
    location: "GHCR_TOKEN"
```

Trade-off: env-var rotation does not work — see
[Pitfalls](#3-pitfalls) §3. Use 2.1 if you need rotation.

### 2.3 Vault Agent sidecar → tmpfs file

Operator side — annotate the Hort pod so Vault Agent injects a sidecar
that writes the secret to a shared tmpfs:

```yaml
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "hort-server"
        vault.hashicorp.com/agent-inject-secret-ghcr-token: "secret/data/ghcr/pat"
        vault.hashicorp.com/agent-inject-template-ghcr-token: |
          {{- with secret "secret/data/ghcr/pat" -}}
          {{ .Data.data.token }}
          {{- end }}
```

Vault Agent writes the rendered file to `/vault/secrets/ghcr-token`
on a tmpfs that the main container can read. The default re-render
interval picks up upstream rotations.

Hort side:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: file
    location: "/vault/secrets/ghcr-token"
```

### 2.4 HashiCorp Vault / OpenBao CSI driver → mounted file

Operator side — declare a `SecretProviderClass` that pulls from
Vault, then mount it via the secrets-store CSI driver:

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: ghcr-vault
  namespace: hort
spec:
  provider: vault
  parameters:
    roleName: "hort-server"
    vaultAddress: "https://vault.example.com"
    objects: |
      - objectName: "ghcr-token"
        secretPath: "secret/data/ghcr/pat"
        secretKey: "token"
```

```yaml
# Hort Deployment fragment
spec:
  template:
    spec:
      containers:
        - name: hort-server
          volumeMounts:
            - name: ghcr-vault
              mountPath: /mnt/secrets/ghcr
              readOnly: true
      volumes:
        - name: ghcr-vault
          csi:
            driver: secrets-store.csi.k8s.io
            readOnly: true
            volumeAttributes:
              secretProviderClass: "ghcr-vault"
```

Hort side:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: file
    location: "/mnt/secrets/ghcr/ghcr-token"
```

### 2.5 AWS Secrets Manager / Parameter Store CSI → mounted file

Operator side — use the AWS provider for secrets-store CSI:

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: ghcr-aws
  namespace: hort
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "prod/hort/ghcr-token"
        objectType: "secretsmanager"
        objectAlias: "ghcr-token"
```

Mount identically to 2.4 (`csi.driver: secrets-store.csi.k8s.io`,
`secretProviderClass: ghcr-aws`).

Hort side:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: file
    location: "/mnt/secrets/ghcr/ghcr-token"
```

The pod must run with an IRSA role permitted to read
`prod/hort/ghcr-token` from Secrets Manager.

### 2.6 GCP Secret Manager CSI → mounted file

Operator side — use the GCP provider for secrets-store CSI:

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: ghcr-gcp
  namespace: hort
spec:
  provider: gcp
  parameters:
    secrets: |
      - resourceName: "projects/my-project/secrets/ghcr-token/versions/latest"
        path: "ghcr-token"
```

Mount identically to 2.4.

Hort side:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: file
    location: "/mnt/secrets/ghcr/ghcr-token"
```

The pod's KSA must be Workload-Identity-bound to a GSA with
`roles/secretmanager.secretAccessor` on the secret.

### 2.7 Azure Key Vault CSI → mounted file

Operator side — use the Azure provider for secrets-store CSI:

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: ghcr-azure
  namespace: hort
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "true"
    keyvaultName: "hort-prod-kv"
    tenantId: "00000000-0000-0000-0000-000000000000"
    objects: |
      array:
        - |
          objectName: ghcr-token
          objectType: secret
```

Mount identically to 2.4.

Hort side:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: file
    location: "/mnt/secrets/ghcr/ghcr-token"
```

### 2.8 Plain Kubernetes Secret → mounted file

For workloads where bringing in ESO / CSI is overkill — a bare
`Secret` (sealed-secrets, sops-encrypted, or just kubectl-applied)
mounted as a file:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ghcr-pat-secret
  namespace: hort
type: Opaque
stringData:
  token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

```yaml
# Hort Deployment fragment
spec:
  template:
    spec:
      containers:
        - name: hort-server
          volumeMounts:
            - name: ghcr-pat
              mountPath: /run/secrets/ghcr
              readOnly: true
      volumes:
        - name: ghcr-pat
          secret:
            secretName: ghcr-pat-secret
            defaultMode: 0440
            items:
              - key: token
                path: ghcr-token
```

Hort side:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: file
    location: "/run/secrets/ghcr/ghcr-token"
```

### 2.9 Plain Kubernetes Secret → env var

Same `Secret` as 2.8, consumed via `envFrom`:

```yaml
spec:
  template:
    spec:
      containers:
        - name: hort-server
          envFrom:
            - secretRef:
                name: ghcr-pat-secret
```

The `Secret`'s key (`token` in 2.8) becomes the env-var name. Rename
the key to `GHCR_TOKEN` in the `Secret` so it satisfies the POSIX
env-var name regex:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ghcr-pat-secret
type: Opaque
stringData:
  GHCR_TOKEN: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Hort side:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: env_var
    location: "GHCR_TOKEN"
```

Same rotation caveat as 2.2.

### 2.10 Docker Compose `secrets:` → `/run/secrets/<name>`

For non-Kubernetes deployments. Compose mounts each declared secret
at `/run/secrets/<name>` inside the container.

```yaml
# docker-compose.yml
services:
  hort-server:
    image: ghcr.io/project-hort/hort-server:latest
    secrets:
      - ghcr-token
    environment:
      HORT_CONFIG_DIR: /etc/hort/config
    volumes:
      - ./config:/etc/hort/config:ro
    # ... usual hort-server config ...

secrets:
  ghcr-token:
    file: ./secrets/ghcr-token
```

The host-side `./secrets/ghcr-token` file holds the token. Compose
mounts it read-only at `/run/secrets/ghcr-token` inside the
container.

Hort side:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: file
    location: "/run/secrets/ghcr-token"
```

### 2.11 systemd `LoadCredential=` → `$CREDENTIALS_DIRECTORY`

For bare-metal / VM deployments running hort-server as a systemd unit.
`LoadCredential=` reads a file at unit start, copies it into a
per-unit tmpfs, and exposes the directory as `$CREDENTIALS_DIRECTORY`
inside the unit's process tree.

```ini
# /etc/systemd/system/hort-server.service
[Unit]
Description=hort
After=network-online.target

[Service]
ExecStart=/usr/local/bin/hort-server
LoadCredential=ghcr-token:/etc/hort/secrets/ghcr.token
Environment=HORT_CONFIG_DIR=/etc/hort/config
DynamicUser=yes
ProtectSystem=strict
ReadOnlyPaths=/etc/hort

[Install]
WantedBy=multi-user.target
```

systemd resolves `$CREDENTIALS_DIRECTORY` at unit start to a path
like `/run/credentials/hort-server.service`. The
`source-path:credential-name` form means systemd reads
`/etc/hort/secrets/ghcr.token` at unit start and writes it to
`$CREDENTIALS_DIRECTORY/ghcr-token` for the duration of the unit's
runtime.

Hort does not see the env var `$CREDENTIALS_DIRECTORY` — `secretRef:
file` requires an absolute path. Hard-code the resolved path:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: file
    location: "/run/credentials/hort-server.service/ghcr-token"
```

If your packaging conventions don't permit hard-coding the unit
name, wrap `ExecStart=` in a small shell script that copies
`$CREDENTIALS_DIRECTORY/ghcr-token` to a stable path and exec's
hort-server. Hort reads from the stable path; the credential never
leaves tmpfs.

### 2.12 Local development → raw `export`

The trivial case. No operator, no sync, no controller:

```bash
export GHCR_TOKEN='ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
cargo run -p hort-server
```

Hort side:

```yaml
proxy:
  upstreamUrl: "https://ghcr.io"
  secretRef:
    source: env_var
    location: "GHCR_TOKEN"
```

Adequate for local testing of upstream-credential code paths. Do
not ship this to production — env-var rotation does not work and
the value is visible in `/proc/<pid>/environ` to anyone with the
right uid.

---

## 3. Pitfalls

### 3.1 Trailing-newline rule

The file adapter strips exactly one trailing `\n` or `\r\n` (design
doc §5.2). Multi-line secrets retain their interior newlines; only
the final one is removed. The strip is byte-level — secrets need
not be valid UTF-8.

How tools differ when writing the underlying file:

- `vim` / `nano` / most text editors save with a trailing `\n`.
- `kubectl create secret --from-literal=KEY=value` does **not** add
  a newline.
- `printf '%s' "$value" > file` does **not** add a newline.
- `echo "$value" > file` **does** add a newline. Use `printf` or
  `echo -n` if you don't want one.
- Most CSI providers (Vault, AWS, GCP, Azure) do **not** add a
  newline.
- Vault Agent template-rendered files inherit whatever your template
  emits (the example in 2.3 ends in a trailing newline by template
  convention; the strip handles it).

Rule of thumb: don't worry about it for single-line tokens. For
multi-line PEM blocks or JWTs, the strip removes the editor's
trailing newline and leaves your block intact.

### 3.2 File permissions

The mounted file (or the file written by `LoadCredential=`) must be
readable by the Hort process UID. Most CSI drivers default to `0600`
owned by root; if the Hort container runs as a non-root user, set
`defaultMode: 0440` on the volume mount and ensure the file is
group-readable. A failed read surfaces as a `SecretError::ReadFailure`
at `resolve()` time, mapped to `DomainError::Invariant` by the
adapter consumer.

The file adapter additionally checks `mode & 0o077` on every
successful read and emits a `WARN` (not an error) when group/other
have any bit set. `0644` (Kubernetes default) and `0440` both warn;
`0600` and `0400` are silent. The warning is informational — the read
still succeeds — because refusing to read on `0644` would break real
deployments. Tighten to `0600`/`0400` if your secret-sync tool
permits.

Set the optional `HORT_SECRETS_FILE_ROOT` env var on the Hort process to
restrict the file adapter to a specific directory. When set, every
`secretRef` whose canonical path (with symlinks resolved) falls
outside the configured root is rejected with a structured error. This
is symlink-escape protection — a malicious or buggy `secretRef:
{source: file, location: /etc/shadow}` cannot read host files even if
the Hort process would otherwise have permission. Leave unset for the
legacy unconstrained behaviour. Recommended value in containerised
deployments: `HORT_SECRETS_FILE_ROOT=/run/secrets` (or wherever your
mounts land).

### 3.3 Env-var rotation does not work

Process env is set at fork-exec time and cannot change for the life
of the process. If you need rotation, use `source: file` instead.
Operators sometimes wire ESO + `envFrom.secretRef` thinking a
re-render rotates the value — it rotates the Kubernetes `Secret`,
but the running Hort process keeps the old value until restart.

### 3.4 Path absoluteness

`source: file` requires an absolute path. Relative paths like
`./secrets/ghcr-token` fail at parse time with
`SecretRefLocationInvalid`. If you're testing locally with
`~/secrets/...`, the shell expands `~` before Hort sees the path; if
Hort runs as a daemon, `~` does not expand and the path fails. Always
write absolute paths.

### 3.5 POSIX env-var name regex

`source: env_var` requires `location` to match `^[A-Z_][A-Z0-9_]*$`.
Lowercase, dashes, dots, or shell-special characters fail at parse
time. Use uppercase-with-underscores. Many tools auto-uppercase, so
`GHCR_TOKEN` works; `ghcr-token` does not.

### 3.6 Reference existence is not checked at parse time

The operator's wiring may populate the file or env var **after**
gitops apply. Hort does not refuse to boot just because
`/run/secrets/ghcr-token` is missing — it boots, and the first
`resolve()` at upstream-fetch time produces the error. Plan your
rollouts so the secret-sync mechanism is healthy before Hort starts
pulling from the upstream.

---

## 4. Rotation guarantees per source

- **`source: file`** — re-read on each `resolve()` call. tmpfs-
  backed file reads are microseconds; the OS page cache is the
  cache. Operators using ESO / CSI drivers / Vault Agent get
  rotation for free without configuring Hort; the secret-sync tool's
  normal cadence drives it.

- **`source: env_var`** — set at fork-exec time, immutable for the
  process lifetime. Rotation requires restarting Hort. Operators
  choosing `env_var` for production pulls need to plan restart
  cadence; for local dev this is fine.

Hort deliberately adds no inotify watching and no in-process secret
cache: every `resolve()` re-reads the source, the OS page cache is the
cache, and rotation therefore needs no invalidation machinery in Hort
at all — the operator's secret-sync tool owns the rotation cadence.

---

## 5. OCI token signing key (chart-level, not via `SecretPort`)

The patterns in §2 wire **upstream-registry credentials** that the
runtime reads via `SecretPort::resolve` at fetch time. The OCI token
signing key is a different concern: it's a chart-level Kubernetes
Secret that the `hort-server` Deployment consumes as an env var
(`HORT_OCI_TOKEN_SIGNING_KEY`) at boot. The binary parses it once into
an `ed25519_dalek::SigningKey` and uses it for the lifetime of the
process. There is no `SecretPort` involvement, no `source:`/`location:`
shape, no `secretRef:` envelope — just a `secretKeyRef` on the
deployment template.

This section exists because the boot-time gate
(`ConfigError::TokenExchangeRequiresNativeTokens`) made the signing
key a hard prerequisite for `auth.tokenExchange.enabled=true`: without
it, the chart's install-block schema rule trips at `helm template`
time and the binary boot-fails as a backstop.

### 5.1 Generate the key

PKCS#8 PEM is the only accepted format
(`crates/hort-app/src/oci_token_signing.rs` parses with
`SigningKey::from_pkcs8_pem`). `openssl genpkey -algorithm ed25519`
produces that natively.

```bash
# Run on an offline workstation, never on the cluster.
openssl genpkey -algorithm ed25519 -out hort-oci-token-signing-key.pem
chmod 0600 hort-oci-token-signing-key.pem
```

The file contains a 32-byte private key in PKCS#8 wrapping; total PEM
size is ~120 bytes. No passphrase — Ed25519 PKCS#8 in this codebase
is consumed plaintext.

### 5.2 Stash in Vault

```bash
vault kv put secret/hort/oci-signing-key \
  hort-oci-token-signing-key.pem=@hort-oci-token-signing-key.pem
```

The Vault path is operator choice; the property name
(`hort-oci-token-signing-key.pem`) is the convention the chart's default
`secretKey` value uses — keeping the two aligned avoids a remap in
the `ExternalSecret`.

### 5.3 Sync into Kubernetes via External Secrets Operator

Mirrors the §2.1 / §2.2 pattern, but the target Secret is consumed by
the chart's `Deployment` (not by `SecretPort`):

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: hort-oci-signing-key
  namespace: <hort-namespace>
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: <your-cluster-secret-store>
    kind: ClusterSecretStore   # or SecretStore for a namespace-scoped store
  target:
    name: hort-oci-signing-key   # ← referenced from chart values below
    creationPolicy: Owner
  data:
    - secretKey: hort-oci-token-signing-key.pem
      remoteRef:
        key: secret/hort/oci-signing-key
        property: hort-oci-token-signing-key.pem
```

### 5.4 Reference from chart values

```yaml
auth:
  tokenExchange:
    enabled: true
    cliClientId: hort-cli
  nativeTokens:
    enabled: true
    signingKey:
      existingSecret: hort-oci-signing-key
      secretKey: hort-oci-token-signing-key.pem
```

The schema gate enforces that `tokenExchange.enabled=true` requires
`nativeTokens.enabled=true` AND a non-empty `signingKey.existingSecret`;
omitting any of these fails `helm template` with a clear error message.

### 5.5 Rotation

The chart exposes a second slot (`signingKey.prevExistingSecret` +
`prevSecretKey`) that the binary serves out of JWKS during a rotation
window. Procedure:

1. Generate a new key, push to a new Vault path (e.g. `oci-signing-key-v2`).
2. Create a second `ExternalSecret` syncing the *current* key into a
   Secret named `hort-oci-signing-key-prev` — this is what the prev slot
   will reference once cutover happens.
3. Update chart values:
   ```yaml
   signingKey:
     existingSecret: hort-oci-signing-key-v2      # the new active
     prevExistingSecret: hort-oci-signing-key     # the previous active
   ```
4. Helm upgrade. The server now signs with the new key and verifies
   against both halves on `/v2/auth` JWKS.
5. Wait out the longest live-token TTL. Admin PATs issued via
   `issue_self_token` are capped at 30 days
   (`crates/hort-app/src/use_cases/api_token_use_case.rs` —
   `MAX_ADMIN_EXPIRY_DAYS: u32 = 30`), so 30 days is the safe minimum
   window. CLI sessions are short-lived (15 min access tokens, 30-day
   sliding refresh). OCI Distribution-Spec tokens are short-lived
   (~5 minutes) — they're not the binding constraint here.
6. After the window, drop the `prev*` chart values and the old Vault
   path. Helm upgrade re-renders the Deployment without the prev env
   var.

### 5.6 What we deliberately do NOT do here

- **Generate the key from the chart.** A Helm `lookup`/`randAlphaNum`
  approach would either re-generate on every upgrade (token-validation
  Armageddon) or hash-pin into the rendered manifest (the private key
  ends up in `helm get manifest` output and git history of any
  flux/argo-managed cluster). The chart consumes; the operator
  generates.
- **Mount the key as a file.** PKCS#8 PEM is short and well-suited to
  an env var; mounting adds permissions / inotify / restartPolicy
  concerns without changing the security shape. `secretKeyRef` is the
  Kubernetes-native way to feed a single short secret to a process.
- **Reuse `SecretPort` for this.** `SecretPort` is the upstream-
  credential abstraction (§1). The OCI signing key is composed into
  `AppContext` at boot, not resolved per-request — different layer,
  different lifecycle.

---

## 6. What we do NOT support

These are deliberate omissions, not roadmap items. The design keeps
Hort out of the secret-distribution business: the binary reads bytes
from a file or env var, and everything upstream of that is the
operator's tooling.

- **Direct Vault / OpenBao / ESO / cloud-KMS clients in-tree.**
  Operators wire whatever secret-sync mechanism they prefer; Hort
  reads the resulting env vars or mounted files. Adding a new
  upstream secret store is a documentation change to this file,
  not a code change in Hort.
- **Inotify / file-watch reload.** v1 reads files on each
  `resolve()`. tmpfs handles this trivially.
- **In-process caching of resolved values.** The OS page cache plus
  tmpfs is the cache. Hort adds nothing on top.
- **Env-var rotation.** Use `source: file` if you need rotation.
- **Encryption-at-rest** for the in-memory `SecretValue`. Protection
  is the `Zeroizing<Vec<u8>>` wrapper plus the missing `Debug` /
  `Display` / `Serialize` impls — accidental log emission is a
  compile error. The process boundary is the trust boundary.
