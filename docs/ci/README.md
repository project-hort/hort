# GitLab CI — running the pipeline on another installation

`.gitlab-ci.yml` is the canonical pipeline. The lint / test / coverage /
`cargo audit` / `cargo deny` / pin-sync / chart-template / SBOM-generation
stages are portable and need no configuration. The **build → publish → sign**
tail and the **Sonar** gate talk to external services; this page documents the
variables and runner prerequisites those need so the pipeline runs on a vanilla
GitLab installation.

The pipeline ships with **no environment-specific defaults** — the portable
default is keyless signing with no registry, CA, or Vault assumptions baked in.
Every install sets the variables below to point at its own infrastructure.

## CI/CD variables

Set these under **Settings → CI/CD → Variables** (mask secrets).

### Registry (image + chart publish)

| Variable | Default | Purpose |
|----------|---------|---------|
| `REGISTRY` | *(required)* | OCI registry host for images **and** Helm charts. No default — the build/publish/sign jobs need it. Set `REGISTRY=$CI_REGISTRY` to use this GitLab instance's own registry. |
| `IMAGE_PREFIX` | `hort` | Path namespace: images at `$REGISTRY/$IMAGE_PREFIX/hort-{server,worker}`, charts at `$REGISTRY/$IMAGE_PREFIX/charts`. |
| `REGISTRY_USER` / `REGISTRY_PASSWORD` | *(unset)* | Registry credentials. Resolution precedence: these vars → the `/secrets/zot` file mount → GitLab's built-in `$CI_REGISTRY_USER` / `$CI_REGISTRY_PASSWORD`. To publish to **this GitLab instance's** container registry, set `REGISTRY=$CI_REGISTRY` and leave user/password unset (the `$CI_REGISTRY_*` fallback authenticates automatically). |

### Internal-PKI CA

| Variable | Default | Purpose |
|----------|---------|---------|
| `PLATFORM_CA_PATH` | *(empty — disabled)* | Path to an internal CA cert to trust before TLS calls to the registry / Vault. Empty by default, so a public-CA registry needs nothing. Set to the in-runner path of a mounted internal CA to enable it; the trust step is a **no-op when the file is absent**. The cert itself must be mounted into the runner pod; it is not in the repo. |

### Signing (`SIGNING_MODE`)

| Value | What it does | Extra setup |
|-------|--------------|-------------|
| `keyless` *(default)* | Signs via Sigstore (Fulcio cert + Rekor transparency log) using the GitLab OIDC token. **No Vault, no key material** — the portable default. | Outbound network to Fulcio/Rekor (public Sigstore). The `SIGSTORE_ID_TOKEN` id_token is already declared in the pipeline. |
| `vault-key` | Fetches an offline cosign key from Vault/OpenBao and signs images + the SBOM with it (no Rekor). | The Vault variables below (all required — no defaults). |
| `none` | Skips signing entirely. | — |

Vault variables (only for `SIGNING_MODE=vault-key`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `VAULT_ADDR` | *(required)* | Vault/OpenBao base URL. Also the `aud` of the `VAULT_ID_TOKEN` OIDC token. |
| `VAULT_JWT_ROLE` | *(required)* | JWT auth role bound to this project (install-specific — no default). |
| `VAULT_COSIGN_SECRET_PATH` | *(required)* | KV-v2 path holding `private_key` + `password` (install-specific — no default). |
| `VAULT_LOGIN_PATH` | `v1/auth/gitlab/login` | JWT auth-backend login path (conventional default; override if your JWT mount differs). |

The Vault JWT auth backend must be configured to trust this GitLab instance's
OIDC issuer and bind `VAULT_JWT_ROLE` to this project.

### Quality gate (Sonar)

| Variable | Default | Purpose |
|----------|---------|---------|
| `SONAR_TOKEN` | *(unset)* | **The `quality:sonar` job runs only when this is set**, so installations without Sonar don't fail the quality stage. |
| `SONAR_HOST_URL` | *(unset)* | SonarQube/SonarCloud base URL. |
| `SONAR_PROJECT_KEY` / `SONAR_ORGANIZATION` | *(unset)* | Optional — point at a specific Sonar project. Static analysis config lives in `sonar-project.properties`. |

## Runner prerequisites

- **Executor.** The `KUBERNETES_*` resource requests/limits apply to the GitLab
  Kubernetes executor and are harmless no-ops on other executors. They are tuned
  for a Kubernetes runner's node sizing (`CARGO_BUILD_JOBS=2`, line-tables-only
  debug) to bound peak RSS — leave them unless you hit OOM/eviction.
- **Secret-file mounts (optional).** If the runner mounts registry credentials
  at `/secrets/zot/{username,password}`, credential resolution picks them up
  automatically (see the precedence above). Most installs instead set
  `REGISTRY_USER`/`REGISTRY_PASSWORD` (and `PLATFORM_CA_PATH` for an internal CA)
  and need no mounts.
- **Network egress.** The build/sign jobs download cosign from
  `github.com/sigstore/cosign/releases`; several jobs `cargo install` and
  install OS packages. `SIGNING_MODE=keyless` additionally needs reach to public
  Sigstore (Fulcio + Rekor). Air-gapped installs must mirror these.

## Quick recipes

**Publish to this GitLab's registry, keyless signing, no Sonar/Vault** (the
minimal portable setup):

```
REGISTRY        = $CI_REGISTRY            # e.g. registry.gitlab.example.com/group/project
SIGNING_MODE    = keyless                 # (this is the default; shown for clarity)
# REGISTRY_USER / REGISTRY_PASSWORD: leave unset (CI_REGISTRY_* fallback)
# PLATFORM_CA_PATH: leave unset (no internal CA → trust step skipped)
# SONAR_TOKEN: leave unset (Sonar job is skipped)
```

**Build images but never publish/sign** (CI-only validation): set
`SIGNING_MODE=none` and point `REGISTRY` at a registry you can push to (the build
jobs still run on `main` / `release/*` / tags and push the image; only signing is
skipped). To skip the publish stages entirely, disable the `build-images:*` and
`helm:lint-and-publish` jobs in your fork.
