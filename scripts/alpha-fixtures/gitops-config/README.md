# Alpha gitops config

hort-server walks `$HORT_CONFIG_DIR` at boot and applies the diff against
the database. Edit YAML → restart `hort-server` → diff re-applied. The
model is *files-in, startup-only*; there is no live reconciler. See
`docs/architecture/how-to/declare-gitops-config.md` for the full schema.

## Two-track layout (`base/` vs `auth/`)

The runbook has two tracks (see `docs/architecture/how-to/alpha-testing-runbook.md`):

| Track | `HORT_CONFIG_DIR` points at | Applies |
|---|---|---|
| **A — no OIDC (PAT-only)** | `…/gitops-config/base` | `base/` only (repositories, upstreams, policies) |
| **B — OIDC (full features)** | `…/gitops-config` (full tree) | `base/` **and** `auth/` |

The OIDC `auth/` ClaimMappings + claim-subject PermissionGrants live one
level **above** `base/` on purpose: `hort-server` **fail-closes at boot**
if any ClaimMapping is declared while `HORT_AUTH_PROVIDER=disabled` (no
"silent dormant state"). Track A runs auth-disabled, so it must point at
`base/` to exclude `auth/`. Track B sets `HORT_AUTH_PROVIDER=oidc`
(`alpha.env.oidc`) and points at the full tree so the ClaimMappings apply.

> The `alpha_fixtures` guard test (`crates/hort-config/tests/alpha_fixtures.rs`)
> walks the **whole** `gitops-config/` tree recursively, so both `base/`
> and `auth/` stay under regression coverage regardless of the split.

## What this fixture declares

### `base/` — both tracks

| File | Kind | Purpose |
|---|---|---|
| `base/repositories/01-npm-proxy.yaml`  | ArtifactRepository | Pull-through cache of `registry.npmjs.org` |
| `base/repositories/02-npm-hosted.yaml` | ArtifactRepository | Local-publish hosted repo |
| `base/repositories/03-pypi-proxy.yaml` | ArtifactRepository | Pull-through cache of `pypi.org` |
| `base/repositories/04-pypi-hosted.yaml`| ArtifactRepository | Local-publish hosted repo |
| `base/repositories/05-cargo-proxy.yaml`| ArtifactRepository | Pull-through cache of `crates.io` |
| `base/repositories/06-cargo-hosted.yaml`| ArtifactRepository | Local-publish hosted repo |
| `base/repositories/07-oci-proxy.yaml`  | ArtifactRepository | Pull-through cache of `index.docker.io` |
| `base/repositories/08-oci-hosted.yaml` | ArtifactRepository | Local-publish hosted repo |
| `base/upstreams/11-npm-proxy.yaml`     | UpstreamMapping    | Runtime routing for npm-proxy → registry.npmjs.org |
| `base/upstreams/12-pypi-proxy.yaml`    | UpstreamMapping    | Runtime routing for pypi-proxy → pypi.org |
| `base/upstreams/13-cargo-proxy.yaml`   | UpstreamMapping    | Runtime routing for cargo-proxy → crates.io |
| `base/upstreams/14-oci-proxy.yaml`     | UpstreamMapping    | Runtime routing for oci-proxy → docker.io/library |
| `base/policies/20-default-scan-policy.yaml` | ScanPolicy    | Global Trivy + OSV at Critical, 60 s quarantine |

### `auth/` — Track B (OIDC) only

| File | Kind | Purpose |
|---|---|---|
| `auth/29-admins-claim-mapping.yaml` | ClaimMapping  | OIDC group `hort-admins` → `admin` claim (the realm's `admin` user; required for the admin-only surfaces) |
| `auth/30-developers-claim-mapping.yaml` | ClaimMapping  | OIDC group `test-developers` → `developer` claim |
| `auth/30b-ci-pushers-claim-mapping.yaml` | ClaimMapping | OIDC group `test-developers` → `ci-pusher` claim (fan-out — a member's resolved set is `[developer, ci-pusher]`, the two-claim subject the grants require) |
| `auth/31-read-npm-proxy.yaml` | PermissionGrant | `[developer, ci-pusher]` → Read on `npm-proxy` |
| `auth/32-read-pypi-proxy.yaml` | PermissionGrant | `[developer, ci-pusher]` → Read on `pypi-proxy` |
| `auth/33-read-cargo-proxy.yaml` | PermissionGrant | `[developer, ci-pusher]` → Read on `cargo-proxy` |
| `auth/34-prefetch-npm-proxy.yaml` | PermissionGrant | `[developer, ci-pusher]` → Prefetch on `npm-proxy` |
| `auth/35-prefetch-pypi-proxy.yaml` | PermissionGrant | `[developer, ci-pusher]` → Prefetch on `pypi-proxy` |
| `auth/36-prefetch-cargo-proxy.yaml` | PermissionGrant | `[developer, ci-pusher]` → Prefetch on `cargo-proxy` |

The Read+Prefetch grants are **≥2-claim + per-repo** (mirroring
`deploy/compose/example-config/auth/dev-*-e2e.yaml`) so they clear the
apply linter's `single-claim-grant` AND `wildcard-repo-non-admin` rules
(both `reject` by secure default; do NOT downgrade `LintConfig` to
re-admit the old global single-claim shape).
They are paired per repo (Read ∧ Prefetch) to satisfy the
self-service-prefetch requirement. OCI is excluded at the use-case layer
(`oci_unsupported`), so no OCI grant is declared. The
discovery/prefetch endpoints are reachable only via the OIDC CLI-session
flow — the CliSession access token is a claims-carrying hort-signed JWT,
so a `test-developers` member's resolved `[developer, ci-pusher]` set
authorizes these claim-subject grants.

## Why both `ArtifactRepository` and `UpstreamMapping` for each proxy

`ArtifactRepository.spec.proxy.upstreamUrl` is *validator-only* — it
keeps the gitops linter happy but the runtime never reads it. The
runtime path resolves upstreams through `UpstreamResolver`, which
reads `repository_upstream_mappings` (populated by
`kind: UpstreamMapping`). Without the matching upstream YAML, every
pull-through fetch returns 404. See
`crates/hort-http-npm/src/upstream_pull.rs::try_upstream_file_pull` for
the call site.

## Storage paths

All repos use filesystem CAS under `$HORT_STORAGE_FILESYSTEM_PATH` (set in
`alpha.env` to `./data/alpha/storage/`). The `spec.storage.path` is
relative to the storage backend root.

## What this fixture does NOT include

- **Static credentials** (no `kind: User`, `kind: ApiToken`). Track A
  uses the svc-token from `hort-server admin issue-svc-token` for the
  write/publish steps — see §3 of the runbook. The `auth/` ClaimMapping
  + PermissionGrant fixtures back the OIDC CLI-session discovery/prefetch
  flow and apply only in Track B, not the svc-token path.
- **Multi-upstream OCI** — the OCI proxy points at `docker.io/library`
  only. To test multi-upstream OCI (`upstream_name_prefix`),
  add additional `UpstreamMapping` rows with distinct `pathPrefix`
  values.
- **Retention policies** — the alpha pass doesn't exercise
  retention by default; declare `kind: RetentionPolicy` envelopes
  here if you want to.
- **Curation rules** (`kind: CurationRule`) — out of scope.
