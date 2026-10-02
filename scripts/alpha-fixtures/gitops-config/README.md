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
| `base/service-accounts/40-metrics-scraper.yaml` | ServiceAccount | PAT-only `read_metrics` scrape identity (#113 item 5) |
| `base/service-accounts/41-metrics-scraper-read-metrics.yaml` | PermissionGrant | `serviceAccount metrics-scraper` → `read_metrics` (global — `repository:` omitted) |
| `base/upstreams/11-npm-proxy.yaml`     | UpstreamMapping    | Runtime routing for npm-proxy → registry.npmjs.org |
| `base/upstreams/12-pypi-proxy.yaml`    | UpstreamMapping    | Runtime routing for pypi-proxy → pypi.org |
| `base/upstreams/13-cargo-proxy.yaml`   | UpstreamMapping    | Runtime routing for cargo-proxy → crates.io |
| `base/upstreams/14-oci-proxy.yaml`     | UpstreamMapping    | Runtime routing for oci-proxy → docker.io/library |
| `base/policies/20-default-scan-policy.yaml` | ScanPolicy    | Global Trivy + OSV at Critical, 60 s quarantine |
| `base/policies/27-npm-proxy-retention-policy.yaml` | RetentionPolicy | `AgeExceeds: 86400` over `{Repos: [npm-proxy]}` — one re-fetchable proxy cache |

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

## Why the retention policy is sharp

`base/policies/27-npm-proxy-retention-policy.yaml` is deliberately a
policy that **matches**, not a placeholder that proves the apply path
runs. An age predicate with a span nothing reaches would show that a
`RetentionPolicy` arrives and produces a `retention_policy_projections`
row, and nothing about whether the candidate reader, the scope resolution
or the dry run work — which is how three independent reasons that nothing
was ever expired came to be found in code review rather than on a walk.

The two choices are bounded by the same two facts:

- **`{Repos: [npm-proxy]}`** — a proxy repository's artifacts are
  pull-through cache entries upstream still holds, so an expiry costs one
  re-fetch of byte-identical content. The hosted repositories hold the
  only copy of what was published into them. Naming one repository also
  exercises the `metadata.name` → id resolution the apply pipeline does
  once (the name-free scope variants skip it).
- **`AgeExceeds: 86400`** — the anchor is `Artifact.created_at` (ingest
  time, not upstream publish time). A day is long enough that a walk
  cannot match what it just ingested, and short enough that anything
  cached on an earlier day already does.

Reading the proposal is safe and needs no destructive authority:

```bash
hort-cli admin retention preview            # dry run: appends nothing, deletes nothing
```

Executing is the separate, destructive step (`hort-cli admin retention
apply`), and it needs the `task:destructive` claim on a fresh IdP-backed
admin session.

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
- **A retention sweep on a schedule** — one `kind: RetentionPolicy` IS
  declared (see *Why the retention policy is sharp* below), but both
  retention CronJobs ship `enabled: false` and this tree does not change
  that. The evaluate/purge pair is run by a person through `hort-cli admin
  retention preview` / `apply`; `preview` (the dry run) needs only
  `Permission::AdminTaskInvoke`, while executing additionally needs the
  `task:destructive` claim, which a claimless bootstrap svc-token cannot
  carry.
- **`KeepLastN` / `UnusedFor` retention** — neither predicate is declared.
  `KeepLastN` ranks siblings and decides nothing over groups of size one,
  and this tree's own walk publishes exactly one version of each hosted
  fixture package. `UnusedFor` has no last-use input wired at the
  evaluator yet (`last_downloaded_at` is passed as `None`), so it would
  read as "old" rather than "unused" — and the gitops apply linter now
  rejects the predicate outright, so declaring it would fail the apply.
- **Curation rules** (`kind: CurationRule`) — out of scope.
