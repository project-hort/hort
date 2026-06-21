# 0034 — Public dogfood deployment and supply-chain hardening posture

- **Status:** Accepted
- **Enforced by:** the gitops apply-time linter (rejects any `ServiceAccount`
  with an empty `federatedIdentities[].claims` map — ADR 0018); the
  `trust_upstream_publish_time_requires_scan_backends` apply-time rule (ADR 0016
  — rejects the dangerous collapse if a future operator enables it); the
  `hort_binaries` Ansible role (cosign `--bundle` verify with pinned
  `--certificate-identity-regexp` + `--certificate-oidc-issuer` — fail-closed,
  non-zero exit on failure; see `deploy/ansible/roles/hort_binaries/defaults/main.yml`).
  The deferred open items are tracked in the open-items register in
  [0000](0000-historical-decisions-index.md).
- **Supersedes:** —
- **Relates:** [0007](0007-fail-closed-quarantine-release-predicate.md),
  [0009](0009-least-privilege-runtime-migrate-subcommand.md),
  [0010](0010-tls-builder-no-insecure-knobs.md),
  [0012](0012-claim-based-rbac-claimless-static-tokens.md),
  [0013](0013-idp-authoritative-cli-sessions.md),
  [0015](0015-apply-time-linter-inert-fields-and-naming.md),
  [0016](0016-cross-opt-in-interaction-matrix.md),
  [0018](0018-auth-catalog-canonical.md),
  [0021](0021-read-handler-anonymous-by-default.md),
  [0031](0031-virtual-repository-aggregation.md)

## Context

Hort's own builds needed supply-chain hardening: every third-party dependency
should be quarantined and scanned before any build consumes it. The same
instance doubles as the world-readable pull point for hort's own OCI images and
a public Cargo registry for hort's crates. This is a deployment + gitops-config
+ CI-integration initiative — it adds no new domain or port code; every
capability it relies on (pull-through, quarantine gate, OIDC federation, RBAC)
was already shipped.

Four design questions had non-obvious answers that must outlive the branch-local
planning documents:

1. **What repository classes to use, and why this exact topology.** The instance
   mixes public first-party repos (anonymous pull) and private proxy repos
   (authenticated ingest + pull) on one endpoint. Getting the visibility
   boundaries wrong either leaks third-party artifacts to the world (making hort
   a free open proxy) or forces unwanted authentication on first-party consumers.

2. **How to authenticate CI workloads without long-lived secrets.** GitHub
   Actions and GitLab CI both issue short-lived OIDC JWTs. The confused-deputy
   risk is real: `token.actions.githubusercontent.com` issues tokens to every
   repository on GitHub, so binding authority on `aud` alone is insufficient.
   Two static operator tokens (dev fetch, emergency curator) are needed but must
   carry the minimum required permission.

3. **What scan posture to hold.** The cross-opt-in interaction matrix (ADR 0016)
   defines a dangerous combination: `trust_upstream_publish_time = true` together
   with `scan_backends: []` collapses the release gate to near-zero latency. This
   instance must never enter that state, and the design decisions below guarantee
   that by construction.

4. **How to run the runtime on a single VPS.** Two deployment flavors exist with
   different isolation boundaries and provenance models; the choice is now a
   standing operational decision, not an ad-hoc choice at every upgrade.

## Decision

### Three repository classes

The gitops tree (`deploy/ansible/files/gitops/`) defines three distinct
repository classes.

**Class A — first-party hosted, `isPublic: true` (anonymous read).**

- `hort-oci` — hort's own `hort-server`/`hort-worker` OCI images. World-readable
  pull; push restricted to the `gha-release` ServiceAccount.
- `hort-crates` — hort's own published crates (`cargo publish` from the release
  CI). World-readable fetch; push restricted to `gha-release`.

Both carry a `*-permissive` ScanPolicy (`scanBackends: []`,
`quarantineDuration: 0s`). This is sound: first-party artifacts are built and
signed by the same operator; the quarantine gate protects against *upstream*
supply-chain contamination, not self-published first-party code. The ADR 0016
cross-opt-in collapse (`trust_upstream_publish_time = true` × `scan_backends:
[]`) cannot arise here because `trust_upstream_publish_time` is irrelevant to
hosted repos — there is no upstream clock to trust.

**Class B — upstream dependency proxies, `isPublic: false` (authenticated ingest
+ read, quarantined + scanned).**

| Repository | Upstream | `scanBackends` | `indexMode` |
|---|---|---|---|
| `crates-proxy` | crates.io sparse index | `["osv"]` | `include_pending` |
| `dockerhub-proxy` | `registry-1.docker.io` | `["trivy"]` | *(default)* |
| `quay-proxy` | `quay.io` | `["trivy"]` | *(default)* |
| `npm-proxy` | `registry.npmjs.org` | `["osv"]` | `include_pending` |

`isPublic: false` means both ingest-on-miss and download require an authenticated
principal with Read. Hort never serves third-party artifacts to anonymous callers.

`scanBackends` is non-empty on every Class B repo — this is a deliberate,
unconditional decision, not an operator opt-in. See the *Scan posture* section.

`indexMode: include_pending` on the SimpleIndex proxies (`crates-proxy`,
`npm-proxy`) is load-bearing for the warming model: the default `released_only`
serves an empty index on a cold mirror, so a range-based `cargo build` or `npm
install` cannot discover a never-ingested version, the first pull never happens,
and the quarantine clock never starts. The OCI proxies leave the default because
OCI clients request an exact tag or digest — index mode is irrelevant. The
`include_pending` additive set is only the `Unknown` (never-ingested) tier;
`NonServableStatusFilter` runs first and strips quarantined/rejected entries, so
no third-party artifact leaks pre-release (ADR 0016 cross-opt-in matrix, §1
Step 0.5 of the design).

**Class C — `cargo-virtual` build endpoint, `isPublic: false`.**

`cargo-virtual` is a `type: virtual` repository with `virtualMembers: [hort-crates,
crates-proxy]`. It is the single cargo endpoint CI and dev builds resolve
against — hort's own crates and the crates.io mirror through one
`[source]` replacement. It is private as a whole (its `crates-proxy` member is
private; builds authenticate before resolving).

**Dependency on ADR 0031:** The cargo serve-path member aggregation (merge member
indexes, delegate pull-through to `crates-proxy` on local miss, thread the caller
through each member's visibility filter) is implemented per [ADR 0031 —
Virtual (aggregated) repository resolution](0031-virtual-repository-aggregation.md).
Until that work is available in the deployed version, builds point at
`crates-proxy` directly. The gitops config (`deploy/ansible/files/gitops/repositories/cargo-virtual.yaml`)
is in the tree so the repository exists at apply time; the virtual aggregation
path gates on the hort version deployed.

### Asymmetric identity model — three surfaces, no IdP

There is no interactive-user OIDC IdP (no Keycloak, Dex, or Authelia). The
`admin bootstrap` command is removed end-to-end. There are no `PermissionGrant`
or `ClaimMapping` rows. There are no human users. The three identity surfaces are
deliberately asymmetric.

**Surface 1 — CI workloads: federated `kind: ServiceAccount`.**

Two `kind: OidcIssuer` objects declare the accepted issuers with
`spec.audiences: ["hort-server"]`:

- `github-actions` → `issuerUrl: https://token.actions.githubusercontent.com`
- `gitlab` → `issuerUrl: https://gitlab.kdp.kloni.cloud`

JWKS is fetched over TLS against the system trust store plus
`HORT_EXTRA_CA_BUNDLE`; no `insecure_jwks_url` (ADR 0010).

Three `kind: ServiceAccount` objects define CI authority. `role` and
`repositories` confer authority; there are no `PermissionGrant`s:

- **`gha-ci`** — `role: reader`, `repositories: [cargo-virtual, crates-proxy,
  dockerhub-proxy, quay-proxy, npm-proxy]`; bound to GitHub Actions via
  `{ issuer: github-actions, claims: { repository: project-hort/hort } }`.
- **`gitlab-ci`** — `role: reader`, same repositories; bound via
  `{ issuer: gitlab, claims: { project_path: <group>/hort } }`.
- **`gha-release`** — `role: developer` (push to `hort-oci` and `hort-crates`);
  `repositories: [hort-oci, hort-crates]`; bound via
  `{ issuer: github-actions, claims: { repository: project-hort/hort, environment: release } }`.

**The confused-deputy risk is closed by the `repository`/`project_path` claim,
not by `aud`.** Any workflow can request any audience; only the `repository` (or
`project_path`) claim is unforgeable — it is bound to the calling workflow's
repository at token issuance by the issuer. The `aud` check (`hort-server`)
merely prevents a different service's token from being replayed at hort.

**The tag restriction on `gha-release` lives in the GitHub Actions `release`
environment, not in hort.** A glob like `ref: refs/tags/v*` cannot be used in SA
claims because matching is exact. The `release` environment is declared as a
protected GitHub Actions environment whose protection rules require a tag ref and
reviewer approval; GitHub then emits the exact `environment: release` claim,
which the SA matches. CI must explicitly request `aud: hort-server` when minting
the token (`core.getIDToken('hort-server')` on GitHub; `id_tokens: { …: { aud:
hort-server } }` on GitLab).

The `HORT_PROXY_ENABLED == 'true'` gate in both CI pipelines ensures the
exchange curl and tool-config steps run only when the proxy is live — the gate is
off-unless-exactly-`true`; setting the variable to `false` or leaving it unset
has no effect.

**Surface 2 — dev fetch token (static `hort_svc_*`, minimum-read, DB-direct).**

Minted by the `gitops` Ansible role via `hort-server admin issue-svc-token --name
maintainer-dev --permission read` (no admin API, no IdP). Operators log in via
`hort-cli auth login --paste` with this token. Global `read` is acceptable on
this instance because the only private repos are the dependency proxies;
`hort-oci` and `hort-crates` are public. This is not a GitHub PAT and is not
bound to any GitHub identity.

**Surface 3 — emergency early-release token (static, curator-permission only,
DB-direct).**

Minted by `hort-server admin issue-svc-token --name maintainer-curator
--permission curate`. Covers `Quarantined` artifacts only: `hort-cli curation
waive <artifact_id> --justification "…"`. It cannot release `ScanIndeterminate`
(stuck scanner) or `Rejected` (findings) artifacts — those require a `Permission::Admin`
ad-hoc token or a scan exclusion respectively (see the operate how-to).

The `curate` token lives in a password manager; it is finite-expiry and rotated
on any suspected compromise. A leaked curator token can release held artifacts
early — bypassing the observation window — so it is treated as sensitive. Both
tokens are auditable: `issue-svc-token` rows, and waivers emit attributed
`ArtifactReleased { authority: CuratorWaiver }` events.

**Apply model.** The gitops tree is applied at `hort-server` boot
(`crates/hort-server/src/gitops_boot.rs` — restart-to-apply). The `gitops`
Ansible role syncs the tree and restarts the server; the two operator tokens are
runtime `issue-svc-token` mints, not gitops resources.

### Scan posture and the warming model

**Non-empty `scan_backends` on every Class B repo is unconditional.** A clean
scan does not release early (ADR 0007); release requires both
`quarantine_until <= now()` *and* a release authority (`ScanSucceeded`). Terminal
scan failure yields `ScanIndeterminate` (non-downloadable), released only by
admin override.

**`trust_upstream_publish_time` is not set** on any repository. Together with
non-empty `scan_backends`, this means the ADR 0016 cross-opt-in collapse
(observation window ≤ sweep-tick latency) **cannot arise on this instance by
construction**. The dangerous combination would require both halves to be
enabled; neither is.

**`quarantineDuration` starts at `24h` on every Class B ScanPolicy, ramped
upward** as operational confidence grows. This is a gitops field (not a
deployment env var); the ramp is an edit to each Class B ScanPolicy's
`quarantineDuration` + server restart. The `24h` initial window is comfortably
under typical dev→review→merge latency.

**The warming invariant** (load-bearing operational contract): dev environments
route all cargo/OCI/npm pulls through this instance. A maintainer who adds or
bumps a dependency builds locally → the pull ingests the artifact and starts the
quarantine clock → by the time the change survives review and merge (days to
weeks, much greater than the window) the artifact is `Released`. CI therefore
only ever pulls released, scanned artifacts. The dev→review→merge latency *is*
the warming pipeline; no separate warming job is needed or exists. This depends
on `indexMode: include_pending` on `crates-proxy` and `npm-proxy` as described
above.

### Two deployment flavors

The runtime layer has two interchangeable flavors sharing the same host roles
(nginx, certbot, fail2ban, gitops, operator-token bootstrap). See the operate
how-to at `docs/architecture/how-to/operate/public-supply-chain-deployment.md`
for provisioning, upgrade, and runbook details.

**Podman flavor (`site-podman.yml`)** — rootless Podman Quadlet containers under
a lingering `hort` user (uid 65532). hort-server, hort-worker, and Postgres run
as containers. CAS uses a named volume with `:U` mount flag (chown-on-mount to
the container's mapped UID — the docker-compose root-init-container pattern does
not translate to rootless Podman). Isolation boundary: container + userns.

**Native flavor (`site-native.yml`)** — `hort-{server,worker}` release binaries
as hardened systemd units under a `hort` system user; Postgres via apt
`postgresql` (Debian 13). The `hort_binaries` role fetches the pinned-version
`.tar.gz` + `.sha256` + `.bundle` from the GitHub release, verifies the SHA-256
checksum, then runs `cosign verify-blob --bundle` with pinned
`--certificate-identity-regexp` and `--certificate-oidc-issuer`; the role fails
closed if verification does not exit zero. Isolation boundary: systemd hardening
(`ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, `ReadWritePaths=<cas>`,
capped `CapabilityBoundingSet`). Trivy and OSV scanner binaries are host
packages.

The native flavor deploys only released `v*` versions (the binary + signature
pipeline is tag-triggered). `hort_version` in
`deploy/ansible/group_vars/all.yml` is the single pin to bump on upgrade.

**Shared host layer** (both flavors): nginx (apt, host-level, binds :443),
certbot/Let's Encrypt, fail2ban with two jails (sshd and a custom hort jail
watching the nginx access log for repeated 401/403 on the auth/exchange/registry
paths), and the `gitops` role.

**Why fail2ban watches the nginx access log:** hort behind the reverse proxy sees
only `127.0.0.1` as the client IP; the real client IP is available only in the
nginx log. The hort application-level lockout (`HORT_PAT_LOCKOUT_*`) and the
federation replay seen-set operate on hort's view; fail2ban provides
network-level defense-in-depth on the real client IP upstream of hort.

## Consequences

- The supply-chain attack surface is bounded: every third-party dependency is
  quarantined and scanned before CI can consume it. The warming invariant ensures
  that under normal development flow CI only ever pulls Released, scanned
  artifacts, with no separate warming pipeline to maintain.
- CI workloads carry no long-lived secrets. An expired or compromised OIDC token
  cannot be replayed (ADR 0018 anti-replay seen-set). A token from any repository
  other than `project-hort/hort` cannot assume the CI service accounts.
- No standing full-admin token exists on the VPS (ADR 0013). The curator token
  has the minimum permission to release held artifacts; full-admin tokens are
  minted ad-hoc and revoked immediately.
- The ADR 0016 dangerous combination (`trust_upstream_publish_time = true` ×
  `scan_backends: []`) is avoided by construction: neither half is enabled on any
  Class B repo.
- The `cargo-virtual` build endpoint depends on ADR 0031's serve-time member
  aggregation. Until that is available in the deployed version, builds resolve
  against `crates-proxy` directly; the `cargo-virtual` gitops resource exists and
  applies cleanly but its aggregation path is version-gated.
- The `gitlab-ci` ServiceAccount carries a `project_path` placeholder
  (`REPLACE_ME/hort`); the real GitLab project path must be substituted before
  enabling the proxy in production (go-live runbook item — see open-items
  register in [0000](0000-historical-decisions-index.md)).
- The apply-time under-constrained-issuer warning fires on both `gha-ci` and
  `gitlab-ci` — these SAs bind only a `repository`/`project_path` claim without
  a `ref` or `env` discriminator. This is expected and secure for reader SAs: a
  reader across all branches of one repo is the intended posture. It is not a
  defect.

## Alternatives considered

- **Interactive-user OIDC (Keycloak / Dex / Authelia) for operator login.**
  Rejected: a single-operator, single-maintainer instance with no human-login
  requirement does not justify a full IdP. The dev fetch token (`hort_svc_*`) is
  fetch-only and acceptable. If the maintainer set grows, an IdP can be added
  without changing the CI federation or scan posture.
- **GitHub PAT for dev fetch.** Rejected: a GitHub PAT is bound to a GitHub
  identity and can be used to access GitHub APIs — wider blast radius than a
  hort-native read token. The `issue-svc-token` path mints a token with minimum
  scope directly in hort's DB.
- **`ref: refs/tags/v*` glob in the `gha-release` SA claims.** Rejected:
  SA claim matching is exact, not glob-based. The tag restriction is enforced by
  the protected GitHub Actions `release` environment.
- **A single deployment flavor (Podman only).** The native flavor adds no code
  and the existing binary + cosign-signing pipeline already publishes the required
  assets. Keeping the native flavor preserves the option to deploy without a
  container runtime and provides a reference for operators running on bare metal
  or systems without Podman.
- **Organic warming only, no documentation.** Rejected: the warming invariant is
  a load-bearing operational contract. If dev environments stop routing through
  hort (e.g. because a developer configures `crates.io` directly), the invariant
  silently breaks and CI may race the quarantine window. The invariant must be
  documented and checked in the operate runbook.

## References

- `deploy/ansible/` — Ansible playbooks and roles for both flavors.
- `deploy/ansible/files/gitops/` — the committed gitops config tree (placeholder
  values for production secrets).
- `deploy/ansible/group_vars/all.yml` — `hort_version` pin (native flavor).
- `deploy/ansible/roles/hort_binaries/defaults/main.yml` — cosign identity pin.
- `docs/architecture/how-to/operate/public-supply-chain-deployment.md` — the
  operate how-to / runbook (provisioning, warming, backup, emergency release).
- `crates/hort-server/src/gitops_boot.rs` — restart-to-apply entrypoint.
- [0007](0007-fail-closed-quarantine-release-predicate.md) — the quarantine
  release predicate this posture relies on.
- [0009](0009-least-privilege-runtime-migrate-subcommand.md) — least-privilege
  runtime; migrations as a separate subcommand (both flavors run
  `hort-server migrate` before `hort-server serve`).
- [0013](0013-idp-authoritative-cli-sessions.md) — no standing full-admin token;
  the ad-hoc admin mint + revoke pattern.
- [0016](0016-cross-opt-in-interaction-matrix.md) — the cross-opt-in interaction
  matrix; the dangerous `trust_upstream_publish_time × scan_backends:[]`
  combination this decision avoids by construction.
- [0018](0018-auth-catalog-canonical.md) — federation mechanics (anti-replay,
  `aud` binding, exact-match claims, empty-claims fail-closed).
- [0021](0021-read-handler-anonymous-by-default.md) — anonymous read-by-default;
  per-repo `isPublic` as the visibility gate.
- [0031](0031-virtual-repository-aggregation.md) — virtual repository aggregation
  that the `cargo-virtual` build endpoint depends on.
