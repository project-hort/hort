# Hort Ansible Deployment

Ansible playbooks for deploying hort to a bare-metal or VM host running
Debian 13 (trixie).  Two flavors are provided:

| Flavor | Playbook | Container runtime |
|---|---|---|
| Podman | `site-podman.yml` | Rootless Podman + Quadlet systemd units |
| Native | `site-native.yml` | Bare `hort-server`/`hort-worker` binaries + systemd (Task 9) |

## Prerequisites

1. **Target host:** bare Debian 13 with SSH access (`ansible_user=debian` by
   default; adjust in `inventory/production/hosts.ini`).
   **Ensure key-based SSH authentication works before applying** — the `base`
   role disables password authentication (`PasswordAuthentication no`).  If the
   play reaches that task, key auth is confirmed to work; password auth is then
   disabled as a hardening measure.
2. **DNS A record:** `registry.hort.rs` must resolve to the target host's
   public IP before running the play (certbot ACME challenge needs this).
3. **Ansible Vault:** secret values live in the gitignored
   `group_vars/production/` directory.  Create it and populate the required
   variables (see *Vault variables* below) before running.
4. **Control node:** Ansible 2.15+, `community.general` and `ansible.posix`
   collections installed (`ansible-galaxy collection install community.general
   ansible.posix`).
5. **Customise the gitops tree** (see *Customising the gitops tree* below).
6. **Set binary checksums** (see *Obtaining binary checksums* below).

## Deploying user

Ansible connects as `ansible_user` (set per host in
`inventory/production/hosts.ini`; the example uses `debian`) and runs every task
via `become` (sudo → root). This is the **operator** account — distinct from the
non-login `hort` **service** user that the `base` role creates to run the
binaries. You provide the operator account; the playbook never creates it.

It must have:

1. **Key-based SSH access.** The `base` role sets `PasswordAuthentication no`, so
   a working SSH key is mandatory — there is no password fallback once the play
   reaches that task.
2. **sudo.** Either passwordless (`NOPASSWD`) or run the playbook with
   `--ask-become-pass` (`-K`).

On a stock Debian 13 cloud image the default sudo user (often `debian`) already
has both via cloud-init — just point `ansible_user` at it. **To use a different
name, change `ansible_user` in the inventory; nothing else hardcodes it.**

To create a dedicated operator account from scratch (run as root on the host —
substitute your public key):

```bash
adduser --disabled-password --gecos "" deploy
usermod -aG sudo deploy
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
echo 'ssh-ed25519 AAAA... you@laptop' > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys
printf 'deploy ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/deploy && chmod 440 /etc/sudoers.d/deploy
```

**Lockout safety.** `base_sshd_allow_groups` is unset by default (no
`AllowGroups` restriction). If you *do* set it, the operator user's group MUST
be in the list or the sshd reload locks you out. Because password auth and
root-password login are disabled by the `base` role, always confirm
`ssh <user>@<host> sudo whoami` prints `root` **before** the first run, and keep
a second SSH session open as a safety net during it.

## Vault variables (`group_vars/production/`)

Create `group_vars/production/vault.yml` (encrypted with `ansible-vault`). You
set *passwords*, not a DSN string — hort-server constructs its own
`HORT_DATABASE_URL`/`DATABASE_URL` from the role name + password. The required
secrets differ by flavor.

**Both flavors:**

```yaml
# Let's Encrypt registration email (required by certbot).
le_email: you@example.com
```

**Native flavor (`site-native.yml`)** — two ADR-0009 PostgreSQL roles, each with
its own password (the runtime role is least-privilege; the DDL role runs
migrations):

```yaml
hort_db_ddl_password: "<strong random>"      # DDL / migrate role
hort_db_runtime_password: "<strong random>"  # least-privilege runtime role
```

**Podman flavor (`site-podman.yml`)** — a single container PostgreSQL password:

```yaml
hort_db_password: "<strong random>"
```

Generate values with e.g. `openssl rand -base64 32`.  Never commit plaintext
secrets — the `group_vars/production/` path is gitignored.

## Customising the gitops tree

The `files/gitops/` directory is synchronised verbatim to the managed host on
every playbook run.  It ships a set of base resources for `registry.hort.rs`
plus example templates for site-specific customisation.

### GitLab CI service account

`files/gitops/auth/service-accounts/gitlab-ci.yaml.example` is an example
`ServiceAccount` resource for GitLab CI pipelines.  The `project_path` claim
value must be set to your actual GitLab namespace/project before deploying.

**Steps:**

1. Copy the example to a real resource file:
   ```bash
   cp files/gitops/auth/service-accounts/gitlab-ci.yaml.example \
      files/gitops/auth/service-accounts/gitlab-ci.yaml
   ```

2. Open `gitlab-ci.yaml` and replace the `REPLACE_ME` placeholder:
   ```yaml
   project_path: "REPLACE_ME/hort"   # ← change to your actual namespace/project
   ```
   Example: if your GitLab group is `myorg` and the project is `hort`, set:
   ```yaml
   project_path: "myorg/hort"
   ```
   Verify the exact claim name from a real `CI_JOB_JWT_V2` token on your GitLab
   instance — the claim is typically `project_path` on GitLab 16+.

3. The M8 placeholder guard (in `roles/gitops/tasks/main.yml`) scans
   `files/gitops/` for any remaining `REPLACE_ME` or `<...>` tokens before
   syncing to the host.  The play will abort with a clear error if any are found.
   `*.example` files are excluded from the scan.

Do NOT commit `gitlab-ci.yaml` with a real project path — it is gitignored
alongside `group_vars/production/`.

## Obtaining binary checksums

The `hort_binaries` and `hort_systemd` roles pin specific versions of `cosign`
and `slsa-verifier` and verify their SHA-256 checksums before installation.
The default values in `roles/*/defaults/main.yml` ship with sentinel strings
(`REPLACE_WITH_SHA256_FROM_RELEASE_PAGE`) rather than placeholder hex values,
so the play aborts immediately with an actionable error if the real checksums
have not been configured.

Store the verified checksum values in `host_vars/<hostname>.yml` or
`group_vars/production/vault.yml` (vault-encrypted) — NOT in the committed
defaults files.

### cosign (`hort_binaries_cosign_sha256_amd64` / `_arm64`)

Pinned version: `hort_binaries_cosign_version` (default `2.4.3`).

```bash
# 1. Download the binaries from the release page:
COSIGN_VER="2.4.3"
curl -fsSLO "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VER}/cosign-linux-amd64"
curl -fsSLO "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VER}/cosign-linux-arm64"

# 2. Compute checksums:
sha256sum cosign-linux-amd64 cosign-linux-arm64

# 3. Cross-check against the published checksums on the GitHub release page:
#    https://github.com/sigstore/cosign/releases/tag/v2.4.3
#    (look for the SHA-256 values in the release notes or a checksums file)

# 4. Set in your vault:
#    hort_binaries_cosign_sha256_amd64: "<verified 64-hex value>"
#    hort_binaries_cosign_sha256_arm64: "<verified 64-hex value>"
```

### slsa-verifier (`hort_systemd_slsa_verifier_sha256_amd64` / `_arm64`)

Pinned version: `hort_systemd_slsa_verifier_version` (default `2.7.0`).

```bash
# 1. Download the binaries from the release page:
SLSA_VER="2.7.0"
curl -fsSLO "https://github.com/slsa-framework/slsa-verifier/releases/download/v${SLSA_VER}/slsa-verifier-linux-amd64"
curl -fsSLO "https://github.com/slsa-framework/slsa-verifier/releases/download/v${SLSA_VER}/slsa-verifier-linux-arm64"

# 2. Compute checksums:
sha256sum slsa-verifier-linux-amd64 slsa-verifier-linux-arm64

# 3. Cross-check against the published checksums on the GitHub release page:
#    https://github.com/slsa-framework/slsa-verifier/releases/tag/v2.7.0

# 4. Set in your vault:
#    hort_systemd_slsa_verifier_sha256_amd64: "<verified 64-hex value>"
#    hort_systemd_slsa_verifier_sha256_arm64: "<verified 64-hex value>"
```

**Do not set these values from the downloaded binary's checksum alone.**  Always
cross-check the `sha256sum` output against the value published on the official
GitHub release page.  Setting the value from the download without cross-checking
defeats the trust anchor: the checksum is the only thing preventing a
MITM-substituted binary from passing the integrity gate.

## Running the playbook

```bash
# Podman flavor (recommended for single-host deploy):
ansible-playbook -i inventory/production/hosts.ini site-podman.yml --ask-vault-pass

# Native flavor (Task 9; requires postgres-apt + hort-binaries + hort-systemd roles):
ansible-playbook -i inventory/production/hosts.ini site-native.yml --ask-vault-pass
```

Dry-run (check mode, no changes applied):

```bash
ansible-playbook -i inventory/production/hosts.ini site-podman.yml \
  --ask-vault-pass --check --diff
```

## Role summary

| Role | Task | Purpose |
|---|---|---|
| `base` | 4 | System user, ufw firewall (80/443 open; 8080 denied) |
| `podman` | 3 | Rootless Podman runtime, service user, linger |
| `hort` | 3 | Quadlet container units (migrate, server, worker, postgres) |
| `nginx` | 4 | TLS-terminating reverse proxy (127.0.0.1:8080 → 443) |
| `certbot` | 4 | Let's Encrypt certificate issuance + renewal timer |
| `fail2ban` | 4 | SSH + nginx auth brute-force protection |
| `gitops` | 4 | Sync gitops config tree; restart hort-server; mint operator tokens |

## certbot operations

### Switching from staging to production certificates

Set `certbot_staging: false` and **re-run the playbook** — that is the whole
procedure. No manual `certbot delete` is needed.

The certbot role detects a staging-issued certificate (the renewal config points
at `acme-staging-v02`) and, when `certbot_staging` is now `false`, deletes it so
the issuance task re-runs against production. This is **gap-free**: the delete
happens *after* the nginx role has rendered the vhost with the still-present cert,
so the `listen 443 ssl` block stays in place and nginx keeps serving the previous
cert from memory; the re-issue's post-issue handlers (`Render nginx vhost (cert
present)` → `Validate` → `Reload`) then swap in the production cert on a graceful
reload. The transition is idempotent — on a host already holding a production
cert, the detection is a no-op and the `creates:` guard skips re-issuance.

```bash
# group_vars/production/main.yml (or your inventory):
certbot_staging: false

ansible-playbook -i inventory/production/hosts.ini site-native.yml --ask-vault-pass
```

(If you ever need to force a manual re-issue for another reason, `sudo certbot
delete --cert-name <fqdn>` on the host followed by a playbook run still works —
the role's detection simply finds no cert and issues a fresh one.)

## CI token exchange recipe

CI pipelines authenticate to hort-server using the RFC 8693 token exchange
flow.  The pipeline requests a short-lived OIDC JWT from the CI platform
(GitHub Actions or GitLab CI) and exchanges it for a hort bearer token.

**Step 1 — obtain the CI OIDC JWT**

GitHub Actions (in a job with `id-token: write` permission):
```bash
OIDC_TOKEN=$(curl -sSf \
  -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=hort-server" \
  | jq -r '.value')
```

GitLab CI (CI_JOB_JWT_V2 provides an OIDC-compatible JWT):
```bash
OIDC_TOKEN="$CI_JOB_JWT_V2"
# GitLab 16+: use id_token with aud: hort-server in .gitlab-ci.yml instead.
```

The OIDC token must carry `aud: hort-server` (the audience value declared in
the gitops `OidcIssuer` resources under `files/gitops/auth/issuers/`).

**Step 2 — exchange for a hort bearer token**

```bash
HORT_TOKEN=$(curl -sSf \
  -X POST "https://registry.hort.rs/api/v1/auth/exchange" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=${OIDC_TOKEN}" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  | jq -r '.access_token')
```

This is a standard RFC 8693 token exchange (form-encoded, not JSON body).
There is no `hort-cli auth exchange` subcommand — use `curl` directly.

**Step 3 — use the token**

```bash
# Cargo sparse index (read):
curl -H "Authorization: Bearer $HORT_TOKEN" \
  "https://registry.hort.rs/crates/index/config.json"

# npm install (read):
npm install --registry "https://:${HORT_TOKEN}@registry.hort.rs/npm/hort-npm/"

# OCI pull (read):
crane pull --insecure-registry=false \
  registry.hort.rs/hort-oci/myimage:latest ./myimage.tar
# (crane uses ~/.docker/config.json; log in first with `crane auth login`)
```

## Pointing a `cargo build` at the gated proxy (build-driven warming)

A gated (`isPublic: false`) cargo pull-through proxy is reachable by stock
`cargo`, but two things must line up:

1. **The token must carry an auth scheme.** cargo sends its configured token
   *verbatim* in the `Authorization` header (the crates.io / RFC 3231 convention
   is a raw, scheme-less token), but hort accepts only `Bearer` / `Basic`. Bake
   the scheme in — use the same Basic-with-dummy-user form the other clients use:

   ```bash
   export HORT_TOKEN="hort_svc_…"                 # a read-capable token
   export CARGO_REGISTRIES_HORT_TOKEN="Basic $(printf 'x:%s' "$HORT_TOKEN" | base64 -w0)"
   ```

2. **A credential provider must be declared** (cargo ≥ 1.74 requires one for
   `auth-required` registries). In the project (or `$CARGO_HOME`) `config.toml`:

   ```toml
   [registry]
   global-credential-providers = ["cargo:token"]
   [source.crates-io]
   replace-with = "hort"
   [registries.hort]
   index = "sparse+https://registry.hort.rs/cargo/crates-proxy/"
   ```

`config.json` is anonymously readable and advertises `auth-required: true`
(server-side, since 0.9.4-beta.3), so cargo bootstraps the registry without a
token and then authenticates the index/download requests with the credential
above.

While the TLS cert is Let's Encrypt **staging** (see *certbot operations*), also
point cargo at a CA bundle that trusts the staging roots:

```bash
export CARGO_HTTP_CAINFO=/path/to/ca-bundle-with-le-staging-roots.pem
```

Drop `CARGO_HTTP_CAINFO` once a real (production) cert is issued.

**Warming behaviour.** The first build *warms* the proxy: each dependency is
fetched from the upstream, ingested, and held in **quarantine** — so the crate
download returns `503 {"error":"artifact is quarantined"}` and the build cannot
complete yet. That is expected. After the quarantine window elapses and the scan
passes, the artifacts release and later builds succeed. Run the build
periodically to pull the dependency closure into quarantine ahead of time.

## GitHub protected `release` environment setup

The `hort-publish` job in `.github/workflows/release.yml` declares
`environment: release`. This causes the job's OIDC token to carry the claim
`environment: release`, which is the exact discriminator the `gha-release`
ServiceAccount binds on (Task 2). Without the protected environment, this claim
is absent and the token exchange is rejected with `no_sa_match`.

**Create the `release` environment before enabling `HORT_PROXY_ENABLED`:**

1. Go to the GitHub repository → **Settings** → **Environments** →
   **New environment** → name it `release`.
2. Under **Deployment branches and tags**, add a rule:
   - Type: **Tag**
   - Pattern: `v*`
   This restricts the environment to tag-triggered runs only.  A non-tag push
   (e.g. a branch push) cannot request the `release` environment, so the OIDC
   token cannot carry `environment: release` from that context.
3. Under **Required reviewers**, add at least one reviewer.
   This enforces a manual approval gate before the `hort-publish` job can run,
   so a tag push alone is not sufficient — a human must approve the deploy.

**Why this is load-bearing, not cosmetic:**

The `gha-release` ServiceAccount's `federatedIdentities` clause matches exactly
on `{repository: project-hort/hort, environment: release}`.  Without the
protected environment and its tag-ref restriction:

- Any workflow run (including branch pushes) could in theory request the `release`
  environment (unless the branch restriction is set), potentially minting an
  `environment: release` OIDC token.
- The reviewer gate enforces "only a reviewed, tagged release can push first-party
  crates to hort-crates".

**After setting up the environment**, flip the proxy on by creating a repo
variable:  **Settings** → **Variables** → **New repository variable**:

```
Name:  HORT_PROXY_ENABLED
Value: true
```

This activates the `hort-auth` action and the `hort-publish` job.

## Post-provisioning operator token retrieval

After the first playbook run the gitops role writes two operator tokens to
`/run/secrets/` on the target host (tmpfs; cleared on reboot).  Retrieve and
store them in your secret manager immediately:

```bash
ssh debian@registry.hort.rs sudo cat /run/secrets/hort-dev.token
ssh debian@registry.hort.rs sudo cat /run/secrets/hort-curator.token
```

These are `hort_svc_*` tokens (not OIDC JWTs).  Store them in Ansible Vault
or your team's secret manager.  Pass `--rotate` to `issue-svc-token` to
replace them on the next provisioning run.
