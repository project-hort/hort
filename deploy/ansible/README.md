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

## Vault variables (`group_vars/production/`)

Create `group_vars/production/vault.yml` (encrypted with `ansible-vault`) with
at minimum:

```yaml
# Let's Encrypt registration email (required by certbot).
le_email: you@example.com

# PostgreSQL DSN — used by hort-server at runtime.
# Must match the DATABASE_URL injected into the hort-server env-file.
hort_database_url: "postgres://hort:CHANGEME@localhost:5432/hort"

# PostgreSQL password for the hort container user.
hort_postgres_password: CHANGEME
```

Never commit plaintext secrets.  The `group_vars/production/` path is
gitignored.

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
