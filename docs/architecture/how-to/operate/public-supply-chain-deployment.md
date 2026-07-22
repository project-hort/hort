# Operating the public supply-chain deployment (`registry.hort.rs`)

This guide is for the operator of the `registry.hort.rs` dogfood instance —
the hort deployment that proxies, quarantines, and scans hort's own build
dependencies and serves hort's first-party OCI images and Cargo crates.

For the design rationale — *why* this topology, repo classes, scan posture, and
identity model — see [ADR 0034](../../../adr/0034-public-dogfood-deployment.md).

---

## 1. Choosing a deployment flavor

Two Ansible playbooks share the host roles (nginx, certbot, fail2ban, gitops,
operator-token bootstrap) and differ only in how hort itself runs.

| | Podman flavor | Native flavor |
|---|---|---|
| Playbook | `deploy/ansible/site-podman.yml` | `deploy/ansible/site-native.yml` |
| hort runtime | rootless Podman Quadlet containers | release binaries as systemd units |
| Postgres | container | apt `postgresql` (Debian 13) |
| Isolation | container + userns | systemd hardening directives |
| Upgrade path | pull new image tag | bump `hort_version`, re-run playbook |
| Binary provenance | OCI image digest | `cosign verify-blob --bundle` (pinned identity) |
| Recommended when | container tooling already present | bare metal, no container runtime, or when the binary signature chain matters |

Both flavors are production-grade. Pick the one that fits the host environment
and stick with it; mixing the two on one host is not supported.

---

## 2. Initial provisioning

### Prerequisites

- Debian 13 (trixie) host, reachable by SSH from the Ansible controller.
- DNS for `registry.hort.rs` pointing at the host's public IP.
- Ansible installed on the controller; Ansible Vault password available.
- For the native flavor: `cosign` CLI available on the host (installed by the
  `hort_binaries` role).

### Steps

1. **Create the production inventory.** Copy
   `deploy/ansible/inventory/example/hosts.ini` to the gitignored path
   `deploy/ansible/inventory/production/hosts.ini` and set the host IP and
   SSH user.

2. **Populate Vault-encrypted vars.** Create
   `deploy/ansible/inventory/production/group_vars/all/vault.yml` (Ansible
   Vault) with at minimum:

   ```yaml
   # Native flavor (site-native.yml) — two ADR-0009 Postgres roles:
   hort_db_ddl_password: <strong random>      # DDL / migrate role
   hort_db_runtime_password: <strong random>  # least-privilege runtime role
   # Podman flavor (site-podman.yml) — a single container Postgres password:
   # hort_db_password: <strong random>
   ```

   The gitops role mints the two operator `hort_svc_*` tokens
   (`maintainer-dev` read, `maintainer-curator` curate) on first run and
   writes them to `/run/secrets/` (tmpfs — cleared on reboot). Retrieve
   them from there and store them in Ansible Vault / your secret store
   immediately after provisioning; they are **not** written to Vault
   automatically.

3. **Pin `hort_version` (native flavor only).** Edit
   `deploy/ansible/group_vars/all.yml` and set `hort_version` to the desired
   released `v*` tag (e.g. `0.9.3`). Podman deployments use OCI image tags
   (`hort_server_image` / `hort_worker_image` in the same file) instead.

4. **Set up the GitLab CI service account.** Copy
   `deploy/ansible/files/gitops/auth/service-accounts/gitlab-ci.yaml.example`
   to `gitlab-ci.yaml` in the same directory, then replace the
   `REPLACE_ME` `project_path` placeholder with the real GitLab
   namespace/project (e.g. `mygroup/hort`). Without this, GitLab CI
   tokens will not match the `gitlab-ci` ServiceAccount.

5. **Run the playbook** (choose the flavor):

   ```bash
   # Podman flavor
   ansible-playbook -i inventory/production deploy/ansible/site-podman.yml \
     --ask-vault-pass

   # Native flavor
   ansible-playbook -i inventory/production deploy/ansible/site-native.yml \
     --ask-vault-pass
   ```

   The playbook: installs packages; configures nginx, certbot, and fail2ban;
   writes the gitops config tree; (re)starts hort-server so the boot-time apply
   runs; then mints the two operator `hort_svc_*` tokens via
   `hort-server admin issue-svc-token` and writes them to `/run/secrets/`
   (tmpfs) — retrieve them from there and store them in Vault yourself
   immediately after provisioning; the playbook does not do this for you.

6. **Verify.** After the playbook succeeds:
   - `curl -s https://registry.hort.rs/api/v1/status` → `{"status":"ok"}` (or
     similar healthy response).
   - `curl -s https://registry.hort.rs/v2/` → `200` or `401` (the nginx proxy
     is live; `401` is correct when the OCI endpoint requires auth, `200` if the
     anonymous root endpoint is reachable).
   - `fail2ban-client status` → shows both `sshd` and `hort-nginx-auth` jails running.

### Cosign identity verification (native flavor)

The `hort_binaries` role verifies the downloaded release tarball using:

```bash
cosign verify-blob --bundle hort-server-linux-amd64.tar.gz.bundle \
  --certificate-identity-regexp \
  '^https://github\.com/project-hort/hort/\.github/workflows/build-binaries\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  hort-server-linux-amd64.tar.gz
```

The regexp pins to the exact `build-binaries.yml` workflow triggered by a
release tag — a branch or PR build fails verification. The role exits non-zero
on any verification failure; the playbook halts and the binary is not installed.
Do not loosen the identity regexp without a corresponding ADR change.

---

## 3. Upgrades

### Podman flavor

Update the image tags in `deploy/ansible/group_vars/all.yml` (or in your Vault
vars if you override per-host):

```yaml
hort_server_image: ghcr.io/project-hort/hort-server:0.9.4
hort_worker_image:  ghcr.io/project-hort/hort-worker:0.9.4
```

Then re-run the playbook. Quadlet units are restarted by the `hort`
role's handler when the unit definition changes. Migrations run automatically
via the `hort-server migrate` one-shot unit that is ordered before
`hort-server serve`.

### Native flavor

1. Bump `hort_version` in `deploy/ansible/group_vars/all.yml` to the new
   release tag.
2. Re-run `site-native.yml`. The `hort_binaries` role downloads, verifies, and
   installs the new binaries; the `hort_systemd` role restarts the units.
   Migrations run automatically.

In both flavors: **migrations run before the serve unit starts** (ADR 0009).
There is no manual migration step.

---

## 4. The warming invariant and window-ramp schedule

The warming invariant is a load-bearing operational contract (ADR 0034):
**every developer's local build environment routes cargo, OCI, and npm pulls
through this instance.** A dependency bump merged without a prior local build
through hort means CI may race the quarantine window.

**Do not merge a dependency bump without first building locally through hort.**
The typical dev→review→merge cycle (days) is much greater than the initial
`quarantineDuration: 24h` window, so a developer who builds locally is also
warming CI.

### Ramp schedule

Start conservative and tighten as operations prove smooth:

| Phase | `quarantineDuration` | Trigger to advance |
|---|---|---|
| Launch (first 4 weeks) | `24h` | No 503-on-quarantine CI failures in normal flow |
| Ramp 1 | `48h` | Two weeks at 24h with zero warming failures |
| Ramp 2 | `72h` | Two weeks at 48h with zero warming failures |
| Steady state | `72h`–`168h` (operator judgement) | Operational confidence established |

To apply a ramp: edit the `quarantineDuration` field in each Class B ScanPolicy
file under `deploy/ansible/files/gitops/policies/`, commit, and re-run the
`gitops` role (or the full playbook). The restart-to-apply model means the new
window takes effect on next server start.

### Edge cases

- **CI-only dependency, never built locally.** Mitigations: the 24h initial
  window is comfortably under typical merge latency; for fast-merged PRs
  (hotfixes) a maintainer can run
  `hort-cli prefetch <repo> <package> --version <version>` ahead of merge to warm the
  artifact manually.
- **A build that races the window.** Hort returns `503 + Retry-After`
  (ADR 0007, quarantine invariant #5). The build fails; the developer waits for
  the window to elapse or triggers an early release (§8).

### Base-image prefetch

OCI base images change rarely but can be large. Prefetch them after initial
provisioning to warm the OCI proxies before any CI build runs:

```bash
# Using the maintainer-dev token
hort-cli auth login --paste   # paste the maintainer-dev hort_svc_* token

# Pull the images you use (exact tag must match your CI Dockerfiles)
podman pull registry.hort.rs/dockerhub-proxy/library/rust:1.81-alpine
podman pull registry.hort.rs/dockerhub-proxy/library/postgres:16-alpine
podman pull registry.hort.rs/quay-proxy/buildah/buildah:latest
```

The first pull ingests the artifact and starts the quarantine clock. Subsequent
pulls are served from hort's CAS once the window elapses and the artifact is
released.

---

## 5. Backup and restore

### CAS directory

The CAS (content-addressable storage) directory holds the raw artifact blobs,
addressed by SHA-256 content hash. It can be reconstructed from upstream on
cache miss, but re-warming after a total CAS loss takes time (full quarantine
windows for each artifact).

**Podman flavor.** The CAS lives in a named Podman volume. Back it up:

```bash
# On the VPS — copy the volume to a tarball
podman volume export hort-cas > /backup/hort-cas-$(date +%Y%m%d).tar
```

Restore: `podman volume import hort-cas < /backup/hort-cas-YYYYMMDD.tar` then
restart the stack.

**Native flavor.** The CAS lives in a host directory (default
`/var/lib/hort/cas`, owned by the `hort` system user). Back it up with rsync:

```bash
rsync -a --delete /var/lib/hort/cas/ /backup/hort-cas/
```

### PostgreSQL

The Postgres database holds all non-blob state: artifact metadata, quarantine
status, event streams, service accounts, scan results, and operator tokens.

**Performance tuning.** Both flavors apply RAM-scaled Postgres tuning sourced
from `deploy/ansible/group_vars/all.yml` (`pg_*` variables).  Values are
computed from `ansible_memtotal_mb` (a gathered fact) using co-location-
conservative ratios — Postgres shares the VPS with hort-server, hort-worker,
and the scanners.  The native flavor deploys a conf.d drop-in
(`/etc/postgresql/17/main/conf.d/10-hort-tuning.conf`); the Podman flavor
passes identical values as `-c` flags in the Quadlet `Exec=` line.  Override
any `pg_*` variable in `group_vars/production/` or `host_vars/` as needed.

**Podman flavor** (Postgres as a container):

```bash
# Dump inside the container
podman exec postgres pg_dump -U hort artifact_registry > /backup/hort-db-$(date +%Y%m%d).sql
```

**Native flavor** (apt Postgres):

```bash
sudo -u postgres pg_dump artifact_registry > /backup/hort-db-$(date +%Y%m%d).sql
```

**Restore** (both flavors — stop hort-server first):

```bash
# Podman:  podman exec -i postgres psql -U hort artifact_registry < /backup/hort-db-YYYYMMDD.sql
# Native:  sudo -u postgres psql artifact_registry < /backup/hort-db-YYYYMMDD.sql
```

Then restart hort-server. The boot-time gitops apply is idempotent; existing
gitops-managed rows are reconciled against the config tree on every restart.

---

## 6. fail2ban

### Jails

Two jails run on the host:

- **`sshd`** — standard SSH brute-force protection (apt-package defaults).
- **`hort-nginx-auth`** — custom jail: watches the nginx access log for repeated
  `4xx` responses on the auth/exchange/registry paths; bans the offending IP at
  the firewall. This provides network-level defense-in-depth for the real client
  IP (hort behind the proxy sees only `127.0.0.1`).

### Status check

```bash
# List all jails
sudo fail2ban-client status

# Inspect the hort-nginx-auth jail
sudo fail2ban-client status hort-nginx-auth

# Example output — look for banned IPs
# Jail:        hort-nginx-auth
# ...
# Currently banned: 2
# IP list: 203.0.113.5 203.0.113.17
```

### Unban an IP

```bash
# Unban from a specific jail
sudo fail2ban-client set hort-nginx-auth unbanip 203.0.113.5

# Verify
sudo fail2ban-client status hort-nginx-auth
```

An IP can be permanently whitelisted in the jail config
(`deploy/ansible/roles/fail2ban/templates/jail-hort.local.j2` or the
production host_vars) under `ignoreip`. Re-run the `fail2ban` role to apply.

### Testing the filter

Before enabling the ban action on a new host, verify the filter against real log
lines:

```bash
sudo fail2ban-regex /var/log/nginx/access.log \
  /etc/fail2ban/filter.d/hort-nginx-auth.conf \
  --print-all-matched
```

Adjust the `failregex` in the filter if legitimate health-check `401`s (e.g.
anonymous `/api/v1/status` probes) are being matched.

---

## 7. TLS certificate renewal

Certificates are issued and renewed by certbot (Let's Encrypt). The renewal
timer is installed by the `certbot` Ansible role.

Check renewal status:

```bash
sudo certbot certificates
# Look for "VALID: X days" — renews automatically when < 30 days remain
```

Check the certbot renewal timer:

```bash
sudo systemctl status certbot.timer
```

After a renewal, nginx must reload to pick up the new certificate. The certbot
**deploy** hook (installed by the role — fires only on an actual renewal, not
every renewal attempt) runs `systemctl reload nginx` automatically. Verify the
hook is in place:

```bash
cat /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

If you need to force a manual renewal and reload:

```bash
sudo certbot renew --force-renewal
sudo systemctl reload nginx
# Verify: echo | openssl s_client -connect registry.hort.rs:443 2>/dev/null \
#           | openssl x509 -noout -dates
```

---

## 8. Dev onboarding

### Configure local cargo

Add to `~/.cargo/config.toml` (or the project-level `.cargo/config.toml`):

```toml
[source.crates-io]
replace-with = "hort"

[registries.hort]
# cargo-virtual is the aggregation repo (ADR 0031, shipped) — use it
# unless you specifically need to bypass aggregation and resolve
# against the crates-proxy mirror member directly.
index = "sparse+https://registry.hort.rs/cargo/cargo-virtual/"
```

### Configure container registry

```bash
# Docker / Podman — log in to the proxy
docker login registry.hort.rs
# or
podman login registry.hort.rs
```

When prompted for credentials, use the `maintainer-dev` token (see below) as
the password; any non-empty string works as the username.

In your `Dockerfile` or CI rewrite, replace public registry refs:

```
# Before
FROM rust:1.81-alpine
# After
FROM registry.hort.rs/dockerhub-proxy/library/rust:1.81-alpine
```

### Authenticate with hort-cli

The `maintainer-dev` token is a `hort_svc_*` service-account token minted by
the `gitops` Ansible role during provisioning. Retrieve it from Ansible Vault
(or from the password manager where the operator stored it) and authenticate:

```bash
# The token is a hort_svc_* string — NOT a GitHub PAT
hort-cli auth login --paste
# Paste the token when prompted.
```

Verify:

```bash
hort-cli auth status
# Expected: a service-account identity with read permission
```

This token grants `read` on all repos (the only private repos are the dependency
proxies; first-party repos are public). It cannot push or curate.

---

## 9. Emergency early-release runbook

Use this when a security fix must ship before the quarantine window elapses.
Determine the artifact's current state first:

```bash
hort-cli list-versions <repo> <package>
# Find the version in question and look at the status column:
# released | quarantined | quarantined-awaiting-release | rejected | scan-indeterminate

# For the artifact UUID needed in subsequent steps, query the patch-candidate list:
hort-cli admin quarantine list-patch-candidates
# Locate the artifact; note its id (UUID) for use in the state-specific steps below.
```

### State: `Quarantined` — curator waiver

The `maintainer-curator` token covers this case. Retrieve it from the password
manager (do not store it in `.cargo/config.toml` or any developer config — it is
sensitive).

```bash
hort-cli auth login --paste  # paste the maintainer-curator hort_svc_* token
hort-cli curation waive <artifact_id> \
  --justification "CVE-YYYY-NNNN: security fix, fix PR #NNN merged, window waiver authorized by maintainer"
```

The `--justification` field (≤512 bytes, mandatory) is persisted in the event
stream as an attributed `ArtifactReleased { authority: CuratorWaiver }` event.
Choose a justification that a future auditor can evaluate.

After waiving, verify the artifact is released:

```bash
hort-cli list-versions <repo> <package>
# Expected: the version now shows status = released
```

Re-authenticate as the dev token afterward; do not leave the curator token active
in the session.

### State: `ScanIndeterminate` — ad-hoc admin token

`ScanIndeterminate` means the scanner failed terminally (network outage, OOM,
etc.). The curator token is insufficient; `Permission::Admin` is required.
**`issue-svc-token` unconditionally rejects `--permission=admin`** — service
accounts are strictly non-admin (ADR 0038) — so the break-glass admin path is
the dedicated, DSN-gated `bootstrap-session` command instead, which mints a
short-lived (≤1 h, ADR 0013 cap), non-service-account, full-cap token:

```bash
# On the VPS — note: hort-server must be running, and this requires
# HORT_TOKEN_ALLOW_ADMIN=true (an issuance-time gate you set in your shell
# for this command only — the running hort-server does NOT need it set).
# Podman flavor:
podman exec -e HORT_TOKEN_ALLOW_ADMIN=true hort-server \
  hort-server admin bootstrap-session --ttl 1h

# Native flavor:
HORT_TOKEN_ALLOW_ADMIN=true hort-server admin bootstrap-session --ttl 1h
```

Paste the token into `hort-cli auth login --paste`, release the artifact via the
admin quarantine endpoint, then immediately revoke the token:

```bash
hort-cli admin quarantine release <artifact_id> \
  --justification "ScanIndeterminate: scanner outage, manually verified clean, admin release authorized"

# Revoke — replace <token_id> with the id from bootstrap-session's output
# (a normal api_tokens row; same revocation path as any other token).
# No hort-cli subcommand exists for token revocation; use the admin REST API
# directly (supply the bootstrap-session token as HORT_TOKEN):
curl -s -X DELETE \
  -H "Authorization: Bearer $HORT_TOKEN" \
  https://registry.hort.rs/api/v1/admin/tokens/<token_id>
# Expected: 204 No Content
```

Confirm the token is gone by checking that it no longer works:

```bash
# Re-authenticate as the dev token
hort-cli auth login --paste   # paste the maintainer-dev hort_svc_* token
hort-cli auth status
# Expected: dev service-account identity with read permission
```

No standing full-admin token exists on this instance (ADR 0013). The ad-hoc
mint-and-revoke pattern is the correct procedure, not a workaround.

### State: `Rejected` — scan exclusion

`Rejected` means the scanner found real findings in the artifact version. The
correct path is a scan exclusion (e.g. the finding is a false positive, or the
CVE has been triaged and accepted):

```bash
hort-cli curation exclude-finding \
  --policy <scan_policy_uuid> \
  --cve <CVE-YYYY-NNNN> \
  --justification "False positive: CVE-YYYY-NNNN does not apply because <reason>"
```

Adding the exclusion triggers the post-exclusion re-evaluation cascade
immediately server-side: artifacts whose only blocking finding was the
now-excluded CVE may transition `Rejected` → `Quarantined`/`Released` without
waiting for the next scan sweep. The audit chain records one `ExclusionAdded`
event and N `ArtifactReleased { authority: PolicyReEvaluation }` events.

Once all blocking findings are excluded or resolved, and the quarantine window
has also elapsed, the artifact transitions to `Released`.

### Credential hygiene reminders

- The `maintainer-curator` token can release held (possibly malicious) artifacts
  early, bypassing the observation window. Store it in a password manager;
  do not commit it or paste it into CI.
- Both operator tokens are auditable: waivers emit `ArtifactReleased { authority:
  CuratorWaiver }` events; token issuances and revocations are recorded in the
  `issue-svc-token` rows.
- Rotate the curator token if there is any reason to suspect it has been
  disclosed. Re-run the `gitops` Ansible role after rotation to write the new
  token to Vault.
