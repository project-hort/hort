# Install hort on Linux with native binaries

Run `hort-server` and `hort-worker` as **separate systemd services**, without Kubernetes or a container runtime. The repository's native Ansible playbook is the closest maintained deployment reference: it is used for the native installation pattern behind `registry.hort.rs`. The following is an operator walkthrough of that pattern, **not** a one-command local demo.

## Prerequisites

- A supported Linux host with systemd and sudo/root access. The reviewed Ansible roles target Debian 13; other distributions need adaptations.
- PostgreSQL with distinct **migration (DDL)** and **runtime (DML)** roles. Treat database credentials as secrets.
- TLS/DNS for the public registry hostname, and a persistent [artifact storage backend](storage.md) shared by the server and worker.
- Release `hort-server` and `hort-worker` executables for the host architecture. The native playbook downloads and **verifies** them using the `hort_binaries` role (checksum and cosign provenance), provided the pinned verifier checksums have been correctly configured; do not substitute unverified binaries.
- If scanning is enabled, **Trivy** and **osv-scanner** must be installed independently of `hort-worker` and available at the configured paths. Unlike the worker container image, the native executable does **not** bundle these scanner tools.

## Option A: Deploy with the existing Ansible playbook

From the hort source tree, configure the production inventory and the required variables and secrets. Review the `base`, `postgres_apt`, `hort_binaries`, `hort_systemd`, `nginx`, `certbot`, `gitops`, and `hort_timers` roles before running the playbook on a host. The native workflow is defined in [`deploy/ansible/site-native.yml`](https://github.com/project-hort/hort/blob/main/deploy/ansible/site-native.yml).

```bash
cd deploy/ansible
ansible-playbook -i inventory/production/hosts.ini site-native.yml --ask-vault-pass
```

**This changes a server.** Do not run it against an unprepared production inventory. The committed defaults contain **placeholder verifier checksums in both** `hort_binaries` (cosign) **and** `hort_systemd` (slsa-verifier). Set independently verified checksums in trusted inventory variables before deploying; the roles reject their placeholder values. See `deploy/ansible/roles/hort_systemd/defaults/main.yml` in your checkout. Populate and encrypt credentials through your Ansible Vault workflow; do not commit passwords.

The playbook provisions PostgreSQL, installs the signed hort binaries, places environment files under `/etc/hort`, creates the service units, configures Nginx/TLS and applies the GitOps configuration tree. It also creates periodic operator timers. This is a **full server deployment**, not merely a command to start the two executables.

## Option B: Understand or maintain the native services

If installing by hand, reproduce the native Ansible role's setup rather than starting the binaries with a single shared administrator DSN. The following commands are the **actual executable entry points**, once the database, storage, permissions and environment files have been provisioned:

```bash
hort-server migrate             # One-shot migration using the DDL database role
hort-server serve               # Long-running API server, runtime database role
hort-worker                     # Separate long-running background process
```

The production pattern uses three systemd units, installed at `/etc/systemd/system/`:

| Unit | Executable | Environment file | Purpose |
| --- | --- | --- | --- |
| `hort-migrate.service` | `hort-server migrate` | `/etc/hort/hort-migrate.env` | One-shot schema migration using the DDL role |
| `hort-server.service` | `hort-server serve` | `/etc/hort/hort-server.env` | Registry API, GitOps startup apply, health endpoints |
| `hort-worker.service` | `hort-worker` | `/etc/hort/hort-worker.env` | Scanning, prefetch, quarantine and other background tasks |

The Ansible template units require the migration unit to complete before server and worker start. When managing units yourself, preserve that ordering and ensure the database service is available. The reference templates include systemd hardening, an unprivileged `hort` user and filesystem write restrictions; **do not replace them with unconfined root services**.

For orientation, important environment variables used by the reference deployment include:

```ini
# Server runtime, supplied through /etc/hort/hort-server.env:
HORT_DATABASE_URL=postgres://<runtime-user>:<secret>@<db-host>/<db-name>
HORT_STORAGE_BACKEND=filesystem
HORT_STORAGE_FILESYSTEM_PATH=/var/lib/hort/cas
HORT_API_BIND=127.0.0.1:8080
HORT_CONFIG_DIR=/etc/hort/gitops
# Additional auth, OCI token signing and public URL settings are required
# for the enabled features; use the maintained Ansible env template.

# Worker runtime, supplied through /etc/hort/hort-worker.env:
HORT_DATABASE_URL=postgres://<runtime-user>:<secret>@<db-host>/<db-name>
HORT_STORAGE_BACKEND=filesystem
HORT_STORAGE_FILESYSTEM_PATH=/var/lib/hort/cas
HORT_SCANNER_TRIVY_BIN=/usr/bin/trivy
HORT_SCANNER_OSV_BIN=/usr/local/bin/osv-scanner
```

**Illustrative values only:** paths and port vary by inventory, and the snippet is **not a complete bootable configuration**. `HORT_CONFIG_DIR`, signing keys, authentication and other options must match your installation. The two processes must have consistent database/storage configuration. Keep the API bound to loopback when a local reverse proxy provides TLS.

The worker's service includes a persistent scanner cache (`CacheDirectory=hort-worker`) with `TRIVY_CACHE_DIR` and `XDG_CACHE_HOME`, because Trivy needs writable space for its advisory database. The native worker template also documents **systemd sandboxing directives that require a staging scan test** before production rollout. See the current Ansible unit template rather than assuming every hardening option has been live-tested.

## Start and verify the services

After the playbook has provisioned the host, check units and their logs:

```bash
sudo systemctl status hort-migrate hort-server hort-worker
sudo journalctl -u hort-server -n 100 --no-pager
sudo journalctl -u hort-worker -n 100 --no-pager
```

If units have been installed or modified manually, run `sudo systemctl daemon-reload` and arrange migration, server and worker startup in dependency order using the provided units. Avoid rerunning migrations without understanding the database state.

With Nginx/TLS configured to forward to the server's API listener, check:

```bash
curl -fsS https://<your-registry-host>/healthz
curl -fsS https://<your-registry-host>/readyz
```

Replace `<your-registry-host>` with your real hostname. A passing health check **does not** demonstrate that artifact ingestion, worker scanning or authorization works. Confirm all three independently before declaring the deployment ready.

## Apply repository configuration and test a pull

The native playbook synchronizes its GitOps YAML into the directory configured by `HORT_CONFIG_DIR`. You can validate a proposed configuration **offline** before deployment:

```bash
HORT_CONFIG_DIR=/path/to/proposed/config hort-server validate-config --strict
```

Validation does not apply changes to a live server. After deploying changed YAML, restart `hort-server` so the startup apply can run; check the server logs for errors. See [Declarative configuration](../configuration/declarative.md) and [OCI pull-through proxy](../repositories/oci-pull-through.md) for the next operator steps. Verify a real client pull before putting the repository into service.

