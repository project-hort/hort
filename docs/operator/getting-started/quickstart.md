# Quickstart: run hort and verify a repository workflow

**Audience:** operators deploying hort on Linux or Kubernetes. You need a prepared deployment environment, PostgreSQL, suitable authentication and storage, and a registry hostname with trusted TLS. Follow the full installation guide for your chosen environment before performing the client test below.

## Choose your deployment path

hort runs as **native Linux executables** or as **containers in Kubernetes**. Both options run the API server (`hort-server`) and background processing (`hort-worker`) separately and require PostgreSQL and artifact storage.

| Deployment | Best starting point | What it installs |
| --- | --- | --- |
| **Native Linux (systemd)** | [Install native binaries](../installation/native-linux.md) | Signed release binaries, PostgreSQL, systemd services, scanner tools, Nginx and GitOps configuration via the included Ansible playbook. |
| **Kubernetes (Helm)** | [Install with Helm](../installation/kubernetes-helm.md) | Server, worker and migration workloads, with operator-provided PostgreSQL, secrets and edge routing. |

### Native Linux: start here

The existing native playbook deploys the two executables as separate Linux services. On a prepared host, the sequence is **migrate → server + worker** (with separate migration and runtime database credentials):

```bash
# From a configured hort source checkout and prepared Ansible inventory:
cd deploy/ansible
ansible-playbook -i inventory/production/hosts.ini site-native.yml --ask-vault-pass

# On the deployed host, verify both executables are running:
sudo systemctl status hort-migrate hort-server hort-worker
sudo journalctl -u hort-server -n 50 --no-pager
sudo journalctl -u hort-worker -n 50 --no-pager
```

The services invoke `hort-server migrate` (once), `hort-server serve` (API) and `hort-worker` (background processing). For prerequisites, required secret files, scanner dependencies and the systemd security settings, **read [Install native binaries](../installation/native-linux.md) before running Ansible**. This is a full deployment that configures PostgreSQL, Nginx and TLS; it is not safe to run against an unprepared host.

After the native service is healthy, continue at [Configure a repository](#4-apply-an-oci-repository-configuration). For Kubernetes, use the Helm steps below. Neither path changes configuration dynamically: apply declarative YAML by restarting the server. An initial artifact pull is still an acceptance test, not a demonstrated result.

## 1. Kubernetes: prepare prerequisites

- Kubernetes 1.27+, Helm 3.8+, `kubectl`, a DNS/TLS endpoint, and OIDC issuer URL/audience.
- External PostgreSQL 14+ with **separate application and migration roles**, provisioned as described in [Prepare PostgreSQL](../installation/postgresql.md) (including migration role `CREATEROLE` and required privileges).
- In the `hort` namespace, create Secrets `hort-postgres-app` and `hort-postgres-admin`, each with a `DATABASE_URL` key. Do not commit database URLs to Git.
- A filesystem PVC for a single replica, or external S3-compatible storage **and Redis** if using multiple replicas. See [Configure artifact storage](../installation/storage.md).

## 2. Kubernetes: install the service

Save the following as `values.yaml`, replacing the example URLs with **real** operator-managed endpoints:

```yaml
publicBaseUrl: https://hort.example.com
auth:
  provider: oidc
  oidc:
    issuerUrl: https://idp.example.com/realms/hort
    audience: hort-server
postgres:
  app:
    existingSecret: hort-postgres-app
  admin:
    existingSecret: hort-postgres-admin
storage:
  backend: filesystem
  filesystem:
    pvc:
      enabled: true
      size: 50Gi
ephemeralStore:
  backend: memory
```

Before using this against a real cluster, **add appropriate NetworkPolicy ingress/egress rules** and read [Install with Helm](../installation/kubernetes-helm.md). With the chart defaults (`networkPolicy.enabled: true`, empty application rules), the server pods cannot reach PostgreSQL/OIDC or accept client traffic. The example below is **not** a complete, immediately functional cluster deployment.

```bash
helm show chart oci://ghcr.io/project-hort/charts/hort-server --version 0.17.0
helm install hort oci://ghcr.io/project-hort/charts/hort-server \
  --version 0.17.0 --namespace hort --create-namespace -f values.yaml
kubectl -n hort get pods
kubectl -n hort get jobs
```

**Do not assume** the Helm chart creates an Ingress, Gateway or HTTPRoute; you must provide your own edge routing. The chart ships NetworkPolicies with restrictive defaults; configure network access to PostgreSQL, OIDC, the edge, and any needed services explicitly.

## 3. Confirm health and readiness (either path)

With the public URL and network route for your chosen deployment in place:

```bash
curl -fsS https://hort.example.com/healthz
curl -fsS https://hort.example.com/readyz
```

Successful responses indicate the service is reachable and ready. Do **not** treat an anonymous `/metrics` request returning 401 (or 404 on the main API listener) as a failed install: metrics are exposed separately and require authorized access.

## 4. Apply an OCI repository configuration

For a **first client operation**, use an OCI repository and verify that a client can push and pull an image with `skopeo`.

**Choose which operation you need:**

- **Publish and pull an image:** Create a `hosted` OCI repository and grant
  both `write` and `read` to the publishing/consuming identity, as illustrated
  below. See [Identity & access](../configuration/identity-access.md) for
  how your deployment authenticates those identities.
- **Pull an upstream image through hort:** Follow the
  [OCI pull-through guide](../repositories/oci-pull-through.md). Its
  `UpstreamMapping` resources are applied at server startup, not created on
  demand by a client request.

### Example: a hosted OCI repository with explicit access

Save the following resource as `config/repositories/oci-internal.yaml`:

```yaml
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: oci-internal
spec:
  name: "Internal OCI"
  format: oci
  type: hosted
  isPublic: false
  replicationPriority: local_only
```

Storage uses your installation's **global** configured backend; do not
invent a separate per-repository storage path.

For an OIDC installation whose identity provider supplies the group
`hort-oci-publishers`, the following resources map that group to a hort
claim and grant **both** repository-scoped permissions. Adjust the IdP group
name to your actual provider; a group claim must really be present in the
login token. Store these as separate YAML documents in your config tree:

```yaml
apiVersion: project-hort.de/v1
kind: ClaimMapping
metadata:
  name: oci-publishers
spec:
  idpGroup: hort-oci-publishers
  claim: oci-publisher
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: oci-publishers-read
spec:
  subject:
    kind: claims
    required: [oci-publisher]
  permission: read
  repository: oci-internal
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: oci-publishers-write
spec:
  subject:
    kind: claims
    required: [oci-publisher]
  permission: write
  repository: oci-internal
```

**Authentication still needs to be configured:** the OIDC provider, client
credentials/token flow, TLS and OCI registry login vary by deployment. The
snippet does not install an IdP or mint a token. A `ServiceAccount` with its
own explicit grants is another supported option for automation. Verify that
`skopeo login` uses credentials accepted by the enabled OCI authentication
mode; do not substitute an ordinary IdP password where a bearer/native token
is required.

Validate the version-controlled configuration **before** deployment:

```bash
HORT_CONFIG_DIR="$PWD/config" hort-server validate-config --strict
```

Transfer the validated files to the server or Helm deployment, and restart
`hort-server` / roll out the server. A successful validator exit code alone
**does not** prove that the runtime applied every resource successfully.
Inspect the resulting repository through your authorized administration interface and review server startup logs. See [Declarative configuration](../configuration/declarative.md).

## 5. Verify an OCI image round trip with a real client

The following is a client-side verification procedure. It assumes that you have already applied a hosted OCI repository
named `oci-internal` (or changed `REPO_KEY` accordingly), have push/read permission,
and use a registry endpoint with a trusted TLS certificate. It is **not** an
out-of-the-box test against an unconfigured installation.

```bash
# Install skopeo on the operator workstation first.
REGISTRY_HOST=hort.example.com           # no https:// prefix
REPO_KEY=oci-internal
SOURCE_IMAGE=ghcr.io/oci-playground/hello-world:latest
DEST_IMAGE="$REGISTRY_HOST/$REPO_KEY/quickstart:v1"
ARCHIVE="$(mktemp --suffix=.tar)"

# Authenticate using your configured identity or service account.
# Use the same supported credential form as your deployed OCI auth mode.
# Avoid entering tokens in shell history or embedding them in documentation.
skopeo login "$REGISTRY_HOST"

# Publish an image from a public registry into your hosted hort repository.
skopeo copy "docker://$SOURCE_IMAGE" "docker://$DEST_IMAGE"

# Record the digest returned by hort and pull the image back.
PUSHED_DIGEST="$(skopeo inspect --format '{{.Digest}}' "docker://$DEST_IMAGE")"
skopeo copy "docker://$DEST_IMAGE" "oci-archive:$ARCHIVE"
PULLED_DIGEST="$(skopeo inspect --format '{{.Digest}}' "oci-archive:$ARCHIVE")"
printf 'Pushed: %s\nPulled: %s\n' "$PUSHED_DIGEST" "$PULLED_DIGEST"
test -n "$PUSHED_DIGEST" && test "$PUSHED_DIGEST" = "$PULLED_DIGEST"
rm -f "$ARCHIVE"
```

**Expected outcome:** `skopeo` exits successfully, both digests are nonempty, and the final comparison succeeds. Use credentials and TLS trust configured for your own installation. When scanning/quarantine policy applies, availability
may be delayed until the artifact is released.

For an upstream-only workflow, use the [OCI pull-through guide](../repositories/oci-pull-through.md)
instead of pushing to a hosted repository.

## 6. If verification fails

Check the server and worker health, repository permissions, TLS trust, and any quarantine/scanning policy. For a pull-only workflow, see [OCI pull-through](../repositories/oci-pull-through.md). For diagnostics, see [Monitoring & troubleshooting](../operations/monitoring.md).
