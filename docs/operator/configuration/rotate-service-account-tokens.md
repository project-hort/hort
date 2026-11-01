# Rotate service-account credentials

Prefer short-lived OIDC federation for workloads that support it. Use **fallback token rotation** only for clients that need persistent credentials, such as Kubernetes `imagePullSecrets` or legacy CI agents.

## Before you begin

You need a working Kubernetes deployment with a running worker, permission to change Helm values and GitOps resources, and a namespace that the worker may manage. A `ServiceAccount` is an identity **without** implicit access: grant only the repository permissions it needs.

## Enable the rotation workflow

In your Helm values, enable the scheduled task and restrict where the worker can write Secrets:

```yaml
scheduledTasks:
  adminTasksEnabled: true
  serviceAccountRotation:
    enabled: true
    schedule: "*/15 * * * *"
worker:
  enabled: true
  rotation:
    targetNamespaces: [ci-system]
    publicRegistryHost: registry.example.com
```

Apply the updated chart configuration with your normal deployment process. Ensure the worker has the chart-provided Kubernetes Secret write permissions for the target namespace.

## Declare the rotating identity

Add the following to the declarative configuration, replacing the repository and namespace with your own:

```yaml
apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: ci-image-puller
spec:
  fallbackRotation:
    targetSecret:
      name: hort-pull-secret
      namespace: ci-system
      format: dockerconfigjson
    rotationInterval: 6h
    validity: 24h
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: ci-image-puller-read
spec:
  subject:
    kind: serviceAccount
    name: ci-image-puller
  permission: read
  repository: oci-internal
```

The token lifetime must accommodate rotation delays and client reloads. Validate the **complete** configuration and apply it at server startup:

```bash
HORT_CONFIG_DIR=/path/to/config hort-server validate-config --strict
```

Restart the server after deploying GitOps changes. Keep the rotation task and worker running.

## Verify and troubleshoot

Check for the Kubernetes Secret in `ci-system`, confirm it has the expected owner information, and test a real image pull. If no Secret appears, check the worker and scheduled-task logs, the namespace allowlist, and namespace RBAC. Existing Secrets not owned by that service account are **not** silently overwritten. Previously issued tokens remain valid until expiry unless revoked by the applicable authorization rules.

See [Kubernetes image pulls](../operations/kubernetes-image-pulls.md) for attaching the Secret to a workload, or [Identity & access](identity-access.md) for permissions.
