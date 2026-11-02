# Pull private images from Kubernetes

Use a namespace-scoped Kubernetes `imagePullSecret` when kubelet must pull private OCI images from hort. Kubelet cannot perform a workload OIDC token exchange as part of a normal `imagePullSecrets` pull.

## Grant read access to a service account

Declare a hort identity and a repository-scoped read grant:

```yaml
apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: image-puller
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: image-puller-read
spec:
  subject:
    kind: serviceAccount
    name: image-puller
  permission: read
  repository: oci-internal
```

Validate the GitOps tree, deploy it, and restart `hort-server` to apply the declarations. From an **authorized administration environment**, mint a token for the already declared identity:

```bash
hort-server admin issue-svc-token --name image-puller --permission=read --expires-in-days=30
```

This prints a secret token **only once**. Do not put the token in Git, command history, CI logs, or support tickets. Use your approved secret-management process to create a Kubernetes Secret of type `kubernetes.io/dockerconfigjson` with a registry host exactly matching the image reference. Store the token as the registry password (`oauth` is a conventional username).

## Attach the Secret to a workload

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: image-pull-check
  namespace: ci-system
spec:
  imagePullSecrets:
    - name: hort-pull-secret
  containers:
    - name: app
      image: registry.example.com/oci-internal/my-app:1.2.3
```

Create the Pod only after creating the Secret in `ci-system`. Inspect the Pod events for an image pull success; delete the test Pod afterward. A `401` may mean credentials were not offered, while `403` typically means the identity does not have permission for the repository. Verify TLS trust and the **exact host:port** in the Secret.

## Rotate credentials

For ongoing workloads, prefer [automatic service-account token rotation](../configuration/rotate-service-account-tokens.md). The worker can maintain `dockerconfigjson` Secrets in approved namespaces. A service account is not granted permissions by its declaration alone.
