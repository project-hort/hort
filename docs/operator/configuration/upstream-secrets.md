# Supply credentials for a private upstream

An upstream registry may require credentials. Store the credential **outside** the GitOps YAML and reference it using an `UpstreamMapping` resource. Do not put tokens or passwords in repository configuration or logs.

## Configure an upstream reference

The following example assumes an existing `ArtifactRepository` named `ghcr-mirror`. Replace the username, URL and secret location for your environment:

```yaml
apiVersion: project-hort.de/v1
kind: UpstreamMapping
metadata:
  name: ghcr-mirror-upstream
spec:
  repository: ghcr-mirror
  pathPrefix: ""
  upstreamUrl: "https://ghcr.io"
  auth:
    type: basic
    username: "YOUR_UPSTREAM_USERNAME"
  secretRef:
    source: file
    location: /run/secrets/ghcr/token
```

`secretRef` belongs to **`UpstreamMapping.spec`**, not to `ArtifactRepository.spec.proxy`. For `auth.type: basic`, it supplies the password/token. The file path must be absolute. Alternatively use `source: env_var` with the **name** of an environment variable, not its value.

## Native Linux

Deliver the token through an administrator-managed secret file, restricted to the process account. Make the absolute path visible to the hort process that performs upstream requests. If using systemd's `LoadCredential=`, account for the **service-specific** path under `/run/credentials/<unit-name>/`; do not assume `$CREDENTIALS_DIRECTORY` is interpolated in the GitOps YAML.

Keep credentials out of the regular environment where practical and review file permissions and sandbox restrictions. Restart the relevant process if you change startup environment variables.

## Kubernetes

Use your approved secret manager, External Secrets Operator, or a Kubernetes Secret to project the token into a read-only file in the workload. The example YAML requires the path `/run/secrets/ghcr/token` to exist **inside the container**.

The chart does not automatically mount an arbitrary upstream token simply because the GitOps file contains `secretRef`. Configure the secret volume and volume mount for the workload and verify file readability. Do not paste token values into Helm values stored in Git.

## Validate and troubleshoot

```bash
HORT_CONFIG_DIR=/path/to/config hort-server validate-config --strict
```

Offline validation checks the YAML structure, **not** whether a runtime secret file or environment variable exists. Missing credentials typically surface when hort resolves the secret during an upstream request. Test with an authenticated pull and check upstream errors without logging credential values.

Rotate upstream credentials in your secret provider, reproject/restart workloads as required, and verify a pull after rotation. Do not mistake a cached pull for evidence that upstream credentials still work; test a request that genuinely reaches the upstream.

Related: [Declarative configuration](declarative.md) · [Trust internal CAs](../installation/custom-ca.md).
