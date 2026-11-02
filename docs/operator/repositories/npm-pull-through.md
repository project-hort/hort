# Configure npm pull-through

Use a hort repository as the npm registry for dependency downloads. This example proxies the public npm registry; use HTTPS and appropriate access controls for your deployment.

## Before you begin

You need a working hort installation, storage configured for the repository, outbound HTTPS access to `registry.npmjs.org`, and permission to change its declarative configuration. Choose a repository key that does not conflict with an existing repository.

## Declare the repository and upstream

Add `repositories/npm-public.yaml` under your `HORT_CONFIG_DIR`:

```yaml
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: npm-public
spec:
  name: "npm Public Mirror"
  format: npm
  type: proxy
  # Allow a cold proxy to expose upstream versions in its index.
  indexMode: include_pending
  proxy:
    upstreamUrl: https://registry.npmjs.org
  isPublic: true
  replicationPriority: local_only
```

Add `upstreams/npm-public.yaml`:

```yaml
apiVersion: project-hort.de/v1
kind: UpstreamMapping
metadata:
  name: npm-public
spec:
  repository: npm-public
  pathPrefix: ""
  upstreamUrl: https://registry.npmjs.org
  auth:
    type: anonymous
```

Artifact storage is configured **at deployment level** (`HORT_STORAGE_BACKEND` and its associated settings). Repository declarations do not need a storage path. Ensure the shared storage backend is reachable and writable. `isPublic: true` is intended only for a deliberately public mirror; use `false` and configure explicit grants for private access. `indexMode: include_pending` is important for an initially empty npm proxy: the default `released_only` can leave a cold index unable to advertise upstream versions. This makes pending versions discoverable; downloads remain subject to quarantine and scan policy.

## Validate and apply

```bash
HORT_CONFIG_DIR=/path/to/config hort-server validate-config --strict
```

Deploy the reviewed configuration to the server and restart `hort-server` (or roll the deployment). File changes are applied **at startup**, not continuously.

## Configure and verify npm

With a trusted HTTPS endpoint, set the registry in a project's `.npmrc`:

```ini
registry=https://hort.example.com/npm/npm-public/
```

Then run in a throwaway project or directory:

```bash
npm view express version --registry=https://hort.example.com/npm/npm-public/
npm install --registry=https://hort.example.com/npm/npm-public/ express
```

Confirm the request reached hort and the package was installed. Check server logs if metadata downloads succeed but tarballs fail. Repeat the install if you want to assess caching, but remember local npm caching can also avoid network requests.

## Troubleshoot

- `401` or `403`: verify hort authentication and repository permissions.
- `502`: inspect hort server logs, upstream connectivity and checksum-related diagnostics. Do not bypass checksum verification.
- Package not found: check the repository key, upstream mapping and the client's configured registry URL.
- TLS error: check the client trust store; for hort's outbound TLS trust, see [Trust custom CAs](../installation/custom-ca.md).

See [Declarative configuration](../configuration/declarative.md) and [Supply upstream credentials](../configuration/upstream-secrets.md) for private upstreams.
