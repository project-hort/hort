# Configure PyPI pull-through

Route Python dependency downloads through a hort PyPI repository. This guide uses the public PyPI registry and a TLS-protected hort endpoint.

## Before you begin

You need a running hort installation with storage, outbound HTTPS access to `pypi.org` and its file hosts, and access to the declarative configuration directory.

## Declare the repository and upstream

Add `repositories/pypi-public.yaml`:

```yaml
apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: pypi-public
spec:
  name: "PyPI Public Mirror"
  format: pypi
  type: proxy
  # Allow a cold proxy to expose upstream versions in its index.
  indexMode: include_pending
  proxy:
    upstreamUrl: https://pypi.org/
  isPublic: true
  replicationPriority: local_only
```

Add `upstreams/pypi-public.yaml`:

```yaml
apiVersion: project-hort.de/v1
kind: UpstreamMapping
metadata:
  name: pypi-public
spec:
  repository: pypi-public
  pathPrefix: ""
  upstreamUrl: https://pypi.org/
  auth:
    type: anonymous
```

Artifact storage is configured **at deployment level**, not routed by a repository-specific storage path. `isPublic: true` is suitable only when public access is intended; otherwise configure permissions. `indexMode: include_pending` lets a cold PyPI mirror list upstream versions for the first install. Download availability remains subject to quarantine and scanning policy. Validate the complete directory and deploy the files:

```bash
HORT_CONFIG_DIR=/path/to/config hort-server validate-config --strict
```

Restart `hort-server` to apply. An offline validation does not check live connectivity or runtime permissions.

## Install a package through hort

Use a disposable virtual environment and point pip to hort's simple index:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --index-url https://hort.example.com/pypi/pypi-public/simple/ requests
```

For a persistent project configuration, use `pip.conf` or `pip.ini` and configure `index-url` with the same HTTPS endpoint. Avoid using `--extra-index-url` when your intent is to require all downloads to pass through hort: it allows package resolution from other registries.

## Verify and troubleshoot

Confirm that pip used the hort index and that requests appear in hort's server logs. If a file is rejected with `502`, check the upstream metadata and checksum-verification logs; do not disable verification or silently fall back to direct PyPI downloads. For TLS problems, see [Trust custom CAs](../installation/custom-ca.md). For authentication failures, see [Identity & access](../configuration/identity-access.md).
