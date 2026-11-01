# Trust an internal certificate authority

Use this procedure when hort must connect to HTTPS endpoints signed by a private or corporate CA—for example upstream registries, OIDC providers, S3-compatible storage, or webhooks.

`HORT_EXTRA_CA_BUNDLE` points to a PEM file containing one or more trusted CA certificates. It **adds** trust roots; it does not replace normal public-root trust. **Both `hort-server` and `hort-worker` must be able to read the file** if they make affected TLS connections.

## Native Linux / systemd

1. Obtain the CA certificate through a trusted administrative channel and verify its fingerprint out of band.
2. Install the PEM bundle at a readable, administrator-controlled path, e.g. `/etc/hort/certs/internal-roots.pem`.
3. Supply the **absolute path** through `HORT_EXTRA_CA_BUNDLE` to the relevant server and worker environment files, making sure systemd sandboxing allows the file to be read.
4. Restart both services as appropriate and inspect their logs for TLS errors.

```ini
HORT_EXTRA_CA_BUNDLE=/etc/hort/certs/internal-roots.pem
```

This is a trust-root configuration, **not** a reason to disable certificate verification.

## Kubernetes with Helm

Create a ConfigMap with the PEM bundle (do not store private keys in this file):

```bash
kubectl -n hort create configmap corporate-ca-bundle \
  --from-file=ca.crt=/path/to/internal-roots.pem
```

Configure chart values:

```yaml
extraCaBundle:
  path: /etc/hort-server/ca-bundle/ca.crt
  configMapName: corporate-ca-bundle
```

The chart mounts the ConfigMap read-only and sets the environment variable for the server, worker, and relevant CronJobs. Alternatively use `extraCaBundle.secretName` if a Secret is appropriate; **do not set both sources**. Apply the chart update and confirm workloads are healthy.

## Validate and rotate

- Verify the configured file exists and contains valid PEM-encoded CA certificates; startup fails if an explicitly configured bundle is unreadable or invalid.
- Test the specific upstream/OIDC/storage connection that previously failed. A green `/healthz` alone does not prove every remote TLS path works.
- When rotating roots, overlap old and new CA certificates long enough to transition remote endpoints safely, update the bundle, and restart affected processes or roll pods so they read the new bundle.

Avoid distributing credentials or CA private keys via a ConfigMap. See [Supply upstream credentials](../configuration/upstream-secrets.md) for authentication secrets.
