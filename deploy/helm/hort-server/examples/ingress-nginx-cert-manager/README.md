# Overlay: ingress-nginx + cert-manager

A partial values overlay for the `hort-server` chart that wires the
binary to sit behind an [ingress-nginx](https://kubernetes.github.io/ingress-nginx/)
controller with TLS terminated at the ingress layer. The certificate
is issued and rotated by [cert-manager](https://cert-manager.io/).

## When to pick this overlay

ingress-nginx + cert-manager is by far the most common edge in a
Kubernetes cluster: the controller is widely deployed, cert-manager is
the de-facto Let's Encrypt integration, and the combination handles
TLS termination, ACME challenges, and certificate rotation without
operator intervention. Pick this overlay if you do not already have an
external load balancer doing TLS termination outside the cluster.

## Prerequisites

- [cert-manager](https://cert-manager.io/docs/installation/) is
  installed in the cluster (the overlay does not install it; follow
  upstream docs).
- A `ClusterIssuer` exists. The Ingress example below references
  `letsencrypt-prod`; substitute your own (e.g. `letsencrypt-staging`
  during initial bring-up to avoid Let's Encrypt rate limits).
- An [ingress-nginx](https://kubernetes.github.io/ingress-nginx/deploy/)
  controller is installed and reachable.
- DNS for the public hostname (e.g. `registry.example.com`) points at
  the ingress-nginx LoadBalancer IP or hostname.

## Install

```
helm install hort-server deploy/helm/hort-server/ \
  -f my-values.yaml \
  -f deploy/helm/hort-server/examples/ingress-nginx-cert-manager/values.yaml
```

`my-values.yaml` is the operator's own file: it carries
`image.repository`, `image.tag`, `publicBaseUrl`, the
`postgres.{app,admin}.existingSecret` references, and the
`auth.oidc.*` settings. The overlay only adds the keys characteristic
of this edge shape (`requireHttps`, `api.bindAddr`, `trustedProxyCidrs`).

## Apply the Ingress

The chart deliberately does not ship an Ingress resource (the operator
owns the edge).
Apply the following manifest separately. Replace `<fullname>` with
the chart's rendered fullname (default: `<release>-hort-server`; if you
set `nameOverride` or `fullnameOverride` in your values, use that
instead).

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hort-server
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    # OCI manifest lists can be large — bump proxy buffers.
    nginx.ingress.kubernetes.io/proxy-buffer-size: "16k"
    nginx.ingress.kubernetes.io/proxy-buffers-number: "8"
    # Container images can be many GB; raise the body-size limit.
    nginx.ingress.kubernetes.io/proxy-body-size: "8g"
    # Long blob uploads need long read timeouts.
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
spec:
  ingressClassName: nginx
  tls:
    - hosts: [registry.example.com]
      secretName: hort-server-tls
  rules:
    - host: registry.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: <fullname>-hort-server
                port:
                  name: http
```

## Pitfalls

### `proxy-buffer-size` truncates OCI manifest list responses

The default ingress-nginx proxy buffer is 4k. OCI manifest list
responses for multi-arch images, especially with many layers and
extensive annotations, routinely exceed that. When a buffer overflows,
ingress-nginx replies with a `502 Bad Gateway` or — worse — emits a
truncated body. Container clients then see partial JSON, fail to parse
the manifest, and report cryptic pull errors. Setting
`proxy-buffer-size: "16k"` and `proxy-buffers-number: "8"` (as in the
Ingress above) accommodates the largest realistic manifest lists.

### `proxy-body-size` blocks large blob uploads

`docker push` of a large container image streams every blob through
the ingress. ingress-nginx defaults to a 1 MB body limit, which fails
every realistic image push partway through. Set
`proxy-body-size: "8g"` to cover most enterprise images. If you push
images larger than that (custom OS bases, ML model layers), raise it
further.

### proxy timeouts must exceed `oci.uploadTimeoutSeconds`

The chart's `oci.uploadTimeoutSeconds` defaults to `3600`
(60 minutes) — that is the chart-side window for an OCI long-tail blob
upload to complete. The Ingress annotations above set the
`proxy-read-timeout` and `proxy-send-timeout` to `3600` to match. If
you raise `oci.uploadTimeoutSeconds` in your values, raise the
Ingress annotations to match — otherwise the ingress will sever the
connection while the binary is still happily reading.
