# Overlay: Gateway API

A partial values overlay for the `hort-server` chart that exposes the
binary via the [Gateway API](https://gateway-api.sigs.k8s.io/) v1
resources (`Gateway` + `HTTPRoute`). The Gateway terminates TLS and
forwards plain HTTP to the chart's Service.

## When to pick this overlay

The Gateway API graduated to v1 (GA) in Kubernetes 1.30 and is the
strategic replacement for the older Ingress resource. Pick this
overlay if your cluster already has a Gateway-API-aware controller
installed (Cilium, Istio, Envoy Gateway, NGINX Gateway Fabric,
Traefik, etc.) and you want to consolidate ingress under the new API
rather than maintain Ingress resources. Operators with no existing
Gateway controller will find ingress-nginx + cert-manager simpler;
prefer that overlay.

## Prerequisites

- Kubernetes >= 1.30 (Gateway API v1 GA'd in 1.30; earlier versions
  require `gateway.networking.k8s.io/v1beta1` and may not match the
  YAML below verbatim).
- A Gateway API controller is installed and watching the cluster. One
  of: [Cilium](https://docs.cilium.io/en/stable/network/servicemesh/gateway-api/),
  [Istio](https://istio.io/latest/docs/tasks/traffic-management/ingress/gateway-api/),
  [Envoy Gateway](https://gateway.envoyproxy.io/),
  [NGINX Gateway Fabric](https://docs.nginx.com/nginx-gateway-fabric/),
  [Traefik](https://doc.traefik.io/traefik/providers/kubernetes-gateway/),
  or another conformant implementation.
- The `gateway.networking.k8s.io/v1` CRDs are installed (most
  controllers install them; verify with `kubectl get crd | grep gateway.networking.k8s.io`).
- DNS for the public hostname (e.g. `registry.example.com`) resolves
  to the address the Gateway publishes (controller-specific —
  LoadBalancer IP, hostname, or external address).
- A TLS Secret (`hort-server-tls` in the example below) exists in the
  Gateway's namespace. Either provision it manually or let
  cert-manager populate it via a `Certificate` resource.

## Install

```
helm install hort-server deploy/helm/hort-server/ \
  -f my-values.yaml \
  -f deploy/helm/hort-server/examples/gateway-api/values.yaml
```

`my-values.yaml` is the operator's own file: it carries
`image.repository`, `image.tag`, `publicBaseUrl`, the
`postgres.{app,admin}.existingSecret` references, and the
`auth.oidc.*` settings. The overlay only adds the keys characteristic
of this edge shape.

## Apply the Gateway + HTTPRoute

The chart deliberately does not ship Gateway / HTTPRoute resources
(the operator owns the edge). Apply the following
manifests separately. Replace `<fullname>` with the chart's rendered
fullname (default: `<release>-hort-server`; if you set `nameOverride` or
`fullnameOverride`, use that instead). Replace
`<your-gateway-class>` with the GatewayClass installed by your
controller (`kubectl get gatewayclass`).

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: hort-server
spec:
  gatewayClassName: <your-gateway-class>
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      hostname: registry.example.com
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: hort-server-tls
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: hort-server
spec:
  parentRefs:
    - name: hort-server
  hostnames: [registry.example.com]
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: <fullname>-hort-server
          port: 8080
```

## BackendTLSPolicy notes

For end-to-end TLS — where the Gateway re-encrypts traffic to the
chart's pods rather than forwarding plain HTTP — Gateway API exposes
the [`BackendTLSPolicy`](https://gateway-api.sigs.k8s.io/api-types/backendtlspolicy/)
resource (also under `gateway.networking.k8s.io/v1`). hort-server does **not** terminate TLS in the binary itself, so the
Gateway terminates TLS and talks plain HTTP to the chart's pods. `BackendTLSPolicy` becomes relevant
once the in-binary-TLS initiative ships and the chart's Service grows
an HTTPS port.

## Pitfalls

### Kubernetes < 1.30 needs `v1beta1`

The YAML above targets `gateway.networking.k8s.io/v1`, which is GA in
K8s 1.30 and later. On 1.27–1.29 you must use the `v1beta1` API group.
The shape is similar but not identical; consult your controller's
documentation for the exact CRD versions it supports.

### `gatewayClassName` is operator-specific

The Gateway resource references a `GatewayClass` by name; the value
depends on which controller you installed. Run
`kubectl get gatewayclass` to see what is available, and pick the one
the controller is reconciling.

### Long-lived blob upload connections

Gateway controllers vary in how they handle long-lived HTTP/1.1
connections. Verify your controller's request and response timeout
defaults against the chart's `oci.uploadTimeoutSeconds`
(default `3600`). If your controller imposes a shorter timeout, either
raise the controller's setting via a controller-specific policy
resource (consult its docs) or lower `oci.uploadTimeoutSeconds`
to match — but the latter will cause large OCI blob uploads to fail
mid-stream.

### Body-size limits at the controller layer

Gateway API does not define a portable body-size knob — each
controller exposes its own resource. OCI blob layers routinely run
into the hundreds of MB; Postgres / .NET base images and ML model
layers can exceed multi-GB. Most Gateway controllers default-deny
request bodies smaller than the largest blob a real workload pushes;
the cap is invisible from the chart's perspective and surfaces as
`413 Payload Too Large` (or `502 Bad Gateway` if the controller
drops the connection mid-stream) on `docker push` / `cargo publish`
/ `npm publish` / `twine upload`. Pulls succeed regardless — the
binary streams blob downloads, so the controller-side cap primarily
affects pushes.

hort-server's own application-layer cap is
`HORT_PUBLISH_BODY_MAX_SIZE` (chart key `http.publishBodyMaxSize`, a
size string such as `"512Mi"`; empty ⇒ binary default 300 MiB). For
pushes larger than 300 MiB raise the chart value AND the controller's
per-route cap.
Note that the OCI chunked-upload path bounds each `PATCH` chunk
individually rather than the whole blob, so OCI base layers many
GB in size pass the binary's per-request limit even at the default;
the controller-side cap is the one operators most often need to
raise.

Per-controller cookbook (verify field names against your
controller's current docs — Gateway API extension resources evolve
fast):

- **Traefik** — apply a `Middleware` (`traefik.io/v1alpha1`) with
  `spec.buffering.maxRequestBodyBytes` and reference it from the
  HTTPRoute via `ExtensionRef` (or via the
  `traefik.ingress.kubernetes.io/router.middlewares` annotation on
  the Service if the controller version's HTTPRoute filter does not
  yet support `ExtensionRef` for buffering middleware). See the
  [Traefik Buffering middleware docs](https://doc.traefik.io/traefik/middlewares/http/buffering/).

- **Envoy Gateway** — apply a `BackendTrafficPolicy`
  (`gateway.envoyproxy.io/v1alpha1`) targeting the HTTPRoute, or a
  `ClientTrafficPolicy` targeting the Gateway listener, depending on
  whether you want the limit per-route or per-listener. The relevant
  field is the per-connection client buffer / max-request-bytes
  setting. See the
  [Envoy Gateway traffic policy docs](https://gateway.envoyproxy.io/latest/tasks/traffic/).

- **NGINX Gateway Fabric** — apply a `ClientSettingsPolicy`
  (`gateway.nginx.org/v1alpha1`) with `spec.body.maxSize` (e.g.
  `"8g"`) targeting the Gateway or HTTPRoute. See the
  [NGF custom policies docs](https://docs.nginx.com/nginx-gateway-fabric/overview/custom-policies/).

- **Cilium Gateway** — Cilium implements Gateway API via Envoy under
  the hood; the body-size knob is the same Envoy
  `max_request_bytes` setting, exposed via `CiliumEnvoyConfig` or
  the per-Listener filter chain. See the
  [Cilium Gateway API docs](https://docs.cilium.io/en/stable/network/servicemesh/gateway-api/).

- **Istio (Gateway API mode)** — apply an `EnvoyFilter` patching the
  listener's HTTP connection-manager filter with
  `max_request_bytes`. Istio does not yet expose a first-class
  Gateway API extension for this; the `EnvoyFilter` escape hatch is
  the canonical workaround.

If your controller is not in this list, search its docs for
"request body size", "buffering", or "max bytes". The symptom is
the same in every case: large pushes fail at the proxy before
reaching the binary. Once raised at the controller layer, the
binary's `http.publishBodyMaxSize` (and per-format hard ceilings
like Cargo's 200 MiB) become the only remaining caps.
