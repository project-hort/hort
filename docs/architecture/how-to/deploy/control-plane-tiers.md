# `control-plane-tiers.md` — the three exposure tiers, egress posture, and the control-plane listener

> Companion to [`security-hardening-checklist.md`](./security-hardening-checklist.md).
> This document describes a **shipped, default, documented control** —
> not a future proposal. The pieces that are shipped vs. P1-future are
> labelled inline.

## Why this exists

Hort's intended deployment topology has
**three** exposure classes, not two. Historically the binary expressed
none of them beyond URL path-prefixes while the Helm `networkPolicy`
was gated **off by default** — the intended segmentation was an
*operator assumption*, not a shipped control, which made the
"secure by default" claim (CRA Annex I Part I (1)) untrue for the
admin / subscription-management surface.

The control-plane listener makes the segmentation a shipped, default,
documented control. This document is that documentation.

**This is defense-in-depth — never a substitute for authz.** See
[§4](#4-defense-in-depth-framing-not-a-substitute-for-authz).

---

## 1. The three exposure tiers

| Tier | Routes | Reachability | Sole protection |
|---|---|---|---|
| **(i) Public artifact-serving plane** | npm / PyPI / Cargo / OCI pulls + pushes, `/api/v1/events` pull-resync read API, `/healthz` `/readyz` | Public — package managers and CI pull from anywhere | Per-route authz + the app-layer middleware stack |
| **(ii) Public token-generation plane** | `/api/v1/auth/exchange` (RFC 8693 federation exchange), `/api/v1/auth`, OCI `/v2/auth`, self-service `/api/v1/users/me/tokens` | **Public by requirement** — external push clients and CI/CD *must* be able to mint/exchange tokens (operator-confirmed) | **Application-layer only.** There is **no network backstop** and there cannot be one. Anti-replay (`jti` seen-set), audience binding, per-issuer rate-limiting, short minted-token TTLs and brute-force lockout are *load-bearing and unsubstitutable* here. |
| **(iii) Internal-only control plane** | the `/admin` API, the `/api/v1/admin/*` admin surfaces (incl. `/api/v1/admin/tasks`, `/api/v1/admin/subscriptions`), and `/api/v1/subscriptions` subscription **management** | Internal — operator/admin network only | Network position (this listener + NetworkPolicy) **plus** the admin-gate (claim-based RBAC). DiD, not either-or. |

Tier (ii) **cannot be hidden** behind any network choice, because the
clients that legitimately use it are the same untrusted internet that
an attacker comes from. No `HORT_*_BIND` knob, ingress rule, or
NetworkPolicy removes its core threats (replay of a captured-but-valid
JWT, audience confusion, mint brute-force) — those arrive as
legitimate-looking requests. The application-layer anti-replay and
audience-binding controls are the *sole* protection for tier (ii) and
that is by design, not an oversight. **A control-plane listener does
not change this.**

### What is deliberately NOT on the control tier

Moving any tier-(ii) route onto the internal control listener is an
**anti-pattern** and is explicitly prevented in code
(`crates/hort-server/src/http.rs::control_plane_routes` — the
token-generation, artifact-pull, events-read, and security-score read
surfaces are deliberately excluded; a regression test asserts the
split carries the control plane *only*). `/api/v1` stays on the public
listener because it is a mixed nest (self-service token mint, which is
public by requirement, sits next to admin-mint).

---

## 2. The control-plane listener (`HORT_CONTROL_BIND`) — SHIPPED

A first-class internal-only control-plane listener, mirroring the
existing `HORT_METRICS_BIND` / metrics-listener split exactly.

- **Binary:** `HORT_CONTROL_BIND=<addr:port>` binds the control-plane
  routes ([tier (iii)](#1-the-three-exposure-tiers)) on a dedicated
  listener and **removes them from the public/main listener** — the
  admin + subscription-management surface is then genuinely not
  reachable on the public listener (not merely path-hidden). The
  listener carries the *same* auth / tracing / rate-limit / load-shed /
  security-headers middleware stack the main router applies to those
  routes.
- **Default = unset = `None`.** When `HORT_CONTROL_BIND` is unset the
  control routes stay on the main listener, **byte-identical to the
  no-split behaviour — no migration, no behaviour change.** A
  regression test (`build_router_without_control_split_keeps_admin_on_main`)
  pins this.
- **0.0.0.0 footgun guard.** Binding the control listener to an
  unspecified address (`0.0.0.0:port` / `[::]:port`) is **refused at
  config-parse time** unless the operator explicitly opts in with
  `HORT_CONTROL_PUBLIC_BIND=true`. This is the *same* guard the metrics
  listener carries, extended to the new socket —
  not a new pattern. Loopback and concrete interface addresses always
  pass through.
- **Composition-root log.** On boot the binary logs (once, at the
  composition root) whether the control listener was wired and which
  routes moved.

### Chart wiring — SHIPPED

| Value | Default | Effect |
|---|---|---|
| `control.bindAddr` | `""` | Empty ⇒ control routes on main listener (byte-identical to the no-split behaviour). Non-empty ⇒ dedicated listener; `HORT_CONTROL_BIND` set; container + Service `controlPort` (default `9443`) exposed. |
| `control.allowUnspecifiedBind` | `false` | `HORT_CONTROL_PUBLIC_BIND` — required to bind `0.0.0.0`/`::`. |
| `service.controlPort` | `9443` | Container/Service port for the control listener (only exposed when `control.bindAddr` is set). |

All three pod-listener bind keys share one `<subsystem>.bindAddr` shape
— `api.bindAddr` (the main API listener, `HORT_API_BIND`),
`metrics.bindAddr` (`HORT_METRICS_BIND`), and `control.bindAddr`
(`HORT_CONTROL_BIND`). The pre-existing top-level `apiBindAddr` key was
retired to land this consistency (HARD rename, no alias; the env var is
unchanged).

Example overlay (control on a pod-internal interface, restricted by the
default-on NetworkPolicy):

```yaml
control:
  bindAddr: "0.0.0.0:9443"
  allowUnspecifiedBind: true   # operator owns the NetworkPolicy in front
networkPolicy:
  enabled: true                # default; shown for clarity
  ingress:
    - from:
        - podSelector: {}                       # same-namespace artifact/token-gen clients
      ports:
        - { protocol: TCP, port: 8080 }
    - from:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: hort-operators }
      ports:
        - { protocol: TCP, port: 9443 }         # control plane: operator namespace only
```

---

## 3. Egress posture + the `HORT_TOKEN_BIND` P1 sketch

### Egress posture — SHIPPED

The Helm `networkPolicy` is **on by default**.
The recommended egress posture is to restrict
Hort's outbound reach to the **known webhook-forwarder
set** plus its infrastructure dependencies (Postgres, S3, Redis, the
OIDC issuer, upstream registries). This is the network-side companion
to the **already-shipped** application-side webhook allowlist
(`HORT_WEBHOOK_ALLOWLIST_HOSTS`): the
SSRF blast radius of the user-submittable webhook surface is governed
by Hort's *egress* reachability, so a default-on egress NetworkPolicy is
a strong compensating control. It is **distinct from, and not
substitutable by, ingress-tiering** the management API — they operate
at different layers against different threats (egress bounds where a
forged subscription can reach; ingress bounds who can call the
management API).

**Escape hatch:** `networkPolicy.enabled: false` disables the policy
entirely (documented, explicit operator choice — e.g. clusters with a
service-mesh `AuthorizationPolicy` or an external L3/L4 control already
governing the namespace). The default is on.

### `HORT_TOKEN_BIND` — P1, NOT YET IMPLEMENTED (design sketch)

> **Status: P1 defense-in-depth, not implemented.** This is a recorded
> design sketch, sequenced *alongside* (never before) the application-layer
> anti-replay and audience-binding hardening. It is documented here so
> the intended end-state is visible; **no `HORT_TOKEN_BIND` knob exists
> today.**

The sketch: split `build_router` so the token-generation routes
(`/api/v1/auth/exchange`, `/api/v1/auth`, OCI `/v2/auth`) can
*optionally* bind to a third listener, mirroring the
`build_admin_router` / `HORT_METRICS_BIND` (and now the
`HORT_CONTROL_BIND`) split exactly.

- **Default = unset = same listener as today** — zero behaviour change,
  no migration (identical contract to the shipped `HORT_CONTROL_BIND`).
- When set, the token-gen router is built with the *same* auth /
  tracing / rate-limit middleware stack (the real cost is the
  middleware duplication — accept it or factor a shared `tower` layer).
- Extend the existing config-layer "0.0.0.0 footgun" guard to the new
  socket so the split cannot become an unspecified-bind footgun (same
  mechanism the metrics and control listeners already use).
- Pairs with a chart value to expose the token-gen listener on its own
  Service/Ingress so operators can apply CI-source IP allowlists / mTLS
  / a dedicated rate-limit profile to it **without touching the
  artifact plane** (a mint flood then cannot starve artifact pulls;
  distinct audit/alert stream; bypass-resistant — direct-to-pod still
  hits a *separately governable* socket).

**What it buys and what it does not:** a configurable token-gen
listener narrows *who can reach* the token-gen plane and isolates its
DoS budget; it never changes *what a reachable caller does with a valid
credential*. Tier (ii) stays public by requirement; the application-layer
anti-replay and audience-binding controls stay load-bearing and are not
reordered or substituted by this sketch.

---

## 4. Defense-in-depth framing — NOT a substitute for authz

The control-plane listener (and the egress NetworkPolicy, and the
future `HORT_TOKEN_BIND`) are **defense-in-depth on top of — never
instead of**:

- the **admin-gate** (shipped) — privileged-category
  endpoints (admin API, privileged-category subscriptions) are
  authz-gated at the application layer regardless of which network
  tier the request arrives on; and
- the **webhook allowlist** (shipped) — the
  user-submittable webhook surface is application-side allowlisted
  regardless of egress policy.

**Network position is never a substitute for access control.** Under
NIS2 Art. 21 and the CRA, a single network-layer control is not
sufficient for the insider and egress threats it does not cover:

- The subscription-management API on an internal tier does **not**
  mitigate a forged-subscription SSRF from an *authenticated Hort user
  with subscription-create rights* (insider or stolen ordinary-user
  token) — that attacker is already inside whatever tier the API lives
  on, and subscription delivery is outbound by design. The enforcement
  point there is **authz** (admin-gate on privileged-category
  subscriptions) and **egress** (the default-on NetworkPolicy), not
  ingress placement.
- A reverse proxy / mesh `AuthorizationPolicy` is **required but
  insufficient as the sole boundary**: L7 path-routing is fully
  bypassed if anything reaches the pod `IP:port` directly (mesh peer,
  misroute, missing/misconfigured proxy). The separate-listener model
  is the better L3/L4 DiD primitive precisely because direct-to-pod
  traffic still hits a separately governable socket — but it, too, is
  one layer, not the whole defense.

If you remember one sentence: **the control tier raises the cost of
reaching the admin/subscription surface; it does not lower the bar of
proving you are allowed to use it. Keep both.**

---

## Cross-links

- [`security-hardening-checklist.md`](./security-hardening-checklist.md)
  — the per-control checklist (the metrics-listener split is the
  pattern this listener mirrors).
- [`values-reference.md`](./values-reference.md) — per-key values
  reference (`control.*`, `networkPolicy.*`, `service.controlPort`).
- [`../operate/claim-based-rbac.md`](../operate/claim-based-rbac.md)
  and [ADR 0012](../../../adr/0012-claim-based-rbac-claimless-static-tokens.md)
  — the admin-gate this tier is DiD on top of.
