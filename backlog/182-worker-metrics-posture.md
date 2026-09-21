# 182 — accept the metrics asymmetry, and close the one hole that is real

**Issue:** #118 · **Branch:** `agent/118-worker-metrics-posture` · single item.

## Decision being implemented

`hort-worker`'s opt-in `GET /metrics` has no per-request auth, while
`hort-server`'s is `ReadMetrics`-grant-gated (ADR 0052). That asymmetry is
**accepted**. Giving the worker an inbound-auth stack was considered and
**rejected** — not deferred.

Do not implement worker authz. Do not add an `AppContext`, a token
validator, or an `RbacEvaluator` to `hort-worker`. The worker is
deliberately not an HTTP edge — its Deployment declares no HTTP ports and no
readiness probe — and that property is load-bearing for its deployment
shape.

## What this item delivers

### 1. An open-items-register row in ADR 0000, carrying the *reasoning*

Record the metrics-surface asymmetry with the argument, not just the
disposition. A future reader must find why it was accepted, or they will
re-open it as an oversight. The argument has two halves:

- Gating one metrics route means giving the worker token validation, an
  `AppContext` equivalent and an `RbacEvaluator` wired for HTTP — a large
  new attack surface in a component that has none, introduced to protect a
  reconnaissance endpoint (repository names and traffic shape; no
  credentials, no artifact content). More auth code is not automatically
  more security.
- **ADR 0052's rejection of network-position control was cost-scoped.** It
  rejected network-only for the *server's* exposition, where the auth edge
  already existed and a grant gate was therefore nearly free. Applying that
  conclusion where the alternative is building an entire auth edge inverts
  its own logic. State this explicitly — it is the part that makes the
  asymmetry look like a self-inflicted contradiction when read carelessly.

Also record what actually protects the listener today, because the as-built
posture is four controls and is routinely described as one: the listener is
off by default; `networkPolicy.enabled` defaults to true and its
component-agnostic `podSelector` also selects worker pods, so worker ingress
is deny-all by default; the scrape allowance renders only when both knobs
are on; and the scrape source is fail-closed when empty.

### 2. ADR 0052's scope-boundary bullet points at that row

So the asymmetry is discoverable from either document rather than only from
whichever one the reader happens to open.

### 3. The chart refuses the one combination nothing currently rejects

`networkPolicy.enabled: false` is a documented escape hatch. Combined with
`worker.metrics.enabled: true` it yields an unauthenticated listener with no
policy at all — the coupling that `worker-networkpolicy.yaml` describes as
"ONE structural action" silently degrades to nothing.

Make the chart `fail` on exactly that pairing, with a message naming both
values and saying what the combination would produce. Everything else stays
renderable: both off, listener off with policy on, listener on with policy
on.

Add a fixture and an expectation row to `scripts/test-helm-templates.sh`
covering the rejection and at least one permitted combination, following the
`<fixture>|<pattern>|<count>|<label>` format its header documents.

## Read first

- `docs/adr/0052-*.md` — the scope-boundary consequence naming the asymmetry.
- `docs/adr/0000-historical-decisions-index.md` — the open-items register and
  the shape of its existing rows.
- `deploy/helm/hort-server/templates/worker-networkpolicy.yaml` — its header
  comment already states the coupling this item makes enforceable.
- `deploy/helm/hort-server/values.yaml` — `networkPolicy.enabled` and
  `worker.metrics.enabled` defaults.
- `scripts/test-helm-templates.sh` — the fixture/expectation contract.

## Acceptance

- `helm template` fails, naming both values, when `worker.metrics.enabled`
  is true and `networkPolicy.enabled` is false.
- Both-off, listener-off-policy-on, and listener-on-policy-on all still
  render.
- A fixture and expectation row cover the rejection and a permitted case.
- ADR 0000 carries the register row, with the cost argument and the
  four as-built controls.
- ADR 0052's scope-boundary bullet references it.
- No change to any `hort-worker` source file. `git diff --stat` shows no
  `.rs` at all.
