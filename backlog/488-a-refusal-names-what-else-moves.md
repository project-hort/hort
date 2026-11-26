# 488 — the chart's two new refusals name what else moves, not only what to set

**Issue:** #462 · **Branch:** `agent/462-refusals-name-what-moves`.
**Found in production use**, within hours of units 483/484 shipping: a live
staging install stopped taking the release, and the refusal told the operator
exactly one of the two things they needed.

## What happened

`0.18.1-alpha.5` would not render on an installation with the TLS sidecar
enabled and `metrics.bindAddr: "0.0.0.0:9090"`:

```
execution error at (deployment.yaml:25:4): metrics.bindAddr must equal
127.0.0.1:<service.metricsPort> when tlsSidecar.enabled so the admin
listener has no reachable plaintext bypass
```

**The refusal is correct and stays.** With the sidecar enabled a non-loopback
plaintext metrics bind cannot serve any working scrape — there is no anonymous
`/metrics` (ADR 0052) and a credentialed scrape over a plaintext hop is refused
`426`, measured against a running installation. The port offers surface and
nothing else.

**What the message does not say is that fixing it moves their scrape.** When the
sidecar is enabled the Service's `metrics` port targets `metrics-https`
(`templates/service.yaml`), so after the operator sets the loopback bind, a
scraper of that port needs `https`, the CA and a bearer carrying `read_metrics`.
An operator who follows the message literally fixes the render and may silently
lose metrics collection in the same step.

**A render-time `fail` is the operator's documentation at the moment they meet
it.** They are not reading `values.yaml` prose then; they are reading one line
in a Flux condition. So the line has to carry the consequence, not only the
requirement.

The same gap exists in the sibling refusal: `metrics.serviceMonitor.enabled=true
requires caSecretName, caSecretKey, serverName, bearerSecretName and
bearerSecretKey` lists five fields and never says why — that the scrape is now
HTTPS against the sidecar. That one is the path a **pinned production** install
meets at its next bump, so it matters at least as much.

## What to do

1. Both refusal messages state the consequence as well as the requirement: that
   with the sidecar enabled the Service's metrics port serves TLS, so the
   scraper needs `https`, a CA and a `read_metrics` bearer.
2. Keep them **one line each and readable in a Flux condition**. A `fail`
   message is not a document; if the full migration needs more words, the extra
   words go in the values reference and the message points there by path.
3. The values reference (`docs/architecture/how-to/deploy/values-reference.md`,
   and the chart reference if it carries the metrics block) gains a short
   migration note: enabling the sidecar on an install whose metrics bind was
   non-loopback is a two-part change, and both parts belong in one edit.
4. `values.yaml`'s comment on `metrics.bindAddr` and on
   `metrics.allowUnspecifiedBind` says that with the sidecar enabled the bind
   must be loopback and that `allowUnspecifiedBind` does not exempt it — the
   operator who hit this had set that flag precisely expecting it would.

## Acceptance

- Both messages name the consequence, and a render test asserts the text of
  each — so a later edit that drops the consequence fails rather than passing
  quietly.
- Each message still fits one readable line in a condition; judged by reading
  it, and the report quotes both verbatim.
- The negative render matrix from unit 484 still fails for the same inputs, and
  the positive render still succeeds. No refusal is relaxed, removed or made
  conditional — this unit changes words, not behaviour.
- `values.yaml` states the `allowUnspecifiedBind` non-exemption where the flag
  is defined.

## Not in scope

Relaxing either refusal, adding an opt-out, or changing when they fire. The
behaviour is right; only what it tells the reader is short. Also not here: the
certificate-rotation or metrics-listener mechanics themselves (units 483, 484,
already merged).
