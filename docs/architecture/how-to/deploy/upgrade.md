# Upgrade a running `hort-server` deployment

How to move an installed release forward safely, and what changes for the
minority of releases that carry a **Migration notice**.

This is the operator-facing half of [ADR
0030](../../../adr/0030-sensitive-surface-structural-guards.md)'s
expand/contract policy. The build-side half — a guard test that refuses to let
a destructive migration be authored too early — is what makes the routine path
below boring; this document exists for the two cases where boring is not
enough: a flagged release, and a deployment that mirrors its own images.

## 1. The routine upgrade

Every hort upgrade has a window in which the **new schema and the old binaries
coexist**. The chart runs migrations in a pre-upgrade hook, so the schema
changes *before* a single new pod is Ready; a rolling update then keeps old
pods serving until the new ones pass their probes. On a multi-replica install
that window is minutes.

Hort's schema change is **expand/contract**, which is what makes that window
safe:

- **Expand** — a release adds columns and tables, moves every reader onto
  them, and stops referencing the old ones. The previous release's binaries
  never name the new identifiers, and the old identifiers are still there for
  them. Nothing breaks.
- **Contract** — a *later* release removes the old identifier. By then no
  supported binary names it.

The two never share a release: the `expand_contract_guard` build gate fails if
a migration drops, renames or narrows an identifier the code stopped
referencing in the same cycle. So for a release with no Migration notice, the
upgrade is simply:

```bash
helm upgrade <release> hort/hort-server -f values.yaml --version <chart-version>
kubectl rollout status deploy/<release>-hort-server
```

Watch the migration Job before the rollout, as at install time:

```bash
kubectl get job <release>-hort-server-migrate \
  -o jsonpath='{.status.succeeded}'   # expected: 1
```

**Skipping releases is fine for the schema** — migrations are cumulative and
`sqlx` applies them in order — but it is *not* fine for a contraction. See §2:
the minimum tolerating version in a Migration notice is a floor on the version
you upgrade **from**, and skipping past a flagged release does not remove that
floor, it only means you meet several of them at once.

## 2. A release with a `### Migration notice`

A release whose migration set contains a contraction carries a
`### Migration notice` block at the top of its changelog entry, naming:

- the identifier being removed or narrowed, and the migration that does it;
- the **minimum tolerating binary version** — the first release whose code
  does not reference that identifier;
- what to do about it.

The failure this warns about is specific and worth understanding, because it
does not look like a normal upgrade problem. The moment the pre-upgrade
migration hook commits, **every still-running old pod starts erroring** on any
query naming the contracted identifier — before the new pods exist. The
deployment is not "degraded during rollout"; the *old* version is broken while
it is still the only version serving.

Check what you are upgrading from:

```bash
kubectl get deploy <release>-hort-server \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
```

- **Running version ≥ the minimum tolerating version** — the old pods do not
  name the contracted identifier, so the window is safe again. Upgrade
  normally.
- **Running version < the minimum tolerating version** — upgrade in **two
  steps**: first to any release at or above the floor, let it settle, then to
  the flagged release. This is always available and always the cheapest
  answer.
- **Cannot do a two-step upgrade** (or the errors during the rollout are
  themselves unacceptable) — take a **maintenance window**: scale the
  Deployment to zero, run the upgrade, scale back up. A contraction is
  forward-only; there is no schema rollback to fall back on, so the window is
  what buys certainty.

```bash
kubectl scale deploy/<release>-hort-server --replicas=0
helm upgrade <release> hort/hort-server -f values.yaml --version <chart-version>
kubectl scale deploy/<release>-hort-server --replicas=<n>
```

Because a flagged release is the expensive one, contractions are deliberately
**batched**: several in one release cost one window, spread over three
releases they cost three.

## 3. Self-hosting deployments have no safety net

A deployment that mirrors, through hort, the images hort itself is upgraded
from — the `registry.hort.rs` cold-start shape described in
[`self-contained-registry-install.md`](./self-contained-registry-install.md) —
has a failure mode ordinary deployments do not.

In that topology the old pod is doing two jobs at once: serving the API, and
**serving the image the new pod is about to pull**. An API-degrading window is
therefore self-pinning. The old pod errors, the new pod's image pull goes to
the same instance and fails, no new pod becomes Ready, and nothing in the
cluster can resolve it — the deployment cannot roll forward, and rolling the
chart back does not undo a forward-only migration. This is not theoretical:
it is exactly how a routine 0.11.0 → 0.12.0 upgrade turned into a ~22-minute
outage that had to be broken by hand.

The expand/contract guarantee is what makes this topology safe for ordinary
releases: if the old pod keeps working across the migration, it keeps serving
images, and the pull succeeds. For a **flagged** release, do not rely on it —
either meet the minimum tolerating version first (§2), or pre-stage the new
images somewhere that does not depend on the instance being upgraded (a second
registry, or `crictl pull` / a node-level preload on each node before the
upgrade) so the new pods can start even while the old ones are erroring.

## 4. Flux and automated remediation

If a `HelmRelease` manages the install, check its remediation settings before
a flagged release:

```bash
kubectl get helmrelease <name> -o jsonpath='{.spec.upgrade.remediation}'
```

Automated rollback against a forward-only contraction makes things **worse,
not better**. The chart rolls back to the previous version; the *schema* does
not roll back, because migrations are forward-only. The result is the previous
release's binaries running against a contracted schema — precisely the state
the Migration notice warns about — and Flux will keep retrying until it
exhausts its retry budget, pinning the outage for the duration.

For a flagged release, suspend remediation for the upgrade:

```bash
flux suspend helmrelease <name>
# perform the upgrade per §2 (two-step, or maintenance window)
flux resume helmrelease <name>
```

Alternatively set `spec.upgrade.remediation.retries: 0` and
`remediateLastFailure: false` on that `HelmRelease` for the duration. Either
way, the point is the same: a failed contraction upgrade needs a human
deciding what to do next, not an automatic retry loop that cannot reach a good
state.

Ordinary (unflagged) releases need none of this — leave remediation on.

## See also

- [`install.md`](./install.md) — first install: prerequisites, Postgres roles,
  Secrets, OIDC, `helm install`, post-install verification.
- [`self-contained-registry-install.md`](./self-contained-registry-install.md)
  — the cold-start topology §3 is about.
- [ADR 0030](../../../adr/0030-sensitive-surface-structural-guards.md) — the
  expand/contract policy, the guard that enforces it, and what the guard
  cannot see.
- [ADR 0048](../../../adr/0048-release-branch-staging-strategy.md) — the
  release model whose boundaries the policy counts in.
- `RELEASING.md` — where a Migration notice comes from, on the release side.
