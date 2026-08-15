# 114 — Component-discriminated Deployment selectors (pre-1.0 breaking window)

Issue: #159. One reviewable unit: chart selector fix + sweep + tests +
migration documentation. No Rust change.

## Why

Both Deployments' `spec.selector.matchLabels` carry only
`app.kubernetes.io/name` + `instance` — each selector matches BOTH pod
sets. Observed: `kubectl exec deploy/hort-server-test` resolved to a worker
pod. Pod templates already carry `app.kubernetes.io/component`
(server/worker); Services already discriminate — only the selectors lag.
`matchLabels` is immutable post-create, so this is a near-free fix while
the only k8s install is staging, and a breaking migration-documented
release forever after (operator decision, 2026-08-15: do it before v1.0).

## Change (`deploy/helm/hort-server/`)

1. `templates/deployment.yaml`: selector gains
   `app.kubernetes.io/component: server` (identical to the pod-template
   label already rendered).
2. `templates/worker-deployment.yaml`: selector gains
   `app.kubernetes.io/component: worker` (ditto).
3. **Sweep** every other `matchLabels`/selector consumer in the chart
   (PDBs, NetworkPolicies, anything selecting pods) for the same
   ambiguity; fix identically where a selector could match both pod sets,
   and LIST the sweep's findings (including "checked, unaffected" entries)
   in the report — the sweep result is part of the deliverable.
4. helm-template assertions: both Deployments' rendered selectors include
   the component key (scoped single-template assertions, following the
   worker-mount pattern).
5. **Migration documentation** (values comment near the top of
   `values.yaml` or the chart README section the repo convention favors —
   pick the one place an upgrading operator actually reads): a selector
   change makes `helm upgrade` fail on existing releases; the documented
   path is deleting the two Deployment objects first
   (`kubectl delete deploy <fullname> <fullname>-worker`) then upgrading
   (brief downtime; pods are recreated), or `--cascade=orphan` +
   re-adoption for zero-downtime-sensitive installs. Flux installs:
   suspend → delete the two Deployments → resume. One-time, per install.

## Golden discipline

The bootstrap Job / RBAC goldens don't cover the Deployments, but run the
full helm suite; if any golden or fixture pins the old selector shape,
update it deliberately and say so.

## Out of scope

- Runtime/Rust changes; Service selectors (already correct).
- Automating the migration (the chart cannot delete Deployments for the
  operator; documentation is the deliverable).

## Acceptance

- Rendered: both selectors carry the component discriminator; pod-template
  labels unchanged.
- Full helm-template suite green (incl. new assertions); `helm lint` clean.
- Migration note present and names the exact commands.
- After the staging migration (operator-side), `kubectl exec
  deploy/hort-server-test -- ...` targets a server pod deterministically —
  verified in a later UAT round, not in this MR.
