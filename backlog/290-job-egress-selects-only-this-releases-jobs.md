# 290 — The chart's Job egress exception selects only this release's Jobs

**Issue:** #341 · **Branch:** `agent/341-audit-block-4`
**Governing decisions:** the chart's own documented Job-only carve-out and its
default-on isolation posture (`values.yaml`'s `networkPolicy` block) — the
contract this finding contradicts. ADR 0052's worker-metrics ingress posture is
separate and stays untouched.

The last of the seven findings in this block.

## What is true today

`deploy/helm/hort-server/templates/networkpolicy-migrate-job.yaml` grants an
unrestricted-egress NetworkPolicy (`egress: - {}` — every destination, every
port) to a pod selector that tests **only whether a label key exists**:

    podSelector:
      matchExpressions:
        - key: hort-server.io/job
          operator: Exists

Its own comment three lines above says it "Selects exactly the Job/CronJob pods",
and `values.yaml` repeats the Job-only claim to the operator. Neither is true:
the selector carries **none** of the chart's name/instance labels, so any pod
in the namespace that sets `hort-server.io/job` to anything at all is selected.

A principal who may create a Pod with labels of their choosing in that
namespace — and may *not* touch NetworkPolicies — therefore takes the
unrestricted egress rule by writing one label. In a namespace with a
deny-egress policy that reaches destinations the namespace meant to block. The
same label patched onto an existing restricted pod has the same effect.

Two things make this the block's lens rather than a plain bug:

- **The template already knows the rule that defeats the advice it gives.**
  Lines 6-22 explain that NetworkPolicy allowances are **additive**; lines
  48-50 and 110-118 then advise the operator that they can "layer a tighter
  Job policy" over this one. They cannot: a second policy cannot subtract an
  allow rule. The correct half and the false half are twenty lines apart in one
  file.
- **The render test asserts the shape that hides it.**
  `scripts/test-helm-templates.sh:107-109` checks only that the label *key*
  appears in the rendered policy, so it passes whatever the selector's scope
  is.

## What to do

1. **Make the selector release-scoped.** Add `matchLabels` with
   `hort-server.selectorLabels` beside the existing `matchExpressions`; a
   `podSelector`'s two clauses AND together, so the result is "this release's
   pods **and** carrying an `hort-server.io/job` key". Measured as sound before
   writing this item: `hort-server.selectorLabels` is
   `app.kubernetes.io/name` + `app.kubernetes.io/instance: {{ .Release.Name }}`
   (`_helpers.tpl:43-46`), and every Job/CronJob/DaemonSet pod template in the
   chart already includes it next to its own `hort-server.io/job` discriminator
   (`job-migrate.yaml:32-33` is the pattern). So no legitimate pod loses the
   allowance.
2. **Make the render test assert the scope**, not the key. It must fail if the
   name/instance labels are missing from the selector — that is the assertion
   whose absence let this ship. Follow the file's existing table-driven shape.
3. **Delete the false advice**, both places. Replace it with what is actually
   available to an operator who wants narrower Job egress: not another
   NetworkPolicy, but changing *this* rule — and say that the rule's scope is
   now the release, so it no longer leaks to unrelated pods.
4. **Correct the two claims that will otherwise stay wrong**: the template's
   "Selects exactly the Job/CronJob pods" comment, and `values.yaml`'s Job-only
   sentence. Each must say "this release's" rather than "the chart's", because
   two releases of this chart in one namespace is exactly the case the old
   wording got wrong.

## Explicitly out of scope

- **Whether the Job egress should be narrowed beyond release scope at all.**
  The unrestricted allowance exists for the pre-install migrate/bootstrap Jobs,
  which must reach Postgres and the kube-apiserver before the app exists. The
  finding's own report raises narrowing as a **decision** the chart owner has
  to take; this unit closes the label-capture hole and does not take it. If you
  find yourself writing an `ipBlock` or a port list, stop — that is the
  decision, not this unit.
- ADR 0052's worker-metrics ingress posture.
- The `networkPolicy.enabled` default, and the app-pod policy in
  `networkpolicy.yaml` (deliberately byte-identical, per its own comment).

## Acceptance

- `helm template` output shows the selector carrying both the name/instance
  labels and the `Exists` expression.
- The render test fails when the name/instance labels are removed from the
  selector — **demonstrate that, do not assert it**, the same way the guard in
  the previous unit was shown red.
- A rendered-output check that the migrate Job's own pod labels still satisfy
  the tightened selector, so the carve-out it exists for still applies.
- No sentence in the template or in `values.yaml` still claims a scope the
  selector does not have, and no sentence advises layering a tighter policy.
- Gate: this diff touches no `crates/`, no `Cargo.*` and no `migrations/`, so
  the gate economy applies — **`scripts/test-helm-templates.sh`, a
  `helm template` render of the chart, and `cargo audit` + `cargo deny`
  unconditionally**. Do **not** run `cargo test --workspace`; say in the report
  that you skipped it and why.
