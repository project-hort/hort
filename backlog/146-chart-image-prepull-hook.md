# 146 — Chart pre-upgrade image pre-pull: every node holds the new images before migrations run

Issue: #215 (the 0.11.0→0.12.1 self-lock incident; policy/guard/fence live
in #214 — this is the chart-layer complement).

The incident's image-pull failure was a **node-cache miss, not a registry
miss**: the pre-upgrade migration hook (`job-migrate.yaml`, weight -5) runs
the NEW image and pulled it successfully through the then-healthy old pod —
onto the hook job's node. The new server pod then needed the same image on a
*different* node, inside the degraded window. Front-loading the pulls closes
that gap for every topology, and for a self-hosting deployment specifically
it makes the fix-serving path node-local before the window can open. A
pre-pull failure stops the upgrade BEFORE the schema is touched — fail
before the point of no return.

**Governing decisions:** ADR 0030 as amended by #214/item 144 (this is the
deploy-layer complement the amendment's context names); NO interaction with
quarantine/release gates (deliberately — ADR 0016: no gate exemptions for
the self-publish repo).

## Confirmed design

1. **Pre-upgrade pre-pull hook at weight -10** (strictly before the migrate
   hook's -5): a short-lived hook workload that pulls the release's
   `hort-server` and `hort-worker` images on every node eligible to schedule
   them.
   - Implementation shape: a hook **DaemonSet is not hook-friendly** (Helm
     hooks want run-to-completion); use the established pattern of a hook
     Job per image whose pod spec forces the pull (init/main containers
     running the target images with a no-op command, e.g. the binary's
     `--version`), replicated across nodes via pod anti-affinity + parallel
     completions sized to the eligible node count — OR, if the chart cannot
     know the node count, a DaemonSet created by the hook Job with a bounded
     readiness wait. The implementer picks the mechanically simplest variant
     that (a) touches every eligible node, (b) completes deterministically,
     (c) fails the upgrade on pull failure. State the choice + why in the
     report.
   - Respect the chart's existing nodeSelector/tolerations/affinity values
     for the server/worker workloads — pre-pull exactly where the real pods
     can land.
2. **Default ON**, `prePull.enabled` value to disable (an operator with an
   external registry may not want the extra hook). Values documented in the
   chart docs alongside the migrate hook.
3. **`--version` as the no-op command** must exist on both binaries (it
   does — the deploy relies on it elsewhere); no new binary surface.
4. **hook-delete-policy** mirrors `job-migrate.yaml`
   (`before-hook-creation,hook-succeeded`) so failed pre-pulls stay
   inspectable.
5. No gate/quarantine interaction, no registry-side changes, no detection
   of self-hosting — this is unconditional chart behavior.

## Read first

- `deploy/helm/hort-server/templates/job-migrate.yaml` — hook annotations,
  weight, delete-policy, image wiring to mirror.
- `deploy/helm/hort-server/templates/networkpolicy-migrate-job.yaml` — if a
  NetworkPolicy gates hook pods, the pre-pull pods need the equivalent
  (they only pull; they may need NO egress at all once scheduled — verify).
- `deploy/helm/hort-server/values.yaml` — where `prePull.*` lands; existing
  nodeSelector/tolerations plumbing.
- `quality:helm-template-test` CI job + its test inputs — the chart-level
  test harness that must cover the new template.

## Acceptance

- `helm template` renders the hook at weight -10 with both images, wired to
  the same tag/digest values as the workloads; disabled cleanly via
  `prePull.enabled=false` (helm-template-test covers both).
- Hook failure blocks the upgrade before `job-migrate` runs (hook ordering
  asserted in the template test via weights; runtime behavior documented).
- Chart docs: what the hook does, why (node-local images before the schema
  moves), and the `prePull.enabled` switch.
- Comment discipline: YAML comments state invariants (why weight -10, why
  fail-closed), no issue refs.
