# 399 — A failed hook keeps its log

**Issue:** #196 · **Branch:** `agent/196-a-failed-hook-keeps-its-log` · single
item. **Chart and docs only — no Rust.**

**Governing decisions:** ADR 0046 (`--require-authority`: the bootstrap hook
fails loudly so a missing service account or grant is diagnosable *at install
time*). The whole value of that decision is the message the init container
prints, and a five-minute retention window is what makes that message
frequently unreadable. Nothing governs hook-Job retention — but the chart's own
convention does, and it settles this.

## The property

**A failed bootstrap hook keeps its log until someone has had a chance to read
it, and a successful one is cleaned up at once.** Today it is the other way
round in both directions.

## The chart already answers this; one template diverges

`job-migrate.yaml` and `prepull-job.yaml` are both Helm hook Jobs. Both carry
`helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded` and **no**
`ttlSecondsAfterFinished`, and `prepull-job.yaml` states the reasoning in its
own docstring: *"failures stay visible, only success cleans up."*

`svc-token-bootstrap-job.yaml` carries `before-hook-creation` alone plus
`ttlSecondsAfterFinished: 300`. So:

| outcome | today | after |
|---|---|---|
| success | Job + pod linger 5 min, then TTL-deleted — with a Memory-medium volume that held a plaintext token | deleted by Helm the moment the hook succeeds |
| failure | Job + pod linger 5 min, then TTL-deleted | retained until the next install/upgrade reclaims it via `before-hook-creation` |

This is not an open design question. It is one template out of step with a
convention the chart documents two files over.

## Both halves are required

Change the annotation **and** remove the TTL. Leaving the TTL would let the TTL
controller delete a failed Job at 300 s whatever the delete policy says — which
is exactly today's behaviour. And **do not add `hook-failed`**: that restores
precisely the thing this item removes.

Retention stays bounded without a history limit: the Job name is fixed
(`<fullname>-svc-token-bootstrap`), so at most one exists at a time and the next
upgrade reclaims it.

## The security delta goes the right way

The init container writes a plaintext service-account token to a
`medium: Memory` emptyDir, so "retain the pod longer" deserves a second look
rather than a shrug. It improves the common path and is acceptable on the rare
one: **success — every routine upgrade — is cleaned up faster than today**,
immediately instead of after five minutes. Only the failure path is retained
longer, and a failed bootstrap is both rare and the one moment the evidence is
needed. That path's token is headed for revocation anyway: the documented
recovery for a mint-succeeded/write-failed run is `--rotate`, which revokes the
row and mints afresh.

One open factual question, worth a line in the template comment: does kubelet
reclaim a terminated pod's emptyDir before the pod object is deleted? It does
not change the decision either way. Answer it from the Kubernetes
documentation if you can reach it, and if you cannot, write that it is
unverified rather than asserting either answer.

## The documented diagnosis procedure is currently a race

`docs/architecture/how-to/deploy/enable-admin-task-cronjobs.md` §4.1 and §4.2
both tell the operator to run `kubectl logs job/<release>-svc-token-bootstrap
-c issue-token`. That is the documented procedure for both of ADR 0046's
failure modes, and the TTL makes it a race the operator usually loses. §4.1's
existing sentence about `before-hook-creation` stays true and gains the other
half: a failed Job and its log remain available until the retry, so the
procedure works whenever it is actually needed.

## Scope — four files

1. `deploy/helm/hort-server/templates/svc-token-bootstrap-job.yaml` — the
   annotation, the removed TTL and its comment, and the docstring's *Hook
   annotations* list, which enumerates the current policy. State the invariant
   there in terms of what it protects — a failed hook's log is the only record
   of ADR 0046's message — and that neither `hook-failed` nor a TTL comes back.
2. `deploy/helm/hort-server/testdata/svc-token-bootstrap-job.golden.yaml` — the
   same two lines. It pins both, so a stale golden blocks the MR at
   `quality:helm-template-test`.
3. `docs/architecture/how-to/deploy/enable-admin-task-cronjobs.md` — §4.1's
   retention sentence and the policy string it quotes.
4. `CHANGELOG.md` under `### Changed` — **one line**, about what an operator can
   now do (read a failed bootstrap's log after the fact). No mechanism, no
   before/after narration.

Nothing else. No other template, no values key, no Rust.

## Verification, and what you cannot run here

**`helm` is not in this sandbox** — `scripts/test-helm-templates.sh` exits 2
rather than failing. So the golden is **hand-edited** to match the template,
and the real comparison is CI's `quality:helm-template-test` on the MR.

Edit it with that in mind: the golden is a rendered manifest, so the two
changed lines must match the template's output character for character,
including indentation and the quoting style the renderer emits for the
annotation. Read both files side by side before you write, and say in the
report that the render comparison is CI's rather than claiming the golden
verified.

There is no Rust change here, so no workspace suite is owed for its own sake —
run `cargo test --workspace` **once** anyway, because the structural guards
scan the `deploy/` tree and a malformed YAML file fails there, which is the one
local signal available for this change.

## Acceptance

- The rendered bootstrap Job carries
  `helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded` and no
  `ttlSecondsAfterFinished`; the golden matches the template.
- `grep -rn ttlSecondsAfterFinished deploy/helm/` returns **nothing**.
- The three hook Jobs — migrate, prepull, bootstrap — now share one retention
  policy.
- The template comment states the invariant in terms of what it protects, not
  in terms of this change having been made.
- The how-to is accurate about what remains readable after a failure.
- One `CHANGELOG.md` line under `### Changed`.
- Gate green, workspace suite run **once**.
