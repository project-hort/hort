# 355 — The rescan-drive warning prints its own field names where values belong

**Issue:** #331, entry **E97** · **Branch:** `agent/331-e97-rescan-warn-prose` · single item.

## Problem

`crates/hort-server/src/composition.rs:677-693` emits the boot WARN that #388
introduced so an operator learns what an undriven rescan cadence costs. The
fields are attached correctly:

```rust
shortest_interval_hours = cadence.interval_hours,
policy_name = %cadence.policy_name,
```

but the message is a plain string literal that contains those **field names as
prose**:

> "rescan cadence declared but never driven: ScanPolicy **policy_name**
> declares the shortest rescanIntervalHours on this deployment
> (**shortest_interval_hours** h), and no cron-rescan-tick has ever completed
> here — …"

`tracing` does not substitute field names into a message literal. Captured
verbatim from a running deployment on 2026-11-01, the line renders with the
words `policy_name` and `shortest_interval_hours` sitting where the values
belong, and the values arrive separately in the structured block:
`{"shortest_interval_hours": 24, "policy_name": "crates-scan", …}`.

No information is lost — an aggregator reads the fields. What is lost is the
sentence. This line has exactly one purpose: to be read by a human deciding
whether their configuration is what they intended. It currently reads like a
template nobody filled in, which makes a reader doubt the text instead of
their configuration.

## The correction — match the house style, do not interpolate

**The established shape is in the same release.** The sweep ERROR added by
#389 (`crates/hort-adapters-postgres/src/quarantine_release_candidates.rs:476-484`)
attaches `repository_id` and `quarantine_duration_secs` as fields and writes
the sentence generically — *"this repository's effective quarantine
duration…"*. It never names a field in prose, so the sentence is correct on
its own and the fields supply the specifics.

Reword the rescan WARN to that shape. Concretely: refer to the policy and the
interval by role rather than by field name — *"the ScanPolicy declaring the
shortest rescanIntervalHours on this deployment"* — and let `policy_name` and
`shortest_interval_hours` carry the values.

**Do not pull the values into the message with `{}` arguments.** It would work,
but it duplicates each value between the message and its own field, and the
codebase has already answered this question one file away. Mirroring a
convention the design named is the design's own answer, not a deviation.

Keep every other part of the message as it is: it names the chart value to set
(`scheduledTasks.cronRescanTick.enabled=true`) and the one-shot admin task,
and both are deliberate. `scheduledTasks.cronRescanTick.enabled` is a **chart
value**, not a tracing field — it must stay spelled out.

## Census — the same class, the same file

This is the second instance of the class in one release; the first was
`event_store.rs`, where a `message = msg` field collided with the literal's
own `message` field and the database's text fell out of the line (fixed in
`180c85a0`). So do not fix one line blindly:

Check the sibling boot signals in the same file for a message literal that
names one of its own fields — `emit_pat_over_http_signal` (`:285`),
`emit_staging_sweep_liveness_signal` (`:406`),
`emit_event_chain_verify_liveness_signal` (`:502`), and the three
`run_*_liveness_check` wrappers (`:1329`, `:1371`, `:1424`, including the two
query-failure WARNs at `:1440` and `:1463`).

**Report what you find; fix only what is the same defect** — a message naming
its own tracing field where a value belongs. A message that mentions an env
var, a chart value, a metric name or a task kind is **not** a hit: those are
operator surfaces and belong in the prose.

## Acceptance

- The rescan-drive WARN renders with no tracing field name standing where a
  value belongs, and still names the chart value and the admin task.
- `policy_name` and `shortest_interval_hours` remain attached as structured
  fields with their values.
- A test pins the rendered message, not just the fields. There is a working
  capturing-subscriber idiom to copy at
  `crates/hort-adapters-postgres/src/quarantine_release_candidates.rs:1450-1500`
  (`CapturedEvents`): a `tracing_subscriber::Layer` whose visitor stringifies
  each field as `name=value`, which captures the message too, since `tracing`
  records a message literal as a field named `message`. Assert that the
  rendered message contains neither the bare word `policy_name` nor
  `shortest_interval_hours`, and that both fields still carry their values.
- The existing gauge tests at `composition.rs:4329-4435` stay unmodified and
  green — this unit changes no verdict and no metric.
- The census above is reported, with a verdict per site.
- `CHANGELOG.md` gets **no** entry: the line is new in this unreleased cycle,
  so from a reader's point of view there is nothing to correct — the entry for
  #388 already describes the warning.
