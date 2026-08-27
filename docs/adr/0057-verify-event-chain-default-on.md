# 0057 — Event-chain verification is default-on, and a missing anchor is not a failure where no anchor is expected

- **Status:** Accepted
- **Enforced by:** the single shared predicate
  `hort_app::event_chain_anchoring` — the checkpoint *writer*
  (`register_eventstore_checkpoint` in `hort-worker`) and the checkpoint
  *reader* (`hort-server verify-event-chain`) both derive their gate from
  it, and the exhaustive
  `reader_and_writer_derive_from_one_shared_predicate` matrix test goes
  red if either side grows a locally-restated condition; the
  `the_verify_path_never_reads_the_private_signing_key` source-scan test,
  which fails if the verify subcommand ever reaches for the anchor
  private key; `scheduledTasks.verifyEventChain.enabled: true` in
  `values.yaml`; the `result_label_set_is_closed_at_three_values` test,
  which pins the metric's `{ok, broken, missing_checkpoint}` catalogue
  against the fourth-series temptation that
  `scripts/check-g1-attestation-gate.sh` keys on.
- **Supersedes:** —
- **Relates:** [0002](0002-event-sourced-artifact-lifecycle.md) (the event
  chain and the externally-anchored checkpoint this verifies),
  [0015](0015-apply-time-linter-inert-fields-and-naming.md) (the
  inert-knob anti-pattern the rejected alternative would have been),
  [0016](0016-cross-opt-in-interaction-matrix.md) (checked below — not
  triggered), [0009](0009-least-privilege-runtime.md) (the least-privilege
  posture this extends from the DSN to the anchor key material).

## Context

The event-chain tamper-detection task shipped **disabled**. An operator
who did nothing got no integrity verification at all — and that is the
operator whose deployment most needs it. This was live: production ran
with `hort_event_chain_verify_overdue = 1`.

Making it default-on ran into one hard obstacle. A deployment with **no
checkpoint anchor** — a filesystem-backed install, where an S3
Object-Lock WORM anchor can never exist — produced
`ChainReport::MissingCheckpoint` on every run, which mapped to exit `3`.
Default-on would therefore have meant a CronJob that fails every single
night on installs that are configured exactly as intended. The verifier
would go from "nobody runs it" to "everybody ignores it", which is worse:
a red signal nobody reads is not a signal.

The chain check itself is exactly what those installs want. Only the
*anchor* half is inapplicable. The two were fused into one verdict.

## Decision

**Event-chain verification is default-on, and the missing-anchor
semantic is split at its source: a missing checkpoint is a failure only
where an anchor was expected.**

Concretely:

- `scheduledTasks.verifyEventChain.enabled` defaults to `true`. An
  existing install gains the CronJob on upgrade (it still sits under the
  `scheduledTasks.adminTasksEnabled` umbrella, and `enabled: false` opts
  out).
- Anchor-expectedness is a property of the **deployment**, resolved from
  configuration, not a property of a run.
- Where an anchor is **not** expected: the chain still runs, a real break
  still fails, and a missing checkpoint is exit `0` with a one-line
  `info!` — *"anchoring not configured; chain verified, no anchor
  expected"*.
- Where an anchor **is** expected: a missing/stale/gapped checkpoint is
  exit `3`, unchanged. A real chain break is exit `2`, unchanged.

### The shared, verifier-observable predicate

The condition is stated **once**, in `hort_app::event_chain_anchoring`:

```text
anchoring_configured == (storage backend is S3) && (anchor public key present)
```

- **Writer** (`hort-worker`): `should_register == anchoring_configured &&
  signing_key_present`. It needs the private key because it *writes*
  anchors, so that check is layered **on top** — never folded into the
  base.
- **Reader** (`hort-server verify-event-chain`): `anchor_expected ==
  anchoring_configured`. Nothing more.

Anchoring is a two-sided mechanism, and the two sides must never answer
"is anchoring configured here?" differently: a writer that anchors while
the reader expects nothing silently stops attesting; a reader that
expects an anchor no writer emits fails every run. So the shared base
predicate **is** the drift guard — rename or extend it and both sides
move together. Neither side may restate it locally, and an exhaustive
matrix test asserts exactly that relationship over every combination of
(backend, public key, signing key).

### The verify job never gets the private signing key

The base predicate is deliberately restricted to facts a **reader** can
observe. Checkpoint verification is a public-key operation; there is no
reason for a read-only auditor to hold the integrity system's private
key, and every reason not to — a verifier that could sign checkpoints
could fabricate the very attestation it exists to check. This extends
ADR 0009's least-privilege posture from the database DSN to the anchor
key material, and it is enforced by a source-scan test rather than by
convention.

**Consequence, and it is the correct one:** a half-configured deployment
(S3 + anchor public key present, signing key absent) reads as
anchor-*expected* on the verifier side and will flag. An operator who
provisioned an anchor public key and an S3 backend but no signing key has
a broken anchor setup, and that is worth alarming about. The alternative
— teaching the verifier to check for a private key it must not hold —
would trade a true alarm for a privilege it should never have.

### Metric semantics: the unanchored case maps to `ok`

`hort_event_chain_verify_total{result}` keeps its closed three-value
catalogue `{ok, broken, missing_checkpoint}`. A missing checkpoint where
no anchor is expected reports **`ok`**: the chain was verified and
nothing was missing that this deployment ever promised to produce.

No fourth `result` value. The cardinality is contractual — the catalogue
fixes it at ≤ 3 series and `scripts/check-g1-attestation-gate.sh` keys on
that exact `{metric, result-enum}` shape, so a fourth value would break
the G1 attestation gate. The anchored-vs-unanchored distinction is
carried instead by the **exit code**, the **log line**, and the
`anchor_expected` field of the subcommand's JSON output.

The label keys on the configuration-derived fact, never on the resolved
fail-on-missing decision. An operator who forces
`--fail-on-missing-checkpoint=false` on an anchored deployment suppresses
the exit code; the counter still records `missing_checkpoint`. The
compliance evidence must not be silenceable by a CLI flag.

### The tri-state CLI flag

`--fail-on-missing-checkpoint` becomes `Option<bool>`:

- **unset (default)** — *derive* from anchor-expectedness.
- **explicit `true` / `false`** — *force*, either way.

Forcing preserves the two real use cases the previous boolean served: a
compliance-critical CI job demanding a checkpoint regardless of what the
deployment's configuration says, and an operator spot-check ignoring one.
The forced value wins outright rather than being intersected with the
derived one — an operator who says "fail" means fail. The chart's
`failOnMissingCheckpoint` key mirrors the same tri-state, defaulting to
`null` (derive) rather than being removed, so operators who set it keep
their forcing surface.

## Posture statement

**An unanchored deployment is a supported posture, not a degraded one.**

Until now this lived only in scattered metrics-catalogue prose and chart
comments, and nothing governed it — which is precisely how the
default-disabled CronJob and the always-red unanchored run came to
coexist without anyone having to reconcile them. It is recorded here as a
decision:

- The per-stream hash chain is the integrity property. It is verified in
  full on every deployment, anchored or not, and a break is `broken`
  everywhere.
- The external anchor raises the bar against an attacker who can rewrite
  the database *and* recompute the chain. It requires S3 Object-Lock WORM
  retention (ADR 0002); a filesystem backend has nowhere to put an anchor
  that such an attacker could not also rewrite.
- A deployment that cannot host an anchor is therefore running the
  verification it is able to run, correctly. It must not be told
  otherwise every night.

## Rejected alternatives

**A `failOnMissingCheckpoint` chart key shipped `false` by default.**
This is the inert-knob anti-pattern (ADR 0015-adjacent) in its most
expensive form: it would silence the benign unanchored case *and* a real
integrity gap on any anchor provisioned later, and nothing would ever
flip it back. The knob would encode "I do not want to hear about
checkpoints" when the operator meant "I do not have checkpoints". Those
are different statements, and only one of them stays true after the
operator provisions an anchor bucket. The semantic is split at the source
instead, so a deployment that gains an anchor starts expecting one on the
next run with no config change.

**A fourth `result` label value (e.g. `unanchored`).** Rejected on the
cardinality contract above: `≤ 3` series is what the attestation gate
keys on. The distinction is real, so it is carried by the exit code, the
log line and the JSON output — surfaces with no cardinality contract.

**Teaching the verifier to check for the signing key** so the
half-configured case reads as unanchored. Rejected: it would put the
private key in the read-only auditor to *suppress* an alarm that is
correct.

## ADR 0016 check — not triggered

The cross-opt-in interaction matrix governs operator opt-ins that let
**untrusted input influence the release-gate computation**. This change
introduces no such opt-in and interacts with none:

- Nothing here touches the quarantine deadline, the release predicate, or
  what an index advertises. The verifier is a read-only auditor of the
  event log; it has no write path and no input to the release gate.
- Anchor-expectedness is derived from **operator configuration** (the
  storage backend and a provisioned key file), never from upstream- or
  caller-supplied data. There is no untrusted input in the predicate at
  all.
- The tri-state flag can only move this subcommand's own exit code. A
  forced `false` cannot release an artifact, shorten an observation
  window, or waive a release authority.

The interaction is therefore documented as **none**, explicitly rather
than by silence, and this change adds no row or column to the matrix.

## Consequences

- Deployments that upgrade get integrity verification without doing
  anything, which was the point.
- The `hort_event_chain_verify_overdue` gauge becomes meaningful by
  default rather than after an opt-in.
- An unanchored install's `hort_event_chain_verify_total{result="ok"}`
  attests chain verification but **not** external anchoring. The
  catalogue says so in prose; a compliance claim that needs the anchor
  half must read the deployment's configuration (or the run's
  `anchor_expected` output), not the counter alone.
- The half-configured (S3 + public key, no signing key) deployment now
  flags where it previously would not have been noticed. That is the
  intended behaviour, and it is the one case where this change makes a
  run *newly* red.
