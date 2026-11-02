# 361 — Existence is the first question of a pull-through fetch

**Issue:** #391 (follow-on) · **Branch:** `agent/391-existence-before-verification` · single item.

## Why

`!790` made the **answer** right: a Maven coordinate the upstream lacks now
answers 404 instead of 502, so a virtual repository walks to the next member.
It left the **cost** wrong, and the maintainer named why (2026-11-01): asking
for a checksum of something that may not exist answers a question nobody asked.

Measured shape today, for a member whose upstream lacks the coordinate:
`.sha512` 404 → `.sha256` 404 → `.sha1` 404 → the `!790` probe. **Four upstream
round trips to say "not here."** For a virtual repository with N members where
only the last holds the artifact, that is 4·(N−1) requests instead of (N−1) —
and for a virtual repository, members that lack a coordinate are the normal
case, not the exception.

"Does this exist?" is logically prior to "how do I verify it?". Put it first.

## The change

### 1. `UpstreamProxy` gains an existence check

`crates/hort-domain/src/ports/upstream_proxy.rs`. Non-generic, so the trait
stays dyn-compatible (ADR 0026), mirroring the shape of its siblings.

**It must return three states, not a bool.** The third is the whole reason this
is safe:

```rust
pub enum UpstreamExistence { Present, Absent, Unknown }
```

- **`Absent`** — the upstream said, cleanly, that it does not have this. Only a
  `404` (and `410`) earns it.
- **`Present`** — the upstream has it.
- **`Unknown`** — the upstream did not answer the question. **A `405 Method Not
  Allowed`, a `401`, a `403`, any `5xx`, a transport failure or a timeout is
  `Unknown`, never `Absent`.** Mapping any of those to `Absent` would invent a
  miss for an artifact that exists — the same defect as #391 with the sign
  flipped, and worse, because it would make hort deny content it holds a path
  to.

This enumeration is the heart of the unit. Write it as an exhaustive match with
no wildcard, so a future status has to state its answer.

### 2. The Maven pull asks it first

`crates/hort-http-maven/src/upstream_pull.rs`, before the sidecar leg:

- `Absent` → `NotFoundUpstream` → **404**, immediately, one round trip, no
  sidecar fetched;
- `Present` → today's flow unchanged: sidecars preferring strength, then the
  body, hashed in one pass;
- `Unknown` → today's flow unchanged **including `!790`'s
  `classify_sidecar_exhaustion`**, which stays exactly as it is and becomes the
  backstop for an upstream that will not answer HEAD.

**Do not delete the `!790` classifier.** It is what keeps the answer right when
the cheap question cannot be asked, and `SidecarsExhausted`'s missing `From`
impl is what stops a future `?` regressing it.

### 3. ADR 0006 is untouched

Verification still precedes any store. The digest is still known before the
body streams, so the read-and-hash-in-one-pass property is unchanged; this
only puts a cheap question in front of an unchanged sequence.

## Scope

**Maven only.** npm, PyPI and Cargo resolve a coordinate out of an upstream
*metadata document* (packument, JSON, sparse index) rather than a sidecar — a
404 on that document already **is** their miss signal, so they do not have this
shape. Do not touch them. If while reading you find one of them does have it,
report that; do not widen the diff.

## Not in scope

- No change to the virtual fall-through — a genuine 502 still aborts, for the
  reason in `backlog/360`.
- No change to `map_upstream_pull_error`.
- No ADR edit. ADR 0032 and ADR 0033's clauses (clarified in `!791`) stay
  correct: a 502 still means present-but-unverifiable. If you think the
  mechanism sentence in 0033 now reads oddly, say so in the report rather than
  editing it.

## Acceptance

- `Absent` short-circuits: a miss costs **one** upstream request. Assert the
  count, do not assert the status alone — the point of this unit is the cost,
  and a passing status test would hide a regression to four.
- `Present` costs exactly **one more** request than today's happy path, and the
  happy-path behaviour is otherwise byte-for-byte unchanged — prove it with the
  existing sidecar tests passing unmodified.
- `Unknown` reproduces today's behaviour end to end, including a 405 and a
  transport failure each yielding the pre-`!790`-era classification path and
  **not** a 404.
- A test pins that `405` does not map to `Absent`. That is the regression this
  unit could introduce, so it gets its own named test.
- Every `UpstreamProxy` implementation and test double compiles with the new
  method, and the mock can seed all three states.
- `CHANGELOG.md`: **no entry.** An operator observes nothing new — the answer
  was already corrected by `!790`; this changes only how many requests reaching
  it costs.
