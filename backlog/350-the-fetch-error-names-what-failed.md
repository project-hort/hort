# 350 — A broken constituent fetch says what broke, and where

**Issue:** #388 · **Branch:** `agent/388-scan-obligation`
**Governing decisions:** ADR 0003 (CAS: the hash is computed on the stream) ·
ADR 0006 (mandatory upstream verification) · none governing diagnostics.

## What is true today

The only thing an operator sees when a layer fetch breaks mid-stream is:

```
layers[18] (sha256:…) was fetched but could not be written to storage:
storage read failed: upstream stream error: error decoding response body
```

Two defects in one sentence.

**The subject is wrong for the reported fault — but not for every fault that
arm sees.** The same `map_err` receives *every* `put` error, including genuine
filesystem create/write/sync failures
(`crates/hort-adapters-storage/src/filesystem.rs:232-264`) and object-store
multipart-init failures (`object_store_backend.rs:215-219`). So the correction
is to *distinguish*, never to relabel every `put` failure as upstream. That string is assembled in the **storage-write**
arm of `fetch_attempt`
(`crates/hort-app/src/use_cases/constituent_acquisition.rs:382-386`), but the
inner text is a *read* failure: `put` was consuming a `StreamReader` over the
upstream body (`:375-378`), the body ended, and the adapter reported "storage
read failed" with the upstream error underneath
(`crates/hort-adapters-upstream-http/src/lib.rs:2744`). Nothing failed on the
storage side, and the layer was **not** "fetched". The sentence sends an
operator to disk and node pressure — which is exactly the elimination work the
reporting operator did: 0 restarts, peak 428 MiB against a 2 GiB limit,
`MemoryPressure: False`, 111 GB free.

**Nothing records how far it got.** `do_fetch_blob`
(`crates/hort-adapters-upstream-http/src/lib.rs:2707-2749`) has the response
in hand — it already reads `docker-content-digest` and `Last-Modified` off the
headers — and carries none of the HTTP status, the declared `Content-Length`,
the bytes read before the error, or the elapsed time into the error or a log
line. So the three candidate causes (a short body, a non-2xx mid-redirect, a
reset connection) are indistinguishable from outside.

**Two retry budgets are reported as if they were one.** The message says
"could not be acquired in 2 attempts" inside a frame that says "attempt 1 of
5". Both are real and nested — `MAX_ATTEMPTS_PER_CONSTITUENT = 2`
(`constituent_acquisition.rs:112`) inside `ScanOrchestrationConfig::max_attempts`
— and nothing in the text says so.

## A third fault the same text cannot distinguish

The composite path runs every acquisition step under **one shared wall-clock
deadline** — `MAX_IMAGE_LAYOUT_DURATION = 300 s`
(`crates/hort-domain/src/oci.rs:812`) — applied as `tokio::time::timeout_at`
over the manifest read, the config phase, the config read and all layer
fetches together (`constituent_acquisition.rs:170-210,264`). Its expiry is
classified transient, so it spends the whole attempt budget.

When it fires, `CompositionSpan` words its own exhaustion and names the step
that was still running, so that case is already legible. What is **not**
legible is the pair: an operator reading `was fetched but could not be written
to storage` cannot tell a slow-but-progressing transfer that ran out of span
from a body that ended early, and the two call for opposite responses — raise
throughput or look at the upstream.

This unit therefore has to leave **three** faults distinguishable in the text:
an upstream read that failed, a storage write that failed, and a span that
ran out. Measured note for whoever implements it: the reported failures were
**not** span expiries — the operator received the inner stream error, which is
an alternative outcome to `Elapsed`, not the same one. The 300 s bound itself
is a separate concern (an image whose layers cannot reach CAS inside 300 s can
never compose) and is **not** this unit's to change.

## Why this is a defect

A diagnostic that names the wrong subsystem costs an operator the exact
investigation it should have saved them, and this one cost a measured
elimination pass over memory, disk and node pressure. The missing numbers are
the difference between a diagnosable failure and a guess: if the break lands
near a constant *time* it is a transfer timeout, near a constant *byte
offset* it is something else. Only the reader knows the count, so only the
reader can record it.

## The change

1. The storage-write arm distinguishes the two faults, or states a subject
   true for both ("could not be streamed into storage"). An upstream read
   failure must not read as a storage failure.
2. The body-read path carries, in the error and in one `warn!`: HTTP status,
   declared `Content-Length` when present, **bytes read before the error**,
   and elapsed time. The count comes from the read loop; plumb it rather than
   re-deriving it.
3. The nested budgets name themselves — the per-constituent attempt says it
   is per constituent.

## Acceptance

1. A body that ends early produces a message whose subject is the fetch, not
   storage, and carries status, declared length, bytes read and elapsed.
2. A genuine storage-write failure still reads as a storage failure. Both
   arms are distinguishable in a test.
3. The bytes-read figure is the count actually consumed, asserted against a
   fixture that truncates at a known offset.
4. A `Deterministic` fault is unchanged — it is not retried at either level
   and this unit does not make it retryable.
5. The outer scan attempt accounting is untouched (item 349 owns the row).
6. `hort-app` needs 100% for branches added there; the adapter needs ≥ 85%.

## Out of scope

- **Resumable fetch** (HTTP `Range` on retry). It is the only change that
  would make a ~900 MB layer survivable on a flaky link rather than merely
  diagnosable, and it is the one that would have served the reported images —
  but it is new functionality, not a correction, and it needs its own
  decision. Named here so the next sweep finds it rather than silence.
- Any change to the attempt budgets. Their sufficiency is a separate question
  and this unit only makes their reporting honest.
- The CDN-timeout hypothesis itself. This unit produces the evidence that
  would settle it; it does not presume the answer.

## What the independent review changed

`codex/gpt-6-sol` confirmed the misattribution for the reported nested error
and sharpened its scope: the arm is shared with genuine storage faults
(`filesystem.rs:232-264`, `object_store_backend.rs:215-219`), so "nothing
failed on the storage side" holds for *that* error, not for the arm. The
correction must preserve the distinction rather than invert it. Acceptance
criterion 2 already demanded that both arms stay distinguishable; it is now
the point of the unit rather than a side condition.
