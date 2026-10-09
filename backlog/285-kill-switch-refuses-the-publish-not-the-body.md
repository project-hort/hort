# 285 — The kill switch refuses the publish, not merely the body

**Issue:** #341 · **Branch:** `agent/341-audit-block-4`
**Governing decisions:** ADR 0015 (an operator-facing field is enforced by its
consumer or rejected) · the architect doc's anti-pattern *"409 for quarantined
artifact in proxy path — the proxy path must return 503 + Retry-After"*, which
is where this project's answer for "not serving right now" is recorded.

Item 284 gave the kill switch its reach: `HORT_PUBLISH_BODY_MAX_SIZE=0` now
closes all four hosted formats instead of two. This item gives it its meaning.

## What is true after item 284

Refusal happens **through the body limit**, so `DefaultBodyLimit::max(0)`
rejects a body that has bytes in it and admits one that does not. Measured
through the real router with the switch on:

| Format | empty body at limit `0` |
|---|---|
| Maven `.jar` PUT | **`201 Created`** — an empty artifact is ingested |
| Cargo | `400` — its publish envelope fails to parse |
| npm | `400` — the decoder finds no attachment |
| PyPI | `400` — multipart parse |

Only Maven's PUT has no envelope to fail, so the zero-byte case reaches
`ingest_direct`. The other three refuse as a side effect of their payload
grammar, which is a property of the grammar and not a guarantee the limit
gives — if any of those grammars ever admits an empty payload, that format
joins Maven silently.

**So the switch currently refuses every publish with a body.** That is not what
`values.yaml`, the configuration reference and the parser docstring say, and
item 284 rewrote all three to say "closes all four". An ingested zero-byte
artifact is not harmless bookkeeping either: it creates an artifact row, an
`ArtifactIngested` event, a quarantine timer and a scan job, so a gate the
operator believes is shut is still a free event-generation path.

**And the status code is wrong for the case.** `413 Payload Too Large` on a
0-byte request, or on any request while publishing is administratively off,
tells the client something untrue. Item 284 was told not to invent a rejection
path, and correctly did not; this item is where that is decided.

## The decisions, made here so the unit is not open-ended

1. **`503 Service Unavailable`** when the configured limit is `0`, for the
   *publish* methods only. It is this project's recorded answer for "not
   serving right now" (the quarantine path), and it reads as what it is: an
   administrative hold, not a client error and not an authorization failure.
   **No `Retry-After`** — the quarantine path carries one because it knows its
   deadline; this one does not, and a fabricated value would be a lie. State
   that in the response body's message instead.
2. **An over-size body with a non-zero limit stays `413`.** Unchanged, and the
   two cases must not be collapsed into one code path that answers the same
   way.
3. **A read path must keep working.** The guard discriminates by method, not by
   route tree: GET/HEAD are untouched while the switch is on. A hort that
   stops serving because publishing was disabled would be a far worse defect
   than the one being fixed.
4. **One definition, applied per subtree.** The rule lives once in
   `hort-http-core` (beside `cargo_publish_body_limit`, which is the precedent
   for "the shared answer lives where the shared constant lives") and each
   `*_routes_with_publish_limit` applies it. Four applications of one
   mechanism, not four mechanisms — if you find yourself writing the predicate
   twice, stop and restructure.

## What to do

1. Add the guard in `hort-http-core` and apply it in the four hosted-format
   route builders that already receive the limit.
2. **Answer the OCI question with evidence, and do not assume it.**
   `HORT_PUBLISH_BODY_MAX_SIZE` is documented as refusing *all publishes*; item
   284 scoped OCI out because its upload path has its own size handling, and
   the docs it rewrote therefore promise "all four". Establish which is true:
   - if the same guard covers the OCI push path (the blob-upload POST/PATCH/PUT
     dance and the manifest PUT), cover it and make the documentation say
     "every publish";
   - if covering it needs anything more than this guard, **stop and report
     that** with what it would take, and make the documentation state
     explicitly that OCI push is governed separately — naming what governs it.
   Either outcome is acceptable. Silence is not: an operator who reads "refuse
   all publishes" and keeps an open OCI push path is the exact defect family
   this block exists to close.
3. Update the four new `kill_switch_refuses_a_*_publish` tests to the new
   status, and add the empty-body case per format — that is the assertion this
   unit exists for.
4. Correct every operator-facing sentence item 284 touched that now says
   something narrower or wider than the truth: `values.yaml`,
   `values.schema.json`, the values reference, the configuration reference, the
   security explanation, and the parser docstring.

## Explicitly out of scope

- A cargo-specific size override (parked by a recorded decision).
- Changing the `413` for a genuine over-size body.
- Rate limiting, authorization, or any other reason a publish might be refused.
- Making the hold time-bounded (no `Retry-After`, no scheduled reopen).

## Behaviour changes to surface in the report

- **npm and PyPI's limit-`0` refusal moves from `413` to `503`.** It is the
  one pre-existing behaviour this unit changes. The old code was not a
  contract — it was the body limit answering a question it was not asked — but
  it is observable, so name it.
- A zero-byte publish is refused on every hosted format, where Maven ingested
  it.

## Acceptance

- Per hosted format, two tests at limit `0`: a non-empty body and an **empty**
  body, both `503`.
- A test that GET/HEAD still succeed while the switch is on.
- A test that a non-zero limit still yields `413` for an over-size body.
- The OCI question is answered in the report with file-and-line evidence, and
  the documentation matches whichever answer it is.
- No operator-facing sentence claims a reach the code does not have.
- The diff adds no uncovered lines.
- Gate green: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace` as one invocation
  with `DATABASE_URL` set and no source file touched between launch and
  completion, `cargo-audit audit -D warnings`, `cargo-deny check`.
