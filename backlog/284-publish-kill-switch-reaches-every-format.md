# 284 — The documented publish kill switch reaches every hosted format

**Issue:** #341 · **Branch:** `agent/341-audit-block-4`
**Governing decisions:** ADR 0015 (an operator-facing field must be enforced
by its consumer or rejected — "accepted now, enforced later" is the prohibited
posture) · the recorded decision in `hort_http_core::limits` that Cargo's
ceiling is deliberately *not* driven by the shared override (preserved here,
see below).

## What is true today

`HORT_PUBLISH_BODY_MAX_SIZE` parses through
`config::parse_publish_body_limit_bytes`, which — unlike every other
`Option<_>` parser in that file — **deliberately does not reject zero**. Its
docstring says why:

> a zero publish-body-limit is an explicit "refuse all publishes"
> kill-switch, handled downstream — so an explicit `"0"` resolves to
> `Some(0)`, distinct from the unset `None`.

A test pins it (`publish_body_limit_bytes_explicit_zero_is_kill_switch`), and
`deploy/helm/hort-server/values.yaml` repeats the promise to operators.

**"Downstream" is two of four hosted formats.** In
`crates/hort-server/src/http.rs` the effective value is computed once and
handed to npm and PyPI only:

    let publish_limit = ctx.publish_body_limit_bytes
        .unwrap_or(hort_http_core::limits::DEFAULT_PUBLISH_BODY_LIMIT);
    …
    .nest("/cargo", hort_http_cargo::cargo_routes())          // no limit argument
    .nest("/npm",   hort_http_npm::npm_routes_with_publish_limit(publish_limit))
    .nest("/pypi",  hort_http_pypi::pypi_routes_with_publish_limit(publish_limit))
    .nest("/maven", hort_http_maven::maven_routes());          // no limit argument

- **Cargo** applies its own fixed `CARGO_PUBLISH_BODY_LIMIT` (200 MiB).
- **Maven** hard-codes `DefaultBodyLimit::max(DEFAULT_PUBLISH_BODY_LIMIT)` on
  its PUT — it uses the shared *default constant* but never the configured
  value.

The router comment states the Cargo half plainly, which is what makes this the
lens this block is about: the knowledge is present, accurate and local, and it
never reached the document the operator reads. An operator who sets `0` during
an incident gets npm and PyPI closed, Cargo and Maven open, and nothing says
so. **A kill switch that cannot be trusted is worse than none**, because it
changes what the operator does next — they stop looking for another way to
halt writes.

## The one decision this item must respect, not overturn

`CARGO_PUBLISH_BODY_LIMIT`'s own docstring records a deliberate choice:

> Not driven by `HORT_PUBLISH_BODY_MAX_SIZE` — that override ties to the
> shared 300 MiB default and changing cargo's ceiling silently alongside
> npm/PyPI would surprise operators who tuned the shared variable for Python
> wheels. A future item can introduce a cargo-specific override if
> operational data calls for one.

That reasoning is about **magnitude**, and it holds. It does not reach zero:
`0` is not a different ceiling, it is "refuse all publishes", and no operator
tuning a wheel size wants Cargo publishing left open during an incident.

**So the correction splits the two meanings, and only the second changes:**

| `HORT_PUBLISH_BODY_MAX_SIZE` | npm / PyPI | Maven | Cargo |
|---|---|---|---|
| unset | 300 MiB (shared default) | 300 MiB — unchanged | 200 MiB — unchanged |
| a size, e.g. `1Gi` | that size | **that size** (today: ignored) | 200 MiB — **unchanged, per the recorded decision** |
| `0` | refuse | **refuse** (today: open) | **refuse** (today: open) |

Maven gets the full override because it has no recorded reason not to and
already reaches for the shared default. Cargo gets only the kill switch.

## What to do

1. **Thread the effective limit into both route builders**, mirroring the
   npm/PyPI shape exactly (`*_routes_with_publish_limit(limit)` plus a
   `*_routes()` wrapper that passes the format's own default, so existing
   callers and tests are unaffected). Read `npm_routes_with_publish_limit`
   first — it also carries the limit as a router-scoped `Extension` for the
   handler, because `DefaultBodyLimit` does not apply to a streaming
   extractor. Establish per format whether the handler needs the same, rather
   than assuming the layer is enough.
2. **Cargo takes the kill switch only:** `0` → refuse; any other value →
   `CARGO_PUBLISH_BODY_LIMIT` unchanged. Put that rule in one place, not at
   the call site and in the crate.
3. **Refuse the same way the working formats already do** — through the body
   limit, so all four behave identically. Do **not** invent a new status code
   or a new rejection path; whether `413` is the ideal answer for "publishing
   is disabled" is a separate question and not this item's.
4. **Correct the two comments that will otherwise go stale**: the router
   comment in `http.rs` that says Cargo is "not threaded through the env
   override", and `CARGO_PUBLISH_BODY_LIMIT`'s docstring, which must now state
   the kill-switch exception to its own rule. State the invariant, no issue or
   backlog reference (CLAUDE.md → *Code comments*).
5. **Check `values.yaml` and the config docstring say what is now true** for
   all four formats, and fix them if not.

## Explicitly out of scope

- A cargo-specific size override. The recorded decision parks it until
  operational data calls for one, and this item does not supply that data.
- Changing the rejection status code for an over-limit or disabled publish.
- The OCI publish path. It is not one of the four hosted-format routers and
  has its own upload-size handling.
- Any other `HORT_*` limit.

## Acceptance

- One test per hosted format proving `0` refuses a publish — four tests, one
  shape.
- A test proving a non-zero override reaches Maven, and a test proving it does
  **not** change Cargo's ceiling (the recorded decision, now pinned rather
  than merely commented).
- A test proving the unset case leaves all four at today's values.
- No comment claims Cargo is unreachable from the override without naming the
  kill-switch exception.
- The diff adds no uncovered lines: for every line the diff adds, the
  `--show-missing-lines` output for the touched crates does not list it.
- Gate green, one-shot capture, exit codes separate from the output.

## This unit makes the issue's MR E2E-gated

It changes the composition of the publish path, so the whole of #341 is handed
to the human as a **branch** for his compose E2E before any MR is opened
(`scripts/native-tests/run.sh --hort=compose` covers cargo, npm, PyPI and
Maven publish). Nothing about that is this unit's work — it is why the unit is
flagged.
