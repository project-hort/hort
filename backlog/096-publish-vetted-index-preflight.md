# 096 — hort-publish: vetted-index preflight + release choreography

**Issue:** #137 · **Branch:** `agent/137-publish-index-preflight` · **Scope:** `.github/workflows/release.yml` + `RELEASING.md`

## Problem

`hort-publish` resolves the whole workspace graph through `cargo-virtual`
(`[source.crates-io] replace-with = "hort"`, written by `hort-auth`).
`cargo-virtual` is `released_only`, so the served index omits every version
that hort has never ingested or that is still inside its quarantine window
(`NonServableStatusFilter` + `IndexModeFilter`, `hort-http-cargo/src/serve.rs`).
A locked dep in that state reads to cargo as "version does not exist":

```
error: failed to select a version for the requirement `lru = "^0.18"` (locked to 0.18.2)
candidate versions found which didn't match: 0.18.1, 0.18.0, 0.17.0
```

Discovery is **serial** — cargo fails at the first miss, so each release
attempt surfaces exactly one cold dep and each retry costs a full quarantine
window. `prefetch-warm.yml` already batches the warm; nothing checks that it
actually completed before the publish runs.

## Change

### 1. Preflight step in `hort-publish` (`release.yml`)

Insert between the `hort-auth` step and the publish step. Give the `hort-auth`
step an `id` so its `token` output is reachable.

- **Locked set** — parse `Cargo.lock` DIRECTLY (awk over `[[package]]` blocks,
  keep entries whose `source` starts with `registry+`, emit `name version`).
  Do NOT use `cargo metadata` here: source replacement is already active in
  this job, so `cargo metadata` would hit the very index being tested and fail
  with the same one-miss-at-a-time error the preflight exists to replace.
  (`prefetch-warm.yml` may keep `cargo metadata` — it runs without replacement.)
- **Index membership** — for each DISTINCT crate name, one GET against
  `${HORT_URL}/cargo/${CARGO_SOURCE_REPO}/{prefix}/{name}` with the hort bearer,
  collecting served `.vers` values; a locked `(name, version)` whose version is
  absent from that crate's served set is COLD. Cargo sparse-index prefix rule
  (lowercased name): 1 char → `1/{n}`, 2 → `2/{n}`, 3 → `3/{n[0]}/{n}`,
  else → `{n[0:2]}/{n[2:4]}/{n}`. Parallelize with `xargs -P8`; a non-200
  counts as COLD (fail closed).
- **On any cold dep**: POST the full locked set to
  `${HORT_URL}/api/v1/repositories/${CARGO_SOURCE_REPO}/prefetch` (same shape
  as `prefetch-warm.yml` — idempotent, starts EVERY window in parallel), then
  emit one `::error::` listing every cold `name version` and exit 1 **before
  any publish**. The message must state that the warm was started and that a
  re-run is due after the crates-proxy quarantine window (24h, or 3d once
  #126's playbook run is applied).
- **On no cold deps**: log the checked count and fall through to publishing.

### 2. `RELEASING.md` choreography

Add the release-ceremony step that today exists only as a workflow comment:
the github-public sync of `develop` (or a manual `prefetch-warm`
`workflow_dispatch`) must precede the tag push by at least one crates-proxy
quarantine window; otherwise `hort-publish` fails on cold deps. Name the
preflight as the guard that reports the whole cold set at once.

## Acceptance

- The preflight's shell parses clean (`bash -n` on the extracted `run:` block)
  and the YAML parses.
- Self-test evidence in the report, run in the sandbox against the repo's real
  files: the `Cargo.lock` parser emits a plausible count of `name version`
  pairs (hundreds, and `lru 0.18.2` is among them), and the prefix function
  maps `a`/`ab`/`abc`/`serde` to `1/a`, `2/ab`, `3/a/abc`, `se/rd/serde`.
- No crates/ change ⇒ no cargo gates.

## Out of scope

Shortening the crates-proxy quarantine window (ADR 0007 observation window,
deliberately raised in #126) and changing whether the release dogfoods the
vetted index (issue #80's deliberate design).
