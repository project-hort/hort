# 312 — The document whose checksum was just refuted does not stay the answer

**Issue:** #346 · **Branch:** `agent/346-pullthrough-weaker-than-its-proof`
**Governing decisions:** ADR 0006 (mandatory upstream verification — a format
that cannot verify cannot proxy), ADR 0007 (fail-closed), and the ephemeral
cache's own eviction contract.

**Independent of items 311 and 313.**

## What is true today

npm's pull-through verifies the artifact against the `dist.integrity` the
**packument** declared. When that comparison fails, the handler warns and
returns (`crates/hort-http-npm/src/upstream_pull.rs:505`–`:516`, the
`AppError::Domain(DomainError::Conflict(_))` arm) — and **leaves the packument
in the ephemeral cache**.

So the document that made a claim the bytes just refuted stays the answer for
the next reader, who resolves the same version to the same lying integrity and
fails the same way. The means to prevent it is already wired in the same file:
`ctx.ephemeral_evictable` (`:200`, `:926`, `:1474`, `:1643`).

The warn itself is correct and stays as it is: it carries `algorithm`,
`format`, `repository_id` and deliberately **no** `artifact_id`, because no
artifact row was minted (mint-after-verify).

## What to do

1. **Evict the metadata document that declared the refuted checksum** on the
   mismatch path, through the evictable the file already holds. The eviction is
   part of the refusal, not a cleanup afterwards: a cache entry whose claim has
   been disproved is not a cache entry.
2. **Say what the eviction is for** at the site: the next reader must re-fetch
   the packument rather than inherit a disproved one. A reader who then gets
   the same document from a still-lying upstream fails again — that is correct,
   and it is a different thing from failing against *our* stale copy.
3. **Check the sibling formats and report, do not sweep.** PyPI, Cargo and OCI
   reach the same mismatch class. State per format whether the refuted document
   survives the failure, with `file:line`. **Fix only npm here**; if another
   format has the same gap, it is a finding for the collector (#331) with its
   measurement, because each format's cache wiring differs and a blind sweep is
   how one of them gets it wrong.

## Explicitly out of scope

- Any change to the mismatch's wire answer, its typed error, or the
  `ChecksumMismatch` event.
- The warn's field set (deliberate, see above).
- A negative-cache or a quarantine of the upstream. One refusal is not a
  verdict about the origin.
- Fixing a sibling format found by task 3.

## Acceptance

- After a refused npm pull, the packument is **gone from the ephemeral cache** —
  asserted by driving the pull and then reading the cache, not by asserting the
  eviction call was made.
- The refusal's wire answer and typed error are byte-identical to today.
- **Non-vacuity: remove the eviction, show the test red, restore it.**
- The per-format census from task 3 is in the report.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p hort-http-npm -p hort-app` — judge by the
  output, not the rc, and quote the totals. Do **not** run
  `cargo test --workspace`, `cargo audit`, `cargo deny` or the attribution
  script; the architect runs the full gate before any MR.
