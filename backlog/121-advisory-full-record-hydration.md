# 121 — Hydrate full OSV records in the advisory enrichment path

Issue: #172. Single unit; unblocks the crates publish (#147/#148) and
restores the CVSS-vector scoring to effect.

## The defect in one line

The pre-scan advisory enrichment queries OSV `/v1/querybatch`, which
returns **only** `id` and `modified` — never a `severity` array — so every
enrichment finding falls through to the SUP-4 fail-closed `Critical` with a
NULL score, and then outranks the scanner's correctly-scored finding in the
dedup merge.

Verified against the live API:

```
POST https://api.osv.dev/v1/querybatch
{"results":[{"vulns":[{"id":"RUSTSEC-2023-0071","modified":"2026-04-25T06:45:06.122559Z"}]}]}
```

`GET https://api.osv.dev/v1/vulns/RUSTSEC-2023-0071` **does** carry it:

```
"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}]
```

## What

In `hort-adapters-advisory-osv`, hydrate each advisory id returned by
`querybatch` with its full record before deriving severity, so
`cvss_vector_base_score` receives the vector it was written for.

1. **The fetch.** After `querybatch` yields ids, fetch each distinct id's
   full record. Reuse the existing HTTP client construction — the
   `reqwest::Client::builder()` rule (ADR 0010) applies, and the endpoint
   base must be configurable alongside `advisory_osv_url` /
   `advisory_osv_bulk_url` rather than hardcoded.
2. **Cache it.** The adapter already holds an evictable cache keyed for
   querybatch inputs. Hydrated records are keyed by `(id, modified)` —
   `modified` is exactly the invalidation signal `querybatch` returns, so a
   record is re-fetched only when OSV actually changed it. Do not key by
   `id` alone.
3. **Fail soft, fail closed.** A hydration failure (network, 404,
   malformed) must not fail the scan: fall back to today's behaviour for
   that id — unscored, hence `Critical` — and emit a counter so the
   degradation is visible rather than silent. The enrichment is already
   best-effort (`advisory query failed; proceeding with empty enrichment`);
   stay consistent with that.
4. **Bound the work.** One request per *distinct* id per scan, deduplicated
   across components. A scan matching N advisories must issue at most N
   hydration requests, not one per (component, advisory) pair.

## What NOT to do

- Do **not** change `prefer_replacement` in this unit. Making a scored
  finding outrank an unscored one across severity tiers is the right
  hardening, but it touches the ADR 0007 fail-closed rule and needs its own
  design pass — tracked separately on #172. This unit removes the bad
  input; that one would remove the bad rule.
- Do **not** weaken the SUP-4 fail-closed default. A genuinely unscored
  advisory must still land on `Critical`. The fix is to stop *manufacturing*
  unscored findings from a source that had the score all along.
- Do **not** touch the bulk/watch-tick path (`bulk.rs`). It models a
  different wire shape for a different purpose and is not implicated.

## Tests

- **The regression that would have caught this**: a fixture built from a
  *real* `querybatch` response — `id` + `modified` only, no `severity` —
  driven through the enrichment, asserting the hydrated record supplies the
  score. The existing unit tests pass today only because they construct a
  vuln with a populated `severity` array, a shape the endpoint never
  returns. Assert that shape explicitly so it cannot regress into a
  fixture that flatters the code.
- End-to-end through the derivation for RUSTSEC-2023-0071: hydrated →
  `cvss_score = 5.9` → `Medium`, not `Critical`.
- Hydration failure → unscored → `Critical`, and the counter fires.
- Cache: same `(id, modified)` hits the cache; a changed `modified`
  re-fetches.
- One request per distinct id when several components share an advisory.

## Done when

A rescan of an artifact whose only advisory is vector-scored records the
scored severity, and a policy whose `severityThreshold` sits above that
score no longer rejects it.
