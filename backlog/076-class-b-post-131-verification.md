# 076 — #130 class B: verify the proxy-503 failures are downstream of the #131 flood (verification-first)

**Issue:** #130 (remaining scope after classes A — fixed, !348 — and C — split to #131).

## Analysis (architect, evidence-based — see #131 for the flood mechanism)

The two failing scenarios (`quarantine/proxy-multiarch-zero-window`,
`quarantine/proxy-required-multilayer`) run AFTER `quarantine/provenance-push-then-sign`
in suite order — i.e. after the never-signed index has started #131's self-sustaining
priority-10 flood. Their step-1 cold pulls need fast-path release decisions driven by
**priority-0** ingest-time jobs (verifies for the `Required` repo — confirmed prio 0;
scans likewise `priority: 0`, `ingest_use_case.rs:2979`), exactly the tier #131's flood
starves. A starved decision job leaves the artifact held → `GET` → **503**. Consistency
checks: `proxy/oci-mirror` (runs BEFORE the flood starts) pulled from both docker.io and
ghcr successfully in the same run — so upstream egress/rate-limiting is ruled out; 503
is hort's own hold response.

Open uncertainty, deliberately not hand-waved: `kind='scan'` may be claimed by its own
`claim_scan_jobs` loop rather than the shared claim — if so, the zero-window scenario's
503 needs the verify/sweep path (or another cause) rather than scan starvation. The
verification below resolves this empirically either way.

## Work (gated on #131's MR merging to develop)

1. **Verification run (human-side):** the full local suite
   (`./scripts/native-tests/run.sh --hort=compose --keep`) on the develop head carrying
   #131 items 1+2. Expected: both class-B scenarios PASS (and [6/6] of the provenance
   scenario passes — #131's own acceptance).
2. **If green:** close class B on #130 as a downstream symptom of #131 — no code
   change; document the causal chain on the issue.
3. **If either scenario still 503s:** collect from the kept stack (a) the hort-server
   log lines for the failing GET (hold reason), (b) the jobs GROUP-BY dump, (c) the
   artifact row for the pulled digest — attach to #130 and return the issue to
   `workflow::in-specification` for a real spec. No blind fixes.

## Scope / acceptance

- No cockpit dispatch unless step 3 triggers (then a new spec round decides).
- This item is the groomed record of the verification plan; the "fix" may legitimately
  be zero code.

**Model hint:** n/a (no cockpit work in the green path).
