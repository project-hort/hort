# 219 — A pipe into `grep -q` under `pipefail` reports "no match" on a large body

**Issue:** #279 · **Branch:** `agent/279-pipefail-grep`
**Governing decisions:** none — this is a harness defect, not a decision. It
does not touch a metric, the boot apply, or `bounded_poll`'s bounds.

## Why

The `gitops/gitops` smoke failed with `no line matched
^hort_gitops_objects_total{ after 15s poll`, and the failure's own diagnostic
dump — the one added for #277 — listed six such lines in the very scrape it had
just called empty. The boot apply was fine; the check was wrong.

Every one of these predicates has the shape

```bash
curl -sSf … "$METRICS_URL" | grep -Eq '^hort_gitops_…'
```

under the `set -euo pipefail` in `scripts/native-tests/lib/common.sh:10`.
`grep -q` exits at the **first** match. If that match is near the front of a
body larger than the pipe buffer (64 KiB), the producer still has data to write,
blocks, takes `SIGPIPE` and exits 141; `pipefail` promotes that to the pipeline's
status, so the predicate reads as "no match" and `bounded_poll` spends its whole
budget re-running the same doomed command. If the match falls inside the last
64 KiB, the producer has already finished and the identical check passes.

That asymmetry is exactly what the failing run shows: `hort_gitops_objects_total`
renders **before** `hort_gitops_apply_total`, and the body was 94 027 B.
Reproduced at that size (match in the first line vs. the last):

```
early match:  rc=141   PIPESTATUS = 141 0
late  match:  rc=0     PIPESTATUS = 0 0
```

It is deterministic above the threshold, not flaky, and the threshold moves
closer as a deployment grows more objects. The 0.14.0 staging UAT passed the same
assertion against an 18 133 B body — below the buffer.

## Read first

- `scripts/native-tests/lib/common.sh` — `set -euo pipefail` (line 10),
  `bounded_poll`, `metrics_scrape_diag`, `assert_metric_ingest`.
- `scripts/native-tests/scenarios/gitops/gitops.sh:49-63` — the two predicates.
- `scripts/native-tests/scenarios/clients/maven.sh:527` — same shape.
- `scripts/check-g1-attestation-gate.sh`, `scripts/check-advisory-sync.sh` — the
  guard-script family and how `.gitlab-ci.yml` runs it (`quality:*` jobs).

## Scope

1. **One capture helper** in `scripts/native-tests/lib/common.sh`: fetch the body
   once into a temp file, then match the **file**, never the pipe — the same
   one-shot-capture rule the gate scripts already follow. It returns 0/1 for the
   match and never leaks the temp file. Keep the signature small enough that a
   predicate string stays readable inside `bounded_poll`.

2. **Convert the metric predicates** in
   `scripts/native-tests/scenarios/gitops/gitops.sh` (both),
   `scripts/native-tests/lib/common.sh` (`assert_metric_ingest`) and
   `scripts/native-tests/scenarios/clients/maven.sh`. `bounded_poll` itself does
   not change — the predicate it evaluates does.

3. **Convert every other unbounded producer** piping into `grep -q`, across
   `scripts/native-tests/`, `scripts/host-tests/`, `scripts/k8s-tests/` and
   `scripts/e2e/` — roughly 50 sites, of which the ones that matter are
   `docker logs …`, `curl …` and `printf '%s' "$BIG_VARIABLE"` (an index page or
   a scrape held in a shell variable is exactly as unbounded as a stream). Where
   a producer is provably small — a fixed list, a single-line response — leave
   the pipe but say so in one line of comment stating *why* it is bounded. A
   silent leftover is indistinguishable from an oversight.

4. **Close the form structurally**: a new `scripts/check-*.sh` in the existing
   guard family, wired into the same `quality:*` CI job list, rejecting a pipe
   into `grep -q` / `grep -Eq` under `scripts/` and naming the helper in its
   failure message. Without it the shape returns with the next smoke.

5. **Pin the trap in a test**: a body larger than 64 KiB whose only match is in
   the first line must report a match. Assert on the helper, so the test fails if
   someone re-pipes it later.

## Acceptance

- A body > 64 KiB with the match in line 1 reports a match; the `gitops/gitops`
  smoke passes against it.
- `grep -rn '| *grep -[A-Za-z]*q' scripts/` returns only sites carrying the
  bounded-producer note, and the guard script enforces that.
- The guard script is red on a re-introduced pipe and names the helper.
- The #277 diagnostic output is untouched — it is what made this diagnosable.
- `bash -n` clean on every edited script; no issue, MR or backlog numbers in
  comments.

## Explicitly not in this item

No change to the metrics themselves, to the boot-apply path, to `bounded_poll`'s
timeouts, or to which assertions the smokes make.
