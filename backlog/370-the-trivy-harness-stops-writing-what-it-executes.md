# 370 — The Trivy harness stops writing what it executes

**Issue:** #401 · **Branch:** `agent/401-release-safeguards` · item 2 of 2.

Second wave of the #331 sweep. Found on 2026-10-15 at the tag pipeline of
`v0.15.0-alpha.3`, which published nothing because one test failed.

## What happened

`test:coverage` failed on exactly one test,
`hort_adapters_scanner_trivy::tests::a_report_with_a_vulnerability_is_a_verdict_with_findings`:

```
trivy adapter: trivy binary not found at /tmp/.tmpjh3XnG/fake-trivy.sh:
Text file busy (os error 26)
```

ETXTBSY on `exec` of a script the same test had written immediately before.
The same test passed in the full local workspace run; the difference is the
coverage instrumentation, which widens the window.

**The finding is not the flake — it is that a defence against it already
exists, three times over.** The census is **three** write-then-exec sites in
**two** files, each carrying its own defence of a different shape (re-measured
2026-11-03):

| Site | Defence |
|---|---|
| `src/lib.rs:1352` (the cap test) | `SCRIPT_WRITE_GUARD` (`:797`), the sync-and-drop handle, **and** a five-iteration retry loop on `Text file busy` (`:1381-1390`) |
| `src/lib.rs:1434` (`scan_against_fake_trivy_with_payload`, the shared helper) | the same static, the same sync-and-drop |
| `tests/timeout.rs:123` → `hung_child_script` (`:103-119`) | a **second** `SCRIPT_WRITE_GUARD` (`:49`, because a `tests/` binary cannot see the inline module's static) and `TempPath` instead of sync-and-drop |

A defence re-invented three times in two files, in three shapes, is the
argument for closing the path rather than narrowing it. The comment at
`:1356` states what the second shape is for:

> Write via an explicit handle we sync + drop before exec so the kernel has
> no open writable fd on the file (avoids the transient ETXTBSY race on
> spawn).

So the defence addresses "this thread still holds a write descriptor" — and
that cause is no longer the effective one. A plausible remaining cause, and
it is **a hypothesis, not verified**: ETXTBSY also arises when *another*
thread of the same process `fork`s during the write window; the child
inherits the open write descriptor and holds it until it `exec`s, long after
the writing thread closed its own. Neither `sync_all` + drop nor a mutex
scoped to the script-writing tests helps against that, because the forking
thread need not be in that set at all.

## Why it is worth a unit

The failure is not confined to the test. `test:coverage` is in stage `test`
(`.gitlab-ci.yml:739`) and carries no `allow_failure`, so
`build-images:hort-server`, `build-images:hort-worker`,
`helm:lint-and-publish` and `helm:sign-chart` were all **skipped**. A tag
that fails on this flake publishes **nothing** — staging cannot roll the
version although code and gate are fine. A job re-run repaired it. That
shape — green local gate, red tag run, no artifact, re-run helps — costs a
release cycle per occurrence and is indistinguishable in the result from a
real test failure.

## The outcome

**Dissolve the write-then-exec instead of narrowing the race.** A script that
is not generated at runtime — a checked-in fixture that is only executed —
cannot raise ETXTBSY. A third tightening of the guard would be the third
defence against the same observation, defending the path instead of closing
it.

Two consequences to handle rather than discover:

- a checked-in executable fixture must keep its executable bit in git, and
  the test must fail with a clear message if it does not (a fixture that is
  not executable fails exactly like the bug this unit removes);
- the tests parameterise the fake's **output** today. A single fixture that
  reads its payload from a path or an environment variable keeps that
  parameterisation without regenerating the script — the payload may be
  written at runtime, the executable may not.

Once no test writes the script any more, all three defences and both
`SCRIPT_WRITE_GUARD` statics have nothing left to protect. Remove what becomes dead
rather than leaving a guard whose reason no longer exists; if any writer
remains, say which and why its defence stays.

## Acceptance

1. **The proof is at the mechanism, not at the intent**: no test in
   `crates/hort-adapters-scanner-trivy` writes a file it then executes, shown
   by the diff and by the absence of the write path — not by an assertion
   that the flake is gone (a race cannot be proven absent by a passing run).
2. **All three** sites are converted, not just the one that failed:
   `src/lib.rs:1352`, `src/lib.rs:1434`, and `tests/timeout.rs`'s
   `hung_child_script`. `src/extract.rs:321-329` sets modes on extracted
   archive members and is production code nothing execs — out of scope.
3. The fixture's executable bit is in git, and a test states what happens if
   it is lost.
4. No safeguard is loosened: `test:coverage` keeps its position and its
   relationship to the publish jobs. The flake is removed, not the
   dependency.
5. `cargo test -p hort-adapters-scanner-trivy` passes, and so does the same
   suite under coverage instrumentation — the configuration that widened the
   window is the one that has to run.
6. `CHANGELOG.md`: no entry — test harness only.

## Not in this item

- E18 and E24 (item 1).
- Whether a failed `test:coverage` should drag a tag's publish jobs with it.
  Changing that would loosen a safeguard to make a case fit, which this
  ticket's own rule forbids.
