# 369 — The two CI safeguards reach the case they were built for

**Issue:** #401 · **Branch:** `agent/401-release-safeguards` · item 1 of 2.

Second wave of the #331 sweep. Two safeguards that exist, work, and do not
cover the case they exist for. Both were found at damage, not by reasoning:
one cost a tag pipeline, the other a red MR on work already handed to a
human.

The rule that governs this wave: a safeguard that does not cover the case it
is there for is worse than none — it creates confidence that does not hold.
And neither fix may loosen a safeguard to make a case fit.

Both verified against develop `9202dcbc`.

## a) The release build does not depend on the warm job that enables it

**What holds.** `warm:base-images` (`.gitlab-ci.yml:1115`) pulls every pinned
base-image digest through the proxy. Its own header states the problem it
exists for (`:1074-1082`): `build-images:*` runs on tags, `main` and
`release/*` only, so the first consumer of a newly pinned digest is always a
release-shaped build — which is also the first request that pulls it through
the proxy, so ingest and the quarantine window start **inside** the release
build, which then fails for exactly one window.

The job carries `allow_failure: true` (`:1121`), `needs: []` (`:1120`), and
its verdict lives only in its log. Its rules (`:1123-1124`) fire on `develop`
pushes and on schedules — **not** on a tag pipeline. So the pipeline is green
either way and **nothing stops a release build from running while a reference
is still warming.**

**What it cost.** A base-image digest bump, then a tag whose
`build-images:hort-worker` failed after six minutes of Rust compile on a
`503` from our own proxy — fail-closed and correct, in the most expensive
place. The server image was built, pushed and signed; the worker image, the
SBOM and the chart were not. A half-published tag that nothing in the
registry alone reveals, and a retry that only works after the window. The
same gap reaches a `main` promotion, not just an alpha.

**The outcome.** A precondition on `build-images:*` that checks every pinned
`FROM …@sha256:` digest with one manifest `HEAD` **before anything compiles**
and refuses with the `Retry-After` in its message, so six minutes of build
failure become an immediate, self-explaining refusal that names the time from
which the tag works. The quarantine window is not bypassed, no digest is
pulled around the proxy, and `warm:base-images` keeps its `allow_failure`
(it is a warm, not a gate).

The digest set must come from the Dockerfiles themselves, not from a second
list in CI — a list that drifts is the defect one level up.

## b) Eleven shell guards run only in CI, and a feature branch gets no pipeline

**What holds.** Eleven guards under `scripts/` are invoked by
`.gitlab-ci.yml` and nothing else — measured, not quoted:

```
$ grep -oE "scripts/(check|test)-[a-z0-9-]+\.sh" .gitlab-ci.yml | sort -u
scripts/check-advisory-sync.sh      scripts/check-attribution.sh
scripts/check-g1-attestation-gate.sh scripts/check-osv-scanner-version.sh
scripts/check-pipe-grep-q.sh        scripts/check-rust-version.sh
scripts/check-values-comments.sh    scripts/test-capture-match.sh
scripts/test-crate-version-in-index.sh scripts/test-fail2ban-regex.sh
scripts/test-helm-templates.sh
```

Nothing aggregates them: there is no command that runs them all, and the
pre-push checklist in `CLAUDE.md` names only the cargo commands. And the
`workflow:` rules (`.gitlab-ci.yml:45-53`) run pipelines on
`merge_request_event`, `main`, `develop`, `release/*` and tags, with no
catch-all — an ordinary push to `agent/…` matches none of them, so a feature
branch gets **no CI at all** until its MR opens.

**Why that combination bites.** The Rust guard family lives in
`crates/*/tests/` and therefore runs under `cargo test --workspace`
automatically — which is exactly why it works. The shell guards sit beside it
and run **never** in the whole dispatch/review cycle. For a block of ten
units, every shell invariant is unenforced until the end, and the first
feedback is a red pipeline on work a human has already been handed as
gate-checked. That is how three unannotated `| grep -q` pipes in
`scripts/test-helm-templates.sh` survived the directive, the review, the
per-unit gate, the handover and a compose E2E.

**The outcome.** One command that runs **every** guard, and CI invokes that
same command, so there is exactly one place that knows every guard and a
newly added one is in the local gate without anyone remembering it. The
command goes into the pre-push checklist in `CLAUDE.md` and into the gate
line of every directive.

**The property that makes it worth building** is single-sourcing, so the
obvious shortcuts are both wrong: "remember to run them" is a habit, not a
gate, and "add eleven commands to the directive's gate line" is a second list
beside `.gitlab-ci.yml` that drifts from the next guard on.

**A guard that cannot run where it is invoked must say so.** `helm` is not
present in the project sandbox, and `test-helm-templates.sh` exits 2 there.
A skip that reads as a pass would reproduce, in the aggregator, the very
defect this wave is about: the aggregator reports such a guard as
**not runnable, named**, and its own exit code distinguishes "all guards
passed" from "some guard could not run here".

## Acceptance

1. **Per entry, the proof is at the mechanism, not at the intent**: that the
   precondition / the aggregator actually reaches the case, shown by a run or
   a test — not by the rules file.
2. (b) reports the list of guards **untruncated** and derives it rather than
   copying it from this item; if the derived list is not eleven, the
   difference is reported.
3. (a) does not bypass the quarantine window and does not move the digest
   pull out of the proxy.
4. **No safeguard is loosened to cover a case.**
5. (b)'s command runs without CI — that is its whole point — and a guard
   that cannot run in the sandbox is reported as such rather than skipped
   silently.
6. `CHANGELOG.md`: no entry. Both halves are CI and developer tooling, which
   the changelog policy excludes.

## Not in this item

- E42, the ETXTBSY race in the Trivy test harness (item 2).
- Whether a failed `test:coverage` should drag a tag's publish jobs with it.
  Changing that would loosen a safeguard to make a case fit, which this
  ticket's own rule forbids; the flake is what gets removed, in item 2.
