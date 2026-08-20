# 125 — Forward the runner mode into scenarios, and make pull-dedup's coldness gates mode-aware

Issue: #169.

## What is wrong

`proxy/pull-dedup` gates on fixture premises that only hold on a stack the
runner owns. Under `--hort=compose` a violation means a dirty fixture and
`compose down -v` clears it, so failing is right. Under `--hort=external`
against a long-lived hort nobody can clean, the same violation is a permanent
red that no amount of local correctness clears — and a permanently-red scenario
is how a signal gets ignored, which is the disease that produced the issue this
scenario came from.

The scenario cannot currently tell the two apart: **`HORT_MODE` is not
forwarded into scenario containers**. `scripts/native-tests/run.sh` keeps it
host-side (set at line 26, consumed at 68/110/254/278), and no scenario or lib
reads it.

## Three gates, not one — the issue names only the first

### Gate 1 — the per-repository coldness preflight

`scripts/native-tests/scenarios/proxy/pull-dedup.sh`, in the preflight:

```sh
resident="$(psql_one "SELECT count(*) FROM artifacts
    WHERE repository_id = '${repo_id}' AND path = '${ARTIFACT_PATH}';")"
```

Scoped to the two dedicated repositories. Under external this hard-fails if that
pair exists and is warm. (If the pair is *absent*, the earlier preflight already
skips cleanly — that path is fine.)

### Gate 2 — the content-level coldness assertion, which is instance-wide

Much later in the same file:

```sh
leader_full_window="$(psql_one "SELECT (quarantine_window_start = created_at)
    FROM artifacts WHERE id = '${LEADER_ARTIFACT_ID}';")"
```

The anchor is `MIN(created_at)` over **every** `artifacts` row sharing the
checksum — unscoped by repository, unfiltered by `is_deleted`. So *any* row
anywhere in the instance carrying the same bytes, under any repository, in any
format, present or soft-deleted, back-dates the content minimum and fails this
assertion. Its own failure message says it: *"these bytes were already resident
somewhere in this instance despite the preflight, so the checks below are not
measuring this run"*.

**Gate 1's fix does not reach gate 2.** A dedicated pair can be perfectly cold
while the bytes sit in the shared npm mirror next door. Forwarding the mode and
fixing only the preflight leaves the scenario still permanently red under
external — just failing later, after a page of passes, which is worse to read.

### Gate 3 — the content-elsewhere preflight check

Sitting between gates 1 and 2, in the same preflight block as gate 1:

```sh
content_elsewhere="$(psql_one "SELECT count(*) FROM artifacts WHERE path = '${ARTIFACT_PATH}';")"
```

Also instance-wide and unscoped by repository, like gate 2 — it counts every
`artifacts` row anywhere carrying `ARTIFACT_PATH`, not just rows in the
dedicated pair. Gate 1 does not shield it: gate 1 only fires when the
*dedicated* pair is warm, so on an external instance where the pair is
declared and cold but the drive package has been proxied through some other
repository, gate 1 passes cleanly and gate 3 hard-fails instead. Its own
failure message concedes the point: *"against an external hort this scenario
needs a package that instance has never proxied"*.

All three gates need the mode.

## What

1. **Forward the mode into the scenario environment.** Add it to the `-e` block
   in `run.sh` (~line 371–376), alongside `HORT_PULL_DEDUP_LEADER_LOCK_TTL_SECS`
   — same shape, same place. Name it so it reads as runner-provided context
   rather than a hort setting.

   This is deliberately a general capability, not a one-scenario hack: any
   scenario whose fixture premise is only enforceable on a runner-owned stack
   has this shape. Document it in `scripts/native-tests/README.md`'s scenario
   contract so the next one does not re-derive it.

2. **Make all three gates mode-aware**, with the same rule at each: violation
   under compose stays a `fail` (dirty fixture, actionable); under external it
   becomes a `skip` (exit 77) whose message says the premise is unenforceable
   on a long-lived instance and names the package, so a reader knows why
   rather than seeing a bare skip.

   Gate 2 fires mid-run, after passes have printed. A skip there is still a skip
   to the runner, and it is the correct verdict: the comment already states the
   checks below stop measuring this run. Do not let it print `PASS` on the
   remaining assertions after the premise is known broken.

3. **Default the mode when unset.** A scenario run outside the runner (directly,
   by hand) must not silently take the external branch and skip everything.
   Absent or empty should behave as the strict mode, so a missing forward
   surfaces as a failure rather than as a green run that asserted nothing.

## Out of scope

Making the scenario cold-proof on a shared instance — e.g. a per-run unique
drive package. That would remove the premise instead of detecting it, and it is
a different, larger change. If it turns out to be the better answer, raise it;
do not fold it in here.

## Not urgent, and why it is worth doing anyway

The external + `HORT_DB_DSN` combination is not in use today: CI runs compose,
and the staging verifier is read-mostly and does not run native-tests. This is a
latent trap, not a live failure — the cost of fixing it now is small and the
cost of discovering it is a suite someone has already learned to ignore.

## Done when

`HORT_MODE` (or its forwarded equivalent) is readable inside scenario
containers and documented in the scenario contract; all three coldness gates
fail under compose and skip with a diagnostic under external; and an unset
mode behaves as compose. Verify the compose lane still goes green —
`./scripts/native-tests/run.sh --hort=compose --group proxy` — since the
scenario's compose behaviour must be unchanged.
