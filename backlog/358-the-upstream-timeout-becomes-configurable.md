# 358 — The upstream fetch timeout becomes configurable

**Issue:** #331, entry **E102** · **Branch:** `agent/331-e102-upstream-timeout-configurable` · single item.

## Problem

`HttpUpstreamProxyConfig::new` hard-codes
`timeout: Duration::from_secs(30)` (`crates/hort-adapters-upstream-http/src/lib.rs:238`,
documented as a default at `:147`), applied to the reqwest builder at `:669`
and `:818`. reqwest's `.timeout()` is a **total** request timeout covering the
response body, not an idle deadline — so a transfer making uninterrupted
progress is still cut at 30 s. The limit is therefore a statement about
**size**, not health: a blob needing more than 30 s to transfer can never be
ingested, bandwidth-independently, and every retry restarts at byte 0.

Neither composition root can change it. Both override only
`extra_trust_anchors` and `user_agent` and take the rest from
`..HttpUpstreamProxyConfig::new(...)`
(`crates/hort-worker/src/composition.rs:569-576`,
`crates/hort-server/src/composition.rs:2386-2400`). There is no env knob —
searched, none exists. An operator hitting this cannot mitigate it at all.

## Scope — configurability only

**The maintainer's decision (2026-11-01), and it bounds this unit:**

1. the value must be configurable;
2. the configurability ships in **0.17.1**;
3. a better answer than globally enlarging the timeout is designed **after**
   that.

So this unit makes the existing number settable and changes **nothing else**.
The default stays **30 s**, so no deployment's behaviour moves unless its
operator moves it.

## The shape: mirror `HORT_UPSTREAM_USER_AGENT` exactly

That knob is the same kind of thing in the same adapter and already has every
part this one needs. Follow it rather than inventing a parallel style:

1. **`timeout_from_env()` beside `user_agent_from_env()`**
   (`lib.rs:325`), reading `HORT_UPSTREAM_TIMEOUT_SECS`, defaulting to the
   current 30 s. One env read in the adapter, so both composition roots get
   identical behaviour instead of each parsing it.
2. **Both composition roots call it**, exactly where they already call
   `user_agent_from_env()` — `hort-worker/src/composition.rs:574` and the
   `hort-server` site at `composition.rs:2386-2400`.
3. **A first-class chart value**, `upstream.timeoutSeconds`, beside
   `upstream.userAgent`: a constrained entry in
   `deploy/helm/hort-server/values.schema.json` (the UA uses a `pattern`; this
   wants an integer with a sensible minimum), a documented default in
   `values.yaml`, and the env wired into **both** `templates/deployment.yaml`
   and `templates/worker-deployment.yaml`. Without this the knob is reachable
   only through `extraEnv`, and a knob an operator cannot find is not
   configurability.
4. **`docs/architecture/reference/server-and-worker-configuration.md`** gets
   the row, in the same form as the other `HORT_*` entries.

### One deliberate difference from the User-Agent, and the reason

The UA warns and falls back on an invalid value, because *"a `User-Agent` is
not worth a boot crash"* (`lib.rs:320-324`). **A timeout is not in that
class.** An operator sets this knob precisely because fetches are failing; a
value silently discarded back to 30 s leaves them watching the identical
failures while believing they raised the limit. So an unparseable value, or
`0`, must be **refused loudly at boot** rather than defaulted.

Absent (or empty, matching `parse_u32_default`'s established treatment) is
different and means "use the default" — that is not an error.

If the adapter's current structure cannot fail at that point, say so in the
report with what it would take, and implement the loudest thing it can do
(a `warn!` naming the variable and the value it refused) rather than silently
defaulting.

## Explicitly not in scope

- **Do not change the default.** 30 s stays.
- **Do not change the instrument.** Replacing the total timeout with
  `connect_timeout` plus an idle/read deadline is the right eventual fix and is
  the maintainer's step 3 — a behaviour change on every pull-through path, so
  it ships as a MINOR with its own design and an E2E that pulls a large blob.
- **No `Range`/resume work.**
- Do not touch `max_redirect_hops`, the cache sizes, or `user_agent`.

## Acceptance

- `HORT_UPSTREAM_TIMEOUT_SECS` unset → the client's timeout is 30 s, proven by
  a test rather than asserted.
- Set to a valid number → that value reaches the reqwest client on **both**
  the server and the worker path.
- Set to an unparseable value or `0` → boot refuses, naming the variable and
  the value (or, if structurally impossible, the loudest alternative plus the
  reason in the report).
- `helm template` with `upstream.timeoutSeconds` set renders the env on both
  Deployments; the schema rejects a non-integer and a value below the minimum.
  `scripts/test-helm-templates.sh` covers chart rendering — install helm in-run
  if absent and report the result per helm version it tests.
- `CHANGELOG.md`: one `### Added` line. This is an operator-visible new knob,
  and the entry should say what it is for — a large upstream blob that cannot
  finish inside the default.
