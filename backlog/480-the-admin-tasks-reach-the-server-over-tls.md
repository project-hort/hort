# 480 — the admin-task CronJobs reach the server over TLS

**Issue:** #457 · **Branch:** `agent/457-tls-sidecar` · Unit 2 of 2.
**Depends on 479** — the sidecar must exist before anything can be pointed at it.
**Decision:** ADR 0068, amendment 2026-11-25.

## Why this exists

These are the pods the measurement found refused: three of the seven kinds that
ran after the roll, and exactly the three that make a credentialed HTTP call
(`hort-cli admin task invoke` with a svc-token). The four `enqueue-*` kinds talk
to Postgres, carry no HTTP credential, and are out of scope — nothing refuses
them and nothing here should change them.

With 479 in place the fix is to stop using the plaintext hop: point them at the
sidecar over TLS, where they get real `Tls` evidence and no waiver is involved.

## The part that is more than a URL

`hort-cli` honours `HORT_EXTRA_CA_BUNDLE` (`crates/hort-cli/src/client.rs:84`),
but these pods mount **no CA bundle today**, and a sidecar certificate will not
be publicly trusted — the staging ingress cert, for one, is signed by a private
intermediate CA. So this unit is a URL **and** a trust path: a mounted CA bundle
plus the env var, from a `ConfigMap`/`Secret` the operator names in values.

Do **not** add an insecure-TLS or skip-verify knob. ADR 0010 forbids the whole
class (`*_INSECURE_TLS`), and a chart value that disabled verification here
would be the same decision wearing chart clothing.

## Scope

- When `tlsSidecar.enabled`, the admin-task CronJob templates set `HORT_SERVER`
  to the sidecar's `https://` Service URL; when disabled they keep today's
  plaintext URL unchanged.
- A values key naming the CA source, mounted into those pods with
  `HORT_EXTRA_CA_BUNDLE` pointing at it. Top-level keys need `#` comments
  (`scripts/check-values-comments.sh`).
- `values.schema.json` entries.
- Revise the `tlsNotRequiredFrom` comment that currently sits on these
  templates: with the sidecar enabled no scope is needed at all, and the
  comment should say which configuration it is talking about rather than
  implying a scope is always required.
- Assertions in `scripts/test-helm-templates.sh` in **both** directions:
  enabled renders the `https://` URL and the CA mount; disabled renders
  neither and leaves the plaintext URL intact.

## Acceptance

- With the sidecar disabled, these CronJobs render byte-identical to today.
- With it enabled, each admin-task CronJob carries the `https://` Service URL,
  the CA mount and `HORT_EXTRA_CA_BUNDLE`; no `enqueue-*` CronJob is touched.
- No skip-verify knob is introduced anywhere.
- `scripts/test-helm-templates.sh` covers both directions; break each assertion
  once to prove it can fail.
- One `CHANGELOG.md` entry folded under the #457 entry.
