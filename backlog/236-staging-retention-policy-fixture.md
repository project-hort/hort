# 236 — A `RetentionPolicy` envelope in the alpha-fixture tree

**Issue:** #294 · **Branch:** `agent/294-staging-retention-fixture`
**Governing decisions:** ADR 0038 §4 and ADR 0046 D3 (destructive action is
operator-performed) · #281 (the concept and its scoping decision) · #282
(`RetentionScope` by `metadata.name`, without which no envelope is writable) ·
#232 (staging rolls only from published artifacts).

## Why

Eight units of the retention cleanup path are on `develop` and **none has ever
run in staging**. That is not the missing alpha tag: the alpha-fixture tree
contains no `RetentionPolicy` envelope at all.

```
$ grep -rh '^kind:' scripts/alpha-fixtures/gitops-config/ | sort | uniq -c
      8 kind: ArtifactRepository
      3 kind: ClaimMapping
      7 kind: PermissionGrant
      7 kind: ScanPolicy
      1 kind: ServiceAccount
      4 kind: UpstreamMapping
```

Without an envelope the apply path never runs, no `policy_projections` row is
created, and `retention-evaluate` returns before it reaches the candidate
reader. A UAT would have nothing to look at — which is also why the three
independent reasons nothing was ever deleted in production surfaced during
implementation rather than in staging.

## The decision

**Staging tests a *sharp* retention, not an inert one.** There are no
irrecoverable packages there. An earlier proposal — `AgeExceeds` with a span
staging can never reach, so the apply path runs and nothing happens — is
superseded: it would have shown that a policy arrives, and nothing about
whether it works.

## Read first

- `scripts/alpha-fixtures/gitops-config/` — the whole tree, especially
  `base/policies/` (the `ScanPolicy` envelopes are the shape to mirror) and
  `base/repositories/` (the `metadata.name`s a scope may reference).
- `crates/hort-config/src/retention_policy.rs` — `RetentionPolicySpec`,
  `parse_retention_policy`, `validate_retention_policy`.
- `crates/hort-config/tests/alpha_fixtures.rs` — the guard the new file must
  pass: parse **and** cross-validate.
- `crates/hort-domain/src/retention/` — `PolicyPredicate`, `RetentionScope`.
- `deploy/helm/hort-server/values.yaml`, the *Retention task templates* block —
  read it to confirm you are **not** changing it.

## Scope

### 1. The envelope

One `RetentionPolicy` under `scripts/alpha-fixtures/gitops-config/base/policies/`,
following the numeric-prefix convention already in that directory.

`RetentionPolicySpec` carries `predicate` and `scope` as **JSON shapes written
in YAML** (`predicate: {AgeExceeds: 2592000}`, `scope: {Repos: [npm-proxy]}`) —
not `serde_yaml` enum tags. `Repos` holds repository `metadata.name`s, never
UUIDs; that is exactly what #282 made possible and it is one of the units this
fixture exists to verify.

**Recommended shape, to be argued rather than copied:**

- **Scope: a single named proxy repository.** Naming one repository exercises
  the `metadata.name` resolution path specifically — the unit most in need of
  verification — and bounds the blast radius to one repository. `IngestSource:
  Proxied` would also be defensible (it is population P1 in the concept, and
  proxy content is by definition re-fetchable) but it verifies less and reaches
  further.
- **Predicate: `AgeExceeds`,** with a span short enough that staging content
  actually matches. Pick it from what staging plausibly holds and say why.
  A span nothing reaches turns this back into the inert policy the decision
  rejected.

### 2. `KeepLastN` is not verifiable in staging today — establish this, do not assume it

`KeepLastN` is the predicate the 69 GB of hosted churn hangs on, so it is what
one would most like verified. It ranks siblings, and it proves nothing over
groups of size one.

The evidence available in-repo says the groups *are* size one: the
alpha-testing runbook publishes exactly one version of each fixture package
(`hort-alpha-smoke@1.0.0`, the PyPI fixture at `1.0.0`, `test-img:v1`).

That is evidence about the **fixture path**, not about the running staging
instance, which also receives dogfood and UAT traffic — and you cannot see that
instance from here. So: state the in-repo finding, state its limit, and
**do not write a `KeepLastN` policy on an assumption**. Whether staging holds
sibling groups is a question for the verifier, and the architect will ask it.

If you conclude the fixture should *create* a sibling group so the predicate
becomes verifiable, argue it — but note the fixture content is published by a
human following the runbook, so that is a change to their steps, not to a
script this repository runs.

### 3. Nothing else changes

- The two retention CronJobs stay `enabled: false`. This is the scoping
  decision, not caution: the cleanup is performed by a person through
  `hort-cli admin retention preview` / `apply`, which is what ADR 0038 §4 and
  ADR 0046 D3 provide for. The claimless bootstrap svc-token cannot satisfy
  `task:destructive` in any case.
- No chart value, no CronJob template, no identity, no mint.

### 4. What the verification split has to be

Say it in the report so the UAT directive can be written from it:

- **Verifier** — the envelope arrived (gitops apply counter, the policy
  visible) and `retention-evaluate` in `dry_run` mode returns a proposal with a
  non-zero row count. That covers the candidate reader, the scope resolution
  and the dry run — and it covers them *sharply*, because a proposal of zero
  rows is exactly the outcome the broken candidate reader produced.
- **Human** — the sharp `apply`. `apply` needs a fresh IdP-backed admin session
  carrying `task:destructive`, and obtaining one is outside the verifier's
  boundary. That run is also the first real before/after measurement the
  concept asks for.

Name which of the eight merged units each half verifies, and which remain
unverified either way.

## Acceptance

- At least one `RetentionPolicy` envelope in the fixture tree that passes
  `alpha_fixtures_parse_and_cross_validate` — parse **and** cross-validate
  (every `Repos` entry names a declared `ArtifactRepository`).
- The chosen scope and span are argued, not asserted.
- No change to `values.yaml`, any CronJob template, or any identity.
- The report contains the verification split of item 4.
- Gate green.

## Explicitly not in this item

No CronJob enablement. No new predicate or scope variant. No change to the
retention code. No UAT directive (the architect writes it from this report).
