# Curator workflow — waive, block, exclude

This guide is for operators acting in the **curator** role: making
day-to-day decisions on artifacts that quarantine-by-default has held,
or that the scanner has rejected, without escalating to a full admin
session. It covers how the curator grant is made, the three decision
flows (waive / block / exclude-finding), the audit trail produced, and
the operational caveats — especially the **finding-exclusion blast
radius** and the **`block-versions` continue-on-error contract**.

The quarantine state model, the quarantine-by-default posture, and the
fail-closed release predicate are documented in
[ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)
and [security.md](../explanation/security.md).

---

## 1. The curator role

`Permission::Curate` is the day-to-day decision role for security /
release-team operators who triage artifacts in `Quarantined` or
`Rejected` state. It is **narrower than `Permission::Admin`** by
design:

| Authority                        | `Permission::Curate` | `Permission::Admin`              |
| -------------------------------- | -------------------- | -------------------------------- |
| Waive a `Quarantined` artifact   | yes                  | yes                              |
| Waive a `ScanIndeterminate`      | **no** (admin-only)  | yes (broader source-state guard) |
| Block any non-terminal artifact  | yes                  | yes                              |
| Bulk-block via explicit version list | yes              | yes                              |
| Exclude / unexclude a CVE finding | yes                 | yes                              |
| All other admin endpoints        | no                   | yes                              |

The narrower source-state guard on waive is intentional. `ScanIndeterminate`
means the scanner could not complete (a terminal scan failure, not a
clean result); releasing such an artifact requires the broader
deliberation that `admin_release` represents (the broader role, the
emergency escalation context). Curator-waive serves the common case:
"the scan was clean, advisory-lag residual risk is acceptable for this
specific artifact, release it before the window completes."

The role is **claim-based** (see
[`operate/claim-based-rbac.md`](operate/claim-based-rbac.md)).
A `Permission::Curate` grant
rides the existing audited `ApplyConfigUseCase` apply path; there is no
admin REST endpoint, no migration backfill, no direct DB insert. The
grant flow is identical to every other claim-based permission in the
system.

### 1.1 Granting the curator role

Curator authority is granted via a gitops `PermissionGrant` envelope
loaded from `$HORT_CONFIG_DIR` at hort-server boot (see
`docs/architecture/how-to/declare-gitops-config.md` for the full
operator flow). Two grant subjects are supported (the `GrantSubject`
taxonomy is deliberately closed at two):

**Grant to a claim set** (the recommended pattern for SSO-backed
operator identities):

```yaml
apiVersion: project-hort.de/v1beta1
kind: PermissionGrant
metadata:
  name: curator-security-team
spec:
  subject:
    kind: claims
    required:
      - org:security-team       # set of claim names the principal must hold
  permission: curate            # the literal DB ENUM value
  # repository omitted = global authority across all repositories
```

**Grant to a service account / individual user** (for an `hort_svc_*`
token or a specific human):

```yaml
apiVersion: project-hort.de/v1beta1
kind: PermissionGrant
metadata:
  name: curator-ci-rotation-bot
spec:
  subject:
    kind: user
    userId: 9c1e3a2f-...         # user_id UUID (the SA's user row)
  permission: curate
  repository: npm-proxy          # optional — narrow to a single repo;
                                 # omit for a global grant
```

The apply emits a `PermissionGrantApplied` event with full actor attribution
(who applied the grant; from which gitops commit); the linter rejects
malformed grants before they hit the DB. Both paths run through the
same audited surface — there is no grant back door.

Apply via the gitops boot path:

```sh
# 1. Write the YAML under $HORT_CONFIG_DIR, e.g.
#      $HORT_CONFIG_DIR/permissions/curator-security-team.yaml
# 2. Restart hort-server (or signal the boot apply if hot-reload is
#    wired in your deployment).
# The boot apply walks $HORT_CONFIG_DIR recursively and emits
#   hort_gitops_objects_total{kind=permission_grant,result=...}
# once per row (created | updated | unchanged | deleted).
```

There is no `hort-cli admin apply` subcommand; `$HORT_CONFIG_DIR` is the
**only** loader path for declarable configuration. See
`docs/architecture/how-to/declare-gitops-config.md` for the directory
layout, validation behaviour, and idempotency contract.

### 1.2 What curator does NOT confer

`Permission::Curate` does **not** confer:

- `Permission::Admin` (any of the admin endpoints, including the
  emergency `admin_release` path that accepts `ScanIndeterminate`)
- `Permission::AdminTaskInvoke` (running admin background tasks)
- `Permission::Write` / `Permission::Read` on repositories (a curator
  who needs to inspect artifact content downloads it as themselves;
  curator authority does not synthesise an artifact read grant)
- Any ability to **modify** policy thresholds, repositories, or upstream
  mappings (those remain admin-only)

If an operator needs more authority than curator, the correct flow is
to assume an admin session via `hort-cli auth login --admin` (see
[`using-hort-cli-with-admin-ops.md`](using-hort-cli-with-admin-ops.md)),
not to widen the curator grant.

---

## 2. The three decision flows

### 2.1 Waive — release a `Quarantined` artifact early

**Use it when:** the scan completed clean, the observation window is
still running, and the cost of waiting (downstream consumers stuck on
an older version with a known issue, a critical patch that fixes a
deployed CVE, an urgent dependency-of-a-dependency unblock) outweighs
the marginal risk-reduction of the remaining window.

**Pre-flight check:** look at the queue listing first.

```sh
hort-cli curation queue --status quarantined --repo npm-proxy
# Identify the artifact_id. Then look at its finding count and scan
# status. A waive is appropriate when finding_count = 0 (clean scan)
# or the findings are known false-positives you intend to follow up
# with --exclude-finding.
```

**Issue the waive:**

```sh
hort-cli curation waive <artifact_id> \
  --justification "lodash@4.17.21 fixes CVE-2024-XXXX (verified upstream
                    npm signature 2026-05-23); risk-accepted by
                    security@example.com"
```

The `--justification` is **required** (non-empty, ≤ 512 bytes — the CLI
rejects empty / oversize before the round trip). The justification
rides the `ArtifactReleased` event's `justification` field; it is the
load-bearing audit anchor.

**Event emitted:**

```text
ArtifactReleased {
  released_by: Curator,
  released_by_user_id: <your user_id>,
  justification: "<the text you supplied>",
  ...
}
```

The audit log distinguishes curator-waive from `admin_release` via the
`released_by` discriminator; both populate `released_by_user_id` +
`justification`, so a single query against the event stream
reconstructs every human-authority release with its attribution.

**Source-state guard reminder:** if `quarantine_status` is
`ScanIndeterminate` (not `Quarantined`), the waive returns `400` — that
artifact requires `admin_release`. The queue listing carries the
status; check it before issuing.

### 2.2 Block — reject a non-terminal artifact

**Use it when:** you've identified an artifact that should not be
served — a shadow-IT upload, a supply-chain risk surfaced by external
intelligence (out-of-band of the scanner DB), a deprecation you want to
hard-pull rather than wait for clients to update.

Two shapes:

**Single artifact:**

```sh
hort-cli curation block artifact <artifact_id> \
  --justification "Shadow-IT upload — pulled per security review
                    SEC-2026-014; vendor-internal package leaked through
                    proxy fallback"
```

**Bulk by version list** (the operator already knows which `(repo,
package, versions)` tuples are vulnerable):

```sh
hort-cli curation block versions \
  --repo npm-proxy \
  --package left-pad \
  --versions 1.0.0,1.0.1,1.0.2,1.0.3 \
  --justification "CVE-2026-XXXX confirmed across these versions per
                    GHSA-aaaa-bbbb-cccc; blocking pending upstream
                    backport"
```

The bulk variant caps at **100 versions per call** (mirrors the
queue's `limit` shape — bounded per-call work).

**Source-state guard:** `None | Quarantined | Released → Rejected`.
`Released → Rejected` is the shadow-IT / retroactive-rejection case
(mirrors `reject_from_retroactive_curation`). Already-
`Rejected` artifacts are an **idempotent no-op** at the use-case layer
(counted in `BlockOutcome.already_rejected_ids`; no re-appended event;
avoids audit-log noise from accidental double-blocks).

**Event emitted (per resolved-and-non-terminal artifact):**

```text
ArtifactRejected {
  rejected_by: Curator { curator_id: <your user_id> },
  reason: "<the justification text>",
  correlation_id: <shared across every event a single block call emits>,
  ...
}
```

**Bulk-call result shape** — operators MUST inspect this:

```json
{
  "correlation_id": "...",
  "blocked_artifact_ids": ["..."],      // transitioned to Rejected on this call
  "already_rejected_ids": ["..."],      // idempotent no-op (no event appended)
  "not_found_versions": ["..."],        // not ingested yet — NOT auto-blocked
  "failed": [["...", "<error>"], ...]   // per-append failures (continue-on-error)
}
```

See §2.4 below for the **continue-on-error contract** — this is the
load-bearing operational contract on `block versions`.

### 2.3 Exclude / unexclude a CVE finding

**Use it when:** the scanner is flagging a CVE that does not apply to
your deployment (the vulnerable code path is unreachable in your
configuration, the CVE was filed against a different ecosystem, the
upstream advisory was retracted), and you want to silence it at policy
level so all currently-quarantined artifacts whose only blocking
finding is this CVE are released.

```sh
# Exclude a CVE for a specific policy
hort-cli curation exclude-finding \
  --policy <policy_id> \
  --cve CVE-2024-XXXX \
  --justification "Vulnerable code path not reachable in our config
                    (issue tracker SEC-2026-022); confirmed with vendor
                    advisory addendum"

# Reverse the decision (the CVE becomes blocking again)
hort-cli curation unexclude-finding \
  --policy <policy_id> \
  --cve CVE-2024-XXXX \
  --justification "Upstream advisory clarified — code path IS reachable
                    in certain build configurations; reinstating block"
```

**Events emitted:**

```text
ExclusionAdded {                      # or ExclusionRemoved on unexclude
  policy_id, cve_id,
  ...
}
# followed by the re-evaluation cascade — see §3 below
ArtifactReleased { released_by: PolicyReEvaluation, ... }   // × N
```

The actor attribution rides the **event envelope**
(`PersistedEvent.actor`), not the payload — `ExclusionAdded` /
`ExclusionRemoved` payloads carry no actor field by design. Item 8's
projector copies the envelope's actor `Uuid` into
`exclusion_projections.added_by_actor_id` (the field the `hort-cli
curation exclusions` listing surfaces).

---

## 3. The finding-exclusion blast-radius warning

> **Read this before issuing your first `exclude-finding`.**

Excluding a CVE finding is the **highest-blast-radius** decision a
curator can make. One exclusion can release N artifacts.

### 3.1 What happens under the hood

When you exclude a CVE:

1. The `ExclusionAdded` event is appended to the policy's stream with
   your curator attribution.
2. The `re_evaluate_after_exclusion` cascade fires
   immediately. It scans every artifact whose policy includes this
   exclusion and whose `quarantine_status = 'rejected'`.
3. For each artifact, the cascade checks: are the artifact's *only*
   blocking findings now excluded? If yes:
   - If `quarantine_until` is still in the future →
     `Rejected → Quarantined` (the time hold still applies).
   - If `quarantine_until` has elapsed → `Rejected → Released`
     immediately (the artifact becomes downloadable).

So a single `exclude-finding` call can release **multiple artifacts**
across multiple repositories in one cascade.

### 3.2 The audit chain

The cascade is **fully reconstructable** after the fact. The event
stream carries:

```text
[policy stream]    ExclusionAdded { actor=<your user_id>, cve_id, ... }
[artifact A]       ArtifactReleased { released_by: PolicyReEvaluation, ... }
[artifact B]       ArtifactReleased { released_by: PolicyReEvaluation, ... }
[artifact C]       ArtifactQuarantined { ... }     # window not elapsed
...
```

Your curator-side justification on `ExclusionAdded` is the **single
audit anchor** for every artifact the cascade released — make it
informative.

### 3.3 The pre-flight check

Before exclusion, run the queue listing scoped to `Rejected` to see how
many artifacts your decision will affect:

```sh
# Approximate the blast radius: rejected artifacts whose latest scan
# findings include this CVE. (Exact resolution needs a join the queue
# listing does not expose today; this is an upper bound.)
hort-cli curation queue --status rejected --output json \
  | jq '.entries[] | select(.finding_count > 0)'

# If the count is small and you've reviewed each row, proceed.
# If the count is large, consider the per-policy `package_pattern` field
# on the exclusion to narrow scope before issuing.
```

### 3.4 Reverting an exclusion

`unexclude-finding` runs the same cascade in reverse: artifacts whose
only re-evaluation-released path was this exclusion transition back to
`Rejected`. The audit chain is symmetric (one `ExclusionRemoved` + N
re-evaluations); the cascade emits `Released → Rejected` or
`Quarantined → Rejected` per artifact.

---

## 4. `admin_release` vs `curator-waive` — when to escalate

The two paths are **structurally distinct**, not interchangeable
authority levels.

| Concern                              | curator-waive                          | admin_release                                  |
| ------------------------------------ | -------------------------------------- | ---------------------------------------------- |
| Required permission                  | `Curate` or `Admin`                    | `Admin`                                        |
| Source-state guard                   | `Quarantined` only                     | Any non-terminal state, **incl. `ScanIndeterminate`** |
| Justification cap (≤ 512 bytes)      | yes, required                          | yes, required                                  |
| `released_by` discriminator          | `ReleaseReason::Curator`               | `ReleaseReason::Admin`                         |
| `released_by_user_id` populated      | curator's user_id                      | admin's user_id                                |
| Use case                             | "scan was clean, accept advisory lag"  | "scanner failed, accept the broader risk"      |

**Escalate to `admin_release` when:**

- the artifact is `ScanIndeterminate` (curator cannot waive it);
- the decision genuinely needs the broader admin context (cross-team
  coordination, post-incident review, a policy exception that survives
  the audit cycle).

**Stay on curator-waive when:**

- the scan completed clean and you're shortening the observation window
  for a specific artifact;
- the decision is one of many (curator is the role designed for
  per-artifact day-to-day decisions — that's its whole point).

The choice is recorded in the `released_by` discriminator on the event,
so future auditors see whether each release went through the broader
or the narrower path.

---

## 5. The `quarantineDuration: 0` per-repo opt-out

For repositories where the quarantine posture itself is wrong (an
internal hosted repo of first-party builds where every artifact is
already vouched-for; a build-cache proxy whose contents the upstream
already vetted), the right answer is **not** to curator-waive every
ingest — it is to set `quarantineDuration: 0s` on the repo's
`ScanPolicy`.

```yaml
apiVersion: project-hort.de/v1beta1
kind: ScanPolicy
metadata:
  name: internal-hosted-quarantine-opt-out
spec:
  scope:
    repository: internal-hosted   # `scope: global` is the cross-repo form
  severityThreshold: high         # critical | high | medium | low — required
  quarantineDuration: 0s          # permissive mode — no time gate
  requireApproval: false          # required
  provenanceMode: off             # optional: off | verify_if_present | required
  scanBackends:                   # scan still runs; finding-rejection still applies
    - trivy
```

Permissive mode (`quarantineDuration: 0`) is a supported posture — the
fail-closed scan gate
([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md))
still applies; only
the time gate is collapsed. This is a per-repo posture choice, not a
per-artifact one.

**When to prefer this over curator-waive:** if you're waiving every
ingest from a specific repo, the posture is wrong for that repo —
encode the decision once in policy, not N times in the audit log.

---

## 6. `hort-cli curation` command reference

All decision subcommands require `--justification` (non-empty, ≤ 512
bytes); the CLI rejects malformed input before the HTTP round trip.

```sh
# Decision flows
hort-cli curation waive <artifact_id> --justification <text>
hort-cli curation block artifact <artifact_id> --justification <text>
hort-cli curation block versions \
  --repo <key> --package <name> --versions v1,v2,v3 \
  --justification <text>
hort-cli curation exclude-finding   --policy <id> --cve <id> --justification <text>
hort-cli curation unexclude-finding --policy <id> --cve <id> --justification <text>

# Read surfaces
hort-cli curation queue \
  [--repo <key>] \
  [--status <quarantined|rejected|scan_indeterminate>] \
  [--reason <scanner|curator|curation_retroactive>] \
  [--limit <n>] [--output json|table]

hort-cli curation decisions \
  [--type <waive|block|exclude_finding|unexclude_finding>] \
  [--actor <user_id>] \
  [--repo <key>] \
  [--package <name>] \
  [--since <iso-time>] \
  [--limit <n>] \
  [--by-correlation] \
  [--output json|table]

hort-cli curation exclusions \
  [--policy <id>] \
  [--cve <id>] \
  [--actor <user_id>] \
  [--limit <n>] \
  [--output json|table]
```

**Notes:**

- `curation queue` does **not** accept `--reason corruption` — corrupted
  artifacts (the `ArtifactCorrupted` event) are a structurally
  different concern from curator decisions. The endpoint returns `400`
  on that value. Run the scrubber's separate listing if you need to
  triage corrupted CAS content.
- `curation decisions` defaults to **uncollapsed** (one row per event);
  `--by-correlation` groups by `correlation_id` so a bulk `block
  versions` operation surfaces as one logical decision rather than N
  rows.
- `curation exclusions` reads the projection's current state — distinct
  from `decisions`, which is a point-in-time history. An exclusion is
  active until removed or expired.

---

## 7. `block versions` — the continue-on-error contract

This is the **most operationally subtle** curation surface and the
one operators most often misread.

### 7.1 What the contract says

Event-sourcing rules out "all-or-nothing" — events are immutable, there
is no rollback once appended. The use case picks **continue-on-error**:

- The justification cap is enforced **once** at the call boundary
  (`AppError::Validation` before any append).
- The use case attempts every resolved-and-non-terminal artifact in
  the version list.
- Per-append failures (event-store version conflict on a concurrent
  decision, aggregate-load failure, etc.) **do not abort the call**.
- Each failure lands in `BlockOutcome.failed: Vec<(Uuid, AppError)>`
  with the artifact_id and the per-append error.
- Successful appends are **never** rolled back.

The HTTP layer mirrors this: a `block-versions` call with a non-empty
`failed` array returns `200 OK` (with the full outcome body), **NOT**
`5xx`. Partial success is a successful outcome at the HTTP semantics
level.

### 7.2 What operators MUST do

After every `block versions` call, **inspect the response**:

```sh
hort-cli curation block versions \
  --repo npm-proxy \
  --package left-pad \
  --versions 1.0.0,1.0.1,1.0.2,1.0.3 \
  --justification "..." \
  --output json | tee block-result.json

# Look at the four lists:
jq '{
  correlation_id,
  blocked: (.blocked_artifact_ids | length),
  already_rejected: (.already_rejected_ids | length),
  not_found: (.not_found_versions | length),
  failed: (.failed | length)
}' block-result.json
```

The CLI's table output highlights the `failed` column in red when it
is non-empty; do not dismiss the highlight.

### 7.3 Retrying the failed subset

If `failed` is non-empty, the contract is:

1. **Identify the failed artifact_ids** from the `failed` list.
2. **Map them back to versions** (either from local context or by
   querying the queue / decisions listing for the affected artifacts).
3. **Re-issue `block versions` for the failed subset only** — using
   the **same justification text** as the original call:

```sh
hort-cli curation block versions \
  --repo npm-proxy \
  --package left-pad \
  --versions 1.0.2 \
  --justification "<same justification text as original>"
```

> **The retry call mints its own `correlation_id`.** The server's
> `BlockVersionsUseCase` generates a fresh `correlation_id` per
> invocation (`Uuid::new_v4()`); there is no caller-supplied
> `--correlation-id` seam on `block versions` today (a retry helper
> that reuses the original correlation_id is recognised, deferred
> future work).
>
> **Reconstructing intent across the two calls.** The operator
> correlates the original batch with the retry batch via the shared
> justification text + actor + close-in-time timestamps:
>
> ```sh
> hort-cli curation decisions --by-correlation \
>   --repo npm-proxy --package left-pad
> ```
>
> The two `correlation_id` groups surface as adjacent rows with
> identical `actor` / `kind` / `justification`; visually grouping them
> as one logical decision is the operator step until a retry helper
> lands.

> **Why the same justification.** The justification rides every event
> the call emits, and is the field that ties the original batch to the
> retry batch in the absence of a shared `correlation_id`. Re-issuing
> with a different justification would fragment the audit trail — two
> reasons for what is conceptually one decision. Re-issuing with the
> same text preserves the one-decision framing.

### 7.4 Why not stop-on-first-error

With a `VersionList` carrying tens of resolved artifact_ids, a
stop-on-first-error contract forces the operator to recompute "what
landed vs what was skipped" on every retry. Continue-on-error gives
the operator a single complete result envelope they can act on (retry
the failed subset only). The choice was made deliberately.

### 7.5 The `not_found_versions` caveat

Versions in the `not_found_versions` list **are not auto-blocked on
future ingest**. If the version arrives in the proxy later, it goes
through the normal scan + policy gate (it does **not** automatically
inherit your curator-block intent). Stored curator block-rules (a
forward-blocking layer keyed on `(repo, package, version-range)`) are
**deliberately not built** — a recognised gap, deferred.

If you need to block versions that haven't been ingested yet:

- For a narrow, known set: pre-ingest them (a proxy fetch you trigger
  yourself, e.g. via a placeholder `npm install` against the proxy URL)
  and then block.
- For a forward-looking range: this gap is recognised; until
  stored rules land, the `quarantineDuration` window + the
  scanner DB + advisory-watch cover the common case
  (a CVE published recently, scanner DB catches up before the window
  elapses).

---

## 8. What the system does NOT do automatically (and why)

These deliberate non-features are the same shape as the patch-release
playbook (`docs/architecture/how-to/quarantine-patch-release.md` §6),
extended for the curator surface:

- **No bulk-waive.** Curator decisions are per-artifact and
  justification-gated. A bulk-waive primitive would re-create the
  auto-release pattern the threat model rejects. The
  asymmetric concession is **bulk-block** (the conservative direction —
  more restrictive, never less); waive has no symmetric primitive.
- **No auto-block on future ingest.** Curator block is per-artifact
  retroactive. Stored block-rules (range/pattern-scoped auto-block at
  ingest) are out of scope — see §7.5 above.
- **No notification when items enter the queue.** Operators poll the
  queue listing or wire up external integration via the event-notifier
  (see [event-notifications.md](../explanation/event-notifications.md)).
  The list of "what needs my attention" is a poll, not a
  push.
- **No web UI.** `hort-cli` is the v1 surface. A web UI is a
  separate programme of work, not a follow-on of the curation surface.

The threat-model rationale is the same as in the patch-release
playbook: **automation here is exactly the attack pattern**. xz's
malicious 5.6.0 was framed as a fix-and-improvement release;
event-stream's compromised 3.3.6 was published as a maintenance update
by a takeover account. A self-service or rule-driven release path
would have shipped both payloads to consumers within minutes of
upload. Manual curator decisions with attribution are the
threat-model-aligned answer.

---

## Related

- Patch-release operator playbook: [`quarantine-patch-release.md`](quarantine-patch-release.md)
- Quarantine state model + quarantine-by-default posture + release
  predicate: [ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md),
  [security.md](../explanation/security.md)
- Build-friction reduction (quarantine-aware index + prefetch):
  [prefetch-pipeline.md](../explanation/prefetch-pipeline.md)
- Claim-based RBAC: [`operate/claim-based-rbac.md`](operate/claim-based-rbac.md),
  [ADR 0012](../../adr/0012-claim-based-rbac-claimless-static-tokens.md)
