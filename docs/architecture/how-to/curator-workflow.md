# Curator workflow — waive, block, exclude

This guide is for operators acting in the **curator** role: making
day-to-day decisions on artifacts that quarantine-by-default has held,
or that the scanner has rejected, without escalating to a full admin
session. It covers how the curator grant is made, the three decision
flows (waive / block / exclude-finding), how each of the two decision
verbs names its target, the audit trail produced, and the operational
caveats — especially the **finding-exclusion blast radius** and the two
bulk contracts, which are deliberately **not** symmetric: a bulk block
is continue-on-error (§8), a bulk waive is all-or-nothing (§9).

The quarantine state model, the quarantine-by-default posture, and the
fail-closed release predicate are documented in
[ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)
and [security.md](../explanation/security.md).

---

## 1. The curator role

`Permission::Curate` is the decision authority over held artifacts —
the role security / release-team operators act in when they triage what
quarantine-by-default is holding or what the scanner has rejected. It is
**narrower in reach** than `Permission::Admin` (it opens the curation
decision surface and nothing else) and it is **the** authority on that
surface:

| Authority                            | `Permission::Curate` | `Permission::Admin` |
| ------------------------------------ | -------------------- | ------------------- |
| Waive a held artifact (release it)    | yes                 | yes                 |
| Bulk-waive via explicit version list  | yes                 | yes                 |
| Bulk-waive via explicit digest list   | yes                 | yes                 |
| Block any non-terminal artifact       | yes                 | yes                 |
| Bulk-block via explicit version list  | yes                 | yes                 |
| Bulk-block via explicit digest list   | yes                 | yes                 |
| Exclude / unexclude a CVE finding     | yes                 | yes                 |
| All other admin endpoints             | no                  | yes                 |

A batch entry's authority is one decision's authority, so the bulk rows
need no higher permission than the single ones: what keeps a bulk waive
safe is the all-or-nothing contract in §9, not a permission tier. That
also keeps the gitops pipeline — which applies decision files under its
own service identity — able to apply the decisions it declares.

An admin passes the same gate (`CurateOrAdminPrincipal` admits either
permission), so an admin never needs an explicit curate grant — but
nothing on this surface *requires* admin. The manual release reaches
`Quarantined`, `ScanIndeterminate` and — on the axes §4.1
enumerates — `Rejected`; §4 is the state rule.

**The split is one of kind, not of tiers** (see
[the glossary](../../glossary.md) and
[ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)'s
one-authority amendment): admin carries the technical and operative
actions — gitops status, effective config, withdrawing a structurally
invalid state — while a verdict about an artifact is a curation
decision. A curator already decides with findings in view — a held
artifact may carry findings its policy weighed — and the same authority
covers the case where the scanner reached no verdict at all. There is no
second, broader manual release to escalate to.

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
apiVersion: project-hort.de/v1
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
apiVersion: project-hort.de/v1
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

- `Permission::Admin` (any of the admin endpoints — gitops status,
  effective config, repository and policy management, the
  provenance-misrejection repair)
- `Permission::AdminTaskInvoke` (running admin background tasks)
- `Permission::Write` / `Permission::Read` on repositories (a curator
  who needs to inspect artifact content downloads it as themselves;
  curator authority does not synthesise an artifact read grant)
- Any ability to **modify** policy thresholds, repositories, or upstream
  mappings (those remain admin-only)

If an operator needs authority this role does not carry, the correct
flow is to assume an admin session via `hort-cli auth login --admin`
(see
[`using-hort-cli-with-admin-ops.md`](using-hort-cli-with-admin-ops.md)),
not to widen the curator grant. That is a step sideways onto the
technical/operative surface, not a step up: no artifact verdict needs
it.

---

## 2. The three decision flows

### 2.1 Waive — release a held artifact early

**Use it when:** the scan completed clean, the observation window is
still running, and the cost of waiting (downstream consumers stuck on
an older version with a known issue, a critical patch that fixes a
deployed CVE, an urgent dependency-of-a-dependency unblock) outweighs
the marginal risk-reduction of the remaining window.

The same command is the release path for an artifact the scanner could
not assess (`ScanIndeterminate`) — a harder decision, not a different
authority. §4 carries the state rule and what the decision commits you
to.

**Pre-flight check:** look at the queue listing first.

```sh
hort-cli curation queue --status quarantined --repo npm-proxy
# Identify the artifact_id or the digest and, for OCI, the path. Then
# look at its finding count and scan status. A waive is appropriate when
# finding_count = 0 (a completed clean scan)
# or the findings are known false-positives you intend to follow up
# with --exclude-finding.
```

`finding_count` and `max_severity` describe the artifact's **last** scan,
which is the same scan the release verdict is derived from. A finding an
earlier scan reported and a later one did not is not counted here — the
row is in the queue because of what is true now, not because of what was
ever true. An artifact that has never been scanned shows `unscanned` in
both finding columns instead of `0` / empty. OCI rows also show their
stored path, which distinguishes blobs and manifests of the same image.

Every row also carries **`checksum_sha256`**, the SHA-256 of the bytes
the decision is about, and **`tags`**, the mutable refs currently
pointing at those bytes. The two are not interchangeable:

- The **digest is the addressing key.** Read it off the row and hand it
  to `waive digests` (§2.1.2) or `block digests` (§2.2) — that is the
  path for an OCI row, whose `version` is `NULL` by construction, and
  for any decision you want bound to the bytes you reviewed rather than
  to a version string. The table abbreviates it to its first 12 hex so
  the columns stay readable; `--output json` carries the whole 64, which
  is the form a decision is addressed by.
- The **tags are an annotation and never an address.** A ref is a
  mutable pointer — it can be moved to other bytes the moment after you
  reviewed these — so no curation command takes one as a target. Tags
  are there so a human recognises the row (`3.19`, `latest`) before
  deciding about the digest beside them.

**Issue the waive** — one artifact, by id:

```sh
hort-cli curation waive artifact <artifact_id> \
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

`released_by: Curator` with a populated `released_by_user_id` +
`justification` is what distinguishes a human release from the two
automatic ones (`Timer` and `PolicyReEvaluation` leave both fields
`None`), so a single query against the event stream reconstructs every
human-authority release with its attribution. A stream may also carry
`released_by: Admin` from before one authority owned the manual release
— the log is append-only
([ADR 0002](../../adr/0002-event-sourced-artifact-lifecycle.md)), and
such an event reads as the same kind of decision: a named operator
released this artifact on purpose.

**Source-state guard reminder:** the waive releases a held artifact —
`Quarantined` or `ScanIndeterminate` — and overrides a `Rejected` one on
the axes §4.1 enumerates. A state it cannot release from answers
`409 Conflict`
([ADR 0025](../../adr/0025-state-precondition-violations-return-409.md)),
with the state in the message. The queue listing carries the status;
check it before issuing, because the status is also what tells you
*which* decision you are making (see §4).

`waive artifact` is the **only** mode that reaches `ScanIndeterminate`
or overrides a `Rejected` verdict. The two bulk modes below reach
`Quarantined` and `Released` and nothing else: overriding a recorded
verdict is a decision taken with that verdict in view, which is a
one-at-a-time decision by construction.

#### 2.1.1 Waive a batch by version list

**Use it when:** one advisory, one review, several versions of the same
package — and `artifacts.version` is populated for the format (npm,
PyPI, Cargo, Maven).

```sh
hort-cli curation waive versions \
  --repo npm-proxy \
  --package left-pad \
  --versions 1.0.0,1.0.1,1.0.2 \
  --justification "CVE-2026-XXXX not reachable in our configuration per
                    SEC-2026-031; risk-accepted by security@example.com"
```

Every released artifact gets its own `ArtifactReleased` event carrying
the same justification, tied together by one `correlation_id` — so
`curation decisions --by-correlation` surfaces the batch as the one
decision you took. Read §9 before using it: **the batch is
all-or-nothing**, and one entry the server cannot release refuses the
whole call.

#### 2.1.2 Waive a batch by content digest

**Use it when:** the bytes are the address — an OCI row (no `version` to
name), or any release where what you reviewed is a specific artifact
rather than a version string.

```sh
# Read the digest off the queue row (--output json carries all 64 hex).
hort-cli curation waive digests \
  --repo oci-proxy \
  --digests sha256:9f86d081884c…,3f79bb7b435b… \
  --justification "base image rebuilt on patched upstream; scanned clean
                    out of band, risk-accepted by security@example.com"
```

A bare 64-hex digest and the same value with a `sha256:` prefix are one
address — paste whichever your source printed. Any other algorithm
prefix (`sha512:…`) is **refused by name**, not stripped: hort addresses
content by SHA-256
([ADR 0003](../../adr/0003-streaming-enforced-cas.md)), so
stripping it would turn "you asked with the wrong algorithm" into "that
artifact is not here" and send you looking for a missing artifact
instead of a mistyped request.

**A digest that matches more than one live row is refused**, naming the
candidate `artifact_id`s. Identical bytes can be ingested at several
paths, and which of those rows you reviewed is not the server's to
guess. Release the one you reviewed with `waive artifact <artifact_id>`.

**A multi-file release is addressed by digest, not by version.** A
version string resolves to the **first matching row**, and a PyPI
release can hold an sdist *and* a wheel under one version — so
`waive versions` on such a package releases one of the two rows and
leaves the other held. The direction is safe (it releases *less* than
you may have intended, never more), and the queue listing shows both
rows with their own digests. When a version names more than one row,
use `waive digests` and name the rows you mean. `block versions`
resolves the same way, for the same reason.

### 2.2 Block — reject a non-terminal artifact

**Use it when:** you've identified an artifact that should not be
served — a shadow-IT upload, a supply-chain risk surfaced by external
intelligence (out-of-band of the scanner DB), a deprecation you want to
hard-pull rather than wait for clients to update.

Three shapes — the same three `waive` has, addressed the same way:

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

**Bulk by content digest** — for OCI rows, and for any block you want
bound to the bytes rather than to a version string:

```sh
hort-cli curation block digests \
  --repo oci-proxy \
  --digests sha256:9f86d081884c…,3f79bb7b435b… \
  --justification "malicious layer confirmed in these images per
                    GHSA-aaaa-bbbb-cccc"
```

Digests follow the same rules as on the waive side (§2.1.2): the bare
and `sha256:`-prefixed spellings are one address, another algorithm
prefix is refused by name, and a digest matching more than one live row
is refused naming the candidates — block the row you reviewed with
`block artifact <artifact_id>`.

Both bulk variants cap at **100 entries per call** (bounded per-call
work, the same shape as the queue's `limit`). That is four times the
bulk-waive cap, and §9 is why.

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
  "not_found_digests": ["..."],         // same, for a digest-addressed call
  "failed": [["...", "<error>"], ...]   // per-append failures (continue-on-error)
}
```

Both `not_found_*` lists are always present; a call addresses by
versions or by digests, so the other one is empty. The CLI table counts
them in one `NOT_FOUND` column and names the unmatched keys in a
section below it.

See §8 below for the **continue-on-error contract** — this is the
load-bearing operational contract on both bulk block modes.

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

**When one CVE names several exclusions.** A policy can hold more than one
exclusion for the same CVE — they differ by `package_pattern`, and the gitops
envelope's uniqueness rule is `(cve_id, package_pattern)`. A CVE therefore
names a *set*, and the row's identity is its `exclusion_id`. When the set has
more than one member, `unexclude-finding` does not guess: the server answers
`409` listing the candidates and nothing is removed. Repeat the command with
the one you mean:

```sh
hort-cli curation unexclude-finding \
  --policy <policy_id> \
  --cve CVE-2024-XXXX \
  --exclusion-id <exclusion_id> \
  --justification "..."
```

The command prints one `--exclusion-id` line per candidate, each with that
row's `package_pattern` (or `no package_pattern`), so the remedy is
copy-pasteable. `--exclusion-id` **narrows within** the CVE in the path — an
id belonging to a different CVE on the same policy is refused, not obeyed.
`exclude-finding` also prints the new `exclusion_id` when it creates a row.
When the CVE names exactly one exclusion the flag is unnecessary and the
invocation above without it is unchanged.

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
`ExclusionRemoved` payloads carry no actor field by design. The
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

**An exclusion cannot be narrowed to one repository.** `scope` takes
only `global`; a repository scope is refused by both writers (the
`POST` and the gitops apply), because the finding filter never reads it
— so such an exclusion would act globally while reading as narrowed.
The two ways to bound the blast radius are real: `package_pattern`
(§3.3), and scoping the **parent `ScanPolicy`** to the repository you
mean and hanging the exclusion off that policy. A policy scope *is*
enforced.

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

## 4. The manual release — one authority, one state rule

There is **one** manual release, and the curator holds it. What changes
with the artifact's state is not who may decide — it is *what you are
deciding*.

| Source state         | What a waive means there                                                                                                                                              |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Quarantined`        | A verdict exists — clean, or findings the policy weighed and permitted — and you are shortening the remaining observation window. The common case.                     |
| `ScanIndeterminate`  | **No** verdict exists: the scanner could not complete. You are releasing on evidence from outside hort, so the window is not the thing you are overriding.             |
| `None`, `Released`   | Nothing to release — the artifact is already downloadable. Answered `409`.                                                                                            |
| `Rejected`           | A verdict exists and it **blocked**. You are overriding that verdict, not a window — on the axes §4.1 enumerates, and never on the corruption axis. The procedure is §4.1.                   |

**A harder case deserves more deliberation, not a different endpoint.**
Cross-team coordination, a post-incident review, a policy exception
that has to survive the audit cycle — none of those is a second
authority to escalate to; they are the work you do *before* issuing the
waive, and the justification is where that work is recorded. Releasing
a `ScanIndeterminate` artifact is the clearest case: with no verdict to
weigh, everything that justifies the release is out-of-band evidence
(the upstream publish, the maintainer's identity, the changelog, the
advisory), and the person who gathered it is the person who should
decide.

**What a waive is.** It is a risk-accepted, attributed override — your
identity and reason enter the immutable log so a later incident response
can reconstruct who decided and why. From `Quarantined` what you
override is a **time gate**; from `Rejected` it is a **verdict**, which
is a materially larger decision and the reason §4.1 exists. The queue
row carries the status and the finding count, so you know which of the
two you are making before you act.

**What a waive is not.** It is not a posture: if you find yourself
waiving every ingest from one repository, encode that once in policy
(§5) instead of N times in the audit log. And it is not a way to make
findings go away — the findings stay on the stream, the override is
recorded next to them, and if the finding is a false positive the
cheaper and more durable fix is to exclude it (§2.3), which re-judges
every artifact it affects instead of just this one.

**Re-blocking afterwards.** A release you granted is a decision about
*this* artifact, so a **fresh scan's** verdict does not undo it: that
protection is keyed on who released the artifact, and it is scan-axis
wide rather than axis-wide
([ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)'s
one-authority amendment carries the partition). Everything else still
reaches a released artifact — a curator block, a retroactive curation
rule, a provenance disproof, the CAS integrity tombstone (§2.2) — and
so does a `ScanPolicy` **tighten**, which re-judges the whole population
from stored findings and does not ask how an artifact came to be
released (§6). Waiving an artifact does not exempt it from a later
policy decision about the class it belongs to.

### 4.1 Overriding a `Rejected` artifact — which axes, and what to record

A `Rejected` artifact was condemned by a verdict, and `rejected` is
reached on **four** axes. The waive reaches three of them. Which axis
condemned the artifact is the `REJECT_REASON` column of the queue row
(`hort-cli curation queue --status rejected`, filterable with
`--reason <kind>`), and it is the only thing that decides whether the
override is available:

| `REJECT_REASON` on the queue row     | Axis          | Waive reaches it |
| ------------------------------------ | ------------- | ---------------- |
| `scanner`, `scan_policy_retroactive` | scan          | yes              |
| `curator`, `curation_retroactive`    | curation      | yes              |
| `provenance`                         | provenance    | yes              |
| `corruption`                         | CAS integrity | **never**        |

**Why those three and not the fourth.** The boundary is what *your*
instrument can reach, not a ranking of severities. The instrument is the
comparison your job is built on: **this content hash against the
publisher's own release page**. On the scan and curation axes you are
weighing findings, which is the decision the role exists for. On the
provenance axis that comparison answers exactly the question a signature
answers — attribution — and it answers it in both directions: a third
party who attached a broken signature to a genuine artifact leaves the
bytes genuine and the comparison confirms them, while an attacker who
modified the artifact and signed it with their own key fails the same
comparison, so you do not override. On the corruption axis the
comparison confirms nothing, because the bytes hort holds are by
definition not the bytes that hash names — see
[cas-storage.md](../explanation/cas-storage.md)'s scrub table for the
recovery, which is re-ingesting the restored blob, not a release.

The queue's `--reason` filter also accepts `admin`, which the waive
refuses — but no path in hort writes an `admin` rejection, because admin
carries the technical and operative actions and a verdict about an
artifact is a curation decision (§1). If you ever see one on a queue
row, that is worth a bug report, not a waive.

**The procedure.**

```sh
# 1. Find the artifact and read its axis off the REJECT_REASON column.
hort-cli curation queue --status rejected --repo npm-proxy

# 2. Perform the comparison the axis calls for, out of band. For
#    provenance that is this artifact's content hash against the
#    publisher's own release page / release artifact list. For a scan or
#    curation rejection it is the findings themselves: read them, decide
#    whether this deployment's exposure makes them acceptable, and
#    record what made that true.

# 3. Issue the override — the same command as any other single waive.
#    Only `waive artifact` reaches a Rejected verdict; the bulk modes
#    deliberately do not (see 2.1).
hort-cli curation waive artifact <artifact_id> \
  --justification "sha256:<hash> matches the signed release listing at
                    https://example.org/releases/v1.2.3 (checked
                    2026-10-11); upstream signing key rotation broke the
                    attestation, not the artifact. Risk accepted by
                    security@example.com, ticket SEC-4312"
```

**What the justification must record.** On this path it is the whole
audit trail of a decision that overrode a block, so it carries more than
"urgent". Name:

- **the comparison you actually performed**, with the content hash and
  the external source you compared it against (URL, release listing,
  signed manifest), and the date you did it;
- **why the rejection was wrong or acceptable** — a broken attestation
  over genuine bytes, a finding that does not apply to how this artifact
  is deployed, a curation rule that over-matched;
- **who accepted the risk**, by name or team, and the out-of-band record
  (ticket, incident, review) that holds the rest.

"Verified upstream" without the hash and the source is not a record of
anything; a later incident response cannot re-perform a comparison it
cannot see.

**A corruption tombstone answers `409`,** with the axis named in the
message, and no justification changes that. It is not a permissions
problem and not a missing feature: there is nothing an override could
decide, because the bytes are not the artifact's bytes and the read
would fail verification even if the status said `released`
([ADR 0003](../../adr/0003-streaming-enforced-cas.md)'s
read-verification amendment). Restore the blob and re-ingest it.

**After the override** the artifact is `released`, its rejection reason
is cleared, and the ordinary rules of §4's *Re-blocking afterwards*
apply — including that a **fresh scan** verdict will not re-block it,
because you decided with the findings in view. A `ScanPolicy` tighten, a
curator block, a retroactive curation rule, a provenance disproof and
the CAS tombstone all still reach it.

---

## 5. The `quarantineDuration: 0` per-repo opt-out

For repositories where the quarantine posture itself is wrong (an
internal hosted repo of first-party builds where every artifact is
already vouched-for; a build-cache proxy whose contents the upstream
already vetted), the right answer is **not** to curator-waive every
ingest — it is to set `quarantineDuration: 0s` on the repo's
`ScanPolicy`.

```yaml
apiVersion: project-hort.de/v1
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
  negligibleAction: ignore        # optional: ignore | warn | block — informational (unmaintained/unsound) advisory handling; default ignore
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

**Changing the duration re-judges nothing — the sweep tick is the way
out.** `quarantineDuration` is deliberately not a re-evaluation trigger
(§6): editing it re-derives no verdict and moves no artifact's
`quarantine_window_start`, which is immutable once stamped. So setting
`0` on a repository that is *already* holding artifacts releases nothing
at apply time — those artifacts leave the hold when the release sweep's
next tick reaches them and the live gates clear (default every five
minutes), or, per artifact, on a curator waive. How to recognise one
that has not moved is in
[the stranded-artifact guide](recover-stranded-artifacts.md) §6.

---

## 6. Changing a `ScanPolicy` re-judges the existing population — in both directions

> **Read this before you tighten or loosen a live `ScanPolicy`.** A gate
> change is no longer point-in-time at ingest: it re-judges every
> artifact already decided under that policy.

Editing the gate-affecting fields of a `ScanPolicy` —
`severityThreshold`, the blocked-class set, `negligibleAction`, or
removing/adding a CVE finding-exclusion — does **not** only change how
*future* ingests are judged. Hort re-derives each in-scope artifact's
verdict under the new policy and transitions the artifact to match, in
**both** directions:

- **Loosening** (lower the bar, drop a blocked class,
  `negligibleAction: block → warn/ignore`, add an exclusion) releases
  the artifacts the relaxed gate now passes — the same cascade as a
  finding-exclusion (§3), generalised to every gate field. A loosen is
  fail-closed: an artifact is released only when *every* gate that could
  hold it currently clears (scan **and** provenance **and** curation),
  never on the scan re-judgement alone. An artifact rejected for a
  non-scan reason (provenance, curation, corruption, admin) is **not**
  released by a scan loosen.
- **Tightening** (raise the bar, add a blocked class,
  `negligibleAction: → block`, remove an exclusion) **re-holds the
  now-non-compliant population**: artifacts that were `Released` or
  `Quarantined` and whose stored findings now cross the tightened gate
  are re-`Quarantined` / re-`Rejected`. This is the direction that used
  to silently fail-open — an artifact you had just declared
  unacceptable stayed downloadable. It no longer does.

**`quarantineDuration` is not on that list, and that is deliberate:**
this pass re-derives the *verdict* from stored findings, never the
*timer*. Editing the duration therefore re-judges nothing and moves no
artifact's immutable `quarantine_window_start` — the release sweep's
next tick is what acts on the new duration (§5).

### 6.1 What a tightening actually pulls — and what it cannot

A re-hold **blocks future downloads** through the status gate. It does
**not** recall already-served bytes — anything a client pulled before
the re-hold is already on disk somewhere. What the re-hold buys you is
the audit record of the moment of non-compliance and the closed door
going forward; closing the door forward is strictly better than leaving
it open, but it is not a recall. If bytes already in the wild are the
concern, the re-hold is necessary but not sufficient — treat it as a
containment step, not a clean-up.

The timer window is **not** re-opened on a tighten. A re-held artifact
is held on the *verdict*, independent of its original quarantine
deadline.

### 6.2 The evidence model — re-evaluation reads stored findings, never rescans

Re-evaluation does **not** run a scanner. The per-finding scan results
recorded at ingest (`scan_findings`) are the durable **evidence**; the
policy is the **interpretation**. A gate change re-runs the *same* pure
evaluator over the *same* stored findings under the new policy — so:

- the verdict is reproducible and the two directions cannot diverge
  (both derive from one evaluation over one evidence set);
- it works on a waived scope (`scanBackends: []`) — a waiver-released
  artifact has no stored findings, so it evaluates clean and a
  tightening **never** manufactures a violation against it (no
  evidence ⇒ no re-rejection);
- a buggy or stale scanner is *not* corrected by a policy change — that
  needs the findings refreshed (a separate corrective-rescan concern),
  after which re-evaluation re-derives the verdict.

### 6.3 It runs asynchronously, off the request path

A gate-affecting policy mutation **enqueues** a re-evaluation pass and
returns; the pass runs as a worker task over the whole in-scope
population, fully paginated (no fixed cap), and is idempotent
(re-running yields the same verdict). Expect the population to settle
shortly after the change, not synchronously with the apply. Each
transition appends its own audit event naming the policy change that
drove it, and the pass surfaces an outcome breakdown
(`released` / `re_held` / `unchanged`) plus a completeness signal —
see `hort_policy_reevaluation_artifacts_total` /
`hort_policy_reevaluation_population` in the
[metrics catalog](../../metrics-catalog.md) — so a partial pass is
observable, never silent.

---

## 7. `hort-cli curation` command reference

All decision subcommands require `--justification` (non-empty, ≤ 512
bytes); the CLI rejects malformed input before the HTTP round trip.

```sh
# Decision flows — each verb, each addressing mode
hort-cli curation waive artifact <artifact_id> --justification <text>
hort-cli curation waive versions \
  --repo <key> --package <name> --versions v1,v2,v3 \
  --justification <text>
hort-cli curation waive digests \
  --repo <key> --digests <sha256>,<sha256> \
  --justification <text>
hort-cli curation block artifact <artifact_id> --justification <text>
hort-cli curation block versions \
  --repo <key> --package <name> --versions v1,v2,v3 \
  --justification <text>
hort-cli curation block digests \
  --repo <key> --digests <sha256>,<sha256> \
  --justification <text>
hort-cli curation exclude-finding   --policy <id> --cve <id> --justification <text>
hort-cli curation unexclude-finding --policy <id> --cve <id> --justification <text>
#   add --exclusion-id <id> when one CVE names several exclusions (the 409 lists them)

# Read surfaces
hort-cli curation queue \
  [--repo <key>] \
  [--status <quarantined|rejected|scan_indeterminate>] \
  [--reason <scanner|admin|curator|curation_retroactive|scan_policy_retroactive|provenance|corruption>] \
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

- `--reason` is validated **server-side only**. Its accepted set is the
  server's own rejection-reason vocabulary, so it widens whenever a new
  rejection axis lands; an unknown value returns `400` listing the set the
  server actually accepts. The CLI deliberately keeps no copy of that list
  — a stale local copy refuses rows that demonstrably exist, which is
  worse than a round trip.
- `--reason corruption` **is** accepted, and lists artifacts the CAS
  integrity scrubber tombstoned because their stored bytes no longer hash
  to their content hash. It is not a curator decision, but it is a
  rejection a curator will be asked about, and it is reachable here
  because the tombstone records an `ArtifactRejected` of its own. Note
  that a tombstone written by an older Hort carries no such record and
  therefore shows an empty `REJECT_REASON`; it will not match
  `--reason corruption`.
- `curation decisions` defaults to **uncollapsed** (one row per event);
  `--by-correlation` groups by `correlation_id` so any bulk operation —
  a `block versions` / `block digests` call, a `waive versions` /
  `waive digests` call — surfaces as one logical decision rather than N
  rows.
- **The flat `curation waive <artifact_id>` form no longer exists.** It
  is `curation waive artifact <artifact_id>`. A script still running the
  old form gets a message naming the replacement, not a bare clap
  error — but it does not run, so fix the line.
- The digest flags take the bare 64-hex or the `sha256:`-prefixed
  spelling interchangeably, on both verbs (§2.1.2).
- `curation exclusions` reads the projection's current state — distinct
  from `decisions`, which is a point-in-time history. An exclusion is
  active until removed or expired.

---

## 8. `block versions` / `block digests` — the continue-on-error contract

This is the **most operationally subtle** curation surface and the
one operators most often misread. Both bulk block modes share it; §9 is
its deliberate opposite on the waive side, and the two must not be
tidied into one shape.

### 8.1 What the contract says

Event-sourcing rules out **rollback** — events are immutable, so once an
append has landed nothing takes it back. A bulk verb therefore has
exactly two honest contracts: apply what it can and report the rest
(continue-on-error), or refuse the whole batch *before the first append*
(all-or-nothing, which is what §9 does). Block picks
**continue-on-error**, because what lands is the restrictive direction:

- The justification cap is enforced **once** at the call boundary
  (`AppError::Validation` before any append).
- The use case attempts every resolved-and-non-terminal artifact in
  the version or digest list.
- Per-append failures (event-store version conflict on a concurrent
  decision, aggregate-load failure, etc.) **do not abort the call**.
- Each failure lands in `BlockOutcome.failed: Vec<(Uuid, AppError)>`
  with the artifact_id and the per-append error.
- Successful appends are **never** rolled back.

The HTTP layer mirrors this: a `block-versions` / `block-digests` call
with a non-empty `failed` array returns `200 OK` (with the full outcome
body), **NOT** `5xx`. Partial success is a successful outcome at the HTTP
semantics level.

### 8.2 What operators MUST do

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

### 8.3 Retrying the failed subset

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

### 8.4 Why not stop-on-first-error

With a `VersionList` carrying tens of resolved artifact_ids, a
stop-on-first-error contract forces the operator to recompute "what
landed vs what was skipped" on every retry. Continue-on-error gives
the operator a single complete result envelope they can act on (retry
the failed subset only). The choice was made deliberately.

### 8.5 The `not_found_versions` / `not_found_digests` caveat

Keys in the `not_found_versions` / `not_found_digests` lists **are not
auto-blocked on future ingest**. If the version arrives in the proxy
later, or those bytes are ingested at some other path, it goes through
the normal scan + policy gate (it does **not** automatically inherit
your curator-block intent). Stored curator block-rules (a
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

## 9. `waive versions` / `waive digests` — the all-or-nothing contract

The bulk waive is the **fail-open** half of curation, and its contract is
the inverse of §8's on purpose. A future editor tidying the two into one
shape would be removing the asymmetry deliberately — don't.

| | bulk **block** | bulk **waive** |
| --- | --- | --- |
| entries per call | 100 | **25** |
| one bad entry | reported, the rest still applies | **the whole batch is refused** |
| partial application | yes, and it is not rolled back | **never** |
| HTTP answer on a bad entry | `200 OK` with the outcome body | `409 Conflict` with the per-entry report |

### 9.1 Why the two differ

`ArtifactReleased` is **history that cannot be retracted.** Nothing
un-releases an artifact: a later block is a new decision over bytes
consumers may already have pulled. So releasing the resolvable subset of
a list you wrote wrongly is not a kindness — it is the defect this
contract exists to prevent. A block you did not mean, by contrast, is
reversible by the same curator a minute later, and the artifact stayed
*unavailable* in the meantime; continue-on-error there costs an operator
a retry, not a release they never reviewed.

The same reasoning sets the caps. Twenty-five entries is a list a curator
can still have read line by line before signing one justification for all
of them; the block side can afford four times that because its failure
mode is a hold, not an exposure.

### 9.2 What an abort looks like

One entry that is unresolvable, ambiguous, or in a state the bulk waive
does not reach (anything other than `Quarantined` / `Released`) refuses
the call:

```sh
hort-cli curation waive versions --repo npm-proxy --package left-pad \
  --versions 1.0.0,9.9.9 --justification "…"
# exit status 3
```

```text
BATCH ABORTED — nothing was released. 1 of 2 entries cannot be released;
a bulk waive is all-or-nothing because a release cannot be retracted.
Fix the entries below and re-run:
KEY    ARTIFACT_ID                           VERDICT       DETAIL
1.0.0  7c0e…-…                               releasable    -
9.9.9  -                                     unresolvable  -
```

The report names **every** entry, the fine ones included, so you can see
which one stopped the batch without bisecting your list. `--output json`
hands back the server's report verbatim for a script to branch on; the
command exits **3** (distinct from `0` for an applied batch and from `1`
for a request that never got an answer — a 403, a bad repository key, a
transport failure).

Per-entry verdicts you will see:

| verdict | what it means | what to do |
| --- | --- | --- |
| `releasable` | this entry was fine | nothing — it is listed so you can see it was not the problem |
| `already_released` | already `Released`; an idempotent no-op | nothing — a re-applied decision file converges instead of failing forever |
| `unresolvable` | no live row matches the key | check the spelling, or the repository, or whether the artifact was ever ingested |
| `ambiguous` | the digest names more than one live row | release the row you reviewed with `waive artifact <artifact_id>` — the report lists the candidates |
| `state_not_releasable` | the row is in a state a bulk waive does not reach | read the `DETAIL` status; a `Rejected` verdict is overridden one artifact at a time (§4.1), and a `scan_indeterminate` hold has an exit that is not a curator override (the rescan sweep re-picks it) |

### 9.3 After an applied batch

A `200` partitions the call into three lists, and the first two are
**different facts**:

- `released_artifact_ids` — released **by this call**; one
  `ArtifactReleased` event each.
- `already_released_ids` — released **earlier**; idempotent, no event
  appended now. An operator who reads this as the first believes a
  waiver took effect now when it took effect before.
- `failed` — entries that passed pre-validation and then lost their
  append (a concurrent decision on the same artifact, say). The CLI
  highlights the count; re-issue for that subset, with the same
  justification text, exactly as §8.3 describes for the block side.

A non-empty `failed` is still a `200` and still exits `0`: those entries
are per-artifact apply failures inside a batch that *was* valid, and the
envelope is how you learn which.

---

## 10. What the system does NOT do automatically (and why)

These deliberate non-features are the same shape as the patch-release
playbook (`docs/architecture/how-to/quarantine-patch-release.md` §6),
extended for the curator surface:

- **No rule-driven or self-service release.** Both bulk decision verbs
  take an **explicit list** the curator wrote, under one
  justification — that is what makes a batch a reviewed decision rather
  than an automation. There is no range, no pattern, no predicate, and
  nothing that releases on a condition; the bulk waive additionally
  refuses the whole batch rather than release an entry the curator's
  list named wrongly (§9). A rule that released artifacts matching a
  shape is the auto-release pattern the threat model rejects, and it
  stays unbuilt.
- **No auto-block on future ingest.** Curator block is per-artifact
  retroactive. Stored block-rules (range/pattern-scoped auto-block at
  ingest) are out of scope — see §8.5 above.
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
