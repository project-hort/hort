# 302 — The standing decision says one authority owns the manual release

**Issue:** #345 · **Branch:** `agent/345-curation-owns-the-manual-release`
**Governing decisions:** ADR 0007 (the release-authority enumeration and the
`(reason, authority)` pairing), ADR 0055 (the rejected `curate` grant to CI),
ADR 0038 (service accounts are never admin). **This unit amends ADR 0007** —
see *Precondition*.

**Precondition — the ADR text.** The amendment is a new standing decision about
who holds the manual release, so the ADR text and the code land only after the
human has confirmed the wording on #345. If the confirmation is not recorded on
the issue, stop and report that; do not write ADR text and do not implement the
widening in item 303.

## What is true today

ADR 0007 enumerates five release authorities, and line 22 bounds the curator's:

> `CuratorWaiver` — curator waive (`Quarantined`-state only).

The how-to argues the bound as deliberate
(`docs/architecture/how-to/curator-workflow.md:22`–`:40`):

> *"The narrower source-state guard on waive is intentional. `ScanIndeterminate`
> means the scanner could not complete […]; releasing such an artifact requires
> the broader deliberation that `admin_release` represents."*

and §4 (`:381`–`:405`) calls the two paths *"structurally distinct, not
interchangeable authority levels"*.

Measured against `develop`, the two paths differ in three things only: the
permission, the source state, and the `released_by` discriminator. Effect,
attribution, the ignored provenance parameter, the event type and the
re-blockability are identical, and each path has exactly one production caller.

## What to do

1. **Amend ADR 0007's authority enumeration** so the manual release is one
   authority with a state-dependent permission requirement, not two authorities.
   The decision to record (human, 2026-10-11): *admin serves technical and
   operative actions; the curator holds the domain's authority. A curator who
   may override known severe findings may also act when no finding exists yet.*
   The argument the amendment replaces is quoted above and must be quoted in
   the ADR too — a reader has to see which sentence was reversed and why.
2. **Record the axis boundary for a `Rejected` artifact** (item 307's subject,
   decided in the same breath because it is the same authority question). The
   curator's override covers the scan, curation **and provenance** axes, and
   not the corruption tombstone. The boundary is what the curator's instrument
   can reach: comparing this content hash against the publisher's own release
   page answers the question a signature answers, so it reaches a missing or
   even a disproved signature — but it cannot reach bytes that do not match the
   hash naming them, where the comparison confirms nothing and
   `VerifyingReader` fails the read regardless (ADR 0003). Record that the
   provenance position was argued the other way first and withdrawn on that
   reasoning (maintainer, 2026-10-11), so the next reader sees a decision and
   not a silence.
3. **Record what does not change**, because the narrow reading is the one that
   survives review: `Permission::Curate` stays strictly less than `Admin` for
   every other route (`authz/extractors.rs:95`–`:102` rejects *mounting* admin
   routes behind the curate extractor, and this change does the opposite — it
   removes a route from the admin gate). Curation keeps re-blocking a manually
   released artifact (#344's unit 4 partition). `ReleaseReason::Admin` stays in
   the vocabulary because the stream is append-only (ADR 0002).
4. **Rewrite `curator-workflow.md` §1 and §4** to the single path: the
   authority table loses the `ScanIndeterminate` row's "no (admin-only)", and
   §4's escalation section is replaced by the state rule. Keep the operator
   guidance that made §4 useful — *when* to waive and what the decision means —
   and drop only the two-path mechanics.
5. **Correct the authority sentence in `quarantine-patch-release.md:84`.** It
   says the release endpoint requires `Permission::Admin` and warns *"do not
   bind an `hort_svc_*` service token with that permission and call it from
   automation"*. After this change the authority is `Curate`, and the rule that
   keeps automation out is **ADR 0055's** (no `curate` grant for CI) — not a
   token-kind check. Say so, and name `maintainer-curator`
   (`deploy/ansible/files/gitops/auth/service-accounts/maintainer-curator.yaml`)
   as the sanctioned shape of a human curator's credential, so the next reader
   does not mistake `kind: ServiceAccount` for "a pipeline".
6. **ADR 0025 keeps its example** (`POST /api/v1/admin/quarantine/:id/release`
   on a rejected artifact, the 409 rationale). It illustrates a status-code
   decision, not an authority one; update the path only if item 304 removes it,
   and say in the report which you did.

## Explicitly out of scope

- The code change itself (items 303–307).
- Any token-kind or principal-shape gate on the manual release. The deployed
  curator identity *is* a `ServiceAccount` (see item 4 above), so such a gate
  would lock out the operator it is meant to protect; ADR 0055 already governs
  the question and this ticket does not reopen it.
- Who may **block**. Curation already owns it.

## Acceptance

- ADR 0007's authority enumeration reads as one manual authority with a
  state-dependent permission, and quotes the sentence it reverses.
- `curator-workflow.md` has no `admin_release` escalation path left, and no
  sentence claiming the two paths are structurally distinct.
- A grep for `admin_release` across `docs/` returns only historical ADR context
  (0025's example, if item 304 kept the path) — no operator instruction tells a
  reader to use it.
- Gate: not applicable (docs + ADR only). Say so in the report rather than
  running the suite.
