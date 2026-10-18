# 295 — Whoever may read the artifact is told why it is withheld (OCI)

**Issue:** #342 · **Branch:** `agent/342-referenced-blob-deliverability`
**Unblocked (human, 2026-10-12): the ADR 0055 clarification is confirmed.**
**Sequenced after item 324** (2026-10-13): the axis this unit puts on the wire
is `None` on every read path until 324 hydrates it — see §(b).
This unit no longer waits on item 296 — that dependency was written before the
ADR work was re-scoped, and 296's remaining three decisions are about what an
index *offers*, while this unit is about why a refusal *says* what it says. The
text this unit lands in ADR 0055, confirmed verbatim:

> **Clarified 2026-10-12 — the audience is the read gate, not a grant.** "Any
> caller holding `Read`" reads as a grant check, and on a public repository
> there is none: the read gate admits an anonymous caller, so the set entitled
> to a reason is *whoever could read the artifact if it were not withheld* —
> the same set the byte route would have served. The qualifier is unchanged;
> what this states is **who the diagnosis is for**. A reason is therefore owed
> to an anonymous caller on a public repository exactly as to a `Read` holder
> on a private one, and it is owed to nobody the read gate itself would
> refuse: a withheld artifact's reason is not a way around a repository's read
> authority.

It goes after ADR 0055's existing dated clarification (2026-09-17), in that
paragraph's own form, and nothing else in 0055 changes.

**Governing decisions:** ADR 0021 / ADR 0045 (the anti-enumeration collapse —
**not** reopened here), ADR 0055 / ADR 0039 §10 (the grant-based visibility
widening whose predicate shape this reuses), ADR 0039 D5 (a hold with no
self-resolving deadline advertises no deadline), ADR 0034 (the public dogfood
deployment, which is why the predicate is read-gate-based and not grant-based).
This unit **changes a posture** and lands only with the human's confirmation
recorded on #342.

**Relation to the other units:** 294's strongest objection is that a hidden 404
removes the consumer's only diagnostic signal. This unit is what removes that
objection, so if 294 is built, this is built with it. It stands on its own if
294 is dropped.

## What is true today — measured 2026-10-13, and it corrects this item

Three premises in the first revision of this item were wrong. The corrections
narrow the work and remove a requirement that cannot be met.

**(a) Only OCI conceals. The other four formats already answer 403.** The
concealed 404 is an OCI-only posture, at exactly two sites:

- `crates/hort-http-oci/src/blobs.rs:612-617` — `Rejected` ⇒
  `OciError::BlobUnknown`, 404, byte-identical to "no such blob".
- `crates/hort-http-oci/src/manifests.rs:322-327` — `Rejected` ⇒
  `OciError::ManifestUnknown`, 404.

Cargo (`crates/hort-http-cargo/src/lib.rs:464-470`), npm
(`crates/hort-http-npm/src/lib.rs:503-509`), PyPI
(`crates/hort-http-pypi/src/lib.rs:718-724`) and Maven
(`crates/hort-http-maven/src/lib.rs:533-539`) already answer **403** with
`{"error": "artifact is rejected"}`. So the *status code* is already
distinguishable on four of five download paths, and what is missing
**everywhere** is the **axis** — which of scan, curation or provenance
condemned the artifact.

**And there is a third concealing site, in a sixth place, which a grep for
`QuarantineStatus::Rejected` does not find.** PyPI's PEP 658 `.metadata`
route collapses `Rejected` and `ScanIndeterminate` onto a plain 404
(`crates/hort-http-pypi/src/metadata_endpoint.rs:280-295`), because the
**use case** flattens them first:
`crates/hort-app/src/use_cases/wheel_metadata_use_case.rs:233-248` returns
`DomainError::NotFound` for both with the rationale stated inline — *"404,
not 403 — anti-enumeration for the metadata surface; the wheel's existence
stays hidden"* — and its doc comment (`:110-116`) calls that collapse "the
anti-enumeration property **the test matrix pins**" (the test is at `:537`).
ADR 0055 already records both postures as legitimate (`docs/adr/
0055-write-authorized-hold-read-generalised.md:51-64`). So that site is not
an oversight; reversing it reverses a documented, test-pinned decision.

**This unit is therefore OCI only**, and the rest is split off so each piece
is one reviewable change:

- **this unit (295)** — the two OCI concealing sites, the new `OciError`
  variant, the `rejection_reason: None` arm, the ADR 0055 clarification, and
  the architect-guide map. This is the posture change and the reported defect.
- **item 322** — the four non-OCI download paths: add the axis to the 403
  body they already send, and fix the indefinite-hold `Retry-After` of (d).
  No status-code change, no use-case change.
- **item 323** — PyPI's `.metadata` route, because it needs a fourth
  `WheelMetadataServeOutcome` variant and it un-pins a test matrix that
  deliberately asserts the collapse.

**(b) CORRECTED 2026-10-13 — the axis is on the entity and `None` on every
read path.** The first revision of this section claimed the axis needed "no new
read, no new port, no use-case change". That is **false**, it was the unit's
load-bearing premise, and the run stopped on it rather than building around it.

`Artifact.rejection_reason` is declared on the entity, but
`crates/hort-adapters-postgres/src/mappers.rs:324` hardcodes it to `None` in
the only `row → Artifact` mapper, and
`ArtifactUseCase::hydrate_quarantine_deadline`
(`crates/hort-app/src/use_cases/artifact_use_case.rs:721-745`) early-returns
for every status except `Quarantined`, so a `Rejected` artifact never reaches
the stream read. `crates/hort-app/src/use_cases/scan_history.rs:100-103` states
it in prose: *"the artifact entity loaded via `ArtifactRepository::find_by_id`
does not carry it."*

**What went wrong in the specification, for the record:** the claim was
"verified" against the struct **declaration**. A declaration is not a value —
the evidence for "field X is populated at site Y" is X's **producer**, which
here is the mapper and the hydration, and both say the opposite.

**Item 324 is the predecessor that fixes this**, once, for all five formats,
and it owns the ADR 0039 D6 branch's correctness argument. **This unit is
sequenced after 324** and inherits a populated field.

The vocabulary half of the original claim does hold:
`RejectionReason::wire_kind()` (`crates/hort-domain/src/events/artifact_events.rs:1153-1165`)
is the operator-facing lowercase token, exhaustive with no wildcard arm, already
used by the curation-queue row and the `?reason=` filter. It is the only place
the token may come from.

**And the count was wrong: there are seven variants, not six** — `Scanner`
(`:1004`), `Admin` (`:1005`), `CurationRetroactive` (`:1010`),
`ScanPolicyRetroactive` (`:1037`), `Curator` (`:1048`), `Provenance` (`:1071`),
`Corruption` (`:1100`). Any test over "every variant" iterates
`RejectionReason::ALL_KIND_SAMPLES` (`:1118-1130`, seven samples) and never a
hand-written list.

**(c) "The policy" is not recoverable and comes out of the requirement.**
`RejectionReason`'s seven variants (`artifact_events.rs:1003-1100`) carry no
policy identifier: five are unit variants carrying nothing at all (`Scanner`,
`ScanPolicyRetroactive`, `Admin`, `Provenance`, `Corruption`), and the two that
do carry a uuid carry the wrong thing —
`Curator { curator_id }` is an **actor** and `CurationRetroactive { rule_id }`
is a **rule**. Naming the policy would therefore require resolving the
repository's effective policy on the refusal path: a new read on a fail-closed
answer, and a disclosure of operator configuration to an anonymous reader on a
public repository. It buys the consumer nothing — the axis already ends the
search, and the next action (ask the operator) is the same either way. **So the
answer carries axis + digest and no policy.** The two uuids are **not**
published: a curator's identity is a new disclosure about a person, not a
diagnosis of an artifact.

**(d) The hold side carries a real defect in four formats.** The only
production reader of `Artifact.provenance_hold_indefinite` is
`crates/hort-http-oci/src/quarantine.rs:93`. Cargo
(`lib.rs:447-454`), npm, PyPI and Maven (`lib.rs:515-522`) each compute
`Retry-After` as `(deadline - now).max(1)` with a `3600` fallback and **never
suppress it**, so an artifact on an indefinite provenance hold is told to come
back — forever, one second at a time once the window has elapsed. This is
exactly the failure ADR 0039 D5 removed from OCI, surviving in four formats,
and it is inside this unit's acceptance ("what the hold waits for, including
the no-self-resolving-deadline case").

Two things make the concealment posture wrong for a caller the read gate
admits:

- **It protects nothing in this case.** ADR 0021 / 0045's anti-enumeration is
  about *repository* visibility for callers **without** Read: whether a repo
  exists must not leak. A caller the read gate admits already lists the tags
  and already holds the manifest naming these digests. Concealing the *reason*
  from them withholds nothing they could not otherwise obtain — except the one
  fact that would end the search.
- **Its measured cost is days.** The reporter spent "several days and several
  wrong hypotheses" distinguishing a blocked layer from a broken registry, and
  said so on the issue.

## What to do

1. **Say it in the status code, because the body does not arrive.** Measured on
   the issue: the kubelet error does not carry the body — at the cluster the
   operator sees the code only. A header is less visible still. So the signal
   lives in the code, the detail in the body for whoever queries directly:
   - artifact **`Rejected`** ⇒ **403** with a body naming the **axis**
     (`RejectionReason::wire_kind()`) and the **digest**. In OCI this replaces
     the concealed 404 and uses the spec-defined code `DENIED`; in the other
     four it keeps today's 403 and adds the axis.
   - artifact **`Quarantined`** ⇒ unchanged in OCI. `quarantine.rs:93`
     already suppresses `Retry-After` for an indefinite hold, which is the
     behaviour item 322 carries to the other four. Do not touch it.
   - A `Rejected` artifact with **`rejection_reason: None`** is the illegal
     state ADR 0039 D6 names. It answers 403 with the digest and **no** axis,
     and logs at `error` level: the client is not told a reason that does not
     exist, and the operator is told the invariant broke. Do not invent an
     `unknown` axis token.
2. **Key on the read gate itself — whoever could read the artifact if it were
   not blocked learns why it is** (human decision, 2026-10-10: "wenn anonyme
   Leser das Artefakt lesen könnten, wenn es nicht blockiert wäre, dann sollen
   sie auch den Blockierungsgrund sehen können"). By the time the handler
   reaches the status arms the gate has already admitted the caller, so there
   is **no new authorization concept to build and no grant to resolve**: a
   caller entitled to the bytes is entitled to know why they are not getting
   them, and for a public repository the bytes themselves would be public
   anyway, so the reason reveals strictly less than the artifact.
   - A caller who does **not** pass the read gate never reaches these arms —
     an anonymous caller on a private repository still meets the repository
     challenge / `NAME_UNKNOWN` of ADR 0021 / 0045, unchanged. State that in
     the ADR so this is not later read as a loosening of repository
     anti-enumeration; it is not one.
   - Because the predicate is "already admitted", there is **no per-caller
     branch in the answer at all**. One answer per artifact state.
3. **Fix the granularity at axis + digest.** Not the policy (see (c)), not the
   finding list, not CVE identifiers, not the curator or rule uuid. Enough to
   stop the search, not an inventory of weaknesses and not a statement about a
   person.
4. **OCI only in this unit.** Items 322 and 323 carry the other formats; do
   not touch them here, and do not "while I am in there" them. Report the
   census you measure against the sites named in (a) so the siblings start
   from a verified map rather than this one.
5. **Leave ADR 0021 / 0045 standing.** Repository-level denial, the anonymous
   challenge, and the `AuthContext::Disabled` carve-out are untouched; their
   regression groups must stay green unchanged. The ADR says which decision
   moves (artifact-state opacity toward a reader the gate admits) and which
   does not (repository enumeration).
6. **Re-argue the push path's concealment; do not leave its comment pointing at
   a deleted rule.** `crates/hort-http-oci/src/manifests_write.rs:1834-1843`
   folds a terminal referenced blob into the `missing[]` list of a 400
   `MANIFEST_BLOB_UNKNOWN` and justifies itself by citing *"the hidden-404
   posture the blob GET already keeps"*. This unit deletes that posture, so the
   justification has to stand on its own or change. **It can stand**, and the
   argument is available: the caller there is a **publisher**, not a consumer,
   and `MANIFEST_BLOB_UNKNOWN`'s `detail.blobs` already names the offending
   digest — so the publisher is not left searching, which is the harm this unit
   exists to end. Rewrite the comment to that argument. Do not change the push
   path's behaviour here.

7. **The `CurationBlocked` asymmetry is deliberate — record it, do not
   "fix" it.** `blobs.rs:473-487` / `:731-738` and `manifests.rs:1753-1759`
   answer 404 when a curation rule blocks a **pull-through ingest**, and the
   stated reason is client behaviour, not anti-enumeration: *"on a `docker
   pull` cache-miss path that surfaces as a cryptic 403 mid-pull."* After this
   unit, OCI therefore answers two curation refusals two ways — a
   locally-ingested-then-rejected blob gets `403` + `curator`, an upstream blob
   a rule blocks gets `404`. **That stays**, because the two callers are in
   different situations: the first is asking about an artifact this registry
   holds a verdict on, the second about one it never admitted. The guide map
   (task 8) must state **both** answers with their reasons, so the asymmetry is
   a recorded decision rather than a leftover.

8. **Add a new `OciError` variant; do not overload `Denied`.**
   `OciError::Denied { repository, actions }` already exists and already maps
   to 403 `DENIED` (`crates/hort-http-oci/src/error.rs:78, 273, 307`), but it
   means *you may not access this repository*. Overloading it would make
   repository-authorization denial and artifact-state denial indistinguishable
   in logs, metrics and tests. The new variant carries the digest and the axis
   and reports the same spec code `DENIED`.

## Preconditions from item 324 (delivered 2026-10-13, commit `2f1401f2`)

324 is in. `ArtifactUseCase` now hydrates `rejection_reason` from the stream on
every `Rejected` read, for all three load paths, so the axis is available to
this unit as a plain field — no stream read from the format crate, ADR 0008
intact. Two things 324 established that change how this unit writes its tests:

- **The double no longer serves the axis.** `MockArtifactRepository`'s twelve
  artifact-returning reads clear `rejection_reason`, mirroring
  `mappers.rs:324`. So an axis test **must** seed the stream
  (`persisted_artifact_rejected`, `test_support.rs:4213`); setting the field on
  a fixture entity now proves nothing, which is the point.
- **The D6 branch is finally a correct detector.** `error!` means "I read the
  stream and it carries no `ArtifactRejected`"; a read that *failed* warns
  instead. So this unit's `rejection_reason: None` arm is keyed on a fact about
  the stream, not on an un-hydrated field.

**First task, before any refusal work: make the harness helper preserve the
wiring it finds.** `hort_http_core::test_support::with_repository_access`
(`crates/hort-http-core/src/test_support.rs:1974-1989`) builds a **fresh**
`ArtifactUseCase` and chains only `with_repository_access` and
`with_artifact_metadata` — its own doc names the one thing it preserves. So
calling it *after* `with_provenance_hold_hydration` silently drops both the
policy projections and the event-store handle, and the axis comes back `None`
with a warning. This unit is the first to want both helpers at once (an
authz-shaped OCI refusal test), and a helper that silently discards a wired
port is a footgun, not an ordering rule to remember.

Fix it by wiring them from the context the way
`with_provenance_hold_hydration` already does — add
`.with_policy_projections(…)` and `.with_artifact_stream_events(ctx.event_store.clone())`
to the chain — so the helper composes in any order. **Do not** instead document
the ordering: that is defending against the gap rather than closing it. One
commit, before the refusal change, with a test that the composed context still
hydrates.

## Explicitly out of scope

- Any new endpoint or operator surface. This is the shape of an answer the
  caller is already receiving.
- The findings themselves, and any widening of who may read them.
- Telling a caller the read gate refuses anything new.
- **The `ScanIndeterminate` status-code divergence.** Measured 2026-10-13: OCI
  answers 503 `UNAVAILABLE` (`hort-http-oci/src/error.rs:280, 314`) while
  cargo, npm, PyPI and Maven answer 403 for the same state. One of the two is
  wrong, it is a defect in its own right, and it is **not** this unit's — do
  not "unify" it here. It is recorded on the collector.
- Resolving or disclosing the policy behind a rejection (see (c)).

## Acceptance

- A `Rejected` blob and manifest answer **403** with the axis and the digest to
  **every** caller the read gate admits — including an anonymous caller on a
  public repository, which is the case the decision turns on. In OCI the code
  is `DENIED` and the concealed 404 is gone.
- A caller the read gate does **not** admit sees answers byte-identical to
  today, asserted against the existing ADR 0021 / 0045 anti-enumeration tests,
  which stay unchanged.
- The axis token comes from `RejectionReason::wire_kind()` and from nowhere
  else; a test asserts the body's axis for **every** variant by iterating
  `RejectionReason::ALL_KIND_SAMPLES` (seven today), so a new variant cannot
  reach the wire undecided and cannot be missed by a hand-written list.
- The axis tests seed the **stream**, never the fixture field — after 324 the
  mock repository nulls `rejection_reason` on read exactly as Postgres does, so
  a test that sets it on the entity proves nothing.
- `rejection_reason: None` answers 403 with no axis and logs at `error`.
- Neither `curator_id` nor `rule_id` appears in any answer; a test asserts no
  uuid and no CVE identifier is present in the body.
- OCI's hold behaviour is unchanged — `quarantine.rs:93` is already correct
  and `provenance_held_past_window_is_503_with_no_retry_after` must stay green
  untouched. The four non-OCI formats' indefinite-hold defect is item 322's.
- The census you measured is in the report, so items 322 and 323 start from a
  verified map.
- **ADR 0055 carries the confirmed clarification, verbatim**, placed after the
  2026-09-17 paragraph, and nothing else in that ADR is touched. The architect
  guide's enforcement line carries the per-format answer map.
- **State the limit rather than paper over it:** a hold stays `503`, because
  that is the correct semantic, so for a hold the reason travels in the body
  and the server log only — and a kubelet discards the body. Only the terminal
  case gains a distinguishable status code. Do not invent a header to work
  around this; record it.
- ADR 0021 / 0045's regression groups pass untouched — the eight-test group the
  prior run named and ran green is the set to re-run:
  `blobs::tests::blob_read_denial_challenges_anonymous_and_404s_authenticated`,
  `blobs::tests::get_blob_missing_repo_authenticated_returns_404_name_unknown`,
  `manifests::tests::manifest_read_denial_challenges_anonymous_and_404s_authenticated`,
  `tags::tests::tags_read_denial_challenges_anonymous_and_404s_authenticated`,
  `catalog::tests::repo_catalog_read_denial_challenges_anonymous_and_404s_authenticated`,
  `referrers::tests::missing_repo_authenticated_returns_404_name_unknown`,
  `referrers::tests::missing_repo_anonymous_challenges_bearer_when_key_wired`,
  plus `crates/hort-http-oci/tests/v2_auth_e2e.rs`.
- `manifests_write.rs`'s comment no longer cites a posture this unit deleted,
  and the guide map records the `CurationBlocked` asymmetry with its reason.
- ADR 0055's per-format passage credits all four 403 download routes.
- Gate: the **unit gate** — `bash handover/gate-unit.sh -p <the crates this
  unit touches>`, judged by its output and never by the rc, with the full
  workspace suite, `cargo audit`, `cargo deny` and the attribution script left
  to the architect on the same tree. Because the OCI serve composition changes,
  hand the human the **branch** for the compose E2E before any merge request.
