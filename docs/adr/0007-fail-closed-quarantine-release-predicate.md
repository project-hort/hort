# 0007 — Fail-closed quarantine release predicate

- **Status:** Accepted
- **Enforced by:** the background sweep releases an artifact only when `quarantine_until <= now()` **AND** the application layer can supply a recognised release authority; the predicate accepts exactly six `(reason, authority)` pairs (five as originally decided, plus `ScanRecorded` — 2026-08-21 — and `ScanCleared` — 2026-10-11, minus `AdminOverride`, folded into the single manual authority — 2026-10-11) and denies every other. The predicate is implemented in `Artifact::release` (`crates/hort-domain/src/entities/artifact.rs`) with exhaustive per-authority tests; the architect anti-pattern *scanner clean → immediate release* is a review hard-block.
- **Supersedes:** —

## Context

Quarantine is the observation window that lets a scan run and lets a malicious package's reputation catch up before it can be downloaded or promoted. Two failure modes must be impossible: (1) a clean scan releasing an artifact *early* (before the window elapses), and (2) a never-successfully-scanned artifact releasing on the timer alone when its window expires. Both would let an unvetted artifact through.

`quarantine_until <= now()` answers "is the window over?" — it must never, by itself, answer "may this be released?".

## Decision

Downloads are blocked while `quarantine_status = 'quarantined'`, regardless of the timestamp — the **status** is the gate, the **timestamp** is only the sweep's candidacy filter.

The background sweep transitions an artifact to `released` only when `quarantine_until <= now()` **AND** a release authority is available. The release predicate accepts **exactly six authorities** — the five originally decided, plus `ScanRecorded` (2026-08-21) and `ScanCleared` (2026-10-11), minus `AdminOverride`, which the 2026-10-11 one-authority amendment folded into the single manual authority — and denies every other `(reason, authority)` pair. Slot 3 below is struck rather than renumbered, so every ordinal this ADR cites still names the authority it named when it was written:

1. `ScanSucceeded` — a successful `ScanCompleted` on the artifact stream.
2. `ScanWaived` — the resolved `ScanPolicy` declares `scan_backends: []`.
3. ~~`AdminOverride` — explicit admin release.~~ Retired by the one-authority amendment below (2026-10-11): the manual release is item 4, in every state it reaches. `ReleaseReason::Admin` stays readable on historical streams — the stream is append-only (ADR 0002).
4. `CuratorWaiver` — **the** manual release: a curator decided this artifact's case and recorded a justification. One authority for the whole manual surface, with a source-state rule in place of the second permission tier it used to share the surface with (one-authority amendment below — it reverses this item's former `Quarantined`-only bound).
5. `PolicyReEvaluation` — post-exclusion policy re-evaluation.
6. `ScanRecorded` — the artifact was scanned and the resolved `ScanPolicy` declares `enforcement: record` (added by the 2026-08-21 amendment below; not part of the original five).
7. `ScanCleared` — the artifact was scanned, its findings exist, and the policy verdict recorded beside the scan did **not** block. Distinct from `ScanSucceeded`, which asserts an empty finding list, and from `ScanRecorded`, which asserts the operator declared a *blocking* verdict non-gating (added by the 2026-10-11 amendment below; not part of the original five).

`ScanCompleted(clean)` does **not** clear `quarantine_until` or set `released`. `ScanCompleted(findings)` sets `rejected` **iff the policy verdict recorded beside it blocks** — the finding list is evidence, the `PolicyEvaluated` verdict is the decision (2026-10-11 amendment). Where it does block, time never reverses it. A scan job that exhausts retries fails closed — see the exhaustion split below.

### "A successful `ScanCompleted`" means the latest verdict, not mere presence (issue #108, amended 2026-08-05; human-approved via `workflow::ready`)

Authority 1 above reads "a successful `ScanCompleted` on the artifact stream" — this was under-specified enough to have been misimplemented as *any* `ScanCompleted`, full stop. That is wrong: the **rejecting** scan branch (the `ScanCompleted(findings)` → `rejected` path noted above) itself commits a `ScanCompleted` event — with a nonzero `finding_count` — immediately before the `ArtifactRejected` that makes the verdict terminal. A presence-only reading of authority 1 therefore treated a dirty scan's own rejection record as a release authority for the very artifact it had just condemned, defeating the `rejected` status it landed in the same commit (issue #108 H3 — closed by hardening the two verdict-commit paths that made the resulting timer-release *reachable*, items 1–2 of the same issue; this clarification closes the authority predicate itself as defense-in-depth, so the amplifier cannot resurface even if a future write path reopens the underlying race).

**"Successful" is defined precisely as:** the artifact's **latest** `ScanCompleted` on the stream carries `finding_count == 0`, **AND** no `ArtifactRejected` appears **later** on the stream than that `ScanCompleted`. Both clauses matter and are independent failure modes:

- A stream whose latest `ScanCompleted` is dirty (`finding_count > 0`) never authorizes release, regardless of how many earlier clean scans preceded it — the latest verdict governs, not any-verdict-ever.
- A stream whose latest `ScanCompleted` is clean but is followed by a later `ArtifactRejected` (an admin/curation rejection landing after the scan, for instance) also never authorizes release — the clean scan is stale with respect to the subsequent rejection.
- Symmetrically, an earlier dirty scan + rejection followed by a genuinely later clean **rescan**, with no further rejection after it, DOES authorize release — the predicate is about the latest verdict on the stream, not "was there ever a rejection anywhere in this artifact's history".

This reads the SAME artifact stream `resolve_release_authority` already reads to check for presence; no new port, query shape, or release authority is introduced. The other four authorities (`ScanWaived`, `AdminOverride`, `CuratorWaiver`, `PolicyReEvaluation`) are unaffected — this clarification is scoped to authority 1 alone.

### Scan-execution failure vs ambiguous result on retry-exhaustion (issue #6, amended 2026-07-14)

A `ScanRunOutcome::Failed` that exhausts `HORT_SCANNER_MAX_ATTEMPTS` is a scanner-**execution** failure (every configured backend errored — the scan could not run), which is operationally distinct from a genuinely ambiguous scan **result**. On exhaustion, `ScanOrchestrationUseCase::record_outcome` splits by the artifact's **current** `quarantine_status`:

- **`quarantined`** (mid-observation-window) → the artifact **stays `quarantined`**. No `ScanIndeterminate` event and **no `quarantine_status` UPDATE at all** — the failed `jobs` row (`status='failed'`, `last_error`) is the persisted "last scan errored" signal. It is re-picked by `RescanCandidatesRepository::select_stranded` + `CronRescanTickHandler` and re-scanned once the scanner recovers, self-healing without operator intervention.

  **Amended (issue #115, 2026-08-05) — "failed **or no job row at all**".** The rescue path above keyed on a *failed* job row, which silently excluded a second, worse stranding shape: an artifact quarantined with **no `kind='scan'` job ever enqueued**. Such a row is invisible to `select_eligible` (which requires `released`/`NULL`) *and* to the original `select_stranded` (whose `JOIN LATERAL` on the most-recent scan job produces no join row at all when none exists) — so it stays `quarantined` and 503s indefinitely, and with no manual per-artifact rescan surface in the product there is no operator recovery. The concrete producer was the seed-import cutover path (`register_by_hash_inner`'s `quarantine_anchor_override` branch), which stamped the backdated anchor without enqueueing the scan; that inflow is now closed at the source (the branch enqueues scan + provenance atomically with the quarantine transition, the same `commit_transition_with_enqueues` shape `ingest_inner` uses). For the rows already stranded in deployed environments, `select_stranded` is widened to a `LEFT JOIN LATERAL` with predicate `(last_job.status = 'failed' OR last_job.status IS NULL)`.

  The widening carries a **scan-policy guard**, and it is load-bearing: candidacy additionally requires the artifact's resolved policy (repo-scoped-else-global-else-`DefaultPolicy`, the same resolution `select_eligible` uses) to actually scan — `COALESCE(cardinality(scan_backends), <default-len>) > 0`. A job-less quarantined artifact under a `scan_backends: []` (ScanWaived) policy is **not** stranded: it releases via the existing `ScanWaived` authority, and enqueueing a scan for it would contradict the operator's own explicit opt-out. Terminal states (`rejected`, `scan_indeterminate`) and `is_deleted` remain never selected, exactly as before. No new release authority is added — this only restores the *scan* that the existing authorities already required.
- **any other status** (`None` — the permissive default, no window to fall back into; or an already-terminal status) → terminal **`scan_indeterminate`**, exactly as before this amendment. A best-effort artifact-load failure resolves to `None` here and therefore also fails to `scan_indeterminate` (safe direction).

**Why staying `quarantined` is still fail-closed.** The two impossible failure modes in *Context* are unchanged. A `quarantined`, never-successfully-scanned artifact is **not** releasable by the timer: release still requires one of the five enumerated authorities, and the only one the sweep can synthesize is `ScanSucceeded` — derived from a `ScanCompleted` **event on the artifact stream**, which a stranded artifact does not have. `resolve_release_authority` returns `None`, the sweep skips it (`skipped_no_authority`), and `Artifact::release` re-denies deny-by-default. Window expiry remains candidacy-only. This amendment adds **no new release authority** and changes **no** release path; it only avoids escalating a recoverable outage to the stricter terminal state, so the artifact can heal via the *existing* `ScanSucceeded` path instead of requiring an admin override.

### Referenced-tree descendant zero-window carve-out (issue #46, amended 2026-07-17)

A **scoped carve-out**, NOT a reversal of the rejected "clean scan releases immediately" alternative below: a scanned-clean artifact that is a `content_references` **target** of an already-ingested parent (a referenced-tree descendant — e.g. an OCI image-index child manifest, or a manifest's config/layer blob) releases on its own `ScanSucceeded` **without re-applying the observation window**; forward observation is the standard released-artifact rescan.

**Why this loses no protection:**

1. **No in-window rescan (verified).** `RescanCandidatesRepository::select_eligible` rescans only `released`/`NULL` artifacts on the 24h interval — the window never re-scans a `quarantined` artifact. So for *every* artifact, quarantined or not, the window is a single-scan-at-ingest + timer, not a rescan mechanism; it does not itself realise "reputation catch-up."
2. **Fresher scan.** The descendant is scanned at first-touch against the *current* CVE database — strictly more recent than the parent's ingest-time scan the operator already trusted at release.
3. **Identical forward observation.** On release the descendant enters the same 24h released-artifact rescan pool as everything else; post-release CVEs are caught identically to any other released artifact.

**Explicitly narrow.** This is *not* the general "clean scan releases immediately" alternative (below), which stays rejected. Only `content_references` **targets** qualify — an artifact with no parent referencing it keeps the full window, unchanged. A blob touched before its referencing manifest exists (no edge yet) takes the normal window; a later re-touch after the edge appears is a non-issue because the pull flow ingests the manifest before its blobs.

**The two impossible failure modes from *Context* are preserved verbatim:**

1. A clean scan cannot release *early*: the release predicate is completely untouched (`Artifact::release`'s deny-by-default `(reason, authority)` match) — a descendant still needs its own `ScanSucceeded`; releasing purely because the window collapsed to zero, with no scan, remains impossible.
2. A never-successfully-scanned artifact cannot release on the timer alone: the carve-out changes only the ingest-time **anchor** (`quarantine_window_start`), never the authority check — `resolve_release_authority` still requires a real `ScanCompleted` event on the artifact's own stream.

**As-built:** the anchor-backdating lives in `IngestUseCase::ingest_inner` (`crates/hort-app/src/use_cases/ingest_use_case.rs`) — a referenced-tree-descendant artifact's `quarantine_window_start` is set to `ingested_at - effective_duration` instead of `ingested_at`, so the live-computed deadline (`effective_quarantine_deadline(anchor, duration)`) equals `ingested_at`. The target-check excludes the self-referencing refcount kinds `primary_content` / `metadata_blob` — every artifact's own ingest writes a `primary_content` row targeting its own hash, so an unfiltered "is this hash a target of any kind" check would misidentify every artifact as its own descendant; this exclusion is load-bearing for the carve-out to stay correctly scoped. The predicate itself now lives in one shared helper (`hort_app::use_cases::referenced_descendant::is_referenced_tree_descendant`) used by both the ingest anchor decision and the provenance hold below, so the two definitions cannot drift.

#### The window is ALSO the `Required`-mode provenance hold predicate (issue #115, amended 2026-08-05)

The #46 rationale above was written against the **scan** release authority, and its "the window is pure latency for every artifact, not protection" claim is correct *on that axis*. It missed that `window_open` had since become load-bearing on a **second** axis: it is the HOLD predicate for the `NoAttestation × Required` provenance arm (issue #13). Collapsing the window to zero therefore did not merely remove a timer for descendants — it flipped "held pending signature" to "terminally rejected as `Unsigned`" the instant a descendant's ingest-enqueued `provenance-verify` ran.

That is a real, reachable failure: OCI pull-through writes `oci_config`/`oci_layer` edges *before* the blobs are pulled, so every layer ingests as a zero-window descendant; cosign signs only the top-level digest, so a layer has no attestation of its own and never will; under `Required` the verify resolved `NoAttestation × window_open == false` → terminal `Rejected{Unsigned}` — **before** the subject's signature cascade could clear the constituent. `cascade_provenance_clearance` refuses a rejected constituent ("terminal is terminal"), so a correctly-signed multi-layer image became permanently unpullable.

**Decision:** `Artifact::complete_provenance`'s `NoAttestation × Required` arm holds on `window_open || is_referenced_descendant`. A descendant's provenance authority **is its parent's signature** — delivered by the ADR 0039 cascade, not by an attestation of its own — so it must never be terminally rejected for lacking one. This is scoped exactly like `window_open`: **only** that arm consults the flag. A forged / untrusted / digest-mismatch signature on a descendant is position-independent (already wrong) and still rejects terminally, so the carve-out cannot launder a tampered layer.

**This strengthens fail-closed rather than relaxing it.** The held descendant stays `Quarantined` — not downloadable, 503 — until either the cascade clears it or an admin releases it under the ADR 0025 source-state rules. An unsigned parent under `Required` leaves its constituents held **forever**, which is the correct outcome and, unlike the terminal rejection it replaces, is recoverable: sign the parent, the S3 hook re-verifies the subject, the cascade clears the constituents. No release authority is added; `Pending` is the fail-closed reading at the release gate either way.

The carve-out is automatic (derived from the reference graph), not an operator opt-in, so it adds no ADR 0016 cross-opt-in matrix row — it is recorded here as a prose interaction between two existing mechanisms.

### `register_by_hash` is gated for every caller, not only the ingest path (issue #107, amended 2026-08-09; human-approved via `workflow::ready`)

The quarantine gate was applied by the ingest path, while `register_by_hash`
— the path that registers a blob already present in CAS — reached the same
artifact table without it. Two callers exercised that gap: the OCI cross-repo
blob **mount**, and a **pull-dedup follower** registering the leader's fetched
bytes. Both produced a target-repository row that had never been held and
never been scanned, and served it.

**The gate belongs to the artifact row, not to the code path that created
it.** `register_by_hash` resolves the target repository's active policy and,
for a non-zero effective duration, commits the `None → Quarantined`
transition together with its scan and provenance enqueues in one transition —
the same shape the ingest path uses. A freshly mounted or follower-registered
blob is therefore held for the target repository's window and scanned before
it serves. `quarantineDuration: 0` remains the single honoured permissive
opt-out, exactly as on the ingest path.

**Source-status refusal is anti-enumeration-shaped.** When registration names
a source row, a source in a terminal state (`Rejected` / `ScanIndeterminate`)
is refused **as `NotFound`**, so a caller cannot distinguish "no such blob"
from "terminally blocked blob"; the OCI handler then falls through to a
regular upload per the spec, with no handler-level special case. A
`Quarantined` source stays mountable on purpose: the target copy is itself
quarantined and scanned under the rule above, so no unscanned bytes serve,
and refusing it would break legitimate mid-window mounts for no gain.

### The scan axis covers artifacts with a scannable surface (clarified 2026-09-18, no new authority)

Authority 1 ("a successful `ScanCompleted`") presumes there is something for a scanner to examine. Some artifacts carry **no package surface at all, by construction** — a manifest row that binds no runnable filesystem (an image index, an artifact or attestation manifest), a non-tar OCI blob such as the image config JSON. **Narrowed 2026-10-19 by [ADR 0064](0064-a-filesystem-finding-is-about-the-composed-filesystem.md):** an *image* manifest is no longer in this list — it binds the composed filesystem and therefore carries the only package surface that describes what an operator runs. No scanner can assign them a threat level, because there is nothing in them for an analyzer to claim. Treating the resulting absence of a verdict as the fail-closed absence this ADR holds on is a category error rather than caution: the hold has nothing to wait on, so it never lifts and a Trivy-policed OCI repository holds every image it ingests, forever.

**Clarification (no authority added, none changed):** the fail-closed rule governs an *expected* surface that could not be assessed. For an artifact with no surface, the recorded assessment is **"not applicable"** — a completed assessment with nothing to assess. It satisfies authority 1 exactly as a clean verdict does, and the **time gate alone** governs the release; the observation window is not shortened, skipped or otherwise weakened. The trail stays honest: `ScanCompleted.assessment` distinguishes `analysed` from `not_applicable`, so a reader can never mistake "nothing to assess" for "examined and clean", and the terminal-decision counter `hort_scan_terminal_total{result="not_applicable"}` keeps the two apart in monitoring.

The **code-level definition** of "nothing for this artifact to be held for" is `NotAnalysable::gates_release` (`crates/hort-domain/src/ports/scanner.rs`) answering `false`, and that is the single place the split is decided. `NotAnalysable::NotApplicable` answers so unconditionally — it is the absence of a surface. One sibling answers so conditionally, and it is the only one: `UnsupportedContainer` (a container this adapter has no decoder for) does not hold an **OCI blob** under a scan policy that has promoted the composite verdict, because the composition that binds the layer decodes it and owns its filesystem verdict ([ADR 0064](0064-a-filesystem-finding-is-about-the-composed-filesystem.md) D2) — the same "this surface is assessed elsewhere" reasoning the rootfs-empty clarification below now rests on. The predicate therefore takes the artifact's kind and the resolved `compositeVerdictMode` alongside the reason; **no eighth authority is added**, and the release predicate above is untouched. Its siblings `UnusableArchive` (an archive the adapter refused to unpack) and `NoAnalyzerMatched` (a materialised target no analyzer claimed) are an expected surface left unassessed and keep the fail-closed `scan_indeterminate` hold unchanged — a single one of them among the abstentions holds the artifact even when every other backend abstained as not-applicable. Advisory enrichment that produced a finding while every backend abstained also keeps the hold: something did have an opinion, so "nothing to assess" would be a false statement.

Consequence for future work: a new `NotAnalysable` variant has to state which side of `gates_release` it falls on (the match is exhaustive, so it cannot inherit an answer), and "not applicable" must never be widened into a way to *skip* a scan an operator asked for — `scan_backends: []` is the sanctioned waiver (authority 2) and stays the only one.

**Further clarification (same date, still no new authority; reason replaced 2026-10-19 by [ADR 0064](0064-a-filesystem-finding-is-about-the-composed-filesystem.md)): a `rootfs`-target scan that comes back empty is "not applicable", not unassessed.** The reason originally given here — that Trivy's `rootfs` target runs every OS-package, language and binary analyzer over the *whole* materialised tree, so an empty result is those analyzers agreeing the tree carries no package surface at all — is **false**, and was measured to be: the OS-package analyzer does not run over a tree that carries a package database but no OS marker; it is skipped for want of an identity, so an empty report is also what a package-bearing layer with no marker produces. The mapping stands for a different reason. Under ADR 0064 the OS-package surface of a layer is assessed by the **composition** that contains it, which is itself a required scan unit; a layer's empty `rootfs` report therefore means "this surface is assessed elsewhere", not "this surface does not exist", and holding the layer for it would hold an obligation that is already owned. Without the mapping a layer would reach no release authority of its own at all; **no eighth authority is added** by ADR 0064, and the release predicate above is untouched. A `fs`-target scan is the other shape: it targets one artifact whose analyzer either engages or does not, so an empty result there stays an *expected* surface left unassessed and keeps the fail-closed `NoAnalyzerMatched` hold.

### A sixth authority: `ScanRecorded` under `enforcement: record` (amended 2026-08-21)

`ScanPolicy` gained an `enforcement: reject | record` mode. Under `record`
the scan still runs, the findings and the `PolicyEvaluated(Fail)` verdict are
still persisted, and the artifact is **not** rejected — the operator has
declared that a scan verdict does not gate publication for that scope
("publish proceeds with findings; blocking at retrieval is the consuming
policy's job").

That declaration cannot be honoured without a release authority. Such an
artifact's own latest `ScanCompleted` carries `finding_count > 0`, so
authority 1 is by construction unavailable to it; with no authority the
artifact stays `Quarantined` and 503s forever — the operator's opt-in would
be inert (ADR 0015). The predicate therefore accepts a **sixth** authority:

6. `ScanRecorded` — the artifact was scanned, and its resolved `ScanPolicy`
   declares `enforcement: record`.

**Why a new variant rather than widening an existing one.** Both
alternatives were considered and are worse, for the same reason:

- *Widening `ScanSucceeded`* would make the "latest verdict, not mere
  presence" clause above (`finding_count == 0`) conditional on a policy
  field — softening a defence-in-depth hardening — and would stamp
  `authority = scan_succeeded` on a release of an artifact that did not
  pass, destroying the audit trail's ability to distinguish the two.
- *Reusing `ScanWaived`* would assert the operator declared the scope
  un-scanned, which is precisely what did **not** happen here: the scan ran
  and its evidence exists.

A distinct token keeps "released with recorded, over-threshold findings"
queryable, and leaves all five existing arms byte-identical. This is the
"adding any new release path means adding an authority to the enumerated
predicate, with its own guard" consequence below, applied as written.

**Its guard, and what it does not relax.** `ScanRecorded` is constructible
only by the application layer, from two verified facts: a `ScanCompleted`
exists on the artifact's own stream with **no later `ArtifactRejected`**, and
the resolved policy's `enforcement` is `record`. The `ScanCompleted`-must-
exist clause is load-bearing — it keeps the second impossible failure mode
from *Context* (a never-successfully-scanned artifact releasing on the timer
alone) true under `record` as well: the mode un-gates the *verdict*, never
the *observation*. It pairs only with `ReleaseReason::Timer` and carries the
**same** provenance AND-precondition as authorities 1 and 2, so a `Required`
-mode artifact with `Pending` clearance still does not release; the curation
conjunct and the observation window are likewise untouched. `record` un-gates
exactly one axis.

Per the bounded-await corollary below, the read-path candidacy gates were
re-validated against this authority: they consult `quarantine_status` and the
provenance clearance only, so a `record`-mode artifact is a wait candidate on
the same terms as a clean-scan one, and the inline fast-path release in
`record_scan_result` mints `ScanRecorded` (not `ScanSucceeded`) for it — the
same token the sweep's `resolve_release_authority` would mint for the same
artifact.

### A seventh authority: `ScanCleared` — findings are evidence, the verdict is the decision (issue #344, amended 2026-10-11)

The release authority was derived in two places from two different facts. The
scan-time fast path asked "did the policy block?" (`!violations.is_empty()`);
the release sweep asked "did the scanner find anything?"
(`finding_count == 0`), under a comment claiming it mirrored the resolver it
contradicted. Both were wrong, in opposite directions, and the same artifact
therefore released or hung forever depending on whether its scan completed
**after** or **inside** its observation window — a behaviour no decision ever
took, and the arithmetic of a divergence rather than a rule.

**The sentence above is where it began.** "`ScanCompleted(findings)`
immediately sets `rejected`" stopped being true when `enforcement: record`
shipped, and was never true for findings below the configured threshold; it
made the finding *count* the authority where the *policy* decides. It is
corrected in the Decision above by the same amendment that adds this authority.

The rule, as decided: an artifact whose latest scan carries findings
**exclusively below** the configured threshold is released when the observation
window ends, regardless of when that scan ran; the earliest release is the end
of the window and the latest is the arrival of a non-blocking verdict. Without
a scan result nothing releases (fail closed).

Three consequences. **The verdict is recorded**: every `record_scan_result`
appends a `PolicyEvaluated` — `Pass` or `Fail` — beside the `ScanCompleted`, so
the durable record answers "what was decided?" without re-running the
evaluator. **One predicate reads it**: both paths call `latest_scan_standing`,
which takes the first verdict after the latest `ScanCompleted` and keeps "no
observation" and "superseded by a later rejection" distinct from "holds", so
`enforcement: record` can never un-gate a missing observation or another axis's
rejection. **And the authority says what it checked**: `ScanCleared` exists
because widening `ScanSucceeded` would have produced correct releases with a
permanently false premise — that token asserts an empty finding list, and a
release log reading `authority = scan_succeeded` over an artifact with findings
is a record no operator can trust. It carries the same provenance
AND-precondition as the other three timer authorities: a recorded,
non-blocking scan verdict says nothing about provenance.

The precondition behind all three was **#264** (fixed in 0.14.0): the Trivy
adapter wrote every artifact as `<sha256>.bin`, Trivy matched no analyzer, and
the empty finding list was recorded as a clean scan — for 54 days and 26,267
scans. The authority rule was therefore never exercised against a non-empty
finding list before, which is why a divergence this old surfaced only now.

### One authority owns the manual release (issue #345, amended 2026-10-11)

The predicate carried **two** manual authorities, told apart by permission and by source state: `AdminOverride` (`Permission::Admin`, from `Quarantined` or `ScanIndeterminate`) and `CuratorWaiver`. Item 4 of the enumeration above read, until this amendment:

> 4. `CuratorWaiver` — curator waive (`Quarantined`-state only).

and the operator guide argued that bound as deliberate (`docs/architecture/how-to/curator-workflow.md`, before this amendment):

> *"The narrower source-state guard on waive is intentional. `ScanIndeterminate` means the scanner could not complete (a terminal scan failure, not a clean result); releasing such an artifact requires the broader deliberation that `admin_release` represents (the broader role, the emergency escalation context)."*

**The decision (maintainer, confirmed 2026-10-11):**

> **Admin serves technical and operative actions; the curator holds the domain's authority. A curator who may override known severe findings may also act when no finding exists yet.**

The bound did not protect the greater power; it split one power across two roles. The two paths differed in exactly three things — the permission, the source state, and the `released_by` discriminator. Effect, attribution, the ignored provenance parameter, the event type and the re-blockability were identical, and each had exactly one production caller. And the state the narrower path was kept away from is not the graver one: `ScanIndeterminate` means *no* verdict was reached, while a waivable `Quarantined` artifact may carry findings a policy weighed and permitted. An authority trusted to decide with a verdict in view is not the weaker one for the case where there is nothing to see. The split in *kind* this completes is already named in `docs/glossary.md` ("Curator (`Permission::Curate`)"): a verdict about an artifact is a curation decision; a structurally invalid state being withdrawn is not.

**The rule, as decided.** One authority — item 4 above — whose requirement depends on the **source state** rather than on a second permission tier:

- **Permission:** `Permission::Curate`, in every state the authority reaches. An admin caller satisfies the same gate (`CurateOrAdminPrincipal` admits either, and the RBAC evaluator short-circuits admin globally), so this **removes a route from the admin-only gate** — it adds nothing to it.
- **Source state:** `Quarantined`; `ScanIndeterminate`; and `Rejected` on the axes the next subsection enumerates. Never `None` and never `Released` — there is nothing there to release.
- **Record:** a justification is required (non-empty, ≤ 512 bytes) and the `ArtifactReleased` carries `released_by: Curator` plus the deciding curator's user id. Who decided, and why, stays answerable from the stream alone (ADR 0002).
- **A state the rule does not admit answers 409, never 500.** An operator can POST a release against an artifact in any state, so the refusal is a caller-reachable state precondition — `DomainError::InvalidState` (ADR 0025).

**What keeps automation out is a grant nobody makes, not a token-kind check.** The deployed curator identity is itself a PAT-only `kind: ServiceAccount` carrying a global `curate` grant (`deploy/ansible/files/gitops/auth/service-accounts/maintainer-curator.yaml`), and service accounts are strictly non-admin (ADR 0038) — so `TokenKind::ServiceAccount` has never meant "a pipeline", and a principal-shape gate on this route would lock out the very operator it was meant to protect. ADR 0055 governs the question and answers it by refusing the grant: *"Granting `curate` to the release identity. Would work, and hands CI standing authority over other people's artifacts to solve a problem about its own."* That refusal is the control. This amendment does not reopen it, and the curator surface keeps its deliberate non-features (no bulk-waive, no rule-driven release).

#### The axis boundary for a `Rejected` artifact: as far as the curator's instrument reaches

`Rejected` is reached on four axes — scan (a fresh verdict, and the ADR 0041 retroactive tighten), curation (a curator's block, a retroactive rule), provenance (a positive disproof, ADR 0039's 2026-09-12 amendment) and corruption (the CAS integrity tombstone). The manual release overrides the first three and **never** the fourth. In the vocabulary the stream records (`RejectionReason`): `Scanner`, `ScanPolicyRetroactive`, `Curator { .. }`, `CurationRetroactive { .. }` and `Provenance` are overridable; `Corruption` is not. `Admin` keeps its place in the enum with no production minting path — admin does not make domain verdicts — so it needs no override arm.

The boundary is **what the curator's instrument can reach**, not a ranking of severities. The instrument is the comparison the curator's job is built on: this content hash against the publisher's own release page. That answers exactly the question a signature answers, so it reaches a **missing** signature and a **disproved** one alike. A third party who attaches a broken signature to a genuine artifact leaves the bytes genuine, and the comparison confirms it. An attacker who modified the artifact and signed it with their own key fails that same comparison, so the curator does not override. The instrument works in both directions, which is why the provenance axis resolves here rather than staying deferred.

It cannot reach bytes that disagree with the hash naming them. Whatever the publisher attests, the bytes hort holds are not those bytes: the comparison confirms nothing, and `VerifyingReader` fails the read regardless (ADR 0003's read-verification amendment). A corruption override would not be a risky decision but a meaningless one, so it stays refused — permanently, not pending a mechanism.

**The provenance position was argued the other way first and withdrawn on that reasoning** (maintainer, 2026-10-11), so a later reader sees a decision and not a silence. The withdrawn position was that a missing signature leaves the artifact insufficiently identified, so a curator can hold no information that permits an alternative decision. It does not survive the answer: the artifact *is* identified — by its content hash, and on a pull-through path by a verified upstream checksum (ADR 0006). What provenance adds is **attribution**, and the hash comparison above is precisely the information the premise said could not exist.

**ADR 0041's invariant #6(a) is untouched.** It bars a *scan re-judgement* from clearing a provenance rejection, and a curator's override is not a re-judgement of the evidence — which is why the override is a predicate of its own beside `is_scan_clearable` rather than a widening of it. A policy re-evaluation still must not clear a curator's block or a provenance disproof.

ADR 0025's observation that `rejected` exits only through finding-exclusion re-evaluation describes the predicate *before* this amendment; the 409 contract it records, and its example, are about the status code a state precondition answers and are unaffected either way.

#### What this amendment does not change

The narrow reading is the one that survives.

- **`Permission::Curate` stays strictly less than `Permission::Admin` for every other route.** The curate extractor's own contract refuses the inverse move — mounting an existing `/admin/...` route behind it would broaden the global admin gate to also accept curators (`crates/hort-http-core/src/authz/extractors.rs`). This amendment does the opposite: it takes one route *out* of the admin gate. No other admin surface moves, and the technical/operative ones (gitops status, effective config, the provenance-misrejection repair) stay admin-only.
- **Curation keeps re-blocking a manually released artifact.** The partition that shipped with the 2026-10-11 scan-verdict amendment above is `ReleaseOrigin::permits_scan_reblock` (`crates/hort-domain/src/entities/artifact.rs`), consulted in exactly one place: the `Released` source state of `Artifact::reject_from_scan`. So a **fresh scan verdict** cannot re-block an artifact whose latest `ArtifactReleased` carries `Admin` or `Curator`, and can re-block one released by `Timer` or `PolicyReEvaluation` — or one with no release event at all. The protection is scan-axis-wide, not axis-wide: a curator's block, a retroactive curation rule, a provenance disproof and the corruption tombstone all still reach a `Released` artifact, whatever released it. Widening *who* may release widens none of that, because the partition is keyed on `released_by`, which a curator release already set.
- **`ReleaseReason::Admin` stays in the vocabulary.** The stream is append-only (ADR 0002): the releases an admin granted are on it, they must still read back as manual human releases, and the re-block partition above must still honour them. What the implementing change retires is the *minting* path and the `(Admin, AdminOverride)` pairing row — never the ability to read the reason a past event carries.

**Decision recorded ahead of the code.** This section is the standing decision. The `(Admin, AdminOverride)` pairing row, the `ReleaseCuratorWaiver` source-state table (`crates/hort-domain/src/entities/quarantine_transitions.rs`), the `Rejected` override predicate beside `is_scan_clearable`, and the admin route and CLI command the decision removes all land with the implementing change under the same issue. Until they do, the code still carries two manual paths and the narrower curator bound; this section, not the code, is what the decision says. The amendment sections *above* keep their contemporaneous wording, as every earlier amendment to this ADR has — where one of them counts five authorities or names `AdminOverride`, it is reporting the predicate as it stood on its own date.

### Read-path bounded-await pattern (issue #65, amended 2026-07-20)

The zero-window carve-out above still leaves a **read-side** race: a cold pull-through blob GET resolves the just-ingested, still-`Quarantined` artifact and would 503 before that artifact's own async scan lands the `ScanSucceeded` that (per the carve-out) releases it almost immediately once it runs — the gap is the scan's own turnaround (~1–5s observed), not an observation window. `hort-http-oci::blobs::maybe_bounded_await_release` closes this by polling the artifact for up to a tunable bound (`HORT_OCI_PULLTHROUGH_RELEASE_WAIT_SECS`, default 10s, `0` = off) before falling through to the existing `check_quarantine` 503 decision.

**This pattern never touches the release predicate and is recorded here as the invariant future read paths adopting it must preserve:** a bounded-await helper may only ever *re-read* `quarantine_status` in a loop and return whatever it observes — it must never call `Artifact::release` or synthesize a release authority itself. It can only ever turn a would-be 503 into a 200 that the artifact's own scan pipeline had already, independently, authorized through the existing five-authority predicate; it can never turn a would-be 503 into an incorrectly-served blob. If the scan never completes, rejects, or the bound elapses first, the artifact is returned unchanged and the caller's existing 503 / hidden-404 handling runs exactly as before.

**Candidacy signal correctness matters as much as the wait mechanism.** The helper must gate the wait on the *real* effective deadline (`quarantine_window_start` anchor + the artifact's actually-matched `ScanPolicy` duration) — never on `ArtifactUseCase::hydrate_quarantine_deadline`'s approximation (`quarantine_deadline = quarantine_window_start`, used only for the `check_quarantine` `Retry-After` computation), which reads as "elapsed" for essentially every `Quarantined` artifact almost immediately because `ArtifactUseCase` holds no policy-projection port to resolve a real duration. Using that signal for the wait-candidacy gate would silently defeat the "never await a genuine, not-yet-elapsed time-quarantine" requirement — a still-running multi-minute (or longer) hold would get bounded-waited on every GET instead of 503ing immediately. `QuarantineUseCase::is_window_elapsed` (new, issue #65) resolves the real matched-policy duration via the same `resolve_active_policy_for_repo` + `effective_quarantine_deadline` computation the `record_scan_result` inline fast-path and the `release_expired` sweep already use, and is the only sanctioned source for this gate.

**Amended (issue #135): a provenance-blocked release is not a wait candidate.** The pattern's premise — "window elapsed ⇒ the only thing left is the artifact's own scan" — predates the provenance release authority (ADR 0039/0041). Under `provenance_mode: Required` with the artifact's clearance still `Pending`, release additionally requires an external signature plus verify/cascade, which cannot land inside the bound, and the inline fast-path release is suppressed for exactly this state — so the await was a guaranteed full-bound stall (measured: a constant 10s per cold blob GET) in front of the same 503. The candidacy gate therefore also consults `QuarantineUseCase::release_blocked_on_provenance`, which delegates to the SAME single-sourced clearance resolution (`release_clearance::resolve_provenance_clearance`) the fast-path suppression and the release sweep use — one authority, no drift; `Pending` ⇒ skip the wait entirely and fall through to the honest `503 + Retry-After` immediately. Both invariants above are untouched: the guard only *narrows* candidacy (it can never start a wait that today would not start, and it never synthesizes a release). A scan-pending artifact whose provenance is already `Cleared` — including a late-joining constituent self-cleared at ingest (ADR 0039 §12) — remains a wait candidate; that is the case the pattern exists for. Corollary for future read paths adopting the pattern: when a NEW release authority is added to the predicate above, every bounded-await candidacy gate must be re-validated against it — an await whose premise omits an authority degrades into a fixed-latency tax on exactly the requests that authority holds.

## Consequences

- A missing or failed scan **fails closed**: the artifact does not leak out when its timer expires. A never-scanned (`None`-status) or already-terminal artifact lands in `scan_indeterminate`; an artifact still `quarantined` when its scan exhausts retries stays `quarantined` and is auto-rescanned once the scanner recovers (issue #6, above) — in both cases the timer cannot release it.
- Adding any new release path means adding an authority to the enumerated predicate, with its own guard — there is no "fall through to released".
- The `scan_backends: []` waiver is an explicit, audited authority, not an accidental gap.
- Re-evaluation after an exclusion does not skip the remaining observation window: it removes the scan block, not the time hold.

## Alternatives considered

- **Release on `quarantine_until` expiry alone.** Rejected: this is precisely the hole the fail-closed predicate exists to plug — an artifact that never passed a scan would auto-release on the timer.
- **Clean scan releases immediately.** Rejected: collapses the observation window the quarantine exists to provide. This general reversal stays rejected; do not conflate it with the *narrow* referenced-tree-descendant carve-out above (issue #46) — that carve-out applies only to `content_references` targets and does not touch the release predicate.
- **A boolean "releasable" flag set by various code paths.** Rejected: a single mutable flag with many writers is exactly the ambiguity the enumerated `(reason, authority)` predicate removes.

## References

- `crates/hort-domain/src/entities/artifact.rs` (`Artifact::release`) and `crates/hort-domain/src/ports/quarantine_release.rs` — the release predicate and `ScanIndeterminate` status.
- `crates/hort-domain/src/ports/scanner.rs` (`NotAnalysable::gates_release`), `crates/hort-domain/src/events/artifact_events.rs` (`ScanAssessment`) and `ScanOrchestrationUseCase::run_scan`'s abstention partition — the 2026-09-18 "scannable surface" clarification above.
- The architect skill → Quarantine Invariants; anti-pattern *scanner clean → immediate release*.
- `docs/architecture/how-to/curator-workflow.md` — the one manual release authority in practice (§1, §2.1, §4); `docs/architecture/how-to/quarantine-patch-release.md` — the patch-release playbook that exercises it; `docs/glossary.md` ("Curator (`Permission::Curate`)") — the admin/curator split in kind.
- `deploy/ansible/files/gitops/auth/service-accounts/maintainer-curator.yaml` and `docs/adr/0055-write-authorized-hold-read-generalised.md` (rejected alternative: *"Granting `curate` to the release identity"*), with `docs/adr/0038-admin-identity-model.md` — why the manual release carries no token-kind gate and what keeps automation out of it instead.
- `crates/hort-domain/src/entities/quarantine_transitions.rs` (`ReleaseCuratorWaiver` / `ReleaseGeneral` source-state rows), `crates/hort-domain/src/entities/artifact.rs` (`is_scan_clearable`, `ReleaseOrigin::permits_scan_reblock`) and `crates/hort-http-core/src/authz/extractors.rs` (`CurateOrAdminPrincipal`) — the sites the issue #345 one-authority amendment above governs.
- `docs/architecture/how-to/recover-stranded-artifacts.md`; `ScanOrchestrationUseCase::record_outcome` and `RescanCandidatesRepository::select_stranded` — the issue #6 exhaustion-split / stranded-scan recovery amended in above (commit `55a93e40`; ratified by decision issue #32, 2026-07-14).
- `crates/hort-http-oci/src/blobs.rs` (`maybe_bounded_await_release`) and `crates/hort-app/src/use_cases/quarantine_use_case.rs` (`QuarantineUseCase::is_window_elapsed`) — the issue #65 read-path bounded-await pattern amended in above.
- `crates/hort-app/src/use_cases/ingest_use_case.rs` (`IngestUseCase::ingest_inner`) — the referenced-tree-descendant zero-window anchor-backdating (issue #46, amended above); `docs/adr/0043-oci-image-index-support.md` — the `content_references` membership graph (`oci_index_member` / `oci_subject` / `oci_config` / `oci_layer`) the target-check reads.
