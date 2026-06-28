# Continuous scan-policy enforcement — backlog

Branch-local (doc-lifecycle **D7**; remove before merge to main). Implements
**ADR 0041** per `scan-policy-reevaluation.md`. PR-sized, dependency-ordered.
Coverage gates: `hort-domain` / `hort-app` **100%**, adapters / HTTP **≥85%**.
New `hort-adapters-postgres` tests touching the shared DB carry
`#[serial(hort_pg_db)]`.

**Dependency order:** **Item 0 → 1 → 2 → 3 → 4.** Item 0 is a self-contained
security fix that **ships as its own PR ahead of the rest** (§1a); Items 1–4
build the generalization on the corrected primitive.

---

## Item 0 — FAST-TRACK: fix the existing cross-axis fail-open (ships independently)

**Design doc section:** §1a, §2 (the conjunction half)
**Read first:** `crates/hort-domain/src/entities/artifact.rs` (`re_evaluate`
~L720-751, `reject_from_retroactive_curation` + its `Quarantined`/`Released`-only
guard ~L351, the apply fold), `crates/hort-domain/src/policy/re_evaluation.rs`
(`re_evaluate_after_exclusion` L145-181), `crates/hort-domain/src/policy/curation.rs`
(`evaluate_curation` L142), `crates/hort-app/src/use_cases/policy_use_case.rs`
(`run_post_exclusion_re_evaluation_pass`, `commit_re_evaluation`, **and the
`PolicyUseCase` struct fields** — it holds `projections/artifacts/artifact_lifecycle/
storage`, NOT a curation or provenance source today),
`crates/hort-app/src/use_cases/quarantine_use_case.rs`
(`resolve_provenance_clearance` ~L1111 — the existing provenance-clearance source),
`crates/hort-domain/src/ports/curation_rule_repository.rs` (`list_for_repo` L42 —
active rules for an artifact's repo, the input to `evaluate_curation`),
`crates/hort-adapters-postgres/src/artifact_repo.rs` (`list_rejected_for_policy`
L679), `crates/hort-domain/src/events/artifact_events.rs` (`RejectionReason`).
**Acceptance:**
- The `Artifact` aggregate carries its **rejection reason** (set on the
  `ArtifactRejected` apply; round-trips through reconstruction — it does not today).
- `re_evaluate`'s `Rejected → Released` path is **extended** to the three-mechanism
  conjunction of invariant #6: (a) eligibility guard — only `reason = Scanner` is a
  candidate; (b) an **active provenance** precondition; (c) an **active curation**
  precondition (reuse `evaluate_curation` over the live rules). (b) and (c) are
  app-computed clearances passed in (mirroring `ProvenanceClearance` on `release()`);
  the domain stays pure.
- **App wiring (this is the bulk of the item, not an afterthought):**
  - *Provenance:* the pass computes the clearance via the **same** logic as
    `QuarantineUseCase::resolve_provenance_clearance`. **Single-source it** — extract
    that resolver into one shared home (a domain helper over the stream events, or a
    shared method) that both `QuarantineUseCase` and the re-eval pass call. Two
    independent release-gating provenance computations is exactly the drift that
    produced the `negligible_action` HIGH finding in MR !39; do not duplicate.
  - *Curation:* add `Arc<dyn CurationRuleRepository>` to `PolicyUseCase` (new
    constructor dependency → **composition-root wiring in `hort-server`**); per
    artifact, `list_for_repo(repo_id)` → `evaluate_curation(coords, rules)` → clears
    iff not a `Block` match.
- The **existing** post-exclusion pass computes and passes both clearances + the
  reason guard. Scope is the existing pass only — no generalization here.
- **Tests (domain 100% AND app 100% for the new clearance-computation branches,
  plus the §6 §1a red→green):** each non-`Scanner` reason → not released;
  provenance-pending → not released; a **scan-rejected artifact matched by a
  curation rule added *after* the rejection** → not released (the case the reason
  guard misses); a genuinely clean+eligible artifact → released as today.
- **Observability:** the extended pass logs `info!` on each release decision
  (security-relevant); `#[instrument(skip(self))]` (no `err`).

### Starter prompt

```
/hort-architect

Implement ADR 0041 §1a (FAST-TRACK) — fix the live cross-axis fail-open in the
EXISTING post-exclusion re-evaluation pass; this ships as its own PR ahead of the
rest of ADR 0041. Read first: artifact.rs (re_evaluate, reject_from_retroactive_curation
and its Quarantined/Released-only guard, the apply fold), policy/re_evaluation.rs,
policy/curation.rs (evaluate_curation), policy_use_case.rs (run_post_exclusion_re_evaluation_pass,
commit_re_evaluation, AND the PolicyUseCase struct fields — no curation/provenance source
today), quarantine_use_case.rs (resolve_provenance_clearance ~L1111), curation_rule_repository.rs
(list_for_repo L42), artifact_repo.rs (list_rejected_for_policy), artifact_events.rs.
(1) Carry the rejection reason on the Artifact aggregate (set on ArtifactRejected apply,
round-trips). (2) Extend re_evaluate's Rejected->Released path to the three-mechanism
conjunction of invariant #6: (a) reason=Scanner eligibility guard; (b) active provenance
precondition; (c) active curation precondition (reuse evaluate_curation over live rules).
(b)+(c) are app-computed clearances passed in (mirror ProvenanceClearance on release());
domain stays pure. (3) App wiring — the bulk of the work: for provenance, single-source
resolve_provenance_clearance (extract the QuarantineUseCase logic into one shared home
that both callers use — do NOT duplicate it, that drift caused the MR !39 negligible_action
HIGH); for curation, add Arc<dyn CurationRuleRepository> to PolicyUseCase (new constructor
dep → wire it in the hort-server composition root) and call list_for_repo -> evaluate_curation.
Scope: the existing pass only. Domain 100% AND app 100% on the new clearance branches, incl.
each non-scan reason -> not released, provenance-pending -> not released, and the
curation-rule-added-after-scan-rejection -> not released case (the one the reason guard
misses). info! on each release decision; instrument(skip(self)) no err. Do NOT generalize
the pass or touch update_policy/remove_exclusion here — that is Items 2-3.
```

---

## Item 1 — Domain: retroactive scan re-hold transition + widened audit event  *(blocked on 0)*

**Design doc section:** §2 (transition + audit-event halves)
**Read first:** `crates/hort-domain/src/entities/artifact.rs`
(`reject_from_retroactive_curation` — the `Released → Rejected` precedent to mirror),
`crates/hort-domain/src/events/artifact_events.rs` (`ArtifactReEvaluated` with its
non-optional `trigger_exclusion_id`, `RejectionReason`),
`crates/hort-domain/src/policy/scan.rs` (`evaluate_scan_result`).
**Acceptance:**
- A **retroactive scan re-hold** transition `Released`/`Quarantined` → re-`Quarantined`
  / re-`Rejected` for a now-failing verdict, mirroring `reject_from_retroactive_curation`
  (accepts a `Released` source). The timer window is **not** re-opened. New
  `RejectionReason::ScanPolicyRetroactive` (or `Scanner` + a retroactive marker —
  decide in review; record the choice).
- `ArtifactReEvaluated` **widened** from the non-optional `trigger_exclusion_id` to a
  policy-change discriminator (which `PolicyUpdated`/`ExclusionAdded`/`ExclusionRemoved`
  drove the pass), with serde back-compat for already-stored events (append-only,
  ADR 0002 — no rewrite of past events).
- Both directions read one verdict source: `evaluate_scan_result` over stored findings.
- **Tests (domain 100%):** tighten → now-failing `Released` re-holds; no-stored-findings
  → never re-rejected on tighten (invariant #4); unchanged → no-op; the widened event
  serializes/deserializes across both shapes.

### Starter prompt

```
/hort-architect

Implement ADR 0041 §2 (domain transitions) — builds on Item 0's extended re_evaluate.
Read first: artifact.rs (reject_from_retroactive_curation, the Released->Rejected
precedent), artifact_events.rs (ArtifactReEvaluated, RejectionReason), policy/scan.rs
(evaluate_scan_result). (1) Add a retroactive scan re-hold transition (Released/
Quarantined -> re-Quarantined/re-Rejected) for a now-failing verdict, mirroring
reject_from_retroactive_curation; do NOT re-open the timer window. Add the reject
reason (ScanPolicyRetroactive, or Scanner + retroactive marker — decide + record).
(2) Widen ArtifactReEvaluated from the non-optional trigger_exclusion_id to a
policy-change discriminator, serde-back-compatible with stored events (append-only,
ADR 0002). Domain 100%: tighten re-holds, no-findings never re-rejected (invariant #4),
unchanged is a no-op, both event shapes round-trip.
```

---

## Item 2 — App: generalised re-evaluation pass + population port  *(blocked on 0,1)*

**Design doc section:** §3 (pass + port)
**Read first:** `crates/hort-app/src/use_cases/policy_use_case.rs`
(`run_post_exclusion_re_evaluation_pass`, `commit_transition`),
`crates/hort-app/src/use_cases/apply_config_use_case.rs` (the curation retroactive
pass to mirror), `crates/hort-domain/src/ports/artifact_repository.rs`
(`list_rejected_for_policy`), `crates/hort-app/src/use_cases/test_support.rs`,
`crates/hort-adapters-postgres/src/artifact_repo.rs`.
**Acceptance:**
- `run_policy_re_evaluation_pass(policy_id, trigger)`: list the in-scope population,
  load each artifact's stored findings, evaluate against the bumped policy, transition
  **both directions** (Item 0's conjunction for loosen, Item 1's transition for tighten),
  commit atomically (audit + transition).
- New paginated `list_active_for_policy` (the `Released`/`Quarantined` scanned set)
  alongside `list_rejected_for_policy`; the pass is **fully paginated, no fixed cap**.
- The pass carries the `#[instrument(skip(self))]` (no `err`) skeleton from the
  start so it is never briefly untraced; the rich `info!`/`warn!` + metric land in
  Item 3 (blocked on this, lands adjacently).
- **Tests:** both directions; no-evidence no-op; **idempotent** (re-run = same verdict);
  paginates past 10k with no silent truncation; ports mocked via `test_support.rs`
  (app 100%); the adapter `list_active_for_policy` tested with `#[serial(hort_pg_db)]`
  (≥85%).

### Starter prompt

```
/hort-architect

Implement ADR 0041 §3 (the generalised pass + population port) — builds on Items 0-1.
Read first: policy_use_case.rs (run_post_exclusion_re_evaluation_pass, commit_transition),
apply_config_use_case.rs (curation retroactive pass to mirror), ports/artifact_repository.rs
(list_rejected_for_policy), use_cases/test_support.rs, artifact_repo.rs. Generalise the
pass to run_policy_re_evaluation_pass(policy_id, trigger): list the in-scope population,
load stored findings, evaluate vs the bumped policy, transition both directions (Item 0
conjunction for loosen, Item 1 transition for tighten), commit atomically. Add a paginated
list_active_for_policy (Released/Quarantined scanned set); the pass is fully paginated,
NO fixed cap (the current 10k truncate-and-warn is fail-open for tighten). App 100%:
both directions, no-evidence no-op, idempotent, paginates past 10k. Adapter test carries
#[serial(hort_pg_db)]. Do NOT wire triggers or the worker task here — that is Item 3.
```

---

## Item 3 — App/infra: async worker task + trigger wiring + metric  *(blocked on 2)*

**Design doc section:** §3 (async + triggers), §5 (observability)
**Read first:** `crates/hort-app/src/use_cases/policy_use_case.rs` (`update_policy`,
`remove_exclusion`, `reactivate_policy`, `add_exclusion`), the existing worker task
handlers (mirror `CronRescanTickHandler`'s port-only shape), the task-kind registration
sites (jobs.kind SQL CHECK in `migrations/`, the enqueue/dispatch registry),
`docs/metrics-catalog.md`.
**Acceptance:**
- A new **worker task kind** runs `run_policy_re_evaluation_pass` off the request path;
  `update_policy` (gate fields), `remove_exclusion`, `reactivate_policy` **enqueue** it
  and return; `add_exclusion` is migrated onto it. **Enqueue once per policy mutation,
  not per event:** `update_policy` emits one `PolicyUpdated` per changed field
  (`policy_use_case.rs:368`), so a multi-field gate change must coalesce to a single
  task, not N.
- The task kind is registered at **every** site (incl. the `jobs.kind` SQL CHECK — the
  easy miss caught only by the DB-gated enqueue test; pre-1.0 the kind is added to the
  inline CHECK in the `009_scan_jobs_and_findings.sql` CREATE in place per ADR 0022,
  post-1.0 it becomes a new numbered ALTER migration) and, if Helm/timers run it,
  mirrored in the scheduledTasks/`hort_timers` parity surface.
- **Idempotency/concurrency model (state it explicitly):** the pass is naturally
  verdict-idempotent and `commit_transition` carries event-version optimistic
  concurrency, so concurrent passes over the same population are safe (a stale
  transition fails its version check and is skipped). This is **not** an ADR 0028
  destructive task — no per-UTC-day idempotency key / seal-pool single-flight is
  required; record that so a reviewer neither demands that machinery nor misses the
  concurrency question.
- Observability (§5): `info!` on each release/re-hold transition and pass-start (trigger
  + in-scope count); `#[instrument(skip(self))]` (no `err`); `warn!` on a skipped
  per-artifact failure (one bad artifact must not abort the pass). New metric
  `hort_policy_reevaluation_*{result}` (`result` ∈ `released`/`re_held`/`unchanged`) +
  a **completeness** signal (pages/population covered) — **update `docs/metrics-catalog.md`
  in the same PR**.
- **Tests:** each trigger enqueues the pass; the outcome metric fires with expected labels
  (`metrics::with_local_recorder`); completeness surfaced; DB-gated enqueue test carries
  `#[serial(hort_pg_db)]`.

### Starter prompt

```
/hort-architect

Implement ADR 0041 §3 (async + triggers) + §5 (observability) — builds on Item 2.
Read first: policy_use_case.rs (update_policy, remove_exclusion, reactivate_policy,
add_exclusion), an existing worker task handler (mirror CronRescanTickHandler's port-only
Arc<dyn _Port> shape), the task-kind registration sites (jobs.kind SQL CHECK in migrations/,
the enqueue/dispatch registry), docs/metrics-catalog.md. Add a worker task kind running
run_policy_re_evaluation_pass off the request path; make update_policy/remove_exclusion/
reactivate_policy enqueue it and return; migrate add_exclusion onto it. Enqueue ONCE per
policy mutation, not per event (update_policy emits one PolicyUpdated per changed field —
coalesce). REGISTER the task kind at every site incl. the jobs.kind SQL CHECK (the easy
miss — caught only by the DB-gated enqueue test): pre-1.0 add it to the inline jobs.kind
CHECK in the 009 CREATE in place (ADR 0022), and mirror it in the hort_timers/scheduledTasks parity surface
if scheduled. State the idempotency model: naturally verdict-idempotent + commit_transition
event-version optimistic concurrency makes concurrent passes safe; NOT an ADR 0028
destructive task (no per-UTC-day key / seal-pool). Observability: info! on transitions +
pass-start, instrument(skip(self)) no err, warn! on skipped artifact. New metric
hort_policy_reevaluation_*{result} + completeness signal; update docs/metrics-catalog.md
same PR. Test: triggers enqueue (once per mutation), metric fires with labels, DB-gated
test carries #[serial(hort_pg_db)].
```

---

## Item 4 — Docs + ADR acceptance (D7 close-out)  *(blocked on 0–3)*

**Design doc section:** §7
**Read first:** the policy/quarantine operator how-to under
`docs/architecture/how-to/`, `docs/adr/0041-continuous-scan-policy-enforcement.md`,
`docs/adr/0000-historical-decisions-index.md`, `docs/metrics-catalog.md`.
**Acceptance:**
- Operator how-to updated: scan-policy changes are retroactive in **both** directions;
  what a tightening pulls (and that it blocks future downloads, not already-served bytes);
  the stored-findings/evidence model.
- ADR 0041 → **Status: Accepted**; ADR index row **confirmed** (already added under
  "Quarantine and release gating"); metric-catalog entry confirmed.
- Remove `docs/plans/scan-policy-reevaluation*.md` (D7) — the ADR + how-to are the durable
  record.

### Starter prompt

```
/hort-architect

Land the ADR 0041 docs + D7 close-out. Update the policy/quarantine operator how-to
(docs/architecture/how-to/): scan-policy changes are retroactive in both directions, what
a tightening pulls (blocks future downloads, not already-served bytes), the stored-findings
evidence model. Flip ADR 0041 to Accepted, confirm its ADR-index row (already added), confirm the
metric-catalog entry. Remove docs/plans/scan-policy-reevaluation*.md (D7 — the ADR + how-to
are the durable record).
```

---

## Out of scope (carried forward — see ADR 0041 §Blast-radius / design §8)

- Tightening **preview / dry-run** — follow-on; the async + completeness-metric floor
  (Item 3) makes deferral acceptable.
- **Corrective rescan** (refresh stored findings for a buggy/stale scanner) — separate,
  narrower; *feeds* this mechanism. Scope a follow-on plan if a findings-changed trigger
  is wanted.
- **Physical** curation/scan-pass engine unification — later refactor; this initiative
  unifies the *principle* only.
