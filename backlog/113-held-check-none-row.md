# 113 — Held-check: a returned None-status row is ingested content, classify it held

Issue: #160. One reviewable unit: classification change + test corrections +
comment/port-doc truthfulness. `hort-app` (+ a port doc line in
`hort-domain`). No schema, no port signature, no event change.

## Why

A self-service prefetch re-POST of a just-ingested artifact re-enqueues and
re-pulls upstream (staging-reproduced, #154 rev3). The classification lets a
`QuarantineStatus::None` row fall through to enqueue, justified by a comment
(H6) claiming proxies return `None` rows for versions "known upstream but
NOT locally ingested." That premise is structurally false: the adapter's
`package_version_status` reads only `artifacts` rows, whose
`checksum_sha256`/`storage_key` are NOT NULL — **a returned row IS ingested
content**. "Known upstream, not ingested" is the row-ABSENT case (already
enqueues). `None` really means "ingested, no quarantine lifecycle" (pure
Sigstore-bundle referrers; no-matching-policy ingests) — those re-pull on
every re-POST today, forever.

Design principle (human, 2026-08-15): ingested-or-not and quarantine-status
are two different dimensions — and they are already separated structurally:
row-presence = ingested; status = lifecycle. The fix aligns the
classification with that.

## Change

1. `crates/hort-app/src/use_cases/self_service_prefetch_use_case.rs`: in
   the held-classification match (used by BOTH the direct path and the
   member-aware walk — it is one match; verify both paths hit it), move
   `QuarantineStatus::None` from fall-through-to-enqueue into the
   held → `skipped_already_held` arm alongside Released/Quarantined.
   Rejected/ScanIndeterminate arms unchanged; row-absent branch unchanged.
2. **H6 test rewritten, not deleted**
   (`none_status_known_upstream_is_enqueued_not_skipped`): the behavior it
   meant to pin — "known upstream, not ingested must enqueue" — is the
   row-ABSENT case; rewrite it to seed absence and keep its name/doc honest.
   Add a companion test pinning None-row → skip, whose doc comment states
   the structural rationale (adapter reads `artifacts` only; content columns
   NOT NULL; a row implies content).
3. **Comment + port-doc truthfulness**: rewrite the in-code H6 comment
   block to the structural invariant; add the same invariant to
   `package_version_status`'s port doc (`hort-domain` port trait) as a
   contract note any future adapter must honour — a row returned by this
   projection asserts locally-ingested content.
4. Member-precedence semantics unchanged: a higher-priority member's
   None-row still wins the walk (it now classifies held — consistent with
   the first-authoritative-wins download path).

## Out of scope

- Enqueue-time dedup against pending prefetch jobs (separate optimization).
- When/where `quarantine_status` is stamped.
- Any adapter/SQL change.

## Tests (hort-app 100% tier)

- None-row → `skipped_already_held`: direct path AND virtual member path.
- Row-absent → enqueue (the rewritten H6, regression for real warming).
- Rejected / ScanIndeterminate → rejected (unchanged, pinned).
- Mixed batch envelope truthfulness: one held-None + one absent + one
  rejected → exactly one skip, one enqueue, one rejection.
- Member precedence: higher-priority None-row (→ skip) wins over
  lower-priority absence.

## Acceptance

- Re-POST of an ingested-unanchored (or lifecycle-less) artifact reports
  `skipped_already_held`, zero upstream contact.
- First POST of a genuinely absent version still enqueues (staging maven
  behavior for a never-pulled GAV unchanged).
- `cargo test --workspace` green; no new dependency.
