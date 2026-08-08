# 089 — #135 item 1: late-joiner provenance self-clear at ingest

**Issue:** #135 (direction confirmed by the human on-issue; that approval also
covers the ADR amendment below). The stranding seam, evidence-closed on #130:
`cascade_clearance` clears constituents once, at the subject's verify, from
the signed bytes; a constituent ingested afterwards has no clearance path —
its own verify holds (no parent lookup), the sweep's expiry backstop skips
parent-gated blobs, and stranded Pending manifests churn the backstop every
tick. Consumer-visible on any multi-arch proxy repo under `Required`
(`skopeo copy --all` after release pulls foreign platform children into the
strand).

**Read first:**
`crates/hort-app/src/use_cases/provenance_orchestration.rs` —
`cascade_clearance` / `cascade_one` (the idempotent append + version-conflict
retry you will reuse), `constituent_digests` (the signed-bytes walk),
the verify skip-path's cascade re-drive (the documented one-shot semantics);
`crates/hort-domain/src/entities/artifact.rs::cascade_provenance_clearance`
(the Quarantined-only guard — unchanged);
`crates/hort-app/src/use_cases/quarantine_use_case.rs` — the #107
`commit_transition_with_enqueues` frame (where quarantine-time side effects
live) and `resolve_provenance_clearance`;
`crates/hort-app/src/use_cases/referenced_descendant.rs` (edge-kind
vocabulary);
the #130 RCA comments (the evidence run: rows, event timeline).

## Work

1. **Domain/orchestration — the second trigger end.** At quarantine-commit
   time of a `Required`-mode artifact (the same transactional frame #107
   established; the clearance attempt itself is post-commit best-effort,
   mirroring the existing cascade's semantics — it must never block or fail
   the ingest):
   a. resolve inbound edges: `content_references.find_by_target(repo, hash)`;
   b. for each source manifest artifact holding a **direct**
      `ProvenanceVerified` (`cascaded_from == None` — a cascaded clearance
      must not recurse, mirroring the re-drive's gate);
   c. **verify membership against the subject's signed CAS bytes** via
      `constituent_digests` — DB edges are mutable projections and MUST NOT
      become clearance authority; only a digest found inside the verified
      bytes clears;
   d. append the idempotent cascaded `ProvenanceVerified` exactly as
      `cascade_one` does (same event shape, `cascaded_from` attribution, same
      version-conflict retry). Prefer extracting/reusing `cascade_one` over
      duplicating it.
2. **Metric** (`docs/metrics-catalog.md` conventions):
   `hort_provenance_late_joiner_cleared_total` (labels per catalog norms) —
   incremented per successful late-joiner clearance; a debug/info log line
   naming subject + constituent.
3. **Churn quiescing assertion:** stranded Pending manifests that self-clear
   on arrival stop being re-enqueued by the S4 backstop — add/extend a test
   pinning that a late-joiner-cleared manifest is NOT re-enqueued on the next
   sweep tick.
4. **ADR amendment:** extend ADR 0039's cascade section with (a) the
   late-joiner rule (symmetric second trigger end, signed-bytes membership
   authority) and (b) the general *both-ends-trigger* principle (every
   standing cross-artifact lifecycle dependency names a trigger at BOTH
   ends). Decision provenance: #135's on-issue approvals.
5. **Cross-opt-in matrix (ADR 0016 discipline), in the ADR text:** enumerate
   `trust_upstream_publish_time` (orthogonal — no timestamps read),
   `scan_backends: []` (scan gate unchanged, still ANDed), `requireApproval`
   (unchanged). State explicitly that this adds a clearance *producer*, not a
   release-authority kind.
6. **E2E acceptance restored:** `proxy-required-multilayer.sh` step 9 back to
   `skopeo copy --all` (revert the subtree-only carve-out; update the block
   comment: late joiners now self-clear, `--all` is the acceptance of exactly
   that). The anonymous-503 pin and all other steps unchanged.

## Scope / acceptance

- Tiers: `hort-domain`/`hort-app` **100%** on new/changed branches (every
  guard arm: no-verified-parent, cascaded-parent-skip, membership-miss,
  version-conflict retry, event-append failure best-effort path).
- Adapter tests touching the DB: `#[serial(hort_pg_db)]`.
- Full pre-push suite (Rust diff — fmt, clippy -D warnings, test --workspace
  with and without DATABASE_URL, audit, deny; one-shot capture idiom).
- No policy/linter surface changes; no new operator knobs (this is
  fail-closed behavior restoration, not an opt-in).
- Final acceptance vehicle: branch-first human run of the base lane
  (`run.sh --hort=compose`) with `--all` restored — dispatch reports readiness
  and stops (no MR).

**Model hint:** opus — clearance-authority change in the event-sourced core;
a wrong subtlety here (projection-as-authority, recursion, idempotency) is a
security regression.
