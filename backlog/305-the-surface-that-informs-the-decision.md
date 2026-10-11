# 305 — The surface that informs the decision moves with it

**Issue:** #345 · **Branch:** `agent/345-curation-owns-the-manual-release`
**Governing decisions:** ADR 0021 / ADR 0045 (repository anti-enumeration — the
listing must not become a discovery surface), ADR 0012 (grant-based authority).

**Independent of items 302–304** in mechanism; it is the same decision applied
to the read that informs the write.

## What is true today

`GET /api/v1/admin/quarantine/patch-candidates`
(`handlers/admin/mod.rs:135`) is gated by `AdminPrincipal`, with a use-case-side
`require_admin()` behind it as defence in depth. Its own how-to builds the
operator flow as *list candidates → decide → release*
(`docs/architecture/how-to/quarantine-patch-release.md:96`–`:123`), and the
listing is what shows the findings before the decision — §3 says so: *"the
patch-candidate listing surface shows you the findings (if any) before you
act."*

So once the decision is the curator's, a curator may decide but may not read
what grounds the decision. That is the decision's own principle applied by
halves.

## What to do

1. **Gate the listing with `CurateOrAdminPrincipal`** and change the
   use-case-side check from `require_admin()` to `require_curate_or_admin()`.
   Admins keep access — the extractor's Curate-then-Admin precedence admits
   them (`authz/extractors.rs:275`).
2. **Keep the route path.** It stays under `/api/v1/admin/...` like the
   curation decision routes themselves (`/api/v1/admin/curation/*` is also
   admin-prefixed and curator-gated); moving the path is a separate, purely
   cosmetic churn with a CLI and documentation cost and no authority meaning.
   Say this in the report so the reviewer does not read it as an oversight.
3. **Check the anti-enumeration question explicitly and write the answer
   down.** The listing returns quarantined artifacts with their repository and
   findings. A global `Curate` grant is already global decision authority over
   exactly those artifacts (`maintainer-curator` holds precisely that), so the
   listing exposes nothing its holder cannot already act on. If the
   implementation finds a field in the response that is **not** covered by that
   argument, name it in the report instead of shipping it.
4. **The CLI follows**: `hort-cli admin quarantine list-patch-candidates` keeps
   working for an admin and now also for a curator — no flag change, no new
   command. Verify it against a curator token in the report, not by inspection.

## Explicitly out of scope

- Moving the route path, renaming the CLI subcommand, or changing the response
  shape.
- The other admin reads (`GET /repositories/:key`, `/effective-config`,
  `/gitops/apply-status`) — technical/operative by the rule this ticket
  applies, and they stay where they are.

## Acceptance

- A caller holding only `Permission::Curate` gets 200 from
  `GET /api/v1/admin/quarantine/patch-candidates`; a caller with neither
  `Curate` nor `Admin` still gets the same denial as today.
- An admin without an explicit `Curate` grant still gets 200.
- The use-case-side gate is `require_curate_or_admin()`; a test calls the use
  case directly with curator-only privileges and passes.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p <the crates this unit touches>` — check, fmt,
  clippy and those crates' tests, with a full per-step log under
  `handover/gatelogs/`. Judge by the output, not the rc, and quote the test
  totals. Do **not** run `cargo test --workspace`, `cargo audit`, `cargo deny`
  or the attribution script: together they take 15–25 minutes, longer than a
  worker's foreground tool window, so the harness backgrounds them and the run
  ends with the gate killed and the report lost. The architect runs the full
  gate on the same tree before any MR; a red workspace-wide step becomes a new
  directive, not an in-run fix. Write the report before exiting.
