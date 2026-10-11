# 304 — One route, one command

**Issue:** #345 · **Branch:** `agent/345-curation-owns-the-manual-release`
**Governing decisions:** ADR 0007, ADR 0008 (layering — the HTTP crate calls a
use case, never a repository), ADR 0025 (the 409 contract the removed route
illustrated).

**Depends on item 303.** Removing the admin route before the curator path
accepts `ScanIndeterminate` would leave that state with no manual exit.

## What is true today

Two surfaces, one transition. The admin half:

| | |
|---|---|
| Route | `handlers/admin/mod.rs:143` (`post_quarantine_release`, `:803`), DTO `:790`, tests `:1772` |
| Use case | `quarantine_use_case.rs:1635` (`admin_release`) — one production caller, the handler above |
| CLI | `hort-cli admin quarantine release` (`crates/hort-cli/src/admin/quarantine/release.rs`) |
| E2E | `scripts/native-tests/scenarios/quarantine/patch-candidate.sh:436` (via CLI), `scripts/native-tests/scenarios/dogfood/registry-supply-chain.sh:251` (raw API, admin OIDC token from Keycloak at `:91`) |

The curator half (`curation_use_case.rs:557`, route
`handlers/admin/curation/mod.rs:70`) does the same thing behind
`CurateOrAdminPrincipal`, which admits admins by design.

## What to do

1. **Remove the admin route, its DTO, its handler and `admin_release`.** One
   production caller each, so nothing is left dangling. The justification cap
   lives on the curation path already (`MAX_JUSTIFICATION_BYTES`), so the
   admin-side constant (`MAX_RELEASE_JUSTIFICATION_BYTES`,
   `handlers/admin/mod.rs:104`) goes with the handler — do not leave two
   constants for one rule.
2. **Decide the authority vocabulary in the same breath.**
   `ReleaseAuthorization::AdminOverride` is a domain *parameter*, never
   persisted (`ArtifactReleased` carries `released_by`, `released_by_user_id`,
   `justification` and nothing else). With no minting path left, its
   `(Admin, AdminOverride)` pairing row is unreachable. Remove the variant and
   its row, and say so in the report — the alternative (keeping a dead row) is
   the thing this ticket exists to stop. **`ReleaseReason::Admin` stays**: the
   stream is append-only (ADR 0002), historical events carry it, and #344's
   unit 4 must keep protecting an artifact an admin released last month. Its
   rustdoc gains one line saying no path mints it any more.
3. **Same call for the two `QuarantineEvent` variants** (item 303 left this
   here deliberately): with `AdminOverride` gone, `ReleaseGeneral` covers the
   timer and policy-re-evaluation arms and `ReleaseCuratorWaiver` the curator
   arm, and the two now have identical source-state sets. Collapse them into
   one variant **iff** that leaves every allow row expressible; if it does not,
   say which row resists and keep both.
4. **The CLI loses `admin quarantine release`**; `hort-cli curation waive` is
   the one command. Remove the subcommand and its module, and make sure the
   remaining `admin quarantine` subtree still compiles with only
   `list-patch-candidates` under it.
5. **Re-point both E2E scenarios.** `patch-candidate.sh` switches to
   `hort-cli curation waive`; the dogfood scenario switches its URL to
   `/api/v1/admin/curation/quarantine/<id>/waive`. Both keep their existing
   credential — a Keycloak admin OIDC token passes `CurateOrAdminPrincipal`.
   **These are Tier-3 scenarios: the branch goes to the maintainer for his
   compose E2E run before any MR.**
6. **Re-point the documentation** named in #345's consumer table:
   `quarantine-patch-release.md` (§4's command sequence, §5.4, the attribution
   passage at `:126`–`:142`), `recover-stranded-artifacts.md:134`,
   `alpha-testing-runbook.md:18`/`:637`/`:731`,
   `operate/public-supply-chain-deployment.md:506`, and the comment in
   `scripts/alpha-fixtures/gitops-config/auth/29-admins-claim-mapping.yaml:5`
   (which names the admin-only surfaces). `backlog/210:25` references the old
   path in a not-yet-implemented item — update the reference, do not implement
   the item.
7. **The architect skill's review checklist** (`.claude/commands/hort-architect.md:619`,
   `:627`) names the CLI command and the justification rule; both lines need the
   new command name.
8. **The break-glass procedure in `operate/public-supply-chain-deployment.md`
   is a section, not a line.** The consumer table in item 6 lists `:506`, but
   §9's subsection *"State: `ScanIndeterminate` — ad-hoc admin token"* spans
   **`:481`–`:530`** and is a whole procedure: mint a DSN-gated
   `bootstrap-session` admin token, release, revoke. After this decision the
   standing `maintainer-curator` credential covers that state, so the procedure
   **goes** rather than gets re-pointed — and that is a user-visible
   simplification worth one line in the changelog entry, not a silent deletion.
   Re-measure the span before editing; this commit's own edits shift it.
9. **Sweep the residual "admin override" phrasing** that describes two manual
   authorities without naming `admin_release` (so the 302 acceptance grep does
   not catch it, and no other unit owns it): `docs/compliance/ISO27001.md:235`
   (a compliance claim — "an admin override, a curator waiver"),
   `docs/architecture/tutorial/first-ingest.md:210`,
   `docs/ci/hort-quarantine-integration.md:34`, `docs/metrics-catalog.md:2332`
   and `:4116`, and `recover-stranded-artifacts.md:28` (`:134` is already on
   item 6's list, `:28` is not). Re-measure each line number; they move.
10. **`quarantine-patch-release.md` is internally split until this unit lands.**
   Item 302 set §3's authority sentence to `Curate` while §4's command sequence,
   the attribution passage and §5.4 still describe the admin path — the
   `:126`–`:142` block named in item 6 shifted by roughly +18 lines when 302
   landed. The playbook contradicts itself in the meantime, which is one reason
   **this unit must not be left out of the issue's merge**: 302 and 304 belong
   in the same MR.

## Explicitly out of scope

- The patch-candidate listing's gate (item 305) and the counters (item 306).
- Any change to what a release *does*, to who may block, or to the provenance
  axis.
- A deprecation shim for the removed route. One path is the point; an alias
  would reintroduce the second surface this ticket removes.

## Acceptance

- `POST /api/v1/admin/quarantine/:id/release` answers 404 (route gone), and a
  grep of `crates/` finds no `admin_release` and no `AdminOverride`.
- `hort-cli admin quarantine release` no longer exists;
  `hort-cli curation waive` performs the release for a `Quarantined` **and** a
  `ScanIndeterminate` artifact.
- Both E2E scenarios pass against compose, run by the maintainer. State in the
  report that the branch is waiting on that run and that no MR was opened.
- A grep for the removed path across `docs/`, `scripts/` and `.claude/` returns
  only ADR 0025's status-code example (or nothing, if item 302 updated it).
- `ReleaseReason::Admin` still exists, still deserializes from a historical
  event, and a test pins that an `ArtifactReleased{Admin}` from the stream is
  still read as a manual release.
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
