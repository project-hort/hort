# 025 — ADR + glossary: hort release / branch / staging strategy

- **Source:** GitLab issue #25 (`agent:decision` — decision content **provided by the maintainer** in the issue; this records a stated policy, it does not decide one)
- **Type:** docs (ADR + glossary + release-doc reconciliation). **No code.**
- **Model hint:** **capable** — ADR authoring + reconciling the existing release docs is cross-cutting; the wording carries authority.
- **Reviewable unit:** one directive. Architect reviews the ADR wording before landing (ADR lands only after an answered `agent:decision` — satisfied by #25).

## Goal

Record hort's release/branch/staging model durably so the architect and future
contributors share one model. Doc-only; staging-deploy / version-bump CI
automation is explicitly a **separate future backlog item**, not this one.

## The policy to record (verbatim intent from #25 — do not re-decide it)

- **Staging is continuous and multi-source** — deploys from `develop`, from
  `test/*` pre-release branches, and from `main`.
- **Pre-release branches are internal-only.** `test/vX.Y.Z-alpha.N` cut **from
  `develop`**, version bumped on the branch. Deploy to staging + the **local hort
  registry only** — never published publicly. Named **`alpha.N`** (not `beta`):
  internal test builds. Semver orders `alpha < beta < rc`, leaving room for public
  betas later.
- **`main` is the public release** — version-fixed, deliberate, infrequent; one
  release may close many `ready-for-staging` / `in-uat` issues at once.
- Issues **rest** in `ready-for-staging` / `in-uat` until a release — not blocked
  merely because `main` hasn't been cut. (`ready-for-staging` → `in-uat` → `closed`
  are resting states decoupled from `main` promotion.)

## Deliverables

### D1 — ADR `docs/adr/0048-release-branch-staging-strategy.md`
- **Next free number is 0048** (latest committed is 0047). Follow the house header
  shape (see `0047-*.md`): `# 0048 — <title>`, then `- **Status:** Accepted`,
  `- **Enforced by:**` (here: process/docs, not a CI gate — say so), `- **Supersedes:**`,
  `- **Relates:**` (link `RELEASING.md`, and the CLAUDE.md Releases section).
- Capture: the branch model `develop → test/vX.Y.Z-alpha.N → main`; staging sources
  (develop + test/* + main); internal-only alpha builds (staging + local registry,
  never public); release cadence (main = deliberate, version-fixed, batch-closes
  issues); the workflow resting-states framing.
- Check the `docs/adr/0000-*` decisions index convention — add a register row if that
  index tracks accepted ADRs (mirror how 0047 is indexed).

### D2 — Glossary `docs/glossary.md` (**create the file — it does not exist yet**)
Entries (concise, definitional): **staging**, **UAT** (`in-uat`), **alpha build /
`test/*` branch**, **release (`main`)**, and the **`ready-for-staging` vs `in-uat`
vs `closed`** distinction. Point each at ADR 0048. Use a simple, sorted term list
(one `### term` + definition, or a table) — this is the first content, so it also
sets the file's format.

### D3 — Reconcile the existing release docs
- `RELEASING.md` and the CLAUDE.md **Releases / Docker image tags** sections
  currently describe pre-releases as `vX.Y.Z-beta.N` / `-rc.N` throwaway-branch
  **tags cut off `develop` and not merged back**. The new policy names internal
  pre-releases `test/vX.Y.Z-alpha.N` **branches** that deploy to staging + local
  registry. **Reconcile, don't silently contradict:** update those sections to the
  `test/*-alpha.N` model and cross-reference ADR 0048, and state how public
  `beta`/`rc` (if reintroduced later) relate. If a genuine conflict needs a
  maintainer call, flag it in the report rather than guessing.
- Add the ADR 0048 reference to CLAUDE.md so the agents apply it.

## Out of scope

- Any staging-deploy automation, `test/*` branch-cut tooling, or version-bump CI
  (explicitly a separate future backlog item per #25).
- Creating/removing workflow labels (`workflow::in-uat` already exists).

## Acceptance criteria

1. `docs/adr/0048-release-branch-staging-strategy.md` exists, Status: Accepted,
   house header shape, capturing the full policy above; indexed per the 0000 convention.
2. `docs/glossary.md` exists with the five term areas, each referencing ADR 0048.
3. `RELEASING.md` + CLAUDE.md reconciled to the `test/*-alpha.N` model and pointing
   at ADR 0048 — no remaining statement that contradicts the recorded policy.
4. Markdown only; no code, no CI/gate changes. (Doc-only push — will not run heavy
   CI once #24 lands; harmless before then.)

## Verification (for the cockpit report)

- List the new/changed files and paste the ADR header + the glossary entries.
- Grep evidence that no residual `-beta.N`/`-rc.N`-off-develop wording in
  `RELEASING.md`/CLAUDE.md now contradicts ADR 0048 (or a flagged item if a
  maintainer call is needed).
- Confirm `docs/glossary.md` links resolve to `docs/adr/0048-*`.
