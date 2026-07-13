# 025 — ADR + glossary: hort release / branch / staging strategy

- **Source:** GitLab issue #25 (`agent:decision` — decision content **provided by the maintainer** in the issue; this records a stated policy, it does not decide one)
- **Type:** docs (ADR + glossary + release-doc reconciliation). **No code.**
- **Model hint:** **capable** — ADR authoring + reconciling the existing release docs is cross-cutting; the wording carries authority.
- **Reviewable unit:** one directive. Architect reviews the ADR wording before landing (ADR lands only after an answered `agent:decision` — satisfied by #25).

## Goal

Record hort's release/branch/staging model durably so the architect and future
contributors share one model. Doc-only; staging-deploy / version-bump CI
automation is explicitly a **separate future backlog item**, not this one.

## The policy to record (from #25 + the maintainer's 2026-07-13 clarification — do not re-decide it)

**Maintainer clarification (2026-07-13, on #25):** *"The old approach using
throwaway tags doesn't necessarily have to be replaced. But changing the naming
from beta to alpha for purely internal versions is justified and it's a
requirement, that those testing version-bump commits do not land in develop and
main."* → **Preserve** the existing throwaway-branch pre-release-tag mechanism
(RELEASING.md); do **not** rip it out. The firm changes are the `beta→alpha`
rename for internal builds and the no-merge-back requirement.

- **The existing throwaway-tag mechanism is retained.** Internal pre-releases stay
  a version-bump commit cut on a throwaway branch **off `develop`**, tagged — as
  RELEASING.md already describes. What changes: (a) the internal pre-release is named
  **`alpha.N`**, not `beta.N`/`rc.N`; (b) the branch is named **`test/vX.Y.Z-alpha.N`**
  and is **pushed** so staging can deploy it (test/* branches are already pushed to
  origin today); (c) **hard requirement: the version-bump commit MUST NOT land on
  `develop` or `main`** — the `test/*` branch is never merged back (only the tag +
  its throwaway branch ride the remote for staging deploy).
- **Naming:** `alpha` for purely-internal test builds. Semver orders
  `alpha < beta < rc`, leaving room for public `beta`/`rc` later — so this rename does
  not foreclose a future public pre-release track.
- **Staging is continuous and multi-source** — deploys from `develop`, from `test/*`
  pre-release branches, and from `main`.
- **Alpha builds are internal-only** — staging + the **local hort registry only**,
  never published publicly.
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
- Capture: the branch model `develop → test/vX.Y.Z-alpha.N (throwaway, tagged, NOT
  merged back) → main`; the retained throwaway-tag mechanism + the `beta→alpha` rename
  + the **no-version-bump-commit-on-develop/main** requirement; staging sources
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

### D3 — Amend the existing release docs (preserve the mechanism, don't replace it)
- `RELEASING.md` and the CLAUDE.md **Releases / Docker image tags** sections already
  describe the throwaway-branch pre-release-tag mechanism (`vX.Y.Z-beta.N`/`-rc.N`
  cut off `develop`, tagged, not merged back). **Keep that mechanism.** Amend, don't
  rewrite:
  - Rename the **internal** pre-release track `beta.N`/`rc.N` → **`alpha.N`**, on a
    **`test/vX.Y.Z-alpha.N`** branch that IS pushed (staging deploys it), and state
    explicitly that its version-bump commit is **never merged to `develop` or `main`**.
  - Note that `alpha` builds go to **staging + local registry only** (never public),
    and that staging is multi-source (develop + test/* + main).
  - Preserve room for a future **public** `beta`/`rc` track (semver `alpha<beta<rc`);
    say the alpha rename does not remove that option.
  - The `build-images:*` / `helm:*` tag regex currently matches
    `-(rc|beta)\.N` — **flag** (do not silently change) that an `alpha` internal tag
    would need the regex widened *if* internal alpha tags are meant to build public
    images; but since alpha is internal/local-registry-only, confirm the intended
    behavior with the maintainer rather than guessing. Surface this in the report.
- Add the ADR 0048 reference to CLAUDE.md so the agents apply it.

## Out of scope

- Any staging-deploy automation, `test/*` branch-cut tooling, or version-bump CI
  (explicitly a separate future backlog item per #25).
- Creating/removing workflow labels (`workflow::in-uat` already exists).

## Acceptance criteria

1. `docs/adr/0048-release-branch-staging-strategy.md` exists, Status: Accepted,
   house header shape, capturing the full policy above; indexed per the 0000 convention.
2. `docs/glossary.md` exists with the five term areas, each referencing ADR 0048.
3. `RELEASING.md` + CLAUDE.md **amended** (throwaway-tag mechanism retained): internal
   pre-releases renamed `beta/rc → alpha` on a pushed-but-never-merged `test/*` branch,
   the no-commit-on-`develop`/`main` requirement stated, staging multi-source +
   internal-only noted, and pointing at ADR 0048 — no remaining statement that
   contradicts the recorded policy. The `build-images/helm` tag-regex interaction is
   flagged in the report (not silently changed).
4. Markdown only; no code, no CI/gate changes. (Doc-only push — will not run heavy
   CI once #24 lands; harmless before then.)

## Verification (for the cockpit report)

- List the new/changed files and paste the ADR header + the glossary entries.
- Grep evidence that no residual `-beta.N`/`-rc.N`-off-develop wording in
  `RELEASING.md`/CLAUDE.md now contradicts ADR 0048 (or a flagged item if a
  maintainer call is needed).
- Confirm `docs/glossary.md` links resolve to `docs/adr/0048-*`.
