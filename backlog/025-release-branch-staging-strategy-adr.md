# 025 — ADR + glossary: hort release / branch / staging strategy

- **Source:** GitLab issue #25 (`agent:decision` — decision content **provided by the maintainer** in the issue; this records a stated policy, it does not decide one)
- **Type:** docs (ADR + glossary + release-doc reconciliation) **+ a scoped CI change**
  (alpha-tag build/publish routing — see D4). No Rust/runtime code.
- **Model hint:** **capable** — ADR authoring + cross-cutting release docs + a
  two-CI-system change whose correctness (internal vs public registry) carries risk.
- **Reviewable unit:** one directive. Architect reviews the ADR wording *and*
  CI-lints the pipeline change before landing (ADR lands only after an answered
  `agent:decision` — satisfied by #25).

## Goal

Record hort's release/branch/staging model durably so the architect and future
contributors share one model, **and** make the alpha/staging mechanism actually
work by routing `alpha` tags to the internal registry/chart (D4). Broader
staging-deploy automation and `test/*` branch-cut tooling remain a separate future
item; the tag-regex routing is in-scope here because staging depends on it
(maintainer, 2026-07-13).

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
  never published publicly. They **do** produce container images + a Helm chart
  (staging deploys from the chart + images — maintainer, 2026-07-13), but those
  artifacts go to the **internal** registry (`${REGISTRY}` / registry.hort.rs via
  GitLab CI), **not** the public ghcr (GitHub `docker-publish.yml`). D4 wires exactly
  this split.
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

### D4 — CI: route `alpha` tags to the internal registry only (maintainer requirement, 2026-07-13)
Staging deploys from the Helm chart + images, so an internal `alpha` tag must build
and publish them — **to the internal registry, never public.** Two edits:

1. **GitLab `.gitlab-ci.yml` — widen the internal-publish regex.** `build-images:hort-server`,
   `build-images:hort-worker`, and `helm:lint-and-publish` currently gate on
   `$CI_COMMIT_TAG =~ /^v[0-9]+\.[0-9]+\.[0-9]+(-(rc|beta)\.[0-9]+)?$/`. Widen the
   pre-release group to include `alpha`: `-(alpha|rc|beta)\.[0-9]+`. These jobs push to
   `${REGISTRY}` (the internal mirror / registry.hort.rs), which is what staging
   consumes — so this is the intended internal build. (These jobs are also now
   `changes:`-gated from #24, but the `$CI_COMMIT_TAG` arm is unconditional, so tag
   pipelines still run — good.)
2. **GitHub `.github/workflows/docker-publish.yml` — exclude `alpha` from the public
   publish.** It triggers on `push: tags: ['v*']` with **no** pre-release filter, so a
   `v…-alpha.N` tag would publish **public** ghcr images/charts — violating internal-only.
   Add a guard so `alpha` pre-release tags are skipped (e.g. a job-level
   `if: !contains(github.ref, '-alpha.')`, or narrow the tag trigger). `:latest` is
   already correctly excluded for any pre-release (`!contains(ref,'-')`); the gap is the
   **versioned** `:X.Y.Z-alpha.N` public push. Keep `beta`/`rc` behaviour unchanged
   (those remain the public pre-release track room the naming leaves open).

**Confirm, don't assume, the public-exclusion intent in the report** if anything about
the internal-vs-public split reads ambiguously against the deployment reality — but the
recorded policy (alpha = internal-only) makes the exclusion the fail-safe default.

## Out of scope

- Broader staging-deploy automation and `test/*` branch-cut tooling (a separate future
  item). D4 covers only the alpha-tag build/publish **routing**, which staging needs now.
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
4. **D4:** the three GitLab internal-publish jobs' tag regex matches `alpha` (so a
   `v…-alpha.N` tag builds/publishes to the internal registry); the GitHub public
   publish **skips** `alpha` tags (no public ghcr image/chart for an alpha); `beta`/`rc`
   behaviour unchanged on both sides.

## Verification (for the cockpit report)

- List the new/changed files and paste the ADR header + the glossary entries.
- Grep evidence that no residual `-beta.N`/`-rc.N`-off-develop wording in
  `RELEASING.md`/CLAUDE.md now contradicts ADR 0048 (or a flagged item if a
  maintainer call is needed).
- Confirm `docs/glossary.md` links resolve to `docs/adr/0048-*`.
- **D4:** paste the before/after of the three GitLab regex lines and the GitHub
  guard; reason through the four cases in the report — `v1.2.3` (public + internal),
  `v1.2.3-alpha.1` (**internal only**, no public), `v1.2.3-beta.1` / `-rc.1`
  (unchanged). CI-lint the `.gitlab-ci.yml` change (the architect will also run the
  GitLab CI-lint API on landing). A YAML/actions syntax check of `docker-publish.yml`
  (e.g. `actionlint` if available, else careful review) for the guard.
