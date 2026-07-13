# 024 — CI: skip the heavy pipeline on documentation-only changes

- **Source:** GitLab issue #24 (filed by maintainer after backlog-commit pushes to `develop` began running full CI)
- **Type:** chore (CI cost)
- **Model hint:** capable — small diff but **merge-gating-correctness sensitive** (acceptance #4 is a real GitLab trap, see Pitfalls)
- **Reviewable unit:** one directive.

## Problem

Every push runs the full pipeline (`test` → `security` → `quality` → …), including markdown/coordination-only pushes — now routine, because the architect commits `backlog/` items to `develop` and each doc-only push runs the whole Rust build/test/lint. Wasted runner time.

## Goal

A commit/MR that changes **only** documentation/coordination paths skips the heavy build/test/lint jobs; any code/build/CI path change runs the full pipeline unchanged. Must hold for MR pipelines, branch pushes, and the default-branch (`develop`/`main`) pipeline — **without breaking merge gating** (a doc-only MR must still be mergeable).

Backlog stays version-controlled — the gitignore-`backlog/` alternative was explicitly rejected by the maintainer (issue #24).

## Repo path split (architect-finalized)

**Doc-only (skip heavy jobs):** `**/*.md`, `docs/**`, `backlog/**`, `handover/**`, `site/**`, `LICENSE*`, `.gitignore`.

**Code/build/CI (run full):** `crates/**`, `Cargo.toml`, `Cargo.lock`, `migrations/**`, `.gitlab-ci.yml`, `deploy/**`, `docker/**`, `scripts/**`, `.cargo/**`, `rust-toolchain.toml`, `deny.toml`, `.clippy.toml`, `rustfmt.toml`, `about.toml`.

Guiding rule: **`.gitlab-ci.yml` itself is a code path** — a change to the pipeline definition must run the full pipeline. When in doubt, a path runs the full pipeline (fail-safe toward *more* CI, never less).

## Existing state to respect

`.gitlab-ci.yml` already has a `workflow: rules` block (~L39) scoping pipelines to MR events, tags, and branch pushes (with the branch/MR de-dup). The doc-only guard must compose with it, not replace its de-dup/tag/MR logic. Heavy jobs live in stages `test` / `security` / `quality` / `build-images` / `helm` / `release` (see the job list `test:lint`, `test:unit`, `test:coverage`, `test:integration`, `security:*`, `quality:*`, `build-images:*`, `helm:*`, `release:sbom`).

## Recommended approach

Per-job `rules: changes:` gating the heavy jobs on the **code/build path set** (positive match — GitLab `changes:` cannot express "NOT docs", so match the code paths that *should* trigger), driven by a shared `.rules-code-changed` YAML anchor / `!reference` so the path list is defined once and reused. Prefer this over workflow-level `changes:` because workflow-level `changes` interacts poorly with the existing multi-rule `workflow:` block.

## Pitfalls (must handle — these are why this isn't trivial)

1. **Empty pipeline blocks merge (acceptance #4).** If every job is gated out on a doc-only MR, GitLab produces a pipeline with no jobs; depending on project settings ("Pipelines must succeed") that can block the MR. Mitigate with a guaranteed-present lightweight always-runs job (e.g. `docs-only:ok` — `script: 'true'`, no heavy image) so a doc-only pipeline is **non-empty and green**. Confirm the MR stays mergeable.
2. **`changes:` semantics on branch/default pipelines.** `rules: changes:` compares against the previous commit on branch pipelines; on force-push or the first pipeline it can evaluate to "changed" (fail-safe → full run, acceptable). Do **not** rely on `changes:` for tag pipelines (releases must always run fully) — gate tags to always-full.
3. **Required/child pipelines & SonarCloud.** `quality:sonar` and any required-status gate must not go "pending forever" on a doc-only pipeline. Either include them in the always-run floor as trivially-passing, or ensure the merge check tolerates their absence.

## Out of scope

- The GitHub `e2e.yml` / `release.yml` workflows (separate host; they already gate on `main`/`release`/tags, not doc-only `develop` pushes).
- Any change to *what* the heavy jobs do.

## Acceptance criteria (from #24)

1. A commit/MR touching only doc paths runs no heavy build/test jobs (empty-but-green or a single trivial job is fine).
2. A commit touching any Rust/code/CI path runs the full pipeline unchanged.
3. MR pipelines **and** the default-branch (`develop`/`main`) pipeline both behave correctly.
4. Merge-request required-pipeline / merge gating is **not** broken — a doc-only MR is still mergeable.

## Verification (for the cockpit report)

- `git ci-lint` / `gitlab-ci-local` or the GitLab CI lint API on the edited `.gitlab-ci.yml` (valid config).
- Evidence of rule evaluation: a doc-only diff (e.g. touch a `backlog/*.md`) vs. a code diff (touch a `crates/**` file), showing the job set differs as specified — via `gitlab-ci-local` dry-run or a pushed throwaway branch's pipeline.
- Confirm the doc-only pipeline is green and the MR-merge check is satisfiable.
