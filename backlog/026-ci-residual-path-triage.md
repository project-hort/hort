# 026 — CI docs-only skip: triage residual uncovered paths + `THIRD-PARTY-LICENSES.md` self-skip

- **Source:** GitLab issue #26 (follow-up from #24 report flags #1/#2)
- **Type:** chore (CI) — `.gitlab-ci.yml` only
- **Model hint:** **small** — one anchor edit + the documented triage decision.
- **Reviewable unit:** one directive.
- **Sequencing:** dispatch **after #30 lands** (both edit `.gitlab-ci.yml`; different sections — the `.code-changed-paths` anchor here vs. `security:attribution-sync`'s `rules:` in #30 — so no textual conflict expected, but rebase on the latest `develop` to be safe).

## Problem

The #24 doc-vs-code split gates heavy jobs on a **positive `.code-changed-paths` match**;
a path on **neither** side silently skips them. #24 covered the two demonstrable cases
(`.gitlab/**`, `sonar-project.properties`) and deferred the rest here:
1. **Untriaged top-level paths** matching neither side.
2. **`THIRD-PARTY-LICENSES.md`** matches the doc-only `**/*.md` glob, so a lone hand-edit
   classifies as doc-only and skips its own `security:attribution-sync` guard; `.json`
   matches neither side.

## Architect triage (the decision)

**Add to `.code-changed-paths` (code side — run the heavy jobs):**
- `.dockerignore` — image-build context (buildah/`docker build`), same rationale as the
  already-listed `docker/**`.
- `about/**/*` — cargo-about templates/config read by `security:attribution-sync`, same
  rationale as the already-listed `about.toml`.
- `THIRD-PARTY-LICENSES.md` and `THIRD-PARTY-LICENSES.json` — the generated attribution
  artifacts; editing them must run their verification, not be classified doc-only.
  **This closes flag #2's classification half.**

**Leave skip-safe (intentionally NOT in the code list — inert to every GitLab job; document this decision in a comment on the anchor):**
`.github/**` (GitHub-only CI; no GitLab job consumes it), `.agents/**` (auto-agents
config), `.env.example`, `.gitguardian.yaml`, `.mergify.yml`, `renovate.json`,
`install/**` (the CLI installer served at hort.rs — not built/tested by the Rust
pipeline), `tools/**` (a **workspace-excluded** dir — `exclude = ["tools/*"]` in the root
`Cargo.toml`, so no `--workspace` job builds it), `.trivyignore` (grep-confirmed: not
referenced anywhere in `.gitlab-ci.yml`; consumed at worker runtime, not in CI).

Rationale for the split: a path goes **code-side** only if editing it can change a heavy
GitLab job's *output* (build, test, lint, attribution). Everything else is skip-safe.

## Interaction with #30 (note, don't duplicate)

#30 re-scopes `security:attribution-sync` to release-relevant pipelines (off the
`.rules-code-changed` changes-filter), which resolves flag #2's *verification-timing* half
(a `THIRD-PARTY-LICENSES.*` edit is re-verified on the promotion MR / tags regardless of
path classification). #26 is complementary: it fixes the **path classification** so the
artifacts are code-side for the other `.rules-code-changed` jobs and for cleanliness. Do
**not** re-touch `attribution-sync`'s `rules:` here (that's #30's).

## Change

Extend the `.code-changed-paths` anchor in `.gitlab-ci.yml` with the four code-side paths
above, and add a comment documenting the skip-safe list as a deliberate decision (so the
next person doesn't re-litigate it). No job-`rules:` changes.

## Out of scope

- `attribution-sync` gating (that's #30).
- Any change to what the heavy jobs do.

## Acceptance criteria

1. `.dockerignore`, `about/**`, `THIRD-PARTY-LICENSES.md`, `THIRD-PARTY-LICENSES.json`
   are on the code side (a lone edit to any of them runs the `.rules-code-changed` jobs).
2. A comment on the anchor documents the skip-safe list + the "changes a heavy job's
   output?" rule, so the residual set is explicitly accepted, not silently uncovered.
3. `.gitlab-ci.yml` remains CI-lint-valid; no other job's gating changed.

## Verification (for the cockpit report)

- Before/after of the `.code-changed-paths` anchor.
- Rule-evaluation reasoning: a `THIRD-PARTY-LICENSES.md`-only diff now RUNS the heavy jobs
  (was skipped); a `renovate.json`-only diff still skips (documented skip-safe); a
  `crates/**` diff unchanged.
- CI-lint the file if possible; the architect runs the GitLab CI-lint API on landing.
