# 045 — Root README.md rewrite for adopters (v1.0 prep 3/3)

**Issue:** #70
**Read first:** the current `README.md` (151 lines — decent but architecture-forward),
`CONTRIBUTING.md`, `docs/architecture/how-to/deploy/self-contained-registry-install.md` (#60 /
ADR 0051), `docs/architecture/how-to/deploy/install.md`, the `site/` landing content (align tone),
and CLAUDE.md (avoid overstated claims — WASM modularization is roadmap, not shipped).

## Goal (final v1.0 doc phase — after operator #68 and developer #69)

Recast the root `README.md` to align with typical root docs for a project of this kind and the
**interests of aspiring users/adopters** — an adopter-facing landing, not an architecture dump
(that lives in `docs/architecture/` + ADRs).

## What to change (the current README is a good base — refine, don't discard)

- **Lead with the value proposition + differentiators**, not the layering. What problem Hort solves
  (a secure, self-hostable, multi-format supply-chain registry) and *why* an adopter comparing to
  Artifactory / Nexus / Harbor would choose it: enforced content-addressed storage, **mandatory
  upstream verification**, **quarantine + fail-closed scan gate**, event-sourced tamper-evident
  audit trail, **self-hostable sovereign registry** (the #60 self-contained chart —
  `registry.hort.rs`), open-source (MIT/Apache-2.0). Keep the HORT acronym but after the hook.
- **Status line** — approaching v1.0; set maturity expectations honestly.
- **Badges** — CI/pipeline, license, latest release (typical OSS root-README shelf).
- **Quickstart that runs** — keep the migrate→serve→pull flow; add the **self-contained Helm chart**
  install path (#60) as the turnkey option, cross-linked to `self-contained-registry-install.md`.
- **Supported formats** table — keep; note the roadmap ones (Maven/Helm/… , WASM modularization)
  as roadmap, not shipped (no overstated claims).
- **Docs + Contributing pointers** — link the swept `docs/architecture/` set (#68/#69) and
  `CONTRIBUTING.md`; keep the License section.
- **Drop or relocate** the "Built mainly with Claude Opus 4.7" dev-meta line from the top hook (it's
  not adopter-facing; if kept, move it to a footer/acknowledgment — and it's version-stale).
- **Consistency with `site/`** (hort.rs) — the README and the landing page shouldn't diverge on the
  pitch/claims.

## Acceptance

- README reads as a compelling, accurate adopter landing; the quickstart works end-to-end; all
  links resolve; no claim exceeds shipped behavior (WASM = roadmap; formats = the 4 shipped + OCI).
- Consistent with the `site/` landing.
- Root README only — operator docs (#68) and developer docs/crate READMEs (#69) already done.
- Gate green (docs-only, but run it).

### Starter prompt

```
/hort-architect

Implement backlog item 045 (issue #70) on branch agent/70-root-readme. IMPORTANT: verify
`git branch --show-current` is agent/70-root-readme before EVERY commit — never commit to develop.
Rewrite ONLY the root README.md into an adopter-facing landing: lead with the value prop +
differentiators (secure/self-hostable/multi-format supply-chain registry; CAS, mandatory upstream
verification, quarantine+scan gate, event-sourced audit, the #60 self-contained sovereign registry,
open-source), add a status line + badges, keep and refine the quickstart (add the self-contained
Helm chart path), keep the formats table (roadmap items marked roadmap), link the swept docs +
CONTRIBUTING, relocate the "Built with Claude" dev-meta line out of the hook. No overstated claims
(WASM modularization is roadmap). Keep it consistent with site/. Run the full gate and report per
the handover protocol.
```
