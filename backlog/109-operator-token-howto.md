# 109 — How-to: operator actions on session-gated endpoints without an IdP

Issue: #150. Docs only — no code change, no new surface.

## What

Record the standing decision (2026-08-13): **no human IdP/Dex on
registry.hort.rs** — the instance hosts no general user activity and maintains
no accounts; the PAT-only `maintainer-dev` ServiceAccount with global grants,
minted host-side, is the designed operator path.

## Deliverables

1. **How-to** under `docs/architecture/how-to/` — "operator actions on
   session-gated endpoints without an IdP". Content:
   - The token-kind contract: prefetch/curation endpoints accept CliSession
     **or** ServiceAccount tokens; PATs are rejected by design.
   - The mint, capture-safe form (`--output=file:` — stdout carries JSON log
     lines and must not be captured):

     ```
     TF=$(mktemp)
     hort-server admin issue-svc-token --name=maintainer-dev \
       --permission=read --permission=prefetch --output=file:$TF
     TOK=$(cat $TF); rm -f $TF
     ```

   - The authority preflight is the **opt-in `--require-authority` flag**
     (a bare mint performs no grant check; runtime RBAC still gates every
     request). With the flag, each declared `--permission` must be backed
     by a live grant **at the declared scope**: global by default, or the
     scope named by `--repository <name>` — where a global grant also
     satisfies a repo-scoped check (same evaluator semantics as runtime).
     With `--repository`, the minted token's capability is itself scoped
     to that repository. `issue-svc-token` is strictly non-admin. Name the
     gitops grant files that back the maintainer-dev permissions, and show
     both mint forms (global identity; repo-scoped identity with
     `--require-authority --repository <name>`).
   - `--rotate` revokes the prior token; per-request RBAC still applies at the
     endpoint (e.g. Read ∧ Prefetch on the resolved repo). Note the
     row-without-Secret trap: a re-mint WITHOUT `--rotate` exits 0 without
     writing the output file when the token row already exists — check the
     file is non-empty before storing.
   - Blast-radius note for `write`: mint write-capable tokens per action only.
2. **`admins.yaml` clarification** — a comment note (or a pointer from the
   how-to, whichever reads better in place) recording that the Dex/OIDC wiring
   the file describes is deliberately NOT applied on registry.hort.rs, so a
   future operator does not read it as an outstanding TODO.

## Constraints

- Diátaxis: this is a **how-to** (task-oriented), not an explanation page —
  keep decision rationale to a short "why there is no IdP here" paragraph and
  link the issue-recorded decision; steps carry the weight.
- No issue/MR references in the docs body beyond durable anchors (ADRs, file
  paths, commands) per the comment-provenance rule; the changelog/commit
  message carries #150.
- English; glossary check — if "session-gated" or "global grant" need
  clarification, add glossary entries in the same MR.

## Acceptance

- An operator with root on the host and no IdP can go from zero to a working
  prefetch POST following the how-to alone.
- `rg -i "dex|oidc" docs/architecture/how-to/<new-page>` explains the absence
  rather than instructing setup.
