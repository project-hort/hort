# 164 — record the widened `maintainer-dev` grant posture in ADR 0034 (+ 0037)

**Issue:** #180 · **Branch:** `agent/180-adr0034-grants` · Single item.

## Problem

ADR 0034 Surface 2 describes a `maintainer-dev` posture the deployment no
longer has. It quotes the mint command verbatim as `--permission read`, calls
the surface "minimum-read", and justifies the grant with an argument that
reasons specifically about *read* and about which repositories are private.
The deployment has held global `read` + `prefetch` + `write` grants since
2026-08-13, and mints read+prefetch tokens by default with write-capable
tokens minted narrowly for the manual per-artifact rescan.

The divergence is a documentation gap, not a posture problem: the reasoning
for the write grant exists, but only as a comment on the
`maintainer-dev-write.yaml` grant envelope, which is not where anyone
evaluating the deployment's security posture will look.

`docs/adr/0037-gitops-service-account-grant.md` carries the same staleness in
one line.

## Decision already taken

The maintainer confirmed **option 1** on #180 (2026-09-10): amend ADR 0034 to
describe the as-built posture and supply the missing justification, rather than
superseding Surface 2 with a new ADR or narrowing the deployment back.

The confirmed text is reproduced below and is the contract for this item. It
was approved as written; changing its substance needs a new answer on #180, not
an implementer's judgement call. Editorial adjustments for fit with the
surrounding ADR prose are fine.

## Read first

- `docs/adr/0034-public-dogfood-deployment.md` — Surface 2 (the paragraph to
  replace) and Surfaces 1 and 3 around it, for voice and depth.
- `docs/adr/0037-gitops-service-account-grant.md:82` — the single stale line.
- The `maintainer-dev-*.yaml` grant envelopes in the gitops tree, for the
  three grants and the write grant's existing rationale comment.

## What to write

Replace ADR 0034's Surface 2 paragraph with:

> **Surface 2 — dev operator token (static `hort_svc_*`, DB-direct).**
>
> The `maintainer-dev` service account is minted by the `gitops` Ansible role
> (no admin API, no IdP); operators authenticate with `hort-cli auth login
> --paste`. It carries three global serviceAccount-subject grants — `read`,
> `prefetch`, and `write` — applied via the gitops tree. Global `read` is
> acceptable because the only private repos are the dependency proxies;
> `hort-oci`, `hort-crates`, `hort-base` and `hort-charts` are public.
> `prefetch` and `write` back operator actions gated on those permissions —
> concretely the manual per-artifact rescan (`ManualRescanUseCase`), the only
> rescan path for terminal artifacts. The grant is **global** because the mint
> check backs a token's declared permissions against global grants only; a
> repo-scoped write grant cannot back a write-capable token.
>
> **Global write is acceptable on this instance because the token is
> host-confined.** It is used only for local operations on registry.hort.rs
> and is not transmitted off that host, so the "a leaked write token could
> push to the public hosted repos" risk requires compromising
> registry.hort.rs itself — beyond which the single-host dogfood is already
> fully compromised; the write grant adds no blast radius short of that.
> Day-to-day mints are read+prefetch only; write-capable tokens are minted
> narrowly for the action at hand, bounded by token expiry, and the grant is
> revocable by deleting `maintainer-dev-write.yaml` and re-applying. This is
> not a GitHub PAT and is bound to no GitHub identity.

And in ADR 0037, the line describing `maintainer-dev` as holding "a global
`read` grant" becomes global `read` + `prefetch` + `write` grants. Keep the
sentence's existing shape and its "none of them admin" clause, which is still
true and still the point that line is making.

Both ADRs get the amendment dated in whatever form each already uses for
amendments; follow the file, do not invent a new convention.

## Explicitly not in this item

- Any change to the deployment, the grants, or the mint commands. This item
  makes the record match the deployment, not the other way round.
- `maintainer-curator`, whose `curate` permission matches its single grant and
  its documented role. Do not touch Surface 3.
- Any reference to the private staging instance. ADR 0034 is the *public*
  dogfood record; local staging facts belong in the operator's own notes and
  must not enter a public ADR.
- Any code, test, or CI change. This is prose only.

## Acceptance

- ADR 0034 Surface 2 reads as the approved text, with the heading no longer
  claiming "minimum-read" and no verbatim `--permission read` mint command
  left in it.
- ADR 0037's `maintainer-dev` line names all three grants.
- No other ADR content changes; `git diff --stat` shows two files.
- The three-layer write justification is present and legible: grant versus
  token, bounded and revocable, host-confined.
- `cargo fmt --all -- --check` and a docs-appropriate gate only — no test run
  is warranted for a prose-only diff, and re-running a green suite for it is
  waste.

## Correction during implementation (2026-11-19)

The confirmed text above was drafted on 2026-09-10 and **two of its factual
claims did not survive being checked against the tree**. Both are recorded here
rather than silently fixed, because the block above is the maintainer's record
of what was approved.

1. *"Day-to-day mints are read+prefetch only; write-capable tokens are minted
   narrowly for the action at hand, bounded by token expiry."* **Not so.** The
   gitops role mints **one** token with all three permissions —
   `issue-svc-token --name maintainer-dev --permission read --permission
   prefetch --permission write` (`deploy/ansible/roles/gitops/tasks/main.yml`),
   widened by `7998b6bf` on 2026-08-20, which is *before* the draft. So the
   write capability is not bounded by narrow per-action minting, and a
   justification that leans on it would be claiming a mitigation the deployment
   does not have.

2. *"The mint check backs a token's declared permissions against global grants
   only; a repo-scoped write grant cannot back a write-capable token."* Half
   true, and the wrong half is load-bearing. The preflight takes a scope
   (`crates/hort-server/src/cli/admin.rs:325-345`): with `None` it checks
   unscoped grants, with `Some((repo_id, repo_name))` it checks at that
   repository and reuses the runtime's global-⊇-repo semantics. So a
   repo-scoped grant *can* back a repo-scoped token; what it cannot do is
   satisfy an **unscoped** mint. The accurate reason the grants are global is
   that the operator token is minted unscoped.

What the amendment says instead: the three grants and the single all-three
mint as facts; the grants are global *because the token is unscoped*; and the
bound on the write capability is **where the token is used**, not how narrowly
it is minted — which is the maintainer's own host-confinement argument,
unchanged. Revocability (delete the grant envelope and re-apply) survives, and
the mint's by-name idempotence is added, because it is the reason an
already-provisioned host keeps a narrower token until someone rotates it
deliberately.

The decision this item implements is untouched: record the as-built posture and
supply the missing justification for global write. Only two of the drafted
sentences were wrong, and they were wrong when drafted.
