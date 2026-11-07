# 396 — A delete leaves the blobs

**Issue:** #319 · **Branch:** `agent/319-a-delete-leaves-the-blobs` · single
item. **No production code changes** — one E2E scenario plus its gitops
fixtures.

**Governing decisions:** ADR 0003's CAS guarantee is what the scenario's last
assertion pins — a manifest delete removes the manifest, not the content.

## The property

**The OCI manifest DELETE is exercised end-to-end once**, so a regression in it
is visible before production. Today nothing runs it: across all 27 scenarios
and the host suites there is no `DELETE` against `/v2/<name>/manifests/<ref>`
— the only matches are a comment and a `psql` cleanup line.

That matters because the endpoint is destructive, authz-gated, and touches
`content_references`, the artifact lifecycle and the referrers projection; the
unit that last changed it could only lean on unit tests against mocks, and its
ordering is what decided whether blobs survived.

## Scope: the digest branch only, and why

`DELETE /v2/:repo_key/*tail` has two branches
(`crates/hort-http-oci/src/manifests_write.rs:1559`): a **tag** reference
routes through `RefUseCase::retire`, a **digest** reference deletes the
artifact and its content-reference rows.

**This item covers the digest branch.** Retiring a tag is not deleting an
artifact — different code path, different semantics — and folding it in as a
second step would put two subjects in one scenario. It gets its own scenario
when someone wants it, not a reflex step here. That is the issue's own lean,
and it is adopted rather than re-litigated.

## Four facts to build on, all verified against `develop`

1. **The response is `202`, not `200`** — deliberately. The handler's doc says
   OCI clients treat them identically here but the spec prefers 202 for
   asynchronous cleanup semantics. Assert 202.
2. **Authorisation runs against `DeleteRepoAccess`, not `WriteRepoAccess`.**
   A `write` grant does **not** authorise a delete. The handler's doc spells
   this out: an operator with `permissions: [write]` must add a parallel
   `delete` grant.
3. **No fixture grants `delete` today.** `deploy/compose/example-config/auth/`
   contains only `read` and `write` grants — grep it and see. So this scenario
   must bring its own grant, and that is part of the unit, not an accident.
4. **`admin` would bypass the grant** via the claim-keyed short-circuit in
   `hort_app::rbac::user_grants_authorize`, which `authorize` reaches through
   `authorize_explained`:
   `if permission != Permission::ReadMetrics && principal.claims.iter().any(|c| c == "admin")`.
   So the scenario must drive a **non-admin** identity, or it proves nothing
   about the grant.

   The function name is the anchor deliberately. Four production doc comments
   cite this as `rbac.rs:104`, and that line is now `DeniedBoth,` — a variant
   of the enum that *reports* a denial. A line number was never a durable
   anchor for it.

## A dedicated repository fixture, not `oci-e2e`

Give the scenario its own hosted OCI repository fixture with a permissive scan
policy, following the house style every other OCI scenario already uses
(`oci-quarantine-e2e`, `oci-trivy-e2e`, `oci-private-e2e`, …): a repository, a
permissive `ScanPolicy` so the push serves immediately and the test is not a
hostage to scan timing, and the grants its identity needs — `read`, `write`,
and `delete`.

**Do not add a `delete` grant to `oci-e2e`.** Three other scenarios share that
repository, and widening its grants would silently hand them a permission they
do not need — and would mean this scenario's own assertion no longer proves
which grant carried it.

## The scenario

Model it on `scripts/native-tests/scenarios/clients/oci.sh` — same `skopeo`
push shape, the same `mint_svc_token` path under the `native-tokens` overlay,
`# requires: egress` because it pulls a source image. Place it in `clients/`;
it is an OCI protocol operation, not a quarantine behaviour.

The run, in order:

1. Push a small multi-layer image to the fixture repository.
2. Resolve its manifest digest, and record **a layer blob digest** from the
   manifest body before deleting anything — after the delete the manifest is
   gone and the body cannot be read again.
3. `DELETE /v2/<repo>/manifests/<digest>` → expect **202**.
4. `GET` the manifest by the same digest → expect **404**.
5. `GET /v2/<repo>/blobs/<layer-digest>` → expect the blob **still resolves**.
   This is the assertion the whole scenario exists for: the blobs belong to the
   CAS and are the garbage collector's business, not the manifest delete's.

## What you cannot verify here, and must not claim

There is **no container runtime** in the sandbox — no `docker`, no `podman`, no
`/var/run/docker.sock`. The native E2E harness drives `docker compose`
throughout, so **you cannot run this scenario at all.** That is expected.

Verify what is verifiable: the scenario is syntactically sound
(`bash -n`, and `scripts/run-shell-guards.sh` if it reaches this path), the
fixtures parse as YAML, the `requires:` token is one the runner actually
provides, and the scenario appears in `--list`'s inventory. Say plainly in the
report that the scenario is unexecuted here.

This change is handed to the human on the branch for that reason. **No merge
request.**

## Acceptance

- A new scenario exists under `scripts/native-tests/scenarios/clients/`,
  self-describing in the house shape, declaring a `requires:` token the runner
  provides.
- Its gitops fixtures exist under `deploy/compose/example-config/`: a
  repository, a permissive scan policy, and `read` / `write` / `delete` grants
  for a non-admin identity. `oci-e2e`'s own fixtures are **untouched** — prove
  it with `git diff --stat origin/develop -- deploy/compose/example-config/auth/`.
- The scenario asserts, in this order: `202` on the delete, `404` on the
  manifest afterwards, and a **resolving** layer blob.
- `bash -n` clean on the new scenario; every new YAML file parses.
- `cargo test --workspace` green, run **once** — nothing here touches Rust, but
  the structural guards scan fixture trees and `alpha_fixtures` in particular
  parses gitops envelopes.
