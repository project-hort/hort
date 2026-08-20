# 126 — Write-authorized hold-read for the cargo sparse index

Issue: #179. Operator decision recorded on the issue (2026-08-20): extend the
**ADR 0039 §10** write-authorized hold-read exemption to the cargo index, and
record the widening in an ADR.

## Why

`cargo publish` resolves each crate's intra-workspace dependencies through the
registry index, even under `--no-verify`. `hort-crates` serves a `ReleasedOnly`
index and quarantines a freshly published crate for 1h, so every publish after
the first fails to resolve its just-uploaded sibling — mid-chain, with earlier
crates already uploaded and only yankable.

The fix is not to weaken quarantine. It is to apply a rule hort has already
decided.

## The principle — already decided, already implemented for OCI

**ADR 0039 §10**, shipped as `write_authorized_hold_read`
(`crates/hort-http-oci/src/manifests.rs`, `ArtifactUseCase::download_hold_read`):
a signer must resolve a held subject manifest *before* release, so a
**write-granted** principal may read a held **manifest**, while held **layer
blobs** stay `503`. The ADR states the boundary:

> no runnable content leaves quarantine (only the metadata manifest, only to a
> write-granted principal) and the transparent-proxy contract (quarantine
> invariant #5) is untouched.

Generalised: **a principal that may write to a repository may resolve held
*metadata* there; held *bytes* never leave quarantine, for anyone.**

Cargo maps one-to-one — sparse index entry ≙ manifest, `.crate` download ≙
layer blob.

## Proven preconditions — build on these, do not re-derive

**1. `cargo publish` needs index metadata only.** Measured against the live
registry using the real `hort-domain 0.11.0-beta.4` (published by
`v0.11.0-beta.4`, present and released). A scratch crate depending on it, with
an isolated `CARGO_HOME`:

```
cargo generate-lockfile   → Locking 1 package     → .crate files in cache: none
cargo package --no-verify → Packaged 4 files      → .crate files in cache: none
```

Neither step fetched a single `.crate`. The exemption therefore stays strictly
on the metadata side of the ADR 0039 §10 line, with no widening to content.

**2. Cap-vs-grants is a named concept — use the right one.**
`crates/hort-app/src/use_cases/repository_access.rs`:

```rust
enum AuthorityBasis {
    /// Grants leg ∧ cap leg — every standard resolve.
    CapIntersected,
    /// Grants leg only — the hold-exemption predicate
    /// (`resolve_granted_write`, ADR 0039 §10).
    GrantedOnly,
}
```

`resolve(repo_key, actor, level)` is `CapIntersected` and is what the cargo
index path calls today. **Reusing it with `AccessLevel::Write` would be
cap-intersected and could silently never engage** — the exact failure ADR 0039
§10 documents. Call `resolve_granted_write`.

## What to build

### 1. The exemption in the cargo index path

`crates/hort-http-cargo/src/serve.rs::serve_index_unified` already receives
`caller: Option<&CallerPrincipal>` and already runs the filters as a list:

```rust
let filters: Vec<Arc<dyn IndexFilter>> = vec![
    Arc::new(NonServableStatusFilter),
    Arc::new(IndexModeFilter::new(repo.index_mode)),
];
```

When the caller has **granted write** on the repo
(`resolve_granted_write`), admit `Quarantined` entries. Everything else —
`Rejected`, `ScanIndeterminate`, the `IndexModeFilter` behaviour, the
anti-enumeration 404 shape — is unchanged.

`Rejected` and `ScanIndeterminate` must **not** be exempted. The OCI precedent
covers held-pending-signature, not terminal verdicts.

Add a test that a **read-scoped token presented by a write-granted principal**
still receives the exemption — that is the ADR 0039 §10 trap, expressed as a
regression test.

### 2. `registry = "hort-crates"` on the workspace dependencies

**Without this the exemption is a no-op on the path the publish actually
takes.** Source replacement is active in the publish job (`hort-auth` writes
`.cargo/config.toml`): `[source.crates-io] replace-with = "hort"`, where
`registries.hort` is the **`cargo-virtual`** index. An intra-workspace dep with
no `registry` key is a crates.io dep, so it is replaced and resolved through
`cargo-virtual` — and the grants are asymmetric:

| grant | repository |
|---|---|
| `gha-release-write-hort-crates` | **hort-crates** |
| `gha-release-read-cargo-virtual` | cargo-virtual — read only |

Verified both directions: with an explicit `registry` key cargo reports
*"location searched: `hort-crates` index"*; without it, *"crates.io index"* —
and `--registry` on the CLI does **not** change that. An explicit-registry dep
is not subject to `[source.crates-io]` replacement, so it reaches the repository
where the principal holds write.

The `publishable_manifests` guard (added in #175) asserts the shape of these
entries — extend it to require the registry key rather than leaving it
optional.

### 3. Cache headers on the index route — same change, not a follow-up

The route emits **no `Cache-Control` and no `Vary`** today, and
`hort-http-cargo` contains no caching code. That is safe only because the
response is currently identical for every reader.

Once it varies by principal, a shared cache or reverse proxy may serve the
publisher's response — held entries included — to an anonymous consumer. Absent
directives are not "no caching": heuristic caching applies, and with no `Vary`
nothing tells an intermediary the response is identity-dependent.

Emit `Cache-Control: private, no-store` (at minimum `Vary` on the authorization
header) **in this change**, with a test asserting the header. This is the single
way this change produces the leak it exists to prevent.

### 4. The ADR

A **new ADR** referencing ADR 0039 §10 and recording the generalised principle
plus the cargo call site. Next free number is **0055**.

Prefer a new ADR over amending 0039: that ADR is about keyed provenance
verification, and cargo publishing is not — folding it in would muddy a
decision record that is currently precise. Reference it explicitly instead.

## Out of scope

The `hort-crates` ScanPolicy, `cargo-virtual`'s index mode, the vetted-index
preflight, and the publish loop's ordering. This changes who may see held
*metadata*, nothing else.

## Done when

A write-granted principal resolves a held sibling from the `hort-crates` index;
an anonymous or read-only caller still does not; held `.crate` bytes are served
to nobody; the route is uncacheable by shared caches; and ADR 0055 records the
widening.

---

## Appendix — approaches ruled out, with the reason

Kept so they are not re-proposed.

- **`indexMode: includePending`.** `IndexModeFilter` only decides the fate of
  versions with **no hort row** — its own comment: *"the only mode-dependent
  column is `None`"*. For a known status both modes keep it iff
  `is_servable_status` (`Released | None`), so a `Quarantined` row is dropped
  under both. And `hort-crates` is `type: hosted`, so the never-ingested column
  has no rows at all. The setting would change nothing.
- **`cargo publish --workspace`.** Measured: packages in dependency order and
  auto-selects the registry, but still resolves each crate through an index —
  fails at the second crate exactly like the sequential loop. Worth adopting
  later for ordering hygiene; it is not a fix.
- **Shortening `quarantineDuration`.** Would work (the window is already largely
  inoperative — `advisory-watch-tick` runs every 6h against a 1h window), but it
  weakens the guarantee for *every consumer* to solve a publisher-only problem.
  The exemption is strictly better.
- **Granting `curate` to `gha-release`.** Would work, but hands CI authority it
  does not need once the exemption exists.
- **Polling until each crate is servable.** Correct, ~5–6h of release wall
  clock. The DAG is 5 levels deep, so parallelising saves one wait, not five.
