# 028 — `cargo audit` red on `develop`: `spin v0.9.8` yanked

- **Source:** GitLab issue #28 (surfaced incidentally by the #22 cockpit gate run)
- **Type:** chore (supply-chain / CI unblock)
- **Model hint:** **small** — mechanical `Cargo.lock`-only update + gate re-verify. **Must run in a `cargo`-capable environment** (the architect host has none — this is why it's a cockpit directive, not an in-session fix).
- **Reviewable unit:** one directive.

## Problem

`cargo audit --deny warnings` fails on `develop` because **`spin v0.9.8` is yanked**
(flagged by the live RustSec DB; not introduced by any recent diff — confirmed
identical on `develop` with zero `Cargo.lock` changes). `spin` is a transitive dep
via `flume`, `governor`, `lazy_static`, `multer`, `spinning_top`.

**Why it matters:** the CI `security:cargo-audit` / `security:cargo-deny` stages are
`main`/`release`/`tags`-gated, so `develop` pushes don't surface it — but it will
**block the next `develop → main` promotion and every `v*` tag**, including the
alpha/staging tags #25 just enabled. Clear it before the next release.

## Approach (per CLAUDE.md's audit guidance)

1. **Preferred:** `cargo update -p spin` (or `--precise <non-yanked 0.9.x>`) — a
   `Cargo.lock`-only bump to the latest non-yanked version that still satisfies the
   `^0.9` requirements of the dependents above. Let cargo resolve; do **not** hand-edit
   `Cargo.lock`.
2. Re-run **both** gates to confirm green: `cargo audit --deny warnings` **and**
   `cargo deny check` (they walk the graph differently and read separate ignore lists).
3. **Fallback only if no compatible non-yanked version exists** (flag it, don't do it
   silently): a version bump is strongly preferred over ignoring a *yanked* crate. If
   genuinely unavoidable, the yanked-handling/ignore must be mirrored into **both**
   `.cargo/audit.toml` and `deny.toml` (parity enforced by `security:advisory-sync`),
   with a justification comment — and this becomes a deliberate risk acceptance worth
   the maintainer's sign-off, not a default.

## Out of scope

- Any unrelated dependency bump (keep the `Cargo.lock` diff minimal — ideally just
  `spin` and anything cargo must move alongside it to keep the graph consistent).
- The separate Renovate-managed routine updates (#20).

## Acceptance criteria

1. `cargo audit --deny warnings` — green.
2. `cargo deny check` — green (`advisories/bans/licenses/sources ok`).
3. `Cargo.lock` diff is minimal (the `spin` bump + only what cargo must move with it);
   no `Cargo.toml` change unless a dependent's requirement genuinely forces it (flag if so).
4. No new `# AUDIT-ONLY` marker / ignore unless the fallback was unavoidable and
   justified (with maintainer sign-off called out in the report).

## Verification (for the cockpit report)

- Paste the `Cargo.lock` `spin` before/after and the full `cargo audit --deny warnings`
  + `cargo deny check` output (both green).
- Confirm no other advisory regressed and the `Cargo.lock` diff is minimal
  (`git diff --stat Cargo.lock`).
