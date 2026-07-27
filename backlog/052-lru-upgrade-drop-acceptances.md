# 052 — #80: upgrade `lru` off RUSTSEC-2026-0002; drop all acceptances (build + registry)

**Issue:** #80 (maintainer-preferred remediation for blocker 2, superseding the just-merged
exclusions from !218)
**Read first:** `.cargo/audit.toml` (the RUSTSEC-2026-0002 ignore + its rationale — the pin
reason), `deny.toml` (the mirrored ignore), `crates/hort-app/src/use_cases/pat_cache.rs`
(the sole `lru` consumer: uses `get`/`put`/`push`/`iter`, `push -> Option<(K,V)>` eviction
at ~L261, already `NonZeroUsize` construction), workspace `Cargo.toml` (`lru = "0.12"`,
~L332), `deploy/ansible/files/gitops/policies/exclusions/` (the two files to REMOVE),
`scripts/check-advisory-sync.sh` (parity must stay green after the removals),
`~/.cargo/advisory-db/crates/lru/RUSTSEC-2026-0002.md` (patched range).

## Why (maintainer decision)

Upgrading removes the vuln outright instead of accepting a *critical* advisory in two
places: the clean version is already `released` in hort's own proxy (0.17.0/0.18.0/0.18.1
all passed OSV), crates-publish converges with **zero** acceptances, and the
build-vs-registry drift surface for this finding disappears entirely.

## Scope

1. **Pick the target version:** confirm RUSTSEC-2026-0002's patched range from the advisory
   db; prefer the **latest** patched line (0.18.x — already vetted clean in crates-proxy)
   unless the API delta forces otherwise. Verify whether `push` still returns
   `Option<(K, V)>` (the pin's stated reason) — if yes the adaptation is minimal; if the
   shape changed, adapt `pat_cache`'s eviction handling accordingly.
2. **Bump + adapt:** workspace `Cargo.toml` → the chosen version; `cargo update -p lru`;
   adapt `pat_cache.rs` as needed. **hort-app is the 100%-coverage tier** — every touched
   branch tested; the existing pat_cache eviction/TTL/index-consistency tests must still
   pin the behavioral contract (eviction returns the evicted pair; secondary-index cleanup
   on evict; the concurrency test).
3. **Drop ALL acceptances for this finding, atomically with the bump:**
   - `.cargo/audit.toml`: remove the `RUSTSEC-2026-0002` ignore (+ its comment block).
   - `deny.toml`: remove the mirrored ignore.
   - `deploy/ansible/files/gitops/policies/exclusions/crates-scan-rustsec-2026-0002.yaml`
     and `crates-scan-ghsa-rhfx-m35p-ff5j.yaml`: **delete** (registry-side acceptance gone
     too — the exclusions merged in !218 are superseded before ever being applied to prod).
   - `scripts/check-advisory-sync.sh` must pass afterward with **zero** lru entries on any
     axis (build ignores gone ↔ registry exclusions gone = parity holds; run it).
4. **Attribution:** a dep re-version is a dependency-graph change → run
   `scripts/regenerate-attribution.sh` and commit the updated
   `THIRD-PARTY-LICENSES.{md,json}` in the same change (CLAUDE.md rule; the alpha-cut trap).
5. **Do NOT** touch the four `REGISTRY-EXEMPT` markers (unrelated advisories, unchanged).

## Acceptance

- `lru` at a patched version; `pat_cache` tests green (100% tier held); `grep` confirms no
  `iter_mut`/`IterMut` usage appeared.
- `cargo audit --deny warnings` green **with the ignore removed** (the honest proof).
- `cargo deny check` green with its ignore removed.
- Both Exclusion files gone; gitops-tree guard + `check-advisory-sync.sh` green.
- Attribution regenerated in-change. Full gate green.

### Starter prompt

```
/hort-architect

Implement backlog item 052 (issue #80, maintainer-preferred remediation) on branch
agent/80-lru-upgrade. IMPORTANT: verify `git branch --show-current` before every commit —
never develop. Upgrade lru off RUSTSEC-2026-0002: confirm the patched range from the
advisory db, prefer 0.18.x (already vetted clean in the proxy), verify the push ->
Option<(K,V)> shape and adapt pat_cache.rs (hort-app = 100% coverage tier — test every
touched branch). Atomically drop ALL acceptances: the audit.toml + deny.toml ignores AND
delete both gitops Exclusion files from !218 (superseded). check-advisory-sync + gitops
guards must pass after. Regenerate THIRD-PARTY attribution in the same change (dep-graph
change). Full gate — cargo audit green WITHOUT the ignore is the honest proof. Report per
the handover protocol.
```
