# 137 — Re-enable scanning on hort-crates, ADRs, E2E

Issue: #191, spec §2 D5 + §4. Depends on items 134–136.
**Read first:** `deploy/ansible/files/gitops/policies/hort-crates-scan.yaml`,
`docs/adr/0034-public-dogfood-deployment.md`, `docs/adr/0041-…`,
`docs/adr/0055-…`, `scripts/native-tests/scenarios/dogfood/registry-supply-chain.sh`.

1. `hort-crates-scan.yaml`: `scanBackends: ["osv"]`, `enforcement: record`,
   window stays `0s`. Comment states the posture honestly: registry-computed
   verdict, recorded findings, retrieval-blocking via explicit policy
   tightening (ADR 0041).
2. **New ADR**: resolved-component SBOMs (scan-time payload extraction, the
   three-way branch, the range-floor prohibition) + the `enforcement`
   vocabulary. **Amend ADR 0034** Class A: scan posture becomes
   record-mode scanning; identity remains the write gate. Cross-reference
   from ADR 0055's scanning remark. ADR changes ride this issue's answered
   decision trail (#191, #187) — no separate agent:decision needed.
   The ADR's **"explicitly out of scope / open"** section must carry the
   proxy-lockfile question, decided-to-defer rather than decided: the
   payload path ships hosted-only because a proxied library's embedded
   lockfile is the upstream author's dev-time resolve, which consumers
   re-resolve and never run — findings from it would be hearsay with gate
   power under the default `enforcement: reject`. The counter-nuance is
   real and unresolved: a **binary** crate installed via
   `cargo install --locked` DOES run the embedded resolve, so for bins the
   upstream signal is genuine, and bin-vs-lib cannot be told apart cheaply
   at scan time. Open: whether proxy lockfile scanning happens at all, and
   under what enforcement if it does.
3. **E2E**: extend the cargo publish scenario — a two-crate workspace where
   crate B names A's feature AND the lockfile pins a known-advisory version;
   assert publish completes 2/2 under `record` and the finding is queryable
   afterwards.
4. Update the `public_deploy_gitops_tree` expectations if the new field
   appears in the tree.

   **Staging joins the same open section** (architect decision on the rev2
   review): the publisher-witness argument covers a staging upload exactly as
   a hosted one, but no staging-type repository exists in any live
   configuration (gitops, compose, native-tests), so extending the gate now
   would fix scan semantics for a dormant class nothing exercises. Include
   Staging when a staging flow materializes, and revisit the `hosted_only`
   metric label's name at that moment (it would then be a misnomer).

**Acceptance:** gitops tree test green; ADR index (0000) rows added; E2E
scenario passes locally (`--hort=compose`); the docs/glossary gains
`enforcement mode` if grooming surfaced the term (it did — add it).
