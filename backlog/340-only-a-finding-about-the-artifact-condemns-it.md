# 340 — Only a finding about the artifact condemns it

**Issue:** #351 · **Branch:** `agent/351-a-finding-condemns-only-its-own-artifact`
**Governing decisions:** ADR 0056 (as amended 2026-10-15 — this item *is* the
amendment's implementation) · ADR 0007 (fail-closed release predicate —
preserved, see §3) · ADR 0040 (the non-enforcing lane this reuses) · ADR 0059
(finding reconciliation — untouched, see §3).

**Depends on items 338 and 339.** This is the item that changes a verdict.

## 1. The one place the rule belongs

`evaluate_scan_result` (`crates/hort-domain/src/policy/scan.rs:258`) is the
single function that composes the per-rule evaluators into one `ScanOutcome`,
and it already receives the subject:

```rust
pub fn evaluate_scan_result(
    coords: &ArtifactCoords,
    findings: &[Finding],
    policy: Option<&ScanPolicyProjection>,
    exclusions: &[ExclusionProjection],
    now: DateTime<Utc>,
) -> ScanOutcome
```

Step 1 already filters the condemning set — `filter_excluded_findings` drops
rows matched by an active exclusion, and the post-exclusion `SeveritySummary`
is computed inside the function from the survivors, deliberately so that no
caller can supply a divergent aggregate. **Put this rule in the same place,
on the same principle:** a finding the artifact does not contain is removed
from the *condemning* set before the threshold walk, by the predicate item 338
introduced.

No signature change. No new parameter. One call site.

## 2. Recorded is not the same as condemning

The finding must **stay in the record**. It is real information — a consumer
may well care that a crate's own lockfile pinned a vulnerable dependency — and
removing it would trade one wrong answer for another. What changes is only its
*authority*:

- it does not contribute to the threshold walk, so it cannot block a release;
- it remains in `scan_findings` and on the events surface, queryable exactly
  as today.

This is the same split ADR 0040 already draws for informational findings:
present, counted on a non-enforcing lane, never gating. Reuse that lane rather
than inventing a second one; `collect_negligible_action` (step 4b in the same
function) is the existing shape to follow.

## 3. What must not move

- **ADR 0007 is preserved.** No release authority is added, removed or
  reinterpreted. An artifact still releases only through the enumerated
  `(reason, authority)` pairs. This item narrows what counts as a *blocking
  finding*; it does not create a new way out of quarantine.
- **ADR 0059 is untouched.** Alias-group collapsing and the
  information-quality merge decide *which finding survives a collision*; this
  decides *whether a surviving finding may condemn*. Do not re-key
  `merge_findings`.
- **The unassessed-severity floor stays as it is.**
  `crates/hort-adapters-scanner-osv/src/parse.rs:375` floors an unscored
  advisory to `Critical`. That is a known, deliberately deferred residual
  (see #351's own write-up) and is **out of scope here** — do not change it,
  and do not route around it.

## 4. The regression that matters more than the fix

A finding **about the subject itself** must still condemn exactly as before.
The failure mode of this change is taking too much away, and it is silent: an
over-broad predicate disarms the scanner while every test that only checks
"the bad artifact was rejected for the right reason" keeps passing on the
cases it still catches.

Pin both directions, with the negative first:

- a subject-component finding over the threshold → still blocks, unchanged;
- a non-contained-component finding over the threshold → no longer blocks, and
  is still present in the recorded findings;
- the `not established` default (item 338) → **blocks**, because a record
  whose relation was never established must keep today's behaviour;
- a format that contains its closure → every component condemns, unchanged.

## 5. Constraints

- `hort-domain` requires **100 % coverage** — every match arm, every error
  path, every boundary.
- No file under `migrations/` changes in this item.
- No issue, MR or backlog reference in any code comment.

## Acceptance

- `evaluate_scan_result` consults the item-338 predicate at exactly one point,
  and a reviewer can see it is the only consumer.
- All four cases in §4 are pinned by tests, the subject-still-blocks one
  written first.
- An artifact whose only finding names a component it does not contain
  evaluates to a non-blocking outcome, with the finding still listed.
- `cargo test --workspace` green; `cargo clippy --workspace --all-targets --
  -D warnings` clean.

## 6. The single-predicate rule gets a structural guard here

Unit 338 established `Finding::may_condemn_artifact` as the one place the
question "may this finding condemn its artifact?" is answered, and holds that
by construction alone — one function, one file, a rustdoc saying so. **This
item is where a second copy first becomes tempting**, because the threshold
walk lives in `crates/hort-domain/src/policy/scan.rs` while the predicate
lives in `crates/hort-domain/src/types/finding.rs`, and matching on
`component_relation` inline is the shorter path.

Convention is not enough for this shape, measured in this codebase: the
https-metadata rule was re-typed five times before
`crates/hort-app/tests/https_rule_is_single_sourced.rs` was written, and the
sixth consumer carried no copy at all.

**So add a DB-free source-scan guard in that family**, under `crates/*/tests/`
so `cargo test --workspace` runs it with no gate-list entry: reject any
`match` or comparison on `Finding::component_relation` outside the defining
file. Follow the established shape — **no allow-list** (a site that genuinely
needs an exemption is a review conversation, not an entry), and a
**counter-assertion** that the predicate and its definition are still found,
so a rename cannot make the scan vacuously green. Its known blind spot, which
the guard's own doc comment should state, is the one every source scan has: a
read reached through a differently-named helper.

## Acceptance (addition)

- The guard exists, runs under `cargo test --workspace`, and fails if a
  second reader of `component_relation` is introduced outside `finding.rs`.
- Its counter-assertion fails if the predicate is renamed or removed.

## 7. The merge must not launder a relation (raised by unit 339)

Tagging happens in the orchestrator, **before** `merge_findings` — correct,
because the producer's evidence is only in scope there. But
`prefer_replacement` picks the surviving finding for a
`(purl, vulnerability_id)` collision on severity / informedness / CVSS and
knows nothing about `component_relation`.

Today that is unobservable: for a lockfile pin both producers tag the same
advisory identically, and the only reachable divergence — a purl the BOM omits,
where a payload-scanned backend says `Contained` and an SBOM-driven one says
`NotEstablished` — ends in two relations that both condemn.

**This item makes it observable**, because the winner's relation now decides
release authority on an axis the merge never considered. So decide it here:

- The surviving finding must not silently inherit the loser's relation.
- Where two merged findings disagree, the **more condemning** relation wins.
  That is the fail-closed direction and the only one consistent with 338's
  default: authority is withheld only where non-containment was actually
  established, never as a side effect of which backend won a severity
  comparison.
- The comparison belongs beside the existing ranking in `prefer_replacement`,
  not as a second pass over the merged set.

Pin it: two findings for one `(purl, vulnerability_id)` with different
relations, merged in both input orders, yield the same surviving relation —
the more condemning one — regardless of which won on severity.

## Acceptance (addition)

- `prefer_replacement` resolves a relation disagreement to the more condemning
  relation, pinned in both input orders.
- A merge cannot produce a surviving finding whose relation is less condemning
  than any of its inputs.
