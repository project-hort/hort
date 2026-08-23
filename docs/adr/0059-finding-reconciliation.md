# 0059 — Finding reconciliation: information-quality merge + alias-group collapsing

- **Status:** Accepted
- **Enforced by:** `Finding.severity_basis` (`SeverityBasis::{Assessed,
  Unassessed}`), emitted `Unassessed` at all three fail-closed sites
  (`hort-adapters-scanner-osv::parse`, `hort-adapters-advisory-osv`,
  `hort-adapters-scanner-trivy::severity`) and `Assessed` on every other
  emission path; `Finding::is_informed()` and the information-quality arms
  in `hort-app::scan_orchestration::prefer_replacement`, which reads
  `ScanOrchestrationConfig::allow_informed_downgrade` on every merge so the
  operator switch can never be inert (ADR 0015). Covered by the
  production-pairing, fail-open-protection, break-glass, and
  legacy-deserialisation tests. Alias-group collapsing is enforced by
  `types::alias_group::collapse_alias_groups`, called by
  `hort-adapters-advisory-osv`'s `query` and `hort-adapters-scanner-osv`'s
  `aggregate_findings`; covered by the `rand` / `typemap` / `traitobject`
  exemplars at both the domain and adapter tiers, the `traitobject` one
  being the negative that pins a scored advisory staying blocking.
- **Supersedes:** —
- **Relates:** [0007](0007-fail-closed-quarantine-release-predicate.md) (the
  fail-closed release predicate — **preserved**),
  [0040](0040-osv-informational-negligible-lane.md) (the informational
  negligible lane — **preserved**, and the "persist the fact, derive the
  interpretation" shape this reuses),
  [0015](0015-apply-time-linter-inert-fields-and-naming.md) (the knob is
  enforced in the consumer),
  [0016](0016-cross-opt-in-interaction-matrix.md) (**not triggered** — see
  below), [0041](0041-continuous-scan-policy-enforcement.md) (re-evaluation
  reads the stored findings this merge produced).

## Context

Cross-backend deduplication had no ADR. `merge_findings` collapsed findings
sharing a `(purl, vulnerability_id)` key and picked a winner by severity
tier, with one carve-out for informational classifications (ADR 0040).

Severity tier is the wrong discriminator, because two of the values it
compares are not the same kind of thing. When a backend cannot determine a
severity at all it emits `Critical` — the SUP-4 fail-closed floor, so that
an unreadable finding still trips a default `Critical` block threshold
rather than slipping under it. That record is byte-identical to a genuine
unscored `Critical`: same tier, `cvss_score: None`, `informational_class:
None`. The merge could not tell them apart, so the floor won every
collision, **including against a correctly-scored finding for the same
advisory**.

The production case: `rsa 0.9.10` / `RUSTSEC-2023-0071`. One backend scored
it, another could not read a severity and floored it to `Critical`; the
merge discarded the scored reading and the artifact sat terminally rejected
for six weeks on a verdict **no backend had actually reached**. Every
rescan reproduced it, because the inputs were unchanged and the merge was
deterministic.

A second, related problem: the same vulnerability arrives from different
backends under different primary ids (GHSA vs CVE vs RUSTSEC), so the
`(purl, vulnerability_id)` key does not collapse them at all and the
artifact carries duplicate findings for one advisory.

## Decision

### 1. `SeverityBasis` — persist which of the two a `Critical` is

`Finding` carries `severity_basis: SeverityBasis`, an enum (not a bare
bool, following `informational_class`'s "persist the fact" precedent — a
future consumer can distinguish more bases without a data migration):

- **`Assessed`** — the backend produced a real severity reading: a parsed
  CVSS score, a recognised severity label, or an informational
  classification.
- **`Unassessed`** — the backend could **not** read a severity and fell
  back to the unconditional `Critical`. Emitted at all three fail-closed
  sites, and nowhere else.

This records what the backend *did*, not what the merge should conclude
from it. The interpretation is derived at decision time by
`Finding::is_informed()`.

### 2. Legacy records default to `Assessed`, deliberately

`#[serde(default)]` yields `Assessed`. This is the fail-safe direction and
it is not an accident of enum ordering:

A record persisted before the field existed **cannot be proven** to be a
fail-closed default. Defaulting it to `Assessed` preserves exactly today's
behaviour for it — a legacy `Critical` still wins on tier and is never
talked down. Defaulting it to `Unassessed` would let a scored `Low`
supersede a legacy **genuine** `Critical`, silently converting the entire
pre-existing finding corpus into fail-open input. That is the one change
here that could weaken a live gate, so the default goes the other way.

The consequence is accepted: legacy records that genuinely *were*
fail-closed defaults stay stranded under this ADR alone. They are un-stuck
by **re-emission with a correct basis** (the terminally-rejected
remediation sweep, below), not by a permissive default. "Re-derive the
fact" beats "assume the fact".

### 3. Information quality first, severity tier second

A finding is **informed** iff it has a real `cvss_score`, **or** a
recognised informational classification, **or**
`SeverityBasis::Assessed`. The complement — `Unassessed` with neither a
score nor a class — is **uninformed**: its `Critical` is a floor, not an
assessment.

- An informed finding supersedes an uninformed one for the same advisory,
  **across severity tiers**. A scored `Medium` beats an `Unassessed`
  `Critical`.
- Two informed findings still compare by **severity tier**, unchanged. A
  scored `Critical` is never talked down by a scored `Low` — ADR 0007 holds
  where it actually applies, between two real readings.
- Two uninformed findings compare by tier as before.
- ADR 0040's informational arms sit **ahead** of this rule and are
  unchanged: `is_informational()` stays gated on `cvss_score.is_none()`, so
  any real CVSS always blocks and a scored member is the
  highest-information reading by construction.

The fail-open protection is keyed on `SeverityBasis`, **not** on
`cvss_score.is_none()`. Keying it on the absent score would have made every
unscored-but-genuinely-assessed finding uninformed, which is a much larger
and unintended weakening.

**Accepted residual risk.** Where two backends disagree and the *lower*
reading is the wrong one, a wrong `Low` now outranks the other backend's
unknown-defaulted `Critical`. This is the deliberate trade. An unassessed
`Critical` is not evidence of severity — it is evidence that one backend
could not parse the advisory — and treating it as evidence is what kept
correctly-scored advisories terminally rejected. The risk is bounded by
the fact that the surviving reading is still a real reading from a
configured backend, and by the break-glass switch below.

### 4. Break-glass switch, default-on and enforced

`HORT_FINDING_MERGE_ALLOW_INFORMED_DOWNGRADE` (default `true`), surfaced as
the Helm value `worker.scanner.findingMerge.allowInformedDowngrade` and
threaded onto `ScanOrchestrationConfig::allow_informed_downgrade`.

Set `false` and the merge reverts to strict always-fail-closed: the
information-quality rule is skipped entirely and the `Unassessed`
`Critical` wins on tier again, exactly as before this ADR. Note the
direction — **engaging the switch makes the release gate stricter**, which
is the opposite of the ADR 0015 inert-knob smell and of a
fail-open opt-in. It is an escape hatch for an operator who would rather
absorb false rejections than let one backend's lower reading supersede
another's unknown default.

The switch is read **inside `prefer_replacement`, on every merge**. A field
accepted at config time and ignored at runtime is a hard block (ADR 0015);
a `run_scan` test pins identical inputs producing opposite outcomes under
the two settings, so the flag cannot silently become inert.

### 5. Alias-group collapsing and the terminally-rejected sweep

§3 reconciles two readings of **one advisory id**. It cannot reconcile
one advisory that arrives under **two ids** — and OSV routinely returns
exactly that: a RustSec advisory *and* its GitHub-reviewed GHSA mirror, as
separate records in the same response. The RustSec copy carries the
metadata; the mirror frequently carries neither a severity nor an
informational marker, so it lowers to the SUP-4 `Critical` floor and
shadows its better-informed sibling — with §3 powerless, because the two
have different ids. `rand 0.7.3` and `typemap 0.3.3` are rejected this
way; `traitobject 0.1.1` is the same shape but genuinely scored (CVSS
9.8) and must stay rejected.

**Mutually-aliased findings for one package are one advisory, and only
the best-informed member survives.** `Finding.aliases` already carries the
cross-id set (populated by both OSV adapters and by Trivy's `VendorIDs`,
and already consumed by `policy::exclusion::cve_matches`), so the grouping
needs no new data: union-find over `{id} ∪ aliases`, scoped to a `purl`,
transitive, with the winner chosen by an explicit information ranking —
**real CVSS > recognised informational class > a severity genuinely read
without a score > the SUP-4 fail-closed floor**. The middle two refine
§3's `is_informed()` into the finer order this selection needs; the
lowest tier is exactly `SeverityBasis::Unassessed`. Collapsed-away
identifiers are unioned onto the survivor's aliases (collapsed primary
ids first, hard-truncated at the alias cap) so an operator exclusion
keyed by any member id still clears the advisory.

**Where it runs: in the two OSV adapters, not on the cross-backend merge
key.** The shadowing happens *inside a single backend's output* — OSV
returns both records in one response — so a deployment running
`scanBackends: ["osv"]` alone is affected, and the cross-backend merge
never even executes there. Widening `merge_findings`'s key to alias groups
would also change the dedup key for every other backend, which is a much
larger behavioural change than the defect needs. The rule itself lives
once, as a pure domain function (`types::alias_group::collapse_alias_groups`)
that both OSV adapters call; the scanner adapter additionally folds
osv-scanner's own `groups[].ids` into each lowered finding's aliases, so
its grouping is honoured without a second grouping implementation.

**Known residual, deliberately not closed here:** two *different* backends
reporting one advisory under different ids (trivy's `CVE-X` against osv's
`GHSA-Y`) still produce two findings, because neither adapter sees the
other's output and the cross-backend merge still keys on
`(purl, vulnerability_id)`. Closing it means applying the same collapse to
the merged set in `scan_orchestration`. That is a one-line change with a
wider blast radius (it would re-key trivy's findings too), so it is a
separate decision rather than a silent widening of this one.

The stranded-legacy consequence of §2 is closed by a **remediation sweep**
over terminally-rejected artifacts, re-scanning them so their findings are
re-emitted with a correct `severity_basis` and a collapsed alias group.
Re-derivation, not a permissive default. The sweep is **operational**:
`rejected` is deliberately excluded from the *automatic* cron-rescan
candidate queries (ADR 0007), so freeing a stranded artifact is a deliberate
operator action rather than an automatic one. It uses the existing admin
tools — manual rescan then curator re-evaluate; see the Consequences section.

## ADR 0016 — not triggered

The cross-opt-in interaction matrix governs operator opt-ins that let
**untrusted input** influence the release-gate computation
(`trust_upstream_publish_time`-shaped, `scan_backends: []`-shaped,
`IndexMode`-shaped). This is neither:

- The inputs are **trusted advisory-DB data** and our own adapters' parse
  results — never artifact-supplied or upstream-supplied content. An
  attacker cannot author a `SeverityBasis`; it is set by the adapter
  according to whether *our* parser succeeded.
- The one operator surface introduced (`allowInformedDowngrade`) moves the
  gate in the **stricter** direction when engaged, so it cannot combine
  with another opt-in to collapse an observation window or widen an
  admitted set.

**The one interaction worth documenting:** the merge feeds the
`SeveritySummary` that `negligible_action` consumes (ADR 0040) and that the
threshold walk enforces. That relationship is **unchanged** — this ADR
changes *which* finding survives a collision, not how a surviving finding
is counted or enforced. An informational finding still routes to
`negligible`; a scored finding still routes to its tier. No new path exists
by which the summary can be computed from a finding that no backend
produced.

## Consequences

- A correctly-scored advisory is no longer discarded because another
  backend could not read it — the `rsa 0.9.10` class of terminal rejection
  cannot recur for newly-emitted findings.
- `Finding` gains a field, additively: `#[serde(default)]` keeps every
  persisted event and cached blob parseable, and no migration is required.
- The `scan_findings` projection is **not** extended with the basis. The
  merge operates on in-flight backend output and on the CAS-stored
  `findings_blob` (which round-trips the full `Finding`, basis included);
  the projection is a read model for listing and retention, and no merge
  reads from it. Adding a column would be cost with no consumer.
- Operators get one new switch whose only effect is to make the gate
  stricter, and whose default requires no action.
- A backend that starts reporting severities it previously could not read
  changes merge outcomes without any config change — which is the intended
  behaviour, since the merge follows the best available reading.
- Alias-group collapsing reduces the finding **count** for a package whose
  advisory has mirrors. A per-advisory count is now a count of advisories
  rather than of database records, which is the honest number, but an
  operator watching finding volume will see a step change at deploy.
- **Artifacts already `rejected` are not freed *automatically*, but are
  freed by an operator with the existing admin tools.** `rejected` is
  deliberately excluded from the *automatic* cron-rescan candidate queries
  (ADR 0007) — `select_eligible` takes `released`/`NULL`, `select_stranded`
  takes `quarantined` — so nothing auto-re-runs the collapsing code over
  them. The operator flow is **manual rescan → curator re-evaluate**, and it
  needs no new mechanism: `POST /api/v1/artifacts/{id}/rescan`
  (`ManualRescanUseCase`, by-id, with no terminal-state gate) re-runs the
  scan under the new code and appends a fresh `ScanCompleted` carrying the
  collapsed findings; then
  `POST /api/v1/admin/curation/quarantine/{id}/reevaluate` (`Rejected`-only,
  ADR 0025) re-derives the verdict from the **latest** event-store scan
  evidence — the just-refreshed findings — and resets to
  released/quarantined. Re-evaluate *alone* would not help (it re-derives
  from the pre-collapse evidence); the rescan step is what refreshes it.
  This is **not** an ADR 0007 exemption — the rescan re-runs the release
  gate rather than bypassing it. (Alternatives that avoid a rescan: an
  exclusion on the bare mirror id, which re-evaluation clears via release
  authority #5 at the cost of a standing exclusion; or purge-and-re-ingest.)

## Alternatives considered

- **Key the rule on `cvss_score.is_none()` instead of a new field.**
  Rejected: it conflates "unscored" with "unassessed". Many genuinely
  assessed findings carry no CVSS (label-derived severities, informational
  advisories), and demoting all of them is a far broader weakening than the
  problem requires.
- **Persist a derived boolean (`is_fail_closed_default`).** Rejected for
  the same reason ADR 0040 rejected persisting the informational boolean:
  it freezes one interpretation. The enum records the fact; consumers
  derive.
- **Default legacy records to `Unassessed`.** Rejected — see §2. It would
  convert the whole existing corpus into fail-open input to buy an
  un-stranding that the remediation sweep provides safely.
- **Drop the merge preference entirely and keep both findings.** Rejected:
  the duplicate then double-counts in `SeveritySummary` and the
  fail-closed floor still blocks, so nothing is fixed and the summary
  becomes wrong as well.
- **Make the fix operator-opt-in (default off).** Rejected: the default
  behaviour was producing verdicts no backend reached. A correctness fix
  that requires an operator to discover and enable it leaves every existing
  deployment broken. The switch therefore defaults on, and exists to
  restore the old behaviour rather than to unlock the new one.

## References

- `crates/hort-domain/src/types/finding.rs` — `SeverityBasis`,
  `Finding::severity_basis`, `Finding::is_informed`.
- `crates/hort-domain/src/types/alias_group.rs` —
  `collapse_alias_groups`, the information ranking, and the alias-union
  contract.
- `crates/hort-adapters-postgres/src/rescan_candidates.rs` —
  `select_eligible` / `select_stranded`, the two queries that exclude
  `rejected` and so make the remediation sweep operational rather than
  automatic.
- `crates/hort-app/src/use_cases/scan_orchestration.rs` —
  `merge_findings`, `prefer_replacement`,
  `ScanOrchestrationConfig::allow_informed_downgrade`.
- `crates/hort-adapters-scanner-osv/src/parse.rs`,
  `crates/hort-adapters-advisory-osv/src/lib.rs`,
  `crates/hort-adapters-scanner-trivy/src/severity.rs` — the three
  fail-closed emission sites.
- `crates/hort-worker/src/config.rs` —
  `HORT_FINDING_MERGE_ALLOW_INFORMED_DOWNGRADE`.
- `deploy/helm/hort-server/values.yaml`,
  `deploy/helm/hort-server/templates/worker-configmap.yaml` — the Helm
  surface.
- `docs/architecture/reference/server-and-worker-configuration.md` — the
  operator env-var reference.
- `docs/architecture/explanation/scanning-pipeline.md` — where the merge
  sits in the pipeline.
