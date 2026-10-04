# Apply-time linter rows — coverage matrix

Every **named** apply-time lint row, what it rejects, and — for the rows
that exist because a control is missing rather than because a value is
wrong — the condition under which the row is deleted again.

The rows live in
[`StaticConfigValidator::validate`](../../../crates/hort-app/src/lint/static_validate.rs)
and are consumed, in this order, by `PRE_WRITE_REJECT_ROWS` in
[`apply_config_use_case.rs`](../../../crates/hort-app/src/use_cases/apply_config_use_case.rs).
The same validator backs `hort-server validate-config`, so the offline
gate and the apply reach the same verdict on every row here.

## Read this table the right way

**"No named linter row" is not "unvalidated."** The second table below
exists because conflating the two is how a surface goes unchecked: a
reviewer looks for a rule key, finds none, and concludes the field is
unguarded — or, worse, finds a row-0 reference rule nearby and concludes
the field is guarded. The two tables are different questions:

- **Table 1** — is there a *named row with a rule key and a metric
  label*, i.e. a check an operator can grep for in the catalog and
  alert on?
- **Table 2** — where does this surface's validation actually live?
  Several surfaces are checked by the per-envelope validators, by the
  cross-document rules (row 0), or at runtime, with no rule key at all.

A new operator surface has to be placed in one of them deliberately.
Adding a field and placing it in neither is the
accepted-at-apply-inert-at-runtime defect [ADR 0015](../../adr/0015-apply-time-linter-inert-fields-and-naming.md)
treats as a hard block.

## Table 1 — the named rows

`metric` is the `rule` label on `hort_apply_config_linter_total`
(catalogued in [`docs/metrics-catalog.md`](../../metrics-catalog.md));
`—` means the row emits no metric.

| Row | Rule / metric | Subject | Rejects |
|---|---|---|---|
| 2 | `SaIssuerFk` / — | `ServiceAccount.federatedIdentities[].issuer` | an issuer reference no `OidcIssuer` envelope declares |
| 3 | `UnderConstrainedFederatedIdentities` / — | `ServiceAccount.federatedIdentities[]` | nothing — **advisory warning only** |
| 5 | `TrustUpstreamPublishTimeRequiresScanBackends` / `trust_upstream_publish_time_requires_scan_backends` | `UpstreamMapping` × resolved `ScanPolicy` | `trustUpstreamPublishTime: true` paired with a resolved `scanBackends: []` — the cross-opt-in collapse of the Gate-2 observation window ([ADR 0016](../../adr/0016-cross-opt-in-interaction-matrix.md)) |
| 6 | `PrefetchMaxAgeDaysNotImplemented` / `prefetch_max_age_days_not_implemented` | `ArtifactRepository.prefetchPolicy.maxAgeDays` | any non-`None` value |
| 6b | `PrefetchTriggerRequiresVersionDiscovery` / `prefetch_trigger_requires_version_discovery` | `ArtifactRepository.prefetchPolicy.triggers[]` | `transitive_deps` / `scheduled` on a format whose handler does not declare `VersionDiscovery` |
| 7 | `ProvenanceConfig` / — | `ScanPolicy.provenanceMode` + `provenanceBackends` + `provenanceIdentities` | the domain's provenance-config rules, plus `required` resolving to a format no `ProvenancePort` covers. Also emits the `verify_if_present`-without-identities **warning** |
| 7b | `RepoStorageBackendMismatch` / — | `ArtifactRepository.storage.backend` | a per-repository backend differing from the deployment's effective global backend |
| 7c | `ScanBackendCapability` / `scan_backend_capability` | `ScanPolicy.scanBackends[]` × governed repository | a backend the compiled-in capability map says cannot analyse that repository's format, and a repository no backend covers at all |
| 8 | `PermissionGrant` / — | `PermissionGrant` | the grant linter's rules, run offline. Rejects **or** warns per the resolved `LintConfig`. The metric is emitted by the apply's own grant stage under its per-rule keys (`single-claim-grant`, …), never from the validator |
| 9 | `RetentionUnusedForNotImplemented` / `retention_unused_for_not_implemented` | `RetentionPolicy.predicate` | `UnusedFor` at the root or nested in a `Composite` |
| 10 | `ScanPolicyLicensePolicyNotImplemented` / `scan_policy_license_policy_not_implemented` | `ScanPolicy.licensePolicy` | any value other than `{}` / omitted |
| 11 | `ExclusionScopeNotImplemented` / `exclusion_scope_not_implemented` | `Exclusion.scope` | any `{ repository: <name> }` |
| 12 | `VirtualMemberFormatNotEnforced` / `virtual_member_format_not_enforced` | `ArtifactRepository.virtualMembers[]` | a member whose `format` differs from the virtual's |
| 13 | `ScanPolicyMaxArtifactAgeNotImplemented` / `scan_policy_max_artifact_age_not_implemented` | `ScanPolicy.maxArtifactAge` | any value — the inert state is the absent field |

Rows 0, 1 and 4 are not in this table because they are not lint rows:
row 0 is `DesiredState::validate` (per-envelope + cross-document), row 1
is `validate_against` (snapshot/env), row 4 is the `scanBackends`
supported-**name** check. See
[the `validate-config` how-to section](../how-to/declare-gitops-config.md)
for which of them the offline gate runs.

### Row order is append-only

Apply aborts on the **first** row with an error finding, so a row
inserted ahead of an existing one changes which message an
already-failing config is rejected with. New rows are therefore appended
at the end — rows 9 through 13 all carry that note in their
`LinterRule` doc comment, and rows 10–13 were appended in that order for
exactly this reason.

### Retirement triggers

Six rows exist because a control is **missing**, not because the value
is wrong. Each is wrong the moment its control ships, and each names its
trigger in the `validate_*` doc comment:

| Row | Retired when |
|---|---|
| 6 — `maxAgeDays` | the prefetch planner gains a per-version published-at surface to gate against |
| 9 — `UnusedFor` | `RetentionUseCase` stops constructing `EvaluationInputs` with a hard-coded `last_downloaded_at: None` and feeds a real last-download anchor from a port |
| 10 — `licensePolicy` | `evaluate_scan_result` stops passing `&[]` for licences and feeds a real licence list from a port |
| 11 — `Exclusion.scope` | the finding filter reads the scope, which needs a repository identity on `ArtifactCoords`. At that point the dangling-reference rule row 0 does **not** have for this kind becomes required — it is the sibling of `push_scan_policy_scope_reference_errors` |
| 12 — `virtualMembers[].format` | a format-compatibility model for virtual aggregation exists, in apply **and** in serve-time member resolution |
| 13 — `maxArtifactAge` | a consumer feeds `ScanPolicyProjection.max_artifact_age_secs` and the artifact's ingest instant through `hort_domain::policy::evaluate_age_gates` and folds the resulting violation into the accumulator. The evaluator already exists and is not deleted by this row — the row withdraws the operator surface until something calls it |

The other rows are not on this list: they reject a configuration that is
wrong, and no future work makes them obsolete.

## Table 2 — surfaces with no named row, and where they are checked

| Surface | Checked by | Not a linter row because |
|---|---|---|
| `type: virtual` on a format with no serve-time member resolution | `validate_virtual_type_shape` (per-envelope, `hort-config::repository`) | the fact it needs — `VIRTUAL_SERVE_SUPPORTED_FORMATS` — is compiled in and visible to a single envelope. This is an [ADR 0015](../../adr/0015-apply-time-linter-inert-fields-and-naming.md) inert-field rejection **without** a rule key, which is why "no key" cannot be read as "no check" |
| `ScanPolicy.scope` / `RetentionPolicy.scope` naming an undeclared repository | row 0 — `push_scan_policy_scope_reference_errors`, `push_retention_policy_scope_reference_errors` | a dangling reference is a cross-document fact, and the rule exists to keep the apply's scope **resolver** from panicking on an unmapped name rather than to withdraw an assurance |
| `Exclusion.policy`, `UpstreamMapping.repository`, `PermissionGrant.repository` / `serviceAccount` | row 0 reference rules | same |
| `virtualMembers` entry that is undeclared, self-referential, duplicated, or itself `type: virtual` | row 0 (`DanglingVirtualMember`, the no-nested-virtuals rule) + per-envelope entry checks | same. Row 12 above is the *format* question these rules never asked |
| `Exclusion.scope` naming an undeclared repository | **row 11** — which refuses every repository scope, undeclared or not | a reference rule here would be dead code behind row 11, and row 11 is what keeps `ExclusionsApplier::resolve_scope`'s panic unreachable |
| `scanBackends` entry naming a backend this build does not compile in | row 4 (inline on the apply path) | not yet wired into the offline validator; row 7c catches most such typos as a side effect, because a name this build does not know analyses nothing |
| `proxy.credentials` | `ParseError::CredentialsFieldForbidden` — parse time | the field is forbidden outright, so it never reaches a `DesiredState` |
| A declared name that already exists as a `managed_by=local` row; `HORT_AUTH_PROVIDER=disabled` with `ClaimMapping` envelopes declared | row 1 — `validate_against` | needs the current-state snapshot / the deployment env, which the pure validator cannot hold by construction |
| `ScanPolicy.requireApproval`, `severityThreshold`, `negligibleAction`, `enforcement`, `quarantineDuration` | enforced at runtime (`policy::promotion`, `policy::scan`, `effective_quarantine_deadline`) | nothing to withdraw — these decide what they say they decide |
| `ScanPolicy.maxArtifactAge` carrying a malformed duration | row 0 — `validate_scan_policy_env`'s humantime parse | a parse failure is a per-envelope fact. The *field itself* is **row 13** above, which refuses every well-formed duration too; the format check stays beside it, so a malformed value trips both and the row-0 message is what the operator sees first |

### The gap this table found, and how it was closed

`ScanPolicy.maxArtifactAge` belonged in neither table when this page was
written. It is parsed, converted to `max_artifact_age_secs`, diffed
field-by-field, event-sourced onto the policy stream and persisted —
and never evaluated: `hort_domain::policy::age::evaluate_age_gates` has
**no production caller** (only its own unit tests), and
`ScanPolicyProjection.max_artifact_age_secs` is read by the Postgres
adapter solely to write it back. It was the same ADR 0015 shape as rows
10–12 with neither a row nor a runtime consumer, recorded here rather
than fixed because it was outside the scope of the item that produced
this page.

**Row 13 is that row.** The evaluator is deliberately kept: it is the
implementation the row is held open for, and the retirement trigger
above names the condition. A projection written before row 13 shipped
keeps its `max_artifact_age_secs` and keeps deciding nothing — the row
stops a *new* claim being accepted, it does not rewrite stored ones.

This is the page's own argument working: the surface was invisible to
review for as long as the two questions — "is there a rule key?" and
"where is this checked?" — were conflated into one.

## Adding a row

A new row touches five places, and the workspace's own tests fail until
four of them agree:

1. `hort-config::desired` — the pure `validate_*` function, with the
   inert default and (for a missing-control row) the retirement trigger
   in its doc comment.
2. `LinterRule` in `hort-app::lint::static_validate` — a new variant,
   appended; its `metric_rule` arm; a metric `rule`-label `const` if it
   emits one; and the call in `validate`, appended after the last row.
3. `PRE_WRITE_REJECT_ROWS` — the `error!` line and the `RowAbort`.
   `pre_write_validation_consumes_every_reject_row` matches `LinterRule`
   **without a wildcard**, so a new variant does not compile until it is
   classified, and then fails until it is in the table.
4. `static_validator_and_apply_agree_on_reject_rule` — a corpus entry,
   so the offline gate and the apply cannot drift on the new row.
5. `docs/metrics-catalog.md` — the `hort_apply_config_linter_total` rule
   list and its cardinality, plus **this table**.

For a row that rejects because a control is missing, name the retirement
trigger in the `validate_*` doc comment and delete the row, its metric
`const`, its catalog entry and its rows in both tables here in the same
commit that implements the control. A guard kept past the condition that
justified it is worse than no guard: the next reader has to re-derive
whether it still applies.
