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
| 14 | `SaRotationTargetConflict` / — | `ServiceAccount.fallbackRotation.targetSecret` | two `ServiceAccount` envelopes declaring the same `(namespace, name)` target — the reconciler's ownership barrier refuses one of them on every tick, so its declared rotation never happens |
| 15 | `ScanPolicyCompositeVerdictModeRetired` / `scan_policy_composite_verdict_mode_retired` | `ScanPolicy.compositeVerdictMode` | any value — the inert state is the absent field. The composed image's verdict decides its manifest's release unconditionally ([ADR 0064](../../adr/0064-a-filesystem-finding-is-about-the-composed-filesystem.md) D2), so neither value selects anything and nothing reads the field. **Retired, not deferred**, like row 17: no future implementation gives it a consumer. The field stays in the `deny_unknown_fields` spec solely so this rejection replaces an `unknown field` parse error |
| 18 | `OciRepositoryRequiresScanBackends` / `oci_repository_requires_scan_backends` | `ScanPolicy.scanBackends` × governed repository | an **empty** `scanBackends` on an effective policy governing a `format: oci` repository. The composition is the unit of assessment for an OCI artifact and now the only thing carrying a verdict on one ([ADR 0064](../../adr/0064-a-filesystem-finding-is-about-the-composed-filesystem.md) D2), and the waiver returns `SkippedNoBackends` before a composition is resolved — so no image is ever assessed while the waiver is itself the release authority. The **exact complement of row 7c**, which returns early on the empty list this row judges, so the two partition `scanBackends` and neither restates the other. Evaluated over the effective pairing (same resolver as row 7c), because a `ScanPolicy` has no format scope — `global` or `{repository: X}` — so "governs an OCI repository" is a question only the resolved pairing answers. The waiver stays supported for **every other format** |

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
at the end — rows 9 through 18 all carry that note in their
`LinterRule` doc comment, and rows 10–18 were appended in that order for
exactly this reason.

Appending means **two** places, not one, and row 18 is where that became
load-bearing. `static_validator_and_apply_agree_on_reject_rule` compares
the report's *first error* against the apply table's *first row with
findings*, so a row's position in `StaticConfigValidator::validate` has to
match its position in `PRE_WRITE_REJECT_ROWS`. Row 18 reads the same two
scope tables as row 7c and would naturally have been collected in that
row's walk; it is collected at the end of `validate` instead, in its own
walk, because its table entry is last.

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
wrong, and no future work makes them obsolete. Row 14 is one of them —
two ServiceAccounts cannot share a rotation target under any
implementation, because the owner of a Secret is a single value. Rows 15
and 17 are on it for a different reason again: both name a **retired**
field rather than a missing control, so there is no implementation to
wait for and the only thing that retires the row is the field leaving
the spec. Row 18 is not on it either, and for row 5's reason: a waived
scan composes nothing under any scanner that ships later.

Row 5 is still the only row whose subject is **two** operator opt-ins
collapsing. Row 18 is the surviving half of the row that used to be the
second: row 15 previously rejected `compositeVerdictMode: promoted` ×
`scanBackends: []`, and when the composed verdict's authority stopped
being an opt-in at all, the half that remained an operator declaration
was the waiver. One declaration now does what two used to, which makes
the rejection **wider** than the one it replaces — and is why it could
not stay a per-envelope rule in `hort-config`: the other half is the
governed repository's `format`, which no single `ScanPolicy` envelope
carries.

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
| `UpstreamMapping.allowedRealmHosts` | `validate_allowed_realm_hosts` (per-envelope, `hort-config::upstream_mapping`) + the value-object constructor + two schema CHECKs | both rules are decidable from this one envelope — the auth type and the list are in the same spec — so per-spec validation is the earliest place the verdict exists and the only one provably before the bundle's first write, exactly as [`validate_tls_material`](../../../crates/hort-config/src/upstream_mapping.rs) argues beside it. The non-`bearer_challenge` rejection is an [ADR 0015](../../adr/0015-apply-time-linter-inert-fields-and-naming.md) inert-field rejection **without** a rule key, like `validate_virtual_type_shape` above. A mapping with no `secretRef` is deliberately **not** rejected: the consumer (the credentialed realm exchange) comes into being the moment a secret is added to the same mapping, so the field is conditional, not inert |
| `UpstreamMapping.notFoundCacheSeconds` | `validate_not_found_cache_seconds` (per-envelope, `hort-config::upstream_mapping`) + `push_upstream_mapping_format_compatibility_errors` (row 0, cross-document) + the value-object constructor + a schema CHECK | the value rule — a positive number of seconds the `integer` column can hold — is decidable from this one envelope, so per-spec validation is the earliest place the verdict exists and the only one provably before the bundle's first write, the same argument [`validate_tls_material`](../../../crates/hort-config/src/upstream_mapping.rs) makes for its siblings on this kind. It is a *value-range* check rather than an [ADR 0015](../../adr/0015-apply-time-linter-inert-fields-and-naming.md) inert-field withdrawal or an [ADR 0016](../../adr/0016-cross-opt-in-interaction-matrix.md) cross-opt-in collapse, which is what every row in Table 1 is; the rule itself is the domain's `not_found_cache_seconds_reason`, shared rather than mirrored, exactly as `allowedRealmHosts` shares `allowed_realm_host_reason`. `0` is refused because it would be *enforced* — a zero TTL re-fetches on every retry inside the negative-cache window, the coalescing loss the window exists to prevent, which is also why `HORT_PULL_DEDUP_TTL_NOT_FOUND_SECS` refuses it. The **format**-effective half is a row-0 cross-document rule because it needs the parent repository's `format` in scope: only the Maven pull-through legs pass the value to `PullDedup`, so the field on any other format would be stored and never read, and that rejection is deleted per format as each format's legs are wired |
| `PermissionGrant.subject.userId` that is not UUID syntax | row 0 — `validate_permission_grant`'s `Uuid::parse_str` | UUID syntax is a per-envelope fact, so per-spec validation is the earliest place the verdict exists. It is also the only place provably before the bundle's first write: the consolidated grant reconcile runs **last**, so the parse that used to own this verdict refused a typo only after the repository, policy and mapping writes of the same bundle had committed. That parse is now a `DomainError::Invariant` this rule makes unreachable — the same shape `Permission::from_str` beside it already had. Whether the UUID names an **existing user** is deliberately unchecked: it is not a static property of the bundle |
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
   in its doc comment. A row whose verdict spans *envelopes* rather than
   reading one spec — rows 2 and 14 — lives in
   `hort-app::lint::static_validate` instead, beside the other
   cross-envelope validators, and returns rendered message strings
   directly.
2. `LinterRule` in `hort-app::lint::static_validate` — a new variant,
   appended; its `metric_rule` arm; a metric `rule`-label `const` if it
   emits one; and the call in `validate`, appended after the last row.
   **Appended there even when the row could share an earlier row's walk** —
   the report position has to match the table position in (3), or step
   (4)'s test fails for a config that trips both rows (see *Row order is
   append-only* above).
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
