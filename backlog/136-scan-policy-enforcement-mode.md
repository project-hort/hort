# 136 — `enforcement: reject | record` on ScanPolicy

Issue: #191, spec §2 D4. Operator decision recorded on the issue: publish
proceeds with findings; blocking at retrieval is the policy's job.
**Read first:** `crates/hort-config/src/scan_policy.rs`,
`crates/hort-domain/src/policy/scan.rs` (`evaluate_scan_result`),
`crates/hort-app/src/use_cases/quarantine_use_case.rs` (`record_scan_result`
and the reject transition), ADR 0041 (re-derivation from stored findings),
ADR 0015 (no accepted-but-inert fields).

1. New `ScanPolicy` field `enforcement`, values `reject` (default — today's
   behaviour everywhere, zero migration) and `record`. Apply-time validation
   rejects unknown values loudly.
2. Under `record`: the scan runs, findings persist, the verdict is computed
   and stored — but no automatic transition to `rejected`; the artifact's
   status is untouched by the verdict. Surfacing (API/metrics) unchanged —
   findings are queryable exactly as under `reject`.
3. ADR 0041 integration: tightening a policy `record → reject` re-derives
   from stored findings and re-holds the now-non-compliant population;
   loosening the reverse way un-rejects via authority #5. Pin both
   directions with tests.
4. ADR 0015 compliance: the field is enforced by the consuming use case in
   the same change — an accepted-but-inert `enforcement` value is the
   anti-pattern this project hard-blocks.

**Acceptance:** domain evaluation tests for both modes (100 % on touched
`hort-domain`/`hort-app` code); apply-time validation tests; the ADR 0041
both-direction tests; gitops-tree guard updated if the fixture tree gains the
field.
