# 081 — #133 item 1: shared per-repo svc-token mint helper + fix the three stale mint call sites

**Issue:** #133 (native-tokens E2E lane repair; scheduled after the 0.10.0
train). Dispatched first — items 082/083 build on this helper.

**Context:** three scenarios admin-mint svc tokens **without
`repository_ids`**. The issuance gate treats that as a global token: every
declared permission must be held **globally** by the target SA
(`run_issuance_gates`, global branch — "a per-repo-only grantee CANNOT mint a
global token, only a per-repo one"). The e2e SAs hold deliberately repo-scoped
grants, so the mint is 403 `CapExceedsAuthority` — correct product behavior
(the admin-short-circuit hole it replaced was the security bug); the scenarios
are stale. Additionally the call sites mask the failure
(`2>/dev/null | jq -r '.token // empty'` → "returned no token" and the
misleading "no users row … or mint failed").

**Read first:**
`crates/hort-app/src/use_cases/api_token_use_case.rs` — the cap-vs-authority
walk (global vs `Some(ids)` branches) and `issue_for_service_account`'s
target-SA authz subject;
the three call sites: `scripts/native-tests/scenarios/quarantine/provenance-push-then-sign.sh`
(~:229-240), `quarantine/proxy-required-multilayer.sh`,
`clients/oci-private-pull.sh` (native-mode branch);
`scripts/native-tests/lib/common.sh` (helper conventions, `fetch_token`,
diagnosability precedent in `assert_metric_ingest`/`metrics_scrape_diag`).

## Work

1. **`lib/common.sh` helper** `mint_svc_token <sa-username> <repo-key>[,<repo-key>…]`:
   - resolve the SA uid and each repo's **uuid** via `HORT_DB_DSN` psql
     (NB: `repositories.key` holds the repo key; `name` is the display name);
   - admin-mint (`POST /api/v1/admin/users/<uid>/tokens`) with the caller's
     `declared_permissions` and `repository_ids:[<uuids>]`;
   - on ANY failed step, print the failing stage + HTTP status + problem+json
     body excerpt to stderr and return non-zero — no silent empty-token path.
2. **Convert the three call sites** to the helper (declared permissions stay
   what each scenario needs — `read`,`write`; scope = the scenario's repo).
   Remove their bespoke mint blocks.
3. **Negative regression pin** (in ONE of the three scenarios, native mode
   only): a deliberate global mint (no `repository_ids`) for the repo-scoped
   SA asserts 403 and `cap_exceeds_authority`-shaped denial — pins the
   issuance invariant at the E2E tier.

## Scope / acceptance

- No `crates/` changes; no changes to run.sh; legacy-mode scenario behavior
  byte-identical.
- `bash -n` on every touched script; full pre-push suite (expected Rust
  no-op).
- Acceptance vehicle: `run.sh --hort=compose --compose-overlay=native-tokens`
  — the three mints succeed; report cites the issuance-gate branch the tokens
  now satisfy.

**Model hint:** sonnet.
