# 082 — #133 item 2: native-posture adaptation for the three non-adapting OCI client scenarios

**Issue:** #133. Dispatched AFTER item 081 (uses its `mint_svc_token` helper).

**Context:** under the native-tokens overlay the anonymous `/v2` challenge is
`Bearer realm=…/v2/auth` and OCI clients run the Distribution-Spec token
dance — whose Basic mint carrier is a **PAT/svc token** (auth-catalog
Entries 7/8). `clients/oci.sh`, `clients/oci-push-under-quarantine.sh`, and
`quarantine/oci-image-index.sh` pass the Keycloak `DEV_TOKEN` as the skopeo
password unconditionally, so every push/pull dies with
`unable to retrieve auth token: … invalid credential` (2026-08-08 overlay-run
baseline). The overlay's own header documents the intended adaptation
(`HORT_COMPOSE_OVERLAYS` detection), already implemented by
`provenance-push-then-sign.sh` and `oci-private-pull.sh`.

**Read first:** `deploy/compose/docker-compose.native-tokens.yml` header;
the two already-adapting scenarios' native-mode branches (the detection +
credential-switch pattern to mirror); `deploy/compose/example-config/
service-accounts/provenance-ci.yaml` + its paired grants (the SA exemplar);
ADR 0052 (single-capability SA spirit).

## Work

1. **Identity material** (gitops example-config): writer SA(s) + repo-scoped
   write PermissionGrants covering `oci-e2e` and `oci-quarantine-e2e`,
   mirroring the `provenance-ci` file/comment conventions.
   `oci-image-index.sh` drives BOTH repos in one run and needs one token
   spanning both → one SA holding both grants, minted with both
   `repository_ids`, is the expected shape; a per-repo split is acceptable if
   the implementer finds it cleaner within the single-capability spirit —
   grant scoping itself is not negotiable. Read scenarios first to determine
   whether read grants are also required (pull legs).
2. **Scenario adaptation**: in each of the three scenarios, when
   `HORT_COMPOSE_OVERLAYS` contains `native-tokens`, mint via item 081's
   helper and use the svc token as the skopeo/docker credential (mirror the
   provenance scenario's credential-switch block verbatim in style). Legacy
   mode stays byte-identical.

## Scope / acceptance

- No `crates/` changes; no overlay/compose changes; no `lib/common.sh`
  changes beyond what 081 landed.
- `bash -n` on touched scripts; example-config revalidated offline
  (`validate-config` invocation from report 069); full pre-push suite.
- Acceptance vehicle: `run.sh --hort=compose --compose-overlay=native-tokens
  --group clients` + the `quarantine/oci-image-index` scenario — the three
  2026-08-08 failures green; legacy base lane untouched.

**Model hint:** sonnet.
