# 080 — #130 class B close: rework proxy-multiarch-zero-window onto the designed hold-read path

**Issue:** #130 (release gate). Evidence and root cause: the two 2026-08-08
class-B comments on the issue. Summary: the scenario — contained in no released
tag; first-ever executions were the red beta gates — expects an **anonymous**
cold pull-through of the 24h-quarantining `oci-proxy-quarantine-e2e` repo to
return 200. The product, by design (ADR 0007 proxy-503 read path), ingests on
the triggering pull and answers 503 + `Retry-After` (`"artifact is
quarantined"`, confirmed live: `Retry-After: 83513` anchoring the window at the
scenario's own step-1 GET). The designed route for privileged reads of held
manifests is the ADR 0039 §10 write-authorized hold-read exemption — and this
is the only OCI e2e repo without a dev-write grant. Zero production code:
grant + scenario edits only.

**Read first:**
`scripts/native-tests/scenarios/quarantine/proxy-multiarch-zero-window.sh`
(whole header — the hollowness-trap and eligibility-predicate rationale MUST
survive this rework);
`deploy/compose/example-config/auth/dev-write-oci-quarantine-e2e.yaml` (the
grant shape to mirror);
`crates/hort-http-oci/src/manifests.rs` step-4 block (~:252-330 — the
`write_authorized_hold_read` predicate the reworked pulls ride);
`scripts/native-tests/lib/common.sh` `fetch_token`;
sibling `quarantine/proxy-required-multilayer.sh` legacy-mode auth block
(`fetch_token dev-user dev` → `Authorization: Bearer`) — the exact pattern to
reuse.

## Work

1. **Grant** — new `deploy/compose/example-config/auth/dev-write-oci-proxy-
   quarantine-e2e.yaml`: dev-user write on repository `oci-proxy-quarantine-e2e`,
   mirroring `dev-write-oci-quarantine-e2e.yaml` verbatim (subject shape,
   comment style; comment states the invariant: the zero-window scenario reads
   held manifests via the write-authorized hold-read exemption).
2. **Scenario rework** (`proxy-multiarch-zero-window.sh`):
   - New step 0 (regression pin of the hold itself): **anonymous** GET of the
     index by tag → assert **503**, `Retry-After` header present, body code
     `UNAVAILABLE`. This both pins the designed behavior and performs the cold
     ingest.
   - Step 1 becomes an **authenticated** GET (`DEV_TOKEN` via
     `fetch_token dev-user dev`, `Authorization: Bearer`) → assert 200 +
     `Docker-Content-Digest` (hold-read exemption path).
   - Step 2 (child manifest by digest) also authenticated → 200. This GET
     triggers the child's pull-through ingest; the #46 Item 2 zero-window
     carve-out anchors it — exactly what the DB differential assert then checks.
   - DB differential assertions (index full window vs child zero window) and
     the eligibility-predicate assert stay UNCHANGED — they are the scenario's
     purpose.
   - Update the header comment where it described the anonymous-200 expectation;
     keep the hollowness-trap section intact.
3. **No other changes.** Zero `crates/` edits, zero policy/upstream-mapping
   edits, zero changes to other scenarios or `lib/common.sh`.

## Scope / acceptance

- `bash -n` on the scenario; example-config revalidated via the offline
  `validate-config` invocation report 069 used.
- Full pre-push suite (expected Rust no-op; run anyway).
- Report states the exact assert lines added for step 0 (status + header +
  body code) and confirms the DB asserts are byte-identical.

**Model hint:** sonnet (bounded scenario+config edit; design decided on the issue).
