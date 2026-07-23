# 046 — #73 step 1: surface the masked manifest-PUT 500 (diagnosability + idempotent-Conflict)

**Issue:** #73
**Read first:** `crates/hort-http-oci/src/manifests_write.rs` (`put_manifest_dispatch`, the 7 fold
sites), `crates/hort-app/src/use_cases/artifact_group_use_case.rs`,
`crates/hort-app/src/use_cases/ref_use_case.rs`,
`crates/hort-app/src/use_cases/content_reference_use_case.rs`. `/hort-architect`.

## Context (prod-confirmed, #73)

The hort-oci mirror 500s on the **worker** image's image-index PUT (server image succeeds; worker
has ~20 layers/arch). Prod data ruled out re-push/idempotency: content is **genuinely new** each run
(non-reproducible builds → disjoint digests), no duplicate `(repo,checksum)` rows. All manifests +
blobs `ingested` ms before the 500 — so it's a **genuine error at one of 7 sites** that fold *any*
error (incl. `DomainError::Conflict`) into a silent `OciError::Internal`, logging only `warn!` (**no
ERROR**), so it's undiagnosable from the logs. This step makes it legible; the actual fix (step 2) is
groomed once the surfaced ERROR names the failing write.

## Scope — diagnosability first (NOT the root fix yet)

The 7 sites in `manifests_write.rs` (lines ~665, 691, 719, 744, 784, 840, 892 — `add_member` ×3,
`ref_use_case.set`, `content_reference` inserts ×3):

1. **Log at `error!`, not `warn!`**, with rich context: the operation (which member/edge/ref), the
   full `DomainError` (variant + message), the manifest/index **digest**, repo, and referenced
   child digest where relevant. A 5xx must be diagnosable from the log (Tom will pull the surfaced
   ERROR to pin the genuine error on the worker index PUT).
2. **Treat a provable idempotent-duplicate `Conflict` as success** where the underlying op is
   genuinely idempotent (e.g. a `content_reference` edge that already exists, an `add_member`
   same-role no-op) — return success rather than 500. Do NOT swallow a *genuine* divergence Conflict
   (different primary role, different ref target): that stays an error, but now logged at `error!`
   and (optionally) mapped to a diagnosable 409 rather than an opaque 500. **Be conservative** —
   only collapse Conflicts you can prove idempotent; when in doubt, log + surface, don't swallow.

**Out of scope:** the actual root fix for the worker-index-PUT genuine error (step 2, after the log
names it). Do not attempt a speculative behavior change to "make it pass" — the goal here is to stop
masking the error.

## Acceptance

- All 7 sites log at `error!` with operation + `DomainError` + digest/repo context on failure.
- A provable idempotent-duplicate Conflict returns success (with a test); a genuine divergent Conflict
  is surfaced (logged at error!, not a silent 500) — tests for both.
- No behavior change on the success path; `put_idempotence_second_put_emits_zero_new_events` still passes.
- Full gate green.

### Starter prompt

```
/hort-architect

Implement backlog item 046 (issue #73 step 1) on branch agent/73-diagnose-manifest-500. IMPORTANT:
verify `git branch --show-current` before every commit — never develop. This is a DIAGNOSABILITY
change, not the root fix. In manifests_write.rs put_manifest_dispatch, the 7 sites (~665/691/719/744/
784/840/892) that fold any error into a silent OciError::Internal with only warn!: (1) log at error!
with the operation + full DomainError + manifest/child digest + repo; (2) treat a PROVABLE
idempotent-duplicate Conflict as success (test it), but surface a genuine divergent Conflict (logged
error!, optionally a 409) — be conservative, don't swallow genuine divergence. Do NOT attempt the
root fix for the worker-index-PUT error (that's step 2, after the logs name it). Run the full gate;
confirm put_idempotence_second_put_emits_zero_new_events still passes. Report per the handover protocol.
```
