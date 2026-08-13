# 094 — #65 bounded await: skip when release is provenance-blocked (and before a served-anyway HEAD)

**Issue:** #135 (acceptance-blocking rider) · **Branch:** `agent/135-late-joiner-clearance` · **Scope:** `hort-http-oci` + `hort-app`

## Problem (evidence-backed)

`maybe_bounded_await_release` (`crates/hort-http-oci/src/blobs.rs`, the #65
cold-blob first-GET release race) polls up to
`oci_pullthrough_release_wait_secs` (default 10s) whenever a blob is
`Quarantined` with its window already elapsed. Its stated premise: "nothing
left to wait on except the artifact's own scan result." Under
`provenance_mode: Required` with the provenance gate still `Pending` that
premise is false — release additionally needs sign + verify + cascade, which
cannot land inside the bound, and the inline fast-path release is suppressed
for exactly this case (`quarantine_use_case.rs` "fast-path release suppressed:
provenance gate not cleared"). Every such GET burns the full 10s and then
503s anyway.

Measured (2026-08-08 run, repo `oci-provenance-proxy-e2e`): the step-3 forcing
GETs — authenticated, serial, no client-side sleep — produced artifact rows
10.27/10.29/10.37/10.26/10.25/10.29s apart: a constant 10s server-side stall
+ ~0.3s real work per cold blob. Across a multi-arch `--all` tree this tax
alone exceeds any sane E2E budget, and for anonymous callers it delays an
honest `503 + Retry-After` by 10s per request.

A second, smaller waste: the ADR 0039 §10 write-authorized existence-probe
(HEAD) exemption is evaluated AFTER the await — a caller whose HEAD will be
served regardless still burns the await first.

## Change

1. **hort-app:** expose the fast-path suppression predicate as a
   `QuarantineUseCase` method (e.g. `release_blocked_on_provenance(&Artifact)
   -> DomainResult<bool>`), implemented by the SAME provenance-clearance +
   mode resolution the inline fast-path release uses — one authority, no
   drift. `true` iff the effective policy gates release on provenance
   (`Required`) AND the artifact's clearance is `Pending`. 100% coverage per
   the hort-app tier (every arm: Required+Pending, Required+Cleared,
   non-Required modes, resolution error).
2. **hort-http-oci `blobs.rs`:** in `maybe_bounded_await_release`, after the
   existing window-elapsed check, consult the new method; on `true` return
   immediately (debug breadcrumb mirroring the existing elapsed-bound line).
   Fail-safe on `Err`: treat as NOT blocked (keep today's await) — the guard
   is an optimization, never a new hold.
3. **hort-http-oci `blobs.rs`:** evaluate the write-authorized existence-probe
   exemption BEFORE the await and skip the await when it will serve the HEAD
   anyway (reorder or pass the flag in) — a caller served regardless must not
   wait.

No config change; `oci_pullthrough_release_wait_secs` semantics otherwise
unchanged (still bounds the genuinely-scan-pending case the await was built
for — which post-#135 late joiners hit and benefit from).

## Acceptance

- hort-app unit tests for the predicate (all arms); hort-http-oci handler
  tests via `build_mock_ctx`: (a) Required+Pending quarantined window-elapsed
  blob GET returns 503 without sleeping the bound, (b) scan-pending
  (provenance-cleared) case still awaits and serves on release, (c)
  write-authorized HEAD on a quarantined blob is served without awaiting.
- Full gate: fmt, clippy, `cargo test --workspace` (one-shot captures).
- E2E effect (Tom's next run, rebuild required): step-3 forcing GETs drop
  from ~72s to ~2s; steps 9a/9b fit their 120s/90s budgets.
