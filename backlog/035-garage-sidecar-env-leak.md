# 035 — Stop the garage sidecar exposing server-runtime env into the toolchain container

- **Source:** GitLab issue #56. **Scope narrowed 2026-07-20** after a necessity review — the original ask (refactor the S3 config resolver to take an env map) is withdrawn as disproportionate.
- **Type:** chore (dev-loop config). `.agents/manifest.yaml` only.
- **Model hint:** **small** — a three-line deletion plus a comment. No Rust.
- **Reviewable unit:** one directive.

## Problem

The garage sidecar's `expose:` block in `.agents/manifest.yaml` publishes seven variables into the **toolchain** container:

```yaml
expose:
  AWS_ACCESS_KEY_ID: "{{values.access_key}}"
  AWS_SECRET_ACCESS_KEY: "{{values.secret_key}}"
  AWS_ENDPOINT_URL: "http://{{host}}:3900"
  AWS_REGION: "garage"
  HORT_STORAGE_S3_BUCKET: "{{values.bucket}}"          # <- remove
  HORT_STORAGE_S3_ALLOW_HTTP: "true"                   # <- remove
  HORT_STORAGE_S3_FORCE_PATH_STYLE: "true"             # <- remove
```

`hort-server`'s `config::tests::s3_*` read ambient process env, so the three `HORT_STORAGE_S3_*` vars make `cargo test --workspace` fail with ~10 failures inside the sandbox:

```
called `Result::unwrap()` on an `Err` value: InvalidValue {
  var: "HORT_STORAGE_S3_ALLOW_HTTP",
  reason: "HORT_STORAGE_S3_ALLOW_HTTP=true but no endpoint set ..." }
```

CI is unaffected (no such env there), but this breaks the mandatory local pre-push gate — and a gate that fails for environmental reasons trains us to wave failures through. It cost three full-suite reruns to isolate during the v0.9.11 cut.

## CORRECTION (2026-07-20, during implementation)

**The "remove the trio, keep the `AWS_*` four" split below was wrong on the facts, and removing only the trio does not pass acceptance.** Recorded here rather than silently rewritten, because the reasoning error is the instructive part.

Removing the trio while keeping `AWS_ENDPOINT_URL=http://sbx-hort-garage:3900` left the container **inconsistent rather than merely polluted** — an `http://` endpoint with no allow-http opt-in — and the gate still failed, just differently (2 failures instead of ~10):

```
config::tests::s3_backend_missing_bucket
config::tests::stateful_upload_staging_dir_s3_fallback
  InvalidValue { var: "HORT_STORAGE_S3_ALLOW_HTTP",
    reason: "endpoint is http:// but HORT_STORAGE_S3_ALLOW_HTTP not set ..." }
```

The justification for keeping the `AWS_*` four — "genuine S3 client credentials an integration test consumes" — **is false**. Nothing consumes them:

- `crates/hort-adapters-storage/tests/s3_multipart.rs` is opt-in via `HORT_TEST_S3=1` and reads its **own** `HORT_TEST_S3_{ENDPOINT,ACCESS_KEY,SECRET_KEY,BUCKET,REGION}` namespace — chosen precisely to avoid colliding with the server's variables.
- `.agents/garage-smoke.bats` passes `AWS_*` **explicitly with `-e`** to its aws-cli container.
- `hort-server` / `hort-worker` read `AWS_*` as **runtime server settings** — the same class as the trio.

**Actual fix: remove the entire `expose:` block.** Simpler than the original ask *and* simpler than the narrowed one. Verified: `cargo test --workspace` under `sbx exec` with **no manual `unset`** → **10263 passed / 0 failed / 50 ignored**, exit 0. The sidecar remains reachable at `sbx-hort-garage:3900`; anything that wants it brings its own config.

Acceptance criteria 1 and 4 below are superseded accordingly (the `AWS_*` four are removed too; `garage-smoke.bats` is unaffected because it never used the exposed values).

## Why remove the trio rather than fix the tests

**The trio does not enable anything on its own.** `HORT_STORAGE_BACKEND` is *not* in the `expose:` block, so the S3 backend is not selected by these vars — anyone actually running hort-server against the sidecar Garage must set `HORT_STORAGE_BACKEND=s3` themselves, at which point they can set the other three in the same breath. So the exposure buys no working configuration; it only leaks server-runtime settings into a container whose job is compiling and testing.

The `AWS_*` four **stay** — those are genuine S3 *client* credentials, which is exactly what an integration test pointing at the sidecar Garage would consume (e.g. the `s3_multipart.rs` external-Garage mode from #53).

## Residual, accepted

`hort-server`'s `config::tests::s3_*` still read ambient process env. That is a latent test-isolation wart, but it is only reachable by deliberately exporting those vars and has never affected CI. Refactoring the resolver to take an injected env map is the tidy fix and is **not** worth it for this. **Revisit trigger:** the same collision class recurs with a different variable — i.e. the pattern, not this instance, becomes the problem.

## Acceptance

1. The three `HORT_STORAGE_S3_*` entries are removed from the garage sidecar's `expose:` block in `.agents/manifest.yaml`. The four `AWS_*` entries remain.
2. A short comment above `expose:` records why: these are server-runtime settings, the toolchain container only compiles and tests, and `HORT_STORAGE_BACKEND` is not exposed so the trio configured nothing anyway.
3. After `sbx sidecar down && sbx sidecar up`, `sbx -C ~/repo exec -- bash -c 'cd /work && cargo test --workspace'` passes **without** any manual `unset` — expected **10263 passed / 0 failed / 50 ignored** (the post-!168 baseline).
4. `.agents/garage-smoke.bats` still passes (it uses the `AWS_*` vars, which are unchanged).

## Starter prompt

/hort-architect

Implement backlog item 035 (issue #56) on branch `agent/56-garage-sidecar-env-leak`.

Remove the three `HORT_STORAGE_S3_*` entries from the garage sidecar's `expose:` block in `.agents/manifest.yaml`, keeping the four `AWS_*` entries, and add a brief comment recording the rationale. Then bounce the sidecars and verify `cargo test --workspace` passes in the sandbox with no manual `unset`.

Do **not** touch any Rust. The `hort-server` config tests reading ambient env is a known, accepted residual — see the backlog item.
