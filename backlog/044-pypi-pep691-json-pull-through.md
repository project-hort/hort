# 044 — PyPI pull-through: PEP 691 JSON upstream fetch + ReleasedOnly bootstrap

**Issue:** #72
**Read first:** `crates/hort-http-pypi/src/index_source.rs`, `crates/hort-http-pypi/src/upstream_pull.rs`
(the upstream simple-index fetch — currently requests HTML), `crates/hort-http-pypi/src/html_projection.rs`
(the buffered 2 MiB-capped HTML projector, `:90`), `crates/hort-formats/src/pypi/projection.rs`
(the **streaming** PEP 691 JSON projector — already exists), `crates/hort-http-pypi/src/simple_index.rs`
(`fire_prefetch_trigger_pypi:679` → `fire_hot_path_trigger`), `crates/hort-http-pypi/src/serve.rs`.
Verify against **PEP 691** (JSON simple API) and PEP 503 (HTML). `/hort-architect`; the protocol
spec is authoritative.

## Problem (log-confirmed on prod — see #72)

Two failure modes make the pypi pull-through non-functional:
- **Mode 1 (primary):** hort fetches the upstream simple index as **HTML** and buffers it; the HTML
  projector hard-rejects any body over `per_value_object_max_bytes` (2 MiB) — `html_projection.rs:90`.
  `pypi.org/simple/rapidfuzz/` HTML is **5.3 MiB** → rejected as malformed → 0 versions → pip
  `No matching distribution`. **Any package whose HTML index exceeds 2 MiB is unresolvable.**
- **Mode 2 (secondary):** under-cap packages parse but `index_mode: released_only` filters all
  versions (nothing released), and the on-index-serve hot-path plans only `OnDistTagMove` (which
  `pypi-public` doesn't subscribe) → no prefetch job enqueued → nothing ever warms. pip is
  index-driven, so an empty index is fatal (npm avoids this — `npm ci` is URL/tarball-driven).

## Fix — Mode 1 (primary): fetch PEP 691 JSON via the streaming projector

Switch the **upstream** simple-index fetch from HTML to PEP 691 JSON and route it through the
existing streaming projector — reuses shipped infra, no new parser:
- Request `Accept: application/vnd.pypi.simple.v1+json` (PEP 691) on the upstream simple-index
  fetch (currently HTML). Route the response through `hort-formats`'s streaming
  `PypiSimpleIndexProjector` (`serde_json::Deserializer::from_reader` + counting cap) instead of
  the buffered `html_projection`. **Wins:** JSON is far smaller than HTML; the streaming projector
  never buffers the whole body, so the whole-body hard-reject can't fire; and if a truly enormous
  index still trips the cap it **truncates with the existing `cap_trip_flag` signal** instead of
  serving zero.
- **Field completeness (maintainer constraint):** confirm the PEP 691 `files[]` provides everything
  the current HTML parse extracts — the projector's `PypiSimpleFile` already reads `filename`,
  `url`, `hashes.sha256` (ADR 0006 upstream-checksum, load-bearing), `requires-python`,
  `dist-info-metadata.sha256` (PEP 658). PEP 691 carries all of these; verify no HTML-only field is
  lost (e.g. `data-yanked`).
- **Upstream that doesn't speak PEP 691:** pypi.org does. For robustness, if an upstream returns
  HTML despite the JSON `Accept` (content-negotiation fallback), keep the HTML projector as a
  fallback path — but the JSON request is primary. Don't regress non-pypi.org pypi upstreams.
- The **`per_value_object_max_bytes` (2 MiB) cap is mis-applied** to a package-file *list* that grows
  with release count. A larger index-specific cap (or relying on the streaming truncate-with-signal)
  is a reasonable secondary tuning — but the JSON+streaming switch is the load-bearing fix; don't
  just bump the HTML cap.

## Fix — Mode 2 (secondary): ReleasedOnly bootstrap for index-driven clients

For a `ReleasedOnly` pypi proxy that serves 0 versions on an index request, kick off a warm so the
package becomes resolvable:
- Enqueue a prefetch (transitive-deps, the trigger `pypi-public` actually subscribes) for the
  requested package on index-serve — extend `fire_prefetch_trigger_pypi` / the hot-path so it isn't
  gated solely on `OnDistTagMove`. So a first pip request warms the package in the background.
- **Quarantine-duration friction (config, not code):** even warmed, a 1h proxy-quarantine means the
  first CI build waits an hour. Recommend a **short proxy-quarantine** for `pypi-public` (operator
  gitops tuning) or a documented pre-warm — same tension as #65. Note this in the report; the
  duration itself is Tom's operator config, not this change.
- Consider (optional, if clean) a retryable download signal for not-yet-released versions mirroring
  npm's `503 "quarantined"` — but pip being index-driven, the prefetch-on-serve is the primary lever.

## Acceptance

- A large package (HTML index > 2 MiB, e.g. rapidfuzz) resolves via the pypi proxy (JSON fetch, no
  hard-reject). Test with a fixture whose JSON `files[]` is large.
- No upstream-checksum / requires-python / PEP 658 metadata regression — the JSON path extracts the
  same fields the HTML path did (assert parity).
- A `ReleasedOnly` pypi proxy enqueues a prefetch on a cold index-serve (Mode 2).
- Full gate green (`cargo test --workspace`, fmt, clippy, audit, deny).

### Starter prompt

```
/hort-architect

Implement backlog item 044 (issue #72) on branch agent/72-pypi-pep691-json. IMPORTANT: verify
`git branch --show-current` is agent/72-pypi-pep691-json before EVERY commit — never commit to
develop. Verify against PEP 691. Mode 1 (primary): switch the UPSTREAM pypi simple-index fetch from
HTML to PEP 691 JSON (Accept: application/vnd.pypi.simple.v1+json), routing through the existing
streaming PypiSimpleIndexProjector instead of the buffered 2MiB-capped html_projection; assert the
JSON path extracts the same fields (filename/url/hashes.sha256/requires-python/dist-info-metadata,
+ data-yanked); keep HTML as a fallback for non-691 upstreams; test a >2MiB-HTML package resolving.
Mode 2 (secondary): make a ReleasedOnly pypi proxy enqueue a prefetch on a cold index-serve (not
only OnDistTagMove); note the 1h proxy-quarantine friction as an operator-config recommendation.
Run the full gate and report per the handover protocol.
```
