# 337 — The CLI can name the exclusion it means

**Issue:** #349 · **Branch:** `agent/349-the-predicate-of-the-purpose`
**Governing decisions:** ADR 0011 (authority hierarchy and API versioning) ·
ADR 0025 (the 409 item 335 installed) · ADR 0008.

**Depends on item 335** (already on this branch, `1c78acf0`). It completes
it: without this, 335's own promise — *both rows are reachable, neither is
stranded* — does not hold for anyone using `hort-cli`.

## 1. The surface item 335 left behind

`crates/hort-cli/src/curation/unexclude_finding.rs` exposes
`--policy`, `--cve` and `--justification` (`:57-71`) and sends a body of
exactly one field (`:47-49`):

```rust
/// **Sync-required**: mirrors `RemoveExclusionRequestDto` in
/// `hort-http-core::handlers::admin::policies::exclusions`.
struct RemoveExclusionRequestBody<'a> {
    reason: &'a str,
}
```

That `Sync-required` marker is the repository saying these two move
together, and item 335 moved one of them: `RemoveExclusionRequestDto` now
also carries an optional `exclusion_id`.

The consequence is not cosmetic. On a policy holding two exclusions for one
CVE, the CLI now receives the 409 and **has no flag with which to answer
it**. Before item 335 the command removed an arbitrary one of the two; after
it, the command cannot remove either. The operator does see the candidates —
`AkClient::response_to_error` (`crates/hort-cli/src/client.rs:270-277`)
echoes the raw body as `HTTP 409 Conflict: {…}` — so they are handed the
`exclusion_id`s and no way to use them.

The ambiguous state is reachable without the CLI: the HTTP POST accepts
`package_pattern`, and the gitops envelope carries it with a
`(cve_id, package_pattern)` uniqueness rule
(`crates/hort-config/src/exclusion.rs:4-6,38`). It is only the CLI's own
*add* side that cannot produce it — which is precisely why a curator can
meet two rows they never created and cannot withdraw.

## 2. The change

- **`--exclusion-id <UUID>`**, optional, on `UnexcludeFindingArgs`. Present
  → it travels as the body's `exclusion_id`; absent → the body is what it is
  today, so every existing invocation behaves exactly as before.
- **`RemoveExclusionRequestBody` gains the field** and keeps its
  `Sync-required` marker pointed at the DTO it now actually mirrors. The
  field is `Option<Uuid>` and is **omitted** from the serialised body when
  absent (`skip_serializing_none` or `#[serde(skip_serializing_if)]`), so an
  older server that does not know the field sees the body it saw before.
- **Client-side validation stays client-side where it already is**: the
  `--cve`-not-empty and `validate_justification` checks (`:92-95`) keep their
  placement. A malformed `--exclusion-id` is a clap parse error, which is the
  cheapest possible answer and needs no new code.
- **The 409 is rendered, not dumped.** A caller who hits the ambiguity must
  be told what to do in one line, not handed a JSON blob to read. The
  command recognises the 409 shape item 335 defined — `cve_id` plus
  `candidates[].{exclusion_id, package_pattern}` — and prints one line per
  candidate plus the exact flag to add. An unrecognised 409 body falls back
  to today's raw echo rather than swallowing it.

  This is the one place the unit needs a decision rather than a translation:
  `response_to_error` is shared by every CLI call and must **not** learn
  about exclusions. The rendering belongs in `unexclude_finding.rs`, which
  means the command needs the response rather than an `anyhow::Error` that
  has already flattened it. Keep the blast radius at this command —
  a new narrow client method for this call, or an inspection of the error
  chain, is a judgement call for the implementer; widening
  `response_to_error`'s contract is not.

## 3. Three statements that stop being true

- **The module doc** (`unexclude_finding.rs:1-7`): *"the server-side handler
  resolves the CVE → exclusion_id via the projection"*. It does that only
  when the CVE names exactly one row; otherwise it reports the ambiguity and
  the caller resolves it.
- **The `--cve` help text** (`:62-65`): *"A miss surfaces as 404 (no
  exclusion with that CVE on this policy)"* — true, and now incomplete: a
  *multiple* hit surfaces as 409.
- **The `# Wire shape` section** (`:19-24`) enumerates the body as `reason`
  only.

## Acceptance

- A test that **kills the gap**: given the 409 body item 335 renders, the
  command's output names both candidates' `exclusion_id` and tells the
  operator the flag to repeat with. A raw-JSON dump does not pass it.
- A test that `--exclusion-id` reaches the wire as the body's `exclusion_id`,
  and a test that its absence produces **byte-identical** body to today's.
- A test that an unrecognised 409 body still surfaces, rather than being
  swallowed by the new rendering.
- The three prose statements say what the command does.
- No new capability on the *add* side — `exclude-finding` is untouched. This
  unit restores an operation the server change would otherwise block; it does
  not widen what the CLI can express.
- No file under `migrations/` is changed.
- Full gate green (`CHECK/FMT/CLIPPY/TEST/AUDIT/DENY/ATTR`). No issue/MR
  references in code comments.

## Out of scope

- `exclude-finding` and any `--package-pattern` on the add side.
- `AkClient::response_to_error`'s contract for every other call.
- The other findings on this issue (items 334, 335, 336).
