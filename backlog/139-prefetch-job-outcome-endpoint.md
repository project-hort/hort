# 139 — Read-only prefetch job outcome endpoint

Issue: #158, Item B (confirmed spec in the issue description). Milestone
0.12.0 — dispatch after the 0.11.0 promotion. Depends on nothing in item 138.

**Read first:** the prefetch POST handler (`crates/hort-http-*` — the format
crate that owns `POST /api/v1/repositories/<key>/prefetch`), its authz gate
(`Read ∧ Prefetch`, CliSession/ServiceAccount token kinds — the
#150-documented contract), `crates/hort-domain/src/ports/` `JobsRepository`,
and ADR 0008 (format crates reach data through use cases only).

## Shape (from the spec, binding)

`GET /api/v1/repositories/<key>/prefetch/jobs/<job_id>` →
`{status, attempts, last_error, result_summary, kind, created_at,
completed_at?}` for jobs of kind `prefetch`/`prefetch-dependencies`
belonging to `<key>`'s repository. **404 for any other repo's job** — id
probing must not enumerate cross-repo (the wrong-repo 404 is
indistinguishable from not-found, the anti-enumeration shape the codebase
uses elsewhere).

- Authz identical to the prefetch POST that minted the id — same token
  kinds, same `Read ∧ Prefetch` on the resolved repo.
- Use case in `hort-app` over `JobsRepository`; a read-by-id port method may
  need adding (port extension; no adapter schema change — the columns all
  exist).
- Non-goals (binding): no list endpoint, no filtering, no retry trigger.

## Governing decisions

ADR 0008 (use-case-only access), ADR 0025 (error-shape conventions), the
anti-enumeration posture (ADR 0035's bounded-give-up documents the
existence-leak trade-off — this endpoint leaks nothing: 404 uniformly).

## Acceptance

- Envelope id → GET returns terminal `failed` + `last_error` after worker
  give-up (handler test, mock ctx via `hort-http-core::test_support`).
- Wrong-repo id → 404 shaped identically to unknown id.
- PAT (wrong token kind) → rejected exactly as the POST rejects it.
- Kind gate: a non-prefetch job id in the right repo → 404.
- DB-touching tests (if the port read gets an integration test) carry
  `#[serial(hort_pg_db)]`.
- CHANGELOG (Added). `hort-http-*` ≥ 85 %, `hort-app` 100 % on touched code.
