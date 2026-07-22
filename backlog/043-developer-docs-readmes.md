# 043 — Developer docs sweep + per-crate README.md (v1.0 prep 2/3)

**Issue:** #69
**Read first:** `crates/hort-server/README.md` (the one existing crate README — binary-style
template basis), `CLAUDE.md` (layer/coverage/anti-pattern rules), the `/hort-architect` skill
(layer taxonomy, ports, event vocabulary, ADR 0008 dep rules), `docs/adr/0000-…-index.md`,
`docs/architecture/explanation/**`, `docs/architecture/how-to/add-a-format-handler.md`,
`CONTRIBUTING.md`, `TESTING.md`, `RELEASING.md`.

## Goal (two parts)

Developer-facing docs consistency **and** a `README.md` in every workspace crate — the biggest of
the three v1.0 doc phases. Do the developer-doc sweep first (small), then the 36 crate READMEs
(the bulk), batched by layer.

## Part A — developer documentation sweep

Review + fix drift against the as-built (crate layering, ports, event vocabulary, ADRs):
- `docs/architecture/explanation/**` (architecture explanation set)
- `docs/architecture/how-to/add-a-format-handler.md` (the WASM/format extension guide)
- `docs/adr/0000-historical-decisions-index.md` (index consistency — every ADR present + status)
- `CONTRIBUTING.md`, `TESTING.md`, `RELEASING.md` (dev workflow docs)
- Cross-links resolve; no stale crate names / removed types / dead references.
- **Coordinate with #67 (just landed): `apiVersion` in dev-doc snippets is `project-hort.de/v1`.**

## Part B — per-crate `README.md` (37 crates; only `hort-server` has one → ~36 new)

**One consistent template.** A crate README that misstates its layer is worse than none — pin each
against the actual `Cargo.toml` deps + the layer rules.

**Library-crate template** (domain / app / config / adapters / http / formats / leaf):
```markdown
# <crate> — <one-line role>

## Layer
<Domain | Application | Config | Outbound adapter | Inbound HTTP | Formats/WASM | Leaf>
— <the rule this layer obeys>

## Responsibility
<what it does, in domain terms>

## Ports
- Implements: <outbound port trait(s), or "—">
- Consumes: <ports/use-cases it depends on, or "—">

## Key types
<main public types / trait impls / entrypoints>

## Rules
<governing constraints — cite the ADR/CLAUDE.md rule that structurally binds it>
```

**Binary-crate** (`hort-worker`, `hort-cli`): follow the existing `hort-server/README.md` shape
(what it IS / is NOT, run/quickstart, key env or flags). Keep `hort-server`'s README; refresh only
if drifted.

**Per-crate layer assignment** (verify each against its `Cargo.toml`):
- **Domain (zero-I/O, security boundary, 100% cov):** `hort-domain`
- **Application (orchestrates domain+ports, 100% cov):** `hort-app`
- **Config (gitops parse/validate):** `hort-config`
- **Outbound adapters (implement port traits; SQL/HTTP/TLS here):** `hort-adapters-postgres`,
  `hort-adapters-storage`, `hort-adapters-oidc`, `hort-adapters-scanner-osv`,
  `hort-adapters-scanner-trivy`, `hort-adapters-secrets`, `hort-adapters-upstream-http`,
  `hort-adapters-kubernetes`, `hort-adapters-checkpoint-anchor`, `hort-adapters-ephemeral-memory`,
  `hort-adapters-ephemeral-redis`, `hort-adapters-advisory-osv`,
  `hort-adapters-provenance-sigstore`, `hort-adapters-provenance-cosign-key`, `hort-net-egress`,
  `hort-notifier-nats`, `hort-notifier-webhook`
- **Inbound HTTP (ADR 0008: NO `hort-adapters-*`/`sqlx`/`reqwest`; call use cases, not `ctx.*`):**
  `hort-http-core`, `hort-http-cargo`, `hort-http-npm`, `hort-http-pypi`, `hort-http-oci`,
  `hort-http-maven`, `hort-http-admin-security`, `hort-http-admin-tasks`, `hort-http-subscriptions`,
  `hort-http-discovery`, `hort-http-events`
- **Formats/WASM host + upstream dispatch:** `hort-formats`, `hort-formats-upstream`
- **Binaries:** `hort-server` (has README), `hort-worker`, `hort-cli`
- **Leaf (std-only, zero `hort-*` deps):** `hort-attribution`

State each crate's real, layer-appropriate rule (e.g. domain zero-I/O; http-crate ADR 0008 no-
adapter dep; `hort-cli` dep-isolation; `hort-formats-upstream` is the one non-server crate importing
multiple `hort-http-<format>` crates). Don't invent a port a crate doesn't have — read its lib.rs.

## Acceptance

- Every workspace crate has a `README.md` following one template, correctly stating layer + role +
  ports + key types + governing rule (verified against `Cargo.toml` + lib.rs, not guessed).
- Developer docs (explanation, add-a-format-handler, ADR index, CONTRIBUTING/TESTING/RELEASING)
  internally consistent + match the as-built; `apiVersion` snippets on `v1`.
- Scoped to developer docs + crate READMEs — root README is #70, operator docs were #68.
- Full gate green (docs/README-only, but run it).

Batch the READMEs by layer group in sub-commits; one MR. This is large — pace it across the layer
groups.

### Starter prompt

```
/hort-architect

Implement backlog item 043 (issue #69) on branch agent/69-developer-docs-readmes. IMPORTANT: verify
`git branch --show-current` is agent/69-developer-docs-readmes before EVERY commit — never commit to
develop. Part A: sweep the developer docs (explanation, add-a-format-handler, ADR index,
CONTRIBUTING/TESTING/RELEASING) for drift vs the as-built; apiVersion snippets → project-hort.de/v1.
Part B: add a README.md to every workspace crate lacking one (~36), following the two templates in
the backlog item, with each crate's layer/ports/rules VERIFIED against its Cargo.toml + lib.rs (a
README that misstates a crate's layer is a defect). Batch by layer group in sub-commits. Run the
full gate and report per the handover protocol.
```
