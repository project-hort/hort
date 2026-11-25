# 477 — the standing decision, the operator contract, and what the product says

**Issue:** #457 · **Branch:** `agent/457-transport-evidence` · Unit 6 of 7.
**Design:** `docs/plans/457-transport-evidence.md` §1, §3, §4.2, §6.
**Depends on 471–474, 476 and 478** — the ADR records what landed, not what
was planned, and this unit **deletes the design document that unit 478 reads**,
so it must be the last unit of the issue.
**Read first:** `docs/adr/0000-historical-decisions-index.md`, ADR 0010,
ADR 0017, ADR 0018, ADR 0021, `docs/architecture/how-to/deploy/`,
`docs/auth-catalog.md`.

## Why this unit exists

No standing decision governs inbound transport evidence: ADR 0010 is outbound
(TLS builder, no insecure knobs) and ADR 0021 borders the question without
deciding it. The answer is a new standing decision, and the per-unit catalog
edits (ADR 0018) land with their own units — this unit writes the decision and
the operator contract, not the claims.

## What to write

1. **The ADR.** Transport security is a property the binary has positive
   evidence of or does not know. Evidence comes **only** from a trusted peer's
   overwritten forwarded scheme; an address is never evidence; ambiguity
   denies. A scope-qualified operator **waiver**
   (`HORT_TLS_NOT_REQUIRED_FROM`) changes what is accepted and never what is
   claimed to have been seen, and it reaches only a request that is **not**
   relayed (design §4.3.2). A presented **or issued** credential with neither
   evidence nor an applicable waiver is refused. Record:
   - the four recognised precedent shapes (terminate-yourself;
     declared-header-with-default-distrust; scope-qualified requirement;
     out-of-band measured state) and the finding that **no precedent defaults
     to assuming `https`**;
   - what was rejected and why: making the address honest, a single global
     declaration switch, withdrawing the claim;
   - the wildcard boot refusal's **honest scope** — a tripwire for the
     documented copy-paste, not a boundary, because an equivalent CIDR union
     cannot be refused and the operator is the trust authority;
   - the future evidence sources (in-process TLS, PROXY protocol v2) as
     designed-for, not built;
   - the §3 answer, and in plain words: **RFC 6749 §3.2 conformance is not
     claimed for a request inside a waived scope.** This sentence is the ADR's
     load-bearing admission — the alternative was option (b), declined because
     hort measures TLS in neither option and (b) only moves the assertion from
     a configuration file to a proxy header;
   - that the eleven admin-task CronJobs are the worked example of a waived
     in-cluster hop (unit 478).
   No drafting history.
2. **Operator documentation** under `docs/architecture/how-to/deploy/`:
   - the edge must **overwrite**, never pass through, both `Forwarded` and
     `X-Forwarded-Proto`, and direct access to the listener must be restricted
     — a shared pod subnet declared as trusted means any pod that reaches the
     socket can supply its own scheme;
   - what the **waiver** is for: a hop that is plaintext by design, never a
     way to silence the refusal for external callers — and what a declared
     range admits, because every caller that can reach the socket from inside
     it inherits the waiver, which makes network policy the remaining control;
   - **which stream carries a transport refusal, because it is not one
     stream.** `hort_credential_transport_refusals_total{entry_point}` covers
     all six route classes; `hort_auth_attempts_total` and the audit event are
     emitted from `hort-http-core`'s auth middleware only, so the OCI plane's
     refusals never appear there — that subtree has never emitted either, and
     unifying its audit posture is a larger question than this refusal. So the
     operator instruction is to alert on the **transport counter**, which is
     complete, and the page says why the auth stream is not;
   - that `HORT_BEARER_ALLOW_OVER_HTTP` is the **unscoped** blunt instrument,
     that it does not reach the token endpoint, and that the scoped waiver is
     the thing to reach for instead;
   - **how to measure exposure first** with
     `hort_credential_transport_total{entry_point,evidence}` before tightening
     anything;
   - one sentence distinguishing `HORT_REQUIRE_HTTPS` from per-request
     evidence, **describing it accurately**: a boot-time
     configuration-consistency gate, satisfied by either an `https://` base URL
     **or** a non-empty trusted-proxy list (`config.rs:2543-2571`). It says the
     deployment is *configured* as if TLS were in front and is **never**
     evidence about a request — do not describe it as evidence anywhere;
   - the loopback metrics-scrape case: the chart binds the metrics listener to
     `127.0.0.1:9090` for a sidecar, whose peer is loopback, so that path needs
     its own waiver or TLS — and a loopback waiver admits **any process sharing
     the pod's network namespace**. Add `426` to the scrape troubleshooting
     table in `docs/architecture/how-to/operate/metrics-scraper-service-account.md`.
3. **The `426` refusal body literal.** It still reads
   `{"error":"pat over http refused"}` — correct for the token shape the old
   gate keyed on, wrong English for the IdP access token the broadened subject
   now refuses. The literal is a keyword operators grep and alert on, so
   changing it is a decision rather than a fix: pick the wording, change it in
   the one place that defines it (`credential_transport.rs`'s
   `REFUSAL_REASON`), and record in the ADR that it changed. Unit 472 already
   changed the `warn!` text, which is itself a break for anyone alerting on the
   old "bearer-over-HTTP refused" string — note that too.
4. **`docs/compliance/ISO27001.md:91`** says the `426` applies "on the non-OCI
   read and write paths". That was true of unit 472 alone and is now
   incomplete three units over — a reader concludes the OCI plane and the
   token endpoint are uncovered, which is the failure ADR 0018 exists to
   prevent, one document across. The one-clause fix is "on every credential
   surface".
5. **The `hort_cli_*` claim the CLI makes to a human.** A CliSession token is a
   **signed JWT**, not an opaque `hort_cli_`-prefixed string — asserted by
   `crates/hort-app/src/use_cases/api_token_use_case.rs:6871-6899`, which
   requires `!plaintext.starts_with("hort_cli_")` and three base64url segments.
   No mint produces that prefix. Yet the CLI tells a human to paste one:

   - **User-facing, in scope** — `crates/hort-cli/src/auth/login.rs:796` (the
     `rpassword` prompt: *"Paste your hort_cli_* or hort_pat_* token: "*),
     `login.rs:686` and `:692` (two hints), and
     `crates/hort-cli/README.md:37`. The prompt names a prefix that cannot
     occur for the kind it is asking for. Replace with what the flow actually
     accepts — an opaque `hort_pat_*` / `hort_svc_*` token **or** a CLI-session
     JWT — and keep the wording short enough for a terminal prompt.
   - **Doc comments, in scope** — `crates/hort-cli/src/config.rs:87`,
     `auth/loopback.rs:223`, `auth/oidc.rs:9`, `:521`, `:536`.
   - **Deliberately NOT in scope, do not sweep** — `hort_cli_` as a *parsed*
     prefix is real and correctly documented where the validator describes the
     shapes it rejects (`hort-app/src/use_cases/pat_validation_use_case.rs:24`
     and its tests, `authenticate_use_case.rs:655,683`). Those say "this shape
     is recognised and refused", which is true. Test fixtures that merely use
     the string as an arbitrary value are not claims either.

   The maintainer asked for the user-facing strings to ride with this issue
   (2026-11-25), which is why a documentation unit now carries a code change.
6. **`CHANGELOG.md`** — unit 472 already added an entry under `### Security`.
   Verify it covers the whole issue in one or two operator-facing lines and
   **do not add a second**: one entry per issue, not one per unit.
7. **Delete `docs/plans/457-transport-evidence.md`** — its decisions now live
   in the ADR, the catalog entries and the backlog items.

## Acceptance

- The ADR text goes to the maintainer as an amendment **before** it lands,
  with any touched catalog text quoted — ADR changes land only after an
  answered decision.
- After this unit, no catalog entry claims a protection without naming its
  enforcement, the seven inbound "in transit — TLS" claims (Entries 1–4, 6–8)
  each point at a landed mechanism, and each says plaintext can be accepted
  under a named operator waiver where that is true — a Protection line that
  still reads as "TLS was observed" for a waivable surface is a blocking
  finding, not a wording preference.
- The ADR contains no sentence calling the operator declaration an evidence
  source, and none calling `HORT_REQUIRE_HTTPS` evidence.
- `docs/plans/` is empty on this branch.
- No string the CLI shows a human names `hort_cli_*` as something to paste,
  and `git grep -n 'hort_cli_' crates/hort-cli` returns only the parsed-shape
  documentation and test fixtures named above.
- Gate: `cargo test --workspace`, clippy, fmt last, plus
  `bash scripts/run-shell-guards.sh` where it applies. The CLI wording is a
  code change; the rest of this unit is documentation.
