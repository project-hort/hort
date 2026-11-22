# 458 — the 22 findings re-anchored against develop

**Issue:** #458 · **Branch:** `agent/458-reanchor-audit-findings`
Measured against `develop 6a38bdec`, 2026-11-22. Audit baselines: `e30eb7da`, `b17801d8` (both 2026-10-29).

## A fifth verdict was needed

The issue's acceptance named four: *besteht* / *erledigt* / *teilweise* /
*trägt eine Entscheidung*. The pass needed a fifth, and the gap matters:

**5. die Behauptung trifft nicht zu** — the claim is false against today's code
*and* was false at the audit baseline. That is not *erledigt* (nothing did it)
and not *trägt eine Entscheidung* (there is no intent to argue with). One
finding lands here, and it only became visible because the file's history was
checked rather than only its content.

## The result, after the peer review corrected six verdicts

**Sixteen of 22 are work. Four carry a decision an ADR already made. One is
done. One claim does not hold.** And the findings do **not** group into
criteria families — all four pairings this pass proposed were split by the
review, each because one application of the criterion does not settle both
members. See §"The cut that did not survive".

The first version of this document said "nine carry a declared decision",
which its own per-finding table did not support: the table labelled six
`Entscheidung`, two `teilweise` and one `trifft nicht zu`. The count conflated
"not to be implemented" with "declared decision" and is corrected below.

## Per finding

| Befund | Urteil | Heutige Fundstelle | Mechanismus |
|---|---|---|---|
| S1-2 | **trifft nicht zu** | `hort-http-core/src/handlers/health.rs:53` | `readyz` is one `health_check()`, and the Postgres impl (`event_store.rs:638-650`) is exactly `SELECT 1`. `git log e30eb7da..develop -- handlers/health.rs` is **empty**, so it was never unbounded. The residue — unauthenticated, one pool acquisition per request — is declared in the module header ("kubelet probes do not carry credentials"). |
| S2-1 | **Entscheidung** | `authenticate_use_case.rs:1009`, `:1160` | The code says it: "CliSession authority = claims + live grants; no cap leg", `token_cap = None`. ADR 0013's amendment already answers it — the 900 s lifetime is deliberately the only bound. A scope-narrowed session is a new control. |
| S2-3 | **besteht** | `pat_validation_use_case.rs:672` | `self.cache.insert(...)` is not fenced against an invalidation that landed after the row was read, so a revocation concurrent with an in-flight validation is overwritten by the validation's own write and the token stays accepted for the cache TTL. |
| S3-3 | **besteht** | `hort-adapters-oidc/src/multi_issuer.rs:111` | The JWKS cache is `HashMap<issuer_name, JwksCacheEntry>`. The key is the issuer's *name*, not the URL the keys came from, so changing the URL leaves the old signing keys trusted until a refresh. |
| S4-1 | **erledigt** (`5621a559`) | `hort-domain/src/policy/exclusion.rs:52`, `:101-103` | Closed structurally, the way the anti-pattern checklist prescribes: *"a repository-scoped exclusion is refused by every writer"*, plus the apply-time `validate_exclusion_scope_not_implemented`. Tick it off in #383. |
| S5-1 | **besteht** | `discovery_use_case.rs:244`, `:281` | Gate 1 is a plain `self.repositories.find_by_key(repo_key)` — **not** visibility-filtered — so an existing-but-unreadable repository reaches Gate 2 and is refused with a message naming it, while a nonexistent one answers `NotFound`. Two distinguishable answers. **Worse than a plain gap:** the comment beside it asserts the anti-enumeration property ("a missing repo collapses to NotFound for callers who hold neither Read nor admin … the two helpers are equivalent"), which the call does not provide. |
| F7-2 | **teilweise** | `hort-http-npm/src/upstream_pull.rs:505-528`, `packument.rs:283-310` | The eviction exists and is *part of the refusal*, not cleanup after it — and it predates the audit baseline (`4e67e5cf` is an ancestor of `e30eb7da`), so the finding was never "no eviction". The residue is that both eviction arms are best-effort and name their own consequence in the log: "a reader inside the fresh window can still be served the evicted document". Declared. |
| F7b-2 | **besteht** (corrected) | `hort-formats/src/cargo/projection.rs:45-46`, `hort-http-cargo/src/index_source.rs:419-437`, `hort-formats/src/cargo/index.rs:199-205` | My first verdict said `cksum` had **no reader anywhere**. That was wrong, and the cause was a truncated grep (`\| head -12`) over two directories. It has readers: `hort-http-cargo/src/upstream_pull.rs:297-315` recovers "the upstream cksum from the projection's verbatim `cksum`" through `checksum_from_entry`, and `index_source.rs` copies `line.cksum` onto the **served index**. The artifact pull is still fail-closed (`UpstreamPublishedChecksum::new` validates shape), so the defect is not an unverified download — it is that a missing upstream field becomes `""` and the served index can then **advertise a version with an empty checksum**. ADR 0062: "Hort advertises nothing it will not serve." A comment would not have addressed that. |
| F7b-3 | **besteht / Risikoentscheidung** (corrected) | `object_store_backend.rs:184-192`, `:345`, `:1200-1205` | The comment's *equivalence* premise is false, which is what my first verdict rested on. `tokio::time::timeout(put_timeout, inner)` **drops** the inner future on elapse, so `upload.abort()` (reached only on the dedup branch, `:306`) never runs; and `list_all` deliberately does not descend into `.staging/` — its own test is named `list_all_ignores_staging_keys`, with the reason "must not pollute the scrub". So orphaned staging keys are **not** the same class of cleanup as orphaned CAS content: the scrub reaches the second and is built not to reach the first. An *incomplete* multipart leaves no object at all, only parts the bucket must expire through a separate lifecycle rule. Either abort on cancellable failure or make the bucket lifecycle an operator obligation and verify it — the comment cannot settle it. |
| S8-2 | **besteht** | `rejected_reevaluation.rs:169` | `policy.map(|p| p.provenance_mode).unwrap_or_default()` — a default stands in for a policy-derived measurement, so "no active policy" reads as a concrete mode rather than as "unknown". |
| S9b-3 | **Entscheidung** | `hort-config/src/desired.rs:1162-1215` | An apply-time linter now rejects a non-empty `licensePolicy` (`5621a559`, pre-baseline), and its message states the remaining shape: `licensePolicy: {}` is the only applyable value and "a different value does not change" anything. Keeping an inert empty surface instead of removing it is the checklist's other resolution, chosen deliberately. |
| F11-4 | **besteht** | `ingest_use_case.rs:1442` (`ingest_verified`) | `enforce_metadata_cap` is called in exactly two places — `ingest` (`:1125`) and `register_by_hash_inner` (`:4854`). `ingest_verified` passes `payload_metadata` straight through to `ingest_verified_sha256`, and PyPI's verified publication path is precisely `ingest_verified` (`hort-http-pypi/src/upstream_pull.rs:369`, `metadata_endpoint.rs:37`). |
| F12-1 | **Entscheidung** (corrected) | `docs/adr/0055-write-authorized-hold-read-generalised.md:52-68` | My first verdict called the distinguishable refusal an existence oracle and paired it with S5-1. **ADR 0055 decides the opposite, deliberately:** "Resolvability is gated by this qualifier; diagnosability is not. *Why* a version cannot be resolved is information, not access, and every byte route is free to say so to any caller holding `Read`." The ADR then names this exact history — OCI's manifest and blob routes "previously took the opposite, format-specific anti-enumeration choice — `MANIFEST_UNKNOWN` / `BLOB_UNKNOWN`, byte-identical to 'does not exist' — which is the posture the 2026-10-12 clarification retired." Implementing my first verdict would have re-introduced a posture an ADR retired two weeks before the audit ran. Not work. |
| F12-4 | **besteht, beide Hälften** (corrected) | `hort-http-oci/src/upload_session.rs:739`, `:1102`, `:1358`; `uploads.rs:599-605`, `:681-702`, `:1034-1036` | I read *stored* as *enforced*. The record's own doc says what the field is for: `principal_id_bytes` exists so "finalize / cleanup paths … release the per-`(repo, principal)` live-session set member without re-querying" — a cap-release key, not an authorization check. Measured: `append_chunk_core`, `finalize_core` and `cancel` each compare **`record.repository_id() != repo_id`** and nothing else; the PATCH handler builds `_actor` and discards it, and passes no principal at all. So another writer holding the UUID and `Write` on the same repository can append to, finalize under their own attribution, or delete someone else's session. The name half is absent too (`initiate` takes no name). The OCI spec makes the push location's match a `MUST`. **Security work, this wave.** |
| F12b-1 | **besteht** | `hort-http-oci/src/manifests_write.rs:3100-3125` (`pull_membership_claims`) | The hosted-write half is closed and says so: "An insert failure … is **no longer reachable here**: there is no insert left in this function" (`f75bfaae`, pre-baseline). What remains is the **derivation** failure: a parse failure yields no claims, the manifest is minted without membership edges, and the repair — `oci_membership_edge_backfill` — is **operator-invoked**, not scheduled. "No automatic repair" is exactly right, for a different reason than the one recorded. |
| F12b-5 | **teilweise / Protokollarbeit** (corrected) | `hort-http-oci/src/middleware/oci_auth.rs:287-309` | The declared collapse of a *truly absent* credential stands. The scheme-case half is **both** matchers, not one: `strip_prefix("Bearer ")` and `strip_prefix("Basic ")`, while RFC 9110 §11.1 / RFC 7235 §2.1 make the scheme case-insensitive and RFC 7617 §2 says the same for Basic. A lower-case valid Basic carrier reads as no credential. Whether a *present but malformed* carrier should be 401 rather than anonymous is **not** settled by the ADRs inspected (ADR 0045's table says "invalid credential" → 401 without defining malformed) — that part is an open question, not a verdict. |
| F13-5 | **besteht** (corrected) | `metadata_mirror.rs:477-483`, `hort-app/src/project.rs:152-189` | Two comments, each true about its own half, jointly false. The adapter's `BOUNDED-BODY ASSUMPTION` says it receives "the small, already-capped upstream metadata **projection's source**". The caller hands it the **raw body**: `project.rs` PASS 2 re-opens the tempfile and streams it in, promising "No full-body `Vec`: the body flows file → `tokio::io::copy` → mirror" — a promise the object-store adapter then breaks with `tokio::io::copy(&mut body, &mut buf)` + `Bytes::from(buf)`. ADR 0026 is explicit that "Upstream metadata bodies are not small" (a measured ~50 MiB packument), that "Memory scales with body size × concurrency" was the failure it was written to end, and that the 64 MiB cap is a storage/plausibility bound and **not** a memory bound. An ADR outranks a comment. |
| F14-7 | **besteht** | `hort-http-maven/src/lib.rs:321` (early return) vs `:343` (resolution) | The sidecar branch `return`s before the unresolved-SNAPSHOT resolution runs, with `base_path` built by literal string surgery. `mvn deploy` stores only timestamped files, which the comment at `:331-342` says itself — so `foo-1.0-SNAPSHOT.jar.sha1` is resolved against a path that does not exist while `foo-1.0-SNAPSHOT.jar` resolves fine. The ordering **is** the defect. |
| F16-4 | **besteht** | `event_chain_head_reader.rs:98`, `:151`, `:157` | A malformed stored hash column, a failed `StreamSealed` deserialize and an unexpected variant all return `DomainError::Invariant`, the same type as "begin snapshot tx failed" (`:180`) and "reading live stream heads failed" (`:201`). Data-integrity evidence and infrastructure failure share one channel, so the verifier cannot reach a chain-break verdict. |
| F16b-1 | **besteht** | `hort-adapters-checkpoint-anchor/src/lib.rs:560-571` | `emit` writes the sequence-derived key with a plain `put`. Two emissions on one sequence overwrite, erasing a signed record — and the protection is WORM via "the operator-provisioned bucket default retention", a property the code cannot verify and does not check. |
| F18-1 | **Entscheidung** | `task_use_case.rs:11-44` | The module header enumerates the trade-off, including both distinguishable ways a task can execute un-audited, and why the row cannot simply be deleted: "deleting it would also free the durable single-flight idempotency key (ADR 0028) that stops a destructive kind running twice." |
| F19-2 | **besteht** | `hort-worker/src/composition.rs:1452-1457` | `InProcessReconcileGate(reconcile_gate_state.is_open())` freezes the boot-sweep verdict into a `bool` whose `is_converged()` returns it forever. A precondition evaluated once stands in for a continuing property. |

## The cut that did not survive

This pass proposed seven criteria over the remaining findings. The peer review
split **all four** pairings, each for the same reason: one application of the
criterion does not settle both members. I checked each argument and all four
hold.

| Proposed pairing | Why it is not one criterion |
|---|---|
| S8-2 + F19-2 ("a placeholder stands for a measurement") | S8-2 needs a defined meaning for *absent policy* in one derivation; F19-2 needs a gate that can react to *post-boot drift*. A default-mode change does nothing for a frozen worker gate and vice versa. The shared sentence was an analogy, not a criterion. |
| S2-3 + S3-3 ("a cache survives what falsifies it") | S2-3 is an ordering race that persists even with a perfect key; S3-3 is a keying problem that persists under serial execution. Neither fix nor acceptance test transfers. |
| F16-4 + F16b-1 ("a refusal must not lose its verdict") | F16-4 must preserve the *classification* of corrupt chain evidence across an error channel; F16b-1 must prevent or verify *replacement* of a signed record under storage configuration. There is no shared refusal. |
| S5-1 + F12-1 ("a refusal must not reveal what it hides") | Removed outright: F12-1 is ADR 0055's decision, and the audience is the opposite one — S5-1 leaks to a caller **without** `Read`, F12-1 diagnoses to a caller the read gate already **admitted**. |

**So the honest conclusion reverses this unit's own premise.** The issue argued
for cutting by criterion rather than by file, because "ein Kriterium einmal
konsequent angewandt schließt seine Fälle". For these sixteen that is simply
not true: they are sixteen mechanisms that happen to have been found in one
audit. What #458 was worth was the **verification** — six verdicts corrected,
one unit prevented from re-introducing a retired posture — not the cut.

Grouping for dispatch is therefore by **code locality, declared as locality**,
not dressed up as a criterion. Severity order, highest first:

1. **F12-4** — OCI upload-session binding (principal *and* name). An
   authorization gap: another writer can finalize or delete a session.
2. **S5-1** — discovery's unfiltered `find_by_key` plus a comment asserting the
   anti-enumeration property it does not provide.
3. **F13-5** — the object-store mirror buffers a raw metadata body, against
   ADR 0026.
4. **F11-4** — the metadata cap is absent at the verified-ingest entry.
5. **F7b-2** — the served cargo index can advertise an empty checksum.
6. **S2-3** — a revoked token stays accepted for the cache TTL.
7. **F14-7** — the Maven sidecar branch returns before SNAPSHOT resolution.
8. **F16-4** — corrupt chain evidence and infrastructure share one error type.
9. **F16b-1** — a signed checkpoint can be overwritten; WORM is unverified.
10. **F12b-5** — both auth scheme matchers are case-sensitive (RFC 9110 / 7617).
11. **S3-3** — the JWKS cache is keyed on the issuer name, not its URL.
12. **F12b-1** — a derivation failure leaves membership edges with only an
    operator-invoked repair.
13. **F19-2** — the purge gate freezes the boot sweep's verdict.
14. **F7-2** — a disproved packument's invalidation is best-effort.

Two of the sixteen are **decisions before they are work**, and neither should
be dispatched as an implementation:

- **F7b-3** — abort an incomplete multipart on a cancellable failure, or make
  the bucket lifecycle rule an operator obligation and verify provisioning. A
  risk choice about a cost that lands outside this repository.
- **S8-2** — what "no active policy" *means* for re-evaluation (unknown, or the
  project default) is not settled by any rule found. Classify before fixing.

## Final accounting

| | Count | Findings |
|---|---:|---|
| **besteht / work** | 14 | S2-3, S3-3, S5-1, F7-2, F7b-2, F11-4, F12-4, F12b-1, F12b-5, F13-5, F14-7, F16-4, F16b-1, F19-2 |
| **decision before work** | 2 | F7b-3, S8-2 |
| **trägt eine Entscheidung — not work** | 4 | S2-1 (ADR 0013), S9b-3 (ADR 0015), F18-1 (ADR 0028), F12-1 (ADR 0055) |
| **erledigt — tick off in #383** | 1 | S4-1 (`5621a559`) |
| **Behauptung trifft nicht zu** | 1 | S1-2 |

22 accounted for.

**On S1-2, the one verdict the review would not confirm.** It asked whether
"unbounded database work" meant per request or in aggregate. The claim as
#383 records it is *"`/readyz` permits unbounded database work without
authentication"* — work, not rate — and one `SELECT 1` per request is bounded
work, so the verdict stands. The review did measure something adjacent and
true that the claim does not say: the probe route is mounted outside the
middleware stack at both the baseline and today, so it is not rate-limited.
That is **a separate observation with no ticket here** — the collector is
closed to new entries — and it is named for the maintainer rather than folded
into a finding it is not.

## What this pass did not do

It fixed nothing, and that was the point. Four of the verdicts above would have
been written as implementations by a unit that started from the table in #383,
and one of those four (F12-1) would have reversed an ADR. One (S1-2) would have
been implemented against a claim that was never true. In the other direction,
three findings I would have closed with a comment or waved off as declared
(F7b-2, F7b-3, F13-5) are real work, and one (F12-4) is a security gap I had
recorded as half-done.
