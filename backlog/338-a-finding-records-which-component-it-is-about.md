# 338 — A finding records which component it is about

**Issue:** #351 · **Branch:** `agent/351-a-finding-condemns-only-its-own-artifact`
**Governing decisions:** ADR 0056 (resolved-component SBOMs from the payload —
**amended 2026-10-15**, see §1) · ADR 0040 ("persist the fact, derive the
interpretation") · ADR 0007 (fail-closed release predicate, untouched here).

**First of four. Pure domain, no behaviour change.** This item adds the fact
and its single interpretation; nothing populates or consumes it yet. Items 339
(populate), 340 (consume) and 341 (persist) follow in that order.

## 1. Why this exists

A cargo `.crate` is a **source** tarball. It carries the publishing
maintainer's own `Cargo.lock`, and `CargoFormatHandler`'s `PayloadSbom`
(`crates/hort-formats/src/cargo.rs:605-637`) walks that lockfile to build the
artifact's component list. ADR 0056 decided that deliberately, to stop
declared version *ranges* from reaching a scanner.

The consequence, which ADR 0056's own 2026-09-17 amendment names: on a proxied
format those resolved components are "the upstream author's dev-time resolve,
not the consumer's build". Cargo ignores a dependency's lockfile — only the
top-level package's lockfile decides a build — and the `.crate` contains none
of that dependency's code. A measured case: `hyper-util 0.1.21` was terminally
rejected by an advisory about `h2 0.4.13`, a version read out of hyper-util's
vendored lockfile, while this workspace's own lock resolves `h2 0.4.16`.

**The amendment agreed on 2026-10-15** narrows ADR 0056: a finding may
condemn an artifact only when the affected code is *in* the artifact. The
component list stays — it is useful information — but a component the artifact
does not contain carries no release authority. `enforcement` stays the
operator's answer to "should findings gate in this repo"; it is not the answer
to "is this finding about this artifact".

Nothing in `crates/hort-domain/src/policy/` can express that today: a hit is a
hit, with no notion of which component it names.

## 2. What to add

`Finding` (`crates/hort-domain/src/types/finding.rs`) already carries two
fields of exactly the shape this needs, both ADR 0040's "persist the fact,
derive the interpretation", both `#[serde(default)]` for records written
before they existed:

| field | stored fact | derived reading |
|---|---|---|
| `informational_class` | the raw OSV class string | `is_informational()` |
| `severity_basis` | did the backend read a severity? | `is_informed()` |

Add a third of the same shape, recording **how the finding's component relates
to the artifact's subject component**. Model it as an enum, not a bool — the
same reasoning ADR 0059 gives for `SeverityBasis` being an enum: a bool cannot
later distinguish a third case, and there is one already in view (a format
whose artifact *does* contain its closure, e.g. an OCI image, where every
component is contained).

Name the variants for the fact, not the verdict. Something of the shape
"this finding names the subject itself" / "this finding names a component the
artifact does not contain" / "not established". **The `not established` variant
is the `Default`**, and therefore what `#[serde(default)]` yields for a
record written before this field existed — mirroring `SeverityBasis`'s
reasoning exactly: a pre-field record cannot be *proven* to be anything, so it
must default to the reading that preserves today's behaviour. Today's
behaviour is "this finding condemns", so the default must condemn. Defaulting
to "not contained" would silently disarm the entire existing corpus.

**This default is not merely a legacy accommodation, and the distinction
matters.** Measured: every production SBOM builder sets a subject, and the
subject is derived from the artifact's *coordinates* rather than its payload
(`crates/hort-formats/src/npm.rs:666-671` states the rule). So after item 339
lands, `not established` is structurally unreachable for a new scan — it is a
migration artefact that shrinks toward zero, not a resting state. A fail-closed
default is defensible exactly while it stays rare, recognisable after
persistence (item 341) and correctable; item 339 §5 owes the observable that
keeps that claim honest.

Add one derived predicate beside it — the single place that answers *"may this
finding condemn its artifact?"* — and document that it is the only such place.
Item 340 is its only production caller.

## 3. Constraints

- `hort-domain` is pure: no I/O, no `sqlx`, no `reqwest`, no `axum`.
- **100 % coverage** for `hort-domain` — every variant, every branch of the
  predicate, plus the legacy-deserialisation case (a payload without the field
  round-trips to the condemning default).
- `#[serde(default)]`, matching the two existing fields. Do not re-validate
  old payloads.
- No file under `migrations/` changes in this item. Persistence is item 341.
- No issue, MR or backlog reference in any code comment. State the invariant.

## Acceptance

- `Finding` carries the new fact; `cargo test --workspace` green.
- A `Finding` deserialised from a payload lacking the field reads as the
  condemning default, pinned by a test.
- Exactly one predicate derives "may this condemn", with a rustdoc saying so.
- No production caller yet — this item changes no verdict. A reviewer can
  confirm that by grepping for the predicate and finding only tests.
