# 428 — the referrers list belongs to the name that was asked for

**Issue:** #456 · **Branch:** `agent/456-referrers-spec-conformance` · Item 2 of 3.

## Problem

F12b-3 and F12b-4 (item 427) are about what the response *contains*. This one is
about **which rows are in it**, which is a different blast radius and therefore
its own unit.

The spec scopes the list to the requested name:

> Each descriptor is of an image manifest or index **in the same `<name>`
> namespace** with a `subject` field that specifies the value of `<digest>`.

The lookup is not name-scoped (`referrers.rs:226-227`):

```rust
.content_reference_use_case
.find_by_visible_target(repo_key, &target_hash, Some("oci_subject"), actor)
```

It filters on **repository** and **subject digest**. A referrer pushed under a
different OCI name inside the same repository, pointing at the same subject,
therefore appears in the requested name's list.

### The comment that hides it

`referrers.rs:440`:

```rust
// The OCI referrers response is spec-mandated NOT to echo `name` in
// the image-index body, so dropping it here is correct.
let _ = name;
```

That is **true and about a different question**. The spec does not put `name`
in the image-index body, so not echoing it is right. The comment explains why
`name` does not belong in the *response* and thereby reads as a justification
for discarding it entirely — while the value is also not used to *scope the
query*, which the spec requires. Two questions, one answered.

This is the second comment in this file that argues the current behaviour on a
neighbouring rule (see item 427's `artifactType` comment). Both need correcting
with the code, not after it.

## What this item does

Scope the listing to the requested name as well as the repository and subject.

**The shape is a decision this item has to make and record, not assume.** The
subject hash is the join key today; the name is not stored on the
`content_references` edge in a form the query filters on, or it would already
be used. Establish where the referring object's name lives — the artifact row,
the metadata JSON, a path prefix — before choosing between filtering in the
query and filtering the rows after the fetch. State the choice and its cost:
a post-fetch filter reads rows it then discards, which on a hot subject is
work per request.

Whichever shape: `name` stops being `let _ = name;` and the comment says both
things, or it goes.

## Why this is riskier than item 427 and gets its own MR

427 adds fields to a response. This one **removes rows from it** — a client
that today sees a referrer from a sibling name stops seeing it. That is the
spec's intent and still a visible behaviour change, so it wants its own
reviewable unit, its own test, and its own line in the changelog.

Check the existing tests before changing the query: `referrers.rs` carries a
test suite from `:518` onward, and any fixture that pushes referrers under a
name different from the one it then queries is asserting today's behaviour.
Such a test is not wrong to update — it encoded the defect — but it must be
updated deliberately and named in the report, never quietly re-pointed.

## Read first

- `crates/hort-http-oci/src/referrers.rs:220-300` and the test module from `:518`.
- `ContentReferenceUseCase::find_by_visible_target` and the `content_references`
  schema, to establish what is available to filter on.
- The spec section named in item 427.

## Acceptance

- A referrer pushed under name `a` and queried under name `b` in the same
  repository does **not** appear in `b`'s list, with a test that fails before
  the change.
- A referrer pushed and queried under the same name still appears, and the
  `artifactType` filter from item 427 still composes with the name scoping —
  one test that exercises both, because they both narrow the same list.
- Every existing test whose fixture pushed under one name and queried another is
  named in the report with what it now asserts.
- The `let _ = name;` comment states both rules or the discard is gone.
- A `CHANGELOG.md` entry under `### Fixed`, one or two lines, saying that a
  referrers list no longer includes referrers from another name in the same
  repository (#456).

---

## Nachtrag nach dem Peer-Review — der vorgeschlagene Schlüssel ist der falsche

Diese Einheit hätte, so wie sie oben steht, einen **neuen** Defekt in die Gegenrichtung eingebaut. Der Review hat es gefunden, ich habe es nachgeprüft:

`oci_manifest_path` (`crates/hort-http-oci/src/coords.rs:88-103`) ist

```rust
format!("manifests/sha256:{}", digest.as_ref())
```

mit dem Doc-Kommentar *„the image name deliberately absent, so `(repository_id, path)` holds at most one manifest row per digest"*, und `oci_manifest_coords` setzt `name`/`name_as_published` auf den Namen des **ersten** Pushes. Der Ingest dedupliziert auf Pfad und Hash.

**Folge: dieselben Bytes, unter zwei OCI-Namen im selben Repository gepusht, sind EINE Artefaktzeile mit EINEM Namen.** Auf `artifact.name` zu filtern hätte also einen Referrer ausgelassen, der unter dem angefragten Namen legitim gepusht wurde — bloß weil die Zeile den anderen Namen trägt. Die Spec verlangt die Namensbindung; sie verlangt nicht, dass wir dabei legitime Einträge verlieren.

**Das System speichert nicht, unter welchen Namen ein Subject referenziert wurde.** `ContentReference` trägt Quell-Id, Target, Kind, JSON-Metadaten, Repository und Zeit — keinen Namen (`content_reference_index.rs:183-205`), und der Sidecar schreibt nur `artifact_type` und `media_type`. Die Information, die F12b-2 braucht, existiert heute nicht.

Damit ist auch diese Einheit eine Entscheidung und keine Implementierung:

1. **Den Namen auf der `oci_subject`-Kante projizieren** (Write- und Proxy-Pfad), plus eine Antwort für bestehende Kanten. Dann ist die Kante die Namensquelle und die Mehrfachbenennung bleibt abbildbar.
2. **Auf `artifact.name` filtern und den Verlust akzeptieren** — ausdrücklich begründet, mit der Mehrfachbenennung als benanntem Kostenpunkt. Billig und in genau dem Fall falsch, den die Coords absichtlich zulassen.
3. **Die Mehrfachbenennung als nicht unterstützt erklären.** Dann ist `artifact.name` korrekt, und die Erklärung gehört an die Coords, wo heute das Gegenteil steht.

**Der Test, der oben in der Akzeptanz steht, prüft zu wenig.** „Referrer unter `a` gepusht, unter `b` angefragt" benutzt zwei verschiedene Referrer-Artefakte. Der harte Fall ist **ein** Referrer-Digest, unter zwei Namen gepusht, dann unter beiden angefragt — der muss in **beiden** Listen erscheinen, und genau den bricht Variante 2.

Nicht anfangen, bevor die Entscheidung steht.

**Abhängigkeit:** diese Einheit konsumiert `name` aus der Projektion in `backlog/430-project-what-the-referrers-list-needs.md`. Vor 430 gibt es keinen tragfähigen Namensschlüssel — `artifact.name` ist, wie oben gezeigt, der falsche.


---

## Superseded (2026-11-21)

This item asked whether the list should filter on `artifact.name` and accept the
multi-naming error, or not filter and serve the unnarrowed list. The question is
gone: #459 decided that the OCI wire `<name>` is the namespace for artifact
identity, with the reach confirmed as the whole OCI surface, so narrowing the
list is a **consequence of identity** rather than a filter to design.

The work lives in `backlog/461-the-referrers-list-belongs-to-the-asked-name.md`,
which rests on the decided model instead of asking the question. Two of this
item's premises were already falsified before the supersession and are recorded
there so they are not re-derived: `artifact.name` is the wrong key, and the
projected `name` on the edge — correct while identity was name-free — is now a
second source of truth for a fact the path carries.

Nothing here is to be implemented.
