# 427 — the referrers descriptor carries what the spec says it carries

**Issue:** #456 · **Branch:** `agent/456-referrers-spec-conformance` · Item 1 of 3.

## Problem

Two of #456's four findings are about the **contents of the response**, and both
are `MUST` violations read off the OCI Distribution Specification §"Listing
Referrers" rather than inferred from the code.

### F12b-3a — the `artifactType` fallback is missing, and a code comment argues the wrong half

`crates/hort-http-oci/src/referrers.rs:400-420` builds the descriptor from
`mediaType`, `digest`, `size`, then echoes `artifactType` only when the
metadata row supplied one:

```rust
// Echo `artifactType` only when the metadata row supplied a
// non-null value. Spec §referrers-api permits the field to be
// omitted when the source manifest had no `artifactType`.
if let Some(at) = row.metadata.get("artifact_type").and_then(|v| v.as_str()) {
```

The spec says three things, and they differ by the kind of the referring
object:

> The descriptors MUST include an `artifactType` field that is set to the value
> of the `artifactType` in the image manifest or index, if present.
> If the `artifactType` is empty or missing in the image **manifest**, the value
> of `artifactType` MUST be set to the **config descriptor `mediaType`** value.
> If the `artifactType` is empty or missing in an **index**, the `artifactType`
> MUST be omitted.

So omission is correct for an **index** and wrong for a **manifest**, where a
fallback is mandatory. The comment states the index rule and applies it to
both — it is not a missing feature with a placeholder comment, it is a comment
that argues the current behaviour is already right. **Correct the comment in
the same change**, or the next reader re-derives the same mistake from it.

### F12b-3b — annotations are absent

> The descriptors MUST include annotations from the image manifest or index.

The descriptor carries no `annotations` field at all. This is the half with the
most consumer impact: tooling that selects a signature or SBOM by
`org.opencontainers.image.created` or a vendor annotation gets a list it cannot
discriminate, and has to fetch every referrer to find out.

### F12b-4 — an applied filter is not disclosed

Filtering **is** implemented — `referrers.rs:269-273` filters rows on the
`artifact_type` metadata key against the query parameter — and the response
sets only `Content-Type` (`:446-450`).

> If filtering is requested and applied, the response MUST include a header
> `OCI-Filters-Applied: artifactType` denoting that an `artifactType` filter was
> applied. If multiple filters are applied, the header MUST contain a comma
> separated list of applied filters.

The precondition therefore holds today: we apply the filter and do not say so.
A client cannot tell a filtered list from a complete one, which is the whole
reason the header exists.

## What this item does

One criterion, applied to the response builder once: **the referrers response is
a spec surface, and what it contains is decided by the specification, not by
what the metadata row happens to hold.**

- `artifactType`: present → echo; absent on a **manifest** → the config
  descriptor's `mediaType`; absent on an **index** → omit. The descriptor
  builder must therefore know which kind it is describing — establish where
  that is available before assuming it is, and if it is not, say so rather than
  guessing a default.
- `annotations`: included from the referring manifest or index.
- `OCI-Filters-Applied: artifactType` when and only when a filter was requested
  **and applied**. Comma-separated if a second filter is ever added.

## Out of scope, and why — so a reviewer does not flag these

Reading the spec for this item surfaced two further `MUST`s. Both were checked
and neither is a defect here:

- **`Link` header for pagination.** *"A `Link` header MUST be included in the
  response when the descriptor list cannot be returned in a single manifest."*
  The handler applies no limit, offset or truncation, so the list is always
  returned in one manifest and the obligation is satisfied vacuously. It
  becomes real the moment a cap is introduced — that is a note for whoever
  introduces one, not work for this item.
- **`MUST NOT return a 404`.** *"If the registry supports the referrers API,
  the registry MUST NOT return a `404 Not Found` to a referrers API requests."*
  The handler answers `NAME_UNKNOWN` for a repository that is missing **or**
  invisible to the caller (`:145-175`, the anti-enumeration control). That is
  not this sentence's case: the sentence immediately before it reads *"Assuming
  a repository is found, this request MUST return a `200 OK`"*, which scopes
  the prohibition to a **found** repository and aims at the pre-1.1 "API not
  supported" fallback. Our 404 is for a repository that is not found. Reading
  the line alone and generalising is the error here.

## Read first

- `crates/hort-http-oci/src/referrers.rs` — the whole file; it is 1500 lines
  but the module header carries the visibility policy that item 3 turns on.
- The spec section, authoritative over the code:
  `https://github.com/opencontainers/distribution-spec/blob/main/spec.md`
  §"Listing Referrers".

## Acceptance

- A referring **manifest** with no `artifactType` produces a descriptor whose
  `artifactType` is the config descriptor's `mediaType`; a referring **index**
  with none produces a descriptor with no `artifactType` key. Both asserted,
  and both shown to fail before the change.
- Annotations from the referring object appear in the descriptor; an object
  with no annotations does not grow an empty object (the spec says include
  them, not invent them) — state which of the two you chose and why.
- A filtered request carries `OCI-Filters-Applied: artifactType`; an unfiltered
  one does not carry the header at all.
- The `artifactType` comment no longer states the index rule as if it covered
  manifests.
- The change adds no uncovered lines (intersect the diff's added line numbers
  with `cargo llvm-cov --show-missing-lines`, per touched file).

---

## Nachtrag nach dem Peer-Review — diese Einheit ist blockiert, und zwar begründet

Der Review hat eine Tatsache widerlegt, die ich oben als „vom Implementierer zu klären" offengelassen hatte. Ich habe sie selbst nachgeprüft:

**Die Daten, die die Spec verlangt, liegen nicht in der Projektion.** `subject_content_reference_claim` (`manifests_write.rs:1596-1611`) schreibt in die `oci_subject`-Kante genau

```rust
metadata: serde_json::json!({
    "artifact_type": artifact_type_opt,
    "media_type": media_type,
}),
```

Also **keine Annotations** — `annotations` kommt in `manifests_write.rs` und `referrers.rs` überhaupt nicht vor — und **nicht die `mediaType` des Config-Descriptors**; die `media_type` hier ist der Typ des referenzierenden Manifests selbst. Beides ist nur aus den Manifest-Bytes zu holen.

**Damit ist die Einheit keine Implementierung mehr, sondern hängt an einer Entscheidung:**

1. **Ein begrenzter CAS-Read plus Parse pro Descriptor** (`ArtifactUseCase::read_content_for_projection`). Erfüllt die Spec für Alt- und Neubestand gleich, ändert aber das Kostenmodell der Liste von „eine Projektionsabfrage" auf „ein Objekt-Read je Zeile" — und ADR 0062 benutzt für die Listen-Schließung bewusst Projektionsdaten.
2. **Die Projektion erweitern** (Write- **und** Proxy-Pfad) und für bestehende Zeilen einen Weg nennen. Billig im Betrieb, aber jede vor der Änderung gepushte Zeile bleibt unvollständig, bis etwas sie nachzieht.

Das ist eine Kosten-gegen-Vollständigkeit-Abwägung über eine heiße Leseroute und keine Implementierungsdetailfrage. **Nicht anfangen, bevor sie beantwortet ist.**

### Zwei weitere Korrekturen aus dem Review, selbst nachgelesen

- **Der Filter und der Fallback sind gekoppelt.** `referrers.rs:267-278` filtert auf dem **rohen** `artifact_type` der Kante, bevor der Descriptor gebaut wird. Ein Manifest ohne deklarierten `artifactType`, dessen **effektiver** Typ nach der Fallback-Regel die Config-`mediaType` wäre, wird damit aus einer gefilterten Antwort verworfen. Wer `OCI-Filters-Applied` setzt, ohne den Filter auf den effektiven Typ umzustellen, behauptet einen angewandten Filter über einer Liste, der ein passendes Manifest fehlt. Die beiden gehören in **eine** Änderung.
- **Die Akzeptanz oben nennt nur „absent".** Die Spec sagt *„empty or missing"* — der leere String ist mitgemeint und muss mitgetestet werden.
- **`referrers.rs:396-401` rät.** Eine Zeile ohne Sidecar-`media_type` wird als Image-Manifest angenommen; eine alte Index-Zeile wäre damit falsch beschriftet, und die Fallback-Regel unterscheidet gerade nach dieser Art. Entweder aus autoritativen Bytes ableiten oder eine Alt-Zeilen-Politik hinschreiben.

### Was der Review bestätigt hat

Die beiden geparkten MUSTs halten, und beim 404 ist die Lage besser als von mir behauptet: die **Endpoint-Tabelle der Spec selbst** führt für `end-12a`/`end-12b` `404`/`400` als Fehlercodes (`spec.md:860-861`). Mein „vertretbar" war zu schwach — die Tabelle deckt es. Beim `Link`-Header hat der Review die Kette unter dem Handler mitgelesen, was ich nicht getan hatte: `content_reference.rs:97-112` gibt den Vektor unverändert weiter, der Adapter benutzt `fetch_all` ohne `LIMIT` oder Offset. Die Pflicht ist damit wirklich leer erfüllt — und das unbegrenzte Fan-out bleibt ein Kostenrisiko, das kein MUST auslöst.

**Abhängigkeit:** diese Einheit konsumiert die Projektion aus `backlog/430-project-what-the-referrers-list-needs.md` und beginnt erst, wenn 430 gemergt ist. Vor 430 existieren die Daten nicht, die die Spec hier verlangt.
