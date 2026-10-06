# 265 — Geschützte Evidenz beansprucht ihre Bytes, auch ohne Kante

**Issue:** #335 · **Branch:** `agent/335-gc-authority`
**Governing decisions:** ADR 0007 (Quarantäne-Lebenszyklus) · E1 und E1a auf
#335 (beide entschieden) · #272 (additive Ereignisfelder werden hier **nicht**
angefasst).

## Warum

`GC_PROTECTED_QUARANTINE_STATUSES`
(`crates/hort-adapters-postgres/src/lib.rs:117-120`) nennt drei Zustände, die
„never be offered to garbage collection or refcount repair paths":
`quarantined`, `rejected`, `scan_indeterminate`. Die Liste wird an drei
Stellen gebunden und wirkt nur an zweien als Schutz:

| Stelle | Wirkung |
|---|---|
| `purge_gc.rs:452` (`list_pending_purge`) | Schutz — nie Purge-Kandidat |
| `retention_candidate_reader.rs:346` | Schutz — erwirbt nie `ArtifactExpired` |
| `refcount_reconcile.rs:171,218` | **kein Schutz** — bekommt keine Kante repariert |

Die ersten beiden schützen das **Artefakt**, die dritte entzieht ihm den
**Anspruch auf seine Bytes**. Zurückgewonnen wird aber auf Hash-Ebene:
`remaining_refs` (`purge_gc.rs:292-299`) zählt nur `content_references`-Zeilen
zu einem `target_content_hash`.

Ein geschütztes Artefakt ohne Kante trägt damit zur Zählung seines eigenen
Hashes **null** bei. Wird ein freigegebenes Geschwister mit demselben Hash
gepurgt, liest `begin_blob_reclaim` unter dem Lock `refs_now == 0`, gibt
`BlobReclaim::Granted` zurück, und das gemeinsame CAS-Objekt wird gelöscht.
Das geschützte Artefakt war nie Kandidat — seine Bytes sind trotzdem weg.

**Der Ausschluss im Reconcile bleibt, wie er ist.** Sein Kommentar
(`refcount_reconcile.rs:144-151`) begründet ihn, und die Entscheidung E1 hat
sich ausdrücklich dagegen entschieden, ihn umzudrehen. Nicht anfassen.

## Was zu tun ist

### 1 · Das Prädikat

In `begin_blob_reclaim` (`purge_gc.rs:594-650`), **unter dem Blob-Lock** und
**nur auf dem Pfad, der sonst löschen würde** — also nachdem
`remaining_refs` `0` geliefert hat. Läuft die Zählung über null, bleibt der
Blob ohnehin; dann ist die zusätzliche Abfrage überflüssig.

Das Prädikat fragt: **beansprucht irgendein nicht gelöschtes, GC-geschütztes
Artefakt diesen Hash?**

**Ein geschütztes Artefakt beansprucht ZWEI Hashes, nicht einen.** Das ist die
Falle dieser Einheit:

- der Primärinhalt steht in `artifacts.checksum_sha256`;
- der Metadaten-Blob steht in **`artifact_metadata.metadata_blob`** — einer
  anderen Tabelle, die der Reconkile in seiner zweiten Kategorie mit
  `trim(am.metadata_blob)` vergleicht (`refcount_reconcile.rs:196-215`).

Ein Prädikat nur gegen `artifacts.checksum_sha256` ließe den Metadaten-Blob
eines geschützten Artefakts weiterhin ungeschützt und schlösse damit genau die
Hälfte des Befundes, die man beim flüchtigen Lesen übersieht. **Beide Quellen
vereinigen, mit demselben `trim`.** In beiden Zweigen gilt
`a.deleted_at IS NULL` und der geschützte Status, gebunden über
`gc_protected_quarantine_status_names()` — nie eine zweite Literalliste.

Gezählt wird, nicht nur geprüft: der Rückgabewert trägt die Zahl.

### 2 · Die eigene `BlobReclaim`-Variante

`BlobReclaim` (`crates/hort-domain/src/ports/purge_gc.rs:192-218`) bekommt
eine Variante — Vorschlag `ProtectedClaim { claimants: u32 }`.

**`Referenced { refs_now }` zu missbrauchen ist keine Option:** dessen Doc
legt den Wert als `content_references`-Zählung fest, und es gibt hier keine
einzige solche Zeile. Das wäre dieselbe Unwahrheit eine Ebene tiefer.

Die Variante ist **terminal, keine Vertagung** — aus demselben Grund, den
`Referenced` bereits nennt: ein Anspruch, der jetzt besteht, hält die Bytes,
und ewiges Nachfragen ließe den Purge des Geschwisters nie fertig werden. Ein
`rejected` Artefakt ist dauerhaft; `Contended`-Semantik wäre hier eine
Endlosschleife.

Das `match` in `purge_use_case.rs:584-617` ist **wildcard-frei**: die neue
Variante compiliert erst, wenn sie überall eingeordnet ist. Das ist der
Mechanismus, nicht ein Hindernis. Auch die Mock-Implementierungen in
`task_handlers/retention_purge.rs:153,306` und
`use_cases/purge_use_case_tests.rs:238` gehören dazu.

### 3 · `refs_remaining` bedeutet Ansprüche (E1a)

`ArtifactPurged.refs_remaining`
(`crates/hort-domain/src/events/artifact_events.rs:1448-1451`) dokumentiert
heute:

> Cross-`kind` `content_references` count for `content_hash` **after** this
> artifact's reference was removed. `0` ⇒ the blob was deleted; `> 0` ⇒ the
> blob stays, this ref is gone.

Schriebe der neue Pfad `0` und behielte den Blob, widerspräche das Ereignis
seiner eigenen Zusage — unsichtbar, weil es nur eine Zahl ist. Das Feld
bedeutet daher künftig **Ansprüche auf diese Bytes, unter dem Lock
beobachtet**: `content_references`-Zeilen, oder — wenn es keine gibt —
geschützte Artefakte, die den Hash beanspruchen. `0` ⇒ der Blob wurde
gelöscht; `> 0` ⇒ der Blob bleibt. **Die Felddokumentation umschreiben ist
die eigentliche Arbeit an diesem Punkt**, nicht eine Nebensache.

Der Aufrufer setzt im neuen Arm `pr.refs_remaining = claimants`, genau wie der
`Referenced`-Arm es mit `refs_now` tut.

**Kein neues Feld an `ArtifactPurged`.** Additive Ereignisfelder sind der
Gegenstand von #272 (manipulationssichere Kette, Golden-Vector-Test über die
kanonischen Payload-Bytes) und werden hier nicht nebenbei angefasst.

## Akzeptanz

- Ein quarantäniertes Artefakt und ein freigegebenes Geschwister teilen einen
  Hash; das Geschwister läuft ab und wird gepurgt. **Die Bytes bleiben.** Das
  `ArtifactPurged` des Geschwisters trägt `refs_remaining > 0`.
- Dasselbe für `rejected` und für `scan_indeterminate`.
- **Dasselbe für den Metadaten-Blob**, dessen Hash nur in
  `artifact_metadata.metadata_blob` steht — eigener Test, nicht derselbe mit
  anderem Namen.
- Ohne geschützten Ansprecher und ohne Referenzzeile wird weiterhin gelöscht,
  mit `refs_remaining = 0`.
- **Mutationsnachweis:** das Prädikat entfernen macht genau die neuen Tests
  rot, und zwar mit der Aussage „Bytes gelöscht", nicht mit einem
  Compilefehler.
- Die Felddokumentation von `refs_remaining` beschreibt die neue Bedeutung,
  und keine Stelle im Baum behauptet noch die alte.
- Der Reconcile ist unverändert.
- Gate grün: `cargo fmt --check`, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo test --workspace --no-fail-fast`, `cargo-audit audit
  --deny warnings`, `cargo deny check`.
