# 267 — Der Terminalitätsbeweis und das Löschen des Streams sind nicht eine Entscheidung

**Issue:** #335 · **Branch:** `agent/335-gc-authority`
**Governing decisions:** ADR 0020 (Single-Flight für Seal-Jobs) · der Vertrag
aus #334 (eine Entscheidung wird mit der Version gepaart, die ihren Schreibzug
autorisiert) · `migrations/004_events.sql:171` („Optimistic concurrency").
Schließt **F19-6**.

## Warum

`EventStoreRetentionUseCase` beweist, dass der Tail eines Artefakt-Streams
`ArtifactPurged` ist, und prüft den Floor
(`eventstore_retention_use_case.rs:389-445,453-499,525-576`). Danach ruft es
`delete_stream` / `archive_stream`.

`seal_and_remove` (`event_store.rs:797-…`) eröffnet eine **neue** Transaktion,
liest den Head mit

```sql
SELECT stream_position, event_hash FROM events
 WHERE stream_id = $1 ORDER BY stream_position DESC LIMIT 1
```

— **ohne `FOR UPDATE`** —, schreibt den Tombstone auf einen *anderen*
Meta-Stream und löscht dann alle Zeilen des Zielstreams nach `stream_id`.
**Nirgends wird Terminalität oder Floor noch einmal geprüft.**

Ein später eintreffendes `ArtifactExpired` kann nach dem Beweis anhängen, weil
die Retention-Bewertung `ExpectedVersion::Any` auf ihrem zuvor gelesenen
Kandidaten verwendet (`retention_use_case.rs:371-382,634-698`). Landet es vor
dem Head-Read des Seals, wird ein **nicht mehr terminaler** Stream mit
passendem Tombstone gelöscht; landet es zwischen Head-Read und `DELETE`,
verzeichnet der Tombstone den alten Head, während das neue Ereignis
mitgelöscht wird.

**ADR 0020 hilft hier nicht**, und das ist der Punkt, an dem man sich täuschen
kann: seine Single-Flight-Schichten serialisieren **Seal-Jobs gegeneinander**,
nicht einen Seal gegen einen *Append* auf denselben Stream.

## Die Form der Lösung liegt im Repository schon vor

Die Append-Strecke sperrt nicht. Sie liest den Tail mit **derselben Abfrage**
(`event_store.rs:1052-1056`, ebenfalls ohne `FOR UPDATE`) und verlässt sich
auf den eindeutigen Index über `(stream_id, stream_position)`
(`migrations/004_events.sql:171-172`), der dort ausdrücklich als
„Optimistic concurrency" bezeichnet ist. Ein Seal kann sich also **nicht** auf
eine Zeilensperre verlassen, um Appender auszuschließen — es gibt keine.

Die passende Antwort ist deshalb dieselbe, die #334 eine Ebene höher
eingeführt hat: **die Entscheidung wird mit der Version gepaart, die sie
autorisiert.** Der Aufrufer hat den Tail bereits gelesen, um Terminalität zu
beweisen; er soll ihn **mitgeben**, und der Adapter soll ablehnen, wenn der
Stream inzwischen weitergewachsen ist. Das ist `ExpectedVersion` für den Seal.

Die genaue Signatur und wie die Ablehnung zurückkommt, entscheidest Du —
aber die Richtung ist vorgegeben: **kein neuer Lock-Mechanismus**, sondern die
optimistische Prüfung, die dieses Schema ohnehin trägt.

**Das Löschen selbst muss die Bedingung tragen.** Eine Nachprüfung als eigenes
Statement kurz vor dem `DELETE` schließt das Fenster nicht: unter READ
COMMITTED sieht jedes Statement einen neuen Snapshot, ein Append zwischen
Prüfung und `DELETE` bliebe unsichtbar. Entweder trägt das `DELETE` das
Prädikat, oder die betroffene Zeilenzahl wird gegen die erwartete geprüft und
die Transaktion bei Abweichung zurückgerollt.

## Was offen bleiben darf — aber benannt

Ein Append, das **nach** dem `DELETE` committet, ist von hier aus nicht
erreichbar; das ist die Bedeutung von „nach dem Seal" überall. Schreib den
verbleibenden Rest an die Stelle, so wie es Einheit 266 für das Tag-Fenster
getan hat. Eine ehrlich dokumentierte Restlücke ist das Ziel; eine
stillschweigende ist genau der Defekt, um den es hier geht.

## Nebenbei, weil Du ohnehin in `purge_gc.rs` warst

Beide `AssertSqlSafe`-Stellen (`purge_gc.rs:632` und `:709`) tragen **keine**
Injection-Audit-Begründung, die die sqlx-0.9-Konvention verlangt. Beide sind
tatsächlich sicher — das SQL wird ausschließlich aus `const`-Strings
zusammengesetzt, kein Laufzeitwert fließt ein. Schreib das an beiden Stellen
hin. Zwei Zeilen, und die ältere Stelle hat dieselbe Lücke.

## Akzeptanz

- Ein `ArtifactExpired`, das **nach** dem Terminalitätsbeweis und **vor** dem
  Seal anhängt, führt dazu, dass **nicht gelöscht** wird: der Stream bleibt
  vollständig, kein Tombstone, und der nächste Durchlauf bewertet neu.
- Ein Stream, an dem sich im Fenster nichts ändert, wird weiterhin normal
  gesiegelt und gelöscht — eigener Test, sonst beweist der Mutationsnachweis
  nur, dass die Prüfung pauschal bremst.
- Der Tombstone verzeichnet nie einen Head, der zum Zeitpunkt des `DELETE`
  nicht mehr der Head war.
- **Mutationsnachweis:** die Bedingung am `DELETE` entfernen macht genau diese
  Tests rot, und zwar mit der Aussage „Stream gelöscht" bzw. „Tombstone nennt
  den falschen Head" — nicht mit einem Compilefehler.
- Die verbleibende Restlücke steht als Kommentar an der Stelle.
- Beide `AssertSqlSafe`-Stellen in `purge_gc.rs` tragen ihre Begründung.
- Gate grün: `cargo fmt --check`, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo test --workspace --no-fail-fast`, `cargo-audit audit
  --deny warnings`, `cargo deny check`.
