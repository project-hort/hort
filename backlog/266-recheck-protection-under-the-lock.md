# 266 — Der Purge prüft Schutz und Tags auf einer veralteten Seite

**Issue:** #335 · **Branch:** `agent/335-gc-authority`
**Governing decisions:** ADR 0007 · das Vorbild steht im selben File
(`begin_blob_reclaim`, „a snapshot is not permission to delete").
Schließt **F19-3**.

## Warum — und der Kommentar sagt bereits das Gegenteil

Der Sweep liest eine Seite und arbeitet sie ab:

```
let page = … list_pending_purge(batch_size, after) …   // purge_use_case.rs:370
for item in &page {                                     // :379
    self.process_one(now, item, &mut summary).await;    // :384
}
```

`item` ist die **Seitenzeile**. `list_pending_purge`
(`purge_gc.rs:~509-560`) liest `quarantine_status`, `tag_targeted`,
`expired_only_by_keep_last_n` und `user_deleted` **einmal**, in die Seite.

`process_one` prüft danach genau diese DTO-Felder — die
Evidenz-Reassertion (`purge_use_case.rs:415-431`) und die
Tag-Ausnahme (`:457`). Beide lesen `item`, also den Schnappschuss.

**Der Kommentar an der Tag-Prüfung behauptet etwas anderes**
(`purge_use_case.rs:435-445`):

> Re-reading the fact here is what makes the *interval* correct and not
> merely the steady state — the last reader before the destructive step is
> the one that decides.

Das stimmt nicht. Hier wird nichts neu gelesen, sondern eine veraltete
Tatsache neu *bewertet*. Der letzte Leser ist `list_pending_purge`, und das
Intervall zwischen Seitenlesung und dem destruktiven Schritt dieses Elements
enthält die **vollständige Abarbeitung aller vorangehenden Elemente der
Seite**, Storage-Löschungen eingeschlossen. Es ist das längste Intervall im
ganzen Ablauf, nicht das kürzeste.

Konkret: ein Scan, der ein freigegebenes Artefakt in diesem Fenster nach
`rejected` bewegt, oder ein Tag, der auf ein `KeepLastN`-Ziel gesetzt wird,
wird nicht mehr gesehen. `purge_artifact_refs` sperrt die Artefaktzeile zwar
(`purge_gc.rs:616`, `SELECT … FOR UPDATE`) — liest unter der Sperre aber
**nur `checksum_sha256`** und löscht die Kanten bedingungslos.

Die Sperre ist also da. Es wird nur nichts Entscheidendes unter ihr gelesen.

## Was zu tun ist

**Die Schutzfakten unter die bestehende Sperre ziehen.** Das `SELECT … FOR
UPDATE` bei `purge_gc.rs:616` holt zusätzlich zu `checksum_sha256`:

- `quarantine_status` — gegen `gc_protected_quarantine_status_names()`,
  gebunden, **nie** eine zweite Literalliste;
- die Tag-Tatsache über `crate::ARTIFACT_IS_TAG_TARGETED_SQL` — denselben
  String, den `list_pending_purge` und der Bewertungslauf benutzen, damit es
  dieselbe Lesung ist und nicht zwei, die heute übereinstimmen;
- `expired_only_by_keep_last_n` und `user_deleted`, soweit die
  Ausnahmeregel sie braucht.

Sagt die frische Lesung „jetzt geschützt" oder „jetzt tag-ausgenommen nach
derselben Regel wie in `process_one`", wird **nichts gelöscht**: die
Transaktion endet ohne `DELETE FROM content_references`, der
`ArtifactExpired` bleibt auf dem Stream, und der nächste Sweep fragt erneut.

**Zu entscheiden beim Bauen, und im Bericht zu begründen:** wie der Abbruch
zurückgegeben wird. `Ok(Vec::new())` ist bereits belegt — es heißt „die
Artefaktzeile existiert nicht" (`purge_gc.rs:620-625`) — und die beiden Fälle
dürfen nicht zusammenfallen, weil der Aufrufer sie verschieden zählen und
protokollieren muss. Einheit 265 hat für genau diese Form eine eigene
`BlobReclaim`-Variante bekommen; dasselbe Muster liegt nahe, ist aber nicht
vorgeschrieben.

**Die Prüfungen in `process_one` bleiben** als billige Vorab-Ausstiege — sie
sparen die Sperre im Normalfall. Aber **ihre Kommentare müssen aufhören,
Intervallkorrektheit zu behaupten**, die sie nicht liefern. Die Zusage gehört
an die Stelle, die sie einlöst. Eine falsche Zusicherung im Kommentar ist
derselbe Defekttyp wie eine falsche im Code, nur schlechter auffindbar.

## Akzeptanz

- Ein freigegebenes Artefakt wird Purge-Kandidat; **nach** der Seitenlesung
  und **vor** seinem destruktiven Schritt wechselt es auf `rejected`. Seine
  Kanten bleiben, seine Bytes bleiben, der `ArtifactExpired` bleibt.
  Derselbe Test für `scan_indeterminate`.
- Dasselbe für ein `KeepLastN`-Ziel, das im selben Fenster getaggt wird:
  nicht gelöscht, und zwar nach derselben Regel, die `process_one` anwendet
  (`tag_targeted && expired_only_by_keep_last_n && !user_deleted`).
- Ein Artefakt, das im Fenster **nichts** ändert, wird weiterhin normal
  gepurgt — die Prüfung darf nicht pauschal bremsen.
- **Mutationsnachweis:** die frische Lesung entfernen (nicht die Felder,
  nicht den Typ) macht genau diese Tests rot, mit der Aussage „Kanten
  gelöscht" bzw. „Bytes gelöscht", nicht mit einem Compilefehler.
- Kein Kommentar im Baum behauptet noch, `process_one` lese die Fakten neu.
- Gate grün: `cargo fmt --check`, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo test --workspace --no-fail-fast`, `cargo-audit
  audit --deny warnings`, `cargo deny check`.
