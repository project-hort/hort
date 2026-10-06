# 270 — Die letzten drei Kantenschreiber: Manifest-PUT und Pull-Through

**Issue:** #335 · **Branch:** `agent/335-gc-authority`
**Governing decisions:** E2 (Tom, 2026-10-06) — die Lücke verschwindet durch
Transaktion; kein Backfill, keine Bestandsreparatur. · ADR 0008 (Format-Crates
reden nur über Use Cases) · ADR 0043 (Index-Kinder werden beim PUT in-repo
geprüft, `MANIFEST_BLOB_UNKNOWN` bei Fehlen) · ADR 0007 (Nullfenster-Anker für
Referenced-Tree-Descendants).
Schließt **F19-2** endgültig. Einheiten 268 und 269 haben den Ingest-Pfad, den
`register_by_hash`-Pfad, das `oci_subject`-Edge des Manifest-PUTs und den
eager Child-Ingest erledigt.

## Warum es eine vierte Einheit gibt

Meine Aufzählung in 268 nannte zwei Schreiber, die in 269 drei. Der Sweep in
269 hat **sieben** Produktionsstellen dieser Form gefunden. Vier sind erledigt,
zwei hat derselbe Lauf mit erklärter Begründung mitgenommen
(`ingest_signature_manifest`, `commit_referrer_manifest`). Drei stehen aus —
und sie sind der Rest derselben Lücke, nicht eine neue Sorte Arbeit.

| # | Stelle | Kanten |
|---|---|---|
| A1 | `manifests_write.rs::insert_blob_content_references` | `oci_config`, `oci_layer` |
| A2 | `manifests_write.rs::insert_index_member_content_references` | `oci_index_member` |
| B | `manifests.rs`, zwei Leader-Beine (`:963`, `:1309`) über `register_membership_edges_from_pull` | dieselben drei Arten |
| C | `manifests.rs::register_follower_membership_edges` (`:1705`) | dieselben drei Arten |

Alle schreiben eine Zeile, die einen **Anspruch auf Bytes** festhält,
außerhalb der Transaktion, die den Referrer leben lässt. Für eine Baum-Kante
repariert das nichts nachträglich: der Refcount-Reconcile-Sweep leitet
`primary_content` und `metadata_blob` aus der Artefakt-Zeile ab und mintet
keine Baum-Kante, weil keine relationale Zeile festhält, was ein Manifest
referenziert.

## A — Der Manifest-PUT (A1 + A2)

**Der Bericht zu 269 nennt das „entscheidungsbedürftig“. Es ist es nicht, und
das ist der wichtigste Satz dieser Einheit.** Er stellte zwei Optionen
gegenüber: Kanten vor dem Blob-Existenz-Gate beanspruchen (dann kann eine
Kante einen Blob nennen, den das Repository nicht hält) oder das Gate vor den
Mint ziehen (dann kippen zwei absichtlich gesetzte Pins). Es gibt eine dritte
Form, die beides vermeidet.

`resolve_and_check_referenced_blobs` ist ein **Lesevorgang**
(`resolve_referenced_blobs` → `artifacts`), und sowohl sie als auch
`parse_referenced_blobs` benutzen `manifest_artifact.id` **nur als Log-Feld**.
Beide sind damit vor den Mint ziehbar. Die Form:

1. `parse_referenced_blobs` + `resolve_referenced_blobs` laufen **vor**
   `run_manifest_ingest`. Das Log-Feld wird der berechnete Digest
   (`hashes.computed_hash`), der dort schon bekannt ist.
2. Ist `missing` **leer**: die `oci_config`/`oci_layer`/`oci_index_member`-
   Claims werden **aus der aufgelösten Menge** gebaut und zusammen mit dem
   bestehenden `subject_claim` an `run_manifest_ingest` gegeben. Sie reiten
   die Transition. Keine Kante kann je einen Blob nennen, den das Repository
   nicht hält — die Carve-out-Sorge aus dem 269-Bericht entfällt, sie wird
   nicht abgewogen.
3. Ist `missing` **nicht leer**: das Manifest wird **ohne**
   Mitgliedschafts-Claims gemintet und dieselbe 400 `MANIFEST_BLOB_UNKNOWN`
   zurückgegeben wie heute, und die Gruppe wird wie heute nicht angelegt.
   Beobachtbares Verhalten unverändert, beide Pins
   (`put_with_missing_blob_returns_400_manifest_blob_unknown`,
   `put_image_index_with_missing_child_returns_400_manifest_blob_unknown`)
   bleiben grün, **kein Posture-Wechsel**.

Heute schreibt der Fehlerpfad ohnehin **gar keine** Kante (das Gate kehrt vor
`insert_blob_content_references` zurück), auch bei teilweise vorhandenen
Blobs. Punkt 3 ist also nicht schlechter als der Status quo, und Punkt 2 ist
echt besser.

**Eine Sache, die Du prüfen und berichten musst, bevor Du sie änderst:**
`parse_referenced_blobs` schlägt bei einem *strukturell* ungültigen (aber
JSON-gültigen) Body mit 400 `ManifestInvalid` fehl, und das Artefakt bleibt
heute committed — der Docstring sagt das ausdrücklich. Vor den Mint gezogen
gäbe es dieses Artefakt nicht mehr. Zähl **jede** beobachtbare Änderung auf
den Fehlerpfaden auf und schreib sie in den Bericht. Muss dafür ein Pin
kippen: **STOP and report**, nicht kippen.

Die Gruppenanbindung (`add_member`) bleibt, wo sie ist — sie ist kein Anspruch
auf Bytes.

## B + C — Der Pull-Through-Pfad

Drei Aufrufstellen von `register_membership_edges_from_pull`. Strukturell, nicht
entscheidungsbedürftig:

- **B (zwei Leader-Beine, `manifests.rs:963` und `:1309`).** Der Body wird
  heute per `tokio::fs::read(&cache_handle.path)` **nach** dem Ingest gelesen,
  während der Ingest selbst aus derselben Tempdatei streamt. Lies ihn
  **vorher** einmal in den Speicher — genau wie `oci_index_child_ingest` es
  seit 269 tut, mit derselben Begründung (gedeckelt durch den
  `manifest_cache_max_bytes`-Cap des Upstream-Adapters, und der Body wird
  ohnehin geparst) —, leite die Claims daraus ab und gib sie an
  `ingest_verified`. `Cursor` statt `File` als `AsyncRead`. Die beiden anderen
  Verbraucher derselben Bytes (`enqueue_declared_children`, der
  Prefetch-/Warm-Trigger) bleiben, wo sie sind, und lesen dieselbe Kopie.
- **C (der koaleszierte Follower, `register_follower_membership_edges`).** Er
  ingestet nicht, er mintet über `register_by_hash`; die Bytes liegen schon in
  CAS. Zieh die `read_content_for_projection`-Lesung **vor** den
  `register_by_hash`-Aufruf und gib die Claims auf dem `IngestRequest` mit
  (`claimed_edges`, seit 269 vorhanden).

**Hier wird keine Existenzprüfung eingebaut.** Der Pull-Through registriert
heute bewusst **nur nach Digest**: das ist der Mechanismus, durch den ein
Proxy-Descendant beim späteren eigenen Einzug den Nullfenster-Anker bekommt
(ADR 0007, `referenced_descendant.rs`). Diese Einheit ändert ausschließlich die
**Atomarität**, nicht die Frage, wann eine Kante geschrieben wird.

**Fehlerposture, einheitlich mit 269:** ein *Ableitungs-/Parse*-Fehler bleibt
`warn!`-und-weiter — das Artefakt wird ohne Mitgliedschaftskanten gemintet, die
Bytes passen zu ihrem Digest und das Manifest ist legitim auslieferbar
(Vorbild: `oci_index_child_ingest::derive_claims`). Ein *Insert*-Fehler lässt
die Operation fehlschlagen; ein Client-Retry des GET ist wiederholbar, ein
committetes Manifest ohne Anspruch nicht reparierbar.

## Ausdrücklich draußen

- **Kein Backfill, keine Migration, keine Bestandsreparatur** (Toms
  Entscheidung, wörtlich). `refcount_reconcile.rs` und
  `InProcessReconcileGate` dürfen in `git diff --name-only` nicht vorkommen.
- **Die beiden Backfill-Handler** (`wheel_metadata_backfill`,
  `oci_membership_edge_backfill`) — nicht anfassen.
- **Kein Blob-Warming.** Ob der Handler-Pfad die Blobs seiner Kinder holt, ist
  eine andere, offene Frage; diese Einheit fasst `warm_manifest_blobs` /
  `fire_prefetch_trigger_oci` / `enqueue_declared_children` nicht an.
- **ADR 0008 bleibt unangetastet:** `hort-http-oci` importiert keinen Adapter
  und kein `sqlx`. Fällt Dir nur eine Lösung ein, die das verletzt, ist das ein
  STOP-and-report.

## Akzeptanz

- Für jede der drei Stellen: schlägt der Kanten-Insert fehl, schlägt die
  Operation fehl, und **weder** der Referrer **noch** seine Ereignisse bleiben
  zurück. Je ein Test mit injiziertem Fehler, der beides prüft.
- Je ein Erfolgs-Pin, der zeigt, dass **ein** Lifecycle-Aufruf Referrer und
  Kantenmenge trägt — nicht zwei Aufrufe.
- Die beiden Unknown-Blob-Pins sind unverändert und grün. Jede beobachtbare
  Änderung auf einem Fehlerpfad steht im Bericht.
- Kein `warn!`-und-weiter-Pfad bleibt für einen *Insert* dieser Kanten übrig;
  `register_membership_edges_from_pull` ist verschwunden oder hat keinen
  Produktionsaufrufer mehr.
- Eine eigene Suche nach weiteren Schreibern ist erneut gelaufen und ihr
  Ergebnis steht im Bericht — auch wenn es leer ist. Mehrzeilige Aufrufketten
  mitsuchen.
- Gate grün: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace --no-fail-fast`,
  `cargo-audit audit --deny warnings`, `cargo deny check`.

Danach ist #335 vollständig und der MR geht auf.
