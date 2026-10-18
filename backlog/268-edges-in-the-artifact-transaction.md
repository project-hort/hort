# 268 — Die Kante entsteht in derselben Transaktion wie das Artefakt

**Issue:** #335 · **Branch:** `agent/335-gc-authority`
**Governing decisions:** E2 (Tom, Matrix, 2026-10-06): *„Ja, wir schließen
diese Lücke durch Transaktion. Fehlende Kanten im Bestand interessieren mich
nicht. Wir bauen keine Extra-Lösungen für pre-1.0 Daten."* · ADR 0001 /
ADR 0008 (die Komposition bleibt hinter der Portgrenze).
Schließt **F19-2** für den Ingest-Pfad.

## Warum

Die GC löscht einen Blob, wenn keine `content_references`-Zeile auf seinen
Hash zeigt. Eine fehlende Zeile ist deshalb kein harmloser Ausfall, sondern
ein Anspruch, den die GC nicht sieht — und der Blob wird **früher** löschbar,
nicht später.

Der Ingest committet heute erst das Artefakt und schreibt die Kante danach,
in einem Schritt, der scheitern darf, ohne den Ingest scheitern zu lassen
(`ingest_use_case.rs::write_ingest_refcounts`). **Der Kommentar dort begründet
das mit einer Aussage, die verkehrt herum steht:**

> Insert failure is recoverable: the refcount row is eventual; an operator-side
> reconcile sweep catches any divergence. We do NOT abort the ingest on
> refcount-insert failure — the artifact is already alive and downloadable, and
> **a missing refcount row only delays GC, it doesn't break correctness.**

Eine fehlende Zeile verzögert die GC nicht. Sie senkt die Zählung für diesen
Hash, und ein freigegebenes Geschwister mit denselben Bytes treibt sie auf
null. Der Kommentar stützt sich danach auf den Reconcile — dessen beide
Ausfallarten genau F19-1 (geschützte Evidenz wird absichtlich übersprungen)
und F19-2 (das Boot-Urteil ist für die Worker-Lebenszeit eingefroren) sind.
**Diesen Kommentar mitkorrigieren ist Teil der Einheit**, nicht Beiwerk: er
ist der Grund, warum die Stelle so aussieht, wie sie aussieht.

## Die Klammer gibt es schon

`commit_transition_with_enqueues`
(`crates/hort-adapters-postgres/src/artifact_lifecycle.rs:218-289`) öffnet
eine Unit of Work und schreibt darin **vier** Dinge atomar: die Ereignisse
(`append_in_tx`), die Artefaktzeile (`save_in_tx`), die Metadaten
(`upsert_in_tx`) und die Job-Queue-Zeilen — letztere als rohe Statements über
`uow.conn()`. Dann `uow.commit()`, das Ganze in einer Contention-Retry-Schleife.

`begin_unit_of_work`, `append_in_tx` und `save_in_tx` sind **`pub(crate)`
innerhalb des Adapters**. Es sind keine Port-Methoden. Die Komposition liegt
also bereits vollständig hinter der Portgrenze — es ist **keine**
Architekturfrage und **kein** Leck von Persistenzsemantik in `hort-app`. Die
Kante steht lediglich außerhalb einer Klammer, die es schon gibt.

## Was zu tun ist

Die Kanten des Ingest-Pfades wandern in dieselbe Unit of Work:

| Kante | Heute geschrieben in |
|---|---|
| `primary_content` | `ingest_use_case.rs::write_ingest_refcounts` |
| `metadata_blob` | dieselbe Funktion |
| `wheel_metadata` | `ingest_use_case.rs::extract_and_link_wheel_metadata` (ab `:3069`) |

Wie die Kantendaten in den Adapter kommen, entscheidest Du — der naheliegende
Weg ist ein zusätzlicher Parameter an `commit_transition_with_enqueues`, in
der Form, die `metadata: Option<ArtifactMetadata>` dort schon hat. Der
Fremdschlüssel `content_references_source_artifact_id_fkey` verlangt die
Artefaktzeile zuerst; die Unit of Work hat diese Reihenfolge ohnehin.

**Scheitert die Kante, scheitert der Ingest.** Das ist der Punkt der Einheit:
ein committetes Artefakt ohne Kante darf nicht mehr entstehen können. Der
`warn!`-und-weiter-Pfad entfällt für diese drei Kanten.

**Das `wheel_metadata` kann nachgelagert sein.** Prüfe, ob die Extraktion vor
dem Commit abgeschlossen ist. Ist sie es nicht, ist die ehrliche Antwort nicht
„dann eben wieder danach", sondern: die Kante gehört in die Transaktion, in
der sie entsteht — notfalls in einen zweiten, eigenen `commit_transition`.
Schreib im Bericht, was Du vorgefunden hast.

## Ausdrücklich NICHT in dieser Einheit

- **Kein Backfill, keine Migration, keine Reparatur für Bestandsdaten.** Toms
  Entscheidung ist hier wörtlich zu nehmen.
- **Der Reconcile bleibt unverändert** und ebenso das
  `InProcessReconcileGate`. Beide sind für den Altbestand weiterhin das, was
  sie sind; sie zu entfernen wäre eine Extralösung in die andere Richtung.
- **Die beiden Backfill-Handler** (`wheel_metadata_backfill`,
  `oci_membership_edge_backfill`) arbeiten auf Bestandsdaten — nicht anfassen.
- **Die zwei OCI-Schreiber** (`hort-http-oci/src/manifests_write.rs`, Kante
  `oci_subject`; `task_handlers/oci_index_child_ingest.rs:940`, Kante
  `oci_index_member`) schreiben ebenfalls neben der Transaktion her und
  gehören in **Einheit 269**. Sie liegen in anderen Crates und haben eine
  andere Klammer; sie hier mitzunehmen würde die Einheit unüberprüfbar machen.
  **Nicht vergessen** — ohne sie bleibt die Tür dreifach offen.

## Akzeptanz

- Schlägt der Kanten-Insert fehl, schlägt der Ingest fehl: kein Artefakt, kein
  Ereignis, keine Zeile. Test mit injiziertem Insert-Fehler, der prüft, dass
  **nichts** von beidem persistiert ist.
- Der Erfolgsfall schreibt Artefakt, Ereignisse und Kante in **einer**
  Transaktion — nachgewiesen dadurch, dass ein Rollback mittendrin beides
  zurücknimmt, nicht dadurch, dass am Ende beides da ist.
- `wheel_metadata` wird gleich behandelt oder der Bericht begründet, warum es
  eine eigene Transaktion braucht.
- Der falsche Kommentar ist korrigiert; keine Stelle im Baum behauptet noch,
  eine fehlende Refcount-Zeile verzögere die GC.
- Reconcile und Gate sind unverändert (`git diff` nennt sie nicht).
- Gate grün: `cargo fmt --check`, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo test --workspace --no-fail-fast`, `cargo-audit audit
  --deny warnings`, `cargo deny check`.
