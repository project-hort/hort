# 269 — Die drei übrigen Kantenschreiber in ihre Transaktion ziehen

**Issue:** #335 · **Branch:** `agent/335-gc-authority`
**Governing decisions:** E2 (Tom, 2026-10-06) — die Lücke verschwindet, sie
wird nicht überwacht. Kein Backfill, keine Bestandsreparatur. · ADR 0008 (die
Format-Crates reden nur über Use Cases, nie über Adapter).
Schließt **F19-2** vollständig; Einheit 268 hat den Ingest-Pfad gemacht.

## Warum es drei sind und nicht zwei

Einheit 268 zählte zwei OCI-Schreiber. Der Lauf dort hat beim Sweep einen
**dritten** gefunden, den meine Aufzählung übersehen hatte — der Aufruf ist
über zwei Zeilen verteilt (`.content_references` / `.insert(…)`) und fällt
durch eine zeilenweise Suche. Das ist die Lehre für diese Einheit: **suche
selbst, verlass Dich nicht auf diese Tabelle.**

| # | Stelle | Kante | Klammer heute |
|---|---|---|---|
| 1 | `ingest_use_case.rs::register_by_hash_inner` (`:4899`) | `primary_content` | blankes `commit_transition`, Kante danach, `warn!`-und-weiter |
| 2 | `hort-http-oci/src/manifests_write.rs::insert_subject_content_reference` (`:933`) | `oci_subject` | `ContentReferenceUseCase::insert_for_repo`, nach dem Ingest des Manifest-Artefakts |
| 3 | `task_handlers/oci_index_child_ingest.rs` (`:940`) | `oci_index_member` | eigener Insert nach dem Commit des Kindes |

Alle drei sind derselbe Befund: eine Zeile, die einen **Anspruch auf Bytes**
festhält, entsteht außerhalb der Transaktion, die die beanspruchenden Daten
leben lässt. Fehlt sie, sinkt die Zählung für den Zielhash, und ein
freigegebenes Geschwister treibt sie auf null.

`oci_subject` und `oci_index_member` sind dabei schärfer als
`primary_content`: sie beanspruchen **fremde** Bytes — die des Subjekts bzw.
der Index-Kinder. Fehlt so eine Kante, verliert ein Blob einen Anspruch,
während der Referrer weiterlebt und ihn nicht ersetzen kann.

## Reihenfolge und Erwartung

**Zuerst (1), es ist das kleinste.** Der Genesis-Commit dort ist ein blankes
`commit_transition`; auf `commit_transition_with_enqueues(&artifact, …, &[],
&edges)` umstellen. Der Mock protokolliert beide Methoden in
`committed_transitions()`, die bestehenden Zählungs-Assertions bleiben also
stehen. Der Test `..._is_warn_only` beschreibt danach das Gegenteil dessen,
was gilt — umbenennen und umdrehen, nicht löschen.

**Dann (2) und (3).** Die Frage ist dort dieselbe und sie ist echt: **ist die
Kante bekannt, bevor die Transaktion committet, die den Referrer leben
lässt?** Für `oci_subject` wird der Subject-Digest aus dem Manifest-Body
geparst, also vermutlich ja. Ist es so, reicht die Kante durch bis zum
Commit des Referrers. Ist es **nicht** so, ist die richtige Antwort nicht
eine Post-Commit-Kompensation, sondern ein Bericht: schreib auf, was im Weg
steht, und schlag die Form vor. Eine erfundene Kompensation wäre genau die
Sorte Halblösung, die dieses Audit überall gefunden hat.

**ADR 0008 bleibt unangetastet:** `hort-http-oci` importiert keine Adapter
und kein `sqlx`. Was dort gebraucht wird, geht über einen Use Case. Fällt Dir
nur eine Lösung ein, die diese Grenze verletzt, ist das ein STOP-and-report.

## Ausdrücklich draußen

- **Kein Backfill, keine Migration, keine Bestandsreparatur** (Toms
  Entscheidung, wörtlich).
- **`refcount_reconcile.rs` und `InProcessReconcileGate` unverändert** —
  `git diff` darf sie nicht nennen.
- **Die beiden Backfill-Handler** (`wheel_metadata_backfill`,
  `oci_membership_edge_backfill`) arbeiten auf Bestandsdaten — nicht
  anfassen.

## Akzeptanz

- Für jede der drei Kanten: schlägt der Insert fehl, schlägt die Operation
  fehl, und **weder** der Referrer **noch** seine Ereignisse bleiben zurück.
  Je ein Test mit injiziertem Fehler, der beides prüft — nicht nur das Fehlen
  der Kante.
- Der Erfolgsfall ist durch einen Pin belegt, der zeigt, dass **ein**
  Lifecycle-Aufruf Referrer und Kante trägt (wie
  `ingest_direct_commits_both_refcount_edges_with_the_transition` es für 268
  tut) — nicht zwei Aufrufe.
- Kein `warn!`-und-weiter-Pfad bleibt für diese drei Kanten übrig.
- Eine eigene Suche nach weiteren Schreibern ist gelaufen und ihr Ergebnis
  steht im Bericht — auch wenn es leer ist. Mehrzeilige Aufrufketten
  mitsuchen.
- Gate grün: `cargo fmt --check`, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo test --workspace --no-fail-fast`, `cargo-audit audit
  --deny warnings`, `cargo deny check`.

Danach ist #335 vollständig und der MR geht auf.
