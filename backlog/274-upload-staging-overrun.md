# 274 — Ein fehlgeschlagener PATCH lässt Staging über die Obergrenze wachsen

**Issue:** #338 · **Branch:** `agent/338-audit-block-2`
**Governing decisions:** ADR 0003 (CAS-Garantie beginnt beim finalen Ingest —
hier unberührt) · ADR 0042 (Upload-Session-Cap).
Vierte und letzte Einheit in Block 2 des Audits #332. Die Einheiten 271
(`07057a62`), 272 (`69e78556` + `8d95d7b0`) und 273 (`54755820`) liegen auf dem
Branch, Gate grün — nicht ändern, nur ergänzen.

## Der Befund, und er hat drei Pfade statt einem

`append_chunk_core` (`crates/hort-http-oci/src/upload_session.rs:~700-860`)
hängt die Bytes an die Staging-Datei an und schreibt den Record **erst
danach** per `compare_and_swap` fort. Zwischen beidem gibt es drei Ausgänge,
die die physische Datei vor `bytes_received` stehen lassen. Der Audit-Befund
nennt den ersten; ich habe die anderen beiden beim Lesen gefunden:

1. **Declared-length, Short Read.** `append` liefert
   `new_total != record.bytes_received + len` → `Invariant` (500). Kein
   Kürzen. Die Datei hält, was gelandet ist.
2. **Streaming, über der Grenze.** Der Lesevorgang ist auf
   `max_bytes + 1` begrenzt, danach `SizeExceeded`. Kein Kürzen. Die Datei
   steht bei bis zu `max_bytes + 1`.
3. **CAS-Miss durch einen nebenläufigen PATCH** — der schärfste. Beide
   PATCHes haben **schon angehängt**; nur einer bumpt den Record, der andere
   bekommt `Conflict`. Der Record sagt danach `r + len₁`, die Datei hält
   `r + len₁ + len₂`.

Danach rechnet jeder weitere gültige PATCH die Obergrenze gegen den
**veralteten, kleineren** Record-Offset, hängt an, sieht eine unerwartet große
physische Summe, liefert `Invariant` — und lässt die Datei abermals
vergrößert zurück. Wiederholung treibt eine einzelne `.part`-Datei beliebig
weit, ohne dass die konfigurierte Grenze im Record je fortschreitet. Ein
berechtigter Schreiber erreicht das mit zwei konkurrierenden PATCHes.

Der Test `uploads.rs:2645-2687` prüft nur die 400 auf einen synthetischen
CAS-Miss, nicht die Nebenwirkung im Staging. Die Digest-Prüfung beim
Finalisieren verhindert falsche Bytes, aber weder die Plattenfüllung noch die
Reparatur der Session.

## Die Wurzel steht im Docstring des Ports — und sie stimmt nicht

`StatefulUploadStagingPort::append`
(`crates/hort-domain/src/ports/stateful_upload_staging.rs:60-75`) beschreibt
seinen Nebenläufigkeitsvertrag so:

> Callers that require a strict ordering of chunks must serialise at a higher
> layer — the OCI use case does this by gating every `PATCH` on an
> optimistic-concurrency check against the upload session state … via
> `compare_and_swap`.

**Der Aufrufer tut das nicht.** Der `compare_and_swap` läuft *nach* dem
`append`, er gattert es also nicht. Der Port verlässt sich auf eine
Serialisierung, die der einzige Aufrufer nicht liefert, und genau diese Lücke
ist Pfad 3. Das ist die Stelle, an der die Korrektur ansetzen muss — nicht an
den drei Rückgabezweigen.

## Was Du entwerfen musst

**Such die richtige Stelle, nicht die nächstgelegene.** Mindestens zwei Formen
sind denkbar, und beide haben eine Falle:

- **Auf jedem Fehlerpfad auf `record.bytes_received` kürzen.** Klein und
  naheliegend — aber im nebenläufigen Fall kürzt der Verlierer unter Umständen
  Bytes weg, die der *Gewinner* gerade geschrieben hat. Eine Korrektur, die
  Pfad 1 und 2 schließt und Pfad 3 verschlimmert, ist keine.
- **Anhängen und Record-Fortschritt zu einer Einheit machen**, sodass die
  physische Länge nie Autorität über den Record erlangt — etwa, indem der
  Port an einer *erwarteten Position* schreibt statt blind anzuhängen, womit
  ein veralteter Schreiber nicht wachsen lässt, sondern abgewiesen wird oder
  idempotent dieselbe Stelle trifft. Das ändert den Port-Vertrag, und der
  Docstring oben muss dann ohnehin angefasst werden.

Entscheide mit Argument und schreib es in den Bericht. **Eine Flickstelle je
Fehlerzweig ist das Muster, das dieses Audit überall gefunden hat.**

Welche Form Du auch wählst, diese Eigenschaften müssen danach gelten:

- Nach **jedem** fehlgeschlagenen PATCH ist die physische Datei nicht größer,
  als der Record ausweist — oder ein nachfolgender gültiger PATCH kann sie
  jedenfalls nicht unbegrenzt wachsen lassen.
- Wiederholung treibt die `.part`-Datei **nicht** über `max_bytes`.
- Im nebenläufigen Fall verliert der Gewinner keine Bytes an den Verlierer.
- Der Docstring des Ports beschreibt danach, was wirklich gilt.

## Ausdrücklich draußen

- **F12-6** (Freigeben des letzten Quota-Mitglieds kann eine nebenläufige
  Admission löschen) — eigener Befund, nicht diese Einheit.
- Die Digest-Prüfung beim Finalisieren und ADR 0003 bleiben unberührt.
- `migrations/` wird nicht angefasst.

## Akzeptanz

- Je ein Test pro Pfad (Short Read, Over-Cap-Streaming, CAS-Miss), der die
  **physische Staging-Länge** nach dem Fehlschlag prüft — nicht nur den
  Statuscode. Das ist genau die Lücke im bestehenden Test.
- Ein Test, der die Wiederholung fährt: N fehlgeschlagene PATCHes lassen die
  Datei nicht über `max_bytes` wachsen.
- Ein Test für den nebenläufigen Fall, der zeigt, dass der Gewinner seine
  Bytes behält.
- Der Port-Docstring stimmt mit dem Verhalten überein.
- Die Wahl zwischen den Formen ist im Bericht begründet.
- CHANGELOG: `### Security` unter `[Unreleased]`.
- Gate grün: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace --no-fail-fast`,
  `cargo-audit audit --deny warnings`, `cargo deny check`.

Danach ist #338 vollständig; der Branch geht an Tom für den Compose-E2E und
der MR erst nach dessen Grün.
