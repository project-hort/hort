# 273 — Die `file:`-Ausgabe der Admin-CLI kann ein frisches Bearer offenlegen

**Issue:** #338 · **Branch:** `agent/338-audit-block-2`
**Governing decisions:** ADR 0038 (Bootstrap als kurzlebiger Break-Glass-Pfad)
· ADR 0012 (Service-Account-Token, Cap beim Mint eingefroren) ·
`docs/auth-catalog.md` (kanonische Spezifikation der Inbound-Authentisierung).
Dritte von vier Einheiten in Block 2 des Audits #332. Die Einheiten 271
(`07057a62`) und 272 (`69e78556`, plus meine Korrektur `8d95d7b0`) liegen auf
dem Branch, Gate grün — nicht ändern, nur ergänzen.

## Der Befund

`admin issue-svc-token` und `admin bootstrap-session` geben das Klartext-Token
an `write_plaintext` (`crates/hort-server/src/cli/admin.rs:664-665,989`). Der
dokumentierte Modus `file:<pfad>` verspricht eine 0600-Datei
(`:142-147,219-225,708-712`). Der Helfer schreibt aber so (`:717-727`):

```rust
fs::OpenOptions::new()
    .write(true).create(true).truncate(true).mode(0o600)
    .open(path)?
```

`OpenOptionsExt::mode` wirkt ausweislich der Rust-Dokumentation **nur beim
Neuanlegen**. Es gibt kein `create_new`, keine Rechteprüfung und kein
nachträgliches `chmod`. Daraus folgen drei Fälle:

1. **Bestehende Datei mit laxen Rechten.** Eine gruppen- oder weltlesbare
   Datei behält ihre Rechte; das Token landet darin. Der Operator hat die
   dokumentierte 0600-Ausgabe verlangt und etwas anderes bekommen.
2. **Bestehender Symlink.** `open` folgt ihm. Das Token landet dort, wohin er
   zeigt — ein Pfad, den der Operator nicht gewählt hat.
3. **Das Zeitfenster beim Neuanlegen** ist hier *nicht* das Problem:
   `create(true) + mode(0o600)` legt direkt mit 0600 an. Fall 3 ist, dass ein
   lokaler Nutzer die Datei **vorher** anlegen kann und damit Fall 1 oder 2
   selbst herstellt.

Die Ausstellungs-Gatter (DSN-Zugriff, `HORT_TOKEN_ALLOW_ADMIN`) schützen das
Prägen des Tokens, nicht diese Senke. Was hier ausläuft, ist ein
Full-Cap-Bootstrap-PAT oder ein Service-Account-Bearer.

## Die Lösung steht schon im Baum — übernimm sie, erfinde sie nicht neu

`crates/hort-cli/src/auth/login.rs:898-989` (`persist_token_to`) hat **genau
diesen Fehler schon einmal behoben**, und sein Docstring zählt dieselben drei
Fälle auf. Die Form dort:

- eindeutig benannte Temp-Datei **im selben Verzeichnis**, via
  `OpenOptions … create_new(true).mode(0o600)` — atomares Anlegen mit 0600
  ohne Umask-Fenster, und es **schlägt fehl**, wenn dort schon irgendetwas
  liegt (Datei oder Symlink);
- `sync_all()`, dann `std::fs::rename(temp, ziel)` — ein atomares Ersetzen auf
  demselben Dateisystem. Das Ziel erbt damit **nie** den Modus einer
  vorhandenen Datei, und ein Symlink am Ziel wird **ersetzt statt verfolgt**;
- Temp-Datei auf jedem Fehlerpfad best-effort entfernt.

**Zwei Unterschiede, die Du bewerten musst, statt die Vorlage blind zu
kopieren:**

1. `persist_token_to` macht `create_dir_all(parent)` und zieht den Elternordner
   auf `0o700`. Das ist für einen Pfad unter `$HOME` richtig und für einen
   **vom Operator gewählten** Pfad vermutlich falsch — `/etc/hort/` auf 0700
   zu ziehen, weil dort ein Token abgelegt wird, ist eine Nebenwirkung, die
   niemand bestellt hat. Entscheide und begründe.
2. Das Überschreiben muss **erhalten bleiben**. Ein Operator, der
   `issue-svc-token` mit demselben `file:`-Pfad erneut aufruft, erwartet, dass
   es funktioniert. Gesucht ist also nicht `create_new` **auf dem Ziel**,
   sondern das atomare Ersetzen des Ziels.

## Was Du zusätzlich prüfen sollst

- **Gibt es weitere Geheimnis-Senken dieser Form?** Such im Workspace nach
  Schreibpfaden, die ein Klartext-Credential in eine Datei legen (`fs::write`,
  `OpenOptions`, `File::create`), und sieh nach, ob sie dieselbe Lücke haben.
  Das Ergebnis gehört in den Bericht — **auch wenn es leer ist**.
- **Ein weltschreibbares Elternverzeichnis** (`/tmp`) lässt einen Angreifer den
  Temp-Namen vorbelegen. `create_new` scheitert dann, also ist das
  fail-closed — aber wiederholbar und damit ein Verweigerungs-Vektor.
  Berichten, nicht ungefragt eine Prüfung einbauen.

## Ausdrücklich draußen

- **F22-2** (CliSession-Widerruf implementiert, aber unerreichbar) und
  **F22-3** (ein Bootstrap-PAT kann ein längerlebiges Admin-PAT prägen) —
  beides eigene Befunde, F22-3 ausdrücklich ein Entscheidungskonflikt.
- Der `stdout`-Modus bleibt, wie er ist.
- Die Ausstellungs-Gatter (`HORT_TOKEN_ALLOW_ADMIN`, DSN) werden nicht
  angefasst.
- `migrations/` wird nicht angefasst.

## Akzeptanz

- Ein Geheimnis landet nie in einer Datei, deren Rechte oder Typ der Prozess
  nicht selbst gesetzt hat.
- Ein Symlink am Zielpfad wird **ersetzt, nicht verfolgt**.
- Das Überschreiben eines vorhandenen regulären Ziels funktioniert weiterhin,
  und das Ergebnis ist 0600 — unabhängig davon, welche Rechte vorher galten.
- Drei Tests gegen ein echtes Dateisystem: bestehende weltlesbare Datei,
  bestehender Symlink, nicht existierendes Ziel. Je die **Rechte der
  resultierenden Datei** prüfen, nicht nur den Inhalt — und im Symlink-Fall
  prüfen, dass das Linkziel **nicht** beschrieben wurde.
- Der Sweep nach weiteren Geheimnis-Senken steht im Bericht.
- Ein Weg, nicht zwei: die sichere Schreibform wird geteilt oder
  wiederverwendet, nicht ein zweites Mal geschrieben.
- Gate grün: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace --no-fail-fast`,
  `cargo-audit audit --deny warnings`, `cargo deny check`.
