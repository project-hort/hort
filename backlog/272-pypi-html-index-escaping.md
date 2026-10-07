# 272 — Die PyPI-HTML-Indexseite interpoliert Upstream-Text roh

**Issue:** #338 · **Branch:** `agent/338-audit-block-2`
**Governing decisions:** ADR 0031 (`IncludePending`-Indexmodus — akzeptiert und
unberührt; hier geht es um das Escaping eines aufgenommenen Eintrags) ·
ADR 0006 (Upstream-Checksummenprüfung — siehe „Die Typfrage").
Zweite von vier Einheiten in Block 2 des Audits #332. Einheit 271
(`07057a62`) liegt auf dem Branch, Gate grün — nicht anfassen, nur ergänzen.

## Der Befund

`PypiHtmlIndexBuilder::build` (`crates/hort-formats/src/pypi/index.rs:93-155`)
baut die PEP-503-Seite per Konkatenation. Von fünf dynamischen Werten läuft
**einer** durch `html_escape_attr` — eine Funktion, die zwölf Zeilen tiefer in
derselben Datei steht (`:161-167`).

Ein Upstream-Hash der Form

```
a"></a><a href="https://attacker.example/demo-99.0.tar.gz
```

schließt das `href`, schließt den Anker und öffnet einen zweiten. Ein
normkonformer Parser liest ihn als weiteren Download-Link: die
[Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/)
definiert Projektseiten-Anker als Datei-Links und erlaubt absolute URLs. Die
**Kandidatenmenge des Clients** ändert sich damit, und sie kann aus Horts
Artefakt- und Quarantänepfad herausführen. Die spätere verifizierte
Dateiauslieferung repariert den Index nicht, den der Client längst geparst hat.

## Die Bestandsaufnahme — ich habe sie nachgezählt, der Audit-Befund war unvollständig

| Wert | Kontext | Herkunft | Lage |
|---|---|---|---|
| `file.hash_sha256` | `href`-Attribut | **Upstream, unvalidiert** (`Option<String>`, `index_source.rs:547` übernimmt `f.sha256` wörtlich) | **roh — der Hauptvektor** |
| `file.filename` | `href`-Attribut **und** Ankertext | **Upstream, unvalidiert** (`index_source.rs:524-530`: `f.filename` oder der URL-Basename) | **roh — zweiter Vektor, zwei Stellen** |
| `ctx.package_name` | `<title>` und `<h1>` | Anfragepfad | roh |
| `ctx.base_url` | `href`-Attribut | Operator-Konfiguration | roh |
| `file.metadata_hash` | `data-dist-info-metadata`-Attribut | **auf beiden Pfaden zu `ContentHash` geparst** (`index_source.rs:535-538` und `:243-245`) | **sicher per Typ** |
| `file.requires_python` | `data-requires-python`-Attribut | Upstream | escaped |

Der Audit-Bericht nennt `hash_sha256`, `filename` und `package_name`. Er nennt
`metadata_hash` nicht — ich habe es geprüft: es wird auf **beiden** Pfaden
durch `hex.parse::<ContentHash>().ok()` geschickt, ein unparsbarer Wert fällt
auf `None` und der Builder lässt das Attribut weg. Es kann also nicht
injizieren. **Wenn Du zu einem anderen Ergebnis kommst, ist das ein Befund für
den Bericht** — ändere es nicht stillschweigend.

## Die Typfrage — und warum sie hierher gehört

Escaping schließt die Lücke. Aber `metadata_hash` steht im **selben Struct**
und zeigt die stärkere Form: ein Upstream-Hex wird bei der Projektion zu einem
`ContentHash` geparst, und was nicht parst, verschwindet. `hash_sha256` ist
daneben ein `Option<String>`, das verbatim bis in eine URL durchgereicht wird.
Das ist die eigentliche Wurzel, und das Vorbild steht eine Zeile weiter oben.

**Entscheide das nicht im Vorbeigehen, sondern beantworte es im Bericht.** Die
Abwägung, die ich sehe:

- Der `#sha256=`-Fragmentwert ist das, woran ein pip-Client die
  heruntergeladene Datei prüft. Fällt ein unparsbarer Hash auf `None`, liefert
  Hort den Link **ohne** Fragment aus — der Client verifiziert dann nicht mehr
  gegen diesen Wert.
- Dem steht gegenüber, dass Hort selbst auf dem Ingest-Pfad verifiziert
  (ADR 0006) und der Client von Hort lädt, nicht vom Upstream.
- `PypiVersionFileInfo.sha256` in der Projektion **muss** verbatim bleiben —
  der Docstring dort nennt es load-bearing für die Upstream-Prüfung über
  `parse_upstream_checksum`. Die Typfrage betrifft nur
  `PypiVersionFile.hash_sha256`, das indexbauende Struct, nicht das
  projizierende.

Mein Rat: beides. Escaping ist die Korrektur, die **jeden** interpolierten Wert
abdeckt und sofort gilt; die Typverengung ist die, die diesen einen Wert
strukturell unerreichbar macht. Kommst Du zu dem Schluss, dass die Typverengung
das Client-Verhalten unvertretbar ändert, schreib das auf und lass sie weg —
mit Begründung, nicht als Auslassung.

## Kontext ist nicht gleich Kontext

`html_escape_attr` ersetzt `&`, `<`, `>`, `"`, `'`. Für einen **Textknoten**
ist das eine sichere Obermenge (`&quot;` rendert als `"`), also funktioniert es
auch für den Ankertext. Aber eine Funktion mit `_attr` im Namen, die im
Textkontext benutzt wird, ist genau die Sorte stiller Annahme, die beim
nächsten Mal falsch gelesen wird: entweder gibst Du ihr einen kontextneutralen
Namen, oder Du stellst eine Textvariante daneben. Eine der beiden, mit einem
Satz Begründung.

**Zweite Frage, getrennt davon: das `href` ist eine URL, nicht nur ein
Attribut.** HTML-Escaping macht das Attribut parsbar; es macht aus einem
Dateinamen mit `#` oder `?` keinen korrekten Pfadbestandteil. Ein
Upstream-Dateiname kann beides enthalten. Prüf, ob die Pfadsegmente
URL-kodiert gehören, und **berichte das Ergebnis** — ändere die URL-Form nicht
stillschweigend, das ist eine beobachtbare Änderung für jeden Client.

## Das Maß liegt im eigenen Baum

Jede Nachbarausgabe benutzt einen formgerechten Serialisierer: npm
`serde_json::to_vec` (`crates/hort-formats/src/npm/index.rs:535-540`), Cargo
`serde_json::to_string` (`cargo/index.rs:248-253`), PyPI PEP 691
`serde_json::to_vec` (`pypi/index.rs:281`), Maven `xml_escape_text`
(`maven/metadata.rs:380-402`). Nur der HTML-Zweig baut per Konkatenation. Kein
zweiter Mechanismus: benutz das vorhandene Werkzeug oder ergänze es, baue keine
Parallelimplementierung.

## Ausdrücklich draußen

- **F14-7** (Maven-SNAPSHOT-Sidecars umgehen die Auflösung der Datei) — anderer
  Befund, nicht diese Einheit.
- **Der Indexmodus** (ADR 0031, `IncludePending`) bleibt unberührt.
- **`migrations/`** wird nicht angefasst.
- Die PEP-691-JSON-Ausgabe ist über `serde_json` bereits korrekt und braucht
  keine Änderung.

## Akzeptanz

- Jeder dynamische Wert in der HTML-Ausgabe ist kontextgerecht behandelt:
  `package_name`, `filename` (Attribut **und** Text), `hash_sha256`,
  `base_url`, `requires_python`.
- Je ein Test pro interpoliertem Wert mit einem Anführungszeichen- **und**
  einem Tag-Grenzfall, der zeigt, dass die Seite danach **genau einen** Anker
  pro Datei enthält. Zähl die Anker, prüf nicht nur auf das Fehlen eines
  Teilstrings.
- Ein Test, der den Hauptvektor in seiner realistischen Form fährt: ein
  Upstream-Hash, der einen zweiten `<a href="https://…">` einzuschleusen
  versucht.
- Die Namensfrage (`_attr` im Textkontext) ist entschieden und begründet.
- Die Typfrage zu `hash_sha256` ist im Bericht beantwortet — umgesetzt oder
  mit Begründung verworfen.
- Die URL-Kodierungsfrage ist im Bericht beantwortet, nicht stillschweigend
  umgesetzt.
- Gate grün: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace --no-fail-fast`,
  `cargo-audit audit --deny warnings`, `cargo deny check`.
