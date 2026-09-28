# 252 — the 200-event cap is enforced, except by the retention expiry

**Issue:** #324 · **Branch:** `agent/324-stream-cap-bypass`

## Der Befund, korrigiert am Baum

Meine urspruengliche Fassung sagte, die 200 seien „unbelegt und plausibel zu klein". Das ist nicht der Kern. **Die 200 sind eine durchgesetzte Obergrenze — und genau ein Schreiber umgeht sie.**

### Die Grenze ist real und fail-closed

`use_cases::read_expected_version` liest `STREAM_EVENT_CAP + 1` — das `+1` ist die Ueberlauferkennung — und lehnt ab, sobald ein Strom die Grenze reisst:

```
"stream {stream_id} exceeds {STREAM_EVENT_CAP}-event cap"  → DomainError::Conflict
```

Solange jeder Append seine Version darueber ableitet, **kann** ein Artefaktstrom 200 Ereignisse nicht ueberschreiten. Der Kommentar an der Stelle sagt das auch: ein gekappter Vorwaertsscan ist „correct ONLY for a stream that is bounded by design".

### Der Bypass

`RetentionUseCase::append_expired` haengt mit `ExpectedVersion::Any` an (`crates/hort-app/src/use_cases/retention_use_case.rs:666`). Der Adapter behandelt das als **gar keine Pruefung** (`crates/hort-adapters-postgres/src/event_store.rs:1009`: `ExpectedVersion::Any => {}`). Die Ablauf-Ereignisse der Retention sind damit die einzigen, die einen Artefaktstrom ueber die Grenze schieben koennen.

Besonders sprechend: `append_expired` bekommt die Stromlaenge als Parameter **`_stream_len: u64`** herein und wirft sie weg. Die Information, um zu verweigern, liegt bereits an der Aufrufstelle.

### Was passiert, sobald ein Strom die Grenze reisst

Alle gekappten `ReadFrom::Start`-Leser liefern dann die **aeltesten** 200 Ereignisse und drehen sie um. „Neuester Scan" ist damit der neueste **innerhalb der ersten 200**, nicht der neueste ueberhaupt:

| Stelle | Rolle |
|---|---|
| `quarantine_use_case.rs:1409` | **Release-Autorisierung** — sucht den letzten `ScanCompleted` und prueft den Suffix danach auf `ArtifactRejected`. Bei Trunkierung ist beides falsch. |
| `retention_use_case.rs:374` | die Auswertung selbst — ein vorhandenes `ArtifactExpired` jenseits von 199 ist unsichtbar, und da mit `Any` angehaengt wird, kommt taeglich ein weiteres dazu |
| `scan_history.rs:76, 114` | Scan-Historie |
| `eventstore_retention_use_case.rs:477` | Terminal-Nachweis |

**Die Release-Autorisierung ist die folgenschwerste**: sie laeuft immer, nicht nur wenn Retention eingeschaltet ist.

### Das fehlende Primitiv

`ReadFrom` kennt nur `Start` und `After(u64)` (`crates/hort-domain/src/ports/event_store.rs:93-98`). „Die letzten N Ereignisse" ist ueber den Port **nicht ausdrueckbar**. Deshalb liest jeder dieser Aufrufer vorne und dreht um — und deshalb kann keiner Trunkierung von Vollstaendigkeit unterscheiden.

Die einzige Stelle, die es richtig macht, tut es mit `CAP + 1` und einem harten Fehler bei Ueberlauf. Das Idiom existiert also bereits im Baum und ist an vier Stellen nicht angewandt.

## Was zu tun ist

Der Zuschnitt ist **eine** Einheit, weil es eine fehlende Grundlage ist und nicht vier Einzelfehler:

1. **Den Bypass schliessen.** Der Ablauf-Append muss die Grenze respektieren, die alle anderen respektieren — die Laenge liegt schon als `_stream_len` vor. Damit gilt die Invariante „ein Artefaktstrom ueberschreitet 200 nie" wieder ausnahmslos.
2. **Die gekappten Leser ehrlich machen.** Ein gekappter Lesevorgang muss sagen koennen, ob er trunkiert hat — das `CAP + 1`-Idiom, an allen vier Stellen. Ein Leser, der stillschweigend den aeltesten Praefix fuer den ganzen Strom haelt, ist der Defekt; eine groessere Zahl verschiebt ihn nur.

Ob zusaetzlich ein Tail-Lesen (`ReadFrom::End`/`Last(n)`) in den Port gehoert, ist beim Umsetzen mit Argument zu entscheiden — es waere das saubere Primitiv, kostet aber eine Portaenderung mit mehreren Implementierungen.

**Was ein voller Strom heute bedeutet, ist ebenfalls zu beantworten:** ein Artefakt an der Grenze nimmt keine weiteren Ereignisse mehr an — kein Scan, kein Ablauf. Das ist fail-closed und insofern richtig, aber es ist ein eingefrorenes Artefakt, und ob das erkennbar ist, gehoert geprueft.

## Akzeptanz

- Kein Schreibpfad kann einen Artefaktstrom ueber `STREAM_EVENT_CAP` schieben; ein Test deckt den Retention-Ablauf-Append ab.
- Jeder der vier gekappten Leser erkennt Trunkierung und behandelt sie als Fehler statt als vollstaendigen Strom.
- Ein Test, der einen Strom jenseits der Grenze aufbaut und zeigt, dass die Release-Autorisierung nicht auf einem veralteten Scan entscheidet.
- Der Kommentar an `STREAM_READ_LIMIT` beschreibt, was die Zahl ist — eine durchgesetzte Grenze, nicht eine Schaetzung „far beyond any real stream".
- Gate gruen.

## Governing decisions

ADR 0007 (fail-closed Release-Praedikat — das Praedikat, das die Trunkierung faelschen kann) · ADR 0002 (Ereignisse und Projektion in einer Transaktion) · `backlog/056-expected-version-capped-read-audit.md` (das Audit, aus dem die Grenze stammt)
