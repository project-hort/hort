# 271 — Artefakt-Ereignisse ohne Repository-Id umgehen die Sichtbarkeit

**Issue:** #338 · **Branch:** `agent/338-audit-block-2`
**Governing decisions:** ADR 0061 (Subscriptions/Zustellposition) · ADR 0021
(Live-Sichtbarkeit je Ressource) · ADR 0002 + #272 (kanonische Bytes der
Ereigniskette — siehe „Warum die Payload nicht erweitert wird").
Erste von vier Einheiten in Block 2 des Audits #332.

## Der Befund

`EventTypeKind::repository_id`
(`crates/hort-domain/src/entities/subscription.rs:467-519,547-553`) liefert
`None` für `ArtifactQuarantined`, `ScanRequested`, `ScanCompleted`,
`ArtifactBecameVulnerable`, `ArtifactReleased`, `ArtifactRejected`,
`ScanIndeterminate`, `ChecksumVerified`, die Provenance-Ereignisse, die
Promotion-/Approval-Kette, `ArtifactExpired` und `ArtifactPurged`. Nur
`ArtifactIngested`, `ChecksumMismatch` und `ArtifactDeleted` tragen eine Id.

Der Lesepfad (`crates/hort-http-events/src/handler.rs:159-194`) entscheidet
darauf mit

```rust
match EventTypeKind::repository_id(&e.event) {
    None => true,
    Some(repo_id) => evaluator.authorize(&principal, Permission::Read, Some(repo_id)),
}
```

Ein authentifiziertes Konto **ohne einen einzigen Read-Grant** bekommt damit
über `GET /api/v1/events?category=artifact` Stream-Identität, Actor und die
vollständige serialisierte Payload (`crates/hort-http-events/src/dto.rs:78-109`)
jedes Repositories: bei `ScanCompleted` Scanner, Schweregrad-Zählungen und den
Findings-Blob-Hash, bei `ArtifactReleased` Operator-Id und Freigabe-Begründung
(`crates/hort-domain/src/events/artifact_events.rs:325-355,509-522`).

Dieselbe Lücke erreicht die externe Zustellung: eine `OwnedByActor`-Subscription
entsteht ohne Read-Nachweis auf irgendein Repository
(`crates/hort-app/src/use_cases/subscription_use_case.rs:395-407`),
`subscription_filter::matches` lässt ein Ereignis ohne Repository-Id ohne
Live-RBAC durch (`subscription_filter.rs:104-125,165-212`), und
`subscription_task` reicht die volle Payload an den Notifier
(`crates/hort-app/src/dispatcher/subscription_task.rs:595-631`).

## Es ist eine Konvention, kein Flüchtigkeitsfehler

Beide Stellen begründen das `None` ausdrücklich im Kommentar: „an
artifact-stream event that lacks a direct repo column still belongs to the
artifact aggregate; the dispatcher applies the same convention." Die
Konvention ist also bewusst gesetzt und an zwei Stellen gespiegelt. **Sie ist
genau die halbe Wahrheit, die den Befund erzeugt:** das Ereignis gehört in der
Tat zum Artefakt-Aggregat — nur zieht niemand daraus das Repository. Die
Korrektur ersetzt die Konvention, sie flickt sie nicht.

Der eigene Baum enthält den Gegenbeweis: `ArtifactDeleted` denormalisiert
`repository_id` „precisely so an audit / subscription consumer never has to
resolve the projection row the deletion retired". Also **wird** die Auflösung
aus dem Aggregat überall sonst erwartet — die Löschung ist die eine Ausnahme,
weil es danach keine Projektionszeile mehr gibt.

## Die Symmetrie ist Teil des Auftrags

Dasselbe `None` lässt eine explizite `RepositoryScope::Some([erlaubtes_repo])`
diese Ereignisse **verwerfen**: ein korrekt eingeschränkter Abonnent verliert
still die Lifecycle-Benachrichtigungen, auf die er Anspruch hat. Ein fehlender
Wert, der gleichzeitig zu viel offenlegt und zu wenig zustellt.

**Beide Richtungen sind ein Fix und werden zusammen geschlossen.** Eine
Änderung, die nur die Offenlegung stopft (etwa `None => false`) und den
berechtigten Abonnenten weiter leer ausgehen lässt, ist nicht die Lösung — sie
tauscht einen stillen Fehler gegen den anderen.

## Warum die Payload nicht erweitert wird

Naheliegend wäre, `repository_id` in die neun Ereignistypen aufzunehmen. Das
ist **nicht** der Weg, aus zwei unabhängigen Gründen:

1. **Der Bestand bliebe offen.** Bereits gespeicherte Ereignisse bekämen kein
   Feld. Die Offenlegung gilt für alles, was heute im Store liegt — ein
   Zugriffsfix, der nur künftige Ereignisse erfasst, ist keiner.
2. **Die Ereigniskette.** #272 hält fest: ein nachträglich hinzugefügtes Feld
   verändert die kanonischen Bytes jedes vorher geschriebenen Ereignisses und
   wirft die Kettenprüfung auf `ChainBreak::HashMismatch`, sofern es nicht
   `skip_serializing_if` trägt. Das ist vermeidbare Nähe zu einem Defekt, den
   ein anderes Ticket gerade erst eingegrenzt hat.

Die Auflösung gehört auf die **Lese- und Filterseite**: das Repository wird aus
dem Aggregat des Ereignisses ermittelt. Damit wirkt der Fix auf den Bestand.

## Was Du entwerfen musst

**Ein gemeinsames Primitiv, nicht zwei Antworten.** Lesepfad und
Subscription-Filter sind heute zwei Aufrufstellen derselben falschen
Konvention. Die Auflösung muss beide bedienen; zwei getrennte Implementierungen
driften auseinander, und genau diese Drift ist das, was dieses Audit überall
findet.

**Der Lesepfad ist heiß, und das ist eine harte Randbedingung.** Der Kommentar
dort sagt es selbst („that would tank the read hot path"). Eine Auflösung je
Ereignis mit je einer Abfrage ist keine Lösung. Zwei Dinge dazu, aus früheren
Befunden dieses Projekts:

- Die `events`-Tabelle ist indiziert abfragbar; eine Sammelauflösung über die
  Seite, die der Handler ohnehin schon in der Hand hält, ist die naheliegende
  Form.
- **Kein `= ANY($1::array)` auf dem heißen Pfad.** Bei der sechsten Ausführung
  kippt der gepoolte Plan auf einen zeilenweisen Scan (gemessen: 64,2 s gegen
  1,7 s). Benutz einen Join/Anti-Join und pinne die Form.

Findest Du heraus, dass die Auflösung für eine Ereignisklasse **nicht** möglich
ist (etwa Promotion mit Quell- und Zielrepository), ist die richtige Antwort
nicht eine Sonderregel, sondern ein Bericht: schreib auf, welche Klasse, warum,
und welche Form Du vorschlägst. Fail-closed ist für eine nicht auflösbare
Klasse die sichere Richtung, aber ob sie richtig ist, entscheide ich nach
Deinem Bericht.

## Der Test, der das Falsche festhält

`crates/hort-app/src/use_cases/subscription_filter.rs:1297-1345` behauptet, ein
`ArtifactQuarantined` müsse einen Nicht-Admin **ohne Claims** erreichen. Dieser
Test wird **umbenannt und umgedreht, nicht gelöscht** — er beschreibt danach,
was gilt. (Das ist der dritte Fall in diesem Audit, in dem ein Test das
gefährliche Verhalten als Soll festhält; es gehört in den Bericht, wenn Dir ein
weiterer auffällt.)

## Ausdrücklich draußen

- **F17-2** — gepatchte Subscriptions bleiben in laufenden Tasks stale.
- **F17-3** — widerrufenes `User.is_admin` bleibt bis zum Respawn wirksam. Das
  ist ein erklärter Entscheidungskonflikt und wartet auf eine Entscheidung.
- **Keine Payload-Erweiterung, keine Migration.** `migrations/` darf in
  `git diff --name-only` nicht vorkommen. Geht es ohne Migration nicht, ist das
  ein STOP-and-report.
- Die Admin-Kategorien und das Typ-Gatter (`is_privileged_audit`,
  `is_authorization_model_mutation`) bleiben, wie sie sind — sie greifen vor
  dieser Stelle und sind nicht der Befund.

## Akzeptanz

- Ein Konto ohne Read-Grant bekommt über `GET /api/v1/events` kein Ereignis
  eines Repositories, auf das es keinen Anspruch hat — **auch kein bereits
  gespeichertes**, also ohne Payload-Änderung belegt.
- Ein Abonnent mit `RepositoryScope::Some([repo])` bekommt die
  Lifecycle-Ereignisse dieses Repositories, die er heute verliert.
- Beide Richtungen je durch einen Test belegt; `subscription_filter.rs:1297-1345`
  ist umgedreht statt gelöscht.
- Lesepfad und Filter teilen **ein** Auflösungs-Primitiv.
- Keine Abfrageform auf dem Lesepfad, die pro Ereignis eine Runde kostet, und
  kein `= ANY($1::array)`.
- Gate grün: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace --no-fail-fast`,
  `cargo-audit audit --deny warnings`, `cargo deny check`.
