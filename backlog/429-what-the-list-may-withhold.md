# 429 — what the referrers list may withhold, and on whose authority

**Issue:** #456 · **Branch:** `agent/456-referrers-spec-conformance` · Item 3 of 3.

## Problem

S5-2 reads *"Read-only callers receive held and rejected OCI referrer
resolution descriptors."* It carries the judgement **teilweise** in #383, and
the reason is in the file: `referrers.rs` already documents a deliberate
policy, in its module header at `:45-60`:

> A row whose referrer is merely **quarantined** stays listed: a hold is "not
> yet", and the per-leaf `503` is that answer. A row whose referrer is not
> ingested at all stays listed too — absence is the ordinary state of a cold
> pull-through, not a verdict.
>
> **The omission does not move the diagnosis.** Asked for the same manifest
> directly, `GET /v2/<name>/manifests/<digest>` still answers `403 DENIED`
> naming the subject and its rejection axis (ADR 0055): the list omits, the
> direct ask explains.

There is also a closure half — `ListDeliverabilityUseCase::non_deliverable_in`,
asked once per request for every surviving row (`:360`).

**So this item is not "add the missing omission".** The policy exists, it is
argued, and it is anchored in ADR 0055. The item is to determine **what part of
S5-2 still stands beside it** — and that is a reading task with three possible
outcomes, not a change with a known shape.

## What this item does

Decide, and record, exactly one of:

1. **Nothing stands.** The policy answers the finding in full, and S5-2 is a
   finding against a state the file had already left. Then the outcome is a
   recorded acceptance on #383 naming ADR 0055 and this item — not silence.
   #383's own Abgrenzung allows exactly two exits, and this is one of them.
2. **Part stands.** Name which caller, which status, and which descriptor field
   leaks something the policy did not intend to disclose, and fix that part
   only. A `rejected` referrer is the candidate worth the closest look: the
   module header argues the case for `quarantined` ("a hold is 'not yet'") and
   for absent ("the ordinary state of a cold pull-through"), and those two
   arguments do not obviously carry over to a terminal rejection.
3. **The policy itself is wrong.** Then it is an ADR 0055 question and a
   decision issue, not an implementation — stop and say so.

Outcome 1 is a legitimate result. An item that must produce a code change in
order to count is an item that will produce one whether or not it is warranted.

## Read first

- `crates/hort-http-oci/src/referrers.rs:45-60` (the policy), `:299-300`
  (`find_visible_by_id`), `:360` (the deliverability census).
- `docs/adr/0055-*.md` — the decision the policy leans on. Read the Decision,
  not only its guarantee.
- `#383`'s S5-2 row and the audit's original wording, to establish what the
  finding actually claimed rather than what the summary line compresses it to.

## Acceptance

- One of the three outcomes above is recorded, with the reasoning, on #456 and
  abgehakt on #383 with this item named.
- If outcome 2: a test that shows the leak before the fix, and the module
  header extended to say what it now withholds and why — the policy paragraph
  is the place a future reader will look.
- If outcome 1 or 3: no code change, and the report says so plainly. Do not
  manufacture a change to have something to show.

---

## Nachtrag nach dem Peer-Review — Ergebnis 1 ist ausgeschlossen, und es liegt ein Spec/ADR-Konflikt darunter

Der Review hat meine Vermutung **umgedreht**, und das ist der wichtigste Punkt der ganzen Runde.

Ich hatte geschrieben, die terminale Ablehnung sei der Kandidat, der neben der Politik noch stehe. Tatsächlich werden **terminale Quellen schon heute ausgelassen** — `artifact.quarantine_status.is_terminal()` (`referrers.rs:322-336`) plus die gebündelte Deliverability-Zählung, und ADR 0062 ordnet diese Auslassung ausdrücklich an. Meine Vermutung lag genau falsch herum.

Was neben der Politik steht, ist das andere Ende: eine **gehaltene** Quelle bleibt gelistet, und zwar für jeden Aufrufer mit bloßem `Read` — während ADR 0055 digest-tragende Auflösungs-Metadaten eines Holds den berechtigten Schreibern vorbehält. Das ist die offene Frage, nicht die terminale.

### Und darunter liegt ein Konflikt, den keine Einheit entscheiden darf

Die Spezifikation sagt im Abschnitt *Enabling the Referrers API*, Punkt 3 — von mir im Wortlaut nachgelesen:

> After the referrers API is enabled, Registries **MUST include all newly pushed image manifests** with a valid `subject` field in the referrers API response.

Ein gepushtes Manifest, das später abgelehnt wurde, war ein neu gepushtes mit gültigem `subject`. Die von ADR 0062 angeordnete terminale Auslassung steht damit gegen ein `MUST` der Spec — und nach der Autoritätsordnung dieses Projekts schlägt die Spec die Implementierung, ein ADR also auch.

**Das ist eine Produktentscheidung und keine Lesearbeit:** Konformität gegen die Nichtoffenlegung terminal abgelehnter Inhalte. Beide Seiten haben ein Dokument hinter sich (die Spec hier, ADR 0062 und ADR 0055 dort). Die drei Ergebnisse oben bleiben gültig, aber Ergebnis 1 ist ausgeschlossen und Ergebnis 3 ist eingetreten: es ist eine Entscheidungsfrage.

Der Modulkopf trägt sie nicht — seine Argumente gelten für `quarantined` („ein Hold ist 'noch nicht'") und für `absent` („der gewöhnliche Zustand eines kalten Pull-through") und beanspruchen für die terminale Auslassung gar nichts. Die kommt aus dem ADR.
