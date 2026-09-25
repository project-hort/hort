# 237 — Parked dependencies belong in `renovate.json`

**Issue:** #249 · **Branch:** `agent/249-parked-deps-renovate`

## Why

Three dependency parkings are carried as *"leave the Renovate MR open, do not
merge, re-evaluate at the trigger"*. The open MR **is** the reminder — and that
carrier does not hold: Renovate autoclosed the `quick-xml` MR by itself, with
nothing about the situation changed. A reminder the bot can clear is not one.

It also costs something every cycle: a dashboard nudge per run, a
seemingly-mergeable entry in the MR list, and a red pipeline that has to be
recognised as the parking rather than a defect — repeated hand-work with a
mis-merge risk each time.

**The same file already demonstrates the right mechanism.** `renovate.json`
carries five `packageRules`, one of them a parking in exactly this shape (the
RustCrypto `digest` hold) with its reason in `description`. There is no reason
to run three parkings by agreement while five others are configuration.

## Scope

`renovate.json` gains one `packageRules` entry per parked dependency, mirroring
the RustCrypto entry's shape — `matchPackageNames`, `matchUpdateTypes:
["minor", "major"]`, `enabled: false`. Patch moves on the current line stay
allowed; only the jump into the next breaking slot is held.

**Every `description` names the unpark trigger, not only the reason.** That is
the whole point: the reason explains today, the trigger is what a future reader
checks to know whether today is over.

### The four

1. **`quick-xml`** — hold below 0.42. *Reason:* 0.42 makes text decoding
   infallible, which breaks the Maven readers' fallible-decode invariant
   (`decode_text` returns `None` on invalid UTF-8 so an unneeded element cannot
   abort the reader); and while `object_store` requires `^0.41`, a bump splits
   the graph across both. *Trigger:* `object_store`'s `quick-xml` requirement
   reaches 0.42.
2. **`x509-cert`** and **`const-oid`** — RustCrypto tranche B, coupled to
   sigstore. *Trigger:* a sigstore release that itself moves to `x509-cert
   0.3` / `der 0.8`. The coupling is described at length in
   `crates/hort-adapters-provenance-sigstore/Cargo.toml` — **point at it, do
   not restate it**; a second copy of that reasoning is a second thing to keep
   true.
3. **`cvss`** — hold below 3.0. **This one is not in the issue's list**: it was
   parked the same day the issue was confirmed, so the list is one item stale.
   It is the same class and the same recurring red pipeline, so it is folded in
   here rather than left to repeat the whole cycle. *Reason:* 3.0 removes or
   renames `cvss::v3::Base`, measured (`test:lint` fails with `cannot find type
   Base in module cvss::v3`), and both call sites parse a CVSS v3 vector into
   the base score that drives severity classification — which is what the
   scan-policy gates act on. 2.2.0 carries no advisory, so the bump buys
   nothing functional while costing a port on the path that decides what gets
   quarantined. *Trigger:* unlike the other three this one is not waiting on an
   upstream — it is waiting on a decision to do the port, or on an advisory
   against 2.2.0 forcing it. Say that plainly rather than inventing an external
   trigger.

## Explicitly not in this item

- **No unparking.** All four stay held; only the carrier changes.
- **No dependency version change**, and `Cargo.lock` is not touched.
- **Do not close the open Renovate MRs.** Renovate will do that itself once the
  rules take effect; closing them earlier only invites re-creation.
- No change to the existing five rules, in particular the RustCrypto `digest`
  entry.
- Nothing about `renovate/rust-1.x` — the toolchain disposition is unchanged.

## The delay, which must be stated in the report

`renovate.json`'s own `description` records it: *"Renovate reads this from the
default branch (main), so it takes effect once this reaches main via a
develop->main promotion."* The rules therefore bite **after the next
promotion**, and until then Renovate may keep re-creating these MRs. That does
not devalue the change — it means one more autoclose/re-create cycle is
expected and must **not** be re-investigated.

## Acceptance

- Four parked packages covered, each with reason **and** trigger in
  `description`.
- The existing five rules are byte-identical.
- `renovate.json` is valid JSON against the declared schema, and the file's
  existing formatting convention is followed.
- No `Cargo.toml` / `Cargo.lock` change.
