# Design — releasing a proxy artifact's referenced tree without stacked quarantine waves (#46)

**Status:** design / decision pending · **Branch-local** (docs/plans, per architect D7 — distil to an ADR amendment before merge) · **Driver:** issue #46

## §0 — Step 0 deferred-items sweep

Grep of prior plans + `docs/adr/0043-oci-image-index-support.md` + the ADR open-items register:

- **ADR 0043 "child-status rollup" (deferred)** — roll a child's `rejected`/`quarantined` status *up* into the index's served visibility. **Related but opposite direction** to #46 (that makes the index reflect a held child; #46 wants a held child to release faster). Keep separate; cross-referenced here so a future sweep finds the link.
- **ADR 0043 "promotion cascade" (deferred, open-items row)** — `PromotionUseCase` promoting an index does not promote its children/blobs. **Same tree-coordination shape as #46 but on the promotion axis, not the release-timing axis.** Whatever release model we pick here should be stated generically enough that the promotion cascade can reuse the same "descendant inherits parent decision" primitive. Carried forward — noted in §5.
- No other deferred items touch descendant *release timing*. Recorded explicitly: no inherited deferred *work* is absorbed here; two adjacent deferrals are cross-referenced.

**Rationale re-validation:** the ADR 0043 "safe because per-child/per-layer gated" rationale is still true for *safety* (verified: each node is independently scanned via `trivy fs` on its own blob; a released index over a held child serves no unscanned bytes). What changed is the *operability* premise: ADR 0043 assumed the per-node windows are a bounded cost; at production windows (hours/days) the **sequential** stacking makes a cold multi-arch proxy pull take N × window — days — which makes pull-through unusable for multi-arch. That is the deliberate reason to revisit the posture (issue #46, confirmed by Tom).

## §1 — Problem (generic)

A released **parent** artifact references a **tree** of descendants — for OCI: index → child manifests → config/layer blobs. Descendants are **lazily ingested on first touch**, each with its **own fresh quarantine observation window**. Because a client can't touch a descendant until the parent is released, the windows run **sequentially**: parent window → child window → blob window = **N stacked waves**, and a containerd pull 503s mid-pull between waves. Generic shape: *any* artifact that references other content-addressed artifacts gated per-node.

## §2 — Hard invariant (non-negotiable)

**Fail-closed (ADR 0007): every runnable byte is scanned before it is served.** The parent (index) scan is degenerate (routing JSON, no layers); the layer blobs — where CVEs live — are scanned only as their own artifacts. So **no option may release a descendant that has not itself been scanned clean.** This kills the "scan-release cascade off the index" idea outright (it would serve unscanned layers). Every option below keeps per-descendant scanning.

The **observation window's** purpose (distinct from the scan): catch a CVE *published shortly after ingest* — the artifact was clean when scanned at T but a CVE lands at T+Δ; the window + rescan sweep hold/flip it before serving. Key question the options turn on: **does a descendant, lazily ingested + scanned against the *current* CVE DB, need its own *fresh* window, or can that window be anchored/elided?** This depends on the **ongoing-rescan model** — whether released artifacts are periodically re-scanned (ADR 0041 continuous enforcement / the rescan sweep). *(Open verification, §4.)*

## §3 — Options

| | Model | Latency (cold multi-arch pull) | Proxy efficiency | Fail-closed | Generic | ADR-0007 perturbation |
|---|---|---|---|---|---|---|
| **A** | **Eager tree ingest** — on parent ingest, fetch+scan the whole referenced tree; windows run in **parallel** | 1 window (all nodes elapse together) | ✗ fetches **every** arch/blob, incl. never-pulled | ✓ | ✓ | none |
| **B** | **Release-on-clean-scan** — lazy fetch; scan each descendant at first-touch vs current DB; release immediately on clean scan, **no window** | ~scan time (seconds) | ✓ lazy (only pulled arch) | ✓ (still scanned) | ✓ | **high** — waives descendant observation window entirely |
| **C** | **Anchor window to parent** — lazy fetch + scan; descendant's `quarantine_until` **inherits the parent's** (not a fresh T'+window); release when parent-window-elapsed **AND** own scan clean | ~scan time if parent window already elapsed (the cold-pull case); else aligned to parent | ✓ lazy | ✓ (still scanned) | ✓ ("descendant inherits parent's observation anchor") | **low** — window preserved, only its *anchor* changes |
| **D** | **Proxy policy: short/zero window** — a `quarantineDuration` override for pull-through repos | shrinks all waves but still N of them | ✓ | ✓ | partial (repo-wide, not tree-aware) | medium — weakens observation for *all* proxy artifacts, not just descendants |

Notes:
- **A** is the obviously-safe brute force but the eager all-arch fetch is exactly the proxy waste (storage + upstream egress for arches nobody runs) that makes it unattractive at scale.
- **B** and **C** both keep lazy fetch + per-descendant scan (fail-closed). They differ only in the **observation window**: B elides it, C anchors it to the parent. B's safety *fully depends* on continuous rescan covering post-release CVEs; C keeps the window (just not stacked), so it's robust to that model either way.
- **D** is a blunt instrument — it changes the security posture for every proxy artifact and doesn't actually remove the *stacking* (still N waves, just shorter). Listed for completeness; not recommended.

## §4 — Decision: Option B (verified)

**DECIDED: Option B — a tree descendant releases on its own clean scan, with no fresh observation window.** (Tom, 2026-07-17.)

**The load-bearing precondition was verified, not assumed:** hort does **not** rescan an artifact *during* its quarantine window. `RescanCandidatesRepository::select_eligible` (`crates/hort-adapters-postgres/src/rescan_candidates.rs`) selects only `quarantine_status = 'released' OR NULL` artifacts whose `last_scan_at` is older than the policy `rescan_interval_hours` (default 24h). So the window is a **single-scan-at-ingest + timer**; forward-CVE observation is the periodic rescan of **released** artifacts.

Therefore **B loses zero observation**: a descendant scanned clean at first-touch is scanned against the **current** CVE DB (fresher than the parent's ingest scan), and on release joins the **identical** released-artifact rescan pool as everything else. The window it skips is pure latency, not protection. B is also **simpler than C** (no parent-edge resolution — precondition #3 dropped).

### B — final shape + implementation sketch
- Lazy fetch (only the pulled arch) — unchanged.
- Each descendant (child manifest, config/layer blob) is **still independently scanned** on first-touch (fail-closed — no unscanned release).
- On its own `ScanCompleted(clean)`, it **releases immediately (window = 0)** — gated on its own scan only (per-node, consistent with ADR 0043's per-child model; robust if the parent is later rejected).
- **Identifying a descendant at ingest:** an artifact that is a `content_references` **target** (referenced by an already-ingested manifest/index) is a tree descendant → assign it a **zero-length window** (`quarantine_until = ingested_at`) so the release sweep clears it as soon as its clean scan lands. Edge case — a blob touched before its referencing manifest exists (no edge yet): it takes the normal window; a later re-touch after the edge appears is a non-issue because the pull flow ingests the manifest before its blobs.
- **⚠️ Scope refinement (verified against the code):** `content_references` today captures **`oci_index_member`** (index→child) and **`oci_subject`** (referrer→subject) — but **NOT** manifest→config/layer **blob** edges. The manifest PUT only *validates* blob existence (`MANIFEST_BLOB_UNKNOWN`), it doesn't record `content_references` rows for blobs. So the target-check identifies child *manifests* but **not blobs** → the **blob wave (wave 3) is NOT fixed** by the target-check alone. To fix all three waves, B must **also write manifest→blob `content_references` edges** (new kinds, e.g. `oci_config` / `oci_layer`) at manifest PUT — a bounded extension of the exact many-to-many ADR 0043 built (mirrors the `oci_index_member` write, capped by the existing `MAX_BLOB_REFERENCES = 1024`), and a generically useful completion of the membership graph (the deferred promotion cascade wants it too). **B's real scope:** (1) `content_references` gains manifest→blob edges at PUT; (2) any target (child manifest **or** blob) gets the zero-length window; (3) sweep unchanged; + tests + ADR 0007/0043 amendments. *(Open with Tom: land the blob-edge extension as its own step, or in one change with the zero-window logic.)*

### Superseded alternative (kept for the record)
Option **C** (anchor the descendant window to the parent) was the prior recommendation; it is safe but strictly more complex than B (needs parent-edge resolution) and buys nothing once the no-in-window-rescan fact is established. **A** (eager all-arch ingest) remains the fallback only if the `content_references` target check turns out not to be cheaply available at descendant-ingest.

---

<details><summary>Prior recommendation text (Option C) — superseded by §4 decision</summary>

**Option C — anchor a descendant's observation window to its parent's, not a fresh per-node window.**

Rationale:
- **Fixes the operability problem generically:** the stacked waves collapse to a *single* window (the parent's) plus each touched descendant's own scan time (~seconds). For the reported case — a cold pull of an *already-released* index — the parent window is already elapsed, so a touched child/blob releases as soon as its own scan is clean. No days-long stall, no mid-pull 503 once the tree is scanned.
- **Preserves fail-closed and the observation model:** every descendant is still independently scanned (no unscanned release), and the observation window still exists — it's just *anchored to the parent's ingest*, reflecting that the descendant is the same upstream content the parent already observed. Minimal ADR 0007 perturbation (change the *anchor*, not the *existence*, of the window). Robust whether or not continuous rescan is in place.
- **Generic + reusable:** "a referenced descendant inherits its parent's release-decision anchor" is the same primitive the deferred **promotion cascade** (§0) needs — one concept covers both axes.

**Open verification before implementation** (flagged, not assumed — I will confirm against the code, not hand-wave):
1. The **ongoing-rescan model** — do released artifacts get periodically re-scanned (ADR 0041 / rescan sweep)? This decides whether B is even viable and confirms C loses no forward observation.
2. The **sweep candidacy + `quarantine_until` write path** — can a descendant's `quarantine_until` be set to the parent's at lazy-ingest time cheaply (the `content_references` edge already links them)?
3. **Where "parent" is known at descendant-ingest** — a lazily-ingested blob must resolve its parent index (via `content_references`) to inherit the anchor; confirm that edge is queryable on the ingest path.

If (1)–(3) hold, C is a contained change (descendant ingest sets `quarantine_until` from the parent edge; the sweep predicate is unchanged — it already gates on window + own-scan). If the parent edge isn't resolvable cheaply at blob-ingest, **A** is the fallback (eager fetch makes the tree present so windows parallelize) at the cost of proxy efficiency.

## §4a — ADR 0007 amendment: reconciling with the rejected "clean scan releases immediately"

**Load-bearing for the amendment author:** Option B *is* the alternative ADR 0007 explicitly **rejected** — *"Clean scan releases immediately. Rejected: collapses the observation window the quarantine exists to provide."* The amendment must therefore be a **scoped carve-out**, not a reversal, and justify why the observation window is not actually lost for a **referenced-tree descendant**:

- **No in-window rescan (verified).** `select_eligible` rescans only `released`/`NULL` artifacts on the 24h interval — the window never re-scans a `quarantined` artifact. So the window is a single-scan-at-ingest + timer for *every* artifact, parent included; it does not itself realise "reputation catch-up" via rescan.
- **The descendant is scanned fresher than the parent.** A descendant scanned at first-touch T' uses the *current* CVE DB — strictly more recent than the parent's ingest-time scan the operator already trusted at release.
- **Identical forward observation.** On release the descendant enters the same 24h released-artifact rescan pool as everything else; post-release CVEs are caught identically to any released artifact.

So the carve-out is: *a scanned-clean artifact that is a `content_references` target of an already-ingested parent (a referenced-tree descendant) releases on its own `ScanSucceeded` without re-applying the observation window; forward observation is the standard released-artifact rescan.* The two impossible failure modes in ADR 0007 §Context are preserved (no unscanned release; no timer-only release — the descendant still needs its own `ScanSucceeded`). The scope is deliberately narrow (referenced descendants), **not** a general "clean scan releases immediately." Reviewer note: this reconciliation is the crux of the ADR amendment — do not land a broad reversal.

## §5 — Decision requested

Pick the posture: **A (eager)**, **B (no descendant window)**, **C (anchor to parent — recommended)**, or **D (proxy short window)**. On decision I will: verify §4's three preconditions against the code, amend **ADR 0043 + ADR 0007** (the observation-window anchor for referenced descendants), and produce the backlog. The **promotion cascade** deferral (§0) is carried forward to reuse the chosen "descendant inherits parent decision" primitive — not implemented here.
