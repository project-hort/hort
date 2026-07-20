# 037 — E2E: proxy multi-arch pull → zero-window descendant release

- **Source:** GitLab issue #50. Confirmed by the maintainer 2026-07-20; **Tom will validate the new scenario locally** (this environment has no docker/compose, so CI is not the gate here).
- **Type:** E2E test infrastructure. `scripts/native-tests/` + `deploy/compose/example-config/`.
- **Model hint:** capable — the assertion design is the hard part, not the shell.
- **Reviewable unit:** one directive.

## Why it is still needed

#46's proxy tree-release fix shipped **twice** — once broken (hosted-push path only) and once re-fixed (`58b8548c`, the pull-through path) — and both times the composition of *pull-through edge-write × ingest target-check × release sweep* had no automated gate. Only prod validation caught the first failure. #51 has since shipped on the same surface with unit/HTTP coverage alone.

Verified 2026-07-20 that the gap is still open: `quarantine/oci-image-index.sh` is the **hosted push** path; `proxy/` holds `oci-mirror.sh`, `oci-mirror-name-prefix.sh`, `pull-dedup.sh`; and the only scenario referencing `quarantine_window_start` is the Cargo `patch-candidate.sh`.

## Refinement finding — the issue's acceptance criterion 2 is not achievable as written

The issue asks the scenario to assert *"the child releases on its own `ScanSucceeded` at the next sweep."* **It cannot, in the compose harness.** `deploy/compose/example-config/policies/oci-quarantine-e2e-quarantine.yaml` records why:

> `scanBackends: []` keeps the hold purely time-based: **the compose stack runs no hort-worker**, so no scan would ever complete anyway — the 24h window, not a scan result, is what holds the blob.

No worker ⇒ no `ScanSucceeded` ⇒ chasing that assertion would send the implementer after machinery that does not exist in this harness.

**Substitute a differential assertion, which is stronger anyway.** Under one policy with a non-zero `quarantineDuration`, compare two artifacts from the same pull:

| Artifact | Expected |
|---|---|
| the **index** (not a `content_references` target) | full window — `quarantine_window_start == created_at` |
| a **child manifest** (a referenced descendant) | zero window — `quarantine_window_start == created_at − duration` |

That proves the #46 Item 2 carve-out fires *for proxy-pulled trees specifically*, needs no worker, and cannot pass hollowly.

## The hollowness trap — the single most important design constraint

**The repo's `quarantineDuration` MUST be non-zero.** With `0s`, `created_at − duration` and `created_at` are the same value and the assertion passes no matter what the code does. `oci-mirror-e2e`'s existing policy is `quarantineDuration: 0s`, so it is unusable for this.

State this in the scenario's header comment so nobody later "simplifies" the fixture onto the permissive mirror repo and silently guts the test — the same failure mode `backlog/036` guards against with its >5 MiB blob-size rationale.

## Config to add (additive to `example-config/`, affects no existing scenario)

1. **`repositories/oci-proxy-quarantine-e2e.yaml`** — `format: oci`, `type: hosted` (pull-through comes from the upstream mapping, exactly as `oci-mirror-e2e` does), `isPublic: true`.
2. **`upstreams/oci-proxy-quarantine-e2e-dockerhub.yaml`** — `pathPrefix: dockerhub/`, `upstreamUrl: https://registry-1.docker.io`, `auth: {type: bearer_challenge}`. Copy `oci-mirror-e2e-dockerhub.yaml`.
3. **`policies/oci-proxy-quarantine-e2e-quarantine.yaml`** — repo-scoped, `quarantineDuration: 24h`, `scanBackends: []`, `provenanceMode: off`. Model on `oci-quarantine-e2e-quarantine.yaml`, whose comment already explains the no-worker rationale.

Repo-scoped policy ⇒ no other scenario is affected.

## The scenario

`scripts/native-tests/scenarios/quarantine/proxy-multiarch-zero-window.sh`, `requires: egress, db`.

`alpine:3.19` is a genuine multi-arch index and is already the upstream fixture `proxy/oci-mirror.sh` uses — reuse it rather than introducing a new external dependency.

Steps:

1. Cold-pull the index by tag through `dockerhub/library/alpine:3.19`.
2. Pull the platform-specific child manifest by digest (this is what a real client does after reading the index).
3. Assert via `psql_one` / `psql_exec` (`scripts/native-tests/lib/common.sh`, gated behind `requires: db`):
   - `content_references` carries `oci_index_member` rows sourced from the index artifact — the edges the pull-through path writes;
   - plus `oci_config` / `oci_layer` rows for the child's own referenced blobs;
   - the **index**'s `quarantine_window_start == created_at` (full window);
   - the **child**'s `quarantine_window_start == created_at − 24h` (zero window) — the assertion that would have caught the original #46 breakage.
4. Confirm the child becomes releasable at the next sweep while the index does not.

## Note for the implementer — #51 changed the pull sequence

#51 (merged) now fires blob warming on the **digest** path, so pulling the child manifest also spawns background pull-throughs of its config + layers. Extra artifacts appearing shortly after step 2 are expected and correct, not a leak. Assertions should target specific digests rather than counting rows in a table.

## Acceptance

1. The three gitops objects parse and cross-validate; no existing scenario changes behaviour.
2. The scenario appears in `--list` under the `quarantine` group.
3. The zero-window assertion is **differential** (index full window vs child zero window) and the repo's `quarantineDuration` is non-zero, with the rationale in the header comment.
4. It passes against a live compose stack. **This cannot be verified in the architect/cockpit sandbox — Tom validates locally.** Say so plainly in the report rather than implying CI proved it.

## Starter prompt

/hort-architect

Implement backlog item 037 (issue #50) on branch `agent/50-e2e-proxy-multiarch-zero-window`.

Read the backlog item first — especially the *refinement finding* (the compose stack has no hort-worker, so `ScanSucceeded` is unreachable; use the index-vs-child differential instead) and the *hollowness trap* (`quarantineDuration` must be non-zero or the assertion is vacuous).

Add the three gitops objects, then the scenario. Reuse `alpine:3.19` and the `psql_one`/`psql_exec` helpers. Do not modify any existing scenario or policy.

You cannot run compose in this sandbox — do not claim the scenario passes. Report exactly what you verified and what you did not.
