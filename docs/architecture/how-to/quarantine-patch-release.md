# Release a security-fix from quarantine

This guide is for operators who hold a quarantine policy on an upstream-
facing repository and need to act on the case where the quarantined
artifact is a **fix** for a vulnerability in a version that hort
is already serving. It covers the `hort-cli admin quarantine` workflow, the
audit trail produced, and the alternative "fast-patch repository" pattern
including the per-format transparency limits.

For the quarantine state model and release predicate see
[ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md)
and [security.md](../explanation/security.md).

---

## 1. The scenario

Your `npm-proxy` repository quarantines newly-pulled tarballs for 72 hours
before they become downloadable. Today:

- `lodash@4.17.20` is in your repo, released, downloadable. A scan ran
  yesterday and `ArtifactBecameVulnerable` fired — a new advisory matched
  this version (prototype-pollution, severity High).
- `lodash@4.17.21` arrived in your proxy this morning, claims to fix that
  advisory, and is sitting in quarantine for another 71 hours.

Your downstream consumers are still hitting `4.17.20` — the version with
the known vulnerability — for the next three days. The version that
fixes their problem is in your queue, held by the same defense-in-depth
gate that protects you against malicious "fixes."

This is not a quarantine bug. The threat model is intentional: recent
high-profile supply-chain compromises (xz, event-stream) were delivered as
**new releases of trusted packages**, several framed as fixes or
improvements. "Claims to fix CVE-X" is the attack pattern, not a defense.
The quarantine window is doing its job; what you need is **visibility +
an explicit, audited override**, not an automatic shortcut.

---

## 2. What the system tells you

Two signals together identify this situation:

1. **`ArtifactBecameVulnerable`** — the scan pipeline emits this event
   when a scan finds a CVE in an artifact you're currently serving.
   Subscribe via the event-notifier (webhook / NATS) or query
   `repo_security_scores` to see the affected versions.

2. **`hort-cli admin quarantine list-patch-candidates`** — surfaces
   every quarantined artifact whose same-named older sibling in the same
   repository has unresolved scan findings. Output:

```sh
$ hort-cli admin quarantine list-patch-candidates --repo npm-proxy
PACKAGE  FORMAT  VERSION_TRANSITION  SEVERITY  FINDINGS  QUARANTINE_UNTIL
lodash   npm     4.17.20 -> 4.17.21  high      1         in 71h 14m
axios    npm     1.6.2 -> 1.6.7      critical  2         in 62h 3m
```

The `QUARANTINE_UNTIL` column is the time until the timer sweep would
automatically release the quarantined version on its own. If you do
nothing, the quarantine window completes, the artifact is released, and
your consumers pick up the fix at that point. The override below is for
the case where waiting is not acceptable.

---

## 3. The decision

Releasing a quarantined artifact early is a **risk-accepted operator
override**. You are saying:

- I have reason to believe this newer version is genuine.
- The cost of waiting (consumers continuing to fetch the vulnerable older
  version) outweighs the marginal risk-reduction of completing the full
  observation window.
- My identity and justification are recorded in the immutable audit log
  so a future incident response can reconstruct who decided and why.

Who should make the call: someone who can verify the upstream publish
signature, the upstream maintainer's identity, the changelog, and the
public advisory — not a CI pipeline. The release endpoint requires
`Permission::Admin`; do not bind an `hort_svc_*` service token with that
permission and call it from automation.

What you are **not** signing up for: the scan still ran (and either
completed clean, completed with its own findings, or is still pending).
A `release` action does not bypass scan-rejected state — an artifact with
its own disqualifying findings is in `quarantine_status='rejected'`, not
`'quarantined'`, and the patch-candidate listing surface shows you the
findings (if any) before you act.

---

## 4. Command sequence

The four commands below are the full workflow. Substitute one artifact
ID and they run as-shown.

```sh
# 1. List candidates. Use --output json | jq for inspection scripts.
hort-cli admin quarantine list-patch-candidates --repo npm-proxy --output json \
  | jq '.candidates[] | {package_name, vulnerable_version, quarantined_version,
                          quarantined_artifact_id, vulnerable_max_severity,
                          vulnerable_finding_count}'

# 2. Verify the upstream publish. For npm:
npm view lodash@4.17.21 --registry https://registry.npmjs.org \
  | grep -E 'dist|integrity|signatures'

# 3. Release the quarantined artifact. --justification is REQUIRED and
#    is recorded in the ArtifactReleased event's `justification` field
#    (max 512 bytes, non-empty after trimming whitespace).
hort-cli admin quarantine release <quarantined_artifact_id> \
  --justification "lodash@4.17.21 fixes CVE-2024-XXXX (prototype pollution
                   reported in GHSA-...); verified upstream npm signature
                   2026-05-11; risk-accepted by security@example.com"

# 4. Confirm. The artifact transitions to quarantine_status='released'
#    immediately; downstream clients pick up the fix on their next pull.
hort-cli admin quarantine list-patch-candidates --repo npm-proxy
#    The row for lodash should no longer appear.
```

The `ArtifactReleased` event for step 3 carries:
- `released_by = Admin`
- `released_by_user_id = <your user UUID>` (from the admin token used)
- `justification = "<the text you supplied>"`

Both `released_by_user_id` and `justification` are present iff `released_by = Admin`;
the timer-sweep release path produces an `ArtifactReleased` with both
fields `None`, and the policy-re-evaluation path (when an exclusion is
added and the observation window has elapsed) also produces both `None`.
This contrast is what makes the admin path forensically distinguishable
from the routine release paths.

---

## 5. Alternative: fast-patch repository

A pattern operators sometimes ask about: run a **second proxy repository**
alongside the main one, configured with a short quarantine window (e.g.
0-1 hour), and route security fixes through it.

The pattern works in some environments. It is not transparent for most
clients. Before adopting it, check whether your consumer formats and your
ability to push client configuration line up.

### 5.1 Per-format transparency

| Format        | Transparent? | What it requires                                                                                                  |
| ------------- | ------------ | ----------------------------------------------------------------------------------------------------------------- |
| **npm**       | No           | `.npmrc` configures one `registry=`. Scope-based routing (`@scope:registry=`) does not help — security fixes hit arbitrary packages. Consumers must explicitly target the fast-patch URL. |
| **Cargo**     | No           | A workspace resolves against one registry. Alternate registries exist (`[source.X]` in `~/.cargo/config.toml`) but precedence is per-crate explicit, not "newer wins across registries." |
| **OCI / Docker** | No        | The registry URL is part of the image name (`registry.example.com/img:tag`). Two repos = two image names. No client-side merging. OCI is excluded from the patch-candidate listing for this reason (no version-precedence relation between tags across two registries). |
| **Helm**      | No           | `helm repo add` is named; `helm install <name>/<chart>` is keyed. The chart pulls from exactly one named repo. |
| **PyPI**      | Partial      | `pip install --extra-index-url <url>` merges indexes and resolves to the higher version. **Caveat:** same mechanism behind dependency-confusion attacks; you must lock down which packages can come from where (e.g. via `pip-tools` constraints) or an attacker who can publish to one index can poison your resolution from the other. |
| **Maven**     | Partial      | `<repositories>` in `pom.xml` / `~/.m2/settings.xml` is merge-capable. Workable if every consumer's POM (or a parent POM / `settings.xml` pushed via config-management) lists both repos with the fast-patch one first. |
| **APT**       | Partial      | Multiple `/etc/apt/sources.list.d/*.list` entries + `/etc/apt/preferences.d/*` pin priorities. Works when the operator owns the consumer's apt config; not workable for arbitrary dev workstations. |

### 5.2 When the pattern fits

Two preconditions, either one sufficient:

1. **You own the client configuration.** CI runners with a managed
   `.npmrc` / `pip.conf` / `settings.xml`; fleet-managed dev environments
   with `/etc/apt/sources.list.d/*` distributed via Ansible / Chef /
   Salt; container base images that bake in the resolver config. In
   these cases "list both registries and put the fast-patch one first"
   is a one-place change.

2. **The format natively supports multi-index resolution.** Maven, PyPI
   (with the dependency-confusion caveat above), or APT with pin
   priorities. Even then, every consumer's config has to be touched
   once.

For developer laptops with hand-edited `.npmrc` / `~/.cargo/config.toml`,
or for `docker pull` flows that hard-code an image registry, the
fast-patch repository is **not** transparent. The consumer has to know
which URL to use.

### 5.3 Setting it up

If your environment meets the preconditions above, the chart values for
a fast-patch repo look like:

```yaml
# values.yaml fragment — under your gitops config or apply-pipeline input
repositories:
  - key: npm-security-fixes
    format: npm
    kind: proxy
    upstream:
      url: https://registry.npmjs.org
      secretRef: npm-upstream-creds
    scanPolicy:
      quarantineDurationHours: 1     # short window — the explicit risk choice
      rescanIntervalHours: 24

  - key: npm-main
    format: npm
    kind: proxy
    upstream:
      url: https://registry.npmjs.org
      secretRef: npm-upstream-creds
    scanPolicy:
      quarantineDurationHours: 72    # default — full observation window
      rescanIntervalHours: 24
```

The fast-patch repo lists upstream once, runs the same scanner, and
emits the same `ChecksumVerified` / `ScanCompleted` events; the
*only* difference is the operator-explicit shortened quarantine
window. Routing decisions ("which artifacts go through the fast-patch
repo") happen at the client side, not the server side — hort
treats both repos as independent proxy pipelines.

### 5.4 When to prefer the per-artifact override instead

The `hort-cli admin quarantine release` flow in §4 keeps consumers on
**one** registry URL. They never see a config change. The operator pays
the cost (one CLI invocation per fix) instead of pushing the cost to
every consumer. This is the right default for the common case.
Fast-patch is an optimisation for environments where the operator-side
cost of "audit + release each fix individually" is genuinely too high.

---

## 6. What the system does NOT do automatically (and why)

The system **never auto-releases** a quarantined artifact based on:

- A clean scan result. `ScanCompleted(clean)` leaves `quarantine_status =
  'quarantined'` and `quarantine_until` unchanged. The timer is the
  release path; a clean scan is necessary but not sufficient.
- An advisory database claim that the artifact "fixes CVE-X". OSV / GHSA
  / npm advisory metadata is public-mutable and attacker-influenceable;
  the system does not trust it as a release trigger.
- A name-and-version-pattern match against a known-vulnerable older
  version. The "this is a newer sibling of a vulnerable artifact"
  signal surfaces in `hort-cli admin quarantine list-patch-candidates`
  for *operator decision-making*. It does not gate state changes.

Why: **automation here is exactly the attack
pattern**. xz's malicious 5.6.0 was framed as a fix-and-improvement
release; event-stream's compromised version 3.3.6 was published as a
maintenance update by a takeover account. An auto-release path keyed on
"newer version of a vulnerable package" would have shipped both
payloads to consumers within minutes of upload. A 72-hour observation
window with a human-gated override would not have.

The audit-trail invariant in `ArtifactReleased` is the
load-bearing piece of this story. Every early release in the system has
a named human attached. There is no automated principal that holds
`Permission::Admin` and can shortcut the gate; if you discover an
`hort_svc_*` token in your deployment with admin scope, treat it as a
configuration error and rotate it.

---

## Related

- Quarantine state model + release predicate: [ADR 0007](../../adr/0007-fail-closed-quarantine-release-predicate.md), [security.md](../explanation/security.md)
- Vulnerability scanning producer pipeline: [scanning-pipeline.md](../explanation/scanning-pipeline.md)
- Event notification substrate (push delivery of `ArtifactBecameVulnerable`): [event-notifications.md](../explanation/event-notifications.md)
- Per-format pull-through guides: [`npm-pull-through.md`](npm-pull-through.md), [`pypi-pull-through.md`](pypi-pull-through.md)
