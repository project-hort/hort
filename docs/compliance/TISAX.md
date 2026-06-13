# TISAX / VDA ISA control support

This document is for an operator who runs a hort server inside an
automotive software supply chain and needs to show, during a **TISAX**
(Trusted Information Security Assessment Exchange) assessment, how the
component supports the controls in the **VDA ISA** (Information Security
Assessment) catalogue. It maps the VDA ISA control areas onto the
hort capabilities that satisfy them, the concrete operator action that
turns the capability on, and the source ADR / architecture doc that is
the authority for the claim.

It is the assessment-facing companion to the engineering docs: the
security posture is in
[`../architecture/explanation/security.md`](../architecture/explanation/security.md);
the inbound-auth control spec is the canonical
[`../auth-catalog.md`](../auth-catalog.md); the data-protection record
for the event log (relevant to the TISAX **Data Protection** objective)
is [`GDPR.md`](GDPR.md). The standing decisions live in the ADRs under
[`../adr/`](../adr/) (decision index:
[`0000-historical-decisions-index.md`](../adr/0000-historical-decisions-index.md)).

> **What this document does NOT claim.** TISAX assesses **organisations,
> not tools**. A TISAX label is awarded to an assessed scope (a site, a
> business unit, a process) by an accredited audit provider; it is never
> awarded to a piece of software. hort is **one component** inside such
> a scope. This document describes how hort *supports* the relevant
> controls and *supplies evidence* an assessor can collect — it is not,
> and may not be cited as, an attestation of TISAX conformity. The same
> hard rule the authentication catalog states in its §1.1 applies here:
> a control inventory is not a conformity assessment. Where hort lacks a
> control, this document says so plainly.

---

## 1. Scope and assessment context

### 1.1 What TISAX and VDA ISA are

**VDA ISA** is the *Information Security Assessment* catalogue maintained
by the German automotive industry association (VDA). It is structured as
a control questionnaire aligned with **ISO/IEC 27001 / 27002**, extended
with automotive-specific modules — most notably **Prototype Protection**
and **Data Protection**. **TISAX** is the assessment-and-exchange
mechanism built on top of VDA ISA: an accredited audit provider assesses
an organisation against the catalogue, and the result is published to
other participants through the ENX exchange platform so a supplier is
assessed once and recognised by many OEMs.

A TISAX engagement is scoped by **assessment objectives** (labels) and an
**assessment level**:

| Concept | Values relevant to a hort deployment |
|---|---|
| **Assessment objectives** | *Information Security* with protection needs **high** and **very high**; *Prototype Protection*; *Data Protection* (GDPR Art 28 processing). |
| **Assessment levels (AL)** | **AL 1** (self-assessment), **AL 2** (plausibility check, evidence + remote interview), **AL 3** (in-depth audit, on-site verification). Higher protection needs require AL 2 / AL 3. |

In an automotive software supply chain, hort serves as the artifact /
build-output / dependency repository — the place where third-party
dependencies are proxied and verified, where build outputs are stored,
and where the supply-chain gate decides what may be consumed downstream.
That makes it directly relevant to **Information Security (high / very
high)** and **Data Protection**, and adjacent to **Prototype Protection**
where the build outputs themselves are sensitive prototype data.

### 1.2 The shared-responsibility split

The single most important framing for an assessor: hort is a control
*provider*, not a control *owner*. Roughly:

| hort provides (in-component) | The operator / organisation owns (in-scope, out-of-component) |
|---|---|
| Identity gating, RBAC evaluation, short-lived sessions, token-at-rest hashing | The IdP itself (MFA, session policy, account lifecycle), the ISMS, access-review governance |
| Tamper-evident event log, integrity-verified CAS, fail-closed quarantine | Physical security, the SIEM, key custody, backup/restore execution, the assessment process |
| Mandatory upstream verification + provenance gates for supplier dependencies | The supplier-risk programme, the incident-response organisation, personnel security |
| Config-as-code surface (gitops), strict Helm schema, structural guards | Change-management governance, network segmentation at the cluster edge, TLS termination |

Every row in the control mapping below is read with this split in mind:
the *capability* column is hort's; the *operator action* column is the
organisation's, and it is the organisation that the assessor labels.

---

## 2. VDA ISA control mapping

The table below maps VDA ISA control areas (the ISO/IEC 27001/27002
families the catalogue is built on, named by topic rather than by a
specific ISA question number — question numbering moves between ISA
revisions) to the hort capability, the concrete operator action that
activates it, and the source of authority.

### 2.1 Identity and access management

| VDA ISA area | hort capability | Operator action | Source |
|---|---|---|---|
| Identification & authentication | OIDC bearer (interactive humans) + native tokens (PAT / service-account / CLI session); pinned issuer, JWKS verified over TLS | Set `HORT_OIDC_ISSUER_URL`; HS-family / `none` algorithms are refused at startup | [auth-catalog](../auth-catalog.md) Entry 1/12, [ADR 0018](../adr/0018-auth-catalog-canonical.md) |
| Access control / least privilege | Claim-based RBAC: authority is granted only by `PermissionGrant` rows whose subject is `Claims([...])` or `User(uuid)`, applied through one audited path; `Delete` is split from `Write` | Declare `ClaimMapping` + grants in gitops; give CI push-only grants no delete | [ADR 0012](../adr/0012-claim-based-rbac-claimless-static-tokens.md) |
| Privileged-access / session management | CLI sessions are short-lived (≤ 15 min for both standard and admin sessions), IdP-backed, with a `jti` emergency-revocation denylist | Use the mediated-login flow; do not reintroduce a long-lived token model | [ADR 0013](../adr/0013-idp-authoritative-cli-sessions.md), auth-catalog Entry 3 |
| Machine identity / credential rotation | Federation exchange (keyless workload identity) is preferred; PAT auto-rotation reconciler for workloads that cannot federate | Prefer `/api/v1/auth/exchange`; for the fallback, set a `fallbackRotation` block with `validity ≥ 2 × rotationInterval` | [federate-ci-oidc](../architecture/how-to/federate-ci-oidc.md), [rotating-service-account-tokens](../architecture/how-to/rotating-service-account-tokens.md), auth-catalog Entry 6 |
| Anti-enumeration / need-to-know | Read denials collapse "missing" and "invisible" into one `NotFound` envelope; private-repo existence does not leak | None — structural in the use-case layer | [security.md](../architecture/explanation/security.md) "Visibility model" |

### 2.2 Cryptography

| VDA ISA area | hort capability | Operator action | Source |
|---|---|---|---|
| Cryptographic concept — transport | All outbound TLS verified against the system trust store + an additive operator CA bundle; **no `*_INSECURE_TLS` knob exists** | Add internal CAs to `HORT_EXTRA_CA_BUNDLE`; never disable verification | [ADR 0010](../adr/0010-tls-builder-no-insecure-knobs.md) |
| Cryptographic concept — integrity | Content-addressable storage keys every blob by SHA-256, computed incrementally as bytes stream; the key *is* the content hash | None — enforced by the `StoragePort` signature | [ADR 0003](../adr/0003-streaming-enforced-cas.md), [cas-storage.md](../architecture/explanation/cas-storage.md) |
| Cryptographic concept — secrets at rest | Opaque native tokens (`hort_pat_*` / `hort_svc_*`) are **Argon2id-hashed** at rest; CLI-session and OCI tokens are **Ed25519-signed JWTs** (a dedicated signing keypair, not stored hashed) | Wire the OCI signing key and upstream creds via `SecretPort` (file / env) | auth-catalog Entry 2/4, [wire-secrets](../architecture/how-to/wire-secrets.md) |
| Key management | hort holds no key store: it reads bytes from an operator-wired file or env var, re-read on every `resolve()` | Wire ESO / CSI / Vault Agent → mounted file; use `source: file` for rotation | [wire-secrets](../architecture/how-to/wire-secrets.md) §2/§4 |

### 2.3 Event logging and monitoring

| VDA ISA area | hort capability | Operator action | Source |
|---|---|---|---|
| Logging of security events | Every artifact and policy lifecycle change is an immutable domain event; authn / authz attempts produce `AuthenticationAttempted` events + structured tracing | Forward Postgres event rows / the `tracing` JSON stream to the SIEM | [ADR 0002](../adr/0002-event-sourced-artifact-lifecycle.md), [event-sourcing.md](../architecture/explanation/event-sourcing.md) |
| Log integrity / tamper-evidence | The `events` table is append-only — a Postgres trigger owned by a *separate* role rejects `UPDATE`/`DELETE`; the runtime role has `INSERT` only; an event-chain verifier detects tampering | Schedule `hort-server verify-event-chain`; alarm on `hort_event_chain_verify_overdue` | [event-sourcing.md](../architecture/explanation/event-sourcing.md) |
| Monitoring | A `snake_case` `hort_*` Prometheus surface covers auth attempts, authz decisions, token issuance/validation, scan/provenance verdicts, queue depth | Scrape `/metrics` (admin-auth-gated by default); build dashboards/alerts | [metrics-catalog](../metrics-catalog.md) |
| Log retention | Per-category retention floors (auth ≥ 6 mo, download audit ≥ 90 d, config/artifact ≥ 36 mo) bound growth without deleting privileged streams | Configure the retention runner per [`GDPR.md`](GDPR.md) §1 | [GDPR.md](GDPR.md) §1, [ADR 0030](../adr/0030-sensitive-surface-structural-guards.md) |

### 2.4 Handling of information assets and integrity

| VDA ISA area | hort capability | Operator action | Source |
|---|---|---|---|
| Asset integrity at rest | Read-time `VerifyingReader` re-hashes every byte streamed out and fails the read on drift; a scheduled `hort-server scrub` re-hashes blobs nobody reads | Run the scrub CronJob (default 03:00 UTC); choose `alert` or `tombstone` on mismatch | [cas-storage.md](../architecture/explanation/cas-storage.md), [ADR 0003](../adr/0003-streaming-enforced-cas.md) |
| Decision-history integrity | "What changed, when, and on whose authority" is reconstructable for every security-relevant transition by replaying the immutable stream | None — structural; gitops apply attributes events to `Actor::GitOps` | [ADR 0002](../adr/0002-event-sourced-artifact-lifecycle.md), security.md "Audit trail" |
| Protection of sensitive schema | Fail-closed structural guards reject any migration that drops or de-constrains the authorization model, credential store, or event ledger | None — the guard runs in the pre-push / CI gate | [ADR 0030](../adr/0030-sensitive-surface-structural-guards.md) |

### 2.5 Supplier / external-source security (the automotive supply-chain angle)

| VDA ISA area | hort capability | Operator action | Source |
|---|---|---|---|
| Integrity of externally-sourced software | **Every** pull-through fetch verifies a protocol-native checksum *before* the bytes are stored; a `ChecksumMismatch` rejects the artifact at the door — **not an operator opt-in** | None to enable; a format with no verifiable digest cannot be proxied at all | [ADR 0006](../adr/0006-mandatory-upstream-verification.md) |
| Provenance of supplier dependencies | Sigstore/cosign provenance verification (offline, pinned trust root) verifies *who built and published* an artifact against allowed signer identities, for hosted **and** proxied (upstream-referrer-fetched) content | Enable the worker verifier + pin `trusted_root.json`; set `provenanceMode` + `provenanceIdentities` per scope | [ADR 0027](../adr/0027-artifact-provenance-verification.md), [enable-provenance-verification](../architecture/how-to/enable-provenance-verification.md) |
| Restriction of external sources | An upstream allowlist restricts pull-through to an enumerated registry set; plaintext upstreams require an explicit per-mapping opt-in | Set `HORT_UPSTREAM_ALLOWLIST_HOSTS`; keep upstream URLs `https://` | [security-hardening-checklist](../architecture/how-to/deploy/security-hardening-checklist.md) |
| Upstream transport trust | Per-upstream mTLS, custom CA, and cert-pinning for zero-trust internal mirrors | Set `mtlsCertRef`/`mtlsKeyRef` / `caBundleRef` / `pinnedCertSha256` on a `kind: UpstreamMapping` (gitops) | [security-hardening-checklist](../architecture/how-to/deploy/security-hardening-checklist.md) |

### 2.6 Secure software development and supply chain

| VDA ISA area | hort capability | Operator action | Source |
|---|---|---|---|
| Quarantine / staged release | A fresh or proxied artifact is quarantined and downloads are blocked while quarantined; release is **fail-closed** — the predicate accepts exactly five `(reason, authority)` pairs and denies all others | Set a `ScanPolicy` (quarantine duration, severity threshold); use `scanBackends: []` only as a deliberate, audited waiver | [ADR 0007](../adr/0007-fail-closed-quarantine-release-predicate.md) |
| Vulnerability scanning | Trivy (content adjudicator) + OSV (SBOM-based) backends run in the worker; SBOM extraction for npm/PyPI/Cargo feeds advisory enrichment | Enable a scanner backend; the out-of-box default scans (`["trivy"]`) | [scanning-pipeline.md](../architecture/explanation/scanning-pipeline.md) |
| Release gating on provenance | In `required` mode, an OCI artifact only timer-releases once a `ProvenanceVerified` event exists — provenance is an AND-precondition that can only *tighten* the gate | Set `provenanceMode: required` on scopes you control + enable the worker verifier | [ADR 0027](../adr/0027-artifact-provenance-verification.md) |
| Provenance of hort itself | Release assets ship `cosign sign-blob` signatures (keyless OIDC on GitHub; Vault-pinned key on GitLab) | Verify with `cosign verify-blob` before deploying a release | [release-verification](../architecture/how-to/release-verification.md) |

### 2.7 Vulnerability and incident management

| VDA ISA area | hort capability | Operator action | Source |
|---|---|---|---|
| Vulnerability handling over time | A clean verdict decays: the cron rescan re-adjudicates released artifacts on a policy cadence; the advisory watch targets artifacts a new advisory affects via the `sbom_components` reverse index | Schedule the `cron-rescan-tick` and `advisory-watch-tick` admin-task CronJobs | [scanning-pipeline.md](../architecture/explanation/scanning-pipeline.md) "Rescan and advisory watch" |
| Newly-vulnerable detection | `ArtifactBecameVulnerable` fires with the exact new `(purl, vulnerability_id)` pairs on a transition from clean to vulnerable | Alert on the event / its metric | [scanning-pipeline.md](../architecture/explanation/scanning-pipeline.md) |
| Incident-relevant log detail | Auth-failure events carry `client_ip` (NIS2-aligned incident horizon); `idp_unavailable` is kept distinct from `invalid_token` so a credential-stuffing campaign is distinguishable from an IdP outage | Pivot SIEM dashboards on the `result` label | [GDPR.md](GDPR.md) §4, [metrics-catalog](../metrics-catalog.md) "Auth middleware" |

### 2.8 Change and configuration management

| VDA ISA area | hort capability | Operator action | Source |
|---|---|---|---|
| Config as code | Policies, RBAC, repositories, and upstream mappings are declared in a gitops config tree applied at boot; every authz mutation appends an audit event attributed to `Actor::GitOps` | Manage `$HORT_CONFIG_DIR` in version control; review changes as code | [declare-gitops-config](../architecture/how-to/declare-gitops-config.md) |
| Apply-time validation | A strict Helm `values.schema.json` and an apply-time linter reject dangerous or inert configurations (e.g. a policy field accepted but read by no gate) fail-closed | None — fail-fast at `helm template` / boot | [ADR 0015](../adr/0015-apply-time-linter-inert-fields-and-naming.md), [ADR 0029](../adr/0029-operator-config-hard-rename.md) |
| Least-privilege schema changes | Migrations run from a dedicated, separately-privileged subcommand; the runtime DSN cannot run DDL | Run migrations as a separate Job with the admin role | [ADR 0009](../adr/0009-least-privilege-runtime-migrate-subcommand.md) |
| Idempotent destructive operations | Destructive task kinds carry a server-derived, DB-enforced per-UTC-day idempotency key — at most one run per kind per day, including after failure | None — structural | [ADR 0028](../adr/0028-destructive-task-idempotency.md) |

### 2.9 Prototype Protection (honest scope)

TISAX Prototype Protection is largely a **physical and organisational**
control set — secured rooms, vehicle/component handling, photography
bans, visitor control, contractual confidentiality. **hort cannot
satisfy those controls**, and this document does not claim it does.

What hort *does* support is the **information-security facet** of
Prototype Protection where the sensitive prototype data is itself a build
output or dependency stored in the repository:

- **Access segregation / need-to-know** — per-repository RBAC plus
  claim-based grants confine a prototype repository to the identities
  explicitly granted on it, and the anti-enumeration model prevents an
  unauthorised principal from even learning the repository exists
  ([ADR 0012](../adr/0012-claim-based-rbac-claimless-static-tokens.md),
  [security.md](../architecture/explanation/security.md)).
- **Tamper-evidence on prototype-artifact handling** — ingest, release,
  promotion, and rejection of a prototype artifact are immutable events
  with attributed authorship
  ([ADR 0002](../adr/0002-event-sourced-artifact-lifecycle.md)).
- **Confidentiality in transit and at rest** — TLS posture
  ([ADR 0010](../adr/0010-tls-builder-no-insecure-knobs.md)) and
  integrity-verified CAS
  ([ADR 0003](../adr/0003-streaming-enforced-cas.md)).

The **physical and organisational prototype-protection controls remain
entirely the organisation's responsibility** and are out of scope for
this component (see §5).

### 2.10 Data Protection (cross-reference)

The TISAX **Data Protection** objective (GDPR Art 28 processing on behalf
of an OEM) is covered for the hort event log by the dedicated record
[`GDPR.md`](GDPR.md): the per-category retention schedule, the Art 17(3)(b)
erasure-exemption rationale for the tamper-evident log, the ROPA (Art 30)
outline, the PII-pseudonymization stance (actors identified by `user_id:
Uuid`, never by email/username), and the SAR playbook. An assessor working
the Data Protection objective should take `GDPR.md` as the primary artefact
and this document as the cross-reference.

---

## 3. Operational procedures (runbook)

Concrete, assessor-checkable operating guidance, grouped by control theme.
The security-hardening checklist
([`../architecture/how-to/deploy/security-hardening-checklist.md`](../architecture/how-to/deploy/security-hardening-checklist.md))
carries the per-control `kubectl` / `curl` verification one-liners; this
section names *what* to do and *why* it matters for the assessment.

### 3.1 Hardened deployment

- **Terminate TLS at the edge and require https.** hort speaks plain
  HTTP; TLS and HSTS are the reverse proxy's job. Set `publicBaseUrl` to
  the edge https URL (or populate `trustedProxyCidrs` for an in-cluster
  TLS-terminating proxy). Keep `requireHttps: true`.
- **Do not reintroduce insecure-TLS knobs.** Trust internal CAs via
  `HORT_EXTRA_CA_BUNDLE` only, sourced from an RBAC-restricted
  `ClusterTrustBundle` — treat it as an auth-critical asset (it can
  impersonate the IdP).
- **Run the three-role Postgres model.** Migrations as `hort_admin` (DDL),
  runtime as `hort_app_role` (`INSERT`/`SELECT` on `events`), and the
  migration-created `NOLOGIN` `hort_retention_role` (the only role that may
  `DELETE` from `events`). The event store refuses to start if the runtime
  role can `UPDATE`/`DELETE`.
- **Keep the pod hardening on.** Non-root UID 65532, read-only root FS,
  `drop: [ALL]`, `seccompProfile: RuntimeDefault`,
  `allowPrivilegeEscalation: false`. Do not loosen.
- **Default-on NetworkPolicy + control-plane tier.** Keep
  `networkPolicy.enabled: true`; for production set `control.bindAddr` so
  `/admin` lives on an internal-only listener. Network position is
  defence-in-depth on top of RBAC, never instead of it.

### 3.2 Access governance and periodic reviews

- **Express all authority as gitops grants.** Declare `ClaimMapping`
  and `PermissionGrant` rows in version control; the apply path is the
  single audited mutation channel. Periodic access reviews are then a
  review of the config tree's diff history.
- **Confine CI to push-only where appropriate.** After the `Write`/`Delete`
  split, a push-only grant no longer carries delete; review existing
  grants for accidental delete authority.
- **Prefer federation for machine identities.** OIDC exchange is keyless,
  scoped per workflow, and needs no rotation discipline; fall back to PAT
  rotation only for workloads that genuinely cannot federate.

### 3.3 Cryptography and secret management

- **Wire secrets, do not embed them.** Land upstream credentials and the
  OCI signing key via ESO / CSI / Vault Agent / Kubernetes Secret into a
  mounted file or env var; use `source: file` where rotation is needed
  (env-var rotation does not work).
- **Constrain the secrets root.** Set
  `HORT_SECRETS_FILE_ROOT=/run/secrets` so a malicious `secretRef` cannot
  escape to host files; tighten mounted-file mode to `0400`/`0600`.

### 3.4 Logging, monitoring and retention

- **Forward the log to the SIEM.** Tail the Postgres `events` rows and the
  `tracing` JSON stream to the operator's log pipeline (the binary pushes
  nothing directly).
- **Schedule and alarm the event-chain verifier.** Enable the
  `verify-event-chain` CronJob and alarm on
  `hort_event_chain_verify_overdue`; pair with an S3 Object-Lock anchor
  bucket for full external-anchor attestation.
- **Run the retention runner.** Configure it against the longer of the
  `GDPR.md` §1 floors and the local regulator's floor; it is the only
  component with `DELETE` on `events`.

### 3.5 Vulnerability and patch handling

- **Keep a scan backend enabled** and a `ScanPolicy` in force (severity
  threshold, quarantine duration). Treat `scanBackends: []` as a
  deliberate, audited waiver, not a default.
- **Schedule the rescan and advisory-watch CronJobs** so released
  artifacts are re-adjudicated as advisories land; alarm on the
  `hort_advisory_diff_processed_total` direction-of-feed signals.
- **Run `cargo audit` discipline on the deployment image** by tracking the
  hort release line — advisory gating is a blocking CI control upstream.

### 3.6 Supply-chain integrity (central to automotive)

- **Rely on mandatory upstream verification** — it is on by construction;
  a format that cannot verify a checksum cannot proxy.
- **Enable provenance verification for supplier dependencies.** Pin a
  Sigstore `trusted_root.json` into the worker, enable the cosign
  verifier, and set `provenanceMode` + `provenanceIdentities` per scope.
  Use `required` (with the verifier enabled) on scopes you control;
  `verify_if_present` is the proxy-safe default.
- **Restrict upstreams** with `HORT_UPSTREAM_ALLOWLIST_HOSTS` and pin
  internal-mirror certs where the threat model warrants it.

### 3.7 Backup, recovery and incident response

- **Back up Postgres and the CAS backend** (operator-owned). The event log
  is the system of record; restore-from-backup of a corrupted blob is the
  recovery path the scrub's `tombstone` action assumes.
- **Drive incident response off the durable signals.** Auth-failure
  events with `client_ip`, the `result`-labelled auth metrics, and the
  per-job provenance/scan `result_summary` are the forensic trail; the
  organisation owns the IR process, timelines, and reporting.

### 3.8 Change management

- **Manage `$HORT_CONFIG_DIR` as code**, review changes through the normal
  code-review process, and rely on apply-time linting / strict Helm schema
  to fail dangerous changes fast. Migrations are a separately-privileged,
  explicit deployment step.

---

## 4. Audit / assessment evidence

What a TISAX assessor (AL 2 / AL 3) can collect from a running hort
deployment, and where it comes from:

| Evidence | How to collect | Demonstrates |
|---|---|---|
| Tamper-evident event-log export | Read-only export of `events` rows for an artifact/policy/actor; `hort-server verify-event-chain --format json` | Immutable, attributed decision history (log integrity, change management) |
| Provenance & scan verdicts | The per-job `result_summary` on `jobs` rows; `ProvenanceVerified`/`ProvenanceRejected` and `ScanCompleted` events; `hort_provenance_verify_total` / scan metrics | Supplier-dependency verification and supply-chain gating are enforced, not theatre |
| RBAC and config as code | The `$HORT_CONFIG_DIR` gitops tree + its version-control history; the authz audit stream (`ClaimMappingApplied`, `PermissionGrantApplied`, …) | Access control is declarative, reviewed, and audited |
| Cryptographic posture | `HORT_DATABASE_URL` resolves to `hort_app_role`; absence of any `*_INSECURE_TLS` knob; CAS keys equal content hashes; `hort-server scrub` exit code | Integrity and confidentiality controls are active |
| Monitoring & retention | The `hort_*` metric surface; the retention runner's schedule and owning role; `hort_event_chain_verify_overdue` | Security events are monitored and bounded per a documented schedule |
| Deployment hardening | The security-hardening checklist's per-control `kubectl`/`curl` one-liners (pod securityContext, metrics auth, three-role Postgres, HSTS, NetworkPolicy) | The shipped deployment matches the documented hardened baseline |

---

## 5. Limitations and operator / organisational responsibilities

What hort does **not** cover. None of these are roadmap gaps to be
hand-waved — they are out-of-component by design, and the **organisation**
owns them within the assessed scope:

- **Physical and environmental security** — facilities, media handling,
  device control. Entirely the organisation's.
- **Prototype-protection physical/organisational controls** — secured
  areas, vehicle/component handling, photography bans, visitor control,
  contractual confidentiality. hort supports only the information-security
  facet (§2.9); the physical regime is out of scope.
- **Personnel security** — screening, training, awareness, joiner/mover/
  leaver processes. The IdP and HR processes own identity lifecycle; hort
  only consumes the resulting claims.
- **TLS termination, HSTS, and edge DDoS** — the reverse proxy's job;
  hort's per-IP rate limiting absorbs small-scale abuse only.
- **A full SIEM / log-correlation platform** — hort emits durable events
  and structured logs; correlation, alerting, and long-term storage are
  the operator's log pipeline.
- **Key custody and a key-management system** — hort reads secret bytes
  from an operator-wired file/env var; generation, storage, rotation
  policy, and HSM/KMS integration are the operator's.
- **Backup execution and disaster-recovery testing** — hort assumes the
  operator backs up Postgres + CAS and tests restores.
- **The ISMS and the assessment process itself** — risk management,
  supplier-risk governance, coordinated-vulnerability-disclosure policy,
  incident-reporting timelines, the TISAX engagement and its evidence
  package. A control inventory is not an ISMS and is not a conformity
  assessment.
- **Multi-tenant workload isolation** — repositories are scoped and
  authorized, but workload isolation between tenants on a shared
  deployment is out of scope today
  ([security.md](../architecture/explanation/security.md) "Operator
  responsibilities").

---

## 6. Document maintenance

This document is a mapping aid for assessors and operators, not a
normative control of hort's runtime. It must be revised when a mapped
capability materially changes (a new provenance mode, a retention-floor
change, a new auth mechanism) or when the VDA ISA catalogue revision an
assessment targets changes the relevant control areas. Material changes
should be recorded as a CHANGELOG entry under the release in which they
ship.

Reviewers: the operator's information-security officer / TISAX engagement
owner; the security maintainer of the hort project.
