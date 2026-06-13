# GDPR compliance — retention, erasure exemption, and ROPA

This document is the formal data-protection record for the hort
event log. It exists so that a Data Protection Authority (DPA) auditor, a
customer DPO, or an internal compliance reviewer can validate the
deployment's lawful basis for retaining authentication, authorization, and
artifact-lifecycle events past the point at which the underlying user
account is deleted.

The technical design of the event log is described in
[`docs/architecture/explanation/event-sourcing.md`](../architecture/explanation/event-sourcing.md);
the security posture and trust boundaries in
[`docs/architecture/explanation/security.md`](../architecture/explanation/security.md).
This document is the legal artefact that complements those engineering
explainers.

**Applicable regulations cited throughout:**

- **GDPR** — Regulation (EU) 2016/679. Articles 5 (principles relating to
  processing), 6 (lawfulness of processing), 17 (right to erasure), 30
  (records of processing activities).
- **NIS2** — Directive (EU) 2022/2555. Article 21(2)(h) — logging of
  security-relevant events with tamper-resistance.
- **CRA** — Regulation (EU) 2024/2847 (Cyber Resilience Act). Annex I
  §1(j) — secure-by-default attestation.

The combination of NIS2 Art 21(2)(h) and CRA Annex I §1(j) constitutes the
"legal obligation" within the meaning of GDPR Art 17(3)(b) that releases
the event log from the right-to-erasure flow described in GDPR Art 17(1).

---

## 1. Retention schedule per event category

The event log distinguishes three retention tiers. Each tier reflects a
different regulatory or operational driver. Tiers are minimums; operators
are free to retain longer where their own jurisdiction or sector regulator
imposes stricter floors (e.g. financial services, healthcare).

| Event category | Minimum retention | Driver |
|---|---|---|
| `Authentication*` (`AuthenticationAttempted`, `OidcKeyRotated`) | **6 months** | NIS2 Art 21(2)(h) — incident-investigation horizon. The competent authority's typical request-for-records window in a post-incident review of a security event is 90 to 180 days; six months covers it with margin. |
| `Policy*`, `Authorization*`, `Admin*` (`PolicyCreated`, `PolicyUpdated`, `PolicyArchived`, `PolicyReactivated`, `ExclusionAdded`, `ExclusionRemoved`, `ClaimMappingApplied`, `ClaimMappingRevoked`, `PermissionGrantApplied`, `PermissionGrantRevoked`, `AdminStatusChanged`) | **36 months** | CRA Annex I §1(j) — secure-by-default attestation. The vendor must, on request, demonstrate that the deployed authorization model and secure-default posture were correctly applied at any point in the product's supported life. The 36-month figure is anchored to the typical CRA support obligation for a product release. |
| `Artifact*` (excluding `ArtifactDownloaded`) — `ArtifactIngested`, `ArtifactQuarantined`, `ScanCompleted`, `ArtifactReleased`, `ArtifactPromoted`, `ArtifactCorrupted` | **36 months** | Co-located with the authorization tier: an artifact's lifecycle is the supply-chain attestation surface. The CRA ships with the product; the artifact-event tail proves the product shipped. |
| `ArtifactDownloaded` | **90 days** | Operational-only, high-volume. No regulatory floor applies; the event is retained long enough to support short-term incident triage and metric reconciliation. |

### Storage substrate

All categories share one Postgres event-store table (`events`). Retention
is enforced by an out-of-process retention runner that deletes **whole event
streams** once their category's floor has elapsed: `delete_stream` emits a
`StreamSealed` tombstone and removes the stream's rows
(`DELETE FROM events WHERE stream_id = $1`) under the dedicated retention
role — never a per-row delete, which would break the per-stream hash chain.
The runner is the single component with `DELETE` privilege on `events`; the
application role does not. Append-only is enforced at the database level by a
row-level trigger. The per-stream hash chain makes the audit log
**tamper-evident, not tamper-proof**: an out-of-band mutation cannot be applied
silently — it is detectable by the offline event-chain verifier — but the chain
*detects* tampering rather than preventing it.

The retention runner is not part of hort's runtime. It is a
deployment concern — see the operator guide for the recommended cron
schedule and the role that owns it.

### Operator override

Operators MAY extend retention indefinitely. Operators MAY NOT shorten
retention below the figures above without first updating this document and
documenting the lawful basis for the shortened window. The retention
runner MUST be configured against the longer of (a) the floor in this
document and (b) the operator's local regulator's floor.

---

## 2. Erasure-exemption rationale (GDPR Art 17(3)(b))

GDPR Art 17(1) gives the data subject a right to obtain from the
controller the erasure of personal data concerning them. Art 17(3) lists
the exemptions; subsection (b) covers processing necessary "for compliance
with a legal obligation which requires processing by Union or Member State
law to which the controller is subject".

Two such legal obligations apply concurrently:

1. **NIS2 Art 21(2)(h)** requires "policies and procedures regarding the
   use of cryptography and, where appropriate, encryption" *and* "security
   procedures for employees with access to sensitive or important data,
   including data access policies". The recital text and the national
   transpositions consistently interpret this as a tamper-resistant
   logging mandate covering authentication events, authorization changes,
   and security-relevant administrative actions. A log that is mutable at
   a per-record granularity by a downstream actor (the data subject)
   cannot satisfy the tamper-resistance requirement.

2. **CRA Annex I §1(j)** requires that products with digital elements
   "be designed, developed and produced to limit attack surfaces,
   including external interfaces" and that the manufacturer can attest to
   the secure-by-default state across the supported life of the product.
   A configuration log that can be selectively rewritten by a former
   employee or contractor cannot underpin such an attestation.

The hort event log is therefore exempt from the right to
erasure for the categories listed in §1 above, for the retention window
listed in §1, on the legal basis of Art 17(3)(b).

### Scope of the exemption

The exemption covers **only** the event log. It does **not** extend to
the live operational records on which a subject access request would
otherwise act:

| Data | Subject access | Erasure |
|---|---|---|
| Live `users` row (display name, email, IdP subject claim) | yes — admin tooling | yes — admin tooling, on request |
| Active sessions / API tokens | yes — `GET /api/v1/users/me/tokens` | yes — `DELETE /api/v1/users/me/tokens/:id`, immediate |
| Event log entries referencing the user's UUID | yes — read-only export | **no** — Art 17(3)(b) exemption applies |
| Operational metrics (`hort_*`) | not applicable — no PII | not applicable |

When a user is deleted from the live `users` table, the event log retains
the `user_id: Uuid` reference. The UUID is not, by itself, personal data
under the GDPR's identifiability test once the live row is gone: there is
no ordinary path to re-associate the UUID to a natural person without the
live row's email/sub claim. (The IdP retains its own mapping, but that
mapping is the IdP's controllership, not the hort deployment's.)
This is the pseudonymization stance described in §4 below.

---

## 3. Records of Processing Activities (ROPA) — Art 30 outline

GDPR Art 30 requires the controller to maintain a record of processing
activities under its responsibility. The following table is the
hort-specific extract; operators MUST integrate it into the
deployment's overall ROPA register.

### Processing activity: hort event log

| Field | Value |
|---|---|
| **Name of the processing activity** | Audit logging for hort authentication, authorization, and artifact lifecycle events |
| **Purposes of the processing** | (1) Security incident detection and response (NIS2 Art 21). (2) Authorization-model and policy-evaluation attestation (CRA Annex I §1(j)). (3) Operational reconciliation of artifact lifecycle (download counts, quarantine outcomes). |
| **Categories of data subjects** | (a) Operators and administrators of the deployment. (b) Authenticated end-users publishing or downloading artifacts. (c) Anonymous clients whose authentication failed (logged by `client_ip` only). |
| **Categories of personal data** | User UUID (`user_id: Uuid`); on a *failed* authentication, the attempted IdP subject identifier (`external_id_if_decoded` — the JWT `sub`); IP address of the requesting client (`client_ip: IpAddr`); IdP issuer URL (on OIDC-issuer-config and federation-exchange events); group-claim label strings (on claim-mapping events). **Not stored:** email, username, display name, password, password hash, JWT body, JWKS material, user-agent string. |
| **Categories of recipients** | Internal: SRE / SecOps / IR teams via the SIEM forwarder. External: the operator's chosen log shipper / SIEM vendor (sub-processor — see below). |
| **Transfers to third countries** | Determined by the operator's choice of storage and SIEM vendor. The hort deployment itself does not initiate cross-border transfers; it writes to the operator-controlled Postgres instance. |
| **Retention periods** | Per §1 of this document. |
| **Technical and organisational measures** | Append-only event store enforced by Postgres trigger owned by a separate role. `DELETE` privilege on `events` held only by the retention-runner role. Application role has `INSERT`/`SELECT` only. TLS in transit (operator-terminated). At-rest encryption is the storage substrate's concern. Pseudonymization at-write per §4. |

### Sub-processors

The hort deployment passes log data to the operator's chosen:

- **Storage backend** — the Postgres instance itself. Operator-managed
  (RDS / Cloud SQL / on-prem cluster). Operators MUST ensure the
  storage-substrate provider is listed as a sub-processor in their
  customer-facing DPA where applicable.
- **SIEM / log shipper** — Splunk, Loki, Elastic, Datadog, etc. The
  hort binary does not push events directly to SIEM; the
  operator's log pipeline does, typically by tailing Postgres or by
  reading the `tracing` JSON line stream. The chosen SIEM is therefore a
  sub-processor under the operator's DPA, not under any DPA between the
  customer and the hort project.
- **Identity Provider (IdP)** — the OIDC issuer pinned at
  `HORT_OIDC_ISSUER_URL`. The IdP is the controller for the IdP-side
  identity record (email, `sub` claim, group membership). Within the
  hort deployment, the IdP is the upstream from which the
  user UUID is JIT-provisioned; group-claim values land in the event log
  only as labels, never as the IdP-side primary keys.

The hort project itself is not a sub-processor — it is
software the operator deploys. Any commercial relationship (support,
hosting) imposed on top of the open-source distribution is between the
operator and the support vendor and is out of scope for this document.

---

## 4. PII pseudonymization stance

Pseudonymization (GDPR Art 4(5)) is the design property that personal
data can no longer be attributed to a specific data subject without the
use of additional information held separately and subject to technical
and organisational measures that ensure non-attribution.

### Identifier policy

The event log identifies the actor of every successfully recorded event
by **`user_id: Uuid`**, never by email address, username, or display
name. The one exception is a *failed* authentication, which records the
*attempted* identity (`external_id_if_decoded` — the JWT `sub`) so an
incident investigator can see who tried to authenticate; that value is a
pseudonymous IdP subject identifier, re-associable to a natural person
only via the IdP, not from inside the hort deployment. The mapping
`user_id → email` lives in the live `users` table; once that row is
deleted, the UUID is a bare opaque identifier with no ordinary path back
to a natural person from inside the hort deployment.

This is not full anonymization — the IdP retains its own
`Uuid → IdP-sub` mapping, and an operator who runs both the IdP and the
hort deployment has the additional information needed to
re-identify. But the hort event store, taken in isolation, is
pseudonymized within the meaning of Art 4(5).

### Concretely, the event log NEVER contains

- email addresses
- usernames or display names
- token hashes (Argon2id) or any credential-derived material
- raw JWTs, refresh tokens, or any bearer credential
- JWKS key bytes
- session tokens or cookies
- bind values from outbound SQL queries

Enforcement is partly structural (the event types in
`crates/hort-domain/src/events/` do not have fields for these) and partly
by `Debug` impls that redact secret-bearing values. See
[`docs/architecture/explanation/security.md`](../architecture/explanation/security.md)
"Secrets hygiene" for the engineering-side rules.

### `client_ip` on auth-failure events

`AuthenticationAttempted` events carry `client_ip: IpAddr` for both
successful and failed attempts. This is intentional and load-bearing for
NIS2 incident response: the incident-response horizon for an attack on
the authentication surface is "did this IP probe other services in the
same time window", and that question is unanswerable without a stable
IP attribution.

The 2026-04-30 security audit recorded a Low-severity observation
(**L-9**) that the IP also lands in `tracing::info!` on every auth
failure. The disposition is documented-as-accepted. The rationale:

1. The throttle that exists on `hort_auth_events_appended_total`
   (per-(client_ip_bucket, result), 60s window) operates at the event
   store, not at the tracing layer. The tracing emission is
   per-attempt by design; SIEM-side throttling happens at the operator's
   log pipeline.
2. NIS2 Art 21(2)(h) requires logging of authentication failures with
   sufficient detail to support incident investigation. Stripping
   `client_ip` from the tracing line would defeat that.
3. GDPR Art 5(1)(c) (data minimization) is satisfied: the IP is the
   minimum identifier needed for the security purpose; no broader
   identifier (e.g. user-agent + cookie + fingerprint) is logged in
   addition.

The `client_ip` field is included in the retention window of §1 above
(6 months for `Authentication*` events). On expiry the row is deleted
by the retention runner.

### `client_ip` and the dynamic-IP edge case

For ISP-assigned dynamic IPs the IP is attributable to the ISP customer
only via ISP-side records that the hort deployment does not
hold. The deployment treats `client_ip` as an opaque network identifier,
not as a direct identifier of a natural person. A subject access request
that names a natural person cannot be served by IP correlation alone;
the requestor must supply the user UUID (recoverable via the IdP) for
the request to be actionable against the event log.

---

## 5. Subject access request (SAR) playbook

The deployment operator is the controller for SAR purposes. The
hort project provides the technical mechanism; the operator
provides the legal handling.

### Discovery

Given a verified data-subject request:

1. Resolve the subject's `user_id` from the IdP (or from the live
   `users` table for local accounts).
2. Query the event log for all entries referencing that UUID. The
   admin / DPO tooling for this is operator-defined; a representative
   query is:

   ```sql
   SELECT * FROM events
    WHERE actor_id = $1::uuid
       OR event_data @> jsonb_build_object('user_id', $1::text)
    ORDER BY stored_at;
   ```

3. Export the rows in the format mandated by the operator's local
   regulator (typically machine-readable JSON or CSV).

### Erasure

Erasure of the live `users` row, active sessions, and API tokens is
unconditional and follows the operator's existing user-deletion flow.

Erasure of the event log entries is **refused** under GDPR Art 17(3)(b)
on the legal basis described in §2. The refusal must be communicated to
the subject in writing, citing the legal basis and the retention window
after which the record will be deleted by the retention runner.

### Rectification

Event log entries are immutable by design (Art 16 rectification). The
correct response to "this event mis-attributes me" is a new corrective
event, not a mutation of the existing row. The operator's incident
process owns the corrective-event mechanism; the project does not ship
a generic "rectification" event variant.

---

## 6. Document maintenance

This document is normative. Material changes (retention floor changes,
new event categories with PII implications, sub-processor changes) MUST
be recorded as a CHANGELOG entry under the release in which they ship,
and the "Last reviewed" date below MUST be updated.

Reviewers: the operator's DPO; the security maintainer of the
hort project.
