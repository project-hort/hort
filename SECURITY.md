# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (development) | Yes |
| Latest release tag | Yes |
| Older releases | No |

## Reporting a Vulnerability

We take security seriously. **Please do not open a public issue for a
vulnerability.** Instead, report it privately:

> Use **GitHub private vulnerability reporting**: open the
> [Security tab](https://github.com/project-hort/hort/security) of the
> repository and click **"Report a vulnerability"**. The report stays
> visible only to the maintainers.

If possible, include:

- Description of the vulnerability
- Steps to reproduce
- Affected components (the `hort-server` API, auth, storage, a specific
  format handler, the event store, etc.)
- Potential impact assessment
- Suggested fix or patch, if available

## What to Expect

- **Acknowledgment** within 72 hours of your report
- **Initial assessment** within 1 week
- **Fix timeline** depends on severity — critical issues are prioritized immediately

We will coordinate disclosure with you and credit reporters in the release notes
(unless you prefer to remain anonymous).

## Scope

### In scope

- The `hort-server` API and the per-protocol format handlers (OCI, npm, PyPI,
  Cargo) — upload, download, and pull-through proxy paths
- Authentication and authorization — see [`docs/auth-catalog.md`](docs/auth-catalog.md)
  for the canonical inbound-auth control spec
- Content-addressed storage and storage backends (filesystem, S3)
- The event store and the tamper-evident event chain
- Container images published to `ghcr.io/project-hort/*`

### Out of scope

- The public demo instance (report issues, but no bounties)
- Third-party dependencies (report upstream, but let us know if it affects us)

## Security Best Practices for Operators

See [`docs/architecture/how-to/deploy/security-hardening-checklist.md`](docs/architecture/how-to/deploy/security-hardening-checklist.md)
for the full checklist. In brief:

- Always run behind a reverse proxy with TLS.
- Use the least-privilege two-role Postgres setup (the runtime role holds no
  DDL; migrations run as a separate role) — see
  `docs/architecture/how-to/deploy/postgres-roles.md`.
- Trust internal CAs via `HORT_EXTRA_CA_BUNDLE` (never an `*_INSECURE_TLS` knob).
- Regularly rotate signing keys and credentials.
- Keep your instance updated to the latest release.
