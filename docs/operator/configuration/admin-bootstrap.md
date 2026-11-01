# Bootstrap administrator access

Use the bootstrap mechanism **only** to establish the first administrator or recover access when the configured identity provider is unavailable. Normal administration should use human OIDC login with a group-to-claim mapping.

## Prerequisites and safeguards

- You control the target installation and have authorized access to its PostgreSQL connection settings.
- Run the command **on a trusted operator host**, with the same deployment configuration used by the target server.
- Restrict shell access, logs and command output: the bootstrap operation returns a privileged credential.
- Arrange a short maintenance window or restricted operator session and prepare the permanent OIDC configuration first.

## Create a short-lived bootstrap session

The command is gated by **both** database access and `HORT_TOKEN_ALLOW_ADMIN=true`:

```bash
# Run only in a trusted operator shell with the correct database settings.
HORT_TOKEN_ALLOW_ADMIN=true hort-server admin bootstrap-session --ttl 1h
```

Handle the returned credential as a secret. Do not paste it into issue trackers, chat or shell history. The bootstrap credential has a maximum lifetime of one hour and is not a standing service-account identity.

## Configure regular administrator login

Configure your group-capable OIDC provider and declare a claim mapping:

```yaml
apiVersion: project-hort.de/v1
kind: ClaimMapping
metadata:
  name: admins
spec:
  idpGroup: hort-admins
  claim: admin
```

Validate the complete configuration directory:

```bash
HORT_CONFIG_DIR=/path/to/config hort-server validate-config --strict
```

Deploy it, restart `hort-server`, and have an authorized member of `hort-admins` log in using `hort-cli auth login`. Verify administrator operations with the regular OIDC session **before** retiring the bootstrap session. The identity provider must actually emit the `groups` claim: Dex configured with `staticPasswords` alone does not.

## After access is restored

- End use of the bootstrap credential and protect or clear any temporary files containing it.
- Disable the bootstrap capability again outside an explicitly authorized recovery procedure.
- Verify that non-admin users and service accounts **cannot** perform administrator operations.
- Document an operational recovery procedure without recording privileged tokens.

Service accounts cannot be administrators; do not replace OIDC administration with a long-lived service token. See [Identity & access](identity-access.md) and [Declarative configuration](declarative.md).
