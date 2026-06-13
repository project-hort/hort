# Configuring your IdP for hort-cli OIDC login

`hort-cli auth login` uses OAuth 2.0 RFC 8628 (device-code flow) to obtain an
**access_token** from your identity provider (IdP), and then exchanges it
for a CLI-session token at the hort server (`/api/v1/auth/exchange`, RFC 8693).

hort-server validates that access_token and resolves the user from its `sub`
claim. **If `sub` is absent from the access_token, login fails with
`HTTP 401 invalid_token: subject_token invalid` (server side) or
`IdP returned no access_token ...` (CLI side).**

The standards-shaped fix is on the IdP, not in hort-cli: configure your
OAuth client so its access_tokens carry a `sub` claim. This page lists
recipes for the IdPs we test against.

> **Why access_token and not id_token?** `access_token` is OAuth's
> canonical "use this to call APIs" credential (RFC 6749) with
> `aud = resource_server`, matching `HORT_OIDC_AUDIENCE`. `id_token` is
> OIDC's "prove to the OAuth client that the user authenticated" credential
> (OIDC Core §2) with `aud = client_id`, which conflicts with hort's
> single-audience validator — so `subject_token_type` is `access_token` only.

---

## Keycloak 26 — declarative setup (recommended)

Enterprise operators run Keycloak via GitOps: the realm definition is
checked into source control and applied declaratively, not edited
through the Admin Console. This section is the canonical setup recipe
for Keycloak 26. The `realm.json` fragment below is the source of
truth; the tooling that applies it is interchangeable (Helm import on
startup, `keycloak-config-cli`, Terraform, or the Keycloak Operator).
The "Keycloak — verification and legacy realms" section that follows
covers auditing an existing realm and operating on realms that
pre-date this workflow; it is **not** the primary setup path.

### The `hort-cli` client (realm.json fragment)

Add the following entry to the `clients[]` array of your
`realm.json`. The same fragment ships in
`deploy/compose/keycloak/realm.json` as part of the worked-example realm:

```json
{
  "clientId": "hort-cli",
  "name": "hort-cli",
  "description": "Hort CLI — public OAuth client for RFC 8628 device flow and RFC 8252 loopback flow",
  "enabled": true,
  "protocol": "openid-connect",
  "publicClient": true,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "authorizationServicesEnabled": false,
  "fullScopeAllowed": true,
  "redirectUris": [
    "http://127.0.0.1/*",
    "http://localhost/*"
  ],
  "webOrigins": [],
  "attributes": {
    "oauth2.device.authorization.grant.enabled": "true",
    "pkce.code.challenge.method": "S256",
    "post.logout.redirect.uris": "+"
  },
  "defaultClientScopes": ["openid", "profile", "email", "groups"],
  "optionalClientScopes": ["offline_access"],
  "protocolMappers": [
    {
      "name": "audience-hort-server",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "consentRequired": false,
      "config": {
        "included.client.audience": "hort-server",
        "id.token.claim": "false",
        "access.token.claim": "true"
      }
    }
  ]
}
```

Attribute groups, annotated:

- **Capability config.** `publicClient: true` means the client has no
  client secret — required for desktop CLIs that cannot keep one.
  `standardFlowEnabled: true` allows RFC 8252 loopback (authorization
  code + PKCE). `directAccessGrantsEnabled: false` and
  `serviceAccountsEnabled: false` disable the password and
  client-credentials grants — neither applies to a user-facing CLI.
  `implicitFlowEnabled: false` because implicit flow is deprecated by
  OAuth 2.1 and OAuth 2.0 BCP 240.
- **Device-grant attribute.** `oauth2.device.authorization.grant.enabled`
  is a client attribute (not a top-level boolean) in Keycloak 26.
  Setting it to `"true"` opts the client into RFC 8628 — the
  fallback the CLI uses for headless / SSH / CI environments.
- **PKCE attribute.** `pkce.code.challenge.method: "S256"` makes
  Keycloak **require** PKCE on the standard (auth-code) flow for
  this client. The realm-wide default is "permitted" not "required";
  the per-client attribute is the lever that enforces it.
- **Redirect URIs.** `http://127.0.0.1/*` and `http://localhost/*`
  cover the RFC 8252 loopback flow. Keycloak accepts a `*` wildcard
  on the port; one entry handles any ephemeral port the CLI binds.
  `post.logout.redirect.uris: "+"` is shorthand for "everything in
  `redirectUris` is also valid for post-logout."
- **Audience mapper.** The per-client `protocolMapper` of type
  `oidc-audience-mapper` rewrites the access token's `aud` claim to
  `hort-server`. Without this, Keycloak emits `aud = hort-cli` (the
  minting client), which fails hort's audience check. See "Audience
  configuration" below.

### Applying realm.json — pick one

#### 1. Helm chart with `--import-realm` / `KC_IMPORT_REALM=true`

For chart-based deployments. Mount `realm.json` into
`/opt/keycloak/data/import/` (the chart values typically expose this
as `extraVolumeMounts` or `realmImport.configMap`). Start Keycloak
with `--import-realm` or set `KC_IMPORT_REALM=true`. This is a
**one-time import on container startup**; subsequent edits to
`realm.json` are NOT reflected on a running cluster — they require a
pod restart or operator reconcile to take effect.

#### 2. `keycloak-config-cli` (adorsys)

Recommended for live updates. `keycloak-config-cli`
(https://github.com/adorsys/keycloak-config-cli) is a single container
that POSTs `realm.json` against the admin REST API. It is
idempotent, safe to re-run in a GitOps reconcile loop, and supports
live updates without restart. Minimal kubectl Job manifest:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: keycloak-config-apply
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: keycloak-config-cli
          image: adorsys/keycloak-config-cli:latest
          env:
            - name: KEYCLOAK_URL
              value: http://keycloak.keycloak.svc:8080
            - name: KEYCLOAK_USER
              value: admin
            - name: KEYCLOAK_PASSWORD
              valueFrom:
                secretKeyRef: { name: keycloak-admin, key: password }
            - name: IMPORT_FILES_LOCATIONS
              value: /config/realm.json
          volumeMounts:
            - { name: realm, mountPath: /config }
      volumes:
        - name: realm
          configMap: { name: hort-realm }
```

Apply with `kubectl create configmap hort-realm --from-file=realm.json`
then `kubectl apply -f job.yaml`. Re-run the Job (or wire it to a
GitOps controller like Argo CD / Flux) on every realm.json change.

#### 3. Terraform `keycloak/keycloak` provider

For operators who already manage infrastructure as Terraform code. Use the
**official** Keycloak-maintained provider, `keycloak/keycloak` — the Keycloak
project adopted the formerly-community `mrparkers/keycloak` provider in
December 2024, so `mrparkers/keycloak` is now the deprecated predecessor. Pin
the official provider in `required_providers`:

```hcl
terraform {
  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = ">= 5.8.0"
    }
  }
}
```

The provider docs are at
https://registry.terraform.io/providers/keycloak/keycloak/latest/docs.
Operators with existing state on the old provider migrate in place with
`terraform state replace-provider mrparkers/keycloak keycloak/keycloak`
(the resource schema is unchanged — same provider lineage). A minimal HCL
snippet matching the realm.json fragment:

```hcl
resource "keycloak_openid_client" "hort_cli" {
  realm_id                     = keycloak_realm.hort.id
  client_id                    = "hort-cli"
  name                         = "hort-cli"
  enabled                      = true
  access_type                  = "PUBLIC"
  standard_flow_enabled        = true
  direct_access_grants_enabled = false
  valid_redirect_uris          = ["http://127.0.0.1/*", "http://localhost/*"]
  pkce_code_challenge_method   = "S256"
  extra_config = {
    "oauth2.device.authorization.grant.enabled" = "true"
  }
}

resource "keycloak_openid_audience_protocol_mapper" "hort_cli_aud" {
  realm_id                 = keycloak_realm.hort.id
  client_id                = keycloak_openid_client.hort_cli.id
  name                     = "audience-hort-server"
  included_client_audience = "hort-server"
  add_to_id_token          = false
  add_to_access_token      = true
}
```

The project does not maintain a first-party Terraform module —
realm.json is the single source of truth and a Terraform module
would be a second one. Use the provider directly against the
fragment above.

#### 4. Keycloak Operator + `KeycloakRealmImport` CR

For Kubernetes-native deployments using the official Keycloak
Operator (https://www.keycloak.org/operator/realm-import). YAML CR
referencing a ConfigMap-mounted realm.json:

```yaml
apiVersion: k8s.keycloak.org/v2alpha1
kind: KeycloakRealmImport
metadata:
  name: hort-realm
  namespace: keycloak
spec:
  keycloakCRName: keycloak
  realm:
    realm: hort
    enabled: true
    clients:
      # Embed the realm.json contents here, or use spec.realm.<...>
      # to project a ConfigMap value into the CR via a templating
      # layer (Helm, Kustomize, Argo CD). See operator docs.
```

`KeycloakRealmImport` is **one-shot per CR object** — applying a
modified CR does not update an existing realm in place. Subsequent
updates require either deleting and recreating the CR, or moving to
`keycloak-config-cli` for declarative live updates. For most
production GitOps loops, recipe (2) is the better fit.

### Audience configuration

Keycloak's default behaviour is to set the access token's `aud`
claim to the client that minted it (the "minting client" — `hort-cli`
in this setup). hort-server validates the inbound token against
`HORT_OIDC_AUDIENCE`, which is set to `hort-server` in
`deploy/compose/keycloak/realm.json` and in the worked-example install
docs. Without an explicit audience mapper, hort rejects the token
with `OidcValidationError::AudienceMismatch`. The audience mapper
in the `hort-cli` client rewrites the access token's `aud` to
`hort-server` and matches.

There is an alternative: set `HORT_OIDC_AUDIENCE=hort-cli` on the
hort-server side and omit the audience mapper. This works, but it
muddies the audit story: every access token's `aud` claim names
the CLI rather than the resource server it is authorising access
to. The recommended setup uses an explicit `hort-server` audience
because it produces audit-log entries that map cleanly to "this
token was minted to call hort-server" — and the same access token
shape is emitted regardless of which OAuth client a user logged in
through. See `docs/architecture/how-to/deploy/install.md` §4 for
the equivalent `hort-server` audience-mapper rationale on the
confidential server-side client.

### Verification with `kcadm.sh`

`kcadm.sh` is Keycloak's bundled CLI. The recipes below **audit**
the applied configuration; they are not the recommended setup
path. Authenticate first with
`kcadm.sh config credentials --server <url> --realm master --user admin`.

Confirm the `hort-cli` client exists with the expected ID and
public-client flag:

```bash
kcadm.sh get clients -r hort -q clientId=hort-cli \
  --fields id,clientId,publicClient,standardFlowEnabled
```

Confirm the audience mapper resolves to `hort-server` (and not the
minting client's name):

```bash
kcadm.sh get clients/<id>/protocol-mappers/models -r hort \
  --fields name,protocolMapper,config
```

Confirm the device-grant and PKCE attributes are set:

```bash
kcadm.sh get clients/<id> -r hort \
  --fields 'attributes(oauth2.device.authorization.grant.enabled,pkce.code.challenge.method)'
```

---

## Keycloak — verification and legacy realms

This section covers two cases that fall outside the GitOps setup
path above: (a) auditing an existing realm to confirm the `sub`
claim mapper is present, and (b) operating on a legacy realm that
pre-dates the declarative tooling described in the previous
section. For a new deployment, follow "Keycloak 26 — declarative
setup (recommended)" instead.

Keycloak ships a built-in `sub` mapper that adds the user's subject to
access_tokens. It is part of the `basic` client scope, which is assigned
to new clients by default in **Keycloak 19 and later** — so a freshly
created `hort-cli` client usually works without any extra configuration.

If you have an older deployment, a stripped-down realm, or your operator
team has previously customised default scopes, verify the mapper is in
place:

1. Sign in to the Keycloak Admin Console for the realm hosting `hort-cli`.
2. Navigate to **Client scopes** → **basic** → **Mappers** tab.
3. Confirm a mapper named **sub** of type **User Property** or
   **Subject (sub)** is present.
4. Open the mapper and confirm **Add to access token** is **On**.
   (The `Add to ID token` and `Add to userinfo` toggles are independent
   and unrelated to hort.)
5. If the `basic` client scope is not in the `hort-cli` client's
   **Default Client Scopes** list (Clients → hort-cli → Client scopes),
   add it.

After saving, run `hort-cli auth login` again. The "Validation" snippet at
the bottom of this page lets you confirm the claim is present before
re-running the CLI.

---

## Okta

Okta has two flavours of authorization server, and they behave
differently:

- **Custom Authorization Server** (recommended for hort): access_tokens
  include `sub` by default. No extra configuration needed.
- **Org Authorization Server** (the default `default` AS that ships with
  every Okta tenant): access_tokens do **not** include `sub` in the
  standard claim set; only `uid` and a few Okta-specific claims appear.

Recommendation: create a Custom Authorization Server for hort (Security →
API → Authorization Servers → Add Authorization Server) and use its
issuer URL as `HORT_OIDC_ISSUER_URL`. The default access_token policy
already includes `sub`; verify with the snippet below before configuring
hort-cli.

If you must use the Org Authorization Server, add a custom access_token
claim mapping `sub` to `user.id` (or `user.login`, depending on what you
want hort's stored `external_id` to look like) under **Token Preview** →
**Claims**.

---

## Auth0

Auth0 omits `sub` from access_tokens by default unless a custom API
audience is configured for the OAuth client. The fix:

1. In the Auth0 dashboard, open **Applications** → **APIs** and create
   an API for hort (or reuse an existing one). Note its **Identifier** —
   this is the value you pass to `HORT_OIDC_AUDIENCE` on the hort side.
2. In **Applications** → your `hort-cli` application → **APIs** tab,
   authorise the new API.
3. When `hort-cli` requests a device-code with the API audience, Auth0
   issues a real JWT access_token (instead of the opaque token it would
   issue otherwise), and `sub` is included.

See the Auth0 documentation on "API audience" and "JWT access tokens"
for the canonical reference. The `audience` parameter is automatically
included by `hort-cli` when the discovery doc's
`exchange.subject_token_types_supported` lists `access_token`.

---

## Microsoft Entra ID (formerly Azure AD)

Microsoft Entra ID does include `sub` in access_tokens, but it is
**pairwise-hashed per application registration**. The same user logging
in through two different Entra app registrations receives two different
`sub` values; the values are stable per app but cannot be correlated
across apps. This is intentional Entra behaviour, not a bug.

What this means for hort:

- The `external_id` hort stores against the JIT-provisioned user is the
  per-app pairwise `sub` for whichever Entra app `HORT_OIDC_CLI_CLIENT_ID`
  refers to.
- Re-registering hort-cli as a new Entra app changes every user's `sub`,
  effectively orphaning all `external_id` rows — the JIT path will
  provision a new user record on next login. Plan registration changes
  accordingly.
- Cross-tenant correlation is impossible by design. If your operational
  workflow depended on it (e.g. correlating hort audit events with another
  app's logs by `sub`), key on `email` or `username` instead.

No mapper configuration is needed; Entra is fine out of the box for
single-app deployments.

---

## Validation

Before configuring hort-cli, confirm the IdP issues an access_token with a
`sub` claim. Run a device-code flow manually and decode the resulting
access_token's payload:

```bash
# Replace <issuer> and <client_id> with your values, then follow the
# verification_uri prompt in a browser to authorise the device code.
ISSUER='https://idp.example.com/realms/hort'
CLIENT_ID='hort-cli'

curl -sS -X POST "$ISSUER/protocol/openid-connect/auth/device" \
  -d "client_id=$CLIENT_ID" -d 'scope=openid profile email'
# → note the device_code, then visit verification_uri, log in, then:

curl -sS -X POST "$ISSUER/protocol/openid-connect/token" \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  -d "device_code=<paste-from-above>" \
  -d "client_id=$CLIENT_ID" \
  | jq -r .access_token \
  | jq -R 'split(".") | .[1] | @base64d | fromjson'
```

The decoded payload should contain a `sub` field, for example:

```json
{
  "exp": 1715450000,
  "iat": 1715446400,
  "iss": "https://idp.example.com/realms/hort",
  "aud": "hort-server",
  "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "preferred_username": "alice",
  "email": "alice@example.com"
}
```

If `sub` is missing, follow the IdP-specific recipe above. If `sub` is
present but `aud` does not match your `HORT_OIDC_AUDIENCE` value, that is
a separate issue — see the audience configuration notes in your IdP's
documentation.

Once `sub` is present, `hort-cli auth login --server https://hort.example.com`
should complete successfully.

---

## Configuring redirect URIs for the loopback flow

`hort-cli` defaults to the **RFC 8252 loopback-redirect flow** (BCP 212) on
desktops, and falls back to the RFC 8628 device flow on headless / SSH /
CI sessions. Whichever flow is picked, the OAuth client must accept the
loopback's `http://127.0.0.1:<ephemeral-port>/callback` (or `[::1]` IPv6
form) as a registered redirect URI. Recipes per IdP:

### Keycloak

Add both patterns to the `hort-cli` client's **Valid redirect URIs** list:

- `http://127.0.0.1/*`
- `http://localhost/*`

Keycloak accepts the `*` wildcard on the port — the same client entry
handles any ephemeral port the CLI binds.

### Okta

Okta does **not** accept a wildcard port in the redirect URI. The CLI
binds an OS-allocated ephemeral port (no fixed-port knob exists), so
there is no single URI to register. The recommended workaround is to
register a set of explicit URIs (e.g. `http://127.0.0.1:8000` through
`http://127.0.0.1:8020`) and instruct users to use `--flow=device`
instead, which has no redirect URI and no listener:

```bash
hort-cli auth login --flow=device --server https://hort.example.com
```

Alternatively, if your Okta tenant supports it, the PKCE loopback flow
may be combined with a wildcard-port URI configured via the Okta admin
API (not available in the UI as of Okta Classic). Without one of these
approaches, Okta will reject the redirect with `invalid_request:
redirect_uri did not match a registered URI`.

### Auth0

Add `http://127.0.0.1` to the **Allowed Callback URLs** field on the
`hort-cli` application — the `127.0.0.1` entry covers any port. Auth0's
behaviour parallels Keycloak's wildcard handling.

### Microsoft Entra ID (formerly Azure AD)

Register `hort-cli` as a **"Public client / native (mobile & desktop)"**
application:

1. **App registrations** → **New registration** → set "Supported account
   types" appropriately, and choose **"Public client/native (mobile &
   desktop)"** under "Redirect URI" with the value `http://localhost`.
2. Under **Authentication**, ensure **"Allow public client flows"** is
   set to **Yes** (required for PKCE without a client secret).

Entra's "public client" redirect type accepts `http://localhost` with any
port; no port pinning is needed.

### Falling back to device flow

If your IdP cannot be configured for loopback (locked-down corporate
tenant, no wildcard support, etc.), force the device flow on every
invocation:

```bash
hort-cli auth login --flow=device --server https://hort.example.com
```

Or set the default per shell via:

```bash
alias hort-cli='hort-cli --flow=device'
```

The device flow has no redirect URI and no listener — it works in every
environment but requires the user to copy a code from the terminal to a
browser tab. The CLI auto-detects headless / SSH / CI environments and
selects device flow without an explicit `--flow=device`.
