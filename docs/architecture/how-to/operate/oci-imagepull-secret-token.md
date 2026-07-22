# Mint a least-privilege reader token for a Kubernetes `imagePullSecret`

This guide is for operators who need kubelet/containerd to pull a **private**
OCI image from Hort — the standard `imagePullSecrets` flow, with a
purpose-minted, read-only `hort_svc_*` token as the credential. It is the
manual, one-shot minting recipe: run it once, hand the Secret to the
namespace, done. It does not set up automatic rotation — see
[`rotating-service-account-tokens.md`](../rotating-service-account-tokens.md)
if you want the worker to refresh the credential on a schedule instead.

For the design background — why a bare unauthenticated pull of a private
image now gets a `401` challenge instead of a silent `404` — see
[ADR 0045](../../../adr/0045-oci-read-challenge-before-anti-enum.md). For the
service-account authority model this recipe relies on, see
[ADR 0044](../../../adr/0044-service-accounts-identity-only.md) and
[ADR 0037](../../../adr/0037-gitops-service-account-grant.md).

---

## 1. When to use this

Prefer
[`federate-k8s-workload-identity.md`](../federate-k8s-workload-identity.md)
when the pulling workload can present a projected Kubernetes ServiceAccount
token to `/api/v1/auth/exchange` — no static credential to store, no
rotation discipline. This recipe is for the common case where that is not
available: kubelet itself has no OIDC exchange step, so any
`imagePullSecrets`-based pull needs a static bearer sitting in a Secret.

Use this recipe when you need:

- A **read-only** credential scoped to exactly one (or a small, named set of)
  repositories, for pulling private images via `imagePullSecrets`.
- A **manually managed** token — you mint it once, rotate it by hand when
  you choose to, and there is no worker reconciler watching it.

If you want the credential refreshed automatically on a fixed cadence
instead, use the `fallbackRotation` flow in
[`rotating-service-account-tokens.md`](../rotating-service-account-tokens.md)
§3/§5 (its `dockerconfigjson` section covers the same consumer shape, wired
to the worker's `ServiceAccountRotationHandler` instead of a one-off CLI
mint).

---

## 2. Step 1 — declare the reader identity and its grant

A `ServiceAccount` envelope is identity-only; it confers no authority by
itself (ADR 0044). The read authority comes from a `serviceAccount`-subject
`PermissionGrant` declared beside it (ADR 0037). This SA needs neither
`federatedIdentities` nor `fallbackRotation` — it is the "PAT-only identity"
shape, minted by hand via the CLI in step 2:

```yaml
apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: image-puller
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: image-puller-read
spec:
  subject:
    kind: serviceAccount
    name: image-puller
  permission: read
  repository: oci-internal
```

Apply this to the gitops tree the usual way. Two subject kinds exist for a
`PermissionGrant` and only one of them can ever match a service-account
token: a `serviceAccount`-subject grant (above) resolves at apply time to
`GrantSubject::User(backing_user_id)` — the same identity the minted token's
authority is evaluated against. A `claims`-subject grant, by contrast, can
**never** match an SA-minted token, because a service-account principal
always carries `claims: []` — there is no claim set for a `claims`-subject
grant to intersect with. Reaching for `kind: claims` here is a silent no-op:
the grant applies cleanly, but the reader token it was meant to authorize
still gets `403` on every pull. If you already have a grant like this and
reads are failing, check the `subject.kind` first.

---

## 3. Step 2 — mint the token

```bash
hort-server admin issue-svc-token \
  --name image-puller \
  --permission=read \
  --expires-in-days=365
```

This requires the `ServiceAccount` from step 1 to already exist (`sa:image-
puller` in `users`) — `issue-svc-token` never fabricates an identity; it
only mints a token for a pre-existing gitops-declared service account. The
plaintext `hort_svc_…` token prints to stdout once; capture it immediately,
it is never recoverable afterward (only its Argon2id hash is stored).

The mint log line looks like this:

```text
service-account token issued token_id=… name=image-puller kind=ServiceAccount user_id=…
```

and the issuance log line reports `declared_permission_count=1,
repository_count=0`. **`repository_count: 0` does NOT mean "this token can
read zero repositories."** `issue-svc-token` always mints with
`repository_ids: None`, and `None` is the **unrestricted** sentinel — it
means "no per-repo restriction on the cap leg; consult the grants leg for
scope" (ADR 0044). The token's actual repository scope comes entirely from
the `PermissionGrant` in step 1: it can read `oci-internal` because that
grant exists, and nothing else, because no other grant exists — not because
of anything encoded in the token's cap. Reading `repository_count: 0` as "no
access" is the most common misread of this log line; it is the *ceiling*
field reporting "no ceiling," not the *floor*.

---

## 4. Step 3 — build the `dockerconfigjson` Secret

`docker`/containerd's config format expects `auth` to be
`base64(<username>:<password>)`. Hort ignores the username on every Basic
carrier surface (`docs/auth-catalog.md` Entry 8) — the token in the password
slot is the only thing that is checked — so any placeholder username works;
`oauth` is the conventional choice registries use for opaque bearer-style
credentials:

```bash
TOKEN='hort_svc_…'                          # the plaintext from step 2
AUTH=$(printf '%s' "oauth:${TOKEN}" | base64 -w0)

cat > dockerconfig.json <<EOF
{
  "auths": {
    "registry.example.com:5443": {
      "username": "oauth",
      "password": "${TOKEN}",
      "auth": "${AUTH}"
    }
  }
}
EOF

kubectl create secret generic image-puller-secret \
  --namespace ci-system \
  --type=kubernetes.io/dockerconfigjson \
  --from-file=.dockerconfigjson=dockerconfig.json

rm dockerconfig.json   # do not leave the plaintext token on disk
```

Replace `registry.example.com:5443` with the registry host your image
references use — it must match the host portion of the image reference
byte-for-byte, or kubelet will not look up this Secret for the pull.

---

## 5. Step 4 — wire the workload

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: ci-system
spec:
  imagePullSecrets:
    - name: image-puller-secret
  containers:
    - name: app
      image: registry.example.com:5443/oci-internal/my-app:1.2.3
```

Or attach it to the namespace's default `ServiceAccount` so every Pod in the
namespace inherits it without repeating `imagePullSecrets` per Pod:

```bash
kubectl patch serviceaccount default -n ci-system \
  -p '{"imagePullSecrets": [{"name": "image-puller-secret"}]}'
```

---

## 6. Why the pull works

Before the OCI read-path challenge fix (ADR 0045), an unauthenticated
`GET`/`HEAD` of a private manifest returned a bare `404 NAME_UNKNOWN` — the
same response a nonexistent repository produces (ADR 0021's anti-enumeration
collapse). containerd's resolver requests the manifest with no credential
on the first try and only engages its authorizer — the code path that reads
`imagePullSecrets` and retries with `Authorization: Basic …` — when the
server answers `401` with a `WWW-Authenticate` challenge. A `404` gave it no
such signal, so the Secret above was never presented and the pull failed
with `fetch failed after status: 404` regardless of how correctly it was
configured.

The manifest endpoint now challenges every anonymous denied read with `401`
+ the deployment's mode-appropriate `WWW-Authenticate` scheme (`Basic
realm="hort"` in legacy/Basic-token deployments, `Bearer
realm=.../v2/auth,...` in native-token deployments). containerd's authorizer
reacts to either scheme the same way: it looks up the matching
`imagePullSecrets` entry by registry host and retries with the stored
credential. That retry is what completes the pull.

---

## 7. Verify it works

```bash
kubectl run pull-test -n ci-system --restart=Never \
  --image=registry.example.com:5443/oci-internal/my-app:1.2.3 \
  --command -- sleep 3600
kubectl describe pod pull-test -n ci-system
```

A successful pull shows `Successfully pulled image` in the Pod's events with
no `ImagePullBackOff`. Clean up with `kubectl delete pod pull-test -n
ci-system`.

---

## 8. Troubleshooting

### `403` from the registry, not `401`

The pull got past the challenge (the Secret was presented and the token
validated) but the token's authority does not cover this repository. Check
that the `PermissionGrant` from step 1 names the correct `repository:` and
uses `permission: read` — and that its `subject.kind` is `serviceAccount`,
not `claims` (see the note at the end of step 1: a `claims`-subject grant
can never match this token).

### Still `ImagePullBackOff` with an "unauthorized" or "authentication
required" event

Confirm the registry host in `dockerconfig.json`'s `auths` key matches the
image reference's host **exactly**, including the port. A mismatch means
kubelet never looks up this Secret at all — the failure looks identical to
a missing Secret.

### The token stopped working after 365 days

`issue-svc-token` mints with a fixed expiry (`--expires-in-days`, default
365) and does not auto-renew. Re-run step 2 with `--rotate` to mint a
replacement under the same name, then repeat steps 3–4 with the new
plaintext. If you want this to happen automatically instead of by hand,
switch this SA to the `fallbackRotation` flow in
[`rotating-service-account-tokens.md`](../rotating-service-account-tokens.md).

---

## 9. What's NOT covered

- **Automatic rotation.** This recipe mints a static token with a fixed
  expiry. See
  [`rotating-service-account-tokens.md`](../rotating-service-account-tokens.md)
  for the worker-reconciled alternative.
- **Federation (no static credential at rest).** If the pulling workload can
  run an OIDC exchange itself, prefer
  [`federate-k8s-workload-identity.md`](../federate-k8s-workload-identity.md)
  — it needs no Secret at all.
- **Write access.** This recipe mints `permission: read` only. A publisher
  that also needs to push follows the same grant/mint shape with
  `permission: write` (plus `read` too if it reads back what it pushed —
  permissions are flat, `write` does not imply `read`).

---

## 10. See also

- [`docs/auth-catalog.md`](../../../auth-catalog.md) Entry 4 (ServiceAccount
  token), Entry 7 (the OCI `/v2/auth` challenge posture), Entry 8 (the Basic
  carrier convention this recipe's `dockerconfigjson` relies on).
- [ADR 0045](../../../adr/0045-oci-read-challenge-before-anti-enum.md) — why
  the manifest endpoint challenges instead of anti-enumerating for an
  anonymous caller.
- [ADR 0044](../../../adr/0044-service-accounts-identity-only.md) — the
  identity-only `ServiceAccount` envelope and the `repository_ids: None`
  unrestricted-cap sentinel.
- [ADR 0037](../../../adr/0037-gitops-service-account-grant.md) — the
  `serviceAccount`-subject `PermissionGrant` shape.
- [ADR 0012](../../../adr/0012-claim-based-rbac-claimless-static-tokens.md) —
  why a service-account token always carries `claims: []`, and therefore why
  a `claims`-subject grant can never authorize it.
- [`declare-gitops-config.md`](../declare-gitops-config.md) `kind:
  ServiceAccount` / `kind: PermissionGrant` — the full schema reference.
- [`rotating-service-account-tokens.md`](../rotating-service-account-tokens.md)
  — the auto-rotated alternative to this manual recipe.
