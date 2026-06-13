{{/*
Standard chart helpers — name, fullname, labels, selector labels, SA name,
and image-tag resolution.
*/}}

{{- define "hort-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hort-server.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "hort-server.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels — applied to every resource. Includes the Helm release
metadata + Kubernetes recommended labels.
*/}}
{{- define "hort-server.labels" -}}
helm.sh/chart: {{ include "hort-server.chart" . }}
{{ include "hort-server.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: hort-server
{{- end -}}

{{/*
Selector labels — used in pod selectors. MUST be stable across
chart upgrades (otherwise existing Deployments lose their pods).
*/}}
{{- define "hort-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hort-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
ServiceAccount name — generated from fullname when serviceAccount.create
is true and no explicit name is set; otherwise uses the explicit name.
*/}}
{{- define "hort-server.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "hort-server.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the image reference. Empty `image.tag` falls back to
`Chart.AppVersion`.
*/}}
{{- define "hort-server.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
PVC name — stable identifier for the filesystem-backend storage volume.
*/}}
{{- define "hort-server.pvcName" -}}
{{- printf "%s-data" (include "hort-server.fullname" .) -}}
{{- end -}}

{{/*
Worker ServiceAccount name.

Operators may override via `worker.serviceAccount.name`; default
is the chart fullname suffixed with `-worker` so the worker SA
is visibly distinct from the server SA in `kubectl get sa`. When
`worker.serviceAccount.create` is false, falls back to `default`
matching the same posture as `hort-server.serviceAccountName`.
*/}}
{{- define "hort-server.worker.serviceAccountName" -}}
{{- if .Values.worker.serviceAccount.create -}}
{{- default (printf "%s-worker" (include "hort-server.fullname" .)) .Values.worker.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.worker.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Worker image reference.

Empty `worker.image.tag` falls back to `Chart.AppVersion`. The default
repository points at the bundled image variant
(`ghcr.io/project-hort/hort-worker`) which carries the Rust binary
plus the pre-installed Trivy + osv-scanner CLIs. Operators who build
their own worker image override `image.repository`.
*/}}
{{- define "hort-server.worker.image" -}}
{{- $tag := default .Chart.AppVersion .Values.worker.image.tag -}}
{{- printf "%s:%s" .Values.worker.image.repository $tag -}}
{{- end -}}

{{/*
Runtime env vars — used by the scrub CronJob. Emits the
parse-time-relevant subset of `Config::from_env`: every variable the
binary's parser walks at startup, so a misconfigured value triggers a
loud refusal at the CronJob's first fire rather than a silent skip.

Note: `deployment.yaml` maintains its own inline env block carrying
many more variables (auth, HTTP transport, metrics, OCI, shutdown,
secrets, storage…) than the scrub CronJob needs. The two blocks
deliberately diverge in scope. The shape that MUST agree is the
parsing surface: any var emitted by both must use the same value
source so a misconfiguration cannot diverge between the two pods.

Inputs: the standard Helm `.` (Chart, Release, Values) — same as any
other helper.
*/}}
{{- define "hort-server.runtimeEnv" -}}
# ----- Postgres (app-role DSN, NOT admin) -----
# Backlog 078 Item 5 — inject the canonical HORT_DATABASE_URL var.
# The binary prefers HORT_DATABASE_URL and falls back to bare
# DATABASE_URL (sqlx-cli / Tier-2 / 12-factor compat), so bare
# DATABASE_URL is still honored — the chart just sets the canonical name.
- name: HORT_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgres.app.existingSecret | quote }}
      key: {{ .Values.postgres.app.secretKey | quote }}
# ----- Public surface -----
- name: HORT_PUBLIC_BASE_URL
  value: {{ .Values.publicBaseUrl | quote }}
- name: HORT_API_BIND
  value: {{ .Values.api.bindAddr | quote }}
- name: HORT_REQUIRE_HTTPS
  value: {{ .Values.requireHttps | quote }}
{{- if .Values.trustedProxyCidrs }}
- name: HORT_TRUSTED_PROXY_CIDRS
  value: {{ join "," .Values.trustedProxyCidrs | quote }}
{{- end }}
# ----- Auth -----
- name: HORT_AUTH_PROVIDER
  value: {{ .Values.auth.provider | quote }}
{{- if eq .Values.auth.provider "oidc" }}
- name: HORT_OIDC_ISSUER_URL
  value: {{ .Values.auth.oidc.issuerUrl | quote }}
- name: HORT_OIDC_AUDIENCE
  value: {{ .Values.auth.oidc.audience | quote }}
- name: HORT_OIDC_GROUPS_CLAIM
  value: {{ .Values.auth.oidc.groupsClaim | quote }}
- name: HORT_JWKS_CACHE_TTL_SECS
  value: {{ .Values.auth.oidc.jwksCacheTtlSeconds | quote }}
{{- end }}
# ----- Storage -----
- name: HORT_STORAGE_BACKEND
  value: {{ .Values.storage.backend | quote }}
{{- if eq .Values.storage.backend "filesystem" }}
- name: HORT_STORAGE_FILESYSTEM_PATH
  value: /var/lib/hort-server/cas
{{- else if eq .Values.storage.backend "s3" }}
- name: AWS_ENDPOINT_URL_S3
  value: {{ .Values.storage.s3.endpoint | quote }}
- name: AWS_REGION
  value: {{ .Values.storage.s3.region | quote }}
- name: HORT_STORAGE_S3_BUCKET
  value: {{ .Values.storage.s3.bucket | quote }}
- name: HORT_STORAGE_S3_FORCE_PATH_STYLE
  value: {{ .Values.storage.s3.pathStyle | quote }}
- name: HORT_STORAGE_S3_ALLOW_HTTP
  value: {{ .Values.storage.s3.allowHttp | quote }}
{{- if .Values.storage.s3.sseMode }}
- name: HORT_S3_SSE_MODE
  value: {{ .Values.storage.s3.sseMode | quote }}
{{- end }}
{{- if .Values.storage.s3.sseKmsKeyArn }}
- name: HORT_S3_SSE_KMS_KEY_ARN
  value: {{ .Values.storage.s3.sseKmsKeyArn | quote }}
{{- end }}
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.storage.s3.existingSecret | quote }}
      key: AWS_ACCESS_KEY_ID
- name: AWS_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.storage.s3.existingSecret | quote }}
      key: AWS_SECRET_ACCESS_KEY
{{- end }}
# ----- Secrets containment root -----
- name: HORT_SECRETS_FILE_ROOT
  value: {{ .Values.secrets.fileRoot | quote }}
# ----- gitops config dir -----
- name: HORT_CONFIG_DIR
  value: /etc/hort-server/config
# ----- CAS scrub -----
- name: HORT_CAS_SCRUB_ACTION_ON_MISMATCH
  value: {{ .Values.scheduledTasks.scrub.actionOnMismatch | quote }}
{{- end -}}

{{/*
Backlog 078 Item 7 (chart S2 / convention 9) — CA-bundle auto-mount
source resolution + the no-env-without-mount guard.

Two trust-bundle *auto-mount* sources are supported, and they are
mutually exclusive (a pod cannot mount two different `ca.crt` files at
the same path):

  - `extraCaBundle.configMapName` — Recipe A. The bundle lives in a
    ConfigMap; the chart mounts it read-only at `extraCaBundle.path`.
  - `extraCaBundle.secretName` — Recipe B (auto). The bundle lives in a
    Secret (e.g. cert-manager output, or an operator-managed Secret);
    the chart mounts it read-only at `extraCaBundle.path`.

Both auto-mount the SAME targets symmetrically: the server Deployment,
the worker Deployment, and the server-runtime CronJobs. The manual
Recipe-B path (`extraCaBundle.path` set, but NEITHER source) is for
operators wiring `extraVolumes`/`extraVolumeMounts` (and the
`worker.*` equivalents) themselves — e.g. a CSI-projected
ClusterTrustBundle.

`hort-server.extraCaBundle.autoMounted` returns a non-empty string when
the chart owns the mount (configMapName OR secretName set) and empty
otherwise. This is the single gate that BOTH the volume/volumeMount
blocks AND the `HORT_EXTRA_CA_BUNDLE` env var key off, so the chart can
NEVER set the env on a pod it did not also mount the bundle onto
(convention 9). For the manual path the chart leaves the env unset and
the operator sets `HORT_EXTRA_CA_BUNDLE` themselves via `extraEnv` /
`worker.extraEnv`.

`hort-server.extraCaBundle.validateSources` fails the render when BOTH
sources are set (an ambiguous double-source config) — fail-fast at
`helm install` rather than a confusing double-mount at runtime.
*/}}
{{- define "hort-server.extraCaBundle.autoMounted" -}}
{{- if or .Values.extraCaBundle.configMapName .Values.extraCaBundle.secretName -}}
true
{{- end -}}
{{- end -}}

{{- define "hort-server.extraCaBundle.validateSources" -}}
{{- if and .Values.extraCaBundle.configMapName .Values.extraCaBundle.secretName -}}
  {{- fail "Backlog 078 Item 7: extraCaBundle.configMapName and extraCaBundle.secretName are mutually exclusive — a pod can mount only one ca.crt source at extraCaBundle.path. Set exactly one (or neither, for the manual extraVolumes recipe)." -}}
{{- end -}}
{{- if and (or .Values.extraCaBundle.configMapName .Values.extraCaBundle.secretName) (not .Values.extraCaBundle.path) -}}
  {{- fail "Backlog 078 Item 7: extraCaBundle.configMapName/secretName is set but extraCaBundle.path is empty — set extraCaBundle.path to the in-container mount path for the bundle." -}}
{{- end -}}
{{- end -}}

{{/*
Backlog 078 Item 7 — the auto-mount `volumeMount` for the CA bundle.
Emitted by the server Deployment, worker Deployment, and the
server-runtime CronJobs whenever `hort-server.extraCaBundle.autoMounted`
is true. Mounting at `extraCaBundle.path` with `subPath: ca.crt` matches
the shape used by both ConfigMap- and Secret-backed volumes (the volume
itself projects `ca.crt`). Callers nest the output at the right indent.
*/}}
{{- define "hort-server.extraCaBundle.volumeMount" -}}
- name: extra-ca-bundle
  mountPath: {{ .Values.extraCaBundle.path }}
  subPath: ca.crt
  readOnly: true
{{- end -}}

{{/*
Backlog 078 Item 7 — the auto-mount `volume` for the CA bundle. Selects
the ConfigMap or Secret projection from whichever of
`extraCaBundle.{configMapName,secretName}` is set (the two are mutually
exclusive — see `validateSources`). Both project the single `ca.crt`
key read-only (0444). Callers nest the output at the right indent.
*/}}
{{- define "hort-server.extraCaBundle.volume" -}}
- name: extra-ca-bundle
{{- if .Values.extraCaBundle.configMapName }}
  configMap:
    # Read-only trust anchors. 0444 (octal) = -r--r--r--: any process
    # in the container can verify a TLS chain without the file carrying
    # write/execute bits.
    name: {{ .Values.extraCaBundle.configMapName | quote }}
    defaultMode: 0444
    items:
      - key: ca.crt
        path: ca.crt
{{- else if .Values.extraCaBundle.secretName }}
  secret:
    # Backlog 078 Item 7 (a) — Secret-backed auto-mount, symmetric with
    # the ConfigMap path above. Same 0444 read-only trust-anchor posture.
    secretName: {{ .Values.extraCaBundle.secretName | quote }}
    defaultMode: 0444
    items:
      - key: ca.crt
        path: ca.crt
{{- end }}
{{- end -}}

{{/*
extraCaConfigMapChecksum — CA-bundle auto-mount checksum helper.

Renders a SHA-256 digest that mixes:

  1. The ConfigMap NAME the chart wires the volume to
     (`extraCaBundle.configMapName`). Bumping the chart values to point
     at a new ConfigMap rolls the pods automatically.
  2. The ConfigMap DATA fetched via `lookup` (when the resource is
     reachable from the templating client — i.e. on `helm install` /
     `upgrade` against a live cluster, not on `helm template`). When
     the ConfigMap exists, edits to its `ca.crt` key roll the pods on
     the next `helm upgrade`. When the lookup returns nil
     (`helm template`, or the ConfigMap not yet created), only the
     name contributes — which is the correct fallback because the
     pods need to roll if the operator subsequently switches the
     ConfigMap target.

Operator escalation when lookup is empty: a hot edit to the existing
ConfigMap's `ca.crt` (without bumping anything in `values.yaml`) does
NOT trigger a pod roll under `helm upgrade` because the rendered
checksum is unchanged. This is the documented rotation contract — see
`docs/architecture/how-to/deploy/extra-ca-bundle.md` "Rotation
contract" section. Operators MUST trigger
`kubectl rollout restart deployment/<release>` after a hot ConfigMap
edit. The annotation only auto-rolls when `helm upgrade` re-renders
with a different lookup result.

Returns the hex digest only — the caller wraps it in the annotation
value. Empty when extraCaBundle is not configured (caller gates on
`.Values.extraCaBundle.configMapName`).
*/}}
{{- define "hort-server.extraCaConfigMapChecksum" -}}
{{- $name := .Values.extraCaBundle.configMapName | default "" -}}
{{- $found := "" -}}
{{- if $name -}}
  {{- $cm := lookup "v1" "ConfigMap" .Release.Namespace $name -}}
  {{- if $cm -}}
    {{- $found = ($cm.data | toYaml) -}}
  {{- end -}}
{{- end -}}
{{- printf "%s|%s" $name $found | sha256sum -}}
{{- end -}}

{{/*
Backlog 078 Item 9 (chart S4) — the rotation switch pair is collapsed.

Pre-078 there were TWO toggles — `worker.rotation.enabled` (worker-side
wiring) and `scheduledTasks.serviceAccountRotation.enabled` (CronJob
trigger) — cross-validated here by a bespoke `fail` directive so a
half-on config (one switch set, the other not) was rejected.

Item 9 collapsed this to a SINGLE source-of-truth toggle:
`scheduledTasks.serviceAccountRotation.enabled` now drives BOTH the
CronJob AND the worker-side rotation env + RBAC. The two pieces that
must still physically agree — the `adminTasksEnabled` umbrella, the
worker Deployment being enabled, and a non-empty
`worker.rotation.publicRegistryHost` — are enforced by `values.schema.json`
`if/then` couplings (mirroring the `replicaCount ⇒ ephemeralStore/storage`
couplings), so this bespoke template helper is no longer needed and was
removed. The schema is the single validation style for cross-field
couplings in this chart.
*/}}
