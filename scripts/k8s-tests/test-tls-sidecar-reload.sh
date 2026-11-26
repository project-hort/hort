#!/usr/bin/env bash
# Exercise TLS Secret projection and new handshakes against the chart in kind.
# Run from any directory. Docker builds the server image unless it is already local.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
chart_dir="$repo_root/deploy/helm/hort-server"
cluster_name="${CLUSTER_NAME:-hort-tls-reload-$$}"
namespace="${NAMESPACE:-hort-tls-reload}"
image="${HORT_SERVER_IMAGE:-hort/hort-server:tls-reload-test}"
postgres_image="${POSTGRES_IMAGE:-postgres:17-alpine}"
work_dir=""
cluster_created=false
forward_pid=""

cleanup() {
    if [[ -n "$forward_pid" ]]; then
        kill "$forward_pid" 2>/dev/null || true
        wait "$forward_pid" 2>/dev/null || true
    fi
    if [[ "$cluster_created" == true ]]; then
        kind delete cluster --name "$cluster_name" >/dev/null 2>&1 || true
    fi
    if [[ -n "$work_dir" && -d "$work_dir" ]]; then
        find "$work_dir" -depth -delete
    fi
}
trap cleanup EXIT

check_map() {
    python3 - "$1" <<'PY'
import pathlib
import re
import sys

config = pathlib.Path(sys.argv[1]).read_text()
expected = {
    "$tls_certificate_path": "/etc/nginx/tls/tls.crt",
    "$tls_private_key_path": "/etc/nginx/tls/tls.key",
}
maps = re.findall(r"(?m)^\s*map\s+\$ssl_server_name\s+(\$\w+)\s*\{([^{}]*)\}", config)
assert len(maps) == len(expected), f"expected two constant SNI maps, found {len(maps)}"
assert {name for name, _ in maps} == set(expected), "unexpected certificate map variable"
for name, body in maps:
    arms = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.fullmatch(r"(\S+)\s+(\S+);", line)
        assert match, f"unrecognised map arm: {line}"
        arms.append(match.groups())
    assert any(key == "default" for key, _ in arms), f"{name} has no default arm"
    assert all(value == expected[name] for _, value in arms), f"{name} has a variable path"

listeners = re.findall(r"(?m)^\s*listen\s+(?:\d+|\{\{[^\n}]+\}\})\s+ssl;", config)
assert listeners, "no TLS listener found"
for directive, variable in (
    ("ssl_certificate", "$tls_certificate_path"),
    ("ssl_certificate_key", "$tls_private_key_path"),
):
    values = re.findall(rf"(?m)^\s*{directive}\s+(\S+);", config)
    assert values == [variable] * len(listeners), f"{directive} must use its map on every TLS listener"
cache = re.findall(r"(?m)^\s*ssl_certificate_cache\s+(\S+);", config)
assert cache == ["off"] * len(listeners), "certificate cache must be off on every TLS listener"
print(f"PASS: constant certificate maps and cache off on {len(listeners)} TLS listener(s)")
PY
}

# This mode runs without kind or Helm and catches a variable path before deployment.
if [[ "${1:-}" == --check-map ]]; then
    if (($# > 2)); then
        echo "usage: $0 [--check-map [config-path]]" >&2
        exit 2
    fi
    check_map "${2:-$chart_dir/templates/tls-sidecar-configmap.yaml}"
    exit 0
fi
if (($#)); then
    echo "usage: $0 [--check-map [config-path]]" >&2
    exit 2
fi
check_map "$chart_dir/templates/tls-sidecar-configmap.yaml"

for binary in kind kubectl helm docker openssl python3 timeout curl; do
    if ! command -v "$binary" >/dev/null 2>&1; then
        echo "MISSING: $binary is required for the kind TLS rotation run" >&2
        exit 2
    fi
done
if ! docker info >/dev/null 2>&1; then
    echo "MISSING: Docker daemon is unavailable" >&2
    exit 2
fi
cluster_list="$(kind get clusters)"
if grep -Fxq "$cluster_name" <<<"$cluster_list"; then
    echo "REFUSING: kind cluster $cluster_name already exists" >&2
    exit 2
fi

work_dir="$(mktemp -d)"
export KUBECONFIG="$work_dir/kubeconfig"
kind create cluster --name "$cluster_name" --kubeconfig "$KUBECONFIG" --wait 60s
cluster_created=true
[[ "$(kubectl config current-context)" == "kind-$cluster_name" ]]

if ! docker image inspect "$image" >/dev/null 2>&1; then
    (cd "$repo_root" && docker build -t "$image" -f docker/Dockerfile.hort-server .)
fi
kind load docker-image "$image" --name "$cluster_name"

kubectl create namespace "$namespace"
kubectl -n "$namespace" apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: postgres}
spec:
  replicas: 1
  selector: {matchLabels: {app: postgres}}
  template:
    metadata: {labels: {app: postgres}}
    spec:
      containers:
        - name: postgres
          image: $postgres_image
          env:
            - {name: POSTGRES_USER, value: hort}
            - {name: POSTGRES_PASSWORD, value: hort-test}
            - {name: POSTGRES_DB, value: hort}
          readinessProbe:
            exec: {command: ["pg_isready", "-U", "hort", "-d", "hort"]}
            initialDelaySeconds: 2
            periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata: {name: postgres}
spec:
  selector: {app: postgres}
  ports: [{port: 5432, targetPort: 5432}]
EOF
kubectl -n "$namespace" wait --for=condition=ready pod -l app=postgres --timeout=180s
for role in app admin; do
    kubectl -n "$namespace" create secret generic "hort-postgres-$role" \
        --from-literal=DATABASE_URL='postgres://hort:hort-test@postgres:5432/hort' \
        --dry-run=client -o yaml | kubectl apply -f -
done
openssl genpkey -algorithm ed25519 -out "$work_dir/signing.pem"
kubectl -n "$namespace" create secret generic hort-oci-signing-key \
    --from-file=hort-oci-token-signing-key.pem="$work_dir/signing.pem" \
    --dry-run=client -o yaml | kubectl apply -f -

make_certificate() {
    local generation="$1"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj "/CN=hort-server.$namespace.svc" \
        -addext "subjectAltName=DNS:hort-server.$namespace.svc" \
        -keyout "$work_dir/key-$generation.pem" \
        -out "$work_dir/cert-$generation.pem" >/dev/null 2>&1
}

replace_secret() {
    local cert="$1" key="$2"
    # The generic constructor permits a deliberately mismatched pair while
    # retaining the TLS Secret type. The TLS constructor rejects it locally.
    kubectl -n "$namespace" create secret generic hort-server-tls \
        --type=kubernetes.io/tls \
        --from-file=tls.crt="$work_dir/cert-$cert.pem" \
        --from-file=tls.key="$work_dir/key-$key.pem" \
        --dry-run=client -o yaml | kubectl apply -f -
}

make_certificate 1
make_certificate 2
make_certificate 3
if cmp -s "$work_dir/cert-1.pem" "$work_dir/cert-2.pem"; then
    echo "FAIL: generated certificates are identical" >&2
    exit 1
fi
replace_secret 1 1
secret_uid="$(kubectl -n "$namespace" get secret hort-server-tls -o jsonpath='{.metadata.uid}')"

cat >"$work_dir/values.yaml" <<EOF
image:
  repository: ${image%:*}
  tag: ${image##*:}
  pullPolicy: Never
publicBaseUrl: "https://hort-server.$namespace.svc"
auth:
  provider: disabled
  nativeTokens:
    enabled: true
    signingKey:
      existingSecret: hort-oci-signing-key
postgres:
  app: {existingSecret: hort-postgres-app}
  admin: {existingSecret: hort-postgres-admin}
storage:
  backend: filesystem
  filesystem:
    pvc: {enabled: false}
ephemeralStore: {backend: memory}
networkPolicy: {enabled: false}
worker: {enabled: false}
prePull: {enabled: false}
tlsSidecar:
  enabled: true
  secretName: hort-server-tls
gitopsConfig:
  "service-account.metrics-granted.yaml": |
    apiVersion: project-hort.de/v1
    kind: ServiceAccount
    metadata:
      name: metrics-granted
    spec:
      federatedIdentities: []
  "service-account.metrics-ungranted.yaml": |
    apiVersion: project-hort.de/v1
    kind: ServiceAccount
    metadata:
      name: metrics-ungranted
    spec:
      federatedIdentities: []
  "grant.metrics-granted.yaml": |
    apiVersion: project-hort.de/v1
    kind: PermissionGrant
    metadata:
      name: metrics-granted-read
    spec:
      subject: {kind: serviceAccount, name: metrics-granted}
      permission: read_metrics
EOF

if ! helm upgrade --install hort-server "$chart_dir" -n "$namespace" \
        -f "$work_dir/values.yaml" --wait --timeout 5m; then
    kubectl -n "$namespace" get pods -o wide || true
    kubectl -n "$namespace" logs -l app.kubernetes.io/component=server \
        --all-containers --tail=120 || true
    exit 1
fi

deployment="hort-server"
kubectl -n "$namespace" get deployment "$deployment" -o json >"$work_dir/deployment.json"
python3 - "$work_dir/deployment.json" <<'PY'
import json
import sys

pod = json.load(open(sys.argv[1]))["spec"]["template"]["spec"]
security = pod["securityContext"]
assert security["runAsNonRoot"] is True
assert all(security[k] == 65532 for k in ("runAsUser", "runAsGroup", "fsGroup"))
sidecar = next(c for c in pod["containers"] if c["name"] == "tls-sidecar")
context = sidecar["securityContext"]
assert context["readOnlyRootFilesystem"] is True
assert context["allowPrivilegeEscalation"] is False
assert context["capabilities"]["drop"] == ["ALL"]
assert not context["capabilities"].get("add")
volume = next(v for v in pod["volumes"] if v["name"] == "tls-sidecar-cert")
assert volume["secret"]["defaultMode"] == 0o440
PY

pod="$(kubectl -n "$namespace" get pod -l app.kubernetes.io/component=server \
    -o jsonpath='{.items[0].metadata.name}')"
[[ -n "$pod" ]]
kubectl -n "$namespace" get configmap "$deployment-tls-sidecar" \
    -o jsonpath='{.data.nginx\.conf}' >"$work_dir/nginx.conf"
check_map "$work_dir/nginx.conf"
kubectl -n "$namespace" get service "$deployment" -o json >"$work_dir/service.json"
python3 - "$work_dir/service.json" "$work_dir/deployment.json" <<'PY'
import json
import sys

service = json.load(open(sys.argv[1]))
deployment = json.load(open(sys.argv[2]))
ports = {port["name"]: port for port in service["spec"]["ports"]}
assert ports["http"]["targetPort"] == "https"
assert ports["metrics"]["targetPort"] == "metrics-https"
containers = deployment["spec"]["template"]["spec"]["containers"]
server = next(c for c in containers if c["name"] == "hort-server")
sidecar = next(c for c in containers if c["name"] == "tls-sidecar")
env = {entry["name"]: entry.get("value") for entry in server["env"]}
assert env["HORT_METRICS_BIND"] == "127.0.0.1:9090"
sidecar_ports = {port["name"]: port["containerPort"] for port in sidecar["ports"]}
assert sidecar_ports == {"https": 8443, "metrics-https": 9444}
PY

read -r uid gid groups < <(kubectl -n "$namespace" exec "$pod" -c tls-sidecar -- id \
    | sed -E 's/^uid=([0-9]+).*gid=([0-9]+).*groups=([0-9,]+).*/\1 \2 \3/')
[[ "$uid" == 65532 && "$gid" == 65532 ]]
[[ ",$groups," == *,65532,* ]]

pod_identity() {
    kubectl -n "$namespace" get pod "$pod" -o json \
        | python3 -c 'import json,sys; p=json.load(sys.stdin); print(p["metadata"]["uid"]); print(" ".join(sorted(c["name"]+":"+str(c["restartCount"])+":"+c["containerID"] for c in p["status"]["containerStatuses"])))'
}
initial_identity="$(pod_identity)"

mapfile -t ports < <(sed -nE 's/^[[:space:]]*listen ([0-9]+) ssl;$/\1/p' "$work_dir/nginx.conf")
[[ "${ports[*]}" == "8443 9444" ]]
forward_args=()
local_ports=()
for index in "${!ports[@]}"; do
    local_ports+=("$((25443 + index))")
    forward_args+=("${local_ports[index]}:${ports[index]}")
done
forward_args+=("25445:9090")
kubectl -n "$namespace" port-forward "pod/$pod" "${forward_args[@]}" \
    >"$work_dir/port-forward.log" 2>&1 &
forward_pid=$!
for _ in {1..30}; do
    if grep -q "Forwarding from 127.0.0.1:${local_ports[0]}" "$work_dir/port-forward.log"; then
        break
    fi
    kill -0 "$forward_pid" 2>/dev/null || { cat "$work_dir/port-forward.log"; exit 1; }
    sleep 1
done
grep -q "Forwarding from 127.0.0.1:${local_ports[0]}" "$work_dir/port-forward.log"

granted_token="$(kubectl -n "$namespace" exec "$pod" -c hort-server -- \
    /usr/local/bin/hort-server admin issue-svc-token \
    --name=metrics-granted --permission=read_metrics --require-authority --output=stdout)"
ungranted_token="$(kubectl -n "$namespace" exec "$pod" -c hort-server -- \
    /usr/local/bin/hort-server admin issue-svc-token \
    --name=metrics-ungranted --permission=read_metrics --output=stdout)"
[[ -n "$granted_token" && -n "$ungranted_token" ]]

assert_status() {
    local expected="$1" url="$2" token="${3:-}" observed
    local args=(--silent --show-error --noproxy '*' --output "$work_dir/response" \
        --write-out '%{http_code}' --max-time 15)
    if [[ "$url" == https:* ]]; then
        args+=(--cacert "$work_dir/cert-1.pem" \
            --resolve "hort-server.$namespace.svc:25444:127.0.0.1" \
            --resolve "hort-server.$namespace.svc:25443:127.0.0.1")
    fi
    if [[ -n "$token" ]]; then
        args+=(--header "Authorization: Bearer $token")
    fi
    observed="$(curl "${args[@]}" "$url")"
    if [[ "$observed" != "$expected" ]]; then
        echo "FAIL: $url returned $observed, expected $expected" >&2
        cat "$work_dir/response" >&2
        return 1
    fi
}

metrics_url="https://hort-server.$namespace.svc:25444/metrics"
assert_status 200 "$metrics_url" "$granted_token"
assert_status 401 "$metrics_url"
assert_status 403 "$metrics_url" "$ungranted_token"
assert_status 426 "http://127.0.0.1:25445/metrics" "$granted_token"
assert_status 404 "https://hort-server.$namespace.svc:25443/metrics" "$granted_token"
echo "PASS: credentialed metrics TLS and transport status matrix"

wait_for_projection() {
    local cert="$1" key="$2" deadline=$((SECONDS + 240))
    while ((SECONDS < deadline)); do
        if kubectl -n "$namespace" exec "$pod" -c tls-sidecar -- \
                cat /etc/nginx/tls/tls.crt 2>/dev/null \
                | cmp -s - "$work_dir/cert-$cert.pem" &&
            kubectl -n "$namespace" exec "$pod" -c tls-sidecar -- \
                cat /etc/nginx/tls/tls.key 2>/dev/null \
                | cmp -s - "$work_dir/key-$key.pem"; then
            return 0
        fi
        sleep 2
    done
    echo "FAIL: projected Secret files did not change within 240 seconds" >&2
    return 1
}

handshake() {
    local port="$1" output="$2"
    # A new OpenSSL process has no session cache; no ticket or session input is supplied.
    timeout 15s openssl s_client -connect "127.0.0.1:$port" \
        -servername "hort-server.$namespace.svc" -tls1_2 -no_ticket -showcerts \
        </dev/null >"$output" 2>&1 || true
}

assert_served_certificate() {
    local generation="$1" index output expected observed
    expected="$(openssl x509 -in "$work_dir/cert-$generation.pem" -noout -fingerprint -sha256)"
    for index in "${!local_ports[@]}"; do
        output="$work_dir/handshake-${generation}-${index}.log"
        handshake "${local_ports[index]}" "$output"
        observed="$(openssl x509 -in "$output" -noout -fingerprint -sha256)" || {
            cat "$output" >&2
            return 1
        }
        grep -q 'New, TLSv1.2,' "$output" || {
            echo "FAIL: TLS port ${ports[index]} did not complete a new TLS 1.2 handshake" >&2
            cat "$output" >&2
            return 1
        }
        [[ "$observed" == "$expected" ]] || {
            echo "FAIL: TLS port ${ports[index]} served $observed, expected $expected" >&2
            return 1
        }
    done
}

assert_identity() {
    [[ "$(pod_identity)" == "$initial_identity" ]] || {
        echo "FAIL: pod UID, container ID or restart count changed" >&2
        return 1
    }
    [[ "$(kubectl -n "$namespace" get secret hort-server-tls -o jsonpath='{.metadata.uid}')" \
        == "$secret_uid" ]] || {
        echo "FAIL: TLS Secret object was recreated" >&2
        return 1
    }
}

assert_served_certificate 1
replace_secret 2 2
wait_for_projection 2 2
assert_identity
assert_served_certificate 2
assert_identity

error_pattern='(cannot load certificate( key)?|SSL_do_handshake\(\) failed.*(key|cert|PEM|X509)).*while SSL handshaking'
error_count_before="$(kubectl -n "$namespace" logs "$pod" -c tls-sidecar \
    | grep -Ec "$error_pattern" || true)"
# The third certificate and second key are individually valid but do not match.
# The API accepts both bytes and kubelet projects them; nginx must reject the pair.
replace_secret 3 2
wait_for_projection 3 2
assert_identity
for index in "${!local_ports[@]}"; do
    output="$work_dir/handshake-invalid-${index}.log"
    handshake "${local_ports[index]}" "$output"
    if openssl x509 -in "$output" -noout >/dev/null 2>&1; then
        echo "FAIL: TLS port ${ports[index]} served a certificate after invalid rotation" >&2
        exit 1
    fi
done
error_count_after="$(kubectl -n "$namespace" logs "$pod" -c tls-sidecar \
    | grep -Ec "$error_pattern" || true)"
if ((error_count_after <= error_count_before)); then
    echo "FAIL: nginx did not log a certificate/key handshake error" >&2
    kubectl -n "$namespace" logs "$pod" -c tls-sidecar --tail=60 >&2 || true
    exit 1
fi
assert_identity
echo "Initial leaf: $(openssl x509 -in "$work_dir/cert-1.pem" -noout -fingerprint -sha256)"
echo "Rotated leaf: $(openssl x509 -in "$work_dir/cert-2.pem" -noout -fingerprint -sha256)"
echo "nginx error:"
kubectl -n "$namespace" logs "$pod" -c tls-sidecar \
    | grep -E "$error_pattern" | tail -1
echo "PASS: every TLS listener reloaded the projected certificate without a restart and rejected an invalid pair"
