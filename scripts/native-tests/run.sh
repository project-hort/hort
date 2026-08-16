#!/usr/bin/env bash
# scripts/native-tests/run.sh — the single native-tests runner (CI + local).
# Usage:
#   ./run.sh [--hort=compose|external] [--group G]... [--scenario N]...
#            [--compose-overlay O]... [--list] [--keep]
# Env (external mode): HORT_URL, KEYCLOAK_URL[, METRICS_URL, HORT_DB_DSN].
# Env (compose mode, worker-requiring scenarios only): HORT_E2E_WORKER_REPLICAS
#   (default 4) — hort-worker replica count. Scan concurrency is 1 per replica
#   by design; replicas are the scaling axis so serial trivy runtime stays off
#   the release critical path.
# Env (compose mode): HORT_E2E_FAIL_LOG_LINES (default 2000) — per-service
#   line bound on the hort-server / hort-worker log dump emitted for a FAILED
#   scenario, so a CI failure carries its own server-side diagnosis.
# Env (opt-out, default unset = build as today): HORT_E2E_SKIP_BUILD=1 skips
#   building the test-client image and drops `--build` from `compose up`,
#   for the case where HORT_SERVER_IMAGE / HORT_WORKER_IMAGE / the test-client
#   tag were loaded beforehand (e.g. `docker load`). With the opt-out active,
#   a required image that isn't already loaded is a hard failure naming that
#   image — never a silent rebuild, which would restore the cost this exists
#   to remove while looking like a cache hit.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCEN_DIR="$SCRIPT_DIR/scenarios"

HORT_MODE="compose"; DO_LIST=0; KEEP=0
declare -a SEL_GROUPS=() SEL_SCEN=() OVERLAYS=()
# Accept both `--flag value` and `--flag=value` for the valued flags (the usage
# examples use the space form; --hort=… the equals form). KEEP is consumed by
# the execution block (Task 5).
while [ "$#" -gt 0 ]; do
  case "$1" in
    --hort=*)            HORT_MODE="${1#*=}" ;;
    --hort)              HORT_MODE="${2:?--hort requires a value}"; shift ;;
    --group=*)           SEL_GROUPS+=("${1#*=}") ;;
    --group)             SEL_GROUPS+=("${2:?--group requires a value}"); shift ;;
    --scenario=*)        SEL_SCEN+=("${1#*=}") ;;
    --scenario)          SEL_SCEN+=("${2:?--scenario requires a value}"); shift ;;
    --compose-overlay=*) OVERLAYS+=("${1#*=}") ;;
    --compose-overlay)   OVERLAYS+=("${2:?--compose-overlay requires a value}"); shift ;;
    --list)              DO_LIST=1 ;;
    --keep)              KEEP=1 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

# requires-token -> the `# requires:` line of a scenario file (space-separated).
scenario_requires() { sed -n 's/^# requires:[[:space:]]*//p' "$1" | head -1; }

# quarantine reason -> the `# quarantine:` line if present. A quarantined scenario
# is reported QUARANTINED and NOT run, and does NOT fail the gate — for a scenario
# whose own assertions are known-wrong/under-rework so it can't gate CI yet (e.g.
# proxy/pull-dedup). Remove the header once the scenario is fixed.
scenario_quarantine() { sed -n 's/^# quarantine:[[:space:]]*//p' "$1" | head -1; }

# What the chosen mode provides (egress probed at run time in Task 5).
# compose: `db` is always there (postgres is a base service); `worker`/`scanner`
# are providable because the runner brings up `--profile worker` ON DEMAND
# (Task 5 — hort-worker is profile-gated in the base compose file). Overlay
# tokens appear only when their `--compose-overlay=<o>` is passed — emitted in
# BOTH the `compose:<o>` form (provenance/federation scenarios require that) and
# the bare `<o>` form (wiremock scenarios require bare `wiremock`). The base
# compose file has NO wiremock service, so `wiremock` is never a base token.
provided_tokens() {
  if [ "$HORT_MODE" = "compose" ]; then
    # `compose` = the runner-managed stack itself (mounted example-config →
    # gitops apply-at-boot); only this mode has it.
    printf 'compose db worker scanner'
    local o; for o in "${OVERLAYS[@]:-}"; do [ -n "$o" ] && printf ' compose:%s %s' "$o" "$o"; done
  fi
  [ -n "${HORT_DB_DSN:-}" ] && printf ' db'   # external+DSN can offer db
}

# A scenario is available iff every requires-token is in provided. `egress` is
# governed by $EGRESS (default "yes" so `--list` is optimistic; the execution
# path probes the real value before running anything — see ensure_egress).
EGRESS="${EGRESS:-yes}"
is_available() {
  local reqs="$1" prov; prov=" $(provided_tokens) "
  [ "$EGRESS" = "yes" ] && prov="${prov}egress "
  local t; for t in $reqs; do
    case " $prov " in *" $t "*) ;; *) echo "$t"; return 1 ;; esac
  done
  return 0
}

# Discover scenarios as "group<TAB>name<TAB>path<TAB>requires".
discover() {
  local f group name
  while IFS= read -r f; do
    group="$(basename "$(dirname "$f")")"; name="$(basename "$f" .sh)"
    printf '%s\t%s\t%s\t%s\n' "$group" "$name" "$f" "$(scenario_requires "$f")"
  done < <(find "$SCEN_DIR" -name '*.sh' -type f | sort)
}

selected() {  # filter discover() by --group/--scenario (--scenario takes `name` OR `group/name`)
  discover | while IFS=$'\t' read -r group name path reqs; do
    if [ "${#SEL_GROUPS[@]}" -gt 0 ]; then printf '%s\n' "${SEL_GROUPS[@]}" | grep -qxF "$group" || continue; fi
    if [ "${#SEL_SCEN[@]}" -gt 0 ]; then
      printf '%s\n' "${SEL_SCEN[@]}" | grep -qxF -e "$name" -e "$group/$name" || continue
    fi
    printf '%s\t%s\t%s\t%s\n' "$group" "$name" "$path" "$reqs"
  done
}

if [ "$DO_LIST" = "1" ]; then
  printf '%-14s %-26s %-22s %s\n' GROUP SCENARIO REQUIRES "AVAIL(${HORT_MODE})"
  selected | while IFS=$'\t' read -r group name path reqs; do
    q="$(scenario_quarantine "$path")"
    if [ -n "$q" ]; then avail="QUARANTINED ($q)"
    elif miss="$(is_available "$reqs")"; then avail="yes"
    else avail="skip (needs: $miss)"; fi
    printf '%-14s %-26s %-22s %s\n' "$group" "$name" "${reqs:--}" "$avail"
  done
  exit 0
fi

COMPOSE_FILE="$REPO_ROOT/deploy/compose/docker-compose.yml"
COMPOSE_NETWORK="hort_default"
IMAGE="${HORT_TEST_CLIENT_IMAGE:-hort-test-client:dev}"
# Same variables docker-compose.yml interpolates for the server/worker
# services — exporting them here (even at their defaults) means run.sh and
# compose agree on exactly which tag a `docker load` needs to satisfy.
HORT_SERVER_IMAGE="${HORT_SERVER_IMAGE:-hort-server:dev}"
HORT_WORKER_IMAGE="${HORT_WORKER_IMAGE:-hort-worker:dev}"
export HORT_SERVER_IMAGE HORT_WORKER_IMAGE
SKIP_BUILD="${HORT_E2E_SKIP_BUILD:-0}"
KC_DISCOVERY="http://localhost:25082/realms/hort/.well-known/openid-configuration"
# Host-mapped Keycloak token endpoint + hort-server base — same realm/client
# `lib/common.sh`'s `fetch_token` uses from inside a scenario container, just
# reached from the HOST instead of the compose network. Used only by
# `mint_metrics_token` below.
HOST_KC_TOKEN_URL="http://localhost:25082/realms/hort/protocol/openid-connect/token"
HOST_HORT="http://localhost:25080"
# Readiness probe for hort-server itself. NOT `/metrics` — that endpoint
# unconditionally requires a bearer carrying `read_metrics` (#113 item 3,
# no anonymous-scrape opt-out), so an anonymous readiness curl against it
# would 401 forever and never observe "up". `/healthz` on the main
# listener is anonymous by design (kubelet-probe shape) and proves the
# same thing: the binary finished booting and is accepting connections.
HOST_HEALTHZ="${HOST_HORT}/healthz"

# Context is the repo root: the Dockerfile's stage 1 builds hort-cli from the
# workspace (.dockerignore keeps target/.git out, so the context stays small).
build_image() { docker build -q -f "$SCRIPT_DIR/Dockerfile.client" -t "$IMAGE" "$REPO_ROOT" >/dev/null; }

# require_image -> fail loudly (naming the tag) if $1 is not already loaded.
# Only called under the build opt-out, where a miss must never fall through to
# a silent rebuild.
require_image() {
  docker image inspect "$1" >/dev/null 2>&1 || {
    echo "HORT_E2E_SKIP_BUILD=1 but image '$1' is not loaded locally — load it" \
         "(e.g. docker load) before running, or unset HORT_E2E_SKIP_BUILD to build from source." >&2
    exit 1
  }
}

# maybe_build_client_image -> build the test-client image, unless the opt-out
# is active, in which case the pre-loaded image must already be present.
maybe_build_client_image() {
  if [ "$SKIP_BUILD" = "1" ]; then
    require_image "$IMAGE"
    echo "images: test-client prebuilt ($IMAGE)"
  else
    build_image
    echo "images: test-client built from source ($IMAGE)"
  fi
}
now() { date +%s; }

# mint_metrics_token -> prints a read_metrics-granted bearer for the
# `metrics-scraper` ServiceAccount (deploy/compose/example-config/service-
# accounts/metrics-scraper.yaml + the paired serviceAccount-subject
# PermissionGrant in auth/metrics-scraper-read-metrics.yaml), or prints
# nothing and returns non-zero on any failed step. Host-side (curl +
# `compose exec postgres psql`) — mirrors
# scenarios/quarantine/provenance-push-then-sign.sh's admin-mint pattern
# for the provenance-ci SA, but runs ONCE per harness run (here) instead
# of once per scenario, since every /metrics-scraping scenario needs the
# SAME bearer. #113 item 5 — restores the assertion power the anon-hatch
# retirement (#113 item 3) took away from every METRICS_URL call site.
mint_metrics_token() {
  local admin_token sa_uid token
  admin_token="$(curl -sS -X POST "$HOST_KC_TOKEN_URL" \
    -d grant_type=password -d client_id=hort-server \
    -d client_secret=hort-server-secret-dev-only \
    -d username=admin -d password=admin 2>/dev/null | jq -r '.access_token // empty')"
  [ -n "$admin_token" ] || { echo "mint_metrics_token: could not fetch admin Keycloak token" >&2; return 1; }
  sa_uid="$(docker compose "${CA[@]}" exec -T postgres \
    psql -U registry -d artifact_registry -tAX \
    -c "SELECT id FROM users WHERE username='sa:metrics-scraper';" 2>/dev/null | tr -d '[:space:]')"
  [ -n "$sa_uid" ] || {
    echo "mint_metrics_token: no users row 'sa:metrics-scraper' — " \
         "deploy/compose/example-config/service-accounts/metrics-scraper.yaml not applied?" >&2
    return 1
  }
  token="$(curl -sS -X POST \
    -H "Authorization: Bearer ${admin_token}" -H 'Content-Type: application/json' \
    -d "{\"name\":\"metrics-scraper-e2e-$(date +%s)\",\"declared_permissions\":[\"read_metrics\"],\"expires_in_days\":1}" \
    "${HOST_HORT}/api/v1/admin/users/${sa_uid}/tokens" 2>/dev/null | jq -r '.token // empty')"
  [ -n "$token" ] || { echo "mint_metrics_token: admin-mint POST returned no token" >&2; return 1; }
  printf '%s' "$token"
}
wait_url() { local u="$1" t="${2:-120}"; local d=$(( $(now)+t )); until curl -fsS -o /dev/null "$u" 2>/dev/null; do [ "$(now)" -ge "$d" ] && return 1; sleep 2; done; }

# Base compose file + any `--compose-overlay=<o>` files (provenance/federation/wiremock).
compose_args() { local a=(-f "$COMPOSE_FILE"); local o; for o in "${OVERLAYS[@]:-}"; do [ -n "$o" ] && a+=(-f "$REPO_ROOT/deploy/compose/docker-compose.$o.yml"); done; printf '%s\n' "${a[@]}"; }
mapfile -t CA < <(compose_args)

# hort-worker is profile-gated in the base compose file, so a bare `up` never
# starts it. Bring `--profile worker` up ONLY when a selected scenario requires
# worker/scanner — otherwise those scenarios would be advertised available and
# then hang/fail with no worker behind them.
NEED_WORKER=0
while IFS=$'\t' read -r _g _n _p reqs; do
  for t in $reqs; do case "$t" in worker|scanner) NEED_WORKER=1;; esac; done
done < <(selected)
PROFILE_ARGS=(); [ "$NEED_WORKER" = 1 ] && PROFILE_ARGS=(--profile worker)
# Scale hort-worker replicas so serial trivy scan throughput isn't the E2E
# release-cadence floor (backlog 095). Only when the worker profile is on —
# compose errors scaling a profile-inactive service.
SCALE_ARGS=(); [ "$NEED_WORKER" = 1 ] && SCALE_ARGS=(--scale "hort-worker=${HORT_E2E_WORKER_REPLICAS:-4}")

# The worker has no HTTP health/port, so readiness = compose reports it running.
wait_running() { local svc="$1" t="${2:-180}"; local d=$(( $(now)+t )); until docker compose "${CA[@]}" "${PROFILE_ARGS[@]}" ps --status running --services 2>/dev/null | grep -qx "$svc"; do [ "$(now)" -ge "$d" ] && return 1; sleep 2; done; }

STARTED=0

# Bounded, delimited server-side log dump for a scenario that FAILED.
#
# A CI failure must carry its own diagnosis. A scenario assertion can only
# report the state it can observe from outside (an HTTP code, a row count);
# it can never say WHICH server-side code path produced that state, and the
# stack is torn down by the EXIT trap moments later, so a failure observed
# only in CI is otherwise unreproducible from its own output. Dumping the
# services' logs at the moment of failure is what turns "count=0" into
# "count=0, and here is the request that wrote the row".
#
# FAIL only. A pass or a self-skip prints nothing new — the pass-path
# output stays byte-identical — because logs attached to green runs are
# noise that trains readers to scroll past the block that matters. Bounded
# per service so a wedged service that logged for an hour cannot bury the
# summary at the end of the run.
#
# Compose mode only: in external mode the services belong to whoever runs
# the target stack, and this runner has no compose project to read them
# from. `--keep` is orthogonal — it governs teardown, not output.
FAIL_LOG_LINES="${HORT_E2E_FAIL_LOG_LINES:-2000}"
dump_failure_logs() {
  local scenario="$1" svc
  [ "$HORT_MODE" = "compose" ] || return 0
  [ "$STARTED" = 1 ] || return 0
  for svc in hort-server hort-worker; do
    # hort-worker only exists when the worker profile was brought up; asking
    # compose for a profile-inactive service's logs is a hard error, not an
    # empty result.
    if [ "$svc" = "hort-worker" ] && [ "$NEED_WORKER" != 1 ]; then
      continue
    fi
    echo ""
    echo "----- FAIL LOGS BEGIN [$scenario] $svc (last ${FAIL_LOG_LINES} lines) -----"
    if ! docker compose "${CA[@]}" "${PROFILE_ARGS[@]}" logs \
           --no-color --tail "$FAIL_LOG_LINES" "$svc" 2>&1 | tail -n "$FAIL_LOG_LINES"; then
      echo "(could not read $svc logs)"
    fi
    echo "----- FAIL LOGS END [$scenario] $svc -----"
  done
}

# Profile-aware teardown: a worker started under --profile worker is only
# reliably removed when the same profile is on the `down` (otherwise it lingers).
cleanup() { [ "$STARTED" = 1 ] && [ "$KEEP" = 0 ] && docker compose "${CA[@]}" "${PROFILE_ARGS[@]}" down -v --remove-orphans || true; }
trap cleanup EXIT

if [ "$HORT_MODE" = "compose" ]; then
  maybe_build_client_image
  # UP_BUILD_ARGS: `--build` by default (today's behaviour — compose always
  # rebuilds server/worker regardless of any cached image). Under the opt-out
  # it's dropped so `up` uses the already-loaded HORT_SERVER_IMAGE /
  # HORT_WORKER_IMAGE tags instead — but only once we've confirmed those tags
  # actually exist locally; otherwise compose would build them anyway (silent
  # rebuild) simply because the requested tag is missing.
  UP_BUILD_ARGS=(--build)
  if [ "$SKIP_BUILD" = "1" ]; then
    UP_BUILD_ARGS=()
    require_image "$HORT_SERVER_IMAGE"
    if [ "$NEED_WORKER" = 1 ]; then
      require_image "$HORT_WORKER_IMAGE"
      echo "images: server/worker prebuilt (server=$HORT_SERVER_IMAGE worker=$HORT_WORKER_IMAGE)"
    else
      echo "images: server prebuilt (server=$HORT_SERVER_IMAGE); worker profile inactive"
    fi
  else
    echo "images: server/worker building from source (server=$HORT_SERVER_IMAGE worker=$HORT_WORKER_IMAGE)"
  fi
  # E2E sweep cadence: for scan-less policies (scanBackends: []) the release
  # sweep is the ONLY release engine, and the OCI cold-blob bounded await
  # (default 10s) only catches a release when the tick fits inside its bound —
  # tick <= await turns a cold `--all` tree pull into a single client pass
  # instead of a 503-abort frontier crawl. Compose interpolates the ticker's
  # ${SWEEP_TICK_SECS:-15} from THIS process env at `up` time.
  export SWEEP_TICK_SECS="${SWEEP_TICK_SECS:-5}"
  docker compose "${CA[@]}" "${PROFILE_ARGS[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose "${CA[@]}" "${PROFILE_ARGS[@]}" up -d "${UP_BUILD_ARGS[@]}" "${SCALE_ARGS[@]}"
  STARTED=1
  wait_url "$KC_DISCOVERY" 120 || { echo "Keycloak not ready" >&2; exit 1; }
  wait_url "$HOST_HEALTHZ" 120 || { echo "hort-server not ready" >&2; exit 1; }
  [ "$NEED_WORKER" = 1 ] && { wait_running hort-worker 180 || { echo "hort-worker not running" >&2; exit 1; }; }
  IN_HORT="http://hort-server:8080"; IN_KC="http://keycloak:8080/realms/hort"; IN_METRICS="http://hort-server:9090/metrics"
  NET_ARGS=(--network "$COMPOSE_NETWORK")
  DB_DSN="postgres://registry:registry@postgres:5432/artifact_registry"
  # Harness setup: mint the read_metrics bearer ONCE for the whole run, but
  # ONLY when the native-tokens overlay is active. PAT/token-exchange consume
  # requires the native-token validator (HORT_NATIVE_TOKENS_ENABLED), which
  # the legacy-posture base stack deliberately does not enable. Minting there
  # would either boot-fail (no signing key) or produce a token the base
  # stack can't validate, so the base lane instead leaves the token unset:
  # every assert_metric_ingest call site takes its existing "METRICS_TOKEN
  # unset" note-and-skip path rather than failing.
  # Under the overlay, a mint failure is an infra problem, not a
  # per-scenario skip condition — every scenario in the METRICS_URL
  # call-site inventory needs this token to scrape anything, so fail the
  # whole run loudly rather than let those scenarios silently degrade to
  # "unauthenticated / always-skip".
  NATIVE_TOKENS_OVERLAY=0
  for o in "${OVERLAYS[@]:-}"; do [ "$o" = "native-tokens" ] && NATIVE_TOKENS_OVERLAY=1; done
  if [ "$NATIVE_TOKENS_OVERLAY" = 1 ]; then
    IN_METRICS_TOKEN="$(mint_metrics_token)" || { echo "could not mint the read_metrics scrape token" >&2; exit 1; }
  else
    IN_METRICS_TOKEN=""
    echo "metrics-content assertions skip on the legacy-posture base stack" \
         "(no native-token validator) — run with --compose-overlay=native-tokens" \
         "to assert them" >&2
  fi
else
  : "${HORT_URL:?external mode needs HORT_URL}"; : "${KEYCLOAK_URL:?external mode needs KEYCLOAK_URL}"
  maybe_build_client_image
  # External /metrics is usually an internal control-plane port, not on HORT_URL;
  # leave IN_METRICS empty unless the caller set METRICS_URL → assert_metric_ingest
  # then skips rather than failing on a 404 (S2). METRICS_TOKEN mirrors it:
  # external mode has no gitops-managed metrics-scraper SA to admin-mint
  # against, so the caller supplies a pre-minted read_metrics-granted
  # bearer via the METRICS_TOKEN env var if they want the scrape
  # assertions to run authenticated; unset means they stay skipped exactly
  # like the METRICS_URL-unset case already did pre-#113.
  IN_HORT="$HORT_URL"; IN_KC="$KEYCLOAK_URL"; IN_METRICS="${METRICS_URL:-}"
  IN_METRICS_TOKEN="${METRICS_TOKEN:-}"
  NET_ARGS=(); DB_DSN="${HORT_DB_DSN:-}"
fi

run_one() {  # group name path
  local group="$1" name="$2" path="$3" rel="${3#"$SCRIPT_DIR"/}"
  # --add-host lets external-mode clients reach a host-mapped hort via
  # host.docker.internal (Linux needs the explicit host-gateway mapping; it is a
  # harmless no-op in compose mode, where NET_ARGS attaches the compose network).
  # HORT_COMPOSE_OVERLAYS: the active --compose-overlay names (space-separated)
  # so a scenario can adapt to an overlay-reconfigured stack (e.g. the
  # provenance scenario switches to the /v2/auth token dance under
  # `native-tokens`). External mode: set it in the environment to match the
  # external stack's posture.
  docker run --rm --add-host=host.docker.internal:host-gateway "${NET_ARGS[@]}" \
    -e HORT_URL="$IN_HORT" -e KEYCLOAK_URL="$IN_KC" -e METRICS_URL="$IN_METRICS" \
    -e METRICS_TOKEN="$IN_METRICS_TOKEN" \
    -e HORT_DB_DSN="$DB_DSN" \
    -e HORT_COMPOSE_OVERLAYS="${OVERLAYS[*]:-${HORT_COMPOSE_OVERLAYS:-}}" \
    -v "$SCRIPT_DIR":/work:ro -e FIXTURES=/work/fixtures \
    "$IMAGE" bash "/work/$rel"
}

# Probe real internet egress once, using the client image so the result matches
# what scenarios actually get. Overrides the optimistic default used by --list.
if docker run --rm "$IMAGE" curl -fsS -o /dev/null --max-time 8 https://registry.npmjs.org/lodash >/dev/null 2>&1; then
  EGRESS=yes
else
  EGRESS=no
fi
echo "egress: $EGRESS"

PASS=(); FAILED=(); SKIPPED=(); QUARANTINED=()
while IFS=$'\t' read -r group name path reqs; do
  q="$(scenario_quarantine "$path")"
  if [ -n "$q" ]; then QUARANTINED+=("$group/$name ($q)"); continue; fi
  if miss="$(is_available "$reqs")"; then :; else SKIPPED+=("$group/$name (needs: $miss)"); continue; fi
  echo ">>> $group/$name"; rc=0; run_one "$group" "$name" "$path" || rc=$?
  # 0=pass, 77=scenario self-skip (the `skip` helper), anything else=fail (incl.
  # a tool crash exiting 2, which must NOT be mistaken for a skip).
  case "$rc" in
    0)  PASS+=("$group/$name");;
    77) SKIPPED+=("$group/$name (skipped)");;
    # Dump BEFORE the next scenario runs and long before the EXIT trap tears
    # the stack down, so the logs belong unambiguously to this scenario.
    *)  FAILED+=("$group/$name"); dump_failure_logs "$group/$name";;
  esac
done < <(selected)

echo ""; echo "PASS=${#PASS[@]} FAIL=${#FAILED[@]} SKIP=${#SKIPPED[@]} QUARANTINED=${#QUARANTINED[@]}"
if [ "${#QUARANTINED[@]}" -gt 0 ]; then printf '  quarantined: %s\n' "${QUARANTINED[@]}"; fi
printf '  skip: %s\n' "${SKIPPED[@]:-}"; printf '  FAIL: %s\n' "${FAILED[@]:-}"
[ "${#FAILED[@]}" -eq 0 ]
