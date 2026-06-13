#!/usr/bin/env bash
# scripts/native-tests/run.sh — the single native-tests runner (CI + local).
# Usage:
#   ./run.sh [--hort=compose|external] [--group G]... [--scenario N]...
#            [--compose-overlay O]... [--list] [--keep]
# Env (external mode): HORT_URL, KEYCLOAK_URL[, METRICS_URL, HORT_DB_DSN].
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
IMAGE="hort-test-client:dev"
KC_DISCOVERY="http://localhost:25082/realms/hort/.well-known/openid-configuration"
HOST_METRICS="http://localhost:25090/metrics"

# Context is the repo root: the Dockerfile's stage 1 builds hort-cli from the
# workspace (.dockerignore keeps target/.git out, so the context stays small).
build_image() { docker build -q -f "$SCRIPT_DIR/Dockerfile.client" -t "$IMAGE" "$REPO_ROOT" >/dev/null; }
now() { date +%s; }
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

# The worker has no HTTP health/port, so readiness = compose reports it running.
wait_running() { local svc="$1" t="${2:-180}"; local d=$(( $(now)+t )); until docker compose "${CA[@]}" "${PROFILE_ARGS[@]}" ps --status running --services 2>/dev/null | grep -qx "$svc"; do [ "$(now)" -ge "$d" ] && return 1; sleep 2; done; }

STARTED=0
# Profile-aware teardown: a worker started under --profile worker is only
# reliably removed when the same profile is on the `down` (otherwise it lingers).
cleanup() { [ "$STARTED" = 1 ] && [ "$KEEP" = 0 ] && docker compose "${CA[@]}" "${PROFILE_ARGS[@]}" down -v --remove-orphans || true; }
trap cleanup EXIT

if [ "$HORT_MODE" = "compose" ]; then
  build_image
  docker compose "${CA[@]}" "${PROFILE_ARGS[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose "${CA[@]}" "${PROFILE_ARGS[@]}" up -d --build
  STARTED=1
  wait_url "$KC_DISCOVERY" 120 || { echo "Keycloak not ready" >&2; exit 1; }
  wait_url "$HOST_METRICS" 120 || { echo "hort-server not ready" >&2; exit 1; }
  [ "$NEED_WORKER" = 1 ] && { wait_running hort-worker 180 || { echo "hort-worker not running" >&2; exit 1; }; }
  IN_HORT="http://hort-server:8080"; IN_KC="http://keycloak:8080/realms/hort"; IN_METRICS="http://hort-server:9090/metrics"
  NET_ARGS=(--network "$COMPOSE_NETWORK")
  DB_DSN="postgres://registry:registry@postgres:5432/artifact_registry"
else
  : "${HORT_URL:?external mode needs HORT_URL}"; : "${KEYCLOAK_URL:?external mode needs KEYCLOAK_URL}"
  build_image
  # External /metrics is usually an internal control-plane port, not on HORT_URL;
  # leave IN_METRICS empty unless the caller set METRICS_URL → assert_metric_ingest
  # then skips rather than failing on a 404 (S2).
  IN_HORT="$HORT_URL"; IN_KC="$KEYCLOAK_URL"; IN_METRICS="${METRICS_URL:-}"
  NET_ARGS=(); DB_DSN="${HORT_DB_DSN:-}"
fi

run_one() {  # group name path
  local group="$1" name="$2" path="$3" rel="${3#"$SCRIPT_DIR"/}"
  # --add-host lets external-mode clients reach a host-mapped hort via
  # host.docker.internal (Linux needs the explicit host-gateway mapping; it is a
  # harmless no-op in compose mode, where NET_ARGS attaches the compose network).
  docker run --rm --add-host=host.docker.internal:host-gateway "${NET_ARGS[@]}" \
    -e HORT_URL="$IN_HORT" -e KEYCLOAK_URL="$IN_KC" -e METRICS_URL="$IN_METRICS" \
    -e HORT_DB_DSN="$DB_DSN" \
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
  case "$rc" in 0) PASS+=("$group/$name");; 77) SKIPPED+=("$group/$name (skipped)");; *) FAILED+=("$group/$name");; esac
done < <(selected)

echo ""; echo "PASS=${#PASS[@]} FAIL=${#FAILED[@]} SKIP=${#SKIPPED[@]} QUARANTINED=${#QUARANTINED[@]}"
if [ "${#QUARANTINED[@]}" -gt 0 ]; then printf '  quarantined: %s\n' "${QUARANTINED[@]}"; fi
printf '  skip: %s\n' "${SKIPPED[@]:-}"; printf '  FAIL: %s\n' "${FAILED[@]:-}"
[ "${#FAILED[@]}" -eq 0 ]
