#!/usr/bin/env bash
# requires: egress
# quarantine: coalescing assertions (follower_waited_hit >=N, upstream_fetch{npm}) are wrong for npm's serialized installs — under rework, tracked separately
# Pull-through coalescing scenario.
#
# Drives 10 concurrent `npm install <pinned-leaf-package>` requests through
# the npm proxy repo declared in deploy/compose/example-config/repositories/
# npm-public.yaml (registry.npmjs.org pull-through). Captures /metrics
# before + after; asserts the PullDedup service collapsed the 10-way race
# down to one upstream packument fetch + one upstream tarball fetch.
#
# Why a leaf package: lodash@4.17.21 declares no `dependencies` (verified
# with `npm view lodash@4.17.21 dependencies` → undefined). `npm install`
# therefore resolves to exactly one tarball + one packument GET. With a
# transitive tree the unique-tarball count would drift across npm resolution
# algorithm changes and break the deterministic upper-bound assertion.
#
# Cardinality model — what gets emitted, where:
#
#   PullDedup::coalesce_metadata for the packument fetch is keyed on
#   `(repo_id, "/lodash")` and emits `format="npm"`.
#   PullDedup::coalesce_blob for the tarball uses DedupKey::blob_by_hash
#   keyed on the SRI integrity string and emits `format="_any"` per the
#   cross-format blob coalescing model (crates/hort-app/src/pull_dedup.rs:264).
#
#   So for a single leaf package and 10 concurrent installs:
#     hort_pull_dedup_total{format="npm",   outcome="leader_started"}     +1   (packument)
#     hort_pull_dedup_total{format="_any",  outcome="leader_started"}     +1   (tarball)
#     hort_pull_dedup_total{format="npm",   outcome="follower_waited_hit"} ≥9  (packument)
#     hort_pull_dedup_total{format="_any",  outcome="follower_waited_hit"} ≥9  (tarball)
#     hort_upstream_fetch_total{format="npm",result="success"}            +2   (packument + tarball)
#
# NOTE: the coalescing assertions are known timing-sensitive (tracked
# separately). They are ported faithfully — do not relax them.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

NPM_REPO_KEY="${NPM_REPO_KEY:-npm-public}"

PKG_NAME="${PKG_NAME:-lodash}"
PKG_VERSION="${PKG_VERSION:-4.17.21}"
CONCURRENCY="${CONCURRENCY:-10}"
EXPECTED_TARBALLS="${EXPECTED_TARBALLS:-1}"

log "==> Pull-through coalescing scenario"
log "Registry:        ${HORT_URL}"
log "Metrics:         ${METRICS_URL}"
log "Repo key:        ${NPM_REPO_KEY}"
log "Package:         ${PKG_NAME}@${PKG_VERSION}"
log "Concurrency:     ${CONCURRENCY}"
log "Expected tarballs (N): ${EXPECTED_TARBALLS}"

# Tool prereqs (node + npm baked into the client image; curl + python3 too).
command -v node  >/dev/null 2>&1 || skip "node not found"
command -v npm   >/dev/null 2>&1 || skip "npm not found"
command -v curl  >/dev/null 2>&1 || skip "curl not found"

# ---------------------------------------------------------------------
# Preflight 1: probe the metrics endpoint. If /metrics is unreachable
# the stack is not up — skip cleanly (exit 77).
# ---------------------------------------------------------------------
log ""
log "--- Preflight: probing ${METRICS_URL}"
if ! curl -sf -o /dev/null --max-time 5 "$METRICS_URL"; then
    skip "metrics endpoint not reachable at ${METRICS_URL} — bring up deploy/compose/docker-compose.yml first"
fi
log "  metrics endpoint reachable"

HEALTH_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${HORT_URL}/health" 2>/dev/null || echo "000")
case "$HEALTH_CODE" in
    200|401|404)
        log "  registry /health responded HTTP ${HEALTH_CODE} (reachable)"
        ;;
    *)
        skip "registry not reachable at ${HORT_URL}/health (got HTTP ${HEALTH_CODE})"
        ;;
esac

# ---------------------------------------------------------------------
# Preflight 2: the npm proxy repo must exist. 404 = not configured.
# ---------------------------------------------------------------------
NPM_REGISTRY_URL="${HORT_URL%/}/npm/${NPM_REPO_KEY}/"
PROBE_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${NPM_REGISTRY_URL}${PKG_NAME}" 2>/dev/null || echo "000")
log "  GET ${NPM_REGISTRY_URL}${PKG_NAME} -> HTTP ${PROBE_CODE}"
case "$PROBE_CODE" in
    200|401|403)
        ;;
    404)
        skip "npm repo '${NPM_REPO_KEY}' not found — declare it in deploy/compose/example-config/repositories/${NPM_REPO_KEY}.yaml"
        ;;
    *)
        skip "registry returned unexpected HTTP ${PROBE_CODE} for the packument probe — stack not fully up"
        ;;
esac

# ---------------------------------------------------------------------
# Helpers: read the running value of a metric. Implemented in one awk
# pass to dodge `grep | awk` pipefail bites under set -e -o pipefail
# (no matches → grep exits 1 → set -e aborts; awk's regex match always
# exits 0). Pattern mirrors test-npm-upstream-verification.sh:200-204.
#
# Args: $1 = label-match snippet, e.g. 'format="npm".*outcome="leader_started"'.
# Returns the integer sum to stdout.
read_pull_dedup_metric() {
    local pattern="$1"
    curl -sf "$METRICS_URL" 2>/dev/null \
        | awk -v pat="$pattern" '
            $0 ~ ("^hort_pull_dedup_total\\{[^}]*" pat "[^}]*\\}") { s += $NF }
            END { printf "%d\n", (s+0) }
          ' \
        || true
}

read_upstream_fetch_metric() {
    # hort_upstream_fetch_total{format="npm",upstream="...",result="success"} N
    local pattern="$1"
    curl -sf "$METRICS_URL" 2>/dev/null \
        | awk -v pat="$pattern" '
            $0 ~ ("^hort_upstream_fetch_total\\{[^}]*" pat "[^}]*\\}") { s += $NF }
            END { printf "%d\n", (s+0) }
          ' \
        || true
}

# ---------------------------------------------------------------------
# Snapshot baseline. Captures both "packument" (format="npm") and
# "blob" (format="_any") entries because the npm tarball coalesce
# uses DedupKey::blob_by_hash → format="_any" sentinel
# (crates/hort-app/src/pull_dedup.rs:260, design doc §3).
# ---------------------------------------------------------------------
log ""
log "--- Capturing baseline metric snapshot"

DEDUP_LEADER_NPM_BEFORE=$(read_pull_dedup_metric 'format="npm".*outcome="leader_started"')
DEDUP_LEADER_ANY_BEFORE=$(read_pull_dedup_metric 'format="_any".*outcome="leader_started"')
DEDUP_FOLLOWER_NPM_BEFORE=$(read_pull_dedup_metric 'format="npm".*outcome="follower_waited_hit"')
DEDUP_FOLLOWER_ANY_BEFORE=$(read_pull_dedup_metric 'format="_any".*outcome="follower_waited_hit"')
UPSTREAM_FETCH_BEFORE=$(read_upstream_fetch_metric 'format="npm".*result="success"')

log "  baseline hort_pull_dedup_total{format=npm, outcome=leader_started}     = ${DEDUP_LEADER_NPM_BEFORE}"
log "  baseline hort_pull_dedup_total{format=_any,outcome=leader_started}     = ${DEDUP_LEADER_ANY_BEFORE}"
log "  baseline hort_pull_dedup_total{format=npm, outcome=follower_waited_hit}= ${DEDUP_FOLLOWER_NPM_BEFORE}"
log "  baseline hort_pull_dedup_total{format=_any,outcome=follower_waited_hit}= ${DEDUP_FOLLOWER_ANY_BEFORE}"
log "  baseline hort_upstream_fetch_total{format=npm,result=success}          = ${UPSTREAM_FETCH_BEFORE}"

# ---------------------------------------------------------------------
# Spawn N concurrent `npm install`s. Each install runs in its own
# scratch directory with its own scratch HOME + npm cache so they
# don't share node_modules / a packument cache (which would make npm
# itself dedup the work and zero out the upstream race we're measuring).
# Background each install with `&` and wait on all PIDs at the end.
# ---------------------------------------------------------------------
RUN_DIR="$(mktemp -d -t pull-dedup-XXXXXX)"
trap 'rm -rf "$RUN_DIR"' EXIT
log ""
log "--- Spawning ${CONCURRENCY} concurrent npm installs of ${PKG_NAME}@${PKG_VERSION}"
log "    Run dir: ${RUN_DIR}"

PIDS=()
for i in $(seq 1 "$CONCURRENCY"); do
    (
        WORKER="${RUN_DIR}/worker-${i}"
        mkdir -p "$WORKER/home" "$WORKER/cache" "$WORKER/proj"

        # Per-worker HOME so each writes its own .npmrc. Per-worker cache
        # so a previous worker's packument doesn't short-circuit a later
        # worker's upstream fetch (defeating the race).
        export HOME="$WORKER/home"
        export npm_config_cache="$WORKER/cache"

        cd "$WORKER/proj" || exit 1
        npm config set registry "$NPM_REGISTRY_URL"

        # `--prefer-online` forces the packument re-fetch even though we
        # already gave each worker a clean cache. Belt-and-braces: the
        # cache is per-worker, but a future npm version may decide to
        # consult a shared offline mirror; the flag pins behaviour.
        # Output is suppressed; failure is detected via exit code.
        if ! npm install --no-audit --no-fund --prefer-online \
            "${PKG_NAME}@${PKG_VERSION}" \
            > "${WORKER}/install.log" 2>&1; then
            echo "[worker ${i}] FAILED — install.log tail:"
            tail -n 20 "${WORKER}/install.log" | sed 's/^/    /'
            exit 1
        fi
        echo "[worker ${i}] ok"
    ) &
    PIDS+=($!)
done

# Wait on every worker; collect the joint exit status. We do NOT abort on
# the first failure — the metric snapshot below is more informative when
# we see the partial outcome.
WORKER_FAILURES=0
for pid in "${PIDS[@]}"; do
    if ! wait "$pid"; then
        WORKER_FAILURES=$((WORKER_FAILURES + 1))
    fi
done
log "  ${CONCURRENCY} workers complete, ${WORKER_FAILURES} failed"
if [ "$WORKER_FAILURES" -gt 0 ]; then
    fail "${WORKER_FAILURES}/${CONCURRENCY} npm installs failed" "see worker logs above"
    # Don't exit yet — the metric dump below is the diagnostic the
    # human reviewer needs.
fi

# ---------------------------------------------------------------------
# Snapshot post-state and compute deltas.
# ---------------------------------------------------------------------
log ""
log "--- Capturing post-test metric snapshot"

DEDUP_LEADER_NPM_AFTER=$(read_pull_dedup_metric 'format="npm".*outcome="leader_started"')
DEDUP_LEADER_ANY_AFTER=$(read_pull_dedup_metric 'format="_any".*outcome="leader_started"')
DEDUP_FOLLOWER_NPM_AFTER=$(read_pull_dedup_metric 'format="npm".*outcome="follower_waited_hit"')
DEDUP_FOLLOWER_ANY_AFTER=$(read_pull_dedup_metric 'format="_any".*outcome="follower_waited_hit"')
UPSTREAM_FETCH_AFTER=$(read_upstream_fetch_metric 'format="npm".*result="success"')

DELTA_LEADER_NPM=$((DEDUP_LEADER_NPM_AFTER - DEDUP_LEADER_NPM_BEFORE))
DELTA_LEADER_ANY=$((DEDUP_LEADER_ANY_AFTER - DEDUP_LEADER_ANY_BEFORE))
DELTA_FOLLOWER_NPM=$((DEDUP_FOLLOWER_NPM_AFTER - DEDUP_FOLLOWER_NPM_BEFORE))
DELTA_FOLLOWER_ANY=$((DEDUP_FOLLOWER_ANY_AFTER - DEDUP_FOLLOWER_ANY_BEFORE))
DELTA_UPSTREAM=$((UPSTREAM_FETCH_AFTER - UPSTREAM_FETCH_BEFORE))

log "  Δ hort_pull_dedup_total{format=npm, outcome=leader_started}     = ${DELTA_LEADER_NPM}   (expect 1)"
log "  Δ hort_pull_dedup_total{format=_any,outcome=leader_started}     = ${DELTA_LEADER_ANY}   (expect ${EXPECTED_TARBALLS})"
log "  Δ hort_pull_dedup_total{format=npm, outcome=follower_waited_hit}= ${DELTA_FOLLOWER_NPM} (expect ≥ $((CONCURRENCY - 1)))"
log "  Δ hort_pull_dedup_total{format=_any,outcome=follower_waited_hit}= ${DELTA_FOLLOWER_ANY} (expect ≥ $((CONCURRENCY - 1)) per tarball)"
log "  Δ hort_upstream_fetch_total{format=npm,result=success}          = ${DELTA_UPSTREAM}   (expect $((1 + EXPECTED_TARBALLS)))"

# ---------------------------------------------------------------------
# Assertions — ordered so the most diagnostic failure surfaces first.
#   1. upstream-fetch delta = 1 + N (one packument + one per unique tarball)
#   2. leader_started delta = 1 + N (same shape)
#   3. follower_waited_hit ≥ 9 × (1 + N) (loose lower bound on race ordering)
# ---------------------------------------------------------------------
EXPECTED_UPSTREAM=$((1 + EXPECTED_TARBALLS))
if [ "$DELTA_UPSTREAM" -eq "$EXPECTED_UPSTREAM" ]; then
    pass "upstream fetch delta is ${DELTA_UPSTREAM} (= 1 packument + ${EXPECTED_TARBALLS} tarball)"
else
    fail "expected hort_upstream_fetch_total{format=npm,result=success} delta = ${EXPECTED_UPSTREAM}, got ${DELTA_UPSTREAM}" "coalescing did not collapse the race"
fi

# leader_started: one per coalesce window.
if [ "$DELTA_LEADER_NPM" -eq 1 ]; then
    pass "packument leader_started delta is 1"
else
    fail "expected hort_pull_dedup_total{format=npm,outcome=leader_started} delta = 1, got ${DELTA_LEADER_NPM}" ""
fi

if [ "$DELTA_LEADER_ANY" -eq "$EXPECTED_TARBALLS" ]; then
    pass "tarball leader_started delta is ${DELTA_LEADER_ANY}"
else
    fail "expected hort_pull_dedup_total{format=_any,outcome=leader_started} delta = ${EXPECTED_TARBALLS}, got ${DELTA_LEADER_ANY}" ""
fi

# follower_waited_hit: ≥ (concurrency - 1) per coalesce window. Loose bound
# because the very first request may complete its fetch before later ones
# can attach as followers, especially on a fast LAN.
LOWER_BOUND_FOLLOWERS=$((CONCURRENCY - 1))
if [ "$DELTA_FOLLOWER_NPM" -ge "$LOWER_BOUND_FOLLOWERS" ]; then
    pass "packument follower_waited_hit delta is ${DELTA_FOLLOWER_NPM} (≥ ${LOWER_BOUND_FOLLOWERS})"
else
    fail "expected hort_pull_dedup_total{format=npm,outcome=follower_waited_hit} delta ≥ ${LOWER_BOUND_FOLLOWERS}, got ${DELTA_FOLLOWER_NPM}" ""
fi

# Tarball follower lower bound: same shape × N tarballs.
TARBALL_FOLLOWER_LOWER=$((LOWER_BOUND_FOLLOWERS * EXPECTED_TARBALLS))
if [ "$DELTA_FOLLOWER_ANY" -ge "$TARBALL_FOLLOWER_LOWER" ]; then
    pass "tarball follower_waited_hit delta is ${DELTA_FOLLOWER_ANY} (≥ ${TARBALL_FOLLOWER_LOWER})"
else
    fail "expected hort_pull_dedup_total{format=_any,outcome=follower_waited_hit} delta ≥ ${TARBALL_FOLLOWER_LOWER}, got ${DELTA_FOLLOWER_ANY}" ""
fi

# ---------------------------------------------------------------------
# Failure-mode dump: on any assertion miss, print the relevant metric
# lines so the CI log shows the actual shape of /metrics, not just the
# computed deltas.
# ---------------------------------------------------------------------
if [ "$_FAIL" -gt 0 ]; then
    log ""
    log "--- /metrics dump (hort_pull_dedup* and hort_upstream_fetch*) ---"
    curl -sf "$METRICS_URL" 2>/dev/null \
        | grep -E '^hort_pull_dedup|^hort_upstream_fetch' \
        | sort \
        || log "  (curl failed — metrics endpoint unreachable)"
    log "------------------------------------------------------------"
fi

summary
