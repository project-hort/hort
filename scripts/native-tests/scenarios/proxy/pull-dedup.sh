#!/usr/bin/env bash
# requires: egress db
# Pull-through request-coalescing scenario (hort-app's `PullDedup`).
#
# ---------------------------------------------------------------------------
# WHAT IS ASSERTED, AND WHY IT NEEDS NO CONCURRENCY
# ---------------------------------------------------------------------------
# `PullDedup` coalesces on two layers. Layer A is the per-replica in-process
# broadcast join — genuinely concurrency-dependent, and therefore only
# probed best-effort at the very end of this file. Layer B is the
# cluster-wide `EphemeralStore` record, and it is what this scenario gates
# on, because it needs no concurrency at all:
#
#   the leader writes its TERMINAL SUCCESS record under the dedup key and
#   that record lives for `leader_lock_ttl`
#   (`PullDedupConfig::defaults`, HORT_PULL_DEDUP_LEADER_LOCK_TTL_SECS,
#   default 90s — not overridden in deploy/compose/docker-compose.yml),
#
# so ANY caller arriving on the same key inside that window takes the fast
# path and is counted as `outcome="follower_waited_hit"` with
# `layer="cluster"`. Two SEQUENTIAL requests inside the window therefore
# assert the coalescing property deterministically. A concurrency-based
# formulation cannot: `npm install` serialises its installs, so ten parallel
# invocations never produce ten in-flight requests for one key.
#
# The key that makes a sequential follower reachable is the BLOB key.
# `DedupKey::blob_by_hash` is derived from the tarball's `dist.integrity`
# SRI alone (crates/hort-app/src/pull_dedup.rs) — cross-repository and
# cross-format by construction, because the content hash is the natural
# dedup boundary. `DedupKey::metadata`, by contrast, is keyed per
# repository (two repos may carry different trust configs), and so is the
# npm packument projection cache (keyed per upstream mapping). Hence the
# shape of this scenario: the SAME tarball pulled through TWO repositories,
# the second arriving as a blob follower while each repository still fetches
# its own packument.
#
# ---------------------------------------------------------------------------
# CARDINALITY MODEL — the exact expectation for the two-leg drive
# ---------------------------------------------------------------------------
# Leg 1 (leader repo, cold) — one GET of the tarball URL:
#   packument miss  -> coalesce_metadata leader   -> 1 upstream metadata fetch
#   tarball  miss   -> coalesce_blob     leader   -> 1 upstream artifact fetch
# Leg 2 (follower repo, cold) — one GET of the same tarball URL:
#   packument miss  -> coalesce_metadata leader   -> 1 upstream metadata fetch
#                      (per-repository key; a leader, never a follower)
#   tarball         -> coalesce_blob FOLLOWER     -> 0 upstream fetches
#                      (the leader's terminal record is still live)
#
#   Δ hort_pull_dedup_total{format="npm", outcome="leader_started"}      = 2
#   Δ hort_pull_dedup_total{format="_any",outcome="leader_started"}      = 1
#   Δ hort_pull_dedup_total{format="_any",outcome="follower_waited_hit"} ≥ 1
#   Δ hort_upstream_fetch_total{result="success"} (all formats)          = 3
#
# WHAT A NO-COALESCING BUILD WOULD PRODUCE. If leg 2's tarball stopped
# taking the fast path — the terminal record not written, not read, or the
# blob keyspace made per-repository — leg 2 would elect its own leader and
# fetch the tarball itself:
#   follower_waited_hit{_any} 0  (assertion demands ≥ 1  -> FAIL)
#   leader_started{_any}      2  (assertion demands = 1  -> FAIL)
#   upstream_fetch{result=success} (all formats) 4  (assertion demands = 3  -> FAIL)
# and, independently of any counter, the follower repo's row would carry a
# `ChecksumVerified` event (it only fires when bytes are actually fetched
# and re-hashed) — which the event assertions below demand is ABSENT.
# There is no build in which coalescing stops happening and this scenario
# still passes.
#
# ---------------------------------------------------------------------------
# WHY A DEDICATED REPOSITORY PAIR
# ---------------------------------------------------------------------------
# Both legs must start COLD: a package already resident in a repository is
# served straight from CAS and never enters `PullDedup` at all, so a leg
# through the shared npm-public mirror would silently stop being a leader
# the moment another scenario pulled the same package. The pair
# (npm-dedup-leader-e2e / npm-dedup-follower-e2e, with matched 24h
# quarantining ScanPolicies) exists for that isolation and for the
# quarantine-anchor parity assertion below — see
# deploy/compose/example-config/policies/npm-dedup-leader-e2e-quarantine.yaml
# for why a NON-ZERO window is what makes that assertion mean anything.
#
# Consequence of the quarantining policy: both tarball GETs answer 503 with
# a Retry-After. That is the designed hold, and it happens AFTER the
# pull-through has minted the row — the row is what this scenario reads.
#
# ---------------------------------------------------------------------------
# WHY A LEAF PACKAGE
# ---------------------------------------------------------------------------
# lodash@4.17.21 declares no `dependencies`, so a tarball pull resolves to
# exactly one packument GET + one tarball GET. With a transitive tree the
# upstream-fetch count would drift across upstream metadata changes and
# break the deterministic equality above.
#
# ---------------------------------------------------------------------------
# STRUCTURAL COMPLETENESS OF THE FOLLOWER'S ROW
# ---------------------------------------------------------------------------
# A cross-repository blob follower has no row in its own repository when the
# coalesce returns (the leader minted only the leader repo's row), so it
# mints its own via `IngestUseCase::register_existing_cas_blob`. Two defects
# in that registration reached a release gate: the row was minted without
# its `content_references` membership edges, and it was minted through a
# quarantine gate that did not match the one the leader's row went through.
# Both are pinned below, on the FOLLOWER's own row in its OWN repository.
#
# Not covered here (covered by quarantine/proxy-multiarch-zero-window.sh,
# which needs a reference tree this npm leaf does not have): the
# referenced-tree-descendant ZERO-window carve-out itself. lodash is nobody's
# descendant, so neither row takes that carve-out and both anchor on the
# content-level age evidence instead — which is precisely what the parity
# assertion checks they agree on.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

LEADER_REPO_KEY="${LEADER_REPO_KEY:-npm-dedup-leader-e2e}"
FOLLOWER_REPO_KEY="${FOLLOWER_REPO_KEY:-npm-dedup-follower-e2e}"

PKG_NAME="${PKG_NAME:-lodash}"
PKG_VERSION="${PKG_VERSION:-4.17.21}"

# The Layer-B terminal-success record's lifetime, in seconds. Read under the
# same variable name the server parses (crates/hort-server/src/config.rs
# `parse_pull_dedup_leader_lock_ttl_secs`), with the same default;
# scripts/native-tests/run.sh forwards it into the scenario container, so an
# operator who retunes the server points this scenario at the same value
# instead of editing an assertion. The two-leg drive must complete well
# inside the window; the guard below spends at most half of it and names the
# variable when it does not, so a retuned (or merely slow) stack fails with a
# diagnosis rather than an unexplained counter mismatch.
LEADER_LOCK_TTL_SECS="${HORT_PULL_DEDUP_LEADER_LOCK_TTL_SECS:-90}"
DRIVE_BUDGET_SECS=$((LEADER_LOCK_TTL_SECS / 2))

# Best-effort Layer-A probe (never gates — see its section).
PROBE_CONCURRENCY="${PROBE_CONCURRENCY:-6}"
PROBE_PKG="${PROBE_PKG:-is-number}"
PROBE_VERSION="${PROBE_VERSION:-7.0.0}"

TARBALL_FILE="${PKG_NAME}-${PKG_VERSION}.tgz"
ARTIFACT_PATH="${PKG_NAME}/-/${TARBALL_FILE}"
LEADER_TARBALL_URL="${HORT_URL%/}/npm/${LEADER_REPO_KEY}/${ARTIFACT_PATH}"
FOLLOWER_TARBALL_URL="${HORT_URL%/}/npm/${FOLLOWER_REPO_KEY}/${ARTIFACT_PATH}"

log "==> Pull-through coalescing scenario (cross-repository Layer-B follower)"
log "Registry:        ${HORT_URL}"
log "Metrics:         ${METRICS_URL:-<unset>}"
log "Leader repo:     ${LEADER_REPO_KEY}"
log "Follower repo:   ${FOLLOWER_REPO_KEY}"
log "Package:         ${PKG_NAME}@${PKG_VERSION}"
log "Leader-lock TTL: ${LEADER_LOCK_TTL_SECS}s (drive budget ${DRIVE_BUDGET_SECS}s)"

command -v curl >/dev/null 2>&1 || skip "curl not found"
command -v psql >/dev/null 2>&1 || skip "psql not found"
[ -n "${HORT_DB_DSN:-}" ] || skip "HORT_DB_DSN unset (needs requires: db)"

# ---------------------------------------------------------------------
# Preflight. Deliberately does NOT touch either repository over HTTP: a
# packument probe IS a pull-through, so it would consume the very metadata
# coalescing windows the cardinality model counts and leave a fresh
# projection cache behind. Existence is established through the DB
# instead, which costs the registry nothing.
#
# A missing repository pair means this hort does not declare it (an
# external hort) — a genuinely-absent environment, hence skip. In compose
# the pair's presence is separately gated by gitops/gitops.sh, so a failed
# apply surfaces there as a failure rather than hiding here as a skip.
# ---------------------------------------------------------------------
log ""
log "--- Preflight"

HEALTH_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${HORT_URL}/health" 2>/dev/null || echo "000")
case "$HEALTH_CODE" in
    200|401|404) log "  registry /health responded HTTP ${HEALTH_CODE} (reachable)" ;;
    *) skip "registry not reachable at ${HORT_URL}/health (got HTTP ${HEALTH_CODE})" ;;
esac

LEADER_REPO_ID="$(psql_one "SELECT id FROM repositories WHERE key = '${LEADER_REPO_KEY}';")"
FOLLOWER_REPO_ID="$(psql_one "SELECT id FROM repositories WHERE key = '${FOLLOWER_REPO_KEY}';")"
if [ -z "$LEADER_REPO_ID" ] || [ -z "$FOLLOWER_REPO_ID" ]; then
    skip "repository pair not declared here (leader='${LEADER_REPO_ID:-<none>}' follower='${FOLLOWER_REPO_ID:-<none>}') — declare deploy/compose/example-config/repositories/${LEADER_REPO_KEY}.yaml and ${FOLLOWER_REPO_KEY}.yaml"
fi
log "  leader repo id   = ${LEADER_REPO_ID}"
log "  follower repo id = ${FOLLOWER_REPO_ID}"

# The repository envelope's `spec.proxy.upstreamUrl` is validator-only —
# without an UpstreamMapping row the pull-through 404s and every assertion
# below would fail with an unhelpful diagnosis.
for repo in "leader:${LEADER_REPO_ID}" "follower:${FOLLOWER_REPO_ID}"; do
    repo_label="${repo%%:*}"; repo_id="${repo##*:}"
    mapping_count="$(psql_one "SELECT count(*) FROM repository_upstream_mappings WHERE repository_id = '${repo_id}';")"
    if [ "${mapping_count:-0}" -ge 1 ]; then
        log "  ${repo_label} repo has ${mapping_count} upstream mapping(s)"
    else
        fail "${repo_label} repository has an UpstreamMapping" \
            "no repository_upstream_mappings row for ${repo_id} — declare deploy/compose/example-config/upstreams/<repo>.yaml"
        summary
    fi
done

# Both legs must start cold: a package already resident in a repository is
# served from CAS and never enters PullDedup, so a leftover row from an
# earlier run in the same stack would silently gut the drive.
for repo in "leader:${LEADER_REPO_ID}" "follower:${FOLLOWER_REPO_ID}"; do
    repo_label="${repo%%:*}"; repo_id="${repo##*:}"
    resident="$(psql_one "SELECT count(*) FROM artifacts WHERE repository_id = '${repo_id}' AND path = '${ARTIFACT_PATH}';")"
    if [ "${resident:-0}" = "0" ]; then
        log "  ${repo_label} repo is cold for ${PKG_NAME}@${PKG_VERSION}"
    else
        fail "${repo_label} repository is cold for ${PKG_NAME}@${PKG_VERSION}" \
            "${resident} row(s) already present — this repository pair is dedicated to this scenario and must start empty (a re-run against a kept stack needs \`compose down -v\`)"
        summary
    fi
done

# The quarantine anchor is a property of the CONTENT, not of the row: it is
# derived from `MIN(created_at)` over every `artifacts` row sharing the
# hash, unscoped by repository and unfiltered by `is_deleted`. The leader
# assertion below ("the minimum IS my own mint instant") therefore needs
# these bytes to be new to the whole instance, not merely to the pair: a row
# for this tarball in ANY other repository — including a soft-deleted one,
# which withdraws a row from service without un-observing the bytes — moves
# the minimum earlier and falsifies that assertion with nothing wrong in the
# code. Checked by path because the hash is not known until the drive has
# run; a same-bytes row filed under a different path would instead surface
# in the anchor block's row-count diagnostic.
content_elsewhere="$(psql_one "SELECT count(*) FROM artifacts WHERE path = '${ARTIFACT_PATH}';")"
if [ "${content_elsewhere:-0}" = "0" ]; then
    log "  no repository in this instance has ever held ${ARTIFACT_PATH}"
else
    fail "these bytes are new to this hort instance" \
        "${content_elsewhere} artifacts row(s) outside the dedicated pair already carry path ${ARTIFACT_PATH} — the content-level anchor minimum would predate this run's leader row (a re-run against a kept stack needs \`compose down -v\`; against an external hort this scenario needs a package that instance has never proxied)"
    summary
fi

# ---------------------------------------------------------------------
# Metric plumbing. Metric-content assertions are armed only where a
# read_metrics bearer exists (compose `--compose-overlay=native-tokens`,
# or an external hort with METRICS_URL + METRICS_TOKEN supplied). Where it
# does not, `metrics_scrape_preflight` logs a note and this scenario runs
# its structural half only — the DB + event assertions below, which pin
# the same coalescing property without a scrape.
# ---------------------------------------------------------------------
METRICS_ARMED=0
if metrics_scrape_preflight "pull-dedup coalescing counters"; then
    METRICS_ARMED=1
fi

# metric_sum <metric-name> <label="value">... — sum every exposition line
# whose metric name matches exactly and whose label block contains ALL the
# given `label="value"` fragments. Order-independent (the exposition's label
# order is the recorder's business, not ours) and implemented in a single
# awk pass, because a `grep | awk` pipeline with no matches trips
# `set -o pipefail` via grep's exit 1.
metric_sum() {
    local metric="$1"; shift
    curl -sf "${METRICS_AUTH_HEADER[@]}" "$METRICS_URL" 2>/dev/null \
        | awk -v m="$metric" -v want="$*" '
            index($0, m "{") == 1 {
                labels = $0
                sub(/^[^{]*\{/, "", labels)
                sub(/\}.*$/, "", labels)
                n = split(want, toks, " ")
                for (i = 1; i <= n; i++) if (index(labels, toks[i]) == 0) next
                s += $NF
            }
            END { printf "%d\n", (s+0) }
          ' \
        || true
}

dedup_total() { metric_sum hort_pull_dedup_total "$@"; }
# The server builds one pull-through proxy with a single fixed `format`
# label, so every format's upstream fetch is attributed to that one label
# and a per-format filter would read zero. Filter on `result` only; restore
# `format="npm"` once the label identifies the format.
upstream_success() { metric_sum hort_upstream_fetch_total 'result="success"'; }

# Every counter this scenario reasons about, as one string. Used both for
# the quiesce below and for the before/after snapshots.
witness_snapshot() {
    printf '%s|%s|%s|%s|%s' \
        "$(dedup_total 'format="npm"' 'outcome="leader_started"')" \
        "$(dedup_total 'format="_any"' 'outcome="leader_started"')" \
        "$(dedup_total 'format="_any"' 'outcome="follower_waited_hit"')" \
        "$(dedup_total 'format="npm"' 'outcome="follower_waited_hit"')" \
        "$(upstream_success)"
}

# ---------------------------------------------------------------------
# Quiesce. The scenarios that run before this one leave background
# pull-throughs in flight (OCI blob warming, for instance, fetches an
# image's config + layer blobs after the manifest GET has already
# returned) and those emit on the very counters asserted below. Wait for
# two consecutive identical readings before taking the baseline, so the
# deltas measured across the drive are this scenario's alone.
# ---------------------------------------------------------------------
if [ "$METRICS_ARMED" = "1" ]; then
    log ""
    log "--- Quiescing background pull-through traffic"
    QUIESCE_DEADLINE=$(( $(date +%s) + 60 ))
    QUIESCE_LAST=""
    QUIESCE_STABLE=0
    QUIESCE_OK=0
    while :; do
        QUIESCE_NOW="$(witness_snapshot)"
        if [ "$QUIESCE_NOW" = "$QUIESCE_LAST" ]; then
            QUIESCE_STABLE=$((QUIESCE_STABLE + 1))
            if [ "$QUIESCE_STABLE" -ge 2 ]; then QUIESCE_OK=1; break; fi
        else
            QUIESCE_STABLE=0
        fi
        QUIESCE_LAST="$QUIESCE_NOW"
        if [ "$(date +%s)" -ge "$QUIESCE_DEADLINE" ]; then break; fi
        sleep 2
    done
    if [ "$QUIESCE_OK" = "1" ]; then
        log "  counters stable at ${QUIESCE_NOW}"
    else
        fail "quiesce background pull-through traffic" \
            "hort_pull_dedup_total / hort_upstream_fetch_total still moving after 60s (last=${QUIESCE_NOW}) — the deltas below cannot be attributed to this scenario"
        summary
    fi

    LEADER_NPM_BEFORE=$(dedup_total 'format="npm"' 'outcome="leader_started"')
    LEADER_ANY_BEFORE=$(dedup_total 'format="_any"' 'outcome="leader_started"')
    FOLLOWER_ANY_BEFORE=$(dedup_total 'format="_any"' 'outcome="follower_waited_hit"')
    FOLLOWER_CLUSTER_ANY_BEFORE=$(dedup_total 'layer="cluster"' 'format="_any"' 'outcome="follower_waited_hit"')
    UPSTREAM_BEFORE=$(upstream_success)
    log "  baseline leader_started{npm}       = ${LEADER_NPM_BEFORE}"
    log "  baseline leader_started{_any}      = ${LEADER_ANY_BEFORE}"
    log "  baseline follower_waited_hit{_any} = ${FOLLOWER_ANY_BEFORE} (of which layer=cluster: ${FOLLOWER_CLUSTER_ANY_BEFORE})"
    log "  baseline upstream_fetch{result=success} (all formats) = ${UPSTREAM_BEFORE}"
fi

# ---------------------------------------------------------------------
# The drive: two sequential tarball GETs, leader repo then follower repo.
# Each GET is one request — no client-side retry, no packument warm-up —
# so the cardinality model above is exact.
# ---------------------------------------------------------------------
log ""
log "--- Drive: GET the same tarball through both repositories, sequentially"

DRIVE_START=$(date +%s)

LEADER_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 120 "$LEADER_TARBALL_URL" 2>/dev/null || echo "000")
LEADER_DONE=$(date +%s)
log "  leg 1  GET ${LEADER_TARBALL_URL} -> HTTP ${LEADER_CODE} ($((LEADER_DONE - DRIVE_START))s)"

FOLLOWER_CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 120 "$FOLLOWER_TARBALL_URL" 2>/dev/null || echo "000")
DRIVE_END=$(date +%s)
DRIVE_ELAPSED=$((DRIVE_END - DRIVE_START))
log "  leg 2  GET ${FOLLOWER_TARBALL_URL} -> HTTP ${FOLLOWER_CODE} ($((DRIVE_END - LEADER_DONE))s)"
log "  drive elapsed: ${DRIVE_ELAPSED}s"

# The hold is the designed response for a freshly-pulled artifact under a
# quarantining policy, and it proves the pull-through ran to completion.
for leg in "leader:${LEADER_CODE}" "follower:${FOLLOWER_CODE}"; do
    leg_name="${leg%%:*}"; leg_code="${leg##*:}"
    if [ "$leg_code" = "503" ]; then
        pass "${leg_name} leg: tarball GET -> 503 (pull-through completed, quarantine hold applied)"
    else
        fail "${leg_name} leg: tarball GET -> 503" \
            "got HTTP ${leg_code} — expected the 24h quarantining ScanPolicy's hold; a 200 means the policy is not in effect and the anchor assertions below are hollow"
    fi
done

# The TTL guard: the follower's fast path only exists while the leader's
# terminal record lives. Measured from the START of leg 1 (the record is
# written before leg 1's response returns, so this over-estimates the
# record's age at leg 2's read — the conservative direction for a guard).
if [ "$DRIVE_ELAPSED" -le "$DRIVE_BUDGET_SECS" ]; then
    pass "drive completed in ${DRIVE_ELAPSED}s, inside the ${DRIVE_BUDGET_SECS}s budget (half of the ${LEADER_LOCK_TTL_SECS}s leader-lock TTL)"
else
    fail "drive completed inside the leader-lock TTL budget" \
        "took ${DRIVE_ELAPSED}s vs a ${DRIVE_BUDGET_SECS}s budget — the leader's terminal record may have expired before leg 2 read it, so the follower assertions below are not meaningful. If HORT_PULL_DEDUP_LEADER_LOCK_TTL_SECS is set on the server, set it for this scenario too."
fi

# ---------------------------------------------------------------------
# Coalescing counters.
# ---------------------------------------------------------------------
if [ "$METRICS_ARMED" = "1" ]; then
    log ""
    log "--- Coalescing counters"

    LEADER_NPM_DELTA=$(( $(dedup_total 'format="npm"' 'outcome="leader_started"') - LEADER_NPM_BEFORE ))
    LEADER_ANY_DELTA=$(( $(dedup_total 'format="_any"' 'outcome="leader_started"') - LEADER_ANY_BEFORE ))
    FOLLOWER_ANY_DELTA=$(( $(dedup_total 'format="_any"' 'outcome="follower_waited_hit"') - FOLLOWER_ANY_BEFORE ))
    FOLLOWER_CLUSTER_ANY_DELTA=$(( $(dedup_total 'layer="cluster"' 'format="_any"' 'outcome="follower_waited_hit"') - FOLLOWER_CLUSTER_ANY_BEFORE ))
    UPSTREAM_DELTA=$(( $(upstream_success) - UPSTREAM_BEFORE ))

    log "  Δ leader_started{format=npm}            = ${LEADER_NPM_DELTA}            (expect 2 — one packument leader per repository)"
    log "  Δ leader_started{format=_any}           = ${LEADER_ANY_DELTA}            (expect 1 — one tarball leader for both)"
    log "  Δ follower_waited_hit{format=_any}      = ${FOLLOWER_ANY_DELTA}          (expect ≥ 1)"
    log "  Δ follower_waited_hit{_any,layer=cluster} = ${FOLLOWER_CLUSTER_ANY_DELTA} (expect ≥ 1 — the Layer-B fast path)"
    log "  Δ upstream_fetch{result=success} (all formats) = ${UPSTREAM_DELTA}       (expect 3 — 2 packuments + 1 tarball)"

    if [ "$FOLLOWER_CLUSTER_ANY_DELTA" -ge 1 ]; then
        pass "the follower path was taken: hort_pull_dedup_total{layer=\"cluster\",format=\"_any\",outcome=\"follower_waited_hit\"} +${FOLLOWER_CLUSTER_ANY_DELTA}"
    else
        fail "hort_pull_dedup_total{layer=\"cluster\",format=\"_any\",outcome=\"follower_waited_hit\"} delta ≥ 1" \
            "got ${FOLLOWER_CLUSTER_ANY_DELTA} — leg 2 did not read the leader's terminal record; coalescing did not happen"
    fi

    if [ "$LEADER_ANY_DELTA" -eq 1 ]; then
        pass "exactly one leader elected for the tarball key (leader_started{format=\"_any\"} +1)"
    else
        fail "hort_pull_dedup_total{format=\"_any\",outcome=\"leader_started\"} delta = 1" \
            "got ${LEADER_ANY_DELTA} — 2 means both legs fetched the tarball upstream (no coalescing)"
    fi

    if [ "$LEADER_NPM_DELTA" -eq 2 ]; then
        pass "one packument leader per repository (leader_started{format=\"npm\"} +2)"
    else
        fail "hort_pull_dedup_total{format=\"npm\",outcome=\"leader_started\"} delta = 2" \
            "got ${LEADER_NPM_DELTA} — the metadata keyspace is per-repository, so each cold leg must elect its own"
    fi

    if [ "$UPSTREAM_DELTA" -eq 3 ]; then
        pass "exactly 3 upstream fetches (2 packuments + 1 tarball) — the tarball was fetched once for both repositories"
    else
        fail "hort_upstream_fetch_total{result=\"success\"} (all formats) delta = 3" \
            "got ${UPSTREAM_DELTA} — 4 means the follower re-fetched the tarball it should have coalesced onto"
    fi
else
    log ""
    log "  note: metric-content assertions unarmed (no read_metrics bearer) — the"
    log "        structural assertions below pin the same property without a scrape"
fi

# ---------------------------------------------------------------------
# The follower's row: it exists, it is structurally complete, and it never
# went upstream. These hold in every lane, armed metrics or not.
# ---------------------------------------------------------------------
log ""
log "--- Follower row: existence, membership edges, quarantine anchor"

# Synchronous ingest — the row exists by the time the GET returned — but
# poll briefly as defence-in-depth against projection-visibility lag.
find_artifact_id() {
    local repo_id="$1" label="$2" id=""
    bounded_poll "artifact row (${label})" 15 \
        "[ -n \"\$(psql_one \"SELECT id FROM artifacts WHERE repository_id = '${repo_id}' AND path = '${ARTIFACT_PATH}';\")\" ]" \
        1 || true
    id="$(psql_one "SELECT id FROM artifacts WHERE repository_id = '${repo_id}' AND path = '${ARTIFACT_PATH}';")"
    # A captured id must be UUID-shaped or a downstream `[ -n ]` / WHERE
    # clause could be satisfied by garbage.
    if [[ ! "$id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        id=""
    fi
    printf '%s' "$id"
}

LEADER_ARTIFACT_ID="$(find_artifact_id "$LEADER_REPO_ID" "leader")"
FOLLOWER_ARTIFACT_ID="$(find_artifact_id "$FOLLOWER_REPO_ID" "follower")"

if [ -n "$LEADER_ARTIFACT_ID" ]; then
    pass "leader repository has its own row for ${ARTIFACT_PATH} (id=${LEADER_ARTIFACT_ID})"
else
    fail "leader repository row for ${ARTIFACT_PATH}" "no artifacts row in ${LEADER_REPO_KEY}"
    summary
fi

# The pre-fix behaviour of the cross-repository follower leg was to fail
# closed here: the post-coalesce repo-scoped lookup returned None and the
# pull errored instead of registering the follower's own row.
if [ -n "$FOLLOWER_ARTIFACT_ID" ]; then
    pass "follower repository minted its OWN row for ${ARTIFACT_PATH} (id=${FOLLOWER_ARTIFACT_ID})"
else
    fail "follower repository row for ${ARTIFACT_PATH}" \
        "no artifacts row in ${FOLLOWER_REPO_KEY} — the coalesced follower did not register its own per-repo row"
    summary
fi

LEADER_HASH="$(psql_one "SELECT checksum_sha256 FROM artifacts WHERE id = '${LEADER_ARTIFACT_ID}';")"
FOLLOWER_HASH="$(psql_one "SELECT checksum_sha256 FROM artifacts WHERE id = '${FOLLOWER_ARTIFACT_ID}';")"
if [ -n "$LEADER_HASH" ] && [ "$LEADER_HASH" = "$FOLLOWER_HASH" ]; then
    pass "both rows address the same CAS content (sha256=${LEADER_HASH})"
else
    fail "both rows address the same CAS content" \
        "leader='${LEADER_HASH:-<none>}' follower='${FOLLOWER_HASH:-<none>}'"
    summary
fi

# Membership edges. `register_existing_cas_blob` must write the follower
# row's OWN `primary_content` edge in its OWN repository: that edge is what
# keeps the hash alive under GC and what the referenced-tree lookups read.
follower_edge="$(psql_one "SELECT count(*) FROM content_references \
    WHERE repository_id = '${FOLLOWER_REPO_ID}' AND source_artifact_id = '${FOLLOWER_ARTIFACT_ID}' \
      AND target_content_hash = '${FOLLOWER_HASH}' AND kind = 'primary_content';")"
if [ "$follower_edge" = "1" ]; then
    pass "content_references: follower row -> its own content (kind=primary_content) edge present"
else
    fail "content_references primary_content edge on the follower's row" \
        "count=${follower_edge:-0} in repository ${FOLLOWER_REPO_KEY} — the coalesced follower's row was minted without its membership edge"
fi

leader_edge="$(psql_one "SELECT count(*) FROM content_references \
    WHERE repository_id = '${LEADER_REPO_ID}' AND source_artifact_id = '${LEADER_ARTIFACT_ID}' \
      AND target_content_hash = '${LEADER_HASH}' AND kind = 'primary_content';")"
if [ "$leader_edge" = "1" ]; then
    pass "content_references: leader row -> its own content (kind=primary_content) edge present"
else
    fail "content_references primary_content edge on the leader's row" "count=${leader_edge:-0}"
fi

# Quarantine anchor: ONE artifact, ONE content-level anchor, whichever leg
# minted the row.
#
# Both repositories carry the same 24h quarantining policy and neither row
# is a referenced-tree descendant, so neither takes the zero-window
# carve-out. What anchors each window is the earliest defensible evidence of
# the CONTENT's age — `MIN(created_at)` over every `artifacts` row sharing
# the hash, unscoped by repository and unfiltered by `is_deleted`, which is
# what `ArtifactRepository::first_seen_for_checksum` reads. That evidence
# belongs to the bytes, not to the row, so both rows must land on the same
# instant: the leader derives it at its own mint instant (the preflight
# established these bytes are new to this instance), and the follower —
# minting seconds later over already-resident CAS content — reads that same
# instant back and anchors there, NOT at its own `created_at`.
#
# The two assertions below reject three distinct defects:
#   - no gate at all on the follower's row: its anchor is NULL, which
#     neither a `=` comparison nor the minimum-match count can satisfy;
#   - a back-dated anchor from a different gate: it is not the minimum;
#   - a follower that re-anchored at its own `now`: leg 2's `created_at` is
#     strictly later than leg 1's, so such a row fails both — the form this
#     replaced (each row against its own `created_at`) could not see it at
#     all, because that is precisely what a re-anchoring follower produces.
# The leader's `quarantine_window_start = created_at` is kept alongside them
# as the coldness assertion: it pins the content-level minimum to an instant
# minted inside this run, which is what gives the other two their meaning.
leader_status="$(psql_one "SELECT coalesce(quarantine_status, '<null>') FROM artifacts WHERE id = '${LEADER_ARTIFACT_ID}';")"
follower_status="$(psql_one "SELECT coalesce(quarantine_status, '<null>') FROM artifacts WHERE id = '${FOLLOWER_ARTIFACT_ID}';")"
if [ "$leader_status" = "quarantined" ] && [ "$follower_status" = "$leader_status" ]; then
    pass "quarantine_status parity: both rows are '${follower_status}'"
else
    fail "quarantine_status parity (both 'quarantined')" \
        "leader='${leader_status}' follower='${follower_status}'"
fi

# Rendered forms, for the diagnostics only — every verdict below is decided
# in SQL, on timestamps, so no assertion rests on how a timestamp prints.
# `AT TIME ZONE 'UTC'` pins the rendering to the value rather than to the
# session's TimeZone, and the space is swapped for `T` because `psql_one`
# strips whitespace from what it returns.
anchor_text="coalesce(replace((quarantine_window_start AT TIME ZONE 'UTC')::text, ' ', 'T'), '<null>')"
leader_anchor="$(psql_one "SELECT ${anchor_text} FROM artifacts WHERE id = '${LEADER_ARTIFACT_ID}';")"
follower_anchor="$(psql_one "SELECT ${anchor_text} FROM artifacts WHERE id = '${FOLLOWER_ARTIFACT_ID}';")"
content_min="$(psql_one "SELECT coalesce(replace((min(created_at) AT TIME ZONE 'UTC')::text, ' ', 'T'), '<null>') \
    FROM artifacts WHERE checksum_sha256 = '${LEADER_HASH}';")"
content_rows="$(psql_one "SELECT count(*) FROM artifacts WHERE checksum_sha256 = '${LEADER_HASH}';")"
log "  leader anchor            = ${leader_anchor}"
log "  follower anchor          = ${follower_anchor}"
log "  content-level MIN(created_at) = ${content_min} (over ${content_rows:-?} row(s) sharing sha256=${LEADER_HASH})"

leader_full_window="$(psql_one "SELECT (quarantine_window_start = created_at) FROM artifacts WHERE id = '${LEADER_ARTIFACT_ID}';")"
if [ "$leader_full_window" = "t" ]; then
    pass "leader row: quarantine_window_start == created_at — leg 1 is the first observation of these bytes, so the content-level minimum is its own mint instant (full 24h window)"
else
    fail "leader quarantine_window_start == created_at" \
        "got '${leader_full_window:-<null>}' (expected t) — anchor=${leader_anchor}, content minimum=${content_min} over ${content_rows:-?} row(s). A minimum older than leg 1 means these bytes were already resident somewhere in this instance despite the preflight, so the checks below are not measuring this run; an anchor older than the minimum means some other source moved leg 1's window earlier"
fi

# 1. Both rows carry the SAME anchor, and it is not NULL. `x = y` is NULL
#    when either side is NULL, hence the explicit `IS NOT NULL`: an ungated
#    follower must read as `f`, never as an empty string that a later
#    comparison could be sloppy about.
anchor_parity="$(psql_one "SELECT (l.quarantine_window_start = f.quarantine_window_start \
      AND l.quarantine_window_start IS NOT NULL) \
    FROM artifacts l, artifacts f \
    WHERE l.id = '${LEADER_ARTIFACT_ID}' AND f.id = '${FOLLOWER_ARTIFACT_ID}';")"
if [ "$anchor_parity" = "t" ]; then
    pass "anchor parity: both rows carry the same non-NULL quarantine_window_start (${leader_anchor})"
else
    fail "both rows carry the same non-NULL quarantine_window_start" \
        "got '${anchor_parity:-<null>}' (expected t) — leader='${leader_anchor}' follower='${follower_anchor}'; one artifact's bytes carry one anchor whichever leg minted the row, so a divergence here is a follower gated differently from the leader"
fi

# 2. That shared anchor IS the content-level minimum. Counting matching rows
#    rather than aggregating booleans keeps this NULL-safe in the direction
#    that matters: a NULL anchor simply fails to match, where `bool_and`
#    would have discarded it and passed on the other row alone.
anchors_at_content_min="$(psql_one "SELECT count(*) FROM artifacts \
    WHERE id IN ('${LEADER_ARTIFACT_ID}', '${FOLLOWER_ARTIFACT_ID}') \
      AND quarantine_window_start = ( \
          SELECT min(created_at) FROM artifacts WHERE checksum_sha256 = '${LEADER_HASH}');")"
if [ "$anchors_at_content_min" = "2" ]; then
    pass "both anchors sit at the content-level minimum ${content_min} — MIN(created_at) over the ${content_rows} row(s) sharing the hash, the same evidence first_seen_for_checksum reads"
else
    fail "both rows anchored at MIN(created_at) over the rows sharing the hash" \
        "${anchors_at_content_min:-0}/2 rows match: leader='${leader_anchor}' follower='${follower_anchor}' minimum='${content_min}' over ${content_rows:-?} row(s) — a follower anchored at its own created_at (leg 2's, strictly later than leg 1's) lands here, as does a back-dated anchor from a different gate"
fi

# The scrape-free proof of "exactly one upstream fetch for that key".
# `ChecksumVerified` fires only where bytes were actually fetched and
# re-hashed against the upstream-declared digest; the coalesced follower
# re-uses CAS content and emits `ArtifactIngested` alone.
log ""
log "--- Event streams: the follower never fetched or re-verified upstream bytes"

leader_verified="$(psql_one "SELECT count(*) FROM events WHERE stream_id = 'artifact-${LEADER_ARTIFACT_ID}' AND event_type = 'ChecksumVerified';")"
follower_verified="$(psql_one "SELECT count(*) FROM events WHERE stream_id = 'artifact-${FOLLOWER_ARTIFACT_ID}' AND event_type = 'ChecksumVerified';")"
follower_ingested="$(psql_one "SELECT count(*) FROM events WHERE stream_id = 'artifact-${FOLLOWER_ARTIFACT_ID}' AND event_type = 'ArtifactIngested';")"

# `ingest_verified`'s audit invariant is exactly one ChecksumVerified per
# artifact stream, appended in the same batch as ArtifactIngested.
if [ "${leader_verified:-0}" -eq 1 ]; then
    pass "leader row carries exactly one ChecksumVerified (it is the one that fetched and verified the tarball)"
else
    fail "leader row carries exactly one ChecksumVerified" "count=${leader_verified:-0} on stream artifact-${LEADER_ARTIFACT_ID}"
fi

if [ "${follower_verified:-0}" -eq 0 ]; then
    pass "follower row carries NO ChecksumVerified — its bytes came from the coalesce, not from upstream"
else
    fail "follower row carries no ChecksumVerified" \
        "count=${follower_verified} on stream artifact-${FOLLOWER_ARTIFACT_ID} — the follower fetched and verified the tarball itself, so the coalesce did not happen"
fi

if [ "${follower_ingested:-0}" -ge 1 ]; then
    pass "follower row carries ArtifactIngested (the registration is event-sourced, not a silent UPDATE)"
else
    fail "follower row carries ArtifactIngested" "count=${follower_ingested:-0} on stream artifact-${FOLLOWER_ARTIFACT_ID}"
fi

# ---------------------------------------------------------------------
# Best-effort Layer-A probe — EXPLICITLY NON-GATING.
#
# Layer A is the per-replica in-process broadcast join, and observing it
# needs real client concurrency plus a race the leader does not win
# outright. Neither is guaranteed on any given runner, so this section
# only ever logs: no `pass`, no `fail`, and every command tolerates
# failure. It runs LAST so it cannot perturb the measured window above.
# Curl (unlike npm, which serialises its installs) does produce genuine
# parallelism, so the counters below are informative when they move.
# ---------------------------------------------------------------------
log ""
log "--- Layer-A concurrency probe (best-effort, never fails the suite)"

if [ "$METRICS_ARMED" = "1" ]; then
    PROBE_INPROC_BEFORE=$(dedup_total 'layer="in_process"' 'outcome="follower_waited_hit"')
    PROBE_CLUSTER_BEFORE=$(dedup_total 'layer="cluster"' 'outcome="follower_waited_hit"')
fi

PROBE_URL="${HORT_URL%/}/npm/${LEADER_REPO_KEY}/${PROBE_PKG}/-/${PROBE_PKG}-${PROBE_VERSION}.tgz"
log "  firing ${PROBE_CONCURRENCY} concurrent GETs of ${PROBE_URL}"
PROBE_PIDS=()
for _ in $(seq 1 "$PROBE_CONCURRENCY"); do
    curl -sS -o /dev/null --max-time 120 "$PROBE_URL" >/dev/null 2>&1 &
    PROBE_PIDS+=($!)
done
for pid in "${PROBE_PIDS[@]}"; do wait "$pid" || true; done

if [ "$METRICS_ARMED" = "1" ]; then
    PROBE_INPROC_DELTA=$(( $(dedup_total 'layer="in_process"' 'outcome="follower_waited_hit"') - PROBE_INPROC_BEFORE ))
    PROBE_CLUSTER_DELTA=$(( $(dedup_total 'layer="cluster"' 'outcome="follower_waited_hit"') - PROBE_CLUSTER_BEFORE ))
    log "  Δ follower_waited_hit{layer=in_process} = ${PROBE_INPROC_DELTA} (Layer-A joins)"
    log "  Δ follower_waited_hit{layer=cluster}    = ${PROBE_CLUSTER_DELTA} (arrivals after the leader finished)"
    log "  (informational only — a leader that completes before its peers arrive is a legitimate outcome)"
else
    log "  (metrics unarmed — probe drove traffic only)"
fi

# ---------------------------------------------------------------------
# Failure-mode dump: show the actual shape of /metrics, not just deltas.
# ---------------------------------------------------------------------
if [ "$_FAIL" -gt 0 ] && [ "$METRICS_ARMED" = "1" ]; then
    log ""
    log "--- /metrics dump (hort_pull_dedup* and hort_upstream_fetch*) ---"
    curl -sf "${METRICS_AUTH_HEADER[@]}" "$METRICS_URL" 2>/dev/null \
        | awk '/^hort_pull_dedup/ || /^hort_upstream_fetch/' \
        | sort \
        || log "  (curl failed — metrics endpoint unreachable)"
    log "------------------------------------------------------------"
fi

summary
