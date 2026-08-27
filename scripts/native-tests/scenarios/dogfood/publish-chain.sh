#!/usr/bin/env bash
# requires: db compose worker
# Full first-party publish chain against a policy-gated hosted cargo registry.
#
# The routine cargo client scenario publishes ONE standalone crate into a
# repository whose observation window is 0s. Every interesting failure mode of
# a real release is invisible to that shape, because all of them are emergent
# properties of publishing a whole workspace, in dependency order, against a
# registry that actually holds what it just received:
#
#   * a crate resolves the sibling it uploaded moments ago through the
#     registry's own index — cargo does this even under `--no-verify` — and
#     that index is `released_only`, so the sibling is inside its observation
#     window and invisible to an ordinary reader;
#   * the sibling's index entry has to carry real dependencies and features,
#     because cargo validates a feature edge against the INDEX entry rather
#     than against the dependency's own manifest;
#   * an upload is irreversible, so a chain that dies partway leaves real
#     crates behind that cargo will refuse to republish — the re-run has to
#     recognise them and continue, without ever mistaking a genuine failure
#     for one of them.
#
# This scenario drives all three against the real stack.
#
# ## What is real here, and what is a fixture
#
# The CHAIN is real: `scripts/ci/publish-crates.sh`,
# `scripts/ci/publishable-crates-in-order.sh` and
# `scripts/ci/crate-version-in-index.sh` — the exact scripts a tagged release
# runs — are copied into the generated workspace and executed unmodified. A
# scenario that paraphrased them would pass while the real chain was broken,
# which is the only failure mode worth guarding against here. The runner
# bind-mounts them at $HORT_CI_SCRIPTS.
#
# The WORKSPACE is a fixture: five generated crates with no third-party
# dependencies, shaped like hort's own published set — a base crate, two
# crates that depend on it (one of them naming a feature of it), a crate that
# depends on both, and a `publish = false` member that must stay out of the
# published set. Generating it keeps the scenario egress-free and lets it
# assert an exact publish order; what it cannot do is say anything about
# hort's real manifests, which is the job of the workspace-manifest guards
# that run under `cargo test`.
#
# The REGISTRY is real and gating: `hort-crates-chain-e2e` carries a genuine
# observation window (see the paired ScanPolicy), so every crate after the
# first resolves a held sibling. Collapsing that window to 0s would make this
# scenario pass for the wrong reason.
#
# ## The three identities
#
#   publisher (dev-user)  — write-GRANTED on the repository. Held index
#                           entries are served on granted write authority, so
#                           this is the only identity the chain can run as.
#   reader   (reader-user)— read-granted, not write-granted. The control: it
#                           must keep seeing the ordinary released-only view
#                           the entire time the publisher is resolving held
#                           siblings.
#   anonymous             — no credentials at all.
#
# ## Assertions
#
#   (1) the publish order derived from the manifests is exactly the
#       dependency order, and excludes the `publish = false` member;
#   (2) the whole chain publishes green against the window — the crates
#       resolve their held siblings, feature edges included;
#   (3) the hold is genuinely in force: the same index answers differently to
#       the publisher and to the read-only identity, and the held BYTES are
#       refused to both (the exemption is metadata-only);
#   (4) a chain interrupted mid-way leaves exactly the crates it uploaded and
#       no more, and re-running it skips those by index lookup and finishes
#       the tail — while they are still held, which is the case a read-only
#       index lookup would get wrong;
#   (5) once the window elapses the crates release and serve to the read-only
#       identity.

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

if [ "${HORT_TEST_DEBUG:-0}" = "1" ]; then
    set -x
fi

REPO_KEY="${CHAIN_REPO_KEY:-hort-crates-chain-e2e}"
REGISTRY_URL="${HORT_URL%/}/cargo/${REPO_KEY}"
CI_SCRIPTS="${HORT_CI_SCRIPTS:-/work-ci}"

# Per-run versions. The compose stack is cycled between runs, but a nonce
# costs nothing and keeps a `--keep` debugging session from colliding with
# itself. The two chains must differ: an upload is immutable, so the resume
# leg cannot reuse the first chain's version.
NONCE="$(date +%s)"
V_CHAIN="0.1.${NONCE}"
V_RESUME="0.2.${NONCE}"

BASE_CRATE="hort-chain-base"
MID_CRATE="hort-chain-mid"
SIDE_CRATE="hort-chain-side"
TOP_CRATE="hort-chain-top"
TOOL_CRATE="hort-chain-tool"

log "==> Full first-party publish chain"
log "hort           : ${HORT_URL}"
log "registry       : ${REGISTRY_URL}"
log "ci scripts     : ${CI_SCRIPTS}"
log "chain version  : ${V_CHAIN}"
log "resume version : ${V_RESUME}"

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
command -v cargo >/dev/null 2>&1 || skip "cargo not found in PATH"
command -v curl  >/dev/null 2>&1 || skip "curl not found in PATH"
command -v jq    >/dev/null 2>&1 || skip "jq not found in PATH"

REAL_CARGO="$(command -v cargo)"

for _s in publish-crates.sh publishable-crates-in-order.sh \
          crate-version-in-index.sh lib-cargo-sparse-index.sh; do
    [ -f "${CI_SCRIPTS}/${_s}" ] \
        || skip "release-time chain script ${_s} not mounted at ${CI_SCRIPTS} — is HORT_CI_SCRIPTS set by the runner?"
done

DEV_TOKEN="$(fetch_token dev-user dev)"
[ -n "$DEV_TOKEN" ] || skip "could not fetch dev-user token from Keycloak — stack not ready"
READER_TOKEN="$(fetch_token reader-user reader)"
[ -n "$READER_TOKEN" ] || skip "could not fetch reader-user token from Keycloak"
log "[auth] publisher (dev-user) + read-only control (reader-user) tokens fetched"

# The chain publishes as dev-user, whose write authority on this repository
# comes from a real PermissionGrant. That matters: held index entries are
# served on GRANTED write authority for the repository, so publishing as an
# admin-claim principal would take a different path through the authorization
# decision than a release identity does.
CARGO_TOKEN_ENV="CARGO_REGISTRIES_$(printf '%s' "$REPO_KEY" | tr 'a-z-' 'A-Z_')_TOKEN"
export "${CARGO_TOKEN_ENV}=Bearer ${DEV_TOKEN}"
# Read by `crate-version-in-index.sh`: the skip check has to observe the index
# as the publishing identity, because that is the view cargo is about to get.
export HORT_TOKEN="$DEV_TOKEN"
# The index-serve path is synchronous; this sleep only covers propagation, and
# the release-time default of 10s per crate would add a minute to the run for
# nothing. It does NOT cover the observation window — that is the point.
export HORT_PUBLISH_PROPAGATION_SLEEP=2

# `config.json` is the anonymous bootstrap endpoint every cargo client reads
# first, and this scenario's whole premise rests on what it says: cargo
# attaches its registry token to index requests only when this document
# advertises `auth-required: true`. A repository that answered `false` would
# have cargo resolving the index anonymously, where no rule keyed on the
# caller's granted authority can reach it — the chain would fail for a reason
# that has nothing to do with the code under test, so assert the premise
# rather than discovering it as a confusing publish error.
CONFIG_JSON="$(curl -sS --max-time 8 "${REGISTRY_URL}/config.json" 2>/dev/null || echo '')"
AUTH_REQUIRED="$(printf '%s' "$CONFIG_JSON" | jq -r '."auth-required" // "absent"' 2>/dev/null || echo 'absent')"
case "$AUTH_REQUIRED" in
    true)
        pass "(0) ${REPO_KEY} advertises auth-required: true — cargo will attach the publisher's token to index reads"
        ;;
    false)
        fail "(0) the chain registry must advertise auth-required: true" \
            "config.json says false, so cargo reads the index anonymously and the write-authorized hold-read can never engage; is hort-crates-chain-e2e still isPublic: false?"
        summary
        ;;
    *)
        fail "(0) preflight: ${REPO_KEY} must exist on this stack" \
            "GET ${REGISTRY_URL}/config.json returned no usable document (${CONFIG_JSON:-<empty>}); deploy/compose/example-config/repositories/hort-crates-chain-e2e.yaml not applied?"
        summary
        ;;
esac

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# ---------------------------------------------------------------------------
# Workspace generation.
#
# The dependency shape, and why each edge is there:
#
#   base ──┬──▶ mid ──┐
#          │          ├──▶ top          tool (publish = false) ──▶ top
#          └──▶ side ─┘
#
#   * `mid` names `base`'s `extra` feature. Cargo validates that edge against
#     `base`'s INDEX entry, so an entry that lost its feature map fails `mid`'s
#     publish even though `base` uploaded fine — a mid-chain failure whose
#     cause is two crates back.
#   * `top` depends on both `mid` and `side`, so the order is a real
#     topological sort rather than a line.
#   * `tool` is unpublished and depends on a published crate: legal, and the
#     direction that must NOT be reported as a violation. The reverse edge
#     (published depending on unpublished) is what the order script rejects.
#
# Every intra-workspace dependency carries `registry = "<repo key>"` as well
# as a path. Without the registry key the published manifest's requirement is
# a crates.io requirement, which resolves somewhere the publishing identity
# cannot write and where the held-metadata exemption correctly does not apply.
# `.cargo/config.toml` declares the matching index because cargo refuses to
# PARSE a manifest naming a registry it has no index for.
# ---------------------------------------------------------------------------
emit_member() {  # <workspace> <dir> <crate-name> <description> <manifest-tail>
    local ws="$1" dir="$2" name="$3" description="$4" tail="$5"
    mkdir -p "${ws}/${dir}/src"
    {
        printf '[package]\n'
        printf 'name = "%s"\n' "$name"
        printf 'version.workspace = true\n'
        printf 'edition.workspace = true\n'
        printf 'license.workspace = true\n'
        printf 'description = "%s"\n' "$description"
        printf '%s\n' "$tail"
    } > "${ws}/${dir}/Cargo.toml"
    printf 'pub fn %s() -> u32 { %s }\n' "$dir" "${#dir}" > "${ws}/${dir}/src/lib.rs"
}

emit_workspace() {  # <dir> <version>
    local ws="$1" version="$2"

    mkdir -p "${ws}/.cargo"

    {
        printf '[workspace]\n'
        printf 'members = ["base", "mid", "side", "top", "tool"]\n'
        printf 'resolver = "2"\n\n'
        printf '[workspace.package]\n'
        printf 'version = "%s"\n' "$version"
        printf 'edition = "2021"\n'
        printf 'license = "MIT"\n\n'
        printf '[workspace.dependencies]\n'
        printf '%s = { path = "base", version = "=%s", registry = "%s" }\n' "$BASE_CRATE" "$version" "$REPO_KEY"
        printf '%s = { path = "mid", version = "=%s", registry = "%s" }\n'  "$MID_CRATE"  "$version" "$REPO_KEY"
        printf '%s = { path = "side", version = "=%s", registry = "%s" }\n' "$SIDE_CRATE" "$version" "$REPO_KEY"
        printf '%s = { path = "top", version = "=%s", registry = "%s" }\n'  "$TOP_CRATE"  "$version" "$REPO_KEY"
    } > "${ws}/Cargo.toml"

    cat > "${ws}/.cargo/config.toml" << EOF
[registries.${REPO_KEY}]
index = "sparse+${REGISTRY_URL}/"

# An auth-required registry needs a declared credential provider, or cargo
# never attaches a token — it resolves the index and publishes ANONYMOUSLY,
# and a private repo answers 404 (anti-enumeration), failing every
# authenticated leg. cargo:token reads CARGO_REGISTRIES_<KEY>_TOKEN (set to
# "Bearer <jwt>" above) and sends it verbatim as the Authorization header,
# which is exactly what hort's bearer auth expects.
[registry]
global-credential-providers = ["cargo:token"]
EOF

    emit_member "$ws" base "$BASE_CRATE" \
        "Publish-chain E2E fixture: the root of the dependency chain" \
        "publish = [\"${REPO_KEY}\"]

[features]
# Named by ${MID_CRATE}. A published index entry that lost its feature map
# fails that crate's resolve, so this edge is load-bearing, not decoration.
extra = []"

    emit_member "$ws" mid "$MID_CRATE" \
        "Publish-chain E2E fixture: depends on the base crate and names its feature" \
        "publish = [\"${REPO_KEY}\"]

[dependencies]
${BASE_CRATE} = { workspace = true, features = [\"extra\"] }"

    emit_member "$ws" side "$SIDE_CRATE" \
        "Publish-chain E2E fixture: the second dependent of the base crate" \
        "publish = [\"${REPO_KEY}\"]

[dependencies]
${BASE_CRATE} = { workspace = true }"

    emit_member "$ws" top "$TOP_CRATE" \
        "Publish-chain E2E fixture: the diamond join, published last" \
        "publish = [\"${REPO_KEY}\"]

[dependencies]
${MID_CRATE} = { workspace = true }
${SIDE_CRATE} = { workspace = true }"

    emit_member "$ws" tool "$TOOL_CRATE" \
        "Publish-chain E2E fixture: an unpublished member of the workspace" \
        "publish = false

[dependencies]
${TOP_CRATE} = { workspace = true }"

    # The release-time chain, copied rather than referenced: `publish-crates.sh`
    # locates its siblings and the workspace root relative to its own path, so
    # it has to sit at <workspace>/scripts/ci exactly as it does in the repo.
    mkdir -p "${ws}/scripts/ci"
    cp -r "${CI_SCRIPTS}/." "${ws}/scripts/ci/"
    chmod +x "${ws}"/scripts/ci/*.sh
}

# index_has <crate> <version> [bearer] — the REAL release-time index check.
# Exit status is the verdict: 0 present, 1 absent. The bearer defaults to the
# publisher's; passing the read-only identity's is how the two halves of the
# held-visibility rule are compared through one implementation.
index_has() {
    local name="$1" version="$2" token="${3:-$DEV_TOKEN}"
    HORT_TOKEN="$token" "${CI_SCRIPTS}/crate-version-in-index.sh" \
        "$HORT_URL" "$REPO_KEY" "$name" "$version" >/dev/null 2>&1
}

# download_code <crate> <version> [bearer] — HTTP status of the crate-file
# endpoint, without following redirects (a redirect to CAS is itself a success
# signal and must not be flattened into the redirect target's code).
download_code() {
    local name="$1" version="$2" token="${3:-}"
    local -a auth=()
    if [ -n "$token" ]; then auth=(-H "Authorization: Bearer ${token}"); fi
    curl -sS -o /dev/null -w '%{http_code}' --max-time 30 \
        "${auth[@]+"${auth[@]}"}" \
        "${REGISTRY_URL}/api/v1/crates/${name}/${version}/download" 2>/dev/null || echo "000"
}

# ---------------------------------------------------------------------------
# (1) The publish order comes from the manifests.
# ---------------------------------------------------------------------------
log ""
log "--- (1) derived publish order: dependency order, published members only"

CHAIN_WS="${WORK_DIR}/chain"
emit_workspace "$CHAIN_WS" "$V_CHAIN"

cd "$CHAIN_WS" || { fail "(1) cd into the generated workspace" "$CHAIN_WS"; summary; }

ORDER_OUT="$(mktemp)"
if scripts/ci/publishable-crates-in-order.sh > "$ORDER_OUT" 2>/dev/null; then
    ACTUAL_ORDER="$(awk -F'\t' '{ printf "%s ", $2 }' "$ORDER_OUT")"
    EXPECTED_ORDER="${BASE_CRATE} ${MID_CRATE} ${SIDE_CRATE} ${TOP_CRATE} "
    if [ "$ACTUAL_ORDER" = "$EXPECTED_ORDER" ]; then
        pass "(1) publish order is '${ACTUAL_ORDER% }' — every crate after its dependencies"
    else
        fail "(1) derived publish order" \
            "expected '${EXPECTED_ORDER}' got '${ACTUAL_ORDER}'"
    fi

    if grep -q "$TOOL_CRATE" "$ORDER_OUT"; then
        fail "(1) the publish = false member must be excluded from the set" \
            "${TOOL_CRATE} appears in the derived order"
    else
        pass "(1) ${TOOL_CRATE} (publish = false) is excluded from the published set"
    fi
else
    fail "(1) derive the publish order from the workspace manifests" \
        "publishable-crates-in-order.sh exited non-zero: $(tail -5 "$ORDER_OUT" 2>/dev/null)"
fi
rm -f "$ORDER_OUT"

# ---------------------------------------------------------------------------
# (2) The whole chain publishes against a live observation window.
#
# This is the assertion the routine single-crate scenario cannot make. Each
# crate after the first resolves siblings that are still held, through the
# repository's own `released_only` index, and the feature edge is validated
# against the served index entry rather than the local manifest.
# ---------------------------------------------------------------------------
log ""
log "--- (2) publish the full chain in dependency order (siblings held, real window)"

CHAIN_LOG="$(mktemp)"
CHAIN_RC=0
scripts/ci/publish-crates.sh "$HORT_URL" "$REPO_KEY" > "$CHAIN_LOG" 2>&1 || CHAIN_RC=$?

if [ "$CHAIN_RC" = "0" ]; then
    pass "(2) publish-crates.sh completed the four-crate chain"
else
    fail "(2) the full chain must publish against a held index" \
        "publish-crates.sh exited ${CHAIN_RC}; last lines: $(tail -12 "$CHAIN_LOG")"
fi

if grep -q '4 uploaded, 0 already present' "$CHAIN_LOG"; then
    pass "(2) all four crates uploaded, none skipped"
else
    fail "(2) the chain must upload all four crates on a fresh registry" \
        "summary line was: $(grep 'Publish complete' "$CHAIN_LOG" || echo '<none>')"
fi
rm -f "$CHAIN_LOG"

CHAIN_PRESENT=0
for _c in "$BASE_CRATE" "$MID_CRATE" "$SIDE_CRATE" "$TOP_CRATE"; do
    if index_has "$_c" "$V_CHAIN"; then
        CHAIN_PRESENT=$(( CHAIN_PRESENT + 1 ))
    else
        fail "(2) ${_c} ${V_CHAIN} must be in the ${REPO_KEY} index after the chain" \
            "the publishing identity's index read does not list it"
    fi
done
if [ "$CHAIN_PRESENT" = "4" ]; then
    pass "(2) all four crates are listed in the index to the publishing identity"
fi

# ---------------------------------------------------------------------------
# (3) The window is real, and the exemption is metadata-only.
#
# Three observations of the SAME crate at the SAME instant:
#   - the publisher resolves it (asserted above);
#   - the read-only identity does not — a `released_only` index hides a held
#     version, which is exactly why the chain used to fail here;
#   - neither of them can download the bytes.
# If the window had been waived, the second observation would match the first
# and this section would silently assert nothing — hence the recorded-state
# check that opens it.
# ---------------------------------------------------------------------------
log ""
log "--- (3) held-visibility: index yes to the publisher, no to a read-only caller; bytes to neither"

HELD_COUNT="$(psql_one "SELECT count(*) FROM artifacts WHERE version = '${V_CHAIN}' AND name LIKE 'hort-chain-%' AND quarantine_status = 'quarantined';")"
if [ "${HELD_COUNT:-0}" = "4" ]; then
    pass "(3) all four crates are recorded quarantined — the window is in force"
else
    fail "(3) the chain must publish into a genuine observation window" \
        "expected 4 quarantined artifacts at ${V_CHAIN}, found ${HELD_COUNT:-0} — a waived window would make (2) prove nothing"
fi

if index_has "$BASE_CRATE" "$V_CHAIN" "$READER_TOKEN"; then
    fail "(3) a read-only caller must NOT resolve a held version" \
        "${BASE_CRATE} ${V_CHAIN} is listed to reader-user while quarantined — held visibility is not keyed on granted write authority"
else
    pass "(3) the read-only identity does not see the held ${BASE_CRATE} ${V_CHAIN}"
fi

PUB_DL_CODE="$(download_code "$BASE_CRATE" "$V_CHAIN" "$DEV_TOKEN")"
if [ "$PUB_DL_CODE" = "503" ]; then
    pass "(3) held crate FILE is 503 to the publisher itself (the exemption is metadata-only)"
else
    fail "(3) held bytes must never leave quarantine, publisher included" \
        "download as the publishing identity returned HTTP ${PUB_DL_CODE}, expected 503"
fi

READER_DL_CODE="$(download_code "$BASE_CRATE" "$V_CHAIN" "$READER_TOKEN")"
case "$READER_DL_CODE" in
    503|403|404)
        pass "(3) held crate file is not downloadable by the read-only identity (HTTP ${READER_DL_CODE})"
        ;;
    *)
        fail "(3) a held crate file must not be downloadable by a read-only caller" \
            "got HTTP ${READER_DL_CODE}"
        ;;
esac

ANON_DL_CODE="$(download_code "$BASE_CRATE" "$V_CHAIN")"
case "$ANON_DL_CODE" in
    401|403|404|503)
        pass "(3) held crate file is not anonymously downloadable (HTTP ${ANON_DL_CODE})"
        ;;
    *)
        fail "(3) a held crate file must not be anonymously downloadable" \
            "got HTTP ${ANON_DL_CODE}"
        ;;
esac

# ---------------------------------------------------------------------------
# (4) Interrupted chain, then resume.
#
# An upload cannot be withdrawn, so a chain that dies partway leaves crates
# behind that cargo refuses to republish. The re-run must skip exactly those
# and finish the rest — and it must decide that from an index lookup made
# BEFORE each attempt, never from cargo's exit status afterwards, which
# cannot tell "refused to republish" apart from "the upload failed".
#
# The interruption is injected with a cargo shim that fails one specific
# publish invocation and forwards everything else to the real cargo. Injecting
# it is what makes the leg deterministic; everything the assertions then read
# is real. The crates before the failure point are really uploaded, really in
# the index, and really still held when the re-run reads them — which is the
# case a read-only index lookup would get wrong.
# ---------------------------------------------------------------------------
log ""
log "--- (4) mid-chain failure, then resume without republishing what landed"

RESUME_WS="${WORK_DIR}/resume"
emit_workspace "$RESUME_WS" "$V_RESUME"

mkdir -p "${RESUME_WS}/shim"
cat > "${RESUME_WS}/shim/cargo" << EOF
#!/usr/bin/env bash
# Fault injection for the partial-failure leg: fail the publish of one
# specific crate, forward every other invocation to the real cargo unchanged.
for _a in "\$@"; do
    case "\$_a" in
        */side/Cargo.toml|side/Cargo.toml)
            echo "injected mid-chain publish failure for ${SIDE_CRATE}" >&2
            exit 101
            ;;
    esac
done
exec "${REAL_CARGO}" "\$@"
EOF
chmod +x "${RESUME_WS}/shim/cargo"

cd "$RESUME_WS" || { fail "(4) cd into the resume workspace" "$RESUME_WS"; summary; }

PARTIAL_LOG="$(mktemp)"
PARTIAL_RC=0
PATH="${RESUME_WS}/shim:${PATH}" scripts/ci/publish-crates.sh "$HORT_URL" "$REPO_KEY" \
    > "$PARTIAL_LOG" 2>&1 || PARTIAL_RC=$?

PARTIAL_TAIL="$(tail -12 "$PARTIAL_LOG" 2>/dev/null || true)"
rm -f "$PARTIAL_LOG"
if [ "$PARTIAL_RC" != "0" ]; then
    pass "(4) a failing publish aborts the chain (exit ${PARTIAL_RC}) rather than continuing past it"
else
    fail "(4) a failing publish must abort the chain" \
        "publish-crates.sh exited 0 with a crate that could not be published — a loop that continues past a failure ships a release with crates missing; log tail: ${PARTIAL_TAIL}"
fi

PARTIAL_OK=1
for _c in "$BASE_CRATE" "$MID_CRATE"; do
    if ! index_has "$_c" "$V_RESUME"; then
        fail "(4) ${_c} ${V_RESUME} must be in the index after the interrupted chain" \
            "the crates published before the failure point are what makes the re-run non-trivial"
        PARTIAL_OK=0
    fi
done
for _c in "$SIDE_CRATE" "$TOP_CRATE"; do
    if index_has "$_c" "$V_RESUME"; then
        fail "(4) ${_c} ${V_RESUME} must NOT be in the index after the interrupted chain" \
            "the chain published past its own failure"
        PARTIAL_OK=0
    fi
done
if [ "$PARTIAL_OK" = "1" ]; then
    pass "(4) exactly the crates before the failure point landed (${BASE_CRATE}, ${MID_CRATE})"
fi

# The re-run, with the real cargo. Everything it skips, it skips because it
# observed the version in the index first — and those versions are still
# inside their observation window, so that observation only succeeds for a
# caller with write authority here.
RESUME_LOG="$(mktemp)"
RESUME_RC=0
scripts/ci/publish-crates.sh "$HORT_URL" "$REPO_KEY" > "$RESUME_LOG" 2>&1 || RESUME_RC=$?

if [ "$RESUME_RC" = "0" ]; then
    pass "(4) the re-run completes the chain"
else
    fail "(4) re-running an interrupted chain must succeed" \
        "publish-crates.sh exited ${RESUME_RC}; last lines: $(tail -12 "$RESUME_LOG")"
fi

if grep -q '2 uploaded, 2 already present' "$RESUME_LOG"; then
    pass "(4) the re-run skipped the two already-published crates and uploaded the two missing ones"
else
    fail "(4) the re-run must skip exactly the crates that already landed" \
        "summary line was: $(grep 'Publish complete' "$RESUME_LOG" || echo '<none>')"
fi

RESUME_SKIPS=0
for _c in "$BASE_CRATE" "$MID_CRATE"; do
    if grep -q "${_c} ${V_RESUME} is already published" "$RESUME_LOG"; then
        RESUME_SKIPS=$(( RESUME_SKIPS + 1 ))
    fi
done
if [ "$RESUME_SKIPS" = "2" ]; then
    pass "(4) each skip is logged by crate name and version"
else
    fail "(4) skips must be logged by name and version" \
        "found ${RESUME_SKIPS}/2 skip lines; log tail: $(tail -12 "$RESUME_LOG")"
fi
rm -f "$RESUME_LOG"

RESUME_PRESENT=0
for _c in "$BASE_CRATE" "$MID_CRATE" "$SIDE_CRATE" "$TOP_CRATE"; do
    if index_has "$_c" "$V_RESUME"; then
        RESUME_PRESENT=$(( RESUME_PRESENT + 1 ))
    fi
done
if [ "$RESUME_PRESENT" = "4" ]; then
    pass "(4) all four crates are published at ${V_RESUME} after the resume"
else
    fail "(4) the resumed chain must leave the whole set published" \
        "only ${RESUME_PRESENT}/4 crates present at ${V_RESUME}"
fi

cd "$WORK_DIR" || true

# ---------------------------------------------------------------------------
# (5) The window elapses and the crates release.
#
# Nothing here releases anything by hand: with no scanner configured on this
# repository the release authority is a waived scan, so the quarantine timer
# plus the release sweep are the only things that can move these artifacts.
# If they release, the hold asserted in (3) was a timed hold and not a
# permanent one.
# ---------------------------------------------------------------------------
log ""
log "--- (5) the observation window elapses → the chain releases and serves to an ordinary reader"

RELEASED_PRED="[ \"\$(psql_one \"SELECT count(*) FROM artifacts WHERE version = '${V_CHAIN}' AND name LIKE 'hort-chain-%' AND quarantine_status = 'released';\")\" = '4' ]"
if bounded_poll "chain ${V_CHAIN} released" 240 "$RELEASED_PRED" 5; then
    pass "(5) all four crates released once their window elapsed"

    if index_has "$BASE_CRATE" "$V_CHAIN" "$READER_TOKEN"; then
        pass "(5) the released ${BASE_CRATE} ${V_CHAIN} is now listed to the read-only identity"
    else
        fail "(5) a released version must resolve for a read-granted caller" \
            "${BASE_CRATE} ${V_CHAIN} is still hidden from reader-user's index read after release"
    fi

    REL_DL_CODE="$(download_code "$TOP_CRATE" "$V_CHAIN" "$READER_TOKEN")"
    case "$REL_DL_CODE" in
        200|302|307|308)
            pass "(5) read-only download of the released ${TOP_CRATE} -> HTTP ${REL_DL_CODE}"
            ;;
        *)
            fail "(5) a released crate file must be downloadable by a read-granted caller" \
                "got HTTP ${REL_DL_CODE}"
            ;;
    esac
else
    FINAL_STATES="$(psql_one "SELECT string_agg(DISTINCT quarantine_status::text, ',') FROM artifacts WHERE version = '${V_CHAIN}' AND name LIKE 'hort-chain-%';" || true)"
    fail "(5) the chain must release once its observation window elapses" \
        "still '${FINAL_STATES:-<none>}' after 240s — is the release sweep ticking (the worker profile) on this stack?"
fi

assert_metric_ingest cargo

summary
