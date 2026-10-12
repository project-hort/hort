//! Publish-chain gating guard.
//!
//! Governing decisions: ADR 0030 (structural guards on the sensitive surface
//! — the family this joins), ADR 0048 (the release/pre-release artifact model
//! these two workflows implement), ADR 0051 (the registry.hort.rs chart and
//! base-image mirrors this chain also publishes), ADR 0016 (fail closed; never
//! fall back to a degraded authority).
//!
//! This DB-free, network-free, git-free source scan is the **committed proof**
//! — in the family of `expand_contract_guard`, `no_sensitive_drops`,
//! `capped_stream_reads` and `status_decode_fails_closed` — that the two
//! GitHub publish workflows cannot ship an artifact without the gates that
//! stand in front of them.
//!
//! ## Why a test, and why here
//!
//! `.github/workflows/docker-publish.yml` and
//! `.github/workflows/release.yml` run only on GitHub. Neither the local
//! verification gate nor the compose E2E suite executes them, so the edges
//! that make a publish conditional — a `needs:` entry, a `startsWith(github.ref,
//! 'refs/tags/v')` in an `if:` — were, until this file existed, claims that
//! nothing in the repository re-checked. Removing one is a one-line diff that
//! no test, no linter and no pipeline here would notice — and an unchecked
//! claim is the failure shape this whole guard family exists for: a mechanism
//! correct where it runs, never carried to new surface, because nothing
//! re-checked it.
//!
//! Being a `tests/` target means `cargo test --workspace` runs it with no
//! gate-list entry, which is what CLAUDE.md asks of a new structural guard.
//! It reads a checked-in non-Rust tree outside its own crate exactly the way
//! `expand_contract_guard` reads `migrations/`: resolve the workspace root
//! from `CARGO_MANIFEST_DIR`, then join.
//!
//! ## The three assertions
//!
//! For every job classified as **publishing** (see *Classification* below):
//!
//!   1. Its **effective** `needs:` closure reaches `ci-gate` — the
//!      reusable-workflow call that puts `cargo audit`, `cargo deny` and the
//!      `THIRD-PARTY-LICENSES` sync inside this run's dependency graph, where
//!      `needs:` can hold the publish.
//!   2. In `docker-publish.yml`, that closure also reaches `scan-containers`
//!      — the Trivy CVE gate, which sits between the build and the first
//!      tagged push.
//!   3. Its **own** run condition requires a `refs/tags/v` ref.
//!
//! ### "Effective", not declared
//!
//! A job whose `if:` contains `always()` runs even when a `needs:` entry
//! failed, so that edge gates only if the `if:` *also* tests that entry's
//! result. `release.yml`'s `release` job is the live example: `sbom` and
//! `verify-images-published` are in its `needs:`, `always()` voids both, and
//! the `if:` tests only `needs.build-binaries.result == 'success'` — so the
//! other two are draft-or-publish *inputs*, not gates, and a guard that walked
//! declared `needs:` would have called a tree with a decorative `sbom` edge
//! correctly gated. `effective_needs` therefore keeps, for a job whose `if:`
//! carries a status function, only the declared entries that same `if:`
//! conjunctively tests for success.
//!
//! ### (3) is asserted per job, not over the closure
//!
//! A chain whose *root* is ref-gated makes every mid-chain removal look fine:
//! walk only the closure and three separate "delete the ref condition"
//! mutations pass. Every publishing job in both files states the condition
//! itself today, and that is the property pinned here — `requires_ref` is
//! applied to the job's own `if:`. The closure-inherited form
//! (`requires_ref_effective`) exists too, but only to compute the
//! *ungated set* counter-assertion below, where a job that inherits a skip
//! honestly is gated.
//!
//! ### `requires_ref` credits neither a disjunction nor a negation
//!
//! Turning `startsWith(github.ref, 'refs/tags/v') && X` into
//! `… || X` is a one-character edit that re-opens the whole finding and reads
//! as gated to any grep. So the expression is split into **top-level `&&`
//! conjuncts** (quote- and paren-aware) and a conjunct counts only if it is
//! the ref test itself, unnegated, with no `||` anywhere inside it. A
//! parenthesised conjunct is unwrapped and re-split, so `(A && ref)` still
//! counts.
//!
//! One spelling is recognised: `startsWith(github.ref, 'refs/tags/v')`,
//! modulo whitespace and quote style. An equivalent-but-different test
//! (`github.ref_type == 'tag'`, a regex, a job-level `env` indirection) fails
//! this guard rather than silently passing it. That is deliberate and in the
//! safe direction — the cost is a review conversation, and the alternative is
//! a predicate that credits forms nobody has checked.
//!
//! ## Classification, and why there is no allow-list
//!
//! A job publishes if the text it **executes** carries one of
//! `PUBLISH_MARKERS`. The text is the job's parsed YAML value flattened to
//! scalars — so YAML comments, which the parser drops, cannot classify a job;
//! prose about `cosign sign` stays writable.
//!
//! Reading executed text has to fold in the text of a `uses:` callee, or a job
//! that publishes *through* a reusable workflow reads as inert — that is
//! exactly how `release.yml`'s `build-binaries` publishes (it calls
//! `build-binaries.yml` with `publish: true`, where `cosign sign-blob` lives).
//! Fold it in, and `ci-gate` (`uses: ./ci.yml`) inherits the markers of
//! ci.yml's own verify `build-binaries` job — which calls the same
//! `build-binaries.yml` — so `ci-gate` classifies as a signing job and then
//! fails assertion 1 by being unable to reach itself. That is false in fact:
//! ci.yml's verify build carries `if: ${{ !inputs.gate_for && … }}` and both
//! publish workflows pass a non-empty `gate_for`, so it cannot run on a gate
//! pass at all.
//!
//! CLAUDE.md is explicit that this family carries **no allow-list, by
//! design** (`db_tests_are_serialized`, `status_decode_fails_closed`): a site
//! that genuinely should not be flagged is a review conversation, not a table
//! entry. So the exclusion is **derived**, not listed —
//! `statically_unreachable`: skip a callee job whose `if:` contains
//! `!inputs.<name>` when the caller passes a non-empty literal for `<name>`.
//! Only that one syntactic form is evaluated; anything else counts as
//! reachable. Being wrong therefore demands a ref condition that was not
//! needed, and can never excuse a missing one.
//!
//! ### The CVE-gate exemption is derived from the graph, and pinned
//!
//! `build-images` pushes its layers to ghcr.io (`push=true`) and is therefore
//! classified as publishing — correctly: content lands in a public registry.
//! It cannot reach `scan-containers`, because `scan-containers` scans the
//! digest `build-images` pushed; requiring the reverse edge asks for a cycle,
//! which no workflow graph can express. So assertion 2 exempts exactly the
//! jobs `scan-containers` itself transitively depends on (reflexively). That
//! is a property of the graph, not a name list — and
//! `the_cve_gate_exemption_is_exactly_the_scans_own_prerequisite` pins the
//! resulting set to `{build-images}`, so a future edit that slips a new
//! publisher into the scan's prerequisites has to be argued for in review
//! rather than appearing quietly. The exemption is only from assertion 2:
//! `build-images` still has to reach `ci-gate` and state the ref condition,
//! and the publish it performs is an untagged, content-addressed digest that
//! nothing resolves without knowing it — the first *tagged* push is `merge`,
//! which does carry the CVE gate.
//!
//! ## The counter-assertions
//!
//! The family's convention (`capped_stream_reads`,
//! `status_decode_fails_closed`): prove the corpus is real, so a rename
//! cannot empty the scan and pass.
//!
//!   * Both workflow files exist, parse, and carry a non-trivial job set.
//!   * `ci-gate` exists **by name** in both files and `scan-containers` in
//!     `docker-publish.yml`. Without this, a rename would make assertions 1–3
//!     vacuous rather than red.
//!   * The classification finds **at least** the jobs known to publish today,
//!     named explicitly. A rename that hides a publisher from the markers then
//!     fails *this* assertion instead of silently shrinking the set the other
//!     three check.
//!   * **The ungated set is pinned**, and it is nearly empty: in `release.yml`
//!     **empty** — every job there, the two gates included, carries the ref
//!     condition — and in `docker-publish.yml` exactly `summary`, the reporter,
//!     which keeps `if: always()` deliberately so it can explain a held chain.
//!     A new ungated job has to be argued for in review.
//!   * No job-level `if:` uses the `success()` status function, so the one
//!     judgement call in `voids_needs` (bare `success()` is *precisely* the
//!     default gating, and so is not treated as voiding, unlike `always()` /
//!     `cancelled()` / `failure()`) is not load-bearing on this tree.
//!
//! ## What this guard cannot see — read this before trusting the green
//!
//!   * **The publisher markers are a list.** A genuinely new publishing
//!     mechanism — another action, another CLI, a shell script whose name says
//!     nothing — is invisible until its marker is added here. The
//!     known-publisher counter-assertion catches a *rename* of a job the
//!     markers already find; it cannot catch a *new mechanism*. Adding a way
//!     to publish means adding its marker in the same change.
//!   * **Classification reads the text of a `uses:` callee**, which is why the
//!     gate jobs are excluded by the derived `!inputs.<name>` reachability rule
//!     rather than by a pattern over job names — and why a callee reached
//!     through a non-local `uses:` (a third-party or cross-repo reusable
//!     workflow) contributes no text at all and so can publish invisibly.
//!   * **It reads the files as checked in.** It does not implement GitHub's
//!     expression semantics (it recognises shapes, not truth values), and it
//!     cannot see repository settings — notably whether the `release`
//!     environment actually carries required reviewers and a tag-only
//!     deployment rule. An `environment: release` declaration with no
//!     protection rules behind it gates nothing, and nothing in this tree can
//!     assert otherwise.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// The two workflows this guard is about. `ci.yml`, `e2e.yml` and
/// `build-binaries.yml` are read only as `uses:` callees, for classification.
const PUBLISH_WORKFLOWS: &[&str] = &["docker-publish.yml", "release.yml"];

/// The advisory / attribution gate, by name in both publish workflows.
const CI_GATE: &str = "ci-gate";

/// The container CVE gate, by name in `docker-publish.yml`.
const CVE_GATE: &str = "scan-containers";

/// The one ref condition this guard recognises, whitespace- and
/// quote-normalised.
const REF_TEST: &str = "startswith(github.ref,'refs/tags/v')";

/// Status functions that override Actions' default "skip me if a needed job
/// did not succeed". `success()` is the fourth and is deliberately absent:
/// bare `success()` *is* that default, so treating it as voiding would invent
/// a finding. A counter-assertion keeps the distinction unexercised.
const NEEDS_VOIDING_FUNCTIONS: &[&str] = &["always()", "cancelled()", "failure()"];

/// Substrings of executed text that mean "this job makes something public, or
/// signs/attests something public".
///
/// Each carries its trailing space or argument where the bare verb would
/// also match a *mention* — `cosign sign ` does not fire on
/// `cosign signature` (the `.sig`-tag probe in `verify-published`) and
/// nothing here fires on `cosign verify`. Entries that match nothing on the
/// current tree are future-proofing for mechanisms the workflows may grow;
/// the known-publisher counter-assertion exercises the ones that matter.
const PUBLISH_MARKERS: &[&str] = &[
    "cosign sign ",
    "cosign sign-blob",
    "cosign copy ",
    "cosign attest ",
    "imagetools create",
    "helm push ",
    "oras push ",
    "docker push ",
    "push=true",
    "cargo publish",
    "publish-crates.sh",
    "softprops/action-gh-release",
    "actions/attest-build-provenance",
    "gh release edit",
    "gh release delete",
];

/// Jobs known to publish today. The classification must find **at least**
/// these; a rename that hides one fails here rather than shrinking the set the
/// three assertions check.
const KNOWN_PUBLISHERS: &[(&str, &[&str])] = &[
    (
        "docker-publish.yml",
        &[
            "merge",
            "publish-chart",
            "mirror-to-hort-oci",
            "mirror-to-hort-base",
            "publish-chart-registry-hort-rs",
        ],
    ),
    (
        "release.yml",
        &["build-binaries", "sbom", "release", "hort-publish"],
    ),
];

/// Jobs whose **effective** run condition does not require a release ref.
/// `release.yml`: none. `docker-publish.yml`: the reporter, which keeps
/// `if: always()` so it can explain a chain that was held.
const EXPECTED_UNGATED: &[(&str, &[&str])] =
    &[("docker-publish.yml", &["summary"]), ("release.yml", &[])];

/// Publishing jobs exempt from assertion 2 because the CVE gate's own
/// prerequisites cannot depend on it in turn. Derived from the graph; pinned
/// here so the set cannot grow unremarked.
const EXPECTED_CVE_EXEMPT: &[&str] = &["build-images"];

/// Smallest job count each publish workflow must still carry, so a file
/// truncated to a stub cannot make the scan vacuous.
const MIN_JOBS: usize = 7;

/// How many `uses:` hops classification follows. Actions forbids a cycle
/// among reusable workflows and caps nesting at four, so this bound is the
/// platform's own; it exists so a malformed tree cannot make the guard
/// recurse forever instead of failing.
const MAX_USES_DEPTH: usize = 4;

// ---------------------------------------------------------------------------
// Loading.
// ---------------------------------------------------------------------------

/// Locate the workspace root from `CARGO_MANIFEST_DIR`
/// (`<root>/crates/hort-app`), the idiom `expand_contract_guard` uses to read
/// the workspace-root `migrations/` tree.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("CARGO_MANIFEST_DIR resolves under crates/hort-app")
        .to_path_buf()
}

/// The checked-in workflow tree.
fn workflows_dir() -> PathBuf {
    workspace_root().join(".github").join("workflows")
}

/// A parsed workflow's `jobs:` mapping, keyed by job id.
///
/// `expect` rather than `?`: a publish workflow that is missing or does not
/// parse is the vacuous-green failure mode this guard exists to make
/// impossible, so it must abort loudly.
fn load_jobs(file: &str) -> BTreeMap<String, Value> {
    let path = workflows_dir().join(file);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", path.display()));
    let doc = parse_workflow(&text)
        .unwrap_or_else(|err| panic!("{} must parse as YAML: {err}", path.display()));
    let jobs = doc
        .get("jobs")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{} must declare a `jobs:` mapping", path.display()));
    jobs.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// Deserialise one workflow into an untyped document.
///
/// A GitHub workflow is **not** a gitops envelope, so this does not reach
/// for `hort-config`'s parse: that call path is private to the crate and
/// its options encode decisions about an operator-authored envelope which
/// have no bearing on a file in `.github/workflows/`.
///
/// `emit_comments: false` is the one setting that is not the
/// deserialiser's default, and it is load-bearing here rather than
/// cosmetic: with emission on, a run of more than 32 consecutive comment
/// lines before a collection's first entry breaches a buffered-comment
/// budget and fails the parse. `release.yml` carries exactly that — a
/// 38-line rationale block between `jobs:` and its first job — and the
/// guard's own contract is that `classification reads no YAML comments`,
/// so not capturing comment text is what this guard wants in any case.
///
/// The failure mode this avoids is the one that matters for a fail-closed
/// guard: `load_jobs` panics on a parse error, so a comment block growing
/// past the budget would abort the guard with a message about comments
/// rather than letting it answer the question it exists to answer.
fn parse_workflow(text: &str) -> Result<Value, serde_saphyr::Error> {
    serde_saphyr::from_str_with_options(text, serde_saphyr::options! { emit_comments: false })
}

/// A named job, or a legible abort. A counter-assertion is supposed to fail
/// with the reason, not with `no entry found for key`.
fn job_named<'a>(jobs: &'a BTreeMap<String, Value>, file: &str, name: &str) -> &'a Value {
    jobs.get(name).unwrap_or_else(|| {
        panic!(
            "{file} must still declare a `{name}` job — this guard reasons \
             about it by name, and a rename has to fail here rather than quietly removing it from \
             the set the three assertions check"
        )
    })
}

// ---------------------------------------------------------------------------
// Expression shapes.
// ---------------------------------------------------------------------------

/// Replace every quoted span with spaces, so a `&&` or `||` inside a string
/// literal cannot be mistaken for an operator.
///
/// Byte length is preserved — a masked multi-byte character becomes that many
/// spaces — because `split_top_level_and` finds its cut offsets in the masked
/// copy and then slices the original.
fn mask_quoted(expr: &str) -> String {
    let mut out = String::with_capacity(expr.len());
    let mut quote: Option<char> = None;
    for ch in expr.chars() {
        let masked = match quote {
            Some(open) => {
                if ch == open {
                    quote = None;
                }
                true
            }
            None => {
                if ch == '\'' || ch == '"' {
                    quote = Some(ch);
                    true
                } else {
                    false
                }
            }
        };
        if masked {
            for _ in 0..ch.len_utf8() {
                out.push(' ');
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Drop a surrounding `${{ … }}` and collapse all whitespace (a folded
/// multi-line `if:` reads as one line).
fn normalise_expr(expr: &str) -> String {
    let trimmed = expr.trim();
    let body = trimmed
        .strip_prefix("${{")
        .and_then(|rest| rest.strip_suffix("}}"))
        .unwrap_or(trimmed);
    body.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Split on `&&` at paren depth zero, outside string literals.
fn split_top_level_and(expr: &str) -> Vec<String> {
    let masked = mask_quoted(expr);
    let bytes = masked.as_bytes();
    let mut cuts = vec![0usize];
    let mut depth = 0i32;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'&' if depth == 0 && bytes.get(i + 1) == Some(&b'&') => {
                cuts.push(i);
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    let mut parts = Vec::new();
    let mut start = 0usize;
    for cut in cuts.into_iter().skip(1) {
        parts.push(expr[start..cut].trim().to_owned());
        start = cut + 2;
    }
    parts.push(expr[start..].trim().to_owned());
    parts
}

/// `Some(inner)` when `conjunct` is one fully-enclosing paren group.
fn unwrap_parens(conjunct: &str) -> Option<&str> {
    let inner = conjunct.strip_prefix('(')?.strip_suffix(')')?;
    let masked = mask_quoted(inner);
    let mut depth = 0i32;
    for byte in masked.bytes() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            _ => {}
        }
    }
    (depth == 0).then_some(inner)
}

/// Whitespace- and quote-normalised comparison key for a conjunct.
fn conjunct_key(conjunct: &str) -> String {
    conjunct
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| if c == '"' { '\'' } else { c })
        .flat_map(char::to_lowercase)
        .collect()
}

/// Call `probe` on every conjunct a condition **requires**: top-level `&&`
/// operands, recursing into fully-parenthesised ones, skipping any operand
/// that is negated or carries a `||` (neither can be credited as a
/// requirement).
fn any_required_conjunct(expr: &str, probe: &dyn Fn(&str) -> bool) -> bool {
    for conjunct in split_top_level_and(expr) {
        if conjunct.starts_with('!') || mask_quoted(&conjunct).contains("||") {
            continue;
        }
        if probe(&conjunct) {
            return true;
        }
        if let Some(inner) = unwrap_parens(&conjunct) {
            if any_required_conjunct(inner, probe) {
                return true;
            }
        }
    }
    false
}

/// Does this condition **require** a `refs/tags/v` ref?
fn requires_ref(expr: Option<&str>) -> bool {
    let Some(expr) = expr else {
        return false;
    };
    let normalised = normalise_expr(expr);
    any_required_conjunct(&normalised, &|conjunct| conjunct_key(conjunct) == REF_TEST)
}

/// Does this condition **require** `needs.<job>.result == 'success'`?
fn requires_need_success(expr: &str, job: &str) -> bool {
    // `conjunct_key` lowercases, so the wanted key has to as well; Actions
    // job ids are case-sensitive but conventionally lower, and a mixed-case id
    // must not read as an untested edge.
    let wanted = format!("needs.{}.result=='success'", job.to_lowercase());
    let normalised = normalise_expr(expr);
    any_required_conjunct(&normalised, &|conjunct| conjunct_key(conjunct) == wanted)
}

/// Does this condition override Actions' implicit skip-on-failed-need?
fn voids_needs(expr: Option<&str>) -> bool {
    let Some(expr) = expr else {
        return false;
    };
    let key = conjunct_key(expr);
    NEEDS_VOIDING_FUNCTIONS
        .iter()
        .any(|func| key.contains(func))
}

// ---------------------------------------------------------------------------
// The needs graph.
// ---------------------------------------------------------------------------

/// A job's `if:`, as written (block scalars already joined by the parser).
fn job_if(job: &Value) -> Option<String> {
    job.get("if").and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}

/// A job's `needs:`, scalar or sequence.
fn declared_needs(job: &Value) -> Vec<String> {
    match job.get("needs") {
        Some(Value::String(one)) => vec![one.clone()],
        Some(Value::Array(many)) => many
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The declared `needs:` entries that actually gate this job: all of them
/// normally, and — when the `if:` carries a status function that voids the
/// implicit gating — only those the same `if:` conjunctively tests for
/// success.
fn effective_needs(job: &Value) -> Vec<String> {
    let declared = declared_needs(job);
    let Some(condition) = job_if(job) else {
        return declared;
    };
    if !voids_needs(Some(&condition)) {
        return declared;
    }
    declared
        .into_iter()
        .filter(|name| requires_need_success(&condition, name))
        .collect()
}

/// Transitive effective-needs closure of `start`, excluding `start` itself.
fn effective_closure(jobs: &BTreeMap<String, Value>, start: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<String> = jobs.get(start).map(effective_needs).unwrap_or_default();
    while let Some(name) = stack.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        if let Some(job) = jobs.get(&name) {
            stack.extend(effective_needs(job));
        }
    }
    seen
}

/// Does this job's **effective** run condition require a release ref —
/// either because it states the condition, or because it cannot start unless
/// a declared need that states it has run? Only a job that has not voided the
/// implicit gating may inherit.
fn requires_ref_effective(jobs: &BTreeMap<String, Value>, name: &str) -> bool {
    fn walk(jobs: &BTreeMap<String, Value>, name: &str, visiting: &mut BTreeSet<String>) -> bool {
        let Some(job) = jobs.get(name) else {
            return false;
        };
        let condition = job_if(job);
        if requires_ref(condition.as_deref()) {
            return true;
        }
        if voids_needs(condition.as_deref()) || !visiting.insert(name.to_owned()) {
            return false;
        }
        declared_needs(job)
            .iter()
            .any(|parent| walk(jobs, parent, visiting))
    }
    walk(jobs, name, &mut BTreeSet::new())
}

// ---------------------------------------------------------------------------
// Classification.
// ---------------------------------------------------------------------------

/// Flatten a parsed YAML value to the scalars it contains, one per line —
/// mapping keys included, comments gone with the parse. Horizontal runs are
/// collapsed so a marker cannot hide behind alignment.
fn flatten_scalars(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                push_scalar_lines(key, out);
                flatten_scalars(val, out);
            }
        }
        Value::Array(seq) => {
            for item in seq {
                flatten_scalars(item, out);
            }
        }
        Value::String(s) => push_scalar_lines(s, out),
        Value::Null => {}
        // Numbers and booleans: no marker is spelled as one, but they are
        // emitted rather than dropped so a `run:` whose whole body is a
        // scalar cannot vanish from the classified text.
        other => {
            out.push_str(&other.to_string());
            out.push('\n');
        }
    }
}

/// One scalar, one line per source line, horizontal runs collapsed so a
/// marker cannot hide behind alignment.
fn push_scalar_lines(text: &str, out: &mut String) {
    for line in text.lines() {
        out.push_str(&line.split_whitespace().collect::<Vec<_>>().join(" "));
        out.push('\n');
    }
}

/// A local reusable-workflow reference (`./.github/workflows/x.yml`), reduced
/// to its file name. A non-local `uses:` contributes no text — a stated blind
/// spot.
fn local_callee(job: &Value) -> Option<String> {
    let uses = job.get("uses").and_then(Value::as_str)?;
    uses.strip_prefix("./.github/workflows/")
        .map(str::to_owned)
        .filter(|name| !name.contains('/'))
}

/// The literal `with:` inputs a caller passes, scalars only.
fn caller_inputs(job: &Value) -> BTreeMap<String, String> {
    job.get("with")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(key, v)| {
                    let val = match v {
                        Value::String(s) => s.clone(),
                        Value::Bool(b) => b.to_string(),
                        Value::Number(n) => n.to_string(),
                        _ => return None,
                    };
                    Some((key.clone(), val))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Is this callee job unreachable for these caller inputs?
///
/// The one derived exemption, in place of the allow-list this family
/// forbids: a job guarded by `!inputs.<name>` cannot run when the caller
/// passes a non-empty literal for `<name>`. Only this syntactic form is
/// evaluated; everything else counts as reachable, so an error here demands a
/// ref condition that was not needed and can never excuse a missing one.
///
/// A literal `false` counts as reachable, not unreachable: for a
/// boolean-typed input that value makes `!inputs.<name>` *true*. The one live
/// caller passes a non-empty string (`gate_for: release` /
/// `gate_for: docker-publish`), so this distinction costs nothing and keeps
/// the predicate on the safe side of a type it cannot see.
fn statically_unreachable(condition: Option<&str>, inputs: &BTreeMap<String, String>) -> bool {
    let Some(condition) = condition else {
        return false;
    };
    let key = conjunct_key(condition);
    inputs.iter().any(|(name, value)| {
        !value.trim().is_empty()
            && value.trim() != "false"
            && key.contains(&format!("!inputs.{}", name.to_lowercase()))
    })
}

/// Everything a job executes, including the reachable jobs of any local
/// reusable workflow it calls.
fn executed_text(job: &Value, depth: usize) -> String {
    let mut text = String::new();
    flatten_scalars(job, &mut text);
    if depth == 0 {
        return text;
    }
    if let Some(callee) = local_callee(job) {
        let inputs = caller_inputs(job);
        for (_, callee_job) in load_jobs(&callee) {
            if statically_unreachable(job_if(&callee_job).as_deref(), &inputs) {
                continue;
            }
            text.push_str(&executed_text(&callee_job, depth - 1));
        }
    }
    text
}

/// Which publish markers does this job's executed text carry?
fn markers_in(job: &Value) -> Vec<&'static str> {
    let text = executed_text(job, MAX_USES_DEPTH);
    PUBLISH_MARKERS
        .iter()
        .copied()
        .filter(|marker| text.contains(marker))
        .collect()
}

/// The publishing jobs of a workflow, with the markers that classified them.
fn publishers(jobs: &BTreeMap<String, Value>) -> BTreeMap<String, Vec<&'static str>> {
    jobs.iter()
        .filter_map(|(name, job)| {
            let markers = markers_in(job);
            (!markers.is_empty()).then(|| (name.clone(), markers))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The three assertions.
// ---------------------------------------------------------------------------

#[test]
fn every_publishing_job_reaches_the_ci_gate() {
    let mut findings = Vec::new();
    for file in PUBLISH_WORKFLOWS {
        let jobs = load_jobs(file);
        for (name, markers) in publishers(&jobs) {
            let closure = effective_closure(&jobs, &name);
            if !closure.contains(CI_GATE) {
                findings.push(format!(
                    "{file}: `{name}` publishes ({}) but its effective needs closure {closure:?} \
                     does not reach `{CI_GATE}` — a fresh advisory, a banned dependency or stale \
                     THIRD-PARTY-LICENSES would not hold it",
                    markers.join(", ")
                ));
            }
        }
    }
    assert!(
        findings.is_empty(),
        "the advisory / attribution gate does not gate every publish:\n  {}",
        findings.join("\n  ")
    );
}

#[test]
fn every_publishing_job_in_docker_publish_reaches_the_cve_gate() {
    let file = "docker-publish.yml";
    let jobs = load_jobs(file);
    let mut exempt = effective_closure(&jobs, CVE_GATE);
    exempt.insert(CVE_GATE.to_owned());

    let mut findings = Vec::new();
    for (name, markers) in publishers(&jobs) {
        if exempt.contains(&name) {
            continue;
        }
        let closure = effective_closure(&jobs, &name);
        if !closure.contains(CVE_GATE) {
            findings.push(format!(
                "{file}: `{name}` publishes ({}) but its effective needs closure {closure:?} does \
                 not reach `{CVE_GATE}` — a fixable CRITICAL CVE would fail beside the publish \
                 instead of holding it",
                markers.join(", ")
            ));
        }
    }
    assert!(
        findings.is_empty(),
        "the container CVE gate does not gate every publish:\n  {}",
        findings.join("\n  ")
    );
}

#[test]
fn every_publishing_job_states_the_release_tag_requirement() {
    let mut findings = Vec::new();
    for file in PUBLISH_WORKFLOWS {
        let jobs = load_jobs(file);
        for (name, markers) in publishers(&jobs) {
            let job = job_named(&jobs, file, &name);
            if !requires_ref(job_if(job).as_deref()) {
                findings.push(format!(
                    "{file}: `{name}` publishes ({}) but its own `if:` ({:?}) does not require a \
                     `refs/tags/v` ref as an unnegated conjunct — a dispatch against any writable \
                     ref could publish or sign from it",
                    markers.join(", "),
                    job_if(job).unwrap_or_else(|| "<none>".to_owned()),
                ));
            }
        }
    }
    assert!(
        findings.is_empty(),
        "publication authority is not pinned to the release tag:\n  {}",
        findings.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Counter-assertions: the corpus is real.
// ---------------------------------------------------------------------------

#[test]
fn both_publish_workflows_parse_with_a_non_trivial_job_set() {
    for file in PUBLISH_WORKFLOWS {
        let jobs = load_jobs(file);
        assert!(
            jobs.len() >= MIN_JOBS,
            "{file} declares {} jobs, fewer than the {MIN_JOBS} this guard expects — a truncated \
             or restructured file would make the three assertions vacuous",
            jobs.len()
        );
    }
}

#[test]
fn the_gates_exist_by_name_in_the_workflows_that_must_reach_them() {
    for file in PUBLISH_WORKFLOWS {
        let jobs = load_jobs(file);
        assert!(
            jobs.contains_key(CI_GATE),
            "{file} has no `{CI_GATE}` job. A `needs:` entry naming a job that no longer exists \
             still puts that name into a closure walk, so assertions 1-3 would pass on a tree \
             whose gate has been renamed out from under them — this is the assertion that refuses \
             to let that read as green"
        );
    }
    let docker = load_jobs("docker-publish.yml");
    assert!(
        docker.contains_key(CVE_GATE),
        "docker-publish.yml has no `{CVE_GATE}` job — same hazard as above: the `needs:` entries \
         naming it would keep satisfying assertion 2 after the job itself was gone"
    );
}

#[test]
fn the_classification_finds_every_known_publisher() {
    for (file, known) in KNOWN_PUBLISHERS {
        let jobs = load_jobs(file);
        let found = publishers(&jobs);
        let missing: Vec<&str> = known
            .iter()
            .copied()
            .filter(|name| !found.contains_key(*name))
            .collect();
        assert!(
            missing.is_empty(),
            "{file}: {missing:?} publish but carry no marker in PUBLISH_MARKERS — either the job \
             was renamed, or its publishing mechanism changed and the marker list has to follow. \
             Classified today: {:?}",
            found.keys().collect::<Vec<_>>()
        );
    }
}

#[test]
fn the_ungated_job_sets_are_pinned() {
    for (file, expected) in EXPECTED_UNGATED {
        let jobs = load_jobs(file);
        let ungated: BTreeSet<String> = jobs
            .keys()
            .filter(|name| !requires_ref_effective(&jobs, name))
            .cloned()
            .collect();
        let expected: BTreeSet<String> = expected.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(
            ungated, expected,
            "{file}: the set of jobs whose effective run condition does not require a release ref \
             changed. A new entry is a job that runs on any writable ref and must be argued for in \
             review; a disappearing entry means the pin is stale"
        );
    }
}

#[test]
fn the_cve_gate_exemption_is_exactly_the_scans_own_prerequisite() {
    let jobs = load_jobs("docker-publish.yml");
    let mut reachable_from_gate = effective_closure(&jobs, CVE_GATE);
    reachable_from_gate.insert(CVE_GATE.to_owned());

    let exempt: BTreeSet<String> = publishers(&jobs)
        .into_keys()
        .filter(|name| reachable_from_gate.contains(name))
        .collect();
    let expected: BTreeSet<String> = EXPECTED_CVE_EXEMPT
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(
        exempt, expected,
        "docker-publish.yml: the publishing jobs the CVE gate itself depends on — and which \
         therefore cannot depend on it in turn — changed. `build-images` pushes an untagged \
         content-addressed digest, which is exactly what `{CVE_GATE}` scans; any other publisher \
         in this set has found a way around the CVE gate"
    );
}

#[test]
fn no_job_condition_leans_on_the_success_status_function() {
    for file in PUBLISH_WORKFLOWS {
        for (name, job) in load_jobs(file) {
            let Some(condition) = job_if(&job) else {
                continue;
            };
            assert!(
                !conjunct_key(&condition).contains("success()"),
                "{file}: `{name}`'s `if:` uses `success()`. `voids_needs` deliberately does not \
                 treat it as voiding the implicit needs-gating, because bare `success()` IS that \
                 gating — revisit that judgement here before relying on this guard's reading of \
                 the job"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Predicate unit tests: the failure paths, exercised.
// ---------------------------------------------------------------------------

#[test]
fn requires_ref_accepts_the_shapes_the_workflows_use() {
    assert!(requires_ref(Some(
        "${{ startsWith(github.ref, 'refs/tags/v') }}"
    )));
    assert!(requires_ref(Some(
        "${{ startsWith(github.ref, 'refs/tags/v') && !contains(github.ref, '-alpha.') }}"
    )));
    assert!(requires_ref(Some(
        "always() &&\nstartsWith(github.ref, 'refs/tags/v') &&\nneeds.build-binaries.result == 'success'\n"
    )));
    assert!(requires_ref(Some("startsWith(github.ref, 'refs/tags/v')")));
    // Quote style and spacing are normalised, and a fully-parenthesised
    // conjunct is unwrapped and re-split.
    assert!(requires_ref(Some(
        "${{ (vars.X == 'true' && startsWith(github.ref,\"refs/tags/v\")) }}"
    )));
}

#[test]
fn requires_ref_refuses_to_credit_a_disjunction() {
    // One character turns the gate into a no-op and still greps as gated,
    // which is why `requires_ref` reads structure rather than substrings.
    assert!(!requires_ref(Some(
        "${{ startsWith(github.ref, 'refs/tags/v') || github.event_name == 'workflow_dispatch' }}"
    )));
    assert!(!requires_ref(Some(
        "${{ vars.HORT_PROXY_ENABLED == 'true' && (startsWith(github.ref, 'refs/tags/v') || true) }}"
    )));
}

#[test]
fn requires_ref_refuses_to_credit_a_negation() {
    assert!(!requires_ref(Some(
        "${{ !startsWith(github.ref, 'refs/tags/v') }}"
    )));
    assert!(!requires_ref(Some(
        "${{ !startsWith(github.ref, 'refs/tags/v') && vars.X == 'true' }}"
    )));
}

#[test]
fn requires_ref_refuses_a_condition_that_is_about_something_else() {
    assert!(!requires_ref(Some("${{ always() }}")));
    assert!(!requires_ref(Some(
        "${{ always() && !contains(github.ref, '-alpha.') }}"
    )));
    // A near-miss spelling is not credited: the guard recognises one form, so
    // a rewrite is a review conversation rather than a silent pass.
    assert!(!requires_ref(Some("${{ github.ref_type == 'tag' }}")));
    assert!(!requires_ref(Some(
        "${{ startsWith(github.ref, 'refs/tags/') }}"
    )));
    assert!(!requires_ref(None));
}

#[test]
fn an_operator_inside_a_string_literal_is_not_an_operator() {
    // `mask_quoted` keeps a literal from splitting a conjunct or faking a
    // disjunction.
    assert!(requires_ref(Some(
        "${{ vars.SEP == '&&' && startsWith(github.ref, 'refs/tags/v') }}"
    )));
    assert!(requires_ref(Some(
        "${{ startsWith(github.ref, 'refs/tags/v') && vars.SEP == '||' }}"
    )));
}

#[test]
fn masking_a_literal_preserves_byte_offsets() {
    // The conjunct cuts are found in the masked copy and applied to the
    // original, so a multi-byte character inside a literal must mask to the
    // same number of bytes — otherwise the split lands mid-character and the
    // guard panics, which reads as a finding rather than a bug.
    let expr = "vars.NOTE == 'kein Ümlaut — und kein && hier' && \
                startsWith(github.ref, 'refs/tags/v')";
    assert_eq!(mask_quoted(expr).len(), expr.len());
    assert_eq!(split_top_level_and(expr).len(), 2);
    assert!(requires_ref(Some(expr)));
}

#[test]
fn effective_needs_keeps_every_declared_edge_without_a_status_function() {
    let job: Value = parse_workflow(
        "needs: [e2e-gate, ci-gate]\nif: ${{ startsWith(github.ref, 'refs/tags/v') }}\n",
    )
    .expect("fixture parses");
    assert_eq!(effective_needs(&job), vec!["e2e-gate", "ci-gate"]);
}

#[test]
fn effective_needs_drops_the_edge_an_always_voids() {
    // The shape a guard that walked declared edges would have called gated:
    // `sbom` is in `needs:`, `always()` voids it, and the `if:` never tests
    // it. Decorative, and this is where the guard says so.
    let job: Value = parse_workflow(
        "needs: [build-binaries, sbom]\nif: |\n  always() &&\n  needs.build-binaries.result == 'success'\n",
    )
    .expect("fixture parses");
    assert_eq!(effective_needs(&job), vec!["build-binaries"]);
}

#[test]
fn effective_needs_credits_a_tested_edge_even_under_always() {
    let job: Value = parse_workflow(
        "needs: [e2e-gate, ci-gate]\nif: |\n  always() &&\n  needs.e2e-gate.result == 'success' &&\n  needs.ci-gate.result == 'success'\n",
    )
    .expect("fixture parses");
    assert_eq!(effective_needs(&job), vec!["e2e-gate", "ci-gate"]);
}

#[test]
fn effective_needs_does_not_credit_a_disjoined_result_test() {
    let job: Value = parse_workflow(
        "needs: [ci-gate]\nif: |\n  always() &&\n  (needs.ci-gate.result == 'success' || github.event_name == 'workflow_dispatch')\n",
    )
    .expect("fixture parses");
    assert!(effective_needs(&job).is_empty());
}

#[test]
fn a_cancelled_or_failure_condition_voids_the_implicit_gating_too() {
    for condition in ["${{ !cancelled() }}", "${{ failure() }}"] {
        let job: Value = parse_workflow(&format!("needs: [ci-gate]\nif: \"{condition}\"\n"))
            .expect("fixture parses");
        assert!(
            effective_needs(&job).is_empty(),
            "{condition} overrides skip-on-failed-need just as always() does"
        );
    }
}

#[test]
fn statically_unreachable_fires_only_on_the_negated_input_form() {
    let gate_for: BTreeMap<String, String> = [("gate_for".to_owned(), "release".to_owned())]
        .into_iter()
        .collect();
    // ci.yml's verify build — the one case that would otherwise classify
    // `ci-gate` as a signing job.
    assert!(statically_unreachable(
        Some("${{ !inputs.gate_for && (github.event_name == 'pull_request') }}"),
        &gate_for
    ));
    // The caller passes nothing, or passes an empty / false literal: nothing
    // is derivable, so the job counts as reachable.
    assert!(!statically_unreachable(
        Some("${{ !inputs.gate_for }}"),
        &BTreeMap::new()
    ));
    assert!(!statically_unreachable(
        Some("${{ !inputs.gate_for }}"),
        &[("gate_for".to_owned(), String::new())]
            .into_iter()
            .collect()
    ));
    // Any other shape — including the un-negated read — is reachable.
    assert!(!statically_unreachable(
        Some("${{ inputs.gate_for == 'release' }}"),
        &gate_for
    ));
    assert!(!statically_unreachable(None, &gate_for));
}

#[test]
fn the_derived_callee_rule_is_what_keeps_the_gate_jobs_unclassified() {
    // Without it, `ci-gate` inherits `build-binaries.yml`'s `cosign
    // sign-blob` through ci.yml's verify build and classifies as a signing
    // job that cannot reach itself. Assert the rule is load-bearing rather
    // than inert: the callee job it skips really does carry a marker.
    let ci_jobs = load_jobs("ci.yml");
    let verify = job_named(&ci_jobs, "ci.yml", "build-binaries");
    assert!(
        statically_unreachable(
            job_if(verify).as_deref(),
            &[("gate_for".to_owned(), "release".to_owned())]
                .into_iter()
                .collect()
        ),
        "ci.yml's verify build must be derivably unreachable for a gate caller"
    );
    assert!(
        !markers_in(verify).is_empty(),
        "ci.yml's verify build must still reach a publish marker through its own callee — \
         otherwise this guard's one derived exemption has nothing to exempt and the reasoning \
         in the module doc has gone stale"
    );
    for file in PUBLISH_WORKFLOWS {
        let jobs = load_jobs(file);
        assert!(
            markers_in(job_named(&jobs, file, CI_GATE)).is_empty(),
            "{file}: `{CI_GATE}` must not classify as publishing"
        );
    }
}

#[test]
fn a_marker_does_not_fire_on_a_mention_of_the_mechanism() {
    // `verify-published` probes the chart's cosign signature and must stay a
    // verifier; `summary` prints a `cosign verify` command and must stay a
    // reporter. Both would be false positives that read as real findings.
    let docker = load_jobs("docker-publish.yml");
    for name in ["verify-published", "summary", CVE_GATE] {
        assert!(
            markers_in(job_named(&docker, "docker-publish.yml", name)).is_empty(),
            "docker-publish.yml: `{name}` mentions a publishing mechanism but does not use one"
        );
    }
}

#[test]
fn classification_reads_no_yaml_comments() {
    let job: Value = parse_workflow(
        "# This job used to run `cosign sign --yes` and `helm push .`\nsteps:\n  - run: echo ok\n",
    )
    .expect("fixture parses");
    assert!(
        markers_in(&job).is_empty(),
        "a comment describing a retired publish step must stay writable"
    );
}

#[test]
fn classification_folds_in_a_local_callee() {
    let jobs = load_jobs("release.yml");
    let build = job_named(&jobs, "release.yml", "build-binaries");
    let own_text = executed_text(build, 0);
    assert!(
        !PUBLISH_MARKERS
            .iter()
            .any(|marker| own_text.contains(marker)),
        "release.yml's `build-binaries` carries no marker of its own — which is the whole reason \
         classification has to fold in the callee"
    );
    assert!(
        markers_in(build).contains(&"cosign sign-blob"),
        "it must still classify as publishing, through build-binaries.yml"
    );
}
