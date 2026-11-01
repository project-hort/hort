//! Structural guard: **the CLI advertises only task kinds the server
//! routes, and every routed kind is either advertised or declared
//! unadvertised here.**
//!
//! `hort-cli admin task invoke --help` prints the kinds an operator may
//! invoke. That list is prose in a `clap` doc comment inside
//! [`CLI_HELP_FILE`]; the kinds that actually answer a `POST` are `axum`
//! routes in [`ROUTER_FILE`], mounted by `hort-server::http` under
//! `/api/v1/admin/tasks`. Nothing connected the two, and they drifted:
//! the help text named `scan`, which the router has never carried, so the
//! advertised call fell through to the `GET /{id}` pattern and answered
//! `405 Method Not Allowed`.
//!
//! The cost of that drift is not cosmetic. An operator reaching for a
//! documented recovery instrument mid-incident got a status code and no
//! hint of where the real instrument is — and `scan` is not a near miss a
//! route could fix: a `scan` row is only well-formed carrying the four
//! scan-typed columns (`artifact_id`, `repository_id`, `content_hash`,
//! `format`) that `JobsRepository::enqueue_scan` writes and the generic
//! admin enqueue path never does, which is why `"scan"` is absent from
//! `hort_domain::events::ADMIN_INVOKABLE_TASK_KINDS` as well. The
//! per-artifact instrument is `hort-cli admin rescan`
//! ([`RESCAN_POINTER`]), and the corrected help text says so.
//!
//! ## Why a source scan and not a shared constant
//!
//! A constant *imported from the router crate* is unsound: `hort-cli`
//! deliberately carries no domain, app or adapter dependency while the
//! router depends on both, so that direction inverts ADR 0008's layering.
//! A third, dependency-free crate holding the advertised list would work
//! and is not forbidden. The scan is chosen over it because it adds no
//! crate and leaves the list inside the help text, where a reader of
//! either side will look — **a choice, not a forced move.**
//!
//! ## The property
//!
//! Let *advertised* be the kinds named in [`CLI_HELP_FILE`]'s run of kind
//! names, and *routed* be the paths of [`ROUTER_FILE`]'s
//! `post(invoke::<…>)` routes. Then:
//!
//! 1. every advertised kind is routed — the help text names nothing that
//!    answers `405`;
//! 2. every routed kind is advertised **or** listed in
//!    [`DELIBERATELY_UNADVERTISED`] with its reason.
//!
//! The comparison is against the `post(invoke::<…>)` routes and
//! deliberately **not** against `ADMIN_INVOKABLE_TASK_KINDS`, which is
//! broader than the router on purpose: that constant is the set of kinds
//! an admin may enqueue *at all* (it also gates the DSN-direct
//! `hort-server enqueue-*` subcommands and event validation), and the
//! router being a subset of it is the design. Comparing the help text
//! against the wider set would bless exactly the `405` this guard exists
//! to prevent.
//!
//! ## No allow-list file
//!
//! The routed-but-unadvertised kinds are declared in
//! [`DELIBERATELY_UNADVERTISED`], in this file, each with the reason it is
//! absent from the operator-facing list. That is the point: a kind that
//! should not be advertised says so where the assertion stands, so a
//! reviewer reading the guard reads the reasons, and a reason that has
//! stopped being true sits in front of whoever next touches the list. An
//! exemption file would put them where only the guard looks.
//!
//! ## Counter-assertions
//!
//! A scan whose needle has been renamed out of existence is vacuously
//! green, which is how guards in this family die. Three things hold that
//! off:
//!
//! * [`the_scanned_lists_are_real`] asserts both lists parse, and that
//!   each still contains [`ANCHOR_KIND`] — the one kind routed and
//!   advertised since v1 — and that the help text still names the
//!   per-artifact instrument.
//! * It also asserts the comparison's **premise**: every `POST` route in
//!   the router is an `invoke::<…>` route. A `POST` to something else
//!   would mean "routed kind" no longer equals "`POST` route", and both
//!   checks would be comparing against the wrong set without failing.
//! * [`the_scan_still_fails_on_a_mutated_tree`] mutates in-memory copies
//!   of both files and asserts each check fires: an extra advertised kind
//!   with no route, an extra route neither advertised nor declared, a
//!   renamed heading, a renamed router function, and a non-invoke `POST`.
//!   Emptying a predicate would pass the tests above on today's tree and
//!   fail here.
//!
//! ## Blind spots — read these before trusting a green run
//!
//! A route assembled through a macro or a helper rather than a literal
//! `.route("<path>", post(invoke::<…>))` call in `fn router` is invisible,
//! as is a second router mounted under the same prefix from another crate
//! (there is one mount point today, `hort-server::http`). A `MethodRouter`
//! chaining `post(invoke::<…>).get(…)` reads as an invoke route, which is
//! right about the kind but hides the `get`. And the help text's kinds are
//! read from the heading to the period that closes the run, so a kind
//! named in a later sentence of the same doc comment is not checked — the
//! corrected text says `scan` is *not* a kind in exactly such a sentence,
//! which is why that boundary is where it is.
//!
//! DB-free and sub-second, so `cargo test --workspace` runs it with no
//! database — same family as `capped_stream_reads`,
//! `cas_reads_are_verified` and `db_tests_are_serialized`.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

mod rust_scan;

use rust_scan::{block_end, is_ident_byte, line_of, mark_literals, starts_a_token, workspace_root};

/// This guard's own path, for failure messages that tell a reader where
/// the declaration they need to edit lives.
const GUARD_FILE: &str = "crates/hort-app/tests/cli_advertises_only_routed_task_kinds.rs";

/// The CLI file whose `clap` help text advertises the invokable kinds.
const CLI_HELP_FILE: &str = "crates/hort-cli/src/admin/mod.rs";

/// The heading that introduces the advertised run of kind names. Must
/// appear exactly once in [`CLI_HELP_FILE`]; a rename fails loudly rather
/// than emptying the scan.
const ADVERTISED_HEADING: &str = "v1 allowlist:";

/// The per-artifact instrument the same help text must point at, because
/// `scan` leaving the advertised list is only half the fix — the other
/// half is telling the operator where the real one is.
const RESCAN_POINTER: &str = "hort-cli admin rescan";

/// The inbound adapter that mounts the admin-task routes.
const ROUTER_FILE: &str = "crates/hort-http-admin-tasks/src/lib.rs";

/// The function in [`ROUTER_FILE`] that builds the route subtree.
const ROUTER_FN: &str = "router";

/// The handler expression that makes a `POST` route an *invoke* route.
const INVOKE_HANDLER: &str = "invoke::<";

/// The kind that has been both routed and advertised since v1, named so a
/// scan that silently stopped finding either list cannot read as green.
const ANCHOR_KIND: &str = "noop";

/// Routed kinds deliberately absent from the operator-facing help text,
/// each with the reason it is absent.
///
/// All four are reached by `hort-cli admin task invoke <kind>` — that is
/// why they carry routes — but the caller is a **scheduler**, not a human
/// at a terminal: the chart's CronJob
/// (`deploy/helm/hort-server/templates/cronjob-<kind>.yaml`) or the native
/// deploy's systemd timer (`deploy/ansible/roles/hort_timers`), both on
/// the `admin-task` execution path with the `<release>-svc-token` PAT.
/// None of the four has a `hort-server enqueue-*` subcommand, so the
/// route is how its schedule reaches it.
///
/// The help text is the hand-invocation surface: what an operator types
/// during an incident. A scheduled maintenance sweep belongs on its
/// schedule, and advertising one as a recovery instrument invites a manual
/// run at the worst possible moment.
const DELIBERATELY_UNADVERTISED: &[(&str, &str)] = &[
    (
        "service-account-rotation",
        "Rotates service-account PATs and rewrites the Kubernetes Secret \
         holding them. A hand-run cuts every consumer still carrying the \
         previous PAT, so the schedule — which overlaps issuance with \
         expiry — is the caller that makes it safe.",
    ),
    (
        "eventstore-checkpoint",
        "Writes the periodic stream-hash anchors `verify-event-chain` \
         checks against. Its value is the regular cadence, not any one \
         run; an operator has no reason to want a single checkpoint now.",
    ),
    (
        "replay-seen-prune",
        "Drops replay-protection bookkeeping past its window. \
         Housekeeping with no operator-visible outcome to inspect \
         afterwards.",
    ),
    (
        "scanner-registry-prune",
        "Deletes dead scanner-worker rows from `scanner_registry`. The \
         liveness read that matters is `hort-cli admin workers list`, \
         which shows a stale worker as `LIVE=NO` rather than hiding it, so \
         pruning is maintenance rather than diagnosis.",
    ),
];

// ---------------------------------------------------------------------------
// The advertised list
// ---------------------------------------------------------------------------

/// The kinds [`CLI_HELP_FILE`]'s help text advertises, in the order it
/// names them.
///
/// The run is the text between [`ADVERTISED_HEADING`] and the period that
/// closes it, with the doc-comment prefixes dropped. Anything in it that
/// is not a kind token — a backtick, a parenthetical, the word "and" — is
/// an `Err` rather than a silently-shorter list: the help text is prose a
/// reader will reasonably want to reword, and the guard has to say so
/// instead of quietly checking less than the operator reads.
fn advertised_kinds(source: &str) -> Result<Vec<String>, String> {
    let headings = source.matches(ADVERTISED_HEADING).count();
    if headings != 1 {
        return Err(format!(
            "expected exactly one `{ADVERTISED_HEADING}` heading in \
             {CLI_HELP_FILE}, found {headings}. Zero means the heading was \
             renamed and this guard is reading nothing — point \
             `ADVERTISED_HEADING` in {GUARD_FILE} at the new wording. More \
             than one means there are two advertised lists, and which one \
             an operator reads is a coin toss"
        ));
    }
    let after = source
        .find(ADVERTISED_HEADING)
        .expect("the count above found a heading")
        + ADVERTISED_HEADING.len();
    let span = source[after..].find('.').ok_or_else(|| {
        format!(
            "the `{ADVERTISED_HEADING}` run in {CLI_HELP_FILE} is not \
             terminated by a period, so this guard cannot tell where the \
             kinds end and the surrounding prose begins"
        )
    })?;
    // The run spans several doc-comment lines; `///` is not part of a kind.
    let flat = source[after..after + span].replace("///", " ");

    let mut kinds = Vec::new();
    for piece in flat.split(',') {
        let token = piece.trim();
        if !is_kind_token(token) {
            return Err(format!(
                "`{token}` sits in the `{ADVERTISED_HEADING}` run in \
                 {CLI_HELP_FILE} but is not a task kind \
                 (lowercase-hyphenated, as every `jobs.kind` value is). \
                 Keep the run one comma-separated list of bare kind names \
                 ending in a period, and put the prose in a sentence after \
                 it — otherwise this guard checks a shorter list than the \
                 operator reads"
            ));
        }
        kinds.push(token.to_owned());
    }
    Ok(kinds)
}

/// A lowercase-hyphenated task kind, the shape every `jobs.kind` value has.
fn is_kind_token(token: &str) -> bool {
    !token.is_empty()
        && token.starts_with(|c: char| c.is_ascii_lowercase())
        && token.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && !token.contains("--")
        && token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

// ---------------------------------------------------------------------------
// The routed list
// ---------------------------------------------------------------------------

/// One `POST` route mounted by [`ROUTER_FN`].
struct PostRoute {
    /// The path literal's contents, e.g. `/noop`.
    path: String,
    /// The handler expression, e.g. `post(invoke::<NoopParams>)`.
    handler: String,
    /// 1-based line of the `.route(` call.
    line: usize,
}

impl PostRoute {
    fn is_invoke(&self) -> bool {
        self.handler.contains(INVOKE_HANDLER)
    }
}

/// Every `POST` route [`ROUTER_FN`] mounts, invoke or not.
///
/// Reads the route table structurally rather than by substring. Comments
/// and literals are blanked first — the module header documents the whole
/// route table in prose, and the `/{id}` path literal carries braces that
/// would otherwise derail a brace matcher — then the function's body is
/// bounded, then each `.route(` call is split into its path literal and
/// its handler expression.
fn post_routes(source: &str) -> Result<Vec<PostRoute>, String> {
    let (marked, spans) = mark_literals(source);
    let bytes = marked.as_bytes();

    let offsets = fn_offsets(&marked, ROUTER_FN);
    if offsets.len() != 1 {
        return Err(format!(
            "expected exactly one `fn {ROUTER_FN}` in {ROUTER_FILE}, found \
             {}. Zero means the route-builder was renamed and this guard is \
             reading nothing; more than one means it is ambiguous which \
             table is the mounted one",
            offsets.len()
        ));
    }
    let fn_at = offsets[0];
    let open = marked[fn_at..]
        .find('{')
        .map(|i| fn_at + i)
        .ok_or_else(|| format!("`fn {ROUTER_FN}` in {ROUTER_FILE} has no body"))?;
    let close = block_end(bytes, open)
        .ok_or_else(|| format!("`fn {ROUTER_FN}`'s body in {ROUTER_FILE} is unbalanced"))?;

    const ROUTE_CALL: &str = ".route(";
    let mut routes = Vec::new();
    let mut cursor = open;
    while cursor < close {
        let Some(found) = marked[cursor..close].find(ROUTE_CALL) else {
            break;
        };
        let at = cursor + found;
        cursor = at + ROUTE_CALL.len();
        let paren = at + ROUTE_CALL.len() - 1;
        let call_end = paren_end(bytes, paren).ok_or_else(|| {
            format!(
                "the `.route(` call at {ROUTER_FILE}:{} is unbalanced",
                line_of(&marked, at)
            )
        })?;

        let (literal_at, literal_end) = spans
            .iter()
            .copied()
            .find(|(start, _)| *start > paren && *start < call_end)
            .ok_or_else(|| {
                format!(
                    "the `.route(` call at {ROUTER_FILE}:{} supplies no path \
                     literal. A path built at runtime is a route this guard \
                     cannot name",
                    line_of(&marked, at)
                )
            })?;
        let literal = &source[literal_at..literal_end];
        let path = literal
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or_else(|| {
                format!(
                    "the route path {literal} at {ROUTER_FILE}:{} is not a \
                     plain double-quoted string",
                    line_of(&marked, at)
                )
            })?;

        let handler = marked[literal_end..call_end]
            .trim()
            .trim_start_matches(',')
            .trim()
            .trim_end_matches(',')
            .trim();
        let method = handler
            .split('(')
            .next()
            .expect("`split` always yields a first element")
            .trim();
        match method {
            "post" => routes.push(PostRoute {
                path: path.to_owned(),
                handler: handler.to_owned(),
                line: line_of(&marked, at),
            }),
            // The list and single-job reads; not part of the invoke surface.
            "get" => {}
            other => {
                return Err(format!(
                    "the route `{path}` at {ROUTER_FILE}:{} is mounted with \
                     `{other}`, a method router this guard does not know. It \
                     compares the help text against the POST surface, so a \
                     new method needs a deliberate decision in {GUARD_FILE} \
                     rather than silent omission",
                    line_of(&marked, at)
                ))
            }
        }
    }
    Ok(routes)
}

/// The kinds reachable as `POST /api/v1/admin/tasks/<kind>`.
fn routed_invoke_kinds(source: &str) -> Result<BTreeSet<String>, String> {
    let routes = post_routes(source)?;
    let mut kinds = BTreeSet::new();
    for route in routes.iter().filter(|route| route.is_invoke()) {
        let kind = route.path.strip_prefix('/').ok_or_else(|| {
            format!(
                "the invoke route path `{}` at {ROUTER_FILE}:{} does not \
                 start with `/`",
                route.path, route.line
            )
        })?;
        if !is_kind_token(kind) {
            return Err(format!(
                "the invoke route path `{}` at {ROUTER_FILE}:{} is not \
                 `/<kind>` for a lowercase-hyphenated kind, so it cannot be \
                 compared against the help text",
                route.path, route.line
            ));
        }
        kinds.insert(kind.to_owned());
    }
    Ok(kinds)
}

/// Offsets of the `fn` keyword of every `fn <name>` in blanked text.
fn fn_offsets(marked: &str, name: &str) -> Vec<usize> {
    let needle = format!("fn {name}");
    let bytes = marked.as_bytes();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(found) = marked[cursor..].find(&needle) {
        let at = cursor + found;
        cursor = at + 1;
        let after = at + needle.len();
        if starts_a_token(bytes, at) && !(after < bytes.len() && is_ident_byte(bytes[after])) {
            out.push(at);
        }
    }
    out
}

/// The offset of the `)` closing the call whose `(` sits at `open`.
///
/// A byte scan, sound only on text [`mark_literals`] has already blanked:
/// a `(` inside a doc comment or a path literal is not a call opener.
fn paren_end(bytes: &[u8], open: usize) -> Option<usize> {
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    for (at, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// The two comparisons, factored out so the mutation test can drive them
// ---------------------------------------------------------------------------

/// Advertised kinds with no `post(invoke::<…>)` route — each one a `405`
/// waiting for an operator.
fn advertised_without_a_route(advertised: &[String], routed: &BTreeSet<String>) -> Vec<String> {
    advertised
        .iter()
        .filter(|kind| !routed.contains(*kind))
        .cloned()
        .collect()
}

/// Routed kinds that are neither advertised nor declared unadvertised.
fn routed_without_a_declaration(routed: &BTreeSet<String>, advertised: &[String]) -> Vec<String> {
    routed
        .iter()
        .filter(|kind| !advertised.iter().any(|named| named == *kind))
        .filter(|kind| {
            !DELIBERATELY_UNADVERTISED
                .iter()
                .any(|(declared, _)| *declared == kind.as_str())
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn read(root: &Path, rel: &str) -> String {
    fs::read_to_string(root.join(rel))
        .unwrap_or_else(|why| panic!("{rel} must exist and be readable UTF-8: {why}"))
}

fn lists(root: &Path) -> (Vec<String>, BTreeSet<String>) {
    let advertised =
        advertised_kinds(&read(root, CLI_HELP_FILE)).unwrap_or_else(|why| panic!("{why}"));
    let routed =
        routed_invoke_kinds(&read(root, ROUTER_FILE)).unwrap_or_else(|why| panic!("{why}"));
    (advertised, routed)
}

fn joined(kinds: &BTreeSet<String>) -> String {
    kinds.iter().cloned().collect::<Vec<_>>().join(", ")
}

// ---------------------------------------------------------------------------
// The property
// ---------------------------------------------------------------------------

#[test]
fn every_advertised_kind_has_a_post_route() {
    let root = workspace_root();
    let (advertised, routed) = lists(&root);
    let unrouted = advertised_without_a_route(&advertised, &routed);

    assert!(
        unrouted.is_empty(),
        "{CLI_HELP_FILE}'s `{ADVERTISED_HEADING}` run advertises {} kind(s) \
         the server does not route: {}.\n\
         `hort-cli admin task invoke <kind>` POSTs to \
         /api/v1/admin/tasks/<kind>; with no `post` route for that path the \
         request falls through to the `GET /{{id}}` pattern and the operator \
         gets `405 Method Not Allowed` — a documented recovery instrument \
         answering with a status code and no hint of where the real one is. \
         That is how `scan` read as invokable for as long as it did.\n\
         Either take the kind out of the help text (and, if there is a real \
         instrument behind it, point at that instead — `scan`'s is \
         `{RESCAN_POINTER}`), or add the route in {ROUTER_FILE}. Adding a \
         route is much the bigger decision: the kind also has to be in \
         `hort_domain::events::ADMIN_INVOKABLE_TASK_KINDS`, and its generic \
         enqueue has to produce a `jobs` row the claim can resolve.\n\
         Routed kinds today: {}",
        unrouted.len(),
        unrouted.join(", "),
        joined(&routed)
    );
}

#[test]
fn every_routed_kind_is_advertised_or_declared_unadvertised() {
    let root = workspace_root();
    let (advertised, routed) = lists(&root);
    let undeclared = routed_without_a_declaration(&routed, &advertised);

    assert!(
        undeclared.is_empty(),
        "{ROUTER_FILE} routes {} kind(s) that {CLI_HELP_FILE} does not \
         advertise and this guard does not declare: {}.\n\
         A route no operator-facing text mentions is a capability only \
         whoever wrote it knows about. Pick one:\n\
         * it is for operators — add it to the `{ADVERTISED_HEADING}` run \
         in {CLI_HELP_FILE};\n\
         * it is for a scheduler (a chart CronJob or a systemd timer) and a \
         human should not be reaching for it — add it to \
         `DELIBERATELY_UNADVERTISED` in {GUARD_FILE} together with the \
         reason, which is the part a reviewer actually reads.\n\
         There is no exemption file on purpose: the reason belongs where \
         the assertion stands, so it stays in front of the next reader.",
        undeclared.len(),
        undeclared.join(", ")
    );
}

#[test]
fn the_unadvertised_declaration_matches_the_router() {
    let root = workspace_root();
    let (advertised, routed) = lists(&root);

    let stale: Vec<&str> = DELIBERATELY_UNADVERTISED
        .iter()
        .map(|(kind, _)| *kind)
        .filter(|kind| !routed.contains(*kind))
        .collect();
    assert!(
        stale.is_empty(),
        "`DELIBERATELY_UNADVERTISED` declares {} kind(s) the router no \
         longer carries: {}. A declaration outliving its route is dead \
         weight that would also silently excuse the kind if a route came \
         back for some different reason — delete the entry.\n\
         Routed kinds today: {}",
        stale.len(),
        stale.join(", "),
        joined(&routed)
    );

    let both: Vec<&str> = DELIBERATELY_UNADVERTISED
        .iter()
        .map(|(kind, _)| *kind)
        .filter(|kind| advertised.iter().any(|named| named == kind))
        .collect();
    assert!(
        both.is_empty(),
        "{} kind(s) are both advertised in {CLI_HELP_FILE} and declared \
         unadvertised in {GUARD_FILE}: {}. One of the two statements is \
         wrong, and while they disagree the routed-kind check passes for \
         the wrong reason",
        both.len(),
        both.join(", ")
    );

    let unreasoned: Vec<&str> = DELIBERATELY_UNADVERTISED
        .iter()
        .filter(|(_, reason)| reason.trim().is_empty())
        .map(|(kind, _)| *kind)
        .collect();
    assert!(
        unreasoned.is_empty(),
        "{} declared-unadvertised kind(s) carry no reason: {}. The reason \
         is the whole difference between this declaration and an \
         allow-list file",
        unreasoned.len(),
        unreasoned.join(", ")
    );
}

// ---------------------------------------------------------------------------
// Counter-assertions
// ---------------------------------------------------------------------------

/// Counter-assertion: both lists are real. A rename of the help text's
/// heading, of the router's builder function, or of the route call would
/// otherwise make every test above pass by comparing two empty sets.
#[test]
fn the_scanned_lists_are_real() {
    let root = workspace_root();
    let cli = read(&root, CLI_HELP_FILE);
    let router = read(&root, ROUTER_FILE);

    let advertised = advertised_kinds(&cli).unwrap_or_else(|why| panic!("{why}"));
    assert!(
        advertised.iter().any(|kind| kind == ANCHOR_KIND),
        "the advertised list parsed to {advertised:?}, which does not \
         include `{ANCHOR_KIND}`. That kind has been both routed and \
         advertised since v1; its absence means the parse is reading \
         something other than the help text's list of kinds, and the \
         comparisons above are then about nothing"
    );

    let routed = routed_invoke_kinds(&router).unwrap_or_else(|why| panic!("{why}"));
    assert!(
        routed.contains(ANCHOR_KIND),
        "the routed set parsed to {routed:?}, which does not include \
         `{ANCHOR_KIND}`. The route table is not being read"
    );

    assert!(
        cli.contains(RESCAN_POINTER),
        "{CLI_HELP_FILE} no longer names `{RESCAN_POINTER}`. Taking `scan` \
         out of the advertised list was only half the fix: an operator who \
         came looking for it needs the per-artifact instrument named in the \
         same help text, or the `405` is merely replaced by silence"
    );

    // The premise of both comparisons: on this router, "routed kind" means
    // "POST route". A POST to anything but `invoke::<…>` would break that
    // equivalence without breaking either comparison.
    let routes = post_routes(&router).unwrap_or_else(|why| panic!("{why}"));
    let non_invoke: Vec<String> = routes
        .iter()
        .filter(|route| !route.is_invoke())
        .map(|route| format!("{ROUTER_FILE}:{} {}", route.line, route.path))
        .collect();
    assert!(
        non_invoke.is_empty(),
        "{} POST route(s) in {ROUTER_FILE} are not `{INVOKE_HANDLER}…>` \
         handlers: {}.\n\
         This guard equates `POST /api/v1/admin/tasks/<x>` with \"<x> is an \
         invokable task kind\" — that equivalence is what lets it compare \
         the help text's kinds against route paths. A POST route that is \
         not an invoke breaks it, so the comparison needs re-reading in \
         {GUARD_FILE} before such a route lands.",
        non_invoke.len(),
        non_invoke.join(", ")
    );
}

/// Counter-assertion: the comparisons can still fail. Each mutation below
/// is a regression someone could plausibly write, applied to an in-memory
/// copy of the real file — so emptying a predicate passes the tests above
/// on today's tree and fails here.
#[test]
fn the_scan_still_fails_on_a_mutated_tree() {
    let root = workspace_root();
    let cli = read(&root, CLI_HELP_FILE);
    let router = read(&root, ROUTER_FILE);
    let advertised = advertised_kinds(&cli).unwrap_or_else(|why| panic!("{why}"));
    let routed = routed_invoke_kinds(&router).unwrap_or_else(|why| panic!("{why}"));

    // (1) advertised-but-unrouted — the `scan` regression itself.
    let advertised_plus = advertised_kinds(&with_extra_advertised_kind(&cli, "scan"))
        .unwrap_or_else(|why| panic!("{why}"));
    assert_eq!(
        advertised_without_a_route(&advertised_plus, &routed),
        vec!["scan".to_owned()],
        "advertising `scan` again must be reported as unrouted; if it is \
         not, `advertised_without_a_route` has stopped comparing"
    );

    // (2) routed-but-undeclared — a new route nobody mentions.
    let widened = with_extra_post_route(
        &router,
        "/synthetic-unrouted-kind",
        "post(invoke::<NoopParams>)",
    );
    let routed_plus = routed_invoke_kinds(&widened).unwrap_or_else(|why| panic!("{why}"));
    assert_eq!(
        routed_without_a_declaration(&routed_plus, &advertised),
        vec!["synthetic-unrouted-kind".to_owned()],
        "a route that is neither advertised nor declared must be reported; \
         if it is not, `routed_without_a_declaration` has stopped comparing"
    );

    // (3) the heading renamed — the help text's list stops being found.
    assert!(
        advertised_kinds(&cli.replace(ADVERTISED_HEADING, "invokable kinds:")).is_err(),
        "renaming `{ADVERTISED_HEADING}` must be an error, not an empty \
         list: an empty advertised list satisfies every comparison above"
    );

    // (4) the builder renamed — the route table stops being found.
    assert!(
        routed_invoke_kinds(&router.replace(&format!("fn {ROUTER_FN}("), "fn routes(")).is_err(),
        "renaming `fn {ROUTER_FN}` must be an error, not an empty routed \
         set. An empty set makes every advertised kind a violation, which \
         at least fails loudly — but it also silently excuses every \
         declaration, so the scan has to refuse to guess"
    );

    // (5) a POST route that is not an invoke — the premise breaking.
    let odd_post = with_extra_post_route(&router, "/not-an-invoke", "post(list_tasks)");
    let routes = post_routes(&odd_post).unwrap_or_else(|why| panic!("{why}"));
    assert!(
        routes.iter().any(|route| !route.is_invoke()),
        "a `post(list_tasks)` route must read as a non-invoke POST; if it \
         does not, the premise check in `the_scanned_lists_are_real` cannot \
         fire"
    );
}

/// [`CLI_HELP_FILE`] with one more kind in the advertised run.
fn with_extra_advertised_kind(source: &str, kind: &str) -> String {
    let after = source
        .find(ADVERTISED_HEADING)
        .expect("the real file carries the heading")
        + ADVERTISED_HEADING.len();
    let period = after
        + source[after..]
            .find('.')
            .expect("the real file terminates the run with a period");
    format!("{}, {kind}{}", &source[..period], &source[period..])
}

/// [`ROUTER_FILE`] with one more route mounted at the head of the table.
fn with_extra_post_route(source: &str, path: &str, handler: &str) -> String {
    const BUILDER: &str = "Router::new()";
    assert_eq!(
        source.matches(BUILDER).count(),
        1,
        "expected exactly one `{BUILDER}` in {ROUTER_FILE} to splice a \
         synthetic route after; the mutation counter-assertion has nowhere \
         to put one otherwise"
    );
    let at = source
        .find(BUILDER)
        .expect("the count above found the builder")
        + BUILDER.len();
    format!(
        "{}\n        .route(\"{path}\", {handler}){}",
        &source[..at],
        &source[at..]
    )
}
