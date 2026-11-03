//! `jobs.trigger_source` CHECK / [`TriggerSource::ALL`] lock-step guard.
//!
//! DB-free, network-free source-scan — the committed proof (in the spirit
//! of its sibling `task_kind_check_lockstep_guard`, and of
//! `ephemeral_keyspace_exhaustive` / `no_bcrypt` / `no_sensitive_drops`)
//! that the `jobs.trigger_source` SQL CHECK list **in force**, the
//! generated set [`hort_domain::ports::jobs_repository::TriggerSource`]
//! accepts, and that type's own variants never drift apart.
//!
//! ## Why a guard, and why this column in particular
//!
//! The set used to be written down three times with no two copies
//! agreeing. The SQL CHECK admitted eight literals; the domain type named
//! **four** while its own doc comment claimed to mirror the CHECK; and
//! the writers produced a ninth, `'register-by-hash'`, that was in
//! neither. Nothing was holding any pair of them together, and the
//! consequence was reachable: the OCI cross-repository blob mount
//! answered `500` whenever the gate requested a scan for the mounted
//! blob, because the enqueue it stamps violated the CHECK and aborted the
//! ingest transition.
//!
//! A mock-based unit test cannot see this — `MockArtifactLifecycle` and
//! `MockJobsRepository` accept any `trigger_source` whatsoever, because
//! the CHECK lives in the schema. So the drift surfaced only against a
//! real Postgres, on the one path that reaches it. This guard closes that
//! without needing a database.
//!
//! ## Which migration the guard reads — the effective list
//!
//! Not `009_scan_jobs_and_findings.sql` unconditionally. A migration
//! chain is applied in order and the constraint can be redefined by a
//! later `ALTER TABLE public.jobs DROP CONSTRAINT
//! jobs_trigger_source_check; ADD CONSTRAINT jobs_trigger_source_check
//! CHECK (trigger_source IN (…))`, which is how a literal reaches a
//! database that has already applied 009 (editing 009 in place changes
//! its checksum and makes `sqlx::migrate!` reject every already-migrated
//! database with `VersionMismatch`). So the list in force — the
//! *effective* list, the only one a running database actually enforces —
//! is the one defined by the **newest** migration that defines it: today
//! `036_jobs_trigger_source_register_by_hash.sql`, tomorrow whichever
//! migration redefines it next, with no edit to this guard required.
//!
//! Reading 009 unconditionally would make the guard assert against a list
//! no live database enforces: it would go red on a legitimate
//! redefinition and, worse, stay green while the effective list and the
//! domain type disagreed. That mistake was live in the tree — the
//! pre-existing `prefetch_trigger_source_is_allowed_by_jobs_check_constraint`
//! test parsed 009 by hand — which is why this guard replaces it rather
//! than sitting beside it.
//!
//! ## What it asserts — two links of one chain
//!
//! The chain is `pub enum TriggerSource` → the `trigger_source_wire!`
//! list → `TriggerSource::ALL` → the SQL CHECK in force, and a break at
//! either end has the same consequence: a literal one side can produce
//! and the other refuses.
//!
//! 1. **SQL ↔ `ALL`.** The `trigger_source IN (…)` list parsed out of
//!    the newest migration that defines the `jobs.trigger_source` CHECK
//!    equals the wire strings of [`TriggerSource::ALL`] exactly — same
//!    members, order-independent.
//! 2. **enum ↔ the wire list.** Every `TriggerSource` variant appears in
//!    the one `trigger_source_wire!` list that `ALL` and `as_str` are
//!    both generated from. The compiler already refuses the omission
//!    (the generated `as_str` match is wildcard-free, so a variant the
//!    list does not name is `E0004`); this is the net under that, for
//!    the day `ALL` or `as_str` is unwound back into a second
//!    hand-written list. That arrangement is exactly what the escape
//!    needed: a variant with an `as_str` literal, a tier, an ordinal and
//!    a producer, and no `ALL` entry — `ALL.len()`, every test iterating
//!    `ALL` and assertion 1 all stayed green while `FromStr` rejected
//!    the literal the producer stamped and the `INSERT` died on a
//!    `23514`.
//!
//! Either mismatch fails naming **both** sites with the per-side
//! difference, so a reviewer does not have to diff the two lists by
//! hand.
//!
//! ## Parser scope — and why it refuses rather than guesses
//!
//! Deliberately narrow — this is not a general SQL parser (see
//! `no_sensitive_drops.rs` for that shape when the full generality is
//! actually needed). `--` line comments are stripped first, so prose (a
//! reversal runbook spelling out the reverse `CHECK (trigger_source IN
//! (…))`, a comment quoting a `trigger_source IN ('cron', …)` predicate)
//! can neither be mistaken for the definition nor contribute members.
//! The scan then takes **whole `CHECK (…)` predicates** — balanced
//! parens, string-aware — attributes each to the table of the nearest
//! preceding `TABLE <name>` (so `CREATE TABLE public.jobs (… CHECK …)`
//! and `ALTER TABLE public.jobs ADD CONSTRAINT … CHECK (…)` both
//! resolve, and another table's `trigger_source` CHECK in the same file
//! does not), and keeps the ones about `jobs`.
//!
//! The predicate is then required to be **exactly** `trigger_source IN
//! ('a', 'b', …)` and nothing else. Anything the tokenizer does not
//! fully account for — a bolted-on disjunct, a `NOT IN`, a nested
//! predicate, a second `trigger_source` CHECK in the same migration — is
//! [`TriggerSourceCheck::Unsupported`], and the guard **fails** on it
//! rather than comparing a list it cannot prove is the whole predicate.
//!
//! That strictness is the fix for a concrete escape. The parser used to
//! find the first `trigger_source IN (` marker and stop at its closing
//! paren, so a later same-name constraint of the form
//!
//! ```text
//! CHECK (trigger_source IN (<the current nine>) OR trigger_source = 'other')
//! ```
//!
//! read back as the unchanged nine. The guard and both its mutation
//! self-tests stayed green while the column accepted a tenth value that
//! `TriggerSource::FromStr` rejects — the read-side half of exactly the
//! drift this file exists to catch. A guard that silently accepts what
//! it cannot parse is the same defect one level up.
//!
//! ## What this guard does not model, and what covers it instead
//!
//! It models ONE constraint on the column, redefined by the newest
//! migration that defines it — which is how the chain actually works
//! (`DROP CONSTRAINT jobs_trigger_source_check` + `ADD CONSTRAINT` of
//! the same name). It does not compose the column's constraints across
//! migrations, so a second, differently-named CHECK introduced by some
//! other migration is invisible here. That is not the hazard this guard
//! is for: PostgreSQL requires every CHECK on a row to pass, so the
//! accepted set is the **intersection** of them and an extra constraint
//! can only narrow it, never widen it. Widening is what makes the
//! database accept what `FromStr` refuses, and that is what the
//! strictness above closes. Narrowing — a writer's `INSERT` dying on a
//! `23514` — is closed empirically instead, by
//! `jobs_trigger_source_register_by_hash.rs`'s
//! `every_trigger_source_literal_survives_the_jobs_check`, which
//! enqueues every member of `TriggerSource::ALL` against a
//! fully-migrated database.
//!
//! Known blind spot, the same one every source scan has: a list assembled
//! through string concatenation or a `DO $$ … $$` block would not be
//! seen. The counter-assertions below are what keep a parser that has
//! stopped finding anything from reading as agreement.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use hort_domain::ports::jobs_repository::TriggerSource;

/// The column this guard is about.
const COLUMN: &str = "trigger_source";

/// The table the column lives on. A `CHECK` predicate is attributed to a
/// table before it is considered ours, so another table that one day
/// carries a column of the same name cannot contribute members.
const TABLE: &str = "jobs";

/// The source file that holds the domain side of the chain — the
/// `TriggerSource` declaration and the `trigger_source_wire!` list that
/// `ALL` and `as_str` are generated from.
const DOMAIN_SOURCE: &str = "crates/hort-domain/src/ports/jobs_repository.rs";

/// Locate the workspace root from `CARGO_MANIFEST_DIR`
/// (`<root>/crates/hort-adapters-postgres`), so two levels up is the
/// root. Mirrors how the sibling guards resolve their scan roots.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("CARGO_MANIFEST_DIR has a grandparent (the workspace root)")
        .to_path_buf()
}

fn migrations_dir() -> PathBuf {
    workspace_root().join("migrations")
}

/// Every `*.sql` file under `dir`, as `(file_name, source)` pairs. Order
/// is unspecified — [`effective_trigger_source_check`] orders by
/// migration number.
fn read_migration_sources(dir: &Path) -> Vec<(String, String)> {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    let mut out = Vec::new();
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("read_dir entry in {dir:?}: {e}"))
            .path();
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_else(|| panic!("migration file name is not UTF-8: {path:?}"))
            .to_string();
        let source = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        out.push((name, source));
    }
    out
}

// ---------------------------------------------------------------------------
// SQL source scanning.
// ---------------------------------------------------------------------------

/// Replace every `--` line comment with spaces (newlines preserved) so
/// prose cannot be mistaken for SQL. Single-quoted literals are left
/// intact — they are what the list parser collects — which is safe here
/// because no migration embeds a `--` sequence inside a trigger-source
/// literal.
fn strip_line_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        match line.find("--") {
            Some(idx) => {
                out.push_str(&line[..idx]);
                for c in line[idx..].chars() {
                    out.push(if c == '\n' { '\n' } else { ' ' });
                }
            }
            None => out.push_str(line),
        }
    }
    out
}

/// `true` when `bytes[idx..]` starts with `word` (ASCII, case-insensitive)
/// as a whole token — i.e. neither neighbour is an identifier character.
fn word_at(bytes: &[u8], idx: usize, word: &str) -> bool {
    let end = idx + word.len();
    if end > bytes.len() || !bytes[idx..end].eq_ignore_ascii_case(word.as_bytes()) {
        return false;
    }
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    if idx > 0 && ident(bytes[idx - 1]) {
        return false;
    }
    !bytes.get(end).copied().is_some_and(ident)
}

/// `true` when `text` names [`COLUMN`] as a whole word. `_trigger_source`
/// and `parent_trigger_source` are different columns and do not count.
fn mentions_column(text: &str) -> bool {
    let bytes = text.as_bytes();
    (0..bytes.len()).any(|i| word_at(bytes, i, COLUMN))
}

/// Skip ASCII whitespace from `idx`.
fn skip_ws(bytes: &[u8], mut idx: usize) -> usize {
    while bytes.get(idx).is_some_and(u8::is_ascii_whitespace) {
        idx += 1;
    }
    idx
}

/// The parenthesised body that opens at `open` (the byte just past a
/// `(`), and the offset just past its matching `)`.
///
/// Paren depth is tracked outside `'…'` string literals only, so a paren
/// inside a literal cannot close the body. A body that never closes is a
/// malformed migration or parser drift, and panics rather than being
/// silently truncated — a truncated predicate is the exact failure mode
/// this guard was escaped through once already.
fn balanced_body(stripped: &str, open: usize) -> (&str, usize) {
    let bytes = stripped.as_bytes();
    let mut depth: i32 = 1;
    let mut in_string = false;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => in_string = !in_string,
            b'(' if !in_string => depth += 1,
            b')' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return (&stripped[open..i], i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!(
        "a `CHECK (` body never closed — parser drift or a malformed migration; the scan \
         walked to EOF without finding the matching `)`. Unparsed tail: {:?}",
        &stripped[open..]
    )
}

/// Every whole `CHECK (…)` predicate in an already-comment-stripped
/// source, paired with the table its enclosing statement names.
///
/// Attribution is "the bare name after the nearest preceding whole-word
/// `TABLE`", which resolves both shapes the chain uses: the inline column
/// constraint inside `CREATE TABLE public.jobs (…)` and the `ALTER TABLE
/// public.jobs ADD CONSTRAINT … CHECK (…)` redefinition. It is what keeps
/// another table's `trigger_source` CHECK — in the same migration as a
/// `jobs` statement — from being read as ours.
fn check_predicates(stripped: &str) -> Vec<(Option<String>, &str)> {
    let bytes = stripped.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !word_at(bytes, i, "check") {
            i += 1;
            continue;
        }
        let open = skip_ws(bytes, i + "check".len());
        if bytes.get(open) != Some(&b'(') {
            i += 1;
            continue;
        }
        let (body, end) = balanced_body(stripped, open + 1);
        out.push((enclosing_table(stripped, i), body));
        i = end;
    }
    out
}

/// The bare table name of the statement enclosing byte `before`: the
/// identifier after the LAST whole-word `TABLE` that precedes it, with a
/// schema qualifier and quoting trimmed and case folded.
fn enclosing_table(stripped: &str, before: usize) -> Option<String> {
    let bytes = stripped.as_bytes();
    let mut after_keyword = None;
    for i in 0..before {
        if word_at(bytes, i, "table") {
            after_keyword = Some(i + "table".len());
        }
    }
    let mut j = after_keyword?;
    // Skip the optional `IF NOT EXISTS` / `ONLY` qualifiers between
    // `TABLE` and the table name.
    loop {
        j = skip_ws(bytes, j);
        let qualifier = ["if", "not", "exists", "only"]
            .into_iter()
            .find(|q| word_at(bytes, j, q));
        match qualifier {
            Some(q) => j += q.len(),
            None => break,
        }
    }
    let start = j;
    while bytes
        .get(j)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.' || *b == b'"')
    {
        j += 1;
    }
    if j == start {
        return None;
    }
    let raw = &stripped[start..j];
    let bare = raw.rsplit('.').next().unwrap_or(raw);
    Some(bare.trim_matches('"').to_ascii_lowercase())
}

/// A token of a `CHECK` predicate. The set is deliberately small: a
/// predicate containing anything this cannot name is one the guard
/// refuses rather than half-reads.
#[derive(Debug, PartialEq, Eq)]
enum Tok {
    /// An identifier or keyword, case-folded (`trigger_source`, `in`).
    Word(String),
    /// A `'…'` string literal's contents, with `''` unescaped.
    Str(String),
    Open,
    Close,
    Comma,
}

/// Tokenize a `CHECK` predicate body, or say what defeated it.
///
/// Anything outside the token set above — an operator, a cast, a block
/// comment, a non-ASCII byte — is an error rather than a skipped
/// character, because every character the tokenizer drops is a character
/// the shape check below cannot account for.
fn tokenize(body: &str) -> Result<Vec<Tok>, String> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        match b {
            b'(' => {
                out.push(Tok::Open);
                i += 1;
            }
            b')' => {
                out.push(Tok::Close);
                i += 1;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            b'\'' => {
                let mut lit: Vec<u8> = Vec::new();
                i += 1;
                loop {
                    match bytes.get(i) {
                        None => {
                            return Err(
                                "a string literal ran to the end of the predicate".to_string()
                            );
                        }
                        // SQL escapes an embedded quote by doubling it.
                        Some(b'\'') if bytes.get(i + 1) == Some(&b'\'') => {
                            lit.push(b'\'');
                            i += 2;
                        }
                        Some(b'\'') => {
                            i += 1;
                            break;
                        }
                        Some(c) => {
                            lit.push(*c);
                            i += 1;
                        }
                    }
                }
                let text = String::from_utf8(lit)
                    .map_err(|e| format!("a string literal is not valid UTF-8: {e}"))?;
                out.push(Tok::Str(text));
            }
            _ if b.is_ascii_alphanumeric() || b == b'_' => {
                let start = i;
                while bytes
                    .get(i)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
                {
                    i += 1;
                }
                out.push(Tok::Word(body[start..i].to_ascii_lowercase()));
            }
            other => {
                return Err(format!(
                    "unexpected byte {:?} — the predicate carries something beyond a plain \
                     IN-list",
                    other as char
                ));
            }
        }
    }
    Ok(out)
}

/// What a migration says about the `jobs.trigger_source` CHECK.
#[derive(Debug, PartialEq, Eq)]
enum TriggerSourceCheck {
    /// The migration does not constrain `jobs.trigger_source`.
    Absent,
    /// A predicate of exactly the one shape this guard can compare
    /// against the domain type: `trigger_source IN ('a', 'b', …)`, with
    /// nothing else in it. Carries the literals in file order.
    InList(Vec<String>),
    /// The migration DOES constrain `jobs.trigger_source`, with a
    /// predicate the guard cannot fully account for. Fail-closed, and
    /// carries why — comparing the part it *did* understand is how a
    /// disjunct bolted onto the IN-list once read back as the unchanged
    /// list while the column accepted a tenth value.
    Unsupported(String),
}

/// Require a predicate known to mention [`COLUMN`] to be exactly
/// `trigger_source IN ('a', 'b', …)`.
fn classify_predicate(body: &str) -> TriggerSourceCheck {
    let unsupported = |why: String| {
        TriggerSourceCheck::Unsupported(format!(
            "`CHECK ({})` is not a plain `{COLUMN} IN ('a', 'b', …)`: {why}",
            body.split_whitespace().collect::<Vec<_>>().join(" ")
        ))
    };
    let tokens = match tokenize(body) {
        Ok(tokens) => tokens,
        Err(why) => return unsupported(why),
    };
    let mut rest = tokens.iter();
    match (rest.next(), rest.next(), rest.next()) {
        (Some(Tok::Word(column)), Some(Tok::Word(keyword)), Some(Tok::Open))
            if column == COLUMN && keyword == "in" => {}
        _ => return unsupported(format!("it does not open with `{COLUMN} IN (`")),
    }
    let mut members = Vec::new();
    let mut want_literal = true;
    loop {
        match (rest.next(), want_literal) {
            (Some(Tok::Str(literal)), true) => {
                members.push(literal.clone());
                want_literal = false;
            }
            (Some(Tok::Comma), false) => want_literal = true,
            (Some(Tok::Close), false) => break,
            (Some(token), _) => {
                return unsupported(format!("unexpected {token:?} inside the IN-list"));
            }
            (None, _) => return unsupported("the IN-list never closed".to_string()),
        }
    }
    match rest.next() {
        None => TriggerSourceCheck::InList(members),
        Some(token) => unsupported(format!(
            "{token:?} follows the IN-list, so the predicate admits more than the list does"
        )),
    }
}

/// Read a migration's statement about `jobs.trigger_source`.
fn parse_trigger_source_check(source: &str) -> TriggerSourceCheck {
    let stripped = strip_line_comments(source);
    let ours: Vec<&str> = check_predicates(&stripped)
        .into_iter()
        .filter(|(table, body)| table.as_deref() == Some(TABLE) && mentions_column(body))
        .map(|(_, body)| body)
        .collect();
    match ours.as_slice() {
        [] => TriggerSourceCheck::Absent,
        [only] => classify_predicate(only),
        many => TriggerSourceCheck::Unsupported(format!(
            "{} separate CHECK predicates on `{TABLE}.{COLUMN}` in one migration — the \
             column's accepted set is their intersection, which this guard does not \
             compose, so it refuses to compare any one of them: {many:?}",
            many.len()
        )),
    }
}

/// Leading numeric prefix of a migration file name (`036_foo.sql` → 36).
fn migration_number(file_name: &str) -> Option<u32> {
    let digits: String = file_name.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// The `jobs.trigger_source` CHECK **in force**: the statement made by
/// the highest-numbered migration that makes one, as `(file_name,
/// statement)`.
///
/// Pure over `(file_name, source)` pairs so the selection rule is
/// testable without touching the filesystem. An
/// [`TriggerSourceCheck::Unsupported`] statement is a definition like any
/// other and takes part in the selection — skipping it would silently
/// fall back to an older migration's list, which is the opposite of
/// fail-closed.
fn effective_trigger_source_check(
    files: &[(String, String)],
) -> Option<(String, TriggerSourceCheck)> {
    let mut defining: Vec<(u32, &str, TriggerSourceCheck)> = files
        .iter()
        .filter_map(|(name, source)| {
            let number = migration_number(name)?;
            match parse_trigger_source_check(source) {
                TriggerSourceCheck::Absent => None,
                found => Some((number, name.as_str(), found)),
            }
        })
        .collect();
    defining.sort_by_key(|(number, _, _)| *number);
    defining
        .pop()
        .map(|(_, name, found)| (name.to_string(), found))
}

/// The lock-step comparison. Returns `None` when the two sides agree, or
/// the failure message naming **both** sites when they have drifted.
fn drift_report(
    file_name: &str,
    from_migration: &[String],
    from_type: &[String],
) -> Option<String> {
    let mut migration: Vec<String> = from_migration.to_vec();
    let mut domain: Vec<String> = from_type.to_vec();
    migration.sort();
    migration.dedup();
    domain.sort();
    domain.dedup();
    if migration == domain {
        return None;
    }
    let only_in_migration: Vec<&String> =
        migration.iter().filter(|k| !domain.contains(k)).collect();
    let only_in_domain: Vec<&String> = domain.iter().filter(|k| !migration.contains(k)).collect();
    Some(format!(
        "the `jobs.trigger_source` CHECK in force (migrations/{file_name} — the newest \
         migration that defines the constraint, i.e. the list a migrated database actually \
         enforces) and `hort_domain::ports::jobs_repository::TriggerSource::ALL` \
         (crates/hort-domain/src/ports/jobs_repository.rs) have drifted apart.\n\
         Only in migrations/{file_name}: {only_in_migration:?}\n\
         Only in TriggerSource::ALL: {only_in_domain:?}\n\
         The Rust type is the definition of the set: add the variant (with its \
         `trigger_source_wire!` entry, which is where both `ALL` and `as_str` come from) \
         first, then append a new numbered migration that redefines \
         `jobs_trigger_source_check` over the full list. Never edit an applied \
         migration in place (that changes its checksum and makes `sqlx::migrate!` reject \
         every already-migrated database)."
    ))
}

// ---------------------------------------------------------------------------
// Rust source scanning — the enum → wire-list half of the chain.
// ---------------------------------------------------------------------------

/// The lines of a brace-delimited top-level Rust item whose opening line
/// is `header`, i.e. everything between `header` and the next `}` in
/// column 0.
///
/// Line-oriented rather than brace-matching on purpose: both items this
/// reads are top-level and rustfmt-shaped, and a scan that cannot find
/// its header must fail loudly rather than return an empty body that
/// reads as agreement — which is what the `None` here becomes at every
/// call site.
fn top_level_item_body<'a>(source: &'a str, header: &str) -> Option<Vec<&'a str>> {
    let mut lines = source.lines().skip_while(|l| l.trim_end() != header);
    lines.next()?;
    let body: Vec<&str> = lines.take_while(|l| *l != "}").collect();
    Some(body)
}

/// `true` for a line that carries no declaration — blank, a `//` or
/// `///` comment, or an attribute.
fn is_rust_noise(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#[")
}

/// The variant identifiers declared by `pub enum TriggerSource`.
///
/// Every non-noise line must be a bare `Ident,` — the type is fieldless
/// and rustfmt puts one variant per line. A line of any other shape
/// panics instead of being skipped: a variant this scan silently dropped
/// would be a variant it then reported as missing from the wire list, or
/// worse, one it never looked at.
fn enum_variants(source: &str) -> Vec<String> {
    let body = top_level_item_body(source, "pub enum TriggerSource {").unwrap_or_else(|| {
        panic!(
            "`pub enum TriggerSource {{` not found in {DOMAIN_SOURCE} — the declaration moved \
             or was reshaped, and this scan must be taught the new shape rather than pass \
             vacuously"
        )
    });
    body.iter()
        .filter(|line| !is_rust_noise(line))
        .map(|line| {
            let ident = line.trim().strip_suffix(',').unwrap_or_else(|| {
                panic!(
                    "unexpected line in `pub enum TriggerSource`: {line:?} — this scan reads \
                     one bare `Variant,` per line"
                )
            });
            assert!(
                ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "unexpected variant shape in `pub enum TriggerSource`: {ident:?} — the type is \
                 fieldless and this scan reads bare identifiers"
            );
            ident.to_string()
        })
        .collect()
}

/// The `Variant => "literal"` pairs of the `trigger_source_wire!`
/// invocation — the one list `TriggerSource::ALL` and
/// `TriggerSource::as_str` are both generated from.
fn wire_list_pairs(source: &str) -> Vec<(String, String)> {
    let body = top_level_item_body(source, "trigger_source_wire! {").unwrap_or_else(|| {
        panic!(
            "`trigger_source_wire! {{` not found in {DOMAIN_SOURCE}. If `ALL` and `as_str` \
             have been unwound back into two hand-written lists, the compile-time guarantee \
             that every variant reaches `ALL` is gone with them — a variant omitted from \
             `ALL` is then unparseable by its own `FromStr` while a producer stamps it, and \
             the INSERT dies on a 23514 check_violation"
        )
    });
    body.iter()
        .filter(|line| !is_rust_noise(line))
        .map(|line| {
            let (variant, literal) = line.trim().split_once("=>").unwrap_or_else(|| {
                panic!(
                    "unexpected line in the `trigger_source_wire!` list: {line:?} — this scan \
                     reads one `Variant => \"literal\",` per line"
                )
            });
            let literal = literal
                .trim()
                .trim_end_matches(',')
                .trim()
                .trim_matches('"');
            (variant.trim().to_string(), literal.to_string())
        })
        .collect()
}

/// The enum → wire-list comparison. `None` when the two sides agree, or
/// the failure message naming both sides.
fn variant_drift_report(from_enum: &[String], from_list: &[String]) -> Option<String> {
    let mut declared: Vec<&String> = from_enum.iter().collect();
    let mut wired: Vec<&String> = from_list.iter().collect();
    declared.sort();
    wired.sort();
    if declared == wired {
        return None;
    }
    let only_declared: Vec<&&String> = declared.iter().filter(|v| !wired.contains(v)).collect();
    let only_wired: Vec<&&String> = wired.iter().filter(|v| !declared.contains(v)).collect();
    Some(format!(
        "`TriggerSource`'s variants and the `trigger_source_wire!` list have drifted apart in \
         {DOMAIN_SOURCE}.\n\
         Only in `pub enum TriggerSource`: {only_declared:?}\n\
         Only in the `trigger_source_wire!` list: {only_wired:?}\n\
         A variant the list does not name has no `ALL` entry, so `FromStr` rejects the very \
         literal its producers stamp and the INSERT dies on a 23514 check_violation. The \
         compiler normally refuses this (the generated `as_str` match is wildcard-free, so \
         the omission is `E0004`); if it compiled, `ALL` or `as_str` has been unwound out of \
         the macro and the compile-time guarantee is gone."
    ))
}

// ---------------------------------------------------------------------------
// The guard.
// ---------------------------------------------------------------------------

#[test]
fn effective_jobs_trigger_source_check_matches_the_domain_type() {
    let dir = migrations_dir();
    let files = read_migration_sources(&dir);
    let (file_name, found) = effective_trigger_source_check(&files).unwrap_or_else(|| {
        panic!(
            "no migration under {dir:?} defines a `jobs.trigger_source` CHECK list — a path \
             or parser error would otherwise let this guard pass vacuously"
        )
    });
    let TriggerSourceCheck::InList(literals) = &found else {
        panic!(
            "migrations/{file_name} is the newest migration that constrains \
             `jobs.trigger_source`, and this guard will not compare a predicate it cannot \
             fully account for — the part it understood is not the part the database \
             enforces.\n{found:?}\n\
             Express the constraint as a plain `trigger_source IN (…)`, the shape every \
             migration in the chain uses; or, if a new shape is genuinely needed, teach \
             `classify_predicate` that shape AND add the mutation self-test that proves it \
             still refuses an unparsed one."
        )
    };
    assert!(
        !literals.is_empty(),
        "parsed zero literals out of migrations/{file_name}'s `trigger_source IN (…)` list — a \
         parser error would otherwise let this guard pass vacuously"
    );

    let from_type: Vec<String> = TriggerSource::ALL
        .iter()
        .map(|v| v.as_str().to_string())
        .collect();
    if let Some(message) = drift_report(&file_name, literals, &from_type) {
        panic!("{message}");
    }
}

/// Counter-assertion: the scan really is reading a redefining migration,
/// not 009's inline list, and the literal whose absence cost the mount a
/// `500` is on both sides.
///
/// Without this, a parser that silently fell back to the first `CHECK` it
/// found would still agree with the domain type on the day the two sets
/// happened to match, and would then go quiet exactly when a later
/// redefinition landed.
#[test]
fn the_effective_list_is_a_redefining_migration_and_carries_register_by_hash() {
    let files = read_migration_sources(&migrations_dir());
    let (file_name, found) =
        effective_trigger_source_check(&files).expect("a defining migration must exist");
    let TriggerSourceCheck::InList(literals) = found else {
        panic!("the effective predicate must be a plain IN-list: {found:?}")
    };
    assert_ne!(
        file_name, "009_scan_jobs_and_findings.sql",
        "the effective list is 009's inline CHECK, which means no redefining migration was \
         found — the scan is not reading what a migrated database enforces"
    );
    assert!(
        literals.iter().any(|l| l == "register-by-hash"),
        "migrations/{file_name} must admit 'register-by-hash' — without it the OCI \
         cross-repository blob mount answers 500 whenever the gate requests a scan; got \
         {literals:?}"
    );
    assert!(
        TriggerSource::ALL
            .iter()
            .any(|v| v.as_str() == "register-by-hash"),
        "TriggerSource::ALL must carry the same literal"
    );
}

/// The other half of the chain: every `TriggerSource` variant reaches the
/// one `trigger_source_wire!` list, which is where `ALL` and `as_str`
/// both come from.
///
/// The compiler already refuses the omission — the generated `as_str`
/// match is wildcard-free, so a variant the list does not name is
/// `E0004`. This is the test that notices if that stops being true,
/// i.e. if `ALL` or `as_str` is ever unwound back into a second
/// hand-written list. That arrangement is what let a variant exist with
/// an `as_str` literal, a tier, an ordinal and a producer, and no `ALL`
/// entry: `ALL.len()`, every test iterating `ALL` and the SQL comparison
/// above all stayed green while `FromStr` rejected the literal the
/// producer stamped.
#[test]
fn every_trigger_source_variant_reaches_the_wire_list() {
    let source = fs::read_to_string(workspace_root().join(DOMAIN_SOURCE))
        .unwrap_or_else(|e| panic!("read {DOMAIN_SOURCE}: {e}"));
    let declared = enum_variants(&source);
    let pairs = wire_list_pairs(&source);
    let wired: Vec<String> = pairs.iter().map(|(v, _)| v.clone()).collect();

    // Counter-assertions first: a scan that found nothing must not read
    // as agreement, and the list it found must be the list `ALL` is
    // actually built from.
    assert_eq!(
        declared.len(),
        TriggerSource::ALL.len(),
        "the scan read {} variants out of `pub enum TriggerSource` but `ALL` has {} entries \
         — the declaration's shape changed under the scan: {declared:?}",
        declared.len(),
        TriggerSource::ALL.len()
    );
    let literals: Vec<&str> = pairs.iter().map(|(_, l)| l.as_str()).collect();
    let from_type: Vec<&str> = TriggerSource::ALL.iter().map(|v| v.as_str()).collect();
    assert_eq!(
        literals, from_type,
        "the literals this scan read out of the `trigger_source_wire!` list are not \
         `TriggerSource::ALL`'s wire strings in order — the scan is not reading the list that \
         generates `ALL`"
    );

    if let Some(message) = variant_drift_report(&declared, &wired) {
        panic!("{message}");
    }
}

/// Counter-assertion on the strictness itself: EVERY migration in the
/// chain that constrains `jobs.trigger_source` states it in a shape this
/// guard understands — 009's inline column CHECK included.
///
/// The main guard only reads the newest definer, so an `Unsupported`
/// predicate sitting in an older migration would be invisible there
/// until the day migration order changed and it became the newest. More
/// to the point: this is what says the strictness above is calibrated to
/// the chain as it actually is, rather than refusing shapes the project
/// already uses.
#[test]
fn every_migration_that_constrains_the_column_states_it_in_a_shape_we_read() {
    let files = read_migration_sources(&migrations_dir());
    let mut definers = 0;
    for (name, source) in &files {
        match parse_trigger_source_check(source) {
            TriggerSourceCheck::Absent => {}
            TriggerSourceCheck::InList(literals) => {
                definers += 1;
                assert!(
                    !literals.is_empty(),
                    "migrations/{name} parsed as an empty IN-list"
                );
            }
            TriggerSourceCheck::Unsupported(why) => panic!(
                "migrations/{name} constrains `{TABLE}.{COLUMN}` in a shape this guard \
                 refuses: {why}"
            ),
        }
    }
    assert!(
        definers >= 2,
        "expected at least 009's inline CHECK and the newest redefinition to be found; got \
         {definers} — the scan has stopped finding definitions and the guard above would \
         pass vacuously"
    );
}

// ---------------------------------------------------------------------------
// Self-tests (no I/O) — pin the selection and parsing behaviour against
// deliberately-shaped snippets so a future refactor cannot silently break
// the comparisons above into a false pass.
// ---------------------------------------------------------------------------

fn owned(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, source)| ((*name).to_string(), (*source).to_string()))
        .collect()
}

/// `InList(…)` or the panic message — self-tests read better asserting on
/// the members than on the enum.
fn in_list(source: &str) -> Vec<String> {
    match parse_trigger_source_check(source) {
        TriggerSourceCheck::InList(members) => members,
        other => panic!("expected a plain IN-list, got {other:?}"),
    }
}

/// The `Unsupported` reason, or a panic naming what was returned
/// instead.
fn unsupported_reason(source: &str) -> String {
    match parse_trigger_source_check(source) {
        TriggerSourceCheck::Unsupported(why) => why,
        other => panic!("expected the predicate to be refused, got {other:?}"),
    }
}

#[test]
fn self_check_parses_simple_list() {
    let src = "ALTER TABLE public.jobs ADD CONSTRAINT c \
               CHECK (trigger_source IN (\n 'a',\n 'b',\n 'c'\n))";
    assert_eq!(in_list(src), vec!["a".to_string(), "b".into(), "c".into()]);
}

#[test]
fn self_check_skips_line_comments() {
    let src = "ALTER TABLE public.jobs ADD CONSTRAINT c CHECK (trigger_source IN (\n\
               'a', -- comment mentioning 'z'\n    'b'\n));";
    assert_eq!(in_list(src), vec!["a".to_string(), "b".into()]);
}

#[test]
fn self_check_stops_at_the_predicates_own_close_paren() {
    let src = "ALTER TABLE public.jobs ADD CONSTRAINT c CHECK (trigger_source IN (\n\
               'a',\n    'b'\n));\n\
               CREATE INDEX i ON public.jobs (created_at);";
    assert_eq!(in_list(src), vec!["a".to_string(), "b".into()]);
}

#[test]
fn self_check_ignores_a_list_quoted_in_a_comment() {
    // A reversal runbook spells out the reverse constraint in prose. The
    // real definition follows it, and is the one that must be parsed.
    let src = "-- Reversal: ADD CONSTRAINT jobs_trigger_source_check \
               CHECK (trigger_source IN ('old-a', 'old-b'));\n\
               ALTER TABLE public.jobs ADD CONSTRAINT jobs_trigger_source_check \
               CHECK (trigger_source IN (\n'a',\n 'b'\n));";
    assert_eq!(in_list(src), vec!["a".to_string(), "b".into()]);
}

#[test]
fn self_check_does_not_match_another_columns_in_list() {
    // Whole-word matching on the column name: a longer identifier that
    // merely ends in `trigger_source` is a different column.
    let src = "CREATE TABLE public.jobs (\n parent_trigger_source text \
               CHECK (parent_trigger_source IN ('a', 'b'))\n);";
    assert_eq!(
        parse_trigger_source_check(src),
        TriggerSourceCheck::Absent,
        "`parent_trigger_source` is a different column"
    );
}

#[test]
fn self_check_another_tables_check_in_the_same_migration_is_not_ours() {
    // Per-predicate table attribution: one migration can touch `jobs`
    // and some other table that carries a column of the same name, and
    // only the `jobs` predicate is the effective list.
    let src = "ALTER TABLE public.audit_hooks ADD CONSTRAINT h \
               CHECK (trigger_source IN ('webhook'));\n\
               ALTER TABLE public.jobs ADD CONSTRAINT jobs_trigger_source_check \
               CHECK (trigger_source IN ('a', 'b'));";
    assert_eq!(in_list(src), vec!["a".to_string(), "b".into()]);
}

#[test]
fn self_check_reads_an_inline_column_check_inside_create_table() {
    // 009's shape: the constraint is declared inline on the column, so
    // the nearest preceding `TABLE` is the `CREATE TABLE` header several
    // columns above it.
    let src = "CREATE TABLE IF NOT EXISTS public.jobs (\n\
               id uuid PRIMARY KEY,\n\
               priority smallint NOT NULL CHECK (priority BETWEEN 0 AND 100),\n\
               trigger_source text NOT NULL DEFAULT 'manual' \
               CHECK (trigger_source IN ('a', 'b'))\n);";
    assert_eq!(in_list(src), vec!["a".to_string(), "b".into()]);
}

/// A `CHECK` the scan cannot attribute to a table belongs to no table,
/// and therefore not to `jobs`. Both ways attribution can come up empty:
/// no `TABLE` keyword precedes the predicate at all, and a `TABLE`
/// keyword with no name after it. The second is not valid SQL — it is
/// here because a defensive branch that nothing exercises is a branch
/// nobody knows the behaviour of.
#[test]
fn self_check_an_unattributable_check_is_not_ours() {
    assert_eq!(
        parse_trigger_source_check("CREATE DOMAIN source AS text CHECK (trigger_source IN ('a'));"),
        TriggerSourceCheck::Absent,
        "no TABLE keyword precedes the predicate, so it is not a `jobs` constraint"
    );
    assert_eq!(
        parse_trigger_source_check("ALTER TABLE (CHECK (trigger_source IN ('a')));"),
        TriggerSourceCheck::Absent,
        "a TABLE keyword with no name after it names no table"
    );
}

#[test]
fn self_check_effective_list_is_the_newest_definer() {
    // The guard must follow a redefinition: the newer migration's list is
    // the one in force, whatever the older one still says, and whatever
    // order the directory happens to be read in.
    let base = "CREATE TABLE public.jobs (trigger_source text \
                CHECK (trigger_source IN ('a', 'b')));";
    let redefinition = "ALTER TABLE public.jobs DROP CONSTRAINT jobs_trigger_source_check;\n\
                        ALTER TABLE public.jobs ADD CONSTRAINT jobs_trigger_source_check \
                        CHECK (trigger_source IN ('a', 'b', 'c'));";
    let expected = Some((
        "036_redefine.sql".to_string(),
        TriggerSourceCheck::InList(vec!["a".to_string(), "b".into(), "c".into()]),
    ));
    assert_eq!(
        effective_trigger_source_check(&owned(&[
            ("009_base.sql", base),
            ("036_redefine.sql", redefinition)
        ])),
        expected
    );
    assert_eq!(
        effective_trigger_source_check(&owned(&[
            ("036_redefine.sql", redefinition),
            ("009_base.sql", base)
        ])),
        expected
    );
}

#[test]
fn self_check_effective_list_ignores_other_tables_and_prose() {
    // Higher-numbered migrations that touch a different table's
    // `trigger_source` CHECK, or only mention `jobs` in a comment, must
    // not be mistaken for a redefinition of the effective list.
    let base = "CREATE TABLE public.jobs (trigger_source text \
                CHECK (trigger_source IN ('a', 'b')));";
    let other_table = "CREATE TABLE public.audit_hooks (trigger_source text \
                       CHECK (trigger_source IN ('webhook')));";
    let prose_only = "-- Reversal: ALTER TABLE public.jobs ADD CONSTRAINT \
                      jobs_trigger_source_check CHECK (trigger_source IN ('a'));\n\
                      CREATE INDEX i ON public.jobs (created_at);";
    let selected = effective_trigger_source_check(&owned(&[
        ("009_base.sql", base),
        ("037_other.sql", other_table),
        ("038_prose.sql", prose_only),
    ]));
    assert_eq!(
        selected,
        Some((
            "009_base.sql".to_string(),
            TriggerSourceCheck::InList(vec!["a".to_string(), "b".into()])
        ))
    );
}

/// **The mutation proof.** A literal added in only one place is red.
///
/// Both directions, because the two failures have different causes and a
/// guard that only caught one would let the other through: a literal in
/// the migration but not in the type is a row the column accepts and the
/// read paths reject; a literal in the type but not in the migration is a
/// writer whose INSERT dies on a `23514` check_violation — which is
/// exactly the defect this whole change exists to close.
#[test]
fn self_check_drift_report_catches_a_literal_added_in_only_one_place() {
    let real: Vec<String> = TriggerSource::ALL
        .iter()
        .map(|v| v.as_str().to_string())
        .collect();

    // Agreement is silent.
    assert_eq!(
        drift_report("036_x.sql", &real, &real),
        None,
        "the real pair must agree — otherwise the guard above is failing for another reason"
    );
    // ...whatever the order.
    let mut shuffled = real.clone();
    shuffled.reverse();
    assert_eq!(
        drift_report("036_x.sql", &shuffled, &real),
        None,
        "agreeing lists must not report drift, whatever their order"
    );

    // SQL-only literal.
    let mut sql_only = real.clone();
    sql_only.push("only-in-sql".to_string());
    let message = drift_report("036_x.sql", &sql_only, &real)
        .expect("a literal present only in the migration must be reported");
    assert!(
        message.contains("only-in-sql") && message.contains("TriggerSource::ALL"),
        "report must name the literal and the Rust site: {message}"
    );

    // Rust-only literal.
    let mut rust_only = real.clone();
    rust_only.push("only-in-rust".to_string());
    let message = drift_report("036_x.sql", &real, &rust_only)
        .expect("a literal present only in the type must be reported");
    assert!(
        message.contains("only-in-rust") && message.contains("migrations/036_x.sql"),
        "report must name the literal and the migration: {message}"
    );
}

/// **The mutation proof for the predicate shape** — the escape that was
/// live in this guard.
///
/// A later same-name constraint that keeps the nine-member IN-list and
/// bolts a disjunct onto it admits a tenth value. The parser used to stop
/// at the IN-list's closing paren, so it returned the unchanged nine and
/// both of this file's other mutation self-tests kept comparing a list
/// that was no longer the whole predicate: the guard stayed green while
/// the database accepted `'other'` and `TriggerSource::FromStr` rejected
/// it.
///
/// The counter-mutation is the point of the second half: with the
/// disjunct removed, the *same* snippet is understood and yields the
/// list. So the refusal is caused by the disjunct and not by the
/// surrounding shape, which is what makes this a proof rather than a
/// statement that something somewhere fails.
#[test]
fn self_check_refuses_a_predicate_with_a_disjunct_bolted_onto_the_in_list() {
    let escape = "ALTER TABLE public.jobs DROP CONSTRAINT jobs_trigger_source_check;\n\
                  ALTER TABLE public.jobs ADD CONSTRAINT jobs_trigger_source_check \
                  CHECK (trigger_source IN ('a', 'b') OR trigger_source = 'other');";
    let why = unsupported_reason(escape);
    assert!(
        why.contains("not a plain `trigger_source IN"),
        "the refusal must name the shape it required: {why}"
    );
    assert!(
        why.contains("other"),
        "the refusal must quote the predicate so a reader sees what was not parsed: {why}"
    );

    // The same escape with a disjunct the tokenizer CAN name, so the
    // shape check rather than the tokenizer is what refuses it. Both
    // paths have to reject, because which one fires depends only on
    // which characters the bolted-on clause happens to use.
    let tokenizable = "ALTER TABLE public.jobs ADD CONSTRAINT jobs_trigger_source_check \
                       CHECK (trigger_source IN ('a', 'b') OR legacy_flag);";
    let why = unsupported_reason(tokenizable);
    assert!(
        why.contains("follows the IN-list"),
        "the refusal must say the predicate admits more than the list: {why}"
    );

    // Counter-mutation: the same statement without the disjunct IS the
    // shape this guard reads.
    let clean = "ALTER TABLE public.jobs DROP CONSTRAINT jobs_trigger_source_check;\n\
                 ALTER TABLE public.jobs ADD CONSTRAINT jobs_trigger_source_check \
                 CHECK (trigger_source IN ('a', 'b'));";
    assert_eq!(in_list(clean), vec!["a".to_string(), "b".into()]);
}

/// The same refusal for every other way a predicate can admit more (or
/// less) than its IN-list. Each of these would have been read as "the
/// nine, unchanged" by a scan that keyed on the first `trigger_source IN
/// (` marker.
#[test]
fn self_check_refuses_every_other_predicate_shape() {
    let table = "ALTER TABLE public.jobs ADD CONSTRAINT jobs_trigger_source_check ";
    for (label, predicate) in [
        // Admits everything except the list — the inverse set.
        ("NOT IN", "CHECK (trigger_source NOT IN ('a', 'b'))"),
        // A conjunct narrows rather than widens, but the guard still
        // cannot say what the accepted set is from the list alone.
        (
            "AND",
            "CHECK (trigger_source IN ('a', 'b') AND length(trigger_source) < 4)",
        ),
        // The list is nested inside a larger expression.
        (
            "nested",
            "CHECK ((trigger_source IN ('a', 'b')) OR trigger_source IS NULL)",
        ),
        // No list at all — a single permitted value.
        ("equality", "CHECK (trigger_source = 'a')"),
        // An operator the tokenizer cannot name.
        ("regex", "CHECK (trigger_source ~ '^[a-z]+$')"),
        // A cast inside the list.
        ("cast", "CHECK (trigger_source IN ('a'::text, 'b'))"),
        // An empty list.
        ("empty", "CHECK (trigger_source IN ())"),
    ] {
        let source = format!("{table}{predicate};");
        let why = unsupported_reason(&source);
        assert!(
            why.contains(COLUMN),
            "the {label} refusal must name the column it is about: {why}"
        );
    }
}

/// Two `trigger_source` CHECK predicates on `jobs` in one migration: the
/// accepted set is their intersection, which this guard does not
/// compose, so it refuses rather than comparing whichever one it happened
/// to read first.
#[test]
fn self_check_refuses_two_trigger_source_checks_in_one_migration() {
    let src = "ALTER TABLE public.jobs ADD CONSTRAINT jobs_trigger_source_check \
               CHECK (trigger_source IN ('a', 'b'));\n\
               ALTER TABLE public.jobs ADD CONSTRAINT jobs_trigger_source_extra \
               CHECK (trigger_source IN ('a'));";
    let why = unsupported_reason(src);
    assert!(
        why.contains("2 separate CHECK predicates"),
        "the refusal must say how many predicates it found: {why}"
    );
}

/// A refused predicate must reach the guard, not be skipped into a
/// fallback on an older migration's list — which would be the same
/// silent-acceptance defect one level up.
#[test]
fn self_check_an_unsupported_newest_definer_is_what_gets_selected() {
    let base = "CREATE TABLE public.jobs (trigger_source text \
                CHECK (trigger_source IN ('a', 'b')));";
    let escape = "ALTER TABLE public.jobs ADD CONSTRAINT jobs_trigger_source_check \
                  CHECK (trigger_source IN ('a', 'b') OR trigger_source = 'other');";
    let (file_name, found) = effective_trigger_source_check(&owned(&[
        ("009_base.sql", base),
        ("037_escape.sql", escape),
    ]))
    .expect("the escape migration is a definer and must be selected");
    assert_eq!(file_name, "037_escape.sql");
    assert!(
        matches!(found, TriggerSourceCheck::Unsupported(_)),
        "the newest definer's refusal must survive the selection, not fall back to 009: \
         {found:?}"
    );
}

/// A `CHECK (` whose parens never close is a malformed migration. The
/// scan panics rather than truncating the predicate at EOF — a truncated
/// predicate is read as a shorter list, which is the shape of the escape
/// above.
#[test]
#[should_panic(expected = "never closed")]
fn self_check_panics_on_an_unclosed_check_body() {
    let src = "ALTER TABLE public.jobs ADD CONSTRAINT c CHECK (trigger_source IN ('a', 'b';";
    let _ = parse_trigger_source_check(src);
}

/// **The mutation proof for the enum → wire-list half.** A variant in one
/// place and not the other is red, in both directions.
///
/// The compiler refuses this today (`E0004` on the generated `as_str`
/// match), so this proves the test-time net under it still has holes in
/// the right places: the net exists for the day `ALL` or `as_str` is
/// unwound back into a hand-written list, which is the arrangement the
/// escape needed.
#[test]
fn self_check_variant_drift_report_catches_a_variant_in_only_one_place() {
    let real: Vec<String> = ["Manual", "Cron", "RegisterByHash"]
        .into_iter()
        .map(str::to_string)
        .collect();

    assert_eq!(
        variant_drift_report(&real, &real),
        None,
        "agreeing lists must be silent"
    );
    let mut shuffled = real.clone();
    shuffled.reverse();
    assert_eq!(
        variant_drift_report(&shuffled, &real),
        None,
        "agreeing lists must not report drift, whatever their order"
    );

    // Declared but never wired — the escape: the variant has an `as_str`
    // literal and a producer, and no `ALL` entry.
    let mut declared_only = real.clone();
    declared_only.push("Api".to_string());
    let message = variant_drift_report(&declared_only, &real)
        .expect("a variant missing from the wire list must be reported");
    assert!(
        message.contains("Api") && message.contains("23514"),
        "the report must name the variant and what it costs: {message}"
    );

    // Wired but not declared. Cannot compile either, but the scan says
    // which side is short rather than reporting a bare mismatch.
    let mut wired_only = real.clone();
    wired_only.push("Api".to_string());
    let message = variant_drift_report(&real, &wired_only)
        .expect("a variant missing from the enum must be reported");
    assert!(
        message.contains("Api") && message.contains("trigger_source_wire!"),
        "the report must name the variant and the list: {message}"
    );
}

/// Counter-assertion on the two Rust-source scans: each must be able to
/// fail. A scan whose header moved returns nothing, and "nothing" must
/// not read as "the two sides agree".
#[test]
#[should_panic(expected = "pub enum TriggerSource")]
fn self_check_enum_scan_panics_when_its_header_is_gone() {
    let _ = enum_variants("struct NotTheEnum;\n");
}

#[test]
#[should_panic(expected = "trigger_source_wire!")]
fn self_check_wire_list_scan_panics_when_the_macro_is_unwound() {
    let _ = wire_list_pairs("impl TriggerSource {\n    pub const ALL: [Self; 0] = [];\n}\n");
}

/// Both Rust scans read the shapes they claim to read, on snippets whose
/// expected answer is written out — so a refactor that breaks the
/// line-oriented reading fails here rather than in the file-reading
/// guard, where the cause is harder to see.
#[test]
fn self_check_rust_scans_read_their_shapes() {
    let source = "/// Doc.\n\
                  #[derive(Debug)]\n\
                  pub enum TriggerSource {\n\
                  \x20   /// `'manual'` — an operator asked.\n\
                  \x20   Manual,\n\
                  \x20   // A plain comment.\n\
                  \x20   Cron,\n\
                  }\n\
                  \n\
                  // The set, spoken once.\n\
                  trigger_source_wire! {\n\
                  \x20   Manual => \"manual\",\n\
                  \x20   Cron => \"cron\",\n\
                  }\n";
    assert_eq!(
        enum_variants(source),
        vec!["Manual".to_string(), "Cron".into()]
    );
    assert_eq!(
        wire_list_pairs(source),
        vec![
            ("Manual".to_string(), "manual".to_string()),
            ("Cron".to_string(), "cron".to_string())
        ]
    );
}
