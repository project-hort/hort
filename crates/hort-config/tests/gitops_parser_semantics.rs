//! Pin the six YAML semantics the gitops corpus cannot reach, on the
//! deserialiser the control path uses.
//!
//! # Why this exists
//!
//! The corpus cannot prove what it does not contain. Re-measured on this
//! tree, **no** gitops envelope contains a merge key, an anchor, an alias
//! or a `---` document separator — all of those live in CI / Helm /
//! Ansible YAML, which is not an envelope. Those are exactly the
//! constructs where YAML implementations are known to differ, so every
//! question below needs a purpose-built document; asserting it from a
//! walk of the checked-in trees would only prove that those trees happen
//! not to contain it.
//!
//! Each question has a security direction, and each answer is measured
//! through the crate's real per-kind entry point (`parse_repository`,
//! `parse_scan_policy`, …) — the parse an operator's boot performs:
//! `serde-saphyr` under the one `Options` value `hort-config` defines.
//! Routing through the entry point rather than the deserialiser directly
//! is load-bearing twice over — it puts the crate's `Options` in the
//! loop, and it is what makes a future deserialiser or options change
//! **break these tests** instead of quietly changing their subject.
//!
//! # What these answers are, and what moved to get them
//!
//! Several rows are agreements with what this tree meant before the
//! parser swap *only because a flag was set to make them so*, and those
//! are where a silent regression would land: `strict_booleans` keeps a
//! YAML 1.1 boolean word out of a boolean field, `merge_keys:
//! AsOrdinary` keeps `<<` from becoming an expansion, and the snippet
//! settings keep operator source out of a rendered error. Drop any of
//! those from `hort-config`'s options and a test here goes red.
//!
//! Four answers are operator-visible *changes* the swap took
//! deliberately, and they are asserted as the answers they now are:
//!
//! 1. a duplicate key inside a map-typed spec field is **rejected**
//!    rather than silently applying the last value (strictly stricter,
//!    and the clearest reason to have made the move);
//! 2. `quotaBytes: 1_000` parses as `1000`;
//! 3. **numeric** scalars in an untyped position are YAML-resolved
//!    (`1_000` → `1000`, `0755` → `755.0`) rather than staying text —
//!    boolean words there still stay text, because strict booleans reach
//!    untyped positions too;
//! 4. one anchor backing a hundred or more aliases is rejected by a
//!    default budget.
//!
//! Operator-visible **message wording** is asserted too: these messages
//! reach a boot log and the apply-time linter output, so they are an
//! interface.
//!
//! # Maintaining this file
//!
//! A test here that has to be *edited* at a parser or options change is
//! the instrument working; the edit is where the behaviour change becomes
//! visible instead of silent. Two tests deliberately keep a second probe
//! at the deserialiser's **stock** options beside the entry point's
//! answer — the snippet test and the flatten test — because a claim of
//! the form "this crate's configuration is what buys you X" is vacuous
//! without the unconfigured answer next to it.
//!
//! No database, no network, no filesystem: in-memory parses only.

use std::fmt::Debug;
use std::path::Path;

use hort_config::{
    parse_lint_config, parse_permission_grant, parse_repository, parse_scan_policy,
    parse_service_account, ApiVersion, Envelope, Kind, Metadata, ParseError,
    PermissionGrantLintConfigSpec, RuleActionSpec, RuleOverridesSpec,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;

/// The parse's answer for one document, reduced to what these tests
/// compare: the value it produced, or the operator-visible message it
/// rejected with. The rendered message — not the error type — is what an
/// operator reads out of a boot log, so it is what the error-shape
/// question asserts.
type Answer<T> = Result<T, String>;

/// A per-kind production entry point, the shape
/// `DesiredState::parse_files` dispatches to.
type EntryPoint<S> = fn(&Path, &[u8]) -> Result<Envelope<S>, ParseError>;

/// Parse one document through the production entry point for its kind,
/// which is the parse an operator's boot performs.
fn through_entry_point<S>(entry_point: EntryPoint<S>, doc: &str) -> Answer<Envelope<S>>
where
    S: DeserializeOwned + PartialEq + Debug,
{
    entry_point(Path::new("pinned.yaml"), doc.as_bytes()).map_err(|e| e.to_string())
}

/// A complete `ArtifactRepository` envelope with `spec` lines appended.
/// Every field `RepositorySpec` requires is present, so a rejection is
/// always about the appended lines.
fn repository(spec_lines: &str) -> String {
    format!(
        "apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: pinned-repo
spec:
  name: Pinned
  format: npm
  type: hosted
  isPublic: false
  replicationPriority: on_demand
{spec_lines}"
    )
}

/// A complete `ScanPolicy` envelope, parameterised on the `scope` block
/// (the untagged-enum field) and on appended `spec` lines.
fn scan_policy(scope: &str, spec_lines: &str) -> String {
    format!(
        "apiVersion: project-hort.de/v1
kind: ScanPolicy
metadata:
  name: pinned-policy
spec:
  scope: {scope}
  severityThreshold: critical
  quarantineDuration: 0s
  provenanceMode: off
  scanBackends: []
{spec_lines}"
    )
}

/// A complete `ServiceAccount` envelope with the `claims` map's entries
/// appended. `claims` is the crate's only map-typed spec field, which
/// makes it the only place a YAML duplicate key is not also a duplicate
/// *struct field*.
fn service_account(claim_lines: &str) -> String {
    format!(
        "apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: pinned-sa
spec:
  federatedIdentities:
    - issuer: pinned-issuer
      claims:
{claim_lines}"
    )
}

/// A complete `PermissionGrant` envelope with the `subject` block's
/// body appended. `subject` is an internally-tagged enum carrying
/// `deny_unknown_fields`.
fn permission_grant(subject_lines: &str) -> String {
    format!(
        "apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: pinned-grant
spec:
  subject:
{subject_lines}  permission: read
"
    )
}

// =========================================================================
// 1. Duplicate keys
//
// A silent overwrite on a policy or identity document is the hazard:
// the operator reads the first value, the system applies the second.
// =========================================================================

/// A duplicate key naming a **struct field** is rejected, and the
/// rejection comes from the **YAML layer** — `duplicate_keys: Error`
/// refuses the repeated key before any Rust type is consulted. That is
/// what distinguishes it from serde's derived `Deserialize`, which only
/// reaches the fields a struct declares, and it is what lets the same
/// policy reach inside a map two tests below.
///
/// Measured through `parse_scan_policy`, which deserialises once.
/// `parse_repository` would answer from its forbidden-field pre-scan
/// instead (see the test below it).
#[test]
fn a_duplicate_struct_field_is_rejected() {
    let doc = scan_policy(
        "global",
        "  requireApproval: false\n  requireApproval: true\n",
    );

    let rejection = through_entry_point(parse_scan_policy, &doc)
        .expect_err("a duplicate `requireApproval` must not be accepted");
    assert!(
        rejection.contains("duplicate mapping key: requireApproval"),
        "the message must name the duplicated key: {rejection}"
    );
    assert!(
        !rejection.contains("duplicate field"),
        "and must name it as a repeated mapping key rather than as a struct field, which is \
         what proves the YAML layer refused it: {rejection}"
    );
}

/// The repository entry point reads the bytes **twice** — an untyped
/// forbidden-field pre-scan, then the typed envelope — and before the
/// swap those two reads had two different duplicate-key vocabularies: the
/// untyped mapping said `duplicate entry with key "isPublic"`, the
/// derived impl said `duplicate field`. Which one an operator saw
/// depended on which read tripped first.
///
/// Now both reads are the same deserialiser under one `duplicate_keys`
/// policy, so there is one verdict and one message. Pinned because an
/// entry point whose two reads of the same bytes can disagree is exactly
/// the shape a divergence hides in.
#[test]
fn a_duplicate_key_is_rejected_alike_by_both_of_the_repository_entry_points_reads() {
    let doc = repository("  isPublic: true\n");

    let rejection = through_entry_point(parse_repository, &doc)
        .expect_err("a duplicate `isPublic` must not be accepted");
    assert!(
        rejection.contains("duplicate mapping key: isPublic"),
        "one message, from whichever read saw it first: {rejection}"
    );

    // The entry point's two reads are both this deserialiser, so the
    // untyped read on its own produces the same sentence. Asserted
    // because the one-verdict claim is about the *pair* of reads: a
    // second parser entering either read is how two vocabularies came
    // back last time.
    let untyped = serde_saphyr::from_slice::<serde_json::Value>(doc.as_bytes())
        .map(|_| ())
        .expect_err("the untyped read rejects it too");
    assert!(
        untyped
            .to_string()
            .contains("duplicate mapping key: isPublic"),
        "the untyped read must reach the same verdict in the same words: {untyped}"
    );
}

/// **The strictness this crate must never lose.**
/// `FederatedIdentitySpec::claims` is a `BTreeMap`, so serde's
/// duplicate-field rejection does not apply and the YAML layer decides.
/// The claim set is the exact-match condition under which a JWT may
/// assume the service account (ADR 0018): a last-wins there applies a
/// trust policy the file does not read as, with the discarded entry
/// visible nowhere in parse, validate or the apply diff. That is what a
/// parser without `duplicate_keys: Error` does, silently, and it is the
/// reason this is the one option whose regression would be a
/// vulnerability rather than a behaviour change.
///
/// A tree carrying such a duplicate stops booting instead of applying one
/// of the two values.
#[test]
fn a_duplicate_key_in_the_claims_map_is_rejected() {
    let doc = service_account(
        "        project_path: trusted/group\n        project_path: attacker/group\n",
    );

    let rejection = through_entry_point(parse_service_account, &doc)
        .expect_err("a repeated claim key must not be accepted");
    assert!(
        rejection.contains("duplicate mapping key: project_path"),
        "the rejection must name the duplicated claim: {rejection}"
    );

    // The counter-assertion: a single claim of the same name parses, so
    // the rejection above is about the repetition and not about the key.
    let single = service_account("        project_path: trusted/group\n");
    let accepted = through_entry_point(parse_service_account, &single)
        .expect("one claim of that name is the normal case");
    let claims = &accepted.spec.federated_identities[0].claims;
    assert_eq!(
        claims.get("project_path").map(String::as_str),
        Some("trusted/group")
    );
    assert_eq!(claims.len(), 1);
}

// =========================================================================
// 2. `deny_unknown_fields` across the shapes that break it
//
// A typo'd field name must be rejected: an operator who misspells a
// knob must not be handed the default while believing they set it.
// =========================================================================

/// An unknown field is rejected in every shape the crate's specs
/// actually use: a plain struct, an untagged enum's strict variant, and
/// an internally-tagged enum. The needles are the parts of the message an
/// operator acts on — the offending field's name, or the enum that failed
/// to match. Three shapes rather than one because `deny_unknown_fields`
/// is inherited differently by each, and the untagged arm in particular
/// rejects by *failing to match a variant* rather than by naming the
/// field.
#[test]
fn an_unknown_field_is_rejected_in_every_spec_shape() {
    // Plain struct: `RepositorySpec` carries `deny_unknown_fields`.
    let plain = repository("  isPubIic: true\n");
    let plain = through_entry_point(parse_repository, &plain);

    // Untagged enum: `ScopeSpec::Repository`'s inner struct is strict,
    // and a non-matching map makes the whole untagged dispatch fail.
    let untagged = scan_policy("\n    repo: pinned-repo", "  requireApproval: false\n");
    let untagged = through_entry_point(parse_scan_policy, &untagged);

    // Internally-tagged enum: `GrantSubjectSpec` is `tag = "kind"` plus
    // `deny_unknown_fields`.
    let tagged = permission_grant("    kind: claims\n    required: [ops]\n    requred: [ops]\n");
    let tagged = through_entry_point(parse_permission_grant, &tagged);

    for (label, answer, needle) in [
        (
            "plain struct",
            plain.map(|_| ()),
            "unknown field `isPubIic`",
        ),
        (
            "untagged enum",
            untagged.map(|_| ()),
            "did not match any variant of untagged enum ScopeSpec",
        ),
        (
            "internally-tagged enum",
            tagged.map(|_| ()),
            "unknown field `requred`",
        ),
    ] {
        let rejection = answer.unwrap_err_or_panic(label);
        assert!(
            rejection.contains(needle),
            "{label}: the message must say why: {rejection}"
        );
    }
}

/// Small helper so the loop above can report which shape failed.
trait ExpectRejected {
    fn unwrap_err_or_panic(self, label: &str) -> String;
}

impl ExpectRejected for Answer<()> {
    fn unwrap_err_or_panic(self, label: &str) -> String {
        match self {
            Ok(()) => panic!("{label}: a typo'd field name was accepted"),
            Err(message) => message,
        }
    }
}

/// A struct **without** `deny_unknown_fields` ignores the typo, so the
/// operator is handed the field's default while believing they set it.
/// `PrefetchPolicy` is such a struct — a reused domain entity carrying
/// `rename_all` but no strictness — reached through
/// `RepositorySpec::prefetch_policy`, whose own strictness does not
/// extend into it. This is the standing gap the strictness rule has on
/// this tree, and it is a serde shape rather than a parser setting: no
/// `Options` value closes it.
#[test]
fn a_spec_struct_without_deny_unknown_fields_ignores_the_typo() {
    // `dephth` is a typo for `depth`, whose default is 3.
    let doc = repository("  prefetchPolicy:\n    enabled: true\n    triggers: []\n    dephth: 9\n");

    let parsed = through_entry_point(parse_repository, &doc).expect("the unknown key is ignored");
    assert_eq!(
        parsed.spec.prefetch_policy.depth, 3,
        "the typo is dropped and the default applied, with no diagnostic"
    );
}

/// `#[serde(flatten)]` **defeats** `deny_unknown_fields`: the unknown key
/// is absorbed by the flattened map rather than rejected. No spec type in
/// this crate uses `flatten` today, and this test is why it must stay
/// that way — introducing one would retire the typo rejection the
/// apply-time hard block depends on, with nothing in parse or validate
/// flagging it.
///
/// `Outer` is a local shape rather than a spec type, so there is no entry
/// point to route it through. It is measured at the deserialiser's
/// **stock** options on purpose: the gap is serde's, not a consequence of
/// anything `hort-config` chose, and a reader who finds this failing
/// after an options change should look at the derive and not at
/// `yaml.rs`.
#[test]
fn serde_flatten_defeats_deny_unknown_fields() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Inner {
        known: u32,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Outer {
        top: String,
        #[serde(flatten)]
        inner: Inner,
    }

    let doc = "top: t\nknown: 1\nunknown: 2\n";
    let parsed: Answer<Outer> = serde_saphyr::from_str(doc).map_err(|e| e.to_string());

    assert_eq!(
        parsed.as_ref(),
        Ok(&Outer {
            top: "t".into(),
            inner: Inner { known: 1 },
        }),
        "the unknown key is accepted through the flattened map — a flattened struct has no \
         unknown-field rejection to inherit"
    );
}

// =========================================================================
// 3. YAML 1.1 vs 1.2 scalar resolution
//
// The direction that matters: a document rejected before the swap being
// accepted after it, carrying a value the operator did not write.
// =========================================================================

/// **A YAML 1.1 boolean word into a `bool` field is rejected, and only
/// because `strict_booleans` is set.** `requireApproval` decides whether
/// a release needs a human: at the deserialiser's defaults
/// `requireApproval: no` resolves to `false` and answers that question
/// for the operator. The flag restricts booleans to the literals `true` /
/// `false`, which is what this tree has always required, so the words are
/// refused.
///
/// `y` / `n` are included because they are the widest form of the YAML
/// 1.1 rule and the easiest to write by accident.
#[test]
fn a_yaml_1_1_boolean_word_into_a_bool_field_is_rejected() {
    for word in ["yes", "no", "on", "off", "y", "n"] {
        let doc = scan_policy("global", &format!("  requireApproval: {word}\n"));

        let rejection = match through_entry_point(parse_scan_policy, &doc) {
            Ok(env) => panic!("`{word}` must not parse into a boolean, got {env:?}"),
            Err(message) => message,
        };
        assert!(
            rejection.contains("invalid boolean (strict mode expects true/false)"),
            "the rejection must name the rule it applied: {rejection}"
        );
    }
}

/// The same words in a **string-typed** field stay verbatim. This is what
/// keeps the checked-in trees parsing: `provenanceMode: off` appears in
/// shipped policies, and `off` there is the mode identifier, not the
/// boolean `false`.
#[test]
fn a_yaml_1_1_boolean_word_in_a_string_field_stays_verbatim() {
    let doc = scan_policy("global", "  requireApproval: false\n");

    assert_eq!(
        through_entry_point(parse_scan_policy, &doc)
            .expect("the shipped policy shape must parse")
            .spec
            .provenance_mode,
        "off",
        "a string field keeps the literal text, so the shipped shape is unaffected"
    );
}

/// A leading-zero integer is rejected into `i64` — it is **not** read as
/// octal — and kept verbatim in a string field. Explicit `0o` / `0x`
/// prefixes do resolve. The rejection is the load-bearing half: a
/// legacy-octal reading would turn a 755-byte quota into 493 with no
/// error anywhere.
#[test]
fn a_leading_zero_integer_is_rejected_into_i64_and_kept_verbatim_in_a_string() {
    let numeric = repository("  quotaBytes: 0755\n");
    assert!(
        through_entry_point(parse_repository, &numeric).is_err(),
        "a legacy-octal reading would turn 755 bytes into 493"
    );

    let textual = repository("  description: 0755\n");
    assert_eq!(
        through_entry_point(parse_repository, &textual)
            .expect("a string field accepts it")
            .spec
            .description,
        Some("0755".to_string()),
        "the leading zero survives into a string"
    );

    for (literal, value) in [("0o755", 493_i64), ("0x1f", 31)] {
        let doc = repository(&format!("  quotaBytes: {literal}\n"));
        assert_eq!(
            through_entry_point(parse_repository, &doc)
                .expect("explicit radix parses")
                .spec
                .quota_bytes,
            Some(value)
        );
    }
}

/// **A digit separator is accepted as the grouped number.**
/// `quotaBytes: 1_000` is 1000. There is no option that restores the
/// rejection this tree used to answer with, so this is one of the two
/// loosenings the parser swap took deliberately: the field is typed, the
/// operator meant 1000, and the value they get is the value the grouping
/// spells. Pinned so the acceptance is a stated answer rather than an
/// accident of a default.
#[test]
fn a_digit_separator_is_accepted_as_the_grouped_number() {
    let doc = repository("  quotaBytes: 1_000\n");

    assert_eq!(
        through_entry_point(parse_repository, &doc)
            .expect("the separator is accepted")
            .spec
            .quota_bytes,
        Some(1000),
        "the separator is stripped and the grouped number is what the field gets"
    );
}

/// `~`, `null`, `Null`, `NULL`, an empty value and an absent key all mean
/// `None` — every spelling resolves the same way, which is what lets an
/// optional spec field be written any of the six ways an operator might
/// reach for.
#[test]
fn tilde_null_an_empty_value_and_an_absent_key_all_mean_none() {
    for spelling in ["~", "null", "Null", "NULL", ""] {
        let doc = repository(&format!("  description: {spelling}\n"));
        assert_eq!(
            through_entry_point(parse_repository, &doc)
                .unwrap_or_else(|e| panic!("`{spelling}` must parse: {e}"))
                .spec
                .description,
            None,
            "`{spelling}` must mean None"
        );
    }

    let absent = repository("");
    assert_eq!(
        through_entry_point(parse_repository, &absent)
            .expect("absent key parses")
            .spec
            .description,
        None
    );
}

/// **An untyped field YAML-resolves *numeric* scalars, and only numeric
/// ones.** `licensePolicy` deserialises into a free-form
/// `serde_json::Value`, so the deserialiser — not a Rust type — decides
/// what each scalar *is*: numeric grouping is applied and a leading-zero
/// decimal becomes a float, where this tree used to keep both as text.
/// Those are value changes with no error on either side of them, which is
/// why they are asserted by value rather than by verdict.
///
/// A YAML 1.1 boolean word there stays **text**, because `strict_booleans`
/// is not a typed-position rule — it reaches untyped positions too. That
/// is the half that mattered: a bare `yes` turning into `true` in a
/// position no Rust type polices is the one that changes a decision rather
/// than a number's spelling.
///
/// Blast radius today: `ScanPolicySpec::license_policy` is the only spec
/// field that reaches `deserialize_any`, and
/// `validate_scan_policy_license_policy_not_implemented` rejects anything
/// richer than `null` / `{}` at apply. This goes live the day that
/// rejection is deleted.
#[test]
fn an_untyped_value_field_resolves_numeric_scalars_but_not_boolean_words() {
    let doc = scan_policy(
        "global",
        "  requireApproval: false
  licensePolicy:
    word: yes
    grouped: 1_000
    leadingZero: 0755
    explicitRadix: 0o755
    literal: true
",
    );
    let parsed = through_entry_point(parse_scan_policy, &doc).expect("an untyped map parses");
    let policy = &parsed.spec.license_policy;

    // Resolved rather than text — the two value changes.
    assert_eq!(
        policy["grouped"],
        serde_json::json!(1000),
        "a digit separator resolves here too, where the whole value used to stay text"
    );
    assert_eq!(
        policy["leadingZero"],
        serde_json::json!(755.0),
        "a leading-zero decimal becomes a float, not the octal 493"
    );

    // The one that decides things: a YAML 1.1 boolean word stays text,
    // because strict booleans reach an untyped position too. Were this
    // row to flip, a `yes` would become a boolean in the one place no
    // Rust type is watching.
    assert_eq!(
        policy["word"],
        serde_json::json!("yes"),
        "a bare `yes` in an untyped position must not become a boolean"
    );

    // And the spellings that were never in question.
    assert_eq!(policy["explicitRadix"], serde_json::json!(493));
    assert_eq!(policy["literal"], serde_json::json!(true));
}

// =========================================================================
// 4. Anchors, aliases, merge keys, multi-document
//
// None of these appears in a single gitops envelope today, so every
// document here is purpose-built. The hazard is twofold: a merge key
// means nothing on this tree and would mean something under the
// replacement's defaults, and an alias expansion is an amplification
// primitive.
// =========================================================================

/// **A merge key stays an unknown field, and only because `merge_keys:
/// AsOrdinary` is set.** Into a `deny_unknown_fields` spec, `<<` is
/// rejected by name. At the deserialiser's defaults it would be expanded
/// instead, and a document that fails the boot today would start
/// configuring the repository.
#[test]
fn a_merge_key_is_an_unknown_field_to_a_strict_spec() {
    let doc = repository("  <<: &shared\n    quotaBytes: 1000\n");

    let rejection = through_entry_point(parse_repository, &doc)
        .expect_err("`<<` must not parse into a strict spec");
    assert!(
        rejection.contains("unknown field `<<`"),
        "the merge key must be treated as an ordinary unknown field: {rejection}"
    );
}

/// **The silent one, and the reason `merge_keys: AsOrdinary` is not a
/// matter of taste.** A merge key into a struct without
/// `deny_unknown_fields` has no error to raise: `PrefetchPolicy` has no
/// strictness and gives every field a default, so an expansion would
/// change `depth` from 3 to 9 with the parse succeeding and nothing
/// downstream able to tell which value it got. Every other row in this
/// file fails loudly in at least one direction; this one does not fail at
/// all, it just means something else.
///
/// `AsOrdinary` makes `<<` an ordinary key here too, so it is dropped —
/// which is what this tree has always meant by it.
#[test]
fn a_merge_key_into_a_non_strict_struct_is_ignored() {
    let doc = repository(
        "  prefetchPolicy:\n    <<: &shared\n      depth: 9\n    enabled: true\n    triggers: []\n",
    );

    let parsed = through_entry_point(parse_repository, &doc).expect("the document is accepted");
    assert_eq!(
        parsed.spec.prefetch_policy.depth, 3,
        "the `<<` key is dropped and the default applied — an expansion would read 9 here, \
         with no diagnostic on either side of the difference"
    );
}

/// An anchor and an alias **without** a merge key resolve: the alias
/// carries the anchored value into the aliasing position. Asserted
/// separately from the merge-key rows because `AsOrdinary` is about `<<`
/// alone — it does not turn anchors off, and a reader could reasonably
/// expect it to.
#[test]
fn an_anchor_and_alias_without_a_merge_key_resolves() {
    let doc = repository("  description: &shared pinned text\n  storage:\n    backend: filesystem\n    path: *shared\n");

    let parsed = through_entry_point(parse_repository, &doc).expect("the alias resolves");
    assert_eq!(
        parsed.spec.storage.as_ref().map(|s| s.path.as_str()),
        Some("pinned text")
    );
    assert_eq!(parsed.spec.description.as_deref(), Some("pinned text"));
}

/// More than one document in one file is rejected, and a leading `---` is
/// accepted. The 41 files in this repository that carry `---` are all
/// non-envelope YAML, so this question is about what an operator could
/// write, not about the tree today — and the rejection is the half that
/// matters: taking the first of several documents would apply a tree the
/// operator cannot see in their own file.
#[test]
fn more_than_one_document_is_rejected_but_a_leading_separator_is_fine() {
    let one = repository("");

    let two = format!("{one}---\n{one}");
    assert!(
        through_entry_point(parse_repository, &two)
            .expect_err("two documents must not parse")
            .contains("multiple YAML documents detected"),
        "the rejection names the condition"
    );

    let separated = format!("---\n{one}");
    assert_eq!(
        through_entry_point(parse_repository, &separated)
            .expect("a leading separator parses")
            .spec,
        through_entry_point(parse_repository, &one)
            .expect("as does the same document without one")
            .spec,
        "a leading separator changes nothing about what the document means"
    );
}

/// An alias bomb is **bounded** — the parse is not an unbounded
/// expansion. The default node budget is what stops it, which is why
/// `yaml.rs` asserts the budget is still on: `budget: None` would turn
/// this document into the 10^12-node expansion it spells.
///
/// Cost, recorded so the next reader of the number is not surprised:
/// rejecting this takes a few hundred milliseconds rather than the ~15 ms
/// it used to, because a node budget has to count to its limit where
/// libyaml's alias-repetition counter short-circuited. Both are far
/// inside a boot budget. It would matter only if the gitops parse ever
/// became request-reachable.
#[test]
fn an_alias_bomb_is_bounded_and_not_expanded() {
    // Twelve levels of ten-fold self-reference: 10^12 nodes if either
    // deserialiser expanded it eagerly and without a cap.
    let mut bomb = String::from("  licensePolicy:\n    b0: &b0 [x]\n");
    for level in 1..=12 {
        let previous = level - 1;
        let refs = vec![format!("*b{previous}"); 10].join(", ");
        bomb.push_str(&format!("    b{level}: &b{level} [{refs}]\n"));
    }
    let doc = scan_policy("global", &format!("  requireApproval: false\n{bomb}"));

    assert!(
        through_entry_point(parse_scan_policy, &doc)
            .expect_err("the bomb must not be expanded")
            .contains("budget breached"),
        "the node budget is what stops it"
    );
}

/// **One anchor reused a hundred times is rejected**, by an
/// alias-to-anchor ratio the parser enforces by default: past 100
/// aliases, a single anchor may back at most ten of them. Ninety-nine
/// aliases pass, the hundredth does not. This tree used to have no such
/// limit at all.
///
/// The default is kept rather than loosened: no gitops envelope in this
/// repository uses an anchor, so no tree is affected, and relaxing a
/// bound to accommodate a document nobody has written is the wrong
/// direction. An operator-authored tree that leans on one heavily-reused
/// anchor stops booting, which is a compatibility consequence that
/// belongs in the changelog rather than in the options.
#[test]
fn one_anchor_reused_a_hundred_times_is_rejected() {
    // Aliases go inside the free-form `licensePolicy` map so the keys
    // need not be declared spec fields.
    let aliases = |count: usize| {
        let mut body = String::from("  licensePolicy:\n    seed: &reused 1\n");
        for i in 0..count {
            body.push_str(&format!("    k{i}: *reused\n"));
        }
        scan_policy("global", &format!("  requireApproval: false\n{body}"))
    };

    assert!(
        through_entry_point(parse_scan_policy, &aliases(99)).is_ok(),
        "99 aliases on one anchor are inside the limit — the boundary is where it is \
         claimed to be, not somewhere below it"
    );

    assert!(
        through_entry_point(parse_scan_policy, &aliases(100))
            .expect_err("the hundredth alias must be refused")
            .contains("AliasAnchorRatio"),
        "and the rejection names the ratio it enforced"
    );
}

// =========================================================================
// 5. Error shape
//
// These messages are what the apply-time linter surfaces into a boot
// log, so their content is an operator interface — and, as the second
// test measures, a disclosure surface.
// =========================================================================

/// An unknown field is reported with the field's name and a **line and
/// column**, and with **no serde field path** (`spec.proxy: unknown field
/// …` is what this tree used to say) and no echo of the document.
///
/// Losing the field path is a real cost on a deeply nested spec — the
/// line and column locate the key in the file, but not the path through
/// the schema that made it unknown. Asserted in both directions because
/// the absence is as much an interface as the presence: an operator's log
/// matching on the old prefix matches nothing now.
#[test]
fn an_unknown_field_error_names_a_line_and_column() {
    let doc =
        repository("  proxy:\n    upstreamUrl: https://registry.npmjs.org\n    usernme: svc\n");

    let rejection = through_entry_point(parse_repository, &doc).expect_err("the typo is rejected");
    assert!(
        rejection.contains("unknown field `usernme`") && rejection.contains("at line 13, column 5"),
        "the message names the field and locates it in the file: {rejection}"
    );
    assert!(
        !rejection.contains("spec.proxy:"),
        "and carries no serde field path: {rejection}"
    );
    assert!(
        !rejection.contains("https://registry.npmjs.org"),
        "and reproduces no part of the document: {rejection}"
    );
}

/// **The rendered error must never reproduce operator source, and that is
/// a configuration choice rather than a property of the parser.** A YAML
/// syntax error beside a `credentials:` block is the worst case: the
/// repository entry point's forbidden-field pre-scan normally rejects a
/// plaintext `proxy.credentials` *without* reading its contents, but the
/// pre-scan is itself a parse, so a syntax error defeats it and the parse
/// error is what surfaces into the boot log.
///
/// The crate's configuration does not echo the plaintext. The
/// deserialiser **at its stock options** does, verbatim, with two lines
/// of context — so the second half of this test is the counter-assertion
/// that `with_snippet` / `crop_radius` are doing work: delete them from
/// the crate's `Options` and this test goes red rather than silently
/// starting to log passwords. The stock probe is the whole point of the
/// test and does not depend on any second parser.
#[test]
fn a_syntax_error_beside_a_plaintext_value_never_echoes_it_though_the_parser_defaults_would() {
    // Written out rather than built from `repository()`: the fixture
    // declares `type: hosted`, and this document needs `type: proxy`
    // for the `proxy` block to be where an operator would put it.
    let doc = "apiVersion: project-hort.de/v1
kind: ArtifactRepository
metadata:
  name: pinned-repo
spec:
  name: Pinned
  format: npm
  type: proxy
  isPublic: false
  replicationPriority: on_demand
  proxy:
    upstreamUrl: https://registry.npmjs.org
    credentials:
      password: pinned-plaintext-value
     misindented: x
";
    let rejection =
        through_entry_point(parse_repository, doc).expect_err("the syntax error is rejected");
    assert!(
        rejection.contains("did not find expected key"),
        "the message names the syntax condition: {rejection}"
    );
    assert!(
        !rejection.contains("pinned-plaintext-value"),
        "and reproduces none of the document: {rejection}"
    );

    let at_defaults =
        serde_saphyr::from_slice::<Envelope<hort_config::RepositorySpec>>(doc.as_bytes())
            .map(|_| ())
            .expect_err("the document is rejected at the parser's defaults too");
    let at_defaults = at_defaults.to_string();
    assert!(
        at_defaults.contains("pinned-plaintext-value"),
        "at the parser's defaults the snippet reproduces the neighbouring line verbatim, which \
         is exactly what the gitops options turn off: {at_defaults}"
    );
}

/// A type mismatch names only the **expected type** (`invalid i64`) and
/// not the received value — this tree used to say `invalid type: string
/// "notanumber", expected i64`. The received value appearing nowhere is a
/// disclosure reduction on every mistyped field: a secret pasted into a
/// numeric knob used to reach the boot log inside the error sentence.
///
/// The cost is diagnostic: an operator reading `invalid i64 at line 11,
/// column 15` has to open the file to see what they wrote. Both halves
/// are asserted, because the absence of the value is the security claim.
#[test]
fn a_type_mismatch_error_names_only_the_expected_type() {
    let doc = repository("  quotaBytes: notanumber\n");

    let rejection =
        through_entry_point(parse_repository, &doc).expect_err("the mismatch is rejected");
    assert!(
        rejection.contains("invalid i64") && rejection.contains("at line 11, column 15"),
        "the sentence names the expected type and the location: {rejection}"
    );
    assert!(
        !rejection.contains("notanumber"),
        "and not the value the operator wrote: {rejection}"
    );
}

// =========================================================================
// 6. Re-emitted form
//
// The serialised shape is what the round-trip assertions in `src/` and
// the fixture comparisons stand on, so a reformat has to be a failing
// test rather than a silent diff.
// =========================================================================

/// The re-emitted form is pinned **byte for byte**, including the
/// quoting: every scalar that would otherwise resolve as a boolean word,
/// a number or null comes back double-quoted. That is what makes the
/// emitter's own output round-trip safe under any options — a bare `on`
/// re-read into an untyped position at stock options resolves to `true`,
/// and this tree's previous emitter left it bare.
///
/// The emitter has **no production call site** — nothing in `src/`
/// serialises an envelope outside tests — so this pins a shape the
/// fixtures and the `src/` round-trips depend on, not an operator
/// interface. Worth knowing before anyone treats the emitted form as one.
#[test]
fn the_re_emitted_form_is_pinned_byte_for_byte() {
    let env = Envelope {
        api_version: ApiVersion::V1,
        kind: Kind::PermissionGrantLintConfig,
        metadata: Metadata {
            name: "pinned-lint".into(),
        },
        spec: PermissionGrantLintConfigSpec {
            single_claim_allowlist: vec!["team-alpha".into(), "on".into(), "1.0".into()],
            rule_overrides: RuleOverridesSpec {
                single_claim_grant: Some(RuleActionSpec::Warn),
                direct_user_grant: None,
                wildcard_repo_non_admin: Some(RuleActionSpec::Pass),
            },
        },
    };

    let emitted = serde_saphyr::to_string(&env).expect("the emitter");

    assert_eq!(
        emitted,
        "apiVersion: project-hort.de/v1
kind: PermissionGrantLintConfig
metadata:
  name: pinned-lint
spec:
  singleClaimAllowlist:
  - team-alpha
  - \"on\"
  - \"1.0\"
  ruleOverrides:
    singleClaimGrant: warn
    wildcardRepoNonAdmin: pass
",
        "the emitted form, byte for byte: block style, two-space indent, sequence items at \
         the parent key's own indentation, and every ambiguous scalar double-quoted"
    );

    // Round-trip through the real entry point, which is stricter than a
    // bare deserialise and is what a fixture comparison stands on.
    let reparsed = parse_lint_config(Path::new("pinned.yaml"), emitted.as_bytes())
        .expect("the entry point re-reads the emitter's own output");
    assert_eq!(reparsed, env);
}

// =========================================================================
// The kind the corpus cannot reach
// =========================================================================

/// `PermissionGrantLintConfig` has **no envelope anywhere in the
/// repository**, so the corpus differential compiles an arm for it that
/// nothing reaches and its parse would have migrated unmeasured. It is a
/// cluster-wide singleton carrying the grant linter's opt-*out* surface,
/// and every checked-in tree wants the secure default that an absent
/// envelope means — so the document stays here, in a test, rather than
/// in a gitops tree where it would change what a deployment means.
///
/// Asserted twice over: through the production entry point (so the
/// per-kind post-parse checks are in the loop), and against a bare
/// deserialise of the same bytes — which is what shows the entry point
/// applies no post-parse transform on this kind, and therefore that the
/// value assertions below are about the parse itself.
#[test]
fn the_lint_config_kind_absent_from_every_tree_parses_through_the_entry_point() {
    let doc = "apiVersion: project-hort.de/v1
kind: PermissionGrantLintConfig
metadata:
  name: cluster
spec:
  singleClaimAllowlist:
    - team-alpha
    - platform-readers
  ruleOverrides:
    singleClaimGrant: warn
    wildcardRepoNonAdmin: pass
";
    let bytes = doc.as_bytes();

    let via_entry_point =
        parse_lint_config(Path::new("pinned.yaml"), bytes).expect("the entry point accepts it");
    let via_deserialiser: Envelope<PermissionGrantLintConfigSpec> =
        serde_saphyr::from_slice(bytes).expect("the deserialiser accepts it");

    assert_eq!(
        via_entry_point, via_deserialiser,
        "the entry point applies no post-parse transform on this kind, so the value \
         assertions below are about the parse and nothing else"
    );

    // The opt-out surface is what makes this kind worth measuring, so
    // assert the parsed values rather than only the equality.
    assert_eq!(
        via_entry_point.spec.single_claim_allowlist,
        vec!["team-alpha".to_string(), "platform-readers".to_string()]
    );
    assert_eq!(
        via_entry_point.spec.rule_overrides,
        RuleOverridesSpec {
            single_claim_grant: Some(RuleActionSpec::Warn),
            direct_user_grant: None,
            wildcard_repo_non_admin: Some(RuleActionSpec::Pass),
        }
    );
}
