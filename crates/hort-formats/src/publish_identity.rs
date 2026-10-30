//! What a published archive declares about its own identity, compared with
//! the identity it is being stored under.
//!
//! # Why this module exists
//!
//! On every hosted publish path the coordinates come from channels the
//! client controls and never from the bytes: npm takes the name from the
//! route and the version from the `_attachments` key, cargo takes
//! `name`/`vers` from the publish frame, Maven takes the whole GAV from the
//! request URL. The checksum each of those paths verifies proves **byte
//! integrity, not package identity** — a tarball whose `package.json` says
//! `evil` hashes exactly as cleanly stored under `express` as under its own
//! name.
//!
//! A registry's contract is that the coordinates you publish under are the
//! coordinates you are served under. Two independent consumers depend on
//! it: a client that reads the archive's own manifest after install sees the
//! archive's declaration rather than the path it came from, and hort's own
//! scan subjects are built from the *stored* identity while the dependency
//! evidence is read from the *archive* bytes — so a divergence puts one
//! package's dependencies under another package's name in the scan record.
//!
//! # The rule
//!
//! **What the archive declares must agree with what it is stored under, or
//! the publish is refused.** Not a rewrite to the archive's identity, and
//! not a store-with-warning: a silent rewrite breaks the same contract a
//! silent accept does, just at a different end.
//!
//! The comparison is **one fact**, not an archive validation. Whether the
//! archive's file list, dependency declarations or signatures are plausible
//! is a different question with a different answer.
//!
//! # Undeclared is not divergent
//!
//! An archive that does not declare the identity at all cannot disagree
//! with it, and refusing one would reject correct artifacts over a fact the
//! format does not require them to carry — a Maven `.jar` built by anything
//! other than Maven has no `META-INF/maven/**/pom.properties`, and that is
//! not an error. [`IdentityCheck::Undeclared`] is therefore a distinct
//! outcome from [`IdentityCheck::Diverges`], and only the latter refuses.
//!
//! This is *not* the same as an archive whose declaration could not be
//! read: a format whose specification requires the manifest (npm's
//! `package/package.json`, a `.crate`'s top-level `Cargo.toml`) and does not
//! carry one has not declared nothing — it has declared something this
//! process could not reach, and an agreement that could not be established
//! is not an agreement. Those extractors return `Err`, and the publish path
//! refuses.

/// The longest fragment of archive-supplied text that may reach an error
/// message or a metric label.
///
/// Both destinations are shared with operators and automation, so a
/// coordinate recovered from artifact bytes is truncated before it leaves
/// the extractor. 200 characters is well past any legitimate package name,
/// version or Maven coordinate and well short of a log-flooding payload.
pub const DECLARED_FRAGMENT_MAX_CHARS: usize = 200;

/// Strip control characters and truncate — applied to every fragment of
/// archive-supplied text that reaches an error message or a skip record.
///
/// The identity a refusal names comes from bytes the publisher chose, so it
/// is attacker-controlled on exactly the path that reports it. Stripping
/// control bytes keeps a crafted name from forging log lines or rewriting a
/// terminal; the cap keeps it from flooding them. The refusal still names
/// both identities, which is the whole point of reporting it — a publisher
/// told only "identity mismatch" cannot tell a typo from an attack.
#[must_use]
pub fn sanitize_declared(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(DECLARED_FRAGMENT_MAX_CHARS)
        .collect()
}

/// The verdict of comparing one declared identity field against the value
/// the artifact is being stored under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityCheck {
    /// Every field the archive declared matches what it is stored under.
    Agrees,
    /// A field the archive declared names something else. Both halves
    /// travel out so the refusal can name them; `declared` has already
    /// been through [`sanitize_declared`].
    Diverges {
        /// Which coordinate disagreed, in the format's own vocabulary
        /// (`"name"`, `"version"`, `"groupId"`, …). A `&'static str` so it
        /// is safe in a metric label.
        field: &'static str,
        /// What the archive said, sanitised.
        declared: String,
        /// What the publish path is storing it under. Already through its
        /// format's grammar validator by the time this is built.
        stored: String,
    },
    /// The archive carries no declaration of this identity, so there is
    /// nothing to disagree with. The publish proceeds; `reason` says what
    /// was looked for and not found, for the log line.
    Undeclared {
        /// What the extractor looked for, as a `&'static str` so it is safe
        /// in a metric label.
        reason: &'static str,
    },
}

impl IdentityCheck {
    /// The divergence this check found, if it found one.
    ///
    /// Lets a publish path write `if let Some(d) = check.divergence() {
    /// return refusal(d) }` without matching the `Undeclared` arm it has
    /// nothing to do about.
    #[must_use]
    pub fn divergence(&self) -> Option<Divergence<'_>> {
        match self {
            Self::Diverges {
                field,
                declared,
                stored,
            } => Some(Divergence {
                field,
                declared,
                stored,
            }),
            Self::Agrees | Self::Undeclared { .. } => None,
        }
    }

    /// Compare one optional declared field against the stored value.
    ///
    /// `declared` is `None` when the archive does not carry the field —
    /// see the module docs on why that is [`Self::Undeclared`] and not a
    /// refusal. The comparison is byte-exact: on every path that reaches
    /// here both strings are produced by the same publishing tool from the
    /// same manifest, so a tolerance would only ever widen what passes.
    #[must_use]
    pub fn compare(field: &'static str, declared: Option<&str>, stored: &str) -> Self {
        Self::compare_with(field, declared, stored, str::eq)
    }

    /// [`Self::compare`] with a format-supplied equality.
    ///
    /// Used where a specification defines an escaping between the two
    /// spellings — a wheel filename escapes the version it carries — so
    /// byte equality would reject the correct spelling.
    #[must_use]
    pub fn compare_with(
        field: &'static str,
        declared: Option<&str>,
        stored: &str,
        equal: impl Fn(&str, &str) -> bool,
    ) -> Self {
        let Some(declared) = declared else {
            return Self::Undeclared { reason: field };
        };
        if equal(declared, stored) {
            Self::Agrees
        } else {
            Self::Diverges {
                field,
                declared: sanitize_declared(declared),
                stored: stored.to_string(),
            }
        }
    }

    /// The first non-[`Self::Agrees`] verdict in `checks`, or
    /// [`Self::Agrees`] when every field agreed.
    ///
    /// A [`Self::Diverges`] anywhere in the list wins over an
    /// [`Self::Undeclared`] before it: a refusal the caller must report
    /// outranks a field there was nothing to say about.
    #[must_use]
    pub fn first_divergence(checks: impl IntoIterator<Item = Self>) -> Self {
        let mut undeclared: Option<Self> = None;
        for check in checks {
            match check {
                Self::Diverges { .. } => return check,
                Self::Undeclared { .. } => undeclared = undeclared.or(Some(check)),
                Self::Agrees => {}
            }
        }
        undeclared.unwrap_or(Self::Agrees)
    }
}

/// A borrowed view of [`IdentityCheck::Diverges`], for building the
/// per-format refusal response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Divergence<'a> {
    /// Which coordinate disagreed.
    pub field: &'static str,
    /// What the archive said, sanitised.
    pub declared: &'a str,
    /// What the publish path is storing it under.
    pub stored: &'a str,
}

impl Divergence<'_> {
    /// The sentence every format's refusal is built from: the field, what
    /// the archive declared, and what it would have been stored under.
    ///
    /// Both identities are named on purpose — a publisher told only
    /// "identity mismatch" cannot tell a mis-set `version` in their build
    /// from a tampered artifact, and the two call for opposite responses.
    #[must_use]
    pub fn message(&self, archive_noun: &str) -> String {
        format!(
            "{archive_noun} declares {field} '{declared}' but is being published as '{stored}'; \
             the coordinates an artifact is published under must be the coordinates it declares",
            field = self.field,
            declared = self.declared,
            stored = self.stored,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agreeing_field_agrees() {
        assert_eq!(
            IdentityCheck::compare("name", Some("express"), "express"),
            IdentityCheck::Agrees
        );
    }

    #[test]
    fn diverging_field_carries_both_identities() {
        let check = IdentityCheck::compare("name", Some("evil"), "express");
        let divergence = check.divergence().expect("diverges");
        assert_eq!(divergence.field, "name");
        assert_eq!(divergence.declared, "evil");
        assert_eq!(divergence.stored, "express");
        assert!(divergence.message("npm tarball").contains("evil"));
        assert!(divergence.message("npm tarball").contains("express"));
    }

    #[test]
    fn absent_field_is_undeclared_not_divergent() {
        let check = IdentityCheck::compare("version", None, "1.0.0");
        assert_eq!(check, IdentityCheck::Undeclared { reason: "version" });
        assert!(check.divergence().is_none());
    }

    #[test]
    fn compare_with_honours_a_format_supplied_equality() {
        // A wheel filename escapes `+` to `_`; byte equality would reject
        // the spelling the specification prescribes.
        let check =
            IdentityCheck::compare_with("version", Some("1.0.0_local"), "1.0.0+local", |a, b| {
                a.replace('+', "_") == b.replace('+', "_")
            });
        assert_eq!(check, IdentityCheck::Agrees);
    }

    #[test]
    fn a_divergence_outranks_an_earlier_undeclared() {
        let verdict = IdentityCheck::first_divergence([
            IdentityCheck::Undeclared { reason: "groupId" },
            IdentityCheck::Diverges {
                field: "version",
                declared: "9.9.9".into(),
                stored: "1.0.0".into(),
            },
        ]);
        assert_eq!(verdict.divergence().expect("diverges").field, "version");
    }

    #[test]
    fn all_agreeing_is_agrees() {
        let verdict =
            IdentityCheck::first_divergence([IdentityCheck::Agrees, IdentityCheck::Agrees]);
        assert_eq!(verdict, IdentityCheck::Agrees);
    }

    #[test]
    fn undeclared_survives_when_nothing_diverges() {
        let verdict = IdentityCheck::first_divergence([
            IdentityCheck::Agrees,
            IdentityCheck::Undeclared { reason: "version" },
        ]);
        assert_eq!(verdict, IdentityCheck::Undeclared { reason: "version" });
    }

    #[test]
    fn sanitize_strips_control_bytes_and_truncates() {
        let crafted = format!("ev\nil\r\u{0}{}", "x".repeat(400));
        let clean = sanitize_declared(&crafted);
        assert!(!clean.chars().any(char::is_control));
        assert_eq!(clean.chars().count(), DECLARED_FRAGMENT_MAX_CHARS);
        assert!(clean.starts_with("evilxxx"));
    }

    #[test]
    fn a_crafted_declaration_cannot_forge_a_log_line_through_the_message() {
        let check = IdentityCheck::compare("name", Some("a\nFATAL: pwned"), "express");
        let divergence = check.divergence().expect("diverges");
        assert!(!divergence.message("npm tarball").contains('\n'));
    }
}
