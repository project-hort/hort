//! IP routability classification primitives.
//!
//! Charter: **zero business logic.** This crate hosts the canonical
//! [`is_routable`] predicate used by every workspace adapter that
//! needs to classify IP addresses for URL-input validation. It is
//! the single source of truth for:
//!
//! - [`is_routable`] — the canonical routability predicate. IPv4 +
//!   IPv6 with IPv4-mapped / IPv4-compatible addresses both inheriting
//!   the IPv4 filter (audit H-3 close).
//!
//! # History
//!
//! Earlier revisions of this crate also hosted a `GuardedDnsResolver`
//! (connect-time DNS guard) and `build_egress_redirect_policy`
//! (redirect-policy builder). Both were dropped during a release
//! close-out after re-evaluating the `EGRESS-1` posture: the project's
//! settled posture is to accept operator-vetted upstream / IdP / S3
//! target trust without a connect-time guard. See
//! `docs/architecture/explanation/security.md` for the per-adapter SSRF
//! posture table.
//!
//! A subsequent review-pass also dropped the `is_routable_with_allowlist`
//! and `is_ip_routable_with_allowlist` exports — both were
//! `wiremock`-loopback-allowlist helpers consumed exclusively by the
//! now-deleted connect-time DNS guard. After removal they had zero
//! external callers; the remaining tests covered the helpers
//! themselves rather than any production behaviour. Production
//! `check_ssrf_safe` (`hort-adapters-upstream-http`) calls the bare
//! `is_routable` predicate.
//!
//! What stays: the `is_routable` predicate, used by
//! `hort-adapters-upstream-http::check_ssrf_safe` for URL-input validation
//! against operator-supplied or upstream-metadata-derived URLs. That
//! validation does not depend on connect-time guarding.
//!
//! # Why a dedicated crate?
//!
//! Two adapters were found maintaining drift-prone copies of the same
//! routability check (see `docs/architecture/explanation/security.md`).
//! Hoisting the canonical implementation into one crate eliminates the
//! duplication and makes the next adapter to need this primitive a
//! one-line `path` dep away.
//!
//! # Dep budget
//!
//! Zero runtime dependencies. The crate explicitly does NOT depend on
//! `hort-domain`, `hort-app`, or any `hort-adapters-*` crate. Re-introducing
//! such a dep is a structural review block — the dep graph is the
//! enforcement mechanism for the "infrastructure-only" charter.
//!
//! Audit findings addressed: M-A2 (drift), H-3 (the IPv4-mapped IPv6
//! routability bug this crate's predicate fixes).

mod ssrf;

pub use ssrf::is_routable;
