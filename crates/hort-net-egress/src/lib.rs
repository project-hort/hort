//! IP routability classification primitives.
//!
//! Charter: **zero business logic.** This crate hosts the canonical
//! [`is_routable`] predicate used by every workspace adapter that
//! needs to classify IP addresses for URL-input validation. It is
//! the single source of truth for:
//!
//! - [`is_routable`] — the canonical routability predicate. IPv4 +
//!   IPv6 with IPv4-mapped / IPv4-compatible addresses both inheriting
//!   the IPv4 filter.
//!
//! # History
//!
//! Earlier revisions of this crate also hosted a `GuardedDnsResolver`
//! (connect-time DNS guard) and `build_egress_redirect_policy`
//! (redirect-policy builder). Both were dropped during a release
//! close-out after re-evaluating the `EGRESS-1` posture: a
//! shared, crate-hosted connect-time guard produced a false-positive
//! class against legitimate operator-vetted internal targets (IdP, S3
//! endpoint), so it does not belong here. Individual adapters have
//! since grown their **own**, narrowly-scoped connect-time guards where
//! their target is attacker-reachable (upstream-http's dial guard,
//! security audit finding INJ-1; webhook's create→deliver TOCTOU guard)
//! — both still call this crate's bare `is_routable`, they just apply
//! it at connect time instead of only at validation time. See
//! `docs/architecture/explanation/security.md`'s "Egress and SSRF
//! posture" section for the per-adapter table.
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
//! against operator-supplied or upstream-metadata-derived URLs, and by
//! the per-adapter connect-time guards described above.
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
//! The predicate fixes the IPv4-mapped IPv6 routability bug and eliminates
//! drift-prone copies across adapters.

mod ssrf;

pub use ssrf::is_routable;
