# Legacy documentation cleanup — transition stage

The existing generated URLs must not be treated as current operator guidance.
This patch preserves all old pages and heading anchors but adds a prominent **Archived documentation** notice and `<meta name="robots" content="noindex,follow">`.
No automatic redirects are configured: many historic pages are too broad or contain implementation-specific instructions, and redirecting would break deep links or mislead readers.

## Audit counts

- developer/internal: 8
- specialized/operator-review: 17
- specialized/reference: 5
- superseded/operator: 13

## Next editorial stages

1. Review the 13 suggested successors against each source's operational tasks and migrate missing operator details. These are *suggestions*, not verified 1:1 replacements.
2. Author missing narrow operator how-tos for specialized tasks.
3. Plan separate, curated developer documentation on hort.rs; do not dump old testing or Rust implementation pages into its user-facing nav.
4. After reviewing inbound anchors and feature coverage, replace old pages with explicit server-side redirects where safe; otherwise keep archival landing pages.
5. `noindex` is a request to crawlers, not a guarantee of immediate removal. Do not add archive pages to sitemap.

The original Markdown sources remain in the repository. No production deployment was performed.

See `docs/LEGACY_DOCS_AUDIT.csv` for the per-file decisions.
