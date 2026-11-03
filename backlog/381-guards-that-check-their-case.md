# 381 — Two guards report green without checking their case

**Issue:** #408 · **Branch:** `agent/408-guards-that-check-their-case` · single item.

Found by the third review pass over everything since `v0.17.2`. Two safeguards,
one class of defect: **green reported on a case neither one examined.** Both were
added in this cycle. Each correction is one line plus the test that proves it.

The pattern is the same in both halves and is the reason to fix them together:
a comment asserts that some other check owns the case, and nothing does.

## a) The base-image preflight keeps the first of two equal-length prefixes

`scripts/ci/base-image-preflight.sh:115` selects with
`((${#source} > ${#selected_prefix}))` — strictly greater, so when two registry
tables carry a prefix of the **same length** the **first one read** wins. The
main configuration is read before the drop-ins.

The [containers/image drop-in specification][dropin] says the opposite: a later
table with the same prefix **overrides** the earlier one. With a duplicate
prefix the preflight therefore probes the **old** location and reports
`AVAILABLE` for a registry the build will not use — a false release-readiness
signal in a release gate.

[dropin]: https://github.com/containers/image/blob/main/docs/containers-registries.conf.d.5.md

The existing longest-prefix test pins prefixes of *different* lengths, so it
does not reach the override case. The platform runner has no duplicate prefix
today, so the case is latent — but that configuration does not live in this
repository and can change without us.

## b) A protocol-relative script escapes both site checks

`scripts/site/cspcheck.py:139` skips URLs beginning `http://`, `https://`
**or `//`**, with the comment *"linkcheck owns the no-external-asset rule"*.
`scripts/site/linkcheck.py:74` rejects only `http://` and `https://`. So
`<script src="//cdn.example/app.js">` passes **both** checks, while the
published `default-src 'self'` refuses it in the browser.

Reproduced: a temporary page of that shape yields `linkcheck: True` and
`cspcheck: True`. The generated pages do not currently have this shape, so the
defect is in the safeguard against a later edit. The new external-asset test
uses `https://` only.

## Acceptance

1. (a) A later table with the same prefix wins, shown by a fixture carrying a
   duplicate prefix across two files — the resolved URL is the later table's.
2. (b) A protocol-relative `//` asset is refused, by the check whose comment
   claims the ownership. After the correction no comment claims an ownership
   that does not hold.
3. Both corrections fail before the change and pass after it — mutation, not
   assertion.
4. `CHANGELOG.md`: no entry. CI and developer tooling.
