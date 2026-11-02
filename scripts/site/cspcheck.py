#!/usr/bin/env python3
"""Post-build check: no built page may need CSP 'unsafe-inline'.

The published vhost serves both sites with

    Content-Security-Policy: default-src 'self'

(deploy/ansible/roles/website/templates/static-vhost.conf.j2). With no
'unsafe-inline' in that policy, a browser refuses every <style> block,
every src-less <script>, every style="" attribute, every on*="" event
handler and every javascript: URL in the document it just fetched. A page
carrying any of those still parses, still passes a link check and still
renders -- unstyled, with its interactive parts dead. That failure mode is
invisible to scripts/site/linkcheck.py by construction: a link checker
resolves references, it cannot evaluate a policy. So this check runs beside
it on every build.

The fix for a hit is always to move the content into a file under
site/assets/ and reference it, never to loosen the policy.

The same pass asserts the other half of that move: every <script src> and
every <link rel="stylesheet" href> on a built page must resolve to a file
that exists in the built tree. A 404 on the stylesheet a page's styling was
just moved into is the same blank page as the CSP refusal, and linkcheck's
href scan does not cover <script src> at all.

Runs as part of scripts/build-site.sh; also callable standalone:
    python3 scripts/site/cspcheck.py --dist site/dist
"""

import argparse
import os
import sys
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import generate  # noqa: E402

# The site list is the generator's own, never a second copy: a site added to
# generate.py must not be able to ship unchecked because this file was not
# updated alongside it.
SITE_KEYS = tuple(generate.BUILDERS)


class _InlineScan(HTMLParser):
    """Collect every construct on a page that needs CSP 'unsafe-inline'."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.violations = []  # (line, description)
        self.references = []  # (line, kind, url)

    def _record(self, description):
        self.violations.append((self.getpos()[0], description))

    def handle_starttag(self, tag, attrs):
        pairs = [(name.lower(), value or "") for name, value in attrs]
        names = {name for name, _v in pairs}

        if tag == "style":
            self._record("<style> block (move it into a file under site/assets/)")
        if tag == "script":
            if "src" not in names:
                self._record(
                    "<script> without src (move it into a file under site/assets/)"
                )
            else:
                for name, value in pairs:
                    if name == "src":
                        self.references.append((self.getpos()[0], "script src", value))
        if tag == "link":
            rels = {
                part.lower()
                for name, value in pairs
                if name == "rel"
                for part in value.split()
            }
            if "stylesheet" in rels:
                for name, value in pairs:
                    if name == "href":
                        self.references.append((self.getpos()[0], "stylesheet", value))

        for name, value in pairs:
            if name == "style":
                self._record(f'style="" attribute on <{tag}>')
            elif name.startswith("on"):
                self._record(f'{name}="" event-handler attribute on <{tag}>')
            if value.strip().lower().startswith("javascript:"):
                self._record(f'javascript: URL in {name}="" on <{tag}>')

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def scan_page(text):
    """(violations, references) for one page's HTML source."""
    parser = _InlineScan()
    parser.feed(text)
    parser.close()
    return parser.violations, parser.references


def _html_files(site_dist):
    found = []
    for dirpath, _dirs, files in os.walk(site_dist):
        for fn in files:
            if fn.endswith(".html"):
                found.append(os.path.join(dirpath, fn))
    return sorted(found)


def check(site_dist):
    """Scan one built site. Prints a per-site count; returns True when clean."""
    site_dist = os.path.abspath(site_dist)
    label = os.path.basename(site_dist)
    pages = _html_files(site_dist)
    errors = []

    # A pass with nothing to scan proves nothing -- fail rather than report
    # a vacuous zero.
    if not pages:
        print(
            f"cspcheck: no pages found under {site_dist} -- nothing was checked",
            file=sys.stderr,
        )
        return False

    inline_count = 0
    for path in pages:
        rel = os.path.relpath(path, site_dist)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        violations, references = scan_page(text)
        inline_count += len(violations)
        for line, description in violations:
            errors.append(f"{label}/{rel}:{line}: {description}")
        for line, kind, url in references:
            if url.startswith(("http://", "https://", "//")):
                continue  # linkcheck owns the no-external-asset rule
            target = os.path.normpath(
                os.path.join(os.path.dirname(path), url.split("#", 1)[0])
            )
            if not os.path.isfile(target):
                errors.append(
                    f"{label}/{rel}:{line}: {kind} does not exist in the built "
                    f"tree: {url}"
                )

    if errors:
        print(
            f"cspcheck: {len(errors)} problem(s) in {label} "
            f"({inline_count} need CSP 'unsafe-inline'):",
            file=sys.stderr,
        )
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return False

    print(
        f"Checked {len(pages)} pages in {label}, 0 inline style/script, "
        "every asset reference resolves."
    )
    return True


def main(argv=None):
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--site",
        choices=list(SITE_KEYS),
        action="append",
        help="check only this site (repeatable); default: check both",
    )
    parser.add_argument(
        "--dist",
        default=os.path.join(repo_root, "site", "dist"),
        help="output root (default: site/dist/); each site lives in <dist>/<fqdn>/",
    )
    args, _unknown = parser.parse_known_args(argv)

    sites = args.site or list(SITE_KEYS)
    ok = True
    for site_key in sites:
        if not check(os.path.join(os.path.abspath(args.dist), site_key)):
            ok = False
    if not ok:
        print(
            "CSP inline-content check FAILED -- the published policy is "
            "default-src 'self'; move the content into site/assets/ and "
            "reference it.",
            file=sys.stderr,
        )
        return 1
    print(f"CSP inline-content check passed for {len(sites)} site(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
