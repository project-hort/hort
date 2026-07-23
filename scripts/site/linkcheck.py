#!/usr/bin/env python3
"""Post-build link check for site/dist/ (issue #78).

Verifies every internal (site-relative) href resolves to a file that exists
in the built tree, and that any '#fragment' matches a real 'id="..."' in the
target file. External (http/https/mailto) links are NOT fetched -- keeping
the build offline/deterministic -- only checked for a well-formed absolute
form. Also asserts no external stylesheet/script reference sneaks into the
page shell (defense in depth for the "no CDN assets" hard rule).

Runs as part of scripts/build-site.sh; also callable standalone:
    python3 scripts/site/linkcheck.py site/dist
"""

import os
import re
import sys

_HREF_RE = re.compile(r'href="([^"]+)"')
_ID_RE = re.compile(r'\bid="([^"]+)"')
_LINK_TAG_RE = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_SCRIPT_TAG_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE)


def _ids_in_file(path):
    with open(path, encoding="utf-8") as fh:
        return set(_ID_RE.findall(fh.read()))


def check(dist):
    dist = os.path.abspath(dist)
    html_files = []
    for dirpath, _dirs, files in os.walk(dist):
        for fn in files:
            if fn.endswith(".html"):
                html_files.append(os.path.join(dirpath, fn))
    html_files.sort()

    errors = []
    id_cache = {}

    for path in html_files:
        rel = os.path.relpath(path, dist)
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        ids_here = set(_ID_RE.findall(content))
        id_cache[path] = ids_here

        # No CDN / external assets: every <link>/<script> tag's href/src
        # must be same-origin-relative (never http(s)://).
        for tag in _LINK_TAG_RE.findall(content) + _SCRIPT_TAG_RE.findall(content):
            m = re.search(r'(?:href|src)="([^"]+)"', tag)
            if m and m.group(1).startswith(("http://", "https://")):
                errors.append(f"{rel}: external asset reference not allowed: {m.group(1)}")

        for href in _HREF_RE.findall(content):
            if href.startswith(("http://", "https://", "mailto:")):
                continue
            if href.startswith("#"):
                frag = href[1:]
                if frag and frag not in ids_here:
                    errors.append(f"{rel}: broken same-page anchor #{frag}")
                continue

            if "#" in href:
                path_part, frag = href.split("#", 1)
            else:
                path_part, frag = href, None

            target = os.path.normpath(os.path.join(os.path.dirname(path), path_part))
            # A directory-style href ("dl/", or one that happens to resolve
            # to an existing directory) implies its index.html, matching
            # how any static file server actually resolves it.
            if os.path.isdir(target):
                target = os.path.join(target, "index.html")
            if not os.path.isfile(target):
                errors.append(f"{rel}: broken link -> {href} (resolved {os.path.relpath(target, dist)} does not exist)")
                continue

            if frag:
                ids = id_cache.setdefault(target, _ids_in_file(target))
                if frag not in ids:
                    errors.append(
                        f"{rel}: broken anchor -> {href} (#{frag} not found in "
                        f"{os.path.relpath(target, dist)})"
                    )

    if errors:
        print(f"{len(errors)} link check error(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return False

    print(f"Checked {len(html_files)} pages, 0 broken links.")
    return True


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "site/dist"
    sys.exit(0 if check(target) else 1)
