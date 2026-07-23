#!/usr/bin/env python3
"""Generate the project-hort.de static site into site/dist/ (issue #78).

Single source of truth: this repo's Markdown. The landing page's factual
content (pillars, supported formats) is EXTRACTED from the root README.md's
sections at build time -- never hand-retyped -- so a README edit reaches the
site on the next build with no manual copying. The operator-docs section is
generated from docs/architecture/{how-to,reference,tutorial} (developer-facing
explanation/ and the ADRs are out of this cut -- see the design contract in
backlog/048).

Rendering uses scripts/site/mdconv.py, a small hand-rolled Markdown-subset
converter -- not pandoc, not a pip package, not an npm-ecosystem SSG. This
sandbox has no network/root access to install anything (verified: no pandoc,
no pip, no apt without root), and the hard rule is "dependency-light pinned
tooling ... NOT a floating-lockfile SSG" -- a ~300-line stdlib-only script
that this build (and any future contributor) can read start to finish is the
most auditable option available, at the cost of not being full CommonMark.
It covers exactly the constructs this doc corpus actually uses (checked by
grep before writing it): ATX headings, paragraphs, one level of nested lists,
fenced code (incl. ```plantuml, rendered as a plain code block per
docs/architecture/README.md's own "any PlantUML-aware viewer" guidance),
GFM tables, blockquotes, inline bold/italic/code/links, and hr. No images are
used in the in-scope docs (verified by grep), so image support is omitted.

Usage: python3 scripts/site/generate.py [--dist DIR]
Exits non-zero (via the link-check at the end) if any internal link or
heading anchor is broken.
"""

import argparse
import html
import os
import re
import shutil
import sys
from string import Template

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mdconv  # noqa: E402

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
GITHUB_BLOB = "https://github.com/project-hort/hort/blob/main/"
GITHUB_TREE = "https://github.com/project-hort/hort/tree/main/"

DOCS_ROOT = "docs/architecture"
# In-scope subtrees, per the design contract (backlog/048): how-to/ (incl.
# deploy/ + operate/), reference/, tutorial/. explanation/ + docs/adr/ +
# docs/operator/ are developer-facing / out of this cut.
IN_SCOPE_CATEGORIES = [
    ("how-to", "How-to", "how-to"),
    ("reference", "Reference", "reference"),
    ("tutorial", "Tutorial", "tutorial"),
]

SITE_TITLE = "project-hort.de"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_docs():
    """Return a list of repo-relative .md paths under the in-scope subtrees,
    sorted for deterministic output."""
    found = []
    for sub, _label, _slug in IN_SCOPE_CATEGORIES:
        base = os.path.join(REPO_ROOT, DOCS_ROOT, sub)
        for dirpath, _dirs, files in os.walk(base):
            for fn in sorted(files):
                if fn.endswith(".md"):
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, REPO_ROOT).replace(os.sep, "/")
                    found.append(rel)
    return sorted(found)


def source_to_output(src_rel):
    """docs/architecture/how-to/deploy/install.md -> docs/how-to/deploy/install.html"""
    assert src_rel.startswith(DOCS_ROOT + "/")
    tail = src_rel[len(DOCS_ROOT) + 1 :]
    assert tail.endswith(".md")
    return "docs/" + tail[:-3] + ".html"


# ---------------------------------------------------------------------------
# Link resolution
# ---------------------------------------------------------------------------


def _in_scope_prefixes():
    return tuple(f"{DOCS_ROOT}/{sub}/" for sub, _l, _s in IN_SCOPE_CATEGORIES)


def make_link_resolver(source_rel, output_rel):
    """href as written in `source_rel` (repo-relative .md file) -> href to
    emit in `output_rel` (dist-relative .html file).

    - http(s)/mailto/bare-fragment links: untouched.
    - .md links resolving inside the in-scope docs subtree: rewritten to a
      dist-relative path (computed relative to `output_rel`'s directory, so
      the whole site works from any base path / over file://).
    - every other relative link (ADRs, auth-catalog.md, explanation/,
      docs/operator/, source files under crates/ or deploy/, ...): rewritten
      to the canonical GitHub blob URL, mirroring install/index.html's
      existing convention of pointing at a full github.com/.../blob/main/...
      URL for content that isn't reproduced on the static page itself. This
      covers non-.md targets too (e.g. a how-to linking a source file or a
      Helm example directory) -- anything that isn't one of this site's own
      generated pages is, by definition, external to it.
    """

    def resolve(href):
        if href.startswith(("http://", "https://", "mailto:", "#")):
            return href
        if "#" in href:
            path_part, frag = href.split("#", 1)
        else:
            path_part, frag = href, None
        if not path_part:
            return href

        src_dir = os.path.dirname(source_rel)
        resolved = os.path.normpath(os.path.join(src_dir, path_part)).replace(
            os.sep, "/"
        )

        if path_part.endswith(".md") and resolved.startswith(_in_scope_prefixes()):
            target_output = source_to_output(resolved)
            rel = os.path.relpath(
                target_output, os.path.dirname(output_rel) or "."
            ).replace(os.sep, "/")
            return rel + (f"#{frag}" if frag else "")

        # Directory references (e.g. a Helm examples/ subtree) use GitHub's
        # /tree/ view, not /blob/ (which is file-only and 404s on a
        # directory) -- distinguished by the trailing slash the source
        # markdown already uses for directory links.
        if path_part.endswith("/"):
            gh = GITHUB_TREE + resolved + "/"
        else:
            gh = GITHUB_BLOB + resolved
        return gh + (f"#{frag}" if frag else "")

    return resolve


# ---------------------------------------------------------------------------
# Page shell (site chrome)
# ---------------------------------------------------------------------------

PAGE_SHELL = Template(
    """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$title</title>
<meta name="description" content="$description">
<link rel="stylesheet" href="$assets_href/style.css">
</head><body>
<header class="site-header">
  <a class="brand" href="$root_href/index.html">project-hort.de</a>
  <nav>
    <a href="$root_href/index.html">Home</a>
    <a href="$root_href/docs/index.html">Docs</a>
    <a href="https://github.com/project-hort/hort">GitHub</a>
    <a href="https://hort.rs">hort.rs (CLI)</a>
  </nav>
</header>
<main>
$body
</main>
<footer class="site-footer">
  <p>Hort is dual-licensed under MIT or Apache-2.0. Source, issues, and
  releases on <a href="https://github.com/project-hort/hort">GitHub</a>.
  This site is fully static -- generated from the project's own
  documentation, no server-side component.</p>
</footer>
</body></html>
"""
)


def render_page(output_rel, title, body_html, description=""):
    depth = output_rel.count("/")
    root_href = "/".join([".."] * depth) if depth else "."
    assets_href = (root_href + "/assets") if depth else "assets"
    full_title = f"{title} — {SITE_TITLE}" if title != SITE_TITLE else SITE_TITLE
    return PAGE_SHELL.substitute(
        title=html.escape(full_title, quote=False),
        description=html.escape(
            description or "Hort: a self-hostable, multi-format artifact repository.",
            quote=True,
        ),
        root_href=root_href,
        assets_href=assets_href,
        body=body_html,
    )


def write(dist, output_rel, content):
    full = os.path.join(dist, output_rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(content)


# ---------------------------------------------------------------------------
# README section extraction (landing page content -- single source of truth)
# ---------------------------------------------------------------------------


def extract_readme_sections(readme_text):
    """Split README.md into named H2 sections (plus an implicit 'intro'
    section for everything between the H1 and the first H2).

    Fence-aware: a line starting with '## ' inside a fenced code block is
    prose/example content, not a real heading, and must not split a
    section -- README.md has no such line today, but this is a build
    script that re-parses README.md on every change, and a false split
    would silently truncate the landing page's content rather than erroring.
    """
    lines = readme_text.replace("\r\n", "\n").split("\n")
    sections = {}
    current = "intro"
    buf = []
    started = False
    in_fence = False
    for line in lines:
        if re.match(r"^(`{3,}|~{3,})", line):
            in_fence = not in_fence
            if started:
                buf.append(line)
            continue
        if in_fence:
            if started:
                buf.append(line)
            continue
        if line.startswith("# ") and not started:
            started = True
            continue
        m = re.match(r"^## (.+)$", line)
        if m:
            sections[current] = "\n".join(buf).strip("\n")
            current = m.group(1).strip()
            buf = []
            continue
        if started:
            buf.append(line)
    sections[current] = "\n".join(buf).strip("\n")
    return sections


def build_landing(dist, readme_sections):
    resolver = make_link_resolver("README.md", "index.html")

    intro_html, _ = mdconv.convert(readme_sections.get("intro", ""), resolver)
    formats_html, _ = mdconv.convert(
        readme_sections.get("Supported formats", ""), resolver
    )

    body = f"""
<div class="hero">
{intro_html}
</div>

<div class="cta">
  <a class="primary" href="docs/how-to/deploy/self-contained-registry-install.html">Quickstart: self-contained install</a>
  <a class="secondary" href="docs/index.html">Browse the docs</a>
  <a class="secondary" href="https://github.com/project-hort/hort">View on GitHub</a>
</div>

<h2>Supported formats</h2>
{formats_html}
"""
    page_html = render_page(
        "index.html",
        SITE_TITLE,
        body,
        description="Hort: a secure, self-hostable, multi-format artifact repository and supply-chain registry.",
    )
    write(dist, "index.html", page_html)


# ---------------------------------------------------------------------------
# Docs pages + docs index
# ---------------------------------------------------------------------------


def humanize_filename(fn):
    base = os.path.splitext(os.path.basename(fn))[0]
    return base.replace("-", " ").replace("_", " ").title()


def build_docs(dist):
    records = []  # (src_rel, output_rel, category_sub, title)
    for src_rel in discover_docs():
        output_rel = source_to_output(src_rel)
        with open(os.path.join(REPO_ROOT, src_rel), encoding="utf-8") as fh:
            text = fh.read()
        resolver = make_link_resolver(src_rel, output_rel)
        body_html, headings = mdconv.convert(text, resolver)
        title = headings[0][2] if headings else humanize_filename(src_rel)
        title = mdconv.strip_inline_markup(title)

        rel_tail = src_rel[len(DOCS_ROOT) + 1 :]  # how-to/deploy/x.md
        sub = rel_tail.split("/")[0]  # how-to / reference / tutorial
        rest = rel_tail[len(sub) + 1 :]
        category_sub = sub
        if sub == "how-to" and "/" in rest:
            category_sub = f"how-to/{rest.split('/')[0]}"  # how-to/deploy, how-to/operate

        records.append((src_rel, output_rel, category_sub, title))

        page_html = render_page(output_rel, title, body_html)
        write(dist, output_rel, page_html)

    return records


CATEGORY_LABELS = {
    "how-to": "Configuration and operations",
    "how-to/deploy": "Deployment",
    "how-to/operate": "Operate",
    "reference": "Reference",
    "tutorial": "Tutorial",
}
CATEGORY_ORDER = ["how-to", "how-to/deploy", "how-to/operate", "reference", "tutorial"]


def build_docs_index(dist, records):
    by_category = {}
    for src_rel, output_rel, category_sub, title in records:
        by_category.setdefault(category_sub, []).append((title, output_rel))

    parts = ["<h1>Operator documentation</h1>",
             "<p>Generated from this repository's <code>docs/architecture/</code> "
             "tree (how-to, reference, tutorial) -- always in sync with the source "
             "checked into the repo.</p>",
             '<div class="docs-index">']
    for cat in CATEGORY_ORDER:
        entries = sorted(by_category.get(cat, []), key=lambda e: e[0])
        if not entries:
            continue
        parts.append(f"<h3>{CATEGORY_LABELS[cat]}</h3>")
        parts.append("<ul>")
        for title, output_rel in entries:
            rel = os.path.relpath(output_rel, "docs").replace(os.sep, "/")
            parts.append(f'<li><a href="{rel}">{html.escape(title)}</a></li>')
        parts.append("</ul>")
    parts.append("</div>")

    page_html = render_page("docs/index.html", "Documentation", "\n".join(parts))
    write(dist, "docs/index.html", page_html)


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


def copy_assets(dist):
    src = os.path.join(REPO_ROOT, "site", "assets")
    dst = os.path.join(dist, "assets")
    if os.path.exists(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dist",
        default=os.path.join(REPO_ROOT, "site", "dist"),
        help="output directory (default: site/dist)",
    )
    args = parser.parse_args()

    dist = os.path.abspath(args.dist)
    if os.path.exists(dist):
        shutil.rmtree(dist)
    os.makedirs(dist, exist_ok=True)

    with open(os.path.join(REPO_ROOT, "README.md"), encoding="utf-8") as fh:
        readme_text = fh.read()
    readme_sections = extract_readme_sections(readme_text)

    build_landing(dist, readme_sections)
    records = build_docs(dist)
    build_docs_index(dist, records)
    copy_assets(dist)

    print(f"Generated {len(records) + 2} pages into {os.path.relpath(dist, REPO_ROOT)}/")

    import linkcheck

    ok = linkcheck.check(dist)
    if not ok:
        print("Link check FAILED", file=sys.stderr)
        sys.exit(1)
    print("Link check passed.")


if __name__ == "__main__":
    main()
