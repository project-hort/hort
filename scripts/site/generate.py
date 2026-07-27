#!/usr/bin/env python3
"""Generate hort's static sites into site/dist/<fqdn>/ (issues #78, #77).

Single source of truth: this repo's Markdown (plus, for hort.rs, the
committed installer scripts). Two sites share one pipeline:

- **project-hort.de** — landing (extracted from README.md) + operator docs
  generated from docs/architecture/{how-to,reference,tutorial}.
- **hort.rs** — CLI landing (extracted from docs/architecture/how-to/
  install-cli.md) + CLI user docs (install-cli.md, cli-completions.md,
  using-hort-cli-with-admin-ops.md, crates/hort-cli/README.md) + the
  installer scripts (install-cli.sh, install-cli.ps1, cosign.pin) copied
  verbatim to their exact published apex paths + a placeholder dl/index.html
  (the real permanent version archive at dl/<tag>/ is populated separately,
  host-side, by scripts/populate-dl-archive.sh -- see that script and
  deploy/ansible/roles/website/ for why it is NOT part of this build).

A link from one site's docs to content that's in scope for the OTHER site
resolves to that site's live absolute URL (e.g. a hort-cli doc linking
declare-gitops-config.md resolves to https://project-hort.de/docs/how-to/
declare-gitops-config.html) rather than falling through to GitHub -- both
sites are built by the same pipeline, so it knows what the sibling site
actually serves.

Rendering uses scripts/site/mdconv.py, a small hand-rolled Markdown-subset
converter -- not pandoc, not a pip package, not an npm-ecosystem SSG. This
sandbox has no network/root access to install anything (verified: no pandoc,
no pip, no apt without root), and the hard rule is "dependency-light pinned
tooling ... NOT a floating-lockfile SSG" -- a small stdlib-only script that
this build (and any future contributor) can read start to finish is the most
auditable option available, at the cost of not being full CommonMark. It
covers exactly the constructs the source corpus actually uses (checked by
grep before writing it): ATX headings, paragraphs, one level of nested
lists, fenced code, GFM tables, blockquotes, inline bold/italic/code/links,
and hr. No images are used in any in-scope doc (verified by grep), so image
support is omitted.

Usage: python3 scripts/site/generate.py [--site {project-hort.de,hort.rs}] [--dist DIR]
  (default: builds both sites)
Exits non-zero (via the link-check at the end) if any internal link or
heading anchor is broken, in either site.
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
PROJECT_HORT_DE = "project-hort.de"
HORT_RS = "hort.rs"

# ---------------------------------------------------------------------------
# project-hort.de: in-scope subtrees, per the design contract (backlog/048):
# how-to/ (incl. deploy/ + operate/), reference/, tutorial/. explanation/ +
# docs/adr/ + docs/operator/ are developer-facing / out of this cut.
# ---------------------------------------------------------------------------
IN_SCOPE_CATEGORIES = [
    ("how-to", "How-to", "how-to"),
    ("reference", "Reference", "reference"),
    ("tutorial", "Tutorial", "tutorial"),
]


def _in_scope_prefixes():
    return tuple(f"{DOCS_ROOT}/{sub}/" for sub, _l, _s in IN_SCOPE_CATEGORIES)


def discover_project_hort_de_docs():
    """Repo-relative .md paths under project-hort.de's in-scope subtrees."""
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


def project_hort_de_source_to_output(src_rel):
    """docs/architecture/how-to/deploy/install.md -> docs/how-to/deploy/install.html"""
    assert src_rel.startswith(DOCS_ROOT + "/")
    tail = src_rel[len(DOCS_ROOT) + 1 :]
    assert tail.endswith(".md")
    return "docs/" + tail[:-3] + ".html"


def project_hort_de_in_scope(resolved):
    return resolved.startswith(_in_scope_prefixes())


# ---------------------------------------------------------------------------
# hort.rs: explicit doc list (issue #77) -- four named sources, not a
# subtree walk. crates/hort-cli/README.md lives outside docs/architecture/
# entirely, so this site's discovery is a fixed list, not a directory walk.
# ---------------------------------------------------------------------------
HORT_RS_DOCS = [
    (f"{DOCS_ROOT}/how-to/install-cli.md", "docs/install-cli.html"),
    (f"{DOCS_ROOT}/how-to/cli-completions.md", "docs/cli-completions.html"),
    (
        f"{DOCS_ROOT}/how-to/using-hort-cli-with-admin-ops.md",
        "docs/using-hort-cli-with-admin-ops.html",
    ),
    ("crates/hort-cli/README.md", "docs/cli-reference.html"),
]
HORT_RS_DOC_MAP = dict(HORT_RS_DOCS)


def hort_rs_in_scope(resolved):
    return resolved in HORT_RS_DOC_MAP


def hort_rs_source_to_output(resolved):
    return HORT_RS_DOC_MAP[resolved]


# ---------------------------------------------------------------------------
# Site registry -- drives cross-site link resolution and page chrome.
# ---------------------------------------------------------------------------

SITES = {
    PROJECT_HORT_DE: {
        "base_url": f"https://{PROJECT_HORT_DE}",
        "brand": PROJECT_HORT_DE,
        "in_scope": project_hort_de_in_scope,
        "to_output": project_hort_de_source_to_output,
        "nav": [(f"https://{HORT_RS}", "hort.rs (CLI)")],
        "default_description": "Hort: a self-hostable, multi-format artifact repository.",
    },
    HORT_RS: {
        "base_url": f"https://{HORT_RS}",
        "brand": HORT_RS,
        "in_scope": hort_rs_in_scope,
        "to_output": hort_rs_source_to_output,
        "nav": [
            ("dl/", "Downloads"),
            (f"https://{PROJECT_HORT_DE}", "project-hort.de"),
        ],
        "default_description": "Install hort-cli, the Hort command-line client.",
    },
}


# ---------------------------------------------------------------------------
# Link resolution
# ---------------------------------------------------------------------------


def make_link_resolver(site_key, source_rel, output_rel):
    """href as written in `source_rel` (repo-relative .md file) -> href to
    emit in `output_rel` (dist-relative .html file, within `site_key`'s own
    dist root).

    - http(s)/mailto/bare-fragment links: untouched.
    - .md links resolving inside THIS site's own scope: rewritten to a
      dist-relative path (computed relative to `output_rel`'s directory, so
      each site works from any base path / over file://).
    - .md links resolving inside the OTHER known site's scope: rewritten to
      that site's live absolute URL -- both sites are built by the same
      pipeline, so it knows what the sibling site actually serves, and a
      real rendered page beats bouncing the reader to raw GitHub markdown.
    - every other relative link (ADRs, auth-catalog.md, explanation/,
      docs/operator/, source files under crates/ or deploy/, ...): rewritten
      to the canonical GitHub blob/tree URL, mirroring install/index.html's
      existing convention of pointing at a full github.com/.../blob/main/...
      URL for content that isn't reproduced on either static site.
    """
    current = SITES[site_key]

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

        if path_part.endswith(".md") and current["in_scope"](resolved):
            target_output = current["to_output"](resolved)
            rel = os.path.relpath(
                target_output, os.path.dirname(output_rel) or "."
            ).replace(os.sep, "/")
            return rel + (f"#{frag}" if frag else "")

        if path_part.endswith(".md"):
            for other_key, other in SITES.items():
                if other_key == site_key:
                    continue
                if other["in_scope"](resolved):
                    target_output = other["to_output"](resolved)
                    return (
                        other["base_url"] + "/" + target_output
                        + (f"#{frag}" if frag else "")
                    )

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
  <a class="brand" href="$root_href/index.html">$brand</a>
  <nav>
    <a href="$root_href/index.html">Home</a>
    <a href="$root_href/docs/index.html">Docs</a>
$nav_extra
    <a href="https://github.com/project-hort/hort">GitHub</a>
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


def render_page(site_key, output_rel, title, body_html, description=""):
    site = SITES[site_key]
    depth = output_rel.count("/")
    root_href = "/".join([".."] * depth) if depth else "."
    assets_href = (root_href + "/assets") if depth else "assets"
    full_title = (
        f"{title} — {site['brand']}" if title != site["brand"] else site["brand"]
    )
    def nav_href(href):
        # Internal nav targets (e.g. "dl/") are root-relative -- they must
        # be re-anchored with root_href on every page, not just the ones at
        # depth 0, where a bare relative href would happen to work by
        # coincidence.
        if href.startswith(("http://", "https://")):
            return href
        return f"{root_href}/{href}"

    nav_extra = "\n".join(
        f'    <a href="{nav_href(href)}">{label}</a>' for href, label in site["nav"]
    )
    return PAGE_SHELL.substitute(
        title=html.escape(full_title, quote=False),
        description=html.escape(description or site["default_description"], quote=True),
        root_href=root_href,
        assets_href=assets_href,
        brand=html.escape(site["brand"], quote=False),
        nav_extra=nav_extra,
        body=body_html,
    )


def write(dist, output_rel, content):
    full = os.path.join(dist, output_rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(content)


# ---------------------------------------------------------------------------
# Markdown section extraction (landing page content -- single source of
# truth for both sites' landing pages).
# ---------------------------------------------------------------------------


def extract_md_sections(md_text):
    """Split a Markdown document into named H2 sections (plus an implicit
    'intro' section for everything between the H1 and the first H2).

    Fence-aware: a line starting with '## ' inside a fenced code block is
    prose/example content, not a real heading, and must not split a
    section.
    """
    lines = md_text.replace("\r\n", "\n").split("\n")
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


# ---------------------------------------------------------------------------
# project-hort.de: landing + docs + docs index
# ---------------------------------------------------------------------------


def build_project_hort_de_landing(dist, readme_sections):
    resolver = make_link_resolver(PROJECT_HORT_DE, "README.md", "index.html")

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
        PROJECT_HORT_DE,
        "index.html",
        PROJECT_HORT_DE,
        body,
        description="Hort: a secure, self-hostable, multi-format artifact repository and supply-chain registry.",
    )
    write(dist, "index.html", page_html)


def humanize_filename(fn):
    base = os.path.splitext(os.path.basename(fn))[0]
    return base.replace("-", " ").replace("_", " ").title()


def build_project_hort_de_docs(dist):
    records = []  # (src_rel, output_rel, category_sub, title)
    for src_rel in discover_project_hort_de_docs():
        output_rel = project_hort_de_source_to_output(src_rel)
        with open(os.path.join(REPO_ROOT, src_rel), encoding="utf-8") as fh:
            text = fh.read()
        resolver = make_link_resolver(PROJECT_HORT_DE, src_rel, output_rel)
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

        page_html = render_page(PROJECT_HORT_DE, output_rel, title, body_html)
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


def build_project_hort_de_docs_index(dist, records):
    by_category = {}
    for src_rel, output_rel, category_sub, title in records:
        by_category.setdefault(category_sub, []).append((title, output_rel))

    parts = [
        "<h1>Operator documentation</h1>",
        "<p>Generated from this repository's <code>docs/architecture/</code> "
        "tree (how-to, reference, tutorial) -- always in sync with the source "
        "checked into the repo.</p>",
        '<div class="docs-index">',
    ]
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

    page_html = render_page(
        PROJECT_HORT_DE, "docs/index.html", "Documentation", "\n".join(parts)
    )
    write(dist, "docs/index.html", page_html)


def build_project_hort_de(dist):
    with open(os.path.join(REPO_ROOT, "README.md"), encoding="utf-8") as fh:
        readme_text = fh.read()
    readme_sections = extract_md_sections(readme_text)

    build_project_hort_de_landing(dist, readme_sections)
    records = build_project_hort_de_docs(dist)
    build_project_hort_de_docs_index(dist, records)
    copy_assets(dist)
    return len(records) + 2


# ---------------------------------------------------------------------------
# hort.rs: CLI landing + user docs + docs index + apex installer files +
# dl/ placeholder
# ---------------------------------------------------------------------------

# The exact cosign verify-blob parameters install-cli.sh uses (also pinned
# in install/README.md's "Verify parameters" table) -- the manual-download
# path below must use the identical values or a manually-verified binary
# could pass a check the real installer would have rejected.
HORT_RS_COSIGN_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
HORT_RS_COSIGN_IDENTITY_REGEXP = "https://github.com/project-hort/.*"


def build_hort_rs_landing(dist):
    with open(
        os.path.join(REPO_ROOT, DOCS_ROOT, "how-to", "install-cli.md"),
        encoding="utf-8",
    ) as fh:
        install_cli_text = fh.read()
    sections = extract_md_sections(install_cli_text)
    resolver = make_link_resolver(
        HORT_RS, f"{DOCS_ROOT}/how-to/install-cli.md", "index.html"
    )

    intro_html, _ = mdconv.convert(sections.get("intro", ""), resolver)
    linux_html, _ = mdconv.convert(sections.get("Linux / macOS", ""), resolver)
    windows_html, _ = mdconv.convert(
        sections.get("Windows (PowerShell)", ""), resolver
    )
    guarantee_html, _ = mdconv.convert(
        sections.get("What the installer guarantees", ""), resolver
    )

    # Manual-download & verify: hand-authored -- this exact recipe (browse
    # dl/<tag>/, verify locally) isn't documented anywhere in the four
    # source files (they only cover the automated installer script), so it
    # can't be extracted the way the sections above are. Uses the identical
    # cosign parameters install-cli.sh itself verifies against.
    manual_html = f"""
<p>Prefer to fetch and verify a binary yourself? Every release is archived
permanently at <a href="dl/">/dl/</a>, keyed by tag. Pick your platform's
archive (e.g. <code>hort-cli-linux-amd64.tar.gz</code>) plus its
<code>.sha256</code> and <code>.bundle</code> sidecars, then:</p>
<pre><code># checksum
sha256sum -c hort-cli-&lt;platform&gt;.tar.gz.sha256

# keyless cosign signature (same identity the installer itself checks)
cosign verify-blob \\
  --certificate-oidc-issuer={HORT_RS_COSIGN_OIDC_ISSUER} \\
  --certificate-identity-regexp='{HORT_RS_COSIGN_IDENTITY_REGEXP}' \\
  --bundle hort-cli-&lt;platform&gt;.tar.gz.bundle \\
  hort-cli-&lt;platform&gt;.tar.gz</code></pre>
<p>Nothing here differs from the one-liner above -- it runs the identical
checks. <code>dl/</code> exists for pinning an exact historical version,
air-gapped installs, and auditing.</p>
"""

    body = f"""
<div class="hero">
{intro_html}
</div>

<h2>Install</h2>
<h3>Linux / macOS</h3>
{linux_html}
<h3>Windows (PowerShell)</h3>
{windows_html}

<div class="cta">
  <a class="secondary" href="docs/index.html">CLI docs</a>
  <a class="secondary" href="dl/">Browse all versions</a>
  <a class="secondary" href="https://github.com/project-hort/hort">View on GitHub</a>
</div>

<h2>Fail-closed by design</h2>
{guarantee_html}

<h2>Manual download &amp; verify</h2>
{manual_html}
"""
    page_html = render_page(
        HORT_RS,
        "index.html",
        HORT_RS,
        body,
        description="Install hort-cli: fail-closed, cosign-verified, single-command install for Linux, macOS, and Windows.",
    )
    write(dist, "index.html", page_html)


def build_hort_rs_docs(dist):
    records = []  # (src_rel, output_rel, title)
    for src_rel, output_rel in HORT_RS_DOCS:
        with open(os.path.join(REPO_ROOT, src_rel), encoding="utf-8") as fh:
            text = fh.read()
        resolver = make_link_resolver(HORT_RS, src_rel, output_rel)
        body_html, headings = mdconv.convert(text, resolver)
        title = headings[0][2] if headings else humanize_filename(src_rel)
        title = mdconv.strip_inline_markup(title)
        records.append((src_rel, output_rel, title))
        page_html = render_page(HORT_RS, output_rel, title, body_html)
        write(dist, output_rel, page_html)
    return records


def build_hort_rs_docs_index(dist, records):
    parts = [
        "<h1>hort-cli documentation</h1>",
        "<p>Generated from this repository's own docs and "
        "<code>crates/hort-cli/README.md</code> -- always in sync with the "
        "source checked into the repo.</p>",
        '<div class="docs-index"><ul>',
    ]
    for src_rel, output_rel, title in sorted(records, key=lambda r: r[2]):
        rel = os.path.relpath(output_rel, "docs").replace(os.sep, "/")
        parts.append(f'<li><a href="{rel}">{html.escape(title)}</a></li>')
    parts.append("</ul></div>")

    page_html = render_page(
        HORT_RS, "docs/index.html", "Documentation", "\n".join(parts)
    )
    write(dist, "docs/index.html", page_html)


def copy_hort_rs_apex_files(dist):
    """Copy the installer contract files verbatim to their exact published
    apex paths (issue #77 -- these URLs are load-bearing: install-cli.sh
    itself fetches https://hort.rs/cosign.pin, and the one-liners in
    README.md / install-cli.md reference /install-cli.sh, /install-cli.ps1
    directly)."""
    for fn in ("install-cli.sh", "install-cli.ps1", "cosign.pin"):
        shutil.copyfile(
            os.path.join(REPO_ROOT, "install", fn), os.path.join(dist, fn)
        )
    # install-cli.sh is fetched and executed via `sh`; keep it executable in
    # the built tree too (harmless for a static file server, but avoids
    # surprise if it's ever served or copied by a tool that preserves modes).
    os.chmod(os.path.join(dist, "install-cli.sh"), 0o755)


def write_dl_placeholder(dist):
    """A minimal placeholder for dl/index.html -- the real permanent version
    archive is populated separately, host-side, by
    scripts/populate-dl-archive.sh (see deploy/ansible/roles/website/ for
    why: it needs network access to GitHub from the deploy target, runs
    independently of a site rebuild, and must never be wiped by one -- this
    build only guarantees the /dl/ link resolves so the link-check (and a
    plain `scripts/build-site.sh` in CI, which has no archive to populate)
    stays green. The real script overwrites this exact file with the real
    index once it has populated at least one version."""
    body = """
<h1>hort-cli release archive</h1>
<p>Permanent, immutable per-version download archive. No versions are
archived on this build -- see the recommended one-line installer on
<a href="../index.html">hort.rs</a>, which always resolves the latest
release directly from GitHub.</p>
<p>On a deployed host, this page is replaced by
<code>scripts/populate-dl-archive.sh</code> once it has backfilled at
least one published release.</p>
"""
    page_html = render_page(HORT_RS, "dl/index.html", "Downloads", body)
    write(dist, "dl/index.html", page_html)


def build_hort_rs(dist):
    build_hort_rs_landing(dist)
    records = build_hort_rs_docs(dist)
    build_hort_rs_docs_index(dist, records)
    copy_assets(dist)
    copy_hort_rs_apex_files(dist)
    write_dl_placeholder(dist)
    return len(records) + 3  # landing + docs index + dl placeholder


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

BUILDERS = {
    PROJECT_HORT_DE: build_project_hort_de,
    HORT_RS: build_hort_rs,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--site",
        choices=list(BUILDERS),
        action="append",
        help="build only this site (repeatable); default: build both",
    )
    parser.add_argument(
        "--dist",
        default=os.path.join(REPO_ROOT, "site", "dist"),
        help="output root (default: site/dist/); each site builds into "
        "<dist>/<fqdn>/",
    )
    args = parser.parse_args()

    sites = args.site or list(BUILDERS)
    dist_root = os.path.abspath(args.dist)
    os.makedirs(dist_root, exist_ok=True)

    total_pages = 0
    built_dirs = []
    for site_key in sites:
        site_dist = os.path.join(dist_root, site_key)
        if os.path.exists(site_dist):
            shutil.rmtree(site_dist)
        os.makedirs(site_dist, exist_ok=True)
        n = BUILDERS[site_key](site_dist)
        total_pages += n
        built_dirs.append(site_dist)
        print(
            f"Generated {n} pages for {site_key} into "
            f"{os.path.relpath(site_dist, REPO_ROOT)}/"
        )

    import linkcheck

    ok = True
    for site_dist in built_dirs:
        if not linkcheck.check(site_dist):
            ok = False
    if not ok:
        print("Link check FAILED", file=sys.stderr)
        sys.exit(1)
    print(f"Link check passed for {len(built_dirs)} site(s), {total_pages} pages total.")


if __name__ == "__main__":
    main()
