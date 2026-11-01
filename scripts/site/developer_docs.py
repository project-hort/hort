"""Curated developer portal source paths and navigation, not an ADR dump."""
import html
import os

GROUPS = [
    ("Getting Started", [("Develop hort locally", "getting-started/local-development")]),
    ("Crates & APIs", [("Crate map", "crates/crate-map"), ("Extend a registry format", "crates/format-handlers")]),
    ("Architecture & Extending", [("Ports and adapters", "architecture/ports-and-adapters"), ("Artifact lifecycle & CAS", "architecture/artifact-lifecycle"), ("Architectural decisions", "architecture/decisions")]),
    ("Contributing", [("Testing changes", "contributing/testing-changes")]),
    ("CLI & Downloads", [("Install the CLI", "__legacy__/install-cli"), ("CLI completions", "__legacy__/cli-completions"), ("CLI for admin operations", "__legacy__/using-hort-cli-with-admin-ops"), ("CLI reference", "__legacy__/cli-reference")]),
]


def new_sources():
    return ["docs/developer/" + slug + ".md" for _heading, entries in GROUPS for _label, slug in entries if not slug.startswith("__legacy__/")]


def path_for(src):
    return "docs/developer/" + src[len("docs/developer/"):-3] + ".html"


def entry_path(slug):
    return "docs/" + slug[len("__legacy__/"):] + ".html" if slug.startswith("__legacy__/") else "docs/developer/" + slug + ".html"


def sidebar(current_output):
    dirname = os.path.dirname(current_output) or "."
    def rel(path): return os.path.relpath(path, dirname).replace(os.sep, "/")
    chunks = ['<aside class="op-sidebar" aria-label="Developer documentation">', '<p class="op-sidebar-title">Developer docs</p>', '<a class="op-start" href="' + rel('docs/index.html') + '">Documentation overview</a>']
    for group, entries in GROUPS:
        chunks.append('<h2>' + html.escape(group) + '</h2><ul>')
        for label, slug in entries:
            output = entry_path(slug)
            active = ' aria-current="page"' if output == current_output else ''
            chunks.append('<li><a' + active + ' href="' + rel(output) + '">' + html.escape(label) + '</a></li>')
        chunks.append('</ul>')
    chunks.append('</aside>')
    return ''.join(chunks)
