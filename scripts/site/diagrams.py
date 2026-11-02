"""Kroki-compatible diagrams in fenced Markdown blocks.

Only the graphviz/DOT language is enabled for the operator documentation at
present. This uses Kroki's built-in Graphviz renderer (no companion service).
SVG names are keyed to source content, so a stale pre-rendered image cannot
silently survive a diagram edit.
"""

import hashlib
import html
import os
import re

FENCE_OPEN = re.compile(r"^(`{3,}|~{3,})\s*(graphviz|dot)\s*$", re.IGNORECASE)
COMMENT = re.compile(r"^\s*//\s*(alt|caption):\s*(.+?)\s*$", re.IGNORECASE)


def normalize(source):
    return source.replace("\r\n", "\n").rstrip("\n") + "\n"


def diagram_filename(source):
    digest = hashlib.sha256(("graphviz\n" + normalize(source)).encode("utf-8")).hexdigest()[:24]
    return "graphviz-" + digest + ".svg"


def metadata(source):
    parsed = {}
    for line in source.splitlines()[:8]:
        m = COMMENT.match(line)
        if m:
            parsed[m.group(1).lower()] = m.group(2).strip()
    if not parsed.get("alt") or not parsed.get("caption"):
        raise ValueError("graphviz diagrams require '// alt:' and '// caption:' comments")
    return parsed


def extract(markdown, source_name):
    """Yield fenced DOT blocks; fail on an unclosed fence."""
    lines = markdown.replace("\r\n", "\n").splitlines()
    i = 0
    while i < len(lines):
        match = FENCE_OPEN.match(lines[i])
        if match is None:
            i += 1
            continue
        fence = match.group(1)
        start = i + 1
        i += 1
        while i < len(lines) and not lines[i].startswith(fence[0] * len(fence)):
            i += 1
        if i == len(lines):
            raise ValueError(f"{source_name}:{start}: unclosed graphviz diagram")
        source = "\n".join(lines[start:i])
        metadata(source)
        yield source
        i += 1


def html_figure(source, output_rel):
    """HTML references only the pre-rendered local SVG, never Kroki URLs."""
    info = metadata(source)
    target = "assets/diagrams/" + diagram_filename(source)
    href = os.path.relpath(target, os.path.dirname(output_rel) or ".").replace(os.sep, "/")
    return (
        '<figure class="doc-diagram">'
        f'<img src="{html.escape(href, quote=True)}" '
        f'alt="{html.escape(info["alt"], quote=True)}" loading="lazy" decoding="async">'
        f'<figcaption>{html.escape(info["caption"])}</figcaption></figure>'
    )
