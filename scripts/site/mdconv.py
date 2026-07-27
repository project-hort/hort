#!/usr/bin/env python3
"""A small, dependency-free Markdown-subset -> HTML converter for the
project-hort.de static site (issue #78).

Not a general CommonMark implementation -- it covers exactly the constructs
used across docs/architecture/{how-to,reference,tutorial} and README.md:
ATX headings, paragraphs, bullet/numbered lists (one level of nesting),
fenced code blocks (with a language class), GFM pipe tables, blockquotes,
horizontal rules, and inline bold/italic/code/links. Anything outside that
set (raw HTML blocks, footnotes, images, deep nesting) is intentionally
unhandled -- see scripts/site/generate.py's docstring for why a hand-rolled
subset was chosen over a third-party dependency.

Pure Python 3 standard library only (re, html) -- no pip install, no
floating lockfile, so this is the whole supply chain for the site's content
pipeline.
"""

import html
import re

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_FENCE_RE = re.compile(r"^(`{3,}|~{3,})\s*([\w+.-]*)\s*$")
_ULIST_RE = re.compile(r"^(\s*)([-*+])\s+(.*)$")
_OLIST_RE = re.compile(r"^(\s*)(\d+)[.)]\s+(.*)$")
_TABLE_ROW_RE = re.compile(r"^\s*\|?(.+\|.+)\|?\s*$")
_TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$")
_BLOCKQUOTE_RE = re.compile(r"^>\s?(.*)$")
_HR_RE = re.compile(r"^ {0,3}(-{3,}|\*{3,}|_{3,})\s*$")
_BLANK_RE = re.compile(r"^\s*$")

# ---------------------------------------------------------------------------
# Heading slugs (GitHub-compatible, since existing docs cross-reference
# headings with GitHub-style '#anchor' fragments already).
# ---------------------------------------------------------------------------

_SLUG_STRIP_RE = re.compile(r"[^a-z0-9\s-]")
_SLUG_WS_RE = re.compile(r"\s")


def strip_inline_markup(text):
    """Reduce inline markdown syntax to plain text (for slug computation)."""
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\*\*([^*]*)\*\*", r"\1", text)
    text = re.sub(r"__([^_]*)__", r"\1", text)
    text = re.sub(r"\*([^*]*)\*", r"\1", text)
    text = re.sub(r"(?<!\w)_([^_]*)_(?!\w)", r"\1", text)
    return text


def slugify(text, seen):
    """GitHub-compatible heading slug, de-duplicated against `seen` (a dict
    mapping slug -> next suffix to use, mutated in place)."""
    plain = strip_inline_markup(text).lower()
    plain = _SLUG_STRIP_RE.sub("", plain)
    plain = _SLUG_WS_RE.sub("-", plain).strip("-")
    if plain == "":
        plain = "section"
    if plain in seen:
        seen[plain] += 1
        return f"{plain}-{seen[plain]}"
    seen[plain] = 0
    return plain


# ---------------------------------------------------------------------------
# Inline rendering
# ---------------------------------------------------------------------------

_INLINE_CODE_RE = re.compile(r"`([^`]+)`")
_LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*|__([^_]+)__")
_ITALIC_RE = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)|(?<!\w)_([^_]+)_(?!\w)")


def render_inline(text, link_resolver):
    """Render inline markdown (code spans, bold, italic, links) to HTML.

    `link_resolver(href) -> href` rewrites a link target; plain text is
    HTML-escaped, code-span/link content is escaped independently so raw
    '<', '>', '&' in prose (e.g. literal placeholder tokens like <UUID>)
    never get interpreted as HTML.
    """
    # Links are extracted FIRST, from the raw (still-has-real-backticks)
    # text, and each label is fully rendered right away via a recursive
    # call. This must happen before code-span stashing below: a link
    # label like [`x.md`](x.html) has its own inline code span, and if
    # the outer pass stashed code spans first, the label text handed to
    # this function's own recursive call would already be an opaque
    # \x00CODE-n\x00 placeholder from the OUTER scope -- meaningless to
    # (and unresolvable by) the inner call, which has no visibility into
    # the outer scope's `codes` list. Resolving links to complete HTML
    # up front avoids that cross-scope placeholder collision entirely.
    links = []

    def _stash_link(m):
        label, href = m.group(1), m.group(2)
        resolved = link_resolver(href)
        links.append((render_inline(label, link_resolver), resolved))
        return f"\x00LINK{len(links) - 1}\x00"

    text = _LINK_RE.sub(_stash_link, text)

    # Now stash code spans in the remaining (non-link) text.
    codes = []

    def _stash_code(m):
        codes.append(html.escape(m.group(1)))
        return f"\x00CODE{len(codes) - 1}\x00"

    text = _INLINE_CODE_RE.sub(_stash_code, text)

    # Escape remaining plain text, then re-apply bold/italic (safe: markup
    # chars '*'/'_' are not escaped by html.escape).
    text = html.escape(text, quote=False)

    def _bold(m):
        inner = m.group(1) or m.group(2)
        return f"<strong>{inner}</strong>"

    text = _BOLD_RE.sub(_bold, text)

    def _italic(m):
        inner = m.group(1) or m.group(2)
        return f"<em>{inner}</em>"

    text = _ITALIC_RE.sub(_italic, text)

    for i, code in enumerate(codes):
        text = text.replace(f"\x00CODE{i}\x00", f"<code>{code}</code>")
    for i, (label, href) in enumerate(links):
        href_escaped = html.escape(href, quote=True)
        text = text.replace(
            f"\x00LINK{i}\x00", f'<a href="{href_escaped}">{label}</a>'
        )
    return text


# ---------------------------------------------------------------------------
# Block-level parsing
# ---------------------------------------------------------------------------


def _render_list(lines, start, link_resolver):
    """Render a contiguous run of list-item lines (with possible one-level
    nested sub-lists and indented continuation text) starting at `start`.
    Returns (html, next_index)."""
    base_indent = None
    ordered = None
    items = []  # list of (indent, marker_is_ordered, content_lines)
    i = start
    while i < len(lines):
        line = lines[i]
        if _BLANK_RE.match(line):
            # A blank line ends the list unless followed by another list
            # item at the same (or deeper) indent -- keep it simple: a
            # blank line terminates this list run.
            break
        m_u = _ULIST_RE.match(line)
        m_o = _OLIST_RE.match(line)
        if m_u or m_o:
            indent = len(m_u.group(1)) if m_u else len(m_o.group(1))
            if base_indent is None:
                base_indent = indent
                ordered = bool(m_o)
            if indent > base_indent:
                # Nested item: append as a continuation line of the last
                # top-level item, tagged so the caller can render a
                # sub-list. Represented simply as raw text with a marker.
                items[-1][1].append(("nested", line))
                i += 1
                continue
            if indent < base_indent:
                break
            content = m_u.group(3) if m_u else m_o.group(3)
            items.append([content, []])
            i += 1
            continue
        # Continuation line (indented plain text belonging to the last item).
        if items and (line.startswith("  ") or line.startswith("\t")):
            items[-1][1].append(("cont", line.strip()))
            i += 1
            continue
        break

    def render_items(items):
        parts = []
        for content, extra in items:
            body = render_inline(content, link_resolver)
            nested_lines = [l for kind, l in extra if kind == "nested"]
            cont_lines = [l for kind, l in extra if kind == "cont"]
            if cont_lines:
                body += " " + render_inline(" ".join(cont_lines), link_resolver)
            if nested_lines:
                sub_html, _ = _render_list(nested_lines, 0, link_resolver)
                body += sub_html
            parts.append(f"<li>{body}</li>")
        return "".join(parts)

    tag = "ol" if ordered else "ul"
    return f"<{tag}>{render_items(items)}</{tag}>", i


def _render_table(lines, start, link_resolver):
    header = [c.strip() for c in lines[start].strip().strip("|").split("|")]
    i = start + 2  # skip header + separator row
    rows = []
    while i < len(lines) and _TABLE_ROW_RE.match(lines[i]):
        cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
        rows.append(cells)
        i += 1
    out = ["<table><thead><tr>"]
    for c in header:
        out.append(f"<th>{render_inline(c, link_resolver)}</th>")
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>")
        for j in range(len(header)):
            cell = row[j] if j < len(row) else ""
            out.append(f"<td>{render_inline(cell, link_resolver)}</td>")
        out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out), i


def convert(markdown_text, link_resolver):
    """Convert `markdown_text` to an HTML fragment.

    Returns (html_fragment, headings) where headings is a list of
    (level, slug, text) for building a page's local table of contents.
    """
    lines = markdown_text.replace("\r\n", "\n").split("\n")
    out = []
    headings = []
    seen_slugs = {}
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]

        if _BLANK_RE.match(line):
            i += 1
            continue

        m = _HEADING_RE.match(line)
        if m:
            level = len(m.group(1))
            text = m.group(2)
            slug = slugify(text, seen_slugs)
            headings.append((level, slug, text))
            out.append(
                f'<h{level} id="{slug}">{render_inline(text, link_resolver)}</h{level}>'
            )
            i += 1
            continue

        m = _FENCE_RE.match(line)
        if m:
            fence, lang = m.group(1), m.group(2)
            body_lines = []
            i += 1
            while i < n and not lines[i].startswith(fence[0] * len(fence)):
                body_lines.append(lines[i])
                i += 1
            i += 1  # skip closing fence
            code = html.escape("\n".join(body_lines))
            cls = f' class="language-{lang}"' if lang else ""
            out.append(f"<pre><code{cls}>{code}</code></pre>")
            continue

        if _HR_RE.match(line):
            out.append("<hr>")
            i += 1
            continue

        if _ULIST_RE.match(line) or _OLIST_RE.match(line):
            list_html, i = _render_list(lines, i, link_resolver)
            out.append(list_html)
            continue

        if (
            _TABLE_ROW_RE.match(line)
            and i + 1 < n
            and _TABLE_SEP_RE.match(lines[i + 1])
        ):
            table_html, i = _render_table(lines, i, link_resolver)
            out.append(table_html)
            continue

        m = _BLOCKQUOTE_RE.match(line)
        if m:
            quote_lines = [m.group(1)]
            i += 1
            while i < n and _BLOCKQUOTE_RE.match(lines[i]):
                quote_lines.append(_BLOCKQUOTE_RE.match(lines[i]).group(1))
                i += 1
            out.append(
                f"<blockquote><p>{render_inline(' '.join(quote_lines), link_resolver)}</p></blockquote>"
            )
            continue

        # Paragraph: gather lines until a blank line or a new block starts.
        para_lines = [line]
        i += 1
        while i < n and not _BLANK_RE.match(lines[i]):
            nxt = lines[i]
            if (
                _HEADING_RE.match(nxt)
                or _FENCE_RE.match(nxt)
                or _ULIST_RE.match(nxt)
                or _OLIST_RE.match(nxt)
                or _BLOCKQUOTE_RE.match(nxt)
                or _HR_RE.match(nxt)
            ):
                break
            para_lines.append(nxt)
            i += 1
        out.append(f"<p>{render_inline(' '.join(para_lines), link_resolver)}</p>")

    return "\n".join(out), headings
