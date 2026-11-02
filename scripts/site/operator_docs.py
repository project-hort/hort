"""Curated operator documentation navigation. Legacy content remains addressable but unlisted."""
import html
import os
import re

GROUPS = [
    ("Getting Started", [("What is hort?", "getting-started/what-is-hort"), ("Quickstart", "getting-started/quickstart")]),
    ("Installation & Deployment", [("Native Linux (systemd)", "installation/native-linux"), ("Kubernetes with Helm", "installation/kubernetes-helm"), ("Prepare PostgreSQL", "installation/postgresql"), ("Configure artifact storage", "installation/storage"), ("Upgrade hort", "installation/upgrade"), ("Trust custom CAs", "installation/custom-ca")]),
    ("Repositories", [("Repository types", "repositories/overview"), ("OCI pull-through proxy", "repositories/oci-pull-through"), ("npm pull-through", "repositories/npm-pull-through"), ("PyPI pull-through", "repositories/pypi-pull-through")]),
    ("Configuration & Access", [("Declarative configuration", "configuration/declarative"), ("Identity & access", "configuration/identity-access"), ("Supply upstream credentials", "configuration/upstream-secrets"), ("Bootstrap administrator access", "configuration/admin-bootstrap"), ("Rotate service-account credentials", "configuration/rotate-service-account-tokens")]),
    ("Security & Operations", [("Scanning & governance", "operations/scanning-governance"), ("Server & workers", "operations/workers"), ("Monitoring & troubleshooting", "operations/monitoring"), ("Security hardening", "operations/security-hardening"), ("Kubernetes image pulls", "operations/kubernetes-image-pulls"), ("Recover stalled scans", "operations/recover-scans"), ("OCI provenance verification", "operations/provenance-verification")]),
]


def operator_sources():
    return ["docs/operator/" + slug + ".md" for _group, entries in GROUPS for _title, slug in entries]


def operator_output(src):
    return src[:-3] + ".html"


def sidebar(current_output, index=False):
    parts = ['<aside class="op-sidebar" aria-label="Operator documentation">', '<p class="op-sidebar-title">Operator documentation</p>', '<a class="op-start" href="' + os.path.relpath('docs/index.html', os.path.dirname(current_output) or '.').replace(os.sep, '/') + '">Documentation overview</a>']
    for title, entries in GROUPS:
        parts.append('<h2>' + html.escape(title) + '</h2><ul>')
        for label, slug in entries:
            out = 'docs/operator/' + slug + '.html'
            rel = os.path.relpath(out, os.path.dirname(current_output) or '.').replace(os.sep, '/')
            active = ' aria-current="page"' if out == current_output else ''
            parts.append('<li><a' + active + ' href="' + rel + '">' + html.escape(label) + '</a></li>')
        parts.append('</ul>')
    parts.append('</aside>')
    return '\n'.join(parts)


def toc(headings):
    items=[]
    for item in headings:
        if len(item) >= 3:
            level, anchor, title = item[0], item[1], item[2]
            if level in (2,3):
                items.append('<li class="toc-level-' + str(level) + '"><a href="#' + html.escape(str(anchor), quote=True) + '">' + html.escape(str(title)) + '</a></li>')
    return ('<aside class="op-toc" aria-label="On this page"><strong>On this page</strong><ul>' + ''.join(items) + '</ul></aside>') if items else ''
