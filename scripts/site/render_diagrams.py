#!/usr/bin/env python3
"""Pre-render operator Markdown graphviz code fences to local SVG assets.

Usage:
  python3 scripts/site/render_diagrams.py --check
  python3 scripts/site/render_diagrams.py --render --kroki-url http://127.0.0.1:8000

Kroki: POST /graphviz/svg with text/plain. No runtime browser requests.
For offline QA only, --renderer local-dot uses the equivalent Graphviz DOT
engine; production generation and CI should use the Kroki renderer.
"""
import argparse
import os
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import diagrams  # noqa: E402
import operator_docs  # noqa: E402
import developer_docs  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / 'site/assets/diagrams'
MAX_SOURCE = 50000
MAX_SVG = 1000000
SVG_NS = 'http://www.w3.org/2000/svg'
FORBIDDEN_TAGS = {'script', 'foreignObject', 'image', 'iframe', 'object', 'embed', 'use', 'animate', 'set', 'feImage'}


def all_diagrams():
    found = {}
    for rel in operator_docs.operator_sources() + developer_docs.new_sources():
        md = (ROOT / rel).read_text(encoding='utf-8')
        for src in diagrams.extract(md, rel):
            target = diagrams.diagram_filename(src)
            if len(src.encode('utf-8')) > MAX_SOURCE:
                raise ValueError(f'{rel}: diagram exceeds {MAX_SOURCE} bytes')
            found[target] = (src, rel)
    return found


def svg_is_safe(data, filename):
    if len(data) > MAX_SVG:
        raise ValueError(f'{filename}: SVG exceeds limit')
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f'{filename}: invalid SVG: {exc}') from exc
    if root.tag != '{' + SVG_NS + '}svg':
        raise ValueError(f'{filename}: response is not SVG')
    if sum(1 for _ in root.iter()) > 4000:
        raise ValueError(f'{filename}: too many SVG nodes')
    for el in root.iter():
        tag = el.tag.rsplit('}', 1)[-1]
        if tag in FORBIDDEN_TAGS:
            raise ValueError(f'{filename}: forbidden SVG element {tag}')
        if tag == 'style' and el.text and ('@import' in el.text.lower() or 'url(' in el.text.lower()):
            raise ValueError(f'{filename}: forbidden CSS import/url')
        for attr, val in el.attrib.items():
            key = attr.rsplit('}', 1)[-1].lower()
            if key.startswith('on') or key == 'href':
                raise ValueError(f'{filename}: forbidden SVG attribute {key}')
            if ('url(' in val.lower() and ('http:' in val.lower() or 'https:' in val.lower())):
                raise ValueError(f'{filename}: external SVG URL forbidden')
    return True


def kroki_render(src, url):
    uri = url.rstrip('/') + '/graphviz/svg'
    request = urllib.request.Request(
        uri, diagrams.normalize(src).encode('utf-8'),
        headers={'Content-Type': 'text/plain', 'Accept': 'image/svg+xml'}, method='POST')
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise ValueError(f'Kroki HTTP {response.status}')
        payload = response.read(MAX_SVG + 1)
    return payload


def dot_render(src):
    return subprocess.run(['dot', '-Tsvg'], input=diagrams.normalize(src).encode('utf-8'),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='verify all SVG assets exist and are safe')
    mode.add_argument('--render', action='store_true', help='render with Kroki or local DOT')
    parser.add_argument('--kroki-url', default=os.environ.get('KROKI_URL', ''), help='trusted Kroki HTTP endpoint')
    parser.add_argument('--renderer', choices=['kroki', 'local-dot'], default='kroki')
    parser.add_argument('--force', action='store_true', help='regenerate even if cached')
    args = parser.parse_args()
    try:
        found = all_diagrams()
        DEST.mkdir(parents=True, exist_ok=True)
        if args.render and args.renderer == 'kroki' and not args.kroki_url:
            parser.error('--render requires --kroki-url or --renderer local-dot (offline QA only)')
        for filename, (src, rel) in sorted(found.items()):
            path = DEST / filename
            if args.render and (not path.exists() or args.force):
                payload = kroki_render(src, args.kroki_url) if args.renderer == 'kroki' else dot_render(src)
                svg_is_safe(payload, filename)
                path.write_bytes(payload)
                print(f'rendered {filename} from {rel} ({args.renderer})')
            if not path.is_file():
                raise ValueError(f'{filename} missing (from {rel}); render before publishing')
            svg_is_safe(path.read_bytes(), filename)
        print(f'Checked {len(found)} diagram asset(s), all present and valid.')
    except (OSError, ValueError, urllib.error.URLError, subprocess.CalledProcessError) as exc:
        print(f'diagram build failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
