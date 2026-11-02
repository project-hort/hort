"""Dependency-free unit checks for diagram source IDs, markup and SVG safety."""
import importlib.util
import pathlib
import sys
import tempfile
import unittest

SCRIPT_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_ROOT))
import diagrams
import render_diagrams

SAMPLE = '''// alt: A connects to B.
// caption: Sample two-step flow.
digraph G { a -> b; }'''


class DiagramTests(unittest.TestCase):
    def test_markdown_extraction(self):
        md = 'Some text\n\n```graphviz\n' + SAMPLE + '\n```\n'
        self.assertEqual(list(diagrams.extract(md, 'test.md')), [SAMPLE])

    def test_source_hash_changes_when_modified(self):
        self.assertNotEqual(diagrams.diagram_filename(SAMPLE),
                            diagrams.diagram_filename(SAMPLE.replace('a -> b', 'a -> c')))

    def test_alt_and_caption(self):
        figure = diagrams.html_figure(SAMPLE, 'docs/operator/example.html')
        self.assertIn('<figure', figure)
        self.assertIn('alt="A connects to B."', figure)
        self.assertIn('assets/diagrams/', figure)
        self.assertNotIn('kroki.io', figure)

    def test_missing_alt_fails(self):
        with self.assertRaises(ValueError):
            diagrams.metadata('digraph G {a -> b}')

    def test_svg_rejects_active_content(self):
        unsafe = b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>'
        with self.assertRaises(ValueError):
            render_diagrams.svg_is_safe(unsafe, 'unsafe.svg')

    def test_svg_accepts_safe_shape(self):
        safe = b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="3" height="3"/></svg>'
        self.assertTrue(render_diagrams.svg_is_safe(safe, 'safe.svg'))

    def test_unclosed_fence_fails(self):
        with self.assertRaises(ValueError):
            list(diagrams.extract('```graphviz\n' + SAMPLE, 'unfinished.md'))


if __name__ == '__main__':
    unittest.main()
