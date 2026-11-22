"""Dependency-free checks for Markdown image rendering and asset validation."""
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_ROOT))
import generate
import mdconv


SOURCE = "docs/architecture/how-to/example.md"
OUTPUT = "docs/how-to/example.html"
ASSET = "../../../site/assets/badge.svg"


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "site/assets").mkdir(parents=True)
        self.root_patch = patch.object(generate, "REPO_ROOT", str(self.root))
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def asset(self, name="badge.svg"):
        (self.root / "site/assets" / name).write_text("image", encoding="utf-8")

    def convert(self, markdown):
        return mdconv.convert(
            markdown,
            generate.make_link_resolver(generate.PROJECT_HORT_DE, SOURCE, OUTPUT),
            image_resolver=generate.make_image_resolver(SOURCE, OUTPUT),
        )[0]

    def test_bare_image_renders_escaped_alt_without_stray_bang(self):
        self.asset()
        self.assertEqual(
            self.convert(f"![A & B]({ASSET})"),
            '<p><img src="../../assets/badge.svg" alt="A &amp; B" '
            'loading="lazy" decoding="async"></p>',
        )

    def test_linked_image_uses_link_target_and_nests_image(self):
        self.asset()
        self.assertEqual(
            self.convert(f"[![Quality Gate]({ASSET})](https://example.test/dash)"),
            '<p><a href="https://example.test/dash"><img '
            'src="../../assets/badge.svg" alt="Quality Gate" '
            'loading="lazy" decoding="async"></a></p>',
        )

    def test_empty_alt_refuses(self):
        self.asset()
        with self.assertRaises(ValueError):
            self.convert(f"![]({ASSET})")

    def test_unresolvable_source_refuses_with_page_and_path(self):
        with self.assertRaises(ValueError) as raised:
            self.convert(f"![Missing]({ASSET})")
        self.assertIn(SOURCE, str(raised.exception))
        self.assertIn(ASSET, str(raised.exception))

    def test_remote_source_refuses_with_alternatives(self):
        for scheme in ("http", "https"):
            with self.subTest(scheme=scheme):
                with self.assertRaises(ValueError) as raised:
                    self.convert(f"![Badge]({scheme}://example.test/badge.svg)")
                self.assertIn("outside rendered Markdown", str(raised.exception))
                self.assertIn("vendor", str(raised.exception))

    def test_page_without_images_is_byte_identical(self):
        markdown = (
            '# A & B\n\nA **bold** word, *emphasis*, `code <x>`, and '
            '[guide](guide.md).\n\n- one\n- two\n\n'
            '| Name | Value |\n| --- | --- |\n| x | y |'
        )
        self.assertEqual(
            mdconv.convert(
                markdown, lambda href: "docs/" + href,
                image_resolver=lambda src: src,
            ),
            ('<h1 id="a--b">A &amp; B</h1>\n'
             '<p>A <strong>bold</strong> word, <em>emphasis</em>, '
             '<code>code &lt;x&gt;</code>, and '
             '<a href="docs/guide.md">guide</a>.</p>\n'
             '<ul><li>one</li><li>two</li></ul>\n'
             '<table><thead><tr><th>Name</th><th>Value</th></tr></thead>'
             '<tbody><tr><td>x</td><td>y</td></tr></tbody></table>',
             [(1, 'a--b', 'A & B')]),
        )

    def test_image_and_surrounding_link_escape_html_metacharacters(self):
        name = 'badge&<".svg'
        self.asset(name)
        source = "../../../site/assets/" + name
        self.assertEqual(
            self.convert(f'[![A & "B" < C >]({source})](https://example.test/?a=1&b=<x>)'),
            '<p><a href="https://example.test/?a=1&amp;b=&lt;x&gt;">'
            '<img src="../../assets/badge&amp;&lt;&quot;.svg" '
            'alt="A &amp; &quot;B&quot; &lt; C &gt;" '
            'loading="lazy" decoding="async"></a></p>',
        )

    def test_malformed_linked_image_refuses(self):
        self.asset()
        with self.assertRaises(ValueError):
            self.convert(f"[![Badge]({ASSET})](target with space)")

    def test_image_text_in_code_span_stays_code(self):
        self.assertEqual(
            self.convert("`![Badge](missing.svg)`"),
            "<p><code>![Badge](missing.svg)</code></p>",
        )


if __name__ == "__main__":
    unittest.main()
