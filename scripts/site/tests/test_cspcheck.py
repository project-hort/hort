"""Unit checks for the build-time "no page needs CSP 'unsafe-inline'" guard.

Each construct the published policy (default-src 'self') refuses gets a
rejection case, every allowed shape gets an acceptance case, and the guard
is driven end-to-end over a throwaway dist tree so a seeded violation is
shown to fail the build rather than merely to be detectable.
"""
import contextlib
import io
import pathlib
import sys
import tempfile
import unittest

SCRIPT_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_ROOT))
import cspcheck
import linkcheck

CLEAN = (
    '<!doctype html><html lang="en"><head><title>t</title>'
    '<link rel="stylesheet" href="assets/landing.css">'
    '<script src="assets/landing-1.js"></script></head>'
    '<body><p class="lead">text</p>'
    '<script src="assets/landing-2.js" defer></script></body></html>'
)


def descriptions(html):
    violations, _refs = cspcheck.scan_page(html)
    return [description for _line, description in violations]


class SiteListTests(unittest.TestCase):
    def test_site_list_is_the_generators_own(self):
        """Counter-assertion: a site the generator builds is a site this
        guard checks, with no second list to fall out of date."""
        import generate
        self.assertEqual(cspcheck.SITE_KEYS, tuple(generate.BUILDERS))
        self.assertTrue(cspcheck.SITE_KEYS)


class ScanTests(unittest.TestCase):
    def test_clean_page_has_no_violations(self):
        self.assertEqual(descriptions(CLEAN), [])

    def test_style_block_rejected(self):
        self.assertEqual(len(descriptions(CLEAN.replace(
            '<title>t</title>', '<title>t</title><style>body{margin:0}</style>'))), 1)

    def test_style_block_inside_inline_svg_rejected(self):
        self.assertEqual(len(descriptions(CLEAN.replace(
            '<p class="lead">text</p>',
            '<svg><style>.a{fill:red}</style></svg>'))), 1)

    def test_srcless_script_rejected(self):
        self.assertEqual(len(descriptions(CLEAN.replace(
            '<body>', '<body><script>alert(1)</script>'))), 1)

    def test_style_attribute_rejected(self):
        self.assertEqual(len(descriptions(CLEAN.replace(
            '<p class="lead">', '<p style="margin-top:32px">'))), 1)

    def test_event_handler_attribute_rejected(self):
        self.assertEqual(len(descriptions(CLEAN.replace(
            '<p class="lead">', '<p onclick="go()">'))), 1)

    def test_javascript_url_rejected(self):
        self.assertEqual(len(descriptions(CLEAN.replace(
            '<p class="lead">text</p>', '<a href="javascript:go()">x</a>'))), 1)

    def test_data_attribute_starting_with_on_is_not_a_handler(self):
        self.assertEqual(descriptions(CLEAN.replace(
            '<p class="lead">', '<p data-open-scenario="dmz">')), [])

    def test_every_violation_carries_a_line_number(self):
        violations, _refs = cspcheck.scan_page(
            '<html><head>\n<style>a{}</style>\n</head>\n'
            '<body>\n<script>x</script>\n</body></html>')
        self.assertEqual([line for line, _d in violations], [2, 5])

    def test_references_are_collected_for_resolution(self):
        _v, refs = cspcheck.scan_page(CLEAN)
        self.assertEqual(
            sorted((kind, url) for _line, kind, url in refs),
            [('script src', 'assets/landing-1.js'),
             ('script src', 'assets/landing-2.js'),
             ('stylesheet', 'assets/landing.css')])

    def test_non_stylesheet_link_is_not_a_reference(self):
        _v, refs = cspcheck.scan_page(
            '<link rel="icon" href="assets/hort-logo.svg" type="image/svg+xml">')
        self.assertEqual(refs, [])


def run(callable_):
    """Run the guard with its own reporting captured, not leaked into the
    test log: the report is an assertion target here, not test output."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        result = callable_()
    return result, out.getvalue() + err.getvalue()


class CheckTests(unittest.TestCase):
    def _site(self, tmp, page=CLEAN, assets=('landing.css', 'landing-1.js',
                                             'landing-2.js')):
        site = pathlib.Path(tmp) / 'project-hort.de'
        (site / 'assets').mkdir(parents=True)
        for name in assets:
            (site / 'assets' / name).write_text('/* x */', encoding='utf-8')
        (site / 'index.html').write_text(page, encoding='utf-8')
        return site

    def test_clean_site_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = self._site(tmp)
            ok, report = run(lambda: cspcheck.check(site))
            self.assertTrue(ok)
            self.assertIn('Checked 1 pages in project-hort.de', report)

    def test_seeded_style_block_fails_and_names_the_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = self._site(tmp, CLEAN.replace(
                '<body>', '<body><style>body{margin:0}</style>'))
            ok, report = run(lambda: cspcheck.check(site))
            self.assertFalse(ok)
            self.assertIn('project-hort.de/index.html:1: <style> block', report)

    def test_missing_script_asset_fails(self):
        """A moved-out script that 404s is the same dead page as a refusal."""
        with tempfile.TemporaryDirectory() as tmp:
            site = self._site(tmp, assets=('landing.css', 'landing-1.js'))
            ok, report = run(lambda: cspcheck.check(site))
            self.assertFalse(ok)
            self.assertIn('script src does not exist in the built tree: '
                          'assets/landing-2.js', report)

    def test_external_asset_reference_is_left_to_the_link_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = self._site(tmp, CLEAN.replace(
                'src="assets/landing-2.js"', 'src="https://cdn.example/x.js"'),
                assets=('landing.css', 'landing-1.js'))
            self.assertTrue(run(lambda: cspcheck.check(site))[0])

    def test_protocol_relative_script_is_rejected_by_link_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = self._site(tmp, CLEAN.replace(
                'src="assets/landing-2.js"', 'src="//cdn.example/app.js"'),
                assets=('landing.css', 'landing-1.js'))
            self.assertTrue(run(lambda: cspcheck.check(site))[0])
            ok, report = run(lambda: linkcheck.check(site))
            self.assertFalse(ok, report)
            self.assertIn('external asset reference not allowed: '
                          '//cdn.example/app.js', report)

    def test_empty_tree_fails_rather_than_reporting_a_vacuous_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = pathlib.Path(tmp) / 'project-hort.de'
            site.mkdir()
            ok, report = run(lambda: cspcheck.check(site))
            self.assertFalse(ok)
            self.assertIn('nothing was checked', report)

    def test_cli_exit_code_follows_the_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._site(tmp)
            argv = ['--site', 'project-hort.de', '--dist', tmp]
            self.assertEqual(run(lambda: cspcheck.main(argv))[0], 0)
            (pathlib.Path(tmp) / 'project-hort.de' / 'index.html').write_text(
                CLEAN.replace('<body>', '<body><script>alert(1)</script>'),
                encoding='utf-8')
            self.assertEqual(run(lambda: cspcheck.main(argv))[0], 1)


if __name__ == '__main__':
    unittest.main()
