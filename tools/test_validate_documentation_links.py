# Copyright (C) 2026, Leo Galambos
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. All advertising materials mentioning features or use of this software must
#    display the following acknowledgement:
#    This product includes software developed by the Egothor project.
#
# 4. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Deterministic fixtures for the documentation link gate."""

from pathlib import Path
import tempfile
import unittest

from validate_documentation_links import validate, validate_site, declared_javadoc_modules


class DocumentationLinksTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.docs = self.root / "documentation"
        self.docs.mkdir()

    def check(self, contents, nav=None):
        paths = []
        for name, content in contents.items():
            path = self.docs / name
            path.write_text(content, encoding="utf-8")
            paths.append(path)
        return validate(self.root, paths, self.docs,
                        list(contents) if nav is None else nav,
                        ["toc", "attr_list", "fenced_code"], {})

    def test_rendered_headings_reference_links_and_escaped_paths(self):
        self.assertEqual([], self.check({
            "index.md": "[ref][target]\n\n[target]: other%20page.md#same_1\n"
                        "[explicit](other%20page.md#chosen)\n"
                        "[html](other%20page.md#html-id)\n"
                        "```markdown\n[ignored](absent.md)\n# Not an anchor\n```",
            "other page.md": "# Same\n\n# Same\n\n# Different {#chosen}\n"
                             '<span id="html-id"></span>'}))

    def test_missing_targets_and_anchors_are_reported(self):
        errors = self.check({"index.md": "# Here\n[missing](absent.md)\n[bad](#nope)"})
        self.assertEqual(2, len(errors))
        self.assertTrue(any("missing target" in error for error in errors))
        self.assertTrue(any("missing anchor" in error for error in errors))

    def test_navigation_is_complete_and_targets_exist(self):
        errors = self.check({"index.md": "# Home", "other.md": "# Other"},
                            [{"Home": "index.md"}, {"Lost": "missing.md"}])
        self.assertEqual(2, len(errors))

    def test_repository_relative_links_and_external_urls(self):
        (self.root / "README.md").write_text("# Root", encoding="utf-8")
        self.assertEqual([], self.check({"index.md":
            "[web](https://example.invalid/x#unchecked)"}))
        page = self.root / "README.md"
        page.write_text("[site](documentation/index.md#home)", encoding="utf-8")
        (self.docs / "index.md").write_text("# Home", encoding="utf-8")
        self.assertEqual([], validate(self.root, [page], self.docs, ["index.md"], ["toc"], {}))

    def test_existing_repository_file_is_not_a_site_target(self):
        (self.root / "README.md").write_text("# Root", encoding="utf-8")
        errors = self.check({"index.md": "[repo](../README.md#root)"})
        self.assertEqual(1, len(errors))
        self.assertIn("site link escapes", errors[0])

    def test_invalid_and_escaping_targets(self):
        errors = self.check({"index.md":
            '[escape](../../outside.md) <a href="bad%00path">bad</a> '
            '<a href="https://[bad">malformed</a> [bad](bad%zz.md)'})
        self.assertEqual(4, len(errors))


    def test_html_source_alias_and_index_preserve_anchor_checks(self):
        self.assertEqual([], self.check({"index.md": '[ok](other.html#there)',
                                         "other.md": '# There'}))
        errors = self.check({"index.md": '[bad](other.html#absent)', "other.md": '# There'})
        self.assertEqual(1, len(errors))
        self.assertIn("missing anchor", errors[0])

    def test_unknown_html_is_not_accepted(self):
        self.assertIn("missing target", self.check({"index.md": '[bad](absent.html)'})[0])

    def test_excluded_navigation_does_not_hide_explicit_broken_links(self):
        page = self.docs / "vendor.md"
        page.write_text('[broken](absent.md)', encoding="utf-8")
        errors = validate(self.root, [page], self.docs, [], ["toc"], {},
                          excluded={"vendor.md"})
        self.assertEqual(1, len(errors))
        self.assertIn("missing target", errors[0])

    def test_generated_namespace_requires_declared_module_and_site_proof(self):
        page = self.docs / "index.md"
        page.write_text('[api](javadoc/lib/index.html#api)', encoding="utf-8")
        args = (self.root, [page], self.docs, ["index.md"], ["toc"], {})
        self.assertEqual([], validate(*args, generated_modules={"lib"}))
        self.assertIn("missing target", validate(*args, generated_modules={"ext"})[0])
        site = self.root / "site"
        (site / "javadoc/lib").mkdir(parents=True)
        self.assertIn("missing target", validate(*args, generated_modules={"lib"}, site=site)[0])
        (site / "javadoc/lib/index.html").write_text('<h1 id="other">Other</h1>')
        self.assertIn("missing anchor", validate(*args, generated_modules={"lib"}, site=site)[0])
        (site / "javadoc/lib/index.html").write_text('<h1 id="api">API</h1>')
        self.assertEqual([], validate(*args, generated_modules={"lib"}, site=site))

    def test_assembled_output_checks_html_assets_anchors_and_escaping(self):
        site = self.root / "site"
        site.mkdir()
        self.assertEqual(["assembled site: missing index.html"], validate_site(site))
        (site / "index.html").write_text('<a href="page/#yes">ok</a><img src="asset.png">')
        (site / "page").mkdir()
        (site / "page/index.html").write_text('<h1 id="yes">Yes</h1>')
        (site / "asset.png").write_bytes(b"fixture")
        self.assertEqual([], validate_site(site))
        (site / "index.html").write_text('<a href="page/#absent">bad</a><a href="../outside">escape</a><a href="bad%zz">bad</a>')
        self.assertEqual(3, len(validate_site(site)))

    def test_build_declared_namespaces_exclude_disabled_and_nonjava_modules(self):
        (self.root / "settings.gradle").write_text("include('lib', 'samples', 'frontend', 'unknown')")
        (self.root / "build.gradle").write_text("AssembleDocumentationSite javadoc.get().enabled")
        for name, text in {"lib": "id 'buildlogic.java-library-conventions'",
                           "samples": "id 'buildlogic.java-library-conventions'\ntasks.named('javadoc').configure { enabled = false }",
                           "frontend": "id 'base'"}.items():
            (self.root / name).mkdir()
            (self.root / name / "build.gradle").write_text(text)
        self.assertEqual({"lib"}, declared_javadoc_modules(self.root))

    def test_excluded_alias_target_is_not_published(self):
        page = self.docs / "index.md"
        page.write_text('[bad](vendor.html)')
        (self.docs / "vendor.md").write_text('# Vendor')
        errors = validate(self.root, [page], self.docs, ['index.md'], ['toc'], {},
                          excluded={'vendor.md'})
        self.assertEqual(1, len(errors))

    def test_html_index_alias_and_directory_index(self):
        (self.docs / "section").mkdir()
        (self.docs / "section/index.md").write_text('# Section')
        self.assertEqual([], self.check({"index.md":
            '[one](section/index.html#section) [two](section/#section)'}))

    def test_malformed_unicode_and_encoded_traversal_still_fail(self):
        errors = self.check({"index.md":
            '<a href="bad%ff.md">bad</a><a href="%2e%2e/%2e%2e/out.md">escape</a>'})
        self.assertEqual(2, len(errors))

    def test_existing_directory_requires_published_index_and_valid_anchor(self):
        section = self.docs / "section"
        section.mkdir()
        index = section / "index.md"
        index.write_text('# Present')
        errors = self.check({"index.md": '[bad](section/#absent)'})
        self.assertEqual(1, len(errors))
        self.assertIn("missing anchor", errors[0])
        index.unlink()
        self.assertIn("missing target", self.check({"index.md": '[bad](section/)'})[0])
        index.write_text('# Present')
        page = self.docs / 'index.md'
        errors = validate(self.root, [page], self.docs, ['index.md'], ['toc'], {},
                          excluded={'section/index.md'})
        self.assertEqual(1, len(errors))

    def test_source_alias_and_index_symlinks_cannot_escape_docs(self):
        outside = self.root / 'outside.md'
        outside.write_text('# Secret')
        (self.docs / 'alias.md').symlink_to(outside)
        section = self.docs / 'section'
        section.mkdir()
        (section / 'index.md').symlink_to(outside)
        errors = self.check({'index.md':
            '[alias](alias.html#secret) [index](section/#secret)'})
        self.assertEqual(2, len(errors))
        self.assertTrue(all('site link escapes docs directory' in error for error in errors))

    def test_alias_symlink_to_excluded_page_is_not_published(self):
        (self.docs / 'excluded.md').write_text('# Secret')
        (self.docs / 'alias.md').symlink_to(self.docs / 'excluded.md')
        page = self.docs / 'index.md'
        page.write_text('[alias](alias.html#secret)')
        errors = validate(self.root, [page], self.docs, ['index.md'], ['toc'], {},
                          excluded={'excluded.md'})
        self.assertEqual(1, len(errors))
        self.assertIn('target excluded from publication', errors[0])

    def test_assembled_directory_index_symlink_cannot_escape_site(self):
        outside = self.root / 'outside.html'
        outside.write_text('<h1 id="secret">Secret</h1>')
        site = self.root / 'site'
        (site / 'section').mkdir(parents=True)
        (site / 'index.html').write_text('<a href="section/#secret">bad</a>')
        (site / 'section/index.html').symlink_to(outside)
        errors = validate_site(site)
        self.assertEqual(2, len(errors))
        self.assertTrue(any('target escapes assembled site' in error for error in errors))
        self.assertTrue(any('source escapes assembled site' in error for error in errors))

    def test_source_alias_symlink_cannot_escape_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / 'outside.md'
            outside.write_text('# Secret')
            (self.docs / 'alias.md').symlink_to(outside)
            errors = self.check({'index.md': '[alias](alias.html#secret)'})
            self.assertEqual(1, len(errors))
            self.assertIn('target escapes repository', errors[0])

    def test_source_symlink_cannot_escape_docs(self):
        outside = self.root / 'outside.md'
        outside.write_text('# Secret')
        alias = self.docs / 'alias.md'
        alias.symlink_to(outside)
        errors = validate(self.root, [alias], self.docs, [], ['toc'], {})
        self.assertEqual(1, len(errors))
        self.assertIn('source escapes docs directory', errors[0])


if __name__ == "__main__":
    unittest.main()
