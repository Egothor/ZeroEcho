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

from validate_documentation_links import validate


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


if __name__ == "__main__":
    unittest.main()
