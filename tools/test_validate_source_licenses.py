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
"""Regression tests for complete source-license verification."""

from pathlib import Path
import hashlib
import unittest

from validate_source_licenses import header_text, normalize, source_path, validate_header

CANONICAL = (Path(__file__).resolve().parents[1] / "LICENSE-source.txt").read_text()


class SourceLicenseTest(unittest.TestCase):
    def test_complete_comment_styles_and_preserved_year(self):
        for prefix in (" * ", "# ", "// ", "@rem "):
            content = "\n".join(prefix + line for line in CANONICAL.splitlines())
            if prefix == " * ":
                content = "/*\n" + content + "\n*/"
            with self.subTest(prefix=prefix):
                self.assertIsNone(validate_header("example.java", content, CANONICAL))

    def test_shebang_and_docker_parser_directive(self):
        comment = "\n".join("# " + line for line in CANONICAL.splitlines())
        for preamble in ("#!/bin/sh\n", "# syntax=docker/dockerfile:1.7\n"):
            self.assertIsNone(validate_header("example.sh", preamble + comment, CANONICAL))

    def test_missing_clause_and_altered_word_rejected(self):
        for text in (CANONICAL.replace("derived", "inherit"),
                     CANONICAL.replace("All rights reserved.", ""),
                     "Copyright (C) 2026, Leo Galambos. See LICENSE.md."):
            self.assertIsNotNone(validate_header("example.java", "/*" + text + "*/", CANONICAL))

    def test_license_after_code_does_not_count_as_header(self):
        self.assertIsNotNone(validate_header("example.java", "class Example {}\n/*" + CANONICAL + "*/", CANONICAL))

    def test_wrong_owner_rejected(self):
        self.assertIsNotNone(validate_header("example.java",
            "/*" + CANONICAL.replace("Leo Galambos", "ZeroEcho") + "*/", CANONICAL))

    def test_apache_exception_is_path_specific(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("gradlew", "gradlew.bat"):
            source = (root / name).read_text()
            self.assertIsNone(validate_header(name, source, CANONICAL))
            self.assertIsNotNone(validate_header("other.sh", source, CANONICAL))
            self.assertIsNotNone(validate_header(name, source.replace("WITHOUT WARRANTIES", "WITH WARRANTIES"), CANONICAL))

    def test_source_inventory_includes_build_and_frontend(self):
        for name in ("a.java", "a.tsx", "a.gradle", "Dockerfile", "a.sh", "a.yml"):
            self.assertTrue(source_path(Path(name)))
        self.assertFalse(source_path(Path("a.png")))

    def test_reviewed_foreign_notice_is_preserved_not_relicensed(self):
        source = "/* Copyright 2020 Another Author. Licensed under MIT. */\nclass Foreign {}"
        manifest = {"vendor/Foreign.java": {
            "origin": "upstream project, reviewed MIT notice",
            "header_sha256": hashlib.sha256(normalize(header_text(source)).encode()).hexdigest(),
        }}
        self.assertIsNone(validate_header("vendor/Foreign.java", source, CANONICAL, manifest))
        self.assertIsNotNone(validate_header("vendor/Foreign.java", source.replace("MIT", "BSD"), CANONICAL, manifest))
        self.assertIsNotNone(validate_header("vendor/Foreign.java", "/*" + CANONICAL + "*/", CANONICAL, manifest))


if __name__ == "__main__":
    unittest.main()
