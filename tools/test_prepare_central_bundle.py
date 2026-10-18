#!/usr/bin/env python3
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
"""Offline contract tests for Central release versions and ZIP contents."""

from pathlib import Path
import tempfile
import unittest
import zipfile

from prepare_central_bundle import MODULES, prepare_bundle, release_version


class CentralBundleTest(unittest.TestCase):
    """Exercise release boundaries, expected artifacts and incomplete repositories."""

    def test_release_tags(self):
        """Accept zero and regular versions; reject paths, suffixes and padded values."""
        for tag, expected in [('release@0.0.0', '0.0.0'), ('release@12.3.45', '12.3.45')]:
            self.assertEqual(expected, release_version(tag))
        for tag in ['v1.2.3', 'release@1.2', 'release@01.2.3', 'release@1.2.3-SNAPSHOT', 'release@../x']:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release_version(tag)

    def test_complete_bundle_and_missing_signature(self):
        """Include only signed Maven artifacts/checksums and fail without any signature."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / 'repo'
            for module in MODULES:
                directory = repository / 'org/egothor' / f'ZeroEcho-{module}' / '1.2.3'
                directory.mkdir(parents=True)
                for suffix in ('.pom', '.jar', '-sources.jar', '-javadoc.jar'):
                    artifact = directory / f'ZeroEcho-{module}-1.2.3{suffix}'
                    artifact.write_bytes(b'artifact')
                    Path(str(artifact) + '.asc').write_bytes(b'signature')
                (directory / 'maven-metadata.xml').write_text('excluded')
            internal = repository / 'org/egothor/ZeroEcho-api-spec/1.2.3'
            internal.mkdir(parents=True)
            (internal / 'ZeroEcho-api-spec-1.2.3.jar').write_bytes(b'internal tool')
            output = root / 'bundle.zip'
            prepare_bundle(repository, output, '1.2.3')
            with zipfile.ZipFile(output) as bundle:
                names = bundle.namelist()
                self.assertEqual(80, len(names))
                self.assertFalse(any('ZeroEcho-api-spec' in name for name in names))
                self.assertFalse(any('metadata' in name or '.asc.' in name for name in names))
                self.assertEqual(b'8e5b948a454515dbabfc7eb718daa52f', bundle.read(
                    'org/egothor/ZeroEcho-lib/1.2.3/ZeroEcho-lib-1.2.3.jar.md5'))
            signature = repository / 'org/egothor/ZeroEcho-lib/1.2.3/ZeroEcho-lib-1.2.3.jar.asc'
            signature.unlink()
            with self.assertRaises(ValueError):
                prepare_bundle(repository, output, '1.2.3')


if __name__ == '__main__':
    unittest.main()
