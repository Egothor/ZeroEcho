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
"""Validate a signed Maven repository and produce a Central Publisher ZIP offline."""

import argparse
import hashlib
from pathlib import Path
import re
import zipfile

MODULES = ('app', 'ext', 'lib', 'pki', 'pki-server')


def release_version(tag):
    """Return x.y.z from a release@x.y.z tag; raise ValueError for invalid tags."""
    if not re.fullmatch(r'release@(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', tag):
        raise ValueError('Expected release@x.y.z with nonnegative, unpadded integers')
    return tag.removeprefix('release@')


def prepare_bundle(repository, output, version):
    """Validate five signed module publications and ZIP artifacts with MD5/SHA1 checksums.

    repository and output are Paths; version is a release version. Raises ValueError
    for incomplete publications. Reads only the expected org.egothor coordinates;
    Gradle metadata and checksum sidecars are excluded. No network calls occur.
    """
    release_version('release@' + version)
    artifacts = []
    for module in MODULES:
        stem = f'ZeroEcho-{module}-{version}'
        directory = repository / 'org' / 'egothor' / f'ZeroEcho-{module}' / version
        for suffix in ('.pom', '.jar', '-sources.jar', '-javadoc.jar'):
            artifact = directory / (stem + suffix)
            signature = Path(str(artifact) + '.asc')
            if not artifact.is_file() or not signature.is_file():
                raise ValueError(f'Missing artifact or signature: {artifact}')
            if artifact.stat().st_size == 0 or signature.stat().st_size == 0:
                raise ValueError(f'Empty artifact or signature: {artifact}')
            artifacts.extend((artifact, signature))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
        for artifact in artifacts:
            name = artifact.relative_to(repository).as_posix()
            content = artifact.read_bytes()
            bundle.writestr(name, content)
            if not name.endswith('.asc'):
                for algorithm in ('md5', 'sha1'):
                    bundle.writestr(name + '.' + algorithm,
                                    hashlib.new(algorithm, content).hexdigest())


def main():
    """Parse CLI paths/version or tag, returning normally on success and raising on error."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag')
    parser.add_argument('--repository', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--version')
    args = parser.parse_args()
    if args.tag:
        print(release_version(args.tag))
    elif args.repository and args.output and args.version:
        prepare_bundle(args.repository, args.output, args.version)
    else:
        parser.error('Provide --tag or --repository, --output and --version')


if __name__ == '__main__':
    main()
