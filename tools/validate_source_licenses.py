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
"""Check complete first-party source license headers without changing files.

The canonical terms are LICENSE-source.txt. Copyright years are preserved.
Third-party paths and their original notice fingerprints are recorded in
third_party_source_licenses.json; new foreign sources require provenance review,
never replacement of their notices with the project's license.
Tracked and non-ignored untracked source files are checked; generated build
outputs and dependencies ignored by Git are outside the source distribution.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

SOURCE_SUFFIXES = frozenset({
    ".java", ".kt", ".kts", ".groovy", ".gradle", ".ts", ".tsx", ".js",
    ".jsx", ".mjs", ".cjs", ".py", ".sh", ".bash", ".bat", ".ps1", ".css",
    ".scss", ".html", ".c", ".h", ".cpp", ".hpp", ".rs", ".go",
    ".yaml", ".yml",
})
THIRD_PARTY = json.loads(Path(__file__).with_name("third_party_source_licenses.json").read_text())


def source_path(path):
    """Recognize maintained source, executable launchers and build recipes."""
    return path.suffix.lower() in SOURCE_SUFFIXES or path.name in {
        "Dockerfile", "gradlew",
    }


def header_text(source):
    """Read only a leading comment, after an optional shebang or HTML doctype."""
    source = source.lstrip("\ufeff")
    if source.startswith("#!"):
        source = source.partition("\n")[2]
    source = source.lstrip()
    if source.lower().startswith("<!doctype"):
        source = source.partition(">")[2].lstrip()
    if source.startswith("/*"):
        end = source.find("*/")
        return source[2:end] if end >= 0 else ""
    if source.startswith("<!--"):
        end = source.find("-->")
        return source[4:end] if end >= 0 else ""
    lines = []
    for line in source.splitlines():
        stripped = line.lstrip()
        if stripped.startswith(("#", "//")) or re.match(r"(?i)@?rem(?:\s|$)", stripped):
            lines.append(stripped)
        elif not stripped:
            lines.append("")
        else:
            break
    return "\n".join(lines)


def normalize(header):
    """Ignore comment decoration and wrapping, never words or punctuation."""
    text = re.sub(r"(?im)^\s*(?:\*+|//|\#+|@?rem\b)\s?", "", header)
    return " ".join(text.split())


def validate_header(path, source, canonical, third_party=None):
    """Return a diagnostic for a missing, altered or misattributed header."""
    header = normalize(header_text(source))
    notices = THIRD_PARTY if third_party is None else third_party
    if path in notices:
        notice = notices[path]
        if not notice.get("origin") or hashlib.sha256(header.encode()).hexdigest() != notice.get("header_sha256"):
            return "third-party notice differs from its reviewed provenance record"
        return None
    notice = re.search(r"Copyright \([Cc]\) [0-9]{4}(?:[-–][0-9]{4})?, Leo Galambos\s+", header)
    if notice is None:
        return "missing leading copyright notice naming Leo Galambos"
    expected = normalize(canonical).split("All rights reserved.", 1)[1]
    actual = header[notice.end():]
    if not actual.startswith("All rights reserved." + expected):
        return "source license differs from the complete LICENSE-source.txt terms"
    return None


def validate(root):
    """Return checked-file count and deterministic path-qualified diagnostics."""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others",
         "--exclude-standard", "-z"],
        check=True, capture_output=True,
    )
    paths = sorted(set(result.stdout.decode("utf-8").split("\0")) - {""})
    canonical = (root / "LICENSE-source.txt").read_text(encoding="utf-8")
    notices = json.loads((root / "tools/third_party_source_licenses.json").read_text(encoding="utf-8"))
    errors = []
    checked = 0
    for relative in paths:
        path = root / relative
        if not source_path(path):
            continue
        checked += 1
        if path.is_symlink() or not path.is_file():
            errors.append(f"{relative}: source must be a regular file")
            continue
        problem = validate_header(relative, path.read_text(encoding="utf-8"), canonical, notices)
        if problem:
            errors.append(f"{relative}: {problem}")
    return checked, errors


def main():
    """Validate the selected repository and return a CI-compatible exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    checked, errors = validate(args.root.resolve())
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Source licenses: {checked} files, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
