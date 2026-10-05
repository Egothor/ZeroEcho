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
"""Validate repository Markdown links and MkDocs navigation without network I/O.

Uses the installed documentation requirements and the same Markdown extensions as
MkDocs. Run from any directory; pass --root for a fixture or another checkout.
"""

import argparse
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

import markdown
from mkdocs.config import load_config


class References(HTMLParser):
    """Collect browser-visible anchors and references from rendered Markdown."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors = set()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if attributes.get("id"):
            self.anchors.add(attributes["id"])
        if tag == "a" and attributes.get("name"):
            self.anchors.add(attributes["name"])
        for attribute in ("href", "src"):
            if attributes.get(attribute):
                self.links.append(attributes[attribute])


def render(path, extensions, extension_configs):
    references = References()
    references.feed(markdown.markdown(path.read_text(encoding="utf-8"),
                                     extensions=extensions,
                                     extension_configs=extension_configs))
    return references


def navigation_paths(nav):
    if isinstance(nav, str):
        yield nav
    elif isinstance(nav, list):
        for item in nav:
            yield from navigation_paths(item)
    elif isinstance(nav, dict):
        for item in nav.values():
            yield from navigation_paths(item)


def validate(root, paths, docs, nav, extensions, extension_configs):
    """Return deterministic diagnostics; local targets never escape root."""
    root = root.resolve()
    docs = docs.resolve()
    errors = []
    rendered = {}

    def parsed(path):
        if path not in rendered:
            rendered[path] = render(path, extensions, extension_configs)
        return rendered[path]

    pages = sorted(set(path.resolve() for path in paths))
    for source in pages:
        for link in parsed(source).links:
            label = f"{source.relative_to(root)}: {link}"
            try:
                url = urlsplit(link)
                if url.scheme or url.netloc:
                    continue
                if re.search(r"%(?![0-9a-fA-F]{2})", link):
                    raise ValueError("malformed percent escape")
                path = unquote(url.path, errors="strict")
                fragment = unquote(url.fragment, errors="strict")
                if "\x00" in path or "\\" in path:
                    raise ValueError("invalid local path")
                target = ((docs / path.lstrip("/")) if path.startswith("/")
                          else (source.parent / path if path else source)).resolve()
                if not target.is_relative_to(root):
                    raise ValueError("target escapes repository")
                if source.is_relative_to(docs) and not target.is_relative_to(docs):
                    raise ValueError("site link escapes docs directory")
                if not target.exists():
                    errors.append(f"{label}: missing target")
                elif fragment and target.suffix.lower() == ".md":
                    if fragment not in parsed(target).anchors:
                        errors.append(f"{label}: missing anchor")
                elif fragment and target.suffix.lower() in (".html", ".htm"):
                    html = References()
                    html.feed(target.read_text(encoding="utf-8"))
                    if fragment not in html.anchors:
                        errors.append(f"{label}: missing anchor")
            except (ValueError, UnicodeError) as failure:
                errors.append(f"{label}: {failure}")
    navigation = set()
    for entry in navigation_paths(nav):
        url = urlsplit(entry)
        if url.scheme or url.netloc:
            continue
        target = (docs / unquote(url.path)).resolve()
        if not target.is_relative_to(docs) or not target.is_file():
            errors.append(f"mkdocs.yml: {entry}: invalid navigation target")
        navigation.add(target)
    for page in pages:
        if page.is_relative_to(docs) and page not in navigation:
            errors.append(f"mkdocs.yml: {page.relative_to(docs)}: missing navigation entry")
    return sorted(set(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    config = load_config(config_file=str(root / "mkdocs.yml"))
    listed = subprocess.run(["git", "-C", str(root), "ls-files", "-z",
                             "--cached", "--others", "--exclude-standard"],
                            check=True, capture_output=True).stdout
    paths = [root / name.decode("utf-8") for name in listed.split(b"\0")
             if name.endswith(b".md") and (root / name.decode("utf-8")).is_file()]
    errors = validate(root, paths, Path(config["docs_dir"]), config["nav"],
                      config["markdown_extensions"], config["mdx_configs"])
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Documentation links: {len(paths)} Markdown files, {len(errors)} errors")
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
