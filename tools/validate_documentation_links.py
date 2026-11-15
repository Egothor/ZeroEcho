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
        """Collect anchors and URL attributes from an HTMLParser tag and attrs pair."""
        attributes = dict(attrs)
        if attributes.get("id"):
            self.anchors.add(attributes["id"])
        if tag == "a" and attributes.get("name"):
            self.anchors.add(attributes["name"])
        for attribute in ("href", "src"):
            if attributes.get(attribute):
                self.links.append(attributes[attribute])


def render(path, extensions, extension_configs):
    """Parse Markdown references at path using extensions and extension_configs.

    Returns a References parser; UTF-8 read and Markdown rendering errors propagate.
    """
    references = References()
    references.feed(markdown.markdown(path.read_text(encoding="utf-8"),
                                     extensions=extensions,
                                     extension_configs=extension_configs))
    return references


def navigation_paths(nav):
    """Yield page paths from a nested MkDocs nav string/list/mapping."""
    if isinstance(nav, str):
        yield nav
    elif isinstance(nav, list):
        for item in nav:
            yield from navigation_paths(item)
    elif isinstance(nav, dict):
        for item in nav.values():
            yield from navigation_paths(item)


def validate(root, paths, docs, nav, extensions, extension_configs, *,
             excluded=(), generated_modules=(), site=None):
    """Return local-link diagnostics for source pages and optional assembled output.

    Args:
        root: Repository boundary; links cannot escape it.
        paths: Markdown source files to inspect, including excluded files.
        docs: MkDocs source directory.
        nav: MkDocs navigation configuration.
        extensions: Markdown extension names used by MkDocs.
        extension_configs: Per-extension settings.
        excluded: Exact docs-relative source paths excluded from publication.
        generated_modules: Build-declared enabled Javadoc module names.
        site: Optional assembled-site directory, required for generated proof.

    Returns:
        Sorted unique diagnostics. Generated paths are deferred only in source mode.
    """
    root = root.resolve()
    docs = docs.resolve()
    errors = []
    rendered = {}
    excluded = set(excluded)
    site = Path(site).resolve() if site is not None else None

    def parsed(path):
        if path not in rendered:
            rendered[path] = render(path, extensions, extension_configs)
        return rendered[path]

    pages = set()
    for path in paths:
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            errors.append(f"{path}: source escapes repository")
        elif path.is_relative_to(docs) and not resolved.is_relative_to(docs):
            errors.append(f"{path}: source escapes docs directory")
        else:
            pages.add(resolved)
    pages = sorted(pages)
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
                generated = False
                if target.is_relative_to(docs):
                    relative = target.relative_to(docs)
                    parts = relative.parts
                    generated = (len(parts) >= 3 and parts[0] == "javadoc"
                                 and parts[1] in generated_modules
                                 and target.suffix.lower() in (".html", ".htm"))
                    if generated:
                        if site is None:
                            continue
                        target = (site / relative).resolve()
                        if not target.is_relative_to(site):
                            raise ValueError("target escapes assembled site")
                    elif not target.exists() or target.is_dir():
                        candidates = []
                        if target.is_dir() or not target.suffix:
                            candidates = [target / "index.md", target / "README.md", target / "index.html"]
                        elif target.suffix.lower() == ".html":
                            candidates = [target.with_suffix(".md")]
                            if target.name == "index.html":
                                candidates.append(target.parent / "README.md")
                        target = next((candidate for candidate in candidates
                                       if candidate.is_file()
                                       and candidate.relative_to(docs).as_posix() not in excluded), target).resolve()
                        if not target.is_relative_to(root):
                            raise ValueError("target escapes repository")
                        if source.is_relative_to(docs) and not target.is_relative_to(docs):
                            raise ValueError("site link escapes docs directory")
                    if (not generated and target != source
                            and target.relative_to(docs).as_posix() in excluded):
                        errors.append(f"{label}: target excluded from publication")
                        continue
                if not target.is_file():
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
        if (page.is_relative_to(docs) and page not in navigation
                and page.relative_to(docs).as_posix() not in excluded):
            errors.append(f"mkdocs.yml: {page.relative_to(docs)}: missing navigation entry")
    return sorted(set(errors))


def validate_site(site):
    """Return broken local links and anchors in an assembled HTML site.

    Args:
        site: Existing assembled publication root, including generated Javadocs.

    Returns:
        Sorted diagnostics; absent root/index, traversal and invalid encoding fail.
    """
    site = Path(site).resolve()
    if not (site / "index.html").is_file():
        return ["assembled site: missing index.html"]
    errors = []
    cache = {}

    def parsed(path):
        if path not in cache:
            references = References()
            references.feed(path.read_text(encoding="utf-8"))
            cache[path] = references
        return cache[path]

    for source in sorted(site.rglob("*.html")):
        if not source.resolve().is_relative_to(site):
            errors.append(f"assembled site/{source.relative_to(site)}: source escapes assembled site")
            continue
        for link in parsed(source).links:
            label = f"assembled site/{source.relative_to(site)}: {link}"
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
                target = ((site / path.lstrip("/")) if path.startswith("/")
                          else (source.parent / path if path else source)).resolve()
                if not target.is_relative_to(site):
                    raise ValueError("target escapes assembled site")
                if target.is_dir():
                    target = (target / "index.html").resolve()
                    if not target.is_relative_to(site):
                        raise ValueError("target escapes assembled site")
                if not target.is_file():
                    errors.append(f"{label}: missing target")
                elif fragment and target.suffix.lower() in (".html", ".htm"):
                    if fragment not in parsed(target).anchors:
                        errors.append(f"{label}: missing anchor")
            except (ValueError, UnicodeError) as failure:
                errors.append(f"{label}: {failure}")
    return sorted(set(errors))


def declared_javadoc_modules(root):
    """Return enabled Java-convention modules declared by this repository build.

    Args:
        root: Repository containing settings.gradle and module build.gradle files.

    Returns:
        Module names included by settings with a Java convention and enabled Javadoc.
        Unknown build shapes are not treated as evidence of generated targets.
    """
    settings = Path(root) / "settings.gradle"
    build = Path(root) / "build.gradle"
    if not settings.is_file() or not build.is_file():
        return set()
    assembly = build.read_text(encoding="utf-8")
    if "AssembleDocumentationSite" not in assembly or "javadoc.get().enabled" not in assembly:
        return set()
    includes = re.findall(r"include\(([^)]*)\)", settings.read_text(encoding="utf-8"))
    result = set()
    for declaration in includes:
        for name in re.findall(r"['\"]([A-Za-z0-9_-]+)['\"]", declaration):
            module = Path(root) / name / "build.gradle"
            if not module.is_file():
                continue
            text = module.read_text(encoding="utf-8")
            if (re.search(r"id ['\"]buildlogic\.java-(?:library|application)-conventions['\"]", text)
                    and not re.search(r"(?:named\(['\"]javadoc['\"]\)|javadoc)\s*(?:\.configure)?\s*\{\s*enabled\s*=\s*false", text)):
                result.add(name)
    return result


def main():
    """Run source validation and optional assembled-site proof; return nonzero on errors."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--site", type=Path,
                        help="assembled MkDocs plus Javadoc output; check generated targets/anchors")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    config = load_config(config_file=str(root / "mkdocs.yml"))
    listed = subprocess.run(["git", "-C", str(root), "ls-files", "-z",
                             "--cached", "--others", "--exclude-standard"],
                            check=True, capture_output=True).stdout
    paths = [root / name.decode("utf-8") for name in listed.split(b"\0")
             if name.endswith(b".md") and (root / name.decode("utf-8")).is_file()]
    from mkdocs.structure.files import get_files, InclusionLevel
    excluded = {file.src_uri for file in get_files(config)
                if file.inclusion == InclusionLevel.EXCLUDED}
    errors = validate(root, paths, Path(config["docs_dir"]), config["nav"],
                      config["markdown_extensions"], config["mdx_configs"],
                      excluded=excluded, generated_modules=declared_javadoc_modules(root),
                      site=arguments.site)
    if arguments.site is not None:
        errors = sorted(set(errors + validate_site(arguments.site)))
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Documentation links: {len(paths)} Markdown files, {len(errors)} errors")
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
