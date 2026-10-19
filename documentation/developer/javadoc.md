# Java API documentation

Each Java module has its own generated reference. Start with `lib` for the
cryptographic framework and SDK, or `pki` for certificate-authority services
and provider contracts. The [module map](modules.md) explains their dependencies.

<table>
<thead><tr><th>Module</th><th>Reference</th></tr></thead>
<tbody>
<tr><td><a href="../javadoc/lib/index.html"><code>lib</code></a></td><td>Cryptographic core, SDK, keyring and PKIX building blocks.</td></tr>
<tr><td><a href="../javadoc/ext/index.html"><code>ext</code></a></td><td>Content export, steganography and covert-channel integrations.</td></tr>
<tr><td><a href="../javadoc/pki/index.html"><code>pki</code></a></td><td>Certificate-authority domain, application services and provider SPIs.</td></tr>
<tr><td><a href="../javadoc/pki-server/index.html"><code>pki-server</code></a></td><td>HTTPS server and enrollment, trust, TLS and certificate-transparency extension contracts.</td></tr>
<tr><td><a href="../javadoc/app/index.html"><code>app</code></a></td><td>Command-line application implementation reference.</td></tr>
<tr><td><a href="../javadoc/api-spec/index.html"><code>api-spec</code></a></td><td>Internal OpenAPI generation tooling.</td></tr>
</tbody>
</table>

Application and build-tool modules are included for implementation reference;
they are not additional public library APIs. `samples` contains demonstration
tests and has no main-source JavaDoc. `pki-frontend` is a TypeScript application.

## Stable reference paths

The published references live under
`https://www.egothor.org/ZeroEcho/javadoc/<module>/`. This dedicated subtree
keeps generated files separate from the handwritten guides. Use the module
links above as entry points; JavaDoc itself supplies the package and type paths.

## Build and preview the complete site

Install the pinned documentation tools from `documentation/requirements.txt`,
then run these commands from the repository root with JDK 25 available:

```sh
python -m mkdocs build --strict
./gradlew assembleDocumentationSite --no-daemon
python -m http.server --directory build/documentation-site
```

The combined directory contains both the guides and all enabled module
references. Preview that directory rather than MkDocs' intermediate `site/`
directory, which does not contain the generated JavaDoc.

You can also open `build/documentation-site/index.html` directly using
`file://`. Diagram rendering and search use bundled local assets, so this
preview does not require a network connection.

The documentation workflow builds this same combined artifact for pull
requests. Changes on `main` and manual runs on the default branch deploy it
to GitHub Pages. In the repository's **Settings → Pages**, set **Source** to
**GitHub Actions**. The organization website supplies the custom domain;
this project does not add its own `CNAME` file.
