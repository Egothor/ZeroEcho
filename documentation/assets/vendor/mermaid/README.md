# Mermaid runtime

This is the unmodified standalone UMD bundle from **Mermaid 11.17.2**,
the maintained major version used by Material for MkDocs 9.7.7.

- Upstream: https://github.com/mermaid-js/mermaid/tree/mermaid%4011.17.2
- Distribution: https://registry.npmjs.org/mermaid/-/mermaid-11.17.2.tgz
- Bundle within distribution: `package/dist/mermaid.min.js`
- License: MIT; see the adjacent `LICENSE` and retained bundled dependency notices.
- Bundle SHA-256: `581ed7d74bd9048d0e3a91363927d72ef22942d7722546b27f7cc29e35390eb8`
- npm distribution integrity: `sha512-V6K3C8EBdEsPFZXSKMJe6ppQOENxuHARr9GvHX4hh47lAbhMRD9qf4oEK7LoaRQxULMa80/qt5gHO73aCleBBg==`

The theme override loads this local global runtime synchronously before Material
and immediately initializes it with `startOnLoad: false`. This disables the
standalone bundle's automatic window-load renderer, which would otherwise race
Material and parse Markdown's surrounding `<code>` markup as diagram syntax.
Material then owns themed initialization, rendering and navigation updates;
its optional runtime CDN download is consequently unnecessary. No custom diagram
renderer or relaxed Mermaid security settings are installed.

When upgrading, retain the standalone bundle and upstream notices, update these
fingerprints and the third-party source record, and render every documentation
diagram in a browser with external requests blocked before publishing.
