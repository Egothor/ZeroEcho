# Offline worker shim

Unmodified standalone shim from **iframe-worker 1.0.4**, used by Material for
MkDocs' bundled offline plugin to support search under `file://`.

- Upstream: https://github.com/squidfunk/iframe-worker
- Distribution: https://registry.npmjs.org/iframe-worker/-/iframe-worker-1.0.4.tgz
- Bundle within distribution: `package/shim/index.js`
- License: MIT; see the adjacent upstream `LICENSE`.
- Bundle SHA-256: `e8e412dbcfea9b7e31b5ffa288d7b6035915e714c542f4176a0cdbe262fc9609`
- npm distribution integrity: `sha512-roeaaI+Lg1LJNfgpCjoRe/+WzEjy9+Z08LoEvu85MCPbBjwm+qXz8Ag5U05lHa6V1CysZyGzE0SOkAtSUA5q7Q==`

The local path is configured through Material's `extra.polyfills` setting.
Its filename includes `iframe-worker`, so the offline plugin uses it instead of
adding an unpinned CDN URL. The shim replaces `Worker` only for the `file:`
protocol. Published HTTPS pages continue to use native browser workers.

When upgrading, preserve the upstream source and license, update these hashes
and the third-party source manifest, and verify real offline search and Mermaid
rendering as well as ordinary HTTPS behavior.
