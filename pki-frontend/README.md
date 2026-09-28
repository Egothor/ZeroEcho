# ZeroEcho PKI Frontend (`pki-frontend`)

A professional, descriptor-driven **single-page administration console** for the
ZeroEcho `pki-server` admin API, plus a **demo mode** for reviewing the whole
console without a server or client certificate.

This is a static SPA bundle. It is **not** a Java/JPMS module — it has no
`module-info.java`, does not participate in the module graph, and is unaffected by
the `verifyBouncyCastleConfinement` gate. It compiles against nothing in
`pki-server`; it consumes the HTTP admin API at runtime only.

## What it does

- Renders typed, validated forms for the **entire** server operation catalog
  (107 operations — 41 PKI, 10 signing, 56 control), grouped into administration areas
  (authorities, issuer generations, profiles, requests, issuance, lifecycle,
  revocation, status/CRLs, publication, principals, roles & grants, approvals,
  break-glass, disclosure, audit, ACME, OCSP, repository aliases, configuration),
  plus an **Operations Explorer** covering every operation and a **public
  repository** browser.
- Executes operations with the server's real semantics: synchronous bounded wait,
  `202 PENDING` signing hand-off (polls `/admin/v1/signing-operations/{id}`), and
  the `409 APPROVAL_REQUIRED` dual-control flow.
- Is **discoverability-aware**: it reflects `GET /admin/v1/operations` so a
  principal sees the operations they may invoke; the UI never grants authority —
  the server authorizes every request.

## Technology

React 19 + TypeScript + Vite + MUI (Material UI, with MUI X DataGrid for result
tables) + TanStack Query + React Router. The
[capability reference](docs/backend-gap-analysis.md) describes the implemented
administration surface and its current boundaries.

## Prerequisites

- **Node 22.11+** and npm (for local development). The Gradle build downloads a
  pinned Node itself (see below), so a system Node is not required for CI.

## Develop

```bash
npm install
npm run dev          # Vite dev server on http://localhost:5173
```

Point the dev proxy at a running server with `VITE_DEV_API_TARGET` (defaults to
`https://localhost:8443`). Same-origin `/admin`, `/public`, `/health`, `/account`
requests are proxied there.

## Demo mode (no server, no certificate)

Demo mode swaps the network transport for an **in-browser mock backend** with a
**persona switcher** (Administrator / Operator / Issuer / Auditor / Ordinary user)
so you can walk the entire console and see how discoverability and available
actions change per identity. It also powers the browser e2e suite.

Enable it by:

- appending `?demo=1` to the URL (persists for the session; `?demo=0` clears it), or
- building with `VITE_DEMO=true` for a standalone demo bundle.

```bash
npm run build && npm run preview   # then open http://localhost:4173/?demo=1
```

## Build, test, lint

```bash
npm run typecheck    # tsc, app + node configs
npm run lint         # eslint (flat config, typescript-eslint)
npm run test:ci      # vitest unit tests + coverage
npm run build        # production bundle -> dist/
npm run test:e2e     # Playwright browser tests (demo mode by default)
```

Unit tests cover the API client, the operation catalog integrity (asserts the
full 107-operation contract), request-envelope construction (realm vs authority
scoping), and the demo backend (persona discoverability, denial, approval flow).
The default Playwright suite drives a real browser against the built demo bundle.
`E2E_BASE_URL` changes where that bundle is served and disables the preview server;
the demo tests still use the mock backend. The separate live fixture below
exercises the actual PKI backend without demo mode.

## Gradle integration

`pki-frontend` is a Gradle subproject wired via the `gradle-node-plugin` with a
**pinned, downloaded Node toolchain** (so `./gradlew :pki-frontend:build` is
self-contained and reproducible on a build host with no system Node):

```bash
./gradlew :pki-frontend:build        # npm ci -> typecheck -> lint -> unit test -> vite build -> zip
./gradlew :pki-frontend:npmBuild     # just the SPA bundle (dist/)
./gradlew :pki-frontend:npmE2e -PrunFrontendE2e   # opt-in browser e2e
./gradlew :pki-server:frontendIntegrationTest   # opt-in real backend fixture
```

`check` runs typecheck + lint + unit tests; `assemble` builds the bundle and a
`zeroecho-pki-frontend-*.zip` distributable consumed by the container image.

The live gate builds the SPA with the pinned Node toolchain, starts a temporary
PKI HTTPS server and keyring, and runs a separate Playwright scenario. Install
the Playwright Chromium browser beforehand, or pass
`-PfrontendBrowser=/absolute/path/to/chromium`. An explicit Node executable can
be supplied with `-PfrontendNode=/absolute/path/to/node`.

The fixture verifies known-value selections, two-principal approval binding,
root/intermediate CA signing and receipt recovery after a network failure or
local timeout, with one accepted signing POST per operation. A component test
also checks exact confirmation-proof CAS handoff. The test-only loopback HTTP
bridge forwards fixed API routes over verified mTLS using separate requester
and approver identities. Browser certificates, nginx forwarding and packaged
deployment are verified by the [packaged deployment gate](e2e/packaged/README.md);
this fixture does not verify those boundaries.

## Deployment

The SPA is served at the deployment edge by **nginx**, which terminates the
browser's client certificate (mTLS), forwards the verified identity per RFC 9440,
and reverse-proxies the API to `pki-server` (which stays API-only). The container
image, data/config contract, compose/k8s manifests, and smoke test live under
`deploy/` — see `deploy/README.md`.

## Security model

- Static bundle with **no secrets**; authentication is the TLS client certificate
  presented to nginx. The SPA holds no token and caches no authorization decision.
- All authorization is server-side and enforced per request; hidden or disabled
  controls are **not** an authorization boundary.
- Self-hosted assets (no CDN), strict CSP/HSTS at the UI origin (see `deploy/`),
  pinned npm lockfile.

## Capability boundaries

The [capability reference](docs/backend-gap-analysis.md) describes current backend
support. Known identities are available through selection APIs; advanced search
filters and other unapproved extensions belong to the single
[outstanding-work plan](../docs/project-work-plan.md).

### Selections and signing receipts

Existing PKI identities use searchable, paged selections with readable names and
exact identifiers. Authority/profile/issuer changes clear dependent choices.
Read failures remain visible; an unavailable list does not enable arbitrary IDs.
New subjects, imported documents and external key references remain authorable.
See [selection API contract](docs/selection-api.md) for permissions and paging.

The ten signing operations submit once and receive HTTP 202 with an operation ID.
The client polls the fixed same-origin signing-operation route sequentially for
up to 30 seconds. Local timeout/network failure retains the accepted receipt;
**Check status** resumes polling without resubmitting. Completed receipts show
kind, encoding, SHA-256 and optional credential/status identifiers. HTTP 409 alone
does not mean approval is required.

Approval preparation carries typed arguments and authority from the original
request. Confirmation completion carries the exact server-issued CAS values.
ACME policy sets come from the active profile; validity defaults to its maximum
within the existing 398-day limit and permits an explicit shorter policy.
