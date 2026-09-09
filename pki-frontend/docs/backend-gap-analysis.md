# ZeroEcho PKI Frontend — capability coverage and backend gap analysis

This document records what the ZeroEcho administration frontend covers relative
to the reference enterprise product (**EJBCA**), and — where a workflow a serious
PKI administrator expects is **not** fully supported by the `pki-server` backend
today — specifies exactly which backend methods should be added, including their
request/response shape, semantics, and security, so the frontend can offer them.

The bar set by the owner: the web interface must offer **at least** the
functionality EJBCA offers. Where the backend cannot yet support a feature, the
gap is listed here with an implementable specification.

## Method

- The frontend is **descriptor/catalog driven**: it renders typed forms for the
  full server operation catalog (101 operations — 47 PKI, 54 control) and runs
  them with the server's synchronous bounded-wait / `PENDING` / `APPROVAL_REQUIRED`
  semantics. See `src/api/operationCatalog.ts`.
- EJBCA is used as the feature benchmark (Community + Enterprise). Each EJBCA
  functional area is mapped to the ZeroEcho operation(s) and UI that cover it.
- Status legend: **✓ covered**, **◐ partial**, **✗ gap (backend addition needed)**,
  **∅ intentional non-goal** (documented, not a defect).

## Coverage matrix

| EJBCA area | ZeroEcho coverage | Status |
|---|---|---|
| CA management (create root/sub, activate/suspend/retire) | `ca.create`, `ca.intermediate.create`, `ca.intermediate.issue`, `ca.transition`, `ca.inspect`, `ca.list` | ✓ |
| CA key rollover / renewal / rotation | `ca.rollover`, `ca.rotate`, issuer generations `issuer.*` | ✓ |
| Certificate profiles | `profile.register`, `profile.validate`, `profile.inspect`, `profile.list`, `profile.activate` | ✓ |
| End-entity profiles (enrollment constraints) | Partially expressed via certificate profiles + issuance approval requirements | ◐ (GAP-3) |
| Certificate issuance from CSR | `request.import`, `request.verify`, `request.inspect`, `credential.issue` | ✓ |
| Certificate lifecycle (renew/rekey/replace) | `credential.renew`, `credential.replace`, `credential.reissue` | ✓ |
| Revocation + reasons, reactivation from hold | `credential.revoke` (RFC 5280 reasons incl. `CERTIFICATE_HOLD`/`REMOVE_FROM_CRL`), `revocation.inspect`, `revocation.history` | ✓ |
| CRL / delta CRL generation & inspection | `status.generate` (`CRL`/`DELTA_CRL`), `status.inspect`, `inventory.status`, `revocation.snapshot` | ✓ |
| **Certificate search** (by subject/SAN/serial/status) | Only lookup by id (`credential.inspect`) + `inventory.status` by issuer | ✗ (GAP-1) |
| OCSP responder administration | `ocsp.responder.register/inspect/list/activate/deactivate` | ✓ |
| Publishers / publication | `publication.register/process/retry/reconcile/inspect/list`, `repository.alias.*` | ✓ (config of publisher endpoints is server-config, ◐ GAP-6) |
| ACME | `acme.directory.*`, `acme.account.*` + the ACME protocol listener | ✓ |
| EST / SCEP / CMP enrollment protocols | Not present (ACME is the supported automated protocol) | ✗ (GAP-4) |
| Approvals (dual control) | `security.approval.request/inspect/list/approve/reject/cancel`, HIGH_RISK `APPROVAL_REQUIRED` flow | ✓ |
| Roles & access rules (RBAC) | `security.role-template.*`, `security.role-assignment.*`, `security.grant.*`, `security.authorization.evaluate` | ✓ |
| Administrators / principals | `security.principal.*` | ✓ |
| Admin authentication | mTLS (DIRECT_MTLS / TRUSTED_REVERSE_PROXY, RFC 9440) | ✓ |
| Break-glass / emergency access | `security.break-glass.*` | ✓ (exceeds EJBCA) |
| Audit trail + integrity | `security.audit.search`, `security.audit-view.inspect-*`, `security.audit.verify-integrity` | ✓ (cryptographic chain integrity exceeds EJBCA) |
| Disclosure / publication capability control | `security.disclosure.*`, `certificate.publication.enroll` | ✓ (exceeds EJBCA) |
| Crypto token / HSM management | Keyring + remote signing configured via server-config, not an admin API | ∅ / ◐ (GAP-7) |
| Key recovery / archival | Not a feature (keys stay with the subject / remote signer) | ∅ |
| Validators (pre-issuance checks) | Expressed inside certificate profiles / algorithm bindings (`algorithm.binding.*`) | ◐ |
| Scheduled services (auto CRL, etc.) | Generation is triggered (`status.generate`); scheduling is deployment concern | ◐ (GAP-5) |
| Dashboard statistics / counts | Discoverable-operation counts + per-domain views; no aggregate metrics endpoint | ✗ (GAP-2) |
| System configuration view/validate | `configuration.validate`, `algorithm.binding.validate`; container `--validate-config` | ✓ |
| REST API | Admin HTTP API (`/admin/v1/...`) | ✓ |
| CLI (automation) | `zeroecho pki` — local in-process **and** remote WebAPI mode (`--url` + mTLS) | ✓ |

## Gaps requiring backend additions

Each gap below is written as an implementable backend work item.

### GAP-1 — Certificate/credential search operation (highest priority)

**Problem.** EJBCA's most-used RA/admin screen is *Search End Entities / Search
Certificates* (by subject DN, SAN, serial, status, profile, issuer, validity
window). ZeroEcho exposes lookup **by id** (`credential.inspect`) and a per-issuer
`inventory.status`, but **no general certificate search**. Notably the permission
vocabulary already reserves `Permission.Action.CERTIFICATE_SEARCH`, but no
operation consumes it — the capability is named yet unexposed.

**Proposed operation.** `credential.search` (family `PKI_OPERATION`, non-mutating,
`Permission.Action.CERTIFICATE_SEARCH`, resource `CERTIFICATE`, `approval NONE`,
authority-scoped or realm-wide by `authorityId` presence).

Request `arguments`:
```
{
  "subjectContains":   string?,     // substring/DN match
  "serial":            string?,     // hex serial, exact
  "sanContains":       string?,     // subjectAltName substring
  "state":             enum?,       // VALID | REVOKED | EXPIRED | HELD
  "profileId":         string?,
  "issuerCaId":        pkiId?,
  "issuedAfter":       instant?,
  "issuedBefore":      instant?,
  "expiresBefore":     instant?,
  "afterExclusive":    string?,     // opaque pagination cursor
  "limit":             integer      // required, bounded
}
```
Response `result`: `{ "credentials": [ {credentialId, subject, serial, state,
issuerCaId, notBefore, notAfter, profileId} ... ], "nextCursor": string? }`.

**Semantics.** Deterministic ordering (e.g. issuance time desc, then id) for
stable cursor pagination; results filtered to the caller's authorized scope and
data view (`DataView`); PII/content fields gated by `CERTIFICATE_READ_PII` /
`CERTIFICATE_READ_CONTENT`. Once added, the frontend replaces the id-only lookup
on the Issuance and Revocation screens with a full search grid.

**Reference-picker support (related).** The frontend renders reference fields
(e.g. `caId`, `principalId`, `grantId`, `publicationId`) as **type-to-search
pickers** backed by each entity's list operation. This works today for entities
that have a realm-wide list operation (authorities, principals, grants, role
assignments/templates, approvals, break-glass, publications, ACME directories/
accounts, OCSP responders, algorithm bindings). It **cannot** yet suggest for
entities that lack such an operation — **credentials, requests, certificate
profiles (list-all), issuer generations, status objects, chain paths** — where
the field falls back to free-entry search. Adding list/search operations for
these (credentials via GAP-1; a `profile.list-all`, `request.list`,
`issuer.generation.list`, `status.list-all`) would make every reference field a
true picker. These are the concrete, prioritised list operations the frontend
needs.

### GAP-2 — Machine-readable operation parameter schema

**Problem.** `GET /admin/v1/operations` descriptors carry only *security* metadata
(`operation, family, mutating, resourceType, approval, dataView`). The input
parameter contract (field names, types, enums, required/optional, per-argument
constraints) lives only in the server decoder `HttpOperationCodec`. The frontend
therefore ships a **client-side mirror** of that contract
(`src/api/operationCatalog.ts`) that must be kept in lockstep with the server by
hand — a maintenance and correctness hazard.

**Proposed addition.** Publish the parameter schema from the server, either by
extending each descriptor with a `parameters` array or by adding
`GET /admin/v1/operations/{id}/schema`:
```
{
  "operation": "credential.revoke",
  "scope": "authority",            // realm | authority
  "authorityFrom": "credentialId?",// argument that supplies authorityId, if any
  "parameters": [
    {"name":"credentialId","type":"pkiId","required":true},
    {"name":"reason","type":"enum","required":true,"choices":["UNSPECIFIED", ...]},
    {"name":"justification","type":"text","required":false,"maxLength":4096}
  ]
}
```
Types mirror the decoder primitives (`text, pkiId, integer, long, boolean, enum,
enumSet, stringSet, instant, base64, object`). This lets the frontend drop its
mirror and become truly server-driven, and guarantees the UI can never drift from
the server contract. **This is the single highest-leverage backend change for the
frontend.**

### GAP-3 — End-entity profile / enrollment-constraint object

**Problem.** EJBCA separates *certificate profiles* (technical certificate shape)
from *end-entity profiles* (which fields an enroller may/must set, allowed CAs,
allowed certificate profiles, default validity, subject DN constraints). ZeroEcho
has certificate profiles + per-profile issuance approval requirements, but no
first-class enrollment-constraint object, so RA self-service enrollment cannot be
constrained as richly.

**Proposed addition.** An enrollment-profile object and operations
`enrollment.profile.register/inspect/list/activate` describing: allowed issuer
CAs, allowed certificate profiles, subject-DN and SAN policy (required/optional/
fixed), default and max validity, and approval requirement. The `credential.issue`
path would validate requests against the referenced enrollment profile.

### GAP-4 — Additional enrollment protocols (EST / SCEP / CMP)

**Problem.** EJBCA supports EST (RFC 7030), SCEP, and CMP (RFC 4210) in addition
to ACME. ZeroEcho supports ACME only.

**Proposed addition (if required by target deployments).** Protocol listeners +
admin operations mirroring the ACME model: e.g. `est.profile.register/...`,
`cmp.alias.register/...`, each binding an authority + certificate profile +
authentication policy, surfaced under new nav areas. Priority depends on whether
device/enterprise enrollment beyond ACME is in scope; flagged, not assumed.

### GAP-5 — Scheduled / recurring status generation

**Problem.** EJBCA "Services" can auto-generate CRLs on a schedule. ZeroEcho
`status.generate` is caller-triggered; scheduling is left to an external cron.

**Proposed addition.** Either document the external-scheduler pattern as the
supported approach (deployment concern), or add `schedule.*` operations (register
a recurring CRL/delta generation per issuer with a cadence) so the schedule is
visible and manageable in the UI. Recommended: document externally for the RC;
add operations later if operators need in-product scheduling.

### GAP-6 — Publisher endpoint configuration as data

**Problem.** Publication *records* are managed via `publication.*`, but the
concrete publisher endpoints (LDAP/HTTP/object-store targets and credentials) are
configured in `server-config.json`, not through an admin API. EJBCA manages
publishers as first-class configurable objects in the UI.

**Proposed addition (optional).** `publisher.register/inspect/list/activate`
operations describing a named target (type + connection + auth-by-env-secret),
referenced by `publication.register`. Until then the frontend documents that
publisher endpoints are a deployment/config concern (see `deploy/README.md`).

### GAP-7 — Idempotent certificate-profile reconcile (deployer ergonomics)

**Problem.** The container startup reconciles certificate profiles from a mounted,
version-controlled directory, but `profile.register` always creates a **new
immutable version**; there is no content-addressed idempotent reconcile, so
re-applying an unchanged profile directory would keep creating versions (the
container entrypoint currently mitigates by skipping ids already present, which
means editing an existing profile does not update it on restart).

**Proposed addition.** A server entrypoint flag `--reconcile-profiles <dir>` (or
operation `profile.reconcile`) that, for each profile document: canonicalises and
hashes it; if absent, registers + activates; if content differs from the active
version, registers a new version + activates; if it matches, no-ops. Runs before
the listener opens. Reuses the existing register/activate path. This makes
"profiles as configuration" work cleanly for GitOps deployers.

### GAP-8 — Aggregate metrics for the dashboard

**Problem.** A production console shows counts (active CAs, certificates by state,
CRL freshness, pending approvals). ZeroEcho has no aggregate metrics endpoint; the
dashboard currently summarises discoverable operations only.

**Proposed addition.** `metrics.summary` (non-mutating) returning realm-scoped
counts respecting the caller's authorization: `{authorities:{active,retired},
credentials:{valid,revoked,expired}, approvals:{pending}, crl:{oldestNextUpdate}}`.

## Intentional non-goals (documented, not defects)

- **Key recovery / private-key archival.** ZeroEcho keeps private keys with the
  subject or a remote signer; it deliberately does not archive subject private
  keys, so there is no key-recovery screen. This is a security posture, not a gap.
- **In-product crypto-token/HSM lifecycle.** Signing backends (keyring, remote
  signing) are provisioned via configuration and the `PkiStore`/remote-signing
  SPIs, not mutated through the admin API. Token administration is a deployment
  activity; the console surfaces algorithm bindings (`algorithm.binding.*`).

## Summary

The frontend already covers the full ZeroEcho operation catalog and the core
EJBCA administration surface (CA lifecycle, profiles, issuance, lifecycle,
revocation, CRL/OCSP, ACME, approvals, RBAC, audit), and **exceeds** EJBCA in
break-glass, cryptographic audit-chain integrity, and disclosure control. The
highest-value backend additions, in order, are **GAP-1 (certificate search)** and
**GAP-2 (operation parameter schema)**; the remainder are feature-parity or
deployer-ergonomics items that can follow.
