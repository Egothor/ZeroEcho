# PKI frontend capability coverage

This reference describes the implemented administration surface. Enterprise PKI
products such as EJBCA provide comparison context, not a requirement for complete
feature parity. Unimplemented proposals are consolidated in the sole
[outstanding-work plan](../../docs/project-work-plan.md).

## Method

- The frontend is **descriptor/catalog driven**: it renders typed forms for the
  available operations from the generated server catalog and runs
  them with the server's signing-receipt `PENDING` / explicit `APPROVAL_REQUIRED`
  semantics. See `src/api/operationCatalog.ts`.
- EJBCA is used as the feature benchmark (Community + Enterprise). Each EJBCA
  functional area is mapped to the ZeroEcho operation(s) and UI that cover it.
- Status legend: **✓ covered**, **◐ partial**, **✗ unavailable capability**,
  **∅ intentional non-goal** (documented, not a defect).
- Coverage refers to the named implemented operations, not full EJBCA feature
  parity or complete implementation of every protocol extension. Backend support,
  configured availability and a dedicated frontend workflow are separate concerns.

## Coverage matrix

| EJBCA area | ZeroEcho coverage | Status |
|---|---|---|
| CA management (create root/sub, activate/suspend/retire) | `ca.create`, `ca.intermediate.create`, `ca.intermediate.issue`, `ca.transition`, `ca.inspect`, `ca.list` | ✓ |
| CA key rollover / renewal / rotation | `ca.rollover`, `ca.rotate`, issuer generations `issuer.*` | ✓ |
| Certificate profiles | `profile.register`, `profile.validate`, `profile.inspect`, `profile.list`, `profile.activate` | ✓ |
| End-entity profiles (enrollment constraints) | Durable realm-owned profiles and mandatory endpoint/directory bindings enforce policy and approval across EST enrollment/renewal/server-keygen, SCEP, CMP enrollment/key update and ACME finalization. The Enrollment Profiles route exposes existing discovery-filtered management forms | ✓ |
| Certificate issuance from CSR | `request.import`, `request.verify`, `request.inspect`, `credential.issue` | ✓ |
| Certificate lifecycle (renew/replace/reissue) | `credential.renew`, `credential.replace`, `credential.reissue`; no separate generic rekey operation is implied | ✓ |
| Revocation + reasons, reactivation from hold | `credential.revoke` accepts permanent revocation reasons; `credential.hold` and `credential.unhold` expose reversible holds with separate permissions and grant-conditioned approval. `revocation.inspect/history` are available. Permanent revocation cannot be reversed | ✓ |
| CRL / delta CRL generation & inspection | `status.generate` (`CRL`/`DELTA_CRL`), `status.inspect`, `inventory.status`, `revocation.snapshot` | ✓ |
| **Certificate search** (by subject/SAN/serial/status) | Optional embedded H2 index enables authority-scoped `credential.search`: subject-reference and serial substrings, exact typed issued SAN/status/profile, credential-ID prefix. Without deployment activation, search is unavailable. `fingerprintFilter` retains credential-ID-prefix semantics and is labeled accordingly | ✓ (deployment opt-in) |
| OCSP responder administration | `ocsp.responder.register/inspect/list/activate/deactivate` | ✓ |
| Publishers / publication | `publication.register/process/retry/reconcile/inspect/list`, `repository.alias.*` | ✓ (config of publisher endpoints is server-config, ◐ publisher administration) |
| ACME | `acme.directory.*`, `acme.account.*` + the ACME protocol listener | ✓ |
| EST / SCEP / CMP enrollment protocols | Listeners and endpoint administration (`est.*`, `scep.*`, `cmp.*`) have discovery-filtered SPA routes; authenticated protocol workflows use durable policy, approval and continuation. CMP preserves original CRMF; EST server-keygen retains client-encrypted delivery artifacts | ✓ |
| Approvals (dual control) | `security.approval.request/inspect/list/approve/reject/cancel`, HIGH_RISK `APPROVAL_REQUIRED` flow | ✓ |
| Roles & access rules (RBAC) | `security.role-template.*`, `security.role-assignment.*`, `security.grant.*`, `security.authorization.evaluate` | ✓ |
| Administrators / principals | `security.principal.*` | ✓ |
| Admin authentication | mTLS (DIRECT_MTLS / TRUSTED_REVERSE_PROXY, RFC 9440) | ✓ |
| Break-glass / emergency access | `security.break-glass.*` | ✓ |
| Audit trail + integrity | `security.audit.search`, `security.audit-view.inspect-*`, `security.audit.verify-integrity` | ✓ |
| Disclosure / publication capability control | `security.disclosure.*`, `certificate.publication.enroll` | ✓ |
| Crypto token / HSM management | Keyring + remote signing configured via server-config, not an admin API | ∅ / ◐ |
| Subject private-key recovery / archival | No subject private-key archival/recovery workflow; this does not preclude locally managed CA signing keys | ∅ |
| Validators (pre-issuance checks) | Expressed inside certificate profiles / algorithm bindings (`algorithm.binding.*`) | ◐ |
| Scheduled services (auto CRL, etc.) | `status.schedule.set/inspect/list` and a durable server worker schedule X.509 CRL/delta CRL generation. OCSP and non-X.509 schedules are unsupported | ◐ (CRL/delta scheduling implemented) |
| Dashboard statistics / counts | The home dashboard presents `dashboard.authority/certificate/revocation/publication/server` snapshots as metric cards and comparable-count bars. CA panels query one selected authority; discovery and server authorization apply. Manual refresh, computation times, partial-count warnings and explicit unavailable/failed measurements preserve the API's limits, including unavailable pending-request counts | ✓ |
| System configuration view/validate | `configuration.validate`, `algorithm.binding.validate`; container `--validate-config` | ✓ |
| REST API | Admin HTTP API (`/admin/v1/...`) | ✓ |
| CLI (automation) | `zeroecho pki` — local in-process **and** remote WebAPI mode (`--url` + mTLS) | ✓ |

## Known-value selection

The selection APIs `profile.list-all`, `request.list`, `credential.search`,
`issuer.generation.list`, `configuration.choices` and
`security.disclosure.capability.list` expose authorized known identities.
Authority, status, publication and binding lists support cursors; scoped
profile-version and chain-path lists supply dependent choices. Control lists
use their existing offset pages. An unavailable list does not enable arbitrary
identity entry. See the [selection API contract](selection-api.md) for permissions,
wire shapes and scan costs.

Authority-scoped certificate search requires the optional embedded SQL index.
It performs case-insensitive subject-reference and serial substring matching,
exact typed issued-certificate SAN and status/profile matching, and credential-ID
prefix matching. Local and remote execution apply the same filters with current
authorization. It does not compute certificate fingerprints. Disabled search is
omitted from discovery and is unavailable through direct invocation.
Publisher endpoint and signing-provider configuration remain deployment concerns.
Profile bootstrap compares active canonical content: an identical active profile
is skipped; otherwise the supplied version is registered and activated.

EST, SCEP and CMP have dedicated administration routes in `App.tsx`, using the
same discovery-filtered forms as Operation Explorer. The Enrollment Profiles
navigation entry opens `/enrollment` with the same discovery-filtered forms for
registration, inspection, updates and state changes.
Enrollment profiles, EST/SCEP/CMP endpoint bindings and ACME directory bindings are persisted in the
server-control store and validated at realm startup. EST, SCEP, CMP enrollment and
ACME finalization use the shared policy and approval coordinator. Protocol custody
and exact retained transactions support approval, restart and repeated completion.
CMP key update and revocation require the certificate holder's signature or an
explicit authority-scoped RA grant; PBM does not grant certificate ownership.
EST server-keygen binds encrypted delivery to the authenticated recipient and
retains the original generated key across retries. Live browser tests verify
enrollment-profile management, validation failures, unauthorized mutation rejection
and persistence after backend restart.

## Intentional non-goals (documented, not defects)

- **Subject private-key recovery / archival.** ZeroEcho has no subject-key archive
  or recovery screen. CA signing keys may be managed locally or through configured
  external providers; that is separate from subject-key archival.
- **In-product crypto-token/HSM lifecycle.** Signing backends (keyring, remote
  signing) are provisioned through configured key-access/signing providers,
  not mutated through the admin API. Token administration is a deployment
  activity; the console surfaces algorithm bindings (`algorithm.binding.*`).
