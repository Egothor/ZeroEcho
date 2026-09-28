# PKI frontend capability coverage

This reference describes the implemented administration surface. Enterprise PKI
products such as EJBCA provide comparison context, not a requirement for complete
feature parity. Unimplemented proposals are consolidated in the sole
[outstanding-work plan](../../docs/project-work-plan.md).

## Method

- The frontend is **descriptor/catalog driven**: it renders typed forms for the
  full server operation catalog (107 operations — 41 PKI, 10 signing, 56 control) and runs
  them with the server's signing-receipt `PENDING` / explicit `APPROVAL_REQUIRED`
  semantics. See `src/api/operationCatalog.ts`.
- EJBCA is used as the feature benchmark (Community + Enterprise). Each EJBCA
  functional area is mapped to the ZeroEcho operation(s) and UI that cover it.
- Status legend: **✓ covered**, **◐ partial**, **✗ unavailable capability**,
  **∅ intentional non-goal** (documented, not a defect).

## Coverage matrix

| EJBCA area | ZeroEcho coverage | Status |
|---|---|---|
| CA management (create root/sub, activate/suspend/retire) | `ca.create`, `ca.intermediate.create`, `ca.intermediate.issue`, `ca.transition`, `ca.inspect`, `ca.list` | ✓ |
| CA key rollover / renewal / rotation | `ca.rollover`, `ca.rotate`, issuer generations `issuer.*` | ✓ |
| Certificate profiles | `profile.register`, `profile.validate`, `profile.inspect`, `profile.list`, `profile.activate` | ✓ |
| End-entity profiles (enrollment constraints) | Partially expressed via certificate profiles + issuance approval requirements | ◐ (enrollment profiles) |
| Certificate issuance from CSR | `request.import`, `request.verify`, `request.inspect`, `credential.issue` | ✓ |
| Certificate lifecycle (renew/rekey/replace) | `credential.renew`, `credential.replace`, `credential.reissue` | ✓ |
| Revocation + reasons, reactivation from hold | `credential.revoke` (RFC 5280 reasons incl. `CERTIFICATE_HOLD`/`REMOVE_FROM_CRL`), `revocation.inspect`, `revocation.history` | ✓ |
| CRL / delta CRL generation & inspection | `status.generate` (`CRL`/`DELTA_CRL`), `status.inspect`, `inventory.status`, `revocation.snapshot` | ✓ |
| **Certificate search** (by subject/SAN/serial/status) | Authority-scoped `credential.search` and metadata selection; subject/SAN/serial filtering remains a future gap | ◐ (advanced search) |
| OCSP responder administration | `ocsp.responder.register/inspect/list/activate/deactivate` | ✓ |
| Publishers / publication | `publication.register/process/retry/reconcile/inspect/list`, `repository.alias.*` | ✓ (config of publisher endpoints is server-config, ◐ publisher administration) |
| ACME | `acme.directory.*`, `acme.account.*` + the ACME protocol listener | ✓ |
| EST / SCEP / CMP enrollment protocols | Not present (ACME is the supported automated protocol) | ✗ (enrollment protocols) |
| Approvals (dual control) | `security.approval.request/inspect/list/approve/reject/cancel`, HIGH_RISK `APPROVAL_REQUIRED` flow | ✓ |
| Roles & access rules (RBAC) | `security.role-template.*`, `security.role-assignment.*`, `security.grant.*`, `security.authorization.evaluate` | ✓ |
| Administrators / principals | `security.principal.*` | ✓ |
| Admin authentication | mTLS (DIRECT_MTLS / TRUSTED_REVERSE_PROXY, RFC 9440) | ✓ |
| Break-glass / emergency access | `security.break-glass.*` | ✓ |
| Audit trail + integrity | `security.audit.search`, `security.audit-view.inspect-*`, `security.audit.verify-integrity` | ✓ |
| Disclosure / publication capability control | `security.disclosure.*`, `certificate.publication.enroll` | ✓ |
| Crypto token / HSM management | Keyring + remote signing configured via server-config, not an admin API | ∅ / ◐ |
| Key recovery / archival | Not a feature (keys stay with the subject / remote signer) | ∅ |
| Validators (pre-issuance checks) | Expressed inside certificate profiles / algorithm bindings (`algorithm.binding.*`) | ◐ |
| Scheduled services (auto CRL, etc.) | Generation is triggered (`status.generate`); scheduling is deployment concern | ◐ (scheduling) |
| Dashboard statistics / counts | Discoverable-operation counts + per-domain views; no aggregate metrics endpoint | ✗ (aggregate metrics) |
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

Authority-scoped certificate search supplies bounded metadata enumeration, not
subject/SAN/serial filtering. Publisher endpoint and signing-provider configuration
remain deployment concerns. Profile bootstrap skips known identities, including
inactive ones; it does not reconcile content changes.

## Intentional non-goals (documented, not defects)

- **Key recovery / private-key archival.** ZeroEcho keeps private keys with the
  subject or a remote signer; it deliberately does not archive subject private
  keys, so there is no key-recovery screen. This is a security posture, not a gap.
- **In-product crypto-token/HSM lifecycle.** Signing backends (keyring, remote
  signing) are provisioned via configuration and the `PkiStore`/remote-signing
  SPIs, not mutated through the admin API. Token administration is a deployment
  activity; the console surfaces algorithm bindings (`algorithm.binding.*`).
