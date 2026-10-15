# Implemented capabilities and future work

Current contracts live in the maintained [documentation](../documentation/index.md),
source and behavior tests. Historical design documents are not a release checklist.

## Implemented

- HTTPS server, administration frontend, local synchronous CLI and remote
  submit/poll transport; generated operation schemas and OpenAPI.
- Configured enrollment and publication protocols, authorization and approvals.
- Optional H2-backed credential search with bounded pagination: subject/serial
  case-insensitive substring, credential-ID prefix (`fingerprintFilter`), exact
  status/profile filters and exact typed SAN matching. Without explicit deployment
  activation, credential search is unavailable.
- Durable CRL/delta schedules with stable execution identity and crash
  reconciliation. OCSP and non-X.509 schedules are rejected. Failed executions
  and publication failures need explicit operator follow-up.
- Realm/authority operational metrics and dashboard operations. The SPA's home
  dashboard presents current server and selected-CA snapshots as accessible cards
  and count bars, with manual refresh and explicit unavailable/failed states.
- Configured publisher endpoints and content-aware profile reconciliation.
- Consistent logical backups, bounded local streaming and cold staged restore.
  Opt-in authenticated HTTP upload/download and the frontend backup workflow
  support exact approvals and outcome reconciliation after restart (ZE-06).
- Durable local LMS/XMSS authority and supported PQC/hybrid certificate lifecycle.

## Active and future work

The publisher-secrets PBKDF2 integration defect is resolved. CLASSIC/HYBRID
creation and password unlocking enforce the existing 600,000-iteration policy.
Command tests cover all profiles, including independent password and BIKE
unlocking of HYBRID stores, and reject incorrect passwords.

| Extension | Disposition and boundary |
|---|---|
| HTTP streaming backup transfer and frontend workflow | ZE-06 completed. Disabled by default; explicit administrator budgets and private persistent spool required. Legacy byte-array adapters remain bounded and legacy remote restore stays disabled. |
| Carry-forward restore merge (Option B) | Future alternative to the implemented conservative no-regression checks (Option A). Requires explicit safety-authority merge and recovery design. |
| Independently hosted stateful-signing authority (Option B) | Future administrator-selected alternative to the default local authority (Option A). Requires a separate availability, durability and trust contract. |
| SAN search and additional search indexes | ZE-18 completed with an optional H2 index, bounded queries and startup rebuild. True certificate-digest search remains outside the implemented contract. |
| Graphical aggregate metrics dashboard | ZE-19 completed over existing metrics operations; current snapshots only, with authorization, manual refresh and explicit unavailable/failed measurements. |

## Implementation backlog from the frontend capability audit

The following work is recorded for subsequent implementation; it does not expand
the completed ZE-06 package. Evidence and current limitations are described in the
[capability analysis](../pki-frontend/docs/backend-gap-analysis.md). Ordering below
expresses dependencies, not an approved delivery date.
The owner authorized implementation of this backlog on 2026-10-11. The former
FE-01–FE-06 identifiers are superseded by ZE-14–ZE-19, respectively, to avoid
confusion with completed ZE-01–ZE-06. Authorization does not resolve the design
and compatibility decisions identified below.

| ID | Work and acceptance boundary | State |
|---|---|---|
| ZE-14 | Complete EST/SCEP/CMP SPA routes matching existing navigation and catalog operations. Respect configured availability and server permissions; verify direct navigation and authorized/denied flows in browser tests. | DONE; routes, runtime availability gate and live browser tests passed |
| ZE-15 | Install a durable production enrollment-profile registry and require explicit profile bindings for all enrollment. Enforce policy and implement durable approval with protocol completion, restart and duplicate-request reconciliation. Owner selected B/B: no legacy unbound compatibility path; rejection-only approval is not accepted. | DONE; protocol, recovery, module and integration gates passed |
| ZE-16 | Complete the enrollment-profile SPA route after ZE-15. Verify persistence, validation failures and authorization through the real backend. | DONE; discovery-filtered route, profile management, validation, authorization and restart verified through the live backend |
| ZE-17 | Expose domain hold/unhold through authoritative administrative operations and generated projections. Preserve permanent revocation semantics; test permissions, approvals, status publication and restart. | DONE; canonical hold/unhold, scoped authorization and approval, published CRLs, restart, live SPA and affected-module gates verified |
| ZE-18 | Add SAN search and clarify existing `fingerprintFilter` credential-ID semantics. Owner selected an optional embedded SQL index, with the engine chosen jointly by architect and implementer; credential search is unavailable unless activated at deployment. Preserve existing filter meanings and define bounded queries, index recovery and pagination. True certificate-digest search remains outside this package. | DONE; optional H2 2.5.252 index, typed SAN, authorization/filter parity, recovery, live and packaged deployment gates verified |
| ZE-19 | Build a graphical dashboard over existing metrics operations, preserving explicit unavailable/failed states and authorization. Do not represent missing measurements as zero. | DONE; accessible cards/count bars, selected-CA scope, bounded request lifecycle, frontend and live backend tests verified |

OCSP/non-X.509 scheduling, in-product publisher/HSM administration and additional
validator capabilities remain optional extensions requiring concrete requirements;
their absence is not evidence of a broken supported contract. Subject private-key
archival remains an intentional non-goal. No full EJBCA or protocol-extension
parity is implied by this backlog.

Backup integrity is not authentication, and a historical backup is not permission
to roll back signing or revocation authority. See [backup and restore](../documentation/admin/backup-restore.md)
and [stateful signing](../documentation/developer/stateful-signing.md).
