# Implemented capabilities and future work

Current contracts live in the maintained [documentation](../documentation/index.md),
source and behavior tests. Historical design documents are not a release checklist.

## Implemented

- HTTPS server, administration frontend, local synchronous CLI and remote
  submit/poll transport; generated operation schemas and OpenAPI.
- Configured enrollment and publication protocols, authorization and approvals.
- Credential search with bounded pagination: subject/serial case-insensitive
  substring, fingerprint prefix, and exact status/profile filters. SAN search
  is not part of the implemented search contract.
- Durable CRL/delta schedules with stable execution identity and crash
  reconciliation. OCSP and non-X.509 schedules are rejected. Failed executions
  and publication failures need explicit operator follow-up.
- Realm/authority operational metrics and dashboard operations. The SPA's home
  dashboard supplies navigation cards; aggregate graphical charts are not claimed.
- Configured publisher endpoints and content-aware profile reconciliation.
- Consistent logical backups, bounded local streaming and cold staged restore.
- Durable local LMS/XMSS authority and supported PQC/hybrid certificate lifecycle.

## Deferred or unapproved extensions

The publisher-secrets PBKDF2 integration defect is resolved. CLASSIC/HYBRID
creation and password unlocking enforce the existing 600,000-iteration policy.
Command tests cover all profiles, including independent password and BIKE
unlocking of HYBRID stores, and reject incorrect passwords.

| Extension | Disposition and boundary |
|---|---|
| HTTP streaming backup transfer and complete frontend backup workflow | Accepted deferral, unscheduled. Current byte-array server adapters remain bounded; remote restore is unavailable. |
| Carry-forward restore merge (Option B) | Future alternative to the implemented conservative no-regression checks (Option A). Requires explicit safety-authority merge and recovery design. |
| Independently hosted stateful-signing authority (Option B) | Future administrator-selected alternative to the default local authority (Option A). Requires a separate availability, durability and trust contract. |
| SAN search and additional search indexes | Unapproved scope; define authorization, pagination and resource budgets before implementation. |
| Graphical aggregate metrics dashboard | Unapproved UI extension over existing bounded metrics operations. |

Backup integrity is not authentication, and a historical backup is not permission
to roll back signing or revocation authority. See [backup and restore](../documentation/admin/backup-restore.md)
and [stateful signing](../documentation/developer/stateful-signing.md).
