# Operation permissions reference

Every operation exposed by the administrative API requires a specific `action` on a specific `resourceType`. This page lists every operation, the exact grant it consumes, and whether the operation requires a high-risk approval before it executes.

To discover this mapping at runtime, call `GET /admin/v1/operations` — the response includes `action`, `resourceType`, and `approval` for every operation the caller is permitted to see.

For the full grant model — scopes, conditions, data-view levels, and the decision engine — see the [Security model](security-model.md).

## How to read this table

| Column | Meaning |
| --- | --- |
| **Operation ID** | The stable string identifier used in API requests and CLI `--operation` arguments. |
| **Required action** | The `action` a grant must carry for the caller's principal to perform this operation. |
| **Resource type** | The `resourceType` a grant must carry. |
| **HIGH_RISK** | When checked, the operation requires a realm-wide dual-control approval before it executes. |

## Certificate authorities and issuers

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `ca.list` | `AUTHORITY_LIST` | `AUTHORITY` | |
| `ca.inspect` | `AUTHORITY_READ` | `AUTHORITY` | |
| `ca.create` | `AUTHORITY_CREATE` | `AUTHORITY` | ✓ |
| `ca.transition` | `AUTHORITY_ACTIVATE` | `AUTHORITY` | ✓ |
| `ca.rollover` | `ISSUER_CREATE` | `AUTHORITY` | ✓ |
| `ca.rotate` | `ISSUER_ROTATE` | `AUTHORITY` | ✓ |
| `ca.intermediate.create` | `ISSUER_CREATE` | `AUTHORITY` | ✓ |
| `ca.intermediate.issue` | `ISSUER_CREATE` | `AUTHORITY` | ✓ |
| `issuer.generation.list` | `AUTHORITY_READ` | `ISSUER` | |
| `issuer.generation.inspect` | `AUTHORITY_READ` | `ISSUER` | |
| `issuer.path.list` | `CA_CHAIN_DOWNLOAD` | `ISSUER` | |
| `issuer.path.inspect` | `CA_CHAIN_DOWNLOAD` | `ISSUER` | |
| `issuer.path.register` | `ISSUER_ROTATE` | `AUTHORITY` | |
| `issuer.path.select` | `ISSUER_ROTATE` | `AUTHORITY` | ✓ |

## Profiles and algorithm bindings

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `profile.list` | `PROFILE_READ` | `PROFILE` | |
| `profile.list-all` | `PROFILE_READ` | `PROFILE` | |
| `profile.inspect` | `PROFILE_READ` | `PROFILE` | |
| `profile.register` | `PROFILE_REGISTER` | `PROFILE` | |
| `profile.validate` | `PROFILE_VALIDATE` | `PROFILE` | |
| `profile.activate` | `PROFILE_ACTIVATE` | `PROFILE` | ✓ |
| `algorithm.binding.list` | `X509_BINDING_READ` | `X509_BINDING` | |
| `algorithm.binding.inspect` | `X509_BINDING_READ` | `X509_BINDING` | |
| `algorithm.binding.validate` | `X509_BINDING_READ` | `X509_BINDING` | |

## Credential issuance and lifecycle

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `credential.search` | `CERTIFICATE_SEARCH` | `CERTIFICATE` | |
| `credential.inspect` | `CERTIFICATE_READ_METADATA` | `CERTIFICATE` | |
| `credential.issue` | `CERTIFICATE_ISSUE` | `CERTIFICATE` | |
| `credential.renew` | `CERTIFICATE_RENEW` | `CERTIFICATE` | |
| `credential.replace` | `CERTIFICATE_REKEY` | `CERTIFICATE` | |
| `credential.reissue` | `CERTIFICATE_ISSUE` | `CERTIFICATE` | ✓ |
| `credential.revoke` | `CERTIFICATE_REVOKE` | `CERTIFICATE` | |
| `credential.hold` | `CERTIFICATE_HOLD` | `CERTIFICATE` | |
| `credential.unhold` | `CERTIFICATE_RELEASE_HOLD` | `CERTIFICATE` | |
| `credential.confirmation.pending.list` | `CERTIFICATE_SEARCH` | `CERTIFICATE` | |
| `credential.confirmation.challenge.issue` | `CERTIFICATE_PUBLICATION_CHANGE` | `CERTIFICATE` | |
| `credential.confirmation.proof.complete` | `CERTIFICATE_CONFIRM` | `CERTIFICATE` | |
| `credential.confirmation.pending.revoke` | `CERTIFICATE_REVOKE` | `CERTIFICATE` | |
| `certificate.publication.enroll` | `CERTIFICATE_PUBLICATION_CHANGE` | `CERTIFICATE` | |

## Requests

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `request.list` | `REQUEST_READ_ANY` | `REQUEST` | |
| `request.inspect` | `REQUEST_READ_ANY` | `REQUEST` | |
| `request.import` | `REQUEST_SUBMIT` | `REQUEST` | |
| `request.verify` | `REQUEST_READ_ANY` | `REQUEST` | |

## Enrollment requests

These operations act on durable protocol enrollment transactions. Requester
separation and the frozen approval policy apply in addition to the listed grants.

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `enrollment.request.list` | `REQUEST_READ_ANY` | `ENROLLMENT_REQUEST` | |
| `enrollment.request.inspect` | `REQUEST_READ_ANY` | `ENROLLMENT_REQUEST` | |
| `enrollment.request.approve` | `REQUEST_APPROVE` | `ENROLLMENT_REQUEST` | |
| `enrollment.request.reject` | `REQUEST_REJECT` | `ENROLLMENT_REQUEST` | |

## Revocation and status objects

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `revocation.inspect` | `REVOCATION_HISTORY_READ` | `REVOCATION` | |
| `revocation.snapshot` | `REVOCATION_HISTORY_READ` | `REVOCATION` | |
| `revocation.history` | `REVOCATION_HISTORY_READ` | `REVOCATION` | |
| `status.inspect` | `CRL_DOWNLOAD` | `STATUS_OBJECT` | |
| `inventory.status` | `CRL_DOWNLOAD` | `STATUS_OBJECT` | |
| `status.generate` | `CRL_GENERATE` | `STATUS_OBJECT` | |

## Publication

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `publication.list` | `PUBLICATION_READ` | `PUBLICATION` | |
| `publication.inspect` | `PUBLICATION_READ` | `PUBLICATION` | |
| `publication.register` | `PUBLICATION_REGISTER` | `PUBLICATION` | |
| `publication.process` | `PUBLICATION_PROCESS` | `PUBLICATION` | |
| `publication.retry` | `PUBLICATION_RETRY` | `PUBLICATION` | |
| `publication.reconcile` | `PUBLICATION_RECONCILE` | `PUBLICATION` | |

## OCSP responders

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `ocsp.responder.list` | `OCSP_RESPONDER_READ` | `OCSP_RESPONDER` | |
| `ocsp.responder.inspect` | `OCSP_RESPONDER_READ` | `OCSP_RESPONDER` | |
| `ocsp.responder.register` | `OCSP_ADMINISTER` | `OCSP_RESPONDER` | ✓ |
| `ocsp.responder.activate` | `OCSP_ADMINISTER` | `OCSP_RESPONDER` | ✓ |
| `ocsp.responder.deactivate` | `OCSP_ADMINISTER` | `OCSP_RESPONDER` | |

## ACME directories and accounts

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `acme.directory.list` | `ACME_DIRECTORY_READ` | `ACME_DIRECTORY` | |
| `acme.directory.inspect` | `ACME_DIRECTORY_READ` | `ACME_DIRECTORY` | |
| `acme.directory.register` | `ACME_DIRECTORY_MANAGE` | `ACME_DIRECTORY` | ✓ |
| `acme.directory.activate` | `ACME_DIRECTORY_MANAGE` | `ACME_DIRECTORY` | ✓ |
| `acme.directory.deactivate` | `ACME_DIRECTORY_MANAGE` | `ACME_DIRECTORY` | |
| `acme.account.list` | `ACME_ACCOUNT_READ` | `ACME_ACCOUNT` | |
| `acme.account.inspect` | `ACME_ACCOUNT_READ` | `ACME_ACCOUNT` | |
| `acme.account.deactivate` | `ACME_ACCOUNT_MANAGE` | `ACME_ACCOUNT` | |

## Repository aliases and disclosure

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `repository.alias.list` | `REPOSITORY_ALIAS_READ` | `REPOSITORY_ALIAS` | |
| `repository.alias.inspect` | `REPOSITORY_ALIAS_READ` | `REPOSITORY_ALIAS` | |
| `repository.alias.set` | `REPOSITORY_ALIAS_MANAGE` | `REPOSITORY_ALIAS` | ✓ |
| `repository.alias.remove` | `REPOSITORY_ALIAS_MANAGE` | `REPOSITORY_ALIAS` | ✓ |
| `security.disclosure.inspect` | `DISCLOSURE_READ` | `DISCLOSURE` | |
| `security.disclosure.capability.list` | `DISCLOSURE_READ` | `DISCLOSURE` | |
| `security.disclosure.set` | `DISCLOSURE_CHANGE` | `DISCLOSURE` | ✓ |
| `security.disclosure.capability.issue` | `DISCLOSURE_CAPABILITY_ISSUE` | `CAPABILITY` | |
| `security.disclosure.capability.revoke` | `DISCLOSURE_CAPABILITY_REVOKE` | `CAPABILITY` | |

## Principals, roles, and grants

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `security.principal.list` | `PRINCIPAL_MANAGE` | `PRINCIPAL` | |
| `security.principal.inspect` | `PRINCIPAL_MANAGE` | `PRINCIPAL` | |
| `security.principal.register` | `PRINCIPAL_MANAGE` | `PRINCIPAL` | ✓ |
| `security.principal.enable` | `PRINCIPAL_MANAGE` | `PRINCIPAL` | |
| `security.principal.disable` | `PRINCIPAL_MANAGE` | `PRINCIPAL` | ✓ |
| `security.role-template.list` | `ROLE_MANAGE` | `ROLE` | |
| `security.role-template.inspect` | `ROLE_MANAGE` | `ROLE` | |
| `security.role-assignment.list` | `ROLE_MANAGE` | `ROLE` | |
| `security.role-assignment.inspect` | `ROLE_MANAGE` | `ROLE` | |
| `security.role-assignment.create` | `ROLE_MANAGE` | `ROLE` | ✓ |
| `security.role-assignment.revoke` | `ROLE_MANAGE` | `ROLE` | |
| `security.grant.list` | `PERMISSION_GRANT` | `GRANT` | |
| `security.grant.inspect` | `PERMISSION_GRANT` | `GRANT` | |
| `security.grant.create` | `PERMISSION_GRANT` | `GRANT` | ✓ |
| `security.grant.revoke` | `PERMISSION_GRANT` | `GRANT` | |
| `security.authorization.evaluate` | `PERMISSION_GRANT` | `GRANT` | |

## Approvals and break-glass

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `security.approval.list` | `REQUEST_READ_ANY` | `APPROVAL` | |
| `security.approval.inspect` | `REQUEST_READ_ANY` | `APPROVAL` | |
| `security.approval.request` | `REQUEST_SUBMIT` | `APPROVAL` | |
| `security.approval.approve` | `REQUEST_APPROVE` | `APPROVAL` | |
| `security.approval.reject` | `REQUEST_REJECT` | `APPROVAL` | |
| `security.approval.cancel` | `REQUEST_CANCEL` | `APPROVAL` | |
| `security.break-glass.list` | `PERMISSION_GRANT` | `BREAK_GLASS` | |
| `security.break-glass.inspect` | `PERMISSION_GRANT` | `BREAK_GLASS` | |
| `security.break-glass.create` | `PERMISSION_GRANT` | `BREAK_GLASS` | ✓ |
| `security.break-glass.activate` | `PERMISSION_GRANT` | `BREAK_GLASS` | ✓ |
| `security.break-glass.revoke` | `PERMISSION_GRANT` | `BREAK_GLASS` | |

## Audit

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `security.audit-view.inspect-redacted` | `AUDIT_READ_REDACTED` | `AUDIT` | |
| `security.audit-view.inspect-full` | `AUDIT_READ_FULL` | `AUDIT` | |
| `security.audit-view.inspect-pii` | `AUDIT_READ_PII` | `AUDIT` | |
| `security.audit.search` | `AUDIT_EXPORT` | `AUDIT` | |
| `security.audit.verify-integrity` | `AUDIT_INTEGRITY_VERIFY` | `AUDIT` | |

## Server configuration

| Operation ID | Required action | Resource type | HIGH_RISK |
| --- | --- | --- | --- |
| `configuration.choices` | `SERVER_CONFIGURATION_READ` | `SERVER_CONFIGURATION` | |
| `configuration.validate` | `SERVER_CONFIGURATION_READ` | `SERVER_CONFIGURATION` | |
