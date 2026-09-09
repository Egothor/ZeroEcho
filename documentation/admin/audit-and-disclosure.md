# Audit and disclosure

This page covers proving what happened and controlling what is visible: searching
the audit trail, reading audit records at the appropriate level of detail,
verifying the integrity of the audit chain, and governing the disclosure of
objects — including issuing time-bounded capabilities that grant temporary access.

Audit lives under **Audit** in the Trust & Access group; disclosure and
capabilities under **Disclosure & Capabilities**.

## The audit trail

Every governed action is recorded as an audit record. The **Audit** area searches
the trail (`security.audit.search`) into a table. Filter by:

| Filter | Meaning |
|---|---|
| `category` | The record category. |
| `action` | The recorded action. |
| `after`, `before` | A time window. |
| `objectId` | A specific object. |
| `principalName` | The acting principal. |
| `limit` | Maximum records returned. |

Individual records can be opened by their `objectId`.

## Redacted, full, and PII views

Audit records can be read at three increasing levels of sensitivity, each gated by
a separate permission and data view. Choose the least-sensitive view sufficient
for your task.

| View | Operation | Data view | Shows |
|---|---|---|---|
| **Redacted** | `security.audit-view.inspect-redacted` | `METADATA_REDACTED` | Metadata with sensitive fields redacted. |
| **Full** | `security.audit-view.inspect-full` | `METADATA_FULL` | Full metadata. |
| **PII** | `security.audit-view.inspect-pii` | `PII_FULL` | Personally identifiable information. |

Each accepts the record `objectId` and an optional `reasonReference`. Content and
PII authority are kept distinct in the [access model](access-control.md#effect-relationship-and-data-view):
holding the full-metadata view does not confer the PII view.

!!! note "Reads are governed too"
    Reading audit at the full or PII level is itself an audited, permissioned
    action. A grant can require a reason for such reads via the `REASON_REQUIRED`
    [condition](access-control.md#conditions).

## Verifying audit-chain integrity

Audit records form a tamper-evident chain. **Verify audit integrity**
(`security.audit.verify-integrity`) checks that the chain is intact. You may
optionally pin the check to a known chain head by supplying its `sequence` and
`recordHash` (supply both together); the server confirms the chain up to that head
matches. Use this to demonstrate to a reviewer or auditor that the trail has not
been altered.

## Disclosure policies

A disclosure policy controls who may see an object. Manage it under **Disclosure &
Capabilities**.

| Policy | Meaning |
|---|---|
| `PUBLIC` | Visible to anyone, and listed. |
| `PUBLIC_UNLISTED` | Retrievable if you know it, but not listed. |
| `AUTHENTICATED` | Visible to any authenticated principal. |
| `OWNER_ONLY` | Visible only to the owner. |
| `RESTRICTED` | Visible only through an explicit grant or capability. |
| `NOT_PUBLISHED` | Not disclosed. |

- **Inspect disclosure** (`security.disclosure.inspect`) — show an object's current
  policy by `objectId`.
- **Set disclosure** (`security.disclosure.set`) — high-risk; set the `policy` for
  an `objectId`. Because it changes who can see an object, it requires an
  [approval](access-control.md#approvals).

### Enrolling a credential for publication

**Enroll credential publication** (`certificate.publication.enroll`) marks a
credential as eligible for publication and optionally records its
`ownerPrincipalId`. This governs whether and to whom the credential is disclosed
through the public repository, working together with the credential's disclosure
policy.

## Time-bounded disclosure capabilities

A **capability** grants temporary, time-bounded access to an otherwise restricted
object without permanently widening its disclosure policy — useful for a
short-lived, auditable disclosure to a specific party.

- **Issue disclosure capability** (`security.disclosure.capability.issue`) — issue
  a capability over an `objectId` with a mandatory `expiresAt`.
- **Revoke disclosure capability** (`security.disclosure.capability.revoke`) —
  revoke a capability by `capabilityId` before it expires.

!!! tip "Prefer a capability to a policy change"
    When you need to disclose a `RESTRICTED` object to someone briefly, issue a
    time-bounded capability rather than relaxing the object's disclosure policy.
    The capability expires on its own and its issue and revocation are recorded in
    the audit trail.

## Related tasks

- Understand the permissions that gate these views: [Access control](access-control.md).
- Distribute publicly disclosed artefacts: [Publication](publication.md).
