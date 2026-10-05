# Access control

This page covers who may act in the realm and how their permissions are expressed:
principals, role templates and role assignments, explicit grants, the approval
workflow with requester/approver separation, and break-glass emergency access.

These areas live under **Trust & Access**: **Principals**, **Roles & Grants**,
**Approvals**, and **Break-glass**. The full model is also documented in the
[security model reference](../reference/security-model.md).

!!! warning "Access-control changes are governed changes"
    Registering or disabling a principal, creating a role assignment or a grant,
    and creating or activating break-glass are all high-risk and require an
    [approval](#approvals). Access control is itself dual-controlled.

## Principals

A **principal** is an identity that can authenticate and be authorised. Every
principal has a type:

| Type | Meaning |
|---|---|
| `USER` | A human operator. |
| `SERVICE` | A machine or automation identity. |
| `ACCOUNT` | An enrolment account identity. |
| `PUBLIC` | The unauthenticated public identity. |

The **Principals** area lists principals (`security.principal.list`). Manage them
with:

- **Register principal** (`security.principal.register`) — high-risk; supply
  `principalId`, `type`, `displayName`, and whether it is `enabled`.
- **Enable principal** (`security.principal.enable`) — re-enable a principal.
- **Disable principal** (`security.principal.disable`) — high-risk; disable a
  principal so it can no longer act.
- **Inspect principal** (`security.principal.inspect`).

## Roles and grants

Authorisation is expressed two ways: **role assignments** apply a reusable role
template to a principal, and **grants** express one explicit permission. Both are
managed under **Roles & Grants**, which shows Grants, Role assignments, and Role
templates as tabs.

### Role templates and assignments

- **List role templates** (`security.role-template.list`) and **Inspect role
  template** (`security.role-template.inspect`) — browse the available reusable
  roles and their versions.
- **Create role assignment** (`security.role-assignment.create`) — high-risk;
  assign a template to a principal. Supply `assignmentId`, `principalId`,
  `templateId`, and `templateVersion`; optionally scope it to a `profileId` and
  set an `expiresAt`.
- **Inspect role assignment** (`security.role-assignment.inspect`), **List role
  assignments** (`security.role-assignment.list`), and **Revoke role assignment**
  (`security.role-assignment.revoke`).

### Grants

A grant is one permission expressed over a precise vocabulary. Create it with
**Create grant** (`security.grant.create`) — high-risk — supplying:

| Field | Meaning |
|---|---|
| `grantId`, `principalId` | The grant identity and the principal it applies to. |
| `effect` | `ALLOW` or `DENY`. |
| `action` | The permitted action (see below). |
| `resourceType` | The resource type the action applies to. |
| `issuerId`, `profileId`, `responderId` | *(Optional)* Narrow the grant's scope. |
| `relationship` | `OWN` (only the principal's own objects) or `ANY`. |
| `dataView` | The maximum data view the grant confers (see below). |
| `conditions` | Zero or more conditions that must hold (see below). |
| `expiresAt` | *(Optional)* When the grant expires. |

Inspect, list, and revoke grants with **Inspect grant** (`security.grant.inspect`),
**List grants** (`security.grant.list`), and **Revoke grant**
(`security.grant.revoke`). To test the effective decision for a principal without
performing an action, use **Evaluate authorization**
(`security.authorization.evaluate`), supplying the `principalId`, `action`,
`resourceType`, `relationship`, and `dataView`.

#### Effect, relationship, and data view

| Dimension | Values | Meaning |
|---|---|---|
| **Effect** | `ALLOW`, `DENY` | Whether the grant permits or forbids. A `DENY` overrides. |
| **Relationship** | `OWN`, `ANY` | Whether the grant applies only to objects the principal owns, or to any object. |
| **Data view** | `METADATA_REDACTED`, `METADATA_FULL`, `CONTENT_FULL`, `PII_FULL` | The maximum sensitivity of data the grant exposes. Content and PII authority are kept separate — neither is implied by the other. |

#### Conditions

Conditions are closed, non-programmable predicates attached to a grant:

| Condition | Effect |
|---|---|
| `REASON_REQUIRED` | The action must carry a reason/justification. |
| `APPROVAL_REQUIRED` | The action must proceed through an approval, even if not statically high-risk. |
| `REQUESTER_APPROVER_SEPARATION` | The requester may not also approve. |
| `AUTHORITY_ACTIVE` | The target authority must be `ACTIVE`. |
| `PROFILE_MATCH_REQUIRED` | The action's profile must match the grant's profile scope. |

#### Actions and resource types

Grants draw their `action` and `resourceType` from fixed vocabularies. Actions
span the whole surface — realm and server configuration, principal and role
management, permission granting, authority lifecycle, issuer and chain operations,
profile management, request handling, certificate issuance and lifecycle,
certificate reads at metadata/content/PII levels, revocation and hold, CRL
generate/publish/download, OCSP administration and queries, publication
register/process/retry/reconcile, audit reads (redacted/full/PII), export and
integrity verification, backup and restore, disclosure and capability management,
repository-alias management, and ACME directory/account management. Resource types
cover the corresponding objects (authority, issuer, profile, certificate,
revocation, status object, publication, audit, disclosure, capability, approval,
break-glass, repository alias, ACME directory/account, OCSP responder, and the
server/realm/principal/role/grant control objects).

The complete enumerations are listed in the
[security model reference](../reference/security-model.md). For a per-operation
lookup table that maps every operation ID to its required action and resource
type, see the
[operation permissions reference](../reference/operation-permissions.md).

## Approvals

An **approval** is a durable record that authorises one exact high-risk (or
grant-conditioned) operation to run. It binds the operation identity, the exact
arguments (through an *operation commitment*), and the scope, so an approval can
never be reused for a different action.

The lifecycle of an approval:

| State | Meaning |
|---|---|
| `PENDING` | Awaiting decisions. |
| `APPROVED` | The threshold of approvals has been met; it can be claimed. |
| `REJECTED` | An approver rejected it. |
| `EXPIRED` | Its lifetime elapsed before it was approved or executed. |
| `CANCELLED` | The requester cancelled it. |
| `EXECUTING` | It has been claimed and the operation is running. |
| `EXECUTED` | The operation completed; the safe result is linked to the record. |

Manage approvals under **Approvals** (`security.approval.list`):

- **Request approval** (`security.approval.request`) — create a pending approval.
  Supply the `approvalId`, the `targetOperation` id, the `targetArguments` (a JSON
  object of the exact arguments), and, for an authority-scoped target, the
  `targetAuthorityId`. In the console, a high-risk operation form can create this
  for you from the *approval required* outcome.
- **Approve** (`security.approval.approve`) and **Reject**
  (`security.approval.reject`) — record a decision with a `justification`.
- **Cancel approval** (`security.approval.cancel`) — the requester withdraws a
  pending request.
- **Inspect approval** (`security.approval.inspect`).

Once an approval reaches `APPROVED`, re-run the target operation citing the
approval id; the server claims the approval, executes the operation, and links the
result.

### Requester/approver separation

An approval policy defines a **threshold** of distinct approvals and the set of
eligible approvers (named principals and/or required role templates), a lifetime,
and whether a **justification** is mandatory. Crucially, a policy can require
**requester separation**: the principal who requested the approval is barred from
approving it, and no principal may record more than one decision. This enforces
genuine dual control rather than self-approval.

!!! note "Approvals expire"
    A pending or approved approval that is not acted on within its policy lifetime
    expires automatically and can no longer be executed. Request a fresh approval
    if this happens.

## Break-glass emergency access

Break-glass provides a controlled path to emergency privilege when the normal
grant path is insufficient. It is deliberately conspicuous: creation and
activation are both high-risk and every step is audited.

Manage break-glass under **Break-glass** (`security.break-glass.list`):

- **Create break-glass** (`security.break-glass.create`) — high-risk. Supply the
  `breakGlassId`, the `principalId` it empowers, the `grantId` it stands in for,
  the `action` and `resourceType` it covers, a `reason`, and a mandatory
  `expiresAt`.
- **Activate break-glass** (`security.break-glass.activate`) — high-risk; bring
  the emergency grant into effect.
- **Revoke break-glass** (`security.break-glass.revoke`) — withdraw it.
- **Inspect break-glass** (`security.break-glass.inspect`).

!!! warning "Use, then account for, break-glass"
    Every break-glass grant is time-bounded and requires a reason, and each
    creation, activation, and revocation is recorded in the
    [audit trail](audit-and-disclosure.md). Treat any break-glass activation as a
    reviewable event.

## Related tasks

- See the outcome of governed actions: [Audit and disclosure](audit-and-disclosure.md).
- Understand how discoverability reflects your permissions in the UI:
  [The administration console](console.md#the-console-hides-what-you-cannot-do).
