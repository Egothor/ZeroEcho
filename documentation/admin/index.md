# Administrator Guide

This guide explains how to administer a running ZeroEcho PKI realm: how to create
and govern certificate authorities, issue and manage credentials, publish status
information, control who may do what, and prove after the fact that every change
was authorised. It covers both the web administration console and the equivalent
command-line access over mutual TLS.

Start with the [operator activity reference](operator-activities.md) to find each
task's permissions, inputs, approval, result checks and safe recovery. The
[interface reference](../reference/pki-operator-interfaces.md) distinguishes the
host CLI/TUI, direct remote Java CLI and exclusive local store administration.

If you have not yet stood up the platform, start with the
[Deployment Guide](../deployment/index.md). If you are new to the platform's
vocabulary, the [concepts overview](../overview/concepts.md) introduces
authorities, profiles, credentials, and status objects.

## What an administrator does

An administrator is any principal that authenticates to the realm with an X.509
client certificate and holds permissions to act on it. In practice the work falls
into a handful of recurring activities:

- **Establish trust.** Create root and intermediate
  [certificate authorities](authorities.md), issue subordinate CA certificates,
  and choose the chain path each authority issues from.
- **Define what may be issued.** Register, validate, and activate certificate
  [profiles](profiles-and-issuance.md), import certification requests, and issue
  credentials.
- **Keep credentials current.** Renew, replace, and reissue credentials over
  their lifetime.
- **Withdraw trust.** [Revoke](revocation-and-status.md) credentials with the
  correct RFC 5280 reason, place and release certificate holds, and generate CRLs,
  delta CRLs, and OCSP responses.
- **Distribute artefacts.** [Publish](publication.md) certificates and status
  objects to filesystem, LDAP, HTTP, or object-store targets, and maintain stable
  [repository aliases](publication.md#repository-aliases) that always point at the
  current CRL or chain.
- **Govern access.** Manage [principals, roles, and grants](access-control.md),
  approve high-risk work, and grant time-bounded emergency access.
- **Prove integrity.** Search the [audit trail](audit-and-disclosure.md), read it
  at the appropriate level of detail, and verify that the audit chain has not been
  tampered with.

The console groups these activities into navigation areas; the
[console tour](console.md) walks through each one.

## The administration surface

Everything an administrator can do is exposed as a fixed catalogue of named
**operations** on the server's administrative HTTPS listener. There are two
families:

| Family | Purpose | Examples |
|---|---|---|
| `PKI_OPERATION` | Acts on PKI state — authorities, profiles, requests, credentials, revocation, status, publication. | `ca.create`, `credential.issue`, `credential.revoke`, `status.generate` |
| `SERVER_CONTROL_OPERATION` | Governs the server itself — principals, roles, grants, approvals, disclosure, audit, ACME, OCSP, repository aliases. | `security.principal.register`, `security.grant.create`, `security.approval.approve` |

Each operation is either **realm-scoped** (it acts across the realm and carries no
authority) or **authority-scoped** (it acts within one certificate authority and
must name that authority). Each operation is also classified as a **read** or a
**mutation**, which determines the permission it requires and whether it can
commit state.

You reach these operations three ways, all of which invoke exactly the same
server operation and enforce exactly the same rules:

- **The web console** — task-oriented screens over the operation catalogue.
- **The command line** — `zeroecho pki` against a running server; see
  [Administering from the command line](command-line.md).
- **The HTTP API directly** — documented in the
  [Admin API reference](../reference/admin-api.md).

## The operation model

Understanding one uniform execution model explains the behaviour of every screen
in the console.

### Every action is an operation

Every action has a typed catalog operation and authority scope. The console
uses `durableRequest` metadata to select the retained business workflow:
`POST /admin/v1/requests` once, then `GET /admin/v1/requests/{requestId}` for
approval/execution/result observation. Arguments and linked approval/signing IDs
stay attached to that original request. See
[administrative requests](administrative-requests.md).

Reads and dedicated actions retain their direct
`POST /admin/v1/operations/{operationId}` contract. A semantic read can therefore
use POST without being a mutation. Dedicated decisions/proofs/backup transfers
have their documented separate once-only or binary transport boundaries. The
server validates arguments and authorization for every path; no unavailable
durable operation falls back to approval-then-repeat.

### Executed synchronously with a bounded wait

Low-level direct operation calls have a bounded wait and the following outcomes.
This does not make console business signing synchronous or mean a durable
request should be submitted twice:

| Outcome | Meaning |
|---|---|
| **Succeeded** | The operation completed; any result payload is returned. |
| **Failed** | The operation was rejected or could not complete. The failure carries a classification and, where relevant, flags indicating that recovery or reconciliation is required. |
| **Approval required** | The operation is high-risk (or grant-conditioned) and cannot proceed without a durable approval. The response includes the *operation commitment* to bind the approval to these exact arguments. |
| **Pending** | The operation deferred to an asynchronous signing hand-off and did not complete within the wait budget. |

### Some defer to a signing hand-off

Operations that require a CA signature may outlast the direct call's wait budget.
A low-level call returns a **pending** outcome with its signing identity;
`/admin/v1/signing-operations/{id}` provides authorized GET inspection. The console
and reusable host client retain the outer administrative request and observe that
original request instead of reconstructing it. Pending or approved states are
not success. Preserve all returned identities and never resubmit after an
uncertain acknowledgement. The direct Java CLI's distinct pending/observation
exits are in the [CLI reference](../reference/cli-reference.md).

### High-risk ones require an approval

Some operations are classified **high-risk** and enforce dual control: they cannot
be executed directly, only through a durable [approval](access-control.md#approvals).
The retained business request binds its linked approval to the exact operation
and arguments. Eligible justified decisions allow server execution to continue;
the operator observes the original request, without another business submission.
Ordinary requesters need another eligible principal; explicit root own-approval
does not waive thresholds or eligibility. Low-level direct clients retain their
separate explicit approval-ID contract. A grant may additionally *condition* an otherwise
approval-free operation (for example a revocation) on approval. Examples of
statically high-risk operations include creating an authority (`ca.create`),
transitioning an authority's state (`ca.transition`), selecting an issuance path
(`issuer.path.select`), registering a principal (`security.principal.register`),
creating a grant (`security.grant.create`), and creating or activating
break-glass access.

!!! note "Issuance approval is decided by the profile"
    End-entity issuance (`credential.issue`) is not statically high-risk. Whether
    it needs a single or a threshold approval is decided per issuance from the
    resolved [certificate profile](profiles-and-issuance.md), not from the
    operation identity.

## Authorisation in one paragraph

Every operation requires a permission expressed over an **action**, a
**resource type**, and a **scope**, and evaluated against the caller's roles and
grants. The console never shows you an operation you cannot invoke, but the server
remains the sole authority: it independently re-checks every request and fails
closed. The full vocabulary — effects, actions, resource types, relationships,
data views, and conditions — is described under
[Access control](access-control.md) and in the
[security model reference](../reference/security-model.md).

## Where to go next

| If you want to… | Read |
|---|---|
| Learn the console layout and conventions | [The administration console](console.md) |
| Create and govern CAs | [Certificate authorities](authorities.md) |
| Define profiles and issue credentials | [Profiles and issuance](profiles-and-issuance.md) |
| Revoke and publish status | [Revocation and status](revocation-and-status.md) |
| Publish artefacts and manage aliases | [Publication](publication.md) |
| Manage principals, roles, and approvals | [Access control](access-control.md) |
| Search and verify the audit trail | [Audit and disclosure](audit-and-disclosure.md) |
| Administer ACME enrolment | [Protocols](protocols.md) |
| Script against the server | [Command line](command-line.md) |
| Monitor the server in production | [Operational monitoring](operational-monitoring.md) |
