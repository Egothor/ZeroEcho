# Administrator Guide

This guide explains how to administer a running ZeroEcho PKI realm: how to create
and govern certificate authorities, issue and manage credentials, publish status
information, control who may do what, and prove after the fact that every change
was authorised. It covers both the web administration console and the equivalent
command-line access over mutual TLS.

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

An administrative action is invoked by posting a request envelope to
`POST /admin/v1/operations/{operationId}`. The envelope carries the operation's
typed arguments and, for authority-scoped operations, the target `authorityId`.
The server validates the arguments, checks that the caller is authorised, executes
the operation, and returns an outcome envelope.

### Executed synchronously with a bounded wait

Operations run synchronously: the call blocks until the operation reaches a
terminal outcome or a bounded wait budget elapses. The outcome is one of:

| Outcome | Meaning |
|---|---|
| **Succeeded** | The operation completed; any result payload is returned. |
| **Failed** | The operation was rejected or could not complete. The failure carries a classification and, where relevant, flags indicating that recovery or reconciliation is required. |
| **Approval required** | The operation is high-risk (or grant-conditioned) and cannot proceed without a durable approval. The response includes the *operation commitment* to bind the approval to these exact arguments. |
| **Pending** | The operation deferred to an asynchronous signing hand-off and did not complete within the wait budget. |

### Some defer to a signing hand-off

Operations that require a CA signature may hand off to a signing service — which,
for a remote signer, can take longer than the synchronous budget. When that
happens the server returns a **pending** outcome that identifies a *signing
operation*. The console polls `/admin/v1/signing-operations/{id}` until the
operation terminalises or the wait budget elapses; if it is still pending, the
work is not lost — it can be resumed later by its signing-operation id. The
command line surfaces the same behaviour, including a distinct exit code for a
still-pending operation (see the [CLI reference](../reference/cli-reference.md)).

### High-risk ones require an approval

Some operations are classified **high-risk** and enforce dual control: they cannot
be executed directly, only through a durable [approval](access-control.md#approvals).
The requester creates an approval that binds the exact operation and arguments;
one or more separate, eligible principals approve it; then the operation is re-run
citing the approval id. A grant may additionally *condition* an otherwise
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
