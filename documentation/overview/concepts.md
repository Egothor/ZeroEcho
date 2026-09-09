# Concepts

This page defines the vocabulary used throughout the documentation. A concise
alphabetical list is also available in the [Glossary](../reference/glossary.md).

## Organising concepts

Realm
:   The administrative boundary a server instance serves. Every authority,
    principal, grant, and audit record belongs to a realm, and access is always
    evaluated within it.

Certificate authority (CA)
:   An issuing authority. A **root** authority signs its own certificate; an
    **intermediate** authority is subordinate to another. Authorities have a
    lifecycle state (for example active, retired, or compromised).

Issuer generation
:   A specific signing generation of an authority. Rolling the CA certificate or
    rotating its key produces a new generation, so historical material remains
    identifiable.

Chain path
:   An explicit certification path from an issuer generation up to a trust
    anchor. An authority has an active issuance path used for newly issued
    certificates.

## Issuance concepts

Certificate profile
:   A versioned template that constrains the certificates an authority issues —
    key usage, extended key usage, validity, and related policy. A profile
    version is registered, validated, then activated.

Certification request (CSR)
:   A request for a certificate carrying a public key and proof that the
    requester holds the corresponding private key. Requests are imported and
    verified before issuance.

Credential
:   An issued certificate together with the platform's record of it. Credentials
    can be inspected, renewed, replaced, reissued, and revoked.

## Status and distribution

Revocation
:   Declaring a credential no longer valid, with a reason (following the standard
    reason codes, including hold and release‑from‑hold semantics).

Status object
:   A signed statement of revocation status — a **CRL** (certificate revocation
    list) or a **delta CRL** carrying only recent changes.

OCSP
:   The Online Certificate Status Protocol — a responder that answers real‑time
    status queries for individual certificates.

Publication
:   Making a certificate or status object available through the public
    repository. A publication record tracks the source, the target, and its
    processing state.

Repository alias
:   A stable route to the *current* artifact of a kind for an authority — for
    example its current CRL or current chain — so relying parties can use a fixed
    URL.

## Access, approval, and audit

Principal
:   An authenticated identity — a person, a service, or a protocol account.

Role template &amp; role assignment
:   A role template is a named bundle of permissions; assigning it to a principal
    grants those permissions within a scope.

Grant
:   An explicit authorization rule: an *effect* (allow or deny) for an *action*
    on a *resource type*, within a *scope*, qualified by a *relationship*, a
    *data view*, and optional *conditions*.

Approval
:   A durable, dual‑control record for a high‑risk action. Such actions return an
    approval requirement; a separate principal must approve before the action can
    proceed, enforcing requester/approver separation.

Break‑glass
:   A pre‑declared, auditable emergency grant that can be activated when normal
    authorization is insufficient.

Audit trail
:   A cryptographically chained log of sensitive actions whose integrity can be
    verified. It supports redacted, full, and PII views according to the
    caller's authorization.

Disclosure
:   The policy controlling how much of an object may be revealed, and to whom,
    including time‑bounded disclosure capabilities.

## Automation

ACME
:   The Automatic Certificate Management Environment protocol, for automated
    enrollment and renewal by ACME clients against a configured directory.

## The operation model

Every administrative action is an **operation**. Operations are executed
synchronously with a bounded wait and return an outcome: it either succeeds,
fails, is still **pending** (when signing is handed off to an external signer and
can be resumed later), or reports that an **approval is required**. This uniform
model underlies the API, the command line, and the web console — see the
[Administrative API](../reference/admin-api.md) for details.
