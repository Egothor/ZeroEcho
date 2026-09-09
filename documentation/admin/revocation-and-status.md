# Revocation and status

This page covers withdrawing trust from credentials and publishing the resulting
status: revoking credentials with the correct RFC 5280 reason (including
certificate hold and its release), inspecting revocation state and history,
generating and inspecting CRLs and delta CRLs, and administering OCSP responders.

Revocation is managed under **Revocation**, CRLs and delta CRLs under **Status &
CRLs**, and responders under **OCSP**.

## Revoking a credential

Use **Revoke credential** (`credential.revoke`) — available as a row action in the
Revocation area and directly by `credentialId`. Complete:

| Field | Meaning |
|---|---|
| `credentialId` | The credential to revoke. |
| `reason` | An RFC 5280 revocation reason (see below). |
| `justification` | *(Optional)* Operator justification, retained for audit. |

Revocation is ordinarily approval-free. However, a matching RBAC grant may
*condition* the revoke permission on approval; when it does, the operation becomes
high-risk and follows the normal [approval](access-control.md#approvals) flow —
the console reports *approval required* with the operation commitment.

### RFC 5280 revocation reasons

The `reason` is one of the standard code points:

| Reason | Use for |
|---|---|
| `UNSPECIFIED` | No specific reason given. |
| `KEY_COMPROMISE` | The subject's private key is compromised. |
| `CA_COMPROMISE` | The issuing CA's key is compromised. |
| `AFFILIATION_CHANGED` | The subject's affiliation or attributes changed. |
| `SUPERSEDED` | The credential has been replaced. |
| `CESSATION_OF_OPERATION` | The subject no longer operates. |
| `CERTIFICATE_HOLD` | Temporary hold — reversible (see hold/unhold below). |
| `REMOVE_FROM_CRL` | Release a certificate previously placed on hold. |
| `PRIVILEGE_WITHDRAWN` | A privilege in the credential has been withdrawn. |
| `AA_COMPROMISE` | An attribute authority's key is compromised. |

### Placing and releasing a hold

Certificate hold is a *reversible* revocation:

=== "Hold"

    Revoke the credential with reason `CERTIFICATE_HOLD`. The credential is treated
    as revoked in status output but can be reinstated.

=== "Release (unhold)"

    Revoke again with reason `REMOVE_FROM_CRL` to lift a hold and restore the
    credential. Only a credential currently on hold can be released.

!!! warning "Compromise reasons are effectively permanent"
    `KEY_COMPROMISE`, `CA_COMPROMISE`, and `AA_COMPROMISE` reflect key-compromise
    events and are not reversible. Reserve `CERTIFICATE_HOLD` for genuinely
    temporary situations.

## Inspecting revocation

- **Inspect revocation** (`revocation.inspect`) — the current revocation state of
  one `credentialId`.
- **Revocation history** (`revocation.history`) — the ordered revocation history
  of a `credentialId`, up to a `limit`. Use this to see hold/unhold sequences and
  reason changes.
- **Snapshot revocations** (`revocation.snapshot`) — a realm-wide snapshot of
  revocations, up to a `limit`, which backs the Revocation table.

## CRLs and delta CRLs

The **Status & CRLs** area produces and inspects status objects. A status object
is either a full CRL or a delta CRL.

- **Generate status object** (`status.generate`) — generate a status object for an
  issuer. Complete the `issuerCaId`, the `type` (`CRL` or `DELTA_CRL`), and the
  `formatId`. Generation runs synchronously; if signing hands off, the outcome may
  be [pending](index.md#some-defer-to-a-signing-hand-off) and resumable.
- **List status objects** (`inventory.status`) — list an issuer's status objects.
  Supply the `issuerCaId` in the filter bar; set an optional `limit`.
- **Inspect status object** (`status.inspect`) — show one status object by
  `statusObjectId`.

=== "Full CRL"

    Choose type `CRL` to produce a complete revocation list for the issuer.

=== "Delta CRL"

    Choose type `DELTA_CRL` to produce a delta relative to a base CRL, for
    lower-latency distribution of recent changes.

!!! tip "Keep relying parties pointed at the current list"
    After generating a CRL or delta, publish it and keep the authority's
    *current CRL* / *current delta CRL* [repository alias](publication.md#repository-aliases)
    pointing at the latest object so relying parties always fetch it.

## OCSP responder administration

The **OCSP** area manages responders that answer online status queries. Register,
activate, deactivate, and inspect responders here; the live query path itself is
served by the responder and is not an administrative operation.

- **Register OCSP responder** (`ocsp.responder.register`) — high-risk; requires
  approval. Its registration binds a responder to an authority and issuer and
  configures how it signs and answers.
- **Activate OCSP responder** (`ocsp.responder.activate`) — high-risk; put a
  registered responder into service.
- **Deactivate OCSP responder** (`ocsp.responder.deactivate`) — withdraw a
  responder from service.
- **Inspect OCSP responder** (`ocsp.responder.inspect`) and **List OCSP
  responders** (`ocsp.responder.list`) — read responder configuration.

Key registration options include:

| Option | Meaning |
|---|---|
| `authorityId`, `issuerId` | The authority and issuer generation the responder answers for. |
| `signingMode` | `ISSUER_SIGNED` (the issuer signs) or `DELEGATED_RESPONDER` (a delegated responder credential signs). |
| `responderCredentialId`, `signingKeyRef`, `signatureAlgorithm` | The signing credential, key, and algorithm. |
| `responderIdForm` | `BY_NAME` or `BY_KEY`. |
| `noncePolicy` | `REJECT`, `OPTIONAL_ECHO`, or `REQUIRED`. |
| `acceptedHashes` | Accepted CertID hashes — `SHA1`, `SHA256`. |
| `requestAuthenticationMode` | `UNSIGNED_ONLY`, `UNSIGNED_OR_AUTHORIZED_SIGNED`, or `AUTHORIZED_SIGNED_REQUIRED`. |
| `responseValidityMillis`, `cacheLifetimeMillis` | Response validity and cache lifetime. |
| `maximumRequestBytes`, `maximumEntries`, `maximumNonceBytes` | Request-size and batching limits. |
| `requesterTrustPolicy` | *(Optional)* JSON policy for authorised signed requests. |

## Related tasks

- Distribute CRLs and certificates: [Publication](publication.md).
- Confirm a compromise event on the authority itself: [Certificate authorities](authorities.md#authority-lifecycle-states).
