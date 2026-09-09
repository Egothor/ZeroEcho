# Glossary

A concise reference for terms used across this documentation. See
[Concepts](../overview/concepts.md) for fuller explanations.

ACME
:   Automatic Certificate Management Environment — a protocol for automated
    certificate enrollment and renewal.

Approval
:   A durable dual‑control record required before a high‑risk action proceeds,
    enforcing requester/approver separation.

Authority (CA)
:   A certificate authority; may be a self‑signed **root** or a subordinate
    **intermediate**.

Break‑glass
:   A pre‑declared, auditable emergency grant activated when normal authorization
    is insufficient.

Chain path
:   An explicit certification path from an issuer generation to a trust anchor.

Credential
:   An issued certificate together with the platform's record of it.

CRL / Delta CRL
:   Certificate Revocation List — a signed list of revoked certificates. A delta
    CRL carries only the changes since a base CRL.

CSR (certification request)
:   A request for a certificate carrying a public key and proof of possession of
    the private key.

Data view
:   The level of detail a caller is authorized to see (for example redacted,
    full, or including personal data).

Disclosure
:   Policy governing how much of an object is revealed and to whom, including
    time‑bounded disclosure capabilities.

Grant
:   An explicit authorization rule combining effect, action, resource type,
    scope, relationship, data view, and conditions.

Issuer generation
:   A specific signing generation of an authority, produced by certificate
    rollover or key rotation.

Keyring
:   The protected storage for authorities' private keys, kept separate from the
    metadata store.

Mutual TLS (mTLS)
:   TLS in which both server and client present certificates; the platform
    authenticates every request this way.

OCSP
:   Online Certificate Status Protocol — real‑time certificate status responses.

Operation
:   The unit of administrative action, executed synchronously with a bounded wait
    and returning a succeeded, failed, pending, or approval‑required outcome.

Post‑quantum cryptography (PQC)
:   Cryptographic algorithms designed to resist attacks by quantum computers,
    supported alongside classic algorithms.

Principal
:   An authenticated identity — a person, service, or protocol account.

Profile (certificate profile)
:   A versioned template constraining the certificates an authority issues.

Publication
:   Making a certificate or status object available through the public
    repository; tracked by a publication record.

Realm
:   The administrative boundary within which authorities, principals, grants, and
    audit records live and access is evaluated.

Repository alias
:   A stable route to the current artifact of a kind (for example the current CRL
    or chain) for an authority.

Revocation
:   Declaring a credential no longer valid, with a standard reason code.

Role template / role assignment
:   A named bundle of permissions, and the act of granting it to a principal
    within a scope.

Scope
:   The realm, authority, issuer, or profile boundary within which a grant
    applies.

Status object
:   A signed statement of revocation status, such as a CRL or delta CRL.
