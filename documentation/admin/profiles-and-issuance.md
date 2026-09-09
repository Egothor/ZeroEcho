# Profiles and issuance

This page covers the material that governs what may be issued and the act of
issuing it: registering, validating, inspecting, and activating certificate
profile versions; importing and verifying certification requests (CSRs); issuing
credentials; and the credential lifecycle — renew, replace, and reissue.

Profiles are managed under **Certificate Profiles**, requests under **Requests
(CSRs)**, issuance under **Issuance**, and the lifecycle actions under
**Lifecycle**.

## Certificate profiles

A **profile** is a versioned document that constrains a class of certificates —
key usage, validity, subject rules, and the issuance-approval requirement. A
profile is registered as a document, validated, and then a specific version is
activated for use.

### Registering and validating

=== "Register"

    **Register profile** (`profile.register`) uploads a profile document
    (DER or JSON, base64-encoded) into the realm. Registration alone does not put
    the profile into service — you activate a version separately.

=== "Validate without registering"

    **Validate profile** (`profile.validate`) checks a profile document for
    correctness and returns the findings *without* registering it. Use this to
    dry-run a document before committing it.

### Inspecting versions

- **List profile versions** (`profile.list`) — list the versions of a profile.
  Supply the `profileId` in the filter bar before the table loads.
- **Inspect profile** (`profile.inspect`) — show one version by `profileId` and
  `profileVersion`.

### Activating a version

**Activate profile** (`profile.activate`) puts a specific `profileVersion` into
service for the given `profileId`. Activation is high-risk and requires an
[approval](access-control.md#approvals): it changes the constraints applied to
every credential subsequently issued under that profile.

!!! note "The profile decides whether issuance needs approval"
    Whether issuing a credential requires a single approval or a threshold of
    approvals is carried by the resolved profile, not by the issue operation. A
    profile can therefore make its own issuance subject to dual control without
    any change to the issuing workflow.

## Certification requests (CSRs)

A certification request carries the subject's public key and proof that they hold
the matching private key. Requests are managed under **Requests (CSRs)**.

- **Import request (CSR)** (`request.import`) — import a DER certification request
  (base64-encoded) with its `formatId`. The server assigns a request identifier
  you use in issuance.
- **Verify request** (`request.verify`) — verify a request by `requestId`,
  including proof of possession.
- **Inspect request** (`request.inspect`) — show one request by `requestId`.

Requests do not have a realm-wide list; keep the identifier returned by import (or
inspect it directly) to reference it in the next step.

!!! tip "How requesters submit"
    End users can submit and track their own requests. See
    [Requesting certificates](../user/requesting-certificates.md) in the User
    Guide, and [Protocols](protocols.md) for automated ACME enrolment.

## Issuing a credential

**Issue credential** (`credential.issue`) mints a credential from a verified
request and a profile. Complete:

| Field | Meaning |
|---|---|
| `issuerCaId` | The issuing authority (a picker) — also the operation's target authority. |
| `requestId` | The certification request to issue against. |
| `profileId` | The profile governing the issued certificate. |

Issuance runs synchronously with a [bounded wait](index.md#executed-synchronously-with-a-bounded-wait).
If the issuing authority hands off to a signing service that does not return in
time, the outcome is **pending** and identifies a signing operation to resume. If
the resolved profile requires it, the outcome is **approval required** — create a
single or threshold approval, have it approved, and re-run citing the approval id.

**Inspect credential** (`credential.inspect`) shows an issued credential by
`credentialId`. Credentials are looked up by identifier (for example the one
returned by issuance) rather than from a realm-wide list.

## Credential lifecycle

Three operations keep a credential current over its life. All act within the
owning authority.

| Operation | Id | What it does | Approval |
|---|---|---|---|
| **Renew credential** | `credential.renew` | Renews an existing credential by `credentialId`. | None |
| **Replace credential** | `credential.replace` | Replaces `existingCredentialId` using a new `requestId` and `profileId` (for example a re-key). | None |
| **Reissue credential** | `credential.reissue` | Reissues a credential (same key) by `credentialId`. | High-risk |

=== "Renew"

    Choose *Renew credential* and supply the `credentialId`. The credential is
    renewed under its governing profile.

=== "Replace"

    Choose *Replace credential* and supply the `existingCredentialId`, a new
    verified `requestId`, and the `profileId`. Use this when the subject key or
    request changes.

=== "Reissue"

    Choose *Reissue credential* and supply the `credentialId`. Reissue keeps the
    same key and is high-risk, so it requires an approval.

### Credential confirmation

Some profiles require the holder to confirm possession before the credential is
fully in force. The **Credential Confirmation** area supports this exchange:

- **List pending confirmations** (`credential.confirmation.pending.list`) —
  pending confirmations for an authority, filterable by profile and cutoff.
- **Issue confirmation challenge** (`credential.confirmation.challenge.issue`) —
  issue a proof-of-possession challenge for a `credentialId`.
- **Complete confirmation proof** (`credential.confirmation.proof.complete`) —
  complete the challenge with the holder's response and the expected lifecycle
  commitments.
- **Revoke pending confirmation** (`credential.confirmation.pending.revoke`) —
  withdraw a pending confirmation, optionally with a justification.

## Related tasks

- Establish the issuing authority first: [Certificate authorities](authorities.md).
- Withdraw an issued credential: [Revocation and status](revocation-and-status.md).
- Distribute the issued certificate: [Publication](publication.md).
