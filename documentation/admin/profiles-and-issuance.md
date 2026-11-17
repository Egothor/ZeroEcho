# Profiles and issuance

For runnable profile, CSR, issuance and holder-confirmation commands, follow
[Set up and administer a PKI](getting-started.md#5-validate-and-manage-certificate-profiles).
Use this page to understand the profile and credential lifecycle contracts.

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

    **Register profile** (`profile.register`) imports a profile document
    (DER or JSON, base64-encoded) into the realm. The behaviour depends on the
    profile's `approvalRequirement` field and on whether the content has changed:

    - **No approval required (`NONE`):** `profile.register` imports the new version
      and immediately activates it. No separate `profile.activate` call is needed.
    - **Approval required (`SINGLE` or `THRESHOLD`):** `profile.register` imports
      the new version but leaves it in DRAFT state. Use `profile.activate` to put
      it into service after the required approval has been obtained.
    - **Identical content (reconciliation):** if the incoming document's content is
      identical to the currently active version (same canonical SHA-256 of the
      document), `profile.register` is a no-op and returns the existing active
      reference without creating a new version.

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

!!! info "Profile document format"
    The structure of a profile JSON document — all fields, types, constraints,
    and enum values — is documented in the
    [Certificate profile schema](../reference/certificate-profile-schema.md)
    reference.

## Certification requests (CSRs)

A certification request carries the subject's public key and proof that they hold
the matching private key. Requests are managed under **Requests (CSRs)**.

- **Import request (CSR)** (`request.import`) — import a DER certification request
  (base64-encoded) with its `formatId`. The server assigns a request identifier
  you use in issuance.
- **Verify request** (`request.verify`) — verify a request by `requestId`,
  including proof of possession.
- **Inspect request** (`request.inspect`) — show one request by `requestId`.

Use `request.list` with `limit` and optional `after` to inventory stored requests
under the applicable read authority. Keep the identifier returned by import and
verify that exact request before using it in issuance.

For request-owned AltSignature issuance, the SDK additionally requires fresh
operation-bound proof of both subject keys. An ordinary single-key CSR alone
does not authorize that form. See the
[approved recipes](../deployment/pki-exercise.md#approved-algorithm-scenarios).

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

Remote signing may remain **pending** after acceptance. Prefer a retained
[administrative request](administrative-requests.md): submit once, retain its
approval/signing identities, have the exact target approved when required, and
observe the original request. Do not re-enter or resubmit it after an uncertain
acknowledgement. Low-level direct operations retain their explicit approval-ID
contract; the [host client](../deployment/pki-operator.md) manages durable request
observation instead. Only terminal SUCCEEDED with the credential result is success.

**Inspect credential** (`credential.inspect`) shows an issued credential by
`credentialId`. Credentials are looked up by identifier (for example the one
returned by issuance); use `credential.list` for the authority inventory below.

## Browse / search credentials

**List stored credentials** (`credential.list`) is the mandatory metadata inventory
and works without H2. Select the issuing `authorityId`, set `limit` from 1 to 1000,
and pass the previous page's `nextCursor` as the optional exclusive `after` cursor.
The local CLI accepts `credential.list --authority-id <id> --limit <1..1000>
[--after <cursor>]`. Metadata listing does not grant certificate-content download
permission.

**Advanced search** (`credential.search`) requires the optional H2 search index
to be activated in the [deployment configuration](../reference/configuration-reference.md).
It lists credentials issued by a given authority. Supply `authorityId` to scope the results, then optionally narrow them
with any combination of the filters below. All filters are optional and
AND-combined: omitting a filter leaves that field unconstrained.

| Filter parameter | Type | How it matches |
|---|---|---|
| `subjectFilter` | optional text | Case-insensitive substring match on the subject distinguished name. For example, `server1` matches `CN=server1,O=Northstar Example`. |
| `serialFilter` | optional text | Case-insensitive substring match on the serial number or unique identifier. |
| `fingerprintFilter` | optional text | Case-insensitive prefix match on the credential ID (`credentialId`); no certificate digest is computed. |
| `statusFilter` | optional enum: `ISSUED`, `REVOKED`, `EXPIRED` | Exact match on the credential's inventory status. |
| `profileIdFilter` | optional text | Exact match on the profile logical identifier. |
| `sanFilter` | optional text | Exact typed SAN match, such as `DNS_NAME:api.example.test`; see [credential search](../user/managing-certificates.md). |

Results are paginated. Use `limit` to control the page size and `after` to advance
to the next page, exactly as in other paginated operations.

!!! note "Fields included in search results"
    Each result row includes `subjectRef` and `serialOrUniqueId` in addition to the
    standard identifier and status fields. Use `credential.inspect` to retrieve full
    credential detail for a specific entry.

!!! tip "Filtering in the admin UI"
    The **Browse certificates** form in the admin UI exposes all five filters as
    labelled input fields: a subject DN substring box, a serial box, a fingerprint
    prefix box, a status dropdown, and a profile ID box. Leave any field blank to
    omit that filter.

## Credential lifecycle

Three operations keep a credential current over its life. All act within the
owning authority.

| Operation | Id | What it does | Approval |
|---|---|---|---|
| **Renew credential** | `credential.renew` | Renews an existing credential by `credentialId`. | Governing profile |
| **Replace credential** | `credential.replace` | Replaces `existingCredentialId` using a new `requestId` and `profileId` (for example a re-key). | Governing profile |
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

Hybrid renewal and reissue require fresh operation-bound proof of **both**
unchanged subject keys; replacement proves the complete requested key tuple.
Use the configured SDK workflow with its retained target, not ordinary replay
of an old proof. Keep exact subject SPKIs and the accepted immutable issuer
selection when checking the resulting certificate.

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

Enroll the exact credential with `certificate.publication.enroll` and its intended
`ownerPrincipalId` before issuing an OWNER_ONLY challenge. Use the challenge's
actual lifecycle revision and lifecycle/challenge commitments; pending-review rows
do not supply those CAS fields. Check expiry and current state before submission.
For RSA with `zeroecho.signature-pop.v1`, sign the decoded presentation with
SHA-256/RSA-PSS, MGF1-SHA256 and a 32-byte salt; ordinary PKCS#1 v1.5 is not valid
for that proof suite. Require `confirmationResult: CONFIRMED`, not merely a
SUCCEEDED operation containing REJECTED. The
[complete command walkthrough](getting-started.md#8-enroll-publication-and-confirm-possession)
shows enrollment, exact response construction and recovery boundaries.

## Related tasks

- Establish the issuing authority first: [Certificate authorities](authorities.md).
- Withdraw an issued credential: [Revocation and status](revocation-and-status.md).
- Distribute the issued certificate: [Publication](publication.md).
