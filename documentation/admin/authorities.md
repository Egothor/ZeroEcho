# Certificate authorities and issuer generations

Owner: PKI maintainers. Reviewed: 2026-11-16. Review on CA/issuer contract
changes. Written procedures remain unverified pending clean-environment rehearsal.
See the [activity reference](operator-activities.md) for the shared retained
CLI/TUI workflow and [algorithm recipes](../deployment/pki-exercise.md#approved-algorithm-scenarios).

A certificate authority (CA) is the trust anchor or intermediate that issues
credentials in your realm. This page covers creating root and intermediate CAs,
issuing subordinate CA certificates, moving an authority through its lifecycle
states, rolling the CA certificate to a new generation, rotating the signing key,
and selecting which chain path an authority issues from.

Authorities are managed under **Certificate Authorities** in the console;
generations and chain paths under **Issuer Generations & Paths**.

!!! warning "Most authority operations are high-risk"
    Creating an authority, transitioning its state, creating or issuing an
    intermediate, rolling over, rotating a key, and selecting an issuance path are
    all classified high-risk and require a durable [approval](access-control.md#approvals).
    Ordinary requesters need another eligible principal. The initial root
    administrator may decide their own request only with explicit own-approval
    permission; justification, eligibility and thresholds still apply.

## The authorities table

The **Certificate Authorities** area lists every authority in the realm
(`ca.list`), showing each authority's identifier, subject, and state. Each row
offers *Inspect authority* (`ca.inspect`) and the state and key operations
described below. Because the server assigns an authority's identifier, the create
flows are offered as explicit actions on this screen.

## Creating a root authority

Use **Create root authority** (`ca.create`). Complete:

| Field | Meaning |
|---|---|
| `formatId` | The certificate format to produce. |
| `subjectRef` | Reference to the subject (distinguished name) material for the root. |
| `profileId` | The [profile](profiles-and-issuance.md) governing the root certificate. |
| `keyRef` | Reference to the key material the root will use. |
| `signatureAlgorithmId` | Optional explicit outgoing signature identity; select the approved compatible binding when composing classical/PQC/hybrid authorities in one realm. |

The console prepares a retained administrative request with its linked approval
for this high-risk operation. Review and submit that exact request, obtain an
eligible justified decision, then observe execution. On terminal success inspect
the returned credential and outgoing issuer generation before selecting the new
authority. The low-level direct API has a separate explicit approval-ID contract;
do not reconstruct a second mutation to recover a pending console request.

## Creating an intermediate authority

An intermediate (subordinate) CA is created against a parent authority that will
issue its CA certificate. Use **Create intermediate CA**
(`ca.intermediate.create`) and complete:

| Field | Meaning |
|---|---|
| `formatId` | Certificate format. |
| `issuerCaId` | The parent authority that will issue the subordinate's certificate (a type-to-search picker). This is also the operation's target authority. |
| `subjectRef` | Subject material for the intermediate. |
| `profileId` | Profile governing the intermediate certificate. |
| `keyRef` | Required existing compatible managed key reference. Generation is a separate protected-FIRST operation; omission does not provision a key. |
| `signatureAlgorithmId` | Optional explicit outgoing signature identity of the new intermediate; its incoming certificate signature is selected from the parent issuer. |

### Issuing an intermediate certificate

To issue (or re-issue) the CA certificate for an already-known subordinate
authority, use **Issue intermediate certificate** (`ca.intermediate.issue`):

| Field | Meaning |
|---|---|
| `formatId` | Certificate format. |
| `issuerCaId` | Issuing (parent) authority — the target authority. |
| `subjectCaId` | The subordinate authority receiving the certificate. |
| `profileId` | Profile governing the issued CA certificate. |
| `notBefore`, `notAfter` | *(Optional)* Explicit validity window; supply both together or neither. |

## Authority lifecycle states

An authority is always in one of three states:

| State | Meaning |
|---|---|
| `ACTIVE` | The authority is in service and may issue. |
| `RETIRED` | The authority has been withdrawn from issuing service. |
| `COMPROMISED` | The authority's key is considered compromised. |

Use **Transition authority state** (`ca.transition`) on the authority row to move
between states. Complete the target `caId`, the new `state`, and a `reason`. The
transition is high-risk and requires approval.

!!! note "Compromise is consequential"
    Marking an authority `COMPROMISED` reflects a key-compromise event and drives
    downstream revocation and status handling. Record the reason precisely; it is
    retained in the [audit trail](audit-and-disclosure.md).

## Certificate rollover and key rotation

Two distinct operations renew an authority's own certificate material:

=== "Roll over the certificate"

    **Roll over CA certificate** (`ca.rollover`) advances the authority's
    certificate to a new generation while keeping the same key. Complete `caId`
    and, for a subordinate, optionally the issuing `issuerCaId`. Rollover is
    high-risk.

=== "Rotate the key"

    **Rotate CA key** (`ca.rotate`) issues a new generation on a *new signing key*.
    Complete `caId` and explicitly select the roles to change: `newKeyRef`,
    `newAlternativeKeyRef`, `primarySignatureAlgorithmId` and/or
    `alternativeSignatureAlgorithmId`, with compatible existing managed keys.
    Omitted roles retain their exact current binding; no implicit key generation
    occurs. Alternative-only rotation does not require a new primary key.
    For a subordinate also select the issuing `issuerCaId` as applicable.
    Rotation is high-risk; compare the captured `expectedHead` fence.

Both operations produce a new **issuer generation** for the authority. Existing
credentials remain chained to the generation that issued them; new issuance uses
the authority's active issuance path (below).

For a root, a change to either role's SPKI or explicit outgoing algorithm is
two-phase: publish a candidate without advancing the selected head; download and
distribute the exact candidate; then perform separate approved path activation
with the expected head, transition commitment and `distributionAcknowledged`.
The acknowledgement does not prove client trust stores were updated. Same-key,
same-algorithm rollover retains the immediate behavior. Hybrid accepted work
keeps its frozen keys/generation, and hybrid leaf lifecycle requires fresh proof
of both applicant keys. See [activity reference](operator-activities.md).

## Issuer generations and chain paths

Every rollover or rotation creates a new issuer generation, and each generation
can be reached by one or more **chain paths** (the ordered list of issuer
certificates from the generation up to a trust anchor). The **Issuer Generations
& Paths** area lets you inspect and manage these.

- **Inspect issuer generation** (`issuer.generation.inspect`) — show one
  generation by `issuerId`.
- **Inspect chain path** (`issuer.path.inspect`) — show one path by `pathId`.
- **List chain paths** (`issuer.path.list`) — list the paths for a given
  `issuerId`. Supply the issuer in the filter bar before the table loads.
- **Register chain path** (`issuer.path.register`) — record a new path for an
  authority, giving the target `caId`, the `issuerId`, and the `parentPathId` it
  extends.

### Selecting the active issuance path

When a generation is reachable by more than one path, choose which one new
issuance uses with **Select issuance path** (`issuer.path.select`). Complete the
target `caId`, the `issuerId`, the chosen `pathId`, and a `reason`. This is
high-risk and requires approval: it changes the chain that every subsequently
issued credential will present, so the reason is recorded for audit.

!!! tip "Publish the chain your relying parties expect"
    After selecting a path, keep the authority's *current chain* repository alias
    pointing at it so relying parties always fetch the intended chain. See
    [Repository aliases](publication.md#repository-aliases).

## Related tasks

- Define what these authorities may issue: [Profiles and issuance](profiles-and-issuance.md).
- Publish CA certificates and chains: [Publication](publication.md).
- Generate revocation status for an authority: [Revocation and status](revocation-and-status.md).
