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

## Automatic status generation

Instead of invoking `status.generate` manually or from an external scheduler,
you can configure an in-product schedule for each CA and status type. When a
schedule is active the server's background worker checks due work at least once
per minute while idle, and sooner for a known due time. It prepares a full or
delta CRL using the configured validity interval, durably accepts signing, and
optionally registers and processes one publication attempt.

No schedules exist until you create one. Scheduling requires a configured signing
service and a store supporting durable scheduling. Automated OCSP generation is
not offered. Manual generation retains its existing validity policy.

### Managing schedules

Requires the `STATUS_SCHEDULE_MANAGE` permission.

- **Set status schedule** (`status.schedule.set`) — create or replace the
  schedule for one CA + status-type pair.
- **Inspect status schedule** (`status.schedule.inspect`) — show the schedule
  for one CA + status-type pair.
- **List status schedules** (`status.schedule.list`) — page through enabled
  schedules; inspect a known CA/type pair to read a disabled schedule.

### Schedule fields

| Field | Meaning |
|---|---|
| `caId` | Issuing authority identifier. |
| `statusType` | `CRL` or `DELTA_CRL`. |
| `formatId` | `x509`. |
| `interval` | ISO 8601 duration — how often to generate (minimum `PT1M`). |
| `graceSeconds` | Seconds before `nextUpdate` to trigger early generation; use `0` for no lead time. Must leave at least one whole second of cadence after CRL timestamp truncation. |
| `enabled` | `true` to activate; `false` to pause without deleting. |
| `targetType`, `targetId` | *(Optional)* Configured publication destination. If omitted the worker generates the status object but does not publish it. |

### Due-time derivation

The next due instant is persisted from the committed execution's `nextUpdate`
minus the current configured grace. A new schedule is immediately due. Restart
does not reset that deadline; missed occurrences coalesce into one fresh CRL.

### Restart, edits, and failures

Each occurrence has a deterministic execution identity and a captured configuration
revision. The canonical CRL identifier remains the SHA-256 identity of its DER.
Signing acceptance and its schedule receipt commit together. Status content and
the `EFFECT_COMMITTED` marker also commit together, so recovery after publication
of the status object advances the schedule without generating another signature.
The worker traverses all pages, including unfinished work whose configuration has
since been disabled.

`status.schedule.inspect` exposes `nextDue`, `workerRevision`, and, when present,
`executionState`, `executionId`, `signingOperationId`, and `failureCode`.
Disabling prevents fresh claims; it does not revoke accepted signing work.
An explicit configuration edit fences an unaccepted claim. After a proven terminal
signing failure, explicitly setting the configuration again clears `FAILED` and
authorizes a fresh occurrence. Accepted pending work always resumes its recorded
signing operation; editing cadence or target does not replace it.

Publication registration uses a deterministic identity. Pending publication is
attempted before schedule advancement. A crash before that attempt remains
recoverable even after disabling the schedule. Once an attempt is durably recorded,
failure or uncertainty does not block future CRL refreshes: use the existing
publication retry/reconcile operations for delivery follow-up. There is no blind
automatic retry of an uncertain external effect.

Scheduling failures produce safe log codes, audit events, and the server's
`statusScheduleFailureTotal` counter. Repeated observation of one persisted
`FAILED` execution does not create another failure event. See
[Operational monitoring](operational-monitoring.md) for metric availability.

Existing version-18 stores without schedules open as an empty schedule set. New
schedule records use versioned metadata namespaces; downgrade after using this
feature is not supported. Backups and historical snapshots retain current signing
and scheduling safety state so restoring history does not repeat accepted work.

### High-availability note

The PKI publication-runtime ownership invariant guarantees that only one active
server instance holds the store write lease at a time. The scheduler therefore
needs no additional distributed-lock infrastructure — lease fencing prevents
concurrent generation across replicas.

### External scheduling

If you prefer to drive generation from an external scheduler (cron, Kubernetes
CronJob, CI/CD pipeline), do not configure an in-product schedule. Instead,
call `status.generate` directly via the CLI or REST API:

```
status.generate issuerCaId=<id> type=CRL formatId=crl.v2
```

followed by `publication.register` and `publication.process` if you want to
publish the result.

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
