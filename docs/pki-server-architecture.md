# ZeroEcho PKI Server Architecture and Authorization Model

**Status:** Normative architecture decision  
**Version:** 1.0  
**Target location:** `docs/pki-server-architecture.md`  
**Applies to:** `pki`, planned `pki-server`, future ACME and public repository interfaces  
**Change authority:** Project owner approval is required for any semantic change to this document.

## 1. Purpose

This document defines the mandatory architecture, authority boundaries, authorization model, disclosure model, approval model, and ACME integration principles for the ZeroEcho PKI server.

The implementation MUST remain consistent with this document. Codex, contributors, future agents, and maintainers MUST NOT silently reinterpret or weaken these decisions.

A change to this document is an explicit architecture decision. It MUST NOT be introduced as an incidental implementation detail, compatibility workaround, optimization, or refactoring.

## 2. Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

Where this document conflicts with an implementation convenience, the document prevails unless the project owner explicitly approves a revision.

## 3. Core architectural decision

### 3.1 Multi-CA server process

One ZeroEcho PKI server process MUST be capable of serving multiple certificate authorities.

A deployment MAY still configure a server process to expose only one authority.

The server process MUST NOT assume that one process equals one CA.

### 3.2 PKI realm

A server process serves one **PKI realm**.

A realm is one shared operational and security domain containing one or more logical authorities.

A realm MAY share:

- authentication configuration;
- authorization policy;
- audit infrastructure;
- configured cryptographic providers;
- configured publisher providers;
- a logical PKI store;
- process lifecycle and health state.

Every logical authority inside the realm MUST retain separate:

- `authorityId`;
- issuer generations;
- `KeyRef` and signing authority;
- profiles and issuance policy;
- revocation state;
- CRLs and other status objects;
- publication policy;
- disclosure policy;
- authorization scope;
- readiness and lifecycle state;
- audit scope.

### 3.3 Isolation boundaries

Unrelated trust domains, organizations, regulatory domains, classification levels, or HSM security domains SHOULD use separate realms and normally separate server processes.

A single process is a shared compromise boundary. Deployments MUST NOT assume that logical multi-CA separation is equivalent to process or HSM isolation.

### 3.4 Root CA deployment

Offline or high-assurance root CAs SHOULD run outside the continuously online issuing server.

Recommended topology:

```text
offline or high-assurance root realm
        |
        +-- signs intermediate CA certificates
                |
                +-- online issuing realm
                        |
                        +-- issues leaf certificates
```

A root CA MAY be served online only through an explicit deployment decision and corresponding security policy.

## 4. Authority and issuer model

### 4.1 Logical authority

A **logical authority** is the long-lived administrative and policy identity of a CA service.

It survives issuer rotation.

### 4.2 Issuer generation

An **issuer generation** is one concrete CA certificate, signing key reference, validity period, and lifecycle state.

Example:

```text
authority: internal-tls
    issuer: 2024-retiring
    issuer: 2026-active
```

### 4.3 Identity model

The server MUST distinguish at least:

- `realmId`;
- `authorityId`;
- `issuerId`;
- `credentialId`;
- `requestId`;
- `statusObjectId`;
- `publicationId`.

These identities MUST use canonical ZeroEcho identities such as `PkiId`.

No magic numeric identifier is permitted.

In particular:

- certificate ID `1` MUST NOT implicitly mean a CA certificate;
- an authority certificate MUST be retrieved through an authority/issuer-specific operation;
- a random object ID MUST NOT be treated as an access token.

## 5. Server and module boundaries

### 5.1 `pki`

The `pki` module remains the reusable backend authority.

It owns:

- PKI domain services;
- certificate profiles and policy;
- authority and issuer lifecycle;
- issuance;
- revocation;
- status objects;
- publication state;
- snapshots and restore;
- X.509 algorithm bindings;
- durable persistence and recovery;
- transport-neutral typed PKI operations;
- lifecycle-owned `PkiSession`.

It MUST NOT depend on HTTP, CLI parsing, terminal output, process exit codes, or server authentication types.

### 5.2 `pki-server`

The planned `pki-server` module owns:

- HTTP or other network transport;
- server configuration;
- authentication;
- authorization;
- request admission;
- bounded execution;
- request cancellation and deadlines;
- API versioning;
- server lifecycle;
- transport-safe auditing;
- health and readiness endpoints.

It MUST reuse `PkiSession` and transport-neutral typed operations from `pki`.

It MUST NOT duplicate PKI business rules.

Store allocation receives an immutable `PkiStoreRuntimeDependencies` object.
Its non-null `Clock` is the same authoritative clock already selected by the
owning `PkiSession`; the provider must use that exact instance for persisted
expiry and lifecycle decisions. Explicit bootstrap composition propagates the
dependency through the provider SPI, while the one-argument production path
selects `Clock.systemUTC()`. This is request-independent composition state, not
a second lifecycle owner, and it adds no worker, queue, cache, or handle.

Pending credential-confirmation administration is a transport-neutral PKI read
operation. The confirmation lifecycle remains authoritative; two derived
metadata projections provide authority-wide and exact authority-profile keyset
paging ordered by review time and credential identity. The issued credential is
the authoritative source of authority and profile during projection creation
and recovery. Confirmation removes both projections in the same transaction as
the lifecycle transition. Cursors bind the store, cutoff, and exact query scope.
The query examines at most `E = limit` scoped projections, returns their
actionable subset, and performs bounded `O(log M + E log M)` work with `O(E)`
result memory. It may additionally collect and delete at most thirty exact
derived revisions for at most ten authoritative permanently-revoked
credentials after closing the snapshot. Empty pages may therefore continue via
the last-examined cursor; only an absent cursor denotes completion. Concurrent
revision conflicts are benign, uncertain durability fails the read, and
malformed or non-permanently-revoked state is never deleted. The query never
scans an inaccessible global page before filtering. The projections add no
lifecycle owner, worker, thread, queue, cache, or long-lived handle.

Overdue pending-confirmation revocation is a separate transport-neutral typed
mutation rather than a non-atomic composition of list and general revocation.
The gateway reconstructs the exact credential authority/profile/object scope
before applying `CERTIFICATE_REVOKE`; a nested approval request reconstructs the
same target and enclosing approval scope before authorization and commitment.
The list's `CERTIFICATE_SEARCH` permission does not authorize mutation. The
filesystem store serializes the specialized
transition with confirmation under the existing credential lock, reads its own
authoritative clock, and admits only a non-public `PENDING` lifecycle strictly
after `confirmationReviewAt`. Equality is still timely. The revocation log is
authoritative and records fixed permanent reason `UNSPECIFIED`; lifecycle state
remains historically `PENDING`.

After the revocation append is known committed, derived review projections and
the outstanding challenge are removed. Reads and startup recovery define an
actionable review as `PENDING` with no revocation history, so interrupted cleanup
cannot restore confirmation or return a revoked credential. Exact retry evidence
may finish cleanup; startup also removes stale derived records without resident
retry machinery. One revocation is a constant number of `O(log M)` point
operations plus bounded append/fsync and bounded metadata cleanup with `O(1)`
auxiliary memory. No new index, lifecycle state, worker, queue, cache, handle, or
requester identity is introduced.

Administrative proof-challenge issuance is a transport-neutral mutating PKI
operation with only a credential identity as its typed argument. The server
gateway uses the committed credential to reconstruct authority, frozen profile,
and object scope before authorization, while treating the mandatory outer
authority only as a cross-check. After exact
`CERTIFICATE_PUBLICATION_CHANGE` authorization, the PKI executor loads the
authoritative pending lifecycle, constructs the internal revision-and-record
commitment expectation, and delegates once to the existing confirmation
service. This keeps replay, expiry replacement, concurrency, proof-provider
selection, and challenge persistence in their existing authority and introduces
no duplicate lifecycle state or resident request object. After authorization,
challenge construction uses `O(D + K + T)` CPU, bounded credential-content I/O,
and a constant number of `O(log M)` metadata point operations; memory is bounded
by 1 MiB DER and the 2048-byte pre-Base64 presentation bound. Whole-request cost
also includes existing grant/role scans and audit/transport I/O.

Administrative proof completion is a second transport-neutral adapter over the
same confirmation service. The strict operation supplies only the credential
identity, exact lifecycle/challenge CAS coordinates, and a bounded proof
response. The gateway reuses the same one-lookup authoritative scope
reconstruction as challenge issuance before applying exact
`CERTIFICATE_CONFIRM` authorization. The operation commitment contains the CAS
coordinates and a SHA-256 response digest, never the response. The executor
delegates once; `REJECTED` is a successful non-mutating proof outcome and exact
terminal replay remains the core service's idempotent `CONFIRMED` result. The
pending path uses `O(D + T + R + V(K))` post-authorization CPU plus a constant
number of `O(log M)` metadata point operations; exact terminal replay uses
`O(R + log M)` without provider, DER, or proof verification. Memory is bounded
by 1 MiB credential content, 2 KiB presentation, and 16 KiB response. Existing
grant/role scans and audit/transport I/O remain separate whole-request costs.

Signing submission, status, result consumption, reconciliation, restart, and
retirement derive from `SignWorkflowStore`. A signing-backed CA, issuance, or
status operation additionally owns one bounded, versioned domain continuation
in the same segmented metadata ledger, keyed by the same private `PkiId`. The
signing record owns signing only; the domain record owns the exact command,
frozen commitments and content references required to publish that domain
result. Where signing may yield, both records and their staged-content ownership
are created by one ledger transaction. Signing MUST NOT synchronously project
operations into the generic workflow-state store or append-only async-bus log.
Those generic APIs remain available for unrelated asynchronous consumers.

### Signing operation identity and execution model

At operation start, the client and server establish one private, unambiguous
submission identifier. Every later submit, status, cancellation, reconciliation,
result, retirement, and audit action refers to that identifier. The authoritative
record stores the state-machine position and the durable context needed for the
next transition. A process may reconstruct that context from the identifier and
record at any time; a workflow is not represented by a long-lived in-memory
handle.

The signing provider and its security-relevant configuration are selected when
the operation first applies that configuration. The durable namespace identifies
the selected workflow/provider and the configuration commitment detects whether
its exact configuration still matches; the commitment is not a copy of endpoint
credentials or other secrets. A later administrative configuration change MUST
NOT reroute an already-started operation. The active session continues using its
already-applied provider configuration. The administrator is responsible for
keeping that configuration available when completion is required. If it is
removed, is unavailable after reload or restart, no longer responds, or no
longer recognizes the identifier, the operation remains durably unresolved and
is never submitted to the replacement provider. Until the original operation
deadline, status and reconciliation may address only that original provider
when its configuration is available. Without an authoritative terminal result
from that provider, the deadline atomically ends the operation in the existing
`EXPIRED` state. A cancellation request may remain durably `CANCELLING`, but the
system MUST NOT claim `CANCELLED` without the provider's authoritative
acknowledgement; absent that acknowledgement, the same deadline produces
`EXPIRED`. The deadline transaction also removes the live continuation and its
staged-content owner edge, clears lease, retry, result, and provider evidence,
and then safely reclaims the staged payload. The record remains `EXPIRED`;
payload cleanup never rewrites it to `RETIRED` or `CANCELLED`. No new failure
classification or reason code is implied by this rule.
An authoritative signature durably recorded before that deadline is different:
its domain continuation must publish the exact certificate, CA, or status
object even if publication recovery continues past the deadline or retention
horizon. `PUBLISHING` remains durable and is retried with the existing bounded
2, 4, 8, 16, then 30 second schedule; it is never discarded merely because
time advanced. Exact publication completes the continuation, retires the
signing record, and reclaims its operation-lifecycle staging.
The core
MUST NOT silently archive old provider credentials or invent a configuration
version repository for this purpose. Configuration changed before an operation
applied or persisted its provider selection may be used by that not-yet-started
operation.

Each execution unit is one short state-machine step: load by identifier, validate
the expected durable state and fence, perform the bounded step, and atomically
publish the resulting transition and audit evidence. A state-transition lock
covers only the short validation/publication critical section and is not held
while waiting for remote or cryptographic work. Scheduler lanes bound only the
provider step that is currently executing. Neither remains allocated merely
because the durable workflow is pending. A remote or approval wait therefore
consumes durable record capacity but no
per-operation thread, scheduler slot, lease, activity root, callback ownership,
or resident workflow object. Provider callbacks carry identifiers and are only
advisories to advance lookup/reconciliation; the persisted state remains
authoritative.

Configured lane and ready-queue limits bound simultaneously executable blocking
provider steps and short waiting-to-run steps. They are not a limit on the
number of durable signing workflows. Durable capacity is a separate explicit
storage and recovery safety bound sized for the supported population.

For example, operation `op-123` started under CA configuration selecting remote
provider A. An administrator later changes that CA to provider B. While A's
applied configuration remains available, `op-123` continues to address A. If the
administrator removes A or A cannot complete it, `op-123` remains unresolved and
reaches its original deadline in `EXPIRED` unless A first reports an
authoritative terminal result. The
system MUST NOT add dynamic routing, archive provider credentials, share or move
a non-exportable key, or keep a namespace-wide activity handle in order to
redirect `op-123` to B.

This persistence boundary does not constrain provider topology. Local, remote,
multi-hop, and human-approval providers use the same transport-neutral
`SignatureWorkflow` SPI. Provider endpoint, authentication, and transport
settings belong to the selected signing workflow's `ProviderConfig`; they are
not signing-bus persistence paths. Provider notifications remain bounded
advisories that accelerate reconciliation, while fenced status reconciliation remains
authoritative after missed callbacks, ambiguous calls, and process restart.
The server never owns a second signing pool. Every transport enters the
session-owned fixed-lane runtime configured beneath `realm.pkiSession.signing`.
`laneCount` and `queueCapacity` default to 16 and 64; `gracefulDrainMillis` and
`forcedCancellationMillis` default to 30,000 and 10,000. A new arrival reserves
one transient initial-step slot and one store-owned durable-work slot before
content staging; exhaustion is mapped without message parsing to admin HTTP 429,
ACME `rateLimited`, and OCSP HTTP 429. Durable work is independently bounded at
`W = 100,000`. Remote and approval waits retain durable ownership but no scheduler
slot between provider calls. Callback identifiers enter a bounded asynchronous
notifier that coalesces reconciliation wakes; authoritative state lookup and the
durable due index remain the recovery authority.
Natural success or failure is published through its `Future` only after scheduler
ownership and capacity are released and any FIFO ready-step handoff is established.
`Future` cancellation retains its standard semantics; a cancelled running action
may retain its lane and slot until the callable physically exits.
Session composition passes an empty runtime-dependency object when no local
keyring unlock is configured; the selected provider alone decides whether that
is valid. Local software-keyring providers MUST reject an absent unlock
capability, while remote providers MUST NOT require one merely to satisfy core
composition.

The shared signing ledger uses the independently versioned segmented
WAL, manifest, and immutable checkpoint formats described in
`pki-signing-performance.md`. The package-private production metadata adapter
owns the bounded active writer, MVCC and due indexes, retained transaction
outcomes, manifest-directed recovery, and maintenance lifecycle. Recovery requires an
explicit clean-format marker, treats the manifest target as sole authority,
validates self-contained checkpoint data, replays checkpoint state followed by
post-boundary sealed and active suffixes, then repairs only a proven uncommitted
active-WAL suffix. Maintenance seals closed active WALs through a same-filesystem
hard link without reading or copying their bytes, publishes
checkpoints and manifests in crash-safe order, conditionally relocates unchanged
current pointers, and reclaims superseded generations only after current
references and snapshot pins reach zero. Unreferenced artifacts
receive bounded metadata/header classification and are returned as a deferred
cleanup plan rather than scanned or deleted during recovery. The built-in
ZeroEcho-lib workflow borrows a narrow process-local participant from the opened
filesystem store. Provider intent and orchestrator dispatch share one commit, as
do provider terminal state and the orchestrator-visible result. The store remains
the only owner of the segmented writer, force, recovery, maintenance, and index
budget. These local composites are self-describing direct commits: each is one
WAL frame covered by one grouped force and creates no separate issuance or
acknowledgement frames. Observed monotonic signing time remains in memory until a
state-changing commit folds it into that same frame; status and time reads append
and force nothing. Remote workflows continue to use the transport-neutral
`SignatureWorkflow` boundary and do not require this local participant.

Signing requests carry a canonical `content-sha256:v1` commitment containing the
exact byte length and SHA-256 digest. `signfp:v2` binds this commitment and the
semantic request fields but excludes the mutable fence and storage-specific
content identifier. The local cryptographic path verifies length and digest in
the same single sequential stream consumed by signing. The filesystem content
source opens once and does not pre-hash or rewind the file. A mismatch durably
fails the operation and cannot expose or retry a signature. The former
`operationRoot` configuration is rejected; there is no provider-root reader or
migration path.

Transactions admit at most 31 caller mutations and a 2 MiB encoded payload,
which preserves the exact 1 MiB signature-result contract plus its authoritative
record envelope. The active writer additionally caps queued payload ownership at
64 MiB and each force group at 32 frames, 8 MiB encoded, or 2 ms. A lifecycle
maintenance coordinator proactively rotates at 64 MiB, checkpoints after eight
sealed segments, and performs bounded reclamation. The coordinator reserves both
encoded and detached caller bytes before encoding. Rotation drains durable
projection, publishes the new active generation, and reopens admission before
the longer checkpoint-copy and relocation phase.

Correction Package 1 contains and attributes the currently reproduced online
relocation/publication race but does not yet repair it. Generation ownership is
partitioned into fixed MVCC, due, owner, and recovery-temporary counters, and a
typed underflow fails at the offending component without consuming another
component's references. Prepared plus admitted-but-not-projected ledger work is
also bounded by the active-WAL queue capacity. Packages 2–4 must correct and
verify stale prepared publication while preserving the online-admission contract;
the signing performance benchmark is prohibited until those packages complete.

Correction Package 2 adds the internal committed-prefix boundary used by the
future online correction. The writer publishes its forced endpoint only after
force; the bounded reader accepts only complete commitment- and continuity-
validated groups whose revisions are already visible in MVCC. A partially
projected forced group leaves the accepted boundary unchanged for a later
exact-once reread. This package does not create or publish a detached candidate
and does not alter the maintenance cutover.

Correction Package 3 adds an internal MVCC-only relocation candidate built from
an immutable boundary snapshot. It pre-reserves the complete conservative
candidate footprint before constructing its detached root directly in one pass,
without a second record-sized staging list. Its authoritative accepted-prefix
cursor requires every scan to start at the prior accepted endpoint and advances
only after one validated WAL group is applied as one detached batch. The prepared
swap rejects any live prepared publication and any
expected-endpoint mismatch before its allocation-free, I/O-free `O(1)` root
assignment; displaced MVCC ownership is released outside that publication
critical section. DUE and OWNER state is never copied or changed. Maintenance,
manifest/cutover ordering, generation supersession, and reclamation remain
unchanged until Package 4, and benchmark execution remains prohibited.
Build is `O(M)` time and `O(M)` candidate memory after pre-reservation. Catch-up
is `O(B_new + U log M + groups*G)` time with at most one bounded incomplete-group
reread; `G` is the detached generation-count map size copied once per accepted
group. Publication remains `O(1)`, allocation-free, and I/O-free.

Correction Package 4 integrates that candidate into maintenance. Rotation captures
the immutable boundary and new active-WAL baseline, then reopens ordinary admission
while the unreferenced checkpoint and detached MVCC candidate are built. Incremental
catch-up reduces the tail to the existing queue capacity. The existing admission
gate then drains all lifecycle slots, enforces a final tail of at most twice that
capacity, and performs final replay. The forced manifest is the durable
linearization point; only afterward does the allocation- and I/O-free MVCC root
swap occur, followed by generation supersession. DUE and OWNER remain untouched,
and reclamation remains a later typed-reference/pin-gated maintenance action.
Concurrent catch-up is incremental, final gate work is `O(Q)` bounded groups/frames,
and root publication is `O(1)`. Benchmark execution remains separately prohibited
until independent verification authorizes it.

Each ledger has two independent, configurable resident-byte envelopes. The
steady envelope owns live MVCC, DUE, OWNER, retention, projection, and snapshot
state; ordinary request processing uses only this envelope. The transient
envelope is exclusive to the detached compaction candidate and catch-up. Both
default to 512 MiB, giving a checked default combined envelope of 1 GiB.
Candidate construction reserves its complete initial transient footprint before
rotation or candidate-specific checkpoint, generation, artifact, or manifest effects;
canonical key bytes shared from the source are not charged twice, while new
catch-up keys are charged to the transient envelope.

The A1-G final-cutover reservation-capture gate is separately owned by the
engine, package-private, and short-lived. It does not block readers during
candidate construction or catch-up. Immediately before manifest publication,
snapshot, current-range, due-page, and owner-page capture waits at the gate;
signing admission remains nonblocking and returns the existing retryable
capacity result. A capture token is released once its reservations and
generation pins are installed rather than at returned-resource close. The gate
holds no mutex across I/O and permits releases and non-reserving reads to
continue. The distinct capacity cutover permit does not gate admission; it owns
only atomic accounting validation and the `O(1)` transfer of candidate ownership
from transient to steady under the fixed steady-then-transient budget-lock order.
Capacity exhaustion or an external live snapshot produces a typed controlled
deferral: candidate resources are closed exactly once, any already successful
rotation remains authoritative, recovery is not required, and an unrelated
commit cannot re-arm the pass. A budget release epoch atomically covers the
failure-to-registration interval; only a release from the blocking budget or a
last-snapshot-close signal delivers the one-shot wake. Outside
that short final-cutover interval, the request path has no transient-budget branch or
allocation. Internal and benchmark diagnostics report separate steady and
transient current/high-water/maximum values plus checked combined values.

WAL-headroom Packages H1–H2 reserve, under the existing admission lock and before
sequence/revision assignment, each outstanding encoded frame plus one conservative
singleton batch marker. Consequently every admitted group fits the configured
active segment even when emitted as singleton groups. A distinct internal
headroom condition maps to the existing retryable `LIMIT_EXCEEDED` admission
result and raises sticky maintenance pressure rather than recovery-required.
Pressure bypasses the ordinary 64 MiB rotation threshold, is cleared only after
successful rotation/compaction, and preserves a concurrent signal for the next
pass. This adds no public contract, polling loop, or persistent state.

### 5.3 `app`

The `app` module owns the CLI and batch-plan adapter.

The CLI and server MUST use the same backend session and typed operation contracts.

## 6. Authority invariants

The server MUST preserve the existing ZeroEcho authority model.

### 6.1 Immutable PKI authority

No API permission may permit direct mutation of:

- issued certificate bytes;
- certificate identity;
- signed certificate fields;
- committed revocation history;
- committed status objects;
- committed audit events;
- committed signing records.

Corrections MUST occur through explicit domain operations such as:

- revocation;
- replacement issuance;
- issuer rotation;
- new status-object generation;
- superseding policy or profile activation.

### 6.2 No database-forgery permission

There MUST NOT be an owner, administrator, or break-glass permission equivalent to:

```text
rewrite certificate database
edit issued certificate
erase revocation history
rewrite audit history
force challenge valid
```

Such operations MUST NOT exist in the normal API.

### 6.3 Private-key confinement

Production `pki` and `pki-server` MUST NOT materialize or expose CA private keys.

Signing MUST use `KeyRef` and the established signing workflow boundary.

### 6.4 Signing staging, retirement, and recovery

Synchronous X.509 adapters are one-shot resources. They stream to disposable,
operation-lifecycle staging and MUST be closed on every path. Closing before the
signature request completes aborts partial staging. Once submission to the signing
bus begins, the bus owns disposition of the completed reference: it deletes the
reference only after proving that no durable intent exists, and retains it when a
commit is present or durability is uncertain.

Terminal outcome and payload ownership are independent. At the exact original
deadline, every active `INTENT` (claimed or unclaimed), `DISPATCHED`, and
`CANCELLING` record atomically becomes content-free `EXPIRED`. No provider call
may begin after that boundary, and a call already in progress may return but
cannot publish. A `CANCELLED` acknowledgement committed before the deadline
remains `CANCELLED`.

Operation retirement likewise separates live payload from durable evidence. After an
immutable provider terminal state is observed, retirement removes staged
to-be-signed content and workflow continuation state. The authoritative signing
record remains through the signing horizon with content-free commitment metadata
and, for a trustworthy on-time success, the signature result. A provider that is
not yet terminal remains `CANCELLING`; it is not falsely retired.

For a trustworthy signature recorded before the original deadline, retirement
follows exact domain publication rather than wall-clock expiry. A transient
publication failure keeps the continuation in `PUBLISHING` and schedules a
future retry capped at 30 seconds, including beyond the normal signing horizon.
The record continues to consume bounded durable-work capacity because its
payload is still required. Completion makes the outer continuation and signing
record content-free before staged reclamation.

If staged-content deletion fails after a content-free `EXPIRED` or `RETIRED`
record commits,
the store retirement boundary reports only the stable redacted cleanup marker
`SIGNING_CONTENT_CLEANUP_FAILED`; higher-level adapters may map it to their stable
cleanup marker. Logical retirement still deletes workflow continuation state and
retires advisory state before reporting that marker. The retained record does not
regain a live content reference. Store restart recovery uses authoritative live
references to reclaim the orphaned staged file safely.

An active local cancellation first commits `CANCELLING` and signals the exact
in-process execution. `CANCELLED` is committed only after cryptographic execution
acknowledges the signal; a racing completed signature is instead reconciled as
its actual terminal result. The live signing owner therefore prevents staged
content retirement while the signer can still read it. Restart converts a local
`DISPATCHED` or `CANCELLING` record to durable `RECOVERY_INCOMPLETE` without
re-running cryptography.

The current signing ownership contract is defined by the
[single-admission reactor architecture](pki-single-admission-reactor-architecture.md).
The legacy signing reconciliation and workflow descriptions elsewhere in this
section are superseded by that contract for the current server adapters.

Each fully opened realm owns one `AuditProjectionWorker`, started immediately
before readiness. Its single daemon thread runs revocation-audit and evidence
projections synchronously and self-schedules only after the current pass returns.
It owns no signing session, provider dispatch, signing continuation, or signing
advisory registration. Its retained scheduling state is O(1); existing projector
costs and realm/store ownership remain unchanged.

The mandatory `auditProjection` policy independently gives revocation and each
evidence-family projector the configured `maximumRecords` and `maximumSinkCalls`
budgets. A projection failure cannot suppress the other phase or later passes.
Revocations beyond a captured feed head remain for a later pass.

The existing realm-scoped payload-free signal holds one lifecycle listener.
Administrative and ACME revocation paths retain their wake behavior; signals
coalesce and periodic polling provides convergence without a wake. Unblocked
audit or evidence backlog schedules an immediate follow-up. Otherwise the next
pass uses the earliest reported retry eligibility, bounded by the idle interval.
Each projector enforces its persisted retry eligibility even when another family
has immediate work. Clock failure falls back to the idle interval.

Projection is at least once, not exactly once. The durable projection cursor
advances only after the audit sink returns normally. A crash or uncertain state
commit after sink acknowledgement can replay the same transition, whose stable
lowercase SHA-256 `eventId` lets consumers deduplicate it. Immediate gateway and
ACME telemetry remains best effort and cannot change a committed revocation
outcome. Projection checks shutdown cancellation between feed entries, before
sink calls, and around safe cursor commits. Cancellation observed after sink
acknowledgement but before cursor commit preserves the old cursor and may replay
the same stable event ID; it never skips that transition.

The worker synchronously invokes projector deliveries and aggregate telemetry.
Runtime failures are isolated, but a blocking sink can delay subsequent
projections and shutdown. Cancellation is cooperative. No additional thread,
queue, or timeout lane is introduced.

Content-free `EXPIRED` records leave the due-work projection immediately and
enter the horizon-retention projection directly, so idle passes do not rescan
them as active work. Each admitted scheduled reconciliation pass also runs exactly one bounded
retention purge of at most 31 records and at most one force. This occurs even
when there is no due signing work, so successive idle worker passes reclaim
expired retained capacity without request traffic; cancellation or an expired
pass deadline prevents admission, and no pass loops to purge exhaustion.

Normal periodic sweep selects bounded due work from the identity-ordered,
minimum-eligibility-augmented projection. For nonempty indexed work `W` and `R`
returned due records, effective `D = max(1, R)`, so `1 <= D <= W`; the page-bound
worst case uses `D = min(record bound, W)`. Selection takes worst-case
`Theta(log W + D + D log(W / D))` time, returns `O(D)` immutable memory, and uses
`O(D + log W)` total auxiliary memory. An empty index returns an empty page in
constant time and memory. The reconciliation cursor remains an advisory
exclusive key into a metadata snapshot ordered by canonical submission
identifier. A pass examines no more than its
record bound, makes no more than its independent provider-call budget, and wraps
to the beginning after reaching the end so deferred records cannot starve other
records. A returned cursor identifies the last metadata candidate actually
dispositioned; a provider-call, deadline, or cancellation stop never publishes a
prefetched page-end key. Malformed candidates advance individually without
skipping a later valid candidate and contribute to both aggregate `unresolved`
and `retryable` counts. A cycle retains the greatest key from its first stable
snapshot as a high-watermark and the cycle-start cursor as the inclusive upper
bound of its wrapped prefix. Both boundaries remain stable across worker passes.
After crossing the high-watermark, the cycle scans only through its captured
prefix bound before accepting a new high-watermark, so continuous inserts above
the boundary cannot starve lower keys or cause the completed tail to be revisited.
A cycle that starts without a cursor completes at its high-watermark without a
wrapped phase. Per-record failures are isolated and persisted separately from the
provider detail code with a store-time retry schedule of 2, 4, 8, 16, then 30
seconds. Terminal and retired records carry no retry metadata.

The reconciliation API carries the cursor, high-watermark, wrapped-prefix bound,
and phase as one validated `SigningReconciliationContinuation`. A scheduler must
pass that value unchanged between passes; `SigningReconciliationRequest.continueFrom`
copies it while replacing only the next pass's record, provider-call, deadline,
timeout, and cancellation bounds. This prevents a partial cursor-only resume from
silently discarding the cycle's frozen fairness boundaries.

Audit shutdown first stops scheduling and unregisters the realm wake listener,
then cancels and drains the active projection before closing realm dependencies.
Projection observes cancellation between its bounded feed, sink, and
control-store operations. A synchronous call that outlives forced shutdown
reports `AUDIT_PROJECTION_SHUTDOWN_TIMEOUT` and leaves dependencies open for a
retry after that call returns. Partial startup cleanup preserves the same rule.

`SignatureWorkflow` implementations are trusted in-process components and every
submit, status, verify, and cancel call now requires a `CallControl` carrying an
absolute deadline and cancellation signal. This is an intentionally breaking
provider-SPI migration: implementations must check the control before and
between I/O, before an externally visible effect, and before returning. These
controls are cooperative bounds; the server does not kill provider threads or
close their dependencies while a violating call remains live. Providers that
need enforcement against untrusted or non-cooperative code require a future
out-of-process provider boundary with process or RPC isolation.

Payload staging remains streaming `O(n)` time and `O(1)` aggregate auxiliary heap
excluding the signature. The synchronous BC adapter performs at most one bounded
initial provider step and one authoritative point observation; pending work
returns its durable private `PkiId` without sleeping or retaining a caller thread.
Ordinary active-record point lookup is expected `O(1)`. Identity-ordered
selection and processing of up to `D` due records has worst-case
`Theta(log W + D + D log(W / D))` selection time plus the bounded provider and
persistence work for those records. Normal pass total auxiliary memory is
`O(D + log W)`; the returned immutable page is `O(D)`. The primary
metadata index plus workflow/domain-continuation projections retain `O(M + W)`
state, where `M` is the current metadata-key population. A concurrent metadata commit
may detach the currently pinned index generation once in `O(M)` time and memory;
later commits do not copy again merely because an older generation remains
pinned. A pass uses at most `maximumProviderCalls` external calls, and each realm
owns `O(1)` scheduler state.

## 7. Authorization architecture

### 7.1 Model

Authorization MUST use:

```text
RBAC templates
        over
fine-grained scoped permission grants
```

Roles are convenience bundles. Permissions are the actual authority.

### 7.2 Permission structure

A permission decision SHOULD be expressible as:

```text
action
+ resource type
+ realm scope
+ authority scope
+ issuer scope
+ profile scope
+ object relationship
+ data-view level
+ optional conditions
```

Example:

```text
action: CERTIFICATE_REVOKE
realm: production
authority: corporate-tls
profiles: [server-tls, client-tls]
relationship: ANY
conditions: reason-required
```

### 7.3 Mandatory rules

- Authorization MUST be default deny.
- Explicit deny MUST override allow.
- Administrative operations MUST have explicit realm and authority scope.
- Search permission MUST be distinct from direct object lookup.
- Creating a request MUST NOT grant approval permission.
- A principal MUST NOT approve its own request where separation of duties applies.
- Server-level administration MUST NOT implicitly grant CA administration.
- CA administration MUST NOT implicitly grant identity and role administration.
- Access denial MUST NOT reveal whether a protected object exists.

## 8. Administrative roles

Roles below are normative default templates. Deployments MAY define additional roles, but MUST preserve the underlying separation of duties.

### 8.1 Platform Operator

May manage:

- server lifecycle;
- listener configuration;
- health and readiness;
- deployment-level provider availability;
- operational diagnostics.

Does not automatically receive:

- issuance rights;
- CA lifecycle rights;
- profile activation rights;
- revocation rights;
- access to PII;
- signing-key usage rights.

### 8.2 Security Administrator

May manage:

- principals;
- roles;
- scoped grants;
- authentication providers;
- break-glass policy.

Does not automatically receive CA or issuance rights.

### 8.3 CA Security Officer

May manage assigned authorities:

- authority creation or import;
- issuer generation;
- key ceremony;
- issuer activation, suspension, retirement, and rotation;
- CA-specific profiles and policies.

Does not automatically manage principals or grant its own permissions.

### 8.4 Profile and Policy Manager

May:

- register profiles;
- validate profiles;
- activate or deactivate profiles;
- inspect policy;
- manage allowed algorithm bindings where authorized.

Does not automatically issue certificates.

### 8.5 Enrollment or RA Officer

May:

- inspect and process enrollment requests;
- issue certificates within assigned authority/profile scope;
- manage approved request workflows.

Does not automatically approve its own requests.

### 8.6 Approver

May approve or reject assigned operations.

Approval rights MUST be independently scoped.

### 8.7 Requester

May:

- create requests;
- inspect its own requests;
- download its own resulting credentials;
- request renewal, rekey, or revocation when policy permits.

The requester template may also submit `CERTIFICATE_CONFIRM` for an exact
authority/profile credential scope. That action deliberately uses relationship
`ANY`: possession is established by the cryptographic proof and is not inferred
from stored requester ownership.

### 8.8 Revocation Officer

May:

- revoke;
- place on hold;
- release from hold;
- inspect revocation history within scope.

Issuance rights are separate.

### 8.9 Publication Operator

May:

- register publication where policy permits;
- process publication;
- retry definitive retryable failures;
- reconcile unknown outcomes;
- inspect publication state.

Cannot modify the source certificate or status object.

### 8.10 Backup Operator

May:

- create or export backups;
- verify backup integrity.

Restore is a separate permission.

### 8.11 Recovery Officer

May perform restore or recovery operations when approval policy is satisfied.

### 8.12 Standard Auditor

Receives a read-only redacted view sufficient to verify PKI operation and control compliance.

### 8.13 Privileged or Forensic Auditor

May receive full PII and object content only through explicit, reason-bound, time-limited, and audited authorization.

### 8.14 ACME Administrator

May configure:

- ACME directories;
- authority/profile binding;
- challenge providers;
- EAB requirements;
- identifier namespace policy;
- ACME rate and validity policy.

Does not receive arbitrary issuance rights outside configured ACME policy.

### 8.15 ACME Account

Receives protocol-specific rights only for its own account, orders, authorizations, challenges, and certificates.

### 8.16 Anonymous or Public Principal

May access only explicitly public protocol and repository resources.

## 9. No permanent omnipotent owner

The system MUST NOT define a permanent principal with unrestricted authority over:

- platform;
- identities;
- CA lifecycle;
- issuance;
- approval;
- PII;
- restore;
- audit.

Emergency access MUST use a break-glass mechanism.

Break-glass access MUST be:

- explicit;
- time-limited;
- reason-bound;
- audited;
- optionally multi-party approved;
- incapable of rewriting immutable PKI or audit history.

## 10. Permission catalog

The implementation SHOULD provide permissions equivalent to the following categories.

### 10.1 Realm and platform

```text
REALM_READ
SERVER_HEALTH_READ
SERVER_CONFIGURATION_READ
SERVER_CONFIGURATION_UPDATE
IDENTITY_PROVIDER_MANAGE
PRINCIPAL_MANAGE
ROLE_MANAGE
PERMISSION_GRANT
```

### 10.2 Authorities and issuers

```text
AUTHORITY_LIST
AUTHORITY_READ
AUTHORITY_CREATE
AUTHORITY_IMPORT
AUTHORITY_ACTIVATE
AUTHORITY_SUSPEND
AUTHORITY_RETIRE
ISSUER_CREATE
ISSUER_ROTATE
ISSUER_RETIRE
CA_CHAIN_DOWNLOAD
```

### 10.3 Profiles, policy, and X.509 bindings

```text
PROFILE_READ
PROFILE_REGISTER
PROFILE_VALIDATE
PROFILE_ACTIVATE
PROFILE_DEACTIVATE
POLICY_READ
POLICY_UPDATE
X509_BINDING_READ
X509_BINDING_PROVIDER_ENABLE
```

### 10.4 Enrollment and issuance

```text
REQUEST_SUBMIT
REQUEST_READ_OWN
REQUEST_READ_ANY
REQUEST_APPROVE
REQUEST_REJECT
REQUEST_CANCEL
CERTIFICATE_ISSUE
CERTIFICATE_RENEW
CERTIFICATE_REKEY
```

### 10.5 Certificates

```text
CERTIFICATE_READ_METADATA
CERTIFICATE_READ_CONTENT
CERTIFICATE_SEARCH
CERTIFICATE_READ_PII
CERTIFICATE_DOWNLOAD
CERTIFICATE_PUBLICATION_CHANGE
CERTIFICATE_CONFIRM
```

### 10.6 Revocation and status

```text
CERTIFICATE_REVOKE
CERTIFICATE_HOLD
CERTIFICATE_RELEASE_HOLD
REVOCATION_HISTORY_READ
CRL_GENERATE
CRL_PUBLISH
CRL_DOWNLOAD
OCSP_ADMINISTER
```

### 10.7 Publication

```text
PUBLICATION_REGISTER
PUBLICATION_READ
PUBLICATION_PROCESS
PUBLICATION_RETRY
PUBLICATION_RECONCILE
```

### 10.8 Audit, backup, and recovery

```text
AUDIT_READ_REDACTED
AUDIT_READ_FULL
AUDIT_READ_PII
AUDIT_EXPORT
AUDIT_INTEGRITY_VERIFY
BACKUP_EXPORT
BACKUP_VERIFY
RESTORE_EXECUTE
```

Permission names MAY be adjusted to repository conventions, but their semantic separation MUST be preserved.

## 11. Approval model

High-risk operations MUST support approval policy.

Applicable operations include:

- root or intermediate CA creation/import;
- issuer activation or retirement;
- key rotation or destruction;
- significant profile activation;
- custom X.509/OID binding changes;
- privileged role or grant changes;
- snapshot restore;
- bulk revocation;
- disclosure transition to a more public state;
- audit mechanism changes;
- high-assurance issuance.

Approval policy MUST be able to express:

```text
N-of-M approvals
requester and approver separation
required approver roles
approval expiry
mandatory justification
authority and profile scope
```

An approval record MUST be durable, attributable, immutable after commitment, and bound to the exact operation content or commitment.

## 12. Auditor and PII model

### 12.1 Standard auditor

A standard auditor MAY see:

- audit event identity;
- event time;
- authority, issuer, profile, and operation identities;
- state transitions;
- safe error classifications;
- object commitments and digests;
- approval chain;
- revocation state;
- redacted subject and SAN metadata;
- aggregate operational data.

A standard auditor MUST NOT automatically receive:

- full certificate DER;
- full CSR;
- full subject or SAN;
- ACME contact data;
- internal asset names;
- publisher credentials;
- secret configuration.

### 12.2 Privileged auditor

A privileged auditor MAY inspect full certificate, CSR, subject, SAN, and related PII only when:

- the permission is explicit;
- the reason is recorded;
- access is time-limited;
- access is audited;
- approval is applied where policy requires it.

### 12.3 DER and redaction

A certificate containing PII cannot be meaningfully redacted while preserving the original DER.

Therefore:

- redacted audit access MUST return a redacted metadata view;
- full DER access requires the corresponding full-content and PII permissions.

Auditors never require private keys or unlock secrets.

## 13. Issuance, publication, and disclosure

These are distinct lifecycle dimensions:

```text
issuance
publication processing
retrieval disclosure
```

Issuing a certificate MUST NOT automatically make it public.

Publication success MUST NOT change certificate authority or validity.

### 13.1 Disclosure policy

Every retrievable certificate or repository object SHOULD have a persisted disclosure policy equivalent to:

```text
PUBLIC
PUBLIC_UNLISTED
AUTHENTICATED
OWNER_ONLY
RESTRICTED
NOT_PUBLISHED
```

### 13.2 Semantics

#### PUBLIC

- anonymously retrievable;
- MAY be publicly indexed or searchable when policy permits.

#### PUBLIC_UNLISTED

- not publicly indexed;
- not publicly searchable;
- anonymous retrieval MUST require a separate capability token or equivalent.

The object ID itself MUST NOT be the capability token.

#### AUTHENTICATED

- retrievable by authenticated principals within configured scope.

#### OWNER_ONLY

- retrievable by the requester, owner, and specifically authorized administrators.

#### RESTRICTED

- retrievable only by explicit principals or roles.

#### NOT_PUBLISHED

- validly issued;
- available only through authorized ownership or administrative access;
- not placed in a public repository.

### 13.3 Default disclosure recommendations

| Object type | Recommended default |
|---|---|
| Root CA certificate | `PUBLIC` |
| Intermediate CA certificate | `PUBLIC` |
| CA chain | `PUBLIC` |
| CRL | `PUBLIC` |
| OCSP protocol response | Public protocol access |
| Internal leaf certificate | `OWNER_ONLY` or `AUTHENTICATED` |
| Public TLS leaf certificate | Profile-defined |
| Certificate with sensitive PII | `RESTRICTED` or `NOT_PUBLISHED` |

Disclosure policy changes MUST NOT alter issued certificate bytes or revocation history.

## 14. API separation

The server architecture MUST separate:

```text
/admin/v1/...
/acme/{directoryAlias}/...
/public/v1/...
```

Exact paths MAY change according to API conventions, but the boundaries MUST remain distinct.

### 14.1 Administrative API

Requires:

- configured authentication;
- scoped permission evaluation;
- approval handling;
- typed PKI operations;
- safe audit.

### 14.2 ACME API

Uses:

- ACME account-key authentication;
- ACME state machine;
- directory-specific policy;
- challenge validation;
- optional EAB.

It MUST NOT expose general administrative operations.

### 14.3 Public API

May expose only:

- CA certificates;
- CA chains;
- CRLs;
- OCSP endpoints;
- explicitly `PUBLIC` objects;
- capability-based retrieval for `PUBLIC_UNLISTED` objects where supported.

## 15. ACME architecture

### 15.1 Directory binding

Each ACME directory MUST be bound to:

- one realm;
- one logical authority;
- one certificate profile;
- one issuance policy;
- allowed identifier types;
- allowed DNS suffixes, IP ranges, or other namespaces;
- maximum validity;
- allowed key algorithms;
- allowed X.509 algorithm bindings;
- challenge provider policy;
- optional EAB policy;
- resulting disclosure policy;
- rate/admission policy.

An ACME client MUST NOT freely select arbitrary authorities or profiles.

### 15.2 ACME account permissions

An ACME account may receive permissions equivalent to:

```text
ACCOUNT_UPDATE_OWN
ORDER_CREATE
ORDER_READ_OWN
AUTHORIZATION_READ_OWN
CHALLENGE_RESPOND_OWN
ORDER_FINALIZE_OWN
CERTIFICATE_DOWNLOAD_OWN
CERTIFICATE_REVOKE_OWN
```

An ACME account MUST NOT receive:

```text
AUTHORITY_MANAGE
PROFILE_MANAGE
CERTIFICATE_ISSUE_ARBITRARY
CERTIFICATE_SEARCH
CERTIFICATE_DOWNLOAD_ANY
CHALLENGE_FORCE_VALID
```

### 15.3 External Account Binding

EAB policy SHOULD bind the account to:

- realm;
- authority;
- directory;
- profile;
- identifier namespace;
- account policy;
- expiry;
- single-use state.

After registration, these restrictions become part of the account authorization policy.

### 15.4 Challenge validation

There MUST NOT be a permission or endpoint that simply marks a failed challenge as valid.

Out-of-band validation MAY be supported only through a configured validator SPI producing durable evidence equivalent to:

```text
validatorId
identifier
accountKeyCommitment
evidenceType
validatedAt
expiresAt
policyCommitment
result
```

Issuance requires:

```text
valid ACME account
+ valid authorization evidence
+ directory issuance policy
+ active profile
+ active authority and issuer
```

### 15.5 ACME is not generic issuance

ACME MUST NOT invoke a generic arbitrary `credential.issue` operation using only ACME account authorization.

ACME issuance MUST pass through the ACME order, authorization, challenge, directory, profile, and authority constraints.

### 15.6 Credential confirmation and frozen-directory routing

Only a valid account-owned order for a non-public credential with a pending
confirmation lifecycle exposes the version-1 `credentialConfirmation`
extension. Challenge issuance and completion are account-KID JWS operations on
separate, versioned URLs beneath the order's exact directory alias. The server
derives the credential identity from that order and delegates once to the
authoritative transport-neutral confirmation service. It MUST NOT accept a
client-selected credential identity, create parallel confirmation state, or
route through the administrative gateway.

Challenge payload is exactly `{}`. Completion has a strict schema containing
only exact lifecycle/challenge compare-and-set coordinates and one canonical
unpadded Base64url proof response. Proof possession supplements rather than
replaces ACME account authority. Current account-key commitment, exact URL and
nonce, order ownership and validity, frozen directory/order/credential
correlation, publication binding, and confirmation policy MUST all validate
before the confirmation service is invoked. Stale account keys, including
after rollover or deactivation, do not retain authority. Raw proof,
presentation, JWS, compare-and-set cryptographic material, and provider details
MUST NOT enter audit, exceptions, or diagnostics.

Directory activation is an admission property. Discovery, new-account, and
new-order require the currently active revision; authenticated access to an
existing owned resource resolves the exact directory identity, revision, and
immutable policy commitment persisted with that resource, even after
deactivation. Directory status remains part of the directory's mutable
whole-record compare-and-set commitment and is deliberately not copied into
accounts or orders. Frozen validation checks the original realm, exposure,
profile, confirmation policy, issuer, and chain path without requiring that
issuer/path to remain the authority's globally current selection. New
admission or issuance additionally requires an active directory and authority
whose current selection still equals the frozen one; it never reroutes to a
replacement. This permits deterministic completion of already-issued work
without silently redirecting it to later configuration and without weakening
cross-directory or cross-account isolation.

Replay nonces bind to the listener and canonical directory alias. A known alias
may use its existing `new-nonce` URL while all revisions are inactive, enabling
a fresh process or client to authenticate continuation of an existing owned
resource. The nonce remains one-time and process-local; unknown aliases do not
receive one. Exact URL, current account-key commitment, frozen revision, and
resource ownership remain the authority checks.

## 16. Public retrieval rules

### 16.1 CA certificates and chains

CA certificates and chains SHOULD be publicly retrievable through explicit authority/issuer resources.

### 16.2 CRL and OCSP

CRLs and OCSP protocol endpoints SHOULD be public unless deployment policy explicitly establishes a closed PKI.

### 16.3 Leaf certificates

Leaf certificate retrieval MUST honor persisted disclosure policy.

Knowing `credentialId` alone MUST NOT grant access unless the object is `PUBLIC`.

### 16.4 Search

Public search MUST be separately authorized from direct retrieval.

Search by subject, SAN, email, account, or asset identity has elevated privacy impact and MUST require explicit permission.

## 17. Multi-process and frontend aggregation

A future frontend MAY aggregate multiple ZeroEcho server endpoints.

The frontend MUST NOT collapse authority identities or authorization decisions across realms.

Each server remains authoritative for its own realm.

Cross-realm UI aggregation is presentation and orchestration, not shared PKI authority.


## Trusted reverse-proxy TLS termination

The ZeroEcho PKI server MUST support exactly these two explicit administrative authentication deployment modes:

```text
DIRECT_MTLS
TRUSTED_REVERSE_PROXY
```

### Direct mutual TLS

In `DIRECT_MTLS` mode, ZeroEcho terminates TLS, validates the client certificate, verifies possession through the TLS handshake, and maps the validated certificate to one persisted `SecurityPrincipal`.

Forwarded client-identity headers MUST be rejected in this mode.

### Trusted reverse proxy

In `TRUSTED_REVERSE_PROXY` mode, a configured TLS-terminating reverse proxy such as NGINX validates the external client certificate and forwards the authenticated client identity to ZeroEcho.

The proxy-to-ZeroEcho connection MUST itself be authenticated.

The preferred deployment is:

```text
administrative client
    -- mutual TLS -->
trusted reverse proxy
    -- separate mutual TLS -->
ZeroEcho
```

The proxy MUST authenticate using a dedicated infrastructure identity that is distinct from every end-user principal.

The server MUST distinguish:

```text
transport principal
end-client principal
```

The transport principal identifies the trusted proxy. The end-client principal is used for administrative authorization.

The proxy principal MUST NOT inherit the permissions of the end-client principal. It MAY only receive the narrowly scoped infrastructure authority required to forward an authenticated client identity.

That infrastructure authority MUST be an explicit realm-scoped permission equivalent to `FORWARD_AUTHENTICATED_CLIENT_IDENTITY`. It grants no PKI, identity-administration, PII, approval, or end-client authority, and break-glass access MUST NOT create implicit forwarding authority.

### Forwarded certificate formats

The preferred forwarding format is the RFC 9440 `Client-Cert` header and optional `Client-Cert-Chain` header.

ZeroEcho MAY additionally support one explicitly configured NGINX compatibility format based on URL-escaped PEM, but it MUST NOT auto-detect arbitrary proxy-specific identity headers.

Every accepted format MUST have:

* one stable configuration identifier;
* strict bounded decoding;
* duplicate-header rejection;
* exact certificate consumption;
* canonical certificate validation;
* no subject-string-only identity mapping.

### Header sanitization

The trusted reverse proxy MUST remove or overwrite every incoming forwarded client-certificate header.

A request for which external mutual TLS authentication did not succeed MUST NOT contain a forwarded client identity.

ZeroEcho MUST reject:

* forwarded identity received from an untrusted transport principal;
* duplicate client-certificate headers;
* malformed certificate or chain data;
* absent client identity for an administrative operation;
* zero or multiple principal mappings;
* conflicting identity representations.

### Independent backend validation

ZeroEcho MUST independently validate the forwarded certificate and, when provided, its chain using the configured administrative-client trust policy.

ZeroEcho MUST validate:

* strict canonical certificate DER;
* certificate validity;
* configured trust;
* allowed certificate usage;
* exact certificate or SPKI commitment mapping;
* persisted principal enabled state.

The proof of possession for the external client certificate is attested by the trusted reverse proxy. Therefore, proxy authentication and transport integrity are part of the authentication authority in this mode.

### Backend transport policy

Plain unauthenticated HTTP over TCP MUST NOT be an enterprise-grade trusted-proxy mode, including over loopback.

A production trusted-proxy deployment MUST use either:

* mutually authenticated TLS from proxy to ZeroEcho; or
* a future explicitly supported operating-system-authenticated local transport such as a permission-protected Unix domain socket.

Client source-address headers, `X-Forwarded-For`, `Forwarded`, or PROXY protocol information MUST NOT establish authentication or authorization.

### Audit

Safe authentication audit MUST record:

* authentication mode;
* transport-principal identity;
* end-client principal identity when resolved;
* request correlation ID;
* safe result classification.

It MUST NOT record:

* raw certificates;
* subjects or SAN values;
* forwarded certificate headers;
* private material;
* proxy credentials;
* unrestricted parser or provider errors.

### Security invariant

Possession of a forwarded identity header is never authentication authority by itself.

Forwarded client identity is trusted only when all of the following hold:

```text
configured trusted-proxy mode
+ authenticated authorized transport principal
+ valid forwarded-certificate format
+ successful certificate and principal validation
```

## 18. Server implementation constraints

The future server implementation MUST:

- maintain one long-lived `PkiSession` per realm/server instance;
- support multiple logical authorities within the realm;
- require explicit authority scope for administrative operations;
- use bounded request execution;
- use default-deny authentication and authorization;
- keep server execution state non-authoritative;
- preserve `RECOVERY_REQUIRED` and `EXTERNAL_OUTCOME_UNKNOWN`;
- avoid automatic retries of unknown external outcomes;
- avoid implicit checkpoint or publication scheduling unless explicitly configured later;
- never expose private-key material;
- never place secrets or PII in thread names or unsafe logs.

## 19. Configuration principles

Server configuration MUST explicitly define:

- realm identity;
- allowed authorities;
- provider configuration;
- authentication providers;
- authorization roles and grants;
- listener/TLS settings;
- audit configuration;
- optional approval policies;
- optional ACME directories;
- public disclosure defaults;
- deployment-specific limits.

Configuration MUST NOT silently grant broad permissions.

Unknown security-relevant fields MUST be rejected.

Secrets MUST use external references rather than ordinary plaintext configuration output.

## 20. Persistence principles

The following must be durable where implemented:

- role and grant assignments;
- approval requests and decisions;
- disclosure policy;
- ACME account, order, authorization, challenge, and evidence state;
- capability-token metadata;
- configuration commitments required to validate authority;
- audit records.

Durable operational records MUST remain separate from certificate, revocation, and status-object authority.

## 21. Deferred design areas

The following remain separate future workstreams and MUST NOT be guessed during the initial server foundation:

- exact REST resource schemas;
- production authentication provider implementations;
- server clustering;
- leader election;
- horizontal scaling;
- distributed store semantics;
- ACME protocol implementation;
- OCSP responder implementation where absent;
- frontend implementation;
- metrics platform;
- log compaction policy;
- deployment orchestration.

Deferral does not permit deviation from this document.

## 22. Mandatory architecture tests

The server and authorization implementation MUST eventually test:

- multiple authorities in one realm;
- strict cross-authority isolation;
- one-authority deployment;
- separate issuer generations;
- default deny;
- explicit deny precedence;
- role and authority scoping;
- requester/approver separation;
- break-glass expiry and auditing;
- redacted versus privileged auditor views;
- PII exclusion from redacted output;
- public versus restricted certificate retrieval;
- object ID not acting as bearer token;
- public CA chain and CRL retrieval;
- ACME account isolation;
- ACME directory authority/profile binding;
- challenge evidence validation;
- impossibility of force-validating a challenge;
- no API for certificate, revocation, or audit rewriting.

## 23. Change-control rule

Any implementation that conflicts with this document MUST stop and report the conflict.

Codex or another agent MUST NOT:

- weaken a requirement to make tests pass;
- add a compatibility path that changes authority semantics;
- replace scoped permissions with coarse process-wide administrator access;
- make certificate IDs act as bearer credentials;
- combine admin and ACME authorization models;
- introduce a permanent omnipotent owner;
- allow direct editing of immutable PKI records;
- silently make issued certificates public;
- permit challenge force-validation.

A proposed deviation MUST be presented to the project owner with:

1. the exact conflicting requirement;
2. the implementation reason;
3. security and operational consequences;
4. at least one compliant alternative;
5. an explicit requested decision.

Until approval, the normative design in this document remains authoritative.

## 24. Accepted architecture summary

The following decisions are final for the current architecture:

1. One process serves one PKI realm.
2. One realm may contain multiple logical authorities.
3. Deployments may restrict a process to one authority.
4. Unrelated security domains use separate realms/processes.
5. Root CA is normally offline or isolated.
6. Logical authorities are distinct from issuer generations.
7. No magic certificate IDs exist.
8. RBAC roles are templates over scoped permissions.
9. No permanent omnipotent owner exists.
10. High-risk operations support multi-party approval.
11. Standard and privileged auditor views are separate.
12. PII access is explicit, reason-bound, and audited.
13. Issuance, publication, and disclosure are independent.
14. Leaf certificates are not public by default unless policy says so.
15. Object identity is not a bearer credential.
16. Admin, ACME, and public APIs are separate.
17. ACME directories are bound to authority, profile, and policy.
18. ACME accounts have only protocol-scoped rights.
19. ACME challenge validity cannot be administratively forged.
20. The future frontend may aggregate multiple realms without merging their authority.
