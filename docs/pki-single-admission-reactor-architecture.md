# PKI Durable Signing Reactor Architecture

**Status:** Normative for the implemented reactive backend and shared local execution.
**Applies to:** Signing-backed PKI workflows.

## Architectural boundary

Signing is one operation group. System access, role assignment, administration,
and other non-signing work have no certificate-signing semantics and do not use
this reactor. Such work is synchronous or belongs to another independently
managed reactor with its own capacity, backlog, and state machine.

Each configured reactive session owns one `SigningReactor`, one scanner thread, and one
shared `SigningProvider`. Its immutable topology maps disjoint exact `KeyRef`
groups to dedicated lane pools and requires one catch-all pool for every
unmatched key. The mapping is fixed during the session. A signing step is routed
by the key that performs it, not by the subject being produced. Pools never
borrow lanes and are scheduling boundaries, not admission or security
boundaries; the shared store owns the single realm-wide active-request limit.

Within each bounded pool prefetch, authorities receive equal round-robin turns
and retain FIFO order within one authority. A newly buffered authority joins the
tail of the current round. This is a volatile scheduling policy only: fairness
state resets on restart, does not inspect the durable backlog beyond the bounded
prefetch, and provides no backlog-wide latency or service-level guarantee.
`fairnessAuthorityId` is trusted server-derived metadata, never a caller-selected
authorization or isolation primitive.

Topology construction rejects oversized inputs before copying, hashing, or
aggregate traversal. It reads the exact-group list size directly and permits at
most 255 groups, requires 1..4096 keys in each group, and counts each `KeyRef`
in allocation-free UTF-8 code units with correct paired and unpaired surrogate
handling before enforcing the 1,048,576-byte bound.

The configuration schema is version 6 and contains only the topology form; no
legacy runtime configuration, constructor, parser, adapter or migration remains.

## Standalone execution boundary

The standalone synchronous CLI uses local ZeroEcho signing without constructing
or starting a signing reactor or HTTP server. Its explicit session composition
shares durable step execution, domain preparation and publication with the
reactive backend used by web and remote CLI clients.

Local commands use an explicitly configured local audit identity; the trusted
root/superadministrator's invocation constitutes local approval, including for
`SINGLE`/`THRESHOLD` profiles. This does not fabricate server approval evidence
or change server approval gates or other domain validation. Interrupted
local operations are completed only by an explicit command selecting their
persisted ID; unrelated commands do not drive their signing or publication.
Structural store recovery remains required. Local signing does not remove
`INTENT`/fenced dispatch, proof, publication or unknown-durability safeguards.
There is no new publisher network prohibition: existing synchronous publishers
remain governed by their contracts. Concrete entry points, configuration and
mode/result boundaries are defined in the
[deployment and CLI contracts](pki-deployment-cli-contracts.md). `SigningStepExecutor` shares
execution; `PkiSigningCommands` shares semantic commands. `PkiSession.openLocal`
exposes the session-borrowed `LocalSigningExecutor`. Caller-thread execution
requires outer completion for success and retains receipts for explicit recovery.
Local sessions are sequential, including closure. They construct no signing
reactor or OCSP adapter; existing store infrastructure remains active. Server
preparation and completed-result projection delegate to `PkiSigningCommands`,
retaining authorization, approval evidence, acceptance custody and asynchronous
HTTP behavior. GET authorizes and projects the same semantic snapshot.

## Variant A durable model

Each operation has one logical workflow represented by non-overlapping records:

- an immutable acceptance envelope containing operation identity, internal
  canonical acceptance commitment, provider namespace and configuration
  commitment, trusted `AccessContext`, exact `KeyRef`, server-derived
  `fairnessAuthorityId`, algorithm and encoding, creation/deadline timestamps,
  exact sealed candidate reference/commitment, and optional outer commitment;
- a separately replaced mutable state containing lifecycle, revision, fence,
  lease, downstream operation identity, retry metadata, safe detail, provider
  time, and result;
- one immutable unique binding from candidate identity to operation identity and
  candidate commitment;
- when an outer command is present, exactly paired outer and correlation records.

Acceptance atomically creates all required records and prepared projections.
Later transitions replace only mutable state, except an atomic multi-record
transition required by the outer lifecycle. The active projection retains state
pointers and the minimum point-lookup identity; it does not cache decoded
envelopes. Candidate binding remains through the identity horizon even after
candidate bytes are retired.

An absent outer command means sign-only and forbids an outer continuation. A
present outer command requires the exact paired correlation. Its canonical
command commitment and semantic fields are recomputed and validated before
acceptance. The outer terminal state controls slot release. Signing success by
itself is not terminal for an outer-backed workflow. Signing expiry atomically
terminalizes the outer continuation before the slot or content can be released.

## Acceptance and uncertainty

The cohesive store operations are:

```text
acceptSign(AcceptanceCommand)
  -> ACCEPTED | ATTACHED_EXISTING | CONFLICT | CAPACITY_REJECTED

resolveAcceptance(operationId, AcceptanceCommitment)
  -> MATCHED | CONFLICT | NOT_ACCEPTED
```

Per-operation serialization and the transaction's create recheck guarantee
that identical racing commands yield one `ACCEPTED` and otherwise
`ATTACHED_EXISTING`, including at capacity. A different immutable commitment
conflicts before capacity. A candidate can bind to at most one operation; a
loser never deletes winner-owned content.

`CAPACITY_REJECTED` is a definite precommit result. Every logical
`LIMIT_EXCEEDED` source is classified only after operation and candidate-binding
rechecks. Storage I/O, ENOSPC, integrity failure, and unconfirmed durability are
infrastructure failures outside the acceptance enum. Unknown commit makes the
store recovery-required, stops admission, preserves candidate custody, and can
only be resolved after recovery. It never becomes a false rejection or false
absence.

Both local and remote acceptance first persist `INTENT`. One atomic dispatch
claim changes it to `DISPATCHED`, increments revision and fence, records the
exact downstream operation identity, and publishes a lease before provider or
local cryptographic I/O. Reconciliation and cancellation claims on
`DISPATCHED`/`CANCELLING` renew those authoritative fields without replaying the
original dispatch. A stale worker cannot advance state. Lost, duplicated, or
coalesced wake-ups are safe because eligible durable state, rather than the
event, is authoritative.

The `SigningProvider` SPI executes bounded calls and owns no orchestration
lifecycle. Its finite observation taxonomy distinguishes known pending,
retryably unknown, terminal success/failure/cancellation, and terminal
unrecoverable outcomes. A local provider signs inline, retains no per-operation
request/status/fingerprint/fence/cancellation maps, and reports a recovered
local `DISPATCHED` operation as unrecoverable without repeating cryptography.
Remote external idempotency is permitted, but never replaces store authority.
Each HTTPS response is consumed through an endpoint-specific finite streaming
bound before JSON buffering. Status bounds cover at most the 1 MiB signature
plus bounded metadata; capability and public-key responses have separate finite
bounds. Base64 text is bounded before decoding, and a non-`SIGNED` response may
not carry signature bytes.

Before every dispatch, reconciliation, or cancellation provider call, the bound
executor checks the exact namespace
`store.signingNamespace() + "." + provider.id()` and constant-time configuration
commitment equality. Every returned operation identity must equal the requested
identity. Raw remote reasons, including oversized or hostile text, are discarded
and only finite safe detail codes may enter store state, APIs, or logs.

## Candidate publication

Candidate preparation streams through one store-wide transient open-sink gate.
The configured maximum-active-request value supplies its numeric bound, but its
counters are independent of durable active slots. Exhaustion is preparation
backpressure and never `CAPACITY_REJECTED`.

The writer uses owner-only, no-follow, create-new temporary files; checks actual
streamed length and SHA-256; forces content; requires same-directory atomic move
without fallback; forces the directory; then publishes versioned metadata by
the same create/force/atomic-move/directory-force sequence, metadata last. The
configured/domain byte limit is enforced on actual bytes rather than trusting
`Content-Length`. Before `acceptSign`, the caller owns cleanup. The call consumes
custody: definite nonacceptance reclaims only an unbound supplied candidate,
while uncertainty preserves it for recovery.

## Clean persistent format

The only supported outer format is v16, with `FsCodec` 10 and schema 1 for the
separate envelope, mutable state, and binding records. Unchanged low-level WAL
formats remain unchanged. There are no legacy readers, combined-record readers,
owner-key formats, or migration paths.

The v16 boundary adds immutable raw-signing mode and the durable bounded
initial-attempt phase, with `accept-sign:v2` commitments. The preceding v15
boundary requires the exact 23-field intermediate command for creation,
additional issuance and rollover, including frozen managed-key proof scope and
TBS length/digest. Creation uses no existing subject scope; the other operations
bind their exact subject authority. Previous 21-field commands and v14 roots are
rejected; lower-level record encodings are unchanged.

An empty-store initialization durably publishes and validates namespace,
staged-content, metadata, and other mandatory components before publishing the
outer `VERSION` marker last through temp create, file force, mandatory atomic
move, and root-directory force. Before any cleanup or recovery mutation, a
bounded read-only preflight validates outer/nested versions, staged topology,
cross-record integrity, canonical encoding, size limits, and symlink absence,
then rechecks under ownership. Unsupported non-empty roots fail with stable
redacted `STORE_FORMAT_UNSUPPORTED` and remain byte-for-byte unchanged.

Signing-ledger open then follows one ownership sequence:
`PREPARED_READ_ONLY` -> `PASSIVE_ACTIVATED` -> `ENGINE_RECONSTRUCTED` ->
`RECOVERY_WRITES_FORCED` -> `THREADS_STARTED` -> `OWNERSHIP_TRANSFERRED`.
Passive activation opens no WAL writer and starts no thread. The full semantic
validator proves the forward and reverse state-envelope-candidate-binding and
outer-continuation-correlation graph before passive activation or staged-state
cleanup. Malformed persistence is normalized to cause-free
`STORE_FORMAT_UNSUPPORTED`, while genuine operational I/O remains causeful
`STORE_OPEN_FAILED`. Recovery reconstructs projections, performs and forces its
synchronous writes, starts the WAL writer and engine threads last, and only then
transfers ownership to the returned store.

## Lifecycle and capacity

```text
bounded request and candidate preparation
                  |
                  v
          atomic acceptSign
          /       |        \
  CONFLICT  CAPACITY_REJECTED  ACCEPTED/ATTACHED
                                |
                                v
                    durable INTENT + active pointer
                                |
                    bounded reactor pull and claim
                                |
                                v
                  DISPATCHED / CANCELLING / retry
                                |
                                v
              signing terminal + optional outer work
                                |
                                v
             complete outer terminal -> slot release
```

Waiting accepted work owns no thread, future, task, or unbounded mailbox.
Coordinator, WAL, due-index, resident-index, and maintenance pressure after
acceptance may defer progress but cannot produce overload. Protected progress
resources keep terminal/retry transitions possible. A soft usable-space probe
runs off acceptance and reactor paths. The filesystem query itself is
rate-limited, while warning publication is hysteretic and rate-limited; it emits
only redacted `FILESYSTEM_USABLE_SPACE_LOW`, and never changes state, result,
priority, or readiness.

For live `INTENT`, `DISPATCHED`, and `CANCELLING` state, the due index uses
`max(nextEligibleAt, leaseUntil)`. Consequently a prefix of live leased records
cannot fill a bounded page ahead of ready intent. An untouched `INTENT` has no
provider side effect and may cancel atomically to terminal `CANCELLED` without a
provider call. A dispatched operation must first commit `CANCELLING`; only then
may cancellation I/O occur, and reconciliation decides its terminal outcome.

The due projection retains only the operation identity, malformed-state flag,
and derived `SchedulingCoordinates(KeyRef, fairnessAuthorityId)`. Coordinates
are extracted from the fully decoded, canonical, commitment-validated immutable
acceptance envelope before live admission and rebuilt the same way during
recovery; they are not a new persisted field or format. Reopen validates the
complete recovered signing graph, candidate binding, outer continuation, and
correlation before any recovery mutation and fails closed on a mismatch.
The validator returns only scheduling coordinates and scalar recovery state;
reconstruction reuses them without a second envelope read or decode.

One stable scanner cycle fixes its cutoff and inclusive high watermark, then
advances the exclusive cursor until that range is exhausted. Malformed entries
and entries targeting a currently saturated pool advance the cursor and do not
starve later routes. Whenever aggregate capacity exists, every store call uses
the fixed configured page quantum `Q`; aggregate remaining capacity may make the
scanner wait but never fragments a page request. A lane completion only removes
its retained slot and signals capacity. That signal resumes a capacity-blocked
scanner in the same stable cycle but does not create a new scan after the cycle
ends. Only external acceptance/wake or the idle poll begins such a later scan;
external wakes remain coalesced.

## Complexity

For candidate size `B`, staging is `O(B)` time, `O(1)` payload heap, and `O(B)`
disk. Acceptance is expected `O(1)` point lookup plus `O(log M)` index work,
`O(log Wr)` WAL coordination, and `O(E)` envelope encoding; it is independent of
candidate bytes. Semantic validation and scheduling reconstruction are one
linear bulk rebuild over already recovered metadata: `Theta(M + Z)` time for
`M` metadata records and `Z` decoded envelope bytes, without sorting or
`W log W` reinsertion. Full recovery/open additionally replays `F`
checkpoint/WAL frames or records totaling `R` encoded bytes, for
`Theta(F + R + M + Z)` time; bounded per-frame metadata does not make the
variable-byte-volume `R` term disappear. Stable radix ordering feeds linear
due-tree and identity-tree bulk builders, and capacity plus generation
references are acquired in aggregate. Recovery owns at most one encoded
envelope workspace at a time, records `peakTrackedEnvelopeWorkspaceBytes`, and
releases it in `finally` so `currentTrackedEnvelopeWorkspaceBytes` returns to
zero. Those counters describe explicitly tracked encoded-envelope workspace,
not total heap.
The validated result contains scheduling coordinates rather than envelope bytes
or decoded envelope objects, for transient `O(Emax)` workspace and retained
`O(W + A)` recovery state for `W` active workflows and `A` scheduling/index
entries. Recovery counters are produced by this production
rebuild rather than by a benchmark-side classifier.

For at most `K <= 4096` exact key assignments, `sum(L) <= 256` lanes, and
`sum(P) <= 4096` prefetched identifiers, the reactor owns exactly
`1 + sum(L)` daemon threads and `O(K + sum(P) + sum(L))` volatile routing,
queue, and active-identifier metadata. It retains no resident workflow,
envelope, candidate, or payload backlog. A due page uses
`Theta(log W + D + D log(W / D))` selection time, returns `O(D)` lightweight
immutable memory, and uses `O(D + log W)` auxiliary memory without decoding or
copying envelope or payload bytes on the scan path. A stable scan across `W`
entries with configured page quantum `Q` costs
`Theta(W + ceil(W / Q) log W)` and `O(Q)` page memory.

Local provider dispatch consumes `O(B)` time and `O(1)` payload heap beyond
cryptographic/content streaming while retaining O(1) provider state. A remote
call consumes `O(B)` time and `O(B)` heap because the bounded transport
materializes the wire request/response, so active remote calls use at most
`O(sum(L)B)` payload heap. No throughput threshold or backlog-wide fairness SLA
is claimed.

Test-only evidence may count encoded envelope/state bytes, isolated WAL bytes,
commits, forces, result categories, and recovery visits. It must not introduce
an always-on decoded-envelope cache or a throughput threshold.
