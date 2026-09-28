# PKI Signing Performance Evidence

## Scope

The reactive backend uses a bounded pull runtime: one `SigningReactor`, one scanner,
one shared `SigningProvider`, and dedicated lane pools for disjoint exact
`KeyRef` groups plus the mandatory catch-all. Historical measurements of the
deleted push runtime are not evidence for this architecture.

The retained benchmark sources characterize storage capacity, WAL durability,
due selection, maintenance, and recovery. Deterministic reactor and queue tests
provide the current topology evidence. No synthetic throughput threshold or
backlog-wide fairness SLA is an acceptance gate.

## Cost model

For candidate payload size `B`, staging costs `O(B)` time, `O(1)` payload heap,
and `O(B)` disk. With at most `S` concurrently open sinks, aggregate staged disk
is `O(SB)`. The shared finite sink gate is independent of active workflow slots;
its exhaustion is preparation backpressure, not durable capacity rejection.

A successful new acceptance performs expected `O(1)` identity and candidate
point lookups, `O(log M)` metadata/index work, `O(log Wr)` WAL coordination, and
`O(E)` envelope encoding for `M` metadata entries, `Wr` WAL coordination state,
and encoded envelope size `E`. The acceptance cost is independent of candidate
payload bytes because acceptance persists the sealed content reference rather
than copying the payload.

Semantic validation and scheduling reconstruction over already recovered
metadata cost `Theta(M + Z)` for `M` metadata records and `Z` decoded envelope
bytes. Full recovery/open also replays `F` checkpoint/WAL frames or records
totaling `R` encoded bytes, so it costs `Theta(F + R + M + Z)`; bounded
per-frame metadata does not substitute a count for the variable encoded byte
volume `R`. The semantic phase uses stable radix ordering, bulk-builds the
due-time tree and canonical-identity tree, and acquires capacity and generation
references in aggregate; it does not sort metadata records or reinsert due work
one entry at a time. Before passive activation or cleanup, read-only validation
proves the complete state-envelope-candidate-binding and
outer-continuation-correlation graph. Its result contains only scheduling
coordinates and scalar recovery state, which reconstruction reuses without a
second envelope read or decode.

Recovery explicitly acquires one encoded-envelope workspace and releases it in
`finally`. Its transient bound is `O(Emax)` and retained active/scheduling state
is `O(W + A)` for `W` active workflows and `A` scheduling/index entries.
`peakTrackedEnvelopeWorkspaceBytes` and
`currentTrackedEnvelopeWorkspaceBytes` measure only that owned encoded-envelope
workspace, not total process heap; a completed validation has current tracked
bytes equal to zero.

The recovery visit counters are emitted by that production rebuild during store
open. They are not reconstructed by a benchmark-only classifier.

Local provider dispatch costs `O(B)` time and `O(1)` payload heap beyond the
cryptographic/content stream and retains no per-operation state. The current
remote transport materializes each bounded wire request/response, so a remote
call costs `O(B)` time and `O(B)` heap. Across `sum(L)` simultaneous lanes, the
remote-call payload heap bound is `O(sum(L)B)`.

The version 6 topology allows at most `K <= 4096` exact key assignments,
`sum(L) <= 256` lanes, and `sum(P) <= 4096` prefetched identifiers. The reactor
owns exactly `1 + sum(L)` daemon threads and
`O(K + sum(P) + sum(L))` volatile routing, queue, and active-identifier memory.
It retains no workflow, envelope, candidate, or payload backlog.

One due page selects in `Theta(log W + D + D log(W / D))` time, returns `O(D)`
lightweight immutable memory, and uses `O(D + log W)` auxiliary memory. The
scanner consumes only operation IDs, malformed flags, and derived scheduling
coordinates, so due scanning does not decode or copy envelope or payload bytes.
It preserves one cutoff/cursor/high watermark through a stable cycle and
advances past candidates for a saturated route while other pools have room.
Every store scan uses the configured page quantum `Q` whenever aggregate
capacity exists; remaining capacity never fragments the requested page. A scan
over `W` entries therefore costs `Theta(W + ceil(W / Q) log W)` and `O(Q)` page
memory. Lane completion signals capacity for a scanner blocked within that same
cycle but does not synthesize a new wake after the cycle; external
acceptance/wake and the idle poll remain the sources of later scans.

## Retained foundation evidence

`FilesystemSignWorkflowStoreTest.acceptanceAndMutableTransitionReportIsolatedWalAndCodecEvidence`
reports and asserts:

- `acceptanceEnvelopeEncodedBytes`;
- `initialStateEncodedBytes`;
- isolated `acceptanceWalBytes` and `mutableTransitionWalBytes`;
- committed requests and force counts;
- successful new acceptance transactions and result accounting; and
- transition WAL cost independent of immutable-envelope size.

Recovery instrumentation reports `envelopesVisited`, `statesVisited`,
`bindingsVisited`, `outerRecordsVisited`, `activeEntriesBuilt`,
`statePointersRetained`, `peakTrackedEnvelopeWorkspaceBytes`, and
`currentTrackedEnvelopeWorkspaceBytes`. Maximum-envelope recovery tests require
a nonzero tracked peak no larger than the largest single encoded envelope,
current tracked bytes equal to zero after validation, and exact reconstructed
due tuples. The result type structurally retains scheduling coordinates rather
than encoded or decoded envelope objects.

Additional deterministic coverage establishes:

| Boundary | Evidence |
| --- | --- |
| WAL grouping, force, and uncertainty | `SigningActiveWalTest` |
| Coordinator and resident-index capacity | `SigningLedgerCoordinatorCapacityTest`, `SigningIndexCapacityBudgetTest` |
| Due-index bounds | `SigningDueWorkIndexTest` |
| Recovery and active state pointers | `SigningWorkProjectionTest`, `FilesystemSignWorkflowStoreTest.recoveryStreamsMaximumEnvelopesIntoExactDueTuples`, retained signing recovery benchmarks |
| Maintenance publication and reclamation | `SigningLedgerMaintenanceTest` |
| Strict candidate publication | `FilesystemStagedContentStoreTest.strictSealCrashMatrixNeverExposesPartialCandidate` |
| Shared open-sink bound | `FilesystemStagedContentStoreTest.oneOpenSinkGateIsSharedAcrossCandidateLifecyclesAndReleasedByTerminalPaths` |
| Usable-space observation off admission | `SigningLedgerCoordinatorCapacityTest.usableSpaceProbeRunsOnlyOnMaintenanceCoordinator` |

## Acceptance accounting

Only a successful new `ACCEPTED` result increments the acceptance-transaction
count. `ATTACHED_EXISTING`, `CONFLICT`, and `CAPACITY_REJECTED` append no
acceptance transaction. Infrastructure uncertainty is outside those results and
requires recovery before resolution; it must never be reported as rejection or
absence.

Mutable transitions encode and persist the mutable state only. Enlarging the
immutable acceptance envelope may increase initial acceptance bytes but must not
increase the mutable-transition WAL delta.

## Reactor scheduling evidence

`SigningReactorTest` verifies exact and catch-all routing, fixed daemon thread
ownership, no lane borrowing, fixed-quantum progress when one pool is saturated,
same-cycle capacity resumption without a completion-generated wake, stable
paging beyond prefetch, malformed-entry skipping, restart, and bounded shutdown.
The two retryable-close scenarios use independent stores, providers, reactors,
and latches and each repeats deterministically twenty times.
`AuthorityFairQueueTest` verifies equal round-robin among currently buffered
authorities and FIFO within each authority. Fairness state is volatile and
resets on restart; it gives no backlog-wide latency guarantee and is not an
admission or security boundary. The trusted server derives the authority value.

## Measurement boundaries

Performance measurements are informational observations of a specified hardware,
runtime, topology and workload. They impose no minimum throughput or maximum
latency acceptance threshold. Correctness and recovery remain mandatory.

Local synchronous execution shares preparation, durable steps and publication
with the reactor. It owns no signing scheduler and adds constant orchestration
work and metadata per stage. Store opening and recovery retain the costs above;
process startup and session opening must be reported separately from command
execution. A sequential workload with one outstanding operation does not measure
saturation capacity or establish a concurrency-scaling guarantee.

## Recorded serial measurements — 2026-09-28

The [local validation harness](../app/docs/local-validation.md) completed all
three fresh JVM repetitions: 90 measured local and 90 measured reactive root-CA
publications, plus 90 measured packaged startup invocations, with zero failures.
Each series also discarded five warmups per repetition. The measurement run
finished before subsequent builds and browser integration checks began.

Environment: AMD Ryzen 5 5625U (6 cores / 12 logical CPUs), 62.2 GiB physical
memory, Linux 7.2.7 x86-64, encrypted Btrfs storage, Red Hat OpenJDK
25.0.4.1+1. Signing harness JVMs used `-Xms128m -Xmx512m`; packaged launcher
JVMs used their normal defaults. Each repetition shared one RSA-2048 key pair
between separate local and reactor stores. Each signing store accumulated
35 authorities including warmups. The topology and timing boundaries are
defined in the harness reference above; this is a one-outstanding-operation
workload with memory audit capacity 128.

Raw samples: [repetition 0](measurements/pki-2026-09-28/repetition-0.csv),
[repetition 1](measurements/pki-2026-09-28/repetition-1.csv),
[repetition 2](measurements/pki-2026-09-28/repetition-2.csv). Durations in these
files are nanoseconds; the tables below use milliseconds. P95 is the nearest-rank
95th percentile (rank 29 of 30), not an interpolated estimate.

| Repetition | Series | Median ms | P95 ms | Min–max ms | Operations / summed timed seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| 0 | Local publication | 139.466 | 154.011 | 128.657–154.651 | 7.085 |
| 0 | Reactive publication | 129.235 | 140.878 | 121.429–141.668 | 7.678 |
| 0 | Packaged startup | 1141.941 | 1300.704 | 1075.866–1321.198 | 0.869 |
| 1 | Local publication | 128.076 | 141.404 | 123.165–194.394 | 7.651 |
| 1 | Reactive publication | 136.419 | 151.634 | 131.416–151.941 | 7.242 |
| 1 | Packaged startup | 1118.214 | 1227.856 | 1091.970–1236.193 | 0.886 |
| 2 | Local publication | 141.600 | 158.254 | 131.324–158.852 | 7.006 |
| 2 | Reactive publication | 129.877 | 136.005 | 122.349–139.566 | 7.741 |
| 2 | Packaged startup | 1131.715 | 1222.619 | 1079.263–1301.016 | 0.875 |

The final column divides the 30 operations by the sum of their measured durations;
it excludes between-sample recording overhead and is not saturation throughput.
Reactive samples include preparation, durable acceptance, nominal 1 ms polling
through outer completion, and completed metadata projection. Local samples
include the public synchronous execution path and its audit wrapper. No speedup
or concurrency-scaling claim follows from the ordering-dependent differences.

Session lifecycle and parser observations remain separate:

| Repetition | Mode | Local-config parser median / P95 ms | Session open ms | Session close ms |
| --- | --- | ---: | ---: | ---: |
| 0 | local | 0.294 / 0.400 | 415.951 | 0.581 |
| 0 | reactor | 0.094 / 0.133 | 151.476 | 0.601 |
| 1 | local | 0.181 / 0.220 | 148.946 | 0.392 |
| 1 | reactor | 0.324 / 0.446 | 367.739 | 0.646 |
| 2 | local | 0.318 / 0.520 | 559.854 | 0.921 |
| 2 | reactor | 0.141 / 0.182 | 150.987 | 0.603 |

Both parsing series invoke the local CLI configuration parser. Typed reactor
topology construction is included in reactor session-open time, not a separate
reactor JSON parse. Open/close values are single observations per mode and JVM.
Mode order alternated local/reactor, reactor/local, local/reactor, so JVM and
filesystem warming affect both parser and lifecycle observations. Packaged startup
measures a fresh process through successful `configuration.validate`, including
keyring unlock and store open/close; its discarded invocations warm filesystem
caches, not a reused JVM.

Private build output retains before/after heap, GC and thread snapshots, but these
are not allocation rates, peak-memory bounds, or retained-workflow measurements.
The harness writes samples in O(n) time with O(1) retained sample memory; the
reporting calculation sorts n samples in O(n log n) time outside measured code.
These observations impose no numeric acceptance limit.
