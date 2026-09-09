# PKI signing performance measurement

## Scope

The `pki` module contains an explicitly opt-in open-loop macrobenchmark. It is
not part of the ordinary `test` task and it does not change production behavior.
Increment 2 implements the `legacy-filesystem-diagnostic` target. Increment 11
adds a small `native-shared-ledger` correctness smoke using the production
filesystem store, built-in local provider, shared local signing ledger, and
session signing runtime with no benchmark-owned outer executor. The legacy
target remains structurally diagnostic and can never satisfy the final acceptance
gate. Package 13.2 adds the native open-loop runner. Package 13.3a adds the
checked population planner and real-ledger preload/recovery fixture. Package
13.3b1 adds the exact quiescent-`M` capacity artifact, package 13.3b2 adds
the standalone due-selection diagnostic, package 13.3b3 adds direct maintenance
boundary characterization, and package 13.3b4 adds controlled production-ledger
recovery characterization. Package 13.3d adds the fixed, non-launching evidence
aggregator. Only collection of the full grid, retained-heap artifact, and three
five-minute anchor repetitions on the approved reference host remains before
Increment 13 can close.

The benchmark sends a 1 KiB payload through the production
`FilesystemPkiStore` staging implementation and `PkiSigningBus` orchestration.
The legacy target uses a benchmark-only deterministic provider with a seeded,
configurable delay and reports its private durability counters. The native smoke
instead performs production local cryptography and shared atomic ledger commits.
It deliberately creates three terminal-but-unretired durable operations with a
one-lane/one-ready scheduler, observes them at explicit event boundaries while
scheduler reserved/running/ready metrics return to zero between operations, and
then retires all three safely. That event observation is diagnostic, not a
capacity verdict.
Those topology values and the zero synthetic-provider delay are fixed for the
smoke; overriding them is rejected rather than producing a mislabeled report.

Signing has exactly one orchestration authority: `SignWorkflowStore`. The
submission acknowledgement path does not create a generic `WorkflowStateRecord`
current/history artifact and does not append or replay a `DurableAsyncBus` line
log. Generic workflow-state and async-bus persistence remain supported for
non-signing consumers. Removing these redundant synchronous projections reduces
the current diagnostic target's writes without changing the benchmark provider's
independently reported durability counters.

The change is independent of provider location. Remote endpoints and credentials
remain workflow-provider configuration, and the transport-neutral
`SignatureWorkflow` submission, status, fenced cancellation, deadline, and
notification contracts are unchanged. Notifications are acceleration hints;
restart and unknown-outcome recovery continue through authoritative bounded
reconciliation of persisted state.

The controlled legacy provider does not perform production cryptography. Its
results characterize persistence and orchestration with the configured delay,
not a particular HSM or algorithm implementation. The native smoke is a bounded
correctness topology, not a throughput characterization.

## Increment 12 correctness evidence

Increment 12 is closed by the following fixed fault/restart matrix. These tests
establish durability, isolation, recovery, and diagnostic invariants only. They
do not measure throughput, latency, allocation, or capacity; those acceptance
claims remain exclusively Increment 13 work.

| Boundary cell | Test evidence | Fixed invariant |
| --- | --- | --- |
| WAL append, group marker, and force | `SigningActiveWalTest.singletonTimeoutCommitsOneGroupWithOneForceAndStableBoundaries`, `restartMatrixPublishesOnlyCompleteGroupsAndNeverReportsFalseSuccess`, and `forceFailureMakesInflightUncertainAndQueuedWorkNotAttempted` | Recovery publishes complete forced groups only; failed or ambiguous appends never report false success. |
| Transaction acknowledgement and unknown outcome | `FilesystemSignWorkflowStoreTest.localSharedLedgerRestartMatrixNeverSplitsAuthorityOrRepeatsCryptography` | Acknowledged terminal state survives restart; an ambiguous local transaction remains recoverable without repeating cryptography. |
| Manifest and checkpoint publication | `SigningFilePublicationRecoveryTest.manifestPublicationRestartSelectsOneCompleteEquivalentTopology` | Every write, file-force-before/after, atomic-move, and directory-force boundary selects the complete old or new topology, never a hybrid; unreferenced checkpoint/WAL artifacts remain cleanup candidates only. |
| Integrity, checksum, and commitment | `SigningLedgerRecoveryTest.integrityRestartMatrix` | CRC32C, group digest, rolling commitment, SHA-256 artifact commitment, manifest commitment, ordering, and continuity corruption fail closed with stable redacted recovery diagnostics. |
| Seal, hard link, and maintenance publication | `SigningActiveWalTest.hardSegmentBoundSignalsRotationBeforeAppendingAndSealNeedsNoRescan`, `SigningLedgerMaintenanceTest.everyRotationCrashBoundaryRecoversExactlyOneTopology`, and `maintenanceCrashRestartMatrix` | Sealing stays within the hard bound, and rotation/compaction publication recovers one complete manifest-selected topology. |
| Shared-ledger cross-authority/provider isolation | `FilesystemSignWorkflowStoreTest.sharedRemoteLedgerTerminalFaultIsolatesAuthoritiesAndNeverRepeatsProviderWork` | Equal configuration commitments cannot substitute provider identity; foreign submit, status, cancellation, or terminal publication cannot mutate another authority, and provider work remains exactly once. |
| Callback, cancellation, and redaction | `PkiSigningBusFailureTest.callbackAndCancellationRestartMatrix`, `hostileCancellationFailureIsRedactedAndRestartConvergesWithoutResubmission`, and `providerCallbackDropsMalformedAdvisoriesWithoutThrowing` | Callbacks remain advisory, cancellation converges after restart without resubmission, and public/JUL diagnostics contain only their stable redacted messages. |
| Reclamation and direct restart | `SigningLedgerMaintenanceTest.directReclamationRestartMatrix` | Restart directly after pre-delete, post-delete, or directory-force failure preserves every referenced artifact and authoritative record; surviving unreferenced artifacts are reclaimed and a second reopen is idempotent. |

## Workload model

Arrivals are scheduled from an absolute monotonic start time at the configured
open-loop rate. A slow operation never delays the schedule of a later arrival,
so the reported end-to-end latency does not hide queueing through coordinated
omission. End-to-end latency begins at the scheduled arrival, not at lane start.

The legacy target wraps the current path in a fixed number of execution lanes
and a bounded outer queue. Exhaustion rejects an arrival before content staging
or durable intent creation. This outer admission topology is useful for
measuring the current bottleneck but is not equivalent to native production
admission. Final acceptance requires the `native-shared-ledger` target and its
production-owned bounded lanes and shared durability ledger.

The benchmark stores latency in fixed-capacity primitive reservoirs; it does not
retain one sample object per operation. The frozen acceptance fingerprint uses:

- minimum 4 GiB maximum heap;
- 16 lanes and 64 queued operations;
- 1,100 scheduled arrivals per second, allowing a meaningful 1,000/s completion
  gate inside the fixed measurement window;
- 1 KiB deterministic payloads;
- actual built-in local-provider latency, with no synthetic provider delay;
- 30 seconds of warm-up and 300 seconds of measurement;
- at most 1,000,000 samples per latency series.

The controlled 10 ± 2 ms provider remains a separate diagnostic target and can
never satisfy native acceptance. The production group maximum remains 32;
group 64 is a required fail-closed `UNSUPPORTED_MAX_32` contract cell, not a
production tuning option.

The benchmark process sets the `zeroecho.pki` JUL namespace to `WARNING` before
warm-up so per-operation informational console output does not become part of the
measured path. Warnings and failures remain visible.

The 4 GiB heap is the minimum supported capacity tier, not a fixed upper limit.
Its associated target is `M = 1,000,000` current metadata keys,
`W = 100,000` active or not-yet-retired signing operations, and no more than
512 MiB of resident indexes. A larger heap may define a separate tier only after
the same retained-memory, recovery, overload, throughput, and latency measurements
are repeated. Capacity must not be extrapolated linearly from heap size.

The production store exposes this ceiling as the positive
`FsPkiStoreOptions.signingResidentIndexBudgetBytes` parameter; its default is
exactly 512 MiB. The setting is applied identically to initial creation and
recovery/open. Recovery fails closed when the reconstructed indexes cannot fit.
Changing the setting does not by itself approve a new capacity tier.

## Commands

Run the fast deterministic contract test:

```bash
./gradlew :pki:signingPerformanceSmoke
```

Run a short diagnostic profile:

```bash
./gradlew :pki:signingPerformanceBenchmark \
  -PsigningBenchmarkProfile=diagnostic \
  -PsigningBenchmarkDiagnosticEnvironmentOverride=true
```

Run the fixed non-grid native diagnostic on a non-reference host:

```bash
./gradlew :pki:signingPerformanceBenchmark \
  -PsigningBenchmarkProfile=native-diagnostic \
  -PsigningBenchmarkDiagnosticEnvironmentOverride=true \
  -PsigningBenchmarkWarmupSeconds=0 \
  -PsigningBenchmarkDurationSeconds=1 \
  -PsigningBenchmarkRate=2
```

This fixed diagnostic uses `M=1,000`, `W=10`, 16 lanes, group 32, and the
actual local provider. It is deliberately outside the 11-cell grid and can
never produce an evaluated or passing acceptance result.

The final acceptance command, after the remaining Increment 13 packages close,
is:

```bash
./gradlew :pki:signingPerformanceBenchmark \
  -PsigningBenchmarkProfile=acceptance \
  -PsigningBenchmarkTarget=native-shared-ledger \
  -PsigningBenchmarkHeap=4g \
  -PsigningBenchmarkOutput=/trusted/pki-signing-evidence/anchor-1.json
```

Package 13.3a constructs each valid grid cell's planned real-ledger population;
combined-workload cells use explicit zero active preload. The command is not yet an
acceptance gate: recovery characterization, aggregation, and the remaining
acceptance evidence are still pending. The bounded native smoke continues to
exercise composite admission, the shared filesystem ledger, local cryptography,
retirement, runtime metrics, and shutdown. On the reference host, repeat the
command three times with output names `anchor-1.json` through `anchor-3.json`.
Each Gradle `JavaExec` invocation launches a fresh benchmark JVM; the Gradle
daemon is not the measured process. Do not pool repetitions in one JVM. Record
all three reports and use the worst repetition for the throughput and p99 gate.

## Final evidence aggregation

The aggregator never launches a benchmark and never enumerates its input
directory. It accepts only the fixed Increment-13 bundle: `anchor-1.json`
through `anchor-3.json`, the nine supported `grid-<cell>.json` reports,
`group64-rejection.json`, `due-selection.json`,
`direct-maintenance.json`, `recovery.json`,
`retained-index-evidence.json`, `retained-index-heap-artifact.bin`, and
`evidence-sha256.txt`. The manifest contains lowercase SHA-256 entries in
lexical filename order for the 18 evidence files other than the manifest.

`retained-index-evidence.json` uses schema
`zeroecho-signing-retained-index-evidence-v1` and contains `method`
(`CLASS_HISTOGRAM` or `HEAP_DUMP`), `environmentEvidenceSha256`,
`retainedIndexBytes`,
`rawArtifactFile`, `rawArtifactSha256`, `tool`, `toolVersion`, `command`, and
`capturedOutsideLatency=true`. The raw artifact name is fixed to
`retained-index-heap-artifact.bin`; its measurement must be taken outside the
three latency repetitions. `environmentEvidenceSha256` must exactly equal the
manifest SHA-256 of `anchor-1.json`; the aggregator verifies that binding before
accepting either the retained-byte measurement or its raw artifact. The
aggregator streams the raw hash, caps every JSON input at 1 MiB, and enforces
the approved 512 MiB retained-index limit.

Run it only after all reference artifacts and the manifest have been collected:

```bash
./gradlew :pki:signingPerformanceAggregate \
  -PsigningEvidenceRoot=/trusted/pki-signing-evidence \
  -PsigningEvidenceOutput=/trusted/pki-signing-verdict.json
```

The output is schema `zeroecho-signing-evidence-verdict-v1`. A failing bundle
still produces a deterministic verdict with sorted reasons and input hashes,
then exits nonzero. The output must be lexically outside the evidence directory.
Aggregation is `O(B)` time for total evidence bytes and uses bounded metadata
plus a fixed streaming hash buffer.

The following Gradle properties override a profile:

| Property | Meaning |
| --- | --- |
| `signingBenchmarkProfile` | `diagnostic`, fixed non-grid `native-diagnostic`, `acceptance`, or test-only `smoke` |
| `signingBenchmarkTarget` | `legacy-filesystem-diagnostic` or `native-shared-ledger` |
| `signingBenchmarkCellId` | exact stable grid-cell identifier |
| `signingBenchmarkCellMode` | `grid`, `controlled-diagnostic`, fixed `native-diagnostic`, or test-only `smoke` |
| `signingBenchmarkRetainedPopulation` | retained metadata population `M`, bounded to 1,000,000 |
| `signingBenchmarkActivePopulation` | active signing population `W`, bounded to 100,000 |
| `signingBenchmarkGroupSize` | `1`, `8`, or `32`; `64` exercises fail-closed `UNSUPPORTED_MAX_32` |
| `signingBenchmarkWarmupSeconds` | warm-up arrival duration, from 0 through 30 seconds |
| `signingBenchmarkDurationSeconds` | measured arrival duration, from 1 through 300 seconds |
| `signingBenchmarkRate` | scheduled arrivals per second, from 1 through 1,100 |
| `signingBenchmarkLanes` | concurrent signing lanes, from 1 through 32 |
| `signingBenchmarkQueueCapacity` | ready provider steps, from 0 through 64; zero uses direct handoff |
| `signingBenchmarkProviderMeanMillis` | controlled provider mean delay |
| `signingBenchmarkProviderJitterMillis` | symmetric integer-millisecond jitter |
| `signingBenchmarkPayloadBytes` | staged payload size |
| `signingBenchmarkSampleCapacity` | maximum retained samples per latency series |
| `signingBenchmarkDrainSeconds` | maximum post-arrival drain time, from 1 through 120 seconds |
| `signingBenchmarkSeed` | payload, provider-delay, and reservoir seed |
| `signingBenchmarkDiagnosticEnvironmentOverride` | labels a non-reference-host run as diagnostic; it can never satisfy acceptance |
| `signingBenchmarkHeap` | benchmark JVM maximum heap; minimum `4g` outside smoke |
| `signingBenchmarkOutput` | JSON report path |
| `signingBenchmarkWorkRoot` | temporary store parent, normally on the measured filesystem |

### Increment 13 package 13.1 status

Package 13.1 is complete and defines the pre-workload contract. Its
orthogonal grid is an explicit, deterministic 11-cell sequence after anchor
deduplication: one anchor (`M=1,000,000`, `W=100,000`, lanes 16, group 32), two
additional retained-population cells, two additional active-population cells,
three additional lane cells, two additional supported-group cells, and the
group-64 unsupported boundary. It is not a Cartesian product. Grid construction
and verification use `O(A)` time and `O(A)` bounded memory for fixed `A=11`.

Environment discovery now runs before work-root creation, fixture construction,
preload, or workload execution. A reference/acceptance mismatch stops before
work. An explicit diagnostic override permits bounded diagnostic execution but
retains every mismatch reason and forces `evaluated=false` and
`targetMet=false`. Report schema v5 records the exact cell fingerprint and
preflight result. Package 13.1 does not implement the native open-loop workload,
capacity preload, recovery runner, or multi-run aggregation; native non-smoke
execution remains rejected after successful preflight until package 13.2.

Before environment discovery, an `O(1)` verifier rejects any value outside the
documented execution envelope without clamping it. It also binds `acceptance`
and `smoke` to `native-shared-ledger`, and `diagnostic` to
`legacy-filesystem-diagnostic`. Rejection occurs before work-root mutation and
reports a stable machine-readable contract reason.

### Increment 13 package 13.2 status

Package 13.2 implements native open-loop execution with a fixed capacity of
`W=activePopulation` lightweight workflow contexts and
`E=min(W, lanes + queueCapacity)` short-step workers. The scheduler derives
every arrival from one absolute monotonic start and stores due contexts in a
fixed-capacity binary min-heap. A leader/follower condition pattern allows at
most one idle worker to time the earliest due context while other idle workers
wait without polling. A context is queued or exclusively owned by one worker
for one transition; no thread, handle, future, or lease remains attached while
it waits. Context-capacity exhaustion is reported as
`HARNESS_CONTEXT_CAPACITY_EXHAUSTED` and makes the report non-evaluable rather
than appearing as product rejection.

The benchmark-native state path is
`SUBMIT -> OBSERVE -> CONSUME -> RETIRE_SUCCESS|RETIRE_FAILURE -> DONE`.
Each worker executes one short transition outside the scheduler lock and then
requeues by absolute monotonic due time or completes the context. `OBSERVE`
uses the production-aligned 10 ms cadence. Submit-local foreground, admission,
and staged-content handles never survive a transition; persistent state between
transitions is identifier-based. Provider execution remains solely owned by
the production `SigningExecutionRuntime`.

Warm-up uses the identical path and must drain and retire fully before metrics,
reservoirs, writer counters, allocation, GC, and heap baselines reset. The
report separates context-capacity exhaustion, product admission rejection,
pre-accept failure, durable acceptance, fixed-window/post-window completion,
failure, uncertainty, and retirement. It also records bytes and forces per
accepted signature, baseline/final heap, and the sum of individual heap-pool
peaks. Whole-run runtime and writer
maxima remain labelled as cumulative where the production counter is not
resettable. Dynamic no-duplicate-cryptography assurance relies on the one-shot
local execution permit and the Increment 12 fault/restart evidence; the
benchmark adds no duplicate production counter.

Queue insertion and removal cost `O(log W)` per transition, so `T` state
transitions, including bounded observation polls, cost `O(T log W)` in total.
Earliest-due lookup is `O(1)`, context memory is `O(W)`, and worker threads are
`O(E)`. No measured-path signing-record scan or operation-ID registry is used.

Package 13.2b adds the immutable public
`FsPkiStoreOptions.signingMaximumGroupSize` setting with a default and hard
maximum of 32. Values 1 through 32 constrain newly committed durability groups;
valid historical groups up to the unchanged format limit of 32 remain readable
after reopening with a smaller runtime maximum. The exact configuration is
preserved across create, reopen, recovery, maintenance, and WAL rotation without
a manifest, WAL, or store-format change.

Native grid groups 1, 8, and 32 now reach the real writer whenever their cell
otherwise has an executable zero-preload topology. The native diagnostic keeps
fixed `M=1,000`, `W=10`, and 16 lanes while allowing the supported group axis for
bounded non-reference investigation; it remains outside the grid and can never
satisfy acceptance. Every native report records the observed whole-run maximum
batch size and verifies that it does not exceed the selected group size. Group
64 retains `UNSUPPORTED_MAX_32` precedence and cannot mutate the work root.

### Increment 13 package 13.3a status

Package 13.3a is complete. Every supported grid cell receives one checked,
deterministic plan. The two non-anchor retained-population cells use
`RETAINED_ONLY`: `G=M-1`, one durable watermark, and no active preload or
workload. The anchor and W/lane/group families use `COMBINED_WORKLOAD`:
`C=W`, `P=0`, `A=warmup arrivals + measured arrivals`, and
`G=M-(A+W+1)`. The anchor is exactly `W=100,000`, `P=0`, `A=363,000`, and
`G=536,999`. Here `M` is the planned maximum number of current keys; after all
benchmark-owned active work retires, the planned drained population is `M-W`,
or `900,000` at the anchor. Negative, impossible, or checked-arithmetic-invalid shapes fail
before work-root mutation. Group 64 retains earlier `UNSUPPORTED_MAX_32`
precedence.

The benchmark-only fixture writes generic population through the real segmented
ledger in direct-commit cohorts of at most 31; combined-workload cells begin
with the explicit `P=0` active preload. It then closes and replays the image
through production recovery before the normal benchmark-store reopen. Mutation
count and serialized payload bytes are `O(G)`; CPU cost is `O(G log M)`, and
bounded-cohort transient auxiliary memory is `O(log M)`. Recovery publishes
an immutable scalar observation of exact generic, signing-record, owner,
watermark, current, due, and shared-content-owner counts. Native diagnostic and
smoke profiles do not use this fixture and report population mode `NONE`.
Successful owner-admission and retirement events maintain an exact quiescent
final count and a separately named `accountedEventHighWaterRecords` diagnostic.
The event high-water depends on post-commit callback ordering and is not an
authoritative durable-population or capacity measurement.
The selected filesystem's setup force count, setup group topology, and physical
disk/history amplification remain explicit package 13.3b characterization;
13.3a introduces no inferred threshold or acceptance claim for them.

### Increment 13 package 13.3b1 status

Package 13.3b1 is complete. A retained-only cell persists `G=M-1` generic keys
and one watermark, then production-reopens the ledger at quiescence. One
package-private on-demand observation composes existing index statistics in
`O(L+S)` time and `O(1)` auxiliary memory for `L` live MVCC snapshots and `S`
registered generations, independent of `M` and `W`, without scanning keys or
retaining a snapshot, handle, cache, counter, thread, or queue. A verified
retained-only artifact requires `L=0`, reducing observation time to `O(S)`. It records current-key count and
canonical bytes; MVCC estimated and
reserved bytes; due-work, retention, owner-projection, and identity-reservation
statistics; generation identity-state counts, current references, and pins; and
the shared current, lifetime-high-water, and maximum budget. The public
constant-time `localSigningIndexCapacityMetrics()` operational observation
provides the same three shared counters without requiring ledger quiescence or
resetting the high-water value.

The capacity artifact is verified only when current keys and generation current
references equal exact planned `M`, work/owner/retention projections and pins are
empty, published generation state is consistent, and shared reservation does
not exceed the 512 MiB tier. The checked sum of MVCC, due, retention, owner, and
projection reservations must exactly equal the shared reservation. Failures use stable machine-readable capacity
reasons and invalidate evaluation. Diagnostic environment override remains
unconditionally non-evaluable. The artifact also records existing bounded JVM
used-heap, live-thread allocation, and GC counters while the reopened ledger is
live. Those counters do not substitute for retained-object attribution: the
operator must still collect a class histogram or heap dump outside the latency
repetition on the approved reference host for the final capacity evidence.
Retained-only mode is selected before local-provider initialization and creates
no keyring or unlock material. A combined-workload run zeroes every created
unlock character array in its outer cleanup boundary, including setup failure.

### Increment 13 package 13.3b2 status

Package 13.3b2 is complete. The standalone, opt-in due-selection diagnostic
populates active work through the benchmark-only real-ledger fixture, performs
production recovery, reopens the segmented ledger, and times only
`metadata.selectSigningDue(cutoff, D)`. The timed call includes bounded `O(D)`
identity conversion and selection close but performs no workflow-record I/O.
Its fixed selection-bound axis is exactly `D={1,64,1024,4096}`. The first sample
is labelled `firstInProcess`, never cold or cache-free; a strictly bounded
primitive array holds the configured `subsequentInProcessSamples` and reports
p50/p95/p99/max. Neither population has a JIT steady-state or cache-state
guarantee.

Schema `zeroecho-signing-due-selection-v1` records `W`, the exact eligible
count, cutoff classification, `D`, subsequent-sample count, normalized paths,
a deterministic configuration fingerprint, and
`environmentEvidenceSha256`. The latter is the manifest SHA-256 of
`anchor-1.json`; package 13.3d requires the exact match before accepting the
sidecar. Every sample must return exactly `D`
identities. The artifact explicitly records `recordIoIncluded=false`,
`algorithmicWorkEvidence=STATIC_COMPLEXITY_ONLY`, `O(log W + D)` selection time,
and `O(D)` selection memory. It is diagnostic-only and defines no latency
threshold or acceptance verdict. Ordinary CI executes only a real-ledger shape
with `W<=10` and `D=1`; the fixed-axis contract proves the required 4,096 bound
without running it. Full `W=100,000` remains reference-host opt-in work. The
configured work root must not exist, including as a symbolic link; an existing
root fails with `WORK_ROOT_NOT_FRESH` before mutation and is never deleted or
overwritten.

This schema-v1 sidecar deliberately contains no mount, JVM, cgroup, host, or
power-policy discovery. The operator must capture the approved environment
separately, or bind the matching main schema-v5 report. Package 13.3d must bind
that environment evidence to this sidecar before using it in a final verdict;
the fixed bundle uses the `anchor-1.json` hash for that binding.

Example reference/diagnostic invocation:

```bash
./gradlew :pki:signingDueSelectionBenchmark \
  -PsigningDueSelectionBenchmarkActivePopulation=100000 \
  -PsigningDueSelectionBenchmarkSelectionBound=4096 \
  -PsigningDueSelectionBenchmarkSubsequentInProcessSamples=64 \
  -PsigningDueSelectionBenchmarkEnvironmentEvidenceSha256=<sha256-of-anchor-1.json> \
  -PsigningDueSelectionBenchmarkOutput=/trusted/pki-signing-evidence/due-selection.json \
  -PsigningDueSelectionBenchmarkWorkRoot=build/signing-performance/due-selection
```

### Increment 13 package 13.3b3 status

Package 13.3b3 is complete. Its standalone opt-in fixture uses the real active
WAL, immutable sealed hard links, manifest, MVCC pointers, artifact catalog,
generation registry, checkpoint writer, and bounded reclamation path. The
configured `sourceGenerations` is the maintenance source-generation bound (1–64),
while the fresh fixture contains exactly `sealedSegments+1` readable pointer
sources. The reference operational shape uses eight pre-compaction sealed
segments; ordinary CI uses only one sealed segment and four live records.

One fresh JVM and absent `workRoot` perform exactly one direct
`SigningLedgerMaintenance.compact` call. Timestamps taken immediately before the
call, in its rotation-boundary callback, and after return produce exactly
`rotationToBoundaryNanos`, `checkpointAfterBoundaryNanos`, and
`totalCompactionNanos`; monotonicity and the checked equality of the first two
intervals to the total are mandatory. A separately reported bounded reclaim is
outside all three compaction intervals. `MaintenanceException` preserves the
stable `ROTATE`, `CHECKPOINT`, or `RECLAIM` stage.

Schema `zeroecho-signing-direct-maintenance-v1` reports pre/post manifests,
sealed counts and bytes, checkpoint bytes/live records, source channels opened,
reclaimed artifacts/actions, and bounded JVM used-heap, GC, and
live-caller-thread allocation deltas. It identifies the rotation publication
mode as `HARD_LINK` and its zero-copy evidence as `STATIC_CODE_PATH`; it does not
misrepresent uninstrumented runtime byte counters as measured evidence.
Used-heap delta is not a retained-heap measurement and allocation is only a
live caller-thread estimate.
The artifact sets `directMaintenanceCharacterization=true` and
`automaticEngineAdmissionContentionMeasured=false`: this direct maintenance
interval is not a full-checkpoint admission pause and defines no latency
threshold or acceptance verdict. Work is
`O(L + B_live + S)` time for `L` live records, their `B_live` serialized bytes,
and `S` source generations. Auxiliary memory is
`O(L + B_batch + S)`: the replacement AVL contains `L` records, the existing
checkpoint batch `B_batch` is at most 64 MiB, and `S` is at most 64.

The benchmark `workRoot` and report-output parent are trusted deployment paths
exclusively owned by the PKI process. They must not be writable by untrusted
users or processes, and the PKI benchmark must not run with elevated privileges
over untrusted paths. The output path is lexically separate from `workRoot`; an
existing report leaf must be a regular file and is opened without following a
symbolic link. This trust axiom deliberately does not claim ancestor-realpath or
symlink-race defense.

```bash
./gradlew :pki:signingDirectMaintenanceBenchmark \
  -PsigningDirectMaintenanceBenchmarkLiveRecords=100000 \
  -PsigningDirectMaintenanceBenchmarkSourceGenerations=64 \
  -PsigningDirectMaintenanceBenchmarkSealedSegments=8 \
  -PsigningDirectMaintenanceBenchmarkOutput=build/reports/signing-performance/direct-maintenance.json \
  -PsigningDirectMaintenanceBenchmarkWorkRoot=build/signing-performance/direct-maintenance
```

Run only one benchmark against the measured filesystem at a time. Use the same
filesystem and mount options for comparisons, leave adequate free space, and
avoid unrelated I/O load. The main schema-v5 report records discoverable mount, JVM, cgroup,
and power-policy information and states why a constraint is unavailable when it
cannot be discovered portably.

## Report contract

The task prints one concise line and writes schema
`zeroecho-signing-performance-v5` JSON. The report contains:

- scheduled, workflow-context-admitted, context-capacity-rejected, product-admitted, durably
  accepted, product-admission-rejected, pre-accept-failed, completed, retired,
  failed, and uncertain counts;
- completions inside the exact scheduled-arrival window, completions during
  drain, authoritative terminals inside/after the window, backlog at window
  close, and fixed-window achieved throughput;
- end-to-end and admission-queue p50, p95, p99, and maximum latency from the
  scheduled arrival;
- provider implementation and submit/status time; controlled-provider force
  latency where available; and native shared-writer groups, committed requests, bytes,
  force, and group-wait evidence;
- accounted event-boundary high-water as a non-authoritative diagnostic,
  explicitly inferred shared-local atomic commit identity, and measurement-end
  scheduler/advisory metrics;
- the population mode, planned `G/P/W/A`, planned maximum current keys `M`,
  planned drained current keys `M-W`, recovery-observed preload counts, and
  benchmark-owned quiescent actual current count and non-authoritative event
  high-water derived from successful owner admission and retirement accounting;
- the quiescent capacity-artifact state/reasons, exact scalar index and generation
  observation, shared capacity reservation, and live-ledger JVM counter sample;
- live-thread allocation estimate or `null` when unavailable/regressed, GC
  count/time, heap-use delta, baseline/final heap, and sum-of-pool-peaks;
- sanitized JVM option evidence, heap, OS, processor, filesystem/mount, free-space, host,
  container, and power-policy metadata;
- the multiplexer `contextCapacity`, `stepWorkers`, measurement-phase
  `workflowTransitionsExecuted`, `observationAttempts`, and
  `peakResidentContexts`; the seed, sample bound, drain timeout, work root, target, and admission
  topology needed to reproduce the run; and
- cleanup state plus exact-fingerprint acceptance evaluation; pending or failed
  cleanup is unconditionally non-evaluable/non-passing, and only successful
  cleanup may publish the workload assessment.

`contextCapacity` and `stepWorkers` are zero in reports for paths that do not
instantiate the native multiplexer, including retained-only cells.

The benchmark also emits stable, single-line `key=value` JUL events through
the dedicated `zeroecho.benchmark.signing` logger. These events mark preflight,
work setup, population, warm-up, measurement deadline, drain, report, cleanup,
and final verdict boundaries. Population reports start and completion plus at
most nine count-derived intermediate milestones for each generic and active
stage; it performs no time polling. The scheduled-arrival and signing-operation
paths contain no logging, runtime/writer snapshot, or counter polling. The
measurement-deadline event is counter-free, and counter/runtime snapshots are
taken only after phase quiescence or on a terminal phase failure.

If execution fails before a complete schema-v5 report is available, the normal
output remains absent and the benchmark writes a sibling named
`<output-basename>.failure.json`. Its schema is
`zeroecho-signing-performance-failure-v2` and contains the failed phase, every
known invariant deviation with actual and expected values, elapsed time, the
trusted benchmark configuration, environment fingerprint, latest bounded
population progress, the complete latest run-counter and runtime snapshots,
cleanup outcome, and the first safe deviation category/cause type. It never
records operation identifiers, payloads, exception messages, throwable graphs,
or per-operation history. JVM option evidence preserves only bounded numeric
heap forms and explicit collector flags; system properties, agents, paths, and
arbitrary valued options retain at most a bounded option name with the value
redacted. Failure-artifact I/O failure is suppressed on the primary exception.
A successful final schema-v5 report removes a stale sibling failure artifact.
Completed but non-passing runs log and retain `evaluable`, `targetMet`, and all
acceptance reasons in the normal report.

`completed`, `failed`, and `uncertain` are disjoint accepted-operation outcomes.
An authoritative terminal observation is timestamped before result consumption:
both success and terminal failure reduce fixed-window backlog when observed by
the deadline. If later successful-result consumption becomes uncertain, that
operation remains terminal for backlog but is counted only as `uncertain`, not
as completed success. `uncertain` can overlap `accepted` when failure occurs
after submission acknowledgement. Throughput is successful completions whose
authoritative terminal observation preceded the exact measurement deadline,
divided by the configured measurement duration; drain time is never counted in
that denominator. The report separately exposes post-window completion and
backlog so draining cannot hide overload.

For the legacy target, `admitted` counts every scheduled arrival handed to its
bounded outer executor. Native accounting is more explicit:
`scheduled = workflowContextsAdmitted + contextCapacityRejected` and
`workflowContextsAdmitted = admitted + productionAdmissionRejected + preAcceptFailure`.
Native `admitted` is recorded at successful composite reservation and is rolled
back if the call fails before durable acceptance, so `admitted = accepted` for a
completed valid run. `backlogAtWindowClose` is computed after drain from the
immutable event-time classifications
`admittedWithinWindow - terminalWithinWindow`; drain cannot race or change the
fixed deadline. `completed = completedWithinWindow + completedAfterWindow`.

Native JSON names the WAL transition count `requestsCommitted`; it is distinct
from `groupsCommitted`, which is the batching dimension. The former generic
`writes` field does not exist. `inferredSharedLocalAtomicCommits` is explicitly
derived from the exact accepted/provider-invocation invariant and is not
presented as a raw writer counter.

Acceptance is evaluable only for the exact approved fingerprint: acceptance
profile, native shared-ledger target and native admission, 4 GiB heap tier,
30-second warm-up, 300-second window, 1,100/s offered rate, 16 lanes, queue 64,
the `M=1,000,000`/`W=100,000`/group-32 anchor, actual local-provider latency
with no synthetic delay, 1 KiB payload, 1,000,000-sample bound,
120-second drain timeout, and seed `0x5eed2026`. Any override makes the result
non-evaluable and lists the mismatched fields. A passing run additionally
requires exactly 330,000 scheduled, composite-admitted, and durably accepted
operations, zero rejections,
failures, uncertainties, or retained provider operations, every accepted
operation completed, at least 300,000 completions inside the window
(>= 1,000/s), and end-to-end p99 below 100 ms.

The approved reference environment is also part of the fail-closed fingerprint:
Java 25 LTS, G1, an AMD Ryzen 5 7600 with 12 logical processors, and local
non-rotational NVMe-backed Btrfs mounted with `noatime`, `compress=zstd:3`,
`ssd`, and `discard=async`. CPU identity is normalized for punctuation and case,
but incomplete or unverifiable Java, CPU topology, collector, filesystem, mount,
or block-device evidence makes acceptance non-evaluable with an explicit reason.
`signingBenchmarkDiagnosticEnvironmentOverride=true` is available only to label
an intentionally non-reference comparison: it does not suppress mismatch reasons
and unconditionally prevents `targetMet=true`.

The native smoke reads an immutable shared-writer snapshot before and after its
three local atomic commits and reports exact deltas for force, committed request,
group, byte, force-time, and group-wait counters. The legacy diagnostic reports
its benchmark provider's private counters; shared-writer-only fields are `null`
rather than inferred from file counts.

The allocation estimate uses live JVM thread-allocation counters before and
after measurement. Counter unavailability or regression produces JSON `null`,
never a clamped zero. It is useful for comparing identical profiles but is not a
retained-heap measurement. The capacity gate must additionally use a post-warmup
class histogram or heap dump at the configured `M` and `W`, attribute retained
bytes to each index, verify the 512 MiB index budget, then restart the same store
and measure recovery time and recovered resident heap. Heap inspection must be
performed outside the latency repetition because a dump or histogram perturbs
latency. Package 13.3b1 supplies the separate quiescent scalar artifact that
establishes exact planned `M`. Operator-collected retained-object attribution on
the reference host remains mandatory package 13.3b evidence, and package 13.3d
must consume both before issuing the final capacity verdict.

## Current diagnostic baseline

The Increment 2 baseline is intentionally diagnostic, not an acceptance result.
It uses the pre-segmented per-operation persistence path and exists to show the
forced-write bottleneck before persistence work begins. The exact command,
machine metadata, and measured values are recorded here after the local run; the
generated JSON remains the authoritative detailed artifact.

On 2026-08-12 the reference host ran:

```bash
./gradlew :pki:signingPerformanceBenchmark \
  -PsigningBenchmarkProfile=diagnostic \
  -PsigningBenchmarkWarmupSeconds=1 \
  -PsigningBenchmarkDurationSeconds=5 \
  -PsigningBenchmarkRate=200 \
  -PsigningBenchmarkLanes=16 \
  -PsigningBenchmarkQueueCapacity=64 \
  -PsigningBenchmarkProviderMeanMillis=10 \
  -PsigningBenchmarkProviderJitterMillis=2 \
  -PsigningBenchmarkPayloadBytes=1024 \
  -PsigningBenchmarkOutput=build/reports/signing-performance/increment-2-diagnostic.json
```

The fresh Java 21 JVM used a 4 GiB maximum heap on an AMD Ryzen 5 7600
(12 logical processors), local NVMe-backed Btrfs with zstd compression, and G1.
Of 1,000 scheduled arrivals at 200/s, 96 were admitted, accepted, and completed; 904 were
rejected by bounded outer admission, and none failed or were uncertain. Sixteen
completed inside the exact five-second window, 80 completed during drain, and
the window-close backlog was 80 admitted tasks; fixed-window throughput was 3.2/s.
End-to-end p50/p95/p99/max were
11,589.7/20,014.1/20,217.1/20,217.1 ms. Admission-queue p99 was 16,423.3 ms.
The controlled provider recorded 384 forces (four per completion), with force
p50/p95/p99/max of 3.078/5.861/6.303/7.817 ms, and retained zero terminal
operations after result consumption. The live-thread allocation delta was
255,176,432 bytes with no measured GC collection. Cleanup succeeded. The report
also captured the exact JVM arguments and the `/home` Btrfs mount source/options;
cgroup-v2 and portable power-policy constraints were reported unavailable with
reasons.

This five-second saturation probe is deliberately too short and too lightly
warmed to be an acceptance result. It demonstrates that the current forced,
per-operation persistence path rapidly fills the approved 64-entry queue even at
one fifth of the target arrival rate. It must not be compared to the final
five-minute, three-process acceptance gate as though the sampling confidence were
equivalent.

Increment 10 removes that provider-side persistence path from production. The
built-in ZeroEcho-lib workflow now shares the filesystem store's segmented
writer, force, recovery, maintenance, and bounded index domain through a borrowed
process-local participant. One durability round accepts local orchestrator and
provider intent before cryptography; one round commits provider terminal state
and the orchestrator result before success becomes visible. No provider
operation files or separately forced provider watermark exist. Each round is one
self-describing direct-commit frame and one grouped force, with no issuance or
acknowledgement frames. Status and monotonic-time reads perform no WAL append or
force; a later state mutation folds the observed watermark into its commit. The
diagnostic numbers above remain historical baseline evidence and are not
Increment 13 acceptance results.

The local payload path is one sequential pass: SHA-256 commitment verification
and cryptographic consumption share the same stream, and the filesystem source
is opened once without a pre-hash pass, requiring `O(P)` time and
`O(1)` auxiliary transfer/digest memory. Point lookup remains expected `O(1)`;
state update is `O(P + log W)` plus sequential append; due selection and purge
are not the same operation. For a nonempty identity index with `W` records and
`R` returned due records, effective `D = max(1, R)`, so `1 <= D <= W`; the
page-bound worst case uses `D = min(page bound, W)`. Identity-ordered
reconciliation selection has worst-case
`Theta(log W + D + D log(W / D))` time, `O(D)` returned immutable memory, and
`O(D + log W)` total auxiliary memory. An empty index returns an empty page in
constant time and memory. One retention pass instead costs
`O(log W + B + B(log M + log W))` for `B <= 31` and performs at most one forced
direct commit. Repeated lifecycle sweeps converge across later bounded passes.
Recovery is linear in referenced structural bytes and post-checkpoint
changes. The shared resident projection remains `O(M + W)` under the existing
index cap.

## Segmented signing format primitives

Increment 4 introduced the package-internal version-one format primitives that
Increment 9 subsequently wired into the production segmented metadata ledger.
This is a clean pre-release format: there is no legacy decoder, migration,
downgrade, or rollback path. The WAL container, WAL frame, transaction payload,
manifest, and checkpoint schemas are independently versioned and use big-endian
byte order. The production store root marker is currently v10; that root marker
is not a WAL codec version.

Each WAL file begins with a 64-byte container header containing magic, schema
version, reserved flags, nonnegative WAL identity, first sequence, baseline
committed revision, and a SHA-256
header integrity commitment. Frames use this canonical layout:

| Field | Bytes |
| --- | ---: |
| magic, version, header length, frame length | 12 |
| record type and reserved flags | 4 |
| sequence | 8 |
| transaction UUID | 16 |
| payload length | 4 |
| bounded payload | 0–2,097,152 |
| CRC32C over header and payload | 4 |

The complete structural frame enum retains the primitive `INTENT`, `MUTATION`,
`PROVIDER_RESULT`, and `TERMINAL` values and adds `ISSUE`, `COMMIT`, `REJECT`,
`ACK`, `WATERMARK`, and `BATCH_COMMIT`. The live segmented metadata engine emits
`ISSUE`, `COMMIT`, `REJECT`, `ACK`, and `WATERMARK` data frames. A transaction
payload inside those frames has one of `ISSUE`, `COMMIT`, `REJECT`, `ACK`,
`WATERMARK`, or `DIRECT_COMMIT`; `DIRECT_COMMIT` is a payload kind inside a
`COMMIT` frame, not a separate WAL frame type. Mutations are `CREATE`, `REPLACE`,
or `DELETE`. Retained outcomes, signing domain continuations, and domain
correlations are ordinary metadata keys and projections carried by commit
mutations rather than additional WAL record types. A commit or direct commit may
fold in the monotonic watermark instead of emitting a separate watermark frame.

A structural batch-commit marker follows each group of at most 32 data frames.
The complete encoded group, including its 184-byte marker, is also limited to
8 MiB, and the maximum wait from first admission is 2 ms. A caller transaction
contains at most 31 mutations and both its encoded payload and caller-content
budget are bounded to 2 MiB; encoding overhead means 2 MiB of caller values does
not necessarily fit. The active writer and metadata coordinator each bound
owned queued/in-flight admission to 256 entries and 64 MiB. There is no fixed
four-record grouping contract.

The marker's integrity-covered fields bind the group start/end sequence, frame
count, committed revision, prior rolling commitment, digest of the exact encoded
data frames plus marker core, and resulting rolling commitment. The production
writer appends all group frames and the marker, then issues one `force(true)`.
The marker uses the ordinary 44-byte frame header and four-byte CRC32C footer;
its 136-byte payload consists of a 40-byte marker core and three 32-byte
commitments.
The container baseline is the active-manifest baseline. The first marker must
advance beyond it, and every subsequent marker must strictly advance beyond the
previous committed revision. The stateless batch primitive therefore requires
the caller to supply the previous committed revision explicitly.

The scanner checks the container, CRC32C, contiguous order, marker fields, group
digest, and rolling commitment in one sequential pass. It buffers at most one
bounded group and invokes its consumer only after the complete marker validates;
a corrupt, torn, reordered, or falsely marked group is never partially applied.
A complete or partial suffix without a marker is an uncommitted active-WAL tail.
The same suffix in a sealed WAL fails closed. Production recovery truncates and
forces only a validated active uncommitted suffix after every referenced artifact
has passed read-only validation. It never truncates a sealed WAL, and it publishes
no partial recovered state. This removes a separate full-file committed-prefix
hash pass and places recovery validation at `O(bytes)` sequential work.

The manifest carries its own SHA-256 commitment and names exactly one optional
checkpoint, at most 4,096 ordered sealed segments, and exactly one active WAL
generation baseline. Every immutable descriptor carries its byte length and
SHA-256 commitment; checkpoint and sealed descriptors also carry explicit
generation identities, and identities are unique across every referenced
artifact. The active descriptor commits only its initial container,
identity, first sequence, and baseline revision. Normal group commits do not
rewrite or publish the manifest; manifest publication is reserved for WAL
creation/rotation, sealing, and checkpoint generation. Names are strict
lowercase canonical names derived from identities and ranges. Checkpoint,
sealed-segment, and generation ranges must be contiguous and non-overlapping.

The immutable checkpoint has a 44-byte header containing its explicit generation
identity, revision, covered sequence, entry count, and checkpoint-data offset,
plus a 32-byte whole-file SHA-256 footer. Entries are strictly ordered by unsigned
bytes of their canonical UTF-8 metadata keys. Each index descriptor contains the
key, closed record type, checkpoint-local frame offset and length, original
logical revision, and sequence. The data region contains the exact validated
encoded live WAL frames in the same order. A checkpoint is therefore
self-contained and current pointers recovered from it target the checkpoint
generation, not an older sealed WAL. Its reader and writer are thread-confined
and retain at most one bounded key, descriptor, and frame while tracking position
locally. A reader
must consume every entry or explicitly verify completion
before trusting the footer. The format does not contain a bloom filter or sparse
seek table.

Immutable files and manifests publish through an owner-controlled ledger
directory. Filesystem permissions and exclusive process ownership are the trust
boundary: CRC32C and unkeyed SHA-256 detect accidental corruption but do not
authenticate a malicious rewrite, recomputation, or rollback. Publication uses
an unpredictable same-directory temporary file opened atomically with
`CREATE_NEW` and no symbolic-link following, complete partial-write loops, file
identity revalidation, file force, mandatory atomic move (replace
only for the manifest), and parent-directory force. There is no non-atomic
fallback. Failure before the atomic move deletes the temporary file where
possible and leaves the target uncommitted. An ambiguous atomic-move failure, or
failure after the move and before or during directory force, reports a stable
durability-uncertain state; neither a possibly published target nor an ambiguous
temporary path is deleted, and rollback is not claimed. Diagnostics identify only the format
or publication stage and never include metadata keys, payloads, transaction
identities, providers, or paths.

Temporary-file identity checks apply only to immutable file and manifest
publication. They are not part of the production append/group-commit WAL hot path.
The design does not attempt to defend against an administrator who can mutate
the owner-controlled ledger directory while the process is running.

Operationally, every PKI ledger work root and report-output parent is exclusively
owned by the PKI process and is not writable by untrusted users or processes.
The PKI process must not run with elevated privileges over untrusted filesystem
paths. This is a deployment trust axiom, not an ancestor-realpath or
symlink-race defense.

Frame encoding, decoding, CRC, and rolling commitments are `O(bytes)` time.
Recovery retains one owned payload per not-yet-committed frame, bounded by 32
frames and the 2 MiB per-frame limit; it does not create a complete-frame copy.
Checkpoint traversal is `O(entries + bytes)` time with
`O(maxKeyBytes + fixedBufferBytes)` auxiliary memory.
Manifest encoding and validation are `O(segmentCount)` time and memory with
`segmentCount <= 4,096`.

## Resident MVCC and due-work indexes

Increment 5 introduced package-internal ownership and index primitives.
Increment 9 wired them into the production recovery engine, grouped writer, and
segmented metadata adapter.

The metadata primary index is a bounded hash map from `MetadataKey` to one
current immutable record pointer and revision. It retains generation identity,
frame offset and length, WAL sequence, record kind, and revision, but no record
payload and no historical version chain. Current point lookup is expected
`O(1)`. Each admitted key has one cached canonical ASCII representation shared
with an immutable persistent AVL range index; comparisons do not encode UTF-8
or allocate temporary key bytes. An update path-copies and rebalances
`O(log M)` AVL nodes. A snapshot therefore captures one root without cloning
`M` entries, and a range is `O(log M + R)`. Immutable roots, rather than a second
per-key history structure, retain the pointer values visible to live snapshots.

Recovery requires a checkpoint view already sorted in exact
canonical key order. It validates order, uniqueness, pointer bounds, revisions,
and committed-sequence bounds in one pass, then constructs an exactly balanced
AVL with `M` nodes and the final primary hash table in `O(M)` expected time. The
only traversal stack is `O(log M)`; the candidate table and nodes become the
installed state after generation ownership and byte capacity are acquired
atomically. Validation or admission failure publishes no state.

Snapshots pin one committed revision, one immutable root, and every referenced
generation. The index bounds current keys, live snapshots, and snapshot revision
span. A write that would cross a key, revision-span, or shared byte bound is
rejected before publication. Closing a snapshot releases its generation pins and
root reservation without an `O(M)` prune or scan. Each snapshot also captures the
current cumulative retained-node allocation watermark. One preallocated indexed
min-heap contains every live snapshot, including distinct entries with equal
watermarks, ordered by revision and then its monotonically correlated watermark.
Closing a snapshot releases the capacity delta up to the oldest remaining live
watermark, or all retained-node capacity when none remain. Heap maintenance is
`O(log L)` per snapshot open or close, oldest-revision and oldest-watermark lookup
are `O(1)`, and the preallocated heap uses `O(L)` scalar/reference memory without
per-open collection nodes. Updates retain their existing `O(log M)` path-copy cost
and keep no per-update history. Snapshot and index close operations are idempotent.
The index owner can close all outstanding snapshots. No finalizer or background
cleanup thread is used.

Generation lifecycle uses one short-held registry lock and explicit created,
published, superseded, and reclaiming states. Every current MVCC or due-work
pointer holds a counted current reference; snapshots and due selections hold
separate pins. Acquisition is all-or-nothing before state publication and rolls
back on failure. A superseded generation remains snapshot-pinnable while any
current pointer owns it. It becomes reclaimable only when both current references
and snapshot pins reach zero. Reclaimable identities are maintained incrementally
in an ordered set, so bounded deterministic claim is `O(D log G)`, not a scan of
lifetime registrations. Failed external deletion requeues the identity;
successful deletion removes its registry entry. This increment performs no
filesystem deletion.

The online-compaction correction Package 1 is complete as containment and exact
attribution, not as a repair of the publication race. Current references are
partitioned into the fixed internal owners `MVCC`, `DUE`, `OWNER`, and
`RECOVERY_TEMPORARY`; acquisition and release validate one exact owner atomically,
so a stale MVCC publication cannot consume another index's references. Registry
close rejects any remaining owner bucket or snapshot pin with safe owner/state
diagnostics. The counters add `O(1)` work per acquire/release and fixed primitive
memory per registered generation. A deterministic test-only identifier reproduces
the stale prepared-apply sequence without adding any production field, branch,
log, persistence, or API. The same package bounds prepared plus admitted-but-not-
projected WAL lifecycle slots by the configured WAL queue capacity. Packages 2–4
must fix and verify the online relocation/publication race before another signing
performance benchmark is run.

Online-compaction correction Package 2 supplies the bounded committed-prefix
foundation only. The active writer atomically publishes an immutable forced-end
offset/sequence/revision/commitment tuple after a successful force. A reader starts
from a previously accepted lower-exclusive tuple, never reads beyond the captured
forced end, validates complete groups, exact sequence/revision continuity, and the
commitment chain, and applies only revisions newer than its candidate and no newer
than the published MVCC revision. A group whose forced end is ahead of projection
does not advance the accepted start; a later reread skips candidate revisions and
applies the newly projected suffix once. A drained result explicitly proves forced
and projected endpoint equality. Time is `O(B_new + B_group)`, where `B_new` is
newly accepted prefix bytes and `B_group` is at most one existing bounded group;
auxiliary memory remains bounded by existing group/batch limits and is independent
of workflow population. Package 2 changes no persistent format and is not the
detached candidate or cutover integration. The benchmark remains prohibited until
Packages 3 and 4 are complete and independently verified.

Online-compaction correction Package 3 supplies the detached MVCC relocation
candidate and the prevalidated root-swap seam. Candidate construction walks one
immutable snapshot after conservatively reserving its complete footprint, builds
an independent hash/AVL root directly without an `O(M)` staging list, with its
own MVCC generation counts, revision, sequence, and commitment, and never changes the
live MVCC root or the DUE/OWNER indexes. Catch-up consumes only Package 2's
bounded committed-prefix reader. An authoritative full accepted descriptor
anchors each next scan to the prior accepted endpoint; each validated group is
applied as one detached batch, advances the cursor only after success, and copies
the generation-count map once. A short rollback token rejects a live
`PreparedApply` or endpoint mismatch
before publication; its final root/scalar assignment is allocation- and I/O-free
and `O(1)`, while token close performs displaced MVCC-count cleanup outside that
critical section. Build is `O(M)` time and `O(M)` candidate memory after
pre-reservation. Catch-up is `O(B_new + U log M + groups*G)` time, with bounded
one-incomplete-group reread and auxiliary memory limited by the existing WAL
group plus candidate MVCC state. Publication is `O(1)`, allocation- and I/O-free.
Package 3 does not alter maintenance,
manifest publication, supersession, reclamation, or persistent formats. Package
4 integration and independent verification remain mandatory, so benchmark
execution remains prohibited.

Online-compaction correction Package 4 is integrated in the maintenance path.
Candidate checkpoint construction runs after rotation has reopened admission;
authoritative-prefix catch-up is incremental. Once the remaining forced tail is
within the existing active-WAL queue capacity `Q`, the existing admission gate
closes, lifecycle ownership drains to zero, and final replay is hard-bounded to
at most `2Q` frames. Durable ordering is checkpoint candidate, manifest force,
allocation-/I/O-free MVCC root swap, generation supersession, then gate release.
Every failure before manifest force leaves the old manifest authoritative; every
failure after it requires restart under the new manifest, with no premature
supersession or reclaim. DUE/OWNER are never relocated. Final gate work is `O(Q)`
and publication is `O(1)`.

The completed A1/A1-G capacity correction gives every ledger two independent,
configurable resident envelopes. The steady envelope owns all live MVCC, DUE,
OWNER, retention, projection, and snapshot state; its default is 512 MiB and
ordinary request processing never reserves the transient envelope. The transient
envelope is used exclusively by the detached compaction candidate and catch-up;
its default is also 512 MiB. The checked default combined envelope is therefore
1 GiB. Candidate construction reserves its initial transient footprint before
rotation or candidate-specific checkpoint, generation, artifact, or manifest
effects; a failed initial preflight therefore leaves topology and generation
identity unchanged. Later catch-up exhaustion and an external live snapshot are
typed controlled deferrals: candidate state is closed and removed, any already
successful rotation remains authoritative, and the store does not enter
recovery-required state.

Immediately before manifest publication, a separate engine-owned,
package-private reservation-capture gate closes only for final cutover. It does
not block readers during candidate construction or catch-up. Snapshot, current-
range, due-page, and owner-page capture waits during that final window; signing
admission remains nonblocking and returns the existing retryable capacity result.
Each capture token is released as soon as its reservations and generation pins
are installed, not when the returned resource is later closed. The gate holds no
mutex across manifest I/O, while releases and non-reserving reads continue. The
capacity cutover permit has no admission responsibility: it retains only exact
atomic accounting validation and `O(1)` transient-to-steady reclassification
under the fixed steady-then-transient budget-lock order. Every success and
rollback path releases the gate and permit exactly once. A deferred pass is not
polled or retried by an unrelated commit: only a release from the blocking
budget or the last external snapshot close supplies its one-shot wake. An atomic
release epoch closes the failure-to-registration race. The request-path cost
outside the short final-cutover window remains one existing steady reservation,
with no transient-budget branch or allocation.

WAL-headroom correction H1 reserves the exact conservative singleton encoded
cost for every outstanding request before assigning sequence/revision state.
H2 maps an exhausted segment to the existing retryable capacity result and
records sticky coordinator pressure. Such pressure bypasses the ordinary
64 MiB trigger even for a smaller configured segment; it is consumed only
after successful rotation/compaction, while a concurrent pressure signal is
retained for another pass. Admission and signaling are `O(1)` time and `O(1)`
state and introduce no population-proportional memory.

The completed post-accept terminal-persistence correction uses bounded Variant
A. A local result that encounters known pre-admission WAL-headroom
exhaustion is retained in at most one `SUSPENDED_TERMINAL` slot per signing lane,
while the provider worker is released. The existing maintenance-epoch wake
reschedules terminal persistence with priority before ordinary admission. This
adds no thread, polling loop, persistent format, public API, or result capacity
proportional to the ready queue. Suspend/resume is `O(1)`, the rare wake is
`O(L)`, and retained result memory is `O(L * S)`.

The final runtime uses no attachment registry or terminal reference count. One
opaque token isolates each store, all worker handoffs use one slot-reserving
path, and three intrusive ready partitions share the original configured
capacity with `O(1)` selection. Normal execution is `O(1)` with no additional
persistent I/O, polling, or worker wait. Attached close is a bounded lifecycle
operation with accepted worst-case `O(L^2)` worker inspections for `L <= 256`.
Focused validation and independent correctness, security, and performance
reviews pass.

Deterministic correction verification R3a–R3d is complete. Real WAL pressure
covers successful suspended-terminal restoration, attached close before
restoration, Variant-A restart to `FAILED / RECOVERY_INCOMPLETE` without
repeated cryptography, and safe application/administrative HTTP uncertainty
classification. The complete `pki` and `pki-server` test suites and both
production PMD gates pass. Test-source PMD remains an existing unbaselined
repository report with 6,893 findings and is outside this correction.

Durable terminal-result staging (Variant C) remains a resilience backlog item.
It may later preserve computed results across a process crash during WAL
pressure, but would add persistent state, recovery ownership, I/O, and a
durability round. The backlog records the opportunity only; implementation is
not authorized without a separate architecture, format, and performance
decision.

The signing due-work index contains every non-retired operation that may still
need reconciliation or terminal cleanup. A boundary factory validates and
encodes each operation identity once; the same canonical object is then reused
for updates, removal, and retirement. A hash map owns exact replacement while a
tree ordered by `(nextEligibleAt, canonicalOperationId)` provides `O(log W)`
insertion, update, and removal and `O(log W + D)` bounded selection through a
cutoff. A returned selection is immutable and closeable: until close it pins all
referenced generations and reserves its descriptor memory. The index contains no
payload, cannot accumulate duplicate or stale ordering keys, and rejects a new
entry before crossing its configured count or byte capacity.

The metadata index, due-work index, snapshots, and due selections share the
steady atomic conservative resident-byte budget. The approved 4 GiB tier
hard-caps that budget by default at 512 MiB, `M` at 1,000,000, and `W` at
100,000.
Alternative positive ceilings are explicit per-store configuration and require
their own measured capacity-tier approval. Estimates include
canonical identity bytes and conservative fixed allowances for hash tables,
tree nodes, pointers, descriptors, roots, and selections. They are stable
admission reservations, not a claim of exact JVM retained heap. Long identities
can exhaust the byte budget before the count bound; representative identities
are characterized at the combined approved tier.

Each index lock is outermost for operations on that index. Snapshot close also
takes its handle lock before releasing pins. The capacity and generation
registry locks are short-held, independent, never call back into an index or one
another, and execute no caller callback. Snapshot reads use only the handle read
lock, so concurrent close cannot release generation pins during a read.

Both indexes expose counts, canonical-byte totals, structural allocation counts,
a proof counter that remains zero for full-map copies, and their conservative
reserved-byte estimates. Normal tests exercise 10,000-key/work populations and
deterministic byte-limit boundaries. The combined one-million-key and
100,000-work retained-heap characterization is explicitly opt-in because it
creates the full approved tier and performs controlled garbage collection:

The signing macrobenchmark accepts two non-grid resource parameters:
`residentIndexBudgetBytes` (Gradle property
`signingBenchmarkResidentIndexBudgetBytes`) and
`compactionTransientBudgetBytes` (Gradle property
`signingBenchmarkCompactionTransientBudgetBytes`). Both default to 512 MiB and
are included in validation, the arguments fingerprint, and success/failure
configuration. They are fixed parameters, not grid axes. The post-drain report
contains separate steady and transient current/lifetime-high-water/maximum/
headroom values and checked combined values; the combined high-water is the
conservative sum of the two independently observed high-water values. A
non-default value is diagnostic and makes an acceptance-profile result
explicitly non-evaluable.

```bash
ZEROECHO_SIGNING_INDEX_CAPACITY=1000000 \
  ./gradlew :pki:signingPerformanceSmoke \
  --tests zeroecho.pki.impl.fs.SigningIndexCapacityCharacterizationTest
```

Identity-ordered due paging has a separate deterministic, explicitly opt-in
100,000-work characterization. It records and bounds node visits for clustered
and evenly scattered due identities at page sizes 1, 64, 1,024, and 4,096:

```bash
ZEROECHO_SIGNING_DUE_INDEX_CHARACTERIZATION=100000 \
  ./gradlew :pki:signingPerformanceSmoke \
  --tests zeroecho.pki.impl.fs.SigningDueWorkIndexCharacterizationTest
```

This is structural regression evidence against a linear retained-work scan. It
does not establish latency, throughput, allocation, or writer-delay acceptance;
those verdicts remain Increment 13 work.

An MVCC update is `O(log M)` time and allocation, with expected `O(1)` current
point lookup. Snapshot capture and close are `O(G)` for referenced generations,
not `O(M)`. Recovery is expected `O(M)` time with `O(log M)` traversal stack in
addition to the state being installed. Resident state is `O(M + W + N + D)`,
where `N` is the bounded set of AVL nodes retained by live snapshot roots and
`D` is the bounded population held by live due selections. Eligibility-ordered
`selectThrough` selection is `O(log W + D)` time. Identity-ordered reconciliation
paging uses the effective nonempty-index `D` defined above and has worst-case
`Theta(log W + D + D log(W / D))` time. It returns `O(D)` immutable memory and
uses `O(D + log W)` total auxiliary memory; an empty index is constant. The
eligibility-ordered selection also returns `O(D)` immutable memory.

## Active WAL group commit

Increment 6 introduced the package-internal active-WAL lifecycle and group-commit
writer. Increment 9 connected it to manifest-selected recovery and the production
segmented metadata store. A new v1 WAL is created with `CREATE_NEW`, forced, and
followed by a parent-directory force. Opening an existing WAL validates its exact
container identity and scans every committed group. Only a suffix classified by
the v1 scanner as an incomplete active group is truncated and forced before the
writer accepts work. Committed corruption or a descriptor mismatch fails closed.

One lifecycle-owned thread exclusively owns the channel position, sequence,
revision, rolling commitment, append, and force operations. Submitters copy the
payload once and transfer that copy into an admission queue capped at 256 entries
and a configured byte bound. Slot and byte ownership is reserved before the copy,
so a known-full writer rejects without allocating an acknowledgement or copying
up to 2 MiB. The copy occurs outside the admission lock; close or copy failure
rolls the reservation back. The capacity covers reserved, queued, and in-flight
payloads. A full or unavailable writer rejects without
admission; there is no caller-runs path, executor backlog, callback registry, or
manifest publication on commit. Cancelling an acknowledgement after admission
does not cancel the durable mutation.

The writer assigns consecutive sequences and consecutive committed revisions in
admission order from the restored baseline. A group contains at most 32 frames
and closes when full or 2 ms after its first request. Duplicate transaction IDs,
revision/sequence overflow, and configured encoded-byte overflow are rejected
before append. One batch marker and exactly one commit force cover a successful
group. Each immutable acknowledgement contains its frame sequence, assigned
revision, frame offset and length, durable group-end offset, and rolling
commitment, and completes only after that force succeeds.
Acknowledgements implement only the bounded `Future` handle contract; they do
not expose completion-stage callbacks, so the sole writer only records completion
state and signals waiters and can never execute caller code.

Any write, no-progress, partial-append, encoding, or force failure after append
starts permanently moves the writer to `RECOVERY_REQUIRED`. In-flight requests
receive a durability-uncertain outcome; queued work that was not started receives
a distinct not-attempted outcome. The writer does not rewind, truncate, or retry
after such a failure. Diagnostics expose only stable stages and outcomes, never
paths, payloads, transaction IDs, or provider details. Orderly close stops
admission, drains admitted work, performs a final force, and then closes the
channel without racing the writer. Close is idempotent.
There is no extra orderly-close force: creation already forces the container and
each admitted group is forced before acknowledgement, so another force would add
latency without making additional bytes durable.

The opt-in active-WAL characterization uses the real package-internal writer,
1 KiB payloads, absolute monotonic open-loop arrivals, and a maximum 1,100/s
schedule. It reports acknowledgement latency from scheduled origin at p50/p95/p99,
rejection and maximum backlog, group size and wait/write/force time, bytes,
submission-thread allocation, heap growth, and GC. The normal performance smoke
uses fake force only to verify the report and bounded topology. A short real
filesystem diagnostic is:

```bash
./gradlew :pki:signingActiveWalBenchmark \
  -PsigningActiveWalBenchmarkWarmupSeconds=2 \
  -PsigningActiveWalBenchmarkDurationSeconds=10 \
  -PsigningActiveWalBenchmarkRate=1100
```

The Increment 13 native acceptance run is exactly 30 seconds of warm-up and
300 seconds of measurement at 1,100/s:

```bash
./gradlew :pki:signingActiveWalBenchmark \
  -PsigningActiveWalBenchmarkWarmupSeconds=30 \
  -PsigningActiveWalBenchmarkDurationSeconds=300 \
  -PsigningActiveWalBenchmarkRate=1100 \
  -PsigningActiveWalBenchmarkHeap=4g \
  -PsigningActiveWalBenchmarkOutput=build/reports/signing-performance/active-wal-native.json
```

The active writer is production-wired; the five-minute command remains an
Increment 13 acceptance gate because its complete reference-environment and
capacity verdict has not yet been executed.

Admission is `O(P)` time for the single payload copy plus `O(1)` queue work.
Group validation, encoding, and append are `O(B)` for encoded group bytes, with
one force per group. Resident auxiliary memory is `O(Q + B)`, where `Q` is the
bounded queued payload population and `B` is at most 32 bounded frames. No cost
depends on the total metadata or due-work population.

## Manifest-directed recovery

Increment 7 introduced the package-internal recovery owner, which Increment 9
wired into the production metadata store. A clean root is identified by a small canonical `FORMAT`
file that is created only by an explicit empty-root initializer and forced before
use. Recovery never treats a missing manifest as an empty store and never opens a
legacy or unsupported reader. The manifest target is the sole publication
authority; a newer-looking unreferenced file cannot supersede it.

Checkpoint and sealed-WAL manifest descriptors carry explicit nonnegative
generation identities. The checkpoint header binds its identity through the
checkpoint commitment, each sealed descriptor identity must equal its WAL
container identity, and the manifest rejects identity collisions across the
checkpoint, sealed WALs, and active WAL. This is a clean pre-release v1 format
correction: no earlier image is accepted, migrated, downgraded, or rewritten.

Recovery first performs bounded, `NOFOLLOW` enumeration of immediate root
entries and builds one bounded name index. It validates the format marker and
committed manifest, then verifies every referenced file's canonical name, type,
length, identity, range, baseline, and format version. Checkpoint and sealed-WAL
SHA-256 commitments are verified during their single sequential pass; the active
descriptor commits only its container header, while its committed groups are
authenticated by the frame, marker, group, and rolling commitments. The
checkpoint and WAL readers use 16 KiB transfer buffers instead of a channel read
or seek for every entry or frame.

A checkpoint is self-contained. Recovery validates each indexed frame directly
from its checkpoint-local offset and requires exact length, record type, sequence,
revision bound, contiguous data layout, and whole-file commitment. No external
pointer-join map or retained source WAL is required. The first retained sealed
segment begins at `checkpoint.coveredSequence + 1`; recovery applies checkpoint
entries first, then manifest-ordered sealed suffix mutations, then active-WAL
groups. Sequence or revision gaps, duplicates, or regressions fail closed. The
WAL scanner retains at most one 32-frame committed
group and exposes its payload through a package-private, read-only view whose
lifetime is the recovery callback; sinks must not retain that view. The public
frame payload accessor remains defensive. A transactional sink candidate stays
unpublished until all validation completes.

After validating authoritative names, types, sizes, and headers, recovery
registers and pins the manifest's exact generation set before classifying any
orphan. It rolls those registrations and pins back on every later failure. Full
checkpoint/sealed/active replay validation and orphan classification must all
succeed before the recovered state is prepared. Recovery then rechecks the
active file's size and container identity.
The sole recovery mutation is truncation of a scanner-proven unmarked active
suffix, followed immediately by an active-WAL force. A full malformed frame or
corruption in any committed prefix fails closed and is never truncated. A
truncate or force failure is reported as durability-uncertain. The recovered
state is published only after a ready active writer is owned; closing the
recovery handle drains the writer, closes the recovered state, releases all
generation pins, and is idempotent.

Orphan handling is classification-only. Exact publisher temporary names are
safe stale temporaries. A strictly named unreferenced checkpoint, sealed WAL, or
active WAL must have the expected regular-file type, bounded size, and matching
header fields before it appears as a deferred cleanup candidate. Recovery never
hashes or scans the arbitrary body of an unreferenced artifact and never
promotes one. Full validation and identity recheck belong to the later cleanup
owner. Unknown names, symbolic links, directories, type mismatches, malformed
known headers, or a root-entry bound overflow fail recovery without deletion.
Referenced files never appear as cleanup candidates.

Recovery takes `O(E + U log U + C + R + A)` time: `E` is the bounded immediate
root-entry count, `U` the returned orphan count, `C` checkpoint bytes, `R`
manifest-referenced sealed-WAL bytes, and `A` active-WAL bytes. Orphan content
does not contribute; startup reads at most one bounded header buffer per known
orphan. Auxiliary recovery memory is `O(E + S + maxFrame + B)`, where
`S <= 4,096` and `B <= 32`; there is no `O(M)` checkpoint-pointer join. Payload
bytes are callback-scoped rather than cloned or retained across history. The
active pass does not calculate an unused whole-file SHA-256, and none of this
affects the per-signature path.

## Cold sealing, iceberg compaction, and reclamation

Increment 8 introduced package-owned maintenance, which Increment 9 wired into
production. Rotation stops
admission and drains the active writer only for the bounded cold-seal handoff,
validates the closed WAL as a complete committed image, enforces the configured
256 MiB default maximum active-segment size before append, and atomically
publishes the immutable cold name as a same-directory hard link to the already
forced active inode. Normal rotation therefore reads and copies zero WAL bytes;
it creates and forces the next active WAL and publishes the new manifest last.
The writer-maintained final length and commitment are carried into the descriptor
without rereading the normal rotation image. The production filesystem adapter
keeps the active and sealed paths on the same filesystem and requires hard-link
support.
A failure whose publication state is ambiguous requires
manifest-directed recovery; exact already-published retry artifacts are adopted
only after full identity, length, and commitment validation.

Compaction rotates to a stable boundary, pins the exact MVCC snapshot before
exposing the next active writer, then resumes admission while it builds a
self-contained checkpoint in metadata-key semantic order. Its manifest retains
only post-boundary sealed suffixes plus the current active WAL. After durable
manifest publication it registers the checkpoint generation and performs one
linear sorted merge/rebuild: current entries that still equal their boundary
value receive checkpoint-local physical pointers, while newer updates and
deletes remain untouched. Logical revision and sequence never change. Retention
does not infer expiry during compaction: a record disappears only through its
ordinary durable delete mutation, and compaction copies the exact live snapshot.

An exact owner-created artifact catalog maps generation identities to the paths
eligible for reclamation. The registry claims only superseded generations with
zero current references and zero snapshot pins. Before deletion, maintenance
revalidates canonical ownership, regular-file type, no-follow behavior, and the
embedded generation identity. Completion occurs only after deleting the whole
claimed batch and one parent-directory force; failure requeues the batch.
Reclamation of `D`
claimed generations is `O(D log G)` registry work plus bytes needed to validate
bounded headers. Checkpoint construction is `O(M + liveBytes)` time with a
bounded 4,096-entry/64 MiB generation-local source batch plus the maximum frame
and fixed transfer buffers. A compaction-wide configured generation limit
(default 64) keeps each source channel open once, so opens are `O(G)` and file
descriptors remain bounded. Physical relocation is an `O(M + G)` transactional
sorted rebuild: it constructs only the replacement immutable AVL nodes,
pre-acquires aggregate generation references, replaces values in the existing
primary hash table, and publishes the root. The duplicate-node reservation is
64 bytes per live key while a boundary snapshot retains the old root; it is
released when the final snapshot closes. No second primary map is allocated.

Package 13.3b4 replaces the synthetic recovery generator with a controlled image
derived from `SigningPopulationFixture`. Prepare-only creates a real `M/W`
production-ledger population, performs one valid state-preserving generic
`REPLACE`, compacts through the real maintenance path to a checkpoint containing
exactly `M` current keys, and appends exactly `F` state-preserving `REPLACE`
frames partitioned deterministically across exactly `S` nonempty sealed segments.
The bounds are `1 <= S <= 4096` and `S <= F <= 1,000,000`; reference/default
`F=S`. There is no additional replay-volume axis.

Prepare-only publishes an immutable descriptor containing exact configuration,
manifest and descriptor fingerprints, and `synthetic=false` provenance.
The canonical descriptor is capped at exactly 334 ASCII bytes before allocation:
eight `name=value\n` lines comprising the schema, bounded `M/W/S/F` decimal
fields, the longest Boolean spelling, and two 64-character SHA-256 values. It
contains no path. Manifest reads use the codec's exact schema maximum instead
of the artifact-format 1 TiB ceiling. Work and report paths remain subject to
the trusted, exclusively owned reference-Linux deployment contract described
above.
Recover-only in a fresh JVM validates it before timing only
`SegmentedTransactionalMetadataStore.open(metadataRoot)`. Capacity, recovery,
artifact-byte, heap, live-caller allocation, and GC evidence is captured outside
that interval and comes from that same open recovery; no second recovery fold is
performed. Used-heap delta is not retained-heap attribution, caller-thread
allocation excludes allocations by other threads, and GC counters are
process-global. Exact gates require checkpoint entries `M`, sealed suffix `S/F`,
an empty active WAL, current keys `M`, due/owner/projection counts `W`, zero
retention and snapshot pins, and no orphan artifacts. The authoritative measured
generation-reference total must equal checked `M+2W`; the logical expected
breakdown `primaryMvccReferences=M`, `dueReferences=W`, and `ownerReferences=W`
is explicitly accounting rather than new per-index instrumentation.

This is the owner-imposed recovery benchmark scope ceiling: it does not reopen
`FilesystemPkiStore`, add production instrumentation, introduce another replay
axis or optional topology, define a latency threshold, or produce an acceptance
verdict. Work is `O(M log M + W log W + F + S)` for the current indexed replay;
configurations with absent indexed populations reduce the corresponding term.
Installed state is `O(M+W)`, and existing production auxiliary memory is
`O(M+W+S+B)` without an `S*W` structure. Ordinary tests use
only `M<=1000`, `W<=10`, and `S=F<=4`.

```bash
./gradlew :pki:signingRecoveryBenchmark \
  -PsigningRecoveryBenchmarkMode=prepare-only \
  -PsigningRecoveryBenchmarkRetainedPopulation=1000000 \
  -PsigningRecoveryBenchmarkActivePopulation=100000 \
  -PsigningRecoveryBenchmarkSealedSegments=4096 \
  -PsigningRecoveryBenchmarkSuffixFrames=4096 \
  -PsigningRecoveryBenchmarkWorkRoot=/absolute/empty/recovery-fixture


./gradlew :pki:signingRecoveryBenchmark \
  -PsigningRecoveryBenchmarkMode=recover-only \
  -PsigningRecoveryBenchmarkRetainedPopulation=1000000 \
  -PsigningRecoveryBenchmarkActivePopulation=100000 \
  -PsigningRecoveryBenchmarkSealedSegments=4096 \
  -PsigningRecoveryBenchmarkSuffixFrames=4096 \
  -PsigningRecoveryBenchmarkWorkRoot=/absolute/empty/recovery-fixture \
  -PsigningRecoveryBenchmarkOutput=/trusted/report-parent/recovery.json
```

The work root and report parent obey the approved trusted, exclusively
PKI-process-owned path axiom. Never run the benchmark privileged over untrusted
paths. Prepare requires an absent root and never overwrites or deletes it;
recover-only leaves the prepared image unchanged. Output is lexically outside
the work root and the report leaf is opened without following a symbolic link.

## Complexity and memory

### Production metadata ledger (Increment 9)

Filesystem stores now create only the v10 segmented metadata layout under
`metadata/`: `FORMAT`, a manifest, optional checkpoint and sealed segments, and
one active WAL. There is no legacy reader or migration path. Any incompatible prior root, the old
`transactions.log`, a missing or unsupported format/manifest, symbolic links,
mixed layouts, and unknown artifacts are rejected before metadata mutation with
a stable redacted format-unsupported result.

One versioned transaction payload contains at most 31 caller mutations and is
capped at 2 MiB, preserving the exact 1 MiB signature-result contract plus its
signing-record envelope. Its containing encoded data frame may be up to
2,097,200 bytes. Structural `ISSUE`, `COMMIT`, `REJECT`, `ACK`, and `WATERMARK`
frames are group committed through the bounded 256-entry, 64-MiB payload writer;
`DIRECT_COMMIT` is a transaction-payload kind inside a `COMMIT` frame. Retained
outcomes are metadata keys/projections rather than transaction-payload fields.
Groups contain at most 32 frames, at most 8 MiB encoded including the marker,
and wait at most 2 ms. A valid large transaction is isolated when the next frame
would exceed the group byte cap. Coordinator admission separately reserves the
encoded frame, its WAL-owned copy, plus retained caller values before encoding, so detached values
cannot bypass the 64 MiB bound. Distinct mutations in
one transaction share one sequence and revision. Outcomes remain resolvable
until acknowledgement; ordinary filesystem-store operations durably acknowledge
known results, while recovery closes an incomplete durable issuance as
`ABANDONED_BY_RECOVERY`.

A `DIRECT_COMMIT` contains 1–31 mutations with distinct canonical keys. A delete
uses content length exactly `-1`; create and replace use a non-negative content
length. Its folded watermark is exactly `-1` when absent or a non-negative epoch
millisecond when present. Encoding, decoding, and recovery reject every other
shape. Direct commits validate preconditions in WAL-admission order against both
published and earlier prepared state, so overlapping keys cannot pass validation
concurrently; a failure after admission makes the writer recovery-required.

Each durability acknowledgement resolves the offset/length slot of an immutable
logical frame pointer after the WAL force. MVCC, due, retention, malformed, and
live-owner changes reserve their hash/AVL slots, shared capacity, and generation
ownership before WAL admission; post-force publication performs no validation or
capacity allocation. Rotation waits only for already acknowledged frames to be
projected, then reopens admission on the new active WAL before checkpoint copying
and relocation.

Current lookup is expected `O(1)`. Commit preparation is `O(P + K log M)` plus
ordered signing/retention projection updates, where `P` is payload bytes and
`K <= 31`. Range reads are `O(log M + R)`. Identity-ordered due paging has
worst-case `Theta(log W + D + D log(W / D))` time, `O(D)` returned immutable
memory, and `O(D + log W)` total auxiliary memory for the effective nonempty
`D` defined above; an empty index is constant. An augmented AVL stores each
subtree's minimum eligibility, so paging avoids a linear scan of non-due
retained records. Retention purge and live-owner
recovery likewise use ordered projections rather than namespace-wide scans.
Recovery consumes live owners in bounded 4,096-record pages and resolves segment
identity with one monotonic `O(F + S)` pass over `F` frames and `S` segments.
Signing owner edges use the strict composite metadata key
`contentId:submissionId`, where `contentId` is the canonical 36-character
store-issued UUID and the suffix is a canonical signing-submission identifier.
Each serialized composite-key occurrence contains exactly 37 additional ASCII
bytes per live owner relative to the former submission-only shape; physical disk
amplification and history cost are measured separately. Because the MVCC
capacity model conservatively reserves both canonical key representations, this
is exactly 74 additional reserved bytes per live owner: 7,400,000 bytes at
`W = 100,000`, before JVM object overhead. No duplicate entry or index is
retained.
Current-record reads point-read the record, derive its exact content reference,
and then point-read the composite owner edge. An absent or content-free record
uses the existing operation-identity owner projection for an exact stale-edge
check. Reference-owner enumeration performs one current-index content-prefix
seek, captures and generation-pins only its `K` matching immutable pointers,
and performs record I/O after releasing the index lock. Its cost is
`O(log M + K)` time and `O(K)` returned memory. The retirement existence check
pins only the first matching pointer and costs `O(log M)` time and `O(1)`
auxiliary memory. All selection reservations and pins are released on every
failure path. Operation-lifecycle content never scans persisted
status-object owners. Recovery rejects submission-only owner keys; this
pre-release format has no legacy decoder or migration path.
Each retention invocation selects at most `B = 31` records and explicitly deletes
that batch in one direct commit and one force; it does not loop to exhaustion.
Its cost is `O(log W + B + B(log M + log W))`, and periodic lifecycle sweeps
naturally reschedule remaining eligible records. The signing-reconciliation
worker invokes exactly one such purge pass per admitted scheduled pass, including
when there is no active signing work, so an idle capacity-full store converges
without request traffic. MVCC, work indexes, snapshots, and projections share
the bounded 512 MiB resident-index
budget at the 4 GiB heap tier. Snapshot export pins one source MVCC revision and
streams one synthesized one-key frame per retained key into a fresh checkpoint,
then publishes an empty active WAL and the target manifest last; target-rebuilt status,
publication, and credential-serial namespaces remain excluded from raw copying.

Scheduling is `O(A)` time for `A` arrivals. Each accepted operation performs
`O(P)` payload work for payload length `P` plus the current persistence I/O.
Transient scheduler state is `O(lanes + queueCapacity)` and contains at most one
queued/active provider step per operation. Durable live/not-yet-retired workflow
state is independently store-owned and bounded by `W = 100,000`; pending durable
work consumes no scheduler slot. Each latency reservoir uses
`O(sampleCapacity)` primitive memory, independent of total arrivals; final
percentile calculation takes `O(S log S)` time and `O(S)` temporary memory for
`S <= sampleCapacity`. The legacy target retires terminal operations during the
run. The native smoke temporarily retains exactly three terminal operations to
prove scheduler/workflow independence and then retires them. Work-root cleanup
walks files in `O(F)` time and `O(depth)` auxiliary memory. The JSON report is
persisted before cleanup with a stable `CLEANUP_PENDING`, non-evaluable verdict.
A cleanup failure leaves the report available but replaces that verdict with
stable `CLEANUP_FAILED`; only successful cleanup may publish the workload
assessment. The native smoke is not the Increment 13 capacity or throughput
verdict.

## Bounded signing execution runtime (Increment 11)

Every configured signing session owns one `SigningExecutionRuntime`; server,
admin, ACME, OCSP, direct, CLI, and native-smoke entry paths share that runtime
through the session signing bus. `SigningConfiguration` schema version 4 adds
`laneCount`, `queueCapacity`, `gracefulDrain`, and `forcedCancellation`. The
reference defaults are 16 lanes, 64 ready entries, a 30-second graceful drain,
and a 10-second forced-cancellation wait. Supported bounds are 1–256 lanes,
0–65,535 ready entries, no more than 65,536 derived admissions, and 1 ms–10
minutes for each lifecycle duration.

New-arrival admission is a composite non-blocking expected-`O(1)` operation. It
reserves one exact transient initial-step slot and one store-owned durable-work
slot before staged content, submission identifiers, intent/WAL work, or provider
calls. Publication transfers durable ownership to the store; the initial-step
slot is released as soon as that provider step returns. Pending remote or approval
work therefore owns no scheduler slot between bounded submission, status,
cancellation, and retirement steps.
For signing-backed CA, issuance, and status work, the same transaction also
creates one bounded domain continuation under the same private `PkiId` in the
segmented ledger. It contains only the exact immutable command, commitments, and
content references needed to reconstruct and publish the outer result; it stores
no BC builder or resident workflow object. The foreground BC adapter takes at
most the initial step and one point observation. A pending result unwinds to the
typed application outcome, and realm reconciliation publishes the exact domain
result idempotently before atomically retiring signing ownership.
The same absolute deadline decides whether a signature may be accepted; no
second signing TTL is started at submission. A signature durably recorded before that deadline must
still publish its exact domain result: transient `PUBLISHING` failures retain
bounded durable ownership and use the persisted 2/4/8/16/30-second retry
schedule beyond the horizon until exact publication completes. A signature not
recorded by the deadline instead becomes content-free `EXPIRED`. Runtime and
callback memory is `O(lanes + queueCapacity)`.
Callbacks validate and coalesce identifiers in a bounded insertion-ordered set
independent of runtime operation membership. A prestarted notifier invokes the
wake listener outside scheduler/advisory locks; callbacks perform no provider/store
call. Missed, dropped, late, unknown, and restart-lost callbacks change latency
only.

The immutable runtime snapshot reports `schedulerReserved`, `running`, `ready`,
`pendingAdvisories`, `highWaterSchedulerReserved`, `schedulingRejected`, callback
coalesced/dropped/wake counters, and lifecycle state. Scheduler counters are
captured under the scheduler lock and advisory state under the advisory lock.

Shutdown transitions `OPEN -> QUIESCING -> DRAINING -> CLOSED`: admission stops,
unconsumed initial reservations and queued/active steps receive the configured
graceful interval, then are cancelled cooperatively before the forced wait. A
non-cooperative step yields stable `SIGNING_SHUTDOWN_TIMEOUT`; the runtime remains
retryably `DRAINING` and the session leaves workflow/store resources open until a
later close succeeds. This increment adds bounded smoke and deterministic
correctness coverage only. The five-minute/reference and million-scale capacity
verdict remain exclusively Increment 13.
