# Local process recovery and informational measurements

Run the opt-in gates from the repository root:

```sh
./gradlew :app:packagedLocalRecoveryTest --offline
./gradlew :app:localPerformanceTest --offline
```

Both tasks build the actual `app/build/install/app/bin/app` distribution. Ordinary
unit tests exclude these gates. They need the existing Java 25 toolchain and a
POSIX filesystem; no server, container engine, network, new dependency, or
production test hook is used. Each run retains private test directories and
process logs under `build/pki-validation/packaged-local-recovery` or
`build/pki-validation/local-performance`, including generated test keyrings. Child processes
have bounded failure timeouts and are terminated in `finally`.

The recovery fixture accepts a root operation using the existing public session,
then halts a separate JVM at one of two public durability boundaries. The first
uses `SigningStepExecutor`'s progress callback after `SUCCEEDED` is durable and
before the outer continuation publishes. The second halts after the public fenced
claim changes the workflow to `DISPATCHED`, before any provider call. Inspection
through the packaged CLI must preserve every mutable signing field, the outer
record, and the absence of a CA. Only explicit completion of the selected ID may
advance it. The lost-result case waits for its persisted lease eligibility and
must return policy-rejection exit 4 and `LOCAL_RESTART_UNRECOVERABLE` without a
signature or authority.

Successful completion retires the retained signature with exactly one revision
increment, preserves its fence, provider timestamp, stage and attempt phase, and
publishes a certificate whose JDK signature bytes equal the retained result and
whose self-signature verifies. Both scenarios compare the original keyring bytes after inspection and completion.
The keyring remains unchanged: its configuration
commitment includes entry metadata and ciphertext. This process test proves
retained-signature publication after a real halt. Deterministic RSA signature
equality alone cannot establish the number of provider calls. The independent
`LocalPkiSessionTest.durableSignatureResumesPublicationOnlyAfterExplicitEligibleCompletion`
regression supplies that evidence with a dispatch counter remaining exactly one
across reopening and explicit completion.

Measurements are informational, with no numerical performance requirement.
Three fresh JVMs use `-Xms128m -Xmx512m`; each generates one RSA-2048 pair shared by
its local and reactive modes, using separate fresh filesystem stores and the same
root profile. Each mode records five warmups and thirty serial root publications.
Mode order alternates between repetitions. Local timing covers the public local
executor through completed domain metadata. Reactive timing covers public
preparation, acceptance, repeated observation of outer `COMPLETED`, and completed
metadata projection. Its one-millisecond observation polling and scheduling
costs are included; raw samples retain the poll count. The reactor has one lane,
one prefetched identifier, page size one, ten-second claims, five-second provider
calls, ten-millisecond idle polling, and a five-second close timeout. Both modes
use the existing memory audit sink with capacity 128. This is a serial
end-to-end diagnostic, not a saturation or isolated cryptographic benchmark.

Separate rows record configuration parsing and session open/close. A third fresh
store records five warmup and thirty measured **whole packaged process**
`configuration.validate` invocations, including launcher, JVM, keyring unlock,
store open, output, and close. Startup samples are not added to in-process signing
latency. Raw CSV, runtime/OS/CPU information, and before/after heap, GC and thread
observations remain available per repetition. Heap and GC observations are not
allocation counts, peak-memory bounds, or measurements of retained workflow
memory. No forced GC is used. Each timed operation holds only one active request;
the store accumulates the completed warmup and measured authorities naturally.
