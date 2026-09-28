# ZeroEcho PKI Conformance Matrix

This matrix connects the current signing and administration contracts to executable
evidence. The library, server, frontend and CLI are integrated; historical delivery
checkpoints are not compatibility contracts. See the [validation record](pki-validation.md)
for the completed cross-module, static-analysis, documentation and deployment checks.

## Reactive runtime and persistence

A configured asynchronous session composes one bounded `SigningReactor`, one scanner, and one shared provider
when signing is configured, and exposes the privileged two-phase
`SigningService`. Version 6 contains the final topology configuration—disjoint
exact `KeyRef` groups plus a mandatory catch-all, with dedicated lanes and no
borrowing—and an optional pure-EdDSA full-CRL TBS byte limit. When absent, the
limit uses half of the maximum JVM heap as the aggregate pure-EdDSA buffer budget
and divides it conservatively across the configured lanes and SunEC buffering
amplification. An unconfigured session remains signing-threadless.

| Requirement | Current evidence | Contract |
| --- | --- | --- |
| Clean store format | `FilesystemPkiStoreTest.initializationCrashMatrixLeavesUnsupportedUnversionedRootWithoutRetryMutation`, noncanonical/oversized/old-version preflight tests | Current boundary: outer v18, `FsCodec` 11; no legacy reader or migration |
| Atomic signing acceptance | `FilesystemSignWorkflowStoreTest.acceptancePersistsSeparateImmutableEnvelopeIntentAndCandidateBindingAcrossRestart` | Retained: envelope + `INTENT` state + candidate binding + optional outer records in one transaction |
| Idempotent operation identity | `concurrentSameCommandAcceptsOnceAndAttachesAllRacersEvenAtCapacity`, `identityConflictAndAttachmentAreResolvedBeforeFullCapacity` | `ACCEPTED`, `ATTACHED_EXISTING`, `CONFLICT`, and `CAPACITY_REJECTED` are distinguished before provider work |
| Unique candidate custody | `concurrentCandidateClaimHasOneWinnerAndLoserNeverDeletesWinnerContent`, `malformedAcceptanceCannotReclaimCandidateWhileValidAcceptanceClaimsIt` | One candidate binds to at most one operation; definite loser cleanup cannot delete winner-owned bytes |
| Outer semantic integrity | `malformedOuterIsRejectedBeforeAcceptanceAndItsCandidateIsReclaimed`, `canonicalCommitmentValidOuterWithWrongKindIsRejectedAndReclaimed` | Encoding, commitment, canonical form, kind, and command schema are validated before acceptance |
| Outer-controlled lifecycle | `outerTerminalControlsCapacityReleaseAndAcceptancePublishesExactCorrelation`, `expiryAtomicallyTerminalizesRequiredOuterBeforeReleasingContentAndCapacity` | Required outer completion controls retirement, content reclamation, and slot release |
| Split immutable/mutable storage | `codecSeparatesEnvelopeStateAndBindingSchemas`, `cancellationReopenAndRetirementPreserveStatePointerAndIdentityBinding` | Later transitions replace state only; identity metadata and binding survive their required horizon |
| Strict staged publication | `FilesystemStagedContentStoreTest.strictSealCrashMatrixNeverExposesPartialCandidate` | Checked streaming length/digest, mandatory atomic publication, metadata-last, and fail-closed recovery |
| Shared preparation bound | `FilesystemStagedContentStoreTest.oneOpenSinkGateIsSharedAcrossCandidateLifecyclesAndReleasedByTerminalPaths` | One finite open-sink gate covers candidate lifecycles; exhaustion is preparation backpressure |
| WAL/index capacity and recovery | `SigningActiveWalTest`, `SigningDueWorkIndexTest`, `SigningLedgerCoordinatorCapacityTest`, `SigningWorkProjectionTest` | Durable work is bounded and recovered from authoritative store state |
| Soft usable-space observation | `SigningLedgerCoordinatorCapacityTest.usableSpaceProbeRunsOnlyOnMaintenanceCoordinator`, `softUsableSpaceObservationIsHystereticRateLimitedAndRedacted` | Observation is off admission threads and cannot alter acceptance results |
| Signing acceptance custody | `DefaultSigningServiceTest` | Preparation stages candidate bytes once; acceptance returns a durable recovery receipt and uncertainty resolves through the store |
| Final configuration | `PkiSessionConfigurationSigningTopologyTest.rejectsOversizedTopologyCollectionsBeforeTraversalCopyOrHashing`, `enforcesUtf8KeyReferenceBytesAtMultibyteAndSurrogateBoundaries` | Version 6 has no legacy runtime form; exact groups, group key lists, and UTF-8 key bytes are bounded before copy/hash/allocation, and aggregate lanes, prefetch, and page size are bounded |
| Derived scheduling projection | `SigningWorkProjectionTest.recoveryRetainsOnlyValidatedSchedulingCoordinates`, `FilesystemSignWorkflowStoreTest.recoveryStreamsMaximumEnvelopesIntoExactDueTuples`, `lightweightDuePagesPreserveCursorAndStableHighWatermark` | Due pages and validated recovery retain scheduling coordinates rather than envelopes; recovery decodes each envelope once and tracks at most one owned encoded-envelope workspace, not total heap |
| Fail-closed signing graph recovery | `SigningLedgerRecoveryTest.recoveryOwnershipAdvancesOnceThroughPassiveActivationAndExplicitStart`, recovery boundary fault tests, `FilesystemSignWorkflowStoreTest` graph-mismatch reopen tests | Read-only semantic validation precedes passive activation and cleanup; recovery forces synchronous writes, starts writer/threads last, and exposes malformed persistence as cause-free `STORE_FORMAT_UNSUPPORTED` while operational I/O remains causeful |
| Bounded topology runtime | `SigningReactorTest.routesExactAndCatchAllWithFixedDaemonThreadsAndRedactedNames`, `saturatedExactPoolDoesNotBorrowOrBlockCatchAll` | Exactly `1 + sum(L)` daemon threads, dedicated pools without borrowing, one provider, and `O(K + sum(P) + sum(L))` volatile metadata |
| Authority fairness | `AuthorityFairQueueTest.rotatesAuthoritiesAndPreservesPerAuthorityFifo`, `everyBufferedAuthorityProgressesWithinEachFiniteRound`, `SigningReactorTest.authorityRoundRobinPreservesPerAuthorityFifo` | Equal round-robin applies only among authorities in one bounded pool prefetch; FIFO is preserved within an authority and state resets on restart |
| Stable scanning and restart | `SigningReactorTest.stableCycleSkipsMalformedDrainsBacklogAndRestartFindsSkippedWork`, `saturatedRouteScansWithFixedPageQuantumUntilUnrelatedCapacityIsFilled`, `capacityBlockedScannerResumesItsStableCycleWhenLaneFreesSlot` | Stable cursor/high-watermark paging uses fixed configured quantum `Q`, advances past malformed and saturated-route entries, and a capacity signal resumes only the active cycle; later scans require external wake/acceptance or idle poll |
| Scheduling recheck | `SigningReactorTest.rechecksScheduledCoordinatesAndRouteBeforeClaim` | A lane point-loads and rechecks exact key, authority, and route before claim or provider work |
| Shutdown and acceptance | `SigningReactorTest.acceptanceGateRejectsNewWorkWhileAnAcceptedCallDrains`, `commonCloseDeadlineCanBeRetriedAfterBlockedProviderReturns` | Independent repeated scenarios prove that acceptance and claims close under one reactor lifecycle, the accepted call drains, one deadline applies across pools, and timeout remains retryable without cross-test durable or latch contamination |
| Outer terminal lifecycle | `SigningReactorTest.terminalOuterContinuationAdvancesBeforeRetirement`, `FilesystemSignWorkflowStoreTest.succeededOuterContinuationLocalFailureBackoffIsStrictAndDurable` | Outer-backed signing retires only after authoritative outer terminal state; local continuation failure is durably deferred |
| Reactive session boundary | `PkiSessionLifecycleTest.configuredTopologyRoutesExactAndUnmatchedKeysToDedicatedPools`, configured/unconfigured lifecycle tests | Configured sessions compose one provider/reactor/service; unconfigured sessions remain signing-threadless; invalid topology fails before allocation |
| Local and remote provider substrate | provider contract/configuration tests under `impl.crypto.zeroecholib` and `impl.crypto.remote` | `SigningProvider` implementations execute through the bounded topology reactor |

## Domain operations and recovery

| Capability | Evidence | Contract |
| --- | --- | --- |
| Full CRL publication | `FullCrlStreamingPublicationTest`, full-CRL recovery and export tests | Streaming staged-content adoption and publication; retained-signature replay, strict signed fields and completed lookup survive content retirement. |
| Metadata inspection and listings | `PkiOperationInspectionTest`, query listing tests | Explicit missing-object outcomes, bounded result windows, cancellation and authorization; listings preserve backend validation costs. |
| Authority compare-and-set | `AuthorityMetadataCompareAndSetTest` | Complete expected metadata and replacement share one snapshot/head; only a definite conflict maps to false; uncertain commit outcomes propagate. |
| Concurrent authority publication | `CaContinuationPublisherConcurrencyTest`, `IntermediateCreationRecoveryTest` | Losing publishers preserve the winner; replay retains later authority changes and does not generate another signature. |
| Durability failure classification | `PkiOperationInspectionTest` | Typed `STORE_DURABILITY_UNCONFIRMED` maps to redacted `RECOVERY_REQUIRED` without retry or message parsing. Other reasons retain the documented fallback. |
| Non-signing authority administration | `PkiOperationAdministrationTest` | State/selection/path updates preserve memberships, validate references and depth, and report CAS conflict without retry. |
| Root creation | `RootSigningPreparationTest`, `PkiSessionRootCreationTest` | Exact profile, subject principal, SPKI, validity and TBS are frozen before acceptance; signature verification precedes publication. |
| Intermediate creation and lifecycle | `IntermediateSigningPreparationTest`, `PkiSessionManagedKeyProofTest`, `IntermediateCreationRecoveryTest` | The accepted parent owns its internal subject-key proof and certificate stages; no caller-supplied proof operation or separate acceptance is required. |
| Root rollover and rotation | Root lifecycle preparation tests, `PkiSessionRootCreationTest` | The active profile version and authoritative principal are retained; current/replacement keys and publication rules remain distinct. |
| OCSP | OCSP unsigned encoding, initial-attempt, observation and response-service tests | Exact algorithm identity, bounded wait/observation, cancellation and strict response encoding share the signing runtime. |
| Internal proof durability | Managed-proof, signing-store and reactor tests | Recovery validates stage/candidate/binding correlation; verification and ready stages do not redispatch provider work. |
| Retained results and CSR | Semantic result-projection and retained-CSR tests | Completed identities derive from strict retained metadata; CSR snapshots are independently owned and identity-checked. |
| Delta CRL provenance | Snapshot-coordinate, revocation-prefix, signed-CRL and delta-integration tests | A selected full base and authoritative prefix are frozen before reservation; bounded snapshot filtering, signed base number and replay survive restart without reselection. |

The clean store boundary is version 18 with `FsCodec` version 11. Earlier store
markers have no compatibility reader. Authoritative state, candidate custody,
publication and recovery rules are described in the
[reactor architecture](pki-single-admission-reactor-architecture.md); payload,
index and recovery costs are described in the [performance reference](pki-signing-performance.md).
The [failure model](pki-failure-model.md) defines safe classification and redaction.

## Server, frontend and CLI

| Boundary | Evidence | Contract |
| --- | --- | --- |
| Server signing gateway | Server gateway, signing executor and operation codec tests | Permissions and canonical approvals precede semantic preparation and one durable acceptance; polling uses persisted scope. |
| ACME and public responses | ACME retained-binding, OCSP and public evidence tests | Effective retained bindings and owned CSR snapshots drive protocol adaptation; no additional signing queue or resource owner is introduced. |
| Known-value selection | [Selection API validation](../pki-frontend/docs/selection-api.md) | Authorized lists expose exact identities and readable labels; selection errors do not silently become free-text input. |
| Async web and remote CLI | [Packaged deployment gate](../pki-frontend/e2e/packaged/README.md) | Real mTLS, independent approval, scope enforcement, submit-once behavior and retained operation-ID observation. |
| Standalone synchronous CLI | [Local validation gates](../app/docs/local-validation.md) | Explicit configured operator, caller-thread signing, no backend/reactor, durable publication and explicit completion after process interruption. |

The [deployment and CLI contracts](pki-deployment-cli-contracts.md) define mode
boundaries, local administrative approval and exit codes. The
[validation record](pki-validation.md) contains current test totals and quality
results; [raw measurements](pki-signing-performance.md#recorded-serial-measurements--2026-09-28)
are informational and impose no numerical performance threshold.
