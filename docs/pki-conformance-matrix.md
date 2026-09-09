# ZeroEcho PKI Conformance Matrix

Traceable mapping from each retained security/architecture requirement to the
automated test(s) that exercise it, plus the build/CI gates and the small number
of justified manual release checks. This is the externally visible conformance
artifact for Task 14.

## How coverage is executed

- **Unit & integration tests** — run by `./gradlew build` (WSL, JDK 25). Every
  row below whose "Covering tests" cite `*.java` classes is executed there; the
  full build being green is the pass signal. Representative positive and negative
  method names are cited so a reviewer can trace requirement → scenario → code.
- **Build/CI gates** — architecture/packaging properties that are not unit-testable
  are enforced at build time (§2): JPMS modular compile, the BouncyCastle-confinement
  gate (`verifyBouncyCastleConfinement`, wired into `check`), the Java 25 toolchain,
  and thin-jar packaging.
- **Manual / large-machine release checks** — explicitly listed in §3 with their
  justification; only the frozen signing macrobenchmark falls here.

Test paths are under `<module>/src/test/java`. Notation: `ClassName#method`.

## §1 Requirement → test matrix

| # | Requirement area | Covering tests (representative) | Positive | Negative |
|---|------------------|--------------------------------|:--------:|:--------:|
| 1 | CSR / PKCS#10 parse + proof-of-possession | `BcX509CertificationRequestParserDerTest#acceptsOnlyExactSingleCsrPemObject`, `WorkflowProofOfPossessionVerifierTest#verifyRsaCsrViaWorkflow_ok`, `H7EndEntityCsrRejectionE2eTest` | ✅ | ✅ `#rejectsOversizeAndNonCanonicalDerBeforePkcs10Parsing`, `#mapsSuccessfulVerifiedFalseToSignatureInvalid` |
| 2 | End-entity issuance (profile-gated) | `CaProfileIssuanceEnforcementTest`, `H7ProfileEnforcementTest`, `H7EndEntityAcceptanceE2eTest` | ✅ | ✅ `#postconditionRejectsDuplicateEkuAndUnknownExtensions`, `#parserRejectsUnsupportedSubjectAndCsrExtensionShapes` |
| 3 | Intermediate CA issuance + cross-certification | `CaProfileIssuanceEnforcementTest#fixedSubjectIntermediateIsValidatedOnceAndPersistsCanonicalSubject`, `#generatedRootCanBeImportedAgainstTheSameActivatedProfile` | ✅ | ✅ `#rootCannotBeUsedAsAdditionalIntermediateSubject`, `#invalidRequestedIntermediateValidityFailsBeforeProof` |
| 4 | CA lifecycle: create / state / rollover / key rotation | `LifecycleOperationsE2eTest#rootRolloverMintsNewGenerationKeepsKeyAndAdvancesCurrentPointer`, `#rootKeyRotationAdoptsNewKeyAndAdvancesCurrentPointer`, `CaRecordTest` | ✅ | ✅ `#renewAndReissueRejectRevokedPredecessorWhileReplaceRecoversWithNewKey` |
| 5 | Credential lifecycle: renew / replace / reissue | `LifecycleOperationsE2eTest#replaceIssuesSuccessorLinksLineageAndSupersedesPredecessor`, `#renewKeepsSubjectAndKeyIssuesFreshValidityAndLeavesPredecessorValid`, `#reissueReproducesFromRecordAndSupersedesPredecessor` | ✅ | ✅ `#renewAndReissueRejectRevokedPredecessorWhileReplaceRecoversWithNewKey` |
| 6 | Issuance approvals / dual-control | `IssuanceApprovalGatewayTest#thresholdProfileGatesIssuanceUntilQuorumApprovesThenExecutesExactlyOnce`, `PkiSigningBusOperatorApprovalTest#approvalSurvivesRestartAndStillGatesIssuance` | ✅ | ✅ `#rejectedApprovalPreventsIssuance`, `#expiredApprovalPreventsIssuance` |
| 7 | Local signing (keyring / zeroecho-lib) | `ZeroEchoLibSignatureWorkflowPersistenceTest#binaryDerAndPemTransferOneEquivalentOwnedResultAndClearOnce`, `ZeroEchoLibSignatureWorkflowVerifyEncodedTest` | ✅ | ✅ `#signingMapsCanonicalInvalidMissingForeignAndMismatchedInputs`, `ZeroEchoLibSignatureWorkflowConfigurationCommitmentTest#configurationCommitmentMismatchIsRejectedBeforeContentOrCrypto` |
| 8 | Remote signing provider (mTLS-HTTPS) | `HttpsRemoteSigningTransportTest#signsEndToEndOverMutualTlsThroughTheTransport`, `RemoteSignatureWorkflowContractTest#submitsThroughToASignedResultAndConfinesKeys` | ✅ | ✅ `#conflictingResubmissionSurfacesAsIllegalState`, `#unknownOperationIsReportedDeniedNotThrown` |
| 9 | Per-CA signing routing | `PkiSigningBusRoutingTest#routesEachAuthorityKeyToItsConfiguredService`, `#defaultServiceHandlesUnmappedAuthorityKeys`, `PkiCliTest#configurationReadsPerCaSigningServicesAndRouting` | ✅ | ➖ default-fallback covered; no dedicated rejection case (see §4) |
| 10 | Revocation (permanent reasons; reject temporary/invalid) | `DefaultRevocationServiceTest#everyLegalPermanentTransitionIsAccepted`, `FilesystemRevocationAuthorityTest` | ✅ | ✅ `CrlEntryTest#rejectsInvalidSerialTimeAndReason` (rejects `REMOVE_FROM_CRL`), `RevokeCredentialTest#rejectsBlankAndOversizedJustification` |
| 11 | Full CRL incl. cRLNumber | `DefaultStatusObjectServiceCrlTest#assignsMonotonicCrlNumberAcrossGenerationsAndRestart`, `#bouncyCastleGeneratorPreservesFullSerialReasonAndTransitionTime` | ✅ | ✅ `#malformedAuthoritativeInputsAbortBeforeSigningAndPersistence`, `#generatedCrlIssuerNameMustMatchSelectedIssuerCertificate` |
| 12 | Delta CRL | `DefaultStatusObjectServiceCrlTest#deltaCrlCarriesDeltaIndicatorAndOnlyChangesSinceBase` | ✅ | ✅ `#deltaCrlWithoutBaseFullCrlIsRejected` |
| 13 | Persistent OCSP + durable republish | `DefaultStatusObjectServiceOcspTest#generatesIssuerSignedGoodOcspForCleanCertificate`, `SigningFilePublicationRecoveryTest` | ✅ | ✅ `#ocspForUnknownSerialIsRejected`, `DefaultStatusObjectServiceCrlTest#ocspWithoutTargetSerialIsRejected` |
| 14 | Live/response OCSP (parse / build / verify) | `OcspRequestParserTest#parsesCanonicalSha1Sha256AndExactNonce`, `OcspResponderServiceTest#validatesDelegatedResponderIssuerEkuUsageAndSigningCapability`, `AcmeEndToEndTest` (`assertSignedOcsp`) | ✅ | ✅ `OcspRequestParserTest#rejectsAlternateGetEncodingBoundsAndUnknownCriticalExtension` |
| 15 | Status publication (process / retry / reconcile / idempotency) | `DefaultPublicationServiceTest#registrationRequiresCommittedExactSourceAndIsIdempotent`, `#dispatchRetryAndTerminalStatesAreDurable`, `SigningFilePublisherTest`, `FilesystemPublicationEvidenceReconciliationTest` | ✅ | ✅ `#storeRejectsForeignContentAndObsoleteSidecarAuthority`, `#strictCodecRejectsTrailingAndImpossiblePublicationMetadata` |
| 16 | Administrative HTTPS API (contract, descriptors, dual-control) | `PkiHttpsServerTest#servesAuthenticatedHealthRealmDiscoveryAndGatewayOperation`, `ServerOperationGatewayTest`, `AdminSigningOperationAuthorizationTest#requiresExactApprovalForHighRiskOperationAndExecutesOnce` | ✅ | ✅ `#rejectsClientWithoutCertificateBeforeGatewayInvocation`, `#delegatesAllowedOperationAndDeniesCrossAuthorityWithoutExecution` |
| 17 | ACME (http-01 / dns-01 / EAB) | `AcmeEndToEndTest#completesRealHttpsAccountIssuanceRolloverRestartAndRevocation`, `AcmeProviderSecurityTest#eabProviderIsClasspathInactiveUntilExplicitlySelected` | ✅ | ✅ `#httpProviderRejectsInternalTargetBeforeNetworkAccess`, `#dnsProviderRequiresExplicitNumericResolver`, `AcmeSecurityPrimitivesTest#es256JwsRequiresCanonicalUrlNonceAndJwkMode` |
| 18 | TLS + client-trust providers (PKCS12) | `ForwardedClientCertificateParserTest#parsesStrictRfc9440LeafAndChain`, `PkiHttpsServerTest#authenticatesTrustedProxyWithRfc9440ForwardedClient`, `HttpsRemoteSigningTransportTest#providerConfiguredWithPkcs12SignsOverHttps` | ✅ | ✅ `#rejectsMalformedRfc9440ByteSequences`, `PkiHttpsServerTest#rejectsForwardedHeadersInDirectModeAndDuplicateProxyHeaders` (live SSLContext note in §4) |
| 19 | Audit & evidence (append-only log, projections, cross-store anchor, search/verify) | `FileAuditSinkIntegrityTest#verifiesIntactChainAndReportsHead`, `IssuanceAuditProjectionTest`/`StatusAuditProjectionTest`/`PublicationAuditProjectionTest`/`SigningAuditProjectionTest`, `ServerRealmContextTest#auditAnchorDetectsAuditLogRewriteAcrossReopen`, `ServerControlOperationExecutorTest#auditSearchProjectsSafeMetadataAndVerifyReportsStatus` | ✅ | ✅ `#detectsRecordContentMutation`, `#detectsRecordDeletionAsSequenceGap`, `#detectsTailTruncationOnlyAgainstTrustedHead`, `#auditOperationsFailClosedWhenSinkIsNotQueryable` |
| 20 | Signing liveness / crash-consistency / recovery | `FilesystemSignWorkflowStoreTest#acceptedWorkflowProgressesAndRetiresWithOrdinaryCapacityExhausted`, `#localSuccessUsesExactlyTwoForcedCompositeRounds`, `PkiSigningBusResilienceTest#requesterRestart_canConsumeResult_afterServerCompletes`, `SigningReconciliationWorkerTest` | ✅ | ✅ `SigningLedgerRecoveryTest#recoveredStateCheckpointBoundaryFailsClosedForMissingDuplicateAndConflict`, `#unsupportedRootEntryAndReferencedSymlinkFailClosed` |
| 21 | X.509 algorithm binding / security floor / suite compatibility | `X509BindingPhaseATest#bootstrapMatrixIsExactAndSymmetric`, `#universalSnapshotComposesExtensionsAndRejectsCrossSnapshotUse` | ✅ | ✅ `#parameterizedRsaPssRoundTripsAndRejectsWrongParameters`, `#bcBoundaryPreservesExactParametersAndRejectsSha1`, `#bcExecutorRejectsSignatureAndSpkiSubstitutionBeforeExecution` |
| 22 | Canonical DER strictness | `StreamingDerReaderTest#validatesCanonicalCrlAndLocatesSignedFields`, `#enforcesCanonicalSetOrdering`, `#subjectPublicKeyInfoRequiresZeroPadBits` | ✅ | ✅ `#rejectsTrailingIndefiniteAndNonMinimalLength`, `#rejectsNonCanonicalPrimitiveForms`, `#boundedEntryRejectsOversizeAndHostileHighTags` (writer note in §4) |
| 23 | lib PKIX API round-trips (`zeroecho.pkix`) | `PkixRoundTripTest#certificateBuildsParsesAndVerifies`, `#crlBuildsAndParses`, `#ocspResponseBuildsAsSuccessful`, `#distinguishedNameIsByteExactAndRawSpkiBuildsCerts` | ✅ | ✅ `PkixApiRejectionTest#rejectsMalformedCertificateCsrCrlOcspAndBadPoP` (added for Task 14) |
| 24 | Failure taxonomy (structural `PkiFailureReason`) | `PkiFailureReasonTest#everyReasonDeclaresANonNullClassification`, `PkiFailureTest#exceptionCarriesTheReasonStructurally` | ✅ | ✅ `#storeDurabilityUnconfirmedIsRecoveryRequiredAndInternalOnly`, `#unclassifiedExceptionHasNoReason` |
| 25 | Repository/store durability + content integrity | `FilesystemPkiStoreTest#everyNonSigningTopLevelSchemaRoundTripsThroughRealStore`, `#statusAuthorityIsAtomicDurableWriteOnceAndProtectsContent`, `FsCodecTest`, `TransactionalMetadataStoreContractTest` | ✅ | ✅ `#statusRecoveryRejectsMalformedOrMismatchedMetadata`, `#noncanonicalVersionMarkerIsRejectedBeforeMutation`, `FsCodecTest` trailing-byte + `oldStoreVersionIsRejected` |
| 26 | PKI CLI (single-op, batch `${step.field}`, bounded-wait resume, env unlock) | `PkiCliTest#resolvesEarlierFieldsAndContinuesOnlyIndependentSteps`, `#pendingOperationExitsCleanlyForResumeWhenWaitElapses` (exit 7 / `OPERATION_PENDING`), `#packagedEntryPointProvidesHelpAndSafeValidationFailure` | ✅ | ✅ `#rejectsFutureReferencesScriptsInterpolationAndSecretArgumentsBeforeOpening`, `PkiPlanParserTest#rejectsEmptyDuplicateAndUnknownOperationPlans` |
| 27 | Keyring security (0700 dir / POSIX / 0600 files) | `KeyringFilesystemSecurityTest#secureCreationAndUnsafePermissionsMatrix`, `KeyringStoreTest` | ✅ | ✅ `#nonPosixAndOwnershipMismatchFailClosed`, `#symlinkAndHardLinkMatrixFailsClosed` |
| 28 | Anti-substitution postcondition (output bound to signing plan) | `X509BindingPhaseATest#bcExecutorRejectsSignatureAndSpkiSubstitutionBeforeExecution`, `DefaultStatusObjectServiceCrlTest#generatedCrlIssuerNameMustMatchSelectedIssuerCertificate`, `OcspResponderServiceTest#persistsExactIssuerBindingAndFailsOnChangedRegistryCommitment` | ✅ | ✅ (all three are substitution-rejection cases; behavioral coverage, see §4) |
| 29 | Credential confirmation / proof suite (disclosure policy) | `DefaultCredentialConfirmationServiceTest#issuesPersistedChallengeAndExactlyReplaysPublicPresentation`, `SignatureProofSuiteTest#deterministicTranscriptAndEd25519ProofMatchFrozenVectors` | ✅ | ✅ `#mismatchingCredentialIdentityFailsBeforeChallengePersistence`, `SignatureProofSuiteTest#publicProviderRejectsWrongProofCoordinatesAndSuiteSpecificOversize` |
| 30 | HTTP transports + public repository routes | `RepositoryAliasServiceTest#currentCrlUsesExpectedCurrentAndSurvivesRecovery`, `PkiHttpsServerTest#publicIssuerAndAliasedChainUseExactAuthoritativeRecordsAndValidators` | ✅ | ✅ `RepositoryAliasServiceTest#currentDeltaCrlAliasRequiresDeltaCrlTypeAndIsPublicByDefault`, `PkiHttpsServerTest#acmeListenerIsLifecycleOwnedAndRouteIsolated` |

Legend: ✅ automated & passing · ➖ partial (see §4).

## §2 Architecture & packaging — build/CI gates

These properties are not unit-testable but are enforced or verified at build time.

| Requirement | Gate | Status |
|-------------|------|--------|
| JPMS module-per-artifact; implementation packages not exported | Modular `compileJava` of `lib`/`ext`/`pki`/`pki-server`/`app` (each has `module-info.java`); `./gradlew build` fails on an invalid module graph or an accidental export | Automated (build) |
| Runs on the module path AND the classpath | Tests run on the classpath (`modularity.inferModulePath=false`); a module-path smoke (`java --module-path … --module zeroecho.app/zeroecho.ZeroEcho`) was run this milestone | Build (classpath) + verified (module path) |
| **BouncyCastle confined to `lib`** | `verifyBouncyCastleConfinement` task (wired into `check`) fails the build if any module other than `lib` references `org.bouncycastle` under `src/main/java` | Automated (build, added for Task 14) |
| Installed distribution works end to end | `AcmeEndToEndTest#completesInstalledDistributionAccountToRevocationWorkflow`, `PkiCliTest#packagedEntryPointProvidesHelpAndSafeValidationFailure` (spawn the `installDist` image); the three `docs/examples/pki-cli` demos run against the image | Automated (spawned) + verified (demos) |
| Java 25 toolchain | `JavaLanguageVersion.of(25)` in the common convention; build fails on a mismatched toolchain | Automated (build) |
| Thin module jars (no bundled BouncyCastle) | `pki`/`app` jars carry only their own classes (fat-jar bundling removed) | Verified this milestone (jar contents) |

## §3 Manual / large-machine release checks (justified)

| Check | Why not a unit test | Procedure |
|-------|--------------------|-----------|
| Signing throughput acceptance (open-loop macrobenchmark) | Requires a dedicated large reference host and a frozen, timed drain window; the harness is a performance measurement, not a correctness assertion. Its functional harness *is* smoke-tested (`SigningPerformanceBenchmarkTest#smokeProfileExercisesNativeRuntimeAndProducesVersionedJson`). | `RUN_ON_LARGE_MACHINE.txt` (three frozen `:pki:signingPerformanceBenchmark` anchors). Known limitation: the frozen warmup-drain deadline cannot be met on a small/WSL host — the run then reports `uncertain`/`completedVsRetired` and is (correctly) non-evaluable, not a system fault; the system sheds load (`SigningExecutionException.OVERLOADED` → `rejected`) rather than collapsing. See `project_signing_throughput_bottleneck`. |

## §4 Known near-gaps and disposition

- **Area 23 (lib PKIX API negatives) — CLOSED.** `PkixRoundTripTest` was positive-only; added `PkixApiRejectionTest` covering malformed certificate/CSR/CRL/OCSP DER and bad-PoP rejection.
- **Area 9 (per-CA routing) — accepted.** The meaningful negative (unmapped authority → default service) is asserted; there is no invalid-input rejection path to test at the routing layer (config validation is covered by `PkiCliTest`). No action.
- **Area 22 (`StreamingDerWriter`) — accepted.** Writer canonicalization is covered indirectly by reader round-trips and codec round-trip tests; a dedicated writer test is a low-value follow-up.
- **Area 28 (anti-substitution) — accepted.** No test is literally named `validateGeneratedCertificate/Crl/Ocsp`; the postcondition is verified behaviorally by the three substitution-rejection cases cited in row 28.
- **Area 18 (live TLS server) — accepted.** The production `PkiServerTlsProvider` SSLContext wiring is exercised end to end only through the client-certificate authentication paths (`PkiHttpsServerTest`, `AcmeEndToEndTest`); the provider SPI itself is unit-tested via test doubles. Live TLS handshake correctness is inherently an integration/manual concern.

No requirement area has zero automated coverage.

## §5 Platform-conditional tests (tagged, with documented justification)

A small number of tests validate a property that can only be *exercised* on a host
exposing a specific operating-system/filesystem capability. On a host lacking that
capability the property is genuinely unobservable, so the test is **skipped via a
JUnit `ExecutionCondition`, never disabled or weakened** — it reports as *skipped*
(not passed, so no false assurance) and runs to completion on every platform that
can exercise it. Each such test carries a JUnit `@Tag` for traceability and
filtering; the tag's meaning and the acceptability justification are documented on
the composed annotation that declares it (single source of truth). This satisfies
the requirement that a skipped test be tagged and justified.

| Tag | Annotation | Capability required | Why skipping is acceptable | Tests |
|-----|-----------|---------------------|----------------------------|-------|
| `requires-symlink-creation` | `@RequiresSymlinkCreation` | Creating a symbolic link (Windows needs `SeCreateSymbolicLinkPrivilege`; unconditional on POSIX) | The tests assert the store **refuses to follow** a symbolic link (`NOFOLLOW_LINKS`). One cannot exercise "refuse to follow a link" on a host that cannot create the link. The platform-neutral production path (`NOFOLLOW_LINKS` on every open) is still covered by the non-symlink assertions in the same suites, and each test runs fully on POSIX and privileged Windows. | `DurableMetadataFilesTest#secureOpenRejectsSymlinkAndFaultsExplicitly`, `FilesystemPkiStoreTest#snapshotRejectsTruncatedRevocationAuthorityAndObsoleteSchema`, `FilesystemRevocationLogTest#authorityPreambleAndEntryTypeFailuresFailClosed`, `FilesystemStagedContentStoreTest#rejectsTraversalForeignMetadataAndSymlinkContent`, `FilesystemStagedContentStoreTest#ownerIndexValidatesCompleteCommittedNamespace`, `SegmentedTransactionalMetadataStoreTest#unknownAndSymlinkEntriesFailClosedWithoutMutation`, `SigningFilePublisherTest#replacedTemporaryPathIsRejectedWithoutFollowingSymlink`, `SigningLedgerRecoveryTest#unsupportedRootEntryAndReferencedSymlinkFailClosed` |
| `requires-file-identity` | `@RequiresFileIdentity` | Stable filesystem file identity via `BasicFileAttributes.fileKey()` (POSIX inode; `null` on Windows/NTFS) | The test asserts that temporary-file cleanup distinguishes a swapped file by its stable identity and refuses to delete it. Where `fileKey` is `null` the platform cannot provide that identity; the store falls back to a regular-file check with the owner-only directory as the boundary (a documented, in-threat-model choice). Runs fully on POSIX. | `SigningFilePublisherTest#cleanupNeverDeletesReplacementRegularFile` |

Execution evidence: on native Windows (standard host) these 9 tests report *skipped*
and every other test passes (0 failures); on POSIX (WSL ext4) all 9 execute and
pass, with 0 skipped. The skip is therefore a property of the host capability, not
of ZeroEcho — a defect would be caught by the POSIX run.
