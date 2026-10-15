/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.LongFunction;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.OneShotContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningService;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.signing.SigningRequest;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.store.AuditEvidenceFeed;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
import zeroecho.pki.testkit.PkiTestRuntime;

final class PkiSessionLifecycleTest {

    @Test
    void opensUnconfiguredServicesAndClosesIdempotently(@TempDir Path temporary) throws Exception {
        PkiSession session = PkiSession.open(configuration(temporary));

        assertTrue(session.profiles() == session.profiles());
        assertTrue(session.confirmations() == session.confirmations());
        assertTrue(session.revocations() == session.revocations());
        assertTrue(session.requests().isPresent());
        assertTrue(session.publications().isEmpty());
        assertTrue(session.signing().isEmpty());
        assertTrue(session.semanticSigning().isEmpty());
        assertTrue(session.signingCommands().isEmpty());
        assertTrue(session.algorithmBindings() == session.algorithmBindings());
        assertTrue(session.resourceScopes() == session.resourceScopes());
        assertTrue(session.repository() == session.repository());
        assertFalse(session.supportsSigningEvidenceFeed());
        assertThrows(UnsupportedOperationException.class, () -> session.openSigningEvidenceFeed(-1L));
        assertInstanceOf(PkiOperationOutcome.Completed.class,
                session.operations().execute(new PkiOperation.ValidateConfiguration(), CancellationSignal.NONE));

        session.close();
        session.close();
        assertThrows(IllegalStateException.class, session::operations);
        assertThrows(IllegalStateException.class, session::repository);
        assertThrows(IllegalStateException.class, session::requests);
        assertThrows(IllegalStateException.class, session::semanticSigning);
        assertThrows(IllegalStateException.class, session::signingCommands);
        assertThrows(IllegalStateException.class, () -> session.openIssuanceEvidenceFeed(-1L));
        assertThrows(IllegalStateException.class, () -> session.openStatusEvidenceFeed(-1L));
        assertThrows(IllegalStateException.class, () -> session.openPublicationEvidenceFeed(-1L));
        assertThrows(IllegalStateException.class, session::supportsSigningEvidenceFeed);
        assertThrows(IllegalStateException.class, () -> session.openSigningEvidenceFeed(-1L));
    }

    @Test
    void exposesCommittedIssuanceAndStatusEvidenceWithExclusiveResume(@TempDir Path temporary) throws Exception {
        RecordingSigningBootstrap bootstrap = new RecordingSigningBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                Clock.fixed(Instant.EPOCH, ZoneOffset.UTC), bootstrap)) {
            assertEvidenceFeedEmpty(session.openIssuanceEvidenceFeed(-1L), 0L);
            assertEvidenceFeedEmpty(session.openStatusEvidenceFeed(-1L), 0L);

            DurableContentReference content = PkiTestRuntime.fixtureReference(
                    bootstrap.store.stagedContent(), Encoding.DER, new byte[] { 0x01, 0x02, 0x03 });
            PkiId credentialId = new PkiId("session-credential");
            PkiId statusId = new PkiId("session-status");
            PkiId issuerId = new PkiId("session-issuer");
            bootstrap.store.putCredential(new Credential(credentialId, new FormatId("fmt-x509"),
                    new IssuerRef(issuerId), new SubjectRef("CN=session"),
                    new Validity(Instant.EPOCH, Instant.EPOCH.plusSeconds(60L)), "01",
                    new PkiId("session-public-key"),
                    new EndEntityProfileBinding(new CertificateProfileRef("session-profile", 1, new byte[32])),
                    CredentialStatus.ISSUED, content, new SimpleAttributeSet()));
            bootstrap.store.putStatusObject(new StatusObject(statusId, new FormatId("x509"), issuerId,
                    StatusObjectType.CRL, Instant.EPOCH, Optional.of(Instant.EPOCH.plusSeconds(60L)),
                    content, new SimpleAttributeSet()));

            assertEvidenceFeed(session::openIssuanceEvidenceFeed, credentialId);
            assertEvidenceFeed(session::openStatusEvidenceFeed, statusId);
        }
    }

    @Test
    void exposesAuthoritativeStatusAndFencesRetainedEvaluationsAfterClose(@TempDir Path temporary) throws Exception {
        RecordingSigningBootstrap bootstrap = new RecordingSigningBootstrap();
        Instant now = Instant.EPOCH.plusSeconds(30);
        PkiSession session = DefaultPkiSession.open(configuration(temporary), Clock.fixed(now, ZoneOffset.UTC), bootstrap);
        zeroecho.pki.api.credential.EffectiveCredentialStatusResolver resolver;
        zeroecho.pki.api.credential.EffectiveCredentialStatusResolver.Evaluation evaluation;
        Credential credential;
        try (session) {
            DurableContentReference content = PkiTestRuntime.fixtureReference(bootstrap.store.stagedContent(), Encoding.DER, new byte[] { 1, 2, 3 });
            PkiId id = new PkiId("status-credential");
            credential = new Credential(id, new FormatId("fmt-x509"), new IssuerRef(new PkiId("status-issuer")), new SubjectRef("CN=status"),
                    new Validity(Instant.EPOCH, Instant.EPOCH.plusSeconds(60)), "01", new PkiId("status-key"),
                    new EndEntityProfileBinding(new CertificateProfileRef("status-profile", 1, new byte[32])), CredentialStatus.ISSUED,
                    content, new SimpleAttributeSet());
            bootstrap.store.putCredential(credential);
            resolver = session.credentialStatuses(); evaluation = resolver.beginEvaluation();
            assertTrue(resolver == session.credentialStatuses()); assertEquals(now, evaluation.evaluationTime());
            assertEquals(zeroecho.pki.api.credential.EffectiveCredentialStatus.USABLE, evaluation.resolve(session.repository().credential(id).orElseThrow()));
            bootstrap.store.transitionRevocation(new zeroecho.pki.api.revocation.RevocationCommand.Hold(id, new SimpleAttributeSet()), Instant.EPOCH.plusSeconds(10));
            assertEquals(zeroecho.pki.api.credential.EffectiveCredentialStatus.HELD, evaluation.resolve(session.repository().credential(id).orElseThrow()));
            bootstrap.store.transitionRevocation(new zeroecho.pki.api.revocation.RevocationCommand.RevokePermanently(id,
                    zeroecho.pki.api.revocation.RevocationReason.KEY_COMPROMISE, new SimpleAttributeSet()), Instant.EPOCH.plusSeconds(20));
            assertEquals(zeroecho.pki.api.credential.EffectiveCredentialStatus.PERMANENTLY_REVOKED, evaluation.resolve(session.repository().credential(id).orElseThrow()));
        }
        assertThrows(IllegalStateException.class, session::credentialStatuses);
        assertThrows(IllegalStateException.class, resolver::beginEvaluation);
        assertThrows(IllegalStateException.class, evaluation::evaluationTime);
        assertThrows(IllegalStateException.class, () -> evaluation.resolve(credential));
        assertThrows(IllegalStateException.class, () -> evaluation.requireUsable(credential, zeroecho.pki.api.credential.CredentialUse.BUNDLE_DELIVERY));
    }

    @Test
    void exposesEnabledSigningEvidenceThroughSessionAndPreservesExclusiveResume(@TempDir Path temporary) throws Exception {
        RecordingSigningBootstrap bootstrap = new RecordingSigningBootstrap();
        bootstrap.signingEvidence = true;
        PkiSession session = DefaultPkiSession.open(configuration(temporary), Clock.systemUTC(), bootstrap);
        try (session) {
            assertTrue(session.supportsSigningEvidenceFeed());
            assertEvidenceFeedEmpty(session.openSigningEvidenceFeed(-1), 0);
            Instant created = bootstrap.store.signingNow();
            String namespace = bootstrap.store.signingNamespace() + ".test-signer";
            PkiId operation = zeroecho.pki.api.orch.SigningSubmissionId.create(namespace, created,
                    new java.security.SecureRandom()).id();
            zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceCommand command = new zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceCommand(
                    operation, namespace, new SigningProvider.ConfigurationCommitment(new byte[32]),
                    new AccessContext(new Principal("TEST", "session"), new Purpose("SIGN"), Optional.empty(), Optional.empty()),
                    new KeyRef("session-key"), new PkiId("session-authority"), "SHA256withRSA", Encoding.BINARY,
                    created, created.plusSeconds(60), PkiTestRuntime.operationReference(bootstrap.store.stagedContent(), Encoding.BINARY,
                            new byte[] {1}), Optional.empty(), zeroecho.pki.spi.store.SignWorkflowStore.Mode.NORMAL, Optional.empty());
            assertEquals(zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceResult.ACCEPTED, bootstrap.store.acceptSign(command));
            bootstrap.store.requestSignCancellation(operation, 0, 0).orElseThrow();
            assertEvidenceFeed(session::openSigningEvidenceFeed, operation);
            try (AuditEvidenceFeed feed = session.openSigningEvidenceFeed(-1)) {
                assertTrue(feed.next(CancellationSignal.NONE));
                assertEquals(SigningExecutionEvidence.Outcome.CANCELLED,
                        SigningExecutionEvidence.decode(feed.current().evidence()).orElseThrow().outcome());
            }
        }
        assertThrows(IllegalStateException.class, session::supportsSigningEvidenceFeed);
        assertThrows(IllegalStateException.class, () -> session.openSigningEvidenceFeed(-1));
    }

    private static void assertEvidenceFeed(LongFunction<AuditEvidenceFeed> opener, PkiId expectedId)
            throws IOException {
        try (AuditEvidenceFeed feed = opener.apply(-1L)) {
            assertEquals(1L, feed.highWatermark());
            assertTrue(feed.next(CancellationSignal.NONE));
            assertEquals(0L, feed.current().sequence());
            assertEquals(expectedId, feed.current().objectId());
            assertTrue(feed.current().evidence().length > 0);
            assertFalse(feed.next(CancellationSignal.NONE));
        }
        assertEvidenceFeedEmpty(opener.apply(0L), 1L);
    }

    private static void assertEvidenceFeedEmpty(AuditEvidenceFeed feed, long expectedWatermark) throws IOException {
        try (feed) {
            assertEquals(expectedWatermark, feed.highWatermark());
            assertFalse(feed.next(CancellationSignal.NONE));
        }
    }

    @Test
    void unconfiguredSessionRemainsSigningThreadless(@TempDir Path temporary) throws Exception {
        try (PkiSession session = PkiSession.open(configuration(temporary))) {
            assertTrue(session.requests().isPresent());
        }
    }

    @Test
    void exposesRestoredOcspWithoutLegacySigningSessionSurface() {
        Set<String> methods = Arrays.stream(PkiSession.class.getMethods())
                .map(java.lang.reflect.Method::getName)
                .collect(Collectors.toUnmodifiableSet());

        assertTrue(methods.contains("ocsp"));
        assertTrue(methods.stream().noneMatch(Set.of("authorities", "issuance", "statusObjects",
                "reconcileSigning", "registerSigningAdvisoryWake", "signingExecutionMetrics")::contains));
    }

    @Test
    void configuredSessionOwnsSigningRuntimeAndClosesProvider(@TempDir Path temporary)
            throws Exception {
        RecordingSigningBootstrap bootstrap = new RecordingSigningBootstrap();
        PkiSession session = DefaultPkiSession.open(configured(temporary, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm()),
                Clock.systemUTC(), bootstrap);
        zeroecho.pki.api.SigningService service = session.signing().orElseThrow();
        zeroecho.pki.api.SemanticSigningService semantic = session.semanticSigning().orElseThrow();
        assertTrue(semantic == session.semanticSigning().orElseThrow());
        PkiSigningCommands commands = session.signingCommands().orElseThrow();
        assertTrue(commands == session.signingCommands().orElseThrow());
        assertEquals(1, bootstrap.provider.opens);
        session.close();
        assertEquals(1, bootstrap.provider.closes);
        assertThrows(IllegalStateException.class, () -> commands.completedResult(null));
        assertThrows(IllegalStateException.class, () -> commands.prepare(null, null, null, null));
        assertThrows(SigningExecutionException.class, service::newSubmissionId);
        assertThrows(SigningExecutionException.class,
                () -> semantic.findByCorrelation(zeroecho.pki.api.signing.SemanticSigningKind.CA, "closed"));
    }

    @Test
    void configuredSessionDispatchesExactNondefaultRequestAlgorithm(@TempDir Path temporary) throws Exception {
        RecordingSigningBootstrap bootstrap = new RecordingSigningBootstrap(1);
        try (PkiSession session = DefaultPkiSession.open(configured(temporary,
                zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm()), Clock.systemUTC(), bootstrap)) {
            SigningService service = session.signing().orElseThrow();
            KeyRef key = new KeyRef("nondefault-ed-key");
            AccessContext access = new AccessContext(new Principal("TEST", "algorithm"), new Purpose("SIGN"), Optional.empty(), Optional.empty());
            SigningRequest request = new SigningRequest(service.newSubmissionId(), access, key, new PkiId("algorithm-authority"),
                    zeroecho.core.alg.BootstrapAlgorithmIdentities.ED25519_SIGNATURE, Encoding.BINARY, Encoding.BINARY);
            zeroecho.pki.api.signing.PreparedSigningRequest prepared = service.prepare(request, oneShot(new byte[] {1, 2}), CancellationSignal.NONE);
            assertEquals(request.signatureAlgorithm(), prepared.request().signatureAlgorithm());
            service.accept(prepared);
            assertTrue(bootstrap.provider.dispatched.await(5, TimeUnit.SECONDS));
            assertEquals(request.signatureAlgorithm().canonicalForm(), bootstrap.provider.dispatchAlgorithms.get(key));
            assertEquals(request.signatureAlgorithm().canonicalForm(), bootstrap.store.getSignWorkflow(request.submissionId().id())
                    .orElseThrow().envelope().algorithmId());
            assertEquals(zeroecho.pki.api.signing.SigningAcceptanceResolution.MATCHED, service.resolve(prepared.receipt()));
        }
    }

    @Test
    void configuredTopologyRoutesExactAndUnmatchedKeysToDedicatedPools(
            @TempDir Path temporary) throws Exception {
        KeyRef exactKey = new KeyRef("session-exact-sensitive");
        KeyRef unmatchedKey = new KeyRef("session-unmatched-sensitive");
        PkiSessionConfiguration.SigningTopology topology = topology(2,
                List.of(new PkiSessionConfiguration.SigningKeyGroup(List.of(exactKey),
                        new PkiSessionConfiguration.SigningLanePool(1, 1))),
                new PkiSessionConfiguration.SigningLanePool(1, 1));
        RecordingSigningBootstrap bootstrap = new RecordingSigningBootstrap(2);

        try (PkiSession session = DefaultPkiSession.open(
                configured(temporary, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), topology),
                Clock.systemUTC(), bootstrap)) {
            SigningService service = session.signing().orElseThrow();
            submit(service, exactKey, new PkiId("authority-exact"));
            submit(service, unmatchedKey, new PkiId("authority-catch-all"));
            assertTrue(bootstrap.provider.dispatched.await(5L, TimeUnit.SECONDS));
            assertTrue(bootstrap.provider.threadFor(exactKey).contains("pool-0"));
            assertTrue(bootstrap.provider.threadFor(unmatchedKey).contains("pool-1"));
            assertTrue(bootstrap.provider.threadNames().stream()
                    .noneMatch(name -> name.contains(exactKey.value())
                            || name.contains(unmatchedKey.value())));
        }
        assertEquals(1, bootstrap.provider.closes);
    }

    @Test
    void failedSigningCompositionClosesProviderAndStore(@TempDir Path temporary) {
        RecordingSigningBootstrap bootstrap = new RecordingSigningBootstrap();
        assertThrows(IllegalArgumentException.class, () -> DefaultPkiSession.open(
                configured(temporary, "unsupported"), Clock.systemUTC(), bootstrap));
        assertEquals(1, bootstrap.provider.closes);
        assertThrows(IllegalStateException.class, bootstrap.store::signingNow);
    }

    @Test
    void invalidDuplicateRouteFailsBeforeResourceAllocation(@TempDir Path temporary) {
        RecordingSigningBootstrap bootstrap = new RecordingSigningBootstrap();

        assertThrows(IllegalArgumentException.class, () -> DefaultPkiSession.open(
                duplicateRouteConfiguration(temporary), Clock.systemUTC(), bootstrap));
        assertEquals(0, bootstrap.provider.opens);
        assertTrue(bootstrap.store == null);
    }

    @Test
    void rejectsEveryConfigurationVersionExceptCurrent(@TempDir Path temporary) {
        ProviderConfig store = new ProviderConfig("fs", Map.of("root", temporary.toString()));
        ProviderConfig audit = new ProviderConfig("memory", Map.of("size", "16"));
        assertThrows(IllegalArgumentException.class,
                () -> new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION - 1,
                        store, audit, Optional.empty(), List.of(), List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION + 1,
                        store, audit, Optional.empty(), List.of(), List.of()));
    }

    private static PkiSessionConfiguration configuration(Path temporary) {
        return new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", temporary.resolve("store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")),
                Optional.empty(), List.of(), List.of());
    }

    private static PkiSessionConfiguration configured(Path temporary, String algorithm) {
        return configured(temporary, algorithm, topology(2, List.of(),
                new PkiSessionConfiguration.SigningLanePool(1, 4)));
    }

    private static PkiSessionConfiguration configured(Path temporary, String algorithm,
            PkiSessionConfiguration.SigningTopology topology) {
        PkiSessionConfiguration.SigningConfiguration signing =
                new PkiSessionConfiguration.SigningConfiguration(
                        new ProviderConfig("test-signing", Map.of()), algorithm,
                        Duration.ofMinutes(1L), Optional.empty(), topology, OptionalLong.empty());
        return new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", temporary.resolve("store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")),
                Optional.of(signing), List.of(), List.of());
    }

    private static PkiSessionConfiguration duplicateRouteConfiguration(Path temporary) {
        KeyRef duplicate = new KeyRef("duplicate-sensitive-key");
        PkiSessionConfiguration.SigningKeyGroup first =
                new PkiSessionConfiguration.SigningKeyGroup(List.of(duplicate),
                        new PkiSessionConfiguration.SigningLanePool(1, 1));
        PkiSessionConfiguration.SigningKeyGroup second =
                new PkiSessionConfiguration.SigningKeyGroup(List.of(duplicate),
                        new PkiSessionConfiguration.SigningLanePool(1, 1));
        return configured(temporary, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), topology(2,
                List.of(first, second), new PkiSessionConfiguration.SigningLanePool(1, 1)));
    }

    private static PkiSessionConfiguration.SigningTopology topology(int pageSize,
            List<PkiSessionConfiguration.SigningKeyGroup> exactGroups,
            PkiSessionConfiguration.SigningLanePool catchAll) {
        return new PkiSessionConfiguration.SigningTopology(
                new PkiSessionConfiguration.SigningCoordinatorLimits(pageSize,
                        Duration.ofSeconds(10L), Duration.ofSeconds(5L),
                        Duration.ofDays(1L), Duration.ofSeconds(2L)),
                exactGroups, catchAll);
    }

    private static void submit(SigningService service, KeyRef keyRef, PkiId authority) {
        AccessContext access = new AccessContext(new Principal("TEST", "session"),
                new Purpose("SIGN"), Optional.empty(), Optional.empty());
        SigningRequest request = new SigningRequest(service.newSubmissionId(), access,
                keyRef, authority, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, Encoding.BINARY, Encoding.BINARY);
        service.accept(service.prepare(request, oneShot(new byte[] { 1, 2, 3 }),
                CancellationSignal.NONE));
    }

    private static OneShotContent oneShot(byte[] content) {
        byte[] snapshot = content.clone();
        return new OneShotContent() {
            private boolean opened;
            @Override public InputStream openStream() {
                if (opened) {
                    throw new IllegalStateException("Content was already opened");
                }
                opened = true;
                return new ByteArrayInputStream(snapshot);
            }
            @Override public OptionalLong length() { return OptionalLong.of(snapshot.length); }
            @Override public void close() { }
        };
    }

    private static final class RecordingSigningBootstrap implements DefaultPkiSession.Bootstrap {
        private final RecordingProvider provider;
        private PkiStore store;
        private boolean signingEvidence;

        private RecordingSigningBootstrap() {
            this(0);
        }

        private RecordingSigningBootstrap(int expectedDispatches) {
            provider = new RecordingProvider(expectedDispatches);
        }

        @Override public void validateStore(ProviderConfig configuration) {
            PkiBootstrap.validateStoreConfiguration(configuration);
        }
        @Override public void validateAudit(ProviderConfig configuration) {
            PkiBootstrap.validateAuditConfiguration(configuration);
        }
        @Override public PkiStore openStore(ProviderConfig configuration) {
            store = signingEvidence ? evidenceStore(configuration) : PkiBootstrap.openStore(configuration);
            return store;
        }
        @Override public PkiStore openStore(ProviderConfig configuration,
                PkiStoreRuntimeDependencies dependencies) {
            store = signingEvidence ? evidenceStore(configuration) : PkiBootstrap.openStore(configuration, dependencies);
            return store;
        }
        private static PkiStore evidenceStore(ProviderConfig configuration) {
            return new zeroecho.pki.impl.fs.FilesystemPkiStore(Path.of(configuration.get("root").orElseThrow()),
                    zeroecho.pki.impl.fs.FsPkiStoreOptions.defaults().withSigningEvidenceAudit(true));
        }
        @Override public AuditSink openAudit(ProviderConfig configuration) {
            return PkiBootstrap.openAudit(configuration);
        }
        @Override public void validateSigning(ProviderConfig configuration) { }
        @Override public SigningProvider openSigning(ProviderConfig configuration,
                SigningProviderRuntimeDependencies dependencies) {
            provider.opens++;
            return provider;
        }
    }

    private static final class RecordingProvider implements SigningProvider {
        @Override public zeroecho.pki.spi.crypto.SigningInputCapabilities inputCapabilities() {
            return new zeroecho.pki.spi.crypto.SigningInputCapabilities(Long.MAX_VALUE, java.util.Map.of());
        }
        private final ConfigurationCommitment commitment =
                new ConfigurationCommitment(new byte[ConfigurationCommitment.BYTE_LENGTH]);
        private int opens;
        private int closes;
        private final CountDownLatch dispatched;
        private final Map<KeyRef, String> dispatchThreads = new ConcurrentHashMap<>();
        private final Map<KeyRef, String> dispatchAlgorithms = new ConcurrentHashMap<>();

        private RecordingProvider(int expectedDispatches) {
            dispatched = new CountDownLatch(expectedDispatches);
        }
        @Override public String id() { return "test-signer"; }
        @Override public ConfigurationCommitment configurationCommitment() { return commitment; }
        @Override public Set<String> supportedAlgorithms() { return Set.of(zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(),
                zeroecho.core.alg.BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm()); }
        @Override public OperationObservation dispatch(SigningProvider.SignRequest request,
                CallControl control) {
            dispatchThreads.put(request.keyRef(), Thread.currentThread().getName());
            dispatchAlgorithms.put(request.keyRef(), request.algorithmId());
            dispatched.countDown();
            return pending(request.operationId());
        }
        @Override public OperationObservation reconcile(PkiId operationId, CallControl control) {
            return pending(operationId);
        }
        @Override public OperationObservation cancel(PkiId operationId, long fencingToken,
                CancellationReason reason, CallControl control) {
            return pending(operationId);
        }
        @Override public void close() { closes++; }
        private String threadFor(KeyRef keyRef) { return dispatchThreads.get(keyRef); }
        private List<String> threadNames() { return List.copyOf(dispatchThreads.values()); }
        private static OperationObservation pending(PkiId operationId) {
            return new OperationObservation(operationId, ObservationState.PENDING,
                    java.time.Instant.now(), DetailCode.PENDING, Optional.empty());
        }
    }
}
