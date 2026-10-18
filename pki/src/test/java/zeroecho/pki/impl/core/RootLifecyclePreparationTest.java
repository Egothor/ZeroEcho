/* *****************************************************************************
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

package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.InterruptedIOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.core.continuation.SigningOuterTerminalDriver;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.testkit.RootCreationFixture;
import zeroecho.pkix.Pkix;

final class RootLifecyclePreparationTest {
    @Test void rolloverUsesCurrentKeyActiveProfileAndTrustedPrincipalBeyondOldExpiry(@TempDir Path root) throws Exception {
        MutableClock clock = new MutableClock();
        try (FilesystemPkiStore actual = open(root, clock)) {
            RootCreationFixture fixture = new RootCreationFixture();
            CaRecord existing = seed(actual, fixture);
            Credential old = selected(actual, existing);
            assertEquals(1, ((CaProfileBinding) old.profileBinding()).reference().profileVersion());
            CertificateProfileRef active = activateVersionTwo(actual);
            clock.now = RootCreationFixture.NOW.plus(Duration.ofDays(101));
            assertTrue(clock.instant().isAfter(old.validity().notAfter()));
            List<String> calls = new ArrayList<>();
            PkiStore store = proxy(PkiStore.class, actual, (method, args) -> {
                calls.add(method);
                return PROCEED;
            });
            int lookups = fixture.provider.lookups.get();
            Validity requested = new Validity(clock.instant(), clock.instant().plus(Duration.ofDays(5)));
            DomainSigningRequest prepared = preparer(store, fixture, clock).prepare(RootCreationFixture.ACCESS,
                    new CaRolloverCommand.Root(existing.caId(), Optional.of(requested), new SimpleAttributeSet()),
                    submission(actual, fixture), RootCreationFixture.TTL, CancellationSignal.NONE);
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(prepared.domainTemplate().command());
            assertEquals("ROLLOVER_ROOT", command.operation());
            assertEquals(existing.caId().value(), command.field(13));
            assertEquals(RootCreationFixture.KEY, prepared.keyRef());
            assertEquals(Long.toString(active.profileVersion()), command.field(5));
            assertEquals(java.util.HexFormat.of().formatHex(active.canonicalSha256()), command.field(6));
            assertEquals(command.field(1), command.field(10));
            X509Certificate certificate = certificate(actual, prepared);
            assertEquals(new X500Principal(existing.subjectRef().value()), certificate.getSubjectX500Principal());
            assertEquals(certificate.getSubjectX500Principal(), certificate.getIssuerX500Principal());
            assertEquals(certificate.getSubjectX500Principal(), new X500Principal(command.field(1)));
            assertTrue(command.field(1).contains("O=Frozen Organization"));
            assertArrayEquals(fixture.key.getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
            assertEquals(requested.notBefore().truncatedTo(ChronoUnit.SECONDS).plusSeconds(1), certificate.getNotBefore().toInstant());
            assertEquals(requested.notAfter().truncatedTo(ChronoUnit.SECONDS), certificate.getNotAfter().toInstant());
            assertSame(RootCreationFixture.ACCESS, prepared.accessContext());
            assertEquals(lookups + 1, fixture.provider.lookups.get());
            assertEquals(0, fixture.provider.dispatches.get());
            assertTrue(!calls.contains("getIssuerChainPath") && !calls.contains("getDomainContinuation"),
                    "Root renewal must not walk an old chain or consume a key proof");
            assertEquals(existing, actual.getCa(existing.caId()).orElseThrow());
            assertTrue(actual.getSignWorkflow(prepared.operationId()).isEmpty());
            actual.stagedContent().retireUnownedContent(prepared.content());
        }
    }

    @Test void rotationSelectsSuppliedKeyAndPermitsSameReference(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root, RootCreationFixture.CLOCK)) {
            RootCreationFixture fixture = new RootCreationFixture();
            CaRecord existing = seed(store, fixture);
            int lookups = fixture.provider.lookups.get();
            RootSigningPreparation preparation = preparer(store, fixture, RootCreationFixture.CLOCK);
            DomainSigningRequest replacement = preparation.prepare(RootCreationFixture.ACCESS,
                    new CaKeyRotationCommand.Root(existing.caId(), RootCreationFixture.REPLACEMENT_KEY, new SimpleAttributeSet()),
                    submission(store, fixture), RootCreationFixture.TTL, CancellationSignal.NONE);
            DomainSigningRequest same = preparation.prepare(RootCreationFixture.ACCESS,
                    new CaKeyRotationCommand.Root(existing.caId(), RootCreationFixture.KEY, new SimpleAttributeSet()),
                    submission(store, fixture), RootCreationFixture.TTL, CancellationSignal.NONE);
            assertNotEquals(replacement.operationId(), same.operationId());
            assertNotEquals(replacement.domainTemplate().correlationId(), same.domainTemplate().correlationId());
            assertEquals(RootCreationFixture.REPLACEMENT_KEY, replacement.keyRef());
            assertEquals(RootCreationFixture.KEY, same.keyRef());
            assertArrayEquals(fixture.otherKey.getPublic().getEncoded(), certificate(store, replacement).getPublicKey().getEncoded());
            assertArrayEquals(fixture.key.getPublic().getEncoded(), certificate(store, same).getPublicKey().getEncoded());
            assertEquals(lookups + 2, fixture.provider.lookups.get());
            assertEquals(0, fixture.provider.dispatches.get());
            assertEquals(existing, store.getCa(existing.caId()).orElseThrow());
            store.stagedContent().retireUnownedContent(replacement.content());
            store.stagedContent().retireUnownedContent(same.content());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void retainedRotationSignatureRecoversAndWrongKeyCannotAdvanceAuthority(boolean wrongKey, @TempDir Path root) throws Exception {
        RootCreationFixture fixture = new RootCreationFixture();
        PkiId operation;
        CaRecord existing;
        CertificateProfileRef active;
        try (FilesystemPkiStore store = open(root, RootCreationFixture.CLOCK)) {
            existing = seed(store, fixture);
            active = activateVersionTwo(store);
            DomainSigningRequest prepared = preparer(store, fixture, RootCreationFixture.CLOCK).prepare(RootCreationFixture.ACCESS,
                    new CaKeyRotationCommand.Root(existing.caId(), RootCreationFixture.REPLACEMENT_KEY, new SimpleAttributeSet()),
                    submission(store, fixture), RootCreationFixture.TTL, CancellationSignal.NONE);
            DefaultSemanticSigningService semantic = fixture.semantic(store);
            operation = semantic.accept(semantic.prepare(prepared, existing.caId())).receipt().operationId();
            fixture.wrongSigningKey = wrongKey;
            succeed(store, fixture, operation);
            assertEquals(existing, store.getCa(existing.caId()).orElseThrow());
        }
        try (FilesystemPkiStore store = open(root, RootCreationFixture.CLOCK)) {
            driver(store, fixture).advance(store.getSignWorkflow(operation).orElseThrow());
            assertEquals(wrongKey ? SemanticSigningState.FAILED : SemanticSigningState.COMPLETED,
                    fixture.semantic(store).find(operation).orElseThrow().state());
            CaRecord current = store.getCa(existing.caId()).orElseThrow();
            if (wrongKey) {
                assertEquals(existing, current);
            } else {
                assertEquals(2, current.issuerIds().size());
                assertEquals(existing.issuerIds().getFirst(), current.issuerIds().getFirst());
                assertEquals(current.issuerIds().getLast(), current.currentIssuanceIssuerId());
                assertEquals(RootCreationFixture.REPLACEMENT_KEY, current.issuerKeyRef());
                assertEquals(existing.subjectRef(), current.subjectRef());
                Credential issued = selected(store, current);
                assertEquals(active, ((CaProfileBinding) issued.profileBinding()).reference());
                X509Certificate certificate = Pkix.parseCertificate(PkiTestRuntime.readContent(store, issued.content()));
                certificate.verify(fixture.otherKey.getPublic());
                assertEquals(new X500Principal(existing.subjectRef().value()), certificate.getSubjectX500Principal());
                assertEquals(certificate.getSubjectX500Principal(), new X500Principal(issued.subjectRef().value()));
            }
            assertEquals(2, fixture.provider.lookups.get());
            assertEquals(0, fixture.provider.dispatches.get());
        }
    }

    @Test void authorityProfileAttributesAndRequestedValidityFailBeforeStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root, RootCreationFixture.CLOCK)) {
            RootCreationFixture fixture = new RootCreationFixture();
            CaRecord existing = seed(actual, fixture);
            AtomicInteger stages = new AtomicInteger();
            StagedContentStore staging = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                if (method.equals("beginContent")) stages.incrementAndGet();
                return PROCEED;
            });
            PkiStore store = proxy(PkiStore.class, actual, (method, args) -> method.equals("stagedContent") ? staging : PROCEED);
            RootSigningPreparation preparation = preparer(store, fixture, RootCreationFixture.CLOCK);
            AttributeSet attributes = SimpleAttributeSet.builder().put(new AttributeId("urn:test:override"),
                    new AttributeValue.StringValue("denied")).build();
            for (CaRolloverCommand.Root invalid : List.of(
                    new CaRolloverCommand.Root(new PkiId("missing-root"), Optional.empty(), new SimpleAttributeSet()),
                    new CaRolloverCommand.Root(existing.caId(), Optional.empty(), attributes),
                    new CaRolloverCommand.Root(existing.caId(), Optional.of(new Validity(RootCreationFixture.NOW.minusSeconds(1),
                            RootCreationFixture.NOW.plusSeconds(10))), new SimpleAttributeSet()),
                    new CaRolloverCommand.Root(existing.caId(), Optional.of(new Validity(RootCreationFixture.NOW,
                            RootCreationFixture.NOW.plus(Duration.ofDays(101)))), new SimpleAttributeSet()))) {
                assertThrows(PkiException.class, () -> preparation.prepare(RootCreationFixture.ACCESS, invalid,
                        submission(actual, fixture), RootCreationFixture.TTL, CancellationSignal.NONE));
            }
            assertThrows(PkiException.class, () -> preparation.prepare(RootCreationFixture.ACCESS,
                    new CaKeyRotationCommand.Root(existing.caId(), RootCreationFixture.REPLACEMENT_KEY, attributes),
                    submission(actual, fixture), RootCreationFixture.TTL, CancellationSignal.NONE));
            for (String fault : List.of("kind", "generation", "profile")) {
                PkiStore invalid = proxy(PkiStore.class, store, (method, args) -> {
                    if (fault.equals("kind") && method.equals("getCa")) return Optional.of(new CaRecord(existing.caId(), CaKind.INTERMEDIATE,
                            existing.state(), existing.issuerKeyRef(), existing.subjectRef(), existing.issuerIds(),
                            existing.currentIssuanceIssuerId(), existing.issuanceChainPathId()));
                    if (fault.equals("generation") && method.equals("getIssuerGeneration")) {
                        IssuerGeneration generation = actual.getIssuerGeneration((PkiId) args[0]).orElseThrow();
                        return Optional.of(new IssuerGeneration(generation.issuerId(), generation.authorityId(), generation.credentialId(),
                                generation.signingKeyRef(), IssuerGenerationState.RETIRED, generation.profilePolicyCommitment(), generation.x509BindingCommitment()));
                    }
                    if (fault.equals("profile") && method.equals("getCredential")) {
                        Credential credential = actual.getCredential((PkiId) args[0]).orElseThrow();
                        return Optional.of(new Credential(credential.credentialId(), credential.formatId(), credential.issuerRef(),
                                credential.subjectRef(), credential.validity(), credential.serialOrUniqueId(), credential.publicKeyId(),
                                new EndEntityProfileBinding(((CaProfileBinding) credential.profileBinding()).reference()), credential.status(),
                                credential.content(), credential.attributes()));
                    }
                    return PROCEED;
                });
                assertThrows(PkiException.class, () -> preparer(invalid, fixture, RootCreationFixture.CLOCK).prepare(RootCreationFixture.ACCESS,
                        new CaRolloverCommand.Root(existing.caId(), Optional.empty(), new SimpleAttributeSet()),
                        submission(actual, fixture), RootCreationFixture.TTL, CancellationSignal.NONE));
            }
            actual.putCa(new CaRecord(existing.caId(), existing.kind(), CaState.DISABLED, existing.issuerKeyRef(), existing.subjectRef(),
                    existing.issuerIds(), existing.currentIssuanceIssuerId(), existing.issuanceChainPathId()));
            assertThrows(PkiException.class, () -> preparation.prepare(RootCreationFixture.ACCESS,
                    new CaKeyRotationCommand.Root(existing.caId(), RootCreationFixture.REPLACEMENT_KEY, new SimpleAttributeSet()),
                    submission(actual, fixture), RootCreationFixture.TTL, CancellationSignal.NONE));
            assertEquals(0, stages.get());
            assertEquals(0, fixture.provider.dispatches.get());
        }
    }

    @Test void rootTypedCancellationRetiresOnlyItsSingleStagedCandidate(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root, RootCreationFixture.CLOCK)) {
            RootCreationFixture fixture = new RootCreationFixture();
            CaRecord existing = seed(actual, fixture);
            AtomicBoolean cancelled = new AtomicBoolean();
            AtomicInteger stages = new AtomicInteger();
            AtomicInteger retired = new AtomicInteger();
            StagedContentStore staging = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                if (method.equals("beginContent")) {
                    stages.incrementAndGet();
                    ContentSink sink = actual.stagedContent().beginContent((Encoding) args[0], (DurableContentReference.Lifecycle) args[1]);
                    return proxy(ContentSink.class, sink, (name, ignored) -> {
                        if (name.equals("complete")) {
                            DurableContentReference content = sink.complete();
                            cancelled.set(true);
                            return content;
                        }
                        return PROCEED;
                    });
                }
                if (method.equals("retireUnownedContent")) retired.incrementAndGet();
                return PROCEED;
            });
            PkiStore store = proxy(PkiStore.class, actual, (method, args) -> method.equals("stagedContent") ? staging : PROCEED);
            CaRolloverCommand.Root input = new CaRolloverCommand.Root(existing.caId(), Optional.empty(), new SimpleAttributeSet());
            assertThrows(InterruptedIOException.class, () -> preparer(store, fixture, RootCreationFixture.CLOCK).prepare(RootCreationFixture.ACCESS,
                    input, submission(actual, fixture), RootCreationFixture.TTL, () -> true));
            assertEquals(0, stages.get());
            assertThrows(InterruptedIOException.class, () -> preparer(store, fixture, RootCreationFixture.CLOCK).prepare(RootCreationFixture.ACCESS,
                    input, submission(actual, fixture), RootCreationFixture.TTL, cancelled::get));
            assertEquals(1, stages.get());
            assertEquals(1, retired.get());
            assertEquals(existing, actual.getCa(existing.caId()).orElseThrow());
            assertEquals(0, fixture.provider.dispatches.get());
        }
    }

    private static CaRecord seed(FilesystemPkiStore store, RootCreationFixture fixture) throws Exception {
        fixture.initialize(store);
        DefaultSemanticSigningService semantic = fixture.semantic(store);
        PkiId operation = semantic.accept(semantic.prepareRootCreation(RootCreationFixture.ACCESS, fixture.command(), CancellationSignal.NONE))
                .receipt().operationId();
        succeed(store, fixture, operation);
        driver(store, fixture).advance(store.getSignWorkflow(operation).orElseThrow());
        return store.getCa(DomainCommandEncoding.rootAuthorityId(operation)).orElseThrow();
    }
    private static CertificateProfileRef activateVersionTwo(PkiStore store) throws Exception {
        CertificateProfileDefinition original = store.requireActiveProfile("root-test").definition();
        return RootCreationFixture.install(store, new CertificateProfileDefinition(original.certificateType(), original.profileId(), 2,
                original.formatId(), original.displayName(), Duration.ofDays(30), original.subjectPolicy(), original.certificatePolicy(),
                original.algorithmBindingPolicy()));
    }
    private static Credential selected(PkiStore store, CaRecord ca) {
        return store.getCredential(store.getIssuerGeneration(ca.currentIssuanceIssuerId()).orElseThrow().credentialId()).orElseThrow();
    }
    private static X509Certificate certificate(PkiStore store, DomainSigningRequest request) throws Exception {
        return Pkix.parseCertificate(Pkix.assembleCertificateOrCrl(PkiTestRuntime.readContent(store, request.content()), new byte[] {0}, false));
    }
    private static RootSigningPreparation preparer(PkiStore store, RootCreationFixture fixture, Clock clock) {
        return new RootSigningPreparation(store, clock, fixture.provider, fixture.signing, fixture.bindings,
                RootCreationFixture.ALGORITHM, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES);
    }
    private static SigningSubmissionId submission(PkiStore store, RootCreationFixture fixture) {
        return SigningSubmissionId.create(store.signingNamespace() + "." + fixture.provider.id(), store.signingNow(), new SecureRandom());
    }
    private static void succeed(FilesystemPkiStore store, RootCreationFixture fixture, PkiId operation) throws Exception {
        SignWorkflowStore.Workflow workflow = store.getSignWorkflow(operation).orElseThrow();
        SignWorkflowStore.Workflow claimed = store.claimSignStep(operation, workflow.revision(), Duration.ofSeconds(10)).orElseThrow();
        store.transitionSign(operation, claimed.revision(), claimed.fence(), SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                Optional.of(fixture.signature(PkiTestRuntime.readContent(store, workflow.envelope().candidate()), workflow.envelope().keyRef())),
                Optional.of(store.signingNow()));
    }
    private static SigningOuterTerminalDriver driver(PkiStore store, RootCreationFixture fixture) {
        return new SigningOuterTerminalDriver(store, fixture.verification, fixture.verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES);
    }
    private static FilesystemPkiStore open(Path root, Clock clock) { return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock); }
    private static final Object PROCEED = new Object();
    @FunctionalInterface private interface Intercept { Object call(String method, Object[] args) throws Exception; }
    private static <T> T proxy(Class<T> type, T delegate, Intercept intercept) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (proxy, method, args) -> {
            Object result = intercept.call(method.getName(), args);
            if (result != PROCEED) return result;
            try { return method.invoke(delegate, args); }
            catch (InvocationTargetException failure) { throw failure.getCause(); }
        }));
    }
    private static final class MutableClock extends Clock {
        private Instant now = RootCreationFixture.NOW;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return Clock.fixed(now, zone); }
        @Override public Instant instant() { return now; }
    }
}
