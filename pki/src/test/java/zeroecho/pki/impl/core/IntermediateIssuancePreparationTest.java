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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.InterruptedIOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.profile.CertificateProfileRef;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.core.continuation.SigningOuterTerminalDriver;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.IntermediateIssuanceFixture;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.testkit.RootCreationFixture;
import zeroecho.pkix.Pkix;

final class IntermediateIssuancePreparationTest {
    @Test void trustedPrincipalUsesDerOrderAndRetainsExistingStringOverloadPolicy() {
        CertificateProfileDefinition profile = RootCreationFixture.definition("subject-policy", CertificateProfileKind.INTERMEDIATE_CA,
                Duration.ofDays(30), X509AlgorithmBindingPolicy.standardOnly());
        assertEquals(IntermediateIssuanceFixture.PRINCIPAL, BcX509ProfileSupport.subject(
                CaCertificateProfileValidator.validateTrustedSubject(IntermediateIssuanceFixture.PRINCIPAL, profile)));
        assertEquals(CaCertificateProfileValidator.validateTrustedSubject(IntermediateIssuanceFixture.PRINCIPAL, profile),
                CaCertificateProfileValidator.validateTrustedSubject(new SubjectRef("CN=Existing Intermediate,C=CZ,O=Frozen Organization"), profile));
        assertThrows(PkiException.class, () -> CaCertificateProfileValidator.validateTrustedSubject(
                new X500Principal("O=Changed,C=CZ,CN=Existing Intermediate"), profile));
    }

    @Test void freezesExplicitProfileAuthoritativePrincipalAndRequestedValidityWithoutAcceptance(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root, IntermediateCreationFixture.CLOCK)) {
            IntermediateIssuanceFixture fixture = new IntermediateIssuanceFixture();
            fixture.initialize(store);
            CaRecord before = store.getCa(IntermediateIssuanceFixture.SUBJECT).orElseThrow();
            int lookups = fixture.base.provider.lookups;
            IntermediateCertIssueCommand command = fixture.command();
            Validity requested = new Validity(IntermediateCreationFixture.NOW, IntermediateCreationFixture.NOW.plus(Duration.ofDays(10)));
            DomainSigningRequest prepared = fixture.preparer(store, IntermediateCreationFixture.CLOCK).prepare(IntermediateCreationFixture.ACCESS,
                    new IntermediateCertIssueCommand(command.formatId(), command.issuerCaId(), command.subjectCaId(), command.profileId(),
                            command.keyRef(), Optional.of(requested), command.attributes()), fixture.base.submission(store),
                    IntermediateCreationFixture.TTL, CancellationSignal.NONE);
            DomainCommandEncoding.Decoded frozen = DomainCommandEncoding.decode(prepared.domainTemplate().command());
            assertEquals("ISSUE_INTERMEDIATE", frozen.operation());
            assertEquals(IntermediateIssuanceFixture.PROFILE, frozen.field(7));
            assertEquals(before.subjectRef().value(), frozen.field(10));
            assertEquals(before.caId().value(), frozen.field(2));
            assertSame(IntermediateCreationFixture.ACCESS, prepared.accessContext());
            X509Certificate certificate = Pkix.parseCertificate(Pkix.assembleCertificateOrCrl(
                    PkiTestRuntime.readContent(store, prepared.content()), new byte[] {0}, false));
            assertEquals(IntermediateIssuanceFixture.PRINCIPAL, certificate.getSubjectX500Principal());
            assertEquals(new X500Principal(frozen.field(10)), certificate.getSubjectX500Principal());
            assertArrayEquals(fixture.base.childKey.getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
            assertEquals(requested.notBefore(), certificate.getNotBefore().toInstant());
            assertEquals(requested.notAfter(), certificate.getNotAfter().toInstant());
            assertEquals(before, store.getCa(before.caId()).orElseThrow());
            assertTrue(store.getSignWorkflow(prepared.operationId()).isEmpty());
            // Internal proof preparation freezes the current subject SPKI in exactly one provider lookup.
            assertEquals(lookups + 1, fixture.base.provider.lookups);
            assertEquals(0, fixture.base.provider.dispatches);
            for (zeroecho.pki.api.content.DurableContentReference candidate : prepared.candidates()) {
                store.stagedContent().retireUnownedContent(candidate);
            }
        }
    }

    @Test void rejectsStaleKeyProfileKindInactiveSubjectAndAttributesBeforeStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root, IntermediateCreationFixture.CLOCK)) {
            IntermediateIssuanceFixture fixture = new IntermediateIssuanceFixture();
            fixture.initialize(actual);
            AtomicInteger stages = new AtomicInteger();
            StagedContentStore staging = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                if (method.equals("beginContent")) stages.incrementAndGet();
                return PROCEED;
            });
            PkiStore store = proxy(PkiStore.class, actual, (method, args) -> method.equals("stagedContent") ? staging : PROCEED);
            IntermediateCertIssueCommand good = fixture.command();
            for (IntermediateCertIssueCommand invalid : List.of(
                    new IntermediateCertIssueCommand(good.formatId(), good.issuerCaId(), good.subjectCaId(), good.profileId(),
                            new KeyRef("stale-key"), good.requestedValidity(), good.attributes()),
                    new IntermediateCertIssueCommand(good.formatId(), good.issuerCaId(), good.subjectCaId(), "root-ca",
                            good.keyRef(), good.requestedValidity(), good.attributes()),
                    new IntermediateCertIssueCommand(good.formatId(), good.issuerCaId(), good.issuerCaId(), good.profileId(),
                            IntermediateCreationFixture.PARENT_KEY, good.requestedValidity(), good.attributes()),
                    new IntermediateCertIssueCommand(good.formatId(), good.issuerCaId(), good.subjectCaId(), good.profileId(),
                            good.keyRef(), Optional.of(new Validity(IntermediateCreationFixture.NOW.minusSeconds(1),
                                    IntermediateCreationFixture.NOW.plusSeconds(60))), good.attributes()),
                    new IntermediateCertIssueCommand(good.formatId(), good.issuerCaId(), good.subjectCaId(), good.profileId(),
                            good.keyRef(), good.requestedValidity(), SimpleAttributeSet.builder()
                                    .put(new AttributeId("urn:test:override"), new AttributeValue.StringValue("denied")).build()))) {
                assertThrows(RuntimeException.class, () -> fixture.preparer(store, IntermediateCreationFixture.CLOCK).prepare(
                        IntermediateCreationFixture.ACCESS, invalid, fixture.base.submission(actual), IntermediateCreationFixture.TTL, CancellationSignal.NONE));
            }
            CaRecord current = actual.getCa(good.subjectCaId()).orElseThrow();
            actual.putCa(new CaRecord(current.caId(), current.kind(), CaState.DISABLED, current.issuerKeyRef(), current.subjectRef(),
                    current.issuerIds(), current.currentIssuanceIssuerId(), current.issuanceChainPathId()));
            assertThrows(PkiException.class, () -> fixture.preparer(store, IntermediateCreationFixture.CLOCK).prepare(
                    IntermediateCreationFixture.ACCESS, good, fixture.base.submission(actual), IntermediateCreationFixture.TTL, CancellationSignal.NONE));
            assertEquals(0, stages.get());
            assertEquals(0, fixture.base.provider.dispatches);
        }
    }

    @Test void cancellationAfterStagingRetiresTheSingleUnownedCandidate(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root, IntermediateCreationFixture.CLOCK)) {
            IntermediateIssuanceFixture fixture = new IntermediateIssuanceFixture();
            fixture.initialize(actual);
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
            assertThrows(InterruptedIOException.class, () -> fixture.preparer(store, IntermediateCreationFixture.CLOCK).prepare(
                    IntermediateCreationFixture.ACCESS, fixture.command(), fixture.base.submission(actual), IntermediateCreationFixture.TTL, () -> true));
            assertEquals(0, stages.get());
            assertThrows(InterruptedIOException.class, () -> fixture.preparer(store, IntermediateCreationFixture.CLOCK).prepare(
                    IntermediateCreationFixture.ACCESS, fixture.command(), fixture.base.submission(actual), IntermediateCreationFixture.TTL, cancelled::get));
            assertEquals(1, stages.get());
            assertEquals(1, retired.get());
            assertEquals(0, fixture.base.provider.dispatches);
        }
    }

    @Test void lifecycleUsesActiveProfileBeyondOldExpiryAndAllowsSameKeyRotation(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root, IntermediateCreationFixture.CLOCK)) {
            IntermediateIssuanceFixture fixture = new IntermediateIssuanceFixture();
            fixture.initialize(store);
            CaRecord before = store.getCa(IntermediateIssuanceFixture.SUBJECT).orElseThrow();
            Credential old = store.getCredential(store.getIssuerGeneration(before.currentIssuanceIssuerId()).orElseThrow().credentialId()).orElseThrow();
            assertEquals(1, ((CaProfileBinding) old.profileBinding()).reference().profileVersion());
            CertificateProfileRef active = fixture.activateLifecycleVersionTwo(store);
            Instant evaluation = IntermediateCreationFixture.NOW.plus(Duration.ofDays(91));
            assertTrue(evaluation.isAfter(old.validity().notAfter()));
            Clock clock = Clock.fixed(evaluation, ZoneOffset.UTC);
            Validity requested = new Validity(evaluation, evaluation.plus(Duration.ofDays(5)));
            IntermediateSigningPreparation preparation = fixture.preparer(store, clock);
            int lookups = fixture.base.provider.lookups;
            DomainSigningRequest rollover = preparation.prepare(IntermediateCreationFixture.ACCESS,
                    new CaRolloverCommand.Intermediate(before.caId(), IntermediateCreationFixture.CA, before.issuerKeyRef(),
                            Optional.of(requested), new SimpleAttributeSet()), fixture.base.submission(store),
                    IntermediateCreationFixture.TTL, CancellationSignal.NONE);
            DomainSigningRequest rotation = preparation.prepare(IntermediateCreationFixture.ACCESS,
                    new CaKeyRotationCommand.Intermediate(before.caId(), before.issuerKeyRef(), IntermediateCreationFixture.CA,
                            new SimpleAttributeSet()), fixture.base.submission(store), IntermediateCreationFixture.TTL, CancellationSignal.NONE);
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(rollover.domainTemplate().command());
            assertEquals("ROLLOVER_INTERMEDIATE", command.operation());
            assertEquals(active.profileId(), command.field(7));
            assertEquals("2", command.field(8));
            assertEquals(before.issuerKeyRef().value(), command.field(6));
            assertEquals(IntermediateCreationFixture.PARENT_KEY.value(), command.field(14));
            X509Certificate certificate = Pkix.parseCertificate(Pkix.assembleCertificateOrCrl(
                    PkiTestRuntime.readContent(store, rollover.content()), new byte[] {0}, false));
            assertEquals(IntermediateIssuanceFixture.PRINCIPAL, certificate.getSubjectX500Principal());
            assertEquals(before.subjectRef().value(), command.field(10));
            assertEquals(requested.notBefore(), certificate.getNotBefore().toInstant());
            assertEquals(requested.notAfter(), certificate.getNotAfter().toInstant());
            X509Certificate rotated = Pkix.parseCertificate(Pkix.assembleCertificateOrCrl(
                    PkiTestRuntime.readContent(store, rotation.content()), new byte[] {0}, false));
            assertArrayEquals(fixture.base.childKey.getPublic().getEncoded(), rotated.getPublicKey().getEncoded());
            assertEquals(lookups + 2, fixture.base.provider.lookups);
            assertEquals(0, fixture.base.provider.dispatches);
            assertTrue(store.getSignWorkflow(rollover.operationId()).isEmpty());
            assertTrue(store.getSignWorkflow(rotation.operationId()).isEmpty());
            assertEquals(before, store.getCa(before.caId()).orElseThrow());
            for (zeroecho.pki.api.content.DurableContentReference candidate : rollover.candidates()) {
                store.stagedContent().retireUnownedContent(candidate);
            }
            for (zeroecho.pki.api.content.DurableContentReference candidate : rotation.candidates()) {
                store.stagedContent().retireUnownedContent(candidate);
            }
        }
    }

    @Test void lifecycleRejectsStaleKeyAttributesAndInactiveAuthorityBeforeStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root, IntermediateCreationFixture.CLOCK)) {
            IntermediateIssuanceFixture fixture = new IntermediateIssuanceFixture();
            fixture.initialize(actual);
            CertificateProfileRef active = fixture.activateLifecycleVersionTwo(actual);
            CaRecord before = actual.getCa(IntermediateIssuanceFixture.SUBJECT).orElseThrow();
            AtomicInteger stages = new AtomicInteger();
            StagedContentStore staging = proxy(StagedContentStore.class, actual.stagedContent(), (name, args) -> {
                if (name.equals("beginContent")) stages.incrementAndGet();
                return PROCEED;
            });
            PkiStore store = proxy(PkiStore.class, actual, (name, args) -> name.equals("stagedContent") ? staging : PROCEED);
            IntermediateSigningPreparation preparation = fixture.preparer(store, IntermediateCreationFixture.CLOCK);
            assertThrows(PkiException.class, () -> preparation.prepare(IntermediateCreationFixture.ACCESS,
                    rollover(before, new KeyRef("stale-key")), fixture.base.submission(actual), IntermediateCreationFixture.TTL, CancellationSignal.NONE));
            AttributeSet attributes = SimpleAttributeSet.builder().put(new AttributeId("urn:test:override"),
                    new AttributeValue.StringValue("denied")).build();
            assertThrows(PkiException.class, () -> preparation.prepare(IntermediateCreationFixture.ACCESS,
                    new CaKeyRotationCommand.Intermediate(before.caId(), before.issuerKeyRef(), IntermediateCreationFixture.CA, attributes),
                    fixture.base.submission(actual), IntermediateCreationFixture.TTL, CancellationSignal.NONE));
            assertThrows(PkiException.class, () -> preparation.prepare(IntermediateCreationFixture.ACCESS,
                    new CaRolloverCommand.Intermediate(before.caId(), IntermediateCreationFixture.CA, before.issuerKeyRef(),
                            Optional.of(new Validity(IntermediateCreationFixture.NOW, IntermediateCreationFixture.NOW.plus(Duration.ofDays(31)))),
                            new SimpleAttributeSet()), fixture.base.submission(actual), IntermediateCreationFixture.TTL, CancellationSignal.NONE));
            assertThrows(InterruptedIOException.class, () -> preparation.prepare(IntermediateCreationFixture.ACCESS,
                    rollover(before, before.issuerKeyRef()), fixture.base.submission(actual), IntermediateCreationFixture.TTL, () -> true));
            actual.putCa(new CaRecord(before.caId(), before.kind(), CaState.DISABLED, before.issuerKeyRef(), before.subjectRef(),
                    before.issuerIds(), before.currentIssuanceIssuerId(), before.issuanceChainPathId()));
            assertThrows(PkiException.class, () -> preparation.prepare(IntermediateCreationFixture.ACCESS,
                    rollover(before, before.issuerKeyRef()), fixture.base.submission(actual), IntermediateCreationFixture.TTL, CancellationSignal.NONE));
            assertEquals(0, stages.get());
            assertEquals(0, fixture.base.provider.dispatches);
        }
    }

    private static CaRolloverCommand.Intermediate rollover(CaRecord ca, KeyRef key) {
        return new CaRolloverCommand.Intermediate(ca.caId(), IntermediateCreationFixture.CA, key, Optional.empty(), new SimpleAttributeSet());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void preparedIssuanceOrRotationResumesInternalVerificationAfterReopen(boolean rotation, @TempDir Path root) throws Exception {
        IntermediateIssuanceFixture fixture = new IntermediateIssuanceFixture();
        MutableClock clock = new MutableClock();
        PkiId operation;
        CaRecord before;
        CertificateProfileRef active = null;
        int lookups;
        try (FilesystemPkiStore store = open(root, clock)) {
            fixture.initialize(store);
            before = store.getCa(IntermediateIssuanceFixture.SUBJECT).orElseThrow();
            if (rotation) {
                active = fixture.activateLifecycleVersionTwo(store);
            }
            clock.now = IntermediateCreationFixture.NOW.plus(store.signingHorizon()).minusSeconds(10);
            DefaultSemanticSigningService semantic = fixture.semantic(store, clock);
            PreparedSemanticSigningRequest prepared = rotation
                    ? semantic.prepareCaKeyRotation(IntermediateCreationFixture.ACCESS,
                            new CaKeyRotationCommand.Intermediate(before.caId(), IntermediateCreationFixture.ROTATED_KEY,
                                    IntermediateCreationFixture.CA, new SimpleAttributeSet()), CancellationSignal.NONE)
                    : semantic.prepareIntermediateIssuance(IntermediateCreationFixture.ACCESS, fixture.command(), CancellationSignal.NONE);
            operation = semantic.accept(prepared).receipt().operationId();
            lookups = fixture.base.provider.lookups;
            fixture.base.checkpointProof(store, operation);
            SignWorkflowStore.Workflow verifying = store.getSignWorkflow(operation).orElseThrow();
            assertEquals(SignWorkflowStore.Stage.CA_PROOF_VERIFYING, verifying.stage());
            assertTrue(store.getSignWorkflow(verifying.envelope().proofStep().orElseThrow().operationId()).isEmpty());

        }
        try (FilesystemPkiStore store = open(root, clock)) {
            fixture.base.signCertificate(store, operation);
            new SigningOuterTerminalDriver(store, fixture.base.verification, fixture.base.verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES)
                    .advance(store.getSignWorkflow(operation).orElseThrow());
            assertEquals(SemanticSigningState.COMPLETED, fixture.semantic(store, clock).find(operation).orElseThrow().state());
            CaRecord after = store.getCa(before.caId()).orElseThrow();
            assertEquals(2, after.issuerIds().size());
            assertEquals(before.issuerIds().getFirst(), after.issuerIds().getFirst());
            if (rotation) {
                assertEquals(after.issuerIds().getLast(), after.currentIssuanceIssuerId());
                assertEquals(IntermediateCreationFixture.ROTATED_KEY, after.issuerKeyRef());
                assertTrue(!before.issuanceChainPathId().equals(after.issuanceChainPathId()));
            } else {
                assertEquals(before, new CaRecord(after.caId(), after.kind(), after.state(), after.issuerKeyRef(), after.subjectRef(),
                        List.of(after.issuerIds().getFirst()), after.currentIssuanceIssuerId(), after.issuanceChainPathId()));
            }
            Credential issued = store.getCredential(store.getIssuerGeneration(after.issuerIds().getLast()).orElseThrow().credentialId()).orElseThrow();
            if (rotation) {
                assertEquals(active, ((CaProfileBinding) issued.profileBinding()).reference());
                X509Certificate certificate = Pkix.parseCertificate(PkiTestRuntime.readContent(store, issued.content()));
                certificate.verify(fixture.base.parentKey.getPublic());
                assertArrayEquals(fixture.base.rotatedKey.getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
            } else {
                assertEquals(IntermediateIssuanceFixture.PROFILE, ((CaProfileBinding) issued.profileBinding()).reference().profileId());
            }
            assertEquals(lookups, fixture.base.provider.lookups);
            assertEquals(before.subjectRef(), issued.subjectRef());
            assertEquals(0, fixture.base.provider.dispatches);
        }
    }

    private static FilesystemPkiStore open(Path path, Clock clock) { return new FilesystemPkiStore(path, FsPkiStoreOptions.defaults(), clock); }
    private static final Object PROCEED = new Object();
    @FunctionalInterface private interface Intercept { Object call(String name, Object[] args) throws Exception; }
    private static <T> T proxy(Class<T> type, T delegate, Intercept intercept) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (proxy, method, args) -> {
            Object result = intercept.call(method.getName(), args);
            if (result != PROCEED) return result;
            try { return method.invoke(delegate, args); }
            catch (InvocationTargetException failure) { throw failure.getCause(); }
        }));
    }
    private static final class MutableClock extends Clock {
        private Instant now = IntermediateCreationFixture.NOW;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return Clock.fixed(now, zone); }
        @Override public Instant instant() { return now; }
    }
}
