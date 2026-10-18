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
import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.core.continuation.SigningOuterTerminalDriver;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.testkit.RootCreationFixture;
import zeroecho.pkix.Pkix;

final class RootSigningPreparationTest {
    @Test void freezesCanonicalSubjectProfileSpkiAndNarrowedValidityWithoutPublishing(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            RootCreationFixture fixture = new RootCreationFixture();
            CertificateProfileRef profile = fixture.initialize(store);
            DomainSigningRequest first = prepare(fixture, store, fixture.command());
            DomainSigningRequest second = prepare(fixture, store, fixture.command());
            assertNotEquals(first.operationId(), second.operationId());
            assertNotEquals(first.domainTemplate().correlationId(), second.domainTemplate().correlationId());
            assertEquals(2, fixture.provider.lookups.get());
            assertEquals(0, fixture.provider.dispatches.get());
            assertTrue(store.listCas().isEmpty());
            assertTrue(store.getSignWorkflow(first.operationId()).isEmpty());
            assertSame(RootCreationFixture.ACCESS, first.accessContext());
            assertEquals(RootCreationFixture.KEY, first.keyRef());
            assertEquals(Encoding.DER, first.content().encoding());
            assertEquals(DurableContentReference.Lifecycle.OPERATION, first.content().lifecycle());
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(first.domainTemplate().command());
            command.requireFields(14);
            assertEquals("CREATE_ROOT", command.operation());
            assertEquals(DomainCommandEncoding.rootAuthorityId(first.operationId()).value(), command.field(13));
            assertEquals("root-test", command.field(2));
            assertEquals(profile.profileId(), command.field(4));
            assertEquals(Long.toString(profile.profileVersion()), command.field(5));
            assertEquals(HexFormat.of().formatHex(profile.canonicalSha256()), command.field(6));
            byte[] tbs = PkiTestRuntime.readContent(store, first.content());
            X509Certificate certificate = Pkix.parseCertificate(Pkix.assembleCertificateOrCrl(tbs, new byte[] {0}, false));
            assertArrayEquals(fixture.key.getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
            assertEquals(new X500Principal(command.field(1)), certificate.getSubjectX500Principal());
            assertEquals(new X500Principal(command.field(10)), certificate.getSubjectX500Principal());
            assertEquals(certificate.getSubjectX500Principal(), certificate.getIssuerX500Principal());
            assertTrue(command.field(1).contains("C=CZ"));
            assertTrue(command.field(1).contains("O=Frozen Organization"));
            assertEquals(RootCreationFixture.NOW.truncatedTo(ChronoUnit.SECONDS).plusSeconds(1), certificate.getNotBefore().toInstant());
            assertEquals(RootCreationFixture.NOW.plus(Duration.ofDays(100)).truncatedTo(ChronoUnit.SECONDS), certificate.getNotAfter().toInstant());
            assertTrue(certificate.getSerialNumber().signum() > 0);
            assertEquals(2, certificate.getBasicConstraints());
            assertEquals(Set.of("2.5.29.19", "2.5.29.15"), certificate.getCriticalExtensionOIDs());
            boolean[] usage = certificate.getKeyUsage();
            for (int index = 0; index < usage.length; index++) assertEquals(index == 5 || index == 6, usage[index]);
            fixture.exported = new EncodedObject(Encoding.DER, fixture.otherKey.getPublic().getEncoded());
            assertArrayEquals(tbs, PkiTestRuntime.readContent(store, first.content()));
            store.stagedContent().retireUnownedContent(first.content());
            store.stagedContent().retireUnownedContent(second.content());
        }
    }

    @Test void invalidProfileSubjectAttributesAndKeyRejectBeforeAnyStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root)) {
            RootCreationFixture fixture = new RootCreationFixture();
            fixture.initialize(actual);
            RootCreationFixture.install(actual, RootCreationFixture.definition("intermediate-test", CertificateProfileKind.INTERMEDIATE_CA,
                    Duration.ofDays(100), X509AlgorithmBindingPolicy.standardOnly()));
            AtomicInteger stages = new AtomicInteger();
            PkiStore store = observedStages(actual, stages);
            CaCreateCommand good = fixture.command();
            for (CaCreateCommand invalid : List.of(
                    new CaCreateCommand(good.formatId(), good.subjectRef(), "missing-profile", good.keyRef(), good.attributes()),
                    new CaCreateCommand(good.formatId(), good.subjectRef(), "intermediate-test", good.keyRef(), good.attributes()),
                    new CaCreateCommand(new FormatId("other"), good.subjectRef(), good.profileId(), good.keyRef(), good.attributes()),
                    new CaCreateCommand(good.formatId(), new SubjectRef("CN=Root,C=cz,O=Override"), good.profileId(), good.keyRef(), good.attributes()),
                    new CaCreateCommand(good.formatId(), new SubjectRef("CN=Root,CN=Other,C=cz"), good.profileId(), good.keyRef(), good.attributes()),
                    new CaCreateCommand(good.formatId(), new SubjectRef("CN=Root"), good.profileId(), good.keyRef(), good.attributes()),
                    new CaCreateCommand(good.formatId(), good.subjectRef(), good.profileId(), new KeyRef("missing-key"), good.attributes()),
                    new CaCreateCommand(good.formatId(), good.subjectRef(), good.profileId(), good.keyRef(),
                            SimpleAttributeSet.builder().put(new AttributeId("urn:test:override"), new AttributeValue.StringValue("no")).build()))) {
                assertThrows(RuntimeException.class, () -> prepare(fixture, store, invalid));
            }
            assertEquals(0, stages.get());
            assertEquals(0, fixture.provider.dispatches.get());
        }
    }

    @Test void rejectsInvalidPublicKeySourceEncodingAndCanonicalDerBeforeStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root)) {
            RootCreationFixture fixture = new RootCreationFixture();
            fixture.initialize(actual);
            AtomicInteger stages = new AtomicInteger();
            PkiStore store = observedStages(actual, stages);
            byte[] canonical = fixture.key.getPublic().getEncoded();
            byte[] noncanonicalLength = new byte[canonical.length + 1];
            noncanonicalLength[0] = 0x30;
            noncanonicalLength[1] = (byte) 0x81;
            System.arraycopy(canonical, 1, noncanonicalLength, 2, canonical.length - 1);
            for (EncodedObject invalid : List.of(new EncodedObject(Encoding.BINARY, canonical),
                    new EncodedObject(Encoding.DER, new byte[ManagedKeyProofCommand.MAX_SPKI_BYTES + 1]),
                    new EncodedObject(Encoding.DER, new byte[] {0x30, 0}), new EncodedObject(Encoding.DER, noncanonicalLength))) {
                fixture.exported = invalid;
                assertThrows(Exception.class, () -> prepare(fixture, store, fixture.command()));
            }
            // EncodedObject itself prevents an empty provider result from being constructed.
            assertThrows(IllegalArgumentException.class, () -> new EncodedObject(Encoding.DER, new byte[0]));
            fixture.exported = null;
            assertThrows(NullPointerException.class, () -> prepare(fixture, store, fixture.command()));
            SigningProvider noSource = proxy(SigningProvider.class, fixture.provider, (method, arguments) -> PROCEED);
            RootSigningPreparation unavailable = new RootSigningPreparation(store, RootCreationFixture.CLOCK, noSource,
                    PkiTestRuntime.signingAuthority(noSource), fixture.bindings, RootCreationFixture.ALGORITHM, 4_000_000);
            assertThrows(PkiException.class, () -> unavailable.prepare(RootCreationFixture.ACCESS, fixture.command(),
                    fixture.submission(actual), RootCreationFixture.TTL, CancellationSignal.NONE));
            assertEquals(0, stages.get());
            assertEquals(0, fixture.provider.dispatches.get());
        }
    }

    @Test void exactBindingsCapacityValidityAndLifetimeRejectBeforeStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root)) {
            RootCreationFixture fixture = new RootCreationFixture();
            fixture.initialize(actual);
            AtomicInteger stages = new AtomicInteger();
            PkiStore store = observedStages(actual, stages);
            X509AlgorithmBindingPolicy.BindingReference missing = new X509AlgorithmBindingPolicy.BindingReference("missing-binding", "different-commitment");
            for (boolean signature : new boolean[] {false, true}) {
                String id = signature ? "signature-binding" : "spki-binding";
                RootCreationFixture.install(actual, RootCreationFixture.definition(id, CertificateProfileKind.ROOT_CA, Duration.ofDays(100),
                        new X509AlgorithmBindingPolicy(X509AlgorithmBindingPolicy.Mode.EXPLICIT,
                                signature ? Optional.empty() : Optional.of(missing), Optional.empty(),
                                signature ? Optional.of(missing) : Optional.empty(), Optional.empty())));
                CaCreateCommand good = fixture.command();
                assertThrows(RuntimeException.class, () -> prepare(fixture, store,
                        new CaCreateCommand(good.formatId(), good.subjectRef(), id, good.keyRef(), good.attributes())));
            }
            fixture.inputMaximum = 1;
            assertThrows(IllegalArgumentException.class, () -> prepare(fixture, store, fixture.command()));
            fixture.inputMaximum = 4_000_000;
            RootSigningPreparation smallEdDsa = new RootSigningPreparation(store, RootCreationFixture.CLOCK, fixture.provider,
                    fixture.signing, fixture.bindings, RootCreationFixture.ALGORITHM, 1);
            assertThrows(IllegalArgumentException.class, () -> smallEdDsa.prepare(RootCreationFixture.ACCESS, fixture.command(),
                    fixture.submission(actual), RootCreationFixture.TTL, CancellationSignal.NONE));
            RootCreationFixture.install(actual, RootCreationFixture.definition("short-root", CertificateProfileKind.ROOT_CA,
                    Duration.ofSeconds(1), X509AlgorithmBindingPolicy.standardOnly()));
            CaCreateCommand good = fixture.command();
            assertThrows(PkiException.class, () -> prepare(fixture, store,
                    new CaCreateCommand(good.formatId(), good.subjectRef(), "short-root", good.keyRef(), good.attributes())));
            for (Duration lifetime : List.of(Duration.ZERO, Duration.ofSeconds(-1), Duration.ofSeconds(Long.MAX_VALUE))) {
                assertThrows(RuntimeException.class, () -> fixture.preparer(store).prepare(RootCreationFixture.ACCESS,
                        good, fixture.submission(actual), lifetime, CancellationSignal.NONE));
            }
            assertEquals(0, stages.get());
            assertEquals(0, fixture.provider.dispatches.get());
        }
    }

    @Test void cancellationDiscardAndFailedAdoptionRetireOnlyUnownedContent(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root)) {
            RootCreationFixture fixture = new RootCreationFixture();
            fixture.initialize(actual);
            AtomicInteger stages = new AtomicInteger();
            AtomicInteger retired = new AtomicInteger();
            AtomicBoolean cancelled = new AtomicBoolean();
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
            assertThrows(InterruptedIOException.class, () -> fixture.preparer(store).prepare(RootCreationFixture.ACCESS,
                    fixture.command(), fixture.submission(actual), RootCreationFixture.TTL, () -> true));
            assertEquals(0, stages.get());
            assertThrows(InterruptedIOException.class, () -> fixture.preparer(store).prepare(RootCreationFixture.ACCESS,
                    fixture.command(), fixture.submission(actual), RootCreationFixture.TTL, cancelled::get));
            assertEquals(1, stages.get());
            assertEquals(1, retired.get());
            StagedContentStore adoption = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                if (method.equals("restoreReference")) throw new IOException("Controlled adoption failure");
                if (method.equals("retireUnownedContent")) retired.incrementAndGet();
                return PROCEED;
            });
            PkiStore adoptionStore = proxy(PkiStore.class, actual, (method, args) -> method.equals("stagedContent") ? adoption : PROCEED);
            assertThrows(PkiException.class, () -> fixture.semantic(adoptionStore).prepareRootCreation(RootCreationFixture.ACCESS,
                    fixture.command(), CancellationSignal.NONE));
            assertEquals(2, retired.get());
            DefaultSemanticSigningService semantic = fixture.semantic(actual);
            PreparedSemanticSigningRequest prepared = semantic.prepareRootCreation(RootCreationFixture.ACCESS,
                    fixture.command(), CancellationSignal.NONE);
            semantic.discard(prepared);
            assertThrows(IllegalStateException.class, () -> semantic.accept(prepared));
            assertThrows(IllegalStateException.class, () -> semantic.discard(prepared));
            assertTrue(actual.getSignWorkflow(prepared.receipt().operationId()).isEmpty());
            assertEquals(0, fixture.provider.dispatches.get());
        }
    }

    @Test void durableSignatureCompletesAfterReopenWithoutAnotherPublicKeyLookupOrSignature(@TempDir Path root) throws Exception {
        RootCreationFixture fixture = new RootCreationFixture();
        PkiId operation;
        try (FilesystemPkiStore store = open(root)) {
            fixture.initialize(store);
            DefaultSemanticSigningService semantic = fixture.semantic(store);
            PreparedSemanticSigningRequest prepared = semantic.prepareRootCreation(RootCreationFixture.ACCESS,
                    fixture.command(), CancellationSignal.NONE);
            operation = semantic.accept(prepared).receipt().operationId();
            SignWorkflowStore.Workflow current = store.getSignWorkflow(operation).orElseThrow();
            byte[] tbs = PkiTestRuntime.readContent(store, current.envelope().candidate());
            SignWorkflowStore.Workflow claimed = store.claimSignStep(operation, current.revision(), Duration.ofSeconds(10)).orElseThrow();
            store.transitionSign(operation, claimed.revision(), claimed.fence(), SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                    Optional.of(fixture.signature(tbs)), Optional.of(RootCreationFixture.NOW));
            assertTrue(store.listCas().isEmpty());
        }
        fixture.exported = new EncodedObject(Encoding.DER, fixture.otherKey.getPublic().getEncoded());
        try (FilesystemPkiStore store = open(root)) {
            new SigningOuterTerminalDriver(store, fixture.verification, fixture.verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES)
                    .advance(store.getSignWorkflow(operation).orElseThrow());
            assertEquals(SemanticSigningState.COMPLETED, fixture.semantic(store).find(operation).orElseThrow().state());
            assertEquals(1, store.getCa(DomainCommandEncoding.rootAuthorityId(operation)).orElseThrow().issuerIds().size());
            assertEquals(1, fixture.provider.lookups.get());
            assertEquals(0, fixture.provider.dispatches.get());
        }
    }

    private static FilesystemPkiStore open(Path root) { return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), RootCreationFixture.CLOCK); }
    private static DomainSigningRequest prepare(RootCreationFixture fixture, PkiStore store, CaCreateCommand command) throws IOException {
        return fixture.preparer(store).prepare(RootCreationFixture.ACCESS, command, fixture.submission(store),
                RootCreationFixture.TTL, CancellationSignal.NONE);
    }
    private static PkiStore observedStages(PkiStore actual, AtomicInteger stages) {
        StagedContentStore staged = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
            if (method.equals("beginContent")) stages.incrementAndGet();
            return PROCEED;
        });
        return proxy(PkiStore.class, actual, (method, args) -> method.equals("stagedContent") ? staged : PROCEED);
    }
    private static final Object PROCEED = new Object();
    @FunctionalInterface private interface Intercept { Object call(String method, Object[] arguments) throws Exception; }
    private static <T> T proxy(Class<T> type, T delegate, Intercept intercept) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (proxy, method, arguments) -> {
            Object result = intercept.call(method.getName(), arguments);
            if (result != PROCEED) return result;
            try { return method.invoke(delegate, arguments); }
            catch (InvocationTargetException failure) { throw failure.getCause(); }
        }));
    }
}
