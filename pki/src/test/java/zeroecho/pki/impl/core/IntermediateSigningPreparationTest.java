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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.InterruptedIOException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.core.signing.DefaultSigningService;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pkix.Pkix;

final class IntermediateSigningPreparationTest {
    @Test void existingLegacySubjectRotationPreservesActualDerAndMetadata(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(store, 2);
            fixture.legacyIntermediateParent(store, 1);
            zeroecho.pki.api.profile.CertificateProfileDefinition base = store.requireActiveProfile("intermediate-ca").definition();
            zeroecho.pki.testkit.RootCreationFixture.install(store, new zeroecho.pki.api.profile.CertificateProfileDefinition(
                    base.certificateType(), base.profileId(), 2, base.formatId(), base.displayName(), base.maximumValidity(),
                    new zeroecho.pki.api.profile.SubjectPolicy(false, java.util.List.of(
                            new zeroecho.pki.api.profile.SubjectRdnRule(zeroecho.pki.api.profile.SubjectRdnType.COMMON_NAME,
                                    1, 1, 128, Optional.empty(), true),
                            new zeroecho.pki.api.profile.SubjectRdnRule(zeroecho.pki.api.profile.SubjectRdnType.COUNTRY_NAME,
                                    1, 1, 2, Optional.empty(), true))), base.certificatePolicy()));
            PkiId middle = new PkiId("middle-authority");
            String oldMetadata = store.getCa(middle).orElseThrow().subjectRef().value();
            zeroecho.pki.api.ca.CaKeyRotationCommand.Intermediate rotation = new zeroecho.pki.api.ca.CaKeyRotationCommand.Intermediate(
                    middle, IntermediateCreationFixture.ROTATED_KEY, IntermediateCreationFixture.CA,
                    new zeroecho.pki.impl.core.attr.SimpleAttributeSet());
            DomainSigningRequest prepared = fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS, rotation,
                    fixture.submission(store), IntermediateCreationFixture.TTL, CancellationSignal.NONE);
            byte[] tbs = PkiTestRuntime.readContent(store, prepared.content());
            X509Certificate certificate = Pkix.parseCertificate(Pkix.assembleCertificateOrCrl(tbs, new byte[]{0}, false));
            assertEquals(new javax.security.auth.x500.X500Principal("CN=Legacy Middle,C=CZ"), certificate.getSubjectX500Principal());
            assertEquals(oldMetadata, DomainCommandEncoding.decode(prepared.domainTemplate().command()).field(10));
            for (zeroecho.pki.api.content.DurableContentReference candidate : prepared.candidates()) {
                store.stagedContent().retireUnownedContent(candidate);
            }
        }
    }
    @Test void enforcesEveryPathLevelAndCountsOnlyNonSelfIssuedCertificates(@TempDir Path root) throws Exception {
        for (int scenario = 0; scenario < 3; scenario++) {
            try (FilesystemPkiStore store = open(root.resolve(Integer.toString(scenario)))) {
                IntermediateCreationFixture fixture = new IntermediateCreationFixture();
                // Scenario 0: direct parent's zero limit binds despite anchor capacity.
                // Scenario 1: the anchor permits its child but not a non-self-issued grandchild.
                // Scenario 2: a self-issued middle CA does not consume an anchor path slot.
                fixture.initialize(store, scenario == 0 ? 2 : 1);
                zeroecho.pki.api.ca.IntermediateCreateCommand grandchild = fixture.intermediateParent(store,
                        scenario == 0 ? 0 : 1, scenario == 2);
                if (scenario != 2) {
                    PkiException denied = assertThrows(PkiException.class, () -> fixture.preparer(store).prepare(
                            IntermediateCreationFixture.ACCESS, grandchild, fixture.submission(store),
                            IntermediateCreationFixture.TTL, CancellationSignal.NONE));
                    assertTrue(denied.getMessage().contains("PATH_LENGTH_EXCEEDED"));
                } else {
                    DomainSigningRequest prepared = fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                            grandchild, fixture.submission(store), IntermediateCreationFixture.TTL, CancellationSignal.NONE);
                    for (zeroecho.pki.api.content.DurableContentReference candidate : prepared.candidates()) {
                        store.stagedContent().retireUnownedContent(candidate);
                    }
                }
                // A self-issued new child consumes no slot at its direct parent.
                zeroecho.pki.api.ca.IntermediateCreateCommand selfIssuedChild = new zeroecho.pki.api.ca.IntermediateCreateCommand(
                        grandchild.formatId(), grandchild.issuerCaId(), new zeroecho.pki.api.SubjectRef(scenario == 2 ? "CN=Parent" : "CN=Middle"),
                        grandchild.profileId(), grandchild.keyRef(), grandchild.attributes());
                DomainSigningRequest prepared = fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                        selfIssuedChild, fixture.submission(store), IntermediateCreationFixture.TTL, CancellationSignal.NONE);
                for (zeroecho.pki.api.content.DurableContentReference candidate : prepared.candidates()) {
                    store.stagedContent().retireUnownedContent(candidate);
                }
                assertEquals(0, fixture.provider.dispatches);
            }
        }
    }

    @Test void substitutedCandidateRejectsAtAdoptionAndAcceptanceBeforeDispatch(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(store, 1);
            for (int extra : new int[] {0, 1}) {
                DomainSigningRequest original = fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                        fixture.command("CN=Child"), fixture.submission(store), IntermediateCreationFixture.TTL, CancellationSignal.NONE);
                byte[] exact = PkiTestRuntime.readContent(store, original.content());
                byte[] changed = java.util.Arrays.copyOf(exact, exact.length + extra);
                changed[changed.length - 1] ^= 1;
                zeroecho.pki.api.content.DurableContentReference candidate = PkiTestRuntime.operationReference(store.stagedContent(),
                        zeroecho.pki.api.Encoding.DER, changed);
                DomainSigningRequest substituted = new DomainSigningRequest(original.operationId(), original.accessContext(),
                        original.keyRef(), original.algorithmId(), original.signatureEncoding(), candidate, original.ttl(), original.domainTemplate(), original.proofStep());
                assertThrows(RuntimeException.class, () -> semantic(store, fixture).prepare(substituted, IntermediateCreationFixture.CA));
                assertArrayEquals(changed, PkiTestRuntime.readContent(store, candidate));
                assertThrows(RuntimeException.class, () -> fixture.accept(store, substituted));
                assertTrue(store.getSignWorkflow(original.operationId()).isEmpty());
                // Definite acceptance rejection owns the one cleanup; the test must not retire it again.
                assertThrows(IOException.class, () -> PkiTestRuntime.readContent(store, candidate));
                assertThrows(IOException.class, () -> PkiTestRuntime.readContent(store, original.proofStep().orElseThrow().challenge()));
                store.stagedContent().retireUnownedContent(original.content());
            }
            assertEquals(0, fixture.provider.dispatches);
        }
    }

    @Test void cancellationAfterFirstStageAndAdoptionFailureRetireOwnedCandidates(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(actual, 1);
            AtomicBoolean cancelled = new AtomicBoolean();
            AtomicInteger staged = new AtomicInteger();
            AtomicInteger retired = new AtomicInteger();
            StagedContentStore staging = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                if (method.equals("beginContent")) {
                    staged.incrementAndGet();
                    ContentSink sink = actual.stagedContent().beginContent((zeroecho.pki.api.Encoding) args[0],
                            (zeroecho.pki.api.content.DurableContentReference.Lifecycle) args[1]);
                    return proxy(ContentSink.class, sink, (sinkMethod, ignored) -> {
                        if (sinkMethod.equals("complete")) {
                            zeroecho.pki.api.content.DurableContentReference content = sink.complete();
                            cancelled.set(true);
                            return content;
                        }
                        return PROCEED;
                    });
                }
                if (method.equals("retireUnownedContent")) { retired.incrementAndGet(); }
                return PROCEED;
            });
            PkiStore cancellationStore = proxy(PkiStore.class, actual, (method, args) -> method.equals("stagedContent") ? staging : PROCEED);
            assertThrows(InterruptedIOException.class, () -> fixture.preparer(cancellationStore).prepare(
                    IntermediateCreationFixture.ACCESS, fixture.command("CN=Child"), fixture.submission(actual),
                    IntermediateCreationFixture.TTL, cancelled::get));
            assertEquals(1, staged.get());
            assertEquals(1, retired.get());

            StagedContentStore adoptionStaging = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                if (method.equals("restoreReference")) { throw new IOException("Controlled adoption failure"); }
                if (method.equals("retireUnownedContent")) { retired.incrementAndGet(); }
                return PROCEED;
            });
            PkiStore adoptionStore = proxy(PkiStore.class, actual, (method, args) -> method.equals("stagedContent") ? adoptionStaging : PROCEED);
            assertThrows(PkiException.class, () -> semantic(adoptionStore, fixture).prepareIntermediateCreation(
                    IntermediateCreationFixture.ACCESS, fixture.command("CN=Child"), CancellationSignal.NONE));
            assertEquals(3, retired.get());
            assertEquals(0, fixture.provider.dispatches);
        }
    }

    @Test void invalidIssuerAndProfileRejectBeforeStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(actual, 1);
            AtomicInteger stages = new AtomicInteger();
            StagedContentStore staging = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                if (method.equals("beginContent")) { stages.incrementAndGet(); }
                return PROCEED;
            });
            PkiStore store = proxy(PkiStore.class, actual, (method, args) -> method.equals("stagedContent") ? staging : PROCEED);
            zeroecho.pki.api.ca.IntermediateCreateCommand original = fixture.command("CN=Child");
            for (zeroecho.pki.api.ca.IntermediateCreateCommand invalid : java.util.List.of(
                    new zeroecho.pki.api.ca.IntermediateCreateCommand(original.formatId(), new PkiId("missing"), original.subjectRef(),
                            original.profileId(), original.keyRef(), original.attributes()),
                    new zeroecho.pki.api.ca.IntermediateCreateCommand(original.formatId(), original.issuerCaId(), original.subjectRef(),
                            "root-ca", original.keyRef(), original.attributes()),
                    new zeroecho.pki.api.ca.IntermediateCreateCommand(original.formatId(), original.issuerCaId(), original.subjectRef(),
                            original.profileId(), original.keyRef(), new zeroecho.pki.impl.core.attr.SimpleAttributeSet(
                                    java.util.List.of(new zeroecho.pki.impl.core.attr.SimpleAttributeSet.Entry(
                                            new zeroecho.pki.api.attr.AttributeId("urn:test:large"), java.util.Collections.nCopies(4096,
                                                    new zeroecho.pki.api.attr.AttributeValue.StringValue("x".repeat(131_072))))))))) {
                assertThrows(RuntimeException.class, () -> fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                        invalid, fixture.submission(actual), IntermediateCreationFixture.TTL, CancellationSignal.NONE));
            }
            assertEquals(0, stages.get());
            assertEquals(0, fixture.provider.dispatches);
        }
    }

    @Test void publicFacadeOwnsPreparationAndPublishesExactChildMetadata(@TempDir Path root) throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        PkiId operation;
        PkiId child;
        try (FilesystemPkiStore store = open(root)) {
            fixture.initialize(store, 1);
            DefaultSemanticSigningService semantic = semantic(store, fixture);
            PreparedSemanticSigningRequest discarded = semantic.prepareIntermediateCreation(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Child"), CancellationSignal.NONE);
            semantic.discard(discarded);
            PreparedSemanticSigningRequest prepared = semantic.prepareIntermediateCreation(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Child"), CancellationSignal.NONE);
            assertEquals(0, fixture.provider.dispatches);
            operation = semantic.accept(prepared).receipt().operationId();
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(store.getDomainContinuation(operation).orElseThrow().command());
            child = new PkiId(command.field(2));
            assertEquals(Optional.of(child), semantic.find(operation).orElseThrow().scope().subjectAuthorityId());
            fixture.finish(store, operation);
            assertEquals(SemanticSigningState.COMPLETED, semantic.find(operation).orElseThrow().state());
            zeroecho.pki.api.ca.CaRecord ca = store.getCa(child).orElseThrow();
            assertEquals(IntermediateCreationFixture.CHILD_KEY, ca.issuerKeyRef());
            zeroecho.pki.api.ca.IssuerGeneration generation = store.getIssuerGeneration(ca.currentIssuanceIssuerId()).orElseThrow();
            zeroecho.pki.api.credential.Credential credential = store.getCredential(generation.credentialId()).orElseThrow();
            assertTrue(credential.attributes().ids().isEmpty());
            assertEquals("intermediate-ca", ((zeroecho.pki.api.credential.CaProfileBinding) credential.profileBinding()).reference().profileId());
            X509Certificate certificate = Pkix.parseCertificate(PkiTestRuntime.readContent(store, credential.content()));
            certificate.verify(fixture.parentKey.getPublic());
            assertArrayEquals(fixture.childKey.getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
            assertEquals(2, store.getIssuerChainPath(ca.issuanceChainPathId()).orElseThrow().orderedCredentialIds().size());
        }
        try (FilesystemPkiStore store = open(root)) {
            assertEquals(SemanticSigningState.COMPLETED, semantic(store, fixture).find(operation).orElseThrow().state());
            assertEquals(1, store.getCa(child).orElseThrow().issuerIds().size());
        }
    }

    @Test void freezesProofSpkiProfileParentAndDeterministicAuthorityBeforeBothStages(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(store, 1);
            DomainSigningRequest prepared = fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Child"), fixture.submission(store), IntermediateCreationFixture.TTL, CancellationSignal.NONE);
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(prepared.domainTemplate().command());
            assertEquals("ca:" + IntermediateCreationFixture.hash(("zeroecho:pki:intermediate-authority:v1\0"
                    + prepared.operationId().value()).getBytes(StandardCharsets.UTF_8)), command.field(2));
            assertEquals(prepared.proofStep().orElseThrow().operationId().value(), command.field(18));
            assertEquals(2, prepared.candidates().size());
            assertTrue(store.getSignWorkflow(prepared.proofStep().orElseThrow().operationId()).isEmpty());
            assertEquals(IntermediateCreationFixture.PARENT_KEY, prepared.keyRef());
            X509Certificate certificate = Pkix.parseCertificate(Pkix.assembleCertificateOrCrl(
                    PkiTestRuntime.readContent(store, prepared.content()), new byte[] {0}, false));
            assertArrayEquals(fixture.childKey.getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
            assertEquals(0, certificate.getBasicConstraints());
            assertTrue(certificate.getKeyUsage()[5]);
            assertTrue(certificate.getKeyUsage()[6]);
            assertEquals("CN=Parent", certificate.getIssuerX500Principal().getName());
            assertTrue(store.getSignWorkflow(prepared.operationId()).isEmpty());
            assertEquals(0, fixture.provider.dispatches);
            for (zeroecho.pki.api.content.DurableContentReference candidate : prepared.candidates()) {
                store.stagedContent().retireUnownedContent(candidate);
            }
        }
    }

    @Test void enforcesAnchorPathLengthAndExemptsSelfIssuedChildFromCount(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(store, 0);
            PkiException denied = assertThrows(PkiException.class, () -> fixture.preparer(store).prepare(
                    IntermediateCreationFixture.ACCESS, fixture.command("CN=Child"), fixture.submission(store),
                    IntermediateCreationFixture.TTL, CancellationSignal.NONE));
            assertTrue(denied.getMessage().contains("PATH_LENGTH_EXCEEDED"));
            DomainSigningRequest selfIssued = fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Parent"), fixture.submission(store), IntermediateCreationFixture.TTL, CancellationSignal.NONE);
            for (zeroecho.pki.api.content.DurableContentReference candidate : selfIssued.candidates()) {
                store.stagedContent().retireUnownedContent(candidate);
            }
        }
    }

    @Test void cancellationRejectsBeforeSubjectKeyLookupOrSigning(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(store, 1);
            assertThrows(InterruptedIOException.class, () -> fixture.preparer(store).prepare(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Child"), fixture.submission(store), IntermediateCreationFixture.TTL, () -> true));
            assertEquals(0, fixture.provider.lookups);
            assertEquals(0, fixture.provider.dispatches);
        }
    }
    @Test void partialDiscardRetriesOnlyUnfinishedContentAndNeverPermitsAcceptance(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(actual, 1);
            DomainSigningRequest request = fixture.preparer(actual).prepare(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Discard"), fixture.submission(actual), IntermediateCreationFixture.TTL, CancellationSignal.NONE);
            java.util.List<zeroecho.pki.api.content.DurableContentReference> attempts = new java.util.ArrayList<>();
            AtomicInteger restores = new AtomicInteger();
            AtomicInteger admissions = new AtomicInteger();
            IOException interruptedRetirement = new IOException("Controlled challenge retirement failure");
            AtomicBoolean failChallenge = new AtomicBoolean(true);
            StagedContentStore staging = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                if (method.equals("restoreReference")) { restores.incrementAndGet(); }
                if (method.equals("retireUnownedContent")) {
                    zeroecho.pki.api.content.DurableContentReference candidate = (zeroecho.pki.api.content.DurableContentReference) args[0];
                    attempts.add(candidate);
                    if (candidate.equals(request.proofStep().orElseThrow().challenge()) && failChallenge.getAndSet(false)) {
                        throw interruptedRetirement;
                    }
                }
                return PROCEED;
            });
            PkiStore store = proxy(PkiStore.class, actual, (method, args) -> {
                if (method.equals("acceptSign")) { admissions.incrementAndGet(); }
                return method.equals("stagedContent") ? staging : PROCEED;
            });
            DefaultSemanticSigningService service = semantic(store, fixture);
            PreparedSemanticSigningRequest prepared = service.prepare(request, IntermediateCreationFixture.CA);
            PkiException failure = assertThrows(PkiException.class, () -> service.discard(prepared));
            org.junit.jupiter.api.Assertions.assertSame(interruptedRetirement, failure.getCause());
            assertEquals(request.candidates(), attempts);
            assertThrows(IOException.class, () -> PkiTestRuntime.readContent(actual, request.content()));
            assertTrue(PkiTestRuntime.readContent(actual, request.proofStep().orElseThrow().challenge()).length > 0);
            int beforeRetry = restores.get();
            assertThrows(IllegalStateException.class, () -> service.accept(prepared));
            service.discard(prepared);
            assertEquals(beforeRetry, restores.get(), "Retry must not restore the already retired certificate candidate");
            assertEquals(java.util.List.of(request.content(), request.proofStep().orElseThrow().challenge(),
                    request.proofStep().orElseThrow().challenge()), attempts);
            assertThrows(IOException.class, () -> PkiTestRuntime.readContent(actual, request.proofStep().orElseThrow().challenge()));
            assertThrows(IllegalStateException.class, () -> service.accept(prepared));
            assertThrows(IllegalStateException.class, () -> service.discard(prepared));
            assertEquals(0, admissions.get());
            assertEquals(0, fixture.provider.dispatches);
            assertTrue(actual.getSignWorkflow(request.operationId()).isEmpty());
        }
    }

    @Test void discardAttemptsBothCandidatesAndPreservesPrimaryAndSuppressedFailures(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(actual, 1);
            DomainSigningRequest request = fixture.preparer(actual).prepare(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Cleanup Failure"), fixture.submission(actual), IntermediateCreationFixture.TTL, CancellationSignal.NONE);
            IOException first = new IOException("Controlled first retirement failure");
            IllegalStateException second = new IllegalStateException("Controlled second retirement failure");
            AtomicBoolean fail = new AtomicBoolean(true);
            AtomicInteger attempts = new AtomicInteger();
            StagedContentStore staging = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                if (method.equals("retireUnownedContent")) {
                    attempts.incrementAndGet();
                    if (fail.get()) {
                        if (args[0].equals(request.content())) { throw first; }
                        throw second;
                    }
                }
                return PROCEED;
            });
            PkiStore store = proxy(PkiStore.class, actual, (method, args) -> method.equals("stagedContent") ? staging : PROCEED);
            DefaultSemanticSigningService service = semantic(store, fixture);
            PreparedSemanticSigningRequest prepared = service.prepare(request, IntermediateCreationFixture.CA);
            PkiException failure = assertThrows(PkiException.class, () -> service.discard(prepared));
            org.junit.jupiter.api.Assertions.assertSame(first, failure.getCause());
            assertArrayEquals(new Throwable[] {second}, first.getSuppressed());
            assertEquals(2, attempts.get());
            assertThrows(IllegalStateException.class, () -> service.accept(prepared));
            fail.set(false);
            service.discard(prepared);
            assertEquals(4, attempts.get());
            for (zeroecho.pki.api.content.DurableContentReference candidate : request.candidates()) {
                assertThrows(IOException.class, () -> PkiTestRuntime.readContent(actual, candidate));
            }
            assertEquals(0, fixture.provider.dispatches);
        }
    }

    @Test void secondStageFailureOrCancellationReclaimsEveryCompletedCandidate(@TempDir Path root) throws Exception {
        for (boolean cancel : new boolean[] {false, true}) {
            try (FilesystemPkiStore actual = open(root.resolve(Boolean.toString(cancel)))) {
                IntermediateCreationFixture fixture = new IntermediateCreationFixture();
                fixture.initialize(actual, 1);
                AtomicInteger stages = new AtomicInteger();
                AtomicBoolean cancelled = new AtomicBoolean();
                java.util.List<zeroecho.pki.api.content.DurableContentReference> completed = new java.util.ArrayList<>();
                java.util.List<zeroecho.pki.api.content.DurableContentReference> retired = new java.util.ArrayList<>();
                IOException stageFailure = new IOException("Controlled second staging failure");
                StagedContentStore staging = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                    if (method.equals("beginContent")) {
                        int stage = stages.incrementAndGet();
                        if (stage == 2 && !cancel) { throw stageFailure; }
                        ContentSink sink = actual.stagedContent().beginContent((zeroecho.pki.api.Encoding) args[0],
                                (zeroecho.pki.api.content.DurableContentReference.Lifecycle) args[1]);
                        return proxy(ContentSink.class, sink, (name, ignored) -> {
                            if (name.equals("complete")) {
                                zeroecho.pki.api.content.DurableContentReference candidate = sink.complete();
                                completed.add(candidate);
                                if (stage == 2) { cancelled.set(true); }
                                return candidate;
                            }
                            return PROCEED;
                        });
                    }
                    if (method.equals("retireUnownedContent")) {
                        retired.add((zeroecho.pki.api.content.DurableContentReference) args[0]);
                    }
                    return PROCEED;
                });
                PkiStore store = proxy(PkiStore.class, actual, (method, args) -> method.equals("stagedContent") ? staging : PROCEED);
                IOException failure = assertThrows(IOException.class, () -> fixture.preparer(store).prepare(
                        IntermediateCreationFixture.ACCESS, fixture.command("CN=Second Stage"), fixture.submission(actual),
                        IntermediateCreationFixture.TTL, cancelled::get));
                if (cancel) { org.junit.jupiter.api.Assertions.assertInstanceOf(InterruptedIOException.class, failure); }
                else { org.junit.jupiter.api.Assertions.assertSame(stageFailure, failure); }
                assertEquals(2, stages.get());
                assertEquals(cancel ? 2 : 1, completed.size());
                assertEquals(new java.util.HashSet<>(completed), new java.util.HashSet<>(retired));
                assertEquals(completed.size(), retired.size());
                for (zeroecho.pki.api.content.DurableContentReference candidate : completed) {
                    assertThrows(IOException.class, () -> PkiTestRuntime.readContent(actual, candidate));
                }
                assertEquals(1, fixture.provider.lookups);
                assertEquals(0, fixture.provider.dispatches);
            }
        }
    }

    @Test void onePreparationExportsOnceStagesTwiceAndAdmitsOneParent(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore actual = open(root)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(actual, 1);
            AtomicInteger stages = new AtomicInteger();
            AtomicInteger admissions = new AtomicInteger();
            StagedContentStore staging = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                if (method.equals("beginContent")) { stages.incrementAndGet(); }
                return PROCEED;
            });
            PkiStore store = proxy(PkiStore.class, actual, (method, args) -> {
                if (method.equals("acceptSign")) { admissions.incrementAndGet(); }
                return method.equals("stagedContent") ? staging : PROCEED;
            });
            DefaultSemanticSigningService service = semantic(store, fixture);
            PreparedSemanticSigningRequest prepared = service.prepareIntermediateCreation(IntermediateCreationFixture.ACCESS,
                    fixture.command("CN=Single Admission"), CancellationSignal.NONE);
            assertEquals(1, fixture.provider.lookups);
            assertEquals(2, stages.get());
            assertEquals(0, admissions.get());
            assertEquals(0, fixture.provider.dispatches);
            PkiId operation = service.accept(prepared).receipt().operationId();
            zeroecho.pki.spi.store.SignWorkflowStore.Workflow accepted = actual.getSignWorkflow(operation).orElseThrow();
            assertEquals(2, accepted.candidates().size());
            assertTrue(actual.getSignWorkflow(accepted.envelope().proofStep().orElseThrow().operationId()).isEmpty());
            assertThrows(IllegalStateException.class, () -> service.accept(prepared));
            assertEquals(1, admissions.get());
            fixture.finish(actual, operation);
            assertEquals(SemanticSigningState.COMPLETED, service.find(operation).orElseThrow().state());
            assertEquals(1, admissions.get());
        }
    }

    private static FilesystemPkiStore open(Path root) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK);
    }
    private static DefaultSemanticSigningService semantic(PkiStore store, IntermediateCreationFixture fixture) {
        DefaultSigningService signing = new DefaultSigningService(store, fixture.provider, fixture.signing.resolveIdentity(IntermediateCreationFixture.ALGORITHM),
                IntermediateCreationFixture.TTL, new SecureRandom(), () -> { },
                (command, custody) -> { custody.run(); return store.acceptSign(command); }, () -> { },
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
        return new DefaultSemanticSigningService(store, signing, PkiTestRuntime.endEntityPreparation(store, IntermediateCreationFixture.CLOCK),
                ManagedKeyProofCommand.MAX_CHALLENGE_BYTES, Optional.empty(), Optional.empty(), Optional.of(fixture.preparer(store)));
    }

    private static final Object PROCEED = new Object();
    @FunctionalInterface private interface Intercept { Object call(String method, Object[] args) throws Exception; }
    private static <T> T proxy(Class<T> type, T delegate, Intercept intercept) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (proxy, method, args) -> {
            Object result = intercept.call(method.getName(), args);
            if (result != PROCEED) { return result; }
            try { return method.invoke(delegate, args); }
            catch (InvocationTargetException failure) { throw failure.getCause(); }
        }));
    }
}
