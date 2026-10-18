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

package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.PkiTestRuntime;

final class CaContinuationPublisherConcurrencyTest {
    private static final Instant BEFORE = Instant.parse("2026-08-20T10:00:00Z");
    private static final Instant AFTER = Instant.parse("2027-08-20T10:00:00Z");
    private static final String DIGEST = "1".repeat(64);
    private static final PkiId MIDDLE = new PkiId("middle-authority");

    @Test
    void rootRolloverConflictRetainsPublishingAndRetriesWithoutSigning(@TempDir Path root) throws Exception {
        KeyPair key = DomainContinuationPublisherRecoveryTest.rsa();
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            DomainContinuationStore.Record creation = rootOperation(store, key, "CREATE_ROOT", null, 10, "root-key");
            advance(store, creation);
            PkiId caId = authorityId(creation);
            PkiId first = store.getCa(caId).orElseThrow().currentIssuanceIssuerId();
            advance(store, rootOperation(store, key, "ROLLOVER_ROOT", caId, 11, "root-key"));
            DomainContinuationStore.Record pending = rootOperation(store, key, "ROLLOVER_ROOT", caId, 12, "new-root-key");
            CaRecord winner = select(store, store.getCa(caId).orElseThrow(), first, CaState.ACTIVE);
            assertConflictThenRetry(store, pending, winner, true);
            assertEquals(3, store.getCa(caId).orElseThrow().issuerIds().size());
        }
    }

    @Test
    void intermediateIssuanceConflictRetainsWinnerSelectionAndRetriesWithoutSigning(@TempDir Path root) throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            initializeMiddle(store, fixture);
            advance(store, intermediateOperation(store, fixture, "ISSUE_INTERMEDIATE", 10));
            CaRecord current = store.getCa(MIDDLE).orElseThrow();
            CaRecord winner = select(store, current, current.issuerIds().getLast(), CaState.ACTIVE);
            DomainContinuationStore.Record pending = intermediateOperation(store, fixture, "ISSUE_INTERMEDIATE", 11);
            assertConflictThenRetry(store, pending, winner, false);
            assertEquals(3, store.getCa(MIDDLE).orElseThrow().issuerIds().size());
            assertEquals(0, fixture.provider.dispatches);
        }
    }

    @Test
    void rootCreationAndRolloverReplayPreserveLaterDisabledSelectionAndAppendedGenerations(@TempDir Path root)
            throws Exception {
        KeyPair key = DomainContinuationPublisherRecoveryTest.rsa();
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            DomainContinuationStore.Record creation = rootOperation(store, key, "CREATE_ROOT", null, 20, "root-key");
            crashAfterCa(store, creation);
            PkiId caId = authorityId(creation);
            PkiId first = store.getCa(caId).orElseThrow().currentIssuanceIssuerId();
            advance(store, rootOperation(store, key, "ROLLOVER_ROOT", caId, 21, "later-key"));
            CaRecord later = select(store, store.getCa(caId).orElseThrow(), first, CaState.DISABLED);
            replaceCurrent(store, later);
            advance(store, creation);
            assertCompletedWithUnchangedCa(store, creation, later);

            replaceCurrent(store, select(store, later, first, CaState.ACTIVE));
            DomainContinuationStore.Record rollover = rootOperation(store, key, "ROLLOVER_ROOT", caId, 22, "rollover-key");
            crashAfterCa(store, rollover);
            advance(store, rootOperation(store, key, "ROLLOVER_ROOT", caId, 23, "latest-key"));
            CaRecord finalAdministration = select(store, store.getCa(caId).orElseThrow(), first, CaState.DISABLED);
            replaceCurrent(store, finalAdministration);
            advance(store, rollover);
            assertCompletedWithUnchangedCa(store, rollover, finalAdministration);
            assertEquals(4, finalAdministration.issuerIds().size());
        }
    }

    @Test
    void intermediateIssueAndRolloverReplayPreserveLaterFullAuthorityRecord(@TempDir Path root) throws Exception {
        IntermediateCreationFixture fixture = new IntermediateCreationFixture();
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            initializeMiddle(store, fixture);
            PkiId first = store.getCa(MIDDLE).orElseThrow().currentIssuanceIssuerId();
            DomainContinuationStore.Record issue = intermediateOperation(store, fixture, "ISSUE_INTERMEDIATE", 20);
            crashAfterCa(store, issue);
            advance(store, intermediateOperation(store, fixture, "ISSUE_INTERMEDIATE", 21));
            CaRecord later = select(store, store.getCa(MIDDLE).orElseThrow(), first, CaState.DISABLED);
            replaceCurrent(store, later);
            advance(store, issue);
            assertCompletedWithUnchangedCa(store, issue, later);

            replaceCurrent(store, select(store, later, first, CaState.ACTIVE));
            DomainContinuationStore.Record rollover = intermediateOperation(store, fixture, "ROLLOVER_INTERMEDIATE", 22);
            crashAfterCa(store, rollover);
            advance(store, intermediateOperation(store, fixture, "ISSUE_INTERMEDIATE", 23));
            CaRecord finalAdministration = select(store, store.getCa(MIDDLE).orElseThrow(), first, CaState.DISABLED);
            replaceCurrent(store, finalAdministration);
            advance(store, rollover);
            assertCompletedWithUnchangedCa(store, rollover, finalAdministration);
            assertEquals(5, finalAdministration.issuerIds().size());
            assertEquals(0, fixture.provider.dispatches);
        }
    }

    @Test
    void publishedMembershipCannotBypassExactGraphOwnershipOrCreationPrefixChecks(@TempDir Path root) throws Exception {
        KeyPair key = DomainContinuationPublisherRecoveryTest.rsa();
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            DomainContinuationStore.Record creation = rootOperation(store, key, "CREATE_ROOT", null, 30, "root-key");
            crashAfterCa(store, creation);
            PkiId caId = authorityId(creation);
            CaRecord created = store.getCa(caId).orElseThrow();
            IssuerGeneration generation = store.getIssuerGeneration(created.currentIssuanceIssuerId()).orElseThrow();
            IssuerChainPath path = store.getIssuerChainPath(created.issuanceChainPathId()).orElseThrow();
            EncodedObject certificate = new DomainContinuationPublisher(store).reconstruct(creation,
                    store.getSignWorkflow(creation.operationId()).orElseThrow().result().orElseThrow());
            advance(store, rootOperation(store, key, "ROLLOVER_ROOT", caId, 31, "later-key"));
            CaRecord current = select(store, store.getCa(caId).orElseThrow(), generation.issuerId(), CaState.DISABLED);
            replaceCurrent(store, current);
            IssuerChainPath otherPath = store.listIssuerChainPaths(current.issuerIds().getLast()).getFirst();
            for (String fault : List.of("missing-generation", "different-generation", "different-path", "subject", "kind", "initial-prefix")) {
                PkiStore observed = decorator(store, (method, arguments) -> {
                    if (method.getName().equals("getCa") && arguments[0].equals(caId)) {
                        return switch (fault) {
                            case "subject" -> Optional.of(new CaRecord(current.caId(), current.kind(), current.state(),
                                    current.issuerKeyRef(), new SubjectRef("CN=Other"), current.issuerIds(),
                                    current.currentIssuanceIssuerId(), current.issuanceChainPathId()));
                            case "kind" -> Optional.of(new CaRecord(current.caId(), CaKind.INTERMEDIATE, current.state(),
                                    current.issuerKeyRef(), current.subjectRef(), current.issuerIds(),
                                    current.currentIssuanceIssuerId(), current.issuanceChainPathId()));
                            case "initial-prefix" -> Optional.of(new CaRecord(current.caId(), current.kind(), current.state(),
                                    current.issuerKeyRef(), current.subjectRef(), current.issuerIds().reversed(),
                                    current.currentIssuanceIssuerId(), current.issuanceChainPathId()));
                            default -> invoke(store, method, arguments);
                        };
                    }
                    if (method.getName().equals("getIssuerGeneration") && arguments[0].equals(generation.issuerId())) {
                        if (fault.equals("missing-generation")) return Optional.empty();
                        if (fault.equals("different-generation")) return Optional.of(new IssuerGeneration(generation.issuerId(),
                                generation.authorityId(), generation.credentialId(), generation.signingKeyRef(), generation.state(),
                                "2".repeat(64), generation.x509BindingCommitment()));
                    }
                    if (fault.equals("different-path") && method.getName().equals("getIssuerChainPath")
                            && arguments[0].equals(path.pathId())) return Optional.of(otherPath);
                    return invoke(store, method, arguments);
                });
                assertThrows(DomainContinuationPublisher.PostconditionFailure.class,
                        () -> new DomainContinuationPublisher(observed).publish(creation, certificate), fault);
                assertEquals(current, store.getCa(caId).orElseThrow());
            }
            PkiStore wrongOwner = decorator(store, (method, arguments) -> {
                if (method.getName().equals("putCredentialFromSigning")) {
                    Object[] changed = arguments.clone();
                    changed[2] = "domain:v1:" + "f".repeat(64);
                    return invoke(store, method, changed);
                }
                return invoke(store, method, arguments);
            });
            assertThrows(IllegalStateException.class, () -> new DomainContinuationPublisher(wrongOwner).publish(creation, certificate));
            assertEquals(DomainContinuationStore.State.PUBLISHING,
                    store.getDomainContinuation(creation.operationId()).orElseThrow().state());
            advance(store, creation);
            assertCompletedWithUnchangedCa(store, creation, current);
        }
    }

    private static void assertConflictThenRetry(FilesystemPkiStore store, DomainContinuationStore.Record pending,
            CaRecord winner, boolean selectsNew) {
        List<Boolean> outcomes = new ArrayList<>();
        byte[] signature = store.getSignWorkflow(pending.operationId()).orElseThrow().result().orElseThrow().bytes();
        PkiStore observed = decorator(store, (method, arguments) -> {
            if (method.getName().equals("replaceCa")) {
                if (outcomes.isEmpty()) assertTrue(store.replaceCa((CaRecord) arguments[0], winner));
                boolean committed = store.replaceCa((CaRecord) arguments[0], (CaRecord) arguments[1]);
                outcomes.add(committed);
                return committed;
            }
            return invoke(store, method, arguments);
        });
        assertThrows(IllegalStateException.class, () -> advance(observed, pending));
        assertEquals(List.of(false), outcomes);
        assertEquals(winner, store.getCa(winner.caId()).orElseThrow());
        assertEquals(DomainContinuationStore.State.PUBLISHING,
                store.getDomainContinuation(pending.operationId()).orElseThrow().state());
        SignWorkflowStore.Workflow signing = store.getSignWorkflow(pending.operationId()).orElseThrow();
        assertEquals(SignWorkflowStore.State.SUCCEEDED, signing.state());
        assertArrayEquals(signature, signing.result().orElseThrow().bytes());
        advance(observed, pending);
        assertEquals(List.of(false, true), outcomes);
        assertEquals(DomainContinuationStore.State.COMPLETED,
                store.getDomainContinuation(pending.operationId()).orElseThrow().state());
        CaRecord completed = store.getCa(winner.caId()).orElseThrow();
        assertEquals(winner.issuerIds(), completed.issuerIds().subList(0, winner.issuerIds().size()));
        assertEquals(winner.issuerIds().size() + 1, completed.issuerIds().size());
        assertEquals(selectsNew ? completed.issuerIds().getLast() : winner.currentIssuanceIssuerId(),
                completed.currentIssuanceIssuerId());
        advance(observed, pending);
        assertEquals(List.of(false, true), outcomes);
        assertEquals(completed, store.getCa(winner.caId()).orElseThrow());
    }

    private static void assertCompletedWithUnchangedCa(PkiStore store, DomainContinuationStore.Record pending, CaRecord later) {
        assertEquals(DomainContinuationStore.State.COMPLETED,
                store.getDomainContinuation(pending.operationId()).orElseThrow().state());
        assertEquals(later, store.getCa(later.caId()).orElseThrow());
        for (PkiId issuer : later.issuerIds()) {
            IssuerGeneration generation = store.getIssuerGeneration(issuer).orElseThrow();
            assertTrue(store.getCredential(generation.credentialId()).isPresent());
            assertFalse(store.listIssuerChainPaths(issuer).isEmpty());
        }
        advance(store, pending);
        assertEquals(later, store.getCa(later.caId()).orElseThrow());
    }

    private static void advance(PkiStore store, DomainContinuationStore.Record domain) {
        new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(domain.operationId()).orElseThrow());
    }

    private static void crashAfterCa(PkiStore store, DomainContinuationStore.Record domain) {
        DomainContinuationPublisher.installPublicationFault(point -> {
            if (point == DomainContinuationPublisher.PublicationFaultPoint.AFTER_CA) throw new SimulatedCrash();
        });
        try { assertThrows(SimulatedCrash.class, () -> advance(store, domain)); }
        finally { DomainContinuationPublisher.clearPublicationFault(); }
        assertEquals(DomainContinuationStore.State.PUBLISHING,
                store.getDomainContinuation(domain.operationId()).orElseThrow().state());
    }

    private static DomainContinuationStore.Record rootOperation(FilesystemPkiStore store, KeyPair key,
            String operation, PkiId caId, int serial, String keyRef) throws Exception {
        List<String> fields = new ArrayList<>(List.of("x509", "CN=Root", "root", keyRef, "root", "1", DIGEST,
                BEFORE.toString(), AFTER.toString(), Integer.toString(serial), "CN=Root", "policy:test", "binding:test"));
        if (caId != null) fields.add(caId.value());
        DomainContinuationTemplate template = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA, operation,
                fields.toArray(String[]::new));
        return DomainContinuationPublisherRecoveryTest.publishingCertificate(store, template, operation.toLowerCase(Locale.ROOT) + "-" + serial,
                DomainContinuationPublisherRecoveryTest.certificate(key, "CN=Root", BigInteger.valueOf(serial)));
    }

    private static PkiId authorityId(DomainContinuationStore.Record creation) {
        return new PkiId(DomainCommandEncoding.decode(creation.command()).field(13));
    }

    private static void initializeMiddle(FilesystemPkiStore store, IntermediateCreationFixture fixture) throws Exception {
        fixture.initialize(store, 2);
        fixture.intermediateParent(store, 1, false);
    }

    private static DomainContinuationStore.Record intermediateOperation(FilesystemPkiStore store,
            IntermediateCreationFixture fixture, String operation, int serial) throws Exception {
        CaRecord parent = store.getCa(IntermediateCreationFixture.CA).orElseThrow();
        IssuerGeneration parentGeneration = store.getIssuerGeneration(parent.currentIssuanceIssuerId()).orElseThrow();
        IssuerChainPath parentPath = store.getIssuerChainPath(parent.issuanceChainPathId()).orElseThrow();
        Credential parentCredential = store.getCredential(parentGeneration.credentialId()).orElseThrow();
        CaRecord middle = store.getCa(MIDDLE).orElseThrow();
        Credential original = store.getCredential(store.getIssuerGeneration(middle.issuerIds().getFirst())
                .orElseThrow().credentialId()).orElseThrow();
        CertificateProfileRef profile = ((CaProfileBinding) original.profileBinding()).reference();
        X509CertificateHolder parentCertificate = new X509CertificateHolder(PkiTestRuntime.readContent(store, parentCredential.content()));
        X509CertificateHolder originalCertificate = new X509CertificateHolder(PkiTestRuntime.readContent(store, original.content()));
        Instant before = original.validity().notBefore();
        Instant after = original.validity().notAfter();
        X509CertificateHolder certificate = new X509v3CertificateBuilder(parentCertificate.getSubject(), BigInteger.valueOf(serial),
                Date.from(before), Date.from(after), originalCertificate.getSubject(), originalCertificate.getSubjectPublicKeyInfo())
                .build(new JcaContentSignerBuilder("Ed25519").build(fixture.parentKey.getPrivate()));
        String fingerprint = DomainContinuationPublisher.sha256SubjectPublicKey(zeroecho.pkix.Pkix.parseCertificate(certificate.getEncoded()));
        DomainContinuationTemplate template = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA, operation,
                "x509", parent.caId().value(), MIDDLE.value(), parentGeneration.issuerId().value(), parentPath.pathId().value(),
                parentPath.pathCommitment(), middle.issuerKeyRef().value(), profile.profileId(), Long.toString(profile.profileVersion()),
                HexFormat.of().formatHex(profile.canonicalSha256()), middle.subjectRef().value(), before.toString(), after.toString(),
                Integer.toString(serial), parentGeneration.signingKeyRef().value(), parentCredential.content().contentId(),
                parentCredential.content().sha256(), fingerprint, originalCertificate.getSubject().toString(), "policy:test", "binding:test");
        byte[] tbs = certificate.toASN1Structure().getTBSCertificate().getEncoded();
        template = zeroecho.pki.testkit.IntermediateProofProvenanceFixture.withProof(template,
                store.signingNamespace() + ".publication-test", new zeroecho.pki.spi.crypto.SigningProvider.ConfigurationCommitment(new byte[32]),
                tbs.length, IntermediateCreationFixture.hash(tbs));
        return DomainContinuationPublisherRecoveryTest.publishingCertificate(store, template, operation.toLowerCase(Locale.ROOT) + "-" + serial,
                certificate, IntermediateCreationFixture.ALGORITHM);
    }

    private static CaRecord select(PkiStore store, CaRecord current, PkiId issuer, CaState state) {
        IssuerGeneration generation = store.getIssuerGeneration(issuer).orElseThrow();
        IssuerChainPath path = store.listIssuerChainPaths(issuer).getFirst();
        return new CaRecord(current.caId(), current.kind(), state, generation.signingKeyRef(), current.subjectRef(),
                current.issuerIds(), issuer, path.pathId());
    }

    private static void replaceCurrent(PkiStore store, CaRecord replacement) {
        assertTrue(store.replaceCa(store.getCa(replacement.caId()).orElseThrow(), replacement));
    }

    private static PkiStore decorator(PkiStore store, StoreCall call) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> call.invoke(method, arguments));
    }

    private static Object invoke(PkiStore store, Method method, Object[] arguments) throws Throwable {
        try { return method.invoke(store, arguments); }
        catch (InvocationTargetException failure) { throw failure.getCause(); }
    }

    @FunctionalInterface private interface StoreCall { Object invoke(Method method, Object[] arguments) throws Throwable; }
    private static final class SimulatedCrash extends Error { private static final long serialVersionUID = 1L; }
}
