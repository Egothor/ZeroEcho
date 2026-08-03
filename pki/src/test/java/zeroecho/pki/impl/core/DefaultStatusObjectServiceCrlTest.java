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
package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsHistoryPolicy;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.X509SignedObjectCompletion;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.CrlEntry;
import zeroecho.pki.spi.framework.CrlEntrySource;
import zeroecho.pki.spi.framework.StatusObjectGenerator;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.testkit.PkiTestRuntime;

final class DefaultStatusObjectServiceCrlTest {
    private static final Instant EVALUATION_TIME = Instant.parse("2026-07-30T12:00:00Z");
    private static final String SENTINEL = "DO_NOT_EXPOSE_CRL_SENTINEL";

    @Test
    void bouncyCastleGeneratorPreservesFullSerialReasonAndTransitionTime(@TempDir Path root) throws Exception {
        KeyPair rootKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:crl-generator");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(root, root.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            PkiId caId = createRoot(runtime, rootKeyRef, "CRL Generator Root");
            Credential issuer = runtime.caCredential(runtime.caService().getCa(caId), 0);
            StatusObjectGenerateCommand command = crlCommand(runtime, caId, issuer, rootKeyRef);
            List<RevocationReason> reasons = activeReasons();
            List<BigInteger> serials = serials(reasons.size());
            List<CrlEntry> entries = new ArrayList<>();
            for (int index = 0; index < reasons.size(); index++) {
                entries.add(new CrlEntry(serials.get(index),
                        EVALUATION_TIME.minusSeconds(index + 1L).plusNanos(987_654_321L), reasons.get(index)));
            }

            X509SignedObjectCompletion completion = runtime.framework().statusObjectGenerator().generate(command,
                    entrySource(entries));
            StatusObject status = runtime.signingBus().authority().requireStatusCompletion(completion);
            X509CRLHolder crl = new X509CRLHolder(PkiTestRuntime.readContent(runtime.signingBus(), status.content()));
            for (CrlEntry entry : entries) {
                X509CRLEntryHolder encoded = crl.getRevokedCertificate(entry.serialNumber());
                assertTrue(encoded != null, () -> "missing serial " + entry.serialNumber().bitLength());
                assertEquals(Date.from(entry.transitionTime().truncatedTo(ChronoUnit.SECONDS)),
                        encoded.getRevocationDate());
                assertEquals(reasonCode(entry.reason()), encodedReason(encoded));
            }
        }
    }

    @Test
    void serviceProjectsLatestHeldAndPermanentEntriesAndOmitsClear(@TempDir Path root) throws Exception {
        KeyPair rootKey = generateRsa();
        KeyPair heldKey = generateRsa();
        KeyPair permanentKey = generateRsa();
        KeyPair clearKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:crl-service");
        Path snapshot = root.resolve("crl-service-restored");
        FsHistoryPolicy history = FsHistoryPolicy.onWrite(Optional.of(Duration.ofDays(90)));
        FsPkiStoreOptions snapshotOptions = new FsPkiStoreOptions(
                history, history, history, history, false, Duration.ofDays(90), Duration.ZERO);
        PkiId caId;
        BigInteger heldSerial;
        BigInteger permanentSerial;
        try (PkiTestRuntime runtime = PkiTestRuntime.create(root, root.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey), snapshotOptions)) {
            caId = createRoot(runtime, rootKeyRef, "CRL Service Root");
            Credential held = issue(runtime, caId, heldKey, "Held");
            Credential permanent = issue(runtime, caId, permanentKey, "Permanent");
            Credential clear = issue(runtime, caId, clearKey, "Clear");

            RevocationRecord heldRecord = runtime.revocationService()
                    .hold(new RevocationCommand.Hold(held.credentialId(), emptyAttributes()));
            RevocationRecord permanentRecord = runtime.revocationService()
                    .revokePermanently(new RevocationCommand.RevokePermanently(permanent.credentialId(),
                            RevocationReason.AA_COMPROMISE, emptyAttributes()));
            runtime.revocationService().hold(new RevocationCommand.Hold(clear.credentialId(), emptyAttributes()));
            runtime.revocationService().unhold(new RevocationCommand.Unhold(clear.credentialId(), emptyAttributes()));

            try (java.util.stream.Stream<Path> files = java.nio.file.Files.walk(
                    root.resolve("store").resolve("profiles"))) {
                for (Path active : files.filter(path -> "active.bin".equals(
                        path.getFileName().toString())).toList()) {
                    java.nio.file.Files.delete(active);
                }
            }
            java.nio.file.Files.createDirectories(snapshot);
            ((FilesystemPkiStore) runtime.store()).exportSnapshot(snapshot.resolve("store"), Instant.now());

            StatusObject status = runtime.statusObjectService().generate(new StatusObjectGenerateCommand(caId,
                    StatusObjectType.CRL, runtime.framework().formatId(), emptyAttributes()));
            X509CRLHolder crl = new X509CRLHolder(PkiTestRuntime.readContent(runtime.signingBus(), status.content()));
            X509CertificateHolderView heldCertificate = certificate(runtime, held);
            X509CertificateHolderView permanentCertificate = certificate(runtime, permanent);
            X509CertificateHolderView clearCertificate = certificate(runtime, clear);
            assertEntry(crl, heldCertificate.serial(), heldRecord.transition().time(), RevocationReason.CERTIFICATE_HOLD);
            assertEntry(crl, permanentCertificate.serial(), permanentRecord.transition().time(),
                    RevocationReason.AA_COMPROMISE);
            assertNull(crl.getRevokedCertificate(clearCertificate.serial()));
            heldSerial = heldCertificate.serial();
            permanentSerial = permanentCertificate.serial();
        }
        try (PkiTestRuntime restored = PkiTestRuntime.create(snapshot, snapshot.resolve("restored-bus.log"),
                Map.of(rootKeyRef, rootKey), snapshotOptions)) {
            StatusObject restoredStatus = restored.statusObjectService().generate(new StatusObjectGenerateCommand(
                    caId, StatusObjectType.CRL, restored.framework().formatId(), emptyAttributes()));
            X509CRLHolder restoredCrl = new X509CRLHolder(
                    PkiTestRuntime.readContent(restored.signingBus(), restoredStatus.content()));
            assertTrue(restoredCrl.getRevokedCertificate(heldSerial) != null);
            assertTrue(restoredCrl.getRevokedCertificate(permanentSerial) != null);
        }
    }

    @Test
    void malformedAuthoritativeInputsAbortBeforeSigningAndPersistence(@TempDir Path root) throws Exception {
        KeyPair rootKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:crl-fail-closed");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(root, root.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            PkiId caId = createRoot(runtime, rootKeyRef, "CRL Failure Root");
            Credential template = runtime.caCredential(runtime.caService().getCa(caId), 0);
            StatusObjectGenerateCommand command = new StatusObjectGenerateCommand(caId, StatusObjectType.CRL,
                    runtime.framework().formatId(), emptyAttributes());

            assertCrlFailure(runtime, command, List.of(record(new PkiId("credential:missing"), RevocationState.HELD,
                    EVALUATION_TIME.minusSeconds(1), Optional.empty())), Map.of(), false);

            Credential wrongFormat = copy(template, "wrong-format", new FormatId("not-x509"), template.content());
            assertCrlFailure(
                    runtime, command, List.of(record(wrongFormat.credentialId(), RevocationState.HELD,
                            EVALUATION_TIME.minusSeconds(1), Optional.empty())),
                    Map.of(wrongFormat.credentialId(), wrongFormat), false);

            zeroecho.pki.api.content.DurableContentReference originalContent = template.content();
            zeroecho.pki.api.content.DurableContentReference wrongEncodingContent =
                    zeroecho.pki.testkit.PkiTestRuntime.untrustedReference(originalContent, Encoding.PEM);
            Credential wrongEncoding = copy(template, "wrong-encoding", BcX509CredentialFramework.FORMAT_ID,
                    wrongEncodingContent);
            assertCrlFailure(
                    runtime, command, List.of(record(wrongEncoding.credentialId(), RevocationState.HELD,
                            EVALUATION_TIME.minusSeconds(1), Optional.empty())),
                    Map.of(wrongEncoding.credentialId(), wrongEncoding), false);

            Credential malformed = copy(template, "malformed", BcX509CredentialFramework.FORMAT_ID,
                    runtime.stageCredential(new byte[] { 1, 2, 3 }));
            assertCrlFailure(
                    runtime, command, List.of(record(malformed.credentialId(), RevocationState.HELD,
                            EVALUATION_TIME.minusSeconds(1), Optional.empty())),
                    Map.of(malformed.credentialId(), malformed), false);

            byte[] certificateWithTrailing = Arrays.copyOf(runtime.credentialBytes(template),
                    runtime.credentialBytes(template).length + 1);
            Credential trailing = copy(template, "trailing", BcX509CredentialFramework.FORMAT_ID,
                    runtime.stageCredential(certificateWithTrailing));
            assertCrlFailure(runtime, command,
                    List.of(record(trailing.credentialId(), RevocationState.HELD,
                            EVALUATION_TIME.minusSeconds(1), Optional.empty())),
                    Map.of(trailing.credentialId(), trailing), false);

            byte[] csrInsteadOfCertificate = certificationRequest(generateRsa(), "Type Confusion").getEncoded();
            Credential typeConfused = copy(template, "type-confused", BcX509CredentialFramework.FORMAT_ID,
                    runtime.stageCredential(csrInsteadOfCertificate));
            assertCrlFailure(runtime, command,
                    List.of(record(typeConfused.credentialId(), RevocationState.HELD,
                            EVALUATION_TIME.minusSeconds(1), Optional.empty())),
                    Map.of(typeConfused.credentialId(), typeConfused), false);

            Credential duplicateOne = copy(template, "duplicate-one", BcX509CredentialFramework.FORMAT_ID,
                    template.content());
            Credential duplicateTwo = copy(template, "duplicate-two", BcX509CredentialFramework.FORMAT_ID,
                    template.content());
            assertCrlFailure(runtime, command,
                    List.of(record(duplicateOne.credentialId(), RevocationState.HELD, EVALUATION_TIME.minusSeconds(1),
                            Optional.empty()),
                            record(duplicateTwo.credentialId(), RevocationState.PERMANENTLY_REVOKED,
                                    EVALUATION_TIME.minusSeconds(1), Optional.of(RevocationReason.KEY_COMPROMISE))),
                    Map.of(duplicateOne.credentialId(), duplicateOne, duplicateTwo.credentialId(), duplicateTwo),
                    false);

            Credential future = copy(template, "future", BcX509CredentialFramework.FORMAT_ID, template.content());
            assertCrlFailure(
                    runtime, command, List.of(record(future.credentialId(), RevocationState.HELD,
                            EVALUATION_TIME.plusSeconds(1), Optional.empty())),
                    Map.of(future.credentialId(), future), false);

            assertCrlFailure(runtime, command, List.of(), Map.of(), true);
        }
    }

    @Test
    void generatorAndPersistenceFailuresExposeNoPartialCrlOrHostileDiagnostics(@TempDir Path root) throws Exception {
        KeyPair rootKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:crl-boundary");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(root, root.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            PkiId caId = createRoot(runtime, rootKeyRef, "CRL Boundary Root");
            StatusObjectGenerateCommand command = new StatusObjectGenerateCommand(caId, StatusObjectType.CRL,
                    runtime.framework().formatId(), emptyAttributes());
            int signCount = runtime.submittedSignCount();
            int statusCount = runtime.store().listStatusObjects(caId).size();

            AtomicInteger generatorCalls = new AtomicInteger();
            StatusObjectGenerator hostileGenerator = (ignoredCommand, ignoredEntries) -> {
                generatorCalls.incrementAndGet();
                throw new IllegalStateException(SENTINEL);
            };
            DefaultStatusObjectService generatorFailureService = new DefaultStatusObjectService(runtime.store(),
                    frameworkView(runtime.framework(), hostileGenerator), runtime.auditSink(), usableResolver(),
                    runtime.signingBus().authority());
            AtomicReference<StatusObject> generatorResult = new AtomicReference<>();
            PkiException generatorFailure = assertThrows(PkiException.class,
                    () -> generatorResult.set(generatorFailureService.generate(command)));
            assertBoundaryFailure(generatorFailure);
            assertNull(generatorResult.get());
            assertEquals(1, generatorCalls.get());
            assertEquals(statusCount, runtime.store().listStatusObjects(caId).size());
            assertEquals(signCount, runtime.submittedSignCount());

            AtomicInteger persistenceCalls = new AtomicInteger();
            StatusObjectGenerator controlledGenerator = runtime.framework().statusObjectGenerator();
            DefaultStatusObjectService persistenceFailureService = new DefaultStatusObjectService(
                    failingPersistenceStore(runtime.store(), persistenceCalls),
                    frameworkView(runtime.framework(), controlledGenerator), runtime.auditSink(), usableResolver(),
                    runtime.signingBus().authority());
            AtomicReference<StatusObject> persistenceResult = new AtomicReference<>();
            PkiException persistenceFailure = assertThrows(PkiException.class,
                    () -> persistenceResult.set(persistenceFailureService.generate(command)));
            assertBoundaryFailure(persistenceFailure);
            assertNull(persistenceResult.get());
            assertEquals(1, persistenceCalls.get());
            assertEquals(statusCount, runtime.store().listStatusObjects(caId).size());
            assertEquals(signCount + 1, runtime.submittedSignCount());
        }
    }

    @Test
    void maliciousCompletionMetadataAbortsBeforePersistence(@TempDir Path root) throws Exception {
        System.out.println("maliciousCompletionMetadataAbortsBeforePersistence");
        KeyPair rootKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:crl-metadata");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(root, root.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            PkiId caId = createRoot(runtime, rootKeyRef, "CRL Metadata Root");
            StatusObjectGenerateCommand command = new StatusObjectGenerateCommand(caId, StatusObjectType.CRL,
                    runtime.framework().formatId(), emptyAttributes());
            List<UnaryOperator<StatusObject>> mutations = List.of(
                    status -> copyStatus(status, new FormatId("wrong-format"), status.issuerCaId(), status.type(),
                            status.thisUpdate(), status.nextUpdate()),
                    status -> copyStatus(status, status.formatId(), new PkiId("ca:wrong-issuer"), status.type(),
                            status.thisUpdate(), status.nextUpdate()),
                    status -> copyStatus(status, status.formatId(), status.issuerCaId(), StatusObjectType.DELTA_CRL,
                            status.thisUpdate(), status.nextUpdate()),
                    status -> copyStatus(status, status.formatId(), status.issuerCaId(), status.type(),
                            status.thisUpdate(), Optional.of(status.thisUpdate())),
                    status -> copyStatus(status, status.formatId(), status.issuerCaId(), status.type(),
                            status.thisUpdate().plusSeconds(1L), status.nextUpdate()),
                    status -> copyStatus(status, status.formatId(), status.issuerCaId(), status.type(),
                            status.thisUpdate(), Optional.empty()),
                    status -> copyStatus(status, status.formatId(), status.issuerCaId(), status.type(),
                            status.thisUpdate(), status.nextUpdate().map(next -> next.plusSeconds(1L))));
            int signCount = runtime.submittedSignCount();
            int statusCount = runtime.store().listStatusObjects(caId).size();
            AtomicInteger persistenceCalls = new AtomicInteger();

            for (UnaryOperator<StatusObject> mutation : mutations) {
                StatusObjectGenerator delegate = runtime.framework().statusObjectGenerator();
                StatusObjectGenerator malicious = (wired, entries) -> {
                    X509SignedObjectCompletion completion = delegate.generate(wired, entries);
                    StatusObject modified = mutation.apply(
                            runtime.signingBus().authority().requireStatusCompletion(completion));
                    return runtime.signingBus().authority().completeStatusObject(modified,
                            runtime.signingBus().authority().requireStatusSigningPlan(completion));
                };
                DefaultStatusObjectService service = new DefaultStatusObjectService(
                        failingPersistenceStore(runtime.store(), persistenceCalls),
                        frameworkView(runtime.framework(), malicious), runtime.auditSink(), usableResolver(),
                        runtime.signingBus().authority());
                assertBoundaryFailure(assertThrows(PkiException.class, () -> service.generate(command)));
            }

            assertEquals(0, persistenceCalls.get());
            assertEquals(statusCount, runtime.store().listStatusObjects(caId).size());
            assertEquals(signCount + mutations.size(), runtime.submittedSignCount());
            System.out.println("...rejected=type, format, issuer, time order, changed/omitted/later signed times");
        }
        System.out.println("maliciousCompletionMetadataAbortsBeforePersistence...ok");
    }

    @Test
    void generatedCrlIssuerNameMustMatchSelectedIssuerCertificate(@TempDir Path root) throws Exception {
        System.out.println("generatedCrlIssuerNameMustMatchSelectedIssuerCertificate");
        KeyPair expectedKey = generateRsa();
        KeyPair substitutedKey = generateRsa();
        KeyRef expectedKeyRef = new KeyRef("kref:v1:keyring:test:crl-expected-issuer");
        KeyRef substitutedKeyRef = new KeyRef("kref:v1:keyring:test:crl-substituted-issuer");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(root, root.resolve("bus.log"),
                Map.of(expectedKeyRef, expectedKey, substitutedKeyRef, substitutedKey))) {
            PkiId expectedCaId = createRoot(runtime, expectedKeyRef, "Expected CRL Issuer");
            PkiId substitutedCaId = createRoot(runtime, substitutedKeyRef, "Substituted CRL Issuer");
            Credential substitutedIssuer = runtime.caCredential(runtime.caService().getCa(substitutedCaId), 0);
            StatusObjectGenerateCommand command = new StatusObjectGenerateCommand(expectedCaId,
                    StatusObjectType.CRL, runtime.framework().formatId(), emptyAttributes());
            StatusObjectGenerateCommand substituted = crlCommand(runtime, expectedCaId, substitutedIssuer,
                    substitutedKeyRef);
            StatusObjectGenerator delegate = runtime.framework().statusObjectGenerator();
            StatusObjectGenerator malicious = (wired, entries) -> delegate.generate(
                    new StatusObjectGenerateCommand(wired.issuerCaId(), wired.type(), wired.formatId(),
                            substituted.attributes()), entries);
            AtomicInteger persistenceCalls = new AtomicInteger();
            DefaultStatusObjectService service = new DefaultStatusObjectService(
                    failingPersistenceStore(runtime.store(), persistenceCalls),
                    frameworkView(runtime.framework(), malicious), runtime.auditSink(), usableResolver(),
                    runtime.signingBus().authority());

            assertBoundaryFailure(assertThrows(PkiException.class, () -> service.generate(command)));
            assertEquals(0, persistenceCalls.get());
            assertTrue(runtime.store().listStatusObjects(expectedCaId).isEmpty());
            System.out.println("...rejected=exact issuer Name mismatch");
        }
        System.out.println("generatedCrlIssuerNameMustMatchSelectedIssuerCertificate...ok");
    }

    private static void assertCrlFailure(PkiTestRuntime runtime, StatusObjectGenerateCommand command,
            List<RevocationRecord> records, Map<PkiId, Credential> credentials, boolean failListing) {
        int signCount = runtime.submittedSignCount();
        int statusCount = runtime.store().listStatusObjects(command.issuerCaId()).size();
        PkiStore view = storeView(runtime.store(), records, credentials, failListing);
        DefaultStatusObjectService service = new DefaultStatusObjectService(view, runtime.framework(),
                runtime.auditSink(), usableResolver(), runtime.signingBus().authority());

        PkiException failure = assertThrows(PkiException.class, () -> service.generate(command));
        assertTrue(failure.getMessage().contains("code=CRL_GENERATION_FAILED"));
        assertFalse(failure.getMessage().contains(SENTINEL));
        assertNull(failure.getCause());
        assertEquals(signCount, runtime.submittedSignCount());
        assertEquals(statusCount, runtime.store().listStatusObjects(command.issuerCaId()).size());
    }

    private static PkiStore storeView(PkiStore delegate, List<RevocationRecord> records,
            Map<PkiId, Credential> credentials, boolean failListing) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    if (method.getName().equals("openRevocationSnapshot")) {
                        if (failListing) {
                            throw new IllegalStateException(SENTINEL);
                        }
                        List<RevocationRecord> snapshot = List.copyOf(records);
                        return new zeroecho.pki.spi.store.RevocationSnapshot() {
                            @Override
                            public String snapshotId() {
                                return "test-snapshot";
                            }

                            @Override
                            public long revision() {
                                return snapshot.size();
                            }

                            @Override
                            public long boundary() {
                                return snapshot.size();
                            }

                            @Override
                            public String commitment() {
                                return "test-commitment";
                            }

                            @Override
                            public java.util.OptionalLong count() {
                                return java.util.OptionalLong.of(snapshot.size());
                            }

                            @Override
                            public Cursor openCursor() {
                                return new Cursor() {
                                    private int index = -1;

                                    @Override
                                    public boolean next(zeroecho.core.io.CancellationSignal cancellation) {
                                        index++;
                                        return index < snapshot.size();
                                    }

                                    @Override
                                    public RevocationRecord current() {
                                        return snapshot.get(index);
                                    }

                                    @Override
                                    public long ordinal() {
                                        return index;
                                    }

                                    @Override
                                    public void close() {
                                        // No resources.
                                    }
                                };
                            }

                            @Override
                            public void close() {
                                // No resources.
                            }
                        };
                    }
                    if (method.getName().equals("getCredential")) {
                        PkiId id = (PkiId) arguments[0];
                        if (credentials.containsKey(id)) {
                            return Optional.of(credentials.get(id));
                        }
                    }
                    try {
                        return method.invoke(delegate, arguments);
                    } catch (InvocationTargetException exception) {
                        throw exception.getCause();
                    }
                });
    }

    private static PkiStore failingPersistenceStore(PkiStore delegate, AtomicInteger persistenceCalls) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    if (method.getName().equals("putStatusObject")) {
                        persistenceCalls.incrementAndGet();
                        throw new IllegalStateException(SENTINEL);
                    }
                    try {
                        return method.invoke(delegate, arguments);
                    } catch (InvocationTargetException exception) {
                        throw exception.getCause();
                    }
                });
    }

    private static CredentialFramework frameworkView(CredentialFramework delegate, StatusObjectGenerator generator) {
        return (CredentialFramework) Proxy.newProxyInstance(CredentialFramework.class.getClassLoader(),
                new Class<?>[] { CredentialFramework.class }, (proxy, method, arguments) -> {
                    if (method.getName().equals("statusObjectGenerator")) {
                        return generator;
                    }
                    try {
                        return method.invoke(delegate, arguments);
                    } catch (InvocationTargetException exception) {
                        throw exception.getCause();
                    }
                });
    }

    private static void assertBoundaryFailure(PkiException failure) {
        assertTrue(failure.getMessage().contains("code=CRL_GENERATION_FAILED"));
        assertFalse(failure.getMessage().contains(SENTINEL));
        assertNull(failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
    }

    private static EffectiveCredentialStatusResolver usableResolver() {
        return () -> new EffectiveCredentialStatusResolver.Evaluation() {
            @Override
            public Instant evaluationTime() {
                return EVALUATION_TIME;
            }

            @Override
            public EffectiveCredentialStatus resolve(Credential credential) {
                return EffectiveCredentialStatus.USABLE;
            }

            @Override
            public Credential requireUsable(Credential credential, CredentialUse use) {
                return credential;
            }
        };
    }

    private static RevocationRecord record(PkiId credentialId, RevocationState state, Instant time,
            Optional<RevocationReason> reason) {
        return new RevocationRecord(credentialId,
                new RevocationTransition(1L, state, time, reason, emptyAttributes()));
    }

    private static Credential copy(Credential template, String suffix, FormatId formatId,
            zeroecho.pki.api.content.DurableContentReference content) {
        CaProfileBinding binding = assertInstanceOf(CaProfileBinding.class, template.profileBinding());
        return new Credential(new PkiId("credential:" + suffix), formatId, template.issuerRef(), template.subjectRef(),
                template.validity(), template.serialOrUniqueId(), template.publicKeyId(),
                new CaProfileBinding(binding.reference()), CredentialStatus.ISSUED, content, template.attributes());
    }

    private static StatusObject copyStatus(StatusObject source, FormatId formatId, PkiId issuerCaId,
            StatusObjectType type, Instant thisUpdate, Optional<Instant> nextUpdate) {
        return new StatusObject(source.statusObjectId(), formatId, issuerCaId, type, thisUpdate, nextUpdate,
                source.content(), source.attributes());
    }

    private static StatusObjectGenerateCommand crlCommand(PkiTestRuntime runtime, PkiId caId, Credential issuer,
            KeyRef keyRef) throws Exception {
        AttributeSet attributes = SimpleAttributeSet.builder()
                .put(BcX509Attributes.ISSUER_CERT_DER,
                        new AttributeValue.BytesValue(runtime.credentialBytes(issuer)))
                .put(BcX509Attributes.ISSUER_KEYREF, new AttributeValue.StringValue(keyRef.value())).build();
        return new StatusObjectGenerateCommand(caId, StatusObjectType.CRL, BcX509CredentialFramework.FORMAT_ID,
                attributes);
    }

    private static Credential issue(PkiTestRuntime runtime, PkiId caId, KeyPair subjectKey, String commonName)
            throws Exception {
        PKCS10CertificationRequest request = certificationRequest(subjectKey, commonName);
        ParsedCertificationRequest parsed = runtime.certificationRequestService().parse(new CertificationRequest(
                runtime.framework().formatId(), new EncodedObject(Encoding.DER, request.getEncoded())));
        runtime.certificationRequestService().verifyProofOfPossession(parsed,
                new VerificationPolicy(true, Optional.empty()));
        IssuanceService issuance = runtime.issuanceService();
        return issuance.issueEndEntity(new IssueEndEntityCommand(caId, parsed, "default", Optional.empty()))
                .credential();
    }

    private static PKCS10CertificationRequest certificationRequest(KeyPair pair, String commonName) throws Exception {
        X500Name subject = new X500Name("CN=" + commonName);
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        return builder.build(signer);
    }

    private static PkiId createRoot(PkiTestRuntime runtime, KeyRef keyRef, String commonName) {
        return runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                new SubjectRef("CN=" + commonName), "root-ca", Optional.of(keyRef), emptyAttributes()));
    }

    private static KeyPair generateRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static List<RevocationReason> activeReasons() {
        return Arrays.stream(RevocationReason.values()).filter(reason -> reason != RevocationReason.REMOVE_FROM_CRL)
                .toList();
    }

    private static List<BigInteger> serials(int size) {
        List<BigInteger> values = new ArrayList<>(List.of(BigInteger.ONE, BigInteger.valueOf(Long.MAX_VALUE),
                BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE),
                BigInteger.ONE.shiftLeft(159).subtract(BigInteger.ONE)));
        for (long value = 2L; values.size() < size; value++) {
            values.add(BigInteger.valueOf(value));
        }
        return List.copyOf(values);
    }

    private static CrlEntrySource entrySource(List<CrlEntry> entries) {
        List<CrlEntry> snapshot = List.copyOf(entries);
        return new CrlEntrySource() {
            @Override
            public Cursor openCursor() {
                return new Cursor() {
                    private int index = -1;

                    @Override
                    public boolean next() {
                        index++;
                        return index < snapshot.size();
                    }

                    @Override
                    public CrlEntry current() {
                        return snapshot.get(index);
                    }

                    @Override
                    public long ordinal() {
                        return index;
                    }

                    @Override
                    public void close() {
                        // No resources.
                    }
                };
            }

            @Override
            public java.util.OptionalLong count() {
                return java.util.OptionalLong.of(snapshot.size());
            }

            @Override
            public void close() {
                // No resources.
            }
        };
    }

    private static int encodedReason(X509CRLEntryHolder entry) {
        org.bouncycastle.asn1.x509.Extension extension = entry.getExtension(Extension.reasonCode);
        if (extension == null) {
            return CRLReason.unspecified;
        }
        return CRLReason.getInstance(extension.getParsedValue()).getValue().intValueExact();
    }

    private static int reasonCode(RevocationReason reason) {
        return switch (reason) {
            case UNSPECIFIED -> CRLReason.unspecified;
            case KEY_COMPROMISE -> CRLReason.keyCompromise;
            case CA_COMPROMISE -> CRLReason.cACompromise;
            case AFFILIATION_CHANGED -> CRLReason.affiliationChanged;
            case SUPERSEDED -> CRLReason.superseded;
            case CESSATION_OF_OPERATION -> CRLReason.cessationOfOperation;
            case CERTIFICATE_HOLD -> CRLReason.certificateHold;
            case REMOVE_FROM_CRL -> throw new IllegalArgumentException("inactive reason");
            case PRIVILEGE_WITHDRAWN -> CRLReason.privilegeWithdrawn;
            case AA_COMPROMISE -> CRLReason.aACompromise;
        };
    }

    private static void assertEntry(X509CRLHolder crl, BigInteger serial, Instant time, RevocationReason reason) {
        X509CRLEntryHolder entry = crl.getRevokedCertificate(serial);
        assertTrue(entry != null);
        assertEquals(Date.from(time.truncatedTo(ChronoUnit.SECONDS)), entry.getRevocationDate());
        assertEquals(reasonCode(reason), encodedReason(entry));
    }

    private static X509CertificateHolderView certificate(PkiTestRuntime runtime, Credential credential)
            throws Exception {
        byte[] encoded = runtime.credentialBytes(credential);
        try {
            return new X509CertificateHolderView(
                    new org.bouncycastle.cert.X509CertificateHolder(encoded).getSerialNumber());
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static SimpleAttributeSet emptyAttributes() {
        return new SimpleAttributeSet();
    }

    private record X509CertificateHolderView(BigInteger serial) {
    }
}
