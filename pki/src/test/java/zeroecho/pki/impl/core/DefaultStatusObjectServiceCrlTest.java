/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
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
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

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
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationJournal;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.spi.framework.CrlEntry;
import zeroecho.pki.spi.framework.CredentialFramework;
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
            Credential issuer = runtime.caService().getCa(caId).caCredentials().get(0);
            StatusObjectGenerateCommand command = crlCommand(caId, issuer, rootKeyRef);
            List<RevocationReason> reasons = activeReasons();
            List<BigInteger> serials = serials(reasons.size());
            List<CrlEntry> entries = new ArrayList<>();
            for (int index = 0; index < reasons.size(); index++) {
                entries.add(new CrlEntry(serials.get(index),
                        EVALUATION_TIME.minusSeconds(index + 1L).plusNanos(987_654_321L),
                        reasons.get(index)));
            }

            StatusObject status = runtime.framework().statusObjectGenerator().generate(command, entries);
            X509CRLHolder crl = new X509CRLHolder(status.encoded().bytes());
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
        try (PkiTestRuntime runtime = PkiTestRuntime.create(root, root.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            PkiId caId = createRoot(runtime, rootKeyRef, "CRL Service Root");
            Credential held = issue(runtime, caId, heldKey, "Held");
            Credential permanent = issue(runtime, caId, permanentKey, "Permanent");
            Credential clear = issue(runtime, caId, clearKey, "Clear");

            RevocationJournal heldJournal = runtime.revocationService().hold(
                    new RevocationCommand.Hold(held.credentialId(), emptyAttributes()));
            RevocationJournal permanentJournal = runtime.revocationService().revokePermanently(
                    new RevocationCommand.RevokePermanently(permanent.credentialId(),
                            RevocationReason.AA_COMPROMISE, emptyAttributes()));
            runtime.revocationService().hold(
                    new RevocationCommand.Hold(clear.credentialId(), emptyAttributes()));
            runtime.revocationService().unhold(
                    new RevocationCommand.Unhold(clear.credentialId(), emptyAttributes()));

            StatusObject status = runtime.statusObjectService().generate(new StatusObjectGenerateCommand(
                    caId, StatusObjectType.CRL, runtime.framework().formatId(), emptyAttributes()));
            X509CRLHolder crl = new X509CRLHolder(status.encoded().bytes());
            X509CertificateHolderView heldCertificate = certificate(held);
            X509CertificateHolderView permanentCertificate = certificate(permanent);
            X509CertificateHolderView clearCertificate = certificate(clear);
            assertEntry(crl, heldCertificate.serial(), heldJournal.latest().time(),
                    RevocationReason.CERTIFICATE_HOLD);
            assertEntry(crl, permanentCertificate.serial(), permanentJournal.latest().time(),
                    RevocationReason.AA_COMPROMISE);
            assertNull(crl.getRevokedCertificate(clearCertificate.serial()));
        }
    }

    @Test
    void malformedAuthoritativeInputsAbortBeforeSigningAndPersistence(@TempDir Path root) throws Exception {
        KeyPair rootKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:crl-fail-closed");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(root, root.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            PkiId caId = createRoot(runtime, rootKeyRef, "CRL Failure Root");
            Credential template = runtime.caService().getCa(caId).caCredentials().get(0);
            StatusObjectGenerateCommand command = new StatusObjectGenerateCommand(caId, StatusObjectType.CRL,
                    runtime.framework().formatId(), emptyAttributes());

            assertCrlFailure(runtime, command,
                    List.of(journal(new PkiId("credential:missing"), RevocationState.HELD,
                            EVALUATION_TIME.minusSeconds(1), Optional.empty())),
                    Map.of(), false);

            Credential wrongFormat = copy(template, "wrong-format", new FormatId("not-x509"),
                    template.encoded());
            assertCrlFailure(runtime, command,
                    List.of(journal(wrongFormat.credentialId(), RevocationState.HELD,
                            EVALUATION_TIME.minusSeconds(1), Optional.empty())),
                    Map.of(wrongFormat.credentialId(), wrongFormat), false);

            Credential wrongEncoding = copy(template, "wrong-encoding",
                    BcX509CredentialFramework.FORMAT_ID,
                    new EncodedObject(Encoding.PEM, template.encoded().bytes()));
            assertCrlFailure(runtime, command,
                    List.of(journal(wrongEncoding.credentialId(), RevocationState.HELD,
                            EVALUATION_TIME.minusSeconds(1), Optional.empty())),
                    Map.of(wrongEncoding.credentialId(), wrongEncoding), false);

            Credential malformed = copy(template, "malformed", BcX509CredentialFramework.FORMAT_ID,
                    new EncodedObject(Encoding.DER, new byte[] { 1, 2, 3 }));
            assertCrlFailure(runtime, command,
                    List.of(journal(malformed.credentialId(), RevocationState.HELD,
                            EVALUATION_TIME.minusSeconds(1), Optional.empty())),
                    Map.of(malformed.credentialId(), malformed), false);

            Credential duplicateOne = copy(template, "duplicate-one", BcX509CredentialFramework.FORMAT_ID,
                    template.encoded());
            Credential duplicateTwo = copy(template, "duplicate-two", BcX509CredentialFramework.FORMAT_ID,
                    template.encoded());
            assertCrlFailure(runtime, command, List.of(
                    journal(duplicateOne.credentialId(), RevocationState.HELD,
                            EVALUATION_TIME.minusSeconds(1), Optional.empty()),
                    journal(duplicateTwo.credentialId(), RevocationState.PERMANENTLY_REVOKED,
                            EVALUATION_TIME.minusSeconds(1), Optional.of(RevocationReason.KEY_COMPROMISE))),
                    Map.of(duplicateOne.credentialId(), duplicateOne,
                            duplicateTwo.credentialId(), duplicateTwo), false);

            Credential future = copy(template, "future", BcX509CredentialFramework.FORMAT_ID,
                    template.encoded());
            assertCrlFailure(runtime, command,
                    List.of(journal(future.credentialId(), RevocationState.HELD,
                            EVALUATION_TIME.plusSeconds(1), Optional.empty())),
                    Map.of(future.credentialId(), future), false);

            assertCrlFailure(runtime, command, List.of(), Map.of(), true);
        }
    }

    @Test
    void generatorAndPersistenceFailuresExposeNoPartialCrlOrHostileDiagnostics(@TempDir Path root)
            throws Exception {
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
            DefaultStatusObjectService generatorFailureService = new DefaultStatusObjectService(
                    runtime.store(), frameworkView(runtime.framework(), hostileGenerator),
                    runtime.auditSink(), usableResolver());
            AtomicReference<StatusObject> generatorResult = new AtomicReference<>();
            PkiException generatorFailure = assertThrows(PkiException.class,
                    () -> generatorResult.set(generatorFailureService.generate(command)));
            assertBoundaryFailure(generatorFailure);
            assertNull(generatorResult.get());
            assertEquals(1, generatorCalls.get());
            assertEquals(statusCount, runtime.store().listStatusObjects(caId).size());
            assertEquals(signCount, runtime.submittedSignCount());

            AtomicInteger persistenceCalls = new AtomicInteger();
            StatusObject generated = new StatusObject(new PkiId("status:controlled-crl"),
                    command.formatId(), caId, StatusObjectType.CRL, EVALUATION_TIME,
                    Optional.empty(), new EncodedObject(Encoding.DER, new byte[] { 1 }),
                    emptyAttributes());
            StatusObjectGenerator controlledGenerator = (ignoredCommand, ignoredEntries) -> generated;
            DefaultStatusObjectService persistenceFailureService = new DefaultStatusObjectService(
                    failingPersistenceStore(runtime.store(), persistenceCalls),
                    frameworkView(runtime.framework(), controlledGenerator),
                    runtime.auditSink(), usableResolver());
            AtomicReference<StatusObject> persistenceResult = new AtomicReference<>();
            PkiException persistenceFailure = assertThrows(PkiException.class,
                    () -> persistenceResult.set(persistenceFailureService.generate(command)));
            assertBoundaryFailure(persistenceFailure);
            assertNull(persistenceResult.get());
            assertEquals(1, persistenceCalls.get());
            assertEquals(statusCount, runtime.store().listStatusObjects(caId).size());
            assertEquals(signCount, runtime.submittedSignCount());
        }
    }

    private static void assertCrlFailure(PkiTestRuntime runtime, StatusObjectGenerateCommand command,
            List<RevocationJournal> journals, Map<PkiId, Credential> credentials, boolean failListing) {
        int signCount = runtime.submittedSignCount();
        int statusCount = runtime.store().listStatusObjects(command.issuerCaId()).size();
        PkiStore view = storeView(runtime.store(), journals, credentials, failListing);
        DefaultStatusObjectService service = new DefaultStatusObjectService(view, runtime.framework(),
                runtime.auditSink(), usableResolver());

        PkiException failure = assertThrows(PkiException.class, () -> service.generate(command));
        assertTrue(failure.getMessage().contains("code=CRL_GENERATION_FAILED"));
        assertFalse(failure.getMessage().contains(SENTINEL));
        assertNull(failure.getCause());
        assertEquals(signCount, runtime.submittedSignCount());
        assertEquals(statusCount, runtime.store().listStatusObjects(command.issuerCaId()).size());
    }

    private static PkiStore storeView(PkiStore delegate, List<RevocationJournal> journals,
            Map<PkiId, Credential> credentials, boolean failListing) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    if (method.getName().equals("listRevocationJournals")) {
                        if (failListing) {
                            throw new IllegalStateException(SENTINEL);
                        }
                        return journals;
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

    private static CredentialFramework frameworkView(CredentialFramework delegate,
            StatusObjectGenerator generator) {
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

    private static RevocationJournal journal(PkiId credentialId, RevocationState state, Instant time,
            Optional<RevocationReason> reason) {
        return new RevocationJournal(credentialId, List.of(new RevocationTransition(
                1L, state, time, reason, emptyAttributes())));
    }

    private static Credential copy(Credential template, String suffix, FormatId formatId, EncodedObject encoded) {
        CaProfileBinding binding = assertInstanceOf(CaProfileBinding.class, template.profileBinding());
        return new Credential(new PkiId("credential:" + suffix), formatId, template.issuerRef(),
                template.subjectRef(), template.validity(), template.serialOrUniqueId(),
                template.publicKeyId(), new CaProfileBinding(binding.reference()), CredentialStatus.ISSUED, encoded,
                template.attributes());
    }

    private static StatusObjectGenerateCommand crlCommand(PkiId caId, Credential issuer, KeyRef keyRef) {
        AttributeSet attributes = SimpleAttributeSet.builder()
                .put(BcX509Attributes.ISSUER_CERT_DER,
                        new AttributeValue.BytesValue(issuer.encoded().bytes()))
                .put(BcX509Attributes.ISSUER_KEYREF, new AttributeValue.StringValue(keyRef.value()))
                .build();
        return new StatusObjectGenerateCommand(caId, StatusObjectType.CRL,
                BcX509CredentialFramework.FORMAT_ID, attributes);
    }

    private static Credential issue(PkiTestRuntime runtime, PkiId caId, KeyPair subjectKey, String commonName)
            throws Exception {
        PKCS10CertificationRequest request = certificationRequest(subjectKey, commonName);
        ParsedCertificationRequest parsed = runtime.certificationRequestService().parse(
                new CertificationRequest(runtime.framework().formatId(),
                        new EncodedObject(Encoding.DER, request.getEncoded())));
        runtime.certificationRequestService().verifyProofOfPossession(parsed,
                new VerificationPolicy(true, Optional.empty()));
        IssuanceService issuance = runtime.issuanceService();
        return issuance.issueEndEntity(new IssueEndEntityCommand(caId, parsed, "default",
                Optional.empty())).credential();
    }

    private static PKCS10CertificationRequest certificationRequest(KeyPair pair, String commonName)
            throws Exception {
        X500Name subject = new X500Name("CN=" + commonName);
        PKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic());
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
        return Arrays.stream(RevocationReason.values())
                .filter(reason -> reason != RevocationReason.REMOVE_FROM_CRL)
                .toList();
    }

    private static List<BigInteger> serials(int size) {
        List<BigInteger> values = new ArrayList<>(List.of(
                BigInteger.ONE,
                BigInteger.valueOf(Long.MAX_VALUE),
                BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE),
                BigInteger.ONE.shiftLeft(159).subtract(BigInteger.ONE)));
        for (long value = 2L; values.size() < size; value++) {
            values.add(BigInteger.valueOf(value));
        }
        return List.copyOf(values);
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

    private static void assertEntry(X509CRLHolder crl, BigInteger serial, Instant time,
            RevocationReason reason) {
        X509CRLEntryHolder entry = crl.getRevokedCertificate(serial);
        assertTrue(entry != null);
        assertEquals(Date.from(time.truncatedTo(ChronoUnit.SECONDS)), entry.getRevocationDate());
        assertEquals(reasonCode(reason), encodedReason(entry));
    }

    private static X509CertificateHolderView certificate(Credential credential) throws Exception {
        byte[] encoded = credential.encoded().bytes();
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
