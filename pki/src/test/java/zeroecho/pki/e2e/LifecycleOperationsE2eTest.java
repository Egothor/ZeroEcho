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
package zeroecho.pki.e2e;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.credential.CredentialLineage;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.ReplaceCommand;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.RequestQuery;
import zeroecho.pki.api.request.RequestStorePolicy;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.RevocationView;
import zeroecho.pki.testkit.PkiTestRuntime;

/** End-to-end coverage for the credential lifecycle operations (Task 11). */
final class LifecycleOperationsE2eTest {

    @Test
    void replaceIssuesSuccessorLinksLineageAndSupersedesPredecessor(@TempDir Path tempDir) throws Exception {
        KeyPair rootKp = genRsa();
        KeyPair originalKp = genRsa();
        KeyPair replacementKp = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        Map<KeyRef, KeyPair> keys = new HashMap<>();
        keys.put(rootKeyRef, rootKp);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));

            ParsedCertificationRequest original = parse(runtime, originalKp, "CN=Alice");
            CredentialBundle issued = runtime.issuanceService()
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, original, "default", Optional.empty()));
            PkiId originalId = issued.credential().credentialId();

            ParsedCertificationRequest replacementRequest = parse(runtime, replacementKp, "CN=Alice");
            CredentialBundle replacement = runtime.issuanceService()
                    .replace(new ReplaceCommand(originalId, replacementRequest, "default", new SimpleAttributeSet()));
            PkiId replacementId = replacement.credential().credentialId();

            assertNotEquals(originalId, replacementId, "replacement must be a distinct credential");
            assertEquals(Optional.of(originalId),
                    CredentialLineage.supersededCredentialId(replacement.credential().attributes()),
                    "successor must carry a durable lineage pointer to the predecessor");

            try (RevocationView view = runtime.store().openRevocationView()) {
                RevocationRecord record = view.get(originalId).orElseThrow(
                        () -> new AssertionError("predecessor must have a revocation record"));
                assertEquals(RevocationState.PERMANENTLY_REVOKED, record.transition().state());
                assertEquals(Optional.of(RevocationReason.SUPERSEDED), record.transition().permanentReason());
            }

            assertTrue(runtime.store().getCredential(originalId).isPresent(),
                    "superseded predecessor remains stored for audit");
        }
    }

    @Test
    void renewKeepsSubjectAndKeyIssuesFreshValidityAndLeavesPredecessorValid(@TempDir Path tempDir) throws Exception {
        KeyPair rootKp = genRsa();
        KeyPair subjectKp = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        Map<KeyRef, KeyPair> keys = new HashMap<>();
        keys.put(rootKeyRef, rootKp);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));

            ParsedCertificationRequest original = parse(runtime, subjectKp, "CN=Alice");
            CredentialBundle issued = runtime.issuanceService()
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, original, "default", Optional.empty()));
            PkiId originalId = issued.credential().credentialId();
            org.bouncycastle.cert.X509CertificateHolder issuedCert =
                    new org.bouncycastle.cert.X509CertificateHolder(runtime.credentialBytes(issued.credential()));

            CredentialBundle renewed = runtime.issuanceService()
                    .renew(new zeroecho.pki.api.issuance.RenewCommand(originalId, Optional.empty(),
                            new SimpleAttributeSet()));
            org.bouncycastle.cert.X509CertificateHolder renewedCert =
                    new org.bouncycastle.cert.X509CertificateHolder(runtime.credentialBytes(renewed.credential()));

            assertNotEquals(originalId, renewed.credential().credentialId());
            assertEquals(issuedCert.getSubject(), renewedCert.getSubject(), "renewal keeps the subject");
            assertEquals(issuedCert.getSubjectPublicKeyInfo(), renewedCert.getSubjectPublicKeyInfo(),
                    "renewal keeps the subject public key");
            assertNotEquals(issuedCert.getSerialNumber(), renewedCert.getSerialNumber(), "renewal allocates a serial");
            try (RevocationView view = runtime.store().openRevocationView()) {
                Optional<RevocationRecord> record = view.get(originalId);
                assertTrue(record.isEmpty() || record.orElseThrow().transition().state() == RevocationState.CLEAR,
                        "renewal leaves the predecessor valid");
            }
        }
    }

    @Test
    void reissueReproducesFromRecordAndSupersedesPredecessor(@TempDir Path tempDir) throws Exception {
        KeyPair rootKp = genRsa();
        KeyPair subjectKp = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        Map<KeyRef, KeyPair> keys = new HashMap<>();
        keys.put(rootKeyRef, rootKp);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));

            ParsedCertificationRequest original = parse(runtime, subjectKp, "CN=Alice");
            CredentialBundle issued = runtime.issuanceService()
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, original, "default", Optional.empty()));
            PkiId originalId = issued.credential().credentialId();

            CredentialBundle reissued = runtime.issuanceService()
                    .reissue(new zeroecho.pki.api.issuance.ReissueCommand(originalId, new SimpleAttributeSet()));

            assertNotEquals(originalId, reissued.credential().credentialId());
            assertEquals(Optional.of(originalId),
                    CredentialLineage.supersededCredentialId(reissued.credential().attributes()));
            try (RevocationView view = runtime.store().openRevocationView()) {
                RevocationRecord record = view.get(originalId).orElseThrow();
                assertEquals(RevocationState.PERMANENTLY_REVOKED, record.transition().state());
                assertEquals(Optional.of(RevocationReason.SUPERSEDED), record.transition().permanentReason());
            }
        }
    }

    @Test
    void rootRolloverMintsNewGenerationKeepsKeyAndAdvancesCurrentPointer(@TempDir Path tempDir) throws Exception {
        KeyPair rootKp = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        Map<KeyRef, KeyPair> keys = new HashMap<>();
        keys.put(rootKeyRef, rootKp);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            CaRecord before = runtime.caService().getCa(rootCaId);
            PkiId originalGeneration = before.currentIssuanceIssuerId();

            PkiId returned = runtime.caService().rolloverCaCertificate(
                    new CaRolloverCommand(rootCaId, Optional.empty(), Optional.empty(), new SimpleAttributeSet()));

            assertEquals(rootCaId, returned);
            CaRecord after = runtime.caService().getCa(rootCaId);
            assertNotEquals(originalGeneration, after.currentIssuanceIssuerId(), "rollover advances the generation");
            assertEquals(rootKeyRef, after.issuerKeyRef(), "rollover keeps the key");
            assertTrue(after.issuerIds().contains(originalGeneration), "historical generation retained");
            assertTrue(after.issuerIds().contains(after.currentIssuanceIssuerId()), "new generation present");
            assertEquals(2, after.issuerIds().size());
        }
    }

    @Test
    void intermediateRolloverMintsNewGenerationKeepsKeyAndAdvancesCurrentPointer(@TempDir Path tempDir)
            throws Exception {
        KeyPair rootKp = genRsa();
        KeyPair intermediateKp = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        KeyRef intermediateKeyRef = new KeyRef("kref:v1:keyring:test:intermediate");
        Map<KeyRef, KeyPair> keys = new HashMap<>();
        keys.put(rootKeyRef, rootKp);
        keys.put(intermediateKeyRef, intermediateKp);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            PkiId rootId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            PkiId intermediateId = runtime.caService().createIntermediate(new IntermediateCreateCommand(
                    runtime.framework().formatId(), rootId, new SubjectRef("CN=Intermediate"), "intermediate-ca",
                    Optional.of(intermediateKeyRef), new SimpleAttributeSet()));
            PkiId originalGeneration = runtime.caService().getCa(intermediateId).currentIssuanceIssuerId();

            PkiId returned = runtime.caService().rolloverCaCertificate(new CaRolloverCommand(intermediateId,
                    Optional.of(rootId), Optional.empty(), new SimpleAttributeSet()));

            assertEquals(intermediateId, returned);
            CaRecord after = runtime.caService().getCa(intermediateId);
            assertNotEquals(originalGeneration, after.currentIssuanceIssuerId(),
                    "intermediate rollover advances the generation");
            assertEquals(intermediateKeyRef, after.issuerKeyRef(), "rollover keeps the key");
            assertEquals(2, after.issuerIds().size());
            assertTrue(after.issuerIds().contains(originalGeneration), "historical generation retained");
        }
    }

    @Test
    void rootKeyRotationAdoptsNewKeyAndAdvancesCurrentPointer(@TempDir Path tempDir) throws Exception {
        KeyPair rootKp = genRsa();
        KeyPair rotatedKp = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        KeyRef rotatedKeyRef = new KeyRef("kref:v1:keyring:test:root-rotated");
        Map<KeyRef, KeyPair> keys = new HashMap<>();
        keys.put(rootKeyRef, rootKp);
        keys.put(rotatedKeyRef, rotatedKp);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            PkiId originalGeneration = runtime.caService().getCa(rootCaId).currentIssuanceIssuerId();

            runtime.caService().rotateCaKey(new CaKeyRotationCommand(rootCaId, Optional.of(rotatedKeyRef),
                    Optional.empty(), new SimpleAttributeSet()));

            CaRecord after = runtime.caService().getCa(rootCaId);
            assertEquals(rotatedKeyRef, after.issuerKeyRef(), "rotation adopts the new key");
            assertNotEquals(originalGeneration, after.currentIssuanceIssuerId(), "rotation advances the generation");
            assertEquals(2, after.issuerIds().size());
        }
    }

    @Test
    void requestSearchFiltersBySubjectAndFormatWithinBound(@TempDir Path tempDir) throws Exception {
        KeyPair rootKp = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        Map<KeyRef, KeyPair> keys = new HashMap<>();
        keys.put(rootKeyRef, rootKp);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            ParsedCertificationRequest alice = parse(runtime, genRsa(), "CN=Alice");
            ParsedCertificationRequest bob = parse(runtime, genRsa(), "CN=Bob");
            runtime.certificationRequestService().store(alice, RequestStorePolicy.STORE_ALWAYS);
            runtime.certificationRequestService().store(bob, RequestStorePolicy.STORE_ALWAYS);

            List<ParsedCertificationRequest> all = runtime.certificationRequestService().search(new RequestQuery(
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
            assertEquals(2, all.size(), "empty query returns all stored requests");

            List<ParsedCertificationRequest> aliceOnly = runtime.certificationRequestService().search(new RequestQuery(
                    Optional.empty(), Optional.of(alice.subjectRef()), Optional.empty(), Optional.empty(),
                    Optional.empty()));
            assertEquals(1, aliceOnly.size(), "subject filter narrows to one");
            assertEquals(alice.requestId(), aliceOnly.get(0).requestId());

            List<ParsedCertificationRequest> byFormat = runtime.certificationRequestService().search(new RequestQuery(
                    Optional.of(runtime.framework().formatId()), Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty()));
            assertEquals(2, byFormat.size(), "matching format returns all");

            List<ParsedCertificationRequest> none = runtime.certificationRequestService().search(new RequestQuery(
                    Optional.of(new FormatId("no-such-format")), Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty()));
            assertTrue(none.isEmpty(), "non-matching format returns empty");
        }
    }

    @Test
    void renewAndReissueRejectRevokedPredecessorWhileReplaceRecoversWithNewKey(@TempDir Path tempDir)
            throws Exception {
        KeyPair rootKp = genRsa();
        KeyPair subjectKp = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        Map<KeyRef, KeyPair> keys = new HashMap<>();
        keys.put(rootKeyRef, rootKp);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            PkiId leafId = runtime.issuanceService().issueEndEntity(new IssueEndEntityCommand(rootCaId,
                    parse(runtime, subjectKp, "CN=Alice"), "default", Optional.empty())).credential().credentialId();

            runtime.revocationService().revokePermanently(
                    new zeroecho.pki.api.revocation.RevocationCommand.RevokePermanently(leafId,
                            RevocationReason.KEY_COMPROMISE, new SimpleAttributeSet()));

            // renew and reissue re-certify the same (now-compromised) key — must be rejected.
            assertThrows(PkiException.class, () -> runtime.issuanceService().renew(
                    new zeroecho.pki.api.issuance.RenewCommand(leafId, Optional.empty(), new SimpleAttributeSet())));
            assertThrows(PkiException.class, () -> runtime.issuanceService().reissue(
                    new zeroecho.pki.api.issuance.ReissueCommand(leafId, new SimpleAttributeSet())));

            // replace issues under a fresh key from a new request — the correct recovery path.
            CredentialBundle replaced = runtime.issuanceService().replace(new ReplaceCommand(leafId,
                    parse(runtime, genRsa(), "CN=Alice"), "default", new SimpleAttributeSet()));
            assertNotEquals(leafId, replaced.credential().credentialId());
            assertEquals(Optional.of(leafId),
                    CredentialLineage.supersededCredentialId(replaced.credential().attributes()));
            try (RevocationView view = runtime.store().openRevocationView()) {
                assertEquals(RevocationState.PERMANENTLY_REVOKED,
                        view.get(leafId).orElseThrow().transition().state());
            }
        }
    }

    private static ParsedCertificationRequest parse(PkiTestRuntime runtime, KeyPair subjectKey, String dn)
            throws Exception {
        PKCS10CertificationRequest csr = makeCsr(subjectKey, dn);
        return runtime.certificationRequestService().parse(new CertificationRequest(runtime.framework().formatId(),
                new EncodedObject(Encoding.DER, csr.getEncoded())));
    }

    private static PKCS10CertificationRequest makeCsr(KeyPair kp, String dn) throws Exception {
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name(dn), kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return builder.build(signer);
    }

    private static KeyPair genRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
