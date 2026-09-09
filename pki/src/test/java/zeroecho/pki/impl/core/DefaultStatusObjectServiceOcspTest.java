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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;
import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.testkit.PkiTestRuntime;

/** Persistent (pre-generated) OCSP status-object generation, signing confinement, and status resolution. */
final class DefaultStatusObjectServiceOcspTest {

    @Test
    void generatesIssuerSignedGoodOcspForCleanCertificate(@TempDir Path root) throws Exception {
        KeyPair rootKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:ocsp-good");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(root, root.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            PkiId caId = createRoot(runtime, rootKeyRef, "OCSP Good Root");
            Credential subject = issue(runtime, caId, generateRsa(), "OcspGoodTarget");
            BigInteger serial = serialOf(runtime, subject);

            StatusObject status = generateOcsp(runtime, caId, serial);

            assertEquals(StatusObjectType.OCSP, status.type());
            assertTrue(status.statusObjectId().value().startsWith("status:"));
            SingleResp single = singleResponse(runtime, caId, status, serial);
            assertEquals(CertificateStatus.GOOD, single.getCertStatus());
            // The pre-generated object is persisted and discoverable as the latest OCSP object.
            assertEquals(status.statusObjectId(),
                    runtime.statusObjectService().getLatest(caId, StatusObjectType.OCSP).orElseThrow()
                            .statusObjectId());
        }
    }

    @Test
    void generatesIssuerSignedRevokedOcspForRevokedCertificate(@TempDir Path root) throws Exception {
        KeyPair rootKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:ocsp-revoked");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(root, root.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            PkiId caId = createRoot(runtime, rootKeyRef, "OCSP Revoked Root");
            Credential subject = issue(runtime, caId, generateRsa(), "OcspRevokedTarget");
            BigInteger serial = serialOf(runtime, subject);
            runtime.revocationService().revokePermanently(new RevocationCommand.RevokePermanently(
                    subject.credentialId(), RevocationReason.KEY_COMPROMISE, runtime.emptyAttributes()));

            StatusObject status = generateOcsp(runtime, caId, serial);

            SingleResp single = singleResponse(runtime, caId, status, serial);
            assertTrue(single.getCertStatus() instanceof RevokedStatus, "expected a revoked OCSP status");
            RevokedStatus revoked = (RevokedStatus) single.getCertStatus();
            assertTrue(revoked.hasRevocationReason());
            assertEquals(CRLReason.keyCompromise, revoked.getRevocationReason());
        }
    }

    @Test
    void ocspForUnknownSerialIsRejected(@TempDir Path root) throws Exception {
        KeyPair rootKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:ocsp-unknown");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(root, root.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            PkiId caId = createRoot(runtime, rootKeyRef, "OCSP Unknown Root");
            PkiException failure = assertThrows(PkiException.class,
                    () -> generateOcsp(runtime, caId, BigInteger.valueOf(999_999L)));
            assertTrue(failure.getMessage().contains("OCSP_TARGET_UNKNOWN"));
        }
    }

    private static StatusObject generateOcsp(PkiTestRuntime runtime, PkiId caId, BigInteger serial) {
        AttributeSet attributes = SimpleAttributeSet.builder()
                .put(BcX509Attributes.OCSP_TARGET_SERIAL, new AttributeValue.StringValue(serial.toString())).build();
        return runtime.statusObjectService().generate(new StatusObjectGenerateCommand(caId, StatusObjectType.OCSP,
                runtime.framework().formatId(), attributes));
    }

    private static SingleResp singleResponse(PkiTestRuntime runtime, PkiId caId, StatusObject status,
            BigInteger serial) throws Exception {
        byte[] der = PkiTestRuntime.readContent(runtime.signingBus(), status.content());
        OCSPResp outer = new OCSPResp(der);
        assertEquals(OCSPRespBuilder.SUCCESSFUL, outer.getStatus());
        BasicOCSPResp basic = (BasicOCSPResp) outer.getResponseObject();
        assertNotNull(basic);
        X509CertificateHolder issuer = issuerCertificate(runtime, caId);
        assertTrue(basic.isSignatureValid(new JcaContentVerifierProviderBuilder()
                .build(issuer.getSubjectPublicKeyInfo())), "OCSP response must verify under the issuer key");
        SingleResp[] responses = basic.getResponses();
        assertEquals(1, responses.length);
        assertEquals(0, responses[0].getCertID().getSerialNumber().compareTo(serial));
        return responses[0];
    }

    private static X509CertificateHolder issuerCertificate(PkiTestRuntime runtime, PkiId caId) throws Exception {
        CaRecord ca = runtime.store().getCa(caId).orElseThrow();
        return new X509CertificateHolder(runtime.credentialBytes(runtime.caCredential(ca, 0)));
    }

    private static BigInteger serialOf(PkiTestRuntime runtime, Credential credential) throws Exception {
        return new X509CertificateHolder(runtime.credentialBytes(credential)).getSerialNumber();
    }

    private static Credential issue(PkiTestRuntime runtime, PkiId caId, KeyPair subjectKey, String commonName)
            throws Exception {
        PKCS10CertificationRequest request = certificationRequest(subjectKey, commonName);
        ParsedCertificationRequest parsed = runtime.certificationRequestService().parse(new CertificationRequest(
                runtime.framework().formatId(), new EncodedObject(Encoding.DER, request.getEncoded())));
        runtime.certificationRequestService().verifyProofOfPossession(parsed,
                new VerificationPolicy(true, Optional.empty()));
        return runtime.issuanceService()
                .issueEndEntity(new IssueEndEntityCommand(caId, parsed, "default", Optional.empty())).credential();
    }

    private static PKCS10CertificationRequest certificationRequest(KeyPair pair, String commonName) throws Exception {
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=" + commonName), pair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        return builder.build(signer);
    }

    private static PkiId createRoot(PkiTestRuntime runtime, KeyRef keyRef, String commonName) {
        return runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                new SubjectRef("CN=" + commonName), "root-ca", Optional.of(keyRef), runtime.emptyAttributes()));
    }

    private static KeyPair generateRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
