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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.CaService;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.api.request.RequestStorePolicy;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevokeCommand;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.testkit.PkiTestRuntime;

/**
 * End-to-end test for PKI core services.
 */
public final class PkiCoreE2eTest {

    @Test
    void e2eRootIssueRevokeCrl(@TempDir Path tempDir) throws Exception {
        System.out.println("e2eRootIssueRevokeCrl");

        Path busFile = tempDir.resolve("bus.log");

        KeyPair rootKp = genRsa();
        KeyPair eeKp = genRsa();

        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        KeyRef eeKeyRef = new KeyRef("kref:v1:keyring:test:ee");

        Map<KeyRef, KeyPair> keys = new HashMap<>();
        keys.put(rootKeyRef, rootKp);
        keys.put(eeKeyRef, eeKp);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, busFile, keys)) {
            CaService caSvc = runtime.caService();
            CertificationRequestService reqSvc = runtime.certificationRequestService();
            IssuanceService issSvc = runtime.issuanceService();
            RevocationService revSvc = runtime.revocationService();
            StatusObjectService stSvc = runtime.statusObjectService();

            // Create ROOT CA (self-signed).
            PkiId rootCaId = caSvc.createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "default", Optional.of(rootKeyRef), emptyAttributes()));
            System.out.println("...rootCaId=" + rootCaId.value());

            // CSR for end entity.
            PKCS10CertificationRequest csr = makeCsr(eeKp, "CN=Alice");
            CertificationRequest req = new CertificationRequest(runtime.framework().formatId(),
                    new EncodedObject(Encoding.DER, csr.getEncoded()));
            ParsedCertificationRequest parsed = reqSvc.parse(req);
            System.out.println("...csrId=" + parsed.requestId().value());

            ProofOfPossessionResult pop = reqSvc.verifyProofOfPossession(parsed,
                    new VerificationPolicy(true, Optional.empty()));
            assertEquals(ProofOfPossessionStatus.VERIFIED, pop.status());

            reqSvc.store(parsed, RequestStorePolicy.STORE_ALWAYS);

            CredentialBundle bundle = issSvc.issueEndEntity(new IssueEndEntityCommand(rootCaId, parsed, "default",
                    Optional.of(new Validity(Instant.now().minus(Duration.ofMinutes(1)),
                            Instant.now().plus(Duration.ofDays(365)))),
                    emptyAttributes()));

            assertNotNull(bundle);
            System.out.println("...issuedCredentialId=" + bundle.credential().credentialId().value());

            X509CertificateHolder eeCert = new X509CertificateHolder(bundle.credential().encoded().bytes());
            assertEquals("CN=Root", eeCert.getIssuer().toString());
            assertEquals("CN=Alice", eeCert.getSubject().toString());

            revSvc.revoke(new RevokeCommand(bundle.credential().credentialId(), RevocationReason.KEY_COMPROMISE,
                    emptyAttributes()));

            StatusObject crl = stSvc.generate(new StatusObjectGenerateCommand(rootCaId, StatusObjectType.CRL,
                    runtime.framework().formatId(), emptyAttributes()));
            assertNotNull(crl);
            System.out.println("...crlId=" + crl.statusObjectId().value());

            X509CRLHolder crlHolder = new X509CRLHolder(crl.encoded().bytes());
            assertTrue(crlHolder.getRevokedCertificate(eeCert.getSerialNumber()) != null);
        }

        System.out.println("e2eRootIssueRevokeCrl...ok");
    }

    private static KeyPair genRsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static PKCS10CertificationRequest makeCsr(KeyPair kp, String dn) throws Exception {
        X500Name subject = new X500Name(dn);
        PKCS10CertificationRequestBuilder b = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return b.build(cs);
    }

    /**
     * Codec-friendly {@link AttributeSet} for tests.
     *
     * <p>
     * The filesystem store codec expects persisted value types to be either
     * primitive/string-like, or be a simple record structure. Using internal
     * runtime attribute implementations may break persistence decoding.
     * </p>
     */
    private static AttributeSet emptyAttributes() {
        return new SimpleAttributeSet();
    }
}
