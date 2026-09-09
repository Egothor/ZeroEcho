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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;
import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.PkiTestRuntime;

/** Real new-arrival admission exhaustion through each core signing service. */
final class SigningOverloadPropagationTest {

    @Test
    void durableWorkExhaustionRetainsTypedOverloadAcrossSigningServices(@TempDir Path root) throws Exception {
        KeyPair rootKey = generateRsa();
        KeyPair intermediateKey = generateRsa();
        KeyPair nextKey = generateRsa();
        KeyPair leafKey = generateRsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:test:overload-root");
        KeyRef intermediateRef = new KeyRef("kref:v1:keyring:test:overload-intermediate");
        KeyRef nextRef = new KeyRef("kref:v1:keyring:test:overload-next");
        Map<KeyRef, KeyPair> keys = Map.of(rootRef, rootKey, intermediateRef, intermediateKey, nextRef, nextKey);

        try (PkiTestRuntime runtime = PkiTestRuntime.createWithMaximumSigningWork(root, root.resolve("bus.log"),
                keys, 1)) {
            PkiId rootId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Overload Root"), "root-ca", Optional.of(rootRef), new SimpleAttributeSet()));
            PkiId intermediateId = runtime.caService().createIntermediate(new IntermediateCreateCommand(
                    runtime.framework().formatId(), rootId, new SubjectRef("CN=Overload Intermediate"),
                    "intermediate-ca", Optional.of(intermediateRef), new SimpleAttributeSet()));
            ParsedCertificationRequest leaf = runtime.certificationRequestService().parse(new CertificationRequest(
                    runtime.framework().formatId(), new EncodedObject(Encoding.DER,
                            certificationRequest(leafKey, "Overload Leaf").getEncoded())));
            int providerCalls = runtime.submittedSignCount();
            int records = runtime.store().listSignRecords().size();
            long stagedFiles = stagedFileCount(root.resolve("store"));

            try (SignWorkflowStore.SignAdmission ignored = runtime.store().reserveSignAdmission()) {
                assertOverloaded(() -> runtime.caService().createRoot(new CaCreateCommand(
                        runtime.framework().formatId(), new SubjectRef("CN=Rejected Root"), "root-ca",
                        Optional.of(nextRef), new SimpleAttributeSet())));
                assertOverloaded(() -> runtime.caService().createIntermediate(new IntermediateCreateCommand(
                        runtime.framework().formatId(), rootId, new SubjectRef("CN=Rejected Intermediate"),
                        "intermediate-ca", Optional.of(nextRef), new SimpleAttributeSet())));
                assertOverloaded(() -> runtime.caService().issueIntermediateCertificate(
                        new IntermediateCertIssueCommand(runtime.framework().formatId(), rootId, intermediateId,
                                "intermediate-ca", Optional.empty(), new SimpleAttributeSet())));
                assertOverloaded(() -> runtime.issuanceService().issueEndEntity(
                        new IssueEndEntityCommand(rootId, leaf, "default", Optional.empty())));
                assertOverloaded(() -> runtime.statusObjectService().generate(new StatusObjectGenerateCommand(rootId,
                        StatusObjectType.CRL, runtime.framework().formatId(), new SimpleAttributeSet())));

                assertEquals(providerCalls, runtime.submittedSignCount());
                assertEquals(records, runtime.store().listSignRecords().size());
                assertEquals(stagedFiles, stagedFileCount(root.resolve("store")));
            }
        }
    }

    private static void assertOverloaded(ThrowingAction action) {
        SigningExecutionException failure = assertThrows(SigningExecutionException.class, action::run);
        assertEquals(SigningExecutionException.Classification.OVERLOADED, failure.classification());
    }

    private static PKCS10CertificationRequest certificationRequest(KeyPair pair, String commonName) throws Exception {
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=" + commonName), pair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        return builder.build(signer);
    }

    private static KeyPair generateRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static long stagedFileCount(Path storeRoot) throws Exception {
        if (!Files.exists(storeRoot)) {
            return 0L;
        }
        try (var paths = Files.walk(storeRoot)) {
            return paths.filter(Files::isRegularFile)
                    .filter(path -> path.toString().contains("signing-content"))
                    .count();
        }
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }
}
