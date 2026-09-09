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
package zeroecho.pki.impl.framework.x509.bc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import java.time.Instant;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionReason;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSignatureWorkflowProvider;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;

public final class WorkflowProofOfPossessionVerifierTest {

    @TempDir
    Path tempDir;

    @Test
    public void verifyRsaCsrViaWorkflow_ok() throws Exception {
        System.out.println("verifyRsaCsrViaWorkflow_ok");

        Path keyringPath = tempDir.resolve("keyring.zek");
        try (KeyringPassword password = zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks.provider().acquire();
                KeyringStore ignored = KeyringStore.create(keyringPath, password)) {
            // Encoded-key verification needs no persisted key entry.
        }
        System.out.println("...keyringPath=" + keyringPath.getFileName());

        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        X500Name subject = new X500Name("CN=csr-test");
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));

        byte[] csrDer = csr.getEncoded();
        System.out.println("...csrDerLen=" + csrDer.length);

        CertificationRequest req = new CertificationRequest(BcX509CredentialFramework.FORMAT_ID,
                new EncodedObject(Encoding.DER, csrDer));

        ParsedCertificationRequest parsed = new BcX509CertificationRequestParser().parse(req);

        ZeroEchoLibSignatureWorkflowProvider provider = new ZeroEchoLibSignatureWorkflowProvider(
                zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks.provider());
        ProviderConfig cfg = new ProviderConfig(provider.id(), Map.of("keyringPath", keyringPath.toString(),
                "keyRefPrefix", "zeroecho-lib:"));
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                tempDir.resolve("store"), FsPkiStoreOptions.defaults());
                SignatureWorkflow wf = provider.allocate(cfg, SignatureWorkflowRuntimeDependencies.local(
                        zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks.provider(), store))) {

            zeroecho.pki.impl.framework.x509.X509AlgorithmResolver.Policy algorithmPolicy =
                    (suite, direction) -> true;
            zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot authority =
                    zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot.compose(List.of(), List.of(provider),
                            List.of(zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot.bindExecutor(
                                    "zeroecho-lib.signature-workflow",
                                    zeroecho.core.spi.AlgorithmExecutionCapability.Direction.VERIFY, wf)),
                            algorithmPolicy);
            WorkflowProofOfPossessionVerifier verifier = new WorkflowProofOfPossessionVerifier(wf, authority);
            VerificationPolicy policy = new VerificationPolicy(true, Optional.empty());

            ProofOfPossessionResult res = verifier.verify(parsed, policy);
            System.out.println("...status=" + res.status());
            assertEquals(ProofOfPossessionStatus.VERIFIED, res.status());
        }

        System.out.println("verifyRsaCsrViaWorkflow_ok...ok");
    }

    @Test
    public void verifyEarlyFailuresViaWorkflow() throws Exception {
        Path keyringPath = tempDir.resolve("keyring-early.zek");
        try (KeyringPassword password = zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks.provider().acquire();
                KeyringStore ignored = KeyringStore.create(keyringPath, password)) {
            // Encoded-key verification needs no persisted key entry.
        }

        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X500Name subject = new X500Name("CN=csr-early");
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));

        ParsedCertificationRequest parsedValid = new BcX509CertificationRequestParser().parse(
                new CertificationRequest(BcX509CredentialFramework.FORMAT_ID,
                        new EncodedObject(Encoding.DER, csr.getEncoded())));

        org.bouncycastle.asn1.pkcs.CertificationRequest original = csr.toASN1Structure();
        org.bouncycastle.asn1.pkcs.CertificationRequest unknownAlgorithm =
                new org.bouncycastle.asn1.pkcs.CertificationRequest(original.getCertificationRequestInfo(),
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4.5.6.7")),
                        original.getSignature());
        ParsedCertificationRequest parsedUnsupported = new BcX509CertificationRequestParser().parse(
                new CertificationRequest(BcX509CredentialFramework.FORMAT_ID,
                        new EncodedObject(Encoding.DER,
                                new PKCS10CertificationRequest(unknownAlgorithm).getEncoded())));

        ParsedCertificationRequest parsedMalformed = new ParsedCertificationRequest(
                parsedValid.requestId(), parsedValid.formatId(), parsedValid.subjectRef(),
                parsedValid.publicKeyInfo(), parsedValid.requestedValidity(), parsedValid.requestedProfileId(),
                parsedValid.subjectRdns(), parsedValid.subjectAlternativeNames(),
                parsedValid.subjectAlternativeNamePresent(),
                SimpleAttributeSet.builder().put(BcX509Attributes.CSR_DER,
                        new AttributeValue.BytesValue(new byte[] { 1, 2, 3, 4 })).build());

        ZeroEchoLibSignatureWorkflowProvider provider = new ZeroEchoLibSignatureWorkflowProvider(
                zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks.provider());
        ProviderConfig cfg = new ProviderConfig(provider.id(), Map.of("keyringPath", keyringPath.toString(),
                "keyRefPrefix", "zeroecho-lib:"));
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                tempDir.resolve("store-early"), FsPkiStoreOptions.defaults());
                SignatureWorkflow wf = provider.allocate(cfg, SignatureWorkflowRuntimeDependencies.local(
                        zeroecho.pki.impl.crypto.zeroecholib.TestKeyringUnlocks.provider(), store))) {
            zeroecho.pki.impl.framework.x509.X509AlgorithmResolver.Policy algorithmPolicy =
                    (suite, direction) -> true;
            zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot authority =
                    zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot.compose(List.of(), List.of(provider),
                            List.of(zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot.bindExecutor(
                                    "zeroecho-lib.signature-workflow",
                                    zeroecho.core.spi.AlgorithmExecutionCapability.Direction.VERIFY, wf)),
                            algorithmPolicy);
            WorkflowProofOfPossessionVerifier verifier = new WorkflowProofOfPossessionVerifier(wf, authority);
            VerificationPolicy policy = new VerificationPolicy(true, Optional.empty());

            assertEquals(ProofOfPossessionReason.UNSUPPORTED_ALGORITHM,
                    verifier.verify(parsedUnsupported, policy).reason());
            assertEquals(ProofOfPossessionReason.CSR_MALFORMED,
                    verifier.verify(parsedMalformed, policy).reason());
        }
    }

    @Test
    public void mapsAbsentStatusToProviderUnavailable() {
        assertEquals(ProofOfPossessionReason.PROVIDER_UNAVAILABLE,
                WorkflowProofOfPossessionVerifier.mapWorkflowStatus(null).reason());
    }

    @Test
    public void mapsNonTerminalStatesToOperationIncomplete() {
        for (SignatureWorkflow.State state : new SignatureWorkflow.State[] {
                SignatureWorkflow.State.PENDING, SignatureWorkflow.State.RUNNING,
                SignatureWorkflow.State.WAITING_APPROVAL }) {
            assertEquals(ProofOfPossessionReason.OPERATION_INCOMPLETE,
                    WorkflowProofOfPossessionVerifier.mapWorkflowStatus(statusWithoutResult(state)).reason(),
                    "state " + state);
        }
    }

    @Test
    public void mapsFailedStateToInternalFailure() {
        assertEquals(ProofOfPossessionReason.INTERNAL_FAILURE,
                WorkflowProofOfPossessionVerifier.mapWorkflowStatus(
                        statusWithoutResult(SignatureWorkflow.State.FAILED)).reason());
    }

    @Test
    public void mapsCancelledAndExpiredToOperationIncomplete() {
        for (SignatureWorkflow.State state : new SignatureWorkflow.State[] {
                SignatureWorkflow.State.CANCELLED, SignatureWorkflow.State.EXPIRED }) {
            assertEquals(ProofOfPossessionReason.OPERATION_INCOMPLETE,
                    WorkflowProofOfPossessionVerifier.mapWorkflowStatus(statusWithoutResult(state)).reason(),
                    "state " + state);
        }
    }

    @Test
    public void mapsSuccessfulVerifiedTrueToVerified() {
        assertEquals(ProofOfPossessionReason.VERIFIED,
                WorkflowProofOfPossessionVerifier.mapWorkflowStatus(succeeded(true)).reason());
    }

    @Test
    public void mapsSuccessfulVerifiedFalseToSignatureInvalid() {
        assertEquals(ProofOfPossessionReason.SIGNATURE_INVALID,
                WorkflowProofOfPossessionVerifier.mapWorkflowStatus(succeeded(false)).reason());
    }

    @Test
    public void mapsSuccessfulWithoutVerifiedFlagToInternalFailure() {
        SignatureWorkflow.OperationStatus status = new SignatureWorkflow.OperationStatus(
                SignatureWorkflow.State.SUCCEEDED, Instant.EPOCH, Optional.empty(),
                Optional.of(new SignatureWorkflow.OperationResult(Optional.empty(), Optional.empty())));
        assertEquals(ProofOfPossessionReason.INTERNAL_FAILURE,
                WorkflowProofOfPossessionVerifier.mapWorkflowStatus(status).reason());
    }

    private static SignatureWorkflow.OperationStatus statusWithoutResult(SignatureWorkflow.State state) {
        return new SignatureWorkflow.OperationStatus(state, Instant.EPOCH, Optional.empty(), Optional.empty());
    }

    private static SignatureWorkflow.OperationStatus succeeded(boolean verified) {
        return new SignatureWorkflow.OperationStatus(SignatureWorkflow.State.SUCCEEDED, Instant.EPOCH,
                Optional.empty(), Optional.of(new SignatureWorkflow.OperationResult(
                        Optional.empty(), Optional.of(verified))));
    }
}
