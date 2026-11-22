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
package zeroecho.pki.impl.framework.x509.bc;


import zeroecho.pki.api.PkiException;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.PkixEncoding;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;

/**
 * Fixed-suite v1 verifier of two SUBJECT-key proofs; it grants no issuance authority.
 */
public final class BcHybridSdkProofVerifier {
    private static final int PRIMARY_FRAME_KIND = 1;
    private static final int MLDSA_SIGNATURE_BYTES = 4627;

    /** Creates a stateless, thread-safe verifier. */
    public BcHybridSdkProofVerifier() {
        // This verifier retains no mutable state.
    }

    /**
     * Verifies the original signed CSR and both domain-separated fresh proofs. Authenticated actor,
     * issuer context and one-shot consumption remain the server gate's responsibility.
     *
     * @param request exact SDK request view
     * @param primaryFrame retained F1 challenge; F2 uses identical fields with kind 2
     * @param primaryProof canonical DER ECDSA/SHA-384 signature
     * @param alternativeProof pure ML-DSA-87 signature with empty context
     * @param now authoritative acceptance time
     * @return immutable sha512-prefixed F3 proof commitment
     * @throws PkiException for mismatched request, expired context or invalid proofs
     * @throws NullPointerException if {@code request}, {@code primaryFrame}, {@code primaryProof},
     *     {@code alternativeProof} or {@code now} is null
     */
    // Retain the stable proof-failure boundary without forwarding untrusted parser diagnostics.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public String verify(
            ParsedHybridSdkRequest request,
            HybridSdkFrame primaryFrame,
            byte[] primaryProof,
            byte[] alternativeProof,
            Instant now) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(primaryFrame, "primaryFrame");
        Objects.requireNonNull(primaryProof, "primaryProof");
        Objects.requireNonNull(alternativeProof, "alternativeProof");
        Objects.requireNonNull(now, "now");
        if (primaryProof.length > 104 || alternativeProof.length != MLDSA_SIGNATURE_BYTES) {
            throw invalid();
        }
        byte[] primary = primaryProof.clone();
        byte[] alternative = alternativeProof.clone();
        try {
            byte[] original = ProofChecks.original(request);
            requireMatchingRequest(request);
            requireFrameContext(request, primaryFrame, now, original);
            Keys keys = ProofChecks.keys(request);
            ProofChecks.requireEcdsaSignature(primary);
            if (alternative.length != MLDSA_SIGNATURE_BYTES) {
                throw invalid();
            }
            HybridSdkFrame alternativeFrame = new HybridSdkFrame(2, primaryFrame.fields());
            if (!ProofChecks.verifyEcdsa(keys.primary(), primaryFrame.encode(), primary)
                    || !ProofChecks.verifyMldsa(
                            keys.alternative(), alternativeFrame.encode(), alternative)) {
                throw invalid();
            }
            HybridSdkFrame proof =
                    new HybridSdkFrame(
                            3,
                            Map.of(
                                    1,
                                    HybridSdkFrame.hash(primaryFrame.encode()),
                                    2,
                                    HybridSdkFrame.hash(alternativeFrame.encode()),
                                    3,
                                    primary.clone(),
                                    4,
                                    alternative.clone(),
                                    5,
                                    primaryFrame.field(17)));
            return "sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(proof.encode()));
        } catch (java.io.IOException | GeneralSecurityException | IllegalArgumentException invalid) {
            throw invalid();
        }
    }

    private static void requireFrameContext(
            ParsedHybridSdkRequest request,
            HybridSdkFrame primaryFrame,
            Instant now,
            byte[] original) {
        if (primaryFrame.kind() != PRIMARY_FRAME_KIND) {
            throw invalid();
        }
        long issued = ByteBuffer.wrap(primaryFrame.field(7)).getLong();
        long expires = ByteBuffer.wrap(primaryFrame.field(8)).getLong();
        if (now.isBefore(Instant.ofEpochSecond(issued))
                || !now.isBefore(Instant.ofEpochSecond(expires))) {
            throw invalid();
        }
        if (!MessageDigest.isEqual(HybridSdkFrame.hash(original), primaryFrame.field(11))
                || !MessageDigest.isEqual(
                        HybridSdkFrame.hash(request.primary().publicKeyInfo().bytes()),
                        primaryFrame.field(13))
                || !MessageDigest.isEqual(
                        HybridSdkFrame.hash(request.alternativeSubjectPublicKeyInfo().bytes()),
                        primaryFrame.field(14))) {
            throw invalid();
        }
    }

    private static void requireMatchingRequest(ParsedHybridSdkRequest request) {
            ParsedHybridSdkRequest reparsed = new BcX509CertificationRequestParser().parseHybridSdk(request.originalPayload());
        if (!request.primary().subjectRef().equals(reparsed.primary().subjectRef())
                || !request.primary().subjectRdns().equals(reparsed.primary().subjectRdns())
                || !request.primary()
                        .subjectAlternativeNames()
                        .equals(reparsed.primary().subjectAlternativeNames())
                || !Arrays.equals(
                        request.primary().publicKeyInfo().bytes(),
                        reparsed.primary().publicKeyInfo().bytes())
                || !Arrays.equals(
                        request.alternativeSubjectPublicKeyInfo().bytes(),
                        reparsed.alternativeSubjectPublicKeyInfo().bytes())) {
            throw invalid();
        }
    }

    /**
     * Checks the original CSR or CRMF request's exact P-384 proof against its parsed public key.
     *
     * @param request bounded parsed enrollment request retaining its original DER payload
     * @throws NullPointerException if the request or required retained evidence is null
     * @throws IllegalArgumentException if the original request, algorithm, key or proof is
     *     inconsistent or invalid
     */
    // Retain the stable request-failure boundary without forwarding untrusted parser diagnostics.
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static void requireRequest(ParsedHybridSdkRequest request) {
        try {
            Keys keys = ProofChecks.keys(request);
            byte[] der = ProofChecks.original(request);
            if (request.originalPayload().kind() == X509EnrollmentPayload.Kind.CRMF) {
                zeroecho.pkix.cmp.CrmfRequest crmf = zeroecho.pkix.cmp.CrmfRequest.parse(der);
                if (!Arrays.equals(
                                Pkix.encodeAlgorithmIdentifier(crmf.signatureAlgorithm()),
                                HybridSdkFrame.primaryAlgorithm())
                        || !Arrays.equals(
                                crmf.subjectPublicKeyInfo(),
                                request.primary().publicKeyInfo().bytes())) {
                    throw invalid();
                }
                ProofChecks.requireEcdsaSignature(crmf.signature());
                if (!ProofChecks.verifyEcdsa(
                        keys.primary(), crmf.signedRequest(), crmf.signature())) {
                    throw invalid();
                }
            } else {
                PkixEncoding.requireCanonicalCertificationRequest(der);
                CertificationRequest csr = Pkix.parseCertificationRequest(der);
                if (!Arrays.equals(Pkix.encodeAlgorithmIdentifier(csr.signatureAlgorithm()), HybridSdkFrame.primaryAlgorithm())
                        || !Arrays.equals(csr.subjectPublicKeyInfo(), request.primary().publicKeyInfo().bytes())) {
                    throw invalid();
                }
                ProofChecks.requireEcdsaSignature(csr.signature());
                if (!ProofChecks.verifyEcdsa(keys.primary(), csr.certificationRequestInfo(), csr.signature())) {
                    throw invalid();
                }
            }
        } catch (java.io.IOException | GeneralSecurityException | IllegalArgumentException invalid) {
            throw invalid();
        }
    }

    /** Fixed-suite key, encoding and signature checks. */
    private static final class ProofChecks {
        private static Keys keys(ParsedHybridSdkRequest request)
                throws java.io.IOException, GeneralSecurityException {
        byte[] primary = request.primary().publicKeyInfo().bytes();
        byte[] alternative = request.alternativeSubjectPublicKeyInfo().bytes();
            spki(primary);
            spki(alternative);
            PkixEncoding.requireP384SubjectPublicKeyInfo(primary);
            AlgorithmIdentifier alternativeAlgorithm = Pkix.subjectPublicKeyAlgorithm(alternative);
            if (!"2.16.840.1.101.3.4.3.19".equals(alternativeAlgorithm.oid())
                    || alternativeAlgorithm.parameterForm() != AlgorithmIdentifier.ParameterForm.ABSENT
                    || Pkix.subjectPublicKeyBytes(alternative).length != 2592) {
                throw invalid();
            }
            zeroecho.sdk.util.BouncyCastleActivator.init();
            PublicKey primaryKey =
                    KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(primary));
            PublicKey alternativeKey =
                    KeyFactory.getInstance("ML-DSA", "BC")
                            .generatePublic(new X509EncodedKeySpec(alternative));
            if (!Arrays.equals(primary, primaryKey.getEncoded())
                    || !Arrays.equals(alternative, alternativeKey.getEncoded())) {
                throw invalid();
            }
        return new Keys(primaryKey, alternativeKey);
    }

        private static void spki(byte[] der) throws java.io.IOException {
            new StreamingDerReader().validate(der, 8192);
            PkixEncoding.requireCanonicalSubjectPublicKeyInfo(der);
        }
    private static byte[] original(ParsedHybridSdkRequest request) {
        X509EnrollmentPayload payload = BcX509RequestPayloads.extract(request.primary());
            if (payload.kind() != request.originalPayload().kind()
                    || !Arrays.equals(payload.der(), request.originalPayload().der())) {
                throw invalid();
            }
        return payload.der();
    }
    private static boolean verifyEcdsa(PublicKey key, byte[] bytes, byte[] signature) throws GeneralSecurityException {
            Signature verifier = Signature.getInstance("SHA384withECDSA");
            verifier.initVerify(key); verifier.update(bytes); return verifier.verify(signature);
    }
    private static boolean verifyMldsa(PublicKey key, byte[] bytes, byte[] signature) throws GeneralSecurityException {
        return PkixEncoding.verifyEmptyContextMldsa87(key, bytes, signature);
    }

        private static void requireEcdsaSignature(byte[] der) throws java.io.IOException {
            new StreamingDerReader().validate(der, 104);
            PkixEncoding.requireP384Signature(der);
    }
    }

    private static PkiException invalid() { return new PkiException("SDK_PROOF_INVALID"); }
    private record Keys(PublicKey primary, PublicKey alternative) { }
}
