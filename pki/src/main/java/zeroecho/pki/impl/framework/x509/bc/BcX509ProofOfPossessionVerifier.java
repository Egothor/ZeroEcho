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

import java.util.Optional;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.spi.framework.ProofOfPossessionVerifier;

/**
 * Bouncy Castle backed proof-of-possession verifier for X.509 PKCS#10
 * certification requests.
 *
 * <p>
 * This verifier evaluates whether a parsed certification request demonstrates
 * possession of the private key corresponding to the public key carried in the
 * CSR. For PKCS#10 requests, this is done by validating the CSR's
 * self-signature using the {@code SubjectPublicKeyInfo} embedded in the request
 * itself.
 * </p>
 *
 * <p>
 * The verifier expects the original CSR payload to be present in the parsed
 * request attributes under {@link BcX509Attributes#CSR_DER} as a DER-encoded
 * byte sequence. The parsed request object is otherwise treated only as a
 * carrier of normalized request metadata and of the original CSR encoding
 * needed for cryptographic proof-of-possession verification.
 * </p>
 *
 * <h2>Verification policy handling</h2>
 * <ul>
 * <li>When {@link VerificationPolicy#requireProofOfPossession()} returns
 * {@code false}, this implementation does not attempt CSR signature validation
 * and instead returns {@link ProofOfPossessionStatus#NOT_PRESENT}.</li>
 * <li>When proof of possession is required, the verifier performs cryptographic
 * validation of the PKCS#10 signature.</li>
 * </ul>
 *
 * <h2>Failure model</h2>
 * <p>
 * This implementation does not throw framework-specific verification failures
 * for malformed, unsigned, or unverifiable CSRs during normal verification
 * flow. Instead, such conditions are mapped to {@link ProofOfPossessionResult}
 * with status {@link ProofOfPossessionStatus#FAILED} and a stable textual
 * reason. Only caller contract violations such as {@code null} input arguments
 * are surfaced as immediate argument exceptions.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>This verifier validates only proof of possession of the CSR key pair. It
 * does not perform issuance policy validation, trust evaluation, subject
 * authorization checks, or profile compliance checks.</li>
 * <li>The presence of a valid PKCS#10 self-signature does not by itself imply
 * that the requester is entitled to receive the requested certificate.</li>
 * <li>Algorithm identity, X.509 binding, immutable security-floor, capability,
 * and configured-policy decisions are taken from one injected
 * {@link X509AuthoritySnapshot}. Bouncy Castle remains only the structural and
 * cryptographic adapter at this Phase A boundary.</li>
 * <li>The CSR payload carried under {@link BcX509Attributes#CSR_DER} may be
 * operationally sensitive and must not be logged unsafely.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is immutable and thread-safe when its authority snapshot is shared
 * as part of one immutable runtime graph.
 * </p>
 */
public final class BcX509ProofOfPossessionVerifier implements ProofOfPossessionVerifier {

    private final X509AuthoritySnapshot authority;
    private final BcX509VerificationExecutor executor;

    /**
     * Creates a verifier backed by one runtime authority and its exact executor.
     *
     * @param authority identity, binding, capability, floor, and policy authority;
     *                  must not be {@code null}
     * @param executor process-local verification executor bound into
     *                 {@code authority}
     * @throws NullPointerException if {@code authority} is {@code null}
     */
    public BcX509ProofOfPossessionVerifier(X509AuthoritySnapshot authority, BcX509VerificationExecutor executor) {
        this.authority = java.util.Objects.requireNonNull(authority, "authority");
        this.executor = java.util.Objects.requireNonNull(executor, "executor");
    }

    /**
     * Verifies proof of possession for a parsed PKCS#10 certification request.
     *
     * <p>
     * If the supplied {@link VerificationPolicy} does not require proof of
     * possession, the method returns {@link ProofOfPossessionStatus#NOT_PRESENT}
     * without attempting CSR signature validation.
     * </p>
     *
     * <p>
     * Otherwise, the method expects the original CSR DER payload to be present in
     * {@code request.attributes()} under {@link BcX509Attributes#CSR_DER} as an
     * {@link AttributeValue.BytesValue}. It then parses the CSR, creates a Bouncy
     * Castle content verifier from the CSR's embedded subject public
     * key information, and validates the PKCS#10 signature.
     * </p>
     *
     * <p>
     * Verification outcomes are mapped as follows:
     * </p>
     * <ul>
     * <li>missing or wrongly typed CSR payload attribute -
     * {@link ProofOfPossessionStatus#FAILED} with reason
     * {@code "CSR payload not present"},</li>
     * <li>structurally invalid CSR - {@link ProofOfPossessionStatus#FAILED} with
     * reason {@code "Invalid CSR"},</li>
     * <li>verifier construction failure - {@link ProofOfPossessionStatus#FAILED}
     * with reason {@code "Verifier unavailable"},</li>
     * <li>signature validation failure - {@link ProofOfPossessionStatus#FAILED}
     * with reason {@code "CSR signature invalid"},</li>
     * <li>successful signature validation -
     * {@link ProofOfPossessionStatus#VERIFIED}.</li>
     * </ul>
     *
     * <p>
     * Any other unexpected verification problem is mapped to
     * {@link ProofOfPossessionStatus#FAILED} with reason
     * {@code "Verification failed"}.
     * </p>
     *
     * @param request parsed certification request to verify; must not be
     *                {@code null}
     * @param policy  verification policy controlling whether proof of possession is
     *                required; must not be {@code null}
     * @return proof-of-possession verification result, never {@code null}
     * @throws IllegalArgumentException if {@code request} or {@code policy} is
     *                                  {@code null}
     */
    @Override
    public ProofOfPossessionResult verify(ParsedCertificationRequest request, VerificationPolicy policy) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        if (policy == null) {
            throw new IllegalArgumentException("policy must not be null");
        }
        if (!policy.requireProofOfPossession()) {
            return new ProofOfPossessionResult(ProofOfPossessionStatus.NOT_PRESENT, Optional.empty());
        }

        Optional<AttributeValue> csrDerOpt = request.attributes().get(BcX509Attributes.CSR_DER);
        if (csrDerOpt.isEmpty() || !(csrDerOpt.get() instanceof AttributeValue.BytesValue)) {
            return new ProofOfPossessionResult(ProofOfPossessionStatus.FAILED, Optional.of("CSR payload not present"));
        }
        byte[] csrDer = ((AttributeValue.BytesValue) csrDerOpt.get()).value();

        try {
            PKCS10CertificationRequest csr;
            try {
                new StreamingDerReader().validate(csrDer,
                        BcX509CertificationRequestParser.MAXIMUM_CSR_DER_BYTES);
                csr = new PKCS10CertificationRequest(csrDer);
            } catch (Exception ex) {
                return new ProofOfPossessionResult(ProofOfPossessionStatus.FAILED, Optional.of("Invalid CSR"));
            }
            BcX509AlgorithmAdapter algorithmAdapter = new BcX509AlgorithmAdapter(authority.bindings());
            try {
                AlgorithmIdentity signatureIdentity = algorithmAdapter.decode(csr.getSignatureAlgorithm(),
                        X509AlgorithmRole.SIGNATURE_ALGORITHM);
                AlgorithmIdentity keyIdentity = algorithmAdapter.decode(csr.getSubjectPublicKeyInfo().getAlgorithm(),
                        X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
                X509ExecutionPlan<BcX509VerificationExecutor> plan = authority.plan(signatureIdentity, keyIdentity,
                        AlgorithmExecutionCapability.Direction.VERIFY,
                        Optional.of(BcX509VerificationExecutor.IMPLEMENTATION_ID), "csr-proof",
                        BcX509VerificationExecutor.class);
                byte[] signedBytes = csr.toASN1Structure().getCertificationRequestInfo().getEncoded();
                boolean valid = executor.verify(authority, plan, csr.getSubjectPublicKeyInfo(),
                        csr.getSignatureAlgorithm(), new ImmutableByteContent(signedBytes), csr.getSignature());
                if (!valid) {
                    return new ProofOfPossessionResult(ProofOfPossessionStatus.FAILED,
                            Optional.of("CSR signature invalid"));
                }
            } catch (IllegalArgumentException unsupported) {
                return new ProofOfPossessionResult(ProofOfPossessionStatus.FAILED,
                        Optional.of("Unsupported CSR algorithm"));
            }
            return new ProofOfPossessionResult(ProofOfPossessionStatus.VERIFIED, Optional.empty());
        } catch (OperatorCreationException ex) {
            return new ProofOfPossessionResult(ProofOfPossessionStatus.FAILED, Optional.of("Verifier unavailable"));
        } catch (Exception ex) {
            return new ProofOfPossessionResult(ProofOfPossessionStatus.FAILED, Optional.of("Verification failed"));
        }
    }
}
