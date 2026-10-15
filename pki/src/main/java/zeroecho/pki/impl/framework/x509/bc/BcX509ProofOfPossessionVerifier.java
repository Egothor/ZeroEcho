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

import zeroecho.pkix.cmp.CrmfRequest;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import java.util.Optional;

import zeroecho.pkix.Pkix;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionReason;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.spi.framework.ProofOfPossessionVerifier;

/**
 * Immutable proof verifier for exact PKCS#10 and signing-key CRMF requests.
 * The sole original transport attribute and syntax-specific digest identity are
 * checked before parsing. Both syntaxes use the requested SPKI and exact signed
 * bytes through the injected authority's algorithm bindings, immutable security
 * floor, configured policy and verification executor.
 *
 * <p>CRMF supports a complete subject/key CertRequest without PoPInput.
 * Verification proves possession only; it does not authorize enrollment or
 * replace certificate-profile validation. When proof is not required by the
 * supplied verification policy, the result is NOT_PRESENT without parsing.
 * Untrusted request diagnostics are reduced to stable failure reasons.</p>
 *
 * <p>Instances are thread-safe with their immutable runtime authority graph.
 * Parsing and defensive snapshots use linear time and memory in the bounded
 * request size, in addition to cryptographic verification costs.</p>
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
     * Verifies the retained request's original self-signature or signing-key PoP.
     * Exactly one bounded byte-valued {@link BcX509Attributes#CSR_DER} or
     * {@link BcX509Attributes#CRMF_DER} attribute is accepted. Malformed payloads,
     * unsupported algorithms and invalid signatures produce stable failed results.
     * @param request normalized request retaining its original signed bytes
     * @param policy whether proof is required for this verification invocation
     * @return proof outcome, never null
     * @throws IllegalArgumentException if either argument is null
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
            return ProofOfPossessionResult.of(ProofOfPossessionReason.NOT_PRESENT);
        }

        X509EnrollmentPayload payload;
        try {
            payload = BcX509RequestPayloads.extract(request);
        } catch (IllegalArgumentException invalid) {
            return ProofOfPossessionResult.of(ProofOfPossessionReason.CSR_PAYLOAD_MISSING, "CSR payload not present");
        }
        byte[] csrDer = payload.der();

        try {
            byte[] spkiDer;
            byte[] signedBytes;
            byte[] signature;
            zeroecho.pkix.AlgorithmIdentifier signatureAlgorithm;
            try {
                new StreamingDerReader().validate(csrDer,
                        BcX509CertificationRequestParser.MAXIMUM_CSR_DER_BYTES);
                if (payload.kind() == X509EnrollmentPayload.Kind.PKCS10) {
                    zeroecho.pkix.csr.CertificationRequest csr = Pkix.parseCertificationRequest(csrDer);
                    spkiDer = csr.subjectPublicKeyInfo();
                    signedBytes = csr.certificationRequestInfo();
                    signatureAlgorithm = csr.signatureAlgorithm();
                    signature = csr.signature();
                } else {
                    CrmfRequest crmf = CrmfRequest.parse(csrDer);
                    spkiDer = crmf.subjectPublicKeyInfo();
                    signedBytes = crmf.signedRequest();
                    signatureAlgorithm = crmf.signatureAlgorithm();
                    signature = crmf.signature();
                }
            } catch (Exception ex) {
                return ProofOfPossessionResult.of(ProofOfPossessionReason.CSR_MALFORMED, "Invalid CSR");
            }
            BcX509AlgorithmAdapter algorithmAdapter = new BcX509AlgorithmAdapter(authority.bindings());
            try {
                AlgorithmIdentity signatureIdentity = algorithmAdapter.decode(signatureAlgorithm,
                        X509AlgorithmRole.SIGNATURE_ALGORITHM);
                AlgorithmIdentity keyIdentity = algorithmAdapter.decode(Pkix.subjectPublicKeyAlgorithm(spkiDer),
                        X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
                X509ExecutionPlan<BcX509VerificationExecutor> plan = authority.plan(signatureIdentity, keyIdentity,
                        AlgorithmExecutionCapability.Direction.VERIFY,
                        Optional.of(BcX509VerificationExecutor.IMPLEMENTATION_ID), "csr-proof",
                        authority.bindings().bindingId(BcX509AlgorithmAdapter.fromLib(signatureAlgorithm),
                                X509AlgorithmRole.SIGNATURE_ALGORITHM),
                        BcX509VerificationExecutor.class);
                boolean valid = executor.verify(authority, plan, spkiDer,
                        signatureAlgorithm, new ImmutableByteContent(signedBytes), signature);
                if (!valid) {
                    return ProofOfPossessionResult.of(ProofOfPossessionReason.SIGNATURE_INVALID,
                            "CSR signature invalid");
                }
            } catch (IllegalArgumentException unsupported) {
                return ProofOfPossessionResult.of(ProofOfPossessionReason.UNSUPPORTED_ALGORITHM,
                        "Unsupported CSR algorithm");
            }
            return ProofOfPossessionResult.of(ProofOfPossessionReason.VERIFIED);
        } catch (Exception ex) {
            return ProofOfPossessionResult.of(ProofOfPossessionReason.INTERNAL_FAILURE, "Verification failed");
        }
    }
}
