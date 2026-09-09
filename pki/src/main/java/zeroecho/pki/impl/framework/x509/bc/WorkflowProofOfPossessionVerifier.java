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

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pkix.Pkix;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionReason;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.spi.framework.ProofOfPossessionVerifier;

/**
 * Proof-of-possession verifier for PKCS#10 certification requests that
 * delegates signature verification to a {@link SignatureWorkflow}.
 *
 * <p>
 * This verifier evaluates whether a parsed PKCS#10 certification request proves
 * possession of the private key corresponding to the public key embedded in the
 * CSR. Unlike a purely local verifier, this implementation routes the actual
 * cryptographic verification through the configured {@link SignatureWorkflow}.
 * This allows proof-of-possession verification to be executed inside the same
 * cryptographic boundary and provider stack used by the runtime for signing and
 * verification.
 * </p>
 *
 * <p>
 * The verifier expects the original CSR payload to be present in the parsed
 * request attributes under {@link BcX509Attributes#CSR_DER} as DER-encoded
 * bytes. It parses the PKCS#10 request, extracts the
 * {@code CertificationRequestInfo} structure as the to-be-verified payload,
 * maps the CSR signature algorithm OID to a ZeroEcho canonical algorithm
 * identifier, and submits a workflow verification request using the CSR
 * {@code SubjectPublicKeyInfo} as the verification key material.
 * </p>
 *
 * <h2>Execution model</h2>
 * <ul>
 * <li>The verifier is synchronous from the caller perspective.</li>
 * <li>It submits one verification workflow operation and immediately reads the
 * resulting workflow status.</li>
 * <li>Providers used for proof-of-possession verification are expected to
 * complete verification immediately or within a short bounded time window.</li>
 * </ul>
 *
 * <h2>Verification policy handling</h2>
 * <ul>
 * <li>When {@link VerificationPolicy#requireProofOfPossession()} returns
 * {@code false}, this verifier does not attempt cryptographic validation and
 * returns {@link ProofOfPossessionStatus#NOT_PRESENT}.</li>
 * <li>When proof of possession is required, the verifier performs cryptographic
 * verification of the PKCS#10 self-signature through the workflow.</li>
 * </ul>
 *
 * <h2>Failure model</h2>
 * <p>
 * This implementation does not throw framework-specific verification failures
 * for malformed, unsupported, or unverifiable CSRs during normal verification
 * flow. Instead, such conditions are mapped to {@link ProofOfPossessionResult}
 * with a stable {@link ProofOfPossessionStatus} and optional textual reason.
 * Only direct caller contract violations such as {@code null} input arguments
 * are surfaced as immediate argument exceptions.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>This verifier validates only proof of possession of the CSR key pair. It
 * does not perform issuance policy validation, subject authorization, or trust
 * evaluation.</li>
 * <li>The original CSR bytes, extracted signature bytes, and subject public key
 * information are operationally sensitive and must not be logged unsafely.</li>
 * <li>The ability to verify a CSR signature does not by itself imply that the
 * requester is entitled to receive a certificate.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is immutable and thread-safe provided that the configured
 * {@link SignatureWorkflow} implementation is safe for the intended runtime
 * model.
 * </p>
 */
public final class WorkflowProofOfPossessionVerifier implements ProofOfPossessionVerifier {

    private static final Purpose PURPOSE = new Purpose("CSR_POP");
    private static final Principal SYSTEM = new Principal("SYSTEM", "pki");

    private final SignatureWorkflow workflow;
    private final X509AuthoritySnapshot authority;

    /**
     * Creates a verifier bound to the runtime's immutable authority snapshot.
     *
     * @param workflow selected verification workflow
     * @param authority matching authority snapshot
     */
    public WorkflowProofOfPossessionVerifier(SignatureWorkflow workflow, X509AuthoritySnapshot authority) {
        this.workflow = Objects.requireNonNull(workflow, "workflow");
        this.authority = Objects.requireNonNull(authority, "authority");
    }

    /**
     * Verifies proof of possession for a parsed PKCS#10 certification request by
     * delegating signature verification to the configured workflow.
     *
     * <p>
     * If the supplied {@link VerificationPolicy} does not require proof of
     * possession, the method returns {@link ProofOfPossessionStatus#NOT_PRESENT}
     * without attempting any CSR processing.
     * </p>
     *
     * <p>
     * Otherwise, the method:
     * </p>
     * <ol>
     * <li>extracts the original CSR DER bytes from
     * {@link BcX509Attributes#CSR_DER},</li>
     * <li>parses the CSR,</li>
     * <li>extracts the subject public key information, signature bytes, and
     * DER-encoded {@code CertificationRequestInfo},</li>
     * <li>maps the X.509 signature algorithm OID to a ZeroEcho algorithm
     * identifier,</li>
     * <li>submits a {@link SignatureWorkflow.VerifyRequest},</li>
     * <li>maps the resulting workflow status to a
     * {@link ProofOfPossessionResult}.</li>
     * </ol>
     *
     * @param request parsed certification request to verify; must not be
     *                {@code null}
     * @param policy  verification policy controlling whether proof of possession is
     *                required; must not be {@code null}
     * @return proof-of-possession verification result, never {@code null}
     * @throws IllegalArgumentException if {@code request} or {@code policy} is
     *                                  {@code null}
     */
    // Provider-backed CSR accessors can throw distinct runtime failures, all mapped to MALFORMED_REQUEST.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
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

        Optional<byte[]> csrDer = extractCsrDer(request);
        if (csrDer.isEmpty()) {
            return failed(ProofOfPossessionReason.CSR_PAYLOAD_MISSING, "CSR payload not present");
        }

        Optional<zeroecho.pkix.csr.CertificationRequest> csr = parseCsr(csrDer.get());
        if (csr.isEmpty()) {
            return failed(ProofOfPossessionReason.CSR_MALFORMED, "Invalid CSR");
        }

        byte[] spkiDer;
        byte[] tbs;
        byte[] signature;
        try {
            spkiDer = csr.get().subjectPublicKeyInfo();
            tbs = csr.get().certificationRequestInfo();
            signature = csr.get().signature();
        } catch (RuntimeException ex) {
            return failed(ProofOfPossessionReason.CSR_MALFORMED, "CSR SPKI missing");
        }

        BcX509AlgorithmAdapter algorithmAdapter = new BcX509AlgorithmAdapter(authority.bindings());
        zeroecho.core.spec.AlgorithmIdentity signatureIdentity;
        X509ExecutionPlan<SignatureWorkflow> executionPlan;
        try {
            signatureIdentity = algorithmAdapter.decode(
                    csr.get().signatureAlgorithm(), X509AlgorithmRole.SIGNATURE_ALGORITHM);
            zeroecho.core.spec.AlgorithmIdentity keyIdentity = algorithmAdapter.decode(
                    Pkix.subjectPublicKeyAlgorithm(spkiDer), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            executionPlan = authority.plan(signatureIdentity, keyIdentity,
                    zeroecho.core.spi.AlgorithmExecutionCapability.Direction.VERIFY,
                    Optional.empty(), "csr-proof",
                    authority.bindings().bindingId(BcX509AlgorithmAdapter.fromLib(
                            csr.get().signatureAlgorithm()), X509AlgorithmRole.SIGNATURE_ALGORITHM),
                    SignatureWorkflow.class);
        } catch (IllegalArgumentException unsupported) {
            return ProofOfPossessionResult.of(ProofOfPossessionReason.UNSUPPORTED_ALGORITHM,
                    "Unsupported CSR algorithm");
        }

        String algorithmId = signatureIdentity.canonicalForm();

        SignatureWorkflow.VerifyRequest verifyRequest = toVerifyRequest(request, algorithmId, tbs, signature,
                spkiDer);

        return verifyWithWorkflow(verifyRequest, executionPlan);
    }

    /**
     * Extracts the original CSR DER bytes from the parsed request attributes.
     *
     * @param request parsed certification request; must not be {@code null}
     * @return optional CSR DER bytes, or an empty optional when the attribute is
     *         missing or has an unexpected value type
     */
    private static Optional<byte[]> extractCsrDer(ParsedCertificationRequest request) {
        Optional<AttributeValue> csrDer = request.attributes().get(BcX509Attributes.CSR_DER);
        if (csrDer.isEmpty() || !(csrDer.get() instanceof AttributeValue.BytesValue)) {
            return Optional.empty();
        }
        return Optional.of(((AttributeValue.BytesValue) csrDer.get()).value());
    }

    /**
     * Parses the supplied PKCS#10 CSR bytes.
     *
     * @param csrDer DER-encoded PKCS#10 request; must not be {@code null}
     * @return optional parsed CSR, or an empty optional when the input is not a
     *         valid PKCS#10 request
     */
    private static Optional<zeroecho.pkix.csr.CertificationRequest> parseCsr(byte[] csrDer) {
        try {
            new StreamingDerReader().validate(csrDer,
                    BcX509CertificationRequestParser.MAXIMUM_CSR_DER_BYTES);
            return Optional.of(Pkix.parseCertificationRequest(csrDer));
        } catch (java.io.IOException | IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    /**
     * Builds the workflow verification request corresponding to the parsed CSR.
     *
     * @param request     original parsed certification request; must not be
     *                    {@code null}
     * @param algorithmId ZeroEcho canonical algorithm identifier; must not be
     *                    {@code null}
     * @param tbsDer      DER-encoded CSR {@code CertificationRequestInfo}; must not
     *                    be {@code null}
     * @param signature   raw CSR signature bytes; must not be {@code null}
     * @param spkiDer     DER-encoded subject public key info; must not be
     *                    {@code null}
     * @return workflow verification request
     */
    private static SignatureWorkflow.VerifyRequest toVerifyRequest(ParsedCertificationRequest request,
            String algorithmId, byte[] tbsDer, byte[] signature, byte[] spkiDer) {
        AccessContext accessContext = new AccessContext(SYSTEM, PURPOSE, Optional.of(request.requestId()),
                Optional.of(request.formatId()));

        return new SignatureWorkflow.VerifyRequest(accessContext, algorithmId, new ImmutableByteContent(tbsDer),
                new EncodedObject(Encoding.BINARY, signature), Optional.empty(),
                Optional.of(new EncodedObject(Encoding.DER, spkiDer)), Optional.of(Instant.now().plusSeconds(30)),
                CancellationSignal.NONE);
    }

    /**
     * Executes workflow-based signature verification and maps the resulting
     * workflow status to a proof-of-possession result.
     *
     * @param verifyRequest workflow verification request; must not be {@code null}
     * @return mapped proof-of-possession result
     */
    private ProofOfPossessionResult verifyWithWorkflow(SignatureWorkflow.VerifyRequest verifyRequest,
            X509ExecutionPlan<SignatureWorkflow> executionPlan) {
        authority.authorize(executionPlan, workflow,
                zeroecho.core.spi.AlgorithmExecutionCapability.Direction.VERIFY);
        Instant callDeadline = verifyRequest.deadline().orElseGet(() -> Instant.now().plusSeconds(30));
        SignatureWorkflow.CallControl control = new SignatureWorkflow.CallControl(callDeadline,
                verifyRequest.cancellation());
        PkiId verifyOperationId = executionPlan.executor().submitVerify(verifyRequest, control);
        return mapWorkflowStatus(executionPlan.executor().status(verifyOperationId, control));
    }

    /**
     * Maps a terminal or non-terminal workflow status to a stable proof-of-possession
     * result. The {@code switch} is exhaustive over {@link SignatureWorkflow.State}, so
     * a new workflow state cannot be introduced without an explicit mapping decision.
     *
     * @param status workflow operation status, or {@code null} if none was reported
     * @return the deterministic proof-of-possession result
     */
    /* default */ static ProofOfPossessionResult mapWorkflowStatus(SignatureWorkflow.OperationStatus status) {
        if (status == null) {
            return failed(ProofOfPossessionReason.PROVIDER_UNAVAILABLE, "Verifier returned no status");
        }
        return switch (status.state()) {
            case SUCCEEDED -> fromVerifiedResult(status);
            case FAILED -> failed(ProofOfPossessionReason.INTERNAL_FAILURE, "Verification workflow failed");
            case CANCELLED -> failed(ProofOfPossessionReason.OPERATION_INCOMPLETE, "Verification was cancelled");
            case EXPIRED -> failed(ProofOfPossessionReason.OPERATION_INCOMPLETE, "Verification deadline expired");
            case PENDING, RUNNING, WAITING_APPROVAL ->
                    failed(ProofOfPossessionReason.OPERATION_INCOMPLETE, "Verifier not completed");
        };
    }

    private static ProofOfPossessionResult fromVerifiedResult(SignatureWorkflow.OperationStatus status) {
        Optional<Boolean> verified = status.result().flatMap(SignatureWorkflow.OperationResult::verified);
        if (verified.isEmpty()) {
            return failed(ProofOfPossessionReason.INTERNAL_FAILURE, "Verification result missing");
        }
        return verified.orElseThrow()
                ? ProofOfPossessionResult.of(ProofOfPossessionReason.VERIFIED)
                : failed(ProofOfPossessionReason.SIGNATURE_INVALID, "CSR signature invalid");
    }

    /**
     * Creates a failed proof-of-possession result carrying a stable reason and
     * non-sensitive diagnostic detail.
     *
     * @param reason  stable verification reason; must not be {@code null}
     * @param details non-sensitive diagnostic text; must not be {@code null}
     * @return the proof-of-possession result
     */
    private static ProofOfPossessionResult failed(ProofOfPossessionReason reason, String details) {
        return ProofOfPossessionResult.of(reason, details);
    }
}
