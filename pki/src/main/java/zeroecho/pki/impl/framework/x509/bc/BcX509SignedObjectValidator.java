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

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ContentSlice;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.ocsp.OcspResponse;
import zeroecho.pkix.ocsp.ResponderId;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

/**
 * Edge inspection of a canonically validated signed X.509 object.
 *
 * <p>
 * The original repeatable content is validated incrementally before any
 * normalization. Only the individually bounded algorithm and SPKI values are
 * materialized. Exact outer and TBS algorithm encodings, authoritative binding
 * identities, and signature/key compatibility are then required. This adapter
 * contains no key material and does not perform Phase B execution. It is
 * expressed entirely in terms of the ZeroEcho PKIX library and standard JDK types.
 * </p>
 */
public final class BcX509SignedObjectValidator {

    private static final int COMPARE_BUFFER_BYTES = 4096;
    private static final int MAXIMUM_CERTIFICATE_BYTES = 1024 * 1024;
    private static final int MAXIMUM_ELEMENT_BYTES = 1024 * 1024;
    private static final int MAXIMUM_OCSP_RESPONSE_BYTES = 1024 * 1024;

    private final X509AuthoritySnapshot authority;
    private final StreamingDerReader reader;

    /**
     * Creates a validator owned by one immutable authority snapshot.
     *
     * @param authority runtime binding and security authority
     */
    public BcX509SignedObjectValidator(X509AuthoritySnapshot authority) {
        this.authority = Objects.requireNonNull(authority, "authority");
        this.reader = new StreamingDerReader();
    }

    /**
     * Validates one complete canonical certificate and its exact bindings.
     *
     * @param content original repeatable certificate DER
     * @param expectedSignature optional exact signature identity selected for
     *                          generation
     * @param cancellation operation cancellation signal
     * @return exact signature and subject-key identities
     * @throws IOException if DER, structure, binding, or compatibility is invalid
     */
    public CertificateBindings validateCertificate(RepeatableContent content,
            Optional<AlgorithmIdentity> expectedSignature, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(expectedSignature, "expectedSignature");
        Objects.requireNonNull(cancellation, "cancellation");
        long contentLength = content.length().orElse(-1L);
        if (contentLength <= 0L || contentLength > MAXIMUM_CERTIFICATE_BYTES) {
            throw new IOException("Certificate exceeds adapter domain: code=ADAPTER_ELEMENT_LIMIT_EXCEEDED");
        }
        StreamingDerReader.SignedObjectLayout layout = reader.inspectSignedObject(content,
                StreamingDerReader.SignedObjectKind.CERTIFICATE, cancellation);
        ContentSlice tbsAlgorithm = new ContentSlice(content, layout.tbsAlgorithmOffset(),
                layout.tbsAlgorithmLength());
        ContentSlice outerAlgorithm = new ContentSlice(content, layout.outerAlgorithmOffset(),
                layout.outerAlgorithmLength());
        if (!equalContent(tbsAlgorithm, outerAlgorithm, cancellation)) {
            throw new IOException("Certificate algorithms differ: code=OUTER_TBS_ALGORITHM_MISMATCH");
        }
        AlgorithmIdentity signature = decodeAlgorithm(tbsAlgorithm, X509AlgorithmRole.SIGNATURE_ALGORITHM);
        X509SecurityFloor.requirePermitted(signature);
        if (expectedSignature.isPresent() && !expectedSignature.get().equals(signature)) {
            throw new IOException(
                    "Certificate signature differs from execution plan: code=EXPECTED_SIGNATURE_IDENTITY_MISMATCH");
        }
        ContentSlice spki = new ContentSlice(content, layout.subjectPublicKeyInfoOffset(),
                layout.subjectPublicKeyInfoLength());
        AlgorithmIdentity key = decodeSpki(spki);
        X509SuiteCompatibility.requireCompatible(signature, key);
        return new CertificateBindings(signature, key, layout);
    }

    /**
     * Validates a generated certificate against its exact live signing plan.
     *
     * @param content generated canonical certificate content
     * @param plan non-forgeable execution plan used by the signer
     * @param cancellation cancellation signal
     * @return exact signature and subject-key identities
     * @throws IOException if DER or binding postconditions fail
     * @throws IllegalArgumentException if the plan belongs to another runtime
     */
    public CertificateBindings validateGeneratedCertificate(RepeatableContent content,
            X509ExecutionPlan<SignatureWorkflow> plan, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(plan, "plan");
        authority.authorize(plan, plan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
        return validateCertificate(content, Optional.of(plan.selection().requested()), cancellation);
    }

    /**
     * Validates a generated CRL against its exact live signing plan and issuer
     * certificate.
     *
     * @param content original complete CRL DER
     * @param plan exact non-forgeable SIGN plan used for generation
     * @param issuerCertificate authorized issuer certificate whose exact subject
     *                          Name and SPKI must bind the CRL
     * @param expectedThisUpdate exact {@code thisUpdate} metadata to bind to the
     *                           signed TBSCertList
     * @param expectedNextUpdate exact optional {@code nextUpdate} metadata to bind
     *                           to the signed TBSCertList
     * @param cancellation operation cancellation signal
     * @throws IOException if canonical DER, binding, suite, or signature
     *                     validation fails
     * @throws IllegalArgumentException if the plan belongs to another runtime
     */
    public void validateGeneratedCrl(RepeatableContent content, X509ExecutionPlan<SignatureWorkflow> plan,
            X509Certificate issuerCertificate, Instant expectedThisUpdate,
            Optional<Instant> expectedNextUpdate, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(issuerCertificate, "issuerCertificate");
        Objects.requireNonNull(expectedThisUpdate, "expectedThisUpdate");
        Objects.requireNonNull(expectedNextUpdate, "expectedNextUpdate");
        Objects.requireNonNull(cancellation, "cancellation");
        authority.authorize(plan, plan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
        StreamingDerReader.SignedObjectLayout layout = reader.inspectSignedObject(content,
                StreamingDerReader.SignedObjectKind.CRL, cancellation);
        if (!layout.thisUpdate().equals(Optional.of(expectedThisUpdate))
                || !layout.nextUpdate().equals(expectedNextUpdate)) {
            throw new IOException("CRL update times differ from metadata: code=STATUS_OBJECT_BINDING_MISMATCH");
        }
        ContentSlice issuer = new ContentSlice(content, layout.issuerOffset(), layout.issuerLength());
        try (RepeatableContent expectedIssuer = new ImmutableByteContent(
                issuerCertificate.getSubjectX500Principal().getEncoded())) {
            if (!equalContent(issuer, expectedIssuer, cancellation)) {
                throw new IOException("CRL issuer differs from issuer certificate: code=STATUS_OBJECT_BINDING_MISMATCH");
            }
        }
        ContentSlice tbsAlgorithm = new ContentSlice(content, layout.tbsAlgorithmOffset(),
                layout.tbsAlgorithmLength());
        ContentSlice outerAlgorithm = new ContentSlice(content, layout.outerAlgorithmOffset(),
                layout.outerAlgorithmLength());
        if (!equalContent(tbsAlgorithm, outerAlgorithm, cancellation)) {
            throw new IOException("CRL algorithms differ: code=OUTER_TBS_ALGORITHM_MISMATCH");
        }
        AlgorithmIdentity signatureIdentity = decodeAlgorithm(outerAlgorithm,
                X509AlgorithmRole.SIGNATURE_ALGORITHM);
        if (!plan.selection().requested().equals(signatureIdentity)) {
            throw new IOException("CRL signature differs from execution plan: code=STATUS_OBJECT_BINDING_MISMATCH");
        }
        byte[] issuerPublicKey = Pkix.subjectPublicKeyInfo(issuerCertificate);
        AlgorithmIdentity issuerKey = new BcX509AlgorithmAdapter(authority.bindings()).decode(
                Pkix.subjectPublicKeyAlgorithm(issuerPublicKey), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        X509SuiteCompatibility.requireCompatible(signatureIdentity, issuerKey);
        zeroecho.pkix.AlgorithmIdentifier identifier = decodeIdentifier(outerAlgorithm);
        byte[] signature = materializeElement(new ContentSlice(content, layout.signatureOffset(),
                layout.signatureLength()));
        X509ExecutionPlan<BcX509VerificationExecutor> verification = authority.plan(signatureIdentity, issuerKey,
                AlgorithmExecutionCapability.Direction.VERIFY,
                Optional.of(BcX509VerificationExecutor.IMPLEMENTATION_ID), "status-postcondition",
                authority.bindings().bindingId(BcX509AlgorithmAdapter.fromLib(identifier),
                        X509AlgorithmRole.SIGNATURE_ALGORITHM),
                BcX509VerificationExecutor.class);
        try (RepeatableContent tbs = new ContentSlice(content, layout.tbsOffset(), layout.tbsLength())) {
            if (!verification.executor().verify(authority, verification, issuerPublicKey, identifier, tbs,
                    signature)) {
                throw new IOException("CRL signature invalid: code=SIGNATURE_VERIFICATION_FAILED");
            }
        } catch (GeneralSecurityException exception) {
            throw new IOException("CRL signature invalid: code=SIGNATURE_VERIFICATION_FAILED", exception);
        } finally {
            java.util.Arrays.fill(signature, (byte) 0);
        }
    }

    /**
     * Validates a generated persistent OCSP status object at the service boundary:
     * the plan is re-authorized, the DER parses as a {@code SUCCESSFUL} OCSP
     * response, its responder id and single-response update times bind to the
     * expected metadata, and its signature verifies under the responder (issuer)
     * public key.
     *
     * @param content              signed OCSP response content
     * @param plan                 exact live signing plan minted by this authority
     * @param responderCertificate responder (issuer) certificate
     * @param expectedThisUpdate   exact producedAt / single-response thisUpdate
     * @param expectedNextUpdate   exact single-response nextUpdate metadata
     * @param cancellation         operation cancellation signal
     * @throws IOException if parsing, binding, or signature validation fails
     */
    public void validateGeneratedOcsp(RepeatableContent content, X509ExecutionPlan<SignatureWorkflow> plan,
            X509Certificate responderCertificate, Instant expectedThisUpdate,
            Optional<Instant> expectedNextUpdate, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(responderCertificate, "responderCertificate");
        Objects.requireNonNull(expectedThisUpdate, "expectedThisUpdate");
        Objects.requireNonNull(expectedNextUpdate, "expectedNextUpdate");
        Objects.requireNonNull(cancellation, "cancellation");
        authority.authorize(plan, plan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
        byte[] der;
        try (InputStream input = content.openStream()) {
            der = input.readNBytes(MAXIMUM_OCSP_RESPONSE_BYTES + 1);
        }
        if (der.length > MAXIMUM_OCSP_RESPONSE_BYTES) {
            throw new IOException("OCSP response exceeds its finite bound: code=STATUS_OBJECT_BINDING_MISMATCH");
        }
        try {
            OcspResponse response = Pkix.parseOcspResponse(der);
            ResponderId expectedResponder = ResponderId.byName(responderCertificate.getSubjectX500Principal());
            if (!response.isSuccessful() || !response.producedAt().equals(expectedThisUpdate)
                    || !response.responderId().equals(expectedResponder)
                    || !response.verifySignature(responderCertificate.getPublicKey())) {
                throw new IOException("OCSP response binding invalid: code=STATUS_OBJECT_BINDING_MISMATCH");
            }
            for (OcspResponse.SingleResponse single : response.responses()) {
                if (!single.thisUpdate().equals(expectedThisUpdate)
                        || !single.nextUpdate().equals(expectedNextUpdate)) {
                    throw new IOException("OCSP single-response times differ: code=STATUS_OBJECT_BINDING_MISMATCH");
                }
            }
        } catch (IllegalArgumentException exception) {
            throw new IOException("OCSP signature invalid: code=SIGNATURE_VERIFICATION_FAILED", exception);
        }
    }

    private zeroecho.pkix.AlgorithmIdentifier decodeIdentifier(RepeatableContent content) throws IOException {
        byte[] encoded = materializeElement(content);
        try {
            return Pkix.parseAlgorithmIdentifier(encoded);
        } catch (IllegalArgumentException exception) {
            throw new IOException("Malformed AlgorithmIdentifier: code=UNKNOWN_SIGNATURE_BINDING", exception);
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    private AlgorithmIdentity decodeAlgorithm(RepeatableContent content, X509AlgorithmRole role) throws IOException {
        byte[] encoded = materializeElement(content);
        try {
            zeroecho.pkix.AlgorithmIdentifier identifier = Pkix.parseAlgorithmIdentifier(encoded);
            return new BcX509AlgorithmAdapter(authority.bindings()).decode(identifier, role);
        } catch (IllegalArgumentException exception) {
            throw new IOException("Unknown X.509 algorithm binding: code=UNKNOWN_SIGNATURE_BINDING", exception);
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    private AlgorithmIdentity decodeSpki(RepeatableContent content) throws IOException {
        byte[] encoded = materializeElement(content);
        try {
            return new BcX509AlgorithmAdapter(authority.bindings()).decode(
                    Pkix.subjectPublicKeyAlgorithm(encoded), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        } catch (IllegalArgumentException exception) {
            throw new IOException("Unknown SPKI binding: code=UNKNOWN_SPKI_BINDING", exception);
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    private static byte[] materializeElement(RepeatableContent content) throws IOException {
        long length = content.length().orElse(-1L);
        if (length <= 0L || length > MAXIMUM_ELEMENT_BYTES) {
            throw new IOException("X.509 element exceeds adapter domain: code=ADAPTER_ELEMENT_LIMIT_EXCEEDED");
        }
        byte[] encoded = new byte[(int) length];
        try (InputStream input = content.openStream()) {
            int offset = 0;
            while (offset < encoded.length) {
                int count = input.read(encoded, offset, encoded.length - offset);
                if (count < 0) {
                    throw new IOException("Truncated X.509 element");
                }
                offset += count;
            }
            if (input.read() >= 0) {
                throw new IOException("Trailing X.509 element data");
            }
        }
        return encoded;
    }

    private static boolean equalContent(RepeatableContent left, RepeatableContent right,
            CancellationSignal cancellation) throws IOException {
        if (left.length().orElseThrow() != right.length().orElseThrow()) {
            return false;
        }
        byte[] leftBuffer = new byte[COMPARE_BUFFER_BYTES];
        byte[] rightBuffer = new byte[COMPARE_BUFFER_BYTES];
        try (InputStream leftInput = left.openStream(); InputStream rightInput = right.openStream()) {
            while (true) {
                cancellation.throwIfCancelled();
                int leftCount = leftInput.read(leftBuffer);
                int rightCount = rightInput.read(rightBuffer);
                if (leftCount != rightCount) {
                    return false;
                }
                if (leftCount < 0) {
                    return true;
                }
                for (int index = 0; index < leftCount; index++) {
                    if (leftBuffer[index] != rightBuffer[index]) {
                        return false;
                    }
                }
            }
        } finally {
            java.util.Arrays.fill(leftBuffer, (byte) 0);
            java.util.Arrays.fill(rightBuffer, (byte) 0);
        }
    }

    /**
     * Exact role-specific identities extracted from validated original DER.
     *
     * @param signature exact certificate signature identity
     * @param subjectPublicKey exact subject SPKI identity
     * @param layout immutable original-content offsets
     */
    public record CertificateBindings(AlgorithmIdentity signature, AlgorithmIdentity subjectPublicKey,
            StreamingDerReader.SignedObjectLayout layout) {
        /**
         * Creates immutable binding results.
         *
         * @throws NullPointerException if a value is {@code null}
         */
        public CertificateBindings {
            Objects.requireNonNull(signature, "signature");
            Objects.requireNonNull(subjectPublicKey, "subjectPublicKey");
            Objects.requireNonNull(layout, "layout");
        }
    }
}
