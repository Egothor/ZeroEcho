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
package zeroecho.pki.server.ct;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import zeroecho.pkix.Pkix;
import zeroecho.pkix.ct.PreCertificateResult;
import zeroecho.pkix.ct.SignedCertificateTimestamp;
import zeroecho.pkix.sign.ContentSigner;

/**
 * Certificate Transparency pipeline stage that runs between request approval and final
 * certificate signing (Mode B — external CT log submission).
 *
 * <p>For each issuance, {@link #beforeSigning} performs the full RFC 9162 pre-issuance
 * CT sequence:</p>
 * <ol>
 *   <li>Build a CT pre-certificate by adding the CT poison extension and signing it with
 *       the CA's key ({@link PreCertificateBuilder}).</li>
 *   <li>Submit the pre-certificate in parallel to all configured CT logs and collect SCTs
 *       within the configured timeout ({@link CtLogSubmitter}).</li>
 *   <li>Verify each collected SCT's timestamp freshness and cryptographic signature
 *       against the corresponding log's public key ({@link SctVerifier}).</li>
 *   <li>Embed the verified SCTs into the original {@code TBSCertificate} as the SCT list
 *       extension (OID 1.3.6.1.4.1.11129.2.4.2) using {@link Pkix#embedScts}.</li>
 *   <li>Return the modified {@code TBSCertificate} DER for final signing.</li>
 * </ol>
 *
 * <p>If fewer than {@link #minScts} SCTs survive verification the method throws
 * {@link CtSubmissionException} and the issuance is aborted. No serial number is
 * consumed and no credential is committed to the store.</p>
 *
 * <p>This interceptor is a no-op when instantiated with an empty log list (useful for
 * authorities that do not require CT). Use the factory method {@link #disabled()} to
 * obtain a disabled instance.</p>
 *
 * <h2>Thread safety</h2>
 * <p>This class is immutable and thread-safe after construction.</p>
 *
 * @since 1.0
 */
public final class CtIssuanceInterceptor {

    private final List<CtLogClient> logs;
    private final Map<String, PublicKey> logPublicKeys;
    private final int minScts;
    private final Duration submissionTimeout;

    /**
     * Creates a CT issuance interceptor.
     *
     * @param logs              CT log clients to submit pre-certificates to; must not be
     *                          {@code null}; may be empty (disables CT for this authority)
     * @param logPublicKeys     map from hex log ID to the log's EC or RSA public key; must
     *                          not be {@code null}
     * @param minScts           minimum number of valid SCTs required for issuance (typically ≥ 2)
     * @param submissionTimeout maximum total time allowed for parallel log submission; must
     *                          not be {@code null} and must be positive
     * @throws NullPointerException     if any argument is {@code null}
     * @throws IllegalArgumentException if {@code minScts} is negative or
     *                                  {@code submissionTimeout} is not positive
     * @since 1.0
     */
    public CtIssuanceInterceptor(List<CtLogClient> logs, Map<String, PublicKey> logPublicKeys,
            int minScts, Duration submissionTimeout) {
        this.logs = List.copyOf(Objects.requireNonNull(logs, "logs"));
        this.logPublicKeys = Map.copyOf(Objects.requireNonNull(logPublicKeys, "logPublicKeys"));
        if (minScts < 0) {
            throw new IllegalArgumentException("minScts must be >= 0; got " + minScts);
        }
        this.minScts = minScts;
        Objects.requireNonNull(submissionTimeout, "submissionTimeout");
        if (submissionTimeout.isNegative() || submissionTimeout.isZero()) {
            throw new IllegalArgumentException("submissionTimeout must be positive: " + submissionTimeout);
        }
        this.submissionTimeout = submissionTimeout;
    }

    /**
     * Returns a disabled interceptor that passes {@code tbsCertificateDer} through unchanged.
     *
     * <p>This sentinel avoids null checks at call sites for authorities without CT configured.</p>
     *
     * @return disabled interceptor instance
     * @since 1.0
     */
    public static CtIssuanceInterceptor disabled() {
        return new CtIssuanceInterceptor(List.of(), Map.of(), 0, Duration.ofSeconds(30));
    }

    /**
     * Returns {@code true} if this interceptor has at least one CT log configured.
     *
     * @return {@code true} if CT log submission will be performed
     * @since 1.0
     */
    public boolean isEnabled() {
        return !logs.isEmpty();
    }

    /**
     * Executes the CT pre-issuance pipeline and returns the modified {@code TBSCertificate}
     * DER with SCTs embedded.
     *
     * <p>If this interceptor was constructed with an empty log list (see {@link #disabled()}),
     * the input {@code tbsCertificateDer} is returned unchanged.</p>
     *
     * @param tbsCertificateDer DER-encoded {@code TBSCertificate} for the certificate being
     *                          issued; must not be {@code null}
     * @param issuerChainDer    DER-encoded issuer chain, issuer certificate first; must not be
     *                          {@code null}
     * @param signer            content signer for the issuing CA key, used to sign the
     *                          pre-certificate; must not be {@code null}
     * @return DER-encoded {@code TBSCertificate} with the SCT list extension embedded
     * @throws CtSubmissionException    if fewer than {@link #minScts} SCTs survive verification
     * @throws IllegalArgumentException if pre-certificate construction or SCT embedding fails
     * @throws NullPointerException     if any argument is {@code null}
     * @since 1.0
     */
    public byte[] beforeSigning(byte[] tbsCertificateDer, List<byte[]> issuerChainDer,
            ContentSigner signer) throws CtSubmissionException {
        Objects.requireNonNull(tbsCertificateDer, "tbsCertificateDer");
        Objects.requireNonNull(issuerChainDer, "issuerChainDer");
        Objects.requireNonNull(signer, "signer");

        if (logs.isEmpty()) {
            return tbsCertificateDer;
        }

        // Step 1 — build pre-certificate (adds CT poison extension and signs with CA key)
        PreCertificateResult preCert = PreCertificateBuilder.build(tbsCertificateDer, issuerChainDer, signer);

        // Step 2 — submit pre-certificate in parallel to all configured CT logs
        Instant deadline = Instant.now().plus(submissionTimeout);
        List<SignedCertificateTimestamp> collected = CtLogSubmitter.submitAll(
                preCert.preCertDer(), preCert.chainDer(), logs, deadline);

        // Step 3 — verify timestamp freshness and cryptographic signatures; enforce minScts
        List<SignedCertificateTimestamp> verified = SctVerifier.verifyAll(
                collected, logPublicKeys, preCert.preCertDer(), minScts);

        // Step 4 — embed verified SCTs into the original TBSCertificate
        return Pkix.embedScts(tbsCertificateDer, verified);
    }

    /**
     * Returns the minimum number of valid SCTs required for issuance.
     *
     * @return minimum SCT count
     * @since 1.0
     */
    public int minScts() {
        return minScts;
    }

    /**
     * Returns the maximum time allowed for parallel log submission.
     *
     * @return submission timeout
     * @since 1.0
     */
    public Duration submissionTimeout() {
        return submissionTimeout;
    }
}
