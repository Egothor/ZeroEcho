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
package zeroecho.pki.server.ct;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pkix.Pkix;
import zeroecho.pkix.ct.SignedCertificateTimestamp;

/**
 * Verifies Signed Certificate Timestamps collected from CT logs before they may be
 * embedded in a final certificate.
 *
 * <p>Verification enforces two invariants per RFC 9162 §4.9 and the operator policy:
 * <ol>
 *   <li><b>Timestamp freshness:</b> SCTs with a timestamp more than
 *       {@value #MAX_FUTURE_DRIFT_MINUTES} minutes in the future are rejected.
 *       A future timestamp indicates a misbehaving or malicious log.</li>
 *   <li><b>Signature validity:</b> The SCT's {@code DigitallySigned} structure must verify
 *       against the corresponding log's public key using the pre-certificate as input.
 *       Any SCT whose cryptographic signature is invalid is discarded.</li>
 * </ol>
 *
 * <p>SCTs from logs not present in the supplied {@code logPublicKeys} map are silently
 * discarded (the log is not trusted by the operator for this authority).</p>
 *
 * <p>After filtering, the {@link #verifyAll} method enforces a minimum SCT count. If
 * fewer than {@code minScts} SCTs survive verification the issuance is aborted by throwing
 * {@link CtSubmissionException}.</p>
 *
 * <h2>Thread safety</h2>
 * <p>This class is stateless and thread-safe.</p>
 *
 * @since 1.0
 */
public final class SctVerifier {

    private static final Logger LOG = Logger.getLogger(SctVerifier.class.getName());

    /** Maximum allowed clock skew between a CT log and the local clock. */
    public static final int MAX_FUTURE_DRIFT_MINUTES = 10;

    /** Prevents instantiation; all methods are static. */
    private SctVerifier() {
        // utility class
    }

    /**
     * Verifies all collected SCTs and returns the subset that are cryptographically valid,
     * enforcing the minimum count required for issuance.
     *
     * <p>Steps performed for each SCT:</p>
     * <ol>
     *   <li>Reject if the SCT's log ID is not in {@code logPublicKeys}.</li>
     *   <li>Reject if the SCT's timestamp is more than {@value #MAX_FUTURE_DRIFT_MINUTES}
     *       minutes in the future.</li>
     *   <li>Reject if {@link Pkix#verifySct} returns {@code false} for the corresponding
     *       log public key and pre-certificate.</li>
     * </ol>
     *
     * <p>If the number of surviving SCTs is less than {@code minScts}, this method throws
     * {@link CtSubmissionException}. Otherwise the verified SCTs are returned.</p>
     *
     * @param scts          SCTs collected by {@link CtLogSubmitter#submitAll}; must not be
     *                      {@code null}
     * @param logPublicKeys map from hex log ID to the corresponding CT log's public key; must
     *                      not be {@code null}
     * @param preCertDer    DER-encoded pre-certificate that was submitted; must not be
     *                      {@code null}
     * @param minScts       minimum number of valid SCTs required for issuance (typically ≥ 2)
     * @return immutable list of verified SCTs; never fewer than {@code minScts} elements
     * @throws CtSubmissionException if fewer than {@code minScts} SCTs survive verification
     * @throws NullPointerException  if any argument is {@code null}
     * @since 1.0
     */
    public static List<SignedCertificateTimestamp> verifyAll(List<SignedCertificateTimestamp> scts,
            Map<String, PublicKey> logPublicKeys, byte[] preCertDer, int minScts)
            throws CtSubmissionException {
        Objects.requireNonNull(scts, "scts");
        Objects.requireNonNull(logPublicKeys, "logPublicKeys");
        Objects.requireNonNull(preCertDer, "preCertDer");

        Instant now = Instant.now();
        Instant maxTimestamp = now.plus(Duration.ofMinutes(MAX_FUTURE_DRIFT_MINUTES));
        HexFormat hex = HexFormat.of();

        List<SignedCertificateTimestamp> verified = new ArrayList<>(scts.size());

        for (SignedCertificateTimestamp sct : scts) {
            String logIdHex = hex.formatHex(sct.logId());

            PublicKey logKey = logPublicKeys.get(logIdHex);
            if (logKey == null) {
                if (LOG.isLoggable(Level.FINE)) {
                    LOG.fine("Discarding SCT from unknown or untrusted log: " + logIdHex);
                }
                continue;
            }

            if (sct.timestamp().isAfter(maxTimestamp)) {
                LOG.warning(() -> "Discarding SCT with future timestamp from log " + logIdHex
                        + ": " + sct.timestamp() + " (local clock: " + now + ")");
                continue;
            }

            boolean valid = Pkix.verifySct(sct, logKey, preCertDer);
            if (!valid) {
                LOG.warning(() -> "Discarding SCT with invalid signature from log " + logIdHex);
                continue;
            }

            verified.add(sct);
        }

        if (verified.size() < minScts) {
            throw new CtSubmissionException(
                    "CT policy requires at least " + minScts + " valid SCT(s), but only "
                            + verified.size() + " survived verification",
                    "");
        }

        return List.copyOf(verified);
    }
}
