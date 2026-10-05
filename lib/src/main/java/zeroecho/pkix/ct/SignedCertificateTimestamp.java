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
package zeroecho.pkix.ct;

import java.time.Instant;
import java.util.Objects;

/**
 * A Signed Certificate Timestamp (SCT) received from a Certificate Transparency log,
 * as defined by RFC 9162 (CT 2.0) and RFC 6962 (CT 1.0).
 *
 * <p>An SCT is a cryptographically signed promise from a CT log that it has received
 * and will publish a given certificate (or pre-certificate) within a maximum merge
 * delay. SCTs must be embedded in the final certificate before issuance when operating
 * as a publicly trusted CA.</p>
 *
 * <p>All array fields are defensively copied; the record is immutable and thread-safe.</p>
 *
 * @param version            SCT version: 0 = v1 (RFC 6962), 1 = v2 (RFC 9162)
 * @param logId              32-byte SHA-256 fingerprint of the CT log's public key
 * @param timestamp          the time at which the SCT was issued by the log
 * @param extensions         raw TLS-encoded extensions bytes (empty for most logs)
 * @param signatureAlgorithm JCA signature algorithm name (e.g. {@code "SHA256withECDSA"})
 * @param signature          raw signature bytes from the {@code DigitallySigned} structure
 * @since 1.0
 */
public record SignedCertificateTimestamp( // NOPMD DataClass - Immutable RFC carrier uses defensive array copies.
        int version,
        byte[] logId,
        Instant timestamp,
        byte[] extensions,
        String signatureAlgorithm,
        byte[] signature) {

    /** Required byte length of a CT log ID. */
    public static final int LOG_ID_LENGTH = 32;

    /** Validates and defensively copies all array fields. */
    public SignedCertificateTimestamp {
        Objects.requireNonNull(logId, "logId");
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(extensions, "extensions");
        Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm");
        Objects.requireNonNull(signature, "signature");
        if (logId.length != LOG_ID_LENGTH) {
            throw new IllegalArgumentException(
                    "CT log ID must be exactly " + LOG_ID_LENGTH + " bytes; got " + logId.length);
        }
        if (signatureAlgorithm.isBlank()) {
            throw new IllegalArgumentException("signatureAlgorithm must not be blank");
        }
        if (signature.length == 0) {
            throw new IllegalArgumentException("signature must not be empty");
        }
        logId = logId.clone();
        extensions = extensions.clone();
        signature = signature.clone();
    }

    /**
     * Returns an independent copy of the log ID bytes.
     *
     * @return log ID bytes
     */
    @Override
    public byte[] logId() {
        return logId.clone();
    }

    /**
     * Returns an independent copy of the extensions bytes.
     *
     * @return extensions bytes
     */
    @Override
    public byte[] extensions() {
        return extensions.clone();
    }

    /**
     * Returns an independent copy of the signature bytes.
     *
     * @return signature bytes
     */
    @Override
    public byte[] signature() {
        return signature.clone();
    }
}
