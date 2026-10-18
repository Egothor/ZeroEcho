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
package zeroecho.pki.api.ct;

import java.util.HexFormat;
import java.util.Objects;

/**
 * Describes a Certificate Transparency log endpoint used for Mode B SCT collection.
 *
 * <p>Each operator-configured CT log has a stable log ID (SHA-256 of the log's public key),
 * a base URL for API calls, the log's DER-encoded public key (for future SCT verification),
 * an enabled flag, and a human-readable description.</p>
 *
 * @param logId        64-character lowercase hex string of the SHA-256 of the log's public key
 * @param baseUrl      base URL of the CT log (e.g. {@code "https://ct.googleapis.com/logs/argon2025/"}),
 *                     must end with {@code /}
 * @param publicKeyDer DER-encoded EC or RSA public key of the CT log (for SCT verification)
 * @param enabled      whether this log is active for SCT collection
 * @param description  human-readable label for the log
 * @since 1.0
 */
public record CtLogDescriptor(
        String logId,
        String baseUrl,
        byte[] publicKeyDer,
        boolean enabled,
        String description) {

    /** Expected length of a hex-encoded CT log ID (32 bytes × 2 hex chars). */
    public static final int LOG_ID_HEX_LENGTH = 64;

    /**
     * Validates and defensively copies mutable fields.
     *
     * @throws NullPointerException     if any field is {@code null}
     * @throws IllegalArgumentException if {@code logId} is not a 64-character lowercase hex string,
     *                                  if {@code baseUrl} is blank or does not end with {@code /},
     *                                  or if {@code publicKeyDer} is empty
     */
    public CtLogDescriptor {
        Objects.requireNonNull(logId, "logId");
        Objects.requireNonNull(baseUrl, "baseUrl");
        Objects.requireNonNull(publicKeyDer, "publicKeyDer");
        Objects.requireNonNull(description, "description");
        if (logId.length() != LOG_ID_HEX_LENGTH) {
            throw new IllegalArgumentException(
                    "logId must be exactly 64 hex characters; got " + logId.length());
        }
        try {
            HexFormat.of().parseHex(logId);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("logId is not valid hex: " + logId, invalid);
        }
        if (baseUrl.isBlank()) {
            throw new IllegalArgumentException("baseUrl must not be blank");
        }
        if (!baseUrl.endsWith("/")) {
            throw new IllegalArgumentException("baseUrl must end with '/': " + baseUrl);
        }
        if (publicKeyDer.length == 0) {
            throw new IllegalArgumentException("publicKeyDer must not be empty");
        }
        publicKeyDer = publicKeyDer.clone();
    }

    /**
     * Returns an independent copy of the DER-encoded public key bytes.
     *
     * @return copy of the public key bytes
     */
    @Override
    public byte[] publicKeyDer() {
        return publicKeyDer.clone();
    }
}
