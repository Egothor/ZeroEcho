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
package zeroecho.pkix;

import java.util.List;
import java.util.Objects;

/**
 * An X.509 {@code ExtendedKeyUsage} extension value (RFC 5280, 4.2.1.12): an
 * ordered list of key-purpose OIDs.
 *
 * <p>
 * Well-known purpose OID constants are provided; arbitrary purpose OIDs are
 * supported for extensibility.
 * </p>
 *
 * @param keyPurposeOids the ordered, non-empty list of key-purpose OIDs
 */
public record ExtendedKeyUsage(List<String> keyPurposeOids) {

    /** {@code id-kp-serverAuth}. */
    public static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    /** {@code id-kp-clientAuth}. */
    public static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    /** {@code id-kp-codeSigning}. */
    public static final String CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
    /** {@code id-kp-emailProtection}. */
    public static final String EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";
    /** {@code id-kp-timeStamping}. */
    public static final String TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
    /** {@code id-kp-OCSPSigning}. */
    public static final String OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    /** Canonicalizing constructor. */
    public ExtendedKeyUsage {
        Objects.requireNonNull(keyPurposeOids, "keyPurposeOids");
        if (keyPurposeOids.isEmpty()) {
            throw new IllegalArgumentException("keyPurposeOids must not be empty");
        }
        keyPurposeOids = List.copyOf(keyPurposeOids);
    }

    /**
     * Creates an extended key usage from the given purpose OIDs.
     *
     * @param keyPurposeOids one or more key-purpose OIDs
     * @return the extended key usage value
     */
    public static ExtendedKeyUsage of(String... keyPurposeOids) {
        return new ExtendedKeyUsage(List.of(keyPurposeOids));
    }
}
