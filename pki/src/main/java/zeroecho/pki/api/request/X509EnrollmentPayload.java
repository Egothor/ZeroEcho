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
package zeroecho.pki.api.request;

import java.util.Objects;

/**
 * Immutable, explicitly typed original X.509 enrollment request.
 * Construction snapshots at most one MiB; it performs no parsing or proof
 * verification. Copying requires O(N) time and memory. Instances are thread-safe.
 *
 * @param kind exact encoded request syntax
 * @param der original DER payload, between one byte and one MiB
 */
public record X509EnrollmentPayload(Kind kind, byte[] der) {
    /** Closed X.509 enrollment request syntaxes. */
    public enum Kind {
        /** PKCS#10 CertificationRequest. */ PKCS10,
        /** RFC 4211 CertReqMsg with signing-key proof. */ CRMF
    }
    /** Maximum complete original request size in bytes. */
    public static final int MAXIMUM_DER_BYTES = 1_048_576;

    /** Validates syntax and bounds before copying the caller-owned bytes. */
    public X509EnrollmentPayload {
        Objects.requireNonNull(kind, "kind");
        if (der == null || der.length == 0 || der.length > MAXIMUM_DER_BYTES) {
            throw new IllegalArgumentException("Invalid X.509 enrollment request size");
        }
        der = der.clone();
    }

    /**
     * Returns an independently owned original payload.
     * @return defensive DER snapshot
     */
    @Override public byte[] der() { return der.clone(); }

    /** Returns a diagnostic representation without request data. */
    @Override public String toString() { return "X509EnrollmentPayload[kind=" + kind + ", redacted]"; }
}

