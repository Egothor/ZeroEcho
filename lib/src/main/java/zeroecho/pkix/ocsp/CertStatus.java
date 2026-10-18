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
package zeroecho.pkix.ocsp;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pkix.crl.CrlReason;

/**
 * An OCSP certificate status (RFC 6960): {@code good}, {@code revoked}, or
 * {@code unknown}.
 */
public sealed interface CertStatus permits CertStatus.Good, CertStatus.Revoked, CertStatus.Unknown {

    /** The certificate is not revoked. */
    record Good() implements CertStatus {
    }

    /**
     * The certificate is revoked.
     *
     * @param revocationTime the revocation time
     * @param reason the revocation reason, if present
     */
    record Revoked(Instant revocationTime, Optional<CrlReason> reason) implements CertStatus {
        /** Canonicalizing constructor. */
        public Revoked {
            Objects.requireNonNull(revocationTime, "revocationTime");
            Objects.requireNonNull(reason, "reason");
        }
    }

    /** The responder does not know the status of the requested certificate. */
    record Unknown() implements CertStatus {
    }

    /**
     * Returns a {@code good} status.
     *
     * @return good status
     */
    static CertStatus good() {
        return new Good();
    }

    /**
     * Returns an {@code unknown} status.
     *
     * @return unknown status
     */
    static CertStatus unknown() {
        return new Unknown();
    }

    /**
     * Returns a {@code revoked} status.
     *
     * @param revocationTime the revocation time
     * @param reason the revocation reason
     * @return revoked status
     */
    static CertStatus revoked(Instant revocationTime, CrlReason reason) {
        return new Revoked(revocationTime, Optional.of(reason));
    }
}
