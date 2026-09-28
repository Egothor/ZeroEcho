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

package zeroecho.pki.api.issuance;

/**
 * Immutable, thread-safe exact issuance input and its frozen orchestration intent.
 * The intent is correlation metadata, never authorization. Its command commitment
 * is only one input to the PKI-derived effective commitment; exact CSR bytes and
 * requested validity also participate. Construction performs no CSR verification.
 *
 * @param request bounded immutable issuance request
 * @param intent immutable external identity and exact frozen PKI selection
 */
public record CorrelatedEndEntityIssuanceRequest(EndEntityIssuanceRequest request, IssuanceIntent intent) {
    /** Maximum UTF-8 byte length of each authority, issuer, path or profile identifier. */
    public static final int MAXIMUM_IDENTIFIER_UTF8_BYTES = 4096; // NOPMD - LongVariable: descriptive byte-unit/projection name preserves its established contract.

    /**
     * Validates bounded coordinates without copying the already immutable request.
     * Identifier validation takes linear time and constant auxiliary memory.
     *
     * @throws IllegalArgumentException if either argument is null, the profile IDs
     *         differ, or an identifier exceeds the byte limit or contains an unpaired surrogate
     */
    public CorrelatedEndEntityIssuanceRequest {
        if (request == null || intent == null) {
            throw new IllegalArgumentException("Correlated issuance request and intent are required");
        }
        requireBoundedIdentifier(request.issuerCaId().value());
        requireBoundedIdentifier(request.profileId());
        requireBoundedIdentifier(intent.expectedProfile().profileId());
        requireBoundedIdentifier(intent.expectedIssuerId().value());
        requireBoundedIdentifier(intent.expectedChainPathId().value());
        if (!request.profileId().equals(intent.expectedProfile().profileId())) {
            throw new IllegalArgumentException("Correlated issuance profile selection differs");
        }
    }

    /* default */ static void requireBoundedIdentifier(String value) {
        if (value.length() > MAXIMUM_IDENTIFIER_UTF8_BYTES) {
            throw new IllegalArgumentException("Correlated issuance identifier exceeds its bound");
        }
        int bytes = 0;
        int index = 0;
        while (index < value.length()) {
            char current = value.charAt(index);
            if (Character.isHighSurrogate(current)) {
                if (++index == value.length() || !Character.isLowSurrogate(value.charAt(index))) {
                    throw new IllegalArgumentException("Correlated issuance identifier is not valid Unicode");
                }
                bytes += 4;
            } else if (Character.isLowSurrogate(current)) {
                throw new IllegalArgumentException("Correlated issuance identifier is not valid Unicode");
            } else {
                bytes += current < 0x80 ? 1 : current < 0x800 ? 2 : 3;
            }
            if (bytes > MAXIMUM_IDENTIFIER_UTF8_BYTES) {
                throw new IllegalArgumentException("Correlated issuance identifier exceeds its bound");
            }
            index++;
        }
    }

    /**
     * Returns a safe diagnostic description without requester or correlation values.
     *
     * @return redacted description
     */
    @Override public String toString() {
        return "CorrelatedEndEntityIssuanceRequest[redacted]";
    }
}
