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
package zeroecho.pki.api.confirmation;

import java.util.Arrays;
import java.util.Objects;

import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;

/**
 * Immutable bounded submission of one key-possession proof response.
 *
 * <p>The response is defensively copied on input and output and is never
 * included in {@link #toString()}.</p>
 *
 * @param proofCas exact pending lifecycle and challenge compare-and-set coordinates
 * @param response non-empty suite-defined response, at most 16384 bytes
 */
public record CredentialConfirmationProofSubmission(CredentialConfirmationProofCas proofCas,
        byte[] response) {

    /**
     * Validates the exact proof coordinates and defensively owns the response.
     *
     * @throws NullPointerException if {@code proofCas} is {@code null}
     * @throws IllegalArgumentException if the response is null, empty, or exceeds 16384 bytes
     */
    public CredentialConfirmationProofSubmission {
        Objects.requireNonNull(proofCas, "proofCas");
        if (response == null || response.length == 0
                || response.length > KeyPossessionProofResponse.MAXIMUM_BYTES) {
            throw new IllegalArgumentException("Proof submission response length is outside the supported range");
        }
        response = response.clone();
    }

    /**
     * Returns a defensive copy of the suite-defined response.
     *
     * @return submitted response bytes
     */
    @Override
    public byte[] response() {
        return response.clone();
    }

    /** Compares response bytes by content. */
    @Override
    public boolean equals(Object other) {
        return this == other || other instanceof CredentialConfirmationProofSubmission candidate
                && proofCas.equals(candidate.proofCas)
                && Arrays.equals(response, candidate.response);
    }

    /** Returns a content-based hash code for every component. */
    @Override
    public int hashCode() {
        return 31 * proofCas.hashCode() + Arrays.hashCode(response);
    }

    /** Returns a structural description without response bytes. */
    @Override
    public String toString() {
        return "CredentialConfirmationProofSubmission[proofCas=" + proofCas
                + ", response=<" + response.length + " bytes>]";
    }
}
