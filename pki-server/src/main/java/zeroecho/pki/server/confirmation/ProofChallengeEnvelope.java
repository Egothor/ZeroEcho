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
package zeroecho.pki.server.confirmation;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * Bounded public challenge with copied signing input and explicit buffer erasure.
 *
 * <p>The descriptor and expiry remain fixed. Signing-input access returns a copy;
 * {@link #clear()} erases retained bytes. Callers serialize access and erasure and
 * must not reuse the envelope for verification after erasure.</p>
 */
final class ProofChallengeEnvelope {

    private final ProofSuiteDescriptor descriptor;
    private final byte[] signatureInput;
    private final Instant expiresAt;

    /**
     * Snapshots the bounded public signing input for a proof challenge.
     *
     * @param descriptor exact suite profile; must not be null
     * @param signatureInput nonempty signing input of at most 2,048 bytes; copied
     * @param expiresAt absolute challenge expiry; must not be null
     * @throws NullPointerException if the descriptor or expiry is null
     * @throws IllegalArgumentException if signing input is null, empty or oversized
     */
    /* default */ ProofChallengeEnvelope(ProofSuiteDescriptor descriptor, byte[] signatureInput,
            Instant expiresAt) {
        this.descriptor = Objects.requireNonNull(descriptor, "descriptor");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        if (signatureInput == null || signatureInput.length == 0
                || signatureInput.length > CanonicalProofTranscript.MAXIMUM_ENCODED_BYTES) {
            throw new IllegalArgumentException("Proof challenge payload has an invalid length");
        }
        this.signatureInput = signatureInput.clone();
    }

    /**
     * Returns the exact suite profile associated with this challenge.
     *
     * @return retained non-null suite descriptor
     */
    /* default */ ProofSuiteDescriptor descriptor() {
        return descriptor;
    }

    /**
     * Copies the current challenge signing input.
     *
     * @return caller-owned copy, containing zeroes after {@link #clear()}
     */
    /* default */ byte[] signatureInput() {
        return signatureInput.clone();
    }

    /**
     * Returns the absolute expiry of this challenge.
     *
     * @return retained non-null expiry
     */
    /* default */ Instant expiresAt() {
        return expiresAt;
    }

    /**
     * Erases the retained signing-input bytes.
     *
     * <p>Previously returned copies remain the caller's responsibility. The envelope
     * must not be reused for verification after erasure.</p>
     */
    /* default */ void clear() {
        Arrays.fill(signatureInput, (byte) 0);
    }
}
