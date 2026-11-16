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

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Immutable SHA-256 commitment to the exact proof-suite configuration.
 */
final class ProofSuiteCommitment {

    /**
     * Required SHA-256 commitment length, in bytes.
     */
    /* default */ static final int LENGTH = 32;

    private final byte[] bytes;

    /**
     * Snapshots the SHA-256 digest of an exact proof-suite configuration.
     *
     * @param bytes exactly 32 commitment bytes; copied
     * @throws IllegalArgumentException if the input is null or has another length
     */
    /* default */ ProofSuiteCommitment(byte[] bytes) {
        if (bytes == null || bytes.length != LENGTH) {
            throw new IllegalArgumentException("Proof-suite commitment must contain exactly 32 bytes");
        }
        this.bytes = bytes.clone();
    }

    /**
     * Copies the immutable proof-suite configuration commitment.
     *
     * @return newly allocated 32-byte commitment
     */
    /* default */ byte[] bytes() {
        return bytes.clone();
    }

    /**
     * Compares configuration commitments without an early exit on differing bytes.
     *
     * @param candidate commitment to compare, or null
     * @return whether the candidate is non-null and contains the same 32 bytes
     */
    /* default */ boolean matches(ProofSuiteCommitment candidate) {
        return candidate != null && MessageDigest.isEqual(bytes, candidate.bytes);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object candidate) {
        return candidate instanceof ProofSuiteCommitment other && matches(other);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
