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

import java.util.Objects;

/**
 * Immutable public coordinates and input bounds of one proof-suite profile.
 *
 * @param suiteId stable versioned suite identity
 * @param configurationCommitment commitment to the complete suite configuration
 * @param challengeBytes required challenge length, from 32 through 256 bytes inclusive
 * @param maximumResponseBytes maximum accepted response length, from 1 through 16,384 bytes inclusive
 */
record ProofSuiteDescriptor(ProofSuiteId suiteId, ProofSuiteCommitment configurationCommitment,
        int challengeBytes, int maximumResponseBytes) {

    private static final int MAXIMUM_CHALLENGE_BYTES = 256;
    private static final int MAXIMUM_RESPONSE_BYTES = 16_384;

    /**
     * Validates required suite coordinates and supported input bounds.
     *
     * @param suiteId stable versioned identity; must not be null
     * @param configurationCommitment exact configuration commitment; must not be null
     * @param challengeBytes required challenge length, in bytes
     * @param maximumResponseBytes maximum accepted proof-response length, in bytes
     * @throws NullPointerException if the suite identity or commitment is null
     * @throws IllegalArgumentException if a byte bound is outside its supported range
     */
    ProofSuiteDescriptor {
        Objects.requireNonNull(suiteId, "suiteId");
        Objects.requireNonNull(configurationCommitment, "configurationCommitment");
        if (challengeBytes < 32 || challengeBytes > MAXIMUM_CHALLENGE_BYTES) {
            throw new IllegalArgumentException("Proof challenge length is outside the supported range");
        }
        if (maximumResponseBytes < 1 || maximumResponseBytes > MAXIMUM_RESPONSE_BYTES) {
            throw new IllegalArgumentException("Proof response limit is outside the supported range");
        }
    }
}
