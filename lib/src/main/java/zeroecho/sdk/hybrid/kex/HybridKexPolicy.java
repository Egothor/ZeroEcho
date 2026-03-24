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
package zeroecho.sdk.hybrid.kex;

import java.security.Key;
import java.util.Objects;

import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.policy.SecurityStrengthAdvisor;

/**
 * Hybrid KEX policy helper for minimum security strength enforcement.
 *
 * <p>
 * This policy applies additional hybrid-specific checks beyond per-algorithm
 * policy validation. It is intended to prevent accidental downgrade
 * combinations (for example a strong PQC leg combined with a too-weak classic
 * leg, or an undersized OKM output).
 * </p>
 *
 * <h2>What is checked</h2>
 * <ul>
 * <li>Classic leg estimated strength in bits (algorithm id + key)</li>
 * <li>PQC leg estimated strength in bits (algorithm id + key)</li>
 * <li>Minimum OKM length (in bytes) for the intended usage</li>
 * </ul>
 *
 * <p>
 * Strength estimates are provided by
 * {@link SecurityStrengthAdvisor#estimateBits(String, Key)} and are
 * conservative heuristics suitable for gating and coarse comparisons.
 * </p>
 *
 * @since 1.0
 */
public final class HybridKexPolicy {

    private final int minClassicBits;
    private final int minPqcBits;
    private final int minOkmBytes;

    /**
     * Creates a hybrid policy.
     *
     * @param minClassicBits minimum estimated bits for classic leg (for example 128
     *                       or 192)
     * @param minPqcBits     minimum estimated bits for PQC leg (for example 192)
     * @param minOkmBytes    minimum OKM output length in bytes (for example 32)
     */
    public HybridKexPolicy(int minClassicBits, int minPqcBits, int minOkmBytes) {
        if (minClassicBits < 0 || minPqcBits < 0) {
            throw new IllegalArgumentException("min bits must be non-negative");
        }
        if (minOkmBytes < 1) { // NOPMD
            throw new IllegalArgumentException("minOkmBytes must be >= 1");
        }
        this.minClassicBits = minClassicBits;
        this.minPqcBits = minPqcBits;
        this.minOkmBytes = minOkmBytes;
    }

    /**
     * Enforces the policy for a given hybrid configuration.
     *
     * @param profile hybrid profile
     * @param classic classic agreement context
     * @param pqc     PQC message agreement context
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if policy is violated
     */
    public void enforce(HybridKexProfile profile, AgreementContext classic, MessageAgreementContext pqc) {
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(classic, "classic");
        Objects.requireNonNull(pqc, "pqc");

        if (profile.outLenBytes() < minOkmBytes) {
            throw new IllegalArgumentException(
                    "Hybrid OKM length too small: " + profile.outLenBytes() + " < " + minOkmBytes);
        }

        int classicBits = SecurityStrengthAdvisor.estimateBits(classic.algorithm().id(), classic.key());
        int pqcBits = SecurityStrengthAdvisor.estimateBits(pqc.algorithm().id(), pqc.key());

        if (classicBits < minClassicBits) {
            throw new IllegalArgumentException("Classic leg too weak: " + classicBits + " < " + minClassicBits);
        }
        if (pqcBits < minPqcBits) {
            throw new IllegalArgumentException("PQC leg too weak: " + pqcBits + " < " + minPqcBits);
        }
    }
}
