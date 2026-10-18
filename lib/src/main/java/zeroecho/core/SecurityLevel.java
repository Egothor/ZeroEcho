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
package zeroecho.core;

import java.util.OptionalInt;

/**
 * Security level of a cryptographic algorithm or parameter set.
 *
 * <p>
 * Dual representation supports both classical and NIST PQC levels:
 * </p>
 * <ul>
 * <li>{@link #nistLevel()} — NIST PQC security category (1–5), or empty for
 * classical-only algorithms.</li>
 * <li>{@link #classicalBits()} — equivalent classical security in bits (e.g.,
 * 128, 192, 256).</li>
 * </ul>
 *
 * <h2>Construction</h2>
 * <ul>
 * <li>{@link #classical(int)} — classical algorithms (RSA, AES, ECDSA …) where
 * no NIST PQC category applies.</li>
 * <li>{@link #nist(int, int)} — post-quantum parameter sets with a defined NIST
 * category.</li>
 * </ul>
 *
 * <h2>NIST PQC categories</h2>
 * <pre>
 * Level 1 ≈ 128-bit classical  (AES-128 search)
 * Level 2 ≈ 128-bit (stronger collision requirement)
 * Level 3 ≈ 192-bit classical  (AES-192 search)
 * Level 4 ≈ 192-bit (stronger collision requirement)
 * Level 5 ≈ 256-bit classical  (AES-256 search)
 * </pre>
 *
 * @param nistLevel optional NIST security category, from 1 to 5
 * @param classicalBits positive classical security strength in bits
 * @since 1.0
 */
public record SecurityLevel(OptionalInt nistLevel, int classicalBits) {

    /**
     * Validates the record fields on construction.
     *
     * @throws NullPointerException     if {@code nistLevel} is {@code null}
     * @throws IllegalArgumentException if {@code classicalBits} is not positive, or
     *                                  if a NIST level is present but not in [1, 5]
     */
    public SecurityLevel {
        java.util.Objects.requireNonNull(nistLevel, "nistLevel must not be null");
        if (classicalBits <= 0) {
            throw new IllegalArgumentException("classicalBits must be positive, got: " + classicalBits);
        }
        if (nistLevel.isPresent()) {
            int level = nistLevel.getAsInt();
            if (level < 1 || level > 5) {
                throw new IllegalArgumentException("NIST level must be in [1, 5], got: " + level);
            }
        }
    }

    /**
     * Creates a classical-only security level with no NIST PQC category.
     *
     * @param bits classical security strength in bits (must be positive)
     * @return a {@code SecurityLevel} with an empty {@code nistLevel}
     */
    public static SecurityLevel classical(int bits) {
        return new SecurityLevel(OptionalInt.empty(), bits);
    }

    /**
     * Creates a post-quantum security level with a NIST PQC category.
     *
     * @param nistCategory NIST security category (1–5)
     * @param classicalBits equivalent classical security in bits (must be positive)
     * @return a {@code SecurityLevel} with the given NIST category
     */
    public static SecurityLevel nist(int nistCategory, int classicalBits) {
        return new SecurityLevel(OptionalInt.of(nistCategory), classicalBits);
    }
}
